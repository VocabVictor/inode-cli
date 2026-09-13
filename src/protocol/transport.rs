use super::{MAX_BODY, Tunnel, endpoint};
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use reqwest::cookie::{CookieStore, Jar};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use url::Url;
pub struct Session {
    pub gateway: Url,
    pub(super) jar: Arc<Jar>,
    tls: native_tls::TlsConnector,
    pin: Option<[u8; 32]>,
    pub timeout: Duration,
}

impl Session {
    pub fn new(
        gateway: Url,
        ca: Option<&[u8]>,
        pin: Option<&str>,
        timeout: Duration,
    ) -> Result<Self> {
        let jar = Arc::new(Jar::default());
        let mut tls = native_tls::TlsConnector::builder();
        tls.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        if let Some(ca) = ca {
            tls.add_root_certificate(
                native_tls::Certificate::from_pem(ca).context("Invalid CA PEM")?,
            );
        }
        let pin = pin.map(parse_pin).transpose()?;
        if pin.is_some() {
            // Exact leaf-certificate verification occurs on this same stream,
            // before any HTTP data or credentials can be transmitted.
            tls.danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }
        Ok(Self {
            gateway,
            jar,
            tls: tls.build()?,
            pin,
            timeout,
        })
    }

    pub(super) async fn tls_stream(&self) -> Result<Tunnel> {
        let host = self
            .gateway
            .host_str()
            .context("Missing gateway hostname")?;
        let tcp = timeout(
            self.timeout,
            TcpStream::connect((host, self.gateway.port_or_known_default().unwrap())),
        )
        .await??;
        tcp.set_nodelay(true)?;
        let stream = timeout(
            self.timeout,
            tokio_native_tls::TlsConnector::from(self.tls.clone()).connect(host, tcp),
        )
        .await??;
        if let Some(expected) = self.pin {
            let cert = stream
                .get_ref()
                .peer_certificate()?
                .context("Gateway did not present a certificate")?;
            let actual: [u8; 32] = Sha256::digest(cert.to_der()?).into();
            ensure!(
                actual == expected,
                "Gateway certificate fingerprint mismatch; no credentials sent"
            );
        }
        Ok(stream)
    }

    async fn single_request(
        &self,
        url: &Url,
        body: Option<&str>,
        discovery: bool,
    ) -> Result<(hyper::StatusCode, hyper::HeaderMap, Vec<u8>)> {
        let stream = self.tls_stream().await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let deadline = self.timeout;
        let task = tokio::spawn(async move {
            let _ = timeout(deadline, connection).await;
        });
        let result = async {
            let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
            let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
            let mut req = hyper::Request::builder()
                .method(if body.is_some() { "POST" } else { "GET" })
                .uri(path)
                .header("Host", authority)
                .header("Connection", "close")
                .header(
                    "User-Agent",
                    if discovery {
                        "SSLVPN-Client/3.0"
                    } else {
                        "SSLVPN-Client/7.0"
                    },
                );
            if let Some(cookie) = self.jar.cookies(url) {
                req = req.header("Cookie", cookie);
            }
            if body.is_some() {
                // Native iNode V7 uses text/html for its XML request form.
                req = req.header("Content-Type", "text/html");
            }
            let req = req.body(Full::new(Bytes::copy_from_slice(
                body.unwrap_or("").as_bytes(),
            )))?;
            let res = sender
                .send_request(req)
                .await
                .context("Gateway HTTP request failed")?;
            let (parts, mut body) = res.into_parts();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.frame().await {
                if let Ok(data) = chunk
                    .context("Reading gateway response failed")?
                    .into_data()
                {
                    ensure!(
                        bytes.len() + data.len() <= MAX_BODY,
                        "Gateway response too large"
                    );
                    bytes.extend_from_slice(&data);
                }
            }
            Ok::<_, anyhow::Error>((parts.status, parts.headers, bytes))
        }
        .await;
        task.abort();
        result
    }

    pub async fn request(&self, url: Url, body: Option<String>, discovery: bool) -> Result<String> {
        String::from_utf8(self.request_bytes(url, body, discovery).await?)
            .context("Gateway XML is not UTF-8")
    }

    pub async fn request_bytes(
        &self,
        url: Url,
        body: Option<String>,
        discovery: bool,
    ) -> Result<Vec<u8>> {
        let mut current = endpoint(&self.gateway, url.as_str())?;
        for _ in 0..6 {
            let (status, headers, bytes) = timeout(
                self.timeout,
                self.single_request(&current, body.as_deref(), discovery),
            )
            .await??;
            self.jar
                .set_cookies(&mut headers.get_all("set-cookie").iter(), &current);
            if status.is_redirection() {
                ensure!(
                    body.is_none(),
                    "Login redirect requires gateway-specific adaptation"
                );
                let location = headers
                    .get("Location")
                    .context("Redirect without Location")?
                    .to_str()?;
                current = endpoint(&self.gateway, current.join(location)?.as_str())?;
                continue;
            }
            ensure!(
                status.is_success(),
                "Gateway returned HTTP {}",
                status.as_u16()
            );
            return Ok(bytes);
        }
        bail!("Too many gateway redirects")
    }
}
pub fn parse_pin(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "--servercert must be 64 SHA-256 hexadecimal characters"
    );
    let mut pin = [0; 32];
    for (i, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(pin)
}
