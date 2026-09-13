use inode_cli::protocol::{self, Session};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

async fn mock_gateway(wrong_pin: bool) -> (String, String, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let pin = format!("{:x}", Sha256::digest(cert.cert.der()));
    let accept = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        for step in 0..if wrong_pin { 1 } else { 4 } {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = accept.accept(tcp).await else {
                assert!(wrong_pin);
                return;
            };
            let mut received = Vec::new();
            let mut byte = [0];
            while !received.ends_with(b"\r\n\r\n") {
                let n = tls.read(&mut byte).await.unwrap_or(0);
                if wrong_pin {
                    assert_eq!(n, 0, "HTTP bytes leaked despite wrong certificate pin");
                    return;
                }
                assert_ne!(n, 0);
                received.push(byte[0]);
            }
            let headers = String::from_utf8(received).unwrap();
            match step {
                0 => {
                    assert!(headers.starts_with("GET /svpn/index.cgi"));
                    let body = "<data><gatewayinfo><auth><supportPassword>true</supportPassword></auth><url><login>/login</login><logout>/logout</logout></url></gatewayinfo></data>";
                    tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                }
                1 => {
                    assert!(headers.starts_with("POST /login"));
                    let length: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|n| n.trim().parse().unwrap())
                        })
                        .unwrap();
                    let mut body = vec![0; length];
                    tls.read_exact(&mut body).await.unwrap();
                    let form: Vec<_> = url::form_urlencoded::parse(&body).collect();
                    let doc = roxmltree::Document::parse(&form[0].1).unwrap();
                    assert_eq!(
                        doc.descendants()
                            .find(|n| n.has_tag_name("password"))
                            .unwrap()
                            .text(),
                        Some("test%26password")
                    );
                    let body = "<data><result>Success</result></data>";
                    tls.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: svpnginfo=mock-session; Path=/; Secure\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                }
                2 => {
                    assert!(headers.starts_with("NET_EXTEND /"));
                    assert!(headers.contains("svpnginfo=mock-session"));
                    tls.write_all(b"HTTP/1.1 200 OK\r\nIPADDRESS: 10.99.0.7\r\n\r\n")
                        .await
                        .unwrap();
                    let mut packet = [0; 24];
                    tls.read_exact(&mut packet).await.unwrap();
                    assert_eq!(&packet[..4], &[1, 0, 0, 20]);
                    for b in packet {
                        tls.write_all(&[b]).await.unwrap();
                    }
                }
                3 => {
                    assert!(headers.starts_with("GET /logout"));
                    tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n<data/>",
                    )
                    .await
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let _ = tls.shutdown().await;
        }
    });
    (url, pin, task)
}

#[tokio::test]
async fn full_pinned_tls_authentication_tunnel_and_logout() {
    let (url, pin, task) = mock_gateway(false).await;
    let session = Session::new(
        protocol::gateway(&url).unwrap(),
        None,
        Some(&pin),
        Duration::from_secs(5),
    )
    .unwrap();
    let info = session.discover(None).await.unwrap();
    session
        .login(&info, "test-user", "test&password")
        .await
        .unwrap();
    let (mut tunnel, ip, initial) = session.open_tunnel().await.unwrap();
    assert_eq!(ip.to_string(), "10.99.0.7");
    assert!(initial.is_empty());
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[3] = 20;
    let packet = protocol::frame(&ip).unwrap();
    tunnel.write_all(&packet).await.unwrap();
    let mut reply = vec![0; packet.len()];
    tunnel.read_exact(&mut reply).await.unwrap();
    assert_eq!(protocol::Frames::default().feed(&reply).unwrap(), vec![ip]);
    drop(tunnel);
    session.logout(&info).await;
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn incorrect_pin_sends_no_http_or_credentials() {
    let (url, _, task) = mock_gateway(true).await;
    let session = Session::new(
        protocol::gateway(&url).unwrap(),
        None,
        Some(&"00".repeat(32)),
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        session
            .discover(None)
            .await
            .unwrap_err()
            .to_string()
            .contains("fingerprint mismatch")
    );
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
