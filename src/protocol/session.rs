use super::{discovery::xml, *};
use anyhow::{Context, Result, bail, ensure};
use reqwest::cookie::CookieStore;
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    time::{sleep, timeout},
};
use zeroize::Zeroizing;

/// 自动模式下两次抓取验证码之间的固定间隔。
const CAPTCHA_REFETCH_PAUSE: Duration = Duration::from_millis(300);

enum LoginOutcome {
    Success,
    VerifyCode,
    Other(String),
}

impl Session {
    pub async fn discover(&self, domain: Option<&str>) -> Result<GatewayInfo> {
        let body = self
            .request(endpoint(&self.gateway, "/svpn/index.cgi")?, None, true)
            .await?;
        let body = if let Some(url) = domain_endpoint(&self.gateway, &body, domain)? {
            self.request(url, None, false).await?
        } else {
            body
        };
        gateway_info(&self.gateway, &body)
    }

    pub async fn login(&self, info: &GatewayInfo, username: &str, password: &str) -> Result<()> {
        self.login_with_captcha(info, username, password, None)
            .await
    }

    pub async fn login_with_captcha(
        &self,
        info: &GatewayInfo,
        username: &str,
        password: &str,
        captcha: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !info.extra_auth || (info.captcha.is_some() && captcha.is_some()),
            "Additional authentication requires a CAPTCHA or unsupported SMS/SSO flow"
        );
        match self.submit_login(info, username, password, captcha).await? {
            LoginOutcome::Success => Ok(()),
            LoginOutcome::VerifyCode => bail!("verification code rejected; no automatic retries"),
            LoginOutcome::Other(reason) => bail!("{reason}; no automatic retries"),
        }
    }

    /// 提交一次登录，返回可区分的结果（成功 / 验证码错 / 其它）。
    async fn submit_login(
        &self,
        info: &GatewayInfo,
        username: &str,
        password: &str,
        captcha: Option<&str>,
    ) -> Result<LoginOutcome> {
        let client = ClientInfo::local(&self.gateway).await?;
        let body = self
            .request(
                info.login.clone(),
                Some(login_body_with_client(
                    username,
                    password,
                    captcha,
                    Some(&client),
                )),
                false,
            )
            .await?;
        if login_succeeded(&body)? {
            self.cookie()?;
            return Ok(LoginOutcome::Success);
        }
        let doc = xml(&body)?;
        let message = doc
            .descendants()
            .filter(|n| n.is_element())
            .filter(|n| {
                ["replyMessage", "errorMsg", "result", "type"].contains(&n.tag_name().name())
            })
            .filter_map(|n| n.text())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        if ["verify", "vldcode", "code", "captcha", "验证码"]
            .iter()
            .any(|k| message.contains(k))
        {
            Ok(LoginOutcome::VerifyCode)
        } else {
            Ok(LoginOutcome::Other(authentication_summary(message.trim())))
        }
    }

    /// 全自动登录：内嵌 CNN 识别验证码，只在高置信时提交，低置信免费换图。
    /// 抓图不限次（最多 max_fetch 张），提交上限 max_submit 次（防锁定）。
    /// 每次重新抓图前固定间隔，避免连续请求触发网关风控。
    pub async fn login_auto(
        &self,
        info: &GatewayInfo,
        username: &str,
        password: &str,
        threshold: f32,
        max_fetch: usize,
        max_submit: usize,
    ) -> Result<()> {
        let captcha_url = info
            .captcha
            .clone()
            .context("Gateway does not advertise a CAPTCHA endpoint for auto mode")?;
        let model = crate::captcha_cnn::Model::load();
        let mut submits = 0usize;
        let mut best_seen = 0f32;
        for attempt in 0..max_fetch {
            if attempt > 0 {
                sleep(CAPTCHA_REFETCH_PAUSE).await;
            }
            let bytes = self.request_bytes(captcha_url.clone(), None, false).await?;
            let Some((code, conf)) = model.solve(&bytes) else {
                continue; // 分割不出 4 个字形，换图
            };
            if conf > best_seen {
                best_seen = conf;
            }
            if conf < threshold {
                continue; // 低置信，免费换图
            }
            match self
                .submit_login(info, username, password, Some(&code))
                .await?
            {
                LoginOutcome::Success => {
                    eprintln!("CAPTCHA auto-solved: {code} (confidence {conf:.2})");
                    return Ok(());
                }
                LoginOutcome::VerifyCode => {
                    submits += 1;
                    eprintln!(
                        "CAPTCHA {code} rejected (submit {submits}/{max_submit}); refetching"
                    );
                    if submits >= max_submit {
                        bail!(
                            "CAPTCHA auto-recognition failed {max_submit} submissions; stopping to avoid lockout"
                        );
                    }
                }
                LoginOutcome::Other(reason) => bail!("{reason}; no automatic retries"),
            }
        }
        bail!(
            "No high-confidence CAPTCHA within {max_fetch} fetches (best {best_seen:.2} < {threshold:.2})"
        );
    }

    fn cookie(&self) -> Result<Zeroizing<String>> {
        let cookie = self
            .jar
            .cookies(&self.gateway)
            .context("Missing tunnel session cookie")?;
        let value = cookie.to_str()?;
        ensure!(
            value.split(';').any(|v| v.trim().starts_with("svpnginfo=")),
            "Missing svpnginfo cookie"
        );
        ensure!(!value.contains(['\r', '\n']), "Invalid cookie header");
        Ok(Zeroizing::new(value.to_owned()))
    }

    pub async fn open_tunnel(&self) -> Result<(Tunnel, Ipv4Addr, Vec<u8>)> {
        let mut stream = self.tls_stream().await?;
        let authority = &self.gateway[url::Position::BeforeHost..url::Position::AfterPort];
        let request = Zeroizing::new(format!(
            "NET_EXTEND / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: SSLVPN-Client/7.0\r\nCookie: {}\r\nContent-Length: 0\r\n\r\n",
            self.cookie()?.as_str()
        ));
        timeout(self.timeout, stream.write_all(request.as_bytes())).await??;
        let (address, pending) = timeout(self.timeout, read_handshake(&mut stream)).await??;
        Ok((stream, address, pending))
    }

    pub async fn logout(&self, info: &GatewayInfo) {
        if let Some(url) = &info.logout {
            let _ = self.request(url.clone(), None, false).await;
        }
    }
}
