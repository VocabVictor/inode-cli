use super::{Session, authentication_summary, endpoint};
use anyhow::{Result, bail, ensure};
use reqwest::cookie::CookieStore;
use zeroize::Zeroizing;

pub(super) fn challenge_type(doc: &roxmltree::Document<'_>) -> Option<&'static str> {
    let field = |name| {
        doc.root_element()
            .children()
            .find(|n| n.has_tag_name(name))
            .and_then(|n| n.text())
            .map(str::trim)
    };
    if field("result") != Some("Challenge") {
        return None;
    }
    match field("type") {
        Some("PROMPTPWD") => Some("PROMPTPWD"),
        Some("CHANGEPWD") => Some("CHANGEPWD"),
        _ => None,
    }
}

impl Session {
    // Gateway /login/login.js: closeDialogPwd -> onDialogPwdSubmit(PROMPTPWD).
    pub(super) async fn continue_password_prompt(
        &self,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("user_name", username)
                .append_pair("password", password)
                .append_pair("type", "PROMPTPWD")
                .finish(),
        );
        let url = endpoint(&self.gateway, "/wnm/login/login_result.json")?;
        let (status, headers, reply) = tokio::time::timeout(
            self.timeout,
            self.single_request(
                &url,
                Some(&body),
                false,
                "application/x-www-form-urlencoded",
            ),
        )
        .await??;
        ensure!(
            status.is_success(),
            "password reminder continuation rejected: HTTP {}; no automatic retries",
            status.as_u16()
        );
        self.jar
            .set_cookies(&mut headers.get_all("set-cookie").iter(), &url);
        let reply: serde_json::Value = serde_json::from_slice(&reply)
            .map_err(|_| anyhow::anyhow!("Unsupported password reminder response"))?;
        if reply["result"] == "Challenge" && reply["type"] == "CHANGEPWD" {
            bail!(
                "password change required by gateway; user action required; no automatic retries"
            );
        }
        ensure!(
            reply["result"] == "Success",
            "password reminder continuation rejected: {}; no automatic retries",
            authentication_summary(reply["errorMsg"].as_str().unwrap_or(""))
        );
        self.cookie()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_password_challenges_are_continued() {
        for (result, kind, expected) in [
            ("Challenge", "PROMPTPWD", Some("PROMPTPWD")),
            ("Challenge", "CHANGEPWD", Some("CHANGEPWD")),
            ("Failed", "PROMPTPWD", None),
            ("Challenge", "SMS", None),
        ] {
            let xml = format!("<data><result>{result}</result><type>{kind}</type></data>");
            assert_eq!(
                challenge_type(&roxmltree::Document::parse(&xml).unwrap()),
                expected
            );
        }
    }
}
