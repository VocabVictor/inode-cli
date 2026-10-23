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
        let reply = parse_reply(&reply).ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported password reminder response: {}",
                describe(&headers, &reply)
            )
        })?;
        if reply.result == "Challenge" && reply.kind == "CHANGEPWD" {
            bail!(
                "password change required by gateway; user action required; no automatic retries"
            );
        }
        ensure!(
            reply.result == "Success",
            "password reminder continuation rejected: {}; no automatic retries",
            authentication_summary(&reply.message)
        );
        self.cookie()?;
        Ok(())
    }
}

struct Reply {
    result: String,
    kind: String,
    message: String,
}

// The web page receives JSON; some gateways answer the client with the XML login format.
fn parse_reply(body: &[u8]) -> Option<Reply> {
    let text = std::str::from_utf8(body)
        .ok()?
        .trim_start_matches('\u{feff}')
        .trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        let get = |k: &str| v[k].as_str().unwrap_or("").to_owned();
        return Some(Reply {
            result: get("result"),
            kind: get("type"),
            message: get("errorMsg"),
        });
    }
    let doc = super::discovery::xml(text).ok()?;
    let field = |name: &str| {
        doc.root_element()
            .children()
            .find(|n| n.has_tag_name(name))
            .and_then(|n| n.text())
            .map(|s| s.trim().to_owned())
    };
    Some(Reply {
        result: field("result")?,
        kind: field("type").unwrap_or_default(),
        message: super::errors::response_message(&doc),
    })
}

// Never echo the body: it can carry credentials or session cookies.
fn describe(headers: &hyper::HeaderMap, body: &[u8]) -> String {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");
    let start = body
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .map(|b| {
            if b.is_ascii_graphic() {
                (*b as char).to_string()
            } else {
                format!("0x{b:02x}")
            }
        })
        .unwrap_or_else(|| "empty".into());
    let html = String::from_utf8_lossy(&body[..body.len().min(512)])
        .to_ascii_lowercase()
        .contains("<html");
    format!(
        "content-type={content_type}, {} bytes, starts with {start}, html={html}",
        body.len()
    )
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

    #[test]
    fn continuation_reply_accepts_json_and_xml() {
        for body in [
            &br#"{"result":"Success"}"#[..],
            b"\xef\xbb\xbf<data><result>Success</result></data>\r\n",
            b"  <data><result> Success </result><type></type></data>",
        ] {
            assert_eq!(parse_reply(body).unwrap().result, "Success");
        }
        let change =
            parse_reply(b"<data><result>Challenge</result><type>CHANGEPWD</type></data>").unwrap();
        assert_eq!(
            (change.result.as_str(), change.kind.as_str()),
            ("Challenge", "CHANGEPWD")
        );
        assert!(parse_reply(b"<html><body>error</body></html>").is_none());
        assert!(parse_reply(b"").is_none());
    }
}
