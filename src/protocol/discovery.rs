use super::MAX_BODY;
use anyhow::{Context, Result, ensure};
use roxmltree::{Document, Node};
use url::Url;
use zeroize::Zeroizing;
#[derive(Clone, Debug)]
pub struct GatewayInfo {
    pub login: Url,
    pub logout: Option<Url>,
    pub extra_auth: bool,
    pub auth_parameters: Vec<(String, String)>,
    pub challenge: Option<Url>,
    pub captcha: Option<Url>,
}

pub fn gateway(value: &str) -> Result<Url> {
    ensure!(!value.chars().any(char::is_control), "Invalid gateway URL");
    let url = Url::parse(value).context("Expected https://hostname[:port]")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port() != Some(0),
        "Gateway must be HTTPS without credentials, path, query, or fragment"
    );
    Ok(url)
}

pub fn endpoint(base: &Url, value: &str) -> Result<Url> {
    ensure!(
        !value.chars().any(char::is_control),
        "Invalid gateway endpoint"
    );
    let url = base.join(value).context("Invalid gateway endpoint")?;
    ensure!(
        url.origin() == base.origin()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Gateway endpoint leaves the original HTTPS origin"
    );
    Ok(url)
}

pub(super) fn xml(body: &str) -> Result<Document<'_>> {
    ensure!(
        body.len() <= MAX_BODY && !body.contains("<!DOCTYPE") && !body.contains("<!ENTITY"),
        "Unsupported XML response"
    );
    Document::parse(body).map_err(|_| anyhow::anyhow!("Gateway response is not supported H3C XML"))
}

fn child_text<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|n| n.has_tag_name(name))
        .and_then(|n| n.text())
        .map(str::trim)
}

pub fn domain_endpoint(base: &Url, body: &str, domain: Option<&str>) -> Result<Option<Url>> {
    let doc = xml(body)?;
    let Some(list) = doc.descendants().find(|n| n.has_tag_name("domainlist")) else {
        return Ok(None);
    };
    let domains: Vec<_> = list
        .children()
        .filter(|n| n.has_tag_name("domain"))
        .collect();
    let selected: Vec<_> = domains
        .iter()
        .filter(|n| domain.is_none_or(|d| child_text(**n, "name") == Some(d)))
        .collect();
    ensure!(
        selected.len() == 1,
        "Select an exact VPN domain with --domain (missing or ambiguous domain)"
    );
    let value = child_text(**selected.first().unwrap(), "url").context("VPN domain URL missing")?;
    Ok(Some(endpoint(base, value)?))
}

pub fn gateway_info(base: &Url, body: &str) -> Result<GatewayInfo> {
    let doc = xml(body)?;
    let gw = doc
        .descendants()
        .find(|n| n.has_tag_name("gatewayinfo"))
        .context("No gatewayinfo; unsupported gateway variant")?;
    let urls = gw
        .children()
        .find(|n| n.has_tag_name("url"))
        .context("Gateway URL list missing")?;
    let auth = gw.children().find(|n| n.has_tag_name("auth"));
    let extra_auth = auth.is_some_and(|node| {
        node.descendants().filter(|n| n.is_element()).any(|n| {
            if ["false", "0", "no"].contains(&n.text().unwrap_or("").trim().to_lowercase().as_str())
            {
                return false;
            }
            let content =
                format!("{} {}", n.tag_name().name(), n.text().unwrap_or("")).to_lowercase();
            [
                "captcha",
                "vldimg",
                "verifycode",
                "sms",
                "totp",
                "saml",
                "rsa",
                "challenge",
            ]
            .iter()
            .any(|s| content.contains(s))
        })
    });
    let auth_parameters = auth
        .map(|node| {
            node.descendants()
                .filter(|n| n.is_element() && !n.children().any(|child| child.is_element()))
                .map(|n| {
                    (
                        n.tag_name().name().to_owned(),
                        n.text().unwrap_or("").trim().chars().take(200).collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(GatewayInfo {
        login: endpoint(
            base,
            child_text(urls, "login").context("Login endpoint missing")?,
        )?,
        logout: child_text(urls, "logout")
            .map(|v| endpoint(base, v))
            .transpose()?,
        extra_auth,
        auth_parameters,
        challenge: child_text(urls, "challenge")
            .map(|v| endpoint(base, v))
            .transpose()?,
        captcha: if child_text(auth.unwrap_or(gw), "supportvldimg") == Some("true") {
            child_text(urls, "vldimg")
                .map(|v| endpoint(base, v))
                .transpose()?
        } else {
            None
        },
    })
}

pub fn login_body(username: &str, password: &str) -> String {
    login_body_with_captcha(username, password, None)
}

fn native_url_encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => result.push(byte as char),
            b' ' => result.push('+'),
            _ => result.push_str(&format!("%{byte:02X}")),
        }
    }
    result
}

pub fn login_body_with_captcha(username: &str, password: &str, captcha: Option<&str>) -> String {
    login_body_with_client(username, password, captcha, None)
}

pub fn login_body_with_client(
    username: &str,
    password: &str,
    captcha: Option<&str>,
    client: Option<&super::ClientInfo>,
) -> String {
    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    let code = captcha
        .map(|v| format!("<vldCode>{}</vldCode>", escape(v)))
        .unwrap_or_default();
    let metadata = client
        .map(|c| {
            format!(
                "<language>EN</language><OS>{}</OS><macAddress>{}</macAddress><private>{}</private>",
                escape(c.os),
                escape(&c.mac),
                super::version::client_private()
            )
        })
        .unwrap_or_default();
    let xml = Zeroizing::new(format!(
        "<data><username>{}</username><password>{}</password>{code}{metadata}</data>\r\n",
        escape(username),
        escape(&Zeroizing::new(native_url_encode(password)))
    ));
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("request", &xml)
        .finish()
}

pub fn login_succeeded(body: &str) -> Result<bool> {
    let doc = xml(body)?;
    Ok(doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("result"))
        .and_then(|n| n.text())
        .is_some_and(|s| s.trim() == "Success"))
}
