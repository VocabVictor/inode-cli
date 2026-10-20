use inode_cli::protocol::{self, GatewayInfo, Session};
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

async fn exercise(kind: &'static str) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = format!("{:x}", Sha256::digest(cert.cert.der()));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = protocol::gateway(&format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        let steps = if kind == "PROMPTPWD" { 2 } else { 1 };
        for step in 0..steps {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                assert_eq!(tls.read(&mut byte).await.unwrap(), 1);
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap().to_lowercase();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            tls.read_exact(&mut body).await.unwrap();
            let (body, cookie) = if step == 0 {
                assert!(headers.starts_with("post /login "));
                (
                    format!(
                        "<data><result>Challenge</result><type>{kind}</type><message>Password update reminder</message></data>"
                    ),
                    "challenge=synthetic",
                )
            } else {
                assert!(headers.starts_with("post /wnm/login/login_result.json "));
                assert!(headers.contains("content-type: application/x-www-form-urlencoded"));
                assert!(headers.contains("challenge=synthetic"));
                let form: std::collections::HashMap<_, _> =
                    url::form_urlencoded::parse(&body).collect();
                assert_eq!(form.get("type").unwrap(), "PROMPTPWD");
                assert_eq!(form.get("password").unwrap(), "test&password");
                assert_eq!(form.get("user_name").unwrap(), "test-user");
                assert!(!form.contains_key("newpass"));
                (
                    r#"{"result":"Success"}"#.to_owned(),
                    "svpnginfo=synthetic-session",
                )
            };
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: {cookie}; Path=/; Secure\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            let _ = tls.shutdown().await;
        }
        if kind == "CHANGEPWD" {
            assert!(
                tokio::time::timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_err()
            );
        }
    });
    let session = Session::new(base.clone(), None, Some(&pin), Duration::from_secs(5)).unwrap();
    let info = GatewayInfo {
        login: base.join("/login").unwrap(),
        logout: None,
        extra_auth: false,
        auth_parameters: vec![],
        challenge: None,
        captcha: None,
    };
    let result = session.login(&info, "test-user", "test&password").await;
    if kind == "PROMPTPWD" {
        result.unwrap();
    } else {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("password change required")
        );
    }
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn optional_reminder_uses_official_continuation_and_existing_password() {
    exercise("PROMPTPWD").await;
}

#[tokio::test]
async fn mandatory_change_is_never_skipped_or_retried() {
    exercise("CHANGEPWD").await;
}
