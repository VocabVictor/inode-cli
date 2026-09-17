//! Privileged test: the gateway drops an established tunnel and the CLI must
//! rebuild it from the existing session cookie, without touching the interface.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

/// 记录网关侧看到的每一步，供断言使用。
#[derive(Debug, PartialEq)]
enum Seen {
    Discovery,
    Login,
    Tunnel,
}

async fn gateway(
    listener: TcpListener,
    accept: TlsAcceptor,
    seen: mpsc::Sender<Seen>,
) -> Result<()> {
    let mut tunnels = 0usize;
    loop {
        let (tcp, _) = listener.accept().await?;
        let mut tls = accept.accept(tcp).await?;
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 65536, "Oversized request");
            tls.read_exact(&mut byte).await?;
            header.push(byte[0]);
        }
        let header = String::from_utf8(header)?;
        let length: usize = header
            .lines()
            .find_map(|l| {
                l.to_lowercase()
                    .strip_prefix("content-length:")
                    .map(|n| n.trim().parse().unwrap())
            })
            .unwrap_or(0);
        ensure!(length < 65536, "Oversized body");
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await?;

        if header.starts_with("NET_EXTEND /") {
            ensure!(
                header.contains("svpnginfo=synthetic"),
                "Tunnel lost the session cookie"
            );
            tunnels += 1;
            seen.send(Seen::Tunnel).await?;
            if tunnels == 2 {
                // 拒绝第一次重连：客户端必须继续退避重试，而不是就此放弃。
                // 这条路径曾经踩到 current 已被 take 的空洞，直接以
                // "Tunnel stream missing" 退出，真实网关上把 5 次重试变成 1 次。
                drop(tls);
                continue;
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nIPADDRESS: 192.0.2.1\r\n\r\n")
                .await?;
            if tunnels == 1 {
                // 立刻掐断已经建立的隧道，模拟弱网/网关回收。
                tls.shutdown().await?;
                continue;
            }
            // 第二条隧道保持打开，让 CLI 稳定在重连后的状态。
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        let (response, cookie) = if header.starts_with("GET /svpn/index.cgi") {
            seen.send(Seen::Discovery).await?;
            (
                "<data><gatewayinfo><auth><supportPassword>true</supportPassword></auth><url><login>/login</login><logout>/logout</logout></url></gatewayinfo></data>",
                "",
            )
        } else if header.starts_with("POST /login") {
            let form: Vec<_> = url::form_urlencoded::parse(&body).collect();
            let doc = roxmltree::Document::parse(&form[0].1)?;
            let submitted = doc
                .descendants()
                .find(|n| n.has_tag_name("password"))
                .and_then(|n| n.text());
            // 密码经过 H3C 的逐字节 URL 编码，连字符变成 %2D。
            ensure!(
                submitted == Some("synthetic%2Dtest%2Dpassword"),
                "Wrong synthetic password: {submitted:?}"
            );
            seen.send(Seen::Login).await?;
            (
                "<data><result>Success</result></data>",
                "Set-Cookie: svpnginfo=synthetic; Path=/; Secure\r\n",
            )
        } else if header.starts_with("GET /logout") {
            ("<data/>", "")
        } else {
            bail!(
                "Unexpected request: {}",
                header.lines().next().unwrap_or("")
            );
        };
        tls.write_all(format!("HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await?;
        let _ = tls.shutdown().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let binary = std::env::args()
        .nth(1)
        .context("Pass the inode binary path")?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
    let pin = format!("{:x}", Sha256::digest(cert.cert.der()));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("https://localhost:{}", listener.local_addr()?.port());
    let (seen_tx, mut seen) = mpsc::channel(16);
    let server = tokio::spawn(gateway(
        listener,
        TlsAcceptor::from(Arc::new(config)),
        seen_tx,
    ));

    let mut child = Command::new(binary)
        .args([
            "connect",
            &url,
            "--servercert",
            &pin,
            "--user",
            "synthetic",
            "--password-stdin",
            "--route",
            "192.0.2.2/32",
            "--reconnect-attempts",
            "3",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-test-password\n")?;

    let stderr = child.stderr.take().unwrap();
    let (log_tx, mut reconnected) = mpsc::channel(16);
    let output = std::thread::spawn(move || {
        let mut log = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.starts_with("Reconnected:") {
                let _ = log_tx.blocking_send(line.clone());
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });

    let verdict = tokio::time::timeout(Duration::from_secs(60), async {
        // 首次连接：发现 -> 登录 -> 隧道，然后网关掐断第一条隧道。
        for expected in [Seen::Discovery, Seen::Login, Seen::Tunnel] {
            let step = seen.recv().await.context("Gateway stopped early")?;
            ensure!(step == expected, "Expected {expected:?}, saw {step:?}");
        }
        // 重连必须复用会话 Cookie 重开隧道，而不是重新登录。
        // 第一次重连被网关拒绝，客户端要继续重试并在第二次成功。
        for attempt in 1..=2 {
            let step = seen.recv().await.context("No reconnect arrived")?;
            ensure!(
                step == Seen::Tunnel,
                "Reconnect {attempt} should reuse the session, but the CLI sent {step:?}"
            );
        }
        let line = reconnected
            .recv()
            .await
            .context("CLI never reported a reconnect")?;
        Ok::<String, anyhow::Error>(line)
    })
    .await;

    let _ = child.kill();
    let _ = child.wait();
    server.abort();
    let log = output.join().unwrap_or_default();
    match verdict {
        Ok(Ok(line)) => {
            println!("Reconnect E2E passed: gateway dropped the tunnel, CLI recovered it.");
            println!("CLI reported: {line}");
            Ok(())
        }
        Ok(Err(error)) => bail!("{error:#}; CLI log:\n{log}"),
        Err(_) => bail!("Timed out waiting for the reconnect; CLI log:\n{log}"),
    }
}
