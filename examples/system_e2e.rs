//! Privileged full CLI/kernel/TLS test against a local, synthetic H3C gateway.
use anyhow::{Context, Result, ensure};
use inode_cli::protocol::{Frames, frame};
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
    sync::oneshot,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

async fn gateway(
    listener: TcpListener,
    accept: TlsAcceptor,
    done: oneshot::Receiver<()>,
) -> Result<()> {
    let mut done = Some(done);
    for step in 0..4 {
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
        if step == 2 {
            ensure!(header.starts_with("NET_EXTEND /"), "Missing tunnel request");
            ensure!(header.contains("svpnginfo=synthetic"), "Missing session");
            tls.write_all(b"HTTP/1.1 200 OK\r\nIPADDRESS: 192.0.2.1\r\n\r\n")
                .await?;
            let mut decoder = Frames::default();
            let mut buf = vec![0; 65536];
            'packets: loop {
                let n = tls.read(&mut buf).await?;
                ensure!(n != 0, "Tunnel ended without ICMP");
                for mut p in decoder.feed(&buf[..n])? {
                    let ihl = (p[0] & 15) as usize * 4;
                    if p.len() < ihl + 8 || p[9] != 1 || p[ihl] != 8 {
                        continue;
                    }
                    ensure!(p[16..20] == [192, 0, 2, 2], "Unexpected test destination");
                    let from = p[12..16].to_vec();
                    p[12..16].copy_from_slice(&[192, 0, 2, 2]);
                    p[16..20].copy_from_slice(&from);
                    p[ihl] = 0;
                    p[ihl + 2..ihl + 4].fill(0);
                    let c = checksum(&p[ihl..]);
                    p[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
                    p[10..12].fill(0);
                    let c = checksum(&p[..ihl]);
                    p[10..12].copy_from_slice(&c.to_be_bytes());
                    let wire = frame(&p)?;
                    // Exercise framing across real TLS reads, not only an in-memory parser.
                    for chunk in wire.chunks(3) {
                        tls.write_all(chunk).await?;
                    }
                    tls.flush().await?;
                    break 'packets;
                }
            }
            tokio::time::timeout(Duration::from_secs(20), done.take().unwrap()).await??;
            // Remote disconnect must trigger CLI route/interface cleanup and logout.
            tls.shutdown().await?;
            continue;
        }
        let (response, cookie) = match step {
            0 => {
                ensure!(
                    header.starts_with("GET /svpn/index.cgi"),
                    "Missing discovery"
                );
                (
                    "<data><gatewayinfo><auth><supportPassword>true</supportPassword></auth><url><login>/login</login><logout>/logout</logout></url></gatewayinfo></data>",
                    "",
                )
            }
            1 => {
                ensure!(header.starts_with("POST /login"), "Missing login");
                let form: Vec<_> = url::form_urlencoded::parse(&body).collect();
                let doc = roxmltree::Document::parse(&form[0].1)?;
                // 真实网关收到的密码经过 H3C 的逐字节 URL 编码（见
                // protocol::discovery 的 native_url_encode），连字符会变成 %2D。
                // 这里比对编码后的形式，顺带验证 CLI 确实做了这层编码。
                let submitted = doc
                    .descendants()
                    .find(|n| n.has_tag_name("password"))
                    .and_then(|n| n.text());
                ensure!(
                    submitted == Some("synthetic%2Dtest%2Dpassword"),
                    "Wrong synthetic password: {submitted:?}"
                );
                (
                    "<data><result>Success</result></data>",
                    "Set-Cookie: svpnginfo=synthetic; Path=/; Secure\r\n",
                )
            }
            3 => {
                ensure!(header.starts_with("GET /logout"), "Missing logout");
                ("<data/>", "")
            }
            _ => unreachable!(),
        };
        tls.write_all(format!("HTTP/1.1 200 OK\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await?;
        let _ = tls.shutdown().await;
    }
    Ok(())
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
    let (done_tx, done_rx) = oneshot::channel();
    let mut server = tokio::spawn(gateway(
        listener,
        TlsAcceptor::from(Arc::new(config)),
        done_rx,
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
            // 这个测试断言的是「远端断开 -> 回收接口和路由 -> 注销」，
            // 所以显式关掉重连；重连路径由 reconnect_e2e 覆盖。
            "--reconnect-attempts",
            "0",
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
    let (ready_tx, ready_rx) = oneshot::channel();
    let output = std::thread::spawn(move || {
        let mut ready = Some(ready_tx);
        let mut log = String::new();
        for line in BufReader::new(stderr)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if line.contains("Tunnel ready:")
                && let Some(tx) = ready.take()
            {
                let _ = tx.send(());
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });
    let readiness = tokio::time::timeout(Duration::from_secs(45), ready_rx).await;
    if !matches!(readiness, Ok(Ok(()))) {
        let _ = child.kill();
        let _ = child.wait();
        server.abort();
        // 模拟网关的断言失败只会关掉连接，CLI 只看得到「连接被关闭」，
        // 所以这里把服务端自己的错误也捞出来一起报。
        let gateway_error =
            match tokio::time::timeout(Duration::from_millis(500), &mut server).await {
                Ok(Ok(Err(error))) => format!("synthetic gateway failed: {error:#}"),
                Ok(Err(error)) => format!("synthetic gateway panicked: {error}"),
                _ => "synthetic gateway was still waiting".to_owned(),
            };
        anyhow::bail!(
            "CLI failed before tunnel readiness: {}; {gateway_error}",
            output.join().unwrap_or_default()
        );
    }
    let ping = tokio::task::spawn_blocking(|| {
        let args = if cfg!(windows) {
            vec!["-n", "1", "-w", "10000", "192.0.2.2"]
        } else if cfg!(target_os = "macos") {
            vec!["-c", "1", "-W", "10000", "192.0.2.2"]
        } else {
            vec!["-c", "1", "-W", "10", "192.0.2.2"]
        };
        Command::new("ping").args(args).output()
    })
    .await??;
    let _ = done_tx.send(());
    if !ping.status.success() {
        server.abort();
    }
    let result = tokio::time::timeout(Duration::from_secs(20), server).await;
    let status = child.wait()?;
    let log = output.join().unwrap_or_default();
    ensure!(
        ping.status.success(),
        "System ping through CLI/TLS failed: {log}; ping: {}",
        String::from_utf8_lossy(&ping.stdout)
    );
    result???;
    ensure!(
        status.code() == Some(2) && log.contains("VPN gateway disconnected"),
        "Unexpected CLI disconnect behavior: {log}"
    );
    println!(
        "Full CLI E2E passed: login -> real TUN -> TLS ICMP roundtrip -> gateway disconnect -> logout. Verify no inode interface/test route remains."
    );
    Ok(())
}
