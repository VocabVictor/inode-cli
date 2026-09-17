use crate::ConnectArgs;
use anyhow::{Context, Result, ensure};
use inode_cli::{
    platform::{self, Platform, Routes, SystemExecutor},
    protocol::{self, Frames, Session, TunnelParams},
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};

const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Ctrl+C/SIGTERM 只到达一次，转成一个可以在重连各阶段反复 select 的信号。
fn stop_signal() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        shutdown().await;
        let _ = tx.send(());
    });
    rx
}

pub(super) async fn connected(session: &Session, args: &ConnectArgs) -> Result<()> {
    let platform = platform::current()?;
    let host = session.gateway.host_str().unwrap();
    let addresses: Vec<_> =
        tokio::net::lookup_host((host, session.gateway.port_or_known_default().unwrap()))
            .await?
            .map(|s| s.ip())
            .collect();
    platform::validate_routes(&args.route, &addresses)?;
    let (stream, params, pending) = session.open_tunnel().await?;
    let address = params.address.context("Tunnel IPADDRESS header missing")?;
    announce(&params);
    let routes = requested_routes(args, &params)?;
    platform::validate_routes(&routes, &addresses)?;
    // /32 avoids automatically adding the gateway's advertised broad subnet.
    let mut builder = tun_rs::DeviceBuilder::new()
        .ipv4(address, 32, None)
        .mtu(args.mtu);
    if platform != Platform::Macos {
        builder = builder.name(format!("inode{}", std::process::id()));
    }
    #[cfg(target_os = "windows")]
    {
        let dll = std::env::current_exe()?
            .parent()
            .context("Executable directory missing")?
            .join("wintun.dll");
        ensure!(
            dll.is_file(),
            "Place the official architecture-matching wintun.dll next to inode.exe"
        );
        builder = builder.wintun_file(dll.to_string_lossy().into_owned());
    }
    let device = builder.build_async().context(
        "Cannot create VPN interface; administrator/root privileges and TUN driver are required",
    )?;
    let name = device.name()?;
    crate::readiness::wait(&device, address).await?;
    let _routes = Routes::install(platform, &name, &routes, SystemExecutor)?;
    eprintln!(
        "Tunnel ready: {name}, IP {address}. DNS/default route unchanged. Ctrl+C disconnects."
    );

    let mut stop = stop_signal();
    let mut current = Some((stream, pending));
    let mut failures = 0u32;
    loop {
        // 有活隧道就先跑它；隧道断了只记一次失败，然后落到下面的重连。
        if let Some((stream, pending)) = current.take() {
            let lost = tokio::select! {
                result = forward(&device, stream, pending, session.timeout) => result,
                _ = &mut stop => {eprintln!("Disconnecting."); return Ok(());}
            };
            let lost = match lost {
                Ok(()) => anyhow::anyhow!("VPN gateway disconnected"),
                Err(error) => error,
            };
            failures += 1;
            ensure!(
                failures <= args.reconnect_attempts,
                "{lost}; giving up after {} reconnect attempts",
                args.reconnect_attempts
            );
            let backoff = backoff(failures);
            eprintln!(
                "Tunnel lost: {lost:#}. Reconnect {failures}/{} in {}s.",
                args.reconnect_attempts,
                backoff.as_secs()
            );
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = &mut stop => {eprintln!("Disconnecting."); return Ok(());}
            }
        }
        // 复用已有会话 Cookie 重开隧道；接口和路由保持不动。
        // 重连本身失败也要继续退避重试，直到用尽 --reconnect-attempts。
        let opened = tokio::select! {
            result = session.open_tunnel() => result,
            _ = &mut stop => {eprintln!("Disconnecting."); return Ok(());}
        };
        let (stream, reassigned, pending) = match opened {
            Ok(tunnel) => tunnel,
            Err(error) => {
                failures += 1;
                ensure!(
                    failures <= args.reconnect_attempts,
                    "{error:#}; giving up after {} reconnect attempts",
                    args.reconnect_attempts
                );
                let backoff = backoff(failures);
                eprintln!(
                    "Reconnect failed: {error:#}. Retry {failures}/{} in {}s.",
                    args.reconnect_attempts,
                    backoff.as_secs()
                );
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = &mut stop => {eprintln!("Disconnecting."); return Ok(());}
                }
                continue;
            }
        };
        let reassigned = reassigned
            .address
            .context("Tunnel IPADDRESS header missing")?;
        ensure!(
            reassigned == address,
            "Gateway reassigned {reassigned} but the interface holds {address}; reconnect aborted"
        );
        failures = 0;
        eprintln!("Reconnected: {name}, IP {address}.");
        current = Some((stream, pending));
    }
}

/// 第 n 次失败的退避：1s 起翻倍，封顶 BACKOFF_MAX。
fn backoff(failures: u32) -> Duration {
    (BACKOFF_FIRST * 2u32.saturating_pow(failures.saturating_sub(1))).min(BACKOFF_MAX)
}

/// 打印网关在握手里下发的内容，便于确认该用哪些 --route。
fn announce(params: &TunnelParams) {
    if let Some(prefix) = params.prefix_len {
        eprintln!("Gateway assigned subnet mask /{prefix}.");
    }
    if !params.routes.is_empty() {
        let list: Vec<_> = params.routes.iter().map(|r| r.to_string()).collect();
        eprintln!("Gateway offers routes: {}", list.join(", "));
    }
    for entry in &params.unparsed_routes {
        eprintln!("Ignoring unparsable gateway route: {entry}");
    }
}

/// --route 永远优先；--gateway-routes 才会采用网关下发的网段，
/// 且两者都要通过同一套安全校验（不得是默认路由、不得捕获网关本身）。
fn requested_routes(args: &ConnectArgs, params: &TunnelParams) -> Result<Vec<ipnet::Ipv4Net>> {
    if !args.gateway_routes {
        return Ok(args.route.clone());
    }
    let mut routes = args.route.clone();
    for route in &params.routes {
        if !routes.contains(route) {
            routes.push(*route);
        }
    }
    ensure!(
        !routes.is_empty(),
        "Gateway advertised no usable routes; specify --route"
    );
    Ok(routes)
}

/// 在一条隧道上双向转发，直到链路出错或对端关闭。
async fn forward(
    device: &tun_rs::AsyncDevice,
    stream: protocol::Tunnel,
    pending: Vec<u8>,
    write_timeout: Duration,
) -> Result<()> {
    let (mut read, mut write) = tokio::io::split(stream);
    let receive = async {
        // 每条隧道都从干净的帧解码器开始，不继承上一条的半截帧。
        let mut decoder = Frames::default();
        for packet in decoder.feed(&pending)? {
            device.send(&packet).await?;
        }
        let mut buf = vec![0; 65536];
        loop {
            let n = read.read(&mut buf).await?;
            ensure!(n > 0, "VPN gateway disconnected");
            for packet in decoder.feed(&buf[..n])? {
                device.send(&packet).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let transmit = async {
        let mut buf = vec![0; 65535];
        loop {
            let n = device.recv(&mut buf).await?;
            if n == 0 || buf[0] >> 4 != 4 {
                continue;
            } // This protocol implementation is IPv4-only.
            let packet = protocol::frame(&buf[..n])?;
            tokio::time::timeout(write_timeout, write.write_all(&packet)).await??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = receive => result,
        result = transmit => result,
    }
}
