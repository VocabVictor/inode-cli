use crate::ConnectArgs;
use anyhow::{Context, Result, ensure};
use inode_cli::{
    platform::{self, Platform, Routes, SystemExecutor},
    protocol::{self, Frames, Session},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub(super) async fn connected(session: &Session, args: &ConnectArgs) -> Result<()> {
    let platform = platform::current()?;
    let host = session.gateway.host_str().unwrap();
    let addresses: Vec<_> =
        tokio::net::lookup_host((host, session.gateway.port_or_known_default().unwrap()))
            .await?
            .map(|s| s.ip())
            .collect();
    platform::validate_routes(&args.route, &addresses)?;
    let (stream, address, pending) = session.open_tunnel().await?;
    // /32 avoids automatically adding the gateway's advertised broad subnet.
    let mut builder = tun_rs::DeviceBuilder::new()
        .ipv4(address, 32, None)
        .mtu(1400);
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
    let _routes = Routes::install(platform, &name, &args.route, SystemExecutor)?;
    eprintln!(
        "Tunnel ready: {name}, IP {address}. DNS/default route unchanged. Ctrl+C disconnects."
    );
    let (mut read, mut write) = tokio::io::split(stream);
    let receive = async {
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
            tokio::time::timeout(session.timeout, write.write_all(&packet)).await??;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = receive => result,
        result = transmit => result,
        _ = shutdown() => {eprintln!("Disconnecting."); Ok(())}
    }
}
