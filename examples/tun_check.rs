//! Explicit, privileged kernel TUN check using the documentation-only test network.
use anyhow::{Context, Result, ensure};
use inode_cli::platform::{self, Platform, Routes, SystemExecutor};
use std::{process::Command, time::Duration};

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

#[tokio::main]
async fn main() -> Result<()> {
    let os = platform::current()?;
    let mut builder = tun_rs::DeviceBuilder::new()
        .ipv4("192.0.2.1", 32, None)
        .mtu(1400);
    if os != Platform::Macos {
        builder = builder.name(format!("inodecheck{}", std::process::id()));
    }
    #[cfg(windows)]
    {
        let dll = std::env::current_exe()?
            .parent()
            .context("Missing executable parent")?
            .join("wintun.dll");
        builder = builder.wintun_file(dll.to_string_lossy().into_owned());
    }
    let device = builder.build_async().context("TUN creation failed")?;
    let name = device.name()?;
    let routes = Routes::install(os, &name, &["192.0.2.2/32".parse()?], SystemExecutor)?;
    // Allow duplicate-address detection to settle before emitting the first packet.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ping = tokio::task::spawn_blocking(move || {
        let args = if os == Platform::Windows {
            vec!["-n", "1", "-w", "10000", "192.0.2.2"]
        } else if os == Platform::Macos {
            vec!["-c", "1", "-W", "10000", "192.0.2.2"]
        } else {
            vec!["-c", "1", "-W", "10", "192.0.2.2"]
        };
        Command::new("ping").args(args).output()
    });
    let exchange = async {
        let mut packet = vec![0; 65535];
        loop {
            let n = device.recv(&mut packet).await?;
            if n < 28 || packet[0] >> 4 != 4 || packet[9] != 1 {
                continue;
            }
            let ihl = ((packet[0] & 15) * 4) as usize;
            if n < ihl + 8 || packet[ihl] != 8 || packet[16..20] != [192, 0, 2, 2] {
                continue;
            }
            let from = packet[12..16].to_vec();
            packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
            packet[16..20].copy_from_slice(&from);
            packet[ihl] = 0;
            packet[ihl + 2..ihl + 4].fill(0);
            let icmp = checksum(&packet[ihl..n]);
            packet[ihl + 2..ihl + 4].copy_from_slice(&icmp.to_be_bytes());
            packet[10..12].fill(0);
            let ip = checksum(&packet[..ihl]);
            packet[10..12].copy_from_slice(&ip.to_be_bytes());
            device.send(&packet[..n]).await?;
            return Ok::<_, anyhow::Error>(());
        }
    };
    let exchange = tokio::time::timeout(Duration::from_secs(15), exchange).await;
    // Ping on Unix has no deadline on some implementations; avoid an indefinite join.
    let status = tokio::time::timeout(Duration::from_secs(3), ping).await;
    drop(routes);
    drop(device);
    exchange??;
    ensure!(status???.status.success(), "Kernel rejected the ICMP reply");
    println!("Kernel TUN roundtrip passed; interface {name} dropped and test route removed");
    Ok(())
}
