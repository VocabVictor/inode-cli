use anyhow::{Context, Result};
use std::net::UdpSocket;
use url::Url;

pub struct ClientInfo {
    pub os: &'static str,
    pub mac: String,
}

impl ClientInfo {
    pub async fn local(gateway: &Url) -> Result<Self> {
        let peer = tokio::net::lookup_host((
            gateway.host_str().context("Missing gateway host")?,
            gateway.port_or_known_default().unwrap(),
        ))
        .await?
        .next()
        .context("Gateway did not resolve")?;
        // UDP connect selects the local route without transmitting a datagram.
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.connect(peer)?;
        let source = socket.local_addr()?.ip();
        let interfaces: Vec<_> = getifaddrs::getifaddrs()?.collect();
        let index = interfaces
            .iter()
            .find(|i| i.address.ip_addr() == Some(source))
            .and_then(|i| i.index);
        let mac = interfaces.iter().find_map(|i| {
            if i.index == index && index.is_some() {
                i.address.mac_addr()
            } else {
                None
            }
        });
        let mac = mac
            .map(|m| {
                m.chunks(2)
                    .map(|pair| pair.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .unwrap_or_default();
        let os = match std::env::consts::OS {
            "windows" => "Windows",
            "macos" => "MacOS",
            "linux" => "Linux",
            other => other,
        };
        Ok(Self { os, mac })
    }
}
