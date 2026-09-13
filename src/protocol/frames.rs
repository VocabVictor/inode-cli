use anyhow::{Context, Result, ensure};
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
pub async fn read_handshake<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Ipv4Addr, Vec<u8>)> {
    let mut data = Vec::new();
    let end = loop {
        if let Some(i) = data.windows(4).position(|s| s == b"\r\n\r\n") {
            break i;
        }
        ensure!(data.len() < 65536, "Tunnel headers too large");
        let mut buf = [0; 4096];
        let n = stream.read(&mut buf).await?;
        ensure!(n != 0, "Gateway closed tunnel handshake");
        data.extend_from_slice(&buf[..n]);
    };
    let headers = std::str::from_utf8(&data[..end]).context("Invalid tunnel headers")?;
    let mut lines = headers.split("\r\n");
    let status: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    ensure!(
        status.len() >= 2 && ["HTTP/1.0", "HTTP/1.1"].contains(&status[0]) && status[1] == "200",
        "NET_EXTEND rejected"
    );
    let mut address = None;
    for line in lines {
        let (key, val) = line.split_once(':').context("Malformed tunnel header")?;
        if key.eq_ignore_ascii_case("IPADDRESS") {
            ensure!(address.is_none(), "Duplicate tunnel IP address");
            address = Some(
                val.trim()
                    .parse::<Ipv4Addr>()
                    .context("Invalid assigned IPv4 address")?,
            );
        }
    }
    Ok((
        address.context("Tunnel IPADDRESS header missing")?,
        data[end + 4..].to_vec(),
    ))
}

#[derive(Default)]
pub struct Frames {
    buffer: Vec<u8>,
}

impl Frames {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.buffer.extend_from_slice(data);
        let mut used = 0;
        let mut packets = Vec::new();
        while self.buffer.len() - used >= 4 {
            let b = &self.buffer[used..];
            ensure!(b[0..2] == [1, 0], "Unsupported H3C frame type");
            let len = u16::from_be_bytes([b[2], b[3]]) as usize;
            ensure!(len >= 20, "Invalid H3C frame length");
            if b.len() < len + 4 {
                break;
            }
            validate_ipv4(&b[4..len + 4])?;
            packets.push(b[4..len + 4].to_vec());
            used += len + 4;
        }
        self.buffer.drain(..used);
        ensure!(self.buffer.len() <= 65539, "Tunnel receive buffer exceeded");
        Ok(packets)
    }
}

fn validate_ipv4(packet: &[u8]) -> Result<()> {
    ensure!(
        packet.len() >= 20 && packet.len() <= 65535 && packet[0] >> 4 == 4,
        "Only valid IPv4 packets are supported"
    );
    let header_len = usize::from(packet[0] & 15) * 4;
    ensure!(
        header_len >= 20
            && header_len <= packet.len()
            && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len(),
        "Malformed IPv4 packet"
    );
    Ok(())
}

pub fn frame(packet: &[u8]) -> Result<Vec<u8>> {
    validate_ipv4(packet)?;
    let mut b = vec![1, 0];
    b.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    b.extend_from_slice(packet);
    Ok(b)
}
