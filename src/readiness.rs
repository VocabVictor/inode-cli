#[cfg(windows)]
pub async fn wait(device: &tun_rs::AsyncDevice, address: std::net::Ipv4Addr) -> anyhow::Result<()> {
    use anyhow::{bail, ensure};
    use std::time::Duration;
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{GetUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW},
        Networking::WinSock::{
            AF_INET, IN_ADDR, IN_ADDR_0, IpDadStateDuplicate, IpDadStatePreferred, SOCKADDR_IN,
            SOCKADDR_INET,
        },
    };
    let index = device.if_index()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: index,
            Address: SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(address.octets()),
                        },
                    },
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        // The initialized row identifies this live interface and IPv4 address;
        // Windows writes only within the supplied row for the duration of this call.
        let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
        if status == 0 {
            ensure!(
                row.DadState != IpDadStateDuplicate,
                "VPN IPv4 address is duplicated on this system"
            );
            if row.DadState == IpDadStatePreferred {
                return Ok(());
            }
        } else if status != 1168 {
            // ERROR_NOT_FOUND while the address is being registered.
            return Err(std::io::Error::from_raw_os_error(status as i32).into());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("VPN IPv4 address did not become ready");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(not(windows))]
pub async fn wait(_: &tun_rs::AsyncDevice, _: std::net::Ipv4Addr) -> anyhow::Result<()> {
    Ok(())
}
