use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use std::{net::IpAddr, process::Command};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Platform {
    Linux,
    Windows,
    Macos,
}

pub fn current() -> Result<Platform> {
    match std::env::consts::OS {
        "linux" => Ok(Platform::Linux),
        "windows" => Ok(Platform::Windows),
        "macos" => Ok(Platform::Macos),
        _ => anyhow::bail!("Unsupported operating system"),
    }
}

pub fn validate_routes(routes: &[Ipv4Net], gateways: &[IpAddr]) -> Result<()> {
    for route in routes {
        ensure!(
            route.prefix_len() != 0,
            "Default route is not supported; choose internal CIDRs using --route"
        );
        ensure!(
            route.addr() == route.network(),
            "Route must be a network address: {route}"
        );
        ensure!(
            !gateways.iter().any(|ip| match ip {
                IpAddr::V4(ip) => route.contains(ip),
                _ => false,
            }),
            "Route {route} would capture the VPN gateway itself"
        );
    }
    Ok(())
}

pub fn route_command(platform: Platform, add: bool, network: Ipv4Net, name: &str) -> Vec<String> {
    let op = if add { "add" } else { "delete" };
    match platform {
        Platform::Linux => vec![
            "ip".into(),
            "route".into(),
            op.into(),
            network.to_string(),
            "dev".into(),
            name.into(),
        ],
        Platform::Windows => vec![
            "netsh.exe".into(),
            "interface".into(),
            "ipv4".into(),
            op.into(),
            "route".into(),
            format!("prefix={network}"),
            format!("interface={name}"),
            "store=active".into(),
        ],
        Platform::Macos => vec![
            "/sbin/route".into(),
            "-n".into(),
            op.into(),
            "-net".into(),
            network.to_string(),
            "-interface".into(),
            name.into(),
        ],
    }
}

pub trait Executor {
    fn execute(&mut self, args: &[String]) -> Result<()>;
}
pub struct SystemExecutor;
impl Executor for SystemExecutor {
    fn execute(&mut self, args: &[String]) -> Result<()> {
        let output = Command::new(&args[0])
            .args(&args[1..])
            .output()
            .context("Unable to run route tool")?;
        ensure!(
            output.status.success(),
            "Route command failed; check administrator privileges or existing route conflicts"
        );
        Ok(())
    }
}

pub struct Routes<E: Executor> {
    platform: Platform,
    name: String,
    added: Vec<Ipv4Net>,
    executor: E,
}
impl<E: Executor> Routes<E> {
    pub fn install(
        platform: Platform,
        name: &str,
        networks: &[Ipv4Net],
        executor: E,
    ) -> Result<Self> {
        let mut routes = Self {
            platform,
            name: name.into(),
            added: Vec::new(),
            executor,
        };
        for &network in networks {
            if routes.added.contains(&network) {
                continue;
            }
            routes
                .executor
                .execute(&route_command(platform, true, network, name))?;
            routes.added.push(network);
        }
        Ok(routes)
    }
}
impl<E: Executor> Drop for Routes<E> {
    fn drop(&mut self) {
        for &network in self.added.iter().rev() {
            if self
                .executor
                .execute(&route_command(self.platform, false, network, &self.name))
                .is_err()
            {
                eprintln!(
                    "Warning: failed removing route {network} on {}; inspect it manually",
                    self.name
                );
            }
        }
    }
}
