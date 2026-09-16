use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use inode_cli::{
    platform::{self, Platform},
    protocol::{self, Session},
};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    time::Duration,
};
mod captcha;
mod connection;
mod readiness;
use connection::connected;
use inode_cli::captcha_cnn;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "inode",
    version,
    about = "Experimental H3C SSL VPN CLI for Windows, Linux and macOS"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Inspect local prerequisites, without changing network configuration.
    Doctor,
    /// Discover gateway protocol without submitting credentials.
    Probe(GatewayArgs),
    /// Authenticate once and log out, without creating a TUN interface.
    Authenticate(LoginArgs),
    /// Connect in foreground; Ctrl+C removes this connection's interface/routes.
    Connect(ConnectArgs),
    /// [test] Recognize a CAPTCHA image file with the embedded CNN.
    CaptchaTest { file: PathBuf },
}
#[derive(Args)]
struct GatewayArgs {
    /// HTTPS VPN gateway (no path), e.g. https://vpn.example.com:443.
    gateway: String,
    /// Trusted organization CA certificate in PEM format.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Exact trusted server certificate SHA-256 fingerprint (64 hex characters).
    #[arg(long)]
    servercert: Option<String>,
    #[arg(long)]
    domain: Option<String>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=120))]
    timeout: u64,
}
#[derive(Args)]
struct LoginArgs {
    #[command(flatten)]
    gateway: GatewayArgs,
    #[arg(long)]
    user: Option<String>,
    /// Read one password line from stdin instead of the terminal (automation).
    #[arg(long)]
    password_stdin: bool,
    /// Optionally save CAPTCHA; interactive terminals display it directly.
    #[arg(long)]
    captcha_file: Option<PathBuf>,
    /// Width of the inline color CAPTCHA in terminal columns.
    #[arg(long, default_value_t = 96, value_parser = clap::value_parser!(u32).range(40..=160))]
    captcha_columns: u32,
    /// Solve the CAPTCHA manually (default: automatic on-device recognition).
    #[arg(long)]
    manual_captcha: bool,
    /// Minimum confidence to submit an auto-recognized CAPTCHA (0-1).
    #[arg(long, default_value_t = 0.90)]
    captcha_confidence: f32,
}
#[derive(Args)]
struct ConnectArgs {
    #[command(flatten)]
    login: LoginArgs,
    /// Internal IPv4 network; repeat for more networks. DNS/default route are unchanged.
    #[arg(long)]
    route: Vec<Ipv4Net>,
}

fn session(args: &GatewayArgs) -> Result<Session> {
    let ca = args
        .ca
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("Unable to read CA file")?;
    Session::new(
        protocol::gateway(&args.gateway)?,
        ca.as_deref(),
        args.servercert.as_deref(),
        Duration::from_secs(args.timeout),
    )
}

fn credentials(args: &LoginArgs) -> Result<(String, Zeroizing<String>)> {
    let username = if let Some(user) = &args.user {
        user.clone()
    } else {
        ensure!(!args.password_stdin, "--password-stdin requires --user");
        print!("Username: ");
        io::stdout().flush()?;
        let mut user = String::new();
        io::stdin().read_line(&mut user)?;
        user.trim().to_owned()
    };
    ensure!(
        !username.is_empty() && !username.chars().any(char::is_control),
        "Invalid username"
    );
    let password = if args.password_stdin {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        ensure!(line.len() <= 4096, "Password input too long");
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        line
    } else {
        rpassword::prompt_password("Password: ")?
    };
    ensure!(!password.is_empty(), "Password is required");
    Ok((username, Zeroizing::new(password)))
}

async fn login(args: &LoginArgs, connect: Option<&ConnectArgs>) -> Result<()> {
    let s = session(&args.gateway)?;
    let info = s.discover(args.gateway.domain.as_deref()).await?;
    ensure!(
        !info.extra_auth || info.captcha.is_some(),
        "Gateway requires unsupported SMS/SSO authentication"
    );
    if let Some(connect) = connect {
        let ips: Vec<_> = tokio::net::lookup_host((
            s.gateway.host_str().unwrap(),
            s.gateway.port_or_known_default().unwrap(),
        ))
        .await?
        .map(|s| s.ip())
        .collect();
        platform::validate_routes(&connect.route, &ips)?;
    }
    let (user, password) = credentials(args)?;
    if info.captcha.is_some() && !args.manual_captcha {
        // 全自动：内嵌 CNN 识别 + 置信门控 + 免费换图（抓图不限次，提交上限 3 防锁定）
        s.login_auto(&info, &user, &password, args.captcha_confidence, 60, 3)
            .await?;
    } else {
        let captcha = if let Some(url) = &info.captcha {
            let bytes = s.request_bytes(url.clone(), None, false).await?;
            ensure!(
                bytes.starts_with(b"\x89PNG")
                    || bytes.starts_with(b"GIF8")
                    || bytes.starts_with(b"\xff\xd8")
                    || bytes.starts_with(b"BM"),
                "Gateway did not return a supported CAPTCHA image"
            );
            captcha::display(&bytes, args.captcha_file.as_deref(), args.captcha_columns)?;
            print!("CAPTCHA: ");
            io::stdout().flush()?;
            let mut code = String::new();
            io::stdin().read_line(&mut code)?;
            ensure!(!code.trim().is_empty(), "CAPTCHA is required");
            Some(code.trim().to_owned())
        } else {
            None
        };
        s.login_with_captcha(&info, &user, &password, captcha.as_deref())
            .await?;
    }
    drop(password);
    let result = if let Some(args) = connect {
        connected(&s, args).await
    } else {
        println!("Authentication succeeded. No interface or routes created.");
        Ok(())
    };
    s.logout(&info).await;
    result
}

#[derive(Serialize)]
struct Health {
    os: &'static str,
    arch: &'static str,
    tun_driver_available: bool,
    note: &'static str,
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Doctor => {
            let platform = platform::current()?;
            let available = match platform {
                Platform::Linux => std::path::Path::new("/dev/net/tun").exists(),
                Platform::Macos => true,
                Platform::Windows => std::env::current_exe()?
                    .parent()
                    .unwrap()
                    .join("wintun.dll")
                    .is_file(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&Health {
                    os: std::env::consts::OS,
                    arch: std::env::consts::ARCH,
                    tun_driver_available: available,
                    note: "Connect needs administrator/root. Doctor does not prove VPN connectivity or driver loadability."
                })?
            );
            ensure!(available, "TUN prerequisites missing");
        }
        Commands::Probe(args) => {
            let s = session(&args)?;
            let info = s.discover(args.domain.as_deref()).await?;
            println!(
                "{}",
                serde_json::json!({"h3c_gatewayinfo": true, "extra_auth_advertised": info.extra_auth,
                "captcha_supported": info.captcha.is_some(), "authenticated": false, "auth_parameters": info.auth_parameters})
            );
        }
        Commands::Authenticate(args) => login(&args, None).await?,
        Commands::Connect(args) => login(&args.login, Some(&args)).await?,
        Commands::CaptchaTest { file } => {
            let bytes = std::fs::read(&file)?;
            match captcha_cnn::Model::load().solve(&bytes) {
                Some((s, c)) => println!("{s}\t{c:.3}"),
                None => println!("<no-4-glyphs>\t0"),
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("Error: {error:#}");
        std::process::exit(2);
    }
}
