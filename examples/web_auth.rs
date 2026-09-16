use anyhow::{Context, Result, ensure};
use inode_cli::protocol::{Session, endpoint, gateway};
use std::{
    io::{self, Write},
    time::Duration,
};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let base = gateway(&args[1])?;
    let s = Session::new(base.clone(), None, Some(&args[2]), Duration::from_secs(15))?;
    let info = s.discover(None).await?;
    let config = s
        .request(endpoint(&base, "/wnm/login/login.json")?, None, false)
        .await?;
    let config: serde_json::Value = serde_json::from_str(&config)?;
    ensure!(
        config["BrowsersDenied"] != "true",
        "Web authentication disallowed"
    );
    let password = Zeroizing::new(rpassword::prompt_password("Password: ")?);
    let captcha = s
        .request_bytes(info.captcha.clone().context("No CAPTCHA URL")?, None, false)
        .await?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[4])?;
    file.write_all(&captcha)?;
    println!("CAPTCHA saved: {}", args[4]);
    print!("CAPTCHA: ");
    io::stdout().flush()?;
    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("user_name", &args[3])
        .append_pair("password", &password)
        .append_pair("browser", "Chrome")
        .append_pair("vldcode", code.trim())
        .finish();
    let result = s
        .request(
            endpoint(&base, "/wnm/login/login_result.json")?,
            Some(body),
            false,
        )
        .await?;
    let result: serde_json::Value = serde_json::from_str(&result)?;
    let success = result["result"] == "Success";
    println!("Web authentication success: {success}");
    if !success {
        let msg = result["errorMsg"].as_str().unwrap_or("").to_lowercase();
        println!(
            "Error classification: captcha={}, password={}, locked={}",
            msg.contains("code") || msg.contains("验证码"),
            msg.contains("password") || msg.contains("密码"),
            msg.contains("lock")
        );
        return Ok(());
    }
    let tunnel = s.open_tunnel().await;
    s.logout(&info).await;
    let (_stream, ip, _) = tunnel?;
    println!(
        "NET_EXTEND succeeded, assigned IPv4 {:?}; session logged out",
        ip.address
    );
    Ok(())
}
