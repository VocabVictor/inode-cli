use inode_cli::protocol::{Session, endpoint, gateway};
use std::time::Duration;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let base = gateway(&args[1])?;
    let session = Session::new(base.clone(), None, Some(&args[2]), Duration::from_secs(15))?;
    let body = session
        .request(endpoint(&base, &args[3])?, None, true)
        .await?;
    // Developer-only tool: output goes to a local path, never to terminal logs.
    std::fs::write(&args[4], body)?;
    Ok(())
}
