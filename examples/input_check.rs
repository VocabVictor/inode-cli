//! Offline terminal-input diagnostic. Use the synthetic test value, never account credentials.
fn main() -> anyhow::Result<()> {
    let input =
        zeroize::Zeroizing::new(rpassword::prompt_password("Enter synthetic test value: ")?);
    anyhow::ensure!(
        input.as_str() == "Aa1zZ9qQ",
        "Terminal input did not preserve the synthetic value"
    );
    println!("Offline terminal input preserved all bytes and letter case");
    Ok(())
}
