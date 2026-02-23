use anyhow::Result;
use quictun_crypto::PrivateKey;

pub fn run() -> Result<()> {
    let key = PrivateKey::generate()?;
    println!("{}", key.to_base64());
    Ok(())
}
