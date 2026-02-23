use std::io::{self, Read};

use anyhow::{Context, Result};
use quictun_crypto::PrivateKey;

pub fn run() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read private key from stdin")?;

    let private_key =
        PrivateKey::from_base64(&input).context("invalid private key (expected base64 PKCS#8)")?;

    let public_key = private_key
        .public_key()
        .context("failed to derive public key")?;

    println!("{}", public_key.to_base64());
    Ok(())
}
