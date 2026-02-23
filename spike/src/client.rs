use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::info;

mod common;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (certified_key, fingerprint) = common::generate_identity()?;
    info!(fingerprint = %fingerprint, "client identity generated");

    let rustls_config = common::build_client_rustls_config(certified_key)?;
    let quic_crypto = QuicClientConfig::try_from(rustls_config)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(common::make_transport_config()));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connection = endpoint.connect(server_addr, "localhost")?.await?;
    info!("QUIC connection established with RPK auth!");

    for i in 0..5 {
        let msg = format!("PING #{i} from QuicTun spike");
        info!(sent = %msg);
        connection.send_datagram(Bytes::from(msg.clone()))?;

        let reply = connection.read_datagram().await?;
        let reply_str = String::from_utf8_lossy(&reply);
        info!(received = %reply_str);

        assert_eq!(msg, reply_str.as_ref(), "echo mismatch");
    }

    connection.close(0u32.into(), b"done");
    info!("Spike complete -- RPK + QUIC DATAGRAM validated!");

    Ok(())
}
