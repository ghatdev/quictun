use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use quinn::crypto::rustls::QuicServerConfig;
use tracing::info;

mod common;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (certified_key, fingerprint) = common::generate_identity()?;
    info!(fingerprint = %fingerprint, "server identity generated");

    let rustls_config = common::build_server_rustls_config(certified_key)?;
    let quic_crypto = QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(common::make_transport_config()));

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!(%addr, "server listening");

    while let Some(incoming) = endpoint.accept().await {
        let remote = incoming.remote_address();
        info!(%remote, "incoming connection");

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("QUIC connection established with RPK auth!");
                    loop {
                        match connection.read_datagram().await {
                            Ok(data) => {
                                info!(len = data.len(), "received datagram, echoing back");
                                if let Err(e) = connection.send_datagram(data) {
                                    tracing::error!("failed to echo datagram: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                info!("connection ended: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("connection failed: {e}");
                }
            }
        });
    }

    Ok(())
}
