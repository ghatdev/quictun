use anyhow::Result;
use quinn::Connection;
use tokio::sync::watch;
use tracing::{debug, warn};

use quictun_tun::TunDevice;

/// Run the bidirectional forwarding loop: TUN ↔ QUIC DATAGRAMs.
///
/// Runs until the shutdown signal is received or a fatal error occurs.
pub async fn run_forwarding_loop(
    connection: Connection,
    tun: &TunDevice,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let max_datagram_size = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(max_datagram_size, "forwarding loop started");

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = tun.recv(&mut buf) => {
                let n = result?;
                if n > max_datagram_size {
                    warn!(
                        packet_size = n,
                        max = max_datagram_size,
                        "dropping oversized packet from TUN"
                    );
                    continue;
                }
                debug!(size = n, "TUN → QUIC");
                connection.send_datagram(bytes::Bytes::copy_from_slice(&buf[..n]))?;
            }
            result = connection.read_datagram() => {
                let datagram = result?;
                debug!(size = datagram.len(), "QUIC → TUN");
                tun.send(&datagram).await?;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, closing connection");
                    connection.close(0u32.into(), b"shutdown");
                    break;
                }
            }
        }
    }

    Ok(())
}
