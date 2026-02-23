use std::sync::Arc;

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
    let initial_max = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(max_datagram_size = initial_max, "forwarding loop started (serial)");

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = tun.recv(&mut buf) => {
                let n = result?;
                // Check dynamically — DPLPMTUD may have updated the path MTU
                let max = connection.max_datagram_size().unwrap_or(1200);
                if n > max {
                    warn!(
                        packet_size = n,
                        max,
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

/// Parallel forwarding: TUN→QUIC and QUIC→TUN run as separate tasks.
///
/// This avoids head-of-line blocking where a slow TUN read blocks QUIC reads and vice versa.
pub async fn run_forwarding_loop_parallel(
    connection: Connection,
    tun: Arc<TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let initial_max = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(max_datagram_size = initial_max, "forwarding loop started (parallel)");

    let conn_tx = connection.clone();
    let tun_rx = tun.clone();

    // TUN → QUIC task (drain loop: read all queued packets per readability notification)
    let tun_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            if let Err(e) = tun_rx.readable().await {
                tracing::error!(error = %e, "TUN readable failed");
                return;
            }
            loop {
                match tun_rx.try_recv(&mut buf) {
                    Ok(n) => {
                        let max = conn_tx.max_datagram_size().unwrap_or(1200);
                        if n > max {
                            warn!(packet_size = n, max, "dropping oversized packet from TUN");
                            continue;
                        }
                        debug!(size = n, "TUN → QUIC");
                        if let Err(e) =
                            conn_tx.send_datagram(bytes::Bytes::copy_from_slice(&buf[..n]))
                        {
                            tracing::error!(error = %e, "QUIC send failed");
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        tracing::error!(error = %e, "TUN recv failed");
                        return;
                    }
                }
            }
        }
    });

    let conn_rx = connection.clone();
    let tun_tx = tun.clone();

    // QUIC → TUN task
    let quic_to_tun = tokio::spawn(async move {
        loop {
            let datagram = match conn_rx.read_datagram().await {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "QUIC recv failed");
                    return;
                }
            };
            debug!(size = datagram.len(), "QUIC → TUN");
            if let Err(e) = tun_tx.send(&datagram).await {
                tracing::error!(error = %e, "TUN send failed");
                return;
            }
        }
    });

    // Wait for shutdown or either task to finish
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing connection");
            connection.close(0u32.into(), b"shutdown");
        }
        _ = tun_to_quic => {
            tracing::info!("TUN→QUIC task ended");
        }
        _ = quic_to_tun => {
            tracing::info!("QUIC→TUN task ended");
        }
    }

    Ok(())
}
