use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
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
                connection.send_datagram(Bytes::copy_from_slice(&buf[..n]))?;
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

    // TUN → QUIC task (drain loop + zero-copy: fresh Vec per packet, ownership to Bytes)
    let tun_to_quic = tokio::spawn(async move {
        let max_packet = conn_tx.max_datagram_size().unwrap_or(1452);
        loop {
            if let Err(e) = tun_rx.readable().await {
                tracing::error!(error = %e, "TUN readable failed");
                return;
            }
            loop {
                let mut packet = vec![0u8; max_packet];
                match tun_rx.try_recv(&mut packet) {
                    Ok(n) => {
                        let max = conn_tx.max_datagram_size().unwrap_or(1200);
                        if n > max {
                            warn!(packet_size = n, max, "dropping oversized packet from TUN");
                            continue;
                        }
                        debug!(size = n, "TUN → QUIC");
                        packet.truncate(n);
                        if let Err(e) = conn_tx.send_datagram(Bytes::from(packet)) {
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

/// Multi-queue forwarding: N TUN→QUIC drain workers + N QUIC→TUN writers.
///
/// Each TUN queue gets its own fd (kernel distributes packets by flow hash).
/// All workers share a single quinn Connection (which supports concurrent `&self` calls).
/// Requires Linux `IFF_MULTI_QUEUE`.
pub async fn run_forwarding_loop_multiqueue(
    connection: Connection,
    tun_queues: Vec<Arc<TunDevice>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let n = tun_queues.len();
    let initial_max = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(
        max_datagram_size = initial_max,
        queues = n,
        "forwarding loop started (multi-queue)"
    );

    let mut tasks = tokio::task::JoinSet::new();

    // Spawn N TUN→QUIC drain workers
    for (i, tun_q) in tun_queues.iter().enumerate() {
        let conn = connection.clone();
        let tun = tun_q.clone();
        tasks.spawn(async move {
            let max_packet = conn.max_datagram_size().unwrap_or(1452);
            loop {
                if let Err(e) = tun.readable().await {
                    tracing::error!(queue = i, error = %e, "TUN readable failed");
                    return;
                }
                loop {
                    let mut packet = vec![0u8; max_packet];
                    match tun.try_recv(&mut packet) {
                        Ok(n) => {
                            let max = conn.max_datagram_size().unwrap_or(1200);
                            if n > max {
                                warn!(queue = i, packet_size = n, max, "dropping oversized packet");
                                continue;
                            }
                            debug!(queue = i, size = n, "TUN → QUIC");
                            packet.truncate(n);
                            if let Err(e) = conn.send_datagram(Bytes::from(packet)) {
                                tracing::error!(queue = i, error = %e, "QUIC send failed");
                                return;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::error!(queue = i, error = %e, "TUN recv failed");
                            return;
                        }
                    }
                }
            }
        });
    }

    // Spawn N QUIC→TUN writers (round-robin queue assignment)
    for (i, tun_q) in tun_queues.iter().enumerate() {
        let conn = connection.clone();
        let tun = tun_q.clone();
        tasks.spawn(async move {
            loop {
                let datagram = match conn.read_datagram().await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(queue = i, error = %e, "QUIC recv failed");
                        return;
                    }
                };
                debug!(queue = i, size = datagram.len(), "QUIC → TUN");
                if let Err(e) = tun.send(&datagram).await {
                    tracing::error!(queue = i, error = %e, "TUN send failed");
                    return;
                }
            }
        });
    }

    // Wait for shutdown or any task to finish
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing connection");
            connection.close(0u32.into(), b"shutdown");
        }
        _ = tasks.join_next() => {
            tracing::info!("a forwarding task ended");
        }
    }

    Ok(())
}
