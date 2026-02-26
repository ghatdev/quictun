use std::sync::Arc;

use bytes::Bytes;
#[cfg(target_os = "linux")]
use bytes::BytesMut;
use quinn::Connection;
use tokio::sync::watch;
use tracing::{debug, warn};

use quictun_tun::TunDevice;

/// Result of a forwarding loop iteration.
#[derive(Debug)]
pub enum TunnelResult {
    /// Clean shutdown (signal received or graceful close).
    Shutdown,
    /// Connection lost — retriable (peer disappeared, timeout, reset).
    ConnectionLost(quinn::ConnectionError),
    /// Fatal error — not retriable (TUN I/O failure, etc.).
    Fatal(anyhow::Error),
}

/// Classify a `quinn::ConnectionError` as retriable or fatal.
fn classify_connection_error(e: quinn::ConnectionError) -> TunnelResult {
    match e {
        quinn::ConnectionError::TimedOut
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::ApplicationClosed(_) => TunnelResult::ConnectionLost(e),
        other => TunnelResult::Fatal(other.into()),
    }
}

/// Classify a `quinn::SendDatagramError` as retriable or fatal.
fn classify_send_error(e: quinn::SendDatagramError) -> TunnelResult {
    match e {
        quinn::SendDatagramError::ConnectionLost(ce) => classify_connection_error(ce),
        other => TunnelResult::Fatal(other.into()),
    }
}

/// Run the bidirectional forwarding loop: TUN ↔ QUIC DATAGRAMs.
///
/// Runs until the shutdown signal is received or a fatal error occurs.
pub async fn run_forwarding_loop(
    connection: Connection,
    tun: &TunDevice,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    let initial_max = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(max_datagram_size = initial_max, "forwarding loop started (serial)");

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = tun.recv(&mut buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => return TunnelResult::Fatal(e.into()),
                };
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
                if let Err(e) = connection.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                    return classify_send_error(e);
                }
            }
            result = connection.read_datagram() => {
                let datagram = match result {
                    Ok(d) => d,
                    Err(e) => return classify_connection_error(e),
                };
                debug!(size = datagram.len(), "QUIC → TUN");
                if let Err(e) = tun.send(&datagram).await {
                    return TunnelResult::Fatal(e.into());
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, closing connection");
                    connection.close(0u32.into(), b"shutdown");
                    return TunnelResult::Shutdown;
                }
            }
        }
    }
}

/// Parallel forwarding: TUN→QUIC and QUIC→TUN run as separate tasks.
///
/// This avoids head-of-line blocking where a slow TUN read blocks QUIC reads and vice versa.
pub async fn run_forwarding_loop_parallel(
    connection: Connection,
    tun: Arc<TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
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
                return TunnelResult::Fatal(e.into());
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
                            return classify_send_error(e);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        tracing::error!(error = %e, "TUN recv failed");
                        return TunnelResult::Fatal(e.into());
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
                    return classify_connection_error(e);
                }
            };
            debug!(size = datagram.len(), "QUIC → TUN");
            if let Err(e) = tun_tx.send(&datagram).await {
                tracing::error!(error = %e, "TUN send failed");
                return TunnelResult::Fatal(e.into());
            }
        }
    });

    // Wait for shutdown or either task to finish
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing connection");
            connection.close(0u32.into(), b"shutdown");
            TunnelResult::Shutdown
        }
        result = tun_to_quic => {
            tracing::info!("TUN→QUIC task ended");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
        result = quic_to_tun => {
            tracing::info!("QUIC→TUN task ended");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
    }
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
) -> TunnelResult {
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
                    return TunnelResult::Fatal(e.into());
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
                                return classify_send_error(e);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            tracing::error!(queue = i, error = %e, "TUN recv failed");
                            return TunnelResult::Fatal(e.into());
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
                        return classify_connection_error(e);
                    }
                };
                debug!(queue = i, size = datagram.len(), "QUIC → TUN");
                if let Err(e) = tun.send(&datagram).await {
                    tracing::error!(queue = i, error = %e, "TUN send failed");
                    return TunnelResult::Fatal(e.into());
                }
            }
        });
    }

    // Wait for shutdown or any task to finish
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing connection");
            connection.close(0u32.into(), b"shutdown");
            TunnelResult::Shutdown
        }
        result = tasks.join_next() => {
            tracing::info!("a forwarding task ended");
            match result {
                Some(Ok(r)) => r,
                Some(Err(e)) => TunnelResult::Fatal(e.into()),
                None => TunnelResult::Fatal(anyhow::anyhow!("no forwarding tasks")),
            }
        }
    }
}

/// Offload-aware forwarding: uses TUN GSO/GRO for batched I/O (Linux only).
///
/// TUN→QUIC: `recv_multiple` reads one super-packet and splits it into individual IP packets.
/// QUIC→TUN: `send_multiple` coalesces individual datagrams via GRO into fewer writes.
/// Requires the TUN device to be created with `offload: true`.
#[cfg(target_os = "linux")]
pub async fn run_forwarding_loop_offload(
    connection: Connection,
    tun: Arc<TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    use quictun_tun::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let initial_max = connection.max_datagram_size().unwrap_or(1200);
    tracing::info!(
        max_datagram_size = initial_max,
        "forwarding loop started (offload GSO/GRO)"
    );

    let conn_tx = connection.clone();
    let tun_rx = tun.clone();

    // TUN → QUIC task: recv_multiple splits GSO super-packets into individual IP packets.
    let tun_to_quic = tokio::spawn(async move {
        let mut original_buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
        let mut bufs: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE).map(|_| vec![0u8; 1500]).collect();
        let mut sizes = vec![0usize; IDEAL_BATCH_SIZE];

        loop {
            let n_pkts = match tun_rx
                .recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)
                .await
            {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "TUN recv_multiple failed");
                    return TunnelResult::Fatal(e.into());
                }
            };

            let max = conn_tx.max_datagram_size().unwrap_or(1200);
            for i in 0..n_pkts {
                let pkt_len = sizes[i];
                if pkt_len > max {
                    warn!(
                        packet_size = pkt_len,
                        max,
                        "dropping oversized packet from TUN"
                    );
                    continue;
                }
                debug!(size = pkt_len, batch = n_pkts, "TUN → QUIC (offload)");
                if let Err(e) =
                    conn_tx.send_datagram(Bytes::copy_from_slice(&bufs[i][..pkt_len]))
                {
                    tracing::error!(error = %e, "QUIC send failed");
                    return classify_send_error(e);
                }
            }
        }
    });

    let conn_rx = connection.clone();
    let tun_tx = tun.clone();

    // QUIC → TUN task: batch datagrams and write with GRO coalescing via send_multiple.
    let quic_to_tun = tokio::spawn(async move {
        let mut gro_table = GROTable::new();

        loop {
            // Wait for at least one datagram.
            let first = match conn_rx.read_datagram().await {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "QUIC recv failed");
                    return classify_connection_error(e);
                }
            };

            // Collect a batch: the first datagram plus any immediately available ones.
            let mut batch: Vec<BytesMut> = Vec::with_capacity(IDEAL_BATCH_SIZE);

            // Reserve VIRTIO_NET_HDR_LEN bytes at front for the virtio header.
            let mut buf = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + first.len());
            buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&first);
            batch.push(buf);

            // Drain any immediately available datagrams up to batch size.
            while batch.len() < IDEAL_BATCH_SIZE {
                match tokio::time::timeout(
                    std::time::Duration::ZERO,
                    conn_rx.read_datagram(),
                )
                .await
                {
                    Ok(Ok(d)) => {
                        let mut buf = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + d.len());
                        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&d);
                        batch.push(buf);
                    }
                    _ => break,
                }
            }

            let n = batch.len();
            debug!(batch_size = n, "QUIC → TUN (offload)");

            if let Err(e) = tun_tx
                .send_multiple(&mut gro_table, &mut batch, VIRTIO_NET_HDR_LEN)
                .await
            {
                tracing::error!(error = %e, "TUN send_multiple failed");
                return TunnelResult::Fatal(e.into());
            }
        }
    });

    // Wait for shutdown or either task to finish.
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing connection");
            connection.close(0u32.into(), b"shutdown");
            TunnelResult::Shutdown
        }
        result = tun_to_quic => {
            tracing::info!("TUN→QUIC task ended (offload)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
        result = quic_to_tun => {
            tracing::info!("QUIC→TUN task ended (offload)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
    }
}
