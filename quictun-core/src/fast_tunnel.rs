//! Fast forwarding loops using quictun-quic (custom 1-RTT data plane).
//!
//! After handshake completes via `proto_driver`, these loops handle the
//! TUN <-> QUIC data plane using `quictun_quic::ConnectionState` directly,
//! bypassing quinn's high-level API entirely.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, warn};

use quictun_quic::ConnectionState;
use quictun_quic::local::LocalConnectionState;
use quictun_tun::TunDevice;

use crate::tunnel::TunnelResult;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// Parallel fast forwarding: TUN->QUIC and QUIC->TUN as separate tasks.
///
/// Both tasks share `Arc<ConnectionState>` (thread-safe via RwLock::read()
/// for encrypt/decrypt). This is the primary variant for `--fast` mode.
///
/// On Linux, uses UDP GSO (send_gso) for TX and recvmmsg for batched RX.
/// On other platforms, falls back to per-packet send_to/recv_from.
pub async fn run_fast_forwarding_loop_parallel(
    conn_state: Arc<ConnectionState>,
    udp: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    remote_addr: SocketAddr,
    idle_timeout: Duration,
    keepalive: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    tracing::info!("fast forwarding loop started (parallel, quictun-quic)");

    let conn_tx = conn_state.clone();
    let udp_tx = udp.clone();
    let tun_rx = tun.clone();

    // TUN -> QUIC task: read from TUN, encrypt with quictun-quic, send UDP.
    let tun_to_quic = tokio::spawn(async move {
        // GSO buffer: encrypt directly into contiguous buffer, send via UDP GSO.
        #[cfg(target_os = "linux")]
        let mut gso_buf = vec![0u8; crate::batch_io::GSO_BUF_SIZE];

        let mut encrypt_buf = vec![0u8; MAX_PACKET];
        let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(25));
        let mut last_tx = Instant::now();

        loop {
            let timeout = if keepalive.is_some() {
                keepalive_interval.saturating_sub(last_tx.elapsed())
            } else {
                Duration::from_secs(60)
            };

            match tokio::time::timeout(timeout, tun_rx.readable()).await {
                Ok(Ok(())) => {
                    // Drain all immediately available TUN packets + encrypt.
                    #[cfg(target_os = "linux")]
                    {
                        let max_segs = crate::batch_io::GSO_MAX_SEGMENTS;
                        let mut gso_pos = 0usize;
                        let mut gso_segment_size = 0usize;
                        let mut gso_count = 0usize;

                        loop {
                            if gso_count >= max_segs {
                                break; // GSO segment limit
                            }
                            let mut packet = [0u8; 1500];
                            match tun_rx.try_recv(&mut packet) {
                                Ok(n) => {
                                    if gso_pos + MAX_PACKET > gso_buf.len() {
                                        break; // GSO buffer full
                                    }
                                    // Piggyback ACK ranges if due.
                                    let ack_ranges = if conn_tx.needs_ack() {
                                        Some(conn_tx.generate_ack_ranges())
                                    } else {
                                        None
                                    };
                                    match conn_tx.encrypt_datagram(
                                        &packet[..n],
                                        ack_ranges.as_deref(),
                                        &mut gso_buf[gso_pos..],
                                    ) {
                                        Ok(result) => {
                                            if gso_count == 0 {
                                                gso_segment_size = result.len;
                                                gso_pos += result.len;
                                                gso_count += 1;
                                            } else if result.len == gso_segment_size {
                                                gso_pos += result.len;
                                                gso_count += 1;
                                            } else {
                                                // Different size (rare: small ACK during bulk).
                                                // The odd packet was written at gso_buf[gso_pos..].
                                                // Send it individually, don't mix into GSO batch.
                                                let odd_pkt_end = gso_pos + result.len;
                                                if let Err(e) = udp_tx
                                                    .send_to(&gso_buf[gso_pos..odd_pkt_end], remote_addr)
                                                    .await
                                                {
                                                    tracing::error!(error = %e, "UDP send failed (odd size)");
                                                    return TunnelResult::Fatal(e.into());
                                                }
                                                // gso_pos unchanged — GSO batch continues.
                                            }
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "encrypt failed, dropping packet");
                                        }
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    tracing::error!(error = %e, "TUN recv failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                            }
                        }

                        // Flush remaining GSO batch.
                        if gso_count > 0 {
                            let seg = gso_segment_size as u16;
                            loop {
                                match crate::batch_io::send_gso(
                                    &udp_tx,
                                    &gso_buf[..gso_pos],
                                    seg,
                                    remote_addr,
                                ) {
                                    Ok(_) => {
                                        debug!(
                                            count = gso_count,
                                            segment_size = gso_segment_size,
                                            total = gso_pos,
                                            "TUN -> QUIC (UDP GSO)"
                                        );
                                        last_tx = Instant::now();
                                        break;
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        if let Err(e) = udp_tx.writable().await {
                                            tracing::error!(error = %e, "writable failed");
                                            return TunnelResult::Fatal(e.into());
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(error = %e, "send_gso failed");
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                            }
                        }
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        loop {
                            let mut packet = [0u8; 1500];
                            match tun_rx.try_recv(&mut packet) {
                                Ok(n) => {
                                    let ack_ranges = if conn_tx.needs_ack() {
                                        Some(conn_tx.generate_ack_ranges())
                                    } else {
                                        None
                                    };
                                    match conn_tx.encrypt_datagram(
                                        &packet[..n],
                                        ack_ranges.as_deref(),
                                        &mut encrypt_buf,
                                    ) {
                                        Ok(result) => {
                                            if let Err(e) = udp_tx
                                                .send_to(
                                                    &encrypt_buf[..result.len],
                                                    remote_addr,
                                                )
                                                .await
                                            {
                                                tracing::error!(error = %e, "UDP send failed");
                                                return TunnelResult::Fatal(e.into());
                                            }
                                            last_tx = Instant::now();
                                            debug!(size = n, pn = result.pn, "TUN -> QUIC (fast)");
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "encrypt failed, dropping packet");
                                        }
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
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "TUN readable failed");
                    return TunnelResult::Fatal(e.into());
                }
                Err(_) => {
                    // Keepalive timeout — send PING with piggybacked ACK ranges.
                    // Always include ACK ranges on keepalive to maintain feedback
                    // even when packet rate is below ACK_INTERVAL threshold.
                    if keepalive.is_some() {
                        let ack_ranges = conn_tx.generate_ack_ranges();
                        let ack_ref = if !ack_ranges.is_empty() {
                            Some(ack_ranges.as_slice())
                        } else {
                            None
                        };
                        match conn_tx.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                            Ok(result) => {
                                if let Err(e) =
                                    udp_tx.send_to(&encrypt_buf[..result.len], remote_addr).await
                                {
                                    tracing::error!(error = %e, "keepalive send failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                                last_tx = Instant::now();
                                debug!(pn = result.pn, "sent keepalive PING");
                            }
                            Err(e) => {
                                warn!(error = %e, "keepalive encrypt failed");
                            }
                        }
                    }
                }
            }
        }
    });

    let conn_rx = conn_state.clone();
    let udp_rx = udp.clone();
    let tun_tx = tun.clone();

    // QUIC -> TUN task: receive UDP, decrypt with quictun-quic, write to TUN.
    let quic_to_tun = tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        let mut recv_bufs: Vec<Vec<u8>> = (0..crate::batch_io::BATCH_SIZE)
            .map(|_| vec![0u8; MAX_PACKET])
            .collect();
        #[cfg(target_os = "linux")]
        let mut recv_lens = vec![0usize; crate::batch_io::BATCH_SIZE];

        #[cfg(not(target_os = "linux"))]
        let mut recv_buf = vec![0u8; MAX_PACKET];
        let mut scratch = BytesMut::with_capacity(MAX_PACKET);
        let mut last_rx = Instant::now();

        loop {
            let remaining = idle_timeout.saturating_sub(last_rx.elapsed());
            if remaining.is_zero() {
                tracing::info!("idle timeout exceeded, connection lost");
                return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
            }

            #[cfg(target_os = "linux")]
            {
                // Wait for readability with idle timeout.
                match tokio::time::timeout(remaining, udp_rx.readable()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "UDP readable failed");
                        return TunnelResult::Fatal(e.into());
                    }
                    Err(_) => {
                        tracing::info!("idle timeout exceeded, connection lost");
                        return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                    }
                }

                // Batch receive via recvmmsg (drains multiple packets in one syscall).
                let n_msgs = match crate::batch_io::recvmmsg_batch(
                    &udp_rx,
                    &mut recv_bufs,
                    &mut recv_lens,
                    crate::batch_io::BATCH_SIZE,
                ) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        tracing::error!(error = %e, "recvmmsg failed");
                        return TunnelResult::Fatal(e.into());
                    }
                };

                let mut got_data = false;
                for i in 0..n_msgs {
                    let n = recv_lens[i];
                    if n == 0 {
                        continue;
                    }
                    if recv_bufs[i][0] & 0x80 != 0 {
                        continue;
                    }
                    match conn_rx.decrypt_packet_with_buf(&mut recv_bufs[i][..n], &mut scratch) {
                        Ok(decrypted) => {
                            got_data = true;
                            if let Some(ref ack) = decrypted.ack {
                                conn_rx.process_ack(ack);
                            }
                            for datagram in &decrypted.datagrams {
                                if datagram.is_empty() {
                                    continue;
                                }
                                debug!(size = datagram.len(), pn = decrypted.pn, "QUIC -> TUN (fast)");
                                if let Err(e) = tun_tx.send(datagram).await {
                                    tracing::error!(error = %e, "TUN send failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                            }
                        }
                        Err(e) => {
                            debug!(error = %e, size = n, "decrypt failed, dropping packet");
                        }
                    }
                }
                if got_data {
                    last_rx = Instant::now();
                    // ACK delivery is handled by the TX task, which piggybacks
                    // ACK ranges on outgoing TUN data (TCP ACKs, keepalive PINGs).
                    // Sending ACK-only packets from the RX task would block it
                    // with send_to().await, causing UDP recv buffer overflow
                    // under high throughput. The TX task's piggybacking is
                    // sufficient for bidirectional flows (iperf3, normal TCP).
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                match tokio::time::timeout(remaining, udp_rx.recv_from(&mut recv_buf)).await {
                    Ok(Ok((n, _from))) => {
                        if n > 0 && recv_buf[0] & 0x80 != 0 {
                            debug!(size = n, "dropping long header packet (stale)");
                            continue;
                        }
                        match conn_rx.decrypt_packet_with_buf(&mut recv_buf[..n], &mut scratch) {
                            Ok(decrypted) => {
                                last_rx = Instant::now();
                                if let Some(ref ack) = decrypted.ack {
                                    conn_rx.process_ack(ack);
                                }
                                for datagram in &decrypted.datagrams {
                                    if datagram.is_empty() {
                                        continue;
                                    }
                                    debug!(size = datagram.len(), pn = decrypted.pn, "QUIC -> TUN (fast)");
                                    if let Err(e) = tun_tx.send(datagram).await {
                                        tracing::error!(error = %e, "TUN send failed");
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, size = n, "decrypt failed, dropping packet");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "UDP recv failed");
                        return TunnelResult::Fatal(e.into());
                    }
                    Err(_) => {
                        tracing::info!("idle timeout exceeded, connection lost");
                        return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                    }
                }
            }
        }
    });

    // Wait for shutdown or either task to finish.
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing fast tunnel");
            TunnelResult::Shutdown
        }
        result = tun_to_quic => {
            tracing::info!("TUN->QUIC task ended (fast)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
        result = quic_to_tun => {
            tracing::info!("QUIC->TUN task ended (fast)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
    }
}

/// Offload fast forwarding: TUN GSO/GRO + sendmmsg/recvmmsg + quictun-quic (Linux only).
///
/// TUN→QUIC: `recv_multiple` splits GSO super-packets → encrypt each → `sendmmsg` batch send.
/// QUIC→TUN: `recvmmsg` batch recv → decrypt each → `send_multiple` GRO coalescing.
/// Requires the TUN device to be created with `offload: true`.
#[cfg(target_os = "linux")]
pub async fn run_fast_forwarding_loop_offload(
    conn_state: Arc<ConnectionState>,
    udp: Arc<UdpSocket>,
    tun: Arc<TunDevice>,
    remote_addr: SocketAddr,
    idle_timeout: Duration,
    keepalive: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    use crate::batch_io::{self, BATCH_SIZE};
    use quictun_tun::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    tracing::info!("fast forwarding loop started (offload + sendmmsg/recvmmsg, quictun-quic)");

    let conn_tx = conn_state.clone();
    let udp_tx = udp.clone();
    let tun_rx = tun.clone();

    // TUN → QUIC task: recv_multiple → encrypt batch → sendmmsg.
    let tun_to_quic = tokio::spawn(async move {
        let mut original_buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 65535];
        let mut bufs: Vec<Vec<u8>> = (0..IDEAL_BATCH_SIZE).map(|_| vec![0u8; 1500]).collect();
        let mut sizes = vec![0usize; IDEAL_BATCH_SIZE];

        // Pre-allocate encrypt output buffers for sendmmsg batch.
        let mut encrypt_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET]).collect();
        let mut encrypt_lens = vec![0usize; BATCH_SIZE];
        // Single buffer for keepalive (not batched).
        let mut keepalive_buf = vec![0u8; MAX_PACKET];

        let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(25));
        let mut last_tx = Instant::now();

        loop {
            let timeout = if keepalive.is_some() {
                keepalive_interval.saturating_sub(last_tx.elapsed())
            } else {
                Duration::from_secs(60)
            };

            match tokio::time::timeout(
                timeout,
                tun_rx.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0),
            )
            .await
            {
                Ok(Ok(n_pkts)) => {
                    // Encrypt all packets into batch buffers.
                    let mut batch_count = 0;
                    for i in 0..n_pkts {
                        if batch_count >= BATCH_SIZE {
                            break;
                        }
                        let pkt_len = sizes[i];
                        let ack_ranges = if conn_tx.needs_ack() {
                            Some(conn_tx.generate_ack_ranges())
                        } else {
                            None
                        };
                        match conn_tx.encrypt_datagram(
                            &bufs[i][..pkt_len],
                            ack_ranges.as_deref(),
                            &mut encrypt_bufs[batch_count],
                        ) {
                            Ok(result) => {
                                encrypt_lens[batch_count] = result.len;
                                batch_count += 1;
                            }
                            Err(e) => {
                                warn!(error = %e, "encrypt failed, dropping packet");
                            }
                        }
                    }

                    // Send entire batch via sendmmsg.
                    if batch_count > 0 {
                        // May need to retry with writable() if EAGAIN.
                        loop {
                            match batch_io::sendmmsg_batch(
                                &udp_tx,
                                &encrypt_bufs,
                                &encrypt_lens,
                                batch_count,
                                remote_addr,
                            ) {
                                Ok(sent) => {
                                    debug!(
                                        sent,
                                        batch = batch_count,
                                        "TUN -> QUIC (fast sendmmsg)"
                                    );
                                    last_tx = Instant::now();
                                    break;
                                }
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock =>
                                {
                                    // Wait for socket writability, then retry.
                                    if let Err(e) = udp_tx.writable().await {
                                        tracing::error!(error = %e, "UDP writable failed");
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "sendmmsg failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "TUN recv_multiple failed");
                    return TunnelResult::Fatal(e.into());
                }
                Err(_) => {
                    // Keepalive timeout — send PING with piggybacked ACK ranges.
                    if keepalive.is_some() {
                        let ack_ranges = conn_tx.generate_ack_ranges();
                        let ack_ref = if !ack_ranges.is_empty() {
                            Some(ack_ranges.as_slice())
                        } else {
                            None
                        };
                        match conn_tx.encrypt_datagram(&[], ack_ref, &mut keepalive_buf) {
                            Ok(result) => {
                                if let Err(e) = udp_tx
                                    .send_to(&keepalive_buf[..result.len], remote_addr)
                                    .await
                                {
                                    tracing::error!(error = %e, "keepalive send failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                                last_tx = Instant::now();
                                debug!(pn = result.pn, "sent keepalive PING (fast offload)");
                            }
                            Err(e) => {
                                warn!(error = %e, "keepalive encrypt failed");
                            }
                        }
                    }
                }
            }
        }
    });

    let conn_rx = conn_state.clone();
    let udp_rx = udp.clone();
    let tun_tx = tun.clone();

    // QUIC → TUN task: recvmmsg batch recv → decrypt → send_multiple GRO.
    let quic_to_tun = tokio::spawn(async move {
        let mut recv_bufs: Vec<Vec<u8>> =
            (0..BATCH_SIZE).map(|_| vec![0u8; MAX_PACKET]).collect();
        let mut recv_lens = vec![0usize; BATCH_SIZE];
        let mut scratch = BytesMut::with_capacity(MAX_PACKET);
        let mut last_rx = Instant::now();
        let mut gro_table = GROTable::new();

        loop {
            let remaining = idle_timeout.saturating_sub(last_rx.elapsed());
            if remaining.is_zero() {
                tracing::info!("idle timeout exceeded, connection lost");
                return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
            }

            // Wait for socket readability (with idle timeout).
            match tokio::time::timeout(remaining, udp_rx.readable()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "UDP readable failed");
                    return TunnelResult::Fatal(e.into());
                }
                Err(_) => {
                    tracing::info!("idle timeout exceeded, connection lost");
                    return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                }
            }

            // Batch receive via recvmmsg (non-blocking, socket is readable).
            let n_msgs = match batch_io::recvmmsg_batch(
                &udp_rx,
                &mut recv_bufs,
                &mut recv_lens,
                BATCH_SIZE,
            ) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    tracing::error!(error = %e, "recvmmsg failed");
                    return TunnelResult::Fatal(e.into());
                }
            };

            // Decrypt each packet and batch datagrams for TUN GRO.
            let mut tun_batch: Vec<BytesMut> = Vec::with_capacity(n_msgs * 2);
            let mut got_data = false;

            for i in 0..n_msgs {
                let n = recv_lens[i];
                if n == 0 {
                    continue;
                }
                // Drop long header packets (stale handshake retransmits).
                if recv_bufs[i][0] & 0x80 != 0 {
                    debug!(size = n, "dropping long header packet (stale)");
                    continue;
                }

                match conn_rx.decrypt_packet_with_buf(&mut recv_bufs[i][..n], &mut scratch)
                {
                    Ok(decrypted) => {
                        got_data = true;
                        if let Some(ref ack) = decrypted.ack {
                            conn_rx.process_ack(ack);
                        }
                        for datagram in &decrypted.datagrams {
                            if datagram.is_empty() {
                                continue; // PING frame
                            }
                            let mut buf =
                                BytesMut::zeroed(VIRTIO_NET_HDR_LEN + datagram.len());
                            buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(datagram);
                            tun_batch.push(buf);
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, size = n, "decrypt failed, dropping packet");
                    }
                }
            }

            if got_data {
                last_rx = Instant::now();
            }

            if !tun_batch.is_empty() {
                debug!(
                    recv_batch = n_msgs,
                    tun_batch = tun_batch.len(),
                    "QUIC -> TUN (fast recvmmsg)"
                );
                if let Err(e) = tun_tx
                    .send_multiple(&mut gro_table, &mut tun_batch, VIRTIO_NET_HDR_LEN)
                    .await
                {
                    tracing::error!(error = %e, "TUN send_multiple failed");
                    return TunnelResult::Fatal(e.into());
                }
            }
        }
    });

    // Wait for shutdown or either task to finish.
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received, closing fast tunnel");
            TunnelResult::Shutdown
        }
        result = tun_to_quic => {
            tracing::info!("TUN->QUIC task ended (fast offload)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
        result = quic_to_tun => {
            tracing::info!("QUIC->TUN task ended (fast offload)");
            match result {
                Ok(r) => r,
                Err(e) => TunnelResult::Fatal(e.into()),
            }
        }
    }
}

/// Serial fast forwarding: single select loop for TUN <-> QUIC.
///
/// Simpler but may have head-of-line blocking between directions.
pub async fn run_fast_forwarding_loop(
    conn_state: &Arc<ConnectionState>,
    udp: &UdpSocket,
    tun: &TunDevice,
    remote_addr: SocketAddr,
    idle_timeout: Duration,
    keepalive: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    tracing::info!("fast forwarding loop started (serial, quictun-quic)");

    let mut tun_buf = vec![0u8; 1500];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(MAX_PACKET);
    let mut last_rx = Instant::now();
    let mut last_tx = Instant::now();

    let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(60));

    loop {
        let idle_remaining = idle_timeout.saturating_sub(last_rx.elapsed());
        if idle_remaining.is_zero() {
            tracing::info!("idle timeout exceeded, connection lost");
            return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
        }

        let keepalive_remaining = if keepalive.is_some() {
            keepalive_interval.saturating_sub(last_tx.elapsed())
        } else {
            Duration::from_secs(3600)
        };

        let timeout = idle_remaining.min(keepalive_remaining);

        tokio::select! {
            result = tun.recv(&mut tun_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(e) => return TunnelResult::Fatal(e.into()),
                };
                let ack_ranges = if conn_state.needs_ack() {
                    Some(conn_state.generate_ack_ranges())
                } else {
                    None
                };
                match conn_state.encrypt_datagram(&tun_buf[..n], ack_ranges.as_deref(), &mut encrypt_buf) {
                    Ok(result) => {
                        if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                            return TunnelResult::Fatal(e.into());
                        }
                        last_tx = Instant::now();
                        debug!(size = n, pn = result.pn, "TUN -> QUIC (fast serial)");
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed, dropping packet");
                    }
                }
            }
            result = udp.recv_from(&mut recv_buf) => {
                let (n, _from) = match result {
                    Ok(r) => r,
                    Err(e) => return TunnelResult::Fatal(e.into()),
                };
                // Drop long header packets.
                if n > 0 && recv_buf[0] & 0x80 != 0 {
                    continue;
                }
                match conn_state.decrypt_packet_with_buf(&mut recv_buf[..n], &mut scratch) {
                    Ok(decrypted) => {
                        last_rx = Instant::now();
                        if let Some(ref ack) = decrypted.ack {
                            conn_state.process_ack(ack);
                        }
                        for datagram in &decrypted.datagrams {
                            if datagram.is_empty() {
                                continue;
                            }
                            debug!(size = datagram.len(), pn = decrypted.pn, "QUIC -> TUN (fast serial)");
                            if let Err(e) = tun.send(datagram).await {
                                return TunnelResult::Fatal(e.into());
                            }
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, size = n, "decrypt failed, dropping packet");
                    }
                }
            }
            _ = tokio::time::sleep(timeout) => {
                // Check idle timeout.
                if last_rx.elapsed() >= idle_timeout {
                    tracing::info!("idle timeout exceeded, connection lost");
                    return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                }
                // Keepalive.
                if keepalive.is_some() && last_tx.elapsed() >= keepalive_interval {
                    let ack_ranges = conn_state.generate_ack_ranges();
                    let ack_ref = if !ack_ranges.is_empty() {
                        Some(ack_ranges.as_slice())
                    } else {
                        None
                    };
                    match conn_state.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                        Ok(result) => {
                            if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                                return TunnelResult::Fatal(e.into());
                            }
                            last_tx = Instant::now();
                            debug!(pn = result.pn, "sent keepalive PING (serial)");
                        }
                        Err(e) => {
                            warn!(error = %e, "keepalive encrypt failed");
                        }
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, closing fast tunnel");
                    return TunnelResult::Shutdown;
                }
            }
        }
    }
}

// ── New single-task fast loop (Phase 1) ──────────────────────────────────

/// Single-task fast forwarding loop using `LocalConnectionState`.
///
/// No shared mutable state, no atomics, no cross-task coordination.
/// Uses GSO send + recvmmsg batching on Linux for high throughput.
/// Falls back to per-packet I/O on other platforms.
pub async fn run_fast_loop(
    mut conn: LocalConnectionState,
    udp: &UdpSocket,
    tun: &TunDevice,
    remote_addr: SocketAddr,
    idle_timeout: Duration,
    keepalive: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) -> TunnelResult {
    tracing::info!("fast forwarding loop started (single-task, LocalConnectionState)");

    let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(25));
    let mut last_tx = Instant::now();
    let mut last_rx = Instant::now();

    let mut encrypt_buf = vec![0u8; MAX_PACKET];
    let mut scratch = BytesMut::with_capacity(2048);

    // Linux: GSO send buffer + recvmmsg batch buffers.
    #[cfg(target_os = "linux")]
    let mut gso_buf = vec![0u8; crate::batch_io::GSO_BUF_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; crate::batch_io::BATCH_SIZE];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; crate::batch_io::BATCH_SIZE];

    // Non-Linux: simple per-packet buffer.
    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    loop {
        let timeout = {
            let since_tx = last_tx.elapsed();
            let since_rx = last_rx.elapsed();
            let keepalive_remaining = if keepalive.is_some() {
                keepalive_interval.saturating_sub(since_tx)
            } else {
                Duration::from_secs(60)
            };
            let idle_remaining = idle_timeout.saturating_sub(since_rx);
            keepalive_remaining.min(idle_remaining)
        };

        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("shutdown signal received, closing fast tunnel");
                    return TunnelResult::Shutdown;
                }
            }

            result = tun.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                // Drain TUN packets, encrypt, batch into GSO buffer.
                #[cfg(target_os = "linux")]
                {
                    let max_segs = crate::batch_io::GSO_MAX_SEGMENTS;
                    let mut gso_pos = 0usize;
                    let mut gso_segment_size = 0usize;
                    let mut gso_count = 0usize;

                    loop {
                        if gso_count >= max_segs {
                            break;
                        }
                        let mut packet = [0u8; 1500];
                        match tun.try_recv(&mut packet) {
                            Ok(n) => {
                                if gso_pos + MAX_PACKET > gso_buf.len() {
                                    break;
                                }
                                let ack_ranges = if conn.needs_ack() {
                                    Some(conn.generate_ack_ranges())
                                } else {
                                    None
                                };
                                match conn.encrypt_datagram(
                                    &packet[..n],
                                    ack_ranges.as_deref(),
                                    &mut gso_buf[gso_pos..],
                                ) {
                                    Ok(result) => {
                                        if gso_count == 0 {
                                            gso_segment_size = result.len;
                                            gso_pos += result.len;
                                            gso_count += 1;
                                        } else if result.len == gso_segment_size {
                                            gso_pos += result.len;
                                            gso_count += 1;
                                        } else {
                                            // Odd-sized packet: send individually.
                                            let odd_end = gso_pos + result.len;
                                            if let Err(e) = udp
                                                .send_to(&gso_buf[gso_pos..odd_end], remote_addr)
                                                .await
                                            {
                                                tracing::error!(error = %e, "UDP send failed (odd size)");
                                                return TunnelResult::Fatal(e.into());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "encrypt failed, dropping packet");
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                tracing::error!(error = %e, "TUN recv failed");
                                return TunnelResult::Fatal(e.into());
                            }
                        }
                    }

                    // Flush GSO batch.
                    if gso_count > 0 {
                        let seg = gso_segment_size as u16;
                        loop {
                            match crate::batch_io::send_gso(
                                udp,
                                &gso_buf[..gso_pos],
                                seg,
                                remote_addr,
                            ) {
                                Ok(_) => {
                                    debug!(
                                        count = gso_count,
                                        segment_size = gso_segment_size,
                                        total = gso_pos,
                                        "TUN -> QUIC (GSO)"
                                    );
                                    last_tx = Instant::now();
                                    break;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    if let Err(e) = udp.writable().await {
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "send_gso failed");
                                    return TunnelResult::Fatal(e.into());
                                }
                            }
                        }
                    }
                }

                // Non-Linux: per-packet send.
                #[cfg(not(target_os = "linux"))]
                {
                    loop {
                        let mut packet = [0u8; 1500];
                        match tun.try_recv(&mut packet) {
                            Ok(n) => {
                                let ack_ranges = if conn.needs_ack() {
                                    Some(conn.generate_ack_ranges())
                                } else {
                                    None
                                };
                                match conn.encrypt_datagram(
                                    &packet[..n],
                                    ack_ranges.as_deref(),
                                    &mut encrypt_buf,
                                ) {
                                    Ok(result) => {
                                        if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                                            return TunnelResult::Fatal(e.into());
                                        }
                                        last_tx = Instant::now();
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "encrypt failed, dropping packet");
                                    }
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => return TunnelResult::Fatal(e.into()),
                        }
                    }
                }
            }

            result = udp.readable() => {
                if let Err(e) = result {
                    return TunnelResult::Fatal(e.into());
                }

                // Linux: recvmmsg batch.
                #[cfg(target_os = "linux")]
                {
                    let n_msgs = match crate::batch_io::recvmmsg_batch(
                        udp,
                        &mut recv_bufs,
                        &mut recv_lens,
                        crate::batch_io::BATCH_SIZE,
                    ) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => {
                            tracing::error!(error = %e, "recvmmsg failed");
                            return TunnelResult::Fatal(e.into());
                        }
                    };

                    for i in 0..n_msgs {
                        let n = recv_lens[i];
                        if n == 0 { continue; }
                        if recv_bufs[i][0] & 0x80 != 0 { continue; }

                        match conn.decrypt_packet_with_buf(&mut recv_bufs[i][..n], &mut scratch) {
                            Ok(decrypted) => {
                                last_rx = Instant::now();
                                if let Some(ref ack) = decrypted.ack {
                                    conn.process_ack(ack);
                                }
                                for datagram in &decrypted.datagrams {
                                    if datagram.is_empty() { continue; }
                                    if let Err(e) = tun.send(datagram).await {
                                        return TunnelResult::Fatal(e.into());
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, size = n, "decrypt failed, dropping");
                            }
                        }
                    }
                }

                // Non-Linux: single recv_from.
                #[cfg(not(target_os = "linux"))]
                {
                    match udp.try_recv_from(&mut recv_buf) {
                        Ok((n, _from)) => {
                            if n > 0 && recv_buf[0] & 0x80 != 0 {
                                continue;
                            }
                            match conn.decrypt_packet_with_buf(&mut recv_buf[..n], &mut scratch) {
                                Ok(decrypted) => {
                                    last_rx = Instant::now();
                                    if let Some(ref ack) = decrypted.ack {
                                        conn.process_ack(ack);
                                    }
                                    for datagram in &decrypted.datagrams {
                                        if datagram.is_empty() { continue; }
                                        if let Err(e) = tun.send(datagram).await {
                                            return TunnelResult::Fatal(e.into());
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, size = n, "decrypt failed, dropping");
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => return TunnelResult::Fatal(e.into()),
                    }
                }
            }

            _ = tokio::time::sleep(timeout) => {
                // Check idle timeout.
                if last_rx.elapsed() >= idle_timeout {
                    tracing::info!("idle timeout exceeded, connection lost");
                    return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
                }
                // Keepalive.
                if keepalive.is_some() && last_tx.elapsed() >= keepalive_interval {
                    let ack_ranges = conn.generate_ack_ranges();
                    let ack_ref = if !ack_ranges.is_empty() {
                        Some(ack_ranges.as_slice())
                    } else {
                        None
                    };
                    match conn.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                        Ok(result) => {
                            if let Err(e) = udp.send_to(&encrypt_buf[..result.len], remote_addr).await {
                                return TunnelResult::Fatal(e.into());
                            }
                            last_tx = Instant::now();
                            debug!(pn = result.pn, "sent keepalive PING");
                        }
                        Err(e) => {
                            warn!(error = %e, "keepalive encrypt failed");
                        }
                    }
                }
            }
        }
    }
}
