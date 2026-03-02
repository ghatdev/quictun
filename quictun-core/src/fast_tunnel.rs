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
use quictun_tun::TunDevice;

use crate::tunnel::TunnelResult;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// Parallel fast forwarding: TUN->QUIC and QUIC->TUN as separate tasks.
///
/// Both tasks share `Arc<ConnectionState>` (thread-safe via RwLock::read()
/// for encrypt/decrypt). This is the primary variant for `--fast` mode.
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
        let mut encrypt_buf = vec![0u8; MAX_PACKET];
        let keepalive_interval = keepalive.unwrap_or(Duration::from_secs(25));
        let mut last_tx = Instant::now();

        loop {
            // Use a timeout for keepalive: if no TUN data for keepalive_interval, send PING.
            let timeout = if keepalive.is_some() {
                keepalive_interval.saturating_sub(last_tx.elapsed())
            } else {
                Duration::from_secs(60)
            };

            match tokio::time::timeout(timeout, tun_rx.readable()).await {
                Ok(Ok(())) => {
                    // Drain all immediately available TUN packets.
                    loop {
                        let mut packet = vec![0u8; 1500];
                        match tun_rx.try_recv(&mut packet) {
                            Ok(n) => {
                                match conn_tx.encrypt_datagram(
                                    &packet[..n],
                                    None,
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
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "TUN readable failed");
                    return TunnelResult::Fatal(e.into());
                }
                Err(_) => {
                    // Keepalive timeout — send PING (empty datagram).
                    if keepalive.is_some() {
                        match conn_tx.encrypt_datagram(&[], None, &mut encrypt_buf) {
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
        let mut recv_buf = vec![0u8; MAX_PACKET];
        let mut scratch = BytesMut::with_capacity(MAX_PACKET);
        let mut last_rx = Instant::now();

        loop {
            // Idle timeout check.
            let remaining = idle_timeout.saturating_sub(last_rx.elapsed());
            if remaining.is_zero() {
                tracing::info!("idle timeout exceeded, connection lost");
                return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
            }

            match tokio::time::timeout(remaining, udp_rx.recv_from(&mut recv_buf)).await {
                Ok(Ok((n, _from))) => {
                    // Drop long header packets (stale handshake retransmits).
                    if n > 0 && recv_buf[0] & 0x80 != 0 {
                        debug!(size = n, "dropping long header packet (stale)");
                        continue;
                    }

                    match conn_rx.decrypt_packet_with_buf(&mut recv_buf[..n], &mut scratch) {
                        Ok(decrypted) => {
                            last_rx = Instant::now();
                            for datagram in &decrypted.datagrams {
                                if datagram.is_empty() {
                                    // PING frame — keepalive, no TUN write needed.
                                    continue;
                                }
                                debug!(
                                    size = datagram.len(),
                                    pn = decrypted.pn,
                                    "QUIC -> TUN (fast)"
                                );
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
                    // Idle timeout.
                    tracing::info!("idle timeout exceeded, connection lost");
                    return TunnelResult::ConnectionLost(quinn::ConnectionError::TimedOut);
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
                match conn_state.encrypt_datagram(&tun_buf[..n], None, &mut encrypt_buf) {
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
                    match conn_state.encrypt_datagram(&[], None, &mut encrypt_buf) {
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
