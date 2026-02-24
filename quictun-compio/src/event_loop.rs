use std::cell::RefCell;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use compio::buf::BufResult;
use compio::fs::AsyncFd;
use compio::io::{AsyncRead, AsyncWrite};
use compio::net::UdpSocket;
use compio::time::timeout_at;
use quinn_proto::{ClientConfig, ServerConfig};
use tracing::{debug, info, warn};

use crate::shared::{self, QuicState};

/// Maximum packet size for UDP/TUN buffers.
const BUF_SIZE: usize = 1500;

/// How the QUIC endpoint should be set up.
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Run the compio async data plane.
///
/// Creates a single-threaded compio runtime with two cooperative async tasks:
/// outbound (TUN->QUIC->UDP) and inbound (UDP->QUIC->TUN).
pub fn run(tun_fd: RawFd, local_addr: SocketAddr, setup: EndpointSetup) -> Result<()> {
    let runtime =
        compio::runtime::Runtime::new().context("failed to create compio runtime")?;
    runtime.block_on(run_async(tun_fd, local_addr, setup))
}

async fn run_async(
    tun_fd: RawFd,
    local_addr: SocketAddr,
    setup: EndpointSetup,
) -> Result<()> {
    // 0. Set TUN fd non-blocking.
    set_nonblocking(tun_fd)?;

    // 1. Create UDP socket.
    let (std_udp, remote_addr, first_packet) = match &setup {
        EndpointSetup::Connector { remote_addr, .. } => {
            let sock =
                std::net::UdpSocket::bind(local_addr).context("failed to bind UDP")?;
            sock.connect(remote_addr)
                .context("failed to connect UDP")?;
            info!(bind = %sock.local_addr()?, remote = %remote_addr, "UDP ready (connector)");
            sock.set_nonblocking(true)?;
            (sock, *remote_addr, None)
        }
        EndpointSetup::Listener { .. } => {
            let sock =
                std::net::UdpSocket::bind(local_addr).context("failed to bind UDP")?;
            info!(bind = %sock.local_addr()?, "waiting for first packet (listener)");

            // Blocking recvfrom to learn peer address.
            let mut buf = vec![0u8; BUF_SIZE];
            let (n, peer) = sock
                .recv_from(&mut buf)
                .context("recvfrom first packet failed")?;
            info!(peer = %peer, bytes = n, "first packet received, connecting");
            buf.truncate(n);

            sock.connect(peer).context("failed to connect to peer")?;
            sock.set_nonblocking(true)?;
            (sock, peer, Some(buf))
        }
    };

    // Dup UDP fd for second socket (one per task direction).
    let udp_fd_dup = dup_raw(std_udp.as_raw_fd())?;
    let udp_main =
        UdpSocket::from_std(std_udp).context("failed to wrap UDP socket")?;
    let udp_dup = UdpSocket::from_std(unsafe {
        std::net::UdpSocket::from_raw_fd(udp_fd_dup)
    })
    .context("failed to wrap dup'd UDP socket")?;

    // 2. Build QuicState.
    let server_config = match &setup {
        EndpointSetup::Listener { server_config } => Some(server_config.clone()),
        EndpointSetup::Connector { .. } => None,
    };
    let mut quic_state = QuicState::new(remote_addr, server_config);

    // Connector: initiate connection.
    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        let (handle, conn) = quic_state
            .endpoint
            .connect(Instant::now(), client_config, remote_addr, "quictun")
            .map_err(|e| anyhow::anyhow!("connect failed: {e:?}"))?;
        quic_state.ch = Some(handle);
        quic_state.connection = Some(conn);
    }

    // Listener: feed first packet.
    if let Some(data) = first_packet {
        let data = BytesMut::from(&data[..]);
        let mut response_buf = Vec::new();
        if let Some(event) = quic_state.endpoint.handle(
            Instant::now(),
            remote_addr,
            None,
            None,
            data,
            &mut response_buf,
        ) {
            let resp =
                shared::handle_datagram_event(&mut quic_state, event, &mut response_buf);
            for pkt in resp {
                let _ = udp_main.send(pkt).await;
            }
        }
    }

    // 3. Initial drive to send handshake packets.
    let dr = shared::drive(&mut quic_state);
    for pkt in dr.transmits {
        let _ = udp_main.send(pkt).await;
    }

    let quic = Rc::new(RefCell::new(quic_state));

    // 4. Create dup'd TUN fd handles.
    let tun_r = AsyncFd::new(dup_fd(tun_fd)?)
        .context("failed to create TUN read handle")?;
    let tun_w_out = AsyncFd::new(dup_fd(tun_fd)?)
        .context("failed to create TUN write handle (outbound)")?;
    let tun_w_in = AsyncFd::new(dup_fd(tun_fd)?)
        .context("failed to create TUN write handle (inbound)")?;

    // 5. Spawn outbound + inbound tasks.
    info!("compio: starting event loop");

    let quic_out = quic.clone();
    let quic_in = quic.clone();

    let h1 = compio::runtime::spawn(async move {
        if let Err(e) = outbound_loop(tun_r, tun_w_out, udp_dup, quic_out).await {
            warn!(error = %e, "outbound loop error");
        }
    });

    let h2 = compio::runtime::spawn(async move {
        if let Err(e) = inbound_loop(tun_w_in, udp_main, quic_in).await {
            warn!(error = %e, "inbound loop error");
        }
    });

    // Wait for either task to complete.
    futures_util::future::select(h1, h2).await;

    info!("compio: event loop finished");
    Ok(())
}

/// Outbound loop: TUN Read -> QUIC encrypt -> UDP Send.
async fn outbound_loop(
    mut tun_r: AsyncFd<OwnedFd>,
    mut tun_w: AsyncFd<OwnedFd>,
    udp: UdpSocket,
    quic: Rc<RefCell<QuicState>>,
) -> Result<()> {
    info!("outbound: started");
    let mut stats_reads: u64 = 0;
    let mut stats_sends: u64 = 0;
    let mut stats_transmits: u64 = 0;
    let mut stats_last = Instant::now();

    loop {
        // Read a TUN packet (ownership-based: buffer passed in, returned with data).
        let buf = vec![0u8; BUF_SIZE];
        let BufResult(result, buf) = tun_r.read(buf).await;
        let n = result.context("TUN read")?;
        if n == 0 {
            info!("outbound: TUN read returned 0, stopping");
            return Ok(());
        }
        stats_reads += 1;

        // Feed to quinn-proto and drive.
        let (transmits, datagrams, connection_lost) = {
            let mut state = quic.borrow_mut();
            if let Some(conn) = state.connection.as_mut() {
                if conn.is_handshaking() {
                    // Can't send datagrams until handshake completes.
                } else {
                    let max = conn.datagrams().max_size().unwrap_or(1200);
                    if n <= max {
                        let packet = Bytes::copy_from_slice(&buf[..n]);
                        match conn.datagrams().send(packet, true) {
                            Ok(()) => stats_sends += 1,
                            Err(e) => {
                                debug!(error = ?e, "outbound: datagrams.send failed")
                            }
                        }
                    } else {
                        debug!(size = n, max, "outbound: dropping oversized TUN packet");
                    }
                }
            }
            let dr = shared::drive(&mut state);
            (dr.transmits, dr.datagrams, dr.connection_lost)
        }; // RefCell borrow dropped here, before any .await

        if connection_lost {
            info!("outbound: connection lost");
            return Ok(());
        }

        // Send QUIC transmits via UDP.
        stats_transmits += transmits.len() as u64;
        for pkt in transmits {
            let _ = udp.send(pkt).await;
        }

        // Write any received datagrams to TUN.
        for dg in datagrams {
            let _ = tun_w.write(dg.to_vec()).await;
        }

        // Stats logging.
        if stats_last.elapsed() >= Duration::from_secs(2) {
            info!(
                reads = stats_reads,
                sends = stats_sends,
                transmits = stats_transmits,
                "outbound: stats"
            );
            stats_reads = 0;
            stats_sends = 0;
            stats_transmits = 0;
            stats_last = Instant::now();
        }
    }
}

/// Inbound loop: UDP Recv -> QUIC decrypt -> TUN Write.
async fn inbound_loop(
    mut tun_w: AsyncFd<OwnedFd>,
    udp: UdpSocket,
    quic: Rc<RefCell<QuicState>>,
) -> Result<()> {
    info!("inbound: started");
    let mut response_buf = Vec::new();
    let mut stats_recvs: u64 = 0;
    let mut stats_datagrams: u64 = 0;
    let mut stats_transmits: u64 = 0;
    let mut stats_timeouts: u64 = 0;
    let mut stats_last = Instant::now();

    loop {
        // Get next timeout deadline from quinn-proto.
        let deadline = quic
            .borrow_mut()
            .connection
            .as_mut()
            .and_then(|c| c.poll_timeout())
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));

        // Recv with timeout (buffer is consumed by compio; allocate fresh each iteration).
        let recv_buf = vec![0u8; BUF_SIZE];

        let (transmits, datagrams, connection_lost) =
            match timeout_at(deadline, udp.recv(recv_buf)).await {
                Ok(BufResult(io_result, buf)) => {
                    let n = io_result.context("UDP recv")?;
                    stats_recvs += 1;
                    let data = BytesMut::from(&buf[..n]);

                    let mut state = quic.borrow_mut();
                    let now = Instant::now();
                    let remote = state.remote_addr;

                    let mut resp_tx = Vec::new();
                    if let Some(event) = state.endpoint.handle(
                        now,
                        remote,
                        None,
                        None,
                        data,
                        &mut response_buf,
                    ) {
                        resp_tx = shared::handle_datagram_event(
                            &mut state,
                            event,
                            &mut response_buf,
                        );
                    }
                    response_buf.clear();

                    let dr = shared::drive(&mut state);
                    let mut all_tx = dr.transmits;
                    all_tx.extend(resp_tx);
                    (all_tx, dr.datagrams, dr.connection_lost)
                }
                Err(_elapsed) => {
                    stats_timeouts += 1;
                    let mut state = quic.borrow_mut();
                    if let Some(conn) = state.connection.as_mut() {
                        conn.handle_timeout(Instant::now());
                    }
                    let dr = shared::drive(&mut state);
                    (dr.transmits, dr.datagrams, dr.connection_lost)
                }
            };

        if connection_lost {
            info!("inbound: connection lost");
            return Ok(());
        }

        // Send QUIC transmits via UDP.
        stats_datagrams += datagrams.len() as u64;
        stats_transmits += transmits.len() as u64;
        for pkt in transmits {
            let _ = udp.send(pkt).await;
        }

        // Write decrypted datagrams to TUN.
        for dg in datagrams {
            let _ = tun_w.write(dg.to_vec()).await;
        }

        // Stats logging.
        if stats_last.elapsed() >= Duration::from_secs(2) {
            info!(
                recvs = stats_recvs,
                datagrams = stats_datagrams,
                transmits = stats_transmits,
                timeouts = stats_timeouts,
                "inbound: stats"
            );
            stats_recvs = 0;
            stats_datagrams = 0;
            stats_transmits = 0;
            stats_timeouts = 0;
            stats_last = Instant::now();
        }
    }
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
    }
    Ok(())
}

/// Duplicate a raw file descriptor, returning an `OwnedFd`.
fn dup_fd(fd: RawFd) -> Result<OwnedFd> {
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("dup() failed");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
}

/// Duplicate a raw file descriptor, returning a raw fd.
fn dup_raw(fd: RawFd) -> Result<RawFd> {
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("dup() failed");
    }
    Ok(new_fd)
}
