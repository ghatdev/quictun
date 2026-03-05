use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use crossbeam_channel::{Receiver, Sender};
use io_uring::{IoUring, cqueue, opcode, squeue::Flags, types};
use quinn_proto::ServerConfig;
use tracing::{debug, info, warn};

use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::{BUF_SIZE as HANDSHAKE_BUF_SIZE, MultiQuicState};
use quictun_quic::local::LocalConnectionState;

use crate::bufpool::{
    self, BUF_GROUP_UDP, BUF_SIZE, BufferPool, OP_PROVIDE_BUF, OP_SHUTDOWN, OP_TIMER, OP_TUN_WRITE,
    OP_UDP_RECV, OP_UDP_SEND, OP_WAKE, ProvidedPool,
};
use crate::event_loop::{set_blocking, set_nonblocking};
use crate::timer::Timer;
use crate::udp;

/// io_uring ring size for the engine thread.
const RING_SIZE: u32 = 1024;

// Registered fd indices for the engine thread.
const FD_UDP: u32 = 0;
const FD_TUN: u32 = 1;
const FD_TIMER: u32 = 2;
const FD_NOTIFY: u32 = 3;
const FD_SHUTDOWN: u32 = 4;

/// Maximum QUIC packet size.
const MAX_PACKET: usize = 2048;

/// How the engine should set up the QUIC connection.
pub enum EngineSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Per-connection state in the connection table.
#[allow(dead_code)]
struct ConnEntry {
    conn: LocalConnectionState,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

/// Run the engine thread: two-phase architecture.
///
/// Phase 1 (Handshake): Uses MultiQuicState + quinn-proto for QUIC handshake.
/// Phase 2 (Data plane): Uses LocalConnectionState from quictun-quic for
///   optimized 1-RTT encrypt/decrypt with zero quinn-proto overhead.
pub fn run(
    tun_fd: RawFd,
    udp_fd: RawFd,
    setup: EngineSetup,
    peers: Vec<PeerConfig>,
    cid_len: usize,
    idle_timeout: Duration,
    timer: Timer,
    rx: Receiver<Vec<u8>>,
    notify_fd: RawFd,
    shutdown_fd: RawFd,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    pool_size: usize,
    zero_copy: bool,
    ring_fd_tx: Option<Sender<RawFd>>,
) -> Result<()> {
    // ── Phase 1: Handshake ─────────────────────────────────────────────
    let (conn_entry, remote_addr) = run_handshake(
        udp_fd, &setup, &peers, idle_timeout,
    )?;

    info!(
        tunnel_ip = %conn_entry.tunnel_ip,
        remote = %remote_addr,
        "handshake complete, entering fast data plane"
    );

    // ── Phase 2: Data plane ────────────────────────────────────────────
    run_data_plane(
        tun_fd, udp_fd, conn_entry, remote_addr, cid_len, idle_timeout,
        timer, rx, notify_fd, shutdown_fd, sqpoll, sqpoll_cpu, pool_size,
        zero_copy, ring_fd_tx,
    )
}

/// Phase 1: Run handshake using MultiQuicState + blocking I/O.
///
/// Returns (ConnEntry, remote_addr) on success.
fn run_handshake(
    udp_fd: RawFd,
    setup: &EngineSetup,
    peers: &[PeerConfig],
    _idle_timeout: Duration,
) -> Result<(ConnEntry, SocketAddr)> {
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut transmit_buf = Vec::with_capacity(HANDSHAKE_BUF_SIZE);

    let (mut multi_state, remote_addr) = match setup {
        EngineSetup::Connector { remote_addr, client_config } => {
            let mut ms = MultiQuicState::new_connector();
            ms.connect(client_config.clone(), *remote_addr)?;

            // Drain initial ClientHello transmits.
            drain_handshake_transmits(udp_fd, &mut ms, &mut transmit_buf, *remote_addr)?;

            (ms, *remote_addr)
        }
        EngineSetup::Listener { server_config } => {
            // Blocking wait for first packet.
            set_blocking(udp_fd)
                .context("engine: failed to set blocking for first-packet recv")?;

            let (n, peer_addr) = udp::recvfrom_first_raw(udp_fd, &mut recv_buf)
                .context("engine: recvfrom_first failed")?;
            info!(peer = %peer_addr, bytes = n, "engine: received first packet");

            udp::connect_to_peer_raw(udp_fd, peer_addr)
                .context("engine: connect_to_peer failed")?;
            set_nonblocking(udp_fd)
                .context("engine: failed to set non-blocking after first-packet recv")?;

            let mut ms = MultiQuicState::new(server_config.clone());

            // Feed the first packet.
            let data = BytesMut::from(&recv_buf[..n]);
            let responses = ms.handle_incoming(
                Instant::now(), peer_addr, None, data, &mut response_buf,
            );
            send_responses_raw(udp_fd, &responses, peer_addr);

            // Drain initial ServerHello transmits.
            drain_handshake_transmits(udp_fd, &mut ms, &mut transmit_buf, peer_addr)?;

            (ms, peer_addr)
        }
    };

    // Blocking handshake loop — poll for packets, drive state machine.
    // Use non-blocking recv with a sleep loop (simpler than setting up io_uring for handshake).
    let handshake_start = Instant::now();
    let handshake_timeout = Duration::from_secs(10);

    loop {
        if handshake_start.elapsed() > handshake_timeout {
            anyhow::bail!("handshake timed out after {handshake_timeout:?}");
        }

        // Try to receive a packet (non-blocking).
        let ret = unsafe {
            libc::recv(
                udp_fd,
                recv_buf.as_mut_ptr() as *mut libc::c_void,
                recv_buf.len(),
                libc::MSG_DONTWAIT,
            )
        };

        if ret > 0 {
            let n = ret as usize;
            let data = BytesMut::from(&recv_buf[..n]);
            let responses = multi_state.handle_incoming(
                Instant::now(), remote_addr, None, data, &mut response_buf,
            );
            send_responses_raw(udp_fd, &responses, remote_addr);
        }

        // Handle timeouts for handshakes.
        let now = Instant::now();
        for hs in multi_state.handshakes.values_mut() {
            hs.connection.handle_timeout(now);
        }

        // Drain transmits.
        drain_handshake_transmits(udp_fd, &mut multi_state, &mut transmit_buf, remote_addr)?;

        // Check for completed handshakes.
        let result = multi_state.poll_handshakes();

        // Drain transmits again after polling.
        drain_handshake_transmits(udp_fd, &mut multi_state, &mut transmit_buf, remote_addr)?;

        for ch in result.completed {
            let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
                continue;
            };

            // Identify peer.
            let matched_peer = if peers.len() == 1 {
                &peers[0]
            } else {
                match peer::identify_peer(&hs.connection, peers) {
                    Some(p) => p,
                    None => {
                        warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                        continue;
                    }
                }
            };

            let tunnel_ip = matched_peer.tunnel_ip;
            let allowed_ips = matched_peer.allowed_ips.clone();
            let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));
            let now_inst = Instant::now();

            info!(
                remote = %hs.remote_addr,
                tunnel_ip = %tunnel_ip,
                cid = %hex::encode(&hs.local_cid[..]),
                "connection established"
            );

            return Ok((
                ConnEntry {
                    conn: conn_state,
                    tunnel_ip,
                    allowed_ips,
                    remote_addr: hs.remote_addr,
                    keepalive_interval,
                    last_tx: now_inst,
                    last_rx: now_inst,
                },
                hs.remote_addr,
            ));
        }

        if !result.failed.is_empty() {
            anyhow::bail!("handshake failed");
        }

        // Small sleep to avoid busy-spinning during handshake.
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Drain quinn-proto handshake transmits via raw fd.
fn drain_handshake_transmits(
    udp_fd: RawFd,
    state: &mut MultiQuicState,
    buf: &mut Vec<u8>,
    _remote: SocketAddr,
) -> Result<()> {
    let now = Instant::now();
    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, buf) else {
                break;
            };
            send_raw(udp_fd, &buf[..transmit.size]);
        }
    }
    Ok(())
}

/// Send handshake response transmits via raw fd.
fn send_responses_raw(udp_fd: RawFd, responses: &[(usize, [u8; HANDSHAKE_BUF_SIZE])], _remote: SocketAddr) {
    for (len, data) in responses {
        send_raw(udp_fd, &data[..*len]);
    }
}

/// Send data via raw fd (connected UDP socket).
fn send_raw(fd: RawFd, data: &[u8]) {
    unsafe {
        libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0);
    }
}

/// Phase 2: Fast data plane using LocalConnectionState + io_uring.
#[allow(clippy::too_many_arguments)]
fn run_data_plane(
    tun_fd: RawFd,
    udp_fd: RawFd,
    mut entry: ConnEntry,
    _remote_addr: SocketAddr,
    cid_len: usize,
    idle_timeout: Duration,
    timer: Timer,
    rx: Receiver<Vec<u8>>,
    notify_fd: RawFd,
    shutdown_fd: RawFd,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    pool_size: usize,
    zero_copy: bool,
    ring_fd_tx: Option<Sender<RawFd>>,
) -> Result<()> {
    let mut ring = if sqpoll {
        let mut builder = IoUring::builder();
        builder.setup_sqpoll(1000);
        if let Some(cpu) = sqpoll_cpu {
            builder.setup_sqpoll_cpu(cpu);
        }
        builder
            .build(RING_SIZE)
            .context("engine: failed to create io_uring with SQPOLL")?
    } else {
        IoUring::new(RING_SIZE).context("engine: failed to create io_uring")?
    };

    // Signal ring fd to reader so it can attach_wq to our SQPOLL thread.
    if let Some(tx) = ring_fd_tx {
        let _ = tx.send(ring.as_raw_fd());
    }

    // Registered buffer pool for sends + TUN writes (WriteFixed).
    let mut pool = BufferPool::new(pool_size);

    // Provided buffer pool for multishot UDP recv (kernel-managed).
    let recv_pool = ProvidedPool::new(pool_size, BUF_GROUP_UDP);

    let timer_fd = timer.raw_fd();
    let mut timer_buf = [0u8; 8];

    // Register file descriptors for zero-overhead fd lookups.
    let fds = [udp_fd, tun_fd, timer_fd, notify_fd, shutdown_fd];
    ring.submitter()
        .register_files(&fds)
        .context("engine: failed to register files")?;

    // Register send/TUN buffer pool.
    pool.register(&ring)?;

    info!(
        sqpoll,
        "engine: io_uring data plane initialized (registered fds + buffers)"
    );

    // Provide all recv buffers to kernel.
    provide_all_buffers(&mut ring, &recv_pool)?;

    // Submit multishot recv.
    submit_multishot_recv(&mut ring, &recv_pool)?;
    let mut multishot_active = true;

    // Submit timer read SQE.
    submit_timer_read(&mut ring, &mut timer_buf)?;

    // Submit channel notification eventfd read.
    let mut notify_buf = [0u8; 8];
    submit_notify_read(&mut ring, &mut notify_buf)?;

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, &mut shutdown_buf)?;

    // Pre-allocate reusable buffers.
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // Arm keepalive timer.
    let keepalive_deadline = Instant::now() + entry.keepalive_interval;
    timer.arm(keepalive_deadline);

    info!(sqpoll, "engine: entering io_uring fast data plane event loop");
    let mut stats_udp_recvs: u64 = 0;
    let mut stats_datagrams: u64 = 0;
    let mut stats_encrypts: u64 = 0;
    let mut stats_timers: u64 = 0;
    let mut stats_channel_wakes: u64 = 0;
    let mut stats_channel_packets: u64 = 0;
    let mut stats_last = Instant::now();
    let mut stats_spins: u64 = 0;

    loop {
        // With SQPOLL: busy-poll CQ (zero syscalls in hot path).
        // SQPOLL thread submits SQEs from shared memory; we read CQEs from shared memory.
        // Only call submit() if SQPOLL thread went to sleep (needs wakeup).
        //
        // Without SQPOLL: submit_and_wait(1) blocks until ≥1 CQE (one syscall per iteration).
        let cqes: Vec<_> = if sqpoll {
            loop {
                // Flush any pending SQEs + wake SQPOLL thread if it slept.
                // submit() with SQPOLL returns immediately (no syscall) if thread is awake.
                ring.submit().context("engine: submit failed")?;

                // Poll CQ — pure shared memory read, no syscall.
                let mut cq = ring.completion();
                cq.sync();
                let batch: Vec<_> = cq.collect();
                if !batch.is_empty() {
                    break batch;
                }
                stats_spins += 1;
                std::hint::spin_loop();
            }
        } else {
            ring.submit_and_wait(1)
                .context("engine: submit_and_wait failed")?;
            ring.completion().collect()
        };

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_UDP_RECV => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: multishot recv error");
                        multishot_active = false;
                        continue;
                    }
                    stats_udp_recvs += 1;
                    let flags = cqe.flags();
                    let bid = cqueue::buffer_select(flags)
                        .expect("RecvMulti CQE must have BUFFER_SELECT flag");
                    let len = result as usize;

                    // Copy to stack buffer for in-place decrypt (provided bufs are read-only).
                    let src = recv_pool.slice(bid, len);
                    let mut pkt_buf = [0u8; BUF_SIZE];
                    pkt_buf[..len].copy_from_slice(src);

                    // Re-provide consumed buffer immediately.
                    reprovide_buffer(&mut ring, &recv_pool, bid)?;

                    if len == 0 || pkt_buf[0] & 0x80 != 0 {
                        if !cqueue::more(flags) {
                            multishot_active = false;
                        }
                        continue;
                    }

                    // Short header — fast path: decrypt in-place (zero heap alloc).
                    if cid_len > 0 && len > cid_len {
                        match entry.conn.decrypt_packet_in_place(&mut pkt_buf[..len]) {
                            Ok(decrypted) => {
                                entry.last_rx = Instant::now();
                                if let Some(ref ack) = decrypted.ack {
                                    entry.conn.process_ack(ack);
                                }
                                if decrypted.close_received {
                                    info!("engine: peer sent CONNECTION_CLOSE");
                                    signal_shutdown(shutdown_fd);
                                    return Ok(());
                                }
                                for range in &decrypted.datagrams {
                                    stats_datagrams += 1;
                                    let datagram = &pkt_buf[range.clone()];
                                    if datagram.len() < 20 {
                                        continue;
                                    }
                                    let src_ip = Ipv4Addr::new(
                                        datagram[12], datagram[13],
                                        datagram[14], datagram[15],
                                    );
                                    if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                                        debug!(src = %src_ip, "dropping: source IP not in allowed_ips");
                                        continue;
                                    }
                                    submit_tun_write(&mut ring, &mut pool, datagram)?;
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "decrypt failed, dropping");
                            }
                        }
                    }

                    if !cqueue::more(flags) {
                        multishot_active = false;
                    }
                }

                OP_TIMER => {
                    stats_timers += 1;
                    // Resubmit timer read.
                    submit_timer_read(&mut ring, &mut timer_buf)?;

                    // Check idle timeout.
                    if entry.last_rx.elapsed() >= idle_timeout {
                        info!("engine: connection idle timeout");
                        if let Ok(result) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                            submit_udp_send(&mut ring, &mut pool, &encrypt_buf[..result.len], zero_copy)?;
                        }
                        signal_shutdown(shutdown_fd);
                        // Submit final sends before returning.
                        let _ = ring.submit();
                        return Ok(());
                    }

                    // Send keepalive if needed.
                    if entry.last_tx.elapsed() >= entry.keepalive_interval {
                        let ack_ranges = entry.conn.generate_ack_ranges();
                        let ack_ref = if !ack_ranges.is_empty() {
                            Some(ack_ranges.as_slice())
                        } else {
                            None
                        };
                        match entry.conn.encrypt_datagram(&[], ack_ref, &mut encrypt_buf) {
                            Ok(result) => {
                                submit_udp_send(&mut ring, &mut pool, &encrypt_buf[..result.len], zero_copy)?;
                                entry.last_tx = Instant::now();
                                debug!(pn = result.pn, "sent keepalive");
                            }
                            Err(e) => {
                                warn!(error = %e, "keepalive encrypt failed");
                            }
                        }
                    }

                    // Check key exhaustion.
                    if entry.conn.is_key_exhausted() {
                        warn!("engine: keys exhausted, closing connection");
                        if let Ok(result) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                            submit_udp_send(&mut ring, &mut pool, &encrypt_buf[..result.len], zero_copy)?;
                        }
                        signal_shutdown(shutdown_fd);
                        let _ = ring.submit();
                        return Ok(());
                    }

                    // Re-arm timer at keepalive interval.
                    timer.arm(Instant::now() + entry.keepalive_interval);
                }

                OP_WAKE => {
                    stats_channel_wakes += 1;

                    // Drain all TUN packets from the channel.
                    while let Ok(packet) = rx.try_recv() {
                        stats_channel_packets += 1;

                        if packet.len() < 20 {
                            continue;
                        }

                        let ack_ranges = if entry.conn.needs_ack() {
                            Some(entry.conn.generate_ack_ranges())
                        } else {
                            None
                        };
                        match entry.conn.encrypt_datagram(
                            &packet, ack_ranges.as_deref(), &mut encrypt_buf,
                        ) {
                            Ok(result) => {
                                stats_encrypts += 1;
                                if pool.available() > RESERVED_BUFS {
                                    submit_udp_send_direct(
                                        &mut ring, &mut pool, &encrypt_buf, result.len, zero_copy,
                                    )?;
                                } else {
                                    submit_udp_send(
                                        &mut ring, &mut pool, &encrypt_buf[..result.len], zero_copy,
                                    )?;
                                }
                                entry.last_tx = Instant::now();
                            }
                            Err(e) => {
                                warn!(error = %e, "encrypt failed, dropping packet");
                            }
                        }
                    }

                    // Resubmit channel eventfd read.
                    submit_notify_read(&mut ring, &mut notify_buf)?;
                }

                OP_UDP_SEND => {
                    if zero_copy {
                        let flags = cqe.flags();
                        if cqueue::notif(flags) {
                            pool.free(idx);
                        } else if result < 0 {
                            let err = std::io::Error::from_raw_os_error(-result);
                            debug!(error = %err, "engine: UDP send error");
                        }
                    } else {
                        if result < 0 {
                            let err = std::io::Error::from_raw_os_error(-result);
                            debug!(error = %err, "engine: UDP send error");
                        }
                        pool.free(idx);
                    }
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: TUN write error");
                    }
                    pool.free(idx);
                }

                OP_PROVIDE_BUF => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: provide buffer failed");
                    }
                }

                OP_SHUTDOWN => {
                    debug!("engine: shutdown signal received");
                    // Send CONNECTION_CLOSE.
                    if let Ok(result) = entry.conn.encrypt_connection_close(&mut encrypt_buf) {
                        let _ = submit_udp_send(&mut ring, &mut pool, &encrypt_buf[..result.len], zero_copy);
                    }
                    let _ = ring.submit();
                    return Ok(());
                }

                _ => {
                    warn!(op, "engine: unknown op in CQE");
                }
            }
        }

        // Resubmit multishot recv if it was cancelled.
        if !multishot_active {
            submit_multishot_recv(&mut ring, &recv_pool)?;
            multishot_active = true;
        }

        if stats_last.elapsed() >= Duration::from_secs(2) {
            info!(
                udp_recvs = stats_udp_recvs,
                datagrams = stats_datagrams,
                encrypts = stats_encrypts,
                timers = stats_timers,
                channel_wakes = stats_channel_wakes,
                channel_packets = stats_channel_packets,
                spins = stats_spins,
                free_bufs = pool.available(),
                "engine: stats"
            );
            stats_udp_recvs = 0;
            stats_datagrams = 0;
            stats_encrypts = 0;
            stats_timers = 0;
            stats_channel_wakes = 0;
            stats_channel_packets = 0;
            stats_spins = 0;
            stats_last = Instant::now();
        }
    }
}

// ── io_uring SQE helpers (unchanged from original) ──────────────────────

/// Minimum free buffers to reserve for recv resubmits and TUN writes.
const RESERVED_BUFS: usize = 64;

/// Provide all buffers in the recv pool to the kernel as a buffer group.
fn provide_all_buffers(ring: &mut IoUring, recv_pool: &ProvidedPool) -> Result<()> {
    let entry = opcode::ProvideBuffers::new(
        recv_pool.ptr(0),
        BUF_SIZE as i32,
        recv_pool.size() as u16,
        recv_pool.group_id(),
        0,
    )
    .build()
    .user_data(bufpool::encode_user_data(OP_PROVIDE_BUF, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a single multishot recv SQE.
fn submit_multishot_recv(ring: &mut IoUring, recv_pool: &ProvidedPool) -> Result<()> {
    let entry = opcode::RecvMulti::new(types::Fixed(FD_UDP), recv_pool.group_id())
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_RECV, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Re-provide a single consumed buffer back to the kernel.
fn reprovide_buffer(ring: &mut IoUring, recv_pool: &ProvidedPool, bid: u16) -> Result<()> {
    let entry = opcode::ProvideBuffers::new(
        recv_pool.ptr(bid),
        BUF_SIZE as i32,
        1,
        recv_pool.group_id(),
        bid,
    )
    .build()
    .flags(Flags::SKIP_SUCCESS)
    .user_data(bufpool::encode_user_data(OP_PROVIDE_BUF, bid as usize));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a UDP send using registered fd + registered buffer.
fn submit_udp_send(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    data: &[u8],
    zero_copy: bool,
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("engine: buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let len = data.len().min(BUF_SIZE);
    pool.slice_mut(idx)[..len].copy_from_slice(&data[..len]);

    let entry = if zero_copy {
        opcode::SendZc::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32)
            .buf_index(Some(idx as u16))
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    } else {
        opcode::WriteFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    };

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a UDP send by copying data into a pool slot (pre-checked availability).
fn submit_udp_send_direct(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    src: &[u8],
    len: usize,
    zero_copy: bool,
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("engine: unexpected buffer pool exhaustion in send_direct");
            return Ok(());
        }
    };
    let dst = pool.slice_mut(idx);
    let len = len.min(BUF_SIZE);
    dst[..len].copy_from_slice(&src[..len]);

    let entry = if zero_copy {
        opcode::SendZc::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32)
            .buf_index(Some(idx as u16))
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    } else {
        opcode::WriteFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    };

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a TUN write using registered fd + registered buffer.
fn submit_tun_write(ring: &mut IoUring, pool: &mut BufferPool, data: &[u8]) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("engine: buffer pool exhausted, dropping TUN write");
            return Ok(());
        }
    };
    let len = data.len().min(BUF_SIZE);
    pool.slice_mut(idx)[..len].copy_from_slice(&data[..len]);

    let entry =
        opcode::WriteFixed::new(types::Fixed(FD_TUN), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_TUN_WRITE, idx));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a timer read using registered fd.
fn submit_timer_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_TIMER), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a channel notification eventfd read.
fn submit_notify_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_NOTIFY), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_WAKE, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a shutdown eventfd read.
fn submit_shutdown_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_SHUTDOWN), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Push an SQE to the submission queue, flushing if full.
fn push_sqe(ring: &mut IoUring, entry: &io_uring::squeue::Entry) -> Result<()> {
    if unsafe { ring.submission().push(entry) }.is_ok() {
        return Ok(());
    }
    ring.submit().context("engine: SQ flush")?;
    loop {
        std::hint::spin_loop();
        if unsafe { ring.submission().push(entry) }.is_ok() {
            return Ok(());
        }
    }
}

/// Write to the shutdown eventfd to wake the reader thread.
fn signal_shutdown(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
