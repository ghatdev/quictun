use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use crossbeam_channel::{Receiver, Sender};
use io_uring::{IoUring, opcode, types};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig,
};
use tracing::{debug, info, warn};

use crate::bufpool::{self, BUF_SIZE, BufferPool, OP_TIMER, OP_UDP_RECV, OP_UDP_SEND, OP_WAKE};
use crate::timer::Timer;
use crate::wakeup::EventFd;

/// Number of UDP recv SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the QUIC thread.
const RING_SIZE: u32 = 256;

/// Configuration for connecting to a remote peer.
pub struct ConnectorSetup {
    pub remote_addr: std::net::SocketAddr,
    pub client_config: ClientConfig,
}

/// Configuration for accepting from a remote peer (listener).
pub struct ListenerSetup {
    pub server_config: Arc<ServerConfig>,
    pub remote_addr: std::net::SocketAddr,
    pub first_packet: Vec<u8>,
    pub first_packet_len: usize,
}

/// What to do with the QUIC endpoint.
pub enum Setup {
    Connector(ConnectorSetup),
    Listener(ListenerSetup),
}

/// Run the QUIC/UDP I/O thread.
///
/// Receives TUN packets from `from_tun` → encrypt + send via UDP.
/// Receives UDP packets → decrypt → send to TUN thread via `to_tun`.
pub fn run(
    udp_fd: RawFd,
    setup: Setup,
    from_tun: Receiver<Bytes>,
    to_tun: Sender<Bytes>,
    wake_fd: &EventFd,
    tun_wake: &EventFd,
) -> Result<()> {
    let mut ring = IoUring::new(RING_SIZE).context("quic: failed to create io_uring")?;
    let mut pool = BufferPool::new();

    let timer = Timer::new().context("quic: failed to create timerfd")?;
    let timer_fd = timer.raw_fd();

    let mut timer_buf = [0u8; 8];
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut response_buf: Vec<u8> = Vec::new();

    let ep_config = Arc::new(EndpointConfig::default());

    let (remote_addr, server_config) = match &setup {
        Setup::Connector(c) => (c.remote_addr, None),
        Setup::Listener(l) => (l.remote_addr, Some(l.server_config.clone())),
    };

    let mut endpoint = Endpoint::new(ep_config, server_config.clone(), true, None);

    let (mut ch, mut connection): (Option<ConnectionHandle>, Option<quinn_proto::Connection>) =
        match &setup {
            Setup::Connector(c) => {
                let (handle, conn) = endpoint
                    .connect(Instant::now(), c.client_config.clone(), c.remote_addr, "quictun")
                    .map_err(|e| anyhow::anyhow!("connect failed: {e:?}"))?;
                (Some(handle), Some(conn))
            }
            Setup::Listener(_) => (None, None),
        };

    // Prime UDP recv SQEs.
    for _ in 0..PREFILL_READS {
        submit_udp_recv(&mut ring, &mut pool, udp_fd)?;
    }

    // Submit timer read SQE.
    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;

    // Submit eventfd read SQE for TUN→QUIC channel wakeup.
    let mut wake_buf = [0u8; 8];
    submit_wake_read(&mut ring, wake_fd.raw_fd(), &mut wake_buf)?;

    // Connector: drain initial handshake transmits.
    if let Some(ref mut conn) = connection {
        drain_transmits(conn, &mut ring, &mut pool, udp_fd, &mut transmit_buf)?;
        if let Some(deadline) = conn.poll_timeout() {
            timer.arm(deadline);
        }
    }

    // Listener: feed the first packet that was captured via recvfrom().
    if let Setup::Listener(ref l) = setup {
        let data = BytesMut::from(&l.first_packet[..l.first_packet_len]);
        let now = Instant::now();
        if let Some(event) =
            endpoint.handle(now, remote_addr, None, None, data, &mut response_buf)
        {
            handle_datagram_event(
                event,
                &mut endpoint,
                &mut ch,
                &mut connection,
                &server_config,
                remote_addr,
                &mut ring,
                &mut pool,
                udp_fd,
                &mut response_buf,
            )?;
        }
        response_buf.clear();

        // Drive after first packet.
        drive_connection(
            &mut connection,
            ch,
            &mut endpoint,
            &mut ring,
            &mut pool,
            udp_fd,
            &mut transmit_buf,
            &timer,
            &to_tun,
            tun_wake,
        )?;
    }

    // Main event loop.
    info!("quic: entering io_uring event loop");
    loop {
        ring.submit_and_wait(1)
            .context("quic: submit_and_wait failed")?;

        let cqes: Vec<_> = ring.completion().collect();
        let now = Instant::now();
        let mut sent_to_tun = false;

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_UDP_RECV => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "quic: UDP recv error");
                        pool.free(idx);
                        submit_udp_recv(&mut ring, &mut pool, udp_fd)?;
                        continue;
                    }
                    let len = result as usize;
                    let data = BytesMut::from(pool.slice(idx, len));
                    pool.free(idx);

                    if let Some(event) =
                        endpoint.handle(now, remote_addr, None, None, data, &mut response_buf)
                    {
                        handle_datagram_event(
                            event,
                            &mut endpoint,
                            &mut ch,
                            &mut connection,
                            &server_config,
                            remote_addr,
                            &mut ring,
                            &mut pool,
                            udp_fd,
                            &mut response_buf,
                        )?;
                    }
                    response_buf.clear();

                    submit_udp_recv(&mut ring, &mut pool, udp_fd)?;
                }

                OP_UDP_SEND => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        debug!(error = %err, "quic: UDP send error");
                    }
                    pool.free(idx);
                }

                OP_TIMER => {
                    if let Some(ref mut conn) = connection {
                        conn.handle_timeout(now);
                    }
                    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;
                }

                OP_WAKE => {
                    // Channel data from TUN thread — drain and feed to QUIC.
                    if let Some(ref mut conn) = connection {
                        while let Ok(data) = from_tun.try_recv() {
                            let max = conn.datagrams().max_size().unwrap_or(1200);
                            if data.len() > max {
                                debug!(
                                    packet_size = data.len(),
                                    max, "quic: dropping oversized TUN packet"
                                );
                            } else if let Err(e) = conn.datagrams().send(data, true) {
                                debug!(error = ?e, "quic: datagrams.send failed (dropped)");
                            }
                        }
                    }
                    submit_wake_read(&mut ring, wake_fd.raw_fd(), &mut wake_buf)?;
                }

                _ => {
                    warn!(op, "quic: unknown op in CQE");
                }
            }

            // Drive connection after each CQE.
            let drove_tun = drive_connection(
                &mut connection,
                ch,
                &mut endpoint,
                &mut ring,
                &mut pool,
                udp_fd,
                &mut transmit_buf,
                &timer,
                &to_tun,
                tun_wake,
            )?;
            sent_to_tun |= drove_tun;
        }

        // Batch-wake TUN thread once per iteration if we sent any packets.
        if sent_to_tun {
            tun_wake.wake();
        }

        ring.submit().context("quic: submit flush failed")?;
    }
}

/// Drive connection state: poll endpoint/app events, drain transmits, update timer.
/// Returns `true` if any datagrams were sent to the TUN channel.
#[allow(clippy::too_many_arguments)]
fn drive_connection(
    connection: &mut Option<quinn_proto::Connection>,
    ch: Option<ConnectionHandle>,
    endpoint: &mut Endpoint,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    transmit_buf: &mut Vec<u8>,
    timer: &Timer,
    to_tun: &Sender<Bytes>,
    _tun_wake: &EventFd,
) -> Result<bool> {
    let (Some(conn), Some(conn_ch)) = (connection.as_mut(), ch) else {
        return Ok(false);
    };

    let mut sent_to_tun = false;

    // Process endpoint events.
    while let Some(event) = conn.poll_endpoint_events() {
        if let Some(conn_event) = endpoint.handle_event(conn_ch, event) {
            conn.handle_event(conn_event);
        }
    }

    // Process application events.
    while let Some(event) = conn.poll() {
        match event {
            Event::Connected => {
                info!("quic: QUIC connection established");
            }
            Event::DatagramReceived => {
                while let Some(datagram) = conn.datagrams().recv() {
                    // Send to TUN thread. Drop on channel full.
                    let _ = to_tun.try_send(datagram);
                    sent_to_tun = true;
                }
            }
            Event::DatagramsUnblocked => {}
            Event::ConnectionLost { reason } => {
                info!(reason = %reason, "quic: connection lost");
                std::process::exit(0);
            }
            Event::HandshakeDataReady | Event::Stream(_) => {}
        }
    }

    // Drain transmit queue.
    drain_transmits(conn, ring, pool, udp_fd, transmit_buf)?;

    // Update timer.
    match conn.poll_timeout() {
        Some(deadline) => timer.arm(deadline),
        None => timer.disarm(),
    }

    Ok(sent_to_tun)
}

/// Handle a DatagramEvent from endpoint.handle().
#[allow(clippy::too_many_arguments)]
fn handle_datagram_event(
    event: DatagramEvent,
    endpoint: &mut Endpoint,
    ch: &mut Option<ConnectionHandle>,
    connection: &mut Option<quinn_proto::Connection>,
    server_config: &Option<Arc<ServerConfig>>,
    remote_addr: std::net::SocketAddr,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    response_buf: &mut Vec<u8>,
) -> Result<()> {
    match event {
        DatagramEvent::ConnectionEvent(event_ch, event) => {
            if let Some(conn) = connection.as_mut() {
                if *ch == Some(event_ch) {
                    conn.handle_event(event);
                }
            }
        }
        DatagramEvent::NewConnection(incoming) => {
            if connection.is_none() {
                let now = Instant::now();
                match endpoint.accept(incoming, now, response_buf, server_config.clone()) {
                    Ok((new_ch, new_conn)) => {
                        info!(remote = %remote_addr, "quic: accepted incoming connection");
                        *ch = Some(new_ch);
                        *connection = Some(new_conn);
                    }
                    Err(e) => {
                        warn!(error = ?e.cause, "quic: failed to accept connection");
                        if let Some(transmit) = e.response {
                            submit_udp_send(ring, pool, udp_fd, &response_buf[..transmit.size])?;
                        }
                    }
                }
            } else {
                endpoint.ignore(incoming);
            }
        }
        DatagramEvent::Response(transmit) => {
            submit_udp_send(ring, pool, udp_fd, &response_buf[..transmit.size])?;
        }
    }
    Ok(())
}

fn submit_udp_recv(ring: &mut IoUring, pool: &mut BufferPool, udp_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("quic: buffer pool exhausted, skipping UDP recv submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(udp_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_RECV, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("quic: SQ full (udp recv)"))?;
    Ok(())
}

fn submit_udp_send(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    data: &[u8],
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("quic: buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry = opcode::Write::new(types::Fd(udp_fd), pool.ptr(idx), len as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("quic: SQ full (udp send)"))?;
    Ok(())
}

fn submit_timer_read(ring: &mut IoUring, timer_fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(timer_fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("quic: SQ full (timer)"))?;
    Ok(())
}

fn submit_wake_read(ring: &mut IoUring, wake_fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(wake_fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_WAKE, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("quic: SQ full (wake)"))?;
    Ok(())
}

fn drain_transmits(
    conn: &mut quinn_proto::Connection,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let now = Instant::now();
    loop {
        buf.clear();
        match conn.poll_transmit(now, 1, buf) {
            Some(transmit) => {
                submit_udp_send(ring, pool, udp_fd, &buf[..transmit.size])?;
            }
            None => break,
        }
    }
    Ok(())
}
