use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use quictun_core::config::{Config, Role};
use quictun_core::connection::{self, TransportTuning};
use quictun_core::tunnel;
use quictun_crypto::{PrivateKey, PublicKey};
use quictun_tun::{TunDevice, TunOptions};
use tokio::signal;
use tokio::sync::watch;

use crate::state;

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &str,
    serial: bool,
    newreno: bool,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    queues: usize,
    iouring: bool,
    sqpoll: bool,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
) -> Result<()> {
    if iouring {
        return run_iouring(
            config_path,
            newreno,
            recv_buf,
            send_buf,
            send_window,
            sqpoll,
            iouring_cores,
            pool_size,
            zero_copy,
        );
    }

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    rt.block_on(run_async(
        config_path,
        serial,
        newreno,
        recv_buf,
        send_buf,
        send_window,
        queues,
    ))
}

#[cfg(not(target_os = "linux"))]
fn run_iouring(
    _config_path: &str,
    _newreno: bool,
    _recv_buf: usize,
    _send_buf: usize,
    _send_window: u64,
    _sqpoll: bool,
    _iouring_cores: usize,
    _pool_size: usize,
    _zero_copy: bool,
) -> Result<()> {
    bail!("--iouring requires Linux");
}

#[cfg(target_os = "linux")]
fn run_iouring(
    config_path: &str,
    newreno: bool,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    sqpoll: bool,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
) -> Result<()> {
    use std::os::fd::{AsRawFd, RawFd};
    use quictun_core::connection::TransportTuning;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let role = config.role();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peer = &config.peer[0];
    let peer_pubkey =
        PublicKey::from_base64(&peer.public_key).context("invalid peer public_key")?;

    let keepalive = peer.keepalive.map(Duration::from_secs);
    let bbr = !newreno;

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        use_bbr: bbr,
        ..Default::default()
    };

    let cores = iouring_cores;

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        bbr,
        recv_buf,
        send_buf,
        send_window,
        sqpoll,
        zero_copy,
        cores,
        "starting quictun (io_uring)"
    );

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    // Create sync TUN device(s).
    // Multi-core requires multi-queue TUN (kernel distributes by flow hash).
    let mut tun_opts = TunOptions::new(addr.addr(), addr.prefix_len(), config.mtu());
    tun_opts.name = Some(iface_name.clone());
    tun_opts.multi_queue = cores > 1;

    let tun_primary =
        quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;

    // Build TUN fd list: primary + (N-1) clones for multi-queue.
    let mut tun_devices = vec![tun_primary];
    for i in 1..cores {
        let clone = tun_devices[0]
            .try_clone()
            .with_context(|| format!("failed to clone TUN queue {i}"))?;
        tun_devices.push(clone);
    }
    let tun_fds: Vec<RawFd> = tun_devices.iter().map(|d| d.as_raw_fd()).collect();

    if cores > 1 {
        tracing::info!(cores, "multi-queue TUN ready ({} queues)", tun_fds.len());
    }

    // Write PID file (guard removes it on exit/panic).
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name);

    // Build quinn-proto configs.
    let (client_config, server_config) = match role {
        Role::Connector => {
            let cc = quictun_uring::quic::build_proto_client_config(
                &private_key, &peer_pubkey, keepalive, &tuning,
            )?;
            (Some(cc), None)
        }
        Role::Listener => {
            let sc = quictun_uring::quic::build_proto_server_config(
                &private_key, &[peer_pubkey], keepalive, &tuning,
            )?;
            (None, Some(sc))
        }
    };

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    let setup = match role {
        Role::Connector => {
            let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
            quictun_uring::event_loop::EndpointSetup::Connector {
                remote_addr,
                client_config: client_config.context("connector requires client_config")?,
            }
        }
        Role::Listener => quictun_uring::event_loop::EndpointSetup::Listener {
            server_config: server_config.context("listener requires server_config")?,
        },
    };

    // Run the io_uring event loop (no tokio).
    // tun_devices must outlive the event loop (they own the fds).
    quictun_uring::event_loop::run(tun_fds, local_addr, setup, sqpoll, pool_size, zero_copy)
}

async fn run_async(
    config_path: &str,
    serial: bool,
    newreno: bool,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    queues: usize,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let role = config.role();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peer = &config.peer[0];
    let peer_pubkey =
        PublicKey::from_base64(&peer.public_key).context("invalid peer public_key")?;

    let keepalive = peer.keepalive.map(Duration::from_secs);

    let parallel = !serial;
    let bbr = !newreno;

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        use_bbr: bbr,
        ..Default::default()
    };

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        parallel,
        bbr,
        recv_buf,
        send_buf,
        send_window,
        queues,
        "starting quictun"
    );

    // Validate multi-queue configuration
    #[cfg(not(target_os = "linux"))]
    if queues > 1 {
        bail!("--queues > 1 requires Linux (IFF_MULTI_QUEUE)");
    }

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    let use_multi_queue = queues > 1;

    let tun_opts = {
        #[allow(unused_mut)]
        let mut opts = TunOptions::new(addr.addr(), addr.prefix_len(), config.mtu());
        opts.name = Some(iface_name.clone());
        #[cfg(target_os = "linux")]
        {
            opts.multi_queue = use_multi_queue;
        }
        opts
    };

    let tun = TunDevice::create_with_options(&tun_opts)
        .context("failed to create TUN device")?;

    // Write PID file (guard removes it on exit/panic).
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn SIGINT handler
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        tracing::info!("received SIGINT, shutting down");
        let _ = shutdown_tx.send(true);
    });

    let connection = match role {
        Role::Listener => {
            let listen_port = config
                .interface
                .listen_port
                .context("listener requires listen_port")?;

            let bind_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

            let server_config =
                connection::build_server_config(&private_key, &[peer_pubkey], keepalive, &tuning)
                    .context("failed to build server config")?;

            let endpoint = quinn::Endpoint::server(server_config, bind_addr)
                .context("failed to bind QUIC endpoint")?;

            tracing::info!(address = %bind_addr, "listening for incoming connection");

            let incoming = endpoint.accept().await.context("no incoming connection")?;

            let conn = incoming.await.context("failed to accept connection")?;
            tracing::info!(
                remote = %conn.remote_address(),
                "connection established (listener)"
            );
            conn
        }
        Role::Connector => {
            let server_endpoint = peer.endpoint.context("connector requires peer endpoint")?;

            let client_config =
                connection::build_client_config(&private_key, &peer_pubkey, keepalive, &tuning)
                    .context("failed to build client config")?;

            let mut endpoint =
                quinn::Endpoint::client("0.0.0.0:0".parse()?).context("failed to bind client")?;

            endpoint.set_default_client_config(client_config);

            tracing::info!(endpoint = %server_endpoint, "connecting to peer");

            let conn = endpoint
                .connect(server_endpoint, "quictun")?
                .await
                .context("failed to connect to peer")?;

            tracing::info!(
                remote = %conn.remote_address(),
                "connection established (connector)"
            );
            conn
        }
    };

    if use_multi_queue {
        // Build N queue handles: the original + (N-1) clones
        let mut tun_queues: Vec<Arc<TunDevice>> = Vec::with_capacity(queues);
        tun_queues.push(Arc::new(tun));
        #[cfg(target_os = "linux")]
        for _ in 1..queues {
            let cloned = tun_queues[0]
                .try_clone()
                .context("failed to clone TUN queue")?;
            tun_queues.push(Arc::new(cloned));
        }
        tracing::info!(queues = tun_queues.len(), "multi-queue TUN ready");
        tunnel::run_forwarding_loop_multiqueue(connection, tun_queues, shutdown_rx).await?;
    } else if parallel {
        tunnel::run_forwarding_loop_parallel(connection, Arc::new(tun), shutdown_rx).await?;
    } else {
        tunnel::run_forwarding_loop(connection, &tun, shutdown_rx).await?;
    }

    tracing::info!("tunnel closed");
    Ok(())
}
