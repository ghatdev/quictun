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

pub fn run(
    config_path: &str,
    serial: bool,
    newreno: bool,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    queues: usize,
    iouring: bool,
) -> Result<()> {
    if iouring {
        return run_iouring(config_path, newreno, recv_buf, send_buf, send_window);
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
) -> Result<()> {
    use std::os::fd::AsRawFd;
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

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        bbr,
        recv_buf,
        send_buf,
        send_window,
        "starting quictun (io_uring)"
    );

    // Create sync TUN device.
    let tun_opts = TunOptions::new(addr.addr(), addr.prefix_len(), config.mtu());
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    let tun_fd = tun.as_raw_fd();

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

    let uring_role = match role {
        Role::Connector => quictun_uring::event_loop::Role::Connector,
        Role::Listener => quictun_uring::event_loop::Role::Listener,
    };

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    let remote_addr = match role {
        Role::Connector => peer.endpoint.context("connector requires peer endpoint")?,
        Role::Listener => {
            // For listener with connected UDP, we need the remote addr.
            // In Phase 1 single-peer, we use 0.0.0.0:0 as placeholder — but connected UDP
            // requires a real address. Listener must wait for the first packet.
            // Workaround: use unconnected UDP or require endpoint for listener too.
            // For Phase 1, require the listener to specify the peer endpoint.
            peer.endpoint.context(
                "--iouring listener requires peer endpoint (connected UDP, Phase 1 limitation)",
            )?
        }
    };

    // Run the io_uring event loop on the current thread (no tokio).
    quictun_uring::event_loop::run(
        tun_fd,
        local_addr,
        remote_addr,
        uring_role,
        client_config,
        server_config,
    )
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

    let use_multi_queue = queues > 1;

    let tun_opts = {
        #[allow(unused_mut)]
        let mut opts = TunOptions::new(addr.addr(), addr.prefix_len(), config.mtu());
        #[cfg(target_os = "linux")]
        {
            opts.multi_queue = use_multi_queue;
        }
        opts
    };

    let tun = TunDevice::create_with_options(&tun_opts)
        .context("failed to create TUN device")?;

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
