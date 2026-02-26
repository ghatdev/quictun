use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use quictun_core::config::{Config, Role};
use quictun_core::connection::{self, CongestionControl, TransportTuning};
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
    cc: &str,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    queues: usize,
    iouring: bool,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
    initial_rtt: u64,
    pin_mtu: bool,
    dpdk: Option<String>,
    dpdk_local_ip: Option<String>,
    dpdk_remote_ip: Option<String>,
    dpdk_local_port: Option<u16>,
    dpdk_gateway_mac: Option<String>,
    dpdk_eal_args: String,
    dpdk_port: u16,
) -> Result<()> {
    let cc: CongestionControl = cc
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    if let Some(dpdk_mode) = dpdk {
        return run_dpdk(
            config_path,
            cc,
            recv_buf,
            send_buf,
            send_window,
            &dpdk_mode,
            dpdk_local_ip,
            dpdk_remote_ip,
            dpdk_local_port,
            dpdk_gateway_mac,
            dpdk_eal_args,
            dpdk_port,
        );
    }

    if iouring {
        return run_iouring(
            config_path,
            cc,
            recv_buf,
            send_buf,
            send_window,
            sqpoll,
            sqpoll_cpu,
            iouring_cores,
            pool_size,
            zero_copy,
        );
    }

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    rt.block_on(run_async(
        config_path,
        serial,
        cc,
        recv_buf,
        send_buf,
        send_window,
        queues,
        initial_rtt,
        pin_mtu,
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_dpdk(
    _config_path: &str,
    _cc: CongestionControl,
    _recv_buf: usize,
    _send_buf: usize,
    _send_window: u64,
    _dpdk_mode: &str,
    _dpdk_local_ip: Option<String>,
    _dpdk_remote_ip: Option<String>,
    _dpdk_local_port: Option<u16>,
    _dpdk_gateway_mac: Option<String>,
    _dpdk_eal_args: String,
    _dpdk_port: u16,
) -> Result<()> {
    bail!("--dpdk requires Linux");
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_dpdk(
    config_path: &str,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    dpdk_mode: &str,
    dpdk_local_ip: Option<String>,
    dpdk_remote_ip: Option<String>,
    dpdk_local_port: Option<u16>,
    dpdk_gateway_mac: Option<String>,
    dpdk_eal_args: String,
    dpdk_port: u16,
) -> Result<()> {
    // Validate mode.
    if dpdk_mode != "tap" && dpdk_mode != "xdp" {
        anyhow::bail!("--dpdk mode must be 'tap' or 'xdp', got '{dpdk_mode}'");
    }

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

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        cc,
        ..Default::default()
    };

    // Parse DPDK-specific IPs.
    let dpdk_local_ip: std::net::Ipv4Addr = dpdk_local_ip
        .context("--dpdk-local-ip is required with --dpdk")?
        .parse()
        .context("invalid --dpdk-local-ip")?;

    let dpdk_remote_ip: std::net::Ipv4Addr = dpdk_remote_ip
        .context("--dpdk-remote-ip is required with --dpdk")?
        .parse()
        .context("invalid --dpdk-remote-ip")?;

    // Parse optional gateway MAC (e.g., "bc:24:11:ab:cd:ef").
    let gateway_mac = dpdk_gateway_mac
        .map(|s| parse_mac(&s))
        .transpose()
        .context("invalid --dpdk-gateway-mac (expected xx:xx:xx:xx:xx:xx)")?;

    let eal_args: Vec<String> = dpdk_eal_args.split(';').map(|s| s.to_string()).collect();

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        dpdk_local_ip = %dpdk_local_ip,
        dpdk_remote_ip = %dpdk_remote_ip,
        dpdk_port,
        dpdk_mode,
        cc = %cc,
        "starting quictun (DPDK)"
    );

    let tunnel_ip = addr.addr();
    let tunnel_prefix = addr.prefix_len();
    let tunnel_mtu = config.mtu();

    // Write PID file.
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name.clone());

    // Build quinn-proto configs.
    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    let setup = match role {
        Role::Connector => {
            let cc = quictun_dpdk::quic::build_proto_client_config(
                &private_key, &peer_pubkey, keepalive, &tuning,
            )?;
            let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
            // Override remote_addr IP with DPDK IP, keep the port.
            let dpdk_remote_addr = SocketAddr::new(dpdk_remote_ip.into(), remote_addr.port());
            quictun_dpdk::event_loop::EndpointSetup::Connector {
                remote_addr: dpdk_remote_addr,
                client_config: cc,
            }
        }
        Role::Listener => {
            let sc = quictun_dpdk::quic::build_proto_server_config(
                &private_key, &[peer_pubkey], keepalive, &tuning,
            )?;
            quictun_dpdk::event_loop::EndpointSetup::Listener {
                server_config: sc,
            }
        }
    };

    let dpdk_config = quictun_dpdk::event_loop::DpdkConfig {
        mode: dpdk_mode.to_string(),
        eal_args,
        port_id: dpdk_port,
        local_ip: dpdk_local_ip,
        remote_ip: dpdk_remote_ip,
        local_port: dpdk_local_port,
        gateway_mac,
        tunnel_ip,
        tunnel_prefix,
        tunnel_mtu,
        tunnel_iface: iface_name,
    };

    quictun_dpdk::event_loop::run(local_addr, setup, dpdk_config)
}

/// Parse a MAC address string like "bc:24:11:ab:cd:ef" into [u8; 6].
#[cfg(target_os = "linux")]
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("MAC must have 6 octets separated by ':'");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid MAC octet: {part}"))?;
    }
    Ok(mac)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_iouring(
    _config_path: &str,
    _cc: CongestionControl,
    _recv_buf: usize,
    _send_buf: usize,
    _send_window: u64,
    _sqpoll: bool,
    _sqpoll_cpu: Option<u32>,
    _iouring_cores: usize,
    _pool_size: usize,
    _zero_copy: bool,
) -> Result<()> {
    bail!("--iouring requires Linux");
}

#[cfg(target_os = "linux")]
fn run_iouring(
    config_path: &str,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
) -> Result<()> {
    use std::os::fd::{AsRawFd, RawFd};

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

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        cc,
        ..Default::default()
    };

    let cores = iouring_cores;

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        cc = %cc,
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
    quictun_uring::event_loop::run(tun_fds, local_addr, setup, sqpoll, sqpoll_cpu, pool_size, zero_copy)
}

async fn run_async(
    config_path: &str,
    serial: bool,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    queues: usize,
    initial_rtt: u64,
    pin_mtu: bool,
) -> Result<()> {
    use quictun_core::tunnel::TunnelResult;

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
    let reconnect_interval = peer.reconnect_interval;

    let parallel = !serial;

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        cc,
        max_idle_timeout_ms: config.interface.max_idle_timeout_ms,
        initial_rtt_ms: initial_rtt,
        pin_mtu,
        ..Default::default()
    };

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        parallel,
        cc = %cc,
        recv_buf,
        send_buf,
        send_window,
        queues,
        reconnect = reconnect_interval.is_some(),
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

    // Build TUN handles once — persist across reconnections.
    // Always wrap in Arc so both parallel and serial modes work in the reconnection loop.
    let tun_queues: Vec<Arc<TunDevice>> = if use_multi_queue {
        let tun_arc = Arc::new(tun);
        let mut qs: Vec<Arc<TunDevice>> = Vec::with_capacity(queues);
        qs.push(tun_arc);
        #[cfg(target_os = "linux")]
        for _ in 1..queues {
            let cloned = qs[0]
                .try_clone()
                .context("failed to clone TUN queue")?;
            qs.push(Arc::new(cloned));
        }
        tracing::info!(queues = qs.len(), "multi-queue TUN ready");
        qs
    } else {
        vec![Arc::new(tun)]
    };

    // Feature flags from config.
    let fips_mode = config.interface.fips_mode;
    let cid_length = config.interface.cid_length as usize;
    let zero_rtt = config.interface.zero_rtt;
    let auth_mode = config.interface.auth_mode.as_str();

    // Enable session resumption when reconnect or 0-RTT is configured.
    let enable_session_resumption = reconnect_interval.is_some() || zero_rtt;

    // Build endpoint config with custom CID length.
    let endpoint_config = connection::build_endpoint_config(cid_length);

    // Create endpoint once (persists across reconnections).
    let endpoint = match role {
        Role::Listener => {
            let listen_port = config
                .interface
                .listen_port
                .context("listener requires listen_port")?;
            let bind_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

            let server_config = match auth_mode {
                "x509" => {
                    let cert_file = config.interface.cert_file.as_ref()
                        .context("x509 mode requires cert_file")?;
                    let key_file = config.interface.key_file.as_ref()
                        .context("x509 mode requires key_file")?;
                    let ca_file = config.interface.ca_file.as_ref()
                        .context("x509 mode requires ca_file")?;
                    connection::build_server_config_x509(
                        Path::new(cert_file),
                        Path::new(key_file),
                        Path::new(ca_file),
                        keepalive,
                        &tuning,
                        fips_mode,
                    )
                    .context("failed to build X.509 server config")?
                }
                _ => {
                    connection::build_server_config_ext(
                        &private_key,
                        &[peer_pubkey.clone()],
                        keepalive,
                        &tuning,
                        fips_mode,
                    )
                    .context("failed to build RPK server config")?
                }
            };

            let socket = std::net::UdpSocket::bind(bind_addr)
                .context("failed to bind UDP socket")?;
            quinn::Endpoint::new(
                endpoint_config,
                Some(server_config),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .context("failed to create QUIC endpoint")?
        }
        Role::Connector => {
            let client_config = match auth_mode {
                "x509" => {
                    let cert_file = config.interface.cert_file.as_ref()
                        .context("x509 mode requires cert_file")?;
                    let key_file = config.interface.key_file.as_ref()
                        .context("x509 mode requires key_file")?;
                    let ca_file = config.interface.ca_file.as_ref()
                        .context("x509 mode requires ca_file")?;
                    connection::build_client_config_x509(
                        Path::new(cert_file),
                        Path::new(key_file),
                        Path::new(ca_file),
                        keepalive,
                        &tuning,
                        fips_mode,
                        enable_session_resumption,
                    )
                    .context("failed to build X.509 client config")?
                }
                _ => {
                    connection::build_client_config_ext(
                        &private_key,
                        &peer_pubkey,
                        keepalive,
                        &tuning,
                        fips_mode,
                        enable_session_resumption,
                    )
                    .context("failed to build RPK client config")?
                }
            };

            let socket = std::net::UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>()?)
                .context("failed to bind UDP socket")?;
            let mut ep = quinn::Endpoint::new(
                endpoint_config,
                None,
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .context("failed to create QUIC endpoint")?;
            ep.set_default_client_config(client_config);
            ep
        }
    };

    let server_endpoint_addr = peer.endpoint;

    // Backoff state for reconnection.
    let mut backoff_secs: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 60;

    loop {
        // Check if shutdown was already requested.
        if *shutdown_rx.borrow() {
            break;
        }

        // Establish connection.
        let connection = match role {
            Role::Listener => {
                let bind_addr = endpoint.local_addr()?;
                tracing::info!(address = %bind_addr, "listening for incoming connection");

                let incoming = match endpoint.accept().await {
                    Some(inc) => inc,
                    None => {
                        tracing::error!("endpoint closed, no more incoming connections");
                        break;
                    }
                };

                match incoming.await {
                    Ok(conn) => {
                        tracing::info!(
                            remote = %conn.remote_address(),
                            "connection established (listener)"
                        );
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept connection");
                        if reconnect_interval.is_some() {
                            continue;
                        }
                        return Err(e).context("failed to accept connection");
                    }
                }
            }
            Role::Connector => {
                let remote = server_endpoint_addr.context("connector requires peer endpoint")?;
                tracing::info!(endpoint = %remote, "connecting to peer");

                match endpoint.connect(remote, "quictun") {
                    Ok(connecting) => {
                        // Try 0-RTT if enabled (requires a cached session ticket).
                        let conn_result = if zero_rtt {
                            match connecting.into_0rtt() {
                                Ok((conn, zero_rtt_accepted)) => {
                                    tracing::info!("0-RTT connection initiated");
                                    tokio::spawn(async move {
                                        if zero_rtt_accepted.await {
                                            tracing::info!("0-RTT accepted by server");
                                        } else {
                                            tracing::warn!("0-RTT rejected, fell back to 1-RTT");
                                        }
                                    });
                                    Ok(conn)
                                }
                                Err(connecting) => {
                                    tracing::debug!("no session ticket for 0-RTT, using 1-RTT");
                                    connecting.await
                                }
                            }
                        } else {
                            connecting.await
                        };

                        match conn_result {
                            Ok(conn) => {
                                tracing::info!(
                                    remote = %conn.remote_address(),
                                    "connection established (connector)"
                                );
                                conn
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to connect to peer");
                                if reconnect_interval.is_some() {
                                    let jitter_ms = (std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .subsec_nanos()
                                        % 1000) as u64;
                                    let delay = Duration::from_millis(backoff_secs * 1000 + jitter_ms);
                                    tracing::info!(delay_ms = delay.as_millis(), "reconnecting after backoff");
                                    tokio::time::sleep(delay).await;
                                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                                    continue;
                                }
                                return Err(e).context("failed to connect to peer");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "connect call failed");
                        return Err(e.into());
                    }
                }
            }
        };

        // Connection established — reset backoff.
        backoff_secs = 1;

        // Run forwarding loop. TUN device + endpoint persist; only Connection is recycled.
        let result = if use_multi_queue {
            tunnel::run_forwarding_loop_multiqueue(
                connection,
                tun_queues.clone(),
                shutdown_rx.clone(),
            )
            .await
        } else if parallel {
            tunnel::run_forwarding_loop_parallel(
                connection,
                tun_queues[0].clone(),
                shutdown_rx.clone(),
            )
            .await
        } else {
            tunnel::run_forwarding_loop(connection, &tun_queues[0], shutdown_rx.clone()).await
        };

        match result {
            TunnelResult::Shutdown => {
                tracing::info!("tunnel closed (shutdown)");
                break;
            }
            TunnelResult::ConnectionLost(e) => {
                if reconnect_interval.is_some() {
                    tracing::warn!(error = %e, "connection lost, will reconnect");
                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        % 1000) as u64;
                    let delay = Duration::from_millis(backoff_secs * 1000 + jitter_ms);
                    tracing::info!(delay_ms = delay.as_millis(), "reconnecting after backoff");
                    tokio::time::sleep(delay).await;
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    continue;
                }
                tracing::info!(error = %e, "connection lost, exiting (no reconnect configured)");
                break;
            }
            TunnelResult::Fatal(e) => {
                return Err(e).context("fatal tunnel error");
            }
        }
    }

    tracing::info!("tunnel closed");
    Ok(())
}
