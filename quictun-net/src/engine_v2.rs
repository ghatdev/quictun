//! v2 engine entry point.
//!
//! Creates the [`KernelAdapter`] and [`ConnectionManager`], then calls the
//! shared engine loop in [`quictun_core::event_loop::run_engine`].
//!
//! Lives alongside the old `engine.rs` / `pipeline.rs` until benchmarks
//! confirm parity, then replaces them.

use anyhow::{Context, Result};
use tracing::info;

use quictun_core::event_loop::{EngineLoopConfig, RunResult};
use quictun_core::manager::ConnectionManager;
use quictun_core::quic_state::MultiQuicState;
use quictun_proto::local::LocalConnectionState;

use crate::adapter::{AdapterConfig, KernelAdapter};
use crate::engine::{EndpointSetup, NetConfig};

/// Run the v2 engine.
///
/// Entry point called from `engine::run()` when v2 is selected.
pub fn run_v2(
    local_addr: std::net::SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });

    // 1. Create the kernel I/O adapter.
    let adapter_config = AdapterConfig {
        local_addr,
        tunnel_ip: config.tunnel_ip,
        tunnel_prefix: config.tunnel_prefix,
        tunnel_mtu: config.tunnel_mtu,
        tunnel_name: config.tunnel_name.clone(),
        recv_buf: config.recv_buf,
        send_buf: config.send_buf,
        offload: config.offload,
        batch_size: config.batch_size,
        poll_events: config.poll_events,
    };
    let mut adapter = KernelAdapter::new(&adapter_config)?;

    // 2. Create the connection manager.
    let mut manager = ConnectionManager::<LocalConnectionState>::new(
        config.tunnel_ip,
        false,
        config.max_peers,
        config.idle_timeout,
    );

    // 3. Create MultiQuicState and initiate connection if connector.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };
    multi_state.ack_interval = config.ack_interval;

    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state
            .connect(client_config, remote_addr, &config.server_name)
            .context("failed to initiate QUIC connection")?;

        // Drain initial handshake transmits (Client Hello).
        drain_initial_transmits(&mut adapter, &mut multi_state)?;
    }

    // 4. Run engine loop — single-thread or multi-core.
    if config.threads > 1 {
        info!(threads = config.threads, "v2 multi-core engine starting");
        crate::multicore::run_multicore(&mut adapter, &mut multi_state, &config)
    } else {
        let loop_config = EngineLoopConfig {
            cid_len: config.cid_len,
            ack_timer_ms: config.ack_timer_ms as u64,
            batch_size: config.batch_size,
            reconnect: config.reconnect,
            is_connector,
        };

        info!("v2 single-thread engine starting");
        quictun_core::event_loop::run_engine(
            &mut adapter,
            &mut manager,
            &mut multi_state,
            &config.peers,
            &loop_config,
        )
    }
}

/// Drain initial handshake transmits (Client Hello for connector mode).
fn drain_initial_transmits(
    adapter: &mut KernelAdapter,
    state: &mut MultiQuicState,
) -> Result<()> {
    use quictun_core::data_plane::DataPlaneIo;
    use std::time::Instant;

    let now = Instant::now();
    let mut buf = Vec::with_capacity(4096);

    for hs in state.handshakes.values_mut() {
        loop {
            buf.clear();
            let Some(transmit) = hs.connection.poll_transmit(now, 1, &mut buf) else {
                break;
            };
            adapter
                .send_outer(&buf[..transmit.size], hs.remote_addr)
                .context("failed to send initial handshake")?;
        }
    }
    Ok(())
}
