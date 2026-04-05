use std::path::Path;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use quictun_core::config::{Backend, Config};
use quictun_core::engine::{Engine, RunResult};
use quictun_core::session;

use crate::state;

pub fn run(config_path: &str) -> Result<()> {
    let config = Config::load(Path::new(config_path)).context("failed to load config")?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mode = config.mode();
    let addr = config.parse_address()?;
    let peers = config.all_peers();

    tracing::info!(
        mode = %mode,
        address = %addr,
        mtu = config.mtu(),
        auth = %config.interface.auth_mode,
        peers = peers.len(),
        backend = ?config.engine.backend,
        cc = %config.engine.cc,
        "starting quictun"
    );

    let iface_name = config.interface_name(Path::new(config_path));
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name);

    // Shared setup: resolve peers + build QUIC endpoint (RPK or X.509).
    let setup = session::build_endpoint_setup(&config)?;
    let resolved_peers = session::resolve_all_peers(&config)?;

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr = format!("0.0.0.0:{listen_port}").parse()?;

    let reconnect = session::reconnect_enabled(&config);
    let reconnect_base = session::reconnect_interval_secs(&config);
    let mut backoff_secs: u64 = reconnect_base;
    let max_backoff_secs: u64 = reconnect_base.saturating_mul(60).min(300);

    loop {
        let result = match config.engine.backend {
            Backend::Kernel => {
                quictun_net::engine::NetEngine.run(
                    local_addr, setup.clone(), &config, resolved_peers.clone(),
                )?
            }
            #[cfg(target_os = "linux")]
            Backend::DpdkVirtio | Backend::DpdkRouter => {
                quictun_dpdk::event_loop::DpdkEngine.run(
                    local_addr, setup.clone(), &config, resolved_peers.clone(),
                )?
            }
            #[cfg(not(target_os = "linux"))]
            Backend::DpdkVirtio | Backend::DpdkRouter => {
                bail!("DPDK backends require Linux");
            }
        };

        match result {
            RunResult::Shutdown => {
                tracing::info!("tunnel closed (shutdown)");
                break;
            }
            RunResult::ConnectionLost if reconnect => {
                let jitter_ms = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos()
                    % 1000) as u64;
                let delay = Duration::from_millis(backoff_secs * 1000 + jitter_ms);
                tracing::info!(delay_ms = delay.as_millis(), "reconnecting after backoff");
                std::thread::sleep(delay);
                backoff_secs = (backoff_secs * 2).min(max_backoff_secs);
                continue;
            }
            RunResult::ConnectionLost => {
                tracing::info!("connection lost, exiting (no reconnect configured)");
                break;
            }
        }
    }

    tracing::info!("tunnel closed");
    Ok(())
}
