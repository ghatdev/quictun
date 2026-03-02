pub mod config;
pub mod connection;
pub mod fast_tunnel;
pub mod proto_config;
pub mod proto_driver;
pub mod tunnel;

#[cfg(target_os = "linux")]
pub mod batch_io;

/// ALPN protocol identifier for quictun v1.
pub const ALPN_QUICTUN_V1: &[u8] = b"quictun-01";
