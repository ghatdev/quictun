pub mod config;
pub mod connection;
pub mod icmp;
pub mod mss;
pub mod nat;
pub mod peer;
pub mod proto_config;
pub mod quic_state;
pub mod routing;

#[cfg(target_os = "linux")]
pub mod batch_io;

/// ALPN protocol identifier for quictun v1.
pub const ALPN_QUICTUN_V1: &[u8] = b"quictun-01";
