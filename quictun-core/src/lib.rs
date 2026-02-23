pub mod config;
pub mod connection;
pub mod tunnel;

/// ALPN protocol identifier for quictun v1.
pub const ALPN_QUICTUN_V1: &[u8] = b"quictun-01";
