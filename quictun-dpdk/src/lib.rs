#[allow(dead_code)] // Used from net.rs on Linux; appears unused on macOS (net.rs is cfg-gated).
mod checksum;
#[cfg(target_os = "linux")]
mod dispatch;
#[cfg(target_os = "linux")]
mod eal;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
pub mod event_loop;
#[cfg(target_os = "linux")]
mod ffi;
#[cfg(target_os = "linux")]
mod mbuf;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod port;
#[cfg(target_os = "linux")]
pub mod quic;
#[cfg(target_os = "linux")]
mod ring;
#[cfg(target_os = "linux")]
mod shared;
#[cfg(target_os = "linux")]
mod veth;
