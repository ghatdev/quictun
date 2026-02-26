mod device;

pub use device::{TunDevice, TunError, TunOptions};
#[cfg(target_os = "linux")]
pub use device::create_sync;

// Re-export tun-rs offload types for use by the forwarding loop (Linux only).
#[cfg(target_os = "linux")]
pub use tun_rs::{ExpandBuffer, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
