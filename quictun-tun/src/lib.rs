mod device;

pub use device::{TunDevice, TunError, TunOptions};
#[cfg(target_os = "linux")]
pub use device::create_sync;
