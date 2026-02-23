use std::net::Ipv4Addr;

use tun_rs::AsyncDevice;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    Create(#[from] std::io::Error),
}

/// Thin async wrapper over a `tun-rs` TUN device.
pub struct TunDevice {
    inner: AsyncDevice,
    name: String,
}

impl TunDevice {
    /// Create and configure a TUN device.
    ///
    /// Requires `CAP_NET_ADMIN` (Linux) or root/sudo (macOS).
    pub fn create(
        address: Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
        name: Option<&str>,
    ) -> Result<Self, TunError> {
        let mut builder = tun_rs::DeviceBuilder::new();

        if let Some(n) = name {
            builder = builder.name(n);
        }

        let device = builder
            .ipv4(address, prefix_len, None)
            .mtu(mtu)
            .build_async()?;

        let actual_name = device
            .name()
            .unwrap_or_else(|_| name.unwrap_or("tun?").to_string());
        tracing::info!(name = %actual_name, address = %address, prefix_len, mtu, "TUN device created");

        Ok(Self {
            inner: device,
            name: actual_name,
        })
    }

    /// Read a packet from the TUN device.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }

    /// Write a packet to the TUN device.
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }

    /// Wait until the TUN device is readable (has queued packets).
    pub async fn readable(&self) -> std::io::Result<()> {
        self.inner.readable().await
    }

    /// Non-blocking read. Returns `Err(WouldBlock)` when no packet is queued.
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.try_recv(buf)
    }

    /// Wait until the TUN device is writable.
    pub async fn writable(&self) -> std::io::Result<()> {
        self.inner.writable().await
    }

    /// Non-blocking write. Returns `Err(WouldBlock)` when the device can't accept data.
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.try_send(buf)
    }

    /// Return the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}
