use std::net::Ipv4Addr;

use tun_rs::AsyncDevice;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    Create(#[from] std::io::Error),
}

/// Options for TUN device creation.
#[derive(Debug, Clone)]
pub struct TunOptions {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub name: Option<String>,
    #[cfg(target_os = "linux")]
    pub multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub offload: bool,
}

impl TunOptions {
    pub fn new(address: Ipv4Addr, prefix_len: u8, mtu: u16) -> Self {
        Self {
            address,
            prefix_len,
            mtu,
            name: None,
            #[cfg(target_os = "linux")]
            multi_queue: false,
            #[cfg(target_os = "linux")]
            offload: false,
        }
    }
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
        Self::create_with_options(&TunOptions {
            address,
            prefix_len,
            mtu,
            name: name.map(|s| s.to_string()),
            #[cfg(target_os = "linux")]
            multi_queue: false,
            #[cfg(target_os = "linux")]
            offload: false,
        })
    }

    /// Create a TUN device with full options (including multi-queue on Linux).
    pub fn create_with_options(opts: &TunOptions) -> Result<Self, TunError> {
        let mut builder = tun_rs::DeviceBuilder::new();

        if let Some(ref n) = opts.name {
            builder = builder.name(n);
        }

        #[cfg(target_os = "linux")]
        if opts.multi_queue {
            builder = builder.multi_queue(true);
        }

        #[cfg(target_os = "linux")]
        if opts.offload {
            builder = builder.offload(true);
        }

        let device = builder
            .ipv4(opts.address, opts.prefix_len, None)
            .mtu(opts.mtu)
            .build_async()?;

        let actual_name = device
            .name()
            .unwrap_or_else(|_| opts.name.as_deref().unwrap_or("tun?").to_string());

        #[cfg(target_os = "linux")]
        if opts.offload {
            tracing::info!(
                name = %actual_name,
                tcp_gso = device.tcp_gso(),
                udp_gso = device.udp_gso(),
                "TUN offload capabilities"
            );
        }

        tracing::info!(
            name = %actual_name,
            address = %opts.address,
            prefix_len = opts.prefix_len,
            mtu = opts.mtu,
            "TUN device created"
        );

        Ok(Self {
            inner: device,
            name: actual_name,
        })
    }

    /// Clone this TUN queue (Linux multi-queue only).
    ///
    /// The device must have been created with `multi_queue: true`.
    /// Each clone gets its own fd; the kernel distributes packets by flow hash.
    #[cfg(target_os = "linux")]
    pub fn try_clone(&self) -> Result<Self, TunError> {
        let cloned = self.inner.try_clone()?;
        Ok(Self {
            inner: cloned,
            name: self.name.clone(),
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

    /// Read one or more packets from TUN with GSO splitting (Linux only, requires offload).
    ///
    /// `original_buffer` stores the raw read including virtio_net_hdr (size: VIRTIO_NET_HDR_LEN + 65535).
    /// `bufs`/`sizes` receive the split IP packets. Returns the number of packets.
    #[cfg(target_os = "linux")]
    pub async fn recv_multiple<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> std::io::Result<usize> {
        self.inner
            .recv_multiple(original_buffer, bufs, sizes, offset)
            .await
    }

    /// Write multiple packets to TUN with GRO coalescing (Linux only, requires offload).
    ///
    /// `offset` must be >= VIRTIO_NET_HDR_LEN (space for the virtio header prepended by tun-rs).
    #[cfg(target_os = "linux")]
    pub async fn send_multiple<B: tun_rs::ExpandBuffer>(
        &self,
        gro_table: &mut tun_rs::GROTable,
        bufs: &mut [B],
        offset: usize,
    ) -> std::io::Result<usize> {
        self.inner.send_multiple(gro_table, bufs, offset).await
    }

    /// Whether TCP GSO is supported (Linux only).
    #[cfg(target_os = "linux")]
    pub fn tcp_gso(&self) -> bool {
        self.inner.tcp_gso()
    }

    /// Whether UDP GSO is supported (Linux only).
    #[cfg(target_os = "linux")]
    pub fn udp_gso(&self) -> bool {
        self.inner.udp_gso()
    }
}

/// Create a synchronous TUN device for non-async data planes (io_uring, quictun-net).
///
/// Returns the `SyncDevice` which provides blocking I/O.
/// On Linux, when `opts.multi_queue` is true, the device supports `try_clone()`
/// for additional queue fds (kernel distributes packets by flow hash).
pub fn create_sync(opts: &TunOptions) -> Result<tun_rs::SyncDevice, TunError> {
    let mut builder = tun_rs::DeviceBuilder::new();

    if let Some(ref n) = opts.name {
        builder = builder.name(n);
    }

    #[cfg(target_os = "linux")]
    if opts.multi_queue {
        builder = builder.multi_queue(true);
    }

    let device = builder
        .ipv4(opts.address, opts.prefix_len, None)
        .mtu(opts.mtu)
        .build_sync()?;

    let actual_name = device
        .name()
        .unwrap_or_else(|_| opts.name.as_deref().unwrap_or("tun?").to_string());
    tracing::info!(
        name = %actual_name,
        address = %opts.address,
        prefix_len = opts.prefix_len,
        mtu = opts.mtu,
        "sync TUN device created"
    );

    Ok(device)
}
