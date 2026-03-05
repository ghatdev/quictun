use std::ffi::CStr;
use std::mem::MaybeUninit;

use anyhow::{Result, bail};

use crate::ffi;

/// Default number of RX/TX descriptors per queue.
const DEFAULT_NB_DESC: u16 = 1024;

/// Configure and start a DPDK Ethernet port with 1 RX queue and 1 TX queue.
///
/// Returns `(mac_address, hw_udp_cksum, hw_ip_cksum)`.
pub fn configure_port(
    port_id: u16,
    mempool: *mut ffi::rte_mempool,
) -> Result<([u8; 6], bool, bool)> {
    // Get device info for default RX/TX conf.
    let mut dev_info = MaybeUninit::<ffi::rte_eth_dev_info>::uninit();
    // SAFETY: dev_info is a valid MaybeUninit; rte_eth_dev_info_get writes into it.
    let ret = unsafe { ffi::rte_eth_dev_info_get(port_id, dev_info.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_dev_info_get failed: {}", dpdk_strerror(-ret));
    }
    // SAFETY: ret == 0 guarantees dev_info was fully initialized by DPDK.
    let dev_info = unsafe { dev_info.assume_init() };

    // Port configuration: enable TX checksum offloads based on device capabilities.
    let mut port_conf = ffi::rte_eth_conf::default();
    let hw_udp_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0;
    let hw_ip_cksum_cap = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0;
    if hw_udp_cksum {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }
    if hw_ip_cksum_cap {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    // SAFETY: port_conf is a valid config; port_id was validated by dev_info_get above.
    let ret = unsafe { ffi::rte_eth_dev_configure(port_id, 1, 1, &port_conf) };
    if ret != 0 {
        bail!("rte_eth_dev_configure failed: {}", dpdk_strerror(-ret));
    }

    // Set up RX queue 0.
    // SAFETY: port is configured; default_rxconf and mempool are valid.
    let ret = unsafe {
        ffi::rte_eth_rx_queue_setup(
            port_id,
            0,
            DEFAULT_NB_DESC,
            0, // socket_id (NUMA node; 0 = any)
            &dev_info.default_rxconf,
            mempool,
        )
    };
    if ret != 0 {
        bail!("rte_eth_rx_queue_setup failed: {}", dpdk_strerror(-ret));
    }

    // Set up TX queue 0.
    // SAFETY: port is configured; default_txconf is valid from dev_info.
    let ret = unsafe {
        ffi::rte_eth_tx_queue_setup(port_id, 0, DEFAULT_NB_DESC, 0, &dev_info.default_txconf)
    };
    if ret != 0 {
        bail!("rte_eth_tx_queue_setup failed: {}", dpdk_strerror(-ret));
    }

    // Enable promiscuous mode (receive all packets, needed since we're not
    // using the kernel stack for MAC filtering).
    // SAFETY: port is configured and queues are set up.
    let ret = unsafe { ffi::rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        // Non-fatal: virtio-user doesn't support promiscuous mode, but it's not
        // required for inner ports where we send/receive to known MACs.
        tracing::warn!(
            port = port_id,
            "rte_eth_promiscuous_enable not supported (ok for inner ports)"
        );
    }

    // Start the port.
    // SAFETY: port is fully configured with RX/TX queues.
    let ret = unsafe { ffi::rte_eth_dev_start(port_id) };
    if ret != 0 {
        bail!("rte_eth_dev_start failed: {}", dpdk_strerror(-ret));
    }

    // Read MAC address.
    let mut mac_addr = MaybeUninit::<ffi::rte_ether_addr>::uninit();
    // SAFETY: port is started; rte_eth_macaddr_get writes into mac_addr.
    let ret = unsafe { ffi::rte_eth_macaddr_get(port_id, mac_addr.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_macaddr_get failed: {}", dpdk_strerror(-ret));
    }
    // SAFETY: ret == 0 guarantees mac_addr was fully initialized.
    let mac = unsafe { mac_addr.assume_init() };

    // Check link status.
    let mut link = MaybeUninit::<ffi::rte_eth_link>::uninit();
    // SAFETY: port is started; rte_eth_link_get_nowait writes into link.
    let ret = unsafe { ffi::rte_eth_link_get_nowait(port_id, link.as_mut_ptr()) };
    if ret < 0 {
        tracing::warn!(
            port = port_id,
            ret,
            "rte_eth_link_get_nowait failed, link status unknown"
        );
    }
    // SAFETY: rte_eth_link_get_nowait always initializes the struct (even on error, zeroed).
    let link = unsafe { link.assume_init() };

    // TX checksum offload: only need UDP (IP done in software).
    let hw_ip_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0;

    // SAFETY: rte_eth_link is a bindgen union; accessing the inner bitfield struct
    // is valid because both union variants share the same underlying memory layout.
    let link_inner = unsafe { &link.__bindgen_anon_1.__bindgen_anon_1 };
    tracing::info!(
        port = port_id,
        mac = %format_mac(&mac.addr_bytes),
        link_speed = link_inner.link_speed,
        link_status = if link_inner.link_status() != 0 { "UP" } else { "DOWN" },
        hw_udp_cksum,
        hw_ip_cksum,
        "DPDK port configured"
    );

    Ok((mac.addr_bytes, hw_udp_cksum, hw_ip_cksum))
}

/// Configure and start a DPDK Ethernet port with N RX/TX queues and RSS.
///
/// Returns `(mac_address, hw_udp_cksum, hw_ip_cksum)` on success.
pub fn configure_port_multiqueue(
    port_id: u16,
    n_queues: u16,
    mempool: *mut ffi::rte_mempool,
) -> Result<([u8; 6], bool, bool)> {
    // Get device info for default RX/TX conf.
    let mut dev_info = MaybeUninit::<ffi::rte_eth_dev_info>::uninit();
    // SAFETY: dev_info is a valid MaybeUninit; rte_eth_dev_info_get writes into it.
    let ret = unsafe { ffi::rte_eth_dev_info_get(port_id, dev_info.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_dev_info_get failed: {}", dpdk_strerror(-ret));
    }
    // SAFETY: ret == 0 guarantees dev_info was fully initialized by DPDK.
    let dev_info = unsafe { dev_info.assume_init() };

    // Create port config with RSS enabled (uses C shim for correct struct layout).
    // SAFETY: shim_rss_ip_udp_flags returns the correct DPDK RSS flag combination.
    let rss_hf = unsafe { ffi::shim_rss_ip_udp_flags() };
    // SAFETY: shim_create_rss_port_conf creates a valid rte_eth_conf with RSS mode.
    let mut port_conf = unsafe { ffi::shim_create_rss_port_conf(rss_hf) };
    // Enable TX checksum offloads if supported.
    if (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0 {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }
    if (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0 {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    // SAFETY: port_conf is a valid RSS config; port_id was validated by dev_info_get above.
    let ret = unsafe { ffi::rte_eth_dev_configure(port_id, n_queues, n_queues, &port_conf) };
    if ret != 0 {
        bail!(
            "rte_eth_dev_configure (multiqueue) failed: {}",
            dpdk_strerror(-ret)
        );
    }

    // Set up N RX queues.
    for qid in 0..n_queues {
        // SAFETY: port is configured; default_rxconf and mempool are valid.
        let ret = unsafe {
            ffi::rte_eth_rx_queue_setup(
                port_id,
                qid,
                DEFAULT_NB_DESC,
                0,
                &dev_info.default_rxconf,
                mempool,
            )
        };
        if ret != 0 {
            bail!(
                "rte_eth_rx_queue_setup(q={qid}) failed: {}",
                dpdk_strerror(-ret)
            );
        }
    }

    // Set up N TX queues.
    for qid in 0..n_queues {
        // SAFETY: port is configured; default_txconf is valid from dev_info.
        let ret = unsafe {
            ffi::rte_eth_tx_queue_setup(port_id, qid, DEFAULT_NB_DESC, 0, &dev_info.default_txconf)
        };
        if ret != 0 {
            bail!(
                "rte_eth_tx_queue_setup(q={qid}) failed: {}",
                dpdk_strerror(-ret)
            );
        }
    }

    // Enable promiscuous mode.
    // SAFETY: port is configured and queues are set up.
    let ret = unsafe { ffi::rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        bail!("rte_eth_promiscuous_enable failed: {}", dpdk_strerror(-ret));
    }

    // Start the port.
    // SAFETY: port is fully configured with RX/TX queues.
    let ret = unsafe { ffi::rte_eth_dev_start(port_id) };
    if ret != 0 {
        bail!("rte_eth_dev_start failed: {}", dpdk_strerror(-ret));
    }

    // Read MAC address.
    let mut mac_addr = MaybeUninit::<ffi::rte_ether_addr>::uninit();
    // SAFETY: port is started; rte_eth_macaddr_get writes into mac_addr.
    let ret = unsafe { ffi::rte_eth_macaddr_get(port_id, mac_addr.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_macaddr_get failed: {}", dpdk_strerror(-ret));
    }
    // SAFETY: ret == 0 guarantees mac_addr was fully initialized.
    let mac = unsafe { mac_addr.assume_init() };

    // Check TX checksum offload capability.
    let hw_udp_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0;
    let hw_ip_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0;

    tracing::info!(
        port = port_id,
        mac = %format_mac(&mac.addr_bytes),
        n_queues,
        hw_udp_cksum,
        hw_ip_cksum,
        "DPDK port configured (multi-queue RSS)"
    );

    Ok((mac.addr_bytes, hw_udp_cksum, hw_ip_cksum))
}

/// Configure a DPDK port for dispatcher mode: 1 RX queue (core 0) + N TX queues.
///
/// Core 0 reads all packets and dispatches via SPSC rings. Each worker has
/// its own TX queue for sending encrypted outer packets directly.
pub fn configure_port_dispatcher(
    port_id: u16,
    n_tx_queues: u16,
    mempool: *mut ffi::rte_mempool,
) -> Result<([u8; 6], bool, bool)> {
    let mut dev_info = MaybeUninit::<ffi::rte_eth_dev_info>::uninit();
    let ret = unsafe { ffi::rte_eth_dev_info_get(port_id, dev_info.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_dev_info_get failed: {}", dpdk_strerror(-ret));
    }
    let dev_info = unsafe { dev_info.assume_init() };

    // No RSS — 1 RX queue, N TX queues. Enable TX checksum offloads if supported.
    let mut port_conf = ffi::rte_eth_conf::default();
    if (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0 {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }
    if (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0 {
        port_conf.txmode.offloads |= ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    let ret = unsafe { ffi::rte_eth_dev_configure(port_id, 1, n_tx_queues, &port_conf) };
    if ret != 0 {
        bail!(
            "rte_eth_dev_configure (dispatcher) failed: {}",
            dpdk_strerror(-ret)
        );
    }

    // 1 RX queue (core 0).
    let ret = unsafe {
        ffi::rte_eth_rx_queue_setup(
            port_id,
            0,
            DEFAULT_NB_DESC,
            0,
            &dev_info.default_rxconf,
            mempool,
        )
    };
    if ret != 0 {
        bail!(
            "rte_eth_rx_queue_setup(q=0) failed: {}",
            dpdk_strerror(-ret)
        );
    }

    // N TX queues (one per core: dispatcher + workers).
    for qid in 0..n_tx_queues {
        let ret = unsafe {
            ffi::rte_eth_tx_queue_setup(port_id, qid, DEFAULT_NB_DESC, 0, &dev_info.default_txconf)
        };
        if ret != 0 {
            bail!(
                "rte_eth_tx_queue_setup(q={qid}) failed: {}",
                dpdk_strerror(-ret)
            );
        }
    }

    // Enable promiscuous mode.
    let ret = unsafe { ffi::rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        bail!("rte_eth_promiscuous_enable failed: {}", dpdk_strerror(-ret));
    }

    // Start the port.
    let ret = unsafe { ffi::rte_eth_dev_start(port_id) };
    if ret != 0 {
        bail!("rte_eth_dev_start failed: {}", dpdk_strerror(-ret));
    }

    // Read MAC address.
    let mut mac_addr = MaybeUninit::<ffi::rte_ether_addr>::uninit();
    let ret = unsafe { ffi::rte_eth_macaddr_get(port_id, mac_addr.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_macaddr_get failed: {}", dpdk_strerror(-ret));
    }
    let mac = unsafe { mac_addr.assume_init() };

    // Check TX checksum offload capability.
    let hw_udp_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_UDP_CKSUM) != 0;
    let hw_ip_cksum = (dev_info.tx_offload_capa & ffi::RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) != 0;

    tracing::info!(
        port = port_id,
        mac = %format_mac(&mac.addr_bytes),
        n_tx_queues,
        hw_udp_cksum,
        hw_ip_cksum,
        "DPDK port configured (dispatcher: 1 RX, {n_tx_queues} TX)"
    );

    Ok((mac.addr_bytes, hw_udp_cksum, hw_ip_cksum))
}

/// Stop and close a DPDK port.
pub fn close_port(port_id: u16) {
    // SAFETY: port_id was previously configured and started; stop+close is the
    // correct shutdown sequence. Called once during cleanup.
    unsafe {
        let _ = ffi::rte_eth_dev_stop(port_id);
        ffi::rte_eth_dev_close(port_id);
    }
}

/// Receive a burst of packets from the port.
///
/// Returns the number of packets received (0..=nb_pkts).
#[inline]
pub fn rx_burst(
    port_id: u16,
    queue_id: u16,
    rx_pkts: &mut [*mut ffi::rte_mbuf],
    nb_pkts: u16,
) -> u16 {
    // SAFETY: rx_pkts has at least nb_pkts slots; DPDK writes valid mbuf pointers into it.
    unsafe { ffi::shim_rte_eth_rx_burst(port_id, queue_id, rx_pkts.as_mut_ptr(), nb_pkts) }
}

/// Transmit a burst of packets on the port.
///
/// Returns the number of packets actually sent.  Caller must free unsent mbufs.
#[inline]
pub fn tx_burst(
    port_id: u16,
    queue_id: u16,
    tx_pkts: &mut [*mut ffi::rte_mbuf],
    nb_pkts: u16,
) -> u16 {
    // SAFETY: tx_pkts contains nb_pkts valid mbuf pointers. DPDK takes ownership of sent
    // mbufs (frees them internally); caller must free unsent ones.
    unsafe { ffi::shim_rte_eth_tx_burst(port_id, queue_id, tx_pkts.as_mut_ptr(), nb_pkts) }
}

fn dpdk_strerror(errnum: i32) -> String {
    // SAFETY: rte_strerror returns a static string pointer (or null for unknown errors).
    unsafe {
        let ptr = ffi::rte_strerror(errnum);
        if ptr.is_null() {
            return format!("errno {errnum}");
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
