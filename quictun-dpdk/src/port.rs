use std::ffi::CStr;
use std::mem::MaybeUninit;

use anyhow::{bail, Result};

use crate::ffi;

/// Default number of RX/TX descriptors per queue.
const DEFAULT_NB_DESC: u16 = 1024;

/// Configure and start a DPDK Ethernet port with 1 RX queue and 1 TX queue.
///
/// Returns the port's MAC address on success.
pub fn configure_port(port_id: u16, mempool: *mut ffi::rte_mempool) -> Result<[u8; 6]> {
    // Get device info for default RX/TX conf.
    let mut dev_info = MaybeUninit::<ffi::rte_eth_dev_info>::uninit();
    let ret = unsafe { ffi::rte_eth_dev_info_get(port_id, dev_info.as_mut_ptr()) };
    if ret != 0 {
        bail!("rte_eth_dev_info_get failed: {}", dpdk_strerror(-ret));
    }
    let dev_info = unsafe { dev_info.assume_init() };

    // Minimal port configuration (no RSS, no offloads).
    let port_conf = ffi::rte_eth_conf::default();

    let ret = unsafe { ffi::rte_eth_dev_configure(port_id, 1, 1, &port_conf) };
    if ret != 0 {
        bail!("rte_eth_dev_configure failed: {}", dpdk_strerror(-ret));
    }

    // Set up RX queue 0.
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
    let ret = unsafe {
        ffi::rte_eth_tx_queue_setup(port_id, 0, DEFAULT_NB_DESC, 0, &dev_info.default_txconf)
    };
    if ret != 0 {
        bail!("rte_eth_tx_queue_setup failed: {}", dpdk_strerror(-ret));
    }

    // Enable promiscuous mode (receive all packets, needed since we're not
    // using the kernel stack for MAC filtering).
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

    // Check link status.
    let mut link = MaybeUninit::<ffi::rte_eth_link>::uninit();
    unsafe { ffi::rte_eth_link_get_nowait(port_id, link.as_mut_ptr()) };
    let link = unsafe { link.assume_init() };

    // rte_eth_link is a union; access the inner struct for speed/status fields.
    let link_inner = unsafe { &link.__bindgen_anon_1.__bindgen_anon_1 };
    tracing::info!(
        port = port_id,
        mac = %format_mac(&mac.addr_bytes),
        link_speed = link_inner.link_speed,
        link_status = if link_inner.link_status() != 0 { "UP" } else { "DOWN" },
        "DPDK port configured"
    );

    Ok(mac.addr_bytes)
}

/// Stop and close a DPDK port.
pub fn close_port(port_id: u16) {
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
    unsafe { ffi::shim_rte_eth_tx_burst(port_id, queue_id, tx_pkts.as_mut_ptr(), nb_pkts) }
}

fn dpdk_strerror(errnum: i32) -> String {
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
