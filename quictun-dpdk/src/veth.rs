use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Ethtool ioctl — legacy commands
const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_SRXCSUM: u32 = 0x16;
const ETHTOOL_SGSO: u32 = 0x24;
const ETHTOOL_SGRO: u32 = 0x2c;

// Ethtool ioctl — SFEATURES API (needed for tx-checksum on modern kernels)
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_SFEATURES: u32 = 0x3b;
const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;

/// Features to disable via SFEATURES (kernel GSTRINGS names).
/// Includes TX checksum (legacy ETHTOOL_STXCSUM doesn't work on modern kernels)
/// and rx-checksumming as a fallback if the legacy SRXCSUM didn't take effect.
const SFEATURES_DISABLE: &[&str] = &[
    "tx-checksum-ip-generic",
    "tx-checksum-ipv4",
    "tx-checksum-ipv6",
    "tx-checksum-sctp",
    "rx-checksumming",
    "tx-generic-segmentation",
    "rx-gro",
];

// Netlink message types
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;

// Netlink flags
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_EXCL: u16 = 0x0200;
const NLMSG_ERROR: u16 = 0x02;

// rtnetlink attribute types (stable kernel ABI)
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;

// ---------------------------------------------------------------------------
// repr(C) structs for netlink payloads
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifinfomsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

// ---------------------------------------------------------------------------
// Ethtool ioctl — disable offloading
// ---------------------------------------------------------------------------

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

/// Disable TX checksum, GSO, and GRO on an interface via SIOCETHTOOL ioctl.
///
/// Uses legacy ioctls for GSO/GRO, plus the ETHTOOL_SFEATURES API for TX checksum
/// features (the legacy ETHTOOL_STXCSUM doesn't disable tx-checksum-ip-generic on
/// modern kernels). rx-checksumming cannot be disabled via SIOCETHTOOL on veth
/// (RXCSUM is not in hw_features); it requires the NETLINK_GENERIC ethtool interface.
/// This is acceptable: RX checksum only tells the kernel to trust hardware verification,
/// which is semantically irrelevant for software veth + AF_XDP.
///
/// Non-fatal: logs failures at debug level (features may not exist on all drivers).
fn disable_offloading(iface: &str) {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        tracing::debug!(iface, "ethtool: cannot open socket");
        return;
    }

    // Legacy commands for rx-checksum, GSO, GRO.
    for cmd in [ETHTOOL_SRXCSUM, ETHTOOL_SGSO, ETHTOOL_SGRO] {
        let mut val = EthtoolValue { cmd, data: 0 };
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        set_ifr_name(&mut ifr, iface);
        ifr.ifr_ifru.ifru_data = &mut val as *mut _ as *mut libc::c_char;
        let ret = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr) };
        if ret < 0 {
            tracing::debug!(iface, "ethtool set 0x{cmd:x}: {}", std::io::Error::last_os_error());
        }
    }

    // SFEATURES covers all features by kernel name (belt-and-suspenders with legacy above).
    disable_features_by_name(fd, iface);

    unsafe { libc::close(fd) };
}

/// Disable offloading features via ETHTOOL_SFEATURES (by kernel feature string names).
fn disable_features_by_name(fd: RawFd, iface: &str) {
    let count = match sset_count(fd, iface) {
        Some(c) => c as usize,
        None => return,
    };

    let names = match get_feature_strings(fd, iface, count) {
        Some(n) => n,
        None => return,
    };

    // Build SFEATURES bitmask: header(8) + blocks * (valid(4) + requested(4)).
    let num_blocks = count.div_ceil(32);
    let buf_len = 8 + num_blocks * 8;
    let mut buf = vec![0u8; buf_len];
    buf[0..4].copy_from_slice(&ETHTOOL_SFEATURES.to_ne_bytes());
    buf[4..8].copy_from_slice(&(num_blocks as u32).to_ne_bytes());

    let mut any = false;
    for feature in SFEATURES_DISABLE {
        if let Some(idx) = names.iter().position(|n| n == feature) {
            let block_off = 8 + (idx / 32) * 8;
            let bit = 1u32 << (idx % 32);
            // Set `valid` bit — `requested` stays 0 (= off).
            let valid = u32::from_ne_bytes(buf[block_off..block_off + 4].try_into().unwrap());
            buf[block_off..block_off + 4].copy_from_slice(&(valid | bit).to_ne_bytes());
            any = true;
        }
    }

    if any {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        set_ifr_name(&mut ifr, iface);
        ifr.ifr_ifru.ifru_data = buf.as_mut_ptr() as *mut libc::c_char;
        let ret = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr) };
        if ret < 0 {
            tracing::debug!(iface, "ethtool SFEATURES: {}", std::io::Error::last_os_error());
        }
    }
}

/// Get the number of strings in a string set via ETHTOOL_GSSET_INFO.
fn sset_count(fd: RawFd, iface: &str) -> Option<u32> {
    // Layout: cmd(4) + reserved(4) + sset_mask(8) + data(4)
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&ETHTOOL_GSSET_INFO.to_ne_bytes());
    let mask: u64 = 1 << ETH_SS_FEATURES;
    buf[8..16].copy_from_slice(&mask.to_ne_bytes());

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, iface);
    ifr.ifr_ifru.ifru_data = buf.as_mut_ptr() as *mut libc::c_char;

    let ret = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr) };
    if ret < 0 {
        tracing::debug!(iface, "ethtool GSSET_INFO: {}", std::io::Error::last_os_error());
        return None;
    }
    Some(u32::from_ne_bytes(buf[16..20].try_into().unwrap()))
}

/// Get feature name strings via ETHTOOL_GSTRINGS.
fn get_feature_strings(fd: RawFd, iface: &str, count: usize) -> Option<Vec<String>> {
    // Layout: cmd(4) + string_set(4) + len(4) + data(count * ETH_GSTRING_LEN)
    let buf_len = 12 + count * ETH_GSTRING_LEN;
    let mut buf = vec![0u8; buf_len];
    buf[0..4].copy_from_slice(&ETHTOOL_GSTRINGS.to_ne_bytes());
    buf[4..8].copy_from_slice(&ETH_SS_FEATURES.to_ne_bytes());
    buf[8..12].copy_from_slice(&(count as u32).to_ne_bytes());

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, iface);
    ifr.ifr_ifru.ifru_data = buf.as_mut_ptr() as *mut libc::c_char;

    let ret = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr) };
    if ret < 0 {
        tracing::debug!(iface, "ethtool GSTRINGS: {}", std::io::Error::last_os_error());
        return None;
    }

    let mut names = Vec::with_capacity(count);
    for i in 0..count {
        let off = 12 + i * ETH_GSTRING_LEN;
        let s = &buf[off..off + ETH_GSTRING_LEN];
        let end = s.iter().position(|&b| b == 0).unwrap_or(ETH_GSTRING_LEN);
        names.push(String::from_utf8_lossy(&s[..end]).into_owned());
    }
    Some(names)
}

/// Copy an interface name into ifreq.ifr_name (null-terminated, max 15 chars).
fn set_ifr_name(ifr: &mut libc::ifreq, name: &str) {
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = src as libc::c_char;
    }
}

// ---------------------------------------------------------------------------
// Netlink message builder
// ---------------------------------------------------------------------------

struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    fn new(msg_type: u16, extra_flags: u16) -> Self {
        let hdr = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: msg_type,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | extra_flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        let mut msg = Self {
            buf: Vec::with_capacity(256),
        };
        msg.put(&hdr);
        msg
    }

    /// Append raw bytes of a `Copy` type.
    fn put<T: Copy>(&mut self, val: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.buf.extend_from_slice(bytes);
    }

    /// Append a netlink attribute (rtattr header + data + pad to 4-byte alignment).
    fn put_attr(&mut self, rta_type: u16, data: &[u8]) {
        let rta_len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&rta_len.to_ne_bytes());
        self.buf.extend_from_slice(&rta_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        let aligned = (self.buf.len() + 3) & !3;
        self.buf.resize(aligned, 0);
    }

    /// Append a null-terminated string attribute.
    fn put_attr_str(&mut self, rta_type: u16, s: &str) {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.put_attr(rta_type, &v);
    }

    /// Append a u32 attribute.
    fn put_attr_u32(&mut self, rta_type: u16, val: u32) {
        self.put_attr(rta_type, &val.to_ne_bytes());
    }

    /// Begin a nested attribute. Returns offset for `end_nested()`.
    fn begin_nested(&mut self, rta_type: u16) -> usize {
        let offset = self.buf.len();
        let zero_len: u16 = 0;
        let nested_type = rta_type | NLA_F_NESTED;
        self.buf.extend_from_slice(&zero_len.to_ne_bytes());
        self.buf.extend_from_slice(&nested_type.to_ne_bytes());
        offset
    }

    /// Close a nested attribute, fixing up its rta_len.
    fn end_nested(&mut self, offset: usize) {
        let len = (self.buf.len() - offset) as u16;
        self.buf[offset..offset + 2].copy_from_slice(&len.to_ne_bytes());
    }

    /// Fix up nlmsg_len and return the complete message bytes.
    fn finish(&mut self) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        &self.buf
    }
}

// ---------------------------------------------------------------------------
// Netlink socket
// ---------------------------------------------------------------------------

struct NlSocket(RawFd);

impl NlSocket {
    fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            bail!("netlink socket: {}", std::io::Error::last_os_error());
        }
        let mut sa = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            bail!("netlink bind: {err}");
        }
        Ok(Self(fd))
    }

    /// Send a netlink message and wait for the ACK.
    fn request(&self, msg: &[u8]) -> Result<()> {
        let ret = unsafe {
            libc::send(
                self.0,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
            )
        };
        if ret < 0 {
            bail!("netlink send: {}", std::io::Error::last_os_error());
        }

        let mut buf = [0u8; 4096];
        let n = unsafe {
            libc::recv(
                self.0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            bail!("netlink recv: {}", std::io::Error::last_os_error());
        }
        let n = n as usize;
        let hdr_size = std::mem::size_of::<libc::nlmsghdr>();
        if n < hdr_size {
            bail!("netlink: response too short ({n} bytes)");
        }

        let hdr = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
        if hdr.nlmsg_type == NLMSG_ERROR {
            if n < hdr_size + 4 {
                bail!("netlink: error response too short");
            }
            let errno = i32::from_ne_bytes(
                buf[hdr_size..hdr_size + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(-errno).into());
            }
        }
        Ok(())
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Netlink operations
// ---------------------------------------------------------------------------

/// Delete a network link by interface index.
fn nl_del_link(sock: &NlSocket, ifindex: i32) -> Result<()> {
    let mut msg = NlMsg::new(RTM_DELLINK, 0);
    msg.put(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: 0,
        ifi_change: 0,
    });
    sock.request(msg.finish())
}

/// Create a veth pair: `app_name` (kernel-facing) and `xdp_name` (DPDK-facing).
fn nl_new_veth(sock: &NlSocket, app_name: &str, xdp_name: &str) -> Result<()> {
    let mut msg = NlMsg::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);
    msg.put(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: 0,
        ifi_flags: 0,
        ifi_change: 0,
    });
    msg.put_attr_str(IFLA_IFNAME, app_name);

    // IFLA_LINKINFO → IFLA_INFO_KIND="veth" → IFLA_INFO_DATA → VETH_INFO_PEER
    let linkinfo = msg.begin_nested(IFLA_LINKINFO);
    msg.put_attr_str(IFLA_INFO_KIND, "veth");
    let info_data = msg.begin_nested(IFLA_INFO_DATA);
    let peer = msg.begin_nested(VETH_INFO_PEER);
    // Peer header (ifinfomsg) + peer interface name.
    msg.put(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: 0,
        ifi_flags: 0,
        ifi_change: 0,
    });
    msg.put_attr_str(IFLA_IFNAME, xdp_name);
    msg.end_nested(peer);
    msg.end_nested(info_data);
    msg.end_nested(linkinfo);

    sock.request(msg.finish())
}

/// Set MTU on an interface by index.
fn nl_set_mtu(sock: &NlSocket, ifindex: i32, mtu: u32) -> Result<()> {
    let mut msg = NlMsg::new(RTM_NEWLINK, 0);
    msg.put(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: 0,
        ifi_change: 0,
    });
    msg.put_attr_u32(IFLA_MTU, mtu);
    sock.request(msg.finish())
}

/// Add an IPv4 address to an interface by index.
fn nl_add_addr(sock: &NlSocket, ifindex: i32, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let mut msg = NlMsg::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL);
    msg.put(&Ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: 0, // RT_SCOPE_UNIVERSE
        ifa_index: ifindex as u32,
    });
    let octets = ip.octets();
    msg.put_attr(IFA_LOCAL, &octets);
    msg.put_attr(IFA_ADDRESS, &octets);
    sock.request(msg.finish())
}

/// Bring an interface up by index.
fn nl_set_up(sock: &NlSocket, ifindex: i32) -> Result<()> {
    let mut msg = NlMsg::new(RTM_NEWLINK, 0);
    msg.put(&Ifinfomsg {
        ifi_family: libc::AF_UNSPEC as u8,
        _pad: 0,
        ifi_type: 0,
        ifi_index: ifindex,
        ifi_flags: libc::IFF_UP as u32,
        ifi_change: libc::IFF_UP as u32,
    });
    sock.request(msg.finish())
}

/// Get interface index by name. Returns `None` if the interface does not exist.
fn ifindex(iface: &str) -> Result<Option<i32>> {
    let cname = CString::new(iface).context("invalid interface name")?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Ok(None);
    }
    Ok(Some(idx as i32))
}

/// Get interface index, failing if the interface does not exist.
fn ifindex_required(iface: &str) -> Result<i32> {
    ifindex(iface)?.with_context(|| format!("interface not found: {iface}"))
}

// ---------------------------------------------------------------------------
// VethPair
// ---------------------------------------------------------------------------

/// A veth pair for AF_XDP inner interface.
///
/// `app_iface` is the kernel-facing end (e.g., "quictun0") with an IP address.
/// `xdp_iface` is the DPDK-facing end (e.g., "quictun0_xdp") bound to AF_XDP PMD.
pub struct VethPair {
    /// Kernel-facing interface name (has IP, used by apps).
    pub app_iface: String,
    /// DPDK-facing interface name (bound to AF_XDP PMD).
    pub xdp_iface: String,
    /// MAC address of the app-facing interface.
    pub app_mac: [u8; 6],
}

impl VethPair {
    /// Create a veth pair and configure the app-facing end with an IP address.
    ///
    /// - `name`: base interface name (e.g., "quictun0")
    /// - `ip`: IPv4 address for the app-facing end
    /// - `prefix`: subnet prefix length (e.g., 24)
    /// - `mtu`: MTU for both ends
    pub fn create(name: &str, ip: Ipv4Addr, prefix: u8, mtu: u16) -> Result<Self> {
        let app_iface = name.to_string();
        let xdp_iface = format!("{name}_xdp");

        let sock = NlSocket::open().context("failed to open netlink socket")?;

        // Clean up any stale interfaces from a previous crash.
        if let Some(idx) = ifindex(&app_iface)? {
            let _ = nl_del_link(&sock, idx);
        }

        // Create veth pair.
        nl_new_veth(&sock, &app_iface, &xdp_iface).context("failed to create veth pair")?;

        // Resolve interface indices (needed for subsequent operations).
        let app_idx = ifindex_required(&app_iface)?;
        let xdp_idx = ifindex_required(&xdp_iface)?;

        // Set MTU on both ends.
        nl_set_mtu(&sock, app_idx, mtu as u32).context("failed to set app_iface MTU")?;
        nl_set_mtu(&sock, xdp_idx, mtu as u32).context("failed to set xdp_iface MTU")?;

        // Assign IP to the app-facing end.
        nl_add_addr(&sock, app_idx, ip, prefix).context("failed to assign IP to app_iface")?;

        // Bring both ends up.
        nl_set_up(&sock, app_idx).context("failed to bring app_iface up")?;
        nl_set_up(&sock, xdp_idx).context("failed to bring xdp_iface up")?;

        // Disable checksum offloading on both ends AFTER bring-up.
        // dev_open() calls netdev_update_features() which can re-evaluate feature
        // flags, so offloading must be disabled after the interfaces are up.
        // AF_XDP passes raw Ethernet frames between user-space and the veth pair.
        // With TX checksum offloading enabled, the kernel writes partial checksums
        // that expect hardware completion — but AF_XDP delivers frames raw, so the
        // remote kernel sees invalid checksums and silently drops TCP/UDP packets.
        disable_offloading(&app_iface);
        disable_offloading(&xdp_iface);

        // Read MAC address of the app-facing interface.
        let app_mac =
            read_mac(&app_iface).with_context(|| format!("failed to read MAC of {app_iface}"))?;

        tracing::info!(
            app_iface = %app_iface,
            xdp_iface = %xdp_iface,
            app_mac = %format_mac(&app_mac),
            ip = %ip,
            prefix,
            mtu,
            "veth pair created"
        );

        Ok(Self {
            app_iface,
            xdp_iface,
            app_mac,
        })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Deleting one end removes both.
        if let (Ok(sock), Some(idx)) = (NlSocket::open(), ifindex(&self.app_iface).unwrap_or(None))
        {
            let _ = nl_del_link(&sock, idx);
        }
        tracing::info!(iface = %self.app_iface, "veth pair deleted");
    }
}

// ---------------------------------------------------------------------------
// MAC address helpers
// ---------------------------------------------------------------------------

/// Read MAC address from sysfs.
fn read_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("cannot read {path}"))?;
    parse_mac(content.trim())
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC: {s}");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid MAC octet: {part}"))?;
    }
    Ok(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
