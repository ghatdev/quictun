use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Generic netlink
const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// Ethtool generic netlink (ETHTOOL_MSG_FEATURES_SET)
const ETHTOOL_MSG_FEATURES_SET: u8 = 12;
const ETHTOOL_A_FEATURES_HEADER: u16 = 1;
const ETHTOOL_A_FEATURES_WANTED: u16 = 3;
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
const ETHTOOL_A_BITSET_BITS: u16 = 3;
const ETHTOOL_A_BITSET_BITS_BIT: u16 = 1;
const ETHTOOL_A_BITSET_BIT_NAME: u16 = 2;

/// Features to disable on veth interfaces for AF_XDP.
///
/// TX checksum offloading causes partial checksums in AF_XDP-delivered frames,
/// leading to silent packet drops. GSO/GRO are disabled for consistency.
const FEATURES_DISABLE: &[&str] = &[
    "tx-checksum-ip-generic",
    "tx-checksum-ipv4",
    "tx-checksum-ipv6",
    "tx-checksum-sctp",
    "rx-checksum",
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

#[repr(C)]
#[derive(Clone, Copy)]
struct Genlmsghdr {
    cmd: u8,
    version: u8,
    reserved: u16,
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

    /// Create a generic netlink message (nlmsghdr + genlmsghdr).
    ///
    /// Unlike `new()`, the caller provides the full `nlmsg_flags` value.
    fn new_genl(family_id: u16, cmd: u8, flags: u16) -> Self {
        let hdr = libc::nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: family_id,
            nlmsg_flags: flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        let mut msg = Self {
            buf: Vec::with_capacity(256),
        };
        msg.put(&hdr);
        msg.put(&Genlmsghdr {
            cmd,
            version: 1,
            reserved: 0,
        });
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
    /// Open a NETLINK_ROUTE socket (for ip link/addr operations).
    fn open() -> Result<Self> {
        Self::open_protocol(libc::NETLINK_ROUTE)
    }

    /// Open a NETLINK_GENERIC socket (for genl ethtool).
    fn open_generic() -> Result<Self> {
        Self::open_protocol(NETLINK_GENERIC)
    }

    fn open_protocol(protocol: libc::c_int) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
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

    /// Send a netlink message and return the raw response.
    fn send_recv(&self, msg: &[u8]) -> Result<Vec<u8>> {
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

        let mut buf = vec![0u8; 4096];
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
        buf.truncate(n as usize);
        Ok(buf)
    }

    /// Send a netlink message and wait for the ACK.
    fn request(&self, msg: &[u8]) -> Result<()> {
        let buf = self.send_recv(msg)?;
        let hdr_size = std::mem::size_of::<libc::nlmsghdr>();
        if buf.len() < hdr_size {
            bail!("netlink: response too short ({} bytes)", buf.len());
        }

        let hdr = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
        if hdr.nlmsg_type == NLMSG_ERROR {
            if buf.len() < hdr_size + 4 {
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
// Generic netlink ethtool — disable offloading
// ---------------------------------------------------------------------------

/// Find a netlink attribute by type in a buffer of NLA entries.
fn find_nla(buf: &[u8], attr_type: u16) -> Option<&[u8]> {
    let mut off = 0;
    while off + 4 <= buf.len() {
        let nla_len = u16::from_ne_bytes(buf[off..off + 2].try_into().ok()?) as usize;
        let nla_type = u16::from_ne_bytes(buf[off + 2..off + 4].try_into().ok()?);
        if nla_len < 4 || off + nla_len > buf.len() {
            break;
        }
        if nla_type == attr_type {
            return Some(&buf[off + 4..off + nla_len]);
        }
        off += (nla_len + 3) & !3;
    }
    None
}

/// Resolve a generic netlink family name (e.g., "ethtool") to its family ID.
fn resolve_genl_family(sock: &NlSocket, name: &str) -> Result<u16> {
    let mut msg = NlMsg::new_genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_REQUEST);
    msg.put_attr_str(CTRL_ATTR_FAMILY_NAME, name);
    let buf = sock.send_recv(msg.finish()).context("GETFAMILY send/recv")?;

    // Response: nlmsghdr(16) + genlmsghdr(4) + NLA attrs.
    let offset = std::mem::size_of::<libc::nlmsghdr>() + std::mem::size_of::<Genlmsghdr>();
    if buf.len() < offset {
        bail!("GETFAMILY response too short");
    }

    // Check for error response.
    let hdr = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
    if hdr.nlmsg_type == NLMSG_ERROR {
        let hdr_size = std::mem::size_of::<libc::nlmsghdr>();
        if buf.len() >= hdr_size + 4 {
            let errno =
                i32::from_ne_bytes(buf[hdr_size..hdr_size + 4].try_into().expect("4 bytes"));
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(-errno).into());
            }
        }
        bail!("GETFAMILY returned error with no errno");
    }

    let attrs = &buf[offset..];
    let id_data =
        find_nla(attrs, CTRL_ATTR_FAMILY_ID).context("CTRL_ATTR_FAMILY_ID not in response")?;
    if id_data.len() < 2 {
        bail!("CTRL_ATTR_FAMILY_ID too short");
    }
    Ok(u16::from_ne_bytes(
        id_data[..2].try_into().expect("2 bytes"),
    ))
}

/// Send ETHTOOL_MSG_FEATURES_SET to disable the given features on an interface.
fn set_features_off(sock: &NlSocket, family: u16, iface: &str, features: &[&str]) -> Result<()> {
    let mut msg =
        NlMsg::new_genl(family, ETHTOOL_MSG_FEATURES_SET, NLM_F_REQUEST | NLM_F_ACK);

    // ETHTOOL_A_FEATURES_HEADER → dev name
    let hdr_nest = msg.begin_nested(ETHTOOL_A_FEATURES_HEADER);
    msg.put_attr_str(ETHTOOL_A_HEADER_DEV_NAME, iface);
    msg.end_nested(hdr_nest);

    // ETHTOOL_A_FEATURES_WANTED → BITSET_BITS → [BIT entries]
    let wanted = msg.begin_nested(ETHTOOL_A_FEATURES_WANTED);
    let bits = msg.begin_nested(ETHTOOL_A_BITSET_BITS);
    for feature in features {
        let bit = msg.begin_nested(ETHTOOL_A_BITSET_BITS_BIT);
        msg.put_attr_str(ETHTOOL_A_BITSET_BIT_NAME, feature);
        // No ETHTOOL_A_BITSET_BIT_VALUE → bit cleared (feature off).
        msg.end_nested(bit);
    }
    msg.end_nested(bits);
    msg.end_nested(wanted);

    sock.request(msg.finish())
}

/// Disable offloading features on a veth interface via generic netlink ethtool.
///
/// Uses ETHTOOL_MSG_FEATURES_SET — the same interface as modern `ethtool -K`.
/// Unlike the legacy SIOCETHTOOL ioctl, this can change all features including
/// rx-checksumming on veth devices.
///
/// Non-fatal: logs failures at debug level.
fn disable_offloading(iface: &str) {
    if let Err(e) = disable_offloading_inner(iface) {
        tracing::debug!(iface, "failed to disable offloading: {e:#}");
    }
}

fn disable_offloading_inner(iface: &str) -> Result<()> {
    let sock = NlSocket::open_generic().context("genl socket")?;
    let family = resolve_genl_family(&sock, "ethtool").context("resolve ethtool family")?;

    // Try all features in a single request.
    match set_features_off(&sock, family, iface, FEATURES_DISABLE) {
        Ok(()) => {
            tracing::debug!(iface, "offloading disabled (batch)");
        }
        Err(e) => {
            tracing::debug!(iface, "batch disable failed ({e:#}), trying individually");
            for feature in FEATURES_DISABLE {
                match set_features_off(&sock, family, iface, &[feature]) {
                    Ok(()) => tracing::debug!(iface, feature, "disabled"),
                    Err(e) => tracing::debug!(iface, feature, "skip: {e:#}"),
                }
            }
        }
    }
    Ok(())
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
