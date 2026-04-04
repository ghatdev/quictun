//! OS-level route management (Layer 2).
//!
//! Adds/removes kernel routes so that traffic destined for peer `allowed_ips`
//! is directed to the TUN device. Distinct from the Layer 3 CID routing in
//! [`quictun_core::routing::RoutingTable`].
//!
//! - Linux: netlink `RTM_NEWROUTE` / `RTM_DELROUTE`
//! - macOS: PF_ROUTE `RTM_ADD` / `RTM_DELETE`

use std::io;

use ipnet::Ipv4Net;

// ── Linux: netlink ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn add_route(dst: Ipv4Net, ifindex: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = netlink_route(fd, libc::RTM_NEWROUTE, dst, ifindex);

    unsafe { libc::close(fd) };
    result
}

#[cfg(target_os = "linux")]
pub fn remove_route(dst: Ipv4Net, ifindex: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = netlink_route(fd, libc::RTM_DELROUTE, dst, ifindex);

    unsafe { libc::close(fd) };
    result
}

#[cfg(target_os = "linux")]
fn netlink_route(fd: i32, msg_type: u16, dst: Ipv4Net, ifindex: u32) -> io::Result<()> {
    // Netlink message: nlmsghdr + rtmsg + RTA_DST + RTA_OIF
    //
    // Layout:
    //   nlmsghdr (16 bytes)
    //   rtmsg (12 bytes)
    //   rtattr RTA_DST (8 bytes: 4 header + 4 IP)
    //   rtattr RTA_OIF (8 bytes: 4 header + 4 ifindex)
    // Total: 44 bytes

    let mut buf = [0u8; 64];
    let prefix_len = dst.prefix_len();
    let dst_ip = dst.network();
    let dst_bytes = dst_ip.octets();

    // nlmsghdr
    let nlmsg_len: u32 = 44; // 16 + 12 + 8 + 8
    buf[0..4].copy_from_slice(&nlmsg_len.to_ne_bytes());
    buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());

    let flags: u16 = if msg_type == libc::RTM_NEWROUTE as u16 {
        (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16
    } else {
        libc::NLM_F_REQUEST as u16
    };
    buf[6..8].copy_from_slice(&flags.to_ne_bytes());

    // seq=1, pid=0
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes());
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes());

    // rtmsg (offset 16)
    buf[16] = libc::AF_INET as u8; // rtm_family
    buf[17] = prefix_len;           // rtm_dst_len
    buf[18] = 0;                    // rtm_src_len
    buf[19] = 0;                    // rtm_tos
    buf[20] = libc::RT_TABLE_MAIN as u8; // rtm_table
    buf[21] = libc::RTPROT_STATIC as u8; // rtm_protocol
    buf[22] = libc::RT_SCOPE_LINK as u8; // rtm_scope
    buf[23] = libc::RTN_UNICAST as u8;   // rtm_type
    buf[24..28].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags

    // RTA_DST (offset 28): rta_len=8, rta_type=RTA_DST=1
    buf[28..30].copy_from_slice(&8u16.to_ne_bytes()); // rta_len
    buf[30..32].copy_from_slice(&(libc::RTA_DST as u16).to_ne_bytes());
    buf[32..36].copy_from_slice(&dst_bytes);

    // RTA_OIF (offset 36): rta_len=8, rta_type=RTA_OIF=4
    buf[36..38].copy_from_slice(&8u16.to_ne_bytes()); // rta_len
    buf[38..40].copy_from_slice(&(libc::RTA_OIF as u16).to_ne_bytes());
    buf[40..44].copy_from_slice(&ifindex.to_ne_bytes());

    // Bind to netlink.
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;

    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Send the message.
    let ret = unsafe { libc::send(fd, buf.as_ptr() as *const _, nlmsg_len as usize, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Read response to check for errors (non-blocking to avoid hanging).
    let mut resp = [0u8; 128];
    let n = unsafe { libc::recv(fd, resp.as_mut_ptr() as *mut _, resp.len(), libc::MSG_DONTWAIT) };
    if n < 0 {
        let err = io::Error::last_os_error();
        // EAGAIN is OK — no response yet (common for duplicate routes).
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(err);
        }
        return Ok(());
    }

    // Check nlmsghdr type — NLMSG_ERROR (2) with error=0 means success.
    if n >= 20 {
        let resp_type = u16::from_ne_bytes([resp[4], resp[5]]);
        if resp_type == libc::NLMSG_ERROR as u16 {
            let error = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
            if error < 0 {
                return Err(io::Error::from_raw_os_error(-error));
            }
        }
    }

    Ok(())
}

// ── macOS: PF_ROUTE ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub fn add_route(dst: Ipv4Net, ifname: &str) -> io::Result<()> {
    pf_route(libc::RTM_ADD as u8, dst, ifname)
}

#[cfg(target_os = "macos")]
pub fn remove_route(dst: Ipv4Net, ifname: &str) -> io::Result<()> {
    pf_route(libc::RTM_DELETE as u8, dst, ifname)
}

#[cfg(target_os = "macos")]
fn pf_route(msg_type: u8, dst: Ipv4Net, ifname: &str) -> io::Result<()> {
    // PF_ROUTE message: rt_msghdr + sockaddr_in (destination) + sockaddr_in (netmask)
    //
    // We use the `route` syscall interface via a PF_ROUTE socket.

    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = pf_route_inner(fd, msg_type, dst, ifname);

    unsafe { libc::close(fd) };
    result
}

#[cfg(target_os = "macos")]
fn pf_route_inner(fd: i32, msg_type: u8, dst: Ipv4Net, ifname: &str) -> io::Result<()> {
    use std::mem;

    let dst_ip = dst.network();
    let prefix_len = dst.prefix_len();

    // Build netmask from prefix length.
    let mask_bits: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let mask_ip = std::net::Ipv4Addr::from(mask_bits.to_be_bytes());

    // We need: rt_msghdr + sockaddr_in (dst) + sockaddr_in (mask)
    // rt_msghdr is variable-size on macOS but we use a fixed buffer.
    let hdr_size = mem::size_of::<libc::rt_msghdr>();
    let sa_size = mem::size_of::<libc::sockaddr_in>();
    let msg_len = hdr_size + sa_size * 2;

    let mut buf = vec![0u8; msg_len];

    // rt_msghdr
    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut libc::rt_msghdr) };
    hdr.rtm_msglen = msg_len as u16;
    hdr.rtm_version = libc::RTM_VERSION as u8;
    hdr.rtm_type = msg_type;
    hdr.rtm_addrs = (libc::RTA_DST | libc::RTA_NETMASK) as i32;
    hdr.rtm_flags = (libc::RTF_UP | libc::RTF_STATIC) as i32;
    hdr.rtm_pid = unsafe { libc::getpid() };
    hdr.rtm_seq = 1;

    // If adding, look up ifindex from ifname.
    if msg_type == libc::RTM_ADD as u8 {
        let ifindex = ifname_to_index(ifname)?;
        hdr.rtm_index = ifindex as u16;
    }

    // sockaddr_in for destination (offset = hdr_size)
    let dst_sa = unsafe { &mut *(buf[hdr_size..].as_mut_ptr() as *mut libc::sockaddr_in) };
    dst_sa.sin_len = sa_size as u8;
    dst_sa.sin_family = libc::AF_INET as u8;
    dst_sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(dst_ip.octets()),
    };

    // sockaddr_in for netmask (offset = hdr_size + sa_size)
    let mask_sa =
        unsafe { &mut *(buf[hdr_size + sa_size..].as_mut_ptr() as *mut libc::sockaddr_in) };
    mask_sa.sin_len = sa_size as u8;
    mask_sa.sin_family = libc::AF_INET as u8;
    mask_sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(mask_ip.octets()),
    };

    let ret = unsafe { libc::write(fd, buf.as_ptr() as *const _, msg_len) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // EEXIST when adding an existing route is not fatal.
        if msg_type == libc::RTM_ADD as u8 && err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        // ESRCH when deleting a non-existing route is not fatal.
        if msg_type == libc::RTM_DELETE as u8 && err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err);
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn ifname_to_index(name: &str) -> io::Result<u32> {
    let c_name =
        std::ffi::CString::new(name).map_err(|_| io::Error::other("invalid interface name"))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}
