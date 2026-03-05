//! Batched UDP I/O via sendmmsg/recvmmsg and UDP GSO/GRO (Linux only).
//!
//! Reduces per-packet syscall overhead by sending/receiving multiple UDP
//! packets in a single kernel call.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

/// Maximum batch size for sendmmsg/recvmmsg.
pub const BATCH_SIZE: usize = 64;

/// Maximum segments per UDP GSO sendmsg (kernel ~64KB limit per sendmsg).
/// 64KB / ~1500 bytes per segment ≈ 43. Use 44 to be exact.
pub const GSO_MAX_SEGMENTS: usize = 44;

/// GSO buffer size: enough for max segments.
pub const GSO_BUF_SIZE: usize = GSO_MAX_SEGMENTS * 2048;

/// Build a sockaddr_in from a SocketAddr::V4.
fn build_sockaddr_v4(remote_addr: SocketAddr) -> io::Result<(libc::sockaddr_in, libc::socklen_t)> {
    match remote_addr {
        SocketAddr::V4(addr) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            Ok((
                sa,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ))
        }
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 not supported yet",
        )),
    }
}

/// Send multiple UDP packets in a single syscall via sendmmsg(2).
///
/// `bufs[i][..lens[i]]` is the data for message i, all sent to `remote_addr`.
/// Returns the number of messages successfully sent.
pub fn sendmmsg_batch(
    fd: &impl AsRawFd,
    bufs: &[Vec<u8>],
    lens: &[usize],
    count: usize,
    remote_addr: SocketAddr,
) -> io::Result<usize> {
    if count == 0 {
        return Ok(0);
    }

    let (sockaddr, sockaddr_len) = build_sockaddr_v4(remote_addr)?;
    let count = count.min(bufs.len()).min(lens.len()).min(BATCH_SIZE);

    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for i in 0..count {
        iovecs[i] = libc::iovec {
            iov_base: bufs[i].as_ptr() as *mut libc::c_void,
            iov_len: lens[i],
        };
        msgs[i].msg_hdr.msg_name = &sockaddr as *const _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = sockaddr_len;
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    let ret =
        unsafe { libc::sendmmsg(fd.as_raw_fd(), msgs.as_mut_ptr(), count as libc::c_uint, 0) };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Receive multiple UDP packets in a single syscall via recvmmsg(2).
///
/// Fills `bufs[0..n]` with received data, `lens[0..n]` with lengths,
/// and `addrs[0..n]` with source addresses.
/// Returns the number of messages received.
///
/// Uses MSG_DONTWAIT so it won't block — call after ensuring readability.
pub fn recvmmsg_batch(
    fd: &impl AsRawFd,
    bufs: &mut [Vec<u8>],
    lens: &mut [usize],
    addrs: &mut [SocketAddr],
    max_count: usize,
) -> io::Result<usize> {
    let count = max_count
        .min(bufs.len())
        .min(lens.len())
        .min(addrs.len())
        .min(BATCH_SIZE);
    if count == 0 {
        return Ok(0);
    }

    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut sockaddrs: [libc::sockaddr_in; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for i in 0..count {
        iovecs[i] = libc::iovec {
            iov_base: bufs[i].as_mut_ptr() as *mut libc::c_void,
            iov_len: bufs[i].len(),
        };
        msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    }

    let ret = unsafe {
        libc::recvmmsg(
            fd.as_raw_fd(),
            msgs.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        let n = ret as usize;
        for i in 0..n {
            lens[i] = msgs[i].msg_len as usize;
            let sa = &sockaddrs[i];
            let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            addrs[i] = SocketAddr::new(ip.into(), port);
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// UDP GSO (sendmsg with UDP_SEGMENT) / GRO (recvmsg with UDP_GRO)
// ---------------------------------------------------------------------------

/// Enable UDP GRO on a socket. Returns Ok(true) if enabled, Ok(false) if
/// the kernel doesn't support it.
pub fn enable_udp_gro(fd: &impl AsRawFd) -> io::Result<bool> {
    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            Ok(false)
        } else {
            Err(err)
        }
    } else {
        Ok(true)
    }
}

/// Send a contiguous buffer as multiple UDP segments via UDP GSO.
///
/// `buf[..total_len]` contains N concatenated segments, each of `segment_size` bytes
/// (the last segment may be smaller). The kernel splits them into individual UDP packets.
///
/// Returns the number of bytes accepted by the kernel.
pub fn send_gso(
    fd: &impl AsRawFd,
    buf: &[u8],
    segment_size: u16,
    remote_addr: SocketAddr,
) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }

    let (sockaddr, sockaddr_len) = build_sockaddr_v4(remote_addr)?;

    let iovec = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // cmsg buffer for UDP_SEGMENT (u16).
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &sockaddr as *const _ as *mut libc::c_void;
    msg.msg_namelen = sockaddr_len;
    msg.msg_iov = &iovec as *const _ as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        *data = segment_size;
    }

    let ret = unsafe { libc::sendmsg(fd.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Receive a GRO-coalesced UDP buffer and split into individual segments.
///
/// Requires `enable_udp_gro()` to have been called on the socket.
/// Returns `(total_bytes, segment_size)`. If no GRO cmsg is present,
/// `segment_size` equals `total_bytes` (single packet).
///
/// Uses MSG_DONTWAIT — call after ensuring readability.
pub fn recv_gro(fd: &impl AsRawFd, buf: &mut [u8]) -> io::Result<(usize, usize)> {
    let mut iovec = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let ret = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let total = ret as usize;

    // Parse cmsg to find GRO segment size.
    let mut segment_size = total; // default: single packet
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                let data = libc::CMSG_DATA(cmsg) as *const u16;
                segment_size = (*data) as usize;
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((total, segment_size))
}
