use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result, bail};

const BUF_SIZE: i32 = 8 * 1024 * 1024; // 8 MB

/// Create a raw connected UDP socket suitable for io_uring.
///
/// Connected mode allows using simple Read/Write io_uring ops instead of
/// RecvMsg/SendMsg with msghdr structs.
pub fn create_udp(local: SocketAddr, remote: SocketAddr) -> Result<OwnedFd> {
    let fd = create_udp_socket(local).context("create_udp")?;
    connect_to_peer(&fd, remote).context("connect_to_peer")?;
    Ok(fd)
}

/// Create a bound-only (unconnected) UDP socket suitable for listener startup.
///
/// The socket is bound to `local` but NOT connected — use `recvfrom_first_raw()` to
/// learn the peer address, then `connect_to_peer_raw()` to enter connected mode.
pub fn create_udp_unbound(local: SocketAddr) -> Result<OwnedFd> {
    create_udp_socket(local).context("create_udp_unbound")
}

/// Blocking `recvfrom()` — waits for the first UDP packet and returns
/// (bytes_read, peer_address). Used once at listener startup to learn the
/// peer address before entering the io_uring loop.
///
/// The socket MUST be in blocking mode when this is called.
pub fn recvfrom_first_raw(fd: RawFd, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let n = unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("recvfrom() failed");
    }

    let peer = sockaddr_to_std(&storage)?;
    Ok((n as usize, peer))
}

/// Connect a previously unbound socket to `remote`, enabling Read/Write ops.
pub fn connect_to_peer(fd: &OwnedFd, remote: SocketAddr) -> Result<()> {
    connect_to_peer_raw(fd.as_raw_fd(), remote)
}

/// Raw fd variant of [`connect_to_peer`] for use from engine threads that only
/// have a `RawFd`.
pub fn connect_to_peer_raw(fd: RawFd, remote: SocketAddr) -> Result<()> {
    let remote_addr = sockaddr_from(remote);
    let remote_len = match remote {
        SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>(),
        SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>(),
    };
    let ret = unsafe {
        libc::connect(
            fd,
            &remote_addr as *const _ as *const libc::sockaddr,
            remote_len as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("connect() failed");
    }
    Ok(())
}

/// Get the local address a socket is bound to (after OS assigns ephemeral port).
pub fn local_addr(fd: &OwnedFd) -> Result<SocketAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("getsockname() failed");
    }

    sockaddr_to_std(&storage)
}

// --- internal helpers ---

/// Create a nonblocking UDP socket, set buffer sizes + PMTUD, bind to `local`.
fn create_udp_socket(local: SocketAddr) -> Result<OwnedFd> {
    let (domain, addr_len) = match local {
        SocketAddr::V4(_) => (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>()),
        SocketAddr::V6(_) => (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>()),
    };

    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket() failed");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = fd.as_raw_fd();

    // Allow rebinding the port immediately after a previous instance exits.
    // Without this, io_uring's register_files() keeps a kernel reference to the
    // socket FD that outlives the process on hard kill (Ctrl+C), causing EADDRINUSE.
    setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1).context("SO_REUSEADDR")?;

    // Set buffer sizes.
    setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, BUF_SIZE).context("SO_RCVBUF")?;
    setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_SNDBUF, BUF_SIZE).context("SO_SNDBUF")?;

    // IP_DONTFRAG / IPV6_DONTFRAG — required for QUIC MTUD.
    match local {
        SocketAddr::V4(_) => {
            setsockopt_int(
                raw,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )
            .context("IP_MTU_DISCOVER")?;
        }
        SocketAddr::V6(_) => {
            setsockopt_int(
                raw,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_PROBE,
            )
            .context("IPV6_MTU_DISCOVER")?;
        }
    }

    // Bind.
    let bind_addr = sockaddr_from(local);
    let ret = unsafe {
        libc::bind(
            raw,
            &bind_addr as *const _ as *const libc::sockaddr,
            addr_len as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("bind() failed");
    }

    Ok(fd)
}

fn setsockopt_int(fd: i32, level: i32, name: i32, value: i32) -> Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Convert a `SocketAddr` to a `libc::sockaddr_storage`.
fn sockaddr_from(addr: SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sa: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
        }
        SocketAddr::V6(v6) => {
            let sa: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut _) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
        }
    }
    storage
}

/// Convert a `libc::sockaddr_storage` to a `SocketAddr`.
fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::new(ip.into(), port))
        }
        f => bail!("unexpected address family: {f}"),
    }
}
