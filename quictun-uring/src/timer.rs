use std::os::fd::{OwnedFd, AsRawFd, RawFd, FromRawFd};
use std::time::Instant;

use anyhow::{Context, Result};

/// Wrapper around a Linux timerfd for integration with io_uring.
///
/// quinn-proto's `Connection::poll_timeout()` returns `Option<Instant>`.
/// We convert that to a timerfd deadline so io_uring can wake us when it fires.
pub struct Timer {
    fd: OwnedFd,
    /// Monotonic reference point for converting `Instant` → kernel timespec.
    epoch: Instant,
}

impl Timer {
    pub fn new() -> Result<Self> {
        // SAFETY: timerfd_create is a safe syscall.
        let raw = unsafe {
            libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("timerfd_create failed");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            epoch: Instant::now(),
        })
    }

    /// Arm the timer to fire at `deadline`.
    pub fn arm(&self, deadline: Instant) {
        let now = Instant::now();
        let duration = if deadline > now {
            deadline - now
        } else {
            // Already past — fire immediately (1 ns minimum).
            std::time::Duration::from_nanos(1)
        };

        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_nsec: duration.subsec_nanos() as libc::c_long,
            },
        };

        // SAFETY: valid fd and spec.
        unsafe {
            libc::timerfd_settime(self.fd.as_raw_fd(), 0, &spec, std::ptr::null_mut());
        }
    }

    /// Disarm the timer (set to zero).
    pub fn disarm(&self) {
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        };

        // SAFETY: valid fd and zeroed spec disarms the timer.
        unsafe {
            libc::timerfd_settime(self.fd.as_raw_fd(), 0, &spec, std::ptr::null_mut());
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
