use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result};

/// Cross-thread wakeup using Linux eventfd.
///
/// One thread holds a pending io_uring Read SQE on this fd. The other thread
/// calls `wake()` to trigger a CQE, breaking the first thread out of
/// `submit_and_wait()`.
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    pub fn new() -> Result<Self> {
        let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error()).context("eventfd() failed");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Signal the eventfd, waking any pending io_uring Read SQE.
    pub fn wake(&self) {
        let val: u64 = 1;
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &val as *const u64 as *const libc::c_void,
                8,
            );
        }
    }
}
