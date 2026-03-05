use std::ffi::CString;

use anyhow::{Context, Result, bail};

use crate::ffi;

/// RAII wrapper for DPDK EAL (Environment Abstraction Layer).
///
/// Calls `rte_eal_init` on construction and `rte_eal_cleanup` on drop.
pub struct Eal {
    _private: (),
}

impl Eal {
    /// Initialize the DPDK EAL with the given arguments.
    ///
    /// `args` should be EAL parameters (e.g., `["-l", "0", "-n", "4"]`).
    /// The program name is prepended automatically.
    pub fn init(args: &[String]) -> Result<Self> {
        let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        c_args.push(CString::new("quictun").expect("program name"));
        for arg in args {
            c_args.push(
                CString::new(arg.as_str()).with_context(|| format!("invalid EAL arg: {arg}"))?,
            );
        }

        let mut c_ptrs: Vec<*mut libc::c_char> =
            c_args.iter().map(|s| s.as_ptr() as *mut _).collect();
        let argc = c_ptrs.len() as libc::c_int;

        // SAFETY: c_ptrs contains valid CString pointers; argc matches the array length.
        // rte_eal_init parses EAL args and initializes the DPDK subsystem.
        let ret = unsafe { ffi::rte_eal_init(argc, c_ptrs.as_mut_ptr()) };
        if ret < 0 {
            bail!("rte_eal_init failed (ret={ret}): check hugepages and DPDK driver binding");
        }

        tracing::info!(parsed_args = ret, "DPDK EAL initialized");
        Ok(Self { _private: () })
    }
}

impl Drop for Eal {
    fn drop(&mut self) {
        // SAFETY: EAL was successfully initialized (checked in init). Called once on drop.
        unsafe {
            ffi::rte_eal_cleanup();
        }
        tracing::info!("DPDK EAL cleaned up");
    }
}
