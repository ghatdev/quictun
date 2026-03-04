//! Safe wrapper around DPDK `rte_ring` for SPSC (single-producer, single-consumer) use.
//!
//! The ring is created with `RING_F_SP_ENQ | RING_F_SC_DEQ` flags, enabling
//! the lock-free SPSC fast path in DPDK. Used for inter-core mbuf dispatch.

use std::ffi::CString;

use anyhow::{bail, Result};

use crate::ffi;

/// SPSC ring for passing mbuf pointers between cores.
///
/// - Producer (core 0 dispatcher) calls `enqueue()` / `enqueue_burst()`
/// - Consumer (worker core) calls `dequeue_burst()`
pub struct SpscRing {
    ring: *mut ffi::rte_ring,
}

// SAFETY: The ring is used in SPSC mode — one producer thread and one consumer
// thread. The rte_ring SPSC path is lock-free and safe for cross-thread use.
unsafe impl Send for SpscRing {}
unsafe impl Sync for SpscRing {}

impl SpscRing {
    /// Create a new SPSC ring with the given name and capacity.
    ///
    /// `count` must be a power of 2. `socket_id` is the NUMA node (0 = any).
    pub fn new(name: &str, count: u32, socket_id: i32) -> Result<Self> {
        let c_name = CString::new(name).expect("ring name contains null byte");
        let flags = ffi::RING_F_SP_ENQ | ffi::RING_F_SC_DEQ;

        // SAFETY: EAL is initialized; name is a valid C string; flags enable SPSC mode.
        let ring = unsafe { ffi::shim_rte_ring_create(c_name.as_ptr(), count, socket_id, flags) };

        if ring.is_null() {
            bail!("rte_ring_create({name}, count={count}) failed");
        }

        Ok(Self { ring })
    }

    /// Enqueue a single mbuf pointer. Returns `true` if successful, `false` if full.
    #[inline]
    pub fn enqueue(&self, mbuf: *mut ffi::rte_mbuf) -> bool {
        // SAFETY: ring is valid; mbuf is a valid pointer. SP enqueue is lock-free.
        let ret = unsafe { ffi::shim_rte_ring_sp_enqueue(self.ring, mbuf as *mut _) };
        ret == 0
    }

    /// Enqueue a burst of mbuf pointers. Returns the number actually enqueued.
    #[inline]
    pub fn enqueue_burst(&self, mbufs: &[*mut ffi::rte_mbuf]) -> u32 {
        let mut free_space: u32 = 0;
        // SAFETY: ring is valid; mbufs is a valid slice of pointers.
        unsafe {
            ffi::shim_rte_ring_sp_enqueue_burst(
                self.ring,
                mbufs.as_ptr() as *mut *mut _,
                mbufs.len() as u32,
                &mut free_space,
            )
        }
    }

    /// Dequeue a burst of mbuf pointers into `out`. Returns the number dequeued.
    #[inline]
    pub fn dequeue_burst(&self, out: &mut [*mut ffi::rte_mbuf]) -> u32 {
        let mut available: u32 = 0;
        // SAFETY: ring is valid; out has space for the dequeued pointers.
        unsafe {
            ffi::shim_rte_ring_sc_dequeue_burst(
                self.ring,
                out.as_mut_ptr() as *mut *mut _,
                out.len() as u32,
                &mut available,
            )
        }
    }
}

impl Drop for SpscRing {
    fn drop(&mut self) {
        // SAFETY: ring was created by rte_ring_create; freed exactly once.
        unsafe { ffi::shim_rte_ring_free(self.ring) };
    }
}
