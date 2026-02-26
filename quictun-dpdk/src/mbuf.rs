use std::ffi::CString;
use std::ptr;

use anyhow::{bail, Result};

use crate::ffi;

/// Create a DPDK packet mbuf mempool.
///
/// `n` is the number of mbufs (should be 2^k - 1 for optimal memory usage).
/// `cache_size` is per-lcore cache (0 to disable, 256 is typical).
pub fn create_mempool(name: &str, n: u32, cache_size: u32) -> Result<*mut ffi::rte_mempool> {
    let c_name = CString::new(name).expect("mempool name");
    // SAFETY: c_name is a valid CString; n, cache_size, and buf_size are within DPDK limits.
    // rte_pktmbuf_pool_create returns null on failure (checked below).
    let pool = unsafe {
        ffi::rte_pktmbuf_pool_create(
            c_name.as_ptr(),
            n,
            cache_size,
            0, // priv_size
            ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
            0, // socket_id (NUMA node)
        )
    };

    if pool.is_null() {
        bail!(
            "rte_pktmbuf_pool_create failed: check hugepages (need {} MB)",
            (n as u64 * ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u64) / (1024 * 1024)
        );
    }

    tracing::info!(name, num_mbufs = n, cache_size, "mempool created");
    Ok(pool)
}

/// RAII wrapper for a DPDK mbuf.
///
/// Owns a single `rte_mbuf`.  Freed on drop via `rte_pktmbuf_free`.
pub struct Mbuf {
    raw: *mut ffi::rte_mbuf,
}

// SAFETY: Mbuf has exclusive (non-aliased) ownership of the underlying rte_mbuf pointer.
// The pointer is never shared between threads simultaneously — ownership is transferred
// via from_raw/into_raw at rx_burst/tx_burst boundaries, ensuring single-owner semantics.
unsafe impl Send for Mbuf {}

impl Mbuf {
    /// Allocate a new mbuf from the mempool.
    pub fn alloc(pool: *mut ffi::rte_mempool) -> Result<Self> {
        // SAFETY: pool is a valid mempool created by rte_pktmbuf_pool_create.
        // Returns null on failure (checked below).
        let raw = unsafe { ffi::shim_rte_pktmbuf_alloc(pool) };
        if raw.is_null() {
            bail!("mbuf alloc failed: mempool exhausted");
        }
        Ok(Self { raw })
    }

    /// Take ownership of a raw mbuf pointer (e.g., from rx_burst).
    ///
    /// # Safety
    /// Caller must ensure `raw` is a valid, owned mbuf pointer.
    pub unsafe fn from_raw(raw: *mut ffi::rte_mbuf) -> Self {
        debug_assert!(!raw.is_null());
        Self { raw }
    }

    /// Release ownership and return the raw pointer (e.g., for tx_burst).
    ///
    /// The caller is responsible for freeing the mbuf.
    pub fn into_raw(self) -> *mut ffi::rte_mbuf {
        let raw = self.raw;
        std::mem::forget(self);
        raw
    }

    /// Read-only access to the mbuf's data.
    pub fn data(&self) -> &[u8] {
        // SAFETY: self.raw is a valid mbuf (invariant maintained by alloc/from_raw).
        // shim_rte_pktmbuf_mtod returns a pointer to the data region, and data_len
        // gives its length. The slice lifetime is tied to &self, preventing use-after-free.
        unsafe {
            let ptr = ffi::shim_rte_pktmbuf_mtod(self.raw) as *const u8;
            let len = ffi::shim_rte_pktmbuf_data_len(self.raw) as usize;
            std::slice::from_raw_parts(ptr, len)
        }
    }

    /// Mutable access to the mbuf's data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: same as data(), but with exclusive &mut self ensuring no aliasing.
        unsafe {
            let ptr = ffi::shim_rte_pktmbuf_mtod(self.raw) as *mut u8;
            let len = ffi::shim_rte_pktmbuf_data_len(self.raw) as usize;
            std::slice::from_raw_parts_mut(ptr, len)
        }
    }

    /// Append `len` bytes at the tail, returning a mutable pointer to the new area.
    ///
    /// Returns `None` if there's not enough tailroom.
    pub fn append(&mut self, len: u16) -> Option<*mut u8> {
        // SAFETY: self.raw is valid; append returns null if insufficient tailroom.
        let ptr = unsafe { ffi::shim_rte_pktmbuf_append(self.raw, len) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr as *mut u8)
        }
    }

    /// Reset the mbuf to its initial state (data_len=0, headroom restored).
    pub fn reset(&mut self) {
        // SAFETY: self.raw is valid; reset restores mbuf to its initial state.
        unsafe { ffi::shim_rte_pktmbuf_reset(self.raw) }
    }

    /// Current data length.
    pub fn len(&self) -> usize {
        // SAFETY: self.raw is valid.
        unsafe { ffi::shim_rte_pktmbuf_data_len(self.raw) as usize }
    }

    /// Reset the mbuf and allocate `len` bytes of writable space.
    ///
    /// Returns a mutable slice into the mbuf's data region. The caller can
    /// build a packet directly into this slice, avoiding an intermediate buffer copy.
    pub fn alloc_space(&mut self, len: u16) -> Result<&mut [u8]> {
        self.reset();
        let ptr = self
            .append(len)
            .ok_or_else(|| anyhow::anyhow!("mbuf too small for {} bytes", len))?;
        // SAFETY: ptr points to freshly appended tailroom of `len` bytes within the mbuf.
        // The slice lifetime is tied to &mut self, preventing aliasing.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) })
    }

    /// Write `data` into a freshly reset mbuf.
    ///
    /// Resets the mbuf, appends space, and copies `data` into it.
    pub fn write_packet(&mut self, data: &[u8]) -> Result<()> {
        self.reset();
        let ptr = self
            .append(data.len() as u16)
            .ok_or_else(|| anyhow::anyhow!("mbuf too small for {} bytes", data.len()))?;
        // SAFETY: ptr points to freshly appended tailroom of data.len() bytes;
        // data.as_ptr() is valid for data.len() bytes; regions don't overlap.
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        Ok(())
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // SAFETY: self.raw is a valid mbuf that we own exclusively.
        // After free, self is being dropped so no further access occurs.
        unsafe {
            ffi::shim_rte_pktmbuf_free(self.raw);
        }
    }
}
