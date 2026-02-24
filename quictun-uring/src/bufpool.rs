use std::collections::VecDeque;
use std::pin::Pin;

use anyhow::{Context, Result};
use io_uring::IoUring;

/// Buffer size: must be > 1500 MTU to hold any TUN/UDP packet.
pub const BUF_SIZE: usize = 2048;

/// Default number of buffers in the pool.
/// Must be ≤ 1024 (kernel UIO_MAXIOV limit for register_buffers).
/// 1024 × 2048 = 2 MB per pool (each reader/engine thread has its own pool).
pub const DEFAULT_POOL_SIZE: usize = 1024;

/// Maximum pool size (kernel UIO_MAXIOV limit for register_buffers).
pub const MAX_POOL_SIZE: usize = 1024;

// Operation type tags packed into the upper 4 bits of user_data.
pub const OP_TUN_READ: u64 = 0;
pub const OP_TUN_WRITE: u64 = 1;
pub const OP_UDP_RECV: u64 = 2;
pub const OP_UDP_SEND: u64 = 3;
pub const OP_TIMER: u64 = 4;
pub const OP_WAKE: u64 = 5;
pub const OP_SHUTDOWN: u64 = 6;
pub const OP_PROVIDE_BUF: u64 = 7;

/// Buffer group ID for multishot UDP recv.
pub const BUF_GROUP_UDP: u16 = 0;

const OP_SHIFT: u32 = 60;
const INDEX_MASK: u64 = (1 << OP_SHIFT) - 1;

/// Encode an operation type and buffer index into an io_uring user_data u64.
#[inline]
pub fn encode_user_data(op: u64, buf_idx: usize) -> u64 {
    (op << OP_SHIFT) | (buf_idx as u64 & INDEX_MASK)
}

/// Decode the operation type from a user_data u64.
#[inline]
pub fn decode_op(user_data: u64) -> u64 {
    user_data >> OP_SHIFT
}

/// Decode the buffer index from a user_data u64.
#[inline]
pub fn decode_index(user_data: u64) -> usize {
    (user_data & INDEX_MASK) as usize
}

/// Pre-allocated slab of fixed-size buffers for io_uring I/O.
///
/// # Safety model
///
/// `base_ptr` is derived from `&mut` access during construction (before pinning),
/// so it carries write provenance. Pin ensures the heap allocation never moves,
/// keeping the pointer valid for the pool's lifetime.
///
/// Buffer lifecycle: alloc → pass ptr to io_uring SQE → kernel reads/writes →
/// CQE arrives → we access via slice/slice_mut → free. No Rust references exist
/// while the kernel has the buffer.
pub struct BufferPool {
    /// Keeps the heap allocation alive and pinned. Not accessed after construction.
    _storage: Pin<Box<[u8]>>,
    /// Raw pointer to the base of the allocation, derived from `&mut` access.
    /// Valid for the lifetime of `_storage` because Pin prevents moves.
    base_ptr: *mut u8,
    free: VecDeque<usize>,
    size: usize,
}

// SAFETY: BufferPool is used single-threaded (one per engine/reader thread).
// The raw pointer is derived from an owned Box and is only accessed by the
// owning thread. No cross-thread sharing occurs.
unsafe impl Send for BufferPool {}

impl BufferPool {
    pub fn new(pool_size: usize) -> Self {
        let size = pool_size.min(MAX_POOL_SIZE);
        let mut storage = vec![0u8; BUF_SIZE * size].into_boxed_slice();
        // Derive the raw pointer from &mut access BEFORE pinning.
        // This gives the pointer write provenance under Stacked Borrows.
        let base_ptr = storage.as_mut_ptr();
        let storage = Pin::new(storage);
        let free: VecDeque<usize> = (0..size).collect();
        Self {
            _storage: storage,
            base_ptr,
            free,
            size,
        }
    }

    /// Allocate a buffer, returning its index. Returns `None` if exhausted.
    pub fn alloc(&mut self) -> Option<usize> {
        self.free.pop_front()
    }

    /// Return a buffer to the free list.
    pub fn free(&mut self, idx: usize) {
        debug_assert!(idx < self.size);
        self.free.push_back(idx);
    }

    /// Get a read-only slice of completed data at `idx` with `len` bytes.
    ///
    /// # Safety invariant
    /// Caller must ensure the buffer is not in-flight with io_uring
    /// (i.e., the CQE for this buffer has been reaped).
    pub fn slice(&self, idx: usize, len: usize) -> &[u8] {
        // SAFETY: base_ptr is valid for size * BUF_SIZE bytes, idx < size (from alloc),
        // len ≤ BUF_SIZE (from io_uring result), and no mutable reference exists.
        unsafe { std::slice::from_raw_parts(self.base_ptr.add(idx * BUF_SIZE), len) }
    }

    /// Get a mutable slice of buffer at `idx` (full BUF_SIZE).
    ///
    /// # Safety invariant
    /// Caller must ensure the buffer is not in-flight with io_uring
    /// and no other references to this buffer index exist.
    pub fn slice_mut(&mut self, idx: usize) -> &mut [u8] {
        // SAFETY: base_ptr has write provenance, idx < size (from alloc),
        // &mut self ensures no other references exist.
        unsafe { std::slice::from_raw_parts_mut(self.base_ptr.add(idx * BUF_SIZE), BUF_SIZE) }
    }

    /// Get the raw pointer for SQE construction.
    ///
    /// The returned pointer is valid for BUF_SIZE bytes and remains stable
    /// (pinned) for the lifetime of the pool.
    pub fn ptr(&self, idx: usize) -> *mut u8 {
        // No unsafe needed — just pointer arithmetic on a stored raw pointer.
        // base_ptr was derived from &mut access and has write provenance.
        unsafe { self.base_ptr.add(idx * BUF_SIZE) }
    }

    /// Number of free buffers available.
    pub fn available(&self) -> usize {
        self.free.len()
    }

    /// Register all pool buffers with io_uring for zero-copy I/O.
    ///
    /// After registration, use `ReadFixed`/`WriteFixed` opcodes with
    /// the buffer pool index as the `buf_index` parameter.
    pub fn register(&self, ring: &IoUring) -> Result<()> {
        let iovecs: Vec<libc::iovec> = (0..self.size)
            .map(|i| libc::iovec {
                iov_base: self.ptr(i) as *mut libc::c_void,
                iov_len: BUF_SIZE,
            })
            .collect();
        // SAFETY: iovecs point to valid, pinned memory that outlives the registration.
        unsafe { ring.submitter().register_buffers(&iovecs) }
            .context("failed to register buffers with io_uring")?;
        Ok(())
    }
}

/// Buffer pool for multishot recv (kernel-managed via provided buffer groups).
///
/// Unlike `BufferPool`, this has no free list — the kernel selects buffers
/// from the provided group and returns the buffer ID in the CQE flags.
/// After consuming a buffer, userspace re-provides it via `ProvideBuffers` SQE.
///
/// # Safety model
///
/// Same as `BufferPool`: `base_ptr` is derived from `&mut` access before pinning,
/// Pin prevents moves, and buffers are only accessed after the kernel returns them
/// in a CQE (no concurrent access).
pub struct ProvidedPool {
    /// Keeps the heap allocation alive and pinned.
    _storage: Pin<Box<[u8]>>,
    /// Raw pointer to the base of the allocation, derived from `&mut` access.
    base_ptr: *mut u8,
    size: usize,
    group_id: u16,
}

// SAFETY: ProvidedPool is used single-threaded (one per engine thread).
// Same justification as BufferPool.
unsafe impl Send for ProvidedPool {}

impl ProvidedPool {
    pub fn new(pool_size: usize, group_id: u16) -> Self {
        let size = pool_size.min(MAX_POOL_SIZE);
        let mut storage = vec![0u8; BUF_SIZE * size].into_boxed_slice();
        let base_ptr = storage.as_mut_ptr();
        let storage = Pin::new(storage);
        Self {
            _storage: storage,
            base_ptr,
            size,
            group_id,
        }
    }

    /// Raw pointer to buffer `bid` for SQE construction.
    pub fn ptr(&self, bid: u16) -> *mut u8 {
        unsafe { self.base_ptr.add(bid as usize * BUF_SIZE) }
    }

    /// Read completed data at buffer `bid` with `len` bytes.
    ///
    /// # Safety invariant
    /// Caller must ensure the buffer was returned by the kernel (CQE reaped)
    /// and is not currently provided to the kernel.
    pub fn slice(&self, bid: u16, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base_ptr.add(bid as usize * BUF_SIZE), len) }
    }

    /// Number of buffers in the pool.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Buffer group ID for io_uring provided buffer operations.
    pub fn group_id(&self) -> u16 {
        self.group_id
    }
}
