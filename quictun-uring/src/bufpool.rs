use std::collections::VecDeque;
use std::pin::Pin;

use anyhow::{Context, Result};
use io_uring::IoUring;

/// Buffer size: must be > 1500 MTU to hold any TUN/UDP packet.
pub const BUF_SIZE: usize = 2048;

/// Number of buffers in the pool.
const POOL_SIZE: usize = 256;

// Operation type tags packed into the upper 4 bits of user_data.
pub const OP_TUN_READ: u64 = 0;
pub const OP_TUN_WRITE: u64 = 1;
pub const OP_UDP_RECV: u64 = 2;
pub const OP_UDP_SEND: u64 = 3;
pub const OP_TIMER: u64 = 4;
pub const OP_WAKE: u64 = 5;
pub const OP_SHUTDOWN: u64 = 6;

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

/// Pre-allocated slab of fixed-size buffers.
///
/// Pointers are stable (pinned) so io_uring can safely borrow them
/// between submit and completion.
pub struct BufferPool {
    storage: Pin<Box<[u8]>>,
    free: VecDeque<usize>,
}

impl BufferPool {
    pub fn new() -> Self {
        let storage = vec![0u8; BUF_SIZE * POOL_SIZE].into_boxed_slice();
        let storage = Pin::new(storage);
        let free: VecDeque<usize> = (0..POOL_SIZE).collect();
        Self { storage, free }
    }

    /// Allocate a buffer, returning its index. Returns `None` if exhausted.
    pub fn alloc(&mut self) -> Option<usize> {
        self.free.pop_front()
    }

    /// Return a buffer to the free list.
    pub fn free(&mut self, idx: usize) {
        debug_assert!(idx < POOL_SIZE);
        self.free.push_back(idx);
    }

    /// Get a read-only slice of completed data at `idx` with `len` bytes.
    pub fn slice(&self, idx: usize, len: usize) -> &[u8] {
        let start = idx * BUF_SIZE;
        &self.storage[start..start + len]
    }

    /// Get the raw pointer for SQE construction.
    pub fn ptr(&self, idx: usize) -> *mut u8 {
        let start = idx * BUF_SIZE;
        // SAFETY: storage is pinned and the pointer is stable for the lifetime of the pool.
        // io_uring writes into this buffer between submit and completion.
        unsafe { (self.storage.as_ptr() as *mut u8).add(start) }
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
        let iovecs: Vec<libc::iovec> = (0..POOL_SIZE)
            .map(|i| libc::iovec {
                iov_base: self.ptr(i) as *mut libc::c_void,
                iov_len: BUF_SIZE,
            })
            .collect();
        unsafe { ring.submitter().register_buffers(&iovecs) }
            .context("failed to register buffers with io_uring")?;
        Ok(())
    }
}
