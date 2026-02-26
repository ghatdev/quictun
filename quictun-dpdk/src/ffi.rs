#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/dpdk_bindings.rs"));

// Constants that bindgen can't extract from #define macros.

/// Default mbuf data room size (RTE_MBUF_DEFAULT_DATAROOM).
pub const RTE_MBUF_DEFAULT_DATAROOM: u16 = 2048;

/// Default headroom reserved at the start of each mbuf (RTE_PKTMBUF_HEADROOM).
pub const RTE_PKTMBUF_HEADROOM: u16 = 128;

/// Default mbuf buffer size: dataroom + headroom.
pub const RTE_MBUF_DEFAULT_BUF_SIZE: u16 = RTE_MBUF_DEFAULT_DATAROOM + RTE_PKTMBUF_HEADROOM;

/// Number of mbufs in the default mempool.
pub const DEFAULT_NUM_MBUFS: u32 = 8191;

/// Per-core mempool cache size.
pub const MEMPOOL_CACHE_SIZE: u32 = 256;
