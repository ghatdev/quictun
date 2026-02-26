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

// RSS (Receive Side Scaling) constants — #define macros not captured by bindgen.

/// Enable RSS multi-queue RX mode.
pub const RTE_ETH_MQ_RX_RSS: u32 = 1;

/// RSS hash function: hash on IPv4 src/dst addresses.
pub const RTE_ETH_RSS_IP: u64 = 0x1 | 0x2; // IPV4 | FRAG_IPV4

/// RSS hash function: hash on UDP src/dst ports (IPv4).
pub const RTE_ETH_RSS_UDP: u64 = 0x40; // UDP IPv4
