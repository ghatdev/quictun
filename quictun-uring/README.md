# quictun-uring

> **Experimental** — This crate is a research/performance exploration track. The production data plane is the tokio-based path in `quictun-core`.

Linux io_uring data plane for QuicTun. Drives `quinn-proto` directly from a single-threaded io_uring event loop, bypassing the tokio runtime entirely.

## Features

- **Batched CQE processing** — All events (UDP recv, timer, wake) handled before a single `process_events()` + `drain_transmits()`, coalescing ACKs
- **RecvMulti + provided buffers** — One persistent multishot recv SQE per engine; kernel picks buffers autonomously
- **SendZc zero-copy UDP sends** — `--zero-copy` flag skips kernel-side memcpy (+27% vs WriteFixed)
- **Multi-core** — `--iouring-cores N` runs N independent engine threads with CPU pinning
- **Back-pressure** — Pool-aware drain prevents congestion collapse under high load

## Benchmark Summary

| Configuration | Throughput | Notes |
|---------------|-----------|-------|
| SendZc 1-core | 820 Mbps | `--zero-copy` |
| RecvMulti 4-core | 649–1.32 Gbps | Hash distribution dependent |
| Batched pipeline 1-core | 813 Mbps | Phase 5 baseline |
| tokio parallel (production) | **1.32 Gbps** | `quictun-core` default |
| kernel WireGuard | 1.72 Gbps | Reference |

## Usage

```
quictun up tunnel.toml --iouring [--iouring-cores N] [--pool-size N] [--zero-copy]
```

Requires Linux 6.0+ with io_uring support.
