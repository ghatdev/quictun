# Bench-002: TUN Tier Throughput Optimizations

**Date:** 2026-02-24

**Author:** SeoulValley Engineering

**Commit:** `7d3c83b` (M4: multi-queue TUN workers)

**Baseline:** bench-001 best = 1.21 Gbits/sec (parallel + BBR + 8MB buffers)

---

## Objective

Measure the throughput impact of four incremental TUN-tier optimizations aimed at closing the gap between quictun (1.21 Gbits/sec) and kernel WireGuard (1.72 Gbits/sec).

## Environment

| Component | Specification |
|-----------|--------------|
| Host | Proxmox VE, single physical host |
| VM1 (listener) | 10.23.30.10, Ubuntu 6.8.0-87-generic x86_64, 4 vCPUs |
| VM2 (connector) | 10.23.30.11, Ubuntu 6.8.0-87-generic x86_64, 4 vCPUs |
| NIC | virtio (paravirtualized) |
| Bridge | vmbr0 (in-host virtual bridge) |
| Tunnel addresses | 10.0.0.1/24 (vm1), 10.0.0.2/24 (vm2) |
| TUN MTU | 1380 bytes |
| QUIC max_datagram_size | 1414 bytes (observed) |

### Optimizations Tested

| Milestone | Description |
|-----------|-------------|
| M1 | Fast defaults: parallel + BBR + 8MB buffers as default |
| M2 | Drain loop: batch TUN reads per `readable()` notification |
| M3a | mimalloc global allocator |
| M3b | Zero-copy TUN→QUIC: `Bytes::from(vec)` instead of `copy_from_slice` |
| M4 | Multi-queue TUN: `IFF_MULTI_QUEUE` with N drain workers |

All milestones are cumulative — each build includes all prior optimizations.

## Results

### Single-Stream (`iperf3 -c 10.0.0.1 -t 10`)

Default config (parallel + BBR + 8MB, queues=1):

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1 | 1.25 Gbits/sec | 2,435 |
| 2 | 1.29 Gbits/sec | 1,485 |
| 3 | 1.31 Gbits/sec | 2,333 |
| **Average** | **1.28 Gbits/sec** | **2,084** |

With `--queues 4` (multi-queue, single-stream):

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1 | 1.32 Gbits/sec | 798 |

Single-stream hashes all packets to one TUN queue, so multi-queue is not expected to help throughput. The lower retransmit count (798 vs 2,084 avg) may be noise or a side-effect of the kernel's queue scheduling.

### Multi-Stream (`iperf3 -c 10.0.0.1 -t 10 -P 4`)

Single-queue (queues=1), 4 iperf3 streams:

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1 | 1.28 Gbits/sec | 5,036 |

Multi-queue (queues=4), 4 iperf3 streams:

| Run | Throughput | Retransmits |
|-----|-----------|-------------|
| 1 | 1.35 Gbits/sec | 5,162 |
| 2 | 1.35 Gbits/sec | 7,677 |
| **Average** | **1.35 Gbits/sec** | **6,420** |

## Summary Table

| Config | Single-stream | Multi-stream (-P 4) |
|--------|--------------|---------------------|
| bench-001 best (baseline) | 1.21 Gbits/sec | — |
| M1–M3 (queues=1) | **1.28 Gbits/sec** (+6%) | 1.28 Gbits/sec |
| M1–M4 (queues=4) | 1.32 Gbits/sec | **1.35 Gbits/sec** (+12%) |
| kernel WireGuard | 1.72 Gbits/sec | — |

## Analysis

### Drain loop + zero-copy provides a modest single-stream gain

The drain loop (M2) and zero-copy path (M3) together improved single-stream throughput from 1.21 to 1.28 Gbits/sec (+6%). This is at the lower end of the projected +13-23% (M2: +10-15%, M3: +3-8%).

The likely reason is that the bottleneck has shifted from per-packet overhead to the QUIC layer itself. With ~93K packets/sec at 1.28 Gbps (1380-byte packets), the drain loop amortizes syscall overhead but the QUIC connection's single congestion controller becomes the limiting factor.

### Multi-queue provides a small multi-stream improvement

Multi-queue (4 queues, 4 streams) improved aggregate throughput from 1.28 to 1.35 Gbits/sec (+5%). This is well below the projected +20-40%.

The disappointing multi-queue result has a clear explanation: **all 4 iperf3 streams share one QUIC connection**. Unlike kernel WireGuard where each inner TCP flow is independently encapsulated, quictun multiplexes all flows through a single QUIC connection with a single congestion controller. The TUN multi-queue distributes packet reads across cores, but the QUIC send path re-serializes them through one congestion window.

### Retransmit patterns

| Config | Retransmits (single) | Retransmits (multi) |
|--------|---------------------|---------------------|
| bench-001 best | 357 | — |
| M1-M3 (queues=1) | 2,084 (avg) | 5,036 |
| M1-M4 (queues=4) | 798 | 6,420 (avg) |

Retransmits increased compared to bench-001 (357), likely because the drain loop pushes packets into QUIC more aggressively, temporarily exceeding the congestion window. This is a trade-off: higher throughput at the cost of more retransmits.

### Current gap to kernel WireGuard

| Metric | quictun (best) | kernel WG | Gap |
|--------|---------------|-----------|-----|
| Single-stream | 1.28 Gbits/sec | 1.72 Gbits/sec | 26% |
| Previous gap | 1.21 Gbits/sec | 1.72 Gbits/sec | 30% |

The gap narrowed from 30% to 26%. The remaining overhead is dominated by:
1. **QUIC encryption + framing** — TLS 1.3 encryption per datagram, QUIC headers
2. **Userspace↔kernel transitions** — read/write syscalls on the TUN fd
3. **Single congestion controller** — one QUIC connection rate-limits all flows

## Conclusions

1. **M1 (fast defaults)**: Pure usability improvement, no perf change as expected.
2. **M2 (drain loop)**: Measurable improvement, reduces per-packet async overhead.
3. **M3 (mimalloc + zero-copy)**: Combined with M2, provides +6% single-stream.
4. **M4 (multi-queue)**: Adds +5% for multi-stream workloads, but limited by single QUIC connection bottleneck.

The TUN-tier userspace optimizations are reaching diminishing returns. Further gains require either:
- **Kernel bypass** (XDP/DPDK) to eliminate syscall overhead entirely
- **Multiple QUIC connections** per tunnel to enable per-flow congestion control
- **GSO/GRO** integration to batch packets at the UDP layer

## Reproduction

```bash
# VM1 (listener):
sudo quictun up tunnel.toml                   # defaults: parallel, BBR, 8MB
sudo quictun up tunnel.toml --queues 4        # multi-queue

# VM2 (connector):
sudo quictun up tunnel.toml                   # same flags as VM1
sudo quictun up tunnel.toml --queues 4

# Benchmarks (from VM2):
iperf3 -c 10.0.0.1 -t 10                     # single-stream
iperf3 -c 10.0.0.1 -t 10 -P 4               # multi-stream
```
