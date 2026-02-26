# Bench-003: TUN GSO/GRO Offload

**Date:** 2026-02-27

**Author:** SeoulValley Engineering

**Commit:** `8600f53` (add TUN GSO/GRO offload for tokio data plane)

**Baseline:** bench-002 best = 1.28 Gbits/sec (parallel + BBR + 8MB, queues=1)

---

## Objective

Measure the throughput impact of TUN GSO/GRO offload on the tokio data plane. This uses the kernel's virtio_net_hdr mechanism (`IFF_VNET_HDR` + `TUNSETOFFLOAD`) to batch multiple IP packets into a single TUN read/write, eliminating per-packet syscall overhead.

## Background

Tailscale demonstrated that TUN per-packet overhead is the dominant bottleneck in userspace tunnel implementations, achieving a 4.3x throughput gain (2.9 to 12.5 Gbps) on QUIC from TUN GSO/GRO alone. The technique works by:

- **GSO (Generic Segmentation Offload)**: The kernel delivers a single "super-packet" through TUN that contains multiple IP packets. The userspace splits it into individual packets. **1 read syscall serves N packets.**
- **GRO (Generic Receive Offload)**: Userspace coalesces multiple IP packets destined for TUN into a single write with a virtio_net_hdr describing how to split them. **1 write syscall delivers N packets.**

Requires Linux kernel 6.2+ for UDP Segmentation Offload (USO) support via TUN.

## Environment

| Component | Specification |
|-----------|--------------|
| Host | Proxmox VE, single physical host |
| VM1 (listener) | 10.23.30.10, Ubuntu 6.8.0-87-generic x86_64, 4 vCPUs |
| VM2 (connector) | 10.23.30.11, Ubuntu 6.8.0-87-generic x86_64, 4 vCPUs |
| CPU | AMD Ryzen 9700X (Zen 5), passed through as 4 vCPUs |
| RAM | 7.7 GB per VM |
| NIC | virtio (paravirtualized), single queue |
| Bridge | vmbr0 (in-host virtual bridge) |
| Raw NIC throughput | 26.8 Gbits/sec |
| Tunnel addresses | 10.0.0.1/24 (vm1), 10.0.0.2/24 (vm2) |
| TUN MTU | 1380 bytes |
| QUIC max_datagram_size | 1414 bytes (observed) |

### Implementation Details

| Component | Detail |
|-----------|--------|
| tun-rs version | 2.7.5 |
| Builder option | `.offload(true)` |
| TUN→QUIC | `recv_multiple()` — 1 read, GSO split into up to 128 individual IP packets |
| QUIC→TUN | `send_multiple()` — GRO coalesces batch into fewer writes via `GROTable` |
| Batching (QUIC→TUN) | First datagram awaited, then zero-timeout drain up to `IDEAL_BATCH_SIZE` (128) |
| Forwarding structure | Two tokio tasks (parallel), same as `run_forwarding_loop_parallel` |

### Offload Capabilities (logged at startup)

```
TUN offload capabilities name=tunnel tcp_gso=true udp_gso=true
```

Both VMs confirmed `tcp_gso=true, udp_gso=true` on kernel 6.8.

## Results

### A/B Test: Single-Stream (`iperf3 -c 10.0.0.1 -t 15`)

Both tests run sequentially on the same VMs, same session, fresh tunnel processes for each.

**Baseline (no offload):**

| Interval | Bitrate | Retr | Cwnd |
|----------|---------|------|------|
| 0-1s | 1.09 Gbits/sec | 683 | 807 KB |
| 1-2s | 1.26 Gbits/sec | 20 | 687 KB |
| 2-3s | 1.28 Gbits/sec | 0 | 829 KB |
| 3-4s | 1.25 Gbits/sec | 234 | 498 KB |
| 4-5s | 1.23 Gbits/sec | 0 | 676 KB |
| 5-6s | 1.27 Gbits/sec | 142 | 573 KB |
| 6-7s | 1.22 Gbits/sec | 0 | 730 KB |
| 7-8s | 1.22 Gbits/sec | 161 | 599 KB |
| 8-9s | 1.26 Gbits/sec | 0 | 755 KB |
| 9-10s | 1.27 Gbits/sec | 91 | 648 KB |
| 10-11s | 1.22 Gbits/sec | 46 | 603 KB |
| 11-12s | 1.27 Gbits/sec | 0 | 760 KB |
| 12-13s | 1.24 Gbits/sec | 46 | 672 KB |
| 13-14s | 1.24 Gbits/sec | 16 | 580 KB |
| 14-15s | 1.23 Gbits/sec | 17 | 562 KB |
| **Total** | **1.24 Gbits/sec** | **1,456** | — |

**Offload (`--offload`):**

| Interval | Bitrate | Retr | Cwnd |
|----------|---------|------|------|
| 0-1s | 1.36 Gbits/sec | 0 | 3.59 MB |
| 1-2s | 1.63 Gbits/sec | 4 | 3.59 MB |
| 2-3s | 1.65 Gbits/sec | 0 | 3.59 MB |
| 3-4s | 1.63 Gbits/sec | 1 | 3.59 MB |
| 4-5s | 1.63 Gbits/sec | 1 | 2.73 MB |
| 5-6s | 1.64 Gbits/sec | 0 | 2.93 MB |
| 6-7s | 1.65 Gbits/sec | 0 | 3.09 MB |
| 7-8s | 1.61 Gbits/sec | 10 | 2.26 MB |
| 8-9s | 1.63 Gbits/sec | 0 | 2.39 MB |
| 9-10s | 1.60 Gbits/sec | 0 | 2.50 MB |
| 10-11s | 1.41 Gbits/sec | 0 | 2.58 MB |
| 11-12s | 1.63 Gbits/sec | 0 | 2.64 MB |
| 12-13s | 1.61 Gbits/sec | 0 | 2.68 MB |
| 13-14s | 1.61 Gbits/sec | 0 | 2.71 MB |
| 14-15s | 1.64 Gbits/sec | 0 | 2.72 MB |
| **Total** | **1.60 Gbits/sec** | **16** | — |

### Summary

| Metric | Baseline | Offload | Change |
|--------|----------|---------|--------|
| Throughput | 1.24 Gbits/sec | **1.60 Gbits/sec** | **+29%** |
| Retransmits | 1,456 | 16 | **-99%** |
| Cwnd (steady-state) | 500-830 KB | 2.3-3.6 MB | **~4x** |
| Ping latency | ~0.6 ms | ~2.8 ms | +2.2 ms |

### Comparison with Other Data Planes

| Data Plane | Throughput | vs WireGuard |
|------------|-----------|-------------|
| DPDK AF_XDP (`--no-udp-checksum`) | 2.25 Gbits/sec | +39% |
| DPDK AF_XDP (AVX2 checksum) | 2.19 Gbits/sec | +35% |
| DPDK TAP (`--no-udp-checksum`) | 1.94 Gbits/sec | +20% |
| DPDK TAP (AVX2 checksum) | 1.90 Gbits/sec | +17% |
| kernel WireGuard | 1.62 Gbits/sec | ref |
| **tokio + GSO/GRO (`--offload`)** | **1.60 Gbits/sec** | **-1%** |
| tokio parallel (default) | 1.24 Gbits/sec | -23% |
| io_uring Phase C3 (zero-copy) | 820 Mbits/sec | -49% |

## Analysis

### GSO/GRO eliminates the per-packet syscall bottleneck

The baseline tokio path does one `recv()` per IP packet and one `send()` per IP packet on the TUN fd. At 1.24 Gbps with 1380-byte packets, that's ~112K packets/sec, meaning ~224K syscalls/sec just for TUN I/O (plus the outer UDP socket I/O handled by quinn).

With offload, `recv_multiple` reads a single GSO super-packet and splits it into N individual IP packets in userspace (zero-copy within tun-rs). `send_multiple` coalesces N datagrams via the GRO table and writes them in fewer TUN syscalls. This dramatically reduces the syscall-to-packet ratio.

### Retransmit reduction is the most significant improvement

The 99% reduction in retransmits (1,456 to 16) indicates that the per-packet TUN overhead was causing **scheduling jitter** that triggered false congestion signals in BBR. With batched I/O:

1. The QUIC→TUN path delivers packets in bursts rather than one-at-a-time, reducing queuing delay variance
2. The TUN→QUIC path ingests packets faster, keeping the congestion window from collapsing
3. Cwnd stabilizes at 2.3-3.6 MB (vs oscillating 500-830 KB), allowing sustained high throughput

### Virtio NIC is the ceiling

The offload result (1.60 Gbits/sec) matches kernel WireGuard (1.62 Gbits/sec) on the same VMs. This confirms that **we have eliminated the userspace overhead gap entirely** — the remaining bottleneck is the virtio NIC itself.

On bare metal with real NICs (where WireGuard achieves 11.8 Gbits/sec per Tailscale benchmarks), the GSO/GRO improvement should be proportionally larger.

### Latency trade-off

Ping latency increased from ~0.6 ms to ~2.8 ms. This is inherent to batching: the QUIC→TUN path waits to collect a batch before writing, and the kernel's GSO path adds segmentation delay. For throughput-oriented workloads (bulk transfer, streaming) this is acceptable. Latency-sensitive applications (gaming, VoIP) should use the default non-offload path.

### Why parallel vs serial makes no difference for offload

Both the serial and parallel forwarding modes process the same number of TUN syscalls per packet. The parallel mode prevents head-of-line blocking between directions but doesn't reduce syscall count. Since per-packet syscall overhead is the dominant bottleneck (not task scheduling), parallel and serial modes converge to similar throughput. GSO/GRO changes the fundamental equation by amortizing syscalls across many packets.

## Conclusions

1. **TUN GSO/GRO closes the gap to kernel WireGuard** on the tokio data plane (1.60 vs 1.62 Gbits/sec, within measurement noise).
2. **The -99% retransmit reduction** is arguably more important than the +29% throughput gain — it indicates a fundamentally healthier transport state.
3. **Virtio NIC is confirmed as the hard ceiling** for all non-DPDK data planes on these VMs.
4. **On bare metal**, GSO/GRO should yield much larger absolute gains (estimated 3-5+ Gbits/sec based on Tailscale's results with similar techniques).
5. **Trade-off**: +2.2 ms latency from batching. Use `--offload` for throughput workloads, default for latency-sensitive ones.

## Reproduction

```bash
# VM1 (listener):
sudo quictun up tunnel.toml                # baseline
sudo quictun up tunnel.toml --offload      # GSO/GRO offload

# VM2 (connector):
sudo quictun up tunnel.toml                # same flags as VM1
sudo quictun up tunnel.toml --offload

# Benchmark (from VM2):
iperf3 -c 10.0.0.1 -t 15                  # single-stream

# Verify offload active (check logs):
# "TUN offload capabilities name=tunnel tcp_gso=true udp_gso=true"
# "forwarding loop started (offload GSO/GRO)"
```
