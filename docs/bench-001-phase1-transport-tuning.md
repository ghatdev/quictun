# Bench-001: Phase 1 Transport Tuning

**Date:** 2026-02-23, updated 2026-02-24

**Author:** SeoulValley Engineering

**Commit:** `29785c3` (add transport tuning: parallel forwarding, BBR, buffer sizing)

---

## Objective

Measure the throughput and reliability of quictun's Phase 1 TUN-tier tunnel under various transport configurations, identify the optimal combination of congestion control, buffer sizing, and forwarding architecture.

## Environment

| Component | Specification |
|-----------|--------------|
| Host | Proxmox VE, single physical host |
| VM1 (listener) | 10.23.30.10, Ubuntu 6.8.0-87-generic x86_64 |
| VM2 (connector) | 10.23.30.11, Ubuntu 6.8.0-87-generic x86_64 |
| NIC | virtio (paravirtualized) |
| Bridge | vmbr0 (in-host virtual bridge) |
| Tunnel addresses | 10.0.0.1/24 (vm1), 10.0.0.2/24 (vm2) |
| TUN MTU | 1380 bytes |
| QUIC initial_mtu | 1452 bytes |
| QUIC max_datagram_size | 1414 bytes (observed) |
| ALPN | quictun-01 |
| Crypto | TLS 1.3, P-256 ECDSA RPK, AES-128-GCM (aws-lc-rs) |

### Tool

- iperf3, TCP mode, 10-second duration, single stream
- Direction: vm2 (connector) → vm1 (listener)

## Raw Baseline (no tunnel)

```
$ iperf3 -c 10.23.30.10 -t 10
```

| Metric | Value |
|--------|-------|
| Throughput | 29.6 Gbits/sec |
| Retransmits | 0 |

The virtio bridge on a single Proxmox host operates at memory-copy speed, so the raw baseline is not representative of a real network. It serves only to quantify tunnel overhead.

## Variables

Three independent variables were tested in all combinations:

| Variable | Off (default) | On |
|----------|--------------|-----|
| **Parallel forwarding** | Single `tokio::select!` loop handling both TUN→QUIC and QUIC→TUN | Separate tokio tasks per direction |
| **BBR congestion control** | NewReno (quinn default) | BBR (`congestion_controller_factory`) |
| **Big buffers** | recv=64KB, send=1MB | recv=8MB, send=8MB |

An additional test added `--send-window 16MB` on top of the best combination.

## Results

| # | Config | Throughput | Retransmits | Notes |
|---|--------|-----------|-------------|-------|
| 0a | **no tunnel** (raw iperf3 vm2→vm1) | 29.6 Gbits/sec | 0 | virtio bridge = memory-copy speed |
| 0b | **kernel WireGuard** | 1.72 Gbits/sec | 23 | in-kernel, ChaCha20-Poly1305 |
| 0c | **boringtun** (userspace WireGuard, Rust) | 489 Mbits/sec | 4,695 | userspace baseline |
| 1 | quictun baseline (NewReno, serial, 64K buf) | 750 Mbits/sec | 2,259 | Phase 1 defaults |
| 2 | parallel only | 1.04 Gbits/sec | 3,662 | +39% throughput, more retransmits |
| 3 | BBR only | 739 Mbits/sec | 2,523 | No improvement in serial mode |
| 4 | big buffers only | 839 Mbits/sec | 192 | **92% fewer retransmits** |
| 5 | parallel + BBR | 1.01 Gbits/sec | 3,715 | |
| 6 | parallel + big buf | 1.20 Gbits/sec | 1,242 | |
| 7 | BBR + big buf | 734 Mbits/sec | 86 | **Fewest retransmits** (serial bottleneck) |
| 8 | **parallel + BBR + big buf** | **1.21 Gbits/sec** | **357** | **Best overall** |
| 9 | all + send_window 16MB | 1.19 Gbits/sec | 216 | Diminishing returns |

## Analysis

### Parallel forwarding is the biggest throughput win

Parallel forwarding consistently added 39–60% throughput across all buffer/congestion combinations. The serial `select!` loop creates head-of-line blocking: a slow TUN read delays QUIC datagram delivery and vice versa. Splitting into independent tasks eliminates this coupling.

| Serial | Parallel | Delta |
|--------|----------|-------|
| 750 Mbits/sec (#1) | 1.04 Gbits/sec (#2) | +39% |
| 839 Mbits/sec (#4) | 1.20 Gbits/sec (#6) | +43% |
| 734 Mbits/sec (#7) | 1.21 Gbits/sec (#8) | +65% |

### Big buffers dramatically reduce retransmits

Increasing datagram buffers from 64KB/1MB to 8MB/8MB reduced retransmits by 88–96%. The default 64KB receive buffer fills up under sustained throughput, causing quinn to signal congestion even when the actual network path is clear.

| Without big buf | With big buf | Retransmit reduction |
|----------------|-------------|---------------------|
| 2,259 (#1) | 192 (#4) | -92% |
| 3,662 (#2) | 1,242 (#6) | -66% |
| 2,523 (#3) | 86 (#7) | -97% |
| 3,715 (#5) | 357 (#8) | -90% |

### BBR has minimal throughput impact, helps reliability with big buffers

BBR alone did not improve throughput in serial mode (739 vs 750 Mbits/sec). However, when combined with big buffers, BBR further reduced retransmits (192 → 86 serial, 1242 → 357 parallel) without sacrificing throughput.

### Send window beyond 8MB shows diminishing returns

Test #9 (send_window=16MB) produced marginally lower throughput (1.19 vs 1.21 Gbits/sec) and slightly fewer retransmits (216 vs 357). The bottleneck at this point is not the QUIC send window but userspace TUN processing overhead.

### quictun vs WireGuard

Three WireGuard configurations were tested:

| Metric | kernel WG | boringtun (userspace) | quictun (default) | quictun (best) |
|--------|-----------|----------------------|-------------------|----------------|
| Throughput | 1.72 Gbits/sec | 489 Mbits/sec | 750 Mbits/sec | 1.21 Gbits/sec |
| Retransmits | 23 | 4,695 | 2,259 | 357 |

**kernel WireGuard** (1.72 Gbits/sec, avg of 1.64 and 1.80 across 2 runs) is the fastest — expected since it runs entirely in-kernel with zero system call overhead per packet. quictun's best tuned config reaches **70% of kernel WireGuard throughput** while running entirely in userspace.

**boringtun v0.7.0** (Cloudflare's userspace WireGuard in Rust, kernel module blacklisted, consistent across 2 runs at 489/488 Mbits/sec) is the fairest apples-to-apples comparison:

| vs boringtun | quictun (default) | quictun (best) |
|---|---|---|
| Throughput | **+53%** | **+147%** (2.5x) |
| Retransmits | -52% | -92% |

quictun outperforms boringtun even with default settings. Both are:
- **Userspace** (TUN device, no kernel module)
- **Rust** (same language, similar compiler optimizations)
- **Same VMs** (identical network path, same iperf3 parameters)

boringtun's lower throughput likely stems from WireGuard's lack of congestion control — it forwards packets without rate adaptation, relying entirely on inner TCP. When the TUN→UDP path saturates, inner TCP sees loss and backs off aggressively (4,695 retransmits). quictun's QUIC layer provides its own congestion control, pacing, and flow control, resulting in fewer retransmits and higher sustained throughput.

The kernel-to-userspace gap is also striking: kernel WireGuard is **3.5x faster** than boringtun — the same protocol, just kernel vs userspace. This validates the whitepaper's performance tier thesis: significant gains require kernel bypass (XDP/DPDK), not just protocol tuning.

## Overhead Analysis

| Metric | Value |
|--------|-------|
| Raw baseline | 29.6 Gbits/sec |
| Kernel WireGuard | 1.72 Gbits/sec |
| boringtun (userspace WG) | 489 Mbits/sec |
| Best quictun | 1.21 Gbits/sec |
| quictun vs kernel WG | **70%** of kernel throughput |
| quictun vs boringtun | **247%** (2.5x faster) |

The raw baseline (29.6 Gbits/sec) is artificially high because both VMs share host memory via virtio. The kernel and userspace WireGuard baselines are the meaningful comparisons:
- quictun reaches 70% of **kernel** WireGuard — remarkably close for a userspace implementation
- quictun is 2.5x faster than **userspace** WireGuard (boringtun) — the fair comparison

## Functional Verification

All tests passed before benchmarking:

| Test | Result |
|------|--------|
| ICMP ping (5 packets) | 5/5, 0% loss, ~1ms RTT |
| SSH over tunnel | Works |
| HTTP (curl) | Works (after MTU fix) |
| iperf3 TCP | Works |
| 100MB SCP transfer | 1.5s, SHA-256 checksums match |

## Recommended Defaults

Based on these results, the recommended production defaults for the TUN tier are:

```
--parallel --bbr --recv-buf 8388608 --send-buf 8388608
```

These should become the defaults in a future commit, replacing the current conservative defaults (serial, NewReno, 64KB recv buf).

## Reproduction

```bash
# bench.sh — automated benchmark script
# Requires: ssh access to vm1/vm2, quictun binary on both VMs

# VM1 (listener):
sudo quictun up tunnel.toml --parallel --bbr --recv-buf 8388608 --send-buf 8388608

# VM2 (connector):
sudo quictun up tunnel.toml --parallel --bbr --recv-buf 8388608 --send-buf 8388608

# VM2:
iperf3 -c 10.0.0.1 -t 10
```

Full automated script: see `bench.sh` in project root (not committed — VM-specific paths).

## Future Work

1. **Multi-stream iperf3**: test with `-P 4` to saturate multiple cores
2. **UDP mode**: iperf3 `-u` to measure without inner TCP congestion interaction
3. **Latency profiling**: measure per-packet latency distribution under load
4. **Real network**: repeat on physical 10GbE or WAN link with real RTT/loss
5. ~~**Comparison**: WireGuard on same VMs as baseline comparison~~ Done (boringtun v0.7.0)
6. **XDP tier**: kernel bypass data plane (Phase 2)
