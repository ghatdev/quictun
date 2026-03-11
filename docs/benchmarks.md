# quictun Benchmarks

**Date:** March 2026

**Author:** SeoulValley Engineering

---

## Environment

- **Host:** AMD Ryzen 9700X (Zen 5), Proxmox KVM
- **vm1 (listener):** 4 vCPUs, 7.7GB RAM, virtio NIC, AVX-512
- **vm2 (connector):** 2 vCPUs, 7.7GB RAM, virtio NIC, AVX-512
- **OS:** Ubuntu 6.8.0-87-generic x86_64
- **NIC:** ens19 (secondary), same Proxmox bridge
- **Tool:** iperf3 TCP, 10s duration
- **Cipher:** AES-128-GCM (hardware accelerated via AVX-512)
- **Raw baseline:** 26.8 Gbps (no tunnel, virtual bridge)
- **VM variance:** ~7-10% run-to-run. Numbers are median of 2-3 runs.

---

## Throughput

### DPDK Engine (quictun-dpdk)

| Config | Throughput | Direction | Notes |
|--------|-----------|-----------|-------|
| **single-core optimized** | **16.0 Gbps** | reverse (-R) | Zero-copy encrypt + decrypt, 10.5x kernel WG |
| **single-core optimized** | **13.4 Gbps** | forward | vm2 connector-limited (2 vCPUs) |
| single-core default | 8.1 Gbps | forward | split vq, no zero-copy |
| kernel ← DPDK connector (-R) | 10.8 Gbps | reverse | DPDK as receiver, kernel connector |
| kernel → DPDK listener | 7.67 Gbps | forward | kernel connector bottleneck |
| TAP PMD | 3.98 Gbps | forward | IPI bottleneck (14% CPU) |

DPDK benchmarks use DPDK engines on both VMs (statically linked binary).

### Kernel Engine (quictun-net)

| Config | Throughput | Retrans | Notes |
|--------|-----------|---------|-------|
| **pipeline + GRO (2 threads)** | **10.7 Gbps** | 41-474 | GRO 27:1 coalescing |
| single-thread + GRO | 10.2 Gbps | ~0 | GRO only |
| pipeline, no GRO (2 threads) | 6.50 Gbps | 2-12 | epoll skip + slab batches |
| single-thread, no GRO | 3.17 Gbps | ~0 | per-packet TUN writes |

Pipeline adds ~5% over single-thread with GRO — within VM variance. AES-128-GCM on
AVX-512 is ~1 us/pkt; crypto is only ~4% of CPU. The pipeline offloads crypto to a
worker thread, but there's barely any work to offload.

### DPDK Router

| Config | Throughput | Notes |
|--------|-----------|-------|
| single-core NAT | 6.95 Gbps | via vm3 |
| single-core NAT (-R) | 3.47 Gbps | reverse direction |
| multi-core pipeline (2 cores) | 10.6 Gbps | ring overhead ~3% |

### Competitors

| Config | Throughput | Notes |
|--------|-----------|-------|
| **wireguard-go (tailscale)** | **7.37 Gbps** | Go 1.26.1, 4 vCPUs |
| wireguard-go 1 core | 5.74 Gbps | GOMAXPROCS=1 |
| wireguard-go 2 cores | 7.08 Gbps | GOMAXPROCS=2 |
| kernel WireGuard | 1.53 Gbps | ens19 |

---

## Latency

Measured with `ping -i 0.1` through tunnel. Raw VM-to-VM latency: 0.39 ms avg.

### Idle

| Config | Avg | Min | Max | Mdev |
|--------|-----|-----|-----|------|
| Raw (no tunnel) | 0.39 ms | 0.11 ms | 0.62 ms | 0.14 ms |
| quictun pipeline + GRO | 0.75 ms | 0.32 ms | 1.24 ms | 0.25 ms |
| Tailscale wireguard-go | 1.17 ms | 0.79 ms | 1.30 ms | 0.12 ms |

### Under iperf3 Load (~10 Gbps)

| Config | Avg | Min | Max | Mdev | Loss |
|--------|-----|-----|-----|------|------|
| **quictun pipeline + GRO** | **2.32 ms** | 1.18 ms | 3.87 ms | 0.52 ms | 0% |
| quictun single + GRO | 2.24 ms | 0.75 ms | 3.68 ms | 0.64 ms | 0% |
| quictun single, no GRO | 4.05 ms | 1.02 ms | 7.26 ms | 1.75 ms | 2% |
| **Tailscale wireguard-go** | **3.51 ms** | 1.11 ms | 6.02 ms | 1.00 ms | 0% |

### Spike Analysis

Occasional spikes to 5-7 ms are caused by **VM hypervisor scheduling**, not our code:

- bpftrace shows 69 events in 10 s where the I/O thread is off-CPU for > 5 ms
- Single-thread and pipeline exhibit the same spike pattern
- On bare metal, these spikes would essentially disappear

GRO **helps** latency: reducing TUN syscalls from 500K to 30K/sec frees CPU headroom,
lowering average latency from 4.05 ms to 2.24 ms under load.

---

## DPDK Profiling

Profiled on vm1 single-core at 13 Gbps (forward direction):

| Component | CPU % | Notes |
|-----------|-------|-------|
| NIC rx_burst | ~50% | Polling outer port (DPDK poll mode) |
| Loop overhead | ~35% | Parse, lookup, mbuf ops, tx_burst |
| ~~Instant::now()~~ | ~~12%~~ | Fixed: rate-limited to every 32K iterations |
| Crypto (AES-GCM) | <0.5% | AVX-512, essentially free |

The bottleneck is the vhost kthread (~100% CPU) that copies packets between kernel
(TAP) and DPDK hugepage memory. This is inherent to virtio-user and is the
DPDK-recommended inner path (KNI was removed in DPDK 23.11).

---

## GRO: The Key Kernel Optimization

The single biggest throughput gain came from fixing GRO buffer capacity.

### Problem

`GroTxPool::push_datagram()` allocated buffers at exactly the packet size (~1390 bytes).
tun-rs GRO coalescing requires `buf_capacity() >= 2 * bufs_offset + coalesced_len` to
merge packets. With capacity ~1390 and a minimum of ~2728 needed for 2 packets, tun-rs
returned `InsufficientCap` for **every** packet — 1:1 coalescing ratio, zero benefit,
pure overhead.

### Fix (commit 1cc1b973)

Allocate buffers with `Vec::with_capacity(65536)`. tun-rs can now extend buffers during
coalescing.

### Result

| Metric | Before | After |
|--------|--------|-------|
| TUN writes/sec | ~500K | ~29K |
| Coalescing ratio | 1:1 | 27:1 |
| TUN write CPU | 52% | 2% |
| Throughput (pipeline) | 6.50 Gbps | **10.7 Gbps (+65%)** |
| Throughput (single) | 3.17 Gbps | **10.2 Gbps (+3.2x)** |

---

## Optimization History

### Kernel Engine

| Step | Change | Before | After | Delta |
|------|--------|--------|-------|-------|
| Baseline | pipeline, no GRO | — | 5.7 Gbps | — |
| Epoll skip | Busy-poll when in_flight > 0 | 5.66 Gbps | 6.50 Gbps | **+15%** |
| Slab batches | Contiguous slab vs Vec\<Vec\<u8\>\> | 6.50 Gbps | 6.47 Gbps | neutral |
| GRO fix | Vec::with_capacity(65536) | 6.50 Gbps | 10.7 Gbps | **+65%** |
| Engine cleanup | Remove container/per-core/pipeline v2 | 10.7 Gbps | 10.3 Gbps | same |

### DPDK Engine (single-core)

| Step | Change | Before | After | Delta |
|------|--------|--------|-------|-------|
| Baseline | virtio-user, packed vq, AVX-512 | — | 14.0 Gbps | — |
| Zero-copy decrypt | rte_pktmbuf_adj reuse | 14.0 Gbps | 16.0 Gbps (-R) | **+14%** |
| Rate-limit clock | Instant::now() every 32K iters | (included above) | (included above) | ~0% fwd |
| Zero-copy encrypt | rte_pktmbuf_prepend reuse | 16.0 Gbps (-R) | 15.7 Gbps (-R) | neutral |

Zero-copy encrypt eliminates mempool alloc + ~1400-byte copy per TX packet, but
throughput is unchanged because the vhost kthread is the bottleneck, not our engine.
