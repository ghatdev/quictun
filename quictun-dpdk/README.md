# quictun-dpdk: DPDK Kernel-Bypass Data Plane

DPDK-based data plane for quictun that bypasses the kernel network stack using DPDK PMD (Poll Mode Driver). Uses a custom QUIC 1-RTT protocol (quictun-proto) for the data plane with zero-copy packet paths.

## Architecture

### Virtio-User Mode (recommended)

```
App (iperf3, etc.)
    | kernel TCP/IP stack
    v
TUN interface
    | TAP (kernel side)
    v
vhost kthread (kernel ↔ DPDK copy)
    | virtio-user PMD
    v
DPDK engine core (single polling loop)
    | quictun-proto encrypt/decrypt (zero-copy)
    v
Outer NIC (vfio-pci, kernel-bypass)
    | wire
    v
Peer
```

The inner path uses virtio-user + vhost-kernel, which is DPDK's recommended way to
bridge between DPDK and the kernel networking stack (KNI was removed in DPDK 23.11).

### Single-Core Engine

One DPDK lcore runs the full packet pipeline:

1. **Outer RX** → parse → CID lookup → decrypt in-place → zero-copy mbuf reuse → inner TX
2. **Inner RX** → route by dst IP → zero-copy encrypt (prepend/append) → outer TX
3. **Handshake** → quinn-proto state machine (cold path)
4. **Stats/timers** → rate-limited clock, ACK generation

### Pipeline Multi-Core Mode

Core 0 handles I/O (RX/TX on both ports). Workers handle crypto via `SharedConnectionState`:

```
Core 0 (I/O)           Workers 1..N (crypto)
  outer rx_burst ──→  decrypt_rx ring ──→ decrypt + process
  inner tx_burst ←──  inner_tx ring   ←── decrypted mbufs
  inner rx_burst ──→  encrypt_rx ring ──→ encrypt
  outer tx_burst ←──  outer_tx ring   ←── encrypted mbufs
```

Limited by virtio TX queue restriction: workers cannot TX directly, must route through
core 0 via rings. On these VMs, pipeline barely helps (~3% over single-core) because
AES-128-GCM with AVX-512 is <0.5% CPU.

### Router Mode

Single-NIC router with NAT for hub-and-spoke topologies. Decrypts from one peer,
routes by IP, re-encrypts for another peer. Supports ARP, ICMP errors, MSS clamping.

## Benchmark Results

| Config | Throughput | Notes |
|--------|-----------|-------|
| **Single-core optimized (-R)** | **16.0 Gbps** | Zero-copy encrypt + decrypt |
| **Single-core optimized (fwd)** | **13.4 Gbps** | vm2 connector-limited |
| Pipeline 2-core | 10.6 Gbps | Ring overhead ~3% |
| Router single-core NAT | 6.95 Gbps | Via vm3 |
| TAP PMD (legacy) | 3.98 Gbps | IPI bottleneck |

All benchmarks on secondary NIC (ens19). Raw: 26.8 Gbps. Both VMs run DPDK.

## Per-Packet Copy Analysis

### Incoming: NIC → Decrypt → Inner

| Step | Operation | Copy? |
|------|-----------|-------|
| RX burst | DMA to mbuf | DMA (zero-copy) |
| Parse headers | Offset arithmetic on mbuf data | No copy |
| QUIC decrypt | `decrypt_packet_in_place()` | In-place (zero-copy) |
| Inner TX | `rte_pktmbuf_adj` + 14-byte ETH write | **Zero-copy** (mbuf reuse) |
| TX burst | DMA from mbuf | DMA (zero-copy) |

**Total incoming: 0 memcpies** (decrypt in-place, mbuf reuse via adj)

### Outgoing: Inner → Encrypt → NIC

| Step | Operation | Copy? |
|------|-----------|-------|
| RX burst | DMA to mbuf | DMA (zero-copy) |
| QUIC encrypt | `encrypt_datagram_in_place()` | In-place (zero-copy) |
| Outer headers | `rte_pktmbuf_prepend` + 42-byte write | **Zero-copy** (headroom reuse) |
| AEAD tag | `rte_pktmbuf_append(16)` | Tailroom (zero-copy) |
| TX burst | DMA from mbuf | DMA (zero-copy) |

**Total outgoing: 0 memcpies** (encrypt in-place, mbuf reuse via prepend/append)

**Round-trip total: 0 application-level copies.** The only copies are DMA (hardware)
and the vhost kthread (kernel ↔ DPDK, unavoidable with virtio-user).

## Config

All DPDK settings are in the `[engine]` section of tunnel.toml:

```toml
[engine]
backend = "dpdk-virtio"        # "dpdk-virtio" or "dpdk-router"
dpdk_local_ip = "10.23.30.100" # IP for DPDK outer port (required)
dpdk_cores = 1                 # Number of engine lcores
dpdk_port = 0                  # DPDK port ID (default: 0)
dpdk_eal_args = "-l;0;-n;4"   # EAL args, semicolon-separated
adaptive_poll = false           # Disable for benchmarks (pure busy-poll)
cc = "none"                    # No congestion control
recv_buf = 8388608             # UDP receive buffer size
send_buf = 8388608             # UDP send buffer size
```

## Crate Structure

```
quictun-dpdk/
  csrc/
    shim.h          # Declarations for inline DPDK function wrappers
    shim.c          # C wrappers (rx_burst, tx_burst, mbuf ops, RSS config)
  src/
    lib.rs          # Crate root, cfg(target_os = "linux")
    ffi.rs          # bindgen output + manual DPDK/RSS constants
    eal.rs          # EAL init/cleanup RAII wrapper
    port.rs         # Port config (single-queue + dispatcher), rx/tx burst
    mbuf.rs         # Mbuf RAII wrapper, mempool, prepend/adj/append
    net.rs          # Userland Eth/IPv4/UDP stack, ARP, checksums, ECN
    shared.rs       # QuicState, MultiQuicState, handshake management
    dispatch.rs     # Connection table, pipeline rings, control messages
    engine.rs       # Single-core DPDK polling loop (zero-copy paths)
    router.rs       # Router-mode engine (NAT, ICMP, ARP, MSS clamp)
    event_loop.rs   # Setup, multi-core spawning, ARP resolution, signals
  build.rs          # bindgen + cc + pkg-config
  Cargo.toml
```

## VM Setup

**DPDK IPs**: 10.23.30.100 (vm1 listener), 10.23.30.101 (vm2 connector)

```bash
# Build DPDK 25.11 from source at /opt/dpdk (or install libdpdk-dev)
PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig cargo build --release

# Hugepages (256 x 2MB = 512MB)
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /dev/hugepages
mount | grep -q hugetlbfs || sudo mount -t hugetlbfs nodev /dev/hugepages

# vfio-pci for NIC binding
sudo modprobe vfio-pci
echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# Bind ens19 to DPDK (NEVER bind the primary NIC!)
sudo ip link set ens19 down
echo "0000:00:13.0" | sudo tee /sys/bus/pci/devices/0000:00:13.0/driver/unbind
echo "0000:00:13.0" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
```

## Build Notes

- All code gated behind `cfg(target_os = "linux")` — compiles as empty crate on macOS
- Binary is statically linked — no DPDK shared libs needed on target
- `PKG_CONFIG_PATH` must point to /opt/dpdk, not system DPDK (version mismatch causes EAL panic)
- `build.rs` uses `-march=native` because DPDK headers use SSSE3/AVX intrinsics
