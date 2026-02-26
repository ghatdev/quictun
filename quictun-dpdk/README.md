# quictun-dpdk: DPDK Kernel-Bypass Data Plane

DPDK-based data plane for quictun that bypasses the kernel network stack using DPDK PMD (Poll Mode Driver).

## Architecture

Single-threaded (or multi-threaded with RSS) polling loop. Both inner and outer
interfaces are DPDK-managed; no reader threads, no channels, no syscalls in the
data path.

### TAP PMD Mode (`--dpdk tap`, default)

```
App (iperf3, etc.)
    | kernel routing
    v
TAP interface (kernel)
    | DPDK TAP PMD
    v
DPDK engine (single polling loop)
    | quinn-proto encrypt/decrypt
    v
Eth/IP/UDP headers (net.rs)
    | DPDK PMD (kernel-bypass)
    v
NIC
```

### AF_XDP Mode (`--dpdk xdp`)

```
App (iperf3, etc.)
    | kernel routing
    v
veth pair (app end: quictun0)
    | AF_XDP PMD (quictun0_xdp)
    v
DPDK engine (single polling loop)
    | quinn-proto encrypt/decrypt
    v
Eth/IP/UDP headers (net.rs)
    | DPDK PMD (kernel-bypass)
    v
NIC
```

### Multi-Core Mode (`--dpdk-cores N`, TAP PMD only)

```
App (iperf3, etc.)
    |
    +-- TAP quictun0 --> Engine thread 0 (queue 0, CPU 0)
    |                        | quinn-proto
    |                        v
    +-- TAP quictun1 --> Engine thread 1 (queue 1, CPU 1)   --> NIC (RSS)
    |                        | quinn-proto
    |                        v
    +-- TAP quictunN --> Engine thread N (queue N, CPU N)
```

- Outer port uses multi-queue RSS (IP + UDP hash distribution)
- Each thread has its own TAP PMD, QUIC state, and queue pair
- CPU pinning via `sched_setaffinity`

### Key Design Points

- **Outer (network)**: DPDK PMD (kernel-bypass, zero syscalls)
- **Inner (app-facing)**: TAP PMD or AF_XDP PMD (kernel-visible for routing)
- **QUIC**: quinn-proto state machine driven directly
- **Userland stack**: Eth/IPv4/UDP headers, ARP, IP checksums, UDP checksums
- **ECN**: Full passthrough (IP TOS field to/from quinn-proto)
- **GSO**: Batched transmits (up to 10 segments per poll_transmit)
- **Adaptive polling**: Exponential backoff on empty polls (saves CPU when idle)

## Benchmark Results

| Backend | Throughput | Notes |
|---------|-----------|-------|
| **DPDK AF_XDP** | **2.24 Gbps** | veth + AF_XDP PMD, single polling loop |
| **DPDK TAP PMD** | **1.94 Gbps** | Built-in TAP vdev, single polling loop |
| Kernel WireGuard | 1.62 Gbps | Reference (range: 1.35-1.82 Gbps) |
| tokio parallel | 1.30 Gbps | quinn internal parallelism |
| io_uring (1-core) | 820 Mbps | SendZc zero-copy UDP sends |

All benchmarks on secondary NIC (ens19, no Proxmox firewall). Raw NIC: 26.8 Gbps.

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
    port.rs         # Port config (single-queue + multi-queue RSS), rx/tx burst
    mbuf.rs         # Mbuf RAII wrapper, mempool creation, zero-copy alloc_space
    net.rs          # Userland Eth/IPv4/UDP stack, ARP, checksums (IP + UDP), ECN
    shared.rs       # QuicState, DriveResult, process_events
    quic.rs         # quinn-proto config builders
    engine.rs       # Main DPDK polling loop (3-phase, GSO, adaptive polling)
    veth.rs         # Virtual Ethernet pair creation/cleanup (AF_XDP mode)
    event_loop.rs   # Setup, multi-core thread spawning, ARP resolution, signal handling
  build.rs          # bindgen + cc + pkg-config
  Cargo.toml
```

## CLI Usage

```bash
# Listener (vm1) -- single core, TAP PMD (default)
sudo quictun up tunnel.toml \
  --dpdk \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11

# Connector (vm2)
sudo quictun up tunnel.toml \
  --dpdk \
  --dpdk-local-ip 192.168.100.11 \
  --dpdk-remote-ip 192.168.100.10

# AF_XDP mode (faster, requires libxdp-dev)
sudo quictun up tunnel.toml \
  --dpdk xdp \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11

# Multi-core (2 cores, TAP PMD, listener only)
sudo quictun up tunnel.toml \
  --dpdk tap \
  --dpdk-cores 2 \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11

# Benchmarking mode (disable adaptive poll)
sudo quictun up tunnel.toml \
  --dpdk \
  --no-adaptive-poll \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dpdk [MODE]` | Enable DPDK data plane (`tap` or `xdp`) | `tap` |
| `--dpdk-local-ip` | IP for DPDK port (required) | -- |
| `--dpdk-remote-ip` | Peer IP (required) | -- |
| `--dpdk-local-port` | Override local UDP port | listen_port or 40000 |
| `--dpdk-gateway-mac` | Static peer MAC (skip ARP) | ARP resolution |
| `--dpdk-eal-args` | EAL args, semicolon-separated | `-l;0;-n;4` |
| `--dpdk-port` | DPDK port ID | 0 |
| `--dpdk-cores` | Number of engine cores (RSS multi-queue) | 1 |
| `--no-adaptive-poll` | Disable adaptive polling (pure busy-poll) | adaptive on |

## Per-Packet Copy Analysis

### Incoming: NIC -> QUIC -> Inner

| Step | Operation | Copy? |
|------|-----------|-------|
| RX burst | DMA to mbuf | DMA (zero-copy) |
| Parse headers | Slice references | No copy |
| Feed QUIC | `BytesMut::from(payload)` | **1 memcpy** |
| QUIC decrypt | quinn-proto internal | Internal |
| Inner TX | `alloc_space` + copy into mbuf | **1 memcpy** |
| TX burst | DMA from mbuf | DMA (zero-copy) |

**Total incoming: 2 memcpies**

### Outgoing: Inner -> QUIC -> NIC

| Step | Operation | Copy? |
|------|-----------|-------|
| RX burst | DMA to mbuf | DMA (zero-copy) |
| Strip Ethernet | `Bytes::copy_from_slice` | **1 memcpy** |
| QUIC encrypt | `poll_transmit()` to buf | Internal |
| Build frame | `alloc_space` + `build_udp_packet` | **1 memcpy** |
| TX burst | DMA from mbuf | DMA (zero-copy) |

**Total outgoing: 2 memcpies**

**Round-trip total: 4 memcpies, 0 kernel copies** (with zero-copy mbuf builds)

Remaining copies are at quinn-proto API boundaries (BytesMut for input, Vec<u8> for output).

## VM Setup

**DPDK IPs**: Separate subnet -- 192.168.100.10 (vm1), 192.168.100.11 (vm2)

```bash
# Install DPDK
sudo apt install -y dpdk dpdk-dev libdpdk-dev pkg-config libclang-dev

# For AF_XDP mode
sudo apt install -y libxdp-dev

# Hugepages (256 x 2MB = 512MB)
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /dev/hugepages
mount | grep -q hugetlbfs || sudo mount -t hugetlbfs nodev /dev/hugepages

# vfio-pci for virtio-net binding
sudo modprobe vfio-pci
echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# Bind ens19 to DPDK (NEVER bind the primary NIC!)
sudo ip link set ens19 down
sudo dpdk-devbind.py --bind=vfio-pci 0000:00:13.0
dpdk-devbind.py --status  # verify
```

## Build Notes

- All code gated behind `cfg(target_os = "linux")` -- compiles as empty crate on macOS
- `build.rs` uses `-march=native` because DPDK headers (rte_memcpy.h) use SSSE3 intrinsics
- `rte_eth_link` is a bindgen union: access via `link.__bindgen_anon_1.__bindgen_anon_1.link_speed`
- RSS port config uses C shim (`shim_create_rss_port_conf`) for correct struct layout
- quinn-proto 0.11 API: `endpoint.handle()` takes `ecn: Option<EcnCodepoint>`, `datagrams().send()` takes `drop: bool`

## Remaining Optimization Opportunities

### Statistics & Monitoring
- `rte_eth_stats_get()` for DPDK port stats
- Per-second packet/byte/drop counters
- Structured log output or prometheus-style metrics

### Custom Bytes impl
- Eliminate the BytesMut copy on RX by providing a custom `Bytes` backed by mbuf data
- Would reduce incoming copies from 2 to 1

### DPDK Crypto PMD
- Hardware AES-GCM acceleration via DPDK crypto device
- Requires hooking into rustls/quinn-proto crypto layer

### Multi-core Connector
- Currently multi-core only supports listener mode
- Connector needs client_config cloning support
