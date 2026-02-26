# quictun-dpdk: DPDK Kernel-Bypass Data Plane

DPDK-based data plane for quictun that bypasses the kernel network stack using DPDK PMD (Poll Mode Driver).

## Current Architecture (v1 — TUN + DPDK)

The initial implementation bypasses the kernel on the network (outer) side only.
The application (inner) side still uses a kernel TUN device.

```
App (iperf3)
    | kernel routing
    v
TUN device (kernel)          <-- still 2 syscalls + 2 kernel copies per packet
    | read() syscall
    v
reader thread (userspace)
    | crossbeam channel
    v
DPDK engine thread
    | quinn-proto
    v
Eth/IP/UDP headers (net.rs)
    |
    v
DPDK PMD (virtio-net)        <-- kernel-bypass
    |
    v
NIC
```

- **Network side**: DPDK PMD replaces kernel UDP socket (zero kernel involvement)
- **TUN side**: Kernel-managed (reader thread -> bounded crossbeam channel -> engine)
- **QUIC**: quinn-proto state machine driven directly (same as quictun-uring)
- **Userland stack**: Manual Eth/IPv4/UDP header parsing and building, ARP

### v1 Bottleneck

The TUN device is now the primary bottleneck. Each packet crosses the user/kernel
boundary twice (read + write). Kernel WireGuard doesn't pay this cost because it
runs entirely in kernel space.

## Target Architecture (v2 — Full Kernel Bypass)

Inspired by [Demikernel](https://github.com/microsoft/demikernel)'s LibOS architecture:
a thin, purpose-built userspace data plane with **zero kernel involvement** in the
packet path. Both inner and outer interfaces managed by DPDK.

```
                        Single DPDK polling loop
                        +-----------------------+
 Apps (iperf3, etc.)    |                       |    Network
         |              |    quinn-proto        |        |
         v              |    +-----------+      |        v
   +-----------+        |    | encrypt   |      |   +----------+
   | virtio-   |<------>|    | decrypt   |      |<->| DPDK PMD |
   | user      |        |    +-----------+      |   | (NIC)    |
   | (tap0)    |        |                       |   +----------+
   +-----------+        |    net.rs             |    same mempool
    shared mempool      |    (Eth/IP/UDP)       |    rx/tx_burst
    rx/tx_burst         +-----------------------+
```

### How It Works

- **Inner (app-facing)**: DPDK `virtio-user` device with `vhost-kernel` backend
  (`/dev/vhost-net`). Creates a kernel-visible TAP interface (`tap0`) for routing,
  but data transfer uses **vhost virtio rings in shared memory** — the kernel's
  vhost-net kthread exchanges packets with DPDK via ring buffers, not syscalls.
- **Outer (network-facing)**: DPDK PMD on the physical NIC (unchanged from v1).
- **Shared mempool**: Both ports use the same mbuf pool — packets move between
  inner and outer as pointer exchanges, not copies.
- **Single polling loop**: One thread polls both ports. No reader thread, no
  channels, no syscalls in the data path.

### Why Not Demikernel Directly?

[Demikernel](https://irenezhang.net/papers/demikernel-sosp21.pdf) (Microsoft Research)
implements the same idea — a userspace LibOS with full TCP/IP/UDP stack on DPDK,
no kernel networking at all. Its Catnip backend provides socket-like API directly
on DPDK with zero kernel involvement.

But Demikernel is too general-purpose for our needs:
- Fixed API (`demi_socket`, `demi_pushto`) — requires apps to use its API or LD_PRELOAD
- Full TCP/IP stack we don't need (we only need raw IP in/out + QUIC)
- Large dependency with opinions about memory management, coroutines, etc.

Instead, we build a **thin, purpose-built layer** with only what a VPN tunnel needs:
- `virtio-user` for app-facing interface (standard routing, shared memory data path)
- `net.rs` for outer-side Eth/IP/UDP (minimal, ~300 lines)
- `quinn-proto` for QUIC (unchanged)
- Single polling loop over both DPDK ports

### v2 Engine Loop

```
loop {
    // -- Inner: apps -> tunnel --
    nb_tap = rx_burst(tap_port, inner_mbufs, 32)
    for mbuf in inner_mbufs:
        conn.datagrams().send(mbuf.data())          // raw IP -> QUIC datagram

    // -- Outer: network -> tunnel --
    nb_nic = rx_burst(nic_port, outer_mbufs, 32)
    for mbuf in outer_mbufs:
        parse_udp(mbuf) -> endpoint.handle()         // QUIC packet in
        handle_arp(mbuf)                              // outer-side ARP

    // -- QUIC state machine --
    handle_timeout(now)
    process_events()

    // -- Inner TX: decrypted -> apps --
    for datagram in datagrams:
        write_into_mbuf(datagram) -> tx_burst(tap_port)

    // -- Outer TX: encrypted -> network --
    for transmit in drain_transmits():
        build_udp_into_mbuf(transmit) -> tx_burst(nic_port)
}
```

### What v2 Eliminates vs v1

| Component | v1 (current) | v2 (target) |
|-----------|-------------|-------------|
| Reader thread | Yes (blocking TUN read) | No (rx_burst polling) |
| Crossbeam channel | Yes (thread boundary) | No (single thread) |
| TUN read() syscall | Yes (per packet) | No (shared memory rings) |
| TUN write() syscall | Yes (per packet) | No (tx_burst to virtio-user) |
| Kernel copies | 2 per packet (TUN r/w) | 0 (shared mempool) |
| to_vec() allocation | Yes (reader thread) | No (mbufs stay in pool) |
| pkt_buf intermediate | Yes (build then copy) | No (build directly in mbuf) |
| Context switches | Per TUN read/write | None in data path |

### v2 Copy Analysis (projected)

| Direction | Path | Copies |
|-----------|------|--------|
| Incoming (NIC->app) | DMA -> mbuf -> BytesMut (QUIC) -> mbuf -> shared mem | 1 memcpy (BytesMut) |
| Outgoing (app->NIC) | shared mem -> mbuf -> Bytes (QUIC) -> mbuf -> DMA | 1 memcpy (into mbuf) |
| **Round-trip** | | **2 memcpies, 0 kernel copies** |

Down from 4 memcpies + 2 kernel copies in v1. The remaining copies are
in quinn-proto's API boundaries (BytesMut for input, Vec<u8> for output).

## Benchmark Results (v1)

| Backend | Throughput | vs Kernel WG | vs Raw Link |
|---------|-----------|-------------|-------------|
| Raw virtio-net (iperf) | 29.7 Gbps | -- | 100% |
| **DPDK tunnel (v1)** | **1.75 Gbps** | **101.7%** | 5.9% |
| Kernel WireGuard | 1.72 Gbps | 100% (baseline) | 5.8% |
| tokio parallel | 1.32 Gbps | 76.7% | 4.4% |
| io_uring (1-core) | 820 Mbps | 47.7% | 2.8% |

**Key finding**: The kernel network stack was the bottleneck, not congestion control.
Bypassing it with DPDK gave +33% over tokio (1.32 -> 1.75 Gbps), matching kernel WireGuard.

## Crate Structure

```
quictun-dpdk/
  csrc/
    shim.h          # Declarations for inline DPDK function wrappers
    shim.c          # C wrappers (rx_burst, tx_burst, mbuf ops)
  src/
    lib.rs          # Crate root, cfg(target_os = "linux")
    ffi.rs          # bindgen output + manual DPDK constants
    eal.rs          # EAL init/cleanup RAII wrapper
    port.rs         # Ethernet port config, rx_burst/tx_burst
    mbuf.rs         # Mbuf RAII wrapper + mempool creation
    net.rs          # Userland Eth/IP/UDP stack, ARP, checksums
    shared.rs       # QuicState, DriveResult, process_events
    quic.rs         # quinn-proto config builders
    engine.rs       # Main DPDK polling loop (3-phase)
    reader.rs       # TUN reader thread (blocking read)     [v1 only, removed in v2]
    event_loop.rs   # Thread spawning, ARP resolution, signal handling
  build.rs          # bindgen + cc + pkg-config
  Cargo.toml
```

## CLI Usage

```bash
# Listener (vm1)
sudo quictun up tunnel.toml \
  --dpdk \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11

# Connector (vm2)
sudo quictun up tunnel.toml \
  --dpdk \
  --dpdk-local-ip 192.168.100.11 \
  --dpdk-remote-ip 192.168.100.10
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dpdk` | Enable DPDK data plane | -- |
| `--dpdk-local-ip` | IP for DPDK port (required) | -- |
| `--dpdk-remote-ip` | Peer IP (required) | -- |
| `--dpdk-local-port` | Override local UDP port | listen_port or 40000 |
| `--dpdk-gateway-mac` | Static peer MAC (skip ARP) | ARP resolution |
| `--dpdk-eal-args` | EAL args, semicolon-separated | `-l;0;-n;4` |
| `--dpdk-port` | DPDK port ID | 0 |

## VM Setup

**DPDK IPs**: Separate subnet -- 192.168.100.10 (vm1), 192.168.100.11 (vm2)

```bash
# Install DPDK
sudo apt install -y dpdk dpdk-dev libdpdk-dev pkg-config libclang-dev

# Hugepages (256 x 2MB = 512MB)
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /dev/hugepages
mount | grep -q hugetlbfs || sudo mount -t hugetlbfs nodev /dev/hugepages

# vfio-pci for virtio-net binding
sudo modprobe vfio-pci
echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

# Bind ens19 to DPDK
sudo ip link set ens19 down
sudo dpdk-devbind.py --bind=vfio-pci 0000:00:13.0
dpdk-devbind.py --status  # verify
```

## Build Notes

- All code gated behind `cfg(target_os = "linux")` -- compiles as empty crate on macOS
- `build.rs` uses `-march=native` because DPDK headers (rte_memcpy.h) use SSSE3 intrinsics
- `rte_eth_link` is a bindgen union: access via `link.__bindgen_anon_1.__bindgen_anon_1.link_speed`
- quinn-proto 0.11 API: `endpoint.handle()` takes `local_ip: Option<IpAddr>` (pass None), `datagrams().send()` takes `drop: bool` (pass true)

## Per-Packet Copy Analysis (v1)

### Incoming: NIC -> QUIC -> TUN

| Step | Operation | Copy? |
|------|-----------|-------|
| RX burst | DMA to mbuf | DMA (zero-copy) |
| Parse headers | Slice references | No copy |
| Feed QUIC | `BytesMut::from(payload)` | **1 memcpy** |
| QUIC decrypt | quinn-proto internal | Internal |
| TUN write | `libc::write()` | 1 kernel copy |

**Total incoming: 1 memcpy + 1 kernel copy**

### Outgoing: TUN -> QUIC -> NIC

| Step | Operation | Copy? |
|------|-----------|-------|
| TUN read | `libc::read()` to stack buf | 1 kernel copy |
| Stack to Vec | `buf[..n].to_vec()` | **1 memcpy** |
| Channel send | Ownership transfer | No copy |
| QUIC encrypt | `poll_transmit()` to buf | Internal |
| Build frame | `build_udp_packet()` to pkt_buf | **1 memcpy** |
| Write mbuf | `mbuf.write_packet()` | **1 memcpy** |
| TX burst | DMA from mbuf | DMA (zero-copy) |

**Total outgoing: 3 memcpies + 1 kernel copy**

**Round-trip total: 4 memcpies + 2 kernel copies = 6 copies per packet**

## Optimization Roadmap

### Priority 0 -- Full Kernel Bypass (v2 architecture)

Replace TUN with DPDK virtio-user. This is the defining change — everything
else is incremental optimization on top of this architecture.

- **virtio-user with vhost-kernel**: `--vdev virtio_user0,path=/dev/vhost-net,queue_size=1024`
- Creates kernel-visible TAP interface for routing
- Data path uses shared memory virtio rings (no syscalls)
- Eliminates reader thread, channel, TUN syscalls, kernel copies
- Both inner and outer become rx_burst/tx_burst in one loop

### Priority 1 -- High Impact (2-4x improvement potential)

#### 1. Multi-Core DPDK Engine
- Currently single-threaded: 1 core doing QUIC + rx/tx
- Add multi-queue RSS + N engine threads (same pattern as quictun-uring multi-core)
- io_uring already proved multi-core works (616 -> 1.32 Gbps at 4 cores)
- Virtio-net supports multi-queue on Proxmox

#### 2. Eliminate Remaining Copies
- **Outgoing**: build Eth/IP/UDP headers directly into mbuf (skip pkt_buf)
- **Incoming**: custom `Bytes` impl referencing mbuf data (skip BytesMut copy)
- **Header template**: pre-compute 42-byte template, only update length + checksum

### Priority 2 -- Medium Impact (10-30% improvement)

#### 3. Adaptive Polling / Hybrid Interrupt Mode
- Pure busy-poll burns 100% CPU even when idle
- Hybrid: poll N iterations -> if no packets, brief pause -> back to polling
- No throughput improvement at peak, but critical for production deployment
- Options: `rte_power` API, manual yield, rx interrupt mode

#### 4. GSO/GRO Support
- Generic Segmentation Offload: send large buffers, NIC segments
- Would require quinn-proto `max_datagrams > 1` in `poll_transmit()`
- Build multiple QUIC packets into one large Ethernet frame with segmentation

### Priority 3 -- Correctness & Production Readiness

#### 5. Unsafe Code Audit
- Signal handler stores raw pointer (intentional leak, needs review)
- Mbuf `from_raw()` / `into_raw()` ownership transfers
- FFI boundary: null checks, return value checks
- Mbuf `Send` impl safety justification

#### 6. UDP Stack Improvements
- UDP checksum verification (currently trusting NIC offload; virtio-net may not do it)
- ECN passthrough from IP TOS field to quinn-proto
- ICMP port unreachable for unknown ports (nice-to-have)
- Note: current stack is sufficient for tunnel operation

#### 7. Statistics & Monitoring
- `rte_eth_stats_get()` for DPDK port stats
- Per-second packet/byte/drop counters
- Structured log output or prometheus-style metrics

### Priority 4 -- Advanced / Experimental

#### 8. DPDK Crypto PMD
- Hardware AES-GCM acceleration via DPDK crypto device
- Would require hooking into rustls/quinn-proto crypto layer
- Very complex integration but could unlock wire-speed crypto

## References

- [DPDK virtio-user as exception path](https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html) -- TAP via shared memory
- [DPDK vhost library](https://doc.dpdk.org/guides/prog_guide/vhost_lib.html) -- shared memory ring mechanism
- [Demikernel: LibOS for Kernel-Bypass (SOSP'21)](https://irenezhang.net/papers/demikernel-sosp21.pdf) -- architectural inspiration
- [microsoft/demikernel](https://github.com/microsoft/demikernel) -- Catnip (DPDK), Catnap (sockets), Catpowder (XDP)
- [VIRTIO-USER: Versatile Channel for Kernel-Bypass](https://dl.acm.org/doi/10.1145/3098583.3098586) -- virtio-user design paper
