# quictun-dpdk: DPDK Kernel-Bypass Data Plane

DPDK-based data plane for quictun that bypasses the kernel network stack entirely for network I/O using DPDK PMD (Poll Mode Driver).

## Architecture

```
TUN (kernel) <--> reader thread <--> [channel] <--> DPDK engine thread
                                                       |
                                                   quinn-proto
                                                       |
                                                 Eth/IP/UDP headers
                                                       |
                                                 DPDK PMD (virtio-net)
                                                       |
                                                      NIC
```

- **Network side**: DPDK PMD replaces kernel UDP socket (zero kernel involvement)
- **TUN side**: Kernel-managed (reader thread -> bounded crossbeam channel -> engine)
- **QUIC**: quinn-proto state machine driven directly (same as quictun-uring)
- **Userland stack**: Manual Eth/IPv4/UDP header parsing and building, ARP

## Benchmark Results

| Backend | Throughput | vs Kernel WG | vs Raw Link |
|---------|-----------|-------------|-------------|
| Raw virtio-net (iperf) | 29.7 Gbps | — | 100% |
| **DPDK tunnel** | **1.75 Gbps** | **101.7%** | 5.9% |
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
    reader.rs       # TUN reader thread (blocking read)
    event_loop.rs   # Thread spawning, ARP resolution, signal handling
  build.rs          # bindgen + cc + pkg-config
  Cargo.toml
```

## Engine Loop (3-phase)

```
Phase 1a: rx_burst -> parse Eth/IP/UDP -> endpoint.handle() (batch)
          Handle ARP requests -> learn peer MAC -> queue reply
Phase 1b: drain TUN channel -> conn.datagrams().send() (batch)
Phase 1c: check timer (Instant::now() vs deadline)
Phase 2:  process_events() -> drain datagrams -> write to TUN
Phase 3:  drain_transmits() -> build_udp_packet() into mbufs -> tx_burst
```

No io_uring, no eventfd, no timerfd -- pure polling.

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
| `--dpdk` | Enable DPDK data plane | — |
| `--dpdk-local-ip` | IP for DPDK port (required) | — |
| `--dpdk-remote-ip` | Peer IP (required) | — |
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

## Per-Packet Copy Analysis

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

### Tier 1 -- High Impact (2-4x improvement potential)

#### 1. Multi-Core DPDK Engine
- Currently single-threaded: 1 core doing QUIC + rx/tx + TUN writes
- Add multi-queue RSS + N engine threads (same pattern as quictun-uring multi-core)
- io_uring already proved multi-core works (616 -> 1.32 Gbps at 4 cores)
- Virtio-net supports multi-queue on Proxmox

#### 2. Eliminate Outgoing Copies (3 -> 1)
- **reader.rs**: Replace `to_vec()` with buffer pool (pre-allocated Vec slabs)
- **build_udp_packet + write_packet**: Build headers directly into mbuf memory
  - New `build_udp_into_mbuf()` that writes Eth/IP/UDP headers + payload in one pass
  - Eliminates intermediate `pkt_buf` entirely
- Cuts 2 memcpies per outgoing packet

#### 3. Batch TUN Operations
- `writev()` for TUN writes (multiple datagrams in one syscall)
- `readv()` or batched reads for TUN reader
- Kernel TUN syscall overhead is now the dominant per-packet cost

### Tier 2 -- Medium Impact (10-30% improvement)

#### 4. Header Template Pre-computation
- Src/dst MAC, src/dst IP, protocol fields never change per-connection
- Pre-build a 42-byte template, only update per-packet: IP total_length, UDP length, IP checksum
- Saves ~30 byte writes per packet

#### 5. Adaptive Polling / Hybrid Interrupt Mode
- Pure busy-poll burns 100% CPU even when idle
- Hybrid: poll N iterations -> if no packets, `usleep(1)` -> back to polling on wakeup
- No throughput improvement at peak, but critical for production deployment
- Options: `rte_power` API, manual yield, rx interrupt mode

#### 6. Zero-Copy Incoming Path
- `BytesMut::from(udp.payload)` copies QUIC data from mbuf
- Keep mbuf alive and create custom `Bytes` referencing mbuf data directly
- Tricky with quinn-proto ownership model but saves 1 copy per incoming packet

### Tier 3 -- Correctness & Production Readiness

#### 7. Unsafe Code Audit
- Signal handler stores raw pointer (intentional leak, needs review)
- Mbuf `from_raw()` / `into_raw()` ownership transfers
- FFI boundary: null checks, return value checks
- `libc::write/read` on TUN fd (unchecked return values in hot path)
- Mbuf `Send` impl safety justification

#### 8. UDP Stack Improvements
- UDP checksum verification (currently trusting NIC offload; virtio-net may not do it)
- ICMP port unreachable for unknown ports (nice-to-have)
- IP identification field (currently 0, fine for DF-bit packets)
- ECN passthrough from IP TOS field to quinn-proto
- Note: current stack is sufficient for tunnel operation

#### 9. Statistics & Monitoring
- `rte_eth_stats_get()` for DPDK port stats
- Per-second packet/byte/drop counters
- Structured log output or prometheus-style metrics
- Connection state reporting

### Tier 4 -- Advanced / Experimental

#### 10. DPDK Crypto PMD
- Hardware AES-GCM acceleration via DPDK crypto device
- Would require hooking into rustls/quinn-proto crypto layer
- Very complex integration but could unlock wire-speed crypto

#### 11. TUN Bypass (Full Userland)
- Replace kernel TUN with TAP device managed by DPDK
- Or use XDP/AF_XDP on the TUN side
- Eliminates all kernel copies but requires routing changes

#### 12. GSO/GRO Support
- Generic Segmentation Offload: send large buffers, NIC segments
- Would require quinn-proto `max_datagrams > 1` in `poll_transmit()`
- Build multiple QUIC packets into one large Ethernet frame with segmentation

## Implementation Priority

Recommended order for maximum impact:

```
1. Multi-core DPDK engine        -- biggest single win, pattern exists in quictun-uring
2. Eliminate outgoing copies      -- build directly into mbuf, remove pkt_buf
3. Batch TUN operations           -- writev/readv, reduce syscall count
4. Header template                -- quick win, ~30 fewer writes per packet
5. Unsafe audit                   -- correctness before more features
6. Adaptive polling               -- production readiness
7. Zero-copy incoming             -- harder, custom Bytes impl needed
8. Statistics                     -- observability
```
