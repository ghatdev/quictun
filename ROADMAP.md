# QuicTun Roadmap

## Current State (Feb 2026)

### Benchmarks

**Current (DPDK 25.11 static, host CPU with AES-NI + AVX-512):**

| Backend | Throughput | vs WireGuard | vs Raw NIC (26.8 Gbps) |
|---------|-----------|-------------|------------------------|
| **DPDK virtio-user** | **4.97 Gbps** | **+225%** | **18.5%** |
| **DPDK AF_XDP** | **4.86 Gbps** | **+218%** | **18.1%** |
| **tokio + GSO/GRO (--offload)** | **2.59 Gbps** | **+69%** | **9.7%** |
| **Kernel WireGuard** | **1.53 Gbps** | **baseline** | **5.7%** |
| io_uring (1-core, SendZc) | 820 Mbps | -46% | 3.1% |

All benchmarks on AMD Ryzen 9700X, Proxmox KVM VM, virtio NIC, host CPU passthrough. DPDK on ens19 (no Proxmox firewall), tokio/WireGuard on ens18. Raw NIC: 26.8 Gbps. Socket buffers: 8 MB (`sysctl net.core.rmem_max=8388608`).

**Key findings:**
- **Packet I/O overhead dominates, not protocol overhead.** Same QUIC+TLS stack, DPDK removes kernel I/O → 1.9x over tokio.
- **Hardware crypto acceleration matters.** Previous results with QEMU generic CPU (no AES-NI): DPDK 2.22 Gbps, WireGuard 1.62 Gbps. With host CPU (AES-NI + AVX-512 VAES): DPDK 4.97 Gbps (+124%). Software AES was the hidden bottleneck.
- **Socket buffer tuning is critical.** Default `rmem_max=212992` (208 KB) caused 600+ retransmits and capped tokio at 937 Mbps. With 8 MB buffers: 2.59 Gbps, zero retransmits.

**Previous results (system DPDK ~23.11, QEMU generic CPU without AES-NI):**

| Backend | Throughput | Notes |
|---------|-----------|-------|
| DPDK AF_XDP (no cksum) | 2.25 Gbps | software AES, generic CPU |
| DPDK virtio-user | 2.22 Gbps | software AES, generic CPU |
| DPDK TAP (no cksum) | 1.94 Gbps | software AES, generic CPU |
| Kernel WireGuard | 1.62 Gbps | software AES, generic CPU |
| tokio + GSO/GRO (--offload) | 1.60 Gbps | software AES, 208 KB socket buffers |
| tokio parallel (default) | 1.24 Gbps | software AES |

### Industry Context

| Implementation | Throughput | Notes |
|----------------|-----------|-------|
| Tailscale wireguard-go | 13.0 Gbps | Go, TUN GSO + GRO + batched syscalls, bare metal |
| MsQuic + XDP | 7.99 Gbps | C, Windows XDP bypass, multi-threaded |
| ngtcp2 + GSO/GRO | 4.94 Gbps | C, kernel-mode with GSO/GRO |
| **quictun DPDK** | **4.97 Gbps** | **Rust, DPDK 25.11 kernel-bypass, virtio VM** |
| quiche (Cloudflare) | ~2-4 Gbps | Rust, used in MASQUE/WARP |

Key insight: **quictun matches ngtcp2 throughput on VM hardware** despite being Rust + single-core DPDK on virtio. On bare metal with real NICs and multi-core, 8+ Gbps is achievable. Protocol overhead is not the bottleneck — packet I/O and hardware crypto acceleration are.

### How Tailscale Achieved 13 Gbps with wireguard-go

This is the most important reference for quictun. A **Go** implementation surpassed in-kernel C WireGuard by exploiting kernel offloads:

| Phase | Technique | Throughput | Delta |
|-------|-----------|-----------|-------|
| Baseline | 1 packet per syscall | 2.42 Gbps | — |
| Phase 1 | `sendmmsg`/`recvmmsg` + larger TUN MTU | 5.36 Gbps | +2.2x |
| Phase 2 | **UDP GSO/GRO on outer socket** | 8.36 Gbps | +1.6x |
| Phase 3 | Crypto vector batching + checksum unrolling | 11.3 Gbps | +1.4x |
| Phase 4 | **TUN UDP GSO/GRO** (kernel 6.2+) | **13.0 Gbps** | +1.2x |

Hardware: i5-12400 bare metal, Mellanox 25G NICs. In-kernel WireGuard on same hardware: 11.8 Gbps.

**Our hardware for context**: AMD Ryzen 9700X (Zen 5), Proxmox KVM VM (vm1: 4 vCPU, vm2: 2 vCPU), virtio NIC, host CPU passthrough (AES-NI + AVX-512). Kernel WireGuard on our VMs: **1.53 Gbps** (vs Tailscale's 11.8 Gbps = 7.7x gap from VM + virtio overhead alone).

**The key insight**: `sendmmsg` = 1 syscall, N stack traversals. **GSO** = 1 syscall, **1** stack traversal, N packets. Per-packet kernel stack traversal is the bottleneck — not crypto, not language speed, not GC.

**For QUIC traffic specifically**, Tailscale measured **4.3x improvement** (2.9 → 12.5 Gbps) from TUN-side UDP GSO/GRO alone (kernel 6.2+ `TUN_F_USO4`/`TUN_F_USO6`).

**Two-sided offloading architecture:**
```
                wireguard-go / quictun
             ┌──────────────────────────┐
             │     encrypt / decrypt     │
             │      (per-packet, irreducible)
             └─────┬──────────────┬─────┘
                   │              │
      TUN SIDE     │              │    UDP SIDE
   (inner packets) │              │  (outer packets)
                   │              │
  ┌────────────┐   │              │   ┌──────────────┐
  │ TSO/GRO    │◄──┘              └──►│ UDP GSO/GRO  │
  │ USO/GRO    │                      │ (sendmmsg)   │
  │(kernel 6.2)│                      │(kernel 4.18) │
  └─────┬──────┘                      └──────┬───────┘
        │                                    │
   TUN device                           UDP socket
   IFF_VNET_HDR                         UDP_SEGMENT
   virtio_net_hdr                       UDP_GRO
```

Both sides are independently optimizable. Crypto is irreducible (must touch every packet), but **everything else is amortizable**.

**Applicability to quictun:**
- **Outer UDP side**: Quinn already uses `quinn-udp` with `UDP_SEGMENT` (GSO) and `UDP_GRO`. Already optimized.
- **Inner TUN side**: **NOT optimized — this is our biggest bottleneck.** Every TUN `read()`/`write()` handles one packet. `tun-rs` already supports `.offload(true)` with `IFF_VNET_HDR`. Enabling this could push tokio from **1.30 Gbps → 3-5 Gbps** without DPDK.

**Kernel version requirements:**

| Feature | Kernel | What It Does |
|---------|--------|-------------|
| TSO on TUN (TCP inner) | v2.6.27+ | TCP super-packets through TUN |
| UDP GSO on socket (outer) | v4.18+ | Batched outer UDP sends |
| UDP GRO on socket (outer) | v5.0+ | Coalesced outer UDP receives |
| **USO on TUN (UDP/QUIC inner)** | **v6.2+** | **UDP super-packets through TUN — critical for QUIC** |
| rx-udp-gro-forwarding | v6.2+ | GRO preservation for VPN forwarding |

### Bottleneck Hierarchy

At 4.97 Gbps vs 26.8 Gbps raw NIC (18.5%), the remaining bottleneck hierarchy:

1. **VM virtio NIC** — single RSS queue prevents multi-core scaling. The ~5 Gbps ceiling is likely the virtio NIC limit with host CPU passthrough.
2. **quinn-proto single-threaded processing** — QUIC decrypt + state machine + encrypt all on one core
3. **Software AES without AES-NI** — previous 2.22 Gbps ceiling was caused by QEMU generic CPU lacking AES-NI. Host CPU passthrough (+AES-NI + AVX-512 VAES) → 4.97 Gbps (+124%).
4. **QUIC protocol overhead vs WireGuard** — header protection, congestion control, ACK tracking, flow control. Proved minimal: DPDK is 3.2x faster than kernel WireGuard despite heavier protocol.

**Tested and ruled out:**
- **`--cc none`** (disable congestion control): negligible improvement. CC overhead is not a significant bottleneck.

**QUIC header protection explained**: Uses AES-ECB as a PRF (pseudorandom function) to XOR-mask the packet number + header flags. Not "encryption" in the traditional sense — just one AES block operation per packet to prevent middlebox ossification. AES-GCM would be wasteful (needs nonce/IV/auth tag for a 5-byte mask). ECB's usual weakness (identical input → identical output) doesn't apply because input is sampled from unique ciphertext. Cost: ~1% CPU overhead per IETF discussion, but adds up at high packet rates.

---

## DPDK 25.11 Key Features for QuicTun

Upgrading from system packages (~23.11) to DPDK 25.11.0 LTS unlocks several critical features.

### Virtio-User Inner Interface (vhost-net) — TAP/AF_XDP Replacement [DONE]

**Implemented and benchmarked.** `--dpdk virtio` uses virtio-user backed by vhost-net. Now built with DPDK 25.11 LTS from source (static linking). **4.97 Gbps** with host CPU passthrough (AES-NI + AVX-512).

```
--vdev=net_virtio_user0,path=/dev/vhost-net,iface=tunnel,queues=1,queue_size=1024
```

| Feature | TAP PMD | AF_XDP+veth (deprecated) | Virtio-User + vhost-net |
|---------|---------|--------------------------|------------------------|
| Throughput | 1.94 Gbps* | 4.86 Gbps | **4.97 Gbps** |
| Multi-queue | 1 TAP per core | Not supported | **Native kthreads per queue** |
| Checksum offload | Software (AVX2) | Software (AVX2) | **vhost-net (kernel)*** |
| TSO/LRO | Not available | Not available | **Yes** |
| Setup complexity | Simple | High (veth + ethtool + BPF) | **Simple** |
| Reliability | Good | Fragile (ethtool regression) | **Good** |

*TAP PMD not re-benchmarked with host CPU. On our virtio VMs, `hw_ip_cksum=false` forces software fallback. Bare-metal NICs should report full offload.

**DPDK 25.11 adds:** multi-queue virtio-user (needs source build), which enables scaling with `queues=N` via native vhost-net kthreads — no eBPF RSS hacks needed.

### Memif PMD — Shared Memory (15x Packet Rate)

Shared-memory interface between DPDK processes. Calico/VPP benchmarks: **15 Mpps** (vs ~1 Mpps for veth AF_PACKET).

```
--vdev=net_memif0,role=server,socket=/tmp/quictun.sock
```

| Aspect | Details |
|--------|---------|
| Architecture | Server/client over Unix socket (control), shared memory (data) |
| Zero-copy | Yes (client-only, requires `--single-file-segments`) |
| Buffer size | 2048 default, configurable |
| Ring size | 1024 default (2^1 to 2^14) |
| Throughput | 15 Mpps single thread (Calico/VPP bench) |

**Limitation**: App side needs libmemif — not a drop-in for general VPN use. But **perfect for router mode** where both sides are DPDK-controlled, and for controlled environments (container-to-container, service mesh).

With Intel DSA DMA offload, memif achieves **2.33-2.63x** additional throughput improvement on copy operations.

### SORING — Staged-Ordered-Ring (25.03)

New ring library for multi-stage pipeline processing with order preservation:

```
Stage 1: RX burst + parse    (N cores)
    |
    v  [SORING - preserves packet order]
Stage 2: QUIC crypto          (N cores)
    |
    v  [SORING - preserves packet order]
Stage 3: TX burst + inner TX  (N cores)
```

**Why this matters**: quinn-proto is single-threaded per connection. SORING enables splitting the hot path across cores while maintaining QUIC packet number ordering. This is the architectural path to scaling past the single-core bottleneck.

### `rte_thash_gen_key` — Optimized RSS Hash Keys (24.11)

Generates Toeplitz hash keys optimized for specific tuple fields. Directly addresses our multi-core hash distribution problem:

```c
// Generate RSS key that maximizes distribution on UDP source port
rte_thash_gen_key(rss_key, key_len,
    reta_log2,          // log2 of RSS redirection table size
    sport_bit_offset,   // offset of source port in 5-tuple
    16);                // 16 bits (port size)
```

Our current multi-core mode (`--dpdk-cores N`) suffers from poor hash distribution with few QUIC flows because the default random RSS key doesn't distribute well on UDP port ranges. This function generates mathematically optimal keys.

### TAP PMD Improvements (25.11)

| Feature | Impact |
|---------|--------|
| Netlink-based link control | Replaces ioctl — more reliable link up/down |
| Device rename without breaking link | Fixes stale interface name bugs |
| Namespace migration (Linux >= 5.2) | Move TAP into container namespace |
| `persist` flag | TAP survives app restart — graceful upgrades |

### Per-Lcore Variables (24.11)

New `RTE_LCORE_VAR` API — per-core data organized spatially for cache efficiency. Eliminates false sharing between engine threads. ~98 MB memory savings in typical deployments vs padded arrays.

### Other Improvements

| Feature | Version | Impact |
|---------|---------|--------|
| FD limit: 8 → 253 | 24.11 | More TAP/AF_XDP queues for multi-core |
| Lcore ID remapping (`-R`) | 25.11 | Simplified multi-core thread management |
| Mbuf lifecycle tracking | 25.11 | Debug buffer leaks (debug-only) |
| `rte_free_sensitive()` | 25.07 | Secure zeroing for QUIC key material |
| Hardened alloc functions | 25.03 | Compile-time double-free detection |
| Systemd journal logging | 24.11 | `--log-timestamp`, `--log-color` |
| Per-queue stats removed | 25.11 | **Breaking**: must migrate to xstats API |

### What Won't Help

| Feature | Why |
|---------|-----|
| AF_XDP + veth (inner) | **Deprecated.** Virtio-user matches throughput (2.22 vs 2.25 Gbps) with simpler setup. AF_XDP+veth had reliability issues (ethtool regression). veth cannot do zero-copy AF_XDP. |
| DPDK GSO library | TCP-only. "UDP GSO" is just IP fragmentation — useless for QUIC (needs per-segment UDP headers). |
| DPDK GRO library | "UDP GRO" is IP fragment reassembly — not true GRO. Cannot merge independent UDP datagrams. |
| TAP PMD GSO/GRO | TAP PMD does **not** use `IFF_VNET_HDR`. No kernel GSO/GRO support. Only TCP TSO via userspace `rte_gso_segment()`. |
| QAT crypto PMD | Needs bare-metal QAT hardware. Not available in VM. AES-NI via aws-lc-rs is already fast. |
| Post-quantum crypto | ML-KEM/ML-DSA not relevant for QUIC TLS 1.3 today. |

---

## Roadmap Items

### 1. ~~Enable TUN GSO/GRO in Tokio Data Plane~~ [DONE]

**Completed Feb 2026.** `--offload` flag enables TUN GSO/GRO via tun-rs `recv_multiple`/`send_multiple`.

**Result:** 1.24 → 1.60 Gbps (+29%), retransmits 1456 → 16 (-99%). At parity with kernel WireGuard (1.62 Gbps) on virtio VMs. See [bench-003](docs/bench-003-tun-gso-gro-offload.md).

### 2. Profile and Find Bottlenecks [Priority: Highest]

Before optimizing further, we need hard data on where CPU time goes.

**Approach:**
- `perf record` + flamegraph during iperf3 through DPDK tunnel
- `perf stat` hardware counters (IPC, cache misses, branch misprediction)
- Instrument quinn-proto: time spent in `handle_event()`, `poll_transmit()`, crypto
- Measure packets/sec (not just Gbps) to distinguish CPU-per-packet vs CPU-per-byte bottleneck
- Test with encryption bypassed to isolate crypto cost vs protocol cost

**Key questions to answer:**
- What % of CPU is crypto (AES-GCM + header protection)?
- What % is quinn-proto state machine (CC, loss detection, ACK)?
- What % is mbuf alloc/copy?
- What % is polling overhead (DPDK) or syscall overhead (tokio)?

**Low-hanging fruit to try:**
- Add jemalloc (`jemallocator` crate) — rustls benchmarks show 2x throughput improvement over glibc malloc
- Quinn segment size tuning — larger segments nearly doubled throughput in research papers
- Profile-guided optimization (PGO) build

### 3. ~~Benchmark Virtio-User as Inner Interface (DPDK)~~ [DONE — Initial]

**Completed Feb 2026.** `--dpdk virtio` mode uses virtio-user + vhost-net as inner interface.

**Result:** 2.22 Gbps — matches AF_XDP (2.25 Gbps), +14% over TAP PMD (1.94 Gbps). Works with system DPDK 23.11, no source build needed. See [bench-003](docs/bench-003-tun-gso-gro-offload.md).

**Remaining work:**
- Multi-queue virtio-user (`queues=N`) — needs DPDK 25.11 source build and multi-queue HW
- TSO/checksum offload tuning — `hw_ip_cksum=false` on virtio VMs, bare metal should report full offload
- Bare-metal benchmarks to validate offload potential beyond VM ceiling

**AF_XDP+veth deprecated.** Virtio-user matches AF_XDP throughput with simpler setup (single `--vdev` arg, no veth pair, no ethtool hacks, no BPF). AF_XDP+veth had reliability issues (netlink ethtool rewrite caused silent regression). Virtio-user is the recommended DPDK inner interface going forward.

### 4. Build DPDK From Source (25.11 LTS) [Priority: High]

**Current:** system `apt install dpdk` (likely 23.11.x)
**Target:** DPDK 25.11.0 LTS (released Nov 30, 2025, EOL Dec 2028)

#### Build Prerequisites

```bash
# Build tools
sudo apt install -y build-essential meson ninja-build python3-pyelftools \
    libnuma-dev pkg-config python3-pip

# AF_XDP PMD dependencies
sudo apt install -y libxdp-dev libbpf-dev

# Verify meson version (>= 0.57 required)
meson --version
```

#### Build from Source

```bash
DPDK_VERSION="25.11"
DPDK_PREFIX="/opt/dpdk"

# Download
wget https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz
tar xJf dpdk-${DPDK_VERSION}.tar.xz
cd dpdk-${DPDK_VERSION}

# Configure — only build PMDs we actually use
meson setup build \
    --prefix=${DPDK_PREFIX} \
    -Dplatform=native \
    -Ddefault_library=static \
    -Denable_drivers=bus/pci,bus/vdev,mempool/ring,net/virtio,net/af_xdp,net/tap,net/vhost \
    -Ddisable_apps=* \
    -Dtests=false \
    -Dexamples='' \
    -Denable_docs=false \
    -Dmax_lcores=128

# Build and install
ninja -C build -j$(nproc)
sudo ninja -C build install
sudo ldconfig
```

**Meson options explained:**

| Option | Value | Why |
|--------|-------|-----|
| `--prefix` | `/opt/dpdk` | Isolated install, won't conflict with system packages |
| `-Dplatform=native` | `-march=native` | DPDK headers use SSSE3/SSE4/AVX intrinsics |
| `-Ddefault_library=static` | `.a` archives | Single binary deployment, no `LD_LIBRARY_PATH` needed |
| `-Denable_drivers=...` | 7 drivers | PCI bus, vdev bus, ring mempool, virtio, AF_XDP, TAP, **vhost** |
| `-Ddisable_apps=*` | Skip all apps | Don't need testpmd/dpdk-devbind in a library-only build |
| `-Dtests=false` | Skip tests | Saves significant compile time |
| `-Dmax_lcores=128` | 128 cores max | Generous for VMs; reduce to 16 for smaller footprint |

#### Verify Installation

```bash
export PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig
pkg-config --modversion libdpdk    # Should print "25.11.0"
pkg-config --cflags libdpdk        # Include paths
pkg-config --static --libs libdpdk # Static link flags (should include --whole-archive)
```

Note: the exact lib subdirectory varies by distro. Ubuntu uses `lib/x86_64-linux-gnu`, Fedora/RHEL uses `lib64`.

#### Build quictun Against Custom DPDK

```bash
# Option 1: env var per build
PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig cargo build --release

# Option 2: persistent in .cargo/config.toml
cat >> .cargo/config.toml << 'EOF'
[env]
PKG_CONFIG_PATH = "/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig"
EOF
cargo build --release
```

#### build.rs Changes Needed

Current `build.rs` uses `pkg_config::Config::new().probe("libdpdk")` which works for both system and custom installs as long as `PKG_CONFIG_PATH` is set. Changes needed for source build:

1. **Static linking**: add `.statik(true)` to pkg-config probe for static DPDK builds
2. **Conditional AF_XDP linking**: the explicit `cargo:rustc-link-lib=rte_net_af_xdp` will fail if AF_XDP PMD wasn't built (e.g., missing libxdp). Make it conditional.
3. **rerun-if-changed for headers**: add `cargo:rerun-if-changed=csrc/shim.h` so bindgen regenerates when headers change (fixes the `cargo clean` requirement)

```rust
// Proposed build.rs changes
let dpdk = pkg_config::Config::new()
    .statik(true)  // for -Ddefault_library=static builds
    .probe("libdpdk")
    .expect("pkg-config: libdpdk not found");

// Conditional AF_XDP linking
if dpdk.libs.iter().any(|l| l.contains("af_xdp")) {
    println!("cargo:rustc-link-lib=rte_net_af_xdp");
}

// Fix incremental rebuild
println!("cargo:rerun-if-changed=csrc/shim.h");
println!("cargo:rerun-if-changed=csrc/shim.c");
```

#### Static Linking Note

With `-Ddefault_library=static`, DPDK PMDs register via `__attribute__((constructor))`. The `pkg-config --static --libs` output includes `-Wl,--whole-archive` flags to prevent the linker from stripping these constructors. The `pkg_config` Rust crate handles this correctly when `.statik(true)` is set.

#### AF_XDP Runtime Note

AF_XDP PMD requires `libxdp` at build time. If meson can't find it, `net/af_xdp` is silently skipped. Check the build log:
```bash
grep af_xdp build/meson-logs/meson-log.txt
```

For AF_XDP at runtime, set `LIBXDP_OBJECT_PATH` if libxdp BPF objects aren't in the default location:
```bash
export LIBXDP_OBJECT_PATH=/usr/local/lib/bpf
```

### 5. Proper Daemon Mode and Lifecycle Hooks [Priority: High]

Replace the current simple `up`/`down` with production-ready lifecycle management.

**Config format (WireGuard-style hooks):**
```toml
[interface]
private_key = "..."
address = "10.0.0.1/24"
listen_port = 443

# Lifecycle hooks (optional)
pre_up = "ip route add ..."
post_up = "iptables -A FORWARD ..."
pre_down = "iptables -D FORWARD ..."
post_down = "ip route del ..."

[peer]
public_key = "..."
endpoint = "203.0.113.1:443"
allowed_ips = ["10.0.0.0/24"]
```

**Features:**
- **Daemon mode**: `quictun up --daemon` — fork to background, write PID file
- **Signal handling**: SIGTERM/SIGINT → graceful shutdown (PreDown, PostDown)
- **PID file**: `/run/quictun/<interface>.pid`
- **Hooks**: `PreUp`, `PostUp`, `PreDown`, `PostDown` — shell commands run at lifecycle points
- **Auto NIC binding (DPDK)**: bind PCI device to vfio-pci via sysfs writes before EAL init — no `dpdk-devbind.py` or Python runtime needed. Just `modprobe vfio-pci` + sysfs `unbind`/`bind`. Could be built into quictun startup or provided as a default PreUp hook.
- **Remove `Command`**: current `down` command uses PID file + SIGTERM; hooks replace ad-hoc scripting
- **Systemd unit**: `quictun@.service` template for per-tunnel management

### 6. Full DPDK Router Mode + Memif [Priority: Medium]

Current architecture: DPDK outer + TUN/TAP/veth inner (kernel-visible for local apps).
New mode: DPDK on **both** sides — the host acts as a router/gateway, not an endpoint.

```
LAN hosts                                          Remote LAN hosts
    |                                                    |
    v                                                    v
Physical NIC 1 (DPDK PMD)                    Physical NIC 1 (DPDK PMD)
    |                                                    |
    v                                                    v
DPDK engine (quinn-proto encrypt)  <---QUIC--->  DPDK engine (quinn-proto decrypt)
    |                                                    |
    v                                                    v
Physical NIC 2 / memif / same NIC            Physical NIC 2 / memif / same NIC
    |                                                    |
    v                                                    v
Remote network / DPDK app                    Local network / DPDK app
```

**Benefits:**
- Zero kernel involvement in data path — eliminates inner-side bottleneck entirely
- True wire-speed potential (limited only by crypto throughput)
- Suitable for dedicated VPN appliance / gateway deployments

**Inner interface options for router mode:**

| Interface | Use Case | Performance |
|-----------|----------|-------------|
| Physical NIC (DPDK PMD) | 2-NIC gateway box | Wire speed |
| Memif (shared memory) | DPDK-to-DPDK, VPP integration | 15 Mpps single thread |
| Same NIC (VLAN) | Single-NIC with VLAN separation | Wire speed |

**Memif for controlled environments:**
```bash
# quictun side (server)
--vdev=net_memif0,role=server,socket=/tmp/quictun.sock

# App side (client, using libmemif or another DPDK process)
--vdev=net_memif0,role=client,socket=/tmp/quictun.sock
```

**Requirements:**
- 2 NICs (or VLAN-based separation, or memif for DPDK-to-DPDK)
- L2/L3 forwarding logic in DPDK engine
- Routing table for allowed_ips → inner/outer decision
- ARP handling on both sides
- Cannot serve regular kernel apps on the same host (dedicated box, unless memif bridge)

**CLI:**
```bash
sudo quictun up tunnel.toml \
  --dpdk router \
  --dpdk-outer-port 0 --dpdk-inner-port 1 \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11

# Or with memif inner
sudo quictun up tunnel.toml \
  --dpdk router \
  --dpdk-inner memif --dpdk-memif-socket /tmp/quictun.sock \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11
```

### 7. Multi-Core Pipeline with SORING [Priority: Medium]

Current single-threaded bottleneck: RX → QUIC process → TX all on one core.
SORING (Staged-Ordered-Ring, DPDK 25.03) enables ordered multi-stage pipeline:

```
                    ┌─── Core 0 ───┐
RX burst ──────────>│ QUIC decrypt  │──────────> Inner TX
(1 core, fast)      │ + state       │           (1 core)
                    ├─── Core 1 ───┤
                    │ QUIC decrypt  │
                    │ + state       │
                    ├─── Core 2 ───┤
                    │ QUIC decrypt  │
                    │ + state       │
                    └───────────────┘
                     Order preserved
                     by SORING
```

**Challenge**: quinn-proto connection state is not thread-safe. Options:
1. Multiple QUIC connections (one per core) — requires cooperative multi-stream from both sides
2. Separate crypto from protocol processing — crypto stage is stateless and parallelizable
3. Lock-free sharding by connection ID

**Dependency**: Profiling (#1) must confirm that quinn-proto/crypto is the bottleneck, not inner interface. If inner interface is the wall, virtio-user (#2) is the right fix.

### 8. Optimized RSS Hash Keys [Priority: Low → High with Multi-Queue HW]

Use `rte_thash_gen_key()` (DPDK 24.11) to generate Toeplitz hash keys optimized for QUIC UDP source port distribution.

**Current problem**: With `--dpdk-cores N`, RSS distributes poorly with few flows because the default random RSS key doesn't maximize entropy on UDP port ranges.

**Fix:**
```c
// C shim addition
void shim_generate_rss_key(uint8_t *key, size_t key_len,
                           uint32_t reta_log2) {
    // Optimize for UDP source port (highest entropy field in QUIC)
    rte_thash_gen_key(key, key_len, reta_log2,
        UDP_SPORT_BIT_OFFSET, 16);
}
```

**Blocked on**: Multi-queue hardware. VM virtio NIC (ens19) only supports 1 queue. Need Proxmox `multiqueue=N` or bare-metal NIC to test.

### ~~9. Inner Interface Research~~ [RESOLVED]

**Resolved: virtio-user wins.** Benchmarked at 2.22 Gbps — matches AF_XDP, simpler setup, better bare-metal potential. No further inner interface research needed. AF_XDP+veth deprecated.

---

## Priority Summary

| # | Item | Priority | Expected Impact | Effort | Status |
|---|------|----------|----------------|--------|--------|
| 1 | ~~TUN GSO/GRO (tokio)~~ | — | 1.24 → 1.60 Gbps (+29%) | — | **DONE** |
| 2 | Profile bottlenecks | **Highest** | Determines remaining priorities | Low | |
| 3 | ~~Virtio-user inner (DPDK)~~ | — | 2.22 Gbps (+14% vs TAP) | — | **DONE (initial)** |
| 4 | Build DPDK 25.11 from source | High | Multi-queue virtio-user, SORING | Medium | |
| 5 | Daemon mode + hooks | High | Production readiness | Medium | |
| 6 | Router mode + memif | Medium | Zero-kernel data path | High | |
| 7 | SORING multi-core pipeline | Medium | Scale past single-core | High | |
| 8 | Optimized RSS hash keys | Low* | Better multi-core distribution | Low | |
| ~~9~~ | ~~Inner interface research~~ | — | — | — | **Resolved**: virtio-user wins |

*Priority 8 becomes High once multi-queue hardware is available.

**Key realizations (updated Feb 27)**:
- **TUN GSO/GRO closes the gap**: tokio + `--offload` matches kernel WireGuard (1.60 vs 1.62 Gbps) on VMs. The userspace overhead is eliminated.
- **Virtio-user replaces AF_XDP**: same throughput (2.22 vs 2.25 Gbps), much simpler, better bare-metal potential. AF_XDP+veth is deprecated.
- **DPDK inner interface is solved**: virtio-user is the answer. Remaining DPDK work is multi-queue + multi-core (needs DPDK 25.11 source build).
- **Two production paths**: tokio + `--offload` (simple, no dependencies) vs DPDK + virtio-user (higher throughput, more complexity).
- **All our benchmarks are VM-limited.** Bare-metal testing would reveal the true potential of both paths.

---

## Dependency Versions

### Current (Feb 2026)

| Component | Cargo.toml spec | Cargo.lock resolved | Latest available |
|-----------|----------------|--------------------|-----------------|
| quinn | 0.11 | 0.11.9 | 0.11.9 |
| quinn-proto | 0.11 | 0.11.13 | 0.11.13 |
| rustls | 0.23.20 | 0.23.36 | 0.23.37 |
| aws-lc-rs | 1 | 1.16.0 | 1.16.0 |
| DPDK | system apt | ~23.11 | **25.11.0 LTS** |

### Notes

- **rustls**: 1 patch behind (0.23.36 vs 0.23.37). 0.23.37 adds ML-KEM-1024 support. Run `cargo update -p rustls` to update.
- **rustls 0.24**: dev pre-release exists (0.24.0-dev.0, Jan 28 2026). Breaking change coming — monitor but don't adopt yet.
- **Post-quantum**: rustls 0.23.27+ prefers PQ key exchange (X25519MLKEM768) by default. Already active in our lock (0.23.36). One-time handshake cost only, negligible for long-lived VPN tunnels.
- **quinn**: `Connection::set_send_window()` added in 0.11.9 — useful for tuning throughput.
- **quinn-proto**: `max_datagrams` fix in 0.11.11 — correctly respects our `max_datagrams=10` GSO setting.
- **aws-lc-rs 1.15.3**: CMake no longer required for non-FIPS builds — simplifies build dependencies.
- **DPDK 25.11.0 LTS**: latest LTS, released Nov 30, 2025, EOL Dec 2028. Previous LTS: 24.11 (latest point release 24.11.4).

---

## Profiling Toolkit

Tools to use for bottleneck analysis (#1):

| Tool | Purpose | When to use |
|------|---------|-------------|
| `perf record` + flamegraph | CPU hotspot identification | First pass — where are cycles spent? |
| `perf stat` | Hardware counters (IPC, cache, branches) | Classify: compute-bound vs memory-bound |
| DPDK telemetry | Packet/byte/drop counters | Non-invasive runtime monitoring |
| Intel VTune | Microarchitectural analysis | If available — cache line contention, NUMA |
| `cargo-flamegraph` | Rust-aware flamegraphs | Easier setup than raw perf |
| Cachegrind | Cache behavior simulation | Targeted analysis of quinn-proto paths |

**Quick start:**
```bash
# Build with debug symbols
RUSTFLAGS="-C debuginfo=2" cargo build --release

# Record during iperf3 test
perf record -g -F 99 -p $(pidof quictun) -- sleep 30
perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg

# Hardware counters
perf stat -e cache-misses,cache-references,instructions,cycles,branch-misses \
  -p $(pidof quictun) -- sleep 10

# DPDK telemetry (non-invasive, while running)
dpdk-telemetry.py /ethdev/xstats,0
```
