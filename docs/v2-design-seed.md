# quictun v2 Architecture — Design Seed

> Captured 2026-04-04 after TUN path production hardening session.
> This is a starting point for the v2 architecture discussion, not a final design.

## 1. Current State

### Crate Structure
```
quictun-crypto    — key gen/serialization, RPK verifiers
quictun-core      — config, QUIC builders, peer ID, routing, session assembly
quictun-tun       — async/sync TUN wrapper (tun-rs v2)
quictun-proto     — custom QUIC 1-RTT data plane
quictun-net       — kernel-mode engine (mio + TUN + UDP)
quictun-dpdk      — DPDK kernel-bypass engine
quictun-cli       — binary (genkey, pubkey, up, down)
```

### Line Counts (2026-04-04)
| File | Lines | Role |
|------|-------|------|
| quictun-net/engine.rs | 1562 | Single-thread kernel engine |
| quictun-net/pipeline.rs | 1582 | Multi-thread kernel engine |
| quictun-dpdk/engine.rs | 2713 | DPDK virtio engine |
| quictun-dpdk/router.rs | 3266 | DPDK router engine |
| quictun-dpdk/dispatch.rs | 286 | DPDK multi-core dispatch |
| quictun-dpdk/event_loop.rs | 848 | DPDK event loop |
| **Total engine code** | **~10,250** | |

### Duplication Problem

These functions are **copy-pasted** across engine.rs, pipeline.rs, and DPDK:

| Logic | Lines per copy | Copies |
|-------|---------------|--------|
| Connection table (ConnEntry struct + management) | ~30 | 3 |
| Handshake promotion (identify_peer, reconnect eviction, max_peers) | ~75 | 3 |
| Timeout/keepalive sweep | ~60 | 3 |
| Key exhaustion check | ~10 | 2 |
| Route cleanup on close | ~5 | 4 (Linux/non-Linux × single/pipeline) |
| TUN + UDP + signal setup | ~50 | 2 |
| ACK timer | ~15 | 2 |
| Stats timer | ~10 | 1 (missing from pipeline) |
| **~300 lines of identical logic duplicated** | | |

### What's Already Clean

- **quictun-proto**: QUIC 1-RTT protocol — fully standalone, no I/O
- **quictun-core/peer.rs**: Unified `identify_peer()` handles both RPK and X.509
- **quictun-core/routing.rs**: `RoutingTable` with longest-prefix matching
- **quictun-core/session.rs**: Config assembly, peer resolution
- **quictun-core/quic_state.rs**: Multi-client handshake state machine
- **Auth separation**: Engine is fully auth-agnostic (no x509/rpk branching)

## 2. Proposed Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Orchestration                                  │
│                                                          │
│  CLI (up/down/status), future web control plane,         │
│  lifecycle hooks (post_up/pre_down), PID management      │
│                                                          │
│  Crate: quictun-cli (today), future: quictun-api         │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Engine (connection management)                 │
│                                                          │
│  Connection table, handshake promotion, peer ID,         │
│  routing (CID lookup), timeouts, keepalives,             │
│  key exhaustion, reconnect eviction, stats               │
│                                                          │
│  PLATFORM-AGNOSTIC. No TUN, no UDP, no DPDK.            │
│  Takes trait objects for I/O operations.                  │
│                                                          │
│  Crate: quictun-core/engine.rs (new module)              │
├─────────────────────────────────────────────────────────┤
│  Layer 2: I/O Adapter                                    │
│                                                          │
│  Reads/writes packets. Calls engine for processing.      │
│  Owns platform-specific resources and optimizations.     │
│                                                          │
│  Responsibilities per adapter:                           │
│  - Packet I/O (TUN/UDP/DPDK ports)                      │
│  - OS route management (netlink / PF_ROUTE / userspace)  │
│  - ARP handling (kernel-managed / userspace)             │
│  - Batch optimizations (GRO/GSO, recvmmsg, DPDK burst)  │
│  - Multi-core dispatch (threading, multi-queue)          │
│  - Signal handling                                       │
│                                                          │
│  Implementations:                                        │
│  - quictun-net: kernel TUN + UDP via mio                 │
│  - quictun-dpdk: DPDK ports + TAP/virtio                │
│  - future: io_uring, XDP                                 │
│                                                          │
│  Each adapter implements a trait interface:               │
│  - send_outer(packet, addr)                              │
│  - recv_outer() -> (packet, addr)                        │
│  - send_inner(packet) [to TUN/TAP]                       │
│  - recv_inner() -> packet [from TUN/TAP]                 │
│  - add_os_route(dst_net, ifindex)                        │
│  - remove_os_route(dst_net, ifindex)                     │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Crypto / Protocol                              │
│                                                          │
│  QUIC 1-RTT packet encode/decode, AEAD encrypt/decrypt,  │
│  key rotation, packet numbers, replay protection, ACKs   │
│                                                          │
│  Crate: quictun-proto (already clean)                    │
├─────────────────────────────────────────────────────────┤
│  Layer 0: Auth / Config                                  │
│                                                          │
│  TLS handshake (RPK/X.509), config parsing, peer         │
│  resolution, cipher selection, transport tuning           │
│                                                          │
│  Crate: quictun-core (config, connection, session, peer) │
│  Crate: quictun-crypto (keys, RPK verifiers)             │
└─────────────────────────────────────────────────────────┘
```

## 3. Key Design Decisions

### Auth is fully decoupled (done in this session)
- Engine calls `identify_peer(conn, peers)` — handles both RPK and X.509 internally
- No auth_mode branching in engine code
- Tunnel IP always from config, never from certificates

### Two routing tables at different layers
| | Layer 3 (Engine) | Layer 2 (I/O Adapter) |
|---|---|---|
| **Purpose** | Map dest IP → peer CID for egress encryption | Tell OS kernel to send packets to TUN device |
| **Implementation** | `RoutingTable` (quictun-core/routing.rs) | netlink `RTM_NEWROUTE` (Linux), `PF_ROUTE` `RTM_ADD` (macOS), userspace (DPDK) |
| **When populated** | On handshake completion | On TUN device creation |
| **Example** | `10.0.0.2 → CID 0xABCD` | `ip route add 10.0.0.0/24 dev tunnel` |

### Per-connection threading for multi-core scaling
```
┌──────────────┐
│  I/O Thread   │  UDP recvmmsg → CID parse → dispatch to worker
│               │  Also: handshake packets → quic_state
├──────────────┤
│  Worker 0     │  Owns connections A, B
│               │  decrypt → is_allowed_source → write to TUN
│  Worker 1     │  Owns connections C, D
│               │  decrypt → is_allowed_source → write to TUN
├──────────────┤
│  TUN Reader   │  TUN read → route lookup → dispatch to worker
│               │  Worker encrypts → UDP sendmmsg
└──────────────┘
```

Why per-connection over multi-queue-only:
- Multi-queue TUN has hash distribution problem: all QUIC packets = one UDP flow = one queue
- Per-connection is portable (no OS-specific requirements)
- Already proven in DPDK pipeline (I/O core + worker cores)
- Multi-queue TUN can optimize TUN egress WITHIN this model

### I/O optimizations compose in Layer 2
These are all Layer 2 concerns, orthogonal to engine logic:
- GRO/GSO (TUN offload)
- recvmmsg/sendmmsg (batch syscalls)
- Multi-queue TUN (parallel TUN read/write)
- SO_REUSEPORT (parallel UDP receive)
- DPDK burst mode
- io_uring submission queues

## 4. What Each Layer Owns

| Concern | Layer | Notes |
|---------|-------|-------|
| Config parsing | 0 | quictun-core/config.rs |
| TLS handshake (RPK/X.509) | 0 | quictun-core/connection.rs |
| Peer resolution (keys/CN) | 0 | quictun-core/session.rs |
| AEAD encrypt/decrypt | 1 | quictun-proto |
| Packet number management | 1 | quictun-proto |
| Key rotation | 1 | quictun-proto |
| Replay protection | 1 | quictun-proto |
| TUN device creation | 2 | quictun-tun (or DPDK TAP) |
| UDP socket creation | 2 | mio (or DPDK port) |
| OS route add/remove | 2 | netlink/PF_ROUTE/userspace |
| ARP management | 2 | kernel-managed / DPDK userspace |
| GRO/GSO batching | 2 | TUN offload flag |
| recvmmsg/sendmmsg | 2 | Linux batch syscall |
| Signal handling | 2 | self-pipe trick |
| Multi-core dispatch | 2 | per-connection threading |
| Connection table | 3 | `FxHashMap<CID, ConnEntry>` |
| Handshake promotion | 3 | identify_peer → insert connection |
| Peer routing (CID lookup) | 3 | `RoutingTable::lookup(dest_ip)` |
| Timeout/keepalive sweep | 3 | periodic, checks last_rx |
| Key exhaustion detection | 3 | checks `is_key_exhausted()` |
| Reconnect eviction | 3 | same tunnel_ip → evict old CID |
| max_peers enforcement | 3 | reject if at capacity |
| Stats logging | 3 | periodic counters |
| PID file management | 4 | quictun-cli/state.rs |
| post_up/pre_down hooks | 4 | shell command execution |
| Reconnect loop + backoff | 4 | quictun-cli/up.rs |

## 5. Platform Abstraction (Trait Sketch)

```rust
/// Layer 2 I/O adapter interface.
///
/// The engine (Layer 3) calls these methods without knowing
/// whether the underlying I/O is TUN+UDP, DPDK, or io_uring.
trait DataPlaneIo {
    /// Send an encrypted packet to a remote peer (outer network).
    fn send_outer(&self, packet: &[u8], remote: SocketAddr) -> io::Result<()>;

    /// Send a decrypted packet to the local network (inner/TUN).
    fn send_inner(&self, packet: &[u8]) -> io::Result<()>;

    /// Add an OS-level route (e.g., netlink RTM_NEWROUTE).
    fn add_route(&self, dst: Ipv4Net) -> io::Result<()>;

    /// Remove an OS-level route.
    fn remove_route(&self, dst: Ipv4Net) -> io::Result<()>;
}

/// Batch variant for high-throughput adapters.
trait DataPlaneIoBatch: DataPlaneIo {
    fn send_outer_batch(&self, packets: &[IoVec], remote: SocketAddr) -> io::Result<usize>;
    fn send_inner_batch(&self, packets: &[IoVec]) -> io::Result<usize>;
}
```

The engine loop becomes:
```rust
// Simplified — actual impl handles batching, GSO, etc.
loop {
    let (packet, from) = io.recv_outer()?;
    let decrypted = engine.process_inbound(packet, from)?;
    if let Some(inner_packet) = decrypted {
        io.send_inner(&inner_packet)?;
    }
}
```

## 6. Scaling Strategy

| Peers | Threads | Model |
|-------|---------|-------|
| 1 | 1 | Single-thread (current default) |
| 2-10 | 1-2 | Single-thread likely sufficient |
| 10-100 | 2-4 | Per-connection dispatch |
| 100-1000 | 4-8 | Per-connection + multi-queue TUN egress |
| 1000+ | Consider DPDK | Kernel overhead becomes bottleneck |

## 7. Migration Path

### Phase 1: Extract engine core (quictun-core/engine.rs)
- Move `ConnEntry`, `drive_handshakes`, `handle_timeouts`, `send_acks` into a generic `ConnectionManager<S>`
- `S` = connection state type (`LocalConnectionState` or `SplitConnectionState`)
- engine.rs and pipeline.rs become thin I/O wrappers calling `ConnectionManager`
- **Deletes ~300 lines of duplication**

### Phase 2: Define I/O adapter trait
- Extract `DataPlaneIo` trait from engine.rs I/O operations
- Implement for kernel (mio + TUN + UDP) and DPDK
- Engine calls trait methods instead of direct syscalls

### Phase 3: Route management in I/O adapter
- Implement netlink route add/remove (Linux)
- Implement PF_ROUTE (macOS)
- Engine tells adapter "add route for this peer" via trait
- CLI lifecycle hooks (post_up/pre_down) call adapter

### Phase 4: Per-connection multi-core
- I/O thread reads UDP, dispatches by CID to worker threads
- Workers own subsets of connections
- TUN read thread distributes to workers by route lookup
- Connection manager becomes per-worker instance

## 8. Open Questions

- Should `ConnectionManager` be generic over `S` or use trait objects (`Box<dyn ConnectionState>`)?
- How does the I/O adapter signal "shutdown" to the engine? (Currently signal pipe → mio token)
- DPDK adapter: the existing 7000+ lines have DPDK-specific optimizations (zero-copy, ring buffers). How much can share the trait vs needs custom paths?
- Multi-core: shared connection table (`Arc<RwLock<HashMap>>`) vs per-worker tables with broadcast?
- Should we keep pipeline.rs at all, or replace entirely with per-connection model?

## Benchmarks (2026-04-04 baseline)

| Config | Throughput | Retransmits | Notes |
|--------|-----------|-------------|-------|
| Tailscale wireguard-go | 7.39 Gbps | 33 | Go 1.26.1, latest fork |
| **quictun kernel (2MB buf, GRO)** | **8.51 Gbps** | **34** | **15% faster than WG** |
| quictun kernel (212KB buf) | 7.37 Gbps | 2342 | small buf = retransmits |
| quictun kernel (8MB buf) | 5.3-6.1 Gbps | 13 | bufferbloat |
| DPDK single-core | 16.0 Gbps | — | reverse path |
| DPDK pipeline 2-core | 10.6 Gbps | — | ~3% over single |

VM: AMD Ryzen 9700X (Zen 5), 4 vCPUs, 7.7GB, Proxmox KVM, virtio NIC, AVX-512.
