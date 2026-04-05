# QuicTun

> **Status: Experimental** — Under active development. APIs and config format may change.

A high-performance VPN tunnel over QUIC + TLS 1.3

## Why

- **Standards-based** — QUIC (RFC 9000), TLS 1.3 (RFC 8446), QUIC Datagrams (RFC 9221). No custom crypto.
- **FIPS-ready** — All cryptography via aws-lc-rs (FIPS 140-3 Certificate #4631).
- **CA-ready** — RPK for pinned identities by default, but the TLS 1.3 handshake supports full X.509 CA chains for enterprise deployments.
- **Firewall traversal** — UDP 443, indistinguishable from HTTP/3 to DPI.
- **Low overhead** — 20-byte per-packet overhead with zero-length CIDs (vs. WireGuard's 32 bytes).
- **Multiple data planes** — mio (default), DPDK kernel-bypass.

## Quick Start

```bash
# Generate keys
quictun genkey > private.key
quictun pubkey < private.key > public.key

# Run tunnel
sudo quictun up tunnel.toml
```

## Architecture

```
quictun-crypto/   Key generation, serialization, RPK TLS verifiers
quictun-core/     Config, QUIC builders, peer management, NAT, ICMP, routing
quictun-proto/    Custom QUIC 1-RTT data plane (RFC 9000/9001 compliant)
quictun-tun/      Sync TUN device wrapper (tun-rs v2)
quictun-net/      Sync mio engine (default kernel data plane)
quictun-dpdk/     Linux DPDK kernel-bypass data plane
quictun-cli/      CLI binary (genkey, pubkey, up, down)
```

### Protocol Design

The handshake uses standard QUIC (quinn-proto) for connection establishment and TLS 1.3
key exchange. After the handshake completes, the data plane switches to quictun-proto — a
custom 1-RTT implementation optimized for tunnel traffic. It uses the same QUIC packet
format (short header, AEAD encryption, header protection) and is wire-compatible with
RFC 9000 and RFC 9001 for the subset it implements.

**What quictun-proto implements (RFC-compliant):**

- Short header format, header protection, AEAD encrypt/decrypt (RFC 9000/9001)
- DATAGRAM frames (RFC 9221), ACK frames, PING, PADDING, CONNECTION_CLOSE
- Key update via key_phase bit rotation with pre-computed key generations
- Replay protection via sliding-window bitmap (65536 PNs)
- Fixed 4-byte packet number encoding for lock-free parallel encrypt

**Intentionally omitted (by design):**

- Streams, flow control — tunnel is DATAGRAM-only, fire-and-forget
- Loss detection, retransmission — inner TCP handles its own recovery
- Congestion control — avoids double-CC with inner TCP (delay-based CC planned)

**Not yet implemented (planned):**

- Connection migration + PATH_CHALLENGE/RESPONSE — tunnel drops on network change today
- CID rotation — fixed CIDs allow observer tracking; rotation preserves privacy
- Spin bit — passive RTT measurement for operators
- ECN passthrough — useful when delay-based CC is added

**Design note: fixed 4-byte PN.** Standard QUIC uses 1-4 byte variable PN encoding
based on `largest_acked`, creating a TX→RX state dependency. quictun-proto uses fixed
4-byte PN unconditionally: the encoder needs only an atomic counter, no ACK state.
This enables lock-free parallel encrypt across pipeline workers and multi-core DPDK,
and preserves the zero-copy mbuf layout where QUIC header (13) + DATAGRAM type (1) =
14 bytes = Ethernet header size. Cost: 2 extra bytes/pkt for the first ~47ms of a
connection (after that, variable PN would need 3-4 bytes anyway at line rate).

### Data Planes

| Data Plane | Throughput | Notes |
|------------|-----------|-------|
| **DPDK single-core** | **16.0 Gbps** | Zero-copy encrypt + decrypt, 10.5x kernel WireGuard |
| **Kernel + GRO** | **10.7 Gbps** | Default, 2 threads |
| **DPDK router** | **6.95 Gbps** | Single-core, NAT |

Kernel WireGuard: 1.53 Gbps. Tailscale wireguard-go: 7.37 Gbps (same hardware).

See [docs/benchmarks.md](docs/benchmarks.md) for full results.

## Config

### Listener (kernel engine)

```toml
[interface]
mode = "listener"
private_key = "base64-encoded-private-key"
address = "10.0.0.1/24"
listen_port = 443

[engine]
threads = 2                # 1 = single-thread, >1 = multi-core
offload = true             # GRO/GSO (Linux)
cc = "none"                # no congestion control

[[peers]]
public_key = "base64-encoded-public-key"
allowed_ips = ["10.0.0.0/24"]
keepalive = 25
```

### Listener (DPDK engine)

```toml
[interface]
mode = "listener"
private_key = "base64-encoded-private-key"
address = "10.0.0.1/24"
listen_port = 4433
ciphers = ["aes-128-gcm"]

[engine]
backend = "dpdk-virtio"    # or "dpdk-router"
dpdk_local_ip = "10.23.30.100"
dpdk_cores = 1
cc = "none"

[[peers]]
public_key = "base64-encoded-public-key"
allowed_ips = ["10.0.0.2/32"]
keepalive = 25
```

## CLI

```
quictun genkey                  # Generate P-256 ECDSA private key
quictun pubkey                  # Derive public key from stdin
quictun up <config.toml>        # Bring up tunnel
quictun down <config.toml>      # Bring down tunnel
```

## Stack

| Component | Library | Version |
|-----------|---------|---------|
| QUIC | quinn | 0.11.9 |
| QUIC protocol | quinn-proto (forked) | 0.11.13 |
| TLS 1.3 | rustls | 0.23.37 |
| Crypto | aws-lc-rs | 1.16.2 |
| DPDK | source build (static) | 25.11.0 LTS |

ALPN: `quictun-01`

## Building

```bash
# Standard build (all platforms)
cargo build --release

# With DPDK (Linux, requires libdpdk-dev)
PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig cargo build --release
```

Requires Rust 2024 edition. TLS backed by aws-lc-rs (needs cmake + C compiler).

## Third-Party Dependencies

`third_party/quinn/` is a [git subtree](https://www.atlassian.com/git/tutorials/git-subtree) of [quinn-rs/quinn](https://github.com/quinn-rs/quinn) at tag `quinn-0.11.9`. Only `quinn-proto` is patched.

| Patch | Files | Purpose |
|-------|-------|---------|
| Key extraction | `quinn-proto/src/connection/mod.rs` | `take_1rtt_keys()`, CID access for quictun-proto |
| decrypt_in_place | `quinn-proto/src/crypto.rs`, `crypto/rustls.rs` | In-place AEAD decrypt |

### Updating upstream

```bash
git subtree pull --prefix=third_party/quinn \
    https://github.com/quinn-rs/quinn.git <new-tag> --squash
```

Then resolve conflicts and run `cargo test -p quictun-proto`.

## License

Apache-2.0
