# QuicTun

A high-performance VPN tunnel over QUIC + TLS 1.3 with Raw Public Keys (RFC 7250). P-256 ECDSA pinned identities, no certificate authorities.

## Why

- **Standards-based** — QUIC (RFC 9000), TLS 1.3 (RFC 8446), QUIC Datagrams (RFC 9221). No custom crypto.
- **FIPS-ready** — All cryptography via aws-lc-rs (FIPS 140-3 Certificate #4631).
- **Firewall traversal** — UDP 443, indistinguishable from HTTP/3 to DPI.
- **Connection migration** — QUIC handles network transitions (Wi-Fi → cellular) without re-handshake.
- **Low overhead** — 20-byte per-packet overhead with zero-length CIDs (vs. WireGuard's 32 bytes).
- **Multiple data planes** — tokio (production), io_uring, DPDK kernel-bypass.

## Quick Start

```bash
# Generate keys
quictun genkey > private.key
quictun pubkey < private.key > public.key

# Run tunnel (tokio, default)
quictun up tunnel.toml

# Run tunnel (DPDK kernel-bypass, Linux)
sudo quictun up tunnel.toml \
  --dpdk \
  --dpdk-local-ip 192.168.100.10 \
  --dpdk-remote-ip 192.168.100.11
```

## Architecture

```
quictun-crypto/   Key generation, serialization, RPK TLS verifiers
quictun-core/     Config, QUIC builders, TUN↔QUIC forwarding loops
quictun-tun/      Async TUN device wrapper (tun-rs v2)
quictun-cli/      CLI binary (genkey, pubkey, up, down)
quictun-uring/    [Experimental] Linux io_uring data plane
quictun-dpdk/     [Experimental] Linux DPDK kernel-bypass data plane
```

### Data Planes

| Data Plane | Backend | Throughput | Maturity |
|------------|---------|-----------|----------|
| **DPDK virtio-user** | quictun-quic + DPDK 25.11 | **14.0 Gbps** | Experimental |
| **DPDK AF_XDP** | quinn-proto + DPDK 25.11 | **4.86 Gbps** | Experimental |
| **tokio + offload** | quinn + tokio + TUN GSO/GRO | 2.59 Gbps | Production |
| **io_uring** | quinn-proto + io_uring | 820 Mbps | Experimental |

Kernel WireGuard reference: 1.53 Gbps (same hardware, same NIC). DPDK is **9.1x faster** than kernel WireGuard. All benchmarks on AMD Ryzen 9700X (AES-NI, AVX-512), Proxmox KVM VM, virtio NIC, host CPU passthrough. Raw NIC: 26.8 Gbps.

See [quictun-dpdk/README.md](quictun-dpdk/README.md) and [quictun-uring/README.md](quictun-uring/README.md) for details.

## Config

```toml
[interface]
private_key = "base64-encoded-private-key"
address = "10.0.0.1/24"
listen_port = 443

[peer]
public_key = "base64-encoded-public-key"
endpoint = "203.0.113.1:443"
allowed_ips = ["10.0.0.0/24"]
```

## CLI

```
quictun genkey                  # Generate P-256 ECDSA private key
quictun pubkey                  # Derive public key from stdin
quictun up <config>             # Bring up tunnel
quictun down <config>           # Bring down tunnel
```

### Key `up` Flags

| Flag | Description |
|------|-------------|
| `--cc {bbr,cubic,newreno,none}` | Congestion control algorithm (default: bbr) |
| `--serial` | Serial forwarding mode (vs parallel) |
| `--queues N` | TUN multi-queue count |
| `--iouring` | io_uring data plane (Linux) |
| `--dpdk [tap\|xdp\|virtio]` | DPDK data plane (Linux) |
| `--offload` | TUN GSO/GRO offload (Linux, kernel 6.2+) |
| `--dpdk-cores N` | Multi-core DPDK engines |
| `--zero-copy` | SendZc zero-copy UDP (io_uring) |
| `--no-udp-checksum` | Skip UDP checksum (benchmarking) |

## Stack

| Component | Library | Version (locked) | Latest |
|-----------|---------|-----------------|--------|
| QUIC | quinn | 0.11.9 | 0.11.9 |
| QUIC protocol | quinn-proto | 0.11.13 | 0.11.13 |
| TLS 1.3 | rustls | 0.23.36 | 0.23.37 |
| Crypto | aws-lc-rs | 1.16.0 | 1.16.0 |
| DPDK | source build (static) | 25.11.0 LTS | 25.11.0 LTS |

ALPN: `quictun-01`

## Building

```bash
# Standard build (tokio data plane, all platforms)
cargo build --release

# Full build with DPDK (Linux, requires libdpdk-dev)
cargo build --release  # quictun-dpdk auto-detects Linux
```

Requires Rust 2024 edition. TLS backed by aws-lc-rs (needs cmake + C compiler).

### DPDK Build Requirements (Linux)

DPDK 25.11.0 LTS built from source at `/opt/dpdk` (statically linked). See [ROADMAP.md](ROADMAP.md) for build instructions.

```bash
# Build quictun with source DPDK
PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig cargo build --release
```

## Third-Party Dependencies

`third_party/quinn/` is a [git subtree](https://www.atlassian.com/git/tutorials/git-subtree) of [quinn-rs/quinn](https://github.com/quinn-rs/quinn) at tag `quinn-0.11.9`. Only `quinn-proto` is patched — rustls and all other dependencies are upstream from crates.io.

Our patches on top of upstream:

| Patch | Files | Purpose |
|-------|-------|---------|
| Key extraction | `quinn-proto/src/connection/mod.rs` | `take_1rtt_keys()`, CID access for quictun-quic data plane |
| decrypt_in_place | `quinn-proto/src/crypto.rs`, `crypto/rustls.rs` | In-place AEAD decrypt without BytesMut allocation |

### Updating upstream

```bash
git subtree pull --prefix=third_party/quinn \
    https://github.com/quinn-rs/quinn.git <new-tag> --squash
```

Then resolve any conflicts in patched files and run `cargo test -p quictun-quic`.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the development roadmap.

## License

Apache-2.0
