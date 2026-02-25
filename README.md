# QuicTun

A secure tunnel primitive over QUIC + TLS 1.3 with Raw Public Keys (RFC 7250). P-256 ECDSA pinned identities, no certificate authorities.

## Why

- **Standards-based** — QUIC (RFC 9000), TLS 1.3 (RFC 8446), QUIC Datagrams (RFC 9221). No custom crypto.
- **FIPS-ready** — All cryptography via aws-lc-rs (FIPS 140-3 Certificate #4631).
- **Firewall traversal** — UDP 443, indistinguishable from HTTP/3 to DPI.
- **Connection migration** — QUIC handles network transitions (Wi-Fi → cellular) without re-handshake.
- **Low overhead** — 20-byte per-packet overhead with zero-length CIDs (vs. WireGuard's 32 bytes).

## Quick Start

```bash
# Generate keys
quictun genkey > private.key
quictun pubkey < private.key > public.key

# Run tunnel
quictun up tunnel.toml
```

## Architecture

```
quictun-crypto/   Key generation, serialization, RPK TLS verifiers
quictun-core/     Config, QUIC builders, TUN↔QUIC forwarding loops
quictun-tun/      Async TUN device wrapper (tun-rs v2)
quictun-cli/      CLI binary (genkey, pubkey, up, down)
quictun-uring/    [Experimental] Linux io_uring data plane
```

The production data plane uses tokio with quinn, forwarding IP packets as QUIC DATAGRAM frames. The `quictun-uring` crate is an experimental research track exploring io_uring-based I/O for lower per-packet overhead on Linux — see its [README](quictun-uring/README.md) for details.

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

## Building

```bash
cargo build --release
```

Requires Rust 2024 edition. TLS backed by aws-lc-rs (needs cmake + C compiler).

## License

Apache-2.0
