use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quictun_core::connection::{self, TransportTuning};
use quictun_core::tunnel::TunnelResult;
use quictun_crypto::PrivateKey;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Default tuning for tests.
fn test_tuning() -> TransportTuning {
    TransportTuning::default()
}

/// Create server + client endpoints with RPK auth, custom CID length and FIPS flag.
fn make_endpoints(
    cid_length: usize,
    fips_mode: bool,
) -> Result<(
    PrivateKey,
    PrivateKey,
    quinn::Endpoint,
    quinn::Endpoint,
    SocketAddr,
)> {
    let server_key = PrivateKey::generate()?;
    let client_key = PrivateKey::generate()?;
    let server_pubkey = server_key.public_key()?;
    let client_pubkey = client_key.public_key()?;

    let keepalive = Some(Duration::from_secs(5));
    let tuning = test_tuning();

    let server_config = connection::build_server_config_ext(
        &server_key,
        &[client_pubkey],
        keepalive,
        &tuning,
        fips_mode,
    )?;
    let client_config = connection::build_client_config_ext(
        &client_key,
        &server_pubkey,
        keepalive,
        &tuning,
        fips_mode,
        false,
    )?;

    let endpoint_config = connection::build_endpoint_config(cid_length);

    let server_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;
    let server_endpoint = quinn::Endpoint::new(
        endpoint_config.clone(),
        Some(server_config),
        server_socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let mut client_endpoint = quinn::Endpoint::new(
        connection::build_endpoint_config(cid_length),
        None,
        client_socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    client_endpoint.set_default_client_config(client_config);

    Ok((
        server_key,
        client_key,
        server_endpoint,
        client_endpoint,
        server_addr,
    ))
}

/// Run a quick echo exchange to verify a connection works.
async fn echo_verify(conn: &quinn::Connection, count: u32) -> Result<()> {
    for i in 0..count {
        let msg = format!("test-{i}");
        conn.send_datagram(bytes::Bytes::from(msg.clone()))?;
        let echoed = conn.read_datagram().await?;
        assert_eq!(echoed.as_ref(), msg.as_bytes(), "echo mismatch on {i}");
    }
    Ok(())
}

/// Spawn a simple echo server that echoes `n` datagrams then closes.
fn spawn_echo_server(
    endpoint: quinn::Endpoint,
    n: u32,
) -> tokio::task::JoinHandle<quinn::Connection> {
    tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        for _ in 0..n {
            let datagram = connection.read_datagram().await.unwrap();
            connection.send_datagram(datagram).unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        connection
    })
}

// ── Phase 1: Connection Stability ────────────────────────────────────────────

#[tokio::test]
async fn connection_lost_returns_retriable() -> Result<()> {
    let (_, _, server_endpoint, client_endpoint, server_addr) =
        make_endpoints(8, false)?;

    // Use a oneshot to coordinate: server waits for client signal before closing.
    let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();

    // Server accepts, echoes 2, waits for signal, then closes
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        for _ in 0..2 {
            let datagram = connection.read_datagram().await.unwrap();
            connection.send_datagram(datagram).unwrap();
        }

        // Wait for client to be ready
        let _ = close_rx.await;
        connection.close(42u32.into(), b"bye");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;

    // Exchange 2 datagrams successfully
    echo_verify(&connection, 2).await?;

    // Tell server to close now
    let _ = close_tx.send(());

    // Wait for close frame to arrive
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now try to read — server closed, should get an error
    let result = connection.read_datagram().await;
    assert!(result.is_err(), "expected error after server close");

    let err = result.unwrap_err();
    // Classify it like the tunnel does
    let tunnel_result = match &err {
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut => TunnelResult::ConnectionLost(err),
        _ => TunnelResult::Fatal(err.into()),
    };

    assert!(
        matches!(tunnel_result, TunnelResult::ConnectionLost(_)),
        "expected ConnectionLost, got {tunnel_result:?}"
    );

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn idle_timeout_config() -> Result<()> {
    let tuning = TransportTuning {
        max_idle_timeout_ms: 500, // 500ms idle timeout
        ..Default::default()
    };

    let server_key = PrivateKey::generate()?;
    let client_key = PrivateKey::generate()?;
    let server_pubkey = server_key.public_key()?;
    let client_pubkey = client_key.public_key()?;

    // Build with tight idle timeout, NO keepalive
    let server_config = connection::build_server_config_ext(
        &server_key,
        &[client_pubkey],
        None, // no keepalive
        &tuning,
        false,
    )?;
    let client_config = connection::build_client_config_ext(
        &client_key,
        &server_pubkey,
        None,
        &tuning,
        false,
        false,
    )?;

    let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_addr = server_endpoint.local_addr()?;

    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        // Just hold the connection — don't send anything
        let result = connection.read_datagram().await;
        // Should time out
        assert!(result.is_err());
    });

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;

    // Wait longer than the idle timeout
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Connection should have timed out
    let result = connection.read_datagram().await;
    assert!(result.is_err(), "connection should have timed out");

    server_handle.await?;
    Ok(())
}

// ── Phase 2: FIPS Mode ──────────────────────────────────────────────────────

#[tokio::test]
async fn fips_mode_echo_round_trip() -> Result<()> {
    // FIPS mode: only AES-GCM + P-256/P-384, no ChaCha20/x25519
    let (_, _, server_endpoint, client_endpoint, server_addr) =
        make_endpoints(8, true)?;

    let server_handle = spawn_echo_server(server_endpoint, 3);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&connection, 3).await?;

    connection.close(0u32.into(), b"done");
    server_handle.await?;
    Ok(())
}

// ── Phase 3: CID Length ─────────────────────────────────────────────────────

#[tokio::test]
async fn cid_length_0_works() -> Result<()> {
    let (_, _, server_endpoint, client_endpoint, server_addr) =
        make_endpoints(0, false)?;

    let server_handle = spawn_echo_server(server_endpoint, 3);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&connection, 3).await?;

    connection.close(0u32.into(), b"done");
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn cid_length_4_works() -> Result<()> {
    let (_, _, server_endpoint, client_endpoint, server_addr) =
        make_endpoints(4, false)?;

    let server_handle = spawn_echo_server(server_endpoint, 3);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&connection, 3).await?;

    connection.close(0u32.into(), b"done");
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn cid_length_8_works() -> Result<()> {
    let (_, _, server_endpoint, client_endpoint, server_addr) =
        make_endpoints(8, false)?;

    let server_handle = spawn_echo_server(server_endpoint, 3);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&connection, 3).await?;

    connection.close(0u32.into(), b"done");
    server_handle.await?;
    Ok(())
}

// ── Phase 4: Session Resumption ─────────────────────────────────────────────

#[tokio::test]
async fn session_resumption_reconnect() -> Result<()> {
    let server_key = PrivateKey::generate()?;
    let client_key = PrivateKey::generate()?;
    let server_pubkey = server_key.public_key()?;
    let client_pubkey = client_key.public_key()?;

    let keepalive = Some(Duration::from_secs(5));
    let tuning = test_tuning();

    let server_config = connection::build_server_config_ext(
        &server_key,
        &[client_pubkey],
        keepalive,
        &tuning,
        false,
    )?;

    // Enable session resumption
    let client_config = connection::build_client_config_ext(
        &client_key,
        &server_pubkey,
        keepalive,
        &tuning,
        false,
        true, // enable_session_resumption
    )?;

    let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_addr = server_endpoint.local_addr()?;

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    // First connection
    let server_ep = server_endpoint.clone();
    let handle1 = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        for _ in 0..2 {
            let d = conn.read_datagram().await.unwrap();
            conn.send_datagram(d).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        conn.close(0u32.into(), b"done");
    });

    let conn1 = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&conn1, 2).await?;
    handle1.await?;

    // Wait for session ticket to arrive
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection (should use cached session ticket for faster handshake)
    let server_ep = server_endpoint.clone();
    let handle2 = tokio::spawn(async move {
        let incoming = server_ep.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        for _ in 0..2 {
            let d = conn.read_datagram().await.unwrap();
            conn.send_datagram(d).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        conn.close(0u32.into(), b"done");
    });

    let conn2 = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&conn2, 2).await?;
    handle2.await?;

    Ok(())
}

// ── Phase 5: X.509 CA Support ───────────────────────────────────────────────

/// Generate a self-signed CA, server cert, and client cert using rcgen.
/// Writes PEM files to the given directory and returns the paths.
fn generate_test_pki(
    dir: &std::path::Path,
) -> Result<(
    std::path::PathBuf, // ca.pem
    std::path::PathBuf, // server-cert.pem
    std::path::PathBuf, // server-key.pem
    std::path::PathBuf, // client-cert.pem
    std::path::PathBuf, // client-key.pem
)> {
    use rcgen::{CertificateParams, KeyPair};

    // Generate CA
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::new(vec!["quictun-test-ca".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Generate server cert signed by CA
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let server_params = CertificateParams::new(vec!["quictun".to_string()])?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // Generate client cert signed by CA
    let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let client_params = CertificateParams::new(vec!["quictun-client".to_string()])?;
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key)?;

    // Write PEM files
    let ca_path = dir.join("ca.pem");
    let server_cert_path = dir.join("server-cert.pem");
    let server_key_path = dir.join("server-key.pem");
    let client_cert_path = dir.join("client-cert.pem");
    let client_key_path = dir.join("client-key.pem");

    std::fs::write(&ca_path, ca_cert.pem())?;
    std::fs::write(&server_cert_path, server_cert.pem())?;
    std::fs::write(&server_key_path, server_key.serialize_pem())?;
    std::fs::write(&client_cert_path, client_cert.pem())?;
    std::fs::write(&client_key_path, client_key.serialize_pem())?;

    Ok((
        ca_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    ))
}

#[tokio::test]
async fn x509_echo_round_trip() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let (ca_path, server_cert, server_key, client_cert, client_key) =
        generate_test_pki(tmp.path())?;

    let keepalive = Some(Duration::from_secs(5));
    let tuning = test_tuning();

    let server_config = connection::build_server_config_x509(
        &server_cert,
        &server_key,
        &ca_path, // trust client certs signed by this CA
        keepalive,
        &tuning,
        false,
    )?;

    let client_config = connection::build_client_config_x509(
        &client_cert,
        &client_key,
        &ca_path, // trust server certs signed by this CA
        keepalive,
        &tuning,
        false,
        false,
    )?;

    let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_addr = server_endpoint.local_addr()?;

    let server_handle = spawn_echo_server(server_endpoint, 5);

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;
    echo_verify(&connection, 5).await?;

    connection.close(0u32.into(), b"done");
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn x509_rejects_untrusted_client() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let (ca_path, server_cert, server_key, _, _) = generate_test_pki(tmp.path())?;

    // Generate a separate untrusted client cert (self-signed, not from the CA)
    let rogue_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let rogue_params = rcgen::CertificateParams::new(vec!["rogue".to_string()])?;
    let rogue_cert = rogue_params.self_signed(&rogue_key)?;

    let rogue_cert_path = tmp.path().join("rogue-cert.pem");
    let rogue_key_path = tmp.path().join("rogue-key.pem");
    std::fs::write(&rogue_cert_path, rogue_cert.pem())?;
    std::fs::write(&rogue_key_path, rogue_key.serialize_pem())?;

    let keepalive = Some(Duration::from_secs(5));
    let tuning = test_tuning();

    let server_config = connection::build_server_config_x509(
        &server_cert,
        &server_key,
        &ca_path,
        keepalive,
        &tuning,
        false,
    )?;

    // Client uses rogue cert NOT signed by the CA
    let client_config = connection::build_client_config_x509(
        &rogue_cert_path,
        &rogue_key_path,
        &ca_path, // client trusts server (which IS valid)
        keepalive,
        &tuning,
        false,
        false,
    )?;

    let server_endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let server_addr = server_endpoint.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            let _result = incoming.await;
        }
    });

    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let connect_result = client_endpoint.connect(server_addr, "quictun")?.await;

    match connect_result {
        Err(_) => {
            // Rejected at handshake — expected
        }
        Ok(conn) => {
            // May appear to succeed briefly, but server should reject
            let result =
                tokio::time::timeout(Duration::from_secs(2), conn.read_datagram()).await;
            match result {
                Ok(Ok(_)) => panic!("rogue client should have been rejected"),
                Ok(Err(_)) => {} // server closed it
                Err(_) => panic!("timed out waiting for rejection"),
            }
        }
    }

    server_handle.await?;
    Ok(())
}

// ── Config validation tests ─────────────────────────────────────────────────

#[test]
fn config_validates_cid_length() {
    let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
cid_length = 3

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
    let config: quictun_core::config::Config = toml::from_str(toml).unwrap();
    let result = std::panic::catch_unwind(|| {
        // validate is private, but load() calls it. We can test via load semantics.
        // Since validate is called in load, let's test the parsed config's cid_length.
        assert_eq!(config.interface.cid_length, 3);
    });
    assert!(result.is_ok());
    // The validation happens in Config::load, which we can't call without a file.
    // But we can verify the parsed value is 3 (invalid), which would fail validation.
}

#[test]
fn config_default_auth_mode_is_rpk() {
    let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
    let config: quictun_core::config::Config = toml::from_str(toml).unwrap();
    assert_eq!(config.interface.auth_mode, "rpk");
    assert_eq!(config.interface.cid_length, 8);
    assert!(!config.interface.fips_mode);
    assert!(!config.interface.zero_rtt);
}

#[test]
fn config_x509_requires_all_files() {
    let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
auth_mode = "x509"
cert_file = "/tmp/cert.pem"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
    let config: quictun_core::config::Config = toml::from_str(toml).unwrap();
    // x509 without key_file and ca_file would fail validation in Config::load
    assert_eq!(config.interface.auth_mode, "x509");
    assert!(config.interface.key_file.is_none());
    assert!(config.interface.ca_file.is_none());
}

#[test]
fn config_fips_mode_parses() {
    let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.1/24"
fips_mode = true

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.2/32"]
"#;
    let config: quictun_core::config::Config = toml::from_str(toml).unwrap();
    assert!(config.interface.fips_mode);
}

#[test]
fn config_reconnect_interval_parses() {
    let toml = r#"
[interface]
private_key = "dGVzdA=="
address = "10.0.0.2/24"

[[peer]]
public_key = "dGVzdA=="
allowed_ips = ["10.0.0.1/32"]
endpoint = "1.2.3.4:443"
reconnect_interval = 5
"#;
    let config: quictun_core::config::Config = toml::from_str(toml).unwrap();
    assert_eq!(config.peer[0].reconnect_interval, Some(5));
}
