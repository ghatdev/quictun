use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use quictun_core::config::CipherSuite;
use quictun_core::connection::{self, TransportTuning};
use quictun_crypto::PrivateKey;

/// Integration test: QUIC datagram round-trip with pinned RPK authentication.
/// Does NOT require root — runs over localhost loopback.
#[tokio::test]
async fn datagram_echo_round_trip() -> Result<()> {
    // Generate two key pairs
    let server_key = PrivateKey::generate()?;
    let client_key = PrivateKey::generate()?;
    let server_pubkey = server_key.public_key()?;
    let client_pubkey = client_key.public_key()?;

    let keepalive = Some(Duration::from_secs(5));

    // Build configs pinned to each other's keys
    let all_ciphers = CipherSuite::all();
    let server_config = connection::build_server_config(
        &server_key,
        &[client_pubkey],
        keepalive,
        &TransportTuning::default(),
        &all_ciphers,
        false,
    )?;
    let client_config = connection::build_client_config(
        &client_key,
        &server_pubkey,
        keepalive,
        &TransportTuning::default(),
        &all_ciphers,
        false,
        false,
    )?;

    // Bind server on ephemeral port
    let bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server_endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn echo server
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        // Echo back 5 datagrams
        for _ in 0..5 {
            let datagram = connection.read_datagram().await.unwrap();
            connection
                .send_datagram(datagram)
                .expect("failed to send echo datagram");
        }

        // Give client time to read the last datagram
        tokio::time::sleep(Duration::from_millis(100)).await;
        connection.close(0u32.into(), b"done");
    });

    // Connect client
    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);

    let connection = client_endpoint.connect(server_addr, "quictun")?.await?;

    // Send and verify 5 datagrams
    for i in 0..5u32 {
        let msg = format!("ping-{i}");
        connection.send_datagram(bytes::Bytes::from(msg.clone()))?;

        let echoed = connection.read_datagram().await?;
        assert_eq!(
            echoed.as_ref(),
            msg.as_bytes(),
            "echo mismatch on datagram {i}"
        );
    }

    connection.close(0u32.into(), b"test-done");
    server_handle.await?;

    Ok(())
}

/// Test that a client with an unknown key is rejected by the server.
/// In TLS 1.3, client auth is post-handshake, so the connection may initially
/// "succeed" from the client's perspective but will be closed shortly after.
#[tokio::test]
async fn rejects_unknown_client_key() -> Result<()> {
    let server_key = PrivateKey::generate()?;
    let authorized_client_key = PrivateKey::generate()?;
    let unauthorized_client_key = PrivateKey::generate()?;
    let server_pubkey = server_key.public_key()?;
    let authorized_pubkey = authorized_client_key.public_key()?;

    let keepalive = Some(Duration::from_secs(5));

    let all_ciphers = CipherSuite::all();

    // Server only allows the authorized client
    let server_config = connection::build_server_config(
        &server_key,
        &[authorized_pubkey],
        keepalive,
        &TransportTuning::default(),
        &all_ciphers,
        false,
    )?;

    // Unauthorized client tries to connect
    let client_config = connection::build_client_config(
        &unauthorized_client_key,
        &server_pubkey,
        keepalive,
        &TransportTuning::default(),
        &all_ciphers,
        false,
        false,
    )?;

    let bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server_endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server that tries to accept
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
            // Connection rejected at handshake level — this is fine
        }
        Ok(conn) => {
            // Connection appeared to succeed, but server should close it.
            // Try to use the connection — it should fail.
            let result = tokio::time::timeout(Duration::from_secs(2), conn.read_datagram()).await;

            match result {
                Ok(Ok(_)) => panic!("expected connection to be rejected, but got data"),
                Ok(Err(_)) => {} // Connection error — server closed it
                Err(_) => panic!("timed out waiting for server to reject connection"),
            }
        }
    }

    server_handle.await?;
    Ok(())
}
