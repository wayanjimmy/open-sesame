//! Integration tests for IPC socket communication.
//!
//! All tests use Noise IK encrypted transport — the same code path as production.
//! There is no plaintext transport path.

use core_ipc::{BusClient, BusServer, Message, generate_keypair};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::time::Duration;
use uuid::Uuid;

/// Helper: start an encrypted bus server on a temp socket.
/// Returns (server, temp_dir, server_public_key).
async fn start_server() -> (BusServer, tempfile::TempDir, [u8; 32]) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus.sock");
    let keypair = generate_keypair().unwrap();
    let server_pub: [u8; 32] = keypair.public.clone().try_into().unwrap();
    let server = BusServer::bind(&sock, keypair).unwrap();
    (server, dir, server_pub)
}

/// Helper: make a DaemonId from a u128.
fn did(n: u128) -> DaemonId {
    DaemonId::from_uuid(Uuid::from_u128(n))
}

#[tokio::test]
async fn server_bind_creates_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("pds/bus.sock");
    let keypair = generate_keypair().unwrap();
    let _server = BusServer::bind(&sock, keypair).unwrap();
    assert!(sock.exists(), "socket file should exist after bind");
}

#[tokio::test]
async fn client_connect_and_server_accept() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => unreachable!(),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                server.connection_count().await
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let _client = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();

    let count = server_handle.await.unwrap();
    assert_eq!(count, 1, "server should have 1 connected client");
}

#[tokio::test]
async fn publish_subscribe_roundtrip() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    let mut client_b = BusClient::connect_encrypted(did(2), &sock, &server_pub)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    client_a
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(1),
                version: "0.1.0".into(),
                capabilities: vec!["test".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_millis(500), client_b.recv())
        .await
        .expect("timeout waiting for message")
        .expect("channel closed");

    assert!(
        matches!(msg.payload, EventKind::DaemonStarted { .. }),
        "expected DaemonStarted, got {:?}",
        msg.payload
    );
}

#[tokio::test]
async fn request_response_correlation() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    let mut client_b = BusClient::connect_encrypted(did(2), &sock, &server_pub)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    let response_handle = tokio::spawn(async move {
        client_a
            .request(
                EventKind::SecretList { profile: TrustProfileName::try_from("test").unwrap() },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    let request_msg = tokio::time::timeout(Duration::from_millis(500), client_b.recv())
        .await
        .expect("timeout waiting for request")
        .expect("channel closed");

    assert!(matches!(request_msg.payload, EventKind::SecretList { .. }));

    let response = Message::new(
        did(2),
        EventKind::SecretListResponse {
            keys: vec!["api-key".into(), "db-pass".into()],
        },
        SecurityLevel::Internal,
        client_b.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    client_b.send(&response).await.unwrap();

    let result = response_handle.await.unwrap().unwrap();
    match result.payload {
        EventKind::SecretListResponse { keys } => {
            assert_eq!(keys, vec!["api-key".to_string(), "db-pass".to_string()]);
        }
        other => panic!("expected SecretListResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn sender_does_not_receive_own_message() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut client = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id: did(1),
                version: "0.1.0".into(),
                capabilities: vec![],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_millis(100), client.recv()).await;
    assert!(result.is_err(), "sender should not receive own broadcast");
}

#[tokio::test]
async fn client_connect_retry_on_missing_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nonexistent.sock");
    let fake_pub = [0u8; 32];

    let result = BusClient::connect_encrypted(did(1), &sock, &fake_pub).await;
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("should fail when socket doesn't exist"),
    };
    assert!(
        err.contains("failed to connect"),
        "error should mention connection failure: {err}"
    );
}

#[tokio::test]
async fn request_timeout() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let result = client
        .request(
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            Duration::from_millis(100),
        )
        .await;

    assert!(result.is_err(), "should timeout with no responder");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("timed out"),
        "error should mention timeout: {err}"
    );
}

// ===== T1.5: IPC Authentication — Noise Handshake Rejection =====

#[tokio::test]
async fn noise_handshake_rejects_wrong_key() {
    let (server, dir, _real_server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Generate a WRONG server public key (not the real one)
    let wrong_keypair = generate_keypair().unwrap();
    let wrong_server_pub: [u8; 32] = wrong_keypair.public.clone().try_into().unwrap();

    // Client attempts to connect expecting the wrong server public key
    let result = BusClient::connect_encrypted(did(1), &sock, &wrong_server_pub).await;

    assert!(
        result.is_err(),
        "Noise IK handshake must fail when client expects wrong server public key"
    );
}

// ===== T1.2: Secret Value Never Broadcast =====

#[tokio::test]
async fn secret_response_not_received_by_bystander() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect requester (client A)
    let client_a = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();

    // Connect bystander (client B) — should NOT receive the response
    let mut bystander = BusClient::connect_encrypted(did(2), &sock, &server_pub)
        .await
        .unwrap();

    // Connect simulated secrets daemon (client C)
    let mut secrets_daemon = BusClient::connect_encrypted(did(3), &sock, &server_pub)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Requester sends SecretList request via request() which registers a pending waiter
    let response_handle = tokio::spawn(async move {
        client_a
            .request(
                EventKind::SecretList {
                    profile: TrustProfileName::try_from("work").unwrap(),
                },
                SecurityLevel::Internal,
                Duration::from_secs(2),
            )
            .await
    });

    // Secrets daemon receives the request
    let request_msg = tokio::time::timeout(Duration::from_millis(500), secrets_daemon.recv())
        .await
        .expect("timeout waiting for request")
        .expect("channel closed");

    assert!(matches!(request_msg.payload, EventKind::SecretList { .. }));

    // Bystander also receives the broadcast request — drain it
    let bystander_request = tokio::time::timeout(Duration::from_millis(500), bystander.recv())
        .await
        .expect("bystander should receive broadcast request")
        .expect("bystander channel closed");
    assert!(matches!(bystander_request.payload, EventKind::SecretList { .. }));

    // Secrets daemon sends correlated response
    let response = Message::new(
        did(3),
        EventKind::SecretListResponse {
            keys: vec!["api-key".into()],
        },
        SecurityLevel::Internal,
        secrets_daemon.epoch(),
    )
    .with_correlation(request_msg.msg_id);

    secrets_daemon.send(&response).await.unwrap();

    // Requester receives the response
    let result = response_handle.await.unwrap().unwrap();
    assert!(matches!(result.payload, EventKind::SecretListResponse { .. }));

    // Bystander must NOT receive the correlated response (unicast routing)
    let bystander_result = tokio::time::timeout(Duration::from_millis(200), bystander.recv()).await;
    assert!(
        bystander_result.is_err(),
        "bystander must not receive correlated response (M11 unicast)"
    );
}

#[tokio::test]
async fn uncorrelated_response_is_dropped() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_a = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    let mut client_b = BusClient::connect_encrypted(did(2), &sock, &server_pub)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client A sends a response with a fabricated correlation_id (no matching request)
    let orphan_response = Message::new(
        did(1),
        EventKind::SecretListResponse {
            keys: vec!["should-not-broadcast".into()],
        },
        SecurityLevel::Internal,
        client_a.epoch(),
    )
    .with_correlation(Uuid::from_u128(99999));

    client_a.send(&orphan_response).await.unwrap();

    // Client B must NOT receive the orphan response
    let result = tokio::time::timeout(Duration::from_millis(200), client_b.recv()).await;
    assert!(
        result.is_err(),
        "orphan response (no matching pending request) must be dropped, not broadcast"
    );
}

#[tokio::test]
async fn multiple_clients_receive_broadcast() {
    let (server, dir, server_pub) = start_server().await;
    let sock = dir.path().join("bus.sock");

    tokio::spawn(async move { let _ = server.run().await; });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let sender = BusClient::connect_encrypted(did(1), &sock, &server_pub)
        .await
        .unwrap();
    let mut recv_a = BusClient::connect_encrypted(did(2), &sock, &server_pub)
        .await
        .unwrap();
    let mut recv_b = BusClient::connect_encrypted(did(3), &sock, &server_pub)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;

    sender
        .publish(
            EventKind::ConfigReloaded {
                daemon_id: did(1),
                changed_keys: vec!["theme".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .unwrap();

    let msg_a = tokio::time::timeout(Duration::from_millis(500), recv_a.recv())
        .await
        .expect("timeout")
        .expect("closed");
    let msg_b = tokio::time::timeout(Duration::from_millis(500), recv_b.recv())
        .await
        .expect("timeout")
        .expect("closed");

    assert!(matches!(msg_a.payload, EventKind::ConfigReloaded { .. }));
    assert!(matches!(msg_b.payload, EventKind::ConfigReloaded { .. }));
}
