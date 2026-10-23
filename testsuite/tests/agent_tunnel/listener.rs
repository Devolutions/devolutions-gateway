use std::time::Duration;

use agent_tunnel_proto::{CertRenewalResult, ControlMessage, ControlStream};
use uuid::Uuid;

use super::common::{bind_test_listener, generate_csr_with_cn, generate_csr_with_key, wait_for_route_advertised};

#[tokio::test]
async fn gateway_listener_rejects_certificate_renewal_key_rotation() {
    let listener = bind_test_listener().await;
    let (agent_id, connection) = listener.connect_agent("key-rotation-agent").await;
    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    ctrl.send(&ControlMessage::route_advertise(1, vec![], vec![]))
        .await
        .expect("send route advertisement");
    wait_for_route_advertised(listener.handle.registry(), agent_id, 1).await;

    let (_, csr_pem) = generate_csr_with_cn("evil-impersonator");
    ctrl.send(&ControlMessage::cert_renewal_request(csr_pem))
        .await
        .expect("send renewal request");

    let response = tokio::time::timeout(Duration::from_secs(5), ctrl.recv())
        .await
        .expect("renewal response timed out")
        .expect("receive renewal response");
    match response {
        ControlMessage::CertRenewalResponse {
            result: CertRenewalResult::Error { reason },
            ..
        } => {
            assert!(
                reason.contains("key rotation"),
                "renewal error should explain that key rotation is rejected: {reason}"
            );
        }
        other => panic!("expected renewal key rotation to fail, got {other:?}"),
    }

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_listener_renews_certificate_with_accepted_key() {
    let listener = bind_test_listener().await;
    let (agent_id, connection, key_pair) = listener.connect_agent_with_key("renewal-agent").await;
    let expected_ca = listener.handle.ca_manager().ca_cert_pem().to_owned();
    let mut ctrl: ControlStream<_, _> = connection.open_bi().await.expect("open control stream").into();

    ctrl.send(&ControlMessage::route_advertise(1, vec![], vec![]))
        .await
        .expect("send route advertisement");
    wait_for_route_advertised(listener.handle.registry(), agent_id, 1).await;

    let csr_pem = generate_csr_with_key("renewal-agent", &key_pair);
    ctrl.send(&ControlMessage::cert_renewal_request(csr_pem))
        .await
        .expect("send renewal request");

    let response = tokio::time::timeout(Duration::from_secs(5), ctrl.recv())
        .await
        .expect("renewal response timed out")
        .expect("receive renewal response");
    match response {
        ControlMessage::CertRenewalResponse {
            result:
                CertRenewalResult::Success {
                    client_cert_pem: _,
                    gateway_ca_cert_pem,
                },
            ..
        } => assert_eq!(gateway_ca_cert_pem, expected_ca),
        other => panic!("expected successful renewal, got {other:?}"),
    }

    connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}

async fn assert_admission_rejected(connection: &quinn::Connection) {
    let reason = tokio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .expect("listener should close the unauthorized connection");
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.reason.as_ref(),
                b"agent-not-accepted",
                "unexpected close reason: {close:?}"
            );
        }
        other => panic!("expected application close from the admission gate, got {other:?}"),
    }
}

#[tokio::test]
async fn gateway_listener_rejects_unknown_agent_id() {
    let listener = bind_test_listener().await;
    let agent_id = Uuid::new_v4();
    let (key_pair, csr_pem) = generate_csr_with_cn("unenrolled-agent");
    let signed = listener
        .handle
        .ca_manager()
        .sign_agent_csr(agent_id, "unenrolled-agent", &csr_pem, None)
        .expect("sign unenrolled agent csr");

    let connection = listener.connect_signed(&signed, &key_pair).await;

    assert_admission_rejected(&connection).await;
    assert!(
        listener.handle.registry().agent_info(&agent_id).await.is_none(),
        "rejected agent must never be registered"
    );

    listener.shutdown().await;
}

#[tokio::test]
async fn gateway_listener_rejects_accepted_agent_id_with_wrong_key() {
    let listener = bind_test_listener().await;
    let (agent_id, accepted_connection) = listener.connect_agent("spki-mismatch-agent").await;

    let (wrong_key_pair, csr_pem) = generate_csr_with_cn("spki-mismatch-agent");
    let signed = listener
        .handle
        .ca_manager()
        .sign_agent_csr(agent_id, "spki-mismatch-agent", &csr_pem, None)
        .expect("sign csr with a different key");

    let rejected_connection = listener.connect_signed(&signed, &wrong_key_pair).await;

    assert_admission_rejected(&rejected_connection).await;
    assert!(
        accepted_connection.close_reason().is_none(),
        "rejected connection must not supersede the accepted one"
    );

    accepted_connection.close(0u32.into(), b"test done");
    listener.shutdown().await;
}
