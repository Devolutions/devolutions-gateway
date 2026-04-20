use agent_tunnel_proto::{ConnectRequest, ConnectResponse, MAX_SESSION_MESSAGE_SIZE, ProtoError, SessionStream};
use uuid::Uuid;

#[tokio::test]
async fn roundtrip_connect_request() {
    let msg = ConnectRequest::new(Uuid::new_v4(), "192.168.1.100:3389".to_owned());

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    stream.send_request(&msg).await.expect("send should succeed");

    let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
    let decoded = stream.recv_request().await.expect("recv should succeed");
    assert_eq!(msg, decoded);
}

#[tokio::test]
async fn roundtrip_connect_response_success() {
    let msg = ConnectResponse::success();

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    stream.send_response(&msg).await.expect("send should succeed");

    let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
    let decoded = stream.recv_response().await.expect("recv should succeed");
    assert_eq!(msg, decoded);
}

#[tokio::test]
async fn roundtrip_connect_response_error() {
    let msg = ConnectResponse::error("connection refused");

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    stream.send_response(&msg).await.expect("send should succeed");

    let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
    let decoded = stream.recv_response().await.expect("recv should succeed");
    assert_eq!(msg, decoded);
}

// ── Wire format lock-in ───────────────────────────────────────────────

#[tokio::test]
async fn connect_request_wire_format_is_stable() {
    let uuid = Uuid::from_bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ]);
    let msg = ConnectRequest::new(uuid, "host:80".to_owned());

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    stream.send_request(&msg).await.expect("send should succeed");

    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x1D,                         // outer length = 29
        0x00, 0x01,                                     // protocol_version = 1
        // session_id (16 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x00, 0x00, 0x00, 0x07,                         // target length = 7
        b'h', b'o', b's', b't', b':', b'8', b'0',       // "host:80"
    ];
    assert_eq!(buf, expected);
}

#[tokio::test]
async fn connect_response_success_wire_format_is_stable() {
    let msg = ConnectResponse::success();

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    stream.send_response(&msg).await.expect("send should succeed");

    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x03, // outer length = 3
        0x00,                   // TAG_RESPONSE_SUCCESS
        0x00, 0x01,             // protocol_version = 1
    ];
    assert_eq!(buf, expected);
}

// ── Negative decode paths ─────────────────────────────────────────────

async fn recv_response_payload(payload: &[u8]) -> ProtoError {
    let len = u32::try_from(payload.len()).expect("test payload fits in u32");
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(payload);
    let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
    stream.recv_response().await.expect_err("decode should fail")
}

#[tokio::test]
async fn decode_rejects_unknown_connect_response_tag() {
    // Valid header shape (tag + 2B version) but tag 0xFF is not assigned.
    let err = recv_response_payload(&[0xFF, 0x00, 0x01]).await;
    assert!(matches!(err, ProtoError::UnknownTag { tag: 0xFF }), "got {err:?}");
}

#[tokio::test]
async fn decode_rejects_truncated_connect_request() {
    // ConnectRequest needs at least 2 (version) + 16 (uuid) = 18 bytes; give only 5.
    let payload = &[0x00, 0x01, 0x00, 0x00, 0x00];
    let len = u32::try_from(payload.len()).expect("fits");
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(payload);
    let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
    let err = stream.recv_request().await.expect_err("decode should fail");
    assert!(matches!(err, ProtoError::Truncated { .. }), "got {err:?}");
}

// ── Send-side size enforcement ────────────────────────────────────────

#[tokio::test]
async fn send_rejects_oversized_session_message() {
    // ConnectRequest carries a variable-length target string; pad it so the
    // encoded message exceeds MAX_SESSION_MESSAGE_SIZE (64 KiB).
    let huge_target = "A".repeat((MAX_SESSION_MESSAGE_SIZE as usize) + 100);
    let msg = ConnectRequest::new(Uuid::nil(), huge_target);

    let mut buf = Vec::new();
    let mut stream = SessionStream::new(&mut buf, &[][..]);
    let err = stream.send_request(&msg).await.expect_err("oversized send should fail");
    assert!(matches!(err, ProtoError::MessageTooLarge { .. }), "got {err:?}");
}

mod proptests {
    use agent_tunnel_proto::{ConnectRequest, ConnectResponse, SessionStream};
    use proptest::prelude::*;
    use uuid::Uuid;

    fn arb_connect_request() -> impl Strategy<Value = ConnectRequest> {
        ("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}")
            .prop_map(|target| ConnectRequest::new(Uuid::new_v4(), target))
    }

    fn arb_connect_response() -> impl Strategy<Value = ConnectResponse> {
        prop_oneof![Just(ConnectResponse::success()), ".*".prop_map(ConnectResponse::error),]
    }

    proptest! {
        #[test]
        fn connect_request_roundtrip(msg in arb_connect_request()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                let mut stream = SessionStream::new(&mut buf, &[][..]);
                stream.send_request(&msg).await.expect("send should succeed");

                let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
                let decoded = stream.recv_request().await.expect("recv should succeed");
                prop_assert_eq!(&msg.target, &decoded.target);
                prop_assert_eq!(msg.protocol_version, decoded.protocol_version);
                prop_assert_eq!(msg.session_id, decoded.session_id);
                Ok(())
            })?;
        }

        #[test]
        fn connect_response_roundtrip(msg in arb_connect_response()) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(async {
                let mut buf = Vec::new();
                let mut stream = SessionStream::new(&mut buf, &[][..]);
                stream.send_response(&msg).await.expect("send should succeed");

                let mut stream = SessionStream::new(tokio::io::sink(), buf.as_slice());
                let decoded = stream.recv_response().await.expect("recv should succeed");
                prop_assert_eq!(msg, decoded);
                Ok(())
            })?;
        }
    }
}
