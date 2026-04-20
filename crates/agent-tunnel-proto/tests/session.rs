use agent_tunnel_proto::{ConnectRequest, ConnectResponse, SessionStream};
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
