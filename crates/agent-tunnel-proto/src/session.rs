use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::version::CURRENT_PROTOCOL_VERSION;

/// Maximum encoded session message size (64 KiB).
pub const MAX_SESSION_MESSAGE_SIZE: u32 = 64 * 1024;

/// Request from Gateway to Agent to open a TCP connection to a target.
///
/// Sent as the first message on a newly opened QUIC bidirectional stream.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectRequest {
    pub protocol_version: u16,
    /// Association/session ID from the Gateway.
    pub session_id: Uuid,
    /// Target address in `host:port` form (e.g., `"192.168.1.100:3389"`).
    pub target: String,
}

/// Agent's response to a ConnectRequest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum ConnectResponse {
    Success { protocol_version: u16 },
    Error { protocol_version: u16, reason: String },
}

impl ConnectRequest {
    pub fn new(session_id: Uuid, target: String) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            session_id,
            target,
        }
    }
}

impl ConnectResponse {
    pub fn success() -> Self {
        Self::Success {
            protocol_version: CURRENT_PROTOCOL_VERSION,
        }
    }

    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            reason: reason.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Extract the protocol version from any variant.
    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Success { protocol_version } | Self::Error { protocol_version, .. } => *protocol_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::SessionStream;

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
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;
    use crate::stream::SessionStream;

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
