//! Registration wire framing.
//!
//! See the "UniGetUI registration" section of the [package-management contract][contract], "Framing" and "Liveness and duplicates".
//! The Agent sends `Welcome`, `Request`, `Ping` and `Pong` and accepts `Hello`, `Response`, `Ping` and `Pong`.
//!
//! [contract]: https://github.com/Devolutions/devolutions-gateway/blob/68baca143ca85c34141a6464dae190998d1aedb2/crates/agent-channel-proto/CONTRACT.package-management.md#registration

use std::fmt;

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use uuid::Uuid;

/// Largest frame body the contract allows.
pub(super) const MAX_FRAME_LEN: u32 = 1_048_576;

/// Largest `Hello` body read before the client identity is authenticated.
///
/// A `Hello` carries one integer and a string of at most 128 characters.
pub(super) const MAX_HELLO_LEN: u32 = 4096;

pub(super) const PROTOCOL_VERSION: u64 = 1;

const MAX_CLIENT_VERSION_CHARS: usize = 128;

const MAX_ERROR_MESSAGE_CHARS: usize = 2048;

const ERROR_CODES: [&str; 4] = ["UnsupportedCommand", "InvalidArguments", "Busy", "Failed"];

/// The `error` object of a `Response` that is not `ok`.
///
/// The message is client-supplied text and is never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    pub code: String,
    pub message: String,
}

/// A frame the Agent accepts from UniGetUI.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Frame {
    Hello {
        protocol_version: u64,
        client_version: String,
    },
    Response {
        id: Uuid,
        outcome: Result<Value, RemoteError>,
    },
    Ping,
    Pong,
}

/// A frame the Agent sends to UniGetUI.
#[derive(Clone, Copy, Debug)]
pub(super) enum OutgoingFrame {
    Welcome,
    Ping,
    Pong,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FrameError {
    InvalidLength,
    InvalidJson,
    MissingKind,
    UnknownKind,
    InvalidHello,
    InvalidResponse,
    /// `Request` flows from the Agent to UniGetUI only.
    UnexpectedRequest,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "frame length is out of range",
            Self::InvalidJson => "frame is not a JSON object",
            Self::MissingKind => "frame has no kind",
            Self::UnknownKind => "frame kind is unknown",
            Self::InvalidHello => "hello members are invalid",
            Self::InvalidResponse => "response members are invalid",
            Self::UnexpectedRequest => "unexpected request frame",
        })
    }
}

#[derive(Debug)]
pub(super) enum ReadError {
    Io(std::io::Error),
    Frame(FrameError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read frame: {error}"),
            Self::Frame(error) => error.fmt(f),
        }
    }
}

/// Reads one frame, allocating the body only as its bytes arrive.
///
/// Reads exactly the frame's bytes and never past it.
/// Not cancellation safe: a cancelled read loses the bytes it consumed.
pub(super) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max_len: u32) -> Result<Frame, ReadError> {
    let mut prefix = [0u8; 4 /* Length */];
    reader.read_exact(&mut prefix).await.map_err(ReadError::Io)?;
    let len = decode_length(prefix, max_len).map_err(ReadError::Frame)?;

    let mut body = Vec::new();
    let read = reader
        .take(u64::from(len))
        .read_to_end(&mut body)
        .await
        .map_err(ReadError::Io)?;
    if read as u64 != u64::from(len) {
        return Err(ReadError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }

    decode_frame(&body).map_err(ReadError::Frame)
}

fn decode_length(prefix: [u8; 4], max_len: u32) -> Result<u32, FrameError> {
    let len = u32::from_le_bytes(prefix);

    if !(1 <= len && len <= max_len) {
        return Err(FrameError::InvalidLength);
    }

    Ok(len)
}

fn decode_frame(body: &[u8]) -> Result<Frame, FrameError> {
    let Ok(Value::Object(members)) = serde_json::from_slice::<Value>(body) else {
        return Err(FrameError::InvalidJson);
    };
    let kind = members
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(FrameError::MissingKind)?;

    match kind {
        "Hello" => {
            let protocol_version = members
                .get("protocolVersion")
                .and_then(Value::as_u64)
                .ok_or(FrameError::InvalidHello)?;
            let client_version = members
                .get("clientVersion")
                .and_then(Value::as_str)
                .filter(|version| version.chars().count() <= MAX_CLIENT_VERSION_CHARS)
                .ok_or(FrameError::InvalidHello)?;

            Ok(Frame::Hello {
                protocol_version,
                client_version: client_version.to_owned(),
            })
        }
        "Ping" => Ok(Frame::Ping),
        "Pong" => Ok(Frame::Pong),
        "Response" => decode_response(&members),
        "Request" => Err(FrameError::UnexpectedRequest),
        _ => Err(FrameError::UnknownKind),
    }
}

fn decode_response(members: &Map<String, Value>) -> Result<Frame, FrameError> {
    let id = members
        .get("id")
        .and_then(Value::as_str)
        .and_then(parse_lowercase_uuid)
        .ok_or(FrameError::InvalidResponse)?;

    let outcome = match members.get("ok") {
        Some(Value::Bool(true)) => Ok(members.get("result").ok_or(FrameError::InvalidResponse)?.clone()),
        Some(Value::Bool(false)) => {
            let Some(Value::Object(error)) = members.get("error") else {
                return Err(FrameError::InvalidResponse);
            };
            let code = error
                .get("code")
                .and_then(Value::as_str)
                .filter(|code| ERROR_CODES.contains(code))
                .ok_or(FrameError::InvalidResponse)?;
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| message.chars().count() <= MAX_ERROR_MESSAGE_CHARS)
                .ok_or(FrameError::InvalidResponse)?;

            Err(RemoteError {
                code: code.to_owned(),
                message: message.to_owned(),
            })
        }
        _ => return Err(FrameError::InvalidResponse),
    };

    Ok(Frame::Response { id, outcome })
}

/// Identifiers are lowercase hyphenated UUIDs on the wire.
fn parse_lowercase_uuid(value: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(value).ok()?;
    (id.hyphenated().to_string() == value).then_some(id)
}

/// Encodes a `Request`, or returns `None` when the frame exceeds the contract limit.
pub(super) fn encode_request(id: Uuid, command: &str, arguments: Value) -> Option<Vec<u8>> {
    let mut members = Map::new();
    members.insert("kind".to_owned(), Value::String("Request".to_owned()));
    members.insert("id".to_owned(), Value::String(id.hyphenated().to_string()));
    members.insert("command".to_owned(), Value::String(command.to_owned()));
    members.insert("arguments".to_owned(), arguments);

    let body = serde_json::to_vec(&Value::Object(members)).ok()?;
    let len = u32::try_from(body.len()).ok().filter(|len| *len <= MAX_FRAME_LEN)?;

    let mut frame = Vec::with_capacity(4 /* Length */ + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Some(frame)
}

pub(super) fn encode_frame(frame: OutgoingFrame) -> Vec<u8> {
    let body = match frame {
        OutgoingFrame::Welcome => format!(r#"{{"kind":"Welcome","protocolVersion":{PROTOCOL_VERSION}}}"#),
        OutgoingFrame::Ping => r#"{"kind":"Ping"}"#.to_owned(),
        OutgoingFrame::Pong => r#"{"kind":"Pong"}"#.to_owned(),
    };
    let len = u32::try_from(body.len()).expect("outgoing frames are small");

    let mut frame = Vec::with_capacity(4 /* Length */ + body.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(body.as_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &str) -> Vec<u8> {
        let mut bytes = u32::try_from(body.len())
            .expect("test body fits")
            .to_le_bytes()
            .to_vec();
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    async fn read(bytes: &[u8], max_len: u32) -> Result<Frame, ReadError> {
        read_frame(&mut &*bytes, max_len).await
    }

    fn frame_error(result: Result<Frame, ReadError>) -> FrameError {
        match result {
            Err(ReadError::Frame(error)) => error,
            other => panic!("expected a frame error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_is_read_with_unknown_members_ignored() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let bytes = framed(r#"{"kind":"Hello","protocolVersion":1,"clientVersion":"3.0","extra":[1]}"#);

        let frame = read(&bytes, MAX_HELLO_LEN).await.expect("valid hello");

        assert_eq!(
            frame,
            Frame::Hello {
                protocol_version: 1,
                client_version: "3.0".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn frame_length_outside_the_contract_range_is_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        assert_eq!(
            frame_error(read(&0u32.to_le_bytes(), MAX_FRAME_LEN).await),
            FrameError::InvalidLength
        );
        assert_eq!(
            frame_error(read(&(MAX_FRAME_LEN + 1).to_le_bytes(), MAX_FRAME_LEN).await),
            FrameError::InvalidLength
        );
    }

    #[tokio::test]
    async fn oversized_hello_is_rejected_before_its_body_is_read() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let mut bytes = (MAX_HELLO_LEN + 1).to_le_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b' ', 8));

        assert_eq!(
            frame_error(read(&bytes, MAX_HELLO_LEN).await),
            FrameError::InvalidLength
        );
    }

    #[tokio::test]
    async fn malformed_frames_are_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        for (body, expected) in [
            ("{", FrameError::InvalidJson),
            ("[]", FrameError::InvalidJson),
            (r#"{"protocolVersion":1}"#, FrameError::MissingKind),
            (r#"{"kind":7}"#, FrameError::MissingKind),
            (r#"{"kind":"Bogus"}"#, FrameError::UnknownKind),
            (r#"{"kind":"Hello","clientVersion":"x"}"#, FrameError::InvalidHello),
            (
                r#"{"kind":"Hello","protocolVersion":1.0,"clientVersion":"x"}"#,
                FrameError::InvalidHello,
            ),
            (r#"{"kind":"Hello","protocolVersion":1}"#, FrameError::InvalidHello),
        ] {
            assert_eq!(
                frame_error(read(&framed(body), MAX_FRAME_LEN).await),
                expected,
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn client_version_is_limited_to_128_characters() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let hello = |version: String| {
            framed(&format!(
                r#"{{"kind":"Hello","protocolVersion":1,"clientVersion":"{version}"}}"#
            ))
        };

        read(&hello("é".repeat(128)), MAX_HELLO_LEN)
            .await
            .expect("128 characters are accepted");
        assert_eq!(
            frame_error(read(&hello("é".repeat(129)), MAX_HELLO_LEN).await),
            FrameError::InvalidHello
        );
    }

    #[tokio::test]
    async fn request_frames_are_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let request = framed(r#"{"kind":"Request","id":"x","command":"c","arguments":{}}"#);

        assert_eq!(
            frame_error(read(&request, MAX_FRAME_LEN).await),
            FrameError::UnexpectedRequest
        );
    }

    const ID: &str = "0b9d6a1e-5c7e-4f43-9d2a-3f1c6a5e8b10";

    #[tokio::test]
    async fn valid_responses_are_decoded() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let ok = framed(&format!(r#"{{"kind":"Response","id":"{ID}","ok":true,"result":null}}"#));
        let failed = framed(&format!(
            r#"{{"kind":"Response","id":"{ID}","ok":false,"error":{{"code":"Busy","message":"later"}}}}"#
        ));
        let id = Uuid::parse_str(ID).expect("valid UUID");

        assert_eq!(
            read(&ok, MAX_FRAME_LEN).await.expect("ok response"),
            Frame::Response {
                id,
                outcome: Ok(Value::Null)
            }
        );
        assert_eq!(
            read(&failed, MAX_FRAME_LEN).await.expect("error response"),
            Frame::Response {
                id,
                outcome: Err(RemoteError {
                    code: "Busy".to_owned(),
                    message: "later".to_owned()
                })
            }
        );
    }

    #[tokio::test]
    async fn invalid_responses_are_rejected() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let long = "x".repeat(2049);
        for body in [
            r#"{"kind":"Response","ok":true,"result":1}"#.to_owned(),
            r#"{"kind":"Response","id":"x","ok":true,"result":1}"#.to_owned(),
            format!(
                r#"{{"kind":"Response","id":"{}","ok":true,"result":1}}"#,
                ID.to_uppercase()
            ),
            format!(
                r#"{{"kind":"Response","id":"{}","ok":true,"result":1}}"#,
                ID.replace('-', "")
            ),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":"true","result":1}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":true}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":false}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":false,"error":"Busy"}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":false,"error":{{"code":"Nope","message":""}}}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":false,"error":{{"code":"Busy"}}}}"#),
            format!(r#"{{"kind":"Response","id":"{ID}","ok":false,"error":{{"code":"Busy","message":"{long}"}}}}"#),
        ] {
            assert_eq!(
                frame_error(read(&framed(&body), MAX_FRAME_LEN).await),
                FrameError::InvalidResponse,
                "{body}"
            );
        }
    }

    #[test]
    fn request_is_encoded_with_its_correlation_id_and_bounded() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let id = Uuid::parse_str(ID).expect("valid UUID");

        let bytes = encode_request(id, "GetInventorySnapshot", serde_json::json!({})).expect("small request");

        let (prefix, body) = bytes.split_at(4);
        assert_eq!(
            usize::try_from(u32::from_le_bytes(prefix.try_into().expect("4 bytes"))),
            Ok(body.len())
        );
        let json: Value = serde_json::from_slice(body).expect("valid JSON");
        assert_eq!(
            json,
            serde_json::json!({"kind": "Request", "id": ID, "command": "GetInventorySnapshot", "arguments": {}})
        );
        let oversized = serde_json::json!({"padding": "x".repeat(MAX_FRAME_LEN as usize)});
        assert!(encode_request(id, "c", oversized).is_none());
    }

    // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
    #[tokio::test]
    async fn truncated_body_is_rejected() {
        let mut bytes = framed(r#"{"kind":"Ping"}"#);
        bytes[0] += 1;

        assert!(read(&bytes, MAX_FRAME_LEN).await.is_err());
    }

    #[tokio::test]
    async fn read_stops_at_the_frame_boundary() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let mut bytes = framed(r#"{"kind":"Ping"}"#);
        bytes.extend_from_slice(b"next");
        let mut reader = &*bytes;

        read_frame(&mut reader, MAX_FRAME_LEN).await.expect("ping");

        assert_eq!(reader, b"next");
    }

    #[test]
    fn welcome_is_length_prefixed_json() {
        // oracle: contract crates/agent-channel-proto/CONTRACT.package-management.md §registration
        let bytes = encode_frame(OutgoingFrame::Welcome);

        let (prefix, body) = bytes.split_at(4);
        assert_eq!(
            usize::try_from(u32::from_le_bytes(prefix.try_into().expect("4 bytes"))),
            Ok(body.len())
        );
        let json: Value = serde_json::from_slice(body).expect("valid JSON");
        assert_eq!(json, serde_json::json!({"kind": "Welcome", "protocolVersion": 1}));
    }
}
