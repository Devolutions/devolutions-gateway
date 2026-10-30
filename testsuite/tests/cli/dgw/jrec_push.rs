//! `/jet/jrec/push` tests: how a producer closes its push decides whether the recording waits for a reconnection.

use std::time::{Duration, Instant};

use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use testsuite::cli::start_dgw;
use testsuite::dgw_config::DgwConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use uuid::Uuid;

/// The close code a producer sends when its recording is over (`RECORDING_ENDED_CLOSE_CODE` in Gateway).
const RECORDING_ENDED_CLOSE_CODE: u16 = 4011;

/// Far longer than any test runs, so only an ended recording can leave the active list.
const REUSE_WINDOW_SECONDS: u32 = 3600;

/// An unsigned token; the Gateway under test runs with token validation disabled.
fn unsigned_token(header: serde_json::Value, claims: serde_json::Value) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(serde_json::to_vec(&header).expect("serialize header"));
    let payload = engine.encode(serde_json::to_vec(&claims).expect("serialize claims"));
    let signature = engine.encode(b"signature");
    format!("{header}.{payload}.{signature}")
}

fn push_token(session_id: Uuid) -> String {
    unsigned_token(
        serde_json::json!({"alg": "RS256", "cty": "JREC"}),
        serde_json::json!({
            "jet_aid": session_id,
            "jet_rop": "push",
            "jet_reuse": REUSE_WINDOW_SECONDS,
            "jti": Uuid::new_v4(),
            "nbf": 1_733_669_999i64,
            "exp": 3_331_553_599i64,
        }),
    )
}

fn recordings_read_token() -> String {
    unsigned_token(
        serde_json::json!({"typ": "JWT", "alg": "RS256"}),
        serde_json::json!({
            "type": "scope",
            "scope": "gateway.recordings.read",
            "jti": Uuid::new_v4(),
            "iat": 1_733_669_999i64,
            "nbf": 1_733_669_999i64,
            "exp": 3_331_553_599i64,
        }),
    )
}

async fn active_recordings(http_port: u16) -> Vec<Uuid> {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{http_port}/jet/jrec/list?active=true"))
        .bearer_auth(recordings_read_token())
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("list active recordings")
        .error_for_status()
        .expect("list active recordings succeeded")
        .json()
        .await
        .expect("parse active recordings")
}

/// Pushes a few bytes for `session_id`, closes the push with `code`, and waits for Gateway to answer the close.
async fn push_and_close(http_port: u16, session_id: Uuid, code: CloseCode) {
    let url = format!(
        "ws://127.0.0.1:{http_port}/jet/jrec/push/{session_id}?fileType=webm&token={}",
        push_token(session_id)
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.expect("open push");
    socket
        .send(Message::Binary(vec![0x1A, 0x45, 0xDF, 0xA3].into()))
        .await
        .expect("push bytes");

    let started = Instant::now();
    while !active_recordings(http_port).await.contains(&session_id) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the push never became an active recording"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: "".into(),
        })))
        .await
        .expect("close push");
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .expect("Gateway answered the close")
    {
        if message.is_err() {
            break;
        }
    }
}

// oracle: intent devolutions-gateway/src/recording.intent.md §Ending a recording
#[tokio::test]
async fn a_push_closed_as_ended_leaves_the_active_recordings_without_waiting_for_a_reconnection() {
    let recordings = tempfile::tempdir().expect("create recording dir");
    let config = DgwConfig::builder()
        .disable_token_validation(true)
        .recording_path(recordings.path().to_path_buf())
        .build()
        .init()
        .expect("init gateway config");
    let _gateway = start_dgw(&config).await.expect("start gateway");
    let session_id = Uuid::new_v4();

    push_and_close(
        config.http_port(),
        session_id,
        CloseCode::from(RECORDING_ENDED_CLOSE_CODE),
    )
    .await;

    let started = Instant::now();
    while active_recordings(config.http_port()).await.contains(&session_id) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the ended recording is still waiting for a reconnection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// oracle: intent devolutions-gateway/src/recording.intent.md §Ending a recording
#[tokio::test]
async fn a_push_closed_as_ended_leaves_the_active_recordings_while_another_waits_for_a_reconnection() {
    let recordings = tempfile::tempdir().expect("create recording dir");
    let config = DgwConfig::builder()
        .disable_token_validation(true)
        .recording_path(recordings.path().to_path_buf())
        .build()
        .init()
        .expect("init gateway config");
    let _gateway = start_dgw(&config).await.expect("start gateway");
    let waiting = Uuid::new_v4();
    let ended = Uuid::new_v4();

    // The waiting recording holds Gateway's removal timer at its one-hour deadline.
    push_and_close(config.http_port(), waiting, CloseCode::Normal).await;
    push_and_close(config.http_port(), ended, CloseCode::from(RECORDING_ENDED_CLOSE_CODE)).await;

    let started = Instant::now();
    while active_recordings(config.http_port()).await.contains(&ended) {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the ended recording waits for the other recording's reconnection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// oracle: intent devolutions-gateway/src/recording.intent.md §Ending a recording
#[tokio::test]
async fn a_push_closed_normally_keeps_the_recording_open_for_a_reconnection() {
    let recordings = tempfile::tempdir().expect("create recording dir");
    let config = DgwConfig::builder()
        .disable_token_validation(true)
        .recording_path(recordings.path().to_path_buf())
        .build()
        .init()
        .expect("init gateway config");
    let _gateway = start_dgw(&config).await.expect("start gateway");
    let session_id = Uuid::new_v4();

    // A producer that resizes its session closes the push like this and reconnects with the next clip.
    push_and_close(config.http_port(), session_id, CloseCode::Normal).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(active_recordings(config.http_port()).await.contains(&session_id));
}
