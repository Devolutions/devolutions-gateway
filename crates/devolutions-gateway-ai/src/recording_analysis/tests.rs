#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::*;
use crate::Provider;

const MODEL: &str = "gpt-test";
const REPORTED_MODEL: &str = "gpt-test-2026-09-30";

/// A mock OpenAI-compatible provider: `status` picks the answer of the n-th request, 0 being a valid answer.
///
/// Returns a client for it and the bodies of the requests it got.
async fn spawn_provider(status: fn(usize) -> u16) -> (AiClient, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));

    tokio::spawn({
        let requests = Arc::clone(&requests);
        async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let requests = Arc::clone(&requests);

                tokio::spawn(async move {
                    let mut stream = BufReader::new(stream);
                    let mut content_length = 0;

                    loop {
                        let mut line = String::new();
                        stream.read_line(&mut line).await.unwrap();
                        let line = line.trim_end();

                        if line.is_empty() {
                            break;
                        }

                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            content_length = value.trim().parse().unwrap();
                        }
                    }

                    let mut body = vec![0; content_length];
                    stream.read_exact(&mut body).await.unwrap();

                    let index = {
                        let mut requests = requests.lock().unwrap();
                        requests.push(String::from_utf8(body).unwrap());
                        requests.len() - 1
                    };

                    let (status, answer) = match status(index) {
                        0 => (
                            200,
                            serde_json::json!({
                                "model": REPORTED_MODEL,
                                "choices": [{
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": format!("{{\"line\":\"L1\",\"description\":\"Step {index}\"}}"),
                                    },
                                    "finish_reason": "stop",
                                }],
                                "usage": { "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30 },
                            }),
                        ),
                        status => (
                            status,
                            serde_json::json!({ "error": { "message": "scripted failure" } }),
                        ),
                    };

                    let answer = answer.to_string();
                    let response = format!(
                        "HTTP/1.1 {status} Scripted\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    stream.get_mut().write_all(response.as_bytes()).await.unwrap();
                });
            }
        }
    });

    let client = AiClient::builder()
        .provider(Provider::OpenAiCompatible)
        .base_url(format!("http://{addr}/v1/").parse().unwrap())
        .model(MODEL)
        .api_key("sk-test-secret")
        .http_client(reqwest::Client::new())
        .build()
        .unwrap();

    (client, requests)
}

/// A finished session with one terminal recording of `lines` lines of about 100 bytes each.
struct Session {
    _dir: tempfile::TempDir,
    manifest: RecordingManifest,
    manifest_path: Utf8PathBuf,
}

impl Session {
    fn new(lines: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8Path::from_path(dir.path()).unwrap();

        let mut cast = String::from("{\"version\": 2}\n");
        for line in 0..lines {
            cast.push_str(&format!("[{line}.0,\"o\",\"line {line} {}\\r\\n\"]\n", "x".repeat(80)));
        }
        std::fs::write(path.join("recording-0.cast"), cast).unwrap();

        Self {
            manifest: RecordingManifest {
                start_time: 1_787_255_035,
                duration: i64::try_from(lines).unwrap(),
                recordings: Recordings::Terminal(vec![
                    TerminalRecording::new("recording-0.cast", 1_787_255_035).unwrap(),
                ]),
            },
            manifest_path: path.join("recording.json"),
            _dir: dir,
        }
    }

    fn workspace(&self) -> Utf8PathBuf {
        recording_dir(&self.manifest_path).join(WORKSPACE_DIR)
    }

    async fn analyze(&self, client: &AiClient) -> Result<RecordingAnalysis, RecordingAnalysisError> {
        finish(client.analyze_recording(&self.manifest, &self.manifest_path).start())
            .await
            .1
    }
}

/// Reads the events of an analysis to the last one, and returns its progress and its result.
async fn finish(
    mut events: mpsc::Receiver<RecordingAnalysisEvent>,
) -> (Vec<Progress>, Result<RecordingAnalysis, RecordingAnalysisError>) {
    let mut progress = Vec::new();

    while let Some(event) = events.recv().await {
        match event {
            RecordingAnalysisEvent::Progress(step) => progress.push(step),
            RecordingAnalysisEvent::Complete(analysis) => {
                assert!(events.recv().await.is_none(), "Complete is the last event");
                return (progress, Ok(analysis));
            }
            RecordingAnalysisEvent::Failure(error) => {
                assert!(events.recv().await.is_none(), "Failure is the last event");
                return (progress, Err(error));
            }
        }
    }

    panic!("the events ended without a last event");
}

fn descriptions(log: &Utf8Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["description"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn the_log_is_left_next_to_the_manifest_and_the_working_files_removed() {
    let session = Session::new(10);
    let (client, _requests) = spawn_provider(|_| 0).await;
    let (progress, analysis) = finish(
        client
            .analyze_recording(&session.manifest, &session.manifest_path)
            .start(),
    )
    .await;
    let analysis = analysis.unwrap();

    assert_eq!(analysis.log_path, recording_dir(&session.manifest_path).join(LOG_FILE));
    assert_eq!(analysis.actions, 1);
    assert_eq!(analysis.model, REPORTED_MODEL);
    assert_eq!(
        analysis.usage,
        Some(Usage {
            input_tokens: 10,
            output_tokens: 20
        })
    );
    assert_eq!(
        descriptions(&analysis.log_path),
        ["Session started", "Step 0", "Session ended"]
    );
    assert!(!session.workspace().exists());
    let recording_size = std::fs::metadata(recording_dir(&session.manifest_path).join("recording-0.cast"))
        .unwrap()
        .len();
    let Some(Progress::Reading {
        read_bytes,
        total_bytes,
    }) = progress.first().copied()
    else {
        panic!("reading the recording is reported first: {progress:?}");
    };
    assert_eq!(total_bytes, recording_size);
    assert!(read_bytes <= total_bytes);
    assert_eq!(
        progress
            .iter()
            .filter(|step| matches!(step, Progress::Describing { .. }))
            .copied()
            .collect::<Vec<_>>(),
        [
            Progress::Describing {
                described_chunks: 0,
                total_chunks: 1
            },
            Progress::Describing {
                described_chunks: 1,
                total_chunks: 1
            },
        ]
    );
    assert_eq!(progress.last(), Some(&Progress::Writing));
}

#[tokio::test]
async fn analysing_again_only_asks_about_the_chunks_left() {
    // About 1 MB of transcript: three chunks.
    let session = Session::new(10_000);
    let (client, requests) = spawn_provider(|index| if index == 1 { 503 } else { 0 }).await;

    let error = session.analyze(&client).await.unwrap_err();
    assert!(error.is_transient(), "{error:?}");
    assert!(session.workspace().join("chunk-0000.json").exists());
    assert!(!session.workspace().join("chunk-0001.json").exists());

    let analysis = session.analyze(&client).await.unwrap();

    assert_eq!(requests.lock().unwrap().len(), 4, "only chunks 1 and 2 are sent again");
    assert_eq!(
        descriptions(&analysis.log_path),
        ["Session started", "Step 0", "Step 2", "Step 3", "Session ended"]
    );
    assert_eq!(
        analysis.usage,
        Some(Usage {
            input_tokens: 30,
            output_tokens: 60
        }),
        "chunk 0 counts from its checkpoint, the failed request not at all"
    );
}

#[tokio::test]
async fn working_files_of_another_analysis_are_not_reused() {
    let session = Session::new(10);
    let (client, requests) = spawn_provider(|index| if index == 0 { 503 } else { 0 }).await;
    session.analyze(&client).await.unwrap_err();

    let settings = session.workspace().join(SETTINGS_FILE);
    let saved = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(&settings, saved.replace(MODEL, "another-model")).unwrap();
    checkpoint::write(
        &checkpoint::path(&session.workspace(), 0),
        &DescribedChunk {
            actions: Vec::new(),
            model: None,
            usage: None,
        },
    )
    .unwrap();

    let analysis = session.analyze(&client).await.unwrap();

    assert_eq!(requests.lock().unwrap().len(), 2, "the chunk is asked about again");
    assert_eq!(
        descriptions(&analysis.log_path),
        ["Session started", "Step 1", "Session ended"]
    );
}

#[tokio::test]
async fn a_manifest_without_recording_fails_for_good() {
    let mut session = Session::new(1);
    session.manifest.recordings = Recordings::Terminal(Vec::new());
    let (client, requests) = spawn_provider(|_| 0).await;

    let error = session.analyze(&client).await.unwrap_err();

    assert!(matches!(error, RecordingAnalysisError::NoRecording), "{error:?}");
    assert!(!error.is_transient());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_cancelled_analysis_stops() {
    let session = Session::new(10);
    let (client, requests) = spawn_provider(|_| 0).await;
    let cancel = CancellationToken::new();
    cancel.cancel();

    let (_, result) = finish(
        client
            .analyze_recording(&session.manifest, &session.manifest_path)
            .cancellation(cancel)
            .start(),
    )
    .await;
    let error = result.unwrap_err();

    assert!(matches!(error, RecordingAnalysisError::Cancelled), "{error:?}");
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn discard_removes_the_working_files_and_the_log() {
    let session = Session::new(10);
    let (client, _requests) = spawn_provider(|index| if index == 0 { 503 } else { 0 }).await;
    session.analyze(&client).await.unwrap_err();
    let log = recording_dir(&session.manifest_path).join(LOG_FILE);
    std::fs::write(&log, "left behind").unwrap();

    discard(&session.manifest_path).await.unwrap();

    assert!(!session.workspace().exists());
    assert!(!log.exists());
    assert!(recording_dir(&session.manifest_path).join("recording-0.cast").exists());
    discard(&session.manifest_path).await.unwrap();
}

#[tokio::test]
async fn dropping_the_events_cancels_the_analysis() {
    // About 1 MB of transcript: three chunks, each answered after a while.
    let session = Session::new(10_000);
    let (client, requests) = spawn_provider(|_| 0).await;

    let mut events = client
        .analyze_recording(&session.manifest, &session.manifest_path)
        .start();
    while let Some(event) = events.recv().await {
        if matches!(event, RecordingAnalysisEvent::Progress(Progress::Describing { .. })) {
            break;
        }
    }
    drop(events);

    // The analysis stops at its next step: it never gets to the log.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(requests.lock().unwrap().len() < 3, "{}", requests.lock().unwrap().len());
    assert!(!recording_dir(&session.manifest_path).join(LOG_FILE).exists());
}

#[test]
fn progress_tells_its_stage_and_how_far_it_is() {
    let reading = Progress::Reading {
        read_bytes: 1_572_864,
        total_bytes: 2_097_152,
    };
    assert_eq!(reading.stage(), "reading");
    assert_eq!(reading.done_and_total(), Some((1_572_864, 2_097_152)));
    assert_eq!(reading.percent(), 75);
    assert_eq!(reading.to_string(), "reading the recordings: 1.5 of 2.0 MB (75%)");

    let describing = Progress::Describing {
        described_chunks: 2,
        total_chunks: 5,
    };
    assert_eq!(describing.stage(), "describing");
    assert_eq!(describing.percent(), 40);
    assert_eq!(describing.to_string(), "asking the AI: 2 of 5 chunks described");

    assert_eq!(Progress::Writing.stage(), "writing");
    assert_eq!(Progress::Writing.done_and_total(), None);
    assert_eq!(Progress::Writing.to_string(), "writing the log");

    let nothing = Progress::Reading {
        read_bytes: 0,
        total_bytes: 0,
    };
    assert_eq!(nothing.percent(), 0);
}
#[test]
fn screenshots_of_several_videos_are_grouped_as_one_session() {
    // 25 screenshots from a first video, then 45 from a second one.
    let frames = (0..70)
        .map(|index| PlannedFrame {
            id: format!("F{index:05}"),
            offset_ms: if index < 25 { index * 500 } else { 60_000 + index * 500 },
        })
        .collect::<Vec<_>>();

    let groups = group_screenshots(frames.clone());

    assert_eq!(
        groups,
        [
            Chunk::Screenshots {
                frames: frames[..40].to_vec(),
                context: None,
            },
            Chunk::Screenshots {
                frames: frames[40..].to_vec(),
                context: Some(frames[39].clone()),
            },
        ],
        "the second video does not start a request of its own"
    );
}

#[test]
fn recordings_listed_out_of_order_are_read_in_time_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = Utf8Path::from_path(dir.path()).unwrap();
    std::fs::write(
        path.join("recording-0.cast"),
        "{\"version\": 2}\n[1.0,\"o\",\"first\\r\\n\"]\n",
    )
    .unwrap();
    std::fs::write(
        path.join("recording-1.cast"),
        "{\"version\": 2}\n[1.0,\"o\",\"second\\r\\n\"]\n",
    )
    .unwrap();

    // A manifest that lists the later recording first.
    let manifest = RecordingManifest {
        start_time: 100,
        duration: 60,
        recordings: Recordings::Terminal(vec![
            TerminalRecording::new("recording-1.cast", 130).unwrap(),
            TerminalRecording::new("recording-0.cast", 100).unwrap(),
        ]),
    };
    let workspace = path.join(WORKSPACE_DIR);
    let settings = WorkspaceSettings {
        prompt_version: "test".to_owned(),
        model: MODEL.to_owned(),
        chunk_len: MAX_CHUNK_LEN,
    };

    let plan = prepare(
        &manifest,
        path,
        &workspace,
        &settings,
        &Arc::new(AtomicU64::new(0)),
        &CancellationToken::new(),
    )
    .unwrap();

    assert_eq!(plan.len(), 1);
    assert_eq!(
        std::fs::read_to_string(transcript::chunk_path(&workspace, 0)).unwrap(),
        "[1.0] first\n[31.0] second\n"
    );
}
#[test]
fn halves_are_cut_on_the_line_boundary_closest_to_the_middle() {
    let line = format!("[1.0] {}\n", "a".repeat(94));
    let part = line.repeat(30);

    let (first, second) = split_in_half(&part).unwrap();

    assert_eq!(first.len(), 15 * line.len());
    assert_eq!(second.len(), 15 * line.len());

    let uneven = format!("{line}{}", "b".repeat(1900));
    let (first, second) = split_in_half(&uneven).unwrap();
    assert_eq!(first, line);
    assert_eq!(second, "b".repeat(1900));

    assert!(split_in_half(&line.repeat(3)).is_none(), "too short");
    assert!(split_in_half(&"c".repeat(MIN_SPLIT_LEN * 2)).is_none(), "one line");
}

#[test]
fn usage_total_is_unknown_once_a_count_is() {
    let usage = |input_tokens, output_tokens| Usage {
        input_tokens,
        output_tokens,
    };

    assert_eq!(add_usage(Some(usage(1, 2)), Some(usage(10, 20))), Some(usage(11, 22)));
    assert_eq!(add_usage(Some(usage(1, 2)), None), None);
    assert_eq!(add_usage(None, Some(usage(10, 20))), None);
}
