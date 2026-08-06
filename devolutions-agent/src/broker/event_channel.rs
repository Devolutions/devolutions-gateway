//! Per-operation event channel.
//!
//! For each executed operation the broker opens a dedicated local named pipe and
//! streams `NOW_BROKER` event frames to the client (see the `event_channel` module
//! of `now-policy-api`): a `Hello` frame first, then `Stdout`/`Stderr` data frames
//! (only when the request opted in via `CaptureOutput`), a `StatusUpdated` frame on
//! every status transition, and a final `Finish` frame once the operation reaches a
//! terminal status.
//!
//! Writing is strictly best-effort: a client that never connects, connects late,
//! reads too slowly, or disconnects early must never stall or fail the operation.
//! Producers push into a bounded in-memory queue; when the per-stream byte budget
//! is exhausted, data is dropped and accounted for with `StdoutOverflow` /
//! `StderrOverflow` frames.

use std::collections::VecDeque;
use std::mem;
use std::sync::{Arc, Mutex};

use now_policy_api::event_channel::{EventFrame, MAX_EVENT_FRAME_BODY_BYTES};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Prefix of per-operation event pipe names (without the `\\.\pipe\` namespace).
pub const OPERATION_PIPE_PREFIX: &str = "Devolutions.Now.PackageBroker.Operation.";

/// Maximum bytes of not-yet-written output buffered per stream (stdout / stderr).
///
/// When the budget is exhausted (client absent or reading too slowly), further
/// output is dropped and reported through overflow frames.
const PER_STREAM_BUDGET_BYTES: usize = 256 * 1024;

/// Bare pipe name for an operation's event channel, as returned to clients in the
/// `EventChannel` descriptor (no `\\.\pipe\` prefix, matching the protocol samples).
pub fn operation_pipe_name(operation_id: &str) -> String {
    format!("{OPERATION_PIPE_PREFIX}{operation_id}")
}

/// UTF-8-safe splitter turning a stream of raw bytes into `String` chunks.
///
/// Bytes may arrive split in the middle of a multi-byte UTF-8 sequence; the
/// incomplete trailing sequence is buffered until more bytes arrive. Invalid
/// sequences are replaced with U+FFFD (lossy). Yielded chunks never exceed
/// [`MAX_EVENT_FRAME_BODY_BYTES`] and never split a character across chunks.
#[derive(Debug, Default)]
pub struct Utf8StreamChunker {
    /// Incomplete trailing UTF-8 sequence carried over to the next push (< 4 bytes).
    pending: Vec<u8>,
}

impl Utf8StreamChunker {
    /// Feed raw bytes; returns zero or more complete UTF-8 chunks.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut buffer = mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);

        let mut decoded = String::new();
        let mut rest: &[u8] = &buffer;
        loop {
            match core::str::from_utf8(rest) {
                Ok(valid) => {
                    decoded.push_str(valid);
                    break;
                }
                Err(error) => {
                    let (valid, after_valid) = rest.split_at(error.valid_up_to());
                    // INVARIANT: `valid` covers `error.valid_up_to()` bytes, which
                    // `from_utf8` guarantees to be valid UTF-8.
                    decoded.push_str(core::str::from_utf8(valid).expect("validated prefix"));
                    match error.error_len() {
                        Some(invalid_len) => {
                            decoded.push(char::REPLACEMENT_CHARACTER);
                            rest = &after_valid[invalid_len..];
                        }
                        None => {
                            // Unexpected end of input: possibly a character split
                            // across reads; wait for more bytes.
                            self.pending = after_valid.to_vec();
                            break;
                        }
                    }
                }
            }
        }

        split_at_char_boundaries(decoded, MAX_EVENT_FRAME_BODY_BYTES)
    }

    /// Flush the buffered incomplete sequence (if any) at end of stream.
    pub fn flush(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        self.pending.clear();
        // The pending bytes can no longer be completed: they decode lossily to a
        // single replacement character.
        Some(char::REPLACEMENT_CHARACTER.to_string())
    }
}

/// Split `text` into chunks of at most `max_bytes` bytes, cutting only at
/// character boundaries.
fn split_at_char_boundaries(text: String, max_bytes: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    if text.len() <= max_bytes {
        return vec![text];
    }

    let mut chunks = Vec::new();
    let mut rest = text.as_str();
    while rest.len() > max_bytes {
        let mut cut = max_bytes;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        chunks.push(rest[..cut].to_owned());
        rest = &rest[cut..];
    }
    if !rest.is_empty() {
        chunks.push(rest.to_owned());
    }
    chunks
}

/// Which output stream a data chunk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// State of one output stream inside the queue.
#[derive(Debug, Default)]
struct StreamState {
    chunker: Utf8StreamChunker,
    /// Bytes of queued (not yet consumed) data frames for this stream.
    queued_bytes: usize,
    /// Bytes dropped since the last overflow frame was queued.
    skipped_bytes: u32,
}

#[derive(Debug)]
struct QueueState {
    items: VecDeque<EventFrame>,
    stdout: StreamState,
    stderr: StreamState,
    /// Set once `finish` was queued; no further items are accepted.
    closed: bool,
}

/// Shared bounded event queue between producers (executor, tracker) and the
/// pipe writer task.
#[derive(Debug)]
struct EventQueue {
    state: Mutex<QueueState>,
    /// Signalled whenever an item is queued or the queue is closed.
    notify: Notify,
    /// Fired when the queue is closed (operation reached a terminal status).
    finished: CancellationToken,
}

/// Cloneable producer handle for an operation's event channel.
///
/// All methods are non-blocking and infallible: they enqueue frames for the
/// writer task (or drop data once the bounded budget is exhausted) and are safe
/// to call from blocking threads.
#[derive(Debug, Clone)]
pub struct OperationEventSink {
    queue: Arc<EventQueue>,
}

impl OperationEventSink {
    fn new() -> Self {
        Self {
            queue: Arc::new(EventQueue {
                state: Mutex::new(QueueState {
                    items: VecDeque::new(),
                    stdout: StreamState::default(),
                    stderr: StreamState::default(),
                    closed: false,
                }),
                notify: Notify::new(),
                finished: CancellationToken::new(),
            }),
        }
    }

    /// Queue raw stdout bytes (chunked into UTF-8-safe data frames).
    pub fn stdout(&self, bytes: &[u8]) {
        self.push_output(OutputStream::Stdout, bytes);
    }

    /// Queue raw stderr bytes (chunked into UTF-8-safe data frames).
    pub fn stderr(&self, bytes: &[u8]) {
        self.push_output(OutputStream::Stderr, bytes);
    }

    /// Queue a `StatusUpdated` notification frame.
    pub fn status_updated(&self) {
        let mut state = self.queue.state.lock().expect("event queue lock poisoned");
        if state.closed {
            return;
        }
        state.items.push_back(EventFrame::StatusUpdated);
        drop(state);
        self.queue.notify.notify_one();
    }

    /// Queue the final `Finish` frame and close the queue.
    ///
    /// Flushes buffered incomplete UTF-8 sequences and pending overflow
    /// accounting first, so `Finish` is always the last frame.
    pub fn finish(&self) {
        let mut state = self.queue.state.lock().expect("event queue lock poisoned");
        if state.closed {
            return;
        }
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            let stream_state = match stream {
                OutputStream::Stdout => &mut state.stdout,
                OutputStream::Stderr => &mut state.stderr,
            };
            let tail = stream_state.chunker.flush();
            if let Some(tail) = tail {
                Self::enqueue_chunk(&mut state, stream, tail);
            }
            let stream_state = match stream {
                OutputStream::Stdout => &mut state.stdout,
                OutputStream::Stderr => &mut state.stderr,
            };
            let skipped = mem::take(&mut stream_state.skipped_bytes);
            if skipped > 0 {
                state.items.push_back(overflow_frame(stream, skipped));
            }
        }
        state.items.push_back(EventFrame::Finish);
        state.closed = true;
        drop(state);
        self.queue.finished.cancel();
        self.queue.notify.notify_one();
    }

    fn push_output(&self, stream: OutputStream, bytes: &[u8]) {
        let mut state = self.queue.state.lock().expect("event queue lock poisoned");
        if state.closed {
            return;
        }
        let stream_state = match stream {
            OutputStream::Stdout => &mut state.stdout,
            OutputStream::Stderr => &mut state.stderr,
        };
        let chunks = stream_state.chunker.push(bytes);
        let mut queued_any = false;
        for chunk in chunks {
            Self::enqueue_chunk(&mut state, stream, chunk);
            queued_any = true;
        }
        drop(state);
        if queued_any {
            self.queue.notify.notify_one();
        }
    }

    /// Queue one data chunk, respecting the per-stream byte budget.
    ///
    /// A chunk that does not fit is dropped in full and accounted in the skipped
    /// counter; once room is available again, an overflow frame is queued before
    /// the next data frame so the client learns how many bytes it missed.
    fn enqueue_chunk(state: &mut QueueState, stream: OutputStream, chunk: String) {
        let stream_state = match stream {
            OutputStream::Stdout => &mut state.stdout,
            OutputStream::Stderr => &mut state.stderr,
        };
        if stream_state.queued_bytes + chunk.len() > PER_STREAM_BUDGET_BYTES {
            let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
            stream_state.skipped_bytes = stream_state.skipped_bytes.saturating_add(len);
            return;
        }
        let skipped = mem::take(&mut stream_state.skipped_bytes);
        stream_state.queued_bytes += chunk.len();
        if skipped > 0 {
            state.items.push_back(overflow_frame(stream, skipped));
        }
        state.items.push_back(data_frame(stream, chunk));
    }

    /// Wait for and take the next queued frame; `None` once the queue is closed
    /// and fully drained.
    async fn next_frame(&self) -> Option<EventFrame> {
        loop {
            let notified = self.queue.notify.notified();
            {
                let mut state = self.queue.state.lock().expect("event queue lock poisoned");
                if let Some(frame) = state.items.pop_front() {
                    match &frame {
                        EventFrame::Stdout(data) => state.stdout.queued_bytes -= data.len(),
                        EventFrame::Stderr(data) => state.stderr.queued_bytes -= data.len(),
                        _ => {}
                    }
                    // Wake any further waiter (Notify stores a single permit).
                    if !state.items.is_empty() {
                        self.queue.notify.notify_one();
                    }
                    return Some(frame);
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Completes once [`OperationEventSink::finish`] was called.
    async fn finished(&self) {
        self.queue.finished.cancelled().await;
    }
}

fn data_frame(stream: OutputStream, chunk: String) -> EventFrame {
    match stream {
        OutputStream::Stdout => EventFrame::Stdout(chunk),
        OutputStream::Stderr => EventFrame::Stderr(chunk),
    }
}

fn overflow_frame(stream: OutputStream, bytes_skipped: u32) -> EventFrame {
    match stream {
        OutputStream::Stdout => EventFrame::StdoutOverflow { bytes_skipped },
        OutputStream::Stderr => EventFrame::StderrOverflow { bytes_skipped },
    }
}

#[cfg(windows)]
pub use windows_channel::open_operation_channel;

#[cfg(windows)]
mod windows_channel {
    use std::time::Duration;

    use anyhow::Context as _;
    use now_policy_api::event_channel::{EVENT_CHANNEL_VERSION_MAJOR, EVENT_CHANNEL_VERSION_MINOR, EventFrame};
    use now_policy_api::{EventChannel, EventChannelKind};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tracing::{debug, warn};
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::security::acl::{Acl, ExplicitAccess, InheritableAcl, InheritableAclKind, Trustee};
    use win_api_wrappers::security::attributes::SecurityAttributesInit;
    use windows::Win32::Foundation::GENERIC_ALL;
    use windows::Win32::Security;
    use windows::Win32::Security::Authorization::SET_ACCESS;
    use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    use super::{OperationEventSink, operation_pipe_name};

    /// How long the channel stays available for a late client connection after the
    /// operation finished without any client having connected.
    const NEVER_CONNECTED_LINGER: Duration = Duration::from_secs(60);

    /// After the final `Finish` frame is written, how long the writer waits for the
    /// client to drain the pipe and close its end before tearing the pipe down.
    const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

    /// Create the event channel for an operation.
    ///
    /// The named pipe instance is created (with its security descriptor) before this
    /// function returns, so the path in the returned descriptor is immediately
    /// connectable. A background task then serves at most one client, best-effort.
    ///
    /// `client_sid` is the authenticated requesting user; only that user (plus
    /// SYSTEM and Administrators) can open the pipe.
    pub fn open_operation_channel(
        operation_id: &str,
        client_sid: &Sid,
    ) -> anyhow::Result<(OperationEventSink, EventChannel)> {
        let pipe_name = operation_pipe_name(operation_id);
        let pipe_path = format!(r"\\.\pipe\{pipe_name}");

        let security_attributes = build_channel_security_attributes(client_sid)
            .context("failed to build event channel security attributes")?;

        // SAFETY: `create_with_security_attributes_raw` requires a pointer to a valid
        // `SECURITY_ATTRIBUTES` living across the call. `security_attributes` owns the
        // structure and its descriptor and outlives the call; `CreateNamedPipeW` copies
        // the descriptor and does not retain the pointer.
        //
        // The pipe is created duplex even though the protocol is one-way (server to
        // client): the DACL grants the client read access only, so nothing can be
        // written back, while the server end keeps read access so the post-`Finish`
        // drain wait below can block until the client closes its end.
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .create_with_security_attributes_raw(&pipe_path, security_attributes.as_mut_ptr().cast())
        }
        .with_context(|| format!("failed to create event channel pipe '{pipe_path}'"))?;

        let sink = OperationEventSink::new();
        let descriptor = EventChannel {
            kind: EventChannelKind::LocalPipe,
            path: pipe_name,
        };

        let writer_sink = sink.clone();
        let operation_id = operation_id.to_owned();
        tokio::spawn(async move {
            run_channel(server, writer_sink, &operation_id).await;
        });

        Ok((sink, descriptor))
    }

    /// Serve one client connection on the operation's event pipe, best-effort.
    async fn run_channel(server: NamedPipeServer, sink: OperationEventSink, operation_id: &str) {
        // Wait for a client; once the operation finishes without one, linger only
        // for a bounded grace period so late clients can still fetch the frames.
        let connected = tokio::select! {
            result = server.connect() => result.is_ok(),
            () = sink.finished() => {
                matches!(
                    tokio::time::timeout(NEVER_CONNECTED_LINGER, server.connect()).await,
                    Ok(Ok(()))
                )
            }
        };
        if !connected {
            debug!(operation_id, "No client connected to the event channel");
            return;
        }

        debug!(operation_id, "Client connected to the event channel");
        let mut server = server;

        let hello = EventFrame::Hello {
            version_major: EVENT_CHANNEL_VERSION_MAJOR,
            version_minor: EVENT_CHANNEL_VERSION_MINOR,
        };
        if let Err(error) = write_frame(&mut server, &hello).await {
            warn!(operation_id, %error, "Failed to write event channel hello frame");
            return;
        }

        while let Some(frame) = sink.next_frame().await {
            if let Err(error) = write_frame(&mut server, &frame).await {
                // Best-effort: the client disconnected or stopped reading; the
                // operation itself is unaffected.
                debug!(operation_id, %error, "Stopped writing event channel frames");
                return;
            }
        }

        // All frames (ending with `Finish`) were handed to the pipe; give the
        // client a bounded amount of time to drain and close its end so buffered
        // data is not discarded by our handle closing first. The client is
        // restricted to read access by the DACL, so this read only ever completes
        // when the client closes the pipe.
        let _ = tokio::time::timeout(CLIENT_DRAIN_TIMEOUT, async {
            let mut scratch = [0u8; 16];
            loop {
                match server.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
        debug!(operation_id, "Event channel closed");
    }

    async fn write_frame(server: &mut NamedPipeServer, frame: &EventFrame) -> anyhow::Result<()> {
        let bytes = frame.encode().context("failed to encode event frame")?;
        // No explicit flush: named pipe writes go straight to the kernel pipe
        // buffer, and tokio's named pipe `flush` is a no-op anyway.
        server.write_all(&bytes).await.context("failed to write event frame")?;
        Ok(())
    }

    /// Security descriptor for a per-operation event pipe:
    /// - SYSTEM: full control
    /// - Administrators: full control
    /// - requesting client user: read (the channel is one-way, server to client)
    fn build_channel_security_attributes(
        client_sid: &Sid,
    ) -> anyhow::Result<win_api_wrappers::security::attributes::SecurityAttributes> {
        let system_sid =
            Sid::from_well_known(Security::WinLocalSystemSid, None).context("failed to create SYSTEM SID")?;
        let admins_sid = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None)
            .context("failed to create Administrators SID")?;

        let entries = [
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(system_sid),
            },
            ExplicitAccess {
                access_permissions: GENERIC_ALL.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(admins_sid),
            },
            ExplicitAccess {
                access_permissions: FILE_GENERIC_READ.0,
                access_mode: SET_ACCESS,
                inheritance: Security::ACE_FLAGS(0),
                trustee: Trustee::Sid(client_sid.clone()),
            },
        ];

        let empty_acl = Acl::new().context("failed to create empty ACL")?;
        let dacl = empty_acl.set_entries(&entries).context("failed to set ACL entries")?;

        Ok(SecurityAttributesInit {
            dacl: Some(InheritableAcl {
                kind: InheritableAclKind::Protected,
                acl: dacl,
            }),
            ..Default::default()
        }
        .init())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(chunker: &mut Utf8StreamChunker, parts: &[&[u8]]) -> Vec<String> {
        let mut out = Vec::new();
        for part in parts {
            out.extend(chunker.push(part));
        }
        if let Some(tail) = chunker.flush() {
            out.push(tail);
        }
        out
    }

    #[test]
    fn chunker_passes_ascii_through() {
        let mut chunker = Utf8StreamChunker::default();
        assert_eq!(collect(&mut chunker, &[b"hello world"]), ["hello world"]);
    }

    #[test]
    fn chunker_reassembles_char_split_across_pushes() {
        let bytes = "héllo π".as_bytes();
        for split in 1..bytes.len() {
            let mut chunker = Utf8StreamChunker::default();
            let chunks = collect(&mut chunker, &[&bytes[..split], &bytes[split..]]);
            assert_eq!(chunks.concat(), "héllo π", "split at {split}");
        }
    }

    #[test]
    fn chunker_replaces_invalid_bytes() {
        let mut chunker = Utf8StreamChunker::default();
        let chunks = collect(&mut chunker, &[&[b'a', 0xff, 0xfe, b'b']]);
        assert_eq!(chunks.concat(), "a\u{FFFD}\u{FFFD}b");
    }

    #[test]
    fn chunker_flushes_incomplete_trailing_sequence_as_replacement() {
        let mut chunker = Utf8StreamChunker::default();
        // First two bytes of a three-byte character.
        let chunks = collect(&mut chunker, &[&[b'x', 0xE2, 0x82]]);
        assert_eq!(chunks.concat(), "x\u{FFFD}");
    }

    #[test]
    fn chunker_respects_max_frame_body_size_and_char_boundaries() {
        // 'é' is 2 bytes; an odd max forces the boundary check to back off.
        let text = "é".repeat(MAX_EVENT_FRAME_BODY_BYTES); // 2 * MAX bytes total.
        let mut chunker = Utf8StreamChunker::default();
        let chunks = chunker.push(text.as_bytes());
        assert!(chunks.len() >= 2);
        for chunk in &chunks {
            assert!(chunk.len() <= MAX_EVENT_FRAME_BODY_BYTES);
            assert!(chunk.chars().all(|c| c == 'é'));
        }
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn split_at_char_boundaries_never_splits_chars() {
        let text = "aπ".repeat(10);
        let chunks = split_at_char_boundaries(text.clone(), 4);
        assert!(chunks.iter().all(|c| c.len() <= 4));
        assert_eq!(chunks.concat(), text);
    }

    #[tokio::test]
    async fn sink_orders_data_status_and_finish() {
        let sink = OperationEventSink::new();
        sink.stdout(b"out");
        sink.status_updated();
        sink.stderr(b"err");
        sink.finish();

        let mut frames = Vec::new();
        while let Some(frame) = sink.next_frame().await {
            frames.push(frame);
        }
        assert_eq!(
            frames,
            [
                EventFrame::Stdout("out".to_owned()),
                EventFrame::StatusUpdated,
                EventFrame::Stderr("err".to_owned()),
                EventFrame::Finish,
            ]
        );
    }

    #[tokio::test]
    async fn sink_ignores_events_after_finish() {
        let sink = OperationEventSink::new();
        sink.finish();
        sink.stdout(b"late");
        sink.status_updated();
        sink.finish();

        assert_eq!(sink.next_frame().await, Some(EventFrame::Finish));
        assert_eq!(sink.next_frame().await, None);
    }

    #[tokio::test]
    async fn sink_accounts_overflow_when_budget_is_exhausted() {
        let sink = OperationEventSink::new();
        let chunk = vec![b'a'; 64 * 1024];
        let pushes = 64; // 4 MiB total, way over the 256 KiB budget.
        for _ in 0..pushes {
            sink.stdout(&chunk);
        }
        sink.finish();

        let mut received = 0usize;
        let mut skipped = 0u64;
        let mut saw_finish = false;
        while let Some(frame) = sink.next_frame().await {
            match frame {
                EventFrame::Stdout(data) => received += data.len(),
                EventFrame::StdoutOverflow { bytes_skipped } => skipped += u64::from(bytes_skipped),
                EventFrame::Finish => saw_finish = true,
                other => panic!("unexpected frame: {other:?}"),
            }
        }

        assert!(saw_finish);
        assert!(skipped > 0, "expected dropped bytes");
        assert!(received <= PER_STREAM_BUDGET_BYTES);
        assert_eq!(received as u64 + skipped, (chunk.len() * pushes) as u64);
    }

    #[tokio::test]
    async fn sink_emits_overflow_frame_before_next_data_frame() {
        let sink = OperationEventSink::new();
        let big = vec![b'a'; PER_STREAM_BUDGET_BYTES]; // Fills the budget exactly (4 frames).
        sink.stdout(&big);
        sink.stdout(b"dropped");

        // Drain the queued data to free budget, then push more data.
        let mut drained = 0;
        while drained < PER_STREAM_BUDGET_BYTES {
            match sink.next_frame().await {
                Some(EventFrame::Stdout(data)) => drained += data.len(),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        sink.stdout(b"fresh");
        sink.finish();

        assert_eq!(
            sink.next_frame().await,
            Some(EventFrame::StdoutOverflow { bytes_skipped: 7 })
        );
        assert_eq!(sink.next_frame().await, Some(EventFrame::Stdout("fresh".to_owned())));
        assert_eq!(sink.next_frame().await, Some(EventFrame::Finish));
        assert_eq!(sink.next_frame().await, None);
    }
}

#[cfg(all(test, windows))]
mod pipe_tests {
    use now_policy_api::EventChannelKind;
    use now_policy_api::event_channel::{
        EVENT_CHANNEL_VERSION_MAJOR, EVENT_CHANNEL_VERSION_MINOR, EventFrame, EventFrameDecoder,
    };
    use tokio::io::AsyncReadExt as _;
    use win_api_wrappers::identity::sid::Sid;
    use win_api_wrappers::process::Process;
    use windows::Win32::Security::TOKEN_QUERY;

    use super::*;

    fn current_user_sid() -> Sid {
        Process::current_process()
            .token(TOKEN_QUERY)
            .expect("open current process token")
            .sid_and_attributes()
            .expect("query token user SID")
            .sid
    }

    fn test_operation_id(tag: &str) -> String {
        format!("test-{tag}-{}", uuid::Uuid::new_v4())
    }

    async fn read_all_frames(pipe_name: &str) -> Vec<EventFrame> {
        let path = format!(r"\\.\pipe\{pipe_name}");
        let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
            .write(false)
            .open(&path)
            .expect("connect to event channel pipe");

        let mut decoder = EventFrameDecoder::new();
        let mut frames = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = match client.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            };
            decoder.extend(&buffer[..read]);
            while let Some(frame) = decoder.next_frame().expect("valid frame stream") {
                let finish = frame == EventFrame::Finish;
                frames.push(frame);
                if finish {
                    return frames;
                }
            }
        }
        assert!(!decoder.has_buffered_data(), "stream truncated mid-frame");
        frames
    }

    fn assert_hello_first(frames: &[EventFrame]) {
        assert_eq!(
            frames.first(),
            Some(&EventFrame::Hello {
                version_major: EVENT_CHANNEL_VERSION_MAJOR,
                version_minor: EVENT_CHANNEL_VERSION_MINOR,
            })
        );
    }

    #[tokio::test]
    async fn channel_streams_hello_data_status_and_finish() {
        let operation_id = test_operation_id("stream");
        let (sink, descriptor) = open_operation_channel(&operation_id, &current_user_sid()).expect("open channel");
        assert_eq!(descriptor.kind, EventChannelKind::LocalPipe);
        assert_eq!(descriptor.path, operation_pipe_name(&operation_id));
        assert!(
            !descriptor.path.contains('\\'),
            "descriptor path must be the bare pipe name"
        );

        let reader = tokio::spawn({
            let pipe_name = descriptor.path.clone();
            async move { read_all_frames(&pipe_name).await }
        });

        sink.status_updated(); // Running.
        sink.stdout("hello π".as_bytes());
        sink.stderr(b"warning");
        sink.status_updated(); // Completed.
        sink.finish();

        let frames = reader.await.expect("reader task");
        assert_hello_first(&frames);
        assert_eq!(
            frames[1..],
            [
                EventFrame::StatusUpdated,
                EventFrame::Stdout("hello π".to_owned()),
                EventFrame::Stderr("warning".to_owned()),
                EventFrame::StatusUpdated,
                EventFrame::Finish,
            ]
        );
    }

    #[tokio::test]
    async fn channel_without_client_does_not_block_operation() {
        let operation_id = test_operation_id("noclient");
        let (sink, _descriptor) = open_operation_channel(&operation_id, &current_user_sid()).expect("open channel");

        // No client ever connects; all sink calls must return immediately.
        sink.status_updated();
        sink.stdout(&vec![b'x'; 1024 * 1024]);
        sink.finish();
    }

    #[tokio::test]
    async fn channel_serves_frames_to_late_client_after_finish() {
        let operation_id = test_operation_id("late");
        let (sink, descriptor) = open_operation_channel(&operation_id, &current_user_sid()).expect("open channel");

        sink.stdout(b"already done");
        sink.status_updated();
        sink.finish();

        // Client connects only after the operation finished (within the linger window).
        let frames = read_all_frames(&descriptor.path).await;
        assert_hello_first(&frames);
        assert_eq!(
            frames[1..],
            [
                EventFrame::Stdout("already done".to_owned()),
                EventFrame::StatusUpdated,
                EventFrame::Finish,
            ]
        );
    }

    #[tokio::test]
    async fn slow_reader_gets_overflow_frames_and_operation_is_unaffected() {
        let operation_id = test_operation_id("slow");
        let (sink, descriptor) = open_operation_channel(&operation_id, &current_user_sid()).expect("open channel");

        // Connect but do not read yet.
        let path = format!(r"\\.\pipe\{}", descriptor.path);
        let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
            .write(false)
            .open(&path)
            .expect("connect to event channel pipe");

        // Push far more than the per-stream budget plus any pipe buffering.
        let chunk = vec![b'a'; 64 * 1024];
        let pushes = 256; // 16 MiB.
        for _ in 0..pushes {
            sink.stdout(&chunk);
        }
        sink.finish();

        // Now read everything.
        let mut decoder = EventFrameDecoder::new();
        let mut received = 0u64;
        let mut skipped = 0u64;
        let mut saw_finish = false;
        let mut buffer = [0u8; 4096];
        'outer: loop {
            let read = match client.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => break,
            };
            decoder.extend(&buffer[..read]);
            while let Some(frame) = decoder.next_frame().expect("valid frame stream") {
                match frame {
                    EventFrame::Hello { .. } => {}
                    EventFrame::Stdout(data) => received += data.len() as u64,
                    EventFrame::StdoutOverflow { bytes_skipped } => skipped += u64::from(bytes_skipped),
                    EventFrame::Finish => {
                        saw_finish = true;
                        break 'outer;
                    }
                    other => panic!("unexpected frame: {other:?}"),
                }
            }
        }

        assert!(saw_finish, "finish frame must arrive even for slow readers");
        assert!(skipped > 0, "slow reader must observe overflow");
        assert_eq!(received + skipped, (chunk.len() * pushes) as u64);
    }
}
