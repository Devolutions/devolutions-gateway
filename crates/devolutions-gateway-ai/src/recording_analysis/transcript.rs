//! Turns the terminal recordings of a session into transcript chunk files sent to the AI.
//!
//! Each transcript line reads `[<seconds since the session start>] <text>`.
//! Recordings are read as a stream, so memory use depends on the chunk size, not on the recording size.

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write as _};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use camino::{Utf8Path, Utf8PathBuf};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::{TerminalFormat, TerminalRecording};

/// Longest text kept from one terminal line, in characters.
const MAX_LINE_CHARS: usize = 500;

/// Longest asciicast event read; a longer one is skipped.
const MAX_CAST_EVENT_LEN: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(super) enum TranscriptError {
    #[error("failed to read {file_name}: {reason}")]
    Invalid { file_name: String, reason: String },
    #[error("failed to write the transcript: {0}")]
    Write(io::Error),
    #[error("transcript cancelled before its end")]
    Cancelled,
}

pub(super) fn chunk_path(workspace: &Utf8Path, index: usize) -> Utf8PathBuf {
    workspace.join(format!("transcript-{index:04}.txt"))
}

/// Writes the transcript of `recordings`, read from `dir`, into chunk files of at most `max_len` bytes in `workspace`,
/// cut on line boundaries, and returns the number of chunks.
///
/// Times are counted from `session_start`, in Unix seconds. The bytes read from the recordings are added to
/// `read_bytes`.
/// Returns [`TranscriptError::Cancelled`] soon after `cancel` is cancelled, leaving the chunk files incomplete.
pub(super) fn write_chunks(
    recordings: &[TerminalRecording],
    session_start: i64,
    dir: &Utf8Path,
    workspace: &Utf8Path,
    max_len: usize,
    read_bytes: &Arc<AtomicU64>,
    cancel: &CancellationToken,
) -> Result<usize, TranscriptError> {
    let mut transcript = Transcript::new(ChunkWriter::new(workspace, max_len), cancel);

    for recording in recordings {
        let to_transcript_error = |error: CastError| match error {
            CastError::Read(reason) => TranscriptError::Invalid {
                file_name: recording.file_name().to_owned(),
                reason,
            },
            CastError::Write(error) => TranscriptError::Write(error),
            CastError::Cancelled => TranscriptError::Cancelled,
        };

        let offset = u32::try_from(recording.start_time().saturating_sub(session_start).max(0)).unwrap_or(u32::MAX);
        let offset = f64::from(offset);

        let file = super::open_counted(&dir.join(recording.file_name()), read_bytes)
            .map(BufReader::new)
            .map_err(|error| to_transcript_error(CastError::Read(error.to_string())))?;

        match recording.format() {
            TerminalFormat::Asciicast => transcript.add_cast(file, offset),
            TerminalFormat::Trp => transcript.add_trp(file, offset),
        }
        .map_err(to_transcript_error)?;
    }

    transcript.chunks.finish().map_err(TranscriptError::Write)
}
enum CastError {
    Read(String),
    Write(io::Error),
    Cancelled,
}

/// Writes lines into numbered chunk files, starting a new file when the next line would not fit.
struct ChunkWriter {
    workspace: Utf8PathBuf,
    max_len: usize,
    count: usize,
    current: Option<BufWriter<File>>,
    current_len: usize,
}

impl ChunkWriter {
    fn new(workspace: &Utf8Path, max_len: usize) -> Self {
        Self {
            workspace: workspace.to_owned(),
            max_len,
            count: 0,
            current: None,
            current_len: 0,
        }
    }

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        if self.current.is_some() && self.current_len + line.len() > self.max_len {
            self.close_current()?;
        }

        let current = match &mut self.current {
            Some(current) => current,
            None => {
                let file = File::create(chunk_path(&self.workspace, self.count))?;
                self.count += 1;
                self.current_len = 0;
                self.current.insert(BufWriter::new(file))
            }
        };

        current.write_all(line.as_bytes())?;
        self.current_len += line.len();

        Ok(())
    }

    fn close_current(&mut self) -> io::Result<()> {
        if let Some(current) = self.current.take() {
            current
                .into_inner()
                .map_err(io::IntoInnerError::into_error)?
                .sync_all()?;
        }

        Ok(())
    }

    fn finish(mut self) -> io::Result<usize> {
        self.close_current()?;
        Ok(self.count)
    }
}

struct Transcript<'a> {
    chunks: ChunkWriter,
    last_line: String,
    cancel: &'a CancellationToken,
}

impl<'a> Transcript<'a> {
    fn new(chunks: ChunkWriter, cancel: &'a CancellationToken) -> Self {
        Self {
            chunks,
            last_line: String::new(),
            cancel,
        }
    }

    /// Adds the terminal output of an asciicast v2 or v3 recording that started `offset` seconds into the session.
    fn add_cast(&mut self, mut cast: impl BufRead, offset: f64) -> Result<(), CastError> {
        let mut line = Vec::new();

        let events = core::iter::from_fn(|| match read_event(&mut cast, &mut line) {
            Ok(true) => Some(Ok(core::mem::take(&mut line))),
            Ok(false) => None,
            Err(error) => Some(Err(CastError::Read(error.to_string()))),
        });

        self.add_cast_events(events, offset)
    }

    /// Adds the terminal output of a TRP recording that started `offset` seconds into the session.
    fn add_trp(&mut self, trp: impl io::Read, offset: f64) -> Result<(), CastError> {
        let events = terminal_streamer::trp_decoder::AsciicastLines::new(trp).map(|line| {
            line.map(String::into_bytes)
                .map_err(|error| CastError::Read(format!("{error:#}")))
        });

        self.add_cast_events(events, offset)
    }

    /// Adds the terminal output of asciicast lines, the header first.
    fn add_cast_events(
        &mut self,
        mut lines: impl Iterator<Item = Result<Vec<u8>, CastError>>,
        offset: f64,
    ) -> Result<(), CastError> {
        let header = loop {
            let line = lines
                .next()
                .ok_or_else(|| CastError::Read("empty asciicast".to_owned()))??;

            if !line.trim_ascii().is_empty() {
                break serde_json::from_slice::<serde_json::Value>(&line)
                    .map_err(|error| CastError::Read(format!("invalid asciicast header: {error}")))?;
            }
        };

        let relative_times = header["version"].as_u64() == Some(3);

        let mut terminal = TerminalText::default();
        let mut time = 0.0;

        for line in lines {
            if self.cancel.is_cancelled() {
                return Err(CastError::Cancelled);
            }

            // Only the output is used: typed passwords are usually not echoed, but printed secrets still reach the AI.
            let Ok((event_time, code, data)) = serde_json::from_slice::<(f64, String, String)>(&line?) else {
                continue;
            };

            time = if relative_times { time + event_time } else { event_time };

            if code == "o" {
                terminal.feed(offset + time, &data, self).map_err(CastError::Write)?;
            }
        }

        terminal.end_line(self).map_err(CastError::Write)
    }

    fn push_line(&mut self, time: f64, text: &str) -> io::Result<()> {
        let text = text.trim();

        if text.is_empty() || text == self.last_line {
            return Ok(());
        }

        let text = match text.char_indices().nth(MAX_LINE_CHARS) {
            Some((cut, _)) => &text[..cut],
            None => text,
        };

        self.chunks.write_line(&format!("[{time:.1}] {text}\n"))?;
        text.clone_into(&mut self.last_line);

        Ok(())
    }
}

/// Reads the next asciicast event into `line`, skipping events longer than [`MAX_CAST_EVENT_LEN`].
fn read_event(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<bool> {
    let limit = u64::try_from(MAX_CAST_EVENT_LEN).unwrap_or(u64::MAX);

    loop {
        line.clear();

        if io::Read::take(&mut *reader, limit).read_until(b'\n', line)? == 0 {
            return Ok(false);
        }

        if line.len() < MAX_CAST_EVENT_LEN || line.ends_with(b"\n") {
            return Ok(true);
        }

        warn!(max_len = MAX_CAST_EVENT_LEN, "Skipped an oversized asciicast event");
        skip_line(reader)?;
    }
}

fn skip_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = reader.fill_buf()?;

        if buffer.is_empty() {
            return Ok(());
        }

        if let Some(end) = buffer.iter().position(|&byte| byte == b'\n') {
            reader.consume(end + 1);
            return Ok(());
        }

        let len = buffer.len();
        reader.consume(len);
    }
}

#[derive(Default, Clone, Copy)]
enum EscapeState {
    #[default]
    Text,
    Escape,
    EscapeArgument,
    ControlSequence,
    OperatingSystemCommand,
    OperatingSystemCommandEscape,
}

/// Rebuilds the text lines of a terminal output stream, without escape sequences.
#[derive(Default)]
struct TerminalText {
    state: EscapeState,
    line: String,
    line_start: Option<f64>,
    carriage_return: bool,
}

impl TerminalText {
    fn feed(&mut self, time: f64, data: &str, transcript: &mut Transcript<'_>) -> io::Result<()> {
        for c in data.chars() {
            self.state = match (self.state, c) {
                (EscapeState::Text, '\x1b') => EscapeState::Escape,
                (EscapeState::Text, '\n') => {
                    self.end_line(transcript)?;
                    EscapeState::Text
                }
                (EscapeState::Text, '\r') => {
                    self.carriage_return = true;
                    EscapeState::Text
                }
                (EscapeState::Text, '\x08') => {
                    self.line.pop();
                    EscapeState::Text
                }
                (EscapeState::Text, '\t') => {
                    self.put(' ', time);
                    EscapeState::Text
                }
                (EscapeState::Text, c) => {
                    if !c.is_control() {
                        self.put(c, time);
                    }
                    EscapeState::Text
                }
                (EscapeState::Escape, '[') => EscapeState::ControlSequence,
                (EscapeState::Escape, ']') => EscapeState::OperatingSystemCommand,
                (EscapeState::Escape, '(' | ')' | '*' | '+' | '#' | '%') => EscapeState::EscapeArgument,
                (EscapeState::Escape | EscapeState::EscapeArgument | EscapeState::OperatingSystemCommandEscape, _) => {
                    EscapeState::Text
                }
                (EscapeState::ControlSequence, '\x40'..='\x7e') => EscapeState::Text,
                (EscapeState::ControlSequence, _) => EscapeState::ControlSequence,
                (EscapeState::OperatingSystemCommand, '\x07') => EscapeState::Text,
                (EscapeState::OperatingSystemCommand, '\x1b') => EscapeState::OperatingSystemCommandEscape,
                (EscapeState::OperatingSystemCommand, _) => EscapeState::OperatingSystemCommand,
            };
        }

        Ok(())
    }

    fn put(&mut self, c: char, time: f64) {
        // A carriage return not followed by a line feed means the line is redrawn.
        if self.carriage_return {
            self.carriage_return = false;
            self.line.clear();
            self.line_start = None;
        }

        self.line_start.get_or_insert(time);

        // Text past the kept length is dropped anyway, so a line that never ends cannot grow without bound.
        if self.line.len() < MAX_LINE_CHARS * 4 {
            self.line.push(c);
        }
    }

    fn end_line(&mut self, transcript: &mut Transcript<'_>) -> io::Result<()> {
        self.carriage_return = false;

        if let Some(start) = self.line_start.take() {
            transcript.push_line(start, &self.line)?;
        }

        self.line.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn read_chunks(dir: &Utf8Path, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| std::fs::read_to_string(chunk_path(dir, index)).expect("chunk file"))
            .collect()
    }

    fn transcript_of(cast: &str, offset: f64) -> String {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Utf8Path::from_path(dir.path()).expect("UTF-8");
        let cancel = CancellationToken::new();
        let mut transcript = Transcript::new(ChunkWriter::new(dir, usize::MAX), &cancel);
        assert!(transcript.add_cast(cast.as_bytes(), offset).is_ok());
        let count = transcript.chunks.finish().expect("written");
        read_chunks(dir, count).concat()
    }

    const CAST: &str = r#"{"version": 2, "width": 80, "height": 24}
[0.3,"o","\u001b]0;user@host: ~\u0007\u001b[01;32muser@host\u001b[00m:~$ "]
[1.0,"i","l"]
[1.1,"o","l"]
[1.2,"o","s\r\n"]
[1.5,"o","file-a  file-b\r\n"]
[2.0,"o","user@host:~$ sudo passwd david\r\n[sudo] password for user: "]
[3.0,"i","hunter2\r"]
[3.5,"o","\r\n"]
[4.0,"o","progress 10%\rprogress 100%\r\n"]
[5.0,"o","same\r\nsame\r\n"]
[6.0,"o","typo\b\b\u001b[Kps\r\n"]
[7.0,"r","100x30"]
"#;

    #[test]
    fn cast_output_becomes_timed_plain_lines() {
        assert_eq!(
            transcript_of(CAST, 10.0),
            concat!(
                "[10.3] user@host:~$ ls\n",
                "[11.5] file-a  file-b\n",
                "[12.0] user@host:~$ sudo passwd david\n",
                "[12.0] [sudo] password for user:\n",
                "[14.0] progress 100%\n",
                "[15.0] same\n",
                "[16.0] typs\n",
            )
        );
    }

    #[test]
    fn asciicast_v3_times_are_intervals() {
        let cast = "{\"version\": 3, \"term\": {\"cols\": 80, \"rows\": 24}}\n[1.0,\"o\",\"a\\r\\n\"]\n[0.5,\"o\",\"b\\r\\n\"]\n";

        assert_eq!(transcript_of(cast, 0.0), "[1.0] a\n[1.5] b\n");
    }

    #[test]
    fn long_lines_are_cut() {
        let cast = format!(
            "{{\"version\": 2}}\n[0,\"o\",\"{}\"]\n",
            "é".repeat(MAX_LINE_CHARS + 10)
        );

        let transcript = transcript_of(&cast, 0.0);

        assert_eq!(transcript.trim_end().chars().count(), "[0.0] ".len() + MAX_LINE_CHARS);
    }

    #[test]
    fn oversized_cast_events_are_skipped() {
        let cast = format!(
            "{{\"version\": 2}}\n[0,\"o\",\"{}\"]\n[1,\"o\",\"kept\\r\\n\"]\n",
            "x".repeat(MAX_CAST_EVENT_LEN)
        );

        assert_eq!(transcript_of(&cast, 0.0), "[1.0] kept\n");
    }

    #[test]
    fn chunks_keep_whole_lines_within_the_budget() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Utf8Path::from_path(dir.path()).expect("UTF-8");
        let mut chunks = ChunkWriter::new(dir, 22);
        for line in ["[1.0] aaaa\n", "[2.0] bbbb\n", "[3.0] cccc\n"] {
            chunks.write_line(line).expect("written");
        }

        let count = chunks.finish().expect("written");

        assert_eq!(read_chunks(dir, count), ["[1.0] aaaa\n[2.0] bbbb\n", "[3.0] cccc\n"]);
        assert_eq!(ChunkWriter::new(dir, 22).finish().expect("nothing written"), 0);
    }

    /// Generates a large recording lazily and records how many events were read when the first chunk file was complete.
    struct LazyRecording {
        next_event: usize,
        events: usize,
        event: fn(usize) -> Vec<u8>,
        pending: Vec<u8>,
        second_chunk: Utf8PathBuf,
        read_when_first_chunk_done: Arc<AtomicUsize>,
    }

    impl LazyRecording {
        fn new(dir: &Utf8Path, events: usize, event: fn(usize) -> Vec<u8>) -> (Self, Arc<AtomicUsize>) {
            let read_when_first_chunk_done = Arc::new(AtomicUsize::new(0));
            let recording = Self {
                next_event: 0,
                events,
                event,
                pending: Vec::new(),
                second_chunk: chunk_path(dir, 1),
                read_when_first_chunk_done: Arc::clone(&read_when_first_chunk_done),
            };
            (recording, read_when_first_chunk_done)
        }
    }

    impl io::Read for LazyRecording {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pending.is_empty() {
                if self.next_event == self.events {
                    return Ok(0);
                }

                if self.second_chunk.exists() {
                    let _ = self.read_when_first_chunk_done.compare_exchange(
                        0,
                        self.next_event,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }

                self.pending = (self.event)(self.next_event);
                self.next_event += 1;
            }

            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    fn cast_event(event: usize) -> Vec<u8> {
        if event == 0 {
            b"{\"version\": 2}\n".to_vec()
        } else {
            format!("[{event}.0,\"o\",\"line {event} of a long session\\r\\n\"]\n").into_bytes()
        }
    }

    fn trp_packet(time_delta: u32, event_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&time_delta.to_le_bytes());
        packet.extend_from_slice(&event_type.to_le_bytes());
        packet.extend_from_slice(&u16::try_from(payload.len()).expect("small").to_le_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn trp_event(event: usize) -> Vec<u8> {
        if event == 0 {
            trp_packet(0, 4, b"")
        } else {
            trp_packet(1000, 0, format!("line {event} of a long session\r\n").as_bytes())
        }
    }

    fn assert_streamed_into_bounded_chunk_files(event: fn(usize) -> Vec<u8>, trp: bool) {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Utf8Path::from_path(dir.path()).expect("UTF-8");
        let events = 20_000;
        let (recording, read_when_first_chunk_done) = LazyRecording::new(dir, events, event);

        let cancel = CancellationToken::new();
        let mut transcript = Transcript::new(ChunkWriter::new(dir, 4096), &cancel);
        let recording = BufReader::with_capacity(64, recording);
        let added = if trp {
            transcript.add_trp(recording, 0.0)
        } else {
            transcript.add_cast(recording, 0.0)
        };
        assert!(added.is_ok());
        let count = transcript.chunks.finish().expect("written");

        assert!(count > 100, "{count}");
        for chunk in read_chunks(dir, count) {
            assert!(chunk.len() <= 4096);
            assert!(chunk.ends_with('\n'));
        }

        let read = read_when_first_chunk_done.load(Ordering::Relaxed);
        assert!(
            read > 0 && read < events / 50,
            "first chunk done after {read} of {events} events"
        );
    }

    #[test]
    fn large_casts_are_streamed_into_bounded_chunk_files() {
        assert_streamed_into_bounded_chunk_files(cast_event, false);
    }

    #[test]
    fn large_trp_recordings_are_streamed_into_bounded_chunk_files() {
        assert_streamed_into_bounded_chunk_files(trp_event, true);
    }

    #[test]
    fn transcript_stops_once_cancelled() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Utf8Path::from_path(dir.path()).expect("UTF-8");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (recording, _) = LazyRecording::new(dir, 1000, cast_event);

        let mut transcript = Transcript::new(ChunkWriter::new(dir, 4096), &cancel);
        let result = transcript.add_cast(BufReader::new(recording), 0.0);

        assert!(matches!(result, Err(CastError::Cancelled)));
    }

    fn session_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        for (name, contents) in files {
            std::fs::write(dir.path().join(name), contents).expect("write recording");
        }
        dir
    }

    fn recordings(files: &[(&str, i64)]) -> Vec<TerminalRecording> {
        files
            .iter()
            .map(|&(file_name, start_time)| TerminalRecording::new(file_name, start_time).expect("terminal recording"))
            .collect()
    }

    fn read(
        recordings: &[TerminalRecording],
        session_start: i64,
        dir: &tempfile::TempDir,
    ) -> Result<String, TranscriptError> {
        let path = Utf8Path::from_path(dir.path()).expect("utf8 path");
        let workspace = path.join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let count = write_chunks(
            recordings,
            session_start,
            path,
            &workspace,
            usize::MAX,
            &Arc::new(AtomicU64::new(0)),
            &CancellationToken::new(),
        )?;
        Ok(read_chunks(&workspace, count).concat())
    }
    #[test]
    fn recordings_are_offset_by_their_start_time() {
        let first: &[u8] = b"{\"version\": 2}\n[1.5,\"o\",\"whoami\\r\\n\"]\n";
        let second: &[u8] = b"{\"version\": 2}\n[2.0,\"o\",\"exit\\r\\n\"]\n";
        let dir = session_dir(&[("recording-0.cast", first), ("recording-1.cast", second)]);

        assert_eq!(
            read(
                &recordings(&[("recording-0.cast", 100), ("recording-1.cast", 160)]),
                100,
                &dir
            )
            .expect("transcript"),
            "[1.5] whoami\n[62.0] exit\n"
        );
    }

    #[test]
    fn trp_recordings_are_decoded() {
        let mut trp = trp_packet(0, 4, b"");
        trp.extend(trp_packet(2500, 0, b"uptime\r\n"));
        let dir = session_dir(&[("recording-0.trp", &trp)]);

        assert_eq!(
            read(&recordings(&[("recording-0.trp", 100)]), 100, &dir).expect("transcript"),
            "[2.5] uptime\n"
        );
    }
}
