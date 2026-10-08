use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Sink, Stream};

trait RecordingClipReader: Read + Seek + Send {}

impl<T> RecordingClipReader for T where T: Read + Seek + Send {}

/// Owns the seekable reader for one recording clip.
///
/// The reader remains attached to this clip while consumers seek for bounded replay.
/// Replay uses this owned handle instead of reopening the clip path.
pub struct RecordingClip {
    reader: Box<dyn RecordingClipReader>,
}

impl RecordingClip {
    pub fn new<R>(reader: R) -> Self
    where
        R: Read + Seek + Send + 'static,
    {
        Self {
            reader: Box::new(reader),
        }
    }

    pub(crate) fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }

    pub(crate) fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.reader.seek(position)
    }
}

impl fmt::Debug for RecordingClip {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RecordingClip").finish_non_exhaustive()
    }
}

/// A structural event from one append-only recording session.
///
/// A session is a sequence of input clips. A source must emit, in this order:
///
/// - for each clip: `ClipStarted`, then `DataAvailable` any number of times with exactly one `CaughtUp` among them,
///   then `ClipEnded`;
/// - after the last clip: `SessionEnded`, then nothing.
///
/// Clips follow one another with nothing in between, and `SessionEnded` may also come before any clip.
/// The stream must not end before `SessionEnded`, and any other order fails the session.
#[derive(Debug)]
pub enum RecordingEvent {
    /// Starts the next input clip and hands over its reader.
    ClipStarted {
        /// The clip’s position in the recording session, for diagnostics.
        sequence: u64,
        /// Where viewing starts within this clip.
        start_at: StartAt,
        clip: RecordingClip,
    },
    /// More bytes may be readable from the current clip.
    DataAvailable,
    /// Every byte the clip held when the viewer joined is now readable; later bytes are live.
    CaughtUp,
    /// The current clip gets no more bytes.
    ClipEnded,
    /// The session gets no more clips.
    SessionEnded,
}

/// Where viewing starts within an input clip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartAt {
    /// From the first frame.
    Beginning,
    /// From the latest decodable group of pictures before `CaughtUp`, then live.
    LiveEdge,
}

/// Encoder settings for the normalized output.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    /// Threads the VP8 encoder may use.
    pub encoder_threads: u32,
    /// When `true`, the encoder skips frames while it falls behind real time, lowering the output frame rate.
    pub adaptive_frame_skip: bool,
    /// When set, a live clip whose source stays quiet repeats its last picture at this interval, so players keep
    /// receiving frames.
    pub fill_interval: Option<Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            encoder_threads: u32::try_from(num_cpus::get()).unwrap_or(1).max(1),
            adaptive_frame_skip: true,
            fill_interval: None,
        }
    }
}

/// WebSocket subprotocol a client offers to get [`ShadowProtocolVersion::V2`].
pub const SHADOW_PROTOCOL_V2: &str = "jrec-shadow.v2";

/// Shadow wire protocol version negotiated for one session stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowProtocolVersion {
    /// The session stream carries one output segment and ends with `StreamEnded` at its first segment boundary.
    ///
    /// Clients that do not offer [`SHADOW_PROTOCOL_V2`] get this version, because they reject `SegmentStarted`.
    V1,
    /// The session stream carries every output segment, and `SegmentStarted` announces each one after the first.
    V2,
}

/// Converts a recording session into independent VP8 WebM segments over one pull-driven stream.
///
/// `start_source` runs once, after the client sent a valid `Start`, and returns the session’s [`RecordingEvent`]s.
/// Each segment has one resolution, and output sequence numbers remain contiguous across input clips.
/// With [`ShadowProtocolVersion::V1`], the stream ends after the first segment.
pub async fn stream_session<F, Fut, S, T, E>(
    start_source: F,
    transport: T,
    config: SessionConfig,
    version: ShadowProtocolVersion,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = anyhow::Result<S>> + Send,
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    crate::protocol::stream_segments(transport, start_source, config, version).await
}
