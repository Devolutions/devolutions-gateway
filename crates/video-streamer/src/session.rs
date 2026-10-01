use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom};

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
#[derive(Debug)]
pub enum RecordingEvent {
    ClipStarted {
        sequence: u64,
        start_at: StartAt,
        clip: RecordingClip,
    },
    DataAvailable,
    CaughtUp,
    ClipEnded,
    SessionEnded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartAt {
    Beginning,
    LiveEdge,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    pub encoder_threads: u32,
    pub adaptive_frame_skip: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            encoder_threads: u32::try_from(num_cpus::get()).unwrap_or(1).max(1),
            adaptive_frame_skip: true,
        }
    }
}

/// Produces structural events and transfers each clip reader to the consumer once.
pub trait RecordingSource: Send + 'static {
    type Stream: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static;
    type Start: Future<Output = anyhow::Result<Self::Stream>> + Send + 'static;

    fn start(self) -> Self::Start;
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
/// Each segment has one resolution, and output sequence numbers remain contiguous across input clips.
/// With [`ShadowProtocolVersion::V1`], the stream ends after the first segment.
pub async fn stream_session<S, T, E>(
    source: S,
    transport: T,
    config: SessionConfig,
    version: ShadowProtocolVersion,
) -> anyhow::Result<()>
where
    S: RecordingSource,
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    crate::protocol::stream_segments(transport, source, config, version).await
}
