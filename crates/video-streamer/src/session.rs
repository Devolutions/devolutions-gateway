use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncWrite};

/// A structural event from one append-only recording session.
///
/// A clip starts, receives zero or more byte events, catches up exactly once, receives more bytes,
/// and ends before another clip starts.
/// The session ends only when no clip is active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordingEvent {
    ClipStarted { sequence: u64, start_at: StartAt },
    Bytes(Bytes),
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
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            encoder_threads: u32::try_from(num_cpus::get()).unwrap_or(1).max(1),
        }
    }
}

/// Converts a recording session into fixed-size VP8 WebM segments over one pull-driven stream.
pub async fn stream_session<S, W>(source: S, output_stream: W, config: SessionConfig) -> anyhow::Result<()>
where
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
    W: AsyncRead + AsyncWrite + Unpin,
{
    let segments = crate::normalizer::normalize(source, config);
    crate::protocol::stream_segments(output_stream, segments).await
}
