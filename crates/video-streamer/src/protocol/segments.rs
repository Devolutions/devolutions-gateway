use std::pin::Pin;
use std::time::Duration;

use anyhow::Context as _;
use futures_util::{Stream, StreamExt as _};

use super::message::ServerMessage;
use crate::normalizer::{NormalizedSession, SegmentEvent};
use crate::session::ShadowProtocolVersion;

// A request the byte budget turns down is asked again at this interval while the client still waits.
const KEY_FRAME_RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentState {
    AwaitingBegin { next_sequence: u64 },
    Streaming { next_sequence: u64 },
    Ended,
}

pub(super) struct SessionSegments<S> {
    inner: Pin<Box<S>>,
    state: SegmentState,
    version: ShadowProtocolVersion,
}

impl<S> SessionSegments<S>
where
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
{
    pub(super) fn new(inner: S, version: ShadowProtocolVersion) -> Self {
        Self {
            inner: Box::pin(inner),
            state: SegmentState::AwaitingBegin { next_sequence: 0 },
            version,
        }
    }

    pub(super) fn into_inner(self) -> S
    where
        S: Unpin,
    {
        *Pin::into_inner(self.inner)
    }

    pub(super) async fn next(&mut self) -> anyhow::Result<ServerMessage> {
        anyhow::ensure!(self.state != SegmentState::Ended, "segment stream already ended");

        loop {
            let Some(event) = self.inner.as_mut().next().await else {
                anyhow::ensure!(
                    matches!(self.state, SegmentState::AwaitingBegin { .. }),
                    "segment stream ended inside a segment"
                );
                return Ok(ServerMessage::StreamEnded);
            };

            match event? {
                SegmentEvent::Begin(info) => {
                    let SegmentState::AwaitingBegin { next_sequence } = self.state else {
                        anyhow::bail!("segment began before the previous segment ended");
                    };
                    anyhow::ensure!(
                        info.sequence == next_sequence,
                        "segment sequence is not contiguous: expected {next_sequence}, got {}",
                        info.sequence
                    );
                    self.state = SegmentState::Streaming {
                        next_sequence: next_sequence.checked_add(1).context("segment sequence overflow")?,
                    };
                    debug!(
                        sequence = info.sequence,
                        width = info.width,
                        height = info.height,
                        "Segment begin"
                    );
                    if info.sequence > 0 {
                        return Ok(ServerMessage::SegmentStarted);
                    }
                }
                SegmentEvent::Data(data) => {
                    anyhow::ensure!(
                        matches!(self.state, SegmentState::Streaming { .. }),
                        "segment data arrived outside a segment"
                    );
                    debug!(bytes = data.len(), "Segment data");
                    return Ok(ServerMessage::Chunk(data));
                }
                SegmentEvent::End => {
                    let SegmentState::Streaming { next_sequence } = self.state else {
                        anyhow::bail!("segment ended outside a segment");
                    };
                    debug!("Segment end");
                    if self.version == ShadowProtocolVersion::V1 {
                        // A V1 client cannot switch to another output segment, so its stream ends at the first boundary.
                        self.state = SegmentState::Ended;
                        return Ok(ServerMessage::StreamEnded);
                    }
                    self.state = SegmentState::AwaitingBegin { next_sequence };
                }
            }
        }
    }
}

impl SessionSegments<NormalizedSession> {
    /// Answers with new data when it is ready, and otherwise asks the normalizer for a synthetic key frame.
    pub(super) async fn next_or_key_frame(&mut self) -> anyhow::Result<ServerMessage> {
        let mut retry = tokio::time::interval(KEY_FRAME_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                response = self.next() => return response,
                _ = retry.tick() => self.inner.request_key_frame(),
            }
        }
    }
}
