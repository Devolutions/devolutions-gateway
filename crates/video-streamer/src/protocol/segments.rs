use std::pin::Pin;

use anyhow::Context as _;
use futures_util::{Stream, StreamExt as _};

use super::message::ServerMessage;
use crate::normalizer::SegmentEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SegmentState {
    AwaitingBegin { next_sequence: u64 },
    Streaming { next_sequence: u64 },
}

pub(super) struct SessionSegments<S> {
    inner: Pin<Box<S>>,
    state: SegmentState,
}

impl<S> SessionSegments<S>
where
    S: Stream<Item = anyhow::Result<SegmentEvent>>,
{
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner: Box::pin(inner),
            state: SegmentState::AwaitingBegin { next_sequence: 0 },
        }
    }

    pub(super) fn into_inner(self) -> S
    where
        S: Unpin,
    {
        *Pin::into_inner(self.inner)
    }

    pub(super) async fn next(&mut self) -> anyhow::Result<ServerMessage> {
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
                    self.state = SegmentState::AwaitingBegin { next_sequence };
                    debug!("Segment end");
                }
            }
        }
    }
}
