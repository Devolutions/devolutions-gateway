use std::error::Error;
use std::future::Future;

use bytes::Bytes;
use futures_util::{Sink, Stream};

use crate::normalizer::NormalizedSession;
use crate::session::{RecordingEvent, SessionConfig, ShadowProtocolVersion};

mod message;
mod segments;
mod transport;

use message::{ClientMessage, ServerMessage, response_kind};
use segments::SessionSegments;
use transport::{CodecTransport, ReceiveError};

pub(crate) async fn stream_segments<F, Fut, S, T, E>(
    transport: T,
    start_source: F,
    config: SessionConfig,
    version: ShadowProtocolVersion,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<S>>,
    S: Stream<Item = anyhow::Result<RecordingEvent>> + Send + 'static,
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let mut transport = CodecTransport::new(transport);
    if !receive_expected_request(&mut transport, ClientMessage::Start).await? {
        return Ok(());
    }

    let source_stream = match start_source().await {
        Ok(source_stream) => source_stream,
        Err(error) => {
            transport.reject().await;
            return Err(error);
        }
    };
    let mut segments = SessionSegments::new(crate::normalizer::normalize(source_stream, config), version);
    let stream_result = run_started_session(&mut transport, &mut segments).await;
    let shutdown_result = segments.into_inner().shutdown().await;

    match (stream_result, shutdown_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// Reads the next request and rejects it unless it is `expected`.
///
/// Returns `false` when the client closed the transport instead.
async fn receive_expected_request<T, E>(
    transport: &mut CodecTransport<T>,
    expected: ClientMessage,
) -> anyhow::Result<bool>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let Some(incoming) = transport.recv().await else {
        return Ok(false);
    };
    let message = match incoming {
        Ok(message) => message,
        Err(ReceiveError::Transport(error)) => {
            return Err(anyhow::Error::new(error).context("read client stream message"));
        }
        Err(ReceiveError::Decode(error)) => {
            debug!(error = %error, "Rejected undecodable client request");
            transport.reject().await;
            return Err(error.context("decode client request"));
        }
    };

    if message != expected {
        debug!(expected = ?expected, got = ?message, "Rejected client request in wrong state");
        transport.reject().await;
        anyhow::bail!("invalid client stream state");
    }

    Ok(true)
}

async fn run_started_session<T, E>(
    transport: &mut CodecTransport<T>,
    segments: &mut SessionSegments<NormalizedSession>,
) -> anyhow::Result<()>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    debug!("Serving Start request");
    transport.send(ServerMessage::Metadata).await?;

    loop {
        if !receive_expected_request(transport, ClientMessage::Pull).await? {
            return Ok(());
        }
        debug!("Serving Pull request");
        let response = match segments.next().await {
            Ok(response) => response,
            Err(error) => {
                debug!(error = %error, "Request failed while waiting");
                transport.reject().await;
                return Err(error);
            }
        };

        debug!(response = ?response_kind(&response), "Sending server response");
        let ended = response == ServerMessage::StreamEnded;
        transport.send(response).await?;
        if ended {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests;
