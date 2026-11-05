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
    let Some(_) = receive_expected_request(&mut transport, ClientMessage::Start).await? else {
        return Ok(());
    };

    let source_stream = match start_source().await {
        Ok(source_stream) => source_stream,
        Err(error) => {
            transport.reject().await;
            return Err(error);
        }
    };
    let mut segments = SessionSegments::new(crate::normalizer::normalize(source_stream, config), version);
    let stream_result = run_started_session(&mut transport, &mut segments, version).await;
    let shutdown_result = segments.into_inner().shutdown().await;

    match (stream_result, shutdown_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn receive_request<T, E>(transport: &mut CodecTransport<T>) -> anyhow::Result<Option<ClientMessage>>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let Some(incoming) = transport.recv().await else {
        return Ok(None);
    };
    match incoming {
        Ok(message) => Ok(Some(message)),
        Err(ReceiveError::Transport(error)) => Err(anyhow::Error::new(error).context("read client stream message")),
        Err(ReceiveError::Decode(error)) => {
            debug!(error = %error, "Rejected undecodable client request");
            transport.reject().await;
            Err(error.context("decode client request"))
        }
    }
}

async fn reject_request<T, E>(transport: &mut CodecTransport<T>, message: ClientMessage) -> anyhow::Error
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    debug!(got = ?message, "Rejected client request in wrong state");
    transport.reject().await;
    anyhow::anyhow!("invalid client stream state")
}

async fn receive_expected_request<T, E>(
    transport: &mut CodecTransport<T>,
    expected: ClientMessage,
) -> anyhow::Result<Option<ClientMessage>>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let Some(message) = receive_request(transport).await? else {
        return Ok(None);
    };
    if message != expected {
        return Err(reject_request(transport, message).await);
    }
    Ok(Some(message))
}

#[derive(Clone, Copy, Debug)]
enum PullRequest {
    Pull,
    PullOrKeyFrame,
}

async fn receive_pull<T, E>(
    transport: &mut CodecTransport<T>,
    version: ShadowProtocolVersion,
) -> anyhow::Result<Option<PullRequest>>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let Some(message) = receive_request(transport).await? else {
        return Ok(None);
    };
    match (message, version) {
        (ClientMessage::Pull, _) => Ok(Some(PullRequest::Pull)),
        (ClientMessage::PullOrKeyFrame, ShadowProtocolVersion::V3) => Ok(Some(PullRequest::PullOrKeyFrame)),
        (ClientMessage::Start | ClientMessage::PullOrKeyFrame, _) => Err(reject_request(transport, message).await),
    }
}

async fn run_started_session<T, E>(
    transport: &mut CodecTransport<T>,
    segments: &mut SessionSegments<NormalizedSession>,
    version: ShadowProtocolVersion,
) -> anyhow::Result<()>
where
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    debug!("Serving Start request");
    transport.send(ServerMessage::Metadata).await?;

    loop {
        let Some(request) = receive_pull(transport, version).await? else {
            return Ok(());
        };
        debug!(?request, "Serving pull request");
        let response = match request {
            PullRequest::Pull => segments.next().await,
            PullRequest::PullOrKeyFrame => segments.next_or_key_frame().await,
        };
        let response = match response {
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
