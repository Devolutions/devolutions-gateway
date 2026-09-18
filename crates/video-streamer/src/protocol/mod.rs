use std::error::Error;

use bytes::Bytes;
use futures_util::{Sink, Stream};

use crate::normalizer::NormalizedSession;
use crate::session::{RecordingSource, SessionConfig};

mod message;
mod segments;
mod transport;

use message::{ClientMessage, ServerMessage, response_kind};
use segments::SessionSegments;
use transport::{CodecTransport, ReceiveError, SessionTransport};

pub(crate) async fn stream_segments<S, T, E>(transport: T, source: S, config: SessionConfig) -> anyhow::Result<()>
where
    S: RecordingSource,
    T: Stream<Item = Result<Bytes, E>> + Sink<Bytes, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let mut transport = SessionTransport::new(CodecTransport::new(transport));
    let Some(_) = receive_expected_request(&mut transport, ClientMessage::Start).await? else {
        return Ok(());
    };

    let source_stream = match source.start().await {
        Ok(source_stream) => source_stream,
        Err(error) => {
            transport.reject().await;
            return Err(error);
        }
    };
    let mut segments = SessionSegments::new(crate::normalizer::normalize(source_stream, config));
    let stream_result = run_started_session(&mut transport, &mut segments).await;
    let shutdown_result = segments.into_inner().shutdown().await;

    match (stream_result, shutdown_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn receive_expected_request<T, E>(
    transport: &mut SessionTransport<T>,
    expected: ClientMessage,
) -> anyhow::Result<Option<ClientMessage>>
where
    T: Stream<Item = Result<ClientMessage, ReceiveError<E>>> + Sink<ServerMessage, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    let Some(incoming) = transport.recv().await else {
        return Ok(None);
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

    Ok(Some(message))
}

async fn run_started_session<T, E>(
    transport: &mut SessionTransport<T>,
    segments: &mut SessionSegments<NormalizedSession>,
) -> anyhow::Result<()>
where
    T: Stream<Item = Result<ClientMessage, ReceiveError<E>>> + Sink<ServerMessage, Error = E> + Unpin,
    E: Error + Send + Sync + 'static,
{
    debug!("Serving Start request");
    transport.send(ServerMessage::Metadata).await?;

    loop {
        let Some(_) = receive_expected_request(transport, ClientMessage::Pull).await? else {
            return Ok(());
        };
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
