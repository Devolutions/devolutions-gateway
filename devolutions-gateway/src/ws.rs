use axum::extract::ws::{self, WebSocket};
use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};

pub fn websocket_compat(ws: WebSocket) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static {
    let ws_compat = ws
        .map(|item| {
            item.map(|msg| match msg {
                ws::Message::Text(s) => transport::WsMessage::Payload(s.into_bytes()),
                ws::Message::Binary(data) => transport::WsMessage::Payload(data),
                ws::Message::Ping(_) | ws::Message::Pong(_) => transport::WsMessage::Ignored,
                ws::Message::Close(_) => transport::WsMessage::Close,
            })
        })
        .with(|item| futures::future::ready(Ok::<_, axum::Error>(ws::Message::Binary(item))));

    transport::WsStream::new(ws_compat)
}
