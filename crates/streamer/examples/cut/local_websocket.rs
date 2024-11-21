use axum::{
    extract::ws::{self, WebSocket, WebSocketUpgrade},
    routing::get,
    Router,
};
use futures::{stream::StreamExt, SinkExt};
use std::{
    io::{Error as IoError, ErrorKind},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as TungsteniteMessage, MaybeTlsStream, WebSocketStream,
};
use tracing::info;

pub(crate) struct WebSocketClient {
    ws: tokio::sync::Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl WebSocketClient {
    pub(crate) async fn next(&self) -> Option<Result<TungsteniteMessage, IoError>> {
        self.ws
            .lock()
            .await
            .next()
            .await
            .map(|result| result.map_err(|e| IoError::new(ErrorKind::Other, e)))
    }

    pub(crate) async fn send(&self, message: Vec<u8>) -> Result<(), IoError> {
        self.ws
            .lock()
            .await
            .send(TungsteniteMessage::Binary(message))
            .await
            .map_err(|e| IoError::new(ErrorKind::Other, e))
    }
}

pub(crate) async fn create_local_websocket() -> (WebSocketClient, impl AsyncRead + AsyncWrite + Unpin + Send + 'static)
{
    // Create a TCP listener on a local port
    let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
    let addr = listener.local_addr().unwrap();
    info!("Listening on {}", addr);

    let ws_tx = Arc::new(Mutex::new(None));

    let app = Router::new().route(
        "/ws",
        get({
            let ws_tx = ws_tx.clone();
            move |ws: WebSocketUpgrade| {
                let ws_tx = ws_tx.clone();
                async move {
                    ws.on_upgrade(move |socket| async move {
                        {
                            let mut lock = ws_tx.lock().unwrap();
                            *lock = Some(socket);
                        }
                        // Keep the connection alive
                        futures::future::pending::<()>().await;
                    })
                }
            }
        }),
    );

    // Start the server
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server failed");
    });

    // Connect to the WebSocket server using a client
    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    let (ws_stream, _) = connect_async(&url).await.unwrap();
    let client = WebSocketClient {
        ws: tokio::sync::Mutex::new(ws_stream),
    };

    // Wait for the server to accept the connection
    while ws_tx.lock().unwrap().is_none() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let server_ws = ws_tx.lock().unwrap().take().unwrap();

    let server = websocket_compat(server_ws);

    (client, server)
}

fn websocket_compat(ws: WebSocket) -> impl AsyncRead + AsyncWrite + Unpin + Send + 'static {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_websocket_client_server() {
        let (client, mut server) = create_local_websocket().await;

        // Send a message from client to server
        let client_to_server_message = b"Hello from client!";
        let client_write = async {
            client.send(client_to_server_message.to_vec()).await.unwrap();
        };

        // Read the message on the server side
        let server_read = async {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            let received = &buf[..n];
            assert_eq!(received, client_to_server_message);
        };

        // Run both tasks concurrently
        tokio::join!(client_write, server_read);

        // Send a message from server to client
        let server_to_client_message = b"Hello from server!";
        let server_write = async {
            server.write_all(server_to_client_message).await.unwrap();
            server.flush().await.unwrap();
        };

        // Read the message on the client side
        let client_read = async {
            let message = client.next().await.unwrap().unwrap();
            assert_eq!(message, TungsteniteMessage::Binary(server_to_client_message.to_vec()));
        };

        // Run both tasks concurrently
        tokio::join!(server_write, client_read);
    }
}
