use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use axum::Router;
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::routing::get;
use devolutions_gateway_task::ChildTask;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn loopback_pair() -> anyhow::Result<(WebSocket, ClientSocket, ChildTask<anyhow::Result<()>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let (sender, receiver) = oneshot::channel();
    let sender = Arc::new(Mutex::new(Some(sender)));
    let router = Router::new().route(
        "/",
        get(move |upgrade: WebSocketUpgrade| {
            let sender = Arc::clone(&sender);
            async move {
                upgrade.on_upgrade(move |socket| async move {
                    sender
                        .lock()
                        .expect("test sender mutex is not poisoned")
                        .take()
                        .expect("one test connection")
                        .send(socket)
                        .expect("test receiver is still waiting");
                })
            }
        }),
    );
    let task = ChildTask::spawn(async move { axum::serve(listener, router).await.context("serve loopback websocket") });
    let (client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/")).await?;
    let server = receiver.await.context("receive upgraded websocket")?;
    Ok((server, client, task))
}
