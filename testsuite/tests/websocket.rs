use std::time::Duration;

use anyhow::Context as _;
use devolutions_gateway_task::{ChildTask, ShutdownHandle};
use futures_util::{SinkExt as _, StreamExt as _};
use rstest::rstest;
use tokio::io::AsyncReadExt as _;
use tokio::sync::oneshot;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::tungstenite::Message;

#[rstest]
#[case::quiet(false, false, false)]
#[case::pending_pong(true, false, false)]
#[case::error_close(false, true, false)]
#[case::error_close_pending_pong(true, true, false)]
#[case::keepalive_response(false, false, true)]
#[tokio::test]
async fn webm_end_and_close_survive_pending_control_traffic(
    #[case] pong: bool,
    #[case] failed: bool,
    #[case] keepalive: bool,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server, mut client, _listener) = testsuite::websocket::loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let interval = if keepalive {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(60)
        };
        let (mut messages, close) = devolutions_gateway::ws::handle_messages(
            server,
            devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
            interval,
        );
        let terminal = if failed {
            b"\x02{\"error\":\"UnexpectedError\"}".to_vec()
        } else {
            vec![3]
        };
        let expected = Message::Binary(terminal.clone().into());
        let (waiting, ready) = oneshot::channel();
        let (finish, ended) = oneshot::channel();
        let task = ChildTask::spawn(async move {
            assert_eq!(messages.next().await.transpose()?.expect("final Pull"), &[1][..]);
            waiting.send(()).expect("client waits for pending Pull");
            ended.await?;
            messages.send(terminal.into()).await?;
            drop(messages);
            if failed {
                close.server_error("test stream failure".to_owned()).await
            } else {
                close.normal_close().await
            }
        });

        client.send(Message::Binary(vec![1].into())).await?;
        ready.await?;
        if keepalive {
            assert!(matches!(
                client.next().await.transpose()?.expect("keepalive Ping"),
                Message::Ping(_)
            ));
            client.flush().await?;
        }
        if pong {
            client.send(Message::Pong(Vec::new().into())).await?;
        }
        finish.send(()).expect("server waits for recording end");
        assert_eq!(next_message(&mut client).await?, expected);
        let close = next_message(&mut client).await?;
        let expected_code = if failed { 1011 } else { 1000 };
        assert!(
            matches!(close, Message::Close(Some(ref frame)) if u16::from(frame.code) == expected_code),
            "expected Close {expected_code}, got {close:?}",
        );
        assert_orderly_eof(&mut client).await?;
        task.join().await??;
        anyhow::Ok(())
    })
    .await
    .context("loopback close regression timed out")?
}

async fn next_message(client: &mut testsuite::websocket::ClientSocket) -> anyhow::Result<Message> {
    loop {
        let message = client
            .next()
            .await
            .transpose()?
            .context("websocket closed before the expected frame")?;
        if matches!(message, Message::Ping(_) | Message::Pong(_)) {
            client.flush().await?;
        } else {
            return Ok(message);
        }
    }
}

async fn assert_orderly_eof(client: &mut testsuite::websocket::ClientSocket) -> anyhow::Result<()> {
    client.flush().await?;
    let MaybeTlsStream::Plain(socket) = client.get_mut() else {
        panic!("loopback client is not TLS");
    };
    assert_eq!(socket.read(&mut [0]).await?, 0, "server must finish TCP orderly");
    Ok(())
}

#[tokio::test]
async fn webm_peer_can_close_immediately_after_end() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server, mut client, _listener) = testsuite::websocket::loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let (mut messages, close) = devolutions_gateway::ws::handle_messages(
            server,
            devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
            Duration::from_secs(60),
        );
        let task = ChildTask::spawn(async move {
            messages.send(vec![3].into()).await?;
            drop(messages);
            close.normal_close().await
        });
        assert_eq!(next_message(&mut client).await?, Message::Binary(vec![3].into()));
        client.close(None).await?;
        assert!(matches!(next_message(&mut client).await?, Message::Close(_)));
        assert_orderly_eof(&mut client).await?;
        task.join().await??;
        anyhow::Ok(())
    })
    .await
    .context("peer closing after End timed out")?
}

#[tokio::test]
async fn webm_acknowledges_a_close_already_received_by_the_stream() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server, mut client, _listener) = testsuite::websocket::loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let (mut messages, close) = devolutions_gateway::ws::handle_messages(
            server,
            devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
            Duration::from_secs(60),
        );
        let task = ChildTask::spawn(async move {
            assert!(messages.next().await.is_none());
            drop(messages);
            close.normal_close().await
        });
        client.close(None).await?;
        assert_eq!(next_message(&mut client).await?, Message::Close(None));
        assert_orderly_eof(&mut client).await?;
        task.join().await??;
        anyhow::Ok(())
    })
    .await
    .context("acknowledging peer Close timed out")?
}

#[tokio::test]
async fn webm_client_abort_surfaces_a_close_error_without_hanging() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (server, client, _listener) = testsuite::websocket::loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let (messages, close) = devolutions_gateway::ws::handle_messages(
            server,
            devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
            Duration::from_secs(60),
        );
        drop(client);
        drop(messages);
        let error = close
            .normal_close()
            .await
            .expect_err("aborted peer has no closing handshake");
        assert!(!error.to_string().contains("timed out"));
        anyhow::Ok(())
    })
    .await
    .context("client abort cleanup timed out")?
}

#[tokio::test]
async fn webm_missing_close_reply_times_out_instead_of_reporting_success() -> anyhow::Result<()> {
    let (server, _client, _listener) = testsuite::websocket::loopback_pair().await?;
    let (_shutdown, signal) = ShutdownHandle::new();
    let (messages, close) = devolutions_gateway::ws::handle_messages(
        server,
        devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
        Duration::from_millis(10),
    );
    drop(messages);
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(7), close.normal_close())
        .await
        .context("close deadline failed to bound cleanup")?;
    assert!(
        result
            .expect_err("peer did not acknowledge Close")
            .to_string()
            .contains("closing handshake timed out"),
    );
    assert!(Duration::from_secs(5) <= started.elapsed());
    Ok(())
}

#[tokio::test]
async fn dropping_webm_close_owner_cancels_keepalive_and_releases_the_socket() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (server, mut client, _listener) = testsuite::websocket::loopback_pair().await?;
        let (_shutdown, signal) = ShutdownHandle::new();
        let (messages, close) = devolutions_gateway::ws::handle_messages(
            server,
            devolutions_gateway::ws::KeepAliveShutdownSignal(signal),
            Duration::from_millis(10),
        );
        drop(messages);
        drop(close);
        assert!(client.next().await.transpose().is_err());
        anyhow::Ok(())
    })
    .await
    .context("dropped close owner retained its socket")?
}
