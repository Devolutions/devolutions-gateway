#![expect(clippy::unwrap_used, reason = "Test code can panic on errors")]

use anyhow::Context as _;
use futures_util::FutureExt;
use proptest::prelude::*;
use test_utils::{TransportKind, find_unused_ports, payload, read_assert_payload, transport_kind, write_payload};
use tokio::io::AsyncWriteExt;

async fn client(payload: &[u8], kind: TransportKind, port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(kind.connect(port).await.context("connect")?);
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("shutdown operation")?;
    Ok(())
}

async fn node(
    port_node: u16,
    client_kind: TransportKind,
    port_server: u16,
    server_kind: TransportKind,
) -> anyhow::Result<()> {
    let mut client_stream = client_kind.accept(port_node).await.context("accept")?;
    let mut server_stream = server_kind.connect(port_server).await.context("connect")?;

    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await;
    let _ = client_stream.shutdown().await;
    let _ = server_stream.shutdown().await;

    Ok(())
}

async fn server(payload: &[u8], kind: TransportKind, port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(kind.accept(port).await.context("accept")?);
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("shutdown operation")?;
    Ok(())
}

#[test]
fn three_points() {
    let ports = find_unused_ports(2);
    let port_node = ports[0];
    let port_server = ports[1];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(10), |(
        payload in payload().no_shrink(),
        client_to_node_kind in transport_kind(),
        node_to_server_kind in transport_kind(),
    )| {
        rt.block_on(async {
            let server_fut = server(&payload.0, node_to_server_kind, port_server).map(|res| res.context("server"));
            let client_fut = client(&payload.0, client_to_node_kind, port_node).map(|res| res.context("client"));
            let node_fut = node(port_node, client_to_node_kind, port_server, node_to_server_kind).map(|res| res.context("node"));
            tokio::try_join!(server_fut, node_fut, client_fut).unwrap();
        });
    })
}
