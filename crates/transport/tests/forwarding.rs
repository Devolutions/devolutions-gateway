use anyhow::Context as _;
use futures_util::FutureExt;
use proptest::prelude::*;
use test_utils::{payload, read_assert_payload, transport_kind, write_payload, TransportKind};
use tokio::io::AsyncWriteExt;

async fn client(payload: &[u8], kind: TransportKind, port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = kind.connect(port).await.context("Connect")?.into_erased_split();
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("Write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("Assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("Shutdown operation")?;
    Ok(())
}

async fn node(
    port_node: u16,
    client_kind: TransportKind,
    port_server: u16,
    server_kind: TransportKind,
) -> anyhow::Result<()> {
    let (mut client_reader, mut client_writer) = client_kind
        .accept(port_node)
        .await
        .context("Accept")?
        .into_erased_split();

    let (mut server_reader, mut server_writer) = server_kind
        .connect(port_server)
        .await
        .context("Connect")?
        .into_erased_split();

    let client_to_server_fut =
        transport::forward(&mut client_reader, &mut server_writer).map(|res| res.context("Forward to server"));
    let server_to_client_fut =
        transport::forward(&mut server_reader, &mut client_writer).map(|res| res.context("Forward to client"));

    tokio::try_join!(client_to_server_fut, server_to_client_fut)?;

    client_writer
        .shutdown()
        .await
        .context("Shutdown operation on client_writer")?;
    server_writer
        .shutdown()
        .await
        .context("Shutdown operation on server_writer")?;

    Ok(())
}

async fn server(payload: &[u8], kind: TransportKind, port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = kind.accept(port).await.context("Accept")?.into_erased_split();
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("Write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("Assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("Shutdown operation")?;
    Ok(())
}

#[test]
fn three_points() {
    let port_node = portpicker::pick_unused_port().expect("No available port");
    let port_server = portpicker::pick_unused_port().expect("No available port");

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
            let server_fut = server(&payload.0, node_to_server_kind, port_server).map(|res| res.context("Server"));
            let node_fut = node(port_node, client_to_node_kind, port_server, node_to_server_kind).map(|res| res.context("Node"));
            let client_fut = client(&payload.0, client_to_node_kind, port_node).map(|res| res.context("Client"));
            tokio::try_join!(server_fut, node_fut, client_fut).unwrap();
        });
    })
}
