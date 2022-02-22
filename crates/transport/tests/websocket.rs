use anyhow::Context as _;
use futures_util::FutureExt;
use proptest::prelude::*;
use test_utils::{large_payload, payload, read_assert_payload, write_payload, ws_accept, ws_connect};
use tokio::io::AsyncWriteExt;

async fn round_trip_client(payload: &[u8], port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = ws_connect(port).await.context("Connect")?.split();
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("Write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("Assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("Shutdown operation")?;
    Ok(())
}

async fn round_trip_server(payload: &[u8], port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = ws_accept(port).await.context("Accept")?.split();
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("Write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("Assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("Shutdown operation")?;
    Ok(())
}

#[test]
fn round_trip() {
    let port = portpicker::pick_unused_port().expect("No available port");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(8), |(
        payload in payload().no_shrink(),
    )| {
        rt.block_on(async {
            let server_fut = round_trip_server(&payload.0, port).map(|res| res.context("Server"));
            let client_fut = round_trip_client(&payload.0, port).map(|res| res.context("Client"));
            tokio::try_join!(server_fut, client_fut).unwrap();
        });
    })
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn round_trip_large_payload() {
    let port = portpicker::pick_unused_port().expect("No available port");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(3), |(
        payload in large_payload().no_shrink(),
    )| {
        rt.block_on(async {
            let server_fut = round_trip_server(&payload.0, port).map(|res| res.context("Server"));
            let client_fut = round_trip_client(&payload.0, port).map(|res| res.context("Client"));
            tokio::try_join!(server_fut, client_fut).unwrap();
        });
    })
}
