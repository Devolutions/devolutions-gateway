#![allow(clippy::unwrap_used, reason = "test code can panic on errors")]

use anyhow::Context as _;
use futures_util::FutureExt;
use proptest::prelude::*;
use test_utils::{
    find_unused_ports, large_payload, payload, read_assert_payload, write_payload, ws_accept, ws_connect,
};
use tokio::io::AsyncWriteExt;

async fn round_trip_client(payload: &[u8], port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(ws_connect(port).await.context("connect")?);
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("shutdown operation")?;
    Ok(())
}

async fn round_trip_server(payload: &[u8], port: u16) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(ws_accept(port).await.context("accept")?);
    let write_fut = write_payload(&mut writer, payload).map(|res| res.context("write payload"));
    let read_fut = read_assert_payload(&mut reader, payload).map(|res| res.context("assert payload"));
    tokio::try_join!(write_fut, read_fut)?;
    writer.shutdown().await.context("shutdown operation")?;
    Ok(())
}

#[test]
fn round_trip() {
    let port = find_unused_ports(1)[0];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(8), |(
        payload in payload().no_shrink(),
    )| {
        rt.block_on(async {
            let server_fut = round_trip_server(&payload.0, port).map(|res| res.context("server"));
            let client_fut = round_trip_client(&payload.0, port).map(|res| res.context("client"));
            tokio::try_join!(server_fut, client_fut).unwrap();
        });
    })
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn round_trip_large_payload() {
    let port = find_unused_ports(1)[0];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    proptest!(ProptestConfig::with_cases(3), |(
        payload in large_payload().no_shrink(),
    )| {
        rt.block_on(async {
            let server_fut = round_trip_server(&payload.0, port).map(|res| res.context("server"));
            let client_fut = round_trip_client(&payload.0, port).map(|res| res.context("client"));
            tokio::try_join!(server_fut, client_fut).unwrap();
        });
    })
}
