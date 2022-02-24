use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use std::mem::transmute;
use test_utils::{read_assert_payload, write_payload, TransportKind};
use transport::Transport;

struct Context {
    client_to_node: Transport,
    node_to_client: Transport,
    node_to_server: Transport,
    server_to_node: Transport,
}

async fn setup(kind: TransportKind) -> Context {
    let port_node = portpicker::pick_unused_port().expect("No available port");
    let port_server = portpicker::pick_unused_port().expect("No available port");

    let client_fut = kind.connect(port_node);
    let node_to_client_fut = kind.accept(port_node);
    let node_to_server_fut = kind.connect(port_server);
    let server_fut = kind.accept(port_server);

    let (node_to_client, server_to_node, client_to_node, node_to_server) =
        tokio::try_join!(node_to_client_fut, server_fut, client_fut, node_to_server_fut).unwrap();

    Context {
        client_to_node,
        node_to_client,
        node_to_server,
        server_to_node,
    }
}

async fn endpoint(transport: &'static mut Transport, payload: Bytes) {
    let (reader, writer) = tokio::io::split(transport);

    let writer_payload = payload.clone();
    let write_fut = tokio::spawn(async move {
        let mut writer = writer;
        write_payload(&mut writer, &writer_payload).await.unwrap()
    });

    let read_fut = tokio::spawn(async move {
        let mut reader = reader;
        read_assert_payload(&mut reader, &payload).await.unwrap();
    });

    tokio::try_join!(write_fut, read_fut).unwrap();
}

async fn transfer(client_to_node: &mut Transport, server_to_node: &mut Transport, payload: Bytes) {
    unsafe {
        // SAFETY: it's kind of fine because we are joining or cancelling all the tasks before exiting (poor man's scoped tasks)
        // (I would definitely not do that for production code though)
        let client_to_node: &'static mut Transport = transmute(client_to_node);
        let server_to_node: &'static mut Transport = transmute(server_to_node);

        let server_fut = endpoint(server_to_node, payload.clone());
        let client_fut = endpoint(client_to_node, payload);

        tokio::join!(server_fut, client_fut);
    }
}

macro_rules! harness {
    ($benchmark_ident:ident, $name:literal, $setup:block) => {
        fn $benchmark_ident(c: &mut Criterion) {
            use tokio::io::AsyncWriteExt;

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            let mut payload_100k = [0u8; 100_000];
            thread_rng().fill(&mut payload_100k[..]);
            let payload_100k = Bytes::copy_from_slice(&payload_100k);

            let mut ctx = rt.block_on(async { $setup });

            let handle = rt.spawn(async move {
                transport::forward_bidirectional(ctx.node_to_client, ctx.node_to_server)
                    .await
                    .unwrap();
            });

            c.bench_function(concat!($name, " forwarding 100KiB"), |b| {
                b.iter(|| {
                    rt.block_on(transfer(
                        &mut ctx.client_to_node,
                        &mut ctx.server_to_node,
                        black_box(payload_100k.clone()),
                    ))
                })
            });

            c.bench_function(concat!($name, " forwarding 10KiB"), |b| {
                b.iter(|| {
                    rt.block_on(transfer(
                        &mut ctx.client_to_node,
                        &mut ctx.server_to_node,
                        black_box(payload_100k.clone().split_to(10_000)),
                    ))
                })
            });

            c.bench_function(concat!($name, " forwarding 1KiB"), |b| {
                b.iter(|| {
                    rt.block_on(transfer(
                        &mut ctx.client_to_node,
                        &mut ctx.server_to_node,
                        black_box(payload_100k.clone().split_to(1_000)),
                    ))
                })
            });

            rt.block_on(async {
                ctx.client_to_node.shutdown().await.unwrap();
                ctx.server_to_node.shutdown().await.unwrap();
                handle.await.unwrap();
            });
        }
    };
}

harness!(duplex_benchmark, "Duplex", {
    let (client_to_node, node_to_client) = tokio::io::duplex(5012);
    let (node_to_server, server_to_node) = tokio::io::duplex(5012);
    Context {
        client_to_node: Transport::new(client_to_node).into_erased(),
        node_to_client: Transport::new(node_to_client).into_erased(),
        node_to_server: Transport::new(node_to_server).into_erased(),
        server_to_node: Transport::new(server_to_node).into_erased(),
    }
});
harness!(tcp_benchmark, "TCP", { setup(TransportKind::Tcp).await });
harness!(ws_benchmark, "WebSocket", { setup(TransportKind::Ws).await });

// TODO: multiple streams in parallel

criterion_group!(benches, duplex_benchmark, tcp_benchmark, ws_benchmark);
criterion_main!(benches);
