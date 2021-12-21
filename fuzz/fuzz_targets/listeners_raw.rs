#![no_main]

use devolutions_gateway::config::Config;
use devolutions_gateway::jet_client::JetAssociationsMap;
use devolutions_gateway::listener::GatewayListener;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run(data));
    rt.shutdown_timeout(tokio::time::Duration::from_nanos(100));
});

async fn run(data: &[u8]) {
    let (tcp_listener, tcp_port) = build_listener("tcp");
    let (ws_listener, ws_port) = build_listener("ws");
    let (wss_listener, wss_port) = build_listener("wss");

    // At this point, sockets are binded and we can send data safely

    let _ = tokio::join!(
        tcp_listener.handle_one(),
        fuzz_listener(data, tcp_port),
        ws_listener.handle_one(),
        fuzz_listener(data, ws_port),
        wss_listener.handle_one(),
        fuzz_listener(data, wss_port),
    );
}

async fn fuzz_listener(data: &[u8], port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(data).await.unwrap();
    let _ = stream.shutdown().await;
}

fn build_listener(scheme: &str) -> (GatewayListener, u16) {
    use get_port::Ops as _;

    let host = "0.0.0.0";
    let port = get_port::tcp::TcpPort::any(host).unwrap();
    let url = format!("{}://{}:{}", scheme, host, port);
    let url = Url::parse(&url).unwrap();

    let config = Arc::new(Config::default());
    let jet_associations: JetAssociationsMap = Arc::new(Mutex::new(HashMap::new()));
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let listener = GatewayListener::init_and_bind(url, config, jet_associations, logger).unwrap();

    (listener, port)
}
