use std::time::Duration;

use devolutions_gateway::config::dto::{ProxyConf, ProxyMode, Subscriber};
use devolutions_gateway::subscriber::{Message, send_message};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

#[tokio::test]
async fn subscriber_requests_identify_gateway() {
    tokio::time::timeout(Duration::from_secs(5), verify_subscriber_user_agent())
        .await
        .expect("subscriber exchange completes before timeout");
}

async fn verify_subscriber_user_agent() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind subscriber");
    let address = listener.local_addr().expect("read subscriber address");

    let subscriber = Subscriber {
        url: format!("http://{address}").parse().expect("subscriber URL is valid"),
        token: "token".to_owned(),
    };
    let proxy = ProxyConf {
        mode: ProxyMode::Off,
        ..ProxyConf::default()
    };
    http_client_proxy::get_or_create_cached_client(
        reqwest::Client::builder(),
        &subscriber.url,
        &proxy.to_proxy_config(),
    )
    .expect("pre-populate client cache without a default user agent");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept subscriber request");
        let mut request = Vec::new();
        let mut buffer = [0; 1024];

        loop {
            let read = stream.read(&mut buffer).await.expect("read subscriber request");
            assert_ne!(read, 0, "subscriber request ended before its headers");
            request.extend_from_slice(&buffer[..read]);

            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .expect("write subscriber response");
        String::from_utf8(request).expect("subscriber request is valid UTF-8")
    });

    let message = Message::session_list(Vec::new());

    send_message(&subscriber, &message, &proxy)
        .await
        .expect("send subscriber message with cached client");

    let request = server.await.expect("subscriber server task succeeds");
    let user_agent = request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("user-agent").then(|| value.trim())
    });
    let version = user_agent
        .and_then(|value| value.strip_prefix("Devolutions-Gateway/"))
        .expect("subscriber user agent identifies Devolutions Gateway");
    assert!(!version.is_empty(), "subscriber user agent includes a version");
}
