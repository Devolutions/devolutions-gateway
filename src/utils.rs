use std::net::SocketAddr;

use url::Url;

pub fn url_to_socket_arr(url: &Url) -> SocketAddr {
    let host = url.host_str().unwrap().to_string();
    let port = url.port().map(|port| port.to_string()).unwrap();

    format!("{}:{}", host, port).parse::<SocketAddr>().unwrap()
}
