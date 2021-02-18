use jetsocat_proxy::socks5::Socks5Stream;
use std::collections::HashMap;
use std::{env, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

macro_rules! test {
    ( $test:expr ) => {{
        let expr_str = stringify!($test);
        let parenthesis_idx = expr_str.find('(').unwrap_or(expr_str.len());
        let test_name = &expr_str[..parenthesis_idx];

        println!("⇢ test `{}` ...", test_name);
        let res = ::std::panic::catch_unwind(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async { $test });
        });
        match res {
            Ok(()) => println!("◉ test `{}` succeeded!\n", test_name),
            Err(_) => println!("✗ test `{}` failed!\n", test_name),
        }
    }};
    ($( $test:expr ; )+) => {{
        $( test!( $test ); )+
    }}
}

const GOOGLE_ADDR: &str = "www.google.com:80";
const USAGE: &str = "--mode <TEST_MODE> --addr <PROXY_ADDR> [--pass <PASSWORD> --user <USERNAME>]";

fn usage() {
    let prgm_name = env::args().next().unwrap();
    println!("Usage: {} {}", prgm_name, USAGE);
}

fn parse_args() -> HashMap<String, String> {
    let mut args = HashMap::new();
    let mut iter = env::args().skip(1);
    loop {
        match (iter.next(), iter.next()) {
            (Some(key), Some(value)) => {
                args.insert(key, value);
            }
            (None, None) => break,
            _ => {
                eprintln!("Invalid argument");
                usage();
                std::process::exit(1);
            }
        }
    }
    args
}

trait OkOrUsage {
    type T;
    fn ok_or_usage(self, msg: &str) -> Self::T;
}

impl<T> OkOrUsage for Option<T> {
    type T = T;

    fn ok_or_usage(self, msg: &str) -> Self::T {
        match self {
            Some(v) => v,
            None => {
                eprintln!("{}", msg);
                usage();
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    let args = parse_args();

    let mode = args
        .get("--mode")
        .ok_or_usage("argument --mode is missing [possible values: socks, http]");
    let addr = args.get("--addr").ok_or_usage("argument --addr is missing");

    match mode.as_str() {
        "socks" => {
            if let (Some(username), Some(password)) = (args.get("--user"), args.get("--pass")) {
                socks_password::test(addr, username, password);
            } else {
                socks_no_password::test(addr);
            }
        }
        "http" => {
            http::test(addr);
        }
        _ => {
            eprintln!("{}", "invalid mode provided");
            usage();
        }
    }
}

async fn ping_google<S>(mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(!buf.is_empty());
    assert!(buf.starts_with(b"HTTP/1.0"));
    assert!(buf.ends_with(b"</HTML>\r\n") || buf.ends_with(b"</html>"));
}

async fn socks5_connect(addr: &str) -> io::Result<Socks5Stream<TcpStream>> {
    let socket = TcpStream::connect(addr).await?;
    Socks5Stream::connect(socket, GOOGLE_ADDR).await
}

async fn socks5_connect_with_password(
    addr: &str,
    username: &str,
    password: &str,
) -> io::Result<Socks5Stream<TcpStream>> {
    let socket = TcpStream::connect(addr).await?;
    Socks5Stream::connect_with_password(socket, GOOGLE_ADDR, username, password).await
}

mod socks_no_password {
    use super::*;

    use jetsocat_proxy::socks4::Socks4Stream;

    pub fn test(addr: &str) {
        test! {
            socks5_no_auth_connect(addr).await;
            socks5_unrequired_username_password_pair(addr).await;
            socks4_connect(addr).await;
        }
    }

    async fn socks5_no_auth_connect(addr: &str) {
        let stream = socks5_connect(addr).await.unwrap();
        crate::ping_google(stream).await;
    }

    async fn socks4_connect(addr: &str) {
        let socket = TcpStream::connect(addr).await.unwrap();
        let stream = Socks4Stream::connect(socket, GOOGLE_ADDR, "david").await.unwrap();
        crate::ping_google(stream).await;
    }

    async fn socks5_unrequired_username_password_pair(addr: &str) {
        let stream = socks5_connect_with_password(addr, "xxxxxxxxxxx", "xxxxxxxxxxx")
            .await
            .unwrap();
        crate::ping_google(stream).await;
    }
}

mod socks_password {
    use super::*;

    pub fn test(addr: &str, username: &str, password: &str) {
        test! {
            socks5_with_password(addr, username, password).await;
            socks5_incorrect_password(addr).await;
            socks5_auth_method_not_supported(addr).await;
        }
    }

    async fn socks5_with_password(addr: &str, username: &str, password: &str) {
        let stream = socks5_connect_with_password(addr, username, password).await.unwrap();
        crate::ping_google(stream).await;
    }

    async fn socks5_incorrect_password(addr: &str) {
        let err = socks5_connect_with_password(addr, "xxxxxxxxxxx", "xxxxxxxxxxx")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "password authentication failed");
    }

    async fn socks5_auth_method_not_supported(addr: &str) {
        let err = socks5_connect(addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "no acceptable auth method");
    }
}

mod http {
    use super::*;
    use jetsocat_proxy::http::HttpProxyStream;

    pub fn test(addr: &str) {
        test! {
            basic(addr).await;
        }
    }

    async fn basic(addr: &str) {
        let socket = TcpStream::connect(addr).await.unwrap();
        let stream = HttpProxyStream::connect(socket, GOOGLE_ADDR).await.unwrap();
        crate::ping_google(stream).await;
    }
}
