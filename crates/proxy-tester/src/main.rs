use std::{env, io};

use proxy_socks::Socks5Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const GOOGLE_ADDR: &str = "www.google.com:80";
const USAGE: &str = "[--mode <TEST_MODE>] [--addr <PROXY_ADDR>] [--user <USERNAME>,<PASSWORD>]";

fn main() {
    let args: Vec<String> = env::args().collect();
    let args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let args = parse_args(&args).expect("bad argument");

    if args.show_usage {
        let prgm_name = env::args().next().unwrap();
        println!("Usage: {prgm_name} {USAGE}");
        return;
    } else {
        println!("{args:?}");
    }

    match args.mode {
        "socks" => {
            if let Some((username, password)) = args.user {
                socks5_password::test(args.addr, username, password);
            } else {
                socks5_no_password::test(args.addr);
                socks4::test(args.addr);
            }
        }
        "socks5" => {
            if let Some((username, password)) = args.user {
                socks5_password::test(args.addr, username, password);
            } else {
                socks5_no_password::test(args.addr);
            }
        }
        "socks4" => {
            if args.user.is_some() {
                eprintln!("socks4 doesn't support authentication");
                std::process::exit(1);
            } else {
                socks4::test(args.addr);
            }
        }
        "http" => {
            http::test(args.addr);
        }
        invalid_mode => {
            eprintln!("invalid mode provided: {invalid_mode} (possible values: socks, socks4, socks5, http)");
            std::process::exit(1);
        }
    }
}

#[derive(Debug)]
struct Args<'a> {
    mode: &'a str,
    addr: &'a str,
    user: Option<(&'a str, &'a str)>,
    show_usage: bool,
}

impl Default for Args<'_> {
    fn default() -> Self {
        Self {
            mode: "socks5",
            addr: "localhost:1080",
            user: None,
            show_usage: false,
        }
    }
}

fn parse_args<'a>(mut input: &[&'a str]) -> io::Result<Args<'a>> {
    let mut args = Args::default();

    loop {
        match input {
            ["--mode" | "-m", value, rest @ ..] => {
                args.mode = value;
                input = rest;
            }
            ["--addr", value, rest @ ..] => {
                args.addr = value;
                input = rest;
            }
            ["--user" | "-u", value, rest @ ..] => {
                let idx = value
                    .find(',')
                    .ok_or_else(|| io::Error::other(format!("malformed username,password: {value}")))?;
                let (user, pass) = value.split_at(idx);
                args.user = Some((user, &pass[1..]));
                input = rest;
            }
            ["--help" | "-h", rest @ ..] => {
                args.show_usage = true;
                input = rest;
            }
            [unexpected_arg, ..] => {
                return Err(io::Error::other(format!("unexpected argument: {unexpected_arg}")));
            }
            [] => break,
        }
    }

    Ok(args)
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

mod socks5_no_password {
    use super::*;

    pub(crate) fn test(addr: &str) {
        test! {
            socks5_no_auth_connect(addr).await;
            socks5_unrequired_username_password_pair(addr).await;
        }
    }

    async fn socks5_no_auth_connect(addr: &str) {
        let stream = socks5_connect(addr).await.unwrap();
        ping_google(stream).await;
    }

    async fn socks5_unrequired_username_password_pair(addr: &str) {
        let stream = socks5_connect_with_password(addr, "xxxxxxxxxxx", "xxxxxxxxxxx")
            .await
            .unwrap();
        ping_google(stream).await;
    }
}

mod socks4 {
    use proxy_socks::Socks4Stream;

    use super::*;

    pub(crate) fn test(addr: &str) {
        test! {
            socks4_connect(addr).await;
        }
    }

    async fn socks4_connect(addr: &str) {
        let socket = TcpStream::connect(addr).await.unwrap();
        let stream = Socks4Stream::connect(socket, GOOGLE_ADDR, "david").await.unwrap();
        ping_google(stream).await;
    }
}

mod socks5_password {
    use super::*;

    pub(crate) fn test(addr: &str, username: &str, password: &str) {
        test! {
            socks5_with_password(addr, username, password).await;
            socks5_incorrect_password(addr).await;
            socks5_auth_method_not_supported(addr).await;
        }
    }

    async fn socks5_with_password(addr: &str, username: &str, password: &str) {
        let stream = socks5_connect_with_password(addr, username, password).await.unwrap();
        ping_google(stream).await;
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
    use proxy_http::ProxyStream;

    use super::*;

    pub(crate) fn test(addr: &str) {
        test! {
            basic(addr).await;
        }
    }

    async fn basic(addr: &str) {
        let socket = TcpStream::connect(addr).await.unwrap();
        let stream = ProxyStream::connect(socket, GOOGLE_ADDR).await.unwrap();
        ping_google(stream).await;
    }
}
