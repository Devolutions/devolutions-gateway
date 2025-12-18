#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::sync::Arc;
use std::{env, io};

use proxy_http::HttpProxyAcceptor;
use proxy_socks::{Socks5Acceptor, Socks5AcceptorConfig, Socks5FailureCode};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const USAGE: &str = "[--no-auth-required] [--socks-port <PORT>] [--https-port <PORT>] [--user <USERNAME>,<PASSWORD>]";

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let args = parse_args(&args)?;

    if args.show_usage {
        let prgm_name = env::args()
            .next()
            .expect("the first argument should be set by the shell");
        println!("Usage: {prgm_name} {USAGE}");
        return Ok(());
    } else {
        println!("{args:?}");
    }

    let conf = Arc::new(Socks5AcceptorConfig {
        no_auth_required: args.no_auth_required,
        users: args.user.map(|(name, pass)| vec![(name.to_owned(), pass.to_owned())]),
    });

    let mut handles = Vec::new();

    if let Some(port) = args.socks_port {
        let socks_listener = TcpListener::bind(("0.0.0.0", port)).await?;
        println!("Listener for SOCKS5 streams on port {port}");

        let handle = tokio::spawn(async move {
            loop {
                if let Ok((socket, addr)) = socks_listener.accept().await {
                    println!("Received SOCKS5 request from {addr:?}");
                    let conf = Arc::clone(&conf);
                    tokio::spawn(async move {
                        match process_socks5(socket, conf).await {
                            Ok(()) => println!("Stream from {addr:?} was processed successfully"),
                            Err(e) => println!("Error: {e}"),
                        }
                    });
                }
            }
        });

        handles.push(handle);
    }

    if let Some(port) = args.https_port {
        let https_listener = TcpListener::bind(("0.0.0.0", port)).await?;
        println!("Listener for HTTPS tunneling on port {port}");

        let handle = tokio::spawn(async move {
            loop {
                if let Ok((socket, addr)) = https_listener.accept().await {
                    println!("Received HTTPS tunneling request from {addr:?}");
                    tokio::spawn(async move {
                        match process_https(socket).await {
                            Ok(()) => println!("Stream from {addr:?} was processed successfully"),
                            Err(e) => println!("Error: {e}"),
                        }
                    });
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

#[derive(Default, Debug)]
struct Args<'a> {
    https_port: Option<u16>,
    socks_port: Option<u16>,
    no_auth_required: bool,
    user: Option<(&'a str, &'a str)>,
    show_usage: bool,
}

fn parse_args<'a>(mut input: &[&'a str]) -> io::Result<Args<'a>> {
    let mut args = Args::default();

    loop {
        match input {
            ["--https-port", value, rest @ ..] => {
                args.https_port = value
                    .parse::<u16>()
                    .map(Some)
                    .map_err(|e| io::Error::other(format!("HTTPS proxy port value malformed: {e}")))?;
                input = rest;
            }
            ["--socks-port", value, rest @ ..] => {
                args.socks_port = value
                    .parse::<u16>()
                    .map(Some)
                    .map_err(|e| io::Error::other(format!("SOCKS5 proxy port value malformed: {e}")))?;
                input = rest;
            }
            ["--no-auth-required", rest @ ..] => {
                args.no_auth_required = true;
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

async fn process_socks5(incoming: TcpStream, conf: Arc<Socks5AcceptorConfig>) -> io::Result<()> {
    let acceptor = Socks5Acceptor::accept_with_config(incoming, &conf).await?;

    if acceptor.is_connect_command() {
        let dest_addr = acceptor.dest_addr();

        println!("Requested proxying to {dest_addr:?}");

        let socket_addr = {
            match dest_addr.clone() {
                proxy_types::DestAddr::Ip(addr) => addr,
                proxy_types::DestAddr::Domain(domain, port) => {
                    let mut addrs = match tokio::net::lookup_host((domain, port)).await {
                        Ok(addrs) => addrs,
                        Err(e) => {
                            acceptor.failed(Socks5FailureCode::HostUnreachable).await?;
                            return Err(e);
                        }
                    };
                    addrs.next().expect("at least one resolved address should be present")
                }
            }
        };

        let target_stream = match TcpStream::connect(socket_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                acceptor.failed(Socks5FailureCode::from(&e)).await?;
                return Err(e);
            }
        };

        let incoming_stream = acceptor.connected(target_stream.local_addr()?).await?;

        let (mut incoming_reader, mut incoming_writer) = incoming_stream.into_split();
        let (mut target_reader, mut target_writer) = target_stream.into_split();

        let incoming_to_target = tokio::io::copy(&mut target_reader, &mut incoming_writer);
        let target_to_incoming = tokio::io::copy(&mut incoming_reader, &mut target_writer);

        println!("SOCKS5 negotiation ended successfully");

        tokio::select! {
            _ = incoming_to_target => {}
            _ = target_to_incoming => {}
        }
    } else {
        acceptor.failed(Socks5FailureCode::CommandNotSupported).await?;
    }

    Ok(())
}

async fn process_https(incoming: TcpStream) -> io::Result<()> {
    let acceptor = HttpProxyAcceptor::accept(incoming).await?;

    let dest_addr = acceptor.dest_addr();

    println!("Requested proxying to {dest_addr:?}");

    let connect_result = match dest_addr {
        proxy_types::DestAddr::Ip(addr) => TcpStream::connect(addr).await,
        proxy_types::DestAddr::Domain(domain, port) => TcpStream::connect((domain.as_str(), *port)).await,
    };

    let target_stream = match connect_result {
        Ok(stream) => stream,
        Err(e) => {
            acceptor.failure(proxy_http::ErrorCode::BadGateway).await?;
            return Err(e);
        }
    };

    let incoming_stream = match acceptor {
        HttpProxyAcceptor::RegularRequest(regular_request) => regular_request.success_with_rewrite()?,
        HttpProxyAcceptor::TunnelRequest(tunnel_request) => tunnel_request.success().await?,
    };

    let (incoming_stream, read_leftover) = incoming_stream.into_parts();

    let (mut incoming_reader, mut incoming_writer) = incoming_stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    target_writer.write_all(&read_leftover).await?;

    let incoming_to_target = tokio::io::copy(&mut target_reader, &mut incoming_writer);
    let target_to_incoming = tokio::io::copy(&mut incoming_reader, &mut target_writer);

    println!("HTTPS tunneling negotiation ended successfully");

    tokio::select! {
        _ = incoming_to_target => {}
        _ = target_to_incoming => {}
    }

    Ok(())
}
