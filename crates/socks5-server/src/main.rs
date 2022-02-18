use proxy_socks::{Socks5Acceptor, Socks5AcceptorConfig, Socks5FailureCode};
use std::sync::Arc;
use std::{env, io};
use tokio::net::{TcpListener, TcpStream};

const USAGE: &str = "[--no-auth-required] [--port <PORT>] [--user <USERNAME>,<PASSWORD>]";

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let args = parse_args(&args)?;

    if args.show_usage {
        let prgm_name = env::args().next().unwrap();
        println!("Usage: {} {}", prgm_name, USAGE);
        return Ok(());
    } else {
        println!("{:?}", args);
    }

    let conf = Arc::new(Socks5AcceptorConfig {
        no_auth_required: args.no_auth_required,
        users: args.user.map(|(name, pass)| vec![(name.to_owned(), pass.to_owned())]),
    });

    let listener = TcpListener::bind(("0.0.0.0", args.port)).await?;
    println!("Listener for SOCKS5 streams on port {}", args.port);
    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Received stream from {:?}", addr);

        let conf = Arc::clone(&conf);
        tokio::spawn(async move {
            match process_socket(socket, conf).await {
                Ok(()) => println!("Stream from {:?} was processed successfully", addr),
                Err(e) => println!("Error: {}", e),
            }
        });
    }
}

#[derive(Debug)]
struct Args<'a> {
    port: u16,
    no_auth_required: bool,
    user: Option<(&'a str, &'a str)>,
    show_usage: bool,
}

impl<'a> Default for Args<'a> {
    fn default() -> Self {
        Self {
            port: 1080,
            no_auth_required: false,
            user: None,
            show_usage: false,
        }
    }
}

fn parse_args<'a>(mut input: &[&'a str]) -> io::Result<Args<'a>> {
    let mut args = Args::default();

    loop {
        match input {
            ["--port" | "-p", value, rest @ ..] => {
                args.port = value
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("port value malformed: {}", e)))?;
                input = rest;
            }
            ["--no-auth-required", rest @ ..] => {
                args.no_auth_required = true;
                input = rest;
            }
            ["--user" | "-u", value, rest @ ..] => {
                let idx = value.find(',').ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, format!("malformed username,password: {}", value))
                })?;
                let (user, pass) = value.split_at(idx);
                args.user = Some((user, &pass[1..]));
                input = rest;
            }
            ["--help" | "-h", rest @ ..] => {
                args.show_usage = true;
                input = rest;
            }
            [unexpected_arg, ..] => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unexpected argument: {}", unexpected_arg),
                ))
            }
            [] => break,
        }
    }

    Ok(args)
}

async fn process_socket(incoming: TcpStream, conf: Arc<Socks5AcceptorConfig>) -> io::Result<()> {
    let acceptor = Socks5Acceptor::accept_with_config(incoming, &conf).await?;

    if acceptor.is_connect_command() {
        let dest_addr = acceptor.dest_addr();

        println!("Requested proxying to {:?}", dest_addr);

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
