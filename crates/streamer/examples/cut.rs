#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use std::{env, path::Path, pin::Pin, process::exit};

use anyhow::Context;
use cadeau::xmf;
use streamer::streamer::{
    protocol::{ClientMessage, Codec, ProtocolCodeC, ServerMessage},
    webm_stream,
};
use tokio::io::AsyncWriteExt;
use tokio_util::{
    bytes::{self, Buf, BufMut},
    codec::{self, Framed},
};
use tracing::error;

pub struct TokioSignal {
    signal: tokio::sync::watch::Receiver<()>,
}

impl streamer::streamer::Signal for TokioSignal {
    async fn wait(&mut self) {
        let _ = self.signal.changed().await;
    }
}

#[derive(Debug)]
pub enum OwnedServerMessage {
    Chunk(Vec<u8>),
    // leave for future extension (e.g. audio metadata, size, etc.)
    MetaData { codec: Codec },
}

pub struct ReversedProtocolCodeC;

impl codec::Decoder for ReversedProtocolCodeC {
    type Item = OwnedServerMessage;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None); // Wait for more data
        }

        let type_code = src.get_u8();
        let message = match type_code {
            0 => {
                // Decode a chunk
                if src.is_empty() {
                    return Ok(None); // Wait for the rest of the chunk
                }
                let chunk = src.split_to(src.len()); // Take the remaining bytes as the chunk
                OwnedServerMessage::Chunk(chunk.to_vec())
            }
            1 => {
                // Decode metadata
                if src.is_empty() {
                    return Ok(None); // Wait for the rest of the metadata
                }
                let json = String::from_utf8(src.to_vec())
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
                let codec = if json.contains("vp8") {
                    Codec::Vp8
                } else if json.contains("vp9") {
                    Codec::Vp9
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unknown codec in metadata",
                    ));
                };
                OwnedServerMessage::MetaData { codec }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid message type",
                ))
            }
        };

        Ok(Some(message))
    }
}

struct WebsocketMimic {
    frame: Framed<tokio::fs::File, ReversedProtocolCodeC>,
    started: bool,
}

impl tokio::io::AsyncRead for WebsocketMimic {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.started {
            buf.put_u8(1);
        } else {
            buf.put_u8(0);
            self.get_mut().started = true;
        }

        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for WebsocketMimic {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.get_mut().frame.
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_line_number(true)
        .init();

    let args: Vec<String> = env::args().collect();
    let args: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let args = parse_arg(&args)?;

    // Check if the input file exists
    if !Path::new(&args.input_path).exists() {
        error!("Error: Input file does not exist at path: {}", args.input_path);
        exit(1);
    }

    // Check if the lib_xmf file exists
    if !Path::new(&args.lib_xmf_path).exists() {
        error!("Error: Lib XMF file does not exist at path: {}", args.lib_xmf_path);
        exit(1);
    }

    unsafe {
        xmf::init(args.lib_xmf_path)?;
    }

    let input_file = streamer::ReOpenableFile::open(args.input_path)?;
    let output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.output_path)
        .await?;

    let websocket_mimic = WebsocketMimic {
        frame: Framed::new(output_file, ReversedProtocolCodeC),
        started: false,
    };

    let (_tx, rx) = tokio::sync::watch::channel(());

    let shutdown_signal = TokioSignal { signal: rx };

    tokio::task::spawn_blocking(move || {
        webm_stream(websocket_mimic, input_file, shutdown_signal, || {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tx.send(()).unwrap();
            rx
        })?;

        Ok::<_, anyhow::Error>(())
    })
    .await??;

    Ok(())
}

#[derive(Debug, Default)]
struct Args<'a> {
    // input path, -i
    input_path: &'a str,
    // lib_xmf path, --lib-xmf
    lib_xmf_path: &'a str,
    // output path, -o
    output_path: &'a str,
    // -c or --cut,cut start time in seconds
    cut_start: u32,
}

const HELP: &str = "Usage: cut -i <input> -o <output> --lib-xmf <libxmf.so> -c <start_time>";

fn parse_arg<'a>(mut value: &[&'a str]) -> anyhow::Result<Args<'a>> {
    let mut arg = Args::default();
    loop {
        match value {
            ["--lib-xmf", lib_xmf_path, rest @ ..] => {
                arg.lib_xmf_path = lib_xmf_path;
                value = rest;
            }
            ["--input" | "-i", input_path, rest @ ..] => {
                arg.input_path = input_path;
                value = rest;
            }
            ["--output" | "-o", output_path, rest @ ..] => {
                arg.output_path = output_path;
                value = rest;
            }
            ["--cut" | "-c", cut_start, rest @ ..] => {
                arg.cut_start = cut_start.parse::<u32>().context("Failed to parse cut start time")?;
                value = rest;
            }
            ["--help" | "-h", ..] => {
                println!("{}", HELP);
                exit(0);
            }
            [] => break,
            _ => {
                anyhow::bail!("Invalid argument");
            }
        }
    }

    Ok(arg)
}
