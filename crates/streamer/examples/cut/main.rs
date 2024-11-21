#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use std::{env, path::Path, process::exit, thread};

use anyhow::Context;
use cadeau::xmf;
use local_websocket::create_local_websocket;
use streamer::{streamer::webm_stream, ReOpenableFile};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch::{Receiver, Sender},
};
use tracing::{error, info};

pub struct TokioSignal {
    signal: tokio::sync::watch::Receiver<()>,
}

impl streamer::streamer::Signal for TokioSignal {
    async fn wait(&mut self) {
        let _ = self.signal.changed().await;
    }
}

mod local_websocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
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

    let input_path = Path::new(args.input_path);
    let (eof_sender, eof_receiver) = tokio::sync::watch::channel(());
    let intermidiate_file = get_slowly_written_file(input_path, eof_sender).await?;

    let (client, server) = create_local_websocket().await;
    let output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.output_path)
        .await?;

    run_client(client, output_file);

    let shutdown_signal = TokioSignal { signal: eof_receiver };

    tokio::task::spawn_blocking(move || {
        webm_stream(server, intermidiate_file, shutdown_signal, || {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tx.send(()).unwrap();
            thread::sleep(std::time::Duration::from_millis(300));
            rx
        })?;

        Ok::<_, anyhow::Error>(())
    })
    .await??;

    Ok(())
}

async fn get_slowly_written_file(input_path: &Path, eof_signal: Sender<()>) -> anyhow::Result<ReOpenableFile> {
    let input_file_name = input_path
        .file_name()
        .context("no file name")?
        .to_str()
        .context("invalid file name")?;
    let input_file = tokio::fs::File::open(input_path).await?;

    let temp_file_path = input_path
        .parent()
        .context("no parent")?
        .join(format!("temp_{}", input_file_name));

    // rmove the temp file if it exists
    tokio::fs::remove_file(&temp_file_path).await.ok();

    let mut temp_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .share_mode(0x00000002 | 0x00000001)
        .open(&temp_file_path)
        .await?;

    tokio::spawn(async move {
        let mut input_file = input_file;

        // write initial 500KB to simulate already written data
        let mut buf = [0; 1024];
        let mut size = 0;
        while size < 500 * 1024 {
            let n = input_file.read(&mut buf).await?;
            temp_file.write_all(&buf[..n]).await?;

            size += n;
        }

        // then slowily write the rest
        loop {
            let n = input_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            // debug!(size, "write to temp file");
            size += n;
            temp_file.write_all(&buf[..n]).await?;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        eof_signal.send(()).unwrap();
        Ok::<_, anyhow::Error>(())
    });

    Ok(ReOpenableFile::open(temp_file_path)?)
}

#[derive(Debug, Default)]
struct Args<'a> {
    // input path, -i
    input_path: &'a str,
    // lib_xmf path, --lib-xmf
    lib_xmf_path: &'a str,
    // output path, -o
    output_path: &'a str,
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

fn run_client(client: local_websocket::WebSocketClient, mut output_file: tokio::fs::File) {
    tokio::spawn(async move {
        client.send(vec![0]).await.unwrap();
        loop {
            let Some(Ok(next_message)) = client.next().await else {
                break;
            };

            match next_message {
                tokio_tungstenite::tungstenite::Message::Text(_) => {
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Binary(vec) => {
                    let file_type = vec[0];
                    if file_type == 0 {
                        info!("client received chunk of size: {}", vec.len());
                        output_file.write_all(&vec[1..]).await.unwrap();
                    }

                    client.send(vec![1]).await.unwrap();
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    break;
                }
                _ => {}
            }
        }
    });
}
