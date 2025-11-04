#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]
#![expect(clippy::clone_on_ref_ptr, reason = "example code clarity over performance")]

use std::env;
use std::path::Path;
use std::process::exit;
use std::sync::Arc;

use anyhow::Context;
use cadeau::xmf;
use local_websocket::create_local_websocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tracing::{error, info};
use video_streamer::config::CpuCount;
use video_streamer::{ReOpenableFile, StreamingConfig, webm_stream};

pub struct TokioSignal {
    signal: tokio::sync::watch::Receiver<()>,
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

    // SAFETY: Just pray at this point
    unsafe {
        xmf::init(args.lib_xmf_path)?;
    }

    let notify = Arc::new(Notify::new());

    let input_path = Path::new(args.input_path);
    let (file_written_sender, file_written_receiver) = tokio::sync::broadcast::channel(1);
    let intermediate_file = get_slowly_written_file(input_path, notify.clone(), file_written_sender).await?;

    let (client, server) = create_local_websocket().await;
    let output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.output_path)
        .await?;

    run_client(client, output_file);

    tokio::task::spawn_blocking(move || {
        webm_stream(
            server,
            intermediate_file,
            notify,
            StreamingConfig {
                encoder_threads: CpuCount::default(),
            },
            || {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let mut file_written_receiver = file_written_receiver.resubscribe();
                tokio::spawn(async move {
                    if file_written_receiver.recv().await.is_ok() {
                        let _ = tx.send(());
                    }
                });
                rx
            },
        )?;

        Ok::<_, anyhow::Error>(())
    })
    .await??;

    Ok(())
}

async fn get_slowly_written_file(
    input_path: &Path,
    eof_signal: Arc<Notify>,
    file_written_sender: tokio::sync::broadcast::Sender<()>,
) -> anyhow::Result<ReOpenableFile> {
    let input_file_name = input_path
        .file_name()
        .context("no file name")?
        .to_str()
        .context("invalid file name")?;
    let input_file = tokio::fs::File::open(input_path).await?;

    let temp_file_path = input_path
        .parent()
        .context("no parent")?
        .join(format!("temp_{input_file_name}"));

    // remove the temp file if it exists
    tokio::fs::remove_file(&temp_file_path).await.ok();

    let mut open_option = tokio::fs::OpenOptions::new();
    open_option.create(true).write(true).truncate(true);

    #[cfg(target_os = "windows")]
    {
        open_option.share_mode(0x00000002 | 0x00000001);
    }
    let mut temp_file = open_option.open(&temp_file_path).await?;

    tokio::spawn(async move {
        let mut input_file = input_file;

        // write initial 500KB to simulate already written data
        let mut buf = [0; 10240];
        let mut size = 0;
        while size < 1_750_000 {
            let n = input_file.read(&mut buf).await?;
            temp_file.write_all(&buf[..n]).await?;

            size += n;
        }
        info!("Jump to 175000");
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        // then slowily write the rest
        loop {
            let n = input_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            size += n;
            temp_file.write_all(&buf[..n]).await?;
            file_written_sender.send(()).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        eof_signal.notify_waiters();
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

const HELP: &str = "Usage: cut -i <input> -o <output> --lib-xmf <libxmf.so> ";

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
                println!("{HELP}");
                exit(0);
            }
            [] => break,
            _ => {
                anyhow::bail!("invalid argument");
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
