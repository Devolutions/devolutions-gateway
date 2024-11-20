#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]

use std::{env, path::Path, process::exit};

use anyhow::Context;
use cadeau::xmf;
use streamer::streamer::webm_stream;
use tracing::error;

pub struct TokioSignal {
    signal: tokio::sync::watch::Receiver<()>,
}

impl streamer::streamer::Signal for TokioSignal {
    async fn wait(&mut self) {
        let _ = self.signal.changed().await;
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
    let output_file = tokio::fs::File::create(&args.output_path).await?;

    let (tx, rx) = tokio::sync::watch::channel(());

    let shutdown_signal = TokioSignal { signal: rx };

    tokio::task::spawn_blocking(move || {
        webm_stream(output_file, input_file, shutdown_signal, || {
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
