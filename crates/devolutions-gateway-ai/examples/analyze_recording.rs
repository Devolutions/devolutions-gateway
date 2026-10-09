//! Analyzes a recorded session with a real AI provider and prints the log.
//!
//! ```text
//! cargo run -p devolutions-gateway-ai --example analyze_recording -- --recording-path <path> [options]
//! ```
//!
//! `--recording-path` is a session folder, its `recording.json`, or one recording file (`.cast`, `.trp`, `.webm`).
//! For a single file next to a `recording.json`, the manifest gives its times; without one, the session starts with it.
//!
//! Options:
//! - `--provider <openai|anthropic|mistral|gemini|openai-compatible>`: `openai` by default.
//! - `--model <name>`: `gpt-6-luna` for OpenAI and `claude-sonnet-5-5` for Anthropic by default; required otherwise.
//! - `--base-url <url>`: required for `openai-compatible`.
//! - `--api-key-env <name>`: environment variable holding the API key; `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
//!   `MISTRAL_API_KEY`, `GEMINI_API_KEY` or `AI_API_KEY` by default.
//! - `--xmf <path>`: XMF library, needed for video; `DGATEWAY_LIB_XMF_PATH` by default.
//! - `--max-output-tokens <n>`.
//!
//! The working files and the log are left next to the manifest, in `.ai-analysis/` and `.ai-analysis.slog`.

#![expect(
    clippy::print_stdout,
    reason = "the example reports its progress and the log on the console"
)]

use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_gateway_ai::recording_analysis::{
    Progress, RecordingAnalysisEvent, RecordingFile, RecordingManifest, Recordings,
};
use devolutions_gateway_ai::{AiClient, Provider};

const USAGE: &str = "usage: analyze_recording --recording-path <session folder | recording.json | recording file> \
[--provider openai|anthropic|mistral|gemini|openai-compatible] [--model <name>] [--base-url <url>] \
[--api-key-env <name>] [--xmf <library>] [--max-output-tokens <n>]";

#[derive(Default)]
struct Args {
    recording_path: Option<Utf8PathBuf>,
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    api_key_env: Option<String>,
    xmf: Option<String>,
    max_output_tokens: Option<u32>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args::default();
    let mut raw = std::env::args().skip(1);

    while let Some(flag) = raw.next() {
        let mut value = || raw.next().with_context(|| format!("{flag} needs a value\n{USAGE}"));

        match flag.as_str() {
            "--recording-path" => args.recording_path = Some(value()?.into()),
            "--provider" => args.provider = Some(value()?),
            "--model" => args.model = Some(value()?),
            "--base-url" => args.base_url = Some(value()?),
            "--api-key-env" => args.api_key_env = Some(value()?),
            "--xmf" => args.xmf = Some(value()?),
            "--max-output-tokens" => args.max_output_tokens = Some(value()?.parse()?),
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }

    Ok(args)
}

/// Finds the manifest and the recordings to analyze from a session folder, a `recording.json`, or one recording file.
fn manifest_for(path: &Utf8Path) -> anyhow::Result<(Utf8PathBuf, RecordingManifest)> {
    let (manifest_path, only) = if path.is_dir() {
        (path.join("recording.json"), None)
    } else if path.extension() == Some("json") {
        (path.to_owned(), None)
    } else {
        let dir = match path.parent() {
            Some(dir) if !dir.as_str().is_empty() => dir,
            _ => Utf8Path::new("."),
        };
        let file_name = path.file_name().context("recording path has no file name")?;
        (dir.join("recording.json"), Some(file_name.to_owned()))
    };

    if !manifest_path.exists() {
        let file_name = only.with_context(|| format!("{manifest_path} not found"))?;
        let recordings = Recordings::from_files([RecordingFile {
            file_name,
            start_time: 0,
        }])?;

        // Without a manifest, the session starts with the recording; its length is unknown.
        return Ok((
            manifest_path,
            RecordingManifest {
                start_time: 0,
                duration: 0,
                recordings,
            },
        ));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).with_context(|| format!("read {manifest_path}"))?)
            .with_context(|| format!("parse {manifest_path}"))?;
    let number = |value: &serde_json::Value, name: &str| value[name].as_i64().with_context(|| format!("no {name}"));

    let files = json["files"]
        .as_array()
        .context("manifest has no files")?
        .iter()
        .map(|file| {
            Ok(RecordingFile {
                file_name: file["fileName"].as_str().context("no fileName")?.to_owned(),
                start_time: number(file, "startTime")?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let files = match &only {
        Some(name) => files.into_iter().filter(|file| &file.file_name == name).collect(),
        None => files,
    };

    Ok((
        manifest_path,
        RecordingManifest {
            start_time: number(&json, "startTime")?,
            duration: number(&json, "duration")?,
            recordings: Recordings::from_files(files)?,
        },
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let recording_path = args
        .recording_path
        .with_context(|| format!("--recording-path is required\n{USAGE}"))?;

    let (provider, default_model, default_key_env) = match args.provider.as_deref().unwrap_or("openai") {
        "openai" => (Provider::OpenAi, Some("gpt-6-luna"), "OPENAI_API_KEY"),
        "anthropic" => (Provider::Anthropic, Some("claude-sonnet-5-5"), "ANTHROPIC_API_KEY"),
        "mistral" => (Provider::Mistral, None, "MISTRAL_API_KEY"),
        "gemini" => (Provider::Gemini, None, "GEMINI_API_KEY"),
        "openai-compatible" => (Provider::OpenAiCompatible, None, "AI_API_KEY"),
        other => bail!("unknown provider {other}\n{USAGE}"),
    };

    let model = args
        .model
        .or_else(|| default_model.map(str::to_owned))
        .with_context(|| format!("--model is required for this provider\n{USAGE}"))?;
    let model_label = model.clone();
    let key_env = args.api_key_env.unwrap_or_else(|| default_key_env.to_owned());
    let api_key = std::env::var(&key_env).with_context(|| format!("{key_env} is not set"))?;

    if let Some(xmf) = args.xmf.or_else(|| std::env::var("DGATEWAY_LIB_XMF_PATH").ok()) {
        // SAFETY: The library is XMF, loaded once before any other XMF call.
        unsafe { cadeau::xmf::init(&xmf) }.with_context(|| format!("load XMF from {xmf}"))?;
    }

    let mut builder = AiClient::builder()
        .provider(provider)
        .model(model)
        .api_key(api_key)
        .http_client(reqwest::Client::new());
    if let Some(base_url) = args.base_url {
        builder = builder.base_url(base_url.parse().context("invalid --base-url")?);
    }
    let client = builder.build()?;

    let (manifest_path, manifest) = manifest_for(&recording_path)?;
    let kind = match &manifest.recordings {
        Recordings::Terminal(recordings) => format!("{} terminal recording(s)", recordings.len()),
        Recordings::Video(recordings) => format!("{} video recording(s)", recordings.len()),
    };

    println!();
    println!("  {}", style(BOLD, "AI analysis"));
    println!("  {}  {manifest_path}", style(DIM, "session "));
    println!("  {}  {kind}", style(DIM, "input   "));
    println!(
        "  {}  {} / {}",
        style(DIM, "model   "),
        provider_name(provider),
        model_label
    );
    println!();

    let started = Instant::now();
    let mut request = client.analyze_recording(&manifest, &manifest_path);
    if let Some(max_output_tokens) = args.max_output_tokens {
        request = request.max_output_tokens(max_output_tokens);
    }
    let mut events = request.start();

    let current = Arc::new(Mutex::new(None));
    let ticker = tokio::spawn(show_progress(Arc::clone(&current), started));

    let result = loop {
        match events.recv().await {
            Some(RecordingAnalysisEvent::Progress(progress)) => {
                *current.lock().expect("not poisoned") = Some(progress);
            }
            Some(RecordingAnalysisEvent::Complete(analysis)) => break Ok(analysis),
            Some(RecordingAnalysisEvent::Failure(error)) => break Err(error.to_string()),
            Some(_) => {}
            None => break Err("the analysis stopped unexpectedly".to_owned()),
        }
    };
    ticker.abort();
    clear_line();

    let analysis = match result {
        Ok(analysis) => analysis,
        Err(error) => {
            println!(
                "  {} after {:.1}s: {error}",
                style(RED, "✗ failed"),
                started.elapsed().as_secs_f64()
            );
            println!(
                "  {}",
                style(DIM, "the working files are kept: run again to resume where it stopped")
            );
            std::process::exit(1);
        }
    };
    println!(
        "  {} {} actions in {:.1}s",
        style(GREEN, "✓"),
        analysis.actions,
        started.elapsed().as_secs_f64()
    );
    println!();
    print_actions(&std::fs::read_to_string(&analysis.log_path)?)?;
    println!();

    let usage = analysis.usage.map_or_else(
        || "not reported".to_owned(),
        |usage| format!("{} in, {} out", usage.input_tokens, usage.output_tokens),
    );
    println!("  {}  {}", style(DIM, "model   "), analysis.model);
    println!("  {}  {}", style(DIM, "prompt  "), analysis.prompt_version);
    println!("  {}  {usage}", style(DIM, "tokens  "));
    println!("  {}  {}", style(DIM, "log     "), analysis.log_path);
    println!();

    Ok(())
}

/// Redraws the progress line ten times a second, from the last progress event, until aborted.
async fn show_progress(current: Arc<Mutex<Option<Progress>>>, started: Instant) {
    const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    const BAR: usize = 24;

    for tick in 0usize.. {
        let text = match *current.lock().expect("not poisoned") {
            None => "starting".to_owned(),
            Some(progress @ Progress::Writing) => progress.to_string(),
            Some(progress) => {
                let filled = usize::from(progress.percent()) * BAR / 100;
                format!("[{}{}]  {progress}", "█".repeat(filled), "░".repeat(BAR - filled))
            }
        };

        clear_line();
        print!(
            "  {} {}  {text}",
            style(CYAN, &SPINNER[tick % SPINNER.len()].to_string()),
            style(DIM, &format!("{:>6.1}s", started.elapsed().as_secs_f64()))
        );
        let _ = std::io::stdout().flush();

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn clear_line() {
    print!("\r\x1b[2K");
    let _ = std::io::stdout().flush();
}

/// Prints the actions of a `.slog`: their time since the session started, then their object and details.
fn print_actions(slog: &str) -> anyhow::Result<()> {
    let entries = slog
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;

    let session_start = entries
        .first()
        .and_then(|entry| entry["timestamp"].as_str())
        .and_then(unix_millis)
        .context("log has no start")?;

    let actions = entries
        .iter()
        .filter(|entry| entry["event"] == "session.action")
        .collect::<Vec<_>>();

    if actions.is_empty() {
        println!("  {}", style(DIM, "the AI found no user action"));
        return Ok(());
    }

    for action in actions {
        let at = action["timestamp"]
            .as_str()
            .and_then(unix_millis)
            .unwrap_or(session_start);
        let seconds = (at - session_start).max(0) / 1000;
        let time = format!("{:02}:{:02}", seconds / 60, seconds % 60);
        let description = action["description"].as_str().unwrap_or_default();

        println!("  {}  {}", style(CYAN, &time), style(BOLD, description));

        if let Some(object) = action["object"].as_str() {
            println!("         {} {object}", style(DIM, "→"));
        }

        if let Some(parameters) = action["parameters"].as_object() {
            for (name, value) in parameters {
                println!(
                    "         {} {}",
                    style(DIM, &format!("{name}:")),
                    value.as_str().unwrap_or_default()
                );
            }
        }
    }

    Ok(())
}

/// Reads a `.slog` timestamp, such as `2026-10-02T16:41:48.001Z`, as milliseconds since the Unix epoch.
fn unix_millis(timestamp: &str) -> Option<i64> {
    let (date, time) = timestamp.strip_suffix('Z')?.split_once('T')?;
    let mut date = date.splitn(3, '-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.splitn(3, ':');
    let (hours, minutes) = (time.next()?.parse::<i64>().ok()?, time.next()?.parse::<i64>().ok()?);
    let seconds = time.next()?.parse::<f64>().ok()?;

    // Days since 1970-01-01 for a proleptic Gregorian date.
    let (year, month) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    #[expect(clippy::cast_possible_truncation, reason = "milliseconds of one minute fit in i64")]
    let millis = (seconds * 1000.0).round() as i64;

    Some(((days * 24 + hours) * 60 + minutes) * 60_000 + millis)
}

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";

/// Wraps `text` in an ANSI style, unless `NO_COLOR` is set.
fn style(code: &str, text: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() {
        text.to_owned()
    } else {
        format!("{code}{text}\x1b[0m")
    }
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::OpenAi => "OpenAI",
        Provider::Anthropic => "Anthropic",
        Provider::Mistral => "Mistral",
        Provider::Gemini => "Gemini",
        Provider::OpenAiCompatible => "OpenAI-compatible",
    }
}
