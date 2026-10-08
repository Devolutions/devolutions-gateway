//! Compacts a WebM recording the way Gateway does after a session ends, and prints the outcome.
//!
//! Usage: compact <xmf-lib> <input.webm> <output.webm>

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context as _;
use video_streamer::{CompactOutcome, compact_webm};

#[expect(clippy::print_stdout, reason = "example output")]
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: compact <xmf-lib> <input.webm> <output.webm>";
    let xmf_path = args.next().context(usage)?;
    let input = PathBuf::from(args.next().context(usage)?);
    let output = PathBuf::from(args.next().context(usage)?);

    // SAFETY: XMF has no initialization precondition beyond a valid library path.
    unsafe { cadeau::xmf::init(&xmf_path) }.context("load XMF")?;

    let raw = output.with_extension("raw.webm");
    let started = Instant::now();
    let outcome = compact_webm(&input, &raw)?;
    let elapsed = started.elapsed();

    let input_size = std::fs::metadata(&input)?.len();
    match outcome {
        CompactOutcome::Written(stats) => {
            cadeau::xmf::muxer::webm_remux(&raw, &output).context("remux")?;
            let output_size = std::fs::metadata(&output)?.len();
            println!(
                "written in={input_size} out={output_size} ratio={:.3} frames={}/{} cpu_s={:.2}",
                output_size as f64 / input_size as f64,
                stats.kept_frames,
                stats.input_frames,
                elapsed.as_secs_f64(),
            );
        }
        CompactOutcome::Skipped(reason) => {
            println!(
                "skipped in={input_size} reason={reason:?} cpu_s={:.2}",
                elapsed.as_secs_f64()
            );
        }
    }
    let _ = std::fs::remove_file(raw);

    Ok(())
}
