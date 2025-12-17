//! For debugging webm video iterators

use std::env;
use std::io::Seek;
use std::path::Path;
use std::process::exit;

use tracing::*;
use video_streamer::debug;
use webm_iterable::matroska_spec::MatroskaSpec;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
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

    let seek_position = args.start_offset.unwrap_or(0);

    let mut file = std::fs::File::open(args.input_path)?;
    file.seek(std::io::SeekFrom::Start(seek_position))?;

    let mut iter = webm_iterable::WebmIterator::new(
        file,
        &[MatroskaSpec::BlockGroup(webm_iterable::matroska_spec::Master::Start)],
    );
    iter.emit_master_end_when_eof(false);

    loop {
        let item = iter.next();
        let Some(item) = item else {
            break;
        };
        match item {
            Ok(tag) => {
                let tag_name = debug::mastroka_spec_name(&tag);
                let absolute_offset = usize::try_from(seek_position)? + iter.last_emitted_tag_offset();
                info!(
                    tag_name = tag_name,
                    absolute_offset = absolute_offset,
                    iter_offset = iter.last_emitted_tag_offset(),
                    "Tag found"
                )
            }
            Err(e) => {
                error!(error = ?e,
                    absolute_offset = usize::try_from(seek_position)? + iter.last_emitted_tag_offset(),
                    iter_offset = iter.last_emitted_tag_offset(),
                    "Error while reading WebM file");
                break;
            }
        }
    }

    todo!()
}

#[derive(Debug, Default)]
struct Args<'a> {
    // input path, -i or --input
    input_path: &'a str,
    // start offset, -s or --start-offset
    start_offset: Option<u64>,
}
const HELP: &str = "
    Print the tag of a WebM file from specific offset.
    Usage: cut -i <input> -o <output> --lib-xmf <libxmf.so> 
";
fn parse_arg<'a>(mut value: &[&'a str]) -> anyhow::Result<Args<'a>> {
    let mut arg = Args::default();

    loop {
        match value {
            ["--input" | "-i", input_path, rest @ ..] => {
                arg.input_path = input_path;
                value = rest;
            }
            ["--start-offset" | "-s", start_offset, rest @ ..] => {
                arg.start_offset = Some(start_offset.parse()?);
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

    if arg.input_path.is_empty() {
        println!("{HELP}");
        anyhow::bail!("Input path is required");
    }

    Ok(arg)
}
