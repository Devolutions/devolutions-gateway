// MCP CLI Proxy (no-argh edition)
// Reads MCP tool calls from stdin (via JSON), proxies them to an MCP server,
// and writes responses to stdout.

use std::env;
use std::io::{self, BufRead, BufReader};
use std::time::Duration;

use anyhow::Context as _;
use mcp_proxy::{Config, McpProxy};

const USAGE: &str = "Usage: mcp-proxy [-u URL | -c CMD [-a ARGS] | -p PIPE] [-t SECS] [-v] [-h]
  -u, --url     HTTP server base URL
  -c, --command Command to run for STDIO transport
  -p, --pipe    Named pipe path (Unix: /path/to/pipe; Windows: \\\\.\\pipe\\name)
  -t, --timeout Timeout in seconds for HTTP (default: 30)
  -v, --verbose Enable verbose output to stderr
  -h, --help    Show this help";

#[derive(Debug, Default)]
struct Args {
    url: Option<String>,
    command: Option<String>,
    pipe: Option<String>,
    timeout: u64,
    verbose: bool,
    show_usage: bool,
}

fn parse_cli() -> anyhow::Result<Args> {
    let mut a = Args {
        timeout: 30,
        ..Default::default()
    };

    let mut it = env::args().skip(1);

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "-u" | "--url" => {
                a.url = Some(it.next().context("missing value for --url")?);
            }
            "-c" | "--command" => {
                a.command = Some(it.next().context("missing value for --command")?);
            }
            "-p" | "--pipe" => {
                a.pipe = Some(it.next().context("missing value for --pipe")?);
            }
            "-t" | "--timeout" => {
                let s = it.next().context("missing value for --timeout")?;
                a.timeout = s.parse::<u64>().with_context(|| format!("invalid --timeout: {s}"))?;
            }
            "-v" | "--verbose" => a.verbose = true,
            "-h" | "--help" => a.show_usage = true,
            other => anyhow::bail!("unexpected argument: {other}\n{USAGE}"),
        }
    }

    Ok(a)
}

fn args_to_config(args: Args) -> anyhow::Result<Config> {
    let cfg = match (args.url, args.command, args.pipe) {
        (None, None, None) => anyhow::bail!("must specify one transport (-u | -c | -p)\n{USAGE}"),
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            anyhow::bail!("only one transport may be specified (-u OR -c OR -p)")
        }
        (Some(url), _, _) => Config::http(url, Some(Duration::from_secs(args.timeout))),
        (_, Some(command), _) => Config::spawn_process(command),
        (_, _, Some(pipe)) => Config::named_pipe(pipe),
    };

    Ok(cfg)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // 1) Parse CLI.
    let args = parse_cli().context("failed to parse CLI")?;

    if args.show_usage {
        println!("{USAGE}");
        return Ok(());
    }

    let verbose = args.verbose;

    // 2) Build proxy config.
    let config = args_to_config(args)?;

    // 3) Verbose startup logs.
    if verbose {
        eprintln!("[INFO] Starting MCP proxy tool");
        eprintln!("[INFO] Configuration: {config:?}");
    }

    // 4) Init proxy.
    let mut proxy = McpProxy::init(config).await?;

    // 5) Stream JSON-RPC from stdin, emit responses to stdout.
    let reader = BufReader::new(io::stdin());
    for line in reader.lines() {
        let line = line.context("failed to read line from stdin")?;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if verbose {
            eprintln!("[DEBUG] Received request: {line}");
        }

        match proxy.handle_jsonrpc_request_str(line).await {
            Ok(Some(resp)) => println!("{}", resp.to_string()?),
            Ok(None) => {} // notification; no response
            Err(e) => {
                eprintln!("[ERROR] Failed to handle request: {e}");
            }
        }
    }

    Ok(())
}
