#[cfg(windows)]
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    OpenHold,
    TimeoutWindow,
    DelayedOpen,
    NoOpen,
}

impl Scenario {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "open-hold" => Some(Self::OpenHold),
            "timeout-window" => Some(Self::TimeoutWindow),
            "delayed-open" => Some(Self::DelayedOpen),
            "no-open" => Some(Self::NoOpen),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenHold => "open-hold",
            Self::TimeoutWindow => "timeout-window",
            Self::DelayedOpen => "delayed-open",
            Self::NoOpen => "no-open",
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    scenario: Scenario,
    channel_name: String,
    cycles: u32,
    delay_ms: u64,
    open_ms: u64,
    gap_ms: u64,
    wait_for_open_ms: u64,
    retry_interval_ms: u64,
}

impl Config {
    fn parse() -> anyhow::Result<Self> {
        let mut args = std::env::args().skip(1);

        let Some(scenario_str) = args.next() else {
            print_usage();
            bail!("missing scenario");
        };

        if scenario_str == "--help" || scenario_str == "-h" {
            print_usage();
            std::process::exit(0);
        }

        let scenario = Scenario::from_str(&scenario_str).with_context(|| {
            format!("unknown scenario `{scenario_str}` (expected open-hold, timeout-window, delayed-open, no-open)")
        })?;

        let mut channel_name = "Devolutions::Now::Agent".to_owned();
        let mut cycles = 1_u32;
        let mut delay_ms = 0_u64;
        let mut open_ms = 5_000_u64;
        let mut gap_ms = 500_u64;
        let mut wait_for_open_ms = 0_u64;
        let mut retry_interval_ms = 250_u64;

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--channel-name" => channel_name = next_value(&mut args, &flag)?,
                "--cycles" => cycles = parse_u32(&next_value(&mut args, &flag)?, &flag)?,
                "--delay-ms" => delay_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--open-ms" => open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--gap-ms" => gap_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--wait-for-open-ms" => wait_for_open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--retry-interval-ms" => retry_interval_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => bail!("unknown argument `{flag}`"),
            }
        }

        if cycles == 0 {
            bail!("--cycles must be at least 1");
        }

        if retry_interval_ms == 0 {
            bail!("--retry-interval-ms must be at least 1");
        }

        match scenario {
            Scenario::OpenHold if cycles != 1 => bail!("open-hold supports exactly one cycle"),
            Scenario::NoOpen if cycles != 1 => bail!("no-open supports exactly one cycle"),
            _ => {}
        }

        Ok(Self {
            scenario,
            channel_name,
            cycles,
            delay_ms,
            open_ms,
            gap_ms,
            wait_for_open_ms,
            retry_interval_ms,
        })
    }
}

fn parse_u32(value: &str, flag: &str) -> anyhow::Result<u32> {
    value
        .parse::<u32>()
        .with_context(|| format!("invalid value for {flag}: `{value}`"))
}

fn parse_u64(value: &str, flag: &str) -> anyhow::Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("invalid value for {flag}: `{value}`"))
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    args.next().with_context(|| format!("missing value after {flag}"))
}

fn ts_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis()
}

fn log_event(scenario: Scenario, cycle: Option<u32>, event: &str, detail: impl AsRef<str>) {
    match cycle {
        Some(cycle) => {
            println!(
                "ts_ms={} scenario={} cycle={} event={} detail=\"{}\"",
                ts_ms(),
                scenario.as_str(),
                cycle,
                event,
                detail.as_ref()
            );
        }
        None => {
            println!(
                "ts_ms={} scenario={} event={} detail=\"{}\"",
                ts_ms(),
                scenario.as_str(),
                event,
                detail.as_ref()
            );
        }
    }
}

#[cfg(windows)]
fn open_channel(channel_name: &str) -> anyhow::Result<win_api_wrappers::wts::WtsVirtualChannel> {
    win_api_wrappers::wts::WtsVirtualChannel::open_dvc(channel_name)
}

#[cfg(windows)]
fn open_channel_with_retry(
    scenario: Scenario,
    cycle: u32,
    config: &Config,
) -> anyhow::Result<win_api_wrappers::wts::WtsVirtualChannel> {
    let start = Instant::now();
    let mut attempt = 1_u32;

    loop {
        log_event(
            scenario,
            Some(cycle),
            "open-attempt",
            format!("opening channel `{}` attempt={attempt}", config.channel_name),
        );

        match open_channel(&config.channel_name) {
            Ok(channel) => {
                log_event(
                    scenario,
                    Some(cycle),
                    "open-success",
                    format!("channel opened on attempt={attempt}"),
                );
                return Ok(channel);
            }
            Err(error) => {
                if config.wait_for_open_ms == 0 {
                    log_event(scenario, Some(cycle), "open-failure", format!("error={error:#}"));
                    return Err(error).context("failed to open DVC channel");
                }

                let elapsed_ms = start.elapsed().as_millis() as u64;
                if elapsed_ms >= config.wait_for_open_ms {
                    log_event(
                        scenario,
                        Some(cycle),
                        "open-timeout",
                        format!("waited {} ms for open; last_error={error:#}", config.wait_for_open_ms),
                    );
                    return Err(error).context("timed out waiting for DVC open");
                }

                log_event(
                    scenario,
                    Some(cycle),
                    "open-retry",
                    format!(
                        "attempt={attempt} elapsed_ms={elapsed_ms} sleeping {} ms error={error:#}",
                        config.retry_interval_ms
                    ),
                );
                std::thread::sleep(std::time::Duration::from_millis(config.retry_interval_ms));
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

#[cfg(windows)]
fn run_windows(config: &Config) -> anyhow::Result<()> {
    if config.delay_ms > 0 {
        log_event(
            config.scenario,
            None,
            "pre-delay-start",
            format!("sleeping {} ms before first open", config.delay_ms),
        );
        std::thread::sleep(std::time::Duration::from_millis(config.delay_ms));
        log_event(config.scenario, None, "pre-delay-end", "pre-delay completed");
    }

    match config.scenario {
        Scenario::NoOpen => {
            log_event(
                config.scenario,
                Some(1),
                "no-open",
                format!("holding without DVC open for {} ms", config.open_ms),
            );
            std::thread::sleep(std::time::Duration::from_millis(config.open_ms));
            Ok(())
        }
        Scenario::OpenHold | Scenario::TimeoutWindow | Scenario::DelayedOpen => {
            for cycle in 1..=config.cycles {
                let channel = open_channel_with_retry(config.scenario, cycle, config)?;

                log_event(
                    config.scenario,
                    Some(cycle),
                    "open-window-start",
                    format!("holding channel for {} ms", config.open_ms),
                );
                std::thread::sleep(std::time::Duration::from_millis(config.open_ms));
                log_event(config.scenario, Some(cycle), "open-window-end", "closing channel");
                drop(channel);
                log_event(config.scenario, Some(cycle), "closed", "channel handle released");

                if cycle != config.cycles {
                    log_event(
                        config.scenario,
                        Some(cycle),
                        "gap-start",
                        format!("sleeping {} ms before next cycle", config.gap_ms),
                    );
                    std::thread::sleep(std::time::Duration::from_millis(config.gap_ms));
                    log_event(config.scenario, Some(cycle), "gap-end", "starting next cycle");
                }
            }

            Ok(())
        }
    }
}

#[cfg(not(windows))]
fn run_windows(_config: &Config) -> anyhow::Result<()> {
    bail!("this harness is windows-only")
}

fn print_usage() {
    eprintln!(
        "dvc-session-harness <scenario> [options]\n\
         \n\
         Scenarios:\n\
           open-hold       Open the DVC channel once, hold, then close.\n\
           timeout-window  Open/hold/close cycles to emulate the server handshake window.\n\
           delayed-open    Sleep first, then behave like timeout-window.\n\
           no-open         Never open DVC (sleep only).\n\
         \n\
         Options:\n\
           --channel-name <name>   DVC channel name (default: Devolutions::Now::Agent)\n\
           --cycles <n>            Number of open/close cycles (default: 1)\n\
           --delay-ms <ms>         Delay before first open (default: 0)\n\
           --open-ms <ms>          Duration to hold each open channel (default: 5000)\n\
           --gap-ms <ms>           Delay between cycles (default: 500)\n\
           --wait-for-open-ms <ms> Retry open up to this duration per cycle (default: 0)\n\
           --retry-interval-ms <ms> Delay between open retries (default: 250)\n\
         \n\
         Examples:\n\
           dvc-session-harness timeout-window --cycles 6 --open-ms 5000 --gap-ms 200\n\
           dvc-session-harness timeout-window --cycles 200 --wait-for-open-ms 300000 --retry-interval-ms 250\n\
           dvc-session-harness delayed-open --delay-ms 12000 --open-ms 5000\n\
           dvc-session-harness no-open --open-ms 15000"
    );
}

fn main() -> anyhow::Result<()> {
    let config = Config::parse()?;

    log_event(
        config.scenario,
        None,
        "start",
        format!(
            "channel={}, cycles={}, delay_ms={}, open_ms={}, gap_ms={}",
            config.channel_name, config.cycles, config.delay_ms, config.open_ms, config.gap_ms
        ),
    );
    log_event(
        config.scenario,
        None,
        "open-policy",
        format!(
            "wait_for_open_ms={}, retry_interval_ms={}",
            config.wait_for_open_ms, config.retry_interval_ms
        ),
    );

    let result = run_windows(&config);

    match &result {
        Ok(()) => log_event(config.scenario, None, "done", "scenario completed"),
        Err(error) => log_event(config.scenario, None, "failed", format!("{error:#}")),
    }

    result
}
