#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use std::{mem::size_of, time::Duration};

use anyhow::{Context, bail};
#[cfg(windows)]
use now_proto_pdu::ironrdp_core::{Decode, DecodeError, DecodeErrorKind, IntoOwned, ReadCursor, WriteBuf, encode_vec};
#[cfg(windows)]
use now_proto_pdu::{
    NowChannelCapsetMsg, NowChannelHeartbeatMsg, NowChannelMessage, NowExecCapsetFlags, NowMessage, NowRdmAppNotifyMsg,
    NowRdmAppState, NowRdmCapabilitiesMsg, NowRdmMessage, NowRdmReason, NowSessionCapsetFlags, NowSystemCapsetFlags,
};
#[cfg(windows)]
use win_api_wrappers::raw::Win32::Storage::FileSystem::{ReadFile, WriteFile};
#[cfg(windows)]
use win_api_wrappers::raw::Win32::System::RemoteDesktop::CHANNEL_PDU_HEADER;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    OpenHold,
    TimeoutWindow,
    DelayedOpen,
    NoOpen,
    LoginChurn,
    TimingReplay,
}

impl Scenario {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "open-hold" => Some(Self::OpenHold),
            "timeout-window" => Some(Self::TimeoutWindow),
            "delayed-open" => Some(Self::DelayedOpen),
            "no-open" => Some(Self::NoOpen),
            "login-churn" => Some(Self::LoginChurn),
            "timing-replay" => Some(Self::TimingReplay),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::OpenHold => "open-hold",
            Self::TimeoutWindow => "timeout-window",
            Self::DelayedOpen => "delayed-open",
            Self::NoOpen => "no-open",
            Self::LoginChurn => "login-churn",
            Self::TimingReplay => "timing-replay",
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(windows), allow(dead_code))]
struct ReplayCycle {
    open_ms: u64,
    gap_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolShim {
    None,
    Minimal,
}

impl ProtocolShim {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "minimal" => Some(Self::Minimal),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    scenario: Scenario,
    protocol_shim: ProtocolShim,
    channel_name: String,
    cycles: u32,
    delay_ms: u64,
    open_ms: u64,
    gap_ms: u64,
    wait_for_open_ms: u64,
    retry_interval_ms: u64,
    heartbeat_ms: u64,
    wait_for_next_open: bool,
    login_churn_cycles: u32,
    login_churn_open_ms: u64,
    login_churn_gap_ms: u64,
    login_settle_open_ms: u64,
    replay_cycles: Vec<ReplayCycle>,
    replay_settle_open_ms: u64,
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
            format!(
                "unknown scenario `{scenario_str}` (expected open-hold, timeout-window, delayed-open, no-open, login-churn, timing-replay)"
            )
        })?;

        let mut channel_name = "Devolutions::Now::Agent".to_owned();
        let mut protocol_shim = ProtocolShim::None;
        let mut cycles = 1_u32;
        let mut delay_ms = 0_u64;
        let mut open_ms = 5_000_u64;
        let mut gap_ms = 500_u64;
        let mut wait_for_open_ms = 0_u64;
        let mut retry_interval_ms = 250_u64;
        let mut heartbeat_ms = 3_000_u64;
        let mut wait_for_next_open = false;
        let mut login_churn_cycles = 10_u32;
        let mut login_churn_open_ms = 1_200_u64;
        let mut login_churn_gap_ms = 120_u64;
        let mut login_settle_open_ms = 900_000_u64;
        let mut replay_cycles = Vec::<ReplayCycle>::new();
        let mut replay_settle_open_ms = 900_000_u64;

        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--channel-name" => channel_name = next_value(&mut args, &flag)?,
                "--protocol-shim" => {
                    let value = next_value(&mut args, &flag)?;
                    protocol_shim = ProtocolShim::from_str(&value)
                        .with_context(|| format!("invalid value for {flag}: `{value}` (expected none or minimal)"))?;
                }
                "--cycles" => cycles = parse_u32(&next_value(&mut args, &flag)?, &flag)?,
                "--delay-ms" => delay_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--open-ms" => open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--gap-ms" => gap_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--wait-for-open-ms" => wait_for_open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--retry-interval-ms" => retry_interval_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--heartbeat-ms" => heartbeat_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--wait-for-next-open" => wait_for_next_open = true,
                "--login-churn-cycles" => login_churn_cycles = parse_u32(&next_value(&mut args, &flag)?, &flag)?,
                "--login-churn-open-ms" => login_churn_open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--login-churn-gap-ms" => login_churn_gap_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--login-settle-open-ms" => login_settle_open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
                "--replay-cycles" => replay_cycles = parse_replay_cycles(&next_value(&mut args, &flag)?, &flag)?,
                "--replay-settle-open-ms" => replay_settle_open_ms = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
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

        if heartbeat_ms == 0 {
            bail!("--heartbeat-ms must be at least 1");
        }

        if login_churn_cycles == 0 {
            bail!("--login-churn-cycles must be at least 1");
        }

        if login_churn_open_ms == 0 {
            bail!("--login-churn-open-ms must be at least 1");
        }

        if login_settle_open_ms == 0 {
            bail!("--login-settle-open-ms must be at least 1");
        }

        match scenario {
            Scenario::OpenHold if cycles != 1 => bail!("open-hold supports exactly one cycle"),
            Scenario::NoOpen if cycles != 1 => bail!("no-open supports exactly one cycle"),
            Scenario::LoginChurn if cycles != 1 => bail!("login-churn manages its own phases; keep --cycles at 1"),
            Scenario::TimingReplay if cycles != 1 => bail!("timing-replay manages its own phases; keep --cycles at 1"),
            _ => {}
        }

        if scenario == Scenario::TimingReplay && replay_cycles.is_empty() {
            bail!("timing-replay requires --replay-cycles");
        }

        Ok(Self {
            scenario,
            protocol_shim,
            channel_name,
            cycles,
            delay_ms,
            open_ms,
            gap_ms,
            wait_for_open_ms,
            retry_interval_ms,
            heartbeat_ms,
            wait_for_next_open,
            login_churn_cycles,
            login_churn_open_ms,
            login_churn_gap_ms,
            login_settle_open_ms,
            replay_cycles,
            replay_settle_open_ms,
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

fn parse_replay_cycles(value: &str, flag: &str) -> anyhow::Result<Vec<ReplayCycle>> {
    let mut cycles = Vec::new();

    for (index, token) in value.split(',').enumerate() {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let mut parts = token.split(':');
        let open_ms = parts
            .next()
            .with_context(|| format!("invalid value for {flag}: `{token}`"))?
            .parse::<u64>()
            .with_context(|| format!("invalid open_ms in {flag} entry `{token}`"))?;
        let gap_ms = parts
            .next()
            .unwrap_or("0")
            .parse::<u64>()
            .with_context(|| format!("invalid gap_ms in {flag} entry `{token}`"))?;
        if parts.next().is_some() {
            bail!("invalid value for {flag}: `{token}` (expected open_ms:gap_ms)");
        }
        if open_ms == 0 {
            bail!("invalid value for {flag}: entry #{} open_ms must be at least 1", index + 1);
        }
        cycles.push(ReplayCycle { open_ms, gap_ms });
    }

    if cycles.is_empty() {
        bail!("invalid value for {flag}: expected at least one entry");
    }

    Ok(cycles)
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
fn classify_pipe_disconnect(error: &anyhow::Error) -> Option<&'static str> {
    fn kind_from_hresult(code: i32) -> Option<&'static str> {
        match u32::from_ne_bytes(code.to_ne_bytes()) {
            0x8007_006D => Some("broken-pipe"),
            0x8007_00E8 => Some("no-data"),
            0x8007_00E9 => Some("pipe-not-connected"),
            _ => None,
        }
    }

    error.chain().find_map(|source| {
        if let Some(error) = source.downcast_ref::<win_api_wrappers::Error>() {
            return kind_from_hresult(error.code());
        }

        source
            .downcast_ref::<win_api_wrappers::raw::core::Error>()
            .and_then(|error| kind_from_hresult(error.code().0))
    })
}

#[cfg(windows)]
#[derive(Default)]
struct NowMessageDissector {
    start_pos: usize,
    pdu_body_buffer: WriteBuf,
}

#[cfg(windows)]
impl NowMessageDissector {
    fn dissect(&mut self, data_chunk: &[u8]) -> anyhow::Result<Vec<NowMessage<'static>>> {
        let mut messages = Vec::new();

        self.pdu_body_buffer.write_slice(data_chunk);

        loop {
            let usable_chunk_size = self
                .pdu_body_buffer
                .filled_len()
                .checked_sub(self.start_pos)
                .context("failed to get usable chunk size")?;

            let mut cursor = ReadCursor::new(&self.pdu_body_buffer.filled()[self.start_pos..]);

            match NowMessage::decode(&mut cursor) {
                Ok(message) => {
                    messages.push(message.into_owned());
                    let pos = cursor.pos();

                    if pos == usable_chunk_size {
                        self.pdu_body_buffer.clear();
                        self.start_pos = 0;
                        return Ok(messages);
                    }

                    self.start_pos += pos;
                }
                Err(DecodeError {
                    kind: DecodeErrorKind::NotEnoughBytes { .. },
                    ..
                }) => break,
                Err(error) => return Err(error.into()),
            }
        }

        Ok(messages)
    }
}

#[cfg(windows)]
fn open_channel(channel_name: &str) -> anyhow::Result<win_api_wrappers::wts::WtsVirtualChannel> {
    win_api_wrappers::wts::WtsVirtualChannel::open_dvc(channel_name)
}

#[cfg(windows)]
fn sleep_with_stop(stop_requested: &AtomicBool, duration_ms: u64) -> bool {
    let deadline = Instant::now() + std::time::Duration::from_millis(duration_ms);
    let sleep_slice = std::time::Duration::from_millis(100);

    while Instant::now() < deadline {
        if stop_requested.load(Ordering::Relaxed) {
            return false;
        }

        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(std::cmp::min(remaining, sleep_slice));
    }

    true
}

#[cfg(windows)]
fn open_channel_with_retry(
    scenario: Scenario,
    cycle: u32,
    config: &Config,
    stop_requested: &AtomicBool,
) -> anyhow::Result<win_api_wrappers::wts::WtsVirtualChannel> {
    let start = Instant::now();
    let mut attempt = 1_u32;

    loop {
        if stop_requested.load(Ordering::Relaxed) {
            log_event(
                scenario,
                Some(cycle),
                "interrupted",
                "stop requested before channel open",
            );
            bail!("interrupted by user");
        }

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
                if !sleep_with_stop(stop_requested, config.retry_interval_ms) {
                    log_event(
                        scenario,
                        Some(cycle),
                        "interrupted",
                        "stop requested during open retry delay",
                    );
                    bail!("interrupted by user");
                }
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

#[cfg(windows)]
fn arm_for_next_open(config: &Config, scenario: Scenario, stop_requested: &AtomicBool) -> anyhow::Result<()> {
    let started_at = Instant::now();
    let mut saw_disconnected = false;
    let mut attempt = 1_u32;

    log_event(
        scenario,
        None,
        "arm-start",
        "arming for next DVC open transition (disconnect -> reconnect)",
    );

    loop {
        if stop_requested.load(Ordering::Relaxed) {
            log_event(scenario, None, "interrupted", "stop requested while arming");
            bail!("interrupted by user");
        }

        if config.wait_for_open_ms != 0 && started_at.elapsed().as_millis() as u64 >= config.wait_for_open_ms {
            bail!("timed out while waiting for next DVC open transition");
        }

        match open_channel(&config.channel_name) {
            Ok(channel) => {
                drop(channel);

                if saw_disconnected {
                    log_event(
                        scenario,
                        None,
                        "arm-ready",
                        format!("next DVC open observed at attempt={attempt}"),
                    );
                    return Ok(());
                }

                log_event(
                    scenario,
                    None,
                    "arm-open-present",
                    format!("channel is currently open at attempt={attempt}; waiting for disconnect"),
                );
            }
            Err(error) => {
                if !saw_disconnected {
                    saw_disconnected = true;
                    log_event(
                        scenario,
                        None,
                        "arm-disconnected",
                        format!("disconnected state observed at attempt={attempt}: {error:#}"),
                    );
                } else {
                    log_event(
                        scenario,
                        None,
                        "arm-wait",
                        format!("still waiting for reopen at attempt={attempt}: {error:#}"),
                    );
                }
            }
        }

        if !sleep_with_stop(stop_requested, config.retry_interval_ms) {
            log_event(
                scenario,
                None,
                "interrupted",
                "stop requested during arming retry delay",
            );
            bail!("interrupted by user");
        }

        attempt = attempt.saturating_add(1);
    }
}

#[cfg(windows)]
fn default_server_caps() -> NowChannelCapsetMsg {
    let exec_flags = NowExecCapsetFlags::STYLE_RUN
        | NowExecCapsetFlags::STYLE_PROCESS
        | NowExecCapsetFlags::STYLE_BATCH
        | NowExecCapsetFlags::STYLE_WINPS
        | NowExecCapsetFlags::IO_REDIRECTION
        | NowExecCapsetFlags::UNICODE_CONSOLE;

    NowChannelCapsetMsg::default()
        .with_system_capset(NowSystemCapsetFlags::SHUTDOWN)
        .with_session_capset(
            NowSessionCapsetFlags::LOCK
                | NowSessionCapsetFlags::LOGOFF
                | NowSessionCapsetFlags::MSGBOX
                | NowSessionCapsetFlags::SET_KBD_LAYOUT
                | NowSessionCapsetFlags::WINDOW_RECORDING,
        )
        .with_exec_capset(exec_flags)
}

#[cfg(windows)]
fn send_message(
    channel_file: &win_api_wrappers::raw::core::Owned<win_api_wrappers::raw::Win32::Foundation::HANDLE>,
    message: &NowMessage<'_>,
) -> anyhow::Result<()> {
    let payload = encode_vec(message).context("encode NOW message")?;
    let mut written = 0_u32;

    // SAFETY: `channel_file` is an owned valid handle returned by WTSVirtualChannelQuery.
    unsafe { WriteFile(**channel_file, Some(payload.as_slice()), Some(&mut written), None)? };
    Ok(())
}

#[cfg(windows)]
fn read_now_messages(
    channel_file: &win_api_wrappers::raw::core::Owned<win_api_wrappers::raw::Win32::Foundation::HANDLE>,
    dissector: &mut NowMessageDissector,
    read_buffer: &mut [u8],
) -> anyhow::Result<Vec<NowMessage<'static>>> {
    let mut bytes_read = 0_u32;

    // SAFETY: `channel_file` is an owned valid handle and `read_buffer` is valid for writes.
    unsafe { ReadFile(**channel_file, Some(read_buffer), Some(&mut bytes_read), None)? };

    if bytes_read == 0 {
        bail!("DVC channel closed by peer");
    }

    let header_size = size_of::<CHANNEL_PDU_HEADER>();
    let bytes_read = usize::try_from(bytes_read).context("bytes read does not fit usize")?;

    if bytes_read < header_size {
        bail!("short DVC read: {} bytes", bytes_read);
    }

    dissector.dissect(&read_buffer[header_size..bytes_read])
}

#[cfg(windows)]
fn run_protocol_shim(
    config: &Config,
    scenario: Scenario,
    cycle: u32,
    channel: &win_api_wrappers::wts::WtsVirtualChannel,
    stop_requested: &AtomicBool,
) -> anyhow::Result<()> {
    if config.protocol_shim == ProtocolShim::None {
        if !sleep_with_stop(stop_requested, config.open_ms) {
            log_event(
                scenario,
                Some(cycle),
                "interrupted",
                "stop requested during open window",
            );
            bail!("interrupted by user");
        }
        return Ok(());
    }

    let channel_file = channel.query_file_handle().context("query DVC channel file handle")?;
    let start = Instant::now();
    let mut dissector = NowMessageDissector::default();
    let mut read_buffer = vec![0_u8; 128 * 1024];
    let handshake_deadline = start + Duration::from_secs(5);

    // Handshake-driven flow: first consume client capset, then answer with server capset.
    let mut handshake_done = false;
    while !handshake_done {
        if stop_requested.load(Ordering::Relaxed) {
            log_event(
                scenario,
                Some(cycle),
                "interrupted",
                "stop requested while waiting for client capset",
            );
            bail!("interrupted by user");
        }

        if Instant::now() >= handshake_deadline {
            bail!("timed out waiting for client capset");
        }

        let messages = match read_now_messages(&channel_file, &mut dissector, &mut read_buffer)
            .context("read handshake messages from DVC channel")
        {
            Ok(messages) => messages,
            Err(error) => {
                if let Some(kind) = classify_pipe_disconnect(&error) {
                    log_event(
                        scenario,
                        Some(cycle),
                        "shim-peer-closed",
                        format!("peer disconnected during handshake ({kind})"),
                    );
                    return Ok(());
                }
                return Err(error);
            }
        };

        for message in messages {
            match message {
                NowMessage::Channel(NowChannelMessage::Capset(_)) => {
                    let capset = default_server_caps();
                    let capset_msg: NowMessage<'_> = capset.into();
                    send_message(&channel_file, &capset_msg).context("send server capset")?;
                    log_event(
                        scenario,
                        Some(cycle),
                        "shim-capset-sent",
                        "received client capset and sent server capset",
                    );
                    handshake_done = true;
                    break;
                }
                other => {
                    log_event(
                        scenario,
                        Some(cycle),
                        "shim-handshake-skip",
                        format!("ignoring pre-capset message: {other:?}"),
                    );
                }
            }
        }
    }

    // Mimic the post-negotiation bootstrap used by Devolutions Session for RDM integration.
    let server_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("get current timestamp")?
        .as_secs();
    let capabilities = NowRdmCapabilitiesMsg::new(server_timestamp, "harness".to_owned())
        .context("create RDM capabilities message")?
        .with_app_available();
    let capabilities_msg: NowMessage<'_> = NowMessage::Rdm(NowRdmMessage::Capabilities(capabilities));
    send_message(&channel_file, &capabilities_msg).context("send RDM capabilities")?;
    log_event(
        scenario,
        Some(cycle),
        "shim-rdm-capabilities-sent",
        "sent RDM capabilities with app_available",
    );

    let app_notify = NowRdmAppNotifyMsg::new(NowRdmAppState::READY, NowRdmReason::NOT_SPECIFIED);
    let app_notify_msg: NowMessage<'_> = NowMessage::Rdm(NowRdmMessage::AppNotify(app_notify));
    send_message(&channel_file, &app_notify_msg).context("send RDM READY notify")?;
    log_event(scenario, Some(cycle), "shim-rdm-ready-sent", "sent RDM AppNotify READY");

    let heartbeat_interval = Duration::from_millis(config.heartbeat_ms);
    let mut next_heartbeat = Instant::now() + heartbeat_interval;

    while start.elapsed().as_millis() < u128::from(config.open_ms) {
        if stop_requested.load(Ordering::Relaxed) {
            log_event(scenario, Some(cycle), "interrupted", "stop requested during shim loop");
            bail!("interrupted by user");
        }

        let now = Instant::now();
        if now >= next_heartbeat {
            let heartbeat_msg: NowMessage<'_> = NowChannelHeartbeatMsg::default().into();
            if let Err(error) = send_message(&channel_file, &heartbeat_msg).context("send heartbeat") {
                if let Some(kind) = classify_pipe_disconnect(&error) {
                    log_event(
                        scenario,
                        Some(cycle),
                        "shim-peer-closed",
                        format!("peer disconnected during heartbeat ({kind})"),
                    );
                    return Ok(());
                }
                return Err(error);
            }
            log_event(scenario, Some(cycle), "shim-heartbeat-sent", "sent heartbeat");
            next_heartbeat = now + heartbeat_interval;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[cfg(windows)]
fn run_windows(config: &Config, stop_requested: &AtomicBool) -> anyhow::Result<()> {
    if config.delay_ms > 0 {
        log_event(
            config.scenario,
            None,
            "pre-delay-start",
            format!("sleeping {} ms before first open", config.delay_ms),
        );
        if !sleep_with_stop(stop_requested, config.delay_ms) {
            log_event(config.scenario, None, "interrupted", "stop requested during pre-delay");
            return Ok(());
        }
        log_event(config.scenario, None, "pre-delay-end", "pre-delay completed");
    }

    if config.wait_for_next_open {
        arm_for_next_open(config, config.scenario, stop_requested)?;
    }

    match config.scenario {
        Scenario::NoOpen => {
            log_event(
                config.scenario,
                Some(1),
                "no-open",
                format!("holding without DVC open for {} ms", config.open_ms),
            );
            if !sleep_with_stop(stop_requested, config.open_ms) {
                log_event(
                    config.scenario,
                    None,
                    "interrupted",
                    "stop requested during no-open hold",
                );
            }
            Ok(())
        }
        Scenario::OpenHold | Scenario::TimeoutWindow | Scenario::DelayedOpen => {
            run_cycles(config, config.scenario, config.cycles, config.open_ms, config.gap_ms, stop_requested)
        }
        Scenario::LoginChurn => {
            log_event(
                config.scenario,
                None,
                "phase-start",
                format!(
                    "login churn burst: cycles={} open_ms={} gap_ms={}",
                    config.login_churn_cycles, config.login_churn_open_ms, config.login_churn_gap_ms
                ),
            );
            run_cycles(
                config,
                config.scenario,
                config.login_churn_cycles,
                config.login_churn_open_ms,
                config.login_churn_gap_ms,
                stop_requested,
            )?;

            if stop_requested.load(Ordering::Relaxed) {
                log_event(config.scenario, None, "interrupted", "stop requested before settle phase");
                return Ok(());
            }

            log_event(
                config.scenario,
                None,
                "phase-start",
                format!("settle hold: open_ms={}", config.login_settle_open_ms),
            );
            run_cycles(config, config.scenario, 1, config.login_settle_open_ms, 0, stop_requested)
        }
        Scenario::TimingReplay => {
            log_event(
                config.scenario,
                None,
                "phase-start",
                format!("timing replay: cycles={}", config.replay_cycles.len()),
            );

            for (index, replay_cycle) in config.replay_cycles.iter().enumerate() {
                let replay_num = index + 1;
                log_event(
                    config.scenario,
                    None,
                    "replay-cycle-start",
                    format!(
                        "replay={} open_ms={} gap_ms={}",
                        replay_num, replay_cycle.open_ms, replay_cycle.gap_ms
                    ),
                );

                run_cycles(config, config.scenario, 1, replay_cycle.open_ms, 0, stop_requested)?;

                if replay_cycle.gap_ms > 0 {
                    log_event(
                        config.scenario,
                        None,
                        "replay-gap-start",
                        format!("replay={} sleeping {} ms", replay_num, replay_cycle.gap_ms),
                    );
                    if !sleep_with_stop(stop_requested, replay_cycle.gap_ms) {
                        log_event(config.scenario, None, "interrupted", "stop requested during replay gap");
                        return Ok(());
                    }
                    log_event(config.scenario, None, "replay-gap-end", format!("replay={} done", replay_num));
                }
            }

            if config.replay_settle_open_ms > 0 {
                log_event(
                    config.scenario,
                    None,
                    "phase-start",
                    format!("settle hold: open_ms={}", config.replay_settle_open_ms),
                );
                run_cycles(config, config.scenario, 1, config.replay_settle_open_ms, 0, stop_requested)?;
            }

            Ok(())
        }
    }
}

#[cfg(windows)]
fn run_cycles(
    config: &Config,
    scenario: Scenario,
    cycles: u32,
    open_ms: u64,
    gap_ms: u64,
    stop_requested: &AtomicBool,
) -> anyhow::Result<()> {
    for cycle in 1..=cycles {
        if stop_requested.load(Ordering::Relaxed) {
            log_event(scenario, Some(cycle), "interrupted", "stop requested before cycle");
            return Ok(());
        }

        let channel = match open_channel_with_retry(scenario, cycle, config, stop_requested) {
            Ok(channel) => channel,
            Err(_error) if stop_requested.load(Ordering::Relaxed) => {
                log_event(
                    scenario,
                    Some(cycle),
                    "interrupted",
                    "stop requested while opening channel",
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        log_event(
            scenario,
            Some(cycle),
            "open-window-start",
            format!("holding channel for {} ms", open_ms),
        );

        let mut phase_config = config.clone();
        phase_config.open_ms = open_ms;

        if let Err(error) = run_protocol_shim(&phase_config, scenario, cycle, &channel, stop_requested) {
            drop(channel);
            if stop_requested.load(Ordering::Relaxed) {
                log_event(scenario, Some(cycle), "interrupted", "stop requested in protocol shim");
                return Ok(());
            }
            return Err(error);
        }

        log_event(scenario, Some(cycle), "open-window-end", "closing channel");
        drop(channel);
        log_event(scenario, Some(cycle), "closed", "channel handle released");

        if cycle != cycles {
            log_event(
                scenario,
                Some(cycle),
                "gap-start",
                format!("sleeping {} ms before next cycle", gap_ms),
            );
            if !sleep_with_stop(stop_requested, gap_ms) {
                log_event(
                    scenario,
                    Some(cycle),
                    "interrupted",
                    "stop requested during inter-cycle gap",
                );
                return Ok(());
            }
            log_event(scenario, Some(cycle), "gap-end", "starting next cycle");
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn run_windows(_config: &Config, _stop_requested: &()) -> anyhow::Result<()> {
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
           login-churn     Run a login-like churn burst followed by a settle hold.\n\
          timing-replay   Replay exact open/gap timing cycles from customer logs.\n\
         \n\
         Options:\n\
           --channel-name <name>   DVC channel name (default: Devolutions::Now::Agent)\n\
           --protocol-shim <mode>  Protocol behavior: none|minimal (default: none)\n\
           --cycles <n>            Number of open/close cycles (default: 1)\n\
           --delay-ms <ms>         Delay before first open (default: 0)\n\
           --open-ms <ms>          Duration to hold each open channel (default: 5000)\n\
           --gap-ms <ms>           Delay between cycles (default: 500)\n\
           --wait-for-open-ms <ms> Retry open up to this duration per cycle (default: 0)\n\
           --retry-interval-ms <ms> Delay between open retries (default: 250)\n\
           --heartbeat-ms <ms>     Heartbeat interval in minimal shim mode (default: 3000)\n\
           --wait-for-next-open    Arm until a disconnect->reconnect open transition is observed\n\
           --login-churn-cycles <n> Churn phase cycles for login-churn (default: 10)\n\
           --login-churn-open-ms <ms> Open duration per churn cycle (default: 1200)\n\
           --login-churn-gap-ms <ms> Gap duration per churn cycle (default: 120)\n\
           --login-settle-open-ms <ms> Final settle hold duration (default: 900000)\n\
          --replay-cycles <spec>   Comma-separated open_ms:gap_ms (e.g. 5032:73210,7867:13328,7831:0)\n\
          --replay-settle-open-ms <ms> Final settle hold after replay (default: 900000, 0 disables)\n\
         \n\
         Examples:\n\
           dvc-session-harness timeout-window --cycles 6 --open-ms 5000 --gap-ms 200\n\
           dvc-session-harness timeout-window --cycles 200 --wait-for-open-ms 300000 --retry-interval-ms 250\n\
           dvc-session-harness timeout-window --protocol-shim minimal --wait-for-open-ms 300000 --wait-for-next-open\n\
           dvc-session-harness login-churn --protocol-shim minimal --wait-for-open-ms 300000\n\
           dvc-session-harness timing-replay --protocol-shim minimal --wait-for-open-ms 300000 --replay-cycles 5032:73210,7867:13328,7831:0 --replay-settle-open-ms 900000\n\
           dvc-session-harness delayed-open --delay-ms 12000 --open-ms 5000\n\
           dvc-session-harness no-open --open-ms 15000"
    );
}

fn main() -> anyhow::Result<()> {
    let config = Config::parse()?;

    #[cfg(windows)]
    let stop_requested = {
        let flag = Arc::new(AtomicBool::new(false));
        let cloned = Arc::clone(&flag);
        ctrlc::set_handler(move || {
            cloned.store(true, Ordering::Relaxed);
        })
        .context("failed to set Ctrl+C handler")?;
        flag
    };

    log_event(
        config.scenario,
        None,
        "start",
        format!(
            "channel={}, protocol_shim={}, cycles={}, delay_ms={}, open_ms={}, gap_ms={}, login_churn_cycles={}, login_churn_open_ms={}, login_churn_gap_ms={}, login_settle_open_ms={}, replay_cycles={}, replay_settle_open_ms={}",
            config.channel_name,
            config.protocol_shim.as_str(),
            config.cycles,
            config.delay_ms,
            config.open_ms,
            config.gap_ms,
            config.login_churn_cycles,
            config.login_churn_open_ms,
            config.login_churn_gap_ms,
            config.login_settle_open_ms,
            config.replay_cycles.len(),
            config.replay_settle_open_ms
        ),
    );
    log_event(
        config.scenario,
        None,
        "open-policy",
        format!(
            "wait_for_open_ms={}, retry_interval_ms={}, heartbeat_ms={}, wait_for_next_open={}",
            config.wait_for_open_ms, config.retry_interval_ms, config.heartbeat_ms, config.wait_for_next_open
        ),
    );

    #[cfg(windows)]
    let result = run_windows(&config, &stop_requested);
    #[cfg(not(windows))]
    let result = run_windows(&config, &());

    match &result {
        Ok(()) => log_event(config.scenario, None, "done", "scenario completed"),
        Err(error) => log_event(config.scenario, None, "failed", format!("{error:#}")),
    }

    result
}
