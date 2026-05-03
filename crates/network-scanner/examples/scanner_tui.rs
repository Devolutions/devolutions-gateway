#![allow(unused_crate_dependencies)]

//! Interactive TUI driver for the network scanner.
//!
//! Vim-flavoured navigation (`j`/`k`/`gg`/`G`, modal editing, `:` command
//! line) plus a zellij-style key-hint bar. Lets you toggle every scanner
//! parameter before launching a scan and watches results stream in,
//! grouped by host with services nested underneath.
//!
//! Run with `cargo run -p network-scanner --example scanner_tui`. Logs are
//! suppressed because tracing output would corrupt the alt screen — set
//! `SCANNER_TUI_LOG=path` to redirect logs to a file if you need them.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Stdout};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::{execute, terminal};
use futures::StreamExt as _;
use network_scanner::broadcast::BroadcastEvent;
use network_scanner::event_bus::{AnyScannerEvent, ScannerEvent};
use network_scanner::ip_utils::IpAddrRange;
use network_scanner::mdns::MdnsEvent;
use network_scanner::named_port::{MaybeNamedPort, NamedPort};
use network_scanner::netbios::NetBiosEvent;
use network_scanner::ping::PingEvent;
use network_scanner::planner::{InterfaceSelector, RangeInterfacePolicy, TargetSelector};
use network_scanner::port_discovery::TcpKnockEvent;
use network_scanner::scanner::{
    DnsEvent, LimitsConfig, NetworkScanner, NetworkScannerParams, NetworkScannerStream, ScannerConfig, ScannerToggles,
    TargetingConfig, TcpKnockWithHost, TimingConfig,
};
use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use tokio::sync::mpsc;

type Term = ratatui::Terminal<CrosstermBackend<Stdout>>;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let mut term = init_terminal()?;
    let result = run(&mut term).await;
    restore_terminal(&mut term)?;
    result
}

fn init_terminal() -> anyhow::Result<Term> {
    // If a panic strikes between enable_raw_mode and the normal restore in
    // `main`, the user is left with a wrecked terminal (alt screen on,
    // raw mode on, no cursor). Chain a hook before any of that happens
    // so the original handler still runs after we put things back.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen);
        prev_hook(info);
    }));

    terminal::enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen).context("enter alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let term = ratatui::Terminal::new(backend).context("create terminal")?;
    Ok(term)
}

fn restore_terminal(term: &mut Term) -> anyhow::Result<()> {
    terminal::disable_raw_mode().ok();
    execute!(term.backend_mut(), terminal::LeaveAlternateScreen).ok();
    term.show_cursor().ok();
    Ok(())
}

async fn run(term: &mut Term) -> anyhow::Result<()> {
    let mut app = App::new();
    let mut input = EventStream::new();
    // Forwarder tasks tag every event with the scan generation that produced
    // it. Stale events from a stopped scan can still land in the channel
    // briefly after `stop()` (the forwarder may have one in-flight `recv`),
    // so the run loop drops anything whose generation no longer matches the
    // current scan.
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<TaggedEvent>();
    let mut tick = tokio::time::interval(Duration::from_millis(120));

    loop {
        term.draw(|f| ui::draw(f, &mut app))?;
        if app.should_exit {
            break;
        }

        tokio::select! {
            biased;
            ev = input.next() => match ev {
                Some(Ok(Event::Key(k))) if k.kind == KeyEventKind::Press => {
                    app.handle_key(k, &event_tx).await;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            Some(TaggedEvent { scan_id, event }) = event_rx.recv() => {
                if scan_id == app.current_scan_id {
                    app.ingest(event);
                }
            }
            _ = tick.tick() => {}
        }
    }

    app.stop_scan();
    Ok(())
}

/// Scanner event paired with the generation id of the scan that produced it.
/// Used to drop residual events after a scan is stopped or restarted.
struct TaggedEvent {
    scan_id: u64,
    event: ScannerEvent,
}

// =============================================================================
// App state
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Settings,
    Results,
    Help,
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Settings => Tab::Results,
            Tab::Results => Tab::Help,
            Tab::Help => Tab::Settings,
        }
    }

    fn prev(self) -> Self {
        match self {
            Tab::Settings => Tab::Help,
            Tab::Results => Tab::Settings,
            Tab::Help => Tab::Results,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Settings => "Settings",
            Tab::Results => "Results",
            Tab::Help => "Help",
        }
    }
}

#[derive(Debug, Clone)]
enum Mode {
    /// Normal vim-mode: navigate, toggle, step.
    Normal,
    /// Direct edit on the currently-focused field.
    Insert { buffer: String, field: SettingField },
    /// `:` ex-style command line.
    Command { buffer: String },
}

struct App {
    tab: Tab,
    mode: Mode,
    settings: Settings,
    settings_cursor: usize,
    results: Results,
    results_cursor: usize,
    pending_g: bool,
    status: Option<(Instant, String, StatusKind)>,
    active_stream: Option<NetworkScannerStream>,
    /// Handle of the spawned `subscribe()` → `event_tx` forwarder. Aborted
    /// on scan stop so it can't keep injecting old-scan events into a new
    /// scan's results.
    forwarder_handle: Option<tokio::task::JoinHandle<()>>,
    /// Generation counter bumped on every `start_scan`. Stamped onto every
    /// event by the forwarder; the run loop drops events whose tag no
    /// longer matches.
    current_scan_id: u64,
    should_exit: bool,
    scan_start: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum StatusKind {
    Info,
    Error,
}

impl App {
    fn new() -> Self {
        Self {
            tab: Tab::Settings,
            mode: Mode::Normal,
            settings: Settings::default(),
            settings_cursor: 0,
            results: Results::default(),
            results_cursor: 0,
            pending_g: false,
            status: None,
            active_stream: None,
            forwarder_handle: None,
            current_scan_id: 0,
            should_exit: false,
            scan_start: None,
        }
    }

    fn flash(&mut self, msg: impl Into<String>, kind: StatusKind) {
        self.status = Some((Instant::now(), msg.into(), kind));
    }

    fn current_status(&self) -> Option<(&str, StatusKind)> {
        self.status.as_ref().and_then(|(at, msg, kind)| {
            if at.elapsed() < Duration::from_secs(4) {
                Some((msg.as_str(), *kind))
            } else {
                None
            }
        })
    }

    async fn handle_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<TaggedEvent>) {
        match self.mode.clone() {
            Mode::Insert { buffer, field } => self.handle_insert_key(key, buffer, field),
            Mode::Command { buffer } => self.handle_command_key(key, buffer, event_tx).await,
            Mode::Normal => self.handle_normal_key(key, event_tx).await,
        }
    }

    async fn handle_normal_key(&mut self, key: KeyEvent, event_tx: &mpsc::UnboundedSender<TaggedEvent>) {
        // Ctrl-c / Ctrl-q always quit.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            self.should_exit = true;
            return;
        }

        // Centralised pending-`g` reset: every keypress clears the latch by
        // default. Only the `g` arm below re-arms it. Without this, tab and
        // mode transitions used to leave the latch dangling and the next
        // `g` from a different context behaved as `gg`.
        let was_pending_g = std::mem::take(&mut self.pending_g);

        match key.code {
            KeyCode::Char(':') => self.mode = Mode::Command { buffer: String::new() },
            KeyCode::Char('?') => self.tab = Tab::Help,
            KeyCode::Tab => self.tab = self.tab.next(),
            KeyCode::BackTab => self.tab = self.tab.prev(),
            KeyCode::Char('1') => self.tab = Tab::Settings,
            KeyCode::Char('2') => self.tab = Tab::Results,
            KeyCode::Char('3') => self.tab = Tab::Help,
            KeyCode::Char('s') => self.start_scan(event_tx).await,
            KeyCode::Char('S') => self.stop_scan(),
            KeyCode::Char('r') => {
                self.stop_scan();
                self.clear_results();
                self.start_scan(event_tx).await;
            }
            KeyCode::Char('c') if matches!(self.tab, Tab::Results) => {
                self.clear_results();
                self.flash("Results cleared", StatusKind::Info);
            }
            KeyCode::Char('g') => {
                if was_pending_g {
                    self.cursor_top();
                } else {
                    self.pending_g = true;
                }
            }
            KeyCode::Char('G') => self.cursor_bottom(),
            KeyCode::Char('j') | KeyCode::Down => self.cursor_down(),
            KeyCode::Char('k') | KeyCode::Up => self.cursor_up(),
            KeyCode::Char('h') | KeyCode::Left => self.step_field(-1),
            KeyCode::Char('l') | KeyCode::Right => self.step_field(1),
            KeyCode::Char('H') => self.step_field(-10),
            KeyCode::Char('L') => self.step_field(10),
            KeyCode::Char(' ') | KeyCode::Enter if matches!(self.tab, Tab::Settings) => self.toggle_field(),
            KeyCode::Char(' ') | KeyCode::Enter if matches!(self.tab, Tab::Results) => {
                self.results.toggle_expand(self.results_cursor);
                self.clamp_results_cursor();
            }
            KeyCode::Char('i') if matches!(self.tab, Tab::Settings) => self.enter_insert_mode(),
            _ => {}
        }
    }

    fn handle_insert_key(&mut self, key: KeyEvent, mut buffer: String, field: SettingField) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                if matches!(key.code, KeyCode::Enter) {
                    if let Err(error) = self.settings.set_text(field, &buffer) {
                        self.flash(format!("Invalid value: {error}"), StatusKind::Error);
                        self.mode = Mode::Insert { buffer, field };
                        return;
                    }
                }
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::Insert { buffer, field };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.mode = Mode::Insert { buffer, field };
            }
            _ => {
                self.mode = Mode::Insert { buffer, field };
            }
        }
    }

    async fn handle_command_key(
        &mut self,
        key: KeyEvent,
        mut buffer: String,
        event_tx: &mpsc::UnboundedSender<TaggedEvent>,
    ) {
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                self.execute_command(&buffer, event_tx).await;
            }
            KeyCode::Backspace => {
                buffer.pop();
                self.mode = Mode::Command { buffer };
            }
            KeyCode::Char(c) => {
                buffer.push(c);
                self.mode = Mode::Command { buffer };
            }
            _ => self.mode = Mode::Command { buffer },
        }
    }

    async fn execute_command(&mut self, raw: &str, event_tx: &mpsc::UnboundedSender<TaggedEvent>) {
        match raw.trim() {
            "q" | "quit" | "exit" => self.should_exit = true,
            "start" => self.start_scan(event_tx).await,
            "stop" => self.stop_scan(),
            "clear" => {
                self.results = Results::default();
                self.results_cursor = 0;
                self.flash("Results cleared", StatusKind::Info);
            }
            "help" => self.tab = Tab::Help,
            "" => {}
            other => self.flash(format!("Unknown command: :{other}"), StatusKind::Error),
        }
    }

    fn enter_insert_mode(&mut self) {
        let field = SETTINGS_FIELDS[self.settings_cursor].0;
        if !field.kind().is_text() {
            self.flash("Field is not text-editable; use h/l or Space", StatusKind::Info);
            return;
        }
        let buffer = self.settings.render_value(field);
        self.mode = Mode::Insert { buffer, field };
    }

    fn cursor_top(&mut self) {
        match self.tab {
            Tab::Settings => self.settings_cursor = 0,
            Tab::Results => self.results_cursor = 0,
            Tab::Help => {}
        }
    }

    fn cursor_bottom(&mut self) {
        match self.tab {
            Tab::Settings => self.settings_cursor = SETTINGS_FIELDS.len().saturating_sub(1),
            Tab::Results => {
                let last = self.results.flatten().len().saturating_sub(1);
                self.results_cursor = last;
            }
            Tab::Help => {}
        }
    }

    fn cursor_down(&mut self) {
        match self.tab {
            Tab::Settings => {
                if self.settings_cursor + 1 < SETTINGS_FIELDS.len() {
                    self.settings_cursor += 1;
                }
            }
            Tab::Results => {
                let len = self.results.flatten().len();
                if len > 0 && self.results_cursor + 1 < len {
                    self.results_cursor += 1;
                }
            }
            Tab::Help => {}
        }
    }

    fn cursor_up(&mut self) {
        match self.tab {
            Tab::Settings => self.settings_cursor = self.settings_cursor.saturating_sub(1),
            Tab::Results => self.results_cursor = self.results_cursor.saturating_sub(1),
            Tab::Help => {}
        }
    }

    fn step_field(&mut self, delta: i64) {
        if !matches!(self.tab, Tab::Settings) {
            return;
        }
        let field = SETTINGS_FIELDS[self.settings_cursor].0;
        self.settings.step(field, delta);
    }

    fn toggle_field(&mut self) {
        let field = SETTINGS_FIELDS[self.settings_cursor].0;
        self.settings.toggle(field);
    }

    async fn start_scan(&mut self, event_tx: &mpsc::UnboundedSender<TaggedEvent>) {
        if self.active_stream.is_some() {
            self.flash("Scan already running — `S` to stop, `r` to restart", StatusKind::Info);
            return;
        }
        let params = match self.settings.build_params() {
            Ok(params) => params,
            Err(error) => {
                self.flash(format!("Invalid settings: {error}"), StatusKind::Error);
                return;
            }
        };
        let scanner = match NetworkScanner::new(params) {
            Ok(scanner) => scanner,
            Err(error) => {
                self.flash(format!("Scanner build failed: {error:#}"), StatusKind::Error);
                return;
            }
        };
        let stream = match scanner.start() {
            Ok(stream) => stream,
            Err(error) => {
                self.flash(format!("Scan start failed: {error:#}"), StatusKind::Error);
                return;
            }
        };
        let mut sub = stream.subscribe::<AnyScannerEvent>().await;

        self.current_scan_id = self.current_scan_id.wrapping_add(1);
        let scan_id = self.current_scan_id;
        let tx = event_tx.clone();
        let handle = tokio::spawn(async move {
            while let Ok(AnyScannerEvent(event)) = sub.recv().await {
                if tx.send(TaggedEvent { scan_id, event }).is_err() {
                    break;
                }
            }
        });
        self.active_stream = Some(stream);
        self.forwarder_handle = Some(handle);
        self.scan_start = Some(Instant::now());
        self.tab = Tab::Results;
        self.flash("Scan started", StatusKind::Info);
    }

    fn stop_scan(&mut self) {
        let stream = self.active_stream.take();
        // Abort the forwarder *first*: once it's gone, any stale events
        // already in the channel get dropped by the run-loop's scan_id
        // check, so we don't race with restart.
        if let Some(handle) = self.forwarder_handle.take() {
            handle.abort();
        }
        if let Some(stream) = stream {
            stream.stop();
            self.flash("Scan stopped", StatusKind::Info);
        } else {
            self.flash("No scan in progress", StatusKind::Info);
        }
    }

    fn clear_results(&mut self) {
        self.results = Results::default();
        self.results_cursor = 0;
    }

    /// Cap `results_cursor` to the current row count. Must be called any
    /// time the flattened results list shrinks: `c` clear, `r` restart,
    /// or `Space` collapsing a host whose service rows were below the
    /// cursor.
    fn clamp_results_cursor(&mut self) {
        let len = self.results.flatten().len();
        if len == 0 {
            self.results_cursor = 0;
        } else if self.results_cursor >= len {
            self.results_cursor = len - 1;
        }
    }

    fn ingest(&mut self, event: ScannerEvent) {
        self.results.ingest(event);
    }
}

// =============================================================================
// Settings model
// =============================================================================

#[derive(Debug, Clone)]
struct Settings {
    enable_broadcast: bool,
    enable_subnet_scan: bool,
    enable_zeroconf: bool,
    enable_resolve_dns: bool,
    interface_bind_strict: bool,
    ping_interval_ms: u64,
    ping_timeout_ms: u64,
    broadcast_timeout_ms: u64,
    port_scan_timeout_ms: u64,
    netbios_timeout_ms: u64,
    netbios_interval_ms: u64,
    mdns_query_timeout_ms: u64,
    max_wait_ms: u64,
    max_concurrency: Option<usize>,
    max_ping_concurrency: Option<usize>,
    max_tcp_probe_concurrency: Option<usize>,
    range_interface_policy: RangeInterfacePolicy,
    targets: String,
    ranges: String,
    interface_ids: String,
    ports: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable_broadcast: true,
            enable_subnet_scan: true,
            enable_zeroconf: true,
            enable_resolve_dns: true,
            interface_bind_strict: false,
            ping_interval_ms: 20,
            ping_timeout_ms: 1000,
            broadcast_timeout_ms: 2000,
            port_scan_timeout_ms: 2000,
            netbios_timeout_ms: 1000,
            netbios_interval_ms: 20,
            mdns_query_timeout_ms: 5_000,
            max_wait_ms: 10_000,
            max_concurrency: None,
            max_ping_concurrency: None,
            max_tcp_probe_concurrency: None,
            range_interface_policy: RangeInterfacePolicy::IntersectSelectedInterfaces,
            targets: String::new(),
            ranges: String::new(),
            interface_ids: String::new(),
            ports: "ssh,http,https,rdp,389,636".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingField {
    EnableBroadcast,
    EnableSubnetScan,
    EnableZeroconf,
    EnableResolveDns,
    InterfaceBindStrict,
    PingIntervalMs,
    PingTimeoutMs,
    BroadcastTimeoutMs,
    PortScanTimeoutMs,
    NetbiosTimeoutMs,
    NetbiosIntervalMs,
    MdnsQueryTimeoutMs,
    MaxWaitMs,
    MaxConcurrency,
    MaxPingConcurrency,
    MaxTcpProbeConcurrency,
    RangeInterfacePolicy,
    Targets,
    Ranges,
    InterfaceIds,
    Ports,
}

#[derive(Debug, Clone, Copy)]
enum FieldKind {
    Bool,
    U64,
    OptUsize,
    Choice,
    Text,
}

impl FieldKind {
    fn is_text(self) -> bool {
        matches!(self, FieldKind::Text | FieldKind::U64 | FieldKind::OptUsize)
    }

    fn hint(self) -> &'static str {
        match self {
            FieldKind::Bool => "Space toggle",
            FieldKind::U64 => "h/l ±1, H/L ±10, i edit",
            FieldKind::OptUsize => "h/l ±1, Space clear, i edit",
            FieldKind::Choice => "Space cycle",
            FieldKind::Text => "i edit",
        }
    }
}

impl SettingField {
    fn kind(self) -> FieldKind {
        match self {
            SettingField::EnableBroadcast
            | SettingField::EnableSubnetScan
            | SettingField::EnableZeroconf
            | SettingField::EnableResolveDns
            | SettingField::InterfaceBindStrict => FieldKind::Bool,
            SettingField::PingIntervalMs
            | SettingField::PingTimeoutMs
            | SettingField::BroadcastTimeoutMs
            | SettingField::PortScanTimeoutMs
            | SettingField::NetbiosTimeoutMs
            | SettingField::NetbiosIntervalMs
            | SettingField::MdnsQueryTimeoutMs
            | SettingField::MaxWaitMs => FieldKind::U64,
            SettingField::MaxConcurrency | SettingField::MaxPingConcurrency | SettingField::MaxTcpProbeConcurrency => {
                FieldKind::OptUsize
            }
            SettingField::RangeInterfacePolicy => FieldKind::Choice,
            SettingField::Targets | SettingField::Ranges | SettingField::InterfaceIds | SettingField::Ports => {
                FieldKind::Text
            }
        }
    }
}

const SETTINGS_FIELDS: &[(SettingField, &str)] = &[
    (SettingField::EnableBroadcast, "Toggle: enable_broadcast"),
    (SettingField::EnableSubnetScan, "Toggle: enable_subnet_scan"),
    (SettingField::EnableZeroconf, "Toggle: enable_zeroconf (mDNS)"),
    (SettingField::EnableResolveDns, "Toggle: enable_resolve_dns"),
    (SettingField::InterfaceBindStrict, "Targeting: interface_bind_strict"),
    (SettingField::PingIntervalMs, "Timing: ping_interval_ms"),
    (SettingField::PingTimeoutMs, "Timing: ping_timeout_ms"),
    (SettingField::BroadcastTimeoutMs, "Timing: broadcast_timeout_ms"),
    (SettingField::PortScanTimeoutMs, "Timing: port_scan_timeout_ms"),
    (SettingField::NetbiosTimeoutMs, "Timing: netbios_timeout_ms"),
    (SettingField::NetbiosIntervalMs, "Timing: netbios_interval_ms"),
    (SettingField::MdnsQueryTimeoutMs, "Timing: mdns_query_timeout_ms"),
    (SettingField::MaxWaitMs, "Timing: max_wait_ms"),
    (SettingField::MaxConcurrency, "Limits: max_concurrency"),
    (SettingField::MaxPingConcurrency, "Limits: max_ping_concurrency"),
    (SettingField::MaxTcpProbeConcurrency, "Limits: max_tcp_probe_concurrency"),
    (SettingField::RangeInterfacePolicy, "Targeting: range_interface_policy"),
    (SettingField::Targets, "Targeting: target=  (csv of IPs)"),
    (SettingField::Ranges, "Targeting: range=    (csv of A-B)"),
    (SettingField::InterfaceIds, "Targeting: interface_id= (csv)"),
    (SettingField::Ports, "Probes: ports (csv of u16/named)"),
];

impl Settings {
    fn render_value(&self, field: SettingField) -> String {
        match field {
            SettingField::EnableBroadcast => bool_str(self.enable_broadcast).to_owned(),
            SettingField::EnableSubnetScan => bool_str(self.enable_subnet_scan).to_owned(),
            SettingField::EnableZeroconf => bool_str(self.enable_zeroconf).to_owned(),
            SettingField::EnableResolveDns => bool_str(self.enable_resolve_dns).to_owned(),
            SettingField::InterfaceBindStrict => bool_str(self.interface_bind_strict).to_owned(),
            SettingField::PingIntervalMs => self.ping_interval_ms.to_string(),
            SettingField::PingTimeoutMs => self.ping_timeout_ms.to_string(),
            SettingField::BroadcastTimeoutMs => self.broadcast_timeout_ms.to_string(),
            SettingField::PortScanTimeoutMs => self.port_scan_timeout_ms.to_string(),
            SettingField::NetbiosTimeoutMs => self.netbios_timeout_ms.to_string(),
            SettingField::NetbiosIntervalMs => self.netbios_interval_ms.to_string(),
            SettingField::MdnsQueryTimeoutMs => self.mdns_query_timeout_ms.to_string(),
            SettingField::MaxWaitMs => self.max_wait_ms.to_string(),
            SettingField::MaxConcurrency => opt_usize_str(self.max_concurrency),
            SettingField::MaxPingConcurrency => opt_usize_str(self.max_ping_concurrency),
            SettingField::MaxTcpProbeConcurrency => opt_usize_str(self.max_tcp_probe_concurrency),
            SettingField::RangeInterfacePolicy => match self.range_interface_policy {
                RangeInterfacePolicy::IntersectSelectedInterfaces => "intersect_selected_interfaces".to_owned(),
                RangeInterfacePolicy::AllowCrossInterfaceRange => "allow_cross_interface_range".to_owned(),
            },
            SettingField::Targets => self.targets.clone(),
            SettingField::Ranges => self.ranges.clone(),
            SettingField::InterfaceIds => self.interface_ids.clone(),
            SettingField::Ports => self.ports.clone(),
        }
    }

    fn toggle(&mut self, field: SettingField) {
        match field {
            SettingField::EnableBroadcast => self.enable_broadcast = !self.enable_broadcast,
            SettingField::EnableSubnetScan => self.enable_subnet_scan = !self.enable_subnet_scan,
            SettingField::EnableZeroconf => self.enable_zeroconf = !self.enable_zeroconf,
            SettingField::EnableResolveDns => self.enable_resolve_dns = !self.enable_resolve_dns,
            SettingField::InterfaceBindStrict => self.interface_bind_strict = !self.interface_bind_strict,
            SettingField::RangeInterfacePolicy => {
                self.range_interface_policy = match self.range_interface_policy {
                    RangeInterfacePolicy::IntersectSelectedInterfaces => RangeInterfacePolicy::AllowCrossInterfaceRange,
                    RangeInterfacePolicy::AllowCrossInterfaceRange => RangeInterfacePolicy::IntersectSelectedInterfaces,
                };
            }
            SettingField::MaxConcurrency => self.max_concurrency = None,
            SettingField::MaxPingConcurrency => self.max_ping_concurrency = None,
            SettingField::MaxTcpProbeConcurrency => self.max_tcp_probe_concurrency = None,
            _ => {}
        }
    }

    fn step(&mut self, field: SettingField, delta: i64) {
        match field {
            SettingField::PingIntervalMs => self.ping_interval_ms = step_u64(self.ping_interval_ms, delta),
            SettingField::PingTimeoutMs => self.ping_timeout_ms = step_u64(self.ping_timeout_ms, delta),
            SettingField::BroadcastTimeoutMs => self.broadcast_timeout_ms = step_u64(self.broadcast_timeout_ms, delta),
            SettingField::PortScanTimeoutMs => self.port_scan_timeout_ms = step_u64(self.port_scan_timeout_ms, delta),
            SettingField::NetbiosTimeoutMs => self.netbios_timeout_ms = step_u64(self.netbios_timeout_ms, delta),
            SettingField::NetbiosIntervalMs => self.netbios_interval_ms = step_u64(self.netbios_interval_ms, delta),
            SettingField::MdnsQueryTimeoutMs => self.mdns_query_timeout_ms = step_u64(self.mdns_query_timeout_ms, delta),
            SettingField::MaxWaitMs => self.max_wait_ms = step_u64(self.max_wait_ms, delta),
            SettingField::MaxConcurrency => self.max_concurrency = step_opt_usize(self.max_concurrency, delta),
            SettingField::MaxPingConcurrency => {
                self.max_ping_concurrency = step_opt_usize(self.max_ping_concurrency, delta)
            }
            SettingField::MaxTcpProbeConcurrency => {
                self.max_tcp_probe_concurrency = step_opt_usize(self.max_tcp_probe_concurrency, delta)
            }
            SettingField::RangeInterfacePolicy => self.toggle(field),
            _ => {}
        }
    }

    fn set_text(&mut self, field: SettingField, raw: &str) -> anyhow::Result<()> {
        match field {
            SettingField::PingIntervalMs => self.ping_interval_ms = raw.trim().parse()?,
            SettingField::PingTimeoutMs => self.ping_timeout_ms = raw.trim().parse()?,
            SettingField::BroadcastTimeoutMs => self.broadcast_timeout_ms = raw.trim().parse()?,
            SettingField::PortScanTimeoutMs => self.port_scan_timeout_ms = raw.trim().parse()?,
            SettingField::NetbiosTimeoutMs => self.netbios_timeout_ms = raw.trim().parse()?,
            SettingField::NetbiosIntervalMs => self.netbios_interval_ms = raw.trim().parse()?,
            SettingField::MdnsQueryTimeoutMs => self.mdns_query_timeout_ms = raw.trim().parse()?,
            SettingField::MaxWaitMs => self.max_wait_ms = raw.trim().parse()?,
            SettingField::MaxConcurrency => self.max_concurrency = parse_opt_usize(raw)?,
            SettingField::MaxPingConcurrency => self.max_ping_concurrency = parse_opt_usize(raw)?,
            SettingField::MaxTcpProbeConcurrency => self.max_tcp_probe_concurrency = parse_opt_usize(raw)?,
            SettingField::Targets => self.targets = raw.to_owned(),
            SettingField::Ranges => self.ranges = raw.to_owned(),
            SettingField::InterfaceIds => self.interface_ids = raw.to_owned(),
            SettingField::Ports => self.ports = raw.to_owned(),
            _ => anyhow::bail!("field is not text-editable"),
        }
        Ok(())
    }

    fn build_params(&self) -> anyhow::Result<NetworkScannerParams> {
        let targets: Vec<IpAddr> = parse_csv(&self.targets)
            .map(|s| s.parse::<IpAddr>().context("parse target IP"))
            .collect::<anyhow::Result<_>>()?;
        let ranges: Vec<IpAddrRange> = parse_csv(&self.ranges)
            .map(IpAddrRange::try_from)
            .collect::<Result<_, _>>()?;
        let interface_ids: Vec<String> = parse_csv(&self.interface_ids).map(|s| s.to_owned()).collect();
        let ports: Vec<MaybeNamedPort> = parse_csv(&self.ports)
            .map(MaybeNamedPort::try_from)
            .collect::<Result<_, _>>()?;

        let target_selector = if !targets.is_empty() || !ranges.is_empty() {
            let mut all = ranges;
            all.extend(targets.into_iter().map(IpAddrRange::single));
            TargetSelector::ExplicitRanges(all)
        } else {
            TargetSelector::DefaultSubnets
        };
        target_selector.validate(network_scanner::planner::DEFAULT_MAX_TARGET_RANGE_ADDRESSES)?;

        let interface_selector = if interface_ids.is_empty() {
            InterfaceSelector::AllEligible
        } else {
            InterfaceSelector::Selected(interface_ids)
        };

        Ok(NetworkScannerParams {
            config: ScannerConfig {
                ports,
                timing: TimingConfig {
                    ping_interval: Duration::from_millis(self.ping_interval_ms),
                    ping_timeout: Duration::from_millis(self.ping_timeout_ms),
                    broadcast_timeout: Duration::from_millis(self.broadcast_timeout_ms),
                    port_scan_timeout: Duration::from_millis(self.port_scan_timeout_ms),
                    netbios_timeout: Duration::from_millis(self.netbios_timeout_ms),
                    netbios_interval: Duration::from_millis(self.netbios_interval_ms),
                    mdns_query_timeout: Duration::from_millis(self.mdns_query_timeout_ms),
                    max_wait_time: Duration::from_millis(self.max_wait_ms),
                },
                limits: LimitsConfig {
                    max_concurrency: self.max_concurrency,
                    max_ping_concurrency: self.max_ping_concurrency.or(self.max_concurrency),
                    max_tcp_probe_concurrency: self.max_tcp_probe_concurrency.or(self.max_concurrency),
                },
                targeting: TargetingConfig {
                    target_selector,
                    interface_selector,
                    range_interface_policy: self.range_interface_policy,
                    interface_bind_strict: self.interface_bind_strict,
                },
            },
            toggle: ScannerToggles {
                enable_broadcast: self.enable_broadcast,
                enable_subnet_scan: self.enable_subnet_scan,
                enable_zeroconf: self.enable_zeroconf,
                enable_resolve_dns: self.enable_resolve_dns,
            },
        })
    }
}

fn parse_csv(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_opt_usize(raw: &str) -> anyhow::Result<Option<usize>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        Ok(None)
    } else {
        Ok(Some(trimmed.parse()?))
    }
}

fn step_u64(value: u64, delta: i64) -> u64 {
    if delta >= 0 {
        value.saturating_add(delta as u64)
    } else {
        value.saturating_sub((-delta) as u64)
    }
}

/// Step a `(unbounded | bounded(usize))` field by `delta`.
///
/// * `h`/`H` (negative delta) on a bounded value floors at `1`, never
///   silently flipping the field to `unbounded`. Use `Space` for that —
///   conflating "minimum" with "unset" surprised early reviewers.
/// * `h` on an `unbounded` value is a no-op (no meaningful decrement).
/// * `l`/`L` on `unbounded` introduces a concrete bound starting at `delta`.
fn step_opt_usize(value: Option<usize>, delta: i64) -> Option<usize> {
    if delta == 0 {
        return value;
    }
    match value {
        Some(current) => {
            if delta > 0 {
                Some(current.saturating_add(delta as usize))
            } else {
                let dec = (-delta) as usize;
                Some(current.saturating_sub(dec).max(1))
            }
        }
        None => {
            if delta > 0 {
                Some(delta as usize)
            } else {
                None
            }
        }
    }
}

fn bool_str(v: bool) -> &'static str {
    if v { "true" } else { "false" }
}

fn opt_usize_str(v: Option<usize>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "(unbounded)".to_owned(),
    }
}

// =============================================================================
// Results aggregation
// =============================================================================

#[derive(Debug, Default)]
struct Results {
    hosts: BTreeMap<IpAddr, HostEntry>,
}

#[derive(Debug)]
struct HostEntry {
    ip: IpAddr,
    hostname: Option<String>,
    /// Merge policy: positive evidence wins. Any reachable signal (Ping
    /// success, broadcast reply, NetBIOS reply, mDNS resolve, TCP knock
    /// success) sets this to `Some(true)` unconditionally. Negative
    /// signals (Ping failure, TCP knock failure) only fill in the value
    /// if it's still `None` — they never downgrade an already-known-up
    /// host, so a host that answers ICMP and refuses port 22 still shows
    /// as up.
    is_reachable: Option<bool>,
    rtt_ms: Option<u128>,
    discovery_sources: BTreeSet<&'static str>,
    services: BTreeMap<u16, ServiceEntry>,
    expanded: bool,
}

impl HostEntry {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            is_reachable: None,
            rtt_ms: None,
            discovery_sources: BTreeSet::new(),
            services: BTreeMap::new(),
            expanded: true,
        }
    }
}

#[derive(Debug)]
struct ServiceEntry {
    port: u16,
    label: Option<String>,
    reachable: bool,
    rtt_ms: Option<u128>,
}

#[derive(Debug, Clone)]
enum ResultRow {
    Host { ip: IpAddr, expanded: bool },
    Service { ip: IpAddr, port: u16 },
}

impl Results {
    fn host_mut(&mut self, ip: IpAddr) -> &mut HostEntry {
        self.hosts.entry(ip).or_insert_with(|| HostEntry::new(ip))
    }

    fn ingest(&mut self, event: ScannerEvent) {
        match event {
            ScannerEvent::Ping(PingEvent::Queued { ip }) => {
                self.host_mut(ip).discovery_sources.insert("subnet");
            }
            ScannerEvent::Ping(PingEvent::Start { .. }) => {}
            ScannerEvent::Ping(PingEvent::Success { ip, time }) => {
                let host = self.host_mut(ip);
                host.is_reachable = Some(true);
                host.rtt_ms = Some(time);
                host.discovery_sources.insert("subnet");
            }
            ScannerEvent::Ping(PingEvent::Failed { ip, .. }) => {
                let host = self.host_mut(ip);
                if host.is_reachable.is_none() {
                    host.is_reachable = Some(false);
                }
            }
            ScannerEvent::Broadcast(BroadcastEvent::Entry { ip, time }) => {
                let host = self.host_mut(IpAddr::V4(ip));
                host.is_reachable = Some(true);
                host.rtt_ms = host.rtt_ms.or(time);
                host.discovery_sources.insert("broadcast");
            }
            ScannerEvent::Broadcast(BroadcastEvent::Start { .. }) => {}
            ScannerEvent::Dns(DnsEvent::Success { ip, hostname }) => {
                self.host_mut(ip).hostname.get_or_insert(hostname);
            }
            ScannerEvent::Dns(_) => {}
            ScannerEvent::NetBios(NetBiosEvent::Success { ip, name, time }) => {
                let host = self.host_mut(IpAddr::V4(ip));
                host.hostname.get_or_insert(name);
                host.rtt_ms = host.rtt_ms.or(time);
                host.discovery_sources.insert("netbios");
                host.is_reachable = Some(true);
            }
            ScannerEvent::NetBios(_) => {}
            ScannerEvent::Mdns(MdnsEvent::ServiceResolved {
                addr,
                device_name,
                protocol,
                port,
                time,
            }) => {
                let host = self.host_mut(addr);
                host.hostname.get_or_insert(device_name);
                host.discovery_sources.insert("mdns");
                host.is_reachable = Some(true);
                host.services.insert(
                    port,
                    ServiceEntry {
                        port,
                        label: protocol.map(|p| format!("{p:?}")),
                        reachable: true,
                        rtt_ms: time,
                    },
                );
            }
            ScannerEvent::Mdns(_) => {}
            ScannerEvent::TcpKnockWithHost(TcpKnockWithHost { tcp_knock, host: hn }) => match tcp_knock {
                TcpKnockEvent::Success { ip, port, time } => {
                    let host = self.host_mut(ip);
                    if let Some(name) = hn {
                        host.hostname.get_or_insert(name);
                    }
                    host.is_reachable = Some(true);
                    let raw = u16::from(&port);
                    host.services.insert(
                        raw,
                        ServiceEntry {
                            port: raw,
                            label: port_label(&port),
                            reachable: true,
                            rtt_ms: Some(time),
                        },
                    );
                }
                TcpKnockEvent::Failed { ip, port, .. } => {
                    let host = self.host_mut(ip);
                    let raw = u16::from(&port);
                    host.services.entry(raw).or_insert_with(|| ServiceEntry {
                        port: raw,
                        label: port_label(&port),
                        reachable: false,
                        rtt_ms: None,
                    });
                }
                TcpKnockEvent::Start { .. } => {}
            },
            ScannerEvent::TcpKnock(_) => {} // duplicate of TcpKnockWithHost; ignore.
        }
    }

    fn flatten(&self) -> Vec<ResultRow> {
        let mut rows = Vec::with_capacity(self.hosts.len());
        for host in self.hosts.values() {
            rows.push(ResultRow::Host {
                ip: host.ip,
                expanded: host.expanded,
            });
            if host.expanded {
                for port in host.services.keys() {
                    rows.push(ResultRow::Service { ip: host.ip, port: *port });
                }
            }
        }
        rows
    }

    fn toggle_expand(&mut self, cursor: usize) {
        if let Some(ResultRow::Host { ip, .. }) = self.flatten().get(cursor).cloned() {
            if let Some(host) = self.hosts.get_mut(&ip) {
                host.expanded = !host.expanded;
            }
        }
    }

    fn host_count(&self) -> usize {
        self.hosts.len()
    }

    fn service_count(&self) -> usize {
        self.hosts.values().map(|h| h.services.len()).sum()
    }
}

fn port_label(port: &MaybeNamedPort) -> Option<String> {
    let raw = u16::from(port);
    NamedPort::try_from(raw).ok().map(named_port_label).map(str::to_owned)
}

/// Stable display label for a [`NamedPort`]. Hand-written rather than going
/// through `Debug` so the TUI doesn't drift if a future refactor changes
/// the derive output.
fn named_port_label(port: NamedPort) -> &'static str {
    match port {
        NamedPort::Rdp => "RDP",
        NamedPort::Ard => "ARD",
        NamedPort::Vnc => "VNC",
        NamedPort::Ssh => "SSH",
        NamedPort::Sshpwsh => "SSH-PWSH",
        NamedPort::Sftp => "SFTP",
        NamedPort::Scp => "SCP",
        NamedPort::Telnet => "TELNET",
        NamedPort::WinrmHttpPwsh => "WinRM-HTTP",
        NamedPort::WinrmHttpsPwsh => "WinRM-HTTPS",
        NamedPort::Http => "HTTP",
        NamedPort::Https => "HTTPS",
        NamedPort::Ldap => "LDAP",
        NamedPort::Ldaps => "LDAPS",
    }
}

// =============================================================================
// UI rendering
// =============================================================================

mod ui {
    use super::*;

    pub(super) fn draw(f: &mut Frame<'_>, app: &mut App) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // tab bar
                Constraint::Min(0),    // body
                Constraint::Length(2), // status / hint
                Constraint::Length(1), // mode line
            ])
            .split(f.area());

        draw_tabs(f, layout[0], app);
        match app.tab {
            Tab::Settings => draw_settings(f, layout[1], app),
            Tab::Results => draw_results(f, layout[1], app),
            Tab::Help => draw_help(f, layout[1]),
        }
        draw_status(f, layout[2], app);
        draw_modeline(f, layout[3], app);
    }

    fn draw_tabs(f: &mut Frame<'_>, area: Rect, app: &App) {
        let titles: Vec<Line<'_>> = [Tab::Settings, Tab::Results, Tab::Help]
            .into_iter()
            .enumerate()
            .map(|(idx, tab)| {
                Line::from(vec![
                    Span::styled(format!(" {} ", idx + 1), Style::default().fg(Color::DarkGray)),
                    Span::raw(tab.title()),
                ])
            })
            .collect();
        let scan_label = if app.active_stream.is_some() {
            let elapsed = app.scan_start.map(|t| t.elapsed().as_secs()).unwrap_or(0);
            format!(" [scanning {elapsed}s] ")
        } else {
            " [idle] ".to_owned()
        };
        let scan_color = if app.active_stream.is_some() {
            Color::LightGreen
        } else {
            Color::DarkGray
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(vec![
                Span::raw(" network-scanner "),
                Span::styled(scan_label, Style::default().fg(scan_color)),
            ]));
        let tabs = Tabs::new(titles)
            .block(block)
            .select(match app.tab {
                Tab::Settings => 0,
                Tab::Results => 1,
                Tab::Help => 2,
            })
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        f.render_widget(tabs, area);
    }

    fn draw_settings(f: &mut Frame<'_>, area: Rect, app: &mut App) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        let items: Vec<ListItem<'_>> = SETTINGS_FIELDS
            .iter()
            .map(|(field, label)| {
                let value = app.settings.render_value(*field);
                let line = Line::from(vec![
                    Span::styled(format!("{label:<40} "), Style::default().fg(Color::Gray)),
                    Span::styled(value, Style::default().fg(Color::Cyan)),
                ]);
                ListItem::new(line)
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(app.settings_cursor));
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" parameters (j/k navigate) "),
            )
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol("▌ ");
        f.render_stateful_widget(list, cols[0], &mut state);

        // Right pane: focused field detail.
        let field = SETTINGS_FIELDS[app.settings_cursor].0;
        let kind = field.kind();
        let detail = vec![
            Line::from(Span::styled(
                SETTINGS_FIELDS[app.settings_cursor].1,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("type: {:?}", kind)),
            Line::from(format!("hint: {}", kind.hint())),
            Line::from(""),
            Line::from(Span::styled("current value:", Style::default().fg(Color::Gray))),
            Line::from(Span::styled(
                app.settings.render_value(field),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(field_help_text(field)),
        ];
        let para = Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" focused field "))
            .wrap(Wrap { trim: false });
        f.render_widget(para, cols[1]);
    }

    fn field_help_text(field: SettingField) -> Line<'static> {
        let txt = match field {
            SettingField::EnableBroadcast => "ScannerToggles.enable_broadcast",
            SettingField::EnableSubnetScan => "ScannerToggles.enable_subnet_scan",
            SettingField::EnableZeroconf => "ScannerToggles.enable_zeroconf",
            SettingField::EnableResolveDns => "ScannerToggles.enable_resolve_dns",
            SettingField::InterfaceBindStrict => "TargetingConfig.interface_bind_strict",
            SettingField::PingIntervalMs => "TimingConfig.ping_interval",
            SettingField::PingTimeoutMs => "TimingConfig.ping_timeout",
            SettingField::BroadcastTimeoutMs => "TimingConfig.broadcast_timeout",
            SettingField::PortScanTimeoutMs => "TimingConfig.port_scan_timeout",
            SettingField::NetbiosTimeoutMs => "TimingConfig.netbios_timeout",
            SettingField::NetbiosIntervalMs => "TimingConfig.netbios_interval",
            SettingField::MdnsQueryTimeoutMs => "TimingConfig.mdns_query_timeout",
            SettingField::MaxWaitMs => "TimingConfig.max_wait_time (whole-scan budget)",
            SettingField::MaxConcurrency => "LimitsConfig.max_concurrency",
            SettingField::MaxPingConcurrency => "LimitsConfig.max_ping_concurrency",
            SettingField::MaxTcpProbeConcurrency => "LimitsConfig.max_tcp_probe_concurrency",
            SettingField::RangeInterfacePolicy => "TargetingConfig.range_interface_policy",
            SettingField::Targets => "TargetSelector::ExplicitRanges (single addresses, CSV)",
            SettingField::Ranges => "TargetSelector::ExplicitRanges (A-B form, CSV)",
            SettingField::InterfaceIds => "InterfaceSelector::Selected (CSV of interface IDs)",
            SettingField::Ports => "ScannerConfig.ports — CSV of u16 or named (rdp/ssh/http/https/...)",
        };
        Line::from(Span::styled(txt, Style::default().fg(Color::DarkGray)))
    }

    fn draw_results(f: &mut Frame<'_>, area: Rect, app: &mut App) {
        let rows = app.results.flatten();
        let items: Vec<ListItem<'_>> = rows
            .iter()
            .map(|row| match row {
                ResultRow::Host { ip, expanded } => {
                    let host = app.results.hosts.get(ip).expect("flatten emits known host");
                    host_line(host, *expanded)
                }
                ResultRow::Service { ip, port } => {
                    let svc = app
                        .results
                        .hosts
                        .get(ip)
                        .and_then(|h| h.services.get(port))
                        .expect("flatten emits known service");
                    service_line(svc)
                }
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(app.results_cursor.min(items.len().saturating_sub(1))));
        let title = format!(
            " hosts: {}   services: {}   (Space expand · c clear) ",
            app.results.host_count(),
            app.results.service_count()
        );
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            .highlight_symbol("▌ ");
        f.render_stateful_widget(list, area, &mut state);
    }

    fn host_line(host: &HostEntry, expanded: bool) -> ListItem<'static> {
        let arrow = if expanded { "▼" } else { "▶" };
        let reachability = match host.is_reachable {
            Some(true) => Span::styled(" up   ", Style::default().fg(Color::Green)),
            Some(false) => Span::styled(" down ", Style::default().fg(Color::Red)),
            None => Span::styled(" ?    ", Style::default().fg(Color::DarkGray)),
        };
        let rtt = match host.rtt_ms {
            Some(t) => format!("{t:>4}ms"),
            None => "  --  ".to_owned(),
        };
        let host_name = host.hostname.as_deref().unwrap_or("");
        let sources: Vec<String> = host.discovery_sources.iter().map(|s| (*s).to_owned()).collect();
        let sources_str = sources.join(",");
        let line = Line::from(vec![
            Span::raw(format!("{arrow} ")),
            Span::styled(format!("{:<22}", host.ip), Style::default().fg(Color::Cyan)),
            reachability,
            Span::styled(format!("{rtt:<8}"), Style::default().fg(Color::Gray)),
            Span::styled(format!("{host_name:<22}"), Style::default().fg(Color::White)),
            Span::styled(format!("[{sources_str}]"), Style::default().fg(Color::DarkGray)),
        ]);
        ListItem::new(line)
    }

    fn service_line(svc: &ServiceEntry) -> ListItem<'static> {
        let status = if svc.reachable {
            Span::styled(" open  ", Style::default().fg(Color::Green))
        } else {
            Span::styled(" closed", Style::default().fg(Color::Red))
        };
        let label = svc.label.clone().unwrap_or_default();
        let rtt = match svc.rtt_ms {
            Some(t) => format!("{t:>4}ms"),
            None => "  --  ".to_owned(),
        };
        let line = Line::from(vec![
            Span::raw("    └─ "),
            Span::styled(format!("{:<6}", svc.port), Style::default().fg(Color::Yellow)),
            status,
            Span::styled(format!(" {rtt:<8}"), Style::default().fg(Color::Gray)),
            Span::styled(label, Style::default().fg(Color::Magenta)),
        ]);
        ListItem::new(line)
    }

    fn draw_help(f: &mut Frame<'_>, area: Rect) {
        let text = vec![
            Line::from(Span::styled(
                " network-scanner TUI — vim-flavoured controls",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(" tabs:"),
            Line::from("   1/2/3            jump to Settings/Results/Help"),
            Line::from("   Tab / Shift-Tab  cycle tabs"),
            Line::from(""),
            Line::from(" navigation (normal mode):"),
            Line::from("   j / k            cursor down / up"),
            Line::from("   gg / G           top / bottom"),
            Line::from("   h / l            decrement / increment numeric ±1"),
            Line::from("   H / L            decrement / increment numeric ±10"),
            Line::from("   Space            toggle bool / cycle choice / expand host"),
            Line::from("   i                edit text (Settings only)"),
            Line::from("   Enter            same as Space (Settings) / expand (Results)"),
            Line::from(""),
            Line::from(" scan control:"),
            Line::from("   s                start scan"),
            Line::from("   S                stop scan"),
            Line::from("   r                restart scan (clears results)"),
            Line::from("   c                clear results (Results tab)"),
            Line::from(""),
            Line::from(" insert mode:"),
            Line::from("   typing           edit field"),
            Line::from("   Backspace        delete char"),
            Line::from("   Enter            commit"),
            Line::from("   Esc              cancel"),
            Line::from(""),
            Line::from(" command line (`:`):"),
            Line::from("   :q :quit :exit   leave"),
            Line::from("   :start :stop     scan control"),
            Line::from("   :clear :help     misc"),
            Line::from(""),
            Line::from(" misc:"),
            Line::from("   ?                show this help"),
            Line::from("   Ctrl-c / Ctrl-q  hard quit"),
        ];
        let para = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" help "))
            .wrap(Wrap { trim: false });
        f.render_widget(para, area);
    }

    fn draw_status(f: &mut Frame<'_>, area: Rect, app: &App) {
        let hint = match (&app.tab, &app.mode) {
            (_, Mode::Insert { .. }) => "INSERT — Enter commit · Esc cancel · Backspace delete",
            (_, Mode::Command { .. }) => "COMMAND — Enter run · Esc cancel",
            (Tab::Settings, _) => {
                "j/k nav · h/l ±1 · H/L ±10 · Space toggle · i edit · s start · S stop · r restart · :q quit"
            }
            (Tab::Results, _) => {
                "j/k nav · gg/G top/bottom · Space expand · c clear · S stop · r restart · :q quit"
            }
            (Tab::Help, _) => "1/2/3 switch tab · :q quit",
        };
        let line = if let Some((msg, kind)) = app.current_status() {
            let color = match kind {
                StatusKind::Info => Color::LightGreen,
                StatusKind::Error => Color::LightRed,
            };
            Line::from(vec![
                Span::styled(format!(" {msg} "), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {hint}"), Style::default().fg(Color::DarkGray)),
            ])
        } else {
            Line::from(Span::styled(format!(" {hint}"), Style::default().fg(Color::DarkGray)))
        };
        let para = Paragraph::new(line);
        f.render_widget(para, area);
    }

    fn draw_modeline(f: &mut Frame<'_>, area: Rect, app: &App) {
        let (mode_label, mode_color, suffix) = match &app.mode {
            Mode::Normal => ("NORMAL", Color::LightBlue, String::new()),
            Mode::Insert { buffer, field } => {
                let label = SETTINGS_FIELDS.iter().find(|(f, _)| *f == *field).map(|(_, l)| *l).unwrap_or("?");
                ("INSERT", Color::LightYellow, format!(" {label} = {buffer}_"))
            }
            Mode::Command { buffer } => ("COMMAND", Color::LightMagenta, format!(" :{buffer}_")),
        };
        let pending = if app.pending_g { " g" } else { "" };
        let line = Line::from(vec![
            Span::styled(
                format!(" {mode_label} "),
                Style::default().bg(mode_color).fg(Color::Black).add_modifier(Modifier::BOLD),
            ),
            Span::styled(suffix, Style::default().fg(Color::White)),
            Span::styled(pending, Style::default().fg(Color::DarkGray)),
        ]);
        let para = Paragraph::new(line);
        f.render_widget(para, area);
    }
}
