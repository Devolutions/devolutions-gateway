use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
use camino::{Utf8Path, Utf8PathBuf};
use devolutions_agent_shared::{default_schedule_window_start, get_data_dir};
use serde::{Deserialize, Serialize};
use tap::prelude::*;
use url::Url;

const DEFAULT_RDP_PORT: u16 = 3389;

#[derive(Debug, Clone)]
pub struct Conf {
    pub log_file: Utf8PathBuf,
    pub verbosity_profile: dto::VerbosityProfile,
    pub updater: dto::UpdaterConf,
    pub remote_desktop: RemoteDesktopConf,
    pub pedm: dto::PedmConf,
    pub session: dto::SessionConf,
    pub tunnel: dto::TunnelConf,
    pub proxy: dto::ProxyConf,
    pub debug: dto::DebugConf,
}

impl Conf {
    pub fn from_conf_file(conf_file: &dto::ConfFile) -> anyhow::Result<Self> {
        let data_dir = get_data_dir();

        let log_file = conf_file
            .log_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("agent"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let remote_desktop = conf_file
            .remote_desktop
            .clone()
            .unwrap_or_default()
            .pipe(RemoteDesktopConf::try_from)
            .context("invalid remote desktop config")?;

        Ok(Conf {
            log_file,
            verbosity_profile: conf_file.verbosity_profile.unwrap_or_default(),
            updater: conf_file.updater.clone().unwrap_or_default(),
            remote_desktop,
            pedm: conf_file.pedm.clone().unwrap_or_default(),
            session: conf_file.session.clone().unwrap_or_default(),
            tunnel: conf_file.tunnel.clone().unwrap_or_default(),
            proxy: conf_file.proxy.clone().unwrap_or_default(),
            debug: conf_file.debug.clone().unwrap_or_default(),
        })
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct RemoteDesktopConf {
    pub enabled: bool,
    pub bind_addresses: Vec<SocketAddr>,
    pub certificate: Option<Utf8PathBuf>,
    pub private_key: Option<Utf8PathBuf>,
}

impl TryFrom<dto::RemoteDesktopConf> for RemoteDesktopConf {
    type Error = anyhow::Error;

    fn try_from(conf: dto::RemoteDesktopConf) -> anyhow::Result<Self> {
        use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
        use std::str::FromStr as _;

        let data_dir = get_data_dir();

        let enabled = conf.enabled;

        let default_port = conf.port.unwrap_or(DEFAULT_RDP_PORT);

        let bind_addresses = if conf.listeners.is_empty() {
            vec![
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), default_port),
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), default_port),
            ]
        } else {
            let addresses: Result<Vec<SocketAddr>, AddrParseError> = conf
                .listeners
                .iter()
                .map(|address| {
                    SocketAddr::from_str(address)
                        .or_else(|_| IpAddr::from_str(address).map(|ip| SocketAddr::new(ip, default_port)))
                })
                .collect();
            addresses.context("failed to parse listener address")?
        };

        let certificate = conf.certificate.map(|path| normalize_data_path(&path, &data_dir));

        let private_key = conf.private_key.map(|path| normalize_data_path(&path, &data_dir));

        Ok(Self {
            enabled,
            bind_addresses,
            certificate,
            private_key,
        })
    }
}

/// Configuration Handle, source of truth for current configuration state
#[derive(Clone)]
pub struct ConfHandle {
    inner: Arc<ConfHandleInner>,
}

struct ConfHandleInner {
    conf: parking_lot::RwLock<Arc<Conf>>,
    conf_file: parking_lot::RwLock<Arc<dto::ConfFile>>,
}

impl ConfHandle {
    /// Initializes configuration for this instance.
    ///
    /// It's best to call this only once to avoid inconsistencies.
    pub fn init() -> anyhow::Result<Self> {
        let conf_file = load_conf_file_or_generate_new()?;
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration file")?;

        Ok(Self {
            inner: Arc::new(ConfHandleInner {
                conf: parking_lot::RwLock::new(Arc::new(conf)),
                conf_file: parking_lot::RwLock::new(Arc::new(conf_file)),
            }),
        })
    }

    /// Returns current configuration state (do not hold it forever as it may become outdated)
    pub fn get_conf(&self) -> Arc<Conf> {
        self.inner.conf.read().clone()
    }

    /// Returns current configuration file state (do not hold it forever as it may become outdated)
    pub fn get_conf_file(&self) -> Arc<dto::ConfFile> {
        self.inner.conf_file.read().clone()
    }

    /// Persists a new auto-update schedule to `agent.json` and updates the in-memory state.
    pub fn save_updater_schedule(&self, schedule: &dto::UpdaterSchedule) -> anyhow::Result<()> {
        let mut conf_file = (*self.inner.conf_file.read()).as_ref().clone();
        conf_file.updater.get_or_insert_with(dto::UpdaterConf::default).schedule = Some(schedule.clone());
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration")?;
        save_config(&conf_file).context("failed to save configuration")?;
        *self.inner.conf.write() = Arc::new(conf);
        *self.inner.conf_file.write() = Arc::new(conf_file);
        Ok(())
    }
}

pub fn save_config(conf: &dto::ConfFile) -> anyhow::Result<()> {
    let conf_file_path = get_conf_file_path();
    let json = serde_json::to_string_pretty(conf).context("failed JSON serialization of configuration")?;
    std::fs::write(&conf_file_path, json).with_context(|| format!("failed to write file at {conf_file_path}"))?;
    Ok(())
}

pub fn get_conf_file_path() -> Utf8PathBuf {
    get_data_dir().join("agent.json")
}

fn normalize_data_path(path: &Utf8Path, data_dir: &Utf8Path) -> Utf8PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        data_dir.join(path)
    }
}

fn load_conf_file(conf_path: &Utf8Path) -> anyhow::Result<Option<dto::ConfFile>> {
    match File::open(conf_path) {
        Ok(file) => BufReader::new(file)
            .pipe(serde_json::from_reader)
            .map(Some)
            .with_context(|| format!("invalid config file at {conf_path}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("couldn't open config file at {conf_path}"))),
    }
}

#[allow(clippy::print_stdout)] // Logger is likely not yet initialized at this point, so it’s fine to write to stdout.
pub fn load_conf_file_or_generate_new() -> anyhow::Result<dto::ConfFile> {
    let conf_file_path = get_conf_file_path();

    let conf_file = match load_conf_file(&conf_file_path).context("failed to load configuration")? {
        Some(conf_file) => conf_file,
        None => {
            let defaults = dto::ConfFile::generate_new();
            println!("Write default configuration to {conf_file_path}…");
            save_config(&defaults).context("failed to save configuration")?;
            defaults
        }
    };

    Ok(conf_file)
}

pub mod dto {
    use devolutions_agent_shared::UpdateProductKey;

    use super::*;

    /// Mirrors [`devolutions_agent_shared::UpdateSchedule`]
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct UpdaterSchedule {
        /// Enable periodic Devolutions Agent self-update checks.
        pub enabled: bool,

        /// Minimum interval between update checks, in seconds.
        ///
        /// 0 value has a special meaning of "only check once at `update_window_start`.
        #[serde(default)]
        pub interval: u64,

        /// Start of the maintenance window as seconds past midnight, local time.
        #[serde(default = "default_schedule_window_start")]
        pub update_window_start: u32,

        /// End of the maintenance window as seconds past midnight, local time, exclusive.
        ///
        /// `None` means no upper bound (only single update check at update_window_start).
        /// When end < start the window crosses midnight.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub update_window_end: Option<u32>,

        /// Products for which the agent autonomously polls for new versions.
        #[serde(default)]
        pub products: Vec<UpdateProductKey>,
    }

    impl From<devolutions_agent_shared::UpdateSchedule> for UpdaterSchedule {
        fn from(s: devolutions_agent_shared::UpdateSchedule) -> Self {
            Self {
                enabled: s.enabled,
                interval: s.interval,
                update_window_start: s.update_window_start,
                update_window_end: s.update_window_end,
                products: s.products,
            }
        }
    }

    impl From<UpdaterSchedule> for devolutions_agent_shared::UpdateSchedule {
        fn from(s: UpdaterSchedule) -> Self {
            Self {
                enabled: s.enabled,
                interval: s.interval,
                update_window_start: s.update_window_start,
                update_window_end: s.update_window_end,
                products: s.products,
            }
        }
    }

    // ── UpdaterConf ──────────────────────────────────────────────────────────

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UpdaterConf {
        /// Enable updater module.
        pub enabled: bool,
        /// Periodic Devolutions Agent self-update schedule.
        ///
        /// When present and `Enabled` is `true`, the agent automatically checks for a new
        /// version of itself at the configured interval and triggers a silent MSI update
        /// during the configured maintenance window.
        ///
        /// This setting can be managed remotely via the Devolutions Gateway API
        /// (`GET`/`POST /jet/update/schedule`) or set directly in this file.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schedule: Option<UpdaterSchedule>,
    }

    #[allow(clippy::derivable_impls)] // Just to be explicit about the default values of the config.
    impl Default for UpdaterConf {
        fn default() -> Self {
            Self {
                enabled: false,
                schedule: None,
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RemoteDesktopConf {
        /// Enable remote desktop module
        pub enabled: bool,
        /// Port number that the service listens on
        ///
        /// Specifies the port number that the RDP service listens on.
        /// The default is 3389.
        pub port: Option<u16>,
        /// Binding addresses for the listeners
        ///
        /// Specifies the local addresses the RDP service should listen on.
        /// The format of a binding address is `<IPv4_addr|IPv6_addr>[:<port>]`.
        /// If `<port>` is not specified, the service will listen on the address and the port specified by the `Port` option.
        /// The default is to listen on all local addresses (the wildcard bind IPv4 address `0.0.0.0` and the wildcard bind IPv6 address `[::]`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub listeners: Vec<String>,
        /// Certificate to use for TLS
        #[serde(skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Utf8PathBuf>,
        /// Private key to use for TLS
        #[serde(skip_serializing_if = "Option::is_none")]
        pub private_key: Option<Utf8PathBuf>,
    }

    impl Default for RemoteDesktopConf {
        fn default() -> Self {
            Self {
                enabled: false,
                port: Some(DEFAULT_RDP_PORT),
                listeners: Vec::new(),
                certificate: None,
                private_key: None,
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct PedmConf {
        /// Enable PEDM module (disabled by default)
        pub enabled: bool,
    }

    #[allow(clippy::derivable_impls)]
    impl Default for PedmConf {
        fn default() -> Self {
            Self { enabled: false }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SessionConf {
        /// Enable Devolutions Session module (disabled by default)
        pub enabled: bool,
    }

    #[allow(clippy::derivable_impls)] // Just to be explicit about the default values of the config.
    impl Default for SessionConf {
        fn default() -> Self {
            Self { enabled: false }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TunnelConf {
        /// Enable tunnel module
        pub enabled: bool,

        /// Gateway QUIC endpoint (e.g., "gateway.example.com:4433")
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub gateway_endpoint: String,

        /// Client certificate path (issued during enrollment)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub client_cert_path: Option<Utf8PathBuf>,

        /// Client private key path
        #[serde(skip_serializing_if = "Option::is_none")]
        pub client_key_path: Option<Utf8PathBuf>,

        /// Gateway CA certificate path
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gateway_ca_cert_path: Option<Utf8PathBuf>,

        /// Subnets to advertise (e.g., ["10.0.0.0/8", "192.168.1.0/24"])
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub advertise_subnets: Vec<String>,

        /// DNS domains to advertise (e.g., ["contoso.local"]). Auto-detected if omitted.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub advertise_domains: Vec<String>,

        /// Whether to auto-detect the machine's DNS domain and add it to advertise_domains (default: true)
        #[serde(default = "default_true")]
        pub auto_detect_domain: bool,

        /// Heartbeat interval in seconds (default: 60)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub heartbeat_interval_secs: Option<u64>,

        /// Route advertise interval in seconds (default: 30)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub route_advertise_interval_secs: Option<u64>,
    }

    fn default_true() -> bool {
        true
    }

    impl Default for TunnelConf {
        fn default() -> Self {
            Self {
                enabled: false,
                gateway_endpoint: String::new(),
                client_cert_path: None,
                client_key_path: None,
                gateway_ca_cert_path: None,
                advertise_subnets: Vec::new(),
                advertise_domains: Vec::new(),
                auto_detect_domain: true,
                heartbeat_interval_secs: Some(60),
                route_advertise_interval_secs: Some(30),
            }
        }
    }

    /// Source of truth for Agent configuration
    ///
    /// This struct represents the JSON file used for configuration as close as possible
    /// and is not trying to be too smart.
    ///
    /// Unstable options are subject to change
    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfFile {
        /// Verbosity profile
        #[serde(skip_serializing_if = "Option::is_none")]
        pub verbosity_profile: Option<VerbosityProfile>,

        /// (Unstable) Folder and prefix for log files
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_file: Option<Utf8PathBuf>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub updater: Option<UpdaterConf>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub remote_desktop: Option<RemoteDesktopConf>,

        /// Devolutions PEDM configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pedm: Option<PedmConf>,

        /// Devolutions Session configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub session: Option<SessionConf>,

        /// Agent Tunnel configuration
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tunnel: Option<TunnelConf>,

        /// HTTP/SOCKS proxy configuration for outbound requests
        #[serde(skip_serializing_if = "Option::is_none")]
        pub proxy: Option<ProxyConf>,

        /// (Unstable) Unsafe debug options for developers
        #[serde(rename = "__debug__", skip_serializing_if = "Option::is_none")]
        pub debug: Option<DebugConf>,

        /// Other unofficial options.
        /// This field is useful so that we can deserialize
        /// and then losslessly serialize back all root keys of the config file.
        #[serde(flatten)]
        pub rest: serde_json::Map<String, serde_json::Value>,
    }

    impl ConfFile {
        pub fn generate_new() -> Self {
            Self {
                verbosity_profile: None,
                log_file: None,
                updater: Some(UpdaterConf {
                    enabled: true,
                    schedule: None,
                }),
                remote_desktop: None,
                pedm: None,
                proxy: None,
                debug: None,
                session: Some(SessionConf { enabled: false }),
                tunnel: None,
                rest: serde_json::Map::new(),
            }
        }
    }

    /// Verbosity profile (pre-defined tracing directives)
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize, Default)]
    pub enum VerbosityProfile {
        /// The default profile, mostly info records
        #[default]
        Default,
        /// Recommended profile for developers
        Debug,
        /// Show all traces
        All,
        /// Only show warnings and errors
        Quiet,
    }

    impl VerbosityProfile {
        pub fn to_log_filter(self) -> &'static str {
            match self {
                VerbosityProfile::Default => "info",
                VerbosityProfile::Debug => "info,devolutions_agent=debug",
                VerbosityProfile::All => "trace",
                VerbosityProfile::Quiet => "warn",
            }
        }
    }

    /// Unsafe debug options that should only ever be used at development stage
    ///
    /// These options might change or get removed without further notice.
    ///
    /// Note to developers: all options should be safe by default, never add an option
    /// that needs to be overridden manually in order to be safe.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct DebugConf {
        /// Directives string in the same form as the RUST_LOG environment variable
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_directives: Option<String>,

        /// Skip MSI installation in updater module
        ///
        /// Useful for debugging updater logic without actually changing the system.
        #[serde(default)]
        pub skip_msi_install: bool,

        /// Enable unstable features which may break at any point
        #[serde(default)]
        pub enable_unstable: bool,

        /// Override productinfo URL (supports https:// and file:// schemes)
        ///
        /// Useful for testing with local productinfo.json files without publishing to CDN.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub productinfo_url: Option<String>,

        /// Allow downloads from non-official CDN URLs
        ///
        /// By default, package downloads are restricted to cdn.devolutions.net.
        /// Enable this to allow downloads from arbitrary URLs for local testing.
        #[serde(default)]
        pub allow_unsafe_updater_urls: bool,

        /// Skip hash validation for downloaded packages
        ///
        /// Useful for testing with modified packages without updating hashes.
        #[serde(default)]
        pub skip_updater_hash_validation: bool,

        /// Skip MSI signature validation for packages
        ///
        /// Useful for testing with unsigned or test-signed packages.
        #[serde(default)]
        pub skip_msi_signature_validation: bool,
    }

    /// Manual Default trait implementation just to make sure default values are deliberates
    #[allow(clippy::derivable_impls)]
    impl Default for DebugConf {
        fn default() -> Self {
            Self {
                log_directives: None,
                skip_msi_install: false,
                enable_unstable: false,
                productinfo_url: None,
                allow_unsafe_updater_urls: false,
                skip_updater_hash_validation: false,
                skip_msi_signature_validation: false,
            }
        }
    }

    impl DebugConf {
        pub fn is_default(&self) -> bool {
            Self::default().eq(self)
        }
    }

    /// Proxy mode for HTTP client configuration.
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Hash, Default, Serialize, Deserialize)]
    pub enum ProxyMode {
        /// Never use a proxy, ignore environment variables.
        Off,
        /// Use environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) or WinHTTP configuration.
        #[default]
        System,
        /// Use manually configured proxy URLs from the configuration file.
        Manual,
    }

    /// HTTP/SOCKS proxy configuration for outbound requests.
    ///
    /// This configuration supports three modes:
    /// - Off: Never use a proxy
    /// - System: Auto-detect proxy from environment variables or system settings
    /// - Manual: Use explicitly configured proxy URLs
    ///
    /// Manual configuration supports protocol-specific proxy URLs:
    /// - Http: HTTP proxy (e.g., `http://proxy.corp:8080`)
    /// - Https: HTTPS proxy (e.g., `http://proxy.corp:8080`)
    /// - All: Fallback proxy for all protocols (e.g., `socks5://proxy.corp:1080`)
    ///
    /// The Exclude list supports NO_PROXY semantics:
    /// - "*" matches everything (bypass proxy for all targets)
    /// - Exact hostname: "localhost", "example.com"
    /// - Domain suffix: ".corp.local" matches "foo.corp.local"
    /// - IP address: "127.0.0.1"
    /// - CIDR range: "10.0.0.0/8", "192.168.0.0/16"
    #[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ProxyConf {
        /// Proxy mode (Off, System, Manual).
        #[serde(default)]
        pub mode: ProxyMode,
        /// HTTP proxy URL (e.g., `http://proxy.corp:8080`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub http: Option<Url>,
        /// HTTPS proxy URL (e.g., `http://proxy.corp:8080`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub https: Option<Url>,
        /// Fallback proxy URL for all protocols (e.g., `socks5://proxy.corp:1080`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub all: Option<Url>,
        /// Bypass list (same semantics as NO_PROXY).
        #[serde(default)]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub exclude: Vec<String>,
    }

    impl ProxyConf {
        /// Convert this DTO to the http-client-proxy library's ProxyConfig enum.
        pub fn to_proxy_config(&self) -> http_client_proxy::ProxyConfig {
            match self.mode {
                ProxyMode::Off => http_client_proxy::ProxyConfig::Off,
                ProxyMode::System => http_client_proxy::ProxyConfig::System,
                ProxyMode::Manual => http_client_proxy::ProxyConfig::Manual(http_client_proxy::ManualProxyConfig {
                    http: self.http.clone(),
                    https: self.https.clone(),
                    all: self.all.clone(),
                    exclude: self.exclude.clone(),
                }),
            }
        }
    }
}

pub fn handle_cli(command: &str) -> Result<(), anyhow::Error> {
    match command {
        "init" => {
            let _config = load_conf_file_or_generate_new()?;
        }
        _ => {
            bail!("unknown config command: {}", command);
        }
    }

    Ok(())
}
