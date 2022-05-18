use crate::plugin_manager::PLUGIN_MANAGER;
use crate::utils::TargetAddr;
use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
use cfg_if::cfg_if;
use clap::{crate_name, crate_version, App, Arg};
use core::fmt;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{rustls, TlsAcceptor};
use url::Url;

pub const SERVICE_NAME: &str = "devolutions-gateway";
pub const DISPLAY_NAME: &str = "Devolutions Gateway";
pub const DESCRIPTION: &str = "Devolutions Gateway service";
pub const COMPANY_NAME: &str = "Devolutions";

const ARG_APPLICATION_PROTOCOLS: &str = "application-protocols";
const ARG_LISTENERS: &str = "listeners";
const ARG_HOSTNAME: &str = "hostname";
const ARG_FARM_NAME: &str = "farm-name";
const ARG_CERTIFICATE_FILE: &str = "certificate-file";
const ARG_CERTIFICATE_DATA: &str = "certificate-data";
const ARG_PRIVATE_KEY_FILE: &str = "private-key-file";
const ARG_PRIVATE_KEY_DATA: &str = "private-key-data";
const ARG_PROVISIONER_PUBLIC_KEY_FILE: &str = "provisioner-public-key-file";
const ARG_PROVISIONER_PUBLIC_KEY_DATA: &str = "provisioner-public-key-data";
const ARG_DELEGATION_PRIVATE_KEY_FILE: &str = "delegation-private-key-file";
const ARG_DELEGATION_PRIVATE_KEY_DATA: &str = "delegation-private-key-data";
const ARG_ROUTING_URL: &str = "routing-url";
const ARG_CAPTURE_PATH: &str = "capture-path";
const ARG_PROTOCOL: &str = "protocol";
const ARG_LOG_FILE: &str = "log-file";
const ARG_SERVICE_MODE: &str = "service";
const ARG_PLUGINS: &str = "plugins";
const ARG_RECORDING_PATH: &str = "recording-path";
const ARG_SOGAR_REGISTRY_URL: &str = "sogar-registry-url";
const ARG_SOGAR_USERNAME: &str = "sogar-username";
const ARG_SOGAR_PASSWORD: &str = "sogar-password";
const ARG_SOGAR_IMAGE_NAME: &str = "sogar-image-name";

const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const PRIVATE_KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY"];

cfg_if! {
    if #[cfg(target_os = "windows")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions\\Gateway";
    } else if #[cfg(target_os = "macos")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions Gateway";
    } else {
        const COMPANY_DIR: &str = "devolutions";
        const PROGRAM_DIR: &str = "gateway";
        const APPLICATION_DIR: &str = "devolutions-gateway";
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Wayk,
    Rdp,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListenerConfig {
    pub internal_url: Url,
    pub external_url: Url,
}

#[derive(Debug, Clone)]
pub struct TlsPublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct TlsConfig {
    pub acceptor: TlsAcceptor,
    pub certificate: rustls::Certificate,
    pub private_key: rustls::PrivateKey,
    pub public_key: TlsPublicKey,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("certificate", &self.certificate)
            .field("private_key", &self.private_key)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    fn init(certificate: rustls::Certificate, private_key: rustls::PrivateKey) -> anyhow::Result<Self> {
        let public_key = {
            let cert = picky::x509::Cert::from_der(&certificate.0).context("couldn't parse TLS certificate")?;
            TlsPublicKey(cert.public_key().to_der().unwrap())
        };

        let rustls_config = crate::tls_sanity::build_rustls_config(certificate.clone(), private_key.clone())
            .context("Couldn't build TLS config")?;

        let acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        Ok(Self {
            acceptor,
            certificate,
            private_key,
            public_key,
        })
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SogarPushRegistryInfo {
    pub registry_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub image_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SogarPermission {
    Push,
    Pull,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SogarUser {
    pub password: Option<String>,
    pub username: Option<String>,
    pub permission: Option<SogarPermission>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SogarRegistryConfig {
    pub serve_as_registry: Option<bool>,
    pub local_registry_name: Option<String>,
    pub local_registry_image: Option<String>,
    pub keep_files: Option<bool>,
    pub keep_time: Option<usize>,
    pub push_files: Option<bool>,
    pub sogar_push_registry_info: SogarPushRegistryInfo,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub service_mode: bool,
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub company_name: String,
    pub listeners: Vec<ListenerConfig>,
    pub farm_name: String,
    pub hostname: String,
    pub routing_url: Option<Url>,
    pub capture_path: Option<Utf8PathBuf>,
    pub protocol: Protocol,
    pub log_file: Option<Utf8PathBuf>,
    pub log_level: Option<String>,
    pub application_protocols: Vec<String>,
    pub tls: Option<TlsConfig>,
    pub provisioner_public_key: Option<PublicKey>,
    pub delegation_private_key: Option<PrivateKey>,
    pub plugins: Option<Vec<Utf8PathBuf>>,
    pub recording_path: Option<Utf8PathBuf>,
    pub sogar_registry_config: SogarRegistryConfig,
    pub sogar_user: Vec<SogarUser>,
    pub jrl_file: Option<Utf8PathBuf>,
    pub debug: DebugOptions,
}

impl Default for Config {
    fn default() -> Self {
        let default_hostname = get_default_hostname().unwrap_or_else(|| "localhost".to_owned());

        Config {
            service_mode: false,
            service_name: SERVICE_NAME.to_owned(),
            display_name: DISPLAY_NAME.to_owned(),
            description: DESCRIPTION.to_owned(),
            company_name: COMPANY_NAME.to_owned(),
            listeners: Vec::new(),
            farm_name: default_hostname.clone(),
            hostname: default_hostname,
            routing_url: None,
            capture_path: None,
            protocol: Protocol::Unknown,
            log_file: None,
            log_level: None,
            application_protocols: Vec::new(),
            tls: None,
            provisioner_public_key: None,
            delegation_private_key: None,
            plugins: None,
            recording_path: None,
            sogar_registry_config: SogarRegistryConfig {
                serve_as_registry: None,
                local_registry_name: None,
                local_registry_image: None,
                keep_files: None,
                keep_time: None,
                push_files: None,
                sogar_push_registry_info: SogarPushRegistryInfo {
                    registry_url: None,
                    username: None,
                    password: None,
                    image_name: None,
                },
            },
            sogar_user: Vec::new(),
            jrl_file: None,
            debug: DebugOptions::default(),
        }
    }
}

#[derive(Deserialize)]
pub struct GatewayListener {
    #[serde(rename = "InternalUrl")]
    pub internal_url: String,
    #[serde(rename = "ExternalUrl")]
    pub external_url: String,
}

impl GatewayListener {
    pub fn to_listener_config(&self, hostname: &str) -> Option<ListenerConfig> {
        let mut internal_url = self.internal_url.parse::<Url>().ok()?;
        let mut external_url = self.external_url.parse::<Url>().ok()?;

        if internal_url.host_str() == Some("*") {
            let _ = internal_url.set_host(Some("0.0.0.0"));
        }

        if external_url.host_str() == Some("*") {
            let _ = external_url.set_host(Some(hostname));
        }

        Some(ListenerConfig {
            internal_url,
            external_url,
        })
    }
}

fn url_map_scheme_http_to_ws(url: &mut Url) {
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        _ => return,
    };
    url.set_scheme(scheme).expect("couldn't update scheme");
}

#[derive(Deserialize)]
pub struct ConfigFile {
    #[serde(rename = "FarmName")]
    pub farm_name: Option<String>,
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "Listeners")]
    pub listeners: Vec<GatewayListener>,
    #[serde(rename = "ApplicationProtocols")]
    pub application_protocols: Option<Vec<String>>,
    #[serde(rename = "CertificateFile")]
    pub certificate_file: Option<Utf8PathBuf>,
    #[serde(rename = "PrivateKeyFile")]
    pub private_key_file: Option<Utf8PathBuf>,
    #[serde(rename = "ProvisionerPublicKeyFile")]
    pub provisioner_public_key_file: Option<Utf8PathBuf>,
    #[serde(rename = "DelegationPrivateKeyFile")]
    pub delegation_private_key_file: Option<Utf8PathBuf>,
    #[serde(rename = "Plugins")]
    pub plugins: Option<Vec<Utf8PathBuf>>,
    #[serde(rename = "RecordingPath")]
    pub recording_path: Option<Utf8PathBuf>,
    #[serde(rename = "SogarRegistryUrl")]
    pub registry_url: Option<String>,
    #[serde(rename = "SogarUsername")]
    pub username: Option<String>,
    #[serde(rename = "SogarPassword")]
    pub password: Option<String>,
    #[serde(rename = "SogarImageName")]
    pub image_name: Option<String>,
    #[serde(rename = "SogarUsersList")]
    pub sogar_users_list: Option<Vec<SogarUser>>,
    #[serde(rename = "ServeAsRegistry")]
    pub serve_as_registry: Option<bool>,
    #[serde(rename = "RegistryName")]
    pub registry_name: Option<String>,
    #[serde(rename = "RegistryImage")]
    pub registry_image: Option<String>,
    #[serde(rename = "KeepFiles")]
    pub keep_files: Option<bool>,
    #[serde(rename = "KeepTime")]
    pub keep_time: Option<usize>,
    #[serde(rename = "PushFiles")]
    pub push_files: Option<bool>,

    // unstable options (subject to change)
    #[serde(rename = "LogFile")]
    pub log_file: Option<Utf8PathBuf>,
    #[serde(rename = "JrlFile")]
    pub jrl_file: Option<Utf8PathBuf>,
    #[serde(rename = "CapturePath")]
    pub capture_path: Option<Utf8PathBuf>,
    /// Directive string in the same form as the RUST_LOG environment variable.
    #[serde(rename = "LogLevel")]
    pub log_level: Option<String>,

    // unsafe debug options for developers
    #[serde(rename = "__debug__")]
    pub debug: DebugOptions,
}

/// Unsafe debug options that should only ever be used at development stage
///
/// These options might change or get removed without further notice.
///
/// Note to developers: all options should be safe by default, never add an option
/// that needs to be overridden manually in order to be safe.
#[derive(PartialEq, Debug, Clone, Deserialize)]
pub struct DebugOptions {
    /// Dump received tokens using a `debug` statement
    #[serde(default)]
    pub dump_tokens: bool,

    /// Ignore token signature and accept as-is (any signer is accepted), expired tokens and token
    /// reuse is allowed, etc. Only restriction is to provide claims in the right format.
    #[serde(default)]
    pub disable_token_validation: bool,

    /// Ignore KDC address provided by KDC token, and use this one instead
    pub override_kdc: Option<TargetAddr>,
}

/// Manual Default trait implementation just to make sure default values are deliberates
#[allow(clippy::derivable_impls)]
impl Default for DebugOptions {
    fn default() -> Self {
        Self {
            dump_tokens: false,
            disable_token_validation: false,
            override_kdc: None,
        }
    }
}

fn get_config_path() -> Utf8PathBuf {
    if let Ok(config_path_env) = env::var("DGATEWAY_CONFIG_PATH") {
        Utf8PathBuf::from(config_path_env)
    } else {
        let mut config_path = Utf8PathBuf::new();

        if cfg!(target_os = "windows") {
            let program_data_env = env::var("ProgramData").unwrap();
            config_path.push(program_data_env);
            config_path.push(COMPANY_DIR);
            config_path.push(PROGRAM_DIR);
        } else if cfg!(target_os = "macos") {
            config_path.push("/Library/Application Support");
            config_path.push(APPLICATION_DIR);
        } else {
            config_path.push("/etc");
            config_path.push(APPLICATION_DIR);
        }

        config_path
    }
}

fn get_config_file_path() -> Utf8PathBuf {
    let mut config_file_path = get_config_path();
    config_file_path.push("gateway.json");
    config_file_path
}

fn load_config_file(file_path: &Utf8Path) -> Option<ConfigFile> {
    let file = File::open(file_path).ok()?;

    match serde_json::from_reader(BufReader::new(file)) {
        Ok(config_file) => Some(config_file),
        Err(e) => panic!(
            "A configuration file has been provided ({}), but it can't be used: {}",
            file_path, e
        ),
    }
}

pub fn get_program_data_file_path(file_path: impl AsRef<Utf8Path>) -> Utf8PathBuf {
    let file_path = file_path.as_ref();
    if file_path.is_absolute() {
        file_path.to_owned()
    } else {
        get_config_path().join(file_path.file_name().unwrap())
    }
}

fn get_default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

impl Config {
    pub fn init() -> Self {
        let mut config = Config::load_from_file(&get_config_file_path()).unwrap_or_default();

        let cli_app = App::new(crate_name!())
            .author("Devolutions Inc.")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about(DISPLAY_NAME)
            .arg(
                Arg::with_name(ARG_LISTENERS)
                    .short("l")
                    .long("listener")
                    .value_name("URL")
                    .env("DGATEWAY_LISTENERS")
                    .help(
                        "An URL on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port>. \
                         Supported schemes: tcp, ws, wss",
                    )
                    .long_help(
                        "An URL on which the server will listen on. \
                         The external URL returned as candidate can be specified after the listener, \
                         separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port> \
                         If it is not specified, the external url will be <scheme>://<hostname>:<port> \
                         where <hostname> is the value of the hostname parameter.",
                    )
                    .multiple(true)
                    .use_delimiter(true)
                    .value_delimiter(";")
                    .takes_value(true)
                    .number_of_values(1),
            )
            .arg(
                Arg::with_name(ARG_FARM_NAME)
                    .long("farm-name")
                    .value_name("FARM-NAME")
                    .env("DGATEWAY_FARM_NAME")
                    .help("Farm name")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_HOSTNAME)
                    .long("hostname")
                    .value_name("HOSTNAME")
                    .env("DGATEWAY_HOSTNAME")
                    .help("Specific name to reach that instance of Devolutions Gateway.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_APPLICATION_PROTOCOLS)
                    .long("application-protocols")
                    .value_name("PROTOCOLS")
                    .env("DGATEWAY_APPLICATION_PROTOCOLS")
                    .help("Protocols supported in sessions")
                    .takes_value(true)
                    .multiple(true)
                    .use_delimiter(true)
                    .possible_values(&["wayk", "rdp"]),
            )
            .arg(
                Arg::with_name(ARG_CERTIFICATE_FILE)
                    .long("certificate-file")
                    .value_name("FILE")
                    .env("DGATEWAY_CERTIFICATE_FILE")
                    .help("Path to the certificate file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_CERTIFICATE_DATA)
                    .long("certificate-data")
                    .value_name("DATA")
                    .env("DGATEWAY_CERTIFICATE_DATA")
                    .help("Certificate data, base64-encoded X509 DER.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PRIVATE_KEY_FILE)
                    .long("private-key-file")
                    .value_name("FILE")
                    .env("DGATEWAY_PRIVATE_KEY_FILE")
                    .help("Path to the private key file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PRIVATE_KEY_DATA)
                    .long("private-key-data")
                    .value_name("DATA")
                    .env("DGATEWAY_PRIVATE_KEY_DATA")
                    .help("Private key data, base64-encoded PKCS10.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PROVISIONER_PUBLIC_KEY_FILE)
                    .long("provisioner-public-key-file")
                    .value_name("FILE")
                    .env("DGATEWAY_PROVISIONER_PUBLIC_KEY_FILE")
                    .help("Path to the public key file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PROVISIONER_PUBLIC_KEY_DATA)
                    .long("provisioner-public-key-data")
                    .value_name("DATA")
                    .env("DGATEWAY_PROVISIONER_PUBLIC_KEY_DATA")
                    .help("Public key data, base64-encoded PKCS10.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_DELEGATION_PRIVATE_KEY_FILE)
                    .long("delegation-private-key-file")
                    .value_name("FILE")
                    .env("DGATEWAY_DELEGATION_PRIVATE_KEY_FILE")
                    .help("Path to the private key file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_DELEGATION_PRIVATE_KEY_DATA)
                    .long("delegation-private-key-data")
                    .value_name("DATA")
                    .env("DGATEWAY_DELEGATION_PRIVATE_KEY_DATA")
                    .help("Private key data, base64-encoded PKCS10.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_ROUTING_URL)
                    .short("r")
                    .long("routing-url")
                    .value_name("URL")
                    .help("An address on which the server will route all packets. Format: <scheme>://<ip>:<port>.")
                    .long_help(
                        "An address on which the server will route all packets.\n\
                         Format: <scheme>://<ip>:<port>.\n\
                         Supported schemes: tcp, tls.\n\
                         If it is not specified, the JET protocol will be used.",
                    )
                    .takes_value(true)
                    .empty_values(false)
                    .validator(|v| {
                        if Url::parse(&v).is_ok() {
                            Ok(())
                        } else {
                            Err(String::from("Expected <scheme>://<ip>:<port>, got invalid value"))
                        }
                    }),
            )
            .arg(
                Arg::with_name(ARG_CAPTURE_PATH)
                    .long("capture-path")
                    .value_name("PATH")
                    .help(
                        "Path to the pcap files. If not set, no pcap files will be created. \
                         WaykNow and RDP protocols can be saved.",
                    )
                    .long_help(
                        "Path to the pcap files. If not set, no pcap files will be created. \
                         WaykNow and RDP protocols can be saved.",
                    )
                    .env("DGATEWAY_CAPTURE_PATH")
                    .takes_value(true)
                    .empty_values(false)
                    .validator(|v| {
                        let path = Utf8Path::new(&v);
                        if !path.is_dir() {
                            Err("Not a path".into())
                        } else if !path.exists() {
                            Err("Path doesn't exist".into())
                        } else {
                            Ok(())
                        }
                    }),
            )
            .arg(
                Arg::with_name(ARG_PROTOCOL)
                    .short("p")
                    .long("protocol")
                    .value_name("PROTOCOL_NAME")
                    .help(
                        "Specify the application protocol used. Useful when pcap file is saved \
                         and you want to avoid application message in two different tcp packet.",
                    )
                    .long_help(
                        "Specify the application protocol used. Useful when pcap file is saved and you want to \
                         avoid application message in two different tcp packet. If protocol is unknown, we can't \
                         be sure that application packet is not split between 2 tcp packets.",
                    )
                    .takes_value(true)
                    .possible_values(&["wayk", "rdp"])
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_LOG_FILE)
                    .long("log-file")
                    .value_name("LOG_FILE")
                    .help("A file with logs")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_SERVICE_MODE)
                    .long("service")
                    .takes_value(false)
                    .help("Enable service mode"),
            )
            .arg(
                Arg::with_name(ARG_PLUGINS)
                    .long("plugin")
                    .value_name("PATH")
                    .help("A path where the plugin is located including the plugin name and plugin extension.")
                    .long_help(
                        "A path where the plugin is located including the plugin name and plugin extension. \
                    The plugin will be loaded as dynamic library. \
                    For example, on linux  - home/usr/libs/libplugin.so \
                    on Windows - D:\\libs\\plugin.dll.",
                    )
                    .multiple(true)
                    .use_delimiter(true)
                    .value_delimiter(";")
                    .takes_value(true)
                    .number_of_values(1),
            )
            .arg(
                Arg::with_name(ARG_RECORDING_PATH)
                    .long("recording-path")
                    .value_name("PATH")
                    .help("A path where the recording of the session will be located.")
                    .long_help(
                        "A path where the recording will be saved. \
                    If not set the TEMP directory will be used.",
                    )
                    .takes_value(true)
                    .empty_values(false)
                    .validator(|v| {
                        if Utf8PathBuf::from(v).is_dir() {
                            Ok(())
                        } else {
                            Err(String::from("The value does not exist or is not a path"))
                        }
                    }),
            )
            .arg(
                Arg::with_name(ARG_SOGAR_REGISTRY_URL)
                    .long(ARG_SOGAR_REGISTRY_URL)
                    .value_name("URL")
                    .help("Registry url to where the session recordings will be pushed.")
                    .env("SOGAR_REGISTRY_URL")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_SOGAR_USERNAME)
                    .long(ARG_SOGAR_USERNAME)
                    .help("Registry username.")
                    .env("SOGAR_REGISTRY_USERNAME")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_SOGAR_PASSWORD)
                    .long(ARG_SOGAR_PASSWORD)
                    .help("Registry password.")
                    .env("SOGAR_REGISTRY_PASSWORD")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_SOGAR_IMAGE_NAME)
                    .long(ARG_SOGAR_IMAGE_NAME)
                    .help("Image name of the registry where to push the file. For example videos/demo")
                    .takes_value(true)
                    .empty_values(false),
            );

        let matches = cli_app.get_matches();

        if matches.is_present(ARG_SERVICE_MODE) {
            config.service_mode = true;
        }

        if let Some(log_file) = matches.value_of(ARG_LOG_FILE) {
            config.log_file = Some(Utf8PathBuf::from(log_file));
        }

        if let Some(farm_name) = matches.value_of(ARG_FARM_NAME) {
            config.farm_name = farm_name.to_owned();
        }

        if let Some(hostname) = matches.value_of(ARG_HOSTNAME) {
            config.hostname = hostname.to_owned();
        }

        if let Some(protocols) = matches.values_of(ARG_APPLICATION_PROTOCOLS) {
            config.application_protocols = protocols.map(|protocol| protocol.to_string()).collect();
        }

        if let Some(routing_url) = matches.value_of(ARG_ROUTING_URL) {
            config.routing_url = Some(
                routing_url
                    .parse::<Url>()
                    .expect("must be checked in the clap validator"),
            );
        }

        if let Some(capture_path) = matches.value_of(ARG_CAPTURE_PATH) {
            config.capture_path = Some(capture_path.into());
        }

        if let Some(protocol) = matches.value_of(ARG_PROTOCOL) {
            match protocol {
                "wayk" => config.protocol = Protocol::Wayk,
                "rdp" => config.protocol = Protocol::Rdp,
                _ => config.protocol = Protocol::Unknown,
            }
        };

        // TLS configuration

        let tls_certificate = matches
            .value_of(ARG_CERTIFICATE_DATA)
            .map(|val| {
                if val.starts_with("-----BEGIN") {
                    val.to_owned()
                } else {
                    format!("-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----", val)
                }
            })
            .or_else(|| {
                let file_path = matches.value_of(ARG_CERTIFICATE_FILE)?;
                let file_path = get_program_data_file_path(file_path);
                Some(std::fs::read_to_string(file_path).expect("couldn't read TLS certificate file"))
            })
            .map(|pem_str| {
                let pem = pem_str.parse::<Pem>().expect("couldn't parse TLS certificate pem");
                if pem.label() != CERTIFICATE_LABEL {
                    panic!("bad pem label for TLS certificate (expected {})", CERTIFICATE_LABEL);
                }
                rustls::Certificate(pem.into_data().into_owned())
            });

        let tls_private_key = matches
            .value_of(ARG_PRIVATE_KEY_DATA)
            .map(|val| {
                if val.starts_with("-----BEGIN") {
                    val.to_owned()
                } else {
                    format!("-----BEGIN PRIVATE KEY-----{}-----END PRIVATE KEY-----", val)
                }
            })
            .or_else(|| {
                let file_path = matches.value_of(ARG_PRIVATE_KEY_FILE)?;
                let file_path = get_program_data_file_path(file_path);
                Some(std::fs::read_to_string(file_path).expect("couldn't read TLS private key file"))
            })
            .map(|pem_str| {
                let pem = pem_str.parse::<Pem>().expect("couldn't parse TLS private key pem");
                if PRIVATE_KEY_LABELS.iter().all(|&label| pem.label() != label) {
                    panic!("bad pem label for TLS private key (expected {:?})", PRIVATE_KEY_LABELS);
                }
                rustls::PrivateKey(pem.into_data().into_owned())
            });

        tls_certificate
            .zip(tls_private_key)
            .map(|(certificate, key)| TlsConfig::init(certificate, key).expect("couldn't init TLS config"))
            .into_iter()
            .for_each(|tls_conf| config.tls = Some(tls_conf));

        // provisioner key

        matches
            .value_of(ARG_PROVISIONER_PUBLIC_KEY_DATA)
            .map(|val| {
                if val.starts_with("-----BEGIN") {
                    val.to_owned()
                } else {
                    format!("-----BEGIN PUBLIC KEY-----{}-----END PUBLIC KEY-----", val)
                }
            })
            .or_else(|| {
                let file_path = matches.value_of(ARG_PROVISIONER_PUBLIC_KEY_FILE)?;
                let file_path = get_program_data_file_path(file_path);
                Some(std::fs::read_to_string(file_path).expect("couldn't read provisioner public key file"))
            })
            .into_iter()
            .for_each(|pem_str| {
                let pem = pem_str
                    .parse::<Pem>()
                    .expect("couldn't parse provisioner public key pem");
                let public_key = PublicKey::from_pem(&pem).expect("couldn't parse provisioner public key");
                config.provisioner_public_key = Some(public_key);
            });

        // delegation key

        matches
            .value_of(ARG_DELEGATION_PRIVATE_KEY_DATA)
            .map(|val| {
                if val.starts_with("-----BEGIN") {
                    val.to_owned()
                } else {
                    format!("-----BEGIN PRIVATE KEY-----{}-----END PRIVATE KEY-----", val)
                }
            })
            .or_else(|| {
                let file_path = matches.value_of(ARG_DELEGATION_PRIVATE_KEY_FILE)?;
                let file_path = get_program_data_file_path(file_path);
                Some(std::fs::read_to_string(file_path).expect("couldn't read delegation private key file"))
            })
            .into_iter()
            .for_each(|pem_str| {
                let pem = pem_str
                    .parse::<Pem>()
                    .expect("couldn't parse delegation private key pem");
                let private_key = PrivateKey::from_pem(&pem).expect("couldn't parse delegation public key");
                config.delegation_private_key = Some(private_key);
            });

        // plugins

        let plugins = matches
            .values_of(ARG_PLUGINS)
            .unwrap_or_default()
            .map(Utf8PathBuf::from)
            .collect::<Vec<Utf8PathBuf>>();

        if !plugins.is_empty() {
            config.plugins = Some(plugins);
        }

        if let Some(registry_url) = matches.value_of(ARG_SOGAR_REGISTRY_URL) {
            config.sogar_registry_config.sogar_push_registry_info.registry_url = Some(registry_url.to_owned());
        }

        if let Some(username) = matches.value_of(ARG_SOGAR_USERNAME) {
            config.sogar_registry_config.sogar_push_registry_info.username = Some(username.to_owned());
        }

        if let Some(password) = matches.value_of(ARG_SOGAR_PASSWORD) {
            config.sogar_registry_config.sogar_push_registry_info.password = Some(password.to_owned());
        }

        if let Some(image_name) = matches.value_of(ARG_SOGAR_IMAGE_NAME) {
            config.sogar_registry_config.sogar_push_registry_info.image_name = Some(image_name.to_owned());
        }

        if let Some(recording_path) = matches.value_of(ARG_RECORDING_PATH) {
            config.recording_path = Some(Utf8PathBuf::from(recording_path));
        }

        // listeners parsing

        for listener in matches.values_of(ARG_LISTENERS).unwrap_or_default() {
            let mut internal_url;
            let mut external_url;

            if let Some(pos) = listener.find(',') {
                let url_str = &listener[0..pos];
                internal_url = listener[0..pos]
                    .parse::<Url>()
                    .unwrap_or_else(|_| panic!("Listener {} is an invalid URL.", url_str));

                if internal_url.host_str() == Some("*") {
                    let _ = internal_url.set_host(Some("0.0.0.0"));
                }

                if listener.len() > pos + 1 {
                    let external_str = listener[pos + 1..].to_string();
                    external_url = external_str
                        .parse::<Url>()
                        .unwrap_or_else(|_| panic!("External_url {} is an invalid URL.", external_str));

                    if external_url.host_str() == Some("*") {
                        let _ = external_url.set_host(Some(&config.hostname));
                    }
                } else {
                    panic!("External url has to be specified after the comma : {}", listener);
                }
            } else {
                internal_url = listener
                    .parse::<Url>()
                    .unwrap_or_else(|_| panic!("Listener {} is an invalid URL.", listener));
                external_url = format!(
                    "{}://{}:{}",
                    internal_url.scheme(),
                    config.hostname,
                    internal_url.port_or_known_default().unwrap_or(8080)
                )
                .parse::<Url>()
                .unwrap_or_else(|_| panic!("External url can't be built based on listener {}", listener));
            }

            config.listeners.push(ListenerConfig {
                internal_url,
                external_url,
            });
        }

        if config.jrl_file.is_none() {
            config.jrl_file = Some(Utf8PathBuf::from("./jrl.json"));
        }

        // NOTE: we allow configs to specify "http" or "https" scheme if it's clearer,
        // but this is ultimately identical to "ws" and "wss" respectively.

        // Normalize all listeners to ws/wss
        for listener in config.listeners.iter_mut() {
            url_map_scheme_http_to_ws(&mut listener.internal_url);
            url_map_scheme_http_to_ws(&mut listener.external_url);
        }

        config
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // early fail if specified plugins can't be loaded
        if let Some(plugins) = &self.plugins {
            let mut manager = PLUGIN_MANAGER.lock();
            for plugin in plugins {
                manager
                    .load_plugin(plugin)
                    .with_context(|| format!("Failed to load plugin {}", plugin))?;
            }
        }

        if !self
            .listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "http" | "https" | "ws" | "wss"))
        {
            anyhow::bail!("At least one HTTP-capable listener is required");
        }

        if self.provisioner_public_key.is_none() {
            anyhow::bail!("provisioner public key is missing");
        }

        let requires_tls = {
            if let Some("tls") = self.routing_url.as_ref().map(|o| o.scheme()) {
                true
            } else {
                self.listeners
                    .iter()
                    .any(|l| matches!(l.internal_url.scheme(), "https" | "wss"))
            }
        };

        if requires_tls && self.tls.is_none() {
            anyhow::bail!("TLS usage implied but TLS certificate or/and private key are missing");
        }

        Ok(())
    }

    pub fn load_from_file(file_path: &Utf8Path) -> Option<Self> {
        let config_file = load_config_file(file_path)?;

        let default_hostname = get_default_hostname().unwrap_or_else(|| "localhost".to_string());
        let hostname = config_file.hostname.unwrap_or(default_hostname);
        let farm_name = config_file.farm_name.unwrap_or_else(|| hostname.clone());

        let mut listeners = Vec::new();
        for listener in config_file.listeners {
            if let Some(listener_config) = listener.to_listener_config(hostname.as_str()) {
                listeners.push(listener_config);
            } else {
                eprintln!(
                    "Invalid Listener: InternalUrl: {} ExternalUrl: {}",
                    listener.internal_url, listener.external_url,
                );
            }
        }

        let application_protocols = config_file.application_protocols.unwrap_or_default();

        let log_file = config_file.log_file.unwrap_or_else(|| Utf8PathBuf::from("gateway.log"));
        let log_file = get_program_data_file_path(&log_file);

        let jrl_file = config_file.jrl_file.unwrap_or_else(|| Utf8PathBuf::from("jrl.json"));
        let jrl_file = get_program_data_file_path(&jrl_file);

        let tls_certificate = config_file.certificate_file.map(|file| {
            let file = get_program_data_file_path(&file);
            let pem_str = std::fs::read_to_string(file).expect("bad provisioner public key file");
            let pem = pem_str.parse::<Pem>().expect("bad TLS certificate pem");
            if pem.label() != CERTIFICATE_LABEL {
                panic!("bad pem label for TLS certificate (expected {})", CERTIFICATE_LABEL);
            }
            rustls::Certificate(pem.into_data().into_owned())
        });

        let tls_private_key = config_file.private_key_file.map(|file| {
            let file = get_program_data_file_path(&file);
            let pem_str = std::fs::read_to_string(file).expect("bad provisioner public key file");
            let pem = pem_str.parse::<Pem>().expect("bad TLS certificate pem");
            if PRIVATE_KEY_LABELS.iter().all(|&label| pem.label() != label) {
                panic!("bad pem label for TLS private key (expected {:?})", PRIVATE_KEY_LABELS);
            }
            rustls::PrivateKey(pem.into_data().into_owned())
        });

        let tls_conf = tls_certificate
            .zip(tls_private_key)
            .map(|(certificate, key)| TlsConfig::init(certificate, key).expect("couldn't init TLS config"));

        let provisioner_public_key = config_file.provisioner_public_key_file.map(|file| {
            let file = get_program_data_file_path(&file);
            let pem_str = std::fs::read_to_string(file).expect("bad provisioner public key file");
            PublicKey::from_pem_str(&pem_str).expect("bad provisioner public key")
        });

        let delegation_private_key = config_file.delegation_private_key_file.map(|file| {
            let file = get_program_data_file_path(&file);
            let pem_str = std::fs::read_to_string(file).expect("bad delegation private key file");
            PrivateKey::from_pem_str(&pem_str).expect("bad delegation private key")
        });

        let plugins = config_file.plugins;
        let recording_path = config_file.recording_path.map(Utf8PathBuf::from);

        let registry_url = config_file.registry_url;
        let username = config_file.username;
        let password = config_file.password;
        let image_name = config_file.image_name;
        let serve_as_registry = config_file.serve_as_registry;
        let registry_name = config_file.registry_name;
        let registry_image = config_file.registry_image;
        let keep_files = config_file.keep_files;
        let keep_time = config_file.keep_time;
        let push_files = config_file.push_files;
        let sogar_user = config_file.sogar_users_list.unwrap_or_default();

        // unstable options (subject to change)
        let capture_path = config_file.capture_path;

        Some(Config {
            listeners,
            farm_name,
            hostname,
            capture_path,
            log_file: Some(log_file),
            log_level: config_file.log_level,
            application_protocols,
            tls: tls_conf,
            provisioner_public_key,
            delegation_private_key,
            plugins,
            recording_path,
            sogar_registry_config: SogarRegistryConfig {
                serve_as_registry,
                local_registry_name: registry_name,
                local_registry_image: registry_image,
                keep_files,
                keep_time,
                push_files,
                sogar_push_registry_info: SogarPushRegistryInfo {
                    registry_url,
                    username,
                    password,
                    image_name,
                },
            },
            sogar_user,
            jrl_file: Some(jrl_file),
            debug: config_file.debug,

            // Not configured through file
            ..Default::default()
        })
    }
}
