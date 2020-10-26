use cfg_if::cfg_if;
use clap::{crate_name, crate_version, App, Arg};
use picky::{
    key::{PrivateKey, PublicKey},
    pem::Pem,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};
use url::Url;

const DEFAULT_HTTP_LISTENER_PORT: u32 = 10256;

const ARG_API_KEY: &str = "api-key";
const ARG_APPLICATION_PROTOCOLS: &str = "application-protocols";
const ARG_UNRESTRICTED: &str = "unrestricted";
const ARG_LISTENERS: &str = "listeners";
const ARG_API_LISTENER: &str = "api-listener";
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

const SERVICE_NAME: &str = "devolutions-gateway";
const DISPLAY_NAME: &str = "Devolutions Gateway";
const DESCRIPTION: &str = "Devolutions Gateway service";
const COMPANY_NAME: &str = "Devolutions";

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
    WAYK,
    RDP,
    UNKNOWN,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub url: Url,
    pub external_url: Url,
}

#[derive(Debug, Default, Clone)]
pub struct CertificateConfig {
    pub certificate_file: Option<String>,
    pub certificate_data: Option<String>,
    pub private_key_file: Option<String>,
    pub private_key_data: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub service_mode: bool,
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    pub company_name: String,
    pub unrestricted: bool,
    pub api_key: Option<String>,
    pub listeners: Vec<ListenerConfig>,
    pub farm_name: String,
    pub hostname: String,
    pub routing_url: Option<Url>,
    pub capture_path: Option<String>,
    pub protocol: Protocol,
    pub log_file: Option<String>,
    pub application_protocols: Vec<String>,
    pub certificate: CertificateConfig,
    pub api_listener: Url,
    pub provisioner_public_key: Option<PublicKey>,
    pub delegation_private_key: Option<PrivateKey>,
}

impl Default for Config {
    fn default() -> Self {
        let default_hostname = get_default_hostname().unwrap_or_else(|| "localhost".to_string());

        let default_api_listener_url = format!("http://0.0.0.0:{}", DEFAULT_HTTP_LISTENER_PORT);
        let api_listener = default_api_listener_url
            .parse::<Url>()
            .unwrap_or_else(|e| panic!("API listener URL is invalid: {}", e));

        Config {
            service_mode: false,
            service_name: SERVICE_NAME.to_string(),
            display_name: DISPLAY_NAME.to_string(),
            description: DESCRIPTION.to_string(),
            company_name: COMPANY_NAME.to_string(),
            unrestricted: true, // TODO: Should be false by default in a future version
            api_key: None,
            listeners: Vec::new(),
            farm_name: default_hostname.clone(),
            hostname: default_hostname,
            routing_url: None,
            capture_path: None,
            protocol: Protocol::UNKNOWN,
            log_file: None,
            application_protocols: Vec::new(),
            certificate: CertificateConfig {
                certificate_file: None,
                certificate_data: None,
                private_key_file: None,
                private_key_data: None,
            },
            api_listener,
            provisioner_public_key: None,
            delegation_private_key: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
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
            url: internal_url,
            external_url,
        })
    }
}

fn url_map_scheme_ws_to_http(url: &mut Url) {
    let scheme = url.scheme().to_string();
    let scheme = match scheme.as_str() {
        "ws" => "http",
        "wss" => "https",
        scheme => scheme,
    };
    let _ = url.set_scheme(scheme);
}

fn url_map_scheme_http_to_ws(url: &mut Url) {
    let scheme = url.scheme().to_string();
    let scheme = match scheme.as_str() {
        "http" => "ws",
        "https" => "wss",
        scheme => scheme,
    };
    let _ = url.set_scheme(scheme);
}

#[derive(Serialize, Deserialize)]
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
    pub certificate_file: Option<String>,
    #[serde(rename = "PrivateKeyFile")]
    pub private_key_file: Option<String>,
    #[serde(rename = "ProvisionerPublicKeyFile")]
    pub provisioner_public_key_file: Option<String>,
    #[serde(rename = "DelegationPrivateKeyFile")]
    pub delegation_private_key_file: Option<String>,

    // unstable options (subject to change)
    #[serde(rename = "ApiKey")]
    pub api_key: Option<String>,
    #[serde(rename = "LogFile")]
    pub log_file: Option<String>,
    #[serde(rename = "CapturePath")]
    pub capture_path: Option<String>,
    #[serde(rename = "Unrestricted")]
    pub unrestricted: Option<bool>,
    #[serde(rename = "ApiListener")]
    pub api_listener: Option<String>,
}

fn get_config_path() -> PathBuf {
    if let Ok(config_path_env) = env::var("DGATEWAY_CONFIG_PATH") {
        Path::new(&config_path_env).to_path_buf()
    } else {
        let mut config_path = PathBuf::new();

        if cfg!(target_os = "windows") {
            let program_data_env = env::var("ProgramData").unwrap();
            config_path.push(Path::new(program_data_env.as_str()));
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

fn get_config_file_path() -> PathBuf {
    let mut config_file_path = get_config_path();
    config_file_path.push("gateway.json");
    config_file_path
}

fn load_config_file(file_path: PathBuf) -> Option<ConfigFile> {
    let file = File::open(file_path.as_path()).ok()?;
    let result = serde_json::from_reader(BufReader::new(file));
    result.ok()
}

pub fn get_program_data_file_path(filename: &str) -> PathBuf {
    let file_path = PathBuf::from(filename);
    if file_path.is_absolute() {
        file_path
    } else {
        get_config_path().join(file_path.file_name().unwrap())
    }
}

fn get_default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

impl Config {
    pub fn init() -> Self {
        let mut config = Config::load_from_file(get_config_file_path()).unwrap_or_else(|| Config::default());

        let cli_app = App::new(crate_name!())
            .author("Devolutions Inc.")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about(DISPLAY_NAME)
            .arg(
                Arg::with_name(ARG_API_KEY)
                    .long("api-key")
                    .value_name("KEY")
                    .env("JET_API_KEY")
                    .help("The API key used by the server to authenticate client queries.")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name(ARG_UNRESTRICTED)
                    .long("unrestricted")
                    .env("JET_UNRESTRICTED")
                    .help("Remove API key validation on some HTTP routes")
                    .takes_value(false),
            )
            .arg(
                Arg::with_name(ARG_LISTENERS)
                    .short("l")
                    .long("listener")
                    .value_name("URL")
                    .env("JET_LISTENERS")
                    .help(
                        "An URL on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port>. \
                         Supported schemes: tcp, ws, wss",
                    )
                    .long_help(
                        "An URL on which the server will listen on. \
                         The external URL returned as candidate can be specified after the listener, \
                         separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port> \
                         If it is not specified, the external url will be <scheme>://<jet_instance>:<port> \
                         where <jet_instance> is the value of the jet-instance parameter.",
                    )
                    .multiple(true)
                    .use_delimiter(true)
                    .value_delimiter(";")
                    .takes_value(true)
                    .number_of_values(1),
            )
            .arg(
                Arg::with_name(ARG_API_LISTENER)
                    .long("api-listener")
                    .value_name("URL")
                    .env("DGATEWAY_API_LISTENER")
                    .help("API HTTP listener URL.")
                    .takes_value(true),
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
                    .env("JET_PROVISIONER_PUBLIC_KEY_DATA")
                    .help("Public key data, base64-encoded PKCS10.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_DELEGATION_PRIVATE_KEY_FILE)
                    .long("delegation-private-key-file")
                    .value_name("FILE")
                    .env("JET_DELEGATION_PRIVATE_KEY_FILE")
                    .help("Path to the private key file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_DELEGATION_PRIVATE_KEY_DATA)
                    .long("delegation-private-key-data")
                    .value_name("DATA")
                    .env("JET_DELEGATION_PRIVATE_KEY_DATA")
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
                        if std::path::PathBuf::from(v).is_dir() {
                            Ok(())
                        } else {
                            Err(String::from("The value does not exist or is not a path"))
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
            );

        let matches = cli_app.get_matches();

        if matches.is_present(ARG_SERVICE_MODE) {
            config.service_mode = true;
        }

        if let Some(log_file) = matches.value_of(ARG_LOG_FILE) {
            config.log_file = Some(log_file.to_owned());
        }

        if let Some(api_key) = matches.value_of(ARG_API_KEY) {
            config.api_key = Some(api_key.to_owned());
        }

        if matches.is_present(ARG_UNRESTRICTED) {
            config.unrestricted = true;
        }

        if let Some(api_listener) = matches.value_of(ARG_API_LISTENER) {
            config.api_listener = api_listener
                .parse::<Url>()
                .unwrap_or_else(|e| panic!("API listener URL is invalid: {}", e));
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
            config.capture_path = Some(capture_path.to_owned());
        }

        if let Some(protocol) = matches.value_of(ARG_PROTOCOL) {
            match protocol {
                "wayk" => config.protocol = Protocol::WAYK,
                "rdp" => config.protocol = Protocol::RDP,
                _ => config.protocol = Protocol::UNKNOWN,
            }
        };

        if let Some(certificate_file) = matches.value_of(ARG_CERTIFICATE_FILE) {
            config.certificate.certificate_file = Some(
                get_program_data_file_path(certificate_file)
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        if let Some(certificate_data) = matches.value_of(ARG_CERTIFICATE_DATA) {
            config.certificate.certificate_data = Some(certificate_data.to_owned());
        }
        if let Some(private_key_file) = matches.value_of(ARG_PRIVATE_KEY_FILE) {
            config.certificate.private_key_file = Some(
                get_program_data_file_path(private_key_file)
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        if let Some(private_key_data) = matches.value_of(ARG_PRIVATE_KEY_DATA) {
            config.certificate.private_key_data = Some(private_key_data.to_owned());
        }

        // provisioner key

        let pem_opt = if let Some(pem_str) = matches.value_of(ARG_PROVISIONER_PUBLIC_KEY_DATA) {
            Some(format!("-----BEGIN PUBLIC KEY-----{}-----END PUBLIC KEY-----", pem_str))
        } else if let Some(file) = matches.value_of(ARG_PROVISIONER_PUBLIC_KEY_FILE) {
            let file_path = get_program_data_file_path(file).as_path().to_str().unwrap().to_string();
            Some(std::fs::read_to_string(file_path).expect("couldn't read provisioner public path key file"))
        } else {
            None
        };

        if let Some(pem_str) = pem_opt {
            let pem = pem_str
                .parse::<Pem>()
                .expect("couldn't parse provisioner public key pem");
            let public_key = PublicKey::from_pem(&pem).expect("couldn't parse provisioner public key");
            config.provisioner_public_key = Some(public_key);
        }

        // delegation key

        let delegation_private_key_pem_opt = if let Some(pem_str) = matches.value_of(ARG_DELEGATION_PRIVATE_KEY_DATA) {
            Some(format!("-----BEGIN PUBLIC KEY-----{}-----END PUBLIC KEY-----", pem_str))
        } else if let Some(file) = matches.value_of(ARG_DELEGATION_PRIVATE_KEY_FILE) {
            let file_path = get_program_data_file_path(file).as_path().to_str().unwrap().to_string();
            Some(std::fs::read_to_string(file_path).expect("couldn't read delegation private path key file"))
        } else {
            None
        };

        if let Some(delegation_private_key_pem) = delegation_private_key_pem_opt {
            let pem = delegation_private_key_pem
                .parse::<Pem>()
                .expect("couldn't parse delegation private key pem");
            let private_key = PrivateKey::from_pem(&pem).expect("couldn't parse delegation private key");
            config.delegation_private_key = Some(private_key);
        }

        // listeners parsing

        let mut listeners = Vec::new();
        for listener in matches.values_of(ARG_LISTENERS).unwrap_or_else(Default::default) {
            let url;
            let external_url;

            if let Some(pos) = listener.find(',') {
                let url_str = &listener[0..pos];
                url = listener[0..pos]
                    .parse::<Url>()
                    .unwrap_or_else(|_| panic!("Listener {} is an invalid URL.", url_str));

                if listener.len() > pos + 1 {
                    let external_str = listener[pos + 1..].to_string();
                    let external_str = external_str.replace("<jet_instance>", &config.hostname);
                    external_url = external_str
                        .parse::<Url>()
                        .unwrap_or_else(|_| panic!("External_url {} is an invalid URL.", external_str));
                } else {
                    panic!("External url has to be specified after the comma : {}", listener);
                }
            } else {
                url = listener
                    .parse::<Url>()
                    .unwrap_or_else(|_| panic!("Listener {} is an invalid URL.", listener));
                external_url = format!(
                    "{}://{}:{}",
                    url.scheme(),
                    config.hostname,
                    url.port_or_known_default().unwrap_or(8080)
                )
                .parse::<Url>()
                .unwrap_or_else(|_| panic!("External url can't be built based on listener {}", listener));
            }

            listeners.push(ListenerConfig { url, external_url });
        }

        if !listeners.is_empty() {
            config.listeners = listeners;
        }

        // early fail if we start without any listeners
        if config.listeners.is_empty() {
            panic!("At least one listener has to be specified.");
        }

        // early fail if we start as restricted without provisioner key
        if !config.unrestricted && config.provisioner_public_key.is_none() {
            panic!("provisioner public key is missing in unrestricted mode");
        }

        config
    }

    pub fn load_from_file(file_path: PathBuf) -> Option<Self> {
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
                    listener.internal_url.to_string(),
                    listener.external_url.to_string()
                );
            }
        }

        for listener in listeners.iter_mut() {
            // normalize all listeners to http/https
            url_map_scheme_ws_to_http(&mut listener.url);
            url_map_scheme_ws_to_http(&mut listener.external_url);
        }

        let http_listeners: Vec<ListenerConfig> = listeners
            .iter()
            .filter(|listener| match listener.url.scheme() {
                "http" => true,
                "https" => true,
                _ => false,
            })
            .cloned()
            .collect();

        if http_listeners.is_empty() {
            eprintln!("At least one HTTP listener is required");
            return None;
        }

        for listener in listeners.iter_mut() {
            // normalize all listeners to ws/wss
            url_map_scheme_http_to_ws(&mut listener.url);
            url_map_scheme_http_to_ws(&mut listener.external_url);
        }

        let application_protocols = config_file.application_protocols.unwrap_or_default();

        let gateway_log_file = config_file.log_file.unwrap_or_else(|| "gateway.log".to_string());
        let log_file = get_program_data_file_path(gateway_log_file.as_str())
            .to_str()
            .unwrap()
            .to_string();

        let certificate_file = config_file
            .certificate_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());

        let private_key_file = config_file
            .private_key_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());

        let provisioner_public_key_file = config_file
            .provisioner_public_key_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());

        let provisioner_public_key_pem = provisioner_public_key_file
            .as_ref()
            .map(|file| std::fs::read_to_string(Path::new(file)).unwrap());
        let provisioner_public_key = provisioner_public_key_pem
            .map(|pem| pem.parse::<Pem>().unwrap())
            .as_ref()
            .map(|pem| PublicKey::from_pem(pem).unwrap());

        let delegation_private_key_file = config_file
            .delegation_private_key_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());

        let delegation_private_key_pem = delegation_private_key_file
            .as_ref()
            .map(|file| std::fs::read_to_string(Path::new(file)).unwrap());
        let delegation_private_key = delegation_private_key_pem
            .map(|pem| pem.parse::<Pem>().unwrap())
            .as_ref()
            .map(|pem| PrivateKey::from_pem(pem).unwrap());

        // unstable options (subject to change)
        let api_key = config_file.api_key;
        let unrestricted = config_file.unrestricted.unwrap_or(true);
        let capture_path = config_file.capture_path;

        // We always create a dummy API listener because Saphir needs one.
        // However, this API listener is unable to process WebSocket traffic.
        // Create the API listener as a dummy listener to make Saphir happy,
        // but in fact we just ignore it and use only our gateway listeners.
        let default_api_listener_url = format!("http://0.0.0.0:{}", DEFAULT_HTTP_LISTENER_PORT);
        let api_listener_url = config_file.api_listener.unwrap_or(default_api_listener_url);
        let api_listener = api_listener_url
            .parse::<Url>()
            .unwrap_or_else(|e| panic!("API listener URL is invalid: {}", e));

        Some(Config {
            unrestricted,
            api_key,
            listeners,
            farm_name,
            hostname,
            capture_path,
            log_file: Some(log_file),
            application_protocols,
            certificate: CertificateConfig {
                certificate_file,
                private_key_file,
                ..Default::default()
            },
            api_listener,
            provisioner_public_key,
            delegation_private_key,
            ..Default::default()
        })
    }

    #[allow(dead_code)]
    pub fn is_rdp_supported(&self) -> bool {
        self.application_protocols.contains(&"rdp".to_string())
    }
}
