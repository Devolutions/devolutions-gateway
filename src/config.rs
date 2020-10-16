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

const ARG_RDP: &str = "rdp";
const ARG_API_KEY: &str = "api-key";
const ARG_UNRESTRICTED: &str = "unrestricted";
const ARG_LISTENERS: &str = "listeners";
const ARG_HTTP_LISTENER_URL: &str = "http-listener-url";
const ARG_JET_INSTANCE: &str = "jet-instance";
const ARG_CERTIFICATE_FILE: &str = "certificate-file";
const ARG_CERTIFICATE_DATA: &str = "certificate-data";
const ARG_PRIVATE_KEY_FILE: &str = "private-key-file";
const ARG_PRIVATE_KEY_DATA: &str = "private-key-data";
const ARG_PROVISIONER_PUBLIC_KEY_FILE: &str = "provisioner-public-key-file";
const ARG_PROVISIONER_PUBLIC_KEY_DATA: &str = "provisioner-public-key-data";
const ARG_DELEGATION_PRIVATE_KEY_FILE: &str = "delegation-private-key-file";
const ARG_DELEGATION_PRIVATE_KEY_DATA: &str = "delegation-private-key-data";
const ARG_ROUTING_URL: &str = "routing-url";
const ARG_PCAP_FILES_PATH: &str = "pcap-files-path";
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
    } else if #[cfg(target_os = "macos")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
    } else {
        const COMPANY_DIR: &str = "devolutions";
        const PROGRAM_DIR: &str = "gateway";
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

#[derive(Debug, Clone)]
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
    pub jet_instance: String,
    pub routing_url: Option<Url>,
    pub pcap_files_path: Option<String>,
    pub protocol: Protocol,
    pub log_file: Option<String>,
    pub rdp: bool, // temporary
    pub certificate: CertificateConfig,
    pub http_listener_url: Url,
    pub provisioner_public_key: Option<PublicKey>,
    pub delegation_private_key: Option<PrivateKey>,
}

#[derive(Serialize, Deserialize)]
pub struct GatewayListener {
    #[serde(rename = "InternalUrl")]
    pub internal_url: String,
    #[serde(rename = "ExternalUrl")]
    pub external_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(rename = "GatewayFarmName")]
    pub farm_name: Option<String>,
    #[serde(rename = "GatewayHostname")]
    pub hostname: Option<String>,
    #[serde(rename = "GatewayListeners")]
    pub listeners: Vec<GatewayListener>,
    #[serde(rename = "CertificateFile")]
    pub certificate_file: Option<String>,
    #[serde(rename = "PrivateKeyFile")]
    pub private_key_file: Option<String>,
    #[serde(rename = "ProvisionerPublicKeyFile")]
    pub provisioner_public_key_file: Option<String>,
    #[serde(rename = "DelegationPrivateKeyFile")]
    pub delegation_private_key_file: Option<String>,
}

pub fn get_working_dir() -> PathBuf {
    let mut working_dir = PathBuf::new();

    if cfg!(target_os = "windows") {
        let program_data_env = env::var("ProgramData").unwrap();
        working_dir.push(Path::new(program_data_env.as_str()));
        working_dir.push(COMPANY_DIR);
        working_dir.push(PROGRAM_DIR);
    } else if cfg!(target_os = "macos") {
        working_dir.push("/Library/Application Support");
        working_dir.push(COMPANY_DIR);
        working_dir.push(PROGRAM_DIR);
    } else {
        working_dir.push("/etc");
        working_dir.push(COMPANY_DIR);
        working_dir.push(PROGRAM_DIR);
    }

    working_dir
}

pub fn get_config_file() -> Option<ConfigFile> {
    let mut config_path = get_working_dir();
    config_path.push("config.json");
    let file = File::open(config_path.as_path()).ok()?;
    let result = serde_json::from_reader(BufReader::new(file));
    result.ok()
}

pub fn get_program_data_file_path(filename: &str) -> PathBuf {
    let file_path = PathBuf::from(filename);
    if file_path.is_absolute() {
        file_path
    } else {
        get_working_dir().join(file_path.file_name().unwrap())
    }
}

fn get_default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

impl Config {
    pub fn load() -> Option<Self> {
        let service_mode = env::args().any(|arg| arg == "--service");

        let config_file = get_config_file()?;

        let default_hostname = get_default_hostname().unwrap_or("localhost".to_string());
        let gateway_hostname = config_file.hostname.unwrap_or(default_hostname.clone());
        let farm_name = config_file.farm_name.unwrap_or(gateway_hostname.clone());

        let mut listeners = Vec::new();
        for listener in config_file.listeners {
            let mut internal_url = listener.internal_url.parse::<Url>().expect("invalid internal URL");
            let mut external_url = listener.external_url.parse::<Url>().expect("invalid external URL");

            if internal_url.host_str() == Some("*") {
                let _ = internal_url.set_host(Some("0.0.0.0"));
            }

            if external_url.host_str() == Some("*") {
                let _ = external_url.set_host(Some(gateway_hostname.as_str()));
            }

            listeners.push(ListenerConfig {
                url: internal_url,
                external_url: external_url,
            });
        }

        let http_listeners: Vec<ListenerConfig> = listeners
            .iter()
            .filter(|listener| match listener.url.scheme() {
                "http" => true,
                "https" => true,
                _ => false,
            })
            .map(|listener| listener.clone())
            .collect();

        let http_listener_url = http_listeners
            .get(0)
            .expect("Expected at least one HTTP listener")
            .url
            .clone();

        let relay_listeners: Vec<ListenerConfig> = listeners
            .iter()
            .filter(|listener| match listener.url.scheme() {
                "ws" => true,
                "wss" => true,
                "tcp" => true,
                "rdp" => true,
                _ => false,
            })
            .map(|listener| listener.clone())
            .collect();

        if relay_listeners.is_empty() {
            panic!("At least one relay listener has to be specified");
        }

        let log_file = get_program_data_file_path("gateway.log").to_str().unwrap().to_string();

        let certificate_file = config_file
            .certificate_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());
        let certificate_data = certificate_file
            .as_ref()
            .map(|file| std::fs::read_to_string(Path::new(file)).unwrap());

        let private_key_file = config_file
            .private_key_file
            .as_ref()
            .map(|file| get_program_data_file_path(file).as_path().to_str().unwrap().to_string());
        let private_key_data = private_key_file
            .as_ref()
            .map(|file| std::fs::read_to_string(Path::new(file)).unwrap());

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

        Some(Config {
            service_mode: service_mode,
            service_name: SERVICE_NAME.to_string(),
            display_name: DISPLAY_NAME.to_string(),
            description: DESCRIPTION.to_string(),
            company_name: COMPANY_NAME.to_string(),
            unrestricted: true,
            api_key: None,
            listeners: relay_listeners,
            http_listener_url: http_listener_url,
            farm_name: farm_name,
            jet_instance: gateway_hostname,
            routing_url: None,
            pcap_files_path: None,
            protocol: Protocol::UNKNOWN,
            log_file: Some(log_file),
            rdp: true,
            certificate: CertificateConfig {
                certificate_file: certificate_file,
                certificate_data: certificate_data,
                private_key_file: private_key_file,
                private_key_data: private_key_data,
            },
            provisioner_public_key: provisioner_public_key,
            delegation_private_key: delegation_private_key,
        })
    }

    pub fn init() -> Self {
        let default_http_listener_url = format!("http://0.0.0.0:{}", DEFAULT_HTTP_LISTENER_PORT);

        let cli_app = App::new(crate_name!())
            .author("Devolutions Inc.")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about(DISPLAY_NAME)
            .arg(
                Arg::with_name(ARG_RDP)
                    .long("rdp")
                    .takes_value(false)
                    .required(false)
                    .help("Enable RDP/TCP and RDP/TLS in all TCP listeners (temporary)"),
            )
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
                Arg::with_name(ARG_HTTP_LISTENER_URL)
                    .long("http-listener-url")
                    .value_name("URL")
                    .env("JET_HTTP_LISTENER_URL")
                    .help("HTTP listener URL.")
                    .takes_value(true)
                    .default_value(&default_http_listener_url),
            )
            .arg(
                Arg::with_name(ARG_JET_INSTANCE)
                    .long("jet-instance")
                    .value_name("NAME")
                    .env("JET_INSTANCE")
                    .help("Specific name to reach that instance of JET.")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name(ARG_CERTIFICATE_FILE)
                    .long("certificate-file")
                    .value_name("FILE")
                    .env("JET_CERTIFICATE_FILE")
                    .help("Path to the certificate file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_CERTIFICATE_DATA)
                    .long("certificate-data")
                    .value_name("DATA")
                    .env("JET_CERTIFICATE_DATA")
                    .help("Certificate data, base64-encoded X509 DER.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PRIVATE_KEY_FILE)
                    .long("private-key-file")
                    .value_name("FILE")
                    .env("JET_PRIVATE_KEY_FILE")
                    .help("Path to the private key file.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PRIVATE_KEY_DATA)
                    .long("private-key-data")
                    .value_name("DATA")
                    .env("JET_PRIVATE_KEY_DATA")
                    .help("Private key data, base64-encoded PKCS10.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name(ARG_PROVISIONER_PUBLIC_KEY_FILE)
                    .long("provisioner-public-key-file")
                    .value_name("FILE")
                    .env("JET_PROVISIONER_PUBLIC_KEY_FILE")
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
                Arg::with_name(ARG_PCAP_FILES_PATH)
                    .long("pcap-files-path")
                    .value_name("PATH")
                    .help(
                        "Path to the pcap files. If not set, no pcap files will be created. \
                         WaykNow and RDP protocols can be saved.",
                    )
                    .long_help(
                        "Path to the pcap files. If not set, no pcap files will be created. \
                         WaykNow and RDP protocols can be saved.",
                    )
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
                    .required(false)
                    .help("Enable service mode"),
            );

        let matches = cli_app.get_matches();

        let service_mode = matches.is_present(ARG_SERVICE_MODE);

        let log_file = matches.value_of(ARG_LOG_FILE).map(String::from);

        let service_name = SERVICE_NAME.to_string();
        let display_name = DISPLAY_NAME.to_string();
        let description = DESCRIPTION.to_string();
        let company_name = COMPANY_NAME.to_string();

        let api_key = matches.value_of(ARG_API_KEY).map(std::string::ToString::to_string);

        let unrestricted = matches.is_present(ARG_UNRESTRICTED);
        let rdp = matches.is_present(ARG_RDP);

        let http_listener_url = matches
            .value_of(ARG_HTTP_LISTENER_URL)
            .unwrap()
            .parse::<Url>()
            .unwrap_or_else(|e| panic!("HTTP listener URL is invalid: {}", e));

        let jet_instance = matches
            .value_of(ARG_JET_INSTANCE)
            .unwrap() // enforced by clap
            .to_string();

        let farm_name = jet_instance.clone();

        let routing_url = matches
            .value_of(ARG_ROUTING_URL)
            .map(|v| Url::parse(&v).expect("must be checked in the clap validator"));

        let pcap_files_path = matches
            .value_of(ARG_PCAP_FILES_PATH)
            .map(std::string::ToString::to_string);

        let protocol = match matches.value_of(ARG_PROTOCOL) {
            Some("wayk") => Protocol::WAYK,
            Some("rdp") => Protocol::RDP,
            _ => Protocol::UNKNOWN,
        };

        let certificate_file = matches.value_of(ARG_CERTIFICATE_FILE).map(String::from);
        let certificate_data = matches.value_of(ARG_CERTIFICATE_DATA).map(String::from);
        let private_key_file = matches.value_of(ARG_PRIVATE_KEY_FILE).map(String::from);
        let private_key_data = matches.value_of(ARG_PRIVATE_KEY_DATA).map(String::from);

        // provisioner key

        let provisioner_public_key_pem = matches
            .value_of(ARG_PROVISIONER_PUBLIC_KEY_DATA)
            .map(|base64| format!("-----BEGIN PUBLIC KEY-----{}-----END PUBLIC KEY-----", base64));
        let provisioner_public_key_path = matches.value_of(ARG_PROVISIONER_PUBLIC_KEY_FILE);

        let pem_str = if let Some(pem) = provisioner_public_key_pem {
            Some(pem)
        } else if let Some(path) = provisioner_public_key_path {
            Some(std::fs::read_to_string(path).expect("couldn't read provisioner public path key file"))
        } else {
            None
        };

        let provisioner_public_key = pem_str.map(|pem_str| {
            let pem = pem_str
                .parse::<Pem>()
                .expect("couldn't parse provisioner public key pem");
            PublicKey::from_pem(&pem).expect("couldn't parse provisioner public key")
        });

        // delegation key

        let delegation_private_key_pem = matches
            .value_of(ARG_DELEGATION_PRIVATE_KEY_DATA)
            .map(|base64| format!("-----BEGIN PUBLIC KEY-----{}-----END PUBLIC KEY-----", base64));
        let delegation_private_key_path = matches.value_of(ARG_DELEGATION_PRIVATE_KEY_FILE);

        let pem_str = if let Some(pem) = delegation_private_key_pem {
            Some(pem)
        } else if let Some(path) = delegation_private_key_path {
            Some(std::fs::read_to_string(path).expect("couldn't read delegation private path key file"))
        } else {
            None
        };

        let delegation_private_key = pem_str.map(|pem_str| {
            let pem = pem_str
                .parse::<Pem>()
                .expect("couldn't parse delegation private key pem");
            PrivateKey::from_pem(&pem).expect("couldn't parse delegation private key")
        });

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
                    let external_str = external_str.replace("<jet_instance>", &jet_instance);
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
                    jet_instance,
                    url.port_or_known_default().unwrap_or(8080)
                )
                .parse::<Url>()
                .unwrap_or_else(|_| panic!("External url can't be built based on listener {}", listener));
            }

            listeners.push(ListenerConfig { url, external_url });
        }

        if listeners.is_empty() {
            panic!("At least one listener has to be specified.");
        }

        Config {
            service_mode,
            service_name,
            display_name,
            description,
            company_name,
            unrestricted,
            api_key,
            listeners,
            http_listener_url,
            farm_name: farm_name,
            jet_instance,
            routing_url,
            pcap_files_path,
            protocol,
            log_file,
            rdp,
            certificate: CertificateConfig {
                certificate_file,
                certificate_data,
                private_key_file,
                private_key_data,
            },
            provisioner_public_key,
            delegation_private_key,
        }
    }
}
