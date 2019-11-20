use std::{env, error::Error, sync::Arc};
use slog_scope::warn;

use clap::{crate_name, crate_version, App, Arg};
use url::Url;

use crate::rdp;

const DEFAULT_HTTP_LISTENER_PORT: u32 = 10256;

#[derive(Debug, Clone)]
pub enum Protocol {
    WAYK,
    RDP,
    UNKNOWN,
}

struct ConfigTemp {
    unrestricted: bool,
    api_key: Option<String>,
    listeners: Vec<String>,
    jet_instance: Option<String>,
    routing_url: Option<String>,
    pcap_files_path: Option<String>,
    protocol: Protocol,
    rdp_identities: Option<rdp::IdentitiesProxy>,
    log_file: Option<String>,

    certificate: CertificateConfig,
    http_listener_url: String
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
    unrestricted: bool,
    api_key: Option<String>,
    listeners: Vec<ListenerConfig>,
    jet_instance: String,
    routing_url: Option<String>,
    pcap_files_path: Option<String>,
    protocol: Protocol,
    rdp_identities: Option<rdp::IdentitiesProxy>,
    log_file: Option<String>,

    pub certificate: CertificateConfig,
    pub http_listener_url: Url
}

impl Config {
    pub fn unrestricted(&self) -> bool {
        self.unrestricted
    }

    pub fn api_key(&self) -> Option<&String> {
        self.api_key.as_ref()
    }

    pub fn listeners(&self) -> &Vec<ListenerConfig> {
        &self.listeners
    }

    pub fn jet_instance(&self) -> &String {
        &self.jet_instance
    }

    pub fn routing_url(&self) -> Option<&String> {
        self.routing_url.as_ref()
    }

    pub fn pcap_files_path(&self) -> Option<&String> {
        self.pcap_files_path.as_ref()
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    pub fn rdp_identities(&self) -> Option<&rdp::IdentitiesProxy> {
        self.rdp_identities.as_ref()
    }

    pub fn log_file(&self) -> Option<&String> {
        self.log_file.as_ref()
    }

    pub fn init() -> Self {
        let default_http_listener_url = format!("http://0.0.0.0:{}", DEFAULT_HTTP_LISTENER_PORT);

        let cli_app = App::new(crate_name!())
            .author("Devolutions")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about("Devolutions-Jet proxy")
            .arg(Arg::with_name("api-key")
                .long("api-key")
                .value_name("JET_API_KEY")
                .help("The api key used by the server to authenticate client queries.")
                .takes_value(true)
                .empty_values(false))
            .arg(Arg::with_name("unrestricted")
                .long("unrestricted")
                .help("This flag remove the api_key validation on some http routes")
                .takes_value(false))
            .arg(Arg::with_name("listeners")
                .short("l")
                .long("listener")
                .value_name("LISTENER_URL")
                .help("An URL on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port>. Supported scheme: tcp, ws, wss")
                .long_help("An URL on which the server will listen on. The external URL returned as candidate can be specified after the listener, separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port>\
                If it is not specified, the external url will be <scheme>://<jet_instance>:<port> where <jet_instance> is the value of the jet-instance parameter.")
                .multiple(true)
                .takes_value(true)
                .number_of_values(1)
            )
            .arg(Arg::with_name("http-listener-url")
                .long("http-listener-url")
                .value_name("HTTP_LISTENER_URL")
                .help("HTTP listener url.")
                .takes_value(true)
                .default_value(&default_http_listener_url))
            .arg(Arg::with_name("jet-instance")
                .long("jet-instance")
                .value_name("JET_INSTANCE")
                .help("Specific name to reach that instance of JET.")
                .takes_value(true)
            )
            .arg(Arg::with_name("certificate-file")
                .long("certificate-file")
                .value_name("JET_CERTIFICATE_FILE")
                .help("Path to the certificate file.")
                .takes_value(true))
            .arg(Arg::with_name("private-key-file")
                .long("private-key-file")
                .value_name("JET_PRIVATE_KEY_FILE")
                .help("Path to the private key file.")
                .takes_value(true))
            .arg(Arg::with_name("certificate-data")
                .long("certificate-data")
                .value_name("JET_CERTIFICATE_DATA")
                .help("Certificate data, pem format.")
                .takes_value(true))
            .arg(Arg::with_name("private-key-data")
                .long("private-key-data")
                .value_name("JET_PRIVATE_KEY_DATA")
                .help("Private key data, pem format.")
                .takes_value(true))
            .arg(
                Arg::with_name("routing-url")
                    .short("r")
                    .long("routing-url")
                    .value_name("ROUTING_URL")
                    .help("An address on which the server will route all packets. Format: <scheme>://<ip>:<port>.")
                    .long_help("An address on which the server will route all packets. Format: <scheme>://<ip>:<port>. Scheme supported : tcp and tls. If it is not specified, the JET protocol will be used.")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name("pcap-files-path")
                    .short("f")
                    .long("pcap-files-path")
                    .value_name("PCAP_FILES_PATH")
                    .help("Path to the pcap files. If not set, no pcap files will be created. WaykNow and RDP protocols can be saved.")
                    .long_help("Path to the pcap files. If not set, no pcap files will be created. WaykNow and RDP protocols can be saved.")
                    .takes_value(true)
                    .empty_values(false)
                    .validator(|v| if std::path::PathBuf::from(v).is_dir() {
                        Ok(())
                    } else {
                        Err(String::from("The value does not exist or is not a path"))
                    })
                ,
            )
            .arg(
                Arg::with_name("protocol")
                    .short("p")
                    .long("protocol")
                    .value_name("PROTOCOL_NAME")
                    .help("Specify the application protocol used. Useful when pcap file is saved and you want to avoid application message in two different tcp packet.")
                    .long_help("Specify the application protocol used. Useful when pcap file is saved and you want to avoid application message in two different tcp packet. If protocol is unknown, we can't be sure that application packet is not split between 2 tcp packets.")
                    .takes_value(true)
                    .possible_values(&["wayk", "rdp"])
                    .empty_values(false)
            )
            .arg(
                Arg::with_name("log-file")
                    .long("log-file")
                    .value_name("LOG_FILE")
                    .help("A file with logs")
                    .takes_value(true)
                    .empty_values(false)
            )
            .arg(
                Arg::with_name("identities-file")
                    .short("i")
                    .long("identities-file")
                    .value_name("IDENTITIES_FILE")
                    .required_if("protocol", "rdp")
                    .help("A JSON-file with a list of identities: proxy credentials, target credentials, and target destination")
                    .long_help(r###"
JSON-file with a list of identities: proxy credentials, target credentials, and target destination.
Every credential must consist of 'username' and 'password' fields with a string,
and optional field 'domain', which also a string if it is present (otherwise - null).
The proxy object must be present with a 'proxy' name, the target object with a 'target' name.
The target destination must be a string with a target URL and be named 'destination'.
identities_file example:
'[
    {
        "proxy":{
            "username":"ProxyUser1",
            "password":"ProxyPassword1",
            "domain":null
        },
        "target":{
            "username":"TargetUser1",
            "password":"TargetPassword1",
            "domain":null
        },
        "destination":"192.168.1.2:3389"
    },
    {
        "proxy":{
            "username":"ProxyUser2",
            "password":"ProxyPassword2",
            "domain":"ProxyDomain2"
        },
        "target":{
            "username":"TargetUser1",
            "password":"TargetPassword2",
            "domain":"TargetDomain2"
        },
        "destination":"192.168.1.3:3389"
    }
]'"
                        "###)
                    .takes_value(true)
                    .empty_values(false)
                    .validator(|filename| match rdp::RdpIdentity::from_file(filename.as_str()) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(e.description().to_string())
                    }),
            );

        let matches = cli_app.get_matches();

        let api_key = matches.value_of("api-key").map(std::string::ToString::to_string);

        let unrestricted = matches.is_present("unrestricted");

        let listeners = matches.values_of("listeners").map_or(Vec::new(), |listeners| {
            listeners.into_iter().map(|listener| listener.to_string()).collect()
        });

        let http_listener_url = matches.value_of("http-listener-url").map(std::string::ToString::to_string).expect("");

        let jet_instance = matches.value_of("jet-instance").map(std::string::ToString::to_string);

        let routing_url = matches.value_of("routing-url").map(std::string::ToString::to_string);

        let pcap_files_path = matches
            .value_of("pcap-files-path")
            .map(std::string::ToString::to_string);

        let protocol = match matches.value_of("protocol") {
            Some("wayk") => Protocol::WAYK,
            Some("rdp") => Protocol::RDP,
            _ => Protocol::UNKNOWN,
        };

        let identities_filename = matches
            .value_of("identities-file")
            .map(std::string::ToString::to_string);
        let rdp_identities = if let Some(filename) = identities_filename {
            Some(rdp::IdentitiesProxy::new(Arc::new(
                rdp::RdpIdentity::from_file(filename.as_str()).unwrap(),
            )))
        } else {
            None
        };

        let log_file = matches.value_of("log-file").map(String::from);

        let certificate_file = matches.value_of("jet-certificate-file").map(String::from);
        let certificate_data = matches.value_of("jet-certificate-data").map(String::from);
        let private_key_file = matches.value_of("jet-private-key-file").map(String::from);
        let private_key_data = matches.value_of("jet-private-key-data").map(String::from);

        let mut config_temp = ConfigTemp {
            unrestricted,
            api_key,
            listeners,
            http_listener_url,
            jet_instance,
            routing_url,
            pcap_files_path,
            protocol,
            rdp_identities,
            log_file,

            certificate: CertificateConfig {
                certificate_file,
                certificate_data,
                private_key_file,
                private_key_data
            }
        };

        config_temp.apply_env_variables();

        config_temp.into()
    }
}

impl ConfigTemp {
    fn apply_env_variables(&mut self) {
        if let Ok(val) = env::var("JET_INSTANCE"){
            self.jet_instance = Some(val);
        }

        if let Ok(val) = env::var("JET_API_KEY") {
            self.api_key = Some(val);
        }

        if let Ok(val) = env::var("JET_UNRESTRICTED") {
            if let Ok(val) = val.to_lowercase().parse::<bool>() {
                self.unrestricted = val;
            }
            else {
                warn!("JET_UNRESTRICTED env. variable is not a boolean value. 'true' or 'false' accepted.");
            }
        }

        if let Ok(val) = env::var("JET_LISTENERS") {
            self.listeners = val.split(";").filter_map(|item: &str| {
                if !item.is_empty() {
                    Some(item.to_string())
                } else {
                    None
                }
            }).collect();
        }

        if let Ok(val) = env::var("JET_CERTIFICATE_FILE") {
            self.certificate.certificate_file = Some(val);
        }

        if let Ok(val) = env::var("JET_CERTIFICATE_DATA") {
            self.certificate.certificate_data = Some(val);
        }

        if let Ok(val) = env::var("JET_PRIVATE_KEY_FILE") {
            self.certificate.private_key_file = Some(val);
        }

        if let Ok(val) = env::var("JET_PRIVATE_KEY_DATA") {
            self.certificate.private_key_data = Some(val);
        }

        if let Ok(val) = env::var("JET_HTTP_LISTENER_URL") {
            self.http_listener_url = val;
        }
    }
}

impl From<ConfigTemp> for Config {
    fn from(temp: ConfigTemp) -> Self {
        let mut listeners = Vec::new();

        let jet_instance = temp.jet_instance.expect("JET_INSTANCE is mandatory. It has to be added on the command line or defined by JET_INSTANCE environment variable.");

        for listener in &temp.listeners {
            let url;
            let external_url;

            if let Some(pos) = listener.find(",") {
                let url_str = &listener[0..pos];
                url = listener[0..pos].parse::<Url>().expect(&format!("Listener {} is an invalid URL.", url_str));

                if listener.len() > pos + 1 {
                    let external_str = listener[pos+1..].to_string();
                    let external_str = external_str.replace("<jet_instance>", &jet_instance);
                    external_url = external_str.parse::<Url>().expect(&format!("External_url {} is an invalid URL.", external_str));
                } else {
                    panic!("External url has to be specified after the comma : {}", listener);
                }
            } else {
                url = listener.parse::<Url>().expect(&format!("Listener {} is an invalid URL.", listener));
                external_url = format!("{}://{}:{}", url.scheme(), jet_instance, url.port_or_known_default().unwrap_or(8080)).parse::<Url>().expect(&format!("External_url can't be built based on listener {}", listener));
            }

            listeners.push(ListenerConfig {
                url,
                external_url
            });
        }

        if listeners.is_empty() {
            panic!("At least one listener has to be specified.");
        }

        let http_listener_url = temp.http_listener_url.parse::<Url>().expect(&format!("Http listener {} is an invalid URL", temp.http_listener_url));

        Config {
            unrestricted: temp.unrestricted,
            api_key: temp.api_key,
            listeners,
            http_listener_url,
            jet_instance: jet_instance,
            routing_url: temp.routing_url,
            pcap_files_path: temp.pcap_files_path,
            protocol: temp.protocol,
            rdp_identities: temp.rdp_identities,
            log_file: temp.log_file,

            certificate: temp.certificate,
        }
    }
}
