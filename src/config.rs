use clap::{crate_name, crate_version, App, Arg};

#[derive(Clone)]
pub enum Protocol {
    WAYK,
    RDP,
    UNKNOWN,
}

#[derive(Clone)]
pub struct Config {
    listener_url: String,
    routing_url: Option<String>,
    pcap_filename: Option<String>,
    protocol: Protocol,
    identities_filename: Option<String>,
}

impl Config {
    pub fn listener_url(&self) -> String {
        self.listener_url.clone()
    }

    pub fn routing_url(&self) -> Option<String> {
        self.routing_url.clone()
    }

    pub fn pcap_filename(&self) -> Option<String> {
        self.pcap_filename.clone()
    }

    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    pub fn identities_filename(&self) -> Option<String> {
        self.identities_filename.clone()
    }

    pub fn init() -> Self {
        let cli_app = App::new(crate_name!())
            .author("Devolutions")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about("Devolutions-Jet proxy")
            .arg(
                Arg::with_name("listener-url")
                    .short("u")
                    .long("url")
                    .value_name("LISTENER_URL")
                    .help("An address on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port>")
                    .long_help("An address on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port>")
                    .takes_value(true)
                    .default_value("tcp://0.0.0.0:8080")
                    .empty_values(false),
            )
            .arg(
                Arg::with_name("routing-url")
                    .short("r")
                    .long("routing_url")
                    .value_name("ROUTING_URL")
                    .help("An address on which the server will route all packets. Format: <scheme>://<ip>:<port>.")
                    .long_help("An address on which the server will route all packets. Format: <scheme>://<ip>:<port>. Scheme supported : tcp and tls. If it is not specified, the JET protocol will be used.")
                    .takes_value(true)
                    .empty_values(false),
            )
            .arg(
                Arg::with_name("pcap-filename")
                    .short("f")
                    .long("pcap_file")
                    .value_name("PCAP_FILENAME")
                    .help("Path of the file where the pcap file will be saved. If not set, no pcap file will be created. WaykNow and RDP protocols can be saved.")
                    .long_help("Path of the file where the pcap file will be saved. If not set, no pcap file will be created. WaykNow and RDP protocols can be saved.")
                    .takes_value(true)
                    .empty_values(false),
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
                Arg::with_name("identities-file")
                    .short("i")
                    .long("identities_file")
                    .value_name("IDENTITIES_FILE")
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
                    .empty_values(false),
            );

        let matches = cli_app.get_matches();

        let listener_url = String::from(matches.value_of("listener-url").expect("This should never happend"));

        let routing_url = matches.value_of("routing-url").map(std::string::ToString::to_string);

        let pcap_filename = matches.value_of("pcap-filename").map(std::string::ToString::to_string);

        let protocol = match matches.value_of("protocol") {
            Some("wayk") => Protocol::WAYK,
            Some("rdp") => Protocol::RDP,
            _ => Protocol::UNKNOWN,
        };

        let identities_filename = matches
            .value_of("identities-file")
            .map(std::string::ToString::to_string);

        Config {
            listener_url,
            routing_url,
            pcap_filename,
            protocol,
            identities_filename,
        }
    }
}
