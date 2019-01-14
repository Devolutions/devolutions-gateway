use clap::{crate_name, crate_version, App, Arg};

#[derive(Clone)]
pub enum Protocol {
    WAYK,
    UNKNOWN
}

#[derive(Clone)]
pub struct Config {
    listener_url: String,
    routing_url: Option<String>,
    pcap_filename: Option<String>,
    protocol: Protocol
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
                    .help("Path of the file where the pcap file will be saved. If not set, no pcap file will be created. Only WaykNow protocol can be saved.")
                    .long_help("Path of the file where the pcap file will be saved. If not set, no pcap file will be created. Only WaykNow protocol can be saved.")
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
                    .possible_values(&["wayk"])
                    .empty_values(false)
            );

        let matches = cli_app.get_matches();

        let listener_url = String::from(matches.value_of("listener-url").expect("This should never happend"));

        let routing_url = matches.value_of("routing-url").map(|url| url.to_string());

        let pcap_filename = matches
            .value_of("pcap-filename")
            .map(|pcap_filename| pcap_filename.to_string());

        let protocol = match matches.value_of("protocol") {
            Some("wayk") => Protocol::WAYK,
            _ => Protocol::UNKNOWN,
        };


        Config {
            listener_url,
            routing_url,
            pcap_filename,
            protocol,
        }
    }
}
