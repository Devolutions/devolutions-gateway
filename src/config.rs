use clap::App;
use clap::Arg;
use std::net::SocketAddr;
use url::Url;

pub struct Config {
    listener_url: String,
    routing_url: Option<SocketAddr>
}

impl Config {
    pub fn listener_url(&self) -> String {
        self.listener_url.clone()
    }

    pub fn routing_url(&self) -> Option<SocketAddr> {
        self.routing_url.clone()
    }

    pub fn init() -> Self {
        let cli_app = App::new(crate_name!())
            .author("Devolutions")
            .version(concat!(crate_version!(), "\n"))
            .version_short("v")
            .about("Wayk-Jet proxy")
            .arg(
                Arg::with_name("listener-url")
                    .short("u")
                    .long("url")
                    .value_name("LISTENER_URL")
                    .help("An address on which the server will listen on. Format: tcp://<local_iface_ip>:<port>")
                    .long_help("An address on which the server will listen on. Format: tcp://<local_iface_ip>:<port>")
                    .takes_value(true)
                    .default_value("tcp://0.0.0.0:8080")
                    .empty_values(false),
            )
            .arg(
                Arg::with_name("routing-url")
                    .short("r")
                    .long("routing_url")
                    .value_name("ROUTING_URL")
                    .help("An address on which the server will route all packet. Format: tcp://<ip>:<port>")
                    .long_help("An address on which the server will route all packet. Format: tcp://<ip>:<port>")
                    .takes_value(true)
                    .empty_values(false)
            );

        let matches = cli_app.get_matches();

        let listener_url = String::from(matches.value_of("listener-url").expect("This should never happend"));

        let routing_url =
            if let Some(url) = matches.value_of("routing-url") {
                let url = Url::parse(&url).expect(&format!("Routing url invalide {}", url));
                let host = url.host_str().expect("Host not specified");
                let port = url.port().map(|port| port.to_string()).expect("Port not specified");

                let mut routing_addr = String::new();
                routing_addr.push_str(&host);
                routing_addr.push_str(":");
                routing_addr.push_str(&port);

                Some(routing_addr.parse::<SocketAddr>().expect("Routing url invalid"))
            }
            else {
                None
            };

        Config {
            listener_url,
            routing_url,
        }
    }
}
