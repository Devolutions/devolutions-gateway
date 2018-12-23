use clap::App;
use clap::Arg;

pub struct Config {
    listener_url: String,
    routing_url: Option<String>,
}

impl Config {
    pub fn listener_url(&self) -> String {
        self.listener_url.clone()
    }

    pub fn routing_url(&self) -> Option<String> {
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
                    .empty_values(false),
            );

        let matches = cli_app.get_matches();

        let listener_url = String::from(matches.value_of("listener-url").expect("This should never happend"));

        let routing_url = matches.value_of("routing-url").map(|url| url.to_string());

        Config {
            listener_url,
            routing_url,
        }
    }
}
