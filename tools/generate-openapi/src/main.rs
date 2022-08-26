use devolutions_gateway::openapi::{ApiDoc, SubscriberApiDoc};
use utoipa::OpenApi;

fn main() {
    let yaml = match std::env::args().nth(1).as_deref() {
        Some("subscriber") => {
            let mut api = SubscriberApiDoc::openapi();
            api.info.title = "devolutions-gateway-subscriber".to_owned();
            api.info.description =
                Some("API a service must implement in order to receive Devolutions Gateway notifications".to_owned());
            api.to_yaml().unwrap()
        }
        Some("gateway") | None => ApiDoc::openapi().to_yaml().unwrap(),
        _ => panic!("Unknown API doc"),
    };
    println!("{yaml}");
}
