use devolutions_gateway::openapi::{ApiDoc, SubscriberApiDoc};
use utoipa::OpenApi;

fn main() {
    let yaml = match std::env::args().nth(1).as_deref() {
        Some("subscriber") => {
            let mut api = SubscriberApiDoc::openapi();
            api.info.title = String::from("devolutions-gateway-subscriber");
            api.info.description = Some(String::from(
                "API a service must implement in order to receive Devolutions Gateway notifications",
            ));
            api.to_yaml().unwrap()
        }
        Some("gateway") | None => ApiDoc::openapi().to_yaml().unwrap(),
        _ => panic!("Unknown API doc"),
    };
    println!("{yaml}");
}
