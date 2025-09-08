use devolutions_gateway::openapi::{ApiDoc, SubscriberApiDoc};
use utoipa::OpenApi;

#[cfg(target_os = "windows")]
fn pedm_yaml() -> String {
    serde_yaml::to_string(&devolutions_pedm::api::openapi()).unwrap()
}

#[cfg(not(target_os = "windows"))]
fn pedm_yaml() -> String {
    panic!("Not supported for this target")
}

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
        Some("pedm") => pedm_yaml(),
        _ => panic!("unknown API doc"),
    };
    println!("{yaml}");
}
