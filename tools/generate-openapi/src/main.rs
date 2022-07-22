use devolutions_gateway::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let api = ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&api).unwrap();
    println!("{yaml}");
}
