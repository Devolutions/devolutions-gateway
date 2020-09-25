
pub struct GatewayService {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
}

impl GatewayService {
    pub fn load() -> Option<Self> {    
        let service_name = "devolutions-gateway";
        let display_name = "Devolutions Gateway";
        let description = "Devolutions Gateway service";
    
        Some(GatewayService {
            service_name: service_name.to_string(),
            display_name: display_name.to_string(),
            description: description.to_string(),
        })
    }

    pub fn get_service_name(&self) -> &str {
        self.service_name.as_str()
    }

    pub fn get_display_name(&self) -> &str {
        self.display_name.as_str()
    }

    pub fn get_description(&self) -> &str {
        self.description.as_str()
    }

    pub fn start(&self) {

    }

    pub fn stop(&self) {

    }
}
