use crate::config::Config;
use saphir::{Method, *};
use std::sync::Arc;

struct ControllerData {
    config: Arc<Config>,
}

pub struct HealthController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl HealthController {
    pub fn new(config: Arc<Config>) -> Self {
        let dispatch = ControllerDispatch::new(ControllerData { config });
        dispatch.add(Method::GET, "/", health);

        HealthController { dispatch }
    }
}

impl Controller for HealthController {
    fn handle(&self, req: &mut SyncRequest, res: &mut SyncResponse) {
        self.dispatch.dispatch(req, res);
    }

    fn base_path(&self) -> &str {
        "/health"
    }
}

fn health(controller: &ControllerData, _req: &SyncRequest, res: &mut SyncResponse) {
    build_health_response(res, &controller.config.hostname);
}

pub fn build_health_response(res: &mut SyncResponse, hostname: &str) {
    res.status(StatusCode::OK)
        .body(format!("Devolutions Gateway \"{}\" is alive and healthy.", hostname));
}
