use saphir::Method;
use saphir::*;

struct ControllerData {}

pub struct HealthController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl HealthController {
    pub fn new() -> Self {
        let dispatch = ControllerDispatch::new(ControllerData {});
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

fn health(_: &ControllerData, _req: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::OK).body("I'm here and I'm alive, that's enough");
}
