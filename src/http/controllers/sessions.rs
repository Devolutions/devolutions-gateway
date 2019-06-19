use crate::SESSION_IN_PROGRESS_COUNT;
use saphir::Method;
use saphir::*;
use std::sync::atomic::Ordering;

struct ControllerData {}

pub struct SessionsController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl SessionsController {
    pub fn new() -> Self {
        let dispatch = ControllerDispatch::new(ControllerData {});
        dispatch.add(Method::GET, "/count", sessions_count);

        SessionsController { dispatch }
    }
}

impl Controller for SessionsController {
    fn handle(&self, req: &mut SyncRequest, res: &mut SyncResponse) {
        self.dispatch.dispatch(req, res);
    }

    fn base_path(&self) -> &str {
        "/sessions"
    }
}

fn sessions_count(_: &ControllerData, _req: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::OK).body(
        SESSION_IN_PROGRESS_COUNT
            .load(Ordering::Relaxed)
            .to_string()
            .as_bytes()
            .to_vec(),
    );
}
