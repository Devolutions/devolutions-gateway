use crate::SESSION_IN_PROGRESS_COUNT;
use saphir::{
    controller::Controller,
    http::{Method, StatusCode},
    macros::controller,
};
use std::sync::atomic::Ordering;

pub struct SessionsController;

impl Default for SessionsController {
    fn default() -> Self {
        Self
    }
}

#[controller(name="sessions")]
impl SessionsController {
    #[get("/count")]
    async fn get_count(&self) -> (u16, String) {
        let sessions_count = SESSION_IN_PROGRESS_COUNT
            .load(Ordering::Relaxed)
            .to_string();
        (StatusCode::OK.as_u16(), sessions_count)
    }
}