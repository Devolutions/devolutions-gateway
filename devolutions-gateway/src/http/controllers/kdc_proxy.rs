use std::sync::Arc;
use saphir::controller::Controller;
use saphir::http::{Method, StatusCode};
use crate::http::HttpErrorStatus;
use saphir::macros::controller;
use crate::config::Config;
use saphir::response::Builder;
use saphir::request::Request;

pub struct KdcProxyController {
    config: Arc<Config>,
}

impl KdcProxyController {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[controller(name = "KdcProxy")]
impl KdcProxyController {
    #[post("/")]
    async fn proxy_kdc_message2(&self, req: Request) -> Result<Builder, HttpErrorStatus> {
        let data = req.load_body().await.unwrap().body().to_vec();
        println!("{:?}", data);
        Ok(Builder::new().body("ok").status(200))
    }
}
