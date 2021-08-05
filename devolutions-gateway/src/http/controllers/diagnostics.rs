use crate::config::Config;
use crate::http::guards::access::{AccessGuard, JetTokenType};
use crate::http::HttpErrorStatus;
use jet_proto::token::JetAccessScope;
use saphir::prelude::*;
use std::sync::Arc;

pub struct DiagnosticsController {
    config: Arc<Config>,
}

impl DiagnosticsController {
    pub fn new(config: Arc<Config>) -> Self {
        DiagnosticsController { config }
    }
}

#[controller(name = "diagnostics")]
impl DiagnosticsController {
    #[get("/logs")]
    #[guard(
        AccessGuard,
        init_expr = r#"JetTokenType::Scope(JetAccessScope::GatewayDiagnosticsRead)"#
    )]
    async fn get_logs(&self) -> Result<File, HttpErrorStatus> {
        let log_file_path = self
            .config
            .log_file
            .as_ref()
            .ok_or_else(|| HttpErrorStatus::not_found("Log file is not configured"))?;
        File::open(log_file_path).await.map_err(HttpErrorStatus::internal)
    }
}
