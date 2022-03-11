use crate::config::Config;
use crate::http::guards::access::{AccessGuard, TokenType};
use crate::http::HttpErrorStatus;
use crate::token::{AccessTokenClaims, CurrentJrl, JetAccessScope};
use saphir::prelude::*;
use std::io::BufWriter;
use std::sync::Arc;
use tap::Pipe as _;
use uuid::Uuid;

pub struct JrlController {
    config: Arc<Config>,
    revocation_list: Arc<CurrentJrl>,
}

impl JrlController {
    pub fn new(config: Arc<Config>, revocation_list: Arc<CurrentJrl>) -> Self {
        Self {
            config,
            revocation_list,
        }
    }
}

#[controller(name = "jet/jrl")]
impl JrlController {
    #[post("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Jrl"#)]
    async fn update_jrl(&self, mut req: Request) -> Result<(), HttpErrorStatus> {
        let claims = req
            .extensions_mut()
            .remove::<AccessTokenClaims>()
            .ok_or_else(|| HttpErrorStatus::unauthorized("identity is missing (token)"))?;

        if let AccessTokenClaims::Jrl(claims) = claims {
            let config = self.config.clone();

            let claims = tokio::task::spawn_blocking(move || {
                let jrl_file = config
                    .jrl_file
                    .as_deref()
                    .ok_or_else(|| HttpErrorStatus::internal("JRL file path is missing"))?;

                info!("Writing JRL file to disk (path: {jrl_file})");

                std::fs::File::options()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(jrl_file)
                    .map_err(HttpErrorStatus::internal)?
                    .pipe(BufWriter::new)
                    .pipe(|w| serde_json::to_writer_pretty(w, &claims))
                    .map_err(HttpErrorStatus::internal)?;

                Ok::<_, HttpErrorStatus>(claims)
            })
            .await
            .map_err(HttpErrorStatus::internal)??;

            *self.revocation_list.lock() = claims;

            info!("Current JRL updated!");

            Ok(())
        } else {
            Err(HttpErrorStatus::forbidden("token not allowed"))
        }
    }

    #[get("/")]
    #[guard(AccessGuard, init_expr = r#"TokenType::Scope(JetAccessScope::GatewayJrlRead)"#)]
    async fn get_jrl_info(&self) -> Json<JrlInfo> {
        let revocation_list = self.revocation_list.lock();
        Json(JrlInfo {
            jti: revocation_list.jti,
            iat: revocation_list.iat,
        })
    }
}

#[derive(Serialize)]
struct JrlInfo {
    pub jti: Uuid,
    pub iat: i64,
}
