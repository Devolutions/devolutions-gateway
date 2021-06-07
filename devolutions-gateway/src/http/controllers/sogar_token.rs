use crate::config::{Config, SogarUser};
use picky::{
    jose::{jws::JwsAlg, jwt::JwtSig},
    key::PrivateKey,
};
use saphir::{
    controller::Controller,
    http::{Method, StatusCode},
    macros::controller,
    prelude::Request,
};
use serde::{Deserialize, Serialize};
use slog_scope::error;
use sogar_core::AccessToken;
use std::sync::Arc;

pub struct TokenController {
    config: Arc<Config>,
}

impl TokenController {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

#[controller(name = "registry")]
impl TokenController {
    #[post("/oauth2/token")]
    async fn get_token(&self, mut req: Request) -> (StatusCode, Option<String>) {
        match req.form::<AccessToken>().await {
            Ok(body) => {
                let password_out = body.password.clone();
                let username_out = body.username;

                let config = self.config.clone();

                for user in &config.sogar_user {
                    if let (Some(username), Some(hashed_password)) = (&user.username, &user.password) {
                        if username == &username_out {
                            let matched = argon2::verify_encoded(hashed_password.as_str(), password_out.as_bytes());
                            if matched.is_err() || !matched.unwrap() {
                                return (StatusCode::UNAUTHORIZED, None);
                            }

                            return create_token(&config.delegation_private_key, user);
                        }
                    }
                }

                (StatusCode::UNAUTHORIZED, None)
            }
            Err(e) => {
                error!("Failed to read request body! Error is {}", e);
                (StatusCode::BAD_REQUEST, None)
            }
        }
    }
}

fn create_token(private_key: &Option<PrivateKey>, user: &SogarUser) -> (StatusCode, Option<String>) {
    #[derive(Serialize, Deserialize, Debug)]
    struct ResponseAccessToken {
        access_token: String,
    }

    match private_key {
        Some(private_key) => {
            let signed_result = JwtSig::new(JwsAlg::RS256, user).encode(private_key);

            match signed_result {
                Ok(access_token) => {
                    let response = ResponseAccessToken { access_token };

                    match serde_json::to_string(&response) {
                        Ok(token) => (StatusCode::OK, Some(token)),
                        Err(e) => {
                            error!("Failed serialize token! Error is {}", e);
                            (StatusCode::BAD_REQUEST, None)
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create token! Error is {}", e);
                    (StatusCode::BAD_REQUEST, None)
                }
            }
        }
        None => {
            error!("Private key is missing. Not able to create the jwt token.");
            (StatusCode::BAD_REQUEST, None)
        }
    }
}
