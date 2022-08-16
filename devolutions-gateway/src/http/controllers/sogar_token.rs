use crate::config::{ConfHandle, SogarUser};
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::PrivateKey;
use saphir::controller::Controller;
use saphir::http::{Method, StatusCode};
use saphir::macros::controller;
use saphir::prelude::Request;
use serde::{Deserialize, Serialize};
use sogar_core::AccessToken;

pub struct TokenController {
    conf_handle: ConfHandle,
}

impl TokenController {
    pub fn new(conf_handle: ConfHandle) -> Self {
        Self { conf_handle }
    }
}

#[controller(name = "registry")]
impl TokenController {
    #[post("/oauth2/token")]
    async fn get_token(&self, mut req: Request) -> (StatusCode, Option<String>) {
        match req.form::<AccessToken>().await {
            Ok(body) => {
                let conf = self.conf_handle.get_conf();

                let password_out = body.password;
                let username_out = body.username;

                for user in &conf.sogar.user_list {
                    if let (Some(username), Some(hashed_password)) = (&user.username, &user.password) {
                        if username == &username_out {
                            let matched = argon2::verify_encoded(hashed_password.as_str(), password_out.as_bytes());
                            if matched.is_err() || !matched.unwrap() {
                                return (StatusCode::UNAUTHORIZED, None);
                            }

                            return create_token(&conf.delegation_private_key, user);
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
        Some(private_key) => match CheckedJwtSig::new(JwsAlg::RS256, user).encode(private_key) {
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
        },
        None => {
            error!("Private key is missing. Not able to create the jwt token.");
            (StatusCode::BAD_REQUEST, None)
        }
    }
}
