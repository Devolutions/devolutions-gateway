use saphir::*;
use log::error;
use crate::config::Config;

pub struct AuthMiddleware {
    config: Config
}

impl AuthMiddleware {
    pub fn new(config: Config) -> Self {
        AuthMiddleware {
            config
        }
    }
}

impl Middleware for AuthMiddleware {
    fn resolve(&self, req: &mut SyncRequest, res: &mut SyncResponse) -> RequestContinuation {
        if let Some(api_key) = self.config.api_key() {
            let auth_header = match req.headers_map().get(header::AUTHORIZATION) {
                Some(h) => h.clone(),
                None => {
                    error!("Authorization header not present in request.");
                    res.status(StatusCode::UNAUTHORIZED);
                    return RequestContinuation::Stop;
                }
            };

            let auth_str = match auth_header.to_str() {
                Ok(s) => s,
                Err(_) => {
                    error!("Authorization header wrong format");
                    res.status(StatusCode::UNAUTHORIZED);
                    return RequestContinuation::Stop;
                }
            };

            match parse_auth_header(auth_str) {
                Some((AuthHeaderType::Bearer, token)) => {
                    // API_KEY
                    if let Some(api_key) = self.config.api_key() {
                        if api_key == token {
                            return RequestContinuation::Continue;
                        }
                    }
                }
                _ => {
                    error!("Invalid authorization type");
                }
            }

            res.status(StatusCode::UNAUTHORIZED);
            RequestContinuation::Stop

        } else {
            // API_KEY not defined, we accept everything
            RequestContinuation::Continue
        }
    }
}

#[derive(PartialEq)]
pub enum AuthHeaderType{
    Basic,
    Bearer,
    Signature,
}

pub fn parse_auth_header(auth_header: &str) -> Option<(AuthHeaderType, String)>{
    let auth_vec = auth_header.trim().split(' ').collect::<Vec<&str>>();

    if auth_vec.len() == 2 {
        return match auth_vec[0].to_lowercase().as_ref(){
            "basic" => Some((AuthHeaderType::Basic, auth_vec[1].to_string())),
            "bearer" => Some((AuthHeaderType::Bearer, auth_vec[1].to_string())),
            "signature" =>Some((AuthHeaderType::Signature, auth_vec[1].to_string())),
            _ => None
        };
    }

    None
}


