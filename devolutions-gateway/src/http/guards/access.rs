use crate::http::HttpErrorStatus;
use jet_proto::token::{JetAccessScope, JetAccessTokenClaims};
use saphir::prelude::*;

#[derive(Deserialize)]
pub enum JetTokenType {
    Scope(JetAccessScope),
    Bridge,
    Association,
}

pub struct AccessGuard {
    token_type: JetTokenType,
}

#[guard]
impl AccessGuard {
    pub fn new(token_type: JetTokenType) -> Self {
        AccessGuard { token_type }
    }

    async fn validate(&self, req: Request) -> Result<Request, HttpErrorStatus> {
        if let Some(claims) = req.extensions().get::<JetAccessTokenClaims>() {
            match (claims, &self.token_type) {
                (JetAccessTokenClaims::Association(_), JetTokenType::Association) => {
                    return Ok(req);
                }
                (JetAccessTokenClaims::Scope(scope_from_request), JetTokenType::Scope(scope_needed))
                    if scope_from_request.scope == *scope_needed =>
                {
                    return Ok(req);
                }
                (JetAccessTokenClaims::Bridge(_), JetTokenType::Bridge) => {
                    return Ok(req);
                }
                _ => {}
            }
        }

        Err(HttpErrorStatus::forbidden(
            "Token provided can't be used to access the route",
        ))
    }
}
