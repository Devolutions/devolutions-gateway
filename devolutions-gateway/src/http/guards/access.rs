use crate::http::HttpError;
use crate::token::{AccessScope, AccessTokenClaims};
use saphir::prelude::*;

#[derive(Deserialize)]
pub enum TokenType {
    Scope(AccessScope),
    Bridge,
    Association,
    Kdc,
    Jrl,
    Jrec,
}

pub struct AccessGuard {
    token_type: TokenType,
}

#[guard]
impl AccessGuard {
    pub fn new(token_type: TokenType) -> Self {
        AccessGuard { token_type }
    }

    async fn validate(&self, req: Request) -> Result<Request, HttpError> {
        let claims = req
            .extensions()
            .get::<AccessTokenClaims>()
            .ok_or_else(|| HttpError::unauthorized().msg("identity missing (no token provided)"))?;

        let allowed = match (&self.token_type, claims) {
            (TokenType::Association, AccessTokenClaims::Association(_)) => true,
            (TokenType::Scope(scope_needed), AccessTokenClaims::Scope(claims))
                if claims.scope == *scope_needed || claims.scope == AccessScope::Wildcard =>
            {
                true
            }
            (TokenType::Bridge, AccessTokenClaims::Bridge(_)) => true,
            (TokenType::Kdc, AccessTokenClaims::Kdc(_)) => true,
            (TokenType::Jrl, AccessTokenClaims::Jrl(_)) => true,
            (TokenType::Jrec, AccessTokenClaims::Jrec(_)) => true,
            _ => false,
        };

        if allowed {
            Ok(req)
        } else {
            Err(HttpError::forbidden().msg("token not allowed"))
        }
    }
}
