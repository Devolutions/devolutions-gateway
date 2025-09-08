use axum::Extension;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::http::HttpError;
use crate::token::{
    AccessScope, AccessTokenClaims, AssociationTokenClaims, BridgeTokenClaims, JmuxTokenClaims, JrecTokenClaims,
    JrlTokenClaims, ScopeTokenClaims, WebAppTokenClaims,
};

use axum::extract::{FromRequest, RawQuery, Request};

#[derive(Clone)]
pub struct AccessToken(pub AccessTokenClaims);

impl<S> FromRequestParts<S> for AccessToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Extension::<AccessTokenClaims>::from_request_parts(parts, state)
            .await
            .map_err(HttpError::internal().err())?
            .0;
        Ok(Self(claims))
    }
}

#[derive(Clone)]
pub struct AssociationToken(pub AssociationTokenClaims);

impl<S> FromRequestParts<S> for AssociationToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Association(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected ASSOCIATION)"))
        }
    }
}

#[derive(Clone)]
pub struct JrlToken(pub JrlTokenClaims);

impl<S> FromRequestParts<S> for JrlToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jrl(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JRL)"))
        }
    }
}

#[derive(Clone)]
pub struct JrecToken(pub JrecTokenClaims);

impl<S> FromRequestParts<S> for JrecToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jrec(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JREC)"))
        }
    }
}

#[derive(Clone)]
pub struct JmuxToken(pub JmuxTokenClaims);

impl<S> FromRequestParts<S> for JmuxToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Jmux(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected JMUX)"))
        }
    }
}

#[derive(Clone)]
pub struct ScopeToken(pub ScopeTokenClaims);

impl<S> FromRequestParts<S> for ScopeToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Scope(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected SCOPE)"))
        }
    }
}

#[derive(Clone, Copy)]
pub struct SessionsReadScope;

impl<S> FromRequestParts<S> for SessionsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::SessionsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct SessionTerminateScope;

impl<S> FromRequestParts<S> for SessionTerminateScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::SessionTerminate => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct AssociationsReadScope;

impl<S> FromRequestParts<S> for AssociationsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::AssociationsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DiagnosticsReadScope;

impl<S> FromRequestParts<S> for DiagnosticsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::DiagnosticsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct JrlReadScope;

impl<S> FromRequestParts<S> for JrlReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::JrlRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ConfigWriteScope;

impl<S> FromRequestParts<S> for ConfigWriteScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::ConfigWrite => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct HeartbeatReadScope;

impl<S> FromRequestParts<S> for HeartbeatReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::HeartbeatRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RecordingDeleteScope;

impl<S> FromRequestParts<S> for RecordingDeleteScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::RecordingDelete => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct RecordingsReadScope;

impl<S> FromRequestParts<S> for RecordingsReadScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::RecordingsRead => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct UpdateScope;

impl<S> FromRequestParts<S> for UpdateScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::Update => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct PreflightScope;

impl<S> FromRequestParts<S> for PreflightScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::Preflight => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct TrafficClaimScope;

impl<S> FromRequestParts<S> for TrafficClaimScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::TrafficClaim => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct TrafficAckScope;

impl<S> FromRequestParts<S> for TrafficAckScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::TrafficAck => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetMonitorConfigScope;

impl<S> FromRequestParts<S> for NetMonitorConfigScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::NetMonitorConfig => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetMonitorDrainScope;

impl<S> FromRequestParts<S> for NetMonitorDrainScope
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match ScopeToken::from_request_parts(parts, state).await?.0.scope {
            AccessScope::Wildcard => Ok(Self),
            AccessScope::NetMonitorDrain => Ok(Self),
            _ => Err(HttpError::forbidden().msg("invalid scope for route")),
        }
    }
}

#[derive(Clone)]
pub struct WebAppToken(pub WebAppTokenClaims);

impl<S> FromRequestParts<S> for WebAppToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::WebApp(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected WEBAPP)"))
        }
    }
}

#[derive(Clone, Copy)]
pub struct NetScanToken;

impl<S> FromRequestParts<S> for NetScanToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::NetScan(_) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self)
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected NETSCAN)"))
        }
    }
}

#[derive(Clone)]
pub struct BridgeToken(pub BridgeTokenClaims);

impl<S> FromRequestParts<S> for BridgeToken
where
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if let AccessTokenClaims::Bridge(claims) = AccessToken::from_request_parts(parts, state).await?.0 {
            Ok(Self(claims))
        } else {
            Err(HttpError::forbidden().msg("token not allowed (expected BRIDGE)"))
        }
    }
}

pub struct RepeatQuery<T>(pub(crate) T);

impl<T, S> FromRequest<S> for RepeatQuery<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = HttpError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let RawQuery(query) = RawQuery::from_request(req, state)
            .await
            .map_err(|e| HttpError::bad_request().build(e))?;

        let query = query.unwrap_or_default();
        let parsed_query = serde_querystring::from_str::<T>(&query, serde_querystring::ParseMode::Duplicate)
            .map_err(|e| HttpError::bad_request().build(e))?;

        Ok(RepeatQuery(parsed_query))
    }
}
