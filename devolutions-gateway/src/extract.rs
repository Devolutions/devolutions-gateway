use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::Extension;

use crate::http::HttpError;
use crate::token::{
    AccessScope, AccessTokenClaims, AssociationTokenClaims, JmuxTokenClaims, JrecTokenClaims, JrlTokenClaims,
    ScopeTokenClaims, WebAppTokenClaims,
};

#[derive(Clone)]
pub struct AccessToken(pub AccessTokenClaims);

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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

#[async_trait]
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
pub struct RecordingsReadScope;

#[async_trait]
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

#[derive(Clone)]
pub struct WebAppToken(pub WebAppTokenClaims);

#[async_trait]
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

#[async_trait]
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
