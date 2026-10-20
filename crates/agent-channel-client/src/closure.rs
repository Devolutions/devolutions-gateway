//! How a stream ended, classified as [CONTRACT.md] §5.4 "Errors" and §7.4 "Termination" say.
//!
//! [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md

use std::error::Error;
use std::fmt;

use crate::transport::NotGrpc;

/// Why a stream closed or its opening failed ([CONTRACT.md] §7.4 "Termination").
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Closure {
    pub class: ClosureClass,
    /// The gRPC status the authority closed the stream with, if it sent one.
    pub grpc_code: Option<tonic::Code>,
    /// The `error-code` trailer.
    pub error_code: Option<String>,
    /// The `server-time` trailer.
    pub server_time: Option<String>,
    /// A description of the cause, for logs.
    pub reason: String,
}

/// What a closure means for the identity ([CONTRACT.md] §5.4 "Errors").
///
/// [CONTRACT.md]: ../../docs/agent-identity/CONTRACT.md
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureClass {
    /// The identity is over for this authority; the channel stops.
    Terminal(TerminalCode),
    /// The certificate expired; the channel stops, and the caller renews before it connects again.
    CertificateExpired,
    /// Any other outcome; the channel opens a new stream after a backoff.
    Transient(TransientKind),
}

/// The error codes that end an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalCode {
    IdentityRevoked,
    IdentityUnknown,
}

impl TerminalCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityRevoked => "identity_revoked",
            Self::IdentityUnknown => "identity_unknown",
        }
    }
}

/// The kind of a transient closure, which sets how far the backoff grows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientKind {
    /// The response shows the path to the authority can't carry gRPC.
    NoGrpcPath,
    /// A network error, server downtime, or any other transient refusal or closure of the stream.
    Outage,
}

impl Closure {
    /// A closure that no gRPC status explains, such as a network error.
    pub(crate) fn transient(kind: TransientKind, reason: impl fmt::Display) -> Self {
        Self {
            class: ClosureClass::Transient(kind),
            grpc_code: None,
            error_code: None,
            server_time: None,
            reason: reason.to_string(),
        }
    }

    pub(crate) fn outage(reason: impl fmt::Display) -> Self {
        Self::transient(TransientKind::Outage, reason)
    }

    /// Classifies the status a stream ended with.
    ///
    /// A status the authority sent is classified by its `error-code` trailer; a status the client derived from a
    /// connection failure carries the failure as its source.
    pub(crate) fn from_status(status: &tonic::Status) -> Self {
        let mut cause = status.source();
        while let Some(error) = cause {
            if error.is::<NotGrpc>() {
                return Self::transient(TransientKind::NoGrpcPath, error);
            }
            cause = error.source();
        }
        if let Some(source) = status.source() {
            return Self::outage(error_chain(status.message(), source));
        }
        let trailer = |name: &str| {
            status
                .metadata()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let error_code = trailer("error-code");
        let class = match error_code.as_deref() {
            Some("identity_revoked") => ClosureClass::Terminal(TerminalCode::IdentityRevoked),
            Some("identity_unknown") => ClosureClass::Terminal(TerminalCode::IdentityUnknown),
            Some("certificate_expired") => ClosureClass::CertificateExpired,
            _ => ClosureClass::Transient(TransientKind::Outage),
        };
        Self {
            class,
            grpc_code: Some(status.code()),
            error_code,
            server_time: trailer("server-time"),
            reason: status.message().to_owned(),
        }
    }
}

/// Formats `message`, then `source` and each of its causes.
pub(crate) fn error_chain(message: &str, source: &(dyn Error + 'static)) -> String {
    let mut chain = message.to_owned();
    let mut cause = Some(source);
    while let Some(error) = cause {
        chain.push_str(": ");
        chain.push_str(&error.to_string());
        cause = error.source();
    }
    chain
}
