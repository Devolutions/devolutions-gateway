//! How a stream ended, classified as [CONTRACT.agent-identity.md §5.4 "Errors"][errors] and [§7.4
//! "Termination"][termination] say.
//!
//! [errors]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#54-errors
//! [termination]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#74-termination

use std::error::Error;
use std::fmt;

use tonic::Code;

use crate::transport::NotGrpc;

/// Why a stream closed or its opening failed ([CONTRACT.agent-identity.md §7.4 "Termination"][contract]).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#74-termination
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Closure {
    pub class: ClosureClass,
    /// The gRPC status the authority closed the stream with, if it sent one.
    pub grpc_code: Option<Code>,
    /// The `error-code` trailer.
    pub error_code: Option<String>,
    /// The `server-time` trailer.
    pub server_time: Option<String>,
    /// A description of the cause, for logs.
    pub reason: String,
}

/// What a closure means for the identity ([CONTRACT.agent-identity.md §5.4 "Errors"][contract]).
///
/// [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#54-errors
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
    /// A status the authority sent is classified by its gRPC code with its `error-code` trailer, as exact pairs, and
    /// any other pair is transient; a status the client derived from a connection failure carries the failure as its
    /// source.
    pub(crate) fn from_status(status: &tonic::Status) -> Self {
        let mut cause = status.source();
        while let Some(error) = cause {
            if let Some(not_grpc) = error.downcast_ref::<NotGrpc>() {
                return Self::transient(not_grpc.kind(), error);
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
        let class = match (status.code(), error_code.as_deref()) {
            (Code::PermissionDenied, Some("identity_revoked")) => ClosureClass::Terminal(TerminalCode::IdentityRevoked),
            (Code::Unauthenticated, Some("identity_unknown")) => ClosureClass::Terminal(TerminalCode::IdentityUnknown),
            (Code::Unauthenticated, Some("certificate_expired")) => ClosureClass::CertificateExpired,
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tonic::Status;
    use tonic::metadata::MetadataMap;

    use super::*;

    /// A status as the authority sends it, with an `error-code` trailer.
    fn status(code: Code, error_code: &str) -> Status {
        let mut metadata = MetadataMap::new();
        metadata.insert("error-code", error_code.parse().expect("ASCII error code"));
        Status::with_metadata(code, "closed by the test", metadata)
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    #[rstest]
    #[case::revoked(
        Code::PermissionDenied,
        "identity_revoked",
        ClosureClass::Terminal(TerminalCode::IdentityRevoked)
    )]
    #[case::unknown(
        Code::Unauthenticated,
        "identity_unknown",
        ClosureClass::Terminal(TerminalCode::IdentityUnknown)
    )]
    #[case::expired(Code::Unauthenticated, "certificate_expired", ClosureClass::CertificateExpired)]
    fn classifies_each_status_and_error_code_pair_of_the_contract(
        #[case] code: Code,
        #[case] error_code: &str,
        #[case] class: ClosureClass,
    ) {
        assert_eq!(Closure::from_status(&status(code, error_code)).class, class);
    }

    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-termination
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §errors
    #[rstest]
    #[case::revoked_unauthenticated(Code::Unauthenticated, "identity_revoked")]
    #[case::revoked_ok(Code::Ok, "identity_revoked")]
    #[case::revoked_unavailable(Code::Unavailable, "identity_revoked")]
    #[case::unknown_permission_denied(Code::PermissionDenied, "identity_unknown")]
    #[case::unknown_ok(Code::Ok, "identity_unknown")]
    #[case::expired_permission_denied(Code::PermissionDenied, "certificate_expired")]
    #[case::expired_ok(Code::Ok, "certificate_expired")]
    #[case::expired_internal(Code::Internal, "certificate_expired")]
    fn a_terminal_or_expired_code_with_another_status_is_an_outage(#[case] code: Code, #[case] error_code: &str) {
        assert_eq!(
            Closure::from_status(&status(code, error_code)).class,
            ClosureClass::Transient(TransientKind::Outage)
        );
    }
}
