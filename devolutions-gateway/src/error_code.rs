//! Machine-readable error codes reported to clients.
//!
//! The same codes are meant for every channel reporting an error to a client,
//! and for the system event log, so that a client and an administrator see the same code.
//!
//! Codes are public API.
//! New codes can be added, but existing codes are never renamed or removed.
//! Clients must treat unknown codes as generic failures.

use core::fmt;

macro_rules! define_error_codes {
    (
        $(
            $( #[doc = $doc:literal] )+
            $variant:ident => $code:literal,
        )+
    ) => {
        /// Machine-readable reason for a rejected request.
        ///
        /// Only the code leaves the Gateway.
        /// The details explaining it (error sources, key names, claim values…) are logged, never sent.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $(
                $( #[doc = $doc] )+
                $variant,
            )+
        }

        impl ErrorCode {
            /// All the codes, in declaration order.
            pub const ALL: &[Self] = &[$( Self::$variant ),+];

            /// Returns the snake_case string sent to clients.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $code, )+
                }
            }

            /// Returns a one-sentence description of the code, for documentation purposes.
            pub const fn description(self) -> &'static str {
                match self {
                    $( Self::$variant => concat!($( $doc ),+).trim_ascii(), )+
                }
            }
        }
    };
}

// Append new codes at the end: generated clients number enum members by position.
// Keep each description on a single line.
define_error_codes! {
    // -- Generic codes, used when no specific code applies -- //

    /// The request is invalid.
    BadRequest => "bad_request",
    /// The request is not authenticated.
    Unauthorized => "unauthorized",
    /// The request is not allowed.
    Forbidden => "forbidden",
    /// The resource doesn't exist.
    NotFound => "not_found",
    /// The request took too long to complete.
    RequestTimeout => "request_timeout",
    /// The request conflicts with the current state of the resource.
    Conflict => "conflict",
    /// The request is too large.
    PayloadTooLarge => "payload_too_large",
    /// The Gateway failed to process the request.
    InternalError => "internal_error",
    /// The Gateway received an invalid response from an upstream server.
    BadGateway => "bad_gateway",
    /// The service is temporarily unavailable.
    ServiceUnavailable => "service_unavailable",
    /// An upstream server didn't respond in time.
    GatewayTimeout => "gateway_timeout",
    /// The Gateway is out of storage space.
    InsufficientStorage => "insufficient_storage",

    // -- Token and authorization codes -- //

    /// No token was found in the `Authorization` header or in the `token` query parameter.
    MissingToken => "missing_token",
    /// The token can't be decoded or decrypted, or its claims don't match the schema expected for its type.
    MalformedToken => "malformed_token",
    /// The token signature doesn't match the provisioner key of the Gateway.
    BadSignature => "bad_signature",
    /// The token refers to a key ID (`kid`) that doesn't match the sub provisioner key of the Gateway.
    UnknownSubkey => "unknown_subkey",
    /// The token has expired (`exp` claim); the clocks of the token issuer and of the Gateway may be out of sync.
    Expired => "expired",
    /// The token is not valid yet (`nbf` claim); the clocks of the token issuer and of the Gateway may be out of sync.
    NotYetValid => "not_yet_valid",
    /// The token is restricted to another Gateway ID (`jet_gw_id` claim).
    GatewayIdMismatch => "gateway_id_mismatch",
    /// The token contains a value revoked by the JSON Revocation List (JRL) of the Gateway.
    Revoked => "revoked",
    /// The token was already used, and can't be used again in this context.
    UnexpectedReplay => "unexpected_replay",
    /// The token is rejected for a reason not covered by another code.
    InvalidToken => "invalid_token",
    /// The type of the token is not accepted by this route.
    WrongTokenType => "wrong_token_type",
    /// The scope of the token doesn't grant access to this route.
    InsufficientScope => "insufficient_scope",
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "openapi")]
impl<'s> utoipa::ToSchema<'s> for ErrorCode {
    fn schema() -> (&'s str, utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>) {
        use core::fmt::Write as _;

        use utoipa::openapi::schema::{ObjectBuilder, SchemaType};

        let mut description = String::from(
            "Machine-readable reason for a rejected request.\n\n\
             New codes can be added, but existing codes are never renamed or removed. \
             Clients must treat unknown codes as generic failures.\n",
        );

        for code in Self::ALL {
            let _ = write!(description, "\n- `{}`: {}", code.as_str(), code.description());
        }

        let schema = ObjectBuilder::new()
            .schema_type(SchemaType::String)
            .description(Some(description))
            .enum_values(Some(Self::ALL.iter().map(|code| code.as_str())))
            .build();

        ("ErrorCode", schema.into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use expect_test::expect;

    use super::*;

    /// Codes are public API: existing codes are never renamed or removed, and new codes are appended.
    #[test]
    fn codes_are_stable() {
        let codes = ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        expect![[r#"
            bad_request
            unauthorized
            forbidden
            not_found
            request_timeout
            conflict
            payload_too_large
            internal_error
            bad_gateway
            service_unavailable
            gateway_timeout
            insufficient_storage
            missing_token
            malformed_token
            bad_signature
            unknown_subkey
            expired
            not_yet_valid
            gateway_id_mismatch
            revoked
            unexpected_replay
            invalid_token
            wrong_token_type
            insufficient_scope"#]]
        .assert_eq(&codes);
    }

    #[test]
    fn codes_are_unique_snake_case_and_documented() {
        let mut seen = HashSet::new();

        for code in ErrorCode::ALL {
            let code_str = code.as_str();

            assert!(seen.insert(code_str), "duplicated code: {code_str}");
            assert!(
                code_str.starts_with(|c: char| c.is_ascii_lowercase())
                    && code_str.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "not snake_case: {code_str}"
            );
            assert!(!code.description().is_empty(), "undocumented code: {code_str}");
            assert_eq!(
                serde_json::to_value(code).expect("serialize the code"),
                serde_json::Value::from(code_str)
            );
        }
    }
}
