use async_trait::async_trait;
use core::fmt;
use devolutions_gateway_task::{ShutdownSignal, Task};
use nonempty::NonEmpty;
use parking_lot::Mutex;
use picky::jose::jws::RawJws;
use picky::key::{PrivateKey, PublicKey};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::recording::ActiveRecordings;
use crate::target_addr::TargetAddr;

pub const MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS: i64 = 60 * 60 * 2; // 2 hours

const LEEWAY_SECS: u16 = 60 * 5; // 5 minutes
const MAX_REUSE_INTERVAL_SECS: i64 = 10; // 10 seconds

pub type TokenCache = Mutex<HashMap<Uuid, TokenSource>>; // TODO: compare performance with a token manager task
pub type CurrentJrl = Mutex<JrlTokenClaims>;

pub fn new_token_cache() -> TokenCache {
    Mutex::new(HashMap::new())
}

// ----- token types -----

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ContentType {
    Association,
    Scope,
    Bridge,
    Jmux,
    Jrec,
    Kdc,
    Jrl,
    WebApp,
    NetScan,
}

impl FromStr for ContentType {
    type Err = BadContentType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ASSOCIATION" => Ok(ContentType::Association),
            "SCOPE" => Ok(ContentType::Scope),
            "BRIDGE" => Ok(ContentType::Bridge),
            "JMUX" => Ok(ContentType::Jmux),
            "JREC" => Ok(ContentType::Jrec),
            "KDC" => Ok(ContentType::Kdc),
            "JRL" => Ok(ContentType::Jrl),
            "WEBAPP" => Ok(ContentType::WebApp),
            "NETSCAN" => Ok(ContentType::NetScan),
            unexpected => Err(BadContentType {
                value: SmolStr::new(unexpected),
            }),
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentType::Association => write!(f, "ASSOCIATION"),
            ContentType::Scope => write!(f, "SCOPE"),
            ContentType::Bridge => write!(f, "BRIDGE"),
            ContentType::Jmux => write!(f, "JMUX"),
            ContentType::Jrec => write!(f, "JREC"),
            ContentType::Kdc => write!(f, "KDC"),
            ContentType::Jrl => write!(f, "JRL"),
            ContentType::WebApp => write!(f, "WEBAPP"),
            ContentType::NetScan => write!(f, "NETSCAN"),
        }
    }
}

#[derive(Debug)]
pub struct BadContentType {
    pub value: SmolStr,
}

impl fmt::Display for BadContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unexpected content type: {}", self.value)
    }
}

impl std::error::Error for BadContentType {}

// ----- generic struct -----

#[derive(Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum AccessTokenClaims {
    Association(AssociationTokenClaims),
    Scope(ScopeTokenClaims),
    Bridge(BridgeTokenClaims),
    Jmux(JmuxTokenClaims),
    Jrec(JrecTokenClaims),
    Kdc(KdcTokenClaims),
    Jrl(JrlTokenClaims),
    WebApp(WebAppTokenClaims),
    NetScan(NetScanClaims),
}

impl AccessTokenClaims {
    fn contains_secret(&self) -> bool {
        match self {
            AccessTokenClaims::Association(claims) => claims.contains_secret(),
            AccessTokenClaims::Scope(_) => false,
            AccessTokenClaims::Bridge(_) => false,
            AccessTokenClaims::Jmux(_) => false,
            AccessTokenClaims::Jrec(_) => false,
            AccessTokenClaims::Kdc(_) => false,
            AccessTokenClaims::Jrl(_) => false,
            AccessTokenClaims::WebApp(_) => false,
            AccessTokenClaims::NetScan(_) => false,
        }
    }
}

// ----- Known application protocols -----

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum ApplicationProtocol {
    Known(Protocol),
    Unknown(SmolStr),
}

impl ApplicationProtocol {
    pub fn unknown() -> Self {
        Self::Unknown(SmolStr::new_inline("unknown"))
    }

    pub fn known_default_port(&self) -> Option<u16> {
        match self {
            Self::Known(known) => known.known_default_port(),
            Self::Unknown(_) => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ApplicationProtocol::Known(known) => known.as_str(),
            ApplicationProtocol::Unknown(unknown) => unknown.as_str(),
        }
    }
}

impl Default for ApplicationProtocol {
    fn default() -> Self {
        Self::unknown()
    }
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationProtocol::Known(protocol) => write!(f, "{protocol:?}"),
            ApplicationProtocol::Unknown(protocol) => write!(f, "{protocol}"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Wayk Remote Desktop Protocol
    Wayk,
    /// Remote Desktop Protocol
    Rdp,
    /// Apple Remote Desktop
    Ard,
    /// Virtual Network Computing
    Vnc,
    /// Secure Shell
    Ssh,
    /// PowerShell over SSH transport
    SshPwsh,
    /// SSH File Transfer Protocol
    Sftp,
    /// Secure Copy Protocol
    Scp,
    /// Telnet
    Telnet,
    /// PowerShell over WinRM via HTTP transport
    WinrmHttpPwsh,
    /// PowerShell over WinRM via HTTPS transport
    WinrmHttpsPwsh,
    /// Hypertext Transfer Protocol
    Http,
    /// Hypertext Transfer Protocol Secure
    Https,
    /// LDAP Protocol
    Ldap,
    /// Secure LDAP Protocol
    Ldaps,
    /// Devolutions Gateway Tunnel (generic JMUX tunnel)
    Tunnel,
}

impl Protocol {
    pub fn known_default_port(self) -> Option<u16> {
        match self {
            Self::Wayk => Some(12876),
            Self::Rdp => Some(3389),
            Self::Ard => Some(5900),
            Self::Vnc => Some(5900),
            Self::Ssh => Some(22),
            Self::SshPwsh => Some(22),
            Self::Sftp => Some(22),
            Self::Scp => Some(22),
            Self::Telnet => Some(23),
            Self::WinrmHttpPwsh => Some(5985),
            Self::WinrmHttpsPwsh => Some(5986),
            Self::Http => Some(80),
            Self::Https => Some(443),
            Self::Ldap => Some(389),
            Self::Ldaps => Some(636),
            Self::Tunnel => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Protocol::Wayk => "wayk",
            Protocol::Rdp => "rdp",
            Protocol::Ard => "ard",
            Protocol::Vnc => "vnc",
            Protocol::Ssh => "ssh",
            Protocol::SshPwsh => "ssh-pwsh",
            Protocol::Sftp => "sftp",
            Protocol::Scp => "scp",
            Protocol::Telnet => "telnet",
            Protocol::WinrmHttpPwsh => "winrm-http-pwsh",
            Protocol::WinrmHttpsPwsh => "winrm-https-pwsh",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Ldap => "ldap",
            Protocol::Ldaps => "ldaps",
            Protocol::Tunnel => "tunnel",
        }
    }
}

// ----- recording file types ----- //

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordingFileType {
    /// WebM/VP8 video file
    WebM,
    /// Terminal Playback
    TRP,
}

impl RecordingFileType {
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordingFileType::WebM => "webm",
            RecordingFileType::TRP => "trp",
        }
    }
}

impl fmt::Display for RecordingFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ----- recording operations ----- //

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordingOperation {
    Push,
    Pull,
}

impl RecordingOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordingOperation::Push => "push",
            RecordingOperation::Pull => "pull",
        }
    }
}

// ----- association claims ----- //

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ConnectionMode {
    /// Connection should be processed following the rendez-vous protocol
    Rdv,

    /// Connection should be forwarded to a given destination host
    Fwd {
        /// Forward targets. Should be tried in order.
        targets: NonEmpty<TargetAddr>,

        /// Credentials to use if protocol is wrapped by the Gateway (e.g. RDP TLS)
        creds: Option<CredsClaims>,
    },
}

#[derive(Serialize, Deserialize, Zeroize, Clone)]
#[zeroize(drop)]
pub struct CredsClaims {
    // Proxy credentials (client ↔ jet)
    pub prx_usr: String,
    pub prx_pwd: String,

    // Target credentials (jet ↔ server)
    pub dst_usr: String,
    pub dst_pwd: String,
}

/// Maximum duration in minutes for a session (aka time to live)
#[derive(Default, Debug, Clone, Copy)]
pub enum SessionTtl {
    #[default]
    Unlimited,
    Limited {
        minutes: NonZeroU64,
    },
}

impl From<u64> for SessionTtl {
    fn from(minutes: u64) -> Self {
        if let Some(minutes) = NonZeroU64::new(minutes) {
            Self::Limited { minutes }
        } else {
            Self::Unlimited
        }
    }
}

#[derive(Clone)]
pub struct AssociationTokenClaims {
    /// Association ID (= Session ID)
    pub jet_aid: Uuid,

    /// Application protocol
    pub jet_ap: ApplicationProtocol,

    /// Connection Mode
    pub jet_cm: ConnectionMode,

    /// Recording Policy
    pub jet_rec: bool,

    /// Filtering Policy
    pub jet_flt: bool,

    /// Max session duration
    pub jet_ttl: SessionTtl,

    /// JWT expiration time claim.
    ///
    /// We need this to build our token invalidation cache.
    /// This doesn't need to be explicitly written in the structure to be checked by the JwtValidator.
    pub exp: i64,

    /// Unique ID for this token
    ///
    /// DVLS up to 2022.1.9 do not generate this claim.
    pub jti: Option<Uuid>,
}

impl AssociationTokenClaims {
    fn contains_secret(&self) -> bool {
        matches!(&self.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. })
    }
}

// ----- scope claims ----- //

#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessScope {
    #[serde(rename = "*")]
    Wildcard,
    #[serde(rename = "gateway.sessions.read")]
    SessionsRead,
    #[serde(rename = "gateway.session.terminate")]
    SessionTerminate,
    #[serde(rename = "gateway.associations.read")]
    AssociationsRead,
    #[serde(rename = "gateway.diagnostics.read")]
    DiagnosticsRead,
    #[serde(rename = "gateway.jrl.read")]
    JrlRead,
    #[serde(rename = "gateway.config.write")]
    ConfigWrite,
    #[serde(rename = "gateway.heartbeat.read")]
    HeartbeatRead,
    #[serde(rename = "gateway.recordings.read")]
    RecordingsRead,
}

#[derive(Clone, Deserialize)]
pub struct ScopeTokenClaims {
    pub scope: AccessScope,

    /// JWT expiration time claim.
    exp: i64,

    /// JWT "JWT ID" claim, the unique ID for this token
    ///
    /// DVLS up to 2022.1.9 do not generate this claim.
    jti: Option<Uuid>,
}

// ----- bridge claims ----- //

#[derive(Clone, Deserialize)]
pub struct BridgeTokenClaims {
    pub target_host: TargetAddr,

    /// JWT expiration time claim.
    exp: i64,

    /// JWT "JWT ID" claim, the unique ID for this token
    jti: Uuid,
}

// ----- jmux claims ----- //

#[derive(Clone)]
pub struct JmuxTokenClaims {
    /// Jet Association ID (= Session ID)
    pub jet_aid: Uuid,

    /// Authorized hosts
    pub hosts: NonEmpty<TargetAddr>,

    /// Application Protocol (mostly used to find a known default port)
    pub jet_ap: ApplicationProtocol,

    /// Max duration
    pub jet_ttl: SessionTtl,

    /// JWT expiration time claim.
    pub exp: i64,

    /// JWT "JWT ID" claim, the unique ID for this token
    pub jti: Uuid,
}

// ----- jrec claims ----- //

#[derive(Deserialize, Clone)]
pub struct JrecTokenClaims {
    /// Association ID (= Session ID)
    pub jet_aid: Uuid,

    /// Recording operation
    pub jet_rop: RecordingOperation,

    /// JWT expiration time claim.
    ///
    /// We need this to build our token invalidation cache.
    /// This doesn't need to be explicitly written in the structure to be checked by the JwtValidator.
    exp: i64,

    /// JWT "JWT ID" claim, the unique ID for this token
    jti: Uuid,
}

// ----- KDC claims ----- //

#[derive(Clone)]
pub struct KdcTokenClaims {
    /// Kerberos realm.
    ///
    /// E.g.: `ad.it-help.ninja`
    /// Should be lowercased (actual validation is case-insensitive though).
    pub krb_realm: SmolStr,

    /// Kerberos KDC address.
    ///
    /// E.g.: `tcp://IT-HELP-DC.ad.it-help.ninja:88`
    /// Default scheme is `tcp`.
    /// Default port is `88`.
    pub krb_kdc: TargetAddr,
}

// ----- jrl claims ----- //

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JrlTokenClaims {
    /// JWT "JWT ID" claim, the unique ID for this token
    pub jti: Uuid,

    /// JWT "Issued At" claim.
    ///
    /// Revocation list is saved only for the more recent token.
    pub iat: i64,

    /// The JWT revocation list as a claim-values map
    pub jrl: HashMap<String, Vec<serde_json::Value>>,
}

impl Default for JrlTokenClaims {
    fn default() -> Self {
        Self {
            jti: Uuid::nil(),
            iat: 0,
            jrl: HashMap::default(),
        }
    }
}

// ----- subkey ----- //

#[derive(Debug, Clone)]
pub struct Subkey {
    pub data: PublicKey,
    pub kid: String,
}

/// Cryptographic key algorithm family
///
/// Taken from [RFC7518 #6](https://tools.ietf.org/html/rfc7518#section-6.1)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// DER-encoded Subject Public Key Info structure
    #[serde(rename = "SPKI")]
    Spki,
    /// Elliptic Curve
    #[serde(rename = "EC")]
    Ec,
    /// Elliptic Curve
    #[serde(rename = "RSA")]
    Rsa,
}

// ----- web app claims ----- //

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppTokenClaims {
    /// JWT "JWT ID" claim, the unique ID for this token
    pub jti: Uuid,

    /// JWT "Issued At" claim.
    pub iat: i64,

    /// JWT "Not Before" claim.
    pub nbf: i64,

    /// JWT "Expiration Time" claim.
    pub exp: i64,

    /// JWT "Subject" claim.
    ///
    /// Identifies the principal that is the subject of the JWT.
    /// This is the username used to obtain this web application token.
    pub sub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetScanClaims {
    /// JWT "JWT ID" claim, the unique ID for this token
    pub jti: Uuid,

    /// JWT "Issued At" claim.
    pub iat: i64,

    /// JWT "Not Before" claim.
    pub nbf: i64,

    /// JWT "Expiration Time" claim.
    pub exp: i64,

    // Gateway ID
    pub jet_gw_id: Option<Uuid>,
}

// ----- cache clean up ----- //

pub struct CleanupTask {
    pub token_cache: Arc<TokenCache>,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "token cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.token_cache, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(token_cache: Arc<TokenCache>, mut shutdown_signal: ShutdownSignal) {
    use tokio::time::{sleep, Duration};

    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 30); // 30 minutes

    debug!("Task started");

    loop {
        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }

        let clean_threshold = time::OffsetDateTime::now_utc().unix_timestamp() - i64::from(LEEWAY_SECS);
        token_cache
            .lock()
            .retain(|_, src| src.expiration_timestamp > clean_threshold);
    }

    debug!("Task terminated");
}

// ----- validation ----- //

#[derive(Debug, Clone)]
pub struct TokenSource {
    ip: IpAddr,
    expiration_timestamp: i64,
    last_use_timestamp: i64,
}

fn is_encrypted(token: &str) -> bool {
    let num_dots = token.chars().fold(0, |acc, c| if c == '.' { acc + 1 } else { acc });
    num_dots == 4
}

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("delegation key is missing")]
    MissingDelegationKey,
    #[error("invalid JWE token")]
    Jwe {
        #[from]
        source: picky::jose::jwe::JweError,
    },
    #[error("invalid JWE token payload")]
    JwePayload { source: std::str::Utf8Error },
    #[error("invalid JWS token")]
    Jws {
        #[from]
        source: picky::jose::jws::JwsError,
    },
    #[error("failed to verify token signature using {key}")]
    SignatureVerification {
        source: picky::jose::jws::JwsError,
        key: &'static str,
    },
    #[error("key ID (kid) {provided_kid} in token is referring to an unknown subkey")]
    UnknownSubkey { provided_kid: String },
    #[error("invalid content type for token")]
    BadContentType {
        #[from]
        source: BadContentType,
    },
    #[error("invalid JWT")]
    Jwt {
        #[from]
        source: picky::jose::jwt::JwtError,
    },
    #[error("subkey can't be used to sign a {content_type:?} token")]
    ContentTypeNotAllowedForSubkey { content_type: ContentType },
    #[error("invalid `nbf` and `exp` claims for subkey-signed token")]
    InvalidValidityForSubkey,
    #[error("claim `{name}` is malformed")]
    MalformedClaim { name: &'static str, source: anyhow::Error },
    #[error("gateway ID scope mismatch")]
    GatewayIdScopeMismatch,
    #[error("a revoked value is contained")]
    Revoked,
    #[error("invalid claims for {content_type:?} token")]
    InvalidClaimScheme {
        content_type: ContentType,
        source: serde_json::Error,
    },
    #[error("payload contains secrets that were not encrypted inside a JWE token")]
    PlaintextSecrets,
    #[error("previously used token unexpectedly reused ({reason})")]
    UnexpectedReplay { reason: &'static str },
    #[error("JSON Revocation List")]
    OldJrl,
}

#[derive(typed_builder::TypedBuilder)]
pub struct TokenValidator<'a> {
    source_ip: IpAddr,
    provisioner_key: &'a PublicKey,
    token_cache: &'a TokenCache,
    revocation_list: &'a CurrentJrl,
    active_recordings: &'a ActiveRecordings,
    delegation_key: Option<&'a PrivateKey>,
    subkey: Option<&'a Subkey>,
    gw_id: Option<Uuid>,
}

impl TokenValidator<'_> {
    pub fn validate(&self, token: &str) -> Result<AccessTokenClaims, TokenError> {
        validate_token_impl(
            token,
            self.source_ip,
            self.provisioner_key,
            self.token_cache,
            self.revocation_list,
            self.active_recordings,
            self.delegation_key,
            self.subkey,
            self.gw_id,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_token_impl(
    token: &str,
    source_ip: IpAddr,
    provisioner_key: &PublicKey,
    token_cache: &TokenCache,
    revocation_list: &CurrentJrl,
    active_recordings: &ActiveRecordings,
    delegation_key: Option<&PrivateKey>,
    subkey: Option<&Subkey>,
    gw_id: Option<Uuid>,
) -> Result<AccessTokenClaims, TokenError> {
    use picky::jose::jwe::Jwe;
    use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
    use serde_json::Value;
    use std::collections::hash_map::Entry;

    // === Decoding JWT === //

    let is_encrypted = is_encrypted(token);

    let jwe_token; // pre-declaration for extended lifetime

    let signed_jwt = if is_encrypted {
        let encrypted_jwt = token;
        let delegation_key = delegation_key.ok_or(TokenError::MissingDelegationKey)?;
        jwe_token = Jwe::decode(encrypted_jwt, delegation_key)?;
        std::str::from_utf8(&jwe_token.payload).map_err(|source| TokenError::JwePayload { source })?
    } else {
        token
    };

    let (jwt, using_subkey): (JwtSig, bool) = {
        let raw_jws = RawJws::decode(signed_jwt)?;

        match (&raw_jws.header.kid, subkey) {
            // Standard verification using master provisioner key
            (None, _) => (
                raw_jws.verify(provisioner_key).map(JwtSig::from).map_err(|source| {
                    TokenError::SignatureVerification {
                        source,
                        key: "main provisioner key",
                    }
                })?,
                false,
            ),

            // Validate token signature using the subkey
            (
                Some(provided_kid),
                Some(Subkey {
                    data: subkey,
                    kid: expected_kid,
                }),
            ) if provided_kid.eq(expected_kid) => (
                raw_jws
                    .verify(subkey)
                    .map(JwtSig::from)
                    .map_err(|source| TokenError::SignatureVerification {
                        source,
                        key: "sub provisioner key",
                    })?,
                true,
            ),

            // Subkey is missing or kid does not match
            (Some(provided_kid), maybe_subkey) => {
                debug!(kid = %provided_kid, subkey = ?maybe_subkey, "bad subkey usage detected");
                return Err(TokenError::UnknownSubkey {
                    provided_kid: provided_kid.to_owned(),
                });
            }
        }
    };

    // === Extracting content type and validating JWT claims === //

    let timestamp_now = time::OffsetDateTime::now_utc().unix_timestamp();
    let now = JwtDate::new_with_leeway(timestamp_now, LEEWAY_SECS);
    let strict_validator = JwtValidator::strict(now);

    let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
        let content_type = content_type
            .parse::<ContentType>()
            .map_err(|source| TokenError::BadContentType { source })?;

        let claims = match content_type {
            ContentType::Association
            | ContentType::Scope
            | ContentType::Bridge
            | ContentType::Jmux
            | ContentType::Jrec
            | ContentType::Kdc
            | ContentType::WebApp
            | ContentType::NetScan => jwt.validate::<Value>(&strict_validator)?.state.claims,
            ContentType::Jrl => {
                // NOTE: JRL tokens are not expected to expire.
                // However, `iat` (Issued At) claim is required, and only more recent tokens will
                // be accepted when updating the revocation list.
                let lenient_validator = strict_validator.not_before_check_optional().expiration_check_optional();
                jwt.validate::<Value>(&lenient_validator)?.state.claims
            }
        };

        (claims, content_type)
    } else {
        let mut claims = jwt.validate::<Value>(&strict_validator)?.state.claims;

        let content_type = if let Some(Value::String(content_type)) = claims.get_mut("type") {
            content_type.make_ascii_uppercase();
            content_type.parse::<ContentType>()?
        } else {
            ContentType::Association
        };

        (claims, content_type)
    };

    // === Check for scopes === //

    if using_subkey {
        match content_type {
            ContentType::Association | ContentType::Jmux | ContentType::Kdc => {}
            _ => return Err(TokenError::ContentTypeNotAllowedForSubkey { content_type }),
        }

        // Subkeys can only be used to sign short-lived token
        if claims
            .get("nbf")
            .and_then(Value::as_i64)
            .zip(claims.get("exp").and_then(Value::as_i64))
            .into_iter()
            .any(|(nbf, exp)| exp - nbf > MAX_SUBKEY_TOKEN_VALIDITY_DURATION_SECS)
        {
            return Err(TokenError::InvalidValidityForSubkey);
        }
    }

    if let Some(Value::String(expected_id)) = claims.get("jet_gw_id") {
        let expected_id = Uuid::parse_str(expected_id).map_err(|source| TokenError::MalformedClaim {
            name: "jet_gw_id",
            source: anyhow::Error::from(source),
        })?;

        match gw_id {
            // Gateway ID is required and must be equal to the scope
            Some(this_gw_id) if expected_id == this_gw_id => {}

            // Gateway ID scope rule is not respected
            Some(_) => return Err(TokenError::GatewayIdScopeMismatch),
            None => {
                warn!("This token is restricted to a specific gateway, but no ID has been assigned. This may become a hard error in the future.")
            }
        }
    }

    // === Check for revoked values in JWT Revocation List === //

    for (key, revoked_values) in &revocation_list.lock().jrl {
        if let Some(value) = claims.get(key) {
            if revoked_values.contains(value) {
                return Err(TokenError::Revoked);
            }
        }
    }

    // === Convert json value into an instance of the correct claims type === //

    let claims = match content_type {
        ContentType::Association => serde_json::from_value(claims).map(AccessTokenClaims::Association),
        ContentType::Scope => serde_json::from_value(claims).map(AccessTokenClaims::Scope),
        ContentType::Bridge => serde_json::from_value(claims).map(AccessTokenClaims::Bridge),
        ContentType::Jmux => serde_json::from_value(claims).map(AccessTokenClaims::Jmux),
        ContentType::Jrec => serde_json::from_value(claims).map(AccessTokenClaims::Jrec),
        ContentType::Kdc => serde_json::from_value(claims).map(AccessTokenClaims::Kdc),
        ContentType::Jrl => serde_json::from_value(claims).map(AccessTokenClaims::Jrl),
        ContentType::WebApp => serde_json::from_value(claims).map(AccessTokenClaims::WebApp),
        ContentType::NetScan => serde_json::from_value(claims).map(AccessTokenClaims::NetScan),
    }
    .map_err(|source| TokenError::InvalidClaimScheme { content_type, source })?;

    // === Applying additional validations as appropriate === //

    if claims.contains_secret() && !is_encrypted {
        return Err(TokenError::PlaintextSecrets);
    }

    match claims {
        // Mitigate replay attacks for RDP associations by rejecting token reuse from a different
        // source address IP (RDP requires multiple connections, so we can't just reject everything)
        AccessTokenClaims::Association(
            AssociationTokenClaims {
                jti: Some(id),
                exp,
                jet_ap: ApplicationProtocol::Known(Protocol::Rdp),
                ..
            }
            | AssociationTokenClaims {
                jet_aid: id,
                exp,
                jet_ap: ApplicationProtocol::Known(Protocol::Rdp),
                ..
            },
        ) => {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();

            match token_cache.lock().entry(id) {
                Entry::Occupied(bucket) => {
                    if bucket.get().ip != source_ip {
                        warn!("A replay attack may have been attempted");
                        return Err(TokenError::UnexpectedReplay {
                            reason: "different source IP",
                        });
                    }

                    if now > bucket.get().last_use_timestamp + MAX_REUSE_INTERVAL_SECS {
                        return Err(TokenError::UnexpectedReplay {
                            reason: "maximum reuse interval is exceeded",
                        });
                    }
                }
                Entry::Vacant(bucket) => {
                    bucket.insert(TokenSource {
                        ip: source_ip,
                        expiration_timestamp: exp,
                        last_use_timestamp: now,
                    });
                }
            }
        }

        // All other tokens can't be reused even if source IP is identical
        AccessTokenClaims::Association(AssociationTokenClaims { jti: Some(id), exp, .. })
        | AccessTokenClaims::Association(AssociationTokenClaims { jet_aid: id, exp, .. })
        | AccessTokenClaims::Scope(ScopeTokenClaims { jti: Some(id), exp, .. })
        | AccessTokenClaims::Bridge(BridgeTokenClaims { jti: id, exp, .. })
        | AccessTokenClaims::Jmux(JmuxTokenClaims { jti: id, exp, .. }) => match token_cache.lock().entry(id) {
            Entry::Occupied(_) => {
                warn!("A replay attack may have been attempted");
                return Err(TokenError::UnexpectedReplay {
                    reason: "never allowed for this usecase",
                });
            }
            Entry::Vacant(bucket) => {
                bucket.insert(TokenSource {
                    ip: source_ip,
                    expiration_timestamp: exp,
                    last_use_timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
                });
            }
        },

        // JREC push tokens may be re-used as long as recording is considered as ongoing
        AccessTokenClaims::Jrec(JrecTokenClaims {
            jet_aid,
            jet_rop: RecordingOperation::Push,
            jti,
            exp,
            ..
        }) => match token_cache.lock().entry(jti) {
            Entry::Occupied(bucket) => {
                if bucket.get().ip != source_ip {
                    warn!("A replay attack may have been attempted");
                    return Err(TokenError::UnexpectedReplay {
                        reason: "different source IP",
                    });
                }

                let recording_is_active = active_recordings.contains(jet_aid);

                if !recording_is_active {
                    return Err(TokenError::UnexpectedReplay {
                        reason: "attempted to reuse jrec token, but the reuse leeway has expired",
                    });
                }
            }
            Entry::Vacant(bucket) => {
                bucket.insert(TokenSource {
                    ip: source_ip,
                    expiration_timestamp: exp,
                    last_use_timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
                });
            }
        },

        // JREC pull tokens can be re-used at will until they are expired
        AccessTokenClaims::Jrec(JrecTokenClaims {
            jet_rop: RecordingOperation::Pull,
            ..
        }) => {}

        // No mitigation if token has no ID (might be disallowed in the future)
        AccessTokenClaims::Scope(ScopeTokenClaims { jti: None, .. }) => {}

        // KDC tokens may be long-lived and reusing them is allowed
        AccessTokenClaims::Kdc(_) => {}

        // JRL token must be more recent than the current revocation list
        AccessTokenClaims::Jrl(JrlTokenClaims { iat, .. }) => {
            if iat < revocation_list.lock().iat {
                return Err(TokenError::OldJrl);
            }
        }

        // Web application tokens are long-lived and reusing them is allowed
        AccessTokenClaims::WebApp(_) => {}
        // Network scan tokens are long-lived and reusing them is allowed
        AccessTokenClaims::NetScan(_) => {}
    }

    Ok(claims)
}

#[deprecated = "make sure this is never used without a deliberate action"]
pub mod unsafe_debug {
    // Any function in this module should only be used at development stage when deliberately
    // enabling debugging options.

    use super::*;
    use picky::jose::jwt;

    /// Dangerous token validation procedure.
    ///
    /// Most security checks are removed.
    /// This will basically only checks for content type and attempt to deserialize into the appropriate struct. No more.
    pub fn dangerous_validate_token(
        token: &str,
        delegation_key: Option<&PrivateKey>,
    ) -> Result<AccessTokenClaims, TokenError> {
        use picky::jose::jwe::Jwe;
        use picky::jose::jwt::JwtSig;
        use serde_json::Value;

        warn!("**DEBUG OPTION** Using dangerous token validation for testing purposes. Make sure this is not happening in production!");

        // === Decoding JWT === //

        let is_encrypted = is_encrypted(token);

        let jwe_token; // pre-declaration for extended lifetime

        let signed_jwt = if is_encrypted {
            let encrypted_jwt = token;
            let delegation_key = delegation_key.ok_or(TokenError::MissingDelegationKey)?;
            jwe_token = Jwe::decode(encrypted_jwt, delegation_key)?;
            std::str::from_utf8(&jwe_token.payload).map_err(|source| TokenError::JwePayload { source })?
        } else {
            token
        };

        let jwt = RawJws::decode(signed_jwt)
            .map(RawJws::discard_signature)
            .map(JwtSig::from)?;

        // === Extracting content type BUT without validating JWT claims === //

        let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
            let content_type = content_type.parse::<ContentType>()?;
            let claims = jwt.validate::<Value>(&jwt::NO_CHECK_VALIDATOR)?.state.claims;
            (claims, content_type)
        } else {
            let mut claims = jwt.validate::<Value>(&jwt::NO_CHECK_VALIDATOR)?.state.claims;

            let content_type = if let Some(Value::String(content_type)) = claims.get_mut("type") {
                content_type.make_ascii_uppercase();
                content_type.parse::<ContentType>()?
            } else {
                ContentType::Association
            };

            (claims, content_type)
        };

        // === Convert json value into an instance of the correct claims type === //

        let claims = match content_type {
            ContentType::Association => serde_json::from_value(claims).map(AccessTokenClaims::Association),
            ContentType::Scope => serde_json::from_value(claims).map(AccessTokenClaims::Scope),
            ContentType::Bridge => serde_json::from_value(claims).map(AccessTokenClaims::Bridge),
            ContentType::Jmux => serde_json::from_value(claims).map(AccessTokenClaims::Jmux),
            ContentType::Jrec => serde_json::from_value(claims).map(AccessTokenClaims::Jrec),
            ContentType::Kdc => serde_json::from_value(claims).map(AccessTokenClaims::Kdc),
            ContentType::Jrl => serde_json::from_value(claims).map(AccessTokenClaims::Jrl),
            ContentType::WebApp => serde_json::from_value(claims).map(AccessTokenClaims::WebApp),
            ContentType::NetScan => serde_json::from_value(claims).map(AccessTokenClaims::NetScan),
        }
        .map_err(|source| TokenError::InvalidClaimScheme { content_type, source })?;

        // Other checks are removed as well

        Ok(claims)
    }
}

mod serde_impl {
    use nonempty::NonEmpty;
    use serde::{de, ser};
    use smol_str::SmolStr;
    use uuid::Uuid;

    use crate::target_addr::TargetAddr;

    use super::*;

    #[derive(Serialize, Deserialize, Clone)]
    #[serde(rename_all = "kebab-case")]
    #[serde(tag = "jet_cm")]
    #[allow(clippy::large_enum_variant)]
    enum ConnectionModeHelper {
        Rdv,
        Fwd {
            /// Destination Host
            dst_hst: SmolStr,
            /// Alternate Destination Hosts
            #[serde(default)]
            dst_alt: Vec<SmolStr>,
            #[serde(flatten)]
            creds: Option<CredsClaims>,
        },
    }

    #[derive(Serialize, Deserialize)]
    struct AssociationClaimsHelper {
        #[serde(default = "Uuid::new_v4")] // DVLS up to 2021.2.10 do not generate this claim.
        jet_aid: Uuid,
        jet_ap: ApplicationProtocol,
        #[serde(flatten)]
        jet_cm: ConnectionModeHelper,
        #[serde(default)]
        jet_rec: bool,
        #[serde(default)]
        jet_flt: bool,
        #[serde(default)]
        jet_ttl: SessionTtl,
        exp: i64,
        jti: Option<Uuid>, // DVLS up to 2022.1.9 do not generate this claim.
    }

    #[derive(Serialize, Deserialize)]
    struct JmuxClaimsHelper {
        // Main target host
        dst_hst: SmolStr,
        // Additional target hosts
        #[serde(default)]
        dst_addl: Vec<SmolStr>,
        #[serde(default)]
        jet_ap: ApplicationProtocol,
        jet_aid: Uuid,
        #[serde(default)]
        jet_ttl: SessionTtl,
        exp: i64,
        jti: Uuid,
    }

    #[derive(Serialize, Deserialize)]
    struct KdcClaimsHelper {
        krb_realm: SmolStr,
        krb_kdc: SmolStr,
    }

    impl ser::Serialize for SessionTtl {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                SessionTtl::Unlimited => serializer.serialize_u64(0),
                SessionTtl::Limited { minutes } => serializer.serialize_u64(minutes.get()),
            }
        }
    }

    impl<'de> de::Deserialize<'de> for SessionTtl {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            u64::deserialize(deserializer).map(SessionTtl::from)
        }
    }

    impl ser::Serialize for AssociationTokenClaims {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            AssociationClaimsHelper {
                jet_aid: self.jet_aid,
                jet_ap: self.jet_ap.clone(),
                jet_cm: match &self.jet_cm {
                    ConnectionMode::Rdv => ConnectionModeHelper::Rdv,
                    ConnectionMode::Fwd { targets, creds } => ConnectionModeHelper::Fwd {
                        dst_hst: SmolStr::new(targets.first().as_str()),
                        dst_alt: targets
                            .tail()
                            .iter()
                            .map(|target| SmolStr::new(target.as_str()))
                            .collect(),
                        creds: creds.clone(),
                    },
                },
                jet_rec: self.jet_rec,
                jet_flt: self.jet_flt,
                jet_ttl: self.jet_ttl,
                exp: self.exp,
                jti: self.jti,
            }
            .serialize(serializer)
        }
    }

    impl<'de> de::Deserialize<'de> for AssociationTokenClaims {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let claims = AssociationClaimsHelper::deserialize(deserializer)?;

            let jet_cm = match claims.jet_cm {
                ConnectionModeHelper::Rdv => ConnectionMode::Rdv,
                ConnectionModeHelper::Fwd {
                    dst_hst,
                    dst_alt,
                    creds,
                } => {
                    let primary_target =
                        TargetAddr::parse(&dst_hst, claims.jet_ap.known_default_port()).map_err(de::Error::custom)?;

                    let mut targets = NonEmpty {
                        head: primary_target,
                        tail: Vec::with_capacity(dst_alt.len()),
                    };

                    for alt in dst_alt {
                        let alt =
                            TargetAddr::parse(&alt, claims.jet_ap.known_default_port()).map_err(de::Error::custom)?;
                        targets.push(alt);
                    }

                    ConnectionMode::Fwd { targets, creds }
                }
            };

            Ok(Self {
                jet_aid: claims.jet_aid,
                jet_ap: claims.jet_ap,
                jet_cm,
                jet_rec: claims.jet_rec,
                jet_flt: claims.jet_flt,
                jet_ttl: claims.jet_ttl,
                exp: claims.exp,
                jti: claims.jti,
            })
        }
    }

    impl ser::Serialize for JmuxTokenClaims {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            JmuxClaimsHelper {
                dst_hst: SmolStr::new(self.hosts.first().as_str()),
                dst_addl: self
                    .hosts
                    .tail()
                    .iter()
                    .map(|target| SmolStr::new(target.as_str()))
                    .collect(),
                jet_ap: self.jet_ap.clone(),
                jet_aid: self.jet_aid,
                jet_ttl: self.jet_ttl,
                exp: self.exp,
                jti: self.jti,
            }
            .serialize(serializer)
        }
    }

    impl<'de> de::Deserialize<'de> for JmuxTokenClaims {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use crate::target_addr::BadTargetAddr;

            let claims = JmuxClaimsHelper::deserialize(deserializer)?;

            let jet_ap = claims.jet_ap;

            let primary = parse_target_address(&claims.dst_hst, &jet_ap).map_err(de::Error::custom)?;

            let mut hosts = NonEmpty {
                head: primary,
                tail: Vec::with_capacity(claims.dst_addl.len()),
            };

            for additional in claims.dst_addl {
                let additional = parse_target_address(&additional, &jet_ap).map_err(de::Error::custom)?;
                hosts.push(additional);
            }

            return Ok(Self {
                jet_aid: claims.jet_aid,
                hosts,
                jet_ap,
                jet_ttl: claims.jet_ttl,
                exp: claims.exp,
                jti: claims.jti,
            });

            // -- local helper -- //

            fn parse_target_address(s: &str, jet_ap: &ApplicationProtocol) -> Result<TargetAddr, BadTargetAddr> {
                const PORT_HTTP: u16 = 80;
                const PORT_HTTPS: u16 = 443;
                const PORT_FTP: u16 = 21;
                const DEFAULT_SCHEME: &str = "tcp";

                let default_port = match s.split("://").next() {
                    Some("http" | "ws") => PORT_HTTP,
                    Some("https" | "wss") => PORT_HTTPS,
                    Some("ftp") => PORT_FTP,
                    Some(_) | None => jet_ap.known_default_port().unwrap_or(PORT_HTTP),
                };

                TargetAddr::parse_with_default_scheme(s, DEFAULT_SCHEME, default_port)
            }
        }
    }

    impl ser::Serialize for KdcTokenClaims {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            KdcClaimsHelper {
                krb_realm: self.krb_realm.clone(),
                krb_kdc: SmolStr::new(self.krb_kdc.as_str()),
            }
            .serialize(serializer)
        }
    }

    impl<'de> de::Deserialize<'de> for KdcTokenClaims {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            const DEFAULT_KDC_PORT: u16 = 88;

            let claims = KdcClaimsHelper::deserialize(deserializer)?;

            // Validate krb_realm value

            if claims.krb_realm.chars().any(char::is_uppercase) {
                return Err(de::Error::custom("krb_realm field contains uppercases"));
            }

            // Validate krb_kdc field

            let krb_kdc = TargetAddr::parse(&claims.krb_kdc, DEFAULT_KDC_PORT).map_err(de::Error::custom)?;
            match krb_kdc.scheme() {
                "tcp" | "udp" => { /* supported! */ }
                unsupported_scheme => {
                    return Err(de::Error::custom(format!(
                        "unsupported protocol for KDC proxy: {unsupported_scheme}"
                    )));
                }
            }

            Ok(Self {
                krb_realm: claims.krb_realm,
                krb_kdc,
            })
        }
    }
}
