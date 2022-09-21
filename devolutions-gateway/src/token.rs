use crate::utils::TargetAddr;
use anyhow::Context as _;
use core::fmt;
use nonempty::NonEmpty;
use parking_lot::Mutex;
use picky::jose::jws::RawJws;
use picky::key::{PrivateKey, PublicKey};
use serde::{de, ser};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

const LEEWAY_SECS: u16 = 60 * 5; // 5 minutes
const CLEANUP_TASK_INTERVAL_SECS: u64 = 60 * 30; // 30 minutes
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
    Kdc,
    Jrl,
}

impl FromStr for ContentType {
    type Err = BadContentType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ASSOCIATION" => Ok(ContentType::Association),
            "SCOPE" => Ok(ContentType::Scope),
            "BRIDGE" => Ok(ContentType::Bridge),
            "JMUX" => Ok(ContentType::Jmux),
            "KDC" => Ok(ContentType::Kdc),
            "JRL" => Ok(ContentType::Jrl),
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
            ContentType::Kdc => write!(f, "KDC"),
            ContentType::Jrl => write!(f, "JRL"),
        }
    }
}

#[derive(Debug)]
pub struct BadContentType {
    pub value: SmolStr,
}

impl fmt::Display for BadContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unexpected content type: {}", self.value)
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
    Kdc(KdcTokenClaims),
    Jrl(JrlTokenClaims),
}

impl AccessTokenClaims {
    fn contains_secret(&self) -> bool {
        match self {
            AccessTokenClaims::Association(claims) => claims.contains_secret(),
            AccessTokenClaims::Scope(_) => false,
            AccessTokenClaims::Bridge(_) => false,
            AccessTokenClaims::Jmux(_) => false,
            AccessTokenClaims::Kdc(_) => false,
            AccessTokenClaims::Jrl(_) => false,
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
            Self::Known(known) => Some(known.known_default_port()),
            Self::Unknown(_) => None,
        }
    }
}

impl Default for ApplicationProtocol {
    fn default() -> Self {
        Self::unknown()
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
    /// Secure Shell Protocol
    Ssh,
    /// PowerShell over SSH
    SshPwsh,
    /// SSH File Transfer Protocol
    Sftp,
    /// Secure Copy Protocol
    Scp,
    /// PowerShell over WinRM via HTTP transport
    WinrmHttpPwsh,
    /// PowerShell over WinRM via HTTPS transport
    WinrmHttpsPwsh,
    /// Hypertext Transfer Protocol
    Http,
    /// Hypertext Transfer Protocol Secure
    Https,
}

impl Protocol {
    pub fn known_default_port(self) -> u16 {
        match self {
            Self::Wayk => 12876,
            Self::Rdp => 3389,
            Self::Ard => 5900,
            Self::Vnc => 5900,
            Self::Ssh => 22,
            Self::SshPwsh => 22,
            Self::WinrmHttpPwsh => 5985,
            Self::WinrmHttpsPwsh => 5986,
            Self::Sftp => 22,
            Self::Scp => 22,
            Self::Http => 80,
            Self::Https => 443,
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
        targets: Vec<TargetAddr>,

        /// Credentials to use if protocol is wrapped by the Gateway (e.g. RDP TLS)
        creds: Option<CredsClaims>,
    },
}

#[derive(Deserialize, Zeroize, Clone)]
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
#[derive(Debug, Clone, Copy)]
pub enum SessionTtl {
    Unlimited,
    Limited { minutes: NonZeroU64 },
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

    // JWT expiration time claim.
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitly written in the structure to be checked by the JwtValidator.
    exp: i64,

    // Unique ID for this token
    // DVLS up to 2022.1.9 do not generate this claim.
    jti: Option<Uuid>,
}

impl AssociationTokenClaims {
    fn contains_secret(&self) -> bool {
        matches!(&self.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. })
    }
}

impl<'de> de::Deserialize<'de> for AssociationTokenClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Clone)]
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

        #[derive(Deserialize)]
        struct ClaimsHelper {
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
            jet_ttl: u64,
            exp: i64,
            jti: Option<Uuid>, // DVLS up to 2022.1.9 do not generate this claim.
        }

        let claims = ClaimsHelper::deserialize(deserializer)?;

        let jet_cm = match claims.jet_cm {
            ConnectionModeHelper::Rdv => ConnectionMode::Rdv,
            ConnectionModeHelper::Fwd {
                dst_hst,
                dst_alt,
                creds,
            } => {
                let primary_target =
                    TargetAddr::parse(&dst_hst, claims.jet_ap.known_default_port()).map_err(de::Error::custom)?;

                let mut targets = Vec::with_capacity(dst_alt.len() + 1);
                targets.push(primary_target);

                for alt in dst_alt {
                    let alt = TargetAddr::parse(&alt, claims.jet_ap.known_default_port()).map_err(de::Error::custom)?;
                    targets.push(alt);
                }

                ConnectionMode::Fwd { targets, creds }
            }
        };

        let jet_ttl = SessionTtl::from(claims.jet_ttl);

        Ok(Self {
            jet_aid: claims.jet_aid,
            jet_ap: claims.jet_ap,
            jet_cm,
            jet_rec: claims.jet_rec,
            jet_flt: claims.jet_flt,
            jet_ttl,
            exp: claims.exp,
            jti: claims.jti,
        })
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
}

#[derive(Clone, Deserialize)]
pub struct ScopeTokenClaims {
    pub scope: AccessScope,

    // JWT expiration time claim.
    exp: i64,

    // Unique ID for this token
    // DVLS up to 2022.1.9 do not generate this claim.
    jti: Option<Uuid>,
}

// ----- bridge claims ----- //

#[derive(Clone, Deserialize)]
pub struct BridgeTokenClaims {
    pub target_host: TargetAddr,

    // JWT expiration time claim.
    exp: i64,

    // Unique ID for this token
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

    // JWT expiration time claim.
    exp: i64,

    // Unique ID for this token
    jti: Uuid,
}

impl<'de> de::Deserialize<'de> for JmuxTokenClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::utils::BadTargetAddr;

        #[derive(Deserialize)]
        struct ClaimsHelper {
            // Main target host
            dst_hst: SmolStr,
            // Additional target hosts
            #[serde(default)]
            dst_addl: Vec<SmolStr>,
            #[serde(default)]
            jet_ap: ApplicationProtocol,
            jet_aid: Uuid,
            #[serde(default)]
            jet_ttl: u64,
            exp: i64,
            jti: Uuid,
        }

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

        let claims = ClaimsHelper::deserialize(deserializer)?;

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

        let jet_ttl = SessionTtl::from(claims.jet_ttl);

        Ok(Self {
            jet_aid: claims.jet_aid,
            hosts,
            jet_ap,
            jet_ttl,
            exp: claims.exp,
            jti: claims.jti,
        })
    }
}

// ----- KDC claims ----- //

#[derive(Clone)]
pub struct KdcTokenClaims {
    /// Kerberos realm.
    /// e.g.: ad.it-help.ninja
    /// Should be lowercased (actual validation is case-insensitive though).
    pub krb_realm: SmolStr,

    /// Kerberos KDC address.
    /// e.g.: tcp://IT-HELP-DC.ad.it-help.ninja:88
    /// Default scheme is `tcp`.
    /// Default port is `88`.
    pub krb_kdc: TargetAddr,
}

impl<'de> de::Deserialize<'de> for KdcTokenClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const DEFAULT_KDC_PORT: u16 = 88;

        #[derive(Deserialize)]
        struct ClaimsHelper {
            krb_realm: SmolStr,
            krb_kdc: SmolStr,
        }

        let claims = ClaimsHelper::deserialize(deserializer)?;

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
                    "unsupported protocol for KDC proxy: {}",
                    unsupported_scheme
                )));
            }
        }

        Ok(Self {
            krb_realm: claims.krb_realm,
            krb_kdc,
        })
    }
}

// ----- jrl claims ----- //

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JrlTokenClaims {
    /// Unique ID for this token
    pub jti: Uuid,

    /// JWT "Issued At" claim.
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

// ----- cache clean up ----- //

pub async fn cleanup_task(token_cache: Arc<TokenCache>) {
    use tokio::time::{sleep, Duration};

    loop {
        sleep(Duration::from_secs(CLEANUP_TASK_INTERVAL_SECS)).await;
        let clean_threshold = chrono::Utc::now().timestamp() - i64::from(LEEWAY_SECS);
        token_cache
            .lock()
            .retain(|_, src| src.expiration_timestamp > clean_threshold);
    }
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

#[derive(typed_builder::TypedBuilder)]
pub struct TokenValidator<'a> {
    source_ip: IpAddr,
    provisioner_key: &'a PublicKey,
    token_cache: &'a TokenCache,
    revocation_list: &'a CurrentJrl,
    delegation_key: Option<&'a PrivateKey>,
    subkey: Option<&'a Subkey>,
    gw_id: Option<Uuid>,
}

impl TokenValidator<'_> {
    pub fn validate(&self, token: &str) -> anyhow::Result<AccessTokenClaims> {
        validate_token_impl(
            token,
            self.source_ip,
            self.provisioner_key,
            self.token_cache,
            self.revocation_list,
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
    delegation_key: Option<&PrivateKey>,
    subkey: Option<&Subkey>,
    gw_id: Option<Uuid>,
) -> anyhow::Result<AccessTokenClaims> {
    use picky::jose::jwe::Jwe;
    use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
    use serde_json::Value;
    use std::collections::hash_map::Entry;

    // === Decoding JWT === //

    let is_encrypted = is_encrypted(token);

    let jwe_token; // pre-declaration for extended lifetime

    let signed_jwt = if is_encrypted {
        let encrypted_jwt = token;
        let delegation_key = delegation_key.context("Delegation key is missing")?;
        jwe_token =
            Jwe::decode(encrypted_jwt, delegation_key).context("Failed to decode encrypted JWT routing token")?;
        std::str::from_utf8(&jwe_token.payload).context("Failed to decode encrypted JWT routing token payload")?
    } else {
        token
    };

    let (jwt, using_subkey): (JwtSig, bool) = {
        let raw_jws = RawJws::decode(signed_jwt).context("Failed to decode signed payload of JWT routing token")?;

        match (&raw_jws.header.kid, subkey) {
            // Standard verification using master provisioner key
            (None, _) => (
                raw_jws
                    .verify(provisioner_key)
                    .map(JwtSig::from)
                    .context("Failed to verify signature of JWT routing token using the provisioner key")?,
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
                    .context("Failed to verify signature of JWT routing token using the subkey")?,
                true,
            ),

            // Subkey is missing or kid does not match
            (Some(provided_kid), maybe_subkey) => {
                debug!(kid = %provided_kid, subkey = ?maybe_subkey, "bad subkey usage detected");
                anyhow::bail!("kid in token is referring to an unknown subkey")
            }
        }
    };

    // === Extracting content type and validating JWT claims === //

    let timestamp_now = chrono::Utc::now().timestamp();
    let now = JwtDate::new_with_leeway(timestamp_now, LEEWAY_SECS);
    let strict_validator = JwtValidator::strict(now);

    let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
        let content_type = content_type.parse::<ContentType>()?;

        let claims = match content_type {
            ContentType::Association
            | ContentType::Scope
            | ContentType::Bridge
            | ContentType::Jmux
            | ContentType::Kdc => jwt.validate::<Value>(&strict_validator)?.state.claims,
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
            ContentType::Association | ContentType::Jmux => {}
            _ => anyhow::bail!("Subkey can't be used to sign a {content_type:?} token"),
        }
    }

    if let Some(Value::String(expected_id)) = claims.get("jet_gw_id") {
        let expected_id = Uuid::parse_str(expected_id).context("bad claim `jet_gw_id`")?;

        match gw_id {
            // Gateway ID is required and must be equal to the scope
            Some(this_gw_id) if expected_id == this_gw_id => {}

            // Gateway ID scope rule is not respected
            Some(_) => anyhow::bail!("This token can't be used for this Gateway (bad ID scope)"),
            None => {
                warn!("This token is restricted to a specific gateway, but no ID has been assigned. This may become a hard error in the future.")
            }
        }
    }

    // === Check for revoked values in JWT Revocation List === //

    for (key, revoked_values) in &revocation_list.lock().jrl {
        if let Some(value) = claims.get(key) {
            if revoked_values.contains(value) {
                anyhow::bail!("Received a token containing a revoked value.");
            }
        }
    }

    // === Convert json value into an instance of the correct claims type === //

    let claims = match content_type {
        ContentType::Association => serde_json::from_value(claims).map(AccessTokenClaims::Association),
        ContentType::Scope => serde_json::from_value(claims).map(AccessTokenClaims::Scope),
        ContentType::Bridge => serde_json::from_value(claims).map(AccessTokenClaims::Bridge),
        ContentType::Jmux => serde_json::from_value(claims).map(AccessTokenClaims::Jmux),
        ContentType::Kdc => serde_json::from_value(claims).map(AccessTokenClaims::Kdc),
        ContentType::Jrl => serde_json::from_value(claims).map(AccessTokenClaims::Jrl),
    }
    .with_context(|| format!("Invalid claims for {content_type:?} token"))?;

    // === Applying additional validations as appropriate === //

    if claims.contains_secret() && !is_encrypted {
        anyhow::bail!("Received a non encrypted JWT containing secrets. This is unacceptable, do it right!");
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
            let now = chrono::Utc::now().timestamp();

            match token_cache.lock().entry(id) {
                Entry::Occupied(bucket) => {
                    if bucket.get().ip != source_ip {
                        anyhow::bail!(
                            "A token was reused from another IP for RDP protocol. A replay attack may have been attempted."
                        );
                    }

                    if now > bucket.get().last_use_timestamp + MAX_REUSE_INTERVAL_SECS {
                        anyhow::bail!(
                            "A token was reused from the same IP for RDP protocol but the maximum reuse interval is exceeded."
                        );
                    }

                    // Refresh the last use timestamp
                    bucket.get_mut().last_use_timestamp = now;
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
                anyhow::bail!("Received identical token twice. A replay attack may have been attempted.");
            }
            Entry::Vacant(bucket) => {
                bucket.insert(TokenSource {
                    ip: source_ip,
                    expiration_timestamp: exp,
                    last_use_timestamp: chrono::Utc::now().timestamp(),
                });
            }
        },

        // No mitigation if token has no ID (might be disallowed in the future)
        AccessTokenClaims::Scope(ScopeTokenClaims { jti: None, .. }) => {}

        // KDC tokens are long-lived and may be reused safely
        AccessTokenClaims::Kdc(_) => {}

        // JRL token must be more recent than the current revocation list
        AccessTokenClaims::Jrl(JrlTokenClaims { iat, .. }) => {
            if iat < revocation_list.lock().iat {
                anyhow::bail!("Received an older JWT Revocation List token.");
            }
        }
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
    ) -> anyhow::Result<AccessTokenClaims> {
        use picky::jose::jwe::Jwe;
        use picky::jose::jwt::JwtSig;
        use serde_json::Value;

        warn!("**DEBUG OPTION** using dangerous token validation for testing purposes. Make sure this is not happening in production!");

        // === Decoding JWT === //

        let is_encrypted = is_encrypted(token);

        let jwe_token; // pre-declaration for extended lifetime

        let signed_jwt = if is_encrypted {
            let encrypted_jwt = token;
            let delegation_key = delegation_key.context("Delegation key is missing")?;
            jwe_token =
                Jwe::decode(encrypted_jwt, delegation_key).context("Failed to decode encrypted JWT routing token")?;
            std::str::from_utf8(&jwe_token.payload).context("Failed to decode encrypted JWT routing token payload")?
        } else {
            token
        };

        let jwt = RawJws::decode(signed_jwt)
            .map(RawJws::discard_signature)
            .map(JwtSig::from)
            .context("Failed to decode signed payload of JWT routing token")?;

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
            ContentType::Kdc => serde_json::from_value(claims).map(AccessTokenClaims::Kdc),
            ContentType::Jrl => serde_json::from_value(claims).map(AccessTokenClaims::Jrl),
        }
        .with_context(|| format!("Invalid claims for {content_type:?} token"))?;

        // Other checks are removed as well

        Ok(claims)
    }
}
