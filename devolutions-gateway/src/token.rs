use crate::utils::TargetAddr;
use anyhow::Context as _;
use core::fmt;
use parking_lot::Mutex;
use picky::key::{PrivateKey, PublicKey};
use serde::de;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

const LEEWAY_SECS: u16 = 60 * 5; // 5 minutes
const CLEANUP_TASK_INTERVAL_SECS: u64 = 60 * 30; // 30 minutes

pub type TokenCache = Mutex<HashMap<Uuid, TokenSource>>;
pub type CurrentJrl = Mutex<JrlTokenClaims>;

// ----- token types -----

#[derive(Deserialize)]
enum ContentType {
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

#[derive(Debug)]
struct BadContentType {
    value: SmolStr,
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
    Association(JetAssociationTokenClaims),
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

// ----- association claims ----- //

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationProtocol {
    Wayk,
    Pwsh,
    Rdp,
    Ard,
    Ssh,
    Sftp,
    #[serde(other)]
    Unknown,
}

impl ApplicationProtocol {
    pub fn known_default_port(self) -> Option<u16> {
        match self {
            ApplicationProtocol::Wayk => None,
            ApplicationProtocol::Pwsh => None,
            ApplicationProtocol::Rdp => Some(3389),
            ApplicationProtocol::Ard => Some(3283),
            ApplicationProtocol::Ssh => Some(22),
            ApplicationProtocol::Sftp => Some(22),
            ApplicationProtocol::Unknown => None,
        }
    }
}

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

#[derive(Clone)]
pub struct JetAssociationTokenClaims {
    /// Jet Association ID (= Session ID)
    pub jet_aid: Uuid,

    /// Jet Application protocol
    pub jet_ap: ApplicationProtocol,

    /// Jet Connection Mode
    pub jet_cm: ConnectionMode,

    /// Jet Recording Policy
    pub jet_rec: bool,

    /// Jet Filtering Policy
    pub jet_flt: bool,

    // JWT expiration time claim.
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitely written in the structure to be checked by the JwtValidator.
    exp: i64,

    // Unique ID for this token
    // DVLS up to 2022.1.9 do not generate this claim.
    jti: Option<Uuid>,
}

impl JetAssociationTokenClaims {
    fn contains_secret(&self) -> bool {
        matches!(&self.jet_cm, ConnectionMode::Fwd { creds: Some(_), .. })
    }
}

impl<'de> de::Deserialize<'de> for JetAssociationTokenClaims {
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

        Ok(Self {
            jet_aid: claims.jet_aid,
            jet_ap: claims.jet_ap,
            jet_cm,
            jet_rec: claims.jet_rec,
            jet_flt: claims.jet_flt,
            exp: claims.exp,
            jti: claims.jti,
        })
    }
}

// ----- scope claims ----- //

#[derive(Clone, Deserialize, PartialEq)]
pub enum JetAccessScope {
    #[serde(rename = "gateway.sessions.read")]
    GatewaySessionsRead,
    #[serde(rename = "gateway.associations.read")]
    GatewayAssociationsRead,
    #[serde(rename = "gateway.diagnostics.read")]
    GatewayDiagnosticsRead,
    #[serde(rename = "gateway.jrl.read")]
    GatewayJrlRead,
}

#[derive(Clone, Deserialize)]
pub struct ScopeTokenClaims {
    pub scope: JetAccessScope,

    // JWT expiration time claim.
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitely written in the structure to be checked by the JwtValidator.
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
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitely written in the structure to be checked by the JwtValidator.
    exp: i64,

    // Unique ID for this token
    jti: Uuid,
}

// ----- jmux claims ----- //

#[derive(Clone, Deserialize)]
pub struct JmuxTokenClaims {
    _filtering: Option<()>, // TODO

    // JWT expiration time claim.
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitely written in the structure to be checked by the JwtValidator.
    exp: i64,

    // Unique ID for this token
    jti: Uuid,
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

    // JWT expiration time claim.
    // We need this to build our token invalidation cache.
    // This doesn't need to be explicitely written in the structure to be checked by the JwtValidator.
    exp: i64,

    // Unique ID for this token
    jti: Uuid,
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
            exp: i64,
            jti: Uuid,
        }

        let claims = ClaimsHelper::deserialize(deserializer)?;

        // Validate krb_realm value

        if !claims.krb_realm.chars().all(char::is_lowercase) {
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
            exp: claims.exp,
            jti: claims.jti,
        })
    }
}

// ----- jrl claims ----- //

#[derive(Clone, Serialize, Deserialize)]
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

// ----- validation ----- //

#[derive(Debug, Clone)]
pub struct TokenSource {
    ip: IpAddr,
    expiration_timestamp: i64,
}

fn is_encrypted(token: &str) -> bool {
    let num_dots = token.chars().fold(0, |acc, c| if c == '.' { acc + 1 } else { acc });
    num_dots == 4
}

pub fn validate_token(
    token: &str,
    source_ip: IpAddr,
    provisioner_key: &PublicKey,
    delegation_key: Option<&PrivateKey>,
    token_cache: &TokenCache,
    revocation_list: &CurrentJrl,
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

    let jwt =
        JwtSig::decode(signed_jwt, provisioner_key).context("failed to decode signed payload of JWT routing token")?;

    // === Extracting content type and validating JWT claims === //

    let timestamp_now = chrono::Utc::now().timestamp();
    let now = JwtDate::new_with_leeway(timestamp_now, LEEWAY_SECS);
    let strict_validator = JwtValidator::strict(&now);

    let (claims, content_type) = if let Some(content_type) = jwt.header.cty.as_deref() {
        let content_type = content_type.parse::<ContentType>()?;

        let claims = match content_type {
            ContentType::Association
            | ContentType::Scope
            | ContentType::Bridge
            | ContentType::Jmux
            | ContentType::Kdc => jwt.validate::<Value>(&strict_validator)?.state.claims,
            ContentType::Jrl => {
                // NOTE: JRL tokens are not expected to have any expiration.
                // However, `iat` (Issued At) claim will be used, and only more recent tokens will
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

    // === Check for revoked values in JWT Revocation List === //

    for (key, revoked_values) in &revocation_list.lock().jrl {
        if let Some(token_value) = claims.get(key) {
            if revoked_values.contains(token_value) {
                anyhow::bail!("received a token containing a revoked value.");
            }
        }
    }

    // === Convert json value into an instance of the correct claims type === //

    let claims = match content_type {
        ContentType::Association => AccessTokenClaims::Association(serde_json::from_value(claims)?),
        ContentType::Scope => AccessTokenClaims::Scope(serde_json::from_value(claims)?),
        ContentType::Bridge => AccessTokenClaims::Bridge(serde_json::from_value(claims)?),
        ContentType::Jmux => AccessTokenClaims::Jmux(serde_json::from_value(claims)?),
        ContentType::Kdc => AccessTokenClaims::Kdc(serde_json::from_value(claims)?),
        ContentType::Jrl => AccessTokenClaims::Jrl(serde_json::from_value(claims)?),
    };

    // === Applying additional validations as appropriate === //

    if claims.contains_secret() && !is_encrypted {
        anyhow::bail!("received a non encrypted JWT containing secrets. This is unacceptable, do it right!");
    }

    match claims {
        // Mitigate replay attacks for RDP associations by rejecting token re-use from a different
        // source address IP (RDP requires multiple connections, so we can't just reject everything)
        AccessTokenClaims::Association(
            JetAssociationTokenClaims {
                jti: Some(id),
                exp,
                jet_ap: ApplicationProtocol::Rdp,
                ..
            }
            | JetAssociationTokenClaims {
                jet_aid: id,
                exp,
                jet_ap: ApplicationProtocol::Rdp,
                ..
            },
        ) => match token_cache.lock().entry(id) {
            Entry::Occupied(bucket) => {
                if bucket.get().ip != source_ip {
                    anyhow::bail!(
                        "received identical token twice from another IP for RDP protocol. A replay attack may have been attempted."
                    );
                }
            }
            Entry::Vacant(bucket) => {
                bucket.insert(TokenSource {
                    ip: source_ip,
                    expiration_timestamp: exp,
                });
            }
        },

        // All other tokens can't be re-used even if source IP is identical
        AccessTokenClaims::Association(JetAssociationTokenClaims { jti: Some(id), exp, .. })
        | AccessTokenClaims::Association(JetAssociationTokenClaims { jet_aid: id, exp, .. })
        | AccessTokenClaims::Scope(ScopeTokenClaims { jti: Some(id), exp, .. })
        | AccessTokenClaims::Bridge(BridgeTokenClaims { jti: id, exp, .. })
        | AccessTokenClaims::Jmux(JmuxTokenClaims { jti: id, exp, .. })
        | AccessTokenClaims::Kdc(KdcTokenClaims { jti: id, exp, .. }) => match token_cache.lock().entry(id) {
            Entry::Occupied(_) => {
                anyhow::bail!("received identical token twice. A replay attack may have been attempted.");
            }
            Entry::Vacant(bucket) => {
                bucket.insert(TokenSource {
                    ip: source_ip,
                    expiration_timestamp: exp,
                });
            }
        },

        // No mitigation if token has no ID (might be disallowed in the future)
        AccessTokenClaims::Scope(ScopeTokenClaims { jti: None, .. }) => {}

        // JRL token must be more recent than the current revocation list
        AccessTokenClaims::Jrl(JrlTokenClaims { iat, .. }) => {
            if iat < revocation_list.lock().iat {
                anyhow::bail!("received an older JWT Revocation List token.");
            }
        }
    }

    Ok(claims)
}

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

pub fn new_token_cache() -> TokenCache {
    Mutex::new(HashMap::new())
}
