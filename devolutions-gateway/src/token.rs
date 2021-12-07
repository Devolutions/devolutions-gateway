use crate::utils::TargetAddr;
use parking_lot::Mutex;
use picky::key::{PrivateKey, PublicKey};
use serde::de;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use uuid::Uuid;
use zeroize::Zeroize;

lazy_static::lazy_static! {
    static ref TOKEN_CACHE: Mutex<HashMap<Uuid, TokenSource>> = Mutex::new(HashMap::new());
}

const LEEWAY_SECS: u16 = 60 * 5; // 5 minutes
const CLEANUP_TASK_INTERVAL_SECS: u64 = 60 * 30; // 30 minutes

// ----- generic struct -----

#[derive(Deserialize, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum JetAccessTokenClaims {
    Association(JetAssociationTokenClaims),
    Scope(JetScopeTokenClaims),
    Bridge(JetBridgeTokenClaims),
    Jmux(JetJmuxTokenClaims),
}

impl JetAccessTokenClaims {
    fn contains_secret(&self) -> bool {
        match &self {
            JetAccessTokenClaims::Association(claims) => claims.contains_secret(),
            JetAccessTokenClaims::Scope(_) => false,
            JetAccessTokenClaims::Bridge(_) => false,
            JetAccessTokenClaims::Jmux(_) => false,
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

    /// Connection should be forwared to a given destination host
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
            #[serde(default = "Uuid::new_v4")] // legacy: DVLS up to 2021.2.10 do not generate this claim.
            jet_aid: Uuid,
            jet_ap: ApplicationProtocol,
            #[serde(flatten)]
            jet_cm: ConnectionModeHelper,
            #[serde(default)]
            jet_rec: bool,
            #[serde(default)]
            jet_flt: bool,
            exp: i64,
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

        Ok(JetAssociationTokenClaims {
            jet_aid: claims.jet_aid,
            jet_ap: claims.jet_ap,
            jet_cm,
            jet_rec: claims.jet_rec,
            jet_flt: claims.jet_flt,
            exp: claims.exp,
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
}

#[derive(Clone, Deserialize)]
pub struct JetScopeTokenClaims {
    pub scope: JetAccessScope,
}

// ----- bridge claims ----- //

#[derive(Clone, Deserialize)]
pub struct JetBridgeTokenClaims {
    pub target_host: TargetAddr,
}

// ----- jmux claims ----- //

#[derive(Clone, Deserialize)]
pub struct JetJmuxTokenClaims {
    _filtering: Option<()>, // TODO
}

// ----- validation ----- //

#[derive(Debug, Clone)]
struct TokenSource {
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
) -> Result<JetAccessTokenClaims, io::Error> {
    use picky::jose::jwe::Jwe;
    use picky::jose::jwt::{JwtDate, JwtSig, JwtValidator};
    use serde_json::Value;

    let is_encrypted = is_encrypted(token);

    let jwe_token; // pre-declaration for extended lifetime

    let signed_jwt = if is_encrypted {
        let encrypted_jwt = token;

        let delegation_key =
            delegation_key.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Delegation key is missing"))?;

        jwe_token = Jwe::decode(encrypted_jwt, delegation_key).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decode encrypted JWT routing token: {}", e),
            )
        })?;

        std::str::from_utf8(&jwe_token.payload).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decode encrypted JWT routing token payload: {}", e),
            )
        })?
    } else {
        token
    };

    let timestamp_now = chrono::Utc::now().timestamp();
    let now = JwtDate::new_with_leeway(timestamp_now, LEEWAY_SECS);
    let validator = JwtValidator::strict(&now);

    let jwt_token = JwtSig::<Value>::decode(signed_jwt, provisioner_key, &validator).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode signed payload of JWT routing token: {}", e),
        )
    })?;

    let claims = match serde_json::from_value::<JetAccessTokenClaims>(jwt_token.claims.clone()) {
        Ok(claims) => claims,
        Err(primary_error) => {
            let association_claims =
                serde_json::from_value::<JetAssociationTokenClaims>(jwt_token.claims).map_err(|secondary_error| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("couldn't decode token claims: {} & {}", primary_error, secondary_error),
                    )
                })?;
            JetAccessTokenClaims::Association(association_claims)
        }
    };

    if claims.contains_secret() && !is_encrypted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received a non encrypted JWT containing secrets. This is unacceptable, do it right!",
        ));
    }

    // Mitigate replay attacks using the token cache
    match &claims {
        JetAccessTokenClaims::Association(association_claims) => {
            use std::collections::hash_map::Entry;
            match TOKEN_CACHE.lock().entry(association_claims.jet_aid) {
                Entry::Occupied(bucket) => {
                    if bucket.get().ip != source_ip {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "received identical token twice from another IP. A replay attack may have been attempted.",
                        ));
                    }
                }
                Entry::Vacant(bucket) => {
                    bucket.insert(TokenSource {
                        ip: source_ip,
                        expiration_timestamp: association_claims.exp,
                    });
                }
            }
        }
        JetAccessTokenClaims::Scope(_) => (),
        JetAccessTokenClaims::Bridge(_) => (),
        JetAccessTokenClaims::Jmux(_) => (),
    }

    Ok(claims)
}

pub async fn cleanup_task() {
    use tokio::time::{sleep, Duration};

    loop {
        sleep(Duration::from_secs(CLEANUP_TASK_INTERVAL_SECS)).await;
        let clean_threshold = chrono::Utc::now().timestamp() - i64::from(LEEWAY_SECS);
        TOKEN_CACHE
            .lock()
            .retain(|_, src| src.expiration_timestamp > clean_threshold);
    }
}
