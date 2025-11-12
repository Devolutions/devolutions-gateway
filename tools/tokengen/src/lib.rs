pub mod server;

use picky::jose::jwe::{Jwe, JweAlg, JweEnc};
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::SystemTime;
use tap::prelude::*;
use uuid::Uuid;

// --- Claims Structures --- //

#[derive(Clone, Serialize)]
pub struct AssociationClaims<'a> {
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
    pub jet_cm: &'a str,
    pub jet_ap: ApplicationProtocol,
    pub jet_rec: RecordingPolicy,
    pub jet_aid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_reuse: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_hst: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_thumb256: Option<&'a str>,
    #[serde(flatten)]
    pub creds: Option<CredsClaims<'a>>,
}

#[derive(Clone, Serialize)]
pub struct CredsClaims<'a> {
    pub prx_usr: &'a str,
    pub prx_pwd: &'a str,
    pub dst_usr: &'a str,
    pub dst_pwd: &'a str,
}

#[derive(Clone, Serialize)]
pub struct ScopeClaims<'a> {
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
    pub scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
pub struct BridgeTokenClaims<'a> {
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
    pub target_host: &'a str,
    pub jet_aid: Uuid,
    pub jet_ap: ApplicationProtocol,
    pub jet_rec: RecordingPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
pub struct JmuxClaims<'a> {
    pub dst_hst: &'a str,
    pub dst_addl: Vec<&'a str>,
    pub jet_ap: ApplicationProtocol,
    pub jet_rec: RecordingPolicy,
    pub jet_aid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
}

#[derive(Clone, Serialize)]
pub struct JrecClaims {
    pub jet_aid: Uuid,
    pub jet_rop: RecordingOperation,
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_reuse: Option<u32>,
}

#[derive(Clone, Serialize)]
pub struct KdcClaims<'a> {
    pub krb_realm: &'a str,
    pub krb_kdc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
    pub exp: i64,
    pub nbf: i64,
    pub jti: Uuid,
}

#[derive(Clone, Serialize)]
pub struct JrlClaims<'a> {
    pub jti: Uuid,
    pub iat: i64,
    pub jrl: HashMap<&'a str, Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jet_gw_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
pub struct NetScanClaim {
    /// JWT "JWT ID" claim, the unique ID for this token
    pub jti: Uuid,

    /// JWT "Issued At" claim.
    pub iat: i64,

    /// JWT "Not Before" claim.
    pub nbf: i64,

    /// JWT "Expiration Time" claim.
    pub exp: i64,

    pub jet_gw_id: Option<Uuid>,
}

// --- Enums --- //

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationProtocol {
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
    /// LDAP Protocol
    Ldap,
    /// Secure LDAP Protocol
    Ldaps,
    /// Unknown Protocol
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordingOperation {
    Push,
    Pull,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecordingPolicy {
    #[default]
    None,
    /// An external application (e.g.: RDM) must push the recording stream via a separate websocket connection
    Stream,
    /// Session must be recorded directly at Devolutions Gateway level
    Proxy,
}

macro_rules! impl_from_str {
    ($ty:ty) => {
        impl std::str::FromStr for $ty {
            type Err = serde_json::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // Not the most elegant / performant solution, but it's DRY and good enough for a small tool like this one.
                let json_s = format!("\"{s}\"");
                serde_json::from_str(&json_s)
            }
        }
    };
}

impl_from_str!(ApplicationProtocol);
impl_from_str!(RecordingOperation);
impl_from_str!(RecordingPolicy);

// --- SubCommandArgs Enum --- //

#[derive(Clone)]
pub enum SubCommandArgs {
    Forward {
        dst_hst: String,
        jet_ap: Option<ApplicationProtocol>,
        jet_ttl: Option<u64>,
        jet_aid: Option<Uuid>,
        jet_rec: bool,
        jet_reuse: Option<u32>,
        cert_thumb256: Option<String>,
    },
    Rendezvous {
        jet_ap: Option<ApplicationProtocol>,
        jet_aid: Option<Uuid>,
        jet_rec: bool,
    },
    RdpTls {
        dst_hst: String,
        prx_usr: String,
        prx_pwd: String,
        dst_usr: String,
        dst_pwd: String,
        jet_aid: Option<Uuid>,
    },
    Scope {
        scope: String,
    },
    Bridge {
        target_host: String,
        jet_aid: Option<Uuid>,
        jet_ap: Option<ApplicationProtocol>,
        jet_rec: bool,
        jet_ttl: Option<u64>,
    },
    Jmux {
        jet_ap: Option<ApplicationProtocol>,
        dst_hst: String,
        dst_addl: Vec<String>,
        jet_ttl: Option<u64>,
        jet_aid: Option<Uuid>,
        jet_rec: bool,
    },
    Jrec {
        jet_rop: RecordingOperation,
        jet_aid: Option<Uuid>,
        jet_reuse: Option<u32>,
    },
    Kdc {
        krb_realm: String,
        krb_kdc: String,
    },
    Jrl {
        revoked_jti_list: Vec<Uuid>,
    },
    NetScan {},
}

pub fn generate_token(
    provisioner_key_path: &std::path::Path,
    validity_duration: std::time::Duration,
    kid: Option<String>,
    delegation_key_path: Option<&std::path::Path>,
    jet_gw_id: Option<Uuid>,
    subcommand: SubCommandArgs,
) -> Result<String, Box<dyn Error>> {
    let provisioner_key = std::fs::read_to_string(provisioner_key_path)?
        .pipe_deref(str::parse::<Pem>)?
        .pipe_ref(PrivateKey::from_pem)?;

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let nbf = i64::try_from(now.as_secs()).unwrap();
    let exp = i64::try_from((now + validity_duration).as_secs()).unwrap();

    let jti = Uuid::new_v4();

    let (cty, claims) = match subcommand {
        SubCommandArgs::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
            jet_aid,
            jet_rec,
            jet_reuse,
            cert_thumb256,
        } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&dst_hst),
                jet_cm: "fwd",
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_rec: if jet_rec {
                    RecordingPolicy::Stream
                } else {
                    RecordingPolicy::None
                },
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_ttl,
                jet_gw_id,
                jet_reuse,
                cert_thumb256: cert_thumb256.as_deref(),
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(claims)?)
        }
        SubCommandArgs::RdpTls {
            dst_hst,
            prx_usr,
            prx_pwd,
            dst_usr,
            dst_pwd,
            jet_aid,
        } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&dst_hst),
                jet_cm: "fwd",
                jet_ap: ApplicationProtocol::Rdp,
                jet_rec: RecordingPolicy::None,
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_ttl: None,
                jet_gw_id,
                jet_reuse: None,
                cert_thumb256: None,
                creds: Some(CredsClaims {
                    prx_usr: &prx_usr,
                    prx_pwd: &prx_pwd,
                    dst_usr: &dst_usr,
                    dst_pwd: &dst_pwd,
                }),
            };
            ("ASSOCIATION", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Rendezvous {
            jet_ap,
            jet_aid,
            jet_rec,
        } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: None,
                jet_cm: "rdv",
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_rec: if jet_rec {
                    RecordingPolicy::Stream
                } else {
                    RecordingPolicy::None
                },
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_ttl: None,
                jet_gw_id,
                jet_reuse: None,
                cert_thumb256: None,
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Scope { scope } => {
            let claims = ScopeClaims {
                exp,
                nbf,
                jti,
                scope: &scope,
                jet_gw_id,
            };
            ("SCOPE", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Bridge {
            target_host,
            jet_aid,
            jet_ap,
            jet_rec,
            jet_ttl,
        } => {
            let claims = BridgeTokenClaims {
                exp,
                nbf,
                jti,
                target_host: &target_host,
                jet_ap: jet_ap.unwrap_or_else(|| {
                    if target_host.starts_with("https") {
                        ApplicationProtocol::Https
                    } else {
                        ApplicationProtocol::Http
                    }
                }),
                jet_rec: if jet_rec {
                    RecordingPolicy::Stream
                } else {
                    RecordingPolicy::None
                },
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_ttl,
                jet_gw_id,
            };
            ("BRIDGE", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Jmux {
            jet_ap,
            dst_hst,
            dst_addl,
            jet_ttl,
            jet_aid,
            jet_rec,
        } => {
            let claims = JmuxClaims {
                dst_hst: &dst_hst,
                dst_addl: dst_addl.iter().map(|o| o.as_str()).collect(),
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_rec: if jet_rec {
                    RecordingPolicy::Stream
                } else {
                    RecordingPolicy::None
                },
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_ttl,
                jet_gw_id,
                exp,
                nbf,
                jti,
            };
            ("JMUX", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Jrec {
            jet_rop,
            jet_aid,
            jet_reuse,
        } => {
            let claims = JrecClaims {
                jet_aid: jet_aid.unwrap_or_else(Uuid::new_v4),
                jet_rop,
                exp,
                nbf,
                jti,
                jet_reuse,
            };
            ("JREC", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Kdc { krb_realm, krb_kdc } => {
            let claims = KdcClaims {
                exp,
                nbf,
                krb_realm: &krb_realm,
                krb_kdc: &krb_kdc,
                jet_gw_id,
                jti,
            };
            ("KDC", serde_json::to_value(claims)?)
        }
        SubCommandArgs::Jrl { revoked_jti_list } => {
            let claims = JrlClaims {
                jti,
                iat: nbf,
                jrl: {
                    let mut jrl = HashMap::new();
                    jrl.insert(
                        "jti",
                        revoked_jti_list
                            .into_iter()
                            .map(|id| serde_json::Value::String(id.to_string()))
                            .collect(),
                    );
                    jrl
                },
                jet_gw_id,
            };
            ("JRL", serde_json::to_value(claims)?)
        }
        SubCommandArgs::NetScan {} => {
            let claims = NetScanClaim {
                jti,
                iat: nbf,
                nbf,
                exp,
                jet_gw_id,
            };
            ("NETSCAN", serde_json::to_value(claims)?)
        }
    };

    let mut jwt_sig = CheckedJwtSig::new_with_cty(JwsAlg::RS256, cty, claims);

    if let Some(kid) = kid {
        jwt_sig.header.kid = Some(kid)
    }

    let signed = jwt_sig.encode(&provisioner_key)?;

    let result = if let Some(delegation_key_path) = delegation_key_path {
        let public_key = std::fs::read_to_string(delegation_key_path)?;
        let public_key = PublicKey::from_pem_str(&public_key)?;
        Jwe::new(JweAlg::RsaOaep256, JweEnc::Aes256Gcm, signed.into_bytes()).encode(&public_key)?
    } else {
        signed
    };

    Ok(result)
}
