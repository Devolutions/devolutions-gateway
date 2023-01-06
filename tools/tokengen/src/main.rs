use clap::{Parser, Subcommand};
use picky::jose::jwe::{Jwe, JweAlg, JweEnc};
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::time::SystemTime;
use tap::prelude::*;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::parse();

    let provisioner_key = std::fs::read_to_string(&app.provisioner_key)?
        .pipe_deref(str::parse::<Pem>)?
        .pipe_ref(PrivateKey::from_pem)?;

    let validity_duration = humantime::parse_duration(&app.validity_duration)?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let nbf = i64::try_from(now.as_secs()).unwrap();
    let exp = i64::try_from((now + validity_duration).as_secs()).unwrap();

    let jti = Uuid::new_v4();

    let (cty, claims) = match app.subcmd {
        SubCommand::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
        } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&dst_hst),
                jet_cm: "fwd",
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_aid: Uuid::new_v4(),
                jet_ttl,
                jet_gw_id: app.jet_gw_id,
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(&claims)?)
        }
        SubCommand::RdpTls {
            dst_hst,
            prx_usr,
            prx_pwd,
            dst_usr,
            dst_pwd,
        } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&dst_hst),
                jet_cm: "fwd",
                jet_ap: ApplicationProtocol::Rdp,
                jet_aid: Uuid::new_v4(),
                jet_ttl: None,
                jet_gw_id: app.jet_gw_id,
                creds: Some(CredsClaims {
                    prx_usr: &prx_usr,
                    prx_pwd: &prx_pwd,
                    dst_usr: &dst_usr,
                    dst_pwd: &dst_pwd,
                }),
            };
            ("ASSOCIATION", serde_json::to_value(&claims)?)
        }
        SubCommand::Rendezvous { jet_ap } => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: None,
                jet_cm: "rdv",
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_aid: Uuid::new_v4(),
                jet_ttl: None,
                jet_gw_id: app.jet_gw_id,
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(&claims)?)
        }
        SubCommand::Scope { scope } => {
            let claims = ScopeClaims {
                exp,
                nbf,
                jti,
                scope: &scope,
                jet_gw_id: app.jet_gw_id,
            };
            ("SCOPE", serde_json::to_value(&claims)?)
        }
        SubCommand::Jmux {
            jet_ap,
            dst_hst,
            dst_addl,
            jet_ttl,
        } => {
            let claims = JmuxClaims {
                dst_hst: &dst_hst,
                dst_addl: dst_addl.iter().map(|o| o.as_str()).collect(),
                jet_ap: jet_ap.unwrap_or(ApplicationProtocol::Unknown),
                jet_aid: Uuid::new_v4(),
                jet_ttl,
                jet_gw_id: app.jet_gw_id,
                exp,
                nbf,
                jti,
            };
            ("JMUX", serde_json::to_value(&claims)?)
        }
        SubCommand::Kdc { krb_realm, krb_kdc } => {
            let claims = KdcClaims {
                exp,
                nbf,
                krb_realm: &krb_realm,
                krb_kdc: &krb_kdc,
                jet_gw_id: app.jet_gw_id,
                jti,
            };
            ("KDC", serde_json::to_value(&claims)?)
        }
        SubCommand::Jrl { jti: revoked_jti_list } => {
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
                jet_gw_id: app.jet_gw_id,
            };
            ("JRL", serde_json::to_value(&claims)?)
        }
    };

    let mut jwt_sig = CheckedJwtSig::new_with_cty(JwsAlg::RS256, cty, claims);

    if let Some(kid) = app.kid {
        jwt_sig.header.kid = Some(kid)
    }

    let signed = jwt_sig.encode(&provisioner_key)?;

    let result = if let Some(delegation_key) = app.delegation_key {
        let public_key = std::fs::read_to_string(&delegation_key)?;
        let public_key = PublicKey::from_pem_str(&public_key)?;
        Jwe::new(JweAlg::RsaOaep256, JweEnc::Aes256Gcm, signed.into_bytes()).encode(&public_key)?
    } else {
        signed
    };

    println!("{result}");

    Ok(())
}

// --- CLI App --- //

#[derive(Parser)]
struct App {
    #[clap(long, default_value = "15m")]
    validity_duration: String,
    /// Path to provisioner private key
    #[clap(long)]
    provisioner_key: PathBuf,
    /// Path to delegation public key
    #[clap(long)]
    delegation_key: Option<PathBuf>,
    #[clap(long)]
    kid: Option<String>,
    #[clap(long)]
    jet_gw_id: Option<Uuid>,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand)]
enum SubCommand {
    Forward {
        #[clap(long)]
        dst_hst: String,
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
        #[clap(long)]
        jet_ttl: Option<u64>,
    },
    Rendezvous {
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
    },
    RdpTls {
        #[clap(long)]
        dst_hst: String,
        #[clap(long)]
        prx_usr: String,
        #[clap(long)]
        prx_pwd: String,
        #[clap(long)]
        dst_usr: String,
        #[clap(long)]
        dst_pwd: String,
    },
    Scope {
        scope: String,
    },
    Jmux {
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
        #[clap(long)]
        dst_hst: String,
        #[clap(long)]
        dst_addl: Vec<String>,
        #[clap(long)]
        jet_ttl: Option<u64>,
    },
    Kdc {
        #[clap(long)]
        krb_realm: String,
        #[clap(long)]
        krb_kdc: String,
    },
    Jrl {
        #[clap(long)]
        jti: Vec<Uuid>,
    },
}

// --- claims --- //

#[derive(Clone, Serialize)]
struct AssociationClaims<'a> {
    exp: i64,
    nbf: i64,
    jti: Uuid,
    jet_cm: &'a str,
    jet_ap: ApplicationProtocol,
    jet_aid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_gw_id: Option<Uuid>,
    dst_hst: Option<&'a str>,
    #[serde(flatten)]
    creds: Option<CredsClaims<'a>>,
}

#[derive(Clone, Serialize)]
pub struct CredsClaims<'a> {
    prx_usr: &'a str,
    prx_pwd: &'a str,
    dst_usr: &'a str,
    dst_pwd: &'a str,
}

#[derive(Clone, Serialize)]
struct ScopeClaims<'a> {
    exp: i64,
    nbf: i64,
    jti: Uuid,
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_gw_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
struct JmuxClaims<'a> {
    dst_hst: &'a str,
    dst_addl: Vec<&'a str>,
    jet_ap: ApplicationProtocol,
    jet_aid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_gw_id: Option<Uuid>,
    exp: i64,
    nbf: i64,
    jti: Uuid,
}

#[derive(Clone, Serialize)]
struct KdcClaims<'a> {
    krb_realm: &'a str,
    krb_kdc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_gw_id: Option<Uuid>,
    exp: i64,
    nbf: i64,
    jti: Uuid,
}

#[derive(Clone, Serialize)]
struct JrlClaims<'a> {
    jti: Uuid,
    iat: i64,
    jrl: HashMap<&'a str, Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jet_gw_id: Option<Uuid>,
}

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
    /// Unknown Protocol
    Unknown,
}

impl std::str::FromStr for ApplicationProtocol {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Not the most elegant / performant solution, but it's DRY and good enough for a small tool like this one
        let json_s = format!("\"{s}\"");
        serde_json::from_str(&json_s)
    }
}
