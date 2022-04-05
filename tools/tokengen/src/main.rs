use clap::Parser;
use picky::jose::jwe::{Jwe, JweAlg, JweEnc};
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::CheckedJwtSig;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::parse();

    let private_key_str = std::fs::read_to_string(&app.provider_private_key)?;
    let private_key_pem = private_key_str.parse::<Pem>()?;
    let private_key = PrivateKey::from_pem(&private_key_pem)?;

    let validity_duration = humantime::parse_duration(&app.validity_duration)?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
    let nbf = i64::try_from(now.as_secs()).unwrap();
    let exp = i64::try_from((now + validity_duration).as_secs()).unwrap();

    let jti = Uuid::new_v4();

    let (cty, claims) = match app.subcmd {
        SubCommand::RdpTcp(params) => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&params.dst_hst),
                jet_cm: "fwd",
                jet_ap: "rdp",
                jet_aid: Uuid::new_v4(),
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::RdpTls(params) => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: Some(&params.dst_hst),
                jet_cm: "fwd",
                jet_ap: "rdp",
                jet_aid: Uuid::new_v4(),
                creds: Some(CredsClaims {
                    prx_usr: &params.prx_usr,
                    prx_pwd: &params.prx_pwd,
                    dst_usr: &params.dst_usr,
                    dst_pwd: &params.dst_pwd,
                }),
            };
            ("ASSOCIATION", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::RdpTcpRendezvous => {
            let claims = AssociationClaims {
                exp,
                nbf,
                jti,
                dst_hst: None,
                jet_cm: "rdv",
                jet_ap: "rdp",
                jet_aid: Uuid::new_v4(),
                creds: None,
            };
            ("ASSOCIATION", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::Scope(params) => {
            let claims = ScopeClaims {
                exp,
                nbf,
                jti,
                scope: &params.scope,
            };
            ("SCOPE", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::Jmux(params) => {
            let claims = JmuxClaims {
                dst_hst: &params.dst_hst,
                dst_addl: params.dst_addl.iter().map(|o| o.as_str()).collect(),
                exp,
                nbf,
                jti,
            };
            ("JMUX", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::Kdc(params) => {
            let claims = KdcClaims {
                exp,
                nbf,
                krb_realm: &params.krb_realm,
                krb_kdc: &params.krb_kdc,
                jti,
            };
            ("KDC", serde_json::to_value(&claims).unwrap())
        }
        SubCommand::Jrl(params) => {
            let claims = JrlClaims {
                jti,
                iat: nbf,
                jrl: {
                    let mut jrl = HashMap::new();
                    jrl.insert(
                        "jti",
                        params
                            .jti
                            .into_iter()
                            .map(|id| serde_json::Value::String(id.to_string()))
                            .collect(),
                    );
                    jrl
                },
            };
            ("JRL", serde_json::to_value(&claims).unwrap())
        }
    };

    let jwt_sig = CheckedJwtSig::new_with_cty(JwsAlg::RS256, cty, claims);
    let signed = jwt_sig.encode(&private_key)?;

    let result = if let Some(delegation_public_key) = app.delegation_public_key {
        let public_key = std::fs::read_to_string(&delegation_public_key)?;
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
    #[clap(long)]
    provider_private_key: PathBuf,
    #[clap(long)]
    delegation_public_key: Option<PathBuf>,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    RdpTcp(TcpParams),
    RdpTls(TlsParams),
    RdpTcpRendezvous,
    Scope(ScopeParams),
    Jmux(JmuxParams),
    Kdc(KdcParams),
    Jrl(JrlParams),
}

#[derive(Parser)]
struct TcpParams {
    #[clap(long)]
    dst_hst: String,
}

#[derive(Parser)]
struct TlsParams {
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
}

#[derive(Parser)]
struct ScopeParams {
    #[clap(long)]
    scope: String,
}

#[derive(Parser)]
struct JmuxParams {
    dst_hst: String,
    dst_addl: Vec<String>,
}

#[derive(Parser)]
struct KdcParams {
    #[clap(long)]
    krb_realm: String,
    #[clap(long)]
    krb_kdc: String,
}

#[derive(Parser)]
struct JrlParams {
    #[clap(long)]
    jti: Vec<Uuid>,
}

// --- claims --- //

#[derive(Clone, Serialize)]
struct AssociationClaims<'a> {
    exp: i64,
    nbf: i64,
    jti: Uuid,
    jet_cm: &'a str,
    jet_ap: &'a str,
    jet_aid: Uuid,
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
}

#[derive(Clone, Serialize)]
struct JmuxClaims<'a> {
    dst_hst: &'a str,
    dst_addl: Vec<&'a str>,
    exp: i64,
    nbf: i64,
    jti: Uuid,
}

#[derive(Clone, Serialize)]
struct KdcClaims<'a> {
    krb_realm: &'a str,
    krb_kdc: &'a str,
    exp: i64,
    nbf: i64,
    jti: Uuid,
}

#[derive(Clone, Serialize)]
struct JrlClaims<'a> {
    jti: Uuid,
    iat: i64,
    jrl: HashMap<&'a str, Vec<serde_json::Value>>,
}
