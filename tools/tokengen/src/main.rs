use clap::Parser;
use humantime::parse_duration;
use picky::jose::jwe::{Jwe, JweAlg, JweEnc};
use picky::jose::jws::JwsAlg;
use picky::jose::jwt::JwtSig;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::Serialize;
use std::error::Error;
use std::path::PathBuf;
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Parser)]
struct App {
    #[clap(long, default_value = "15m")]
    validity_duration: String,
    #[clap(long)]
    provider_private_key: PathBuf,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

// clippy: All enumeration variants that are prefixed with `Rdp`; this produces the clippy error.
// It will be marked as allowed as we may add new non-RDP related protocols in the future
#[allow(clippy::enum_variant_names)]
#[derive(Parser)]
enum SubCommand {
    RdpTcp(TcpParams),
    RdpTls(TlsParams),
    RdpTcpRendezvous,
    Scope(ScopeParams),
    Jmux,
}

#[derive(Parser)]
struct TcpParams {
    #[clap(long)]
    dst_hst: String,
}

#[derive(Clone, Parser, Serialize)]
struct TlsParams {
    #[serde(skip_serializing)]
    #[clap(long)]
    jet_public_key: PathBuf,
    #[serde(skip_serializing)]
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

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
enum GatewayAccessClaims<'a> {
    Association(AssociationClaims<'a>),
    Scope(ScopeClaims),
    Jmux(JmuxClaims),
}

#[derive(Clone, Serialize)]
struct AssociationClaims<'a> {
    exp: i64,
    nbf: i64,
    jet_cm: &'a str,
    jet_ap: &'a str,
    jet_aid: Uuid,
    dst_hst: Option<&'a str>,
    #[serde(flatten)]
    identity: Option<TlsParams>,
}

#[derive(Clone, Serialize)]
struct ScopeClaims {
    exp: i64,
    nbf: i64,
    scope: String,
}

#[derive(Clone, Serialize)]
pub struct JmuxClaims {
    exp: i64,
    nbf: i64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::parse();

    let private_key_str = std::fs::read_to_string(&app.provider_private_key)?;
    let private_key_pem = private_key_str.parse::<Pem>()?;
    let private_key = PrivateKey::from_pem(&private_key_pem)?;

    let validity_duration = parse_duration(&app.validity_duration)?;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;

    let exp = (now + validity_duration).as_secs();

    let jet_cm = match app.subcmd {
        SubCommand::RdpTcpRendezvous => "rdv",
        _ => "fwd",
    };

    let jet_ap = "rdp";

    let jet_aid = Uuid::new_v4();

    let identity = match &app.subcmd {
        SubCommand::RdpTls(identity) => Some(identity.clone()),
        _ => None,
    };

    let dst_hst = match &app.subcmd {
        SubCommand::RdpTcp(params) => Some(params.dst_hst.as_str()),
        SubCommand::RdpTls(identity) => Some(identity.dst_hst.as_str()),
        _ => None,
    };

    let claims = match &app.subcmd {
        SubCommand::Scope(params) => GatewayAccessClaims::Scope(ScopeClaims {
            exp: exp as i64,
            nbf: now.as_secs() as i64,
            scope: params.scope.clone(),
        }),
        SubCommand::Jmux => GatewayAccessClaims::Jmux(JmuxClaims {
            exp: exp as i64,
            nbf: now.as_secs() as i64,
        }),
        _ => GatewayAccessClaims::Association(AssociationClaims {
            exp: exp as i64,
            nbf: now.as_secs() as i64,
            dst_hst,
            jet_cm,
            jet_ap,
            jet_aid,
            identity,
        }),
    };

    let signed = JwtSig::new(JwsAlg::RS256, claims.clone()).encode(&private_key)?;

    let result = if let GatewayAccessClaims::Association(routing_claims) = claims {
        if let Some(TlsParams { jet_public_key, .. }) = routing_claims.identity {
            let public_key_str = std::fs::read_to_string(&jet_public_key)?;
            let public_key_pem = public_key_str.parse::<Pem>()?;
            let public_key = PublicKey::from_pem(&public_key_pem)?;
            Jwe::new(JweAlg::RsaOaep256, JweEnc::Aes256Gcm, signed.into_bytes()).encode(&public_key)?
        } else {
            signed
        }
    } else {
        signed
    };

    println!("{}", result);

    Ok(())
}
