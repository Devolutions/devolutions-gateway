use clap::Clap;
use humantime::parse_duration;
use picky::{
    jose::{
        jwe::{Jwe, JweAlg, JweEnc},
        jws::JwsAlg,
        jwt::JwtSig,
    },
    key::{PrivateKey, PublicKey},
    pem::Pem,
};
use serde::Serialize;
use std::{error::Error, path::PathBuf, time::SystemTime};
use uuid::Uuid;

#[derive(Clap)]
struct App {
    #[clap(long)]
    dst_hst: String,
    #[clap(long, default_value = "15m")]
    validity_duration: String,
    #[clap(long)]
    provider_private_key: PathBuf,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[allow(clippy::enum_variant_names)] // Enumeration variants that are prefixed with `Rdp`, but we are going to add new protocols
#[derive(Clap)]
enum SubCommand {
    RdpTcp,
    RdpTls(RdpTlsIdentity),
    RdpTcpRendezvous(RdpTcpRendezvousJetAID),
}

#[derive(Clone, Clap, Serialize)]
struct RdpTlsIdentity {
    #[serde(skip_serializing)]
    #[clap(long)]
    jet_public_key: PathBuf,

    #[clap(long)]
    prx_usr: String,
    #[clap(long)]
    prx_pwd: String,
    #[clap(long)]
    dst_usr: String,
    #[clap(long)]
    dst_pwd: String,
}

#[derive(Clone, Clap, Serialize)]
struct RdpTcpRendezvousJetAID {
    jet_aid: Uuid,
}

#[derive(Clone, Serialize)]
struct RoutingClaims {
    exp: i64,
    nbf: i64,
    jet_cm: String,
    jet_ap: String,
    jet_aid: Option<Uuid>,
    dst_hst: String,
    #[serde(flatten)]
    identity: Option<RdpTlsIdentity>,
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
        SubCommand::RdpTcpRendezvous(_) => "rdv".to_owned(),
        _ => "fwd".to_owned(),
    };

    let jet_ap = match app.subcmd {
        SubCommand::RdpTcpRendezvous(_) => "rdp-tcp".to_owned(),
        _ => "rdp".to_owned(),
    };

    let jet_aid = match &app.subcmd {
        SubCommand::RdpTcpRendezvous(rdv) => Some(rdv.jet_aid),
        _ => None,
    };

    let identity = match &app.subcmd {
        SubCommand::RdpTls(identity) => Some(identity.clone()),
        _ => None,
    };

    let claims = RoutingClaims {
        exp: exp as i64,
        nbf: now.as_secs() as i64,
        dst_hst: app.dst_hst,
        jet_cm,
        jet_ap,
        jet_aid,
        identity,
    };

    let signed = JwtSig::new(JwsAlg::RS256, claims.clone()).encode(&private_key)?;

    let result = if let Some(RdpTlsIdentity { jet_public_key, .. }) = claims.identity {
        let public_key_str = std::fs::read_to_string(&jet_public_key)?;
        let public_key_pem = public_key_str.parse::<Pem>()?;
        let public_key = PublicKey::from_pem(&public_key_pem)?;
        Jwe::new(JweAlg::RsaOaep256, JweEnc::Aes256Gcm, signed.into_bytes()).encode(&public_key)?
    } else {
        signed
    };

    println!("{}", result);

    Ok(())
}
