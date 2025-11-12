use clap::{Parser, Subcommand};
use std::error::Error;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use tokengen::{generate_token, ApplicationProtocol, RecordingOperation, SubCommandArgs};

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::parse();

    match app.subcmd {
        SubCommand::Sign {
            validity_duration,
            provisioner_key,
            delegation_key,
            kid,
            jet_gw_id,
            subcmd,
        } => {
            sign(
                &validity_duration,
                &provisioner_key,
                delegation_key,
                kid,
                jet_gw_id,
                subcmd,
            )?;
        }
        SubCommand::Server { port } => {
            tokio::runtime::Runtime::new()?.block_on(tokengen::server::start_server(port))?
        }
    }

    Ok(())
}

fn sign(
    validity_duration: &str,
    provisioner_key: &Path,
    delegation_key: Option<PathBuf>,
    kid: Option<String>,
    jet_gw_id: Option<Uuid>,
    subcmd: SignSubCommand,
) -> Result<(), Box<dyn Error>> {
    let subcommand = match subcmd {
        SignSubCommand::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
            jet_aid,
            jet_rec,
            jet_reuse,
            cert_thumb256,
        } => SubCommandArgs::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
            jet_aid,
            jet_rec,
            jet_reuse,
            cert_thumb256,
        },
        SignSubCommand::Rendezvous {
            jet_ap,
            jet_aid,
            jet_rec,
        } => SubCommandArgs::Rendezvous {
            jet_ap,
            jet_aid,
            jet_rec,
        },
        SignSubCommand::RdpTls {
            dst_hst,
            prx_usr,
            prx_pwd,
            dst_usr,
            dst_pwd,
            jet_aid,
        } => SubCommandArgs::RdpTls {
            dst_hst,
            prx_usr,
            prx_pwd,
            dst_usr,
            dst_pwd,
            jet_aid,
        },
        SignSubCommand::Scope { scope } => SubCommandArgs::Scope { scope },
        SignSubCommand::Bridge {
            target_host,
            jet_aid,
            jet_ap,
            jet_rec,
            jet_ttl,
        } => SubCommandArgs::Bridge {
            target_host,
            jet_aid,
            jet_ap,
            jet_rec,
            jet_ttl,
        },
        SignSubCommand::Jmux {
            jet_ap,
            dst_hst,
            dst_addl,
            jet_ttl,
            jet_aid,
            jet_rec,
        } => SubCommandArgs::Jmux {
            jet_ap,
            dst_hst,
            dst_addl,
            jet_ttl,
            jet_aid,
            jet_rec,
        },
        SignSubCommand::Jrec {
            jet_rop,
            jet_aid,
            jet_reuse,
        } => SubCommandArgs::Jrec {
            jet_rop,
            jet_aid,
            jet_reuse,
        },
        SignSubCommand::Kdc { krb_realm, krb_kdc } => SubCommandArgs::Kdc { krb_realm, krb_kdc },
        SignSubCommand::Jrl { jti } => SubCommandArgs::Jrl { revoked_jti_list: jti },
        SignSubCommand::NetScan {} => SubCommandArgs::NetScan {},
    };

    let validity_duration = humantime::parse_duration(validity_duration)?;

    let result = generate_token(
        provisioner_key,
        validity_duration,
        kid.to_owned(),
        delegation_key.as_deref(),
        jet_gw_id,
        subcommand,
    )?;

    println!("{result}");

    Ok(())
}

// --- CLI App --- //

#[derive(Parser)]
struct App {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum SubCommand {
    Sign {
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
        subcmd: SignSubCommand,
    },
    Server {
        #[clap(short, default_value = "8080")]
        port: u16,
    },
}

#[derive(Subcommand)]
enum SignSubCommand {
    Forward {
        #[clap(long)]
        dst_hst: String,
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
        #[clap(long)]
        jet_ttl: Option<u64>,
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_rec: bool,
        #[clap(long)]
        jet_reuse: Option<u32>,
        #[clap(long)]
        cert_thumb256: Option<String>,
    },
    Rendezvous {
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_rec: bool,
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
        #[clap(long)]
        jet_aid: Option<Uuid>,
    },
    Scope {
        scope: String,
    },
    Bridge {
        #[clap(long)]
        target_host: String,
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_ap: Option<ApplicationProtocol>,
        #[clap(long)]
        jet_rec: bool,
        #[clap(long)]
        jet_ttl: Option<u64>,
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
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_rec: bool,
    },
    Jrec {
        #[clap(long)]
        jet_rop: RecordingOperation,
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_reuse: Option<u32>,
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
    NetScan {},
}
