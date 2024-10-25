// main.rs

use clap::{Parser, Subcommand};
use std::error::Error;
use std::path::PathBuf;
use uuid::Uuid;

use tokengen::{generate_token, ApplicationProtocol, RecordingOperation, SubCommandArgs};

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::parse();

    let subcommand = match app.subcmd {
        SubCommand::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
            jet_aid,
            jet_rec,
        } => SubCommandArgs::Forward {
            dst_hst,
            jet_ap,
            jet_ttl,
            jet_aid,
            jet_rec,
        },
        SubCommand::Rendezvous {
            jet_ap,
            jet_aid,
            jet_rec,
        } => SubCommandArgs::Rendezvous {
            jet_ap,
            jet_aid,
            jet_rec,
        },
        SubCommand::RdpTls {
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
        SubCommand::Scope { scope } => SubCommandArgs::Scope { scope },
        SubCommand::Jmux {
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
        SubCommand::Jrec { jet_rop, jet_aid } => SubCommandArgs::Jrec { jet_rop, jet_aid },
        SubCommand::Kdc { krb_realm, krb_kdc } => SubCommandArgs::Kdc { krb_realm, krb_kdc },
        SubCommand::Jrl { jti } => SubCommandArgs::Jrl { revoked_jti_list: jti },
        SubCommand::NetScan {} => SubCommandArgs::NetScan {},
    };

    let result = generate_token(
        &app.provisioner_key,
        &app.validity_duration,
        app.kid,
        app.delegation_key.as_deref(),
        app.jet_gw_id,
        subcommand,
    )?;

    println!("{}", result);

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
        #[clap(long)]
        jet_aid: Option<Uuid>,
        #[clap(long)]
        jet_rec: bool,
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
