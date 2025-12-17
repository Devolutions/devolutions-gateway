//! Module in charge of loading, saving and overall management of the PEDM policy.
//!
//! The policy works in 2 layers:
//! - Profiles: Each profile specifies which type of elevation should be done.
//! - Assignments: A mapping between users on the machine and the profiles available to them.
//!
//! It is possible to edit the policy via the named pipe API.

use core::fmt;
use std::path::{Path, PathBuf};

use anyhow::bail;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use camino::Utf8PathBuf;
use devolutions_pedm_shared::policy::{
    self, Application, AuthenticodeSignatureStatus, Certificate, ElevationRequest, Profile, Signature, Signer, User,
};
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Security::TOKEN_QUERY;
use win_api_wrappers::raw::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use win_api_wrappers::security::crypt::{CryptProviderCertificate, SignerInfo, authenticode_status};
use win_api_wrappers::utils::CommandLine;

use crate::error::Error;
use crate::utils::{AccountExt, MultiHasher, file_hash};

#[derive(Clone)]
pub(crate) struct Policy {
    pub profile: Option<Profile>,
}

impl Policy {
    pub(crate) fn validate(&self, _session_id: u32, request: &ElevationRequest) -> anyhow::Result<()> {
        let profile = match &self.profile {
            Some(val) => val,
            None => bail!(Error::AccessDenied),
        };

        if profile.target_must_be_signed && request.target.signature.status != AuthenticodeSignatureStatus::Valid {
            bail!(Error::AccessDenied)
        }

        let elevation_type = profile.default_elevation_kind;

        match elevation_type {
            policy::ElevationKind::AutoApprove => Ok(()),
            policy::ElevationKind::Confirm => bail!(Error::InvalidParameter),
            policy::ElevationKind::ReasonApproval => bail!(Error::InvalidParameter),
            policy::ElevationKind::Deny => bail!(Error::AccessDenied),
        }
    }
}

#[derive(Debug)]
pub enum LoadPolicyError {
    Io(std::io::Error, Utf8PathBuf),
    Json(serde_json::Error),
    Other(anyhow::Error),
}

impl core::error::Error for LoadPolicyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e, _) => Some(e),
            Self::Json(e) => Some(e),
            Self::Other(e) => Some(e.as_ref()),
        }
    }
}

impl fmt::Display for LoadPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e, path) => write!(f, "IO error while loading policy at {path}: {e}"),
            Self::Json(e) => e.fmt(f),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl From<serde_json::Error> for LoadPolicyError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<anyhow::Error> for LoadPolicyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

pub(crate) fn load_signature(path: &Path) -> anyhow::Result<Signature> {
    let wintrust_result = authenticode_status(path)?;

    // Windows only supports one signer, so getting the first is ok.
    let (signer, cert_chain) = wintrust_result
        .provider
        .and_then(|mut p| (!p.signers.is_empty()).then(|| p.signers.remove(0)))
        .map_or_else(|| (None, None), |x| (Some(x.signer), Some(x.cert_chain)));

    Ok(Signature {
        status: authenticode_win_to_policy(wintrust_result.status),
        signer: signer.map(win_signer_to_policy_signer),
        certificates: cert_chain.map(|x| x.into_iter().map(win_cert_to_policy_cert).collect()),
    })
}

pub(crate) fn application_from_path(
    path: PathBuf,
    command_line: CommandLine,
    working_directory: PathBuf,
    user: User,
) -> anyhow::Result<Application> {
    let signature = load_signature(&path)?;
    let hash = file_hash(&path)?;

    Ok(Application {
        path,
        command_line: command_line.0,
        working_directory,
        signature,
        hash,
        user,
    })
}

pub(crate) fn application_from_process(pid: u32) -> anyhow::Result<Application> {
    let process = Process::get_by_pid(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;

    let path = process.exe_path()?;

    let proc_params = process.peb()?.user_process_parameters()?;

    let user = process
        .token(TOKEN_QUERY)?
        .sid_and_attributes()?
        .sid
        .lookup_account(None)?
        .to_user();

    application_from_path(path, proc_params.command_line, proc_params.working_directory, user)
}

pub(crate) fn authenticode_win_to_policy(
    win_status: win_api_wrappers::security::crypt::AuthenticodeSignatureStatus,
) -> AuthenticodeSignatureStatus {
    match win_status {
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid => AuthenticodeSignatureStatus::Valid,
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Incompatible => {
            AuthenticodeSignatureStatus::Incompatible
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotSigned => {
            AuthenticodeSignatureStatus::NotSigned
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::HashMismatch => {
            AuthenticodeSignatureStatus::HashMismatch
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotSupportedFileFormat => {
            AuthenticodeSignatureStatus::NotSupportedFileFormat
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotTrusted => {
            AuthenticodeSignatureStatus::NotTrusted
        }
    }
}

fn win_signer_to_policy_signer(value: SignerInfo) -> Signer {
    Signer { issuer: value.issuer }
}

fn win_cert_to_policy_cert(value: CryptProviderCertificate) -> Certificate {
    let der = value.cert.encoded.as_slice();

    Certificate {
        issuer: value.cert.info.issuer,
        subject: value.cert.info.subject,
        serial_number: base16ct::upper::encode_string(&value.cert.info.serial_number),
        thumbprint: MultiHasher::default().chain_update(der).finalize(),
        base64: BASE64_STANDARD.encode(der),
        eku: value.cert.eku,
    }
}
