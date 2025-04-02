//! Module in charge of loading, saving and overall management of the PEDM policy.
//!
//! The policy works in 2 layers:
//! - Profiles: Each profile specifies which type of elevation should be done.
//! - Assignments: A mapping between users on the machine and the profiles available to them.
//!
//! The policy is stored under `%ProgramData%\Devolutions\Agent\pedm\policy\`, and is only accessible by `NT AUTHORITY\SYSTEM`.
//! It is possible to edit the policy via the named pipe API.

use core::fmt;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use camino::Utf8PathBuf;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::info;
use uuid::Uuid;

use devolutions_pedm_shared::policy;
use devolutions_pedm_shared::policy::{
    Application, Certificate, Configuration, ElevationRequest, Identifiable, Profile, Signature, Signer, User,
};
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Security::{WinBuiltinUsersSid, TOKEN_QUERY};
use win_api_wrappers::raw::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use win_api_wrappers::security::crypt::{authenticode_status, CryptProviderCertificate, SignerInfo};
use win_api_wrappers::utils::CommandLine;

use crate::data_dir;
use crate::error::Error;
use crate::utils::{ensure_protected_directory, file_hash, AccountExt, MultiHasher};

pub(crate) struct IdList<T: Identifiable> {
    root_path: PathBuf,
    data: HashMap<Uuid, T>,
}

impl<T: Identifiable + DeserializeOwned + Serialize> IdList<T> {
    pub(crate) fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            data: HashMap::new(),
        }
    }

    pub(crate) fn load(&mut self) -> anyhow::Result<()> {
        self.data.clear();

        for dir_entry in fs::read_dir(self.path())? {
            let dir_entry = dir_entry?;

            if !dir_entry.file_type()?.is_file() {
                continue;
            }

            let entry_path = dir_entry.path();

            if !entry_path.extension().is_some_and(|ext| ext == "json") {
                continue;
            }

            let reader = BufReader::new(File::open(&entry_path)?);

            let entry = serde_json::from_reader::<_, T>(reader)?;

            if !entry_path
                .file_stem()
                .is_some_and(|name| *entry.id().to_string() == *name)
            {
                bail!(Error::InvalidParameter);
            }

            self.add_internal(entry, false)?;
        }

        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.root_path
    }

    pub(crate) fn get(&self, id: &Uuid) -> Option<&T> {
        self.data.get(id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.data.values()
    }

    pub(crate) fn contains(&self, id: &Uuid) -> bool {
        self.data.contains_key(id)
    }

    fn add_internal(&mut self, entry: T, write: bool) -> anyhow::Result<()> {
        if self.contains(entry.id()) {
            bail!(Error::InvalidParameter);
        }

        if write {
            let mut path = self.path().to_owned();
            path.push(entry.id().to_string());
            path.set_extension("json");

            let writer = BufWriter::new(OpenOptions::new().create(true).truncate(false).write(true).open(path)?);
            serde_json::to_writer(writer, &entry)?;
        }

        self.data.insert(*entry.id(), entry);

        Ok(())
    }

    pub(crate) fn add(&mut self, entry: T) -> anyhow::Result<()> {
        self.add_internal(entry, true)
    }

    pub(crate) fn remove(&mut self, id: &Uuid) -> anyhow::Result<()> {
        if !self.contains(id) {
            bail!(Error::NotFound);
        }

        let mut path = self.path().to_owned();
        path.push(id.to_string());
        path.set_extension("json");

        fs::remove_file(path)?;

        self.data.remove(id);

        Ok(())
    }
}

pub(crate) struct Policy {
    /// The path to the policy configuration.
    ///
    /// The default is `C:\ProgramData\Devolutions\Agent\pedm\policy\config.json`.
    /// It is written to when assignments are set.
    config_path: Utf8PathBuf,
    /// A hashmap of assignments.
    ///
    /// The key is the assignment ID. The value is the list of users assigned to the profile.
    config: Configuration,
    profiles: IdList<Profile>,
    current_profiles: HashMap<User, Uuid>,
}

impl Policy {
    /// Loads the policy from disk configuration.
    pub(crate) fn load() -> Result<Self, LoadPolicyError> {
        let data_dir = data_dir();
        let policy_path = data_dir.join("policy");

        // load assignments

        let config_path = policy_path.join("config.json");
        let config = match fs::read_to_string(&config_path) {
            Ok(s) => {
                info!("Loading assignments from {config_path}");
                serde_json::from_str(&s)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("Assignments not found at {config_path}. Initializing default assignments");
                let c = Configuration::default();
                fs::write(&config_path, serde_json::to_string(&c)?)
                    .map_err(|e| LoadPolicyError::Io(e, config_path.clone()))?;
                c
            }
            Err(e) => return Err(LoadPolicyError::Io(e, config_path)),
        };

        let mut policy = Self {
            config_path,
            config,
            profiles: IdList::new(policy_path.join("profiles").into_std_path_buf()),
            current_profiles: HashMap::new(),
        };

        ensure_protected_directory(
            data_dir.as_std_path(),
            vec![Sid::from_well_known(WinBuiltinUsersSid, None)?],
        )?;
        ensure_protected_directory(policy_path.as_std_path(), vec![])?;
        ensure_protected_directory(policy.profiles.path(), vec![])?;

        policy.profiles.load()?;
        Ok(policy)
    }

    pub(crate) fn profile(&self, id: &Uuid) -> Option<&Profile> {
        self.profiles.get(id)
    }

    pub(crate) fn user_profile(&self, user: &User, id: &Uuid) -> Option<&Profile> {
        // Check that the user has access to profile.
        if !self
            .config
            .assignments
            .get(id)
            .is_some_and(|users| users.contains(user))
        {
            return None;
        }

        self.profiles.get(id)
    }

    pub(crate) fn user_profiles(&self, user: &User) -> Vec<&Profile> {
        self.config
            .assignments
            .keys()
            .filter_map(|id| self.user_profile(user, id))
            .collect()
    }

    /// Sets the profile ID.
    pub(crate) fn set_profile_id(&mut self, user: User, profile_id: Option<Uuid>) -> anyhow::Result<()> {
        if let Some(id) = profile_id {
            if !self
                .config
                .assignments
                .get(&id)
                .is_some_and(|users| users.contains(&user))
            {
                info!("Unknown profile Id");
                bail!("Unknown profile Id");
            }
            self.current_profiles.insert(user, id);
        } else {
            self.current_profiles.remove(&user);
        }

        Ok(())
    }

    pub(crate) fn user_current_profile(&self, user: &User) -> Option<&Profile> {
        info!("Getting current profile for user {:?}", user);
        let profile_id = self.current_profiles.get(user)?;
        info!("User {:?} is using profile {}", user, profile_id);

        // Make sure the user's assigned profile is actually allowed.
        if !self
            .config
            .assignments
            .get(profile_id)
            .is_some_and(|users| users.contains(user))
        {
            return None;
        }

        self.profiles.get(profile_id)
    }

    pub(crate) fn profiles(&self) -> impl Iterator<Item = &Profile> + '_ {
        self.profiles.iter()
    }

    pub(crate) fn add_profile(&mut self, profile: Profile) -> anyhow::Result<()> {
        let id = profile.id;
        self.profiles.add(profile)?;

        self.set_assignments(id, vec![])?;

        Ok(())
    }

    pub(crate) fn replace_profile(&mut self, old_id: &Uuid, profile: Profile) -> anyhow::Result<()> {
        if !self.profiles.contains(old_id) {
            bail!(Error::NotFound);
        } else if old_id != &profile.id && self.profiles.contains(&profile.id) {
            bail!(Error::InvalidParameter);
        }

        let old_assignments = self.assignments().get(old_id).cloned().unwrap_or_default();

        self.remove_profile(old_id)?;

        let new_id = profile.id;
        self.add_profile(profile)?;

        self.set_assignments(new_id, old_assignments)?;

        Ok(())
    }

    pub(crate) fn remove_profile(&mut self, id: &Uuid) -> anyhow::Result<()> {
        self.profiles.remove(id)?;

        self.config.assignments.remove(id);

        Ok(())
    }

    pub(crate) fn assignments(&self) -> &HashMap<Uuid, Vec<User>> {
        &self.config.assignments
    }

    pub(crate) fn set_assignments(&mut self, profile_id: Uuid, users: Vec<User>) -> anyhow::Result<()> {
        if !self.profiles.contains(&profile_id) {
            bail!(Error::NotFound);
        }

        if let Some(prof_assignments) = self.config.assignments.get_mut(&profile_id) {
            prof_assignments.clear();
            prof_assignments.extend(users);
        } else {
            self.config.assignments.insert(profile_id, users);
        }

        let writer = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.config_path)?,
        );

        serde_json::to_writer(writer, &self.config)?;

        Ok(())
    }

    pub(crate) fn validate(&self, _session_id: u32, request: &ElevationRequest) -> anyhow::Result<()> {
        let profile = self
            .user_current_profile(&request.asker.user)
            .ok_or_else(|| anyhow!(Error::AccessDenied))?;

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
) -> policy::AuthenticodeSignatureStatus {
    match win_status {
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Valid => {
            policy::AuthenticodeSignatureStatus::Valid
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::Incompatible => {
            policy::AuthenticodeSignatureStatus::Incompatible
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotSigned => {
            policy::AuthenticodeSignatureStatus::NotSigned
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::HashMismatch => {
            policy::AuthenticodeSignatureStatus::HashMismatch
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotSupportedFileFormat => {
            policy::AuthenticodeSignatureStatus::NotSupportedFileFormat
        }
        win_api_wrappers::security::crypt::AuthenticodeSignatureStatus::NotTrusted => {
            policy::AuthenticodeSignatureStatus::NotTrusted
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
