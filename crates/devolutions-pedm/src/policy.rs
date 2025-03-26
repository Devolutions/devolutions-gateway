//! Module in charge of loading, saving and overall management of the PEDM policy.
//!
//! The policy works in 2 layers:
//! - Profiles: Each profile specifies which type of elevation should be done.
//! - Assignments: A mapping between users on the machine and the profiles available to them.
//!
//! The policy is stored under `%ProgramData%\Devolutions\Agent\pedm\policy\`, and is only accessible by `NT AUTHORITY\SYSTEM`.
//! It is possible to edit the policy via the named pipe API.

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use camino::Utf8PathBuf;
use devolutions_pedm_shared::policy::{
    Application, Certificate, Configuration, ElevationRequest, Identifiable, Profile, Signature, Signer, User,
};
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::error;
use uuid::Uuid;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::process::Process;
use win_api_wrappers::raw::Win32::Security::{WinBuiltinUsersSid, TOKEN_QUERY};
use win_api_wrappers::raw::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use win_api_wrappers::security::crypt::{authenticode_status, CryptProviderCertificate, SignerInfo};
use win_api_wrappers::utils::CommandLine;

use anyhow::{anyhow, bail, Result};

use crate::config;
use crate::error::Error;
use crate::utils::{ensure_protected_directory, file_hash, AccountExt, MultiHasher};
use devolutions_pedm_shared::policy;

pub struct IdList<T: Identifiable> {
    root_path: PathBuf,
    data: HashMap<Uuid, T>,
}

impl<T: Identifiable + DeserializeOwned + Serialize> IdList<T> {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            data: HashMap::new(),
        }
    }

    pub fn load(&mut self) -> Result<()> {
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

    pub fn path(&self) -> &Path {
        &self.root_path
    }

    pub fn get(&self, id: &Uuid) -> Option<&T> {
        self.data.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.data.values()
    }

    pub fn contains(&self, id: &Uuid) -> bool {
        self.data.contains_key(id)
    }

    fn add_internal(&mut self, entry: T, write: bool) -> Result<()> {
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

    pub fn add(&mut self, entry: T) -> Result<()> {
        self.add_internal(entry, true)
    }

    pub fn remove(&mut self, id: &Uuid) -> Result<()> {
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

pub struct Policy {
    config_path: PathBuf,
    config: Configuration,
    profiles: IdList<Profile>,
    current_profiles: HashMap<User, Uuid>,
}

impl Policy {
    pub fn new() -> Result<Self> {
        let mut policy = Self {
            config_path: policy_config_path().into_std_path_buf(),
            config: Configuration::default(),
            profiles: IdList::new(policy_profiles_path().into_std_path_buf()),
            current_profiles: HashMap::new(),
        };

        ensure_protected_directory(
            config::data_dir().as_std_path(),
            vec![Sid::from_well_known(WinBuiltinUsersSid, None)?],
        )?;

        ensure_protected_directory(policy_path().as_std_path(), vec![])?;
        ensure_protected_directory(policy.profiles.path(), vec![])?;

        if !policy.config_path.exists() {
            let config = Configuration::default();
            fs::write(&policy.config_path, serde_json::to_string(&config)?)?;
        }

        policy.load()?;

        Ok(policy)
    }

    fn load_config(&mut self) {
        match deserialize_file(&self.config_path) {
            Ok(conf) => self.config = conf,
            Err(error) => error!(%error, "Failed to load configuration"),
        }
    }

    pub fn load(&mut self) -> Result<()> {
        self.load_config();
        self.profiles.load()?;
        Ok(())
    }

    pub fn profile(&self, id: &Uuid) -> Option<&Profile> {
        self.profiles.get(id)
    }

    pub fn user_profile(&self, user: &User, id: &Uuid) -> Option<&Profile> {
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

    pub fn user_profiles(&self, user: &User) -> Vec<&Profile> {
        self.config
            .assignments
            .keys()
            .filter_map(|id| self.user_profile(user, id))
            .collect()
    }

    pub fn set_user_current_profile(&mut self, user: User, profile_id: Option<Uuid>) -> Result<()> {
        if let Some(profile_id) = profile_id {
            if !self
                .config
                .assignments
                .get(&profile_id)
                .is_some_and(|users| users.contains(&user))
            {
                bail!("Unknown profile Id");
            }

            self.current_profiles.insert(user, profile_id);
        } else {
            self.current_profiles.remove(&user);
        }

        Ok(())
    }

    pub fn user_current_profile(&self, user: &User) -> Option<&Profile> {
        let profile_id = self.current_profiles.get(user)?;

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

    pub fn profiles(&self) -> impl Iterator<Item = &Profile> + '_ {
        self.profiles.iter()
    }

    pub(crate) fn add_profile(&mut self, profile: Profile) -> Result<()> {
        let id = profile.id;
        self.profiles.add(profile)?;

        self.set_assignments(id, vec![])?;

        Ok(())
    }

    pub fn replace_profile(&mut self, old_id: &Uuid, profile: Profile) -> Result<()> {
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

    pub fn remove_profile(&mut self, id: &Uuid) -> Result<()> {
        self.profiles.remove(id)?;

        self.config.assignments.remove(id);

        Ok(())
    }

    pub fn assignments(&self) -> &HashMap<Uuid, Vec<User>> {
        &self.config.assignments
    }

    pub fn set_assignments(&mut self, profile_id: Uuid, users: Vec<User>) -> Result<()> {
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

    pub fn validate(&self, _session_id: u32, request: &ElevationRequest) -> Result<()> {
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

fn policy_path() -> Utf8PathBuf {
    let mut dir = config::data_dir();
    dir.push("policy");
    dir
}

fn policy_config_path() -> Utf8PathBuf {
    let mut dir = policy_path();
    dir.push("config.json");
    dir
}

fn policy_profiles_path() -> Utf8PathBuf {
    let mut dir = policy_path();
    dir.push("profiles");
    dir
}

pub fn policy() -> &'static RwLock<Policy> {
    static POLICY: OnceLock<RwLock<Policy>> = OnceLock::new();

    POLICY.get_or_init(|| {
        RwLock::new(
            Policy::new()
                .map_err(|error| error!(%error, "Failed to load policy"))
                .expect("Failed to load policy"),
        )
    })
}

fn deserialize_file<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    Ok(serde_json::from_reader(reader)?)
}

pub fn load_signature(path: &Path) -> Result<Signature> {
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

pub fn application_from_path(
    path: PathBuf,
    command_line: CommandLine,
    working_directory: PathBuf,
    user: User,
) -> Result<Application> {
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

pub fn application_from_process(pid: u32) -> Result<Application> {
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

pub fn authenticode_win_to_policy(
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
