use base64::{prelude::BASE64_STANDARD, Engine};
use camino::Utf8PathBuf;
use devolutions_pedm_shared::policy::{
    Application, Certificate, Configuration, ElevationRequest, Filter, Id, Identifiable, Profile, Rule, Signature,
    Signer, User,
};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tracing::{error, warn};
use win_api_wrappers::{
    raw::Win32::{
        Security::{WinBuiltinUsersSid, TOKEN_QUERY},
        System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
    win::{authenticode_status, CommandLine, CryptProviderCertificate, Process, Sid, SignerInfo},
};

use anyhow::{anyhow, bail, Result};

use crate::{
    config,
    utils::{file_hash, AccountExt, MultiHasher},
};
use crate::{desktop::launch_consent, error::Error};
use crate::{elevations, utils::ensure_protected_directory};
use devolutions_pedm_shared::policy;

pub struct IdList<T: Identifiable> {
    root_path: PathBuf,
    data: HashMap<Id, T>,
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

    pub fn get(&self, id: &Id) -> Option<&T> {
        self.data.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.data.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.data.values_mut()
    }

    pub fn contains(&self, id: &Id) -> bool {
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

            let writer = BufWriter::new(OpenOptions::new().create(true).write(true).open(path)?);
            serde_json::to_writer(writer, &entry)?;
        }

        self.data.insert(entry.id().clone(), entry);

        Ok(())
    }

    pub fn add(&mut self, entry: T) -> Result<()> {
        self.add_internal(entry, true)
    }

    pub fn remove(&mut self, id: &Id) -> Result<()> {
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
    rules: IdList<Rule>,
    current_profiles: HashMap<User, Id>,
}

impl Policy {
    pub fn new() -> Result<Self> {
        let mut policy = Self {
            config_path: policy_config_path().into_std_path_buf(),
            config: Configuration::default(),
            profiles: IdList::new(policy_profiles_path().into_std_path_buf()),
            rules: IdList::new(policy_rules_path().into_std_path_buf()),
            current_profiles: HashMap::new(),
        };

        ensure_protected_directory(
            config::data_dir().as_std_path(),
            vec![Sid::from_well_known(WinBuiltinUsersSid, None)?],
        )?;

        ensure_protected_directory(policy_path().as_std_path(), vec![])?;
        ensure_protected_directory(policy.profiles.path(), vec![])?;
        ensure_protected_directory(policy.rules.path(), vec![])?;

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
        self.rules.load()?;
        Ok(())
    }

    pub fn profile(&self, id: &Id) -> Option<&Profile> {
        self.profiles.get(id)
    }

    pub fn user_profile(&self, user: &User, id: &Id) -> Option<&Profile> {
        // Check that the user has access to profile.
        if !self
            .config
            .assignments
            .get(id)
            .is_some_and(|users| users.contains(&user))
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

    pub fn set_user_current_profile(&mut self, user: User, profile_id: Option<Id>) -> Result<()> {
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
        let profile_id = self.current_profiles.get(&user)?;

        // Make sure the user's assigned profile is actually allowed.
        if !self
            .config
            .assignments
            .get(profile_id)
            .is_some_and(|users| users.contains(&user))
        {
            return None;
        }

        self.profiles.get(profile_id)
    }

    pub fn profiles(&self) -> impl Iterator<Item = &Profile> + '_ {
        self.profiles.iter()
    }

    pub fn add_profile(&mut self, profile: Profile) -> Result<()> {
        let id = profile.id.clone();
        self.profiles.add(profile)?;

        self.set_assignments(id, vec![])?;

        Ok(())
    }

    pub fn replace_profile(&mut self, old_id: &Id, profile: Profile) -> Result<()> {
        if !self.profiles.contains(old_id) {
            bail!(Error::NotFound);
        } else if old_id != &profile.id && self.profiles.contains(&profile.id) {
            bail!(Error::InvalidParameter);
        }

        let old_assignments = self.assignments().get(old_id).cloned().unwrap_or_default();

        self.remove_profile(old_id)?;

        let new_id = profile.id.clone();
        self.add_profile(profile)?;

        self.set_assignments(new_id, old_assignments)?;

        Ok(())
    }

    pub fn replace_rule(&mut self, old_id: &Id, rule: Rule) -> Result<()> {
        if !self.rules.contains(old_id) {
            bail!(Error::NotFound);
        } else if old_id != &rule.id && self.rules.contains(&rule.id) {
            bail!(Error::InvalidParameter);
        }

        let profile_ids = self
            .profiles
            .iter()
            .filter(|p| p.rules.contains(old_id))
            .map(|p| p.id().clone())
            .collect::<Vec<_>>();

        self.remove_rule(old_id)?;

        let new_id = rule.id.clone();
        self.add_rule(rule)?;

        for profile_id in profile_ids {
            let mut profile = self
                .profile(&profile_id)
                .cloned()
                .ok_or_else(|| anyhow!(Error::NotFound))?;

            profile.rules.push(new_id.clone());

            self.replace_profile(&profile_id, profile)?;
        }

        Ok(())
    }

    pub fn remove_profile(&mut self, id: &Id) -> Result<()> {
        self.profiles.remove(id)?;

        self.config.assignments.remove(id);

        Ok(())
    }

    pub fn rule(&self, id: &Id) -> Option<&Rule> {
        self.rules.get(id)
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> + '_ {
        self.rules.iter()
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        self.rules.add(rule)
    }

    pub fn remove_rule(&mut self, id: &Id) -> Result<()> {
        self.rules.remove(id)?;

        for prof in self.profiles.iter_mut() {
            if let Some(index) = prof.rules.iter().position(|x| x == id) {
                prof.rules.remove(index);
            }
        }

        Ok(())
    }

    pub fn assignments(&self) -> &HashMap<Id, Vec<User>> {
        &self.config.assignments
    }

    pub fn set_assignments(&mut self, profile_id: Id, users: Vec<User>) -> Result<()> {
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

    pub fn validate(&self, session_id: u32, request: &ElevationRequest) -> Result<()> {
        let profile = self
            .user_current_profile(&request.asker.user)
            .ok_or_else(|| anyhow!(Error::AccessDenied))?;

        let rule = 'r: loop {
            for rule_id in &profile.rules {
                let rule = self.rules.get(&rule_id);
                if rule.is_none() {
                    warn!(%profile.id, %rule_id, "Profile assigned to non existent rule");
                    continue;
                }

                let rule = rule.unwrap();

                if !rule.target.is_match(&request.target)
                    || rule.asker.as_ref().is_some_and(|x| !x.is_match(&request.asker))
                {
                    continue;
                }

                break 'r rule;
            }

            bail!(Error::AccessDenied);
        };

        let mut elevation_type = rule.elevation_kind;
        if elevations::is_elevated(&request.asker.user) {
            elevation_type = policy::ElevationKind::Confirm
        }

        match elevation_type {
            policy::ElevationKind::AutoApprove => Ok(()),
            policy::ElevationKind::Confirm => {
                if !launch_consent(
                    session_id,
                    &Sid::try_from(request.asker.user.account_sid.as_str())?,
                    &request.target.path,
                )? {
                    bail!(Error::Cancelled);
                }

                return Ok(());
            }
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

fn policy_rules_path() -> Utf8PathBuf {
    let mut dir = policy_path();
    dir.push("rules");
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
    let wintrust_result = authenticode_status(&path)?;

    // Windows only supports one signer, so getting the first is ok.
    let (signer, cert_chain) = wintrust_result
        .provider
        .and_then(|mut p| (0 < p.signers.len()).then(|| p.signers.remove(0)))
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
    let process = Process::try_get_by_pid(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;

    let path = process.exe_path()?;

    let proc_params = process.peb()?.user_process_parameters()?;

    let user = process
        .token(TOKEN_QUERY)?
        .sid_and_attributes()?
        .sid
        .account(None)?
        .to_user();

    application_from_path(path, proc_params.command_line, proc_params.working_directory, user)
}

pub fn authenticode_win_to_policy(
    win_status: win_api_wrappers::win::AuthenticodeSignatureStatus,
) -> policy::AuthenticodeSignatureStatus {
    match win_status {
        win_api_wrappers::win::AuthenticodeSignatureStatus::Valid => policy::AuthenticodeSignatureStatus::Valid,
        win_api_wrappers::win::AuthenticodeSignatureStatus::Incompatible => {
            policy::AuthenticodeSignatureStatus::Incompatible
        }
        win_api_wrappers::win::AuthenticodeSignatureStatus::NotSigned => policy::AuthenticodeSignatureStatus::NotSigned,
        win_api_wrappers::win::AuthenticodeSignatureStatus::HashMismatch => {
            policy::AuthenticodeSignatureStatus::HashMismatch
        }
        win_api_wrappers::win::AuthenticodeSignatureStatus::NotSupportedFileFormat => {
            policy::AuthenticodeSignatureStatus::NotSupportedFileFormat
        }
        win_api_wrappers::win::AuthenticodeSignatureStatus::NotTrusted => {
            policy::AuthenticodeSignatureStatus::NotTrusted
        }
    }
}

/*
pub const ID_AZURE_EXT_KEY_USAGE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.97");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureExtendedKeyUsage(pub Vec<ObjectIdentifier>);

impl AssociatedOid for AzureExtendedKeyUsage {
    const OID: ObjectIdentifier = ID_AZURE_EXT_KEY_USAGE;
}

impl_newtype!(AzureExtendedKeyUsage, Vec<ObjectIdentifier>);
*/
fn win_signer_to_policy_signer(value: SignerInfo) -> Signer {
    Signer { issuer: value.issuer }
}

fn win_cert_to_policy_cert(value: CryptProviderCertificate) -> Certificate {
    let der = value.cert.encoded.as_slice();

    Certificate {
        issuer: value.cert.info.issuer,
        subject: value.cert.info.subject,
        serial_number: base16ct::upper::encode_string(&value.cert.info.serial_number),
        thumbprint: MultiHasher::default().chain_update(&der).finalize(),
        base64: BASE64_STANDARD.encode(&der),
        eku: value.cert.eku,
    }
}
