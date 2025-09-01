use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum StringFilterKind {
    Equals,
    Regex,
    StartsWith,
    EndsWith,
    Contains,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct StringFilter {
    pub kind: StringFilterKind,
    pub data: String,
}

pub trait Filter<Base> {
    fn is_match(&self, base: &Base) -> bool;
}

pub fn is_option_match<T>(filter: Option<&impl Filter<T>>, base: Option<&T>) -> bool {
    match filter {
        Some(f) => match base {
            Some(b) => f.is_match(b),
            None => false,
        },
        None => true,
    }
}

pub fn is_option_match_eq<T: PartialEq>(filter: Option<&T>, base: Option<&T>) -> bool {
    match filter {
        Some(f) => match base {
            Some(b) => f == b,
            None => false,
        },
        None => true,
    }
}

impl<T> Filter<T> for StringFilter
where
    for<'a> String: From<&'a T>,
{
    fn is_match(&self, base: &T) -> bool {
        let base = String::from(base);
        match &self.kind {
            StringFilterKind::Equals => base.eq(&self.data),
            StringFilterKind::Regex => Regex::new(&self.data).is_ok_and(|r| r.is_match(&base)),
            StringFilterKind::StartsWith => base.starts_with(&self.data),
            StringFilterKind::EndsWith => base.ends_with(&self.data),
            StringFilterKind::Contains => base.contains(&self.data),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum ElevationKind {
    AutoApprove,
    Confirm,
    ReasonApproval,
    Deny,
}

pub enum ConsentResult {
    Confirm(bool),
    Reason(String),
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Signer {
    pub issuer: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Certificate {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub thumbprint: Hash,
    pub base64: String,
    pub eku: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Signature {
    pub status: AuthenticodeSignatureStatus,
    pub signer: Option<Signer>,
    pub certificates: Option<Vec<Certificate>>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SignatureFilter {
    pub check_authenticode: bool,
}

impl Filter<Signature> for SignatureFilter {
    fn is_match(&self, base: &Signature) -> bool {
        !self.check_authenticode || base.status == AuthenticodeSignatureStatus::Valid
    }
}

#[derive(Serialize, Deserialize, JsonSchema, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum AuthenticodeSignatureStatus {
    Valid,
    Incompatible,
    NotSigned,
    HashMismatch,
    NotSupportedFileFormat,
    NotTrusted,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum PathFilterKind {
    Equals,
    FileName,
    Wildcard,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PathFilter {
    pub kind: PathFilterKind,
    pub data: PathBuf,
}

impl<T> Filter<T> for PathFilter
where
    for<'a> PathBuf: From<&'a T>,
{
    fn is_match(&self, base: &T) -> bool {
        let base = dunce::canonicalize(PathBuf::from(base));
        let data = dunce::canonicalize(&self.data);

        match (base, data) {
            (Ok(base), Ok(data)) => match &self.kind {
                PathFilterKind::Equals => data == base,
                PathFilterKind::FileName => data.file_name() == base.file_name(),
                PathFilterKind::Wildcard => data
                    .as_os_str()
                    .to_str()
                    .is_some_and(|x| glob::Pattern::new(x).is_ok_and(|p| p.matches_path(&base))),
            },
            (_, _) => false,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Hash {
    pub sha1: String,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct HashFilter {
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

impl Filter<Hash> for HashFilter {
    fn is_match(&self, base: &Hash) -> bool {
        is_option_match_eq(self.sha1.as_ref(), Some(&base.sha1))
            && is_option_match_eq(self.sha256.as_ref(), Some(&base.sha256))
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Hash, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct User {
    pub account_name: String,
    pub domain_name: String,
    pub account_sid: String,
    pub domain_sid: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Application {
    pub path: PathBuf,
    pub command_line: Vec<String>,
    pub working_directory: PathBuf,
    pub signature: Signature,
    pub hash: Hash,
    pub user: User,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ApplicationFilter {
    pub path: PathFilter,
    pub command_line: Option<Vec<StringFilter>>,
    pub working_directory: Option<PathFilter>,
    pub signature: Option<SignatureFilter>,
    pub hashes: Option<Vec<HashFilter>>,
}

impl Filter<Application> for ApplicationFilter {
    fn is_match(&self, base: &Application) -> bool {
        let hashes_match = match &self.hashes {
            Some(hashes) => hashes.iter().any(|hash| hash.is_match(&base.hash)),
            None => true,
        };

        let command_line_match = if let Some(command_line) = &self.command_line {
            command_line.len() == base.command_line.len()
                && command_line
                    .iter()
                    .zip(base.command_line.iter())
                    .all(|(x, y)| x.is_match(y))
        } else {
            true
        };

        self.path.is_match(&base.path)
            && command_line_match
            && is_option_match(self.working_directory.as_ref(), Some(&base.working_directory))
            && is_option_match(self.signature.as_ref(), Some(&base.signature))
            && hashes_match
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ElevationRequest {
    pub asker: Application,
    pub target: Application,
    pub unix_timestamp_seconds: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ElevationResult {
    pub request: ElevationRequest,
    pub successful: bool,
}

impl ElevationRequest {
    pub fn new(asker: Application, target: Application) -> Self {
        let cur = SystemTime::now();

        Self {
            target,
            asker,
            unix_timestamp_seconds: cur.duration_since(UNIX_EPOCH).expect("now after UNIX_EPOCH").as_secs(),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[repr(i32)]
#[serde(rename_all = "PascalCase")]
pub enum Version {
    Version1 = 1,
    Other(i32),
}

#[derive(Serialize, Deserialize, JsonSchema, PartialEq, Eq, Clone, Copy, Debug, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum ElevationMethod {
    LocalAdmin,
    VirtualAccount,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Default, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TemporaryElevationConfiguration {
    pub enabled: bool,
    pub maximum_seconds: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Default, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SessionElevationConfiguration {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Default, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ElevationConfigurations {
    pub temporary: TemporaryElevationConfiguration,
    pub session: SessionElevationConfiguration,
}

pub trait Identifiable {
    fn id(&self) -> &Uuid;
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub elevation_method: ElevationMethod,
    pub default_elevation_kind: ElevationKind,
    pub target_must_be_signed: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Assignment {
    pub profile: Profile,
    pub users: Vec<User>,
}
