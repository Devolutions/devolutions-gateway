mod file;
#[cfg(windows)]
mod keystore;
#[cfg(target_os = "macos")]
mod macos_acl;
#[cfg(windows)]
mod windows_acl;

use anyhow::ensure;
use camino::Utf8PathBuf;
use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
use signature::{Keypair, Signer};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, ObjectIdentifier};
use uuid::{Uuid, Variant};

pub const DEFAULT_KEY_NAME_PREFIX: &str = "DevolutionsAgent-Identity-";
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Debug, Clone)]
pub enum KeyBackend {
    #[cfg(windows)]
    KeyStore,
    File {
        dir: Utf8PathBuf,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyOptions {
    pub acl_grant_current_user: bool,
}

/// A device key exposes typed signatures, but not its private key or signature encoding.
/// Use `Signer::try_sign` for both signature types; `Signer::sign` panics if the backend fails.
pub trait IdentityKey: Signer<Signature> + Signer<DerSignature> + Send + Sync {
    fn name(&self) -> &str;
    fn public_key(&self) -> VerifyingKey;
}

pub struct CsrSigner<'a>(pub &'a dyn IdentityKey);

impl Keypair for CsrSigner<'_> {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.public_key()
    }
}

impl DynSignatureAlgorithmIdentifier for CsrSigner<'_> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        })
    }
}

impl Signer<DerSignature> for CsrSigner<'_> {
    fn try_sign(&self, message: &[u8]) -> signature::Result<DerSignature> {
        Signer::<DerSignature>::try_sign(self.0, message)
    }
}

pub fn new_key_name(prefix: &str) -> String {
    format!("{prefix}{}", Uuid::new_v4())
}

pub fn generate(backend: &KeyBackend, name: &str, options: &KeyOptions) -> anyhow::Result<Box<dyn IdentityKey>> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::KeyStore => keystore::generate(name, options),
        KeyBackend::File { dir } => file::generate(dir, name, options),
    }
}

pub fn open(backend: &KeyBackend, name: &str) -> anyhow::Result<Option<Box<dyn IdentityKey>>> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::KeyStore => keystore::open(name),
        KeyBackend::File { dir } => file::open(dir, name),
    }
}

pub fn delete(backend: &KeyBackend, name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::KeyStore => keystore::delete(name),
        KeyBackend::File { dir } => file::delete(dir, name),
    }
}

pub fn list(backend: &KeyBackend, prefix: &str) -> anyhow::Result<Vec<String>> {
    validate_prefix(prefix)?;
    match backend {
        #[cfg(windows)]
        KeyBackend::KeyStore => keystore::list(prefix),
        KeyBackend::File { dir } => file::list(dir, prefix),
    }
}

fn validate_prefix(prefix: &str) -> anyhow::Result<()> {
    ensure!(
        (1..=96).contains(&prefix.len()) && prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid key name prefix"
    );
    Ok(())
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    ensure!(name.is_ascii() && name.len() > 36, "invalid key name");
    let (prefix, uuid) = name.split_at(name.len() - 36);
    validate_prefix(prefix)?;
    let uuid = Uuid::parse_str(uuid).map_err(|_| anyhow::anyhow!("invalid key name"))?;
    ensure!(
        uuid.get_version_num() == 4 && uuid.get_variant() == Variant::RFC4122 && name.ends_with(&uuid.to_string()),
        "invalid key name"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_are_canonical_and_scoped() -> anyhow::Result<()> {
        let name = new_key_name(DEFAULT_KEY_NAME_PREFIX);
        validate_name(&name)?;
        for invalid in [
            "",
            "no-key-",
            "other/00000000-0000-4000-8000-000000000000",
            "../00000000-0000-4000-8000-000000000000",
            "prefix-00000000-0000-1000-8000-000000000000",
            "prefix-00000000-0000-4000-0000-000000000000",
            "prefix-00000000-0000-4000-8000-000000000000.p8",
            "prefix-00000000-0000-4000-8000-00000000000A",
            "prefix-00000000000040008000000000000000",
        ] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
        assert!(validate_prefix(&"a".repeat(97)).is_err());
        assert!(validate_prefix("").is_err());
        Ok(())
    }
}
