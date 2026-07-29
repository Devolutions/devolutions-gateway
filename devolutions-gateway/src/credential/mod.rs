mod crypto;

#[rustfmt::skip]
pub use crypto::EncryptedPassword;

use secrecy::ExposeSecret as _;

use self::crypto::MASTER_KEY;

/// Credential at the application protocol level
#[derive(Debug, Clone)]
pub enum AppCredential {
    UsernamePassword {
        username: String,
        password: EncryptedPassword,
    },
}

impl AppCredential {
    /// Decrypt the password using the global master key.
    ///
    /// Returns the username and a short-lived decrypted password that zeroizes on drop.
    pub fn decrypt_password(&self) -> anyhow::Result<(String, secrecy::SecretString)> {
        match self {
            AppCredential::UsernamePassword { username, password } => {
                let decrypted = MASTER_KEY.lock().decrypt(password)?;
                Ok((username.clone(), decrypted))
            }
        }
    }
}

/// Application protocol level credential mapping
#[derive(Debug, Clone)]
pub struct AppCredentialMapping {
    pub proxy: AppCredential,
    pub target: AppCredential,
}

/// Cleartext credential received from the API, used for deserialization only.
///
/// Passwords are encrypted and stored as [`AppCredential`] inside the provisioning store.
/// This type is never stored directly — hand it to [`ProvisioningStore::insert`].
#[derive(Debug, Deserialize)]
#[serde(tag = "kind")]
pub enum CleartextAppCredential {
    #[serde(rename = "username-password")]
    UsernamePassword {
        username: String,
        password: secrecy::SecretString,
    },
}

impl CleartextAppCredential {
    fn encrypt(self) -> anyhow::Result<AppCredential> {
        match self {
            CleartextAppCredential::UsernamePassword { username, password } => {
                let encrypted = MASTER_KEY.lock().encrypt(password.expose_secret())?;
                Ok(AppCredential::UsernamePassword {
                    username,
                    password: encrypted,
                })
            }
        }
    }
}

/// Cleartext credential mapping received from the API, used for deserialization only.
///
/// Passwords are encrypted on write. Hand this directly to [`ProvisioningStore::insert`].
#[derive(Debug, Deserialize)]
pub struct CleartextAppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub proxy: CleartextAppCredential,
    #[serde(rename = "target_credential")]
    pub target: CleartextAppCredential,
}

impl CleartextAppCredentialMapping {
    pub(crate) fn encrypt(self) -> anyhow::Result<AppCredentialMapping> {
        Ok(AppCredentialMapping {
            proxy: self.proxy.encrypt()?,
            target: self.target.encrypt()?,
        })
    }
}
