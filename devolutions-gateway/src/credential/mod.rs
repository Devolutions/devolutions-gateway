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

/// Application protocol level credentials.
#[derive(Debug, Clone)]
pub struct AppCredentials {
    pub proxy: AppCredential,
    pub target: AppCredential,
}

/// Cleartext credential received from the API, used for deserialization only.
///
/// Passwords are encrypted and stored as [`AppCredential`] by the credential service.
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

/// Cleartext credentials received from the API, used for deserialization only.
#[derive(Debug, Deserialize)]
pub struct CleartextAppCredentials {
    #[serde(rename = "proxy_credential")]
    pub proxy: CleartextAppCredential,
    #[serde(rename = "target_credential")]
    pub target: CleartextAppCredential,
}

impl CleartextAppCredentials {
    pub(crate) fn encrypt(self) -> anyhow::Result<AppCredentials> {
        Ok(AppCredentials {
            proxy: self.proxy.encrypt()?,
            target: self.target.encrypt()?,
        })
    }
}
