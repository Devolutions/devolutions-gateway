//! In-memory credential encryption using the active crypto profile's AEAD.
//!
//! This module provides encryption-at-rest for passwords stored in the credential store.
//! A randomly generated 256-bit master key is held in a [`ProtectedBytes<32>`] allocation backed by `secure-memory`, which applies
//! the best available OS hardening (mlock, guard pages, core-dump exclusion) and always zeroizes on drop.
//!
//! ## Security properties
//!
//! - Passwords encrypted at rest in regular heap memory.
//! - Decryption on-demand into short-lived zeroized buffers.
//! - Authenticated encryption uses ChaCha20-Poly1305 in standard mode and AWS-LC AES-256-GCM in FIPS mode.
//! - Random 96-bit nonces make nonce reuse negligibly unlikely for the volumes handled here.
//! - Master key zeroized on drop regardless of platform.
//! - Master key held in mlock'd / guard-paged memory where the OS permits it.

use core::fmt;
use std::sync::LazyLock;

use anyhow::Context as _;
#[cfg(feature = "fips")]
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
#[cfg(feature = "fips")]
use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
#[cfg(feature = "standard")]
use chacha20poly1305::aead::rand_core::RngCore as _;
#[cfg(feature = "standard")]
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
#[cfg(feature = "standard")]
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use parking_lot::Mutex;
use secrecy::SecretString;
use secure_memory::{ProtectedBytes, ProtectionLevel};

/// Global master key for credential encryption.
///
/// Initialized lazily on first access.
/// The key is stored in a [`ProtectedBytes<32>`] allocation.
/// A [`Mutex`] provides thread-safe interior mutability.
///
/// A warning is logged when the master key is first initialized if full memory hardening is unavailable (see [`ProtectionStatus`]).
///
/// [`ProtectionStatus`]: secure_memory::ProtectionStatus
pub(super) static MASTER_KEY: LazyLock<Mutex<MasterKeyManager>> = LazyLock::new(|| Mutex::new(MasterKeyManager::new()));

/// Manages the master encryption key.
///
/// The key is held in a [`ProtectedBytes<32>`] allocation:
/// - Locked in RAM (`mlock` / `VirtualLock`) where available.
/// - Surrounded by guard pages where available.
/// - Excluded from core dumps on Linux (`MADV_DONTDUMP`).
/// - Always zeroized on drop.
pub(super) struct MasterKeyManager {
    key_material: ProtectedBytes<32>,
}

impl MasterKeyManager {
    /// Generate a new random 256-bit master key and place it in protected memory.
    ///
    /// Logs a warning if any hardening step is unavailable.
    fn new() -> Self {
        let mut raw = [0u8; 32];
        fill_random(&mut raw);
        // `ProtectedBytes::new` copies `raw` into secure storage and then zeroizes it,
        // covering the caller-frame residual without requiring a zeroize dep here.
        let key_material = ProtectedBytes::new(&mut raw);

        let st = key_material.protection_status();
        match st.level() {
            ProtectionLevel::Unprotected => {
                tracing::warn!(
                    "master key: advanced memory protection is unavailable on this platform; \
                     the key is protected only by zeroize-on-drop"
                );
            }
            ProtectionLevel::Partial => {
                if !st.locked {
                    tracing::warn!(
                        "master key: mlock/VirtualLock failed; \
                         the key may be paged to disk under memory pressure"
                    );
                }
                if !st.write_protected {
                    tracing::warn!(
                        "master key: data page could not be demoted to read-only; \
                         accidental overwrites are not prevented"
                    );
                }
                if !st.guard_pages {
                    tracing::warn!(
                        "master key: guard pages could not be established; \
                         adjacent out-of-bounds accesses will not fault"
                    );
                }
                if !st.dump_excluded {
                    tracing::warn!(
                        "master key: core-dump exclusion is not active \
                         (unavailable on this platform or kernel)"
                    );
                }
            }
            ProtectionLevel::Full => {}
        }

        Self { key_material }
    }

    /// Encrypt a password using the active profile's AEAD.
    ///
    /// Returns the nonce and ciphertext, including the authentication tag.
    pub(super) fn encrypt(&self, plaintext: &str) -> anyhow::Result<EncryptedPassword> {
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);

        #[cfg(feature = "standard")]
        let ciphertext = {
            let cipher =
                ChaCha20Poly1305::new_from_slice(self.key_material.expose_secret()).expect("key is exactly 32 bytes");
            cipher
                .encrypt(ChaChaNonce::from_slice(&nonce), plaintext.as_bytes())
                .ok()
                .context("AEAD encryption failed")?
        };

        #[cfg(feature = "fips")]
        let ciphertext = {
            let key = fips_key(self.key_material.expose_secret())?;
            let mut ciphertext = plaintext.as_bytes().to_vec();
            key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut ciphertext)
                .map_err(|_| anyhow::anyhow!("AEAD encryption failed"))?;
            ciphertext
        };

        Ok(EncryptedPassword { nonce, ciphertext })
    }

    /// Decrypt a password, returning a [`SecretString`] that zeroizes on drop.
    ///
    /// The returned value should be used immediately and dropped promptly to
    /// minimize the plaintext lifetime in heap memory.
    pub(super) fn decrypt(&self, encrypted: &EncryptedPassword) -> anyhow::Result<SecretString> {
        #[cfg(feature = "standard")]
        let plaintext_bytes = {
            let cipher =
                ChaCha20Poly1305::new_from_slice(self.key_material.expose_secret()).expect("key is exactly 32 bytes");
            cipher
                .decrypt(ChaChaNonce::from_slice(&encrypted.nonce), encrypted.ciphertext.as_ref())
                .ok()
                .context("AEAD decryption failed")?
        };

        #[cfg(feature = "fips")]
        let plaintext_bytes = {
            let key = fips_key(self.key_material.expose_secret())?;
            let mut plaintext = encrypted.ciphertext.clone();
            let plaintext_len = key
                .open_in_place(
                    Nonce::assume_unique_for_key(encrypted.nonce),
                    Aad::empty(),
                    &mut plaintext,
                )
                .map_err(|_| anyhow::anyhow!("AEAD decryption failed"))?
                .len();
            plaintext.truncate(plaintext_len);
            plaintext
        };

        let plaintext = String::from_utf8(plaintext_bytes).context("decrypted password is not valid UTF-8")?;

        Ok(SecretString::from(plaintext))
    }
}

/// Encrypted password stored in heap memory.
///
/// Contains the nonce and ciphertext, including the authentication tag.
/// Safe to store in regular memory because it is encrypted.
#[derive(Clone)]
pub struct EncryptedPassword {
    /// 96-bit nonce.
    nonce: [u8; 12],

    /// Ciphertext + 128-bit authentication tag (plaintext_len + 16 bytes).
    ciphertext: Vec<u8>,
}

#[cfg(feature = "standard")]
fn fill_random(bytes: &mut [u8]) {
    OsRng.fill_bytes(bytes);
}

#[cfg(feature = "fips")]
fn fill_random(bytes: &mut [u8]) {
    SystemRandom::new()
        .fill(bytes)
        .expect("AWS-LC random generation failed");
}

#[cfg(feature = "fips")]
fn fips_key(key_material: &[u8]) -> anyhow::Result<LessSafeKey> {
    let key = UnboundKey::new(&AES_256_GCM, key_material).map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
    Ok(LessSafeKey::new(key))
}

impl fmt::Debug for EncryptedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPassword")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code, panics are expected")]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_manager = MasterKeyManager::new();
        let plaintext = "my-secret-password";

        let encrypted = key_manager.encrypt(plaintext).unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key_manager = MasterKeyManager::new();
        let plaintext = "password";

        let encrypted1 = key_manager.encrypt(plaintext).unwrap();
        let encrypted2 = key_manager.encrypt(plaintext).unwrap();

        // Same plaintext must produce different ciphertexts (different nonces).
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key_manager1 = MasterKeyManager::new();
        let key_manager2 = MasterKeyManager::new();

        let encrypted = key_manager1.encrypt("secret").unwrap();

        // Decryption with a different key must fail.
        assert!(key_manager2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let key_manager = MasterKeyManager::new();
        let mut encrypted = key_manager.encrypt("secret").unwrap();

        // Corrupt the ciphertext.
        encrypted.ciphertext[0] ^= 0xFF;

        // Authentication must fail.
        assert!(key_manager.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_password() {
        let key_manager = MasterKeyManager::new();
        let encrypted = key_manager.encrypt("").unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), "");
    }

    #[test]
    fn test_unicode_password() {
        let key_manager = MasterKeyManager::new();
        let plaintext = "пароль-密码-كلمة السر";
        let encrypted = key_manager.encrypt(plaintext).unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_global_master_key() {
        let plaintext = "test-password";
        let encrypted = MASTER_KEY.lock().encrypt(plaintext).unwrap();
        let decrypted = MASTER_KEY.lock().decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }
}
