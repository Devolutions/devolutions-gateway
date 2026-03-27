//! In-memory credential encryption using ChaCha20-Poly1305.
//!
//! This module provides encryption-at-rest for passwords stored in the credential store.
//! A randomly generated 256-bit master key is held in a [`ProtectedBytes<32>`] allocation backed by `secure-memory`, which applies
//! the best available OS hardening (mlock, guard pages, core-dump exclusion) and always zeroizes on drop.
//!
//! ## Security properties
//!
//! - Passwords encrypted at rest in regular heap memory.
//! - Decryption on-demand into short-lived zeroized buffers.
//! - ChaCha20-Poly1305 provides authenticated encryption.
//! - Random 96-bit nonces prevent nonce reuse.
//! - Master key zeroized on drop regardless of platform.
//! - Master key held in mlock'd / guard-paged memory where the OS permits it.

use core::fmt;
use std::sync::LazyLock;

use anyhow::Context as _;
use chacha20poly1305::aead::rand_core::RngCore as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use parking_lot::Mutex;
use secrecy::SecretString;
use secure_memory::ProtectedBytes;

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
        OsRng.fill_bytes(&mut raw);
        let key_material = ProtectedBytes::new(raw);

        let st = key_material.protection_status();
        if st.fallback_backend {
            tracing::warn!(
                "master key: advanced memory protection is unavailable on this platform; \
                 the key is protected only by zeroize-on-drop"
            );
        } else {
            if !st.locked {
                tracing::warn!(
                    "master key: mlock/VirtualLock failed; \
                     the key may be paged to disk under memory pressure"
                );
            }
            if !st.dump_excluded {
                tracing::warn!(
                    "master key: core-dump exclusion is not active \
                     (unavailable on this platform or kernel)"
                );
            }
        }

        Self { key_material }
    }

    /// Encrypt a password using ChaCha20-Poly1305.
    ///
    /// Returns the nonce and ciphertext (which includes the Poly1305 auth tag).
    pub(super) fn encrypt(&self, plaintext: &str) -> anyhow::Result<EncryptedPassword> {
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.key_material.expose_secret()).expect("key is exactly 32 bytes");

        // Generate a random 96-bit nonce (12 bytes for ChaCha20-Poly1305).
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

        // Encrypt; ciphertext includes 16-byte Poly1305 authentication tag.
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .ok()
            .context("AEAD encryption failed")?;

        Ok(EncryptedPassword { nonce, ciphertext })
    }

    /// Decrypt a password, returning a [`SecretString`] that zeroizes on drop.
    ///
    /// The returned value should be used immediately and dropped promptly to
    /// minimize the plaintext lifetime in heap memory.
    pub(super) fn decrypt(&self, encrypted: &EncryptedPassword) -> anyhow::Result<SecretString> {
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.key_material.expose_secret()).expect("key is exactly 32 bytes");

        let plaintext_bytes = cipher
            .decrypt(&encrypted.nonce, encrypted.ciphertext.as_ref())
            .ok()
            .context("AEAD decryption failed")?;

        let plaintext = String::from_utf8(plaintext_bytes).context("decrypted password is not valid UTF-8")?;

        Ok(SecretString::from(plaintext))
    }
}

/// Encrypted password stored in heap memory.
///
/// Contains the nonce and ciphertext (including the Poly1305 authentication
/// tag).  Safe to store in regular memory because it is encrypted.
#[derive(Clone)]
pub struct EncryptedPassword {
    /// 96-bit nonce (12 bytes) for ChaCha20-Poly1305.
    nonce: Nonce,

    /// Ciphertext + 128-bit authentication tag (plaintext_len + 16 bytes).
    ciphertext: Vec<u8>,
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
