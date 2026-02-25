//! In-memory credential encryption using ChaCha20-Poly1305.
//!
//! This module provides encryption-at-rest for passwords stored in the credential store.
//! A randomly generated 256-bit master key is stored in a zeroize-on-drop wrapper.
//! When the `mlock` feature is enabled, libsodium's memory locking facilities
//! (mlock/mprotect) are additionally used to prevent the key from being swapped to
//! disk or appearing in core dumps.
//!
//! ## Security Properties
//!
//! - Passwords encrypted at rest in regular heap memory
//! - Decryption on-demand into short-lived zeroized buffers
//! - ChaCha20-Poly1305 provides authenticated encryption
//! - Random 96-bit nonces prevent nonce reuse
//! - Master key zeroized on drop
//! - With `mlock` feature: Master key stored in mlock'd memory (excluded from core dumps)

use core::fmt;
use std::sync::LazyLock;

use anyhow::Context as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use parking_lot::Mutex;
use rand::RngCore as _;
use secrecy::SecretString;
#[cfg(feature = "mlock")]
use secrets::SecretBox;
#[cfg(not(feature = "mlock"))]
use zeroize::Zeroizing;

/// Global master key for credential encryption.
///
/// Initialized lazily on first access. The key material is wrapped in a Mutex
/// for thread-safe access. With the `mlock` feature, key memory is additionally
/// protected by mlock/mprotect via libsodium's SecretBox.
pub(super) static MASTER_KEY: LazyLock<Mutex<MasterKeyManager>> = LazyLock::new(|| {
    Mutex::new(MasterKeyManager::new().expect("failed to initialize credential encryption master key"))
});

/// Manages the master encryption key.
///
/// The key is zeroized on drop. When the `mlock` feature is enabled, the key
/// memory is additionally:
/// - Locked (mlock) to prevent swapping to disk
/// - Protected (mprotect) with appropriate access controls
/// - Excluded from core dumps
pub(super) struct MasterKeyManager {
    #[cfg(feature = "mlock")]
    key_material: SecretBox<[u8; 32]>,
    #[cfg(not(feature = "mlock"))]
    key_material: Zeroizing<[u8; 32]>,
}

impl MasterKeyManager {
    /// Generate a new random 256-bit master key.
    ///
    /// # Errors
    ///
    /// Returns error if secure memory allocation fails or RNG fails.
    fn new() -> anyhow::Result<Self> {
        #[cfg(feature = "mlock")]
        let key_material = SecretBox::try_new(|key_bytes: &mut [u8; 32]| {
            OsRng.fill_bytes(key_bytes);
            Ok::<_, anyhow::Error>(())
        })
        .context("failed to allocate secure memory for master key")?;

        #[cfg(not(feature = "mlock"))]
        let key_material = {
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key.as_mut());
            key
        };

        Ok(Self { key_material })
    }

    /// Encrypt a password using ChaCha20-Poly1305.
    ///
    /// Returns the nonce and ciphertext (which includes the Poly1305 auth tag).
    pub(super) fn encrypt(&self, plaintext: &str) -> anyhow::Result<EncryptedPassword> {
        #[cfg(feature = "mlock")]
        let key_ref = self.key_material.borrow();
        #[cfg(feature = "mlock")]
        let key_bytes: &[u8] = key_ref.as_ref();

        #[cfg(not(feature = "mlock"))]
        let key_bytes: &[u8] = self.key_material.as_ref();

        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes).expect("key is exactly 32 bytes");

        // Generate random 96-bit nonce (12 bytes for ChaCha20-Poly1305).
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

        // Encrypt (ciphertext includes 16-byte Poly1305 tag).
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .ok()
            .context("AEAD encryption failed")?;

        Ok(EncryptedPassword { nonce, ciphertext })
    }

    /// Decrypt a password, returning a `SecretString` that zeroizes on drop.
    ///
    /// The returned `SecretString` should have a short lifetime.
    /// Use it immediately and let it drop to zeroize the plaintext.
    pub(super) fn decrypt(&self, encrypted: &EncryptedPassword) -> anyhow::Result<SecretString> {
        #[cfg(feature = "mlock")]
        let key_ref = self.key_material.borrow();
        #[cfg(feature = "mlock")]
        let key_bytes: &[u8] = key_ref.as_ref();

        #[cfg(not(feature = "mlock"))]
        let key_bytes: &[u8] = self.key_material.as_ref();

        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes).expect("key is exactly 32 bytes");

        let plaintext_bytes = cipher
            .decrypt(&encrypted.nonce, encrypted.ciphertext.as_ref())
            .ok()
            .context("AEAD decryption failed")?;

        // Convert bytes to String.
        let plaintext = String::from_utf8(plaintext_bytes).context("decrypted password is not valid UTF-8")?;

        Ok(SecretString::from(plaintext))
    }
}

// Note: With `mlock` feature, SecretBox handles secure zeroization and munlock automatically on drop.
// Without `mlock` feature, Zeroizing handles secure zeroization on drop (no mlock).

/// Encrypted password stored in heap memory.
///
/// Contains the nonce and ciphertext (including Poly1305 authentication tag).
/// This can be safely stored in regular memory as it's encrypted.
#[derive(Clone)]
pub struct EncryptedPassword {
    /// 96-bit nonce (12 bytes) for ChaCha20-Poly1305.
    nonce: Nonce,

    /// Ciphertext + 128-bit auth tag (plaintext_len + 16 bytes).
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
        let key_manager = MasterKeyManager::new().unwrap();
        let plaintext = "my-secret-password";

        let encrypted = key_manager.encrypt(plaintext).unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key_manager = MasterKeyManager::new().unwrap();
        let plaintext = "password";

        let encrypted1 = key_manager.encrypt(plaintext).unwrap();
        let encrypted2 = key_manager.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertexts (different nonces).
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key_manager1 = MasterKeyManager::new().unwrap();
        let key_manager2 = MasterKeyManager::new().unwrap();

        let encrypted = key_manager1.encrypt("secret").unwrap();

        // Decryption with different key should fail.
        assert!(key_manager2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let key_manager = MasterKeyManager::new().unwrap();
        let mut encrypted = key_manager.encrypt("secret").unwrap();

        // Corrupt the ciphertext.
        encrypted.ciphertext[0] ^= 0xFF;

        // Should fail authentication.
        assert!(key_manager.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_password() {
        let key_manager = MasterKeyManager::new().unwrap();
        let encrypted = key_manager.encrypt("").unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), "");
    }

    #[test]
    fn test_unicode_password() {
        let key_manager = MasterKeyManager::new().unwrap();
        let plaintext = "пароль-密码-كلمة السر";
        let encrypted = key_manager.encrypt(plaintext).unwrap();
        let decrypted = key_manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }

    #[test]
    fn test_global_master_key() {
        // Test that the global MASTER_KEY works.
        let plaintext = "test-password";
        let encrypted = MASTER_KEY.lock().encrypt(plaintext).unwrap();
        let decrypted = MASTER_KEY.lock().decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.expose_secret(), plaintext);
    }
}
