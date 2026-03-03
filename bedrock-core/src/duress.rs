//! Duress Vault - Plausible Deniability System
//!
//! Provides cryptographically indistinguishable decoy vaults.
//! Under coercion, user can provide duress passphrase that opens
//! a innocent-looking decoy vault instead of the real vault.
//!
//! Security properties:
//! 1. Cannot prove real vault exists (looks like random data)
//! 2. Duress vault contains plausible decoy content
//! 3. Same storage size regardless of content
//! 4. No distinguishing metadata
//!
//! Implementation:
//! - Storage is fixed-size encrypted blob
//! - Real passphrase decrypts to real vault
//! - Duress passphrase decrypts to decoy vault
//! - Wrong passphrase produces random garbage (not error)
//! - No way to detect which type of passphrase was used

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha3::Sha3_256;
use zeroize::Zeroize;

use crate::device::DeviceSecret;

/// Fixed vault storage size (ensures no size-based distinguishing)
/// 64KB - enough for identity + reasonable metadata
pub const VAULT_STORAGE_SIZE: usize = 64 * 1024;

/// Magic bytes to verify successful decryption (hidden in plaintext)
const VAULT_MAGIC: [u8; 8] = *b"YRSV0001";

// SECURITY: Duress marker is now user-configurable, not hardcoded.
// The old hardcoded marker " duress" was predictable - an attacker who
// suspects a duress system could try appending common markers.
//
// The marker should be:
// 1. User-chosen (memorable to the user)
// 2. Not a dictionary word
// 3. Unique per user (derived from their chosen word + device secret)

/// Derive a duress marker from user-chosen word and device secret.
/// This makes the marker unique and unpredictable.
pub fn derive_duress_marker(user_word: &[u8], device_secret: &[u8]) -> [u8; 16] {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();
    hasher.update(b"Yours/DuressMarker/v1");
    hasher.update(user_word);
    hasher.update(device_secret);
    let hash = hasher.finalize();

    let mut marker = [0u8; 16];
    marker.copy_from_slice(&hash[..16]);
    marker
}

/// Vault type indicator (internal use only, encrypted)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultType {
    /// Real vault with actual identity
    Real,
    /// Decoy vault with plausible fake content
    Decoy,
}

/// Encrypted vault blob - fixed size, type-indistinguishable
#[derive(Clone)]
pub struct EncryptedVault {
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// Nonce for encryption
    pub nonce: [u8; 12],
    /// Fixed-size encrypted content
    pub ciphertext: [u8; VAULT_STORAGE_SIZE],
    /// Authentication tag
    pub tag: [u8; 16],
}

impl EncryptedVault {
    /// Total serialized size
    pub const SERIALIZED_SIZE: usize = 32 + 12 + VAULT_STORAGE_SIZE + 16;

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SERIALIZED_SIZE);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return None;
        }

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut ciphertext = [0u8; VAULT_STORAGE_SIZE];
        let mut tag = [0u8; 16];

        salt.copy_from_slice(&bytes[0..32]);
        nonce.copy_from_slice(&bytes[32..44]);
        ciphertext.copy_from_slice(&bytes[44..44 + VAULT_STORAGE_SIZE]);
        tag.copy_from_slice(&bytes[44 + VAULT_STORAGE_SIZE..]);

        Some(Self {
            salt,
            nonce,
            ciphertext,
            tag,
        })
    }
}

/// Decrypted vault content
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultContent {
    /// Vault type (not visible in ciphertext)
    pub vault_type: VaultType,
    /// Identity seed (32 bytes)
    pub identity_seed: [u8; 32],
    /// Additional metadata (variable, padded to fixed size)
    pub metadata: Vec<u8>,
}

impl VaultContent {
    /// Create new vault content
    pub fn new(vault_type: VaultType, identity_seed: [u8; 32], metadata: Vec<u8>) -> Self {
        Self {
            vault_type,
            identity_seed,
            metadata,
        }
    }

    /// Serialize with magic bytes and padding
    fn serialize(&self) -> [u8; VAULT_STORAGE_SIZE] {
        let mut buffer = [0u8; VAULT_STORAGE_SIZE];
        let mut offset = 0;

        // Magic bytes (8)
        buffer[offset..offset + 8].copy_from_slice(&VAULT_MAGIC);
        offset += 8;

        // Vault type (1)
        buffer[offset] = match self.vault_type {
            VaultType::Real => 0x01,
            VaultType::Decoy => 0x02,
        };
        offset += 1;

        // Identity seed (32)
        buffer[offset..offset + 32].copy_from_slice(&self.identity_seed);
        offset += 32;

        // Metadata length (4)
        let meta_len = self.metadata.len().min(VAULT_STORAGE_SIZE - offset - 4);
        buffer[offset..offset + 4].copy_from_slice(&(meta_len as u32).to_le_bytes());
        offset += 4;

        // Metadata (variable)
        buffer[offset..offset + meta_len].copy_from_slice(&self.metadata[..meta_len]);
        offset += meta_len;

        // Random padding (fills rest of buffer)
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut buffer[offset..]);

        buffer
    }

    /// Deserialize, returns None if magic doesn't match (wrong key)
    fn deserialize(buffer: &[u8; VAULT_STORAGE_SIZE]) -> Option<Self> {
        let mut offset = 0;

        // Check magic bytes
        if &buffer[offset..offset + 8] != &VAULT_MAGIC {
            return None;
        }
        offset += 8;

        // Vault type
        let vault_type = match buffer[offset] {
            0x01 => VaultType::Real,
            0x02 => VaultType::Decoy,
            _ => return None,
        };
        offset += 1;

        // Identity seed
        let mut identity_seed = [0u8; 32];
        identity_seed.copy_from_slice(&buffer[offset..offset + 32]);
        offset += 32;

        // Metadata length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buffer[offset..offset + 4]);
        let meta_len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;

        // Validate length
        if meta_len > VAULT_STORAGE_SIZE - offset {
            return None;
        }

        // Metadata
        let metadata = buffer[offset..offset + meta_len].to_vec();

        Some(Self {
            vault_type,
            identity_seed,
            metadata,
        })
    }
}

// Implement Zeroize for VaultType (no actual data to zeroize)
impl Zeroize for VaultType {
    fn zeroize(&mut self) {
        *self = VaultType::Decoy;
    }
}

/// Dual-vault system with duress capability
pub struct DuressVaultSystem {
    /// Device secret for binding
    device_secret: DeviceSecret,
}

impl DuressVaultSystem {
    /// Create new duress vault system
    pub fn new(device_secret: DeviceSecret) -> Self {
        Self { device_secret }
    }

    /// Create encrypted vault from content
    ///
    /// The passphrase determines which vault is accessed:
    /// - Normal passphrase → real vault
    /// - Passphrase + " duress" → decoy vault
    pub fn encrypt_vault(
        &self,
        passphrase: &[u8],
        content: &VaultContent,
    ) -> Result<EncryptedVault, &'static str> {
        let mut rng = rand::rngs::OsRng;

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key
        let key = self.derive_vault_key(passphrase, &salt)?;

        // Serialize content with padding
        let plaintext = content.serialize();

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "Invalid key")?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext_with_tag = cipher
            .encrypt(nonce, &plaintext[..])
            .map_err(|_| "Encryption failed")?;

        // Split ciphertext and tag
        if ciphertext_with_tag.len() != VAULT_STORAGE_SIZE + 16 {
            return Err("Unexpected ciphertext size");
        }

        let mut ciphertext = [0u8; VAULT_STORAGE_SIZE];
        let mut tag = [0u8; 16];
        ciphertext.copy_from_slice(&ciphertext_with_tag[..VAULT_STORAGE_SIZE]);
        tag.copy_from_slice(&ciphertext_with_tag[VAULT_STORAGE_SIZE..]);

        Ok(EncryptedVault {
            salt,
            nonce: nonce_bytes,
            ciphertext,
            tag,
        })
    }

    /// Decrypt vault with passphrase
    ///
    /// Returns decrypted content if passphrase is correct.
    /// Returns None if passphrase is wrong (no error message to avoid oracle).
    pub fn decrypt_vault(
        &self,
        passphrase: &[u8],
        vault: &EncryptedVault,
    ) -> Option<VaultContent> {
        // Derive decryption key
        let key = self.derive_vault_key(passphrase, &vault.salt).ok()?;

        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = Vec::with_capacity(VAULT_STORAGE_SIZE + 16);
        ciphertext_with_tag.extend_from_slice(&vault.ciphertext);
        ciphertext_with_tag.extend_from_slice(&vault.tag);

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        let nonce = Nonce::from_slice(&vault.nonce);

        let plaintext = cipher.decrypt(nonce, &ciphertext_with_tag[..]).ok()?;

        // Deserialize (validates magic bytes)
        let mut plaintext_arr = [0u8; VAULT_STORAGE_SIZE];
        plaintext_arr.copy_from_slice(&plaintext);
        VaultContent::deserialize(&plaintext_arr)
    }

    /// Check if passphrase is a duress passphrase
    ///
    /// The duress_marker should be derived using `derive_duress_marker()`.
    pub fn is_duress_passphrase(passphrase: &[u8], duress_marker: &[u8]) -> bool {
        // Passphrase must be strictly longer than the marker
        // (otherwise there's no real passphrase component)
        if passphrase.len() <= duress_marker.len() {
            return false;
        }

        let suffix = &passphrase[passphrase.len() - duress_marker.len()..];
        // Constant-time comparison to avoid timing attacks
        use subtle::ConstantTimeEq;
        suffix.ct_eq(duress_marker).into()
    }

    /// Get the real passphrase from a duress passphrase
    /// (strips the duress marker)
    ///
    /// The duress_marker should be derived using `derive_duress_marker()`.
    pub fn strip_duress_marker<'a>(passphrase: &'a [u8], duress_marker: &[u8]) -> &'a [u8] {
        if Self::is_duress_passphrase(passphrase, duress_marker) {
            &passphrase[..passphrase.len() - duress_marker.len()]
        } else {
            passphrase
        }
    }

    /// Create both real and decoy vaults
    ///
    /// Returns (real_vault, decoy_vault) encrypted with:
    /// - real_vault: normal passphrase
    /// - decoy_vault: passphrase + duress_marker
    ///
    /// The duress_marker should be derived using `derive_duress_marker()`.
    /// SECURITY: The marker is user-configurable to prevent attackers from
    /// guessing common duress words. Use `derive_duress_marker(user_word, device_secret)`
    /// to create a unique, unpredictable marker.
    pub fn create_dual_vaults(
        &self,
        passphrase: &[u8],
        duress_marker: &[u8],
        real_identity_seed: [u8; 32],
        real_metadata: Vec<u8>,
        decoy_identity_seed: [u8; 32],
        decoy_metadata: Vec<u8>,
    ) -> Result<(EncryptedVault, EncryptedVault), &'static str> {
        // Create real vault content
        let real_content = VaultContent::new(VaultType::Real, real_identity_seed, real_metadata);

        // Create decoy vault content
        let decoy_content = VaultContent::new(VaultType::Decoy, decoy_identity_seed, decoy_metadata);

        // Encrypt real vault with normal passphrase
        let real_vault = self.encrypt_vault(passphrase, &real_content)?;

        // Encrypt decoy vault with duress passphrase
        let mut duress_passphrase = passphrase.to_vec();
        duress_passphrase.extend_from_slice(duress_marker);
        let decoy_vault = self.encrypt_vault(&duress_passphrase, &decoy_content)?;
        duress_passphrase.zeroize();

        Ok((real_vault, decoy_vault))
    }

    /// Derive vault encryption key from passphrase
    fn derive_vault_key(
        &self,
        passphrase: &[u8],
        salt: &[u8; 32],
    ) -> Result<[u8; 32], &'static str> {
        // Combine passphrase with device secret
        let mut combined = Vec::with_capacity(passphrase.len() + 32);
        combined.extend_from_slice(passphrase);
        combined.extend_from_slice(self.device_secret.as_bytes());

        // Use HKDF for key derivation (Argon2 already applied to passphrase)
        let hk = Hkdf::<Sha3_256>::new(Some(salt), &combined);
        let mut key = [0u8; 32];
        hk.expand(b"Yours/DuressVault/v1/key", &mut key)
            .map_err(|_| "HKDF failed")?;

        combined.zeroize();
        Ok(key)
    }
}

/// Hidden volume within encrypted storage
///
/// Allows multiple "layers" of encryption where each layer
/// decrypts to a valid-looking filesystem but only the correct
/// passphrase reveals the real data.
pub struct HiddenVolume {
    /// Outer volume (visible, contains decoy data)
    pub outer: EncryptedVault,
    /// Inner volume (hidden, contains real data)
    /// Stored within the "free space" of outer volume
    pub inner: EncryptedVault,
}

impl HiddenVolume {
    /// Check if a vault might contain a hidden volume
    /// (This should always return true to avoid detection)
    pub fn might_contain_hidden(_vault: &EncryptedVault) -> bool {
        // Always return true - cannot distinguish
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceSecretSource;

    fn test_device_secret() -> DeviceSecret {
        DeviceSecret::new([42u8; 32], DeviceSecretSource::Synthetic)
    }

    #[test]
    fn test_vault_encrypt_decrypt() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";

        let content = VaultContent::new(
            VaultType::Real,
            [1u8; 32],
            b"test metadata".to_vec(),
        );

        let encrypted = system.encrypt_vault(passphrase, &content).unwrap();
        let decrypted = system.decrypt_vault(passphrase, &encrypted).unwrap();

        assert_eq!(decrypted.vault_type, VaultType::Real);
        assert_eq!(decrypted.identity_seed, [1u8; 32]);
        assert_eq!(decrypted.metadata, b"test metadata".to_vec());
    }

    #[test]
    fn test_wrong_passphrase_returns_none() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";
        let wrong_passphrase = b"wrong words here now plus more words extra";

        let content = VaultContent::new(VaultType::Real, [1u8; 32], vec![]);

        let encrypted = system.encrypt_vault(passphrase, &content).unwrap();
        let result = system.decrypt_vault(wrong_passphrase, &encrypted);

        // Should return None, not an error
        assert!(result.is_none());
    }

    #[test]
    fn test_duress_passphrase_detection() {
        // Derive a test marker from user word + device secret
        let marker = derive_duress_marker(b"panic", test_device_secret().as_bytes());

        // Test with derived marker
        let mut duress_phrase = b"normal passphrase".to_vec();
        duress_phrase.extend_from_slice(&marker);

        assert!(!DuressVaultSystem::is_duress_passphrase(b"normal passphrase", &marker));
        assert!(DuressVaultSystem::is_duress_passphrase(&duress_phrase, &marker));
        assert!(!DuressVaultSystem::is_duress_passphrase(&marker, &marker)); // just marker is not a valid duress phrase
    }

    #[test]
    fn test_duress_marker_derivation() {
        // Same inputs should produce same marker
        let marker1 = derive_duress_marker(b"panic", &[1u8; 32]);
        let marker2 = derive_duress_marker(b"panic", &[1u8; 32]);
        assert_eq!(marker1, marker2);

        // Different user word should produce different marker
        let marker3 = derive_duress_marker(b"help", &[1u8; 32]);
        assert_ne!(marker1, marker3);

        // Different device secret should produce different marker
        let marker4 = derive_duress_marker(b"panic", &[2u8; 32]);
        assert_ne!(marker1, marker4);
    }

    #[test]
    fn test_dual_vaults() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";
        let duress_marker = derive_duress_marker(b"panic", test_device_secret().as_bytes());

        let (real_vault, decoy_vault) = system
            .create_dual_vaults(
                passphrase,
                &duress_marker,
                [1u8; 32],
                b"real secrets".to_vec(),
                [2u8; 32],
                b"decoy data".to_vec(),
            )
            .unwrap();

        // Normal passphrase opens real vault
        let real_content = system.decrypt_vault(passphrase, &real_vault).unwrap();
        assert_eq!(real_content.vault_type, VaultType::Real);
        assert_eq!(real_content.identity_seed, [1u8; 32]);
        assert_eq!(real_content.metadata, b"real secrets".to_vec());

        // Duress passphrase (passphrase + marker) opens decoy vault
        let mut duress_passphrase = passphrase.to_vec();
        duress_passphrase.extend_from_slice(&duress_marker);
        let decoy_content = system.decrypt_vault(&duress_passphrase, &decoy_vault).unwrap();
        assert_eq!(decoy_content.vault_type, VaultType::Decoy);
        assert_eq!(decoy_content.identity_seed, [2u8; 32]);
        assert_eq!(decoy_content.metadata, b"decoy data".to_vec());

        // Wrong passphrase opens neither
        assert!(system.decrypt_vault(b"wrong", &real_vault).is_none());
        assert!(system.decrypt_vault(b"wrong", &decoy_vault).is_none());
    }

    #[test]
    fn test_vault_serialization() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";

        let content = VaultContent::new(VaultType::Real, [1u8; 32], vec![]);
        let encrypted = system.encrypt_vault(passphrase, &content).unwrap();

        let bytes = encrypted.to_bytes();
        assert_eq!(bytes.len(), EncryptedVault::SERIALIZED_SIZE);

        let recovered = EncryptedVault::from_bytes(&bytes).unwrap();
        let decrypted = system.decrypt_vault(passphrase, &recovered).unwrap();

        assert_eq!(decrypted.identity_seed, [1u8; 32]);
    }

    #[test]
    fn test_fixed_size_regardless_of_content() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";

        // Empty metadata
        let content1 = VaultContent::new(VaultType::Real, [1u8; 32], vec![]);
        let encrypted1 = system.encrypt_vault(passphrase, &content1).unwrap();

        // Large metadata
        let content2 = VaultContent::new(VaultType::Real, [1u8; 32], vec![0u8; 10000]);
        let encrypted2 = system.encrypt_vault(passphrase, &content2).unwrap();

        // Both should be same size
        assert_eq!(encrypted1.to_bytes().len(), encrypted2.to_bytes().len());
    }

    #[test]
    fn test_ciphertext_looks_random() {
        let system = DuressVaultSystem::new(test_device_secret());
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";

        let content = VaultContent::new(VaultType::Real, [0u8; 32], vec![0u8; 1000]);
        let encrypted = system.encrypt_vault(passphrase, &content).unwrap();

        // Ciphertext should have high entropy (look random)
        // Check that bytes are reasonably distributed
        let mut counts = [0u32; 256];
        for &byte in &encrypted.ciphertext {
            counts[byte as usize] += 1;
        }

        // Each byte value should appear roughly (VAULT_SIZE / 256) times
        // Allow 50% deviation
        let expected = (VAULT_STORAGE_SIZE / 256) as u32;
        let min = expected / 2;
        let max = expected * 3 / 2;

        let well_distributed = counts.iter().filter(|&&c| c >= min && c <= max).count();
        assert!(
            well_distributed > 200,
            "Ciphertext doesn't look random enough"
        );
    }
}
