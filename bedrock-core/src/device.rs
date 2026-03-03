//! Device Binding and Passphrase Hardening
//!
//! Ensures that passphrase alone is insufficient to derive keys.
//! Keys are bound to specific device hardware, requiring both:
//! 1. Knowledge of passphrase (8+ words, ~88 bits entropy)
//! 2. Possession of device (hardware-derived secret)
//!
//! This defeats:
//! - Remote passphrase brute-force (attacker needs device)
//! - Device theft alone (attacker needs passphrase)
//! - Coerced passphrase disclosure (without device, useless)
//!
//! Device secret sources (in order of preference):
//! 1. Hardware-backed keystore (if trustworthy)
//! 2. Sovereignty Scanner extracted device keys
//! 3. Filesystem-based secret (fallback, less secure)

use argon2::Argon2;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::bip39;

/// Minimum passphrase words required
pub const MIN_PASSPHRASE_WORDS: usize = 8;

/// BIP-39 wordlist size
pub const BIP39_WORDLIST_SIZE: usize = 2048;

/// Bits of entropy per word (log2(2048) = 11)
pub const BITS_PER_WORD: usize = 11;

/// Minimum required entropy bits
pub const MIN_ENTROPY_BITS: usize = MIN_PASSPHRASE_WORDS * BITS_PER_WORD; // 88 bits

/// Device binding version (for future upgrades)
pub const DEVICE_BINDING_VERSION: u8 = 1;

/// Argon2id parameters - MAXIMUM security
/// Mobile devices in 2025 have 8-12GB RAM, we use 1GB
pub const ARGON2_MEMORY_KB: u32 = 1024 * 1024; // 1GB
pub const ARGON2_ITERATIONS: u32 = 8;
pub const ARGON2_PARALLELISM: u32 = 4;

/// Device secret - extracted from hardware or generated
#[derive(Clone)]
pub struct DeviceSecret {
    /// 32-byte hardware-bound secret
    secret: [u8; 32],
    /// Source of the secret (for audit)
    pub source: DeviceSecretSource,
}

impl Zeroize for DeviceSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        // source doesn't need zeroization (not sensitive)
    }
}

impl Drop for DeviceSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Where the device secret came from
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSecretSource {
    /// Hardware-backed keystore (Android Keystore, iOS Secure Enclave)
    HardwareKeystore,
    /// Extracted via Sovereignty Scanner (device-specific keys)
    SovereigntyScanner,
    /// Filesystem-based (less secure, but still adds entropy)
    Filesystem,
    /// Test/development only
    Synthetic,
}

impl DeviceSecret {
    /// Create from raw bytes and source
    pub fn new(secret: [u8; 32], source: DeviceSecretSource) -> Self {
        Self { secret, source }
    }

    /// Generate synthetic secret (for testing only)
    #[cfg(test)]
    pub fn synthetic() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            secret,
            source: DeviceSecretSource::Synthetic,
        }
    }

    /// Get secret bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Derive from hardware ID (called from Android/iOS)
    pub fn from_hardware_id(hardware_id: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/DeviceSecret/v1/hardware");
        hasher.update(hardware_id);
        let hash = hasher.finalize();

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&hash);

        Self {
            secret,
            source: DeviceSecretSource::HardwareKeystore,
        }
    }

    /// Derive from Sovereignty Scanner extracted keys
    pub fn from_sovereignty_scanner(extracted_keys: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/DeviceSecret/v1/sovereignty");
        hasher.update(extracted_keys);
        let hash = hasher.finalize();

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&hash);

        Self {
            secret,
            source: DeviceSecretSource::SovereigntyScanner,
        }
    }
}

/// Passphrase validation result
#[derive(Debug, Clone)]
pub struct PassphraseValidation {
    pub valid: bool,
    pub word_count: usize,
    pub entropy_bits: usize,
    pub error: Option<PassphraseError>,
}

/// Passphrase validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseError {
    /// Too few words
    TooShort { got: usize, min: usize },
    /// Word not in BIP-39 wordlist
    InvalidWord { position: usize },
    /// Empty passphrase
    Empty,
    /// Contains invalid characters
    InvalidCharacters,
}

/// Validate passphrase meets security requirements
pub fn validate_passphrase(passphrase: &str) -> PassphraseValidation {
    let trimmed = passphrase.trim();

    if trimmed.is_empty() {
        return PassphraseValidation {
            valid: false,
            word_count: 0,
            entropy_bits: 0,
            error: Some(PassphraseError::Empty),
        };
    }

    // Split into words
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    let word_count = words.len();

    // Check minimum word count
    if word_count < MIN_PASSPHRASE_WORDS {
        return PassphraseValidation {
            valid: false,
            word_count,
            entropy_bits: word_count * BITS_PER_WORD,
            error: Some(PassphraseError::TooShort {
                got: word_count,
                min: MIN_PASSPHRASE_WORDS,
            }),
        };
    }

    // Validate each word is lowercase alphabetic
    for (i, word) in words.iter().enumerate() {
        if !word.chars().all(|c| c.is_ascii_lowercase()) {
            return PassphraseValidation {
                valid: false,
                word_count,
                entropy_bits: 0,
                error: Some(PassphraseError::InvalidCharacters),
            };
        }

        // Validate against BIP-39 wordlist using binary search
        if !bip39::is_valid_word(word) {
            return PassphraseValidation {
                valid: false,
                word_count,
                entropy_bits: 0,
                error: Some(PassphraseError::InvalidWord { position: i }),
            };
        }
    }

    PassphraseValidation {
        valid: true,
        word_count,
        entropy_bits: word_count * BITS_PER_WORD,
        error: None,
    }
}

/// Device-bound key derivation
///
/// Combines passphrase and device secret to derive master key.
/// Neither alone is sufficient.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DeviceBoundKey {
    /// The derived master key
    key: [u8; 64],
}

impl DeviceBoundKey {
    /// Derive device-bound key from passphrase and device secret
    ///
    /// Uses Argon2id with maximum parameters:
    /// - 1GB memory (defeats GPU/ASIC attacks)
    /// - 8 iterations (increases time cost)
    /// - 4 threads (uses available parallelism)
    pub fn derive(
        passphrase: &[u8],
        device_secret: &DeviceSecret,
        salt: &[u8; 32],
    ) -> Result<Self, &'static str> {
        // Combine passphrase and device secret
        let mut combined = Vec::with_capacity(passphrase.len() + 32);
        combined.extend_from_slice(passphrase);
        combined.extend_from_slice(device_secret.as_bytes());

        // Create salted input
        let mut full_salt = Vec::with_capacity(salt.len() + 32);
        full_salt.extend_from_slice(salt);
        full_salt.extend_from_slice(b"Yours/DeviceBound/v1");

        // Argon2id with maximum parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY_KB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(64),
            )
            .map_err(|_| "Invalid Argon2 params")?,
        );

        let mut key = [0u8; 64];
        argon2
            .hash_password_into(&combined, &full_salt, &mut key)
            .map_err(|_| "Argon2 failed")?;

        // Zeroize intermediate values
        combined.zeroize();

        Ok(Self { key })
    }

    /// Derive with reduced parameters (for mobile devices with limited RAM)
    /// Still uses 512MB which is substantial
    pub fn derive_mobile(
        passphrase: &[u8],
        device_secret: &DeviceSecret,
        salt: &[u8; 32],
    ) -> Result<Self, &'static str> {
        let mut combined = Vec::with_capacity(passphrase.len() + 32);
        combined.extend_from_slice(passphrase);
        combined.extend_from_slice(device_secret.as_bytes());

        let mut full_salt = Vec::with_capacity(salt.len() + 32);
        full_salt.extend_from_slice(salt);
        full_salt.extend_from_slice(b"Yours/DeviceBound/v1");

        // 512MB for mobile with 12 iterations (compensates for reduced memory)
        // MUST MATCH: HardenedKeyDerivation.kt ARGON2_MOBILE_* constants
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                512 * 1024, // 512MB (ARGON2_MOBILE_MEMORY_KIB)
                12,         // 12 iterations (ARGON2_MOBILE_ITERATIONS)
                2,          // 2 threads (ARGON2_MOBILE_PARALLELISM)
                Some(64),
            )
            .map_err(|_| "Invalid Argon2 params")?,
        );

        let mut key = [0u8; 64];
        argon2
            .hash_password_into(&combined, &full_salt, &mut key)
            .map_err(|_| "Argon2 failed")?;

        combined.zeroize();

        Ok(Self { key })
    }

    /// Get identity seed portion (first 32 bytes)
    pub fn identity_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.key[..32]);
        seed
    }

    /// Get recovery seed portion (last 32 bytes)
    pub fn recovery_seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.key[32..]);
        seed
    }

    /// Get full key material
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.key
    }
}

/// Hardware binding challenge-response
///
/// Used to verify device possession without revealing device secret.
pub struct DeviceChallenge {
    pub challenge: [u8; 32],
    pub timestamp: u64,
}

impl DeviceChallenge {
    /// Create new challenge
    pub fn new() -> Self {
        use rand::RngCore;
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            challenge,
            timestamp,
        }
    }

    /// Compute response using device secret
    pub fn respond(&self, device_secret: &DeviceSecret) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/DeviceChallenge/v1/response");
        hasher.update(&self.challenge);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(device_secret.as_bytes());

        let hash = hasher.finalize();
        let mut response = [0u8; 32];
        response.copy_from_slice(&hash);
        response
    }

    /// Verify response
    pub fn verify(&self, response: &[u8; 32], device_secret: &DeviceSecret) -> bool {
        let expected = self.respond(device_secret);

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in response.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Check if challenge is still fresh (within 5 minutes)
    pub fn is_fresh(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now.saturating_sub(self.timestamp) < 300 // 5 minutes
    }
}

impl Default for DeviceChallenge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passphrase_validation_valid() {
        // All words must be valid BIP-39 words
        let passphrase = "abandon ability able about above absent absorb abstract";
        let result = validate_passphrase(passphrase);

        assert!(result.valid, "Expected valid passphrase, got error: {:?}", result.error);
        assert_eq!(result.word_count, 8);
        assert_eq!(result.entropy_bits, 88);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_passphrase_validation_too_short() {
        let passphrase = "abandon ability able about"; // Only 4 words
        let result = validate_passphrase(passphrase);

        assert!(!result.valid);
        assert_eq!(result.word_count, 4);
        assert!(matches!(
            result.error,
            Some(PassphraseError::TooShort { got: 4, min: 8 })
        ));
    }

    #[test]
    fn test_passphrase_validation_empty() {
        let result = validate_passphrase("");
        assert!(!result.valid);
        assert!(matches!(result.error, Some(PassphraseError::Empty)));
    }

    #[test]
    fn test_passphrase_validation_invalid_chars() {
        let passphrase = "Forest Ember Shadow River Crystal Mountain Ocean Thunder";
        let result = validate_passphrase(passphrase);

        assert!(!result.valid);
        assert!(matches!(
            result.error,
            Some(PassphraseError::InvalidCharacters)
        ));
    }

    #[test]
    fn test_device_secret_from_hardware() {
        let hardware_id = b"unique-device-identifier-12345";
        let secret = DeviceSecret::from_hardware_id(hardware_id);

        assert_eq!(secret.source, DeviceSecretSource::HardwareKeystore);
        assert_ne!(secret.as_bytes(), &[0u8; 32]);

        // Same hardware ID should produce same secret
        let secret2 = DeviceSecret::from_hardware_id(hardware_id);
        assert_eq!(secret.as_bytes(), secret2.as_bytes());

        // Different hardware ID should produce different secret
        let secret3 = DeviceSecret::from_hardware_id(b"different-device");
        assert_ne!(secret.as_bytes(), secret3.as_bytes());
    }

    #[test]
    fn test_device_bound_key_derivation() {
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";
        let device_secret = DeviceSecret::synthetic();
        let salt = [42u8; 32];

        // Use mobile params for faster testing
        let key = DeviceBoundKey::derive_mobile(passphrase, &device_secret, &salt).unwrap();

        // Should produce non-zero key
        assert_ne!(key.identity_seed(), [0u8; 32]);
        assert_ne!(key.recovery_seed(), [0u8; 32]);

        // Identity and recovery seeds should be different
        assert_ne!(key.identity_seed(), key.recovery_seed());
    }

    #[test]
    fn test_device_bound_key_deterministic() {
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";
        let device_secret = DeviceSecret::new([1u8; 32], DeviceSecretSource::Synthetic);
        let salt = [42u8; 32];

        let key1 = DeviceBoundKey::derive_mobile(passphrase, &device_secret, &salt).unwrap();
        let key2 = DeviceBoundKey::derive_mobile(passphrase, &device_secret, &salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_device_bound_key_different_inputs() {
        let passphrase = b"forest ember shadow river crystal mountain ocean thunder";
        let device_secret = DeviceSecret::new([1u8; 32], DeviceSecretSource::Synthetic);
        let salt = [42u8; 32];

        let key1 = DeviceBoundKey::derive_mobile(passphrase, &device_secret, &salt).unwrap();

        // Different passphrase
        let key2 = DeviceBoundKey::derive_mobile(
            b"different words here now plus more words extra",
            &device_secret,
            &salt,
        )
        .unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Different device secret
        let device_secret2 = DeviceSecret::new([2u8; 32], DeviceSecretSource::Synthetic);
        let key3 = DeviceBoundKey::derive_mobile(passphrase, &device_secret2, &salt).unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());

        // Different salt
        let key4 = DeviceBoundKey::derive_mobile(passphrase, &device_secret, &[0u8; 32]).unwrap();
        assert_ne!(key1.as_bytes(), key4.as_bytes());
    }

    #[test]
    fn test_device_challenge_response() {
        let device_secret = DeviceSecret::synthetic();
        let challenge = DeviceChallenge::new();

        let response = challenge.respond(&device_secret);
        assert!(challenge.verify(&response, &device_secret));

        // Wrong device secret should fail
        let wrong_secret = DeviceSecret::synthetic();
        assert!(!challenge.verify(&response, &wrong_secret));

        // Wrong response should fail
        let wrong_response = [0u8; 32];
        assert!(!challenge.verify(&wrong_response, &device_secret));
    }

    #[test]
    fn test_device_challenge_freshness() {
        let challenge = DeviceChallenge::new();
        assert!(challenge.is_fresh());
    }
}
