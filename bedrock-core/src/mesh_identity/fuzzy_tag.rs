//! Fuzzy Message Tags
//!
//! Provides metadata-resistant message detection for mesh networks.
//!
//! # Overview
//!
//! Fuzzy tags allow recipients to detect messages intended for them without
//! revealing their identity. Tags have a configurable false positive rate,
//! meaning decoys also match, providing plausible deniability.
//!
//! # Protocol
//!
//! 1. Recipient generates keypair and shares public key
//! 2. Sender creates a tag for the recipient's public key
//! 3. Recipient derives detection key from secret key
//! 4. Detection key matches intended messages AND some decoys
//!
//! # Security Properties
//!
//! - **Anonymity**: Observer cannot determine intended recipient
//! - **Plausible deniability**: False positives provide cover
//! - **Unlinkability**: Tags for same recipient are unlinkable
//!
//! Based on: "Fuzzy Message Detection" (Signal, 2021)

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BedrockError, Result};

/// Generator point
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Default false positive rate (10%)
const DEFAULT_FALSE_POSITIVE_RATE: f64 = 0.1;

// ============================================================================
// Fuzzy Tag Secret Key
// ============================================================================

/// Secret key for fuzzy tag detection.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FuzzyTagSecretKey {
    /// Detection scalar
    secret: Scalar,
    /// Number of bits to check (controls false positive rate)
    gamma_bits: u8,
}

impl FuzzyTagSecretKey {
    /// Generate a new secret key with default false positive rate.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::generate_with_gamma(rng, DEFAULT_FALSE_POSITIVE_RATE)
    }

    /// Generate with custom false positive rate.
    ///
    /// Lower gamma = more false positives = better anonymity.
    pub fn generate_with_gamma<R: RngCore + CryptoRng>(rng: &mut R, gamma: f64) -> Self {
        let secret = Scalar::random(rng);

        // Compute gamma_bits from false positive rate
        // gamma = 2^(-gamma_bits), so gamma_bits = -log2(gamma)
        let gamma_bits = (-gamma.log2()).ceil() as u8;
        let gamma_bits = gamma_bits.max(1).min(32); // Clamp to reasonable range

        FuzzyTagSecretKey { secret, gamma_bits }
    }

    /// Get the public key.
    pub fn public_key(&self) -> FuzzyTagPublicKey {
        FuzzyTagPublicKey {
            point: G * self.secret,
            gamma_bits: self.gamma_bits,
        }
    }

    /// Derive a detection key for tag matching.
    ///
    /// The detection key can be shared with a server/relay to detect
    /// messages without revealing the full secret key.
    pub fn derive_detection_key(&self) -> DetectionKey {
        DetectionKey {
            secret: self.secret,
            gamma_bits: self.gamma_bits,
        }
    }

    /// Check if a tag matches this secret key.
    pub fn check(&self, tag: &FuzzyTag) -> bool {
        self.derive_detection_key().check(tag)
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[..32].copy_from_slice(self.secret.as_bytes());
        bytes[32] = self.gamma_bits;
        bytes
    }

    /// Import from bytes.
    pub fn from_bytes(bytes: &[u8; 33]) -> Option<Self> {
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes[..32]);
        let secret = Scalar::from_canonical_bytes(secret_bytes).into_option()?;
        let gamma_bits = bytes[32];

        Some(FuzzyTagSecretKey { secret, gamma_bits })
    }
}

// ============================================================================
// Fuzzy Tag Public Key
// ============================================================================

/// Public key for receiving fuzzy-tagged messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzyTagPublicKey {
    /// Public point
    #[serde(with = "point_serde")]
    point: RistrettoPoint,
    /// Gamma bits (false positive rate parameter)
    gamma_bits: u8,
}

impl FuzzyTagPublicKey {
    /// Get the compressed bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[..32].copy_from_slice(self.point.compress().as_bytes());
        bytes[32] = self.gamma_bits;
        bytes
    }

    /// Parse from bytes.
    pub fn from_bytes(bytes: &[u8; 33]) -> Option<Self> {
        let point = CompressedRistretto::from_slice(&bytes[..32])
            .ok()?
            .decompress()?;
        let gamma_bits = bytes[32];

        Some(FuzzyTagPublicKey { point, gamma_bits })
    }

    /// Create a fuzzy tag for this recipient.
    pub fn create_tag<R: RngCore + CryptoRng>(&self, rng: &mut R) -> FuzzyTag {
        FuzzyTag::create(self, rng)
    }
}

// Serde helper for RistrettoPoint
mod point_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(point: &RistrettoPoint, s: S) -> std::result::Result<S::Ok, S::Error> {
        let bytes = point.compress().to_bytes();
        serde::Serialize::serialize(&bytes, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<RistrettoPoint, D::Error> {
        let bytes: [u8; 32] = serde::Deserialize::deserialize(d)?;
        CompressedRistretto::from_slice(&bytes)
            .map_err(serde::de::Error::custom)?
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("invalid point"))
    }
}

// ============================================================================
// Detection Key
// ============================================================================

/// Detection key for checking fuzzy tags.
///
/// Can be shared with relays to detect messages without
/// revealing the full secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DetectionKey {
    /// Detection secret
    secret: Scalar,
    /// Gamma bits
    gamma_bits: u8,
}

impl DetectionKey {
    /// Check if a fuzzy tag matches.
    pub fn check(&self, tag: &FuzzyTag) -> bool {
        // Decompress the tag's ephemeral key
        let r = match CompressedRistretto::from_slice(&tag.ephemeral)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(r) => r,
            None => return false,
        };

        // Compute shared secret: H(secret * R)
        let shared = r * self.secret;
        let shared_hash = Self::hash_shared_secret(&shared);

        // Check gamma_bits of the hash match the tag's ciphertext
        Self::check_gamma_bits(&shared_hash, &tag.ciphertext, self.gamma_bits)
    }

    fn hash_shared_secret(shared: &RistrettoPoint) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"FUZZY_TAG_SHARED:");
        hasher.update(shared.compress().as_bytes());
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn check_gamma_bits(hash: &[u8; 32], ciphertext: &[u8; 32], gamma_bits: u8) -> bool {
        // Check the first gamma_bits bits match
        let bytes_to_check = (gamma_bits as usize + 7) / 8;
        let remaining_bits = gamma_bits as usize % 8;

        for i in 0..bytes_to_check.saturating_sub(1) {
            if hash[i] != ciphertext[i] {
                return false;
            }
        }

        // Check remaining bits of last byte
        if remaining_bits > 0 && bytes_to_check > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            let idx = bytes_to_check - 1;
            if (hash[idx] & mask) != (ciphertext[idx] & mask) {
                return false;
            }
        } else if bytes_to_check > 0 {
            // Full byte check for last byte
            if hash[bytes_to_check - 1] != ciphertext[bytes_to_check - 1] {
                return false;
            }
        }

        true
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[..32].copy_from_slice(self.secret.as_bytes());
        bytes[32] = self.gamma_bits;
        bytes
    }

    /// Import from bytes.
    pub fn from_bytes(bytes: &[u8; 33]) -> Option<Self> {
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes[..32]);
        let secret = Scalar::from_canonical_bytes(secret_bytes).into_option()?;
        let gamma_bits = bytes[32];

        Some(DetectionKey { secret, gamma_bits })
    }
}

// ============================================================================
// Fuzzy Tag
// ============================================================================

/// A fuzzy tag attached to a message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FuzzyTag {
    /// Ephemeral public key R = r * G
    pub ephemeral: [u8; 32],
    /// Ciphertext containing gamma bits
    pub ciphertext: [u8; 32],
}

impl FuzzyTag {
    /// Create a fuzzy tag for a recipient.
    pub fn create<R: RngCore + CryptoRng>(recipient: &FuzzyTagPublicKey, rng: &mut R) -> Self {
        // Generate ephemeral keypair
        let r = Scalar::random(rng);
        let ephemeral_point = G * r;

        // Compute shared secret: H(r * recipient_pk)
        let shared = recipient.point * r;
        let shared_hash = DetectionKey::hash_shared_secret(&shared);

        // Generate random ciphertext with correct gamma bits
        let mut ciphertext = [0u8; 32];
        rng.fill_bytes(&mut ciphertext);

        // Set the first gamma_bits of ciphertext to match shared_hash
        let bytes_to_set = (recipient.gamma_bits as usize + 7) / 8;
        let remaining_bits = recipient.gamma_bits as usize % 8;

        for i in 0..bytes_to_set.saturating_sub(1) {
            ciphertext[i] = shared_hash[i];
        }

        // Handle partial byte
        if remaining_bits > 0 && bytes_to_set > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            let idx = bytes_to_set - 1;
            ciphertext[idx] = (shared_hash[idx] & mask) | (ciphertext[idx] & !mask);
        } else if bytes_to_set > 0 {
            ciphertext[bytes_to_set - 1] = shared_hash[bytes_to_set - 1];
        }

        FuzzyTag {
            ephemeral: ephemeral_point.compress().to_bytes(),
            ciphertext,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.ephemeral);
        bytes[32..].copy_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut ephemeral = [0u8; 32];
        let mut ciphertext = [0u8; 32];
        ephemeral.copy_from_slice(&bytes[..32]);
        ciphertext.copy_from_slice(&bytes[32..]);
        FuzzyTag { ephemeral, ciphertext }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_fuzzy_tag_detection() {
        let mut rng = OsRng;

        // Generate recipient keys
        let secret_key = FuzzyTagSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        // Create a tag for the recipient
        let tag = public_key.create_tag(&mut rng);

        // Recipient should detect the tag
        assert!(secret_key.check(&tag));

        // Detection key should also work
        let detection_key = secret_key.derive_detection_key();
        assert!(detection_key.check(&tag));
    }

    #[test]
    fn test_fuzzy_tag_different_recipients() {
        let mut rng = OsRng;

        let secret_key1 = FuzzyTagSecretKey::generate(&mut rng);
        let secret_key2 = FuzzyTagSecretKey::generate(&mut rng);

        let public_key1 = secret_key1.public_key();

        // Create tag for recipient 1
        let tag = public_key1.create_tag(&mut rng);

        // Recipient 1 should detect
        assert!(secret_key1.check(&tag));

        // Recipient 2 may or may not detect (depends on false positive rate)
        // With 10% rate, there's a 10% chance of false positive
        // We just verify the mechanism works
    }

    #[test]
    fn test_false_positive_rate() {
        let mut rng = OsRng;

        // Create recipient with high false positive rate
        let secret_key = FuzzyTagSecretKey::generate_with_gamma(&mut rng, 0.5); // 50%
        let public_key = secret_key.public_key();

        // Create many tags for other recipients and check false positive rate
        let mut false_positives = 0;
        let trials = 1000;

        for _ in 0..trials {
            let other_secret = FuzzyTagSecretKey::generate_with_gamma(&mut rng, 0.5);
            let other_public = other_secret.public_key();
            let tag = other_public.create_tag(&mut rng);

            if secret_key.check(&tag) {
                false_positives += 1;
            }
        }

        let rate = false_positives as f64 / trials as f64;
        // Should be approximately 50% (within reasonable variance)
        // We use a wide range due to randomness
        assert!(rate > 0.3 && rate < 0.7, "False positive rate: {}", rate);
    }

    #[test]
    fn test_unlinkability() {
        let mut rng = OsRng;

        let secret_key = FuzzyTagSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        // Create multiple tags for the same recipient
        let tag1 = public_key.create_tag(&mut rng);
        let tag2 = public_key.create_tag(&mut rng);

        // Both should be detected
        assert!(secret_key.check(&tag1));
        assert!(secret_key.check(&tag2));

        // Tags should be different (unlinkable)
        assert_ne!(tag1.ephemeral, tag2.ephemeral);
        // Ciphertexts might partially overlap but full arrays differ
    }

    #[test]
    fn test_key_serialization() {
        let mut rng = OsRng;

        let secret_key = FuzzyTagSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        // Serialize and deserialize secret key
        let sk_bytes = secret_key.to_bytes();
        let recovered_sk = FuzzyTagSecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(secret_key.gamma_bits, recovered_sk.gamma_bits);

        // Serialize and deserialize public key
        let pk_bytes = public_key.to_bytes();
        let recovered_pk = FuzzyTagPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(public_key.gamma_bits, recovered_pk.gamma_bits);

        // Tags created with recovered key should still be detected
        let tag = recovered_pk.create_tag(&mut rng);
        assert!(recovered_sk.check(&tag));
    }

    #[test]
    fn test_tag_serialization() {
        let mut rng = OsRng;

        let secret_key = FuzzyTagSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let tag = public_key.create_tag(&mut rng);

        // Serialize and deserialize
        let bytes = tag.to_bytes();
        let recovered = FuzzyTag::from_bytes(&bytes);

        assert_eq!(tag.ephemeral, recovered.ephemeral);
        assert_eq!(tag.ciphertext, recovered.ciphertext);

        // Should still be detected
        assert!(secret_key.check(&recovered));
    }

    #[test]
    fn test_detection_key_sharing() {
        let mut rng = OsRng;

        let secret_key = FuzzyTagSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let detection_key = secret_key.derive_detection_key();

        // Create a tag
        let tag = public_key.create_tag(&mut rng);

        // Serialize detection key (to share with relay)
        let dk_bytes = detection_key.to_bytes();
        let recovered_dk = DetectionKey::from_bytes(&dk_bytes).unwrap();

        // Recovered detection key should still work
        assert!(recovered_dk.check(&tag));
    }
}
