//! Nullifier System for Dead Man's Switch
//!
//! Provides unlinkable, deterministic tags that prove liveness without
//! revealing identity. Used for the dead man's switch: if a user stops
//! publishing nullifiers, recovery may be triggered.
//!
//! Properties:
//! - Deterministic: Same (secret, epoch) always produces same nullifier
//! - Unlinkable: Different epochs produce unrelated nullifiers
//! - Binding: Cannot produce valid nullifier without knowing secret
//!
//! Security: Relies on SHA3-256 random oracle assumption.

use sha3::{Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Duration of one epoch in seconds (1 week)
pub const EPOCH_DURATION_SECS: u64 = 7 * 24 * 60 * 60;

/// Number of missed epochs before dead man's switch triggers
pub const DEFAULT_DEAD_MAN_THRESHOLD: u64 = 4; // 4 weeks

/// A nullifier - deterministic tag for proving liveness
///
/// nf = SHA3-256(secret || epoch || domain)
///
/// Published each epoch to prove user is alive.
/// Nodes cannot link nullifiers across epochs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Derive nullifier for a given epoch
    ///
    /// The secret should be derived from passphrase via HKDF.
    /// This ensures only someone with the passphrase can generate valid nullifiers.
    pub fn derive(secret: &[u8; 32], epoch: u64) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/Nullifier/v1/alive");
        hasher.update(secret);
        hasher.update(&epoch.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Nullifier(result)
    }

    /// Derive nullifier for current epoch
    pub fn derive_current(secret: &[u8; 32]) -> Self {
        Self::derive(secret, current_epoch())
    }

    /// Derive registration commitment
    ///
    /// Published once at identity creation to register with the network.
    /// This commits to the nullifier secret without revealing it.
    pub fn registration_commitment(secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/Nullifier/v1/registration");
        hasher.update(secret);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Nullifier(bytes)
    }
}

/// Get current epoch (weeks since Unix epoch)
pub fn current_epoch() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    now / EPOCH_DURATION_SECS
}

/// Get epoch for a given Unix timestamp
pub fn epoch_at(unix_timestamp: u64) -> u64 {
    unix_timestamp / EPOCH_DURATION_SECS
}

/// Get Unix timestamp at start of epoch
pub fn epoch_start(epoch: u64) -> u64 {
    epoch * EPOCH_DURATION_SECS
}

/// Dead man's switch state
///
/// Tracks when the user last checked in (published a nullifier).
/// If too many epochs pass without check-in, recovery may be triggered.
#[derive(Clone, Debug)]
pub struct DeadManSwitch {
    /// Last epoch when a valid nullifier was received
    pub last_checkin_epoch: u64,
    /// How many missed epochs trigger recovery
    pub threshold_epochs: u64,
    /// Registration commitment (for verifying identity)
    pub registration: [u8; 32],
}

impl DeadManSwitch {
    /// Create new dead man's switch
    pub fn new(nullifier_secret: &[u8; 32], threshold_epochs: u64) -> Self {
        Self {
            last_checkin_epoch: current_epoch(),
            threshold_epochs,
            registration: Nullifier::registration_commitment(nullifier_secret),
        }
    }

    /// Create with default threshold (4 weeks)
    pub fn with_defaults(nullifier_secret: &[u8; 32]) -> Self {
        Self::new(nullifier_secret, DEFAULT_DEAD_MAN_THRESHOLD)
    }

    /// Process a check-in (verify nullifier and update state)
    ///
    /// Returns true if the nullifier is valid for the current epoch
    pub fn checkin(&mut self, nullifier: &Nullifier, secret: &[u8; 32]) -> bool {
        let epoch = current_epoch();
        let expected = Nullifier::derive(secret, epoch);

        if nullifier == &expected {
            // Also verify registration matches
            let reg = Nullifier::registration_commitment(secret);
            if reg == self.registration {
                self.last_checkin_epoch = epoch;
                return true;
            }
        }

        false
    }

    /// Check if dead man's switch has triggered
    pub fn is_triggered(&self) -> bool {
        let current = current_epoch();
        current.saturating_sub(self.last_checkin_epoch) > self.threshold_epochs
    }

    /// Get number of epochs remaining before trigger
    pub fn epochs_remaining(&self) -> u64 {
        let current = current_epoch();
        let elapsed = current.saturating_sub(self.last_checkin_epoch);

        if elapsed >= self.threshold_epochs {
            0
        } else {
            self.threshold_epochs - elapsed
        }
    }

    /// Get seconds remaining before trigger
    pub fn seconds_remaining(&self) -> u64 {
        self.epochs_remaining() * EPOCH_DURATION_SECS
    }

    /// Check if check-in is due (current epoch > last check-in epoch)
    pub fn checkin_due(&self) -> bool {
        current_epoch() > self.last_checkin_epoch
    }
}

/// Signed nullifier for broadcast
///
/// Includes Ed25519 signature to prevent replay attacks.
#[derive(Clone)]
pub struct SignedNullifier {
    /// The nullifier value
    pub nullifier: Nullifier,
    /// Epoch this nullifier is for
    pub epoch: u64,
    /// Ed25519 signature over (nullifier || epoch)
    pub signature: [u8; 64],
    /// Signing public key (for verification)
    pub signing_key: [u8; 32],
}

impl SignedNullifier {
    /// Serialized size
    pub const SERIALIZED_SIZE: usize = 32 + 8 + 64 + 32; // 136 bytes

    /// Create signed nullifier
    pub fn new(
        nullifier_secret: &[u8; 32],
        signing_key: &[u8; 32],
        sign_fn: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Self {
        let epoch = current_epoch();
        let nullifier = Nullifier::derive(nullifier_secret, epoch);

        // Message to sign
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(nullifier.as_bytes());
        message.extend_from_slice(&epoch.to_le_bytes());

        let signature = sign_fn(&message);

        Self {
            nullifier,
            epoch,
            signature,
            signing_key: *signing_key,
        }
    }

    /// Verify signature (caller provides verification function)
    pub fn verify(&self, verify_fn: impl FnOnce(&[u8; 32], &[u8], &[u8; 64]) -> bool) -> bool {
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(self.nullifier.as_bytes());
        message.extend_from_slice(&self.epoch.to_le_bytes());

        verify_fn(&self.signing_key, &message, &self.signature)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut bytes = [0u8; Self::SERIALIZED_SIZE];
        bytes[0..32].copy_from_slice(self.nullifier.as_bytes());
        bytes[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[40..104].copy_from_slice(&self.signature);
        bytes[104..136].copy_from_slice(&self.signing_key);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; Self::SERIALIZED_SIZE]) -> Self {
        let mut nullifier_bytes = [0u8; 32];
        nullifier_bytes.copy_from_slice(&bytes[0..32]);

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[32..40]);
        let epoch = u64::from_le_bytes(epoch_bytes);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[40..104]);

        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&bytes[104..136]);

        Self {
            nullifier: Nullifier(nullifier_bytes),
            epoch,
            signature,
            signing_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_derivation() {
        let secret = [42u8; 32];

        let nf1 = Nullifier::derive(&secret, 1000);
        let nf2 = Nullifier::derive(&secret, 1001);
        let nf1_again = Nullifier::derive(&secret, 1000);

        // Same (secret, epoch) produces same nullifier
        assert_eq!(nf1, nf1_again);

        // Different epochs produce different nullifiers
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_unlinkability() {
        let secret = [42u8; 32];

        // Generate nullifiers for consecutive epochs
        let nullifiers: Vec<_> = (1000..1010)
            .map(|epoch| Nullifier::derive(&secret, epoch))
            .collect();

        // All should be unique
        for i in 0..nullifiers.len() {
            for j in (i + 1)..nullifiers.len() {
                assert_ne!(nullifiers[i], nullifiers[j]);
            }
        }
    }

    #[test]
    fn test_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let nf1 = Nullifier::derive(&secret1, 1000);
        let nf2 = Nullifier::derive(&secret2, 1000);

        // Different secrets produce different nullifiers
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_registration_commitment() {
        let secret = [42u8; 32];

        let reg1 = Nullifier::registration_commitment(&secret);
        let reg2 = Nullifier::registration_commitment(&secret);

        // Same secret produces same registration
        assert_eq!(reg1, reg2);

        // Different secret produces different registration
        let secret2 = [43u8; 32];
        let reg3 = Nullifier::registration_commitment(&secret2);
        assert_ne!(reg1, reg3);
    }

    #[test]
    fn test_dead_man_switch() {
        let secret = [42u8; 32];
        let mut switch = DeadManSwitch::new(&secret, 4);

        // Initially not triggered
        assert!(!switch.is_triggered());
        assert_eq!(switch.epochs_remaining(), 4);

        // Check-in should work
        let nf = Nullifier::derive_current(&secret);
        assert!(switch.checkin(&nf, &secret));

        // Wrong secret should fail
        let wrong_secret = [0u8; 32];
        let wrong_nf = Nullifier::derive_current(&wrong_secret);
        assert!(!switch.checkin(&wrong_nf, &wrong_secret));
    }

    #[test]
    fn test_epoch_calculations() {
        let epoch = 1000u64;
        let start = epoch_start(epoch);
        let recovered_epoch = epoch_at(start);

        assert_eq!(epoch, recovered_epoch);

        // Timestamp within epoch maps to same epoch
        assert_eq!(epoch_at(start + 1000), epoch);
        assert_eq!(epoch_at(start + EPOCH_DURATION_SECS - 1), epoch);

        // Next second is next epoch
        assert_eq!(epoch_at(start + EPOCH_DURATION_SECS), epoch + 1);
    }

    #[test]
    fn test_signed_nullifier_serialization() {
        let secret = [42u8; 32];
        let signing_key = [1u8; 32];

        let signed = SignedNullifier::new(&secret, &signing_key, |_msg| [0u8; 64]);

        let bytes = signed.to_bytes();
        let recovered = SignedNullifier::from_bytes(&bytes);

        assert_eq!(signed.nullifier, recovered.nullifier);
        assert_eq!(signed.epoch, recovered.epoch);
        assert_eq!(signed.signature, recovered.signature);
        assert_eq!(signed.signing_key, recovered.signing_key);
    }
}
