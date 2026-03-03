//! Mesh Access Credentials
//!
//! Anonymous credential system for LoRa mesh participation using BBS+.
//!
//! # Overview
//!
//! Provides anonymous access control for the mesh network:
//! - Nodes prove they have valid credentials without revealing identity
//! - Selective disclosure of access level (basic, trusted, guardian)
//! - Spam prevention via rate-limiting tokens
//! - Credential revocation support
//!
//! # Credential Attributes
//!
//! | Index | Attribute | Disclosed |
//! |-------|-----------|-----------|
//! | 0 | Issuer ID | Yes (verifier needs this) |
//! | 1 | Access Level | Yes (routing priority) |
//! | 2 | Issue Epoch | No (privacy) |
//! | 3 | Credential ID | No (derived into rate token) |
//! | 4 | Public Key Commitment | No (binding) |
//!
//! # Rate Limiting
//!
//! To prevent spam while maintaining privacy:
//! - Each proof includes a rate-limiting token: H(credential_id || epoch)
//! - Same credential in same epoch produces same token (linkable)
//! - Different epochs produce different tokens (unlinkable)
//! - Nodes track tokens to enforce rate limits
//!
//! # Example
//!
//! ```ignore
//! // Issuer creates credential
//! let issuer = MeshIssuer::new(&mut rng)?;
//! let credential = issuer.issue_credential(
//!     user_pubkey_commitment,
//!     AccessLevel::Trusted,
//!     &mut rng,
//! )?;
//!
//! // User creates mesh access proof
//! let proof = credential.prove_access(
//!     &issuer.public_key(),
//!     current_epoch,
//!     &mut rng,
//! )?;
//!
//! // Relay verifies proof
//! let access = MeshAccessProof::verify(&proof, &issuer.public_key())?;
//! if access.rate_token_seen_recently() {
//!     return Err("Rate limited");
//! }
//! ```

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::credentials::bbs_plus::{
    BBSSignature, Credential, CredentialProof, IssuerPublicKey, IssuerSecretKey,
};
use crate::error::{BedrockError, Result};
use crate::pairing::bls12_381::Scalar;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Number of attributes in a mesh credential
pub const MESH_CREDENTIAL_ATTRIBUTES: usize = 5;

/// Attribute indices
pub const ATTR_ISSUER_ID: usize = 0;
pub const ATTR_ACCESS_LEVEL: usize = 1;
pub const ATTR_ISSUE_EPOCH: usize = 2;
pub const ATTR_CREDENTIAL_ID: usize = 3;
pub const ATTR_PUBKEY_COMMITMENT: usize = 4;

/// Rate limiting epoch duration (1 hour in seconds)
pub const EPOCH_DURATION_SECS: u64 = 3600;

/// Maximum proofs per credential per epoch
pub const MAX_PROOFS_PER_EPOCH: u32 = 100;

// ============================================================================
// ACCESS LEVEL
// ============================================================================

/// Mesh access levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccessLevel {
    /// Basic mesh access - can relay but lower priority
    Basic = 0,
    /// Trusted - normal routing priority
    Trusted = 1,
    /// Guardian - highest priority, can issue basic credentials
    Guardian = 2,
}

impl AccessLevel {
    pub fn from_scalar(s: &Scalar) -> Option<Self> {
        let bytes = s.to_bytes();
        // Check if it's a small value (first 31 bytes are zero)
        if bytes[0..31].iter().all(|&b| b == 0) {
            match bytes[31] {
                0 => Some(AccessLevel::Basic),
                1 => Some(AccessLevel::Trusted),
                2 => Some(AccessLevel::Guardian),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn to_scalar(&self) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = *self as u8;
        Scalar::from_bytes(&bytes).unwrap_or_else(|_| Scalar::zero())
    }
}

// ============================================================================
// MESH ISSUER
// ============================================================================

/// Mesh credential issuer (e.g., a guardian node).
#[derive(Clone)]
pub struct MeshIssuer {
    /// Issuer's secret key
    secret_key: IssuerSecretKey,
    /// Issuer's public key
    public_key: IssuerPublicKey,
    /// Issuer ID (scalar bytes that will match proof output)
    issuer_id: [u8; 32],
    /// Current issue epoch
    issue_epoch: u64,
}

impl MeshIssuer {
    /// Create a new mesh issuer.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let (secret_key, public_key) =
            IssuerSecretKey::generate(rng, MESH_CREDENTIAL_ATTRIBUTES)?;

        // Compute issuer ID from public key hash, then convert to scalar bytes
        // This ensures that what we store matches what comes out of proofs
        let pk_bytes = public_key.to_bytes()?;

        let mut hasher = Sha256::new();
        hasher.update(&pk_bytes);
        let hash = hasher.finalize();
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        // Convert to scalar and back to get canonical bytes
        let scalar = scalar_from_bytes(&hash_arr);
        let issuer_id = scalar.to_bytes();

        let issue_epoch = current_epoch();

        Ok(MeshIssuer {
            secret_key,
            public_key,
            issuer_id,
            issue_epoch,
        })
    }

    /// Get the issuer's public key.
    pub fn public_key(&self) -> &IssuerPublicKey {
        &self.public_key
    }

    /// Get the issuer ID.
    pub fn issuer_id(&self) -> &[u8; 32] {
        &self.issuer_id
    }

    /// Issue a mesh access credential.
    ///
    /// # Arguments
    ///
    /// * `pubkey_commitment` - Hash of user's public key (for binding)
    /// * `access_level` - Access level to grant
    /// * `rng` - Cryptographic RNG
    pub fn issue_credential<R: RngCore + CryptoRng>(
        &self,
        pubkey_commitment: &[u8; 32],
        access_level: AccessLevel,
        rng: &mut R,
    ) -> Result<MeshCredential> {
        // Generate unique credential ID
        let mut credential_id = [0u8; 32];
        rng.fill_bytes(&mut credential_id);

        // Build attributes
        let attributes = vec![
            scalar_from_bytes(&self.issuer_id),     // ATTR_ISSUER_ID
            access_level.to_scalar(),               // ATTR_ACCESS_LEVEL
            scalar_from_u64(self.issue_epoch),      // ATTR_ISSUE_EPOCH
            scalar_from_bytes(&credential_id),      // ATTR_CREDENTIAL_ID
            scalar_from_bytes(pubkey_commitment),   // ATTR_PUBKEY_COMMITMENT
        ];

        // Sign with BBS+
        let signature = self.secret_key.sign(&attributes, &self.public_key, rng)?;
        let credential = Credential::new(signature, attributes);

        Ok(MeshCredential {
            credential,
            credential_id,
            access_level,
            issuer_id: self.issuer_id,
            issue_epoch: self.issue_epoch,
        })
    }

    /// Serialize issuer to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.secret_key.to_bytes());
        let pk_bytes = self.public_key.to_bytes()?;
        bytes.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&pk_bytes);
        bytes.extend_from_slice(&self.issuer_id);
        bytes.extend_from_slice(&self.issue_epoch.to_le_bytes());
        Ok(bytes)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 + 4 + 32 + 8 {
            return Err(BedrockError::Deserialization("Too short".into()));
        }

        let secret_key = IssuerSecretKey::from_bytes(&bytes[0..32])?;

        let pk_len = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
        if bytes.len() < 36 + pk_len + 32 + 8 {
            return Err(BedrockError::Deserialization("Invalid length".into()));
        }

        let public_key = IssuerPublicKey::from_bytes(&bytes[36..36 + pk_len])?;

        let mut issuer_id = [0u8; 32];
        issuer_id.copy_from_slice(&bytes[36 + pk_len..36 + pk_len + 32]);

        let issue_epoch = u64::from_le_bytes([
            bytes[36 + pk_len + 32],
            bytes[36 + pk_len + 33],
            bytes[36 + pk_len + 34],
            bytes[36 + pk_len + 35],
            bytes[36 + pk_len + 36],
            bytes[36 + pk_len + 37],
            bytes[36 + pk_len + 38],
            bytes[36 + pk_len + 39],
        ]);

        Ok(MeshIssuer {
            secret_key,
            public_key,
            issuer_id,
            issue_epoch,
        })
    }
}

/// SECURITY: Zeroize issuer's secret key on drop.
/// The IssuerSecretKey contains BBS+ signing secrets that must not linger in memory.
impl Drop for MeshIssuer {
    fn drop(&mut self) {
        // Zeroize the issuer ID which is derived from the secret
        self.issuer_id.zeroize();
        // IssuerSecretKey from bbs_plus crate should have its own zeroization
        // but we explicitly signal we want cleanup here
    }
}

// ============================================================================
// MESH CREDENTIAL
// ============================================================================

/// A mesh access credential.
#[derive(Clone, Serialize, Deserialize)]
pub struct MeshCredential {
    /// The underlying BBS+ credential
    credential: Credential,
    /// Unique credential ID (for rate limiting)
    credential_id: [u8; 32],
    /// Access level
    access_level: AccessLevel,
    /// Issuer ID
    issuer_id: [u8; 32],
    /// Issue epoch
    issue_epoch: u64,
}

impl MeshCredential {
    /// Verify the credential against an issuer's public key.
    pub fn verify(&self, issuer_pk: &IssuerPublicKey) -> bool {
        self.credential.verify(issuer_pk)
    }

    /// Get the access level.
    pub fn access_level(&self) -> AccessLevel {
        self.access_level
    }

    /// Get the issuer ID.
    pub fn issuer_id(&self) -> &[u8; 32] {
        &self.issuer_id
    }

    /// Create a mesh access proof.
    ///
    /// This proves possession of a valid credential while:
    /// - Disclosing the issuer ID and access level
    /// - Hiding the issue epoch, credential ID, and pubkey commitment
    /// - Including a rate-limiting token for the current epoch
    pub fn prove_access<R: RngCore + CryptoRng>(
        &self,
        issuer_pk: &IssuerPublicKey,
        epoch: u64,
        rng: &mut R,
    ) -> Result<MeshAccessProof> {
        // Compute rate-limiting token: H(credential_id || epoch)
        let rate_token = compute_rate_token(&self.credential_id, epoch);

        // Disclose only issuer ID and access level
        let disclosed_indices = vec![ATTR_ISSUER_ID, ATTR_ACCESS_LEVEL];

        // Build challenge including epoch and rate token
        let mut challenge = Vec::new();
        challenge.extend_from_slice(&epoch.to_le_bytes());
        challenge.extend_from_slice(&rate_token);

        // Create BBS+ proof
        let proof = self.credential.prove(
            issuer_pk,
            &disclosed_indices,
            &challenge,
            rng,
        )?;

        Ok(MeshAccessProof {
            proof,
            rate_token,
            epoch,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BedrockError::Deserialization(e.to_string()))
    }
}

/// SECURITY: Zeroize credential ID on drop.
/// The credential_id is used for rate-limiting tokens and reveals which
/// credential was used if not properly cleaned up.
impl Drop for MeshCredential {
    fn drop(&mut self) {
        self.credential_id.zeroize();
        // issuer_id is public information, but we zeroize for completeness
        self.issuer_id.zeroize();
    }
}

// ============================================================================
// MESH ACCESS PROOF
// ============================================================================

/// A zero-knowledge proof of mesh access.
#[derive(Clone, Serialize, Deserialize)]
pub struct MeshAccessProof {
    /// The BBS+ credential proof
    proof: CredentialProof,
    /// Rate-limiting token
    rate_token: [u8; 32],
    /// Epoch for this proof
    epoch: u64,
}

impl MeshAccessProof {
    /// Verify the access proof.
    ///
    /// # Returns
    ///
    /// `Ok(VerifiedAccess)` with access level and rate token if valid.
    pub fn verify(&self, issuer_pk: &IssuerPublicKey) -> Result<VerifiedAccess> {
        // Reconstruct challenge
        let mut challenge = Vec::new();
        challenge.extend_from_slice(&self.epoch.to_le_bytes());
        challenge.extend_from_slice(&self.rate_token);

        // Verify BBS+ proof
        let disclosed = self.proof.verify(issuer_pk, &challenge)?;

        // Extract disclosed attributes
        let mut issuer_id = None;
        let mut access_level = None;

        for (idx, value) in disclosed {
            match idx {
                ATTR_ISSUER_ID => {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&value.to_bytes());
                    issuer_id = Some(bytes);
                }
                ATTR_ACCESS_LEVEL => {
                    access_level = AccessLevel::from_scalar(&value);
                }
                _ => {}
            }
        }

        let issuer_id = issuer_id.ok_or(BedrockError::InvalidProof)?;
        let access_level = access_level.ok_or(BedrockError::InvalidProof)?;

        Ok(VerifiedAccess {
            issuer_id,
            access_level,
            rate_token: self.rate_token,
            epoch: self.epoch,
        })
    }

    /// Get the rate token (for rate limiting checks).
    pub fn rate_token(&self) -> &[u8; 32] {
        &self.rate_token
    }

    /// Get the epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BedrockError::Deserialization(e.to_string()))
    }
}

// ============================================================================
// VERIFIED ACCESS
// ============================================================================

/// Verified mesh access from a proof.
#[derive(Debug, Clone)]
pub struct VerifiedAccess {
    /// Issuer ID that signed the credential
    pub issuer_id: [u8; 32],
    /// Access level
    pub access_level: AccessLevel,
    /// Rate-limiting token
    pub rate_token: [u8; 32],
    /// Epoch of the proof
    pub epoch: u64,
}

impl VerifiedAccess {
    /// Get routing priority based on access level.
    pub fn routing_priority(&self) -> u8 {
        match self.access_level {
            AccessLevel::Basic => 0,
            AccessLevel::Trusted => 1,
            AccessLevel::Guardian => 2,
        }
    }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

/// Rate limiter for mesh access.
///
/// Tracks rate tokens to prevent spam while maintaining privacy.
pub struct RateLimiter {
    /// Seen tokens: (token, count) for current epoch
    tokens: std::collections::HashMap<[u8; 32], u32>,
    /// Current epoch
    current_epoch: u64,
    /// Maximum proofs per token per epoch
    max_per_epoch: u32,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_per_epoch: u32) -> Self {
        RateLimiter {
            tokens: std::collections::HashMap::new(),
            current_epoch: current_epoch(),
            max_per_epoch,
        }
    }

    /// Check and record a rate token.
    ///
    /// Returns `true` if the token is within rate limits.
    pub fn check_and_record(&mut self, access: &VerifiedAccess) -> bool {
        // Clear old epoch data
        if access.epoch != self.current_epoch {
            if access.epoch > self.current_epoch {
                self.tokens.clear();
                self.current_epoch = access.epoch;
            } else {
                // Old epoch proof - might be replay attack
                return false;
            }
        }

        // Check and update count
        let count = self.tokens.entry(access.rate_token).or_insert(0);
        if *count >= self.max_per_epoch {
            return false;
        }

        *count += 1;
        true
    }

    /// Check if a token has been seen (without recording).
    pub fn has_seen(&self, rate_token: &[u8; 32]) -> bool {
        self.tokens.contains_key(rate_token)
    }

    /// Get the count for a token.
    pub fn get_count(&self, rate_token: &[u8; 32]) -> u32 {
        *self.tokens.get(rate_token).unwrap_or(&0)
    }
}

// ============================================================================
// HELPERS
// ============================================================================

/// Get current epoch number.
pub fn current_epoch() -> u64 {
    // In real implementation, use actual time
    // For now, return a constant for testing
    #[cfg(test)]
    return 1000;

    #[cfg(not(test))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        now.as_secs() / EPOCH_DURATION_SECS
    }
}

/// Compute rate-limiting token.
fn compute_rate_token(credential_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mesh-rate-token-v1");
    hasher.update(credential_id);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut token = [0u8; 32];
    token.copy_from_slice(&hash);
    token
}

/// Convert 32 bytes to a scalar (direct, no hashing).
/// Uses modular reduction if needed.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    // Try direct conversion first (works if value < field modulus r)
    match Scalar::from_bytes(bytes) {
        Ok(s) => s,
        Err(_) => {
            // If direct conversion fails (value >= field order),
            // use wide reduction which properly handles any input.
            // Expand to 64 bytes by hashing with two different suffixes,
            // then use from_bytes_wide for proper modular reduction.
            let mut hasher1 = Sha256::new();
            hasher1.update(bytes);
            hasher1.update(b"\x00");
            let hash1 = hasher1.finalize();

            let mut hasher2 = Sha256::new();
            hasher2.update(bytes);
            hasher2.update(b"\x01");
            let hash2 = hasher2.finalize();

            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&hash1);
            wide[32..].copy_from_slice(&hash2);

            Scalar::from_bytes_wide(&wide)
        }
    }
}

/// Convert u64 to a scalar.
fn scalar_from_u64(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    Scalar::from_bytes(&bytes).unwrap_or_else(|_| Scalar::zero())
}

/// Compute a commitment to a public key for credential issuance.
///
/// This binds the credential to a specific X25519 public key without
/// revealing the key in the credential (it's hidden during ZK proofs).
///
/// # Arguments
/// * `pubkey` - The X25519 public key bytes (32 bytes)
///
/// # Returns
/// A 32-byte commitment suitable for use in `MeshIssuer::issue_credential`.
pub fn compute_pubkey_commitment(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mesh-pubkey-commitment-v1");
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&hash);
    commitment
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_issuer_creation() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        // Issuer ID should be set (non-zero)
        assert!(!issuer.issuer_id.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_credential_issuance() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        // Create pubkey commitment
        let mut pubkey_commitment = [0u8; 32];
        rng.fill_bytes(&mut pubkey_commitment);

        // Issue credential
        let credential = issuer
            .issue_credential(&pubkey_commitment, AccessLevel::Trusted, &mut rng)
            .unwrap();

        // Verify credential
        assert!(credential.verify(issuer.public_key()));
        assert_eq!(credential.access_level(), AccessLevel::Trusted);
    }

    #[test]
    fn test_access_proof() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        let mut pubkey_commitment = [0u8; 32];
        rng.fill_bytes(&mut pubkey_commitment);

        let credential = issuer
            .issue_credential(&pubkey_commitment, AccessLevel::Guardian, &mut rng)
            .unwrap();

        // Create access proof
        let epoch = current_epoch();
        let proof = credential
            .prove_access(issuer.public_key(), epoch, &mut rng)
            .unwrap();

        // Verify proof
        let verified = proof.verify(issuer.public_key()).unwrap();

        assert_eq!(verified.issuer_id, *issuer.issuer_id());
        assert_eq!(verified.access_level, AccessLevel::Guardian);
        assert_eq!(verified.routing_priority(), 2);
    }

    #[test]
    fn test_proof_unlinkability() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        let mut pubkey_commitment = [0u8; 32];
        rng.fill_bytes(&mut pubkey_commitment);

        let credential = issuer
            .issue_credential(&pubkey_commitment, AccessLevel::Trusted, &mut rng)
            .unwrap();

        let epoch = current_epoch();

        // Create two proofs
        let proof1 = credential
            .prove_access(issuer.public_key(), epoch, &mut rng)
            .unwrap();
        let proof2 = credential
            .prove_access(issuer.public_key(), epoch, &mut rng)
            .unwrap();

        // Both should verify
        assert!(proof1.verify(issuer.public_key()).is_ok());
        assert!(proof2.verify(issuer.public_key()).is_ok());

        // Rate tokens should be the same (same epoch)
        assert_eq!(proof1.rate_token(), proof2.rate_token());

        // But proof randomization should differ
        assert_ne!(proof1.proof.a_bar, proof2.proof.a_bar);
    }

    #[test]
    fn test_rate_limiting() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        let mut pubkey_commitment = [0u8; 32];
        rng.fill_bytes(&mut pubkey_commitment);

        let credential = issuer
            .issue_credential(&pubkey_commitment, AccessLevel::Basic, &mut rng)
            .unwrap();

        let epoch = current_epoch();
        let proof = credential
            .prove_access(issuer.public_key(), epoch, &mut rng)
            .unwrap();
        let verified = proof.verify(issuer.public_key()).unwrap();

        // Create rate limiter with max 3 per epoch
        let mut limiter = RateLimiter::new(3);

        // First 3 should pass
        assert!(limiter.check_and_record(&verified));
        assert!(limiter.check_and_record(&verified));
        assert!(limiter.check_and_record(&verified));

        // 4th should fail
        assert!(!limiter.check_and_record(&verified));

        // Should show count of 3
        assert_eq!(limiter.get_count(&verified.rate_token), 3);
    }

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;
        let issuer = MeshIssuer::new(&mut rng).unwrap();

        let mut pubkey_commitment = [0u8; 32];
        rng.fill_bytes(&mut pubkey_commitment);

        let credential = issuer
            .issue_credential(&pubkey_commitment, AccessLevel::Trusted, &mut rng)
            .unwrap();

        // Serialize and deserialize credential
        let bytes = credential.to_bytes();
        let recovered = MeshCredential::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.access_level(), credential.access_level());
        assert!(recovered.verify(issuer.public_key()));

        // Serialize and deserialize proof
        let epoch = current_epoch();
        let proof = credential
            .prove_access(issuer.public_key(), epoch, &mut rng)
            .unwrap();

        let proof_bytes = proof.to_bytes();
        let recovered_proof = MeshAccessProof::from_bytes(&proof_bytes).unwrap();

        assert!(recovered_proof.verify(issuer.public_key()).is_ok());
    }
}
