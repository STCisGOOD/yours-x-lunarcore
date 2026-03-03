//! Anonymous Distributed Recovery Protocol
//!
//! Implements the ZKP-based recovery system where:
//! 1. Identity seed is split using Shamir (4-of-7)
//! 2. Each share is committed with Pedersen commitments
//! 3. Shares are distributed to anonymous mesh nodes
//! 4. Recovery requires proving knowledge of blinding factors (from passphrase)
//!
//! Key Hierarchy:
//! ```text
//! passphrase
//!     │
//!     ├──▶ recovery_seed = Argon2id(passphrase, "Yours/recovery/v1")
//!     │        ├──▶ identity_seed (what's split into shares)
//!     │        ├──▶ nullifier_secret
//!     │        ├──▶ blinding_seed
//!     │        ├──▶ node_seed
//!     │        └──▶ share_enc_key
//!     │
//!     └──▶ device_seed = Argon2id(passphrase, device_salt)
//!              └──▶ local_master_key (encrypts identity on device)
//! ```
//!
//! Security Model:
//! - Anonymous nodes: Don't know whose data they hold
//! - Powers of Tau-inspired: Security holds if ANY ONE node is honest
//! - Global adversary resistant: No social graph exposure

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::pedersen::{hash_to_scalar, BlindingCommitment, Commitment, PedersenParams};
use crate::schnorr::BlindingProof;

/// Total number of shares to create
pub const TOTAL_SHARES: usize = 7;

/// Minimum shares needed to reconstruct
pub const THRESHOLD: usize = 4;

/// Dead man's switch threshold in epochs (weeks)
pub const DEAD_MAN_EPOCHS: u64 = 4;

/// Recovery delay for anti-coercion (72 hours)
pub const RECOVERY_DELAY_SECS: u64 = 72 * 60 * 60;

/// A share package ready for distribution to a mesh node
#[derive(Clone)]
pub struct SharePackage {
    /// Pedersen commitment to share value: C = g^s · h^r
    pub share_commitment: Commitment,
    /// Commitment to blinding factor: R = h^r
    pub blinding_commitment: BlindingCommitment,
    /// Encrypted share (ChaCha20-Poly1305)
    pub encrypted_share: Vec<u8>,
    /// Target node identifier (derived deterministically)
    pub node_id: [u8; 16],
    /// Share index (for Shamir reconstruction)
    pub index: u8,
}

impl SharePackage {
    /// Serialize for transmission/storage
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 32 + 4 + self.encrypted_share.len() + 16 + 1);

        bytes.extend_from_slice(&self.share_commitment.to_bytes());
        bytes.extend_from_slice(&self.blinding_commitment.to_bytes());
        bytes.extend_from_slice(&(self.encrypted_share.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_share);
        bytes.extend_from_slice(&self.node_id);
        bytes.push(self.index);

        bytes
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 + 32 + 4 + 16 + 1 {
            return None;
        }

        let mut offset = 0;

        // Share commitment
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&bytes[offset..offset + 32]);
        let share_commitment = Commitment::from_bytes(&c_bytes)?;
        offset += 32;

        // Blinding commitment
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[offset..offset + 32]);
        let blinding_commitment = BlindingCommitment::from_bytes(&r_bytes)?;
        offset += 32;

        // Encrypted share length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let enc_len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;

        if bytes.len() < offset + enc_len + 16 + 1 {
            return None;
        }

        // Encrypted share
        let encrypted_share = bytes[offset..offset + enc_len].to_vec();
        offset += enc_len;

        // Node ID
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;

        // Index
        let index = bytes[offset];

        Some(Self {
            share_commitment,
            blinding_commitment,
            encrypted_share,
            node_id,
            index,
        })
    }
}

/// Recovery secrets derived from passphrase
///
/// These are used both at setup and recovery time.
/// Derived deterministically from passphrase, so they can be
/// recomputed on a new device with just the passphrase.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RecoverySecrets {
    /// The identity seed (what gets split into shares)
    pub identity_seed: [u8; 32],
    /// Secret for nullifier derivation
    pub nullifier_secret: [u8; 32],
    /// Seed for deriving blinding factors
    pub blinding_seed: [u8; 32],
    /// Seed for deriving node locations
    pub node_seed: [u8; 32],
    /// Key for encrypting shares
    pub share_enc_key: [u8; 32],
}

impl RecoverySecrets {
    /// Derive all recovery secrets from passphrase
    ///
    /// Uses fixed salt "Yours/recovery/v1" so secrets can be
    /// recovered with passphrase alone (no device-specific data).
    pub fn derive(passphrase: &[u8]) -> Self {
        // Use Argon2id to derive recovery_seed from passphrase
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            // 256MB memory, 4 iterations, 2 threads - strong parameters
            argon2::Params::new(256 * 1024, 4, 2, Some(64)).unwrap(),
        );

        let mut recovery_seed = [0u8; 64];
        argon2
            .hash_password_into(passphrase, b"Yours/recovery/v1", &mut recovery_seed)
            .expect("Argon2 failed");

        // Derive sub-keys using HKDF
        let mut identity_seed = [0u8; 32];
        let mut nullifier_secret = [0u8; 32];
        let mut blinding_seed = [0u8; 32];
        let mut node_seed = [0u8; 32];
        let mut share_enc_key = [0u8; 32];

        let hk = Hkdf::<Sha3_256>::new(None, &recovery_seed);
        hk.expand(b"Yours/identity/v1", &mut identity_seed).unwrap();
        hk.expand(b"Yours/nullifier/v1", &mut nullifier_secret).unwrap();
        hk.expand(b"Yours/blinding/v1", &mut blinding_seed).unwrap();
        hk.expand(b"Yours/nodes/v1", &mut node_seed).unwrap();
        hk.expand(b"Yours/share_enc/v1", &mut share_enc_key).unwrap();

        recovery_seed.zeroize();

        Self {
            identity_seed,
            nullifier_secret,
            blinding_seed,
            node_seed,
            share_enc_key,
        }
    }

    /// Derive blinding factor for a specific share index
    pub fn derive_blinding(&self, index: u8) -> Scalar {
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&self.blinding_seed);
        input[32] = index;
        hash_to_scalar(&input)
    }

    /// Derive node ID for a specific share index
    pub fn derive_node_id(&self, index: u8) -> [u8; 16] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/node_id/v1");
        hasher.update(&self.node_seed);
        hasher.update(&[index]);

        let hash = hasher.finalize();
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&hash[..16]);
        node_id
    }

    /// Derive encryption key for a specific share
    pub fn derive_share_key(&self, node_id: &[u8; 16]) -> [u8; 32] {
        let hk = Hkdf::<Sha3_256>::new(Some(node_id), &self.share_enc_key);
        let mut key = [0u8; 32];
        hk.expand(b"Yours/share_key/v1", &mut key).unwrap();
        key
    }
}

/// Set up recovery system for an identity
///
/// Returns share packages ready for distribution to mesh nodes.
pub fn setup_recovery(passphrase: &[u8]) -> Result<(RecoverySecrets, Vec<SharePackage>), &'static str> {
    let secrets = RecoverySecrets::derive(passphrase);
    let params = PedersenParams::new();

    // Split identity_seed using Shamir (from lib.rs)
    let shares = crate::shamir_split_internal(&secrets.identity_seed, TOTAL_SHARES, THRESHOLD)?;

    let mut packages = Vec::with_capacity(TOTAL_SHARES);

    for share in shares {
        let index = share.x;

        // Derive blinding factor for this share
        let r = secrets.derive_blinding(index);

        // Convert share value to scalar (pad if needed)
        let s = share_to_scalar(&share.y);

        // Create commitments
        let share_commitment = params.commit(&s, &r);
        let blinding_commitment = params.commit_blinding(&r);

        // Derive node ID
        let node_id = secrets.derive_node_id(index);

        // Encrypt share
        let share_key = secrets.derive_share_key(&node_id);
        let encrypted_share = encrypt_share(&share_key, &share, &share_commitment, &blinding_commitment)?;

        packages.push(SharePackage {
            share_commitment,
            blinding_commitment,
            encrypted_share,
            node_id,
            index,
        });
    }

    Ok((secrets, packages))
}

/// Create proof to retrieve a share from a node
///
/// Returns the expected blinding commitment and proof of knowledge.
pub fn create_retrieval_proof(
    secrets: &RecoverySecrets,
    index: u8,
    context: &[u8],
) -> (BlindingCommitment, BlindingProof) {
    let params = PedersenParams::new();

    // Derive expected blinding factor
    let r = secrets.derive_blinding(index);

    // Compute blinding commitment
    let blinding_commitment = params.commit_blinding(&r);

    // Create proof of knowledge
    let proof = BlindingProof::prove(&params, &r, &blinding_commitment, context);

    (blinding_commitment, proof)
}

/// Verify retrieval proof (for mesh nodes)
pub fn verify_retrieval_proof(
    stored_commitment: &BlindingCommitment,
    claimed_commitment: &BlindingCommitment,
    proof: &BlindingProof,
    context: &[u8],
) -> bool {
    // Commitments must match
    if stored_commitment != claimed_commitment {
        return false;
    }

    let params = PedersenParams::new();
    proof.verify(&params, claimed_commitment, context)
}

/// Decrypt a retrieved share
pub fn decrypt_share(
    secrets: &RecoverySecrets,
    package: &SharePackage,
) -> Result<ShamirShare, &'static str> {
    let share_key = secrets.derive_share_key(&package.node_id);

    let decrypted = decrypt_share_internal(
        &share_key,
        &package.encrypted_share,
        &package.share_commitment,
        &package.blinding_commitment,
    )?;

    Ok(decrypted)
}

/// Reconstruct identity seed from shares
pub fn reconstruct_identity_seed(shares: &[ShamirShare]) -> Result<[u8; 32], &'static str> {
    if shares.len() < THRESHOLD {
        return Err("Not enough shares");
    }

    crate::shamir_combine_internal(&shares[..THRESHOLD])
}

/// Verify that reconstruction matches expected identity
pub fn verify_reconstruction(
    identity_seed: &[u8; 32],
    expected_signing_pk: &[u8; 32],
) -> bool {
    // Derive signing key from identity_seed
    let hk = Hkdf::<Sha3_256>::new(None, identity_seed);
    let mut signing_seed = [0u8; 32];
    hk.expand(b"Yours/ed25519/v1", &mut signing_seed).unwrap();

    // Generate keypair and check public key matches
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let derived_pk = signing_key.verifying_key().to_bytes();

    signing_seed.zeroize();

    derived_pk == *expected_signing_pk
}

// ============================================================================
// Internal types and functions
// ============================================================================

/// Shamir share (x, y) pair
#[derive(Clone)]
pub struct ShamirShare {
    pub x: u8,
    pub y: [u8; 32],
}

impl ShamirShare {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(self.x);
        bytes.extend_from_slice(&self.y);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 33 {
            return Err("Invalid share length");
        }

        let x = bytes[0];
        let mut y = [0u8; 32];
        y.copy_from_slice(&bytes[1..33]);

        Ok(Self { x, y })
    }
}

/// Convert share value to scalar
fn share_to_scalar(share_value: &[u8; 32]) -> Scalar {
    // Use wide reduction for uniform distribution
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(share_value);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive nonce from key and share index using HKDF
/// This ensures the full 12-byte nonce is derived, not just first byte.
fn derive_nonce(key: &[u8; 32], share_index: u8) -> [u8; 12] {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let hk = Hkdf::<Sha3_256>::new(Some(&[share_index]), key);
    let mut nonce = [0u8; 12];
    hk.expand(b"Yours/share_nonce/v1", &mut nonce).unwrap();
    nonce
}

/// Encrypt share with ChaCha20-Poly1305
fn encrypt_share(
    key: &[u8; 32],
    share: &ShamirShare,
    share_commitment: &Commitment,
    blinding_commitment: &BlindingCommitment,
) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    // Derive full nonce using HKDF instead of just setting first byte
    // The previous implementation only used the first byte, leaving 11 bytes as zeros.
    // This was a weak pattern that could enable attacks if key is ever reused.
    let nonce_bytes = derive_nonce(key, share.x);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD binds ciphertext to commitments
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&share_commitment.to_bytes());
    aad.extend_from_slice(&blinding_commitment.to_bytes());

    let plaintext = share.encode();
    cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| "Encryption failed")
}

/// Decrypt share with ChaCha20-Poly1305
fn decrypt_share_internal(
    key: &[u8; 32],
    ciphertext: &[u8],
    share_commitment: &Commitment,
    blinding_commitment: &BlindingCommitment,
) -> Result<ShamirShare, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    // We need to try all possible nonces (share indices 1-7)
    // This is okay because there are only 7 possibilities
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&share_commitment.to_bytes());
    aad.extend_from_slice(&blinding_commitment.to_bytes());

    for index in 1..=TOTAL_SHARES as u8 {
        // Use proper nonce derivation matching encrypt_share
        let nonce_bytes = derive_nonce(key, index);
        let nonce = Nonce::from_slice(&nonce_bytes);

        if let Ok(plaintext) = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &aad }) {
            if let Ok(share) = ShamirShare::decode(&plaintext) {
                if share.x == index {
                    return Ok(share);
                }
            }
        }
    }

    Err("Decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_secrets_derivation() {
        let passphrase = b"forest ember shadow river";

        let secrets1 = RecoverySecrets::derive(passphrase);
        let secrets2 = RecoverySecrets::derive(passphrase);

        // Same passphrase produces same secrets
        assert_eq!(secrets1.identity_seed, secrets2.identity_seed);
        assert_eq!(secrets1.blinding_seed, secrets2.blinding_seed);

        // Different passphrase produces different secrets
        let secrets3 = RecoverySecrets::derive(b"different words here now");
        assert_ne!(secrets1.identity_seed, secrets3.identity_seed);
    }

    #[test]
    fn test_blinding_derivation() {
        let secrets = RecoverySecrets::derive(b"test passphrase");

        // Same index produces same blinding
        let r1 = secrets.derive_blinding(1);
        let r2 = secrets.derive_blinding(1);
        assert_eq!(r1, r2);

        // Different indices produce different blindings
        let r3 = secrets.derive_blinding(2);
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_setup_and_retrieval_proof() {
        let passphrase = b"forest ember shadow river";
        let (secrets, packages) = setup_recovery(passphrase).unwrap();

        assert_eq!(packages.len(), TOTAL_SHARES);

        // Test retrieval proof for first share
        let context = b"node123|timestamp|request";
        let (commitment, proof) = create_retrieval_proof(&secrets, 1, context);

        // Verify proof against stored commitment
        assert!(verify_retrieval_proof(
            &packages[0].blinding_commitment,
            &commitment,
            &proof,
            context
        ));

        // Wrong context should fail
        assert!(!verify_retrieval_proof(
            &packages[0].blinding_commitment,
            &commitment,
            &proof,
            b"wrong context"
        ));
    }

    #[test]
    fn test_share_encryption_decryption() {
        let passphrase = b"forest ember shadow river";
        let (secrets, packages) = setup_recovery(passphrase).unwrap();

        // Decrypt each share
        for package in &packages {
            let share = decrypt_share(&secrets, package).unwrap();
            assert_eq!(share.x, package.index);
        }
    }

    #[test]
    fn test_full_recovery_flow() {
        let passphrase = b"forest ember shadow river";

        // Setup
        let (secrets, packages) = setup_recovery(passphrase).unwrap();
        let original_identity_seed = secrets.identity_seed;

        // Simulate recovery on new device
        let new_secrets = RecoverySecrets::derive(passphrase);

        // Retrieve and decrypt threshold shares
        let mut recovered_shares = Vec::new();
        for i in 0..THRESHOLD {
            let package = &packages[i];

            // Verify proof (simulating node verification)
            let context = format!("recover|{}", i);
            let (commitment, proof) = create_retrieval_proof(&new_secrets, package.index, context.as_bytes());

            assert!(verify_retrieval_proof(
                &package.blinding_commitment,
                &commitment,
                &proof,
                context.as_bytes()
            ));

            // Decrypt share
            let share = decrypt_share(&new_secrets, package).unwrap();
            recovered_shares.push(share);
        }

        // Reconstruct
        let reconstructed = reconstruct_identity_seed(&recovered_shares).unwrap();

        assert_eq!(reconstructed, original_identity_seed);
    }

    #[test]
    fn test_share_package_serialization() {
        let passphrase = b"test";
        let (_, packages) = setup_recovery(passphrase).unwrap();

        for package in packages {
            let bytes = package.serialize();
            let recovered = SharePackage::deserialize(&bytes).unwrap();

            assert_eq!(package.share_commitment, recovered.share_commitment);
            assert_eq!(package.blinding_commitment, recovered.blinding_commitment);
            assert_eq!(package.encrypted_share, recovered.encrypted_share);
            assert_eq!(package.node_id, recovered.node_id);
            assert_eq!(package.index, recovered.index);
        }
    }

    #[test]
    fn test_threshold_property() {
        let passphrase = b"forest ember shadow river";
        let (secrets, packages) = setup_recovery(passphrase).unwrap();

        // With exactly threshold shares, should work
        let mut shares = Vec::new();
        for i in 0..THRESHOLD {
            shares.push(decrypt_share(&secrets, &packages[i]).unwrap());
        }

        let result = reconstruct_identity_seed(&shares);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), secrets.identity_seed);

        // With fewer than threshold shares, should fail
        let result = reconstruct_identity_seed(&shares[..THRESHOLD - 1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_any_threshold_subset_works() {
        let passphrase = b"forest ember shadow river";
        let (secrets, packages) = setup_recovery(passphrase).unwrap();

        // Decrypt all shares
        let all_shares: Vec<_> = packages.iter()
            .map(|p| decrypt_share(&secrets, p).unwrap())
            .collect();

        // Try different subsets of threshold shares
        let subsets = vec![
            vec![0, 1, 2, 3],       // First 4
            vec![3, 4, 5, 6],       // Last 4
            vec![0, 2, 4, 6],       // Even indices
            vec![1, 2, 3, 4],       // Middle 4
        ];

        for indices in subsets {
            let subset: Vec<_> = indices.iter()
                .map(|&i| all_shares[i].clone())
                .collect();

            let result = reconstruct_identity_seed(&subset).unwrap();
            assert_eq!(result, secrets.identity_seed, "Failed for indices {:?}", indices);
        }
    }
}
