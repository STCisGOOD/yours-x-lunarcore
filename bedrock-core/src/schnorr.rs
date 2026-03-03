//! Schnorr Proofs (Σ-Protocol) over Ristretto255
//!
//! Provides zero-knowledge proofs of knowledge for:
//! 1. Pedersen commitment openings (prove you know value and blinding)
//! 2. Blinding factor knowledge (prove you know r such that R = h^r)
//!
//! Uses Fiat-Shamir transform for non-interactive proofs.
//!
//! Security: Sound under discrete log assumption in Ristretto255.
//! Note: NOT post-quantum.

use curve25519_dalek::{
    ristretto::CompressedRistretto,
    scalar::Scalar,
};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

use crate::pedersen::{BlindingCommitment, Commitment, PedersenParams};

/// Schnorr proof of knowledge for Pedersen commitment
///
/// Proves: "I know (value, blinding) such that C = g^value · h^blinding"
///
/// Protocol (Fiat-Shamir transformed):
/// 1. Prover picks random k₁, k₂, computes A = g^k₁ · h^k₂
/// 2. Challenge c = H(A || C || context)
/// 3. Responses z₁ = k₁ + c·value, z₂ = k₂ + c·blinding
/// 4. Verifier checks: g^z₁ · h^z₂ == A · C^c
#[derive(Clone)]
pub struct PedersenProof {
    /// Commitment to random nonces: A = g^k₁ · h^k₂
    pub nonce_commitment: CompressedRistretto,
    /// Response for value: z₁ = k₁ + c·value
    pub response_value: Scalar,
    /// Response for blinding: z₂ = k₂ + c·blinding
    pub response_blinding: Scalar,
}

impl PedersenProof {
    /// Size in bytes when serialized
    pub const SERIALIZED_SIZE: usize = 32 + 32 + 32; // 96 bytes

    /// Create proof of knowledge of (value, blinding) that opens commitment
    pub fn prove(
        params: &PedersenParams,
        value: &Scalar,
        blinding: &Scalar,
        commitment: &Commitment,
        context: &[u8],
    ) -> Self {
        let mut rng = OsRng;

        // Random nonces
        let k1 = Scalar::random(&mut rng);
        let k2 = Scalar::random(&mut rng);

        // Nonce commitment
        let A = params.g * k1 + params.h * k2;
        let A_compressed = A.compress();

        // Fiat-Shamir challenge
        let c = Self::compute_challenge(&A_compressed, &commitment.compress(), context);

        // Responses (masking the secrets)
        let z1 = k1 + c * value;
        let z2 = k2 + c * blinding;

        Self {
            nonce_commitment: A_compressed,
            response_value: z1,
            response_blinding: z2,
        }
    }

    /// Verify proof of knowledge
    pub fn verify(
        &self,
        params: &PedersenParams,
        commitment: &Commitment,
        context: &[u8],
    ) -> bool {
        // Decompress nonce commitment
        let A = match self.nonce_commitment.decompress() {
            Some(p) => p,
            None => return false,
        };

        // Recompute challenge
        let c = Self::compute_challenge(&self.nonce_commitment, &commitment.compress(), context);

        // Verify: g^z₁ · h^z₂ == A · C^c
        let lhs = params.g * self.response_value + params.h * self.response_blinding;
        let rhs = A + commitment.0 * c;

        lhs == rhs
    }

    /// Compute Fiat-Shamir challenge
    fn compute_challenge(
        nonce_commitment: &CompressedRistretto,
        commitment: &CompressedRistretto,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/Schnorr/Pedersen/v1/challenge");
        hasher.update(nonce_commitment.as_bytes());
        hasher.update(commitment.as_bytes());
        hasher.update(context);

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order(bytes)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut bytes = [0u8; Self::SERIALIZED_SIZE];
        bytes[0..32].copy_from_slice(self.nonce_commitment.as_bytes());
        bytes[32..64].copy_from_slice(self.response_value.as_bytes());
        bytes[64..96].copy_from_slice(self.response_blinding.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; Self::SERIALIZED_SIZE]) -> Option<Self> {
        let nonce_commitment = CompressedRistretto::from_slice(&bytes[0..32]).ok()?;

        let mut z1_bytes = [0u8; 32];
        z1_bytes.copy_from_slice(&bytes[32..64]);
        let response_value = Scalar::from_canonical_bytes(z1_bytes).into_option()?;

        let mut z2_bytes = [0u8; 32];
        z2_bytes.copy_from_slice(&bytes[64..96]);
        let response_blinding = Scalar::from_canonical_bytes(z2_bytes).into_option()?;

        Some(Self {
            nonce_commitment,
            response_value,
            response_blinding,
        })
    }
}

/// Schnorr proof for blinding commitment only
///
/// Proves: "I know r such that R = h^r"
///
/// This is the key proof for recovery: the user proves they know
/// the blinding factor (derived from passphrase) to retrieve their share.
/// They don't need to know the share value itself.
#[derive(Clone)]
pub struct BlindingProof {
    /// Commitment to random nonce: A = h^k
    pub nonce_commitment: CompressedRistretto,
    /// Response: z = k + c·r
    pub response: Scalar,
}

impl BlindingProof {
    /// Size in bytes when serialized
    pub const SERIALIZED_SIZE: usize = 32 + 32; // 64 bytes

    /// Create proof of knowledge of blinding factor
    pub fn prove(
        params: &PedersenParams,
        blinding: &Scalar,
        blinding_commitment: &BlindingCommitment,
        context: &[u8],
    ) -> Self {
        let mut rng = OsRng;

        // Random nonce
        let k = Scalar::random(&mut rng);

        // Nonce commitment (using h, not g)
        let A = params.h * k;
        let A_compressed = A.compress();

        // Fiat-Shamir challenge
        let c = Self::compute_challenge(&A_compressed, &blinding_commitment.compress(), context);

        // Response (masking the secret)
        let z = k + c * blinding;

        Self {
            nonce_commitment: A_compressed,
            response: z,
        }
    }

    /// Verify proof of knowledge
    pub fn verify(
        &self,
        params: &PedersenParams,
        blinding_commitment: &BlindingCommitment,
        context: &[u8],
    ) -> bool {
        // Decompress nonce commitment
        let A = match self.nonce_commitment.decompress() {
            Some(p) => p,
            None => return false,
        };

        // Recompute challenge
        let c = Self::compute_challenge(&self.nonce_commitment, &blinding_commitment.compress(), context);

        // Verify: h^z == A · R^c
        let lhs = params.h * self.response;
        let rhs = A + blinding_commitment.0 * c;

        lhs == rhs
    }

    /// Compute Fiat-Shamir challenge
    fn compute_challenge(
        nonce_commitment: &CompressedRistretto,
        blinding_commitment: &CompressedRistretto,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Yours/Schnorr/Blinding/v1/challenge");
        hasher.update(nonce_commitment.as_bytes());
        hasher.update(blinding_commitment.as_bytes());
        hasher.update(context);

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order(bytes)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut bytes = [0u8; Self::SERIALIZED_SIZE];
        bytes[0..32].copy_from_slice(self.nonce_commitment.as_bytes());
        bytes[32..64].copy_from_slice(self.response.as_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; Self::SERIALIZED_SIZE]) -> Option<Self> {
        let nonce_commitment = CompressedRistretto::from_slice(&bytes[0..32]).ok()?;

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&bytes[32..64]);
        let response = Scalar::from_canonical_bytes(z_bytes).into_option()?;

        Some(Self {
            nonce_commitment,
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_proof() {
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);

        let commitment = params.commit(&value, &blinding);

        // Create proof
        let proof = PedersenProof::prove(
            &params,
            &value,
            &blinding,
            &commitment,
            b"test context",
        );

        // Verify proof
        assert!(proof.verify(&params, &commitment, b"test context"));

        // Wrong context should fail
        assert!(!proof.verify(&params, &commitment, b"wrong context"));
    }

    #[test]
    fn test_pedersen_proof_soundness() {
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        let commitment = params.commit(&value, &blinding);

        // Proof for wrong value should not verify
        let wrong_value = Scalar::random(&mut OsRng);
        let wrong_proof = PedersenProof::prove(
            &params,
            &wrong_value,
            &blinding,
            &commitment,
            b"test",
        );

        // This should fail because the commitment doesn't match
        // (The proof will be valid for commitment to wrong_value, not our commitment)
        // Actually, the proof structure allows this to work, but verification against
        // a different commitment should fail
        assert!(!wrong_proof.verify(&params, &commitment, b"test"));
    }

    #[test]
    fn test_pedersen_proof_serialization() {
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        let commitment = params.commit(&value, &blinding);

        let proof = PedersenProof::prove(&params, &value, &blinding, &commitment, b"test");

        let bytes = proof.to_bytes();
        let recovered = PedersenProof::from_bytes(&bytes).unwrap();

        assert!(recovered.verify(&params, &commitment, b"test"));
    }

    #[test]
    fn test_blinding_proof() {
        let params = PedersenParams::new();
        let blinding = Scalar::random(&mut OsRng);

        let blinding_commitment = params.commit_blinding(&blinding);

        // Create proof
        let proof = BlindingProof::prove(
            &params,
            &blinding,
            &blinding_commitment,
            b"recovery context",
        );

        // Verify proof
        assert!(proof.verify(&params, &blinding_commitment, b"recovery context"));

        // Wrong context should fail
        assert!(!proof.verify(&params, &blinding_commitment, b"wrong context"));
    }

    #[test]
    fn test_blinding_proof_soundness() {
        let params = PedersenParams::new();
        let blinding = Scalar::random(&mut OsRng);
        let wrong_blinding = Scalar::random(&mut OsRng);

        let blinding_commitment = params.commit_blinding(&blinding);

        // Proof with wrong blinding should not verify for this commitment
        let wrong_proof = BlindingProof::prove(
            &params,
            &wrong_blinding,
            &blinding_commitment,
            b"test",
        );

        // This verifies against the commitment, which was made with blinding, not wrong_blinding
        assert!(!wrong_proof.verify(&params, &blinding_commitment, b"test"));
    }

    #[test]
    fn test_blinding_proof_serialization() {
        let params = PedersenParams::new();
        let blinding = Scalar::random(&mut OsRng);
        let blinding_commitment = params.commit_blinding(&blinding);

        let proof = BlindingProof::prove(&params, &blinding, &blinding_commitment, b"test");

        let bytes = proof.to_bytes();
        let recovered = BlindingProof::from_bytes(&bytes).unwrap();

        assert!(recovered.verify(&params, &blinding_commitment, b"test"));
    }

    #[test]
    fn test_blinding_proof_for_recovery() {
        // Simulate recovery scenario:
        // 1. Setup: user creates blinding commitment from passphrase
        // 2. Store: node stores R = h^r
        // 3. Recovery: user proves knowledge of r to retrieve share

        let params = PedersenParams::new();

        // Simulate passphrase-derived blinding
        let passphrase = b"forest ember shadow river";
        let blinding = crate::pedersen::hash_to_scalar(passphrase);

        // What gets stored with the share
        let stored_commitment = params.commit_blinding(&blinding);

        // Recovery: user proves knowledge
        let context = b"node123|timestamp|request_id";
        let proof = BlindingProof::prove(&params, &blinding, &stored_commitment, context);

        // Node verifies
        assert!(proof.verify(&params, &stored_commitment, context));

        // Different passphrase should fail
        let wrong_passphrase = b"wrong words here now";
        let wrong_blinding = crate::pedersen::hash_to_scalar(wrong_passphrase);
        let wrong_commitment = params.commit_blinding(&wrong_blinding);

        // User can't prove for the stored commitment with wrong passphrase
        assert_ne!(stored_commitment, wrong_commitment);
    }
}
