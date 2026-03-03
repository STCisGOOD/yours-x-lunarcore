//! Schnorr Proofs
//!
//! Sigma protocols for proving knowledge of discrete logarithms.
//!
//! # Protocols
//!
//! - `SchnorrProof`: Prove knowledge of x such that P = x·G
//! - `DLEQProof`: Prove that log_G(P) = log_H(Q) (same secret)
//!
//! # Security
//!
//! Uses Fiat-Shamir transform for non-interactive proofs.
//! All operations are designed to be constant-time.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{BedrockError, Result};
use crate::pairing::{
    bls12_381::*,
    dst,
    hash_to_curve::hash_to_scalar,
};

// ============================================================================
// Schnorr Proof (G1)
// ============================================================================

/// Schnorr proof of knowledge of discrete log in G1.
///
/// Proves: "I know x such that P = x·G"
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProofG1 {
    /// Commitment R = r·G
    pub commitment: G1Point,
    /// Response s = r + c·x
    pub response: Scalar,
}

impl SchnorrProofG1 {
    /// Create a Schnorr proof.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret scalar x
    /// * `public` - The public point P = x·G
    /// * `context` - Additional context for domain separation
    /// * `rng` - Cryptographic RNG
    pub fn prove<R: RngCore + CryptoRng>(
        secret: &Scalar,
        public: &G1Point,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        // Random commitment
        let r = Scalar::random(rng);
        let commitment = G1Point::generator().mul(&r);

        // Challenge c = H(context || G || P || R)
        let challenge = Self::compute_challenge(public, &commitment, context);

        // Response s = r + c·x
        let response = r.add(&challenge.mul(secret));

        SchnorrProofG1 { commitment, response }
    }

    /// Verify a Schnorr proof.
    ///
    /// Checks: s·G == R + c·P
    pub fn verify(&self, public: &G1Point, context: &[u8]) -> bool {
        let challenge = Self::compute_challenge(public, &self.commitment, context);

        // s·G
        let left = G1Point::generator().mul(&self.response);

        // R + c·P
        let right = self.commitment.add(&public.mul(&challenge));

        left == right
    }

    fn compute_challenge(public: &G1Point, commitment: &G1Point, context: &[u8]) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&G1Point::generator().to_bytes());
        input.extend_from_slice(&public.to_bytes());
        input.extend_from_slice(&commitment.to_bytes());

        hash_to_scalar(&input, b"SCHNORR_G1_")
    }
}

// ============================================================================
// Schnorr Proof (G2)
// ============================================================================

/// Schnorr proof of knowledge of discrete log in G2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrProofG2 {
    /// Commitment R = r·G2
    pub commitment: G2Point,
    /// Response s = r + c·x
    pub response: Scalar,
}

impl SchnorrProofG2 {
    /// Create a Schnorr proof in G2.
    pub fn prove<R: RngCore + CryptoRng>(
        secret: &Scalar,
        public: &G2Point,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let r = Scalar::random(rng);
        let commitment = G2Point::generator().mul(&r);

        let challenge = Self::compute_challenge(public, &commitment, context);
        let response = r.add(&challenge.mul(secret));

        SchnorrProofG2 { commitment, response }
    }

    /// Verify a Schnorr proof in G2.
    pub fn verify(&self, public: &G2Point, context: &[u8]) -> bool {
        let challenge = Self::compute_challenge(public, &self.commitment, context);

        let left = G2Point::generator().mul(&self.response);
        let right = self.commitment.add(&public.mul(&challenge));

        left == right
    }

    fn compute_challenge(public: &G2Point, commitment: &G2Point, context: &[u8]) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&G2Point::generator().to_bytes());
        input.extend_from_slice(&public.to_bytes());
        input.extend_from_slice(&commitment.to_bytes());

        hash_to_scalar(&input, b"SCHNORR_G2_")
    }
}

// ============================================================================
// DLEQ Proof (Discrete Log Equality)
// ============================================================================

/// DLEQ proof: proves log_G1(P) = log_G2(Q) (or across different bases).
///
/// Used in VOPRF to prove correct evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLEQProof {
    /// Challenge
    pub challenge: Scalar,
    /// Response
    pub response: Scalar,
}

impl DLEQProof {
    /// Create a DLEQ proof.
    ///
    /// Proves: log_base1(result1) = log_base2(result2)
    ///
    /// Both result1 = secret·base1 and result2 = secret·base2
    pub fn prove_g1<R: RngCore + CryptoRng>(
        secret: &Scalar,
        base1: &G1Point,
        result1: &G1Point,
        base2: &G1Point,
        result2: &G1Point,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let k = Scalar::random(rng);

        // Commitments
        let r1 = base1.mul(&k);
        let r2 = base2.mul(&k);

        // Challenge
        let challenge = Self::compute_challenge_g1(
            base1, result1, base2, result2, &r1, &r2, context,
        );

        // Response
        let response = k.add(&challenge.mul(secret).neg());

        DLEQProof { challenge, response }
    }

    /// Verify a DLEQ proof in G1.
    pub fn verify_g1(
        &self,
        base1: &G1Point,
        result1: &G1Point,
        base2: &G1Point,
        result2: &G1Point,
        context: &[u8],
    ) -> bool {
        // Recompute commitments
        // r1 = s·base1 + c·result1
        let r1 = base1.mul(&self.response).add(&result1.mul(&self.challenge));
        let r2 = base2.mul(&self.response).add(&result2.mul(&self.challenge));

        // Recompute challenge
        let expected = Self::compute_challenge_g1(
            base1, result1, base2, result2, &r1, &r2, context,
        );

        self.challenge == expected
    }

    fn compute_challenge_g1(
        base1: &G1Point,
        result1: &G1Point,
        base2: &G1Point,
        result2: &G1Point,
        r1: &G1Point,
        r2: &G1Point,
        context: &[u8],
    ) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&base1.to_bytes());
        input.extend_from_slice(&result1.to_bytes());
        input.extend_from_slice(&base2.to_bytes());
        input.extend_from_slice(&result2.to_bytes());
        input.extend_from_slice(&r1.to_bytes());
        input.extend_from_slice(&r2.to_bytes());

        hash_to_scalar(&input, b"DLEQ_G1_")
    }

    /// Create a DLEQ proof across G1 and G2.
    ///
    /// Proves: secret such that result1 = secret·base1 (in G1)
    ///         and result2 = secret·base2 (in G2)
    pub fn prove_cross<R: RngCore + CryptoRng>(
        secret: &Scalar,
        base1: &G1Point,
        result1: &G1Point,
        base2: &G2Point,
        result2: &G2Point,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let k = Scalar::random(rng);

        let r1 = base1.mul(&k);
        let r2 = base2.mul(&k);

        let challenge = Self::compute_challenge_cross(
            base1, result1, base2, result2, &r1, &r2, context,
        );

        let response = k.add(&challenge.mul(secret).neg());

        DLEQProof { challenge, response }
    }

    /// Verify a cross-group DLEQ proof.
    pub fn verify_cross(
        &self,
        base1: &G1Point,
        result1: &G1Point,
        base2: &G2Point,
        result2: &G2Point,
        context: &[u8],
    ) -> bool {
        let r1 = base1.mul(&self.response).add(&result1.mul(&self.challenge));
        let r2 = base2.mul(&self.response).add(&result2.mul(&self.challenge));

        let expected = Self::compute_challenge_cross(
            base1, result1, base2, result2, &r1, &r2, context,
        );

        self.challenge == expected
    }

    fn compute_challenge_cross(
        base1: &G1Point,
        result1: &G1Point,
        base2: &G2Point,
        result2: &G2Point,
        r1: &G1Point,
        r2: &G2Point,
        context: &[u8],
    ) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&base1.to_bytes());
        input.extend_from_slice(&result1.to_bytes());
        input.extend_from_slice(&base2.to_bytes());
        input.extend_from_slice(&result2.to_bytes());
        input.extend_from_slice(&r1.to_bytes());
        input.extend_from_slice(&r2.to_bytes());

        hash_to_scalar(&input, b"DLEQ_CROSS_")
    }
}

// ============================================================================
// Pedersen Commitment
// ============================================================================

/// Pedersen commitment with two generators.
///
/// C = value·G + blinding·H
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// The commitment point
    pub commitment: G1Point,
}

/// Second generator for Pedersen commitments (nothing-up-my-sleeve)
fn pedersen_h() -> G1Point {
    use crate::pairing::hash_to_curve::hash_to_g1;
    hash_to_g1(b"PEDERSEN_H_GENERATOR", b"OFFGRID_PEDERSEN_")
}

impl PedersenCommitment {
    /// Create a Pedersen commitment.
    ///
    /// C = value·G + blinding·H
    pub fn commit(value: &Scalar, blinding: &Scalar) -> Self {
        let c = G1Point::generator()
            .mul(value)
            .add(&pedersen_h().mul(blinding));

        PedersenCommitment { commitment: c }
    }

    /// Verify a commitment opening.
    pub fn verify(&self, value: &Scalar, blinding: &Scalar) -> bool {
        let expected = G1Point::generator()
            .mul(value)
            .add(&pedersen_h().mul(blinding));

        self.commitment == expected
    }

    /// Create a proof of knowledge of opening.
    pub fn prove_opening<R: RngCore + CryptoRng>(
        &self,
        value: &Scalar,
        blinding: &Scalar,
        context: &[u8],
        rng: &mut R,
    ) -> PedersenOpeningProof {
        let r_v = Scalar::random(rng);
        let r_b = Scalar::random(rng);

        // R = r_v·G + r_b·H
        let r = G1Point::generator()
            .mul(&r_v)
            .add(&pedersen_h().mul(&r_b));

        // Challenge
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&self.commitment.to_bytes());
        input.extend_from_slice(&r.to_bytes());
        let c = hash_to_scalar(&input, b"PEDERSEN_OPEN_");

        // Responses
        let s_v = r_v.add(&c.mul(value));
        let s_b = r_b.add(&c.mul(blinding));

        PedersenOpeningProof {
            commitment_r: r,
            response_value: s_v,
            response_blinding: s_b,
        }
    }
}

/// Proof of knowledge of Pedersen commitment opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PedersenOpeningProof {
    /// Commitment R
    pub commitment_r: G1Point,
    /// Response for value
    pub response_value: Scalar,
    /// Response for blinding
    pub response_blinding: Scalar,
}

impl PedersenOpeningProof {
    /// Verify the opening proof.
    pub fn verify(&self, commitment: &PedersenCommitment, context: &[u8]) -> bool {
        // Recompute challenge
        let mut input = Vec::new();
        input.extend_from_slice(context);
        input.extend_from_slice(&commitment.commitment.to_bytes());
        input.extend_from_slice(&self.commitment_r.to_bytes());
        let c = hash_to_scalar(&input, b"PEDERSEN_OPEN_");

        // Check: s_v·G + s_b·H == R + c·C
        let left = G1Point::generator()
            .mul(&self.response_value)
            .add(&pedersen_h().mul(&self.response_blinding));

        let right = self.commitment_r.add(&commitment.commitment.mul(&c));

        left == right
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
    fn test_schnorr_g1() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = G1Point::generator().mul(&secret);

        let context = b"test context";
        let proof = SchnorrProofG1::prove(&secret, &public, context, &mut rng);

        assert!(proof.verify(&public, context));

        // Wrong public key should fail
        let wrong_public = G1Point::random(&mut rng);
        assert!(!proof.verify(&wrong_public, context));

        // Wrong context should fail
        assert!(!proof.verify(&public, b"wrong context"));
    }

    #[test]
    fn test_schnorr_g2() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let public = G2Point::generator().mul(&secret);

        let context = b"test context";
        let proof = SchnorrProofG2::prove(&secret, &public, context, &mut rng);

        assert!(proof.verify(&public, context));
    }

    #[test]
    fn test_dleq_g1() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);

        let base1 = G1Point::random(&mut rng);
        let result1 = base1.mul(&secret);

        let base2 = G1Point::random(&mut rng);
        let result2 = base2.mul(&secret);

        let context = b"dleq test";
        let proof = DLEQProof::prove_g1(
            &secret, &base1, &result1, &base2, &result2, context, &mut rng,
        );

        assert!(proof.verify_g1(&base1, &result1, &base2, &result2, context));

        // Wrong result should fail
        let wrong_result = G1Point::random(&mut rng);
        assert!(!proof.verify_g1(&base1, &result1, &base2, &wrong_result, context));
    }

    #[test]
    fn test_dleq_cross() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);

        let base1 = G1Point::generator();
        let result1 = base1.mul(&secret);

        let base2 = G2Point::generator();
        let result2 = base2.mul(&secret);

        let context = b"cross dleq test";
        let proof = DLEQProof::prove_cross(
            &secret, &base1, &result1, &base2, &result2, context, &mut rng,
        );

        assert!(proof.verify_cross(&base1, &result1, &base2, &result2, context));
    }

    #[test]
    fn test_pedersen_commitment() {
        let mut rng = OsRng;
        let value = Scalar::random(&mut rng);
        let blinding = Scalar::random(&mut rng);

        let commitment = PedersenCommitment::commit(&value, &blinding);

        // Verify opening
        assert!(commitment.verify(&value, &blinding));

        // Wrong value should fail
        let wrong_value = Scalar::random(&mut rng);
        assert!(!commitment.verify(&wrong_value, &blinding));
    }

    #[test]
    fn test_pedersen_opening_proof() {
        let mut rng = OsRng;
        let value = Scalar::random(&mut rng);
        let blinding = Scalar::random(&mut rng);

        let commitment = PedersenCommitment::commit(&value, &blinding);

        let context = b"opening proof test";
        let proof = commitment.prove_opening(&value, &blinding, context, &mut rng);

        assert!(proof.verify(&commitment, context));

        // Wrong context should fail
        assert!(!proof.verify(&commitment, b"wrong context"));
    }
}
