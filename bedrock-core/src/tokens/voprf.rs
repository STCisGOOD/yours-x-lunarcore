//! Verifiable Oblivious Pseudo-Random Function (VOPRF)
//!
//! VOPRF allows a server to evaluate a PRF on a client's input without
//! learning the input, while the client learns nothing about the server's key.
//!
//! # Protocol
//!
//! ```text
//! Client                          Server
//!   |                               |
//!   | r ← random                    |
//!   | blinded = r * H(input)        |
//!   |----------blinded------------->|
//!   |                               | evaluated = sk * blinded
//!   |                               | proof = DLEQ(sk, blinded, evaluated)
//!   |<--------(evaluated, proof)----|
//!   | verify(proof)                 |
//!   | token = (1/r) * evaluated     |
//!   | = sk * H(input)               |
//! ```
//!
//! # Security
//!
//! - Server cannot determine input from blinded value
//! - DLEQ proof ensures correct evaluation
//! - Token is deterministic: same input always produces same token

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BedrockError, Result};
use crate::pairing::{
    bls12_381::{G1Point, G2Point, Scalar, SCALAR_SIZE, G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE},
    dst,
    hash_to_curve::{hash_to_g1, hash_to_scalar},
};

// ============================================================================
// VOPRF Server
// ============================================================================

/// VOPRF server (token issuer).
///
/// Holds the secret key and can evaluate the PRF on blinded inputs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VOPRFServer {
    /// Secret key (scalar)
    secret_key: Scalar,
}

/// VOPRF server public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VOPRFPublicKey {
    /// Public key in G2: pk = sk * G2
    pub key: G2Point,
}

impl VOPRFServer {
    /// Create a new VOPRF server with a random key.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        VOPRFServer {
            secret_key: Scalar::random(rng),
        }
    }

    /// Create from an existing secret key.
    pub fn from_secret_key(secret_key: Scalar) -> Self {
        VOPRFServer { secret_key }
    }

    /// Get the public key.
    pub fn public_key(&self) -> VOPRFPublicKey {
        VOPRFPublicKey {
            key: G2Point::generator().mul(&self.secret_key),
        }
    }

    /// Export secret key bytes.
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.secret_key.to_bytes()
    }

    /// Import from secret key bytes.
    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> Result<Self> {
        let secret_key = Scalar::from_bytes(bytes)?;
        Ok(VOPRFServer { secret_key })
    }

    /// Evaluate VOPRF on a blinded input.
    ///
    /// Returns the evaluated point and a DLEQ proof that the evaluation
    /// was performed correctly.
    pub fn evaluate<R: RngCore + CryptoRng>(
        &self,
        blinded: &G1Point,
        rng: &mut R,
    ) -> (G1Point, VOPRFProof) {
        // evaluated = sk * blinded
        let evaluated = blinded.mul(&self.secret_key);

        // DLEQ proof: proves log_blinded(evaluated) = log_G2(pk)
        let proof = VOPRFProof::create(
            &self.secret_key,
            blinded,
            &evaluated,
            &self.public_key().key,
            rng,
        );

        (evaluated, proof)
    }

    /// Batch evaluate multiple blinded inputs.
    pub fn batch_evaluate<R: RngCore + CryptoRng>(
        &self,
        blinded_inputs: &[G1Point],
        rng: &mut R,
    ) -> Vec<(G1Point, VOPRFProof)> {
        blinded_inputs
            .iter()
            .map(|b| self.evaluate(b, rng))
            .collect()
    }
}

impl VOPRFPublicKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.key.to_bytes()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(VOPRFPublicKey {
            key: G2Point::from_bytes(bytes)?,
        })
    }
}

// ============================================================================
// VOPRF Client
// ============================================================================

/// VOPRF client for blinding and unblinding.
pub struct VOPRFClient;

impl VOPRFClient {
    /// Blind an input for VOPRF evaluation.
    ///
    /// Returns the blinded element and the state needed for unblinding.
    pub fn blind<R: RngCore + CryptoRng>(
        input: &[u8],
        rng: &mut R,
    ) -> VOPRFBlindState {
        // Hash input to curve point
        let p = hash_to_g1(input, dst::VOPRF);

        // Generate random blinding factor
        let blind = Scalar::random(rng);

        // blinded = blind * P
        let blinded_element = p.mul(&blind);

        VOPRFBlindState {
            input: input.to_vec(),
            blind,
            blinded_element,
            input_point: p,
        }
    }

    /// Unblind the server's response.
    ///
    /// Verifies the DLEQ proof and returns the final token value.
    pub fn unblind(
        state: &VOPRFBlindState,
        evaluated: &G1Point,
        proof: &VOPRFProof,
        server_pk: &VOPRFPublicKey,
    ) -> Result<G1Point> {
        // Verify DLEQ proof
        if !proof.verify(&state.blinded_element, evaluated, &server_pk.key) {
            return Err(BedrockError::VOPRFVerificationFailed);
        }

        // Unblind: token = (1/blind) * evaluated = sk * P
        let blind_inv = state.blind.invert().ok_or(BedrockError::Internal(
            "Blind factor is zero".into(),
        ))?;
        let token = evaluated.mul(&blind_inv);

        Ok(token)
    }

    /// Verify a token directly (requires the original input).
    ///
    /// This is used when the verifier has both the input and the token.
    pub fn verify_token(
        input: &[u8],
        token: &G1Point,
        server_pk: &VOPRFPublicKey,
    ) -> bool {
        // Compute P = H(input)
        let p = hash_to_g1(input, dst::VOPRF);

        // Verify: e(token, G2) == e(P, pk)
        // This checks that token = sk * P
        crate::pairing::verify_pairing_eq(token, &G2Point::generator(), &p, &server_pk.key)
    }
}

// ============================================================================
// VOPRF Blind State
// ============================================================================

/// Client state during the VOPRF blinding phase.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VOPRFBlindState {
    /// Original input
    #[zeroize(skip)]
    input: Vec<u8>,
    /// Blinding factor
    blind: Scalar,
    /// Blinded element to send to server
    #[zeroize(skip)]
    blinded_element: G1Point,
    /// Input hashed to curve (for verification)
    #[zeroize(skip)]
    input_point: G1Point,
}

impl VOPRFBlindState {
    /// Get the blinded element to send to the server.
    pub fn blinded_element(&self) -> &G1Point {
        &self.blinded_element
    }

    /// Get the original input.
    pub fn input(&self) -> &[u8] {
        &self.input
    }

    /// Get the blinding factor bytes (for serialization).
    pub fn blind_bytes(&self) -> [u8; 32] {
        self.blind.to_bytes()
    }

    /// Get the input point bytes (for serialization).
    pub fn input_point_bytes(&self) -> [u8; 48] {
        self.input_point.to_bytes()
    }
}

// ============================================================================
// VOPRF DLEQ Proof
// ============================================================================

/// DLEQ (Discrete Log Equality) proof for VOPRF.
///
/// Proves that log_base1(result1) == log_G2(result2) without revealing the secret.
/// This ensures the server used the same key for evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VOPRFProof {
    /// Challenge scalar
    pub c: Scalar,
    /// Response scalar
    pub s: Scalar,
}

impl VOPRFProof {
    /// Create a DLEQ proof.
    ///
    /// Proves: secret such that result1 = secret * base1 AND result2 = secret * G2
    pub fn create<R: RngCore + CryptoRng>(
        secret: &Scalar,
        base1: &G1Point,
        result1: &G1Point,
        result2: &G2Point,
        rng: &mut R,
    ) -> Self {
        // Random commitment
        let k = Scalar::random(rng);

        // Commitments
        let r1 = base1.mul(&k);
        let r2 = G2Point::generator().mul(&k);

        // Challenge: c = H(base1 || result1 || result2 || r1 || r2)
        let c = Self::compute_challenge(base1, result1, result2, &r1, &r2);

        // Response: s = k - c * secret
        let s = k.sub(&c.mul(secret));

        VOPRFProof { c, s }
    }

    /// Verify a DLEQ proof.
    ///
    /// Fix #16: Added point validation to prevent invalid point attacks.
    /// All input points are validated to be in the correct prime-order subgroup.
    pub fn verify(
        &self,
        base1: &G1Point,
        result1: &G1Point,
        result2: &G2Point,
    ) -> bool {
        // Fix #16: Validate all input points are in the correct subgroup
        // This prevents small subgroup attacks and invalid curve attacks
        if !base1.is_valid() || !result1.is_valid() || !result2.is_valid() {
            return false;
        }

        // Reject identity points (would allow trivial proofs)
        if base1.is_identity() || result1.is_identity() || result2.is_identity() {
            return false;
        }

        // Recompute commitments:
        // r1 = s * base1 + c * result1
        // r2 = s * G2 + c * result2
        let r1 = base1.mul(&self.s).add(&result1.mul(&self.c));
        let r2 = G2Point::generator().mul(&self.s).add(&result2.mul(&self.c));

        // Recompute challenge
        let c_prime = Self::compute_challenge(base1, result1, result2, &r1, &r2);

        self.c == c_prime
    }

    fn compute_challenge(
        base1: &G1Point,
        result1: &G1Point,
        result2: &G2Point,
        r1: &G1Point,
        r2: &G2Point,
    ) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(&base1.to_bytes());
        input.extend_from_slice(&result1.to_bytes());
        input.extend_from_slice(&result2.to_bytes());
        input.extend_from_slice(&r1.to_bytes());
        input.extend_from_slice(&r2.to_bytes());

        hash_to_scalar(&input, b"VOPRF_DLEQ_")
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SCALAR_SIZE * 2);
        bytes.extend_from_slice(&self.c.to_bytes());
        bytes.extend_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SCALAR_SIZE * 2 {
            return Err(BedrockError::Deserialization(
                "Invalid VOPRF proof length".into(),
            ));
        }

        let mut c_bytes = [0u8; SCALAR_SIZE];
        let mut s_bytes = [0u8; SCALAR_SIZE];
        c_bytes.copy_from_slice(&bytes[..SCALAR_SIZE]);
        s_bytes.copy_from_slice(&bytes[SCALAR_SIZE..]);

        Ok(VOPRFProof {
            c: Scalar::from_bytes(&c_bytes)?,
            s: Scalar::from_bytes(&s_bytes)?,
        })
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
    fn test_voprf_basic() {
        let mut rng = OsRng;

        // Setup server
        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        // Client blinds input
        let input = b"test input";
        let blind_state = VOPRFClient::blind(input, &mut rng);

        // Server evaluates
        let (evaluated, proof) = server.evaluate(blind_state.blinded_element(), &mut rng);

        // Client unblinds
        let token = VOPRFClient::unblind(&blind_state, &evaluated, &proof, &server_pk).unwrap();

        // Verify token
        assert!(VOPRFClient::verify_token(input, &token, &server_pk));
    }

    #[test]
    fn test_voprf_deterministic() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let input = b"deterministic test";

        // Blind and evaluate twice with different blinding factors
        let blind_state1 = VOPRFClient::blind(input, &mut rng);
        let (evaluated1, proof1) = server.evaluate(blind_state1.blinded_element(), &mut rng);
        let token1 = VOPRFClient::unblind(&blind_state1, &evaluated1, &proof1, &server_pk).unwrap();

        let blind_state2 = VOPRFClient::blind(input, &mut rng);
        let (evaluated2, proof2) = server.evaluate(blind_state2.blinded_element(), &mut rng);
        let token2 = VOPRFClient::unblind(&blind_state2, &evaluated2, &proof2, &server_pk).unwrap();

        // Tokens should be the same (deterministic)
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_voprf_different_inputs() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        // Different inputs should produce different tokens
        let input1 = b"input 1";
        let input2 = b"input 2";

        let blind_state1 = VOPRFClient::blind(input1, &mut rng);
        let (evaluated1, proof1) = server.evaluate(blind_state1.blinded_element(), &mut rng);
        let token1 = VOPRFClient::unblind(&blind_state1, &evaluated1, &proof1, &server_pk).unwrap();

        let blind_state2 = VOPRFClient::blind(input2, &mut rng);
        let (evaluated2, proof2) = server.evaluate(blind_state2.blinded_element(), &mut rng);
        let token2 = VOPRFClient::unblind(&blind_state2, &evaluated2, &proof2, &server_pk).unwrap();

        assert_ne!(token1, token2);
    }

    #[test]
    fn test_voprf_wrong_proof() {
        let mut rng = OsRng;

        // Two different servers
        let server1 = VOPRFServer::new(&mut rng);
        let server2 = VOPRFServer::new(&mut rng);

        let input = b"test";
        let blind_state = VOPRFClient::blind(input, &mut rng);

        // Evaluate with server1
        let (evaluated, proof) = server1.evaluate(blind_state.blinded_element(), &mut rng);

        // Try to verify with server2's public key - should fail
        let result = VOPRFClient::unblind(&blind_state, &evaluated, &proof, &server2.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_voprf_server_serialization() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let pk = server.public_key();

        // Serialize and deserialize server
        let server_bytes = server.to_bytes();
        let recovered_server = VOPRFServer::from_bytes(&server_bytes).unwrap();

        assert_eq!(recovered_server.public_key(), pk);
    }

    #[test]
    fn test_voprf_proof_serialization() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let input = b"test";
        let blind_state = VOPRFClient::blind(input, &mut rng);
        let (_, proof) = server.evaluate(blind_state.blinded_element(), &mut rng);

        // Serialize and deserialize proof
        let proof_bytes = proof.to_bytes();
        let recovered_proof = VOPRFProof::from_bytes(&proof_bytes).unwrap();

        assert_eq!(proof.c, recovered_proof.c);
        assert_eq!(proof.s, recovered_proof.s);
    }

    #[test]
    fn test_voprf_blinding_hides_input() {
        let mut rng = OsRng;

        // Same input with different blinding factors produces different blinded elements
        let input = b"secret input";

        let blind_state1 = VOPRFClient::blind(input, &mut rng);
        let blind_state2 = VOPRFClient::blind(input, &mut rng);

        // Blinded elements should be different (unlinkable)
        assert_ne!(blind_state1.blinded_element(), blind_state2.blinded_element());
    }
}
