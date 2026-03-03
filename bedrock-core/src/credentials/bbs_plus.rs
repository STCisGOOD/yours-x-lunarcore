//! BBS+ Signature Scheme
//!
//! Implementation of BBS+ signatures for anonymous credentials.
//!
//! # Overview
//!
//! BBS+ signatures allow signing multiple messages with a single signature,
//! then later proving knowledge of the signature while selectively disclosing
//! only some of the signed messages.
//!
//! # Signature Structure
//!
//! A BBS+ signature on messages (m_1, ..., m_n) is:
//!
//! σ = (A, e, s) where:
//! - A = (g_1 · h_0^s · h_1^m_1 · ... · h_n^m_n)^(1/(x+e))
//! - e, s are random scalars
//! - x is the issuer's secret key
//!
//! # Proof Protocol (IETF-aligned)
//!
//! The selective disclosure proof uses:
//! 1. Signature randomization: Abar = A * r1 * r2, D = B * r2, Bbar = D * r1 - Abar * e
//! 2. Pairing check: e(Abar, W) = e(Bbar, g2)
//! 3. Schnorr proof for knowledge of hidden messages
//!
//! # Security
//!
//! Based on the q-SDH (Strong Diffie-Hellman) assumption in bilinear groups.

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BedrockError, Result};
use crate::pairing::{
    bls12_381::*,
    constants::MAX_CREDENTIAL_ATTRIBUTES,
    dst,
    hash_to_curve::{derive_generators, fiat_shamir_challenge, hash_to_scalar},
};

// ============================================================================
// Issuer Keys
// ============================================================================

/// BBS+ issuer secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IssuerSecretKey {
    /// The secret scalar x
    x: Scalar,
}

/// BBS+ issuer public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    /// w = g_2^x (in G2)
    pub w: G2Point,
    /// Message generators h_0, h_1, ..., h_n
    pub generators: Vec<G1Point>,
}

impl IssuerSecretKey {
    /// Generate a new issuer keypair for signing up to `max_messages` messages.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        max_messages: usize,
    ) -> Result<(Self, IssuerPublicKey)> {
        if max_messages > MAX_CREDENTIAL_ATTRIBUTES {
            return Err(BedrockError::TooManyAttributes {
                max: MAX_CREDENTIAL_ATTRIBUTES,
                got: max_messages,
            });
        }

        // Generate secret key
        let x = Scalar::random(rng);

        // Public key in G2
        let w = G2Point::generator().mul(&x);

        // Generate message generators (h_0 is for blinding, h_1..h_n for messages)
        let generators = derive_generators(dst::BBS_SIGN, max_messages + 1);

        Ok((
            IssuerSecretKey { x },
            IssuerPublicKey { w, generators },
        ))
    }

    /// Sign messages to create a BBS+ credential.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        messages: &[Scalar],
        public_key: &IssuerPublicKey,
        rng: &mut R,
    ) -> Result<BBSSignature> {
        if messages.len() > public_key.generators.len() - 1 {
            return Err(BedrockError::TooManyAttributes {
                max: public_key.generators.len() - 1,
                got: messages.len(),
            });
        }

        // Generate random e and s
        let e = Scalar::random(rng);
        let s = Scalar::random(rng);

        // Compute B = g_1 · h_0^s · h_1^m_1 · ... · h_n^m_n
        let mut b = G1Point::generator();
        b = b.add(&public_key.generators[0].mul(&s)); // h_0^s

        for (i, m) in messages.iter().enumerate() {
            b = b.add(&public_key.generators[i + 1].mul(m)); // h_i^m_i
        }

        // Compute A = B^(1/(x+e))
        let exp = self.x.add(&e);
        let exp_inv = exp.invert().ok_or(BedrockError::Internal(
            "Failed to invert (x+e)".into(),
        ))?;
        let a = b.mul(&exp_inv);

        Ok(BBSSignature { a, e, s })
    }

    /// Serialize secret key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes().to_vec()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SCALAR_SIZE {
            return Err(BedrockError::InvalidSecretKey);
        }
        let mut arr = [0u8; SCALAR_SIZE];
        arr.copy_from_slice(bytes);
        Ok(IssuerSecretKey {
            x: Scalar::from_bytes(&arr)?,
        })
    }
}

impl IssuerPublicKey {
    /// Verify a BBS+ signature.
    pub fn verify(&self, signature: &BBSSignature, messages: &[Scalar]) -> bool {
        if messages.len() > self.generators.len() - 1 {
            return false;
        }

        // Compute B = g_1 · h_0^s · h_1^m_1 · ... · h_n^m_n
        let mut b = G1Point::generator();
        b = b.add(&self.generators[0].mul(&signature.s));

        for (i, m) in messages.iter().enumerate() {
            b = b.add(&self.generators[i + 1].mul(m));
        }

        // Verify: e(A, w · g_2^e) == e(B, g_2)
        // Which is equivalent to: e(A, w) · e(A, g_2^e) == e(B, g_2)
        // Or: e(A, w · g_2^e) == e(B, g_2)

        let g2_e = G2Point::generator().mul(&signature.e);
        let w_plus_g2e = self.w.add(&g2_e);

        verify_pairing_eq(&signature.a, &w_plus_g2e, &b, &G2Point::generator())
    }

    /// Serialize to bytes (Fix #14: Now returns Result instead of silent failure).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| BedrockError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BedrockError::Deserialization(e.to_string()))
    }
}

// ============================================================================
// BBS+ Signature
// ============================================================================

/// A BBS+ signature on a set of messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BBSSignature {
    /// Signature component A ∈ G1
    pub a: G1Point,
    /// Random scalar e
    pub e: Scalar,
    /// Blinding scalar s
    pub s: Scalar,
}

impl BBSSignature {
    /// Serialize to bytes (Fix #14: Now returns Result instead of silent failure).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| BedrockError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BedrockError::Deserialization(e.to_string()))
    }
}

// ============================================================================
// Credential (signature + messages)
// ============================================================================

/// A BBS+ credential containing a signature and attribute values.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    /// The BBS+ signature
    pub signature: BBSSignature,
    /// Attribute values (as scalars)
    pub attributes: Vec<Scalar>,
}

impl Credential {
    /// Create a new credential from signature and attributes.
    pub fn new(signature: BBSSignature, attributes: Vec<Scalar>) -> Self {
        Credential { signature, attributes }
    }

    /// Verify the credential against an issuer's public key.
    pub fn verify(&self, issuer_pk: &IssuerPublicKey) -> bool {
        issuer_pk.verify(&self.signature, &self.attributes)
    }

    /// Generate a random non-zero scalar (Fix #13: prevents zero nonce issues).
    ///
    /// The probability of generating zero is ~2^-255, but if it happens,
    /// the Schnorr response would directly reveal the secret.
    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Scalar> {
        // Try up to 3 times (probability of 3 consecutive zeros is ~2^-765)
        for _ in 0..3 {
            let scalar = Scalar::random(rng);
            if !scalar.is_zero() {
                return Ok(scalar);
            }
        }
        Err(BedrockError::Internal("Failed to generate non-zero scalar".into()))
    }

    /// Create a zero-knowledge proof of credential possession.
    ///
    /// # Arguments
    ///
    /// * `issuer_pk` - The issuer's public key
    /// * `disclosed_indices` - Indices of attributes to reveal (sorted)
    /// * `verifier_challenge` - External challenge for binding (e.g., from verifier)
    /// * `rng` - Cryptographic RNG
    ///
    /// # Protocol (IETF BBS-aligned for BBS+)
    ///
    /// 1. Randomize signature: Abar = A * r1 * r2, D = B * r2, Bbar = D * r1 - Abar * e
    /// 2. Compute Schnorr commitments T1, T2
    /// 3. Fiat-Shamir challenge from public values
    /// 4. Compute responses
    ///
    /// # Returns
    ///
    /// A proof that can be verified without revealing hidden attributes.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        issuer_pk: &IssuerPublicKey,
        disclosed_indices: &[usize],
        verifier_challenge: &[u8],
        rng: &mut R,
    ) -> Result<CredentialProof> {
        // Validate disclosed indices
        for &idx in disclosed_indices {
            if idx >= self.attributes.len() {
                return Err(BedrockError::InvalidDisclosure);
            }
        }

        // =====================================================================
        // Step 1: Compute B = g1 + h_0*s + Σ h_i*m_i
        // =====================================================================
        let mut b = G1Point::generator();
        b = b.add(&issuer_pk.generators[0].mul(&self.signature.s));
        for (i, m) in self.attributes.iter().enumerate() {
            b = b.add(&issuer_pk.generators[i + 1].mul(m));
        }

        // =====================================================================
        // Step 2: Randomize signature for unlinkability
        // r1, r2 random non-zero scalars
        // r3 = 1/r2
        // =====================================================================
        let r1 = Scalar::random(rng);
        let r2 = Scalar::random(rng);
        let r3 = r2.invert().ok_or(BedrockError::Internal("r2 is zero".into()))?;

        // Abar = A * r1 * r2
        let r1_r2 = r1.mul(&r2);
        let a_bar = self.signature.a.mul(&r1_r2);

        // D = B * r2
        let d = b.mul(&r2);

        // Bbar = D * r1 - Abar * e
        let d_r1 = d.mul(&r1);
        let a_bar_e = a_bar.mul(&self.signature.e);
        let b_bar = d_r1.sub(&a_bar_e);

        // =====================================================================
        // Step 3: Generate Schnorr blindings
        // Witnesses: e, r1, r3, s, hidden messages
        //
        // Fix #13: Added zero-checks for all nonces to prevent secret leakage
        // in the extremely rare (~2^-255) case of zero nonce generation.
        // =====================================================================
        let blind_e = Self::random_nonzero_scalar(rng)?;
        let blind_r1 = Self::random_nonzero_scalar(rng)?;
        let blind_r3 = Self::random_nonzero_scalar(rng)?;
        let blind_s = Self::random_nonzero_scalar(rng)?;

        // Collect hidden attributes and their blindings
        let mut hidden_blindings: Vec<(usize, Scalar)> = Vec::new();
        for i in 0..self.attributes.len() {
            if !disclosed_indices.contains(&i) {
                hidden_blindings.push((i, Self::random_nonzero_scalar(rng)?));
            }
        }

        // =====================================================================
        // Step 4: Compute Schnorr commitments
        //
        // T1 commits to relation: Bbar = D * r1 - Abar * e
        // T1 = Abar * blind_e + D * blind_r1  (note: blind_e for -e, so Abar * blind_e)
        //
        // T2 commits to relation: D * r3 = B (which is g1 + h_0*s + Σ h_i*m_i)
        // T2 = D * blind_r3 + h_0 * blind_s + Σ_{hidden} h_j * blind_m_j
        // =====================================================================

        // T1 = Abar * blind_e + D * blind_r1
        // (Proves knowledge of e, r1 in Bbar = D*r1 - Abar*e)
        let t1 = a_bar.mul(&blind_e).add(&d.mul(&blind_r1));

        // T2 = D * blind_r3 + h_0 * blind_s + Σ_{hidden} h_j * blind_m_j
        // (Proves knowledge of r3, s, hidden messages in D*r3 = g1 + h_0*s + Σ h_i*m_i)
        let mut t2 = d.mul(&blind_r3);
        t2 = t2.add(&issuer_pk.generators[0].mul(&blind_s));
        for &(idx, ref blind) in &hidden_blindings {
            t2 = t2.add(&issuer_pk.generators[idx + 1].mul(blind));
        }

        // =====================================================================
        // Step 5: Compute Fiat-Shamir challenge
        //
        // Hash order (IETF-inspired):
        // (verifier_challenge, R, [i1, msg_i1, ...], Abar, Bbar, D, T1, T2)
        // =====================================================================
        let mut challenge_input = Vec::new();

        // Verifier's external challenge
        challenge_input.extend_from_slice(verifier_challenge);

        // Number of disclosed messages (as 8 bytes)
        let num_disclosed = disclosed_indices.len() as u64;
        challenge_input.extend_from_slice(&num_disclosed.to_be_bytes());

        // Interleaved: (index, message) pairs for disclosed attributes
        let mut sorted_disclosed: Vec<usize> = disclosed_indices.to_vec();
        sorted_disclosed.sort();
        for &idx in &sorted_disclosed {
            challenge_input.extend_from_slice(&(idx as u64).to_be_bytes());
            challenge_input.extend_from_slice(&self.attributes[idx].to_bytes());
        }

        // Randomized signature components
        challenge_input.extend_from_slice(&a_bar.to_bytes());
        challenge_input.extend_from_slice(&b_bar.to_bytes());
        challenge_input.extend_from_slice(&d.to_bytes());

        // Schnorr commitments
        challenge_input.extend_from_slice(&t1.to_bytes());
        challenge_input.extend_from_slice(&t2.to_bytes());

        let c = hash_to_scalar(&challenge_input, dst::BBS_PROOF);

        // =====================================================================
        // Step 6: Compute Schnorr responses
        //
        // response = blinding + witness * challenge
        // (Some protocols use - instead of +; we use + consistently here)
        // =====================================================================

        // For T1 relation (Bbar = D*r1 - Abar*e):
        // Statement: D*r1 + Abar*(-e) = Bbar
        // Witnesses: r1 (positive), -e (negated)
        // resp_e uses MINUS because we're proving knowledge of -e
        // resp_r1 uses PLUS because we're proving knowledge of r1
        let resp_e = blind_e.sub(&c.mul(&self.signature.e));  // MINUS for -e witness
        let resp_r1 = blind_r1.add(&c.mul(&r1));              // PLUS for r1 witness

        // For T2 relation (D*r3 = g1 + h_0*s + Σ h_i*m_i):
        // Rearranged: D*r3 + h_0*(-s) + Σ h_j*(-m_j) = Bv
        // Witnesses: r3 (positive), -s (negated), -m_j (negated)
        // resp_r3 uses PLUS, resp_s and resp_m_j use MINUS
        let resp_r3 = blind_r3.add(&c.mul(&r3));                      // PLUS for r3 witness
        let resp_s = blind_s.sub(&c.mul(&self.signature.s));          // MINUS for -s witness

        let mut hidden_responses: Vec<(usize, Scalar)> = Vec::new();
        for &(idx, ref blind) in &hidden_blindings {
            let resp = blind.sub(&c.mul(&self.attributes[idx]));      // MINUS for -m_j witness
            hidden_responses.push((idx, resp));
        }

        // =====================================================================
        // Step 7: Collect disclosed attributes
        // =====================================================================
        let disclosed: Vec<(usize, Scalar)> = sorted_disclosed
            .iter()
            .map(|&i| (i, self.attributes[i].clone()))
            .collect();

        Ok(CredentialProof {
            a_bar,
            b_bar,
            d,
            challenge: c,
            resp_e,
            resp_r1,
            resp_r3,
            resp_s,
            hidden_responses,
            disclosed,
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

// ============================================================================
// Credential Proof
// ============================================================================

/// Zero-knowledge proof of BBS+ credential possession.
///
/// Structure based on IETF BBS spec:
/// - Abar, Bbar, D: Randomized signature components
/// - T1, T2: Schnorr commitments (included in challenge, reconstructed in verify)
/// - Responses: Schnorr responses for hidden values
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Randomized signature: Abar = A * r1 * r2
    pub a_bar: G1Point,
    /// Randomized: Bbar = D * r1 - Abar * e
    pub b_bar: G1Point,
    /// Randomized: D = B * r2
    pub d: G1Point,
    /// Fiat-Shamir challenge
    pub challenge: Scalar,
    /// Response for e (signature exponent)
    pub resp_e: Scalar,
    /// Response for r1 (first randomizer)
    pub resp_r1: Scalar,
    /// Response for r3 = 1/r2 (inverse of second randomizer)
    pub resp_r3: Scalar,
    /// Response for s (blinding factor)
    pub resp_s: Scalar,
    /// Responses for hidden attributes (index, response)
    pub hidden_responses: Vec<(usize, Scalar)>,
    /// Disclosed attributes (index, value)
    pub disclosed: Vec<(usize, Scalar)>,
}

impl CredentialProof {
    /// Verify the credential proof.
    ///
    /// # Arguments
    ///
    /// * `issuer_pk` - The issuer's public key
    /// * `verifier_challenge` - The external challenge used during proof generation
    ///
    /// # Verification Steps
    ///
    /// 1. Check Abar is not identity
    /// 2. Verify pairing: e(Abar, W) = e(Bbar, g2)
    /// 3. Reconstruct T1, T2 from responses and challenge
    /// 4. Recompute challenge and verify it matches
    ///
    /// # Returns
    ///
    /// Ok with disclosed attributes if valid, Err otherwise.
    pub fn verify(
        &self,
        issuer_pk: &IssuerPublicKey,
        verifier_challenge: &[u8],
    ) -> Result<Vec<(usize, Scalar)>> {
        let c = &self.challenge;

        // =====================================================================
        // Step 1: Check Abar is not identity (prevents trivial proofs)
        // =====================================================================
        if self.a_bar.is_identity() {
            return Err(BedrockError::InvalidProof);
        }

        // =====================================================================
        // Step 2: Verify pairing equation
        //
        // The randomization satisfies: e(Abar, W) = e(Bbar, g2)
        //
        // Proof:
        // - Abar = A * r1 * r2
        // - Bbar = B * r1 * r2 - A * r1 * r2 * e = (B - A*e) * r1 * r2
        // - From signature: A = B^(1/(x+e)), so A*(x+e) = B, meaning B - A*e = A*x
        // - Thus Bbar = A*x * r1*r2 = Abar * x
        // - And e(Abar, W) = e(Abar, g2*x) = e(Abar*x, g2) = e(Bbar, g2) ✓
        // =====================================================================
        if !verify_pairing_eq(&self.a_bar, &issuer_pk.w, &self.b_bar, &G2Point::generator()) {
            return Err(BedrockError::VerificationFailed);
        }

        // =====================================================================
        // Step 3: Reconstruct T1 from responses
        //
        // Original T1 = Abar * blind_e + D * blind_r1
        //
        // Using resp_e = blind_e - e*c and resp_r1 = blind_r1 + r1*c:
        // T1 = Abar * resp_e + D * resp_r1 + Abar * e * c - D * r1 * c
        //    = Abar * resp_e + D * resp_r1 + c * (Abar * e - D * r1)
        //    = Abar * resp_e + D * resp_r1 - c * Bbar   (since Bbar = D*r1 - Abar*e)
        // =====================================================================
        let t1_reconstructed = self.a_bar.mul(&self.resp_e)
            .add(&self.d.mul(&self.resp_r1))
            .add(&self.b_bar.mul(&c.neg()));

        // =====================================================================
        // Step 4: Compute Bv (partial B from disclosed messages)
        //
        // Bv = g1 + Σ_{disclosed} h_i * m_i
        // =====================================================================
        let mut bv = G1Point::generator();
        for &(idx, ref value) in &self.disclosed {
            if idx + 1 >= issuer_pk.generators.len() {
                return Err(BedrockError::InvalidProof);
            }
            bv = bv.add(&issuer_pk.generators[idx + 1].mul(value));
        }

        // =====================================================================
        // Step 5: Reconstruct T2 from responses
        //
        // Original T2 = D * blind_r3 + h_0 * blind_s + Σ_{hidden} h_j * blind_m_j
        //
        // Using resp_r3 = blind_r3 + r3*c, resp_s = blind_s - s*c, resp_m = blind_m - m*c:
        //
        // T2 = D * resp_r3 + h_0 * resp_s + Σ h_j * resp_m_j
        //      + c * (h_0 * s + Σ h_j * m_j - D * r3)
        //
        // Since D = B * r2 and r3 = 1/r2, we have D * r3 = B.
        // And B = g1 + h_0*s + Σ h_i*m_i.
        //
        // So c * (h_0*s + Σ h_j*m_j - D*r3) = c * (h_0*s + Σ h_j*m_j - B)
        //    = c * (h_0*s + Σ h_j*m_j - g1 - h_0*s - Σ h_i*m_i)
        //    = c * (Σ_{hidden} h_j*m_j - g1 - Σ_{disclosed} h_i*m_i - Σ_{hidden} h_j*m_j)
        //    = c * (-g1 - Σ_{disclosed} h_i*m_i)
        //    = -c * Bv
        //
        // Therefore: T2 = D * resp_r3 + h_0 * resp_s + Σ h_j * resp_m_j - c * Bv
        // =====================================================================
        let mut t2_reconstructed = self.d.mul(&self.resp_r3);
        t2_reconstructed = t2_reconstructed.add(&issuer_pk.generators[0].mul(&self.resp_s));

        // Add hidden message responses
        for &(idx, ref resp) in &self.hidden_responses {
            if idx + 1 >= issuer_pk.generators.len() {
                return Err(BedrockError::InvalidProof);
            }
            t2_reconstructed = t2_reconstructed.add(&issuer_pk.generators[idx + 1].mul(resp));
        }

        // Subtract c * Bv
        t2_reconstructed = t2_reconstructed.add(&bv.mul(&c.neg()));

        // =====================================================================
        // Step 6: Recompute challenge hash and verify
        //
        // Must match the order from prove():
        // (verifier_challenge, R, [i1, msg_i1, ...], Abar, Bbar, D, T1, T2)
        // =====================================================================
        let mut challenge_input = Vec::new();

        // Verifier's external challenge
        challenge_input.extend_from_slice(verifier_challenge);

        // Number of disclosed messages (as 8 bytes)
        let num_disclosed = self.disclosed.len() as u64;
        challenge_input.extend_from_slice(&num_disclosed.to_be_bytes());

        // Interleaved: (index, message) pairs for disclosed attributes
        // Note: disclosed should already be sorted from prove()
        for &(idx, ref value) in &self.disclosed {
            challenge_input.extend_from_slice(&(idx as u64).to_be_bytes());
            challenge_input.extend_from_slice(&value.to_bytes());
        }

        // Randomized signature components
        challenge_input.extend_from_slice(&self.a_bar.to_bytes());
        challenge_input.extend_from_slice(&self.b_bar.to_bytes());
        challenge_input.extend_from_slice(&self.d.to_bytes());

        // Reconstructed Schnorr commitments
        challenge_input.extend_from_slice(&t1_reconstructed.to_bytes());
        challenge_input.extend_from_slice(&t2_reconstructed.to_bytes());

        let expected_c = hash_to_scalar(&challenge_input, dst::BBS_PROOF);

        if self.challenge != expected_c {
            return Err(BedrockError::VerificationFailed);
        }

        Ok(self.disclosed.clone())
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_issuer_key_generation() {
        let mut rng = OsRng;
        let (sk, pk) = IssuerSecretKey::generate(&mut rng, 5).unwrap();

        // Public key should have 6 generators (h_0 + 5 message generators)
        assert_eq!(pk.generators.len(), 6);

        // w should not be identity
        assert!(!pk.w.is_identity());
    }

    #[test]
    fn test_signature_creation_and_verification() {
        let mut rng = OsRng;
        let (sk, pk) = IssuerSecretKey::generate(&mut rng, 3).unwrap();

        // Create messages
        let messages = vec![
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];

        // Sign
        let signature = sk.sign(&messages, &pk, &mut rng).unwrap();

        // Verify
        assert!(pk.verify(&signature, &messages));

        // Verification should fail with wrong messages
        let wrong_messages = vec![
            Scalar::random(&mut rng),
            messages[1].clone(),
            messages[2].clone(),
        ];
        assert!(!pk.verify(&signature, &wrong_messages));
    }

    #[test]
    fn test_credential_proof() {
        let mut rng = OsRng;
        let (sk, pk) = IssuerSecretKey::generate(&mut rng, 4).unwrap();

        // Create credential with 4 attributes
        let attributes = vec![
            Scalar::random(&mut rng), // Attribute 0
            Scalar::random(&mut rng), // Attribute 1
            Scalar::random(&mut rng), // Attribute 2
            Scalar::random(&mut rng), // Attribute 3
        ];

        let signature = sk.sign(&attributes, &pk, &mut rng).unwrap();
        let credential = Credential::new(signature, attributes.clone());

        // Verify credential
        assert!(credential.verify(&pk));

        // Create proof disclosing only attributes 0 and 2
        let challenge = b"verifier challenge";
        let proof = credential
            .prove(&pk, &[0, 2], challenge, &mut rng)
            .unwrap();

        // Verify proof
        let disclosed = proof.verify(&pk, challenge).unwrap();

        // Check disclosed attributes
        assert_eq!(disclosed.len(), 2);
        assert_eq!(disclosed[0].0, 0);
        assert_eq!(disclosed[0].1, attributes[0]);
        assert_eq!(disclosed[1].0, 2);
        assert_eq!(disclosed[1].1, attributes[2]);
    }

    #[test]
    fn test_proof_unlinkability() {
        let mut rng = OsRng;
        let (sk, pk) = IssuerSecretKey::generate(&mut rng, 2).unwrap();

        let attributes = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let signature = sk.sign(&attributes, &pk, &mut rng).unwrap();
        let credential = Credential::new(signature, attributes);

        // Create two proofs from the same credential
        let challenge = b"challenge";
        let proof1 = credential.prove(&pk, &[0], challenge, &mut rng).unwrap();
        let proof2 = credential.prove(&pk, &[0], challenge, &mut rng).unwrap();

        // Both should verify
        assert!(proof1.verify(&pk, challenge).is_ok());
        assert!(proof2.verify(&pk, challenge).is_ok());

        // But Abar values should be different (unlinkable)
        assert_ne!(proof1.a_bar, proof2.a_bar);
    }

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;
        let (sk, pk) = IssuerSecretKey::generate(&mut rng, 2).unwrap();

        // Serialize and deserialize public key
        let pk_bytes = pk.to_bytes().unwrap();
        let pk_recovered = IssuerPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.w, pk_recovered.w);
        assert_eq!(pk.generators.len(), pk_recovered.generators.len());

        // Serialize and deserialize signature
        let messages = vec![Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let sig = sk.sign(&messages, &pk, &mut rng).unwrap();
        let sig_bytes = sig.to_bytes().unwrap();
        let sig_recovered = BBSSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig.a, sig_recovered.a);
    }
}
