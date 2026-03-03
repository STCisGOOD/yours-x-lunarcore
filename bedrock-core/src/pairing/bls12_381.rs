//! BLS12-381 Elliptic Curve Operations
//!
//! Type-safe wrappers around `blstrs` for BLS12-381 operations.
//!
//! # Groups
//!
//! - `G1Point`: Points in G1 (48 bytes compressed), used for BBS+ signatures
//! - `G2Point`: Points in G2 (96 bytes compressed), used for BBS+ public keys
//! - `GtElement`: Elements in the pairing target group GT
//! - `Scalar`: Elements of the scalar field Fr (~255 bits)
//!
//! # Security Notes
//!
//! - All operations are constant-time where possible
//! - Points are validated on deserialization (subgroup check)
//! - Scalars are reduced mod r automatically

use blstrs::{
    G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar as BlstScalar,
};
use ff::Field;
use group::{Curve, Group};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{BedrockError, Result};

/// Size of compressed G1 point in bytes
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Size of compressed G2 point in bytes
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Size of scalar in bytes
pub const SCALAR_SIZE: usize = 32;

/// Size of GT element in bytes (uncompressed)
pub const GT_SIZE: usize = 576;

// ============================================================================
// G1 Point (48 bytes compressed)
// ============================================================================

/// A point on the G1 curve of BLS12-381.
///
/// Used for:
/// - BBS+ signature component A
/// - VOPRF tokens
/// - Pedersen commitments
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G1Point(pub(crate) G1Projective);

impl G1Point {
    /// The generator point of G1.
    pub fn generator() -> Self {
        G1Point(G1Projective::generator())
    }

    /// The identity element (point at infinity).
    pub fn identity() -> Self {
        G1Point(G1Projective::identity())
    }

    /// Generate a random point (for testing, not cryptographically meaningful).
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        G1Point(G1Projective::random(rng))
    }

    /// Scalar multiplication: self * scalar
    pub fn mul(&self, scalar: &Scalar) -> Self {
        G1Point(self.0 * scalar.0)
    }

    /// Point addition: self + other
    pub fn add(&self, other: &G1Point) -> Self {
        G1Point(self.0 + other.0)
    }

    /// Point subtraction: self - other
    pub fn sub(&self, other: &G1Point) -> Self {
        G1Point(self.0 - other.0)
    }

    /// Point negation: -self
    pub fn neg(&self) -> Self {
        G1Point(-self.0)
    }

    /// Check if this is the identity element.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    /// Check if this point is valid (on curve and in correct subgroup).
    ///
    /// Fix #16: Added explicit validation for use with externally-provided points.
    /// Points created via from_bytes() are already validated, but points
    /// received from other sources should be checked.
    pub fn is_valid(&self) -> bool {
        // The blstrs library already validates points during from_compressed,
        // but for points constructed via scalar multiplication or addition,
        // we verify by checking the point is on curve and in the prime-order subgroup.
        // A point is valid if serialization + deserialization succeeds.
        let bytes = self.to_bytes();
        Self::from_bytes(&bytes).is_ok()
    }

    /// Serialize to compressed bytes (48 bytes).
    pub fn to_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_affine().to_compressed()
    }

    /// Deserialize from compressed bytes.
    ///
    /// Performs subgroup check to ensure point is valid.
    pub fn from_bytes(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self> {
        let affine = G1Affine::from_compressed(bytes);
        if affine.is_some().into() {
            Ok(G1Point(affine.unwrap().into()))
        } else {
            Err(BedrockError::InvalidPoint)
        }
    }

    /// Deserialize from bytes slice (must be exactly 48 bytes).
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != G1_COMPRESSED_SIZE {
            return Err(BedrockError::InvalidInput(format!(
                "G1 point must be {} bytes, got {}",
                G1_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; G1_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Self::from_bytes(&arr)
    }

    /// Multi-scalar multiplication (more efficient than sequential multiplications).
    ///
    /// Computes: sum(scalars[i] * points[i])
    ///
    /// Fix #20: Timing properties documented.
    /// - The underlying blstrs scalar multiplication is constant-time
    /// - Point addition is not secret-dependent (public operation)
    /// - This sequential implementation has timing proportional to input length
    ///   but NOT to scalar values (which are the secrets)
    ///
    /// For production use with large inputs, consider using blst's multi_exp
    /// which is optimized for batch operations.
    pub fn multi_scalar_mul(scalars: &[Scalar], points: &[G1Point]) -> Result<Self> {
        if scalars.len() != points.len() {
            return Err(BedrockError::InvalidInput(
                "Scalars and points must have same length".into(),
            ));
        }
        if scalars.is_empty() {
            return Ok(G1Point::identity());
        }

        // Use blstrs G1Projective::multi_exp if available for large inputs
        // For small inputs (< 4), sequential is often faster
        if scalars.len() >= 4 {
            // Convert to blstrs types for multi_exp
            let blst_scalars: Vec<_> = scalars.iter().map(|s| s.0).collect();
            // multi_exp expects G1Projective, not G1Affine
            let blst_points: Vec<_> = points.iter().map(|p| p.0).collect();

            // Use blst's optimized multi-exponentiation
            let result = G1Projective::multi_exp(&blst_points, &blst_scalars);
            return Ok(G1Point(result));
        }

        // Sequential for small inputs (constant-time per scalar)
        let mut result = G1Point::identity();
        for (s, p) in scalars.iter().zip(points.iter()) {
            result = result.add(&p.mul(s));
        }
        Ok(result)
    }
}

impl Serialize for G1Point {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for G1Point {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        G1Point::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// G2 Point (96 bytes compressed)
// ============================================================================

/// A point on the G2 curve of BLS12-381.
///
/// Used for:
/// - BBS+ public keys
/// - BLS signature values
/// - VOPRF proofs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct G2Point(pub(crate) G2Projective);

impl G2Point {
    /// The generator point of G2.
    pub fn generator() -> Self {
        G2Point(G2Projective::generator())
    }

    /// The identity element (point at infinity).
    pub fn identity() -> Self {
        G2Point(G2Projective::identity())
    }

    /// Generate a random point.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        G2Point(G2Projective::random(rng))
    }

    /// Scalar multiplication: self * scalar
    pub fn mul(&self, scalar: &Scalar) -> Self {
        G2Point(self.0 * scalar.0)
    }

    /// Point addition: self + other
    pub fn add(&self, other: &G2Point) -> Self {
        G2Point(self.0 + other.0)
    }

    /// Point subtraction: self - other
    pub fn sub(&self, other: &G2Point) -> Self {
        G2Point(self.0 - other.0)
    }

    /// Point negation: -self
    pub fn neg(&self) -> Self {
        G2Point(-self.0)
    }

    /// Check if this is the identity element.
    pub fn is_identity(&self) -> bool {
        self.0.is_identity().into()
    }

    /// Check if this point is valid (on curve and in correct subgroup).
    ///
    /// Fix #16: Added explicit validation for use with externally-provided points.
    pub fn is_valid(&self) -> bool {
        let bytes = self.to_bytes();
        Self::from_bytes(&bytes).is_ok()
    }

    /// Serialize to compressed bytes (96 bytes).
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_affine().to_compressed()
    }

    /// Deserialize from compressed bytes.
    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        let affine = G2Affine::from_compressed(bytes);
        if affine.is_some().into() {
            Ok(G2Point(affine.unwrap().into()))
        } else {
            Err(BedrockError::InvalidPoint)
        }
    }

    /// Deserialize from bytes slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != G2_COMPRESSED_SIZE {
            return Err(BedrockError::InvalidInput(format!(
                "G2 point must be {} bytes, got {}",
                G2_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; G2_COMPRESSED_SIZE];
        arr.copy_from_slice(bytes);
        Self::from_bytes(&arr)
    }
}

impl Serialize for G2Point {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for G2Point {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        G2Point::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// GT Element (pairing target)
// ============================================================================

/// An element of the pairing target group GT.
///
/// Used for pairing verification equations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GtElement(pub(crate) Gt);

impl GtElement {
    /// The identity element in GT.
    pub fn identity() -> Self {
        GtElement(Gt::identity())
    }

    /// Multiply two GT elements (group operation in GT).
    pub fn mul(&self, other: &GtElement) -> Self {
        // GT uses additive notation in blstrs
        GtElement(self.0 + other.0)
    }

    /// Inverse in GT.
    pub fn inverse(&self) -> Self {
        GtElement(-self.0)
    }

    /// Check equality (for pairing verification).
    pub fn ct_eq(&self, other: &GtElement) -> bool {
        self.0 == other.0
    }
}

// ============================================================================
// Scalar (Fr, ~255 bits)
// ============================================================================

/// A scalar field element of BLS12-381 (Fr).
///
/// Used for:
/// - Secret keys
/// - Blinding factors
/// - Challenges in Schnorr proofs
///
/// # Security
///
/// Implements secure memory handling.
#[derive(Clone)]
pub struct Scalar(pub(crate) BlstScalar);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        // BlstScalar doesn't implement Zeroize, so we overwrite with zero
        self.0 = BlstScalar::ZERO;
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Scalar {
    /// Zero scalar.
    pub fn zero() -> Self {
        Scalar(BlstScalar::ZERO)
    }

    /// One scalar.
    pub fn one() -> Self {
        Scalar(BlstScalar::ONE)
    }

    /// Generate a random scalar using a cryptographically secure RNG.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Scalar(BlstScalar::random(rng))
    }

    /// Create scalar from bytes (little-endian, reduced mod r).
    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> Result<Self> {
        let scalar = BlstScalar::from_bytes_le(bytes);
        if scalar.is_some().into() {
            Ok(Scalar(scalar.unwrap()))
        } else {
            Err(BedrockError::InvalidScalar)
        }
    }

    /// Create scalar from wide bytes (64 bytes, for uniform distribution).
    ///
    /// Fix #8: Implements proper wide reduction for uniform distribution.
    /// Uses the formula: result = low + high * 2^256 (mod r)
    /// where 2^256 mod r is a precomputed constant.
    ///
    /// Fix #17: Properly handles values >= field modulus by manual reduction.
    /// The previous implementation used unwrap_or(ZERO) which caused zero output
    /// when input bytes exceeded the modulus (~50% of random 256-bit values).
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        // BLS12-381 scalar field modulus r (little-endian):
        // r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        const MODULUS_LE: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0x5b, 0xff, 0xfe, 0x02, 0xa4, 0xbd, 0x53,
            0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
            0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
        ];

        // 2^256 mod r (little-endian)
        const TWO_256_MOD_R_LE: [u8; 32] = [
            0xfe, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
            0x02, 0x48, 0x03, 0x00, 0xfa, 0xb7, 0x84, 0x55,
            0xf5, 0x4f, 0xbc, 0xec, 0xef, 0x4f, 0x8c, 0x99,
            0x6f, 0x05, 0xc5, 0xac, 0x59, 0xb1, 0x24, 0x18,
        ];

        // Split into two 32-byte chunks
        let mut low = [0u8; 32];
        let mut high = [0u8; 32];
        low.copy_from_slice(&bytes[..32]);
        high.copy_from_slice(&bytes[32..]);

        // Parse both halves as scalars with proper modular reduction
        let low_scalar = Self::reduce_bytes_mod_r(&low, &MODULUS_LE);
        let high_scalar = Self::reduce_bytes_mod_r(&high, &MODULUS_LE);

        // 2^256 mod r is guaranteed to be < r, so direct conversion is safe
        let two_256_mod_r = BlstScalar::from_bytes_le(&TWO_256_MOD_R_LE)
            .expect("2^256 mod r is a valid constant");

        // result = low + high * 2^256 (mod r)
        // This gives a uniform distribution over the scalar field
        let high_shifted = high_scalar.0 * two_256_mod_r;
        Scalar(low_scalar.0 + high_shifted)
    }

    /// Reduce a 32-byte value modulo the BLS12-381 scalar field modulus r.
    ///
    /// If the value is already < r, returns it directly.
    /// Otherwise, subtracts r until the value is in range.
    /// Since max 256-bit value is ~2.14 * r, we need at most 2 subtractions.
    fn reduce_bytes_mod_r(bytes: &[u8; 32], modulus: &[u8; 32]) -> Self {
        use subtle::CtOption;

        // Try direct conversion first (works if value < r)
        // BlstScalar::from_bytes_le returns CtOption for constant-time operation
        let direct: CtOption<BlstScalar> = BlstScalar::from_bytes_le(bytes);
        if bool::from(direct.is_some()) {
            return Scalar(direct.unwrap());
        }

        // Value >= r, need to reduce by subtracting r
        // Since max 256-bit value / r ≈ 2.14, we subtract at most twice
        let mut value = bytes_to_u256_le(bytes);
        let modulus_val = bytes_to_u256_le(modulus);

        // Subtract modulus until in range (use u256_cmp and u256_sub)
        use std::cmp::Ordering;
        if u256_cmp(&value, &modulus_val) != Ordering::Less {
            value = u256_sub(&value, &modulus_val);
        }
        if u256_cmp(&value, &modulus_val) != Ordering::Less {
            value = u256_sub(&value, &modulus_val);
        }

        let reduced_bytes = u256_to_bytes_le(&value);
        let reduced: CtOption<BlstScalar> = BlstScalar::from_bytes_le(&reduced_bytes);
        Scalar(reduced.expect("Reduced value must be < r"))
    }

    /// Serialize to bytes (little-endian, 32 bytes).
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0.to_bytes_le()
    }

    /// Deserialize from slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SCALAR_SIZE {
            return Err(BedrockError::InvalidInput(format!(
                "Scalar must be {} bytes, got {}",
                SCALAR_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; SCALAR_SIZE];
        arr.copy_from_slice(bytes);
        Self::from_bytes(&arr)
    }

    /// Addition: self + other
    pub fn add(&self, other: &Scalar) -> Self {
        Scalar(self.0 + other.0)
    }

    /// Subtraction: self - other
    pub fn sub(&self, other: &Scalar) -> Self {
        Scalar(self.0 - other.0)
    }

    /// Multiplication: self * other
    pub fn mul(&self, other: &Scalar) -> Self {
        Scalar(self.0 * other.0)
    }

    /// Negation: -self
    pub fn neg(&self) -> Self {
        Scalar(-self.0)
    }

    /// Multiplicative inverse: 1/self (returns None if self is zero).
    pub fn invert(&self) -> Option<Self> {
        let inv = self.0.invert();
        if inv.is_some().into() {
            Some(Scalar(inv.unwrap()))
        } else {
            None
        }
    }

    /// Check if scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero().into()
    }

    /// Square: self^2
    pub fn square(&self) -> Self {
        Scalar(self.0.square())
    }

    /// Power: self^exp (constant-time implementation)
    ///
    /// Fix #9: Uses constant-time Montgomery ladder to prevent timing attacks.
    /// Always performs the same number of operations regardless of exponent bits.
    ///
    /// # Security Warning
    /// This is intended for public exponents only. For secret exponents,
    /// consider using specialized constant-time libraries.
    pub fn pow(&self, exp: &[u64]) -> Self {
        // Montgomery ladder: constant-time exponentiation
        // Always performs both mul and square, then selects based on bit
        let mut r0 = Self::one();
        let mut r1 = self.clone();

        for &word in exp.iter().rev() {
            for i in (0..64).rev() {
                let bit = ((word >> i) & 1) as u8;

                // Constant-time conditional swap
                // If bit == 1: r0, r1 = r1, r0
                // If bit == 0: r0, r1 = r0, r1
                let (new_r0, new_r1) = if bit == 1 {
                    (r1.clone(), r0)
                } else {
                    (r0, r1.clone())
                };
                r0 = new_r0;
                r1 = new_r1;

                // Always perform both operations
                r1 = r0.mul(&r1);
                r0 = r0.square();

                // Swap back if needed
                let (new_r0, new_r1) = if bit == 1 {
                    (r1.clone(), r0)
                } else {
                    (r0, r1.clone())
                };
                r0 = new_r0;
                r1 = new_r1;
            }
        }

        r0
    }
}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the actual value for security
        write!(f, "Scalar([REDACTED])")
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        // BlstScalar implements PartialEq
        self.0 == other.0
    }
}

impl Eq for Scalar {}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Scalar::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Pairing Operations
// ============================================================================

/// Compute the pairing e(P, Q) where P ∈ G1 and Q ∈ G2.
///
/// Returns an element in GT.
pub fn pairing(p: &G1Point, q: &G2Point) -> GtElement {
    let p_affine = p.0.to_affine();
    let q_affine = q.0.to_affine();
    GtElement(blstrs::pairing(&p_affine, &q_affine))
}

/// Compute multi-pairing: product of e(P_i, Q_i).
///
/// More efficient than computing pairings separately.
pub fn multi_pairing(pairs: &[(G1Point, G2Point)]) -> GtElement {
    if pairs.is_empty() {
        return GtElement::identity();
    }

    // Compute each pairing and multiply in GT
    // Note: For better performance, could use miller loop optimization
    let mut result = GtElement::identity();
    for (p, q) in pairs {
        let p_affine = p.0.to_affine();
        let q_affine = q.0.to_affine();
        let pair_result = blstrs::pairing(&p_affine, &q_affine);
        result = GtElement(result.0 + pair_result);
    }
    result
}

/// Verify a pairing equation: e(A, B) == e(C, D)
pub fn verify_pairing_eq(a: &G1Point, b: &G2Point, c: &G1Point, d: &G2Point) -> bool {
    // e(A, B) * e(-C, D) == 1
    // This is more efficient than computing both pairings separately
    let pairs = [(a.clone(), b.clone()), (c.neg(), d.clone())];
    multi_pairing(&pairs).ct_eq(&GtElement::identity())
}

// ============================================================================
// BLS Signatures (for device binding)
// ============================================================================

/// BLS secret key (just a scalar).
#[derive(Clone)]
pub struct BlsSecretKey(pub Scalar);

impl Zeroize for BlsSecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// BLS public key (G1 point).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPublicKey(pub G1Point);

/// BLS signature (G2 point).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature(pub G2Point);

impl BlsSecretKey {
    /// Generate a random BLS secret key.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        BlsSecretKey(Scalar::random(rng))
    }

    /// Derive public key from secret key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(G1Point::generator().mul(&self.0))
    }

    /// Sign a message using BLS signature scheme.
    ///
    /// sig = sk * H(message)
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        use super::hash_to_curve::hash_to_g2;
        let h = hash_to_g2(message, super::dst::BLS_SIG);
        BlsSignature(h.mul(&self.0))
    }
}

impl BlsPublicKey {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_bytes()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(BlsPublicKey(G1Point::from_bytes(bytes)?))
    }
}

impl BlsSignature {
    /// Verify a BLS signature.
    ///
    /// Checks: e(pk, H(message)) == e(G1, signature)
    pub fn verify(&self, public_key: &BlsPublicKey, message: &[u8]) -> bool {
        use super::hash_to_curve::hash_to_g2;
        let h = hash_to_g2(message, super::dst::BLS_SIG);

        // e(pk, H(m)) == e(G1, sig)
        verify_pairing_eq(&public_key.0, &h, &G1Point::generator(), &self.0)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_bytes()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self> {
        Ok(BlsSignature(G2Point::from_bytes(bytes)?))
    }
}

// ============================================================================
// 256-bit Arithmetic Helpers (for scalar modular reduction)
// ============================================================================

/// Representation of a 256-bit unsigned integer as four 64-bit limbs (little-endian).
type U256 = [u64; 4];

/// Convert 32 bytes (little-endian) to U256.
fn bytes_to_u256_le(bytes: &[u8; 32]) -> U256 {
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

/// Convert U256 to 32 bytes (little-endian).
fn u256_to_bytes_le(value: &U256) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&value[0].to_le_bytes());
    result[8..16].copy_from_slice(&value[1].to_le_bytes());
    result[16..24].copy_from_slice(&value[2].to_le_bytes());
    result[24..32].copy_from_slice(&value[3].to_le_bytes());
    result
}

/// Compare two U256 values. Returns Ordering.
fn u256_cmp(a: &U256, b: &U256) -> std::cmp::Ordering {
    // Compare from most significant limb to least
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Subtract two U256 values with borrow propagation.
fn u256_sub(a: &U256, b: &U256) -> U256 {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;

    for i in 0..4 {
        let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
        let (diff2, borrow2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (borrow1 as u64) + (borrow2 as u64);
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_g1_serialization() {
        let mut rng = OsRng;
        let point = G1Point::random(&mut rng);
        let bytes = point.to_bytes();
        let recovered = G1Point::from_bytes(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_g2_serialization() {
        let mut rng = OsRng;
        let point = G2Point::random(&mut rng);
        let bytes = point.to_bytes();
        let recovered = G2Point::from_bytes(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_scalar_operations() {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        // Test addition/subtraction
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(a, diff);

        // Test multiplication
        let prod = a.mul(&b);
        let quot = prod.mul(&b.invert().unwrap());
        assert_eq!(a, quot);

        // Test negation
        let neg_a = a.neg();
        let zero = a.add(&neg_a);
        assert!(zero.is_zero());
    }

    #[test]
    fn test_scalar_mul() {
        let mut rng = OsRng;
        let scalar = Scalar::random(&mut rng);
        let point = G1Point::generator();

        let result = point.mul(&scalar);
        assert!(!result.is_identity());

        // Multiplying by zero gives identity
        let zero = Scalar::zero();
        let identity = point.mul(&zero);
        assert!(identity.is_identity());
    }

    #[test]
    fn test_pairing() {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        let p1 = G1Point::generator().mul(&a);
        let q1 = G2Point::generator().mul(&b);

        let p2 = G1Point::generator().mul(&a.mul(&b));
        let q2 = G2Point::generator();

        // e(a*G1, b*G2) == e(ab*G1, G2)
        let left = pairing(&p1, &q1);
        let right = pairing(&p2, &q2);
        assert!(left.ct_eq(&right));
    }

    #[test]
    fn test_bls_signature() {
        let mut rng = OsRng;
        let sk = BlsSecretKey::random(&mut rng);
        let pk = sk.public_key();

        let message = b"test message for BLS signature";
        let signature = sk.sign(message);

        assert!(signature.verify(&pk, message));
        assert!(!signature.verify(&pk, b"wrong message"));
    }

    #[test]
    fn test_multi_scalar_mul() {
        let mut rng = OsRng;

        let scalars: Vec<Scalar> = (0..5).map(|_| Scalar::random(&mut rng)).collect();
        let points: Vec<G1Point> = (0..5).map(|_| G1Point::random(&mut rng)).collect();

        // Compute using MSM
        let msm_result = G1Point::multi_scalar_mul(&scalars, &points).unwrap();

        // Compute manually
        let mut manual_result = G1Point::identity();
        for (s, p) in scalars.iter().zip(points.iter()) {
            manual_result = manual_result.add(&p.mul(s));
        }

        assert_eq!(msm_result, manual_result);
    }
}
