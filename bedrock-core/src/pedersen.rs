//! Pedersen Commitment Scheme over Ristretto255
//!
//! Provides perfectly hiding, computationally binding commitments.
//! Used for anonymous recovery shares where we commit to share values
//! without revealing them.
//!
//! Security: Relies on discrete log hardness in Ristretto255 (~126 bits).
//! Note: NOT post-quantum.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha3::{Digest, Sha3_512};

/// Pedersen commitment parameters
///
/// C = g^value · h^blinding
///
/// where g is the standard basepoint and h is derived via hash-to-point
/// with a nothing-up-my-sleeve construction.
#[derive(Clone)]
pub struct PedersenParams {
    /// Primary generator (standard Ristretto basepoint)
    pub g: RistrettoPoint,
    /// Secondary generator (derived via hash-to-point)
    pub h: RistrettoPoint,
}

impl PedersenParams {
    /// Create parameters with deterministic h (nothing-up-my-sleeve)
    pub fn new() -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;

        // Derive h via hash-to-point using domain separation
        // The log_g(h) is unknown, which is required for hiding
        let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(
            b"Yours/Pedersen/v1/secondary_generator"
        );

        Self { g, h }
    }

    /// Create commitment: C = g^value · h^blinding
    ///
    /// Properties:
    /// - Perfectly hiding: C reveals zero information about value
    /// - Computationally binding: Cannot find (v', r') != (v, r) that opens to same C
    pub fn commit(&self, value: &Scalar, blinding: &Scalar) -> Commitment {
        let point = self.g * value + self.h * blinding;
        Commitment(point)
    }

    /// Create blinding-only commitment: R = h^blinding
    ///
    /// Used for proving knowledge of blinding factor during recovery
    /// without revealing the share value.
    pub fn commit_blinding(&self, blinding: &Scalar) -> BlindingCommitment {
        BlindingCommitment(self.h * blinding)
    }

    /// Verify that a commitment opens to given value and blinding
    pub fn verify_opening(
        &self,
        commitment: &Commitment,
        value: &Scalar,
        blinding: &Scalar,
    ) -> bool {
        let expected = self.commit(value, blinding);
        commitment.0 == expected.0
    }
}

impl Default for PedersenParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Commitment to a value with blinding factor: C = g^v · h^r
#[derive(Clone, Debug)]
pub struct Commitment(pub RistrettoPoint);

impl Commitment {
    /// Compress to 32 bytes for storage/transmission
    pub fn compress(&self) -> CompressedRistretto {
        self.0.compress()
    }

    /// Decompress from stored bytes
    pub fn from_compressed(compressed: &CompressedRistretto) -> Option<Self> {
        compressed.decompress().map(Commitment)
    }

    /// Get raw bytes (32 bytes, compressed format)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }

    /// Parse from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).ok()?;
        Self::from_compressed(&compressed)
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Commitment {}

/// Commitment to blinding factor only: R = h^r
///
/// This is what we store with each share. During recovery,
/// the user proves knowledge of r (derived from passphrase)
/// to retrieve their encrypted share.
#[derive(Clone, Debug)]
pub struct BlindingCommitment(pub RistrettoPoint);

impl BlindingCommitment {
    /// Compress to 32 bytes for storage/transmission
    pub fn compress(&self) -> CompressedRistretto {
        self.0.compress()
    }

    /// Decompress from stored bytes
    pub fn from_compressed(compressed: &CompressedRistretto) -> Option<Self> {
        compressed.decompress().map(BlindingCommitment)
    }

    /// Get raw bytes (32 bytes, compressed format)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compress().to_bytes()
    }

    /// Parse from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).ok()?;
        Self::from_compressed(&compressed)
    }
}

impl PartialEq for BlindingCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for BlindingCommitment {}

/// Derive a scalar from arbitrary bytes using hash-to-scalar
///
/// Uses SHA3-512 then reduces mod group order for uniform distribution
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_commitment_roundtrip() {
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);

        let commitment = params.commit(&value, &blinding);

        // Verify opening
        assert!(params.verify_opening(&commitment, &value, &blinding));

        // Wrong value should not verify
        let wrong_value = Scalar::random(&mut OsRng);
        assert!(!params.verify_opening(&commitment, &wrong_value, &blinding));
    }

    #[test]
    fn test_commitment_serialization() {
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);

        let commitment = params.commit(&value, &blinding);
        let bytes = commitment.to_bytes();
        let recovered = Commitment::from_bytes(&bytes).unwrap();

        assert_eq!(commitment, recovered);
    }

    #[test]
    fn test_blinding_commitment() {
        let params = PedersenParams::new();
        let blinding = Scalar::random(&mut OsRng);

        let r_commit = params.commit_blinding(&blinding);
        let bytes = r_commit.to_bytes();
        let recovered = BlindingCommitment::from_bytes(&bytes).unwrap();

        assert_eq!(r_commit, recovered);
    }

    #[test]
    fn test_hash_to_scalar() {
        let s1 = hash_to_scalar(b"test input 1");
        let s2 = hash_to_scalar(b"test input 2");
        let s1_again = hash_to_scalar(b"test input 1");

        // Same input produces same scalar
        assert_eq!(s1, s1_again);

        // Different inputs produce different scalars
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_hiding_property() {
        // Same value with different blinding produces different commitments
        let params = PedersenParams::new();
        let value = Scalar::random(&mut OsRng);
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);

        let c1 = params.commit(&value, &r1);
        let c2 = params.commit(&value, &r2);

        // Commitments should be different (hiding)
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_deterministic_params() {
        // Parameters should be deterministic
        let p1 = PedersenParams::new();
        let p2 = PedersenParams::new();

        assert_eq!(p1.g, p2.g);
        assert_eq!(p1.h, p2.h);
    }
}
