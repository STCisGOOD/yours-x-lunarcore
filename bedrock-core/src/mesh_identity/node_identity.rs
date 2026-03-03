//! Anonymous Node Identity
//!
//! Provides anonymous identities for mesh network nodes.
//!
//! # Overview
//!
//! Each node has:
//! - A keypair for signing messages
//! - An anonymous node ID derived from the public key
//! - The ability to prove membership in a ring of nodes
//!
//! # Security
//!
//! - Node ID is a hash of the public key (one-way)
//! - Ring signatures prove membership without revealing which node
//! - Key rotation doesn't break anonymity

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
use crate::ring_sig::{KeyImage, RingPublicKey, RingSignature};

/// Generator point
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

// ============================================================================
// Mesh Node ID
// ============================================================================

/// Anonymous mesh node identifier.
///
/// A 32-byte hash of the node's public key. Cannot be reversed to
/// determine the actual identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshNodeId(pub [u8; 32]);

impl MeshNodeId {
    /// Compute node ID from a public key.
    pub fn from_public_key(public_key: &RistrettoPoint) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"MESH_NODE_ID:");
        hasher.update(public_key.compress().as_bytes());
        let result = hasher.finalize();

        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        MeshNodeId(id)
    }

    /// Get the bytes of the node ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MeshNodeId(bytes)
    }

    /// Compute a short display ID (first 8 characters of hex).
    pub fn short_id(&self) -> String {
        // Manual hex encoding to avoid additional dependency
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(8);
        for byte in &self.0[..4] {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}

// ============================================================================
// Mesh Key Pair
// ============================================================================

/// Mesh node keypair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MeshKeyPair {
    /// Private key (scalar)
    secret_key: Scalar,
    /// Public key (point)
    #[zeroize(skip)]
    public_key: RistrettoPoint,
}

impl MeshKeyPair {
    /// Generate a new random keypair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret_key = Scalar::random(rng);
        let public_key = G * secret_key;
        MeshKeyPair { secret_key, public_key }
    }

    /// Create from an existing secret key.
    pub fn from_secret_key(secret_key: Scalar) -> Self {
        let public_key = G * secret_key;
        MeshKeyPair { secret_key, public_key }
    }

    /// Get the public key.
    pub fn public_key(&self) -> RistrettoPoint {
        self.public_key
    }

    /// Get the ring public key (for use with ring signatures).
    pub fn ring_public_key(&self) -> RingPublicKey {
        RingPublicKey(self.public_key)
    }

    /// Get the node ID.
    pub fn node_id(&self) -> MeshNodeId {
        MeshNodeId::from_public_key(&self.public_key)
    }

    /// Compute the key image for linkable ring signatures.
    pub fn key_image(&self) -> KeyImage {
        KeyImage::compute(&self.secret_key, &self.ring_public_key())
    }

    /// Sign a message with a simple Schnorr signature.
    pub fn sign(&self, message: &[u8]) -> MeshSignature {
        let mut rng = rand::rngs::OsRng;
        let k = Scalar::random(&mut rng);
        let r = G * k;

        // Challenge: c = H(R || P || m)
        let c = compute_schnorr_challenge(&r, &self.public_key, message);

        // Response: s = k + c * sk
        let s = k + c * self.secret_key;

        MeshSignature {
            r: r.compress().to_bytes(),
            s: s.as_bytes().clone(),
        }
    }

    /// Create a ring signature proving membership in a set of nodes.
    pub fn sign_ring(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        signer_index: usize,
    ) -> Result<RingSignature> {
        RingSignature::sign(&self.secret_key, ring, signer_index, message)
            .map_err(|e| BedrockError::InvalidRingSignature)
    }

    /// Export secret key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.secret_key.as_bytes()
    }

    /// Import from secret key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let secret_key = Scalar::from_canonical_bytes(*bytes).into_option()?;
        Some(MeshKeyPair::from_secret_key(secret_key))
    }
}

// ============================================================================
// Mesh Signature
// ============================================================================

/// Simple Schnorr signature from a mesh node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshSignature {
    /// Commitment R (compressed)
    pub r: [u8; 32],
    /// Response s
    pub s: [u8; 32],
}

impl MeshSignature {
    /// Verify the signature against a public key.
    pub fn verify(&self, public_key: &RistrettoPoint, message: &[u8]) -> bool {
        // Decompress R
        let r = match CompressedRistretto::from_slice(&self.r)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(r) => r,
            None => return false,
        };

        // Parse s
        let s = match Scalar::from_canonical_bytes(self.s).into_option() {
            Some(s) => s,
            None => return false,
        };

        // Recompute challenge
        let c = compute_schnorr_challenge(&r, public_key, message);

        // Check: s * G == R + c * P
        let lhs = G * s;
        let rhs = r + *public_key * c;

        lhs == rhs
    }

    /// Verify against a node ID (requires knowing the public key).
    pub fn verify_with_pubkey_bytes(&self, pubkey_bytes: &[u8; 32], message: &[u8]) -> bool {
        let public_key = match CompressedRistretto::from_slice(pubkey_bytes)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(pk) => pk,
            None => return false,
        };

        self.verify(&public_key, message)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        MeshSignature { r, s }
    }
}

/// Compute Schnorr challenge.
fn compute_schnorr_challenge(
    r: &RistrettoPoint,
    public_key: &RistrettoPoint,
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"MESH_SIG:");
    hasher.update(r.compress().as_bytes());
    hasher.update(public_key.compress().as_bytes());
    hasher.update(message);
    let hash = hasher.finalize();

    // Reduce hash to scalar
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ============================================================================
// Ring Membership
// ============================================================================

/// A set of nodes forming an anonymity ring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRing {
    /// Public keys in the ring
    pub members: Vec<[u8; 32]>,
}

impl NodeRing {
    /// Create a new ring from compressed public keys.
    pub fn new(members: Vec<[u8; 32]>) -> Self {
        NodeRing { members }
    }

    /// Get the ring as RingPublicKey vector.
    pub fn to_ring_public_keys(&self) -> Option<Vec<RingPublicKey>> {
        self.members
            .iter()
            .map(|bytes| {
                CompressedRistretto::from_slice(bytes)
                    .ok()
                    .and_then(|c| c.decompress())
                    .map(RingPublicKey)
            })
            .collect()
    }

    /// Find the index of a public key in the ring.
    pub fn find_index(&self, public_key: &RistrettoPoint) -> Option<usize> {
        let compressed = public_key.compress().to_bytes();
        self.members.iter().position(|m| m == &compressed)
    }

    /// Check if a public key is in the ring.
    pub fn contains(&self, public_key: &RistrettoPoint) -> bool {
        self.find_index(public_key).is_some()
    }

    /// Size of the ring.
    pub fn size(&self) -> usize {
        self.members.len()
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
    fn test_keypair_generation() {
        let mut rng = OsRng;
        let keypair = MeshKeyPair::generate(&mut rng);

        // Node ID should be deterministic
        let node_id1 = keypair.node_id();
        let node_id2 = keypair.node_id();
        assert_eq!(node_id1, node_id2);

        // Short ID should be 8 hex chars
        assert_eq!(keypair.node_id().short_id().len(), 8);
    }

    #[test]
    fn test_keypair_serialization() {
        let mut rng = OsRng;
        let keypair = MeshKeyPair::generate(&mut rng);

        let bytes = keypair.to_bytes();
        let recovered = MeshKeyPair::from_bytes(&bytes).unwrap();

        assert_eq!(keypair.public_key(), recovered.public_key());
        assert_eq!(keypair.node_id(), recovered.node_id());
    }

    #[test]
    fn test_signature() {
        let mut rng = OsRng;
        let keypair = MeshKeyPair::generate(&mut rng);

        let message = b"test message";
        let signature = keypair.sign(message);

        // Should verify with correct key
        assert!(signature.verify(&keypair.public_key(), message));

        // Should fail with wrong message
        assert!(!signature.verify(&keypair.public_key(), b"wrong message"));

        // Should fail with wrong key
        let other_keypair = MeshKeyPair::generate(&mut rng);
        assert!(!signature.verify(&other_keypair.public_key(), message));
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = OsRng;
        let keypair = MeshKeyPair::generate(&mut rng);

        let message = b"test message";
        let signature = keypair.sign(message);

        let bytes = signature.to_bytes();
        let recovered = MeshSignature::from_bytes(&bytes);

        assert!(recovered.verify(&keypair.public_key(), message));
    }

    #[test]
    fn test_node_ring() {
        let mut rng = OsRng;

        let keypair1 = MeshKeyPair::generate(&mut rng);
        let keypair2 = MeshKeyPair::generate(&mut rng);
        let keypair3 = MeshKeyPair::generate(&mut rng);

        let members = vec![
            keypair1.public_key().compress().to_bytes(),
            keypair2.public_key().compress().to_bytes(),
            keypair3.public_key().compress().to_bytes(),
        ];

        let ring = NodeRing::new(members);

        assert_eq!(ring.size(), 3);
        assert!(ring.contains(&keypair1.public_key()));
        assert!(ring.contains(&keypair2.public_key()));
        assert_eq!(ring.find_index(&keypair2.public_key()), Some(1));

        let other = MeshKeyPair::generate(&mut rng);
        assert!(!ring.contains(&other.public_key()));
    }

    #[test]
    fn test_key_image() {
        let mut rng = OsRng;
        let keypair = MeshKeyPair::generate(&mut rng);

        // Key image should be deterministic
        let ki1 = keypair.key_image();
        let ki2 = keypair.key_image();
        assert_eq!(ki1, ki2);

        // Different keypairs should have different key images
        let other = MeshKeyPair::generate(&mut rng);
        assert_ne!(keypair.key_image(), other.key_image());
    }
}
