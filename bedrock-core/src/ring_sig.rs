//! Linkable Ring Signatures for Anonymous Nullifiers
//!
//! Implements LSAG (Linkable Spontaneous Anonymous Group) signatures
//! over Ristretto255. This allows a user to prove they're part of a
//! set of identities WITHOUT revealing which one.
//!
//! Properties:
//! 1. Anonymity: Cannot determine which ring member signed
//! 2. Linkability: Can detect if same key signs twice (key image)
//! 3. Unforgeability: Cannot forge signature without private key
//!
//! Use case for nullifiers:
//! - User publishes nullifier with ring signature
//! - Ring = set of N public keys (anonymity set)
//! - Key image = deterministic tag that's same for same signer
//! - Network verifies signature without learning identity
//! - If same key image appears twice, detect double-publish
//!
//! Based on: "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups"
//! Liu, Wei, Wong (2004)

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

/// Generator point G (standard Ristretto basepoint)
const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// Minimum ring size for anonymity.
/// A ring with fewer members provides insufficient anonymity.
/// 5 is chosen as a reasonable minimum - smaller rings make deanonymization trivially easy.
/// For high-security contexts, consider requiring larger rings (10+).
pub const MIN_RING_SIZE: usize = 5;

/// Secondary generator H for key image computation
/// H = hash_to_point("Yours/RingSig/v1/H")
fn get_h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(b"Yours/RingSig/v1/key_image_generator")
}

/// A public key in the ring
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingPublicKey(pub RistrettoPoint);

impl RingPublicKey {
    /// Create from private key scalar
    pub fn from_private(private: &Scalar) -> Self {
        RingPublicKey(G * private)
    }

    /// Compress to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).ok()?;
        compressed.decompress().map(RingPublicKey)
    }
}

/// Key image - deterministic tag for detecting double-signing
///
/// I = x * H(P) where x is private key and P is public key
/// Same signer always produces same key image (linkable)
/// Different signers produce different key images (anonymous)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyImage(pub RistrettoPoint);

impl KeyImage {
    /// Compute key image from private key
    pub fn compute(private_key: &Scalar, public_key: &RingPublicKey) -> Self {
        // H_p = hash_to_point(P)
        let h_p = RistrettoPoint::hash_from_bytes::<Sha3_512>(&public_key.to_bytes());
        // I = x * H_p
        KeyImage(h_p * private_key)
    }

    /// Compress to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).ok()?;
        compressed.decompress().map(KeyImage)
    }
}

/// Linkable Ring Signature
///
/// Proves knowledge of private key corresponding to ONE of N public keys
/// without revealing which one. Key image links signatures from same key.
#[derive(Clone)]
pub struct RingSignature {
    /// Key image (for linkability detection)
    pub key_image: KeyImage,
    /// Challenge scalars (one per ring member)
    pub c: Vec<Scalar>,
    /// Response scalars (one per ring member)
    pub r: Vec<Scalar>,
}

impl RingSignature {
    /// Sign a message with ring signature
    ///
    /// - `private_key`: Signer's private key
    /// - `ring`: Public keys forming the anonymity set (must include signer's key)
    /// - `signer_index`: Index of signer's public key in the ring
    /// - `message`: Message to sign
    pub fn sign(
        private_key: &Scalar,
        ring: &[RingPublicKey],
        signer_index: usize,
        message: &[u8],
    ) -> Result<Self, &'static str> {
        if ring.is_empty() {
            return Err("Ring cannot be empty");
        }
        // SECURITY: Enforce minimum ring size for anonymity
        // A ring with fewer than MIN_RING_SIZE members provides insufficient
        // anonymity - an attacker can easily identify the signer.
        if ring.len() < MIN_RING_SIZE {
            return Err("Ring too small for anonymity (minimum 5 members required)");
        }
        if signer_index >= ring.len() {
            return Err("Signer index out of bounds");
        }

        let n = ring.len();
        let mut rng = OsRng;

        // Verify private key matches public key at signer_index
        let expected_pk = RingPublicKey::from_private(private_key);
        if expected_pk != ring[signer_index] {
            return Err("Private key doesn't match public key at signer_index");
        }

        // Compute key image: I = x * H(P)
        let key_image = KeyImage::compute(private_key, &ring[signer_index]);

        // H_p for signer's public key (used in signature)
        let h_p_signer = RistrettoPoint::hash_from_bytes::<Sha3_512>(
            &ring[signer_index].to_bytes()
        );

        // Initialize arrays
        let mut c = vec![Scalar::ZERO; n];
        let mut r = vec![Scalar::ZERO; n];

        // Random nonce for signer
        let alpha = Scalar::random(&mut rng);

        // Compute L_s = alpha * G
        let l_signer = G * alpha;
        // Compute R_s = alpha * H(P_s)
        let r_signer = h_p_signer * alpha;

        // Start computing challenges from signer_index + 1
        let mut next_idx = (signer_index + 1) % n;

        // Compute c_{s+1} = H(m, L_s, R_s)
        c[next_idx] = compute_challenge(message, &ring, &key_image, &l_signer, &r_signer);

        // Go around the ring computing fake signatures
        while next_idx != signer_index {
            // Random response for this index
            r[next_idx] = Scalar::random(&mut rng);

            // H_p for this public key
            let h_p = RistrettoPoint::hash_from_bytes::<Sha3_512>(
                &ring[next_idx].to_bytes()
            );

            // L_i = r_i * G + c_i * P_i
            let l_i = G * r[next_idx] + ring[next_idx].0 * c[next_idx];
            // R_i = r_i * H(P_i) + c_i * I
            let r_i = h_p * r[next_idx] + key_image.0 * c[next_idx];

            // Next index
            let prev_idx = next_idx;
            next_idx = (next_idx + 1) % n;

            // c_{i+1} = H(m, L_i, R_i)
            if next_idx != signer_index {
                c[next_idx] = compute_challenge(message, &ring, &key_image, &l_i, &r_i);
            } else {
                // We've come full circle, compute c_s
                c[signer_index] = compute_challenge(message, &ring, &key_image, &l_i, &r_i);
            }
        }

        // Compute signer's response: r_s = alpha - c_s * x
        r[signer_index] = alpha - c[signer_index] * private_key;

        Ok(RingSignature { key_image, c, r })
    }

    /// Verify ring signature
    pub fn verify(&self, ring: &[RingPublicKey], message: &[u8]) -> bool {
        let n = ring.len();

        if n == 0 || self.c.len() != n || self.r.len() != n {
            return false;
        }

        // Recompute the ring of challenges
        let mut computed_c = vec![Scalar::ZERO; n];

        for i in 0..n {
            // H_p for this public key
            let h_p = RistrettoPoint::hash_from_bytes::<Sha3_512>(&ring[i].to_bytes());

            // L_i = r_i * G + c_i * P_i
            let l_i = G * self.r[i] + ring[i].0 * self.c[i];
            // R_i = r_i * H(P_i) + c_i * I
            let r_i = h_p * self.r[i] + self.key_image.0 * self.c[i];

            // c_{i+1} = H(m, L_i, R_i)
            let next_i = (i + 1) % n;
            computed_c[next_i] = compute_challenge(message, ring, &self.key_image, &l_i, &r_i);
        }

        // Verify the ring closes: all computed challenges match provided ones
        // Due to the ring structure, if signature is valid, challenges will match
        for i in 0..n {
            if computed_c[i] != self.c[i] {
                return false;
            }
        }

        true
    }

    /// Serialize signature
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.c.len();
        let mut bytes = Vec::with_capacity(32 + 4 + n * 64);

        // Key image (32 bytes)
        bytes.extend_from_slice(&self.key_image.to_bytes());

        // Ring size (4 bytes)
        bytes.extend_from_slice(&(n as u32).to_le_bytes());

        // Challenges and responses (64 bytes each)
        for i in 0..n {
            bytes.extend_from_slice(self.c[i].as_bytes());
            bytes.extend_from_slice(self.r[i].as_bytes());
        }

        bytes
    }

    /// Deserialize signature
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 36 {
            return None;
        }

        // Key image
        let mut ki_bytes = [0u8; 32];
        ki_bytes.copy_from_slice(&bytes[0..32]);
        let key_image = KeyImage::from_bytes(&ki_bytes)?;

        // Ring size
        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[32..36]);
        let n = u32::from_le_bytes(n_bytes) as usize;

        if bytes.len() != 36 + n * 64 {
            return None;
        }

        // Challenges and responses
        let mut c = Vec::with_capacity(n);
        let mut r = Vec::with_capacity(n);

        let mut offset = 36;
        for _ in 0..n {
            let mut c_bytes = [0u8; 32];
            c_bytes.copy_from_slice(&bytes[offset..offset + 32]);
            c.push(Scalar::from_canonical_bytes(c_bytes).into_option()?);
            offset += 32;

            let mut r_bytes = [0u8; 32];
            r_bytes.copy_from_slice(&bytes[offset..offset + 32]);
            r.push(Scalar::from_canonical_bytes(r_bytes).into_option()?);
            offset += 32;
        }

        Some(RingSignature { key_image, c, r })
    }
}

/// Compute challenge hash
fn compute_challenge(
    message: &[u8],
    ring: &[RingPublicKey],
    key_image: &KeyImage,
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha3_512::new();

    hasher.update(b"Yours/RingSig/v1/challenge");
    hasher.update(message);

    // Include entire ring in challenge
    for pk in ring {
        hasher.update(&pk.to_bytes());
    }

    hasher.update(&key_image.to_bytes());
    hasher.update(&l.compress().to_bytes());
    hasher.update(&r.compress().to_bytes());

    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Anonymous Nullifier with Ring Signature
///
/// Combines nullifier with ring signature for anonymous check-ins.
/// The network can verify the nullifier came from a valid identity
/// without learning which identity.
#[derive(Clone)]
pub struct AnonymousNullifier {
    /// The nullifier value (epoch-specific)
    pub nullifier: [u8; 32],
    /// Epoch this nullifier is for
    pub epoch: u64,
    /// Ring signature proving membership
    pub ring_sig: RingSignature,
    /// The ring of public keys (anonymity set)
    pub ring: Vec<RingPublicKey>,
}

impl AnonymousNullifier {
    /// Create anonymous nullifier for dead man's switch check-in
    ///
    /// - `nullifier_secret`: Derived from passphrase
    /// - `signing_key`: Private key for ring signature
    /// - `ring`: Anonymity set of public keys (must include signer's key)
    /// - `signer_index`: Index of signer in ring
    /// - `epoch`: Current epoch (week number)
    pub fn create(
        nullifier_secret: &[u8; 32],
        signing_key: &Scalar,
        ring: Vec<RingPublicKey>,
        signer_index: usize,
        epoch: u64,
    ) -> Result<Self, &'static str> {
        // Compute nullifier for this epoch
        let nullifier = crate::nullifier::Nullifier::derive(nullifier_secret, epoch);

        // Message to sign: nullifier || epoch
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(nullifier.as_bytes());
        message.extend_from_slice(&epoch.to_le_bytes());

        // Create ring signature
        let ring_sig = RingSignature::sign(signing_key, &ring, signer_index, &message)?;

        Ok(AnonymousNullifier {
            nullifier: nullifier.to_bytes(),
            epoch,
            ring_sig,
            ring,
        })
    }

    /// Verify anonymous nullifier
    pub fn verify(&self) -> bool {
        // Reconstruct message
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(&self.nullifier);
        message.extend_from_slice(&self.epoch.to_le_bytes());

        // Verify ring signature
        self.ring_sig.verify(&self.ring, &message)
    }

    /// Get key image for linkability checking
    pub fn key_image(&self) -> &KeyImage {
        &self.ring_sig.key_image
    }

    /// Check if two nullifiers are from the same identity
    pub fn is_same_signer(&self, other: &AnonymousNullifier) -> bool {
        self.ring_sig.key_image == other.ring_sig.key_image
    }

    /// Serialize
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_bytes = self.ring_sig.to_bytes();
        let ring_bytes: Vec<u8> = self.ring.iter()
            .flat_map(|pk| pk.to_bytes())
            .collect();

        let mut bytes = Vec::with_capacity(32 + 8 + 4 + sig_bytes.len() + 4 + ring_bytes.len());

        bytes.extend_from_slice(&self.nullifier);
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&sig_bytes);
        bytes.extend_from_slice(&(self.ring.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&ring_bytes);

        bytes
    }

    /// Deserialize
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 48 {
            return None;
        }

        let mut offset = 0;

        // Nullifier
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Epoch
        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let epoch = u64::from_le_bytes(epoch_bytes);
        offset += 8;

        // Signature length
        let mut sig_len_bytes = [0u8; 4];
        sig_len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let sig_len = u32::from_le_bytes(sig_len_bytes) as usize;
        offset += 4;

        if bytes.len() < offset + sig_len + 4 {
            return None;
        }

        // Signature
        let ring_sig = RingSignature::from_bytes(&bytes[offset..offset + sig_len])?;
        offset += sig_len;

        // Ring length
        let mut ring_len_bytes = [0u8; 4];
        ring_len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let ring_len = u32::from_le_bytes(ring_len_bytes) as usize;
        offset += 4;

        if bytes.len() != offset + ring_len * 32 {
            return None;
        }

        // Ring
        let mut ring = Vec::with_capacity(ring_len);
        for _ in 0..ring_len {
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(&bytes[offset..offset + 32]);
            ring.push(RingPublicKey::from_bytes(&pk_bytes)?);
            offset += 32;
        }

        Some(AnonymousNullifier {
            nullifier,
            epoch,
            ring_sig,
            ring,
        })
    }
}

/// Key Image Store - tracks seen key images to detect double-signing
pub struct KeyImageStore {
    /// Seen key images with their epochs
    seen: std::collections::HashMap<[u8; 32], u64>,
}

impl KeyImageStore {
    /// Create new store
    pub fn new() -> Self {
        KeyImageStore {
            seen: std::collections::HashMap::new(),
        }
    }

    /// Check if key image has been seen (and record it)
    ///
    /// Returns Some(previous_epoch) if seen before, None if new
    pub fn check_and_record(&mut self, key_image: &KeyImage, epoch: u64) -> Option<u64> {
        let bytes = key_image.to_bytes();

        if let Some(&prev_epoch) = self.seen.get(&bytes) {
            Some(prev_epoch)
        } else {
            self.seen.insert(bytes, epoch);
            None
        }
    }

    /// Check if key image has been seen (without recording)
    pub fn is_seen(&self, key_image: &KeyImage) -> bool {
        self.seen.contains_key(&key_image.to_bytes())
    }
}

impl Default for KeyImageStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_keypair() -> (Scalar, RingPublicKey) {
        let private = Scalar::random(&mut OsRng);
        let public = RingPublicKey::from_private(&private);
        (private, public)
    }

    #[test]
    fn test_key_image_deterministic() {
        let (private, public) = random_keypair();

        let ki1 = KeyImage::compute(&private, &public);
        let ki2 = KeyImage::compute(&private, &public);

        assert_eq!(ki1, ki2, "Key image should be deterministic");
    }

    #[test]
    fn test_key_image_different_keys() {
        let (private1, public1) = random_keypair();
        let (private2, public2) = random_keypair();

        let ki1 = KeyImage::compute(&private1, &public1);
        let ki2 = KeyImage::compute(&private2, &public2);

        assert_ne!(ki1, ki2, "Different keys should have different key images");
    }

    // Helper to create a ring with minimum required members
    fn create_test_ring(signer_public: RingPublicKey, signer_index: usize) -> Vec<RingPublicKey> {
        let mut ring = Vec::with_capacity(MIN_RING_SIZE);
        for i in 0..MIN_RING_SIZE {
            if i == signer_index {
                ring.push(signer_public.clone());
            } else {
                let (_, pk) = random_keypair();
                ring.push(pk);
            }
        }
        ring
    }

    #[test]
    fn test_ring_signature_rejects_small_ring() {
        // SECURITY TEST: Verify that rings smaller than MIN_RING_SIZE are rejected
        let (private, public) = random_keypair();

        // Single member should fail
        let ring1 = vec![public.clone()];
        assert!(
            RingSignature::sign(&private, &ring1, 0, b"test").is_err(),
            "Single-member ring should be rejected for anonymity"
        );

        // 4 members should fail (MIN_RING_SIZE is 5)
        let ring4: Vec<RingPublicKey> = (0..4)
            .map(|i| if i == 0 { public.clone() } else { random_keypair().1 })
            .collect();
        assert!(
            RingSignature::sign(&private, &ring4, 0, b"test").is_err(),
            "4-member ring should be rejected for anonymity"
        );

        // 5 members should succeed
        let ring5 = create_test_ring(public.clone(), 0);
        assert!(
            RingSignature::sign(&private, &ring5, 0, b"test").is_ok(),
            "5-member ring should be allowed"
        );
    }

    #[test]
    fn test_ring_signature_minimum_members() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);
        let message = b"test message";

        let sig = RingSignature::sign(&private, &ring, 0, message).unwrap();
        assert!(sig.verify(&ring, message), "Signature should verify");
    }

    #[test]
    fn test_ring_signature_signer_in_middle() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 2); // Signer at index 2
        let message = b"test message";

        let sig = RingSignature::sign(&private, &ring, 2, message).unwrap();
        assert!(sig.verify(&ring, message), "Signature should verify");
    }

    #[test]
    fn test_ring_signature_wrong_message() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);
        let message = b"test message";

        let sig = RingSignature::sign(&private, &ring, 0, message).unwrap();
        assert!(!sig.verify(&ring, b"wrong message"), "Wrong message should fail");
    }

    #[test]
    fn test_ring_signature_wrong_ring() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);
        let message = b"test message";

        let sig = RingSignature::sign(&private, &ring, 0, message).unwrap();

        // Different ring (completely new members)
        let (_, other_pub) = random_keypair();
        let wrong_ring = create_test_ring(other_pub, 0);
        assert!(!sig.verify(&wrong_ring, message), "Wrong ring should fail");
    }

    #[test]
    fn test_ring_signature_linkability() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);

        let sig1 = RingSignature::sign(&private, &ring, 0, b"message 1").unwrap();
        let sig2 = RingSignature::sign(&private, &ring, 0, b"message 2").unwrap();

        // Same signer should have same key image
        assert_eq!(sig1.key_image, sig2.key_image, "Same signer should be linkable");
    }

    #[test]
    fn test_ring_signature_serialization() {
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 2);
        let message = b"test message";

        let sig = RingSignature::sign(&private, &ring, 2, message).unwrap();

        let bytes = sig.to_bytes();
        let recovered = RingSignature::from_bytes(&bytes).unwrap();

        assert!(recovered.verify(&ring, message), "Recovered signature should verify");
        assert_eq!(sig.key_image, recovered.key_image);
    }

    #[test]
    fn test_anonymous_nullifier() {
        let nullifier_secret = [42u8; 32];
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 1);
        let epoch = 1000;

        let anon_null = AnonymousNullifier::create(
            &nullifier_secret,
            &private,
            ring.clone(),
            1, // signer at index 1
            epoch,
        ).unwrap();

        assert!(anon_null.verify(), "Anonymous nullifier should verify");
        assert_eq!(anon_null.epoch, epoch);
    }

    #[test]
    fn test_anonymous_nullifier_linkability() {
        let nullifier_secret = [42u8; 32];
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);

        let null1 = AnonymousNullifier::create(&nullifier_secret, &private, ring.clone(), 0, 1000).unwrap();
        let null2 = AnonymousNullifier::create(&nullifier_secret, &private, ring.clone(), 0, 1001).unwrap();

        // Same signer should be detectable
        assert!(null1.is_same_signer(&null2), "Same signer should be linkable");
    }

    #[test]
    fn test_anonymous_nullifier_different_signers() {
        let (private1, public1) = random_keypair();
        let (private2, public2) = random_keypair();

        // Build ring with both signers in it
        let mut ring = Vec::with_capacity(MIN_RING_SIZE);
        ring.push(public1.clone());
        ring.push(public2.clone());
        for _ in 2..MIN_RING_SIZE {
            ring.push(random_keypair().1);
        }

        let null1 = AnonymousNullifier::create(&[1u8; 32], &private1, ring.clone(), 0, 1000).unwrap();
        let null2 = AnonymousNullifier::create(&[2u8; 32], &private2, ring.clone(), 1, 1000).unwrap();

        // Different signers should NOT be linkable
        assert!(!null1.is_same_signer(&null2), "Different signers should not be linkable");
    }

    #[test]
    fn test_key_image_store() {
        let (private1, public1) = random_keypair();
        let (private2, public2) = random_keypair();

        let ki1 = KeyImage::compute(&private1, &public1);
        let ki2 = KeyImage::compute(&private2, &public2);

        let mut store = KeyImageStore::new();

        // First time should return None
        assert!(store.check_and_record(&ki1, 100).is_none());

        // Second time should return previous epoch
        assert_eq!(store.check_and_record(&ki1, 101), Some(100));

        // Different key image should return None
        assert!(store.check_and_record(&ki2, 100).is_none());
    }

    #[test]
    fn test_anonymous_nullifier_serialization() {
        let nullifier_secret = [42u8; 32];
        let (private, public) = random_keypair();
        let ring = create_test_ring(public.clone(), 0);
        let epoch = 1000;

        let anon_null = AnonymousNullifier::create(&nullifier_secret, &private, ring, 0, epoch).unwrap();

        let bytes = anon_null.to_bytes();
        let recovered = AnonymousNullifier::from_bytes(&bytes).unwrap();

        assert!(recovered.verify(), "Recovered anonymous nullifier should verify");
        assert_eq!(anon_null.nullifier, recovered.nullifier);
        assert_eq!(anon_null.epoch, recovered.epoch);
        assert!(anon_null.is_same_signer(&recovered));
    }

    #[test]
    fn test_large_ring() {
        let (private, public) = random_keypair();

        // Create a ring with 10 members
        let mut ring: Vec<RingPublicKey> = (0..9)
            .map(|_| random_keypair().1)
            .collect();

        // Insert signer at random position
        let signer_idx = 5;
        ring.insert(signer_idx, public);

        let message = b"test with large ring";
        let sig = RingSignature::sign(&private, &ring, signer_idx, message).unwrap();

        assert!(sig.verify(&ring, message), "Large ring signature should verify");
    }
}
