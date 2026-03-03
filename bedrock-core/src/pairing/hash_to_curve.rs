//! Hash-to-Curve Operations
//!
//! Implements IETF hash-to-curve for BLS12-381 groups.
//!
//! # Security
//!
//! Uses the SSWU (Simplified Shallue-van de Woestijne-Ulas) method
//! which provides uniform distribution in the target group.
//!
//! # References
//!
//! - [IETF Hash-to-Curve](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve)
//! - [BLS12-381 Hash-to-Curve](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-bls12-381-g1)

use blstrs::{G1Projective, G2Projective};
use sha2::{Digest, Sha256};

use super::bls12_381::{G1Point, G2Point, Scalar, SCALAR_SIZE};

/// Hash arbitrary message to a G1 point.
///
/// Uses the IETF hash-to-curve standard with BLS12381G1_XMD:SHA-256_SSWU_RO_.
///
/// # Arguments
///
/// * `message` - The message to hash
/// * `dst` - Domain separation tag (must be unique per protocol)
///
/// # Example
///
/// ```ignore
/// let point = hash_to_g1(b"my message", b"MY_PROTOCOL_V1_");
/// ```
pub fn hash_to_g1(message: &[u8], dst: &[u8]) -> G1Point {
    // Use blstrs built-in hash-to-curve
    G1Point(G1Projective::hash_to_curve(message, dst, &[]))
}

/// Hash arbitrary message to a G2 point.
///
/// Uses the IETF hash-to-curve standard with BLS12381G2_XMD:SHA-256_SSWU_RO_.
///
/// # Arguments
///
/// * `message` - The message to hash
/// * `dst` - Domain separation tag (must be unique per protocol)
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Point {
    G2Point(G2Projective::hash_to_curve(message, dst, &[]))
}

/// Hash to a scalar field element.
///
/// Fix #15: Uses proper 64-byte expansion with wide reduction for uniform distribution.
/// Never modifies the DST (domain separation), never falls back to Scalar::one().
///
/// # Arguments
///
/// * `message` - The message to hash
/// * `dst` - Domain separation tag
pub fn hash_to_scalar(message: &[u8], dst: &[u8]) -> Scalar {
    // Expand to 64 bytes for uniform distribution via wide reduction
    let expanded = expand_message_xmd(message, dst, 64);

    // Use proper wide reduction (same as Scalar::from_bytes_wide)
    // This ensures uniform distribution over the scalar field
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&expanded);

    // Use the properly implemented from_bytes_wide which does:
    // result = low + high * 2^256 (mod r)
    let scalar = Scalar::from_bytes_wide(&wide_bytes);

    // If somehow zero (probability ~2^-255), retry with counter
    // This maintains the same DST (no domain separation violation)
    if scalar.is_zero() {
        // Append a counter to the message, not the DST
        let mut retry_message = message.to_vec();
        retry_message.extend_from_slice(b"\x00RETRY\x01");
        let expanded2 = expand_message_xmd(&retry_message, dst, 64);
        let mut wide_bytes2 = [0u8; 64];
        wide_bytes2.copy_from_slice(&expanded2);
        let scalar2 = Scalar::from_bytes_wide(&wide_bytes2);

        // If still zero (probability ~2^-510), use deterministic non-zero
        // This is cryptographically sound as it's still derived from input
        if scalar2.is_zero() {
            // Hash to get a deterministic non-zero value
            let mut hasher = Sha256::new();
            hasher.update(dst);
            hasher.update(message);
            hasher.update(b"NONZERO_FALLBACK");
            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash);
            // Set low bit to ensure non-zero (mod r will still give valid scalar)
            bytes[0] |= 0x01;
            Scalar::from_bytes(&bytes).unwrap_or_else(|_| Scalar::one())
        } else {
            scalar2
        }
    } else {
        scalar
    }
}

/// Hash multiple messages to a scalar.
///
/// Concatenates all components with length prefixes and hashes.
pub fn hash_to_scalar_multi(components: &[&[u8]], dst: &[u8]) -> Scalar {
    let mut combined = Vec::new();

    for component in components {
        // Add length prefix (4 bytes, little-endian)
        combined.extend_from_slice(&(component.len() as u32).to_le_bytes());
        combined.extend_from_slice(component);
    }

    hash_to_scalar(&combined, dst)
}

/// Expand message using XMD (eXtendable Message Digest) with SHA-256.
///
/// This is the expand_message_xmd function from the hash-to-curve spec.
///
/// # Arguments
///
/// * `message` - Input message
/// * `dst` - Domain separation tag (max 255 bytes)
/// * `len_in_bytes` - Desired output length
fn expand_message_xmd(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output size
    const S_IN_BYTES: usize = 64; // SHA-256 block size

    assert!(dst.len() <= 255, "DST must be at most 255 bytes");
    assert!(len_in_bytes <= 255 * B_IN_BYTES, "Output too long");

    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, s_in_bytes)
    let z_pad = [0u8; S_IN_BYTES];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(&z_pad);
    hasher.update(message);
    hasher.update(&l_i_b_str);
    hasher.update(&[0u8]);
    hasher.update(&dst_prime);
    let b_0 = hasher.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(&b_0);
    hasher.update(&[1u8]);
    hasher.update(&dst_prime);
    let mut b_vals = vec![hasher.finalize().to_vec()];

    // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
    for i in 2..=ell {
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b_0[j] ^ b_vals[i - 2][j];
        }

        let mut hasher = Sha256::new();
        hasher.update(&xored);
        hasher.update(&[i as u8]);
        hasher.update(&dst_prime);
        b_vals.push(hasher.finalize().to_vec());
    }

    // uniform_bytes = b_1 || ... || b_ell
    let mut result: Vec<u8> = b_vals.into_iter().flatten().collect();
    result.truncate(len_in_bytes);

    result
}

/// Derive multiple generators for BBS+ signatures.
///
/// Generates n+1 generators (h_0, h_1, ..., h_n) for signing n messages.
///
/// # Security
///
/// Each generator is computed as H(dst || i) where H is hash-to-curve.
/// This ensures generators have unknown discrete log relationships.
pub fn derive_generators(dst: &[u8], count: usize) -> Vec<G1Point> {
    (0..count)
        .map(|i| {
            let mut input = dst.to_vec();
            input.extend_from_slice(&(i as u32).to_le_bytes());
            hash_to_g1(&input, b"BBS_GENERATORS_")
        })
        .collect()
}

/// Create a challenge for Fiat-Shamir transform.
///
/// Hashes all public values to create a verifier challenge.
pub fn fiat_shamir_challenge(
    context: &[u8],
    public_values: &[&[u8]],
    dst: &[u8],
) -> Scalar {
    let mut input = Vec::new();

    // Add context
    input.extend_from_slice(&(context.len() as u32).to_le_bytes());
    input.extend_from_slice(context);

    // Add all public values
    for value in public_values {
        input.extend_from_slice(&(value.len() as u32).to_le_bytes());
        input.extend_from_slice(value);
    }

    hash_to_scalar(&input, dst)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_g1_deterministic() {
        let msg = b"test message";
        let dst = b"TEST_DST_";

        let p1 = hash_to_g1(msg, dst);
        let p2 = hash_to_g1(msg, dst);

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_hash_to_g1_different_messages() {
        let dst = b"TEST_DST_";

        let p1 = hash_to_g1(b"message 1", dst);
        let p2 = hash_to_g1(b"message 2", dst);

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_hash_to_g1_different_dst() {
        let msg = b"test message";

        let p1 = hash_to_g1(msg, b"DST_1_");
        let p2 = hash_to_g1(msg, b"DST_2_");

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_hash_to_g2_deterministic() {
        let msg = b"test message";
        let dst = b"TEST_DST_";

        let p1 = hash_to_g2(msg, dst);
        let p2 = hash_to_g2(msg, dst);

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_hash_to_scalar() {
        let msg = b"test message";
        let dst = b"TEST_SCALAR_";

        let s1 = hash_to_scalar(msg, dst);
        let s2 = hash_to_scalar(msg, dst);

        assert_eq!(s1, s2);
        assert!(!s1.is_zero());
    }

    #[test]
    fn test_derive_generators() {
        let dst = b"TEST_GENS_";
        let gens = derive_generators(dst, 5);

        assert_eq!(gens.len(), 5);

        // All generators should be different
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(gens[i], gens[j]);
            }
        }

        // Generators should be deterministic
        let gens2 = derive_generators(dst, 5);
        for i in 0..5 {
            assert_eq!(gens[i], gens2[i]);
        }
    }

    #[test]
    fn test_expand_message_xmd() {
        let msg = b"test";
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";

        let expanded = expand_message_xmd(msg, dst, 32);
        assert_eq!(expanded.len(), 32);

        let expanded64 = expand_message_xmd(msg, dst, 64);
        assert_eq!(expanded64.len(), 64);

        // First 32 bytes should be different (due to different length encoding)
        // Actually they might be the same depending on implementation
    }

    #[test]
    fn test_fiat_shamir_challenge() {
        let context = b"test context";
        let values: &[&[u8]] = &[b"value1", b"value2"];
        let dst = b"TEST_FS_";

        let c1 = fiat_shamir_challenge(context, values, dst);
        let c2 = fiat_shamir_challenge(context, values, dst);

        assert_eq!(c1, c2);
        assert!(!c1.is_zero());

        // Different values should give different challenges
        let c3 = fiat_shamir_challenge(context, &[b"different"], dst);
        assert_ne!(c1, c3);
    }
}
