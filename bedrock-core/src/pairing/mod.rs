//! Pairing Cryptography Foundation (Tier 1)
//!
//! This module provides BLS12-381 elliptic curve operations for:
//! - BBS+ anonymous credentials
//! - BLS signatures for device binding
//! - VOPRF for rate-limiting tokens
//!
//! # Security
//!
//! BLS12-381 provides approximately 128 bits of security against classical attacks.
//! The `blstrs` library is backed by `blst` which has been:
//! - Audited by NCC Group
//! - Formally verified in collaboration with Galois and Ethereum Foundation
//! - Used in production by Ethereum 2.0 and Filecoin
//!
//! # Groups
//!
//! - G1: 48-byte compressed points (used for signatures in BBS+)
//! - G2: 96-byte compressed points (used for public keys in BBS+)
//! - GT: Pairing target group (576 bytes, used for verification)
//! - Fr: Scalar field (~255 bits)

pub mod bls12_381;
pub mod hash_to_curve;

pub use bls12_381::{
    G1Point, G2Point, GtElement, Scalar,
    G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE, GT_SIZE,
    pairing, multi_pairing, verify_pairing_eq,
    BlsSecretKey, BlsPublicKey, BlsSignature,
};
pub use hash_to_curve::{
    hash_to_g1, hash_to_g2, hash_to_scalar, hash_to_scalar_multi,
    derive_generators, fiat_shamir_challenge,
};

/// Domain separation tags for various protocols
pub mod dst {
    /// BBS+ signature
    pub const BBS_SIGN: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGN_";
    /// BBS+ proof
    pub const BBS_PROOF: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_";
    /// Device binding
    pub const DEVICE_BIND: &[u8] = b"OFFGRID_DEVICE_BIND_V1_";
    /// BLS signature
    pub const BLS_SIG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    /// VOPRF
    pub const VOPRF: &[u8] = b"OFFGRID_VOPRF_V1_";
    /// Ring signature
    pub const RING_SIG: &[u8] = b"OFFGRID_RING_SIG_V1_";
    /// Fuzzy tag
    pub const FUZZY_TAG: &[u8] = b"OFFGRID_FUZZY_TAG_V1_";
    /// Key derivation
    pub const KEY_DERIVE: &[u8] = b"OFFGRID_KEY_DERIVE_V1_";
    /// Credential request
    pub const CRED_REQUEST: &[u8] = b"OFFGRID_CRED_REQUEST_V1_";
    /// Token request
    pub const TOKEN_REQUEST: &[u8] = b"OFFGRID_TOKEN_REQUEST_V1_";
}

/// Constants for the anonymous credential system
pub mod constants {
    /// Maximum number of attributes in a credential
    pub const MAX_CREDENTIAL_ATTRIBUTES: usize = 16;

    /// Maximum ring size for ring signatures
    pub const MAX_RING_SIZE: usize = 64;

    /// Minimum ring size for anonymity
    pub const MIN_RING_SIZE: usize = 3;

    /// Default tokens per epoch
    pub const DEFAULT_TOKENS_PER_EPOCH: u32 = 100;

    /// Default epoch duration in seconds (24 hours)
    pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 86400;

    /// Default fuzzy tag false positive rate (10%)
    pub const DEFAULT_FUZZY_TAG_GAMMA: f64 = 0.1;

    /// Argon2id memory cost (64 MB)
    pub const ARGON2_M_COST: u32 = 65536;

    /// Argon2id time cost (3 iterations)
    pub const ARGON2_T_COST: u32 = 3;

    /// Argon2id parallelism (4 lanes)
    pub const ARGON2_P_COST: u32 = 4;

    /// Key output length
    pub const KEY_OUTPUT_LEN: usize = 32;
}
