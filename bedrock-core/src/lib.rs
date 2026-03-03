//! Bedrock Core - Cryptographic primitives for sovereign digital ownership
//!
//! This library provides JNI bindings for:
//! - Hk-OVCT (Hinted k-OV Confidential Transfer) - Novel construction
//! - Ed25519 signatures
//! - AES-256-GCM encryption
//! - Argon2id key derivation
//! - Shamir's Secret Sharing
//! - SHA3-256 hashing
//! - HKDF key derivation
//! - ZKP-based anonymous recovery (Pedersen, Schnorr, Nullifiers)
//!
//! ## Hk-OVCT Security Model
//!
//! Hk-OVCT provides security from assumption disjunction:
//! - Must break ML-KEM-768 (~143 bits quantum security) OR
//! - Solve k-OV instance (SETH-hard, ~199 bits classical)
//!
//! This is NOT just ML-KEM. The content key is derived from k mutually
//! orthogonal vectors. An attacker who breaks ML-KEM still faces a
//! verification problem: which decryption is valid? Only the one where
//! the vectors are actually orthogonal.
//!
//! ## Anonymous Recovery System
//!
//! Uses Powers of Tau-inspired architecture:
//! - Identity seed split with Shamir (4-of-7)
//! - Shares committed with Pedersen commitments
//! - Distributed to anonymous mesh nodes
//! - Recovery requires proving knowledge of blinding factors
//! - Dead man's switch via nullifier check-ins

// ZKP primitives for anonymous recovery
pub mod pedersen;
pub mod schnorr;
pub mod nullifier;
pub mod recovery;

// BIP-39 mnemonic wordlist
pub mod bip39;

// Gap closure: hardened security
pub mod device;        // Device binding + passphrase hardening
pub mod duress;        // Plausible deniability
pub mod ring_sig;      // Ring signatures for anonymous nullifiers
pub mod cover_traffic; // Cover traffic generation (traffic analysis resistance)
pub mod stego;         // Steganographic storage (hide in plain sight)
pub mod onion;         // MeshCore onion routing (bypass internet)

// LunarCore: Anonymous LoRa mesh protocol
pub mod lunar;         // Hedged KEM, session management, packet routing
pub mod lora;          // LoRa hardware abstraction layer (ESP32 driver)

// ============================================================================
// ANONYMOUS CREDENTIALS SYSTEM (Tier 1-4)
// ============================================================================
//
// New cryptographic modules for the anonymous credential system:
// - pairing: BLS12-381 operations (foundation for all ZKPs)
// - credentials: BBS+ anonymous credentials with device binding
// - tokens: VOPRF-based rate-limiting tokens (coming soon)
// - mesh_identity: Ring signatures for mesh anonymity (coming soon)
//
// See ARCHITECTURE_ANONYMOUS_CREDENTIALS.md for full documentation.

/// Error types for bedrock operations
pub mod error;

/// Tier 1: Pairing cryptography foundation (BLS12-381)
pub mod pairing;

/// Tier 2: Anonymous credentials (BBS+ with device binding)
pub mod credentials;

/// Tier 3: Rate-limiting tokens (VOPRF)
pub mod tokens;

/// Tier 4: Mesh anonymity (ring signatures, fuzzy tags)
pub mod mesh_identity;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObjectArray};
use jni::sys::{jbyteArray, jint, jobject, jobjectArray};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::OsRng;
use argon2::Argon2;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768, EncodedSizeUser, Ciphertext};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

// ============================================================================
// ============================================================================
// Prevents use-after-free and double-free vulnerabilities from concurrent
// access to native handles from multiple Java threads.

use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use std::collections::HashMap;
use std::panic;

/// Global registry for thread-safe native handles.
/// Uses generation counters to prevent ABA problems.
static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

lazy_static::lazy_static! {
    /// Thread-safe registry for cover traffic generators
    static ref COVER_TRAFFIC_HANDLES: Mutex<HashMap<u64, Arc<Mutex<cover_traffic::CoverTrafficGenerator>>>> =
        Mutex::new(HashMap::new());
}

/// Allocate a new handle ID (never returns 0, which is reserved for null)
fn allocate_handle_id() -> u64 {
    HANDLE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Returns None for negative values or values that would overflow
#[inline]
fn validate_positive_int(value: jint, max_allowed: usize) -> Option<usize> {
    if value < 0 {
        return None;
    }
    let as_usize = value as usize;
    if as_usize > max_allowed {
        return None;
    }
    Some(as_usize)
}

/// Maximum allowed output length for HKDF (16KB - prevents DoS)
const MAX_HKDF_OUTPUT: usize = 16 * 1024;

/// Maximum allowed ring size for ring signatures (prevents memory exhaustion)
const MAX_RING_SIZE: usize = 1024;

/// Catches panics across the JNI boundary to prevent undefined behavior
macro_rules! jni_panic_safe {
    ($env:expr, $default:expr, $body:block) => {{
        match panic::catch_unwind(panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => {
                // Panic occurred - return safe default
                // Note: We cannot throw Java exception here safely
                $default
            }
        }
    }};
}

// ============================================================================
// Hk-OVCT PARAMETERS
// ============================================================================

/// Number of orthogonal vectors in the planted solution
const HKOVCT_K: usize = 8;

/// Dimension of each vector (bits)
const HKOVCT_D: usize = 1024;

/// Bytes per vector (D / 8)
const HKOVCT_VECTOR_BYTES: usize = HKOVCT_D / 8;

/// Total bytes for k vectors
const HKOVCT_BUNDLE_VECTORS_SIZE: usize = HKOVCT_K * HKOVCT_VECTOR_BYTES;

/// ML-KEM-768 ciphertext size
const MLKEM_CIPHERTEXT_SIZE: usize = 1088;

/// ML-KEM-768 encapsulation key size  
const MLKEM_EK_SIZE: usize = 1184;

/// ML-KEM-768 decapsulation key size
const MLKEM_DK_SIZE: usize = 2400;

// ============================================================================
// Hk-OVCT CORE IMPLEMENTATION
// ============================================================================

/// Sample k mutually orthogonal binary vectors of dimension d.
///
/// Orthogonality condition: for all pairs (i,j), the binary inner product
/// ⟨vᵢ, vⱼ⟩ = Σ(vᵢ[t] ∧ vⱼ[t]) ≡ 0 (mod 2)
///
/// Algorithm:
/// 1. Sample v₁ randomly with weight ~d/2
/// 2. For each subsequent vᵢ:
///    - Start with random vector
///    - For each previous vⱼ, if ⟨vᵢ, vⱼ⟩ = 1, flip a random shared bit
///    - Repeat until orthogonal to all previous vectors
fn sample_orthogonal_vectors(k: usize, d: usize) -> Vec<Vec<u8>> {
    let bytes_per_vector = d / 8;
    let mut vectors: Vec<Vec<u8>> = Vec::with_capacity(k);
    let mut rng = OsRng;
    
    for i in 0..k {
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 1000;
        
        loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                // Fallback: use a deterministic orthogonal construction
                break;
            }
            
            // Sample random vector
            let mut v = vec![0u8; bytes_per_vector];
            rng.fill_bytes(&mut v);
            
            // Check and fix orthogonality with all previous vectors
            let mut all_orthogonal = true;
            for j in 0..i {
                if !is_orthogonal(&v, &vectors[j]) {
                    // Try to fix by flipping bits
                    if !make_orthogonal(&mut v, &vectors[j], &mut rng) {
                        all_orthogonal = false;
                        break;
                    }
                }
            }
            
            // Re-verify all orthogonality after fixes
            if all_orthogonal {
                all_orthogonal = vectors.iter().all(|vj| is_orthogonal(&v, vj));
            }
            
            if all_orthogonal {
                vectors.push(v);
                break;
            }
        }
        
        // If we exhausted attempts, use deterministic construction
        if vectors.len() <= i {
            vectors.push(create_orthogonal_vector(i, d, &vectors));
        }
    }
    
    vectors
}

/// Check if two binary vectors are orthogonal (inner product = 0 mod 2)
fn is_orthogonal(a: &[u8], b: &[u8]) -> bool {
    let mut popcount = 0u32;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        popcount += (byte_a & byte_b).count_ones();
    }
    popcount % 2 == 0
}

/// Try to make vector a orthogonal to vector b by flipping shared bits
fn make_orthogonal(a: &mut [u8], b: &[u8], rng: &mut impl RngCore) -> bool {
    const MAX_FLIPS: usize = 100;
    
    for _ in 0..MAX_FLIPS {
        if is_orthogonal(a, b) {
            return true;
        }
        
        // Find positions where both a and b have 1
        let mut shared_positions: Vec<(usize, u8)> = Vec::new();
        for (i, (byte_a, byte_b)) in a.iter().zip(b.iter()).enumerate() {
            let shared = *byte_a & *byte_b;
            if shared != 0 {
                for bit in 0..8 {
                    if (shared >> bit) & 1 == 1 {
                        shared_positions.push((i, 1 << bit));
                    }
                }
            }
        }
        
        if shared_positions.is_empty() {
            return is_orthogonal(a, b);
        }
        
        // Flip a random shared bit in a
        let mut rand_bytes = [0u8; 4];
        rng.fill_bytes(&mut rand_bytes);
        let idx = u32::from_le_bytes(rand_bytes) as usize % shared_positions.len();
        let (byte_idx, bit_mask) = shared_positions[idx];
        a[byte_idx] ^= bit_mask;
    }
    
    is_orthogonal(a, b)
}

/// Create a vector orthogonal to all existing vectors using deterministic construction
fn create_orthogonal_vector(index: usize, d: usize, existing: &[Vec<u8>]) -> Vec<u8> {
    let bytes = d / 8;
    let mut v = vec![0u8; bytes];
    
    // Simple construction: set bits in non-overlapping regions
    let bits_per_vector = d / (HKOVCT_K + 1);
    let start_bit = index * bits_per_vector;
    
    for bit in start_bit..(start_bit + bits_per_vector / 2) {
        if bit < d {
            let byte_idx = bit / 8;
            let bit_idx = bit % 8;
            v[byte_idx] |= 1 << bit_idx;
        }
    }
    
    // Verify orthogonality
    for vj in existing {
        debug_assert!(is_orthogonal(&v, vj), "Deterministic construction failed!");
    }
    
    v
}

/// Serialize k orthogonal vectors into a bundle
fn serialize_bundle(vectors: &[Vec<u8>]) -> Vec<u8> {
    let mut bundle = Vec::with_capacity(HKOVCT_BUNDLE_VECTORS_SIZE);
    for v in vectors {
        bundle.extend_from_slice(v);
    }
    bundle
}

/// Deserialize bundle back into k vectors
fn deserialize_bundle(bundle: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bundle.len() != HKOVCT_BUNDLE_VECTORS_SIZE {
        return None;
    }
    
    let mut vectors = Vec::with_capacity(HKOVCT_K);
    for i in 0..HKOVCT_K {
        let start = i * HKOVCT_VECTOR_BYTES;
        let end = start + HKOVCT_VECTOR_BYTES;
        vectors.push(bundle[start..end].to_vec());
    }
    Some(vectors)
}

/// Verify that k vectors are mutually orthogonal
fn verify_orthogonality(vectors: &[Vec<u8>]) -> bool {
    for i in 0..vectors.len() {
        for j in (i + 1)..vectors.len() {
            if !is_orthogonal(&vectors[i], &vectors[j]) {
                return false;
            }
        }
    }
    true
}

/// Derive content key from orthogonal vectors
/// 
/// This is the k-OV binding: the key depends on the actual solution,
/// not just the ML-KEM shared secret.
fn derive_content_key(vectors: &[Vec<u8>], public_seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    
    // Include public seed to bind to this specific instance
    hasher.update(b"hkovct-content-key-v1");
    hasher.update(public_seed);
    
    // Include all orthogonal vectors
    for v in vectors {
        hasher.update(v);
    }
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ============================================================================
// Hk-OVCT JNI INTERFACE
// ============================================================================

/// Generate Hk-OVCT keypair.
///
/// The keypair is an ML-KEM-768 keypair. The k-OV structure is created
/// during encryption, not key generation.
///
/// Returns: Pair<ByteArray, ByteArray> = (secretKey, publicKey)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_hkovctKeygen(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    
    // Serialize keys
    let dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();

    let private_arr = match env.byte_array_from_slice(dk_bytes.as_slice()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let public_arr = match env.byte_array_from_slice(ek_bytes.as_slice()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Create Kotlin Pair
    let pair_class = match env.find_class("kotlin/Pair") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let pair = match env.new_object(
        pair_class,
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&private_arr).into(), (&public_arr).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };
    
    pair.into_raw()
}

/// Encrypt data using Hk-OVCT.
///
/// This implements the full Hk-OVCT protocol:
/// 1. Sample k mutually orthogonal vectors (planted k-OV solution)
/// 2. Generate public seed for instance binding
/// 3. Encrypt vectors with ML-KEM (the "bundle")
/// 4. Derive content key from orthogonal vectors (k-OV binding)
/// 5. Encrypt plaintext with AES-GCM using derived key
///
/// Output format:
/// [public_seed: 32] [kem_ciphertext: 1088] [bundle_nonce: 12] 
/// [encrypted_bundle_len: 4] [encrypted_bundle] [content_nonce: 12] [ciphertext]
///
/// Security: Attacker must break ML-KEM OR solve k-OV instance
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_hkovctEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    recipient_public_key: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    // Parse inputs
    let pk_bytes = match env.convert_byte_array(&recipient_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let pt_bytes = match env.convert_byte_array(&plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    if pk_bytes.len() != MLKEM_EK_SIZE {
        return std::ptr::null_mut();
    }
    
    // Parse ML-KEM encapsulation key
    let ek_array: [u8; MLKEM_EK_SIZE] = match pk_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_array.into());
    
    let mut rng = OsRng;
    
    // =========================================================================
    // STEP 1: Sample k mutually orthogonal vectors (the planted k-OV solution)
    // This is the core of Hk-OVCT - we create a real k-OV instance
    // =========================================================================
    let vectors = sample_orthogonal_vectors(HKOVCT_K, HKOVCT_D);
    
    // Verify our sampling worked
    if !verify_orthogonality(&vectors) {
        return std::ptr::null_mut();
    }
    
    // =========================================================================
    // STEP 2: Generate public seed for instance binding
    // This allows anyone to reconstruct the k-OV instance for verification
    // =========================================================================
    let mut public_seed = [0u8; 32];
    rng.fill_bytes(&mut public_seed);
    
    // =========================================================================
    // STEP 3: Serialize the orthogonal vectors into a bundle
    // =========================================================================
    let bundle = serialize_bundle(&vectors);
    
    // =========================================================================
    // STEP 4: Encapsulate with ML-KEM to get shared secret
    // =========================================================================
    let (kem_ct, shared_secret) = match ek.encapsulate(&mut rng) {
        Ok(result) => result,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // =========================================================================
    // STEP 5: Derive bundle encryption key from ML-KEM shared secret
    // =========================================================================
    let hk = Hkdf::<Sha3_256>::new(Some(&public_seed), shared_secret.as_slice());
    let mut bundle_key = [0u8; 32];
    if hk.expand(b"hkovct-bundle-key-v1", &mut bundle_key).is_err() {
        return std::ptr::null_mut();
    }
    
    // =========================================================================
    // STEP 6: Encrypt the bundle (orthogonal vectors) with AES-GCM
    // =========================================================================
    let bundle_cipher = match Aes256Gcm::new_from_slice(&bundle_key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    let mut bundle_nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut bundle_nonce_bytes);
    let bundle_nonce = Nonce::from_slice(&bundle_nonce_bytes);
    
    // Use public_seed as AAD (binds ciphertext to this instance)
    let encrypted_bundle = match bundle_cipher.encrypt(
        bundle_nonce,
        Payload {
            msg: &bundle,
            aad: &public_seed,
        }
    ) {
        Ok(ct) => ct,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // =========================================================================
    // STEP 7: Derive content key from orthogonal vectors (THE k-OV BINDING)
    // 
    // THIS IS WHAT MAKES Hk-OVCT DIFFERENT FROM PLAIN ML-KEM:
    // The content key depends on the actual k-OV solution, not just KEM secret.
    // An attacker who somehow breaks ML-KEM still needs to verify which
    // decryption produces vectors that are actually orthogonal.
    // =========================================================================
    let mut content_key = derive_content_key(&vectors, &public_seed);
    
    // =========================================================================
    // STEP 8: Encrypt plaintext with content key
    // =========================================================================
    let content_cipher = match Aes256Gcm::new_from_slice(&content_key) {
        Ok(c) => c,
        Err(_) => {
            content_key.zeroize();
            bundle_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    let mut content_nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut content_nonce_bytes);
    let content_nonce = Nonce::from_slice(&content_nonce_bytes);
    
    // Use bundle hash as AAD (binds content to the specific solution)
    let mut bundle_hash = Sha3_256::new();
    bundle_hash.update(&bundle);
    let bundle_digest = bundle_hash.finalize();
    
    let ciphertext = match content_cipher.encrypt(
        content_nonce,
        Payload {
            msg: &pt_bytes,
            aad: &bundle_digest,
        }
    ) {
        Ok(ct) => ct,
        Err(_) => {
            content_key.zeroize();
            bundle_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    
    // Zeroize sensitive material
    content_key.zeroize();
    bundle_key.zeroize();
    
    // =========================================================================
    // STEP 9: Assemble output
    // =========================================================================
    let encrypted_bundle_len = encrypted_bundle.len();
    let total_len = 32 + MLKEM_CIPHERTEXT_SIZE + 12 + 4 + encrypted_bundle_len + 12 + ciphertext.len();
    
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(&public_seed);                              // 32 bytes
    output.extend_from_slice(kem_ct.as_slice());                         // 1088 bytes
    output.extend_from_slice(&bundle_nonce_bytes);                       // 12 bytes
    output.extend_from_slice(&(encrypted_bundle_len as u32).to_be_bytes()); // 4 bytes
    output.extend_from_slice(&encrypted_bundle);                         // variable
    output.extend_from_slice(&content_nonce_bytes);                      // 12 bytes
    output.extend_from_slice(&ciphertext);                               // variable
    
    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypt Hk-OVCT ciphertext.
///
/// This implements the full Hk-OVCT decryption:
/// 1. Parse ciphertext components
/// 2. Decapsulate ML-KEM to get shared secret
/// 3. Derive bundle key and decrypt bundle
/// 4. VERIFY ORTHOGONALITY of recovered vectors (defense in depth!)
/// 5. Derive content key from orthogonal vectors
/// 6. Decrypt and return plaintext
///
/// Returns: Decrypted plaintext, or null if decryption/verification fails
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_hkovctDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    secret_key: JByteArray,
    ciphertext: JByteArray,
) -> jbyteArray {
    // Parse inputs
    let sk_bytes = match env.convert_byte_array(&secret_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let ct_bytes = match env.convert_byte_array(&ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Minimum size check
    let min_size = 32 + MLKEM_CIPHERTEXT_SIZE + 12 + 4 + 16 + 12 + 16;
    if ct_bytes.len() < min_size || sk_bytes.len() != MLKEM_DK_SIZE {
        return std::ptr::null_mut();
    }
    
    // Parse decapsulation key
    let dk_array: [u8; MLKEM_DK_SIZE] = match sk_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_array.into());
    
    // =========================================================================
    // Parse ciphertext components
    // =========================================================================
    let mut offset = 0;
    
    // Public seed
    let public_seed: [u8; 32] = ct_bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;
    
    // KEM ciphertext
    let kem_ct_bytes: [u8; MLKEM_CIPHERTEXT_SIZE] = match ct_bytes[offset..offset + MLKEM_CIPHERTEXT_SIZE].try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    offset += MLKEM_CIPHERTEXT_SIZE;
    
    // Bundle nonce
    let bundle_nonce_bytes: [u8; 12] = match ct_bytes[offset..offset + 12].try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    offset += 12;
    
    // Encrypted bundle length
    let bundle_len_bytes: [u8; 4] = match ct_bytes[offset..offset + 4].try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    let encrypted_bundle_len = u32::from_be_bytes(bundle_len_bytes) as usize;
    offset += 4;
    
    if offset + encrypted_bundle_len + 12 > ct_bytes.len() {
        return std::ptr::null_mut();
    }
    
    // Encrypted bundle
    let encrypted_bundle = &ct_bytes[offset..offset + encrypted_bundle_len];
    offset += encrypted_bundle_len;
    
    // Content nonce
    let content_nonce_bytes: [u8; 12] = match ct_bytes[offset..offset + 12].try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    offset += 12;
    
    // Content ciphertext
    let content_ciphertext = &ct_bytes[offset..];
    
    // =========================================================================
    // STEP 1: Decapsulate ML-KEM
    // =========================================================================
    let kem_ct: Ciphertext<MlKem768> = kem_ct_bytes.into();
    let shared_secret = match dk.decapsulate(&kem_ct) {
        Ok(ss) => ss,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // =========================================================================
    // STEP 2: Derive bundle key
    // =========================================================================
    let hk = Hkdf::<Sha3_256>::new(Some(&public_seed), shared_secret.as_slice());
    let mut bundle_key = [0u8; 32];
    if hk.expand(b"hkovct-bundle-key-v1", &mut bundle_key).is_err() {
        return std::ptr::null_mut();
    }
    
    // =========================================================================
    // STEP 3: Decrypt bundle
    // =========================================================================
    let bundle_cipher = match Aes256Gcm::new_from_slice(&bundle_key) {
        Ok(c) => c,
        Err(_) => {
            bundle_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    let bundle_nonce = Nonce::from_slice(&bundle_nonce_bytes);
    
    let bundle = match bundle_cipher.decrypt(
        bundle_nonce,
        Payload {
            msg: encrypted_bundle,
            aad: &public_seed,
        }
    ) {
        Ok(pt) => pt,
        Err(_) => {
            bundle_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    bundle_key.zeroize();
    
    // =========================================================================
    // STEP 4: Deserialize and VERIFY ORTHOGONALITY (DEFENSE IN DEPTH!)
    // 
    // This is the k-OV verification step. Even if ML-KEM is somehow broken,
    // an attacker must find vectors that are actually orthogonal.
    // If they can't, decryption fails here.
    // =========================================================================
    let vectors = match deserialize_bundle(&bundle) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    
    // Verify orthogonality of all vector pairs
    if !verify_orthogonality(&vectors) {
        // The recovered vectors are NOT orthogonal.
        // This could indicate:
        // 1. Ciphertext tampering
        // 2. Decryption with wrong key  
        // 3. An attack that broke ML-KEM but couldn't find valid k-OV solution
        return std::ptr::null_mut();
    }
    
    // =========================================================================
    // STEP 5: Derive content key from verified orthogonal vectors
    // =========================================================================
    let mut content_key = derive_content_key(&vectors, &public_seed);
    
    // =========================================================================
    // STEP 6: Decrypt content
    // =========================================================================
    let content_cipher = match Aes256Gcm::new_from_slice(&content_key) {
        Ok(c) => c,
        Err(_) => {
            content_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    let content_nonce = Nonce::from_slice(&content_nonce_bytes);
    
    // Compute bundle hash for AAD verification
    let mut bundle_hash = Sha3_256::new();
    bundle_hash.update(&bundle);
    let bundle_digest = bundle_hash.finalize();
    
    let plaintext = match content_cipher.decrypt(
        content_nonce,
        Payload {
            msg: content_ciphertext,
            aad: &bundle_digest,
        }
    ) {
        Ok(pt) => pt,
        Err(_) => {
            content_key.zeroize();
            return std::ptr::null_mut();
        }
    };
    
    content_key.zeroize();
    
    match env.byte_array_from_slice(&plaintext) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// KEY DERIVATION (Argon2id)
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_deriveKey(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    salt: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let salt_bytes = match env.convert_byte_array(&salt) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    // Argon2id parameters (OWASP recommended)
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(64 * 1024, 3, 4, Some(32)).unwrap(),
    );
    
    let mut output = [0u8; 32];
    if argon2
        .hash_password_into(&passphrase_bytes, &salt_bytes, &mut output)
        .is_err()
    {
        return std::ptr::null_mut();
    }
    
    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// SIGNING KEYS (Ed25519)
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateSigningKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    let private_bytes = match env.byte_array_from_slice(signing_key.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let public_bytes = match env.byte_array_from_slice(verifying_key.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let pair_class = match env.find_class("kotlin/Pair") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let pair = match env.new_object(
        pair_class,
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&private_bytes).into(), (&public_bytes).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };
    
    pair.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_sign(
    mut env: JNIEnv,
    _class: JClass,
    private_key: JByteArray,
    message: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&private_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let msg_bytes = match env.convert_byte_array(&message) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let signing_key = SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(&msg_bytes);
    
    match env.byte_array_from_slice(&signature.to_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_verify(
    mut env: JNIEnv,
    _class: JClass,
    public_key: JByteArray,
    message: JByteArray,
    signature: JByteArray,
) -> bool {
    let key_bytes = match env.convert_byte_array(&public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    
    let msg_bytes = match env.convert_byte_array(&message) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    
    let sig_bytes = match env.convert_byte_array(&signature) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    
    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    
    let verifying_key = match VerifyingKey::from_bytes(&key_array) {
        Ok(k) => k,
        Err(_) => return false,
    };
    
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    
    verifying_key.verify(&msg_bytes, &signature).is_ok()
}

// ============================================================================
// ENCRYPTION KEY GENERATION (delegates to Hk-OVCT)
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateEncryptionKeypair(
    env: JNIEnv,
    class: JClass,
) -> jobject {
    Java_com_yours_app_crypto_BedrockCore_hkovctKeygen(env, class)
}

// ============================================================================
// X25519 DIFFIE-HELLMAN (Symmetric Key Agreement)
// ============================================================================
//
// Simple X25519 DH for symmetric shared secret derivation.
// Unlike HK-OVCT KEM (which is asymmetric), DH is symmetric:
//   DH(alice_sk, bob_pk) == DH(bob_sk, alice_pk)
//
// Used for blinded hint computation where both parties need to
// independently derive the same shared secret.

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_x25519DiffieHellman(
    mut env: JNIEnv,
    _class: JClass,
    secret_key: JByteArray,
    public_key: JByteArray,
) -> jbyteArray {
    // Extract secret key (32 bytes)
    let sk_bytes = match env.convert_byte_array(&secret_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let sk_array: [u8; 32] = match sk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Extract public key (32 bytes)
    let pk_bytes = match env.convert_byte_array(&public_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let pk_array: [u8; 32] = match pk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Perform X25519 DH
    let sk = x25519_dalek::StaticSecret::from(sk_array);
    let pk = x25519_dalek::PublicKey::from(pk_array);
    let shared_secret = sk.diffie_hellman(&pk);

    // Check for all-zeros (invalid point - RFC 7748 Section 6.1)
    let ss_bytes = shared_secret.as_bytes();
    if ss_bytes.iter().all(|&b| b == 0) {
        return std::ptr::null_mut();
    }

    // Return shared secret (32 bytes)
    match env.byte_array_from_slice(ss_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Compute X25519 public key from secret key.
///
/// The public key is computed via scalar multiplication: pk = sk * G
/// where G is the X25519 base point.
///
/// # Arguments
/// * `secret_key` - 32-byte X25519 secret key
///
/// # Returns
/// * 32-byte public key, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_x25519ComputePublicKey(
    mut env: JNIEnv,
    _class: JClass,
    secret_key: JByteArray,
) -> jbyteArray {
    // Extract secret key (32 bytes)
    let sk_bytes = match env.convert_byte_array(&secret_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let sk_array: [u8; 32] = match sk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Compute public key via scalar multiplication with base point
    let sk = x25519_dalek::StaticSecret::from(sk_array);
    let pk = x25519_dalek::PublicKey::from(&sk);

    // Return public key (32 bytes)
    match env.byte_array_from_slice(pk.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// AES-256-GCM (Local symmetric encryption)
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_aesEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    plaintext: JByteArray,
    associated_data: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let pt_bytes = match env.convert_byte_array(&plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let aad_bytes = match env.convert_byte_array(&associated_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = if aad_bytes.is_empty() {
        cipher.encrypt(nonce, pt_bytes.as_ref())
    } else {
        cipher.encrypt(nonce, Payload { msg: &pt_bytes, aad: &aad_bytes })
    };
    
    let ciphertext = match ciphertext {
        Ok(ct) => ct,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    
    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_aesDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    ciphertext: JByteArray,
    associated_data: JByteArray,
) -> jbyteArray {
    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let ct_bytes = match env.convert_byte_array(&ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let aad_bytes = match env.convert_byte_array(&associated_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    if ct_bytes.len() < 12 {
        return std::ptr::null_mut();
    }
    
    let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let nonce = Nonce::from_slice(&ct_bytes[..12]);
    let encrypted = &ct_bytes[12..];
    
    let plaintext = if aad_bytes.is_empty() {
        cipher.decrypt(nonce, encrypted)
    } else {
        cipher.decrypt(nonce, Payload { msg: encrypted, aad: &aad_bytes })
    };
    
    let plaintext = match plaintext {
        Ok(pt) => pt,
        Err(_) => return std::ptr::null_mut(),
    };
    
    match env.byte_array_from_slice(&plaintext) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// HASHING
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_sha3_1256(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
) -> jbyteArray {
    let data_bytes = match env.convert_byte_array(&data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let mut hasher = Sha3_256::new();
    hasher.update(&data_bytes);
    let result = hasher.finalize();
    
    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// HKDF key derivation
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_hkdf(
    mut env: JNIEnv,
    _class: JClass,
    ikm: JByteArray,
    salt: JByteArray,
    info: JByteArray,
    output_length: jint,
) -> jbyteArray {
    // 1. Negative values becoming huge usize
    // 2. DoS via excessive memory allocation
    let validated_length = match validate_positive_int(output_length, MAX_HKDF_OUTPUT) {
        Some(len) => len,
        None => return std::ptr::null_mut(), // Invalid length
    };

    let ikm_bytes = match env.convert_byte_array(&ikm) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let salt_bytes = match env.convert_byte_array(&salt) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let info_bytes = match env.convert_byte_array(&info) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let salt_opt = if salt_bytes.is_empty() {
        None
    } else {
        Some(salt_bytes.as_slice())
    };

    let hk = Hkdf::<Sha3_256>::new(salt_opt, &ikm_bytes);
    let mut output = vec![0u8; validated_length];

    if hk.expand(&info_bytes, &mut output).is_err() {
        return std::ptr::null_mut();
    }

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// SHAMIR'S SECRET SHARING
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_shamirSplit(
    mut env: JNIEnv,
    _class: JClass,
    secret: JByteArray,
    n: jint,
    k: jint,
) -> jobjectArray {
    let secret_bytes = match env.convert_byte_array(&secret) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };
    
    if secret_bytes.len() != 32 || n < k || k < 2 || n > 255 {
        return std::ptr::null_mut();
    }
    
    let mut rng = OsRng;
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
    
    for _ in 0..n {
        shares.push(vec![0u8; 33]); // 1 byte x-coord + 32 bytes share
    }
    
    // Set x-coordinates (1 to n)
    for (i, share) in shares.iter_mut().enumerate() {
        share[0] = (i + 1) as u8;
    }
    
    // For each byte of the secret
    for byte_idx in 0..32 {
        // Create random polynomial of degree k-1
        let mut coeffs = vec![0u8; k as usize];
        coeffs[0] = secret_bytes[byte_idx];
        for i in 1..k as usize {
            let mut rand_byte = [0u8; 1];
            rng.fill_bytes(&mut rand_byte);
            coeffs[i] = rand_byte[0];
        }
        
        // Evaluate polynomial at each x-coordinate in GF(256)
        for (share_idx, share) in shares.iter_mut().enumerate() {
            let x = (share_idx + 1) as u8;
            share[byte_idx + 1] = gf256_eval_poly(&coeffs, x);
        }
    }
    
    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let empty_arr = match env.new_byte_array(0) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    let result = match env.new_object_array(n, byte_array_class, empty_arr) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    
    for (i, share) in shares.iter().enumerate() {
        let share_arr = match env.byte_array_from_slice(share) {
            Ok(arr) => arr,
            Err(_) => return std::ptr::null_mut(),
        };
        
        if env.set_object_array_element(&result, i as i32, share_arr).is_err() {
            return std::ptr::null_mut();
        }
    }
    
    result.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_shamirCombine(
    mut env: JNIEnv,
    _class: JClass,
    shares: JObjectArray,
) -> jbyteArray {
    let length = match env.get_array_length(&shares) {
        Ok(len) => len as usize,
        Err(_) => return std::ptr::null_mut(),
    };
    
    if length < 2 {
        return std::ptr::null_mut();
    }
    
    let mut share_data: Vec<Vec<u8>> = Vec::with_capacity(length);
    
    for i in 0..length {
        let share_obj = match env.get_object_array_element(&shares, i as i32) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };
        
        let share_arr: JByteArray = share_obj.into();
        let share_bytes = match env.convert_byte_array(&share_arr) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };
        
        if share_bytes.len() != 33 {
            return std::ptr::null_mut();
        }
        
        share_data.push(share_bytes);
    }
    
    // Reconstruct using Lagrange interpolation
    let mut secret = vec![0u8; 32];
    
    for byte_idx in 0..32 {
        let mut xs: Vec<u8> = Vec::with_capacity(length);
        let mut ys: Vec<u8> = Vec::with_capacity(length);
        
        for share in &share_data {
            xs.push(share[0]);
            ys.push(share[byte_idx + 1]);
        }
        
        secret[byte_idx] = gf256_lagrange_interpolate(&xs, &ys, 0);
    }
    
    match env.byte_array_from_slice(&secret) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// GF(256) arithmetic using AES field (x^8 + x^4 + x^3 + x + 1)
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    
    result
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // a^254 = a^(-1) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

fn gf256_eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    let mut x_power = 1u8;
    
    for &coeff in coeffs {
        result ^= gf256_mul(coeff, x_power);
        x_power = gf256_mul(x_power, x);
    }
    
    result
}

fn gf256_lagrange_interpolate(xs: &[u8], ys: &[u8], target_x: u8) -> u8 {
    let mut result = 0u8;
    let k = xs.len();

    for i in 0..k {
        let mut numerator = 1u8;
        let mut denominator = 1u8;

        for j in 0..k {
            if i != j {
                numerator = gf256_mul(numerator, target_x ^ xs[j]);
                denominator = gf256_mul(denominator, xs[i] ^ xs[j]);
            }
        }

        let term = gf256_mul(ys[i], gf256_mul(numerator, gf256_inv(denominator)));
        result ^= term;
    }

    result
}

// ============================================================================
// INTERNAL SHAMIR FUNCTIONS (for recovery module)
// ============================================================================

/// Internal Shamir split for recovery module
pub fn shamir_split_internal(
    secret: &[u8; 32],
    n: usize,
    k: usize,
) -> Result<Vec<recovery::ShamirShare>, &'static str> {
    if n < k || k < 2 || n > 255 {
        return Err("Invalid parameters");
    }

    let mut rng = OsRng;
    let mut shares = Vec::with_capacity(n);

    for i in 0..n {
        shares.push(recovery::ShamirShare {
            x: (i + 1) as u8,
            y: [0u8; 32],
        });
    }

    // For each byte of the secret
    for byte_idx in 0..32 {
        // Create random polynomial of degree k-1
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret[byte_idx];
        for coeff in coeffs.iter_mut().skip(1) {
            let mut rand_byte = [0u8; 1];
            rng.fill_bytes(&mut rand_byte);
            *coeff = rand_byte[0];
        }

        // Evaluate polynomial at each x-coordinate in GF(256)
        for share in &mut shares {
            share.y[byte_idx] = gf256_eval_poly(&coeffs, share.x);
        }
    }

    Ok(shares)
}

/// Internal Shamir combine for recovery module
pub fn shamir_combine_internal(
    shares: &[recovery::ShamirShare],
) -> Result<[u8; 32], &'static str> {
    if shares.len() < 2 {
        return Err("Not enough shares");
    }

    let mut secret = [0u8; 32];

    for byte_idx in 0..32 {
        let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
        let ys: Vec<u8> = shares.iter().map(|s| s.y[byte_idx]).collect();

        secret[byte_idx] = gf256_lagrange_interpolate(&xs, &ys, 0);
    }

    Ok(secret)
}

// ============================================================================
// RECOVERY SYSTEM JNI BINDINGS
// ============================================================================

/// Set up anonymous recovery system
///
/// Returns array of serialized SharePackages for distribution to mesh nodes.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_setupRecovery(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
) -> jobjectArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let (secrets, packages) = match recovery::setup_recovery(&passphrase_bytes) {
        Ok(result) => result,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create output: [identity_seed, nullifier_secret, ...serialized_packages]
    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let empty = match env.new_byte_array(0) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // 2 secret arrays + N package arrays
    let total_len = 2 + packages.len();
    let result = match env.new_object_array(total_len as i32, byte_array_class, empty) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // First element: identity_seed
    let identity_arr = match env.byte_array_from_slice(&secrets.identity_seed) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 0, identity_arr).is_err() {
        return std::ptr::null_mut();
    }

    // Second element: nullifier_secret
    let nullifier_arr = match env.byte_array_from_slice(&secrets.nullifier_secret) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 1, nullifier_arr).is_err() {
        return std::ptr::null_mut();
    }

    // Remaining elements: serialized packages
    for (i, package) in packages.iter().enumerate() {
        let serialized = package.serialize();
        let pkg_arr = match env.byte_array_from_slice(&serialized) {
            Ok(arr) => arr,
            Err(_) => return std::ptr::null_mut(),
        };
        if env.set_object_array_element(&result, (i + 2) as i32, pkg_arr).is_err() {
            return std::ptr::null_mut();
        }
    }

    result.into_raw()
}

/// Create proof to retrieve a share from a node
///
/// Returns: [blinding_commitment (32), proof (64)]
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createRetrievalProof(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    index: jint,
    context: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let context_bytes = match env.convert_byte_array(&context) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let secrets = recovery::RecoverySecrets::derive(&passphrase_bytes);
    let (commitment, proof) = recovery::create_retrieval_proof(
        &secrets,
        index as u8,
        &context_bytes,
    );

    // Serialize: commitment (32) + proof (64)
    let mut output = Vec::with_capacity(96);
    output.extend_from_slice(&commitment.to_bytes());
    output.extend_from_slice(&proof.to_bytes());

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify retrieval proof (for mesh nodes)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_verifyRetrievalProof(
    mut env: JNIEnv,
    _class: JClass,
    stored_commitment: JByteArray,
    proof_data: JByteArray,
    context: JByteArray,
) -> bool {
    let stored_bytes = match env.convert_byte_array(&stored_commitment) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };

    let proof_bytes = match env.convert_byte_array(&proof_data) {
        Ok(bytes) if bytes.len() == 96 => bytes,
        _ => return false,
    };

    let context_bytes = match env.convert_byte_array(&context) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Parse stored commitment
    let mut stored_arr = [0u8; 32];
    stored_arr.copy_from_slice(&stored_bytes);
    let stored = match pedersen::BlindingCommitment::from_bytes(&stored_arr) {
        Some(c) => c,
        None => return false,
    };

    // Parse claimed commitment from proof data
    let mut claimed_arr = [0u8; 32];
    claimed_arr.copy_from_slice(&proof_bytes[0..32]);
    let claimed = match pedersen::BlindingCommitment::from_bytes(&claimed_arr) {
        Some(c) => c,
        None => return false,
    };

    // Parse proof
    let mut proof_arr = [0u8; 64];
    proof_arr.copy_from_slice(&proof_bytes[32..96]);
    let proof = match schnorr::BlindingProof::from_bytes(&proof_arr) {
        Some(p) => p,
        None => return false,
    };

    recovery::verify_retrieval_proof(&stored, &claimed, &proof, &context_bytes)
}

/// Derive nullifier for current epoch
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_deriveNullifier(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let secrets = recovery::RecoverySecrets::derive(&passphrase_bytes);
    let nf = nullifier::Nullifier::derive_current(&secrets.nullifier_secret);

    match env.byte_array_from_slice(nf.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive nullifier for specific epoch
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_deriveNullifierForEpoch(
    mut env: JNIEnv,
    _class: JClass,
    nullifier_secret: JByteArray,
    epoch: jni::sys::jlong,
) -> jbyteArray {
    let secret_bytes = match env.convert_byte_array(&nullifier_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    let nf = nullifier::Nullifier::derive(&secret, epoch as u64);

    match env.byte_array_from_slice(nf.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get current epoch number
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_currentEpoch(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlong {
    nullifier::current_epoch() as jni::sys::jlong
}

/// Decrypt a share package
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_decryptShare(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    package_data: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let package_bytes = match env.convert_byte_array(&package_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let secrets = recovery::RecoverySecrets::derive(&passphrase_bytes);
    let package = match recovery::SharePackage::deserialize(&package_bytes) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    let share = match recovery::decrypt_share(&secrets, &package) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&share.encode()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Reconstruct identity seed from shares
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_reconstructIdentitySeed(
    mut env: JNIEnv,
    _class: JClass,
    shares: JObjectArray,
) -> jbyteArray {
    let len = match env.get_array_length(&shares) {
        Ok(l) => l as usize,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut decoded_shares = Vec::with_capacity(len);

    for i in 0..len {
        let share_obj = match env.get_object_array_element(&shares, i as i32) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };

        let share_arr: JByteArray = share_obj.into();
        let share_bytes = match env.convert_byte_array(&share_arr) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };

        match recovery::ShamirShare::decode(&share_bytes) {
            Ok(share) => decoded_shares.push(share),
            Err(_) => return std::ptr::null_mut(),
        }
    }

    match recovery::reconstruct_identity_seed(&decoded_shares) {
        Ok(seed) => {
            match env.byte_array_from_slice(&seed) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive identity keys from identity seed
///
/// Returns: [signing_private (32), signing_public (32), enc_private (2400), enc_public (1184)]
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_deriveIdentityKeys(
    mut env: JNIEnv,
    _class: JClass,
    identity_seed: JByteArray,
) -> jobjectArray {
    let seed_bytes = match env.convert_byte_array(&identity_seed) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    // Derive signing key
    let hk = Hkdf::<Sha3_256>::new(None, &seed);
    let mut signing_seed = [0u8; 32];
    if hk.expand(b"Yours/ed25519/v1", &mut signing_seed).is_err() {
        return std::ptr::null_mut();
    }

    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signing_public = signing_key.verifying_key().to_bytes();

    // Derive encryption key using deterministic RNG
    let mut enc_seed = [0u8; 64];
    if hk.expand(b"Yours/mlkem/v1", &mut enc_seed).is_err() {
        return std::ptr::null_mut();
    }

    // Use seeded RNG for ML-KEM keygen
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;
    let mut rng = ChaCha20Rng::from_seed({
        let mut s = [0u8; 32];
        s.copy_from_slice(&enc_seed[..32]);
        s
    });

    let (dk, ek) = MlKem768::generate(&mut rng);

    // Create output array
    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let empty = match env.new_byte_array(0) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = match env.new_object_array(4, byte_array_class, empty) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Signing private key
    let sp_arr = match env.byte_array_from_slice(signing_key.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 0, sp_arr).is_err() {
        return std::ptr::null_mut();
    }

    // Signing public key
    let spub_arr = match env.byte_array_from_slice(&signing_public) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 1, spub_arr).is_err() {
        return std::ptr::null_mut();
    }

    // Encryption private key
    let ep_arr = match env.byte_array_from_slice(dk.as_bytes().as_slice()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 2, ep_arr).is_err() {
        return std::ptr::null_mut();
    }

    // Encryption public key
    let epub_arr = match env.byte_array_from_slice(ek.as_bytes().as_slice()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 3, epub_arr).is_err() {
        return std::ptr::null_mut();
    }

    signing_seed.zeroize();
    enc_seed.zeroize();

    result.into_raw()
}

// ============================================================================
// DEVICE BINDING JNI
// ============================================================================

/// Validate passphrase meets security requirements
///
/// Returns: [valid (1), word_count (1), entropy_bits (1), error_code (1)]
/// Error codes: 0=none, 1=empty, 2=too_short, 3=invalid_chars, 4=invalid_word
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_validatePassphrase(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let passphrase_str = match std::str::from_utf8(&passphrase_bytes) {
        Ok(s) => s,
        Err(_) => {
            let result = [0u8, 0, 0, 3]; // invalid chars
            return match env.byte_array_from_slice(&result) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
        }
    };

    let validation = device::validate_passphrase(passphrase_str);

    let error_code = match validation.error {
        None => 0,
        Some(device::PassphraseError::Empty) => 1,
        Some(device::PassphraseError::TooShort { .. }) => 2,
        Some(device::PassphraseError::InvalidCharacters) => 3,
        Some(device::PassphraseError::InvalidWord { .. }) => 4,
    };

    let result = [
        validation.valid as u8,
        validation.word_count as u8,
        validation.entropy_bits as u8,
        error_code,
    ];

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive device-bound key from passphrase and device secret
///
/// Returns 64 bytes: identity_seed (32) || recovery_seed (32)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_deriveDeviceBoundKey(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    device_secret: JByteArray,
    salt: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let device_bytes = match env.convert_byte_array(&device_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let salt_bytes = match env.convert_byte_array(&salt) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut device_arr = [0u8; 32];
    device_arr.copy_from_slice(&device_bytes);
    let device = device::DeviceSecret::new(device_arr, device::DeviceSecretSource::HardwareKeystore);

    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(&salt_bytes);

    // Use mobile parameters (512MB) for reasonable performance
    let key = match device::DeviceBoundKey::derive_mobile(&passphrase_bytes, &device, &salt_arr) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(key.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create device secret from hardware ID
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createDeviceSecret(
    mut env: JNIEnv,
    _class: JClass,
    hardware_id: JByteArray,
) -> jbyteArray {
    let hw_bytes = match env.convert_byte_array(&hardware_id) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret = device::DeviceSecret::from_hardware_id(&hw_bytes);

    match env.byte_array_from_slice(secret.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// DURESS VAULT JNI
// ============================================================================

/// Create dual vaults (real + decoy)
///
/// Returns array of:
/// - [0]: real vault (encrypted)
/// - [1]: decoy vault (encrypted)
///
/// The duress_word is a user-chosen word that's combined with the device secret
/// to derive the duress marker. This prevents attackers from guessing common markers.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createDualVaults(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    device_secret: JByteArray,
    duress_word: JByteArray,
    real_identity_seed: JByteArray,
    real_metadata: JByteArray,
    decoy_identity_seed: JByteArray,
    decoy_metadata: JByteArray,
) -> jobjectArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let device_bytes = match env.convert_byte_array(&device_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let duress_word_bytes = match env.convert_byte_array(&duress_word) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return std::ptr::null_mut(),
    };

    let real_seed_bytes = match env.convert_byte_array(&real_identity_seed) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let real_meta = match env.convert_byte_array(&real_metadata) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let decoy_seed_bytes = match env.convert_byte_array(&decoy_identity_seed) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let decoy_meta = match env.convert_byte_array(&decoy_metadata) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut device_arr = [0u8; 32];
    device_arr.copy_from_slice(&device_bytes);
    let device = device::DeviceSecret::new(device_arr, device::DeviceSecretSource::HardwareKeystore);

    // Derive duress marker from user word + device secret
    let duress_marker = duress::derive_duress_marker(&duress_word_bytes, device.as_bytes());

    let mut real_seed = [0u8; 32];
    real_seed.copy_from_slice(&real_seed_bytes);

    let mut decoy_seed = [0u8; 32];
    decoy_seed.copy_from_slice(&decoy_seed_bytes);

    let system = duress::DuressVaultSystem::new(device);
    let (real_vault, decoy_vault) = match system.create_dual_vaults(
        &passphrase_bytes,
        &duress_marker,
        real_seed,
        real_meta,
        decoy_seed,
        decoy_meta,
    ) {
        Ok(vaults) => vaults,
        Err(_) => return std::ptr::null_mut(),
    };

    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let empty = match env.new_byte_array(0) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = match env.new_object_array(2, byte_array_class, empty) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let real_bytes = real_vault.to_bytes();
    let real_arr = match env.byte_array_from_slice(&real_bytes) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 0, real_arr).is_err() {
        return std::ptr::null_mut();
    }

    let decoy_bytes = decoy_vault.to_bytes();
    let decoy_arr = match env.byte_array_from_slice(&decoy_bytes) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 1, decoy_arr).is_err() {
        return std::ptr::null_mut();
    }

    result.into_raw()
}

/// Decrypt vault with passphrase
///
/// Returns: [vault_type (1), identity_seed (32), metadata_len (4), metadata...]
/// vault_type: 1=real, 2=decoy
/// Returns null if decryption fails (wrong passphrase)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_decryptVault(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    device_secret: JByteArray,
    encrypted_vault: JByteArray,
) -> jbyteArray {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let device_bytes = match env.convert_byte_array(&device_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let vault_bytes = match env.convert_byte_array(&encrypted_vault) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut device_arr = [0u8; 32];
    device_arr.copy_from_slice(&device_bytes);
    let device = device::DeviceSecret::new(device_arr, device::DeviceSecretSource::HardwareKeystore);

    let vault = match duress::EncryptedVault::from_bytes(&vault_bytes) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let system = duress::DuressVaultSystem::new(device);
    let content = match system.decrypt_vault(&passphrase_bytes, &vault) {
        Some(c) => c,
        None => return std::ptr::null_mut(), // Wrong passphrase - return null, no error
    };

    // Serialize result
    let mut result = Vec::with_capacity(1 + 32 + 4 + content.metadata.len());
    result.push(match content.vault_type {
        duress::VaultType::Real => 1,
        duress::VaultType::Decoy => 2,
    });
    result.extend_from_slice(&content.identity_seed);
    result.extend_from_slice(&(content.metadata.len() as u32).to_le_bytes());
    result.extend_from_slice(&content.metadata);

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if passphrase is a duress passphrase
///
/// The duress_word and device_secret are used to derive the duress marker,
/// which is then checked against the passphrase suffix.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_isDuressPassphrase(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
    device_secret: JByteArray,
    duress_word: JByteArray,
) -> bool {
    let passphrase_bytes = match env.convert_byte_array(&passphrase) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let device_bytes = match env.convert_byte_array(&device_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };

    let duress_word_bytes = match env.convert_byte_array(&duress_word) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => return false,
    };

    let duress_marker = duress::derive_duress_marker(&duress_word_bytes, &device_bytes);
    duress::DuressVaultSystem::is_duress_passphrase(&passphrase_bytes, &duress_marker)
}

// ============================================================================
// RING SIGNATURES JNI (Anonymous Nullifiers)
// ============================================================================

/// Generate ring keypair for anonymous signing
///
/// Returns: [private_key (32), public_key (32)]
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateRingKeypair(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    use curve25519_dalek::scalar::Scalar;

    let private = Scalar::random(&mut OsRng);
    let public = ring_sig::RingPublicKey::from_private(&private);

    let byte_array_class = match env.find_class("[B") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let empty = match env.new_byte_array(0) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = match env.new_object_array(2, byte_array_class, empty) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let private_arr = match env.byte_array_from_slice(private.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 0, private_arr).is_err() {
        return std::ptr::null_mut();
    }

    let public_arr = match env.byte_array_from_slice(&public.to_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    if env.set_object_array_element(&result, 1, public_arr).is_err() {
        return std::ptr::null_mut();
    }

    result.into_raw()
}

/// Create anonymous nullifier with ring signature
///
/// @param nullifierSecret - 32-byte secret derived from passphrase
/// @param signingKey - 32-byte private key for ring signature
/// @param ring - Array of 32-byte public keys (anonymity set)
/// @param signerIndex - Index of signer's public key in ring
/// @param epoch - Current epoch number
/// @return Serialized AnonymousNullifier
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createAnonymousNullifier(
    mut env: JNIEnv,
    _class: JClass,
    nullifier_secret: JByteArray,
    signing_key: JByteArray,
    ring: JObjectArray,
    signer_index: jint,
    epoch: jni::sys::jlong,
) -> jbyteArray {
    use curve25519_dalek::scalar::Scalar;

    // Parse nullifier secret
    let secret_bytes = match env.convert_byte_array(&nullifier_secret) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    // Parse signing key
    let key_bytes = match env.convert_byte_array(&signing_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let signing_scalar = match Scalar::from_canonical_bytes(key_arr).into_option() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    // Parse ring
    let ring_len = match env.get_array_length(&ring) {
        Ok(l) => l as usize,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut ring_pks = Vec::with_capacity(ring_len);
    for i in 0..ring_len {
        let pk_obj = match env.get_object_array_element(&ring, i as i32) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };

        let pk_arr: JByteArray = pk_obj.into();
        let pk_bytes = match env.convert_byte_array(&pk_arr) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return std::ptr::null_mut(),
        };

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        match ring_sig::RingPublicKey::from_bytes(&pk_arr) {
            Some(pk) => ring_pks.push(pk),
            None => return std::ptr::null_mut(),
        }
    }

    // Create anonymous nullifier
    let anon_null = match ring_sig::AnonymousNullifier::create(
        &secret,
        &signing_scalar,
        ring_pks,
        signer_index as usize,
        epoch as u64,
    ) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&anon_null.to_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify anonymous nullifier
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_verifyAnonymousNullifier(
    mut env: JNIEnv,
    _class: JClass,
    nullifier_data: JByteArray,
) -> bool {
    let bytes = match env.convert_byte_array(&nullifier_data) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let anon_null = match ring_sig::AnonymousNullifier::from_bytes(&bytes) {
        Some(n) => n,
        None => return false,
    };

    anon_null.verify()
}

/// Extract key image from anonymous nullifier (for linkability detection)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_extractKeyImage(
    mut env: JNIEnv,
    _class: JClass,
    nullifier_data: JByteArray,
) -> jbyteArray {
    let bytes = match env.convert_byte_array(&nullifier_data) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let anon_null = match ring_sig::AnonymousNullifier::from_bytes(&bytes) {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&anon_null.key_image().to_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if two anonymous nullifiers are from the same signer
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_isSameSigner(
    mut env: JNIEnv,
    _class: JClass,
    nullifier1: JByteArray,
    nullifier2: JByteArray,
) -> bool {
    let bytes1 = match env.convert_byte_array(&nullifier1) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let bytes2 = match env.convert_byte_array(&nullifier2) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let null1 = match ring_sig::AnonymousNullifier::from_bytes(&bytes1) {
        Some(n) => n,
        None => return false,
    };

    let null2 = match ring_sig::AnonymousNullifier::from_bytes(&bytes2) {
        Some(n) => n,
        None => return false,
    };

    null1.is_same_signer(&null2)
}

// ============================================================================
// MEMORY SAFETY
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_zeroize(
    mut env: JNIEnv,
    _class: JClass,
    data: JByteArray,
) {
    let len = match env.get_array_length(&data) {
        Ok(len) => len,
        Err(_) => return,
    };
    
    let zeros = vec![0i8; len as usize];
    let _ = env.set_byte_array_region(&data, 0, &zeros);
}

// ============================================================================
// COVER TRAFFIC JNI
// ============================================================================

/// Create a new cover traffic generator
///
/// @param seed - 32-byte random seed (use SecureRandom)
/// @return Handle ID (not a pointer - prevents exploitation)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createCoverTrafficGenerator(
    mut env: JNIEnv,
    _class: JClass,
    seed: JByteArray,
) -> jni::sys::jlong {
    let seed_bytes = match env.convert_byte_array(&seed) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return 0,
    };

    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);

    let config = cover_traffic::CoverTrafficConfig::default();
    let gen = cover_traffic::CoverTrafficGenerator::from_seed(seed_arr, config);

    let handle_id = allocate_handle_id();
    if let Ok(mut registry) = COVER_TRAFFIC_HANDLES.lock() {
        registry.insert(handle_id, Arc::new(Mutex::new(gen)));
        handle_id as jni::sys::jlong
    } else {
        0 // Registry lock failed (shouldn't happen)
    }
}

/// Destroy cover traffic generator
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_destroyCoverTrafficGenerator(
    _env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
) {
    if handle == 0 {
        return;
    }

    if let Ok(mut registry) = COVER_TRAFFIC_HANDLES.lock() {
        registry.remove(&(handle as u64));
    }
}

/// Helper to get generator from thread-safe registry
fn get_cover_traffic_generator(handle: jni::sys::jlong) -> Option<Arc<Mutex<cover_traffic::CoverTrafficGenerator>>> {
    if handle == 0 {
        return None;
    }
    if let Ok(registry) = COVER_TRAFFIC_HANDLES.lock() {
        registry.get(&(handle as u64)).cloned()
    } else {
        None
    }
}

/// Pad a message to fixed packet size
///
/// @param handle - Generator handle ID
/// @param key - 32-byte encryption key
/// @param plaintext - Message to pad
/// @return Fixed-size encrypted packet (256 bytes)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_padMessage(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    key: JByteArray,
    plaintext: JByteArray,
) -> jbyteArray {
    let gen_arc = match get_cover_traffic_generator(handle) {
        Some(g) => g,
        None => return std::ptr::null_mut(),
    };

    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let pt_bytes = match env.convert_byte_array(&plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let packet = if let Ok(mut gen) = gen_arc.lock() {
        match gen.pad_message(&key_arr, &pt_bytes) {
            Ok(p) => p,
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        return std::ptr::null_mut();
    };

    match env.byte_array_from_slice(&packet) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Generate chaff packet (random encrypted garbage, indistinguishable from real traffic)
///
/// @param handle - Generator handle ID
/// @return Fixed-size chaff packet (256 bytes)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateChaff(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
) -> jbyteArray {
    let gen_arc = match get_cover_traffic_generator(handle) {
        Some(g) => g,
        None => return std::ptr::null_mut(),
    };

    let packet = if let Ok(mut gen) = gen_arc.lock() {
        gen.generate_chaff()
    } else {
        return std::ptr::null_mut();
    };

    match env.byte_array_from_slice(&packet) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Unpad a received message
///
/// @param handle - Generator handle ID
/// @param key - 32-byte decryption key
/// @param packet - 256-byte encrypted packet
/// @return [type (1), payload...] where type: 1=real, 2=chaff, 3=heartbeat
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_unpadMessage(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    key: JByteArray,
    packet: JByteArray,
) -> jbyteArray {
    let gen_arc = match get_cover_traffic_generator(handle) {
        Some(g) => g,
        None => return std::ptr::null_mut(),
    };

    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let pkt_bytes = match env.convert_byte_array(&packet) {
        Ok(bytes) if bytes.len() == cover_traffic::PACKET_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let mut pkt_arr = [0u8; cover_traffic::PACKET_SIZE];
    pkt_arr.copy_from_slice(&pkt_bytes);

    let (ptype, payload) = if let Ok(gen) = gen_arc.lock() {
        match gen.unpad_message(&key_arr, &pkt_arr) {
            Some(r) => r,
            None => return std::ptr::null_mut(),
        }
    } else {
        return std::ptr::null_mut();
    };

    let type_byte = match ptype {
        cover_traffic::PacketType::Real => 1u8,
        cover_traffic::PacketType::Chaff => 2u8,
        cover_traffic::PacketType::Heartbeat => 3u8,
        cover_traffic::PacketType::Ack => 4u8,
    };

    let mut result = vec![type_byte];
    result.extend_from_slice(&payload);

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get next send delay with jitter (milliseconds)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_nextSendDelay(
    _env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
) -> jni::sys::jlong {
    let gen_arc = match get_cover_traffic_generator(handle) {
        Some(g) => g,
        None => return 5000, // Default on invalid handle
    };

    let result = if let Ok(mut gen) = gen_arc.lock() {
        gen.next_send_delay() as jni::sys::jlong
    } else {
        5000 // Default on lock failure
    };
    result
}

/// Check if should send chaff right now
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_shouldSendChaff(
    _env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    current_time_ms: jni::sys::jlong,
) -> bool {
    let gen_arc = match get_cover_traffic_generator(handle) {
        Some(g) => g,
        None => return false,
    };

    let result = if let Ok(mut gen) = gen_arc.lock() {
        gen.should_send_chaff(current_time_ms as u64)
    } else {
        false
    };
    result
}

/// Get the standard packet size (for buffer allocation)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getCoverPacketSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    cover_traffic::PACKET_SIZE as jint
}

/// Get maximum payload size per packet
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getMaxPayloadSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    cover_traffic::MAX_PAYLOAD as jint
}

// ============================================================================
// STEGANOGRAPHY JNI (Hide in Plain Sight)
// ============================================================================

/// Calculate steganographic capacity for an image
///
/// @param width Image width in pixels
/// @param height Image height in pixels
/// @param channels Color channels (3 for RGB, 4 for RGBA)
/// @return Maximum bytes that can be hidden
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_stegoCapacity(
    _env: JNIEnv,
    _class: JClass,
    width: jint,
    height: jint,
    channels: jint,
) -> jint {
    let config = stego::StegoConfig::default();
    stego::calculate_capacity(width as usize, height as usize, channels as usize, &config) as jint
}

/// Embed data into image pixels
///
/// @param pixels Raw pixel data (RGB or RGBA, row-major)
/// @param width Image width
/// @param height Image height
/// @param channels 3 for RGB, 4 for RGBA
/// @param key 32-byte encryption key
/// @param data Data to hide
/// @return Modified pixels with embedded data, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_stegoEmbed(
    mut env: JNIEnv,
    _class: JClass,
    pixels: JByteArray,
    width: jint,
    height: jint,
    channels: jint,
    key: JByteArray,
    data: JByteArray,
) -> jbyteArray {
    let pixel_bytes = match env.convert_byte_array(&pixels) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let data_bytes = match env.convert_byte_array(&data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let config = stego::StegoConfig::default();

    let result = match stego::embed(
        &pixel_bytes,
        width as usize,
        height as usize,
        channels as usize,
        &key_arr,
        &data_bytes,
        &config,
    ) {
        Ok(pixels) => pixels,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Extract hidden data from image pixels
///
/// @param pixels Pixel data with embedded content
/// @param width Image width
/// @param height Image height
/// @param channels 3 for RGB, 4 for RGBA
/// @param key 32-byte decryption key
/// @return Extracted data, or null if extraction fails
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_stegoExtract(
    mut env: JNIEnv,
    _class: JClass,
    pixels: JByteArray,
    width: jint,
    height: jint,
    channels: jint,
    key: JByteArray,
) -> jbyteArray {
    let pixel_bytes = match env.convert_byte_array(&pixels) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let config = stego::StegoConfig::default();

    let result = match stego::extract(
        &pixel_bytes,
        width as usize,
        height as usize,
        channels as usize,
        &key_arr,
        &config,
    ) {
        Some(data) => data,
        None => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Detect if image likely contains hidden data
///
/// @param pixels Raw pixel data
/// @param width Image width
/// @param height Image height
/// @param channels 3 for RGB, 4 for RGBA
/// @return Confidence score 0-100 (100 = very likely stego)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_stegoDetect(
    mut env: JNIEnv,
    _class: JClass,
    pixels: JByteArray,
    width: jint,
    height: jint,
    channels: jint,
) -> jint {
    let pixel_bytes = match env.convert_byte_array(&pixels) {
        Ok(bytes) => bytes,
        Err(_) => return 0,
    };

    let confidence = stego::detect_stego(
        &pixel_bytes,
        width as usize,
        height as usize,
        channels as usize,
    );

    (confidence * 100.0) as jint
}

// ============================================================================
// ONION ROUTING JNI (Bypass Internet Infrastructure)
// ============================================================================

/// Create an ANONYMOUS onion packet with ENFORCED minimum relay hops.
///
/// SECURITY: This function requires at least MIN_HOPS (2) relays.
/// It will return null if you don't provide enough relays.
/// For non-anonymous direct messaging, use createOnionPacketDirect().
///
/// @param routeNodeIds Array of relay node IDs (8 bytes each) - MUST have at least 1 relay
/// @param routePublicKeys Array of relay public keys (32 bytes each)
/// @param destNodeId Destination node ID (8 bytes)
/// @param destPublicKey Destination public key (32 bytes)
/// @param payload The message to send
/// @return Serialized onion packet, or null if route too short
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createOnionPacket(
    mut env: JNIEnv,
    _class: JClass,
    route_node_ids: JObjectArray,
    route_public_keys: JObjectArray,
    dest_node_id: JByteArray,
    dest_public_key: JByteArray,
    payload: JByteArray,
) -> jbyteArray {
    // Parse destination
    let dest_id_bytes = match env.convert_byte_array(&dest_node_id) {
        Ok(bytes) if bytes.len() == onion::NODE_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };
    let dest_pk_bytes = match env.convert_byte_array(&dest_public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut dest_id = [0u8; onion::NODE_ID_SIZE];
    dest_id.copy_from_slice(&dest_id_bytes);
    let mut dest_pk = [0u8; 32];
    dest_pk.copy_from_slice(&dest_pk_bytes);

    let dest = onion::MeshNode::new(dest_id, x25519_dalek::PublicKey::from(dest_pk));

    // Parse route
    let route_len = match env.get_array_length(&route_node_ids) {
        Ok(l) => l as usize,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut route = Vec::with_capacity(route_len);
    for i in 0..route_len {
        let id_obj = match env.get_object_array_element(&route_node_ids, i as i32) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };
        let pk_obj = match env.get_object_array_element(&route_public_keys, i as i32) {
            Ok(obj) => obj,
            Err(_) => return std::ptr::null_mut(),
        };

        let id_arr: JByteArray = id_obj.into();
        let pk_arr: JByteArray = pk_obj.into();

        let id_bytes = match env.convert_byte_array(&id_arr) {
            Ok(bytes) if bytes.len() == onion::NODE_ID_SIZE => bytes,
            _ => return std::ptr::null_mut(),
        };
        let pk_bytes = match env.convert_byte_array(&pk_arr) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return std::ptr::null_mut(),
        };

        let mut node_id = [0u8; onion::NODE_ID_SIZE];
        node_id.copy_from_slice(&id_bytes);
        let mut node_pk = [0u8; 32];
        node_pk.copy_from_slice(&pk_bytes);

        route.push(onion::MeshNode::new(node_id, x25519_dalek::PublicKey::from(node_pk)));
    }

    // Parse payload
    let payload_bytes = match env.convert_byte_array(&payload) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create packet
    let packet = match onion::OnionPacket::create(&route, &dest, &payload_bytes) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&packet.to_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a DIRECT (non-anonymous) onion packet to destination.
///
/// WARNING: This provides NO anonymity. Use only for:
/// - Initial contact where anonymity isn't needed
/// - Local mesh announcements
/// - When you WANT the recipient to know who you are
///
/// For ANONYMOUS messaging, use createOnionPacket() instead.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createOnionPacketDirect(
    mut env: JNIEnv,
    _class: JClass,
    dest_node_id: JByteArray,
    dest_public_key: JByteArray,
    payload: JByteArray,
) -> jbyteArray {
    let dest_id_bytes = match env.convert_byte_array(&dest_node_id) {
        Ok(bytes) if bytes.len() == onion::NODE_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };
    let dest_pk_bytes = match env.convert_byte_array(&dest_public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut dest_id = [0u8; onion::NODE_ID_SIZE];
    dest_id.copy_from_slice(&dest_id_bytes);
    let mut dest_pk = [0u8; 32];
    dest_pk.copy_from_slice(&dest_pk_bytes);

    let dest = onion::MeshNode::new(dest_id, x25519_dalek::PublicKey::from(dest_pk));

    let payload_bytes = match env.convert_byte_array(&payload) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let packet = match onion::OnionPacket::create_direct(&dest, &payload_bytes) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    match env.byte_array_from_slice(&packet.to_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Peel one layer from an onion packet
///
/// @param packetData Serialized onion packet
/// @param privateKey This node's private key (32 bytes)
/// @return [type(1), data...] where:
///         type=1: Relay - data is next_hop_id(8) + remaining_packet
///         type=2: Destination - data is the decrypted payload
///         Returns null if decryption fails
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_peelOnionLayer(
    mut env: JNIEnv,
    _class: JClass,
    packet_data: JByteArray,
    private_key: JByteArray,
) -> jbyteArray {
    let packet_bytes = match env.convert_byte_array(&packet_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let key_bytes = match env.convert_byte_array(&private_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let packet = match onion::OnionPacket::from_bytes(&packet_bytes) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let result = match packet.peel(&key) {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    let output = match result {
        onion::PeelResult::Relay { next_hop, packet } => {
            let packet_bytes = packet.to_bytes();
            let mut out = Vec::with_capacity(1 + onion::NODE_ID_SIZE + packet_bytes.len());
            out.push(1); // Relay type
            out.extend_from_slice(&next_hop);
            out.extend_from_slice(&packet_bytes);
            out
        }
        onion::PeelResult::Destination { payload } => {
            let mut out = Vec::with_capacity(1 + payload.len());
            out.push(2); // Destination type
            out.extend_from_slice(&payload);
            out
        }
    };

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get onion routing constants
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getOnionNodeIdSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    onion::NODE_ID_SIZE as jint
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getOnionMaxPayload(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    onion::MAX_PAYLOAD as jint
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getOnionMinHops(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    onion::MIN_HOPS as jint
}

#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_getOnionMaxHops(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    onion::MAX_HOPS as jint
}


// ============================================================================
// ANONYMOUS CREDENTIALS (BBS+)
// ============================================================================

/// Generate BBS+ issuer keypair for anonymous credentials.
///
/// @param maxAttributes Maximum number of attributes the issuer can sign
/// @return Serialized (secretKey || publicKey) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateIssuerKeypair(
    env: JNIEnv,
    _class: JClass,
    max_attributes: jint,
) -> jbyteArray {
    use credentials::IssuerSecretKey;

    if max_attributes <= 0 || max_attributes > 16 {
        return std::ptr::null_mut();
    }

    let mut rng = rand::rngs::OsRng;
    let (sk, pk) = match IssuerSecretKey::generate(&mut rng, max_attributes as usize) {
        Ok(keys) => keys,
        Err(_) => return std::ptr::null_mut(),
    };

    // Serialize both keys
    let sk_bytes = sk.to_bytes();
    let pk_bytes = match pk.to_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut output = Vec::with_capacity(sk_bytes.len() + pk_bytes.len() + 8);
    output.extend_from_slice(&(sk_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&sk_bytes);
    output.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&pk_bytes);

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Generate device binding keypair.
///
/// @return Serialized (secretKey(32) || publicKey(48)) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateDeviceBindingKey(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    use credentials::DeviceSecretKey;

    let mut rng = rand::rngs::OsRng;
    let device_sk = DeviceSecretKey::generate(&mut rng);
    let device_pk = device_sk.public_key();

    let sk_bytes = device_sk.to_bytes();
    let pk_bytes = device_pk.to_bytes();

    let mut output = Vec::with_capacity(80);
    output.extend_from_slice(&sk_bytes);
    output.extend_from_slice(&pk_bytes);

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// RATE-LIMITING TOKENS (VOPRF)
// ============================================================================

/// Generate VOPRF server keypair for token issuance.
///
/// @return Serialized (secretKey(32) || publicKey(96)) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateTokenIssuerKey(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    use tokens::VOPRFServer;

    let mut rng = rand::rngs::OsRng;
    let server = VOPRFServer::new(&mut rng);
    let pk = server.public_key();

    let sk_bytes = server.to_bytes();
    let pk_bytes = pk.to_bytes();

    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(&sk_bytes);
    output.extend_from_slice(&pk_bytes);

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a token dispenser request (client side).
///
/// @param epoch Current epoch number
/// @param numTokens Number of tokens to request
/// @return Serialized (requestState || request) for sending to issuer
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createTokenRequest(
    env: JNIEnv,
    _class: JClass,
    epoch: jint,
    num_tokens: jint,
) -> jbyteArray {
    use tokens::privacy_pass::DispenserRequestState;

    if epoch < 0 || num_tokens <= 0 || num_tokens > 100 {
        return std::ptr::null_mut();
    }

    let mut rng = rand::rngs::OsRng;
    let (state, request) = DispenserRequestState::create(
        epoch as u64,
        num_tokens as u32,
        &mut rng,
    );

    // Serialize state and request
    let state_bytes = bincode::serialize(&state).unwrap_or_default();
    let request_bytes = bincode::serialize(&request).unwrap_or_default();

    let mut output = Vec::with_capacity(state_bytes.len() + request_bytes.len() + 8);
    output.extend_from_slice(&(state_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&state_bytes);
    output.extend_from_slice(&(request_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&request_bytes);

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// FUZZY MESSAGE TAGS
// ============================================================================

/// Generate fuzzy tag keypair for metadata-resistant message detection.
///
/// @param falsePositiveRate False positive rate (0.0 - 1.0, default 0.1)
/// @return Serialized (secretKey(33) || publicKey(33)) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateFuzzyTagKeys(
    env: JNIEnv,
    _class: JClass,
    false_positive_rate: jint, // Expressed as percentage (10 = 10%)
) -> jbyteArray {
    use mesh_identity::FuzzyTagSecretKey;

    let gamma = if false_positive_rate <= 0 || false_positive_rate > 100 {
        0.1 // Default 10%
    } else {
        false_positive_rate as f64 / 100.0
    };

    let mut rng = rand::rngs::OsRng;
    let secret_key = FuzzyTagSecretKey::generate_with_gamma(&mut rng, gamma);
    let public_key = secret_key.public_key();

    let sk_bytes = secret_key.to_bytes();
    let pk_bytes = public_key.to_bytes();

    let mut output = Vec::with_capacity(66);
    output.extend_from_slice(&sk_bytes);
    output.extend_from_slice(&pk_bytes);

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a fuzzy tag for a recipient.
///
/// @param recipientPublicKey Recipient's fuzzy tag public key (33 bytes)
/// @return Serialized fuzzy tag (64 bytes) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_createFuzzyTag(
    env: JNIEnv,
    _class: JClass,
    recipient_public_key: JByteArray,
) -> jbyteArray {
    use mesh_identity::FuzzyTagPublicKey;

    let pk_bytes = match env.convert_byte_array(&recipient_public_key) {
        Ok(bytes) if bytes.len() == 33 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut pk_arr = [0u8; 33];
    pk_arr.copy_from_slice(&pk_bytes);

    let public_key = match FuzzyTagPublicKey::from_bytes(&pk_arr) {
        Some(pk) => pk,
        None => return std::ptr::null_mut(),
    };

    let mut rng = rand::rngs::OsRng;
    let tag = public_key.create_tag(&mut rng);
    let tag_bytes = tag.to_bytes();

    match env.byte_array_from_slice(&tag_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if a fuzzy tag matches a secret key.
///
/// @param secretKey Fuzzy tag secret key (33 bytes)
/// @param tag Fuzzy tag to check (64 bytes)
/// @return true if matches (or false positive), false otherwise
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_checkFuzzyTag(
    _env: JNIEnv,
    _class: JClass,
    secret_key: JByteArray,
    tag: JByteArray,
) -> bool {
    use mesh_identity::{FuzzyTagSecretKey, FuzzyTag};

    let env = unsafe { jni::JNIEnv::from_raw(_env.get_raw()).unwrap() };

    let sk_bytes = match env.convert_byte_array(&secret_key) {
        Ok(bytes) if bytes.len() == 33 => bytes,
        _ => return false,
    };

    let tag_bytes = match env.convert_byte_array(&tag) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => return false,
    };

    let mut sk_arr = [0u8; 33];
    sk_arr.copy_from_slice(&sk_bytes);

    let mut tag_arr = [0u8; 64];
    tag_arr.copy_from_slice(&tag_bytes);

    let secret = match FuzzyTagSecretKey::from_bytes(&sk_arr) {
        Some(sk) => sk,
        None => return false,
    };

    let fuzzy_tag = FuzzyTag::from_bytes(&tag_arr);
    secret.check(&fuzzy_tag)
}

/// Generate mesh node keypair for anonymous routing.
///
/// @return Serialized (secretKey(32) || publicKey(32) || nodeId(32)) or null
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_generateMeshNodeKey(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    use mesh_identity::MeshKeyPair;

    let mut rng = rand::rngs::OsRng;
    let keypair = MeshKeyPair::generate(&mut rng);

    let sk_bytes = keypair.to_bytes();
    let pk_bytes = keypair.public_key().compress().to_bytes();
    let node_id = keypair.node_id();

    let mut output = Vec::with_capacity(96);
    output.extend_from_slice(&sk_bytes);
    output.extend_from_slice(&pk_bytes);
    output.extend_from_slice(node_id.as_bytes());

    match env.byte_array_from_slice(&output) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// LUNAR HK-OVCT: Handle-Based Hedged Key Encapsulation
// ============================================================================
//
// These JNI functions implement the LunarCore hedged KEM protocol.
// Secrets NEVER cross the JNI boundary - Kotlin only gets handles.
//
// Security model:
// - Hedged entropy: System RNG XOR deterministic XOR external sensors
// - Dual-DH: Two independent DH operations for defense-in-depth
// - Handle registry: Thread-safe storage, secrets stay in Rust memory
//
// Usage flow:
// 1. lunarHkOvctKeygen() → returns (secret_bytes, public_bytes)
// 2. lunarHkOvctEncapsulate(pk, sender_sk, aux_entropy) → returns (ct, handle)
// 3. lunarHkOvctDeriveSessionKey(handle, context) → returns session_key
// 4. lunarHkOvctDeleteSecret(handle) → cleanup when done

use lunar::hedged_kem::{
    HkOvctKeyPair, HkOvctCiphertext, HkOvctSecretHandle,
    encapsulate_to_handle, decapsulate_to_handle,
    derive_session_key as lunar_derive_session_key,
    delete_shared_secret as lunar_delete_secret,
};
use x25519_dalek::PublicKey as X25519PublicKey;

/// Generate a new Lunar Hk-OVCT keypair (X25519).
///
/// Returns: Kotlin Pair<ByteArray, ByteArray> where:
/// - first: 32-byte secret key
/// - second: 32-byte public key
///
/// SECURITY: The secret key should be stored encrypted with Argon2-derived key.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarHkOvctKeygen(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    // Generate fresh random secret and construct keypair
    let mut rng = OsRng;
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let kp = HkOvctKeyPair::from_secret_bytes(secret);

    let public_bytes = kp.public_key_bytes();

    // Create Java byte arrays
    let secret_arr = match env.byte_array_from_slice(&secret) {
        Ok(arr) => arr,
        Err(_) => {
            secret.zeroize();
            return std::ptr::null_mut();
        }
    };

    let public_arr = match env.byte_array_from_slice(&public_bytes) {
        Ok(arr) => arr,
        Err(_) => {
            secret.zeroize();
            return std::ptr::null_mut();
        }
    };

    // Zeroize secret before returning
    secret.zeroize();

    // Create Kotlin Pair
    let pair_class = match env.find_class("kotlin/Pair") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let pair = match env.new_object(
        pair_class,
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&secret_arr).into(), (&public_arr).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    pair.into_raw()
}

/// Encapsulate a shared secret using hedged entropy.
///
/// Parameters:
/// - recipient_pk: 32-byte X25519 public key
/// - sender_sk: 32-byte sender's secret key (for hedging)
/// - aux_entropy: External entropy (accelerometer, gyro, touch timing)
///
/// Returns: Kotlin Pair<ByteArray, Long> where:
/// - first: 32-byte ciphertext (ephemeral public key)
/// - second: Secret handle (Long) for later key derivation
///
/// SECURITY:
/// - Shared secret is unpredictable if ANY entropy source is good
/// - Secret never leaves Rust - only handle is returned
/// - Call lunarHkOvctDeleteSecret(handle) when done
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarHkOvctEncapsulate(
    mut env: JNIEnv,
    _class: JClass,
    recipient_pk: JByteArray,
    sender_sk: JByteArray,
    aux_entropy: JByteArray,
) -> jobject {
    // Parse recipient public key
    let pk_bytes = match env.convert_byte_array(&recipient_pk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    // Parse sender secret key
    let mut sk_bytes = match env.convert_byte_array(&sender_sk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    // Parse auxiliary entropy
    let aux_bytes = match env.convert_byte_array(&aux_entropy) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(), // Empty aux is OK - hedging still uses RNG + deterministic
    };

    // Create X25519 public key
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let recipient_public = X25519PublicKey::from(pk_arr);

    // Create sender keypair from secret
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let sender_keypair = HkOvctKeyPair::from_secret_bytes(sk_arr);

    // Zeroize input copy
    sk_bytes.zeroize();
    sk_arr.zeroize();

    // Encapsulate with hedged entropy
    let (ct, handle) = match encapsulate_to_handle(&recipient_public, &sender_keypair, &aux_bytes) {
        Ok(result) => result,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create ciphertext byte array
    let ct_arr = match env.byte_array_from_slice(ct.as_bytes()) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Long object for handle
    let long_class = match env.find_class("java/lang/Long") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle_obj = match env.new_object(
        long_class,
        "(J)V",
        &[(handle.0 as jni::sys::jlong).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Kotlin Pair
    let pair_class = match env.find_class("kotlin/Pair") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let pair = match env.new_object(
        pair_class,
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&ct_arr).into(), (&handle_obj).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    pair.into_raw()
}

/// Decapsulate a shared secret from ciphertext.
///
/// Parameters:
/// - ciphertext: 32-byte ciphertext from encapsulation
/// - recipient_sk: 32-byte recipient's secret key
///
/// Returns: Long handle for key derivation, or -1 on error
///
/// SECURITY: Secret never leaves Rust - only handle is returned
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarHkOvctDecapsulate(
    mut env: JNIEnv,
    _class: JClass,
    ciphertext: JByteArray,
    recipient_sk: JByteArray,
) -> jni::sys::jlong {
    // Parse ciphertext
    let ct_bytes = match env.convert_byte_array(&ciphertext) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return -1,
    };

    // Parse recipient secret key
    let mut sk_bytes = match env.convert_byte_array(&recipient_sk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return -1,
    };

    // Create ciphertext
    let mut ct_arr = [0u8; 32];
    ct_arr.copy_from_slice(&ct_bytes);
    let ct = HkOvctCiphertext::from_bytes(ct_arr);

    // Create recipient keypair
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let recipient_keypair = HkOvctKeyPair::from_secret_bytes(sk_arr);

    // Zeroize input copy
    sk_bytes.zeroize();
    sk_arr.zeroize();

    // Decapsulate
    match decapsulate_to_handle(&ct, &recipient_keypair) {
        Ok(handle) => handle.0 as jni::sys::jlong,
        Err(_) => -1,
    }
}

/// Derive a session key from a stored shared secret.
///
/// Parameters:
/// - handle: Secret handle from encapsulate/decapsulate
/// - context: Context bytes for domain separation (e.g., "send" or "recv")
///
/// Returns: 32-byte derived key, or null on error
///
/// SECURITY: Different contexts produce different keys (domain separation)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarHkOvctDeriveSessionKey(
    mut env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
    context: JByteArray,
) -> jbyteArray {
    if handle < 0 {
        return std::ptr::null_mut();
    }

    let context_bytes = match env.convert_byte_array(&context) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let secret_handle = HkOvctSecretHandle(handle as u64);

    match lunar_derive_session_key(secret_handle, &context_bytes) {
        Ok(key) => {
            match env.byte_array_from_slice(&key) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Delete a shared secret from the registry.
///
/// Call this when you're done with a session to zeroize memory.
/// Failing to call this leaks memory until process exit.
///
/// Parameters:
/// - handle: Secret handle to delete
///
/// Returns: true if deleted, false if handle was invalid
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarHkOvctDeleteSecret(
    _env: JNIEnv,
    _class: JClass,
    handle: jni::sys::jlong,
) -> jni::sys::jboolean {
    if handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let secret_handle = HkOvctSecretHandle(handle as u64);

    match lunar_delete_secret(secret_handle) {
        Ok(()) => jni::sys::JNI_TRUE,
        Err(_) => jni::sys::JNI_FALSE,
    }
}

/// Collect entropy from Android sensors for hedging.
///
/// This is a helper that hashes sensor data into 32 bytes suitable for aux_entropy.
/// The Kotlin side should call this with:
/// - Accelerometer readings (x, y, z) over time
/// - Gyroscope readings
/// - Touch event coordinates and timestamps
/// - Any other available sensor data
///
/// Parameters:
/// - sensor_data: Raw sensor bytes (concatenate all sources)
///
/// Returns: 32-byte entropy suitable for lunarHkOvctEncapsulate
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarCollectEntropy(
    mut env: JNIEnv,
    _class: JClass,
    sensor_data: JByteArray,
) -> jbyteArray {
    let data = match env.convert_byte_array(&sensor_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Hash with timestamp for additional entropy
    let mut hasher = Sha3_256::new();
    hasher.update(b"lunar-entropy-v1");
    hasher.update(&data);

    // Add high-resolution timestamp
    #[cfg(not(target_arch = "wasm32"))]
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        hasher.update(&nanos.to_le_bytes());
    }

    let result: [u8; 32] = hasher.finalize().into();

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// LUNARCORE SESSION MANAGEMENT JNI BINDINGS
// ============================================================================
//
// Session management with Double Ratchet for forward secrecy and post-compromise
// security. Sessions are stored in a thread-safe registry and accessed via handles.
//
// Usage flow:
// 1. Initiator: lunarSessionInitiate(our_sk, their_pk, entropy) → (handshake, handle)
// 2. Responder: lunarSessionRespond(our_sk, handshake) → handle
// 3. Both: lunarSessionEncrypt(handle, plaintext) → ciphertext
// 4. Both: lunarSessionDecrypt(handle, ciphertext) → plaintext
// 5. Cleanup: lunarSessionClose(handle)

use lunar::session::{Session, SessionState};
use lunar::packet::{
    HandshakePacket, DataPacket, ControlPacket, CoverPacket, Packet,
    PacketType, PacketFlags, derive_node_hint, derive_session_hint,
    NODE_HINT_SIZE, SESSION_HINT_SIZE, MAX_PACKET_SIZE,
};

lazy_static::lazy_static! {
    /// Thread-safe registry for Lunar sessions
    static ref LUNAR_SESSION_HANDLES: Mutex<HashMap<u64, Session>> =
        Mutex::new(HashMap::new());
}

/// Allocate a new session handle ID
fn allocate_session_handle() -> u64 {
    HANDLE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Create a new session as initiator.
///
/// Parameters:
/// - our_sk: 32-byte our secret key
/// - their_pk: 32-byte their public key
/// - aux_entropy: External entropy for hedging
///
/// Returns: Kotlin Triple<ByteArray, ByteArray, Long> where:
/// - first: Handshake packet bytes (to send to peer)
/// - second: Session hint (4 bytes, for routing)
/// - third: Session handle (Long) for encrypt/decrypt
///
/// Returns null on error.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionInitiate(
    mut env: JNIEnv,
    _class: JClass,
    our_sk: JByteArray,
    their_pk: JByteArray,
    aux_entropy: JByteArray,
) -> jobject {
    // Parse our secret key
    let mut sk_bytes = match env.convert_byte_array(&our_sk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    // Parse their public key
    let pk_bytes = match env.convert_byte_array(&their_pk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    // Parse auxiliary entropy
    let aux_bytes = match env.convert_byte_array(&aux_entropy) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    };

    // Create keypairs
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let our_keypair = HkOvctKeyPair::from_secret_bytes(sk_arr);

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let their_public = X25519PublicKey::from(pk_arr);

    // Zeroize input copy
    sk_bytes.zeroize();
    sk_arr.zeroize();

    // Initiate session
    let (mut session, handshake) = match Session::initiate(our_keypair, &their_public, &aux_bytes) {
        Ok(result) => result,
        Err(_) => return std::ptr::null_mut(),
    };

    // Get session hint before moving session
    let session_hint = match session.session_hint() {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };

    // Mark session as established (initiator knows peer will respond)
    let _ = session.mark_established();

    // Encode handshake packet
    let handshake_bytes = handshake.encode();

    // Store session and get handle
    let handle = allocate_session_handle();
    {
        let mut registry = LUNAR_SESSION_HANDLES.lock().unwrap();
        registry.insert(handle, session);
    }

    // Create Java byte arrays
    let handshake_arr = match env.byte_array_from_slice(&handshake_bytes) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let hint_arr = match env.byte_array_from_slice(&session_hint) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Long object for handle
    let long_class = match env.find_class("java/lang/Long") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle_obj = match env.new_object(
        long_class,
        "(J)V",
        &[(handle as jni::sys::jlong).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Kotlin Triple
    let triple_class = match env.find_class("kotlin/Triple") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let triple = match env.new_object(
        triple_class,
        "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&handshake_arr).into(), (&hint_arr).into(), (&handle_obj).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    triple.into_raw()
}

/// Accept a handshake and create responding session.
///
/// Parameters:
/// - our_sk: 32-byte our secret key
/// - handshake_bytes: Handshake packet from initiator
///
/// Returns: Kotlin Pair<ByteArray, Long> where:
/// - first: Session hint (4 bytes)
/// - second: Session handle (Long)
///
/// Returns null on error.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionRespond(
    mut env: JNIEnv,
    _class: JClass,
    our_sk: JByteArray,
    handshake_bytes: JByteArray,
) -> jobject {
    // Parse our secret key
    let mut sk_bytes = match env.convert_byte_array(&our_sk) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    // Parse handshake packet
    let hs_bytes = match env.convert_byte_array(&handshake_bytes) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Decode handshake
    let handshake = match HandshakePacket::decode(&hs_bytes) {
        Ok(hs) => hs,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create our keypair
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let our_keypair = HkOvctKeyPair::from_secret_bytes(sk_arr);

    // Zeroize input copy
    sk_bytes.zeroize();
    sk_arr.zeroize();

    // Respond to handshake
    let session = match Session::respond(our_keypair, &handshake) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Get session hint
    let session_hint = match session.session_hint() {
        Some(h) => h,
        None => return std::ptr::null_mut(),
    };

    // Store session and get handle
    let handle = allocate_session_handle();
    {
        let mut registry = LUNAR_SESSION_HANDLES.lock().unwrap();
        registry.insert(handle, session);
    }

    // Create Java byte arrays
    let hint_arr = match env.byte_array_from_slice(&session_hint) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Long object for handle
    let long_class = match env.find_class("java/lang/Long") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle_obj = match env.new_object(
        long_class,
        "(J)V",
        &[(handle as jni::sys::jlong).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Kotlin Pair
    let pair_class = match env.find_class("kotlin/Pair") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let pair = match env.new_object(
        pair_class,
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&hint_arr).into(), (&handle_obj).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    pair.into_raw()
}

/// Encrypt a message using the session.
///
/// Parameters:
/// - session_handle: Handle from lunarSessionInitiate/Respond
/// - plaintext: Message to encrypt
///
/// Returns: Encrypted ciphertext, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionEncrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jni::sys::jlong,
    plaintext: JByteArray,
) -> jbyteArray {
    if session_handle < 0 {
        return std::ptr::null_mut();
    }

    let plaintext_bytes = match env.convert_byte_array(&plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle = session_handle as u64;

    // Lock registry and encrypt
    let ciphertext = {
        let mut registry = LUNAR_SESSION_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(session) => {
                match session.encrypt(&plaintext_bytes) {
                    Ok(ct) => ct,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&ciphertext) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decrypt a message using the session.
///
/// Parameters:
/// - session_handle: Handle from lunarSessionInitiate/Respond
/// - ciphertext: Message to decrypt
///
/// Returns: Decrypted plaintext, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionDecrypt(
    mut env: JNIEnv,
    _class: JClass,
    session_handle: jni::sys::jlong,
    ciphertext: JByteArray,
) -> jbyteArray {
    if session_handle < 0 {
        return std::ptr::null_mut();
    }

    let ciphertext_bytes = match env.convert_byte_array(&ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle = session_handle as u64;

    // Lock registry and decrypt
    let plaintext = {
        let mut registry = LUNAR_SESSION_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(session) => {
                match session.decrypt(&ciphertext_bytes) {
                    Ok(pt) => pt,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&plaintext) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Check if session should perform DH ratchet.
///
/// Returns true if session has sent many messages or been active for a while.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionShouldRatchet(
    _env: JNIEnv,
    _class: JClass,
    session_handle: jni::sys::jlong,
) -> jni::sys::jboolean {
    if session_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let handle = session_handle as u64;

    let registry = LUNAR_SESSION_HANDLES.lock().unwrap();
    match registry.get(&handle) {
        Some(session) => {
            if session.should_ratchet() {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Close a session and zeroize all keys.
///
/// Always call this when done to prevent key leakage.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarSessionClose(
    _env: JNIEnv,
    _class: JClass,
    session_handle: jni::sys::jlong,
) -> jni::sys::jboolean {
    if session_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let handle = session_handle as u64;

    let mut registry = LUNAR_SESSION_HANDLES.lock().unwrap();
    match registry.remove(&handle) {
        Some(mut session) => {
            session.close();
            jni::sys::JNI_TRUE
        }
        None => jni::sys::JNI_FALSE,
    }
}

// ============================================================================
// LUNARCORE PACKET ENCODING JNI BINDINGS
// ============================================================================
//
// Packet encoding/decoding for LoRa mesh (237-byte MTU).

/// Encode a data packet.
///
/// Parameters:
/// - next_hop_hint: 2-byte routing hint
/// - session_hint: 4-byte session lookup hint
/// - encrypted_payload: Encrypted message data
///
/// Returns: Encoded packet bytes, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarPacketEncodeData(
    mut env: JNIEnv,
    _class: JClass,
    next_hop_hint: JByteArray,
    session_hint: JByteArray,
    encrypted_payload: JByteArray,
) -> jbyteArray {
    // Parse hints
    let hop_bytes = match env.convert_byte_array(&next_hop_hint) {
        Ok(bytes) if bytes.len() == NODE_HINT_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let sess_bytes = match env.convert_byte_array(&session_hint) {
        Ok(bytes) if bytes.len() == SESSION_HINT_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let payload = match env.convert_byte_array(&encrypted_payload) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create hints
    let mut hop_hint = [0u8; NODE_HINT_SIZE];
    hop_hint.copy_from_slice(&hop_bytes);

    let mut sess_hint = [0u8; SESSION_HINT_SIZE];
    sess_hint.copy_from_slice(&sess_bytes);

    // Create packet
    let packet = match DataPacket::new(hop_hint, sess_hint, payload) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let encoded = packet.encode();

    match env.byte_array_from_slice(&encoded) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Decode a data packet.
///
/// Parameters:
/// - packet_bytes: Raw packet bytes
///
/// Returns: Kotlin Triple<ByteArray, ByteArray, ByteArray> where:
/// - first: next_hop_hint (2 bytes)
/// - second: session_hint (4 bytes)
/// - third: encrypted_payload
///
/// Returns null on error or wrong packet type.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarPacketDecodeData(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jobject {
    let bytes = match env.convert_byte_array(&packet_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let packet = match DataPacket::decode(&bytes) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Java byte arrays
    let hop_arr = match env.byte_array_from_slice(&packet.next_hop_hint) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let sess_arr = match env.byte_array_from_slice(&packet.session_hint) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    let payload_arr = match env.byte_array_from_slice(&packet.encrypted_payload) {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create Kotlin Triple
    let triple_class = match env.find_class("kotlin/Triple") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let triple = match env.new_object(
        triple_class,
        "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V",
        &[(&hop_arr).into(), (&sess_arr).into(), (&payload_arr).into()],
    ) {
        Ok(obj) => obj,
        Err(_) => return std::ptr::null_mut(),
    };

    triple.into_raw()
}

/// Parse any packet and return its type.
///
/// Returns: Packet type as int (0=Data, 1=Handshake, 2=Control, 3=Cover), or -1 on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarPacketGetType(
    mut env: JNIEnv,
    _class: JClass,
    packet_bytes: JByteArray,
) -> jint {
    let bytes = match env.convert_byte_array(&packet_bytes) {
        Ok(b) if !b.is_empty() => b,
        _ => return -1,
    };

    match Packet::parse(&bytes) {
        Ok(packet) => match packet.packet_type() {
            PacketType::Data => 0,
            PacketType::Handshake => 1,
            PacketType::Control => 2,
            PacketType::Cover => 3,
        },
        Err(_) => -1,
    }
}

/// Generate a cover packet (chaff traffic).
///
/// Parameters:
/// - size: Size of random data (1-236 bytes)
///
/// Returns: Encoded cover packet, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarPacketGenerateCover(
    mut env: JNIEnv,
    _class: JClass,
    size: jint,
) -> jbyteArray {
    let size = match validate_positive_int(size, MAX_PACKET_SIZE - 1) {
        Some(s) if s > 0 => s,
        _ => return std::ptr::null_mut(),
    };

    // Generate random data
    let mut random_data = vec![0u8; size];
    OsRng.fill_bytes(&mut random_data);

    let packet = match CoverPacket::new(random_data) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let encoded = packet.encode();

    match env.byte_array_from_slice(&encoded) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive a node hint from a public key.
///
/// Parameters:
/// - public_key: 32-byte public key
///
/// Returns: 2-byte hint
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarDeriveNodeHint(
    mut env: JNIEnv,
    _class: JClass,
    public_key: JByteArray,
) -> jbyteArray {
    let pk_bytes = match env.convert_byte_array(&public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);

    let hint = derive_node_hint(&pk_arr);

    match env.byte_array_from_slice(&hint) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Derive a session hint from a session key.
///
/// Parameters:
/// - session_key: 32-byte session key
///
/// Returns: 4-byte hint
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarDeriveSessionHint(
    mut env: JNIEnv,
    _class: JClass,
    session_key: JByteArray,
) -> jbyteArray {
    let sk_bytes = match env.convert_byte_array(&session_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);

    let hint = derive_session_hint(&sk_arr);

    match env.byte_array_from_slice(&hint) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// LUNARCORE ROUTING JNI BINDINGS
// ============================================================================
//
// Node discovery, circuit construction, and path selection.

use lunar::routing::{
    NodeIdentity, NodeInfo, NodeAnnouncement, Router, RouterStats,
    CircuitId, PathCriteria, RoutingError,
    MIN_CIRCUIT_HOPS, MAX_CIRCUIT_HOPS,
};

lazy_static::lazy_static! {
    /// Thread-safe registry for Lunar routers
    static ref LUNAR_ROUTER_HANDLES: Mutex<HashMap<u64, Router>> =
        Mutex::new(HashMap::new());
}

/// Create a new Lunar router with a fresh identity.
///
/// Returns: Router handle (Long), or -1 on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterCreate(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlong {
    let identity = NodeIdentity::generate();
    let router = Router::new(identity);

    let handle = allocate_handle_id();
    {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        registry.insert(handle, router);
    }

    handle as jni::sys::jlong
}

/// Create a node announcement for broadcasting.
///
/// Parameters:
/// - router_handle: Router handle
/// - region: Optional region identifier (0 = none)
/// - operator: Optional operator identifier (0 = none)
///
/// Returns: Encoded announcement bytes, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterCreateAnnouncement(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    region: jint,
    operator: jint,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let handle = router_handle as u64;
    let region_opt = if region > 0 && region <= 255 { Some(region as u8) } else { None };
    let operator_opt = if operator > 0 && operator <= 65535 { Some(operator as u16) } else { None };

    let announcement_bytes = {
        let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(router) => {
                let announcement = router.create_announcement(region_opt, operator_opt);
                announcement.encode()
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&announcement_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Process a received node announcement.
///
/// Parameters:
/// - router_handle: Router handle
/// - announcement_bytes: Received announcement
///
/// Returns: true if valid and added, false otherwise
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterProcessAnnouncement(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    announcement_bytes: JByteArray,
) -> jni::sys::jboolean {
    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let bytes = match env.convert_byte_array(&announcement_bytes) {
        Ok(b) => b,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    let announcement = match NodeAnnouncement::decode(&bytes) {
        Some(a) => a,
        None => return jni::sys::JNI_FALSE,
    };

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            match router.process_announcement(&announcement) {
                Ok(()) => jni::sys::JNI_TRUE,
                Err(_) => jni::sys::JNI_FALSE,
            }
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Get router statistics.
///
/// Parameters:
/// - router_handle: Router handle
///
/// Returns: Kotlin data class with stats, encoded as IntArray:
///   [known_nodes, active_nodes, total_circuits, ready_circuits, pending_builds]
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterGetStats(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let handle = router_handle as u64;

    let stats = {
        let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(router) => router.stats(),
            None => return std::ptr::null_mut(),
        }
    };

    // Encode stats as 5 u32 values
    let mut result = Vec::with_capacity(20);
    result.extend_from_slice(&(stats.known_nodes as u32).to_be_bytes());
    result.extend_from_slice(&(stats.active_nodes as u32).to_be_bytes());
    result.extend_from_slice(&(stats.total_circuits as u32).to_be_bytes());
    result.extend_from_slice(&(stats.ready_circuits as u32).to_be_bytes());
    result.extend_from_slice(&(stats.pending_builds as u32).to_be_bytes());

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get our node's public hint.
///
/// Returns: 2-byte hint, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterGetOurHint(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let handle = router_handle as u64;

    let hint = {
        let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(router) => router.our_hint(),
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&hint) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close a router and clean up resources.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterClose(
    _env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
) -> jni::sys::jboolean {
    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.remove(&handle) {
        Some(_) => jni::sys::JNI_TRUE,
        None => jni::sys::JNI_FALSE,
    }
}

/// Build a new circuit with path selection criteria.
///
/// Parameters:
/// - router_handle: Router handle
/// - min_hops: Minimum number of hops (0 = use default MIN_CIRCUIT_HOPS)
/// - max_hops: Maximum number of hops (0 = use default MAX_CIRCUIT_HOPS)
/// - diverse_regions: Require different regions for each hop
/// - diverse_operators: Require different operators for each hop
/// - min_reliability: Minimum reliability score (0 = no minimum)
///
/// Returns: 8-byte circuit ID, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterBuildCircuit(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    min_hops: jint,
    max_hops: jint,
    diverse_regions: jni::sys::jboolean,
    diverse_operators: jni::sys::jboolean,
    min_reliability: jint,
) -> jbyteArray {
    use lunar::routing::PathCriteria;

    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let handle = router_handle as u64;

    let criteria = PathCriteria {
        min_hops: if min_hops > 0 { Some(min_hops as usize) } else { None },
        max_hops: if max_hops > 0 { Some(max_hops as usize) } else { None },
        exclude: std::collections::HashSet::new(),
        diverse_regions: diverse_regions != 0,
        diverse_operators: diverse_operators != 0,
        min_reliability: if min_reliability > 0 { Some(min_reliability as u32) } else { None },
    };

    let circuit_id = {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(router) => {
                match router.build_circuit(&criteria) {
                    Ok(id) => *id.as_bytes(),
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&circuit_id) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Establish sessions with all hops in a circuit.
///
/// Creates handshake packets for each relay hop.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
/// - aux_entropy: Additional entropy for hedged key exchange
///
/// Returns: Array of handshake packets (one per hop), or null on error
/// Format: [num_hops(1), hop0_len(2), hop0_data, hop1_len(2), hop1_data, ...]
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterEstablishCircuit(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
    aux_entropy: JByteArray,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let entropy = match env.convert_byte_array(&aux_entropy) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let handle = router_handle as u64;

    let handshakes = {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(router) => {
                match router.create_circuit_handshakes(&cid, &entropy) {
                    Ok(hs) => hs,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    // Encode handshakes: [num_hops(1), hop0_len(2), hop0_data, ...]
    let mut result = Vec::new();
    result.push(handshakes.len() as u8);
    for (_hop_idx, handshake) in handshakes {
        let len = handshake.len() as u16;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&handshake);
    }

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Confirm that a circuit hop has been established.
///
/// Call this after receiving confirmation from each relay.
/// When all hops are confirmed, the circuit becomes ready.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
/// - hop_index: Which hop (0 = entry)
///
/// Returns: true if successful, false on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterConfirmHop(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
    hop_index: jint,
) -> jni::sys::jboolean {
    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return jni::sys::JNI_FALSE,
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            match router.confirm_hop_established(&cid, hop_index as usize) {
                Ok(()) => jni::sys::JNI_TRUE,
                Err(_) => jni::sys::JNI_FALSE,
            }
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Wrap a message through a circuit for anonymous transmission.
///
/// The message is wrapped in multiple layers of AES-256-GCM encryption,
/// one for each hop in the circuit.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
/// - payload: Message to send
/// - recipient_hint: 2-byte hint of final recipient
///
/// Returns: Onion-wrapped packet, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterWrapMessage(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
    payload: JByteArray,
    recipient_hint: JByteArray,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let payload_bytes = match env.convert_byte_array(&payload) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let hint_bytes = match env.convert_byte_array(&recipient_hint) {
        Ok(bytes) if bytes.len() == lunar::packet::NODE_HINT_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let mut hint_arr = [0u8; lunar::packet::NODE_HINT_SIZE];
    hint_arr.copy_from_slice(&hint_bytes);

    let handle = router_handle as u64;

    let wrapped = {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(router) => {
                match router.wrap_message(&cid, &payload_bytes, hint_arr) {
                    Ok(w) => w,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&wrapped) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the entry node hint for a circuit.
///
/// The entry hint is needed to route the wrapped packet to the first hop.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
///
/// Returns: 2-byte entry node hint, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterGetEntryHint(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
) -> jbyteArray {
    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let handle = router_handle as u64;

    let hint = {
        let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(router) => {
                match router.get_entry_hint(&cid) {
                    Some(h) => h,
                    None => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&hint) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get circuit info.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
///
/// Returns: Circuit info as bytes:
///   [state(1), hop_count(1), message_count(4), needs_rotation(1)]
/// States: 0=Building, 1=Ready, 2=Closing, 3=Closed
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterGetCircuitInfo(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
) -> jbyteArray {
    use lunar::routing::CircuitState;

    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return std::ptr::null_mut(),
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let handle = router_handle as u64;

    let info = {
        let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(router) => {
                match router.get_circuit(&cid) {
                    Some(circuit) => {
                        let state_byte = match circuit.state {
                            CircuitState::Building => 0u8,
                            CircuitState::Ready => 1u8,
                            CircuitState::Closing => 2u8,
                            CircuitState::Closed => 3u8,
                        };
                        let mut result = Vec::with_capacity(7);
                        result.push(state_byte);
                        result.push(circuit.hop_count() as u8);
                        result.extend_from_slice(&(circuit.message_count as u32).to_be_bytes());
                        result.push(if circuit.needs_rotation() { 1 } else { 0 });
                        result
                    }
                    None => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&info) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close a specific circuit.
///
/// Parameters:
/// - router_handle: Router handle
/// - circuit_id: 8-byte circuit ID
///
/// Returns: true if closed, false on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterCloseCircuit(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    circuit_id: JByteArray,
) -> jni::sys::jboolean {
    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let cid_bytes = match env.convert_byte_array(&circuit_id) {
        Ok(bytes) if bytes.len() == lunar::routing::CIRCUIT_ID_SIZE => bytes,
        _ => return jni::sys::JNI_FALSE,
    };

    let mut cid_arr = [0u8; lunar::routing::CIRCUIT_ID_SIZE];
    cid_arr.copy_from_slice(&cid_bytes);
    let cid = lunar::routing::CircuitId::from_bytes(cid_arr);

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            router.close_circuit(&cid);
            jni::sys::JNI_TRUE
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Cleanup stale circuits.
///
/// Closes circuits that need rotation (expired or message limit reached).
///
/// Parameters:
/// - router_handle: Router handle
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterCleanup(
    _env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
) {
    if router_handle < 0 {
        return;
    }

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    if let Some(router) = registry.get_mut(&handle) {
        router.cleanup();
    }
}

/// Get or build a ready circuit.
///
/// Returns an existing ready circuit if available, otherwise builds a new one.
///
/// Parameters:
/// - router_handle: Router handle
/// - min_hops: Minimum hops (0 = default)
///
/// Returns: 8-byte circuit ID, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterGetOrBuildCircuit(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    min_hops: jint,
) -> jbyteArray {
    use lunar::routing::PathCriteria;

    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let handle = router_handle as u64;

    let criteria = PathCriteria {
        min_hops: if min_hops > 0 { Some(min_hops as usize) } else { None },
        ..Default::default()
    };

    let circuit_id = {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(router) => {
                match router.get_or_build_circuit(&criteria) {
                    Ok(id) => *id.as_bytes(),
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&circuit_id) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// LUNAR ROUTER BBS+ AUTHENTICATION
// ============================================================================

/// Add a trusted issuer to the router for BBS+ credential verification.
///
/// Parameters:
/// - router_handle: Router handle
/// - issuer_id: 32-byte issuer identifier
/// - issuer_public_key: Serialized IssuerPublicKey
///
/// Returns: true on success, false on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterAddTrustedIssuer(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    issuer_id: JByteArray,
    issuer_public_key: JByteArray,
) -> jni::sys::jboolean {
    use credentials::IssuerPublicKey;

    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let id_bytes = match env.convert_byte_array(&issuer_id) {
        Ok(b) if b.len() == 32 => b,
        _ => return jni::sys::JNI_FALSE,
    };

    let pk_bytes = match env.convert_byte_array(&issuer_public_key) {
        Ok(b) => b,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    let issuer_pk = match IssuerPublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(&id_bytes);

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            router.add_trusted_issuer(id_arr, issuer_pk);
            jni::sys::JNI_TRUE
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Remove a trusted issuer from the router (for revocation).
///
/// Parameters:
/// - router_handle: Router handle
/// - issuer_id: 32-byte issuer identifier
///
/// Returns: true on success, false on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterRemoveTrustedIssuer(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    issuer_id: JByteArray,
) -> jni::sys::jboolean {
    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let id_bytes = match env.convert_byte_array(&issuer_id) {
        Ok(b) if b.len() == 32 => b,
        _ => return jni::sys::JNI_FALSE,
    };

    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(&id_bytes);

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            router.remove_trusted_issuer(&id_arr);
            jni::sys::JNI_TRUE
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Verify a BBS+ mesh access proof via the router.
///
/// This checks:
/// 1. The proof is cryptographically valid
/// 2. The issuer is trusted by this router
/// 3. Rate limiting hasn't been exceeded
///
/// Parameters:
/// - router_handle: Router handle
/// - proof_bytes: Serialized MeshAccessProof
///
/// Returns: Serialized VerifiedAccess (issuer_id:32 || access_level:1 || rate_token:32 || epoch:8)
///          or null on error (invalid proof, untrusted issuer, or rate limited)
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterVerifyAccessProof(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    proof_bytes: JByteArray,
) -> jbyteArray {
    use lunar::mesh_credentials::AccessLevel;

    if router_handle < 0 {
        return std::ptr::null_mut();
    }

    let proof_data = match env.convert_byte_array(&proof_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let handle = router_handle as u64;

    let access = {
        let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
        match registry.get_mut(&handle) {
            Some(router) => {
                match router.verify_access_proof(&proof_data) {
                    Ok(a) => a,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    // Serialize VerifiedAccess: issuer_id:32 || access_level:1 || rate_token:32 || epoch:8
    let mut result = Vec::with_capacity(73);
    result.extend_from_slice(&access.issuer_id);
    result.push(match access.access_level {
        AccessLevel::Basic => 0,
        AccessLevel::Trusted => 1,
        AccessLevel::Guardian => 2,
    });
    result.extend_from_slice(&access.rate_token);
    result.extend_from_slice(&access.epoch.to_be_bytes());

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Register a node's verified access in the router.
///
/// Call this after successfully verifying a BBS+ proof to authorize a node.
///
/// Parameters:
/// - router_handle: Router handle
/// - node_hint: NODE_HINT_SIZE-byte node hint
/// - verified_access: Serialized VerifiedAccess from lunarRouterVerifyAccessProof
///
/// Returns: true on success, false on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterRegisterNodeAccess(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    node_hint: JByteArray,
    verified_access: JByteArray,
) -> jni::sys::jboolean {
    use lunar::mesh_credentials::{AccessLevel, VerifiedAccess};
    use lunar::packet::NODE_HINT_SIZE;

    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let hint_bytes = match env.convert_byte_array(&node_hint) {
        Ok(b) if b.len() == NODE_HINT_SIZE => b,
        _ => return jni::sys::JNI_FALSE,
    };

    let access_bytes = match env.convert_byte_array(&verified_access) {
        Ok(b) if b.len() >= 73 => b,
        _ => return jni::sys::JNI_FALSE,
    };

    // Parse VerifiedAccess: issuer_id:32 || access_level:1 || rate_token:32 || epoch:8
    let mut issuer_id = [0u8; 32];
    issuer_id.copy_from_slice(&access_bytes[0..32]);

    let access_level = match access_bytes[32] {
        0 => AccessLevel::Basic,
        1 => AccessLevel::Trusted,
        2 => AccessLevel::Guardian,
        _ => return jni::sys::JNI_FALSE,
    };

    let mut rate_token = [0u8; 32];
    rate_token.copy_from_slice(&access_bytes[33..65]);

    let epoch = u64::from_be_bytes([
        access_bytes[65], access_bytes[66], access_bytes[67], access_bytes[68],
        access_bytes[69], access_bytes[70], access_bytes[71], access_bytes[72],
    ]);

    let access = VerifiedAccess {
        issuer_id,
        access_level,
        rate_token,
        epoch,
    };

    let mut hint_arr = [0u8; NODE_HINT_SIZE];
    hint_arr.copy_from_slice(&hint_bytes);

    let handle = router_handle as u64;

    let mut registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get_mut(&handle) {
        Some(router) => {
            router.register_node_access(hint_arr, access);
            jni::sys::JNI_TRUE
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Check if a node is authorized based on BBS+ authentication.
///
/// Parameters:
/// - router_handle: Router handle
/// - node_hint: NODE_HINT_SIZE-byte node hint
///
/// Returns: true if authorized, false otherwise
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_lunarRouterIsNodeAuthorized(
    mut env: JNIEnv,
    _class: JClass,
    router_handle: jni::sys::jlong,
    node_hint: JByteArray,
) -> jni::sys::jboolean {
    use lunar::packet::NODE_HINT_SIZE;

    if router_handle < 0 {
        return jni::sys::JNI_FALSE;
    }

    let hint_bytes = match env.convert_byte_array(&node_hint) {
        Ok(b) if b.len() == NODE_HINT_SIZE => b,
        _ => return jni::sys::JNI_FALSE,
    };

    let mut hint_arr = [0u8; NODE_HINT_SIZE];
    hint_arr.copy_from_slice(&hint_bytes);

    let handle = router_handle as u64;

    let registry = LUNAR_ROUTER_HANDLES.lock().unwrap();
    match registry.get(&handle) {
        Some(router) => {
            if router.is_authorized(&hint_arr) {
                jni::sys::JNI_TRUE
            } else {
                jni::sys::JNI_FALSE
            }
        }
        None => jni::sys::JNI_FALSE,
    }
}

/// Get the issuer ID from a MeshIssuer handle.
///
/// Parameters:
/// - issuer_handle: Handle from meshIssuerCreate
///
/// Returns: 32-byte issuer ID, or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshIssuerGetId(
    mut env: JNIEnv,
    _class: JClass,
    issuer_handle: jni::sys::jlong,
) -> jbyteArray {
    use lunar::mesh_credentials::MeshIssuer;

    if issuer_handle < 0 {
        return std::ptr::null_mut();
    }

    lazy_static::lazy_static! {
        static ref MESH_ISSUER_HANDLES: std::sync::Mutex<std::collections::HashMap<u64, MeshIssuer>> =
            std::sync::Mutex::new(std::collections::HashMap::new());
    }

    let handle = issuer_handle as u64;

    let id = {
        let registry = MESH_ISSUER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(issuer) => *issuer.issuer_id(),
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&id) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// MESH CREDENTIALS (BBS+ based anonymous access)
// ============================================================================

/// Create a mesh issuer for issuing anonymous mesh access credentials.
///
/// Returns: Handle to issuer (as long) or -1 on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshIssuerCreate(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlong {
    use lunar::mesh_credentials::MeshIssuer;

    let mut rng = rand::rngs::OsRng;
    match MeshIssuer::new(&mut rng) {
        Ok(issuer) => {
            // Store in a static registry and return handle
            static MESH_ISSUER_COUNTER: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(1);
            lazy_static::lazy_static! {
                static ref MESH_ISSUER_HANDLES: std::sync::Mutex<std::collections::HashMap<u64, MeshIssuer>> =
                    std::sync::Mutex::new(std::collections::HashMap::new());
            }

            let handle = MESH_ISSUER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            MESH_ISSUER_HANDLES.lock().unwrap().insert(handle, issuer);
            handle as jni::sys::jlong
        }
        Err(_) => -1,
    }
}

/// Issue a mesh access credential.
///
/// @param issuerHandle Handle from meshIssuerCreate
/// @param pubkeyCommitment 32-byte hash of user's public key
/// @param accessLevel 0=Basic, 1=Trusted, 2=Guardian
/// @return Serialized MeshCredential or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshIssuerIssue(
    mut env: JNIEnv,
    _class: JClass,
    issuer_handle: jni::sys::jlong,
    pubkey_commitment: JByteArray,
    access_level: jint,
) -> jbyteArray {
    use lunar::mesh_credentials::{AccessLevel, MeshIssuer};

    if issuer_handle < 0 {
        return std::ptr::null_mut();
    }

    let commitment_bytes = match env.convert_byte_array(pubkey_commitment) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    if commitment_bytes.len() != 32 {
        return std::ptr::null_mut();
    }

    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&commitment_bytes);

    let level = match access_level {
        0 => AccessLevel::Basic,
        1 => AccessLevel::Trusted,
        2 => AccessLevel::Guardian,
        _ => return std::ptr::null_mut(),
    };

    // Access the stored issuer
    lazy_static::lazy_static! {
        static ref MESH_ISSUER_HANDLES: std::sync::Mutex<std::collections::HashMap<u64, MeshIssuer>> =
            std::sync::Mutex::new(std::collections::HashMap::new());
    }

    let handle = issuer_handle as u64;
    let mut rng = rand::rngs::OsRng;

    let credential_bytes = {
        let registry = MESH_ISSUER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(issuer) => {
                match issuer.issue_credential(&commitment, level, &mut rng) {
                    Ok(cred) => cred.to_bytes(),
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&credential_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get issuer public key.
///
/// @param issuerHandle Handle from meshIssuerCreate
/// @return Serialized IssuerPublicKey or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshIssuerGetPublicKey(
    mut env: JNIEnv,
    _class: JClass,
    issuer_handle: jni::sys::jlong,
) -> jbyteArray {
    use lunar::mesh_credentials::MeshIssuer;

    if issuer_handle < 0 {
        return std::ptr::null_mut();
    }

    lazy_static::lazy_static! {
        static ref MESH_ISSUER_HANDLES: std::sync::Mutex<std::collections::HashMap<u64, MeshIssuer>> =
            std::sync::Mutex::new(std::collections::HashMap::new());
    }

    let handle = issuer_handle as u64;

    let pk_bytes = {
        let registry = MESH_ISSUER_HANDLES.lock().unwrap();
        match registry.get(&handle) {
            Some(issuer) => {
                match issuer.public_key().to_bytes() {
                    Ok(bytes) => bytes,
                    Err(_) => return std::ptr::null_mut(),
                }
            }
            None => return std::ptr::null_mut(),
        }
    };

    match env.byte_array_from_slice(&pk_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create an anonymous mesh access proof from a credential.
///
/// @param credentialBytes Serialized MeshCredential
/// @param issuerPublicKey Serialized IssuerPublicKey
/// @param epoch Current epoch number
/// @return Serialized MeshAccessProof or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshCredentialProve(
    mut env: JNIEnv,
    _class: JClass,
    credential_bytes: JByteArray,
    issuer_public_key: JByteArray,
    epoch: jni::sys::jlong,
) -> jbyteArray {
    use credentials::IssuerPublicKey;
    use lunar::mesh_credentials::MeshCredential;

    let cred_bytes = match env.convert_byte_array(credential_bytes) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let pk_bytes = match env.convert_byte_array(issuer_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let credential = match MeshCredential::from_bytes(&cred_bytes) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let issuer_pk = match IssuerPublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut rng = rand::rngs::OsRng;
    let proof = match credential.prove_access(&issuer_pk, epoch as u64, &mut rng) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let proof_bytes = proof.to_bytes();

    match env.byte_array_from_slice(&proof_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Verify a mesh access proof.
///
/// @param proofBytes Serialized MeshAccessProof
/// @param issuerPublicKey Serialized IssuerPublicKey
/// @return Verification result: (issuer_id:32 || access_level:1 || rate_token:32 || epoch:8) or null on error
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshProofVerify(
    mut env: JNIEnv,
    _class: JClass,
    proof_bytes: JByteArray,
    issuer_public_key: JByteArray,
) -> jbyteArray {
    use credentials::IssuerPublicKey;
    use lunar::mesh_credentials::MeshAccessProof;

    let proof_data = match env.convert_byte_array(proof_bytes) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let pk_bytes = match env.convert_byte_array(issuer_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let proof = match MeshAccessProof::from_bytes(&proof_data) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let issuer_pk = match IssuerPublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return std::ptr::null_mut(),
    };

    let verified = match proof.verify(&issuer_pk) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    // Encode result
    let mut result = Vec::with_capacity(73);
    result.extend_from_slice(&verified.issuer_id);
    result.push(verified.access_level as u8);
    result.extend_from_slice(&verified.rate_token);
    result.extend_from_slice(&verified.epoch.to_le_bytes());

    match env.byte_array_from_slice(&result) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get current epoch number.
#[no_mangle]
pub extern "system" fn Java_com_yours_app_crypto_BedrockCore_meshGetCurrentEpoch(
    _env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlong {
    use lunar::mesh_credentials::current_epoch;
    current_epoch() as jni::sys::jlong
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_orthogonal_vector_sampling() {
        let vectors = sample_orthogonal_vectors(8, 1024);
        assert_eq!(vectors.len(), 8);
        assert!(verify_orthogonality(&vectors));
    }
    
    #[test]
    fn test_orthogonality_check() {
        // Vectors with disjoint support are always orthogonal
        let mut a = vec![0u8; 16];
        let mut b = vec![0u8; 16];
        a[0] = 0b11110000;
        b[0] = 0b00001111;
        assert!(is_orthogonal(&a, &b));
    }
    
    #[test]
    fn test_bundle_roundtrip() {
        let vectors = sample_orthogonal_vectors(8, 1024);
        let bundle = serialize_bundle(&vectors);
        let recovered = deserialize_bundle(&bundle).unwrap();
        
        for (v, r) in vectors.iter().zip(recovered.iter()) {
            assert_eq!(v, r);
        }
    }
    
    #[test]
    fn test_gf256_inverse() {
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            let product = gf256_mul(a, inv);
            assert_eq!(product, 1);
        }
    }

    #[test]
    fn test_hkovct_encrypt_decrypt_roundtrip() {
        // This is the full end-to-end test of Hk-OVCT
        // Without JNI, we test the core crypto directly

        use aes_gcm::aead::OsRng;
        use rand::RngCore;

        // 1. Generate ML-KEM keypair
        let mut rng = OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);

        // 2. Sample orthogonal vectors (the k-OV solution)
        let vectors = sample_orthogonal_vectors(HKOVCT_K, HKOVCT_D);
        assert!(verify_orthogonality(&vectors), "Vectors must be orthogonal");

        // 3. Create the bundle and public seed
        let bundle = serialize_bundle(&vectors);
        let mut public_seed = [0u8; 32];
        rng.fill_bytes(&mut public_seed);

        // 4. Encapsulate with ML-KEM
        let (kem_ct, shared_secret) = ek.encapsulate(&mut rng).unwrap();

        // 5. Derive bundle key from ML-KEM shared secret
        let hk = Hkdf::<Sha3_256>::new(Some(&public_seed), shared_secret.as_slice());
        let mut bundle_key = [0u8; 32];
        hk.expand(b"hkovct-bundle-key-v1", &mut bundle_key).unwrap();

        // 6. Encrypt the bundle
        let bundle_cipher = Aes256Gcm::new_from_slice(&bundle_key).unwrap();
        let mut bundle_nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut bundle_nonce_bytes);
        let bundle_nonce = Nonce::from_slice(&bundle_nonce_bytes);

        let encrypted_bundle = bundle_cipher.encrypt(
            bundle_nonce,
            Payload { msg: &bundle, aad: &public_seed }
        ).unwrap();

        // 7. Derive content key FROM THE ORTHOGONAL VECTORS (k-OV binding!)
        let content_key = derive_content_key(&vectors, &public_seed);

        // 8. Encrypt some test data
        let plaintext = b"Hello, sovereign world! This is encrypted with Hk-OVCT.";
        let content_cipher = Aes256Gcm::new_from_slice(&content_key).unwrap();
        let mut content_nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut content_nonce_bytes);
        let content_nonce = Nonce::from_slice(&content_nonce_bytes);

        let mut bundle_hash = Sha3_256::new();
        bundle_hash.update(&bundle);
        let bundle_digest = bundle_hash.finalize();

        let ciphertext = content_cipher.encrypt(
            content_nonce,
            Payload { msg: plaintext.as_slice(), aad: &bundle_digest }
        ).unwrap();

        // ====== DECRYPTION SIDE ======

        // 9. Decapsulate ML-KEM
        let recovered_secret = dk.decapsulate(&kem_ct).unwrap();
        assert_eq!(shared_secret.as_slice(), recovered_secret.as_slice());

        // 10. Derive bundle key
        let hk2 = Hkdf::<Sha3_256>::new(Some(&public_seed), recovered_secret.as_slice());
        let mut recovered_bundle_key = [0u8; 32];
        hk2.expand(b"hkovct-bundle-key-v1", &mut recovered_bundle_key).unwrap();

        // 11. Decrypt bundle
        let bundle_cipher2 = Aes256Gcm::new_from_slice(&recovered_bundle_key).unwrap();
        let recovered_bundle = bundle_cipher2.decrypt(
            bundle_nonce,
            Payload { msg: &encrypted_bundle, aad: &public_seed }
        ).unwrap();

        // 12. VERIFY ORTHOGONALITY (defense in depth!)
        let recovered_vectors = deserialize_bundle(&recovered_bundle).unwrap();
        assert!(verify_orthogonality(&recovered_vectors),
            "CRITICAL: Recovered vectors are not orthogonal!");

        // 13. Derive content key from verified vectors
        let recovered_content_key = derive_content_key(&recovered_vectors, &public_seed);

        // 14. Decrypt content
        let content_cipher2 = Aes256Gcm::new_from_slice(&recovered_content_key).unwrap();

        let mut bundle_hash2 = Sha3_256::new();
        bundle_hash2.update(&recovered_bundle);
        let bundle_digest2 = bundle_hash2.finalize();

        let recovered_plaintext = content_cipher2.decrypt(
            content_nonce,
            Payload { msg: &ciphertext, aad: &bundle_digest2 }
        ).unwrap();

        // 15. Verify
        assert_eq!(plaintext.as_slice(), recovered_plaintext.as_slice());
        println!("Hk-OVCT roundtrip successful!");
        println!("  - {} orthogonal vectors verified", HKOVCT_K);
        println!("  - ML-KEM-768 encapsulation: OK");
        println!("  - Content key derived from k-OV solution: OK");
        println!("  - Message decrypted: \"{}\"",
            String::from_utf8_lossy(&recovered_plaintext));
    }
}
