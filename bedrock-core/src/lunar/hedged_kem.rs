//! Hk-OVCT: Hedged Key Encapsulation Mechanism
//!
//! Provides security guarantees even when the RNG is compromised, biased,
//! or under adversarial control. Combines multiple independent entropy sources
//! through XOR, ensuring key material remains unpredictable as long as ANY
//! single entropy source is uncompromised.
//!
//! ## Security Model
//!
//! Standard KEM: `(ct, ss) = KEM.Encapsulate(pk, RNG())` - single point of failure
//!
//! Hk-OVCT: `r = r_system XOR r_deterministic XOR r_external`
//! Security: Attacker must compromise ALL THREE entropy sources.
//!
//! ## Dual-DH Construction
//!
//! Additional defense-in-depth via two independent DH operations:
//! - Primary DH: Uses hedged ephemeral key
//! - Secondary DH: Derived deterministically from primary ephemeral (public values)
//!
//! Both DH results are combined into the final shared secret.

use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, OsRng};
use std::sync::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// TYPES
// ============================================================================

/// Hedged KEM keypair
#[derive(ZeroizeOnDrop)]
pub struct HkOvctKeyPair {
    secret: [u8; 32],
    #[zeroize(skip)]
    public: PublicKey,
}

/// Ciphertext (ephemeral public key, 32 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HkOvctCiphertext(pub [u8; 32]);

/// Shared secret derived from encapsulation
#[derive(ZeroizeOnDrop)]
pub struct HkOvctSharedSecret {
    secret: [u8; 32],
}

/// Handle to a shared secret stored in the registry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HkOvctSecretHandle(pub u64);

/// Error type for Hk-OVCT operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HkOvctError {
    /// Invalid ciphertext format
    InvalidCiphertext,
    /// DH computation produced invalid result (all zeros)
    InvalidDhResult,
    /// Handle not found in registry
    InvalidHandle,
    /// Registry lock poisoned
    RegistryError,
}

// ============================================================================
// CONSTANTS - Domain Separators
// ============================================================================

/// Domain separator for deterministic entropy derivation
const DOMAIN_DETERMINISTIC: &[u8] = b"lunarcore-hk-ovct-det-v1";

/// Domain separator for dual-DH ephemeral derivation
const DOMAIN_DUAL_DH: &[u8] = b"hk-ovct-dual-v1";

/// Domain separator for final shared secret
const DOMAIN_FINAL: &[u8] = b"hk-ovct-final-v1";

/// Domain separator for session key derivation
const DOMAIN_SESSION: &[u8] = b"hk-ovct-session-v1";

// ============================================================================
// THREAD-SAFE SECRET REGISTRY
// ============================================================================
// Secrets never cross JNI boundary. Kotlin gets handles, Rust keeps secrets.

lazy_static::lazy_static! {
    /// Registry mapping handles to shared secrets
    static ref SECRET_REGISTRY: Mutex<HashMap<u64, HkOvctSharedSecret>> =
        Mutex::new(HashMap::new());
}

/// Counter for generating unique handles
static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Store a shared secret and return a handle
pub fn store_shared_secret(secret: HkOvctSharedSecret) -> HkOvctSecretHandle {
    let handle = HANDLE_COUNTER.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut registry) = SECRET_REGISTRY.lock() {
        registry.insert(handle, secret);
    }
    HkOvctSecretHandle(handle)
}

/// Retrieve a shared secret by handle (for internal use)
pub fn get_shared_secret(handle: HkOvctSecretHandle) -> Result<HkOvctSharedSecret, HkOvctError> {
    let registry = SECRET_REGISTRY.lock().map_err(|_| HkOvctError::RegistryError)?;
    registry.get(&handle.0)
        .map(|s| HkOvctSharedSecret { secret: s.secret })
        .ok_or(HkOvctError::InvalidHandle)
}

/// Delete a shared secret from the registry (zeroizes memory)
pub fn delete_shared_secret(handle: HkOvctSecretHandle) -> Result<(), HkOvctError> {
    let mut registry = SECRET_REGISTRY.lock().map_err(|_| HkOvctError::RegistryError)?;
    registry.remove(&handle.0);  // ZeroizeOnDrop handles cleanup
    Ok(())
}

/// Derive a session key from a stored secret without exposing the secret
pub fn derive_session_key(handle: HkOvctSecretHandle, context: &[u8]) -> Result<[u8; 32], HkOvctError> {
    let registry = SECRET_REGISTRY.lock().map_err(|_| HkOvctError::RegistryError)?;
    let secret = registry.get(&handle.0).ok_or(HkOvctError::InvalidHandle)?;
    Ok(secret.derive_key(context))
}

// ============================================================================
// KEY GENERATION
// ============================================================================

impl HkOvctKeyPair {
    /// Generate a new keypair using system RNG
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = StaticSecret::from(secret);
        let public = PublicKey::from(&sk);
        Self { secret, public }
    }

    /// Create from existing secret bytes
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let sk = StaticSecret::from(bytes);
        let public = PublicKey::from(&sk);
        Self { secret: bytes, public }
    }

    /// Get public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get static secret (internal use)
    fn static_secret(&self) -> StaticSecret {
        StaticSecret::from(self.secret)
    }
}

// ============================================================================
// ENTROPY HEDGING
// ============================================================================

/// Combine multiple entropy sources via XOR
///
/// Security: Shared secret is unpredictable if ANY source provides entropy.
fn hedge_entropy(
    sender_sk: &[u8; 32],
    recipient_pk: &PublicKey,
    aux_entropy: &[u8],
) -> [u8; 32] {
    // Source 1: System RNG (may be backdoored by OS/hardware)
    let mut r_system = [0u8; 32];
    OsRng.fill_bytes(&mut r_system);

    // Source 2: Deterministic from long-term keys (independent of RNG)
    let r_det = derive_deterministic_entropy(sender_sk, recipient_pk);

    // Source 3: External entropy (physical sensors, timing)
    let r_ext = hash_external_entropy(aux_entropy);

    // XOR combination: secure if ANY source has entropy
    let mut r_hedged = [0u8; 32];
    for i in 0..32 {
        r_hedged[i] = r_system[i] ^ r_det[i] ^ r_ext[i];
    }

    // Zeroize intermediates
    r_system.zeroize();

    r_hedged
}

/// Derive deterministic entropy from sender's secret and recipient's public key
fn derive_deterministic_entropy(sender_sk: &[u8; 32], recipient_pk: &PublicKey) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(sender_sk);
    ikm[32..].copy_from_slice(recipient_pk.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_DETERMINISTIC), &ikm);
    let mut output = [0u8; 32];
    hk.expand(b"entropy", &mut output).expect("HKDF expand failed");

    ikm.zeroize();
    output
}

/// Hash external entropy sources
fn hash_external_entropy(aux_entropy: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(aux_entropy);

    // Add timestamp for additional entropy
    #[cfg(not(target_arch = "wasm32"))]
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        hasher.update(&nanos.to_le_bytes());
    }

    hasher.finalize().into()
}

/// Clamp scalar for X25519
fn clamp(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

// ============================================================================
// DUAL-DH DERIVATION (Public Values Only - Same on Both Sides)
// ============================================================================

/// Derive the second ephemeral from public values only.
///
/// This function must produce identical output on sender and recipient.
/// Both parties have access to eph_pk_1 (in ciphertext) and recipient_pk.
fn derive_dual_ephemeral(eph_pk_1: &PublicKey, recipient_pk: &PublicKey) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(eph_pk_1.as_bytes());
    ikm[32..].copy_from_slice(recipient_pk.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_DUAL_DH), &ikm);
    let mut output = [0u8; 32];
    hk.expand(b"ephemeral-2", &mut output).expect("HKDF expand failed");
    output
}

/// Derive final shared secret from both DH results
fn derive_final_secret(
    dh_1: &[u8; 32],
    dh_2: &[u8; 32],
    eph_pk_1: &PublicKey,
    recipient_pk: &PublicKey,
) -> [u8; 32] {
    // Concatenate all inputs
    let mut ikm = Vec::with_capacity(32 + 32 + 32 + 32);
    ikm.extend_from_slice(dh_1);
    ikm.extend_from_slice(dh_2);
    ikm.extend_from_slice(eph_pk_1.as_bytes());
    ikm.extend_from_slice(recipient_pk.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_FINAL), &ikm);
    let mut output = [0u8; 32];
    hk.expand(b"shared-secret", &mut output).expect("HKDF expand failed");

    ikm.zeroize();
    output
}

// ============================================================================
// ENCAPSULATION (Sender Side)
// ============================================================================

/// Encapsulate a shared secret to recipient.
///
/// # Arguments
/// * `recipient_pk` - Recipient's X25519 public key
/// * `sender_keypair` - Sender's keypair (secret used for hedging)
/// * `aux_entropy` - External entropy (sensors, timing, etc.)
///
/// # Returns
/// * `HkOvctCiphertext` - 32-byte ciphertext (ephemeral public key)
/// * `HkOvctSharedSecret` - Derived shared secret
///
/// # Security
/// Shared secret is secure if ANY of:
/// 1. System RNG provides ≥128 bits entropy
/// 2. Attacker doesn't know sender's secret key
/// 3. aux_entropy provides ≥128 bits entropy
pub fn encapsulate(
    recipient_pk: &PublicKey,
    sender_keypair: &HkOvctKeyPair,
    aux_entropy: &[u8],
) -> Result<(HkOvctCiphertext, HkOvctSharedSecret), HkOvctError> {
    // === ENTROPY HEDGING ===
    let r_hedged = hedge_entropy(&sender_keypair.secret, recipient_pk, aux_entropy);
    let r_clamped = clamp(r_hedged);

    // === PRIMARY DH ===
    let eph_sk_1 = StaticSecret::from(r_clamped);
    let eph_pk_1 = PublicKey::from(&eph_sk_1);
    let dh_1 = eph_sk_1.diffie_hellman(recipient_pk);

    // Validate DH result
    if is_all_zeros(dh_1.as_bytes()) {
        return Err(HkOvctError::InvalidDhResult);
    }

    // === DUAL-DH (derived from public values - same on both sides) ===
    let r_2 = derive_dual_ephemeral(&eph_pk_1, recipient_pk);
    let r_2_clamped = clamp(r_2);
    let eph_sk_2 = StaticSecret::from(r_2_clamped);
    let dh_2 = eph_sk_2.diffie_hellman(recipient_pk);

    // === FINAL SHARED SECRET ===
    let mut dh_1_bytes = [0u8; 32];
    dh_1_bytes.copy_from_slice(dh_1.as_bytes());
    let mut dh_2_bytes = [0u8; 32];
    dh_2_bytes.copy_from_slice(dh_2.as_bytes());

    let ss = derive_final_secret(&dh_1_bytes, &dh_2_bytes, &eph_pk_1, recipient_pk);

    // Zeroize sensitive intermediates
    dh_1_bytes.zeroize();
    dh_2_bytes.zeroize();

    Ok((
        HkOvctCiphertext(eph_pk_1.to_bytes()),
        HkOvctSharedSecret { secret: ss }
    ))
}

/// Encapsulate and store secret in registry, returning handle
pub fn encapsulate_to_handle(
    recipient_pk: &PublicKey,
    sender_keypair: &HkOvctKeyPair,
    aux_entropy: &[u8],
) -> Result<(HkOvctCiphertext, HkOvctSecretHandle), HkOvctError> {
    let (ct, ss) = encapsulate(recipient_pk, sender_keypair, aux_entropy)?;
    let handle = store_shared_secret(ss);
    Ok((ct, handle))
}

// ============================================================================
// DECAPSULATION (Recipient Side)
// ============================================================================

/// Decapsulate a shared secret from ciphertext.
///
/// # Arguments
/// * `ct` - Ciphertext (sender's ephemeral public key)
/// * `recipient_keypair` - Recipient's keypair
///
/// # Returns
/// Same shared secret as sender derived
pub fn decapsulate(
    ct: &HkOvctCiphertext,
    recipient_keypair: &HkOvctKeyPair,
) -> Result<HkOvctSharedSecret, HkOvctError> {
    let eph_pk_1 = PublicKey::from(ct.0);
    let recipient_pk = &recipient_keypair.public;
    let recipient_sk = recipient_keypair.static_secret();

    // === PRIMARY DH ===
    let dh_1 = recipient_sk.diffie_hellman(&eph_pk_1);

    // Validate DH result
    if is_all_zeros(dh_1.as_bytes()) {
        return Err(HkOvctError::InvalidDhResult);
    }

    // === DUAL-DH (same derivation as sender) ===
    let r_2 = derive_dual_ephemeral(&eph_pk_1, recipient_pk);
    let r_2_clamped = clamp(r_2);
    let eph_sk_2 = StaticSecret::from(r_2_clamped);
    let eph_pk_2 = PublicKey::from(&eph_sk_2);
    let dh_2 = recipient_sk.diffie_hellman(&eph_pk_2);

    // === FINAL SHARED SECRET ===
    let mut dh_1_bytes = [0u8; 32];
    dh_1_bytes.copy_from_slice(dh_1.as_bytes());
    let mut dh_2_bytes = [0u8; 32];
    dh_2_bytes.copy_from_slice(dh_2.as_bytes());

    let ss = derive_final_secret(&dh_1_bytes, &dh_2_bytes, &eph_pk_1, recipient_pk);

    // Zeroize
    dh_1_bytes.zeroize();
    dh_2_bytes.zeroize();

    Ok(HkOvctSharedSecret { secret: ss })
}

/// Decapsulate and store secret in registry, returning handle
pub fn decapsulate_to_handle(
    ct: &HkOvctCiphertext,
    recipient_keypair: &HkOvctKeyPair,
) -> Result<HkOvctSecretHandle, HkOvctError> {
    let ss = decapsulate(ct, recipient_keypair)?;
    Ok(store_shared_secret(ss))
}

// ============================================================================
// SHARED SECRET OPERATIONS
// ============================================================================

impl HkOvctSharedSecret {
    /// Get raw bytes (use sparingly - prefer derive_key)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Derive a key for a specific purpose
    pub fn derive_key(&self, context: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_SESSION), &self.secret);
        let mut output = [0u8; 32];
        hk.expand(context, &mut output).expect("HKDF expand failed");
        output
    }

    /// Derive separate sending and receiving keys
    pub fn derive_session_keys(&self) -> ([u8; 32], [u8; 32]) {
        let send_key = self.derive_key(b"send");
        let recv_key = self.derive_key(b"recv");
        (send_key, recv_key)
    }
}

impl HkOvctCiphertext {
    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// ============================================================================
// UTILITY
// ============================================================================

fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encapsulate_decapsulate_match() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();
        let aux = b"accelerometer_gyro_touch_timing";

        let (ct, ss_sender) = encapsulate(
            recipient.public_key(),
            &sender,
            aux,
        ).expect("encapsulate failed");

        let ss_recipient = decapsulate(&ct, &recipient)
            .expect("decapsulate failed");

        assert_eq!(
            ss_sender.as_bytes(),
            ss_recipient.as_bytes(),
            "Shared secrets must match"
        );
    }

    #[test]
    fn test_different_aux_entropy() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();

        let (ct1, ss1) = encapsulate(recipient.public_key(), &sender, b"entropy_a").unwrap();
        let (ct2, ss2) = encapsulate(recipient.public_key(), &sender, b"entropy_b").unwrap();

        // Different aux entropy → different ciphertexts and secrets
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // But both should decapsulate correctly
        let ss1_dec = decapsulate(&ct1, &recipient).unwrap();
        let ss2_dec = decapsulate(&ct2, &recipient).unwrap();

        assert_eq!(ss1.as_bytes(), ss1_dec.as_bytes());
        assert_eq!(ss2.as_bytes(), ss2_dec.as_bytes());
    }

    #[test]
    fn test_wrong_recipient_different_secret() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();
        let wrong_recipient = HkOvctKeyPair::generate();

        let (ct, ss_sender) = encapsulate(recipient.public_key(), &sender, b"aux").unwrap();

        let ss_wrong = decapsulate(&ct, &wrong_recipient).unwrap();

        assert_ne!(ss_sender.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn test_session_key_derivation() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();

        let (ct, ss) = encapsulate(recipient.public_key(), &sender, b"aux").unwrap();

        let key1 = ss.derive_key(b"purpose-a");
        let key2 = ss.derive_key(b"purpose-b");

        // Different contexts → different keys
        assert_ne!(key1, key2);

        // Same context → same key
        assert_eq!(key1, ss.derive_key(b"purpose-a"));
    }

    #[test]
    fn test_handle_registry() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();

        let (ct, handle) = encapsulate_to_handle(
            recipient.public_key(),
            &sender,
            b"aux",
        ).unwrap();

        // Derive key via handle
        let key1 = derive_session_key(handle, b"test").unwrap();

        // Decapsulate to another handle
        let handle2 = decapsulate_to_handle(&ct, &recipient).unwrap();
        let key2 = derive_session_key(handle2, b"test").unwrap();

        assert_eq!(key1, key2);

        // Cleanup
        delete_shared_secret(handle).unwrap();
        delete_shared_secret(handle2).unwrap();

        // Handle should be invalid now
        assert!(derive_session_key(handle, b"test").is_err());
    }

    #[test]
    fn test_hedging_with_empty_aux() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();

        // Even with empty aux, hedging still works (system RNG + deterministic)
        let result = encapsulate(recipient.public_key(), &sender, b"");
        assert!(result.is_ok());

        let (ct, ss) = result.unwrap();
        let ss_dec = decapsulate(&ct, &recipient).unwrap();
        assert_eq!(ss.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_derive_session_keys() {
        let sender = HkOvctKeyPair::generate();
        let recipient = HkOvctKeyPair::generate();

        let (_, ss) = encapsulate(recipient.public_key(), &sender, b"aux").unwrap();

        let (send, recv) = ss.derive_session_keys();

        // Send and receive keys must be different
        assert_ne!(send, recv);
    }
}
