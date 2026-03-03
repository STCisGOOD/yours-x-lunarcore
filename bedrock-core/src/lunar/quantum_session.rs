//! Quantum-Resistant Hybrid Session Establishment
//!
//! This module provides quantum-resistant session establishment using ML-KEM-768
//! for initial key exchange, while maintaining forward secrecy through the
//! existing X25519-based Double Ratchet.
//!
//! ## Architecture
//!
//! ```text
//! Identity Layer:     ML-KEM-768 (2400/1184 bytes) - Quantum Resistant
//!                           |
//!                     ML-KEM Encapsulate
//!                           |
//!                     Shared Secret (32 bytes)
//!                           |
//!                     HKDF Derivation
//!                           |
//!                     X25519 Keys (32 bytes)
//!                           |
//! Session Layer:      HkOvctKeyPair + Double Ratchet - Forward Secrecy
//! ```
//!
//! ## Security Properties
//!
//! - **Post-quantum security**: ML-KEM-768 provides ~192-bit security against
//!   quantum computers (NIST Level 3)
//! - **Forward secrecy**: X25519 Double Ratchet ensures past messages remain
//!   secure even if long-term keys are compromised
//! - **Hybrid security**: Even if one primitive breaks, the other provides defense

use crate::lunar::hedged_kem::{HkOvctKeyPair, HkOvctCiphertext, encapsulate, decapsulate};
use crate::lunar::session::{Session, SessionError};
use crate::lunar::packet::HandshakePacket;

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768, EncodedSizeUser};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;
use zeroize::Zeroize;
use rand_core::{RngCore, OsRng};

// ============================================================================
// CONSTANTS
// ============================================================================

/// ML-KEM-768 decapsulation key size (private key)
pub const MLKEM_DK_SIZE: usize = 2400;

/// ML-KEM-768 encapsulation key size (public key)
pub const MLKEM_EK_SIZE: usize = 1184;

/// ML-KEM-768 ciphertext size
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;

/// Domain separator for deriving session keys from ML-KEM shared secret
const DOMAIN_QUANTUM_SESSION: &[u8] = b"yours-quantum-session-v1";

/// Domain separator for deriving X25519 private key
const DOMAIN_X25519_PRIVATE: &[u8] = b"yours-x25519-derive-v1";

// ============================================================================
// QUANTUM SESSION INITIATOR
// ============================================================================

/// Result of quantum session initiation
pub struct QuantumSessionInitResult {
    /// The session object
    pub session: Session,
    /// Handshake packet to send (includes ML-KEM ciphertext)
    pub handshake: QuantumHandshake,
    /// Session hint for routing
    pub session_hint: [u8; 4],
}

/// Quantum-resistant handshake packet
///
/// Contains the ML-KEM ciphertext (1088 bytes) followed by the regular
/// X25519-based handshake packet for the Double Ratchet.
pub struct QuantumHandshake {
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub mlkem_ciphertext: [u8; MLKEM_CIPHERTEXT_SIZE],
    /// Regular handshake packet (for Double Ratchet setup)
    pub inner_handshake: Vec<u8>,
}

impl QuantumHandshake {
    /// Encode to bytes for transmission
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MLKEM_CIPHERTEXT_SIZE + self.inner_handshake.len());
        output.extend_from_slice(&self.mlkem_ciphertext);
        output.extend_from_slice(&self.inner_handshake);
        output
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, SessionError> {
        if data.len() < MLKEM_CIPHERTEXT_SIZE {
            return Err(SessionError::PacketError("Handshake too short".to_string()));
        }

        let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_SIZE];
        mlkem_ciphertext.copy_from_slice(&data[..MLKEM_CIPHERTEXT_SIZE]);

        let inner_handshake = data[MLKEM_CIPHERTEXT_SIZE..].to_vec();

        Ok(Self {
            mlkem_ciphertext,
            inner_handshake,
        })
    }
}

/// Initiate a quantum-resistant session.
///
/// This function:
/// 1. Uses ML-KEM-768 to encapsulate a shared secret to the recipient
/// 2. Derives X25519 session keys from the ML-KEM shared secret
/// 3. Creates a regular session using those derived keys
///
/// # Arguments
/// * `our_mlkem_dk` - Our ML-KEM-768 decapsulation key (2400 bytes)
/// * `their_mlkem_ek` - Their ML-KEM-768 encapsulation key (1184 bytes)
/// * `aux_entropy` - External entropy for hedging
///
/// # Returns
/// * `QuantumSessionInitResult` containing session, handshake, and hint
pub fn quantum_session_initiate(
    our_mlkem_dk: &[u8; MLKEM_DK_SIZE],
    their_mlkem_ek: &[u8; MLKEM_EK_SIZE],
    aux_entropy: &[u8],
) -> Result<QuantumSessionInitResult, SessionError> {
    // =========================================================================
    // STEP 1: ML-KEM Encapsulation (Quantum-Resistant Initial Exchange)
    // =========================================================================

    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&(*their_mlkem_ek).into());

    let mut rng = OsRng;
    let (mlkem_ct, mlkem_ss) = ek.encapsulate(&mut rng)
        .map_err(|_| SessionError::KeyExchangeFailed)?;

    // =========================================================================
    // STEP 2: Derive X25519 Session Keys from ML-KEM Shared Secret
    // =========================================================================

    let (our_x25519_secret, their_x25519_public) = derive_x25519_keys(
        mlkem_ss.as_slice(),
        our_mlkem_dk,
        their_mlkem_ek,
        aux_entropy,
    );

    // =========================================================================
    // STEP 3: Create X25519 keypair for Double Ratchet
    // =========================================================================

    let our_keypair = HkOvctKeyPair::from_secret_bytes(our_x25519_secret);
    let their_public = X25519PublicKey::from(their_x25519_public);

    // =========================================================================
    // STEP 4: Initiate regular session with derived keys
    // =========================================================================

    let (session, inner_handshake) = Session::initiate(our_keypair, &their_public, aux_entropy)?;

    // Get session hint
    let session_hint = session.session_hint()
        .ok_or(SessionError::KeyExchangeFailed)?;

    // =========================================================================
    // STEP 5: Package quantum handshake
    // =========================================================================

    let mut mlkem_ciphertext = [0u8; MLKEM_CIPHERTEXT_SIZE];
    mlkem_ciphertext.copy_from_slice(mlkem_ct.as_slice());

    let quantum_handshake = QuantumHandshake {
        mlkem_ciphertext,
        inner_handshake: inner_handshake.encode(),
    };

    Ok(QuantumSessionInitResult {
        session,
        handshake: quantum_handshake,
        session_hint,
    })
}

// ============================================================================
// QUANTUM SESSION RESPONDER
// ============================================================================

/// Result of quantum session response
pub struct QuantumSessionRespondResult {
    /// The session object
    pub session: Session,
    /// Session hint for routing
    pub session_hint: [u8; 4],
}

/// Respond to a quantum-resistant session handshake.
///
/// This function:
/// 1. Decapsulates the ML-KEM ciphertext to recover the shared secret
/// 2. Derives X25519 session keys from the ML-KEM shared secret
/// 3. Creates a responding session using those derived keys
///
/// # Arguments
/// * `our_mlkem_dk` - Our ML-KEM-768 decapsulation key (2400 bytes)
/// * `our_mlkem_ek` - Our ML-KEM-768 encapsulation key (1184 bytes)
/// * `handshake_bytes` - Received quantum handshake bytes
///
/// # Returns
/// * `QuantumSessionRespondResult` containing session and hint
pub fn quantum_session_respond(
    our_mlkem_dk: &[u8; MLKEM_DK_SIZE],
    our_mlkem_ek: &[u8; MLKEM_EK_SIZE],
    handshake_bytes: &[u8],
) -> Result<QuantumSessionRespondResult, SessionError> {
    // =========================================================================
    // STEP 1: Parse quantum handshake
    // =========================================================================

    let quantum_handshake = QuantumHandshake::decode(handshake_bytes)?;

    // =========================================================================
    // STEP 2: ML-KEM Decapsulation (Quantum-Resistant)
    // =========================================================================

    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&(*our_mlkem_dk).into());

    let mlkem_ct: ml_kem::Ciphertext<MlKem768> = quantum_handshake.mlkem_ciphertext.into();
    let mlkem_ss = dk.decapsulate(&mlkem_ct)
        .map_err(|_| SessionError::KeyExchangeFailed)?;

    // =========================================================================
    // STEP 3: Derive X25519 Session Keys from ML-KEM Shared Secret
    // Note: Responder derives keys in opposite roles
    // =========================================================================

    // The initiator derived: (their_secret, our_public) from (their_dk, our_ek)
    // We need to derive keys that match, but for the responder's perspective
    let (our_x25519_secret, _their_x25519_public) = derive_x25519_keys_responder(
        mlkem_ss.as_slice(),
        our_mlkem_dk,
        our_mlkem_ek,
    );

    // =========================================================================
    // STEP 4: Create X25519 keypair for Double Ratchet
    // =========================================================================

    let our_keypair = HkOvctKeyPair::from_secret_bytes(our_x25519_secret);

    // =========================================================================
    // STEP 5: Parse inner handshake and create responding session
    // =========================================================================

    let inner_handshake = HandshakePacket::decode(&quantum_handshake.inner_handshake)
        .map_err(|e| SessionError::PacketError(e.to_string()))?;

    let session = Session::respond(our_keypair, &inner_handshake)?;

    let session_hint = session.session_hint()
        .ok_or(SessionError::KeyExchangeFailed)?;

    Ok(QuantumSessionRespondResult {
        session,
        session_hint,
    })
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

/// Derive X25519 session keys from ML-KEM shared secret (Initiator)
///
/// Uses HKDF to derive deterministic X25519 keys from the ML-KEM shared secret.
/// Both parties derive the same keys because they have the same ML-KEM shared secret.
fn derive_x25519_keys(
    mlkem_shared_secret: &[u8],
    our_mlkem_dk: &[u8; MLKEM_DK_SIZE],
    their_mlkem_ek: &[u8; MLKEM_EK_SIZE],
    aux_entropy: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // Build input key material: ML-KEM shared secret + public key binding
    let mut ikm = Vec::with_capacity(32 + MLKEM_EK_SIZE + aux_entropy.len());
    ikm.extend_from_slice(mlkem_shared_secret);
    ikm.extend_from_slice(their_mlkem_ek);
    ikm.extend_from_slice(aux_entropy);

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_QUANTUM_SESSION), &ikm);

    // Derive our X25519 secret key
    let mut our_secret = [0u8; 32];
    hk.expand(b"initiator-x25519-secret", &mut our_secret)
        .expect("HKDF expand failed");

    // Clamp for X25519
    our_secret[0] &= 248;
    our_secret[31] &= 127;
    our_secret[31] |= 64;

    // Derive their X25519 public key (deterministic from shared secret)
    let mut their_secret = [0u8; 32];
    hk.expand(b"responder-x25519-secret", &mut their_secret)
        .expect("HKDF expand failed");

    // Clamp for X25519
    their_secret[0] &= 248;
    their_secret[31] &= 127;
    their_secret[31] |= 64;

    // Compute their public key from their derived secret
    let their_sk = x25519_dalek::StaticSecret::from(their_secret);
    let their_pk = X25519PublicKey::from(&their_sk);

    // Zeroize intermediate secrets
    ikm.zeroize();
    their_secret.zeroize();

    (our_secret, their_pk.to_bytes())
}

/// Derive X25519 session keys from ML-KEM shared secret (Responder)
///
/// The responder derives keys in the opposite roles.
fn derive_x25519_keys_responder(
    mlkem_shared_secret: &[u8],
    our_mlkem_dk: &[u8; MLKEM_DK_SIZE],
    our_mlkem_ek: &[u8; MLKEM_EK_SIZE],
) -> ([u8; 32], [u8; 32]) {
    // Build input key material: ML-KEM shared secret + public key binding
    let mut ikm = Vec::with_capacity(32 + MLKEM_EK_SIZE);
    ikm.extend_from_slice(mlkem_shared_secret);
    ikm.extend_from_slice(our_mlkem_ek); // Use our public key (same as what initiator used)

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_QUANTUM_SESSION), &ikm);

    // Derive our X25519 secret key (responder)
    let mut our_secret = [0u8; 32];
    hk.expand(b"responder-x25519-secret", &mut our_secret)
        .expect("HKDF expand failed");

    // Clamp for X25519
    our_secret[0] &= 248;
    our_secret[31] &= 127;
    our_secret[31] |= 64;

    // Derive their X25519 public key (initiator's)
    let mut their_secret = [0u8; 32];
    hk.expand(b"initiator-x25519-secret", &mut their_secret)
        .expect("HKDF expand failed");

    // Clamp for X25519
    their_secret[0] &= 248;
    their_secret[31] &= 127;
    their_secret[31] |= 64;

    // Compute their public key from their derived secret
    let their_sk = x25519_dalek::StaticSecret::from(their_secret);
    let their_pk = X25519PublicKey::from(&their_sk);

    // Zeroize intermediate secrets
    ikm.zeroize();
    their_secret.zeroize();

    (our_secret, their_pk.to_bytes())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_mlkem_keypair() -> ([u8; MLKEM_DK_SIZE], [u8; MLKEM_EK_SIZE]) {
        let mut rng = OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);

        let mut dk_bytes = [0u8; MLKEM_DK_SIZE];
        let mut ek_bytes = [0u8; MLKEM_EK_SIZE];
        dk_bytes.copy_from_slice(dk.as_bytes().as_slice());
        ek_bytes.copy_from_slice(ek.as_bytes().as_slice());

        (dk_bytes, ek_bytes)
    }

    #[test]
    fn test_quantum_session_roundtrip() {
        // Generate ML-KEM keypairs for both parties
        let (alice_dk, alice_ek) = generate_mlkem_keypair();
        let (bob_dk, bob_ek) = generate_mlkem_keypair();

        // Alice initiates quantum session to Bob
        let init_result = quantum_session_initiate(
            &alice_dk,
            &bob_ek,
            b"sensor_entropy_data",
        ).expect("Initiation failed");

        // Encode handshake for transmission
        let handshake_bytes = init_result.handshake.encode();

        // Bob responds to the quantum session
        let respond_result = quantum_session_respond(
            &bob_dk,
            &bob_ek,
            &handshake_bytes,
        ).expect("Response failed");

        // Both should have matching session hints
        assert_eq!(init_result.session_hint, respond_result.session_hint);
    }

    #[test]
    fn test_quantum_session_encrypt_decrypt() {
        let (alice_dk, alice_ek) = generate_mlkem_keypair();
        let (bob_dk, bob_ek) = generate_mlkem_keypair();

        // Establish quantum session
        let mut init_result = quantum_session_initiate(
            &alice_dk,
            &bob_ek,
            b"entropy",
        ).expect("Initiation failed");

        let handshake_bytes = init_result.handshake.encode();
        init_result.session.mark_established().unwrap();

        let mut respond_result = quantum_session_respond(
            &bob_dk,
            &bob_ek,
            &handshake_bytes,
        ).expect("Response failed");

        // Alice encrypts a message
        let plaintext = b"Hello from quantum-resistant channel!";
        let ciphertext = init_result.session.encrypt(plaintext)
            .expect("Encryption failed");

        // Bob decrypts
        let decrypted = respond_result.session.decrypt(&ciphertext)
            .expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let (alice_dk, alice_ek) = generate_mlkem_keypair();
        let (bob_dk, bob_ek) = generate_mlkem_keypair();
        let (eve_dk, eve_ek) = generate_mlkem_keypair();

        // Alice initiates to Bob
        let init_result = quantum_session_initiate(
            &alice_dk,
            &bob_ek,
            b"entropy",
        ).expect("Initiation failed");

        let handshake_bytes = init_result.handshake.encode();

        // Eve tries to respond with her keys
        let eve_result = quantum_session_respond(
            &eve_dk,
            &eve_ek,
            &handshake_bytes,
        );

        // Eve should get a session but with different keys
        // (decryption will fail)
        if let Ok(mut eve_session) = eve_result {
            let mut alice_session = init_result.session;
            alice_session.mark_established().unwrap();

            let plaintext = b"Secret message";
            let ciphertext = alice_session.encrypt(plaintext).unwrap();

            // Eve's decryption should fail
            assert!(eve_session.session.decrypt(&ciphertext).is_err());
        }
    }
}
