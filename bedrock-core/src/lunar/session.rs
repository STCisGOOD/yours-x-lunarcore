//! LunarCore Session Management
//!
//! Implements secure session establishment and the Double Ratchet algorithm
//! for forward secrecy and post-compromise security.
//!
//! ## Session Lifecycle
//!
//! 1. **Initiate**: Generate ephemeral keys, create handshake with Hk-OVCT
//! 2. **Respond**: Receive handshake, derive shared secret, send response
//! 3. **Established**: Encrypt/decrypt messages with ratcheting
//! 4. **Ratchet**: Periodic DH ratchet for post-compromise security
//! 5. **Close**: Zeroize all keys, mark session closed
//!
//! ## Double Ratchet
//!
//! The Double Ratchet combines:
//! - **Symmetric ratchet**: KDF chain for each message (forward secrecy)
//! - **DH ratchet**: Periodic new DH exchange (post-compromise security)
//!
//! ## Security Properties
//!
//! - Forward secrecy: Compromising current keys doesn't expose past messages
//! - Post-compromise security: System heals after key compromise
//! - Hedged key exchange: Secure even with compromised RNG (via Hk-OVCT)

use crate::lunar::hedged_kem::{
    HkOvctKeyPair, HkOvctCiphertext, HkOvctSharedSecret,
    encapsulate, decapsulate, HkOvctError,
};
use crate::lunar::packet::{
    HandshakePacket, DataPacket, derive_node_hint, derive_session_hint,
    NODE_HINT_SIZE, SESSION_HINT_SIZE,
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, OsRng};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for root key derivation
const DOMAIN_ROOT: &[u8] = b"lunarcore-root-v1";

/// Domain separator for chain key derivation
const DOMAIN_CHAIN: &[u8] = b"lunarcore-chain-v1";

/// Domain separator for message key derivation
const DOMAIN_MESSAGE: &[u8] = b"lunarcore-message-v1";

/// Domain separator for ratchet step
const DOMAIN_RATCHET: &[u8] = b"lunarcore-ratchet-v1";

/// Maximum messages before mandatory DH ratchet
const MAX_MESSAGES_BEFORE_RATCHET: u64 = 100;

/// Maximum time (seconds) before mandatory DH ratchet
const MAX_TIME_BEFORE_RATCHET_SECS: u64 = 600; // 10 minutes

/// Maximum skipped message keys to store (for out-of-order delivery)
const MAX_SKIP: usize = 100;

/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;

/// Auth tag size for AES-GCM
const TAG_SIZE: usize = 16;

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Session errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session is in wrong state for this operation
    InvalidState { expected: &'static str, actual: SessionState },
    /// Key exchange failed
    KeyExchangeFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed (wrong key or tampered)
    DecryptionFailed,
    /// Message counter overflow
    CounterOverflow,
    /// Too many skipped messages
    TooManySkipped,
    /// Session has been closed
    SessionClosed,
    /// Packet encoding error
    PacketError(String),
    /// Ratchet required but not performed
    RatchetRequired,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::InvalidState { expected, actual } => {
                write!(f, "Invalid state: expected {}, got {:?}", expected, actual)
            }
            SessionError::KeyExchangeFailed => write!(f, "Key exchange failed"),
            SessionError::EncryptionFailed => write!(f, "Encryption failed"),
            SessionError::DecryptionFailed => write!(f, "Decryption failed"),
            SessionError::CounterOverflow => write!(f, "Message counter overflow"),
            SessionError::TooManySkipped => write!(f, "Too many skipped messages"),
            SessionError::SessionClosed => write!(f, "Session is closed"),
            SessionError::PacketError(msg) => write!(f, "Packet error: {}", msg),
            SessionError::RatchetRequired => write!(f, "DH ratchet required"),
        }
    }
}

impl std::error::Error for SessionError {}

// ============================================================================
// SESSION STATE
// ============================================================================

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session initiated, waiting for response
    Initiating,
    /// Received handshake, preparing response
    Responding,
    /// Session established, ready for messages
    Established,
    /// Session closed, keys zeroized
    Closed,
}

// ============================================================================
// SESSION ID
// ============================================================================

/// Unique session identifier (derived from root key for consistency)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Generate a random session ID
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    /// Derive session ID from root key (ensures both parties have same ID)
    pub fn from_root_key(root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"lunarcore-session-id-v1"), root_key);
        let mut id = [0u8; 16];
        hk.expand(b"session-id", &mut id).expect("HKDF expand failed");
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionId({:02x}{:02x}...)", self.0[0], self.0[1])
    }
}

// ============================================================================
// CHAIN KEY (Symmetric Ratchet)
// ============================================================================

/// Chain key for symmetric ratchet
#[derive(ZeroizeOnDrop)]
struct ChainKey {
    key: [u8; 32],
    counter: u64,
}

impl ChainKey {
    /// Create new chain key
    fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// Derive next message key and advance chain
    fn next_message_key(&mut self) -> Result<MessageKey, SessionError> {
        if self.counter == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }

        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_MESSAGE), &self.key);

        // Derive message key
        let mut message_key = [0u8; 32];
        hk.expand(&self.counter.to_be_bytes(), &mut message_key)
            .expect("HKDF expand failed");

        // Advance chain
        let mut new_chain = [0u8; 32];
        let hk_chain = Hkdf::<Sha256>::new(Some(DOMAIN_CHAIN), &self.key);
        hk_chain.expand(&self.counter.to_be_bytes(), &mut new_chain)
            .expect("HKDF expand failed");

        self.key.zeroize();
        self.key = new_chain;

        let counter = self.counter;
        self.counter += 1;

        Ok(MessageKey { key: message_key, counter })
    }

    /// Get current counter value
    fn counter(&self) -> u64 {
        self.counter
    }
}

// ============================================================================
// MESSAGE KEY
// ============================================================================

/// Single-use message key
#[derive(ZeroizeOnDrop)]
struct MessageKey {
    key: [u8; 32],
    counter: u64,
}

impl MessageKey {
    /// Encrypt plaintext with this message key
    fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| SessionError::EncryptionFailed)?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            }
        ).map_err(|_| SessionError::EncryptionFailed)?;

        // Output: counter (8) || nonce (12) || ciphertext+tag
        let mut output = Vec::with_capacity(8 + NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&self.counter.to_be_bytes());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt ciphertext with this message key
    fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        if ciphertext.len() < 8 + NONCE_SIZE + TAG_SIZE {
            return Err(SessionError::DecryptionFailed);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| SessionError::DecryptionFailed)?;

        // Parse: counter (8) || nonce (12) || ciphertext+tag
        let nonce = Nonce::from_slice(&ciphertext[8..8 + NONCE_SIZE]);
        let encrypted = &ciphertext[8 + NONCE_SIZE..];

        cipher.decrypt(
            nonce,
            Payload {
                msg: encrypted,
                aad: associated_data,
            }
        ).map_err(|_| SessionError::DecryptionFailed)
    }
}

// ============================================================================
// SKIPPED MESSAGE KEYS
// ============================================================================

/// Storage for skipped message keys (out-of-order delivery)
struct SkippedKeys {
    /// Map of (their_public_key, counter) -> message_key
    keys: std::collections::HashMap<([u8; 32], u64), MessageKey>,
}

impl SkippedKeys {
    fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }

    fn store(&mut self, their_pk: [u8; 32], counter: u64, key: MessageKey) -> Result<(), SessionError> {
        if self.keys.len() >= MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        self.keys.insert((their_pk, counter), key);
        Ok(())
    }

    fn try_get(&mut self, their_pk: &[u8; 32], counter: u64) -> Option<MessageKey> {
        self.keys.remove(&(*their_pk, counter))
    }

    fn clear(&mut self) {
        self.keys.clear();
    }
}

// ============================================================================
// SESSION
// ============================================================================

/// Secure communication session with double ratchet
pub struct Session {
    /// Unique session identifier
    id: SessionId,

    /// Current state
    state: SessionState,

    /// Our long-term keypair (for Hk-OVCT hedging)
    our_identity: HkOvctKeyPair,

    /// Their long-term public key
    their_identity: Option<PublicKey>,

    /// Our current ephemeral secret (for DH ratchet)
    our_ephemeral_secret: Option<StaticSecret>,

    /// Our current ephemeral public key
    our_ephemeral_public: Option<PublicKey>,

    /// Their current ephemeral public key
    their_ephemeral_public: Option<PublicKey>,

    /// Root key (survives DH ratchets)
    root_key: Option<[u8; 32]>,

    /// Sending chain key
    sending_chain: Option<ChainKey>,

    /// Receiving chain key
    receiving_chain: Option<ChainKey>,

    /// Skipped message keys for out-of-order delivery
    skipped_keys: SkippedKeys,

    /// Messages sent since last DH ratchet
    messages_since_ratchet: u64,

    /// Time of last DH ratchet (Unix timestamp)
    last_ratchet_time: u64,

    /// Session creation time
    created_at: u64,
}

impl Session {
    // ========================================================================
    // CONSTRUCTION
    // ========================================================================

    /// Create a new session as initiator
    ///
    /// # Arguments
    /// * `our_identity` - Our long-term keypair
    /// * `their_identity_pk` - Their long-term public key
    /// * `aux_entropy` - External entropy for Hk-OVCT
    ///
    /// # Returns
    /// * `Session` - New session in Initiating state
    /// * `HandshakePacket` - Packet to send to recipient
    pub fn initiate(
        our_identity: HkOvctKeyPair,
        their_identity_pk: &PublicKey,
        aux_entropy: &[u8],
    ) -> Result<(Self, HandshakePacket), SessionError> {
        let now = current_timestamp();

        // Generate ephemeral keypair
        let our_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

        // Encapsulate with Hk-OVCT
        let (ct, shared_secret) = encapsulate(their_identity_pk, &our_identity, aux_entropy)
            .map_err(|_| SessionError::KeyExchangeFailed)?;

        // Derive root key from shared secret
        let root_key = derive_root_key(shared_secret.as_bytes(), &our_ephemeral_public, their_identity_pk);

        // Derive initial chain keys
        let (sending_chain, receiving_chain) = derive_chain_keys(&root_key);

        // Create session hint from root key
        let session_hint = derive_session_hint(&root_key);

        // Create handshake packet
        let recipient_hint = derive_node_hint(their_identity_pk.as_bytes());
        let handshake = HandshakePacket::new(
            recipient_hint,
            our_ephemeral_public.to_bytes(),
            ct.0,
            vec![], // No initial message payload
        ).map_err(|e| SessionError::PacketError(e.to_string()))?;

        // Derive session ID from root key (both parties will have same ID)
        let session_id = SessionId::from_root_key(&root_key);

        let session = Session {
            id: session_id,
            state: SessionState::Initiating,
            our_identity,
            their_identity: Some(*their_identity_pk),
            our_ephemeral_secret: Some(our_ephemeral_secret),
            our_ephemeral_public: Some(our_ephemeral_public),
            their_ephemeral_public: None,
            root_key: Some(root_key),
            sending_chain: Some(ChainKey::new(sending_chain)),
            receiving_chain: Some(ChainKey::new(receiving_chain)),
            skipped_keys: SkippedKeys::new(),
            messages_since_ratchet: 0,
            last_ratchet_time: now,
            created_at: now,
        };

        Ok((session, handshake))
    }

    /// Accept an incoming handshake and create responding session
    ///
    /// # Arguments
    /// * `our_identity` - Our long-term keypair
    /// * `handshake` - Received handshake packet
    ///
    /// # Returns
    /// * `Session` - New session in Established state
    pub fn respond(
        our_identity: HkOvctKeyPair,
        handshake: &HandshakePacket,
    ) -> Result<Self, SessionError> {
        let now = current_timestamp();

        // Parse their ephemeral public key
        let their_ephemeral_public = PublicKey::from(handshake.ephemeral_pk);

        // Decapsulate Hk-OVCT
        let ct = HkOvctCiphertext::from_bytes(handshake.hk_ovct_ciphertext);
        let shared_secret = decapsulate(&ct, &our_identity)
            .map_err(|_| SessionError::KeyExchangeFailed)?;

        // Derive root key (same as initiator)
        let root_key = derive_root_key(
            shared_secret.as_bytes(),
            &their_ephemeral_public,
            our_identity.public_key(),
        );

        // Derive chain keys (swapped from initiator's perspective)
        let (sending_chain, receiving_chain) = derive_chain_keys(&root_key);

        // Generate our ephemeral for future DH ratchets
        let our_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

        // Derive session ID from root key (matches initiator's ID)
        let session_id = SessionId::from_root_key(&root_key);

        let session = Session {
            id: session_id,
            state: SessionState::Established,
            our_identity,
            their_identity: None, // Not known from handshake alone
            our_ephemeral_secret: Some(our_ephemeral_secret),
            our_ephemeral_public: Some(our_ephemeral_public),
            their_ephemeral_public: Some(their_ephemeral_public),
            root_key: Some(root_key),
            // Note: Responder's send = Initiator's receive
            sending_chain: Some(ChainKey::new(receiving_chain)),
            receiving_chain: Some(ChainKey::new(sending_chain)),
            skipped_keys: SkippedKeys::new(),
            messages_since_ratchet: 0,
            last_ratchet_time: now,
            created_at: now,
        };

        Ok(session)
    }

    // ========================================================================
    // ENCRYPTION / DECRYPTION
    // ========================================================================

    /// Encrypt a message
    ///
    /// # Arguments
    /// * `plaintext` - Message to encrypt
    ///
    /// # Returns
    /// * Encrypted payload (counter || nonce || ciphertext || tag)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.ensure_state(SessionState::Established)?;

        // Check if DH ratchet is required
        self.check_ratchet_required()?;

        let sending_chain = self.sending_chain.as_mut()
            .ok_or(SessionError::InvalidState {
                expected: "has sending chain",
                actual: self.state
            })?;

        // Get next message key
        let message_key = sending_chain.next_message_key()?;

        // Associated data: session ID
        let ad = self.id.as_bytes();

        // Encrypt
        let ciphertext = message_key.encrypt(plaintext, ad)?;

        self.messages_since_ratchet += 1;

        Ok(ciphertext)
    }

    /// Decrypt a message
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted message (counter || nonce || ciphertext || tag)
    ///
    /// # Returns
    /// * Decrypted plaintext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.ensure_state(SessionState::Established)?;

        if ciphertext.len() < 8 {
            return Err(SessionError::DecryptionFailed);
        }

        // Extract message counter
        let counter = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());

        // Check for skipped message key first
        if let Some(their_pk) = &self.their_ephemeral_public {
            if let Some(message_key) = self.skipped_keys.try_get(&their_pk.to_bytes(), counter) {
                let ad = self.id.as_bytes();
                return message_key.decrypt(ciphertext, ad);
            }
        }

        // Get receiving chain
        let receiving_chain = self.receiving_chain.as_mut()
            .ok_or(SessionError::InvalidState {
                expected: "has receiving chain",
                actual: self.state
            })?;

        // Skip ahead if needed and store skipped keys
        let current_counter = receiving_chain.counter();
        if counter > current_counter {
            let skip_count = counter - current_counter;
            if skip_count as usize > MAX_SKIP {
                return Err(SessionError::TooManySkipped);
            }

            // Store skipped keys
            let their_pk = self.their_ephemeral_public
                .ok_or(SessionError::DecryptionFailed)?
                .to_bytes();

            for _ in 0..skip_count {
                let skipped_key = receiving_chain.next_message_key()?;
                self.skipped_keys.store(their_pk, skipped_key.counter, skipped_key)?;
            }
        }

        // Get the message key for this counter
        let message_key = receiving_chain.next_message_key()?;

        // Associated data: session ID
        let ad = self.id.as_bytes();

        // Decrypt
        message_key.decrypt(ciphertext, ad)
    }

    // ========================================================================
    // DH RATCHET
    // ========================================================================

    /// Perform a DH ratchet step
    ///
    /// This provides post-compromise security by introducing new DH material.
    pub fn ratchet(&mut self, their_new_ephemeral: &PublicKey) -> Result<PublicKey, SessionError> {
        self.ensure_state(SessionState::Established)?;

        let root_key = self.root_key.as_ref()
            .ok_or(SessionError::InvalidState {
                expected: "has root key",
                actual: self.state
            })?;

        // Generate new ephemeral keypair
        let new_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let new_ephemeral_public = PublicKey::from(&new_ephemeral_secret);

        // DH with their new ephemeral
        let dh_output = new_ephemeral_secret.diffie_hellman(their_new_ephemeral);

        // Derive new root key
        let hk = Hkdf::<Sha256>::new(Some(DOMAIN_RATCHET), dh_output.as_bytes());
        let mut new_root_key = [0u8; 32];
        let mut new_sending = [0u8; 32];
        let mut new_receiving = [0u8; 32];

        hk.expand(b"root", &mut new_root_key).expect("HKDF expand failed");
        hk.expand(b"send", &mut new_sending).expect("HKDF expand failed");
        hk.expand(b"recv", &mut new_receiving).expect("HKDF expand failed");

        // Update state
        if let Some(old_root) = self.root_key.as_mut() {
            old_root.zeroize();
        }
        self.root_key = Some(new_root_key);

        self.our_ephemeral_secret = Some(new_ephemeral_secret);
        self.our_ephemeral_public = Some(new_ephemeral_public);
        self.their_ephemeral_public = Some(*their_new_ephemeral);

        self.sending_chain = Some(ChainKey::new(new_sending));
        self.receiving_chain = Some(ChainKey::new(new_receiving));

        self.messages_since_ratchet = 0;
        self.last_ratchet_time = current_timestamp();

        Ok(new_ephemeral_public)
    }

    /// Check if a DH ratchet is recommended
    pub fn should_ratchet(&self) -> bool {
        let now = current_timestamp();
        let time_since_ratchet = now.saturating_sub(self.last_ratchet_time);

        self.messages_since_ratchet >= MAX_MESSAGES_BEFORE_RATCHET
            || time_since_ratchet >= MAX_TIME_BEFORE_RATCHET_SECS
    }

    // ========================================================================
    // STATE MANAGEMENT
    // ========================================================================

    /// Get session ID
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Mark session as established (after receiving response)
    pub fn mark_established(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Initiating {
            return Err(SessionError::InvalidState {
                expected: "Initiating",
                actual: self.state,
            });
        }
        self.state = SessionState::Established;
        Ok(())
    }

    /// Close the session and zeroize all keys
    pub fn close(&mut self) {
        // Zeroize root key
        if let Some(ref mut key) = self.root_key {
            key.zeroize();
        }
        self.root_key = None;

        // Chain keys are ZeroizeOnDrop
        self.sending_chain = None;
        self.receiving_chain = None;

        // Clear skipped keys
        self.skipped_keys.clear();

        // Clear ephemeral keys
        self.our_ephemeral_secret = None;
        self.our_ephemeral_public = None;
        self.their_ephemeral_public = None;

        self.state = SessionState::Closed;
    }

    /// Get our current ephemeral public key
    pub fn our_ephemeral_public(&self) -> Option<&PublicKey> {
        self.our_ephemeral_public.as_ref()
    }

    /// Get their current ephemeral public key
    pub fn their_ephemeral_public(&self) -> Option<&PublicKey> {
        self.their_ephemeral_public.as_ref()
    }

    /// Get session hint for routing
    pub fn session_hint(&self) -> Option<[u8; SESSION_HINT_SIZE]> {
        self.root_key.map(|rk| derive_session_hint(&rk))
    }

    /// Get messages sent since last ratchet
    pub fn messages_since_ratchet(&self) -> u64 {
        self.messages_since_ratchet
    }

    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    fn ensure_state(&self, expected: SessionState) -> Result<(), SessionError> {
        if self.state == SessionState::Closed {
            return Err(SessionError::SessionClosed);
        }
        if self.state != expected {
            return Err(SessionError::InvalidState {
                expected: state_name(expected),
                actual: self.state,
            });
        }
        Ok(())
    }

    fn check_ratchet_required(&self) -> Result<(), SessionError> {
        // For now, just warn but don't fail
        // In production, might want to enforce ratchet
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

// ============================================================================
// KEY DERIVATION HELPERS
// ============================================================================

/// Derive root key from shared secret and public keys
fn derive_root_key(
    shared_secret: &[u8; 32],
    ephemeral_pk: &PublicKey,
    identity_pk: &PublicKey,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 32 + 32);
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(ephemeral_pk.as_bytes());
    ikm.extend_from_slice(identity_pk.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_ROOT), &ikm);
    let mut root_key = [0u8; 32];
    hk.expand(b"root-key", &mut root_key).expect("HKDF expand failed");

    ikm.zeroize();
    root_key
}

/// Derive initial sending and receiving chain keys from root key
fn derive_chain_keys(root_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN_CHAIN), root_key);

    let mut sending = [0u8; 32];
    let mut receiving = [0u8; 32];

    hk.expand(b"sending-chain", &mut sending).expect("HKDF expand failed");
    hk.expand(b"receiving-chain", &mut receiving).expect("HKDF expand failed");

    (sending, receiving)
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get state name for error messages
fn state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Initiating => "Initiating",
        SessionState::Responding => "Responding",
        SessionState::Established => "Established",
        SessionState::Closed => "Closed",
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> HkOvctKeyPair {
        HkOvctKeyPair::generate()
    }

    #[test]
    fn test_session_initiate_and_respond() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        // Alice initiates
        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, handshake) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"sensor_entropy",
        ).unwrap();

        assert_eq!(alice_session.state(), SessionState::Initiating);

        // Bob responds
        let mut bob_session = Session::respond(bob_identity, &handshake).unwrap();

        assert_eq!(bob_session.state(), SessionState::Established);

        // Alice marks established
        alice_session.mark_established().unwrap();
        assert_eq!(alice_session.state(), SessionState::Established);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, handshake) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();
        alice_session.mark_established().unwrap();

        let mut bob_session = Session::respond(bob_identity, &handshake).unwrap();

        // Alice sends to Bob
        let plaintext = b"Hello, Bob! This is a secret message.";
        let ciphertext = alice_session.encrypt(plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob_session.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_multiple_messages() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, handshake) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();
        alice_session.mark_established().unwrap();

        let mut bob_session = Session::respond(bob_identity, &handshake).unwrap();

        // Send multiple messages
        for i in 0..10 {
            let plaintext = format!("Message number {}", i);
            let ciphertext = alice_session.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = bob_session.decrypt(&ciphertext).unwrap();
            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }

        assert_eq!(alice_session.messages_since_ratchet(), 10);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();
        let eve_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, handshake) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();
        alice_session.mark_established().unwrap();

        // Eve tries to respond with wrong identity
        let eve_result = Session::respond(eve_identity, &handshake);

        // Eve can create a session, but decryption will fail
        // because she derived different keys
        if let Ok(mut eve_session) = eve_result {
            let plaintext = b"Secret message";
            let ciphertext = alice_session.encrypt(plaintext).unwrap();

            // Eve's decryption should fail
            assert!(eve_session.decrypt(&ciphertext).is_err());
        }
    }

    #[test]
    fn test_session_close() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, _) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();

        alice_session.close();

        assert_eq!(alice_session.state(), SessionState::Closed);
        assert!(alice_session.encrypt(b"test").is_err());
    }

    #[test]
    fn test_session_hint() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (alice_session, handshake) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();

        let bob_session = Session::respond(bob_identity, &handshake).unwrap();

        // Both should have session hints
        let alice_hint = alice_session.session_hint();
        let bob_hint = bob_session.session_hint();

        assert!(alice_hint.is_some());
        assert!(bob_hint.is_some());

        // Hints should match (same root key)
        assert_eq!(alice_hint, bob_hint);
    }

    #[test]
    fn test_should_ratchet() {
        let alice_identity = generate_keypair();
        let bob_identity = generate_keypair();

        let bob_pk = PublicKey::from(*bob_identity.public_key().as_bytes());
        let (mut alice_session, _) = Session::initiate(
            alice_identity,
            &bob_pk,
            b"entropy",
        ).unwrap();
        alice_session.mark_established().unwrap();

        // Initially should not need ratchet
        assert!(!alice_session.should_ratchet());

        // After MAX_MESSAGES_BEFORE_RATCHET, should need ratchet
        for _ in 0..MAX_MESSAGES_BEFORE_RATCHET {
            let _ = alice_session.encrypt(b"test");
        }

        assert!(alice_session.should_ratchet());
    }
}
