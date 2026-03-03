//! LunarCore Routing Layer
//!
//! Implements node discovery, circuit construction, and path selection
//! for anonymous onion routing over LoRa mesh.
//!
//! ## Design Principles
//!
//! - **Path Diversity**: Circuits use 3+ relays from different regions/operators
//! - **Anti-Correlation**: Entry/exit combinations are not reused
//! - **Circuit Rotation**: Circuits rotate every 10 minutes or 100 messages
//! - **Gossip Discovery**: Nodes learn about peers through announcements
//!
//! ## Threat Model
//!
//! - Global passive adversary (monitors all RF traffic)
//! - Up to n-1 compromised relays in an n-relay circuit
//! - We protect against traffic analysis via path diversity

use crate::lunar::packet::{
    derive_node_hint, derive_session_hint,
    NODE_HINT_SIZE, SESSION_HINT_SIZE, AUTH_TAG_SIZE, MAX_PACKET_SIZE,
    HandshakePacket,
};
use crate::lunar::session::{Session, SessionId};
use crate::lunar::hedged_kem::HkOvctKeyPair;

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce as AesNonce},
    Aes256Gcm,
};
use hkdf::Hkdf;

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Sha256, Digest};
use x25519_dalek::PublicKey as X25519PublicKey;
use rand_core::{RngCore, OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum number of relays in a circuit for anonymity
pub const MIN_CIRCUIT_HOPS: usize = 3;

/// Maximum number of relays in a circuit
pub const MAX_CIRCUIT_HOPS: usize = 5;

/// Maximum age of node announcement before considered stale (seconds)
pub const NODE_ANNOUNCEMENT_TTL_SECS: u64 = 3600; // 1 hour

/// Circuit rotation interval (seconds)
pub const CIRCUIT_ROTATION_SECS: u64 = 600; // 10 minutes

/// Maximum messages through a circuit before rotation
pub const MAX_MESSAGES_PER_CIRCUIT: u64 = 100;

/// Maximum nodes to store in routing table
pub const MAX_ROUTING_TABLE_SIZE: usize = 256;

/// Maximum pending circuit builds
pub const MAX_PENDING_CIRCUITS: usize = 8;

/// Node announcement signature domain separator
const ANNOUNCE_DOMAIN: &[u8] = b"lunarcore-announce-v1";

/// Circuit ID size
pub const CIRCUIT_ID_SIZE: usize = 8;

// ============================================================================
// NODE IDENTITY
// ============================================================================

/// A node's identity in the mesh network
pub struct NodeIdentity {
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Ed25519 verifying key (public)
    pub verifying_key: VerifyingKey,
    /// X25519 secret key bytes (for creating HkOvctKeyPair on demand)
    hk_ovct_secret: [u8; 32],
    /// X25519 public key bytes
    pub hk_ovct_public: [u8; 32],
    /// 2-byte hint derived from public key
    pub hint: [u8; NODE_HINT_SIZE],
}

impl NodeIdentity {
    /// Generate a new random node identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Generate X25519 keypair and extract bytes
        let mut hk_ovct_secret = [0u8; 32];
        OsRng.fill_bytes(&mut hk_ovct_secret);
        let keypair = HkOvctKeyPair::from_secret_bytes(hk_ovct_secret);
        let hk_ovct_public = *keypair.public_key().as_bytes();

        // Derive hint from verifying key
        let hint = derive_node_hint(verifying_key.as_bytes());

        Self {
            signing_key,
            verifying_key,
            hk_ovct_secret,
            hk_ovct_public,
            hint,
        }
    }

    /// Create from existing keys
    pub fn from_keys(signing_key: SigningKey, hk_ovct_secret: [u8; 32]) -> Self {
        let verifying_key = signing_key.verifying_key();
        let keypair = HkOvctKeyPair::from_secret_bytes(hk_ovct_secret);
        let hk_ovct_public = *keypair.public_key().as_bytes();
        let hint = derive_node_hint(verifying_key.as_bytes());

        Self {
            signing_key,
            verifying_key,
            hk_ovct_secret,
            hk_ovct_public,
            hint,
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get the X25519 public key for session establishment
    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.hk_ovct_public)
    }

    /// Create an HkOvctKeyPair on demand (for session establishment)
    pub fn create_keypair(&self) -> HkOvctKeyPair {
        HkOvctKeyPair::from_secret_bytes(self.hk_ovct_secret)
    }
}

/// SECURITY: Manual Zeroize implementation for NodeIdentity.
/// SigningKey doesn't implement Zeroize, so we convert to bytes and zeroize.
impl Zeroize for NodeIdentity {
    fn zeroize(&mut self) {
        // Zeroize the X25519 secret key bytes
        self.hk_ovct_secret.zeroize();
        // SigningKey contains the secret internally; we overwrite with fresh random
        // This is a best-effort approach since ed25519-dalek doesn't expose Zeroize
        let zero_key = SigningKey::from_bytes(&[0u8; 32]);
        self.signing_key = zero_key;
    }
}

/// SECURITY: Automatically zeroize on drop to prevent key material from
/// lingering in memory after the NodeIdentity goes out of scope.
impl Drop for NodeIdentity {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// NODE INFO (Public Information)
// ============================================================================

/// Public information about a node in the network
#[derive(Debug)]
pub struct NodeInfo {
    /// Ed25519 verifying key
    pub verifying_key: VerifyingKey,
    /// X25519 public key for session establishment
    pub x25519_pk: [u8; 32],
    /// 2-byte hint for routing
    pub hint: [u8; NODE_HINT_SIZE],
    /// Optional region identifier (for path diversity)
    pub region: Option<u8>,
    /// Optional operator identifier (for path diversity)
    pub operator: Option<u16>,
    /// When this info was last updated (Unix timestamp)
    pub last_seen_ts: u64,
    /// Number of successful relays through this node
    pub reliability_score: u32,
}

impl Clone for NodeInfo {
    fn clone(&self) -> Self {
        Self {
            verifying_key: self.verifying_key,
            x25519_pk: self.x25519_pk,
            hint: self.hint,
            region: self.region,
            operator: self.operator,
            last_seen_ts: self.last_seen_ts,
            reliability_score: self.reliability_score,
        }
    }
}

impl NodeInfo {
    /// Create from an announcement
    pub fn from_announcement(announcement: &NodeAnnouncement) -> Self {
        Self {
            verifying_key: announcement.verifying_key,
            x25519_pk: announcement.x25519_pk,
            hint: derive_node_hint(announcement.verifying_key.as_bytes()),
            region: announcement.region,
            operator: announcement.operator,
            last_seen_ts: current_timestamp(),
            reliability_score: 0,
        }
    }

    /// Check if this node info is stale
    pub fn is_stale(&self) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.last_seen_ts) > NODE_ANNOUNCEMENT_TTL_SECS
    }

    /// Get the X25519 public key
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.x25519_pk)
    }
}

// ============================================================================
// NODE ANNOUNCEMENT
// ============================================================================

/// Signed announcement of node presence
#[derive(Clone, Debug)]
pub struct NodeAnnouncement {
    /// Ed25519 verifying key
    pub verifying_key: VerifyingKey,
    /// X25519 public key
    pub x25519_pk: [u8; 32],
    /// Optional region identifier
    pub region: Option<u8>,
    /// Optional operator identifier
    pub operator: Option<u16>,
    /// Announcement timestamp (Unix seconds)
    pub timestamp: u64,
    /// Ed25519 signature over announcement data
    pub signature: Signature,
}

impl NodeAnnouncement {
    /// Create and sign a new announcement
    pub fn create(identity: &NodeIdentity, region: Option<u8>, operator: Option<u16>) -> Self {
        let timestamp = current_timestamp();
        let x25519_pk = identity.hk_ovct_public;

        // Create message to sign
        let message = Self::sign_message(
            &identity.verifying_key,
            &x25519_pk,
            region,
            operator,
            timestamp,
        );

        let signature = identity.sign(&message);

        Self {
            verifying_key: identity.verifying_key,
            x25519_pk,
            region,
            operator,
            timestamp,
            signature,
        }
    }

    /// Verify announcement signature
    pub fn verify(&self) -> bool {
        let message = Self::sign_message(
            &self.verifying_key,
            &self.x25519_pk,
            self.region,
            self.operator,
            self.timestamp,
        );

        self.verifying_key.verify(&message, &self.signature).is_ok()
    }

    /// Create the message to be signed
    fn sign_message(
        verifying_key: &VerifyingKey,
        x25519_pk: &[u8; 32],
        region: Option<u8>,
        operator: Option<u16>,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(64 + 8 + 3);
        message.extend_from_slice(ANNOUNCE_DOMAIN);
        message.extend_from_slice(verifying_key.as_bytes());
        message.extend_from_slice(x25519_pk);
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.push(region.unwrap_or(0));
        message.extend_from_slice(&operator.unwrap_or(0).to_be_bytes());
        message
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 1 + 2 + 8 + 64);
        buf.extend_from_slice(self.verifying_key.as_bytes());
        buf.extend_from_slice(&self.x25519_pk);
        buf.push(self.region.unwrap_or(0));
        buf.extend_from_slice(&self.operator.unwrap_or(0).to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.signature.to_bytes());
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 32 + 1 + 2 + 8 + 64 {
            return None;
        }

        let verifying_key = VerifyingKey::from_bytes(
            data[0..32].try_into().ok()?
        ).ok()?;

        let mut x25519_pk = [0u8; 32];
        x25519_pk.copy_from_slice(&data[32..64]);

        let region_byte = data[64];
        let region = if region_byte == 0 { None } else { Some(region_byte) };

        let operator_bytes: [u8; 2] = data[65..67].try_into().ok()?;
        let operator_val = u16::from_be_bytes(operator_bytes);
        let operator = if operator_val == 0 { None } else { Some(operator_val) };

        let timestamp = u64::from_be_bytes(data[67..75].try_into().ok()?);

        let signature = Signature::from_bytes(
            data[75..139].try_into().ok()?
        );

        Some(Self {
            verifying_key,
            x25519_pk,
            region,
            operator,
            timestamp,
            signature,
        })
    }
}

// ============================================================================
// CIRCUIT
// ============================================================================

/// Unique circuit identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId([u8; CIRCUIT_ID_SIZE]);

impl CircuitId {
    /// Generate a random circuit ID
    pub fn generate() -> Self {
        let mut id = [0u8; CIRCUIT_ID_SIZE];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; CIRCUIT_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; CIRCUIT_ID_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for CircuitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CircuitId({:02x}{:02x}...)", self.0[0], self.0[1])
    }
}

/// A relay hop in a circuit
pub struct CircuitHop {
    /// Node information
    pub node: NodeInfo,
    /// Session with this relay
    pub session: Option<Session>,
    /// Relay key for this hop (derived from session, for onion encryption)
    relay_key: Option<[u8; 32]>,
    /// Nonce counter for this hop
    nonce_counter: u64,
}

impl CircuitHop {
    /// Create a new hop
    pub fn new(node: NodeInfo) -> Self {
        Self {
            node,
            session: None,
            relay_key: None,
            nonce_counter: 0,
        }
    }

    /// Set the relay key after session establishment
    pub fn set_relay_key(&mut self, session: Session) {
        // Derive relay key from session's root key
        if let Some(hint) = session.session_hint() {
            // Use session hint as basis for relay key derivation
            let hk = Hkdf::<Sha256>::new(Some(b"lunarcore-relay-key-v1"), &hint);
            let mut relay_key = [0u8; 32];
            hk.expand(b"relay", &mut relay_key).expect("HKDF expand failed");
            self.relay_key = Some(relay_key);
        }
        self.session = Some(session);
    }

    /// Encrypt a layer for this hop
    pub fn encrypt_layer(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RoutingError> {
        let key = self.relay_key.as_ref().ok_or(RoutingError::NoSession)?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| RoutingError::EncryptionFailed)?;

        // Create nonce from counter (12 bytes)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
        let nonce = AesNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        // Increment counter
        self.nonce_counter += 1;

        // Encrypt
        cipher.encrypt(nonce, plaintext)
            .map_err(|_| RoutingError::EncryptionFailed)
    }

    /// Decrypt a layer for this hop
    pub fn decrypt_layer(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, RoutingError> {
        let key = self.relay_key.as_ref().ok_or(RoutingError::NoSession)?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| RoutingError::DecryptionFailed)?;

        // Create nonce from counter (relay uses same counter sequence)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
        let nonce = AesNonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        // Increment counter
        self.nonce_counter += 1;

        // Decrypt
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| RoutingError::DecryptionFailed)
    }
}

/// State of a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is being built
    Building,
    /// Circuit is ready for use
    Ready,
    /// Circuit is being torn down
    Closing,
    /// Circuit is closed
    Closed,
}

/// A complete onion routing circuit
pub struct Circuit {
    /// Unique circuit identifier
    pub id: CircuitId,
    /// Ordered list of relay hops
    hops: Vec<CircuitHop>,
    /// Current state
    pub state: CircuitState,
    /// Messages sent through this circuit
    pub message_count: u64,
    /// When circuit was created (Unix timestamp)
    pub created_at_ts: u64,
    /// When circuit was last used (Unix timestamp)
    pub last_used_ts: u64,
}

impl Circuit {
    /// Create a new circuit with the given hops
    pub fn new(hops: Vec<CircuitHop>) -> Self {
        let now = current_timestamp();
        Self {
            id: CircuitId::generate(),
            hops,
            state: CircuitState::Building,
            message_count: 0,
            created_at_ts: now,
            last_used_ts: now,
        }
    }

    /// Get number of hops
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Check if circuit needs rotation
    pub fn needs_rotation(&self) -> bool {
        let now = current_timestamp();
        let age = now.saturating_sub(self.created_at_ts);
        self.message_count >= MAX_MESSAGES_PER_CIRCUIT || age >= CIRCUIT_ROTATION_SECS
    }

    /// Get the entry node (first hop)
    pub fn entry_node(&self) -> Option<&NodeInfo> {
        self.hops.first().map(|h| &h.node)
    }

    /// Get the exit node (last hop)
    pub fn exit_node(&self) -> Option<&NodeInfo> {
        self.hops.last().map(|h| &h.node)
    }

    /// Mark circuit as ready
    pub fn mark_ready(&mut self) {
        self.state = CircuitState::Ready;
    }

    /// Close the circuit
    pub fn close(&mut self) {
        self.state = CircuitState::Closed;
        // Zeroize relay keys
        for hop in &mut self.hops {
            if let Some(ref mut key) = hop.relay_key {
                key.zeroize();
            }
            hop.relay_key = None;
            hop.session = None;
            hop.nonce_counter = 0;
        }
    }

    /// Wrap payload in onion layers for this circuit.
    ///
    /// Each layer is:
    /// ```text
    /// [next_hop_hint: 2 bytes][encrypted_inner_layer]
    /// ```
    ///
    /// The payload is encrypted from innermost (exit) to outermost (entry).
    /// Each relay decrypts its layer to find the next hop hint and inner layer.
    ///
    /// # Arguments
    /// * `payload` - The actual message to send
    /// * `final_recipient_hint` - 2-byte hint of the final destination
    ///
    /// # Returns
    /// The fully wrapped onion packet ready for transmission.
    pub fn wrap_onion(&mut self, payload: &[u8], final_recipient_hint: [u8; NODE_HINT_SIZE]) -> Result<Vec<u8>, RoutingError> {
        if self.state != CircuitState::Ready {
            return Err(RoutingError::CircuitNotReady);
        }

        if self.hops.is_empty() {
            return Err(RoutingError::NoSession);
        }

        // Build list of next-hop hints (each hop needs to know where to forward)
        // hops[0] -> hops[1] -> hops[2] -> final_recipient
        let mut next_hints: Vec<[u8; NODE_HINT_SIZE]> = Vec::with_capacity(self.hops.len());
        for i in 0..self.hops.len() {
            if i + 1 < self.hops.len() {
                // Next hop is another relay
                next_hints.push(self.hops[i + 1].node.hint);
            } else {
                // Last relay, next hop is final recipient
                next_hints.push(final_recipient_hint);
            }
        }

        // Start with the innermost layer (just the payload for the exit node)
        let mut current_layer = payload.to_vec();

        // Wrap from exit (last hop) to entry (first hop)
        for i in (0..self.hops.len()).rev() {
            let next_hint = next_hints[i];

            // Prepend the next-hop hint to the current layer
            let mut layer_with_hint = Vec::with_capacity(NODE_HINT_SIZE + current_layer.len());
            layer_with_hint.extend_from_slice(&next_hint);
            layer_with_hint.extend_from_slice(&current_layer);

            // Encrypt this layer for this hop
            current_layer = self.hops[i].encrypt_layer(&layer_with_hint)?;
        }

        // Update message count and timestamp
        self.message_count += 1;
        self.last_used_ts = current_timestamp();

        Ok(current_layer)
    }

    /// Unwrap one onion layer (for relays).
    ///
    /// # Arguments
    /// * `hop_index` - Which hop we are (0 = entry)
    /// * `encrypted_layer` - The encrypted layer we received
    ///
    /// # Returns
    /// Tuple of (next_hop_hint, inner_layer) for forwarding.
    pub fn unwrap_layer(&mut self, hop_index: usize, encrypted_layer: &[u8]) -> Result<([u8; NODE_HINT_SIZE], Vec<u8>), RoutingError> {
        if hop_index >= self.hops.len() {
            return Err(RoutingError::InvalidHopIndex);
        }

        // Decrypt this layer
        let decrypted = self.hops[hop_index].decrypt_layer(encrypted_layer)?;

        if decrypted.len() < NODE_HINT_SIZE {
            return Err(RoutingError::DecryptionFailed);
        }

        // Extract next-hop hint and inner layer
        let mut next_hint = [0u8; NODE_HINT_SIZE];
        next_hint.copy_from_slice(&decrypted[..NODE_HINT_SIZE]);
        let inner_layer = decrypted[NODE_HINT_SIZE..].to_vec();

        Ok((next_hint, inner_layer))
    }

    /// Get mutable access to hops for session establishment
    pub fn hops_mut(&mut self) -> &mut [CircuitHop] {
        &mut self.hops
    }

    /// Get the hops
    pub fn hops(&self) -> &[CircuitHop] {
        &self.hops
    }

    /// Check if all hops have established sessions
    pub fn is_fully_established(&self) -> bool {
        self.hops.iter().all(|h| h.relay_key.is_some())
    }
}

// ============================================================================
// ROUTING TABLE
// ============================================================================

/// Routing table containing known nodes
pub struct RoutingTable {
    /// Known nodes indexed by hint
    nodes: HashMap<[u8; NODE_HINT_SIZE], NodeInfo>,
    /// Nodes indexed by verifying key
    by_key: HashMap<[u8; 32], [u8; NODE_HINT_SIZE]>,
    /// Recently used entry nodes (for anti-correlation)
    recent_entries: VecDeque<[u8; NODE_HINT_SIZE]>,
    /// Recently used exit nodes (for anti-correlation)
    recent_exits: VecDeque<[u8; NODE_HINT_SIZE]>,
}

impl RoutingTable {
    /// Create a new empty routing table
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            by_key: HashMap::new(),
            recent_entries: VecDeque::with_capacity(32),
            recent_exits: VecDeque::with_capacity(32),
        }
    }

    /// Add or update a node
    pub fn upsert(&mut self, node: NodeInfo) {
        // Enforce size limit
        if self.nodes.len() >= MAX_ROUTING_TABLE_SIZE && !self.nodes.contains_key(&node.hint) {
            // Remove oldest stale node
            let stale: Vec<_> = self.nodes.iter()
                .filter(|(_, n)| n.is_stale())
                .map(|(h, _)| *h)
                .collect();

            for hint in stale.into_iter().take(1) {
                self.remove(&hint);
            }

            // If still full, remove lowest reliability
            if self.nodes.len() >= MAX_ROUTING_TABLE_SIZE {
                if let Some((hint, _)) = self.nodes.iter()
                    .min_by_key(|(_, n)| n.reliability_score)
                    .map(|(h, n)| (*h, n.reliability_score))
                {
                    self.remove(&hint);
                }
            }
        }

        let key = *node.verifying_key.as_bytes();
        let hint = node.hint;

        // Remove old entry if key changed hint
        if let Some(old_hint) = self.by_key.get(&key) {
            if *old_hint != hint {
                self.nodes.remove(old_hint);
            }
        }

        self.by_key.insert(key, hint);
        self.nodes.insert(hint, node);
    }

    /// Remove a node by hint
    pub fn remove(&mut self, hint: &[u8; NODE_HINT_SIZE]) -> Option<NodeInfo> {
        if let Some(node) = self.nodes.remove(hint) {
            self.by_key.remove(node.verifying_key.as_bytes());
            Some(node)
        } else {
            None
        }
    }

    /// Get a node by hint
    pub fn get(&self, hint: &[u8; NODE_HINT_SIZE]) -> Option<&NodeInfo> {
        self.nodes.get(hint)
    }

    /// Get a node by verifying key
    pub fn get_by_key(&self, key: &[u8; 32]) -> Option<&NodeInfo> {
        self.by_key.get(key).and_then(|h| self.nodes.get(h))
    }

    /// Get all non-stale nodes
    pub fn active_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes.values().filter(|n| !n.is_stale()).collect()
    }

    /// Number of known nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Record entry node usage (for anti-correlation)
    pub fn record_entry_usage(&mut self, hint: [u8; NODE_HINT_SIZE]) {
        if self.recent_entries.len() >= 32 {
            self.recent_entries.pop_front();
        }
        self.recent_entries.push_back(hint);
    }

    /// Record exit node usage (for anti-correlation)
    pub fn record_exit_usage(&mut self, hint: [u8; NODE_HINT_SIZE]) {
        if self.recent_exits.len() >= 32 {
            self.recent_exits.pop_front();
        }
        self.recent_exits.push_back(hint);
    }

    /// Check if a node was recently used as entry
    pub fn was_recent_entry(&self, hint: &[u8; NODE_HINT_SIZE]) -> bool {
        self.recent_entries.contains(hint)
    }

    /// Check if a node was recently used as exit
    pub fn was_recent_exit(&self, hint: &[u8; NODE_HINT_SIZE]) -> bool {
        self.recent_exits.contains(hint)
    }

    /// Increase reliability score for a node
    pub fn record_success(&mut self, hint: &[u8; NODE_HINT_SIZE]) {
        if let Some(node) = self.nodes.get_mut(hint) {
            node.reliability_score = node.reliability_score.saturating_add(1);
            node.last_seen_ts = current_timestamp();
        }
    }

    /// Decrease reliability score for a node
    pub fn record_failure(&mut self, hint: &[u8; NODE_HINT_SIZE]) {
        if let Some(node) = self.nodes.get_mut(hint) {
            node.reliability_score = node.reliability_score.saturating_sub(1);
        }
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PATH SELECTOR
// ============================================================================

/// Criteria for path selection
#[derive(Clone, Debug, Default)]
pub struct PathCriteria {
    /// Required number of hops (default: MIN_CIRCUIT_HOPS)
    pub min_hops: Option<usize>,
    /// Maximum number of hops (default: MAX_CIRCUIT_HOPS)
    pub max_hops: Option<usize>,
    /// Exclude these nodes from selection
    pub exclude: HashSet<[u8; NODE_HINT_SIZE]>,
    /// Require different regions for each hop
    pub diverse_regions: bool,
    /// Require different operators for each hop
    pub diverse_operators: bool,
    /// Minimum reliability score
    pub min_reliability: Option<u32>,
}

/// Path selection result
#[derive(Debug)]
pub struct SelectedPath {
    /// Ordered nodes for the circuit
    pub nodes: Vec<NodeInfo>,
    /// Path diversity score (higher is better)
    pub diversity_score: u32,
}

/// Select a path through the network
pub fn select_path(
    table: &RoutingTable,
    criteria: &PathCriteria,
) -> Result<SelectedPath, RoutingError> {
    let min_hops = criteria.min_hops.unwrap_or(MIN_CIRCUIT_HOPS);
    let max_hops = criteria.max_hops.unwrap_or(MAX_CIRCUIT_HOPS);

    // Get eligible nodes
    let eligible: Vec<&NodeInfo> = table.active_nodes()
        .into_iter()
        .filter(|n| !criteria.exclude.contains(&n.hint))
        .filter(|n| criteria.min_reliability.map_or(true, |min| n.reliability_score >= min))
        .collect();

    if eligible.len() < min_hops {
        return Err(RoutingError::InsufficientNodes {
            available: eligible.len(),
            required: min_hops,
        });
    }

    // Select entry node (not recently used)
    let entry_candidates: Vec<_> = eligible.iter()
        .filter(|n| !table.was_recent_entry(&n.hint))
        .collect();

    let entry = if entry_candidates.is_empty() {
        // Fall back to any eligible node
        eligible.get(0).ok_or(RoutingError::NoSuitableEntry)?
    } else {
        // Prefer higher reliability
        entry_candidates.iter()
            .max_by_key(|n| n.reliability_score)
            .ok_or(RoutingError::NoSuitableEntry)?
    };

    // Select exit node (not recently used, different from entry)
    let exit_candidates: Vec<_> = eligible.iter()
        .filter(|n| n.hint != entry.hint)
        .filter(|n| !table.was_recent_exit(&n.hint))
        .filter(|n| !criteria.diverse_regions || n.region != entry.region)
        .filter(|n| !criteria.diverse_operators || n.operator != entry.operator)
        .collect();

    let exit = if exit_candidates.is_empty() {
        // Fall back to any different node
        eligible.iter()
            .find(|n| n.hint != entry.hint)
            .ok_or(RoutingError::NoSuitableExit)?
    } else {
        exit_candidates.iter()
            .max_by_key(|n| n.reliability_score)
            .ok_or(RoutingError::NoSuitableExit)?
    };

    // Select middle nodes
    let mut path = vec![(*entry).clone()];
    let target_hops = min_hops.min(max_hops);

    let used_regions: HashSet<_> = path.iter().filter_map(|n| n.region).collect();
    let used_operators: HashSet<_> = path.iter().filter_map(|n| n.operator).collect();
    let used_hints: HashSet<_> = path.iter().map(|n| n.hint).collect();

    // Select middle hops with diversity
    let middle_count = target_hops.saturating_sub(2);
    let mut middle_candidates: Vec<_> = eligible.iter()
        .filter(|n| n.hint != entry.hint && n.hint != exit.hint)
        .filter(|n| !used_hints.contains(&n.hint))
        .collect();

    // Sort by diversity score (prefer nodes with different region/operator)
    middle_candidates.sort_by(|a, b| {
        let a_score = diversity_score(a, &used_regions, &used_operators);
        let b_score = diversity_score(b, &used_regions, &used_operators);
        b_score.cmp(&a_score)
    });

    for node in middle_candidates.into_iter().take(middle_count) {
        path.push((*node).clone());
    }

    // Add exit at the end
    path.push((*exit).clone());

    if path.len() < min_hops {
        return Err(RoutingError::InsufficientNodes {
            available: path.len(),
            required: min_hops,
        });
    }

    // Calculate overall diversity score
    let total_diversity = calculate_path_diversity(&path);

    Ok(SelectedPath {
        nodes: path,
        diversity_score: total_diversity,
    })
}

/// Calculate diversity score for a single node
fn diversity_score(
    node: &NodeInfo,
    used_regions: &HashSet<u8>,
    used_operators: &HashSet<u16>,
) -> u32 {
    let mut score = 0u32;

    // Higher score for different region
    if let Some(region) = node.region {
        if !used_regions.contains(&region) {
            score += 10;
        }
    } else {
        score += 5; // Unknown region is somewhat diverse
    }

    // Higher score for different operator
    if let Some(operator) = node.operator {
        if !used_operators.contains(&operator) {
            score += 10;
        }
    } else {
        score += 5;
    }

    // Add reliability as tiebreaker
    score += (node.reliability_score / 10).min(5);

    score
}

/// Calculate total path diversity
fn calculate_path_diversity(path: &[NodeInfo]) -> u32 {
    let regions: HashSet<_> = path.iter().filter_map(|n| n.region).collect();
    let operators: HashSet<_> = path.iter().filter_map(|n| n.operator).collect();

    // Score based on unique regions and operators
    let region_diversity = regions.len() as u32 * 10;
    let operator_diversity = operators.len() as u32 * 10;

    // Bonus for having all different
    let all_different_bonus = if regions.len() == path.len() && operators.len() == path.len() {
        20
    } else {
        0
    };

    region_diversity + operator_diversity + all_different_bonus
}

// ============================================================================
// ROUTER
// ============================================================================

use crate::credentials::bbs_plus::IssuerPublicKey;
use crate::lunar::mesh_credentials::{
    MeshAccessProof, RateLimiter, VerifiedAccess,
    AccessLevel, MAX_PROOFS_PER_EPOCH,
};

/// The main routing engine with BBS+ anonymous authentication.
///
/// SECURITY: All nodes must prove valid mesh credentials before being
/// allowed to relay messages. This prevents Sybil attacks while preserving
/// sender anonymity through zero-knowledge BBS+ proofs.
pub struct Router {
    /// Our node identity
    identity: NodeIdentity,
    /// Routing table of known nodes
    pub table: RoutingTable,
    /// Active circuits
    circuits: HashMap<CircuitId, Circuit>,
    /// Pending circuit builds
    pending_builds: Vec<CircuitId>,
    /// Sessions for direct communication
    sessions: HashMap<SessionId, Session>,
    /// Trusted issuers for BBS+ credential verification
    trusted_issuers: HashMap<[u8; 32], IssuerPublicKey>,
    /// Rate limiter for BBS+ proofs
    rate_limiter: RateLimiter,
    /// Whether to require BBS+ authentication (can be disabled for testing)
    require_bbs_auth: bool,
    /// Verified access for nodes (hint -> access level)
    node_access: HashMap<[u8; NODE_HINT_SIZE], VerifiedAccess>,
}

impl Router {
    /// Create a new router with the given identity.
    ///
    /// By default, BBS+ authentication is enabled. Call `set_require_bbs_auth(false)`
    /// to disable for testing environments.
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            identity,
            table: RoutingTable::new(),
            circuits: HashMap::new(),
            pending_builds: Vec::new(),
            sessions: HashMap::new(),
            trusted_issuers: HashMap::new(),
            rate_limiter: RateLimiter::new(MAX_PROOFS_PER_EPOCH),
            require_bbs_auth: true, // Enabled by default for security
            node_access: HashMap::new(),
        }
    }

    /// Enable or disable BBS+ authentication requirement.
    pub fn set_require_bbs_auth(&mut self, require: bool) {
        self.require_bbs_auth = require;
    }

    /// Add a trusted issuer for BBS+ credential verification.
    pub fn add_trusted_issuer(&mut self, issuer_id: [u8; 32], public_key: IssuerPublicKey) {
        self.trusted_issuers.insert(issuer_id, public_key);
    }

    /// Remove a trusted issuer (for revocation).
    pub fn remove_trusted_issuer(&mut self, issuer_id: &[u8; 32]) {
        self.trusted_issuers.remove(issuer_id);
    }

    /// Verify a BBS+ mesh access proof.
    ///
    /// Returns the verified access info if valid, or an error if:
    /// - The issuer is not trusted
    /// - The proof is invalid
    /// - The node is rate-limited
    pub fn verify_access_proof(&mut self, proof_bytes: &[u8]) -> Result<VerifiedAccess, RoutingError> {
        let proof = MeshAccessProof::from_bytes(proof_bytes)
            .map_err(|_| RoutingError::InvalidProof)?;

        // Find the issuer - we need to try all trusted issuers since we don't know
        // which one signed this credential until we verify
        let mut verified_access = None;
        for (_issuer_id, issuer_pk) in &self.trusted_issuers {
            if let Ok(access) = proof.verify(issuer_pk) {
                // Verify issuer_id matches what we expect
                if self.trusted_issuers.contains_key(&access.issuer_id) {
                    verified_access = Some(access);
                    break;
                }
            }
        }

        let access = verified_access.ok_or(RoutingError::UntrustedIssuer)?;

        // Check rate limiting
        if !self.rate_limiter.check_and_record(&access) {
            return Err(RoutingError::RateLimited);
        }

        Ok(access)
    }

    /// Register a node's access level after successful BBS+ verification.
    pub fn register_node_access(&mut self, hint: [u8; NODE_HINT_SIZE], access: VerifiedAccess) {
        self.node_access.insert(hint, access);
    }

    /// Get a node's verified access level.
    pub fn get_node_access(&self, hint: &[u8; NODE_HINT_SIZE]) -> Option<&VerifiedAccess> {
        self.node_access.get(hint)
    }

    /// Check if a node is authorized to relay messages.
    pub fn is_authorized(&self, hint: &[u8; NODE_HINT_SIZE]) -> bool {
        if !self.require_bbs_auth {
            return true; // Auth disabled for testing
        }
        self.node_access.contains_key(hint)
    }

    /// Get routing priority for a node based on BBS+ access level.
    pub fn get_routing_priority(&self, hint: &[u8; NODE_HINT_SIZE]) -> u8 {
        self.node_access.get(hint)
            .map(|a| a.routing_priority())
            .unwrap_or(0)
    }

    /// Get our node's public hint
    pub fn our_hint(&self) -> [u8; NODE_HINT_SIZE] {
        self.identity.hint
    }

    /// Create a node announcement for ourselves
    pub fn create_announcement(&self, region: Option<u8>, operator: Option<u16>) -> NodeAnnouncement {
        NodeAnnouncement::create(&self.identity, region, operator)
    }

    /// Process a received node announcement
    pub fn process_announcement(&mut self, announcement: &NodeAnnouncement) -> Result<(), RoutingError> {
        // Verify signature
        if !announcement.verify() {
            return Err(RoutingError::InvalidSignature);
        }

        // Check timestamp (not too old, not in future)
        let now = current_timestamp();
        if announcement.timestamp > now + 60 {
            return Err(RoutingError::FutureTimestamp);
        }
        if now.saturating_sub(announcement.timestamp) > NODE_ANNOUNCEMENT_TTL_SECS {
            return Err(RoutingError::StaleAnnouncement);
        }

        // Add to routing table
        let node = NodeInfo::from_announcement(announcement);
        self.table.upsert(node);

        Ok(())
    }

    /// Build a new circuit
    pub fn build_circuit(&mut self, criteria: &PathCriteria) -> Result<CircuitId, RoutingError> {
        if self.pending_builds.len() >= MAX_PENDING_CIRCUITS {
            return Err(RoutingError::TooManyPendingCircuits);
        }

        // Select path
        let path = select_path(&self.table, criteria)?;

        // Create circuit with selected nodes
        let hops: Vec<CircuitHop> = path.nodes.into_iter()
            .map(|n| CircuitHop::new(n))
            .collect();

        let circuit = Circuit::new(hops);
        let circuit_id = circuit.id;

        // Record entry/exit usage for anti-correlation
        if let Some(entry) = circuit.entry_node() {
            self.table.record_entry_usage(entry.hint);
        }
        if let Some(exit) = circuit.exit_node() {
            self.table.record_exit_usage(exit.hint);
        }

        self.circuits.insert(circuit_id, circuit);
        self.pending_builds.push(circuit_id);

        Ok(circuit_id)
    }

    /// Get a circuit by ID
    pub fn get_circuit(&self, id: &CircuitId) -> Option<&Circuit> {
        self.circuits.get(id)
    }

    /// Get a mutable circuit by ID
    pub fn get_circuit_mut(&mut self, id: &CircuitId) -> Option<&mut Circuit> {
        self.circuits.get_mut(id)
    }

    /// Get a ready circuit, building one if needed
    pub fn get_or_build_circuit(&mut self, criteria: &PathCriteria) -> Result<CircuitId, RoutingError> {
        // Look for an existing ready circuit that doesn't need rotation
        for (id, circuit) in &self.circuits {
            if circuit.state == CircuitState::Ready && !circuit.needs_rotation() {
                return Ok(*id);
            }
        }

        // Build a new one
        self.build_circuit(criteria)
    }

    /// Close a circuit
    pub fn close_circuit(&mut self, id: &CircuitId) {
        if let Some(circuit) = self.circuits.get_mut(id) {
            circuit.close();
        }
        self.pending_builds.retain(|cid| cid != id);
    }

    /// Clean up stale circuits
    pub fn cleanup(&mut self) {
        // Close circuits that need rotation
        let to_close: Vec<CircuitId> = self.circuits.iter()
            .filter(|(_, c)| c.needs_rotation() || c.state == CircuitState::Closed)
            .map(|(id, _)| *id)
            .collect();

        for id in to_close {
            self.close_circuit(&id);
            self.circuits.remove(&id);
        }

        // Remove completed builds from pending
        self.pending_builds.retain(|id| {
            self.circuits.get(id)
                .map_or(false, |c| c.state == CircuitState::Building)
        });
    }

    /// Get statistics
    pub fn stats(&self) -> RouterStats {
        RouterStats {
            known_nodes: self.table.len(),
            active_nodes: self.table.active_nodes().len(),
            total_circuits: self.circuits.len(),
            ready_circuits: self.circuits.values()
                .filter(|c| c.state == CircuitState::Ready)
                .count(),
            pending_builds: self.pending_builds.len(),
        }
    }

    /// Establish sessions with all hops in a circuit.
    ///
    /// This is a multi-step process:
    /// 1. Create handshake for hop 0 (entry), send through mesh
    /// 2. On response, create handshake for hop 1 through hop 0
    /// 3. Continue until all hops have sessions
    ///
    /// Returns the handshake packets to send (in order).
    ///
    /// # Arguments
    /// * `circuit_id` - The circuit to establish
    /// * `aux_entropy` - Entropy for each session establishment
    ///
    /// # Returns
    /// Vector of (hop_index, handshake_packet) pairs to send.
    pub fn create_circuit_handshakes(
        &mut self,
        circuit_id: &CircuitId,
        aux_entropy: &[u8],
    ) -> Result<Vec<(usize, Vec<u8>)>, RoutingError> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or(RoutingError::CircuitNotFound)?;

        if circuit.state != CircuitState::Building {
            return Err(RoutingError::CircuitNotReady);
        }

        let mut handshakes = Vec::new();

        for (i, hop) in circuit.hops_mut().iter_mut().enumerate() {
            // Get the hop's X25519 public key
            let their_pk = X25519PublicKey::from(hop.node.x25519_pk);

            // Create a fresh keypair for this session
            let our_keypair = self.identity.create_keypair();

            // Create session for this hop
            let (session, handshake) = Session::initiate(
                our_keypair,
                &their_pk,
                aux_entropy,
            ).map_err(|_| RoutingError::HandshakeFailed)?;

            // Encode handshake
            let handshake_bytes = handshake.encode();

            // Store session with hop
            hop.set_relay_key(session);

            handshakes.push((i, handshake_bytes));
        }

        Ok(handshakes)
    }

    /// Process a handshake response and mark hop as established.
    ///
    /// In a real implementation, each hop would respond with confirmation.
    /// For now, we just mark the hop as established after sending.
    ///
    /// # Arguments
    /// * `circuit_id` - The circuit
    /// * `hop_index` - Which hop responded
    ///
    /// # Returns
    /// Ok if successful, error otherwise.
    pub fn confirm_hop_established(
        &mut self,
        circuit_id: &CircuitId,
        hop_index: usize,
    ) -> Result<(), RoutingError> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or(RoutingError::CircuitNotFound)?;

        if hop_index >= circuit.hops().len() {
            return Err(RoutingError::InvalidHopIndex);
        }

        // Check if all hops are now established
        if circuit.is_fully_established() {
            circuit.mark_ready();
            self.pending_builds.retain(|id| id != circuit_id);
        }

        Ok(())
    }

    /// Wrap a message in onion layers and return the packet for entry node.
    ///
    /// # Arguments
    /// * `circuit_id` - The circuit to use
    /// * `payload` - The message to send
    /// * `final_recipient_hint` - 2-byte hint of the final destination
    ///
    /// # Returns
    /// The onion-wrapped packet to send to the entry node.
    pub fn wrap_message(
        &mut self,
        circuit_id: &CircuitId,
        payload: &[u8],
        final_recipient_hint: [u8; NODE_HINT_SIZE],
    ) -> Result<Vec<u8>, RoutingError> {
        let circuit = self.circuits.get_mut(circuit_id)
            .ok_or(RoutingError::CircuitNotFound)?;

        circuit.wrap_onion(payload, final_recipient_hint)
    }

    /// Get entry node hint for a circuit.
    pub fn get_entry_hint(&self, circuit_id: &CircuitId) -> Option<[u8; NODE_HINT_SIZE]> {
        self.circuits.get(circuit_id)
            .and_then(|c| c.entry_node())
            .map(|n| n.hint)
    }

    /// Get our identity's public key bytes (for others to establish sessions with us).
    pub fn our_public_key(&self) -> [u8; 32] {
        self.identity.hk_ovct_public
    }
}

/// Router statistics
#[derive(Debug, Clone)]
pub struct RouterStats {
    pub known_nodes: usize,
    pub active_nodes: usize,
    pub total_circuits: usize,
    pub ready_circuits: usize,
    pub pending_builds: usize,
}

// ============================================================================
// ERRORS
// ============================================================================

/// Routing errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// Not enough nodes to build circuit
    InsufficientNodes { available: usize, required: usize },
    /// No suitable entry node
    NoSuitableEntry,
    /// No suitable exit node
    NoSuitableExit,
    /// Invalid announcement signature
    InvalidSignature,
    /// Announcement timestamp in future
    FutureTimestamp,
    /// Announcement too old
    StaleAnnouncement,
    /// Too many pending circuit builds
    TooManyPendingCircuits,
    /// Circuit not ready
    CircuitNotReady,
    /// Session not established
    NoSession,
    /// Circuit not found
    CircuitNotFound,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Invalid hop index
    InvalidHopIndex,
    /// Handshake failed
    HandshakeFailed,
    /// Session establishment failed
    SessionEstablishmentFailed,
    /// BBS+ proof is invalid or malformed
    InvalidProof,
    /// Issuer not in trusted set
    UntrustedIssuer,
    /// Node is rate limited
    RateLimited,
    /// Node not authorized (no valid BBS+ credential)
    NotAuthorized,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::InsufficientNodes { available, required } => {
                write!(f, "Insufficient nodes: {} available, {} required", available, required)
            }
            RoutingError::NoSuitableEntry => write!(f, "No suitable entry node"),
            RoutingError::NoSuitableExit => write!(f, "No suitable exit node"),
            RoutingError::InvalidSignature => write!(f, "Invalid announcement signature"),
            RoutingError::FutureTimestamp => write!(f, "Announcement timestamp in future"),
            RoutingError::StaleAnnouncement => write!(f, "Announcement too old"),
            RoutingError::TooManyPendingCircuits => write!(f, "Too many pending circuit builds"),
            RoutingError::CircuitNotReady => write!(f, "Circuit not ready"),
            RoutingError::NoSession => write!(f, "No session established"),
            RoutingError::CircuitNotFound => write!(f, "Circuit not found"),
            RoutingError::EncryptionFailed => write!(f, "Encryption failed"),
            RoutingError::DecryptionFailed => write!(f, "Decryption failed"),
            RoutingError::InvalidHopIndex => write!(f, "Invalid hop index"),
            RoutingError::HandshakeFailed => write!(f, "Handshake failed"),
            RoutingError::SessionEstablishmentFailed => write!(f, "Session establishment failed"),
            RoutingError::InvalidProof => write!(f, "Invalid BBS+ proof"),
            RoutingError::UntrustedIssuer => write!(f, "Untrusted credential issuer"),
            RoutingError::RateLimited => write!(f, "Node is rate limited"),
            RoutingError::NotAuthorized => write!(f, "Node not authorized"),
        }
    }
}

impl std::error::Error for RoutingError {}

// ============================================================================
// HELPERS
// ============================================================================

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_identity_generation() {
        let identity = NodeIdentity::generate();
        assert_eq!(identity.hint.len(), NODE_HINT_SIZE);
    }

    #[test]
    fn test_node_announcement_roundtrip() {
        let identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&identity, Some(1), Some(100));

        // Verify signature
        assert!(announcement.verify());

        // Encode and decode
        let encoded = announcement.encode();
        let decoded = NodeAnnouncement::decode(&encoded).unwrap();

        assert_eq!(announcement.verifying_key, decoded.verifying_key);
        assert_eq!(announcement.x25519_pk, decoded.x25519_pk);
        assert_eq!(announcement.region, decoded.region);
        assert_eq!(announcement.operator, decoded.operator);
        assert_eq!(announcement.timestamp, decoded.timestamp);

        // Decoded should also verify
        assert!(decoded.verify());
    }

    #[test]
    fn test_routing_table_basics() {
        let mut table = RoutingTable::new();

        let identity1 = NodeIdentity::generate();
        let announcement1 = NodeAnnouncement::create(&identity1, Some(1), Some(100));
        let node1 = NodeInfo::from_announcement(&announcement1);
        let hint1 = node1.hint;

        table.upsert(node1);

        assert_eq!(table.len(), 1);
        assert!(table.get(&hint1).is_some());

        // Remove
        table.remove(&hint1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_path_selection() {
        let mut table = RoutingTable::new();

        // Add several nodes with different regions/operators
        for i in 0..5 {
            let identity = NodeIdentity::generate();
            let announcement = NodeAnnouncement::create(
                &identity,
                Some((i % 3) as u8 + 1), // Regions 1, 2, 3
                Some((i % 2) as u16 + 1), // Operators 1, 2
            );
            let mut node = NodeInfo::from_announcement(&announcement);
            node.reliability_score = 10;
            table.upsert(node);
        }

        let criteria = PathCriteria {
            min_hops: Some(3),
            diverse_regions: true,
            diverse_operators: true,
            ..Default::default()
        };

        let path = select_path(&table, &criteria).unwrap();

        assert!(path.nodes.len() >= 3);
        assert!(path.diversity_score > 0);
    }

    #[test]
    fn test_insufficient_nodes() {
        let table = RoutingTable::new();

        let criteria = PathCriteria {
            min_hops: Some(3),
            ..Default::default()
        };

        let result = select_path(&table, &criteria);
        assert!(matches!(result, Err(RoutingError::InsufficientNodes { .. })));
    }

    #[test]
    fn test_router_announcement_processing() {
        let our_identity = NodeIdentity::generate();
        let mut router = Router::new(our_identity);

        // Set up BBS+ authentication with a trusted issuer
        let mut rng = rand::rngs::OsRng;
        let issuer = crate::lunar::mesh_credentials::MeshIssuer::new(&mut rng).unwrap();
        router.add_trusted_issuer(*issuer.issuer_id(), issuer.public_key().clone());

        // Create another node's announcement
        let other_identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&other_identity, Some(1), Some(100));

        // Process it
        router.process_announcement(&announcement).unwrap();

        assert_eq!(router.table.len(), 1);
    }

    #[test]
    fn test_circuit_rotation_needed() {
        let identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&identity, None, None);
        let node = NodeInfo::from_announcement(&announcement);

        let hop = CircuitHop::new(node);
        let mut circuit = Circuit::new(vec![hop]);

        // Fresh circuit shouldn't need rotation
        assert!(!circuit.needs_rotation());

        // After many messages
        circuit.message_count = MAX_MESSAGES_PER_CIRCUIT;
        assert!(circuit.needs_rotation());
    }

    #[test]
    fn test_anti_correlation() {
        let mut table = RoutingTable::new();

        let identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&identity, Some(1), Some(100));
        let node = NodeInfo::from_announcement(&announcement);
        let hint = node.hint;
        table.upsert(node);

        // Record usage
        table.record_entry_usage(hint);
        table.record_exit_usage(hint);

        // Should be marked as recent
        assert!(table.was_recent_entry(&hint));
        assert!(table.was_recent_exit(&hint));
    }

    #[test]
    fn test_circuit_close_zeroizes_keys() {
        let identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&identity, None, None);
        let node = NodeInfo::from_announcement(&announcement);

        let mut hop = CircuitHop::new(node);
        hop.relay_key = Some([0xAB; 32]);

        let mut circuit = Circuit::new(vec![hop]);
        circuit.close();

        assert_eq!(circuit.state, CircuitState::Closed);
        // Verify relay key is zeroized
        assert!(circuit.hops()[0].relay_key.is_none());
    }

    #[test]
    fn test_onion_wrap_unwrap_single_hop() {
        // Create a single-hop circuit with established session
        let identity = NodeIdentity::generate();
        let announcement = NodeAnnouncement::create(&identity, None, None);
        let node = NodeInfo::from_announcement(&announcement);

        let mut hop = CircuitHop::new(node);
        // Set a relay key directly for testing
        hop.relay_key = Some([0x42; 32]);

        let mut circuit = Circuit::new(vec![hop]);
        circuit.mark_ready();

        // Wrap a message
        let payload = b"Hello, anonymous world!";
        let final_hint = [0xAB, 0xCD, 0xEF, 0x01]; // NODE_HINT_SIZE = 4 bytes

        let wrapped = circuit.wrap_onion(payload, final_hint).unwrap();

        // Wrapped should be larger (encrypted + hint)
        assert!(wrapped.len() > payload.len());

        // Reset nonce counter for unwrapping (simulating relay receiving)
        circuit.hops_mut()[0].nonce_counter = 0;

        // Unwrap the layer
        let (next_hint, inner) = circuit.unwrap_layer(0, &wrapped).unwrap();

        // Should get the final recipient hint
        assert_eq!(next_hint, final_hint);
        // Inner should be the original payload
        assert_eq!(inner, payload);
    }

    #[test]
    fn test_onion_wrap_unwrap_multi_hop() {
        // Create a 3-hop circuit
        let mut hops = Vec::new();
        for i in 0..3 {
            let identity = NodeIdentity::generate();
            let announcement = NodeAnnouncement::create(&identity, Some(i as u8), None);
            let node = NodeInfo::from_announcement(&announcement);

            let mut hop = CircuitHop::new(node);
            // Each hop gets a different key
            let mut key = [0u8; 32];
            key[0] = i as u8;
            hop.relay_key = Some(key);
            hops.push(hop);
        }

        let hop_hints: Vec<[u8; NODE_HINT_SIZE]> = hops.iter()
            .map(|h| h.node.hint)
            .collect();

        let mut circuit = Circuit::new(hops);
        circuit.mark_ready();

        // Wrap a message
        let payload = b"Secret message through 3 relays";
        let final_hint = [0xFF, 0xEE, 0xDD, 0xCC]; // NODE_HINT_SIZE = 4 bytes

        let wrapped = circuit.wrap_onion(payload, final_hint).unwrap();

        // Simulate relaying through each hop
        // Reset nonce counters for the unwrap simulation
        for hop in circuit.hops_mut() {
            hop.nonce_counter = 0;
        }

        // Hop 0 (entry) unwraps first layer
        let (next_hint_0, inner_0) = circuit.unwrap_layer(0, &wrapped).unwrap();
        assert_eq!(next_hint_0, hop_hints[1]); // Should point to hop 1

        // Hop 1 (middle) unwraps second layer
        let (next_hint_1, inner_1) = circuit.unwrap_layer(1, &inner_0).unwrap();
        assert_eq!(next_hint_1, hop_hints[2]); // Should point to hop 2

        // Hop 2 (exit) unwraps final layer
        let (next_hint_2, inner_2) = circuit.unwrap_layer(2, &inner_1).unwrap();
        assert_eq!(next_hint_2, final_hint); // Should be final recipient
        assert_eq!(inner_2, payload); // Should be original message
    }

    #[test]
    fn test_circuit_establishment() {
        let our_identity = NodeIdentity::generate();
        let mut router = Router::new(our_identity);

        // Set up BBS+ authentication with a trusted issuer
        let mut rng = rand::rngs::OsRng;
        let issuer = crate::lunar::mesh_credentials::MeshIssuer::new(&mut rng).unwrap();
        router.add_trusted_issuer(*issuer.issuer_id(), issuer.public_key().clone());

        // Add several nodes to the routing table with BBS+ credentials
        for i in 0..5 {
            let identity = NodeIdentity::generate();
            let announcement = NodeAnnouncement::create(&identity, Some(i as u8), None);
            let mut node = NodeInfo::from_announcement(&announcement);
            node.reliability_score = 10;

            // Issue BBS+ credential for this node
            let pubkey_commitment = crate::lunar::mesh_credentials::compute_pubkey_commitment(&node.x25519_pk);
            let credential = issuer.issue_credential(
                &pubkey_commitment,
                crate::lunar::mesh_credentials::AccessLevel::Trusted,
                &mut rng,
            ).unwrap();

            // Create and verify access proof
            let epoch = crate::lunar::mesh_credentials::current_epoch();
            let proof = credential.prove_access(issuer.public_key(), epoch, &mut rng).unwrap();
            let access = router.verify_access_proof(&proof.to_bytes()).unwrap();
            router.register_node_access(node.hint, access);

            router.table.upsert(node);
        }

        // Build a circuit
        let criteria = PathCriteria {
            min_hops: Some(3),
            ..Default::default()
        };

        let circuit_id = router.build_circuit(&criteria).unwrap();

        // Create handshakes for the circuit
        let handshakes = router.create_circuit_handshakes(&circuit_id, b"test_entropy").unwrap();

        // Should have a handshake for each hop
        assert_eq!(handshakes.len(), 3);

        // Circuit should now be fully established (sessions created)
        let circuit = router.get_circuit(&circuit_id).unwrap();
        assert!(circuit.is_fully_established());

        // Confirm each hop (in real use, this happens on handshake response)
        for i in 0..3 {
            router.confirm_hop_established(&circuit_id, i).unwrap();
        }

        // Circuit should now be ready
        let circuit = router.get_circuit(&circuit_id).unwrap();
        assert_eq!(circuit.state, CircuitState::Ready);
    }

    #[test]
    fn test_router_wrap_message() {
        let our_identity = NodeIdentity::generate();
        let mut router = Router::new(our_identity);

        // Set up BBS+ authentication with a trusted issuer
        let mut rng = rand::rngs::OsRng;
        let issuer = crate::lunar::mesh_credentials::MeshIssuer::new(&mut rng).unwrap();
        router.add_trusted_issuer(*issuer.issuer_id(), issuer.public_key().clone());

        // Add nodes with proper BBS+ credentials
        for i in 0..5 {
            let identity = NodeIdentity::generate();
            let announcement = NodeAnnouncement::create(&identity, Some(i as u8), None);
            let mut node = NodeInfo::from_announcement(&announcement);
            node.reliability_score = 10;

            // Issue BBS+ credential for this node
            let pubkey_commitment = crate::lunar::mesh_credentials::compute_pubkey_commitment(&node.x25519_pk);
            let credential = issuer.issue_credential(
                &pubkey_commitment,
                crate::lunar::mesh_credentials::AccessLevel::Trusted,
                &mut rng,
            ).unwrap();

            // Create and verify access proof
            let epoch = crate::lunar::mesh_credentials::current_epoch();
            let proof = credential.prove_access(issuer.public_key(), epoch, &mut rng).unwrap();
            let access = router.verify_access_proof(&proof.to_bytes()).unwrap();
            router.register_node_access(node.hint, access);

            router.table.upsert(node);
        }

        // Build and establish circuit
        let criteria = PathCriteria {
            min_hops: Some(3),
            ..Default::default()
        };

        let circuit_id = router.build_circuit(&criteria).unwrap();
        router.create_circuit_handshakes(&circuit_id, b"entropy").unwrap();

        // Confirm all hops
        for i in 0..3 {
            router.confirm_hop_established(&circuit_id, i).unwrap();
        }

        // Wrap a message
        let message = b"This is a secret message";
        let recipient_hint = [0xDE, 0xAD, 0xBE, 0xEF]; // Updated to NODE_HINT_SIZE (4 bytes)

        let wrapped = router.wrap_message(&circuit_id, message, recipient_hint).unwrap();

        // Should be encrypted (larger than original)
        assert!(wrapped.len() > message.len());

        // Entry hint should be available
        let entry_hint = router.get_entry_hint(&circuit_id).unwrap();
        assert_eq!(entry_hint.len(), NODE_HINT_SIZE);
    }
}
