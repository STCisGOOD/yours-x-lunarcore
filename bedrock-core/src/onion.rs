//! Multi-hop onion encryption for anonymous mesh routing.
//!
//! Each relay knows only the previous and next hop. Payload is encrypted
//! in layers — each relay peels one layer and forwards to the next.
//! Only the final recipient can read the plaintext.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{CryptoRng, Rng, RngCore};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Maximum number of hops in an onion route
pub const MAX_HOPS: usize = 5;

/// Minimum hops for meaningful anonymity.
/// Increased from 2 to 3 to match LunarRouter circuits.
/// With 2 hops, an adversary controlling 2 adjacent nodes can break anonymity.
/// With 3 hops, the adversary must compromise entry AND exit simultaneously.
pub const MIN_HOPS: usize = 3;

/// Size of node ID
pub const NODE_ID_SIZE: usize = 8;

/// Onion packet header size per layer
/// node_id(8) + ephemeral_pubkey(32) + nonce(12) + tag(16) = 68 bytes
pub const LAYER_OVERHEAD: usize = NODE_ID_SIZE + 32 + 12 + 16;

/// Maximum payload size (after all layers stripped)
/// Note: Increased from 200 to 512 to accommodate Double Ratchet encryption
/// overhead (~260 bytes for a simple message). LoRa will fragment if needed.
pub const MAX_PAYLOAD: usize = 512;

/// A node in the mesh network
#[derive(Clone, Debug)]
pub struct MeshNode {
    pub id: [u8; NODE_ID_SIZE],
    pub public_key: PublicKey,
}

impl MeshNode {
    pub fn new(id: [u8; NODE_ID_SIZE], public_key: PublicKey) -> Self {
        Self { id, public_key }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < NODE_ID_SIZE + 32 {
            return None;
        }

        let mut id = [0u8; NODE_ID_SIZE];
        id.copy_from_slice(&data[..NODE_ID_SIZE]);

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&data[NODE_ID_SIZE..NODE_ID_SIZE + 32]);
        let public_key = PublicKey::from(pk_bytes);

        Some(Self { id, public_key })
    }

    pub fn to_bytes(&self) -> [u8; NODE_ID_SIZE + 32] {
        let mut result = [0u8; NODE_ID_SIZE + 32];
        result[..NODE_ID_SIZE].copy_from_slice(&self.id);
        result[NODE_ID_SIZE..].copy_from_slice(self.public_key.as_bytes());
        result
    }
}

/// An encrypted onion packet
#[derive(Clone, Debug)]
pub struct OnionPacket {
    /// Number of layers remaining
    pub layers: u8,
    /// The encrypted payload (includes routing info for each layer)
    pub data: Vec<u8>,
}

impl OnionPacket {
    /// Create an anonymous onion packet with ENFORCED minimum relay hops.
    ///
    /// This is the primary API - it REQUIRES at least MIN_HOPS for anonymity.
    /// Use `create_direct()` only for non-sensitive, non-anonymous messages.
    ///
    /// @param route List of relay nodes (must have at least MIN_HOPS-1 relays)
    /// @param destination Final recipient
    /// @param payload The actual message
    pub fn create(
        route: &[MeshNode],
        destination: &MeshNode,
        payload: &[u8],
    ) -> Result<Self, &'static str> {
        // ENFORCE minimum hops for anonymity - this is not optional
        if route.len() < MIN_HOPS - 1 {
            return Err("Route too short - anonymity requires at least 2 hops");
        }
        if route.len() > MAX_HOPS - 1 {
            return Err("Route too long");
        }
        if payload.len() > MAX_PAYLOAD {
            return Err("Payload too large");
        }

        Self::create_internal(route, destination, payload)
    }

    /// Create a direct (non-anonymous) packet to destination.
    ///
    /// WARNING: This provides NO anonymity. The destination knows your identity.
    /// Only use for:
    /// - Initial contact establishment where anonymity isn't needed
    /// - Local mesh announcements
    /// - When you WANT the recipient to know who you are
    ///
    /// For anonymous messaging, ALWAYS use `create()` instead.
    pub fn create_direct(
        destination: &MeshNode,
        payload: &[u8],
    ) -> Result<Self, &'static str> {
        if payload.len() > MAX_PAYLOAD {
            return Err("Payload too large");
        }

        Self::create_internal(&[], destination, payload)
    }

    /// Internal implementation shared by create() and create_direct()
    fn create_internal(
        route: &[MeshNode],
        destination: &MeshNode,
        payload: &[u8],
    ) -> Result<Self, &'static str> {

        let mut rng = rand::thread_rng();

        // Build complete path: relays + destination
        let mut path: Vec<&MeshNode> = route.iter().collect();
        path.push(destination);

        // Start with the payload
        let mut current_data = payload.to_vec();

        // Wrap in layers from inside out (destination first, then relays in reverse)
        for (i, node) in path.iter().rev().enumerate() {
            let is_final = i == 0; // First iteration is the destination (innermost layer)

            // next_hop is the node AFTER current in the forward path
            // When i=0 (dest), no next hop
            // When i=1 (relay before dest), next_hop = dest = path[path.len()-1]
            // When i=2 (relay before that), next_hop = path[path.len()-2]
            // General: next_hop = path[path.len() - i] for i > 0
            let next_hop = if is_final {
                None
            } else {
                Some(path[path.len() - i])
            };

            current_data = wrap_layer(
                &mut rng,
                node,
                &current_data,
                next_hop,
            )?;
        }

        Ok(Self {
            layers: path.len() as u8,
            data: current_data,
        })
    }

    /// Peel one layer of the onion
    ///
    /// @param private_key This node's private key
    /// @return (next_hop, remaining_packet) or (None, payload) if this is the destination
    pub fn peel(&self, private_key: &[u8; 32]) -> Option<PeelResult> {
        if self.data.len() < LAYER_OVERHEAD {
            return None;
        }

        // Extract ephemeral public key
        let mut ephem_bytes = [0u8; 32];
        ephem_bytes.copy_from_slice(&self.data[..32]);
        let ephemeral_pubkey = PublicKey::from(ephem_bytes);

        // Compute shared secret
        let private = x25519_dalek::StaticSecret::from(*private_key);
        let shared = private.diffie_hellman(&ephemeral_pubkey);

        // Derive decryption key
        let key = derive_layer_key(shared.as_bytes());

        // Extract nonce and ciphertext
        let nonce_bytes = &self.data[32..44];
        let ciphertext = &self.data[44..];

        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&key).ok()?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        // Parse decrypted data
        if plaintext.is_empty() {
            return None;
        }

        let has_next_hop = plaintext[0] == 1;

        if has_next_hop {
            // This is a relay layer
            if plaintext.len() < 1 + NODE_ID_SIZE {
                return None;
            }

            let mut next_id = [0u8; NODE_ID_SIZE];
            next_id.copy_from_slice(&plaintext[1..1 + NODE_ID_SIZE]);

            let remaining_data = plaintext[1 + NODE_ID_SIZE..].to_vec();

            Some(PeelResult::Relay {
                next_hop: next_id,
                packet: OnionPacket {
                    layers: self.layers - 1,
                    data: remaining_data,
                },
            })
        } else {
            // This is the final destination
            let payload = plaintext[1..].to_vec();
            Some(PeelResult::Destination { payload })
        }
    }

    /// Serialize packet for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.data.len());
        result.push(self.layers);
        result.extend_from_slice(&self.data);
        result
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        Some(Self {
            layers: data[0],
            data: data[1..].to_vec(),
        })
    }
}

/// Result of peeling one onion layer
pub enum PeelResult {
    /// This is a relay - forward to next hop
    Relay {
        next_hop: [u8; NODE_ID_SIZE],
        packet: OnionPacket,
    },
    /// This is the final destination - here's the payload
    Destination {
        payload: Vec<u8>,
    },
}

/// Wrap one layer of encryption around data
fn wrap_layer<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient: &MeshNode,
    inner_data: &[u8],
    next_hop: Option<&MeshNode>,
) -> Result<Vec<u8>, &'static str> {
    // Generate ephemeral keypair for this layer
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Compute shared secret
    let shared = ephemeral_secret.diffie_hellman(&recipient.public_key);

    // Derive encryption key
    let key = derive_layer_key(shared.as_bytes());

    // Build plaintext: has_next(1) + [next_id(8)] + inner_data
    let mut plaintext = Vec::new();
    if let Some(next) = next_hop {
        plaintext.push(1); // Has next hop
        plaintext.extend_from_slice(&next.id);
    } else {
        plaintext.push(0); // Final destination
    }
    plaintext.extend_from_slice(inner_data);

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| "Invalid key")?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
        .map_err(|_| "Encryption failed")?;

    // Build layer: ephemeral_pubkey(32) + nonce(12) + ciphertext
    let mut layer = Vec::with_capacity(32 + 12 + ciphertext.len());
    layer.extend_from_slice(ephemeral_public.as_bytes());
    layer.extend_from_slice(&nonce_bytes);
    layer.extend_from_slice(&ciphertext);

    Ok(layer)
}

/// Derive layer encryption key from shared secret
fn derive_layer_key(shared: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(shared);
    hasher.update(b"MeshCore/onion/layer-key/v1");
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Generate a random route through the mesh
///
/// @param available_nodes All nodes in the mesh (excluding self and destination)
/// @param hops Number of relay hops (2-5)
/// @return Selected route nodes
pub fn select_route<R: Rng>(
    rng: &mut R,
    available_nodes: &[MeshNode],
    hops: usize,
) -> Result<Vec<MeshNode>, &'static str> {
    if hops < MIN_HOPS - 1 || hops > MAX_HOPS - 1 {
        return Err("Invalid hop count");
    }
    if available_nodes.len() < hops {
        return Err("Not enough nodes for route");
    }

    // Randomly select nodes without replacement
    let mut indices: Vec<usize> = (0..available_nodes.len()).collect();

    for i in (1..indices.len()).rev() {
        let j = rng.gen_range(0..=i);
        indices.swap(i, j);
    }

    let route: Vec<MeshNode> = indices.iter()
        .take(hops)
        .map(|&i| available_nodes[i].clone())
        .collect();

    Ok(route)
}

/// Reply path for anonymous responses
///
/// Allows recipient to respond without knowing sender's identity
#[derive(Clone)]
pub struct ReplyPath {
    /// Encrypted route information for each hop
    pub encrypted_hops: Vec<Vec<u8>>,
    /// Session key for encrypting the reply
    pub reply_key: [u8; 32],
}

impl ReplyPath {
    /// Create a reply path that routes back to the sender
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        route: &[MeshNode],
        sender: &MeshNode,
    ) -> Result<Self, &'static str> {
        if route.is_empty() {
            return Err("Empty route");
        }

        // Generate session key for reply encryption
        let mut reply_key = [0u8; 32];
        rng.fill(&mut reply_key);

        // Build encrypted hop info for each relay (reverse of send path)
        let mut encrypted_hops = Vec::with_capacity(route.len() + 1);

        // Build reverse path: last relay knows to send to sender
        let mut path: Vec<&MeshNode> = route.iter().collect();
        path.push(sender);

        for i in 0..path.len() - 1 {
            let current = path[i];
            let next = path[i + 1];

            // Encrypt next hop for this relay
            let ephemeral_secret = EphemeralSecret::random_from_rng(&mut *rng);
            let ephemeral_public = PublicKey::from(&ephemeral_secret);
            let shared = ephemeral_secret.diffie_hellman(&current.public_key);
            let key = derive_layer_key(shared.as_bytes());

            let mut nonce_bytes = [0u8; 12];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| "Invalid key")?;
            let ciphertext = cipher.encrypt(nonce, next.id.as_slice())
                .map_err(|_| "Encryption failed")?;

            let mut hop_data = Vec::with_capacity(32 + 12 + ciphertext.len());
            hop_data.extend_from_slice(ephemeral_public.as_bytes());
            hop_data.extend_from_slice(&nonce_bytes);
            hop_data.extend_from_slice(&ciphertext);

            encrypted_hops.push(hop_data);
        }

        Ok(Self {
            encrypted_hops,
            reply_key,
        })
    }

    /// Serialize for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.reply_key);
        result.push(self.encrypted_hops.len() as u8);

        for hop in &self.encrypted_hops {
            result.extend_from_slice(&(hop.len() as u16).to_le_bytes());
            result.extend_from_slice(hop);
        }

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }

        let mut reply_key = [0u8; 32];
        reply_key.copy_from_slice(&data[..32]);

        let hop_count = data[32] as usize;
        let mut pos = 33;
        let mut encrypted_hops = Vec::with_capacity(hop_count);

        for _ in 0..hop_count {
            if pos + 2 > data.len() {
                return None;
            }
            let hop_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + hop_len > data.len() {
                return None;
            }
            encrypted_hops.push(data[pos..pos + hop_len].to_vec());
            pos += hop_len;
        }

        Some(Self {
            encrypted_hops,
            reply_key,
        })
    }
}

// ============================================================================
// REPLAY PROTECTION
// ============================================================================
//
// Prevents replay attacks where an adversary records and replays onion packets.
// Each packet has a unique identifier derived from its ephemeral public key.
// Relay nodes maintain a cache of recently-seen packet IDs and reject duplicates.

/// Unique identifier for a packet, derived from ephemeral public key
/// Using first 16 bytes of SHA3-256 hash saves memory while maintaining uniqueness
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PacketId([u8; 16]);

impl PacketId {
    /// Derive packet ID from the ephemeral public key in the packet
    pub fn from_ephemeral_pubkey(pubkey_bytes: &[u8; 32]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"MeshCore/onion/packet-id/v1");
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();

        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        PacketId(id)
    }

    /// Extract packet ID from an OnionPacket's data
    pub fn from_packet(packet: &OnionPacket) -> Option<Self> {
        if packet.data.len() < 32 {
            return None;
        }
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&packet.data[..32]);
        Some(Self::from_ephemeral_pubkey(&pubkey_bytes))
    }
}

/// Cache entry with timestamp for TTL expiration
struct CacheEntry {
    /// When this entry was added (milliseconds since arbitrary epoch)
    timestamp_ms: u64,
}

/// Replay cache for detecting duplicate packets
///
/// Each relay node should maintain one of these to prevent replay attacks.
/// Entries expire after TTL_MS to prevent unbounded memory growth.
pub struct ReplayCache {
    /// Map from packet ID to cache entry
    seen: std::collections::HashMap<PacketId, CacheEntry>,
    /// Time-to-live in milliseconds (entries older than this are purged)
    ttl_ms: u64,
    /// Maximum entries before forced cleanup
    max_entries: usize,
}

impl ReplayCache {
    /// Default TTL: 5 minutes (enough for any reasonable network delay)
    pub const DEFAULT_TTL_MS: u64 = 5 * 60 * 1000;

    /// Default max entries
    pub const DEFAULT_MAX_ENTRIES: usize = 10000;

    /// Create a new replay cache with default settings
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            ttl_ms: Self::DEFAULT_TTL_MS,
            max_entries: Self::DEFAULT_MAX_ENTRIES,
        }
    }

    /// Create replay cache with custom TTL and max entries
    pub fn with_config(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            ttl_ms,
            max_entries,
        }
    }

    /// Check if packet has been seen before, and record it if not
    ///
    /// Returns true if this is a NEW packet (not a replay)
    /// Returns false if this packet was already seen (replay attack!)
    ///
    /// @param packet_id The packet's unique identifier
    /// @param current_time_ms Current time in milliseconds
    pub fn check_and_record(&mut self, packet_id: PacketId, current_time_ms: u64) -> bool {
        // First, purge expired entries if we're at capacity
        if self.seen.len() >= self.max_entries {
            self.purge_expired(current_time_ms);
        }

        // Check if we've seen this packet before
        if let Some(entry) = self.seen.get(&packet_id) {
            // Check if entry is still within TTL
            if current_time_ms.saturating_sub(entry.timestamp_ms) < self.ttl_ms {
                // REPLAY DETECTED - packet seen within TTL window
                return false;
            }
            // Entry expired, treat as new
        }

        // Record this packet
        self.seen.insert(packet_id, CacheEntry {
            timestamp_ms: current_time_ms,
        });

        true // New packet, not a replay
    }

    /// Check a packet directly
    ///
    /// Convenience method that extracts PacketId from the packet
    pub fn check_packet(&mut self, packet: &OnionPacket, current_time_ms: u64) -> bool {
        match PacketId::from_packet(packet) {
            Some(id) => self.check_and_record(id, current_time_ms),
            None => false, // Invalid packet
        }
    }

    /// Purge expired entries
    fn purge_expired(&mut self, current_time_ms: u64) {
        self.seen.retain(|_, entry| {
            current_time_ms.saturating_sub(entry.timestamp_ms) < self.ttl_ms
        });
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Get number of entries in cache
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionPacket {
    /// Peel one layer with replay protection
    ///
    /// Same as `peel()` but first checks if this packet is a replay.
    /// Returns None if the packet is a replay (already seen).
    ///
    /// @param private_key This node's private key
    /// @param replay_cache Cache of recently seen packets
    /// @param current_time_ms Current time for TTL calculation
    pub fn peel_with_replay_protection(
        &self,
        private_key: &[u8; 32],
        replay_cache: &mut ReplayCache,
        current_time_ms: u64,
    ) -> Option<PeelResult> {
        // Check for replay attack BEFORE decrypting
        if !replay_cache.check_packet(self, current_time_ms) {
            // REPLAY DETECTED - reject packet
            return None;
        }

        // Not a replay, proceed with normal peeling
        self.peel(private_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn create_test_node(id: u8) -> (MeshNode, [u8; 32]) {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        let mut node_id = [0u8; NODE_ID_SIZE];
        node_id[0] = id;

        (MeshNode::new(node_id, public), secret.to_bytes())
    }

    #[test]
    fn test_onion_routing_direct() {
        // Test create_direct() for non-anonymous communication
        let (dest_node, dest_secret) = create_test_node(1);

        let payload = b"Hello, destination!";
        // Use create_direct() - explicitly non-anonymous
        let packet = OnionPacket::create_direct(&dest_node, payload).unwrap();

        // Destination peels the packet
        let result = packet.peel(&dest_secret).unwrap();

        match result {
            PeelResult::Destination { payload: recovered } => {
                assert_eq!(recovered, payload);
            }
            _ => panic!("Expected Destination result"),
        }
    }

    #[test]
    fn test_anonymous_requires_min_hops() {
        // Verify that create() ENFORCES minimum hops
        // MIN_HOPS = 3, so we need at least 2 relays (2 relays + 1 destination = 3 hops)
        let (dest_node, _) = create_test_node(1);
        let payload = b"Secret";

        // Empty route should FAIL for anonymous routing (0 + 1 = 1 hop < MIN_HOPS)
        let result = OnionPacket::create(&[], &dest_node, payload);
        assert!(result.is_err(), "Anonymous routing must require minimum hops");
        assert!(result.unwrap_err().contains("too short"));

        // Single relay should FAIL (1 + 1 = 2 hops < MIN_HOPS)
        let (relay1, _) = create_test_node(2);
        let result = OnionPacket::create(&[relay1.clone()], &dest_node, payload);
        assert!(result.is_err(), "1 relay + destination = 2 hops should NOT meet MIN_HOPS=3");

        // Two relays should SUCCEED (2 + 1 = 3 hops = MIN_HOPS)
        let (relay2, _) = create_test_node(3);
        let result = OnionPacket::create(&[relay1, relay2], &dest_node, payload);
        assert!(result.is_ok(), "2 relays + destination = 3 hops should meet MIN_HOPS");
    }

    #[test]
    fn test_onion_routing_multi_hop() {
        let (relay1_node, relay1_secret) = create_test_node(1);
        let (relay2_node, relay2_secret) = create_test_node(2);
        let (dest_node, dest_secret) = create_test_node(3);

        let route = vec![relay1_node.clone(), relay2_node.clone()];
        let payload = b"Secret message through mesh!";

        let packet = OnionPacket::create(&route, &dest_node, payload).unwrap();

        // Relay 1 peels
        let result1 = packet.peel(&relay1_secret).unwrap();
        let packet2 = match result1 {
            PeelResult::Relay { next_hop, packet } => {
                assert_eq!(next_hop, relay2_node.id);
                packet
            }
            _ => panic!("Expected Relay result"),
        };

        // Relay 2 peels
        let result2 = packet2.peel(&relay2_secret).unwrap();
        let packet3 = match result2 {
            PeelResult::Relay { next_hop, packet } => {
                assert_eq!(next_hop, dest_node.id);
                packet
            }
            _ => panic!("Expected Relay result"),
        };

        // Destination peels
        let result3 = packet3.peel(&dest_secret).unwrap();
        match result3 {
            PeelResult::Destination { payload: recovered } => {
                assert_eq!(recovered, payload);
            }
            _ => panic!("Expected Destination result"),
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let (relay1, _) = create_test_node(1);
        let (relay2, _) = create_test_node(2);
        let (dest_node, _dest_secret) = create_test_node(3);
        let (_, wrong_secret) = create_test_node(4);

        let payload = b"Secret";
        let route = vec![relay1, relay2];
        let packet = OnionPacket::create(&route, &dest_node, payload).unwrap();

        // Try with wrong key - should fail
        let result = packet.peel(&wrong_secret);
        assert!(result.is_none(), "Wrong key should fail");
    }

    #[test]
    fn test_packet_serialization() {
        let (relay1, _) = create_test_node(1);
        let (relay2, _) = create_test_node(2);
        let (dest_node, _) = create_test_node(3);

        let payload = b"Test message";
        let route = vec![relay1, relay2];
        let packet = OnionPacket::create(&route, &dest_node, payload).unwrap();

        let bytes = packet.to_bytes();
        let recovered = OnionPacket::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.layers, packet.layers);
        assert_eq!(recovered.data, packet.data);
    }

    #[test]
    fn test_route_selection() {
        let mut rng = rand::thread_rng();

        let nodes: Vec<MeshNode> = (0..10)
            .map(|i| create_test_node(i).0)
            .collect();

        let route = select_route(&mut rng, &nodes, 3).unwrap();

        assert_eq!(route.len(), 3);

        // Verify no duplicates
        let ids: Vec<_> = route.iter().map(|n| n.id).collect();
        for i in 0..ids.len() {
            for j in i + 1..ids.len() {
                assert_ne!(ids[i], ids[j], "Route should have unique nodes");
            }
        }
    }
}
