//! LunarCore Packet Encoding/Decoding
//!
//! Implements the packet formats for LunarCore mesh protocol.
//! All packets are designed to fit within LoRa's 237-byte MTU.
//!
//! ## Packet Types
//!
//! - `Data`: Encrypted application data with session routing
//! - `Handshake`: Session establishment with Hk-OVCT
//! - `Control`: Routing updates, keep-alive, acknowledgments
//! - `Cover`: Chaff traffic for traffic analysis resistance
//!
//! ## Design Constraints
//!
//! - Maximum packet size: 237 bytes (LoRa physical limit)
//! - No source addresses (enforces initiator anonymity)
//! - Hints are truncated hashes (4-8 bytes) for routing
//! - All encrypted payloads include 16-byte auth tag

use sha2::{Sha256, Digest};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum packet size for LoRa transmission.
/// FIXED: Changed from 237 to 184 to match MeshCore MAX_PACKET_PAYLOAD.
/// MeshCore adds its own framing overhead, so the actual payload limit is 184 bytes.
/// Using 237 caused packets to be silently truncated, corrupting ciphertext and
/// causing decryption failures.
pub const MAX_PACKET_SIZE: usize = 184;

/// Size of node hint (truncated hash of public key)
/// Increased from 2 to 4 bytes (16 to 32 bits).
/// With 16 bits, birthday attack succeeds with ~256 attempts.
/// With 32 bits, birthday attack requires ~65K attempts.
/// Still fits well within LoRa MTU (adds 2 bytes per hint).
pub const NODE_HINT_SIZE: usize = 4;

/// Size of session hint (truncated hash of session key)
/// Increased from 4 to 8 bytes (32 to 64 bits).
/// Provides strong session identification with ~2^32 birthday resistance.
pub const SESSION_HINT_SIZE: usize = 8;

/// Size of X25519 public key
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of Hk-OVCT ciphertext
pub const CIPHERTEXT_SIZE: usize = 32;

/// Size of AES-GCM authentication tag
pub const AUTH_TAG_SIZE: usize = 16;

/// Overhead for Data packet (flags + hints + tag)
pub const DATA_OVERHEAD: usize = 1 + NODE_HINT_SIZE + SESSION_HINT_SIZE + AUTH_TAG_SIZE;

/// Maximum payload for Data packet
pub const DATA_MAX_PAYLOAD: usize = MAX_PACKET_SIZE - DATA_OVERHEAD;

/// Overhead for Handshake packet (flags + hint + ephemeral + ciphertext + tag)
pub const HANDSHAKE_OVERHEAD: usize = 1 + NODE_HINT_SIZE + PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE + AUTH_TAG_SIZE;

/// Maximum payload for Handshake packet
pub const HANDSHAKE_MAX_PAYLOAD: usize = MAX_PACKET_SIZE - HANDSHAKE_OVERHEAD;

// ============================================================================
// PACKET TYPE
// ============================================================================

/// Packet type identifier (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Encrypted application data
    Data = 0b00,
    /// Session establishment
    Handshake = 0b01,
    /// Routing control messages
    Control = 0b10,
    /// Cover traffic (chaff)
    Cover = 0b11,
}

impl PacketType {
    /// Parse packet type from flags byte
    pub fn from_flags(flags: u8) -> Option<Self> {
        match flags & 0b11 {
            0b00 => Some(PacketType::Data),
            0b01 => Some(PacketType::Handshake),
            0b10 => Some(PacketType::Control),
            0b11 => Some(PacketType::Cover),
            _ => None,
        }
    }

    /// Convert to flags byte (only type bits)
    pub fn to_flags(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// FLAGS BYTE STRUCTURE
// ============================================================================

/// Flags byte layout:
/// ```text
/// Bit 7 6 5 4 3 2 1 0
///     │ │ │ │ │ │ └─┴── Packet type (2 bits)
///     │ │ │ │ │ └────── Final hop flag
///     │ │ │ │ └──────── ACK requested
///     │ │ └─┴────────── Reserved
///     └─┴────────────── Onion layers remaining (2 bits)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags {
    /// Packet type (Data, Handshake, Control, Cover)
    pub packet_type: PacketType,
    /// This is the final hop (deliver, don't forward)
    pub final_hop: bool,
    /// Sender requests acknowledgment
    pub ack_requested: bool,
    /// Number of onion layers remaining (0-3)
    pub layers_remaining: u8,
}

impl PacketFlags {
    /// Create new flags
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            packet_type,
            final_hop: false,
            ack_requested: false,
            layers_remaining: 0,
        }
    }

    /// Parse from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        let packet_type = PacketType::from_flags(byte)?;
        Some(Self {
            packet_type,
            final_hop: (byte & 0b0000_0100) != 0,
            ack_requested: (byte & 0b0000_1000) != 0,
            layers_remaining: (byte >> 6) & 0b11,
        })
    }

    /// Encode to byte
    pub fn to_byte(&self) -> u8 {
        let mut byte = self.packet_type.to_flags();
        if self.final_hop {
            byte |= 0b0000_0100;
        }
        if self.ack_requested {
            byte |= 0b0000_1000;
        }
        byte |= (self.layers_remaining & 0b11) << 6;
        byte
    }
}

// ============================================================================
// ERROR TYPE
// ============================================================================

/// Packet encoding/decoding errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Packet exceeds maximum size
    TooLarge { size: usize, max: usize },
    /// Packet too small to contain required fields
    TooSmall { size: usize, min: usize },
    /// Invalid flags byte
    InvalidFlags,
    /// Invalid packet type for operation
    InvalidPacketType,
    /// Payload exceeds maximum for packet type
    PayloadTooLarge { size: usize, max: usize },
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::TooLarge { size, max } => {
                write!(f, "Packet too large: {} bytes (max {})", size, max)
            }
            PacketError::TooSmall { size, min } => {
                write!(f, "Packet too small: {} bytes (min {})", size, min)
            }
            PacketError::InvalidFlags => write!(f, "Invalid flags byte"),
            PacketError::InvalidPacketType => write!(f, "Invalid packet type"),
            PacketError::PayloadTooLarge { size, max } => {
                write!(f, "Payload too large: {} bytes (max {})", size, max)
            }
        }
    }
}

impl std::error::Error for PacketError {}

// ============================================================================
// HINT DERIVATION
// ============================================================================

/// Derive a node hint from a public key.
///
/// The hint is the first NODE_HINT_SIZE bytes of SHA-256(public_key).
/// With 32 bits, birthday collision requires ~65K attempts.
pub fn derive_node_hint(public_key: &[u8; 32]) -> [u8; NODE_HINT_SIZE] {
    let hash = Sha256::digest(public_key);
    let mut hint = [0u8; NODE_HINT_SIZE];
    hint.copy_from_slice(&hash[..NODE_HINT_SIZE]);
    hint
}

/// Derive a session hint from a session key.
///
/// The hint is the first SESSION_HINT_SIZE bytes of SHA-256(session_key).
/// With 64 bits, provides ~2^32 birthday collision resistance.
pub fn derive_session_hint(session_key: &[u8; 32]) -> [u8; SESSION_HINT_SIZE] {
    let hash = Sha256::digest(session_key);
    let mut hint = [0u8; SESSION_HINT_SIZE];
    hint.copy_from_slice(&hash[..SESSION_HINT_SIZE]);
    hint
}

// ============================================================================
// DATA PACKET
// ============================================================================

/// Data packet for encrypted application messages
///
/// Format:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Flags (1 byte)                                              │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Next-Hop Hint (2 bytes)                                     │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Session Hint (4 bytes)                                      │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Encrypted Payload (variable, includes 16-byte tag)          │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Packet flags
    pub flags: PacketFlags,
    /// Truncated hash of next relay's public key
    pub next_hop_hint: [u8; NODE_HINT_SIZE],
    /// Truncated hash of session key for lookup
    pub session_hint: [u8; SESSION_HINT_SIZE],
    /// AES-GCM encrypted payload (includes auth tag)
    pub encrypted_payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet
    pub fn new(
        next_hop_hint: [u8; NODE_HINT_SIZE],
        session_hint: [u8; SESSION_HINT_SIZE],
        encrypted_payload: Vec<u8>,
    ) -> Result<Self, PacketError> {
        if encrypted_payload.len() > DATA_MAX_PAYLOAD {
            return Err(PacketError::PayloadTooLarge {
                size: encrypted_payload.len(),
                max: DATA_MAX_PAYLOAD,
            });
        }

        Ok(Self {
            flags: PacketFlags::new(PacketType::Data),
            next_hop_hint,
            session_hint,
            encrypted_payload,
        })
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + NODE_HINT_SIZE + SESSION_HINT_SIZE + self.encrypted_payload.len()
        );
        buf.push(self.flags.to_byte());
        buf.extend_from_slice(&self.next_hop_hint);
        buf.extend_from_slice(&self.session_hint);
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        let min_size = 1 + NODE_HINT_SIZE + SESSION_HINT_SIZE;
        if data.len() < min_size {
            return Err(PacketError::TooSmall {
                size: data.len(),
                min: min_size,
            });
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge {
                size: data.len(),
                max: MAX_PACKET_SIZE,
            });
        }

        let flags = PacketFlags::from_byte(data[0])
            .ok_or(PacketError::InvalidFlags)?;

        if flags.packet_type != PacketType::Data {
            return Err(PacketError::InvalidPacketType);
        }

        let mut next_hop_hint = [0u8; NODE_HINT_SIZE];
        next_hop_hint.copy_from_slice(&data[1..1 + NODE_HINT_SIZE]);

        let mut session_hint = [0u8; SESSION_HINT_SIZE];
        session_hint.copy_from_slice(
            &data[1 + NODE_HINT_SIZE..1 + NODE_HINT_SIZE + SESSION_HINT_SIZE]
        );

        let encrypted_payload = data[1 + NODE_HINT_SIZE + SESSION_HINT_SIZE..].to_vec();

        Ok(Self {
            flags,
            next_hop_hint,
            session_hint,
            encrypted_payload,
        })
    }

    /// Get total encoded size
    pub fn encoded_size(&self) -> usize {
        1 + NODE_HINT_SIZE + SESSION_HINT_SIZE + self.encrypted_payload.len()
    }
}

// ============================================================================
// HANDSHAKE PACKET
// ============================================================================

/// Handshake packet for session establishment
///
/// Format:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Flags (1 byte)                                              │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Recipient Hint (2 bytes)                                    │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Ephemeral Public Key (32 bytes)                             │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Hk-OVCT Ciphertext (32 bytes)                               │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Encrypted Payload (variable, optional initial message)      │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct HandshakePacket {
    /// Packet flags
    pub flags: PacketFlags,
    /// Truncated hash of recipient's long-term public key
    pub recipient_hint: [u8; NODE_HINT_SIZE],
    /// Ephemeral X25519 public key for this session
    pub ephemeral_pk: [u8; PUBLIC_KEY_SIZE],
    /// Hk-OVCT ciphertext (hedged key encapsulation)
    pub hk_ovct_ciphertext: [u8; CIPHERTEXT_SIZE],
    /// Optional encrypted initial message
    pub encrypted_payload: Vec<u8>,
}

impl std::fmt::Debug for HandshakePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakePacket")
            .field("flags", &self.flags)
            .field("recipient_hint", &self.recipient_hint)
            .field("ephemeral_pk", &"[32 bytes]")
            .field("hk_ovct_ciphertext", &"[32 bytes]")
            .field("encrypted_payload_len", &self.encrypted_payload.len())
            .finish()
    }
}

impl HandshakePacket {
    /// Create a new handshake packet
    pub fn new(
        recipient_hint: [u8; NODE_HINT_SIZE],
        ephemeral_pk: [u8; PUBLIC_KEY_SIZE],
        hk_ovct_ciphertext: [u8; CIPHERTEXT_SIZE],
        encrypted_payload: Vec<u8>,
    ) -> Result<Self, PacketError> {
        if encrypted_payload.len() > HANDSHAKE_MAX_PAYLOAD {
            return Err(PacketError::PayloadTooLarge {
                size: encrypted_payload.len(),
                max: HANDSHAKE_MAX_PAYLOAD,
            });
        }

        Ok(Self {
            flags: PacketFlags::new(PacketType::Handshake),
            recipient_hint,
            ephemeral_pk,
            hk_ovct_ciphertext,
            encrypted_payload,
        })
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + NODE_HINT_SIZE + PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE + self.encrypted_payload.len()
        );
        buf.push(self.flags.to_byte());
        buf.extend_from_slice(&self.recipient_hint);
        buf.extend_from_slice(&self.ephemeral_pk);
        buf.extend_from_slice(&self.hk_ovct_ciphertext);
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        let min_size = 1 + NODE_HINT_SIZE + PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE;
        if data.len() < min_size {
            return Err(PacketError::TooSmall {
                size: data.len(),
                min: min_size,
            });
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge {
                size: data.len(),
                max: MAX_PACKET_SIZE,
            });
        }

        let flags = PacketFlags::from_byte(data[0])
            .ok_or(PacketError::InvalidFlags)?;

        if flags.packet_type != PacketType::Handshake {
            return Err(PacketError::InvalidPacketType);
        }

        let mut offset = 1;

        let mut recipient_hint = [0u8; NODE_HINT_SIZE];
        recipient_hint.copy_from_slice(&data[offset..offset + NODE_HINT_SIZE]);
        offset += NODE_HINT_SIZE;

        let mut ephemeral_pk = [0u8; PUBLIC_KEY_SIZE];
        ephemeral_pk.copy_from_slice(&data[offset..offset + PUBLIC_KEY_SIZE]);
        offset += PUBLIC_KEY_SIZE;

        let mut hk_ovct_ciphertext = [0u8; CIPHERTEXT_SIZE];
        hk_ovct_ciphertext.copy_from_slice(&data[offset..offset + CIPHERTEXT_SIZE]);
        offset += CIPHERTEXT_SIZE;

        let encrypted_payload = data[offset..].to_vec();

        Ok(Self {
            flags,
            recipient_hint,
            ephemeral_pk,
            hk_ovct_ciphertext,
            encrypted_payload,
        })
    }

    /// Get total encoded size
    pub fn encoded_size(&self) -> usize {
        1 + NODE_HINT_SIZE + PUBLIC_KEY_SIZE + CIPHERTEXT_SIZE + self.encrypted_payload.len()
    }
}

// ============================================================================
// CONTROL PACKET
// ============================================================================

/// Control message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlType {
    /// Acknowledgment of received packet
    Ack = 0x01,
    /// Keep-alive ping
    Ping = 0x02,
    /// Response to ping
    Pong = 0x03,
    /// Path probe (for latency measurement)
    Probe = 0x04,
    /// Node announcement
    Announce = 0x05,
}

impl ControlType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(ControlType::Ack),
            0x02 => Some(ControlType::Ping),
            0x03 => Some(ControlType::Pong),
            0x04 => Some(ControlType::Probe),
            0x05 => Some(ControlType::Announce),
            _ => None,
        }
    }
}

/// Control packet for routing and management
///
/// Format:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Flags (1 byte)                                              │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Control Type (1 byte)                                       │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Control Data (variable)                                     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// Packet flags
    pub flags: PacketFlags,
    /// Control message type
    pub control_type: ControlType,
    /// Type-specific data
    pub data: Vec<u8>,
}

impl ControlPacket {
    /// Create a new control packet
    pub fn new(control_type: ControlType, data: Vec<u8>) -> Result<Self, PacketError> {
        let max_data = MAX_PACKET_SIZE - 2; // flags + control_type
        if data.len() > max_data {
            return Err(PacketError::PayloadTooLarge {
                size: data.len(),
                max: max_data,
            });
        }

        Ok(Self {
            flags: PacketFlags::new(PacketType::Control),
            control_type,
            data,
        })
    }

    /// Create an ACK packet
    pub fn ack(session_hint: [u8; SESSION_HINT_SIZE], sequence: u32) -> Self {
        let mut data = Vec::with_capacity(SESSION_HINT_SIZE + 4);
        data.extend_from_slice(&session_hint);
        data.extend_from_slice(&sequence.to_be_bytes());
        Self {
            flags: PacketFlags::new(PacketType::Control),
            control_type: ControlType::Ack,
            data,
        }
    }

    /// Create a PING packet
    pub fn ping(nonce: u64) -> Self {
        Self {
            flags: PacketFlags::new(PacketType::Control),
            control_type: ControlType::Ping,
            data: nonce.to_be_bytes().to_vec(),
        }
    }

    /// Create a PONG packet (response to ping)
    pub fn pong(nonce: u64) -> Self {
        Self {
            flags: PacketFlags::new(PacketType::Control),
            control_type: ControlType::Pong,
            data: nonce.to_be_bytes().to_vec(),
        }
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.data.len());
        buf.push(self.flags.to_byte());
        buf.push(self.control_type as u8);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 2 {
            return Err(PacketError::TooSmall { size: data.len(), min: 2 });
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge {
                size: data.len(),
                max: MAX_PACKET_SIZE,
            });
        }

        let flags = PacketFlags::from_byte(data[0])
            .ok_or(PacketError::InvalidFlags)?;

        if flags.packet_type != PacketType::Control {
            return Err(PacketError::InvalidPacketType);
        }

        let control_type = ControlType::from_byte(data[1])
            .ok_or(PacketError::InvalidFlags)?;

        Ok(Self {
            flags,
            control_type,
            data: data[2..].to_vec(),
        })
    }
}

// ============================================================================
// COVER PACKET
// ============================================================================

/// Cover packet for traffic analysis resistance
///
/// Cover packets are statistically indistinguishable from Data packets
/// to external observers. They contain random encrypted-looking data.
///
/// Format:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Flags (1 byte) - type bits set to Cover                     │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Random Data (236 bytes)                                     │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CoverPacket {
    /// Packet flags
    pub flags: PacketFlags,
    /// Random data (looks like encrypted payload)
    pub random_data: Vec<u8>,
}

impl std::fmt::Debug for CoverPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverPacket")
            .field("flags", &self.flags)
            .field("random_data_len", &self.random_data.len())
            .finish()
    }
}

impl CoverPacket {
    /// Create a new cover packet with provided random data
    pub fn new(random_data: Vec<u8>) -> Result<Self, PacketError> {
        let max_size = MAX_PACKET_SIZE - 1;
        if random_data.len() > max_size {
            return Err(PacketError::PayloadTooLarge {
                size: random_data.len(),
                max: max_size,
            });
        }

        Ok(Self {
            flags: PacketFlags::new(PacketType::Cover),
            random_data,
        })
    }

    /// Create a full-size cover packet (for maximum indistinguishability)
    pub fn full_size(random_data: [u8; MAX_PACKET_SIZE - 1]) -> Self {
        Self {
            flags: PacketFlags::new(PacketType::Cover),
            random_data: random_data.to_vec(),
        }
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.random_data.len());
        buf.push(self.flags.to_byte());
        buf.extend_from_slice(&self.random_data);
        buf
    }

    /// Decode packet from bytes
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.is_empty() {
            return Err(PacketError::TooSmall { size: 0, min: 1 });
        }

        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge {
                size: data.len(),
                max: MAX_PACKET_SIZE,
            });
        }

        let flags = PacketFlags::from_byte(data[0])
            .ok_or(PacketError::InvalidFlags)?;

        if flags.packet_type != PacketType::Cover {
            return Err(PacketError::InvalidPacketType);
        }

        Ok(Self {
            flags,
            random_data: data[1..].to_vec(),
        })
    }
}

// ============================================================================
// GENERIC PACKET PARSING
// ============================================================================

/// Parsed packet (any type)
#[derive(Debug, Clone)]
pub enum Packet {
    Data(DataPacket),
    Handshake(HandshakePacket),
    Control(ControlPacket),
    Cover(CoverPacket),
}

impl Packet {
    /// Parse a packet from raw bytes, determining type from flags
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.is_empty() {
            return Err(PacketError::TooSmall { size: 0, min: 1 });
        }

        let packet_type = PacketType::from_flags(data[0])
            .ok_or(PacketError::InvalidFlags)?;

        match packet_type {
            PacketType::Data => Ok(Packet::Data(DataPacket::decode(data)?)),
            PacketType::Handshake => Ok(Packet::Handshake(HandshakePacket::decode(data)?)),
            PacketType::Control => Ok(Packet::Control(ControlPacket::decode(data)?)),
            PacketType::Cover => Ok(Packet::Cover(CoverPacket::decode(data)?)),
        }
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Packet::Data(p) => p.encode(),
            Packet::Handshake(p) => p.encode(),
            Packet::Control(p) => p.encode(),
            Packet::Cover(p) => p.encode(),
        }
    }

    /// Get packet type
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::Data(_) => PacketType::Data,
            Packet::Handshake(_) => PacketType::Handshake,
            Packet::Control(_) => PacketType::Control,
            Packet::Cover(_) => PacketType::Cover,
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_flags_roundtrip() {
        let flags = PacketFlags {
            packet_type: PacketType::Data,
            final_hop: true,
            ack_requested: true,
            layers_remaining: 2,
        };

        let byte = flags.to_byte();
        let recovered = PacketFlags::from_byte(byte).unwrap();

        assert_eq!(flags, recovered);
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let packet = DataPacket::new(
            [0x12, 0x34, 0x56, 0x78], // NODE_HINT_SIZE = 4 bytes
            [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89], // SESSION_HINT_SIZE = 8 bytes
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ).unwrap();

        let encoded = packet.encode();
        let decoded = DataPacket::decode(&encoded).unwrap();

        assert_eq!(packet.next_hop_hint, decoded.next_hop_hint);
        assert_eq!(packet.session_hint, decoded.session_hint);
        assert_eq!(packet.encrypted_payload, decoded.encrypted_payload);
    }

    #[test]
    fn test_handshake_packet_roundtrip() {
        let packet = HandshakePacket::new(
            [0xAA, 0xBB, 0xCC, 0xDD], // NODE_HINT_SIZE = 4 bytes
            [0x11; 32],
            [0x22; 32],
            vec![0xFF; 50],
        ).unwrap();

        let encoded = packet.encode();
        let decoded = HandshakePacket::decode(&encoded).unwrap();

        assert_eq!(packet.recipient_hint, decoded.recipient_hint);
        assert_eq!(packet.ephemeral_pk, decoded.ephemeral_pk);
        assert_eq!(packet.hk_ovct_ciphertext, decoded.hk_ovct_ciphertext);
        assert_eq!(packet.encrypted_payload, decoded.encrypted_payload);
    }

    #[test]
    fn test_control_packet_roundtrip() {
        let packet = ControlPacket::ping(0x123456789ABCDEF0);
        let encoded = packet.encode();
        let decoded = ControlPacket::decode(&encoded).unwrap();

        assert_eq!(packet.control_type, decoded.control_type);
        assert_eq!(packet.data, decoded.data);
    }

    #[test]
    fn test_cover_packet_roundtrip() {
        let packet = CoverPacket::new(vec![0x42; 200]).unwrap();
        let encoded = packet.encode();
        let decoded = CoverPacket::decode(&encoded).unwrap();

        assert_eq!(packet.random_data, decoded.random_data);
    }

    #[test]
    fn test_generic_packet_parsing() {
        // Test Data packet (NODE_HINT_SIZE=4, SESSION_HINT_SIZE=8)
        let data = DataPacket::new([0x12, 0x34, 0x56, 0x78], [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89], vec![1, 2, 3]).unwrap();
        let parsed = Packet::parse(&data.encode()).unwrap();
        assert!(matches!(parsed, Packet::Data(_)));

        // Test Handshake packet (NODE_HINT_SIZE=4)
        let hs = HandshakePacket::new([0xAA, 0xBB, 0xCC, 0xDD], [0x11; 32], [0x22; 32], vec![]).unwrap();
        let parsed = Packet::parse(&hs.encode()).unwrap();
        assert!(matches!(parsed, Packet::Handshake(_)));

        // Test Control packet
        let ctrl = ControlPacket::ping(12345);
        let parsed = Packet::parse(&ctrl.encode()).unwrap();
        assert!(matches!(parsed, Packet::Control(_)));

        // Test Cover packet
        let cover = CoverPacket::new(vec![0xFF; 100]).unwrap();
        let parsed = Packet::parse(&cover.encode()).unwrap();
        assert!(matches!(parsed, Packet::Cover(_)));
    }

    #[test]
    fn test_derive_node_hint() {
        let pk = [0x42u8; 32];
        let hint = derive_node_hint(&pk);
        assert_eq!(hint.len(), NODE_HINT_SIZE);

        // Same key should produce same hint
        let hint2 = derive_node_hint(&pk);
        assert_eq!(hint, hint2);

        // Different key should produce different hint
        let pk2 = [0x43u8; 32];
        let hint3 = derive_node_hint(&pk2);
        assert_ne!(hint, hint3);
    }

    #[test]
    fn test_derive_session_hint() {
        let sk = [0xABu8; 32];
        let hint = derive_session_hint(&sk);
        assert_eq!(hint.len(), SESSION_HINT_SIZE);
    }

    #[test]
    fn test_max_payload_sizes() {
        // Data packet should accept max payload (NODE_HINT_SIZE=4, SESSION_HINT_SIZE=8)
        let max_data = vec![0u8; DATA_MAX_PAYLOAD];
        assert!(DataPacket::new([0; NODE_HINT_SIZE], [0; SESSION_HINT_SIZE], max_data).is_ok());

        // Data packet should reject oversized payload
        let oversized = vec![0u8; DATA_MAX_PAYLOAD + 1];
        assert!(DataPacket::new([0; NODE_HINT_SIZE], [0; SESSION_HINT_SIZE], oversized).is_err());

        // Handshake packet should accept max payload (NODE_HINT_SIZE=4)
        let max_hs = vec![0u8; HANDSHAKE_MAX_PAYLOAD];
        assert!(HandshakePacket::new([0; NODE_HINT_SIZE], [0; 32], [0; 32], max_hs).is_ok());

        // Handshake packet should reject oversized payload
        let oversized_hs = vec![0u8; HANDSHAKE_MAX_PAYLOAD + 1];
        assert!(HandshakePacket::new([0; NODE_HINT_SIZE], [0; 32], [0; 32], oversized_hs).is_err());
    }

    #[test]
    fn test_packet_size_limits() {
        // Data packet with max payload should fit in 237 bytes (NODE_HINT_SIZE=4, SESSION_HINT_SIZE=8)
        let packet = DataPacket::new(
            [0; NODE_HINT_SIZE],
            [0; SESSION_HINT_SIZE],
            vec![0u8; DATA_MAX_PAYLOAD],
        ).unwrap();
        assert!(packet.encoded_size() <= MAX_PACKET_SIZE);

        // Handshake packet with max payload should fit in 237 bytes (NODE_HINT_SIZE=4)
        let packet = HandshakePacket::new(
            [0; NODE_HINT_SIZE],
            [0; 32],
            [0; 32],
            vec![0u8; HANDSHAKE_MAX_PAYLOAD],
        ).unwrap();
        assert!(packet.encoded_size() <= MAX_PACKET_SIZE);
    }

    #[test]
    fn test_layers_remaining_encoding() {
        for layers in 0..=3 {
            let mut flags = PacketFlags::new(PacketType::Data);
            flags.layers_remaining = layers;

            let byte = flags.to_byte();
            let recovered = PacketFlags::from_byte(byte).unwrap();

            assert_eq!(layers, recovered.layers_remaining);
        }
    }
}
