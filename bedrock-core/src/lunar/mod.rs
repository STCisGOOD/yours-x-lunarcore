//! # LunarCore - Anonymous LoRa Mesh Protocol
//!
//! LunarCore is a cryptographic protocol for anonymous communication over
//! LoRa mesh networks, combining MeshCore's efficiency with Reticulum's privacy.
//!
//! ## Design Philosophy
//!
//! Based on the "Lunarpunk" concept: privacy as architecture, not policy.
//! The protocol provides:
//! - **Initiator anonymity**: No source addresses in packets
//! - **Forward secrecy**: KDF ratcheting deletes old keys
//! - **Post-compromise security**: DH ratchet heals after compromise
//! - **Traffic analysis resistance**: Cover traffic and fixed-size packets
//! - **RNG failure resistance**: Hedged key encapsulation (Hk-OVCT)
//!
//! ## Components
//!
//! | Module | Status | Description |
//! |--------|--------|-------------|
//! | [`hedged_kem`] | ✅ Production | Hk-OVCT with dual-DH and entropy hedging |
//! | [`packet`] | ✅ Production | 237-byte LoRa packet codec |
//! | [`session`] | ✅ Production | Double Ratchet session management |
//! | [`routing`] | ✅ Production | Node discovery, onion routing, path selection |
//! | [`mesh_credentials`] | ✅ Production | BBS+ anonymous credentials for mesh access |
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use lunar::hedged_kem::HkOvctKeyPair;
//! use lunar::session::Session;
//! use lunar::packet::HandshakePacket;
//!
//! // Generate identities
//! let alice = HkOvctKeyPair::generate();
//! let bob = HkOvctKeyPair::generate();
//!
//! // Alice initiates session
//! let (mut alice_session, handshake) = Session::initiate(
//!     alice,
//!     bob.public_key(),
//!     b"sensor_entropy",
//! ).unwrap();
//!
//! // Bob responds
//! let mut bob_session = Session::respond(bob, &handshake).unwrap();
//!
//! // Encrypt/decrypt messages
//! alice_session.mark_established().unwrap();
//! let ciphertext = alice_session.encrypt(b"Hello Bob!").unwrap();
//! let plaintext = bob_session.decrypt(&ciphertext).unwrap();
//! ```
//!
//! ## Security Model
//!
//! **Threat model:**
//! - Global passive adversary monitoring all RF traffic
//! - Up to n-1 compromised relays in n-relay circuit
//! - Compromised RNG on endpoint device
//! - Device seizure (protects past messages via forward secrecy)
//!
//! **NOT defended against:**
//! - Active implant on endpoint device
//! - All relays in circuit compromised simultaneously
//! - Physical layer attacks (jamming, single-transmission DF)
//!
//! ## LoRa Constraints
//!
//! - Maximum packet size: 237 bytes
//! - Duty cycle: 1% (EU) / 10% (US)
//! - Data rate: ~1.76 kbps (SF9, BW125)
//! - Post-quantum: Hybrid Kyber+X25519 via out-of-band QR bootstrap
//!
//! ## Protocol Specification
//!
//! See `LUNARCORE-PROTOCOL-SPEC-v0.1.md` for full protocol details.

pub mod hedged_kem;
pub mod packet;
pub mod session;
pub mod routing;
pub mod mesh_credentials;
