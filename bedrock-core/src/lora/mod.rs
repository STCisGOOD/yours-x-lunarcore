//! # LoRa Hardware Abstraction Layer
//!
//! This module provides the interface between LunarCore protocol and LoRa hardware.
//!
//! ## Architecture
//!
//! ```text
//! Android (Yours App)
//!     │
//!     │ USB/Serial
//!     ▼
//! ESP32 + SX1262/SX1276
//!     │
//!     │ LoRa RF
//!     ▼
//! Mesh Network
//! ```
//!
//! ## Components
//!
//! - [`transport`]: Hardware abstraction traits
//! - [`serial`]: USB/Serial protocol for ESP32 communication
//! - [`mock`]: Mock transport for testing
//!
//! ## Supported Hardware
//!
//! - ESP32 + Semtech SX1262 (868/915 MHz)
//! - ESP32 + Semtech SX1276 (868/915 MHz)
//! - Heltec WiFi LoRa 32
//! - TTGO LoRa32
//! - LilyGo T-Beam

pub mod transport;
pub mod serial;
pub mod mock;

pub use transport::{LoRaTransport, LoRaConfig, LoRaError, LoRaPacket, TransportStats};
pub use serial::{SerialTransport, SerialConfig};
pub use mock::MockTransport;
