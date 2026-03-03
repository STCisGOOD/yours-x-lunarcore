//! Mesh Identity (Tier 4)
//!
//! Anonymous identity management for mesh networks.
//!
//! # Overview
//!
//! This module provides:
//! - Anonymous node identities for mesh routing
//! - Fuzzy tags for metadata-resistant message detection
//! - Ring membership proofs
//!
//! # Security Properties
//!
//! | Property | Description |
//! |----------|-------------|
//! | Anonymity | Node identity cannot be linked to real identity |
//! | Unlinkability | Different messages cannot be linked to same sender |
//! | Metadata resistance | Fuzzy tags prevent traffic analysis |
//! | Plausible deniability | Cannot prove specific node sent message |

pub mod node_identity;
pub mod fuzzy_tag;

pub use node_identity::{MeshNodeId, MeshKeyPair, MeshSignature};
pub use fuzzy_tag::{FuzzyTagSecretKey, FuzzyTagPublicKey, FuzzyTag, DetectionKey};
