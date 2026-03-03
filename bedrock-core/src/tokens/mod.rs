//! Rate-Limiting Tokens (Tier 3)
//!
//! Anonymous rate-limiting using VOPRF-based tokens.
//!
//! # Overview
//!
//! This module implements Privacy Pass-style tokens:
//! - User obtains k tokens per epoch from issuer
//! - Each token can be spent once (tracked by nullifier)
//! - Tokens are unlinkable to each other and to issuance
//!
//! # Security Properties
//!
//! | Property | Description |
//! |----------|-------------|
//! | Anonymity | Tokens cannot be linked to issuance |
//! | Unlinkability | Different tokens from same user are unlinkable |
//! | Rate-limiting | User cannot exceed k tokens per epoch |
//! | Double-spend prevention | Same token cannot be spent twice |
//!
//! # Protocol
//!
//! 1. **Issuance**:
//!    - User blinds input: `blinded = r * H(input)`
//!    - Issuer evaluates: `evaluated = sk * blinded`
//!    - User unblinds: `token = (1/r) * evaluated = sk * H(input)`
//!
//! 2. **Redemption**:
//!    - User presents token with context
//!    - Verifier checks VOPRF proof
//!    - Verifier records nullifier to prevent double-spend

pub mod voprf;
pub mod privacy_pass;
pub mod rate_limiter;

pub use voprf::{VOPRFServer, VOPRFClient, VOPRFBlindState, VOPRFProof};
pub use privacy_pass::{TokenDispenser, AnonymousToken, TokenRedemption, DispenserRequest, DispenserResponse};
pub use rate_limiter::{RateLimitConfig, TokenBucket, EpochInfo};
