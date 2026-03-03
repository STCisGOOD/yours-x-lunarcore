//! Rate Limiter
//!
//! Token bucket implementation for anonymous rate limiting.
//!
//! # Overview
//!
//! This module provides:
//! - Epoch-based token management
//! - Double-spend prevention via nullifier tracking
//! - Configurable rate limits
//!
//! # Usage
//!
//! ```ignore
//! // Create rate limiter config
//! let config = RateLimitConfig {
//!     tokens_per_epoch: 100,
//!     epoch_duration_secs: 86400, // 24 hours
//! };
//!
//! // Client-side: token bucket
//! let mut bucket = TokenBucket::new(dispenser);
//! if bucket.can_spend() {
//!     let token = bucket.spend()?;
//!     // Send token to server
//! }
//!
//! // Server-side: nullifier store
//! let mut store = NullifierStore::new();
//! if store.verify_and_record(&redemption, &issuer_pk) {
//!     // Token is valid and not double-spent
//! }
//! ```

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::error::{BedrockError, Result};

use super::privacy_pass::{AnonymousToken, TokenDispenser, TokenRedemption};
use super::voprf::VOPRFPublicKey;

// ============================================================================
// Rate Limit Configuration
// ============================================================================

/// Rate limiting configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Number of tokens per epoch
    pub tokens_per_epoch: u32,
    /// Epoch duration in seconds
    pub epoch_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            tokens_per_epoch: 100,
            epoch_duration_secs: 86400, // 24 hours
        }
    }
}

impl RateLimitConfig {
    /// Get the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now / self.epoch_duration_secs
    }

    /// Get epoch info for a given timestamp.
    pub fn epoch_info(&self, timestamp: u64) -> EpochInfo {
        let epoch = timestamp / self.epoch_duration_secs;
        let start = epoch * self.epoch_duration_secs;
        let end = start + self.epoch_duration_secs;

        EpochInfo { epoch, start, end }
    }

    /// Check if a timestamp falls within a given epoch.
    pub fn is_in_epoch(&self, epoch: u64, timestamp: u64) -> bool {
        let info = self.epoch_info(timestamp);
        info.epoch == epoch
    }
}

/// Information about an epoch.
#[derive(Clone, Debug)]
pub struct EpochInfo {
    /// Epoch number
    pub epoch: u64,
    /// Start timestamp (unix seconds)
    pub start: u64,
    /// End timestamp (unix seconds)
    pub end: u64,
}

impl EpochInfo {
    /// Check if the epoch has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.end
    }

    /// Remaining time in epoch (seconds).
    pub fn remaining_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= self.end {
            0
        } else {
            self.end - now
        }
    }
}

// ============================================================================
// Token Bucket (Client Side)
// ============================================================================

/// Token bucket for rate-limited operations (client side).
///
/// Manages a dispenser and tracks token usage.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    /// Token dispenser
    dispenser: TokenDispenser,
    /// Configuration
    config: RateLimitConfig,
}

impl TokenBucket {
    /// Create a new token bucket with a dispenser.
    pub fn new(dispenser: TokenDispenser, config: RateLimitConfig) -> Self {
        TokenBucket { dispenser, config }
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u64 {
        self.dispenser.epoch
    }

    /// Check if the dispenser's epoch is still valid.
    pub fn is_epoch_valid(&self) -> bool {
        self.config.current_epoch() == self.dispenser.epoch
    }

    /// Get remaining tokens.
    pub fn remaining(&self) -> u32 {
        self.dispenser.remaining()
    }

    /// Check if a token can be spent.
    pub fn can_spend(&self) -> bool {
        self.is_epoch_valid() && self.dispenser.has_tokens()
    }

    /// Spend a token and create a redemption.
    pub fn spend(&mut self, context: &[u8]) -> Result<TokenRedemption> {
        if !self.is_epoch_valid() {
            return Err(BedrockError::EpochExpired);
        }

        let token = self.dispenser.dispense()?;
        Ok(token.redeem(context))
    }

    /// Get multiple tokens for batch operations.
    pub fn spend_batch(&mut self, contexts: &[&[u8]]) -> Result<Vec<TokenRedemption>> {
        if !self.is_epoch_valid() {
            return Err(BedrockError::EpochExpired);
        }

        if contexts.len() > self.remaining() as usize {
            return Err(BedrockError::TokensExhausted);
        }

        let mut redemptions = Vec::with_capacity(contexts.len());
        for context in contexts {
            let token = self.dispenser.dispense()?;
            redemptions.push(token.redeem(context));
        }
        Ok(redemptions)
    }

    /// Get info about the current epoch.
    pub fn epoch_info(&self) -> EpochInfo {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.config.epoch_info(now)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BedrockError::Deserialization(e.to_string()))
    }
}

// ============================================================================
// Nullifier Store (Server Side)
// ============================================================================

/// Nullifier store for double-spend prevention (server side).
///
/// Tracks which token nullifiers have been seen.
#[derive(Clone, Debug, Default)]
pub struct NullifierStore {
    /// Set of seen nullifiers
    nullifiers: HashSet<[u8; 32]>,
    /// Current epoch
    epoch: u64,
}

impl NullifierStore {
    /// Create a new nullifier store.
    pub fn new() -> Self {
        NullifierStore {
            nullifiers: HashSet::new(),
            epoch: 0,
        }
    }

    /// Set the current epoch, clearing old nullifiers.
    pub fn set_epoch(&mut self, epoch: u64) {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.nullifiers.clear();
        }
    }

    /// Check if a nullifier has been seen.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Record a nullifier.
    pub fn record(&mut self, nullifier: [u8; 32]) {
        self.nullifiers.insert(nullifier);
    }

    /// Verify a redemption and record if valid.
    ///
    /// Returns true if the token is valid and not double-spent.
    pub fn verify_and_record(
        &mut self,
        redemption: &TokenRedemption,
        issuer_pk: &VOPRFPublicKey,
    ) -> Result<()> {
        // Check epoch
        if redemption.token.epoch != self.epoch {
            return Err(BedrockError::EpochMismatch);
        }

        // Check for double-spend
        let nullifier = redemption.nullifier();
        if self.is_spent(&nullifier) {
            return Err(BedrockError::TokenAlreadySpent);
        }

        // Verify token
        if !redemption.verify(issuer_pk) {
            return Err(BedrockError::InvalidToken);
        }

        // Record nullifier
        self.record(nullifier);
        Ok(())
    }

    /// Get number of tokens spent in current epoch.
    pub fn spent_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Clear all nullifiers (for epoch transition).
    pub fn clear(&mut self) {
        self.nullifiers.clear();
    }
}

// ============================================================================
// Rate Limit Status
// ============================================================================

/// Rate limit status for a user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitStatus {
    /// Current epoch
    pub epoch: u64,
    /// Tokens remaining
    pub remaining: u32,
    /// Total tokens per epoch
    pub total: u32,
    /// Seconds until epoch resets
    pub reset_in_secs: u64,
}

impl RateLimitStatus {
    /// Check if any tokens are available.
    pub fn has_tokens(&self) -> bool {
        self.remaining > 0
    }

    /// Get usage percentage.
    pub fn usage_percent(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            ((self.total - self.remaining) as f64 / self.total as f64) * 100.0
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::privacy_pass::DispenserRequestState;
    use super::super::privacy_pass::DispenserResponse;
    use super::super::voprf::VOPRFServer;
    use rand::rngs::OsRng;

    fn create_test_bucket() -> TokenBucket {
        let mut rng = OsRng;
        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();
        let config = RateLimitConfig::default();
        let epoch = config.current_epoch();

        let (state, request) = DispenserRequestState::create(epoch, 5, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let dispenser = state.process_response(&response, &server_pk).unwrap();

        TokenBucket::new(dispenser, config)
    }

    #[test]
    fn test_token_bucket_basics() {
        let mut bucket = create_test_bucket();

        assert_eq!(bucket.remaining(), 5);
        assert!(bucket.can_spend());

        let redemption = bucket.spend(b"test context").unwrap();
        assert_eq!(bucket.remaining(), 4);

        // Nullifier should be deterministic
        let nullifier = redemption.nullifier();
        assert_eq!(nullifier.len(), 32);
    }

    #[test]
    fn test_token_bucket_exhaustion() {
        let mut bucket = create_test_bucket();

        // Spend all tokens
        for i in 0..5 {
            let result = bucket.spend(format!("context {}", i).as_bytes());
            assert!(result.is_ok());
        }

        assert_eq!(bucket.remaining(), 0);
        assert!(!bucket.can_spend());

        // Should fail when exhausted
        assert!(bucket.spend(b"more").is_err());
    }

    #[test]
    fn test_nullifier_store() {
        let mut rng = OsRng;
        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();
        let config = RateLimitConfig::default();
        let epoch = config.current_epoch();

        let (state, request) = DispenserRequestState::create(epoch, 2, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let mut dispenser = state.process_response(&response, &server_pk).unwrap();

        let token = dispenser.dispense().unwrap();
        let redemption = token.redeem(b"context");

        // Create nullifier store
        let mut store = NullifierStore::new();
        store.set_epoch(epoch);

        // First redemption should succeed
        assert!(store.verify_and_record(&redemption, &server_pk).is_ok());
        assert_eq!(store.spent_count(), 1);

        // Double spend should fail
        assert!(matches!(
            store.verify_and_record(&redemption, &server_pk),
            Err(BedrockError::TokenAlreadySpent)
        ));
    }

    #[test]
    fn test_epoch_transition() {
        let mut store = NullifierStore::new();
        store.set_epoch(1);

        let nullifier = [42u8; 32];
        store.record(nullifier);
        assert!(store.is_spent(&nullifier));

        // Transition to new epoch should clear nullifiers
        store.set_epoch(2);
        assert!(!store.is_spent(&nullifier));
        assert_eq!(store.spent_count(), 0);
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig {
            tokens_per_epoch: 100,
            epoch_duration_secs: 3600, // 1 hour
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let info = config.epoch_info(now);
        assert!(info.epoch > 0);
        assert!(info.start <= now);
        assert!(info.end > now);
        assert_eq!(info.end - info.start, 3600);
    }

    #[test]
    fn test_batch_spend() {
        let mut bucket = create_test_bucket();

        let contexts: Vec<&[u8]> = vec![b"ctx1", b"ctx2", b"ctx3"];
        let redemptions = bucket.spend_batch(&contexts).unwrap();

        assert_eq!(redemptions.len(), 3);
        assert_eq!(bucket.remaining(), 2);

        // All nullifiers should be different
        let nullifiers: Vec<_> = redemptions.iter().map(|r| r.nullifier()).collect();
        assert_ne!(nullifiers[0], nullifiers[1]);
        assert_ne!(nullifiers[1], nullifiers[2]);
    }

    #[test]
    fn test_bucket_serialization() {
        let bucket = create_test_bucket();

        let bytes = bucket.to_bytes();
        let recovered = TokenBucket::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.remaining(), bucket.remaining());
        assert_eq!(recovered.epoch(), bucket.epoch());
    }
}
