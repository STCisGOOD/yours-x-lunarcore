//! Privacy Pass Token Protocol
//!
//! Implements anonymous tokens using VOPRF for rate limiting.
//!
//! # Overview
//!
//! This module provides:
//! - Token dispensers: Users obtain a batch of tokens from an issuer
//! - Anonymous tokens: Individual tokens that can be spent
//! - Token redemption: Spending tokens without linking to issuance
//!
//! # Protocol Flow
//!
//! 1. **Setup**: Issuer generates VOPRF keypair
//! 2. **Request**: User creates blinded token requests
//! 3. **Issue**: Issuer evaluates VOPRF on blinded inputs
//! 4. **Dispense**: User unblinds to get anonymous tokens
//! 5. **Redeem**: User spends token with verifier
//! 6. **Verify**: Verifier checks token and records nullifier

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BedrockError, Result};
use crate::pairing::bls12_381::{G1Point, Scalar, G1_COMPRESSED_SIZE, SCALAR_SIZE};
use crate::pairing::hash_to_curve::hash_to_scalar;

use super::voprf::{VOPRFBlindState, VOPRFClient, VOPRFProof, VOPRFPublicKey, VOPRFServer};

// ============================================================================
// Token Dispenser
// ============================================================================

/// Token dispenser containing a batch of tokens.
///
/// Users obtain a dispenser from the issuer and can dispense individual
/// anonymous tokens as needed.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenDispenser {
    /// Issuer's public key
    pub issuer_pk: VOPRFPublicKey,
    /// Epoch identifier
    pub epoch: u64,
    /// Maximum tokens available
    pub max_tokens: u32,
    /// Number of tokens dispensed
    pub dispensed: u32,
    /// Pre-computed token seeds
    token_seeds: Vec<TokenSeed>,
}

/// Internal seed for generating tokens.
#[derive(Clone, Serialize, Deserialize)]
struct TokenSeed {
    /// Token value (VOPRF output)
    token_value: G1Point,
    /// Unique nonce
    nonce: [u8; 32],
}

impl TokenDispenser {
    /// Create a new token dispenser from issuer response.
    pub fn new(
        issuer_pk: VOPRFPublicKey,
        epoch: u64,
        tokens: Vec<(G1Point, [u8; 32])>,
    ) -> Self {
        let max_tokens = tokens.len() as u32;
        let token_seeds = tokens
            .into_iter()
            .map(|(token_value, nonce)| TokenSeed { token_value, nonce })
            .collect();

        TokenDispenser {
            issuer_pk,
            epoch,
            max_tokens,
            dispensed: 0,
            token_seeds,
        }
    }

    /// Get the number of remaining tokens.
    pub fn remaining(&self) -> u32 {
        self.max_tokens - self.dispensed
    }

    /// Check if any tokens are available.
    pub fn has_tokens(&self) -> bool {
        self.dispensed < self.max_tokens
    }

    /// Dispense an anonymous token.
    pub fn dispense(&mut self) -> Result<AnonymousToken> {
        if !self.has_tokens() {
            return Err(BedrockError::TokensExhausted);
        }

        let idx = self.dispensed as usize;
        let seed = &self.token_seeds[idx];
        self.dispensed += 1;

        Ok(AnonymousToken {
            value: seed.token_value.clone(),
            nonce: seed.nonce,
            epoch: self.epoch,
        })
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
// Anonymous Token
// ============================================================================

/// A single anonymous token that can be spent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnonymousToken {
    /// Token value (VOPRF output)
    pub value: G1Point,
    /// Unique nonce
    pub nonce: [u8; 32],
    /// Epoch this token belongs to
    pub epoch: u64,
}

impl AnonymousToken {
    /// Compute the nullifier for this token.
    ///
    /// The nullifier is used to prevent double-spending.
    /// It's deterministic so the same token always produces the same nullifier.
    pub fn nullifier(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"TOKEN_NULLIFIER:");
        hasher.update(&self.value.to_bytes());
        hasher.update(&self.nonce);
        hasher.update(&self.epoch.to_le_bytes());
        let result = hasher.finalize();

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&result);
        nullifier
    }

    /// Create a redemption for this token.
    pub fn redeem(&self, context: &[u8]) -> TokenRedemption {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute context hash
        let mut hasher = Sha256::new();
        hasher.update(context);
        let context_hash = hasher.finalize();
        let mut context_bytes = [0u8; 32];
        context_bytes.copy_from_slice(&context_hash);

        TokenRedemption {
            token: self.clone(),
            context: context_bytes,
            timestamp,
        }
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
// Token Redemption
// ============================================================================

/// Token redemption request sent to a verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRedemption {
    /// The token being redeemed
    pub token: AnonymousToken,
    /// Service context (hashed)
    pub context: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

impl TokenRedemption {
    /// Verify the redemption.
    ///
    /// This checks that the token is valid for the given issuer.
    /// The verifier should also check that the nullifier hasn't been seen before.
    pub fn verify(&self, issuer_pk: &VOPRFPublicKey) -> bool {
        // Reconstruct the expected token input
        let input = Self::compute_token_input(&self.token.nonce, self.token.epoch);

        // Verify VOPRF evaluation
        VOPRFClient::verify_token(&input, &self.token.value, issuer_pk)
    }

    /// Get the nullifier for double-spend prevention.
    pub fn nullifier(&self) -> [u8; 32] {
        self.token.nullifier()
    }

    fn compute_token_input(nonce: &[u8; 32], epoch: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&epoch.to_le_bytes());
        input
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
// Dispenser Request/Response
// ============================================================================

/// Request for a token dispenser.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispenserRequest {
    /// Epoch being requested
    pub epoch: u64,
    /// Number of tokens requested
    pub num_tokens: u32,
    /// Blinded inputs
    pub blinded_inputs: Vec<G1Point>,
}

/// Client state during dispenser request.
///
/// Contains sensitive blinding factors - serialize only for trusted local storage.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct DispenserRequestState {
    /// Epoch
    #[zeroize(skip)]
    epoch: u64,
    /// Blind states for each token
    #[serde(skip)]
    blind_states: Vec<VOPRFBlindState>,
    /// Serialized blind states for recovery (encrypted blinding factors)
    #[zeroize(skip)]
    serialized_blinds: Vec<SerializedBlindState>,
    /// Nonces for each token
    #[zeroize(skip)]
    nonces: Vec<[u8; 32]>,
}

/// Serializable form of blind state (for local encrypted storage).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializedBlindState {
    input: Vec<u8>,
    blind_bytes: Vec<u8>,
    blinded_element_bytes: Vec<u8>,
    input_point_bytes: Vec<u8>,
}

impl DispenserRequestState {
    /// Create a new dispenser request.
    pub fn create<R: RngCore + CryptoRng>(
        epoch: u64,
        num_tokens: u32,
        rng: &mut R,
    ) -> (Self, DispenserRequest) {
        let mut blind_states = Vec::with_capacity(num_tokens as usize);
        let mut nonces = Vec::with_capacity(num_tokens as usize);
        let mut blinded_inputs = Vec::with_capacity(num_tokens as usize);

        for _ in 0..num_tokens {
            // Generate unique nonce
            let mut nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);
            nonces.push(nonce);

            // Compute token input
            let input = TokenRedemption::compute_token_input(&nonce, epoch);

            // Blind the input
            let blind_state = VOPRFClient::blind(&input, rng);
            blinded_inputs.push(blind_state.blinded_element().clone());
            blind_states.push(blind_state);
        }

        // Create serializable blind state backups
        let serialized_blinds = blind_states
            .iter()
            .map(|bs| SerializedBlindState {
                input: bs.input().to_vec(),
                blind_bytes: bs.blind_bytes().to_vec(),
                blinded_element_bytes: bs.blinded_element().to_bytes().to_vec(),
                input_point_bytes: bs.input_point_bytes().to_vec(),
            })
            .collect();

        let state = DispenserRequestState {
            epoch,
            blind_states,
            serialized_blinds,
            nonces,
        };

        let request = DispenserRequest {
            epoch,
            num_tokens,
            blinded_inputs,
        };

        (state, request)
    }

    /// Process the issuer's response to create a dispenser.
    pub fn process_response(
        self,
        response: &DispenserResponse,
        issuer_pk: &VOPRFPublicKey,
    ) -> Result<TokenDispenser> {
        if response.evaluations.len() != self.blind_states.len() {
            return Err(BedrockError::InvalidResponse);
        }

        let mut tokens = Vec::with_capacity(self.blind_states.len());

        for (i, blind_state) in self.blind_states.iter().enumerate() {
            let (evaluated, proof) = &response.evaluations[i];

            // Unblind to get token value
            let token_value = VOPRFClient::unblind(blind_state, evaluated, proof, issuer_pk)?;

            tokens.push((token_value, self.nonces[i]));
        }

        Ok(TokenDispenser::new(issuer_pk.clone(), self.epoch, tokens))
    }
}

/// Response from issuer with evaluated tokens.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispenserResponse {
    /// Epoch
    pub epoch: u64,
    /// Evaluated blinded inputs with proofs
    pub evaluations: Vec<(G1Point, VOPRFProof)>,
}

impl DispenserResponse {
    /// Create a response from a request (issuer side).
    pub fn create<R: RngCore + CryptoRng>(
        request: &DispenserRequest,
        server: &VOPRFServer,
        rng: &mut R,
    ) -> Self {
        let evaluations = request
            .blinded_inputs
            .iter()
            .map(|blinded| server.evaluate(blinded, rng))
            .collect();

        DispenserResponse {
            epoch: request.epoch,
            evaluations,
        }
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_dispenser_creation() {
        let mut rng = OsRng;

        // Setup issuer
        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        // Client creates request
        let epoch = 12345u64;
        let num_tokens = 10u32;
        let (state, request) = DispenserRequestState::create(epoch, num_tokens, &mut rng);

        assert_eq!(request.epoch, epoch);
        assert_eq!(request.num_tokens, num_tokens);
        assert_eq!(request.blinded_inputs.len(), num_tokens as usize);

        // Issuer creates response
        let response = DispenserResponse::create(&request, &server, &mut rng);

        assert_eq!(response.epoch, epoch);
        assert_eq!(response.evaluations.len(), num_tokens as usize);

        // Client processes response
        let dispenser = state.process_response(&response, &server_pk).unwrap();

        assert_eq!(dispenser.epoch, epoch);
        assert_eq!(dispenser.max_tokens, num_tokens);
        assert_eq!(dispenser.dispensed, 0);
        assert_eq!(dispenser.remaining(), num_tokens);
    }

    #[test]
    fn test_token_dispensing() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let (state, request) = DispenserRequestState::create(1, 3, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let mut dispenser = state.process_response(&response, &server_pk).unwrap();

        // Dispense tokens
        assert_eq!(dispenser.remaining(), 3);

        let token1 = dispenser.dispense().unwrap();
        assert_eq!(dispenser.remaining(), 2);

        let token2 = dispenser.dispense().unwrap();
        assert_eq!(dispenser.remaining(), 1);

        let token3 = dispenser.dispense().unwrap();
        assert_eq!(dispenser.remaining(), 0);

        // Should fail when exhausted
        assert!(dispenser.dispense().is_err());

        // All tokens should be different
        assert_ne!(token1.nonce, token2.nonce);
        assert_ne!(token2.nonce, token3.nonce);
    }

    #[test]
    fn test_token_redemption() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let (state, request) = DispenserRequestState::create(1, 1, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let mut dispenser = state.process_response(&response, &server_pk).unwrap();

        let token = dispenser.dispense().unwrap();
        let redemption = token.redeem(b"service context");

        // Verify redemption
        assert!(redemption.verify(&server_pk));
    }

    #[test]
    fn test_nullifier_uniqueness() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let (state, request) = DispenserRequestState::create(1, 2, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let mut dispenser = state.process_response(&response, &server_pk).unwrap();

        let token1 = dispenser.dispense().unwrap();
        let token2 = dispenser.dispense().unwrap();

        // Nullifiers should be different
        assert_ne!(token1.nullifier(), token2.nullifier());

        // Same token should produce same nullifier
        let redemption1 = token1.redeem(b"context1");
        let redemption2 = token1.redeem(b"context2");
        assert_eq!(redemption1.nullifier(), redemption2.nullifier());
    }

    #[test]
    fn test_wrong_issuer_verification() {
        let mut rng = OsRng;

        let server1 = VOPRFServer::new(&mut rng);
        let server2 = VOPRFServer::new(&mut rng);

        let (state, request) = DispenserRequestState::create(1, 1, &mut rng);
        let response = DispenserResponse::create(&request, &server1, &mut rng);
        let mut dispenser = state.process_response(&response, &server1.public_key()).unwrap();

        let token = dispenser.dispense().unwrap();
        let redemption = token.redeem(b"context");

        // Should verify with correct issuer
        assert!(redemption.verify(&server1.public_key()));

        // Should fail with wrong issuer
        assert!(!redemption.verify(&server2.public_key()));
    }

    #[test]
    fn test_dispenser_serialization() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let (state, request) = DispenserRequestState::create(42, 5, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let dispenser = state.process_response(&response, &server_pk).unwrap();

        // Serialize and deserialize
        let bytes = dispenser.to_bytes();
        let recovered = TokenDispenser::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.epoch, dispenser.epoch);
        assert_eq!(recovered.max_tokens, dispenser.max_tokens);
        assert_eq!(recovered.dispensed, dispenser.dispensed);
    }

    #[test]
    fn test_token_serialization() {
        let mut rng = OsRng;

        let server = VOPRFServer::new(&mut rng);
        let server_pk = server.public_key();

        let (state, request) = DispenserRequestState::create(1, 1, &mut rng);
        let response = DispenserResponse::create(&request, &server, &mut rng);
        let mut dispenser = state.process_response(&response, &server_pk).unwrap();

        let token = dispenser.dispense().unwrap();

        // Serialize and deserialize
        let bytes = token.to_bytes();
        let recovered = AnonymousToken::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.nonce, token.nonce);
        assert_eq!(recovered.epoch, token.epoch);
        assert_eq!(recovered.value, token.value);
    }
}
