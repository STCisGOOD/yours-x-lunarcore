//! Error types for bedrock-core
//!
//! Centralized error handling for all cryptographic operations.

use thiserror::Error;

/// Result type for bedrock operations
pub type Result<T> = std::result::Result<T, BedrockError>;

/// Error codes for JNI interface (must match Kotlin side)
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Success = 0,

    // General errors (1-99)
    InvalidInput = 1,
    BufferTooSmall = 2,
    OutOfMemory = 3,
    InternalError = 4,
    SerializationError = 5,
    DeserializationError = 6,

    // Cryptographic errors (100-199)
    InvalidPoint = 100,
    InvalidScalar = 101,
    InvalidSignature = 102,
    InvalidProof = 103,
    VerificationFailed = 104,
    InvalidPublicKey = 105,
    InvalidSecretKey = 106,
    HashToCurveFailed = 107,
    PairingFailed = 108,

    // Credential errors (200-299)
    CredentialExpired = 200,
    CredentialRevoked = 201,
    AttributeNotFound = 202,
    IssuanceIncomplete = 203,
    InvalidCredential = 204,
    TooManyAttributes = 205,
    InvalidDisclosure = 206,

    // Token errors (300-399)
    RateLimitExceeded = 300,
    TokenAlreadySpent = 301,
    InvalidToken = 302,
    DispenserEmpty = 303,
    InvalidBlindFactor = 304,
    EpochMismatch = 305,
    TokensExhausted = 306,
    EpochExpired = 307,
    VOPRFVerificationFailed = 308,
    InvalidResponse = 309,

    // Ring signature errors (400-499)
    NotInRing = 400,
    RingTooSmall = 401,
    RingTooLarge = 402,
    InvalidRingSignature = 403,
    InvalidKeyImage = 404,

    // Device errors (500-599)
    DeviceKeyNotFound = 500,
    DeviceKeyGenerationFailed = 501,
    KeystoreError = 502,
    DeviceBindingFailed = 503,

    // Storage errors (600-699)
    DecryptionFailed = 600,
    CorruptedData = 601,
    StorageError = 602,
}

/// Main error type for bedrock-core
#[derive(Error, Debug)]
pub enum BedrockError {
    // General errors
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Buffer too small: needed {needed}, got {got}")]
    BufferTooSmall { needed: usize, got: usize },

    #[error("Out of memory")]
    OutOfMemory,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    // Cryptographic errors
    #[error("Invalid elliptic curve point")]
    InvalidPoint,

    #[error("Invalid scalar value")]
    InvalidScalar,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid zero-knowledge proof")]
    InvalidProof,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Hash to curve failed")]
    HashToCurveFailed,

    #[error("Pairing computation failed")]
    PairingFailed,

    // Credential errors
    #[error("Credential has expired")]
    CredentialExpired,

    #[error("Credential has been revoked")]
    CredentialRevoked,

    #[error("Attribute not found: {0}")]
    AttributeNotFound(String),

    #[error("Credential issuance incomplete")]
    IssuanceIncomplete,

    #[error("Invalid credential")]
    InvalidCredential,

    #[error("Too many attributes: max {max}, got {got}")]
    TooManyAttributes { max: usize, got: usize },

    #[error("Invalid selective disclosure")]
    InvalidDisclosure,

    // Token errors
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Token has already been spent")]
    TokenAlreadySpent,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token dispenser is empty")]
    DispenserEmpty,

    #[error("Invalid blind factor")]
    InvalidBlindFactor,

    #[error("Epoch mismatch")]
    EpochMismatch,

    #[error("Tokens exhausted")]
    TokensExhausted,

    #[error("Epoch expired")]
    EpochExpired,

    #[error("VOPRF verification failed")]
    VOPRFVerificationFailed,

    #[error("Invalid response")]
    InvalidResponse,

    // Ring signature errors
    #[error("Signer not in ring")]
    NotInRing,

    #[error("Ring too small: minimum {min}, got {got}")]
    RingTooSmall { min: usize, got: usize },

    #[error("Ring too large: maximum {max}, got {got}")]
    RingTooLarge { max: usize, got: usize },

    #[error("Invalid ring signature")]
    InvalidRingSignature,

    #[error("Invalid key image")]
    InvalidKeyImage,

    // Device errors
    #[error("Device key not found")]
    DeviceKeyNotFound,

    #[error("Device key generation failed: {0}")]
    DeviceKeyGenerationFailed(String),

    #[error("Keystore error: {0}")]
    KeystoreError(String),

    #[error("Device binding failed: {0}")]
    DeviceBindingFailed(String),

    // Storage errors
    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Corrupted data")]
    CorruptedData,

    #[error("Storage error: {0}")]
    StorageError(String),
}

impl BedrockError {
    /// Convert to error code for JNI
    pub fn to_code(&self) -> ErrorCode {
        match self {
            BedrockError::InvalidInput(_) => ErrorCode::InvalidInput,
            BedrockError::BufferTooSmall { .. } => ErrorCode::BufferTooSmall,
            BedrockError::OutOfMemory => ErrorCode::OutOfMemory,
            BedrockError::Internal(_) => ErrorCode::InternalError,
            BedrockError::Serialization(_) => ErrorCode::SerializationError,
            BedrockError::Deserialization(_) => ErrorCode::DeserializationError,

            BedrockError::InvalidPoint => ErrorCode::InvalidPoint,
            BedrockError::InvalidScalar => ErrorCode::InvalidScalar,
            BedrockError::InvalidSignature => ErrorCode::InvalidSignature,
            BedrockError::InvalidProof => ErrorCode::InvalidProof,
            BedrockError::VerificationFailed => ErrorCode::VerificationFailed,
            BedrockError::InvalidPublicKey => ErrorCode::InvalidPublicKey,
            BedrockError::InvalidSecretKey => ErrorCode::InvalidSecretKey,
            BedrockError::HashToCurveFailed => ErrorCode::HashToCurveFailed,
            BedrockError::PairingFailed => ErrorCode::PairingFailed,

            BedrockError::CredentialExpired => ErrorCode::CredentialExpired,
            BedrockError::CredentialRevoked => ErrorCode::CredentialRevoked,
            BedrockError::AttributeNotFound(_) => ErrorCode::AttributeNotFound,
            BedrockError::IssuanceIncomplete => ErrorCode::IssuanceIncomplete,
            BedrockError::InvalidCredential => ErrorCode::InvalidCredential,
            BedrockError::TooManyAttributes { .. } => ErrorCode::TooManyAttributes,
            BedrockError::InvalidDisclosure => ErrorCode::InvalidDisclosure,

            BedrockError::RateLimitExceeded => ErrorCode::RateLimitExceeded,
            BedrockError::TokenAlreadySpent => ErrorCode::TokenAlreadySpent,
            BedrockError::InvalidToken => ErrorCode::InvalidToken,
            BedrockError::DispenserEmpty => ErrorCode::DispenserEmpty,
            BedrockError::InvalidBlindFactor => ErrorCode::InvalidBlindFactor,
            BedrockError::EpochMismatch => ErrorCode::EpochMismatch,
            BedrockError::TokensExhausted => ErrorCode::TokensExhausted,
            BedrockError::EpochExpired => ErrorCode::EpochExpired,
            BedrockError::VOPRFVerificationFailed => ErrorCode::VOPRFVerificationFailed,
            BedrockError::InvalidResponse => ErrorCode::InvalidResponse,

            BedrockError::NotInRing => ErrorCode::NotInRing,
            BedrockError::RingTooSmall { .. } => ErrorCode::RingTooSmall,
            BedrockError::RingTooLarge { .. } => ErrorCode::RingTooLarge,
            BedrockError::InvalidRingSignature => ErrorCode::InvalidRingSignature,
            BedrockError::InvalidKeyImage => ErrorCode::InvalidKeyImage,

            BedrockError::DeviceKeyNotFound => ErrorCode::DeviceKeyNotFound,
            BedrockError::DeviceKeyGenerationFailed(_) => ErrorCode::DeviceKeyGenerationFailed,
            BedrockError::KeystoreError(_) => ErrorCode::KeystoreError,
            BedrockError::DeviceBindingFailed(_) => ErrorCode::DeviceBindingFailed,

            BedrockError::DecryptionFailed => ErrorCode::DecryptionFailed,
            BedrockError::CorruptedData => ErrorCode::CorruptedData,
            BedrockError::StorageError(_) => ErrorCode::StorageError,
        }
    }
}

impl From<bincode::Error> for BedrockError {
    fn from(e: bincode::Error) -> Self {
        BedrockError::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_unique() {
        // Ensure all error codes are unique
        let codes = [
            ErrorCode::Success,
            ErrorCode::InvalidInput,
            ErrorCode::BufferTooSmall,
            ErrorCode::InvalidPoint,
            ErrorCode::InvalidSignature,
            ErrorCode::CredentialExpired,
            ErrorCode::RateLimitExceeded,
            ErrorCode::NotInRing,
            ErrorCode::DeviceKeyNotFound,
            ErrorCode::DecryptionFailed,
        ];

        for (i, code1) in codes.iter().enumerate() {
            for (j, code2) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(*code1 as i32, *code2 as i32);
                }
            }
        }
    }

    #[test]
    fn test_error_to_code() {
        let err = BedrockError::InvalidSignature;
        assert_eq!(err.to_code(), ErrorCode::InvalidSignature);

        let err = BedrockError::RateLimitExceeded;
        assert_eq!(err.to_code(), ErrorCode::RateLimitExceeded);
    }
}
