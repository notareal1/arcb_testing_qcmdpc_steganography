// error.rs -- ARCB v4.0
// Unified error types.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ArcError {
    #[error("Decoding failed: bit-flipping decoder did not converge")]
    DecodeError,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Authentication failed: AEAD tag mismatch")]
    AuthFailed,

    #[error("Key generation failed: could not find invertible polynomial")]
    KeyGenError,

    #[error("Algebraic error: {0}")]
    AlgebraicError(String),

    #[error("Stego error: {0}")]
    StegoError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("RNG error: {0}")]
    RngError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type ArcResult<T> = std::result::Result<T, ArcError>;
