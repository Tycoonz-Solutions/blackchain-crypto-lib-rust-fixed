use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
    
    #[error("Signature error: {0}")]
    SignatureError(String),
    
    #[error("RLP error: {0}")]
    RlpError(#[from] alloy_rlp::Error),
    
    #[error("BIP39 error: {0}")]
    Bip39Error(#[from] bip39::Error),

    #[error("Elliptic Curve error: {0}")]
    CurveError(String),

    #[error("Hex decoding error: {0}")]
    HexError(String),

    #[error("Seed error: {0}")]
    SeedError(String),

    #[error("Custom error: {0}")]
    Custom(String),
}
