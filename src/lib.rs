#![forbid(unsafe_code)]

pub mod api;
pub mod crypto;
pub mod dilithium;
pub mod error;
pub mod hdwallet;
pub mod mdecc;
pub mod sign;
pub mod transaction;

pub use api::{create_wallet, sign_message, verify_message, sign_transaction, verify_transaction};
pub use crypto::{BlackChainPrivateKey, BlackChainPublicKey, ALGO_ID, COMPOSITE_PK_SIZE, VERSION};
pub use error::CryptoError;
pub use hdwallet::bip39::{generate_mnemonic, seed_from_mnemonic, validate_mnemonic};
pub use hdwallet::derivation::{
    derive_child_seed, derive_mdecc_curve_seed, parse_hardened_path, CURVE_ID_ED448, CURVE_ID_P521,
};
pub use sign::{PrivateKey, PublicKey, Scheme};
pub use transaction::types::BlackChainTxType;
pub use transaction::signing::verify_signature;
pub use zeroize::Zeroizing;

