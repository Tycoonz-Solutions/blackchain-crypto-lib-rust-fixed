#![forbid(unsafe_code)]

pub mod api;
#[cfg(test)]
mod attack_vectors;
pub mod crypto;
pub mod dilithium;
pub mod error;
pub mod hdwallet;
pub mod mdecc;
pub mod sign;
pub mod transaction;

/// WebAssembly / JavaScript bindings for browser wallet extensions.
/// Gated behind the off-by-default `browser` feature so that neither native
/// builds nor the Substrate runtime's own wasm32 build pull in wasm-bindgen;
/// only `wasm-pack build --features browser` compiles this module.
#[cfg(feature = "browser")]
pub mod wasm;

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

