// wasm.rs — WebAssembly / JavaScript bindings for browser wallet extensions.
//
// This module is compiled ONLY for `wasm32` targets (see the gated `pub mod
// wasm` in lib.rs); it has zero effect on native builds. It exposes a small,
// JS-callable surface over the high-level `api` so a wallet extension's
// background/service-worker can create wallets, show an address, and sign
// messages and transactions without ever handling raw key material in JS.
//
// Build (produces the .wasm + JS glue an extension imports):
//   RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
//     wasm-pack build --target web --release
// (The RUSTFLAGS line is already provided by .cargo/config.toml.)
//
// ## Security model for extension authors
//
// * `BlackWallet` keeps the `BlackChainPrivateKey` inside wasm linear memory.
//   JS receives only the mnemonic (for the user to back up), the address, the
//   public key, and signatures — never the private sub-keys. Do not add getters
//   that return private-key bytes.
// * A wallet is defined by its mnemonic. Persist the mnemonic **encrypted at
//   rest** (e.g. WebCrypto AES-GCM with a key derived from the user's unlock
//   password); never store it in plaintext `localStorage`. Reconstruct the
//   wallet with `BlackWallet.fromMnemonic` on unlock.
// * wasm linear memory is not a secure enclave and cannot be reliably zeroized
//   from JS's perspective; treat the unlocked in-memory wallet as sensitive and
//   drop it (`wallet.free()`) when locking.
// * Randomness comes from the host `crypto.getRandomValues` via getrandom's
//   wasm_js backend — a CSPRNG. Key generation quality matches native.

use wasm_bindgen::prelude::*;

use crate::api;
use crate::crypto::{BlackChainPrivateKey, BlackChainPublicKey};
use crate::transaction::types::BlackChainTxType;

/// Converts any `Display` error into a JS exception.
fn js_err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// Formats a 20-byte address as a `0x`-prefixed lowercase hex string.
fn addr_hex(pk: &BlackChainPublicKey) -> String {
    format!("0x{}", hex::encode(pk.derive_address().as_slice()))
}

/// An unlocked BlackChain wallet. Holds the composite private key in wasm
/// memory; JS interacts through the methods below and never sees private bytes.
#[wasm_bindgen]
pub struct BlackWallet {
    key: BlackChainPrivateKey,
    mnemonic: String,
}

#[wasm_bindgen]
impl BlackWallet {
    /// Creates a brand-new wallet with a fresh 24-word mnemonic.
    ///
    /// Call `mnemonic()` immediately afterwards to show the phrase to the user
    /// for backup, then persist it encrypted. `passphrase` is the optional
    /// BIP-39 passphrase (`""` for none).
    #[wasm_bindgen(js_name = create)]
    pub fn create(passphrase: &str) -> Result<BlackWallet, JsError> {
        let (mnemonic, key) = api::create_wallet(passphrase).map_err(js_err)?;
        Ok(Self { key, mnemonic })
    }

    /// Restores a wallet from a previously-backed-up mnemonic (import / unlock).
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<BlackWallet, JsError> {
        let key = api::restore_wallet(mnemonic, passphrase).map_err(js_err)?;
        Ok(Self {
            key,
            mnemonic: mnemonic.to_string(),
        })
    }

    /// Restores the wallet at HD account `index` (path `m/44'/60'/0'/0'/{index}'`).
    /// `fromMnemonic` is equivalent to `fromMnemonicAt(mnemonic, passphrase, 0)`.
    /// Lets a wallet extension offer multiple accounts from one mnemonic, matching
    /// the derivation used by `pqc-tx-test --index` and the chain-spec wallets.
    #[wasm_bindgen(js_name = fromMnemonicAt)]
    pub fn from_mnemonic_at(
        mnemonic: &str,
        passphrase: &str,
        index: u32,
    ) -> Result<BlackWallet, JsError> {
        use crate::hdwallet::bip39::seed_from_mnemonic;
        use crate::hdwallet::derivation::{derive_child_seed, parse_hardened_path};
        let root_seed = seed_from_mnemonic(mnemonic, passphrase).map_err(js_err)?;
        let path = parse_hardened_path(&format!("m/44'/60'/0'/0'/{index}'")).map_err(js_err)?;
        let child_seed = derive_child_seed(&root_seed, &path).map_err(js_err)?;
        let (key, _) = BlackChainPrivateKey::generate(&child_seed).map_err(js_err)?;
        Ok(Self {
            key,
            mnemonic: mnemonic.to_string(),
        })
    }

    /// The 24-word mnemonic backing this wallet. Show once for backup; do not
    /// log or persist in plaintext.
    #[wasm_bindgen(js_name = mnemonic)]
    pub fn mnemonic(&self) -> String {
        self.mnemonic.clone()
    }

    /// The `0x`-prefixed 20-byte account address.
    #[wasm_bindgen(js_name = address)]
    pub fn address(&self) -> String {
        addr_hex(self.key.public_key())
    }

    /// The serialized composite public key (`ML-DSA-87 ‖ P-521 ‖ Ed448`).
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_bytes()
    }

    /// Signs an arbitrary message, returning the composite signature bytes.
    #[wasm_bindgen(js_name = signMessage)]
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, JsError> {
        self.key.sign_message(message).map_err(js_err)
    }

    /// Signs a transaction supplied as JSON, returning the signed transaction as
    /// JSON (with `pqc_signature` / `pub_key` / `v` / `r` / `s` populated).
    ///
    /// The JSON shape matches `BlackChainTxType`'s serde representation.
    #[wasm_bindgen(js_name = signTransaction)]
    pub fn sign_transaction(&self, tx_json: &str) -> Result<String, JsError> {
        let mut tx: BlackChainTxType = serde_json::from_str(tx_json).map_err(js_err)?;
        tx.sign_transaction(&self.key).map_err(js_err)?;
        serde_json::to_string(&tx).map_err(js_err)
    }
}

/// Verifies a composite signature over `message` under `public_key`
/// (the bytes from `BlackWallet.publicKey`). Returns `true` iff all three
/// sub-signatures verify.
#[wasm_bindgen(js_name = verifyMessage)]
pub fn verify_message(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, JsError> {
    let pk = BlackChainPublicKey::from_bytes(public_key).map_err(js_err)?;
    // `verify_message` returns Err on any failed sub-check; normalise to bool.
    Ok(pk.verify_message(message, signature).unwrap_or(false))
}

/// Verifies a signed transaction (JSON) and returns the recovered sender
/// address (`0x`-prefixed). Errors if the transaction is unsigned or invalid.
#[wasm_bindgen(js_name = recoverSender)]
pub fn recover_sender(signed_tx_json: &str) -> Result<String, JsError> {
    let tx: BlackChainTxType = serde_json::from_str(signed_tx_json).map_err(js_err)?;
    let addr = tx.recover_sender().map_err(js_err)?;
    Ok(format!("0x{}", hex::encode(addr.as_slice())))
}

/// Validates a 24-word BIP-39 mnemonic (word count + checksum) without deriving
/// a wallet. Useful for import-form validation.
#[wasm_bindgen(js_name = validateMnemonic)]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    crate::hdwallet::bip39::validate_mnemonic(mnemonic)
}
