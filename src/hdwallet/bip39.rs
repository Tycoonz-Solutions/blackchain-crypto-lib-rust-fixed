// bip39 — BIP-39 mnemonic and seed utilities.
//
// Policy: only 256-bit entropy (24-word) mnemonics are allowed in BlackChain.
// 12-word (128-bit) mnemonics are intentionally not supported — the longer
// phrase provides stronger entropy for post-quantum key derivation.
//
// The seed returned by `seed_from_mnemonic` is wrapped in `Zeroizing` so the
// 64-byte root secret is scrubbed from memory when the value is dropped.

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Number of entropy bytes for a 24-word mnemonic (256 bits).
pub const ENTROPY_BYTES: usize = 32;

/// Expected word count enforced by this library.
pub const MNEMONIC_WORD_COUNT: usize = 24;

/// Generates a fresh 24-word BIP-39 mnemonic from 256 bits of OS entropy.
///
/// Returns `Err` if the OS RNG fails (extremely rare).
///
/// # Security
/// Uses `getrandom` which reads from `/dev/urandom` on Unix and
/// `BCryptGenRandom` on Windows — both are CSPRNG-backed.
pub fn generate_mnemonic() -> Result<String, CryptoError> {
    let mut entropy = Zeroizing::new(vec![0u8; ENTROPY_BYTES]);
    getrandom::fill(&mut entropy)
        .map_err(|e| CryptoError::Custom(e.to_string()))?;

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(CryptoError::Bip39Error)?;
    Ok(mnemonic.to_string())
}

/// Derives a 64-byte BIP-39 seed from a 24-word mnemonic phrase.
///
/// The optional `password` is used as the BIP-39 passphrase (salt).
/// An empty string `""` is the standard no-passphrase derivation.
///
/// Returns `Err` if:
/// - The mnemonic is not exactly 24 words.
/// - The mnemonic contains invalid BIP-39 words.
/// - The checksum is invalid.
///
/// # Security
/// The returned `Zeroizing<Vec<u8>>` will scrub the 64-byte root seed from
/// heap memory when it is dropped. Callers must not copy it into unprotected
/// buffers.
pub fn seed_from_mnemonic(phrase: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Enforce 24-word policy before parsing to give a clear error.
    let word_count = phrase.split_whitespace().count();
    if word_count != MNEMONIC_WORD_COUNT {
        return Err(CryptoError::Custom(format!(
            "BlackChain requires a {MNEMONIC_WORD_COUNT}-word mnemonic (256-bit entropy); got {word_count} words"
        )));
    }

    let mnemonic = Mnemonic::parse(phrase)
        .map_err(CryptoError::Bip39Error)?;

    Ok(Zeroizing::new(mnemonic.to_seed(password).to_vec()))
}

/// Validates a mnemonic phrase without deriving a seed.
///
/// Returns `true` only if the mnemonic is exactly 24 valid BIP-39 words
/// with a correct checksum.
pub fn validate_mnemonic(phrase: &str) -> bool {
    let word_count = phrase.split_whitespace().count();
    if word_count != MNEMONIC_WORD_COUNT {
        return false;
    }
    Mnemonic::parse(phrase).is_ok()
}
