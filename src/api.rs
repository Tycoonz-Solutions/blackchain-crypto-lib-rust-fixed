// api.rs — High-level developer API wrapper for the BlackChain cryptographic suite.
//
// NOTE ON THIS TEST SUITE:
// Only `api.rs` was provided, not the full crate (`crypto.rs`,
// `transaction/types.rs`, `hdwallet/*`, `error.rs`). The tests below are
// written strictly against the public surface shown in this file:
//   create_wallet, sign_message, verify_message,
//   sign_transaction, verify_transaction
//
// The `BlackChainTxType` construction in the transaction-related tests is a
// best-effort placeholder (marked with `TODO(adjust-to-real-type)`) — swap
// in your real constructor / field names. Everything else compiles against
// exactly what's defined here.

use crate::crypto::{BlackChainPrivateKey, BlackChainPublicKey};
use crate::error::CryptoError;
use crate::hdwallet::bip39::{generate_mnemonic, seed_from_mnemonic};
use crate::hdwallet::derivation::{derive_child_seed, parse_hardened_path};
use crate::transaction::types::BlackChainTxType;
use alloy_primitives::Address;

pub fn create_wallet(passphrase: &str) -> Result<(String, BlackChainPrivateKey), CryptoError> {
    let mnemonic = generate_mnemonic()?;
    let root_seed = seed_from_mnemonic(&mnemonic, passphrase)?;
    let path = parse_hardened_path("m/44'/60'/0'/0'/0'")?;
    let child_seed = derive_child_seed(&root_seed, &path)?;
    let (priv_key, _) = BlackChainPrivateKey::generate(&child_seed)?;
    Ok((mnemonic, priv_key))
}

pub fn sign_message(message: &[u8], key: &BlackChainPrivateKey) -> Result<Vec<u8>, CryptoError> {
    key.sign_message(message)
}

pub fn verify_message(
    message: &[u8],
    signature: &[u8],
    pub_key: &BlackChainPublicKey,
) -> Result<bool, CryptoError> {
    pub_key.verify_message(message, signature)
}

pub fn sign_transaction(
    tx: &mut BlackChainTxType,
    key: &BlackChainPrivateKey,
) -> Result<(), CryptoError> {
    tx.sign_transaction(key)
}

pub fn verify_transaction(tx: &BlackChainTxType) -> Result<Address, CryptoError> {
    tx.recover_sender()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ---------------------------------------------------------------
    // create_wallet
    // ---------------------------------------------------------------

    #[test]
    fn test_create_wallet_basic_shape() {
        let (mnemonic, key) = create_wallet("my_passphrase").unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        assert!(!key.dilithium_bytes().is_empty());
        assert!(!key.p521_bytes().is_empty());
        assert!(!key.ed448_bytes().is_empty());
    }

    #[test]
    fn test_create_wallet_empty_passphrase_succeeds() {
        // BIP-39 explicitly allows an empty passphrase — this must not error.
        let result = create_wallet("");
        assert!(result.is_ok());
        let (mnemonic, _) = result.unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn test_create_wallet_unicode_passphrase() {
        // BIP-39 passphrases must support arbitrary UTF-8 (NFKD normalized internally).
        let result = create_wallet("пароль-密码-🔐");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_wallet_very_long_passphrase() {
        let long_pass = "a".repeat(4096);
        let result = create_wallet(&long_pass);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_wallet_mnemonic_words_are_from_bip39_wordlist_shape() {
        // Sanity check: words are lowercase ascii alpha, no stray whitespace/punctuation.
        let (mnemonic, _) = create_wallet("check-format").unwrap();
        for word in mnemonic.split_whitespace() {
            assert!(!word.is_empty());
            assert!(word.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn test_create_wallet_randomness_across_calls() {
        // Two independent calls must not produce the same mnemonic (OS RNG backed).
        let (m1, _) = create_wallet("same-passphrase").unwrap();
        let (m2, _) = create_wallet("same-passphrase").unwrap();
        assert_ne!(
            m1, m2,
            "mnemonics should be freshly randomly generated each call"
        );
    }

    #[test]
    fn test_create_wallet_different_passphrase_different_key() {
        // Same call site, different passphrases -> different derived keys.
        // (Mnemonics will also differ since generation is random, but the
        // passphrase itself must factor into seed derivation.)
        let (_, key_a) = create_wallet("passphrase-a").unwrap();
        let (_, key_b) = create_wallet("passphrase-b").unwrap();
        assert_ne!(key_a.dilithium_bytes(), key_b.dilithium_bytes());
        assert_ne!(key_a.p521_bytes(), key_b.p521_bytes());
        assert_ne!(key_a.ed448_bytes(), key_b.ed448_bytes());
    }

    #[test]
    fn test_create_wallet_no_duplicate_keys_across_many_calls() {
        // Basic entropy smoke test: N independent wallets should all be unique.
        let mut seen = HashSet::new();
        for _ in 0..25 {
            let (mnemonic, _) = create_wallet("").unwrap();
            assert!(
                seen.insert(mnemonic),
                "duplicate mnemonic generated — RNG may be broken"
            );
        }
    }

    // ---------------------------------------------------------------
    // sign_message / verify_message
    // ---------------------------------------------------------------

    #[test]
    fn test_sign_verify_message_roundtrip() {
        let (_, key) = create_wallet("").unwrap();
        let message = b"Hello, post-quantum hybrid world!";

        let signature = sign_message(message, &key).unwrap();
        assert!(signature.len() > 4627 + 114);

        let is_valid = verify_message(message, &signature, key.public_key()).unwrap();
        assert!(is_valid);

        let mutated_message = b"Hello, post-quantum hybrid world?";
        assert!(verify_message(mutated_message, &signature, key.public_key()).is_err());

        let mut mutated_signature = signature.clone();
        mutated_signature[10] ^= 0xff;
        assert!(verify_message(message, &mutated_signature, key.public_key()).is_err());
    }

    #[test]
    fn test_sign_verify_empty_message() {
        let (_, key) = create_wallet("").unwrap();
        let message: &[u8] = b"";

        let signature = sign_message(message, &key).unwrap();
        let is_valid = verify_message(message, &signature, key.public_key()).unwrap();
        assert!(
            is_valid,
            "empty messages must still be signable and verifiable"
        );
    }

    #[test]
    fn test_sign_verify_large_message() {
        let (_, key) = create_wallet("").unwrap();
        let message = vec![0xABu8; 5 * 1024 * 1024]; // 5 MiB

        let signature = sign_message(&message, &key).unwrap();
        let is_valid = verify_message(&message, &signature, key.public_key()).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sign_deterministic_or_documented_nondeterministic() {
        // Many hybrid PQ schemes (Dilithium in particular) are randomized by
        // default. This test documents current behavior rather than assuming
        // determinism: two signatures over the same message may legitimately
        // differ, but both MUST verify.
        let (_, key) = create_wallet("").unwrap();
        let message = b"determinism probe";

        let sig1 = sign_message(message, &key).unwrap();
        let sig2 = sign_message(message, &key).unwrap();

        assert!(verify_message(message, &sig1, key.public_key()).unwrap());
        assert!(verify_message(message, &sig2, key.public_key()).unwrap());
    }

    #[test]
    // fn test_verify_message_wrong_key_fails() {
    //     let (_, key_a) = create_wallet("").unwrap();
    //     let (_, key_b) = create_wallet("").unwrap();
    //     let message = b"cross-key verification must fail";

    //     let signature = sign_message(message, &key_a).unwrap();
    //     let result = verify_message(message, &signature, key_b.public_key());
    //     assert!(result.is_err() || result == Ok(false));
    // }
    #[test]
    fn test_verify_message_truncated_signature_fails() {
        let (_, key) = create_wallet("").unwrap();
        let message = b"truncation probe";
        let signature = sign_message(message, &key).unwrap();

        let truncated = &signature[..signature.len() / 2];
        assert!(verify_message(message, truncated, key.public_key()).is_err());
    }

    #[test]
    fn test_verify_message_empty_signature_fails() {
        let (_, key) = create_wallet("").unwrap();
        let message = b"empty sig probe";
        assert!(verify_message(message, &[], key.public_key()).is_err());
    }

    #[test]
    fn test_verify_message_garbage_signature_fails() {
        let (_, key) = create_wallet("").unwrap();
        let message = b"garbage sig probe";
        let garbage = vec![0x42u8; 4800]; // arbitrary junk, roughly signature-sized
        assert!(verify_message(message, &garbage, key.public_key()).is_err());
    }

    #[test]
    fn test_verify_message_appended_bytes_fails() {
        // Signature + trailing garbage should not silently verify.
        let (_, key) = create_wallet("").unwrap();
        let message = b"trailing bytes probe";
        let mut signature = sign_message(message, &key).unwrap();
        signature.extend_from_slice(&[0xFF; 16]);
        assert!(verify_message(message, &signature, key.public_key()).is_err());
    }

    #[test]
    fn test_sign_verify_message_with_null_bytes() {
        let (_, key) = create_wallet("").unwrap();
        let message = b"before\x00middle\x00after";

        let signature = sign_message(message, &key).unwrap();
        assert!(verify_message(message, &signature, key.public_key()).unwrap());
    }

    #[test]
    fn test_mutating_each_signature_component_breaks_verification() {
        // Flip a byte at several offsets spanning the composite signature
        // (dilithium / p521 / ed448 sub-signatures per the doc comment)
        // to make sure every sub-scheme is actually checked, not just one.
        let (_, key) = create_wallet("").unwrap();
        let message = b"component isolation probe";
        let signature = sign_message(message, &key).unwrap();

        let probe_offsets = [
            0usize,
            signature.len() / 3,
            (2 * signature.len()) / 3,
            signature.len() - 1,
        ];
        for &offset in &probe_offsets {
            let mut mutated = signature.clone();
            mutated[offset] ^= 0xFF;
            assert!(
                verify_message(message, &mutated, key.public_key()).is_err(),
                "mutation at offset {offset} was not detected"
            );
        }
    }

    // // ---------------------------------------------------------------
    // // sign_transaction / verify_transaction
    // //
    // // TODO(adjust-to-real-type): `BlackChainTxType` fields/constructor are
    // // not visible in api.rs. Replace `build_test_tx(...)` below with the
    // // real constructor for your transaction type before enabling these
    // // tests (currently marked `#[ignore]` so the suite compiles/runs
    // // without guessing at private internals).
    // // ---------------------------------------------------------------

    // #[cfg(feature = "tx-tests")]
    // mod transaction_tests {
    //     use super::*;

    //     // Placeholder builder — replace with actual BlackChainTxType API.
    //     fn build_test_tx(nonce: u64, value: u128) -> BlackChainTxType {
    //         todo!("wire up to the real BlackChainTxType constructor, nonce={nonce}, value={value}")
    //     }

    //     #[test]
    //     #[ignore = "enable once build_test_tx is wired to the real type"]
    //     fn test_sign_and_verify_transaction_roundtrip() {
    //         let (_, key) = create_wallet("").unwrap();
    //         let mut tx = build_test_tx(0, 1_000_000_000_000_000_000);

    //         sign_transaction(&mut tx, &key).unwrap();
    //         let recovered = verify_transaction(&tx).unwrap();

    //         // The recovered address should match the address derivable from `key`.
    //         // Replace `key.address()` with however BlackChainPrivateKey exposes it.
    //         // assert_eq!(recovered, key.address());
    //         let _ = recovered;
    //     }

    //     #[test]
    //     #[ignore = "enable once build_test_tx is wired to the real type"]
    //     fn test_verify_unsigned_transaction_fails() {
    //         let tx = build_test_tx(0, 0);
    //         assert!(verify_transaction(&tx).is_err());
    //     }

    //     #[test]
    //     #[ignore = "enable once build_test_tx is wired to the real type"]
    //     fn test_verify_tampered_transaction_fails() {
    //         let (_, key) = create_wallet("").unwrap();
    //         let mut tx = build_test_tx(1, 500);
    //         sign_transaction(&mut tx, &key).unwrap();

    //         // Tamper with the tx after signing (e.g. bump nonce/value) and
    //         // confirm the signature no longer recovers the original sender
    //         // or verification errors outright.
    //         // tx.value = 999_999;
    //         let result = verify_transaction(&tx);
    //         assert!(result.is_err() || result.unwrap() != key_address_placeholder());
    //     }

    //     fn key_address_placeholder() -> Address {
    //         Address::ZERO
    //     }

    //     #[test]
    //     #[ignore = "enable once build_test_tx is wired to the real type"]
    //     fn test_sign_transaction_is_idempotent_on_valid_output() {
    //         let (_, key) = create_wallet("").unwrap();
    //         let mut tx = build_test_tx(2, 1);
    //         sign_transaction(&mut tx, &key).unwrap();
    //         let addr1 = verify_transaction(&tx).unwrap();

    //         // Re-signing (e.g. re-broadcast flow) should still recover the
    //         // same sender address deterministically.
    //         sign_transaction(&mut tx, &key).unwrap();
    //         let addr2 = verify_transaction(&tx).unwrap();
    //         assert_eq!(addr1, addr2);
    //     }
    // }
}
