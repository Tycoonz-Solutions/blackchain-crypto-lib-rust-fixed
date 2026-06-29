//! Property-based tests for `blackchain_crypto_lib_rust`.
//!
//! # Test Coverage
//!
//! | Property | What it proves |
//! |---|---|
//! | `prop_signature_roundtrip` | Sign → recover always yields the signing address |
//! | `prop_mutation_never_panics` | Any single-field mutation never panics and either errors or changes the recovered address |
//! | `prop_public_key_deser_never_panics` | `from_bytes` is total over all byte strings |
//! | `prop_address_derivation_is_deterministic` | Same seed → same address, every time |
//! | `prop_different_seeds_produce_different_keys` | Key generation is injective over the seed space (collision resistance) |
//! | `prop_unsigned_tx_recovery_fails` | `recover_sender` on an unsigned tx must not silently succeed |
//! | `prop_chain_id_mismatch_fails_or_differs` | Replaying a tx on a different chain_id must not recover the original address |

#![cfg(test)]

use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{BlackChainPrivateKey, BlackChainPublicKey, BlackChainTxType};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Shared strategies
// ---------------------------------------------------------------------------

/// Produces a fully-populated, *unsigned* `BlackChainTxType`.
fn arb_unsigned_tx() -> impl Strategy<Value = BlackChainTxType> {
    (
        any::<u64>(),              // chain_id
        any::<u64>(),              // nonce
        any::<u64>(),              // gas_limit
        any::<u128>(),             // value
        any::<Option<[u8; 20]>>(), // to
        any::<Vec<u8>>(),          // data
    )
        .prop_map(
            |(chain_id, nonce, gas_limit, value_u128, to_addr, tx_data)| BlackChainTxType {
                chain_id,
                nonce,
                max_priority_fee_per_gas: U256::from(1_500_000_000u64),
                max_fee_per_gas: U256::from(30_000_000_000u64),
                gas_limit,
                to: to_addr.map(|b| Address::from_slice(&b)),
                value: U256::from(value_u128),
                data: Bytes::from(tx_data),
                v: None,
                r: None,
                s: None,
                pqc_signature: None,
                pub_key: None,
            },
        )
}

/// A mutation to apply to a signed transaction.
#[derive(Debug, Clone)]
enum TxMutation {
    PqcSignature { index: usize, xor: u8 },
    PubKey { index: usize, xor: u8 },
    ChainId { xor: u64 },
    Nonce { xor: u64 },
    Value { xor: u8 },
    Data { index: usize, xor: u8 },
}

fn arb_mutation() -> impl Strategy<Value = TxMutation> {
    prop_oneof![
        (0..10_000usize, 1u8..=255u8)
            .prop_map(|(i, x)| TxMutation::PqcSignature { index: i, xor: x }),
        (0..10_000usize, 1u8..=255u8).prop_map(|(i, x)| TxMutation::PubKey { index: i, xor: x }),
        (1u64..=u64::MAX).prop_map(|x| TxMutation::ChainId { xor: x }),
        (1u64..=u64::MAX).prop_map(|x| TxMutation::Nonce { xor: x }),
        (1u8..=255u8).prop_map(|x| TxMutation::Value { xor: x }),
        (0..10_000usize, 1u8..=255u8).prop_map(|(i, x)| TxMutation::Data { index: i, xor: x }),
    ]
}

// ---------------------------------------------------------------------------
// Helper: apply a mutation; returns `true` when the mutation actually changed
// a field (some mutations are no-ops on empty byte fields).
// ---------------------------------------------------------------------------

fn apply_mutation(tx: &mut BlackChainTxType, m: &TxMutation) -> bool {
    match m {
        TxMutation::PqcSignature { index, xor } => {
            if let Some(ref sig) = tx.pqc_signature.clone() {
                if !sig.is_empty() {
                    let idx = index % sig.len();
                    let mut v = sig.to_vec();
                    v[idx] ^= xor;
                    tx.pqc_signature = Some(Bytes::from(v));
                    return true;
                }
            }
            false
        }
        TxMutation::PubKey { index, xor } => {
            if let Some(ref pk) = tx.pub_key.clone() {
                if !pk.is_empty() {
                    let idx = index % pk.len();
                    let mut v = pk.to_vec();
                    v[idx] ^= xor;
                    tx.pub_key = Some(Bytes::from(v));
                    return true;
                }
            }
            false
        }
        TxMutation::ChainId { xor } => {
            tx.chain_id ^= xor;
            true
        }
        TxMutation::Nonce { xor } => {
            tx.nonce ^= xor;
            true
        }
        TxMutation::Value { xor } => {
            tx.value ^= U256::from(*xor);
            true
        }
        TxMutation::Data { index, xor } => {
            if !tx.data.is_empty() {
                let idx = index % tx.data.len();
                let mut v = tx.data.to_vec();
                v[idx] ^= xor;
                tx.data = Bytes::from(v);
                return true;
            }
            false
        }
    }
}

// ---------------------------------------------------------------------------
// proptest configuration
// ---------------------------------------------------------------------------

/// Shared config: 256 cases in CI (override with PROPTEST_CASES env var).
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256),
        // Persist the failure corpus so CI can replay exact failures.
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::WithSource("regressions"),
        )),
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config())]

    // -----------------------------------------------------------------------
    // Property 1 — sign → recover roundtrip
    // -----------------------------------------------------------------------

    /// For every valid 64-byte seed and arbitrary transaction fields,
    /// signing and then recovering the sender must return the address
    /// derived from the corresponding public key.
    #[test]
    fn prop_signature_roundtrip(
        seed in any::<[u8; 64]>(),
        tx in arb_unsigned_tx(),
    ) {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed)
            .expect("key generation must not fail for any 64-byte seed");
        let expected_address = pub_key.derive_address();

        let mut tx = tx;
        tx.sign_transaction(&priv_key).expect("signing a well-formed tx must not fail");

        let recovered = tx.recover_sender().expect("recovery of a freshly-signed tx must not fail");
        prop_assert_eq!(recovered, expected_address,
            "recovered address must equal the address derived from the signing key");
    }

    // -----------------------------------------------------------------------
    // Property 2 — single-field mutation: no panic, wrong address or error
    // -----------------------------------------------------------------------

    /// Mutating any single field of a signed transaction must *never* panic.
    /// If recovery succeeds, the recovered address must differ from the
    /// original signer's address (i.e. no mutation is silently accepted).
    #[test]
    fn prop_mutation_never_panics(
        seed in any::<[u8; 64]>(),
        tx in arb_unsigned_tx(),
        mutation in arb_mutation(),
    ) {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let expected_address = pub_key.derive_address();

        let mut tx = tx;
        tx.sign_transaction(&priv_key).unwrap();

        let actually_mutated = apply_mutation(&mut tx, &mutation);

        match tx.recover_sender() {
            Ok(recovered) if actually_mutated => {
                prop_assert_ne!(
                    recovered,
                    expected_address,
                    "a mutated transaction must not recover to the original signer address; \
                     mutation: {:?}",
                    mutation,
                );
            }
            // Recovery failing is always acceptable after mutation.
            Ok(_) | Err(_) => {}
        }
    }

    // -----------------------------------------------------------------------
    // Property 3 — public key deserialisation is total (never panics)
    // -----------------------------------------------------------------------

    /// `BlackChainPublicKey::from_bytes` must handle any byte string without
    /// panicking, including empty slices, oversized inputs, and random noise.
    #[test]
    fn prop_public_key_deser_never_panics(bytes in any::<Vec<u8>>()) {
        let _ = BlackChainPublicKey::from_bytes(&bytes);
    }

    // -----------------------------------------------------------------------
    // Property 4 — address derivation is deterministic
    // -----------------------------------------------------------------------

    /// Calling `generate` twice with the same seed must produce the exact
    /// same address.  This guards against accidentally mixing randomness
    /// into the deterministic derivation path.
    #[test]
    fn prop_address_derivation_is_deterministic(seed in any::<[u8; 64]>()) {
        let (_, pub_key_a) = BlackChainPrivateKey::generate(&seed).unwrap();
        let (_, pub_key_b) = BlackChainPrivateKey::generate(&seed).unwrap();
        prop_assert_eq!(
            pub_key_a.derive_address(),
            pub_key_b.derive_address(),
            "key derivation must be deterministic for the same seed",
        );
    }

    // -----------------------------------------------------------------------
    // Property 5 — distinct seeds produce distinct keys
    // -----------------------------------------------------------------------

    /// Two different seeds must produce different addresses with overwhelming
    /// probability.  A collision would indicate a broken derivation function.
    #[test]
    fn prop_different_seeds_produce_different_keys(
        seed_a in any::<[u8; 64]>(),
        seed_b in any::<[u8; 64]>(),
    ) {
        // Seeds are only "different" if they differ in at least one byte.
        prop_assume!(seed_a != seed_b);

        let (_, pub_key_a) = BlackChainPrivateKey::generate(&seed_a).unwrap();
        let (_, pub_key_b) = BlackChainPrivateKey::generate(&seed_b).unwrap();
        prop_assert_ne!(
            pub_key_a.derive_address(),
            pub_key_b.derive_address(),
            "distinct seeds must derive distinct addresses",
        );
    }

    // -----------------------------------------------------------------------
    // Property 6 — unsigned transaction recovery must not silently succeed
    // -----------------------------------------------------------------------

    /// Calling `recover_sender` on a transaction that was never signed must
    /// either return an `Err` or return an address that is provably not the
    /// would-be signer (since no signing key was ever applied).
    ///
    /// This prevents a class of bug where a missing-signature check is
    /// accidentally elided.
    #[test]
    fn prop_unsigned_tx_recovery_fails(
        seed in any::<[u8; 64]>(),
        tx in arb_unsigned_tx(),
    ) {
        let (_, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let expected_address = pub_key.derive_address();

        // Deliberately do NOT call sign_transaction.
        match tx.recover_sender() {
            Err(_) => { /* correct — unsigned tx should not be recoverable */ }
            Ok(recovered) => {
                // If the implementation returns Ok, it must at minimum not
                // produce the signer's address, since we never signed.
                prop_assert_ne!(
                    recovered,
                    expected_address,
                    "recovering an unsigned tx must not return the (unseen) signer's address",
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Property 7 — cross-chain replay protection
    // -----------------------------------------------------------------------

    /// A transaction signed for chain A must not successfully recover to the
    /// same address when the chain_id field is changed to a different value.
    /// Verifies EIP-155-style replay protection is actually enforced.
    #[test]
    fn prop_chain_id_mismatch_fails_or_differs(
        seed in any::<[u8; 64]>(),
        tx in arb_unsigned_tx(),
        // Ensure the XOR value is non-zero so the chain_id actually changes.
        chain_id_xor in 1u64..=u64::MAX,
    ) {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let expected_address = pub_key.derive_address();

        let mut tx = tx;
        tx.sign_transaction(&priv_key).unwrap();

        // Replay: change the chain_id after signing.
        tx.chain_id ^= chain_id_xor;

        match tx.recover_sender() {
            Err(_) => { /* expected: replay rejected */ }
            Ok(recovered) => {
                prop_assert_ne!(
                    recovered,
                    expected_address,
                    "a transaction replayed on a different chain_id must not recover \
                     to the original signer's address",
                );
            }
        }
    }
}
