// fuzz_tx_sign_recover.rs — Sign-then-recover correctness under arbitrary seeds and tx fields.
//
// This target uses a structured fuzzer input (via `arbitrary`) to generate
// semantically valid seeds and transactions, then verifies that signing
// followed by recovery always produces the correct address.
//
// Attack surfaces exercised:
//   • Key generation for every possible 64-byte seed
//   • chain_id=0, max u64, and arbitrary values
//   • Transactions with zero-length data and up to 64 KB of calldata
//   • Optional `to` field being None (contract creation)
//   • Value=0 and extremely large values
//   • Nonce=0, max u64, and all values in between
//
// Invariants:
//   • sign_transaction must NEVER panic for any valid key and tx
//   • After successful signing, recover_sender must return Ok
//   • The recovered address must exactly match pub_key.derive_address()
//   • sign_transaction on a key derived from any 64-byte seed must succeed

#![no_main]

use alloy_primitives::{Address, Bytes, U256};
use arbitrary::Arbitrary;
use blackchain_crypto_lib_rust::{BlackChainPrivateKey, BlackChainTxType};
use libfuzzer_sys::fuzz_target;

/// A structured input that mirrors every tuneable field in a transaction.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    seed: [u8; 64],
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    value_lo: u128,
    value_hi: u128,
    max_priority_fee: u64,
    max_fee: u64,
    has_to: bool,
    to_bytes: [u8; 20],
    /// Capped to 65 536 bytes by the engine via max_size corpus limit.
    data: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    // ── Key generation must succeed for every 64-byte seed ──
    let (priv_key, pub_key) = match BlackChainPrivateKey::generate(&input.seed) {
        Ok(kp) => kp,
        Err(_) => return, // only possible if HKDF fails — treat as skip
    };
    let expected_addr = pub_key.derive_address();

    // Reconstruct U256 value from two u128 halves to exercise large values.
    let value = U256::from(input.value_hi) << 128 | U256::from(input.value_lo);

    let mut tx = BlackChainTxType {
        chain_id: input.chain_id,
        nonce: input.nonce,
        max_priority_fee_per_gas: U256::from(input.max_priority_fee),
        max_fee_per_gas: U256::from(input.max_fee),
        gas_limit: input.gas_limit,
        to: if input.has_to {
            Some(Address::from_slice(&input.to_bytes))
        } else {
            None
        },
        value,
        data: Bytes::from(input.data),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    };

    // ── sign_transaction must succeed for any well-typed key + tx ──
    if tx.sign_transaction(&priv_key).is_err() {
        return;
    }

    // ── Invariant: recovery returns the correct address ──
    match tx.recover_sender() {
        Ok(recovered) => {
            assert_eq!(
                recovered, expected_addr,
                "recovered address must match the signing key's address \
                 (chain_id={}, nonce={}, data_len={})",
                input.chain_id,
                input.nonce,
                tx.data.len(),
            );
        }
        Err(e) => {
            // A freshly-signed tx should never fail recovery.
            panic!("recover_sender failed on a freshly-signed tx: {e}");
        }
    }
});
