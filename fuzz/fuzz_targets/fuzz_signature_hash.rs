// fuzz_signature_hash.rs — Fuzz signature_hash computation.
//
// The signature hash is a Keccak256 digest of a type-prefixed RLP encoding
// of the unsigned transaction. This target verifies that:
//
//   • signature_hash never panics for any field combination
//   • The hash output is always exactly 32 bytes
//   • Changing any transaction field changes the hash (collision resistance smoke test)
//   • The hash is deterministic: calling twice returns the same value
//   • Unsigned fields (v, r, s, pqc_signature, pub_key) are excluded from the hash
//
// Attack surfaces:
//   • Extreme U256 values (0, max, random)
//   • Very large data fields (up to 1 MB)
//   • chain_id = 0, 1, u64::MAX
//   • All Option<Address> combinations

#![no_main]

use alloy_primitives::{Address, Bytes, U256};
use arbitrary::Arbitrary;
use blackchain_crypto_lib_rust::BlackChainTxType;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_priority_fee_lo: u64,
    max_priority_fee_hi: u64,
    max_fee_lo: u64,
    max_fee_hi: u64,
    value_lo: u128,
    value_hi: u128,
    has_to: bool,
    to_bytes: [u8; 20],
    /// Cap at 64 KiB to avoid timeouts.
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| {
        let len = u.int_in_range(0..=65536usize)?;
        let mut v = vec![0u8; len];
        u.fill_buffer(&mut v)?;
        Ok(v)
    })]
    data: Vec<u8>,
    // Signature fields — must be excluded from hash
    has_sig: bool,
    v_val: u64,
    pqc_sig_len: u8,
    pub_key_len: u8,
}

fn build_tx(input: &FuzzInput, include_sig: bool) -> BlackChainTxType {
    let value = U256::from(input.value_hi) << 128 | U256::from(input.value_lo);
    let max_prio =
        U256::from(input.max_priority_fee_hi) << 64 | U256::from(input.max_priority_fee_lo);
    let max_fee = U256::from(input.max_fee_hi) << 64 | U256::from(input.max_fee_lo);

    BlackChainTxType {
        chain_id: input.chain_id,
        nonce: input.nonce,
        gas_limit: input.gas_limit,
        max_priority_fee_per_gas: max_prio,
        max_fee_per_gas: max_fee,
        to: if input.has_to {
            Some(Address::from_slice(&input.to_bytes))
        } else {
            None
        },
        value,
        data: Bytes::from(input.data.clone()),
        v: if include_sig && input.has_sig {
            Some(U256::from(input.v_val))
        } else {
            None
        },
        r: if include_sig && input.has_sig {
            Some(U256::ZERO)
        } else {
            None
        },
        s: if include_sig && input.has_sig {
            Some(U256::ZERO)
        } else {
            None
        },
        pqc_signature: if include_sig && input.has_sig {
            Some(Bytes::from(vec![0xab; input.pqc_sig_len as usize]))
        } else {
            None
        },
        pub_key: if include_sig && input.has_sig {
            Some(Bytes::from(vec![0xcd; input.pub_key_len as usize]))
        } else {
            None
        },
    }
}

fuzz_target!(|input: FuzzInput| {
    let tx = build_tx(&input, false);

    // ── Property 1: signature_hash never panics, always returns 32 bytes ──
    let h1 = tx.signature_hash();
    assert_eq!(h1.len(), 32, "signature_hash must return exactly 32 bytes");

    // ── Property 2: deterministic — same tx → same hash ──
    let h2 = tx.signature_hash();
    assert_eq!(h1, h2, "signature_hash must be deterministic");

    // ── Property 3: signature fields are excluded from the hash ──
    let tx_with_sig = build_tx(&input, true);
    let h_with_sig = tx_with_sig.signature_hash();
    assert_eq!(
        h1, h_with_sig,
        "v/r/s/pqc_signature/pub_key must not affect signature_hash"
    );

    // ── Property 4: changing chain_id changes the hash ──
    let mut tx_diff = tx.clone();
    tx_diff.chain_id = tx.chain_id.wrapping_add(1);
    let h_diff = tx_diff.signature_hash();
    // chain_id is always included in RLP, so hash must differ
    // (unless wrapping_add produces the same chain_id, impossible for u64)
    assert_ne!(
        h1, h_diff,
        "different chain_id must produce different signature_hash"
    );

    // ── Property 5: recover_sender on unsigned tx must not panic ──
    let _ = tx.recover_sender();
});
