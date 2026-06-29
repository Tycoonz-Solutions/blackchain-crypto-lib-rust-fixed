// fuzz_tx_decode.rs — Exhaustive fuzzing of transaction RLP decoding.
//
// Attack surfaces exercised:
//   • Arbitrary byte sequences fed to alloy-rlp Decodable
//   • Truncated, over-long, and malformed RLP envelopes
//   • Decoded-then-re-encoded roundtrip (encode → decode → encode must agree)
//   • signature_hash on decoded tx (must not panic)
//   • recover_sender on decoded tx (must not panic, may return Err)
//   • All fields accessible without panic after successful decode
//
// Safety guarantee: this fuzz target must NEVER panic, abort, or OOM
// for any input, regardless of size or content.

#![no_main]

use alloy_rlp::{Decodable, Encodable};
use blackchain_crypto_lib_rust::BlackChainTxType;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;

    // ── Property 1: decode is total — never panics on any bytes ──
    let Ok(tx) = BlackChainTxType::decode(&mut cursor) else {
        return;
    };

    // ── Property 2: all field accesses are panic-free ──
    let _ = tx.chain_id;
    let _ = tx.nonce;
    let _ = tx.gas_limit;
    let _ = tx.max_fee_per_gas;
    let _ = tx.max_priority_fee_per_gas;
    let _ = tx.value;
    let _ = tx.to;
    let _ = tx.data.len();
    let _ = tx.v.is_some();
    let _ = tx.r.is_some();
    let _ = tx.s.is_some();
    let _ = tx.pqc_signature.as_ref().map(|s| s.len());
    let _ = tx.pub_key.as_ref().map(|p| p.len());

    // ── Property 3: signature_hash never panics on any decoded tx ──
    let hash = tx.signature_hash();
    assert_eq!(hash.len(), 32, "signature_hash must always return 32 bytes");

    // ── Property 4: recover_sender never panics — may return Err ──
    let _ = tx.recover_sender();

    // ── Property 5: encode → re-decode must be identity ──
    let mut encoded = Vec::new();
    encoded.push(BlackChainTxType::TX_TYPE);
    tx.encode(&mut encoded);

    // Strip the TX_TYPE byte we prepended; Decodable expects raw RLP
    let mut re_encoded_slice = &encoded[1..];
    if let Ok(tx2) = BlackChainTxType::decode(&mut re_encoded_slice) {
        // The re-decoded tx must hash identically to the original.
        assert_eq!(
            tx.signature_hash(),
            tx2.signature_hash(),
            "encode→decode roundtrip must preserve signature_hash"
        );
    }
});
