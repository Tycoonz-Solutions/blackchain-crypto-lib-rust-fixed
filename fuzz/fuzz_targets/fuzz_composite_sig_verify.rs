// fuzz_composite_sig_verify.rs — Fuzz the composite signature verifier.
//
// This target exercises the most security-critical code path: recover_sender.
// It constructs a structurally plausible signed transaction and then replaces
// the pqc_signature bytes with arbitrary fuzzer-controlled data.
//
// Attack surfaces exercised:
//   • Truncated composite signatures (< minimum size)
//   • Wrong Dilithium5 signature bytes
//   • Wrong P-521 DER signature (variable-length field)
//   • Wrong Ed448 signature (last 114 bytes)
//   • Completely random composite blobs of all lengths
//   • Correct-length but all-zero / all-0xff signatures
//   • Signatures from a different message or key
//
// Invariants:
//   • recover_sender must NEVER panic for any input
//   • If it returns Ok(addr), addr must differ from the known signer addr
//     (since the fuzzer-provided sig cannot be a valid composite sig)

#![no_main]

use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{BlackChainPrivateKey, BlackChainTxType};
use libfuzzer_sys::fuzz_target;

/// Deterministic seed so key generation is free (no CSPRNG in hot path).
const FIXED_SEED: [u8; 64] = {
    let mut s = [0u8; 64];
    // Simple compile-time fill: byte i = (i*7 + 13) % 256
    let mut i = 0usize;
    while i < 64 {
        s[i] = ((i * 7 + 13) % 256) as u8;
        i += 1;
    }
    s
};

// Pre-initialised at startup to avoid keygen in every fuzzing iteration.
// libfuzzer is single-threaded, so a global lazy init is fine.
use std::sync::OnceLock;

static KEY: OnceLock<(BlackChainPrivateKey, Address)> = OnceLock::new();

fn key_and_addr() -> &'static (BlackChainPrivateKey, Address) {
    KEY.get_or_init(|| {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&FIXED_SEED)
            .expect("keygen must succeed for fixed seed");
        let addr = pub_key.derive_address();
        (priv_key, addr)
    })
}

fuzz_target!(|data: &[u8]| {
    let (priv_key, signer_addr) = key_and_addr();

    // ── Build a valid signed tx to get correct pub_key field ──
    let mut tx = BlackChainTxType {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: U256::from(1_500_000_000u64),
        max_fee_per_gas: U256::from(30_000_000_000u64),
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xaa)),
        value: U256::from(1_000_000_000_000_000_000u64),
        data: Bytes::new(),
        v: Some(U256::from(2u64 + 35)), // EIP-155 placeholder for chain_id=1
        r: Some(U256::ZERO),
        s: Some(U256::ZERO),
        // Replace the real signature with arbitrary fuzzer bytes
        pqc_signature: Some(Bytes::from(data.to_vec())),
        pub_key: None,
    };

    // Use the real pub_key so the deserialisation step succeeds — this
    // isolates the *signature verification* path.
    let (_, pub_key) = BlackChainPrivateKey::generate(&FIXED_SEED).unwrap();
    tx.pub_key = Some(Bytes::from(pub_key.to_bytes()));

    // ── Invariant: recover_sender must NEVER panic ──
    match tx.recover_sender() {
        Ok(recovered) => {
            // A random sig must not pass as the known signer
            assert_ne!(
                recovered,
                *signer_addr,
                "fuzzer-provided sig must not verify as the signer's address"
            );
        }
        Err(_) => {
            // Expected: verification of random bytes should fail
        }
    }

    // ── Variation 2: also fuzz the pub_key bytes with the same data ──
    let mut tx2 = tx.clone();
    // Restore a plausible signature length to focus on the pub_key parser
    if let Ok(mut signed) = {
        let mut t = BlackChainTxType {
            chain_id: 1,
            nonce: 1,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            gas_limit: 21_000,
            to: None,
            value: U256::ZERO,
            data: Bytes::new(),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        };
        t.sign_transaction(priv_key).map(|()| t)
    } {
        // Replace pub_key with fuzzer data; keep real sig
        signed.pub_key = Some(Bytes::from(data.to_vec()));
        tx2 = signed;
    }
    let _ = tx2.recover_sender(); // must not panic
});
