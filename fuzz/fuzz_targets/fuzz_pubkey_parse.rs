// fuzz_pubkey_parse.rs — Exhaustive fuzzing of the composite public key parser.
//
// Attack surfaces exercised:
//   • Length boundary conditions (0, 1, COMPOSITE_PK_SIZE-1, COMPOSITE_PK_SIZE, COMPOSITE_PK_SIZE+1, large)
//   • Invalid sub-key byte patterns (all-zeros, all-0xff, off-curve points)
//   • Full serialization roundtrip: to_bytes → from_bytes must be identity
//   • Address derivation must not panic on any successfully-parsed key
//   • Component accessors (dilithium_bytes, p521_bytes, ed448_bytes) must
//     return slices of the correct lengths
//
// Safety guarantee: this fuzz target must NEVER panic, abort, or access
// memory out-of-bounds for any input.

#![no_main]

use blackchain_crypto_lib_rust::{BlackChainPublicKey, COMPOSITE_PK_SIZE};
use libfuzzer_sys::fuzz_target;

// Sub-key sizes (must match crypto.rs constants)
const DIL_PK_SIZE: usize = 2592;
const P521_PK_SIZE: usize = 133;
const ED448_PK_SIZE: usize = 57;

fuzz_target!(|data: &[u8]| {
    // ── Property 1: from_bytes is total — never panics on any byte string ──
    let result = BlackChainPublicKey::from_bytes(data);

    match result {
        Ok(pk) => {
            // ── Property 2: successful parse → component slice lengths correct ──
            assert_eq!(
                pk.dilithium_bytes().len(),
                DIL_PK_SIZE,
                "dilithium sub-key must be {DIL_PK_SIZE} bytes"
            );
            assert_eq!(
                pk.p521_bytes().len(),
                P521_PK_SIZE,
                "P-521 sub-key must be {P521_PK_SIZE} bytes"
            );
            assert_eq!(
                pk.ed448_bytes().len(),
                ED448_PK_SIZE,
                "Ed448 sub-key must be {ED448_PK_SIZE} bytes"
            );

            // ── Property 3: to_bytes returns the right size ──
            let bytes = pk.to_bytes();
            assert_eq!(bytes.len(), COMPOSITE_PK_SIZE);

            // ── Property 4: roundtrip — re-parsing must succeed and agree ──
            let pk2 = BlackChainPublicKey::from_bytes(&bytes)
                .expect("re-parsing to_bytes output must always succeed");
            assert_eq!(
                pk.to_bytes(),
                pk2.to_bytes(),
                "roundtrip must be identity"
            );

            // ── Property 5: address derivation never panics ──
            let addr = pk.derive_address();

            // ── Property 6: address from identical pk bytes must be the same ──
            let addr2 = pk2.derive_address();
            assert_eq!(addr, addr2, "same key bytes must yield same address");
        }
        Err(_) => {
            // Error is always acceptable; only the COMPOSITE_PK_SIZE-byte case
            // with valid sub-keys should ever succeed. Every shorter/longer/
            // corrupt input correctly returns Err.
        }
    }
});
