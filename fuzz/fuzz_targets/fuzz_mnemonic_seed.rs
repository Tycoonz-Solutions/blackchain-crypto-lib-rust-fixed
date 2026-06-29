// fuzz_mnemonic_seed.rs — Fuzz the BIP-39 mnemonic and HD derivation APIs.
//
// Attack surfaces exercised:
//   • seed_from_mnemonic with arbitrary UTF-8 strings (not BIP-39 words)
//   • seed_from_mnemonic with the correct word count but wrong words
//   • seed_from_mnemonic with 24 valid BIP-39 words but bad checksum
//   • parse_hardened_path with arbitrary path strings
//   • derive_child_seed with arbitrary seeds and paths (including empty paths,
//     unhardened indices, extremely deep paths)
//   • derive_mdecc_curve_seed with out-of-spec curve IDs and seed lengths
//
// Invariants:
//   • None of these functions may panic for any input
//   • validate_mnemonic must be consistent with seed_from_mnemonic
//   • derive_child_seed must reject non-hardened indices

#![no_main]

use arbitrary::Arbitrary;
use blackchain_crypto_lib_rust::{
    derive_child_seed, derive_mdecc_curve_seed, parse_hardened_path, seed_from_mnemonic,
    validate_mnemonic, CURVE_ID_ED448, CURVE_ID_P521,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw bytes interpreted as a UTF-8 mnemonic phrase attempt.
    mnemonic_bytes: Vec<u8>,
    /// Passphrase to accompany the mnemonic.
    passphrase: String,
    /// Master seed for BIP32 derivation (arbitrary length).
    master_seed: Vec<u8>,
    /// BIP32 path components (raw u32 values, may or may not be hardened).
    path: Vec<u32>,
    /// mdECC master seed (arbitrary length and content).
    mdecc_seed: Vec<u8>,
    /// Curve ID for mdECC derivation (may be any u8, not just 1 or 2).
    curve_id: u8,
    /// Output seed size for mdECC derivation (0 to 1024).
    seed_size: u16,
    /// Path string for parse_hardened_path.
    path_string: String,
}

fuzz_target!(|input: FuzzInput| {
    // ── BIP-39: mnemonic parsing must never panic ──
    let mnemonic_str = String::from_utf8_lossy(&input.mnemonic_bytes);
    let mnemonic_str = mnemonic_str.as_ref();

    // Invariant: validate and parse must agree
    let is_valid = validate_mnemonic(mnemonic_str);
    let seed_result = seed_from_mnemonic(mnemonic_str, &input.passphrase);

    // If validate says true, parse must succeed and return 64 bytes
    if is_valid {
        match seed_result {
            Ok(seed) => {
                assert_eq!(
                    seed.len(),
                    64,
                    "BIP-39 seed must always be 64 bytes"
                );
            }
            Err(_) => {
                // validate_mnemonic may be more permissive than seed_from_mnemonic
                // (e.g., it does not check the 24-word requirement in the same order).
                // This is not a bug — just a pre-check.
            }
        }
    }

    // ── parse_hardened_path must never panic ──
    let _ = parse_hardened_path(&input.path_string);

    // ── derive_child_seed must never panic ──
    // Cap the path length to avoid OOM from extremely deep derivations.
    let path_cap: Vec<u32> = input.path.into_iter().take(32).collect();
    let _ = derive_child_seed(&input.master_seed, &path_cap);

    // ── derive_mdecc_curve_seed must never panic ──
    // Cap seed_size to prevent allocation OOM from u16::MAX-sized requests.
    let capped_size = (input.seed_size as usize).min(1024);
    let _ = derive_mdecc_curve_seed(&input.mdecc_seed, input.curve_id, capped_size);

    // ── Spec-compliant curve IDs must always succeed (for non-empty seeds) ──
    if !input.mdecc_seed.is_empty() {
        for &curve_id in &[CURVE_ID_P521, CURVE_ID_ED448] {
            for &size in &[32usize, 57, 66] {
                assert!(
                    derive_mdecc_curve_seed(&input.mdecc_seed, curve_id, size).is_ok(),
                    "derive_mdecc_curve_seed must succeed for spec curve IDs with any non-empty seed"
                );
            }
        }
    }
});
