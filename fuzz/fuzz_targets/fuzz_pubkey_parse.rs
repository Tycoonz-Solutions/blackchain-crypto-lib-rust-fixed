#![no_main]
use libfuzzer_sys::fuzz_target;
use blackchain_crypto_lib_rust::BlackChainPublicKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(pubkey) = BlackChainPublicKey::from_bytes(data) {
        let _address = pubkey.derive_address();
    }
});
