#![no_main]
use libfuzzer_sys::fuzz_target;
use blackchain_crypto_lib_rust::BlackChainTxType;
use alloy_rlp::Decodable;

fuzz_target!(|data: &[u8]| {
    let mut data_slice = data;
    if let Ok(tx) = BlackChainTxType::decode(&mut data_slice) {
        let _hash = tx.signature_hash();
        let _ = tx.recover_sender();
    }
});
