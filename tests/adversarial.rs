use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{
    BlackChainPrivateKey, BlackChainPublicKey, BlackChainTxType,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property 1: Given any valid 64-byte seed, a transaction can be signed and its sender recovered.
    #[test]
    fn test_signature_roundtrip_prop(
        seed in any::<[u8; 64]>(),
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        gas_limit in any::<u64>(),
        value_u128 in any::<u128>(),
        to_addr in any::<Option<[u8; 20]>>(),
        tx_data in any::<Vec<u8>>(),
    ) {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let expected_address = pub_key.derive_address();

        let to = to_addr.map(|bytes| Address::from_slice(&bytes));
        let value = U256::from(value_u128);

        let mut tx = BlackChainTxType {
            chain_id,
            nonce,
            max_priority_fee_per_gas: U256::from(1_500_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit,
            to,
            value,
            data: Bytes::from(tx_data),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        };

        // Sign the transaction
        tx.sign_transaction(&priv_key).expect("signing failed");

        // Verify recovery matches derived address
        let recovered = tx.recover_sender().expect("recovery failed");
        assert_eq!(recovered, expected_address);
    }

    /// Property 2: Mutating any byte of a valid signature or transaction payload must fail verification or recover a different sender, but NEVER panic.
    #[test]
    fn test_signature_mutation_never_panics(
        seed in any::<[u8; 64]>(),
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        gas_limit in any::<u64>(),
        value_u128 in any::<u128>(),
        to_addr in any::<Option<[u8; 20]>>(),
        tx_data in any::<Vec<u8>>(),
        mutation_index in 0..10000usize,
        mutation_val in 1..255u8,
        target_field in 0..6u8,
    ) {
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let expected_address = pub_key.derive_address();

        let to = to_addr.map(|bytes| Address::from_slice(&bytes));
        let value = U256::from(value_u128);

        let mut tx = BlackChainTxType {
            chain_id,
            nonce,
            max_priority_fee_per_gas: U256::from(1_500_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit,
            to,
            value,
            data: Bytes::from(tx_data),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        };

        tx.sign_transaction(&priv_key).expect("signing failed");

        let mut mutated = true;

        // Mutate based on randomized target_field selection
        match target_field {
            0 => {
                // Mutate pqc_signature
                if let Some(ref mut sig) = tx.pqc_signature
                    && !sig.is_empty() {
                    let idx = mutation_index % sig.len();
                    let mut sig_mut = sig.to_vec();
                    sig_mut[idx] ^= mutation_val;
                    tx.pqc_signature = Some(Bytes::from(sig_mut));
                } else {
                    mutated = false;
                }
            }
            1 => {
                // Mutate pub_key bytes
                if let Some(ref mut pk) = tx.pub_key
                    && !pk.is_empty() {
                    let idx = mutation_index % pk.len();
                    let mut pk_mut = pk.to_vec();
                    pk_mut[idx] ^= mutation_val;
                    tx.pub_key = Some(Bytes::from(pk_mut));
                } else {
                    mutated = false;
                }
            }
            2 => {
                // Mutate transaction chain_id
                tx.chain_id ^= mutation_val as u64;
            }
            3 => {
                // Mutate transaction nonce
                tx.nonce ^= mutation_val as u64;
            }
            4 => {
                // Mutate transaction value
                tx.value ^= U256::from(mutation_val);
            }
            5 => {
                // Mutate transaction data
                if !tx.data.is_empty() {
                    let idx = mutation_index % tx.data.len();
                    let mut data_mut = tx.data.to_vec();
                    data_mut[idx] ^= mutation_val;
                    tx.data = Bytes::from(data_mut);
                } else {
                    mutated = false;
                }
            }
            _ => unreachable!(),
        }

        // Recovery must either fail with an error or recover a different address, but NEVER panic
        match tx.recover_sender() {
            Ok(recovered) => {
                // If it succeeded and a mutation occurred, it must not be the correct address
                if mutated {
                    assert_ne!(recovered, expected_address);
                }
            }
            Err(_) => {
                // Errors are expected and valid outcomes for signature verification failure
            }
        }
    }

    /// Property 3: Passing completely random/malformed bytes of arbitrary length to public key deserialization must never panic.
    #[test]
    fn test_public_key_from_random_bytes_never_panics(
        bytes in any::<Vec<u8>>(),
    ) {
        // Assert that from_bytes handles any input without panicking
        let _ = BlackChainPublicKey::from_bytes(&bytes);
    }
}
