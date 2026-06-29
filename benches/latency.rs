// benches/latency.rs — Production benchmark suite for blackchain-crypto-lib-rust.
//
// Measures wall-clock latency of every performance-critical operation in the
// BlackChain hybrid post-quantum cryptographic pipeline:
//
//   1. BIP-39 mnemonic generation & seed derivation
//   2. BIP-32 HD child-key derivation
//   3. Composite hybrid key generation (Dilithium5 + P-521 + Ed448)
//   4. Public key serialization / deserialization roundtrip
//   5. Address derivation (Keccak256)
//   6. Transaction signature hash computation (RLP + Keccak256)
//   7. Full transaction signing (three-algorithm composite)
//   8. Full transaction sender recovery (three-algorithm verification)
//
// Run:  cargo bench
// HTML: open target/criterion/report/index.html

use criterion::{criterion_group, criterion_main, black_box, Criterion, BenchmarkId};
use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{
    BlackChainPrivateKey, BlackChainPublicKey, BlackChainTxType,
    generate_mnemonic, seed_from_mnemonic,
    derive_child_seed, derive_mdecc_curve_seed,
    parse_hardened_path, CURVE_ID_P521, CURVE_ID_ED448,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic 64-byte seed for reproducible benchmarks.
fn fixed_seed() -> [u8; 64] {
    let mut seed = [0u8; 64];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = (i * 7 + 13) as u8;
    }
    seed
}

/// A realistic unsigned transaction template.
fn tx_template() -> BlackChainTxType {
    BlackChainTxType {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: U256::from(1_500_000_000u64),
        max_fee_per_gas: U256::from(30_000_000_000u64),
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xaa)),
        value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
        data: Bytes::new(),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    }
}

/// Same template but with a 1 KB calldata payload.
fn tx_template_with_data() -> BlackChainTxType {
    let mut tx = tx_template();
    tx.data = Bytes::from(vec![0xab; 1024]);
    tx
}

// ---------------------------------------------------------------------------
// Group 1: BIP-39 Mnemonic & Seed
// ---------------------------------------------------------------------------

fn bench_bip39(c: &mut Criterion) {
    let mut group = c.benchmark_group("bip39");
    group.sample_size(50); // mnemonic gen uses CSPRNG, keep samples reasonable

    group.bench_function("generate_mnemonic", |b| {
        b.iter(|| {
            let _ = generate_mnemonic().unwrap();
        });
    });

    let mnemonic = generate_mnemonic().unwrap();
    group.bench_function("seed_from_mnemonic", |b| {
        b.iter(|| {
            let _ = seed_from_mnemonic(black_box(&mnemonic), "");
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 2: BIP-32 HD Derivation
// ---------------------------------------------------------------------------

fn bench_hd_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hd_derivation");

    let seed = fixed_seed();
    let path = parse_hardened_path("m/44'/60'/0'/0'/0'").unwrap();

    group.bench_function("derive_child_seed", |b| {
        b.iter(|| {
            let _ = derive_child_seed(black_box(&seed), black_box(&path));
        });
    });

    // mdECC per-curve seed derivation
    let mdecc_master = &seed[32..48];
    group.bench_function("derive_mdecc_curve_seed_p521", |b| {
        b.iter(|| {
            let _ = derive_mdecc_curve_seed(
                black_box(mdecc_master),
                CURVE_ID_P521,
                66, // P521_SEED_SIZE
            );
        });
    });

    group.bench_function("derive_mdecc_curve_seed_ed448", |b| {
        b.iter(|| {
            let _ = derive_mdecc_curve_seed(
                black_box(mdecc_master),
                CURVE_ID_ED448,
                57, // ED448_SEED_SIZE
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 3: Hybrid Key Generation
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    let seed = fixed_seed();

    group.bench_function("hybrid_keygen_from_seed", |b| {
        b.iter(|| {
            let _ = BlackChainPrivateKey::generate(black_box(&seed));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 4: Public Key Serialization
// ---------------------------------------------------------------------------

fn bench_pubkey_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("pubkey_serde");

    let seed = fixed_seed();
    let (_, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
    let pk_bytes = pub_key.to_bytes();

    group.bench_function("pubkey_to_bytes", |b| {
        b.iter(|| {
            let _ = black_box(&pub_key).to_bytes();
        });
    });

    group.bench_function("pubkey_from_bytes", |b| {
        b.iter(|| {
            let _ = BlackChainPublicKey::from_bytes(black_box(&pk_bytes));
        });
    });

    group.bench_function("derive_address", |b| {
        b.iter(|| {
            let _ = black_box(&pub_key).derive_address();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 5: Transaction Hashing
// ---------------------------------------------------------------------------

fn bench_tx_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_hash");

    let tx_empty = tx_template();
    let tx_1kb = tx_template_with_data();

    group.bench_function("signature_hash_empty_data", |b| {
        b.iter(|| {
            let _ = black_box(&tx_empty).signature_hash();
        });
    });

    group.bench_function("signature_hash_1kb_data", |b| {
        b.iter(|| {
            let _ = black_box(&tx_1kb).signature_hash();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 6: Transaction Signing (full composite pipeline)
// ---------------------------------------------------------------------------

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    group.sample_size(20); // signing is expensive (~ms range)

    let seed = fixed_seed();
    let (priv_key, _) = BlackChainPrivateKey::generate(&seed).unwrap();

    group.bench_function("sign_tx_empty_data", |b| {
        b.iter(|| {
            let mut tx = tx_template();
            tx.sign_transaction(black_box(&priv_key)).unwrap();
        });
    });

    group.bench_function("sign_tx_1kb_data", |b| {
        b.iter(|| {
            let mut tx = tx_template_with_data();
            tx.sign_transaction(black_box(&priv_key)).unwrap();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 7: Transaction Recovery (full composite verification)
// ---------------------------------------------------------------------------

fn bench_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("recovery");
    group.sample_size(20);

    let seed = fixed_seed();
    let (priv_key, _) = BlackChainPrivateKey::generate(&seed).unwrap();

    let mut tx_signed = tx_template();
    tx_signed.sign_transaction(&priv_key).unwrap();

    let mut tx_signed_1kb = tx_template_with_data();
    tx_signed_1kb.sign_transaction(&priv_key).unwrap();

    group.bench_function("recover_sender_empty_data", |b| {
        b.iter(|| {
            let _ = black_box(&tx_signed).recover_sender();
        });
    });

    group.bench_function("recover_sender_1kb_data", |b| {
        b.iter(|| {
            let _ = black_box(&tx_signed_1kb).recover_sender();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 8: End-to-End Pipeline (mnemonic → sign → recover)
// ---------------------------------------------------------------------------

fn bench_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2e_pipeline");
    group.sample_size(10); // full pipeline is very expensive

    group.bench_function("keygen_sign_recover", |b| {
        let seed = fixed_seed();
        b.iter(|| {
            let (priv_key, pub_key) = BlackChainPrivateKey::generate(black_box(&seed)).unwrap();
            let expected_addr = pub_key.derive_address();

            let mut tx = tx_template();
            tx.sign_transaction(&priv_key).unwrap();

            let recovered = tx.recover_sender().unwrap();
            assert_eq!(recovered, expected_addr);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 9: Payload Size Scaling
// ---------------------------------------------------------------------------

fn bench_payload_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_scaling");
    group.sample_size(10);

    let seed = fixed_seed();
    let (priv_key, _) = BlackChainPrivateKey::generate(&seed).unwrap();

    for size in [0, 256, 1024, 4096, 16384] {
        group.bench_with_input(
            BenchmarkId::new("sign", format!("{size}B")),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut tx = tx_template();
                    tx.data = Bytes::from(vec![0xcd; size]);
                    tx.sign_transaction(black_box(&priv_key)).unwrap();
                });
            },
        );
    }

    for size in [0, 256, 1024, 4096, 16384] {
        let mut tx = tx_template();
        tx.data = Bytes::from(vec![0xcd; size]);
        tx.sign_transaction(&priv_key).unwrap();

        group.bench_with_input(
            BenchmarkId::new("recover", format!("{size}B")),
            &tx,
            |b, tx| {
                b.iter(|| {
                    let _ = black_box(tx).recover_sender();
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_bip39,
    bench_hd_derivation,
    bench_keygen,
    bench_pubkey_serde,
    bench_tx_hash,
    bench_signing,
    bench_recovery,
    bench_e2e,
    bench_payload_scaling,
);
criterion_main!(benches);
