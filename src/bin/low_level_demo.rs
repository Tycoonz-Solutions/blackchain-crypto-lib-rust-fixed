use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{
    ALGO_ID, BlackChainTxType, CURVE_ID_ED448, CURVE_ID_P521, VERSION, derive_child_seed,
    derive_mdecc_curve_seed,
    dilithium::{
        PRIVATE_KEY_SIZE as DIL_SK_SIZE, PUBLIC_KEY_SIZE as DIL_PK_SIZE,
        SEED_SIZE as DIL_SEED_SIZE, new_key_from_seed as dil_key_from_seed,
    },
    generate_mnemonic,
    mdecc::ed448::{
        PRIVATE_KEY_SIZE as ED448_SK_SIZE, PUBLIC_KEY_SIZE as ED448_PK_SIZE,
        PublicKey as Ed448PublicKey, SEED_SIZE as ED448_SEED_SIZE,
        new_key_from_seed as ed448_key_from_seed,
    },
    mdecc::p521::{
        P521PublicKey, P521Scheme, PRIVATE_KEY_SIZE as P521_SK_SIZE,
        PUBLIC_KEY_SIZE as P521_PK_SIZE, SEED_SIZE as P521_SEED_SIZE,
    },
    parse_hardened_path, seed_from_mnemonic,
    sign::TypedScheme,
};
use sha3::{
    Digest, Keccak256, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================================");
    println!("    BLACKCHAIN HYBRID CRYPTOGRAPHIC SUITE - STEP-BY-STEP EXECUTION DEMO   ");
    println!("=========================================================================");

    // -------------------------------------------------------------------------
    // Step 1: Generate Mnemonic (BIP-39, 24 Words)
    // -------------------------------------------------------------------------
    println!("\n[STEP 1] Generating 24-word Mnemonic Phrase...");
    let mnemonic = generate_mnemonic()?;
    println!("  Mnemonic Phrase: \"{}\"", mnemonic);

    // -------------------------------------------------------------------------
    // Step 2: Derive 64-byte BIP-39 Root Seed
    // -------------------------------------------------------------------------
    println!("\n[STEP 2] Deriving the 64-byte root seed using PBKDF2-HMAC-SHA512...");
    let passphrase = "my_custom_passphrase";
    let root_seed = seed_from_mnemonic(&mnemonic, passphrase)?;
    println!("  Root Seed derived successfully! (Protected in secure Zeroizing memory).");
    println!("  Root Seed Hex (64 bytes): {}", hex::encode(&*root_seed));

    // -------------------------------------------------------------------------
    // Step 3: Hardened BIP-32 Child Key Derivation
    // -------------------------------------------------------------------------
    let path_str = "m/44'/60'/0'/0'/0'";
    println!("\n[STEP 3] Parsing and Deriving Child Seed via BIP-32...");
    println!("  Target Derivation Path: \"{}\"", path_str);
    let path = parse_hardened_path(path_str)?;
    println!("  Parsed Hardened Indices: {:?}", path);

    let child_seed = derive_child_seed(&root_seed, &path)?;
    println!(
        "  Derived Child Seed Hex (64 bytes): {}",
        hex::encode(&child_seed)
    );

    // -------------------------------------------------------------------------
    // Step 4: Seed Partitioning
    // -------------------------------------------------------------------------
    println!("\n[STEP 4] Partitioning Child Seed for Hybrid Algorithm Suite...");

    // First 32 bytes (0..32): ML-DSA-87 seed
    let mut dil_seed = [0u8; DIL_SEED_SIZE];
    dil_seed.copy_from_slice(&child_seed[..DIL_SEED_SIZE]);
    println!("  - ML-DSA-87 Seed (Bytes 0..32 - 32 bytes):");
    println!("    0x{}", hex::encode(dil_seed));

    // Remaining 32 bytes (32..64): mdECC Master Seed (256 bits)
    let mdecc_seed = &child_seed[32..64];
    println!("  - mdECC Master Seed (Bytes 32..64 - 32 bytes):");
    println!("    0x{}", hex::encode(mdecc_seed));

    // -------------------------------------------------------------------------
    // Step 5: Sub-Key Generation - ML-DSA-87 (Post-Quantum)
    // -------------------------------------------------------------------------
    println!("\n[STEP 5] Generating ML-DSA-87 Keypair (Post-Quantum Lattice Signature)...");
    let (dil_pk, dil_sk) = dil_key_from_seed(&dil_seed);

    let mut dil_pk_buf = [0u8; DIL_PK_SIZE];
    dil_pk.pack(&mut dil_pk_buf);
    let mut dil_sk_buf = Zeroizing::new([0u8; DIL_SK_SIZE]);
    dil_sk.pack(&mut dil_sk_buf);

    println!(
        "  ML-DSA-87 Public Key ({} bytes, Prefix): 0x{}",
        DIL_PK_SIZE,
        hex::encode(&dil_pk_buf[..32])
    );
    println!(
        "  ML-DSA-87 Private Key ({} bytes, Prefix): 0x{}",
        DIL_SK_SIZE,
        hex::encode(&dil_sk_buf[..32])
    );

    // -------------------------------------------------------------------------
    // Step 6: Sub-Key Generation - NIST P-521 (Classical ECDSA)
    // -------------------------------------------------------------------------
    println!("\n[STEP 6] Deriving NIST P-521 Seed and Keypair...");
    println!(
        "  Deriving P-521 curve seed using domain separation (ID = {}) + SHAKE256 + HKDF...",
        CURVE_ID_P521
    );
    let p521_seed = derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_P521, P521_SEED_SIZE)?;
    println!(
        "  Derived P-521 Seed (66 bytes): 0x{}",
        hex::encode(&p521_seed)
    );

    let (p521_pk, p521_sk) = P521Scheme.derive_key_typed(&p521_seed);
    let p521_pk_bytes = p521_pk.as_bytes();
    let p521_sk_bytes = p521_sk.as_bytes();

    println!(
        "  P-521 Public Key ({} bytes uncompressed SEC1): 0x{}",
        P521_PK_SIZE,
        hex::encode(&p521_pk_bytes)
    );
    println!(
        "  P-521 Private Key ({} bytes scalar): 0x{}",
        P521_SK_SIZE,
        hex::encode(&p521_sk_bytes)
    );

    // -------------------------------------------------------------------------
    // Step 7: Sub-Key Generation - Ed448 (Classical Edwards Curve)
    // -------------------------------------------------------------------------
    println!("\n[STEP 7] Deriving Ed448 Seed and Keypair...");
    println!(
        "  Deriving Ed448 curve seed using domain separation (ID = {}) + SHAKE256 + HKDF...",
        CURVE_ID_ED448
    );
    let ed448_seed = derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_ED448, ED448_SEED_SIZE)?;
    println!(
        "  Derived Ed448 Seed (57 bytes): 0x{}",
        hex::encode(&ed448_seed)
    );

    let (ed448_pk, ed448_sk) = ed448_key_from_seed(&ed448_seed);
    let ed448_pk_bytes = ed448_pk.as_bytes();
    let ed448_sk_bytes = ed448_sk.as_bytes();

    println!(
        "  Ed448 Public Key ({} bytes): 0x{}",
        ED448_PK_SIZE,
        hex::encode(ed448_pk_bytes)
    );
    println!(
        "  Ed448 Private Key ({} bytes seed format): 0x{}",
        ED448_SK_SIZE,
        hex::encode(ed448_sk_bytes)
    );

    // -------------------------------------------------------------------------
    // Step 8: Merging Public Keys & Address Derivation
    // -------------------------------------------------------------------------
    println!("\n[STEP 8] Assembling Composite Public Key & Deriving Address...");

    // Concatenate all public keys
    let mut composite_pk_bytes = Vec::new();
    composite_pk_bytes.extend_from_slice(&dil_pk_buf);
    composite_pk_bytes.extend_from_slice(&p521_pk_bytes);
    composite_pk_bytes.extend_from_slice(&ed448_pk_bytes);
    println!(
        "  Composite Public Key Size: {} bytes (expected 2782)",
        composite_pk_bytes.len()
    );

    // Address = Keccak-256(Dil_PK ‖ P521_PK ‖ Ed448_PK)[12..32]
    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, &composite_pk_bytes);
    let hash = hasher.finalize();
    let derived_address = Address::from_slice(&hash[12..32]);
    println!("  Derived Wallet Address: {:?}", derived_address);

    // -------------------------------------------------------------------------
    // Step 9: Transaction Hashing
    // -------------------------------------------------------------------------
    println!("\n[STEP 9] Constructing Unsigned Transaction and Calculating Hash...");
    let unsigned_tx = BlackChainTxType {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: U256::from(2_000_000_000u64),
        max_fee_per_gas: U256::from(50_000_000_000u64),
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xbb)),
        value: U256::from(500_000_000_000_000_000u64), // 0.5 ETH
        data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    };

    // Unsigned transaction hashing path: 0x80 || RLP(Tx_unsigned)
    let tx_hash = unsigned_tx.signature_hash();
    println!(
        "  Unsigned Transaction Hash H (Keccak-256): 0x{}",
        hex::encode(tx_hash)
    );

    // -------------------------------------------------------------------------
    // Step 10: Cross-Algorithm Entanglement Protocol (nonce & H_combined)
    // -------------------------------------------------------------------------
    println!("\n[STEP 10] Executing Cross-Algorithm Entanglement Protocol...");

    // Entanglement nonce = SHAKE256("entangle" ‖ ALGO_ID ‖ VERSION ‖ address)[0..16]
    let mut shake1 = Shake256::default();
    Update::update(&mut shake1, b"entangle");
    Update::update(&mut shake1, &[ALGO_ID]);
    Update::update(&mut shake1, &[VERSION]);
    Update::update(&mut shake1, derived_address.as_slice());
    let mut entanglement_nonce = [0u8; 16];
    shake1.finalize_xof().read(&mut entanglement_nonce);
    println!(
        "  - Entanglement Nonce (16 bytes): 0x{}",
        hex::encode(entanglement_nonce)
    );

    // H_combined = SHAKE256(dil_pk ‖ p521_pk ‖ ed448_pk ‖ entg_nonce)[0..32]
    let mut shake2 = Shake256::default();
    Update::update(&mut shake2, &dil_pk_buf);
    Update::update(&mut shake2, &p521_pk_bytes);
    Update::update(&mut shake2, &ed448_pk_bytes);
    Update::update(&mut shake2, &entanglement_nonce);
    let mut h_combined = [0u8; 32];
    shake2.finalize_xof().read(&mut h_combined);
    println!(
        "  - H_combined Cross-Algorithm Binding Hash (32 bytes): 0x{}",
        hex::encode(h_combined)
    );

    // -------------------------------------------------------------------------
    // Step 11: Detached Signing on Domain-Separated Payloads
    // -------------------------------------------------------------------------
    println!("\n[STEP 11] Signing Messages with Sub-keys...");

    // 1. ML-DSA-87 signs transaction hash H directly
    println!("  - Signing transaction hash H with ML-DSA-87...");
    let dil_sig = dil_sk.sign_internal(&tx_hash);
    println!("    ML-DSA-87 Signature length: {} bytes", dil_sig.len());

    // 2. P-521 signs (H ‖ H_combined ‖ CURVE_ID_P521)
    println!("  - Signing (H ‖ H_combined ‖ P-521_ID) with P-521...");
    let p521_msg = [tx_hash.as_slice(), &h_combined, &[CURVE_ID_P521]].concat();
    let p521_sig = p521_sk.sign_msg(&p521_msg);
    println!(
        "    P-521 Signature length (variable DER): {} bytes",
        p521_sig.len()
    );

    // 3. Ed448 signs (H ‖ H_combined ‖ CURVE_ID_ED448)
    println!("  - Signing (H ‖ H_combined ‖ Ed448_ID) with Ed448...");
    let ed448_msg = [tx_hash.as_slice(), &h_combined, &[CURVE_ID_ED448]].concat();
    let ed448_sig = ed448_sk.sign_msg(&ed448_msg, None)?;
    println!("    Ed448 Signature length: {} bytes", ed448_sig.len());

    // Merge signatures: dil_sig ‖ p521_sig ‖ ed448_sig
    let mut composite_signature = Vec::new();
    composite_signature.extend_from_slice(&dil_sig);
    composite_signature.extend_from_slice(&p521_sig);
    composite_signature.extend_from_slice(&ed448_sig);
    println!(
        "  - Assembled Composite Signature length: {} bytes",
        composite_signature.len()
    );

    // -------------------------------------------------------------------------
    // Step 12: Verification and Sender Recovery (Step-by-Step Slicing)
    // -------------------------------------------------------------------------
    println!("\n[STEP 12] Simulating Verification & Sender Address Recovery...");

    // We assume we received only `composite_pk_bytes`, `composite_signature` and `tx_hash`
    println!("  Re-extracting sub-public keys from received public key bytes...");
    let rx_dil_pk_bytes = &composite_pk_bytes[..DIL_PK_SIZE];
    let rx_p521_pk_bytes = &composite_pk_bytes[DIL_PK_SIZE..DIL_PK_SIZE + P521_PK_SIZE];
    let rx_ed448_pk_bytes = &composite_pk_bytes[DIL_PK_SIZE + P521_PK_SIZE..];

    // Reconstruct the sender address
    let mut verify_hasher = Keccak256::new();
    Digest::update(&mut verify_hasher, &composite_pk_bytes);
    let verify_hash = verify_hasher.finalize();
    let verify_address = Address::from_slice(&verify_hash[12..32]);
    println!(
        "    Sender Address derived from public key: {:?}",
        verify_address
    );

    // Reconstruct the entanglement nonce and H_combined
    let mut v_shake1 = Shake256::default();
    Update::update(&mut v_shake1, b"entangle");
    Update::update(&mut v_shake1, &[ALGO_ID]);
    Update::update(&mut v_shake1, &[VERSION]);
    Update::update(&mut v_shake1, verify_address.as_slice());
    let mut v_entanglement_nonce = [0u8; 16];
    v_shake1.finalize_xof().read(&mut v_entanglement_nonce);

    let mut v_shake2 = Shake256::default();
    Update::update(&mut v_shake2, rx_dil_pk_bytes);
    Update::update(&mut v_shake2, rx_p521_pk_bytes);
    Update::update(&mut v_shake2, rx_ed448_pk_bytes);
    Update::update(&mut v_shake2, &v_entanglement_nonce);
    let mut v_h_combined = [0u8; 32];
    v_shake2.finalize_xof().read(&mut v_h_combined);

    println!(
        "    Reconstructed Entanglement Nonce: 0x{}",
        hex::encode(v_entanglement_nonce)
    );
    println!(
        "    Reconstructed H_combined Binding: 0x{}",
        hex::encode(v_h_combined)
    );

    // Slicing the composite signature
    println!("  Slicing composite signature from both ends...");
    let rx_dil_sig = &composite_signature[..dil_sig.len()];
    let rx_ed448_sig_offset = composite_signature.len() - ed448_sig.len();
    let rx_p521_sig = &composite_signature[dil_sig.len()..rx_ed448_sig_offset];
    let rx_ed448_sig = &composite_signature[rx_ed448_sig_offset..];

    println!(
        "    Sliced ML-DSA-87 signature length: {} bytes",
        rx_dil_sig.len()
    );
    println!(
        "    Sliced P-521 signature length:      {} bytes",
        rx_p521_sig.len()
    );
    println!(
        "    Sliced Ed448 signature length:      {} bytes",
        rx_ed448_sig.len()
    );

    // 1. Verify ML-DSA-87
    println!("  Verifying sub-signatures...");
    let parsed_dil_pk = DilPublicKey::from_bytes(rx_dil_pk_bytes)?;
    parsed_dil_pk.verify_internal(&tx_hash, rx_dil_sig)?;
    println!("    [ML-DSA-87] Signature is VALID.");

    // 2. Verify P-521
    let parsed_p521_pk = P521PublicKey::from_bytes(rx_p521_pk_bytes)?;
    let verify_p521_msg = [tx_hash.as_slice(), &v_h_combined, &[CURVE_ID_P521]].concat();
    parsed_p521_pk.verify_sig(&verify_p521_msg, rx_p521_sig)?;
    println!("    [NIST P-521] Signature is VALID.");

    // 3. Verify Ed448
    let parsed_ed448_pk = Ed448PublicKey::from_bytes(rx_ed448_pk_bytes)?;
    let verify_ed448_msg = [tx_hash.as_slice(), &v_h_combined, &[CURVE_ID_ED448]].concat();
    parsed_ed448_pk.verify_sig(&verify_ed448_msg, rx_ed448_sig, None)?;
    println!("    [Curve Ed448] Signature is VALID.");

    println!("\n[SUCCESS] All signatures verified successfully! recovered address is authentic.");
    println!("=========================================================================");
    Ok(())
}

// Re-expose public key type under alias so it is easy to import
type DilPublicKey = blackchain_crypto_lib_rust::dilithium::PublicKey;
