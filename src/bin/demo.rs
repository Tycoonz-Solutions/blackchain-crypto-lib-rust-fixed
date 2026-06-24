use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{
    BlackChainPrivateKey, BlackChainTxType, derive_child_seed, generate_mnemonic,
    parse_hardened_path, seed_from_mnemonic,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================================");
    println!("        BLACKCHAIN HYBRID CRYPTOGRAPHIC SUITE - EXECUTION FLOW DEMO       ");
    println!("=========================================================================");

    // -------------------------------------------------------------------------
    // Step 1: Generate Mnemonic (24-word / 256-bit entropy policy)
    // -------------------------------------------------------------------------
    println!("\n[STEP 1] Generating a fresh 24-word mnemonic phrase...");
    let mnemonic = generate_mnemonic()?;
    println!("  Mnemonic Phrase:\n  \"{}\"", mnemonic);

    // -------------------------------------------------------------------------
    // Step 2: Generate Seed from Mnemonic (Zeroizing secret storage)
    // -------------------------------------------------------------------------
    println!("\n[STEP 2] Deriving the 64-byte root seed from the mnemonic...");
    let root_seed = seed_from_mnemonic(&mnemonic, "my_secure_passphrase")?;
    println!("  Root Seed derived successfully! (Protected in secure zeroizing memory).");
    println!("  Root Seed Hex (64 bytes): {}", hex::encode(&*root_seed));

    // -------------------------------------------------------------------------
    // Step 3: Parse Hardened Path & Derive Child Seed
    // -------------------------------------------------------------------------
    let path_str = "m/44'/60'/0'/0'/0'";
    println!("\n[STEP 3] Parsing HD derivation path: \"{}\"...", path_str);
    let path = parse_hardened_path(path_str)?;
    println!("  Hardened Path Indices: {:?}", path);

    println!("  Deriving child seed via BIP32 (Hardened-only path)...");
    let child_seed = derive_child_seed(&root_seed, &path)?;
    println!(
        "  Derived Child Seed Hex (64 bytes): {}",
        hex::encode(&child_seed)
    );

    // -------------------------------------------------------------------------
    // Step 4: Generate Composite Keypair (Dilithium5 + P-521 + Ed448)
    // -------------------------------------------------------------------------
    println!("\n[STEP 4] Generating hybrid keypair from the child seed...");
    let (priv_key, pub_key) = BlackChainPrivateKey::generate(&child_seed)?;
    println!("  Composite Private Key structure derived (Zeroized on drop).");
    println!(
        "    - Dilithium5 SK: {} bytes",
        priv_key.dilithium_bytes().len()
    );
    println!("    - P-521 SK: {} bytes", priv_key.p521_bytes().len());
    println!("    - Ed448 SK: {} bytes", priv_key.ed448_bytes().len());

    let pub_key_bytes = pub_key.to_bytes();
    println!(
        "  Composite Public Key serialized ({} bytes):",
        pub_key_bytes.len()
    );
    println!(
        "    - Dilithium5 PK: {} bytes (Prefix: 0x{})",
        pub_key.dilithium_bytes().len(),
        hex::encode(&pub_key.dilithium_bytes()[..8])
    );
    println!(
        "    - P-521 PK: {} bytes (Prefix: 0x{})",
        pub_key.p521_bytes().len(),
        hex::encode(&pub_key.p521_bytes()[..8])
    );
    println!(
        "    - Ed448 PK: {} bytes (Prefix: 0x{})",
        pub_key.ed448_bytes().len(),
        hex::encode(&pub_key.ed448_bytes()[..8])
    );

    // -------------------------------------------------------------------------
    // Step 5: Derive Wallet Address
    // -------------------------------------------------------------------------
    println!("\n[STEP 5] Deriving transaction/sender address...");
    let address = pub_key.derive_address();
    println!("  Derived Wallet Address: {:?}", address);

    // -------------------------------------------------------------------------
    // Step 6: Construct EIP-1559 Style Transaction
    // -------------------------------------------------------------------------
    println!("\n[STEP 6] Constructing an unsigned BlackChain EIP-1559 transaction...");
    let mut tx = BlackChainTxType {
        chain_id: 1,
        nonce: 12,
        max_priority_fee_per_gas: U256::from(1_500_000_000u64), // 1.5 gwei
        max_fee_per_gas: U256::from(30_000_000_000u64),         // 30 gwei
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xaa)),
        value: U256::from(100_000_000_000_000_000u64), // 0.1 ETH
        data: Bytes::from(vec![0xba, 0xad, 0xf0, 0x0d]),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    };

    let sig_hash = tx.signature_hash();
    println!("  Unsigned Tx Hash to sign: 0x{}", hex::encode(sig_hash));

    // -------------------------------------------------------------------------
    // Step 7: Sign Transaction In-Place
    // -------------------------------------------------------------------------
    println!("\n[STEP 7] Signing the transaction with hybrid private key...");
    println!(
        "  (This performs entanglement nonce expansion, H_combined binding, and signs across all 3 algorithms)"
    );
    tx.sign_transaction(&priv_key)?;

    let signature = tx.pqc_signature.as_ref().unwrap();
    println!("  Transaction signed successfully!");
    println!(
        "  Total Composite Signature length: {} bytes",
        signature.len()
    );
    println!(
        "    - Signature Hex (Prefix): 0x{}",
        hex::encode(&signature[..32])
    );
    println!(
        "    - Embedded Public Key Length: {} bytes",
        tx.pub_key.as_ref().unwrap().len()
    );
    println!(
        "    - Placeholders: v={:?}, r={:?}, s={:?}",
        tx.v, tx.r, tx.s
    );

    // -------------------------------------------------------------------------
    // Step 8: Recover Sender (Signature Verification)
    // -------------------------------------------------------------------------
    println!(
        "\n[STEP 8] Recovering and verifying the sender's address from the signed transaction..."
    );
    let recovered_address = tx.recover_sender()?;
    println!("  Recovered Sender Address: {:?}", recovered_address);

    if recovered_address == address {
        println!("\n[SUCCESS] Recovered address matches the derived address!");
        println!("  The hybrid signature is valid and authentic across all curves.");
    } else {
        println!("\n[FAILURE] Address mismatch!");
        std::process::exit(1);
    }

    println!("\n=========================================================================");
    println!("                        END OF DEMO - FLOW COMPLETE                      ");
    println!("=========================================================================");
    Ok(())
}
