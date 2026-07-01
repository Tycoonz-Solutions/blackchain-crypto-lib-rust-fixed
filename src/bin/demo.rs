use alloy_primitives::{Address, Bytes, U256};
use blackchain_crypto_lib_rust::{
    create_wallet, sign_message, verify_message, sign_transaction, verify_transaction,
    BlackChainTxType,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=========================================================================");
    println!("        BLACKCHAIN HYBRID CRYPTOGRAPHIC SUITE - HIGH-LEVEL API DEMO       ");
    println!("=========================================================================");

    // -------------------------------------------------------------------------
    // Step 1: Wallet Creation
    // -------------------------------------------------------------------------
    println!("\n[STEP 1] Generating fresh 24-word wallet and keypair via create_wallet()...");
    let (mnemonic, private_key) = create_wallet("my_secure_passphrase")?;
    println!("  Mnemonic Phrase:\n  \"{}\"", mnemonic);
    println!("  Wallet Private Key derived successfully! (Protected in zeroizing memory).");

    let public_key = private_key.public_key();
    let address = public_key.derive_address();
    println!("  Derived Wallet Address: {:?}", address);

    // -------------------------------------------------------------------------
    // Step 2: Message Signing & Verification
    // -------------------------------------------------------------------------
    println!("\n[STEP 2] Signing a general message using sign_message()...");
    let message = b"Auth verification: user_login_token_12345";
    println!("  Message to sign: {:?}", String::from_utf8_lossy(message));

    let signature = sign_message(message, &private_key)?;
    println!("  Signature generated successfully ({} bytes)!", signature.len());
    println!("    - Signature Hex (Prefix): 0x{}", hex::encode(&signature[..32]));

    println!("\n[STEP 3] Verifying the signature using verify_message()...");
    let is_valid = verify_message(message, &signature, public_key)?;
    println!("  Signature Verification Result: {}", is_valid);
    assert!(is_valid, "Freshly generated message signature must be valid");

    // -------------------------------------------------------------------------
    // Step 4: Construct EIP-1559 Style Transaction
    // -------------------------------------------------------------------------
    println!("\n[STEP 4] Constructing an unsigned BlackChain transaction...");
    let mut tx = BlackChainTxType {
        chain_id: 1,
        nonce: 42,
        max_priority_fee_per_gas: U256::from(1_500_000_000u64), // 1.5 gwei
        max_fee_per_gas: U256::from(30_000_000_000u64),         // 30 gwei
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xaa)),
        value: U256::from(500_000_000_000_000_000u64), // 0.5 ETH
        data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    };
    println!("  Unsigned Tx Hash to sign: 0x{}", hex::encode(tx.signature_hash()));

    // -------------------------------------------------------------------------
    // Step 5: Sign & Verify Transaction via API
    // -------------------------------------------------------------------------
    println!("\n[STEP 5] Signing the transaction using sign_transaction()...");
    sign_transaction(&mut tx, &private_key)?;
    println!("  Transaction signed successfully!");
    println!(
        "    - Composite Signature Length: {} bytes",
        tx.pqc_signature.as_ref().unwrap().len()
    );
    println!(
        "    - EIP-155 Placeholder: v={:?}, r={:?}, s={:?}",
        tx.v, tx.r, tx.s
    );

    println!("\n[STEP 6] Recovering and verifying sender via verify_transaction()...");
    let recovered_address = verify_transaction(&tx)?;
    println!("  Recovered Sender Address: {:?}", recovered_address);

    if recovered_address == address {
        println!("\n[SUCCESS] Recovered transaction sender matches derived wallet address!");
        println!("  All post-quantum and classical cryptographic signatures are valid.");
    } else {
        println!("\n[FAILURE] Wallet address mismatch!");
        std::process::exit(1);
    }

    println!("\n=========================================================================");
    println!("                        END OF DEMO - FLOW COMPLETE                      ");
    println!("=========================================================================");
    Ok(())
}
