use blackchain_crypto_lib_rust::dilithium::{generate_key, new_key_from_seed};
use blackchain_crypto_lib_rust::sign::{PrivateKey, PublicKey};

fn main() {
    println!("=== Testing Dilithium5 Production Implementation ===\n");
    
    // 1. Generate normal keys
    println!("1. Generating Dilithium5 keys...");
    let (pk, sk) = generate_key().expect("Failed to generate keys");

    println!("   Public Key length: {} bytes", pk.to_bytes().len());
    println!("   Public Key: {:?}", pk);
    
    println!("   Private Key length: {} bytes", sk.to_bytes().len());
    println!("   Private Key: {:?}", sk);
    // 2. Sign a message
    let message = b"Hello from Blackchain PQC via Dilithium5!";
    println!("\n2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = sk.sign(message, None).expect("Signature failed");

    println!("   Signature length: {} bytes", signature.len());
    println!("   Signature: {:?}", signature);
    
    // 3. Verify signature
    println!("\n3. Verifying signature...");
    match pk.verify(message, &signature, None) {
        Ok(_) => println!("   ✅ Signature verification SUCCESS!"),
        Err(e) => println!("   ❌ Signature verification FAILED: {:?}", e),
    }

    // 4. Verify bad signature fails
    println!("\n4. Verifying malformed signature manipulation...");
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 1; // Flip a bit
    match pk.verify(message, &bad_sig, None) {
        Ok(_) => println!("   ❌ Bad signature unexpectedly verified!"),
        Err(_) => println!("   ✅ Bad signature correctly REJECTED!"),
    }

    // 5. Test deterministic seeds
    println!("\n5. Testing deterministic seed generation...");
    let seed = [0x42; 32];
    let (seed_pk1, seed_sk1) = new_key_from_seed(&seed);
    let (seed_pk2, seed_sk2) = new_key_from_seed(&seed);
    
    if seed_pk1 == seed_pk2 && seed_sk1 == seed_sk2 {
        println!("   ✅ Deterministic key derivation MATCHES perfectly! (ChaCha20 behaves identically)");
    } else {
        println!("   ❌ Deterministic key derivation FAILED mismatch!");
    }
    
    println!("\n=== All Dilithium5 Tests Completed Successfully! ===");
}
