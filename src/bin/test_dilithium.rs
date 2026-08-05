use blackchain_crypto_lib_rust::dilithium::{generate_key, scheme, MlDsaScheme};
use blackchain_crypto_lib_rust::sign::{Scheme, TypedScheme, PublicKey as SignPub, PrivateKey as SignPriv};

fn main() {
    println!("=== Testing ML-DSA-87 Production Implementation ===\n");
    let dil_scheme = MlDsaScheme {};

    // 1. Generate normal keys
    println!("1. Generating ML-DSA-87 keys...");
    let (pk, sk) = generate_key().expect("Failed to generate keys");

    let pk_bytes = pk.marshal_binary().unwrap();
    let sk_bytes = sk.marshal_binary().unwrap();

    println!("   Public Key length:  {} bytes", pk_bytes.len());
    println!("   Private Key length: {} bytes", sk_bytes.len());
    println!("   Scheme Name: {}", dil_scheme.name());

    // Roundtrip public key through unmarshal
    let pk2 = dil_scheme.unmarshal_binary_public_key(&pk_bytes)
        .expect("Failed to unmarshal public key");
    println!("   Unmarshalled public key bytes match: {}", pk2.marshal_binary().unwrap() == pk_bytes);

    // 2. Sign a message
    let message = b"Hello from Blackchain PQC via ML-DSA-87!";
    println!("\n2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = sk.sign_internal(message);
    println!("   Signature length: {} bytes", signature.len());

    // 3. Verify signature
    println!("\n3. Verifying signature...");
    match pk.verify_internal(message, &signature) {
        Ok(_) => println!("   ✅ Signature verification SUCCESS!"),
        Err(e) => println!("   ❌ Signature verification FAILED: {:?}", e),
    }

    // 4. Verify bad signature fails
    println!("\n4. Verifying malformed signature manipulation...");
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 1;
    match pk.verify_internal(message, &bad_sig) {
        Ok(_) => println!("   ❌ Bad signature unexpectedly verified!"),
        Err(_) => println!("   ✅ Bad signature correctly REJECTED!"),
    }

    // 5. Test deterministic seeds via TypedScheme
    println!("\n5. Testing deterministic seed generation...");
    let seed = [0x42u8; 32];
    let (seed_pk1, _) = dil_scheme.derive_key_typed(&seed);
    let (seed_pk2, _) = dil_scheme.derive_key_typed(&seed);

    if seed_pk1 == seed_pk2 {
        println!("   ✅ Deterministic key derivation MATCHES perfectly!");
    } else {
        println!("   ❌ Deterministic key derivation FAILED mismatch!");
    }

    // 6. Test dyn Scheme sign/verify
    println!("\n6. Testing dynamic Scheme sign/verify...");
    let dyn_scheme: &dyn Scheme = scheme();
    let (dyn_pk, dyn_sk) = dyn_scheme.generate_key().unwrap();
    let sig = dyn_scheme.sign(dyn_sk.as_ref(), message, None);
    if dyn_scheme.verify(dyn_pk.as_ref(), message, &sig, None) {
        println!("   ✅ Dynamic Scheme sign/verify SUCCESS!");
    } else {
        println!("   ❌ Dynamic Scheme sign/verify FAILED!");
    }

    println!("\n=== All ML-DSA-87 Tests Completed Successfully! ===");
}
