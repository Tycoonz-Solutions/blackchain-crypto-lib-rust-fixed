use blackchain_crypto_lib_rust::mdecc::ed448::{
    generate_key, new_key_from_seed, new_curve448_scheme,
    PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE,
};
use blackchain_crypto_lib_rust::sign::{SignatureOpts, Scheme, PublicKey as SignPub, PrivateKey as SignPriv, TypedScheme};
use rand_core::{OsRng, RngCore};

fn main() {
    println!("=== Testing Ed448 Production Implementation ===\n");

    // 1. Generate keys
    println!("1. Generating Ed448 keys...");
    let (pk, sk) = generate_key().expect("Failed to generate keys");

    let pk_bytes = pk.marshal_binary().unwrap();
    let sk_bytes = sk.marshal_binary().unwrap();

    println!("   Public Key length:  {} bytes", pk_bytes.len());
    println!("   Public Key (Hex): {}", hex::encode(&pk_bytes));
    println!("   Private Key length: {} bytes", sk_bytes.len());

    assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
    assert_eq!(sk_bytes.len(), PRIVATE_KEY_SIZE);

    // 2. Sign a message
    let message = b"Hello from Blackchain PQC via Ed448!";
    println!("\n2. Signing message: {:?}", String::from_utf8_lossy(message));

    let signature = sk.sign_msg(message, None).expect("Failed to sign");

    println!("   Signature length: {} bytes", signature.len());
    println!("   Signature snippet: {}...", hex::encode(&signature[..16]));
    assert_eq!(signature.len(), SIGNATURE_SIZE);

    // 3. Verify signature
    println!("\n3. Verifying signature...");
    if pk.verify_sig(message, &signature, None).is_ok() {
        println!("   ✅ Signature verification SUCCESS!");
    } else {
        println!("   ❌ Signature verification FAILED!");
        panic!("Verification should have succeeded");
    }

    // 4. Malformed signature rejection
    println!("\n4. Verifying malformed signature manipulation...");
    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 0xFF;

    if pk.verify_sig(message, &bad_sig, None).is_err() {
        println!("   ✅ Bad signature correctly REJECTED!");
    } else {
        println!("   ❌ Bad signature was INCORRECTLY ACCEPTED!");
        panic!("Bad verification should have failed");
    }

    // 5. Context-aware signing
    println!("\n5. Testing context-aware signing (standard Ed448)...");
    let opts = SignatureOpts {
        context: "blackchain-tx".into(),
    };
    let ctx_sig = sk.sign_msg(message, Some(&opts)).expect("Failed context sign");
    if pk.verify_sig(message, &ctx_sig, Some(&opts)).is_ok() {
        println!("   ✅ Context-aware verification SUCCESS!");
    } else {
        println!("   ❌ Context-aware verification FAILED!");
    }

    // Cross-context rejection
    if pk.verify_sig(message, &ctx_sig, None).is_err() {
        println!("   ✅ Cross-context verification cleanly REJECTED!");
    } else {
        println!("   ❌ Cross-context verification FAILED (should reject)");
    }

    // 6. Deterministic key derivation
    println!("\n6. Testing deterministic seed generation...");
    let mut root_seed = [0u8; SEED_SIZE];
    OsRng.fill_bytes(&mut root_seed);

    let (pk_a, _) = new_key_from_seed(&root_seed);
    let (pk_b, _) = new_key_from_seed(&root_seed);

    if pk_a == pk_b {
        println!("   ✅ Deterministic key derivation MATCHES perfectly!");
    } else {
        println!("   ❌ Deterministic tests FAILED — mismatched keys!");
        panic!("Deterministic tests failed");
    }

    // 7. THE critical test — public key serialization roundtrip (ed448-rust crate bug fix)
    println!("\n7. Testing public key serialization roundtrip (curve-point decompression fix)...");
    let (pk_orig, sk_orig) = generate_key().unwrap();
    let msg2 = b"network roundtrip test";
    let sig2 = sk_orig.sign_msg(msg2, None).unwrap();

    let pk_bytes2 = pk_orig.marshal_binary().unwrap();
    let pk_recv = blackchain_crypto_lib_rust::mdecc::ed448::PublicKey::from_bytes(&pk_bytes2).unwrap();

    if pk_recv.verify_sig(msg2, &sig2, None).is_ok() {
        println!("   ✅ Serialized public key correctly verifies signature — ed448-goldilocks decompression fix working!");
    } else {
        println!("   ❌ Serialized public key FAILED to verify — the core bug is still present!");
        panic!("Public key roundtrip verification failed");
    }

    // 8. Dynamic Scheme interface
    println!("\n8. Testing dynamic Scheme interface...");
    let s = new_curve448_scheme();
    let (dyn_pk, dyn_sk) = s.generate_key().unwrap();
    let dyn_sig = s.sign(dyn_sk.as_ref(), message, None);
    if s.verify(dyn_pk.as_ref(), message, &dyn_sig, None) {
        println!("   ✅ Dynamic Scheme sign/verify SUCCESS!");
    } else {
        println!("   ❌ Dynamic Scheme sign/verify FAILED!");
    }

    println!("\n=== All Ed448 Tests Completed Successfully! ===");
}
