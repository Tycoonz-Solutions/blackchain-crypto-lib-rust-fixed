use blackchain_crypto_lib_rust::mdecc::ed448::{generate_key, PublicKey};
use blackchain_crypto_lib_rust::sign::PublicKey as SignPub;

fn main() {
    for i in 0..10 {
        let (pk, sk) = generate_key().unwrap();
        let msg = b"roundtrip test";
        let sig = sk.sign_msg(msg, None).unwrap();
        
        // Get bytes
        let pk_bytes = pk.marshal_binary().unwrap();
        
        // Reconstruct
        let pk2 = PublicKey::from_bytes(&pk_bytes).unwrap();
        let pk2_bytes = pk2.marshal_binary().unwrap();
        
        let bytes_match = pk_bytes == pk2_bytes;
        let verify_ok = pk2.verify_sig(msg, &sig, None).is_ok();
        println!("Trial {i}: bytes_match={bytes_match} verify_ok={verify_ok}");
        if !verify_ok {
            println!("  ORIG bytes: {}", hex::encode(&pk_bytes));
            println!("  RECV bytes: {}", hex::encode(&pk2_bytes));
        }
    }
}
