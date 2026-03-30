pub mod dilithium {
    pub mod level2 {
        use pqcrypto_dilithium::dilithium2::{
            keypair, detached_sign as sign_internal, verify_detached_signature as verify_internal,
            PublicKey, SecretKey, DetachedSignature as Signature
        };

        pub fn generate_keypair() -> (PublicKey, SecretKey) {
            keypair()
        }

        pub fn sign_message(message: &[u8], sk: &SecretKey) -> Signature {
            sign_internal(message, sk)
        }

        pub fn verify_signature(signature: &Signature, message: &[u8], pk: &PublicKey) -> bool {
            verify_internal(signature, message, pk).is_ok()
        }
    }

    pub mod level3 {
        use pqcrypto_dilithium::dilithium3::{
            keypair, detached_sign as sign_internal, verify_detached_signature as verify_internal,
            PublicKey, SecretKey, DetachedSignature as Signature
        };

        pub fn generate_keypair() -> (PublicKey, SecretKey) {
            keypair()
        }

        pub fn sign_message(message: &[u8], sk: &SecretKey) -> Signature {
            sign_internal(message, sk)
        }

        pub fn verify_signature(signature: &Signature, message: &[u8], pk: &PublicKey) -> bool {
            verify_internal(signature, message, pk).is_ok()
        }
    }

    pub mod level5 {
        use pqcrypto_dilithium::dilithium5::{
            keypair, detached_sign as sign_internal, verify_detached_signature as verify_internal,
            PublicKey, SecretKey, DetachedSignature as Signature
        };

        pub fn generate_keypair() -> (PublicKey, SecretKey) {
            keypair()
        }

        pub fn sign_message(message: &[u8], sk: &SecretKey) -> Signature {
            sign_internal(message, sk)
        }

        pub fn verify_signature(signature: &Signature, message: &[u8], pk: &PublicKey) -> bool {
            verify_internal(signature, message, pk).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dilithium::*;

    #[test]
    fn test_dilithium2() {
        let (pk, sk) = level2::generate_keypair();
        let message = b"hello world dilithium2";
        let signature = level2::sign_message(message, &sk);
        assert!(level2::verify_signature(&signature, message, &pk));
        
        // Invalid verification
        let message_fake = b"hello fake dilithium2";
        assert!(!level2::verify_signature(&signature, message_fake, &pk));
    }

    #[test]
    fn test_dilithium3() {
        let (pk, sk) = level3::generate_keypair();
        let message = b"hello world dilithium3";
        let signature = level3::sign_message(message, &sk);
        assert!(level3::verify_signature(&signature, message, &pk));
    }

    #[test]
    fn test_dilithium5() {
        let (pk, sk) = level5::generate_keypair();
        let message = b"hello world dilithium5";
        let signature = level5::sign_message(message, &sk);
        assert!(level5::verify_signature(&signature, message, &pk));
    }
}
