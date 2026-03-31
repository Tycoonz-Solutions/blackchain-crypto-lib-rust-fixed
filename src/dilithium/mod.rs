use crate::error::CryptoError;
use crate::sign::{PrivateKey, PublicKey, Scheme};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

pub struct DilithiumPrivateKey(dilithium5::SecretKey);
pub struct DilithiumPublicKey(dilithium5::PublicKey);

impl PublicKey for DilithiumPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))?;
        dilithium5::verify_detached_signature(&sig, msg, &self.0)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for DilithiumPublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let pk = dilithium5::PublicKey::from_bytes(&bytes)
            .map_err(|e| CryptoError::InvalidKeySize { expected: dilithium5::public_key_bytes(), actual: bytes.len() })?;
        Ok(Self(pk))
    }
}

impl PrivateKey for DilithiumPrivateKey {
    type PubKey = DilithiumPublicKey;

    fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn public_key(&self) -> Self::PubKey {
        unimplemented!()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = dilithium5::detached_sign(msg, &self.0);
        Ok(sig.as_bytes().to_vec())
    }
}

impl TryFrom<Vec<u8>> for DilithiumPrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let sk = dilithium5::SecretKey::from_bytes(&bytes)
            .map_err(|e| CryptoError::InvalidKeySize { expected: dilithium5::secret_key_bytes(), actual: bytes.len() })?;
        Ok(Self(sk))
    }
}

pub struct DilithiumScheme;
impl Scheme for DilithiumScheme {
    type PrivKey = DilithiumPrivateKey;
    type PubKey = DilithiumPublicKey;

    fn generate_key(_seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let (pk, sk) = dilithium5::keypair();
        Ok((DilithiumPrivateKey(sk), DilithiumPublicKey(pk)))
    }
}
