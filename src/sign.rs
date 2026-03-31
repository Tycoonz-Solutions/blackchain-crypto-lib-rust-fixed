use crate::error::CryptoError;

pub trait PublicKey: TryFrom<Vec<u8>, Error = CryptoError> + Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

pub trait PrivateKey: TryFrom<Vec<u8>, Error = CryptoError> + Sized {
    type PubKey: PublicKey;
    
    fn to_bytes(&self) -> Vec<u8>;
    fn public_key(&self) -> Self::PubKey;
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait Scheme {
    type PrivKey: PrivateKey;
    type PubKey: PublicKey;
    
    fn generate_key(seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;
}
