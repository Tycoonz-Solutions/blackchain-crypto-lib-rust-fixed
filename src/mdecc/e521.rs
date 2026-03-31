use crate::error::CryptoError;
use crate::sign::{PrivateKey, PublicKey, Scheme};

pub struct E521PublicKey(Vec<u8>);
pub struct E521PrivateKey(Vec<u8>);

impl PublicKey for E521PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn verify(&self, _msg: &[u8], _signature: &[u8]) -> Result<(), CryptoError> {
        Ok(()) // Mocked
    }
}

impl TryFrom<Vec<u8>> for E521PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(bytes))
    }
}

impl PrivateKey for E521PrivateKey {
    type PubKey = E521PublicKey;
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn public_key(&self) -> Self::PubKey {
        E521PublicKey(vec![0u8; 32]) // Mocked
    }
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0u8; 64]) // Mocked
    }
}

impl TryFrom<Vec<u8>> for E521PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(bytes))
    }
}

pub struct E521Scheme;
impl Scheme for E521Scheme {
    type PrivKey = E521PrivateKey;
    type PubKey = E521PublicKey;

    fn generate_key(_seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        Ok((E521PrivateKey(vec![1u8; 32]), E521PublicKey(vec![0u8; 32])))
    }
}
