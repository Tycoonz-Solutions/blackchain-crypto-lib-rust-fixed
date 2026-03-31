use crate::error::CryptoError;
use crate::sign::{PrivateKey, PublicKey, Scheme};
use p521::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

pub struct P521PrivateKey(SigningKey);
pub struct P521PublicKey(VerifyingKey);

impl PublicKey for P521PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))?;
        self.0.verify(msg, &sig)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))
    }
}

impl TryFrom<Vec<u8>> for P521PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let pk = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| CryptoError::CurveError(e.to_string()))?;
        Ok(Self(pk))
    }
}

impl PrivateKey for P521PrivateKey {
    type PubKey = P521PublicKey;

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn public_key(&self) -> Self::PubKey {
        P521PublicKey(VerifyingKey::from(&self.0))
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig: p521::ecdsa::Signature = self.0.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }
}

impl TryFrom<Vec<u8>> for P521PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let sk = SigningKey::from_slice(&bytes)
            .map_err(|e| CryptoError::CurveError(e.to_string()))?;
        Ok(Self(sk))
    }
}

pub struct P521Scheme;
impl Scheme for P521Scheme {
    type PrivKey = P521PrivateKey;
    type PubKey = P521PublicKey;

    fn generate_key(seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let seed_bytes = if seed.len() >= 66 { &seed[..66] } else { &[1u8; 66] };
        let sk = SigningKey::from_slice(seed_bytes)
            .unwrap_or_else(|_| SigningKey::from_slice(&[1u8; 66]).unwrap()); 
        Ok((P521PrivateKey(sk.clone()), P521PublicKey(VerifyingKey::from(&sk))))
    }
}
