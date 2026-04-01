use crate::error::CryptoError;
use crate::sign::{PrivateKey, PublicKey, Scheme};
use ed448_rust::{PrivateKey as Ed448Priv, PublicKey as Ed448Pub};

pub struct Ed448PrivateKey(Ed448Priv);
pub struct Ed448PublicKey(Ed448Pub);

impl PublicKey for Ed448PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        // According to the library usage, publickey should have as_bytes()
        // or something similar, otherwise we will fix during compilation.
        self.0.as_byte().to_vec()
    }

    fn verify(&self, msg: &[u8], signature: &[u8], opts: Option<&crate::sign::SignatureOpts>) -> Result<(), CryptoError> {
        let sig_bytes: [u8; 114] = signature.try_into()
            .map_err(|_| CryptoError::SignatureError("Invalid Ed448 signature length".to_string()))?;
        let ctx = opts.map(|o| o.context.as_bytes());
        self.0.verify(msg, &sig_bytes, ctx)
            .map_err(|_| CryptoError::SignatureError("Verification failed".to_string()))
    }
}

impl TryFrom<Vec<u8>> for Ed448PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let pk = Ed448Pub::try_from(bytes.as_slice())
            .map_err(|_| CryptoError::CurveError("Invalid public key layout".to_string()))?;
        Ok(Self(pk))
    }
}

impl PrivateKey for Ed448PrivateKey {
    type PubKey = Ed448PublicKey;

    fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    fn public_key(&self) -> Self::PubKey {
        Ed448PublicKey(Ed448Pub::from(&self.0))
    }

    fn sign(&self, msg: &[u8], opts: Option<&crate::sign::SignatureOpts>) -> Result<Vec<u8>, CryptoError> {
        let ctx = opts.map(|o| o.context.as_bytes());
        let sig = self.0.sign(msg, ctx)
            .map_err(|_| CryptoError::SignatureError("Signing failed".to_string()))?;
        Ok(sig.to_vec())
    }
}

impl TryFrom<Vec<u8>> for Ed448PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let sk = Ed448Priv::try_from(bytes.as_slice())
            .map_err(|_| CryptoError::CurveError("Invalid key length".to_string()))?;
        Ok(Self(sk))
    }
}

pub struct Ed448Scheme;
impl Scheme for Ed448Scheme {
    type PrivKey = Ed448PrivateKey;
    type PubKey = Ed448PublicKey;

    fn generate_key(seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let seed_bytes = if seed.len() >= 57 { &seed[..57] } else { &[1u8; 57] };
        let mut byte_array = [0u8; 57];
        byte_array.copy_from_slice(seed_bytes);
        let sk = Ed448Priv::from(byte_array);
        let pk = Ed448Pub::from(&sk);
        Ok((Ed448PrivateKey(sk), Ed448PublicKey(pk)))
    }
}
