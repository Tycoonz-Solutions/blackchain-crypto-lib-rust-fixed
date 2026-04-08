use std::fmt;
use subtle::ConstantTimeEq;
use p521::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

use crate::error::CryptoError;
use crate::sign::{
    self, PrivateKey as SignPrivateKey, PublicKey as SignPublicKey, Scheme as SignScheme,
    SignatureOpts, TypedScheme,
};

// ---------------------------------------------------------------------------
// Key structs
// ---------------------------------------------------------------------------

pub struct P521PublicKey(VerifyingKey);
pub struct P521PrivateKey(SigningKey);

// ---------------------------------------------------------------------------
// PublicKey inherent methods
// ---------------------------------------------------------------------------

impl P521PublicKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|e| CryptoError::CurveError(e.to_string()))
    }

    pub fn verify_sig(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))?;
        self.0
            .verify(msg, &sig)
            .map_err(|e| CryptoError::SignatureError(e.to_string()))
    }
}

impl Clone for P521PublicKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for P521PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(&other.as_bytes()).into()
    }
}

impl Eq for P521PublicKey {}

impl fmt::Debug for P521PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P521PublicKey")
            .field(&hex::encode(self.as_bytes()))
            .finish()
    }
}

impl TryFrom<Vec<u8>> for P521PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&bytes)
    }
}

// --- sign::PublicKey impl ---------------------------------------------------

impl SignPublicKey for P521PublicKey {
    fn scheme(&self) -> &dyn SignScheme {
        &P521Scheme
    }

    fn equal(&self, other: &dyn SignPublicKey) -> bool {
        other
            .marshal_binary()
            .map(|b| b.as_slice().ct_eq(&self.as_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// PrivateKey inherent methods
// ---------------------------------------------------------------------------

impl P521PrivateKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|e| CryptoError::CurveError(e.to_string()))
    }

    pub fn public_key_typed(&self) -> P521PublicKey {
        P521PublicKey(VerifyingKey::from(&self.0))
    }

    pub fn sign_msg(&self, msg: &[u8]) -> Vec<u8> {
        let sig: p521::ecdsa::Signature = self.0.sign(msg);
        sig.to_bytes().to_vec()
    }
}

impl Clone for P521PrivateKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for P521PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(&other.as_bytes()).into()
    }
}

impl Eq for P521PrivateKey {}

impl fmt::Debug for P521PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P521PrivateKey")
            .field("public", &self.public_key_typed())
            .finish_non_exhaustive()
    }
}

impl TryFrom<Vec<u8>> for P521PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&bytes)
    }
}

// --- sign::PrivateKey impl --------------------------------------------------

impl SignPrivateKey for P521PrivateKey {
    fn scheme(&self) -> &dyn SignScheme {
        &P521Scheme
    }

    fn equal(&self, other: &dyn SignPrivateKey) -> bool {
        other
            .marshal_binary()
            .map(|b| b.as_slice().ct_eq(&self.as_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.as_bytes())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_typed().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

pub struct P521Scheme;

impl P521Scheme {
    fn generate_keypair_from_seed(seed: &[u8]) -> (P521PublicKey, P521PrivateKey) {
        let seed_bytes = if seed.len() >= 66 { &seed[..66] } else { &[1u8; 66] };
        let sk = SigningKey::from_slice(seed_bytes)
            .unwrap_or_else(|_| SigningKey::from_slice(&[1u8; 66]).unwrap());
        let pk = P521PublicKey(VerifyingKey::from(&sk));
        (pk, P521PrivateKey(sk))
    }
}

// --- sign::Scheme impl ------------------------------------------------------

impl SignScheme for P521Scheme {
    fn name(&self) -> &'static str {
        "P-521"
    }

    fn public_key_size(&self) -> usize {
        133 // Uncompressed SEC1 point: 1 + 2*66
    }

    fn private_key_size(&self) -> usize {
        66
    }

    fn signature_size(&self) -> usize {
        139 // DER-encoded max size
    }

    fn seed_size(&self) -> usize {
        66
    }

    fn supports_context(&self) -> bool {
        false
    }

    fn generate_key(
        &self,
    ) -> Result<(Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>), CryptoError> {
        use rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let pk = P521PublicKey(VerifyingKey::from(&sk));
        Ok((Box::new(pk), Box::new(P521PrivateKey(sk))))
    }

    fn derive_key(&self, seed: &[u8]) -> (Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>) {
        let (pk, sk) = Self::generate_keypair_from_seed(seed);
        (Box::new(pk), Box::new(sk))
    }

    fn sign(&self, sk: &dyn SignPrivateKey, message: &[u8], _opts: Option<&SignatureOpts>) -> Vec<u8> {
        let sk_bytes = sk.marshal_binary().expect("marshal P521 SK");
        let typed_sk = P521PrivateKey::from_bytes(&sk_bytes)
            .unwrap_or_else(|_| panic!("{}", sign::ERR_TYPE_MISMATCH));
        typed_sk.sign_msg(message)
    }

    fn verify(
        &self,
        pk: &dyn SignPublicKey,
        message: &[u8],
        signature: &[u8],
        _opts: Option<&SignatureOpts>,
    ) -> bool {
        let pk_bytes = match pk.marshal_binary() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let typed_pk = match P521PublicKey::from_bytes(&pk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        typed_pk.verify_sig(message, signature).is_ok()
    }

    fn unmarshal_binary_public_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPublicKey>, CryptoError> {
        P521PublicKey::from_bytes(buf).map(|k| Box::new(k) as Box<dyn SignPublicKey>)
    }

    fn unmarshal_binary_private_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPrivateKey>, CryptoError> {
        P521PrivateKey::from_bytes(buf).map(|k| Box::new(k) as Box<dyn SignPrivateKey>)
    }
}

// --- TypedScheme impl -------------------------------------------------------

impl TypedScheme for P521Scheme {
    type Pub = P521PublicKey;
    type Priv = P521PrivateKey;

    fn generate_key_typed(&self) -> Result<(P521PublicKey, P521PrivateKey), CryptoError> {
        use rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let pk = P521PublicKey(VerifyingKey::from(&sk));
        Ok((pk, P521PrivateKey(sk)))
    }

    fn derive_key_typed(&self, seed: &[u8]) -> (P521PublicKey, P521PrivateKey) {
        Self::generate_keypair_from_seed(seed)
    }

    fn sign_typed(&self, sk: &P521PrivateKey, msg: &[u8], _opts: Option<&SignatureOpts>) -> Vec<u8> {
        sk.sign_msg(msg)
    }

    fn verify_typed(
        &self,
        pk: &P521PublicKey,
        msg: &[u8],
        sig: &[u8],
        _opts: Option<&SignatureOpts>,
    ) -> bool {
        pk.verify_sig(msg, sig).is_ok()
    }

    fn unmarshal_public_key_typed(&self, buf: &[u8]) -> Result<P521PublicKey, CryptoError> {
        P521PublicKey::from_bytes(buf)
    }

    fn unmarshal_private_key_typed(&self, buf: &[u8]) -> Result<P521PrivateKey, CryptoError> {
        P521PrivateKey::from_bytes(buf)
    }
}
