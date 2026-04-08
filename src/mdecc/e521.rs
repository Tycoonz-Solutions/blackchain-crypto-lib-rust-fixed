// e521 — Mocked E-521 curve implementation.
//
// E-521 is a high-security elliptic curve (521-bit prime field).
// No production-ready pure-Rust crate exists yet; this module provides a
// structurally-complete stub that compiles and satisfies all trait bounds,
// so the rest of the library can develop and test against it. Replace the
// stub bodies with real cryptography when a suitable crate becomes available.

use std::fmt;
use subtle::ConstantTimeEq;

use crate::error::CryptoError;
use crate::sign::{
    self, PrivateKey as SignPrivateKey, PublicKey as SignPublicKey, Scheme as SignScheme,
    SignatureOpts, TypedScheme,
};

// ---------------------------------------------------------------------------
// Key structs
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq)]
pub struct E521PublicKey(Vec<u8>);

#[derive(Clone, PartialEq, Eq)]
pub struct E521PrivateKey(Vec<u8>);

// ---------------------------------------------------------------------------
// Debug  (never print secret material)
// ---------------------------------------------------------------------------

impl fmt::Debug for E521PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("E521PublicKey")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl fmt::Debug for E521PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E521PrivateKey")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Inherent methods
// ---------------------------------------------------------------------------

impl E521PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl E521PrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn public_key_typed(&self) -> E521PublicKey {
        E521PublicKey(vec![0u8; 66]) // Mocked
    }

    pub fn sign_msg(&self, _msg: &[u8]) -> Vec<u8> {
        vec![0u8; 132] // Mocked 132-byte signature
    }
}

// ---------------------------------------------------------------------------
// TryFrom
// ---------------------------------------------------------------------------

impl TryFrom<Vec<u8>> for E521PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(bytes))
    }
}

impl TryFrom<Vec<u8>> for E521PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(bytes))
    }
}

// ---------------------------------------------------------------------------
// sign::PublicKey impl
// ---------------------------------------------------------------------------

impl SignPublicKey for E521PublicKey {
    fn scheme(&self) -> &dyn SignScheme {
        &E521Scheme
    }

    fn equal(&self, other: &dyn SignPublicKey) -> bool {
        other
            .marshal_binary()
            .map(|b| b.as_slice().ct_eq(self.as_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.0.clone())
    }
}

// ---------------------------------------------------------------------------
// sign::PrivateKey impl
// ---------------------------------------------------------------------------

impl SignPrivateKey for E521PrivateKey {
    fn scheme(&self) -> &dyn SignScheme {
        &E521Scheme
    }

    fn equal(&self, other: &dyn SignPrivateKey) -> bool {
        other
            .marshal_binary()
            .map(|b| b.as_slice().ct_eq(self.as_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.0.clone())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_typed().0
    }
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

pub struct E521Scheme;

impl SignScheme for E521Scheme {
    fn name(&self) -> &'static str {
        "E-521"
    }

    fn public_key_size(&self) -> usize {
        66
    }

    fn private_key_size(&self) -> usize {
        66
    }

    fn signature_size(&self) -> usize {
        132
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
        Ok((
            Box::new(E521PublicKey(vec![0u8; 66])),
            Box::new(E521PrivateKey(vec![1u8; 66])),
        ))
    }

    fn derive_key(&self, seed: &[u8]) -> (Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>) {
        assert!(seed.len() >= 66, "{}", sign::ERR_SEED_SIZE);
        (
            Box::new(E521PublicKey(vec![0u8; 66])),
            Box::new(E521PrivateKey(seed[..66].to_vec())),
        )
    }

    fn sign(&self, sk: &dyn SignPrivateKey, message: &[u8], _opts: Option<&SignatureOpts>) -> Vec<u8> {
        let sk_bytes = sk.marshal_binary().expect("marshal E521 SK");
        E521PrivateKey(sk_bytes).sign_msg(message)
    }

    fn verify(
        &self,
        _pk: &dyn SignPublicKey,
        _message: &[u8],
        _signature: &[u8],
        _opts: Option<&SignatureOpts>,
    ) -> bool {
        true // Mocked
    }

    fn unmarshal_binary_public_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPublicKey>, CryptoError> {
        Ok(Box::new(E521PublicKey(buf.to_vec())))
    }

    fn unmarshal_binary_private_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPrivateKey>, CryptoError> {
        Ok(Box::new(E521PrivateKey(buf.to_vec())))
    }
}

// --- TypedScheme impl -------------------------------------------------------

impl TypedScheme for E521Scheme {
    type Pub = E521PublicKey;
    type Priv = E521PrivateKey;

    fn generate_key_typed(&self) -> Result<(E521PublicKey, E521PrivateKey), CryptoError> {
        Ok((E521PublicKey(vec![0u8; 66]), E521PrivateKey(vec![1u8; 66])))
    }

    fn derive_key_typed(&self, seed: &[u8]) -> (E521PublicKey, E521PrivateKey) {
        assert!(seed.len() >= 66, "{}", sign::ERR_SEED_SIZE);
        (E521PublicKey(vec![0u8; 66]), E521PrivateKey(seed[..66].to_vec()))
    }

    fn sign_typed(&self, sk: &E521PrivateKey, msg: &[u8], _opts: Option<&SignatureOpts>) -> Vec<u8> {
        sk.sign_msg(msg)
    }

    fn verify_typed(
        &self,
        _pk: &E521PublicKey,
        _msg: &[u8],
        _sig: &[u8],
        _opts: Option<&SignatureOpts>,
    ) -> bool {
        true // Mocked
    }

    fn unmarshal_public_key_typed(&self, buf: &[u8]) -> Result<E521PublicKey, CryptoError> {
        Ok(E521PublicKey(buf.to_vec()))
    }

    fn unmarshal_private_key_typed(&self, buf: &[u8]) -> Result<E521PrivateKey, CryptoError> {
        Ok(E521PrivateKey(buf.to_vec()))
    }
}
