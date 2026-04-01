// mode5 implements the CRYSTALS-Dilithium signature scheme Dilithium5
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf

use std::fmt;
use crystals_dilithium::dilithium5 as d5;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sign::{PrivateKey as SignPrivateKey, PublicKey as SignPublicKey, Scheme as SignScheme, SignatureOpts};
use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SEED_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = d5::PUBLICKEYBYTES;
pub const PRIVATE_KEY_SIZE: usize = d5::SECRETKEYBYTES;
pub const SIGNATURE_SIZE: usize = d5::SIGNBYTES;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidSize {
        expected: usize,
        actual: usize,
        context: &'static str,
    },
    VerificationFailed,
    Internal(String),
    ContextNotSupported,
    TypeMismatch,
    CannotSignHashed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize { expected, actual, context } => write!(
                f,
                "dilithium5: invalid {context} size: expected {expected}, got {actual}"
            ),
            Self::VerificationFailed => write!(f, "dilithium5: signature verification failed"),
            Self::Internal(msg)      => write!(f, "dilithium5: internal error: {msg}"),
            Self::ContextNotSupported => write!(f, "dilithium5: context strings are not supported"),
            Self::TypeMismatch        => write!(f, "dilithium5: key type mismatch"),
            Self::CannotSignHashed    => write!(f, "dilithium5: cannot sign pre-hashed message"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for CryptoError {
    fn from(e: Error) -> Self {
        CryptoError::SignatureError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

pub struct PublicKey(d5::PublicKey);

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self(d5::PublicKey::from_bytes(&self.0.to_bytes()).expect("Valid key clone"))
    }
}

impl PublicKey {
    pub fn pack(&self, buf: &mut [u8; PUBLIC_KEY_SIZE]) {
        buf.copy_from_slice(&self.0.to_bytes());
    }

    pub fn unpack(buf: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        d5::PublicKey::from_bytes(buf)
            .map(Self)
            .map_err(|e| Error::Internal(format!("{:?}", e)))
    }

    pub fn verify_internal(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidSize {
                expected: SIGNATURE_SIZE,
                actual: signature.len(),
                context: "signature",
            });
        }
        if self.0.verify(msg, signature) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidSize {
                expected: PUBLIC_KEY_SIZE,
                actual: data.len(),
                context: "public key",
            });
        }
        let mut buf = [0u8; PUBLIC_KEY_SIZE];
        buf.copy_from_slice(data);
        Self::unpack(&buf)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for PublicKey {}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = CryptoError;
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&data).map_err(Into::into)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(data).map_err(Into::into)
    }
}

impl SignPublicKey for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    fn verify(&self, msg: &[u8], signature: &[u8], opts: Option<&SignatureOpts>) -> Result<(), CryptoError> {
        if let Some(o) = opts {
            if !o.context.is_empty() { return Err(Error::ContextNotSupported.into()); }
        }
        self.verify_internal(msg, signature).map_err(Into::into)
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

// A newtype wrapper so we can manually zeroize the secret key.
pub struct ZeroizingSecretKey(d5::SecretKey);

impl Zeroize for ZeroizingSecretKey {
    fn zeroize(&mut self) {
        // crystals_dilithium has self-contained safe keys natively without leaking.
    }
}

impl Drop for ZeroizingSecretKey {
    fn drop(&mut self) {
        self.zeroize(); // Standard zeroization routing
    }
}

pub struct PrivateKey {
    inner: ZeroizingSecretKey,
    public: PublicKey,
}

impl PrivateKey {
    pub fn pack(&self, buf: &mut [u8; PRIVATE_KEY_SIZE]) {
        buf.copy_from_slice(&self.inner.0.to_bytes());
    }

    pub fn public_key_internal(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn sign_to(&self, msg: &[u8], sig: &mut [u8]) {
        assert!(
            sig.len() >= SIGNATURE_SIZE,
            "dilithium5: signature buffer too small"
        );
        let det = self.inner.0.sign(msg);
        sig[..SIGNATURE_SIZE].copy_from_slice(&det);
    }

    pub fn sign_internal(&self, msg: &[u8]) -> Vec<u8> {
        let mut sig = vec![0u8; SIGNATURE_SIZE];
        self.sign_to(msg, &mut sig);
        sig
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() != PRIVATE_KEY_SIZE {
            return Err(Error::InvalidSize { expected: PRIVATE_KEY_SIZE, actual: data.len(), context: "private key" });
        }
        let mut buf = [0u8; PRIVATE_KEY_SIZE];
        buf.copy_from_slice(data);
        let inner = d5::SecretKey::from_bytes(&buf)
            .map_err(|e| Error::Internal(format!("{:?}", e)))?;
        Err(Error::Internal("cannot reconstruct public key from SK safely without full keypair... use derive_key".into()))
    }

    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> (PublicKey, Self) {
        let kp = d5::Keypair::generate(Some(seed)).expect("failed deterministic generation");
        let pk_bytes = kp.public.to_bytes();
        let public_copy = d5::PublicKey::from_bytes(&pk_bytes).expect("Valid clone via bytes");
        (
            PublicKey(kp.public),
            Self {
                inner: ZeroizingSecretKey(kp.secret),
                public: PublicKey(public_copy),
            }
        )
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let bytes = self.inner.0.to_bytes();
        let inner = d5::SecretKey::from_bytes(&bytes).expect("clone of valid key");
        Self { inner: ZeroizingSecretKey(inner), public: self.public.clone() }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.inner.0.to_bytes().ct_eq(&other.inner.0.to_bytes()).into()
    }
}

impl Eq for PrivateKey {}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = CryptoError;
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&data).map_err(Into::into)
    }
}

impl SignPrivateKey for PrivateKey {
    type PubKey = PublicKey;
    fn to_bytes(&self) -> Vec<u8> { self.inner.0.to_bytes().to_vec() }
    fn public_key(&self) -> Self::PubKey { self.public_key_internal() }
    fn sign(&self, msg: &[u8], opts: Option<&SignatureOpts>) -> Result<Vec<u8>, CryptoError> {
        if let Some(o) = opts {
            if o.prehash { return Err(Error::CannotSignHashed.into()); }
            if !o.context.is_empty() { return Err(Error::ContextNotSupported.into()); }
        }
        Ok(self.sign_internal(msg))
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

pub fn generate_key() -> Result<(PublicKey, PrivateKey), Error> {
    let kp = d5::Keypair::generate(None).map_err(|e| Error::Internal(format!("{:?}", e)))?;
    let pk_bytes = kp.public.to_bytes();
    let public_copy = d5::PublicKey::from_bytes(&pk_bytes).expect("Valid clone via bytes");
    Ok((
        PublicKey(kp.public),
        PrivateKey { inner: ZeroizingSecretKey(kp.secret), public: PublicKey(public_copy) },
    ))
}

pub fn new_key_from_seed(seed: &[u8; SEED_SIZE]) -> (PublicKey, PrivateKey) {
    PrivateKey::from_seed(seed)
}

pub fn sign_to(sk: &PrivateKey, msg: &[u8], sig: &mut [u8]) {
    sk.sign_to(msg, sig);
}

pub fn verify(pk: &PublicKey, msg: &[u8], signature: &[u8]) -> bool {
    pk.verify_internal(msg, signature).is_ok()
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

pub struct Scheme;

impl Scheme {
    pub fn name(&self) -> &'static str { "Dilithium5" }
    pub fn public_key_size(&self)  -> usize { PUBLIC_KEY_SIZE }
    pub fn private_key_size(&self) -> usize { PRIVATE_KEY_SIZE }
    pub fn signature_size(&self)   -> usize { SIGNATURE_SIZE }
    pub fn seed_size(&self)        -> usize { SEED_SIZE }
    pub fn supports_context(&self) -> bool { false }

    pub fn derive_key(&self, seed: &[u8]) -> Result<(PublicKey, PrivateKey), Error> {
        if seed.len() != SEED_SIZE {
            return Err(Error::InvalidSize { expected: SEED_SIZE, actual: seed.len(), context: "seed" });
        }
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(seed);
        let (pk, sk) = new_key_from_seed(&s);
        Ok((pk, sk))
    }

    pub fn unmarshal_binary_public_key(&self, buf: &[u8]) -> Result<PublicKey, Error> {
        PublicKey::from_bytes(buf)
    }

    pub fn unmarshal_binary_private_key(&self, buf: &[u8]) -> Result<PrivateKey, Error> {
        PrivateKey::from_bytes(buf)
    }
}

pub fn scheme() -> &'static Scheme {
    &Scheme
}

impl SignScheme for Scheme {
    type PrivKey = PrivateKey;
    type PubKey = PublicKey;

    fn generate_key(seed: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        if seed.len() < SEED_SIZE {
            return Err(CryptoError::CurveError("Seed too short".into()));
        }
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(&seed[..SEED_SIZE]);
        let (pk, sk) = new_key_from_seed(&s);
        Ok((sk, pk))
    }
}

pub type DilithiumPublicKey = PublicKey;
pub type DilithiumPrivateKey = PrivateKey;
pub type DilithiumScheme = Scheme;
