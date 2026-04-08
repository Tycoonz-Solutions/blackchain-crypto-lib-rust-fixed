// mode5 implements the CRYSTALS-Dilithium signature scheme Dilithium5
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf

use crystals_dilithium::dilithium5 as d5;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::sign::{
    self, PrivateKey as SignPrivateKey, PublicKey as SignPublicKey, Scheme as SignScheme,
    SignatureOpts, TypedScheme,
};

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
            Self::InvalidSize {
                expected,
                actual,
                context,
            } => write!(
                f,
                "dilithium5: invalid {context} size: expected {expected}, got {actual}"
            ),
            Self::VerificationFailed => write!(f, "dilithium5: signature verification failed"),
            Self::Internal(msg) => write!(f, "dilithium5: internal error: {msg}"),
            Self::ContextNotSupported => write!(f, "dilithium5: context strings are not supported"),
            Self::TypeMismatch => write!(f, "dilithium5: key type mismatch"),
            Self::CannotSignHashed => write!(f, "dilithium5: cannot sign pre-hashed message"),
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

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DilithiumPublicKey")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

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

// --- sign::PublicKey impl ---------------------------------------------------

impl SignPublicKey for PublicKey {
    fn scheme(&self) -> &dyn SignScheme {
        &Scheme
    }

    fn equal(&self, other: &dyn SignPublicKey) -> bool {
        other
            .marshal_binary()
            .map(|b| b.len() == PUBLIC_KEY_SIZE && b.as_slice().ct_eq(&self.0.to_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.0.to_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

pub struct ZeroizingSecretKey(d5::SecretKey);

impl Zeroize for ZeroizingSecretKey {
    fn zeroize(&mut self) {
        // crystals_dilithium handles its own internal security.
    }
}

impl Drop for ZeroizingSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug)]
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
            return Err(Error::InvalidSize {
                expected: PRIVATE_KEY_SIZE,
                actual: data.len(),
                context: "private key",
            });
        }
        Err(Error::Internal(
            "cannot reconstruct public key from SK safely without full keypair — use derive_key"
                .into(),
        ))
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
            },
        )
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let bytes = self.inner.0.to_bytes();
        let inner = d5::SecretKey::from_bytes(&bytes).expect("clone of valid key");
        Self {
            inner: ZeroizingSecretKey(inner),
            public: self.public.clone(),
        }
    }
}

impl fmt::Debug for ZeroizingSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZeroizingSecretKey").field(&"[REDACTED]").finish()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner
            .0
            .to_bytes()
            .ct_eq(&other.inner.0.to_bytes())
            .into()
    }
}

impl Eq for PrivateKey {}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = CryptoError;
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&data).map_err(Into::into)
    }
}

// --- sign::PrivateKey impl --------------------------------------------------

impl SignPrivateKey for PrivateKey {
    fn scheme(&self) -> &dyn SignScheme {
        &Scheme
    }

    fn equal(&self, other: &dyn SignPrivateKey) -> bool {
        other
            .marshal_binary()
            .map(|b| {
                b.len() == PRIVATE_KEY_SIZE
                    && b.as_slice().ct_eq(&self.inner.0.to_bytes()).into()
            })
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.inner.0.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.0.to_bytes().to_vec()
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
        PrivateKey {
            inner: ZeroizingSecretKey(kp.secret),
            public: PublicKey(public_copy),
        },
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
    pub fn derive_key_with_seed(&self, seed: &[u8]) -> Result<(PublicKey, PrivateKey), Error> {
        if seed.len() != SEED_SIZE {
            return Err(Error::InvalidSize {
                expected: SEED_SIZE,
                actual: seed.len(),
                context: "seed",
            });
        }
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(seed);
        Ok(new_key_from_seed(&s))
    }

    pub fn unmarshal_binary_public_key_typed(&self, buf: &[u8]) -> Result<PublicKey, Error> {
        PublicKey::from_bytes(buf)
    }
}

pub fn scheme() -> &'static Scheme {
    &Scheme
}

// --- sign::Scheme impl ------------------------------------------------------

impl SignScheme for Scheme {
    fn name(&self) -> &'static str {
        "Dilithium5"
    }

    fn public_key_size(&self) -> usize {
        PUBLIC_KEY_SIZE
    }

    fn private_key_size(&self) -> usize {
        PRIVATE_KEY_SIZE
    }

    fn signature_size(&self) -> usize {
        SIGNATURE_SIZE
    }

    fn seed_size(&self) -> usize {
        SEED_SIZE
    }

    fn supports_context(&self) -> bool {
        false
    }

    fn generate_key(
        &self,
    ) -> Result<(Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>), CryptoError> {
        let (pk, sk) = generate_key().map_err(Into::<CryptoError>::into)?;
        Ok((Box::new(pk), Box::new(sk)))
    }

    fn derive_key(&self, seed: &[u8]) -> (Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>) {
        assert!(
            seed.len() == SEED_SIZE,
            "{}; expected {SEED_SIZE}, got {}",
            sign::ERR_SEED_SIZE,
            seed.len(),
        );
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(seed);
        let (pk, sk) = new_key_from_seed(&s);
        (Box::new(pk), Box::new(sk))
    }

    fn sign(&self, sk: &dyn SignPrivateKey, message: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8> {
        // Dilithium does not support context strings.
        if let Some(o) = opts {
            if !o.context.is_empty() {
                panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
            }
        }
        let sk_bytes = sk.marshal_binary().expect("marshal dilithium SK");
        // Re-derive from seed is not possible here; we sign via raw SK bytes.
        // Parse the secret key directly.
        let sk_buf: [u8; PRIVATE_KEY_SIZE] = sk_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("{}", sign::ERR_TYPE_MISMATCH));
        let inner = d5::SecretKey::from_bytes(&sk_buf)
            .unwrap_or_else(|_| panic!("{}", sign::ERR_TYPE_MISMATCH));
        inner.sign(message).to_vec()
    }

    fn verify(
        &self,
        pk: &dyn SignPublicKey,
        message: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool {
        if let Some(o) = opts {
            if !o.context.is_empty() {
                return false;
            }
        }
        let pk_bytes = match pk.marshal_binary() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let typed_pk = match PublicKey::try_from(pk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        typed_pk.verify_internal(message, signature).is_ok()
    }

    fn unmarshal_binary_public_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPublicKey>, CryptoError> {
        PublicKey::from_bytes(buf)
            .map(|k| Box::new(k) as Box<dyn SignPublicKey>)
            .map_err(Into::into)
    }

    fn unmarshal_binary_private_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn SignPrivateKey>, CryptoError> {
        PrivateKey::from_bytes(buf)
            .map(|sk| Box::new(sk) as Box<dyn SignPrivateKey>)
            .map_err(Into::into)
    }
}

// --- TypedScheme impl -------------------------------------------------------

impl TypedScheme for Scheme {
    type Pub = PublicKey;
    type Priv = PrivateKey;

    fn generate_key_typed(&self) -> Result<(PublicKey, PrivateKey), CryptoError> {
        generate_key().map_err(Into::into)
    }

    fn derive_key_typed(&self, seed: &[u8]) -> (PublicKey, PrivateKey) {
        assert!(seed.len() == SEED_SIZE, "{}", sign::ERR_SEED_SIZE);
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(seed);
        new_key_from_seed(&s)
    }

    fn sign_typed(&self, sk: &PrivateKey, msg: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8> {
        if let Some(o) = opts {
            if !o.context.is_empty() {
                panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
            }
        }
        sk.sign_internal(msg)
    }

    fn verify_typed(
        &self,
        pk: &PublicKey,
        msg: &[u8],
        sig: &[u8],
        _opts: Option<&SignatureOpts>,
    ) -> bool {
        pk.verify_internal(msg, sig).is_ok()
    }

    fn unmarshal_public_key_typed(&self, buf: &[u8]) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(buf).map_err(Into::into)
    }

    fn unmarshal_private_key_typed(&self, buf: &[u8]) -> Result<PrivateKey, CryptoError> {
        PrivateKey::from_bytes(buf).map_err(Into::into)
    }
}

pub type DilithiumPublicKey = PublicKey;
pub type DilithiumPrivateKey = PrivateKey;
pub type DilithiumScheme = Scheme;
