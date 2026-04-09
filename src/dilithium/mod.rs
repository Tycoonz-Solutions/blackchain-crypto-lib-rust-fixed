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
        // crystals_dilithium handles its own internal security, but for defense-in-depth,
        // we explicitly zero the memory backing the struct. Since SecretKey is a fixed-size
        // buffer internally, this ensures the key material is scrubbed immediately upon Drop.
        unsafe {
            std::ptr::write_bytes(self as *mut _ as *mut u8, 0, std::mem::size_of_val(self));
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
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
        // Security rationale: Dilithium private keys do not trivially contain the public key.
        // Reconstructing a `PrivateKey` object from just the secret bytes would leave us without
        // the `public` field. We do not allow partial keys, as it can lead to security footguns
        // where verification or serialization might panic or fail silently. Thus, we intentionally
        // disable from_bytes for PrivateKey and encourage users to use deterministic generation
        // (`derive_key` or `derive_key_with_seed`) instead if they must persist keys.
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
        f.debug_tuple("ZeroizingSecretKey")
            .field(&"[REDACTED]")
            .finish()
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
                b.len() == PRIVATE_KEY_SIZE && b.as_slice().ct_eq(&self.inner.0.to_bytes()).into()
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

    fn sign(
        &self,
        sk: &dyn SignPrivateKey,
        message: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Scheme as S, SignatureOpts, TypedScheme as TS};
    use std::time::Instant;

    // ── 1. Constant sanity ────────────────────────────────────────────────────

    /// Verify that our public constants match the crystals_dilithium crate's
    /// own byte-length constants so a library upgrade cannot silently break us.
    #[test]
    fn constants_match_crate_values() {
        assert_eq!(PUBLIC_KEY_SIZE, d5::PUBLICKEYBYTES,
            "PUBLIC_KEY_SIZE mismatch with crystals_dilithium");
        assert_eq!(PRIVATE_KEY_SIZE, d5::SECRETKEYBYTES,
            "PRIVATE_KEY_SIZE mismatch with crystals_dilithium");
        assert_eq!(SIGNATURE_SIZE, d5::SIGNBYTES,
            "SIGNATURE_SIZE mismatch with crystals_dilithium");
        assert_eq!(SEED_SIZE, 32,
            "SEED_SIZE must be exactly 32 bytes for Dilithium5");
    }

    /// Scheme metadata accessors must return our module constants.
    #[test]
    fn scheme_metadata() {
        let s = Scheme;
        assert_eq!(s.name(), "Dilithium5");
        assert_eq!(s.public_key_size(),  PUBLIC_KEY_SIZE);
        assert_eq!(s.private_key_size(), PRIVATE_KEY_SIZE);
        assert_eq!(s.signature_size(),   SIGNATURE_SIZE);
        assert_eq!(s.seed_size(),        SEED_SIZE);
        assert!(!s.supports_context(),
            "Dilithium5 must NOT advertise context support");
    }

    // ── 2. Key generation ─────────────────────────────────────────────────────

    /// Happy-path random key generation produces correctly-sized keys.
    #[test]
    fn generate_key_produces_correct_sizes() {
        let (pk, sk) = generate_key().expect("key generation failed");
        assert_eq!(pk.0.to_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.inner.0.to_bytes().len(), PRIVATE_KEY_SIZE);
    }

    /// Successive random key-generations must yield distinct keys.
    #[test]
    fn generate_key_is_non_deterministic() {
        let (pk1, _) = generate_key().expect("first keygen failed");
        let (pk2, _) = generate_key().expect("second keygen failed");
        assert_ne!(pk1.0.to_bytes(), pk2.0.to_bytes(),
            "two independently generated keys should differ");
    }

    // ── 3. Deterministic derivation ───────────────────────────────────────────

    /// The same 32-byte seed must always produce the same key pair.
    #[test]
    fn derive_key_is_deterministic() {
        let seed = [0xABu8; SEED_SIZE];
        let (pk1, sk1) = new_key_from_seed(&seed);
        let (pk2, sk2) = new_key_from_seed(&seed);
        assert_eq!(pk1.0.to_bytes(), pk2.0.to_bytes(),
            "deterministic keygen must produce identical public keys");
        assert_eq!(sk1.inner.0.to_bytes(), sk2.inner.0.to_bytes(),
            "deterministic keygen must produce identical secret keys");
    }

    /// Two distinct seeds must produce distinct keys.
    #[test]
    fn derive_key_differs_for_different_seeds() {
        let seed_a = [0x11u8; SEED_SIZE];
        let seed_b = [0x22u8; SEED_SIZE];
        let (pk_a, _) = new_key_from_seed(&seed_a);
        let (pk_b, _) = new_key_from_seed(&seed_b);
        assert_ne!(pk_a.0.to_bytes(), pk_b.0.to_bytes(),
            "different seeds must yield different public keys");
    }

    /// `Scheme::derive_key` panics on a wrong-size seed (mirrors Go's panic).
    #[test]
    #[should_panic]
    fn derive_key_panics_on_wrong_seed_size() {
        Scheme.derive_key(&[0u8; SEED_SIZE - 1]);
    }

    /// `Scheme::derive_key_with_seed` returns `Err` on wrong-size seed.
    #[test]
    fn derive_key_with_seed_errors_on_wrong_size() {
        let err = Scheme.derive_key_with_seed(&[0u8; SEED_SIZE + 1]);
        assert!(err.is_err(), "must return Err for oversized seed");
    }

    /// `Scheme::derive_key_with_seed` succeeds on correctly sized seed.
    #[test]
    fn derive_key_with_seed_success() {
        let seed = [0x55u8; SEED_SIZE];
        let result = Scheme.derive_key_with_seed(&seed);
        assert!(result.is_ok(), "must succeed for exactly sized seed");
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.0.to_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.inner.0.to_bytes().len(), PRIVATE_KEY_SIZE);
    }

    // ── 4. Sign / Verify round-trip ───────────────────────────────────────────

    /// Core sign → verify round-trip using the low-level typed methods.
    #[test]
    fn sign_verify_roundtrip_typed() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = b"Blackchain PQC Dilithium5 round-trip";
        let sig = sk.sign_internal(msg);
        assert_eq!(sig.len(), SIGNATURE_SIZE,
            "signature length must equal SIGNATURE_SIZE");
        assert!(pk.verify_internal(msg, &sig).is_ok(),
            "valid signature must verify");
    }

    /// Verifying against the wrong message must fail.
    #[test]
    fn verify_fails_on_wrong_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_internal(b"original message");
        assert!(pk.verify_internal(b"tampered message", &sig).is_err(),
            "signature must not verify against a different message");
    }

    /// Verifying an altered signature must fail.
    #[test]
    fn verify_fails_on_tampered_signature() {
        let (pk, sk) = generate_key().expect("keygen");
        let mut sig = sk.sign_internal(b"hello");
        // flip a byte in the middle of the signature
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        assert!(pk.verify_internal(b"hello", &sig).is_err(),
            "tampered signature must not verify");
    }

    /// Verifying with a different public key must fail.
    #[test]
    fn verify_fails_with_wrong_public_key() {
        let (_, sk) = generate_key().expect("keygen");
        let (pk_other, _) = generate_key().expect("second keygen");
        let sig = sk.sign_internal(b"message");
        assert!(pk_other.verify_internal(b"message", &sig).is_err(),
            "signature must not verify under a different public key");
    }

    /// Signature of the empty message must also verify correctly.
    #[test]
    fn sign_verify_empty_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_internal(b"");
        assert!(pk.verify_internal(b"", &sig).is_ok(),
            "empty-message signature must verify");
    }

    /// Signature of a large message (~64 KiB) must verify correctly.
    #[test]
    fn sign_verify_large_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = vec![0x5Au8; 65_536];
        let sig = sk.sign_internal(&msg);
        assert!(pk.verify_internal(&msg, &sig).is_ok(),
            "large-message signature must verify");
    }

    // ── 5. Signature-size guards ──────────────────────────────────────────────

    /// `verify_internal` must reject a signature that is too short.
    #[test]
    fn verify_rejects_short_signature() {
        let (pk, _) = generate_key().expect("keygen");
        let short_sig = vec![0u8; SIGNATURE_SIZE - 1];
        let err = pk.verify_internal(b"msg", &short_sig);
        assert!(err.is_err(), "short signature must be rejected");
        assert!(
            matches!(err, Err(Error::InvalidSize { context: "signature", .. })),
            "must return an InvalidSize error for the signature"
        );
    }

    /// `verify_internal` must reject a zero-length signature.
    #[test]
    fn verify_rejects_empty_signature() {
        let (pk, _) = generate_key().expect("keygen");
        assert!(pk.verify_internal(b"msg", &[]).is_err(),
            "empty signature must be rejected");
    }

    // ── 6. Serialization round-trips ──────────────────────────────────────────

    /// Pack the public key then unpack it — result must be equal.
    #[test]
    fn public_key_pack_unpack_roundtrip() {
        let (pk, _) = generate_key().expect("keygen");
        let mut buf = [0u8; PUBLIC_KEY_SIZE];
        pk.pack(&mut buf);
        let pk2 = PublicKey::unpack(&buf).expect("unpack failed");
        assert_eq!(pk.0.to_bytes(), pk2.0.to_bytes(),
            "pack → unpack must be an identity");
    }

    /// `PublicKey::from_bytes` must produce a key that can still verify.
    #[test]
    fn public_key_from_bytes_then_verify() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_internal(b"serialisation test");

        let pk_bytes = pk.0.to_bytes().to_vec();
        let pk2 = PublicKey::from_bytes(&pk_bytes).expect("from_bytes failed");
        assert!(pk2.verify_internal(b"serialisation test", &sig).is_ok(),
            "deserialized public key must verify the original signature");
    }

    /// `PublicKey::from_bytes` must reject wrong-length input.
    #[test]
    fn public_key_from_bytes_rejects_bad_length() {
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_SIZE - 1]).is_err(),
            "must reject undersized public key bytes");
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_SIZE + 1]).is_err(),
            "must reject oversized public key bytes");
    }

    /// `PrivateKey::from_bytes` must return an error (cannot safely reconstruct
    /// the public key from SK bytes alone — by design).
    #[test]
    fn private_key_from_bytes_is_intentionally_unsupported() {
        let (_, sk) = generate_key().expect("keygen");
        let sk_bytes = sk.inner.0.to_bytes().to_vec();
        let result = PrivateKey::from_bytes(&sk_bytes);
        assert!(result.is_err(),
            "from_bytes on PrivateKey must return Err — use derive_key instead");
    }

    // ── 7. Equality & Clone ───────────────────────────────────────────────────

    /// `PrivateKey::eq` must return true for key == key and false for key != key.
    #[test]
    fn private_key_equality() {
        let seed = [0x77u8; SEED_SIZE];
        let (_, sk1) = new_key_from_seed(&seed);
        let (_, sk2) = new_key_from_seed(&seed);
        let (_, sk_other) = new_key_from_seed(&[0x88u8; SEED_SIZE]);

        assert_eq!(sk1, sk2,  "same seed → equal secret keys");
        assert_ne!(sk1, sk_other, "different seed → unequal secret keys");
    }

    /// `PublicKey::eq` must return true for equal keys and false for different ones.
    #[test]
    fn public_key_equality() {
        let seed = [0x55u8; SEED_SIZE];
        let (pk1, _) = new_key_from_seed(&seed);
        let (pk2, _) = new_key_from_seed(&seed);
        let (pk_other, _) = new_key_from_seed(&[0x66u8; SEED_SIZE]);

        assert_eq!(pk1, pk2,     "same seed → equal public keys");
        assert_ne!(pk1, pk_other, "different seed → unequal public keys");
    }

    /// Cloning a private key must yield an equal value.
    #[test]
    fn private_key_clone_is_equal() {
        let (_, sk) = generate_key().expect("keygen");
        let sk2 = sk.clone();
        assert_eq!(sk, sk2, "Clone must produce an equal PrivateKey");
    }

    /// Cloning a public key must yield an equal value.
    #[test]
    fn public_key_clone_is_equal() {
        let (pk, _) = generate_key().expect("keygen");
        let pk2 = pk.clone();
        assert_eq!(pk, pk2, "Clone must produce an equal PublicKey");
    }

    // ── 8. sign::Scheme (dyn-dispatch) API ───────────────────────────────────

    /// `Scheme::sign` + `Scheme::verify` through the trait-object interface.
    #[test]
    fn dyn_scheme_sign_verify() {
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let msg = b"dyn dispatch test";
        let sig = s.sign(sk.as_ref(), msg, None);
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        assert!(s.verify(pk.as_ref(), msg, &sig, None),
            "dyn-dispatch verify must return true");
    }

    /// Dyn verify must return `false` for a tampered message.
    #[test]
    fn dyn_scheme_verify_fails_on_wrong_message() {
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sig = s.sign(sk.as_ref(), b"good", None);
        assert!(!s.verify(pk.as_ref(), b"bad", &sig, None),
            "dyn verify must reject wrong message");
    }

    /// `Scheme::sign` must panic when a non-empty context is supplied.
    #[test]
    #[should_panic]
    fn dyn_scheme_sign_panics_on_context() {
        let s: &dyn S = &Scheme;
        let (_, sk) = s.generate_key().expect("dyn keygen");
        let opts = SignatureOpts { context: "ctx".into() };
        s.sign(sk.as_ref(), b"msg", Some(&opts));
    }

    /// `Scheme::verify` must return `false` when a non-empty context is supplied.
    #[test]
    fn dyn_scheme_verify_returns_false_on_context() {
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sig = s.sign(sk.as_ref(), b"msg", None);
        let opts = SignatureOpts { context: "ctx".into() };
        assert!(!s.verify(pk.as_ref(), b"msg", &sig, Some(&opts)),
            "verify with non-empty context must return false");
    }

    /// `Scheme::unmarshal_binary_public_key` round-trip.
    #[test]
    fn dyn_scheme_unmarshal_public_key() {
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let pk_bytes = pk.marshal_binary().expect("marshal");
        let pk2 = s.unmarshal_binary_public_key(&pk_bytes).expect("unmarshal");
        let sig = s.sign(sk.as_ref(), b"unmarshal test", None);
        assert!(s.verify(pk2.as_ref(), b"unmarshal test", &sig, None),
            "unmarshaled public key must verify");
    }

    /// `Scheme::unmarshal_binary_private_key` must currently return `Err`
    /// (intentional limitation — SK cannot be reconstructed without the seed).
    #[test]
    fn dyn_scheme_unmarshal_private_key_is_unsupported() {
        let s: &dyn S = &Scheme;
        let (_, sk) = s.generate_key().expect("dyn keygen");
        let sk_bytes = sk.marshal_binary().expect("marshal");
        assert!(s.unmarshal_binary_private_key(&sk_bytes).is_err(),
            "unmarshal_binary_private_key must return Err (by design)");
    }

    // ── 9. TypedScheme API ────────────────────────────────────────────────────

    /// `TypedScheme::generate_key_typed` + `sign_typed` + `verify_typed`.
    #[test]
    fn typed_scheme_sign_verify() {
        let s = Scheme;
        let (pk, sk) = s.generate_key_typed().expect("typed keygen");
        let msg = b"typed scheme round-trip";
        let sig = s.sign_typed(&sk, msg, None);
        assert!(s.verify_typed(&pk, msg, &sig, None),
            "typed verify must return true");
    }

    /// `TypedScheme::derive_key_typed` must be deterministic.
    #[test]
    fn typed_scheme_derive_key_deterministic() {
        let s = Scheme;
        let seed = [0xCCu8; SEED_SIZE];
        let (pk1, _) = s.derive_key_typed(&seed);
        let (pk2, _) = s.derive_key_typed(&seed);
        assert_eq!(pk1, pk2, "typed derive_key must be deterministic");
    }

    /// `TypedScheme::sign_typed` must panic when a non-empty context is passed.
    #[test]
    #[should_panic]
    fn typed_scheme_sign_panics_on_context() {
        let s = Scheme;
        let (_, sk) = s.generate_key_typed().expect("typed keygen");
        let opts = SignatureOpts { context: "ctx".into() };
        s.sign_typed(&sk, b"msg", Some(&opts));
    }

    /// `TypedScheme::unmarshal_public_key_typed` round-trip.
    #[test]
    fn typed_scheme_unmarshal_public_key() {
        let s = Scheme;
        let (pk, sk) = s.generate_key_typed().expect("typed keygen");
        let pk_bytes = pk.marshal_binary().expect("marshal");
        let pk2 = s.unmarshal_public_key_typed(&pk_bytes).expect("unmarshal");
        assert_eq!(pk, pk2, "unmarshal_public_key_typed must round-trip");
        let msg = b"typed unmarshal";
        let sig = s.sign_typed(&sk, msg, None);
        assert!(s.verify_typed(&pk2, msg, &sig, None),
            "unmarshaled typed public key must verify");
    }

    // ── 10. Cross-key checks ──────────────────────────────────────────────────

    /// Signing with key-A and verifying with key-B must fail.
    #[test]
    fn cross_key_verify_fails() {
        let (_, sk_a) = generate_key().expect("keygen A");
        let (pk_b, _) = generate_key().expect("keygen B");
        let sig = sk_a.sign_internal(b"cross test");
        assert!(pk_b.verify_internal(b"cross test", &sig).is_err(),
            "signature from key-A must not verify under key-B");
    }

    // ── 11. Latency smoke-test (benchmark gate) ───────────────────────────────

    /// Measure key-generation, signing, and verification latency.
    ///
    /// This is a smoke-test rather than a microbenchmark — it checks that
    /// each operation completes in **under 2 seconds** (a very conservative
    /// bound that would catch runaway regressions in production builds).
    ///
    /// For accurate benchmarks use `cargo bench` with Criterion.
    #[test]
    fn latency_smoke_test() {
        use std::time::Duration;
        const MAX: Duration = Duration::from_secs(2);

        // Key generation
        let t = Instant::now();
        let (pk, sk) = generate_key().expect("keygen");
        let keygen_time = t.elapsed();
        assert!(keygen_time < MAX, "keygen took {:?}, expected < {:?}", keygen_time, MAX);

        // Signing
        let msg = b"latency smoke-test message";
        let t = Instant::now();
        let sig = sk.sign_internal(msg);
        let sign_time = t.elapsed();
        assert!(sign_time < MAX, "sign took {:?}, expected < {:?}", sign_time, MAX);

        // Verification
        let t = Instant::now();
        let ok = pk.verify_internal(msg, &sig).is_ok();
        let verify_time = t.elapsed();
        assert!(verify_time < MAX, "verify took {:?}, expected < {:?}", verify_time, MAX);
        assert!(ok, "latency-test signature must verify");

        println!(
            "\nDilithium5 latency: keygen={:?}  sign={:?}  verify={:?}",
            keygen_time, sign_time, verify_time
        );
    }
}
