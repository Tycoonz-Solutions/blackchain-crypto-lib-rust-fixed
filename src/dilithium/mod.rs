// Implements ML-DSA-87, the FIPS 204 standardization of CRYSTALS-Dilithium
// (Module-Lattice-Based Digital Signature Algorithm, security category 5),
// using the RustCrypto `ml-dsa` crate.
//
// https://csrc.nist.gov/pubs/fips/204/final
//
// Design notes:
//   - The secret key is stored as the 32-byte seed (ξ). RustCrypto's
//     `SigningKey::from_seed` deterministically re-expands the full key *and*
//     yields the verifying key, so a 32-byte seed round-trips to a complete,
//     signable keypair — no separate public-key material needs to be persisted.
//   - Signing uses the `Signer` trait, which performs FIPS 204 deterministic
//     signing (rnd = 0) with an empty context string. Deterministic signing is
//     explicitly permitted by FIPS 204 §3.4 and gives reproducible signatures
//     with no RNG dependency at sign time.

use ml_dsa::{
    B32, EncodedVerifyingKey, Keypair, MlDsa87, Signer,
    Signature as MlSignature, SigningKey as MlSigningKey, VerifyingKey as MlVerifyingKey,
};
use std::fmt;
use subtle::ConstantTimeEq;

use crate::error::CryptoError;
use crate::sign::{
    self, PrivateKey as SignPrivateKey, PublicKey as SignPublicKey, Scheme as SignScheme,
    SignatureOpts, TypedScheme,
};

// ---------------------------------------------------------------------------
// Constants (ML-DSA-87 / FIPS 204)
// ---------------------------------------------------------------------------

/// Seed size in bytes (the 32-byte ξ used for deterministic key generation).
pub const SEED_SIZE: usize = 32;
/// ML-DSA-87 public (verifying) key size in bytes.
pub const PUBLIC_KEY_SIZE: usize = 2592;
/// Stored private-key size in bytes: the 32-byte seed, which expands to the
/// full 4896-byte FIPS 204 signing key on demand.
pub const PRIVATE_KEY_SIZE: usize = SEED_SIZE;
/// ML-DSA-87 signature size in bytes.
pub const SIGNATURE_SIZE: usize = 4627;

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
                "ml-dsa-87: invalid {context} size: expected {expected}, got {actual}"
            ),
            Self::VerificationFailed => write!(f, "ml-dsa-87: signature verification failed"),
            Self::Internal(msg) => write!(f, "ml-dsa-87: internal error: {msg}"),
            Self::ContextNotSupported => write!(f, "ml-dsa-87: context strings are not supported"),
            Self::TypeMismatch => write!(f, "ml-dsa-87: key type mismatch"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for CryptoError {
    fn from(e: Error) -> Self {
        CryptoError::SignatureError(e.to_string())
    }
}

/// Builds a 32-byte seed array from a byte slice, validating its length.
fn seed_from_slice(data: &[u8]) -> Result<B32, Error> {
    B32::try_from(data).map_err(|_| Error::InvalidSize {
        expected: SEED_SIZE,
        actual: data.len(),
        context: "seed",
    })
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

pub struct PublicKey(MlVerifyingKey<MlDsa87>);

impl PublicKey {
    /// Serialises the verifying key into a fixed-size buffer.
    pub fn pack(&self, buf: &mut [u8; PUBLIC_KEY_SIZE]) {
        buf.copy_from_slice(self.0.encode().as_slice());
    }

    /// Returns the encoded verifying key bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    /// Deserialises a verifying key from a `[u8; PUBLIC_KEY_SIZE]`.
    pub fn unpack(buf: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self, Error> {
        Self::from_bytes(buf)
    }

    /// Verifies `signature` over `msg` (FIPS 204 pure ML-DSA, empty context).
    pub fn verify_internal(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(Error::InvalidSize {
                expected: SIGNATURE_SIZE,
                actual: signature.len(),
                context: "signature",
            });
        }
        let sig = MlSignature::<MlDsa87>::try_from(signature).map_err(|_| Error::VerificationFailed)?;
        if self.0.verify_with_context(msg, &[], &sig) {
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
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(data)
            .map_err(|_| Error::Internal("invalid ML-DSA verifying key encoding".into()))?;
        Ok(Self(MlVerifyingKey::decode(&enc)))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MlDsa87PublicKey")
            .field(&hex::encode(&self.0.encode().as_slice()[..8]))
            .finish()
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
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
            .map(|b| b.len() == PUBLIC_KEY_SIZE && b.as_slice().ct_eq(self.0.encode().as_slice()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.to_vec())
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

/// An ML-DSA-87 signing key. The inner `SigningKey` is `ZeroizeOnDrop`, so key
/// material is scrubbed from memory automatically on drop.
pub struct PrivateKey {
    inner: MlSigningKey<MlDsa87>,
    public: PublicKey,
}

impl PrivateKey {
    /// Serialises the 32-byte seed into a fixed-size buffer.
    pub fn pack(&self, buf: &mut [u8; PRIVATE_KEY_SIZE]) {
        buf.copy_from_slice(self.inner.to_seed().as_slice());
    }

    /// Returns the raw 32-byte seed.
    pub fn seed_bytes(&self) -> [u8; SEED_SIZE] {
        let mut arr = [0u8; SEED_SIZE];
        arr.copy_from_slice(self.inner.to_seed().as_slice());
        arr
    }

    pub fn public_key_internal(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn sign_to(&self, msg: &[u8], sig: &mut [u8]) {
        assert!(
            sig.len() >= SIGNATURE_SIZE,
            "ml-dsa-87: signature buffer too small"
        );
        let s = self.inner.try_sign(msg).expect("ML-DSA deterministic signing");
        sig[..SIGNATURE_SIZE].copy_from_slice(s.encode().as_slice());
    }

    pub fn sign_internal(&self, msg: &[u8]) -> Vec<u8> {
        self.inner
            .try_sign(msg)
            .expect("ML-DSA deterministic signing")
            .encode()
            .to_vec()
    }

    /// Reconstructs a full keypair from the 32-byte seed.
    ///
    /// Unlike a raw expanded secret key, the seed deterministically re-derives
    /// both the signing key and the verifying key, so this is always safe.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        let xi = seed_from_slice(data)?;
        let inner = MlSigningKey::<MlDsa87>::from_seed(&xi);
        let public = PublicKey(inner.verifying_key());
        Ok(Self { inner, public })
    }

    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> (PublicKey, Self) {
        let sk = Self::from_bytes(seed).expect("a 32-byte seed is always valid");
        (sk.public.clone(), sk)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.seed_bytes()).expect("clone of a valid key")
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed_bytes().ct_eq(&other.seed_bytes()).into()
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
            .map(|b| b.len() == PRIVATE_KEY_SIZE && b.as_slice().ct_eq(&self.seed_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.seed_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.to_vec()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

pub fn generate_key() -> Result<(PublicKey, PrivateKey), Error> {
    let mut seed = [0u8; SEED_SIZE];
    getrandom::fill(&mut seed).map_err(|e| Error::Internal(format!("RNG failure: {e}")))?;
    Ok(PrivateKey::from_seed(&seed))
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
        "ML-DSA-87"
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
        // ML-DSA-87 is used here without a scheme-level context string.
        if let Some(o) = opts
            && !o.context.is_empty()
        {
            panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
        }
        let sk_bytes = sk.marshal_binary().expect("marshal ML-DSA SK");
        let typed_sk = PrivateKey::from_bytes(&sk_bytes)
            .unwrap_or_else(|_| panic!("{}", sign::ERR_TYPE_MISMATCH));
        typed_sk.sign_internal(message)
    }

    fn verify(
        &self,
        pk: &dyn SignPublicKey,
        message: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool {
        if let Some(o) = opts
            && !o.context.is_empty()
        {
            return false;
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
            .map(|k| Box::new(k) as Box<dyn SignPrivateKey>)
            .map_err(Into::into)
    }

    fn supports_priv_key_unmarshal(&self) -> bool {
        true
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
        if let Some(o) = opts
            && !o.context.is_empty()
        {
            panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
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

pub type MlDsaPublicKey = PublicKey;
pub type MlDsaPrivateKey = PrivateKey;
pub type MlDsaScheme = Scheme;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Scheme as S, SignatureOpts, TypedScheme as TS};
    use ml_dsa::EncodedSignature;

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn constants_match_ml_dsa_87() {
        assert_eq!(PUBLIC_KEY_SIZE, EncodedVerifyingKey::<MlDsa87>::default().len());
        assert_eq!(SIGNATURE_SIZE, EncodedSignature::<MlDsa87>::default().len());
        assert_eq!(SEED_SIZE, 32);
        assert_eq!(PRIVATE_KEY_SIZE, SEED_SIZE);
    }

    #[test]
    fn scheme_metadata() {
        let s = Scheme;
        assert_eq!(s.name(), "ML-DSA-87");
        assert_eq!(s.public_key_size(), PUBLIC_KEY_SIZE);
        assert_eq!(s.private_key_size(), PRIVATE_KEY_SIZE);
        assert_eq!(s.signature_size(), SIGNATURE_SIZE);
        assert_eq!(s.seed_size(), SEED_SIZE);
        assert!(!s.supports_context());
    }

    // ── Key generation & derivation ───────────────────────────────────────────

    #[test]
    fn generate_key_produces_correct_sizes() {
        let (pk, sk) = generate_key().expect("keygen");
        assert_eq!(pk.to_vec().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.seed_bytes().len(), PRIVATE_KEY_SIZE);
    }

    #[test]
    fn generate_key_is_non_deterministic() {
        let (pk1, _) = generate_key().expect("keygen 1");
        let (pk2, _) = generate_key().expect("keygen 2");
        assert_ne!(pk1.to_vec(), pk2.to_vec());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let seed = [0xABu8; SEED_SIZE];
        let (pk1, sk1) = new_key_from_seed(&seed);
        let (pk2, sk2) = new_key_from_seed(&seed);
        assert_eq!(pk1.to_vec(), pk2.to_vec());
        assert_eq!(sk1.seed_bytes(), sk2.seed_bytes());
    }

    #[test]
    fn derive_key_differs_for_different_seeds() {
        let (pk_a, _) = new_key_from_seed(&[0x11u8; SEED_SIZE]);
        let (pk_b, _) = new_key_from_seed(&[0x22u8; SEED_SIZE]);
        assert_ne!(pk_a.to_vec(), pk_b.to_vec());
    }

    #[test]
    #[should_panic]
    fn derive_key_panics_on_wrong_seed_size() {
        Scheme.derive_key(&[0u8; SEED_SIZE - 1]);
    }

    #[test]
    fn derive_key_with_seed_errors_on_wrong_size() {
        assert!(Scheme.derive_key_with_seed(&[0u8; SEED_SIZE + 1]).is_err());
    }

    /// Authoritative FIPS 204 keygen KAT for ML-DSA-87.
    ///
    /// Unlike `mldsa87_keygen_regression_lock` (which pins values this crate
    /// generated itself), this vector is external: the 32-byte seed ξ = 00 01
    /// 02 … 1f and its expanded ML-DSA-87 verifying key come from the LAMPS
    /// working group's `dilithium-certificates` interop examples
    /// (https://github.com/lamps-wg/dilithium-certificates/tree/main/examples),
    /// which track the FIPS 204 standard. Reproducing the exact 2592-byte
    /// verifying key from the seed proves our `KeyGen`/`ExpandKey` path is
    /// spec-conformant, not merely self-consistent.
    #[test]
    fn mldsa87_fips204_keygen_kat() {
        // Seed ξ = 0x00,0x01,…,0x1f (the LAMPS example private seed).
        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }

        let expected_pk = hex::decode(include_str!("mldsa87_lamps_pub.hex").trim())
            .expect("valid hex vector");
        assert_eq!(expected_pk.len(), PUBLIC_KEY_SIZE);

        let (pk, sk) = new_key_from_seed(&seed);
        assert_eq!(
            pk.to_vec(),
            expected_pk,
            "ML-DSA-87 seed→verifying-key must match the LAMPS/FIPS 204 interop vector"
        );

        // The re-expanded verifying key must accept a signature this key makes,
        // and a freshly deserialised copy of the authoritative bytes must too —
        // closing the loop from the external vector back through our verify path.
        let sig = sk.sign_internal(b"ml-dsa-87 fips204 kat");
        let pk_from_vector = PublicKey::from_bytes(&expected_pk).expect("deserialise vector pk");
        assert!(pk_from_vector.verify_internal(b"ml-dsa-87 fips204 kat", &sig).is_ok());
    }

    /// Deterministic keygen regression lock for ML-DSA-87: pins seed → public
    /// key so a dependency bump that alters the algorithm is caught.
    #[test]
    fn mldsa87_keygen_regression_lock() {
        let seed = [0x42u8; SEED_SIZE];
        let (pk, _sk) = new_key_from_seed(&seed);
        let mut buf = [0u8; PUBLIC_KEY_SIZE];
        pk.pack(&mut buf);
        assert_eq!(buf.len(), PUBLIC_KEY_SIZE);
        println!("MLDSA87PK16={}", hex::encode(&buf[..16]));
        const EXPECTED_HEAD: &str = "8a9d3f21d2e9cbbdc75ef8f93fbd6ff4";
        assert_eq!(
            hex::encode(&buf[..16]),
            EXPECTED_HEAD,
            "ML-DSA-87 seed→public-key derivation changed"
        );
    }

    // ── Sign / Verify ─────────────────────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip_typed() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = b"Blackchain PQC ML-DSA-87 round-trip";
        let sig = sk.sign_internal(msg);
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        assert!(pk.verify_internal(msg, &sig).is_ok());
    }

    #[test]
    fn signing_is_deterministic() {
        // FIPS 204 deterministic mode: identical (key, message) → identical sig.
        let (_, sk) = new_key_from_seed(&[0x7u8; SEED_SIZE]);
        assert_eq!(sk.sign_internal(b"same"), sk.sign_internal(b"same"));
    }

    #[test]
    fn verify_fails_on_wrong_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_internal(b"original message");
        assert!(pk.verify_internal(b"tampered message", &sig).is_err());
    }

    #[test]
    fn verify_fails_on_tampered_signature() {
        let (pk, sk) = generate_key().expect("keygen");
        let mut sig = sk.sign_internal(b"hello");
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        assert!(pk.verify_internal(b"hello", &sig).is_err());
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let (_, sk) = generate_key().expect("keygen");
        let (pk_other, _) = generate_key().expect("keygen 2");
        let sig = sk.sign_internal(b"message");
        assert!(pk_other.verify_internal(b"message", &sig).is_err());
    }

    #[test]
    fn sign_verify_empty_and_large_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let empty = sk.sign_internal(b"");
        assert!(pk.verify_internal(b"", &empty).is_ok());
        let big = vec![0x5Au8; 65_536];
        let sig = sk.sign_internal(&big);
        assert!(pk.verify_internal(&big, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_short_signature() {
        let (pk, _) = generate_key().expect("keygen");
        let err = pk.verify_internal(b"msg", &vec![0u8; SIGNATURE_SIZE - 1]);
        assert!(matches!(err, Err(Error::InvalidSize { context: "signature", .. })));
    }

    // ── Serialization ─────────────────────────────────────────────────────────

    #[test]
    fn public_key_pack_unpack_roundtrip() {
        let (pk, _) = generate_key().expect("keygen");
        let mut buf = [0u8; PUBLIC_KEY_SIZE];
        pk.pack(&mut buf);
        let pk2 = PublicKey::unpack(&buf).expect("unpack");
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_from_bytes_then_verify() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_internal(b"serialisation test");
        let pk2 = PublicKey::from_bytes(&pk.to_vec()).expect("from_bytes");
        assert!(pk2.verify_internal(b"serialisation test", &sig).is_ok());
    }

    #[test]
    fn public_key_from_bytes_rejects_bad_length() {
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_SIZE - 1]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_SIZE + 1]).is_err());
    }

    /// Unlike round-3 Dilithium, the ML-DSA seed form round-trips a full keypair,
    /// so `from_bytes` (32-byte seed) is now fully supported.
    #[test]
    fn private_key_from_seed_bytes_roundtrips() {
        let (pk, sk) = generate_key().expect("keygen");
        let sk2 = PrivateKey::from_bytes(&sk.seed_bytes()).expect("from_bytes");
        assert_eq!(sk, sk2);
        let sig = sk2.sign_internal(b"seed roundtrip");
        assert!(pk.verify_internal(b"seed roundtrip", &sig).is_ok());
    }

    #[test]
    fn private_key_from_bytes_rejects_bad_length() {
        assert!(PrivateKey::from_bytes(&[0u8; SEED_SIZE - 1]).is_err());
        assert!(PrivateKey::from_bytes(&[0u8; SEED_SIZE + 1]).is_err());
    }

    // ── Equality & Clone ──────────────────────────────────────────────────────

    #[test]
    fn key_equality_and_clone() {
        let seed = [0x77u8; SEED_SIZE];
        let (pk1, sk1) = new_key_from_seed(&seed);
        let (_, sk_other) = new_key_from_seed(&[0x88u8; SEED_SIZE]);
        assert_eq!(sk1, sk1.clone());
        assert_ne!(sk1, sk_other);
        assert_eq!(pk1, pk1.clone());
    }

    // ── dyn Scheme + TypedScheme ──────────────────────────────────────────────

    #[test]
    fn dyn_scheme_sign_verify() {
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sig = s.sign(sk.as_ref(), b"dyn dispatch test", None);
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        assert!(s.verify(pk.as_ref(), b"dyn dispatch test", &sig, None));
        assert!(!s.verify(pk.as_ref(), b"other", &sig, None));
    }

    #[test]
    #[should_panic]
    fn dyn_scheme_sign_panics_on_context() {
        let s: &dyn S = &Scheme;
        let (_, sk) = s.generate_key().expect("dyn keygen");
        let opts = SignatureOpts { context: "ctx".into() };
        s.sign(sk.as_ref(), b"msg", Some(&opts));
    }

    #[test]
    fn dyn_scheme_unmarshal_private_key_roundtrips() {
        // ML-DSA seed form makes SK reconstruction from bytes safe and supported.
        let s: &dyn S = &Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sk_bytes = sk.marshal_binary().expect("marshal SK");
        let sk2 = s.unmarshal_binary_private_key(&sk_bytes).expect("unmarshal SK");
        let sig = s.sign(sk2.as_ref(), b"sk roundtrip", None);
        assert!(s.verify(pk.as_ref(), b"sk roundtrip", &sig, None));
    }

    #[test]
    fn typed_scheme_sign_verify_and_unmarshal() {
        let s = Scheme;
        let (pk, sk) = s.generate_key_typed().expect("typed keygen");
        let sig = s.sign_typed(&sk, b"typed round-trip", None);
        assert!(s.verify_typed(&pk, b"typed round-trip", &sig, None));
        let pk2 = s.unmarshal_public_key_typed(&pk.marshal_binary().unwrap()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn cross_key_verify_fails() {
        let (_, sk_a) = generate_key().expect("keygen A");
        let (pk_b, _) = generate_key().expect("keygen B");
        let sig = sk_a.sign_internal(b"cross test");
        assert!(pk_b.verify_internal(b"cross test", &sig).is_err());
    }
}
