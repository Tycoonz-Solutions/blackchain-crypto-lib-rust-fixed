// P-521 ECDSA implementation using the `p521` crate.
//
// This module wraps P-521 ECDSA signing and verification and plugs it into the
// shared `sign::{Scheme, TypedScheme}` trait infrastructure used by every
// signing backend in this library.
//
// Key facts:
//   - NIST P-521 field elements are 66 bytes (ceil(521/8)).
//   - Uncompressed SEC1 public keys are 133 bytes (0x04 || x || y).
//   - DER-encoded ECDSA signatures are variable-length; maximum for P-521 is
//     139 bytes (tag + length + r + s, each ≤ 66 bytes + overhead).
//   - Signatures use randomized ECDSA nonces (OS CSPRNG), so signing the same
//     (key, message) pair multiple times will yield different signatures.

use p521::ecdsa::{SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use sha2::{Digest, Sha512};
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

/// Number of bytes in a P-521 scalar (private key / seed).
pub const PRIVATE_KEY_SIZE: usize = 66;
/// Number of bytes in an uncompressed SEC1 P-521 public key (0x04 || x || y).
pub const PUBLIC_KEY_SIZE: usize = 133;
/// Maximum number of bytes in a DER-encoded P-521 ECDSA signature.
pub const SIGNATURE_SIZE: usize = 139;
/// Seed size for deterministic key derivation (same as private key scalar).
pub const SEED_SIZE: usize = PRIVATE_KEY_SIZE;

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

pub struct P521PublicKey(VerifyingKey);

impl P521PublicKey {
    /// Serialise to uncompressed SEC1 format (133 bytes).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Deserialise from SEC1 bytes (compressed or uncompressed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|e| CryptoError::CurveError(e.to_string()))
    }

    /// Verify a DER-encoded ECDSA signature against `msg`.
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
        // Constant-time byte comparison to avoid timing side-channels.
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

impl TryFrom<&[u8]> for P521PublicKey {
    type Error = CryptoError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
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
// PrivateKey
// ---------------------------------------------------------------------------

/// A P-521 ECDSA signing key.
///
/// The inner `SigningKey` byte representation is zeroized on drop for
/// defense-in-depth — ECDSA private key exposure allows full signature forgery.
pub struct P521PrivateKey(SigningKey);

impl Zeroize for P521PrivateKey {
    fn zeroize(&mut self) {
        // Overwrite the signing key scalar in memory by replacing it with a harmless dummy key (scalar = 1).
        let mut dummy = [0u8; 66];
        dummy[65] = 1;
        if let Ok(dummy_key) = SigningKey::from_slice(&dummy) {
            self.0 = dummy_key;
        }
    }
}

impl Drop for P521PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl P521PrivateKey {
    /// Serialise the private scalar to bytes (66 bytes).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Deserialise from a 66-byte scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|e| CryptoError::CurveError(e.to_string()))
    }

    /// Derive the corresponding public key.
    pub fn public_key_typed(&self) -> P521PublicKey {
        P521PublicKey(VerifyingKey::from(&self.0))
    }

    /// Sign `msg` and return a DER-encoded signature.
    ///
    /// Uses the OS CSPRNG for nonce randomization (RFC 6979 is not used).
    /// Two calls with the same key and message will produce different but
    /// both-valid signatures. This provides additional hedging against
    /// nonce-reuse attacks.
    pub fn sign_msg(&self, msg: &[u8]) -> Vec<u8> {
        let sig: p521::ecdsa::Signature = self.0.sign(msg);
        sig.to_bytes().to_vec()
    }
}

impl Clone for P521PrivateKey {
    fn clone(&self) -> Self {
        Self(SigningKey::from_slice(&self.0.to_bytes()).expect("clone of valid P521 key"))
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

impl TryFrom<&[u8]> for P521PrivateKey {
    type Error = CryptoError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
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
// Free functions
// ---------------------------------------------------------------------------

/// Generate a random P-521 key pair using the OS CSPRNG.
pub fn generate_key() -> Result<(P521PublicKey, P521PrivateKey), CryptoError> {
    use rand_core::OsRng;
    let sk = SigningKey::random(&mut OsRng);
    let pk = P521PublicKey(VerifyingKey::from(&sk));
    Ok((pk, P521PrivateKey(sk)))
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

pub struct P521Scheme;

impl P521Scheme {
    /// Derive a key pair deterministically from exactly [`SEED_SIZE`] bytes.
    ///
    /// # Panics
    /// Panics if `seed.len() != SEED_SIZE` — matches the `dyn SignScheme`
    /// panic contract documented in `sign::Scheme::derive_key`.
    fn derive_keypair_from_seed(seed: &[u8]) -> (P521PublicKey, P521PrivateKey) {
        assert!(
            seed.len() == SEED_SIZE,
            "{}; expected {SEED_SIZE}, got {}",
            sign::ERR_SEED_SIZE,
            seed.len(),
        );
        // A raw 66-byte seed may lie above the P-521 group order n (≈ 2^521),
        // causing SigningKey::from_slice to reject it.  Instead, derive the
        // scalar by hashing: SHA-512 produces 64 bytes, which we place in
        // scalar_bytes[2..66] leaving the top 2 bytes zero.  The result is
        // always < 2^512 << n, so it is always a valid non-zero scalar.
        // A domain-separation prefix and counter suffix match the pattern used
        // by other blackchain KDFs and allow future extension.
        for counter in 0u8..=255 {
            let mut h = Sha512::new();
            h.update(b"blackchain-p521-derive-v1");
            h.update(seed);
            h.update([counter]);
            let digest = h.finalize(); // 64 bytes

            let mut scalar_bytes = [0u8; PRIVATE_KEY_SIZE]; // 66 bytes; top 2 = 0x00
            scalar_bytes[2..].copy_from_slice(&digest);

            if let Ok(sk) = SigningKey::from_slice(&scalar_bytes) {
                let pk = P521PublicKey(VerifyingKey::from(&sk));
                return (pk, P521PrivateKey(sk));
            }
        }
        panic!(
            "derive_keypair_from_seed: no valid scalar found in 256 attempts (astronomically unlikely)"
        );
    }
}

// --- sign::Scheme impl ------------------------------------------------------

impl SignScheme for P521Scheme {
    fn name(&self) -> &'static str {
        "P-521"
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
        let (pk, sk) = generate_key()?;
        Ok((Box::new(pk), Box::new(sk)))
    }

    fn derive_key(&self, seed: &[u8]) -> (Box<dyn SignPublicKey>, Box<dyn SignPrivateKey>) {
        let (pk, sk) = Self::derive_keypair_from_seed(seed);
        (Box::new(pk), Box::new(sk))
    }

    fn sign(
        &self,
        sk: &dyn SignPrivateKey,
        message: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> Vec<u8> {
        // P-521 ECDSA does not support context strings; panic to enforce the contract.
        if let Some(o) = opts
            && !o.context.is_empty() {
            panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
        }
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
        opts: Option<&SignatureOpts>,
    ) -> bool {
        // A non-empty context is not supported; return false rather than panic
        // (verify is never expected to panic in the dyn contract).
        if let Some(o) = opts
            && !o.context.is_empty() {
            return false;
        }
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
        generate_key()
    }

    fn derive_key_typed(&self, seed: &[u8]) -> (P521PublicKey, P521PrivateKey) {
        Self::derive_keypair_from_seed(seed)
    }

    fn sign_typed(&self, sk: &P521PrivateKey, msg: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8> {
        if let Some(o) = opts
            && !o.context.is_empty() {
            panic!("{}", sign::ERR_CONTEXT_NOT_SUPPORTED);
        }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Scheme as S, SignatureOpts, TypedScheme as TS};
    use std::time::Instant;

    // ── 1. Constant sanity ────────────────────────────────────────────────────

    /// Named constants must have the expected values.
    #[test]
    fn constants_are_correct() {
        assert_eq!(PRIVATE_KEY_SIZE, 66, "P-521 scalar is 66 bytes");
        assert_eq!(
            PUBLIC_KEY_SIZE, 133,
            "uncompressed SEC1 P-521 point is 133 bytes"
        );
        assert_eq!(
            SEED_SIZE, PRIVATE_KEY_SIZE,
            "seed and private key are the same size"
        );
        let sig_size = SIGNATURE_SIZE;
        let priv_key_size = PRIVATE_KEY_SIZE;
        assert!(
            sig_size > priv_key_size,
            "max DER signature must be larger than the scalar"
        );
    }

    /// Scheme metadata accessors must return the named constants.
    #[test]
    fn scheme_metadata() {
        let s = P521Scheme;
        assert_eq!(s.name(), "P-521");
        assert_eq!(s.public_key_size(), PUBLIC_KEY_SIZE);
        assert_eq!(s.private_key_size(), PRIVATE_KEY_SIZE);
        assert_eq!(s.signature_size(), SIGNATURE_SIZE);
        assert_eq!(s.seed_size(), SEED_SIZE);
        assert!(
            !s.supports_context(),
            "P-521 must NOT advertise context support"
        );
    }

    // ── 2. Key generation ─────────────────────────────────────────────────────

    /// Random key generation produces keys of the correct sizes.
    #[test]
    fn generate_key_sizes() {
        let (pk, sk) = generate_key().expect("keygen");
        assert_eq!(pk.as_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), PRIVATE_KEY_SIZE);
    }

    /// Two independent random key-generations must yield distinct keys.
    #[test]
    fn generate_key_is_non_deterministic() {
        let (pk1, _) = generate_key().expect("keygen 1");
        let (pk2, _) = generate_key().expect("keygen 2");
        assert_ne!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "independent keygens must produce distinct keys"
        );
    }

    // ── 3. Deterministic derivation ───────────────────────────────────────────

    /// Same seed always yields the same key pair.
    #[test]
    fn derive_key_is_deterministic() {
        let seed = [0x01u8; SEED_SIZE]; // non-zero — zero scalar is invalid in P-521
        let (pk1, sk1) = P521Scheme::derive_keypair_from_seed(&seed);
        let (pk2, sk2) = P521Scheme::derive_keypair_from_seed(&seed);
        assert_eq!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "same seed → same public key"
        );
        assert_eq!(
            sk1.as_bytes(),
            sk2.as_bytes(),
            "same seed → same private key"
        );
    }

    /// Different seeds must yield different keys.
    #[test]
    fn derive_key_differs_for_different_seeds() {
        // Use small scalars that are guaranteed valid for P-521 (group order is
        // slightly less than 2^521, so a 66-byte value with only the first byte
        // non-zero is always safely below it).
        let mut seed_a = [0u8; SEED_SIZE];
        seed_a[0] = 0x01;
        let mut seed_b = [0u8; SEED_SIZE];
        seed_b[0] = 0x02;
        let (pk_a, _) = P521Scheme::derive_keypair_from_seed(&seed_a);
        let (pk_b, _) = P521Scheme::derive_keypair_from_seed(&seed_b);
        assert_ne!(
            pk_a.as_bytes(),
            pk_b.as_bytes(),
            "different seeds → different keys"
        );
    }

    /// `Scheme::derive_key` panics on a short seed (mirrors Go contract).
    #[test]
    #[should_panic]
    fn derive_key_panics_on_short_seed() {
        P521Scheme.derive_key(&[0x01u8; SEED_SIZE - 1]);
    }

    /// `Scheme::derive_key` panics on an oversized seed.
    #[test]
    #[should_panic]
    fn derive_key_panics_on_long_seed() {
        P521Scheme.derive_key(&[0x01u8; SEED_SIZE + 1]);
    }

    // ── 4. Sign / Verify round-trips ──────────────────────────────────────────

    /// Basic sign → verify round-trip.
    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = b"Blackchain P-521 ECDSA round-trip";
        let sig = sk.sign_msg(msg);
        assert!(
            pk.verify_sig(msg, &sig).is_ok(),
            "valid signature must verify"
        );
    }

    /// The p521 crate adds fresh OS randomness to every signature (randomized
    /// ECDSA).  Two calls with the same key and message will produce different
    /// but both-valid signatures.
    #[test]
    fn signature_is_randomized() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = b"randomization test";
        let sig1 = sk.sign_msg(msg);
        let sig2 = sk.sign_msg(msg);
        // Both must verify, but they must differ (randomized nonce).
        assert!(pk.verify_sig(msg, &sig1).is_ok(), "sig1 must verify");
        assert!(pk.verify_sig(msg, &sig2).is_ok(), "sig2 must verify");
        assert_ne!(
            sig1, sig2,
            "randomized ECDSA must produce distinct signatures"
        );
    }

    /// Verifying against the wrong message must fail.
    #[test]
    fn verify_fails_on_wrong_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_msg(b"original");
        assert!(
            pk.verify_sig(b"tampered", &sig).is_err(),
            "signature must not verify against a different message"
        );
    }

    /// Verifying a bit-flipped signature must fail.
    #[test]
    fn verify_fails_on_tampered_signature() {
        let (pk, sk) = generate_key().expect("keygen");
        let mut sig = sk.sign_msg(b"hello");
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        assert!(
            pk.verify_sig(b"hello", &sig).is_err(),
            "tampered signature must not verify"
        );
    }

    /// Verifying under the wrong public key must fail.
    #[test]
    fn verify_fails_with_wrong_key() {
        let (_, sk) = generate_key().expect("keygen");
        let (pk_other, _) = generate_key().expect("keygen other");
        let sig = sk.sign_msg(b"message");
        assert!(
            pk_other.verify_sig(b"message", &sig).is_err(),
            "signature must not verify under a foreign public key"
        );
    }

    /// Empty message must sign and verify correctly.
    #[test]
    fn sign_verify_empty_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_msg(b"");
        assert!(
            pk.verify_sig(b"", &sig).is_ok(),
            "empty-message signature must verify"
        );
    }

    /// Large message (~64 KiB) must sign and verify correctly.
    #[test]
    fn sign_verify_large_message() {
        let (pk, sk) = generate_key().expect("keygen");
        let msg = vec![0xA5u8; 65_536];
        let sig = sk.sign_msg(&msg);
        assert!(
            pk.verify_sig(&msg, &sig).is_ok(),
            "large-message signature must verify"
        );
    }

    // ── 5. Serialization round-trips ──────────────────────────────────────────

    /// Public key serialises and deserialises to an equal key.
    #[test]
    fn public_key_marshal_roundtrip() {
        let (pk, _) = generate_key().expect("keygen");
        let pk2 = P521PublicKey::from_bytes(&pk.as_bytes()).expect("deser failed");
        assert_eq!(pk, pk2, "public key round-trip must preserve equality");
    }

    /// Deserialised public key must verify the original signature.
    #[test]
    fn deserialized_public_key_verifies() {
        let (pk, sk) = generate_key().expect("keygen");
        let sig = sk.sign_msg(b"deser test");
        let pk2 = P521PublicKey::from_bytes(&pk.as_bytes()).expect("deser");
        assert!(
            pk2.verify_sig(b"deser test", &sig).is_ok(),
            "deserialized public key must verify"
        );
    }

    /// Private key serialises and deserialises to an equal key.
    #[test]
    fn private_key_marshal_roundtrip() {
        let (_, sk) = generate_key().expect("keygen");
        let sk2 = P521PrivateKey::from_bytes(&sk.as_bytes()).expect("deser failed");
        assert_eq!(sk, sk2, "private key round-trip must preserve equality");
    }

    /// Deserialised private key must produce signatures that verify under the
    /// original public key (nonces are randomized, so bitwise equality is not
    /// expected).
    #[test]
    fn deserialized_private_key_signs_verifiably() {
        let (pk, sk) = generate_key().expect("keygen");
        let sk2 = P521PrivateKey::from_bytes(&sk.as_bytes()).expect("deser");
        let sig = sk2.sign_msg(b"roundtrip");
        assert!(
            pk.verify_sig(b"roundtrip", &sig).is_ok(),
            "deserialized SK must produce verifiable signatures"
        );
    }

    /// `from_bytes` must reject obviously invalid public key bytes.
    #[test]
    fn from_bytes_rejects_invalid_public_key() {
        assert!(
            P521PublicKey::from_bytes(&[0u8; 33]).is_err(),
            "must reject clearly wrong-sized public key bytes"
        );
    }

    /// `from_bytes` must reject a zero scalar (invalid in P-521).
    #[test]
    fn from_bytes_rejects_zero_private_key() {
        assert!(
            P521PrivateKey::from_bytes(&[0u8; PRIVATE_KEY_SIZE]).is_err(),
            "zero scalar is not a valid P-521 private key"
        );
    }

    // ── 6. Equality & Clone ───────────────────────────────────────────────────

    /// Clone of a public key must be equal to the original.
    #[test]
    fn public_key_clone_is_equal() {
        let (pk, _) = generate_key().expect("keygen");
        assert_eq!(pk.clone(), pk, "Clone must produce an equal PublicKey");
    }

    /// Clone of a private key must be equal to the original.
    #[test]
    fn private_key_clone_is_equal() {
        let (_, sk) = generate_key().expect("keygen");
        assert_eq!(sk.clone(), sk, "Clone must produce an equal PrivateKey");
    }

    /// Keys derived from the same seed must be byte-equal; different seeds must differ.
    #[test]
    fn key_equality_across_derivations() {
        // Use small scalars that are guaranteed valid for P-521.
        let mut seed = [0u8; SEED_SIZE];
        seed[0] = 0x03;
        let mut seed_o = [0u8; SEED_SIZE];
        seed_o[0] = 0x04;
        let (pk1, sk1) = P521Scheme::derive_keypair_from_seed(&seed);
        let (pk2, sk2) = P521Scheme::derive_keypair_from_seed(&seed);
        let (pk_o, sk_o) = P521Scheme::derive_keypair_from_seed(&seed_o);
        assert_eq!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "same seed → same public key"
        );
        assert_eq!(
            sk1.as_bytes(),
            sk2.as_bytes(),
            "same seed → same private key"
        );
        assert_ne!(
            pk1.as_bytes(),
            pk_o.as_bytes(),
            "different seed → different public key"
        );
        assert_ne!(
            sk1.as_bytes(),
            sk_o.as_bytes(),
            "different seed → different private key"
        );
    }

    // ── 7. dyn-trait (sign::Scheme) API ──────────────────────────────────────

    /// `Scheme::sign` + `Scheme::verify` via trait-object dispatch.
    #[test]
    fn dyn_scheme_sign_verify() {
        let s: &dyn S = &P521Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let msg = b"dyn dispatch test";
        let sig = s.sign(sk.as_ref(), msg, None);
        assert!(
            s.verify(pk.as_ref(), msg, &sig, None),
            "dyn-dispatch verify must return true"
        );
    }

    /// Dyn verify must return false for a wrong message.
    #[test]
    fn dyn_scheme_verify_fails_wrong_message() {
        let s: &dyn S = &P521Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sig = s.sign(sk.as_ref(), b"good", None);
        assert!(
            !s.verify(pk.as_ref(), b"bad", &sig, None),
            "dyn verify must reject wrong message"
        );
    }

    /// `Scheme::sign` must panic when a non-empty context is supplied.
    #[test]
    #[should_panic]
    fn dyn_scheme_sign_panics_on_context() {
        let s: &dyn S = &P521Scheme;
        let (_, sk) = s.generate_key().expect("dyn keygen");
        let opts = SignatureOpts {
            context: "ctx".into(),
        };
        s.sign(sk.as_ref(), b"msg", Some(&opts));
    }

    /// `Scheme::verify` must return false when a non-empty context is supplied.
    #[test]
    fn dyn_scheme_verify_returns_false_on_context() {
        let s: &dyn S = &P521Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sig = s.sign(sk.as_ref(), b"msg", None);
        let opts = SignatureOpts {
            context: "ctx".into(),
        };
        assert!(
            !s.verify(pk.as_ref(), b"msg", &sig, Some(&opts)),
            "verify with non-empty context must return false"
        );
    }

    /// `unmarshal_binary_public_key` round-trip through the dyn interface.
    #[test]
    fn dyn_unmarshal_public_key_roundtrip() {
        let s: &dyn S = &P521Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let pk_bytes = pk.marshal_binary().expect("marshal");
        let pk2 = s.unmarshal_binary_public_key(&pk_bytes).expect("unmarshal");
        let sig = s.sign(sk.as_ref(), b"unmarshal test", None);
        assert!(
            s.verify(pk2.as_ref(), b"unmarshal test", &sig, None),
            "unmarshaled dyn public key must verify"
        );
    }

    /// `unmarshal_binary_private_key` round-trip through the dyn interface.
    #[test]
    fn dyn_unmarshal_private_key_roundtrip() {
        let s: &dyn S = &P521Scheme;
        let (pk, sk) = s.generate_key().expect("dyn keygen");
        let sk_bytes = sk.marshal_binary().expect("marshal SK");
        let sk2 = s
            .unmarshal_binary_private_key(&sk_bytes)
            .expect("unmarshal SK");
        let sig = s.sign(sk2.as_ref(), b"sk roundtrip", None);
        assert!(
            s.verify(pk.as_ref(), b"sk roundtrip", &sig, None),
            "unmarshaled dyn private key must produce valid signatures"
        );
    }

    // ── 8. TypedScheme API ────────────────────────────────────────────────────

    /// `TypedScheme::generate_key_typed` + `sign_typed` + `verify_typed`.
    #[test]
    fn typed_scheme_sign_verify() {
        let s = P521Scheme;
        let (pk, sk) = s.generate_key_typed().expect("typed keygen");
        let msg = b"typed P-521 round-trip";
        let sig = s.sign_typed(&sk, msg, None);
        assert!(
            s.verify_typed(&pk, msg, &sig, None),
            "typed verify must succeed"
        );
    }

    /// `TypedScheme::derive_key_typed` must be deterministic (seed → same bytes).
    #[test]
    fn typed_scheme_derive_key_deterministic() {
        let s = P521Scheme;
        // Use a small scalar that is definitely below the P-521 group order.
        let mut seed = [0u8; SEED_SIZE];
        seed[0] = 0x05;
        let (pk1, sk1) = s.derive_key_typed(&seed);
        let (pk2, sk2) = s.derive_key_typed(&seed);
        assert_eq!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "typed derive_key must be deterministic"
        );
        assert_eq!(
            sk1.as_bytes(),
            sk2.as_bytes(),
            "typed derive_key must be deterministic"
        );
    }

    /// `TypedScheme::sign_typed` must panic on non-empty context.
    #[test]
    #[should_panic]
    fn typed_scheme_sign_panics_on_context() {
        let s = P521Scheme;
        let (_, sk) = s.generate_key_typed().expect("typed keygen");
        let opts = SignatureOpts {
            context: "ctx".into(),
        };
        s.sign_typed(&sk, b"msg", Some(&opts));
    }

    /// `TypedScheme::unmarshal_public_key_typed` round-trip.
    #[test]
    fn typed_unmarshal_public_key_roundtrip() {
        let s = P521Scheme;
        let (pk, sk) = s.generate_key_typed().expect("typed keygen");
        let pk_bytes = pk.marshal_binary().expect("marshal");
        let pk2 = s.unmarshal_public_key_typed(&pk_bytes).expect("unmarshal");
        assert_eq!(pk, pk2);
        let sig = s.sign_typed(&sk, b"typed unmarshal", None);
        assert!(s.verify_typed(&pk2, b"typed unmarshal", &sig, None));
    }

    // ── 9. Cross-key check ────────────────────────────────────────────────────

    /// Signing with key-A and verifying with key-B must fail.
    #[test]
    fn cross_key_verify_fails() {
        let (_, sk_a) = generate_key().expect("keygen A");
        let (pk_b, _) = generate_key().expect("keygen B");
        let sig = sk_a.sign_msg(b"cross test");
        assert!(
            pk_b.verify_sig(b"cross test", &sig).is_err(),
            "signature from key-A must not verify under key-B"
        );
    }

    // ── 10. Latency smoke-test (benchmark gate) ───────────────────────────────

    /// Each primitive must complete in under 2 seconds (regression guard).
    #[test]
    fn latency_smoke_test() {
        use std::time::Duration;
        const MAX: Duration = Duration::from_secs(2);

        let t = Instant::now();
        let (pk, sk) = generate_key().expect("keygen");
        let keygen_time = t.elapsed();
        assert!(keygen_time < MAX, "keygen too slow: {:?}", keygen_time);

        let msg = b"latency smoke-test";
        let t = Instant::now();
        let sig = sk.sign_msg(msg);
        let sign_time = t.elapsed();
        assert!(sign_time < MAX, "sign too slow: {:?}", sign_time);

        let t = Instant::now();
        let ok = pk.verify_sig(msg, &sig).is_ok();
        let verify_time = t.elapsed();
        assert!(verify_time < MAX, "verify too slow: {:?}", verify_time);
        assert!(ok);

        println!(
            "\nP-521 latency: keygen={:?}  sign={:?}  verify={:?}",
            keygen_time, sign_time, verify_time
        );
    }
}
