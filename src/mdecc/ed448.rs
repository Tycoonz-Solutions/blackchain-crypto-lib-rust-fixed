// ed448 — Ed448 / Ed448Ph signature scheme.
//
// Crate roles (verified against actual published APIs):
//
//   ed448-rust 0.1.1
//      PrivateKey::from([u8;57])  — seed → key expansion (SHAKE-256), correct
//      PrivateKey::sign(msg, ctx) — signs with in-memory key, correct
//      PrivateKey::as_bytes()     — returns seed bytes
//      PublicKey::from(&PrivateKey) — derives pk from sk in-memory, correct
//      PublicKey::as_byte()       — returns raw [u8;57] of the point
//      PublicKey::try_from(&[u8]) — BUG: casts bytes as scalar, no decompression
//                                    → NEVER use for deserialization
//
//   ed448-goldilocks 0.4.0
//      CompressedEdwardsY([u8;57]).decompress() -> Option<ExtendedPoint>
//      ExtendedPoint: scalar_mul, add, negate, compress, generator
//      Scalar: from_bytes, to_bytes
//      No signing API (no SigningKey / VerifyingKey in this version)
//
// Strategy
// ────────
// • Key generation and signing: ed448-rust (correct, fast)
// • Public key deserialization: ed448-goldilocks CompressedEdwardsY::decompress
//   to validate the point, then store the validated raw bytes
// • Verification of deserialized keys: re-derive using ed448-rust's in-memory
//   PublicKey constructed via PublicKey::from(&sk) path is unavailable post-
//   deserialization, so we verify using ed448-goldilocks manually (RFC 8032).
//
// Signing modes
// ─────────────
//   ED448   — standard (default), context string forwarded verbatim.
//   ED448Ph — prehash (SHAKE-256), activated when opts.context == "PREHASHED".

use std::fmt;

use ed448_goldilocks::Scalar;
use ed448_goldilocks::curve::edwards::{CompressedEdwardsY, ExtendedPoint};
use ed448_rust::{PrivateKey as Ed448Priv, PublicKey as Ed448RustPub};
use rand_core::{CryptoRng, OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::sign::{
    self, PrivateKey as PrivateKeyTrait, PublicKey as PublicKeyTrait, Scheme as SchemeTrait,
    SignatureOpts, TypedScheme,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SEED_SIZE: usize = 57;
pub const PUBLIC_KEY_SIZE: usize = 57;
pub const PRIVATE_KEY_SIZE: usize = 57;
pub const SIGNATURE_SIZE: usize = 114;

const PREHASH_CONTEXT: &str = "PREHASHED";

/// The Ed448 field prime `p = 2^448 - 2^224 - 1`, little-endian.
/// `bytes[0..28] = 0xff`, `bytes[28] = 0xfe`, `bytes[29..56] = 0xff`.
const FIELD_PRIME_LE: [u8; 56] = {
    let mut p = [0xffu8; 56];
    p[28] = 0xfe;
    p
};

/// Decodes a 57-byte Ed448 point encoding, enforcing RFC 8032 §5.2.3
/// canonicality on top of goldilocks' on-curve check, and rejecting small-order
/// points:
///
///   1. the final byte carries only the x-sign in bit 7 — bits 0..6 must be 0;
///   2. the 56-byte little-endian y-coordinate must be strictly less than `p`;
///   3. the point must not be small-order (identity or torsion).
///
/// goldilocks' `decompress` silently reduces `y` mod `p` and ignores the padding
/// bits, so without guards (1)/(2) several distinct byte strings decode to the
/// same point (a non-canonical-encoding / malleability gap).
///
/// Guard (3) closes a universal-forgery gap: a small-order public key `A` (the
/// identity being the sharpest case) makes the cofactored verification equation
/// `[4]([S]B − [k]A − R) == O` collapse to the identity for `R = O, S = 0`
/// *regardless of the message* — so a signature would verify for anything. A
/// legitimate key `A = [s]B` lies in the prime-order subgroup, so `[4]A` is
/// never the identity; every order-dividing-4 (torsion) point, including `O`,
/// satisfies `[4]P == O` and is rejected. The same guard is applied to the
/// signature point `R`, which is likewise never small-order for honest
/// signatures.
fn decode_canonical_point(raw: &[u8; PUBLIC_KEY_SIZE]) -> Result<ExtendedPoint, CryptoError> {
    // (1) Unused padding bits around the sign bit must be clear.
    if raw[56] & 0x7f != 0 {
        return Err(CryptoError::CurveError(
            "non-canonical Ed448 point: unused bits set in final byte".into(),
        ));
    }

    // (2) Reject y >= p. Little-endian comparison from the most-significant byte.
    let mut y_lt_p = false;
    for i in (0..56).rev() {
        if raw[i] < FIELD_PRIME_LE[i] {
            y_lt_p = true;
            break;
        }
        if raw[i] > FIELD_PRIME_LE[i] {
            break;
        }
    }
    if !y_lt_p {
        return Err(CryptoError::CurveError(
            "non-canonical Ed448 point: y-coordinate >= field prime".into(),
        ));
    }

    let point = CompressedEdwardsY(*raw)
        .decompress()
        .ok_or_else(|| CryptoError::CurveError("invalid Ed448 curve point".into()))?;

    // (3) Reject small-order (torsion) points. Ed448's cofactor is 4, so any
    // point whose order divides 4 — the identity included — is killed by [4]·P.
    if point.double().double() == ExtendedPoint::identity() {
        return Err(CryptoError::CurveError(
            "small-order Ed448 point rejected (identity or torsion)".into(),
        ));
    }

    Ok(point)
}

// ---------------------------------------------------------------------------
// Signing mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningMode {
    Ed448,
    Ed448Ph,
}

impl SigningMode {
    fn from_opts(opts: Option<&SignatureOpts>) -> Self {
        match opts {
            Some(o) if o.context == PREHASH_CONTEXT => Self::Ed448Ph,
            _ => Self::Ed448,
        }
    }

    /// "PREHASHED" is our internal sentinel — never forwarded to the library.
    fn context_opt<'a>(&self, opts: Option<&'a SignatureOpts>) -> Option<&'a [u8]> {
        match self {
            Self::Ed448Ph => None,
            Self::Ed448 => opts.map(|o| o.context.as_bytes()).filter(|b| !b.is_empty()),
        }
    }
}

// ---------------------------------------------------------------------------
// PublicKey
// ---------------------------------------------------------------------------

/// An Ed448 public key.
///
/// Stores validated raw bytes (curve-point-validated via goldilocks) plus the
/// trusted `ed448-rust` object built only from in-memory key derivation.
///
/// The `trusted_inner` field is `Some` when the key was produced by key
/// generation or seed derivation (where `ed448-rust`'s in-memory path is
/// correct), and `None` when the key was deserialised from bytes (where we
/// use the goldilocks-validated bytes for verification instead).
#[derive(Clone)]
pub struct PublicKey {
    /// Validated raw bytes of the compressed Edwards-Y point.
    raw: [u8; PUBLIC_KEY_SIZE],
    /// Present only for keys derived in-memory (not from raw bytes).
    trusted_inner: Option<Ed448RustPub>,
}

impl PublicKey {
    /// Constructs from a trusted in-memory `ed448-rust` key.
    /// No decompression needed — the key was derived correctly.
    fn from_trusted_inner(inner: Ed448RustPub) -> Self {
        let raw = inner.as_byte();
        Self {
            raw,
            trusted_inner: Some(inner),
        }
    }

    /// Deserialises from bytes, using goldilocks to validate the curve point.
    ///
    /// This is the fix: goldilocks' `decompress()` mathematically validates
    /// the Edwards-Y encoding, unlike `ed448-rust`'s broken `try_from`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: PUBLIC_KEY_SIZE,
                actual: data.len(),
            });
        }
        let mut raw = [0u8; PUBLIC_KEY_SIZE];
        raw.copy_from_slice(data);

        // Validate: does this byte string encode a real Ed448 curve point,
        // canonically? (rejects y >= p and non-zero sign-byte padding)
        decode_canonical_point(&raw)?;

        // We do NOT call ed448-rust here — that's the bug we're avoiding.
        // trusted_inner is None; verify_sig will use the goldilocks path.
        Ok(Self {
            raw,
            trusted_inner: None,
        })
    }

    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.raw
    }

    /// Verifies `signature` over `msg`.
    ///
    /// • If this key was generated in-memory: uses `ed448-rust` (fast, correct).
    /// • If this key was deserialised from bytes: uses goldilocks manually
    ///   (RFC 8032 verification, correct, avoids the broken `try_from` path).
    pub fn verify_sig(
        &self,
        msg: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> Result<(), CryptoError> {
        if signature.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: SIGNATURE_SIZE,
                actual: signature.len(),
            });
        }
        let mut sig_arr = [0u8; SIGNATURE_SIZE];
        sig_arr.copy_from_slice(signature);

        let mode = SigningMode::from_opts(opts);
        let ctx_opt = mode.context_opt(opts);

        match &self.trusted_inner {
            // Fast path: key came from in-memory derivation, ed448-rust is safe.
            Some(inner) => {
                let result = match mode {
                    SigningMode::Ed448 => inner.verify(msg, &sig_arr, ctx_opt),
                    SigningMode::Ed448Ph => inner.verify_ph(msg, &sig_arr, ctx_opt),
                };
                result.map_err(|e| CryptoError::SignatureError(format!("ed448 verify: {e:?}")))
            }
            // Deserialized key path: verify manually via RFC 8032 using goldilocks.
            None => self.verify_via_goldilocks(msg, &sig_arr, ctx_opt, mode),
        }
    }

    /// RFC 8032 Ed448 verification using goldilocks primitives.
    ///
    /// This path is taken for keys reconstructed from bytes, where we cannot
    /// trust `ed448-rust`'s `PublicKey::try_from`. We use goldilocks'
    /// mathematically correct decompression and scalar multiplication instead.
    fn verify_via_goldilocks(
        &self,
        msg: &[u8],
        sig: &[u8; SIGNATURE_SIZE],
        ctx: Option<&[u8]>,
        mode: SigningMode,
    ) -> Result<(), CryptoError> {
        use sha3::{
            Shake256,
            digest::{ExtendableOutput, Update, XofReader},
        };

        // Decompress the public key point A (canonically validated).
        let a_point = decode_canonical_point(&self.raw)
            .map_err(|_| CryptoError::CurveError("public key decompression failed".into()))?;

        // Split signature: R (57 bytes) || S (57 bytes).
        let mut r_bytes = [0u8; 57];
        let mut s_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&sig[..57]);
        s_bytes.copy_from_slice(&sig[57..]);

        // Decompress the signature point R, rejecting non-canonical encodings
        // (y >= p or sign-byte padding) just like the public key.
        let r_point = decode_canonical_point(&r_bytes).map_err(|_| {
            CryptoError::SignatureError("signature R decompression failed".into())
        })?;

        // Decode scalar S, rejecting non-canonical encodings. `from_canonical_bytes`
        // enforces both the high-bit constraint (byte 56 == 0, top two bits of
        // byte 55 clear) and full reduction (S < group order L). This prevents
        // signature malleability via S' = S + L, which a raw `Scalar::from_bytes`
        // load would silently accept.
        let s_scalar = Scalar::from_canonical_bytes(s_bytes).ok_or_else(|| {
            CryptoError::SignatureError("non-canonical Ed448 S scalar (S >= L)".into())
        })?;

        // Build the SHAKE-256 challenge hash per RFC 8032 §5.2.7:
        // dom4(x, y) || R || A || msg  where dom4 encodes phflag and context.
        let mut hasher = Shake256::default();

        // Domain separator: "SigEd448" || phflag || |ctx| || ctx
        hasher.update(b"SigEd448");
        let phflag: u8 = match mode {
            SigningMode::Ed448Ph => 1,
            SigningMode::Ed448 => 0,
        };
        hasher.update(&[phflag]);
        let ctx_bytes = ctx.unwrap_or(b"");
        if ctx_bytes.len() > 255 {
            return Err(CryptoError::SignatureError(
                "Ed448 context string exceeds 255 bytes".into(),
            ));
        }
        hasher.update(&[ctx_bytes.len() as u8]);
        hasher.update(ctx_bytes);

        hasher.update(&r_bytes); // R
        hasher.update(&self.raw); // A

        match mode {
            SigningMode::Ed448 => hasher.update(msg),
            SigningMode::Ed448Ph => {
                let mut ph_hasher = Shake256::default();
                ph_hasher.update(msg);
                let mut ph_hash = [0u8; 64];
                ph_hasher.finalize_xof().read(&mut ph_hash);
                hasher.update(&ph_hash);
            }
        }

        let mut k_bytes = [0u8; 114];
        hasher.finalize_xof().read(&mut k_bytes);

        // Reduce k mod group order.
        // RFC 8032 specifies k is derived by reducing the 114-byte hash output modulo L.
        let mut k_scalar = Scalar::zero();
        let base_256 = Scalar::from(256u32);
        for byte in k_bytes.iter().rev() {
            k_scalar = k_scalar * base_256 + Scalar::from(*byte as u32);
        }

        // Verify: [4][S]B == [4](R + [k]A)  (RFC 8032 §5.2.7 step 4, Ed448 cofactor is 4)
        // i.e.   [4]([S]B - [k]A - R) == identity
        let sb = ExtendedPoint::generator().scalar_mul(&s_scalar);
        let ka = a_point.scalar_mul(&k_scalar);
        let neg_ka = ka.negate();
        let neg_r = r_point.negate();
        let lhs = sb.add(&neg_ka).add(&neg_r);

        if lhs.double().double() == ExtendedPoint::identity() {
            Ok(())
        } else {
            Err(CryptoError::SignatureError(
                "ed448 verification equation failed".into(),
            ))
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed448PublicKey")
            .field(&hex::encode(self.raw))
            .finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw.ct_eq(&other.raw).into()
    }
}
impl Eq for PublicKey {}

impl PublicKeyTrait for PublicKey {
    fn scheme(&self) -> &dyn SchemeTrait {
        &Curve448Scheme
    }

    fn equal(&self, other: &dyn PublicKeyTrait) -> bool {
        other
            .marshal_binary()
            .map(|b| b.len() == PUBLIC_KEY_SIZE && b.as_slice().ct_eq(&self.raw).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.raw.to_vec())
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = CryptoError;
    fn try_from(b: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&b)
    }
}
impl TryFrom<&[u8]> for PublicKey {
    type Error = CryptoError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(b)
    }
}

// ---------------------------------------------------------------------------
// PrivateKey
// ---------------------------------------------------------------------------

pub struct PrivateKey {
    inner: Ed448Priv,
    public: PublicKey,
}

impl PrivateKey {
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn as_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        let b = self.inner.as_bytes();
        let mut arr = [0u8; PRIVATE_KEY_SIZE];
        arr.copy_from_slice(b);
        arr
    }

    pub fn sign_msg(
        &self,
        msg: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mode = SigningMode::from_opts(opts);
        let ctx_opt = mode.context_opt(opts);

        let sig = match mode {
            SigningMode::Ed448 => self.inner.sign(msg, ctx_opt),
            SigningMode::Ed448Ph => self.inner.sign_ph(msg, ctx_opt),
        }
        .map_err(|e| CryptoError::SignatureError(format!("ed448 sign: {e:?}")))?;

        Ok(sig.to_vec())
    }

    pub fn from_seed(seed: &[u8]) -> (PublicKey, Self) {
        assert!(
            seed.len() == SEED_SIZE,
            "ed448: seed must be {SEED_SIZE} bytes, got {}",
            seed.len()
        );
        let mut arr = [0u8; SEED_SIZE];
        arr.copy_from_slice(seed);

        let inner = Ed448Priv::from(arr);
        // ed448-rust's in-memory derivation is correct — safe to use here.
        let rust_pub = Ed448RustPub::from(&inner);
        let public = PublicKey::from_trusted_inner(rust_pub);
        arr.zeroize();

        (public.clone(), Self { inner, public })
    }

    pub fn from_bytes(data: &[u8]) -> Result<(PublicKey, Self), CryptoError> {
        if data.len() != PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: PRIVATE_KEY_SIZE,
                actual: data.len(),
            });
        }
        Ok(Self::from_seed(data))
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let mut arr = [0u8; SEED_SIZE];
        arr.copy_from_slice(self.inner.as_bytes());
        let inner = Ed448Priv::from(arr);
        let public = self.public.clone();
        arr.zeroize();
        Self { inner, public }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed448PrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}
impl Eq for PrivateKey {}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        let zero_arr = [0u8; SEED_SIZE];
        self.inner = Ed448Priv::from(zero_arr);
        self.public.raw.zeroize();
    }
}

impl PrivateKeyTrait for PrivateKey {
    fn scheme(&self) -> &dyn SchemeTrait {
        &Curve448Scheme
    }

    fn equal(&self, other: &dyn PrivateKeyTrait) -> bool {
        other
            .marshal_binary()
            .map(|b| b.len() == PRIVATE_KEY_SIZE && b.as_slice().ct_eq(&self.as_bytes()).into())
            .unwrap_or(false)
    }

    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError> {
        Ok(self.as_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public.raw.to_vec()
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = CryptoError;
    fn try_from(b: Vec<u8>) -> Result<Self, Self::Error> {
        PrivateKey::from_bytes(&b).map(|(_, sk)| sk)
    }
}
impl TryFrom<&[u8]> for PrivateKey {
    type Error = CryptoError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        PrivateKey::from_bytes(b).map(|(_, sk)| sk)
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

pub fn generate_key() -> Result<(PublicKey, PrivateKey), CryptoError> {
    generate_key_with_rng(&mut OsRng)
}

pub fn generate_key_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(PublicKey, PrivateKey), CryptoError> {
    let mut seed = [0u8; SEED_SIZE];
    rng.fill_bytes(&mut seed);
    let pair = PrivateKey::from_seed(&seed);
    seed.zeroize();
    Ok(pair)
}

pub fn new_key_from_seed(seed: &[u8]) -> (PublicKey, PrivateKey) {
    PrivateKey::from_seed(seed)
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

pub struct Curve448Scheme;

pub fn new_curve448_scheme() -> &'static Curve448Scheme {
    &Curve448Scheme
}

impl SchemeTrait for Curve448Scheme {
    fn name(&self) -> &'static str {
        "Ed448"
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
        true
    }

    fn generate_key(
        &self,
    ) -> Result<(Box<dyn PublicKeyTrait>, Box<dyn PrivateKeyTrait>), CryptoError> {
        let (pk, sk) = generate_key()?;
        Ok((Box::new(pk), Box::new(sk)))
    }

    fn derive_key(&self, seed: &[u8]) -> (Box<dyn PublicKeyTrait>, Box<dyn PrivateKeyTrait>) {
        assert!(
            seed.len() == SEED_SIZE,
            "{}; expected {SEED_SIZE}, got {}",
            sign::ERR_SEED_SIZE,
            seed.len(),
        );
        let (pk, sk) = new_key_from_seed(seed);
        (Box::new(pk), Box::new(sk))
    }

    fn sign(
        &self,
        sk: &dyn PrivateKeyTrait,
        message: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> Vec<u8> {
        let sk_bytes = sk.marshal_binary().expect("marshal private key");
        let typed_sk = PrivateKey::try_from(sk_bytes)
            .unwrap_or_else(|_| panic!("{}", sign::ERR_TYPE_MISMATCH));
        typed_sk
            .sign_msg(message, opts)
            .unwrap_or_else(|e| panic!("ed448 sign: {e}"))
    }

    fn verify(
        &self,
        pk: &dyn PublicKeyTrait,
        message: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool {
        let pk_bytes = match pk.marshal_binary() {
            Ok(b) => b,
            Err(_) => return false,
        };
        // Uses from_bytes → goldilocks-validated, then verify_via_goldilocks.
        let typed_pk = match PublicKey::try_from(pk_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };
        typed_pk.verify_sig(message, signature, opts).is_ok()
    }

    fn unmarshal_binary_public_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn PublicKeyTrait>, CryptoError> {
        PublicKey::from_bytes(buf).map(|k| Box::new(k) as Box<dyn PublicKeyTrait>)
    }

    fn unmarshal_binary_private_key(
        &self,
        buf: &[u8],
    ) -> Result<Box<dyn PrivateKeyTrait>, CryptoError> {
        PrivateKey::from_bytes(buf).map(|(_, sk)| Box::new(sk) as Box<dyn PrivateKeyTrait>)
    }
}

impl TypedScheme for Curve448Scheme {
    type Pub = PublicKey;
    type Priv = PrivateKey;

    fn generate_key_typed(&self) -> Result<(PublicKey, PrivateKey), CryptoError> {
        generate_key()
    }
    fn derive_key_typed(&self, seed: &[u8]) -> (PublicKey, PrivateKey) {
        new_key_from_seed(seed)
    }
    fn sign_typed(&self, sk: &PrivateKey, msg: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8> {
        sk.sign_msg(msg, opts)
            .unwrap_or_else(|e| panic!("ed448 sign: {e}"))
    }
    fn verify_typed(
        &self,
        pk: &PublicKey,
        msg: &[u8],
        sig: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool {
        pk.verify_sig(msg, sig, opts).is_ok()
    }
    fn unmarshal_public_key_typed(&self, buf: &[u8]) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(buf)
    }
    fn unmarshal_private_key_typed(&self, buf: &[u8]) -> Result<PrivateKey, CryptoError> {
        PrivateKey::from_bytes(buf).map(|(_, sk)| sk)
    }
}

pub type Ed448PublicKey = PublicKey;
pub type Ed448PrivateKey = PrivateKey;
pub type Ed448Scheme = Curve448Scheme;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{Scheme as S, TypedScheme as TS};

    #[test]
    fn constants_correct() {
        assert_eq!(SEED_SIZE, 57);
        assert_eq!(PUBLIC_KEY_SIZE, 57);
        assert_eq!(PRIVATE_KEY_SIZE, 57);
        assert_eq!(SIGNATURE_SIZE, 114);
    }

    #[test]
    fn sign_verify_in_memory() {
        let (pk, sk) = generate_key().unwrap();
        let sig = sk.sign_msg(b"hello", None).unwrap();
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        assert!(pk.verify_sig(b"hello", &sig, None).is_ok());
    }

    /// Known-Answer Test against RFC 8032 §7.4 (Ed448, the "-----Blank" vector:
    /// empty message, no context). This is an *authoritative* conformance check,
    /// not a self-consistency check. It exercises three independent guarantees:
    ///   1. public-key derivation from the 57-byte secret matches the RFC,
    ///   2. our deterministic signing reproduces the RFC signature byte-for-byte,
    ///   3. the hand-rolled goldilocks verification path (`from_bytes` →
    ///      `verify_via_goldilocks`) accepts the RFC signature.
    #[test]
    fn rfc8032_ed448_blank_kat() {
        // RFC 8032, Section 7.4, first Ed448 test vector.
        const SECRET: &str = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
        const PUBLIC: &str = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
        const SIGNATURE: &str = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";

        let sk = hex::decode(SECRET).unwrap();
        let pk_expected = hex::decode(PUBLIC).unwrap();
        let sig_expected = hex::decode(SIGNATURE).unwrap();
        let msg: &[u8] = b""; // empty message

        // (1) Public-key derivation matches RFC 8032.
        let (_, priv_key) = PrivateKey::from_bytes(&sk).expect("valid 57-byte secret");
        assert_eq!(
            priv_key.public_key().as_bytes().to_vec(),
            pk_expected,
            "Ed448 public-key derivation must match RFC 8032"
        );

        // (2) Deterministic signing reproduces the RFC signature exactly.
        let sig = priv_key.sign_msg(msg, None).unwrap();
        assert_eq!(sig, sig_expected, "Ed448 signature must match RFC 8032 byte-for-byte");

        // (3) The goldilocks verification path accepts the authoritative signature.
        let pk_deser = PublicKey::from_bytes(&pk_expected).expect("valid public key");
        assert!(pk_deser.trusted_inner.is_none(), "deserialized key must use goldilocks path");
        pk_deser
            .verify_sig(msg, &sig_expected, None)
            .expect("goldilocks verification must accept the RFC 8032 signature");
    }

    /// Small-order public keys (the identity being the sharpest case) must be
    /// rejected outright: otherwise `(A=O, R=O, S=0)` is a universal forgery
    /// that verifies for ANY message. This pins the fix at the deserialisation
    /// gate (`from_bytes`) and, defensively, at the verifier.
    #[test]
    fn rejects_small_order_identity_public_key() {
        // Identity point encoding: y = 1 (little-endian), x-sign bit clear.
        let mut identity = [0u8; PUBLIC_KEY_SIZE];
        identity[0] = 0x01;

        // The public key must not even deserialise.
        assert!(
            PublicKey::from_bytes(&identity).is_err(),
            "identity / small-order Ed448 public key must be rejected by from_bytes"
        );

        // And the full PoC signature must not verify via any constructed key.
        // (Build a struct directly to prove the verifier itself also rejects it,
        // independent of the from_bytes gate.)
        let pk = PublicKey {
            raw: identity,
            trusted_inner: None,
        };
        let mut forged_sig = [0u8; SIGNATURE_SIZE];
        forged_sig[0] = 0x01; // R = identity encoding; S = all-zero scalar.
        assert!(
            pk.verify_sig(b"any message at all", &forged_sig, None).is_err(),
            "small-order universal forgery must be rejected by the verifier"
        );
        assert!(
            pk.verify_sig(b"a different message", &forged_sig, None).is_err(),
            "small-order forgery must fail for every message"
        );
    }

    // THE critical regression test.
    // Signs with the original key, serialises the public key to bytes,
    // deserialises it (triggering the goldilocks path), then verifies.
    // This is what previously failed with both ed448-rust and the hybrid approach.
    #[test]
    fn pubkey_serialise_then_verify_deserialized() {
        let (pk, sk) = generate_key().unwrap();
        let msg = "network roundtrip — this MUST work".as_bytes();
        let sig = sk.sign_msg(msg, None).unwrap();

        let pk_bytes = pk.marshal_binary().unwrap();
        let pk_deser = PublicKey::from_bytes(&pk_bytes).unwrap();

        pk_deser
            .verify_sig(msg, &sig, None)
            .expect("deserialized public key MUST verify signature");
    }

    #[test]
    fn privkey_serialise_then_sign() {
        let (pk, sk) = generate_key().unwrap();
        let sk_recv = PrivateKey::try_from(sk.as_bytes().to_vec()).unwrap();
        let sig = sk_recv.sign_msg(b"roundtrip", None).unwrap();
        // Verify with deserialized public key to test the full round-trip.
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"roundtrip", &sig, None).is_ok());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let (pk, sk) = generate_key().unwrap();
        let sig = sk.sign_msg(b"hello", None).unwrap();
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"world", &sig, None).is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (_, sk) = generate_key().unwrap();
        let (pk2, _) = generate_key().unwrap();
        let sig = sk.sign_msg(b"hello", None).unwrap();
        let pk2_deser = PublicKey::from_bytes(&pk2.as_bytes()).unwrap();
        assert!(pk2_deser.verify_sig(b"hello", &sig, None).is_err());
    }

    #[test]
    fn sign_verify_with_context() {
        let (pk, sk) = generate_key().unwrap();
        let opts = SignatureOpts { context: "".into() };
        let sig = sk.sign_msg(b"ctx", Some(&opts)).unwrap();
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"ctx", &sig, Some(&opts)).is_ok());
    }

    #[test]
    fn verify_wrong_context_fails() {
        let (pk, sk) = generate_key().unwrap();
        let o1 = SignatureOpts {
            context: "a".into(),
        };
        let o2 = SignatureOpts {
            context: "b".into(),
        };
        let sig = sk.sign_msg(b"msg", Some(&o1)).unwrap();
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"msg", &sig, Some(&o2)).is_err());
    }

    #[test]
    fn sign_verify_prehash() {
        let (pk, sk) = generate_key().unwrap();
        let opts = SignatureOpts {
            context: "PREHASHED".into(),
        };
        let sig = sk.sign_msg(b"ph", Some(&opts)).unwrap();
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"ph", &sig, Some(&opts)).is_ok());
    }

    #[test]
    fn prehash_sig_fails_standard_verify() {
        let (pk, sk) = generate_key().unwrap();
        let opts = SignatureOpts {
            context: "PREHASHED".into(),
        };
        let sig = sk.sign_msg(b"ph", Some(&opts)).unwrap();
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"ph", &sig, None).is_err());
    }

    #[test]
    fn derive_key_deterministic() {
        let seed = [0x42u8; SEED_SIZE];
        let (pk1, _) = new_key_from_seed(&seed);
        let (pk2, _) = new_key_from_seed(&seed);
        assert_eq!(pk1, pk2);
    }

    #[test]
    #[should_panic]
    fn derive_key_bad_seed_panics() {
        new_key_from_seed(&[0u8; SEED_SIZE - 1]);
    }

    #[test]
    fn public_key_marshal_roundtrip() {
        let (pk, _) = generate_key().unwrap();
        let bytes = pk.marshal_binary().unwrap();
        let pk2 = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn pubkey_rejects_noncanonical_y_ge_prime() {
        // y = p (encodes the same low-order point as y = 0) must be rejected as
        // a non-canonical encoding, even though it lands on the curve mod p.
        let mut raw = [0u8; PUBLIC_KEY_SIZE];
        raw[..56].copy_from_slice(&FIELD_PRIME_LE); // y = p
        let err = PublicKey::from_bytes(&raw).unwrap_err();
        assert!(matches!(err, CryptoError::CurveError(_)), "got {err:?}");

        // y = p + 1 as well.
        let mut yp1 = raw;
        let mut carry = 1u16;
        for b in yp1.iter_mut().take(56) {
            let s = *b as u16 + carry;
            *b = (s & 0xff) as u8;
            carry = s >> 8;
        }
        assert!(PublicKey::from_bytes(&yp1).is_err());
    }

    #[test]
    fn pubkey_rejects_noncanonical_signbyte_padding() {
        // A valid canonical key with garbage in the low 7 bits of the sign byte
        // decodes to the same point in goldilocks, so it must be rejected here.
        let (pk, _) = generate_key().unwrap();
        let mut raw = pk.as_bytes();
        raw[56] |= 0x3f; // set unused padding bits
        let err = PublicKey::from_bytes(&raw).unwrap_err();
        assert!(matches!(err, CryptoError::CurveError(_)), "got {err:?}");
    }

    #[test]
    fn verify_rejects_noncanonical_r_signbyte_padding() {
        // Mangling R's sign-byte padding must be rejected at decode time.
        let (pk, sk) = generate_key().unwrap();
        let sig = sk.sign_msg(b"canon-R", None).unwrap();
        let mut bad = sig.clone();
        bad[56] |= 0x3f; // R is sig[0..57]; byte 56 is R's final byte
        let pk_deser = PublicKey::from_bytes(&pk.as_bytes()).unwrap();
        assert!(pk_deser.verify_sig(b"canon-R", &bad, None).is_err());
    }

    #[test]
    fn pubkey_rejects_bad_size() {
        assert!(PublicKey::from_bytes(&[0u8; PUBLIC_KEY_SIZE - 1]).is_err());
    }

    #[test]
    fn privkey_rejects_bad_size() {
        assert!(PrivateKey::from_bytes(&[0u8; PRIVATE_KEY_SIZE + 1]).is_err());
    }

    #[test]
    fn verify_rejects_short_sig() {
        let (pk, _) = generate_key().unwrap();
        assert!(
            pk.verify_sig(b"msg", &[0u8; SIGNATURE_SIZE - 1], None)
                .is_err()
        );
    }

    #[test]
    fn key_equality() {
        let (pk1, sk1) = generate_key().unwrap();
        let (pk2, sk2) = generate_key().unwrap();
        assert_eq!(pk1, pk1.clone());
        assert_ne!(pk1, pk2);
        assert_eq!(sk1, sk1.clone());
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn scheme_metadata() {
        let s = new_curve448_scheme();
        assert_eq!(s.name(), "Ed448");
        assert_eq!(s.public_key_size(), PUBLIC_KEY_SIZE);
        assert_eq!(s.private_key_size(), PRIVATE_KEY_SIZE);
        assert_eq!(s.signature_size(), SIGNATURE_SIZE);
        assert_eq!(s.seed_size(), SEED_SIZE);
        assert!(s.supports_context());
    }

    #[test]
    fn scheme_dyn_sign_verify() {
        let s = new_curve448_scheme();
        let (pk, sk) = s.generate_key().unwrap();
        let sig = s.sign(sk.as_ref(), b"dyn test", None);
        assert!(s.verify(pk.as_ref(), b"dyn test", &sig, None));
    }

    #[test]
    fn typed_scheme_sign_verify() { 
        let s = Curve448Scheme;
        let (pk, sk) = s.generate_key_typed().unwrap();
        let sig = s.sign_typed(&sk, b"typed test", None);
        assert!(s.verify_typed(&pk, b"typed test", &sig, None));
    }
}
