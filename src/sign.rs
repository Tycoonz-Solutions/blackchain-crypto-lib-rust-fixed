// sign — Rust equivalent of the Go `sign` package.
//
// Mirrors the interface structure exactly:
//   - `SignatureOpts`  ↔  Go `SignatureOpts`
//   - `PublicKey`      ↔  Go `PublicKey` interface
//   - `PrivateKey`     ↔  Go `PrivateKey` interface
//   - `Scheme`         ↔  Go `Scheme` interface
//   - sentinel errors  ↔  Go `ErrTypeMismatch`, `ErrSeedSize`, etc.

use std::fmt;

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// SignatureOpts  (mirrors Go `SignatureOpts`)
// ---------------------------------------------------------------------------

/// Options forwarded to signing and verification.
///
/// Equivalent to Go's `sign.SignatureOpts`.
#[derive(Debug, Clone, Default)]
pub struct SignatureOpts {
    /// If non-empty, includes the given context in the signature if the scheme
    /// supports it, and causes an error / panic otherwise — matching Go's
    /// documented behaviour.
    pub context: String,
}

// ---------------------------------------------------------------------------
// Sentinel errors  (mirrors Go's package-level `var Err*` values)
// ---------------------------------------------------------------------------

/// Types of private and public keys don't match.
///
/// Equivalent to Go's `sign.ErrTypeMismatch`.
pub const ERR_TYPE_MISMATCH: &str = "types mismatch";

/// The provided seed is of the wrong size.
///
/// Equivalent to Go's `sign.ErrSeedSize`.
pub const ERR_SEED_SIZE: &str = "wrong seed size";

/// The provided public key is of the wrong size.
///
/// Equivalent to Go's `sign.ErrPubKeySize`.
pub const ERR_PUB_KEY_SIZE: &str = "wrong size for public key";

/// The provided private key is of the wrong size.
///
/// Equivalent to Go's `sign.ErrPrivKeySize`.
pub const ERR_PRIV_KEY_SIZE: &str = "wrong size for private key";

/// A context string was provided but is not supported by the scheme.
///
/// Equivalent to Go's `sign.ErrContextNotSupported`.
pub const ERR_CONTEXT_NOT_SUPPORTED: &str = "context not supported";

/// The context string exceeds the maximum allowed length.
///
/// Equivalent to Go's `sign.ErrContextTooLong`.
pub const ERR_CONTEXT_TOO_LONG: &str = "context string too long";

// ---------------------------------------------------------------------------
// Helper — build a `CryptoError` from a sentinel string.
// Used internally so call-sites stay readable.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn err_type_mismatch() -> CryptoError {
    CryptoError::Custom(ERR_TYPE_MISMATCH.into())
}
#[allow(dead_code)]
pub(crate) fn err_seed_size() -> CryptoError {
    CryptoError::SeedError(ERR_SEED_SIZE.into())
}
#[allow(dead_code)]
pub(crate) fn err_pub_key_size(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidKeySize {
        expected,
        actual,
    }
}
#[allow(dead_code)]
pub(crate) fn err_priv_key_size(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidKeySize {
        expected,
        actual,
    }
}
#[allow(dead_code)]
pub(crate) fn err_context_not_supported() -> CryptoError {
    CryptoError::Custom(ERR_CONTEXT_NOT_SUPPORTED.into())
}
#[allow(dead_code)]
pub(crate) fn err_context_too_long() -> CryptoError {
    CryptoError::Custom(ERR_CONTEXT_TOO_LONG.into())
}

// ---------------------------------------------------------------------------
// PublicKey trait  (mirrors Go `PublicKey` interface)
//
// Go interface:
//   Scheme() Scheme
//   Equal(crypto.PublicKey) bool
//   encoding.BinaryMarshaler   → MarshalBinary() ([]byte, error)
//   crypto.PublicKey           → marker
// ---------------------------------------------------------------------------

/// A public key used to verify signatures produced by the corresponding
/// [`PrivateKey`].
///
/// Implementors must also derive / implement [`Clone`], [`fmt::Debug`],
/// and [`PartialEq`].
pub trait PublicKey: Send + Sync + fmt::Debug {
    /// Returns the [`Scheme`] that created this key.
    ///
    /// Equivalent to Go's `PublicKey.Scheme()`.
    fn scheme(&self) -> &dyn Scheme;

    /// Returns `true` if `other` represents the same public key.
    ///
    /// Equivalent to Go's `PublicKey.Equal(crypto.PublicKey)`.
    fn equal(&self, other: &dyn PublicKey) -> bool;

    /// Serialises the public key to bytes.
    ///
    /// Equivalent to Go's `encoding.BinaryMarshaler.MarshalBinary()`.
    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError>;
}

// ---------------------------------------------------------------------------
// PrivateKey trait  (mirrors Go `PrivateKey` interface)
//
// Go interface:
//   Scheme() Scheme
//   Equal(crypto.PrivateKey) bool
//   crypto.Signer             → Sign(rand, digest, opts) ([]byte, error)
//                                Public() crypto.PublicKey
//   crypto.PrivateKey         → marker
//   encoding.BinaryMarshaler  → MarshalBinary() ([]byte, error)
// ---------------------------------------------------------------------------

/// A private key used to create signatures.
///
/// Rust cannot directly mirror Go's `crypto.Signer` (which uses an `io.Reader`
/// for randomness), so signing is split into:
///  - `sign_message` — the main signing path, taking [`SignatureOpts`].
///  - `public_key_bytes` — returns the raw bytes of the corresponding public key
///    without requiring a concrete associated type, enabling `dyn PrivateKey`.
pub trait PrivateKey: Send + Sync + fmt::Debug {
    /// Returns the [`Scheme`] that created this key.
    ///
    /// Equivalent to Go's `PrivateKey.Scheme()`.
    fn scheme(&self) -> &dyn Scheme;

    /// Returns `true` if `other` represents the same private key.
    ///
    /// Equivalent to Go's `PrivateKey.Equal(crypto.PrivateKey)`.
    /// Implementations MUST use constant-time comparison.
    fn equal(&self, other: &dyn PrivateKey) -> bool;

    /// Serialises the private key to bytes.
    ///
    /// Equivalent to Go's `encoding.BinaryMarshaler.MarshalBinary()`.
    fn marshal_binary(&self) -> Result<Vec<u8>, CryptoError>;

    /// Returns the corresponding public key as raw bytes.
    ///
    /// Equivalent to Go's `crypto.Signer.Public()`, without the concrete-type
    /// constraint so this trait remains object-safe.
    fn public_key_bytes(&self) -> Vec<u8>;
}

// ---------------------------------------------------------------------------
// Scheme trait  (mirrors Go `Scheme` interface exactly, method-for-method)
//
// Go methods:
//   Name() string
//   GenerateKey() (PublicKey, PrivateKey, error)
//   Sign(sk, message, opts) []byte          — panics on bad key / context
//   Verify(pk, message, signature, opts) bool — panics on bad key / context
//   DeriveKey(seed) (PublicKey, PrivateKey)  — panics on wrong seed size
//   UnmarshalBinaryPublicKey([]byte) (PublicKey, error)
//   UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)
//   PublicKeySize() int
//   PrivateKeySize() int
//   SignatureSize() int
//   SeedSize() int
//   SupportsContext() bool
//
// Rust notes:
//   - `Sign`   returns `Vec<u8>`; panics on bad key/context (matching Go).
//   - `Verify` returns `bool`;    panics on bad key/context (matching Go).
//   - `DeriveKey` panics on wrong seed size (matching Go).
//   - The trait is object-safe: `GenerateKey`, `UnmarshalBinary*` return
//     `Box<dyn PublicKey>` / `Box<dyn PrivateKey>` instead of concrete types.
// ---------------------------------------------------------------------------

/// A specific instance of a signature scheme.
///
/// Mirrors Go's `sign.Scheme` interface method-for-method.
pub trait Scheme: Send + Sync {
    /// Name of the scheme, e.g. `"Ed448"` or `"Dilithium5"`.
    ///
    /// Equivalent to Go's `Scheme.Name()`.
    fn name(&self) -> &'static str;

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generates a fresh key pair using the system CSPRNG.
    ///
    /// Equivalent to Go's `Scheme.GenerateKey()`.
    fn generate_key(&self) -> Result<(Box<dyn PublicKey>, Box<dyn PrivateKey>), CryptoError>;

    /// Deterministically derives a key pair from `seed`.
    ///
    /// # Panics
    /// Panics if `seed.len() != self.seed_size()` — matching Go's
    /// `panic(sign.ErrSeedSize)`.
    ///
    /// Equivalent to Go's `Scheme.DeriveKey(seed)`.
    fn derive_key(&self, seed: &[u8]) -> (Box<dyn PublicKey>, Box<dyn PrivateKey>);

    // -----------------------------------------------------------------------
    // Sign / Verify  — panic on bad key type or unsupported context,
    //                  exactly as documented in Go.
    // -----------------------------------------------------------------------

    /// Signs `message` with `sk` and returns the detached signature.
    ///
    /// # Panics
    /// - If `sk` is the wrong key type (`ErrTypeMismatch`).
    /// - If `opts.context` is non-empty and the scheme does not support
    ///   contexts (`ErrContextNotSupported`).
    ///
    /// Equivalent to Go's `Scheme.Sign(sk, message, opts) []byte`.
    fn sign(&self, sk: &dyn PrivateKey, message: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8>;

    /// Returns `true` iff `signature` is a valid signature of `message` under
    /// the private key corresponding to `pk`.
    ///
    /// # Panics
    /// - If `pk` is the wrong key type (`ErrTypeMismatch`).
    /// - If `opts.context` is non-empty and the scheme does not support
    ///   contexts (`ErrContextNotSupported`).
    ///
    /// Equivalent to Go's `Scheme.Verify(pk, message, signature, opts) bool`.
    fn verify(
        &self,
        pk: &dyn PublicKey,
        message: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool;

    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------

    /// Deserialises a public key from `buf`.
    ///
    /// Returns `Err` if the buffer length or content is invalid.
    ///
    /// Equivalent to Go's `Scheme.UnmarshalBinaryPublicKey([]byte)`.
    fn unmarshal_binary_public_key(&self, buf: &[u8]) -> Result<Box<dyn PublicKey>, CryptoError>;

    /// Deserialises a private key from `buf`.
    ///
    /// Returns `Err` if the buffer length or content is invalid.
    ///
    /// Equivalent to Go's `Scheme.UnmarshalBinaryPrivateKey([]byte)`.
    fn unmarshal_binary_private_key(&self, buf: &[u8]) -> Result<Box<dyn PrivateKey>, CryptoError>;

    // -----------------------------------------------------------------------
    // Size accessors  (all mirror Go's `PublicKeySize`, `PrivateKeySize`, etc.)
    // -----------------------------------------------------------------------

    /// Size in bytes of a marshalled public key.
    fn public_key_size(&self) -> usize;

    /// Size in bytes of a marshalled private key.
    fn private_key_size(&self) -> usize;

    /// Size in bytes of a signature.
    fn signature_size(&self) -> usize;

    /// Size in bytes of a key-generation seed.
    fn seed_size(&self) -> usize;

    /// Whether this scheme supports context strings in [`SignatureOpts`].
    ///
    /// Equivalent to Go's `Scheme.SupportsContext()`.
    fn supports_context(&self) -> bool;

    /// Whether this scheme supports private key deserialisation from bytes.
    fn supports_priv_key_unmarshal(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Concrete-typed extension trait
//
// Schemes that expose concrete key types (not erased to `Box<dyn …>`) can
// implement this generic trait in addition to `Scheme`.  The `ed448.rs` and
// `dilithium5.rs` modules use this for their typed APIs; the `Scheme` trait
// above is used wherever dynamic dispatch is required.
// ---------------------------------------------------------------------------

/// Generic, statically-typed counterpart to [`Scheme`].
///
/// Implement this alongside `Scheme` when concrete key types are preferred
/// over `Box<dyn PublicKey>` / `Box<dyn PrivateKey>`.
pub trait TypedScheme {
    /// The concrete public key type.
    type Pub: PublicKey + Clone + PartialEq;
    /// The concrete private key type.
    type Priv: PrivateKey + Clone + PartialEq;

    /// Typed key generation.
    fn generate_key_typed(&self) -> Result<(Self::Pub, Self::Priv), CryptoError>;

    /// Typed deterministic key derivation.
    ///
    /// # Panics
    /// Panics if `seed.len()` is wrong — matches Go.
    fn derive_key_typed(&self, seed: &[u8]) -> (Self::Pub, Self::Priv);

    /// Typed signing — returns `Vec<u8>` signature.
    fn sign_typed(&self, sk: &Self::Priv, message: &[u8], opts: Option<&SignatureOpts>) -> Vec<u8>;

    /// Typed verification.
    fn verify_typed(
        &self,
        pk: &Self::Pub,
        message: &[u8],
        signature: &[u8],
        opts: Option<&SignatureOpts>,
    ) -> bool;

    /// Typed public key deserialisation.
    fn unmarshal_public_key_typed(&self, buf: &[u8]) -> Result<Self::Pub, CryptoError>;

    /// Typed private key deserialisation.
    fn unmarshal_private_key_typed(&self, buf: &[u8]) -> Result<Self::Priv, CryptoError>;
}
