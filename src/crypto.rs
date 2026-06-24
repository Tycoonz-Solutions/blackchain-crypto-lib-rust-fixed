// crypto.rs — Composite BlackChain key types.
//
// Implements the three-algorithm hybrid key used by the BlackChain protocol:
//   - Dilithium5  (post-quantum lattice signature)
//   - P-521 ECDSA (classical elliptic-curve signature)
//   - Ed448       (classical twisted-Edwards signature)
//
// Key derivation matches the Go reference library (`blackchain_crypto/crypto.go`):
//   seed[0..32]  → Dilithium5 seed (256 bits)
//   seed[32..48] → mdECC master seed → per-curve via SHAKE256 + HKDF-SHA3-512
//   seed[48..64] → chain code / reserved
//
// Per-curve mdECC seeds use domain-separation curve IDs (1 = P-521, 2 = Ed448)
// so the three key pairs are cryptographically independent.

use std::fmt;

use alloy_primitives::Address;
use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::dilithium::{
    new_key_from_seed as dil_key_from_seed, SEED_SIZE as DIL_SEED,
    PUBLIC_KEY_SIZE as DIL_PK_SIZE, PRIVATE_KEY_SIZE as DIL_SK_SIZE,
};
use crate::error::CryptoError;
use crate::hdwallet::derivation::{derive_mdecc_curve_seed, CURVE_ID_ED448, CURVE_ID_P521};
use crate::mdecc::ed448::{
    new_key_from_seed as ed448_key_from_seed,
    SEED_SIZE as ED448_SEED, PUBLIC_KEY_SIZE as ED448_PK_SIZE,
};
use crate::mdecc::p521::{
    P521Scheme, PUBLIC_KEY_SIZE as P521_PK_SIZE,
    SEED_SIZE as P521_SEED,
};
use crate::sign::TypedScheme;

// ---------------------------------------------------------------------------
// Protocol constants (must match Go's blackchain_crypto/crypto.go)
// ---------------------------------------------------------------------------

/// Algorithm ID for the entanglement nonce (Version 1 hybrid scheme).
pub const ALGO_ID: u8 = 1;
/// Protocol version for the entanglement nonce.
pub const VERSION: u8 = 1;

/// Total bytes required for the composite public key in serialized form:
///   Dilithium5 pk (2592) ‖ P-521 pk (133) ‖ Ed448 pk (57)
pub const COMPOSITE_PK_SIZE: usize = DIL_PK_SIZE + P521_PK_SIZE + ED448_PK_SIZE;

// ---------------------------------------------------------------------------
// BlackChainPublicKey
// ---------------------------------------------------------------------------

/// The composite BlackChain public key (Dilithium5 + P-521 + Ed448).
///
/// Serialized as `[Dilithium5 pk (2592 B)] ‖ [P-521 pk (133 B)] ‖ [Ed448 pk (57 B)]`.
#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub struct BlackChainPublicKey {
    dilithium: Vec<u8>,
    p521: Vec<u8>,
    ed448: Vec<u8>,
}

impl BlackChainPublicKey {
    /// Returns the raw Dilithium5 public key bytes.
    pub fn dilithium_bytes(&self) -> &[u8] {
        &self.dilithium
    }

    /// Returns the raw P-521 public key bytes.
    pub fn p521_bytes(&self) -> &[u8] {
        &self.p521
    }

    /// Returns the raw Ed448 public key bytes.
    pub fn ed448_bytes(&self) -> &[u8] {
        &self.ed448
    }

    /// Serialises to `[Dilithium5 pk] ‖ [P-521 pk] ‖ [Ed448 pk]`.
    ///
    /// This byte format is also stored in the `pub_key` field of a signed
    /// `BlackChainTxType` and is required for `recover_sender`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMPOSITE_PK_SIZE);
        out.extend_from_slice(&self.dilithium);
        out.extend_from_slice(&self.p521);
        out.extend_from_slice(&self.ed448);
        out
    }

    /// Deserialises from the canonical concatenated byte format.
    ///
    /// Returns `Err` if `bytes.len() != COMPOSITE_PK_SIZE`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != COMPOSITE_PK_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: COMPOSITE_PK_SIZE,
                actual: bytes.len(),
            });
        }
        let dil_bytes = &bytes[..DIL_PK_SIZE];
        let p521_bytes = &bytes[DIL_PK_SIZE..DIL_PK_SIZE + P521_PK_SIZE];
        let ed448_bytes = &bytes[DIL_PK_SIZE + P521_PK_SIZE..];

        // Validate individual sub-keys
        crate::dilithium::PublicKey::from_bytes(dil_bytes)?;
        crate::mdecc::p521::P521PublicKey::from_bytes(p521_bytes)?;
        crate::mdecc::ed448::PublicKey::from_bytes(ed448_bytes)?;

        Ok(Self {
            dilithium: dil_bytes.to_vec(),
            p521: p521_bytes.to_vec(),
            ed448: ed448_bytes.to_vec(),
        })
    }

    /// Derives the 20-byte BlackChain address by Keccak256-hashing all
    /// public key bytes: Keccak256(dil_pk ‖ p521_pk ‖ ed448_pk)[12..32].
    ///
    /// Matches Go's `DeriveAddress` and `Wallet.DeriveAddress`.
    pub fn derive_address(&self) -> Address {
        let mut hasher = Keccak256::new();
        hasher.update(&self.dilithium);
        hasher.update(&self.p521);
        hasher.update(&self.ed448);
        let hash = hasher.finalize();
        Address::from_slice(&hash[12..32])
    }
}

impl fmt::Debug for BlackChainPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlackChainPublicKey")
            .field("dilithium", &hex::encode(&self.dilithium[..8]))
            .field("p521", &hex::encode(&self.p521[..8]))
            .field("ed448", &hex::encode(&self.ed448[..8]))
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// BlackChainPrivateKey
// ---------------------------------------------------------------------------

/// The composite BlackChain private key (Dilithium5 + P-521 + Ed448).
///
/// All fields are private and zeroed on drop.  Use accessor methods for
/// read-only access to raw key bytes.
///
/// The original 64-byte BIP-39 root seed is retained so that child accounts
/// can be derived via BIP32 without re-entering the mnemonic.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlackChainPrivateKey {
    dilithium: Vec<u8>,
    p521: Vec<u8>,
    ed448: Vec<u8>,
    /// The 64-byte root seed used to derive all key material.
    /// Retained for BIP32 child-account derivation.
    seed: Vec<u8>,
    public: BlackChainPublicKey,
}

impl BlackChainPrivateKey {
    /// Returns the raw Dilithium5 secret key bytes (4000 bytes).
    pub fn dilithium_bytes(&self) -> &[u8] {
        &self.dilithium
    }

    /// Returns the raw P-521 private key bytes (66 bytes).
    pub fn p521_bytes(&self) -> &[u8] {
        &self.p521
    }

    /// Returns the raw Ed448 private key bytes (57 bytes).
    pub fn ed448_bytes(&self) -> &[u8] {
        &self.ed448
    }

    /// Returns the original 64-byte root seed.
    ///
    /// The seed is needed for BIP32 child-account derivation and for
    /// reconstructing public keys during transaction signing (H_combined).
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Returns the cached public key.
    pub fn public_key(&self) -> &BlackChainPublicKey {
        &self.public
    }

    /// Derives keys deterministically from a 64-byte BIP-39 root seed.
    ///
    /// Seed layout (matches Go):
    /// ```text
    /// seed[0..32]  → Dilithium5 seed
    /// seed[32..48] → mdECC master → per-curve via SHAKE256 + HKDF-SHA3-512
    /// seed[48..64] → chain code (reserved)
    /// ```
    ///
    /// # Errors
    /// Returns `Err` if the seed is shorter than 64 bytes, or if HKDF
    /// expansion fails (extremely unlikely in practice).
    pub fn generate(seed: &[u8]) -> Result<(Self, BlackChainPublicKey), CryptoError> {
        if seed.len() < 64 {
            return Err(CryptoError::SeedError(
                "seed must be at least 64 bytes for BlackChain key derivation".into(),
            ));
        }

        // ── Dilithium5 ────────────────────────────────────────────────────────
        // Deterministic from the first 32 bytes of the seed.
        let mut dil_seed = Zeroizing::new([0u8; DIL_SEED]);
        dil_seed.copy_from_slice(&seed[..DIL_SEED]);
        let (dil_pk, dil_sk) = dil_key_from_seed(&dil_seed);

        // ── mdECC master seed ─────────────────────────────────────────────────
        // Bytes 32..48 are the 16-byte mdECC master; each curve gets an
        // independent seed via SHAKE256 domain-separation + HKDF-SHA3-512.
        let mdecc_seed = &seed[32..48];

        // ── P-521 ─────────────────────────────────────────────────────────────
        let p521_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_P521, P521_SEED)?);
        let (p521_pk, p521_sk) = P521Scheme.derive_key_typed(&*p521_seed);

        // ── Ed448 ─────────────────────────────────────────────────────────────
        let ed448_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_ED448, ED448_SEED)?);
        let (ed448_pk, ed448_sk) = ed448_key_from_seed(&*ed448_seed);

        // Dilithium5 SK: pack() into a fixed array
        let mut dil_sk_buf = Zeroizing::new([0u8; DIL_SK_SIZE]);
        dil_sk.pack(&mut *dil_sk_buf);

        // Dilithium5 PK: pack() into a fixed array
        let mut dil_pk_buf = [0u8; DIL_PK_SIZE];
        dil_pk.pack(&mut dil_pk_buf);

        let pub_key = BlackChainPublicKey {
            dilithium: dil_pk_buf.to_vec(),
            p521: p521_pk.as_bytes(),
            ed448: ed448_pk.as_bytes().to_vec(),
        };

        let priv_key = BlackChainPrivateKey {
            dilithium: dil_sk_buf.to_vec(),
            p521: p521_sk.as_bytes(),
            ed448: ed448_sk.as_bytes().to_vec(),
            seed: seed.to_vec(),
            public: pub_key.clone(),
        };

        Ok((priv_key, pub_key))
    }

    /// Re-derives only the public keys from the stored seed.
    ///
    /// Used during transaction signing to compute the H_combined entanglement
    /// hash and to embed the composite public key in the transaction body.
    pub fn derive_public_key(&self) -> Result<BlackChainPublicKey, CryptoError> {
        let seed = &self.seed;

        let mut dil_seed = Zeroizing::new([0u8; DIL_SEED]);
        dil_seed.copy_from_slice(&seed[..DIL_SEED]);
        let (dil_pk, _) = dil_key_from_seed(&dil_seed);

        let mdecc_seed = &seed[32..48];
        let p521_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_P521, P521_SEED)?);
        let (p521_pk, _) = P521Scheme.derive_key_typed(&*p521_seed);

        let ed448_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_ED448, ED448_SEED)?);
        let (ed448_pk, _) = ed448_key_from_seed(&*ed448_seed);

        let mut dil_pk_buf = [0u8; DIL_PK_SIZE];
        dil_pk.pack(&mut dil_pk_buf);

        Ok(BlackChainPublicKey {
            dilithium: dil_pk_buf.to_vec(),
            p521: p521_pk.as_bytes(),
            ed448: ed448_pk.as_bytes().to_vec(),
        })
    }
}

impl fmt::Debug for BlackChainPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print any secret material.
        f.debug_struct("BlackChainPrivateKey")
            .finish_non_exhaustive()
    }
}


