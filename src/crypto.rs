// crypto.rs — Composite BlackChain key types.
//
// Implements the three-algorithm hybrid key used by the BlackChain protocol:
//   - ML-DSA-87  (post-quantum lattice signature)
//   - P-521 ECDSA (classical elliptic-curve signature)
//   - Ed448       (classical twisted-Edwards signature)
//
// Key derivation from the 64-byte BIP-39 root seed:
//   seed[0..32]  → ML-DSA-87 seed (256 bits)
//   seed[32..64] → mdECC master seed (256 bits) → per-curve via SHAKE256 + HKDF-SHA3-512
//
// Per-curve mdECC seeds use domain-separation curve IDs (1 = P-521, 2 = Ed448)
// so the three key pairs are cryptographically independent. The full 32-byte
// mdECC master gives the classical sub-keys the same 256-bit seed entropy as
// the ML-DSA-87 seed (no region of the root seed is left reserved/unused).

use std::fmt;

use alloy_primitives::Address;
use sha3::{Digest, Keccak256, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::dilithium::{
    new_key_from_seed as dil_key_from_seed, SEED_SIZE as DIL_SEED,
    PUBLIC_KEY_SIZE as DIL_PK_SIZE, PRIVATE_KEY_SIZE as DIL_SK_SIZE,
    PublicKey as DilPublicKey,
};
use crate::error::CryptoError;
use crate::hdwallet::derivation::{derive_mdecc_curve_seed, CURVE_ID_ED448, CURVE_ID_P521};
use crate::mdecc::ed448::{
    new_key_from_seed as ed448_key_from_seed,
    SEED_SIZE as ED448_SEED, PUBLIC_KEY_SIZE as ED448_PK_SIZE,
    PublicKey as Ed448PublicKey,
};
use crate::mdecc::p521::{
    P521Scheme, PUBLIC_KEY_SIZE as P521_PK_SIZE,
    SEED_SIZE as P521_SEED,
    P521PrivateKey, P521PublicKey,
};
use crate::sign::TypedScheme;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Algorithm ID for the entanglement nonce (Version 1 hybrid scheme).
pub const ALGO_ID: u8 = 1;
/// Protocol version for the entanglement nonce.
pub const VERSION: u8 = 1;

/// Total bytes required for the composite public key in serialized form:
///   ML-DSA-87 pk (2592) ‖ P-521 pk (133) ‖ Ed448 pk (57)
pub const COMPOSITE_PK_SIZE: usize = DIL_PK_SIZE + P521_PK_SIZE + ED448_PK_SIZE;

// ---------------------------------------------------------------------------
// BlackChainPublicKey
// ---------------------------------------------------------------------------

/// The composite BlackChain public key (ML-DSA-87 + P-521 + Ed448).
///
/// Serialized as `[ML-DSA-87 pk (2592 B)] ‖ [P-521 pk (133 B)] ‖ [Ed448 pk (57 B)]`.
#[derive(Serialize, Deserialize, Clone, Zeroize)]
pub struct BlackChainPublicKey {
    dilithium: Vec<u8>,
    p521: Vec<u8>,
    ed448: Vec<u8>,
}

impl BlackChainPublicKey {
    /// Returns the raw ML-DSA-87 public key bytes.
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

    /// Serialises to `[ML-DSA-87 pk] ‖ [P-521 pk] ‖ [Ed448 pk]`.
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
    pub fn derive_address(&self) -> Address {
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, &self.dilithium);
        Digest::update(&mut hasher, &self.p521);
        Digest::update(&mut hasher, &self.ed448);
        let hash = hasher.finalize();
        Address::from_slice(&hash[12..32])
    }

    /// Verifies a composite post-quantum hybrid signature over any general message slice.
    ///
    /// Returns `Ok(true)` if all sub-signatures are valid and bound to the combined
    /// entanglement hash of this public key.
    ///
    /// # Errors
    /// Returns `Err` if any sub-signature verification fails or if the key format is invalid.
    pub fn verify_message(&self, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let hash = Keccak256::digest(message);

        // ── Compute H_combined ──
        let entg_nonce = [0u8; 16];
        let mut shake = Shake256::default();
        shake.update(self.dilithium_bytes());
        shake.update(self.p521_bytes());
        shake.update(self.ed448_bytes());
        shake.update(&entg_nonce);
        let mut h_combined = [0u8; 32];
        shake.finalize_xof().read(&mut h_combined);

        // ── Slicing ──
        // All three sub-signatures are fixed-width, so the composite has an exact
        // expected length. Requiring equality rejects truncated or padded inputs.
        let dil_sig_len = crate::dilithium::SIGNATURE_SIZE;
        let p521_sig_len = crate::mdecc::p521::SIGNATURE_SIZE;
        let ed448_sig_len = crate::mdecc::ed448::SIGNATURE_SIZE;
        let expected_len = dil_sig_len + p521_sig_len + ed448_sig_len;
        if signature.len() != expected_len {
            return Err(CryptoError::SignatureError(format!(
                "composite signature has wrong length: {} bytes (expected {expected_len})",
                signature.len()
            )));
        }

        let dil_sig = &signature[..dil_sig_len];
        let p521_sig = &signature[dil_sig_len..dil_sig_len + p521_sig_len];
        let ed448_sig = &signature[dil_sig_len + p521_sig_len..];

        // ── Verify ML-DSA-87 ──
        let dil_pk = DilPublicKey::from_bytes(self.dilithium_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("ML-DSA-87 public key parse error: {e}"))
        })?;
        dil_pk
            .verify_internal(&hash, dil_sig)
            .map_err(|e| CryptoError::SignatureError(format!("ML-DSA-87 verification failed: {e}")))?;

        // ── Verify P-521 ──
        let p521_msg: Vec<u8> = [&hash[..], &h_combined, &[CURVE_ID_P521]].concat();
        let p521_pk = P521PublicKey::from_bytes(self.p521_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("P-521 public key parse error: {e}"))
        })?;
        p521_pk
            .verify_sig(&p521_msg, p521_sig)
            .map_err(|e| CryptoError::SignatureError(format!("P-521 verification failed: {e}")))?;

        // ── Verify Ed448 ──
        let ed448_msg: Vec<u8> = [&hash[..], &h_combined, &[CURVE_ID_ED448]].concat();
        let ed448_pk = Ed448PublicKey::from_bytes(self.ed448_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("Ed448 public key parse error: {e}"))
        })?;
        ed448_pk
            .verify_sig(&ed448_msg, ed448_sig, None)
            .map_err(|e| CryptoError::SignatureError(format!("Ed448 verification failed: {e}")))?;

        Ok(true)
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

/// The composite BlackChain private key (ML-DSA-87 + P-521 + Ed448).
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
    /// Returns the raw 32-byte ML-DSA-87 seed (the stored secret-key form).
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
    /// Seed layout:
    /// ```text
    /// seed[0..32]  → ML-DSA-87 seed
    /// seed[32..64] → mdECC master (256 bits) → per-curve via SHAKE256 + HKDF-SHA3-512
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

        // ── ML-DSA-87 ────────────────────────────────────────────────────────
        // Deterministic from the first 32 bytes of the seed.
        let mut dil_seed = Zeroizing::new([0u8; DIL_SEED]);
        dil_seed.copy_from_slice(&seed[..DIL_SEED]);
        let (dil_pk, dil_sk) = dil_key_from_seed(&dil_seed);

        // ── mdECC master seed ─────────────────────────────────────────────────
        // Bytes 32..64 are the 32-byte (256-bit) mdECC master; each curve gets an
        // independent seed via SHAKE256 domain-separation + HKDF-SHA3-512.
        let mdecc_seed = &seed[32..64];

        // ── P-521 ─────────────────────────────────────────────────────────────
        let p521_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_P521, P521_SEED)?);
        let (p521_pk, p521_sk) = P521Scheme.derive_key_typed(&p521_seed);

        // ── Ed448 ─────────────────────────────────────────────────────────────
        let ed448_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_ED448, ED448_SEED)?);
        let (ed448_pk, ed448_sk) = ed448_key_from_seed(&ed448_seed);

        // ML-DSA-87 SK: pack() into a fixed array
        let mut dil_sk_buf = Zeroizing::new([0u8; DIL_SK_SIZE]);
        dil_sk.pack(&mut dil_sk_buf);

        // ML-DSA-87 PK: pack() into a fixed array
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

        let mdecc_seed = &seed[32..64];
        let p521_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_P521, P521_SEED)?);
        let (p521_pk, _) = P521Scheme.derive_key_typed(&p521_seed);

        let ed448_seed = Zeroizing::new(derive_mdecc_curve_seed(mdecc_seed, CURVE_ID_ED448, ED448_SEED)?);
        let (ed448_pk, _) = ed448_key_from_seed(&ed448_seed);

        let mut dil_pk_buf = [0u8; DIL_PK_SIZE];
        dil_pk.pack(&mut dil_pk_buf);

        Ok(BlackChainPublicKey {
            dilithium: dil_pk_buf.to_vec(),
            p521: p521_pk.as_bytes(),
            ed448: ed448_pk.as_bytes().to_vec(),
        })
    }

    /// Signs any general message byte slice using the composite post-quantum hybrid scheme.
    ///
    /// Under the hood, this uses a cross-algorithm entanglement hash (`h_combined`)
    /// over a zeroed 16-byte nonce to bind the ML-DSA-87, NIST P-521, and Ed448
    /// signatures together, guaranteeing message integrity and signature non-splicibility.
    ///
    /// # Errors
    /// Propagates any signing or key parsing errors.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let hash = Keccak256::digest(message);
        let pub_key = self.public_key();

        // ── H_combined entanglement hash using a zeroed nonce for general messages ──
        let entg_nonce = [0u8; 16];
        let mut shake = Shake256::default();
        shake.update(pub_key.dilithium_bytes());
        shake.update(pub_key.p521_bytes());
        shake.update(pub_key.ed448_bytes());
        shake.update(&entg_nonce);
        let mut h_combined = [0u8; 32];
        shake.finalize_xof().read(&mut h_combined);

        // ── ML-DSA-87 signature (raw hash) ──
        let dil_sk = crate::dilithium::PrivateKey::from_bytes(self.dilithium_bytes())
            .map_err(|e| CryptoError::SignatureError(format!("ML-DSA-87 key parse failed: {e}")))?;
        let dil_sig = dil_sk.sign_internal(&hash);

        // ── P-521 signature (H ‖ h_combined ‖ curve_id) ──
        let p521_msg: Vec<u8> = [&hash[..], &h_combined, &[CURVE_ID_P521]].concat();
        let p521_sk = P521PrivateKey::from_bytes(self.p521_bytes())?;
        let p521_sig = p521_sk.sign_msg(&p521_msg);

        // ── Ed448 signature (H ‖ h_combined ‖ curve_id) ──
        let ed448_msg: Vec<u8> = [&hash[..], &h_combined, &[CURVE_ID_ED448]].concat();
        let (_, ed448_sk) = crate::mdecc::ed448::PrivateKey::from_bytes(self.ed448_bytes())
            .map_err(|e| CryptoError::SignatureError(e.to_string()))?;
        let ed448_sig = ed448_sk.sign_msg(&ed448_msg, None)?;

        // ── Assemble composite signature [dil ‖ p521 ‖ ed448] ──
        let mut composite = Vec::with_capacity(dil_sig.len() + p521_sig.len() + ed448_sig.len());
        composite.extend_from_slice(&dil_sig);
        composite.extend_from_slice(&p521_sig);
        composite.extend_from_slice(&ed448_sig);

        Ok(composite)
    }
}

impl fmt::Debug for BlackChainPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print any secret material.
        f.debug_struct("BlackChainPrivateKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod golden_tests {
    use super::*;

    /// A fixed, non-zero 64-byte root seed used for deterministic golden vectors.
    fn fixed_seed() -> [u8; 64] {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s
    }

    /// Golden-vector regression lock for the deterministic derivation pipeline
    /// (seed → ML-DSA-87 / P-521 / Ed448 sub-keys → composite address).
    ///
    /// NOTE: these expected values were generated by this implementation itself —
    /// they pin behavior so accidental changes to the KDF, seed layout, or
    /// per-curve derivation are caught. They are NOT an external spec KAT (for
    /// that, see `rfc8032_ed448_blank_kat` in `mdecc::ed448`).
    #[test]
    fn golden_derivation_is_stable() {
        let seed = fixed_seed();
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();

        // Determinism: regenerating from the same seed yields identical material.
        let (priv2, pub2) = BlackChainPrivateKey::generate(&seed).unwrap();
        assert_eq!(pub_key.to_bytes(), pub2.to_bytes());
        assert_eq!(priv_key.dilithium_bytes(), priv2.dilithium_bytes());
        assert_eq!(priv_key.p521_bytes(), priv2.p521_bytes());
        assert_eq!(priv_key.ed448_bytes(), priv2.ed448_bytes());

        // Locked expected outputs (regenerate + update deliberately if the
        // derivation protocol ever intentionally changes).
        const EXPECTED_ADDRESS: &str = "627a606813a11b0ad7c0a1f87e077bd1f83ba976";
        const EXPECTED_ED448_PK: &str = "2533b99ba7648d2b4d586a6f872da504b9cc46909b0223da93a9316a95b42c4454dba369669e874aacc06976f4c9ad5d9b8212a77c84c3e780";
        const EXPECTED_P521_PK_HEAD: &str = "0400e2f88402fede86349efc0385b2d2";
        const EXPECTED_DIL_PK_HEAD: &str = "e3d83ad7a5d3463bc535f46168547e06";

        let addr = hex::encode(pub_key.derive_address().as_slice());
        let ed448 = hex::encode(pub_key.ed448_bytes());
        let p521_head = hex::encode(&pub_key.p521_bytes()[..16]);
        let dil_head = hex::encode(&pub_key.dilithium_bytes()[..16]);

        println!("GOLDEN ADDR={addr}");
        println!("GOLDEN ED448={ed448}");
        println!("GOLDEN P521HEAD={p521_head}");
        println!("GOLDEN DILHEAD={dil_head}");

        assert_eq!(addr, EXPECTED_ADDRESS, "address derivation changed");
        assert_eq!(ed448, EXPECTED_ED448_PK, "Ed448 sub-key derivation changed");
        assert_eq!(p521_head, EXPECTED_P521_PK_HEAD, "P-521 sub-key derivation changed");
        assert_eq!(dil_head, EXPECTED_DIL_PK_HEAD, "ML-DSA-87 sub-key derivation changed");
    }
}


