// derivation.rs — Seed derivation utilities.
//
// Implements the same key-derivation protocol as the Go reference library
// (`blackchain_crypto/hdwallet`).
//
// ## mdECC per-curve seed derivation  (Go: `DeriveMdECCCurveSeed`)
//
// Given the 16-byte mdECC master seed (bytes 32..48 of the BIP-39 root seed)
// and a curve identifier byte, produces a cryptographically independent seed
// of the requested length:
//
//   1. shaken  = SHAKE256(mdECC_seed ‖ curve_id)[0..32]
//   2. output  = HKDF-SHA3-512(IKM=shaken, salt=∅, info=∅)[0..seed_size]
//
// Each curve receives a unique 32-byte IKM (domain-separated by the curve ID)
// before HKDF expansion, so the Dilithium, P-521, and Ed448 key material are
// mutually independent even though they share a common root.
//
// ## BIP32 child-key derivation  (Go: `DeriveKey` via `btcd/hdkeychain`)
//
// Given the 64-byte BIP-39 master seed and an array of hardened child indices,
// returns a fresh 64-byte child seed:
//
//   child_seed = PrivateKeyBytes(path[-1]) ‖ ChainCode(path[-1])
//
// Only hardened indices (≥ 0x80000000) are accepted to prevent public-key
// exposure attacks on parent keys.

use bip32::{ChildNumber, XPrv};
use hkdf::Hkdf;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3_512, Shake256,
};
use zeroize::Zeroizing;

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Curve ID constants (must match Go's hdwallet/wallet.go)
// ---------------------------------------------------------------------------

/// Curve identifier used in mdECC seed derivation for P-521.
pub const CURVE_ID_P521: u8 = 1;
/// Curve identifier used in mdECC seed derivation for Ed448.
pub const CURVE_ID_ED448: u8 = 2;

// ---------------------------------------------------------------------------
// Per-curve seed derivation
// ---------------------------------------------------------------------------

/// Derives a cryptographically independent per-curve seed from the master
/// mdECC seed (16 bytes, taken from bytes 32..48 of the BIP-39 root seed).
///
/// Matches Go's `DeriveMdECCCurveSeed(mdECCSeed, curveID, seedSize)`.
///
/// # Arguments
/// - `mdecc_seed` — the 16-byte mdECC master slice.
/// - `curve_id`   — one of `CURVE_ID_P521` or `CURVE_ID_ED448`.
/// - `seed_size`  — how many output bytes are needed by the target curve.
///
/// # Errors
/// Returns `Err` only if HKDF expansion is asked for more bytes than the
/// hash can produce (practically impossible for small `seed_size` values).
pub fn derive_mdecc_curve_seed(
    mdecc_seed: &[u8],
    curve_id: u8,
    seed_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Step 1: SHAKE256(mdECC_seed ‖ curve_id) → 32 bytes
    //
    // The IKM must be at least as long as the target security level.
    // P-521 targets 256-bit security and Ed448 targets 224-bit security,
    // so 32 bytes (256 bits) is the minimum safe IKM length.
    let mut shake = Shake256::default();
    shake.update(mdecc_seed);
    shake.update(&[curve_id]);
    let mut shaken = [0u8; 32];
    shake.finalize_xof().read(&mut shaken);

    // Step 2: HKDF-SHA3-512(IKM=shaken, salt=∅, info=∅) → seed_size bytes
    let hk = Hkdf::<Sha3_512>::new(None, &shaken);
    let mut output = vec![0u8; seed_size];
    hk.expand(&[], &mut output)
        .map_err(|_| CryptoError::Custom("HKDF-SHA3-512 expand failed".into()))?;

    Ok(output)
}

// ---------------------------------------------------------------------------
// BIP32 child-key derivation
// ---------------------------------------------------------------------------

/// Derives a 64-byte child seed from `master_seed` following the BIP32
/// hardened-only derivation path given in `path`.
///
/// Matches Go's `DeriveKey(masterSeed, path)` using `btcd/hdkeychain`.
///
/// `path` is a slice of raw uint32 child indices.  All must be hardened
/// (≥ `0x80000000`); the function returns `Err` if any are not.
///
/// The returned 64 bytes are:
///   - bytes  0..32 : the 32-byte secp256k1 private key of the leaf node
///   - bytes 32..64 : the 32-byte chain code of the leaf node
///
/// # Errors
/// - `Err` if any path index is not hardened.
/// - `Err` if BIP32 derivation fails (e.g. invalid master seed length).
pub fn derive_child_seed(master_seed: &[u8], path: &[u32]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Enforce hardened-only policy (matches Go's DeriveKey validation).
    for (i, &idx) in path.iter().enumerate() {
        if idx < 0x8000_0000 {
            return Err(CryptoError::Custom(format!(
                "BIP32: index at position {i} must be hardened (≥ 0x80000000), got 0x{idx:08x}"
            )));
        }
    }

    // Build BIP32 master key from the 64-byte BIP-39 root seed.
    let mut key = XPrv::new(master_seed)
        .map_err(|e| CryptoError::Custom(format!("BIP32 master key creation failed: {e}")))?;

    // Iteratively derive each hardened child.
    for &child_index in path {
        // strip the hardening bit to get the raw index, then re-harden via ChildNumber
        let raw_index = child_index & 0x7FFF_FFFF;
        let child_num = ChildNumber::new(raw_index, true)
            .map_err(|e| CryptoError::Custom(format!("BIP32 child number error: {e}")))?;
        key = key
            .derive_child(child_num)
            .map_err(|e| CryptoError::Custom(format!("BIP32 child derivation failed: {e}")))?;
    }

    // Combine private key bytes (32) + chain code (32) → 64-byte child seed.
    // This matches Go: append(privKey.Serialize(), chainCode...)
    let priv_bytes = key.private_key().to_bytes();
    let chain_code = key.attrs().chain_code;

    let mut child_seed = Vec::with_capacity(64);
    child_seed.extend_from_slice(&priv_bytes);
    child_seed.extend_from_slice(&chain_code);
    Ok(Zeroizing::new(child_seed))
}

/// Parses a BIP32 derivation path string (e.g. `"44/60/0/0/0"` or
/// `"m/44'/60'/0'/0'/0'"`) into a vec of hardened child indices.
///
/// - Bare integers like `44` are automatically hardened.
/// - `'`, `h`, `H` suffixes are accepted and stripped.
/// - An optional leading `"m/"` is ignored.
///
/// Returns `Err` if the string is empty, contains non-numeric segments,
/// or any index exceeds the 31-bit pre-hardening limit.
pub fn parse_hardened_path(s: &str) -> Result<Vec<u32>, CryptoError> {
    let s = s.trim().trim_start_matches("m/");
    if s.is_empty() {
        return Err(CryptoError::Custom("derivation path is empty".into()));
    }

    s.split('/')
        .enumerate()
        .map(|(pos, part)| {
            let stripped = part.trim_end_matches(['\'', 'h', 'H']);
            let n: u32 = stripped.parse().map_err(|_| {
                CryptoError::Custom(format!(
                    "BIP32: invalid index {:?} at position {pos}",
                    part
                ))
            })?;
            if n > 0x7FFF_FFFF {
                return Err(CryptoError::Custom(format!(
                    "BIP32: index too large before hardening at position {pos}"
                )));
            }
            Ok(n | 0x8000_0000)
        })
        .collect()
}
