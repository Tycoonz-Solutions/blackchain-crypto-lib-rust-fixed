// transaction/signing.rs — BlackChain transaction signing and sender recovery.
//
// ## Signing protocol (matches Go's hdwallet.Sign)
//
// Given a 32-byte transaction hash `H`:
//
//  1. entg_nonce = SHAKE256("entangle" ‖ ALGO_ID ‖ VERSION ‖ address)[0..16]
//  2. h_combined = SHAKE256(dil_pk ‖ p521_pk ‖ ed448_pk ‖ entg_nonce)[0..32]
//  3. dil_sig    = Dilithium5.sign(H)
//  4. p521_sig   = P-521.sign(H ‖ h_combined ‖ CURVE_ID_P521)
//  5. ed448_sig  = Ed448.sign(H ‖ h_combined ‖ CURVE_ID_ED448)
//  6. composite  = dil_sig ‖ p521_sig ‖ ed448_sig
//
// The composite signature and the serialized composite public key are embedded
// in the transaction's `pqc_signature` and `pub_key` fields respectively.
//
// ## Sender recovery (matches Go's BlackChainSignerV1.Sender)
//
//  1. Deserialize pub_key → BlackChainPublicKey
//  2. Reconstruct h_combined using the same algorithm as above
//  3. Verify dil_sig, p521_sig, ed448_sig
//  4. Return Keccak256(dil_pk ‖ p521_pk ‖ ed448_pk)[12..] as the address

use alloy_primitives::{Address, Bytes, U256};
use crystals_dilithium::dilithium5 as d5;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::crypto::{BlackChainPrivateKey, BlackChainPublicKey, ALGO_ID, VERSION};
use crate::dilithium::{PublicKey as DilPublicKey, SIGNATURE_SIZE as DIL_SIG_SIZE};
use crate::error::CryptoError;
use crate::hdwallet::derivation::{CURVE_ID_ED448, CURVE_ID_P521};
use crate::mdecc::ed448::PublicKey as Ed448PublicKey;
use crate::mdecc::p521::{P521PrivateKey, P521PublicKey, SIGNATURE_SIZE as P521_SIG_MAX};
use crate::transaction::types::BlackChainTxType;

// ---------------------------------------------------------------------------
// Composite signature layout constants
// ---------------------------------------------------------------------------

/// Size of a Dilithium5 signature (bytes).
pub const DIL_SIG_BYTES: usize = DIL_SIG_SIZE;
/// Maximum size of a DER-encoded P-521 ECDSA signature.
pub const P521_SIG_BYTES: usize = P521_SIG_MAX;
/// Size of an Ed448 signature.
pub const ED448_SIG_BYTES: usize = 114;
/// Minimum composite signature size (Dilithium5 + minimum 8 bytes for P-521 + Ed448).
pub const MIN_COMPOSITE_SIG_SIZE: usize = DIL_SIG_BYTES + 8 + ED448_SIG_BYTES;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes the 16-byte entanglement nonce:
///   SHAKE256("entangle" ‖ ALGO_ID ‖ VERSION ‖ address)[0..16]
fn compute_entanglement_nonce(address: &Address) -> [u8; 16] {
    let mut shake = Shake256::default();
    shake.update(b"entangle");
    shake.update(&[ALGO_ID]);
    shake.update(&[VERSION]);
    shake.update(address.as_slice());
    let mut nonce = [0u8; 16];
    shake.finalize_xof().read(&mut nonce);
    nonce
}

/// Computes the 32-byte H_combined cross-algorithm binding hash:
///   SHAKE256(dil_pk ‖ p521_pk ‖ ed448_pk ‖ entg_nonce)[0..32]
fn compute_h_combined(pub_key: &BlackChainPublicKey, entg_nonce: &[u8; 16]) -> [u8; 32] {
    let mut shake = Shake256::default();
    shake.update(pub_key.dilithium_bytes());
    shake.update(pub_key.p521_bytes());
    shake.update(pub_key.ed448_bytes());
    shake.update(entg_nonce);
    let mut h = [0u8; 32];
    shake.finalize_xof().read(&mut h);
    h
}

// ---------------------------------------------------------------------------
// BlackChainTxType — signing and recovery
// ---------------------------------------------------------------------------

impl BlackChainTxType {
    /// Returns the 32-byte hash that must be signed (unsigned RLP + type prefix).
    pub fn signature_hash(&self) -> [u8; 32] {
        use alloy_rlp::Encodable;
        use sha3::{Digest, Keccak256};

        // Build an unsigned copy (no signature fields).
        let unsigned = BlackChainTxType {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            data: self.data.clone(),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        };

        let mut rlp = Vec::new();
        rlp.push(Self::TX_TYPE);
        unsigned.encode(&mut rlp);

        Keccak256::digest(&rlp).into()
    }

    /// Signs this transaction in-place using the BlackChain hybrid scheme.
    ///
    /// Implements the full Go `hdwallet.Sign` protocol including the
    /// H_combined cross-algorithm entanglement binding.
    ///
    /// On success, the `pqc_signature`, `pub_key`, and `v`/`r`/`s` fields
    /// are populated.
    ///
    /// # Errors
    /// Propagates errors from key reconstruction or signing operations.
    pub fn sign_transaction(&mut self, key: &BlackChainPrivateKey) -> Result<(), CryptoError> {
        let hash = self.signature_hash();

        // Use cached public key for H_combined computation.
        let pub_key = key.public_key();
        let address = pub_key.derive_address();

        // ── Entanglement nonce & H_combined ───────────────────────────────
        let entg_nonce = compute_entanglement_nonce(&address);
        let h_combined = compute_h_combined(&pub_key, &entg_nonce);

        // ── Dilithium5 signature (raw hash) ───────────────────────────────
        // Use crystals_dilithium directly to avoid the PrivateKey roundtrip
        // limitation (PrivateKey::from_bytes is intentionally disabled).
        let dil_sk_bytes = key.dilithium_bytes();
        if dil_sk_bytes.len() != crate::dilithium::PRIVATE_KEY_SIZE {
            return Err(CryptoError::SignatureError(format!(
                "Dilithium5 secret key has wrong size: expected {}, got {}",
                crate::dilithium::PRIVATE_KEY_SIZE,
                dil_sk_bytes.len()
            )));
        }
        use zeroize::Zeroizing;

        let mut dil_sk_buf = Zeroizing::new([0u8; crate::dilithium::PRIVATE_KEY_SIZE]);
        dil_sk_buf.copy_from_slice(dil_sk_bytes);
        let dil_inner = d5::SecretKey::from_bytes(&*dil_sk_buf).map_err(|e| {
            CryptoError::SignatureError(format!("Dilithium5 key parse failed: {e:?}"))
        })?;
        let dil_sig = dil_inner.sign(&hash).to_vec();

        // ── P-521 signature (H ‖ h_combined ‖ curve_id) ──────────────────
        let p521_msg: Vec<u8> = [hash.as_slice(), &h_combined, &[CURVE_ID_P521]].concat();
        let p521_sk = P521PrivateKey::from_bytes(key.p521_bytes())?;
        let p521_sig = p521_sk.sign_msg(&p521_msg);

        // ── Ed448 signature (H ‖ h_combined ‖ curve_id) ──────────────────
        let ed448_msg: Vec<u8> = [hash.as_slice(), &h_combined, &[CURVE_ID_ED448]].concat();
        // Ed448 from_bytes returns (PublicKey, PrivateKey)
        let (_, ed448_sk) = crate::mdecc::ed448::PrivateKey::from_bytes(key.ed448_bytes())
            .map_err(|e| CryptoError::SignatureError(e.to_string()))?;
        let ed448_sig = ed448_sk.sign_msg(&ed448_msg, None)?;

        // ── Assemble composite signature [dil ‖ p521 ‖ ed448] ────────────
        let mut composite = Vec::with_capacity(dil_sig.len() + p521_sig.len() + ed448_sig.len());
        composite.extend_from_slice(&dil_sig);
        composite.extend_from_slice(&p521_sig);
        composite.extend_from_slice(&ed448_sig);

        // ── Write fields to tx ────────────────────────────────────────────
        self.pqc_signature = Some(Bytes::from(composite));
        self.pub_key = Some(Bytes::from(pub_key.to_bytes()));
        self.v = Some(U256::from(self.chain_id * 2 + 35)); // EIP-155 placeholder
        self.r = Some(U256::ZERO);
        self.s = Some(U256::ZERO);

        Ok(())
    }

    /// Recovers the sender's address by verifying the composite signature.
    ///
    /// Implements the Go `BlackChainSignerV1.Sender` protocol:
    ///  1. Deserializes the `pub_key` field.
    ///  2. Reconstructs `h_combined` using the embedded public keys.
    ///  3. Verifies Dilithium5, P-521, and Ed448 signatures.
    ///  4. Derives and returns the address from the verified public key.
    ///
    /// # Errors
    /// Returns `Err` if any signature is missing, invalid, or fails verification.
    pub fn recover_sender(&self) -> Result<Address, CryptoError> {
        // ── Require both signature fields ─────────────────────────────────
        let pqc_sig = self.pqc_signature.as_ref().ok_or_else(|| {
            CryptoError::SignatureError("transaction is not signed (pqc_signature missing)".into())
        })?;
        let pub_key_bytes = self.pub_key.as_ref().ok_or_else(|| {
            CryptoError::SignatureError("transaction is not signed (pub_key missing)".into())
        })?;

        // ── Parse composite public key ────────────────────────────────────
        let pub_key = BlackChainPublicKey::from_bytes(pub_key_bytes).map_err(|e| {
            CryptoError::SignatureError(format!("pub_key deserialization failed: {e}"))
        })?;

        // ── Compute tx hash ───────────────────────────────────────────────
        let hash = self.signature_hash();

        // ── Reconstruct H_combined ────────────────────────────────────────
        let address = pub_key.derive_address();
        let entg_nonce = compute_entanglement_nonce(&address);
        let h_combined = compute_h_combined(&pub_key, &entg_nonce);

        // ── Parse composite signature: dil ‖ p521 ‖ ed448 ────────────────
        // P-521 signatures are DER-encoded and variable-length. We locate the
        // ed448 portion from the end (fixed 114 bytes) and treat everything
        // between the Dilithium portion and the Ed448 portion as the P-521 sig.
        if pqc_sig.len() < DIL_SIG_BYTES + ED448_SIG_BYTES {
            return Err(CryptoError::SignatureError(format!(
                "composite signature too short: {} bytes (minimum {})",
                pqc_sig.len(),
                MIN_COMPOSITE_SIG_SIZE
            )));
        }

        let dil_sig = &pqc_sig[..DIL_SIG_BYTES];
        let ed448_sig_offset = pqc_sig.len() - ED448_SIG_BYTES;
        let p521_sig = &pqc_sig[DIL_SIG_BYTES..ed448_sig_offset];
        let ed448_sig = &pqc_sig[ed448_sig_offset..];

        // ── Verify Dilithium5 ─────────────────────────────────────────────
        let dil_pk = DilPublicKey::from_bytes(pub_key.dilithium_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("Dilithium5 public key parse error: {e}"))
        })?;
        dil_pk
            .verify_internal(&hash, dil_sig)
            .map_err(|e| CryptoError::SignatureError(format!("Dilithium5 verification failed: {e}")))?;

        // ── Verify P-521 ──────────────────────────────────────────────────
        let p521_msg: Vec<u8> = [hash.as_slice(), &h_combined, &[CURVE_ID_P521]].concat();
        let p521_pk = P521PublicKey::from_bytes(pub_key.p521_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("P-521 public key parse error: {e}"))
        })?;
        p521_pk
            .verify_sig(&p521_msg, p521_sig)
            .map_err(|e| CryptoError::SignatureError(format!("P-521 verification failed: {e}")))?;

        // ── Verify Ed448 ──────────────────────────────────────────────────
        let ed448_msg: Vec<u8> = [hash.as_slice(), &h_combined, &[CURVE_ID_ED448]].concat();
        let ed448_pk = Ed448PublicKey::from_bytes(pub_key.ed448_bytes()).map_err(|e| {
            CryptoError::SignatureError(format!("Ed448 public key parse error: {e}"))
        })?;
        ed448_pk
            .verify_sig(&ed448_msg, ed448_sig, None)
            .map_err(|e| CryptoError::SignatureError(format!("Ed448 verification failed: {e}")))?;

        // ── Derive sender address from the verified public key ────────────
        Ok(pub_key.derive_address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BlackChainPrivateKey;

    #[test]
    fn test_composite_sign_and_recover_roundtrip() {
        // Generate a non-zero deterministic seed.
        let mut seed = [0u8; 64];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8;
        }
        let (priv_key, pub_key) = BlackChainPrivateKey::generate(&seed).unwrap();
        let address = pub_key.derive_address();

        let mut tx = BlackChainTxType {
            chain_id: 1,
            nonce: 10,
            max_priority_fee_per_gas: U256::from(1_500_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit: 21_000,
            to: Some(Address::repeat_byte(0xaa)),
            value: U256::from(100_000_000_000_000_000u64),
            data: Bytes::from(vec![1, 2, 3, 4]),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        };

        // Sign the transaction
        tx.sign_transaction(&priv_key).expect("Failed to sign transaction");

        // Verify the fields are populated
        assert!(tx.pqc_signature.is_some());
        assert!(tx.pub_key.is_some());
        assert!(tx.v.is_some());
        assert!(tx.r.is_some());
        assert!(tx.s.is_some());

        // Recover the sender
        let recovered = tx.recover_sender().expect("Failed to recover sender");
        assert_eq!(recovered, address);
    }
}
