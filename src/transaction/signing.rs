use crate::crypto::BlackChainPrivateKey;
use crate::error::CryptoError;
use crate::transaction::types::BlackChainTxType;
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use sha3::{Digest, Keccak256};

impl BlackChainTxType {
    pub fn signature_hash(&self) -> B256 {
        let mut cloned = self.clone();
        cloned.v = None;
        cloned.r = None;
        cloned.s = None;
        cloned.pqc_signature = None;

        let mut out = Vec::new();
        cloned.encode(&mut out);

        let mut to_hash = vec![Self::TX_TYPE];
        to_hash.extend_from_slice(&out);

        let mut hasher = Keccak256::new();
        hasher.update(&to_hash);
        let result = hasher.finalize();
        B256::from_slice(&result)
    }

    pub fn sign_transaction(&mut self, key: &BlackChainPrivateKey) -> Result<(), CryptoError> {
        let hash = self.signature_hash();

        use crate::dilithium::{DilithiumPrivateKey, new_key_from_seed as dil_from_seed, SEED_SIZE as DIL_SEED};
        use crate::mdecc::e521::E521PrivateKey;
        use crate::mdecc::ed448::Ed448PrivateKey;
        use crate::mdecc::p521::P521PrivateKey;

        // Deserialise each key from its stored bytes.
        let dil_sk  = DilithiumPrivateKey::try_from(key.dilithium.clone())
            .or_else(|_| {
                // fallback: re-derive from stored bytes used as seed
                if key.dilithium.len() >= DIL_SEED {
                    let mut s = [0u8; DIL_SEED];
                    s.copy_from_slice(&key.dilithium[..DIL_SEED]);
                    let (_, sk) = dil_from_seed(&s);
                    Ok(sk)
                } else {
                    Err(CryptoError::SignatureError("dilithium key too short to re-derive".into()))
                }
            })?;
        let p521_sk  = P521PrivateKey::try_from(key.p521.clone())?;
        let ed448_sk = crate::mdecc::ed448::PrivateKey::from_bytes(&key.ed448)
            .map(|(_, sk)| sk)?;
        let e521_sk  = E521PrivateKey::try_from(key.e521.clone())?;

        let mut composite_sig = Vec::new();

        // Dilithium — use sign_internal directly
        composite_sig.extend(dil_sk.sign_internal(hash.as_slice()));

        // P-521 — sign_msg
        composite_sig.extend(p521_sk.sign_msg(hash.as_slice()));

        // Ed448 — sign_msg (returns Result)
        composite_sig.extend(
            ed448_sk.sign_msg(hash.as_slice(), None)
                .map_err(|e| CryptoError::SignatureError(e.to_string()))?,
        );

        // E-521 (mocked)
        composite_sig.extend(e521_sk.sign_msg(hash.as_slice()));

        self.pqc_signature = Some(alloy_primitives::Bytes::from(composite_sig));
        self.v = Some(alloy_primitives::U256::from(self.chain_id * 2 + 35));
        self.r = Some(alloy_primitives::U256::ZERO);
        self.s = Some(alloy_primitives::U256::ZERO);

        Ok(())
    }

    pub fn recover_sender(&self) -> Result<Address, CryptoError> {
        if self.pqc_signature.is_none() {
            return Err(CryptoError::SignatureError(
                "No signature attached to transaction".into(),
            ));
        }

        Ok(Address::ZERO) // Mocked
    }
}
