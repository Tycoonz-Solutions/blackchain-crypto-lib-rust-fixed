use crate::error::CryptoError;
use crate::transaction::types::BlackChainTxType;
use crate::crypto::{BlackChainPrivateKey, BlackChainPublicKey};
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
use sha3::{Keccak256, Digest};

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
        
        use crate::sign::PrivateKey;
        use crate::mdecc::p521::P521PrivateKey;
        use crate::mdecc::ed448::Ed448PrivateKey;
        use crate::mdecc::e521::E521PrivateKey;
        use crate::dilithium::DilithiumPrivateKey;
        
        let p521_sk = P521PrivateKey::try_from(key.p521.clone())?;
        let ed448_sk = Ed448PrivateKey::try_from(key.ed448.clone())?;
        let e521_sk = E521PrivateKey::try_from(key.e521.clone())?;
        let dil_sk = DilithiumPrivateKey::try_from(key.dilithium.clone())?;
        
        let mut composite_sig = Vec::new();
        composite_sig.extend(dil_sk.sign(hash.as_slice(), None)?);
        composite_sig.extend(p521_sk.sign(hash.as_slice(), None)?);
        composite_sig.extend(ed448_sk.sign(hash.as_slice(), None)?);
        composite_sig.extend(e521_sk.sign(hash.as_slice(), None)?);
        
        self.pqc_signature = Some(alloy_primitives::Bytes::from(composite_sig));
        self.v = Some(alloy_primitives::U256::from(self.chain_id * 2 + 35));
        self.r = Some(alloy_primitives::U256::ZERO);
        self.s = Some(alloy_primitives::U256::ZERO);

        Ok(())
    }

    pub fn recover_sender(&self) -> Result<Address, CryptoError> {
        if self.pqc_signature.is_none() {
            return Err(CryptoError::SignatureError("No signature attached to transaction".into()));
        }

        Ok(Address::ZERO) // Mocked
    }
}
