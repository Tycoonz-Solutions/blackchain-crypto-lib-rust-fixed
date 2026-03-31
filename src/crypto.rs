use crate::error::CryptoError;
use crate::sign::{PrivateKey, PublicKey, Scheme};
use crate::dilithium::DilithiumScheme;
use crate::mdecc::p521::P521Scheme;
use crate::mdecc::ed448::Ed448Scheme;
use crate::mdecc::e521::E521Scheme;
use alloy_primitives::Address;
use sha3::{Keccak256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct BlackChainPublicKey {
    pub dilithium: Vec<u8>,
    pub p521: Vec<u8>,
    pub ed448: Vec<u8>,
    pub e521: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlackChainPrivateKey {
    pub dilithium: Vec<u8>,
    pub p521: Vec<u8>,
    pub ed448: Vec<u8>,
    pub e521: Vec<u8>,
}

impl BlackChainPublicKey {
    pub fn derive_address(&self) -> Address {
        let mut hasher = Keccak256::new();
        hasher.update(&self.dilithium);
        hasher.update(&self.p521);
        hasher.update(&self.ed448);
        hasher.update(&self.e521);
        let hash = hasher.finalize();
        Address::from_slice(&hash[12..32])
    }
}

impl BlackChainPrivateKey {
    pub fn generate(seed: &[u8]) -> Result<(Self, BlackChainPublicKey), CryptoError> {
        if seed.len() < 64 {
            return Err(CryptoError::SeedError("Seed must be at least 64 bytes".into()));
        }

        let (dilithium_sk, dilithium_pk) = DilithiumScheme::generate_key(&seed[..32])?;
        let (p521_sk, p521_pk) = P521Scheme::generate_key(seed)?;
        let (ed448_sk, ed448_pk) = Ed448Scheme::generate_key(seed)?;
        let (e521_sk, e521_pk) = E521Scheme::generate_key(seed)?;

        let priv_key = BlackChainPrivateKey {
            dilithium: dilithium_sk.to_bytes(),
            p521: p521_sk.to_bytes(),
            ed448: ed448_sk.to_bytes(),
            e521: e521_sk.to_bytes(),
        };

        let pub_key = BlackChainPublicKey {
            dilithium: dilithium_pk.to_bytes(),
            p521: p521_pk.to_bytes(),
            ed448: ed448_pk.to_bytes(),
            e521: e521_pk.to_bytes(),
        };

        Ok((priv_key, pub_key))
    }
}
