use crate::error::CryptoError;
use crate::sign::{TypedScheme, PublicKey as SignPub, PrivateKey as SignPriv};
use crate::dilithium::{new_key_from_seed as dil_key_from_seed, SEED_SIZE as DIL_SEED};
use crate::mdecc::p521::P521Scheme;
use crate::mdecc::ed448::{new_key_from_seed as ed448_key_from_seed, SEED_SIZE as ED448_SEED};
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
        if seed.len() < 66 {
            return Err(CryptoError::SeedError("Seed must be at least 66 bytes".into()));
        }

        // Dilithium5 — typed API via TypedScheme, deterministic from first 32 bytes
        let dil_seed: [u8; DIL_SEED] = seed[..DIL_SEED].try_into().unwrap();
        let (dil_pk, dil_sk) = dil_key_from_seed(&dil_seed);

        // P-521 — derive from seed via TypedScheme
        let (p521_pk, p521_sk) = P521Scheme.derive_key_typed(seed);

        // Ed448 — derive from first 57 bytes via TypedScheme
        let ed448_seed = &seed[..ED448_SEED];
        let (ed448_pk, ed448_sk) = ed448_key_from_seed(ed448_seed);

        // E-521 — mocked, derive from seed
        let (e521_pk, e521_sk) = E521Scheme.derive_key_typed(seed);

        let priv_key = BlackChainPrivateKey {
            dilithium: dil_sk.marshal_binary()?,
            p521:      p521_sk.marshal_binary()?,
            ed448:     ed448_sk.marshal_binary()?,
            e521:      e521_sk.marshal_binary()?,
        };

        let pub_key = BlackChainPublicKey {
            dilithium: dil_pk.marshal_binary()?,
            p521:      p521_pk.marshal_binary()?,
            ed448:     ed448_pk.marshal_binary()?,
            e521:      e521_pk.marshal_binary()?,
        };

        Ok((priv_key, pub_key))
    }
}
