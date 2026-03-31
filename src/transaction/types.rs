use alloy_primitives::{Address, U256, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackChainTxType {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    // Add multiple signature fields representing our hybrid post-quantum approach
    pub v: Option<U256>,
    pub r: Option<U256>,
    pub s: Option<U256>,
    // PQC extension
    pub pqc_signature: Option<Bytes>,
}

impl BlackChainTxType {
    pub const TX_TYPE: u8 = 0x80;
}
