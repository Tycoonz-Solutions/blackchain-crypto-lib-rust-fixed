// transaction/types.rs — BlackChain transaction data structure.
//
// `BlackChainTxType` is a custom EIP-style transaction that carries both
// classical EIP-1559 fee fields and the BlackChain hybrid PQC signature.
//
// ## Signature fields
// - `v`, `r`, `s` — retained for EIP-155-compatible RLP framing.  In the
//   current protocol `v = chain_id * 2 + 35`, `r = 0`, `s = 0`.  They are
//   *not* ECDSA values; secp256k1 is not used.
// - `pqc_signature` — the concatenated hybrid signature:
//     [Dilithium5 sig (4627 B)] ‖ [P-521 sig (≤139 B)] ‖ [Ed448 sig (114 B)]
// - `pub_key` — the serialized composite public key (2782 bytes):
//     [Dilithium5 pk (2592 B)] ‖ [P-521 pk (133 B)] ‖ [Ed448 pk (57 B)]
//   Embedded in the transaction to allow `recover_sender` to verify the
//   hybrid signature without a separate public-key lookup.

use alloy_primitives::{Address, Bytes, U256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlackChainTxType {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    /// Recipient address; `None` for contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,

    // ── Signature fields ──────────────────────────────────────────────────
    /// EIP-155 recovery ID placeholder: `chain_id * 2 + 35`. Not secp256k1.
    pub v: Option<U256>,
    /// Zero-padded; secp256k1 `r` is not used in BlackChain.
    pub r: Option<U256>,
    /// Zero-padded; secp256k1 `s` is not used in BlackChain.
    pub s: Option<U256>,
    /// Concatenated hybrid PQC signature: `[Dilithium5 ‖ P-521 ‖ Ed448]`.
    pub pqc_signature: Option<Bytes>,
    /// Serialized composite public key used by `recover_sender`:
    /// `[Dilithium5 pk ‖ P-521 pk ‖ Ed448 pk]` (2782 bytes total).
    pub pub_key: Option<Bytes>,
}

impl BlackChainTxType {
    /// EIP-style transaction type byte (0x80 = BlackChain custom type).
    pub const TX_TYPE: u8 = 0x80;
}
