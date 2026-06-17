// transaction/rlp.rs — RLP encoding/decoding for BlackChainTxType.
//
// Encoding layout (unsigned):
//   [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//    gas_limit, to, value, data]
//
// Encoding layout (signed — v/r/s/pqc_signature/pub_key all present):
//   [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//    gas_limit, to, value, data,
//    v, r, s, pqc_signature, pub_key]
//
// The `pub_key` field is only encoded when at least one of `v` or
// `pqc_signature` is present (i.e. the transaction has been signed).

use crate::transaction::types::BlackChainTxType;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Error, Header};

impl BlackChainTxType {
    /// Computes the total payload length of the transaction when RLP encoded.
    fn rlp_payload_length(&self) -> usize {
        let mut payload_length = 0;
        payload_length += self.chain_id.length();
        payload_length += self.nonce.length();
        payload_length += self.max_priority_fee_per_gas.length();
        payload_length += self.max_fee_per_gas.length();
        payload_length += self.gas_limit.length();
        payload_length += match &self.to {
            Some(addr) => addr.length(),
            None => b"".as_slice().length(),
        };
        payload_length += self.value.length();
        payload_length += self.data.length();

        let has_signature = self.v.is_some() || self.pqc_signature.is_some();
        if has_signature {
            payload_length += self.v.unwrap_or(U256::ZERO).length();
            payload_length += self.r.unwrap_or(U256::ZERO).length();
            payload_length += self.s.unwrap_or(U256::ZERO).length();
            payload_length += self
                .pqc_signature
                .as_ref()
                .unwrap_or(&Bytes::default())
                .length();
            payload_length += self
                .pub_key
                .as_ref()
                .unwrap_or(&Bytes::default())
                .length();
        }
        payload_length
    }
}

impl Encodable for BlackChainTxType {
    fn encode(&self, out: &mut dyn BufMut) {
        let payload_length = self.rlp_payload_length();
        let header = Header { list: true, payload_length };
        header.encode(out);

        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        match &self.to {
            Some(addr) => addr.encode(out),
            None => b"".as_slice().encode(out),
        }
        self.value.encode(out);
        self.data.encode(out);

        let has_signature = self.v.is_some() || self.pqc_signature.is_some();
        if has_signature {
            self.v.unwrap_or(U256::ZERO).encode(out);
            self.r.unwrap_or(U256::ZERO).encode(out);
            self.s.unwrap_or(U256::ZERO).encode(out);
            self.pqc_signature
                .as_ref()
                .unwrap_or(&Bytes::default())
                .encode(out);
            self.pub_key
                .as_ref()
                .unwrap_or(&Bytes::default())
                .encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_payload_length();
        alloy_rlp::length_of_length(payload_length) + payload_length
    }
}

impl Decodable for BlackChainTxType {
    fn decode(buf: &mut &[u8]) -> Result<Self, Error> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(Error::UnexpectedString);
        }

        let chain_id = u64::decode(buf)?;
        let nonce = u64::decode(buf)?;
        let max_priority_fee_per_gas = U256::decode(buf)?;
        let max_fee_per_gas = U256::decode(buf)?;
        let gas_limit = u64::decode(buf)?;

        // Optional `to` field: empty bytes → None, 20 bytes → Some(Address)
        let to_bytes = Bytes::decode(buf)?;
        let to = if to_bytes.is_empty() {
            None
        } else if to_bytes.len() == 20 {
            Some(Address::from_slice(&to_bytes))
        } else {
            return Err(Error::UnexpectedLength);
        };

        let value = U256::decode(buf)?;
        let data = Bytes::decode(buf)?;

        let mut v = None;
        let mut r = None;
        let mut s = None;
        let mut pqc_signature = None;
        let mut pub_key = None;

        if !buf.is_empty() {
            v = Some(U256::decode(buf)?);
            r = Some(U256::decode(buf)?);
            s = Some(U256::decode(buf)?);
            pqc_signature = Some(Bytes::decode(buf)?);
            // pub_key was added in v2; tolerate absence for backwards compat.
            if !buf.is_empty() {
                let pk_bytes = Bytes::decode(buf)?;
                if !pk_bytes.is_empty() {
                    pub_key = Some(pk_bytes);
                }
            }
        }

        Ok(Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            v,
            r,
            s,
            pqc_signature,
            pub_key,
        })
    }
}
