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
        // Bound decoding to exactly the declared list payload. Decoding fields
        // straight out of `buf` would ignore `header.payload_length`, letting a
        // mis-declared length or trailing bytes be silently consumed as fields —
        // a source of non-canonical / malleable encodings. Instead we carve out
        // the payload, decode from it, and require it is fully consumed.
        if header.payload_length > buf.len() {
            return Err(Error::InputTooShort);
        }
        let full: &[u8] = buf;
        let (mut payload, rest) = full.split_at(header.payload_length);
        let body = &mut payload;

        let chain_id = u64::decode(body)?;
        let nonce = u64::decode(body)?;
        let max_priority_fee_per_gas = U256::decode(body)?;
        let max_fee_per_gas = U256::decode(body)?;
        let gas_limit = u64::decode(body)?;

        // Optional `to` field: empty bytes → None, 20 bytes → Some(Address)
        let to_bytes = Bytes::decode(body)?;
        let to = if to_bytes.is_empty() {
            None
        } else if to_bytes.len() == 20 {
            Some(Address::from_slice(&to_bytes))
        } else {
            return Err(Error::UnexpectedLength);
        };

        let value = U256::decode(body)?;
        let data = Bytes::decode(body)?;

        let mut v = None;
        let mut r = None;
        let mut s = None;
        let mut pqc_signature = None;
        let mut pub_key = None;

        if !body.is_empty() {
            v = Some(U256::decode(body)?);
            r = Some(U256::decode(body)?);
            s = Some(U256::decode(body)?);
            pqc_signature = Some(Bytes::decode(body)?);
            // pub_key was added in v2; tolerate absence for backwards compat.
            if !body.is_empty() {
                let pk_bytes = Bytes::decode(body)?;
                if !pk_bytes.is_empty() {
                    pub_key = Some(pk_bytes);
                }
            }
        }

        // Reject any leftover bytes inside the declared list payload.
        if !body.is_empty() {
            return Err(Error::Custom("trailing bytes in transaction payload"));
        }
        *buf = rest;

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_rlp::{Decodable, Encodable};

    fn sample_unsigned() -> BlackChainTxType {
        BlackChainTxType {
            chain_id: 1,
            nonce: 7,
            max_priority_fee_per_gas: U256::from(1u64),
            max_fee_per_gas: U256::from(2u64),
            gas_limit: 21_000,
            to: Some(Address::repeat_byte(0xab)),
            value: U256::from(1000u64),
            data: Bytes::from(vec![1, 2, 3]),
            v: None,
            r: None,
            s: None,
            pqc_signature: None,
            pub_key: None,
        }
    }

    #[test]
    fn encode_decode_roundtrip_unsigned() {
        let tx = sample_unsigned();
        let mut out = Vec::new();
        tx.encode(&mut out);
        let mut slice = out.as_slice();
        let decoded = BlackChainTxType::decode(&mut slice).unwrap();
        assert_eq!(decoded, tx);
        assert!(slice.is_empty(), "decode must consume exactly the list payload");
    }

    #[test]
    fn encode_decode_roundtrip_signed() {
        let mut tx = sample_unsigned();
        tx.v = Some(U256::from(37u64));
        tx.r = Some(U256::ZERO);
        tx.s = Some(U256::ZERO);
        tx.pqc_signature = Some(Bytes::from(vec![0xAAu8; 100]));
        tx.pub_key = Some(Bytes::from(vec![0xBBu8; 50]));

        let mut out = Vec::new();
        tx.encode(&mut out);
        let mut slice = out.as_slice();
        let decoded = BlackChainTxType::decode(&mut slice).unwrap();
        assert_eq!(decoded, tx);
        assert!(slice.is_empty());
    }

    /// Bytes trailing the RLP list must not be silently consumed as signature
    /// fields — the decoder is bounded to the declared list payload length.
    #[test]
    fn trailing_bytes_are_not_consumed_as_fields() {
        let tx = sample_unsigned();
        let mut out = Vec::new();
        tx.encode(&mut out);
        out.extend_from_slice(&[0x01, 0x02]); // junk after the list

        let mut slice = out.as_slice();
        let decoded = BlackChainTxType::decode(&mut slice).unwrap();
        assert!(
            decoded.v.is_none() && decoded.pqc_signature.is_none(),
            "trailing bytes must not be decoded into signature fields"
        );
        assert_eq!(slice, &[0x01, 0x02], "trailing bytes must be left untouched");
    }
}
