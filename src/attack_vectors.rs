//! Known-attack-vector tests for the composite hybrid scheme, the transaction
//! layer, and wallet derivation.
//!
//! Unlike `tests/adversarial.rs` (random property-based fuzzing), every test
//! here constructs a *specific* malicious input a real attacker would attempt —
//! signature malleability, sub-signature/sub-key splicing, transaction
//! tampering, non-canonical RLP, and degenerate keys — and asserts it is
//! rejected.

use alloy_primitives::{Address, Bytes, U256};

use crate::crypto::{BlackChainPrivateKey, BlackChainPublicKey};
use crate::dilithium::{PUBLIC_KEY_SIZE as DIL_PK, SIGNATURE_SIZE as DIL_SIG};
use crate::hdwallet::bip39::{seed_from_mnemonic, validate_mnemonic};
use crate::hdwallet::derivation::{
    derive_child_seed, derive_mdecc_curve_seed, CURVE_ID_ED448, CURVE_ID_P521,
};
use crate::mdecc::ed448::{PUBLIC_KEY_SIZE as ED448_PK, SIGNATURE_SIZE as ED448_SIG};
use crate::mdecc::p521::{P521PublicKey, PUBLIC_KEY_SIZE as P521_PK, SIGNATURE_SIZE as P521_SIG};
use crate::transaction::types::BlackChainTxType;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic wallet from a tag byte.
fn wallet(tag: u8) -> (BlackChainPrivateKey, BlackChainPublicKey) {
    let mut seed = [0u8; 64];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i as u8) ^ tag ^ 0x5a;
    }
    BlackChainPrivateKey::generate(&seed).unwrap()
}

fn sample_tx() -> BlackChainTxType {
    BlackChainTxType {
        chain_id: 1,
        nonce: 3,
        max_priority_fee_per_gas: U256::from(1_500_000_000u64),
        max_fee_per_gas: U256::from(30_000_000_000u64),
        gas_limit: 21_000,
        to: Some(Address::repeat_byte(0xaa)),
        value: U256::from(1_000_000u64),
        data: Bytes::from(vec![1, 2, 3, 4]),
        v: None,
        r: None,
        s: None,
        pqc_signature: None,
        pub_key: None,
    }
}

// Composite signature layout: [ML-DSA (DIL_SIG)] ‖ [P-521 (P521_SIG)] ‖ [Ed448 (ED448_SIG)]
fn p521_sig_range() -> std::ops::Range<usize> {
    DIL_SIG..DIL_SIG + P521_SIG
}
fn ed448_sig_range() -> std::ops::Range<usize> {
    DIL_SIG + P521_SIG..DIL_SIG + P521_SIG + ED448_SIG
}

/// Constructs the high-S malleability twin `(r, n - s)` of a low-S P-521
/// signature. Both are valid ECDSA signatures over the same message; only the
/// canonical (low-S) one must be accepted.
fn p521_high_s_twin(sig132: &[u8]) -> Vec<u8> {
    use p521::ecdsa::Signature;
    let s = Signature::from_slice(sig132).expect("valid P-521 signature");
    let neg_s = -s.s(); // NonZeroScalar negation == n - s
    let twin = Signature::from_scalars(s.r().to_bytes(), neg_s.to_bytes())
        .expect("negated-s signature is well-formed");
    twin.to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// A. Signature malleability
// ---------------------------------------------------------------------------

#[test]
fn attack_p521_high_s_twin_is_rejected() {
    let (pk, sk) = crate::mdecc::p521::generate_key().unwrap();
    let msg = b"malleability probe";
    let sig = sk.sign_msg(msg);

    // The canonical (low-S) signature verifies.
    assert!(pk.verify_sig(msg, &sig).is_ok());

    let twin = p521_high_s_twin(&sig);
    // Same r, negated s → a *different* but mathematically-valid ECDSA signature.
    assert_ne!(twin, sig, "twin must differ from the canonical signature");
    assert_eq!(twin[..66], sig[..66], "r component must be identical");
    assert_ne!(twin[66..], sig[66..], "s component must differ (n - s)");

    // The malleated high-S twin MUST be rejected.
    assert!(
        pk.verify_sig(msg, &twin).is_err(),
        "high-S malleability twin must be rejected"
    );
}

#[test]
fn attack_composite_message_p521_malleation_rejected() {
    let (sk, pk) = wallet(1);
    let msg = b"composite malleability";
    let mut composite = sk.sign_message(msg).unwrap();
    assert!(pk.verify_message(msg, &composite).unwrap());

    // Splice the P-521 high-S twin into the composite signature.
    let twin = p521_high_s_twin(&composite[p521_sig_range()]);
    composite[p521_sig_range()].copy_from_slice(&twin);

    assert!(
        pk.verify_message(msg, &composite).is_err(),
        "composite with malleated P-521 sub-signature must be rejected"
    );
}

#[test]
fn attack_transaction_p521_malleation_breaks_recovery() {
    let (sk, pk) = wallet(2);
    let expected = pk.derive_address();
    let mut tx = sample_tx();
    tx.sign_transaction(&sk).unwrap();
    assert_eq!(tx.recover_sender().unwrap(), expected);

    // Malleate the P-521 sub-signature inside the transaction.
    let mut comp = tx.pqc_signature.as_ref().unwrap().to_vec();
    let twin = p521_high_s_twin(&comp[p521_sig_range()]);
    comp[p521_sig_range()].copy_from_slice(&twin);
    tx.pqc_signature = Some(Bytes::from(comp));

    assert!(
        tx.recover_sender().is_err(),
        "malleated transaction must not recover a sender (txid malleability blocked)"
    );
}

#[test]
fn attack_ed448_noncanonical_s_rejected() {
    // A signature whose S scalar is encoded non-canonically (high byte / high
    // bits set, i.e. S >= L) must be rejected by the canonical decoder.
    let (sk, pk) = wallet(3);
    let msg = b"ed448 canonical probe";
    let base = sk.sign_message(msg).unwrap();
    assert!(pk.verify_message(msg, &base).unwrap());

    // Ed448 sub-sig = R(57) ‖ S(57); S's 57th byte is the last byte of the sig.
    for byte_idx in [56usize, 55] {
        let mut comp = base.clone();
        let ed = ed448_sig_range();
        let s_byte = ed.start + 57 + byte_idx; // into the S half
        comp[s_byte] |= 0xC0; // set the two top bits → non-canonical (S >= L)
        assert!(
            pk.verify_message(msg, &comp).is_err(),
            "non-canonical Ed448 S (byte {byte_idx}) must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// B. Splicing / cross-key mixing (entanglement)
// ---------------------------------------------------------------------------

#[test]
fn attack_splice_ed448_subsig_from_other_identity() {
    let (sk_a, pk_a) = wallet(10);
    let (sk_b, _pk_b) = wallet(11);
    let msg = b"splice probe";

    let comp_a = sk_a.sign_message(msg).unwrap();
    let comp_b = sk_b.sign_message(msg).unwrap();

    // Take A's signature, splice in B's Ed448 sub-signature.
    let mut spliced = comp_a.clone();
    spliced[ed448_sig_range()].copy_from_slice(&comp_b[ed448_sig_range()]);

    assert!(
        pk_a.verify_message(msg, &spliced).is_err(),
        "A's signature with B's Ed448 sub-signature must not verify under A"
    );
}

#[test]
fn attack_splice_mldsa_subsig_from_other_identity() {
    // The ML-DSA sub-signature must be bound to the signer's ML-DSA key.
    let (sk_a, pk_a) = wallet(12);
    let (sk_b, _pk_b) = wallet(13);
    let msg = b"mldsa binding probe";

    let comp_a = sk_a.sign_message(msg).unwrap();
    let comp_b = sk_b.sign_message(msg).unwrap();

    let mut spliced = comp_a.clone();
    spliced[..DIL_SIG].copy_from_slice(&comp_b[..DIL_SIG]);

    assert!(
        pk_a.verify_message(msg, &spliced).is_err(),
        "A's signature with B's ML-DSA sub-signature must not verify under A"
    );
}

#[test]
fn attack_frankenstein_pubkey_recovers_new_address_not_victim() {
    // Build a composite public key mixing A's ML-DSA key with B's P-521/Ed448
    // keys. It is a *valid* key bundle, but its address is a fresh address that
    // is neither A nor B, and A's signature must not verify against it.
    let (sk_a, pk_a) = wallet(20);
    let (_sk_b, pk_b) = wallet(21);

    let mut franken = Vec::new();
    franken.extend_from_slice(&pk_a.dilithium_bytes()[..DIL_PK]);
    franken.extend_from_slice(&pk_b.p521_bytes()[..P521_PK]);
    franken.extend_from_slice(&pk_b.ed448_bytes()[..ED448_PK]);
    let franken_pk = BlackChainPublicKey::from_bytes(&franken).unwrap();

    assert_ne!(franken_pk.derive_address(), pk_a.derive_address());
    assert_ne!(franken_pk.derive_address(), pk_b.derive_address());

    let msg = b"franken probe";
    let comp_a = sk_a.sign_message(msg).unwrap();
    assert!(
        franken_pk.verify_message(msg, &comp_a).is_err(),
        "A's signature must not verify under a spliced composite key"
    );
}

// ---------------------------------------------------------------------------
// C. Transaction / RLP tampering
// ---------------------------------------------------------------------------

#[test]
fn attack_tx_tamper_recipient_breaks_recovery() {
    let (sk, pk) = wallet(30);
    let signer = pk.derive_address();
    let mut tx = sample_tx();
    tx.sign_transaction(&sk).unwrap();
    assert_eq!(tx.recover_sender().unwrap(), signer);

    tx.to = Some(Address::repeat_byte(0xbb)); // redirect funds
    match tx.recover_sender() {
        Err(_) => {}
        Ok(addr) => assert_ne!(addr, signer, "tampered recipient must not recover signer"),
    }
}

#[test]
fn attack_tx_tamper_value_breaks_recovery() {
    let (sk, pk) = wallet(31);
    let signer = pk.derive_address();
    let mut tx = sample_tx();
    tx.sign_transaction(&sk).unwrap();

    tx.value = U256::from(999_999_999u64);
    match tx.recover_sender() {
        Err(_) => {}
        Ok(addr) => assert_ne!(addr, signer),
    }
}

#[test]
fn attack_tx_swapped_pubkey_rejected() {
    // Keep A's signature but claim B's public key: must not recover.
    let (sk_a, _pk_a) = wallet(32);
    let (_sk_b, pk_b) = wallet(33);
    let mut tx = sample_tx();
    tx.sign_transaction(&sk_a).unwrap();

    tx.pub_key = Some(Bytes::from(pk_b.to_bytes()));
    assert!(
        tx.recover_sender().is_err(),
        "A's signature under B's public key must not recover"
    );
}

#[test]
fn attack_rlp_trailing_bytes_rejected_via_decode() {
    use alloy_rlp::{Decodable, Encodable};
    let tx = sample_tx();
    let mut out = Vec::new();
    tx.encode(&mut out);
    out.extend_from_slice(&[0xde, 0xad]); // trailing junk

    let mut slice = out.as_slice();
    let decoded = BlackChainTxType::decode(&mut slice).unwrap();
    assert!(decoded.v.is_none(), "trailing bytes must not become signature fields");
    assert_eq!(slice, &[0xde, 0xad], "trailing bytes must be left unconsumed");
}

#[test]
fn attack_rlp_oversized_to_rejected() {
    use alloy_rlp::Decodable;
    // Hand-craft a list whose `to` field is 21 bytes (invalid; must be 0 or 20).
    // [chain_id=1, nonce=0, maxprio=0, maxfee=0, gas=0, to=<21 bytes>, value=0, data=0x]
    use alloy_rlp::Encodable;
    let mut body = Vec::new();
    1u64.encode(&mut body);
    0u64.encode(&mut body);
    U256::ZERO.encode(&mut body);
    U256::ZERO.encode(&mut body);
    0u64.encode(&mut body);
    Bytes::from(vec![0x11u8; 21]).encode(&mut body); // 21-byte "address"
    U256::ZERO.encode(&mut body);
    Bytes::new().encode(&mut body);

    let mut framed = Vec::new();
    alloy_rlp::Header { list: true, payload_length: body.len() }.encode(&mut framed);
    framed.extend_from_slice(&body);

    let mut slice = framed.as_slice();
    assert!(
        BlackChainTxType::decode(&mut slice).is_err(),
        "a 21-byte `to` field must be rejected"
    );
}

// ---------------------------------------------------------------------------
// D. Wallet / derivation
// ---------------------------------------------------------------------------

#[test]
fn attack_bip39_bad_checksum_rejected() {
    // 24 valid BIP-39 words but an invalid checksum: the all-zero entropy
    // mnemonic ends in "art", not "abandon", so 24×"abandon" fails the checksum.
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon \
               abandon abandon abandon abandon abandon abandon abandon abandon \
               abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(!validate_mnemonic(bad));
    assert!(seed_from_mnemonic(bad, "").is_err());
}

#[test]
fn attack_bip39_wrong_word_count_rejected() {
    let twelve = "abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon about";
    assert!(!validate_mnemonic(twelve));
    assert!(seed_from_mnemonic(twelve, "").is_err());
}

#[test]
fn attack_bip32_nonhardened_index_rejected() {
    let master = [7u8; 64];
    // A raw, non-hardened index (< 0x8000_0000) must be rejected.
    assert!(derive_child_seed(&master, &[0u32]).is_err());
    assert!(derive_child_seed(&master, &[44]).is_err());
    // Hardened is accepted.
    assert!(derive_child_seed(&master, &[0x8000_002Cu32]).is_ok());
}

#[test]
fn attack_short_seed_rejected() {
    assert!(BlackChainPrivateKey::generate(&[0u8; 32]).is_err());
    assert!(BlackChainPrivateKey::generate(&[0u8; 63]).is_err());
    assert!(BlackChainPrivateKey::generate(&[0u8; 64]).is_ok());
}

#[test]
fn attack_kdf_curve_domain_separation() {
    // The same mdECC master must yield independent per-curve seeds.
    let master = [0x33u8; 16];
    let p521_seed = derive_mdecc_curve_seed(&master, CURVE_ID_P521, 32).unwrap();
    let ed448_seed = derive_mdecc_curve_seed(&master, CURVE_ID_ED448, 32).unwrap();
    assert_ne!(
        p521_seed, ed448_seed,
        "curve-ID domain separation must make sub-seeds independent"
    );
}

// ---------------------------------------------------------------------------
// E. Degenerate / malformed keys
// ---------------------------------------------------------------------------

#[test]
fn attack_all_zero_composite_pubkey_rejected() {
    let zero = vec![0u8; DIL_PK + P521_PK + ED448_PK];
    assert!(
        BlackChainPublicKey::from_bytes(&zero).is_err(),
        "all-zero composite public key must be rejected (invalid P-521 / Ed448 point)"
    );
}

#[test]
fn attack_wrong_length_composite_pubkey_rejected() {
    let total = DIL_PK + P521_PK + ED448_PK;
    assert!(BlackChainPublicKey::from_bytes(&vec![0u8; total - 1]).is_err());
    assert!(BlackChainPublicKey::from_bytes(&vec![0u8; total + 1]).is_err());
}

#[test]
fn attack_all_zero_p521_pubkey_rejected() {
    assert!(P521PublicKey::from_bytes(&[0u8; P521_PK]).is_err());
}
