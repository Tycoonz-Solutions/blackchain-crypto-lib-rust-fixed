# BlackChain Cryptographic Library (Rust)

A post-quantum hybrid cryptographic library implemented in Rust, designed for the BlackChain blockchain protocol. This library combines post-quantum lattice-based signature schemes with classical elliptic curves.

> [!IMPORTANT]
> This library enforces a strict security policy designed for post-quantum resistance:
> 1. **24-word (256-bit entropy)** mnemonics only. 12-word mnemonics are explicitly rejected.
> 2. **Hardened-only BIP-32** HD wallet key derivation to prevent public key exposure attacks.
> 3. **Zeroizing memory management** to automatically scrub private keys and root seeds from heap memory when dropped.

---

## Architecture & Features

This library implements a composite, three-algorithm hybrid signature scheme:
- **Post-Quantum Signature**: Dilithium5 (lattice-based, from crystals-dilithium).
- **Classical Signature 1**: NIST P-521 ECDSA (from the p521 crate).
- **Classical Signature 2**: Twisted Edwards Ed448 (from standard implementation).

The composite public/private keys contain material from all three schemes, making the scheme secure as long as at least one of the underlying algorithms remains unbroken.

---

## Directory & File Breakdown

### Root Directory
- [Cargo.toml](Cargo.toml) — Package configuration and dependencies.
- [README.md](README.md) — This documentation file.

### Source Directory (`src/`)

- [src/lib.rs](src/lib.rs) — Entry point of the library. Exposes public modules and exports primary types, errors, key structures, and transaction APIs.
- [src/error.rs](src/error.rs) — Defines the [CryptoError](src/error.rs#L4-L28) enum using the `thiserror` crate, handling RLP errors, BIP-39 parser errors, key size validation mismatches, and signature failures.
- [src/crypto.rs](src/crypto.rs) — Implements composite key containers:
  - [BlackChainPublicKey](src/crypto.rs#L55-L64): A concatenation of Dilithium5, P-521, and Ed448 public keys (Total size: 2,782 bytes).
  - [BlackChainPrivateKey](src/crypto.rs#L135-L153): Private key structure matching the composite key layout. Retains the original 64-byte BIP-39 seed for BIP32 derivation. Both types support secure memory zeroization.
- [src/sign.rs](src/sign.rs) — Defines the signature package design, including the [PublicKey](src/sign.rs#L93-L123), [PrivateKey](src/sign.rs#L125-L166), and [Scheme](src/sign.rs#L168-L290) traits, along with concrete counterparts ([TypedScheme](src/sign.rs#L301-L337)) for type-safe and dynamic signature dispatch.

#### Modules

##### 1. Post-Quantum Cryptography (`src/dilithium/`)
- [src/dilithium/mod.rs](src/dilithium/mod.rs) — Implements Dilithium5 signature bindings, wrapping `crystals-dilithium`. Provides pack/unpack, sign, verify, and seed key generation mechanisms.

##### 2. Multi-Curve Elliptic Curve Cryptography (`src/mdecc/`)
- [src/mdecc/mod.rs](src/mdecc/mod.rs) — Exports classic multi-curve schemes: Ed448 and NIST P-521.
- [src/mdecc/ed448.rs](src/mdecc/ed448.rs) — Implements the Ed448 twisted Edwards curve scheme, containing serialization, signing, verification, and seed derivation.
- [src/mdecc/p521.rs](src/mdecc/p521.rs) — NIST P-521 ECDSA signature wrapper utilizing the `p521` and `ecdsa` crates.

##### 3. HD Wallets (`src/hdwallet/`)
- [src/hdwallet/mod.rs](src/hdwallet/mod.rs) — Exports BIP-39 and child key derivation functions.
- [src/hdwallet/bip39.rs](src/hdwallet/bip39.rs) — Handles generation, validation, and seed extraction for 24-word mnemonics, enforcing 256-bit entropy constraints.
- [src/hdwallet/derivation.rs](src/hdwallet/derivation.rs) — Implements HD key derivation:
  - BIP32 child key derivation (`derive_child_seed`) accepting only hardened indices.
  - Per-curve seed derivation (`derive_mdecc_curve_seed`) from the mdECC master seed using SHAKE256 domain separation and HKDF-SHA3-512 expansion.
  - BIP32 path string parser (`parse_hardened_path`).

##### 4. Transactions (`src/transaction/`)
- [src/transaction/mod.rs](src/transaction/mod.rs) — Exports transaction structures and signing functions.
- [src/transaction/types.rs](src/transaction/types.rs) — Defines the custom transaction type [BlackChainTxType](src/transaction/types.rs#L21-L45) representing EIP-style transactions with fee parameters and signature/pubkey placeholders.
- [src/transaction/rlp.rs](src/transaction/rlp.rs) — RLP (Recursive Length Prefix) encoder and decoder implementations for `BlackChainTxType`.
- [src/transaction/signing.rs](src/transaction/signing.rs) — Handles:
  - Transaction signing: generates entanglement nonces, binding hashes (`H_combined`), computes signatures on all three schemes, and encodes them.
  - Sender recovery: verifies all signatures and derives the sender's address from verified composite public keys.

##### 5. Binaries & Test Tools (`src/bin/`)
- [src/bin/demo.rs](src/bin/demo.rs) — Showcase binary displaying the complete step-by-step cryptographic execution flow with logging outputs.
- [src/bin/test_dilithium.rs](src/bin/test_dilithium.rs) — Standard utility to run standalone tests/verification for the Dilithium5 scheme.
- [src/bin/test_ed448.rs](src/bin/test_ed448.rs) — Command-line utility to sign and verify payloads using the Ed448 scheme.
- [src/bin/test_verify_roundtrip.rs](src/bin/test_verify_roundtrip.rs) — Integration utility testing key generation, signing, and verification workflows.

---

## Cryptographic Specification & Protocols

### 1. Root Seed Partitioning
When deriving composite keys from a 64-byte BIP-39 root seed, the bytes are structured as follows:
- `seed[0..32]` (32 B)  → Dilithium5 Master Seed.
- `seed[32..48]` (16 B) → mdECC Master Seed (produces independent curve seeds).
- `seed[48..64]` (16 B) → Chain Code (reserved).

### 2. mdECC Per-Curve Seed Derivation
To guarantee cryptographic independence across classical curves, each curve's private seed is derived from the common mdECC master seed:
1. `shaken = SHAKE256(mdECC_seed ‖ curve_id)[0..8]`
2. `output_seed = HKDF-SHA3-512(IKM = shaken, salt = ∅, info = ∅)[0..seed_size]`
*Note: `curve_id = 1` for P-521, and `curve_id = 2` for Ed448.*

### 3. Transaction Signing & Binding Protocol
The transaction signature employs a cross-algorithm entanglement hash (`H_combined`) to prevent signature reuse or splicing across schemes:
1. **Entanglement Nonce**:
   `entg_nonce = SHAKE256("entangle" ‖ ALGO_ID ‖ VERSION ‖ address)[0..16]`
2. **H_combined**:
   `h_combined = SHAKE256(dil_pk ‖ p521_pk ‖ ed448_pk ‖ entg_nonce)[0..32]`
3. **Signing Hash**:
   Let `H` be the Keccak256 hash of the transaction RLP representation.
   - **Dilithium5**: Signs `H` raw.
   - **P-521 ECDSA**: Signs `H ‖ h_combined ‖ curve_id(1)`.
   - **Ed448**: Signs `H ‖ h_combined ‖ curve_id(2)`.
4. **Assembly**:
   `pqc_signature = dil_sig ‖ p521_sig ‖ ed448_sig`.

---

## Developer Guide

### Prerequisites
Make sure you have Cargo and Rust installed. This library uses Rust edition 2024. Make sure you have Rust 1.85 or later installed.

### Build & Run Tests
To compile the library:
```bash
cargo build
```

To run the complete step-by-step execution demo showing all keys, addresses, transactions, signatures, and recoveries:
```bash
cargo run --bin demo
```

To run the complete test suite (93 tests covering key derivation, transaction signing, and serialization):
```bash
cargo test
```
