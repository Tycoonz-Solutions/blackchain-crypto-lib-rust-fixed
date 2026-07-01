# Changelog

All notable changes to this project will be documented in this file. This project adheres to Semantic Versioning.

## [0.1.0] - 2026-06-29

### Added
- **Hybrid Post-Quantum Cryptographic Suite**: Implemented composite key generation, signing, and recovery using Dilithium5 (post-quantum lattice), NIST P-521, and Curve Ed448.
- **BIP32 & BIP39 HD Wallet**: Integrated key derivation paths supporting standard 24-word seeds.
- **Safety Documentation**: Documented potential panic vectors on `dyn Scheme` and `TypedScheme` trait bounds.
- **Adversarial Testing Suite**: Added property-based verification using the `proptest` crate checking signature roundtrips, mutation resilience, cross-chain replay protection, and address determinism.
- **Production-Grade Fuzz Suite**: Expanded from basic targets to a 6-target suite (`fuzz_tx_decode`, `fuzz_pubkey_parse`, `fuzz_composite_sig_verify`, `fuzz_tx_sign_recover`, `fuzz_mnemonic_seed`, `fuzz_signature_hash`) utilizing `arbitrary` structured inputs and checking explicit validation invariants.
- **Production-Grade Benchmark Suite**: Enhanced `benches/latency.rs` to measure BIP-39 mnemonic setup, BIP-32 HD wallet path derivation, composite key serialization, transaction hashing, composite signature generation, sender recovery, and transaction payload scaling.
- **MSRV Policy**: Configured Minimum Supported Rust Version to `1.85.0` in `Cargo.toml`.
- **CI/CD Pipeline**: Configured GitHub Actions workflow for linting, testing, and dependency vulnerability audits via Cargo Audit.
- **Unsafe Code Ban**: Banned all unsafe blocks via root `#![forbid(unsafe_code)]` header.
- **Testing Documentation**: Created `FUZZING.md` with guidelines on target invariants, execution commands, and troubleshooting guides.
- **Developer API Wrapper Facade**: Introduced `src/api.rs` providing high-level helper functions for wallet creation, message signing/verification, and transaction signing/verification.
- **Core Key Signature Encapsulation**: Refactored the core message signing and verification routines directly into `BlackChainPrivateKey` and `BlackChainPublicKey` inside `src/crypto.rs` to ensure modularity and clean separation of concerns.
- **Visual Cryptographic Flows Documentation**: Created `docs/README.md` featuring Mermaid diagrams and mathematical step-by-step specifications for key generation and transaction verification pipelines.

### Fixed
- **mdECC Entropy Floor**: Fixed a cryptographic weakness where SHAKE256 seed derivation truncated output to 8 bytes (64 bits of entropy). Extended it to 32 bytes (256 bits).
- **Large Chain ID Overflow**: Fixed a panic in transaction serialization/signature recovery where large `chain_id` multiplication (`chain_id * 2 + 35`) overflowed `u64`.
- **Memory Zeroization UB**: Removed undefined behavior pointer-casting memory zeroization routines in Dilithium, P-521, and Ed448 key drops, replacing them with safe stack/heap overwrites and `Zeroize` traits.
- **Public Key Parser Checking**: Hardened `BlackChainPublicKey::from_bytes` to validate sub-key formats (on-curve checks for P-521/Ed448 and parsing validation for Dilithium5) to reject invalid key slices.
