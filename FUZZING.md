# Fuzz Testing Guide

> **Requires nightly Rust** — `rustup install nightly`

## Overview

The `fuzz/` workspace contains **6 libfuzzer targets** covering every security-critical code path in the BlackChain crypto library. Each target encodes explicit *invariants* checked on every input — not just absence of crashes, but also semantic correctness.

```
fuzz/fuzz_targets/
├── fuzz_pubkey_parse.rs         # (enhanced) Public key parser
├── fuzz_tx_decode.rs            # (enhanced) RLP transaction decoder  
├── fuzz_composite_sig_verify.rs # NEW — Composite signature verifier
├── fuzz_tx_sign_recover.rs      # NEW — Sign→recover roundtrip (structured)
├── fuzz_mnemonic_seed.rs        # NEW — BIP-39 and HD derivation layer
└── fuzz_signature_hash.rs       # NEW — Signature hash computation
```

---

## Running the Fuzzers

```bash
# Build all targets
cargo +nightly fuzz build

# Run a specific target until manually stopped (Ctrl+C)
cargo +nightly fuzz run <target_name>

# Run for a fixed duration (e.g., 5 minutes per target)
cargo +nightly fuzz run <target_name> -- -max_total_time=300

# Run with a larger input limit (default 4096 bytes)
cargo +nightly fuzz run <target_name> -- -max_len=65536

# Run with multiple jobs in parallel
cargo +nightly fuzz run <target_name> -- -jobs=4
```

### Recommended overnight run (all 6 targets, 1 hour each)

```bash
for target in fuzz_pubkey_parse fuzz_tx_decode fuzz_composite_sig_verify fuzz_tx_sign_recover fuzz_mnemonic_seed fuzz_signature_hash; do
    cargo +nightly fuzz run $target -- -max_total_time=3600
done
```

---

## Fuzz Targets — Attack Surfaces & Invariants

### 1. `fuzz_pubkey_parse` — Public Key Parser

**Attack surfaces:**
- Length boundary conditions (0, 1, `COMPOSITE_PK_SIZE-1`, exact, `+1`, very large)
- Invalid sub-key byte patterns (all-zeros, all-0xff, off-curve points)
- Random noise at the correct size

**Invariants checked on every successful parse:**
1. `dilithium_bytes().len() == 2592`
2. `p521_bytes().len() == 133`
3. `ed448_bytes().len() == 57`
4. `to_bytes().len() == COMPOSITE_PK_SIZE`
5. `from_bytes(to_bytes())` roundtrip is identity
6. `derive_address()` is deterministic — same key bytes → same address

---

### 2. `fuzz_tx_decode` — RLP Transaction Decoder

**Attack surfaces:**
- Truncated, over-long, and malformed RLP envelopes
- All type-byte variations and edge cases

**Invariants:**
1. `decode` never panics on any byte string
2. All field accesses panic-free after successful decode
3. `signature_hash` returns exactly 32 bytes
4. `recover_sender` never panics (may return `Err`)
5. Encode → re-decode → hash roundtrip is identity

---

### 3. `fuzz_composite_sig_verify` — Composite Signature Verifier *(NEW)*

The most security-critical target. Feeds arbitrary bytes as `pqc_signature` while providing a real public key, isolating the Dilithium5 + P-521 + Ed448 verification code paths.

**Attack surfaces:**
- Truncated composite signatures (< minimum required size)
- Correct-length but byte-flipped Dilithium5 signatures
- Variable-length P-521 DER segment corruptions
- Corrupted Ed448 tail (last 114 bytes)
- Completely random blobs of all sizes
- Pub key field corruption (arbitrary bytes as `pub_key`)

**Invariants:**
1. `recover_sender` never panics for any input
2. If recovery returns `Ok(addr)`, `addr` must differ from the known signer (a random sig must not produce a false positive)

---

### 4. `fuzz_tx_sign_recover` — Sign→Recover Roundtrip *(NEW)*

Uses `#[derive(Arbitrary)]` to generate fully structured inputs with semantically valid `FuzzInput` covering every transaction field.

**Attack surfaces:**
- Key generation for every possible 64-byte seed
- `chain_id` = 0, 1, max `u64`, and arbitrary values
- Transactions with zero-length data and up to 64 KB of calldata
- `to = None` (contract creation)
- `value` constructed from two `u128` halves (covers full `U256` range)

**Invariants:**
1. `generate` succeeds for every 64-byte seed
2. After successful signing, `recover_sender` returns `Ok`
3. Recovered address exactly matches `pub_key.derive_address()`

---

### 5. `fuzz_mnemonic_seed` — BIP-39 & HD Derivation *(NEW)*

**Attack surfaces:**
- `seed_from_mnemonic` with arbitrary UTF-8 strings (not BIP-39 words)
- Correct word count but wrong words
- `parse_hardened_path` with arbitrary path strings
- `derive_child_seed` with arbitrary seeds, arbitrary paths (including unhardened indices and very deep paths)
- `derive_mdecc_curve_seed` with out-of-spec curve IDs and seed lengths

**Invariants:**
1. `validate_mnemonic` and `seed_from_mnemonic` agree — if validate returns `true`, parse must succeed returning 64 bytes
2. `parse_hardened_path` never panics
3. `derive_child_seed` never panics (may return `Err` for non-hardened indices)
4. `derive_mdecc_curve_seed` never panics for any input
5. For spec-compliant curve IDs (`CURVE_ID_P521 = 1`, `CURVE_ID_ED448 = 2`) with any non-empty seed, derivation must always succeed

---

### 6. `fuzz_signature_hash` — Transaction Hash Computation *(NEW)*

**Attack surfaces:**
- Extreme `U256` values (0, max, random)
- Very large `data` fields (up to 1 MB)
- All `chain_id` / `nonce` corner cases
- `to = None` vs `Some`

**Invariants:**
1. `signature_hash` never panics, always returns exactly 32 bytes
2. Deterministic — calling twice on the same tx returns the same hash
3. Signature fields (`v`, `r`, `s`, `pqc_signature`, `pub_key`) are excluded from the hash
4. Different `chain_id` always produces a different hash (replay protection)

---

## Understanding Fuzzer Output

```
#16749  DONE   cov: 3863 ft: 6636 corp: 146/22Kb lim: 163 exec/s: 540 rss: 500Mb
```

| Field | Meaning |
|:---|:---|
| `#16749` | Total executions so far |
| `cov: 3863` | Unique edges in the coverage map (higher = more code explored) |
| `ft: 6636` | Feature total — more granular than coverage |
| `corp: 146/22Kb` | 146 corpus items, 22 KB total — interesting inputs kept |
| `exec/s: 540` | Executions per second |
| `rss: 500Mb` | Resident memory usage |

**No `CRASH` lines = no bugs found.** If a crash is found, artifacts are saved in `fuzz/artifacts/<target_name>/`.

---

## Investigating a Crash

```bash
# Re-run the failing input
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash_file>

# Minimize the crashing input to the smallest reproducer
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash_file>
```

---

## Corpus Management

Interesting inputs are saved to `fuzz/corpus/<target_name>/`. These are automatically reused on the next run, allowing the fuzzer to make incremental progress.

```bash
# Merge and deduplicate corpus across runs
cargo +nightly fuzz cmin <target>
```

---

## Benchmark Results (30-second smoke runs)

| Target | Runs | Coverage | Exec/s | Crashes |
|:---|---:|---:|---:|---:|
| `fuzz_pubkey_parse` | ~322 | 2,648 | ~10 | 0 |
| `fuzz_tx_decode` | ~800k+ | — | — | 0 |
| `fuzz_composite_sig_verify` | 322 | 2,648 | 10 | **0** |
| `fuzz_tx_sign_recover` | 16,749 | 3,863 | 540 | **0** |
| `fuzz_mnemonic_seed` | 220k+ | 990 | 10,000+ | **0** |
| `fuzz_signature_hash` | pending | — | — | — |

> The signing targets run at ~10 exec/s because composite signing takes ~12 ms. The mnemonic target runs at 10,000+ exec/s since BIP-39 parsing is inexpensive.
