# WebAssembly build (browser wallet extension)

The crate compiles to `wasm32-unknown-unknown` and ships a JS-callable API for a
browser wallet extension. WASM support is **target-gated**: native builds and
`cargo test` are unaffected.

## What's wired up

- `src/wasm.rs` — `wasm-bindgen` bindings (compiled only on `wasm32`).
- `Cargo.toml` — `crate-type = ["cdylib", "rlib"]`, plus wasm-only deps
  (`wasm-bindgen`, `serde_json`) and the browser RNG backends
  (`getrandom` 0.2 `js` + 0.4 `wasm_js`).
- `.cargo/config.toml` — sets `--cfg getrandom_backend="wasm_js"` for wasm only.

Randomness on wasm comes from the host `crypto.getRandomValues` (a CSPRNG), so
key generation quality matches native.

## Build

One-time tooling:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack        # or: cargo install wasm-bindgen-cli
```

Produce the browser package (`.wasm` + JS glue in `pkg/`):

```sh
wasm-pack build --target web --release
```

(The `getrandom_backend` flag is already supplied by `.cargo/config.toml`; no
extra `RUSTFLAGS` needed.)

## JS API

```js
import init, {
  BlackWallet, verifyMessage, recoverSender, validateMnemonic,
} from "./pkg/blackchain_crypto_lib_rust.js";

await init();

// Create a new wallet (show mnemonic once, then store it ENCRYPTED at rest).
const wallet = BlackWallet.create("");         // "" = no BIP-39 passphrase
const phrase = wallet.mnemonic();              // 24 words — back up
const address = wallet.address();              // "0x…"
const pub = wallet.publicKey();                // Uint8Array (composite pubkey)

// Sign / verify an arbitrary message.
const msg = new TextEncoder().encode("login challenge");
const sig = wallet.signMessage(msg);           // Uint8Array
const ok  = verifyMessage(msg, sig, pub);      // true

// Restore later (unlock/import).
const same = BlackWallet.fromMnemonic(phrase, "");

// Sign a transaction (JSON matches BlackChainTxType's serde shape).
const signedJson = wallet.signTransaction(JSON.stringify({
  chain_id: 1, nonce: 0,
  max_priority_fee_per_gas: "0x59682f00",
  max_fee_per_gas: "0x6fc23ac00",
  gas_limit: 21000,
  to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  value: "0xde0b6b3a7640000",
  data: "0x01020304",
  v: null, r: null, s: null, pqc_signature: null, pub_key: null,
}));
const sender = recoverSender(signedJson);      // "0x…" (== address)

wallet.free();                                 // drop key material on lock
```

## Security notes for extension authors

- JS never receives private-key bytes — only the mnemonic (for user backup),
  the address, the public key, and signatures. Do not add getters for private
  material.
- A wallet is defined by its mnemonic. Persist it **encrypted** (e.g. WebCrypto
  AES-GCM keyed from the user's unlock password); never plaintext
  `localStorage`. Reconstruct with `BlackWallet.fromMnemonic` on unlock.
- wasm linear memory is not a secure enclave and can't be reliably zeroized from
  JS; call `wallet.free()` when locking and treat the unlocked wallet as
  sensitive.
- Run signing in the extension's background/service-worker context, not in a
  page/content script, to keep key material off web-page origins.
