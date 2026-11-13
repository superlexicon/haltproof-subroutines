# Haltproof Subroutines (`haltproof-subroutines` / `hps`)

`haltproof-subroutines` is the official developer toolkit for authoring, unit-testing, compiling, optimizing, deploying, and invoking **WebAssembly (`Wasmtime`) Haltproof Subroutines (HPS)** on **Lexicon** — both against a 1-node `lexicon-node --localtestnet` and against live multi-validator FLRC radio subnets.

Zero C++/RocksDB dependencies are required to build Haltproof Subroutines or run `cargo hps`.

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| `crates/hps-sdk/` | `#![no_std]` guest Rust SDK for `wasm32-unknown-unknown` Haltproof Subroutines. Wraps persistent state (`storage`), execution context (`context`), ABI calldata decoding (`abi`), structured return values (`ret`), event logs (`events`), compile-time `selector()` / `event_topic()`, `hps_entry!`, and a native `mock` host so `cargo test` runs in milliseconds. |
| `crates/hps-client/` | Pure-Rust client library implementing Lexicon's 10-field EIP-155 RLP transaction signing, 1-call 2-step WASM deployment (`deploy_hps`), human-readable ABI call encoding, `read_call` (`eth_call`) queries, and cross-subnet `subnet_sendTransaction`. |
| `crates/cargo-hps/` | Developer CLI (`cargo hps` / `cargo-hps`): scaffolds new Haltproof Subroutines (`new`), compiles & strips WASM zero-data segments (`build`), deploys in 1 command (`deploy`), submits stateful invocations (`send`), executes instant read queries (`call`), and manages keys (`keygen`). |
| `examples/counter-registry/` | Complete reference Haltproof Subroutine demonstrating counters, dynamic string storage, indexed events, read calls, and native unit tests. |
| `ts-client/` | JavaScript / TypeScript client helper (`hps.mjs` + `hps.d.ts`) implementing Lexicon's 10-field RLP transaction signing and 2-step WASM HPS deployment for web & SuperLexicon frontends. |
| [`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md) | Step-by-step **End-to-End Haltproof Subroutine (HPS) & App Developer Guide** from zero to live subnet deployment. |

---

## 60-Second Quickstart

### 1. Prerequisites

Install the prebuilt [`lexicon-node`](https://github.com/superlexicon/lexicon-bin) binary and the `cargo hps` CLI:

```bash
# Install lexicon-node -> ~/.local/bin/lexicon-node
git clone https://github.com/superlexicon/lexicon-bin.git
(cd lexicon-bin && bash install.sh)

# Install WASM target & cargo-hps
rustup target add wasm32-unknown-unknown
cargo install --path crates/cargo-hps
```

### 2. Start a 1-Node Local Testnet (No Radios Required)

In Terminal 1, start `lexicon-node` in `--localtestnet` mode (confirms blocks every **4 seconds**, executes Haltproof Subroutines in Wasmtime, and persists world state to `localtestnet.db`):

```bash
lexicon-node --localtestnet
```

### 3. Build & Deploy the Example Haltproof Subroutine

In Terminal 2:

```bash
# 1. Run native unit tests (in-memory mock host, < 0.1s)
cargo test -p counter-registry

# 2. Compile to WASM, strip zero-filled data segments, and validate Wasmtime ABI
cargo hps build -p counter-registry

# 3. Deploy to --localtestnet (runs Step 1 store_bytecode + Step 2 instantiate in one 4s block)
cargo hps deploy dist/counter_registry.wasm --save deployment.json
```

### 4. Invoke Methods & Query State

```bash
HPS=$(jq -r .hps_address deployment.json)

# Increment counter "alpha" by 42 (confirmed in <= 4s, zero balance required)
cargo hps send "$HPS" "increment(bytes32,uint64)" "alpha" 42

# Read counter "alpha" via read-only call (instant, 0 blocks)
cargo hps call "$HPS" "getCount(bytes32)" "alpha"

# Store a UTF-8 note under "alpha" and read it back
cargo hps send "$HPS" "setNote(bytes32,string)" "alpha" "Hello from Haltproof Subroutines!"
cargo hps call "$HPS" "getNote(bytes32)" "alpha"
```

### 5. Scaffold Your Own Haltproof Subroutine

```bash
cargo hps new my-app-hps
cd my-app-hps
cargo test
cargo hps build
cargo hps deploy dist/my_app_hps.wasm
```

---

## Full End-to-End Developer Guide

See **[`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md)** for the complete walkthrough covering:
1. Authoring Haltproof Subroutines with `hps-sdk` (storage keys, ABI types, events, fuel/slot limits)
2. How `cargo hps build` optimizes WASM bytecode for low-bandwidth radio subnets
3. How Lexicon's 2-step content-addressed deployment (`0x000...0100` + `instantiate`) works under the hood
4. Connecting a Rust backend (`hps-client`) or Web/TypeScript frontend (`ts-client/hps.mjs` + WebSocket `logs`)
5. Moving from `--localtestnet` to a multi-node Semtech LR2021 FLRC radio subnet
