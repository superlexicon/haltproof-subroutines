# Haltproof Subroutines (`haltproof-subroutines` / `hps`)

`haltproof-subroutines` is the official developer toolkit and reference suite for authoring, unit-testing, compiling, optimizing, deploying, and invoking **WebAssembly (`Wasmtime`) Haltproof Subroutines (HPS)** on **Lexicon** — both against a 1-node `lexicon-node --localtestnet` and against live multi-validator FLRC radio subnets.

Zero C++/RocksDB dependencies are required to build Haltproof Subroutines or run `cargo hps`.

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| `crates/hps-sdk/` | `#![no_std]` guest Rust SDK for `wasm32-unknown-unknown` Haltproof Subroutines. Wraps persistent state (`storage`), execution context (`context::msg_sender`, `context::self_address`, `context::block_number`), synchronous cross-HPS calls (`call`), ABI calldata decoding/encoding (`abi`, `call::CallEncoder`), structured return payloads (`ret`), event logs (`events`), compile-time `selector()` / `event_topic()`, `hps_entry!`, and a multi-HPS native `mock` host so `cargo test` runs in milliseconds. |
| `crates/hps-client/` | Pure-Rust client library implementing Lexicon's 10-field EIP-155 RLP transaction signing (including multi-HPS `target_addresses`), 1-call 2-step WASM deployment (`deploy_hps`), human-readable ABI call encoding, `read_call` (`eth_call`) queries, and cross-subnet `subnet_sendTransaction`. |
| `crates/cargo-hps/` | Developer CLI (`cargo hps` / `cargo-hps`): scaffolds new Haltproof Subroutines (`new`), compiles & strips WASM zero-data segments (`build`), deploys in 1 command (`deploy`), submits stateful single- or multi-HPS invocations (`send` / `--touch`), executes instant read queries (`call`), and manages keys (`keygen`). |
| `examples/counter-registry/` | Starter reference HPS (`4.7 KB` WASM) demonstrating counters, dynamic string storage, indexed events, read calls, and native unit tests. |
| `examples/messaging/` | High-TPS channel messaging HPS (`4.4 KB` WASM) 100% ABI-, storage-key-, event-, and wire-compatible with Lexicon's maximum-TPS benchmark (`postMessage(bytes32,bytes)`, `getMessages(bytes32,uint64)`, `MessagePosted` event). |
| `examples/asset-ledger/` | Fungible Asset Ledger HPS (`6.9 KB` WASM) tracking balances (`balanceOf`, `mint`, `transfer`) and debit allowances (`approve`, `allowance`, `transferFrom`) across EOA and Identity HPS holders. |
| `examples/identity/` | On-chain Identity HPS (`9.3 KB` WASM) whose 20-byte HPS address holds asset balances in `asset-ledger` instances and executes owner-/delegate-authorized actions (`approveAsset`, `transferAsset`, `execute`). |
| `examples/asset-pair-otc/` | `AssetPair_OTC` HPS (`14.0 KB` WASM) pairing a Base Asset Ledger and a Quote Asset Ledger: lets the contract owner place item ask/sell orders (`placeAskOrder`) and lets buyers fill orders at the prevailing price (`buyOrderWithIdentity` / `buyOrder`) via atomic dual-ledger `transferFrom` settlement after authorizing debit of their Quote Asset balance. |
| `ts-client/` | JavaScript / TypeScript client helper (`hps.mjs` + `hps.d.ts`) implementing Lexicon's 10-field RLP transaction signing (`extraTargets` supported) and 2-step WASM HPS deployment for web & SuperLexicon frontends. |
| [`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md) | Step-by-step **End-to-End Haltproof Subroutine (HPS) & App Developer Guide**, including full CLI walkthroughs for single- and multi-HPS (`Identity` + `AssetLedger` + `AssetPair_OTC`) workflows. |

---

## Sample Haltproof Subroutines Overview

### 1. High-TPS Messaging (`examples/messaging`)
The exact channel-indexed, per-block-grouped messaging subroutine used to benchmark Lexicon's maximum transaction throughput:
- `postMessage(bytes32 channelHash, bytes message)` (`0x482f63b0`) — appends `[sender(20) || message]` to `(channelHash, blockNumber)` and emits `MessagePosted(bytes32,uint64,address,bytes)`.
- `getMessages(bytes32 channelHash, uint64 blockNumber)` (`0xa8c9582d`) — returns `[u64 LE count][sender(20) || u64 LE len || bytes]*`.

### 2. Asset Ledger (`examples/asset-ledger`)
Tracks balances and delegated debit allowances for any fungible asset (e.g., `GOLD`, `USD`, points, or inventory units):
- `initialize(address issuer, string symbol, uint64 decimals)`
- `mint(address to, uint64 amount)` (issuer-only)
- `transfer(address to, uint64 amount)`
- `approve(address spender, uint64 amount)` & `transferFrom(address from, address to, uint64 amount)`
- `balanceOf(address holder)`, `allowance(address owner, address spender)`, `totalSupply()`, `symbol()`, `decimals()`, `issuer()`

### 3. Identity (`examples/identity`)
Programmable on-chain identity / vault whose own 20-byte HPS address holds balances inside `AssetLedger` subroutines:
- `initialize(address owner, string label)`
- `setDelegate(address delegate, bool enabled)` & `transferOwnership(address newOwner)`
- `approveAsset(address ledger, address spender, uint64 amount)` — cross-HPS calls `ledger.approve(spender, amount)` with `msg.sender = Identity`
- `transferAsset(address ledger, address to, uint64 amount)` — cross-HPS calls `ledger.transfer(to, amount)` with `msg.sender = Identity`
- `execute(address target, bytes data)` — general owner/delegate call forwarding
- `isAuthorized(address account)`, `owner()`, `label()`, `nonce()`

### 4. AssetPair OTC (`examples/asset-pair-otc`)
Atomic Over-The-Counter ask-book & settlement subroutine pairing a **Base Asset Ledger** and a **Quote Asset Ledger**:
1. **Pair Ledgers**: `initialize(address owner, address sellerIdentity, address baseLedger, address quoteLedger)`
2. **Place Ask Orders**: `placeAskOrder(bytes32 itemId, uint64 baseQuantity, uint64 unitPriceQuote)` (owner or `sellerIdentity` controller) — lists `baseQuantity` units of Base Asset for `itemId` at `unitPriceQuote` Quote units per Base unit (verifying `sellerIdentity` balance & allowance on `baseLedger`). Also supports `updateAskPrice` and `cancelAskOrder`.
3. **Authorize & Buy at Prevailing Price**:
   - Buyer first authorizes debit of `quoteCost = baseQuantity * unitPriceQuote` on `quoteLedger` via `BuyerIdentity.approveAsset(quoteLedger, otcAddress, quoteCost)`.
   - Buyer calls `buyOrderWithIdentity(bytes32 itemId, address buyerIdentity, uint64 baseQuantity)` (or `buyOrder(bytes32,uint64)` when invoked via `BuyerIdentity.execute` or direct EOA).
   - `AssetPair_OTC` verifies caller authorization on `BuyerIdentity`, then **atomically** debits `quoteCost` from `BuyerIdentity` -> credits `sellerIdentity` in `quoteLedger` **and** debits `baseQuantity` from `sellerIdentity` -> credits `BuyerIdentity` in `baseLedger`. Any insufficient allowance or balance reverts the entire transaction cleanly.

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

### 2. Run All Native Unit Tests (Single & Multi-HPS Simulator)

```bash
cargo test --workspace
```

### 3. Build All 5 Reference Haltproof Subroutines

```bash
cargo hps build -p counter-registry
cargo hps build -p messaging
cargo hps build -p asset-ledger
cargo hps build -p identity
cargo hps build -p asset-pair-otc
```

### 4. Start a 1-Node Local Testnet & Deploy

In Terminal 1:

```bash
lexicon-node --localtestnet
```

In Terminal 2:

```bash
cargo hps deploy dist/messaging.wasm --save msg.json
MSG=$(jq -r .hps_address msg.json)

# Post a message to channel keccak256("alpha") and read it back
cargo hps send "$MSG" "postMessage(bytes32,bytes)" "keccak:alpha" "0x48656c6c6f"
```

---

## Full End-to-End Developer Guide

See **[`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md)** for the complete walkthrough covering:
1. Authoring single- and multi-contract Haltproof Subroutines with `hps-sdk` (`storage`, `context`, `call`, `events`, `ret`)
2. Step-by-step live deployment & settlement walkthrough for **`Identity` + Dual `AssetLedger` + `AssetPair_OTC`**
3. How `cargo hps build` optimizes WASM bytecode (`4–14 KB`) for low-bandwidth radio subnets
4. Connecting a Rust backend (`hps-client`) or Web/TypeScript frontend (`ts-client/hps.mjs` + WebSocket `logs`)
5. Moving from `--localtestnet` to a multi-node Semtech LR2021 FLRC radio subnet
