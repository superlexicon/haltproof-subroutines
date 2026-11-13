# End-to-End Haltproof Subroutine (HPS) & App Developer Guide

This guide walks through developing, testing, compiling, deploying, and integrating **Haltproof Subroutine-driven applications** on Lexicon using `haltproof-subroutines` (`cargo hps`) and `lexicon-node --localtestnet` — from single-subroutine state machines to composable multi-HPS workflows (`Identity` + `AssetLedger` + `AssetPair_OTC`).

---

## 1. Architecture Overview: Why "Haltproof Subroutines" (HPS)?

Lexicon models replicated on-chain programs as **Haltproof Subroutines (HPS)** — deterministic, fuel-bounded state-transition subroutines replicated across ISP-independent broadcast radio subnets that neither hang individual nodes nor depend on centralized cloud infrastructure or token fee markets:

1. **Deterministic, Fuel-Bounded WASM Execution**: Written in `#![no_std]` Rust using `hps-sdk` and compiled to WebAssembly (`wasm32-unknown-unknown`) executed by Lexicon's **Wasmtime** VM (`1 fuel = 1 gas`, strictly bounded per call so every invocation is guaranteed to terminate cleanly).
2. **Synchronous Cross-HPS Calls & Atomic Rollback**: Subroutines can invoke other deployed subroutines synchronously via `hps_sdk::call` (`host_call_contract`, up to depth `8`), sharing the transaction's fuel budget with automatic state rollback if any nested or top-level call returns `< 0` or traps.
3. **Zero-Fee Operations (No Token Balance Required)**: Users and apps never need native tokens to deploy or invoke Haltproof Subroutines. Spam is bounded structurally via per-transaction fuel caps (`10,000,000` gas), per-account nonce horizons, and physical RF TDMA/LBT rules.
4. **2-Step Content-Addressed Deployment**:
   - **Step 1 (`store_bytecode`)**: Uploads `[32-byte keccak256(wasm)] || [wasm]` to `0x0000000000000000000000000000000000000100`.
   - **Step 2 (`instantiate`)**: Sends `to = null` with `[32-byte code_hash] || [init_args]`, binding an HPS instance at `keccak256(rlp(sender, nonce))[12:]`.
   - `cargo hps deploy`, `HpsClient::deploy_hps`, and `HpsRpcClient.deployHps` execute **both steps automatically in a single call** (confirming together in a single 4-second block on `--localtestnet`).
5. **Local vs Subnet Parity**: `lexicon-node --localtestnet` runs the exact same JSON-RPC, WebSocket, `LayeredMempool`, `WasmtimeAdapter`, `NetworkState`, and RocksDB `FlatKvDb` storage as a live multi-validator radio subnet — simply replacing over-the-air TDMA rounds with a 1-node 4-second block timer.

---

## 2. Environment Setup

```bash
# 1. Install the prebuilt `lexicon-node` binary (from superlexicon/lexicon-bin)
git clone https://github.com/superlexicon/lexicon-bin.git
(cd lexicon-bin && bash install.sh)

# 2. Ensure the Rust WASM target is installed
rustup target add wasm32-unknown-unknown

# 3. Install the `cargo hps` CLI from this repository
cd /path/to/haltproof-subroutines
cargo install --path crates/cargo-hps
```

Verify the CLI is installed:

```bash
cargo hps --help
```

---

## 3. Running a Local Testnet (`--localtestnet`)

Start a standalone 1-node chain (no radios, no config file required):

```bash
# Default DB at ./localtestnet.db, HTTP JSON-RPC on 127.0.0.1:8545, WebSocket on 127.0.0.1:8546
lexicon-node --localtestnet

# Or specify an isolated database path for clean test runs:
lexicon-node --localtestnet --db-path /tmp/my-app-dev.db
```

In a second terminal, check node status:

```bash
cargo hps status
```

---

## 4. Scaffolding & Authoring a Haltproof Subroutine (HPS)

Scaffold a new project:

```bash
cargo hps new task-board
cd task-board
```

### Anatomy of an HPS (`src/main.rs`)

```rust
#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// Compile-time 32-byte Keccak-256 event topic hash
const COUNT_UPDATED: [u8; 32] = event_topic("CountUpdated(bytes32,address,uint64)");

// Auto-generates WASM `main`, `#![no_std]` panic handler, and 4-byte selector dispatch
hps_entry! {
    "increment(bytes32,uint64)" => handle_increment,
    "getCount(bytes32)"         => handle_get_count,
}

fn handle_increment(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let delta  = args.u64(1).ok_or(-3)?;
    let sender = context::msg_sender();

    let key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    let next = storage::get_u64(key.as_slice()).saturating_add(delta);
    storage::set_u64(key.as_slice(), next);

    let mut log_data = [0u8; 28];
    log_data[0..20].copy_from_slice(&sender);
    log_data[20..28].copy_from_slice(&next.to_be_bytes());
    events::emit(&[COUNT_UPDATED, bucket], &log_data);

    ret::write_u64_word(next);
    Ok(())
}

fn handle_get_count(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    ret::write_u64_word(storage::get_u64(key.as_slice()));
    Ok(())
}
```

### SDK Reference Cheat Sheet

| Module | Function | Purpose |
| :--- | :--- | :--- |
| `hps_sdk` | `selector("fn(type1,type2)")` | `const fn` 4-byte function selector |
| `hps_sdk` | `event_topic("Ev(type1,type2)")` | `const fn` 32-byte `topic[0]` hash |
| `context` | `context::msg_sender() -> [u8; 20]` | Immediate caller (`EOA` for top-level tx, or calling HPS address during a cross-HPS subcall) |
| `context` | `context::self_address() -> [u8; 20]` | 20-byte address of the currently executing HPS instance |
| `context` | `context::block_number() -> u64` | Current chain block height |
| `storage` | `storage::get_u64(k)` / `set_u64(k, v)` | Read/write `u64` counters (`0` if unset) |
| `storage` | `storage::get_address(k)` / `set_address(k, a)` | Read/write 20-byte addresses |
| `storage` | `storage::get_ref(k)` / `set(k, bytes)` | Read/write arbitrary byte slices (`set(k, &[])` deletes) |
| `storage` | `storage::exists(k) -> bool` | Check if a storage key is non-empty |
| `call` | `CallEncoder::<CAP>::new(sel)` | Encode fixed-word cross-HPS ABI calldata (`push_address`, `push_u64`, `push_bytes32`, `push_bool`) |
| `call` | `call::call_raw`, `call_u64`, `call_bool` | Synchronously invoke another HPS (`msg.sender` inside target becomes `self_address()`) |
| `abi` | `args.bytes32(i)`, `args.u64(i)`, `args.address(i)`, `args.bool(i)`, `args.dynamic_bytes(i)` | Bounds-checked ABI argument decoders safe on 32-bit WASM |
| `ret` | `ret::write_u64_word(v)`, `write_bool(b)`, `write_address(a)`, `write_abi_bytes(b)`, `write(raw)` | Populate `RETURN_BUF` (`0x70000`) for read calls and parent cross-HPS callers |
| `events` | `events::emit(&[topic0, ...], &data)` | Emit indexed receipt logs (`<= 4` topics) |

---

## 5. Multi-HPS Composition Walkthrough: `Identity` + `AssetLedger` + `AssetPair_OTC`

This repository ships five production-grade reference Haltproof Subroutines in `examples/`:
1. **`examples/counter-registry`** — Keyed counters & notes (`4.7 KB`).
2. **`examples/messaging`** — High-TPS channel messaging matching Lexicon's throughput benchmark (`4.4 KB`).
3. **`examples/asset-ledger`** — Fungible Asset Ledger with balances & allowances (`6.9 KB`).
4. **`examples/identity`** — Programmable Identity subroutine that holds balances in Asset Ledgers (`9.3 KB`).
5. **`examples/asset-pair-otc`** — Atomic Over-The-Counter ask-book & settlement subroutine pairing a Base Asset and Quote Asset (`14.0 KB`).

### Declaring Touched Subroutines (`--touch`)
Lexicon's 10-field transaction format includes a `target_addresses` list (`field #10`) enabling deterministic conflict detection in `LayeredMempool`. Whenever a transaction triggers cross-HPS calls, pass `--touch <address>` on the CLI (or `send_call_with_targets` in Rust / `extraTargets` in JS) for the additional subroutines touched by the call:

```bash
# Build the suite
cargo hps build -p asset-ledger
cargo hps build -p identity
cargo hps build -p asset-pair-otc

# 1. Generate Owner (Seller) and Buyer keys
OWNER_ADDR=$(cargo hps keygen --dev | awk '/Address/ {print $3}')
BUYER_OUT=$(cargo hps keygen)
BUYER_ADDR=$(echo "$BUYER_OUT" | awk '/Address/ {print $3}')
BUYER_KEY=$(echo "$BUYER_OUT" | awk '/Private Key/ {print $4}')

# 2. Deploy & initialize Base Asset ("GOLD") and Quote Asset ("USD") ledgers
cargo hps deploy dist/asset_ledger.wasm --save base.json
BASE=$(jq -r .hps_address base.json)
cargo hps send "$BASE" "initialize(address,string,uint64)" "$OWNER_ADDR" "GOLD" 2

cargo hps deploy dist/asset_ledger.wasm --save quote.json
QUOTE=$(jq -r .hps_address quote.json)
cargo hps send "$QUOTE" "initialize(address,string,uint64)" "$OWNER_ADDR" "USD" 2

# 3. Deploy Seller & Buyer Identity subroutines (these addresses hold ledger balances)
cargo hps deploy dist/identity.wasm --save seller_id.json
SELLER_ID=$(jq -r .hps_address seller_id.json)
cargo hps send "$SELLER_ID" "initialize(address,string)" "$OWNER_ADDR" "SellerVault"

cargo hps deploy dist/identity.wasm --private-key "$BUYER_KEY" --save buyer_id.json
BUYER_ID=$(jq -r .hps_address buyer_id.json)
cargo hps send "$BUYER_ID" "initialize(address,string)" "$BUYER_ADDR" "BuyerVault" --private-key "$BUYER_KEY"

# 4. Mint 500 GOLD to SellerIdentity and 50,000 USD to BuyerIdentity
cargo hps send "$BASE"  "mint(address,uint64)" "$SELLER_ID" 500
cargo hps send "$QUOTE" "mint(address,uint64)" "$BUYER_ID"  50000

# 5. Deploy AssetPair_OTC pairing GOLD (base) and USD (quote)
cargo hps deploy dist/asset_pair_otc.wasm --save otc.json
OTC=$(jq -r .hps_address otc.json)
cargo hps send "$OTC" "initialize(address,address,address,address)" \
  "$OWNER_ADDR" "$SELLER_ID" "$BASE" "$QUOTE"

# 6. Seller authorizes 200 GOLD to OTC & Owner places Ask Order for "ITEM-1" @ 100 USD/GOLD
cargo hps send "$SELLER_ID" "approveAsset(address,address,uint64)" "$BASE" "$OTC" 200 --touch "$BASE"
cargo hps send "$OTC" "placeAskOrder(bytes32,uint64,uint64)" "ITEM-1" 200 100 \
  --touch "$SELLER_ID" --touch "$BASE"

# 7. Buyer authorizes debit of 2,500 USD & buys 25 GOLD at the prevailing 100 USD price
cargo hps send "$BUYER_ID" "approveAsset(address,address,uint64)" "$QUOTE" "$OTC" 2500 \
  --private-key "$BUYER_KEY" --touch "$QUOTE"

cargo hps send "$OTC" "buyOrderWithIdentity(bytes32,address,uint64)" "ITEM-1" "$BUYER_ID" 25 \
  --private-key "$BUYER_KEY" \
  --touch "$BUYER_ID" --touch "$SELLER_ID" --touch "$QUOTE" --touch "$BASE"

# 8. Verify atomic settlement across both ledgers
cargo hps call "$BASE"  "balanceOf(address)" "$BUYER_ID"    # -> 25
cargo hps call "$BASE"  "balanceOf(address)" "$SELLER_ID"   # -> 475
cargo hps call "$QUOTE" "balanceOf(address)" "$BUYER_ID"    # -> 47500
cargo hps call "$QUOTE" "balanceOf(address)" "$SELLER_ID"   # -> 2500
cargo hps call "$OTC"   "getAskAvailable(bytes32)" "ITEM-1" # -> 175
```

---

## 6. Integrating Your Application Backend or Frontend

### Option A: Rust Backend / Desktop / Embedded App (`hps-client`)

Add `hps-client` to your app's `Cargo.toml`:

```rust
use hps_client::abi::{encode_call_from_strings, try_decode_u256};
use hps_client::{
    parse_address, HpsClient, HpsSigner, DEFAULT_CHAIN_ID, DEFAULT_DEV_PRIVATE_KEY,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = HpsClient::new("http://127.0.0.1:8545");
    let signer = HpsSigner::from_hex(DEFAULT_DEV_PRIVATE_KEY, DEFAULT_CHAIN_ID)?;

    // 1. Deploy WASM HPS (runs store_bytecode + instantiate automatically)
    let wasm = std::fs::read("dist/counter_registry.wasm")?;
    let deployed = client.deploy_hps(&signer, &wasm, &[]).await?;
    let hps = parse_address(&deployed.hps_address)?;

    // 2. Submit stateful invocation (use `send_call_with_targets` for cross-HPS calls)
    let calldata = encode_call_from_strings(
        "increment(bytes32,uint64)",
        &["keccak:general".into(), "7".into()],
    )?;
    let receipt = client.send_call(&signer, hps, &calldata).await?;
    println!("Confirmed in block #{}, logs={}", receipt.block_number, receipt.logs.len());

    // 3. Read committed state
    let query = encode_call_from_strings("getCount(bytes32)", &["keccak:general".into()])?;
    let raw = client.read_call(None, hps, &query).await?;
    println!("Current count = {:?}", try_decode_u256(&raw));
    Ok(())
}
```

### Option B: Web / TypeScript / SuperLexicon Frontend (`ts-client/hps.mjs`)

Lexicon uses a **10-field EIP-155 RLP** wire format (`[nonce, gasPrice, gasLimit, to, value, data, v, r, s, targetAddresses]`) with a nominal non-zero `gasPrice` (`1 gwei` default — no account balance is required or deducted on-chain). Pass `extraTargets: [addr1, addr2]` when calling across multiple Haltproof Subroutines:

```ts
import { AbiCoder, SigningKey, computeAddress, encodeRlp, id, keccak256 } from "ethers";
import { HpsRpcClient, signLexiconTransaction, DEFAULT_DEV_PRIVATE_KEY } from "./ts-client/hps.mjs";

const ethersUtils = { SigningKey, keccak256, encodeRlp, computeAddress };
const client = new HpsRpcClient("http://127.0.0.1:8545");
const abi = AbiCoder.defaultAbiCoder();

// Build ABI calldata & sign transaction
const selector = id("increment(bytes32,uint64)").slice(0, 10);
const argsHex = abi.encode(["bytes32", "uint64"], [id("general"), 5n]).slice(2);
const sender = computeAddress(DEFAULT_DEV_PRIVATE_KEY);
const nonce = await client.getNonce(sender);

const rawTx = signLexiconTransaction(ethersUtils, {
  privateKey: DEFAULT_DEV_PRIVATE_KEY,
  nonce,
  to: hpsAddress,
  data: selector + argsHex,
  extraTargets: [], // include cross-called HPS addresses here when applicable
});
const txHash = await client.sendRawTransaction(rawTx);
const receipt = await client.waitForReceipt(txHash);
```

### Real-Time Event Streaming via WebSocket (`ws://127.0.0.1:8546`)

Subscribe to live HPS events using standard `eth_subscribe`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": ["logs", { "address": "0xYourHpsAddress" }]
}
```

---

## 7. Moving from `--localtestnet` to a Live Radio Subnet

When your app is ready to move from `--localtestnet` to a live Semtech LR2021 FLRC subnet, **zero HPS or ABI changes are required** — simply point `--rpc` (or `LEXICON_RPC_URL`) at any validator or client gateway node on the subnet and generate a production key (`cargo hps keygen`).

Keep three operational guidelines in mind:
1. **Confirmation Cadence:** `--localtestnet` confirms blocks every `4s`; a live 3–8 validator radio subnet confirms blocks every `~5–9s` across the 4-phase TDMA window, so keep receipt polling timeouts at `>= 30s`.
2. **Compact Bytecode & Calldata:** Radio bursts share airtime (`12 KB` UART / `64 KB` AM36-Pico bursts). Always compile with `cargo hps build` so zero-data segments and debug sections are stripped (`<= 100 KB` hard limit, ideally `< 15 KB`).
3. **Nonce Horizon (`max_nonce_gap`):** Live radio subnets enforce a default future-nonce horizon of `10` in-flight transactions per sender address (`256` on `--localtestnet`). Wait for batch receipts before queuing more than `10` unconfirmed transactions from the same key.
