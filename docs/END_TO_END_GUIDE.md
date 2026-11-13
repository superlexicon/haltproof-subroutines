# End-to-End Haltproof Subroutine (HPS) & App Developer Guide

This guide walks through developing, testing, compiling, deploying, and integrating a **Haltproof Subroutine-driven application** on Lexicon using `haltproof-subroutines` (`cargo hps`) and `lexicon-node --localtestnet`.

---

## 1. Architecture Overview: Why "Haltproof Subroutines" (HPS)?

Lexicon models replicated on-chain programs as **Haltproof Subroutines (HPS)** — deterministic, fuel-bounded state-transition subroutines replicated across ISP-independent broadcast radio subnets that neither hang individual nodes nor depend on centralized cloud infrastructure or token fee markets:

1. **Deterministic, Fuel-Bounded WASM Execution**: Written in `#![no_std]` Rust using `hps-sdk` and compiled to WebAssembly (`wasm32-unknown-unknown`) executed by Lexicon's **Wasmtime** VM (`1 fuel = 1 gas`, strictly bounded per call so every invocation is guaranteed to terminate cleanly).
2. **Zero-Fee Operations (No Token Balance Required)**: Users and apps never need native tokens to deploy or invoke Haltproof Subroutines. Spam is bounded structurally via per-transaction fuel caps (`10,000,000` gas), per-account nonce horizons, and physical RF TDMA/LBT rules.
3. **2-Step Content-Addressed Deployment**:
   - **Step 1 (`store_bytecode`)**: Uploads `[32-byte keccak256(wasm)] || [wasm]` to `0x0000000000000000000000000000000000000100`.
   - **Step 2 (`instantiate`)**: Sends `to = null` with `[32-byte code_hash] || [init_args]`, binding an HPS instance at `keccak256(rlp(sender, nonce))[12:]`.
   - `cargo hps deploy`, `HpsClient::deploy_hps`, and `HpsRpcClient.deployHps` execute **both steps automatically in a single call** (confirming together in a single 4-second block on `--localtestnet`).
4. **Local vs Subnet Parity**: `lexicon-node --localtestnet` runs the exact same JSON-RPC, WebSocket, `LayeredMempool`, `WasmtimeAdapter`, `NetworkState`, and RocksDB `FlatKvDb` storage as a live multi-validator radio subnet — simply replacing over-the-air TDMA rounds with a 1-node 4-second block timer.

---

## 2. Environment Setup

```bash
# 1. Ensure the Rust WASM target is installed
rustup target add wasm32-unknown-unknown

# 2. Install the `cargo hps` CLI from this repository
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
| `context` | `context::msg_sender() -> [u8; 20]` | Verified ECDSA sender of the transaction |
| `context` | `context::block_number() -> u64` | Current chain block height |
| `storage` | `storage::get_u64(k)` / `set_u64(k, v)` | Read/write `u64` counters (`0` if unset) |
| `storage` | `storage::get_ref(k)` / `set(k, bytes)` | Read/write arbitrary byte slices (`set(k, &[])` deletes) |
| `storage` | `storage::exists(k) -> bool` | Check if a storage key is non-empty |
| `abi` | `args.bytes32(i)`, `args.u64(i)`, `args.address(i)`, `args.bool(i)`, `args.dynamic_bytes(i)` | Bounds-checked ABI argument decoders safe on 32-bit WASM |
| `ret` | `ret::write_u64_word(v)`, `ret::write_abi_bytes(b)`, `ret::write(raw)` | Populate `RETURN_BUF` (`0x70000`) for read calls |
| `events` | `events::emit(&[topic0, ...], &data)` | Emit indexed receipt logs (`<= 4` topics) |

---

## 5. Unit Testing, Compiling & Deploying

### Step 1: Fast Native Unit Tests (`< 100 ms`)
Because `hps-sdk` swaps in a thread-local mock host (`hps_sdk::mock`) on native targets, `cargo test` tests your HPS logic directly without spinning up a node:

```bash
cargo test
```

### Step 2: Build & Optimize WASM Bytecode

```bash
cargo hps build
```

`cargo hps build` automatically:
- Compiles `wasm32-unknown-unknown --release` with `2 MiB` initial linear memory (`--initial-memory=2097152 --max-memory=4194304`),
- Strips debug/custom sections and zero-filled data segment runs so `.wasm` artifacts stay ultra-compact (`~1–5 KB`) for radio transmission,
- Verifies that only supported `WasmtimeAdapter` `env::*` imports are used and `main` + `memory` are exported,
- Outputs `dist/<name>.wasm` and `dist/<name>.meta.json` (containing `code_hash`).

### Step 3: Deploy to `--localtestnet` (or a Live Subnet)

```bash
cargo hps deploy dist/task_board.wasm --save deployment.json
```

### Step 4: Invoke & Read via CLI

```bash
HPS=$(jq -r .hps_address deployment.json)

# Stateful write (confirmed in <= 4s on --localtestnet)
cargo hps send "$HPS" "increment(bytes32,uint64)" "sprint-1" 10

# Instant read-only query
cargo hps call "$HPS" "getCount(bytes32)" "sprint-1"
```

> **Tip for `bytes32` arguments on the CLI:** You can pass a full hex value (`0x1122...`), a plain ASCII label up to 32 bytes (`"sprint-1"`, right-padded with zeros), or `keccak:my-long-channel-name` to hash an arbitrary string with Keccak-256!

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

    // 2. Submit stateful invocation
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

Lexicon uses a **10-field EIP-155 RLP** wire format (`[nonce, gasPrice, gasLimit, to, value, data, v, r, s, targetAddresses]`) with a nominal non-zero `gasPrice` (`1 gwei` default — no account balance is required or deducted on-chain). Use `ts-client/hps.mjs` alongside `ethers` v6:

```ts
import { AbiCoder, SigningKey, computeAddress, encodeRlp, id, keccak256 } from "ethers";
import { HpsRpcClient, signLexiconTransaction, DEFAULT_DEV_PRIVATE_KEY } from "./ts-client/hps.mjs";

const ethersUtils = { SigningKey, keccak256, encodeRlp, computeAddress };
const client = new HpsRpcClient("http://127.0.0.1:8545");
const abi = AbiCoder.defaultAbiCoder();

// 1. Build ABI calldata: increment(bytes32,uint64)
const selector = id("increment(bytes32,uint64)").slice(0, 10);
const argsHex = abi.encode(["bytes32", "uint64"], [id("general"), 5n]).slice(2);
const calldata = selector + argsHex;

// 2. Sign zero-balance Lexicon transaction & await confirmation
const sender = computeAddress(DEFAULT_DEV_PRIVATE_KEY);
const nonce = await client.getNonce(sender);
const rawTx = signLexiconTransaction(ethersUtils, {
  privateKey: DEFAULT_DEV_PRIVATE_KEY,
  nonce,
  to: hpsAddress,
  data: calldata,
});
const txHash = await client.sendRawTransaction(rawTx);
const receipt = await client.waitForReceipt(txHash);

// 3. Read state via readCall
const getSelector = id("getCount(bytes32)").slice(0, 10);
const getArgs = abi.encode(["bytes32"], [id("general")]).slice(2);
const resultHex = await client.readCall(hpsAddress, getSelector + getArgs);
const [count] = abi.decode(["uint256"], resultHex);
console.log("Count:", count.toString());
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
