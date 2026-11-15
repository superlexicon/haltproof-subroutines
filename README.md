# Haltproof Subroutines (`haltproof-subroutines` / `hps`)

`haltproof-subroutines` is the official developer toolkit and reference suite for authoring, unit-testing, compiling, optimizing, deploying, and invoking **WebAssembly (`Wasmtime`) Haltproof Subroutines (HPS)** on **Lexicon** — both against a 1-node `lexicon-node --localtestnet` and against live multi-validator FLRC radio subnets.

Zero C++/RocksDB dependencies are required to build Haltproof Subroutines or run `cargo hps`.

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| `crates/hps-sdk/` | `#![no_std]` guest Rust SDK for `wasm32-unknown-unknown` Haltproof Subroutines. Wraps persistent state (`storage`), execution context (`context::msg_sender`, `context::self_address`, `context::code_hash_of`, `context::block_number`), synchronous cross-HPS calls (`call`), institutional governance & sequential/weighted policy codecs (`governance`), ABI calldata decoding/encoding (`abi`, `call::CallEncoder`), structured return payloads (`ret`), event logs (`events`), compile-time `selector()` / `event_topic()`, `hps_entry!`, and a multi-HPS native `mock` host so `cargo test` runs in milliseconds. |
| `crates/hps-client/` | Pure-Rust client library implementing Lexicon's 10-field EIP-155 RLP transaction signing (including multi-HPS `target_addresses`), 1-call 2-step WASM deployment (`deploy_hps`), content-addressed `store_bytecode` + pipelined `instantiate_batch`, human-readable ABI call encoding, `read_call` (`eth_call`) queries, and cross-subnet `subnet_sendTransaction`. |
| `crates/cargo-hps/` | Developer CLI (`cargo hps` / `cargo-hps`): scaffolds new Haltproof Subroutines (`new`), compiles & strips WASM zero-data segments (`build`), deploys in 1 command (`deploy`), submits stateful single- or multi-HPS invocations (`send` / `--touch`), executes instant read queries (`call`), and manages keys (`keygen`). |
| `examples/messaging/` | High-TPS channel messaging HPS (`4.5 KB` WASM) 100% ABI-, storage-key-, event-, and wire-compatible with Lexicon's maximum-TPS benchmark (`postMessage(bytes32,bytes)`, `getMessages(bytes32,uint64)`). |
| `examples/identity/` | On-chain Identity HPS (`16.3 KB` WASM) controlled by an EOA owner + optional delegates. All state-changing interactions with `IdentityRegistry`, `Constitution`, `Authorization`, `AssetLedger`, and `AssetPair_OTC` flow through verified `Identity` HPS instances (`execute`, `initConstitutionAuth`, `initOracleAuth`, `approveAuth`, `approveAndFinalizeAuth`, `issueAsset`, `cancelAsset`, `transferAsset`, `approveAsset`). |
| `examples/identity-registry/` | Verified Identity Register HPS (`20.2 KB` WASM) tracking active/suspended/revoked `Identity` HPS addresses **and** enforcing governance-approved WASM bytecode hashes (`code_hash`) for both `Identity` and `Authorization` subroutines (`isValidIdentity`, `isValidAuthorizationHps`, `registerIdentity`, `suspendIdentity`, `reinstateIdentity`, `revokeIdentity`, `rotateAdmin`, `setGovernancePolicy`, `setAllowedIdentityCodeHash`, `setAllowedAuthCodeHash`), rejecting raw EOAs and malicious clones. |
| `examples/constitution/` | Institutional Bylaws & Policy Registry HPS (`14.7 KB` WASM) storing sequential + weighted + block-expiry `PolicySpec` definitions (`getPolicyRaw`, `setPolicy`, `deactivatePolicy`), gated by `POLICY_SUPER_GOVERNANCE` one-time `Authorization` objects. |
| `examples/authorization/` | Per-Invocation Process & One-Time Authorization HPS (`18.9 KB` WASM) initialized per protected action (`initializeFromConstitution`, `initializeOracle`, `initializeCustom`), enforcing strict sequential stage ordering (`Stage 0 -> Stage 1 -> ...`), per-authorizer integer weights (`>= 1`), per-stage & overall block-height expiry (`context::block_number()`), explicit finalization, and target-only single-use consumption (`consume`). |
| `examples/asset-ledger/` | Institutional Fungible Asset Ledger HPS (`23.6 KB` WASM) enforcing verified `Identity` ownership (`IdentityRegistry`), process-driven permissions (`ACTION_ISSUE`, `ACTION_CANCEL`, `ACTION_TRANSFER`, `ACTION_APPROVE`, `ACTION_SUPER`), unexported private `internal_debit`/`internal_credit` primitives, one-time `Authorization` consumption on every public state mutation (`issue`, `cancel`, `transfer`, `approve`, `setPermission`), genesis allocations + permissions setup, and `SUPER`-gated permission rotation. |
| `examples/asset-pair-otc/` | `AssetPair_OTC` HPS (`13.8 KB` WASM) pairing a Base `AssetLedger` and Quote `AssetLedger` with `IdentityRegistry` verification: lets the verified seller `Identity` list ask orders (`placeAskOrder`) and lets verified buyer `Identity` accounts execute atomic Delivery-vs-Payment trades (`buyOrder`) via dual-ledger `transferFrom`. |
| `ts-client/` | JavaScript / TypeScript client helper (`hps.mjs` + `hps.d.ts`) implementing Lexicon's 10-field RLP transaction signing (`extraTargets` supported) and 2-step WASM HPS deployment for web & SuperLexicon frontends. |
| [`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md) | Step-by-step **End-to-End Haltproof Subroutine (HPS) & Institutional Governance Guide**, including architecture diagrams and full workflows. |
| [`docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md`](docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md) | **Superlexicon Pte. Ltd. (Singapore Private Equity Asset Ledger)** specification: 49-shareholder cap table (`100,000` shares), single-Constitution pinning, Shareholder Super-Majority ($\ge 75\%$) vs. Board of Directors (`2-of-2`) bylaws, event log schemas, positive/negative test catalogue (`P1`–`P4`, `N1`–`N11`), and **Formal Verification Template** (TLA+ & Kani Rust proofs). |

---

## Institutional Governance & Asset Ledger Architecture

Conventional smart contracts rely on flat RBAC (`users / groups / permissions`), which cannot express **joint weighted approvals** alongside **strict sequential multi-party authorization processes** (for example: *an officer from Group A must authorize Stage 0 within 20 blocks first; then and only then can Group B signers with cumulative weight >= 3 authorize Stage 1 within 20 blocks*).

`haltproof-subroutines` solves this cleanly across five composable Haltproof Subroutines:

1. **Identity-First Execution & Bytecode-Hash Attestation (`Identity` + `IdentityRegistry`)**:
   - Every participant operates through an `Identity` HPS (`examples/identity`) registered in `IdentityRegistry` (`examples/identity-registry`).
   - `IdentityRegistry` maintains governance-approved WASM `code_hash` allowlists for both `Identity` and `Authorization` subroutines via `context::code_hash_of` (`host_get_code_hash`). Neither raw EOAs nor malicious/cloned `Identity` or `Authorization` subroutines can be registered or consumed (`ERR_UNAPPROVED_CODE_HASH`).
   - State-changing functions across `AssetLedger`, `Authorization`, `Constitution`, `AssetPair_OTC`, and `IdentityRegistry` verify `IdentityRegistry.isValidIdentity(caller)` (active status **and** approved `Identity` `code_hash`) and `IdentityRegistry.isValidAuthorizationHps(authHps)` (approved `Authorization` `code_hash`) live on-chain.
   - `IdentityRegistry` lifecycle transitions (`registerIdentity`, `suspendIdentity`, `reinstateIdentity`, `revokeIdentity`, `rotateAdmin`, `setGovernancePolicy`, `setAllowedIdentityCodeHash`, `setAllowedAuthCodeHash`) themselves consume a valid one-time `Authorization` object.

2. **Bylaws & Sequential-Weighted Policies (`Constitution`)**:
   - `Constitution` (`examples/constitution`) maps `(targetHps, policyId)` (with global fallback `targetHps = 0x00..00`) to a binary `PolicySpec`:
     - `overall_expiry_blocks`: hard block window from initialization to finalization + consumption.
     - `stages[0..N]`: ordered `StageSpec` entries, each specifying `required_weight`, `expiry_blocks`, and `members: [(identity, weight)]`.
   - Initialized with genesis policies including `POLICY_SUPER_GOVERNANCE`; subsequent bylaw changes (`setPolicy`, `deactivatePolicy`) require a finalized `SUPER_GOVERNANCE` one-time `Authorization` object.

3. **Stateful Per-Call Process & One-Time Token (`Authorization`)**:
   - Instantiated and initialized per protected operation (`initializeFromConstitution` or `initializeOracle`), binding `(targetHps, policyId, actionHash, constitutionHps)`.
   - `approve()` / `approveAndFinalize()` verify the caller `Identity` is active in `IdentityRegistry`, belongs to the **currently active stage**, has not approved that stage yet, and is within both the current stage's `stage_deadline` and `overall_deadline`. Out-of-turn approvals from later stages revert deterministically.
   - Once all stages meet their `required_weight` and `finalize()` is reached, only `targetHps` can call `consume(expectedTarget, expectedConstitution, expectedPolicyId, expectedActionHash)` — atomically transitioning status from `FINALIZED (2)` to `CONSUMED (4)` so the object can **never** be replayed.

4. **Institutional `AssetLedger` (`examples/asset-ledger`)**:
   - **Verified Ownership Map**: Maps active `Identity` HPS addresses to `u64` balances (`totalOutstanding` invariant preserved).
   - **Private `internal_credit` / `internal_debit`**: Unexported Rust functions invoked exclusively by public entrypoints:
     - `issue(toIdentity, amount, authHps)` -> `internal_credit` (`+totalOutstanding`)
     - `cancel(fromIdentity, amount, authHps)` -> `internal_debit` (`-totalOutstanding`)
     - `transfer(toIdentity, amount, authHps)` -> `internal_debit(caller)` + `internal_credit(to)`
     - `transferFrom(fromIdentity, toIdentity, amount)` -> allowance check + `internal_debit(from)` + `internal_credit(to)` (where `approve(spender, amount, authHps)` consumed a one-time `Authorization`)
   - **Genesis State & `SUPER` Rotation**: `initialize(...)` loads initial verified balances + complete action permissions (`ACTION_SUPER`, `ACTION_ISSUE`, `ACTION_CANCEL`, `ACTION_TRANSFER`, `ACTION_APPROVE`, including dynamic `POLICY_HOLDER_SELF` for holder-authorized transfers/allowances). Updating any permission via `setPermission(...)` requires a `SUPER` one-time `Authorization` object.

---

## Quickstart

### 1. Prerequisites

```bash
# Install lexicon-node -> ~/.local/bin/lexicon-node
git clone https://github.com/superlexicon/lexicon-bin.git
(cd lexicon-bin && bash install.sh)

# Install WASM target & cargo-hps
rustup target add wasm32-unknown-unknown
cargo install --path crates/cargo-hps
```

### 2. Run All Native Unit Tests (Milliseconds, Zero External Dependencies)

```bash
cargo test --workspace
```

### 3. Build All 7 Reference Haltproof Subroutines

```bash
for pkg in messaging identity-registry identity constitution authorization asset-ledger asset-pair-otc; do
  cargo hps build -p "$pkg"
done
```

### 4. Run Full Live Wasmtime End-to-End Governance + Ledger + OTC Suite

With `lexicon-node` installed, run the automated live chain test (spawns an isolated `lexicon-node --localtestnet` on port `18555` and exercises the full governance + asset ledger + OTC suite, out-of-order rejection, block expiry, replay rejection, `SUPER` governance rotation, and atomic OTC settlement):

```bash
cargo test -p hps-client --test live_governance_e2e -- --ignored --nocapture

# Run the Superlexicon Pte. Ltd. (49-Shareholder Singapore Private Equity) live Wasmtime E2E suite:
cargo test -p hps-client --test superlexicon_pe_e2e -- --ignored --nocapture
```

---

## Full End-to-End Developer Guide & Formal Verification Template

- **[`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md)** — Complete architectural reference, `PolicySpec` wire format, action-hash formulas, and Rust/CLI/TypeScript integration guide.
- **[`docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md`](docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md)** — Superlexicon Pte. Ltd. 49-shareholder Private Equity Asset Ledger, single-Constitution pinning, event log schemas, positive/negative test suite (`P1`–`P4`, `N1`–`N11`), and Formal Verification Template (LTL/CTL invariants, TLA+ specification, and Kani Rust bounded model checking proofs).
