# Haltproof Subroutines (`haltproof-subroutines` / `hps`)

`haltproof-subroutines` is the developer toolkit and institutional reference suite for authoring, unit-testing, compiling, deploying, and invoking **WebAssembly (`Wasmtime`) Haltproof Subroutines (HPS)** on **Lexicon** — both against a 1-node `lexicon-node --localtestnet` and against live multi-validator FLRC radio subnets.

Zero C++/RocksDB dependencies are required to build Haltproof Subroutines or run `cargo hps`.

---

## Repository Structure

| Path | WASM Size | Description |
| :--- | :---: | :--- |
| `crates/hps-sdk/` | — | `#![no_std]` guest Rust SDK for `wasm32-unknown-unknown` Haltproof Subroutines: persistent `storage`, `context`, synchronous cross-HPS `call`, institutional governance codecs (`PolicySpec`, `StageRole`, `FunctionAuthRule`, `ShareClassSpec`, `AuthorizedModuleSpec`, `ActionHasher`), ABI encoding/decoding, event logs, compile-time `selector()` / `event_topic()`, and an in-memory multi-HPS `mock` host. |
| `crates/hps-client/` | — | Pure-Rust client implementing Lexicon's 10-field EIP-155 RLP transaction signing (including parallel-execution `target_addresses`), content-addressed `store_bytecode` + `instantiate_batch`, human-readable ABI call encoding, and `read_call` (`eth_call`) queries. |
| `crates/cargo-hps/` | — | Developer CLI (`cargo hps`): scaffolds new subroutines (`new`), compiles & strips WASM zero-data segments (`build`), deploys (`deploy`), sends single- or multi-HPS transactions (`send --touch`), queries views (`call`), and generates keys (`keygen`). |
| `examples/identity/` | `33.9 KB` | On-chain Identity HPS controlled by an EOA owner + optional delegates; root `msg_sender()` for all institutional calls. |
| `examples/identity-registry/` | `19.2 KB` | Verified Identity Register tracking active/suspended/revoked `Identity` instances and enforcing governance-approved WASM `code_hash` allowlists for both `Identity` and `Authorization` subroutines. |
| `examples/corporate-charter/` | `58.4 KB` | Pure constitutional Corporate Charter HPS: starts in `PENDING_RATIFICATION` until ratified by the **First Shareholder Resolution** (`activateCharter`), managing authorized `ShareClassSpec`s & voting/conversion formulas, Directors, pre-defined Roles (`0..N` members), `PolicySpec`s, scoped `(targetHps, fnSelector) -> policyId` rules, and authorized sibling module capabilities (`CAP_EQUITY_SETTLEMENT`, `CAP_MERCHANT_PAYMENT`). |
| `examples/share-capital/` | `26.9 KB` | Share Capital & Equity Administration HPS: multi-class share-backed futures underwriting (`authorizeFuturesUnderwriting`, `underwriteFutures`, `closeUnderwrittenFutures`) and restricted 3-step share-transfer call auctions using a segregated **`shareEscrowAccount`**. |
| `examples/authorization/` | `38.7 KB` | Stateful one-time approval process engine enforcing strict sequential stage ordering, per-member & dynamic `StageRole` weights, unanimous `ROLE_ALL_MEMBERS_WEIGHT`, cross-class `ROLE_SHAREHOLDER` supermajority voting, block-height expiry, and target-only `consume`. |
| `examples/asset-ledger/` | `46.6 KB` | Fungible share / bank / futures Asset Ledger HPS pinned to a single `CorporateCharter`, supporting process-driven permissions, client-signed `transferDirect`, 3-step call-auction clearing, and attachable `DexClob` exchanges. |
| `examples/product-ledger/` | `28.2 KB` | Commercial SKU Catalog & Checkout HPS governed via `CorporateCharter.getFunctionAuth` (`ROLE_PRODUCT_MANAGER`), settling buyer payments into a segregated **`operatingRevenueAccount`** and booking sales in `AccountingLedger`. |
| `examples/accounting-ledger/` | `89.2 KB` | Self-contained codified IAS / IFRS Double-Entry Accounting Ledger HPS (`hps_sdk::ifrs` 32-account CoA, Virgin `treasuryIdentity` exclusive cash custody, `IAS 2` Moving WAC, `IAS 16/38` Cost Model, `IFRS 15`, `IFRS 16` PV leases, `IFRS 9` aging `ECL`, `IAS 24` related-party guard, and live `IAS 1` / `IAS 7` statement compiler). |
| `examples/asset-pair-otc/` | `12.2 KB` | Atomic Delivery-vs-Payment Over-The-Counter ask-book pairing Base and Quote `AssetLedger`s. |
| `examples/dex-clob/` | `34.4 KB` | MEV-proof discrete-time FIFO Central Limit Orderbook matching engine attachable to any `AssetLedger` (Two-Tier Static Arena AVL Price-Level Tree + doubly-linked FIFO queues + cohort pro-rata clearing). |
| `examples/messaging/` | `4.5 KB` | High-TPS channel messaging HPS (`postMessage`, `getMessages`). |
| `ts-client/` | — | JavaScript / TypeScript client helper (`hps.mjs` + `hps.d.ts`) for Lexicon's 10-field RLP transactions and 2-step WASM deployment. |

---

## Quickstart

```bash
# 1. Run all offline native unit tests across all 13 workspace crates
cargo test --workspace

# 2. Build all 11 WASM Haltproof Subroutines into dist/
for pkg in identity identity-registry corporate-charter share-capital authorization \
           asset-ledger asset-pair-otc messaging product-ledger accounting-ledger dex-clob; do
  cargo run --quiet -p cargo-hps -- build -p "$pkg" --out-dir dist
done

# 3. Package a zero-server App Store release (.wasm + deterministic .html.gz + .manifest.json)
cargo run --quiet -p cargo-hps -- new my-app --with-ui
./scripts/build-app-bundle.sh ./my-app
# -> Produces my-app/dist/my-app.html.gz + my-app/dist/my_app.wasm + my-app/dist/my-app.manifest.json
#    Upload directly in the SuperLexicon Decentralized App Store (/apps.html?create=1)!

# 4. Run full live Wasmtime E2E suites against isolated `lexicon-node --localtestnet`
cargo test -p hps-client --test live_governance_e2e -- --ignored --test-threads=1 --nocapture
cargo test -p hps-client --test superlexicon_pe_e2e -- --ignored --test-threads=1 --nocapture

# 5. Launch the Full-Stack HFS Studio IDE (`http://127.0.0.1:4770` + auto-discovered by `/hfs-ide.html`)
cargo run --release -p cargo-hps -- studio
# Or stateless hosted sandbox mode for LAN / web portal servers:
cargo run --release -p cargo-hps -- studio --sandbox --bind 0.0.0.0:4770
```

---

## Documentation

- **[`docs/END_TO_END_GUIDE.md`](docs/END_TO_END_GUIDE.md)** — Architecture overview, Option 4A corporate topology, parallel-execution target declarations, and `hps-sdk` authoring guide.
- **[`docs/CORPORATE_CHARTER_ROLES_AND_AUTHORIZATION.md`](docs/CORPORATE_CHARTER_ROLES_AND_AUTHORIZATION.md)** — `CorporateCharter` lifecycle (`PENDING_RATIFICATION` $\to$ `ACTIVE` via First Shareholder Resolution), pre-defined unassigned roles, `StageRole` & scoped `FunctionAuthRule` wire formats, and module capability governance.
- **[`docs/SHARE_CAPITAL_OPERATIONS_AND_DEX_CLOB.md`](docs/SHARE_CAPITAL_OPERATIONS_AND_DEX_CLOB.md)** — Segregation of duties (`shareEscrowAccount` vs. `operatingRevenueAccount` vs. `AccountingLedger`), share-backed futures underwriting, 3-step share-transfer call auctions, and `DexClob` MEV-proof AVL orderbook specification.
- **[`docs/ABI_AND_ERROR_REFERENCE.md`](docs/ABI_AND_ERROR_REFERENCE.md)** — Complete ABI function signatures, WASM artifact sizes, and canonical error codes across all 11 subroutines.
- **[`docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md`](docs/SUPERLEXICON_PE_AND_FSM_VERIFICATION.md)** — Superlexicon Pte. Ltd. 49-shareholder private-equity specification and TLA+ / Kani formal verification templates.
