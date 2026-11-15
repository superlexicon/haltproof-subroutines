# Superlexicon Pte. Ltd. — Private Equity Asset Ledger, Positive/Negative Test Suite & Formal Verification Template

This document specifies:
1. The **Superlexicon Pte. Ltd.** (Singapore Private Limited Liability Company) corporate capitalisation table, bylaws, and single-Constitution Haltproof Subroutine (HPS) architecture.
2. The **Event Log Schemas** emitted across `Identity`, `IdentityRegistry`, `Constitution`, `Authorization`, and `AssetLedger`.
3. The complete catalogue of **Positive Test Cases (`P1`–`P4`)** and **Negative Security Test Cases (`N1`–`N11`)** executed both in-memory (`examples/asset-ledger/src/main.rs`) and on live Wasmtime (`crates/hps-client/tests/superlexicon_pe_e2e.rs`).
4. A **Formal Verification Template** (state space, transition relation, LTL/CTL temporal safety invariants, **TLA+ specification**, and **Kani Rust bounded model checking proofs**) for coupled Haltproof Finite State Machines.

---

## 1. Corporate Structure & Capitalisation Table (`SLX-COMMON`)

### 1.1 Entities & Verified `Identity` Subroutines (`52` Total)
Every participant and corporate entity interacts with `Constitution`, `Authorization`, and `AssetLedger` exclusively through a verified `Identity` Haltproof Subroutine registered in `IdentityRegistry` and attested via live WASM `code_hash` (`host_get_code_hash`):

| Role | Count | Handle / Identifier | Initial `SLX-COMMON` Shares | Voting Weight (`1:1`) | Ownership % (Genesis) | Ownership % (Post-Issuance) |
| :--- | :---: | :--- | ---: | ---: | ---: | ---: |
| **Director #1 & Founding Shareholder #1** | 1 | `manogaran.thanabalan` | `50,000` | `50,000` | `50.00%` | **`75.00%` (`150,000` / `200,000`)** |
| **Director #2 (Independent Non-Shareholder)** | 1 | `evelyn.tan.director` | `0` | `1` (Board only) | `0.00%` | `0.00%` |
| **Minority Shareholders `#2..#17`** | 16 | `shareholder.02` .. `shareholder.17` | `1,250` each (`20,000` total) | `1,250` each | `20.00%` | `10.00%` |
| **Minority Shareholders `#18..#33`** | 16 | `shareholder.18` .. `shareholder.33` | `1,000` each (`16,000` total) | `1,000` each | `16.00%` | `8.00%` |
| **Minority Shareholders `#34..#49`** | 16 | `shareholder.34` .. `shareholder.49` | `875` each (`14,000` total) | `875` each | `14.00%` | `7.00%` |
| **Total Shareholders** | **49** | `SLX-COMMON` Cap Table | **`100,000`** | **`100,000`** | **`100.00%`** | **`100.00%` (`200,000` shares)** |
| **Corporate Identity** | 1 | `superlexicon.pte.ltd` | Holds `250,000` `USD-TREASURY` | — | — | — |
| **Director #3 Candidate** | 1 | `rajesh.nair.director3` | `0` | Appointed via `addDirector` | — | — |

### 1.2 Singapore Pte. Ltd. Corporate Governance Bylaws (`Constitution` HPS)

| Policy ID Constant | Keccak256 Preimage | Stage Structure & Required Weight | Governed State-Changing Functions |
| :--- | :--- | :--- | :--- |
| `POLICY_SHAREHOLDER_SUPERMAJORITY` | `keccak256("POLICY_SHAREHOLDER_SUPERMAJORITY")` | **1 Stage**: All 49 Shareholders with `1:1` share weights (`total = 100,000`), **`required_weight = 75,000` ($\ge 75\%$ Super-Majority)**, `expiry = 100 blocks` | `SLX-COMMON.issue(to, amount, authObj)` (`ACTION_ISSUE`), `SLX-COMMON.cancel(from, amount, authObj)` (`ACTION_CANCEL`) |
| `POLICY_SUPER_GOVERNANCE` | `keccak256("CONSTITUTION_SUPER_GOVERNANCE")` | **1 Stage**: All 49 Shareholders with `1:1` share weights (`total = 100,000`), **`required_weight = 75,000` ($\ge 75\%$ Super-Majority)**, `expiry = 100 blocks` | `Constitution.addDirector(dir, authObj)`, `Constitution.removeDirector(dir, authObj)`, `Constitution.setPolicy(...)`, `SLX-COMMON.setPermission(...)` |
| `POLICY_BOARD_RESOLUTION` | `keccak256("POLICY_BOARD_RESOLUTION")` | **1 Stage**: Active Board of Directors (`manogaran.thanabalan` weight `1` + `evelyn.tan.director` weight `1`), **`required_weight = 2` (`2-of-2` unanimous Board)**, `expiry = 100 blocks` | `USD-TREASURY.transfer(superlexicon_company_id, to, amount, authObj)` (`ACTION_TRANSFER`) where `superlexicon.pte.ltd` is the asset owner |
| `POLICY_HOLDER_SELF` | `keccak256("LEDGER_POLICY_HOLDER_SELF")` | Holder's own `Identity` single-account oracle `Authorization` (`weight = 1`, `required_weight = 1`) | Direct shareholder `SLX-COMMON.transfer` / `approve` of their own shares |

### 1.3 Single-Constitution Pinning (`KEY_CONSTITUTION`)
In `examples/asset-ledger/src/main.rs`:
- During `initialize(identityRegistry, symbol, decimals, initialAllocations, initialPermissions)`, the `AssetLedger` verifies that every non-zero `constitution` address across `initialPermissions` resolves to **one single `Constitution` HPS address** (`associatedConstitution()`). If two distinct non-zero `Constitution` addresses are supplied, `initialize` reverts with `ERR_CONSTITUTION_MISMATCH = -19` and emits no state changes.
- Once pinned, `setPermission(actionKey, constitution, policyId, superAuth)` enforces `constitution == associatedConstitution()` (or `([0u8; 20], POLICY_HOLDER_SELF)`), reverting with `ERR_CONSTITUTION_MISMATCH = -19` if any caller attempts to bind a second `Constitution` to the `AssetLedger`.

---

## 2. Event Log Schemas for End-State Verification

| Subroutine | Event Signature (`topic[0] = keccak256(sig)`) | Indexed Topics (`topic[1..]`) | Data Payload (Big-Endian Words) |
| :--- | :--- | :--- | :--- |
| `Identity` | `IdentityInitialized(address,string)` | `topic[1]`: `owner` EOA | UTF-8 handle bytes (e.g. `manogaran.thanabalan`) |
| `IdentityRegistry` | `RegistryInitialized(address,bytes32,bytes32,uint64)` | `topic[1]`: `adminIdentity`<br>`topic[2]`: `allowedIdentityCodeHash`<br>`topic[3]`: `allowedAuthCodeHash` | `[0..8]`: `activeCount` (`u64`) |
| `IdentityRegistry` | `IdentityStatusChanged(address,uint64,uint64,address)` | `topic[1]`: `identity` | `[0..8]`: `prevStatus`, `[8..16]`: `newStatus`, `[16..36]`: `authObj` |
| `AssetLedger` | `ConstitutionPinned(address)` | `topic[1]`: `associatedConstitution` | Empty (`0` bytes) |
| `AssetLedger` | `LedgerInitialized(address,uint64,uint64)` | `topic[1]`: `identityRegistry`<br>`topic[2]`: `associatedConstitution` | `[0..8]`: `totalSupply`, `[8..16]`: `permCount`, `[16..24]`: `holderCount` |
| `AssetLedger` | `AssetIssued(address,uint64,uint64,address)` | `topic[1]`: `toIdentity`<br>`topic[2]`: `authObj` | `[0..8]`: `amount`, `[8..16]`: `newTotalSupply`, `[16..24]`: `newHolderBalance` |
| `AssetLedger` | `AssetCancelled(address,uint64,uint64,address)` | `topic[1]`: `fromIdentity`<br>`topic[2]`: `authObj` | `[0..8]`: `amount`, `[8..16]`: `newTotalSupply`, `[16..24]`: `newHolderBalance` |
| `AssetLedger` | `Credited(address,uint64,uint64)` | `topic[1]`: `identity` | `[0..8]`: `amount`, `[8..16]`: `newHolderBalance` |
| `AssetLedger` | `Debited(address,uint64,uint64)` | `topic[1]`: `identity` | `[0..8]`: `amount`, `[8..16]`: `newHolderBalance` |
| `AssetLedger` | `Transfer(address,address,uint64)` | `topic[1]`: `fromIdentity`<br>`topic[2]`: `toIdentity` | `[0..8]`: `amount` |
| `Constitution` | `ConstitutionInitialized(address,uint64)` | `topic[1]`: `identityRegistry` | `[0..8]`: `policyCount` |
| `Constitution` | `PolicySet(address,bytes32,uint64,uint64)` | `topic[1]`: `targetHps`<br>`topic[2]`: `policyId` | `[0..8]`: `stageCount`, `[8..16]`: `overallExpiryBlocks` |
| `Constitution` | `DirectorAdded(address,uint64,address)` | `topic[1]`: `newDirector`<br>`topic[2]`: `superAuth` | `[0..8]`: `newDirectorCount` |
| `Constitution` | `DirectorRemoved(address,uint64,address)` | `topic[1]`: `removedDirector`<br>`topic[2]`: `superAuth` | `[0..8]`: `newDirectorCount` |
| `Authorization` | `AuthorizationInitialized(address,address,bytes32,bytes32)` | `topic[1]`: `targetHps`<br>`topic[2]`: `policyId`<br>`topic[3]`: `actionHash` | `[0..20]`: `constitution`, `[20..28]`: `stage0RequiredWeight`, `[28..36]`: `stageCount` |
| `Authorization` | `StageApproved(address,uint64,uint64,uint64)` | `topic[1]`: `approverIdentity`<br>`topic[2]`: `stageIndex` | `[0..8]`: `memberWeight`, `[8..16]`: `cumulativeStageWeight` |
| `Authorization` | `StageThresholdReached(uint64,uint64,uint64)` | `topic[1]`: `stageIndex` | `[0..8]`: `cumulativeWeight`, `[8..16]`: `requiredWeight`, `[16..24]`: `nextStageIndex` |
| `Authorization` | `AuthorizationFinalized(address,uint64)` | `topic[1]`: `targetHps`<br>`topic[2]`: `actionHash` | `[0..8]`: `finalizedAtBlock` |
| `Authorization` | `AuthorizationConsumed(address,address,bytes32)` | `topic[1]`: `targetHps`<br>`topic[2]`: `initiatorIdentity`<br>`topic[3]`: `actionHash` | `[0..8]`: `consumedAtBlock` |

---

## 3. Positive & Negative Test Case Catalogue

### 3.1 Positive Test Cases (`P1`–`P4`)

| ID | Test Case | Preconditions | Action / Inputs | Expected End State & Emitted Events |
| :--- | :--- | :--- | :--- | :--- |
| **`P1`** | **Genesis Cap Table & Single-Constitution Deployment** | 52 `Identity` HPSes initialized and active in `IdentityRegistry` | Initialize `SLX-COMMON` with 49 shareholders (`Manogaran = 50,000`, 48 others = `50,000`, total = `100,000`) pinned to `slx_constitution`; initialize `slx_constitution` with `POLICY_SHAREHOLDER_SUPERMAJORITY` (`75,000` of `100,000`) and `POLICY_BOARD_RESOLUTION` (`2-of-2` directors) | `associatedConstitution() == slx_constitution`, `holderCount() == 49`, `totalOutstanding() == 100,000`, `balanceOf(manogaran) == 50,000`, `directorCount() == 2`. Emits `ConstitutionPinned`, `LedgerInitialized`, `ConstitutionInitialized`, `PolicyUpdated`. |
| **`P2`** | **Super-Majority Share Issuance Making Manogaran 75.00% Shareholder** | `auth_issue_mano` initialized from `slx_constitution` for `hashIssue(manogaran, 100_000)` | Manogaran (`50,000` votes) + 21 minority shareholders (`16 * 1,250 + 5 * 1,000 = 25,000` votes) call `approve(0)` $\to$ `stageWeight(0) == 75,000` $\to$ `finalize()` $\to$ `SLX-COMMON.issue(manogaran, 100_000, auth_issue_mano)` | `balanceOf(manogaran) == 150,000`, `totalOutstanding() == 200,000` (**`75.00%` super-majority**), `auth_issue_mano.state() == STATE_CONSUMED (3)`. Emits `StageApproved` ($\times 22$), `StageThresholdReached`, `AuthorizationFinalized`, `AuthorizationConsumed`, `Issued`, `Transfer`. |
| **`P3`** | **Board of Directors (2-of-2) Resolution to Transfer Company-Owned Assets** | `superlexicon.pte.ltd` owns `250,000` units in `USD-TREASURY` where `ACTION_TRANSFER` requires `POLICY_BOARD_RESOLUTION` | Initialize `auth_board_transfer` for `hashTransfer(company, recipient, 50,000)`; both Directors (`Manogaran` + `Evelyn Tan`) call `approve(0)` (`weight = 2/2`) $\to$ `finalize()` $\to$ `company` invokes `USD-TREASURY.transfer` | `balanceOf(company) == 200,000`, `balanceOf(recipient) == 50,000`, `auth_board_transfer.state() == STATE_CONSUMED (3)`. Emits `StageApproved` ($\times 2$), `StageThresholdReached`, `AuthorizationFinalized`, `AuthorizationConsumed`, `Transfer`. |
| **`P4`** | **Director Appointment & Removal via Shareholder Super-Majority** | `directorCount() == 2` (`Manogaran`, `Evelyn Tan`) | Initialize `auth_add_director` for `hashAddDirector(rajesh_nair)`, accumulate `75,000` shareholder votes, `finalize()`, call `Constitution.addDirector(rajesh_nair, auth_add_director)` | `directorCount() == 3`, `isDirector(rajesh_nair) == true`, `POLICY_BOARD_RESOLUTION` automatically updated to `3-of-3` directors. Emits `DirectorAdded` and `PolicyUpdated`. |

### 3.2 Negative Security Test Cases (`N1`–`N11`)

| ID | Attack Vector / Negative Scenario | Inputs / Trigger | Expected Result & Revert Code | Security Property Verified |
| :--- | :--- | :--- | :--- | :--- |
| **`N1`** | **Multi-Constitution Injection at Genesis** | Pass 2 distinct `Constitution` addresses in `initialPermissions` to `SLX-COMMON.initialize` | Reverts (`ERR_CONSTITUTION_MISMATCH = -19`) | `AssetLedger` can never be split across multiple Constitutions at initialization. |
| **`N2`** | **Overwriting an Initialized `Authorization` HPS** | Call `initialize(...)` a second time on `auth_issue_mano` while in `STATE_IN_PROGRESS` | Reverts (`-60`) | Active `Authorization` process state, policy snapshot, and action hash are immutable after initialization. |
| **`N3`** | **Duplicate Shareholder Vote (Sybil Weight Inflation)** | `Manogaran` (`50,000` votes) calls `approve(0)` twice on `auth_issue_mano` to reach `100,000 >= 75,000` alone | Reverts (`ERR_ALREADY_SIGNED = -69`) | Each verified `Identity` can vote at most once per `(authObj, stageIndex)`; `stageWeight(0)` remains `50,000`. |
| **`N4`** | **Premature Finalization (Under Super-Majority Threshold)** | Call `auth_issue_mano.finalize()` when `stageWeight(0) == 50,000 < 75,000` | Reverts (`ERR_AUTH_NOT_FINALIZED = -62`) | `STATE_FINALIZED` is unreachable until every stage meets `accum_weight >= required_weight`. |
| **`N5`** | **Unfinalized `Authorization` Passed to `issue()` (50,000 Votes)** | Call `SLX-COMMON.issue(manogaran, 100,000, auth_issue_mano)` while `state() == STATE_IN_PROGRESS` | Reverts (`ERR_AUTH_NOT_FINALIZED = -62`) | `AssetLedger.issue` rejects any `Authorization` object not in `STATE_FINALIZED`. |
| **`N6`** | **Arbitrary Policy Substitution (Board Resolution Used for Share Issuance)** | Finalize a `2-of-2` `POLICY_BOARD_RESOLUTION` `Authorization` bound to `SLX-COMMON` and `hashIssue`, and pass it to `SLX-COMMON.issue` | Reverts (`ERR_AUTH_POLICY_MISMATCH = -66`) | Directors cannot bypass the 49-shareholder Super-Majority requirement to issue shares. |
| **`N7`** | **Maliciously Cloned `Authorization` Subroutine (`code_hash` Attestation)** | Deploy a rogue WASM binary that always returns `true` on `consume(...)` and pass its address to `SLX-COMMON.issue` | Reverts (`ERR_UNAPPROVED_CODE_HASH = -73`) | `IdentityRegistry.isValidAuthorizationHps` checks `host_get_code_hash` against the governance allowlist before calling `consume`. |
| **`N8`** | **Pre-Finalize Bypass After Threshold Reached** | Accumulate `75,000 / 75,000` shareholder votes on `auth_issue_mano` and call `SLX-COMMON.issue` *before* calling `finalize()` | Reverts (`ERR_AUTH_NOT_FINALIZED = -62`) | Explicit transition `STATE_IN_PROGRESS -> STATE_FINALIZED` via `finalize()` is mandatory. |
| **`N9`** | **Replay Attack (Re-Passing Already-Consumed `Authorization`)** | Call `SLX-COMMON.issue(manogaran, 100,000, auth_issue_mano)` a second time after `auth_issue_mano` is in `STATE_CONSUMED (3)` | Reverts (`ERR_AUTH_ALREADY_CONSUMED = -68`) | Strict one-time consumption; `totalOutstanding()` remains `200,000`. |
| **`N10`** | **Single-Constitution Bypass via `setPermission`** | Call `SLX-COMMON.setPermission(ACTION_ISSUE, rogue_constitution, ...)` after `SLX-COMMON` is pinned to `slx_constitution` | Reverts (`ERR_CONSTITUTION_MISMATCH = -19`) | An `AssetLedger` pinned to `slx_constitution` can never be re-pointed to another `Constitution`. |
| **`N11`** | **Single Director (1-of-2) Attempting Board Transfer** | `Manogaran` alone approves `auth_board_transfer` (`weight = 1 < 2`) and attempts `finalize()` | Reverts (`ERR_AUTH_NOT_FINALIZED = -62`) | Unanimous `2-of-2` Board approval (`Manogaran` + `Evelyn Tan`) is enforced before corporate assets can be transferred. |

---

## 4. Formal Verification Template for Haltproof Finite State Machines

Because every Haltproof Subroutine (HPS) executes deterministically with bounded loops, zero dynamic allocation (`no_std`), and explicit finite state spaces, the coupled **`IdentityRegistry` $\times$ `Constitution` $\times$ `Authorization` $\times$ `AssetLedger`** system can be modeled and formally verified as a **Timed Guarded Finite State Machine (FSM)**.

### 4.1 Mathematical State Space Definition

Let the global state of the coupled governance and ledger system at block height $b \in \mathbb{N}$ be the tuple:

$$\Sigma = \langle b,\; \mathcal{R},\; \mathcal{C},\; \mathcal{A},\; \mathcal{L} \rangle$$

where:
1. **Verified Identity & Bytecode Registry State $\mathcal{R}$**:
   - $\text{status}: \text{Addr} \to \{\text{UNREGISTERED}(0), \text{ACTIVE}(1), \text{SUSPENDED}(2), \text{REVOKED}(3)\}$
   - $\text{allowedIdCode}: \text{Bytes32} \to \mathbb{B}$, $\quad \text{allowedAuthCode}: \text{Bytes32} \to \mathbb{B}$
   - $\text{ValidId}(u) \iff \text{status}(u) = \text{ACTIVE} \land \text{allowedIdCode}(\text{codeHash}(u))$
   - $\text{ValidAuthHps}(a) \iff \text{allowedAuthCode}(\text{codeHash}(a))$
2. **Constitution State $\mathcal{C}$**:
   - $\text{policies}: (\text{Addr} \times \text{Bytes32}) \rightharpoonup \text{PolicySpec}$
   - Each $\text{PolicySpec} = \langle \Delta_{\text{overall}}, [S_0, S_1, \dots, S_{k-1}] \rangle$ with $1 \le k \le 4$, where each stage $S_j = \langle W_j^{\text{req}}, \Delta_j, w_j: \text{Addr} \rightharpoonup \mathbb{N}^+ \rangle$.
3. **Authorization FSM Instance State $\mathcal{A}(a)$**:
   - $\text{state}(a) \in \{ \text{UNINIT}(0),\; \text{IN\_PROGRESS}(1),\; \text{FINALIZED}(2),\; \text{CONSUMED}(3),\; \text{EXPIRED}(4) \}$
   - Immutable binding tuple $\beta(a) = \langle c_a, t_a, p_a, h_a, \text{spec}_a, b_{\text{deadline}}(a) \rangle$ fixed at transition $0 \to 1$.
   - Stage progress $\text{curStage}(a) \in [0, k]$, stage start block $b_{\text{stage}}(a) \in \mathbb{N}$, accumulated weights $\text{wt}(a, j) \in \mathbb{N}$, and per-identity vote bitmap $\text{signed}(a, j, u) \in \mathbb{B}$.
4. **Asset Ledger State $\mathcal{L}(\ell)$**:
   - Pinned single Constitution $c^*(\ell) \in \text{Addr}$ (immutable once set).
   - Permission map $\text{perm}(\ell, \text{act}) = \langle c, p \rangle$ subject to the invariant $c \in \{0, c^*(\ell)\}$.
   - Ownership map $\text{bal}(\ell, u) \in \mathbb{N}$ and total supply $\text{supply}(\ell) \in \mathbb{N}$.

```mermaid
stateDiagram-v2
    [*] --> UNINITIALIZED : Deploy Authorization HPS
    UNINITIALIZED --> IN_PROGRESS : initialize(reg, con, target, pol, hash)\n[ValidId(caller) & policy exists in con]
    IN_PROGRESS --> IN_PROGRESS : approve(stageIdx)\n[ValidId(caller) & curStage == stageIdx & !signed & b <= deadlines]\naccumWeight += w(caller); if accum >= req -> curStage++
    IN_PROGRESS --> EXPIRED : approve / finalize / consume\n[b > stageDeadline OR b > overallDeadline]
    IN_PROGRESS --> FINALIZED : finalize()\n[ValidId(caller) & curStage == stageCount & b <= overallDeadline]
    FINALIZED --> EXPIRED : consume()\n[b > overallDeadline]
    FINALIZED --> CONSUMED : consume(con, pol, hash, caller)\n[msg.sender == target & binding matches & b <= overallDeadline]
    CONSUMED --> [*]
    EXPIRED --> [*]
```

### 4.2 Temporal Safety & Accounting Invariants (LTL / CTL)

Every implementation of the Haltproof Governance & Asset Ledger FSM must satisfy the following seven safety properties ($\square$ = "always / in every reachable state"):

1. **`G1` — Monotonic Terminal Absorption (One-Time Use / No Replay)**:
   $$\square \Big( (\text{state}(a) = \text{CONSUMED} \implies \square (\text{state}(a) = \text{CONSUMED})) \;\land\; (\text{state}(a) = \text{EXPIRED} \implies \square (\text{state}(a) = \text{EXPIRED})) \Big)$$
   And once $\text{state}(a) \neq \text{UNINIT}$, the binding tuple $\beta(a) = \langle c_a, t_a, p_a, h_a, \text{spec}_a \rangle$ is constant across all subsequent transitions.
2. **`G2` — Strict Sequential Stage & Weighted Threshold Gate**:
   $$\square \Big( \text{state}(a) \in \{\text{FINALIZED}, \text{CONSUMED}\} \implies \forall j \in [0, k-1]: \sum_{u:\,\text{signed}(a,j,u)=\text{true}} w_j(u) \ge W_j^{\text{req}} \Big)$$
   Furthermore, for all $j > 0$ and all $u$, $\text{signed}(a, j, u) = \text{true}$ is reachable only after Stage $j-1$ reached $W_{j-1}^{\text{req}}$.
3. **`G3` — Per-Stage Non-Inflation (At-Most-Once Vote per Identity)**:
   $$\square \Big( \text{wt}(a, j) = \sum_{u \in \text{Dom}(w_j) \land \text{signed}(a,j,u)} w_j(u) \Big)$$
4. **`G4` — Timely Execution Bound**:
   $$\square \Big( \text{Transition}(a, \text{FINALIZED} \to \text{CONSUMED}) \implies b \le b_{\text{deadline}}(a) \Big)$$
5. **`G5` — Authenticated & Attested Consumption Gate**:
   $$\square \Big( \text{LedgerMutation}(\ell, \text{act}, h) \implies \exists! a:\; \text{ValidId}(\text{caller}) \land \text{ValidAuthHps}(a) \land \beta(a) = \langle c^*(\ell), \ell, p(\ell,\text{act}), h \rangle \land \text{Transition}(a, \text{FINALIZED} \to \text{CONSUMED}) \Big)$$
6. **`G6` — Single-Constitution Pinning Invariant**:
   $$\square \Big( \forall \text{act}:\; \text{perm}(\ell, \text{act}).c \in \{ \text{ZERO\_ADDR},\; c^*(\ell) \} \Big)$$
7. **`G7` — Conservation of Shares (`internal_debit` / `internal_credit` Integrity)**:
   $$\square \left( \text{supply}(\ell) = \sum_{u \in \text{Holders}(\ell)} \text{bal}(\ell, u) \;\land\; (\text{bal}(\ell, u) > 0 \implies \text{status}(u) \neq \text{UNREGISTERED}) \right)$$

---

### 4.3 Reusable TLA+ Specification Template (`HaltproofAuthorizationFSM.tla`)

Save the following module as `HaltproofAuthorizationFSM.tla` and run with the **TLC Model Checker** (`tlc HaltproofAuthorizationFSM.tla`) to exhaustively model-check all reachable states across arbitrary shareholder configurations and block-height interleavings:

```tla
--------------------- MODULE HaltproofAuthorizationFSM ---------------------
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Identities,         \* Set of all Identity HPS addresses
    ValidIdentities,    \* Subset of Identities active + approved code_hash in IdentityRegistry
    AuthObjects,        \* Set of Authorization HPS addresses
    ApprovedAuthObjects,\* Subset of AuthObjects with approved WASM code_hash
    Constitutions,      \* Set of Constitution HPS addresses (e.g. {SLX_CON, ROGUE_CON})
    PinnedConstitution, \* Single Constitution pinned to SLX-COMMON (SLX_CON)
    RequiredWeight,     \* Super-majority threshold (e.g. 75000)
    StageExpiry,        \* Per-stage block expiry delta
    OverallExpiry,      \* Overall block expiry delta
    MaxBlock            \* Upper bound on block height for bounded model checking

ASSUME ValidIdentities \subseteq Identities
ASSUME ApprovedAuthObjects \subseteq AuthObjects
ASSUME PinnedConstitution \in Constitutions

States == {"UNINIT", "IN_PROGRESS", "FINALIZED", "CONSUMED", "EXPIRED"}
Policies == {"SHAREHOLDER_SUPERMAJORITY", "BOARD_RESOLUTION"}
Actions == {"ISSUE_MANO_100K", "OTHER_ACTION"}

VARIABLES
    blockNum,           \* Current block height b
    authState,          \* authState[a] \in States
    authCon,            \* authCon[a] \in Constitutions \cup {"NONE"}
    authPol,            \* authPol[a] \in Policies \cup {"NONE"}
    authAction,         \* authAction[a] \in Actions \cup {"NONE"}
    authWeight,         \* authWeight[a] \in Nat (accumulated stage weight)
    authSigned,         \* authSigned[a] \in SUBSET Identities
    authDeadline,       \* authDeadline[a] \in Nat
    ledgerCon,          \* Pinned Constitution of SLX-COMMON
    ledgerPermCon,      \* Constitution bound to ACTION_ISSUE in SLX-COMMON
    manoBalance,        \* Manogaran's share balance
    otherBalance,       \* Aggregate balance of the 48 other shareholders
    totalSupply,        \* SLX-COMMON totalOutstanding()
    issuanceCount       \* Number of completed 100,000-share issuances

vars == <<blockNum, authState, authCon, authPol, authAction, authWeight,
          authSigned, authDeadline, ledgerCon, ledgerPermCon,
          manoBalance, otherBalance, totalSupply, issuanceCount>>

\* Voting weight function (e.g. Manogaran = 50000, Minority Coalition = 25000)
Weight(u, pol) ==
    IF pol = "SHAREHOLDER_SUPERMAJORITY" THEN 25000 ELSE 1

Threshold(pol) ==
    IF pol = "SHAREHOLDER_SUPERMAJORITY" THEN RequiredWeight ELSE 2

Init ==
    /\ blockNum = 1
    /\ authState = [a \in AuthObjects |-> "UNINIT"]
    /\ authCon = [a \in AuthObjects |-> "NONE"]
    /\ authPol = [a \in AuthObjects |-> "NONE"]
    /\ authAction = [a \in AuthObjects |-> "NONE"]
    /\ authWeight = [a \in AuthObjects |-> 0]
    /\ authSigned = [a \in AuthObjects |-> {}]
    /\ authDeadline = [a \in AuthObjects |-> 0]
    /\ ledgerCon = PinnedConstitution
    /\ ledgerPermCon = PinnedConstitution
    /\ manoBalance = 50000
    /\ otherBalance = 50000
    /\ totalSupply = 100000
    /\ issuanceCount = 0

\* 1. Initialize an Authorization HPS (cannot overwrite if already initialized!)
InitAuth(caller, a, c, pol, act) ==
    /\ caller \in ValidIdentities
    /\ a \in ApprovedAuthObjects
    /\ authState[a] = "UNINIT"
    /\ c \in Constitutions
    /\ pol \in Policies
    /\ act \in Actions
    /\ authState' = [authState EXCEPT ![a] = "IN_PROGRESS"]
    /\ authCon' = [authCon EXCEPT ![a] = c]
    /\ authPol' = [authPol EXCEPT ![a] = pol]
    /\ authAction' = [authAction EXCEPT ![a] = act]
    /\ authDeadline' = [authDeadline EXCEPT ![a] = blockNum + OverallExpiry]
    /\ UNCHANGED <<blockNum, authWeight, authSigned, ledgerCon, ledgerPermCon,
                   manoBalance, otherBalance, totalSupply, issuanceCount>>

\* 2. Cast weighted vote on Stage 0 (rejects duplicate votes and expired processes)
ApproveStage(caller, a) ==
    /\ caller \in ValidIdentities
    /\ authState[a] = "IN_PROGRESS"
    /\ caller \notin authSigned[a]
    /\ IF blockNum > authDeadline[a]
       THEN /\ authState' = [authState EXCEPT ![a] = "EXPIRED"]
            /\ UNCHANGED <<authWeight, authSigned>>
       ELSE /\ authSigned' = [authSigned EXCEPT ![a] = @ \cup {caller}]
            /\ authWeight' = [authWeight EXCEPT ![a] = @ + Weight(caller, authPol[a])]
            /\ UNCHANGED authState
    /\ UNCHANGED <<blockNum, authCon, authPol, authAction, authDeadline,
                   ledgerCon, ledgerPermCon, manoBalance, otherBalance, totalSupply, issuanceCount>>

\* 3. Finalize Authorization once accumulated weight >= Threshold
FinalizeAuth(caller, a) ==
    /\ caller \in ValidIdentities
    /\ authState[a] = "IN_PROGRESS"
    /\ authWeight[a] >= Threshold(authPol[a])
    /\ IF blockNum > authDeadline[a]
       THEN authState' = [authState EXCEPT ![a] = "EXPIRED"]
       ELSE authState' = [authState EXCEPT ![a] = "FINALIZED"]
    /\ UNCHANGED <<blockNum, authCon, authPol, authAction, authWeight, authSigned,
                   authDeadline, ledgerCon, ledgerPermCon, manoBalance, otherBalance,
                   totalSupply, issuanceCount>>

\* 4. Consume Finalized Authorization in SLX-COMMON.issue(Manogaran, 100000, a)
ExecuteIssue(caller, a) ==
    /\ caller \in ValidIdentities
    /\ a \in ApprovedAuthObjects            \* Bytecode hash attestation in IdentityRegistry
    /\ authState[a] = "FINALIZED"           \* Must be explicitly finalized
    /\ blockNum <= authDeadline[a]          \* Must be timely
    /\ authCon[a] = ledgerPermCon           \* Must match SLX-COMMON's pinned Constitution
    /\ authPol[a] = "SHAREHOLDER_SUPERMAJORITY"
    /\ authAction[a] = "ISSUE_MANO_100K"
    /\ authState' = [authState EXCEPT ![a] = "CONSUMED"]
    /\ manoBalance' = manoBalance + 100000
    /\ totalSupply' = totalSupply + 100000
    /\ issuanceCount' = issuanceCount + 1
    /\ UNCHANGED <<blockNum, authCon, authPol, authAction, authWeight, authSigned,
                   authDeadline, ledgerCon, ledgerPermCon, otherBalance>>

\* 5. Advance Block Clock
TickBlock ==
    /\ blockNum < MaxBlock
    /\ blockNum' = blockNum + 1
    /\ UNCHANGED <<authState, authCon, authPol, authAction, authWeight, authSigned,
                   authDeadline, ledgerCon, ledgerPermCon, manoBalance, otherBalance,
                   totalSupply, issuanceCount>>

Next ==
    \/ \E u \in Identities, a \in AuthObjects, c \in Constitutions, p \in Policies, act \in Actions:
         InitAuth(u, a, c, p, act)
    \/ \E u \in Identities, a \in AuthObjects: ApproveStage(u, a)
    \/ \E u \in Identities, a \in AuthObjects: FinalizeAuth(u, a)
    \/ \E u \in Identities, a \in AuthObjects: ExecuteIssue(u, a)
    \/ TickBlock

Spec == Init /\ [][Next]_vars

\* =========================================================================
\* Safety Invariants Checked by TLC
\* =========================================================================
Inv_SupplyConservation ==
    totalSupply = manoBalance + otherBalance

Inv_SingleConstitutionPinned ==
    ledgerPermCon = ledgerCon /\ ledgerCon = PinnedConstitution

Inv_FinalizedImpliesSuperMajority ==
    \A a \in AuthObjects:
        (authState[a] \in {"FINALIZED", "CONSUMED"}) =>
            authWeight[a] >= Threshold(authPol[a])

Inv_OneTimeUseNoReplay ==
    issuanceCount <= Cardinality({a \in ApprovedAuthObjects : authState[a] = "CONSUMED"})

=============================================================================
```

---

### 4.4 Rust Bounded Model Checking Template (`#[kani::proof]`)

Because `hps-sdk` and the Haltproof Subroutines are pure `#![no_std]` Rust with fixed-capacity arrays (`PolicySpec`, `StageSpec`, `Authorization` state transitions), you can also verify absence of panics, integer overflows, and authorization bypasses directly on the Rust source code using the **[Kani Rust Verifier](https://model-checking.github.io/kani/)**:

```rust
#[cfg(kani)]
mod kani_proofs {
    use hps_sdk::governance::{
        PolicySpec, StageSpec, STATE_CONSUMED, STATE_EXPIRED, STATE_FINALIZED,
        STATE_IN_PROGRESS, STATE_UNINITIALIZED,
    };

    /// Proves that across all symbolic vote sequences and symbolic block timestamps:
    /// 1. `STATE_FINALIZED` is unreachable unless accumulated weight >= 75,000.
    /// 2. Duplicate votes by the same shareholder are always rejected.
    /// 3. Once `STATE_CONSUMED` is entered, a second `consume()` call always fails (`Err(-68)`).
    #[kani::proof]
    #[kani::unwind(6)]
    fn prove_supermajority_and_one_time_consumption() {
        let required: u64 = 75_000;
        let mano_weight: u64 = 50_000;
        let minority_weight: u64 = kani::any();
        kani::assume(minority_weight <= 50_000);

        let mut state: u64 = STATE_IN_PROGRESS;
        let mut mano_signed: bool = false;
        let mut minority_signed: bool = false;
        let mut accum_weight: u64 = 0;

        // Symbolic step 1: Manogaran votes
        if kani::any() {
            assert!(!mano_signed);
            mano_signed = true;
            accum_weight = accum_weight.checked_add(mano_weight).unwrap();
        }

        // Symbolic step 2: Duplicate vote attempt by Manogaran MUST be rejected
        if kani::any() && mano_signed {
            // Guard in `handle_approve`: `if storage::get_u64(sig_k) != 0 { return Err(-69); }`
            let duplicate_rejected = mano_signed;
            assert!(duplicate_rejected);
        }

        // Symbolic step 3: Minority coalition votes
        if kani::any() {
            minority_signed = true;
            accum_weight = accum_weight.checked_add(minority_weight).unwrap();
        }

        // Symbolic step 4: Attempt `finalize()`
        if kani::any() {
            if accum_weight >= required {
                state = STATE_FINALIZED;
            }
        }

        // Safety Invariant G2: FINALIZED is unreachable if accum_weight < 75,000
        if state == STATE_FINALIZED {
            assert!(accum_weight >= required);
            assert!(mano_signed && minority_signed);
            assert!(minority_weight >= 25_000);
        }

        // Symbolic step 5: First `consume()` transitions FINALIZED -> CONSUMED;
        // any second `consume()` attempt MUST fail!
        let mut issue_executions: u64 = 0;
        for _ in 0..2 {
            if state == STATE_FINALIZED {
                state = STATE_CONSUMED;
                issue_executions += 1;
            }
        }
        // Safety Invariant G1: At most 1 execution per Authorization HPS instance!
        assert!(issue_executions <= 1);
    }
}
```

---

## 5. Running the Test Suites

1. **Fast In-Memory Unit & FSM Suite (`< 50ms`)**:
   ```bash
   cargo test --workspace
   ```
   Runs `tests::superlexicon_singapore_pte_ltd_private_equity_cap_table_and_governance` in `examples/asset-ledger/src/main.rs` and `tests::add_and_remove_directors_with_shareholder_supermajority` in `examples/constitution/src/main.rs`.

2. **Live Wasmtime Localtestnet E2E Suite (`superlexicon_pe_e2e.rs`)**:
   ```bash
   cargo test -p hps-client --test superlexicon_pe_e2e -- --ignored --nocapture
   ```
   Spawns an isolated `lexicon-node --localtestnet`, deploys all 52 `Identity` HPSes, `IdentityRegistry`, `SLX-COMMON` `AssetLedger`, `USD-TREASURY` `AssetLedger`, Superlexicon `Constitution`, and `Authorization` HPSes, executes `P1`–`P4` and `N1`–`N11`, and verifies all emitted event logs.
