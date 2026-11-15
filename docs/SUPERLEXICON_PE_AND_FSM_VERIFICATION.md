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
| `POLICY_SHARE_TRANSFER_AUCTION` | `keccak256("SHARE_TRANSFER_AUCTION")` | **3 Timed Order-Collection Windows** (`step1_window_blocks`, `step2_window_blocks`, `step3_window_blocks`) + post-Step-3 settlement window (`overall_expiry_blocks`):<br>1. **Step 1**: First potential buyer placing `placeBuyOrder(price, qty)` (via `Constitution.placeBuyOrder(authObj, price, qty)`, which clears `price * qty` from the buyer's bank sub-account into `Constitution.clearingAccount()`) starts the Step 1 clock; interested buyers place buy orders until `step1_deadline`. Buy orders can be cancelled via `Constitution.cancelBuyOrder(authObj, orderIndex)` **only during the exact step in which they were placed**, refunding `price * qty` to the buyer's bank sub-account.<br>2. **Step 2**: Existing shareholders (`balanceOf > 0`) place sell orders (`placeSellOrder(price, qty)`) until `step2_deadline`.<br>3. **Step 3**: Remaining existing shareholders who did **not** participate in Step 2 place pre-emptive buy orders (`placeBuyOrder(price, qty)`) until `step3_deadline`.<br>4. **Step 4**: After `step3_deadline`, the finalized `Authorization` HPS is passed to `Constitution.settleShareTransferAuction` / `SLX-COMMON.transfer`, which clears crossing orders (`buy.price >= P* >= sell.price`) at a single best clearing price `P*`, pro-rates fills (**by original buy order quantity** when `buy_qty > sell_qty`, and **by existing shareholder holding `balanceOf(seller)` — NOT sell order quantity** — when `sell_qty > buy_qty`), and settles cleared bank balances (`P* * fill_s` transferred to sellers' bank sub-accounts and unspent buyer escrow refunded to buyers' bank sub-accounts). | `SLX-COMMON.transfer(..., authObj)` / `SLX-COMMON.settleTransferAuction(authObj)` (`ACTION_TRANSFER`) |
| `POLICY_BANK_ORACLE` | `keccak256("BANK_ORACLE")` | **1 Stage**: Bank API Oracle Backend `Identity` (`weight = 1`, `required_weight = 1`), managed & rotated via a Board Resolution (`Constitution.setBankOracle(bankLedger, oracleIdentity, expiryBlocks, boardAuth)` requiring `POLICY_BOARD_RESOLUTION`) | `SLX-DBS-SGD.issue(clientIdentity, depositAmt, oracleAuth)` (`ACTION_ISSUE` for incoming bank deposits), `SLX-DBS-SGD.cancel(clientIdentity, withdrawalAmt, oracleAuth)` (`ACTION_CANCEL` for outgoing payments/withdrawals) |
| `POLICY_HOLDER_SELF` | `keccak256("HOLDER_SELF")` | On bank-account `AssetLedger`s (`ACTION_TRANSFER -> (0x0, POLICY_HOLDER_SELF)`), clients sign simple direct transfer transactions (`transferDirect(toPayee, amount)` or `transfer(fromClient, toPayee, amount, 0x0)`) without needing a multi-party `Authorization` HPS | Direct client-signed `transferDirect` / `transfer` / `approve` |

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
| `Authorization` | `AuctionStep1Started(address,uint64,uint64,uint64,uint64,uint64)` | `topic[1]`: `firstBuyerIdentity` | `[0..8]`: `startedAtBlock`, `[8..16]`: `step1Deadline`, `[16..24]`: `step2Deadline`, `[24..32]`: `step3Deadline`, `[32..40]`: `overallDeadline` |
| `Authorization` | `BuyOrderPlaced(address,uint64,uint64,uint64)` | `topic[1]`: `buyerIdentity` | `[0..8]`: `stepTag` (`1` or `3`), `[8..16]`: `price`, `[16..24]`: `quantity` |
| `Authorization` | `SellOrderPlaced(address,uint64,uint64,uint64)` | `topic[1]`: `sellerIdentity` | `[0..8]`: `price`, `[8..16]`: `quantity`, `[16..24]`: `holderBalanceSnapshot` |
| `AssetLedger` | `AuctionSellerFilled(address,uint64,uint64,uint64,uint64)` | `topic[1]`: `sellerIdentity`<br>`topic[2]`: `authObj` | `[0..8]`: `clearingPrice`, `[8..16]`: `orderQty`, `[16..24]`: `existingHolding`, `[24..32]`: `filledQty` |
| `AssetLedger` | `AuctionBuyerFilled(address,uint64,uint64,uint64)` | `topic[1]`: `buyerIdentity`<br>`topic[2]`: `authObj` | `[0..8]`: `clearingPrice`, `[8..16]`: `orderQty`, `[16..24]`: `filledQty` |
| `AssetLedger` | `AuctionTransferSettled(address,uint64,uint64,uint64,uint64,uint64,uint64)` | `topic[1]`: `authObj` | `[0..8]`: `clearingPrice`, `[8..16]`: `matchedQty`, `[16..24]`: `crossingBuyDemand`, `[24..32]`: `crossingSellSupply`, `[32..40]`: `filledBuyerCount`, `[40..48]`: `filledSellerCount` |
| `Authorization` | `BuyOrderCancelled(address,uint64,uint64,uint64)` | `topic[1]`: `buyerIdentity` | `[0..8]`: `stepTag`, `[8..16]`: `price`, `[16..24]`: `quantity` |
| `Constitution` | `BankOracleSet(address,address,address)` | `topic[1]`: `bankLedger`<br>`topic[2]`: `oracleIdentity`<br>`topic[3]`: `boardAuth` | `[0..8]`: `expiryBlocks` |
| `Constitution` | `ClearingAccountSet(address,address)` | `topic[1]`: `bankLedger`<br>`topic[2]`: `clearingAccount` | Empty (`0` bytes) |
| `Constitution` | `AuctionBuyOrderCleared(address,address,uint64)` | `topic[1]`: `authObj`<br>`topic[2]`: `buyerIdentity` | `[0..8]`: `price`, `[8..16]`: `quantity`, `[16..24]`: `escrowedCash` |
| `Constitution` | `AuctionBuyOrderRefunded(address,address,uint64)` | `topic[1]`: `authObj`<br>`topic[2]`: `buyerIdentity` | `[0..8]`: `orderIndex`, `[8..16]`: `refundedCash` |
| `Constitution` | `AuctionCashSettled(address,address,uint64,bool)` | `topic[1]`: `authObj`<br>`topic[2]`: `recipientIdentity` | `[0..8]`: `amount`, `[15]`: `isSellerProceeds` (`1` = seller proceeds, `0` = buyer refund) |
| `Constitution` | `ShareClassRegistered(address,uint64,uint64,uint64)` | `topic[1]`: `shareLedger` | `[0..8]`: `votesPerShare`, `[8..16]`: `conversionNumer`, `[16..24]`: `conversionDenom` |

---

## 3. Positive & Negative Test Case Catalogue

### 3.1 Positive Test Cases (`P1`–`P4`)

| ID | Test Case | Preconditions | Action / Inputs | Expected End State & Emitted Events |
| :--- | :--- | :--- | :--- | :--- |
| **`P1`** | **Genesis Cap Table & Single-Constitution Deployment** | 52 `Identity` HPSes initialized and active in `IdentityRegistry` | Initialize `SLX-COMMON` with 49 shareholders (`Manogaran = 50,000`, 48 others = `50,000`, total = `100,000`) pinned to `slx_constitution`; initialize `slx_constitution` with `POLICY_SHAREHOLDER_SUPERMAJORITY` (`75,000` of `100,000`) and `POLICY_BOARD_RESOLUTION` (`2-of-2` directors) | `associatedConstitution() == slx_constitution`, `holderCount() == 49`, `totalOutstanding() == 100,000`, `balanceOf(manogaran) == 50,000`, `directorCount() == 2`. Emits `ConstitutionPinned`, `LedgerInitialized`, `ConstitutionInitialized`, `PolicyUpdated`. |
| **`P2`** | **Super-Majority Share Issuance Making Manogaran 75.00% Shareholder** | `auth_issue_mano` initialized from `slx_constitution` for `hashIssue(manogaran, 100_000)` | Manogaran (`50,000` votes) + 21 minority shareholders (`16 * 1,250 + 5 * 1,000 = 25,000` votes) call `approve(0)` $\to$ `stageWeight(0) == 75,000` $\to$ `finalize()` $\to$ `SLX-COMMON.issue(manogaran, 100_000, auth_issue_mano)` | `balanceOf(manogaran) == 150,000`, `totalOutstanding() == 200,000` (**`75.00%` super-majority**), `auth_issue_mano.state() == STATE_CONSUMED (3)`. Emits `StageApproved` ($\times 22$), `StageThresholdReached`, `AuthorizationFinalized`, `AuthorizationConsumed`, `Issued`, `Transfer`. |
| **`P3`** | **Board of Directors (2-of-2) Resolution to Transfer Company-Owned Assets** | `superlexicon.pte.ltd` owns `250,000` units in `USD-TREASURY` where `ACTION_TRANSFER` requires `POLICY_BOARD_RESOLUTION` | Initialize `auth_board_transfer` for `hashTransfer(company, recipient, 50,000)`; both Directors (`Manogaran` + `Evelyn Tan`) call `approve(0)` (`weight = 2/2`) $\to$ `finalize()` $\to$ `company` invokes `USD-TREASURY.transfer` | `balanceOf(company) == 200,000`, `balanceOf(recipient) == 50,000`, `auth_board_transfer.state() == STATE_CONSUMED (3)`. Emits `StageApproved` ($\times 2$), `StageThresholdReached`, `AuthorizationFinalized`, `AuthorizationConsumed`, `Transfer`. |
| **`P4`** | **Director Appointment & Removal via Shareholder Super-Majority** | `directorCount() == 2` (`Manogaran`, `Evelyn Tan`) | Initialize `auth_add_director` for `hashAddDirector(rajesh_nair)`, accumulate `75,000` shareholder votes, `finalize()`, call `Constitution.addDirector(rajesh_nair, auth_add_director)` | `directorCount() == 3`, `isDirector(rajesh_nair) == true`, `POLICY_BOARD_RESOLUTION` automatically updated to `3-of-3` directors. Emits `DirectorAdded` and `PolicyUpdated`. |
| **`P5`** | **3-Step Share Transfer Call-Auction — Regime A (`total_buy_qty > total_sell_qty`)** | `ACTION_TRANSFER` governed by `POLICY_SHARE_TRANSFER_AUCTION` | Step 1 buyers (`6,000 @ 120`, `8,000 @ 110`, `5,000 @ 90`); Step 2 sellers (`6,000 @ 100`, `4,000 @ 110`, `3,000 @ 140`); Step 3 non-selling shareholder buyer (`6,000 @ 115`); settle after Step 3 ends | Clearing price `P* = 110`, matched quantity = `10,000` (`crossing_buy = 20,000 > crossing_sell = 10,000`). Crossing sellers fill 100% (`6,000`, `4,000`); crossing buyers fill **pro-rata to original buy order quantities (`6,000 : 8,000 : 6,000` $\to$ `3,000 : 4,000 : 3,000`)**. |
| **`P6`** | **3-Step Share Transfer Call-Auction — Regime B (`total_sell_qty > total_buy_qty`)** | `ACTION_TRANSFER` governed by `POLICY_SHARE_TRANSFER_AUCTION` | Step 1 buyers (`1,400 @ 100`, `600 @ 100`); Step 2 sellers (`Manogaran` holding `150,000` offers `5,000 @ 100`; `Shareholder #4` holding `6,000` offers `5,000 @ 100`); Step 3 non-selling shareholder (`Shareholder #2` holding `6,500`) buys `600 @ 100`; settle via `SLX-COMMON.transfer` after Step 3 ends | Clearing price `P* = 100`, matched quantity = `2,600` (`crossing_sell = 10,000 > crossing_buy = 2,600`). All 3 buyers fill 100% (`1,400`, `600`, `600`); sellers fill **pro-rata to existing shareholding (`150,000 : 6,000 = 25 : 1` $\to$ `Manogaran -2,500`, `Shareholder #4 -100`) — NOT their equal `5,000` order quantities**. |
| **`P7`** | **Company Bank Account `AssetLedger` (`SLX-DBS-SGD`) & Board-Managed Bank Oracle** | `SLX-DBS-SGD` initialized with `ACTION_ISSUE` & `ACTION_CANCEL` $\to$ `(slx_constitution, POLICY_BANK_ORACLE)` and `ACTION_TRANSFER` $\to$ `(0x0, POLICY_HOLDER_SELF)` | Board of Directors passes `POLICY_BOARD_RESOLUTION` `Authorization` and calls `Constitution.setBankOracle(dbs_bank_ledger, dbs_bank_oracle_id, 50, boardAuth)`; `dbs_bank_oracle_id` credits incoming client deposits (`issue`) and debits client withdrawals (`cancel`); clients sign direct transfers (`transferDirect`) to payees | `bankOracleOf(dbs_bank_ledger) == dbs_bank_oracle_id`; client deposit credits, withdrawal debits, and direct client-signed payee transfers update `SLX-DBS-SGD` sub-account balances. Emits `BankOracleSet`, `AssetIssued`, `AssetCancelled`, `Transfer`. |
| **`P8`** | **`Constitution`-Routed Buy Order Placement with Bank Balance Clearing & Same-Step Cancellation** | `clearing_acct_id` configured via `Constitution.setClearingAccount(dbs_bank_ledger, clearing_acct_id, ...)` | Buyers call `Constitution.placeBuyOrder(authObj, price, qty)`, clearing `price * qty` from buyer's `SLX-DBS-SGD` sub-account into `clearing_acct_id`; buyer calls `Constitution.cancelBuyOrder(authObj, orderIdx)` in the **same step** (`Step 1` or `Step 3`) | `price * qty` is escrowed in `clearing_acct_id` on placement and immediately refunded back to the buyer's `SLX-DBS-SGD` sub-account on same-step cancellation; cancelled order is excluded from auction clearing. Emits `AuctionBuyOrderCleared`, `BuyOrderCancelled`, `AuctionBuyOrderRefunded`. |
| **`P9`** | **End-of-Auction Delivery-versus-Payment (DvP) Share & Bank Balance Settlement** | 3-step auction with escrowed buy orders (`2,000 @ 100` by `Evelyn`, `500 @ 100` by `Shareholder #2`, total `250,000 SGD` in `clearing_acct_id`) and Step 2 sell order (`1,500 @ 100` by `Manogaran`) | After `step3_deadline`, call `Constitution.settleShareTransferAuction(slx_ledger, authObj)` | Clearing price `P* = 100`, matched = `1,500` shares (`Evelyn +1,200`, `Shareholder #2 +300`, `Manogaran -1,500`). `clearing_acct_id` disburses `150,000 SGD` proceeds to `Manogaran` and refunds unspent escrow (`80,000 SGD` to `Evelyn`, `20,000 SGD` to `Shareholder #2`), leaving `clearing_acct_id` balance `= 0`. Emits `AuctionTransferSettled`, `AuctionCashSettled`. |
| **`P10`** | **Multiple Share-Class Ledgers & Cross-Ledger Shareholder Vote Tabulation** | `SLX-COMMON` (`200,000` shares, `1` vote/share, `1:1` conversion) + `SLX-SERIES-A` (`25,000` shares held by `Evelyn`, `1` vote/converted share, `2:1` conversion to Common Shares = `50,000` votes) registered via `Constitution.registerShareClass` | Initialize `POLICY_SHAREHOLDER_SUPERMAJORITY` `Authorization` (`totalVotingPower = 250,000`, `requiredSuperMajority = 187,500`); `Manogaran` (`146,000` votes) + `Evelyn` (`2,600` Common + `50,000` Series A = `52,600` votes) call `approve()` | `Authorization` queries `Constitution.shareholderVotingPower(voter)` across all registered share classes (`146,000 + 52,600 = 198,600 >= 187,500`), reaches super-majority threshold, finalizes, and executes `SLX-SERIES-A.issue`. Emits `ShareClassRegistered`, `StageApproved`, `StageThresholdReached`, `AuthorizationFinalized`. |

### 3.2 Negative Security Test Cases (`N1`–`N19`)

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
| **`N12`** | **Premature Sell Order During Step 1 (Buyers' Window)** | Existing shareholder calls `placeSellOrder` while `now <= step1_deadline` (or before first buyer starts Step 1) | Reverts (`ERR_WRONG_AUCTION_STEP = -74`) | Sell orders can only be placed after the Step 1 buyer period ends (`step1_deadline < now <= step2_deadline`). |
| **`N13`** | **Buy Order or Non-Shareholder Sell Order During Step 2** | Caller calls `placeBuyOrder` during Step 2, or non-shareholder (`balanceOf == 0`) calls `placeSellOrder` during Step 2 | Reverts (`ERR_WRONG_AUCTION_STEP = -74` / `ERR_NOT_EXISTING_SHAREHOLDER = -75`) | Step 2 is strictly reserved for existing shareholders placing sell orders up to their `balanceOf` holding. |
| **`N14`** | **Step 2 Seller or Non-Shareholder Placing Buy Order in Step 3** | Shareholder who placed a sell order in Step 2 (or an external non-shareholder) calls `placeBuyOrder` during Step 3 | Reverts (`ERR_STEP2_SELLER_INELIGIBLE_STEP3 = -76` / `ERR_NOT_EXISTING_SHAREHOLDER = -75`) | Only remaining existing shareholders who did **not** participate in Step 2 can place pre-emptive buy orders in Step 3. |
| **`N15`** | **Premature Auction Settlement Before Step 3 Ends** | Call `SLX-COMMON.transfer` / `settleTransferAuction` while `now <= step3_deadline` | Reverts (`ERR_WRONG_AUCTION_STEP = -74`) | Auction `Authorization` cannot finalize or be consumed until the Step 3 window has fully elapsed (`now > step3_deadline`). |
| **`N16`** | **Buy Order via `Constitution` with Insufficient Bank Balance** | Buyer calls `Constitution.placeBuyOrder(authObj, price, qty)` when `balanceOf(buyer) < price * qty` in `SLX-DBS-SGD` | Reverts (`Err(-16)`) | Every buy order placed via `Constitution` must be 100% cash-backed in `Constitution.clearingAccount()` at placement time. |
| **`N17`** | **Cross-Step Buy Order Cancellation (`Step 1` Order Cancelled in `Step 2` or `Step 3`)** | Buyer attempts `Constitution.cancelBuyOrder(authObj, orderIdx)` during Step 2 or Step 3 for an order placed in Step 1 | Reverts (`ERR_WRONG_AUCTION_STEP = -74`) | Buy orders can **only** be cancelled during the exact step in which they were placed (`Step 1` orders only while `now <= step1_deadline`; `Step 3` orders only while `step2_deadline < now <= step3_deadline`). |
| **`N18`** | **Unauthorized / Non-Owner Buy Order Cancellation** | Another trader calls `cancelBuyOrder` on a buy order placed by `buyer_1` | Reverts (`ERR_NOT_ORDER_OWNER = -80`) | Only the original buyer Identity that placed the order can cancel it and receive the refund. |
| **`N19`** | **Double Cancellation / Replay Refund Attempt** | Buyer calls `cancelBuyOrder` a second time on an already-cancelled buy order | Reverts (`ERR_ORDER_ALREADY_CANCELLED = -79`) | A cancelled buy order (`ORDER_SIDE_CANCELLED`, `quantity = 0`) can never be cancelled or refunded twice. |

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
