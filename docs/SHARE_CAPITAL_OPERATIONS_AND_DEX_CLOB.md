# Share Capital, Commercial Operations & MEV-Proof DEX CLOB Specification

This document details how corporate equity facilities (**`ShareCapital`**), commercial inventory & accounting (**`ProductLedger`** + **`AccountingLedger`**), underlying asset ledgers (**`AssetLedger`**), OTC settlement (**`AssetPair_OTC`**), and the discrete-time FIFO central limit orderbook (**`DexClob`**) compose around **`CorporateCharter`**.

---

## 1. Segregation of Duties & Segregated Cash Accounts

A core architectural invariant across the suite is strict legal and accounting separation between **governance**, **shareholder equity operations**, **commercial sales execution**, and **bookkeeping**:

| Subroutine | Domain | Bank / Custody Authority | Bookkeeping / State |
| :--- | :--- | :--- | :--- |
| **`CorporateCharter`** (`examples/corporate-charter`) | Constitutional Charter | **None** (holds zero bank or escrow accounts) | Ratification state, `ShareClassSpec`s, Directors, Roles, `PolicySpec`s, `(targetHps, fnSelector) -> policyId`, authorized module capabilities |
| **`ShareCapital`** (`examples/share-capital`) | Equity & Share Facilities | **`shareEscrowAccount`** (`CAP_EQUITY_SETTLEMENT`) — holds **only** third-party buyer bids during 3-step share-transfer call auctions | Per-shareholder underwritten futures balances & per-auction buyer cash escrow |
| **`ProductLedger`** (`examples/product-ledger`) | Commercial Catalog & Checkout | **`operatingRevenueAccount`** (`CAP_MERCHANT_PAYMENT`) — collects customer product payments into company operating revenue | SKU catalog (`unitsAvailable`, `latestPrice`, `totalUnitsSold`) |
| **`AccountingLedger`** (`examples/accounting-ledger`) | General / Sales Journal | **None** (pure read/append system of record; cannot move funds or appoint bank oracles) | Immutable `SaleRecord` audit log, `totalRevenue`, per-product & per-buyer aggregates |
| **`AssetLedger`** (`examples/asset-ledger`) | Token / Share / Bank / Futures Ledger | Enforces single-`CorporateCharter` pinning; deposits/withdrawals on bank ledgers require `POLICY_BANK_ORACLE` (`ROLE_BANK_ORACLE`) | Verified `Identity -> u64` balances, allowances, permissions, attached `DexClob` |

---

## 2. `ShareCapital` (`examples/share-capital`)

`ShareCapital` (`27 KB` WASM) is pinned to a single `IdentityRegistry` and `CorporateCharter`, requiring `CorporateCharter.state() == CHARTER_STATE_ACTIVE` on every mutation.

### 2.1 Share-Backed Futures Underwriting
Allows shareholders across **any** registered share class (Common, Preferred Class A, Series B, etc.) to underwrite units of a single-class futures `AssetLedger` up to a constitutionally authorized percentage of converted common shares:

1. **Constitutional Authorization**:
   - Shareholders pass a Super-Majority `Authorization` bound to `ShareCapital` for `hashAuthorizeFuturesUnderwriting(futuresLedger, underwritePct)`.
   - `ShareCapital.authorizeFuturesUnderwriting(futuresLedger, underwritePct, authObj)` verifies `futuresLedger.associatedCharter() == charter`, consumes `authObj`, and stores `(futuresLedger, underwritePct)` (`1..=100` whole `%`, or `101..=10_000` basis points).
2. **Per-Shareholder & Company-Wide Allowance Formula**:
   - Queries `(holderCommon, companyTotalCommon) = CorporateCharter.convertedCommonTotals(caller)`.
   - Maximum futures units `caller` may have open simultaneously:
     $$\text{maxAllowance}(\text{caller}) = \left\lfloor \frac{\text{holderCommon} \times \text{pct}}{\text{denom}} \right\rfloor, \qquad \text{companyCap} = \left\lfloor \frac{\text{companyTotalCommon} \times \text{pct}}{\text{denom}} \right\rfloor$$
   - **Worked Example**: Suppose `underwritePct = 10` ($10\%$) and a shareholder holds **only** `100,000` Preferred Shares Class A with a `50%` conversion rate to Common Shares (`conversionNumer = 1, conversionDenom = 2`) and `0` Common Shares:
     - $\text{holderCommon} = 100{,}000 \times 1 / 2 = 50{,}000$ common-equivalent shares.
     - $\text{maxAllowance} = 10\% \times 50{,}000 = 5{,}000$ futures contract units.
     - Calling `underwriteFutures(5_000)` mints `5,000` units on `futuresLedger` via `charterModuleIssue`; attempting `underwriteFutures(1)` thereafter reverts with `ERR_FUTURES_CAP_EXCEEDED (-87)`.
3. **Closing Positions**:
   - `closeUnderwrittenFutures(amount)` burns `amount` from the caller's balance on `futuresLedger` via `charterModuleCancel` and restores `amount` of underwriting allowance.

### 2.2 Restricted 3-Step Share-Transfer Call Auction (Pre-Emptive Rights / ROFR)
Private-equity share `AssetLedger`s bind `ACTION_TRANSFER` to `POLICY_SHARE_TRANSFER_AUCTION`:

1. **Window 1 (Initial Buyer Bids — `placeBuyOrder`)**:
   - First buyer starts the 3-window clock (`step1_dl`, `step2_dl`, `step3_dl`).
   - `ShareCapital.placeBuyOrder(authObj, price, quantity)` atomically transfers `price * quantity` from `buyer` into `ShareCapital`'s segregated **`shareEscrowAccount`** on `bankLedger` before recording the bid in `authObj`.
   - Buyers may cancel a Window 1 bid **only during Window 1** (`cancelBuyOrder`), receiving an immediate refund from `shareEscrowAccount`.
2. **Window 2 (Existing Shareholder Sell Offers — `placeSellOrder`)**:
   - Existing shareholders (`balanceOf(seller) > 0`) offer up to their current share balance. Buy orders and Window 1 cancellations are rejected (`ERR_WRONG_AUCTION_STEP = -74`).
3. **Window 3 (Non-Selling Existing Shareholder Pre-Emptive Bids — `placeBuyOrder`)**:
   - Existing shareholders who did **not** place a sell order in Window 2 (`ERR_STEP2_SELLER_INELIGIBLE_STEP3 = -76`) may place matching/higher buy bids (escrowed into `shareEscrowAccount`) and cancel Window 3 bids only within Window 3.
4. **Single-Price Pro-Rata Settlement (`settleShareTransferAuction`)**:
   - Once `block_number > step3_dl`, `ShareCapital.settleShareTransferAuction(shareLedger, authObj)` triggers `shareLedger.settleTransferAuction(authObj)`:
     - Computes the single clearing price $P^*$ maximizing matched volume $\min(D(P), S(P))$.
     - If supply exceeds demand ($S(P^*) > D(P^*)$), sellers are pro-rated proportionally to their **existing shareholdings**; if demand exceeds supply ($D(P^*) > S(P^*)$), buyers are pro-rated proportionally to their **order quantities**.
     - `shareLedger` calls back `ShareCapital.disburseAuctionCash(...)` to pay `P* * filledQty` from `shareEscrowAccount` to filled sellers and refund `(limitPrice * orderQty) - (P* * filledQty)` to buyers, returning `shareEscrowAccount` for that auction to `0`.

---

## 3. Commercial Operations (`ProductLedger` + `AccountingLedger`)

1. **Direct Role & Policy Governance**:
   - Catalog operations (`upsertProduct`, `restockProduct`, `setProductPrice`) are invoked directly on `ProductLedger`.
   - `ProductLedger` queries `CorporateCharter.getFunctionAuth(self, fnSelector)`:
     - By default (`POLICY_PRODUCT_MANAGEMENT`), an `Identity` holding `ROLE_PRODUCT_MANAGER` can either pass a finalized one-time `Authorization` object or execute directly (`authObj = 0x0`).
     - If shareholders rotate `(productLedger, selector)` via `CorporateCharter.setFunctionAuth` to a multi-stage policy (for example, `Stage 0: ROLE_PRODUCT_MANAGER` $\to$ `Stage 1: ROLE_CFO`), `ProductLedger` enforces full `Authorization` consumption and rejects `authObj = 0x0`.
2. **Immediate-Fulfilment Checkout (`buyProduct`)**:
   - Clears `quantity * latestPrice` from `buyer` directly into `ProductLedger`'s `operatingRevenueAccount` on `operatingBankLedger` (`CAP_MERCHANT_PAYMENT`), decrements `unitsAvailable`, and appends a `SaleRecord` to `AccountingLedger`.
   - Does **not** write to `CorporateCharter` or `ShareCapital`, enabling parallel execution alongside governance and equity transactions on `lexicon-node`.

---

## 4. MEV-Proof Discrete-Time FIFO Central Limit Orderbook (`DexClob`)

`DexClob` (`examples/dex-clob`, `34.4 KB` WASM) is a standalone exchange matching engine attachable to **any** `AssetLedger` (shares, futures contracts, commodities, stablecoins) via `AssetLedger.setAttachedDex(dexHps, superAuth)`.

### 4.1 MEV-Proof Intra-Block Permutation Invariance
- Traders submit `placeBid(price, quantity)` (escrowing `price * quantity` quote asset) and `placeAsk(price, quantity)` (escrowing `quantity` base asset) into an append-only staging queue tagged with `ord.block_number = context::block_number()`.
- When `matchBlock()` is called in block $B$:
  - **Strict Past-Block Cutoff**: Only staged orders with `ord.block_number < B` are ingested into the active book. Orders submitted in block $B$ wait until block $\ge B + 1$.
  - **Equal Priority Within `(price, block_number)` Cohorts**: Orders at the same price from the same block are **never** ranked by intra-block transaction index (`order_id`). Reordering transactions inside a block cannot change who fills or at what price.

### 4.2 Two-Tier Static Arena AVL Price-Level Tree (`O(log P)` Insertion, `O(1)` Queue Append)
Instead of shifting flat arrays on insert (`O(N)` storage movement), `DexClob` uses a zero-heap `#![no_std]` two-tier structure:
1. **Tier 1 (`PriceLevelArena`, `MAX_PRICE_LEVELS = 64` per side)**:
   - Intrusive **AVL balanced binary search tree** keyed by `price`, augmented with threaded `best_idx` / `next_better` / `prev_worse` pointers (`O(1)` best bid/ask lookup and ordered traversal) and an `O(1)` **free-list allocator** (`free_head`) that recycles exhausted price-level slots across arbitrary numbers of blocks.
2. **Tier 2 (`OrderBookSide`, `MAX_BOOK_ORDERS = 128` per side)**:
   - Intrusive **doubly-linked FIFO queue** (`head_order` $\to$ `tail_order`) within each `PriceLevelNode`. Because staged orders arrive monotonically by block height, appending to `tail_order` is `O(1)` with **zero** element shifting, and `cancelOrder` unlinks in `O(1)` and recycles the order slot onto `free_order_head`.

### 4.3 Clearing Price & Marginal Cohort Pro-Rata Allocation
1. **Single Clearing Price $P^*$**: Evaluates crossing price levels (`best_bid >= best_ask`), selecting $P^*$ that maximizes matched volume $V(P) = \min(D(P), S(P))$ (breaking ties by minimum imbalance $|D(P) - S(P)|$, then midpoint).
2. **Priority Fill**:
   - Better-priced levels fill `100%` first (bids descending from `best_bid`; asks ascending from `best_ask`).
   - Within the marginal price level, earlier `block_number` cohorts fill `100%` in strict FIFO block order.
   - If remaining volume $R$ is smaller than the marginal `(price, block_number)` cohort's total open quantity $C$, every order $i$ in that cohort receives exact integer-floor pro-rata allocation:
     $$\text{fill}_i = \left\lfloor \frac{R \times q_i}{C} \right\rfloor$$
     with any integer rounding dust (`< cohort_len` units) remaining resting in the cohort for the next block (preserving strict intra-block permutation invariance) and any price-improvement savings `(bid.price - P*) * fill_i` immediately refunded to the buyer.
