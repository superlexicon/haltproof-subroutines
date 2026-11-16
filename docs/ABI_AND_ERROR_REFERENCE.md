# Haltproof Subroutines ABI & Error Reference

Complete ABI function signatures, WASM artifact sizes, and canonical error codes across all **11 reference Haltproof Subroutines**.

---

## 1. Compiled WASM Artifact Inventory

| Crate (`examples/*`) | Artifact (`dist/*.wasm`) | Bytecode Size | Purpose |
| :--- | :--- | :---: | :--- |
| `corporate-charter` | `corporate_charter.wasm` | `58,355 B` | Ratification state, authorized share classes, organs, roles, `PolicySpec`s, `(targetHps, fnSelector) -> policyId`, authorized module capabilities |
| `asset-ledger` | `asset_ledger.wasm` | `46,626 B` | Verified-identity fungible share / bank / futures ledger with single-Charter pinning, 3-step auction clearing, and attachable `DexClob` |
| `authorization` | `authorization.wasm` | `38,733 B` | Stateful multi-stage sequential, weighted, role-backed, shareholder-vote, and 3-step call-auction authorization engine |
| `dex-clob` | `dex_clob.wasm` | `34,368 B` | MEV-proof discrete-time FIFO central limit orderbook (Two-Tier Static AVL Price-Level Tree + cohort pro-rata clearing) |
| `identity` | `identity.wasm` | `33,890 B` | EOA + delegate controlled on-chain Identity HPS (`msg_sender()` root for all institutional calls) |
| `product-ledger` | `product_ledger.wasm` | `28,186 B` | Commercial SKU catalog, direct role/policy pricing & restock, and operating-revenue checkout |
| `share-capital` | `share_capital.wasm` | `26,864 B` | Share-backed futures underwriting and 3-step share-transfer call-auction brokerage with segregated `shareEscrowAccount` |
| `identity-registry` | `identity_registry.wasm` | `19,209 B` | Active/suspended/revoked `Identity` directory + WASM `code_hash` attestation for `Identity` & `Authorization` |
| `accounting-ledger` | `accounting_ledger.wasm` | `14,935 B` | Passive append-only sales & revenue accounting journal |
| `asset-pair-otc` | `asset_pair_otc.wasm` | `12,195 B` | Atomic Delivery-vs-Payment Over-The-Counter ask book |
| `messaging` | `messaging.wasm` | `4,460 B` | High-TPS channel messaging subroutine |

---

## 2. Entrypoint Signatures by Subroutine

### 2.1 `CorporateCharter` (`examples/corporate-charter`)
- **Initialization & Lifecycle**:
  - `initialize(address registry, bytes policiesBlob)`
  - `initializeWithGovernance(address registry, bytes rolesBlob, bytes policiesBlob, bytes functionAuthsBlob, bytes shareClassesBlob)`
  - `initializeWithGovernance(address registry, bytes rolesBlob, bytes policiesBlob, bytes functionAuthsBlob, bytes shareClassesBlob, bytes modulesBlob)`
  - `activateCharter(address shareholderAuth) -> bool`
  - `state() -> uint64` (`0 = UNINITIALIZED`, `1 = PENDING_RATIFICATION`, `2 = ACTIVE`)
  - `isActive() -> bool`, `isValid() -> bool`, `activatedAtBlock() -> uint64`, `identityRegistry() -> address`
- **Scoped Per-Function Authority & Module Capabilities**:
  - `setFunctionAuth(address targetHps, bytes4 fnSelector, bytes32 policyId, address authObj) -> bool`
  - `getFunctionAuth(address targetHps, bytes4 fnSelector) -> bytes32`
  - `authorizeModule(address moduleHps, bytes32 capability, bool active, address authObj) -> bool`
  - `isAuthorizedModule(address moduleHps, bytes32 capability) -> bool`
- **Roles & Board of Directors**:
  - `defineRole(bytes32 roleId, address authObj) -> uint64`
  - `isRoleDefined(bytes32 roleId) -> bool`, `definedRoleCount() -> uint64`, `definedRoleAt(uint64 idx) -> bytes32`
  - `grantRole(bytes32 roleId, address account, address authObj) -> uint64`
  - `revokeRole(bytes32 roleId, address account, address authObj) -> uint64`
  - `hasRole(bytes32 roleId, address account) -> bool`, `roleMemberCount(bytes32 roleId) -> uint64`, `roleMemberAt(bytes32 roleId, uint64 idx) -> address`
  - `addDirector(address director, address authObj) -> uint64`, `removeDirector(address director, address authObj) -> uint64`
  - `isDirector(address candidate) -> bool`, `directorCount() -> uint64`
- **Policies & Share Capital Structure**:
  - `setPolicy(address targetHps, bytes32 policyId, bytes rawSpec, address authObj) -> bool`
  - `deactivatePolicy(address targetHps, bytes32 policyId, address authObj) -> bool`
  - `getPolicyRaw(address targetHps, bytes32 policyId) -> bytes`, `hasPolicy(address targetHps, bytes32 policyId) -> bool`
  - `registerShareClass(address shareLedger, uint64 votesPerShare, uint64 conversionNumer, uint64 conversionDenom, address authObj) -> uint64`
  - `shareClassCount() -> uint64`, `getShareClass(uint64 idx) -> (address, uint64, uint64, uint64)`
  - `shareholderVotingPower(address voter) -> (uint64 voterPower, uint64 totalPower, uint64 reqSupermajority, uint64 voterConvertedCommon)`
  - `convertedCommonTotals(address shareholder) -> (uint64 holderConvertedCommon, uint64 companyTotalConvertedCommon)`
- **Action-Hash Views**:
  - `hashActivateCharter() -> bytes32`
  - `hashSetFunctionAuth(address,bytes4,bytes32) -> bytes32`
  - `hashAuthorizeModule(address,bytes32,bool) -> bytes32`
  - `hashDefineRole(bytes32) -> bytes32`, `hashGrantRole(bytes32,address) -> bytes32`, `hashRevokeRole(bytes32,address) -> bytes32`
  - `hashSetPolicy(address,bytes32,bytes) -> bytes32`, `hashDeactivatePolicy(address,bytes32) -> bytes32`
  - `hashAddDirector(address) -> bytes32`, `hashRemoveDirector(address) -> bytes32`
  - `hashRegisterShareClass(address,uint64,uint64,uint64) -> bytes32`

### 2.2 `ShareCapital` (`examples/share-capital`)
- `initialize(address registry, address charter, address bankLedger, address shareEscrowAccount) -> bool`
- `setShareEscrowAccount(address bankLedger, address shareEscrowAccount, address authObj) -> bool`
- `associatedCharter() -> address`, `identityRegistry() -> address`, `bankLedger() -> address`, `shareEscrowAccount() -> address`
- `authorizeFuturesUnderwriting(address futuresLedger, uint64 underwritePct, address authObj) -> uint64`
- `underwriteFutures(uint64 amount) -> uint64`, `closeUnderwrittenFutures(uint64 amount) -> uint64`
- `futuresLedger() -> address`, `futuresUnderwritePct() -> uint64`, `futuresUnderwrittenBy(address) -> uint64`
- `futuresAllowanceOf(address shareholder) -> (uint64 convertedCommon, uint64 maxAllowance, uint64 alreadyUnderwritten, uint64 remaining, uint64 companyCap)`
- `placeBuyOrder(address authObj, uint64 price, uint64 quantity) -> uint64`
- `cancelBuyOrder(address authObj, uint64 orderIndex) -> uint64`
- `placeSellOrder(address authObj, uint64 price, uint64 quantity) -> uint64`
- `settleShareTransferAuction(address shareLedger, address authObj) -> (uint64 clearingPrice, uint64 matchedQty, uint64 buyDemand, uint64 sellSupply)`
- `hasEscrowedAuction(address authObj) -> bool`, `escrowedCashOf(address authObj) -> uint64`, `disburseAuctionCash(address,address,uint64,bool) -> bool`
- `hashSetShareEscrowAccount(address,address) -> bytes32`, `hashAuthorizeFuturesUnderwriting(address,uint64) -> bytes32`

### 2.3 `Authorization` (`examples/authorization`)
- `initializeFromCharter(address registry, address charter, address targetHps, bytes32 policyId, bytes32 actionHash) -> bool`
- `initializeTransferAuction(address registry, address charter, address targetShareLedger) -> bool`
- `initializeOracle(address registry, address oracleId, address targetHps, bytes32 actionHash, uint64 expiryBlocks) -> bool`
- `initializeCustom(address registry, address targetHps, bytes32 policyId, bytes32 actionHash, bytes rawSpec) -> bool`
- `approve() -> bool`, `finalize() -> bool`, `approveAndFinalize() -> bool`
- `placeBuyOrder(uint64,uint64) -> uint64`, `cancelBuyOrder(uint64) -> (uint64,uint64)`, `placeSellOrder(uint64,uint64) -> uint64`
- `placeBuyOrderFor(address,uint64,uint64) -> uint64`, `cancelBuyOrderFor(address,uint64) -> (uint64,uint64)`, `placeSellOrderFor(address,uint64,uint64) -> uint64`
- `consume(address expectedCharter, bytes32 expectedPolicyId, bytes32 expectedActionHash, address invokerIdentity) -> bool`
- `consumeAuction(address expectedCharter, bytes32 expectedPolicyId, address invokerIdentity) -> bytes`
- Views: `status()`, `currentStage()`, `stageCount()`, `stageWeight(uint64)`, `deadlines()`, `auctionDeadlines()`, `orderCount()`, `getOrdersRaw()`, `isReadyToConsume()`, `targetHps()`, `charter()`, `policyId()`, `actionHash()`

### 2.4 `ProductLedger` (`examples/product-ledger`) & `AccountingLedger` (`examples/accounting-ledger`)
- **`ProductLedger`**:
  - `initialize(address registry, address charter, address accountingLedger, bytes initialProducts) -> bool`
  - `initializeWithBank(address registry, address charter, address accountingLedger, address operatingBankLedger, address operatingRevenueAccount, bytes initialProducts) -> bool`
  - `setOperatingAccount(address operatingBankLedger, address operatingRevenueAccount, address authObj) -> bool`
  - `upsertProduct(bytes32 productId, uint64 units, uint64 price, bytes name, address authObj) -> bool`
  - `restockProduct(bytes32 productId, uint64 unitsToAdd, uint64 newPrice, address authObj) -> uint64`
  - `setProductPrice(bytes32 productId, uint64 newPrice, address authObj) -> bool`
  - `buyProduct(bytes32 productId, uint64 quantity) -> uint64`
  - Views & hashes: `getProduct(bytes32)`, `unitsAvailableOf(bytes32)`, `latestPriceOf(bytes32)`, `productCount()`, `productIdAt(uint64)`, `associatedCharter()`, `accountingLedger()`, `operatingBankLedger()`, `operatingRevenueAccount()`, `hashSetOperatingAccount`, `hashUpsertProduct`, `hashRestockProduct`, `hashSetProductPrice`
- **`AccountingLedger`**:
  - `initialize(address registry, address charter, address initialProductLedger) -> bool`
  - `authorizeProductLedger(address productLedger, address boardAuth) -> bool`
  - `recordSale(bytes32 productId, address buyer, uint64 quantity, uint64 unitPrice, uint64 totalAmount) -> uint64`
  - Views: `isAuthorizedProductLedger(address)`, `totalRevenue()`, `totalUnitsSold()`, `saleCount()`, `getSale(uint64)`, `productSalesOf(bytes32)`, `buyerPurchasesOf(address)`, `associatedCharter()`, `hashAuthorizeProductLedger(address)`

### 2.5 `AssetLedger` (`examples/asset-ledger`) & `DexClob` (`examples/dex-clob`)
- **`AssetLedger`**:
  - `initialize(address registry, string symbol, uint64 decimals, bytes initialAllocations, bytes initialPermissions)`
  - `issue(address,uint64,address)`, `cancel(address,uint64,address)`, `transfer(address,address,uint64,address)`, `transferDirect(address,uint64)`, `approve(address,uint64,address)`, `transferFrom(address,address,uint64)`
  - `setPermission(bytes32,address,bytes32,address)`, `setAttachedDex(address,address)`, `dexTransfer(address,address,uint64)`
  - `charterModuleClearTransfer(address,address,uint64)`, `charterModuleIssue(address,uint64)`, `charterModuleCancel(address,uint64)`, `settleTransferAuction(address)`
  - Views & hashes: `balanceOf(address)`, `allowance(address,address)`, `totalSupply()`, `totalOutstanding()`, `holderCount()`, `decimals()`, `symbol()`, `associatedCharter()`, `attachedDex()`, `getPermission(bytes32)`, `lastAuctionSettlement()`, `hashIssue`, `hashCancel`, `hashTransfer`, `hashApprove`, `hashSetPermission`, `hashSetAttachedDex`
- **`DexClob`**:
  - `initialize(address registry, address baseAssetLedger, address quoteAssetLedger, address escrowIdentity) -> bool`
  - `placeBid(uint64 price, uint64 quantity) -> uint64`
  - `placeAsk(uint64 price, uint64 quantity) -> uint64`
  - `cancelOrder(uint64 orderId) -> uint64`
  - `matchBlock() -> (uint64 matchedBlock, uint64 clearingPrice, uint64 matchedVolume, uint64 ordersIngested)`
  - Views: `bestBidAsk()`, `orderOf(uint64)`, `bookCounts()`, `priceLevelDepth()`, `lastMatchSummary()`, `ledgers()`

---

## 3. Canonical Error Codes (`hps_sdk::governance`)

| Code | Constant | Meaning |
| :---: | :--- | :--- |
| `-3` | *(ABI decode)* | Malformed or truncated ABI calldata |
| `-14` | *(Zero/invalid param)* | Zero amount, zero address, or self-transfer |
| `-15` | *(Overflow)* | Checked integer arithmetic overflow |
| `-16` | *(Insufficient balance)* | Insufficient asset/bank/escrow balance |
| `-19` | `ERR_CHARTER_MISMATCH` | Single-`CorporateCharter` pinning violation or unauthorized module caller |
| `-63` | `ERR_NOT_STAGE_AUTHORIZER` / unconfigured account | Caller does not belong to active stage/role, or required bank/escrow account is not configured |
| `-64` | `ERR_ALREADY_SIGNED` | Duplicate approval by the same `Identity` in the same stage |
| `-65` | `ERR_AUTH_EXPIRED` | Stage deadline or overall process block deadline exceeded |
| `-66` | `ERR_WRONG_TARGET` / `ERR_POLICY_MISMATCH` | `Authorization` consumed by wrong target HPS, wrong Charter, wrong `policyId`, or wrong `actionHash` |
| `-67` | `ERR_AUTH_ALREADY_CONSUMED` | Replay attempt on a previously consumed one-time `Authorization` HPS |
| `-70` | `ERR_INVALID_IDENTITY` | Caller or subject is not an active `Identity` with approved WASM `code_hash` in `IdentityRegistry` |
| `-71` | `ERR_AUTH_CONSUME_FAILED` | Missing or invalid `Authorization` object |
| `-72` | `ERR_POLICY_INVALID` | Malformed `PolicySpec` or target policy does not exist in `CorporateCharter` |
| `-73` | `ERR_UNAPPROVED_CODE_HASH` | Unapproved `Identity` or `Authorization` WASM bytecode hash |
| `-74` | `ERR_WRONG_AUCTION_STEP` | Order or cancellation submitted outside its permitted 3-step call-auction window |
| `-75` | `ERR_NOT_EXISTING_SHAREHOLDER` | Step 2 sell order or Step 3 buy order attempted by non-shareholder |
| `-76` | `ERR_STEP2_SELLER_INELIGIBLE_STEP3` | Shareholder who offered shares in Step 2 attempted to bid in Step 3 |
| `-77` | `ERR_NO_CROSSING_ORDERS` | No crossing bid/ask orders at auction settlement |
| `-81` | `ERR_PRODUCT_NOT_FOUND` | Unknown or inactive product SKU in `ProductLedger` |
| `-82` | `ERR_INSUFFICIENT_PRODUCT_UNITS` | Requested purchase quantity exceeds `unitsAvailable` |
| `-84` | `ERR_UNAUTHORIZED_SALES_RECORDER` | Unauthorized caller attempted `AccountingLedger.recordSale` |
| `-85` | `ERR_MISSING_ROLE` | Caller lacks the required role in `CorporateCharter` |
| `-86` | `ERR_INVALID_FUTURES_CONFIG` | Invalid `futuresLedger`, unpinned Charter, or invalid `underwritePct` |
| `-87` | `ERR_FUTURES_CAP_EXCEEDED` | Futures underwriting exceeds shareholder's or company's converted common-share cap |
| `-88` | `ERR_DEX_NOT_ATTACHED` | Caller is not the `AssetLedger`'s attached `DexClob` |
| `-89` | `ERR_ORDERBOOK_FULL` | Static AVL price-level arena or order pool at max capacity |
| `-91` | `ERR_CHARTER_NOT_ACTIVE` | `CorporateCharter` has not yet passed its First Shareholder Resolution (`state != ACTIVE`) |
| `-92` | `ERR_CHARTER_ALREADY_ACTIVE` | `activateCharter` called on an already-active `CorporateCharter` |
| `-93` | `ERR_ROLE_NOT_DEFINED` | `PolicySpec` or `grantRole` references an undefined `roleId` in `CorporateCharter` |
| `-94` | `ERR_FUNCTION_AUTH_NOT_SET` | No authorization policy mapped for the target function selector |
| `-95` | `ERR_UNAUTHORIZED_MODULE` | Sibling module lacks the required capability in `CorporateCharter` |
