//! Self-Contained Codified IAS / IFRS Accounting Ledger **Haltproof Subroutine (HPS)** (`accounting-ledger`).
//!
//! Built on `hps_sdk::ifrs` for SuperLexicon's `code_hash`-deduplicated `WasmtimeAdapter`:
//! - **Zero Bytecode Duplication**: Uploaded once per subnet via `BYTECODE_STORE` and instantiated per
//!   company in 32 bytes (`code_hash`). All companies share one Cranelift-compiled `Arc<Module>` in
//!   validator RAM and execute 100% shard-parallel across companies with zero external rulebook subcalls.
//! - **Zero Creative Accounting**:
//!   1. No free-form `postManualJournal(Dr, Cr)` exists; every journal entry is derived exclusively
//!      through `hps_sdk::ifrs::BalancedBatch` (`sum(Dr) == sum(Cr)` enforced at the type level).
//!   2. **Virgin `treasuryIdentity` Exclusive Cash Custody**: `initialize(...)` directly invokes
//!      `treasuryIdentity.initializeWithNickname(self_address(), ...)` on an uninitialized `Identity`
//!      HFS (`KEY_INIT == 0`), proving zero prior owners or hidden delegates exist and making
//!      `AccountingLedger` the sole controller of outbound operating cash.
//!   3. **Inbound Cash Proof & `2900 Suspense` Quarantine**: Every `Dr 1010 Cash` verifies live
//!      `operatingBankLedger.balanceOf(treasuryIdentity) >= booked_cash + inflow`; unsolicited transfers
//!      into `treasuryIdentity` quarantine into `2900 Unattributed Cash Suspense` *(liability)*.
//!   4. **`HfsRegistry` Module `code_hash` Gate**: Sibling module hooks (`ProductLedger`, `ShareCapital`)
//!      must both hold Charter module authorization and match canonical `HfsRegistry` `code_hash`es.
//!   5. **Bilateral Counterparty Consent & `IAS 24` Anti-Wash-Sale Guard**: Credit invoices, leases, and
//!      term loans require counterparty `Identity` acceptance; related-party credit sales are banned and
//!      related-party cash flows are segregated into `4050 Related-Party Revenue` & `IAS 24` disclosures.
//!   6. **Live Read-Time Accrual Projection & Realized-Profit Dividend Gate**: `getFinancialStatements()`
//!      projects `IAS 16/38` depreciation, `IFRS 16` ROU amortization, `IFRS 15` deferred revenue, and
//!      `IFRS 9` aging `ECL` up to `context::block_number()` on every `eth_call`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    query_charter_function_auth, require_active_charter, require_approved_hfs_code_hash,
    require_valid_identity, verify_and_consume_auth, ActionHasher, ACTION_CLOSE_FISCAL_PERIOD,
    ACTION_IFRS_DISBURSE, CAP_EQUITY_SETTLEMENT, CAP_IFRS_RECORDER, CAP_MERCHANT_PAYMENT,
    ERR_AUTH_CONSUME_FAILED, ERR_CHARTER_MISMATCH, ERR_INVALID_PRODUCT_PARAMS, ERR_MISSING_ROLE,
    ERR_UNAUTHORIZED_MODULE, HFS_TYPE_PRODUCT_LEDGER, HFS_TYPE_SHARE_CAPITAL, POLICY_ACCOUNTING_OPS,
    POLICY_BOARD_RESOLUTION, ROLE_CHIEF_ACCOUNTANT, ROLE_PRODUCT_MANAGER, ROLE_TREASURY_MANAGER,
};
use hps_sdk::ifrs::{
    self, AccrualProjection, BalancedBatch, CashFlowClass, Side, ACC_ALLOWANCE_ECL, ACC_CASH,
    ACC_CASH_SUSPENSE, ACC_TAX_PAYABLE, ACC_TRADE_PAYABLES, ACC_ACCRUED_PAYROLL, COA_COUNT,
    ERR_IFRS_BANK_CASH_SHORTFALL, ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED,
    ERR_IFRS_CUSTODY_OWNER_MISMATCH, ERR_IFRS_NOTHING_TO_POST, ERR_IFRS_SUBLEDGER_FULL,
    ERR_IFRS_SUBLEDGER_NOT_FOUND, ERR_IFRS_ZERO_OR_OVERFLOW, OPEX_GENERAL_ADMIN, OPEX_RND,
    OPEX_SALES_MARKETING,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const EV_INITIALIZED: [u8; 32] =
    event_topic("IfrsLedgerInitialized(address,address,address,address)");
const EV_JOURNAL_POSTED: [u8; 32] =
    event_topic("IfrsJournalPosted(uint64,address,bytes32,bytes)");
const EV_SUBLEDGER_UPDATED: [u8; 32] =
    event_topic("IfrsSubledgerUpdated(uint64,bytes32,bytes)");
const EV_PERIOD_CLOSED: [u8; 32] =
    event_topic("IfrsFiscalPeriodClosed(uint64,int64,uint64,address)");

const SUBLEDGER_KIND_INV_SKU: u64 = 1;
const SUBLEDGER_KIND_FIXED_ASSET: u64 = 2;
const SUBLEDGER_KIND_LEASE: u64 = 3;
const SUBLEDGER_KIND_DEFERRED_REV: u64 = 4;
const SUBLEDGER_KIND_CREDIT_INVOICE: u64 = 5;
const SUBLEDGER_KIND_TERM_LOAN: u64 = 6;
const SUBLEDGER_KIND_AUX_COUNTERS: u64 = 7;

const KEY_INIT: &[u8] = b"ifrs:init";
const KEY_REGISTRY: &[u8] = b"ifrs:reg";
const KEY_HFS_REGISTRY: &[u8] = b"ifrs:hfsreg";
const KEY_CHARTER: &[u8] = b"ifrs:chr";
const KEY_BANK_LEDGER: &[u8] = b"ifrs:bank";
const KEY_TREASURY_ID: &[u8] = b"ifrs:treas";
const KEY_INITIALIZER: &[u8] = b"ifrs:init_by";
const KEY_VIRGIN_CUSTODY: &[u8] = b"ifrs:virgin";

const KEY_COA_BLOB: &[u8] = b"ifrs:coa"; // 32 * 16B = 512B `(dr_u64_be, cr_u64_be)`
const KEY_FISCAL_PERIOD: &[u8] = b"ifrs:period";
const KEY_PERIOD_START_BLK: &[u8] = b"ifrs:pstart";
const KEY_LAST_CLOSED_BLK: &[u8] = b"ifrs:pclosed";
const KEY_JOURNAL_COUNT: &[u8] = b"ifrs:jcnt";

const KEY_CFO_NET: &[u8] = b"ifrs:cfo"; // i64 BE
const KEY_CFI_NET: &[u8] = b"ifrs:cfi"; // i64 BE
const KEY_CFF_NET: &[u8] = b"ifrs:cff"; // i64 BE
const KEY_CFO_IN: &[u8] = b"ifrs:cfo_in";
const KEY_CFO_OUT: &[u8] = b"ifrs:cfo_out";
const KEY_CFI_IN: &[u8] = b"ifrs:cfi_in";
const KEY_CFI_OUT: &[u8] = b"ifrs:cfi_out";
const KEY_CFF_IN: &[u8] = b"ifrs:cff_in";
const KEY_CFF_OUT: &[u8] = b"ifrs:cff_out";

const KEY_RP_TX_CNT: &[u8] = b"ifrs:rp_cnt";
const KEY_RP_INFLOW: &[u8] = b"ifrs:rp_in";
const KEY_RP_OUTFLOW: &[u8] = b"ifrs:rp_out";

const KEY_OPEX_RND: &[u8] = b"ifrs:op_rnd";
const KEY_OPEX_SM: &[u8] = b"ifrs:op_sm";
const KEY_OPEX_GA: &[u8] = b"ifrs:op_ga";

const KEY_TOTAL_UNITS_SOLD: &[u8] = b"ifrs:tot_units";
const KEY_SALE_COUNT: &[u8] = b"ifrs:sale_cnt";
const KEY_INV_SKU_COUNT: &[u8] = b"ifrs:inv_cnt";
const KEY_ASSET_COUNT: &[u8] = b"ifrs:ast_cnt";
const KEY_LEASE_COUNT: &[u8] = b"ifrs:lse_cnt";
const KEY_DEF_COUNT: &[u8] = b"ifrs:def_cnt";
const KEY_INVOICE_COUNT: &[u8] = b"ifrs:inv_ar_cnt";
const KEY_LOAN_COUNT: &[u8] = b"ifrs:loan_cnt";

const MAX_INV_SKUS: u64 = 64;
const MAX_FIXED_ASSETS: u64 = 48;
const MAX_LEASES: u64 = 24;
const MAX_DEFERRED_CONTRACTS: u64 = 48;
const MAX_INVOICES: u64 = 64;
const MAX_LOANS: u64 = 24;
const MAX_JOURNAL_SLICE: u64 = 24;

const JOURNAL_ENTRY_BYTES: usize = 140;
const SALE_RECORD_LEN: usize = 104;
const STATEMENTS_FRAME_BYTES: usize = 640;
const ANCHOR_HEADER_BYTES: usize = 272;

static mut SNAP_BUF: [u8; 24576] = [0u8; 24576];

const ROLE_CEO: [u8; 32] = keccak256(b"ROLE_CEO");
const ROLE_COO: [u8; 32] = keccak256(b"ROLE_COO");
const ROLE_CTO: [u8; 32] = keccak256(b"ROLE_CTO");

const SEL_PAY_OPEX: [u8; 4] =
    selector("payOperatingExpense(address,uint64,uint64,bool,bytes32,address)");
const SEL_PAY_PAYROLL: [u8; 4] =
    selector("bookPayrollRun(address,uint64,bool,bytes32,address)");
const SEL_SETTLE_PAYROLL: [u8; 4] =
    selector("settleAccruedPayroll(address,uint64,address)");
const SEL_SETTLE_AP: [u8; 4] = selector("settleTradePayable(address,uint64,address)");
const SEL_PROCURE_INV: [u8; 4] =
    selector("procureInventory(bytes32,address,uint64,uint64,bool,address)");
const SEL_WRITEDOWN_INV: [u8; 4] =
    selector("writeDownInventoryNrv(bytes32,uint64,address)");
const SEL_ACQUIRE_ASSET: [u8; 4] =
    selector("acquireCapitalAsset(address,uint64,uint64,uint64,uint64,bool,bytes32,address)");
const SEL_DISPOSE_ASSET: [u8; 4] =
    selector("disposeCapitalAsset(uint64,address,uint64,address)");
const SEL_OFFER_LEASE: [u8; 4] =
    selector("proposeLease(address,uint64,uint64,uint64,uint64,address)");
const SEL_PAY_LEASE: [u8; 4] = selector("payLeaseInstallment(uint64,address)");
const SEL_ISSUE_INVOICE: [u8; 4] =
    selector("issueCreditInvoice(address,bytes32,uint64,uint64,uint64,address)");
const SEL_OFFER_LOAN: [u8; 4] =
    selector("proposeTermLoan(address,uint64,uint64,address)");
const SEL_PAY_DEBT: [u8; 4] =
    selector("payDebtService(uint64,uint64,uint64,address)");
const SEL_ACCRUE_TAX: [u8; 4] = selector("accrueCurrentIncomeTax(uint64,address)");
const SEL_PAY_TAX: [u8; 4] = selector("payIncomeTax(address,uint64,address)");
const SEL_REFUND_SUSPENSE: [u8; 4] =
    selector("refundUnattributedDeposit(address,uint64,address)");
const SEL_PAY_DIVIDEND: [u8; 4] = selector("payDividend(address,uint64,address)");
const SEL_RECORD_PAID_IN_CAP: [u8; 4] =
    selector("recordPaidInCapital(uint64,uint64,uint64,address)");
const SEL_CLOSE_PERIOD: [u8; 4] = selector("closeFiscalPeriod(address)");

hps_entry! {
    "hfsType()"                                                                         => handle_hfs_type,
    "standardsVersion()"                                                                => handle_standards_version,
    "initialize(address,address,address,address,address,string,string)"                 => handle_initialize,
    // Sibling module hooks (`ProductLedger` & `ShareCapital`, `HfsRegistry` `code_hash`-gated)
    "bookCashSale(bytes32,address,uint64,uint64,uint64)"                                => handle_book_cash_sale,
    "bookInventoryPurchaseFromModule(bytes32,address,uint64,uint64,bool)"               => handle_book_inv_from_module,
    "bookSalesReturnFromModule(bytes32,address,uint64,uint64)"                          => handle_book_return_from_module,
    "bookEquityIssuanceFromModule(address,uint64,uint64,uint64)"                        => handle_book_eq_from_module,
    "bookShareBuybackFromModule(address,uint64,uint64)"                                 => handle_book_buyback_from_module,
    "bookEsopVestingFromModule(address,uint64,uint64)"                                  => handle_book_esop_vest_from_module,
    "bookEsopExerciseFromModule(address,uint64,uint64,uint64,uint64)"                   => handle_book_esop_ex_from_module,
    // Governed Corporate Accounting & Atomic Treasury Disbursements
    "payOperatingExpense(address,uint64,uint64,bool,bytes32,address)"                   => handle_pay_operating_expense,
    "bookPayrollRun(address,uint64,bool,bytes32,address)"                               => handle_book_payroll_run,
    "settleAccruedPayroll(address,uint64,address)"                                      => handle_settle_accrued_payroll,
    "settleTradePayable(address,uint64,address)"                                        => handle_settle_trade_payable,
    "procureInventory(bytes32,address,uint64,uint64,bool,address)"                      => handle_procure_inventory,
    "writeDownInventoryNrv(bytes32,uint64,address)"                                     => handle_writedown_inventory_nrv,
    "acquireCapitalAsset(address,uint64,uint64,uint64,uint64,bool,bytes32,address)"     => handle_acquire_capital_asset,
    "disposeCapitalAsset(uint64,address,uint64,address)"                                => handle_dispose_capital_asset,
    "proposeLease(address,uint64,uint64,uint64,uint64,address)"                         => handle_propose_lease,
    "acceptAndCommenceLease(uint64)"                                                    => handle_accept_lease,
    "payLeaseInstallment(uint64,address)"                                               => handle_pay_lease_installment,
    "issueCreditInvoice(address,bytes32,uint64,uint64,uint64,address)"                  => handle_issue_credit_invoice,
    "acceptCreditInvoice(uint64)"                                                       => handle_accept_credit_invoice,
    "settleCreditInvoice(uint64,uint64)"                                                => handle_settle_credit_invoice,
    "purchaseSubscription(bytes32,uint64,uint64)"                                       => handle_purchase_subscription,
    "proposeTermLoan(address,uint64,uint64,address)"                                    => handle_propose_term_loan,
    "fundTermLoan(uint64)"                                                              => handle_fund_term_loan,
    "payDebtService(uint64,uint64,uint64,address)"                                      => handle_pay_debt_service,
    "accrueCurrentIncomeTax(uint64,address)"                                            => handle_accrue_income_tax,
    "payIncomeTax(address,uint64,address)"                                              => handle_pay_income_tax,
    "quarantineSuspenseCash()"                                                          => handle_quarantine_suspense_cash,
    "refundUnattributedDeposit(address,uint64,address)"                                 => handle_refund_suspense,
    "payDividend(address,uint64,address)"                                               => handle_pay_dividend,
    "recordPaidInCapital(uint64,uint64,uint64,address)"                                 => handle_record_paid_in_capital,
    "hashRecordPaidInCapital(uint64,uint64,uint64)"                                     => handle_hash_record_paid_in_capital,
    "processPeriodicAccruals()"                                                         => handle_process_periodic_accruals,
    "closeFiscalPeriod(address)"                                                        => handle_close_fiscal_period,
    // Action-Hash Helpers for Multi-Stage `Authorization` Quorums
    "hashCloseFiscalPeriod(uint64)"                                                     => handle_hash_close_fiscal_period,
    "hashPayDividend(address,uint64)"                                                   => handle_hash_pay_dividend,
    // Readers & Financial Statement Snapshots
    "getFinancialStatements()"                                                          => handle_get_financial_statements,
    "getRealtimeAnchorState()"                                                          => handle_get_realtime_anchor_state,
    "getSchedulesSnapshot()"                                                            => handle_get_schedules_snapshot,
    "getJournalSlice(uint64,uint64)"                                                    => handle_get_journal_slice,
    "journalCount()"                                                                    => handle_journal_count,
    "associatedCharter()"                                                               => handle_associated_charter,
    "associatedConstitution()"                                                          => handle_associated_charter,
    "identityRegistry()"                                                                => handle_identity_registry,
    "hfsRegistry()"                                                                     => handle_hfs_registry,
    "operatingBankLedger()"                                                             => handle_operating_bank_ledger,
    "treasuryIdentity()"                                                                => handle_treasury_identity,
    // Storefront Sub-Ledger Readers (compatible with `/commerce.html`)
    "totalRevenue()"                                                                    => handle_total_revenue,
    "totalUnitsSold()"                                                                  => handle_total_units_sold,
    "saleCount()"                                                                       => handle_sale_count,
    "getSale(uint64)"                                                                   => handle_get_sale,
    "productSalesOf(bytes32)"                                                           => handle_product_sales_of,
    "buyerPurchasesOf(address)"                                                         => handle_buyer_purchases_of,
}

// ============================================================================
// Storage Structs & Encoders
// ============================================================================

#[derive(Clone, Copy)]
struct InvSkuState {
    units_on_hand: u64,
    carrying_cost: u64,
    total_units_sold: u64,
}

#[derive(Clone, Copy)]
struct CapitalAssetRow {
    asset_class: u8,
    disposed: bool,
    cost: u64,
    residual: u64,
    useful_life_blocks: u64,
    acquired_block: u64,
    posted_depr: u64,
}

#[derive(Clone, Copy)]
struct LeaseRow {
    lessor: [u8; 20],
    status: u8, // 1 = proposed, 2 = active, 3 = completed
    initial_pv: u64,
    rem_liability: u64,
    periodic_payment: u64,
    rate_bps: u64,
    total_periods: u32,
    paid_periods: u32,
    period_blocks: u64,
    start_block: u64,
    posted_amort: u64,
}

#[derive(Clone, Copy)]
struct DeferredContractRow {
    customer: [u8; 20],
    is_related: bool,
    plan_tag: [u8; 8],
    total_amount: u64,
    posted_earned: u64,
    start_block: u64,
    duration_blocks: u64,
}

#[derive(Clone, Copy)]
struct CreditInvoiceRow {
    buyer: [u8; 20],
    product_id: [u8; 32],
    quantity: u64,
    status: u8, // 1 = offered (unbooked), 2 = open AR, 3 = paid
    original_amount: u64,
    open_amount: u64,
    issued_block: u64,
    due_block: u64,
}

#[derive(Clone, Copy)]
struct TermLoanRow {
    lender: [u8; 20],
    status: u8, // 1 = proposed, 2 = active, 3 = repaid
    initial_principal: u64,
    rem_principal: u64,
    rate_bps: u64,
    start_block: u64,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn u64_topic(val: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&val.to_be_bytes());
    t
}

fn encode_inv_sku_wire(sku: &[u8; 32], st: &InvSkuState) -> [u8; 56] {
    let mut out = [0u8; 56];
    out[0..32].copy_from_slice(sku);
    out[32..40].copy_from_slice(&st.units_on_hand.to_be_bytes());
    out[40..48].copy_from_slice(&st.carrying_cost.to_be_bytes());
    out[48..56].copy_from_slice(&st.total_units_sold.to_be_bytes());
    out
}

fn encode_asset_wire(id: u64, row: &CapitalAssetRow, now: u64) -> [u8; 64] {
    let live_cum = if row.disposed {
        row.posted_depr
    } else {
        ifrs::compute_linear_depreciation(
            row.cost,
            row.residual,
            row.useful_life_blocks,
            row.acquired_block,
            now,
        )
    };
    let mut out = [0u8; 64];
    out[0..8].copy_from_slice(&id.to_be_bytes());
    out[8] = row.asset_class;
    out[9] = u8::from(row.disposed);
    out[16..24].copy_from_slice(&row.cost.to_be_bytes());
    out[24..32].copy_from_slice(&row.residual.to_be_bytes());
    out[32..40].copy_from_slice(&row.useful_life_blocks.to_be_bytes());
    out[40..48].copy_from_slice(&row.acquired_block.to_be_bytes());
    out[48..56].copy_from_slice(&row.posted_depr.to_be_bytes());
    out[56..64].copy_from_slice(&live_cum.to_be_bytes());
    out
}

fn encode_lease_wire(id: u64, ls: &LeaseRow) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[0..8].copy_from_slice(&id.to_be_bytes());
    out[8..28].copy_from_slice(&ls.lessor);
    out[28] = ls.status;
    out[32..40].copy_from_slice(&ls.initial_pv.to_be_bytes());
    out[40..48].copy_from_slice(&ls.rem_liability.to_be_bytes());
    out[48..56].copy_from_slice(&ls.periodic_payment.to_be_bytes());
    out[56..64].copy_from_slice(&ls.rate_bps.to_be_bytes());
    out[64..68].copy_from_slice(&ls.total_periods.to_be_bytes());
    out[68..72].copy_from_slice(&ls.paid_periods.to_be_bytes());
    out[72..80].copy_from_slice(&ls.period_blocks.to_be_bytes());
    out[80..88].copy_from_slice(&ls.start_block.to_be_bytes());
    out[88..96].copy_from_slice(&ls.posted_amort.to_be_bytes());
    out
}

fn encode_def_wire(id: u64, dc: &DeferredContractRow, now: u64) -> [u8; 80] {
    let live_earned = ifrs::compute_linear_deferred_earned(
        dc.total_amount,
        dc.start_block,
        dc.duration_blocks,
        now,
    );
    let mut out = [0u8; 80];
    out[0..8].copy_from_slice(&id.to_be_bytes());
    out[8..28].copy_from_slice(&dc.customer);
    out[28] = u8::from(dc.is_related);
    out[32..40].copy_from_slice(&dc.total_amount.to_be_bytes());
    out[40..48].copy_from_slice(&dc.posted_earned.to_be_bytes());
    out[48..56].copy_from_slice(&live_earned.to_be_bytes());
    out[56..64].copy_from_slice(&dc.start_block.to_be_bytes());
    out[64..72].copy_from_slice(&dc.duration_blocks.to_be_bytes());
    out[72..80].copy_from_slice(&dc.plan_tag);
    out
}

fn encode_invoice_wire(id: u64, inv: &CreditInvoiceRow, now: u64) -> [u8; 72] {
    let live_ecl = if inv.status == 2 {
        ifrs::compute_invoice_ecl_amount(inv.open_amount, inv.due_block, now)
    } else {
        0
    };
    let mut out = [0u8; 72];
    out[0..8].copy_from_slice(&id.to_be_bytes());
    out[8..28].copy_from_slice(&inv.buyer);
    out[28] = inv.status;
    out[32..40].copy_from_slice(&inv.original_amount.to_be_bytes());
    out[40..48].copy_from_slice(&inv.open_amount.to_be_bytes());
    out[48..56].copy_from_slice(&live_ecl.to_be_bytes());
    out[56..64].copy_from_slice(&inv.issued_block.to_be_bytes());
    out[64..72].copy_from_slice(&inv.due_block.to_be_bytes());
    out
}

fn encode_loan_wire(id: u64, row: &TermLoanRow) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..8].copy_from_slice(&id.to_be_bytes());
    out[8..28].copy_from_slice(&row.lender);
    out[28] = row.status;
    out[32..40].copy_from_slice(&row.initial_principal.to_be_bytes());
    out[40..48].copy_from_slice(&row.rem_principal.to_be_bytes());
    out[48..56].copy_from_slice(&row.rate_bps.to_be_bytes());
    out[56..64].copy_from_slice(&row.start_block.to_be_bytes());
    out
}

fn encode_aux_counters_wire() -> [u8; 56] {
    let mut out = [0u8; 56];
    out[0..8].copy_from_slice(&storage::get_u64(KEY_RP_TX_CNT).to_be_bytes());
    out[8..16].copy_from_slice(&storage::get_u64(KEY_RP_INFLOW).to_be_bytes());
    out[16..24].copy_from_slice(&storage::get_u64(KEY_RP_OUTFLOW).to_be_bytes());
    out[24..32].copy_from_slice(&storage::get_u64(KEY_OPEX_RND).to_be_bytes());
    out[32..40].copy_from_slice(&storage::get_u64(KEY_OPEX_SM).to_be_bytes());
    out[40..48].copy_from_slice(&storage::get_u64(KEY_OPEX_GA).to_be_bytes());
    out[48..56].copy_from_slice(&storage::get_u64(KEY_SALE_COUNT).to_be_bytes());
    out
}

fn emit_aux_counters() {
    let wire = encode_aux_counters_wire();
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_AUX_COUNTERS),
            u64_topic(storage::get_u64(KEY_JOURNAL_COUNT)),
        ],
        &wire,
    );
}

fn get_i64(key: &[u8]) -> i64 {
    let mut b = [0u8; 8];
    if storage::get_into(key, &mut b) == Some(8) {
        i64::from_be_bytes(b)
    } else {
        0
    }
}

fn set_i64(key: &[u8], val: i64) {
    storage::set(key, &val.to_be_bytes());
}

fn load_coa_totals() -> [(u64, u64); COA_COUNT] {
    let mut out = [(0u64, 0u64); COA_COUNT];
    let mut raw = [0u8; COA_COUNT * 16];
    if storage::get_into(KEY_COA_BLOB, &mut raw) == Some(COA_COUNT * 16) {
        let mut i = 0;
        while i < COA_COUNT {
            let mut d = [0u8; 8];
            let mut c = [0u8; 8];
            d.copy_from_slice(&raw[i * 16..i * 16 + 8]);
            c.copy_from_slice(&raw[i * 16 + 8..i * 16 + 16]);
            out[i] = (u64::from_be_bytes(d), u64::from_be_bytes(c));
            i += 1;
        }
    }
    out
}

fn save_coa_totals(totals: &[(u64, u64); COA_COUNT]) {
    let mut raw = [0u8; COA_COUNT * 16];
    let mut i = 0;
    while i < COA_COUNT {
        raw[i * 16..i * 16 + 8].copy_from_slice(&totals[i].0.to_be_bytes());
        raw[i * 16 + 8..i * 16 + 16].copy_from_slice(&totals[i].1.to_be_bytes());
        i += 1;
    }
    storage::set(KEY_COA_BLOB, &raw);
}

fn booked_cash_u64(totals: &[(u64, u64); COA_COUNT]) -> u64 {
    let (dr, cr) = totals[ACC_CASH as usize];
    dr.saturating_sub(cr)
}

fn query_bank_balance_of_treasury() -> Result<u64, i32> {
    let bank = storage::get_address(KEY_BANK_LEDGER).ok_or(-10)?;
    let treas = storage::get_address(KEY_TREASURY_ID).ok_or(-10)?;
    let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(&treas);
    call::call_u64(&bank, cd.as_slice())
}

/// Enforce Inbound Cash Custody Proof: real bank balance in `treasuryIdentity` must cover
/// `booked_1010_cash + inflow_amount`.
fn require_inbound_bank_cash(totals: &[(u64, u64); COA_COUNT], inflow_amount: u64) -> Result<(), i32> {
    let actual = query_bank_balance_of_treasury()?;
    let expected = booked_cash_u64(totals)
        .checked_add(inflow_amount)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    if actual < expected {
        return Err(ERR_IFRS_BANK_CASH_SHORTFALL);
    }
    Ok(())
}

/// Execute atomic outbound payment from `treasuryIdentity` (`owner() == AccountingLedger`).
fn disburse_treasury_cash(
    registry: &[u8; 20],
    totals: &[(u64, u64); COA_COUNT],
    payee_identity: &[u8; 20],
    amount: u64,
) -> Result<(), i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let treas = storage::get_address(KEY_TREASURY_ID).ok_or(-10)?;
    let bank = storage::get_address(KEY_BANK_LEDGER).ok_or(-10)?;
    if *payee_identity == [0u8; 20] || *payee_identity == treas {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }
    require_valid_identity(registry, payee_identity)?;
    if booked_cash_u64(totals) < amount {
        return Err(ERR_IFRS_BANK_CASH_SHORTFALL);
    }
    let cd = CallEncoder::<128>::new(const {
        selector("transferBankBalance(address,address,uint64)")
    })
    .push_address(&bank)
    .push_address(payee_identity)
    .push_u64(amount);
    let ok = call::call_bool(&treas, cd.as_slice())?;
    if !ok {
        return Err(ERR_IFRS_BANK_CASH_SHORTFALL);
    }
    Ok(())
}

/// Query `CorporateCharter` to detect if `party` is an `IAS 24` Related Party:
/// - `treasuryIdentity` or `corporateCharter` itself
/// - Active director (`isDirector(party)`)
/// - Key management personnel (`CEO`, `COO`, `CTO`, `TREASURY_MANAGER`, `CHIEF_ACCOUNTANT`, `PRODUCT_MANAGER`)
/// - Significant shareholder holding `>= 5%` of total converted common shares (`holder * 20 >= total`).
fn detect_related_party(charter: &[u8; 20], party: &[u8; 20]) -> bool {
    if *party == [0u8; 20] {
        return false;
    }
    let treas = storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]);
    if *party == treas || *party == *charter {
        return true;
    }
    let dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(party);
    if matches!(call::call_bool(charter, dir_cd.as_slice()), Ok(true)) {
        return true;
    }
    let kmp_roles = [
        ROLE_CEO,
        ROLE_COO,
        ROLE_CTO,
        ROLE_TREASURY_MANAGER,
        ROLE_CHIEF_ACCOUNTANT,
        ROLE_PRODUCT_MANAGER,
    ];
    let mut r = 0;
    while r < kmp_roles.len() {
        let r_cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
            .push_bytes32(&kmp_roles[r])
            .push_address(party);
        if matches!(call::call_bool(charter, r_cd.as_slice()), Ok(true)) {
            return true;
        }
        r += 1;
    }
    let sh_cd = CallEncoder::<64>::new(const { selector("convertedCommonTotals(address)") })
        .push_address(party);
    if let Ok(raw) = call::call_raw(charter, sh_cd.as_slice()) {
        if raw.len() >= 64 {
            let mut hb = [0u8; 8];
            let mut tb = [0u8; 8];
            hb.copy_from_slice(&raw[24..32]);
            tb.copy_from_slice(&raw[56..64]);
            let holder = u64::from_be_bytes(hb);
            let total = u64::from_be_bytes(tb);
            if total > 0 && (holder as u128) * 20 >= (total as u128) {
                return true;
            }
        }
    }
    false
}

fn record_related_party_disclosure(is_inflow: bool, amount: u64) {
    if amount == 0 {
        return;
    }
    storage::set_u64(
        KEY_RP_TX_CNT,
        storage::get_u64(KEY_RP_TX_CNT).saturating_add(1),
    );
    if is_inflow {
        storage::set_u64(
            KEY_RP_INFLOW,
            storage::get_u64(KEY_RP_INFLOW).saturating_add(amount),
        );
    } else {
        storage::set_u64(
            KEY_RP_OUTFLOW,
            storage::get_u64(KEY_RP_OUTFLOW).saturating_add(amount),
        );
    }
    emit_aux_counters();
}

fn journal_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"ifrs:j:").push_u64_be(idx)
}

/// Commit a verified `BalancedBatch` to the 32-account General Ledger, `IAS 7` Cash Flow totals,
/// and append-only General Journal tape, emitting a self-contained `IfrsJournalPosted` event log
/// carrying all double-entry lines and cash-flow deltas for realtime event-sourced statement UIs.
fn commit_batch(
    totals: &mut [(u64, u64); COA_COUNT],
    batch: &BalancedBatch,
    counterparty: &[u8; 20],
    memo_tag: &[u8; 4],
) -> Result<u64, i32> {
    let lines = batch.lines();
    let mut i = 0;
    while i < lines.len() {
        let ln = lines[i];
        let (dr, cr) = totals[ln.account as usize];
        match ln.side {
            Side::Debit => {
                totals[ln.account as usize] = (
                    dr.checked_add(ln.amount).ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?,
                    cr,
                );
            }
            Side::Credit => {
                totals[ln.account as usize] = (
                    dr,
                    cr.checked_add(ln.amount).ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?,
                );
            }
        }
        i += 1;
    }
    save_coa_totals(totals);

    let delta = batch.cash_delta();
    if delta != 0 {
        let mag = delta.unsigned_abs();
        match batch.cash_flow_class() {
            CashFlowClass::Operating => {
                set_i64(KEY_CFO_NET, get_i64(KEY_CFO_NET).saturating_add(delta));
                if delta > 0 {
                    storage::set_u64(KEY_CFO_IN, storage::get_u64(KEY_CFO_IN).saturating_add(mag));
                } else {
                    storage::set_u64(KEY_CFO_OUT, storage::get_u64(KEY_CFO_OUT).saturating_add(mag));
                }
            }
            CashFlowClass::Investing => {
                set_i64(KEY_CFI_NET, get_i64(KEY_CFI_NET).saturating_add(delta));
                if delta > 0 {
                    storage::set_u64(KEY_CFI_IN, storage::get_u64(KEY_CFI_IN).saturating_add(mag));
                } else {
                    storage::set_u64(KEY_CFI_OUT, storage::get_u64(KEY_CFI_OUT).saturating_add(mag));
                }
            }
            CashFlowClass::Financing => {
                set_i64(KEY_CFF_NET, get_i64(KEY_CFF_NET).saturating_add(delta));
                if delta > 0 {
                    storage::set_u64(KEY_CFF_IN, storage::get_u64(KEY_CFF_IN).saturating_add(mag));
                } else {
                    storage::set_u64(KEY_CFF_OUT, storage::get_u64(KEY_CFF_OUT).saturating_add(mag));
                }
            }
            CashFlowClass::None => {}
        }
    }

    let j_idx = storage::get_u64(KEY_JOURNAL_COUNT);
    let entry_id = j_idx + 1;
    let blk = context::block_number();
    let period = storage::get_u64(KEY_FISCAL_PERIOD).max(1).min(255) as u8;
    let line_cnt = lines.len().min(ifrs::MAX_BATCH_LINES);

    let mut rec = [0u8; JOURNAL_ENTRY_BYTES];
    rec[0..8].copy_from_slice(&entry_id.to_be_bytes());
    rec[8..16].copy_from_slice(&blk.to_be_bytes());
    rec[16] = period;
    rec[17] = batch.standard_tag();
    rec[18] = batch.cash_flow_class() as u8;
    rec[19] = line_cnt as u8;
    rec[20..40].copy_from_slice(counterparty);
    rec[40..48].copy_from_slice(&batch.total_debit().to_be_bytes());
    rec[48..56].copy_from_slice(&delta.to_be_bytes());
    rec[56..60].copy_from_slice(memo_tag);
    let mut ev_lines = [0u8; ifrs::MAX_BATCH_LINES * 10];
    let mut l = 0;
    while l < line_cnt {
        let base = 60 + l * 10;
        let ebase = l * 10;
        rec[base] = lines[l].account;
        rec[base + 1] = lines[l].side as u8;
        rec[base + 2..base + 10].copy_from_slice(&lines[l].amount.to_be_bytes());
        ev_lines[ebase..ebase + 10].copy_from_slice(&rec[base..base + 10]);
        l += 1;
    }
    storage::set(journal_key(j_idx).as_slice(), &rec);
    storage::set_u64(KEY_JOURNAL_COUNT, entry_id);

    let mut meta_topic = [0u8; 32];
    meta_topic[0] = period;
    meta_topic[1] = batch.standard_tag();
    meta_topic[2] = batch.cash_flow_class() as u8;
    meta_topic[3] = line_cnt as u8;
    meta_topic[4..8].copy_from_slice(memo_tag);
    meta_topic[8..16].copy_from_slice(&blk.to_be_bytes());
    meta_topic[16..24].copy_from_slice(&batch.total_debit().to_be_bytes());
    meta_topic[24..32].copy_from_slice(&delta.to_be_bytes());

    events::emit(
        &[
            EV_JOURNAL_POSTED,
            u64_topic(entry_id),
            addr_topic(counterparty),
            meta_topic,
        ],
        &ev_lines[..line_cnt * 10],
    );

    Ok(entry_id)
}

// ============================================================================
// Sub-Ledger Storage Helpers
// ============================================================================

fn inv_idx_key(i: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"inv:i:").push_u64_be(i)
}
fn inv_sku_key(sku: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"inv:s:").push(sku)
}

fn load_inv_sku(sku: &[u8; 32]) -> Option<InvSkuState> {
    let mut b = [0u8; 24];
    if storage::get_into(inv_sku_key(sku).as_slice(), &mut b) != Some(24) {
        return None;
    }
    let mut u = [0u8; 8];
    let mut c = [0u8; 8];
    let mut s = [0u8; 8];
    u.copy_from_slice(&b[0..8]);
    c.copy_from_slice(&b[8..16]);
    s.copy_from_slice(&b[16..24]);
    Some(InvSkuState {
        units_on_hand: u64::from_be_bytes(u),
        carrying_cost: u64::from_be_bytes(c),
        total_units_sold: u64::from_be_bytes(s),
    })
}

fn save_inv_sku(sku: &[u8; 32], st: &InvSkuState) -> Result<(), i32> {
    let k = inv_sku_key(sku);
    if !storage::exists(k.as_slice()) {
        let cnt = storage::get_u64(KEY_INV_SKU_COUNT);
        if cnt >= MAX_INV_SKUS {
            return Err(ERR_IFRS_SUBLEDGER_FULL);
        }
        storage::set(inv_idx_key(cnt).as_slice(), sku);
        storage::set_u64(KEY_INV_SKU_COUNT, cnt + 1);
    }
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&st.units_on_hand.to_be_bytes());
    b[8..16].copy_from_slice(&st.carrying_cost.to_be_bytes());
    b[16..24].copy_from_slice(&st.total_units_sold.to_be_bytes());
    storage::set(k.as_slice(), &b);
    let wire = encode_inv_sku_wire(sku, st);
    events::emit(
        &[EV_SUBLEDGER_UPDATED, u64_topic(SUBLEDGER_KIND_INV_SKU), *sku],
        &wire,
    );
    Ok(())
}

fn asset_key(id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"ast:").push_u64_be(id)
}
fn save_asset(id: u64, row: &CapitalAssetRow) {
    let mut b = [0u8; 42];
    b[0] = row.asset_class;
    b[1] = u8::from(row.disposed);
    b[2..10].copy_from_slice(&row.cost.to_be_bytes());
    b[10..18].copy_from_slice(&row.residual.to_be_bytes());
    b[18..26].copy_from_slice(&row.useful_life_blocks.to_be_bytes());
    b[26..34].copy_from_slice(&row.acquired_block.to_be_bytes());
    b[34..42].copy_from_slice(&row.posted_depr.to_be_bytes());
    storage::set(asset_key(id).as_slice(), &b);
    let wire = encode_asset_wire(id, row, context::block_number());
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_FIXED_ASSET),
            u64_topic(id),
        ],
        &wire,
    );
}
fn load_asset(id: u64) -> Option<CapitalAssetRow> {
    let mut b = [0u8; 42];
    if storage::get_into(asset_key(id).as_slice(), &mut b) != Some(42) {
        return None;
    }
    let u64_at = |off: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(x)
    };
    Some(CapitalAssetRow {
        asset_class: b[0],
        disposed: b[1] == 1,
        cost: u64_at(2),
        residual: u64_at(10),
        useful_life_blocks: u64_at(18),
        acquired_block: u64_at(26),
        posted_depr: u64_at(34),
    })
}

fn lease_key(id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"lse:").push_u64_be(id)
}
fn save_lease(id: u64, row: &LeaseRow) {
    let mut b = [0u8; 85];
    b[0..20].copy_from_slice(&row.lessor);
    b[20] = row.status;
    b[21..29].copy_from_slice(&row.initial_pv.to_be_bytes());
    b[29..37].copy_from_slice(&row.rem_liability.to_be_bytes());
    b[37..45].copy_from_slice(&row.periodic_payment.to_be_bytes());
    b[45..53].copy_from_slice(&row.rate_bps.to_be_bytes());
    b[53..57].copy_from_slice(&row.total_periods.to_be_bytes());
    b[57..61].copy_from_slice(&row.paid_periods.to_be_bytes());
    b[61..69].copy_from_slice(&row.period_blocks.to_be_bytes());
    b[69..77].copy_from_slice(&row.start_block.to_be_bytes());
    b[77..85].copy_from_slice(&row.posted_amort.to_be_bytes());
    storage::set(lease_key(id).as_slice(), &b);
    let wire = encode_lease_wire(id, row);
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_LEASE),
            u64_topic(id),
        ],
        &wire,
    );
}
fn load_lease(id: u64) -> Option<LeaseRow> {
    let mut b = [0u8; 85];
    if storage::get_into(lease_key(id).as_slice(), &mut b) != Some(85) {
        return None;
    }
    let mut lessor = [0u8; 20];
    lessor.copy_from_slice(&b[0..20]);
    let u64_at = |off: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(x)
    };
    let mut tp = [0u8; 4];
    let mut pp = [0u8; 4];
    tp.copy_from_slice(&b[53..57]);
    pp.copy_from_slice(&b[57..61]);
    Some(LeaseRow {
        lessor,
        status: b[20],
        initial_pv: u64_at(21),
        rem_liability: u64_at(29),
        periodic_payment: u64_at(37),
        rate_bps: u64_at(45),
        total_periods: u32::from_be_bytes(tp),
        paid_periods: u32::from_be_bytes(pp),
        period_blocks: u64_at(61),
        start_block: u64_at(69),
        posted_amort: u64_at(77),
    })
}

fn def_key(id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"def:").push_u64_be(id)
}
fn save_def(id: u64, row: &DeferredContractRow) {
    let mut b = [0u8; 61];
    b[0..20].copy_from_slice(&row.customer);
    b[20] = u8::from(row.is_related);
    b[21..29].copy_from_slice(&row.plan_tag);
    b[29..37].copy_from_slice(&row.total_amount.to_be_bytes());
    b[37..45].copy_from_slice(&row.posted_earned.to_be_bytes());
    b[45..53].copy_from_slice(&row.start_block.to_be_bytes());
    b[53..61].copy_from_slice(&row.duration_blocks.to_be_bytes());
    storage::set(def_key(id).as_slice(), &b);
    let wire = encode_def_wire(id, row, context::block_number());
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_DEFERRED_REV),
            u64_topic(id),
        ],
        &wire,
    );
}
fn load_def(id: u64) -> Option<DeferredContractRow> {
    let mut b = [0u8; 61];
    if storage::get_into(def_key(id).as_slice(), &mut b) != Some(61) {
        return None;
    }
    let mut customer = [0u8; 20];
    customer.copy_from_slice(&b[0..20]);
    let mut plan_tag = [0u8; 8];
    plan_tag.copy_from_slice(&b[21..29]);
    let u64_at = |off: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(x)
    };
    Some(DeferredContractRow {
        customer,
        is_related: b[20] == 1,
        plan_tag,
        total_amount: u64_at(29),
        posted_earned: u64_at(37),
        start_block: u64_at(45),
        duration_blocks: u64_at(53),
    })
}

fn invoice_key(id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"ar:").push_u64_be(id)
}
fn save_invoice(id: u64, row: &CreditInvoiceRow) {
    let mut b = [0u8; 93];
    b[0..20].copy_from_slice(&row.buyer);
    b[20..52].copy_from_slice(&row.product_id);
    b[52..60].copy_from_slice(&row.quantity.to_be_bytes());
    b[60] = row.status;
    b[61..69].copy_from_slice(&row.original_amount.to_be_bytes());
    b[69..77].copy_from_slice(&row.open_amount.to_be_bytes());
    b[77..85].copy_from_slice(&row.issued_block.to_be_bytes());
    b[85..93].copy_from_slice(&row.due_block.to_be_bytes());
    storage::set(invoice_key(id).as_slice(), &b);
    let wire = encode_invoice_wire(id, row, context::block_number());
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_CREDIT_INVOICE),
            u64_topic(id),
        ],
        &wire,
    );
}
fn load_invoice(id: u64) -> Option<CreditInvoiceRow> {
    let mut b = [0u8; 93];
    if storage::get_into(invoice_key(id).as_slice(), &mut b) != Some(93) {
        return None;
    }
    let mut buyer = [0u8; 20];
    buyer.copy_from_slice(&b[0..20]);
    let mut product_id = [0u8; 32];
    product_id.copy_from_slice(&b[20..52]);
    let u64_at = |off: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(x)
    };
    Some(CreditInvoiceRow {
        buyer,
        product_id,
        quantity: u64_at(52),
        status: b[60],
        original_amount: u64_at(61),
        open_amount: u64_at(69),
        issued_block: u64_at(77),
        due_block: u64_at(85),
    })
}

fn loan_key(id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"ln:").push_u64_be(id)
}
fn save_loan(id: u64, row: &TermLoanRow) {
    let mut b = [0u8; 53];
    b[0..20].copy_from_slice(&row.lender);
    b[20] = row.status;
    b[21..29].copy_from_slice(&row.initial_principal.to_be_bytes());
    b[29..37].copy_from_slice(&row.rem_principal.to_be_bytes());
    b[37..45].copy_from_slice(&row.rate_bps.to_be_bytes());
    b[45..53].copy_from_slice(&row.start_block.to_be_bytes());
    storage::set(loan_key(id).as_slice(), &b);
    let wire = encode_loan_wire(id, row);
    events::emit(
        &[
            EV_SUBLEDGER_UPDATED,
            u64_topic(SUBLEDGER_KIND_TERM_LOAN),
            u64_topic(id),
        ],
        &wire,
    );
}
fn load_loan(id: u64) -> Option<TermLoanRow> {
    let mut b = [0u8; 53];
    if storage::get_into(loan_key(id).as_slice(), &mut b) != Some(53) {
        return None;
    }
    let mut lender = [0u8; 20];
    lender.copy_from_slice(&b[0..20]);
    let u64_at = |off: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(x)
    };
    Some(TermLoanRow {
        lender,
        status: b[20],
        initial_principal: u64_at(21),
        rem_principal: u64_at(29),
        rate_bps: u64_at(37),
        start_block: u64_at(45),
    })
}

fn sale_key(sale_idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"sale:").push_u64_be(sale_idx)
}
fn product_stats_key(product_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"ps:").push(product_id)
}
fn buyer_stats_key(buyer: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"bs:").push(buyer)
}
fn load_pair_u64(key: &[u8]) -> (u64, u64) {
    let mut buf = [0u8; 16];
    if storage::get_into(key, &mut buf) != Some(16) {
        return (0, 0);
    }
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    a.copy_from_slice(&buf[0..8]);
    b.copy_from_slice(&buf[8..16]);
    (u64::from_be_bytes(a), u64::from_be_bytes(b))
}
fn store_pair_u64(key: &[u8], first: u64, second: u64) {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&first.to_be_bytes());
    buf[8..16].copy_from_slice(&second.to_be_bytes());
    storage::set(key, &buf);
}

fn append_sku_sale_subledger(
    product_id: &[u8; 32],
    buyer: &[u8; 20],
    quantity: u64,
    unit_price: u64,
    total_amount: u64,
    recorder_addr: &[u8; 20],
) -> u64 {
    let sale_idx = storage::get_u64(KEY_SALE_COUNT);
    let blk = context::block_number();
    let mut raw = [0u8; SALE_RECORD_LEN];
    raw[0..32].copy_from_slice(product_id);
    raw[32..52].copy_from_slice(buyer);
    raw[52..60].copy_from_slice(&quantity.to_be_bytes());
    raw[60..68].copy_from_slice(&unit_price.to_be_bytes());
    raw[68..76].copy_from_slice(&total_amount.to_be_bytes());
    raw[76..84].copy_from_slice(&blk.to_be_bytes());
    raw[84..104].copy_from_slice(recorder_addr);
    storage::set(sale_key(sale_idx).as_slice(), &raw);
    storage::set_u64(KEY_SALE_COUNT, sale_idx + 1);
    storage::set_u64(
        KEY_TOTAL_UNITS_SOLD,
        storage::get_u64(KEY_TOTAL_UNITS_SOLD).saturating_add(quantity),
    );

    let pk = product_stats_key(product_id);
    let (pu, pr) = load_pair_u64(pk.as_slice());
    store_pair_u64(
        pk.as_slice(),
        pu.saturating_add(quantity),
        pr.saturating_add(total_amount),
    );

    let bk = buyer_stats_key(buyer);
    let (bu, bs) = load_pair_u64(bk.as_slice());
    store_pair_u64(
        bk.as_slice(),
        bu.saturating_add(quantity),
        bs.saturating_add(total_amount),
    );
    emit_aux_counters();
    sale_idx
}

// ============================================================================
// Governance & Sibling-Module Authorization Helpers
// ============================================================================

fn ensure_active() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(-10)?;
    require_active_charter(&charter)?;
    Ok((registry, charter))
}

fn require_verified_sibling_module(expected_hfs_type: &[u8; 32], extra_cap: &[u8; 32]) -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    let (registry, charter) = ensure_active()?;
    let caller = context::msg_sender();
    let has_cap = {
        let c1 = CallEncoder::<96>::new(const {
            selector("isAuthorizedModule(address,bytes32)")
        })
        .push_address(&caller)
        .push_bytes32(&CAP_IFRS_RECORDER);
        let c2 = CallEncoder::<96>::new(const {
            selector("isAuthorizedModule(address,bytes32)")
        })
        .push_address(&caller)
        .push_bytes32(extra_cap);
        matches!(call::call_bool(&charter, c1.as_slice()), Ok(true))
            || matches!(call::call_bool(&charter, c2.as_slice()), Ok(true))
    };
    if !has_cap {
        return Err(ERR_UNAUTHORIZED_MODULE);
    }
    let hfs_reg = storage::get_address(KEY_HFS_REGISTRY).unwrap_or([0u8; 20]);
    if hfs_reg != [0u8; 20] {
        require_approved_hfs_code_hash(&hfs_reg, expected_hfs_type, &caller)?;
    }
    Ok((registry, charter, caller))
}

/// Governance check for routine corporate accounting & treasury operations:
/// - Consumes `auth_obj` when provided (required whenever `CorporateCharter.setFunctionAuth` set a
///   custom multi-stage policy).
/// - When `auth_obj == 0x0` and no custom multi-stage policy override is set, permits direct
///   execution by an active `ROLE_CHIEF_ACCOUNTANT`, `ROLE_TREASURY_MANAGER`, or sole director (`directorCount() == 1`).
fn require_accounting_ops_auth(
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
) -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    let (registry, charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, fn_selector);

    if *auth_obj != [0u8; 20] {
        let req_pol = if let Some(pol) = explicit_pol {
            pol
        } else {
            let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
            if let Ok(raw_pid) = call::call_raw(auth_obj, pid_cd.as_slice()) {
                if raw_pid.len() >= 32 {
                    let mut p = [0u8; 32];
                    p.copy_from_slice(&raw_pid[..32]);
                    p
                } else {
                    POLICY_BOARD_RESOLUTION
                }
            } else {
                POLICY_BOARD_RESOLUTION
            }
        };
        verify_and_consume_auth(&registry, auth_obj, &charter, &req_pol, action_hash, &caller)?;
        return Ok((registry, charter, caller));
    }

    if let Some(pol) = explicit_pol {
        if pol != POLICY_ACCOUNTING_OPS
            && pol != ROLE_CHIEF_ACCOUNTANT
            && pol != ROLE_TREASURY_MANAGER
        {
            return Err(ERR_AUTH_CONSUME_FAILED);
        }
    }

    let check_role = |role_id: &[u8; 32]| -> bool {
        let cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
            .push_bytes32(role_id)
            .push_address(&caller);
        matches!(call::call_bool(&charter, cd.as_slice()), Ok(true))
    };

    if check_role(&ROLE_CHIEF_ACCOUNTANT) || check_role(&ROLE_TREASURY_MANAGER) {
        return Ok((registry, charter, caller));
    }

    let dcnt_cd = CallEncoder::<16>::new(const { selector("directorCount()") });
    let dcnt = call::call_u64(&charter, dcnt_cd.as_slice()).unwrap_or(0);
    let is_dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(&caller);
    if dcnt == 1 && matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true)) {
        return Ok((registry, charter, caller));
    }

    Err(ERR_MISSING_ROLE)
}

/// Governance check for Board-level capital & period-close actions (`payDividend`, `closeFiscalPeriod`).
fn require_board_level_auth(
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
) -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    let (registry, charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, fn_selector);
    if *auth_obj != [0u8; 20] {
        let req_pol = explicit_pol.unwrap_or(POLICY_BOARD_RESOLUTION);
        verify_and_consume_auth(&registry, auth_obj, &charter, &req_pol, action_hash, &caller)?;
        return Ok((registry, charter, caller));
    }
    if explicit_pol.is_some() {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let dcnt_cd = CallEncoder::<16>::new(const { selector("directorCount()") });
    let dcnt = call::call_u64(&charter, dcnt_cd.as_slice()).unwrap_or(0);
    let is_dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(&caller);
    if dcnt == 1 && matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true)) {
        return Ok((registry, charter, caller));
    }
    Err(ERR_AUTH_CONSUME_FAILED)
}

fn disburse_action_hash(tag: u8, party: &[u8; 20], amount: u64, extra: u64) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_IFRS_DISBURSE)
        .push_u64(tag as u64)
        .push_address(party)
        .push_u64(amount)
        .push_u64(extra)
        .finish()
}

// ============================================================================
// Live Accrual Projection & Periodic Accrual Sweep
// ============================================================================

fn compute_live_accrual_projection(totals: &[(u64, u64); COA_COUNT], now_block: u64) -> AccrualProjection {
    let mut proj = AccrualProjection::default();

    // 1. IAS 16 PPE & IAS 38 Intangible straight-line depreciation/amortization
    let ast_cnt = storage::get_u64(KEY_ASSET_COUNT);
    let mut i = 0u64;
    while i < ast_cnt {
        if let Some(a) = load_asset(i) {
            if !a.disposed {
                let cum = ifrs::compute_linear_depreciation(
                    a.cost,
                    a.residual,
                    a.useful_life_blocks,
                    a.acquired_block,
                    now_block,
                );
                let delta = cum.saturating_sub(a.posted_depr);
                if a.asset_class == ifrs::ASSET_CLASS_FINITE_INTANGIBLE {
                    proj.unposted_intang_amort = proj.unposted_intang_amort.saturating_add(delta);
                } else {
                    proj.unposted_ppe_depr = proj.unposted_ppe_depr.saturating_add(delta);
                }
            }
        }
        i += 1;
    }

    // 2. IFRS 16 ROU Lease straight-line amortization
    let lse_cnt = storage::get_u64(KEY_LEASE_COUNT);
    let mut l = 0u64;
    while l < lse_cnt {
        if let Some(ls) = load_lease(l) {
            if ls.status == 2 {
                let total_blks = (ls.total_periods as u64).saturating_mul(ls.period_blocks);
                let cum = ifrs::compute_linear_depreciation(
                    ls.initial_pv,
                    0,
                    total_blks,
                    ls.start_block,
                    now_block,
                );
                proj.unposted_rou_amort = proj
                    .unposted_rou_amort
                    .saturating_add(cum.saturating_sub(ls.posted_amort));
            }
        }
        l += 1;
    }

    // 3. IFRS 15 Over-Time Deferred Contract revenue
    let def_cnt = storage::get_u64(KEY_DEF_COUNT);
    let mut d = 0u64;
    while d < def_cnt {
        if let Some(dc) = load_def(d) {
            let cum = ifrs::compute_linear_deferred_earned(
                dc.total_amount,
                dc.start_block,
                dc.duration_blocks,
                now_block,
            );
            let delta = cum.saturating_sub(dc.posted_earned);
            if dc.is_related {
                proj.unposted_deferred_rev_related =
                    proj.unposted_deferred_rev_related.saturating_add(delta);
            } else {
                proj.unposted_deferred_rev_arms =
                    proj.unposted_deferred_rev_arms.saturating_add(delta);
            }
        }
        d += 1;
    }

    // 4. IFRS 9 Deterministic Aging ECL across open Trade Receivable invoices
    let inv_cnt = storage::get_u64(KEY_INVOICE_COUNT);
    let mut target_ecl = 0u64;
    let mut ar = 0u64;
    while ar < inv_cnt {
        if let Some(inv) = load_invoice(ar) {
            if inv.status == 2 && inv.open_amount > 0 {
                target_ecl = target_ecl.saturating_add(ifrs::compute_invoice_ecl_amount(
                    inv.open_amount,
                    inv.due_block,
                    now_block,
                ));
            }
        }
        ar += 1;
    }
    proj.target_ecl_allowance = target_ecl;

    // 5. IAS 7 Bank Cash vs Booked 1010 Cash reconciliation
    if let Ok(actual_bank) = query_bank_balance_of_treasury() {
        let booked = booked_cash_u64(totals);
        if actual_bank > booked {
            proj.unattributed_bank_inflow = actual_bank - booked;
        } else if actual_bank < booked {
            proj.bank_custody_shortfall = booked - actual_bank;
        }
    }

    proj
}

/// Post all currently due periodic accruals (`IAS 16/38`, `IFRS 16`, `IFRS 15`, `IFRS 9`, and
/// `2900 Unattributed Cash Suspense` quarantine) into permanent storage. Returns number of batches posted.
fn sweep_periodic_accruals_internal(totals: &mut [(u64, u64); COA_COUNT]) -> Result<u64, i32> {
    let now_block = context::block_number();
    let mut posted_batches = 0u64;
    let me = context::self_address();

    // 1. Depreciation & Amortization
    let mut ppe_delta = 0u64;
    let mut intang_delta = 0u64;
    let ast_cnt = storage::get_u64(KEY_ASSET_COUNT);
    let mut i = 0u64;
    while i < ast_cnt {
        if let Some(mut a) = load_asset(i) {
            if !a.disposed {
                let cum = ifrs::compute_linear_depreciation(
                    a.cost,
                    a.residual,
                    a.useful_life_blocks,
                    a.acquired_block,
                    now_block,
                );
                let delta = cum.saturating_sub(a.posted_depr);
                if delta > 0 {
                    a.posted_depr = cum;
                    save_asset(i, &a);
                    if a.asset_class == ifrs::ASSET_CLASS_FINITE_INTANGIBLE {
                        intang_delta = intang_delta.saturating_add(delta);
                    } else {
                        ppe_delta = ppe_delta.saturating_add(delta);
                    }
                }
            }
        }
        i += 1;
    }

    let mut rou_delta = 0u64;
    let lse_cnt = storage::get_u64(KEY_LEASE_COUNT);
    let mut l = 0u64;
    while l < lse_cnt {
        if let Some(mut ls) = load_lease(l) {
            if ls.status == 2 {
                let total_blks = (ls.total_periods as u64).saturating_mul(ls.period_blocks);
                let cum = ifrs::compute_linear_depreciation(
                    ls.initial_pv,
                    0,
                    total_blks,
                    ls.start_block,
                    now_block,
                );
                let delta = cum.saturating_sub(ls.posted_amort);
                if delta > 0 {
                    ls.posted_amort = cum;
                    save_lease(l, &ls);
                    rou_delta = rou_delta.saturating_add(delta);
                }
            }
        }
        l += 1;
    }

    if ppe_delta > 0 || rou_delta > 0 || intang_delta > 0 {
        let b = ifrs::derive_depreciation_posting(ppe_delta, rou_delta, intang_delta)?;
        let _ = commit_batch(totals, &b, &me, b"DEPR")?;
        posted_batches += 1;
    }

    // 2. Deferred Contract Revenue (`IFRS 15`)
    let mut def_arms = 0u64;
    let mut def_rel = 0u64;
    let def_cnt = storage::get_u64(KEY_DEF_COUNT);
    let mut d = 0u64;
    while d < def_cnt {
        if let Some(mut dc) = load_def(d) {
            let cum = ifrs::compute_linear_deferred_earned(
                dc.total_amount,
                dc.start_block,
                dc.duration_blocks,
                now_block,
            );
            let delta = cum.saturating_sub(dc.posted_earned);
            if delta > 0 {
                dc.posted_earned = cum;
                save_def(d, &dc);
                if dc.is_related {
                    def_rel = def_rel.saturating_add(delta);
                } else {
                    def_arms = def_arms.saturating_add(delta);
                }
            }
        }
        d += 1;
    }
    if def_arms > 0 {
        let b = ifrs::derive_deferred_revenue_recognition(def_arms, false)?;
        let _ = commit_batch(totals, &b, &me, b"DFRV")?;
        posted_batches += 1;
    }
    if def_rel > 0 {
        let b = ifrs::derive_deferred_revenue_recognition(def_rel, true)?;
        let _ = commit_batch(totals, &b, &me, b"RPRV")?;
        posted_batches += 1;
    }

    // 3. Deterministic Aging ECL (`IFRS 9`)
    let inv_cnt = storage::get_u64(KEY_INVOICE_COUNT);
    let mut target_ecl = 0u64;
    let mut ar = 0u64;
    while ar < inv_cnt {
        if let Some(inv) = load_invoice(ar) {
            if inv.status == 2 && inv.open_amount > 0 {
                target_ecl = target_ecl.saturating_add(ifrs::compute_invoice_ecl_amount(
                    inv.open_amount,
                    inv.due_block,
                    now_block,
                ));
            }
        }
        ar += 1;
    }
    let (ecl_dr, ecl_cr) = totals[ACC_ALLOWANCE_ECL as usize];
    let cur_ecl = ecl_cr.saturating_sub(ecl_dr);
    if target_ecl != cur_ecl {
        let b = ifrs::derive_ecl_adjustment(cur_ecl, target_ecl)?;
        let _ = commit_batch(totals, &b, &me, b"ECL9")?;
        posted_batches += 1;
    }

    // 4. Unattributed Bank Deposit Suspense Quarantine (`2900`)
    if let Ok(actual_bank) = query_bank_balance_of_treasury() {
        let booked = booked_cash_u64(totals);
        if actual_bank > booked {
            let unattr = actual_bank - booked;
            let b = ifrs::derive_suspense_quarantine(unattr)?;
            let _ = commit_batch(totals, &b, &me, b"SUSP")?;
            posted_batches += 1;
        }
    }

    Ok(posted_batches)
}

// ============================================================================
// Entrypoint Handlers
// ============================================================================

fn handle_hfs_type(_args: &CalldataReader) -> Result<(), i32> {
    let s = b"IFRS_LEDGER";
    let mut out = [0u8; 96];
    out[31] = 32;
    out[63] = s.len() as u8;
    out[64..64 + s.len()].copy_from_slice(s);
    ret::write(&out);
    Ok(())
}

fn handle_standards_version(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(1);
    Ok(())
}

/// Virgin-custody initialization:
/// Directly calls `treasuryIdentity.initializeWithNickname(self_address(), handle, nickname)` on an
/// uninitialized `Identity` HFS (`KEY_INIT == 0`), proving mathematically that zero prior owners or
/// delegates exist on `treasuryIdentity`!
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let hfs_registry = args.address(1).ok_or(-3)?;
    let charter = args.address(2).ok_or(-3)?;
    let bank_ledger = args.address(3).ok_or(-3)?;
    let treasury_id = args.address(4).ok_or(-3)?;
    let handle_bytes = args.dynamic_bytes(5).ok_or(-3)?;
    let nick_bytes = args.dynamic_bytes(6).ok_or(-3)?;

    if registry == [0u8; 20]
        || charter == [0u8; 20]
        || bank_ledger == [0u8; 20]
        || treasury_id == [0u8; 20]
        || handle_bytes.is_empty()
        || handle_bytes.len() > 64
        || nick_bytes.is_empty()
        || nick_bytes.len() > 32
    {
        return Err(ERR_CHARTER_MISMATCH);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    // Caller must be a director of `charter` (or `charter` itself)
    if caller != charter {
        let is_dir_cd =
            CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(&caller);
        if !matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true)) {
            return Err(ERR_MISSING_ROLE);
        }
    }

    // Verify `treasury_id` is deployed from an approved `Identity` WASM `code_hash` in `IdentityRegistry`
    let Some(treas_ch) = context::code_hash_of(&treasury_id) else {
        return Err(ERR_IFRS_CUSTODY_OWNER_MISMATCH);
    };
    let allow_cd = CallEncoder::<64>::new(const {
        selector("isAllowedIdentityCodeHash(bytes32)")
    })
    .push_bytes32(&treas_ch);
    if !matches!(call::call_bool(&registry, allow_cd.as_slice()), Ok(true)) {
        return Err(ERR_IFRS_CUSTODY_OWNER_MISMATCH);
    }

    // Initialize `treasuryIdentity` directly with `owner = self_address()`!
    // Reverts if `treasuryIdentity` was ALREADY initialized (`KEY_INIT != 0`), closing any pre-init `setDelegate` backdoor!
    let me = context::self_address();
    let mut init_treas_cd = [0u8; 320];
    let sel = const { selector("initializeWithNickname(address,string,string)") };
    init_treas_cd[0..4].copy_from_slice(&sel);
    init_treas_cd[16..36].copy_from_slice(&me);
    init_treas_cd[60..68].copy_from_slice(&96u64.to_be_bytes());
    let nick_off = 96 + 32 + ((handle_bytes.len() + 31) / 32) * 32;
    init_treas_cd[92..100].copy_from_slice(&(nick_off as u64).to_be_bytes());
    init_treas_cd[124..132].copy_from_slice(&(handle_bytes.len() as u64).to_be_bytes());
    init_treas_cd[132..132 + handle_bytes.len()].copy_from_slice(handle_bytes);
    let p2 = 4 + nick_off;
    init_treas_cd[p2 + 24..p2 + 32].copy_from_slice(&(nick_bytes.len() as u64).to_be_bytes());
    init_treas_cd[p2 + 32..p2 + 32 + nick_bytes.len()].copy_from_slice(nick_bytes);
    let total_cd_len = p2 + 32 + ((nick_bytes.len() + 31) / 32) * 32;

    call::call_raw(&treasury_id, &init_treas_cd[..total_cd_len])
        .map_err(|_| ERR_IFRS_CUSTODY_OWNER_MISMATCH)?;

    // Double-verify `treasuryIdentity.owner() == self_address()`
    let own_cd = CallEncoder::<16>::new(const { selector("owner()") });
    let own_raw = call::call_raw(&treasury_id, own_cd.as_slice())
        .map_err(|_| ERR_IFRS_CUSTODY_OWNER_MISMATCH)?;
    if own_raw.len() < 32 || own_raw[12..32] != me {
        return Err(ERR_IFRS_CUSTODY_OWNER_MISMATCH);
    }

    // Verify `operatingBankLedger` responds to `balanceOf(treasuryIdentity)`
    let init_bank_bal = {
        let b_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
            .push_address(&treasury_id);
        call::call_u64(&bank_ledger, b_cd.as_slice())?
    };

    let now = context::block_number();
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_HFS_REGISTRY, &hfs_registry);
    storage::set_address(KEY_CHARTER, &charter);
    storage::set_address(KEY_BANK_LEDGER, &bank_ledger);
    storage::set_address(KEY_TREASURY_ID, &treasury_id);
    storage::set_address(KEY_INITIALIZER, &caller);
    storage::set_u64(KEY_VIRGIN_CUSTODY, 1);
    storage::set_u64(KEY_FISCAL_PERIOD, 1);
    storage::set_u64(KEY_PERIOD_START_BLK, now);
    storage::set_u64(KEY_INIT, 1);

    let mut totals = [(0u64, 0u64); COA_COUNT];
    save_coa_totals(&totals);
    if init_bank_bal > 0 {
        let b = ifrs::derive_suspense_quarantine(init_bank_bal)?;
        let _ = commit_batch(&mut totals, &b, &treasury_id, b"INIT")?;
    }

    events::emit(
        &[
            EV_INITIALIZED,
            addr_topic(&charter),
            addr_topic(&bank_ledger),
            addr_topic(&treasury_id),
        ],
        &caller,
    );
    ret::write_bool(true);
    Ok(())
}

// ============================================================================
// Sibling Corporate Module Hooks (`ProductLedger` & `ShareCapital`)
// ============================================================================

fn handle_book_cash_sale(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, caller) =
        require_verified_sibling_module(&HFS_TYPE_PRODUCT_LEDGER, &CAP_MERCHANT_PAYMENT)?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let buyer = args.address(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let unit_price = args.u64(3).ok_or(-3)?;
    let total_amount = args.u64(4).ok_or(-3)?;
    if quantity == 0 || unit_price == 0 || total_amount != quantity.saturating_mul(unit_price) {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, total_amount)?;

    let mut cogs = 0u64;
    if let Some(mut inv) = load_inv_sku(&product_id) {
        let (c, rem_u, rem_c) = ifrs::compute_wac_cogs(inv.units_on_hand, inv.carrying_cost, quantity);
        cogs = c;
        inv.units_on_hand = rem_u;
        inv.carrying_cost = rem_c;
        inv.total_units_sold = inv.total_units_sold.saturating_add(quantity);
        save_inv_sku(&product_id, &inv)?;
    }

    let is_rp = detect_related_party(&charter, &buyer);
    if is_rp {
        record_related_party_disclosure(true, total_amount);
    }
    let batch = ifrs::derive_cash_sale(total_amount, cogs, is_rp)?;
    let _ = commit_batch(&mut totals, &batch, &buyer, b"SALE")?;
    let sale_idx =
        append_sku_sale_subledger(&product_id, &buyer, quantity, unit_price, total_amount, &caller);
    ret::write_u64_word(sale_idx);
    Ok(())
}

fn handle_book_inv_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_PRODUCT_LEDGER, &CAP_MERCHANT_PAYMENT)?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let supplier = args.address(1).ok_or(-3)?;
    let units = args.u64(2).ok_or(-3)?;
    let total_cost = args.u64(3).ok_or(-3)?;
    let is_cash = args.bool(4).ok_or(-3)?;

    let mut totals = load_coa_totals();
    if is_cash {
        disburse_treasury_cash(&registry, &totals, &supplier, total_cost)?;
    } else {
        require_valid_identity(&registry, &supplier)?;
    }
    if detect_related_party(&charter, &supplier) {
        record_related_party_disclosure(false, total_cost);
    }
    let mut inv = load_inv_sku(&product_id).unwrap_or(InvSkuState {
        units_on_hand: 0,
        carrying_cost: 0,
        total_units_sold: 0,
    });
    inv.units_on_hand = inv
        .units_on_hand
        .checked_add(units)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    inv.carrying_cost = inv
        .carrying_cost
        .checked_add(total_cost)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    save_inv_sku(&product_id, &inv)?;

    let batch = ifrs::derive_inventory_purchase(units, total_cost, is_cash)?;
    let j_id = commit_batch(&mut totals, &batch, &supplier, b"INVP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_return_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_PRODUCT_LEDGER, &CAP_MERCHANT_PAYMENT)?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let buyer = args.address(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let refund_amount = args.u64(3).ok_or(-3)?;
    if quantity == 0 || refund_amount == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let mut totals = load_coa_totals();
    disburse_treasury_cash(&registry, &totals, &buyer, refund_amount)?;
    if detect_related_party(&charter, &buyer) {
        record_related_party_disclosure(false, refund_amount);
    }

    let mut restocked_cogs = 0u64;
    if let Some(mut inv) = load_inv_sku(&product_id) {
        if inv.units_on_hand > 0 && inv.carrying_cost > 0 {
            restocked_cogs =
                (((inv.carrying_cost as u128) * (quantity as u128)) / (inv.units_on_hand as u128)) as u64;
            restocked_cogs = restocked_cogs.min(refund_amount);
        }
        inv.units_on_hand = inv.units_on_hand.saturating_add(quantity);
        inv.carrying_cost = inv.carrying_cost.saturating_add(restocked_cogs);
        save_inv_sku(&product_id, &inv)?;
    }

    let batch = ifrs::derive_sales_return(refund_amount, restocked_cogs, true)?;
    let j_id = commit_batch(&mut totals, &batch, &buyer, b"RETN")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_eq_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_SHARE_CAPITAL, &CAP_EQUITY_SETTLEMENT)?;
    let investor = args.address(0).ok_or(-3)?;
    let shares = args.u64(1).ok_or(-3)?;
    let par_per_share = args.u64(2).ok_or(-3)?;
    let total_proceeds = args.u64(3).ok_or(-3)?;

    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, total_proceeds)?;
    let batch = ifrs::derive_equity_issuance(shares, par_per_share, total_proceeds)?;
    let j_id = commit_batch(&mut totals, &batch, &investor, b"EQIS")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_buyback_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_SHARE_CAPITAL, &CAP_EQUITY_SETTLEMENT)?;
    let seller = args.address(0).ok_or(-3)?;
    let _shares = args.u64(1).ok_or(-3)?;
    let total_paid = args.u64(2).ok_or(-3)?;

    let mut totals = load_coa_totals();
    if booked_cash_u64(&totals) < total_paid {
        return Err(ERR_IFRS_BANK_CASH_SHORTFALL);
    }
    let batch = ifrs::derive_share_buyback(total_paid)?;
    let j_id = commit_batch(&mut totals, &batch, &seller, b"BUYB")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_esop_vest_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_SHARE_CAPITAL, &CAP_EQUITY_SETTLEMENT)?;
    let employee = args.address(0).ok_or(-3)?;
    let _options_vested = args.u64(1).ok_or(-3)?;
    let fair_value_vested = args.u64(2).ok_or(-3)?;

    let mut totals = load_coa_totals();
    let batch = ifrs::derive_esop_vesting(fair_value_vested)?;
    let j_id = commit_batch(&mut totals, &batch, &employee, b"ESOP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_esop_ex_from_module(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) =
        require_verified_sibling_module(&HFS_TYPE_SHARE_CAPITAL, &CAP_EQUITY_SETTLEMENT)?;
    let employee = args.address(0).ok_or(-3)?;
    let _shares = args.u64(1).ok_or(-3)?;
    let strike_cash = args.u64(2).ok_or(-3)?;
    let reserve_transfer = args.u64(3).ok_or(-3)?;
    let par_amount = args.u64(4).ok_or(-3)?;

    let mut totals = load_coa_totals();
    if strike_cash > 0 {
        require_inbound_bank_cash(&totals, strike_cash)?;
    }
    let batch = ifrs::derive_esop_exercise(strike_cash, reserve_transfer, par_amount)?;
    let j_id = commit_batch(&mut totals, &batch, &employee, b"EXER")?;
    ret::write_u64_word(j_id);
    Ok(())
}

// ============================================================================
// Corporate Accounting & Atomic Treasury Disbursement Operations
// ============================================================================

fn handle_pay_operating_expense(args: &CalldataReader) -> Result<(), i32> {
    let vendor = args.address(0).ok_or(-3)?;
    let category = args.u64(1).ok_or(-3)? as u8;
    let amount = args.u64(2).ok_or(-3)?;
    let is_cash = args.bool(3).ok_or(-3)?;
    let _invoice_ref = args.bytes32(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let ah = disburse_action_hash(1, &vendor, amount, category as u64);
    let (registry, charter, _caller) = require_accounting_ops_auth(&SEL_PAY_OPEX, &ah, &auth_obj)?;

    let batch = ifrs::derive_operating_expense(category, amount, is_cash)?;
    let mut totals = load_coa_totals();
    if is_cash {
        disburse_treasury_cash(&registry, &totals, &vendor, amount)?;
    } else {
        require_valid_identity(&registry, &vendor)?;
    }
    if detect_related_party(&charter, &vendor) {
        record_related_party_disclosure(false, amount);
    }
    match category {
        OPEX_RND => storage::set_u64(KEY_OPEX_RND, storage::get_u64(KEY_OPEX_RND).saturating_add(amount)),
        OPEX_SALES_MARKETING => storage::set_u64(KEY_OPEX_SM, storage::get_u64(KEY_OPEX_SM).saturating_add(amount)),
        OPEX_GENERAL_ADMIN => storage::set_u64(KEY_OPEX_GA, storage::get_u64(KEY_OPEX_GA).saturating_add(amount)),
        _ => {}
    }
    emit_aux_counters();
    let j_id = commit_batch(&mut totals, &batch, &vendor, b"OPEX")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_book_payroll_run(args: &CalldataReader) -> Result<(), i32> {
    let employee_or_payroll_id = args.address(0).ok_or(-3)?;
    let gross_wages = args.u64(1).ok_or(-3)?;
    let is_paid_now = args.bool(2).ok_or(-3)?;
    let _period_ref = args.bytes32(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let ah = disburse_action_hash(2, &employee_or_payroll_id, gross_wages, u64::from(is_paid_now));
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_PAY_PAYROLL, &ah, &auth_obj)?;

    let batch = ifrs::derive_payroll_run(gross_wages, is_paid_now)?;
    let mut totals = load_coa_totals();
    if is_paid_now {
        disburse_treasury_cash(&registry, &totals, &employee_or_payroll_id, gross_wages)?;
    } else {
        require_valid_identity(&registry, &employee_or_payroll_id)?;
    }
    if detect_related_party(&charter, &employee_or_payroll_id) {
        record_related_party_disclosure(false, gross_wages);
    }
    let j_id = commit_batch(&mut totals, &batch, &employee_or_payroll_id, b"PAYR")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_settle_accrued_payroll(args: &CalldataReader) -> Result<(), i32> {
    let payee = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = disburse_action_hash(3, &payee, amount, 0);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_SETTLE_PAYROLL, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let (dr, cr) = totals[ACC_ACCRUED_PAYROLL as usize];
    if cr.saturating_sub(dr) < amount {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    disburse_treasury_cash(&registry, &totals, &payee, amount)?;
    let batch = ifrs::derive_accrued_payroll_settlement(amount)?;
    let j_id = commit_batch(&mut totals, &batch, &payee, b"SPAY")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_settle_trade_payable(args: &CalldataReader) -> Result<(), i32> {
    let vendor = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = disburse_action_hash(4, &vendor, amount, 0);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_SETTLE_AP, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let (dr, cr) = totals[ACC_TRADE_PAYABLES as usize];
    if cr.saturating_sub(dr) < amount {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    disburse_treasury_cash(&registry, &totals, &vendor, amount)?;
    let batch = ifrs::derive_payable_settlement(amount)?;
    let j_id = commit_batch(&mut totals, &batch, &vendor, b"STAP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_procure_inventory(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let supplier = args.address(1).ok_or(-3)?;
    let units = args.u64(2).ok_or(-3)?;
    let total_cost = args.u64(3).ok_or(-3)?;
    let is_cash = args.bool(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let ah = disburse_action_hash(5, &supplier, total_cost, units);
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_PROCURE_INV, &ah, &auth_obj)?;

    let batch = ifrs::derive_inventory_purchase(units, total_cost, is_cash)?;
    let mut totals = load_coa_totals();
    if is_cash {
        disburse_treasury_cash(&registry, &totals, &supplier, total_cost)?;
    } else {
        require_valid_identity(&registry, &supplier)?;
    }
    if detect_related_party(&charter, &supplier) {
        record_related_party_disclosure(false, total_cost);
    }
    let mut inv = load_inv_sku(&product_id).unwrap_or(InvSkuState {
        units_on_hand: 0,
        carrying_cost: 0,
        total_units_sold: 0,
    });
    inv.units_on_hand = inv
        .units_on_hand
        .checked_add(units)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    inv.carrying_cost = inv
        .carrying_cost
        .checked_add(total_cost)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    save_inv_sku(&product_id, &inv)?;

    let j_id = commit_batch(&mut totals, &batch, &supplier, b"INVP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_writedown_inventory_nrv(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let new_nrv_total = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = disburse_action_hash(6, &[0u8; 20], new_nrv_total, 0);
    let (_registry, _charter, caller) =
        require_accounting_ops_auth(&SEL_WRITEDOWN_INV, &ah, &auth_obj)?;

    let mut inv = load_inv_sku(&product_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    let (batch, _loss) = ifrs::derive_inventory_nrv_writedown(inv.carrying_cost, new_nrv_total)?;
    inv.carrying_cost = new_nrv_total;
    save_inv_sku(&product_id, &inv)?;

    let mut totals = load_coa_totals();
    let j_id = commit_batch(&mut totals, &batch, &caller, b"NRVW")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_acquire_capital_asset(args: &CalldataReader) -> Result<(), i32> {
    let vendor = args.address(0).ok_or(-3)?;
    let asset_class = args.u64(1).ok_or(-3)? as u8;
    let cost = args.u64(2).ok_or(-3)?;
    let residual = args.u64(3).ok_or(-3)?;
    let useful_life_blocks = args.u64(4).ok_or(-3)?;
    let is_cash = args.bool(5).ok_or(-3)?;
    let _asset_tag = args.bytes32(6).ok_or(-3)?;
    let auth_obj = args.address(7).ok_or(-3)?;

    let ah = disburse_action_hash(7, &vendor, cost, useful_life_blocks);
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_ACQUIRE_ASSET, &ah, &auth_obj)?;

    let ast_id = storage::get_u64(KEY_ASSET_COUNT);
    if ast_id >= MAX_FIXED_ASSETS {
        return Err(ERR_IFRS_SUBLEDGER_FULL);
    }
    let batch =
        ifrs::derive_capex_acquisition(asset_class, cost, residual, useful_life_blocks, is_cash)?;
    let mut totals = load_coa_totals();
    if is_cash {
        disburse_treasury_cash(&registry, &totals, &vendor, cost)?;
    } else {
        require_valid_identity(&registry, &vendor)?;
    }
    if detect_related_party(&charter, &vendor) {
        record_related_party_disclosure(false, cost);
    }

    save_asset(
        ast_id,
        &CapitalAssetRow {
            asset_class,
            disposed: false,
            cost,
            residual,
            useful_life_blocks,
            acquired_block: context::block_number(),
            posted_depr: 0,
        },
    );
    storage::set_u64(KEY_ASSET_COUNT, ast_id + 1);

    let _ = commit_batch(&mut totals, &batch, &vendor, b"CAPX")?;
    ret::write_u64_word(ast_id);
    Ok(())
}

fn handle_dispose_capital_asset(args: &CalldataReader) -> Result<(), i32> {
    let asset_id = args.u64(0).ok_or(-3)?;
    let buyer = args.address(1).ok_or(-3)?;
    let cash_proceeds = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let ah = disburse_action_hash(8, &buyer, cash_proceeds, asset_id);
    let (_registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_DISPOSE_ASSET, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let _ = sweep_periodic_accruals_internal(&mut totals)?;
    let mut row = load_asset(asset_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.disposed {
        return Err(ERR_IFRS_SUBLEDGER_NOT_FOUND);
    }
    if cash_proceeds > 0 {
        require_inbound_bank_cash(&totals, cash_proceeds)?;
    }
    let batch =
        ifrs::derive_asset_disposal(row.asset_class, row.cost, row.posted_depr, cash_proceeds)?;
    row.disposed = true;
    save_asset(asset_id, &row);

    let j_id = commit_batch(&mut totals, &batch, &buyer, b"DISP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

/// Step 1 of bilateral `IFRS 16` Lease: Company proposes lease terms (`0` balance-sheet impact until Lessor accepts).
fn handle_propose_lease(args: &CalldataReader) -> Result<(), i32> {
    let lessor = args.address(0).ok_or(-3)?;
    let periodic_payment = args.u64(1).ok_or(-3)?;
    let term_periods = args.u64(2).ok_or(-3)?;
    let period_blocks = args.u64(3).ok_or(-3)?;
    let rate_bps = args.u64(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let ah = disburse_action_hash(9, &lessor, periodic_payment, term_periods);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_OFFER_LEASE, &ah, &auth_obj)?;
    require_valid_identity(&registry, &lessor)?;

    let lse_id = storage::get_u64(KEY_LEASE_COUNT);
    if lse_id >= MAX_LEASES {
        return Err(ERR_IFRS_SUBLEDGER_FULL);
    }
    let (_batch, pv) = ifrs::derive_lease_commencement(
        periodic_payment,
        term_periods,
        period_blocks,
        rate_bps,
    )?;

    save_lease(
        lse_id,
        &LeaseRow {
            lessor,
            status: 1, // Proposed — awaiting bilateral Lessor Identity acceptance!
            initial_pv: pv,
            rem_liability: pv,
            periodic_payment,
            rate_bps,
            total_periods: term_periods as u32,
            paid_periods: 0,
            period_blocks,
            start_block: 0,
            posted_amort: 0,
        },
    );
    storage::set_u64(KEY_LEASE_COUNT, lse_id + 1);
    ret::write_u64_word(lse_id);
    Ok(())
}

/// Step 2 of bilateral `IFRS 16` Lease: Lessor `Identity` accepts & commences the lease, posting
/// `Dr 1600 Right-of-Use Asset (PV) / Cr 2500 Lease Liability (PV)`.
fn handle_accept_lease(args: &CalldataReader) -> Result<(), i32> {
    let (registry, _charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let lease_id = args.u64(0).ok_or(-3)?;
    let mut row = load_lease(lease_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.status != 1 || caller != row.lessor {
        return Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
    }
    let (batch, pv) = ifrs::derive_lease_commencement(
        row.periodic_payment,
        row.total_periods as u64,
        row.period_blocks,
        row.rate_bps,
    )?;
    row.status = 2;
    row.initial_pv = pv;
    row.rem_liability = pv;
    row.start_block = context::block_number();
    save_lease(lease_id, &row);

    let mut totals = load_coa_totals();
    let j_id = commit_batch(&mut totals, &batch, &caller, b"LSEC")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_pay_lease_installment(args: &CalldataReader) -> Result<(), i32> {
    let lease_id = args.u64(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let mut row = load_lease(lease_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.status != 2 || row.paid_periods >= row.total_periods {
        return Err(ERR_IFRS_SUBLEDGER_NOT_FOUND);
    }
    let ah = disburse_action_hash(10, &row.lessor, row.periodic_payment, lease_id);
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_PAY_LEASE, &ah, &auth_obj)?;

    let is_final = (row.paid_periods + 1) == row.total_periods;
    let (batch, principal, interest) = ifrs::derive_lease_installment(
        row.rem_liability,
        row.periodic_payment,
        row.rate_bps,
        is_final,
    )?;
    let cash_paid = principal.saturating_add(interest);

    let mut totals = load_coa_totals();
    disburse_treasury_cash(&registry, &totals, &row.lessor, cash_paid)?;
    if detect_related_party(&charter, &row.lessor) {
        record_related_party_disclosure(false, cash_paid);
    }

    row.rem_liability = row.rem_liability.saturating_sub(principal);
    row.paid_periods += 1;
    if row.rem_liability == 0 || row.paid_periods >= row.total_periods {
        row.status = 3;
    }
    save_lease(lease_id, &row);

    let j_id = commit_batch(&mut totals, &batch, &row.lessor, b"LSEP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

/// Step 1 of bilateral Credit Sale (`IFRS 15` + `IFRS 9`): Company issues an invoice offer (`0` revenue until Buyer accepts!).
/// **Bans** related-party credit invoices (`IAS 24`).
fn handle_issue_credit_invoice(args: &CalldataReader) -> Result<(), i32> {
    let buyer = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let total_amount = args.u64(3).ok_or(-3)?;
    let due_blocks = args.u64(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let ah = disburse_action_hash(11, &buyer, total_amount, due_blocks);
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_ISSUE_INVOICE, &ah, &auth_obj)?;
    require_valid_identity(&registry, &buyer)?;

    let is_rp = detect_related_party(&charter, &buyer);
    let _ = ifrs::derive_credit_sale(total_amount, 0, due_blocks, is_rp)?;

    let inv_id = storage::get_u64(KEY_INVOICE_COUNT);
    if inv_id >= MAX_INVOICES {
        return Err(ERR_IFRS_SUBLEDGER_FULL);
    }
    save_invoice(
        inv_id,
        &CreditInvoiceRow {
            buyer,
            product_id,
            quantity,
            status: 1, // Offered — awaiting Buyer Identity acceptance!
            original_amount: total_amount,
            open_amount: total_amount,
            issued_block: context::block_number(),
            due_block: due_blocks, // stores duration until accepted
        },
    );
    storage::set_u64(KEY_INVOICE_COUNT, inv_id + 1);
    ret::write_u64_word(inv_id);
    Ok(())
}

/// Step 2 of bilateral Credit Sale: Buyer `Identity` co-accepts the invoice (`msg.sender == buyer`),
/// posting `Dr 1100 Trade Receivables / Cr 4000 Operating Revenue` (+ `IAS 2` WAC COGS if SKU exists).
fn handle_accept_credit_invoice(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let invoice_id = args.u64(0).ok_or(-3)?;
    let mut inv_row = load_invoice(invoice_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if inv_row.status != 1 || caller != inv_row.buyer {
        return Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
    }
    let is_rp = detect_related_party(&charter, &caller);

    let mut cogs = 0u64;
    if inv_row.product_id != [0u8; 32] && inv_row.quantity > 0 {
        if let Some(mut sku) = load_inv_sku(&inv_row.product_id) {
            let (c, rem_u, rem_c) =
                ifrs::compute_wac_cogs(sku.units_on_hand, sku.carrying_cost, inv_row.quantity);
            cogs = c;
            sku.units_on_hand = rem_u;
            sku.carrying_cost = rem_c;
            sku.total_units_sold = sku.total_units_sold.saturating_add(inv_row.quantity);
            save_inv_sku(&inv_row.product_id, &sku)?;
        }
    }

    let due_duration = inv_row.due_block;
    let batch = ifrs::derive_credit_sale(inv_row.original_amount, cogs, due_duration, is_rp)?;
    let now = context::block_number();
    inv_row.status = 2;
    inv_row.issued_block = now;
    inv_row.due_block = now.saturating_add(due_duration);
    save_invoice(invoice_id, &inv_row);

    let mut totals = load_coa_totals();
    let j_id = commit_batch(&mut totals, &batch, &caller, b"ARIN")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_settle_credit_invoice(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter) = ensure_active()?;
    let invoice_id = args.u64(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;

    let mut inv_row = load_invoice(invoice_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if inv_row.status != 2 || amount == 0 || amount > inv_row.open_amount {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, amount)?;
    let batch = ifrs::derive_receivable_collection(amount)?;

    inv_row.open_amount -= amount;
    if inv_row.open_amount == 0 {
        inv_row.status = 3;
    }
    save_invoice(invoice_id, &inv_row);

    let j_id = commit_batch(&mut totals, &batch, &inv_row.buyer, b"ARCL")?;
    ret::write_u64_word(j_id);
    Ok(())
}

/// Customer purchases a multi-block subscription (`IFRS 15` over-time performance obligation):
/// Verifies `amount` arrived in `treasuryIdentity` and credits `2300 Contract Liabilities` (Deferred Revenue).
fn handle_purchase_subscription(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let plan_code = args.bytes32(0).ok_or(-3)?;
    let duration_blocks = args.u64(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;

    let def_id = storage::get_u64(KEY_DEF_COUNT);
    if def_id >= MAX_DEFERRED_CONTRACTS {
        return Err(ERR_IFRS_SUBLEDGER_FULL);
    }
    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, amount)?;

    let is_rp = detect_related_party(&charter, &caller);
    if is_rp {
        record_related_party_disclosure(true, amount);
    }
    let batch = ifrs::derive_deferred_contract_receipt(amount, duration_blocks)?;

    let mut plan_tag = [0u8; 8];
    plan_tag.copy_from_slice(&plan_code[0..8]);
    save_def(
        def_id,
        &DeferredContractRow {
            customer: caller,
            is_related: is_rp,
            plan_tag,
            total_amount: amount,
            posted_earned: 0,
            start_block: context::block_number(),
            duration_blocks,
        },
    );
    storage::set_u64(KEY_DEF_COUNT, def_id + 1);

    let _ = commit_batch(&mut totals, &batch, &caller, b"SUBS")?;
    ret::write_u64_word(def_id);
    Ok(())
}

/// Step 1 of bilateral `IFRS 9` Term Loan: Company proposes borrowing terms (`0` liability until Lender funds).
fn handle_propose_term_loan(args: &CalldataReader) -> Result<(), i32> {
    let lender = args.address(0).ok_or(-3)?;
    let principal = args.u64(1).ok_or(-3)?;
    let rate_bps = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let ah = disburse_action_hash(12, &lender, principal, rate_bps);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_OFFER_LOAN, &ah, &auth_obj)?;
    require_valid_identity(&registry, &lender)?;
    if principal == 0 || rate_bps > 5_000 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }
    let ln_id = storage::get_u64(KEY_LOAN_COUNT);
    if ln_id >= MAX_LOANS {
        return Err(ERR_IFRS_SUBLEDGER_FULL);
    }
    save_loan(
        ln_id,
        &TermLoanRow {
            lender,
            status: 1,
            initial_principal: principal,
            rem_principal: principal,
            rate_bps,
            start_block: 0,
        },
    );
    storage::set_u64(KEY_LOAN_COUNT, ln_id + 1);
    ret::write_u64_word(ln_id);
    Ok(())
}

/// Step 2 of bilateral `IFRS 9` Term Loan: Lender transfers `principal` into `treasuryIdentity` and calls
/// `fundTermLoan(loanId)`, posting `Dr 1010 Cash / Cr 2600 Term Debt` (`CFF`).
fn handle_fund_term_loan(args: &CalldataReader) -> Result<(), i32> {
    let (registry, _charter) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let loan_id = args.u64(0).ok_or(-3)?;
    let mut row = load_loan(loan_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.status != 1 || caller != row.lender {
        return Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
    }
    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, row.initial_principal)?;
    let batch = ifrs::derive_loan_drawdown(row.initial_principal)?;

    row.status = 2;
    row.start_block = context::block_number();
    save_loan(loan_id, &row);

    let j_id = commit_batch(&mut totals, &batch, &caller, b"LOAN")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_pay_debt_service(args: &CalldataReader) -> Result<(), i32> {
    let loan_id = args.u64(0).ok_or(-3)?;
    let principal_paid = args.u64(1).ok_or(-3)?;
    let interest_paid = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let mut row = load_loan(loan_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.status != 2 {
        return Err(ERR_IFRS_SUBLEDGER_NOT_FOUND);
    }
    let total_cash = principal_paid
        .checked_add(interest_paid)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    let ah = disburse_action_hash(13, &row.lender, total_cash, loan_id);
    let (registry, charter, _caller) =
        require_accounting_ops_auth(&SEL_PAY_DEBT, &ah, &auth_obj)?;

    let batch = ifrs::derive_debt_service(row.rem_principal, principal_paid, interest_paid)?;
    let mut totals = load_coa_totals();
    disburse_treasury_cash(&registry, &totals, &row.lender, total_cash)?;
    if detect_related_party(&charter, &row.lender) {
        record_related_party_disclosure(false, total_cash);
    }

    row.rem_principal -= principal_paid;
    if row.rem_principal == 0 {
        row.status = 3;
    }
    save_loan(loan_id, &row);

    let j_id = commit_batch(&mut totals, &batch, &row.lender, b"DEBT")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_accrue_income_tax(args: &CalldataReader) -> Result<(), i32> {
    let tax_amount = args.u64(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let ah = disburse_action_hash(14, &[0u8; 20], tax_amount, 0);
    let (_registry, _charter, caller) =
        require_accounting_ops_auth(&SEL_ACCRUE_TAX, &ah, &auth_obj)?;

    let batch = ifrs::derive_current_tax_accrual(tax_amount)?;
    let mut totals = load_coa_totals();
    let j_id = commit_batch(&mut totals, &batch, &caller, b"TAXA")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_pay_income_tax(args: &CalldataReader) -> Result<(), i32> {
    let tax_authority = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = disburse_action_hash(15, &tax_authority, amount, 0);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_PAY_TAX, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let (dr, cr) = totals[ACC_TAX_PAYABLE as usize];
    if cr.saturating_sub(dr) < amount {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    disburse_treasury_cash(&registry, &totals, &tax_authority, amount)?;
    let batch = ifrs::derive_income_tax_payment(amount)?;
    let j_id = commit_batch(&mut totals, &batch, &tax_authority, b"TAXP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_quarantine_suspense_cash(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter) = ensure_active()?;
    let mut totals = load_coa_totals();
    let actual_bank = query_bank_balance_of_treasury()?;
    let booked = booked_cash_u64(&totals);
    if actual_bank <= booked {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let unattr = actual_bank - booked;
    let batch = ifrs::derive_suspense_quarantine(unattr)?;
    let treas = storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]);
    let j_id = commit_batch(&mut totals, &batch, &treas, b"SUSP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_refund_suspense(args: &CalldataReader) -> Result<(), i32> {
    let recipient = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = disburse_action_hash(16, &recipient, amount, 0);
    let (registry, _charter, _caller) =
        require_accounting_ops_auth(&SEL_REFUND_SUSPENSE, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let actual_bank = query_bank_balance_of_treasury()?;
    let booked = booked_cash_u64(&totals);
    if actual_bank > booked {
        let q = ifrs::derive_suspense_quarantine(actual_bank - booked)?;
        let treas = storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]);
        let _ = commit_batch(&mut totals, &q, &treas, b"SUSP")?;
    }
    let (sdr, scr) = totals[ACC_CASH_SUSPENSE as usize];
    if scr.saturating_sub(sdr) < amount {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    disburse_treasury_cash(&registry, &totals, &recipient, amount)?;
    let batch = ifrs::derive_suspense_refund(amount)?;
    let j_id = commit_batch(&mut totals, &batch, &recipient, b"RSUS")?;
    ret::write_u64_word(j_id);
    Ok(())
}

fn compute_pay_dividend_hash(recipient: &[u8; 20], amount: u64) -> [u8; 32] {
    disburse_action_hash(17, recipient, amount, 0)
}

fn handle_hash_pay_dividend(args: &CalldataReader) -> Result<(), i32> {
    let recipient = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_pay_dividend_hash(&recipient, amount));
    Ok(())
}

fn compute_paid_in_cap_hash(shares: u64, par_per_share: u64, total_proceeds: u64) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_IFRS_DISBURSE)
        .push_u64(18)
        .push_u64(shares)
        .push_u64(par_per_share)
        .push_u64(total_proceeds)
        .finish()
}

fn handle_hash_record_paid_in_capital(args: &CalldataReader) -> Result<(), i32> {
    let shares = args.u64(0).ok_or(-3)?;
    let par = args.u64(1).ok_or(-3)?;
    let proceeds = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_paid_in_cap_hash(shares, par, proceeds));
    Ok(())
}

/// Board-governed Paid-In Capital Receipt (`IAS 32`):
/// Requires real bank cash inflow in `treasuryIdentity` (`>= total_proceeds`) and credits strictly
/// `3000 Issued Share Capital` & `3010 Share Premium` (`CFF`), with zero P&L or Retained Earnings impact.
fn handle_record_paid_in_capital(args: &CalldataReader) -> Result<(), i32> {
    let shares = args.u64(0).ok_or(-3)?;
    let par_per_share = args.u64(1).ok_or(-3)?;
    let total_proceeds = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let ah = compute_paid_in_cap_hash(shares, par_per_share, total_proceeds);
    let (_registry, _charter, caller) =
        require_board_level_auth(&SEL_RECORD_PAID_IN_CAP, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    require_inbound_bank_cash(&totals, total_proceeds)?;
    let batch = ifrs::derive_equity_issuance(shares, par_per_share, total_proceeds)?;
    let j_id = commit_batch(&mut totals, &batch, &caller, b"PICP")?;
    ret::write_u64_word(j_id);
    Ok(())
}

/// Board-governed Dividend Disbursement (`IAS 32`):
/// 1. Commits all due periodic accruals (`depreciation`, `ROU`, `deferred revenue`, `ECL`).
/// 2. Reverts if `amount > distributable_profit` (forbidding illegal dividends out of Share Capital or hidden losses!).
/// 3. Disburses `amount` from `treasuryIdentity` and debits `3400 Retained Earnings`.
fn handle_pay_dividend(args: &CalldataReader) -> Result<(), i32> {
    let recipient = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let ah = compute_pay_dividend_hash(&recipient, amount);
    let (registry, _charter, _caller) =
        require_board_level_auth(&SEL_PAY_DIVIDEND, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let _ = sweep_periodic_accruals_internal(&mut totals)?;
    let st = ifrs::compile_statements(&totals, &AccrualProjection::default());

    let batch = ifrs::derive_dividend_payment(amount, st.distributable_profit)?;
    disburse_treasury_cash(&registry, &totals, &recipient, amount)?;
    let j_id = commit_batch(&mut totals, &batch, &recipient, b"DIVD")?;
    ret::write_u64_word(j_id);
    Ok(())
}

/// Permissionless Periodic Accrual Crank (`IAS 16/38`, `IFRS 16`, `IFRS 15`, `IFRS 9`, `2900 Suspense`).
fn handle_process_periodic_accruals(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter) = ensure_active()?;
    let mut totals = load_coa_totals();
    let count = sweep_periodic_accruals_internal(&mut totals)?;
    ret::write_u64_word(count);
    Ok(())
}

fn compute_close_period_hash(period: u64) -> [u8; 32] {
    ActionHasher::<96>::new(&context::self_address(), &ACTION_CLOSE_FISCAL_PERIOD)
        .push_u64(period)
        .finish()
}

fn handle_hash_close_fiscal_period(args: &CalldataReader) -> Result<(), i32> {
    let period = args.u64(0).ok_or(-3)?;
    ret::write_word(&compute_close_period_hash(period));
    Ok(())
}

/// Board-governed Fiscal Period Close (`IAS 1` + `IAS 8`):
/// 1. Commits all due periodic accruals up to `context::block_number()`.
/// 2. Rolls all nominal accounts (`24..=31`) into `3400 Retained Earnings`.
/// 3. Locks the closed period watermark permanently and advances `fiscalPeriod + 1`.
fn handle_close_fiscal_period(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    let cur_period = storage::get_u64(KEY_FISCAL_PERIOD).max(1);
    let ah = compute_close_period_hash(cur_period);
    let (_registry, _charter, caller) =
        require_board_level_auth(&SEL_CLOSE_PERIOD, &ah, &auth_obj)?;

    let mut totals = load_coa_totals();
    let _ = sweep_periodic_accruals_internal(&mut totals)?;
    let net_inc = ifrs::roll_nominal_accounts_into_retained_earnings(&mut totals)?;
    save_coa_totals(&totals);

    let now = context::block_number();
    storage::set_u64(KEY_LAST_CLOSED_BLK, now);
    storage::set_u64(KEY_PERIOD_START_BLK, now);
    storage::set_u64(KEY_FISCAL_PERIOD, cur_period + 1);
    storage::set_u64(KEY_OPEX_RND, 0);
    storage::set_u64(KEY_OPEX_SM, 0);
    storage::set_u64(KEY_OPEX_GA, 0);
    emit_aux_counters();

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&cur_period.to_be_bytes());
    ev[8..16].copy_from_slice(&(net_inc.clamp(i64::MIN as i128, i64::MAX as i128) as i64).to_be_bytes());
    ev[16..24].copy_from_slice(&now.to_be_bytes());
    events::emit(&[EV_PERIOD_CLOSED, addr_topic(&caller)], &ev);

    ret::write_u64_word(cur_period + 1);
    Ok(())
}

// ============================================================================
// Financial Statement & Sub-Ledger Snapshot Readers
// ============================================================================

fn clamp_i64_be(v: i128) -> [u8; 8] {
    (v.clamp(i64::MIN as i128, i64::MAX as i128) as i64).to_be_bytes()
}

fn handle_get_financial_statements(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let now = context::block_number();
    let totals = load_coa_totals();
    let proj = compute_live_accrual_projection(&totals, now);
    let st = ifrs::compile_statements(&totals, &proj);

    let mut out = [0u8; STATEMENTS_FRAME_BYTES];
    let period = storage::get_u64(KEY_FISCAL_PERIOD).max(1);
    let p_start = storage::get_u64(KEY_PERIOD_START_BLK);
    let p_closed = storage::get_u64(KEY_LAST_CLOSED_BLK);
    let j_cnt = storage::get_u64(KEY_JOURNAL_COUNT);
    let actual_bank = query_bank_balance_of_treasury().unwrap_or(0);
    let booked_cash = booked_cash_u64(&totals);

    let mut flags = 0u64;
    if st.equation_balanced {
        flags |= 1;
    }
    if st.custody_clean {
        flags |= 2;
    }
    if storage::get_u64(KEY_VIRGIN_CUSTODY) == 1 {
        flags |= 4;
    }
    if storage::get_address(KEY_HFS_REGISTRY).unwrap_or([0u8; 20]) != [0u8; 20] {
        flags |= 8;
    }

    out[0..8].copy_from_slice(&period.to_be_bytes());
    out[8..16].copy_from_slice(&p_start.to_be_bytes());
    out[16..24].copy_from_slice(&p_closed.to_be_bytes());
    out[24..32].copy_from_slice(&now.to_be_bytes());
    out[32..40].copy_from_slice(&j_cnt.to_be_bytes());
    out[40..48].copy_from_slice(&actual_bank.to_be_bytes());
    out[48..56].copy_from_slice(&booked_cash.to_be_bytes());
    out[56..64].copy_from_slice(&proj.unattributed_bank_inflow.to_be_bytes());
    out[64..72].copy_from_slice(&proj.bank_custody_shortfall.to_be_bytes());
    out[72..80].copy_from_slice(&flags.to_be_bytes());

    out[80..88].copy_from_slice(&get_i64(KEY_CFO_NET).to_be_bytes());
    out[88..96].copy_from_slice(&get_i64(KEY_CFI_NET).to_be_bytes());
    out[96..104].copy_from_slice(&get_i64(KEY_CFF_NET).to_be_bytes());

    out[104..112].copy_from_slice(&storage::get_u64(KEY_RP_TX_CNT).to_be_bytes());
    out[112..120].copy_from_slice(&storage::get_u64(KEY_RP_INFLOW).to_be_bytes());
    out[120..128].copy_from_slice(&storage::get_u64(KEY_RP_OUTFLOW).to_be_bytes());

    out[128..136].copy_from_slice(&storage::get_u64(KEY_OPEX_RND).to_be_bytes());
    out[136..144].copy_from_slice(&storage::get_u64(KEY_OPEX_SM).to_be_bytes());
    out[144..152].copy_from_slice(&storage::get_u64(KEY_OPEX_GA).to_be_bytes());

    let unposted_da = proj
        .unposted_ppe_depr
        .saturating_add(proj.unposted_rou_amort)
        .saturating_add(proj.unposted_intang_amort);
    let unposted_def = proj
        .unposted_deferred_rev_arms
        .saturating_add(proj.unposted_deferred_rev_related);
    out[152..160].copy_from_slice(&unposted_da.to_be_bytes());
    out[160..168].copy_from_slice(&unposted_def.to_be_bytes());
    out[168..176].copy_from_slice(&proj.target_ecl_allowance.to_be_bytes());
    out[176..184].copy_from_slice(&storage::get_u64(KEY_SALE_COUNT).to_be_bytes());

    let aggs = [
        st.total_current_assets,
        st.total_non_current_assets,
        st.total_assets,
        st.total_current_liabilities,
        st.total_non_current_liabilities,
        st.total_liabilities,
        st.total_equity,
        st.gross_revenue_arms_length,
        st.gross_revenue_related_party,
        st.net_revenue,
        st.gross_profit,
        st.operating_income_ebit,
        st.net_income,
        st.distributable_profit,
    ];
    let mut a = 0;
    while a < aggs.len() {
        out[184 + a * 8..192 + a * 8].copy_from_slice(&clamp_i64_be(aggs[a]));
        a += 1;
    }

    let mut c = 0;
    while c < COA_COUNT {
        out[296 + c * 8..304 + c * 8].copy_from_slice(&clamp_i64_be(st.normal_balances[c]));
        c += 1;
    }

    out[552..572].copy_from_slice(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    out[572..592].copy_from_slice(&storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]));
    out[592..612].copy_from_slice(&storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]));

    let counts = [
        storage::get_u64(KEY_INV_SKU_COUNT) as u32,
        storage::get_u64(KEY_ASSET_COUNT) as u32,
        storage::get_u64(KEY_LEASE_COUNT) as u32,
        storage::get_u64(KEY_DEF_COUNT) as u32,
        storage::get_u64(KEY_INVOICE_COUNT) as u32,
        storage::get_u64(KEY_LOAN_COUNT) as u32,
        0u32,
    ];
    let mut k = 0;
    while k < counts.len() {
        out[612 + k * 4..616 + k * 4].copy_from_slice(&counts[k].to_be_bytes());
        k += 1;
    }

    ret::write(&out);
    Ok(())
}

fn pack_schedules_into_buf(out: &mut [u8], mut pos: usize, now: u64) -> (usize, [u32; 6]) {
    let inv_cnt = storage::get_u64(KEY_INV_SKU_COUNT).min(MAX_INV_SKUS);
    let mut written_inv = 0u32;
    let mut i = 0u64;
    while i < inv_cnt && pos + 56 <= out.len() {
        let mut sku = [0u8; 32];
        if storage::get_into(inv_idx_key(i).as_slice(), &mut sku) == Some(32) {
            if let Some(st) = load_inv_sku(&sku) {
                let w = encode_inv_sku_wire(&sku, &st);
                out[pos..pos + 56].copy_from_slice(&w);
                pos += 56;
                written_inv += 1;
            }
        }
        i += 1;
    }

    let ast_cnt = storage::get_u64(KEY_ASSET_COUNT).min(MAX_FIXED_ASSETS);
    let mut written_ast = 0u32;
    let mut a = 0u64;
    while a < ast_cnt && pos + 64 <= out.len() {
        if let Some(row) = load_asset(a) {
            let w = encode_asset_wire(a, &row, now);
            out[pos..pos + 64].copy_from_slice(&w);
            pos += 64;
            written_ast += 1;
        }
        a += 1;
    }

    let lse_cnt = storage::get_u64(KEY_LEASE_COUNT).min(MAX_LEASES);
    let mut written_lse = 0u32;
    let mut l = 0u64;
    while l < lse_cnt && pos + 96 <= out.len() {
        if let Some(ls) = load_lease(l) {
            let w = encode_lease_wire(l, &ls);
            out[pos..pos + 96].copy_from_slice(&w);
            pos += 96;
            written_lse += 1;
        }
        l += 1;
    }

    let def_cnt = storage::get_u64(KEY_DEF_COUNT).min(MAX_DEFERRED_CONTRACTS);
    let mut written_def = 0u32;
    let mut d = 0u64;
    while d < def_cnt && pos + 80 <= out.len() {
        if let Some(dc) = load_def(d) {
            let w = encode_def_wire(d, &dc, now);
            out[pos..pos + 80].copy_from_slice(&w);
            pos += 80;
            written_def += 1;
        }
        d += 1;
    }

    let inv_ar_cnt = storage::get_u64(KEY_INVOICE_COUNT).min(MAX_INVOICES);
    let mut written_ar = 0u32;
    let mut ar = 0u64;
    while ar < inv_ar_cnt && pos + 72 <= out.len() {
        if let Some(inv) = load_invoice(ar) {
            let w = encode_invoice_wire(ar, &inv, now);
            out[pos..pos + 72].copy_from_slice(&w);
            pos += 72;
            written_ar += 1;
        }
        ar += 1;
    }

    let ln_cnt = storage::get_u64(KEY_LOAN_COUNT).min(MAX_LOANS);
    let mut written_ln = 0u32;
    let mut ln = 0u64;
    while ln < ln_cnt && pos + 64 <= out.len() {
        if let Some(row) = load_loan(ln) {
            let w = encode_loan_wire(ln, &row);
            out[pos..pos + 64].copy_from_slice(&w);
            pos += 64;
            written_ln += 1;
        }
        ln += 1;
    }

    (
        pos,
        [
            written_inv,
            written_ast,
            written_lse,
            written_def,
            written_ar,
            written_ln,
        ],
    )
}

/// Atomic Realtime Event-Sourcing Anchor Snapshot (`getRealtimeAnchorState()`):
/// Returns the exact raw 32-account General Ledger (`512B` `(dr_u64, cr_u64)`), gross & net `IAS 7`
/// cash flow accumulators, `IAS 24` & `OpEx` counters, `actualBank`, governance flags, and all 6
/// sub-ledger schedules in a single frame so front-end UIs can hydrate once at `anchorBlock` and
/// stream 100% of subsequent updates from `IfrsJournalPosted` + `IfrsSubledgerUpdated` + `IfrsFiscalPeriodClosed`
/// event logs and block headers with zero RPC polling!
fn handle_get_realtime_anchor_state(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let now = context::block_number();
    let totals = load_coa_totals();
    let proj = compute_live_accrual_projection(&totals, now);
    let st = ifrs::compile_statements(&totals, &proj);
    let period = storage::get_u64(KEY_FISCAL_PERIOD).max(1);
    let p_start = storage::get_u64(KEY_PERIOD_START_BLK);
    let p_closed = storage::get_u64(KEY_LAST_CLOSED_BLK);
    let j_cnt = storage::get_u64(KEY_JOURNAL_COUNT);
    let actual_bank = query_bank_balance_of_treasury().unwrap_or(0);

    let mut flags = 0u64;
    if st.equation_balanced {
        flags |= 1;
    }
    if st.custody_clean {
        flags |= 2;
    }
    if storage::get_u64(KEY_VIRGIN_CUSTODY) == 1 {
        flags |= 4;
    }
    if storage::get_address(KEY_HFS_REGISTRY).unwrap_or([0u8; 20]) != [0u8; 20] {
        flags |= 8;
    }

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        out[0..ANCHOR_HEADER_BYTES].fill(0);
        out[0..8].copy_from_slice(&period.to_be_bytes());
        out[8..16].copy_from_slice(&p_start.to_be_bytes());
        out[16..24].copy_from_slice(&p_closed.to_be_bytes());
        out[24..32].copy_from_slice(&now.to_be_bytes());
        out[32..40].copy_from_slice(&j_cnt.to_be_bytes());
        out[40..48].copy_from_slice(&actual_bank.to_be_bytes());
        out[48..56].copy_from_slice(&flags.to_be_bytes());
        out[56..64].copy_from_slice(&get_i64(KEY_CFO_NET).to_be_bytes());
        out[64..72].copy_from_slice(&get_i64(KEY_CFI_NET).to_be_bytes());
        out[72..80].copy_from_slice(&get_i64(KEY_CFF_NET).to_be_bytes());
        out[80..88].copy_from_slice(&storage::get_u64(KEY_CFO_IN).to_be_bytes());
        out[88..96].copy_from_slice(&storage::get_u64(KEY_CFO_OUT).to_be_bytes());
        out[96..104].copy_from_slice(&storage::get_u64(KEY_CFI_IN).to_be_bytes());
        out[104..112].copy_from_slice(&storage::get_u64(KEY_CFI_OUT).to_be_bytes());
        out[112..120].copy_from_slice(&storage::get_u64(KEY_CFF_IN).to_be_bytes());
        out[120..128].copy_from_slice(&storage::get_u64(KEY_CFF_OUT).to_be_bytes());
        let aux = encode_aux_counters_wire();
        out[128..184].copy_from_slice(&aux);
        out[184..204].copy_from_slice(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
        out[204..224].copy_from_slice(&storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]));
        out[224..244].copy_from_slice(&storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]));

        let mut c = 0usize;
        while c < COA_COUNT {
            let base = ANCHOR_HEADER_BYTES + c * 16;
            out[base..base + 8].copy_from_slice(&totals[c].0.to_be_bytes());
            out[base + 8..base + 16].copy_from_slice(&totals[c].1.to_be_bytes());
            c += 1;
        }

        let sched_start = ANCHOR_HEADER_BYTES + COA_COUNT * 16; // 272 + 512 = 784
        let (end_pos, counts) = pack_schedules_into_buf(out, sched_start, now);
        let mut s = 0usize;
        while s < 6 {
            out[244 + s * 4..248 + s * 4].copy_from_slice(&counts[s].to_be_bytes());
            s += 1;
        }
        ret::write(&out[..end_pos]);
    }
    Ok(())
}

fn handle_get_schedules_snapshot(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let now = context::block_number();
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        let (pos, counts) = pack_schedules_into_buf(out, 24, now);
        let mut s = 0usize;
        while s < 6 {
            out[s * 4..(s + 1) * 4].copy_from_slice(&counts[s].to_be_bytes());
            s += 1;
        }
        ret::write(&out[..pos]);
    }
    Ok(())
}

fn handle_get_journal_slice(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let offset = args.u64(0).ok_or(-3)?;
    let limit = args.u64(1).ok_or(-3)?.min(MAX_JOURNAL_SLICE);
    let total = storage::get_u64(KEY_JOURNAL_COUNT);

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        out[0..8].copy_from_slice(&total.to_be_bytes());
        let mut written = 0u64;
        let mut pos = 16usize;
        let mut idx = offset;
        while idx < total && written < limit && pos + JOURNAL_ENTRY_BYTES <= out.len() {
            let mut rec = [0u8; JOURNAL_ENTRY_BYTES];
            if storage::get_into(journal_key(idx).as_slice(), &mut rec) == Some(JOURNAL_ENTRY_BYTES)
            {
                out[pos..pos + JOURNAL_ENTRY_BYTES].copy_from_slice(&rec);
                pos += JOURNAL_ENTRY_BYTES;
                written += 1;
            }
            idx += 1;
        }
        out[8..16].copy_from_slice(&written.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

fn handle_journal_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_JOURNAL_COUNT));
    Ok(())
}

fn handle_associated_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_hfs_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_HFS_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_operating_bank_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_treasury_identity(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_total_revenue(_args: &CalldataReader) -> Result<(), i32> {
    let totals = load_coa_totals();
    let proj = compute_live_accrual_projection(&totals, context::block_number());
    let st = ifrs::compile_statements(&totals, &proj);
    let rev = st.net_revenue.max(0).min(u64::MAX as i128) as u64;
    ret::write_u64_word(rev);
    Ok(())
}

fn handle_total_units_sold(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_UNITS_SOLD));
    Ok(())
}

fn handle_sale_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_SALE_COUNT));
    Ok(())
}

fn handle_get_sale(args: &CalldataReader) -> Result<(), i32> {
    let sale_idx = args.u64(0).ok_or(-3)?;
    if sale_idx >= storage::get_u64(KEY_SALE_COUNT) {
        return Err(-62);
    }
    let mut raw = [0u8; SALE_RECORD_LEN];
    if storage::get_into(sale_key(sale_idx).as_slice(), &mut raw) != Some(SALE_RECORD_LEN) {
        return Err(-62);
    }
    let mut out = [0u8; 224];
    out[0..32].copy_from_slice(&raw[0..32]);
    out[44..64].copy_from_slice(&raw[32..52]);
    out[88..96].copy_from_slice(&raw[52..60]);
    out[120..128].copy_from_slice(&raw[60..68]);
    out[152..160].copy_from_slice(&raw[68..76]);
    out[184..192].copy_from_slice(&raw[76..84]);
    out[204..224].copy_from_slice(&raw[84..104]);
    ret::write(&out);
    Ok(())
}

fn handle_product_sales_of(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let (u, r) = load_pair_u64(product_stats_key(&product_id).as_slice());
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&u.to_be_bytes());
    out[56..64].copy_from_slice(&r.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_buyer_purchases_of(args: &CalldataReader) -> Result<(), i32> {
    let buyer = args.address(0).ok_or(-3)?;
    let (u, s) = load_pair_u64(buyer_stats_key(&buyer).as_slice());
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&u.to_be_bytes());
    out[56..64].copy_from_slice(&s.to_be_bytes());
    ret::write(&out);
    Ok(())
}

// ============================================================================
// Multi-Subroutine Conservation & Anti-Bypass Security Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::{CHARTER_STATE_ACTIVE, ERR_UNAPPROVED_CODE_HASH};
    use hps_sdk::ifrs::{
        ASSET_CLASS_IT_HARDWARE, ERR_IFRS_BELOW_CAPEX_FLOOR,
        ERR_IFRS_INSUFFICIENT_REALIZED_PROFIT, ERR_IFRS_RELATED_PARTY_CREDIT_BANNED,
    };
    use hps_sdk::mock;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    thread_local! {
        static BANK_BALS: RefCell<BTreeMap<[u8; 20], u64>> = RefCell::new(BTreeMap::new());
        static TREAS_INIT: RefCell<Option<[u8; 20]>> = const { RefCell::new(None) };
    }

    fn encode_init_calldata(
        reg: [u8; 20],
        hfs_reg: [u8; 20],
        chr: [u8; 20],
        bank: [u8; 20],
        treas: [u8; 20],
        handle: &str,
        nick: &str,
    ) -> Vec<u8> {
        let mut cd = vec![0u8; 4 + 32 * 11];
        cd[0..4].copy_from_slice(&selector(
            "initialize(address,address,address,address,address,string,string)",
        ));
        cd[16..36].copy_from_slice(&reg);
        cd[48..68].copy_from_slice(&hfs_reg);
        cd[80..100].copy_from_slice(&chr);
        cd[112..132].copy_from_slice(&bank);
        cd[144..164].copy_from_slice(&treas);
        cd[188..196].copy_from_slice(&(224u64).to_be_bytes());
        cd[220..228].copy_from_slice(&(288u64).to_be_bytes());
        cd[252..260].copy_from_slice(&(handle.len() as u64).to_be_bytes());
        cd[260..260 + handle.len()].copy_from_slice(handle.as_bytes());
        cd[316..324].copy_from_slice(&(nick.len() as u64).to_be_bytes());
        cd[324..324 + nick.len()].copy_from_slice(nick.as_bytes());
        cd
    }

    fn read_stmt_i64(frame: &[u8], off: usize) -> i64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&frame[off..off + 8]);
        i64::from_be_bytes(b)
    }

    fn read_stmt_u64(frame: &[u8], off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&frame[off..off + 8]);
        u64::from_be_bytes(b)
    }

    #[test]
    fn virgin_custody_ifrs_standards_and_anti_bypass_controls_end_to_end() {
        mock::reset();
        BANK_BALS.with(|b| b.borrow_mut().clear());
        TREAS_INIT.with(|t| *t.borrow_mut() = None);

        const REGISTRY: [u8; 20] = [0x10; 20];
        const HFS_REG: [u8; 20] = [0x11; 20];
        const CHARTER: [u8; 20] = [0x20; 20];
        const BANK: [u8; 20] = [0x30; 20];
        const TREAS: [u8; 20] = [0x40; 20];
        const ACC: [u8; 20] = [0x50; 20];
        const PROD_MOD: [u8; 20] = [0x60; 20];
        const ROGUE_MOD: [u8; 20] = [0x66; 20];
        const SHARE_MOD: [u8; 20] = [0x61; 20];

        const FOUNDER_DIR: [u8; 20] = [0x01; 20]; // Director & 60% shareholder (Related Party!)
        const CUSTOMER: [u8; 20] = [0x02; 20]; // Arm's-length customer
        const SUPPLIER: [u8; 20] = [0x03; 20]; // Arm's-length hardware/inventory vendor
        const LESSOR: [u8; 20] = [0x04; 20]; // Arm's-length facility lessor

        fn call_at(target: [u8; 20], sender: [u8; 20], blk: u64, cd: &[u8]) -> (i32, Vec<u8>) {
            mock::set_block_number(blk);
            match mock::transact_as(sender, target, cd) {
                Ok(out) => (0, out),
                Err(rc) => (rc, Vec::new()),
            }
        }

        mock::register_hps(ACC, dispatch_calldata);

        // Mock Virgin Identity HFS for `treasuryIdentity`
        fn treas_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("initializeWithNickname(address,string,string)") } {
                let already = TREAS_INIT.with(|t| t.borrow().is_some());
                if already {
                    return -22; // Rejects already-initialized Identity!
                }
                let owner = args.address(0).unwrap();
                TREAS_INIT.with(|t| *t.borrow_mut() = Some(owner));
                return 0;
            }
            if sel == const { selector("owner()") } {
                let owner = TREAS_INIT.with(|t| t.borrow().unwrap_or([0u8; 20]));
                ret::write_address(&owner);
                return 0;
            }
            if sel == const { selector("transferBankBalance(address,address,uint64)") } {
                let caller = context::msg_sender();
                let owner = TREAS_INIT.with(|t| t.borrow().unwrap_or([0u8; 20]));
                if caller != owner {
                    return -21; // ONLY `AccountingLedger` can move cash!
                }
                let _bank = args.address(0).unwrap();
                let to = args.address(1).unwrap();
                let amt = args.u64(2).unwrap();
                let me = context::self_address();
                let ok = BANK_BALS.with(|b| {
                    let mut map = b.borrow_mut();
                    let cur = *map.get(&me).unwrap_or(&0);
                    if cur < amt {
                        return false;
                    }
                    map.insert(me, cur - amt);
                    *map.entry(to).or_insert(0) += amt;
                    true
                });
                if !ok {
                    return -16;
                }
                ret::write_bool(true);
                return 0;
            }
            -2
        }
        mock::register_hps(TREAS, treas_dispatch);

        fn prod_dispatch(_raw: &[u8]) -> i32 { 0 }
        fn rogue_dispatch(_raw: &[u8]) -> i32 { 0 }
        fn share_dispatch(_raw: &[u8]) -> i32 { 0 }
        mock::register_hps(PROD_MOD, prod_dispatch);
        mock::register_hps(ROGUE_MOD, rogue_dispatch);
        mock::register_hps(SHARE_MOD, share_dispatch);

        mock::register_hps(REGISTRY, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("isAllowedIdentityCodeHash(bytes32)") } {
                let ch = args.bytes32(0).unwrap();
                ret::write_bool(ch == mock::dispatch_code_hash(treas_dispatch));
                return 0;
            }
            -2
        });

        mock::register_hps(HFS_REG, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("allowedAbiVersion(bytes32,bytes32)") } {
                let tid = args.bytes32(0).unwrap();
                let ch = args.bytes32(1).unwrap();
                let ok = (tid == HFS_TYPE_PRODUCT_LEDGER
                    && ch == mock::dispatch_code_hash(prod_dispatch))
                    || (tid == HFS_TYPE_SHARE_CAPITAL
                        && ch == mock::dispatch_code_hash(share_dispatch));
                ret::write_u64_word(if ok { 1 } else { 0 });
                return 0;
            }
            -2
        });

        mock::register_hps(CHARTER, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("state()") } {
                ret::write_u64_word(CHARTER_STATE_ACTIVE);
                return 0;
            }
            if sel == const { selector("directorCount()") } {
                ret::write_u64_word(1);
                return 0;
            }
            if sel == const { selector("isDirector(address)") } {
                ret::write_bool(args.address(0).unwrap() == FOUNDER_DIR);
                return 0;
            }
            if sel == const { selector("hasRole(bytes32,address)") } {
                ret::write_bool(args.address(1).unwrap() == FOUNDER_DIR);
                return 0;
            }
            if sel == const { selector("getFunctionAuth(address,bytes4)") } {
                ret::write_word(&[0u8; 32]);
                return 0;
            }
            if sel == const { selector("isAuthorizedModule(address,bytes32)") } {
                let m = args.address(0).unwrap();
                // Even if Charter authorized `ROGUE_MOD`, `HfsRegistry` code_hash gate must block it!
                ret::write_bool(m == PROD_MOD || m == SHARE_MOD || m == ROGUE_MOD);
                return 0;
            }
            if sel == const { selector("convertedCommonTotals(address)") } {
                let who = args.address(0).unwrap();
                let mut out = [0u8; 64];
                let h: u64 = if who == FOUNDER_DIR { 60_000 } else { 0 };
                out[24..32].copy_from_slice(&h.to_be_bytes());
                out[56..64].copy_from_slice(&100_000u64.to_be_bytes());
                ret::write(&out);
                return 0;
            }
            -2
        });

        mock::register_hps(BANK, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("balanceOf(address)") } {
                let a = args.address(0).unwrap();
                let bal = BANK_BALS.with(|b| *b.borrow().get(&a).unwrap_or(&0));
                ret::write_u64_word(bal);
                return 0;
            }
            -2
        });

        // EXPLOIT CHECK 1: Pre-initialized `treasuryIdentity` (potential hidden `setDelegate` backdoor) MUST REVERT!
        TREAS_INIT.with(|t| *t.borrow_mut() = Some(FOUNDER_DIR));
        let init_cd = encode_init_calldata(
            REGISTRY,
            HFS_REG,
            CHARTER,
            BANK,
            TREAS,
            "acme_treasury",
            "Acme Treasury",
        );
        let (rc_bad_treas, _) = call_at(ACC, FOUNDER_DIR, 100, &init_cd);
        assert_eq!(rc_bad_treas, ERR_IFRS_CUSTODY_OWNER_MISMATCH);

        // Reset `treasuryIdentity` to virgin state (`KEY_INIT == 0`) -> succeeds and locks `owner = ACC`!
        TREAS_INIT.with(|t| *t.borrow_mut() = None);
        let (rc_init, _) = call_at(ACC, FOUNDER_DIR, 100, &init_cd);
        assert_eq!(rc_init, 0);
        assert_eq!(TREAS_INIT.with(|t| *t.borrow()), Some(ACC));

        // EXPLOIT CHECK 2: Rogue module with unapproved `code_hash` rejected even if Charter authorized it!
        let sku_1 = keccak256(b"SKU-QUANTUM-BLADE");
        let rogue_sale_cd = CallEncoder::<192>::new(const {
            selector("bookCashSale(bytes32,address,uint64,uint64,uint64)")
        })
        .push_bytes32(&sku_1)
        .push_address(&CUSTOMER)
        .push_u64(1)
        .push_u64(5_000)
        .push_u64(5_000);
        let (rc_rogue, _) = call_at(ACC, ROGUE_MOD, 101, rogue_sale_cd.as_slice());
        assert_eq!(rc_rogue, ERR_UNAPPROVED_CODE_HASH);

        // EXPLOIT CHECK 3: Phantom cash inflow (`bookCashSale` without real bank transfer) rejected!
        let (rc_phantom, _) = call_at(ACC, PROD_MOD, 101, rogue_sale_cd.as_slice());
        assert_eq!(rc_phantom, ERR_IFRS_BANK_CASH_SHORTFALL);

        // 1. IAS 32 Equity Issuance via `ShareCapital` (`500,000` SGD deposited into `treasuryIdentity`)
        BANK_BALS.with(|b| b.borrow_mut().insert(TREAS, 500_000));
        let eq_cd = CallEncoder::<160>::new(const {
            selector("bookEquityIssuanceFromModule(address,uint64,uint64,uint64)")
        })
        .push_address(&FOUNDER_DIR)
        .push_u64(100_000)
        .push_u64(1)
        .push_u64(500_000);
        let (rc_eq, _) = call_at(ACC, SHARE_MOD, 102, eq_cd.as_slice());
        assert_eq!(rc_eq, 0);

        // 2. IAS 16 CapEx: micro-OpEx capitalization rejected; valid `120,000` IT Hardware disburses cash atomically!
        let bad_capex_cd = CallEncoder::<288>::new(const {
            selector("acquireCapitalAsset(address,uint64,uint64,uint64,uint64,bool,bytes32,address)")
        })
        .push_address(&SUPPLIER)
        .push_u64(ASSET_CLASS_IT_HARDWARE as u64)
        .push_u64(800)
        .push_u64(0)
        .push_u64(1_000)
        .push_bool(true)
        .push_bytes32(&[0xAA; 32])
        .push_address(&[0u8; 20]);
        let (rc_bad_capx, _) = call_at(ACC, FOUNDER_DIR, 105, bad_capex_cd.as_slice());
        assert_eq!(rc_bad_capx, ERR_IFRS_BELOW_CAPEX_FLOOR);

        let good_capex_cd = CallEncoder::<288>::new(const {
            selector("acquireCapitalAsset(address,uint64,uint64,uint64,uint64,bool,bytes32,address)")
        })
        .push_address(&SUPPLIER)
        .push_u64(ASSET_CLASS_IT_HARDWARE as u64)
        .push_u64(120_000)
        .push_u64(0)
        .push_u64(1_200)
        .push_bool(true)
        .push_bytes32(&[0xAA; 32])
        .push_address(&[0u8; 20]);
        let (rc_capx, _) = call_at(ACC, FOUNDER_DIR, 110, good_capex_cd.as_slice());
        assert_eq!(rc_capx, 0);
        assert_eq!(BANK_BALS.with(|b| *b.borrow().get(&SUPPLIER).unwrap_or(&0)), 120_000);

        // 3. IAS 2 Inventory Procurement (`50` units @ `1,000` = `50,000` SGD paid from `treasuryIdentity`)
        let inv_cd = CallEncoder::<224>::new(const {
            selector("procureInventory(bytes32,address,uint64,uint64,bool,address)")
        })
        .push_bytes32(&sku_1)
        .push_address(&SUPPLIER)
        .push_u64(50)
        .push_u64(50_000)
        .push_bool(true)
        .push_address(&[0u8; 20]);
        let (rc_inv, _) = call_at(ACC, FOUNDER_DIR, 112, inv_cd.as_slice());
        assert_eq!(rc_inv, 0);

        // 4. IFRS 15 + IAS 2 WAC Sale: Customer buys 10 units @ `2,500` = `25,000` (auto COGS = `10,000`)
        BANK_BALS.with(|b| *b.borrow_mut().get_mut(&TREAS).unwrap() += 25_000);
        let sale_cd = CallEncoder::<192>::new(const {
            selector("bookCashSale(bytes32,address,uint64,uint64,uint64)")
        })
        .push_bytes32(&sku_1)
        .push_address(&CUSTOMER)
        .push_u64(10)
        .push_u64(2_500)
        .push_u64(25_000);
        let (rc_sale, _) = call_at(ACC, PROD_MOD, 115, sale_cd.as_slice());
        assert_eq!(rc_sale, 0);

        // Take an event-sourcing anchor snapshot right here (`block = 115`), then verify that EVERY
        // subsequent transaction and block tick can reconstruct 100% of `getFinancialStatements()`
        // purely from `mock::events()[ev_cursor..]` without reading storage!
        let anchor_cd = CallEncoder::<16>::new(const { selector("getRealtimeAnchorState()") });
        let (rc_anc, anc_raw) = call_at(ACC, CUSTOMER, 115, anchor_cd.as_slice());
        assert_eq!(rc_anc, 0);
        assert!(anc_raw.len() >= ANCHOR_HEADER_BYTES + COA_COUNT * 16);
        let mut ev_cursor = mock::events().len();

        struct ClientStreamState {
            period: u64,
            journal_cnt: u64,
            cfo_net: i64,
            cfi_net: i64,
            cff_net: i64,
            aux: [u64; 7],
            totals: [(u64, u64); COA_COUNT],
            assets: BTreeMap<u64, CapitalAssetRow>,
            leases: BTreeMap<u64, LeaseRow>,
            defs: BTreeMap<u64, DeferredContractRow>,
            invoices: BTreeMap<u64, CreditInvoiceRow>,
        }

        let u32_be = |b: &[u8], o: usize| -> u32 {
            u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
        };
        let mut client = {
            let mut totals = [(0u64, 0u64); COA_COUNT];
            for c in 0..COA_COUNT {
                let base = ANCHOR_HEADER_BYTES + c * 16;
                totals[c] = (read_stmt_u64(&anc_raw, base), read_stmt_u64(&anc_raw, base + 8));
            }
            let mut aux = [0u64; 7];
            for k in 0..7 {
                aux[k] = read_stmt_u64(&anc_raw, 128 + k * 8);
            }
            let c_inv = u32_be(&anc_raw, 244) as usize;
            let c_ast = u32_be(&anc_raw, 248) as usize;
            let c_lse = u32_be(&anc_raw, 252) as usize;
            let c_def = u32_be(&anc_raw, 256) as usize;
            let c_ar = u32_be(&anc_raw, 260) as usize;
            let mut pos = ANCHOR_HEADER_BYTES + COA_COUNT * 16 + c_inv * 56;
            let mut assets = BTreeMap::new();
            for _ in 0..c_ast {
                let id = read_stmt_u64(&anc_raw, pos);
                assets.insert(
                    id,
                    CapitalAssetRow {
                        asset_class: anc_raw[pos + 8],
                        disposed: anc_raw[pos + 9] != 0,
                        cost: read_stmt_u64(&anc_raw, pos + 16),
                        residual: read_stmt_u64(&anc_raw, pos + 24),
                        useful_life_blocks: read_stmt_u64(&anc_raw, pos + 32),
                        acquired_block: read_stmt_u64(&anc_raw, pos + 40),
                        posted_depr: read_stmt_u64(&anc_raw, pos + 48),
                    },
                );
                pos += 64;
            }
            let mut leases = BTreeMap::new();
            for _ in 0..c_lse {
                let id = read_stmt_u64(&anc_raw, pos);
                let mut lessor = [0u8; 20];
                lessor.copy_from_slice(&anc_raw[pos + 8..pos + 28]);
                leases.insert(
                    id,
                    LeaseRow {
                        lessor,
                        status: anc_raw[pos + 28],
                        initial_pv: read_stmt_u64(&anc_raw, pos + 32),
                        rem_liability: read_stmt_u64(&anc_raw, pos + 40),
                        periodic_payment: read_stmt_u64(&anc_raw, pos + 48),
                        rate_bps: read_stmt_u64(&anc_raw, pos + 56),
                        total_periods: u32_be(&anc_raw, pos + 64),
                        paid_periods: u32_be(&anc_raw, pos + 68),
                        period_blocks: read_stmt_u64(&anc_raw, pos + 72),
                        start_block: read_stmt_u64(&anc_raw, pos + 80),
                        posted_amort: read_stmt_u64(&anc_raw, pos + 88),
                    },
                );
                pos += 96;
            }
            pos += c_def * 80 + c_ar * 72;
            let _ = pos;
            ClientStreamState {
                period: read_stmt_u64(&anc_raw, 0),
                journal_cnt: read_stmt_u64(&anc_raw, 32),
                cfo_net: read_stmt_i64(&anc_raw, 56),
                cfi_net: read_stmt_i64(&anc_raw, 64),
                cff_net: read_stmt_i64(&anc_raw, 72),
                aux,
                totals,
                assets,
                leases,
                defs: BTreeMap::new(),
                invoices: BTreeMap::new(),
            }
        };

        let ingest_events_and_assert_parity = |st: &mut ClientStreamState, cursor: &mut usize, blk: u64| {
            let all_evs = mock::events();
            for ev in &all_evs[*cursor..] {
                if ev.address != ACC || ev.topics.is_empty() {
                    continue;
                }
                let t0 = ev.topics[0];
                if t0 == EV_JOURNAL_POSTED {
                    let entry_id = read_stmt_u64(&ev.topics[1], 24);
                    assert_eq!(entry_id, st.journal_cnt + 1);
                    st.journal_cnt = entry_id;
                    let meta = ev.topics[3];
                    let cf_cls = meta[2];
                    let line_cnt = meta[3] as usize;
                    let cash_delta = read_stmt_i64(&meta, 24);
                    match cf_cls {
                        1 => st.cfo_net += cash_delta,
                        2 => st.cfi_net += cash_delta,
                        3 => st.cff_net += cash_delta,
                        _ => {}
                    }
                    for l in 0..line_cnt {
                        let b = l * 10;
                        let acc = ev.data[b] as usize;
                        let side = ev.data[b + 1];
                        let amt = read_stmt_u64(&ev.data, b + 2);
                        if side == 0 {
                            st.totals[acc].0 += amt;
                        } else {
                            st.totals[acc].1 += amt;
                        }
                    }
                } else if t0 == EV_SUBLEDGER_UPDATED {
                    let kind = read_stmt_u64(&ev.topics[1], 24);
                    let d = &ev.data;
                    match kind {
                        SUBLEDGER_KIND_FIXED_ASSET => {
                            let id = read_stmt_u64(d, 0);
                            st.assets.insert(
                                id,
                                CapitalAssetRow {
                                    asset_class: d[8],
                                    disposed: d[9] != 0,
                                    cost: read_stmt_u64(d, 16),
                                    residual: read_stmt_u64(d, 24),
                                    useful_life_blocks: read_stmt_u64(d, 32),
                                    acquired_block: read_stmt_u64(d, 40),
                                    posted_depr: read_stmt_u64(d, 48),
                                },
                            );
                        }
                        SUBLEDGER_KIND_LEASE => {
                            let id = read_stmt_u64(d, 0);
                            let mut lessor = [0u8; 20];
                            lessor.copy_from_slice(&d[8..28]);
                            st.leases.insert(
                                id,
                                LeaseRow {
                                    lessor,
                                    status: d[28],
                                    initial_pv: read_stmt_u64(d, 32),
                                    rem_liability: read_stmt_u64(d, 40),
                                    periodic_payment: read_stmt_u64(d, 48),
                                    rate_bps: read_stmt_u64(d, 56),
                                    total_periods: u32_be(d, 64),
                                    paid_periods: u32_be(d, 68),
                                    period_blocks: read_stmt_u64(d, 72),
                                    start_block: read_stmt_u64(d, 80),
                                    posted_amort: read_stmt_u64(d, 88),
                                },
                            );
                        }
                        SUBLEDGER_KIND_DEFERRED_REV => {
                            let id = read_stmt_u64(d, 0);
                            let mut customer = [0u8; 20];
                            customer.copy_from_slice(&d[8..28]);
                            let mut plan_tag = [0u8; 8];
                            plan_tag.copy_from_slice(&d[72..80]);
                            st.defs.insert(
                                id,
                                DeferredContractRow {
                                    customer,
                                    is_related: d[28] != 0,
                                    plan_tag,
                                    total_amount: read_stmt_u64(d, 32),
                                    posted_earned: read_stmt_u64(d, 40),
                                    start_block: read_stmt_u64(d, 56),
                                    duration_blocks: read_stmt_u64(d, 64),
                                },
                            );
                        }
                        SUBLEDGER_KIND_CREDIT_INVOICE => {
                            let id = read_stmt_u64(d, 0);
                            let mut buyer = [0u8; 20];
                            buyer.copy_from_slice(&d[8..28]);
                            st.invoices.insert(
                                id,
                                CreditInvoiceRow {
                                    buyer,
                                    product_id: [0u8; 32],
                                    quantity: 0,
                                    status: d[28],
                                    original_amount: read_stmt_u64(d, 32),
                                    open_amount: read_stmt_u64(d, 40),
                                    issued_block: read_stmt_u64(d, 56),
                                    due_block: read_stmt_u64(d, 64),
                                },
                            );
                        }
                        SUBLEDGER_KIND_AUX_COUNTERS => {
                            for k in 0..7 {
                                st.aux[k] = read_stmt_u64(d, k * 8);
                            }
                        }
                        _ => {}
                    }
                } else if t0 == EV_PERIOD_CLOSED {
                    let _ = ifrs::roll_nominal_accounts_into_retained_earnings(&mut st.totals).unwrap();
                    st.period += 1;
                }
            }
            *cursor = all_evs.len();

            // Compute client-side projection from streamed schedules + live bank balance
            let mut proj = AccrualProjection::default();
            for a in st.assets.values() {
                if !a.disposed {
                    let cum = ifrs::compute_linear_depreciation(a.cost, a.residual, a.useful_life_blocks, a.acquired_block, blk);
                    let delta = cum.saturating_sub(a.posted_depr);
                    if a.asset_class == ifrs::ASSET_CLASS_FINITE_INTANGIBLE {
                        proj.unposted_intang_amort += delta;
                    } else {
                        proj.unposted_ppe_depr += delta;
                    }
                }
            }
            for ls in st.leases.values() {
                if ls.status == 2 {
                    let cum = ifrs::compute_linear_depreciation(
                        ls.initial_pv,
                        0,
                        (ls.total_periods as u64) * ls.period_blocks,
                        ls.start_block,
                        blk,
                    );
                    proj.unposted_rou_amort += cum.saturating_sub(ls.posted_amort);
                }
            }
            for dc in st.defs.values() {
                let cum = ifrs::compute_linear_deferred_earned(dc.total_amount, dc.start_block, dc.duration_blocks, blk);
                let delta = cum.saturating_sub(dc.posted_earned);
                if dc.is_related {
                    proj.unposted_deferred_rev_related += delta;
                } else {
                    proj.unposted_deferred_rev_arms += delta;
                }
            }
            for inv in st.invoices.values() {
                if inv.status == 2 && inv.open_amount > 0 {
                    proj.target_ecl_allowance += ifrs::compute_invoice_ecl_amount(inv.open_amount, inv.due_block, blk);
                }
            }
            let actual_bank = BANK_BALS.with(|b| *b.borrow().get(&TREAS).unwrap_or(&0));
            let booked = st.totals[ACC_CASH as usize].0.saturating_sub(st.totals[ACC_CASH as usize].1);
            if actual_bank > booked {
                proj.unattributed_bank_inflow = actual_bank - booked;
            }
            let compiled = ifrs::compile_statements(&st.totals, &proj);

            // Compare against live on-chain `getFinancialStatements()`!
            let stmt_cd = CallEncoder::<16>::new(const { selector("getFinancialStatements()") });
            let (rc, on_chain) = call_at(ACC, CUSTOMER, blk, stmt_cd.as_slice());
            assert_eq!(rc, 0);
            assert_eq!(st.period, read_stmt_u64(&on_chain, 0));
            assert_eq!(st.journal_cnt, read_stmt_u64(&on_chain, 32));
            assert_eq!(st.cfo_net, read_stmt_i64(&on_chain, 80));
            assert_eq!(st.cfi_net, read_stmt_i64(&on_chain, 88));
            assert_eq!(st.cff_net, read_stmt_i64(&on_chain, 96));
            assert_eq!(compiled.total_assets as i64, read_stmt_i64(&on_chain, 200));
            assert_eq!(compiled.total_liabilities as i64, read_stmt_i64(&on_chain, 224));
            assert_eq!(compiled.total_equity as i64, read_stmt_i64(&on_chain, 232));
            assert_eq!(compiled.net_revenue as i64, read_stmt_i64(&on_chain, 256));
            assert_eq!(compiled.net_income as i64, read_stmt_i64(&on_chain, 280));
            for c in 0..COA_COUNT {
                assert_eq!(
                    compiled.normal_balances[c] as i64,
                    read_stmt_i64(&on_chain, 296 + c * 8),
                    "CoA slot {c} mismatch at block {blk}"
                );
            }
        };
        // EXPLOIT CHECK 4: IAS 24 Related-Party Credit Sale rejected; Related-Party Cash Sale segregated into 4050!
        let rp_inv_cd = CallEncoder::<224>::new(const {
            selector("issueCreditInvoice(address,bytes32,uint64,uint64,uint64,address)")
        })
        .push_address(&FOUNDER_DIR)
        .push_bytes32(&sku_1)
        .push_u64(1)
        .push_u64(2_500)
        .push_u64(100)
        .push_address(&[0u8; 20]);
        let (rc_rp_cr, _) = call_at(ACC, FOUNDER_DIR, 116, rp_inv_cd.as_slice());
        assert_eq!(rc_rp_cr, ERR_IFRS_RELATED_PARTY_CREDIT_BANNED);

        BANK_BALS.with(|b| *b.borrow_mut().get_mut(&TREAS).unwrap() += 2_500);
        let rp_cash_cd = CallEncoder::<192>::new(const {
            selector("bookCashSale(bytes32,address,uint64,uint64,uint64)")
        })
        .push_bytes32(&sku_1)
        .push_address(&FOUNDER_DIR)
        .push_u64(1)
        .push_u64(2_500)
        .push_u64(2_500);
        let (rc_rp_cash, _) = call_at(ACC, PROD_MOD, 116, rp_cash_cd.as_slice());
        assert_eq!(rc_rp_cash, 0);
        ingest_events_and_assert_parity(&mut client, &mut ev_cursor, 116);

        // 5. Bilateral IFRS 16 Lease: Propose -> non-lessor accept rejected -> lessor accept capitalizes ROU PV!
        let prop_lse_cd = CallEncoder::<224>::new(const {
            selector("proposeLease(address,uint64,uint64,uint64,uint64,address)")
        })
        .push_address(&LESSOR)
        .push_u64(5_000)
        .push_u64(4)
        .push_u64(100)
        .push_u64(200)
        .push_address(&[0u8; 20]);
        let (rc_pl, _) = call_at(ACC, FOUNDER_DIR, 120, prop_lse_cd.as_slice());
        assert_eq!(rc_pl, 0);

        let acc_lse_cd = CallEncoder::<64>::new(const { selector("acceptAndCommenceLease(uint64)") })
            .push_u64(0);
        let (rc_fake_lessor, _) = call_at(ACC, FOUNDER_DIR, 120, acc_lse_cd.as_slice());
        assert_eq!(rc_fake_lessor, ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
        let (rc_real_lessor, _) = call_at(ACC, LESSOR, 120, acc_lse_cd.as_slice());
        assert_eq!(rc_real_lessor, 0);
        ingest_events_and_assert_parity(&mut client, &mut ev_cursor, 120);

        // 6. Unsolicited `7,777` SGD transfer into `treasuryIdentity` + 60 blocks elapsed -> verify live statement projection!
        BANK_BALS.with(|b| *b.borrow_mut().get_mut(&TREAS).unwrap() += 7_777);
        ingest_events_and_assert_parity(&mut client, &mut ev_cursor, 170);
        let stmt_cd = CallEncoder::<16>::new(const { selector("getFinancialStatements()") });
        let (rc_st, stmt_raw) = call_at(ACC, CUSTOMER, 170, stmt_cd.as_slice());
        assert_eq!(rc_st, 0);
        assert_eq!(stmt_raw.len(), STATEMENTS_FRAME_BYTES);
        let flags = read_stmt_u64(&stmt_raw, 72);
        assert_eq!(flags & 0b1111, 0b1111); // balanced + custody_clean + virgin + hfs_registry!
        assert_eq!(read_stmt_u64(&stmt_raw, 56), 7_777); // quarantined in 2900 Suspense, NOT revenue!
        assert_eq!(read_stmt_i64(&stmt_raw, 184 + 7 * 8), 25_000); // Arm's-Length Revenue = 25,000
        assert_eq!(read_stmt_i64(&stmt_raw, 184 + 8 * 8), 2_500); // Related-Party Revenue = 2,500
        assert!(read_stmt_u64(&stmt_raw, 152) >= 6_000); // Live unposted depreciation projected!

        // EXPLOIT CHECK 5: Illegal dividend exceeding realized profit rejected!
        let bad_div_cd = CallEncoder::<128>::new(const {
            selector("payDividend(address,uint64,address)")
        })
        .push_address(&FOUNDER_DIR)
        .push_u64(50_000)
        .push_address(&[0u8; 20]);
        let (rc_bad_div, _) = call_at(ACC, FOUNDER_DIR, 170, bad_div_cd.as_slice());
        assert_eq!(rc_bad_div, ERR_IFRS_INSUFFICIENT_REALIZED_PROFIT);

        // Legal dividend within realized profit succeeds and disburses cash!
        let ok_div_cd = CallEncoder::<128>::new(const {
            selector("payDividend(address,uint64,address)")
        })
        .push_address(&FOUNDER_DIR)
        .push_u64(5_000)
        .push_address(&[0u8; 20]);
        let (rc_ok_div, _) = call_at(ACC, FOUNDER_DIR, 170, ok_div_cd.as_slice());
        assert_eq!(rc_ok_div, 0);
        ingest_events_and_assert_parity(&mut client, &mut ev_cursor, 170);

        // Close Fiscal Period #1 -> Period #2
        let close_cd = CallEncoder::<64>::new(const { selector("closeFiscalPeriod(address)") })
            .push_address(&[0u8; 20]);
        let (rc_close, close_ret) = call_at(ACC, FOUNDER_DIR, 180, close_cd.as_slice());
        assert_eq!(rc_close, 0);
        assert_eq!(u64::from_be_bytes(close_ret[24..32].try_into().unwrap()), 2);
        ingest_events_and_assert_parity(&mut client, &mut ev_cursor, 180);
    }
}
