//! Codified `#![no_std]` IAS / IFRS Accounting Standards Engine & Cross-HPS Callers (`hps_sdk::ifrs`).
//!
//! Designed specifically for SuperLexicon's `code_hash`-deduplicated `WasmtimeAdapter`:
//! - Compiled directly into `accounting_ledger.wasm` (uploaded once per subnet via `BYTECODE_STORE`
//!   and instantiated in 32 bytes per company with zero bytecode duplication and zero runtime
//!   cross-contract subcall overhead for rule derivation).
//! - Enforces **Zero Creative Accounting** at the Rust type-system level:
//!   - [`BalancedBatch`] has a **private** constructor (`BalancedBatch::build`), so external crates
//!     cannot construct arbitrary or unbalanced `(Debit, Credit)` postings.
//!   - Every `BalancedBatch` is produced exclusively by a codified IAS/IFRS standard function that
//!     validates statutory floors, ceilings, valuation models, and double-entry conservation
//!     ($\sum \text{Dr} \equiv \sum \text{Cr}$).

use crate::call::{self, CallEncoder};
use crate::selector;

/// Number of canonical accounts in the codified IFRS Chart of Accounts (`0..31`).
pub const COA_COUNT: usize = 32;
/// Maximum lines in a single atomic IFRS journal posting (`<= 8`).
pub const MAX_BATCH_LINES: usize = 8;

// ============================================================================
// Canonical 32-Slot Chart of Accounts (`0..31`)
// ============================================================================

// Assets (`0..=10`)
pub const ACC_CASH: u8 = 0; // 1010 Cash & Bank Equivalents (IAS 7)
pub const ACC_TRADE_RECEIVABLES: u8 = 1; // 1100 Trade Receivables (IFRS 15 / IFRS 9)
pub const ACC_ALLOWANCE_ECL: u8 = 2; // 1190 Allowance for Expected Credit Losses [Contra] (IFRS 9)
pub const ACC_INVENTORY: u8 = 3; // 1200 Merchandise Inventory — Moving WAC (IAS 2)
pub const ACC_FUTURE_CONTRACT_RECEIVABLES: u8 = 4; // 1800 Future Contract Receivables — Unbilled Backlog (IFRS 15)
pub const ACC_PREPAID_EXPENSES: u8 = ACC_FUTURE_CONTRACT_RECEIVABLES; // Legacy slot alias
pub const ACC_PPE_COST: u8 = 5; // 1500 Property, Plant & Equipment at Cost (IAS 16)
pub const ACC_ACCUM_DEPR_PPE: u8 = 6; // 1590 Accumulated Depreciation — PPE [Contra] (IAS 16)
pub const ACC_ROU_ASSETS: u8 = 7; // 1600 Right-of-Use Lease Assets at PV (IFRS 16)
pub const ACC_ACCUM_AMORT_ROU: u8 = 8; // 1690 Accumulated Amortization — ROU [Contra] (IFRS 16)
pub const ACC_INTANGIBLES_COST: u8 = 9; // 1700 Finite Intangible Assets at Cost (IAS 38)
pub const ACC_ACCUM_AMORT_INTANG: u8 = 10; // 1790 Accumulated Amortization — Intangibles [Contra] (IAS 38)

// Liabilities (`11..=18`)
pub const ACC_TRADE_PAYABLES: u8 = 11; // 2010 Trade Payables (IAS 1 / IFRS 9)
pub const ACC_ACCRUED_PAYROLL: u8 = 12; // 2100 Accrued Employee Benefits & Payroll (IAS 19)
pub const ACC_TAX_PAYABLE: u8 = 13; // 2200 Current Income Tax Payable (IAS 12)
pub const ACC_CONTRACT_LIABILITIES: u8 = 14; // 2300 Contract Liabilities / Deferred Revenue (IFRS 15)
pub const ACC_DIVIDENDS_PAYABLE: u8 = 15; // 2400 Dividends Payable (IAS 32)
pub const ACC_LEASE_LIABILITIES: u8 = 16; // 2500 Lease Liabilities at Present Value (IFRS 16)
pub const ACC_TERM_DEBT: u8 = 17; // 2600 Term Debt & Borrowings — Amortized Cost (IFRS 9)
pub const ACC_CASH_SUSPENSE: u8 = 18; // 2900 Unattributed Cash Deposit Suspense (IAS 7 Custody Quarantine)

// Equity (`19..=23`)
pub const ACC_SHARE_CAPITAL: u8 = 19; // 3000 Issued Share Capital — Par (IAS 32)
pub const ACC_SHARE_PREMIUM: u8 = 20; // 3010 Share Premium / Additional Paid-In Capital (IAS 32)
pub const ACC_TREASURY_SHARES: u8 = 21; // 3200 Treasury Shares at Cost [Contra-Equity] (IAS 32)
pub const ACC_SBC_RESERVE: u8 = 22; // 3300 Share-Based Payment Reserve (IFRS 2)
pub const ACC_RETAINED_EARNINGS: u8 = 23; // 3400 Retained Earnings / (Accumulated Deficit) (IAS 1)

// Nominal Income Statement Accounts (`24..=31`, rolled into `ACC_RETAINED_EARNINGS` at Period Close)
pub const ACC_REVENUE_ARMS_LENGTH: u8 = 24; // 4000 Operating Revenue — Arm's-Length (IFRS 15)
pub const ACC_REVENUE_RELATED_PARTY: u8 = 25; // 4050 Related-Party Revenue — Segregated (IAS 24)
pub const ACC_SALES_RETURNS: u8 = 26; // 4090 Sales Returns & Allowances [Contra-Revenue] (IFRS 15)
pub const ACC_COGS_AND_NRV: u8 = 27; // 5010 Cost of Goods Sold & Inventory NRV Write-Downs (IAS 2)
pub const ACC_EMPLOYEE_BENEFITS: u8 = 28; // 6100 Employee Benefits & Share-Based Comp (IAS 19 / IFRS 2)
pub const ACC_DEPR_AND_AMORT: u8 = 29; // 6300 Depreciation & Amortization Expense (IAS 16 / 38 / IFRS 16)
pub const ACC_OPERATING_AND_ECL: u8 = 30; // 6400 Operating Expenses (R&D, S&M, G&A) & Credit Loss ECL (IFRS 9)
pub const ACC_FINANCE_DISPOSAL_TAX: u8 = 31; // 7000 Net Finance Interest, Disposal Gain/Loss & Current Tax (IFRS 9 / 16 / IAS 12)

// ============================================================================
// Standard Tags & Statutory Guardrail Constants
// ============================================================================

pub const STD_IAS1_PRESENTATION: u8 = 1;
pub const STD_IAS2_INVENTORY: u8 = 2;
pub const STD_IAS7_CASH_SUSPENSE: u8 = 3;
pub const STD_IAS12_INCOME_TAX: u8 = 4;
pub const STD_IAS16_PPE: u8 = 5;
pub const STD_IAS19_EMPLOYEE: u8 = 6;
pub const STD_IAS24_RELATED_PARTY: u8 = 7;
pub const STD_IAS32_EQUITY: u8 = 8;
pub const STD_IAS38_INTANGIBLES: u8 = 9;
pub const STD_IFRS2_SBC: u8 = 10;
pub const STD_IFRS9_INSTRUMENTS: u8 = 11;
pub const STD_IFRS15_REVENUE: u8 = 12;
pub const STD_IFRS16_LEASES: u8 = 13;

/// Asset class codes for `IAS 16` PPE & `IAS 38` Finite Intangibles.
pub const ASSET_CLASS_IT_HARDWARE: u8 = 1;
pub const ASSET_CLASS_MACHINERY: u8 = 2;
pub const ASSET_CLASS_FACILITY: u8 = 3;
pub const ASSET_CLASS_FINITE_INTANGIBLE: u8 = 4;

/// Operating expense functional categories (`IAS 1.103` Function of Expense).
pub const OPEX_RND: u8 = 1;
pub const OPEX_SALES_MARKETING: u8 = 2;
pub const OPEX_GENERAL_ADMIN: u8 = 3;

/// Statutory minimum cost floor for `IAS 16 / IAS 38` capitalization (blocks micro-OpEx capitalization).
pub const CAPEX_MIN_COST_UNITS: u64 = 1_000;
/// Statutory minimum block duration for `IFRS 15` over-time deferred contracts.
pub const MIN_DEFERRED_CONTRACT_BLOCKS: u64 = 20;
pub const MAX_DEFERRED_CONTRACT_BLOCKS: u64 = 500_000;
/// Statutory credit-sale payment term bounds (in blocks).
pub const MIN_CREDIT_SALE_DUE_BLOCKS: u64 = 10;
pub const MAX_CREDIT_SALE_DUE_BLOCKS: u64 = 100_000;
/// Statutory multi-period B2B / Defense service contract bounds (`IFRS 15` unbilled contract backlog).
pub const MIN_SERVICE_CONTRACT_MONTHS: u64 = 2;
pub const MAX_SERVICE_CONTRACT_MONTHS: u64 = 120;
pub const MIN_SERVICE_MONTH_BLOCKS: u64 = 10;
pub const MAX_SERVICE_MONTH_BLOCKS: u64 = 100_000;
/// Statutory `IFRS 16` lease bounds (prevents abusive discount-rate manipulation).
pub const MIN_LEASE_PERIODS: u64 = 2;
pub const MAX_LEASE_PERIODS: u64 = 120;
pub const MIN_LEASE_PERIOD_BLOCKS: u64 = 10;
pub const MIN_LEASE_RATE_BPS: u64 = 10; // 0.10% per period
pub const MAX_LEASE_RATE_BPS: u64 = 2_500; // 25.00% per period

// ============================================================================
// IFRS Policy Error Codes (`-120..-149`)
// ============================================================================

pub const ERR_IFRS_ZERO_OR_OVERFLOW: i32 = -120;
pub const ERR_IFRS_UNBALANCED_BATCH: i32 = -121;
pub const ERR_IFRS_BELOW_CAPEX_FLOOR: i32 = -122;
pub const ERR_IFRS_INVALID_ASSET_CLASS: i32 = -123;
pub const ERR_IFRS_USEFUL_LIFE_OUT_OF_BOUNDS: i32 = -124;
pub const ERR_IFRS_RESIDUAL_VALUE_EXCEEDED: i32 = -125;
pub const ERR_IFRS_UPWARD_REVALUATION_BANNED: i32 = -126;
pub const ERR_IFRS_RELATED_PARTY_CREDIT_BANNED: i32 = -127;
pub const ERR_IFRS_INVALID_CONTRACT_DURATION: i32 = -128;
pub const ERR_IFRS_INVALID_LEASE_TERMS: i32 = -129;
pub const ERR_IFRS_INSUFFICIENT_REALIZED_PROFIT: i32 = -130;
pub const ERR_IFRS_PAR_EXCEEDS_PROCEEDS: i32 = -131;
pub const ERR_IFRS_INVALID_DEBT_PAYMENT: i32 = -132;
pub const ERR_IFRS_INVALID_OPEX_CATEGORY: i32 = -133;
pub const ERR_IFRS_BANK_CASH_SHORTFALL: i32 = -134;
pub const ERR_IFRS_CUSTODY_OWNER_MISMATCH: i32 = -135;
pub const ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED: i32 = -136;
pub const ERR_IFRS_NOTHING_TO_POST: i32 = -137;
pub const ERR_IFRS_SUBLEDGER_NOT_FOUND: i32 = -138;
pub const ERR_IFRS_SUBLEDGER_FULL: i32 = -139;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Side {
    Debit = 0,
    Credit = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashFlowClass {
    None = 0,
    Operating = 1,
    Investing = 2,
    Financing = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub index: u8,
    pub code: u16,
    pub normal_side: Side,
    pub is_nominal: bool,
    pub name: &'static str,
}

pub const CHART_OF_ACCOUNTS: [AccountMeta; COA_COUNT] = [
    AccountMeta { index: 0, code: 1010, normal_side: Side::Debit, is_nominal: false, name: "Cash & Bank Equivalents" },
    AccountMeta { index: 1, code: 1100, normal_side: Side::Debit, is_nominal: false, name: "Trade Receivables" },
    AccountMeta { index: 2, code: 1190, normal_side: Side::Credit, is_nominal: false, name: "Allowance for ECL (Contra)" },
    AccountMeta { index: 3, code: 1200, normal_side: Side::Debit, is_nominal: false, name: "Merchandise Inventory (WAC)" },
    AccountMeta { index: 4, code: 1800, normal_side: Side::Debit, is_nominal: false, name: "Future Contract Receivables (IFRS 15)" },
    AccountMeta { index: 5, code: 1500, normal_side: Side::Debit, is_nominal: false, name: "Property, Plant & Equipment" },
    AccountMeta { index: 6, code: 1590, normal_side: Side::Credit, is_nominal: false, name: "Accum. Depreciation — PPE" },
    AccountMeta { index: 7, code: 1600, normal_side: Side::Debit, is_nominal: false, name: "Right-of-Use Lease Assets" },
    AccountMeta { index: 8, code: 1690, normal_side: Side::Credit, is_nominal: false, name: "Accum. Amortization — ROU" },
    AccountMeta { index: 9, code: 1700, normal_side: Side::Debit, is_nominal: false, name: "Finite Intangible Assets" },
    AccountMeta { index: 10, code: 1790, normal_side: Side::Credit, is_nominal: false, name: "Accum. Amortization — Intang." },
    AccountMeta { index: 11, code: 2010, normal_side: Side::Credit, is_nominal: false, name: "Trade Payables" },
    AccountMeta { index: 12, code: 2100, normal_side: Side::Credit, is_nominal: false, name: "Accrued Employee Benefits" },
    AccountMeta { index: 13, code: 2200, normal_side: Side::Credit, is_nominal: false, name: "Current Tax Payable" },
    AccountMeta { index: 14, code: 2300, normal_side: Side::Credit, is_nominal: false, name: "Contract Liabilities (Deferred)" },
    AccountMeta { index: 15, code: 2400, normal_side: Side::Credit, is_nominal: false, name: "Dividends Payable" },
    AccountMeta { index: 16, code: 2500, normal_side: Side::Credit, is_nominal: false, name: "Lease Liabilities (PV)" },
    AccountMeta { index: 17, code: 2600, normal_side: Side::Credit, is_nominal: false, name: "Term Debt (Amortized Cost)" },
    AccountMeta { index: 18, code: 2900, normal_side: Side::Credit, is_nominal: false, name: "Unattributed Cash Suspense" },
    AccountMeta { index: 19, code: 3000, normal_side: Side::Credit, is_nominal: false, name: "Issued Share Capital (Par)" },
    AccountMeta { index: 20, code: 3010, normal_side: Side::Credit, is_nominal: false, name: "Share Premium (APIC)" },
    AccountMeta { index: 21, code: 3200, normal_side: Side::Debit, is_nominal: false, name: "Treasury Shares (Contra)" },
    AccountMeta { index: 22, code: 3300, normal_side: Side::Credit, is_nominal: false, name: "Share-Based Payment Reserve" },
    AccountMeta { index: 23, code: 3400, normal_side: Side::Credit, is_nominal: false, name: "Retained Earnings" },
    AccountMeta { index: 24, code: 4000, normal_side: Side::Credit, is_nominal: true, name: "Operating Revenue (Arm's-Length)" },
    AccountMeta { index: 25, code: 4050, normal_side: Side::Credit, is_nominal: true, name: "Related-Party Revenue (IAS 24)" },
    AccountMeta { index: 26, code: 4090, normal_side: Side::Debit, is_nominal: true, name: "Sales Returns & Allowances" },
    AccountMeta { index: 27, code: 5010, normal_side: Side::Debit, is_nominal: true, name: "Cost of Goods Sold & NRV" },
    AccountMeta { index: 28, code: 6100, normal_side: Side::Debit, is_nominal: true, name: "Employee Benefits & SBC" },
    AccountMeta { index: 29, code: 6300, normal_side: Side::Debit, is_nominal: true, name: "Depreciation & Amortization" },
    AccountMeta { index: 30, code: 6400, normal_side: Side::Debit, is_nominal: true, name: "Operating Expenses & ECL" },
    AccountMeta { index: 31, code: 7000, normal_side: Side::Debit, is_nominal: true, name: "Net Finance, Disposal & Tax" },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalLine {
    pub account: u8,
    pub side: Side,
    pub amount: u64,
}

impl JournalLine {
    pub const fn dr(account: u8, amount: u64) -> Self {
        Self {
            account,
            side: Side::Debit,
            amount,
        }
    }

    pub const fn cr(account: u8, amount: u64) -> Self {
        Self {
            account,
            side: Side::Credit,
            amount,
        }
    }
}

/// Verified double-entry IFRS journal batch whose constructor is **private** to `hps_sdk::ifrs`.
/// Every `BalancedBatch` is guaranteed to satisfy $\sum \text{Dr} \equiv \sum \text{Cr} > 0$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalancedBatch {
    lines: [JournalLine; MAX_BATCH_LINES],
    line_count: u8,
    standard_tag: u8,
    cash_flow_class: CashFlowClass,
    cash_delta: i64,
    total_debit: u64,
}

impl BalancedBatch {
    #[inline(never)]
    fn build(
        raw_lines: &[JournalLine],
        standard_tag: u8,
        cash_flow_class: CashFlowClass,
    ) -> Result<Self, i32> {
        let mut lines = [JournalLine::dr(0, 0); MAX_BATCH_LINES];
        let mut count = 0usize;
        let mut dr_sum: u128 = 0;
        let mut cr_sum: u128 = 0;
        let mut cash_delta: i128 = 0;

        let mut i = 0;
        while i < raw_lines.len() {
            let ln = raw_lines[i];
            if ln.amount > 0 {
                if (ln.account as usize) >= COA_COUNT || count >= MAX_BATCH_LINES {
                    return Err(ERR_IFRS_UNBALANCED_BATCH);
                }
                lines[count] = ln;
                count += 1;
                match ln.side {
                    Side::Debit => {
                        dr_sum += ln.amount as u128;
                        if ln.account == ACC_CASH {
                            cash_delta += ln.amount as i128;
                        }
                    }
                    Side::Credit => {
                        cr_sum += ln.amount as u128;
                        if ln.account == ACC_CASH {
                            cash_delta -= ln.amount as i128;
                        }
                    }
                }
            }
            i += 1;
        }

        if count < 2 || dr_sum == 0 || dr_sum != cr_sum || dr_sum > (u64::MAX as u128) {
            return Err(ERR_IFRS_UNBALANCED_BATCH);
        }
        if cash_delta < (i64::MIN as i128) || cash_delta > (i64::MAX as i128) {
            return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
        }

        let cf_class = if cash_delta == 0 {
            CashFlowClass::None
        } else {
            cash_flow_class
        };

        Ok(Self {
            lines,
            line_count: count as u8,
            standard_tag,
            cash_flow_class: cf_class,
            cash_delta: cash_delta as i64,
            total_debit: dr_sum as u64,
        })
    }

    pub fn lines(&self) -> &[JournalLine] {
        &self.lines[..self.line_count as usize]
    }

    pub const fn standard_tag(&self) -> u8 {
        self.standard_tag
    }

    pub const fn cash_flow_class(&self) -> CashFlowClass {
        self.cash_flow_class
    }

    pub const fn cash_delta(&self) -> i64 {
        self.cash_delta
    }

    pub const fn total_debit(&self) -> u64 {
        self.total_debit
    }
}

// ============================================================================
// IFRS 15 (Revenue from Contracts with Customers) + IAS 2 (WAC Inventory) + IAS 24
// ============================================================================

/// Compute Moving Weighted-Average Cost (`WAC`) COGS for `qty_sold` units against
/// `(units_on_hand, carrying_cost)` (`IAS 2.27`).
pub fn compute_wac_cogs(units_on_hand: u64, carrying_cost: u64, qty_sold: u64) -> (u64, u64, u64) {
    if units_on_hand == 0 || carrying_cost == 0 || qty_sold == 0 {
        return (0, units_on_hand, carrying_cost);
    }
    let matched_units = qty_sold.min(units_on_hand);
    let cogs = if matched_units == units_on_hand {
        carrying_cost
    } else {
        (((carrying_cost as u128) * (matched_units as u128)) / (units_on_hand as u128)) as u64
    };
    (
        cogs,
        units_on_hand - matched_units,
        carrying_cost.saturating_sub(cogs),
    )
}

/// Point-in-time cash sale (`IFRS 15.38` + `IAS 2` WAC COGS + `IAS 24` related-party segregation).
pub fn derive_cash_sale(
    revenue_amount: u64,
    cogs_amount: u64,
    is_related_party: bool,
) -> Result<BalancedBatch, i32> {
    if revenue_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let rev_acc = if is_related_party {
        ACC_REVENUE_RELATED_PARTY
    } else {
        ACC_REVENUE_ARMS_LENGTH
    };
    let std_tag = if is_related_party {
        STD_IAS24_RELATED_PARTY
    } else {
        STD_IFRS15_REVENUE
    };
    let raw = [
        JournalLine::dr(ACC_CASH, revenue_amount),
        JournalLine::cr(rev_acc, revenue_amount),
        JournalLine::dr(ACC_COGS_AND_NRV, cogs_amount),
        JournalLine::cr(ACC_INVENTORY, cogs_amount),
    ];
    BalancedBatch::build(&raw, std_tag, CashFlowClass::Operating)
}

/// Point-in-time credit sale (`IFRS 15` + `IFRS 9` Receivable).
/// **Bans** credit sales to related parties (`IAS 24` anti-channel-stuffing guard).
pub fn derive_credit_sale(
    revenue_amount: u64,
    cogs_amount: u64,
    due_blocks: u64,
    is_related_party: bool,
) -> Result<BalancedBatch, i32> {
    if revenue_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    if is_related_party {
        return Err(ERR_IFRS_RELATED_PARTY_CREDIT_BANNED);
    }
    if due_blocks < MIN_CREDIT_SALE_DUE_BLOCKS || due_blocks > MAX_CREDIT_SALE_DUE_BLOCKS {
        return Err(ERR_IFRS_INVALID_CONTRACT_DURATION);
    }
    let raw = [
        JournalLine::dr(ACC_TRADE_RECEIVABLES, revenue_amount),
        JournalLine::cr(ACC_REVENUE_ARMS_LENGTH, revenue_amount),
        JournalLine::dr(ACC_COGS_AND_NRV, cogs_amount),
        JournalLine::cr(ACC_INVENTORY, cogs_amount),
    ];
    BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::None)
}

/// Collection of customer Trade Receivable in cash (`IAS 7` Operating Cash Flow).
pub fn derive_receivable_collection(cash_amount: u64) -> Result<BalancedBatch, i32> {
    if cash_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_CASH, cash_amount),
        JournalLine::cr(ACC_TRADE_RECEIVABLES, cash_amount),
    ];
    BalancedBatch::build(&raw, STD_IFRS9_INSTRUMENTS, CashFlowClass::Operating)
}

/// Customer return & refund (`IFRS 15.55` contra-revenue `4090` + `IAS 2` inventory recovery).
pub fn derive_sales_return(
    refund_amount: u64,
    restocked_cogs: u64,
    is_cash_refund: bool,
) -> Result<BalancedBatch, i32> {
    if refund_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let cr_acc = if is_cash_refund {
        ACC_CASH
    } else {
        ACC_TRADE_RECEIVABLES
    };
    let raw = [
        JournalLine::dr(ACC_SALES_RETURNS, refund_amount),
        JournalLine::cr(cr_acc, refund_amount),
        JournalLine::dr(ACC_INVENTORY, restocked_cogs),
        JournalLine::cr(ACC_COGS_AND_NRV, restocked_cogs),
    ];
    BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::Operating)
}

/// Upfront receipt for an over-time subscription/service contract (`IFRS 15.35` + `IFRS 15.106`).
/// **Bans** immediate revenue recognition — credits `2300 Contract Liabilities` (Deferred Revenue).
pub fn derive_deferred_contract_receipt(
    cash_amount: u64,
    duration_blocks: u64,
) -> Result<BalancedBatch, i32> {
    if cash_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    if duration_blocks < MIN_DEFERRED_CONTRACT_BLOCKS
        || duration_blocks > MAX_DEFERRED_CONTRACT_BLOCKS
    {
        return Err(ERR_IFRS_INVALID_CONTRACT_DURATION);
    }
    let raw = [
        JournalLine::dr(ACC_CASH, cash_amount),
        JournalLine::cr(ACC_CONTRACT_LIABILITIES, cash_amount),
    ];
    BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::Operating)
}

/// Compute cumulative earned revenue for an over-time `IFRS 15` contract at `current_block`.
pub fn compute_linear_deferred_earned(
    total_amount: u64,
    start_block: u64,
    duration_blocks: u64,
    current_block: u64,
) -> u64 {
    if duration_blocks == 0 || current_block <= start_block {
        return 0;
    }
    let elapsed = current_block.saturating_sub(start_block).min(duration_blocks);
    if elapsed == duration_blocks {
        total_amount
    } else {
        (((total_amount as u128) * (elapsed as u128)) / (duration_blocks as u128)) as u64
    }
}

/// Recognize newly earned portion of deferred contract liability (`Dr 2300 / Cr 4000|4050`).
pub fn derive_deferred_revenue_recognition(
    newly_earned: u64,
    is_related_party: bool,
) -> Result<BalancedBatch, i32> {
    if newly_earned == 0 {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let rev_acc = if is_related_party {
        ACC_REVENUE_RELATED_PARTY
    } else {
        ACC_REVENUE_ARMS_LENGTH
    };
    let raw = [
        JournalLine::dr(ACC_CONTRACT_LIABILITIES, newly_earned),
        JournalLine::cr(rev_acc, newly_earned),
    ];
    BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::None)
}

/// Stage 1 of a ratified multi-period B2B / Sovereign Defense Service Contract (`IFRS 15.105`–`108`):
/// Recognizes the bilaterally executed contract backlog as `1800 Future Contract Receivables` (Non-Current)
/// matched 1:1 against `2300 Contract Liabilities` (Unearned Performance Obligations), with **zero**
/// premature P&L revenue recognition! **Bans** related-party contract backlogs (`IAS 24`).
pub fn derive_service_contract_backlog(
    monthly_amount: u64,
    total_months: u64,
    month_blocks: u64,
    is_related_party: bool,
) -> Result<(BalancedBatch, u64), i32> {
    if monthly_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    if is_related_party {
        return Err(ERR_IFRS_RELATED_PARTY_CREDIT_BANNED);
    }
    if total_months < MIN_SERVICE_CONTRACT_MONTHS
        || total_months > MAX_SERVICE_CONTRACT_MONTHS
        || month_blocks < MIN_SERVICE_MONTH_BLOCKS
        || month_blocks > MAX_SERVICE_MONTH_BLOCKS
    {
        return Err(ERR_IFRS_INVALID_CONTRACT_DURATION);
    }
    let total_value = monthly_amount
        .checked_mul(total_months)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    let raw = [
        JournalLine::dr(ACC_FUTURE_CONTRACT_RECEIVABLES, total_value),
        JournalLine::cr(ACC_CONTRACT_LIABILITIES, total_value),
    ];
    let batch = BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::None)?;
    Ok((batch, total_value))
}

/// Stage 2 of a multi-period B2B / Defense Service Contract (`IFRS 15` + `IFRS 9`):
/// Upon completing a monthly milestone and issuing an invoice, reclassifies one monthly installment
/// from `1800 Future Contract Receivables` into `1100 Current Trade Receivables` while satisfying
/// `2300 Contract Liabilities` into `4000 Operating Revenue — Arm's-Length`.
pub fn derive_service_contract_billing(monthly_amount: u64) -> Result<BalancedBatch, i32> {
    if monthly_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_TRADE_RECEIVABLES, monthly_amount),
        JournalLine::cr(ACC_FUTURE_CONTRACT_RECEIVABLES, monthly_amount),
        JournalLine::dr(ACC_CONTRACT_LIABILITIES, monthly_amount),
        JournalLine::cr(ACC_REVENUE_ARMS_LENGTH, monthly_amount),
    ];
    BalancedBatch::build(&raw, STD_IFRS15_REVENUE, CashFlowClass::None)
}

/// Inventory procurement (`IAS 2` Moving WAC — `Dr 1200 Inventory / Cr 1010 Cash | 2010 AP`).
pub fn derive_inventory_purchase(
    units: u64,
    total_cost: u64,
    is_cash: bool,
) -> Result<BalancedBatch, i32> {
    if units == 0 || total_cost == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let cr_acc = if is_cash {
        ACC_CASH
    } else {
        ACC_TRADE_PAYABLES
    };
    let raw = [
        JournalLine::dr(ACC_INVENTORY, total_cost),
        JournalLine::cr(cr_acc, total_cost),
    ];
    BalancedBatch::build(&raw, STD_IAS2_INVENTORY, CashFlowClass::Operating)
}

/// One-way Net Realizable Value (`NRV`) inventory write-down (`IAS 2.9` Lower of Cost and NRV).
/// **Bans** upward revaluation above current carrying cost!
pub fn derive_inventory_nrv_writedown(
    carrying_cost: u64,
    new_nrv_total: u64,
) -> Result<(BalancedBatch, u64), i32> {
    if new_nrv_total >= carrying_cost {
        return Err(ERR_IFRS_UPWARD_REVALUATION_BANNED);
    }
    let write_down = carrying_cost - new_nrv_total;
    let raw = [
        JournalLine::dr(ACC_COGS_AND_NRV, write_down),
        JournalLine::cr(ACC_INVENTORY, write_down),
    ];
    let batch = BalancedBatch::build(&raw, STD_IAS2_INVENTORY, CashFlowClass::None)?;
    Ok((batch, write_down))
}

// ============================================================================
// IAS 16 (PPE — Cost Model) & IAS 38 (Finite Intangibles — Cost Model)
// ============================================================================

/// Statutory useful-life `[min_blocks, max_blocks]` and `max_residual_bps` per `AssetClass`.
pub fn statutory_asset_class_bounds(asset_class: u8) -> Result<(u64, u64, u64, u8, u8, u8), i32> {
    match asset_class {
        ASSET_CLASS_IT_HARDWARE => Ok((
            200,
            50_000,
            1_000, // <= 10% residual value
            ACC_PPE_COST,
            ACC_ACCUM_DEPR_PPE,
            STD_IAS16_PPE,
        )),
        ASSET_CLASS_MACHINERY => Ok((
            500,
            150_000,
            1_500, // <= 15% residual value
            ACC_PPE_COST,
            ACC_ACCUM_DEPR_PPE,
            STD_IAS16_PPE,
        )),
        ASSET_CLASS_FACILITY => Ok((
            2_000,
            500_000,
            2_500, // <= 25% residual value
            ACC_PPE_COST,
            ACC_ACCUM_DEPR_PPE,
            STD_IAS16_PPE,
        )),
        ASSET_CLASS_FINITE_INTANGIBLE => Ok((
            200,
            50_000,
            0, // IAS 38.100: zero residual value required
            ACC_INTANGIBLES_COST,
            ACC_ACCUM_AMORT_INTANG,
            STD_IAS38_INTANGIBLES,
        )),
        _ => Err(ERR_IFRS_INVALID_ASSET_CLASS),
    }
}

pub fn validate_capex_params(
    asset_class: u8,
    cost: u64,
    residual_value: u64,
    useful_life_blocks: u64,
) -> Result<(u8, u8, u8), i32> {
    if cost < CAPEX_MIN_COST_UNITS {
        return Err(ERR_IFRS_BELOW_CAPEX_FLOOR);
    }
    let (min_life, max_life, max_res_bps, cost_acc, accum_acc, std_tag) =
        statutory_asset_class_bounds(asset_class)?;
    if useful_life_blocks < min_life || useful_life_blocks > max_life {
        return Err(ERR_IFRS_USEFUL_LIFE_OUT_OF_BOUNDS);
    }
    let max_res = (((cost as u128) * (max_res_bps as u128)) / 10_000u128) as u64;
    if residual_value > max_res || residual_value >= cost {
        return Err(ERR_IFRS_RESIDUAL_VALUE_EXCEEDED);
    }
    Ok((cost_acc, accum_acc, std_tag))
}

/// Capitalize `IAS 16` PPE or `IAS 38` Finite Intangible at historical cost (`CFI` if cash).
pub fn derive_capex_acquisition(
    asset_class: u8,
    cost: u64,
    residual_value: u64,
    useful_life_blocks: u64,
    is_cash: bool,
) -> Result<BalancedBatch, i32> {
    let (cost_acc, _accum_acc, std_tag) =
        validate_capex_params(asset_class, cost, residual_value, useful_life_blocks)?;
    let cr_acc = if is_cash {
        ACC_CASH
    } else {
        ACC_TRADE_PAYABLES
    };
    let raw = [
        JournalLine::dr(cost_acc, cost),
        JournalLine::cr(cr_acc, cost),
    ];
    BalancedBatch::build(&raw, std_tag, CashFlowClass::Investing)
}

/// Compute cumulative straight-line depreciation / amortization at `current_block`.
pub fn compute_linear_depreciation(
    cost: u64,
    residual_value: u64,
    useful_life_blocks: u64,
    acquired_block: u64,
    current_block: u64,
) -> u64 {
    if useful_life_blocks == 0 || current_block <= acquired_block || cost <= residual_value {
        return 0;
    }
    let depreciable = cost - residual_value;
    let elapsed = current_block
        .saturating_sub(acquired_block)
        .min(useful_life_blocks);
    if elapsed == useful_life_blocks {
        depreciable
    } else {
        (((depreciable as u128) * (elapsed as u128)) / (useful_life_blocks as u128)) as u64
    }
}

/// Post newly accrued `IAS 16` PPE depreciation, `IFRS 16` ROU amortization, and `IAS 38` intangible amortization.
pub fn derive_depreciation_posting(
    ppe_depr: u64,
    rou_amort: u64,
    intang_amort: u64,
) -> Result<BalancedBatch, i32> {
    let total = ppe_depr
        .checked_add(rou_amort)
        .and_then(|v| v.checked_add(intang_amort))
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    if total == 0 {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let raw = [
        JournalLine::dr(ACC_DEPR_AND_AMORT, total),
        JournalLine::cr(ACC_ACCUM_DEPR_PPE, ppe_depr),
        JournalLine::cr(ACC_ACCUM_AMORT_ROU, rou_amort),
        JournalLine::cr(ACC_ACCUM_AMORT_INTANG, intang_amort),
    ];
    BalancedBatch::build(&raw, STD_IAS16_PPE, CashFlowClass::None)
}

/// Derecognize disposed `IAS 16 / IAS 38` asset and record disposal gain or loss (`CFI` proceeds).
pub fn derive_asset_disposal(
    asset_class: u8,
    original_cost: u64,
    accum_depr: u64,
    cash_proceeds: u64,
) -> Result<BalancedBatch, i32> {
    let (_min, _max, _res, cost_acc, accum_acc, std_tag) =
        statutory_asset_class_bounds(asset_class)?;
    if original_cost == 0 || accum_depr > original_cost {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let carrying = original_cost - accum_depr;
    let (gain, loss) = if cash_proceeds >= carrying {
        (cash_proceeds - carrying, 0)
    } else {
        (0, carrying - cash_proceeds)
    };
    let raw = [
        JournalLine::dr(ACC_CASH, cash_proceeds),
        JournalLine::dr(accum_acc, accum_depr),
        JournalLine::dr(ACC_FINANCE_DISPOSAL_TAX, loss),
        JournalLine::cr(cost_acc, original_cost),
        JournalLine::cr(ACC_FINANCE_DISPOSAL_TAX, gain),
    ];
    BalancedBatch::build(&raw, std_tag, CashFlowClass::Investing)
}

// ============================================================================
// IFRS 16 (Leases — Right-of-Use Asset & Present-Value Lease Liability)
// ============================================================================

/// Deterministic integer fixed-point Present Value of `term_periods` lease payments discounted at
/// `rate_bps_per_period` (`10_000 bps = 100%`).
pub fn compute_lease_present_value(
    periodic_payment: u64,
    term_periods: u64,
    rate_bps_per_period: u64,
) -> Result<u64, i32> {
    if periodic_payment == 0
        || term_periods < MIN_LEASE_PERIODS
        || term_periods > MAX_LEASE_PERIODS
        || rate_bps_per_period < MIN_LEASE_RATE_BPS
        || rate_bps_per_period > MAX_LEASE_RATE_BPS
    {
        return Err(ERR_IFRS_INVALID_LEASE_TERMS);
    }
    const SCALE: u128 = 1_000_000_000_000;
    let r_denom = 10_000u128 + (rate_bps_per_period as u128);
    let mut discount_factor = SCALE;
    let mut pv_scaled: u128 = 0;

    let mut t = 0u64;
    while t < term_periods {
        discount_factor = (discount_factor * 10_000u128) / r_denom;
        pv_scaled = pv_scaled
            .checked_add((periodic_payment as u128) * discount_factor)
            .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
        t += 1;
    }
    let pv = (pv_scaled / SCALE) as u64;
    if pv == 0 {
        return Err(ERR_IFRS_INVALID_LEASE_TERMS);
    }
    Ok(pv)
}

/// Capitalize `IFRS 16` Right-of-Use Asset and Lease Liability at commencement (`Dr 1600 / Cr 2500`).
pub fn derive_lease_commencement(
    periodic_payment: u64,
    term_periods: u64,
    period_blocks: u64,
    rate_bps_per_period: u64,
) -> Result<(BalancedBatch, u64), i32> {
    if period_blocks < MIN_LEASE_PERIOD_BLOCKS {
        return Err(ERR_IFRS_INVALID_LEASE_TERMS);
    }
    let pv = compute_lease_present_value(periodic_payment, term_periods, rate_bps_per_period)?;
    let raw = [
        JournalLine::dr(ACC_ROU_ASSETS, pv),
        JournalLine::cr(ACC_LEASE_LIABILITIES, pv),
    ];
    let batch = BalancedBatch::build(&raw, STD_IFRS16_LEASES, CashFlowClass::None)?;
    Ok((batch, pv))
}

/// Pay one `IFRS 16` lease installment (`Dr 7000 Interest + Dr 2500 Principal / Cr 1010 Cash`).
pub fn derive_lease_installment(
    remaining_liability: u64,
    periodic_payment: u64,
    rate_bps_per_period: u64,
    is_final_period: bool,
) -> Result<(BalancedBatch, u64, u64), i32> {
    if remaining_liability == 0 || periodic_payment == 0 {
        return Err(ERR_IFRS_INVALID_LEASE_TERMS);
    }
    let (principal, interest, cash_paid) = if is_final_period {
        let interest = periodic_payment.saturating_sub(remaining_liability);
        let cash = remaining_liability.saturating_add(interest);
        (remaining_liability, interest, cash)
    } else {
        let interest = (((remaining_liability as u128) * (rate_bps_per_period as u128)) / 10_000u128)
            as u64;
        let principal = periodic_payment
            .saturating_sub(interest)
            .min(remaining_liability);
        let cash = principal.saturating_add(interest);
        (principal, interest, cash)
    };
    let raw = [
        JournalLine::dr(ACC_LEASE_LIABILITIES, principal),
        JournalLine::dr(ACC_FINANCE_DISPOSAL_TAX, interest),
        JournalLine::cr(ACC_CASH, cash_paid),
    ];
    let batch = BalancedBatch::build(&raw, STD_IFRS16_LEASES, CashFlowClass::Financing)?;
    Ok((batch, principal, interest))
}

// ============================================================================
// IAS 32 (Equity & Dividends), IFRS 2 (Share-Based Comp) & IFRS 9 (Debt & ECL)
// ============================================================================

/// Share issuance proceeds (`IAS 32` — `Dr 1010 Cash / Cr 3000 Share Capital + Cr 3010 Share Premium`).
pub fn derive_equity_issuance(
    shares: u64,
    par_per_share: u64,
    total_proceeds: u64,
) -> Result<BalancedBatch, i32> {
    if shares == 0 || par_per_share == 0 || total_proceeds == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let par_total = shares
        .checked_mul(par_per_share)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    if par_total > total_proceeds {
        return Err(ERR_IFRS_PAR_EXCEEDS_PROCEEDS);
    }
    let premium = total_proceeds - par_total;
    let raw = [
        JournalLine::dr(ACC_CASH, total_proceeds),
        JournalLine::cr(ACC_SHARE_CAPITAL, par_total),
        JournalLine::cr(ACC_SHARE_PREMIUM, premium),
    ];
    BalancedBatch::build(&raw, STD_IAS32_EQUITY, CashFlowClass::Financing)
}

/// Share buyback at cost (`IAS 32.33` — `Dr 3200 Treasury Shares / Cr 1010 Cash`, zero P&L gain/loss!).
pub fn derive_share_buyback(total_cost: u64) -> Result<BalancedBatch, i32> {
    if total_cost == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_TREASURY_SHARES, total_cost),
        JournalLine::cr(ACC_CASH, total_cost),
    ];
    BalancedBatch::build(&raw, STD_IAS32_EQUITY, CashFlowClass::Financing)
}

/// Cash dividend distribution (`IAS 32` — **reverts** unless `amount <= distributable_profit`).
pub fn derive_dividend_payment(
    amount: u64,
    distributable_profit: i128,
) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    if distributable_profit <= 0 || (amount as i128) > distributable_profit {
        return Err(ERR_IFRS_INSUFFICIENT_REALIZED_PROFIT);
    }
    let raw = [
        JournalLine::dr(ACC_RETAINED_EARNINGS, amount),
        JournalLine::cr(ACC_CASH, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS32_EQUITY, CashFlowClass::Financing)
}

/// Employee option vesting (`IFRS 2` — `Dr 6100 Employee Benefits & SBC / Cr 3300 SBC Reserve`).
pub fn derive_esop_vesting(fair_value_vested: u64) -> Result<BalancedBatch, i32> {
    if fair_value_vested == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_EMPLOYEE_BENEFITS, fair_value_vested),
        JournalLine::cr(ACC_SBC_RESERVE, fair_value_vested),
    ];
    BalancedBatch::build(&raw, STD_IFRS2_SBC, CashFlowClass::None)
}

/// Employee option exercise (`IFRS 2` + `IAS 32` — reclassifies `SBC Reserve` + strike cash into Share Capital/Premium).
pub fn derive_esop_exercise(
    strike_cash: u64,
    reserve_transfer: u64,
    par_amount: u64,
) -> Result<BalancedBatch, i32> {
    let total_eq = strike_cash
        .checked_add(reserve_transfer)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    if total_eq == 0 || par_amount == 0 || par_amount > total_eq {
        return Err(ERR_IFRS_PAR_EXCEEDS_PROCEEDS);
    }
    let premium = total_eq - par_amount;
    let raw = [
        JournalLine::dr(ACC_CASH, strike_cash),
        JournalLine::dr(ACC_SBC_RESERVE, reserve_transfer),
        JournalLine::cr(ACC_SHARE_CAPITAL, par_amount),
        JournalLine::cr(ACC_SHARE_PREMIUM, premium),
    ];
    BalancedBatch::build(&raw, STD_IFRS2_SBC, CashFlowClass::Financing)
}

/// Term loan drawdown at Amortized Cost (`IFRS 9` — `Dr 1010 Cash / Cr 2600 Term Debt`, `CFF`).
pub fn derive_loan_drawdown(principal: u64) -> Result<BalancedBatch, i32> {
    if principal == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_CASH, principal),
        JournalLine::cr(ACC_TERM_DEBT, principal),
    ];
    BalancedBatch::build(&raw, STD_IFRS9_INSTRUMENTS, CashFlowClass::Financing)
}

/// Debt service payment (`IFRS 9` — `Dr 2600 Principal + Dr 7000 Interest / Cr 1010 Cash`).
pub fn derive_debt_service(
    outstanding_principal: u64,
    principal_paid: u64,
    interest_paid: u64,
) -> Result<BalancedBatch, i32> {
    if principal_paid > outstanding_principal {
        return Err(ERR_IFRS_INVALID_DEBT_PAYMENT);
    }
    let total_cash = principal_paid
        .checked_add(interest_paid)
        .ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
    if total_cash == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_TERM_DEBT, principal_paid),
        JournalLine::dr(ACC_FINANCE_DISPOSAL_TAX, interest_paid),
        JournalLine::cr(ACC_CASH, total_cash),
    ];
    BalancedBatch::build(&raw, STD_IFRS9_INSTRUMENTS, CashFlowClass::Financing)
}

/// Statutory deterministic `IFRS 9` simplified aging `ECL` rate (in basis points, `10_000 = 100%`).
/// Eliminates management "cookie-jar" reserve manipulation!
pub const fn compute_invoice_ecl_bps(overdue_blocks: u64) -> u64 {
    if overdue_blocks == 0 {
        100 // 1.0% Stage-1 baseline ECL
    } else if overdue_blocks <= 200 {
        1_000 // 10.0%
    } else if overdue_blocks <= 1_000 {
        5_000 // 50.0%
    } else {
        10_000 // 100.0% credit-impaired
    }
}

pub fn compute_invoice_ecl_amount(open_amount: u64, due_block: u64, current_block: u64) -> u64 {
    if open_amount == 0 {
        return 0;
    }
    let overdue = current_block.saturating_sub(due_block);
    let bps = compute_invoice_ecl_bps(overdue);
    (((open_amount as u128) * (bps as u128)) / 10_000u128) as u64
}

/// Adjust `1190 Allowance for ECL` to match deterministic aging target (`Dr/Cr 6400 <-> Cr/Dr 1190`).
pub fn derive_ecl_adjustment(
    current_allowance: u64,
    target_allowance: u64,
) -> Result<BalancedBatch, i32> {
    if target_allowance == current_allowance {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let raw = if target_allowance > current_allowance {
        let diff = target_allowance - current_allowance;
        [
            JournalLine::dr(ACC_OPERATING_AND_ECL, diff),
            JournalLine::cr(ACC_ALLOWANCE_ECL, diff),
        ]
    } else {
        let diff = current_allowance - target_allowance;
        [
            JournalLine::dr(ACC_ALLOWANCE_ECL, diff),
            JournalLine::cr(ACC_OPERATING_AND_ECL, diff),
        ]
    };
    BalancedBatch::build(&raw, STD_IFRS9_INSTRUMENTS, CashFlowClass::None)
}

// ============================================================================
// IAS 19 (Payroll), Operating Expenses, IAS 12 (Current Tax), IAS 7 Suspense & IAS 1 Close
// ============================================================================

pub fn derive_payroll_run(gross_wages: u64, is_paid_now: bool) -> Result<BalancedBatch, i32> {
    if gross_wages == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let cr_acc = if is_paid_now {
        ACC_CASH
    } else {
        ACC_ACCRUED_PAYROLL
    };
    let raw = [
        JournalLine::dr(ACC_EMPLOYEE_BENEFITS, gross_wages),
        JournalLine::cr(cr_acc, gross_wages),
    ];
    BalancedBatch::build(&raw, STD_IAS19_EMPLOYEE, CashFlowClass::Operating)
}

pub fn derive_accrued_payroll_settlement(amount: u64) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_ACCRUED_PAYROLL, amount),
        JournalLine::cr(ACC_CASH, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS19_EMPLOYEE, CashFlowClass::Operating)
}

pub fn derive_operating_expense(
    category: u8,
    amount: u64,
    is_cash: bool,
) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    if category != OPEX_RND && category != OPEX_SALES_MARKETING && category != OPEX_GENERAL_ADMIN {
        return Err(ERR_IFRS_INVALID_OPEX_CATEGORY);
    }
    let cr_acc = if is_cash {
        ACC_CASH
    } else {
        ACC_TRADE_PAYABLES
    };
    let raw = [
        JournalLine::dr(ACC_OPERATING_AND_ECL, amount),
        JournalLine::cr(cr_acc, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS1_PRESENTATION, CashFlowClass::Operating)
}

pub fn derive_payable_settlement(amount: u64) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_TRADE_PAYABLES, amount),
        JournalLine::cr(ACC_CASH, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS1_PRESENTATION, CashFlowClass::Operating)
}

/// Accrue statutory current corporate income tax (`IAS 12` — bans speculative Deferred Tax Assets).
pub fn derive_current_tax_accrual(tax_amount: u64) -> Result<BalancedBatch, i32> {
    if tax_amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_FINANCE_DISPOSAL_TAX, tax_amount),
        JournalLine::cr(ACC_TAX_PAYABLE, tax_amount),
    ];
    BalancedBatch::build(&raw, STD_IAS12_INCOME_TAX, CashFlowClass::None)
}

pub fn derive_income_tax_payment(amount: u64) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_TAX_PAYABLE, amount),
        JournalLine::cr(ACC_CASH, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS12_INCOME_TAX, CashFlowClass::Operating)
}

/// Quarantine unattributed direct bank deposits into `2900 Unattributed Cash Suspense` (`Liability`)
/// — **never** Revenue or Equity!
pub fn derive_suspense_quarantine(unattributed_inflow: u64) -> Result<BalancedBatch, i32> {
    if unattributed_inflow == 0 {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let raw = [
        JournalLine::dr(ACC_CASH, unattributed_inflow),
        JournalLine::cr(ACC_CASH_SUSPENSE, unattributed_inflow),
    ];
    BalancedBatch::build(&raw, STD_IAS7_CASH_SUSPENSE, CashFlowClass::None)
}

/// Refund quarantined `2900 Unattributed Cash Suspense` back out of `treasuryIdentity`.
pub fn derive_suspense_refund(amount: u64) -> Result<BalancedBatch, i32> {
    if amount == 0 {
        return Err(ERR_IFRS_ZERO_OR_OVERFLOW);
    }
    let raw = [
        JournalLine::dr(ACC_CASH_SUSPENSE, amount),
        JournalLine::cr(ACC_CASH, amount),
    ];
    BalancedBatch::build(&raw, STD_IAS7_CASH_SUSPENSE, CashFlowClass::None)
}

// ============================================================================
// IAS 1 Statement Compilation, Read-Time Accrual Projection & Period Close
// ============================================================================

/// Unposted read-time accrual adjustments projected up to `context::block_number()` so `eth_call`
/// financial statements can NEVER hide depreciation, amortization, deferred revenue, or aging ECL!
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccrualProjection {
    pub unposted_ppe_depr: u64,
    pub unposted_rou_amort: u64,
    pub unposted_intang_amort: u64,
    pub unposted_deferred_rev_arms: u64,
    pub unposted_deferred_rev_related: u64,
    pub target_ecl_allowance: u64,
    pub unattributed_bank_inflow: u64,
    pub bank_custody_shortfall: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompiledStatements {
    /// Net signed balances for all 32 accounts after applying `AccrualProjection`:
    /// - For normal-Debit accounts (`Assets`, `Treasury Shares`, `Expenses`, `Returns`): `Dr - Cr`
    /// - For normal-Credit accounts (`Contra-Assets`, `Liabilities`, `Equity`, `Revenues`): `Cr - Dr`
    pub normal_balances: [i128; COA_COUNT],
    pub total_current_assets: i128,
    pub total_non_current_assets: i128,
    pub total_assets: i128,
    pub total_current_liabilities: i128,
    pub total_non_current_liabilities: i128,
    pub total_liabilities: i128,
    pub gross_revenue_arms_length: i128,
    pub gross_revenue_related_party: i128,
    pub net_revenue: i128,
    pub gross_profit: i128,
    pub operating_income_ebit: i128,
    pub net_income: i128,
    pub closed_retained_earnings: i128,
    pub distributable_profit: i128,
    pub total_equity: i128,
    /// `total_assets == total_liabilities + total_equity && bank_custody_shortfall == 0`
    pub equation_balanced: bool,
    pub custody_clean: bool,
}

/// Compile full `IAS 1` Balance Sheet & Income Statement from raw `(debit, credit)` totals + live `AccrualProjection`.
pub fn compile_statements(
    raw_totals: &[(u64, u64); COA_COUNT],
    proj: &AccrualProjection,
) -> CompiledStatements {
    let mut dr = [0i128; COA_COUNT];
    let mut cr = [0i128; COA_COUNT];
    let mut i = 0;
    while i < COA_COUNT {
        dr[i] = raw_totals[i].0 as i128;
        cr[i] = raw_totals[i].1 as i128;
        i += 1;
    }

    // 1. Apply live unposted depreciation & amortization (`IAS 16 / 38 / IFRS 16`)
    let total_unposted_da = (proj.unposted_ppe_depr as i128)
        + (proj.unposted_rou_amort as i128)
        + (proj.unposted_intang_amort as i128);
    if total_unposted_da > 0 {
        dr[ACC_DEPR_AND_AMORT as usize] += total_unposted_da;
        cr[ACC_ACCUM_DEPR_PPE as usize] += proj.unposted_ppe_depr as i128;
        cr[ACC_ACCUM_AMORT_ROU as usize] += proj.unposted_rou_amort as i128;
        cr[ACC_ACCUM_AMORT_INTANG as usize] += proj.unposted_intang_amort as i128;
    }

    // 2. Apply live unposted over-time deferred revenue (`IFRS 15`)
    if proj.unposted_deferred_rev_arms > 0 {
        dr[ACC_CONTRACT_LIABILITIES as usize] += proj.unposted_deferred_rev_arms as i128;
        cr[ACC_REVENUE_ARMS_LENGTH as usize] += proj.unposted_deferred_rev_arms as i128;
    }
    if proj.unposted_deferred_rev_related > 0 {
        dr[ACC_CONTRACT_LIABILITIES as usize] += proj.unposted_deferred_rev_related as i128;
        cr[ACC_REVENUE_RELATED_PARTY as usize] += proj.unposted_deferred_rev_related as i128;
    }

    // 3. Apply live deterministic aging ECL adjustment (`IFRS 9`)
    let cur_ecl = cr[ACC_ALLOWANCE_ECL as usize] - dr[ACC_ALLOWANCE_ECL as usize];
    let tgt_ecl = proj.target_ecl_allowance as i128;
    if tgt_ecl > cur_ecl {
        let diff = tgt_ecl - cur_ecl;
        dr[ACC_OPERATING_AND_ECL as usize] += diff;
        cr[ACC_ALLOWANCE_ECL as usize] += diff;
    } else if tgt_ecl < cur_ecl {
        let diff = cur_ecl - tgt_ecl;
        dr[ACC_ALLOWANCE_ECL as usize] += diff;
        cr[ACC_OPERATING_AND_ECL as usize] += diff;
    }

    // 4. Apply live unattributed bank deposit quarantine (`2900 Cash Suspense`)
    if proj.unattributed_bank_inflow > 0 {
        dr[ACC_CASH as usize] += proj.unattributed_bank_inflow as i128;
        cr[ACC_CASH_SUSPENSE as usize] += proj.unattributed_bank_inflow as i128;
    }

    let mut normal_balances = [0i128; COA_COUNT];
    let mut k = 0;
    while k < COA_COUNT {
        normal_balances[k] = match CHART_OF_ACCOUNTS[k].normal_side {
            Side::Debit => dr[k] - cr[k],
            Side::Credit => cr[k] - dr[k],
        };
        k += 1;
    }

    let total_current_assets = normal_balances[ACC_CASH as usize]
        + normal_balances[ACC_TRADE_RECEIVABLES as usize]
        - normal_balances[ACC_ALLOWANCE_ECL as usize]
        + normal_balances[ACC_INVENTORY as usize];

    let total_non_current_assets = normal_balances[ACC_FUTURE_CONTRACT_RECEIVABLES as usize]
        + normal_balances[ACC_PPE_COST as usize]
        - normal_balances[ACC_ACCUM_DEPR_PPE as usize]
        + normal_balances[ACC_ROU_ASSETS as usize]
        - normal_balances[ACC_ACCUM_AMORT_ROU as usize]
        + normal_balances[ACC_INTANGIBLES_COST as usize]
        - normal_balances[ACC_ACCUM_AMORT_INTANG as usize];

    let total_assets = total_current_assets + total_non_current_assets;

    let total_current_liabilities = normal_balances[ACC_TRADE_PAYABLES as usize]
        + normal_balances[ACC_ACCRUED_PAYROLL as usize]
        + normal_balances[ACC_TAX_PAYABLE as usize]
        + normal_balances[ACC_CONTRACT_LIABILITIES as usize]
        + normal_balances[ACC_DIVIDENDS_PAYABLE as usize]
        + normal_balances[ACC_CASH_SUSPENSE as usize];

    let total_non_current_liabilities =
        normal_balances[ACC_LEASE_LIABILITIES as usize] + normal_balances[ACC_TERM_DEBT as usize];

    let total_liabilities = total_current_liabilities + total_non_current_liabilities;

    let gross_revenue_arms_length = normal_balances[ACC_REVENUE_ARMS_LENGTH as usize];
    let gross_revenue_related_party = normal_balances[ACC_REVENUE_RELATED_PARTY as usize];
    let net_revenue = gross_revenue_arms_length + gross_revenue_related_party
        - normal_balances[ACC_SALES_RETURNS as usize];
    let gross_profit = net_revenue - normal_balances[ACC_COGS_AND_NRV as usize];
    let operating_income_ebit = gross_profit
        - normal_balances[ACC_EMPLOYEE_BENEFITS as usize]
        - normal_balances[ACC_DEPR_AND_AMORT as usize]
        - normal_balances[ACC_OPERATING_AND_ECL as usize];
    let net_income = operating_income_ebit - normal_balances[ACC_FINANCE_DISPOSAL_TAX as usize];

    let closed_retained_earnings = normal_balances[ACC_RETAINED_EARNINGS as usize];
    let treasury_shares = normal_balances[ACC_TREASURY_SHARES as usize];
    let distributable_profit = closed_retained_earnings + net_income - treasury_shares;

    let paid_in_and_reserves = normal_balances[ACC_SHARE_CAPITAL as usize]
        + normal_balances[ACC_SHARE_PREMIUM as usize]
        - treasury_shares
        + normal_balances[ACC_SBC_RESERVE as usize];
    let total_equity = paid_in_and_reserves + closed_retained_earnings + net_income;

    CompiledStatements {
        normal_balances,
        total_current_assets,
        total_non_current_assets,
        total_assets,
        total_current_liabilities,
        total_non_current_liabilities,
        total_liabilities,
        gross_revenue_arms_length,
        gross_revenue_related_party,
        net_revenue,
        gross_profit,
        operating_income_ebit,
        net_income,
        closed_retained_earnings,
        distributable_profit,
        total_equity,
        equation_balanced: total_assets == (total_liabilities + total_equity),
        custody_clean: proj.bank_custody_shortfall == 0,
    }
}

/// Roll all nominal P&L accounts (`24..=31`) into `3400 Retained Earnings` (`IAS 1` Fiscal Close)
/// while preserving `Dr == Cr` across all 32 accounts. Returns the net income rolled `(i128)`.
pub fn roll_nominal_accounts_into_retained_earnings(
    totals: &mut [(u64, u64); COA_COUNT],
) -> Result<i128, i32> {
    let mut net_cr_over_dr: i128 = 0;
    let mut idx = 24usize;
    while idx < COA_COUNT {
        let (d, c) = totals[idx];
        net_cr_over_dr += (c as i128) - (d as i128);
        totals[idx] = (0, 0);
        idx += 1;
    }

    let (re_dr, re_cr) = totals[ACC_RETAINED_EARNINGS as usize];
    if net_cr_over_dr >= 0 {
        let add_cr = u64::try_from(net_cr_over_dr).map_err(|_| ERR_IFRS_ZERO_OR_OVERFLOW)?;
        let next_cr = re_cr.checked_add(add_cr).ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
        totals[ACC_RETAINED_EARNINGS as usize] = (re_dr, next_cr);
    } else {
        let add_dr = u64::try_from(-net_cr_over_dr).map_err(|_| ERR_IFRS_ZERO_OR_OVERFLOW)?;
        let next_dr = re_dr.checked_add(add_dr).ok_or(ERR_IFRS_ZERO_OR_OVERFLOW)?;
        totals[ACC_RETAINED_EARNINGS as usize] = (next_dr, re_cr);
    }
    Ok(net_cr_over_dr)
}

// ============================================================================
// Cross-HPS Client Wrappers for Sibling Corporate Subroutines
// ============================================================================

/// Called by `ProductLedger.buyProduct` after transferring `total_amount` into `treasuryIdentity`.
pub fn call_book_cash_sale(
    accounting_ledger: &[u8; 20],
    product_id: &[u8; 32],
    buyer: &[u8; 20],
    quantity: u64,
    unit_price: u64,
    total_amount: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<192>::new(const {
        selector("bookCashSale(bytes32,address,uint64,uint64,uint64)")
    })
    .push_bytes32(product_id)
    .push_address(buyer)
    .push_u64(quantity)
    .push_u64(unit_price)
    .push_u64(total_amount);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ProductLedger.restockProductWithCost` when inventory is procured for `unit_cost`.
pub fn call_book_inventory_restock(
    accounting_ledger: &[u8; 20],
    product_id: &[u8; 32],
    supplier: &[u8; 20],
    units: u64,
    total_cost: u64,
    pay_cash_from_treasury: bool,
) -> Result<u64, i32> {
    let cd = CallEncoder::<192>::new(const {
        selector("bookInventoryPurchaseFromModule(bytes32,address,uint64,uint64,bool)")
    })
    .push_bytes32(product_id)
    .push_address(supplier)
    .push_u64(units)
    .push_u64(total_cost)
    .push_bool(pay_cash_from_treasury);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ProductLedger.refundSalesReturn` when returning `quantity` units to `buyer`.
pub fn call_book_sales_return(
    accounting_ledger: &[u8; 20],
    product_id: &[u8; 32],
    buyer: &[u8; 20],
    quantity: u64,
    refund_amount: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<160>::new(const {
        selector("bookSalesReturnFromModule(bytes32,address,uint64,uint64)")
    })
    .push_bytes32(product_id)
    .push_address(buyer)
    .push_u64(quantity)
    .push_u64(refund_amount);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ShareCapital` when primary share issuance proceeds settle into `treasuryIdentity`.
pub fn call_book_equity_issuance(
    accounting_ledger: &[u8; 20],
    investor: &[u8; 20],
    shares: u64,
    par_per_share: u64,
    total_proceeds: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<160>::new(const {
        selector("bookEquityIssuanceFromModule(address,uint64,uint64,uint64)")
    })
    .push_address(investor)
    .push_u64(shares)
    .push_u64(par_per_share)
    .push_u64(total_proceeds);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ShareCapital.executeShareBuyback` when `total_paid` is disbursed from `treasuryIdentity`.
pub fn call_book_share_buyback(
    accounting_ledger: &[u8; 20],
    seller: &[u8; 20],
    shares: u64,
    total_paid: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<128>::new(const {
        selector("bookShareBuybackFromModule(address,uint64,uint64)")
    })
    .push_address(seller)
    .push_u64(shares)
    .push_u64(total_paid);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ShareCapital.processDueEsopIssuances` when employee options vest.
pub fn call_book_esop_vesting(
    accounting_ledger: &[u8; 20],
    employee: &[u8; 20],
    options_vested: u64,
    fair_value_vested: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<128>::new(const {
        selector("bookEsopVestingFromModule(address,uint64,uint64)")
    })
    .push_address(employee)
    .push_u64(options_vested)
    .push_u64(fair_value_vested);
    call::call_u64(accounting_ledger, cd.as_slice())
}

/// Called by `ShareCapital.exerciseEmployeeOptions` when vested options are exercised into shares.
pub fn call_book_esop_exercise(
    accounting_ledger: &[u8; 20],
    employee: &[u8; 20],
    shares: u64,
    strike_cash: u64,
    reserve_transfer: u64,
    par_amount: u64,
) -> Result<u64, i32> {
    let cd = CallEncoder::<192>::new(const {
        selector("bookEsopExerciseFromModule(address,uint64,uint64,uint64,uint64)")
    })
    .push_address(employee)
    .push_u64(shares)
    .push_u64(strike_cash)
    .push_u64(reserve_transfer)
    .push_u64(par_amount);
    call::call_u64(accounting_ledger, cd.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_batch(totals: &mut [(u64, u64); COA_COUNT], b: &BalancedBatch) {
        for ln in b.lines() {
            match ln.side {
                Side::Debit => totals[ln.account as usize].0 += ln.amount,
                Side::Credit => totals[ln.account as usize].1 += ln.amount,
            }
        }
    }

    #[test]
    fn full_ifrs_lifecycle_conserves_accounting_equation_and_blocks_creative_accounting() {
        let mut totals = [(0u64, 0u64); COA_COUNT];

        // 1. IAS 32 Equity Issuance: 100,000 shares @ par 1, issue price 10 = 1,000,000 SGD
        let b_eq = derive_equity_issuance(100_000, 1, 1_000_000).unwrap();
        assert_eq!(b_eq.cash_delta(), 1_000_000);
        apply_batch(&mut totals, &b_eq);

        // 2. IAS 16 CapEx: reject micro-OpEx capitalization (< 1,000) & excessive useful life
        assert_eq!(
            derive_capex_acquisition(ASSET_CLASS_IT_HARDWARE, 500, 0, 1_000, true),
            Err(ERR_IFRS_BELOW_CAPEX_FLOOR)
        );
        assert_eq!(
            derive_capex_acquisition(ASSET_CLASS_IT_HARDWARE, 50_000, 0, 999_999, true),
            Err(ERR_IFRS_USEFUL_LIFE_OUT_OF_BOUNDS)
        );
        // IAS 38 Intangible: reject non-zero residual value
        assert_eq!(
            derive_capex_acquisition(ASSET_CLASS_FINITE_INTANGIBLE, 20_000, 1_000, 2_000, true),
            Err(ERR_IFRS_RESIDUAL_VALUE_EXCEEDED)
        );
        let b_capex =
            derive_capex_acquisition(ASSET_CLASS_IT_HARDWARE, 120_000, 0, 1_200, true).unwrap();
        apply_batch(&mut totals, &b_capex);

        // 3. IFRS 16 Lease Commencement: 10,000/period * 6 periods @ 2.00% (200 bps)
        assert_eq!(
            derive_lease_commencement(10_000, 6, 100, 9_000),
            Err(ERR_IFRS_INVALID_LEASE_TERMS)
        );
        let (b_lease, pv) = derive_lease_commencement(10_000, 6, 100, 200).unwrap();
        assert!(pv > 55_000 && pv < 60_000);
        apply_batch(&mut totals, &b_lease);

        // 4. IAS 2 Inventory WAC: buy 100 @ 200 = 20,000, then 100 @ 300 = 30,000 -> WAC = 250/unit
        apply_batch(&mut totals, &derive_inventory_purchase(100, 20_000, true).unwrap());
        apply_batch(&mut totals, &derive_inventory_purchase(100, 30_000, true).unwrap());
        let (cogs, rem_u, rem_c) = compute_wac_cogs(200, 50_000, 40);
        assert_eq!((cogs, rem_u, rem_c), (10_000, 160, 40_000));
        // Upward inventory revaluation banned
        assert_eq!(
            derive_inventory_nrv_writedown(40_000, 45_000),
            Err(ERR_IFRS_UPWARD_REVALUATION_BANNED)
        );

        // 5. IFRS 15 + IAS 24: cash sale of 40 units @ 600 = 24,000 (COGS = 10,000)
        apply_batch(&mut totals, &derive_cash_sale(24_000, cogs, false).unwrap());
        // Related-party credit sale banned!
        assert_eq!(
            derive_credit_sale(50_000, 0, 100, true),
            Err(ERR_IFRS_RELATED_PARTY_CREDIT_BANNED)
        );
        // Related-party cash sale segregated into 4050!
        apply_batch(&mut totals, &derive_cash_sale(5_000, 0, true).unwrap());

        // 6. IFRS 15 Deferred SaaS Contract: 12,000 over 120 blocks
        apply_batch(&mut totals, &derive_deferred_contract_receipt(12_000, 120).unwrap());

        // 7. Compile statements with live read-time accrual projection (30 blocks elapsed)
        let proj = AccrualProjection {
            unposted_ppe_depr: compute_linear_depreciation(120_000, 0, 1_200, 100, 130), // 3,000
            unposted_rou_amort: compute_linear_depreciation(pv, 0, 600, 100, 130),
            unposted_intang_amort: 0,
            unposted_deferred_rev_arms: compute_linear_deferred_earned(12_000, 100, 120, 130), // 3,000
            unposted_deferred_rev_related: 0,
            target_ecl_allowance: 0,
            unattributed_bank_inflow: 2_500, // quarantined into 2900 Suspense, NEVER revenue!
            bank_custody_shortfall: 0,
        };
        let st = compile_statements(&totals, &proj);
        assert!(st.equation_balanced);
        assert!(st.custody_clean);
        assert_eq!(st.gross_revenue_arms_length, 24_000 + 3_000);
        assert_eq!(st.gross_revenue_related_party, 5_000);
        assert_eq!(st.normal_balances[ACC_CASH_SUSPENSE as usize], 2_500);

        // 8. Illegal dividend exceeding realized profit rejected!
        assert_eq!(
            derive_dividend_payment(100_000, st.distributable_profit),
            Err(ERR_IFRS_INSUFFICIENT_REALIZED_PROFIT)
        );

        // 9. Fiscal period close preserves exact balance
        let net_inc = roll_nominal_accounts_into_retained_earnings(&mut totals).unwrap();
        assert_eq!(net_inc, 19_000); // 24k + 5k - 10k posted before accruals
        let st_after = compile_statements(&totals, &AccrualProjection::default());
        assert!(st_after.equation_balanced);
        assert_eq!(st_after.closed_retained_earnings, 19_000);
        assert_eq!(st_after.net_income, 0);

        // 10. 3-Stage Defense Service Contract (`180k/mo * 12 = 2,160,000`):
        assert_eq!(
            derive_service_contract_backlog(180_000, 12, 32, true),
            Err(ERR_IFRS_RELATED_PARTY_CREDIT_BANNED)
        );
        let (b_svc_sign, total_svc) =
            derive_service_contract_backlog(180_000, 12, 32, false).unwrap();
        assert_eq!(total_svc, 2_160_000);
        apply_batch(&mut totals, &b_svc_sign);
        let st_s1 = compile_statements(&totals, &AccrualProjection::default());
        assert!(st_s1.equation_balanced);
        assert_eq!(st_s1.normal_balances[ACC_FUTURE_CONTRACT_RECEIVABLES as usize], 2_160_000);
        assert_eq!(st_s1.net_income, 0); // Stage 1 signing books 0 premature profit!

        // Stage 2: Monthly invoice generated (180k Future AR -> Current AR + 4000 Revenue)
        apply_batch(&mut totals, &derive_service_contract_billing(180_000).unwrap());
        let st_s2 = compile_statements(&totals, &AccrualProjection::default());
        assert!(st_s2.equation_balanced);
        assert_eq!(st_s2.normal_balances[ACC_FUTURE_CONTRACT_RECEIVABLES as usize], 1_980_000);
        assert_eq!(st_s2.normal_balances[ACC_TRADE_RECEIVABLES as usize], 180_000);
        assert_eq!(st_s2.net_income, 180_000);

        // Stage 3: Bank oracle settlement (180k Current AR -> Current Cash + CFO)
        let b_s3 = derive_receivable_collection(180_000).unwrap();
        assert_eq!(b_s3.cash_delta(), 180_000);
        apply_batch(&mut totals, &b_s3);
        let st_s3 = compile_statements(&totals, &AccrualProjection::default());
        assert!(st_s3.equation_balanced);
        assert_eq!(st_s3.normal_balances[ACC_TRADE_RECEIVABLES as usize], 0);
    }
}
