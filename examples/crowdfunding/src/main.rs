//! Board-Resolution-Activated Pre-Order Crowdfunding & Stretch-Goal Corporate Growth Budget
//! **Haltproof Subroutine (HPS #26)** (`crowdfunding`).
//!
//! Linked directly to a company's [`AccountingLedger`], which is in turn bound to its
//! [`CorporateCharter`], making every pre-order crowdfunding campaign a **multi-step
//! Board-Resolution-activated corporate matter** (analogous to a new share issuance):
//!
//! ### Multi-Step Constitutional & Accounting Lifecycle
//! 1. **Step 1 — Campaign Specification & Board Resolution Trigger (`STATE_PENDING_BOARD_RESOLUTION = 1`):**
//!    - `proposeCampaign(...)` (or `initialize(...)`) binds to `accountingLedger`, resolves and pins
//!      `corporateCharter` (`accountingLedger.associatedCharter()`), `identityRegistry`,
//!      `hfsRegistry`, `operatingBankLedger`, and `treasuryIdentity`, and verifies
//!      `require_active_charter(&corporateCharter)` plus Director/Officer proposer standing.
//!    - Stores the immutable campaign mode, target(s), `durationBlocks`, Hardware Reward SKUs, and
//!      codified IAS/IFRS Stretch-Goal Growth Budget Line Items in `STATE_PENDING_BOARD_RESOLUTION (1)`.
//!    - `bindBoardResolution(authObj)` pins the newly triggered `CorporateCharter` `Authorization`
//!      HFS (`POLICY_BOARD_RESOLUTION`) committed to `specHash()` / `hashActivateCampaign()`.
//!    - **Pre-orders are strictly rejected** (`ERR_AWAITING_BOARD_ACTIVATION = -26`) until the
//!      Board Resolution passes and is activated!
//! 2. **Step 2 — Board of Directors Deliberation & Quorum Signatures:**
//!    - Directors sign the `Authorization` HFS (`approve` / `approveAndFinalize`) under the
//!      company's `CorporateCharter` `POLICY_BOARD_RESOLUTION`.
//! 3. **Step 3 — Resolution Enactment -> `STATE_LIVE = 2`:**
//!    - Enacting the passed Board Resolution via `AccountingLedger.activateCrowdfundingCampaign(cf, authObj)`
//!      (`onBoardResolutionActivated`) or `Crowdfunding.activateCampaign(authObj)` consumes the
//!      one-time `Authorization`, locks `activatedAtBlock = block_number()` and
//!      `deadlineBlock = activatedAtBlock + durationBlocks`, and transitions the HFS to `STATE_LIVE (2)`.
//! 4. **Step 4 — Live Pre-Orders & Three Campaign Modes (`STATE_LIVE = 2`):**
//!    - **`MODE_SINGLE_HARD_CAP = 1`:** Single target `baseTargetAmount`; blocks excess pre-orders
//!      (`ERR_TARGET_CAP_EXCEEDED`); if missed by `deadlineBlock`, **no-one is charged**.
//!    - **`MODE_SINGLE_ALL_OR_NOTHING = 2`:** Single minimum target `baseTargetAmount` (no-one
//!      charged if missed; uncapped above target up to per-SKU `maxUnits`).
//!    - **`MODE_MULTI_TIER_GROWTH_BUDGET = 3`:** Ascending stretch targets `tier[0..N-1]` where
//!      crossing each milestone automatically unlocks a ring-fenced line item in the company's
//!      codified IAS/IFRS growth budget (`1200 Inventory MOQ`, `6400 R&D / Cert / Growth OpEx`,
//!      `1500 IAS 16 PPE CapEx`).
//! 5. **Step 5 — Settlement into `AccountingLedger` (`2300 Contract Liabilities`) or 100% Refund:**
//!    - **Succeeded (`STATE_SETTLED_SUCCEEDED = 3`):** Sweeps escrowed funds into `AccountingLedger`'s
//!      `treasuryIdentity` and posts `Dr 1010 Cash / Cr 2300 Contract Liabilities (IFRS 15 Pre-Order
//!      Unearned Revenue)`; unlocked growth budget lines can then be disbursed within strict caps.
//!    - **Missed (`STATE_FAILED_REFUNDABLE = 4`):** Uncharged credit-card holds are voided without
//!      capture and on-chain escrowed pledges receive 100% trustless refunds (`claimFullRefund`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    query_charter_function_auth, require_active_charter, require_valid_authorization_hps,
    require_valid_identity, verify_and_consume_auth, ActionHasher, ACTION_LAUNCH_CROWDFUNDING,
    ERR_CHARTER_MISMATCH, ERR_MISSING_ROLE, HFS_TYPE_CROWDFUNDING, POLICY_ACCOUNTING_OPS,
    POLICY_BOARD_RESOLUTION, ROLE_CHIEF_ACCOUNTANT, ROLE_PRODUCT_MANAGER, ROLE_TREASURY_MANAGER,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const MODE_SINGLE_HARD_CAP: u64 = 1;
pub const MODE_SINGLE_ALL_OR_NOTHING: u64 = 2;
pub const MODE_MULTI_TIER_GROWTH_BUDGET: u64 = 3;

pub const STATE_UNINITIALIZED: u8 = 0;
pub const STATE_PENDING_BOARD_RESOLUTION: u8 = 1;
pub const STATE_LIVE: u8 = 2;
pub const STATE_SETTLED_SUCCEEDED: u8 = 3;
pub const STATE_FAILED_REFUNDABLE: u8 = 4;

pub const PLEDGE_NONE: u8 = 0;
pub const PLEDGE_ESCROWED_ONCHAIN: u8 = 1;
pub const PLEDGE_PREAUTH_HOLD_ORACLE: u8 = 2;
pub const PLEDGE_FINALIZED_CAPTURED: u8 = 3;
pub const PLEDGE_REFUNDED_OR_VOIDED: u8 = 4;

pub const RAIL_ONCHAIN_ESCROW: u8 = 1;
pub const RAIL_ORACLE_PREAUTH_HOLD: u8 = 2;

pub const BUDGET_CAT_BASE_MANUFACTURING_MOQ: u64 = 1;
pub const BUDGET_CAT_RND_ENGINEERING: u64 = 2;
pub const BUDGET_CAT_CAPEX_EQUIPMENT: u64 = 3;
pub const BUDGET_CAT_CERTIFICATION_COMPLIANCE: u64 = 4;
pub const BUDGET_CAT_GROWTH_DISTRIBUTION: u64 = 5;

pub const MAX_REWARD_SKUS: usize = 8;
pub const MAX_BUDGET_TIERS: usize = 8;

pub const SKU_PACK_IN_LEN: usize = 64;
pub const SKU_WIRE_LEN: usize = 72;
pub const TIER_PACK_IN_LEN: usize = 88;
pub const TIER_WIRE_LEN: usize = 112;
pub const PLEDGE_WIRE_LEN: usize = 128;
pub const SUMMARY_WIRE_LEN: usize = 320;

pub const ERR_NOT_INITIALIZED: i32 = -10;
pub const ERR_ALREADY_INITIALIZED: i32 = -11;
pub const ERR_UNAUTHORIZED: i32 = -12;
pub const ERR_INVALID_PARAMS: i32 = -13;
pub const ERR_CAMPAIGN_NOT_LIVE: i32 = -20;
pub const ERR_DEADLINE_PASSED: i32 = -21;
pub const ERR_DEADLINE_NOT_REACHED: i32 = -22;
pub const ERR_CAMPAIGN_NOT_FAILED: i32 = -23;
pub const ERR_CAMPAIGN_NOT_SUCCEEDED: i32 = -24;
pub const ERR_AWAITING_BOARD_ACTIVATION: i32 = -26;
pub const ERR_ALREADY_ACTIVATED: i32 = -27;
pub const ERR_BOARD_AUTH_MISMATCH: i32 = -28;
pub const ERR_TARGET_CAP_EXCEEDED: i32 = -31;
pub const ERR_SKU_SOLD_OUT: i32 = -32;
pub const ERR_DUPLICATE_PAYMENT_REF: i32 = -33;
pub const ERR_PLEDGE_NOT_ELIGIBLE: i32 = -34;
pub const ERR_ESCROW_SHORTFALL: i32 = -35;
pub const ERR_BUDGET_TIER_LOCKED: i32 = -40;
pub const ERR_BUDGET_LINE_EXCEEDED: i32 = -41;
pub const ERR_INSUFFICIENT_REALIZED_CASH: i32 = -42;
pub const ERR_ALREADY_CHARGED_NO_USER_CANCEL: i32 = -43;
pub const ERR_SUBCALL_FAILED: i32 = -50;

const ROLE_CEO: [u8; 32] = keccak256(b"ROLE_CEO");
const ROLE_COO: [u8; 32] = keccak256(b"ROLE_COO");
const ROLE_CTO: [u8; 32] = keccak256(b"ROLE_CTO");
const ACTION_DISBURSE_CROWDFUND_BUDGET: [u8; 32] = keccak256(b"DISBURSE_CROWDFUND_BUDGET");

const KEY_INIT: &[u8] = b"cf:init";
const KEY_STATE: &[u8] = b"cf:state";
const KEY_MODE: &[u8] = b"cf:mode";
const KEY_BASE_TARGET: &[u8] = b"cf:target";
const KEY_DURATION_BLKS: &[u8] = b"cf:dur_blks";
const KEY_DELIVERY_BLKS: &[u8] = b"cf:deliv_blks";
const KEY_ACTIVATED_BLK: &[u8] = b"cf:act_blk";
const KEY_DEADLINE_BLK: &[u8] = b"cf:deadline";
const KEY_TITLE: &[u8] = b"cf:title";
const KEY_SPEC_HASH: &[u8] = b"cf:spec_h";
const KEY_ACT_HASH: &[u8] = b"cf:act_h";

const KEY_PROPOSER: &[u8] = b"cf:proposer";
const KEY_REGISTRY: &[u8] = b"cf:reg";
const KEY_HFS_REGISTRY: &[u8] = b"cf:hfs_reg";
const KEY_CHARTER: &[u8] = b"cf:charter";
const KEY_ACCOUNTING: &[u8] = b"cf:acc_led";
const KEY_BANK_LEDGER: &[u8] = b"cf:bank_led";
const KEY_TREASURY_ID: &[u8] = b"cf:treas_id";
const KEY_ESCROW_ID: &[u8] = b"cf:esc_id";
const KEY_BOARD_AUTH: &[u8] = b"cf:brd_auth";
const KEY_REWARD_VOUCHER: &[u8] = b"cf:rv_hfs";
const KEY_ORACLE: &[u8] = b"cf:oracle";
const KEY_RATIFIED_VIA_ACC: &[u8] = b"cf:via_acc";

const KEY_TOT_COMMITTED: &[u8] = b"cf:tot_com";
const KEY_TOT_ESCROW_ONCHAIN: &[u8] = b"cf:tot_esc";
const KEY_TOT_PREAUTH_ORACLE: &[u8] = b"cf:tot_hold";
const KEY_TOT_CAPTURED_ORACLE: &[u8] = b"cf:tot_cap";
const KEY_TOT_REFUNDED: &[u8] = b"cf:tot_ref";
const KEY_TOT_BUDGET_UNLOCKED: &[u8] = b"cf:tot_bunl";
const KEY_TOT_BUDGET_SPENT: &[u8] = b"cf:tot_bspn";
const KEY_SWEPT_TO_TREASURY: &[u8] = b"cf:swept";

const KEY_PLEDGE_CNT: &[u8] = b"cf:plg_cnt";
const KEY_SKU_CNT: &[u8] = b"cf:sku_cnt";
const KEY_TIER_CNT: &[u8] = b"cf:tier_cnt";
const KEY_UNLOCKED_TIER_CNT: &[u8] = b"cf:unl_cnt";

const SEL_ACTIVATE_CAMPAIGN: [u8; 4] = selector("activateCampaign(address)");
const SEL_DISBURSE_BUDGET: [u8; 4] =
    selector("disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)");
const SEL_CHARTER_CLEAR_TRANSFER: [u8; 4] =
    selector("charterModuleClearTransfer(address,address,uint64)");
const SEL_ISSUE_PAID_VOUCHER: [u8; 4] =
    selector("issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)");

const EV_PROPOSED: [u8; 32] =
    event_topic("CrowdfundingProposed(address,address,address,uint64,uint64,uint64,bytes32)");
const EV_BOARD_RES_BOUND: [u8; 32] =
    event_topic("CrowdfundingBoardResolutionTriggered(address,address,bytes32)");
const EV_ACTIVATED_LIVE: [u8; 32] =
    event_topic("CrowdfundingActivatedLive(address,address,uint64,uint64)");
const EV_PLEDGE_RECORDED: [u8; 32] =
    event_topic("PreorderPledged(uint64,address,uint64,uint64,uint64,uint64)");
const EV_BUDGET_UNLOCKED: [u8; 32] =
    event_topic("GrowthBudgetLineUnlocked(uint64,bytes32,uint64,uint64,uint64)");
const EV_CAMPAIGN_FINALIZED: [u8; 32] =
    event_topic("CampaignFinalized(uint64,uint64,uint64)");
const EV_PLEDGE_REFUNDED: [u8; 32] =
    event_topic("PledgeRefundedOrVoided(uint64,address,uint64)");
const EV_BUDGET_DISBURSED: [u8; 32] =
    event_topic("GrowthBudgetDisbursed(uint64,address,uint64,uint64,bytes32)");
const EV_BACKER_VOUCHER_ISSUED: [u8; 32] =
    event_topic("BackerVoucherIssued(uint64,bytes32,uint64)");

hps_entry! {
    "hfsType()"                                                                                           => handle_hfs_type,
    "proposeCampaign(address,address,address,address,uint64,uint64,uint64,bytes,bytes,bytes)"             => handle_propose_campaign,
    "initialize(address,address,address,address,uint64,uint64,uint64,bytes,bytes,bytes)"                  => handle_propose_campaign,
    "bindBoardResolution(address)"                                                                        => handle_bind_board_resolution,
    "activateCampaign(address)"                                                                           => handle_activate_campaign,
    "onBoardResolutionActivated(address,address)"                                                         => handle_on_board_resolution_activated,
    "hashActivateCampaign()"                                                                              => handle_hash_activate_campaign,
    "specHash()"                                                                                          => handle_spec_hash,
    "accountingLedger()"                                                                                  => handle_accounting_ledger,
    "associatedCharter()"                                                                                 => handle_associated_charter,
    "associatedConstitution()"                                                                            => handle_associated_charter,
    "boardResolutionAuth()"                                                                               => handle_board_resolution_auth,
    "escrowIdentity()"                                                                                    => handle_escrow_identity,
    "state()"                                                                                             => handle_state,
    "pledgeOnChain(uint64,uint64,bytes32)"                                                                => handle_pledge_onchain,
    "recordOraclePreorderHold(bytes32,uint64,uint64,bytes32)"                                             => handle_record_oracle_hold,
    "recordOraclePreorderHoldForBacker(address,bytes32,uint64,uint64,bytes32)"                            => handle_record_oracle_hold_for_backer,
    "cancelPreorderAuthorization(uint64)"                                                                 => handle_cancel_preorder_auth,
    "confirmOracleHoldCaptured(uint64)"                                                                   => handle_confirm_oracle_captured,
    "grantDiscretionaryRefund(uint64)"                                                                    => handle_grant_discretionary_refund,
    "finalizeCampaign()"                                                                                  => handle_finalize_campaign,
    "claimFullRefund(uint64)"                                                                             => handle_claim_refund,
    "issueBackerVoucher(uint64)"                                                                          => handle_issue_backer_voucher,
    "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)"                                   => handle_disburse_budget,
    "hashDisburseBudgetLine(uint64,address,uint64,bytes32)"                                               => handle_hash_disburse_budget,
    "getCampaignSummary()"                                                                                => handle_get_summary,
    "getBudgetTiers()"                                                                                    => handle_get_budget_tiers,
    "getRewardSkus()"                                                                                     => handle_get_reward_skus,
    "getPledge(uint64)"                                                                                   => handle_get_pledge,
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

fn get_u64_be(buf: &[u8], off: usize) -> u64 {
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&buf[off..off + 8]);
    u64::from_be_bytes(tmp)
}

fn addr_topic(a: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(a);
    t
}

fn u64_topic(v: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&v.to_be_bytes());
    t
}

fn require_init() -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(ERR_NOT_INITIALIZED);
    }
    Ok(())
}

fn get_state() -> u8 {
    storage::get_u64(KEY_STATE) as u8
}

fn call_addr(target: &[u8; 20], cd: &[u8]) -> Result<[u8; 20], i32> {
    let raw = call::call_raw(target, cd)?;
    if raw.len() < 32 {
        return Err(ERR_SUBCALL_FAILED);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw[12..32]);
    Ok(out)
}

fn is_charter_officer_or_director(charter: &[u8; 20], identity: &[u8; 20]) -> bool {
    let is_dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(identity);
    if matches!(call::call_bool(charter, is_dir_cd.as_slice()), Ok(true)) {
        let cons_cd = CallEncoder::<64>::new(const { selector("hasDirectorConsented(address)") })
            .push_address(identity);
        // Accept consented directors (or stubs that don't implement `hasDirectorConsented`)
        if !matches!(call::call_bool(charter, cons_cd.as_slice()), Ok(false)) {
            return true;
        }
    }
    for role in [
        ROLE_CEO,
        ROLE_COO,
        ROLE_CTO,
        ROLE_CHIEF_ACCOUNTANT,
        ROLE_TREASURY_MANAGER,
        ROLE_PRODUCT_MANAGER,
    ] {
        let r_cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
            .push_bytes32(&role)
            .push_address(identity);
        if matches!(call::call_bool(charter, r_cd.as_slice()), Ok(true)) {
            return true;
        }
    }
    false
}

fn require_oracle_or_officer() -> Result<[u8; 20], i32> {
    require_init()?;
    let caller = context::msg_sender();
    if caller == [0u8; 20] {
        return Err(ERR_UNAUTHORIZED);
    }
    let oracle = storage::get_address(KEY_ORACLE).unwrap_or([0u8; 20]);
    let proposer = storage::get_address(KEY_PROPOSER).unwrap_or([0u8; 20]);
    if caller == oracle || caller == proposer {
        return Ok(caller);
    }
    let charter = storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]);
    if charter != [0u8; 20] && is_charter_officer_or_director(&charter, &caller) {
        return Ok(caller);
    }
    Err(ERR_UNAUTHORIZED)
}

fn sku_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cf:sku:").push_u64_be(idx)
}

fn tier_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cf:tier:").push_u64_be(idx)
}

fn pledge_key(pledge_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"cf:plg:")
        .push_u64_be(pledge_id)
}

fn ref_used_key(ref_hash: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"cf:ref:").push(ref_hash)
}

fn load_sku(idx: u64) -> Result<[u8; SKU_WIRE_LEN], i32> {
    let k = sku_key(idx);
    let mut buf = [0u8; SKU_WIRE_LEN];
    let n = storage::get_into(k.as_slice(), &mut buf).unwrap_or(0);
    if n < SKU_WIRE_LEN {
        return Err(ERR_INVALID_PARAMS);
    }
    Ok(buf)
}

fn save_sku(idx: u64, buf: &[u8; SKU_WIRE_LEN]) {
    let k = sku_key(idx);
    storage::set(k.as_slice(), buf);
}

fn load_tier(idx: u64) -> Result<[u8; TIER_WIRE_LEN], i32> {
    let k = tier_key(idx);
    let mut buf = [0u8; TIER_WIRE_LEN];
    let n = storage::get_into(k.as_slice(), &mut buf).unwrap_or(0);
    if n < TIER_WIRE_LEN {
        return Err(ERR_INVALID_PARAMS);
    }
    Ok(buf)
}

fn save_tier(idx: u64, buf: &[u8; TIER_WIRE_LEN]) {
    let k = tier_key(idx);
    storage::set(k.as_slice(), buf);
}

fn load_pledge(pledge_id: u64) -> Result<[u8; PLEDGE_WIRE_LEN], i32> {
    if pledge_id == 0 || pledge_id > storage::get_u64(KEY_PLEDGE_CNT) {
        return Err(ERR_INVALID_PARAMS);
    }
    let k = pledge_key(pledge_id);
    let mut buf = [0u8; PLEDGE_WIRE_LEN];
    let n = storage::get_into(k.as_slice(), &mut buf).unwrap_or(0);
    if n < PLEDGE_WIRE_LEN {
        return Err(ERR_INVALID_PARAMS);
    }
    Ok(buf)
}

fn save_pledge(pledge_id: u64, buf: &[u8; PLEDGE_WIRE_LEN]) {
    let k = pledge_key(pledge_id);
    storage::set(k.as_slice(), buf);
}

fn handle_hfs_type(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&HFS_TYPE_CROWDFUNDING);
    Ok(())
}

fn handle_accounting_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_associated_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_board_resolution_auth(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_BOARD_AUTH).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_escrow_identity(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_state(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_STATE));
    Ok(())
}

fn handle_spec_hash(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    ret::write_word(&storage::get_bytes32(KEY_SPEC_HASH).unwrap_or([0u8; 32]));
    Ok(())
}

fn handle_hash_activate_campaign(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    ret::write_word(&storage::get_bytes32(KEY_ACT_HASH).unwrap_or([0u8; 32]));
    Ok(())
}

/// Step 1 of Multi-Step Crowdfunding Launch:
/// Links to `accountingLedger` -> resolves & validates `corporateCharter` (`CHARTER_STATE_ACTIVE`),
/// validates Proposer standing on the Charter, locks campaign & IFRS stretch-goal budget terms,
/// and sets `STATE_PENDING_BOARD_RESOLUTION (1)` awaiting Board Resolution enactment.
///
/// `proposeCampaign(
///    address accountingLedger,
///    address escrowIdentity,
///    address rewardVoucherHfs,
///    address bankingOracle,
///    uint64  campaignMode,
///    uint64  baseTargetAmount,
///    uint64  durationBlocks,
///    bytes   title,
///    bytes   packedRewardSkus,
///    bytes   packedBudgetTiers
/// )`
fn handle_propose_campaign(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(ERR_ALREADY_INITIALIZED);
    }

    let accounting_led = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    let escrow_id = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    let rv_hfs = args.address(2).ok_or(ERR_INVALID_PARAMS)?;
    let oracle = args.address(3).ok_or(ERR_INVALID_PARAMS)?;
    let mode = args.u64(4).ok_or(ERR_INVALID_PARAMS)?;
    let base_target = args.u64(5).ok_or(ERR_INVALID_PARAMS)?;
    let duration_blocks = args.u64(6).ok_or(ERR_INVALID_PARAMS)?;
    let title_bytes = args.dynamic_bytes(7).ok_or(ERR_INVALID_PARAMS)?;
    let skus_bytes = args.dynamic_bytes(8).ok_or(ERR_INVALID_PARAMS)?;
    let tiers_bytes = args.dynamic_bytes(9).ok_or(ERR_INVALID_PARAMS)?;

    if accounting_led == [0u8; 20] {
        return Err(ERR_CHARTER_MISMATCH);
    }
    if !(mode == MODE_SINGLE_HARD_CAP
        || mode == MODE_SINGLE_ALL_OR_NOTHING
        || mode == MODE_MULTI_TIER_GROWTH_BUDGET)
    {
        return Err(ERR_INVALID_PARAMS);
    }
    if base_target == 0 || duration_blocks == 0 {
        return Err(ERR_INVALID_PARAMS);
    }

    // 1. Resolve Constitutional Graph directly from `accountingLedger`:
    let chr_cd = CallEncoder::<16>::new(const { selector("associatedCharter()") });
    let charter =
        call_addr(&accounting_led, chr_cd.as_slice()).map_err(|_| ERR_CHARTER_MISMATCH)?;
    if charter == [0u8; 20] {
        return Err(ERR_CHARTER_MISMATCH);
    }
    require_active_charter(&charter)?;

    let reg_cd = CallEncoder::<16>::new(const { selector("identityRegistry()") });
    let registry =
        call_addr(&accounting_led, reg_cd.as_slice()).map_err(|_| ERR_CHARTER_MISMATCH)?;
    if registry == [0u8; 20] {
        return Err(ERR_CHARTER_MISMATCH);
    }

    let hfs_cd = CallEncoder::<16>::new(const { selector("hfsRegistry()") });
    let hfs_reg = call_addr(&accounting_led, hfs_cd.as_slice()).unwrap_or([0u8; 20]);

    let bank_cd = CallEncoder::<16>::new(const { selector("operatingBankLedger()") });
    let bank_led = call_addr(&accounting_led, bank_cd.as_slice()).unwrap_or([0u8; 20]);

    let treas_cd = CallEncoder::<16>::new(const { selector("treasuryIdentity()") });
    let treas_id = call_addr(&accounting_led, treas_cd.as_slice()).unwrap_or([0u8; 20]);

    // 2. Verify Proposer is a valid Identity and an active Director / Officer of `charter`:
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    if !is_charter_officer_or_director(&charter, &caller) {
        return Err(ERR_MISSING_ROLE);
    }

    // 3. Optionally claim exclusive custody of virgin `escrowIdentity` if provided (`KEY_INIT == 0`):
    let me = context::self_address();
    if escrow_id != [0u8; 20] {
        let own_cd = CallEncoder::<16>::new(const { selector("owner()") });
        let already_ours = match call::call_raw(&escrow_id, own_cd.as_slice()) {
            Ok(raw) if raw.len() >= 32 && raw[12..32] == me => true,
            _ => false,
        };
        if !already_ours {
            let hdl = b"cf_escrow";
            let nck = b"Crowdfund Escrow";
            let mut init_cd = [0u8; 260];
            init_cd[0..4]
                .copy_from_slice(&const { selector("initializeWithNickname(address,string,string)") });
            init_cd[16..36].copy_from_slice(&me);
            init_cd[60..68].copy_from_slice(&96u64.to_be_bytes());
            init_cd[92..100].copy_from_slice(&160u64.to_be_bytes());
            init_cd[124..132].copy_from_slice(&(hdl.len() as u64).to_be_bytes());
            init_cd[132..132 + hdl.len()].copy_from_slice(hdl);
            init_cd[188..196].copy_from_slice(&(nck.len() as u64).to_be_bytes());
            init_cd[196..196 + nck.len()].copy_from_slice(nck);
            let _ = call::call_raw(&escrow_id, &init_cd[..228]);
        }
    }

    // 4. Validate & persist Hardware Pre-Order SKUs (`64B` packed each):
    if skus_bytes.is_empty() || skus_bytes.len() % SKU_PACK_IN_LEN != 0 {
        return Err(ERR_INVALID_PARAMS);
    }
    let sku_cnt = skus_bytes.len() / SKU_PACK_IN_LEN;
    if sku_cnt > MAX_REWARD_SKUS {
        return Err(ERR_INVALID_PARAMS);
    }
    let mut s = 0usize;
    while s < sku_cnt {
        let off = s * SKU_PACK_IN_LEN;
        let sku_code = get_u64_be(skus_bytes, off);
        let unit_price = get_u64_be(skus_bytes, off + 8);
        let max_units = get_u64_be(skus_bytes, off + 16);
        let voucher_bps = get_u64_be(skus_bytes, off + 24);
        if sku_code == 0 || unit_price == 0 || max_units == 0 {
            return Err(ERR_INVALID_PARAMS);
        }
        let mut wire = [0u8; SKU_WIRE_LEN];
        put_u64(&mut wire, 0, sku_code);
        put_u64(&mut wire, 8, unit_price);
        put_u64(&mut wire, 16, max_units);
        put_u64(&mut wire, 24, voucher_bps);
        put_u64(&mut wire, 32, 0); // sold_units
        wire[40..72].copy_from_slice(&skus_bytes[off + 32..off + 64]);
        save_sku(s as u64, &wire);
        s += 1;
    }

    // 5. Validate & persist Stretch-Goal IFRS Growth Budget Tiers (`88B` packed each):
    let tier_cnt = if tiers_bytes.is_empty() {
        0
    } else {
        if tiers_bytes.len() % TIER_PACK_IN_LEN != 0 {
            return Err(ERR_INVALID_PARAMS);
        }
        tiers_bytes.len() / TIER_PACK_IN_LEN
    };
    if tier_cnt > MAX_BUDGET_TIERS {
        return Err(ERR_INVALID_PARAMS);
    }
    if mode == MODE_MULTI_TIER_GROWTH_BUDGET && tier_cnt == 0 {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut prev_threshold = 0u64;
    let mut cum_alloc = 0u64;
    let mut t = 0usize;
    while t < tier_cnt {
        let off = t * TIER_PACK_IN_LEN;
        let threshold = get_u64_be(tiers_bytes, off);
        let budget_alloc = get_u64_be(tiers_bytes, off + 8);
        let ifrs_cat = get_u64_be(tiers_bytes, off + 16);
        if threshold == 0 || budget_alloc == 0 || threshold <= prev_threshold {
            return Err(ERR_INVALID_PARAMS);
        }
        if t == 0 && threshold != base_target {
            return Err(ERR_INVALID_PARAMS);
        }
        if !(1..=5).contains(&ifrs_cat) {
            return Err(ERR_INVALID_PARAMS);
        }
        cum_alloc = cum_alloc
            .checked_add(budget_alloc)
            .ok_or(ERR_INVALID_PARAMS)?;
        if cum_alloc > threshold {
            return Err(ERR_INVALID_PARAMS);
        }
        prev_threshold = threshold;

        let mut wire = [0u8; TIER_WIRE_LEN];
        put_u64(&mut wire, 0, threshold);
        put_u64(&mut wire, 8, budget_alloc);
        put_u64(&mut wire, 16, 0); // spent_amount
        put_u64(&mut wire, 24, ifrs_cat);
        put_u64(&mut wire, 32, 0); // unlocked (0 = locked, 1 = unlocked)
        put_u64(&mut wire, 40, 0); // unlocked_at_block
        wire[48..80].copy_from_slice(&tiers_bytes[off + 24..off + 56]); // lineItemCode
        wire[80..112].copy_from_slice(&tiers_bytes[off + 56..off + 88]); // title
        save_tier(t as u64, &wire);
        t += 1;
    }

    let mut clean_title = [0u8; 32];
    let n_title = if title_bytes.len() < 32 {
        title_bytes.len()
    } else {
        32
    };
    clean_title[..n_title].copy_from_slice(&title_bytes[..n_title]);

    let skus_hash = keccak256(skus_bytes);
    let tiers_hash = keccak256(tiers_bytes);
    let spec_hash = ActionHasher::<256>::new(&accounting_led, &ACTION_LAUNCH_CROWDFUNDING)
        .push_address(&charter)
        .push_u64(mode)
        .push_u64(base_target)
        .push_u64(duration_blocks)
        .push_bytes32(&skus_hash)
        .push_bytes32(&tiers_hash)
        .finish();
    let act_hash = ActionHasher::<160>::new(&me, &ACTION_LAUNCH_CROWDFUNDING)
        .push_address(&accounting_led)
        .push_bytes32(&spec_hash)
        .finish();

    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, STATE_PENDING_BOARD_RESOLUTION as u64);
    storage::set_u64(KEY_MODE, mode);
    storage::set_u64(KEY_BASE_TARGET, base_target);
    storage::set_u64(KEY_DURATION_BLKS, duration_blocks);
    storage::set_u64(KEY_DELIVERY_BLKS, duration_blocks.max(120));
    storage::set_u64(KEY_ACTIVATED_BLK, 0);
    storage::set_u64(KEY_DEADLINE_BLK, 0);
    storage::set(KEY_TITLE, &clean_title);
    storage::set(KEY_SPEC_HASH, &spec_hash);
    storage::set(KEY_ACT_HASH, &act_hash);

    storage::set_address(KEY_PROPOSER, &caller);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_HFS_REGISTRY, &hfs_reg);
    storage::set_address(KEY_CHARTER, &charter);
    storage::set_address(KEY_ACCOUNTING, &accounting_led);
    storage::set_address(KEY_BANK_LEDGER, &bank_led);
    storage::set_address(KEY_TREASURY_ID, &treas_id);
    storage::set_address(KEY_ESCROW_ID, &escrow_id);
    storage::set_address(KEY_REWARD_VOUCHER, &rv_hfs);
    storage::set_address(KEY_ORACLE, &oracle);

    storage::set_u64(KEY_SKU_CNT, sku_cnt as u64);
    storage::set_u64(KEY_TIER_CNT, tier_cnt as u64);

    let mut ev = [0u8; 56];
    put_u64(&mut ev, 0, mode);
    put_u64(&mut ev, 8, base_target);
    put_u64(&mut ev, 16, duration_blocks);
    ev[24..56].copy_from_slice(&act_hash);
    events::emit(
        &[
            EV_PROPOSED,
            addr_topic(&accounting_led),
            addr_topic(&charter),
            addr_topic(&caller),
        ],
        &ev,
    );

    ret::write_word(&act_hash);
    Ok(())
}

/// Pins the newly triggered `CorporateCharter` `BOARD_RESOLUTION` (`Authorization` HFS) onto this
/// pending crowdfunding campaign so Directors, Auditors, and UI clients can discover and track the
/// active Board vote directly from `Crowdfunding.boardResolutionAuth()`.
fn handle_bind_board_resolution(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_ALREADY_ACTIVATED);
    }
    let auth_obj = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    if auth_obj == [0u8; 20] {
        return Err(ERR_INVALID_PARAMS);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(ERR_NOT_INITIALIZED)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(ERR_NOT_INITIALIZED)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    if !is_charter_officer_or_director(&charter, &caller) {
        return Err(ERR_MISSING_ROLE);
    }
    require_valid_authorization_hps(&registry, &auth_obj)?;

    // Verify `auth_obj.charter() == charter` when `charter()` is exposed
    let chr_cd = CallEncoder::<16>::new(const { selector("charter()") });
    if let Ok(auth_chr) = call_addr(&auth_obj, chr_cd.as_slice()) {
        if auth_chr != [0u8; 20] && auth_chr != charter {
            return Err(ERR_BOARD_AUTH_MISMATCH);
        }
    }

    storage::set_address(KEY_BOARD_AUTH, &auth_obj);
    let act_hash = storage::get_bytes32(KEY_ACT_HASH).unwrap_or([0u8; 32]);
    events::emit(
        &[
            EV_BOARD_RES_BOUND,
            addr_topic(&charter),
            addr_topic(&auth_obj),
        ],
        &act_hash,
    );
    ret::write_bool(true);
    Ok(())
}

fn transition_to_live_state(auth_obj: &[u8; 20], via_accounting: bool) {
    let now = context::block_number();
    let dur = storage::get_u64(KEY_DURATION_BLKS);
    let deadline = now.saturating_add(dur);
    storage::set_address(KEY_BOARD_AUTH, auth_obj);
    storage::set_u64(KEY_ACTIVATED_BLK, now);
    storage::set_u64(KEY_DEADLINE_BLK, deadline);
    storage::set_u64(KEY_RATIFIED_VIA_ACC, u64::from(via_accounting));
    storage::set_u64(KEY_STATE, STATE_LIVE as u64);

    let charter = storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]);
    let mut ev = [0u8; 16];
    put_u64(&mut ev, 0, now);
    put_u64(&mut ev, 8, deadline);
    events::emit(
        &[
            EV_ACTIVATED_LIVE,
            addr_topic(&charter),
            addr_topic(auth_obj),
        ],
        &ev,
    );
}

/// Step 3A — Direct Board Resolution Enactment on `Crowdfunding`:
/// Consumes a passed `CorporateCharter` `BOARD_RESOLUTION` (`auth_obj`) committed to
/// `hashActivateCampaign()` and sets `STATE_LIVE (2)`.
fn handle_activate_campaign(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_ALREADY_ACTIVATED);
    }
    let auth_obj = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    let registry = storage::get_address(KEY_REGISTRY).ok_or(ERR_NOT_INITIALIZED)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(ERR_NOT_INITIALIZED)?;
    require_active_charter(&charter)?;

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let req_pol = query_charter_function_auth(&charter, &me, &SEL_ACTIVATE_CAMPAIGN)
        .unwrap_or(POLICY_BOARD_RESOLUTION);
    let act_hash = storage::get_bytes32(KEY_ACT_HASH).ok_or(ERR_NOT_INITIALIZED)?;

    verify_and_consume_auth(&registry, &auth_obj, &charter, &req_pol, &act_hash, &caller)?;
    transition_to_live_state(&auth_obj, false);
    ret::write_bool(true);
    Ok(())
}

/// Step 3B — Enactment Callback from `AccountingLedger.activateCrowdfundingCampaign`:
/// Invoked exclusively by the pinned `accountingLedger` immediately after `AccountingLedger`
/// verifies and consumes the `CorporateCharter` `BOARD_RESOLUTION`. Sets `STATE_LIVE (2)`.
fn handle_on_board_resolution_activated(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_ALREADY_ACTIVATED);
    }
    let accounting_led = storage::get_address(KEY_ACCOUNTING).ok_or(ERR_NOT_INITIALIZED)?;
    if context::msg_sender() != accounting_led {
        return Err(ERR_UNAUTHORIZED);
    }
    let auth_obj = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    let _invoker = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    transition_to_live_state(&auth_obj, true);
    ret::write_bool(true);
    Ok(())
}

fn evaluate_stretch_tier_unlocks(new_total_committed: u64) {
    let tier_cnt = storage::get_u64(KEY_TIER_CNT);
    if tier_cnt == 0 {
        return;
    }
    let now_blk = context::block_number();
    let mut unl_cnt = storage::get_u64(KEY_UNLOCKED_TIER_CNT);
    let mut tot_bunl = storage::get_u64(KEY_TOT_BUDGET_UNLOCKED);

    let mut i = 0u64;
    while i < tier_cnt {
        if let Ok(mut wire) = load_tier(i) {
            let threshold = get_u64_be(&wire, 0);
            let alloc = get_u64_be(&wire, 8);
            let spent = get_u64_be(&wire, 16);
            let is_unlocked = get_u64_be(&wire, 32) == 1;
            if !is_unlocked && new_total_committed >= threshold {
                put_u64(&mut wire, 32, 1);
                put_u64(&mut wire, 40, now_blk);
                save_tier(i, &wire);
                unl_cnt = unl_cnt.saturating_add(1);
                tot_bunl = tot_bunl.saturating_add(alloc);

                let mut code = [0u8; 32];
                code.copy_from_slice(&wire[48..80]);
                let ifrs_cat = get_u64_be(&wire, 24);
                let mut ev = [0u8; 24];
                put_u64(&mut ev, 0, threshold);
                put_u64(&mut ev, 8, alloc);
                put_u64(&mut ev, 16, ifrs_cat);
                events::emit(&[EV_BUDGET_UNLOCKED, u64_topic(i), code], &ev);
            } else if is_unlocked && spent == 0 && new_total_committed < threshold {
                put_u64(&mut wire, 32, 0);
                put_u64(&mut wire, 40, 0);
                save_tier(i, &wire);
                unl_cnt = unl_cnt.saturating_sub(1);
                tot_bunl = tot_bunl.saturating_sub(alloc);
            }
        }
        i += 1;
    }
    storage::set_u64(KEY_UNLOCKED_TIER_CNT, unl_cnt);
    storage::set_u64(KEY_TOT_BUDGET_UNLOCKED, tot_bunl);
}

fn record_pledge_common(
    backer: [u8; 20],
    sku_idx: u64,
    quantity: u64,
    rail: u8,
    status: u8,
    payment_ref_hash: [u8; 32],
    voucher_commitment: [u8; 32],
) -> Result<(u64, u64), i32> {
    require_init()?;
    let st = get_state();
    if st == STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_AWAITING_BOARD_ACTIVATION);
    }
    if st != STATE_LIVE {
        return Err(ERR_CAMPAIGN_NOT_LIVE);
    }
    let now_blk = context::block_number();
    let deadline = storage::get_u64(KEY_DEADLINE_BLK);
    if now_blk > deadline {
        return Err(ERR_DEADLINE_PASSED);
    }
    if quantity == 0 || sku_idx >= storage::get_u64(KEY_SKU_CNT) {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut sku = load_sku(sku_idx)?;
    let unit_price = get_u64_be(&sku, 8);
    let max_units = get_u64_be(&sku, 16);
    let sold_units = get_u64_be(&sku, 32);

    let new_sold = sold_units
        .checked_add(quantity)
        .ok_or(ERR_INVALID_PARAMS)?;
    if new_sold > max_units {
        return Err(ERR_SKU_SOLD_OUT);
    }

    let amount = unit_price
        .checked_mul(quantity)
        .ok_or(ERR_INVALID_PARAMS)?;
    let mode = storage::get_u64(KEY_MODE);
    let base_target = storage::get_u64(KEY_BASE_TARGET);
    let prev_committed = storage::get_u64(KEY_TOT_COMMITTED);
    let new_committed = prev_committed
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;

    if mode == MODE_SINGLE_HARD_CAP && new_committed > base_target {
        return Err(ERR_TARGET_CAP_EXCEEDED);
    }

    put_u64(&mut sku, 32, new_sold);
    save_sku(sku_idx, &sku);

    let pledge_id = storage::get_u64(KEY_PLEDGE_CNT)
        .checked_add(1)
        .ok_or(ERR_INVALID_PARAMS)?;
    let mut p_wire = [0u8; PLEDGE_WIRE_LEN];
    put_u64(&mut p_wire, 0, pledge_id);
    p_wire[8..28].copy_from_slice(&backer);
    put_u64(&mut p_wire, 32, sku_idx);
    put_u64(&mut p_wire, 40, quantity);
    put_u64(&mut p_wire, 48, amount);
    p_wire[56] = rail;
    p_wire[57] = status;
    p_wire[58] = 0; // voucher_issued
    p_wire[64..96].copy_from_slice(&payment_ref_hash);
    p_wire[96..128].copy_from_slice(&voucher_commitment);
    save_pledge(pledge_id, &p_wire);

    storage::set_u64(KEY_PLEDGE_CNT, pledge_id);
    storage::set_u64(KEY_TOT_COMMITTED, new_committed);

    evaluate_stretch_tier_unlocks(new_committed);

    let mut ev = [0u8; 32];
    put_u64(&mut ev, 0, sku_idx);
    put_u64(&mut ev, 8, quantity);
    put_u64(&mut ev, 16, amount);
    put_u64(&mut ev, 24, rail as u64);
    events::emit(
        &[
            EV_PLEDGE_RECORDED,
            u64_topic(pledge_id),
            addr_topic(&backer),
        ],
        &ev,
    );

    Ok((pledge_id, amount))
}

/// On-chain pre-order pledge (`pledgeOnChain(uint64 skuIndex, uint64 quantity, bytes32 voucherCommitment)`):
/// Verifies inbound escrow deposit in `escrowIdentity` (or executes `charterModuleClearTransfer`)
/// and records a 100%-refundable pledge once the campaign is `STATE_LIVE (2)`.
fn handle_pledge_onchain(args: &CalldataReader) -> Result<(), i32> {
    let sku_idx = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let qty = args.u64(1).ok_or(ERR_INVALID_PARAMS)?;
    let commitment = args.bytes32(2).ok_or(ERR_INVALID_PARAMS)?;
    let caller = context::msg_sender();
    if caller == [0u8; 20] {
        return Err(ERR_UNAUTHORIZED);
    }

    let registry = storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]);
    if registry != [0u8; 20] {
        require_valid_identity(&registry, &caller)?;
    }

    // Check state & deadline before checking bank balances so `-26` / `-20` surface cleanly
    let st = get_state();
    if st == STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_AWAITING_BOARD_ACTIVATION);
    }
    if st != STATE_LIVE {
        return Err(ERR_CAMPAIGN_NOT_LIVE);
    }

    let sku = load_sku(sku_idx)?;
    let unit_price = get_u64_be(&sku, 8);
    let expected_amt = unit_price.checked_mul(qty).ok_or(ERR_INVALID_PARAMS)?;

    let bank_led = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
    let esc_id = storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]);
    let prev_esc = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN);

    if bank_led != [0u8; 20] {
        if esc_id != [0u8; 20] {
            let bal_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                .push_address(&esc_id);
            let live_bal = call::call_u64(&bank_led, bal_cd.as_slice())?;
            let req_bal = prev_esc.checked_add(expected_amt).ok_or(ERR_INVALID_PARAMS)?;
            if live_bal < req_bal {
                return Err(ERR_ESCROW_SHORTFALL);
            }
        } else {
            let me = context::self_address();
            let enc = CallEncoder::<100>::new(SEL_CHARTER_CLEAR_TRANSFER)
                .push_address(&caller)
                .push_address(&me)
                .push_u64(expected_amt);
            call::call_raw(&bank_led, enc.as_slice()).map_err(|_| ERR_SUBCALL_FAILED)?;
        }
    }

    let (pledge_id, amount) = record_pledge_common(
        caller,
        sku_idx,
        qty,
        RAIL_ONCHAIN_ESCROW,
        PLEDGE_ESCROWED_ONCHAIN,
        [0u8; 32],
        commitment,
    )?;

    storage::set_u64(
        KEY_TOT_ESCROW_ONCHAIN,
        prev_esc.saturating_add(amount),
    );
    ret::write_u64_word(pledge_id);
    Ok(())
}

/// Off-chain credit-card / PayNow pre-authorization hold registered by `banking-oracle`
/// (`$0` charged until campaign reaches target).
fn handle_record_oracle_hold(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_oracle_or_officer()?;
    let ref_hash = args.bytes32(0).ok_or(ERR_INVALID_PARAMS)?;
    let sku_idx = args.u64(1).ok_or(ERR_INVALID_PARAMS)?;
    let qty = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let commitment = args.bytes32(3).ok_or(ERR_INVALID_PARAMS)?;
    if ref_hash == [0u8; 32] {
        return Err(ERR_INVALID_PARAMS);
    }
    let rk = ref_used_key(&ref_hash);
    if storage::get_u64(rk.as_slice()) == 1 {
        return Err(ERR_DUPLICATE_PAYMENT_REF);
    }

    let (pledge_id, amount) = record_pledge_common(
        [0u8; 20],
        sku_idx,
        qty,
        RAIL_ORACLE_PREAUTH_HOLD,
        PLEDGE_PREAUTH_HOLD_ORACLE,
        ref_hash,
        commitment,
    )?;
    storage::set_u64(rk.as_slice(), 1);
    storage::set_u64(
        KEY_TOT_PREAUTH_ORACLE,
        storage::get_u64(KEY_TOT_PREAUTH_ORACLE).saturating_add(amount),
    );
    ret::write_u64_word(pledge_id);
    Ok(())
}

/// Off-chain Airwallex credit-authorization hold bound explicitly to the buyer's `Identity` HFS (`backer`),
/// enabling trustless buyer self-cancellation (`cancelPreorderAuthorization`) anytime prior to card capture!
fn handle_record_oracle_hold_for_backer(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_oracle_or_officer()?;
    let backer = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    let ref_hash = args.bytes32(1).ok_or(ERR_INVALID_PARAMS)?;
    let sku_idx = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let qty = args.u64(3).ok_or(ERR_INVALID_PARAMS)?;
    let commitment = args.bytes32(4).ok_or(ERR_INVALID_PARAMS)?;
    if ref_hash == [0u8; 32] {
        return Err(ERR_INVALID_PARAMS);
    }
    let rk = ref_used_key(&ref_hash);
    if storage::get_u64(rk.as_slice()) == 1 {
        return Err(ERR_DUPLICATE_PAYMENT_REF);
    }

    let (pledge_id, amount) = record_pledge_common(
        backer,
        sku_idx,
        qty,
        RAIL_ORACLE_PREAUTH_HOLD,
        PLEDGE_PREAUTH_HOLD_ORACLE,
        ref_hash,
        commitment,
    )?;
    storage::set_u64(rk.as_slice(), 1);
    storage::set_u64(
        KEY_TOT_PREAUTH_ORACLE,
        storage::get_u64(KEY_TOT_PREAUTH_ORACLE).saturating_add(amount),
    );
    ret::write_u64_word(pledge_id);
    Ok(())
}

/// Cancels a credit-card authorization hold (`PLEDGE_PREAUTH_HOLD_ORACLE = 2`) **anytime prior to capture**.
/// - Allowed for the recorded `backer` (`caller == backer`) OR `banking-oracle` / company officer.
/// - Strictly REVERTS with `ERR_ALREADY_CHARGED_NO_USER_CANCEL = -43` once the card has been charged
///   (`status == PLEDGE_FINALIZED_CAPTURED = 3`), enforcing that post-charge refunds are at the sole
///   discretion of the company (`grantDiscretionaryRefund`).
fn handle_cancel_preorder_auth(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut p = load_pledge(pledge_id)?;
    let status = p[57];
    if status == PLEDGE_FINALIZED_CAPTURED {
        return Err(ERR_ALREADY_CHARGED_NO_USER_CANCEL);
    }
    if status != PLEDGE_PREAUTH_HOLD_ORACLE {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let mut backer = [0u8; 20];
    backer.copy_from_slice(&p[8..28]);
    let caller = context::msg_sender();
    let is_backer_caller = backer != [0u8; 20] && caller == backer;
    if !is_backer_caller {
        let _ = require_oracle_or_officer()?;
    }

    let sku_idx = get_u64_be(&p, 32);
    let qty = get_u64_be(&p, 40);
    let amount = get_u64_be(&p, 48);

    if let Ok(mut sku) = load_sku(sku_idx) {
        let sold = get_u64_be(&sku, 32);
        put_u64(&mut sku, 32, sold.saturating_sub(qty));
        save_sku(sku_idx, &sku);
    }

    let new_committed = storage::get_u64(KEY_TOT_COMMITTED).saturating_sub(amount);
    storage::set_u64(KEY_TOT_COMMITTED, new_committed);
    storage::set_u64(
        KEY_TOT_PREAUTH_ORACLE,
        storage::get_u64(KEY_TOT_PREAUTH_ORACLE).saturating_sub(amount),
    );
    if get_state() == STATE_LIVE {
        evaluate_stretch_tier_unlocks(new_committed);
    }

    p[57] = PLEDGE_REFUNDED_OR_VOIDED;
    save_pledge(pledge_id, &p);
    storage::set_u64(
        KEY_TOT_REFUNDED,
        storage::get_u64(KEY_TOT_REFUNDED).saturating_add(amount),
    );
    events::emit(
        &[
            EV_PLEDGE_REFUNDED,
            u64_topic(pledge_id),
            addr_topic(&backer),
        ],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(amount);
    Ok(())
}

/// Post-capture case-by-case refund strictly at the sole discretion of the company
/// (`require_oracle_or_officer()`). Backers cannot invoke this directly.
fn handle_grant_discretionary_refund(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let _ = require_oracle_or_officer()?;
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut p = load_pledge(pledge_id)?;
    if p[57] != PLEDGE_FINALIZED_CAPTURED {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }
    let mut backer = [0u8; 20];
    backer.copy_from_slice(&p[8..28]);
    let sku_idx = get_u64_be(&p, 32);
    let qty = get_u64_be(&p, 40);
    let amount = get_u64_be(&p, 48);

    if let Ok(mut sku) = load_sku(sku_idx) {
        let sold = get_u64_be(&sku, 32);
        put_u64(&mut sku, 32, sold.saturating_sub(qty));
        save_sku(sku_idx, &sku);
    }

    p[57] = PLEDGE_REFUNDED_OR_VOIDED;
    save_pledge(pledge_id, &p);
    storage::set_u64(
        KEY_TOT_CAPTURED_ORACLE,
        storage::get_u64(KEY_TOT_CAPTURED_ORACLE).saturating_sub(amount),
    );
    storage::set_u64(
        KEY_TOT_REFUNDED,
        storage::get_u64(KEY_TOT_REFUNDED).saturating_add(amount),
    );
    events::emit(
        &[
            EV_PLEDGE_REFUNDED,
            u64_topic(pledge_id),
            addr_topic(&backer),
        ],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(amount);
    Ok(())
}

/// Confirms bank settlement capture of a pre-authorized hold after campaign success.
fn handle_confirm_oracle_captured(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_oracle_or_officer()?;
    if get_state() != STATE_SETTLED_SUCCEEDED {
        return Err(ERR_CAMPAIGN_NOT_SUCCEEDED);
    }
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut p = load_pledge(pledge_id)?;
    if p[57] != PLEDGE_PREAUTH_HOLD_ORACLE {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }
    let amount = get_u64_be(&p, 48);
    p[57] = PLEDGE_FINALIZED_CAPTURED;
    save_pledge(pledge_id, &p);

    storage::set_u64(
        KEY_TOT_PREAUTH_ORACLE,
        storage::get_u64(KEY_TOT_PREAUTH_ORACLE).saturating_sub(amount),
    );
    storage::set_u64(
        KEY_TOT_CAPTURED_ORACLE,
        storage::get_u64(KEY_TOT_CAPTURED_ORACLE).saturating_add(amount),
    );
    ret::write_u64_word(1);
    Ok(())
}

/// Finalizes a `STATE_LIVE (2)` campaign:
/// - If `totalCommitted >= baseTarget`: transitions to `STATE_SETTLED_SUCCEEDED (3)`, sweeps on-chain
///   escrowed proceeds into `AccountingLedger`'s `treasuryIdentity`, and books `Dr 1010 Cash /
///   Cr 2300 Contract Liabilities (IFRS 15 Pre-Order Unearned Revenue)` on `AccountingLedger`!
/// - If `now > deadline` and `totalCommitted < baseTarget`: transitions to `STATE_FAILED_REFUNDABLE (4)`
///   so **no-one is charged** (100% escrow refunds open and card holds voided without capture).
fn handle_finalize_campaign(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let st = get_state();
    if st == STATE_PENDING_BOARD_RESOLUTION {
        return Err(ERR_AWAITING_BOARD_ACTIVATION);
    }
    if st != STATE_LIVE {
        return Err(ERR_CAMPAIGN_NOT_LIVE);
    }

    let now_blk = context::block_number();
    let deadline = storage::get_u64(KEY_DEADLINE_BLK);
    let committed = storage::get_u64(KEY_TOT_COMMITTED);
    let base_target = storage::get_u64(KEY_BASE_TARGET);

    let new_state = if committed >= base_target {
        evaluate_stretch_tier_unlocks(committed);
        sweep_escrow_into_accounting_ledger()?;
        STATE_SETTLED_SUCCEEDED
    } else {
        if now_blk <= deadline {
            return Err(ERR_DEADLINE_NOT_REACHED);
        }
        storage::set_u64(KEY_UNLOCKED_TIER_CNT, 0);
        storage::set_u64(KEY_TOT_BUDGET_UNLOCKED, 0);
        STATE_FAILED_REFUNDABLE
    };

    storage::set_u64(KEY_STATE, new_state as u64);
    let unl_budget = storage::get_u64(KEY_TOT_BUDGET_UNLOCKED);
    let mut ev = [0u8; 16];
    put_u64(&mut ev, 0, committed);
    put_u64(&mut ev, 8, unl_budget);
    events::emit(&[EV_CAMPAIGN_FINALIZED, u64_topic(new_state as u64)], &ev);
    ret::write_u64_word(new_state as u64);
    Ok(())
}

fn sweep_escrow_into_accounting_ledger() -> Result<(), i32> {
    let esc_total = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN);
    if esc_total == 0 || storage::get_u64(KEY_SWEPT_TO_TREASURY) == 1 {
        return Ok(());
    }
    let bank_led = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
    let treas_id = storage::get_address(KEY_TREASURY_ID).unwrap_or([0u8; 20]);
    let esc_id = storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]);
    let acc_led = storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]);
    let deliv_blks = storage::get_u64(KEY_DELIVERY_BLKS).max(120);

    let mut plan_code = [0u8; 32];
    plan_code[0..8].copy_from_slice(b"CF-PREOR");

    if bank_led != [0u8; 20] && treas_id != [0u8; 20] && esc_id != [0u8; 20] {
        // 1. Transfer escrowed cash from `escrowIdentity` -> `treasuryIdentity`
        let xfer_cd = CallEncoder::<128>::new(const {
            selector("transferBankBalance(address,address,uint64)")
        })
        .push_address(&bank_led)
        .push_address(&treas_id)
        .push_u64(esc_total);
        let ok = call::call_bool(&esc_id, xfer_cd.as_slice())?;
        if !ok {
            return Err(ERR_SUBCALL_FAILED);
        }

        // 2. Book `Dr 1010 Cash / Cr 2300 Contract Liabilities (IFRS 15)` on `AccountingLedger`
        if storage::get_u64(KEY_RATIFIED_VIA_ACC) == 1 {
            let bk_cd = CallEncoder::<128>::new(const {
                selector("bookCrowdfundingProceedsFromCampaign(bytes32,uint64,uint64)")
            })
            .push_bytes32(&plan_code)
            .push_u64(deliv_blks)
            .push_u64(esc_total);
            let _ = call::call_raw(&acc_led, bk_cd.as_slice())?;
        } else {
            // Compatible with pre-existing `AccountingLedger` instances via `escrowIdentity.execute(accountingLedger, purchaseSubscription(...))`
            let mut inner = [0u8; 100];
            inner[0..4]
                .copy_from_slice(&const { selector("purchaseSubscription(bytes32,uint64,uint64)") });
            inner[4..36].copy_from_slice(&plan_code);
            put_u64(&mut inner, 60, deliv_blks);
            put_u64(&mut inner, 92, esc_total);

            let mut outer = [0u8; 228];
            outer[0..4].copy_from_slice(&const { selector("execute(address,bytes)") });
            outer[16..36].copy_from_slice(&acc_led);
            put_u64(&mut outer, 60, 64);
            put_u64(&mut outer, 92, 100);
            outer[100..200].copy_from_slice(&inner);
            let _ = call::call_raw(&esc_id, &outer[..228])?;
        }
        storage::set_u64(KEY_SWEPT_TO_TREASURY, 1);
    } else if storage::get_u64(KEY_RATIFIED_VIA_ACC) == 1 && acc_led != [0u8; 20] {
        // Unit-test / virtual bank path when `AccountingLedger` ratified this campaign directly
        if bank_led != [0u8; 20] && treas_id != [0u8; 20] {
            let me = context::self_address();
            let enc = CallEncoder::<100>::new(SEL_CHARTER_CLEAR_TRANSFER)
                .push_address(&me)
                .push_address(&treas_id)
                .push_u64(esc_total);
            let _ = call::call_raw(&bank_led, enc.as_slice());
        }
        let bk_cd = CallEncoder::<128>::new(const {
            selector("bookCrowdfundingProceedsFromCampaign(bytes32,uint64,uint64)")
        })
        .push_bytes32(&plan_code)
        .push_u64(deliv_blks)
        .push_u64(esc_total);
        let _ = call::call_raw(&acc_led, bk_cd.as_slice());
        storage::set_u64(KEY_SWEPT_TO_TREASURY, 1);
    }
    Ok(())
}

/// 100% trustless refund / hold void when target is missed (`STATE_FAILED_REFUNDABLE = 4`).
fn handle_claim_refund(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_FAILED_REFUNDABLE {
        return Err(ERR_CAMPAIGN_NOT_FAILED);
    }
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut p = load_pledge(pledge_id)?;
    let status = p[57];
    if !(status == PLEDGE_ESCROWED_ONCHAIN || status == PLEDGE_PREAUTH_HOLD_ORACLE) {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let mut backer = [0u8; 20];
    backer.copy_from_slice(&p[8..28]);
    let amount = get_u64_be(&p, 48);

    if status == PLEDGE_ESCROWED_ONCHAIN {
        let caller = context::msg_sender();
        let charter = storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]);
        if caller != backer && !is_charter_officer_or_director(&charter, &caller) {
            return Err(ERR_UNAUTHORIZED);
        }
        let bank_led = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
        let esc_id = storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]);
        if bank_led != [0u8; 20] {
            if esc_id != [0u8; 20] {
                let xfer_cd = CallEncoder::<128>::new(const {
                    selector("transferBankBalance(address,address,uint64)")
                })
                .push_address(&bank_led)
                .push_address(&backer)
                .push_u64(amount);
                let ok = call::call_bool(&esc_id, xfer_cd.as_slice())?;
                if !ok {
                    return Err(ERR_SUBCALL_FAILED);
                }
            } else {
                let me = context::self_address();
                let enc = CallEncoder::<100>::new(SEL_CHARTER_CLEAR_TRANSFER)
                    .push_address(&me)
                    .push_address(&backer)
                    .push_u64(amount);
                call::call_raw(&bank_led, enc.as_slice()).map_err(|_| ERR_SUBCALL_FAILED)?;
            }
        }
        storage::set_u64(
            KEY_TOT_ESCROW_ONCHAIN,
            storage::get_u64(KEY_TOT_ESCROW_ONCHAIN).saturating_sub(amount),
        );
    } else {
        let _ = require_oracle_or_officer()?;
        storage::set_u64(
            KEY_TOT_PREAUTH_ORACLE,
            storage::get_u64(KEY_TOT_PREAUTH_ORACLE).saturating_sub(amount),
        );
    }

    p[57] = PLEDGE_REFUNDED_OR_VOIDED;
    save_pledge(pledge_id, &p);
    storage::set_u64(
        KEY_TOT_REFUNDED,
        storage::get_u64(KEY_TOT_REFUNDED).saturating_add(amount),
    );
    events::emit(
        &[
            EV_PLEDGE_REFUNDED,
            u64_topic(pledge_id),
            addr_topic(&backer),
        ],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(amount);
    Ok(())
}

/// Mints a blinded 90-day hardware-gated `SLXR` voucher on `RewardVoucher` HFS after settlement.
fn handle_issue_backer_voucher(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_SETTLED_SUCCEEDED {
        return Err(ERR_CAMPAIGN_NOT_SUCCEEDED);
    }
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut p = load_pledge(pledge_id)?;
    let status = p[57];
    if !(status == PLEDGE_ESCROWED_ONCHAIN || status == PLEDGE_FINALIZED_CAPTURED) {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }
    if p[58] == 1 {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&p[96..128]);
    if commitment == [0u8; 32] {
        return Err(ERR_INVALID_PARAMS);
    }

    let sku_idx = get_u64_be(&p, 32);
    let amount = get_u64_be(&p, 48);
    let sku = load_sku(sku_idx)?;
    let sku_code = get_u64_be(&sku, 0);
    let tier_bps = get_u64_be(&sku, 24);

    let mut pay_ref = [0u8; 32];
    pay_ref.copy_from_slice(&p[64..96]);
    if pay_ref == [0u8; 32] {
        pay_ref = keccak256(&p[0..56]);
    }

    let rv_hfs = storage::get_address(KEY_REWARD_VOUCHER).unwrap_or([0u8; 20]);
    if rv_hfs != [0u8; 20] {
        let enc = CallEncoder::<164>::new(SEL_ISSUE_PAID_VOUCHER)
            .push_bytes32(&commitment)
            .push_u64(sku_code)
            .push_u64(tier_bps)
            .push_u64(amount)
            .push_bytes32(&pay_ref);
        call::call_raw(&rv_hfs, enc.as_slice()).map_err(|_| ERR_SUBCALL_FAILED)?;
    }

    p[58] = 1;
    save_pledge(pledge_id, &p);
    events::emit(
        &[
            EV_BACKER_VOUCHER_ISSUED,
            u64_topic(pledge_id),
            commitment,
        ],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(1);
    Ok(())
}

fn compute_disburse_budget_hash(
    tier_idx: u64,
    vendor: &[u8; 20],
    amount: u64,
    expense_ref: &[u8; 32],
) -> [u8; 32] {
    ActionHasher::<256>::new(&context::self_address(), &ACTION_DISBURSE_CROWDFUND_BUDGET)
        .push_u64(tier_idx)
        .push_address(vendor)
        .push_u64(amount)
        .push_bytes32(expense_ref)
        .finish()
}

fn handle_hash_disburse_budget(args: &CalldataReader) -> Result<(), i32> {
    let tier_idx = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let vendor = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    let amount = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let expense_ref = args.bytes32(3).ok_or(ERR_INVALID_PARAMS)?;
    ret::write_word(&compute_disburse_budget_hash(
        tier_idx,
        &vendor,
        amount,
        &expense_ref,
    ));
    Ok(())
}

/// Governed disbursement from an unlocked stretch-goal corporate growth budget line item:
/// `disburseUnlockedBudgetLine(uint64 tierIndex, address vendorIdentity, uint64 amount, bytes32 expenseRefHash, address authHps)`
fn handle_disburse_budget(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_SETTLED_SUCCEEDED {
        return Err(ERR_CAMPAIGN_NOT_SUCCEEDED);
    }
    let tier_idx = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let vendor = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    let amount = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let expense_ref = args.bytes32(3).ok_or(ERR_INVALID_PARAMS)?;
    let auth_hps = args.address(4).ok_or(ERR_INVALID_PARAMS)?;

    if amount == 0 || vendor == [0u8; 20] || tier_idx >= storage::get_u64(KEY_TIER_CNT) {
        return Err(ERR_INVALID_PARAMS);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(ERR_NOT_INITIALIZED)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(ERR_NOT_INITIALIZED)?;
    require_active_charter(&charter)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, &SEL_DISBURSE_BUDGET);
    let action_hash = compute_disburse_budget_hash(tier_idx, &vendor, amount, &expense_ref);

    if auth_hps != [0u8; 20] {
        let req_pol = explicit_pol.unwrap_or(POLICY_BOARD_RESOLUTION);
        verify_and_consume_auth(&registry, &auth_hps, &charter, &req_pol, &action_hash, &caller)?;
    } else {
        if let Some(pol) = explicit_pol {
            if pol != POLICY_ACCOUNTING_OPS {
                return Err(ERR_UNAUTHORIZED);
            }
        }
        if !is_charter_officer_or_director(&charter, &caller) {
            return Err(ERR_MISSING_ROLE);
        }
    }

    let mut tier = load_tier(tier_idx)?;
    let is_unlocked = get_u64_be(&tier, 32) == 1;
    if !is_unlocked {
        return Err(ERR_BUDGET_TIER_LOCKED);
    }
    let alloc = get_u64_be(&tier, 8);
    let prev_spent = get_u64_be(&tier, 16);
    let new_tier_spent = prev_spent
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;
    if new_tier_spent > alloc {
        return Err(ERR_BUDGET_LINE_EXCEEDED);
    }
    let ifrs_cat = get_u64_be(&tier, 24);

    let realized_cash = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN)
        .saturating_add(storage::get_u64(KEY_TOT_CAPTURED_ORACLE));
    let new_tot_spent = storage::get_u64(KEY_TOT_BUDGET_SPENT)
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;
    if new_tot_spent > realized_cash {
        return Err(ERR_INSUFFICIENT_REALIZED_CASH);
    }

    let acc_led = storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]);
    if storage::get_u64(KEY_RATIFIED_VIA_ACC) == 1 && acc_led != [0u8; 20] {
        let disb_cd = CallEncoder::<160>::new(const {
            selector("bookCrowdfundingBudgetDisbursement(address,uint64,uint64,bytes32)")
        })
        .push_address(&vendor)
        .push_u64(ifrs_cat)
        .push_u64(amount)
        .push_bytes32(&expense_ref);
        call::call_raw(&acc_led, disb_cd.as_slice()).map_err(|_| ERR_SUBCALL_FAILED)?;
    }

    put_u64(&mut tier, 16, new_tier_spent);
    save_tier(tier_idx, &tier);
    storage::set_u64(KEY_TOT_BUDGET_SPENT, new_tot_spent);

    let mut ev = [0u8; 48];
    put_u64(&mut ev, 0, amount);
    put_u64(&mut ev, 8, new_tier_spent);
    ev[16..48].copy_from_slice(&expense_ref);
    events::emit(
        &[
            EV_BUDGET_DISBURSED,
            u64_topic(tier_idx),
            addr_topic(&vendor),
        ],
        &ev,
    );
    ret::write_u64_word(new_tier_spent);
    Ok(())
}

/// Compact 320-byte snapshot (`getCampaignSummary()`):
/// - `[0..8]`:     `state` (`1=PENDING_BOARD_RESOLUTION, 2=LIVE, 3=SETTLED_SUCCEEDED, 4=FAILED_REFUNDABLE`)
/// - `[8..16]`:    `mode` (`1=SINGLE_HARD_CAP, 2=SINGLE_ALL_OR_NOTHING, 3=MULTI_TIER_GROWTH_BUDGET`)
/// - `[16..24]`:   `baseTarget`
/// - `[24..32]`:   `durationBlocks`
/// - `[32..40]`:   `activatedAtBlock`
/// - `[40..48]`:   `deadlineBlock`
/// - `[48..56]`:   `totalCommitted`
/// - `[56..64]`:   `totalEscrowedOnChain`
/// - `[64..72]`:   `totalPreauthOracle`
/// - `[72..80]`:   `totalCapturedOracle`
/// - `[80..88]`:   `totalRefunded`
/// - `[88..96]`:   `totalBudgetUnlocked`
/// - `[96..104]`:  `totalBudgetSpent`
/// - `[104..112]`: `pledgeCount`
/// - `[112..120]`: `skuCount`
/// - `[120..128]`: `tierCount`
/// - `[128..136]`: `unlockedTierCount`
/// - `[136..168]`: `title` (32B UTF-8)
/// - `[168..188]`: `accountingLedger` (20B)
/// - `[188..208]`: `corporateCharter` (20B)
/// - `[208..228]`: `boardResolutionAuth` (20B)
/// - `[228..248]`: `escrowIdentity` (20B)
/// - `[248..280]`: `specHash` (32B)
/// - `[280..312]`: `activateActionHash` (32B)
/// - `[312..320]`: `sweptToTreasury` (`0` or `1`)
fn handle_get_summary(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; SUMMARY_WIRE_LEN];
    put_u64(&mut out, 0, storage::get_u64(KEY_STATE));
    put_u64(&mut out, 8, storage::get_u64(KEY_MODE));
    put_u64(&mut out, 16, storage::get_u64(KEY_BASE_TARGET));
    put_u64(&mut out, 24, storage::get_u64(KEY_DURATION_BLKS));
    put_u64(&mut out, 32, storage::get_u64(KEY_ACTIVATED_BLK));
    put_u64(&mut out, 40, storage::get_u64(KEY_DEADLINE_BLK));
    put_u64(&mut out, 48, storage::get_u64(KEY_TOT_COMMITTED));
    put_u64(&mut out, 56, storage::get_u64(KEY_TOT_ESCROW_ONCHAIN));
    put_u64(&mut out, 64, storage::get_u64(KEY_TOT_PREAUTH_ORACLE));
    put_u64(&mut out, 72, storage::get_u64(KEY_TOT_CAPTURED_ORACLE));
    put_u64(&mut out, 80, storage::get_u64(KEY_TOT_REFUNDED));
    put_u64(&mut out, 88, storage::get_u64(KEY_TOT_BUDGET_UNLOCKED));
    put_u64(&mut out, 96, storage::get_u64(KEY_TOT_BUDGET_SPENT));
    put_u64(&mut out, 104, storage::get_u64(KEY_PLEDGE_CNT));
    put_u64(&mut out, 112, storage::get_u64(KEY_SKU_CNT));
    put_u64(&mut out, 120, storage::get_u64(KEY_TIER_CNT));
    put_u64(&mut out, 128, storage::get_u64(KEY_UNLOCKED_TIER_CNT));

    let mut title = [0u8; 32];
    let _ = storage::get_into(KEY_TITLE, &mut title);
    out[136..168].copy_from_slice(&title);
    out[168..188].copy_from_slice(&storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]));
    out[188..208].copy_from_slice(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    out[208..228].copy_from_slice(&storage::get_address(KEY_BOARD_AUTH).unwrap_or([0u8; 20]));
    out[228..248].copy_from_slice(&storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]));
    out[248..280].copy_from_slice(&storage::get_bytes32(KEY_SPEC_HASH).unwrap_or([0u8; 32]));
    out[280..312].copy_from_slice(&storage::get_bytes32(KEY_ACT_HASH).unwrap_or([0u8; 32]));
    put_u64(&mut out, 312, storage::get_u64(KEY_SWEPT_TO_TREASURY));

    ret::write(&out);
    Ok(())
}

fn handle_get_budget_tiers(_args: &CalldataReader) -> Result<(), i32> {
    let cnt = storage::get_u64(KEY_TIER_CNT) as usize;
    let mut out = [0u8; MAX_BUDGET_TIERS * TIER_WIRE_LEN];
    let mut i = 0usize;
    while i < cnt {
        let w = load_tier(i as u64)?;
        out[i * TIER_WIRE_LEN..(i + 1) * TIER_WIRE_LEN].copy_from_slice(&w);
        i += 1;
    }
    ret::write(&out[..cnt * TIER_WIRE_LEN]);
    Ok(())
}

fn handle_get_reward_skus(_args: &CalldataReader) -> Result<(), i32> {
    let cnt = storage::get_u64(KEY_SKU_CNT) as usize;
    let mut out = [0u8; MAX_REWARD_SKUS * SKU_WIRE_LEN];
    let mut i = 0usize;
    while i < cnt {
        let w = load_sku(i as u64)?;
        out[i * SKU_WIRE_LEN..(i + 1) * SKU_WIRE_LEN].copy_from_slice(&w);
        i += 1;
    }
    ret::write(&out[..cnt * SKU_WIRE_LEN]);
    Ok(())
}

fn handle_get_pledge(args: &CalldataReader) -> Result<(), i32> {
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let w = load_pledge(pledge_id)?;
    ret::write(&w);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::CHARTER_STATE_ACTIVE;
    use hps_sdk::mock;
    use std::cell::RefCell;

    const SELF_CF: [u8; 20] = [0xCF; 20];
    const REGISTRY: [u8; 20] = [0xA1; 20];
    const CHARTER: [u8; 20] = [0xC0; 20];
    const ACC_LEDGER: [u8; 20] = [0xAC; 20];
    const BOARD_AUTH: [u8; 20] = [0xB0; 20];
    const DIRECTOR_1: [u8; 20] = [0x11; 20];
    const ORACLE: [u8; 20] = [0x22; 20];
    const BACKER_A: [u8; 20] = [0x33; 20];
    const VENDOR: [u8; 20] = [0x44; 20];

    thread_local! {
        static BOOKED_PROCEEDS: RefCell<u64> = const { RefCell::new(0) };
        static BOOKED_DISBURSED: RefCell<u64> = const { RefCell::new(0) };
        static AUTH_CONSUMED_FLAG: RefCell<bool> = const { RefCell::new(false) };
    }

    fn tx(sender: [u8; 20], blk: u64, cd: &[u8]) -> i32 {
        mock::set_block_number(blk);
        match mock::transact_as(sender, SELF_CF, cd) {
            Ok(_) => 0,
            Err(rc) => rc,
        }
    }

    fn mock_acc_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
        if sel == selector("associatedCharter()") {
            ret::write_address(&CHARTER);
            return 0;
        }
        if sel == selector("identityRegistry()") {
            ret::write_address(&REGISTRY);
            return 0;
        }
        if sel == selector("hfsRegistry()")
            || sel == selector("operatingBankLedger()")
            || sel == selector("treasuryIdentity()")
        {
            ret::write_address(&[0u8; 20]);
            return 0;
        }
        if sel == selector("bookCrowdfundingProceedsFromCampaign(bytes32,uint64,uint64)") {
            let amt = args.u64(2).unwrap();
            BOOKED_PROCEEDS.with(|p| *p.borrow_mut() += amt);
            ret::write_u64_word(1);
            return 0;
        }
        if sel == selector("bookCrowdfundingBudgetDisbursement(address,uint64,uint64,bytes32)") {
            let amt = args.u64(2).unwrap();
            BOOKED_DISBURSED.with(|d| *d.borrow_mut() += amt);
            ret::write_u64_word(2);
            return 0;
        }
        0
    }

    fn mock_charter_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
        if sel == selector("state()") {
            ret::write_u64_word(CHARTER_STATE_ACTIVE);
            return 0;
        }
        if sel == selector("isDirector(address)") {
            let who = args.address(0).unwrap();
            ret::write_bool(who == DIRECTOR_1);
            return 0;
        }
        if sel == selector("hasDirectorConsented(address)") {
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("hasRole(bytes32,address)") {
            ret::write_bool(false);
            return 0;
        }
        if sel == selector("getFunctionAuth(address,bytes4)") {
            ret::write_word(&[0u8; 32]);
            return 0;
        }
        0
    }

    fn mock_registry_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
        if sel == selector("isValidIdentity(address)")
            || sel == selector("isValidAuthorizationHps(address)")
            || sel == selector("isAllowedAuthorizationHps(address)")
        {
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("authorizationCodeHash()") {
            ret::write_word(&[0xAA; 32]);
            return 0;
        }
        0
    }

    fn mock_auth_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
        if sel == selector("charter()") {
            ret::write_address(&CHARTER);
            return 0;
        }
        if sel == selector("consume(address,bytes32,bytes32,address)") {
            let already = AUTH_CONSUMED_FLAG.with(|f| *f.borrow());
            if already {
                return -68;
            }
            AUTH_CONSUMED_FLAG.with(|f| *f.borrow_mut() = true);
            ret::write_bool(true);
            return 0;
        }
        0
    }

    fn install_charter_and_accounting_mocks() {
        BOOKED_PROCEEDS.with(|p| *p.borrow_mut() = 0);
        BOOKED_DISBURSED.with(|d| *d.borrow_mut() = 0);
        AUTH_CONSUMED_FLAG.with(|f| *f.borrow_mut() = false);

        mock::register_hps(SELF_CF, dispatch_calldata);
        mock::register_hps(ACC_LEDGER, mock_acc_dispatch);
        mock::register_hps(CHARTER, mock_charter_dispatch);
        mock::register_hps(REGISTRY, mock_registry_dispatch);
        mock::register_hps(BOARD_AUTH, mock_auth_dispatch);
        mock::set_code_hash(BOARD_AUTH, [0xAA; 32]);
    }

    fn encode_propose_calldata(
        mode: u64,
        base_target: u64,
        duration_blocks: u64,
        title: &[u8],
        skus: &[u8],
        tiers: &[u8],
    ) -> Vec<u8> {
        let sel = selector(
            "proposeCampaign(address,address,address,address,uint64,uint64,uint64,bytes,bytes,bytes)",
        );
        let mut out = Vec::new();
        out.extend_from_slice(&sel);

        let push_addr = |buf: &mut Vec<u8>, a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(a);
            buf.extend_from_slice(&w);
        };
        let push_u64 = |buf: &mut Vec<u8>, v: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&v.to_be_bytes());
            buf.extend_from_slice(&w);
        };
        let pad_len = |n: usize| (n + 31) & !31;

        push_addr(&mut out, &ACC_LEDGER);
        push_addr(&mut out, &[0u8; 20]); // escrowIdentity
        push_addr(&mut out, &[0u8; 20]); // rewardVoucherHfs
        push_addr(&mut out, &ORACLE);
        push_u64(&mut out, mode);
        push_u64(&mut out, base_target);
        push_u64(&mut out, duration_blocks);

        let off_title = 10 * 32;
        let off_skus = off_title + 32 + pad_len(title.len());
        let off_tiers = off_skus + 32 + pad_len(skus.len());
        push_u64(&mut out, off_title as u64);
        push_u64(&mut out, off_skus as u64);
        push_u64(&mut out, off_tiers as u64);

        for blob in [title, skus, tiers] {
            push_u64(&mut out, blob.len() as u64);
            out.extend_from_slice(blob);
            let rem = pad_len(blob.len()) - blob.len();
            out.extend(std::iter::repeat_n(0u8, rem));
        }
        out
    }

    fn pack_sku(code: u64, price: u64, max_units: u64, tier_bps: u64, name: &[u8]) -> [u8; 64] {
        let mut b = [0u8; 64];
        put_u64(&mut b, 0, code);
        put_u64(&mut b, 8, price);
        put_u64(&mut b, 16, max_units);
        put_u64(&mut b, 24, tier_bps);
        let n = name.len().min(32);
        b[32..32 + n].copy_from_slice(&name[..n]);
        b
    }

    fn pack_tier(
        threshold: u64,
        alloc: u64,
        ifrs_cat: u64,
        code: &[u8],
        title: &[u8],
    ) -> [u8; 88] {
        let mut b = [0u8; 88];
        put_u64(&mut b, 0, threshold);
        put_u64(&mut b, 8, alloc);
        put_u64(&mut b, 16, ifrs_cat);
        let nc = code.len().min(32);
        b[24..24 + nc].copy_from_slice(&code[..nc]);
        let nt = title.len().min(32);
        b[56..56 + nt].copy_from_slice(&title[..nt]);
        b
    }

    #[test]
    fn board_resolution_gates_live_state_and_hard_cap_refunds_when_missed() {
        mock::reset();
        install_charter_and_accounting_mocks();

        let sku = pack_sku(1, 200, 100, 15_000, b"SLX-L1 Dongle");
        let init_cd = encode_propose_calldata(
            MODE_SINGLE_HARD_CAP,
            1_000,
            400,
            b"Wave 1 Hard-Cap",
            &sku,
            &[],
        );
        assert_eq!(tx(DIRECTOR_1, 100, &init_cd), 0);

        let st_cd = CallEncoder::<16>::new(selector("state()"));
        assert_eq!(
            get_u64_be(&mock::transact_as(DIRECTOR_1, SELF_CF, st_cd.as_slice()).unwrap(), 24),
            STATE_PENDING_BOARD_RESOLUTION as u64
        );

        // Bind Board Resolution Authorization HFS
        let bind_cd = CallEncoder::<64>::new(selector("bindBoardResolution(address)"))
            .push_address(&BOARD_AUTH);
        assert_eq!(tx(DIRECTOR_1, 100, bind_cd.as_slice()), 0);

        // Attempting to pledge BEFORE Board Resolution passes & activates MUST revert with -26!
        let early_plg =
            CallEncoder::<132>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
                .push_u64(0)
                .push_u64(2)
                .push_bytes32(&[0xAB; 32]);
        assert_eq!(
            tx(BACKER_A, 105, early_plg.as_slice()),
            ERR_AWAITING_BOARD_ACTIVATION
        );

        // Step 3: Director activates the passed Board Resolution -> sets STATE_LIVE (2)!
        let act_cd =
            CallEncoder::<64>::new(selector("activateCampaign(address)")).push_address(&BOARD_AUTH);
        assert_eq!(tx(DIRECTOR_1, 120, act_cd.as_slice()), 0);

        let sum = mock::transact_as(
            DIRECTOR_1,
            SELF_CF,
            CallEncoder::<16>::new(selector("getCampaignSummary()")).as_slice(),
        )
        .unwrap();
        assert_eq!(get_u64_be(&sum, 0), STATE_LIVE as u64);
        assert_eq!(get_u64_be(&sum, 40), 520); // 120 + 400 durationBlocks

        // Now Backer A pledges 3 units ($600)
        let plg1 = CallEncoder::<132>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(0)
            .push_u64(3)
            .push_bytes32(&[0xAB; 32]);
        assert_eq!(tx(BACKER_A, 130, plg1.as_slice()), 0);

        // Hard-cap blocks excess order ($600 + $600 = $1,200 > $1,000)
        let plg_over = CallEncoder::<132>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(0)
            .push_u64(3)
            .push_bytes32(&[0xCD; 32]);
        assert_eq!(
            tx(BACKER_A, 131, plg_over.as_slice()),
            ERR_TARGET_CAP_EXCEEDED
        );

        // Advance past deadline (521) with $600 < $1,000 -> STATE_FAILED_REFUNDABLE (no-one charged!)
        let fin_cd = CallEncoder::<16>::new(selector("finalizeCampaign()"));
        assert_eq!(tx(DIRECTOR_1, 521, fin_cd.as_slice()), 0);

        // Backer claims 100% refund
        let ref_cd = CallEncoder::<40>::new(selector("claimFullRefund(uint64)")).push_u64(1);
        assert_eq!(tx(BACKER_A, 522, ref_cd.as_slice()), 0);

        let sum_after = mock::transact_as(
            DIRECTOR_1,
            SELF_CF,
            CallEncoder::<16>::new(selector("getCampaignSummary()")).as_slice(),
        )
        .unwrap();
        assert_eq!(get_u64_be(&sum_after, 0), STATE_FAILED_REFUNDABLE as u64);
        assert_eq!(get_u64_be(&sum_after, 80), 600); // totalRefunded == 600
        assert_eq!(BOOKED_PROCEEDS.with(|p| *p.borrow()), 0);
    }

    #[test]
    fn accounting_ledger_board_activation_sweeps_ifrs_proceeds_and_disburses_unlocked_tiers() {
        mock::reset();
        install_charter_and_accounting_mocks();

        let sku = pack_sku(2, 500, 1_000, 15_000, b"SLX-G1 Gateway");
        let t0 = pack_tier(1_000, 600, 1, b"1020-MOQ", b"Base 500-Unit MOQ");
        let t1 = pack_tier(2_500, 900, 2, b"6100-RND", b"FPGA Mesh Engine");
        let t2 = pack_tier(5_000, 1_500, 3, b"1600-CAPEX", b"Automated SMT Line");
        let mut tiers = Vec::new();
        tiers.extend_from_slice(&t0);
        tiers.extend_from_slice(&t1);
        tiers.extend_from_slice(&t2);

        let init_cd = encode_propose_calldata(
            MODE_MULTI_TIER_GROWTH_BUDGET,
            1_000,
            600,
            b"Multi-Tier IFRS Launch",
            &sku,
            &tiers,
        );
        assert_eq!(tx(DIRECTOR_1, 50, &init_cd), 0);

        // AccountingLedger invokes `onBoardResolutionActivated` after consuming Board Resolution!
        let on_act_cd = CallEncoder::<96>::new(selector(
            "onBoardResolutionActivated(address,address)",
        ))
        .push_address(&BOARD_AUTH)
        .push_address(&DIRECTOR_1);
        assert_eq!(tx(ACC_LEDGER, 75, on_act_cd.as_slice()), 0);

        let sum_live = mock::transact_as(
            DIRECTOR_1,
            SELF_CF,
            CallEncoder::<16>::new(selector("getCampaignSummary()")).as_slice(),
        )
        .unwrap();
        assert_eq!(get_u64_be(&sum_live, 0), STATE_LIVE as u64);
        assert_eq!(get_u64_be(&sum_live, 40), 675);

        // Backer pledges 6 units ($3,000) -> unlocks Tier 0 ($1,000) and Tier 1 ($2,500), leaves Tier 2 ($5,000) locked!
        let plg = CallEncoder::<132>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(0)
            .push_u64(6)
            .push_bytes32(&[0x77; 32]);
        assert_eq!(tx(BACKER_A, 80, plg.as_slice()), 0);

        // Finalize -> sweeps $3,000 into AccountingLedger (`2300 Contract Liabilities`)!
        let fin_cd = CallEncoder::<16>::new(selector("finalizeCampaign()"));
        assert_eq!(tx(DIRECTOR_1, 85, fin_cd.as_slice()), 0);
        assert_eq!(BOOKED_PROCEEDS.with(|p| *p.borrow()), 3_000);

        let sum_succ = mock::transact_as(
            DIRECTOR_1,
            SELF_CF,
            CallEncoder::<16>::new(selector("getCampaignSummary()")).as_slice(),
        )
        .unwrap();
        assert_eq!(get_u64_be(&sum_succ, 0), STATE_SETTLED_SUCCEEDED as u64);
        assert_eq!(get_u64_be(&sum_succ, 128), 2); // unlockedTierCount == 2
        assert_eq!(get_u64_be(&sum_succ, 88), 1_500); // totalBudgetUnlocked == 1_500

        // Disbursing unreached Tier 2 ($5,000) reverts with ERR_BUDGET_TIER_LOCKED (-40)
        let disb_locked = CallEncoder::<172>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(2)
        .push_address(&VENDOR)
        .push_u64(400)
        .push_bytes32(&[0x01; 32])
        .push_address(&[0u8; 20]);
        assert_eq!(
            tx(DIRECTOR_1, 90, disb_locked.as_slice()),
            ERR_BUDGET_TIER_LOCKED
        );

        // Disbursing $750 from unlocked Tier 1 (`6100-RND`, alloc $900) succeeds & posts to AccountingLedger!
        let disb_ok = CallEncoder::<172>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(1)
        .push_address(&VENDOR)
        .push_u64(750)
        .push_bytes32(&[0x02; 32])
        .push_address(&[0u8; 20]);
        assert_eq!(tx(DIRECTOR_1, 91, disb_ok.as_slice()), 0);
        assert_eq!(BOOKED_DISBURSED.with(|d| *d.borrow()), 750);

        // Overspending Tier 1 ($750 + $200 > $900) reverts with ERR_BUDGET_LINE_EXCEEDED (-41)
        let disb_over = CallEncoder::<172>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(1)
        .push_address(&VENDOR)
        .push_u64(200)
        .push_bytes32(&[0x03; 32])
        .push_address(&[0u8; 20]);
        assert_eq!(
            tx(DIRECTOR_1, 92, disb_over.as_slice()),
            ERR_BUDGET_LINE_EXCEEDED
        );
    }

    #[test]
    fn preorder_auth_allows_cancel_before_charge_blocks_user_after_charge_and_allows_company_discretion() {
        mock::reset();
        install_charter_and_accounting_mocks();

        let sku = pack_sku(1, 198, 500, 2_000, b"Lexicon Dual-RF Dongle");
        let init_cd = encode_propose_calldata(
            MODE_SINGLE_ALL_OR_NOTHING,
            500,
            400,
            b"Superlexicon Pre-Orders",
            &sku,
            &[],
        );
        assert_eq!(tx(DIRECTOR_1, 10, &init_cd), 0);
        let bind_cd = CallEncoder::<64>::new(selector("bindBoardResolution(address)"))
            .push_address(&BOARD_AUTH);
        assert_eq!(tx(DIRECTOR_1, 10, bind_cd.as_slice()), 0);
        let act_cd =
            CallEncoder::<64>::new(selector("activateCampaign(address)")).push_address(&BOARD_AUTH);
        assert_eq!(tx(DIRECTOR_1, 12, act_cd.as_slice()), 0);

        // 1. Oracle records two Airwallex credit-authorization holds for BACKER_A:
        //    - Pledge #1: 1 unit ($198) -> Backer cancels during credit authorization!
        //    - Pledge #2: 3 units ($594 >= $500 target) -> Campaign succeeds & card is charged!
        let rec1 = CallEncoder::<164>::new(selector(
            "recordOraclePreorderHoldForBacker(address,bytes32,uint64,uint64,bytes32)",
        ))
        .push_address(&BACKER_A)
        .push_bytes32(&[0xA1; 32])
        .push_u64(0)
        .push_u64(1)
        .push_bytes32(&[0xB1; 32]);
        assert_eq!(tx(ORACLE, 15, rec1.as_slice()), 0);

        let rec2 = CallEncoder::<164>::new(selector(
            "recordOraclePreorderHoldForBacker(address,bytes32,uint64,uint64,bytes32)",
        ))
        .push_address(&BACKER_A)
        .push_bytes32(&[0xA2; 32])
        .push_u64(0)
        .push_u64(3)
        .push_bytes32(&[0xB2; 32]);
        assert_eq!(tx(ORACLE, 16, rec2.as_slice()), 0);

        // Backer cancels Pledge #1 while in credit-authorization hold -> SUCCEEDS ($0 charged)!
        let cancel1 =
            CallEncoder::<40>::new(selector("cancelPreorderAuthorization(uint64)")).push_u64(1);
        assert_eq!(tx(BACKER_A, 17, cancel1.as_slice()), 0);

        let sum_mid = mock::transact_as(
            DIRECTOR_1,
            SELF_CF,
            CallEncoder::<16>::new(selector("getCampaignSummary()")).as_slice(),
        )
        .unwrap();
        assert_eq!(get_u64_be(&sum_mid, 48), 594); // totalCommitted reduced from 792 -> 594
        assert_eq!(get_u64_be(&sum_mid, 64), 594); // totalPreauthOracle == 594

        // 2. Minimum target ($500) met -> Finalize campaign & capture Pledge #2 card charge!
        let fin_cd = CallEncoder::<16>::new(selector("finalizeCampaign()"));
        assert_eq!(tx(DIRECTOR_1, 20, fin_cd.as_slice()), 0);
        let cap2 =
            CallEncoder::<40>::new(selector("confirmOracleHoldCaptured(uint64)")).push_u64(2);
        assert_eq!(tx(ORACLE, 21, cap2.as_slice()), 0);

        // 3. Backer attempts to cancel Pledge #2 AFTER card has been charged -> REVERTS (-43)!
        let cancel2 =
            CallEncoder::<40>::new(selector("cancelPreorderAuthorization(uint64)")).push_u64(2);
        assert_eq!(
            tx(BACKER_A, 22, cancel2.as_slice()),
            ERR_ALREADY_CHARGED_NO_USER_CANCEL
        );

        // Backer also cannot call grantDiscretionaryRefund directly -> REVERTS (-12 ERR_UNAUTHORIZED)!
        let disc2 =
            CallEncoder::<40>::new(selector("grantDiscretionaryRefund(uint64)")).push_u64(2);
        assert_eq!(tx(BACKER_A, 23, disc2.as_slice()), ERR_UNAUTHORIZED);

        // 4. Company Officer / Oracle grants discretionary refund on Pledge #2 -> SUCCEEDS!
        assert_eq!(tx(DIRECTOR_1, 24, disc2.as_slice()), 0);
    }
}
