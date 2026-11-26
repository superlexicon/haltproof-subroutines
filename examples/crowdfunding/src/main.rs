//! Milestone Crowdfunding & Stretch-Goal Corporate Growth Budget **Haltproof Subroutine (HPS #26)** (`crowdfunding`).
//!
//! Codifies trustless hardware/product pre-order crowdfunding directly on SuperLexicon L1 (`$0.00` gas)
//! with three institutional campaign modes and ring-fenced corporate budget governance:
//!
//! 1. **Single-Target Hard-Cap All-or-Nothing (`MODE_SINGLE_HARD_CAP = 1`):**
//!    - Rejects any pre-order that would push `totalCommitted > baseTargetAmount` (`ERR_TARGET_CAP_EXCEEDED`),
//!      preventing fulfillment over-extension beyond planned MOQ capacity.
//!    - **If `baseTargetAmount` is not met by `deadlineBlock`, no-one is charged:**
//!      - On-chain escrowed pledges return `100%` to backers via `claimFullRefund(pledgeId)`.
//!      - Off-chain credit-card pre-authorization holds registered by `banking-oracle` transition to
//!        `PLEDGE_REFUNDED_OR_VOIDED` without ever being captured.
//!
//! 2. **Single-Target Flexible All-or-Nothing (`MODE_SINGLE_ALL_OR_NOTHING = 2`):**
//!    - Requires `totalCommitted >= baseTargetAmount` by `deadlineBlock` (otherwise `100%` refund /
//!      uncharged void), while allowing pre-orders above `baseTargetAmount` up to per-SKU `maxUnits`.
//!
//! 3. **Multi-Tier Stretch-Goal Corporate Growth Budget (`MODE_MULTI_TIER_GROWTH_BUDGET = 3`):**
//!    - Defines ascending funding thresholds `tier[0 .. N-1]` (`tier[0].threshold == baseTargetAmount`).
//!    - Each tier codifies a **Company Growth Budget Line Item** (`thresholdAmount`, `budgetAllocation`,
//!      `ifrsCategory`, `lineItemCode`, `title`).
//!    - Crossing `tier[k].thresholdAmount` automatically unlocks `tier[k]` in the company's on-chain budget!
//!    - Management can disburse from an unlocked budget line (`disburseUnlockedBudgetLine`) ONLY when:
//!      (a) Campaign succeeded (`totalCommitted >= baseTargetAmount`),
//!      (b) `tier[tierIndex].unlocked == true` (unreached stretch tiers remain permanently locked!),
//!      (c) `tier[tierIndex].spentAmount + amount <= tier[tierIndex].budgetAllocation`, and
//!      (d) `totalBudgetSpent + amount <= realizedCashPool` (`totalEscrowedOnChain + totalCapturedOracle`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    hfs_type_id, verify_and_consume_auth, ActionHasher, POLICY_BOARD_RESOLUTION,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const HFS_TYPE_CROWDFUNDING: [u8; 32] = hfs_type_id(b"CROWDFUNDING");

pub const MODE_SINGLE_HARD_CAP: u64 = 1;
pub const MODE_SINGLE_ALL_OR_NOTHING: u64 = 2;
pub const MODE_MULTI_TIER_GROWTH_BUDGET: u64 = 3;

pub const STATE_UNINITIALIZED: u8 = 0;
pub const STATE_ACTIVE: u8 = 1;
pub const STATE_SUCCEEDED: u8 = 2;
pub const STATE_FAILED_REFUNDABLE: u8 = 3;

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
pub const SUMMARY_WIRE_LEN: usize = 224;

pub const ERR_NOT_INITIALIZED: i32 = -10;
pub const ERR_ALREADY_INITIALIZED: i32 = -11;
pub const ERR_UNAUTHORIZED: i32 = -12;
pub const ERR_INVALID_PARAMS: i32 = -13;
pub const ERR_CAMPAIGN_NOT_ACTIVE: i32 = -20;
pub const ERR_DEADLINE_PASSED: i32 = -21;
pub const ERR_DEADLINE_NOT_REACHED: i32 = -22;
pub const ERR_CAMPAIGN_NOT_FAILED: i32 = -23;
pub const ERR_CAMPAIGN_NOT_SUCCEEDED: i32 = -24;
pub const ERR_TARGET_CAP_EXCEEDED: i32 = -31;
pub const ERR_SKU_SOLD_OUT: i32 = -32;
pub const ERR_DUPLICATE_PAYMENT_REF: i32 = -33;
pub const ERR_PLEDGE_NOT_ELIGIBLE: i32 = -34;
pub const ERR_BUDGET_TIER_LOCKED: i32 = -40;
pub const ERR_BUDGET_LINE_EXCEEDED: i32 = -41;
pub const ERR_INSUFFICIENT_REALIZED_CASH: i32 = -42;
pub const ERR_SUBCALL_FAILED: i32 = -50;

const KEY_INIT: &[u8] = b"cf:init";
const KEY_STATE: &[u8] = b"cf:state";
const KEY_MODE: &[u8] = b"cf:mode";
const KEY_BASE_TARGET: &[u8] = b"cf:target";
const KEY_DEADLINE_BLK: &[u8] = b"cf:deadline";
const KEY_TITLE: &[u8] = b"cf:title";

const KEY_ADMIN: &[u8] = b"cf:admin";
const KEY_CHARTER: &[u8] = b"cf:charter";
const KEY_BANK_LEDGER: &[u8] = b"cf:bank_led";
const KEY_ACCOUNTING: &[u8] = b"cf:acc_led";
const KEY_REWARD_VOUCHER: &[u8] = b"cf:rv_hfs";
const KEY_ORACLE: &[u8] = b"cf:oracle";

const KEY_TOT_COMMITTED: &[u8] = b"cf:tot_com";
const KEY_TOT_ESCROW_ONCHAIN: &[u8] = b"cf:tot_esc";
const KEY_TOT_PREAUTH_ORACLE: &[u8] = b"cf:tot_hold";
const KEY_TOT_CAPTURED_ORACLE: &[u8] = b"cf:tot_cap";
const KEY_TOT_REFUNDED: &[u8] = b"cf:tot_ref";
const KEY_TOT_BUDGET_UNLOCKED: &[u8] = b"cf:tot_bunl";
const KEY_TOT_BUDGET_SPENT: &[u8] = b"cf:tot_bspn";

const KEY_PLEDGE_CNT: &[u8] = b"cf:plg_cnt";
const KEY_SKU_CNT: &[u8] = b"cf:sku_cnt";
const KEY_TIER_CNT: &[u8] = b"cf:tier_cnt";
const KEY_UNLOCKED_TIER_CNT: &[u8] = b"cf:unl_cnt";

const SEL_CHARTER_CLEAR_TRANSFER: [u8; 4] =
    selector("charterModuleClearTransfer(address,address,uint64)");
const SEL_ISSUE_PAID_VOUCHER: [u8; 4] =
    selector("issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)");
const SEL_IDENTITY_REGISTRY: [u8; 4] = selector("identityRegistry()");

const EV_INITIALIZED: [u8; 32] =
    event_topic("CrowdfundingInitialized(uint64,uint64,uint64,uint64,uint64)");
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

const ACTION_DISBURSE_CROWDFUND_BUDGET: [u8; 32] = keccak256(b"DISBURSE_CROWDFUND_BUDGET");

hps_entry! {
    "hfsType()"                                                                                                         => handle_hfs_type,
    "initialize(address,address,address,address,address,address,uint64,uint64,uint64,bytes,bytes,bytes)"                => handle_initialize,
    "pledgeOnChain(uint64,uint64,bytes32)"                                                                              => handle_pledge_onchain,
    "recordOraclePreorderHold(bytes32,uint64,uint64,bytes32)"                                                           => handle_record_oracle_hold,
    "confirmOracleHoldCaptured(uint64)"                                                                                 => handle_confirm_oracle_captured,
    "finalizeCampaign()"                                                                                                => handle_finalize_campaign,
    "claimFullRefund(uint64)"                                                                                           => handle_claim_refund,
    "issueBackerVoucher(uint64)"                                                                                        => handle_issue_backer_voucher,
    "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)"                                                 => handle_disburse_budget,
    "getCampaignSummary()"                                                                                              => handle_get_summary,
    "getBudgetTiers()"                                                                                                  => handle_get_budget_tiers,
    "getRewardSkus()"                                                                                                   => handle_get_reward_skus,
    "getPledge(uint64)"                                                                                                 => handle_get_pledge,
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

fn require_oracle_or_admin() -> Result<[u8; 20], i32> {
    let caller = context::msg_sender();
    let admin = storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]);
    let oracle = storage::get_address(KEY_ORACLE).unwrap_or([0u8; 20]);
    if caller != [0u8; 20] && (caller == admin || caller == oracle) {
        Ok(caller)
    } else {
        Err(ERR_UNAUTHORIZED)
    }
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

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(ERR_ALREADY_INITIALIZED);
    }
    let admin = args.address(0).ok_or(ERR_INVALID_PARAMS)?;
    let charter = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    let bank_ledger = args.address(2).ok_or(ERR_INVALID_PARAMS)?;
    let accounting = args.address(3).ok_or(ERR_INVALID_PARAMS)?;
    let reward_voucher = args.address(4).ok_or(ERR_INVALID_PARAMS)?;
    let oracle = args.address(5).ok_or(ERR_INVALID_PARAMS)?;
    let mode = args.u64(6).ok_or(ERR_INVALID_PARAMS)?;
    let base_target = args.u64(7).ok_or(ERR_INVALID_PARAMS)?;
    let deadline_block = args.u64(8).ok_or(ERR_INVALID_PARAMS)?;
    let title_raw = args.dynamic_bytes(9).ok_or(ERR_INVALID_PARAMS)?;
    let skus_pack = args.dynamic_bytes(10).ok_or(ERR_INVALID_PARAMS)?;
    let tiers_pack = args.dynamic_bytes(11).ok_or(ERR_INVALID_PARAMS)?;

    if admin == [0u8; 20] || base_target == 0 || deadline_block <= context::block_number() {
        return Err(ERR_INVALID_PARAMS);
    }
    if mode != MODE_SINGLE_HARD_CAP
        && mode != MODE_SINGLE_ALL_OR_NOTHING
        && mode != MODE_MULTI_TIER_GROWTH_BUDGET
    {
        return Err(ERR_INVALID_PARAMS);
    }
    if skus_pack.is_empty() || skus_pack.len() % SKU_PACK_IN_LEN != 0 {
        return Err(ERR_INVALID_PARAMS);
    }
    let sku_count = skus_pack.len() / SKU_PACK_IN_LEN;
    if sku_count > MAX_REWARD_SKUS {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut title32 = [0u8; 32];
    let t_len = title_raw.len().min(32);
    title32[..t_len].copy_from_slice(&title_raw[..t_len]);

    for i in 0..sku_count {
        let slice = &skus_pack[i * SKU_PACK_IN_LEN..(i + 1) * SKU_PACK_IN_LEN];
        let unit_price = get_u64_be(slice, 8);
        if unit_price == 0 {
            return Err(ERR_INVALID_PARAMS);
        }
        let mut wire = [0u8; SKU_WIRE_LEN];
        wire[..64].copy_from_slice(slice);
        put_u64(&mut wire, 64, 0);
        save_sku(i as u64, &wire);
    }

    if tiers_pack.len() % TIER_PACK_IN_LEN != 0 {
        return Err(ERR_INVALID_PARAMS);
    }
    let tier_count = tiers_pack.len() / TIER_PACK_IN_LEN;
    if tier_count > MAX_BUDGET_TIERS {
        return Err(ERR_INVALID_PARAMS);
    }
    if mode == MODE_MULTI_TIER_GROWTH_BUDGET && tier_count == 0 {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut prev_threshold = 0u64;
    let mut cumulative_alloc = 0u64;
    for k in 0..tier_count {
        let slice = &tiers_pack[k * TIER_PACK_IN_LEN..(k + 1) * TIER_PACK_IN_LEN];
        let threshold = get_u64_be(slice, 0);
        let alloc = get_u64_be(slice, 8);
        let cat = get_u64_be(slice, 16);
        if k == 0 && threshold != base_target {
            return Err(ERR_INVALID_PARAMS);
        }
        if threshold <= prev_threshold || alloc == 0 || !(1..=5).contains(&cat) {
            return Err(ERR_INVALID_PARAMS);
        }
        cumulative_alloc = cumulative_alloc
            .checked_add(alloc)
            .ok_or(ERR_INVALID_PARAMS)?;
        if cumulative_alloc > threshold {
            return Err(ERR_INVALID_PARAMS);
        }
        prev_threshold = threshold;

        let mut wire = [0u8; TIER_WIRE_LEN];
        wire[..88].copy_from_slice(slice);
        put_u64(&mut wire, 88, 0);
        wire[96] = 0;
        put_u64(&mut wire, 104, 0);
        save_tier(k as u64, &wire);
    }

    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, STATE_ACTIVE as u64);
    storage::set_u64(KEY_MODE, mode);
    storage::set_u64(KEY_BASE_TARGET, base_target);
    storage::set_u64(KEY_DEADLINE_BLK, deadline_block);
    storage::set(KEY_TITLE, &title32);

    storage::set_address(KEY_ADMIN, &admin);
    storage::set_address(KEY_CHARTER, &charter);
    storage::set_address(KEY_BANK_LEDGER, &bank_ledger);
    storage::set_address(KEY_ACCOUNTING, &accounting);
    storage::set_address(KEY_REWARD_VOUCHER, &reward_voucher);
    storage::set_address(KEY_ORACLE, &oracle);

    storage::set_u64(KEY_SKU_CNT, sku_count as u64);
    storage::set_u64(KEY_TIER_CNT, tier_count as u64);

    let mut ev_data = [0u8; 40];
    put_u64(&mut ev_data, 0, mode);
    put_u64(&mut ev_data, 8, base_target);
    put_u64(&mut ev_data, 16, deadline_block);
    put_u64(&mut ev_data, 24, sku_count as u64);
    put_u64(&mut ev_data, 32, tier_count as u64);
    events::emit(&[EV_INITIALIZED], &ev_data);

    ret::write_u64_word(1);
    Ok(())
}

fn evaluate_stretch_tier_unlocks(new_total_committed: u64) {
    let tier_cnt = storage::get_u64(KEY_TIER_CNT);
    if tier_cnt == 0 {
        return;
    }
    let now_blk = context::block_number();
    let mut unlocked_cnt = storage::get_u64(KEY_UNLOCKED_TIER_CNT);
    let mut tot_unlocked_budget = storage::get_u64(KEY_TOT_BUDGET_UNLOCKED);

    for k in 0..tier_cnt {
        let Ok(mut wire) = load_tier(k) else {
            continue;
        };
        if wire[96] == 1 {
            continue;
        }
        let threshold = get_u64_be(&wire, 0);
        if new_total_committed >= threshold {
            let alloc = get_u64_be(&wire, 8);
            let cat = get_u64_be(&wire, 16);
            let mut line_code = [0u8; 32];
            line_code.copy_from_slice(&wire[24..56]);

            wire[96] = 1;
            put_u64(&mut wire, 104, now_blk);
            save_tier(k, &wire);

            unlocked_cnt += 1;
            tot_unlocked_budget = tot_unlocked_budget.saturating_add(alloc);

            let mut ev_data = [0u8; 24];
            put_u64(&mut ev_data, 0, threshold);
            put_u64(&mut ev_data, 8, alloc);
            put_u64(&mut ev_data, 16, cat);
            events::emit(
                &[EV_BUDGET_UNLOCKED, u64_topic(k), line_code],
                &ev_data,
            );
        }
    }

    storage::set_u64(KEY_UNLOCKED_TIER_CNT, unlocked_cnt);
    storage::set_u64(KEY_TOT_BUDGET_UNLOCKED, tot_unlocked_budget);
}

#[allow(clippy::too_many_arguments)]
fn record_pledge_common(
    rail: u8,
    initial_status: u8,
    backer: [u8; 20],
    payment_ref_hash: [u8; 32],
    sku_index: u64,
    quantity: u64,
    voucher_commitment: [u8; 32],
) -> Result<(u64, u64), i32> {
    require_init()?;
    if get_state() != STATE_ACTIVE {
        return Err(ERR_CAMPAIGN_NOT_ACTIVE);
    }
    let now_blk = context::block_number();
    if now_blk > storage::get_u64(KEY_DEADLINE_BLK) {
        return Err(ERR_DEADLINE_PASSED);
    }
    if quantity == 0 {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut sku = load_sku(sku_index)?;
    let unit_price = get_u64_be(&sku, 8);
    let max_units = get_u64_be(&sku, 16);
    let sold_units = get_u64_be(&sku, 64);

    let new_sold = sold_units
        .checked_add(quantity)
        .ok_or(ERR_INVALID_PARAMS)?;
    if max_units > 0 && new_sold > max_units {
        return Err(ERR_SKU_SOLD_OUT);
    }

    let amount = unit_price
        .checked_mul(quantity)
        .ok_or(ERR_INVALID_PARAMS)?;

    let prev_committed = storage::get_u64(KEY_TOT_COMMITTED);
    let new_committed = prev_committed
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;

    if storage::get_u64(KEY_MODE) == MODE_SINGLE_HARD_CAP {
        let base_target = storage::get_u64(KEY_BASE_TARGET);
        if new_committed > base_target {
            return Err(ERR_TARGET_CAP_EXCEEDED);
        }
    }

    put_u64(&mut sku, 64, new_sold);
    save_sku(sku_index, &sku);

    let pledge_id = storage::get_u64(KEY_PLEDGE_CNT) + 1;
    storage::set_u64(KEY_PLEDGE_CNT, pledge_id);

    let mut plg = [0u8; PLEDGE_WIRE_LEN];
    plg[0] = initial_status;
    plg[1] = rail;
    plg[2] = 0;
    put_u64(&mut plg, 8, sku_index);
    put_u64(&mut plg, 16, quantity);
    put_u64(&mut plg, 24, amount);
    put_u64(&mut plg, 32, now_blk);
    plg[40..60].copy_from_slice(&backer);
    plg[60..92].copy_from_slice(&payment_ref_hash);
    plg[92..124].copy_from_slice(&voucher_commitment);
    save_pledge(pledge_id, &plg);

    storage::set_u64(KEY_TOT_COMMITTED, new_committed);
    evaluate_stretch_tier_unlocks(new_committed);

    let mut ev_data = [0u8; 32];
    put_u64(&mut ev_data, 0, sku_index);
    put_u64(&mut ev_data, 8, quantity);
    put_u64(&mut ev_data, 16, amount);
    put_u64(&mut ev_data, 24, new_committed);
    events::emit(
        &[EV_PLEDGE_RECORDED, u64_topic(pledge_id), addr_topic(&backer)],
        &ev_data,
    );

    Ok((pledge_id, amount))
}

fn handle_pledge_onchain(args: &CalldataReader) -> Result<(), i32> {
    let sku_index = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let quantity = args.u64(1).ok_or(ERR_INVALID_PARAMS)?;
    let voucher_commitment = args.bytes32(2).ok_or(ERR_INVALID_PARAMS)?;

    let backer = context::msg_sender();
    if backer == [0u8; 20] {
        return Err(ERR_UNAUTHORIZED);
    }

    let next_id = storage::get_u64(KEY_PLEDGE_CNT) + 1;
    let mut ref_seed = [0u8; 48];
    ref_seed[0..20].copy_from_slice(&context::self_address());
    ref_seed[20..40].copy_from_slice(&backer);
    ref_seed[40..48].copy_from_slice(&next_id.to_be_bytes());
    let payment_ref_hash = keccak256(&ref_seed);

    let (pledge_id, amount) = record_pledge_common(
        RAIL_ONCHAIN_ESCROW,
        PLEDGE_ESCROWED_ONCHAIN,
        backer,
        payment_ref_hash,
        sku_index,
        quantity,
        voucher_commitment,
    )?;

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
    if bank_ledger != [0u8; 20] {
        let self_addr = context::self_address();
        let cd = CallEncoder::<128>::new(SEL_CHARTER_CLEAR_TRANSFER)
            .push_address(&backer)
            .push_address(&self_addr)
            .push_u64(amount);
        if call::call_raw(&bank_ledger, cd.as_slice()).is_err() {
            return Err(ERR_SUBCALL_FAILED);
        }
    }

    let prev_esc = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN);
    storage::set_u64(KEY_TOT_ESCROW_ONCHAIN, prev_esc + amount);

    ret::write_u64_word(pledge_id);
    Ok(())
}

fn handle_record_oracle_hold(args: &CalldataReader) -> Result<(), i32> {
    let _caller = require_oracle_or_admin()?;
    let payment_ref_hash = args.bytes32(0).ok_or(ERR_INVALID_PARAMS)?;
    let sku_index = args.u64(1).ok_or(ERR_INVALID_PARAMS)?;
    let quantity = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let voucher_commitment = args.bytes32(3).ok_or(ERR_INVALID_PARAMS)?;

    let rk = ref_used_key(&payment_ref_hash);
    if storage::get_u64(rk.as_slice()) != 0 {
        return Err(ERR_DUPLICATE_PAYMENT_REF);
    }

    let (pledge_id, amount) = record_pledge_common(
        RAIL_ORACLE_PREAUTH_HOLD,
        PLEDGE_PREAUTH_HOLD_ORACLE,
        [0u8; 20],
        payment_ref_hash,
        sku_index,
        quantity,
        voucher_commitment,
    )?;

    storage::set_u64(rk.as_slice(), pledge_id);
    let prev_hold = storage::get_u64(KEY_TOT_PREAUTH_ORACLE);
    storage::set_u64(KEY_TOT_PREAUTH_ORACLE, prev_hold + amount);

    ret::write_u64_word(pledge_id);
    Ok(())
}

fn handle_confirm_oracle_captured(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let _caller = require_oracle_or_admin()?;
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;

    let tot_com = storage::get_u64(KEY_TOT_COMMITTED);
    let base_target = storage::get_u64(KEY_BASE_TARGET);
    if tot_com < base_target || get_state() == STATE_FAILED_REFUNDABLE {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let mut plg = load_pledge(pledge_id)?;
    if plg[0] != PLEDGE_PREAUTH_HOLD_ORACLE {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }
    let amount = get_u64_be(&plg, 24);
    plg[0] = PLEDGE_FINALIZED_CAPTURED;
    save_pledge(pledge_id, &plg);

    let prev_hold = storage::get_u64(KEY_TOT_PREAUTH_ORACLE);
    storage::set_u64(KEY_TOT_PREAUTH_ORACLE, prev_hold.saturating_sub(amount));
    let prev_cap = storage::get_u64(KEY_TOT_CAPTURED_ORACLE);
    storage::set_u64(KEY_TOT_CAPTURED_ORACLE, prev_cap + amount);

    ret::write_u64_word(1);
    Ok(())
}

fn handle_finalize_campaign(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let st = get_state();
    if st != STATE_ACTIVE {
        ret::write_u64_word(st as u64);
        return Ok(());
    }

    let now_blk = context::block_number();
    let deadline = storage::get_u64(KEY_DEADLINE_BLK);
    let tot_com = storage::get_u64(KEY_TOT_COMMITTED);
    let base_target = storage::get_u64(KEY_BASE_TARGET);
    let mode = storage::get_u64(KEY_MODE);

    let can_finalize_early = (mode == MODE_SINGLE_HARD_CAP && tot_com == base_target)
        || (tot_com >= base_target && require_oracle_or_admin().is_ok());

    if !can_finalize_early && now_blk <= deadline {
        return Err(ERR_DEADLINE_NOT_REACHED);
    }

    let new_state = if tot_com >= base_target {
        STATE_SUCCEEDED
    } else {
        STATE_FAILED_REFUNDABLE
    };
    storage::set_u64(KEY_STATE, new_state as u64);

    let mut ev_data = [0u8; 24];
    put_u64(&mut ev_data, 0, new_state as u64);
    put_u64(&mut ev_data, 8, tot_com);
    put_u64(&mut ev_data, 16, storage::get_u64(KEY_TOT_BUDGET_UNLOCKED));
    events::emit(&[EV_CAMPAIGN_FINALIZED], &ev_data);

    ret::write_u64_word(new_state as u64);
    Ok(())
}

fn handle_claim_refund(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() == STATE_ACTIVE {
        let now_blk = context::block_number();
        if now_blk > storage::get_u64(KEY_DEADLINE_BLK)
            && storage::get_u64(KEY_TOT_COMMITTED) < storage::get_u64(KEY_BASE_TARGET)
        {
            storage::set_u64(KEY_STATE, STATE_FAILED_REFUNDABLE as u64);
        }
    }
    if get_state() != STATE_FAILED_REFUNDABLE {
        return Err(ERR_CAMPAIGN_NOT_FAILED);
    }

    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut plg = load_pledge(pledge_id)?;
    let status = plg[0];
    if status != PLEDGE_ESCROWED_ONCHAIN && status != PLEDGE_PREAUTH_HOLD_ORACLE {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let amount = get_u64_be(&plg, 24);
    let mut backer = [0u8; 20];
    backer.copy_from_slice(&plg[40..60]);

    plg[0] = PLEDGE_REFUNDED_OR_VOIDED;
    save_pledge(pledge_id, &plg);

    if status == PLEDGE_ESCROWED_ONCHAIN {
        let bank_ledger = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
        if bank_ledger != [0u8; 20] {
            let self_addr = context::self_address();
            let cd = CallEncoder::<128>::new(SEL_CHARTER_CLEAR_TRANSFER)
                .push_address(&self_addr)
                .push_address(&backer)
                .push_u64(amount);
            if call::call_raw(&bank_ledger, cd.as_slice()).is_err() {
                return Err(ERR_SUBCALL_FAILED);
            }
        }
        let prev_esc = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN);
        storage::set_u64(KEY_TOT_ESCROW_ONCHAIN, prev_esc.saturating_sub(amount));
    } else {
        let prev_hold = storage::get_u64(KEY_TOT_PREAUTH_ORACLE);
        storage::set_u64(KEY_TOT_PREAUTH_ORACLE, prev_hold.saturating_sub(amount));
    }

    let prev_ref = storage::get_u64(KEY_TOT_REFUNDED);
    storage::set_u64(KEY_TOT_REFUNDED, prev_ref + amount);

    let mut ev_data = [0u8; 8];
    put_u64(&mut ev_data, 0, amount);
    events::emit(
        &[EV_PLEDGE_REFUNDED, u64_topic(pledge_id), addr_topic(&backer)],
        &ev_data,
    );

    ret::write_u64_word(amount);
    Ok(())
}

fn handle_issue_backer_voucher(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_SUCCEEDED {
        return Err(ERR_CAMPAIGN_NOT_SUCCEEDED);
    }
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let mut plg = load_pledge(pledge_id)?;
    let status = plg[0];
    if (status != PLEDGE_ESCROWED_ONCHAIN && status != PLEDGE_FINALIZED_CAPTURED) || plg[2] == 1 {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let sku_index = get_u64_be(&plg, 8);
    let amount = get_u64_be(&plg, 24);
    let mut payment_ref = [0u8; 32];
    payment_ref.copy_from_slice(&plg[60..92]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&plg[92..124]);

    if commitment == [0u8; 32] {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let sku = load_sku(sku_index)?;
    let sku_code = get_u64_be(&sku, 0);
    let tier_bps = get_u64_be(&sku, 24);
    if tier_bps == 0 {
        return Err(ERR_PLEDGE_NOT_ELIGIBLE);
    }

    let rv_hfs = storage::get_address(KEY_REWARD_VOUCHER).unwrap_or([0u8; 20]);
    if rv_hfs != [0u8; 20] {
        let cd = CallEncoder::<224>::new(SEL_ISSUE_PAID_VOUCHER)
            .push_bytes32(&payment_ref)
            .push_u64(sku_code)
            .push_u64(tier_bps)
            .push_u64(amount)
            .push_bytes32(&commitment);
        if call::call_raw(&rv_hfs, cd.as_slice()).is_err() {
            return Err(ERR_SUBCALL_FAILED);
        }
    }

    plg[2] = 1;
    save_pledge(pledge_id, &plg);

    let mut ev_data = [0u8; 8];
    put_u64(&mut ev_data, 0, amount);
    events::emit(
        &[EV_BACKER_VOUCHER_ISSUED, u64_topic(pledge_id), payment_ref],
        &ev_data,
    );

    ret::write_u64_word(1);
    Ok(())
}

fn handle_disburse_budget(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    if get_state() != STATE_SUCCEEDED {
        return Err(ERR_CAMPAIGN_NOT_SUCCEEDED);
    }

    let tier_index = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let vendor = args.address(1).ok_or(ERR_INVALID_PARAMS)?;
    let amount = args.u64(2).ok_or(ERR_INVALID_PARAMS)?;
    let expense_ref = args.bytes32(3).ok_or(ERR_INVALID_PARAMS)?;
    let auth_hps = args.address(4).ok_or(ERR_INVALID_PARAMS)?;

    if vendor == [0u8; 20] || amount == 0 {
        return Err(ERR_INVALID_PARAMS);
    }

    let mut tier = load_tier(tier_index)?;
    if tier[96] != 1 {
        return Err(ERR_BUDGET_TIER_LOCKED);
    }

    let alloc = get_u64_be(&tier, 8);
    let prev_spent = get_u64_be(&tier, 88);
    let new_tier_spent = prev_spent
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;
    if new_tier_spent > alloc {
        return Err(ERR_BUDGET_LINE_EXCEEDED);
    }

    let realized_cash = storage::get_u64(KEY_TOT_ESCROW_ONCHAIN)
        .saturating_add(storage::get_u64(KEY_TOT_CAPTURED_ORACLE));
    let prev_tot_spent = storage::get_u64(KEY_TOT_BUDGET_SPENT);
    let new_tot_spent = prev_tot_spent
        .checked_add(amount)
        .ok_or(ERR_INVALID_PARAMS)?;
    if new_tot_spent > realized_cash {
        return Err(ERR_INSUFFICIENT_REALIZED_CASH);
    }

    let caller = context::msg_sender();
    let charter = storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]);
    if charter != [0u8; 20] {
        let reg_raw =
            call::call_raw(&charter, &SEL_IDENTITY_REGISTRY).map_err(|_| ERR_SUBCALL_FAILED)?;
        if reg_raw.len() < 32 {
            return Err(ERR_SUBCALL_FAILED);
        }
        let mut registry = [0u8; 20];
        registry.copy_from_slice(&reg_raw[12..32]);
        let self_addr = context::self_address();
        let commitment =
            ActionHasher::<256>::new(&self_addr, &ACTION_DISBURSE_CROWDFUND_BUDGET)
            .push_u64(tier_index)
            .push_address(&vendor)
            .push_u64(amount)
            .push_bytes32(&expense_ref)
            .finish();
        verify_and_consume_auth(
            &registry,
            &auth_hps,
            &charter,
            &POLICY_BOARD_RESOLUTION,
            &commitment,
            &caller,
        )?;
    } else if caller != storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]) {
        return Err(ERR_UNAUTHORIZED);
    }

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]);
    if bank_ledger != [0u8; 20] {
        let self_addr = context::self_address();
        let cd = CallEncoder::<128>::new(SEL_CHARTER_CLEAR_TRANSFER)
            .push_address(&self_addr)
            .push_address(&vendor)
            .push_u64(amount);
        if call::call_raw(&bank_ledger, cd.as_slice()).is_err() {
            return Err(ERR_SUBCALL_FAILED);
        }
    }

    put_u64(&mut tier, 88, new_tier_spent);
    save_tier(tier_index, &tier);
    storage::set_u64(KEY_TOT_BUDGET_SPENT, new_tot_spent);

    let mut ev_data = [0u8; 48];
    put_u64(&mut ev_data, 0, amount);
    put_u64(&mut ev_data, 8, new_tier_spent);
    ev_data[16..48].copy_from_slice(&expense_ref);
    events::emit(
        &[EV_BUDGET_DISBURSED, u64_topic(tier_index), addr_topic(&vendor)],
        &ev_data,
    );

    ret::write_u64_word(alloc - new_tier_spent);
    Ok(())
}

fn handle_get_summary(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let mut out = [0u8; SUMMARY_WIRE_LEN];
    out[0] = get_state();
    put_u64(&mut out, 8, storage::get_u64(KEY_MODE));
    put_u64(&mut out, 16, storage::get_u64(KEY_BASE_TARGET));
    put_u64(&mut out, 24, storage::get_u64(KEY_DEADLINE_BLK));
    put_u64(&mut out, 32, storage::get_u64(KEY_TOT_COMMITTED));
    put_u64(&mut out, 40, storage::get_u64(KEY_TOT_ESCROW_ONCHAIN));
    put_u64(&mut out, 48, storage::get_u64(KEY_TOT_PREAUTH_ORACLE));
    put_u64(&mut out, 56, storage::get_u64(KEY_TOT_CAPTURED_ORACLE));
    put_u64(&mut out, 64, storage::get_u64(KEY_TOT_REFUNDED));
    put_u64(&mut out, 72, storage::get_u64(KEY_TOT_BUDGET_UNLOCKED));
    put_u64(&mut out, 80, storage::get_u64(KEY_TOT_BUDGET_SPENT));
    put_u64(&mut out, 88, storage::get_u64(KEY_PLEDGE_CNT));
    put_u64(&mut out, 96, storage::get_u64(KEY_SKU_CNT));
    put_u64(&mut out, 104, storage::get_u64(KEY_TIER_CNT));
    put_u64(&mut out, 112, storage::get_u64(KEY_UNLOCKED_TIER_CNT));

    let mut title = [0u8; 32];
    let _ = storage::get_into(KEY_TITLE, &mut title);
    out[120..152].copy_from_slice(&title);

    out[152..172].copy_from_slice(&storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]));
    out[172..192].copy_from_slice(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    out[192..212].copy_from_slice(&storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]));
    ret::write(&out);
    Ok(())
}

fn handle_get_budget_tiers(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let cnt = storage::get_u64(KEY_TIER_CNT) as usize;
    let mut buf = [0u8; MAX_BUDGET_TIERS * TIER_WIRE_LEN];
    for i in 0..cnt {
        let t = load_tier(i as u64)?;
        buf[i * TIER_WIRE_LEN..(i + 1) * TIER_WIRE_LEN].copy_from_slice(&t);
    }
    ret::write(&buf[..cnt * TIER_WIRE_LEN]);
    Ok(())
}

fn handle_get_reward_skus(_args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let cnt = storage::get_u64(KEY_SKU_CNT) as usize;
    let mut buf = [0u8; MAX_REWARD_SKUS * SKU_WIRE_LEN];
    for i in 0..cnt {
        let s = load_sku(i as u64)?;
        buf[i * SKU_WIRE_LEN..(i + 1) * SKU_WIRE_LEN].copy_from_slice(&s);
    }
    ret::write(&buf[..cnt * SKU_WIRE_LEN]);
    Ok(())
}

fn handle_get_pledge(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let pledge_id = args.u64(0).ok_or(ERR_INVALID_PARAMS)?;
    let plg = load_pledge(pledge_id)?;
    ret::write(&plg);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::{mock, selector};

    fn pack_sku(
        sku_code: u64,
        unit_price: u64,
        max_units: u64,
        tier_bps: u64,
        name: &str,
    ) -> [u8; SKU_PACK_IN_LEN] {
        let mut out = [0u8; SKU_PACK_IN_LEN];
        put_u64(&mut out, 0, sku_code);
        put_u64(&mut out, 8, unit_price);
        put_u64(&mut out, 16, max_units);
        put_u64(&mut out, 24, tier_bps);
        let nb = name.as_bytes();
        out[32..32 + nb.len().min(32)].copy_from_slice(&nb[..nb.len().min(32)]);
        out
    }

    fn pack_tier(
        threshold: u64,
        alloc: u64,
        cat: u64,
        code: &[u8; 32],
        title: &str,
    ) -> [u8; TIER_PACK_IN_LEN] {
        let mut out = [0u8; TIER_PACK_IN_LEN];
        put_u64(&mut out, 0, threshold);
        put_u64(&mut out, 8, alloc);
        put_u64(&mut out, 16, cat);
        out[24..56].copy_from_slice(code);
        let tb = title.as_bytes();
        out[56..56 + tb.len().min(32)].copy_from_slice(&tb[..tb.len().min(32)]);
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_init_calldata(
        admin: &[u8; 20],
        oracle: &[u8; 20],
        mode: u64,
        base_target: u64,
        deadline: u64,
        title: &[u8],
        skus: &[u8],
        tiers: &[u8],
    ) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector(
            "initialize(address,address,address,address,address,address,uint64,uint64,uint64,bytes,bytes,bytes)",
        ));
        let push_addr = |v: &mut Vec<u8>, a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(a);
            v.extend_from_slice(&w);
        };
        let push_u = |v: &mut Vec<u8>, n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&w);
        };
        let pad32 = |len: usize| (len + 31) & !31;

        push_addr(&mut cd, admin);
        push_addr(&mut cd, &[0u8; 20]);
        push_addr(&mut cd, &[0u8; 20]);
        push_addr(&mut cd, &[0u8; 20]);
        push_addr(&mut cd, &[0u8; 20]);
        push_addr(&mut cd, oracle);
        push_u(&mut cd, mode);
        push_u(&mut cd, base_target);
        push_u(&mut cd, deadline);

        let off0 = 12 * 32;
        let off1 = off0 + 32 + pad32(title.len());
        let off2 = off1 + 32 + pad32(skus.len());
        push_u(&mut cd, off0 as u64);
        push_u(&mut cd, off1 as u64);
        push_u(&mut cd, off2 as u64);

        for slice in [title, skus, tiers] {
            push_u(&mut cd, slice.len() as u64);
            cd.extend_from_slice(slice);
            let rem = pad32(slice.len()) - slice.len();
            cd.extend(std::iter::repeat(0u8).take(rem));
        }
        cd
    }

    #[test]
    fn single_target_hard_cap_blocks_excess_preorders_and_refunds_100_percent_when_missed() {
        mock::reset();
        let cf = [0xC1; 20];
        let admin = [0x01; 20];
        let oracle = [0x02; 20];
        let backer_a = [0xA1; 20];
        let backer_b = [0xB2; 20];

        mock::register_hps(cf, dispatch_calldata);
        mock::set_block_number(100);

        let sku = pack_sku(2, 250_000_000, 100, 15_000, "SLX-V1 Early Bird");
        let init_cd = build_init_calldata(
            &admin,
            &oracle,
            MODE_SINGLE_HARD_CAP,
            1_000_000_000,
            500,
            b"Batch 1 Hard-Cap MOQ",
            &sku,
            &[],
        );
        mock::transact_as(admin, cf, &init_cd).unwrap();

        let p1 = CallEncoder::<128>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(0)
            .push_u64(2)
            .push_bytes32(&[0xAA; 32]);
        mock::transact_as(backer_a, cf, p1.as_slice()).unwrap();

        let p2 = CallEncoder::<160>::new(selector(
            "recordOraclePreorderHold(bytes32,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&keccak256(b"card_hold_1"))
        .push_u64(0)
        .push_u64(1)
        .push_bytes32(&[0xBB; 32]);
        mock::transact_as(oracle, cf, p2.as_slice()).unwrap();

        // Pre-order exceeding $1,000 Hard Cap reverts with `ERR_TARGET_CAP_EXCEEDED`
        let p_over = CallEncoder::<128>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(0)
            .push_u64(2)
            .push_bytes32(&[0xCC; 32]);
        assert_eq!(
            mock::transact_as(backer_b, cf, p_over.as_slice()),
            Err(ERR_TARGET_CAP_EXCEEDED)
        );

        // Card hold cannot be captured while $750 < $1,000 target
        let cap_cd =
            CallEncoder::<64>::new(selector("confirmOracleHoldCaptured(uint64)")).push_u64(2);
        assert_eq!(
            mock::transact_as(oracle, cf, cap_cd.as_slice()),
            Err(ERR_PLEDGE_NOT_ELIGIBLE)
        );

        // Past deadline (block 501) -> no-one is charged; 100% refundable!
        mock::set_block_number(501);
        let ref1 = CallEncoder::<64>::new(selector("claimFullRefund(uint64)")).push_u64(1);
        let out1 = mock::transact_as(backer_a, cf, ref1.as_slice()).unwrap();
        assert_eq!(
            u64::from_be_bytes(out1[24..32].try_into().unwrap()),
            500_000_000
        );

        let ref2 = CallEncoder::<64>::new(selector("claimFullRefund(uint64)")).push_u64(2);
        let out2 = mock::transact_as(oracle, cf, ref2.as_slice()).unwrap();
        assert_eq!(
            u64::from_be_bytes(out2[24..32].try_into().unwrap()),
            250_000_000
        );
    }

    #[test]
    fn multi_tier_stretch_targets_unlock_corporate_growth_budget_lines_and_enforce_caps() {
        mock::reset();
        let cf = [0xC2; 20];
        let admin = [0x01; 20];
        let oracle = [0x02; 20];
        let backer = [0xB1; 20];
        let smt_vendor = [0xD9; 20];

        mock::register_hps(cf, dispatch_calldata);
        mock::set_block_number(100);

        let mut skus = Vec::new();
        skus.extend_from_slice(&pack_sku(2, 300_000_000, 5_000, 15_000, "SLX-V1 Validator"));
        skus.extend_from_slice(&pack_sku(3, 500_000_000, 5_000, 15_000, "SLX-G1 Gateway"));

        let mut tiers = Vec::new();
        tiers.extend_from_slice(&pack_tier(
            150_000_000_000,
            120_000_000_000,
            BUDGET_CAT_BASE_MANUFACTURING_MOQ,
            &keccak256(b"BUDGET_TIER0_MOQ"),
            "Base 500-Unit MOQ & Mold Tooling",
        ));
        tiers.extend_from_slice(&pack_tier(
            300_000_000_000,
            90_000_000_000,
            BUDGET_CAT_CERTIFICATION_COMPLIANCE,
            &keccak256(b"BUDGET_TIER1_FCC_CE"),
            "FCC / CE / TELEC RF Certs",
        ));
        tiers.extend_from_slice(&pack_tier(
            600_000_000_000,
            200_000_000_000,
            BUDGET_CAT_CAPEX_EQUIPMENT,
            &keccak256(b"BUDGET_TIER2_SMT"),
            "Automated High-Speed SMT Line",
        ));

        let init_cd = build_init_calldata(
            &admin,
            &oracle,
            MODE_MULTI_TIER_GROWTH_BUDGET,
            150_000_000_000,
            1_000,
            b"SuperLexicon Wave 1 Launch",
            &skus,
            &tiers,
        );
        mock::transact_as(admin, cf, &init_cd).unwrap();

        let plg1 = CallEncoder::<128>::new(selector("pledgeOnChain(uint64,uint64,bytes32)"))
            .push_u64(1)
            .push_u64(400)
            .push_bytes32(&[0x11; 32]);
        mock::transact_as(backer, cf, plg1.as_slice()).unwrap();

        let plg2 = CallEncoder::<160>::new(selector(
            "recordOraclePreorderHold(bytes32,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&keccak256(b"airwallex_batch_1"))
        .push_u64(1)
        .push_u64(300)
        .push_bytes32(&[0x22; 32]);
        mock::transact_as(oracle, cf, plg2.as_slice()).unwrap();

        let cap2 =
            CallEncoder::<64>::new(selector("confirmOracleHoldCaptured(uint64)")).push_u64(2);
        mock::transact_as(oracle, cf, cap2.as_slice()).unwrap();

        let fin_cd = CallEncoder::<32>::new(selector("finalizeCampaign()"));
        let fin_out = mock::transact_as(admin, cf, fin_cd.as_slice()).unwrap();
        assert_eq!(
            u64::from_be_bytes(fin_out[24..32].try_into().unwrap()),
            STATE_SUCCEEDED as u64
        );

        // Unreached Tier 2 ($600k SMT Line) reverts (`ERR_BUDGET_TIER_LOCKED`)
        let disb_locked = CallEncoder::<192>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(2)
        .push_address(&smt_vendor)
        .push_u64(10_000_000_000)
        .push_bytes32(&keccak256(b"INV-SMT-1"))
        .push_address(&[0u8; 20]);
        assert_eq!(
            mock::transact_as(admin, cf, disb_locked.as_slice()),
            Err(ERR_BUDGET_TIER_LOCKED)
        );

        // Unlocked Tier 1 ($90,000 FCC/CE RF Certs) disburses up to exact cap!
        let disb_t1 = CallEncoder::<192>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(1)
        .push_address(&smt_vendor)
        .push_u64(90_000_000_000)
        .push_bytes32(&keccak256(b"INV-FCC-LAB"))
        .push_address(&[0u8; 20]);
        let rem = mock::transact_as(admin, cf, disb_t1.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(rem[24..32].try_into().unwrap()), 0);

        // 1 micro-unit over Tier 1's $90,000 budget allocation reverts (`ERR_BUDGET_LINE_EXCEEDED`)!
        let disb_over = CallEncoder::<192>::new(selector(
            "disburseUnlockedBudgetLine(uint64,address,uint64,bytes32,address)",
        ))
        .push_u64(1)
        .push_address(&smt_vendor)
        .push_u64(1)
        .push_bytes32(&keccak256(b"INV-EXTRA"))
        .push_address(&[0u8; 20]);
        assert_eq!(
            mock::transact_as(admin, cf, disb_over.as_slice()),
            Err(ERR_BUDGET_LINE_EXCEEDED)
        );
    }
}
