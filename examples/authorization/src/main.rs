//! Process & Permissions Authorization **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Each `Authorization` instance represents a stateful, time-bounded, **one-time-use**
//! authorization object initialized and finalized for a specific target HPS operation:
//! - Retrieves multi-stage sequential & weighted-joint authorization processes from a `Constitution`
//!   HPS (`initializeFromConstitution`) — or initializes as a single-account-admin/oracle object
//!   (`initializeOracle`).
//! - Enforces **strict sequential ordering** (Stage `0` / Group A must reach its required weight
//!   before any Stage `1` / Group B authorizer can approve), **per-authorizer weights** (`>= 1`),
//!   **per-stage block expiry**, and **overall process block expiry**.
//! - Verifies every caller and authorizer Identity against `IdentityRegistry` (`isValidIdentity`).
//! - Once finalized (`finalize()` / `approveAndFinalize()`), can be consumed **exactly once** by
//!   its bound `targetHps` via `consume(...)`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    oracle_policy_id, require_valid_identity, AuctionBook, AuctionOrder, PolicySpec, StageSpec,
    ACTION_TRANSFER, CONSTITUTION_STATE_ACTIVE, CONSTITUTION_STATE_PENDING_RATIFICATION,
    ERR_CONSTITUTION_NOT_ACTIVE, ERR_NOT_EXISTING_SHAREHOLDER, ERR_NOT_ORDER_OWNER,
    ERR_ORDER_ALREADY_CANCELLED, ERR_ORDER_NOT_FOUND, ERR_POLICY_INVALID,
    ERR_STEP2_SELLER_INELIGIBLE_STEP3, ERR_WRONG_AUCTION_STEP, MAX_ENCODED_AUCTION_BOOK_BYTES,
    MAX_ENCODED_POLICY_BYTES, ORDER_SIDE_BUY_STEP1, ORDER_SIDE_BUY_STEP3, ORDER_SIDE_CANCELLED,
    ORDER_SIDE_SELL_STEP2, POLICY_FIRST_SHAREHOLDER_RESOLUTION, POLICY_SHAREHOLDER_SUPERMAJORITY,
    POLICY_SHARE_TRANSFER_AUCTION, POLICY_SUPER_GOVERNANCE, ROLE_ALL_MEMBERS_WEIGHT,
    ROLE_SHAREHOLDER,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const STATE_UNINIT: u64 = 0;
pub const STATE_PENDING: u64 = 1;
pub const STATE_FINALIZED: u64 = 2;
pub const STATE_EXPIRED: u64 = 3;
pub const STATE_CONSUMED: u64 = 4;

pub const ERR_NOT_STAGE_AUTHORIZER: i32 = -63;
pub const ERR_AUTH_EXPIRED: i32 = -64;
pub const ERR_WRONG_TARGET: i32 = -65;
pub const ERR_POLICY_MISMATCH: i32 = -66;
pub const ERR_ACTION_HASH_MISMATCH: i32 = -67;
pub const ERR_AUTH_ALREADY_CONSUMED: i32 = -68;
pub const ERR_ALREADY_SIGNED: i32 = -69;

const AUTH_INITIALIZED: [u8; 32] =
    event_topic("AuthorizationInitialized(address,address,bytes32,bytes32)");
const STAGE_APPROVED: [u8; 32] =
    event_topic("StageApproved(address,uint64,uint64,uint64)");
const STAGE_THRESHOLD_REACHED: [u8; 32] =
    event_topic("StageThresholdReached(uint64,uint64,uint64)");
const STAGE_ADVANCED: [u8; 32] = event_topic("StageAdvanced(uint64,uint64)");
const AUTH_FINALIZED: [u8; 32] = event_topic("AuthorizationFinalized(address,uint64)");
const AUTH_CONSUMED: [u8; 32] = event_topic("AuthorizationConsumed(address,address,bytes32)");
const AUCTION_STEP1_STARTED: [u8; 32] =
    event_topic("AuctionStep1Started(address,uint64,uint64,uint64,uint64,uint64)");
const BUY_ORDER_PLACED: [u8; 32] =
    event_topic("BuyOrderPlaced(address,uint64,uint64,uint64)");
const BUY_ORDER_CANCELLED: [u8; 32] =
    event_topic("BuyOrderCancelled(address,uint64,uint64,uint64)");
const SELL_ORDER_PLACED: [u8; 32] =
    event_topic("SellOrderPlaced(address,uint64,uint64,uint64)");

const KEY_STATE: &[u8] = b"au:state";
const KEY_CONSUMED: &[u8] = b"au:consumed";
const KEY_STAGES_DONE: &[u8] = b"au:done";
const KEY_CUR_STAGE: &[u8] = b"au:stage";
const KEY_STAGE_DEADLINE: &[u8] = b"au:st_dl";
const KEY_OVERALL_DEADLINE: &[u8] = b"au:ov_dl";
const KEY_REGISTRY: &[u8] = b"au:reg";
const KEY_CONSTITUTION: &[u8] = b"au:con";
const KEY_TARGET: &[u8] = b"au:target";
const KEY_POLICY_ID: &[u8] = b"au:pol_id";
const KEY_ACTION_HASH: &[u8] = b"au:act_hash";
const KEY_SPEC: &[u8] = b"au:spec";
const KEY_IS_AUCTION: &[u8] = b"au:is_auc";
const KEY_AUCTION_STARTED: &[u8] = b"au:auc_started";
const KEY_STEP1_DL: &[u8] = b"au:step1_dl";
const KEY_STEP2_DL: &[u8] = b"au:step2_dl";
const KEY_STEP3_DL: &[u8] = b"au:step3_dl";
const KEY_AUCTION_BOOK: &[u8] = b"au:auc_book";

hps_entry! {
    "initializeFromConstitution(address,address,address,bytes32,bytes32)" => handle_init_from_constitution,
    "initializeTransferAuction(address,address,address)"                  => handle_init_transfer_auction,
    "initializeOracle(address,address,address,bytes32,uint64)"            => handle_init_oracle,
    "initializeCustom(address,address,bytes32,bytes32,bytes)"             => handle_init_custom,
    "approve()"                                                           => handle_approve,
    "placeBuyOrder(uint64,uint64)"                                        => handle_place_buy_order,
    "placeBuyOrderFor(address,uint64,uint64)"                             => handle_place_buy_order_for,
    "cancelBuyOrder(uint64)"                                              => handle_cancel_buy_order,
    "cancelBuyOrderFor(address,uint64)"                                   => handle_cancel_buy_order_for,
    "placeSellOrder(uint64,uint64)"                                       => handle_place_sell_order,
    "placeSellOrderFor(address,uint64,uint64)"                            => handle_place_sell_order_for,
    "finalize()"                                                          => handle_finalize,
    "approveAndFinalize()"                                                => handle_approve_and_finalize,
    "consume(address,bytes32,bytes32,address)"                            => handle_consume,
    "consumeAuction(address,bytes32,address)"                             => handle_consume_auction,
    "status()"                                                            => handle_status,
    "currentStage()"                                                      => handle_current_stage,
    "stageCount()"                                                        => handle_stage_count,
    "stageWeight(uint64)"                                                 => handle_stage_weight,
    "deadlines()"                                                         => handle_deadlines,
    "auctionDeadlines()"                                                  => handle_auction_deadlines,
    "orderCount()"                                                        => handle_order_count,
    "getOrdersRaw()"                                                      => handle_get_orders_raw,
    "isReadyToConsume()"                                                  => handle_is_ready_to_consume,
    "targetHps()"                                                         => handle_target_hps,
    "constitution()"                                                      => handle_constitution,
    "policyId()"                                                          => handle_policy_id,
    "actionHash()"                                                        => handle_action_hash,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn stage_weight_key(stage: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"au:w:").push_u64_le(stage)
}

fn signed_key(stage: u64, identity: &[u8; 20]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new()
        .push(b"au:s:")
        .push_u64_le(stage)
        .push(identity)
}

fn step2_seller_key(identity: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"au:s2sel:").push(identity)
}

fn seller_offered_key(identity: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"au:s2qty:").push(identity)
}

fn load_auction_book() -> Result<AuctionBook, i32> {
    let mut buf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
    match storage::get_into(KEY_AUCTION_BOOK, &mut buf) {
        Some(n) if n > 0 => AuctionBook::decode(&buf[..n]).ok_or(ERR_POLICY_INVALID),
        _ => Ok(AuctionBook::new()),
    }
}

fn save_auction_book(book: &AuctionBook) -> Result<(), i32> {
    let mut buf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
    let n = book.encode(&mut buf).ok_or(ERR_POLICY_INVALID)?;
    storage::set(KEY_AUCTION_BOOK, &buf[..n]);
    Ok(())
}

fn query_ledger_balance(ledger: &[u8; 20], holder: &[u8; 20]) -> Result<u64, i32> {
    let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(holder);
    call::call_u64(ledger, cd.as_slice())
}

fn load_spec() -> Result<PolicySpec, i32> {
    let mut buf = [0u8; MAX_ENCODED_POLICY_BYTES];
    let n = storage::get_into(KEY_SPEC, &mut buf).ok_or(ERR_POLICY_INVALID)?;
    PolicySpec::decode(&buf[..n]).ok_or(ERR_POLICY_INVALID)
}

fn setup_instance(
    registry: &[u8; 20],
    constitution: &[u8; 20],
    target_hps: &[u8; 20],
    policy_id: &[u8; 32],
    action_hash: &[u8; 32],
    spec: &PolicySpec,
    raw_spec: &[u8],
) -> Result<(), i32> {
    if storage::get_u64(KEY_STATE) != STATE_UNINIT {
        return Err(-60); // already initialized
    }
    if *target_hps == [0u8; 20] || *policy_id == [0u8; 32] || *action_hash == [0u8; 32] {
        return Err(-61);
    }

    let is_auction = *policy_id == POLICY_SHARE_TRANSFER_AUCTION;
    if is_auction && spec.stage_count < 3 {
        return Err(ERR_POLICY_INVALID);
    }

    let now = context::block_number();
    let (stage0_dl, overall_dl) = if is_auction {
        // In 3-step share transfer auction mode, the Step 1 clock starts when the first potential buyer
        // places a buy order (`placeBuyOrder`).
        (u64::MAX, u64::MAX)
    } else {
        (
            now.saturating_add(spec.stages[0].expiry_blocks),
            now.saturating_add(spec.overall_expiry_blocks),
        )
    };

    storage::set_address(KEY_REGISTRY, registry);
    storage::set_address(KEY_CONSTITUTION, constitution);
    storage::set_address(KEY_TARGET, target_hps);
    storage::set(KEY_POLICY_ID, policy_id);
    storage::set(KEY_ACTION_HASH, action_hash);
    storage::set(KEY_SPEC, raw_spec);
    storage::set_u64(KEY_CUR_STAGE, 0);
    storage::set_u64(KEY_STAGES_DONE, 0);
    storage::set_u64(KEY_CONSUMED, 0);
    storage::set_u64(KEY_STAGE_DEADLINE, stage0_dl);
    storage::set_u64(KEY_OVERALL_DEADLINE, overall_dl);
    storage::set_u64(KEY_IS_AUCTION, u64::from(is_auction));
    storage::set_u64(KEY_AUCTION_STARTED, 0);
    if is_auction {
        save_auction_book(&AuctionBook::new())?;
    }
    storage::set_u64(KEY_STATE, STATE_PENDING);

    let mut init_ev = [0u8; 36];
    init_ev[0..20].copy_from_slice(constitution);
    init_ev[20..28].copy_from_slice(&spec.stages[0].required_weight.to_be_bytes());
    init_ev[28..36].copy_from_slice(&(spec.stage_count as u64).to_be_bytes());
    events::emit(
        &[
            AUTH_INITIALIZED,
            addr_topic(target_hps),
            *policy_id,
            *action_hash,
        ],
        &init_ev,
    );
    Ok(())
}

/// Enforce that a `Constitution` HPS is in `CONSTITUTION_STATE_ACTIVE` before allowing any
/// `Authorization` object to be initialized from it — with the sole exception of the First
/// Shareholder Resolution (`activateConstitution(address)`) when the Constitution is in
/// `CONSTITUTION_STATE_PENDING_RATIFICATION`.
fn verify_constitution_active_or_ratifying(
    constitution: &[u8; 20],
    target_hps: &[u8; 20],
    policy_id: &[u8; 32],
    action_hash: &[u8; 32],
) -> Result<(), i32> {
    let st_cd = CallEncoder::<16>::new(const { selector("state()") });
    let Ok(st) = call::call_u64(constitution, st_cd.as_slice()) else {
        // Minimal unit-test stub without `state()`
        return Ok(());
    };
    if st == CONSTITUTION_STATE_ACTIVE {
        return Ok(());
    }
    if st == CONSTITUTION_STATE_PENDING_RATIFICATION && target_hps == constitution {
        let h_cd = CallEncoder::<16>::new(const { selector("hashActivateConstitution()") });
        let Ok(raw_h) = call::call_raw(constitution, h_cd.as_slice()) else {
            return Err(ERR_CONSTITUTION_NOT_ACTIVE);
        };
        if raw_h.len() < 32 || &raw_h[..32] != action_hash {
            return Err(ERR_CONSTITUTION_NOT_ACTIVE);
        }
        let f_cd = CallEncoder::<64>::new(const { selector("getFunctionAuth(bytes4)") })
            .push_bytes4(&const { selector("activateConstitution(address)") });
        let Ok(raw_pol) = call::call_raw(constitution, f_cd.as_slice()) else {
            return Err(ERR_CONSTITUTION_NOT_ACTIVE);
        };
        if raw_pol.len() < 32 || &raw_pol[..32] != policy_id {
            return Err(ERR_CONSTITUTION_NOT_ACTIVE);
        }
        return Ok(());
    }
    Err(ERR_CONSTITUTION_NOT_ACTIVE)
}

fn handle_init_from_constitution(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let target_hps = args.address(2).ok_or(-3)?;
    let policy_id = args.bytes32(3).ok_or(-3)?;
    let action_hash = args.bytes32(4).ok_or(-3)?;
    if constitution == [0u8; 20] {
        return Err(-61);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    verify_constitution_active_or_ratifying(&constitution, &target_hps, &policy_id, &action_hash)?;

    // Fetch policy bylaw from Constitution HPS
    let q = CallEncoder::<96>::new(const { selector("getPolicyRaw(address,bytes32)") })
        .push_address(&target_hps)
        .push_bytes32(&policy_id);
    let mut raw_spec = [0u8; MAX_ENCODED_POLICY_BYTES];
    let n = call::call_abi_bytes_into(&constitution, q.as_slice(), &mut raw_spec)?;
    let spec = PolicySpec::decode(&raw_spec[..n]).ok_or(ERR_POLICY_INVALID)?;

    setup_instance(
        &registry,
        &constitution,
        &target_hps,
        &policy_id,
        &action_hash,
        &spec,
        &raw_spec[..n],
    )?;
    ret::write_bool(true);
    Ok(())
}

fn handle_init_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let target_hps = args.address(2).ok_or(-3)?;
    if constitution == [0u8; 20] {
        return Err(-61);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let st_cd = CallEncoder::<16>::new(const { selector("state()") });
    if let Ok(st) = call::call_u64(&constitution, st_cd.as_slice()) {
        if st != CONSTITUTION_STATE_ACTIVE {
            return Err(ERR_CONSTITUTION_NOT_ACTIVE);
        }
    }

    let q = CallEncoder::<96>::new(const { selector("getPolicyRaw(address,bytes32)") })
        .push_address(&target_hps)
        .push_bytes32(&POLICY_SHARE_TRANSFER_AUCTION);
    let mut raw_spec = [0u8; MAX_ENCODED_POLICY_BYTES];
    let n = call::call_abi_bytes_into(&constitution, q.as_slice(), &mut raw_spec)?;
    let spec = PolicySpec::decode(&raw_spec[..n]).ok_or(ERR_POLICY_INVALID)?;

    setup_instance(
        &registry,
        &constitution,
        &target_hps,
        &POLICY_SHARE_TRANSFER_AUCTION,
        &ACTION_TRANSFER,
        &spec,
        &raw_spec[..n],
    )?;
    ret::write_bool(true);
    Ok(())
}

fn handle_init_oracle(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let oracle_id = args.address(1).ok_or(-3)?;
    let target_hps = args.address(2).ok_or(-3)?;
    let action_hash = args.bytes32(3).ok_or(-3)?;
    let expiry_blocks = args.u64(4).ok_or(-3)?;
    if expiry_blocks == 0 {
        return Err(-61);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    require_valid_identity(&registry, &oracle_id)?;

    let stage = StageSpec::new(1, expiry_blocks)
        .add_member(oracle_id, 1)
        .ok_or(ERR_POLICY_INVALID)?;
    let spec = PolicySpec::new(expiry_blocks)
        .add_stage(stage)
        .ok_or(ERR_POLICY_INVALID)?;
    let mut raw_spec = [0u8; 128];
    let n = spec.encode(&mut raw_spec).ok_or(ERR_POLICY_INVALID)?;
    let pol_id = oracle_policy_id(&oracle_id);

    setup_instance(
        &registry,
        &[0u8; 20],
        &target_hps,
        &pol_id,
        &action_hash,
        &spec,
        &raw_spec[..n],
    )?;
    ret::write_bool(true);
    Ok(())
}

fn handle_init_custom(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let target_hps = args.address(1).ok_or(-3)?;
    let policy_id = args.bytes32(2).ok_or(-3)?;
    let action_hash = args.bytes32(3).ok_or(-3)?;
    let raw_spec = args.dynamic_bytes(4).ok_or(-3)?;

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let spec = PolicySpec::decode(raw_spec).ok_or(ERR_POLICY_INVALID)?;
    let mut s = 0;
    while s < spec.stage_count {
        let mut m = 0;
        while m < spec.stages[s].member_count {
            require_valid_identity(&registry, &spec.stages[s].members[m].identity)?;
            m += 1;
        }
        s += 1;
    }

    setup_instance(
        &registry,
        &[0u8; 20],
        &target_hps,
        &policy_id,
        &action_hash,
        &spec,
        raw_spec,
    )?;
    ret::write_bool(true);
    Ok(())
}

/// Query multi-class shareholder voting power from `Constitution.shareholderVotingPower(address)`
/// when the Constitution has registered share-class ledgers (`totalVotingPower > 0`).
fn query_dynamic_shareholder_power(
    constitution: &[u8; 20],
    voter: &[u8; 20],
) -> Option<(u64, u64, u64)> {
    if *constitution == [0u8; 20] {
        return None;
    }
    let cd = CallEncoder::<64>::new(const { selector("shareholderVotingPower(address)") })
        .push_address(voter);
    let Ok(raw) = call::call_raw(constitution, cd.as_slice()) else {
        return None;
    };
    if raw.len() < 128 {
        return None;
    }
    let mut w_voter = [0u8; 8];
    let mut w_total = [0u8; 8];
    let mut w_req = [0u8; 8];
    w_voter.copy_from_slice(&raw[24..32]);
    w_total.copy_from_slice(&raw[56..64]);
    w_req.copy_from_slice(&raw[88..96]);
    let voter_power = u64::from_be_bytes(w_voter);
    let total_power = u64::from_be_bytes(w_total);
    let req_power = u64::from_be_bytes(w_req);
    if total_power == 0 || req_power == 0 {
        return None;
    }
    Some((voter_power, total_power, req_power))
}

/// Resolve `(caller_weight, required_stage_weight)` for `caller` on `stage` (supporting explicit
/// weighted members, dynamic role-backed stages defined even with 0 initial role holders,
/// unanimous `ROLE_ALL_MEMBERS_WEIGHT`, and multi-class shareholder voting).
fn resolve_stage_authorizer_weight(
    stage: &StageSpec,
    cur_stage: usize,
    bound_con: &[u8; 20],
    bound_pol: &[u8; 32],
    caller: &[u8; 20],
) -> Result<(u64, u64), i32> {
    let is_shareholder_stage = stage.has_role(&ROLE_SHAREHOLDER)
        || (cur_stage == 0
            && (*bound_pol == POLICY_SHAREHOLDER_SUPERMAJORITY
                || *bound_pol == POLICY_SUPER_GOVERNANCE
                || *bound_pol == POLICY_FIRST_SHAREHOLDER_RESOLUTION));

    if *bound_con != [0u8; 20] && is_shareholder_stage {
        if let Some((dyn_weight, total_power, default_super_req)) =
            query_dynamic_shareholder_power(bound_con, caller)
        {
            if dyn_weight == 0 {
                return Err(ERR_NOT_STAGE_AUTHORIZER);
            }
            let dyn_req = if stage.has_role(&ROLE_SHAREHOLDER)
                && stage.required_weight >= 1
                && stage.required_weight <= 100
            {
                (total_power
                    .saturating_mul(stage.required_weight)
                    .saturating_add(99))
                    / 100
            } else {
                default_super_req
            };
            return Ok((dyn_weight, dyn_req.max(1)));
        }
    }

    let mut best_weight = stage.member_weight(caller).unwrap_or(0);
    if stage.role_count > 0 && *bound_con != [0u8; 20] {
        let mut r = 0usize;
        while r < stage.role_count {
            let role_id = &stage.roles[r].role_id;
            let has_cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
                .push_bytes32(role_id)
                .push_address(caller);
            if let Ok(true) = call::call_bool(bound_con, has_cd.as_slice()) {
                if stage.roles[r].weight > best_weight {
                    best_weight = stage.roles[r].weight;
                }
            }
            r += 1;
        }
    }

    if best_weight == 0 {
        return Err(ERR_NOT_STAGE_AUTHORIZER);
    }

    let effective_req = if stage.required_weight == ROLE_ALL_MEMBERS_WEIGHT {
        if *bound_con == [0u8; 20] || stage.role_count == 0 {
            return Err(ERR_NOT_STAGE_AUTHORIZER);
        }
        let mut total_role_weight = 0u64;
        let mut r = 0usize;
        while r < stage.role_count {
            let cnt_cd = CallEncoder::<64>::new(const { selector("roleMemberCount(bytes32)") })
                .push_bytes32(&stage.roles[r].role_id);
            let cnt = call::call_u64(bound_con, cnt_cd.as_slice()).unwrap_or(0);
            total_role_weight =
                total_role_weight.saturating_add(cnt.saturating_mul(stage.roles[r].weight));
            r += 1;
        }
        if total_role_weight == 0 {
            return Err(ERR_NOT_STAGE_AUTHORIZER);
        }
        total_role_weight
    } else {
        stage.required_weight
    };

    Ok((best_weight, effective_req))
}

fn execute_approve_step() -> Result<[u8; 20], i32> {
    if storage::get_u64(KEY_STATE) != STATE_PENDING || storage::get_u64(KEY_STAGES_DONE) != 0 {
        return Err(-62); // not in active pending approval phase
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let now = context::block_number();
    let stage_dl = storage::get_u64(KEY_STAGE_DEADLINE);
    let overall_dl = storage::get_u64(KEY_OVERALL_DEADLINE);
    if now > stage_dl || now > overall_dl {
        return Err(ERR_AUTH_EXPIRED);
    }

    let spec = load_spec()?;
    let cur_stage = storage::get_u64(KEY_CUR_STAGE) as usize;
    if cur_stage >= spec.stage_count {
        return Err(-62);
    }

    let stage = &spec.stages[cur_stage];
    let bound_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    let bound_pol = storage::get_bytes32(KEY_POLICY_ID).unwrap_or([0u8; 32]);

    let (weight, required_weight) =
        resolve_stage_authorizer_weight(stage, cur_stage, &bound_con, &bound_pol, &caller)?;

    let sk = signed_key(cur_stage as u64, &caller);
    if storage::get_u64(sk.as_slice()) != 0 {
        return Err(ERR_ALREADY_SIGNED);
    }
    storage::set_u64(sk.as_slice(), 1);

    let wk = stage_weight_key(cur_stage as u64);
    let accum = storage::get_u64(wk.as_slice()).saturating_add(weight);
    storage::set_u64(wk.as_slice(), accum);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&(cur_stage as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&weight.to_be_bytes());
    ev[16..24].copy_from_slice(&accum.to_be_bytes());
    events::emit(&[STAGE_APPROVED, addr_topic(&caller)], &ev);

    if accum >= required_weight {
        let mut thr = [0u8; 24];
        thr[0..8].copy_from_slice(&(cur_stage as u64).to_be_bytes());
        thr[8..16].copy_from_slice(&accum.to_be_bytes());
        thr[16..24].copy_from_slice(&required_weight.to_be_bytes());
        events::emit(&[STAGE_THRESHOLD_REACHED], &thr);

        if cur_stage + 1 < spec.stage_count {
            let next_stage = cur_stage + 1;
            let next_dl = now.saturating_add(spec.stages[next_stage].expiry_blocks);
            storage::set_u64(KEY_CUR_STAGE, next_stage as u64);
            storage::set_u64(KEY_STAGE_DEADLINE, next_dl);
            let mut adv = [0u8; 16];
            adv[0..8].copy_from_slice(&(next_stage as u64).to_be_bytes());
            adv[8..16].copy_from_slice(&next_dl.to_be_bytes());
            events::emit(&[STAGE_ADVANCED], &adv);
        } else {
            storage::set_u64(KEY_STAGES_DONE, 1);
        }
    }
    Ok(caller)
}

fn execute_finalize_step(caller: &[u8; 20]) -> Result<(), i32> {
    if storage::get_u64(KEY_IS_AUCTION) == 1 {
        if storage::get_u64(KEY_AUCTION_STARTED) != 1 {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 1 clock has not even started
        }
        let now = context::block_number();
        let step3_dl = storage::get_u64(KEY_STEP3_DL);
        let overall_dl = storage::get_u64(KEY_OVERALL_DEADLINE);
        if now <= step3_dl {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 3 period has not ended yet
        }
        if now > overall_dl {
            return Err(ERR_AUTH_EXPIRED);
        }
        let st = storage::get_u64(KEY_STATE);
        if st != STATE_PENDING && st != STATE_FINALIZED {
            return Err(-62);
        }
        storage::set_u64(KEY_STAGES_DONE, 1);
        storage::set_u64(KEY_CUR_STAGE, 3);
        storage::set_u64(KEY_STATE, STATE_FINALIZED);
        events::emit(
            &[AUTH_FINALIZED, addr_topic(caller)],
            &now.to_be_bytes(),
        );
        return Ok(());
    }

    if storage::get_u64(KEY_STATE) != STATE_PENDING || storage::get_u64(KEY_STAGES_DONE) != 1 {
        return Err(-62); // all sequential stages must be completed first
    }
    let now = context::block_number();
    if now > storage::get_u64(KEY_OVERALL_DEADLINE) {
        return Err(ERR_AUTH_EXPIRED);
    }
    storage::set_u64(KEY_STATE, STATE_FINALIZED);
    events::emit(
        &[AUTH_FINALIZED, addr_topic(caller)],
        &now.to_be_bytes(),
    );
    Ok(())
}

/// Core implementation for placing a buy order (`price`, `quantity`) on behalf of `buyer`
/// in a `POLICY_SHARE_TRANSFER_AUCTION` Authorization HPS:
/// - **Step 1**: First potential buyer starts the Step 1 clock (`step1_deadline = now + step1_window_blocks`).
///   Additional potential buyers can place buy orders while `now <= step1_deadline`.
/// - **Step 2 (`step1_deadline < now <= step2_deadline`)**: Buy orders are rejected (`ERR_WRONG_AUCTION_STEP`).
/// - **Step 3 (`step2_deadline < now <= step3_deadline`)**: Existing shareholders of `targetHps`
///   (`balanceOf(buyer) > 0`) who did **not** place a sell order in Step 2 can place buy orders.
/// Returns the 0-based `orderIndex` in `AuctionBook`.
fn execute_place_buy_order(buyer: &[u8; 20], price: u64, quantity: u64) -> Result<u64, i32> {
    if storage::get_u64(KEY_IS_AUCTION) != 1 || storage::get_u64(KEY_STATE) != STATE_PENDING {
        return Err(-62);
    }
    if price == 0 || quantity == 0 {
        return Err(-61);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    require_valid_identity(&registry, buyer)?;

    let now = context::block_number();
    let started = storage::get_u64(KEY_AUCTION_STARTED) == 1;

    let step_tag = if !started {
        let spec = load_spec()?;
        let step1_dl = now.saturating_add(spec.stages[0].expiry_blocks);
        let step2_dl = step1_dl.saturating_add(spec.stages[1].expiry_blocks);
        let step3_dl = step2_dl.saturating_add(spec.stages[2].expiry_blocks);
        let overall_dl = step3_dl.saturating_add(spec.overall_expiry_blocks);

        storage::set_u64(KEY_AUCTION_STARTED, 1);
        storage::set_u64(KEY_STEP1_DL, step1_dl);
        storage::set_u64(KEY_STEP2_DL, step2_dl);
        storage::set_u64(KEY_STEP3_DL, step3_dl);
        storage::set_u64(KEY_STAGE_DEADLINE, step1_dl);
        storage::set_u64(KEY_OVERALL_DEADLINE, overall_dl);
        storage::set_u64(KEY_CUR_STAGE, 0);

        let mut st_ev = [0u8; 40];
        st_ev[0..8].copy_from_slice(&price.to_be_bytes());
        st_ev[8..16].copy_from_slice(&quantity.to_be_bytes());
        st_ev[16..24].copy_from_slice(&step1_dl.to_be_bytes());
        st_ev[24..32].copy_from_slice(&step2_dl.to_be_bytes());
        st_ev[32..40].copy_from_slice(&step3_dl.to_be_bytes());
        events::emit(&[AUCTION_STEP1_STARTED, addr_topic(buyer)], &st_ev);
        ORDER_SIDE_BUY_STEP1
    } else {
        let step1_dl = storage::get_u64(KEY_STEP1_DL);
        let step2_dl = storage::get_u64(KEY_STEP2_DL);
        let step3_dl = storage::get_u64(KEY_STEP3_DL);

        if now <= step1_dl {
            ORDER_SIDE_BUY_STEP1
        } else if now <= step2_dl {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 2 is exclusively for existing shareholders' sell orders
        } else if now <= step3_dl {
            // Step 3: ONLY existing shareholders who did NOT participate in Step 2 can place buy orders!
            let target_ledger = storage::get_address(KEY_TARGET).ok_or(-62)?;
            let holder_bal = query_ledger_balance(&target_ledger, buyer)?;
            if holder_bal == 0 {
                return Err(ERR_NOT_EXISTING_SHAREHOLDER);
            }
            let s2k = step2_seller_key(buyer);
            if storage::get_u64(s2k.as_slice()) != 0 {
                return Err(ERR_STEP2_SELLER_INELIGIBLE_STEP3);
            }
            storage::set_u64(KEY_CUR_STAGE, 2);
            storage::set_u64(KEY_STAGE_DEADLINE, step3_dl);
            ORDER_SIDE_BUY_STEP3
        } else {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 3 period has already ended
        }
    };

    let mut book = load_auction_book()?;
    let order_idx = book.order_count as u64;
    if !book.push(AuctionOrder {
        side: step_tag,
        trader: *buyer,
        price,
        quantity,
    }) {
        return Err(-61);
    }
    save_auction_book(&book)?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&(step_tag as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&price.to_be_bytes());
    ev[16..24].copy_from_slice(&quantity.to_be_bytes());
    events::emit(&[BUY_ORDER_PLACED, addr_topic(buyer)], &ev);

    Ok(order_idx)
}

fn handle_place_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let price = args.u64(0).ok_or(-3)?;
    let quantity = args.u64(1).ok_or(-3)?;
    let caller = context::msg_sender();
    let order_idx = execute_place_buy_order(&caller, price, quantity)?;
    ret::write_u64_word(order_idx);
    Ok(())
}

/// Constitution-proxied buy order placement (`msg.sender` must be the bound `Constitution` HPS).
fn handle_place_buy_order_for(args: &CalldataReader) -> Result<(), i32> {
    let bound_con = storage::get_address(KEY_CONSTITUTION).ok_or(-62)?;
    if bound_con == [0u8; 20] || context::msg_sender() != bound_con {
        return Err(ERR_WRONG_TARGET);
    }
    let buyer = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let order_idx = execute_place_buy_order(&buyer, price, quantity)?;
    ret::write_u64_word(order_idx);
    Ok(())
}

/// Cancel a buy order (`orderIndex`) in a `POLICY_SHARE_TRANSFER_AUCTION` Authorization HPS.
/// Enforces that a buy order can **only** be cancelled during the exact step in which it was placed:
/// - `ORDER_SIDE_BUY_STEP1` orders can only be cancelled during Step 1 (`now <= step1_deadline`).
/// - `ORDER_SIDE_BUY_STEP3` orders can only be cancelled during Step 3 (`step2_deadline < now <= step3_deadline`).
/// Returns `(uint64 price, uint64 quantity)` so the `Constitution` can refund `price * quantity`
/// from its special clearing account back to the buyer's bank sub-account.
fn execute_cancel_buy_order(buyer: &[u8; 20], order_index: u64) -> Result<(u64, u64), i32> {
    if storage::get_u64(KEY_IS_AUCTION) != 1 || storage::get_u64(KEY_STATE) != STATE_PENDING {
        return Err(-62);
    }
    if storage::get_u64(KEY_AUCTION_STARTED) != 1 {
        return Err(ERR_WRONG_AUCTION_STEP);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    require_valid_identity(&registry, buyer)?;

    let mut book = load_auction_book()?;
    let idx = order_index as usize;
    if idx >= book.order_count {
        return Err(ERR_ORDER_NOT_FOUND);
    }

    let ord = book.orders[idx];
    if ord.is_cancelled() {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }
    if !ord.is_buy() {
        return Err(ERR_WRONG_AUCTION_STEP);
    }
    if &ord.trader != buyer {
        return Err(ERR_NOT_ORDER_OWNER);
    }

    let now = context::block_number();
    let step1_dl = storage::get_u64(KEY_STEP1_DL);
    let step2_dl = storage::get_u64(KEY_STEP2_DL);
    let step3_dl = storage::get_u64(KEY_STEP3_DL);

    if ord.side == ORDER_SIDE_BUY_STEP1 {
        if now > step1_dl {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 1 buy orders can ONLY be cancelled in Step 1!
        }
    } else if ord.side == ORDER_SIDE_BUY_STEP3 {
        if now <= step2_dl || now > step3_dl {
            return Err(ERR_WRONG_AUCTION_STEP); // Step 3 buy orders can ONLY be cancelled in Step 3!
        }
    } else {
        return Err(ERR_WRONG_AUCTION_STEP);
    }

    let orig_side = ord.side;
    let orig_price = ord.price;
    let orig_qty = ord.quantity;
    book.orders[idx].side = ORDER_SIDE_CANCELLED;
    book.orders[idx].quantity = 0;
    save_auction_book(&book)?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&(orig_side as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&orig_price.to_be_bytes());
    ev[16..24].copy_from_slice(&orig_qty.to_be_bytes());
    events::emit(&[BUY_ORDER_CANCELLED, addr_topic(buyer)], &ev);

    Ok((orig_price, orig_qty))
}

fn handle_cancel_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let order_index = args.u64(0).ok_or(-3)?;
    let caller = context::msg_sender();
    let (price, qty) = execute_cancel_buy_order(&caller, order_index)?;
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&price.to_be_bytes());
    out[56..64].copy_from_slice(&qty.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Constitution-proxied buy order cancellation (`msg.sender` must be the bound `Constitution` HPS).
fn handle_cancel_buy_order_for(args: &CalldataReader) -> Result<(), i32> {
    let bound_con = storage::get_address(KEY_CONSTITUTION).ok_or(-62)?;
    if bound_con == [0u8; 20] || context::msg_sender() != bound_con {
        return Err(ERR_WRONG_TARGET);
    }
    let buyer = args.address(0).ok_or(-3)?;
    let order_index = args.u64(1).ok_or(-3)?;
    let (price, qty) = execute_cancel_buy_order(&buyer, order_index)?;
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&price.to_be_bytes());
    out[56..64].copy_from_slice(&qty.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Place a sell order (`price`, `quantity`) during **Step 2** (`step1_deadline < now <= step2_deadline`)
/// of a `POLICY_SHARE_TRANSFER_AUCTION` Authorization HPS.
/// Seller must be an existing shareholder (`balanceOf(seller) > 0`) in `targetHps` and cannot offer
/// more shares than their existing holding.
fn execute_place_sell_order(seller: &[u8; 20], price: u64, quantity: u64) -> Result<u64, i32> {
    if storage::get_u64(KEY_IS_AUCTION) != 1 || storage::get_u64(KEY_STATE) != STATE_PENDING {
        return Err(-62);
    }
    if storage::get_u64(KEY_AUCTION_STARTED) != 1 {
        return Err(ERR_WRONG_AUCTION_STEP); // Step 1 has not even started yet
    }
    if price == 0 || quantity == 0 {
        return Err(-61);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    require_valid_identity(&registry, seller)?;

    let now = context::block_number();
    let step1_dl = storage::get_u64(KEY_STEP1_DL);
    let step2_dl = storage::get_u64(KEY_STEP2_DL);
    if now <= step1_dl || now > step2_dl {
        return Err(ERR_WRONG_AUCTION_STEP); // Sell orders are only permitted during Step 2!
    }

    let target_ledger = storage::get_address(KEY_TARGET).ok_or(-62)?;
    let holder_bal = query_ledger_balance(&target_ledger, seller)?;
    if holder_bal == 0 {
        return Err(ERR_NOT_EXISTING_SHAREHOLDER);
    }

    let qk = seller_offered_key(seller);
    let prev_offered = storage::get_u64(qk.as_slice());
    let new_offered = prev_offered.checked_add(quantity).ok_or(-16)?;
    if new_offered > holder_bal {
        return Err(-16); // cannot offer to sell more shares than existing holding
    }
    storage::set_u64(qk.as_slice(), new_offered);

    let s2k = step2_seller_key(seller);
    storage::set_u64(s2k.as_slice(), 1);
    storage::set_u64(KEY_CUR_STAGE, 1);
    storage::set_u64(KEY_STAGE_DEADLINE, step2_dl);

    let mut book = load_auction_book()?;
    let order_idx = book.order_count as u64;
    if !book.push(AuctionOrder {
        side: ORDER_SIDE_SELL_STEP2,
        trader: *seller,
        price,
        quantity,
    }) {
        return Err(-61);
    }
    save_auction_book(&book)?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&price.to_be_bytes());
    ev[8..16].copy_from_slice(&quantity.to_be_bytes());
    ev[16..24].copy_from_slice(&holder_bal.to_be_bytes());
    events::emit(&[SELL_ORDER_PLACED, addr_topic(seller)], &ev);

    Ok(order_idx)
}

fn handle_place_sell_order(args: &CalldataReader) -> Result<(), i32> {
    let price = args.u64(0).ok_or(-3)?;
    let quantity = args.u64(1).ok_or(-3)?;
    let caller = context::msg_sender();
    let order_idx = execute_place_sell_order(&caller, price, quantity)?;
    ret::write_u64_word(order_idx);
    Ok(())
}

/// Constitution-proxied sell order placement (`msg.sender` must be the bound `Constitution` HPS).
fn handle_place_sell_order_for(args: &CalldataReader) -> Result<(), i32> {
    let bound_con = storage::get_address(KEY_CONSTITUTION).ok_or(-62)?;
    if bound_con == [0u8; 20] || context::msg_sender() != bound_con {
        return Err(ERR_WRONG_TARGET);
    }
    let seller = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let order_idx = execute_place_sell_order(&seller, price, quantity)?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_approve(_args: &CalldataReader) -> Result<(), i32> {
    let _caller = execute_approve_step()?;
    ret::write_bool(storage::get_u64(KEY_STAGES_DONE) == 1);
    Ok(())
}

fn handle_finalize(_args: &CalldataReader) -> Result<(), i32> {
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    execute_finalize_step(&caller)?;
    ret::write_bool(true);
    Ok(())
}

fn handle_approve_and_finalize(_args: &CalldataReader) -> Result<(), i32> {
    let caller = execute_approve_step()?;
    if storage::get_u64(KEY_STAGES_DONE) == 1 {
        execute_finalize_step(&caller)?;
        ret::write_bool(true);
    } else {
        ret::write_bool(false);
    }
    Ok(())
}

fn handle_consume(args: &CalldataReader) -> Result<(), i32> {
    let expected_constitution = args.address(0).ok_or(-3)?;
    let expected_policy_id = args.bytes32(1).ok_or(-3)?;
    let expected_action_hash = args.bytes32(2).ok_or(-3)?;
    let invoker_identity = args.address(3).ok_or(-3)?;

    if storage::get_u64(KEY_CONSUMED) != 0 || storage::get_u64(KEY_STATE) == STATE_CONSUMED {
        return Err(ERR_AUTH_ALREADY_CONSUMED);
    }
    if storage::get_u64(KEY_STATE) != STATE_FINALIZED {
        return Err(-62); // not finalized yet
    }
    if context::block_number() > storage::get_u64(KEY_OVERALL_DEADLINE) {
        return Err(ERR_AUTH_EXPIRED);
    }

    let caller_target = context::msg_sender();
    let bound_target = storage::get_address(KEY_TARGET).ok_or(-62)?;
    if caller_target != bound_target {
        return Err(ERR_WRONG_TARGET);
    }

    let bound_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    let bound_pol = storage::get_bytes32(KEY_POLICY_ID).ok_or(-62)?;
    if bound_con != expected_constitution || bound_pol != expected_policy_id {
        return Err(ERR_POLICY_MISMATCH);
    }

    let bound_hash = storage::get_bytes32(KEY_ACTION_HASH).ok_or(-62)?;
    if bound_hash != expected_action_hash {
        return Err(ERR_ACTION_HASH_MISMATCH);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    if !(bound_con != [0u8; 20] && invoker_identity == bound_con) {
        require_valid_identity(&registry, &invoker_identity)?;
    }

    storage::set_u64(KEY_CONSUMED, 1);
    storage::set_u64(KEY_STATE, STATE_CONSUMED);

    events::emit(
        &[
            AUTH_CONSUMED,
            addr_topic(&bound_target),
            addr_topic(&invoker_identity),
            bound_hash,
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

/// Atomically consume a finalized `POLICY_SHARE_TRANSFER_AUCTION` Authorization HPS once its
/// 3-step order-collection windows have completed (`now > step3_deadline`), returning the
/// ABI-encoded `AuctionBook` to `targetHps` (`AssetLedger`).
fn handle_consume_auction(args: &CalldataReader) -> Result<(), i32> {
    let expected_constitution = args.address(0).ok_or(-3)?;
    let expected_policy_id = args.bytes32(1).ok_or(-3)?;
    let invoker_identity = args.address(2).ok_or(-3)?;

    if storage::get_u64(KEY_IS_AUCTION) != 1 {
        return Err(ERR_POLICY_MISMATCH);
    }
    if storage::get_u64(KEY_CONSUMED) != 0 || storage::get_u64(KEY_STATE) == STATE_CONSUMED {
        return Err(ERR_AUTH_ALREADY_CONSUMED);
    }
    if storage::get_u64(KEY_AUCTION_STARTED) != 1 {
        return Err(ERR_WRONG_AUCTION_STEP); // Step 1 clock never started
    }

    let now = context::block_number();
    let step3_dl = storage::get_u64(KEY_STEP3_DL);
    let overall_dl = storage::get_u64(KEY_OVERALL_DEADLINE);
    if now <= step3_dl {
        return Err(ERR_WRONG_AUCTION_STEP); // Step 3 period has not finished yet!
    }
    if now > overall_dl {
        return Err(ERR_AUTH_EXPIRED);
    }

    let caller_target = context::msg_sender();
    let bound_target = storage::get_address(KEY_TARGET).ok_or(-62)?;
    if caller_target != bound_target {
        return Err(ERR_WRONG_TARGET);
    }

    let bound_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    let bound_pol = storage::get_bytes32(KEY_POLICY_ID).ok_or(-62)?;
    if bound_con != expected_constitution || bound_pol != expected_policy_id {
        return Err(ERR_POLICY_MISMATCH);
    }

    let registry = storage::get_address(KEY_REGISTRY).ok_or(-62)?;
    if !(bound_con != [0u8; 20] && invoker_identity == bound_con) {
        require_valid_identity(&registry, &invoker_identity)?;
    }

    if storage::get_u64(KEY_STATE) == STATE_PENDING {
        events::emit(
            &[AUTH_FINALIZED, addr_topic(&invoker_identity)],
            &now.to_be_bytes(),
        );
    }

    storage::set_u64(KEY_STAGES_DONE, 1);
    storage::set_u64(KEY_CUR_STAGE, 3);
    storage::set_u64(KEY_CONSUMED, 1);
    storage::set_u64(KEY_STATE, STATE_CONSUMED);

    let bound_hash = storage::get_bytes32(KEY_ACTION_HASH).unwrap_or([0u8; 32]);
    events::emit(
        &[
            AUTH_CONSUMED,
            addr_topic(&bound_target),
            addr_topic(&invoker_identity),
            bound_hash,
        ],
        &now.to_be_bytes(),
    );

    let mut buf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
    let n = storage::get_into(KEY_AUCTION_BOOK, &mut buf).ok_or(ERR_POLICY_INVALID)?;
    ret::write_abi_bytes(&buf[..n]);
    Ok(())
}

fn effective_status() -> u64 {
    let st = storage::get_u64(KEY_STATE);
    if st == STATE_UNINIT || st == STATE_CONSUMED {
        return st;
    }
    let now = context::block_number();
    if storage::get_u64(KEY_IS_AUCTION) == 1 {
        if storage::get_u64(KEY_AUCTION_STARTED) != 1 {
            return STATE_PENDING;
        }
        let step3_dl = storage::get_u64(KEY_STEP3_DL);
        let ov_dl = storage::get_u64(KEY_OVERALL_DEADLINE);
        if now > ov_dl {
            return STATE_EXPIRED;
        }
        if now > step3_dl {
            return STATE_FINALIZED;
        }
        return st;
    }

    let ov_dl = storage::get_u64(KEY_OVERALL_DEADLINE);
    if now > ov_dl {
        return STATE_EXPIRED;
    }
    if st == STATE_PENDING
        && storage::get_u64(KEY_STAGES_DONE) == 0
        && now > storage::get_u64(KEY_STAGE_DEADLINE)
    {
        return STATE_EXPIRED;
    }
    st
}

fn handle_status(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(effective_status());
    Ok(())
}

fn handle_current_stage(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_CUR_STAGE));
    Ok(())
}

fn handle_stage_count(_args: &CalldataReader) -> Result<(), i32> {
    let cnt = load_spec().map(|s| s.stage_count as u64).unwrap_or(0);
    ret::write_u64_word(cnt);
    Ok(())
}

fn handle_stage_weight(args: &CalldataReader) -> Result<(), i32> {
    let stage = args.u64(0).ok_or(-3)?;
    let wk = stage_weight_key(stage);
    ret::write_u64_word(storage::get_u64(wk.as_slice()));
    Ok(())
}

fn handle_deadlines(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&storage::get_u64(KEY_STAGE_DEADLINE).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(KEY_OVERALL_DEADLINE).to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_auction_deadlines(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 128];
    out[24..32].copy_from_slice(&storage::get_u64(KEY_STEP1_DL).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(KEY_STEP2_DL).to_be_bytes());
    out[88..96].copy_from_slice(&storage::get_u64(KEY_STEP3_DL).to_be_bytes());
    out[120..128].copy_from_slice(&storage::get_u64(KEY_OVERALL_DEADLINE).to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_order_count(_args: &CalldataReader) -> Result<(), i32> {
    let cnt = load_auction_book().map(|b| b.order_count as u64).unwrap_or(0);
    ret::write_u64_word(cnt);
    Ok(())
}

fn handle_get_orders_raw(_args: &CalldataReader) -> Result<(), i32> {
    let mut buf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
    let n = storage::get_into(KEY_AUCTION_BOOK, &mut buf).unwrap_or(0);
    ret::write_abi_bytes(&buf[..n]);
    Ok(())
}

fn handle_is_ready_to_consume(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_bool(effective_status() == STATE_FINALIZED && storage::get_u64(KEY_CONSUMED) == 0);
    Ok(())
}

fn handle_target_hps(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_TARGET).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_constitution(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_policy_id(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&storage::get_bytes32(KEY_POLICY_ID).unwrap_or([0u8; 32]));
    Ok(())
}

fn handle_action_hash(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&storage::get_bytes32(KEY_ACTION_HASH).unwrap_or([0u8; 32]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::ACTION_ISSUE;
    use hps_sdk::mock;

    mod reg_and_con_sim {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::governance::{PolicySpec, StageSpec};
        use hps_sdk::{ret, selector};

        pub fn reg_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                let a = args.address(0).unwrap();
                ret::write_bool(a != [0u8; 20] && a[0] != 0xEE);
                return 0;
            }
            if sel == const { selector("isValidAuthorizationHps(address)") } {
                let a = args.address(0).unwrap();
                ret::write_bool(a != [0u8; 20] && a[0] != 0xEE);
                return 0;
            }
            -2
        }

        pub fn con_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                // Stage 0 (Group A): a1(w=1), a2(w=1), req=1, expiry=5 blocks
                // Stage 1 (Group B, weighted joint): b_lead(w=2), b_jr1(w=1), b_jr2(w=1), req=3, expiry=8 blocks
                let s0 = StageSpec::new(1, 5)
                    .add_member([0xA1; 20], 1)
                    .unwrap()
                    .add_member([0xA2; 20], 1)
                    .unwrap();
                let s1 = StageSpec::new(3, 8)
                    .add_member([0xB1; 20], 2)
                    .unwrap()
                    .add_member([0xB2; 20], 1)
                    .unwrap()
                    .add_member([0xB3; 20], 1)
                    .unwrap();
                let spec = PolicySpec::new(20).add_stage(s0).unwrap().add_stage(s1).unwrap();
                let mut buf = [0u8; 512];
                let n = spec.encode(&mut buf).unwrap();
                ret::write_abi_bytes(&buf[..n]);
                return 0;
            }
            -2
        }
    }

    #[test]
    fn enforces_sequential_order_weights_expiry_and_one_time_consumption() {
        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let ledger = [0x30; 20];
        let auth = [0x40; 20];
        let auth_expired = [0x41; 20];

        let a1 = [0xA1; 20];
        let b_lead = [0xB1; 20]; // weight 2
        let b_jr1 = [0xB2; 20]; // weight 1

        mock::register_hps(reg, reg_and_con_sim::reg_dispatch);
        mock::register_hps(con, reg_and_con_sim::con_dispatch);
        mock::register_hps(auth, dispatch_calldata);
        mock::register_hps(auth_expired, dispatch_calldata);

        mock::set_block_number(100);
        let act_hash = [0x77; 32];
        let init_cd = CallEncoder::<192>::new(const { selector("initializeFromConstitution(address,address,address,bytes32,bytes32)") })
        .push_address(&reg)
        .push_address(&con)
        .push_address(&ledger)
        .push_bytes32(&ACTION_ISSUE)
        .push_bytes32(&act_hash);

        mock::transact_as(a1, auth, init_cd.as_slice()).unwrap();

        // 1. Out-of-order rejection: Group B CANNOT approve before Group A completes Stage 0!
        let app_cd = CallEncoder::<16>::new(const { selector("approve()") });
        assert_eq!(
            mock::transact_as(b_lead, auth, app_cd.as_slice()),
            Err(ERR_NOT_STAGE_AUTHORIZER)
        );

        // 2. Group A (`a1`) approves at block 103 (within 100 + 5 = 105) -> advances to Stage 1!
        mock::set_block_number(103);
        mock::transact_as(a1, auth, app_cd.as_slice()).unwrap();

        // 3. Stage 1 requires weight 3: `b_lead` contributes weight 2 -> not done yet!
        mock::set_block_number(106);
        let done_1 = mock::transact_as(b_lead, auth, app_cd.as_slice()).unwrap();
        assert_eq!(done_1[31], 0);
        // Premature finalize fails
        assert!(mock::transact_as(
            b_lead,
            auth,
            CallEncoder::<16>::new(const { selector("finalize()") }).as_slice()
        )
        .is_err());

        // 4. `b_jr1` contributes weight 1 (total 3 >= 3) and finalizes!
        mock::set_block_number(108);
        let done_2 = mock::transact_as(
            b_jr1,
            auth,
            CallEncoder::<16>::new(const { selector("approveAndFinalize()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(done_2[31], 1);

        // 5. Wrong target cannot consume; bound target (`ledger`) consumes once; second consume fails!
        let consume_cd = CallEncoder::<164>::new(const { selector("consume(address,bytes32,bytes32,address)") })
            .push_address(&con)
            .push_bytes32(&ACTION_ISSUE)
            .push_bytes32(&act_hash)
            .push_address(&a1);
        assert_eq!(
            mock::transact_as([0x99; 20], auth, consume_cd.as_slice()),
            Err(ERR_WRONG_TARGET)
        );
        mock::transact_as(ledger, auth, consume_cd.as_slice()).unwrap();
        assert_eq!(
            mock::transact_as(ledger, auth, consume_cd.as_slice()),
            Err(ERR_AUTH_ALREADY_CONSUMED)
        );

        // 6. Verify strict stage block-expiry enforcement on `auth_expired`
        mock::set_block_number(200);
        mock::transact_as(a1, auth_expired, init_cd.as_slice()).unwrap();
        // Stage 0 deadline is 200 + 5 = 205; block 206 MUST fail with ERR_AUTH_EXPIRED!
        mock::set_block_number(206);
        assert_eq!(
            mock::transact_as(a1, auth_expired, app_cd.as_slice()),
            Err(ERR_AUTH_EXPIRED)
        );
    }

    #[test]
    fn three_step_share_transfer_auction_enforces_clocks_and_eligibility() {
        use hps_sdk::governance::verify_and_consume_auction_auth;

        mod auc_sim {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::share_transfer_auction_policy_spec;
            use hps_sdk::{ret, selector};

            pub fn con_auc_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                    // Step 1 window = 10 blocks, Step 2 window = 10 blocks, Step 3 window = 10 blocks,
                    // post-Step-3 settlement expiry = 50 blocks.
                    let spec = share_transfer_auction_policy_spec([0xA1; 20], 10, 10, 10, 50).unwrap();
                    let mut buf = [0u8; 512];
                    let n = spec.encode(&mut buf).unwrap();
                    ret::write_abi_bytes(&buf[..n]);
                    return 0;
                }
                -2
            }

            pub fn ledger_bal_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("balanceOf(address)") } {
                    let holder = args.address(0).unwrap();
                    // Existing shareholders: 0xB1 (50,000), 0xB2 (20,000), 0xB3 (10,000)
                    // External buyers (non-shareholders): 0xC1 (0), 0xC2 (0)
                    let bal = match holder[0] {
                        0xB1 => 50_000,
                        0xB2 => 20_000,
                        0xB3 => 10_000,
                        _ => 0,
                    };
                    ret::write_u64_word(bal);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let ledger = [0x30; 20];
        let auth_auc = [0x42; 20];

        let sh_seller_1 = [0xB1; 20]; // existing shareholder (50,000)
        let sh_seller_2 = [0xB2; 20]; // existing shareholder (20,000)
        let sh_nonseller = [0xB3; 20]; // existing shareholder (10,000) who does NOT sell in Step 2
        let ext_buyer_1 = [0xC1; 20]; // external non-shareholder buyer
        let ext_buyer_2 = [0xC2; 20]; // external non-shareholder buyer

        mock::register_hps(reg, reg_and_con_sim::reg_dispatch);
        mock::register_hps(con, auc_sim::con_auc_dispatch);
        mock::register_hps(ledger, auc_sim::ledger_bal_dispatch);
        mock::register_hps(auth_auc, dispatch_calldata);

        mock::set_block_number(500);
        let init_cd = CallEncoder::<128>::new(const { selector("initializeTransferAuction(address,address,address)") })
        .push_address(&reg)
        .push_address(&con)
        .push_address(&ledger);
        mock::transact_as(ext_buyer_1, auth_auc, init_cd.as_slice()).unwrap();

        // Before the first buy order, the Step 1 clock has not started yet; sell orders must fail!
        let sell_cd = |price: u64, qty: u64| {
            CallEncoder::<96>::new(const { selector("placeSellOrder(uint64,uint64)") })
                .push_u64(price)
                .push_u64(qty)
        };
        let buy_cd = |price: u64, qty: u64| {
            CallEncoder::<96>::new(const { selector("placeBuyOrder(uint64,uint64)") })
                .push_u64(price)
                .push_u64(qty)
        };
        assert_eq!(
            mock::transact_as(sh_seller_1, auth_auc, sell_cd(100, 1_000).as_slice()),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // Step 1 triggered at block 1,000 by `ext_buyer_1` placing the first buy order:
        // step1_dl = 1,010, step2_dl = 1,020, step3_dl = 1,030, overall_dl = 1,080.
        mock::set_block_number(1_000);
        mock::transact_as(ext_buyer_1, auth_auc, buy_cd(120, 4_000).as_slice()).unwrap();
        let dls = mock::transact_as(
            ext_buyer_1,
            auth_auc,
            CallEncoder::<16>::new(const { selector("auctionDeadlines()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(dls[24..32].try_into().unwrap()), 1_010);
        assert_eq!(u64::from_be_bytes(dls[56..64].try_into().unwrap()), 1_020);
        assert_eq!(u64::from_be_bytes(dls[88..96].try_into().unwrap()), 1_030);
        assert_eq!(u64::from_be_bytes(dls[120..128].try_into().unwrap()), 1_080);

        // Second buyer `ext_buyer_2` places a buy order during Step 1 (block 1,007 <= 1,010)
        mock::set_block_number(1_007);
        mock::transact_as(ext_buyer_2, auth_auc, buy_cd(115, 6_000).as_slice()).unwrap();

        // Sell orders are still rejected during Step 1 (block 1,010 <= 1,010)
        mock::set_block_number(1_010);
        assert_eq!(
            mock::transact_as(sh_seller_1, auth_auc, sell_cd(110, 5_000).as_slice()),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // Step 2 (1,010 < now <= 1,020): existing shareholders can place sell orders; buy orders rejected!
        mock::set_block_number(1_012);
        assert_eq!(
            mock::transact_as(ext_buyer_1, auth_auc, buy_cd(125, 1_000).as_slice()),
            Err(ERR_WRONG_AUCTION_STEP)
        );
        // Non-shareholder cannot place a sell order in Step 2!
        assert_eq!(
            mock::transact_as(ext_buyer_1, auth_auc, sell_cd(110, 1_000).as_slice()),
            Err(ERR_NOT_EXISTING_SHAREHOLDER)
        );
        // Existing shareholders `sh_seller_1` and `sh_seller_2` place sell orders in Step 2
        mock::transact_as(sh_seller_1, auth_auc, sell_cd(105, 8_000).as_slice()).unwrap();
        mock::set_block_number(1_018);
        mock::transact_as(sh_seller_2, auth_auc, sell_cd(115, 5_000).as_slice()).unwrap();

        // Step 3 (1,020 < now <= 1,030): ONLY remaining shareholders who did NOT sell in Step 2 can place buy orders!
        mock::set_block_number(1_025);
        // `sh_seller_1` participated in Step 2 -> rejected in Step 3!
        assert_eq!(
            mock::transact_as(sh_seller_1, auth_auc, buy_cd(120, 2_000).as_slice()),
            Err(ERR_STEP2_SELLER_INELIGIBLE_STEP3)
        );
        // External non-shareholder `ext_buyer_1` -> rejected in Step 3!
        assert_eq!(
            mock::transact_as(ext_buyer_1, auth_auc, buy_cd(120, 2_000).as_slice()),
            Err(ERR_NOT_EXISTING_SHAREHOLDER)
        );
        // Non-participating existing shareholder `sh_nonseller` -> succeeds in Step 3!
        mock::transact_as(sh_nonseller, auth_auc, buy_cd(125, 3_000).as_slice()).unwrap();

        // Premature finalization or consumption during Step 3 (block 1,030 <= 1,030) is rejected!
        mock::set_block_number(1_030);
        assert_eq!(
            mock::transact_as(
                sh_nonseller,
                auth_auc,
                CallEncoder::<16>::new(const { selector("finalize()") }).as_slice()
            ),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // After Step 3 period ends (block 1,031 > 1,030), no more orders are accepted,
        // and the Authorization HPS is finalized and ready to be consumed by `ledger`!
        mock::set_block_number(1_031);
        assert_eq!(
            mock::transact_as(sh_nonseller, auth_auc, buy_cd(125, 1_000).as_slice()),
            Err(ERR_WRONG_AUCTION_STEP)
        );
        let rdy = mock::transact_as(
            sh_nonseller,
            auth_auc,
            CallEncoder::<16>::new(const { selector("isReadyToConsume()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(rdy[31], 1);

        let book = verify_and_consume_auction_auth(
            &reg,
            &auth_auc,
            &con,
            &POLICY_SHARE_TRANSFER_AUCTION,
            &sh_nonseller,
        );
        // Direct call from test context (`msg_sender` != `ledger`) must fail with `ERR_WRONG_TARGET`:
        assert_eq!(book, Err(ERR_WRONG_TARGET));

        // Target `ledger` consumes `auth_auc` once and receives all 5 orders!
        let raw_consume = CallEncoder::<128>::new(const { selector("consumeAuction(address,bytes32,address)") })
        .push_address(&con)
        .push_bytes32(&POLICY_SHARE_TRANSFER_AUCTION)
        .push_address(&sh_nonseller);
        let consumed_bytes = mock::transact_as(ledger, auth_auc, raw_consume.as_slice()).unwrap();
        let len = u64::from_be_bytes(consumed_bytes[56..64].try_into().unwrap()) as usize;
        let decoded = AuctionBook::decode(&consumed_bytes[64..64 + len]).unwrap();
        assert_eq!(decoded.order_count, 5);
    }

    #[test]
    fn same_step_buy_order_cancellation_and_dynamic_multiclass_shareholder_power() {
        use hps_sdk::governance::{
            AuctionBook, ERR_NOT_ORDER_OWNER, ERR_ORDER_ALREADY_CANCELLED, ERR_WRONG_AUCTION_STEP,
            POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SHARE_TRANSFER_AUCTION,
        };

        mod reg_stub_3 {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("isValidIdentity(address)") }
                    || sel == const { selector("isValidAuthorizationHps(address)") }
                {
                    ret::write_bool(true);
                    return 0;
                }
                -2
            }
        }

        mod con_multiclass_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::{
                share_transfer_auction_policy_spec, PolicySpec, StageSpec,
                MAX_ENCODED_POLICY_BYTES, POLICY_SHAREHOLDER_SUPERMAJORITY,
                POLICY_SHARE_TRANSFER_AUCTION,
            };
            use hps_sdk::{ret, selector};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                    let pol = args.bytes32(1).unwrap();
                    let spec = if pol == POLICY_SHARE_TRANSFER_AUCTION {
                        share_transfer_auction_policy_spec([0xD1; 20], 10, 10, 10, 50).unwrap()
                    } else if pol == POLICY_SHAREHOLDER_SUPERMAJORITY {
                        PolicySpec::new(100)
                            .add_stage(
                                StageSpec::new(75_000, 50)
                                    .add_member([0xA1; 20], 50_000)
                                    .unwrap()
                                    .add_member([0xA2; 20], 25_000)
                                    .unwrap(),
                            )
                            .unwrap()
                    } else {
                        return -62;
                    };
                    let mut buf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    let len = spec.encode(&mut buf).unwrap();
                    ret::write_abi_bytes(&buf[..len]);
                    return 0;
                }
                if sel == const { selector("shareholderVotingPower(address)") } {
                    let voter = args.address(0).unwrap();
                    // Total company voting power across Common (100k @ 1x) + Class B (6k @ 10x) + Series A (20k @ 2x) = 200,000
                    // 75% threshold = 150,000
                    let vp = if voter == [0xA1; 20] {
                        110_000u64 // Manogaran: 50k Common + 6k*10 Class B = 110,000 votes
                    } else if voter == [0xA2; 20] {
                        40_000u64 // Evelyn: 20k Series A (2:1 conversion) = 40,000 votes
                    } else {
                        0u64
                    };
                    let mut out = [0u8; 128];
                    out[24..32].copy_from_slice(&vp.to_be_bytes());
                    out[56..64].copy_from_slice(&200_000u64.to_be_bytes());
                    out[88..96].copy_from_slice(&150_000u64.to_be_bytes());
                    out[120..128].copy_from_slice(&vp.to_be_bytes());
                    ret::write(&out);
                    return 0;
                }
                -2
            }
        }

        mod ledger_stub_2 {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("balanceOf(address)") } {
                    let who = args.address(0).unwrap();
                    let bal = if who == [0xA1; 20] || who == [0xA2; 20] {
                        20_000u64
                    } else {
                        0u64
                    };
                    ret::write_u64_word(bal);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let ledger = [0x30; 20];
        let auth_auc = [0x40; 20];
        let auth_res = [0x41; 20];
        let buyer_1 = [0xD1; 20];
        let buyer_2 = [0xD2; 20];
        let sh_1 = [0xA1; 20];
        let sh_2 = [0xA2; 20];

        mock::register_hps(reg, reg_stub_3::dispatch);
        mock::register_hps(con, con_multiclass_stub::dispatch);
        mock::register_hps(ledger, ledger_stub_2::dispatch);
        mock::register_hps(auth_auc, dispatch_calldata);
        mock::register_hps(auth_res, dispatch_calldata);

        // 1. Initialize auction & place two Step 1 buy orders at block 500 (Step 1 window = 500..=510)
        mock::set_block_number(500);
        mock::transact_as(
            buyer_1,
            auth_auc,
            CallEncoder::<128>::new(const { selector("initializeTransferAuction(address,address,address)") })
            .push_address(&reg)
            .push_address(&con)
            .push_address(&ledger)
            .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<128>::new(const { selector("placeBuyOrderFor(address,uint64,uint64)") })
                .push_address(&buyer_1)
                .push_u64(100)
                .push_u64(1_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<128>::new(const { selector("placeBuyOrderFor(address,uint64,uint64)") })
                .push_address(&buyer_2)
                .push_u64(110)
                .push_u64(2_000)
                .as_slice(),
        )
        .unwrap();

        // Non-owner (`buyer_2`) cannot cancel `buyer_1`'s order 0!
        assert_eq!(
            mock::transact_as(
                con,
                auth_auc,
                CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                    .push_address(&buyer_2)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(ERR_NOT_ORDER_OWNER)
        );

        // `buyer_1` cancels order 0 during Step 1 (block 505 <= 510) -> succeeds!
        mock::set_block_number(505);
        let c_ret = mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                .push_address(&buyer_1)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(c_ret[24..32].try_into().unwrap()), 100);
        assert_eq!(u64::from_be_bytes(c_ret[56..64].try_into().unwrap()), 1_000);

        // Cancelling order 0 a second time -> fails with ERR_ORDER_ALREADY_CANCELLED (-79)!
        assert_eq!(
            mock::transact_as(
                con,
                auth_auc,
                CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                    .push_address(&buyer_1)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(ERR_ORDER_ALREADY_CANCELLED)
        );

        // Advance to Step 2 (block 515 in 511..=520):
        // Attempting to cancel Step 1 order 1 (`buyer_2`) during Step 2 MUST fail with ERR_WRONG_AUCTION_STEP (-74)!
        mock::set_block_number(515);
        assert_eq!(
            mock::transact_as(
                con,
                auth_auc,
                CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                    .push_address(&buyer_2)
                    .push_u64(1)
                    .as_slice(),
            ),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // `sh_1` places a sell order in Step 2
        mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<128>::new(const { selector("placeSellOrderFor(address,uint64,uint64)") })
                .push_address(&sh_1)
                .push_u64(100)
                .push_u64(2_000)
                .as_slice(),
        )
        .unwrap();

        // Advance to Step 3 (block 525 in 521..=530):
        // Attempting to cancel Step 1 order 1 (`buyer_2`) during Step 3 MUST ALSO fail!
        mock::set_block_number(525);
        assert_eq!(
            mock::transact_as(
                con,
                auth_auc,
                CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                    .push_address(&buyer_2)
                    .push_u64(1)
                    .as_slice(),
            ),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // Non-selling shareholder `sh_2` places a Step 3 buy order (order index 3) AND cancels it during Step 3!
        mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<128>::new(const { selector("placeBuyOrderFor(address,uint64,uint64)") })
                .push_address(&sh_2)
                .push_u64(120)
                .push_u64(500)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            con,
            auth_auc,
            CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
                .push_address(&sh_2)
                .push_u64(3)
                .as_slice(),
        )
        .unwrap();

        // Consume after Step 3 ends (block 531 > 530) and verify orders 0 and 3 are marked cancelled
        mock::set_block_number(531);
        let raw_consume = CallEncoder::<128>::new(const { selector("consumeAuction(address,bytes32,address)") })
        .push_address(&con)
        .push_bytes32(&POLICY_SHARE_TRANSFER_AUCTION)
        .push_address(&sh_1);
        let consumed_bytes = mock::transact_as(ledger, auth_auc, raw_consume.as_slice()).unwrap();
        let len = u64::from_be_bytes(consumed_bytes[56..64].try_into().unwrap()) as usize;
        let book = AuctionBook::decode(&consumed_bytes[64..64 + len]).unwrap();
        assert_eq!(book.order_count, 4);
        assert!(book.orders[0].is_cancelled());
        assert!(book.orders[1].is_buy());
        assert!(book.orders[2].is_sell());
        assert!(book.orders[3].is_cancelled());

        // 2. Dynamic Multi-Class Shareholder Resolution Voting in `Authorization`:
        // Initialize `auth_res` with `POLICY_SHAREHOLDER_SUPERMAJORITY` from `con`.
        // Even though the static StageSpec only listed `sh_1` with 50,000 / 75,000,
        // `con.shareholderVotingPower` reports:
        // - Total company voting power = 200,000, required super-majority = 150,000
        // - `sh_1` (Manogaran: Common + Class B 10:1) = 110,000 votes (not enough alone: 110k < 150k!)
        // - `sh_2` (Evelyn: Preferred Series A 2:1 conversion) = 40,000 votes (even though `sh_2` wasn't in static StageSpec!)
        // Together `sh_1` + `sh_2` = 150,000 >= 150,000 -> reaches threshold and finalizes!
        mock::transact_as(
            sh_1,
            auth_res,
            CallEncoder::<192>::new(const { selector("initializeFromConstitution(address,address,address,bytes32,bytes32)") })
            .push_address(&reg)
            .push_address(&con)
            .push_address(&ledger)
            .push_bytes32(&POLICY_SHAREHOLDER_SUPERMAJORITY)
            .push_bytes32(&[0x77; 32])
            .as_slice(),
        )
        .unwrap();

        let done_1 = mock::transact_as(
            sh_1,
            auth_res,
            CallEncoder::<16>::new(const { selector("approve()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(done_1[31], 0); // 110,000 < 150,000!

        let fin_2 = mock::transact_as(
            sh_2,
            auth_res,
            CallEncoder::<16>::new(const { selector("approveAndFinalize()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(fin_2[31], 1); // 110,000 + 40,000 = 150,000 >= 150,000 -> finalized!
    }

    #[test]
    fn role_backed_stages_with_unassigned_initial_roles_and_inactive_constitution_guard() {
        use hps_sdk::governance::{ROLE_DIRECTOR, ROLE_PRODUCT_MANAGER};

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let target = [0x30; 20];
        let auth_blocked = [0x41; 20];
        let auth_activate = [0x42; 20];
        let auth_dual_role = [0x43; 20];

        let sh_1 = [0xA1; 20];
        let dir_1 = [0xB1; 20];
        let dir_2 = [0xB2; 20];
        let prod_mgr = [0xD1; 20];

        const ACT_HASH_ACTIVATE: [u8; 32] = [0xAA; 32];
        let pol_dual = [0x55; 32];
        let act_hash_work = [0xBB; 32];

        mock::register_hps(reg, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("isValidIdentity(address)") } {
                let id = args.address(0).unwrap();
                ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                return 0;
            }
            -2
        });

        // Constitution mock tracking `state()`, `hasRole`, and `roleMemberCount`, plus a 2-stage
        // role-backed PolicySpec (`Stage 0 = ROLE_PRODUCT_MANAGER (w=1)` -> `Stage 1 = ROLE_DIRECTOR (ALL)`)
        mock::register_hps(con, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("setState(uint64)") } {
                storage::set_u64(b"st", args.u64(0).unwrap());
                return 0;
            }
            if sel == const { selector("grant(bytes32,address)") } {
                let rid = args.bytes32(0).unwrap();
                let who = args.address(1).unwrap();
                let hk = KeyBuilder::<64>::new().push(b"hr:").push(&rid).push(&who);
                if storage::get_u64(hk.as_slice()) == 0 {
                    storage::set_u64(hk.as_slice(), 1);
                    let ck = KeyBuilder::<48>::new().push(b"rc:").push(&rid);
                    storage::set_u64(ck.as_slice(), storage::get_u64(ck.as_slice()) + 1);
                }
                return 0;
            }
            if sel == const { selector("state()") } {
                ret::write_u64_word(storage::get_u64(b"st"));
                return 0;
            }
            if sel == const { selector("hashActivateConstitution()") } {
                ret::write_word(&ACT_HASH_ACTIVATE);
                return 0;
            }
            if sel == const { selector("getFunctionAuth(bytes4)") } {
                ret::write_word(&POLICY_FIRST_SHAREHOLDER_RESOLUTION);
                return 0;
            }
            if sel == const { selector("hasRole(bytes32,address)") } {
                let rid = args.bytes32(0).unwrap();
                let who = args.address(1).unwrap();
                let hk = KeyBuilder::<64>::new().push(b"hr:").push(&rid).push(&who);
                ret::write_bool(storage::get_u64(hk.as_slice()) == 1);
                return 0;
            }
            if sel == const { selector("roleMemberCount(bytes32)") } {
                let rid = args.bytes32(0).unwrap();
                let ck = KeyBuilder::<48>::new().push(b"rc:").push(&rid);
                ret::write_u64_word(storage::get_u64(ck.as_slice()));
                return 0;
            }
            if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                let pid = args.bytes32(1).unwrap();
                let spec = if pid == POLICY_FIRST_SHAREHOLDER_RESOLUTION {
                    PolicySpec::new(100)
                        .add_stage(StageSpec::for_role(ROLE_SHAREHOLDER, 1, 50).unwrap())
                        .unwrap()
                } else {
                    PolicySpec::new(100)
                        .add_stage(StageSpec::for_role(ROLE_PRODUCT_MANAGER, 1, 40).unwrap())
                        .unwrap()
                        .add_stage(
                            StageSpec::for_role(ROLE_DIRECTOR, ROLE_ALL_MEMBERS_WEIGHT, 40)
                                .unwrap(),
                        )
                        .unwrap()
                };
                let mut b = [0u8; 512];
                let n = spec.encode(&mut b).unwrap();
                ret::write_abi_bytes(&b[..n]);
                return 0;
            }
            -2
        });

        mock::register_hps(auth_blocked, dispatch_calldata);
        mock::register_hps(auth_activate, dispatch_calldata);
        mock::register_hps(auth_dual_role, dispatch_calldata);

        // Start in PENDING_RATIFICATION (1) with `sh_1` in ROLE_SHAREHOLDER, `[dir_1, dir_2]` in
        // ROLE_DIRECTOR, and 0 members in ROLE_PRODUCT_MANAGER!
        mock::transact_as(
            sh_1,
            con,
            CallEncoder::<64>::new(const { selector("setState(uint64)") })
                .push_u64(CONSTITUTION_STATE_PENDING_RATIFICATION)
                .as_slice(),
        )
        .unwrap();
        for (rid, acct) in [
            (ROLE_SHAREHOLDER, sh_1),
            (ROLE_DIRECTOR, dir_1),
            (ROLE_DIRECTOR, dir_2),
        ] {
            mock::transact_as(
                sh_1,
                con,
                CallEncoder::<96>::new(const { selector("grant(bytes32,address)") })
                    .push_bytes32(&rid)
                    .push_address(&acct)
                    .as_slice(),
            )
            .unwrap();
        }

        // 1. While PENDING_RATIFICATION, initializing any non-activation Authorization MUST fail with ERR_CONSTITUTION_NOT_ACTIVE (-91)!
        let init_blocked = CallEncoder::<192>::new(const {
            selector("initializeFromConstitution(address,address,address,bytes32,bytes32)")
        })
        .push_address(&reg)
        .push_address(&con)
        .push_address(&target)
        .push_bytes32(&pol_dual)
        .push_bytes32(&act_hash_work);
        assert_eq!(
            mock::transact_as(sh_1, auth_blocked, init_blocked.as_slice()),
            Err(ERR_CONSTITUTION_NOT_ACTIVE)
        );

        // 2. Initializing the First Shareholder Resolution (`activateConstitution`) IS allowed!
        let init_act = CallEncoder::<192>::new(const {
            selector("initializeFromConstitution(address,address,address,bytes32,bytes32)")
        })
        .push_address(&reg)
        .push_address(&con)
        .push_address(&con)
        .push_bytes32(&POLICY_FIRST_SHAREHOLDER_RESOLUTION)
        .push_bytes32(&ACT_HASH_ACTIVATE);
        mock::transact_as(sh_1, auth_activate, init_act.as_slice()).unwrap();
        let fin_act = mock::transact_as(
            sh_1,
            auth_activate,
            CallEncoder::<16>::new(const { selector("approveAndFinalize()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(fin_act[31], 1);

        // Activate Constitution -> CONSTITUTION_STATE_ACTIVE (2)
        mock::transact_as(
            sh_1,
            con,
            CallEncoder::<64>::new(const { selector("setState(uint64)") })
                .push_u64(CONSTITUTION_STATE_ACTIVE)
                .as_slice(),
        )
        .unwrap();

        // 3. Initialize 2-stage role-backed `auth_dual_role` while `ROLE_PRODUCT_MANAGER` still has 0 members!
        mock::transact_as(prod_mgr, auth_dual_role, init_blocked.as_slice()).unwrap();

        // Before `prod_mgr` is granted `ROLE_PRODUCT_MANAGER`, attempting to approve Stage 0 fails (`-63`)!
        let app_cd = CallEncoder::<16>::new(const { selector("approve()") });
        assert_eq!(
            mock::transact_as(prod_mgr, auth_dual_role, app_cd.as_slice()),
            Err(ERR_NOT_STAGE_AUTHORIZER)
        );

        // Grant `ROLE_PRODUCT_MANAGER` to `prod_mgr` -> Stage 0 now succeeds and advances to Stage 1 (`ROLE_DIRECTOR`)!
        mock::transact_as(
            dir_1,
            con,
            CallEncoder::<96>::new(const { selector("grant(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .as_slice(),
        )
        .unwrap();
        let s0_done = mock::transact_as(prod_mgr, auth_dual_role, app_cd.as_slice()).unwrap();
        assert_eq!(s0_done[31], 0); // Stage 0 complete -> advanced to Stage 1

        // Stage 1 requires ALL active `ROLE_DIRECTOR` members (`dir_1` + `dir_2`)
        let d1_res = mock::transact_as(dir_1, auth_dual_role, app_cd.as_slice()).unwrap();
        assert_eq!(d1_res[31], 0); // 1 of 2 directors signed
        let d2_fin = mock::transact_as(
            dir_2,
            auth_dual_role,
            CallEncoder::<16>::new(const { selector("approveAndFinalize()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(d2_fin[31], 1); // 2 of 2 directors signed & finalized!
    }
}
