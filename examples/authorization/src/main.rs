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
    oracle_policy_id, require_valid_identity, PolicySpec, StageSpec, ERR_POLICY_INVALID,
    MAX_ENCODED_POLICY_BYTES,
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

hps_entry! {
    "initializeFromConstitution(address,address,address,bytes32,bytes32)" => handle_init_from_constitution,
    "initializeOracle(address,address,address,bytes32,uint64)"            => handle_init_oracle,
    "initializeCustom(address,address,bytes32,bytes32,bytes)"             => handle_init_custom,
    "approve()"                                                           => handle_approve,
    "finalize()"                                                          => handle_finalize,
    "approveAndFinalize()"                                                => handle_approve_and_finalize,
    "consume(address,bytes32,bytes32,address)"                            => handle_consume,
    "status()"                                                            => handle_status,
    "currentStage()"                                                      => handle_current_stage,
    "stageCount()"                                                        => handle_stage_count,
    "stageWeight(uint64)"                                                 => handle_stage_weight,
    "deadlines()"                                                         => handle_deadlines,
    "isReadyToConsume()"                                                  => handle_is_ready_to_consume,
    "targetHps()"                                                         => handle_target_hps,
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

    let now = context::block_number();
    let stage0_dl = now.saturating_add(spec.stages[0].expiry_blocks);
    let overall_dl = now.saturating_add(spec.overall_expiry_blocks);

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

    // Fetch policy bylaw from Constitution HPS
    let q = CallEncoder::<96>::new(selector("getPolicyRaw(address,bytes32)"))
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
    let weight = stage
        .member_weight(&caller)
        .ok_or(ERR_NOT_STAGE_AUTHORIZER)?;

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

    if accum >= stage.required_weight {
        let mut thr = [0u8; 24];
        thr[0..8].copy_from_slice(&(cur_stage as u64).to_be_bytes());
        thr[8..16].copy_from_slice(&accum.to_be_bytes());
        thr[16..24].copy_from_slice(&stage.required_weight.to_be_bytes());
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
    require_valid_identity(&registry, &invoker_identity)?;

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

fn effective_status() -> u64 {
    let st = storage::get_u64(KEY_STATE);
    if st == STATE_UNINIT || st == STATE_CONSUMED {
        return st;
    }
    let now = context::block_number();
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

fn handle_is_ready_to_consume(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_bool(effective_status() == STATE_FINALIZED && storage::get_u64(KEY_CONSUMED) == 0);
    Ok(())
}

fn handle_target_hps(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_TARGET).unwrap_or([0u8; 20]));
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
            if sel == selector("isValidIdentity(address)") {
                let a = args.address(0).unwrap();
                ret::write_bool(a != [0u8; 20] && a[0] != 0xEE);
                return 0;
            }
            -2
        }

        pub fn con_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("getPolicyRaw(address,bytes32)") {
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
        let init_cd = CallEncoder::<192>::new(selector(
            "initializeFromConstitution(address,address,address,bytes32,bytes32)",
        ))
        .push_address(&reg)
        .push_address(&con)
        .push_address(&ledger)
        .push_bytes32(&ACTION_ISSUE)
        .push_bytes32(&act_hash);

        mock::transact_as(a1, auth, init_cd.as_slice()).unwrap();

        // 1. Out-of-order rejection: Group B CANNOT approve before Group A completes Stage 0!
        let app_cd = CallEncoder::<16>::new(selector("approve()"));
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
            CallEncoder::<16>::new(selector("finalize()")).as_slice()
        )
        .is_err());

        // 4. `b_jr1` contributes weight 1 (total 3 >= 3) and finalizes!
        mock::set_block_number(108);
        let done_2 = mock::transact_as(
            b_jr1,
            auth,
            CallEncoder::<16>::new(selector("approveAndFinalize()")).as_slice(),
        )
        .unwrap();
        assert_eq!(done_2[31], 1);

        // 5. Wrong target cannot consume; bound target (`ledger`) consumes once; second consume fails!
        let consume_cd = CallEncoder::<164>::new(selector("consume(address,bytes32,bytes32,address)"))
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
}
