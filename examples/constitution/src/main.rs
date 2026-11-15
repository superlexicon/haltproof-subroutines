//! Constitution (Policies & Bylaws) **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Stores institutional authorization policies/bylaws retrieved by `Authorization` HPS instances:
//! - Defines ordered sequential stages (`Stage 0` -> `Stage 1` -> ...), where each stage specifies
//!   its eligible Identity HPS authorizers, per-authorizer integer weights (`>= 1`), required stage
//!   weight threshold (supporting both sequential steps and joint M-of-N weighted approvals), and
//!   per-stage block-expiry window, plus an overall process expiry window.
//! - Verifies all callers and all listed policy authorizer Identities against `IdentityRegistry`.
//! - Supports atomic genesis setup of multiple policies (including `SUPER_GOVERNANCE`) and requires
//!   a finalized, one-time-use `SUPER_GOVERNANCE` `Authorization` HPS object to amend or deactivate
//!   any policy (`setPolicy`, `deactivatePolicy`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::governance::{
    require_valid_identity, verify_and_consume_auth, ActionHasher, PolicySpec,
    ERR_POLICY_INVALID, MAX_ENCODED_POLICY_BYTES, POLICY_SUPER_GOVERNANCE,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const CONSTITUTION_INITIALIZED: [u8; 32] = event_topic("ConstitutionInitialized(address,uint64)");
const POLICY_SET: [u8; 32] = event_topic("PolicySet(address,bytes32,uint64,uint64)");
const POLICY_DEACTIVATED: [u8; 32] = event_topic("PolicyDeactivated(address,bytes32)");

const TAG_SET_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_SET_POLICY");
const TAG_DEACTIVATE_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_DEACTIVATE_POLICY");

const KEY_INIT: &[u8] = b"con:init";
const KEY_REGISTRY: &[u8] = b"con:reg";

hps_entry! {
    "initialize(address,bytes)"                             => handle_initialize,
    "setPolicy(address,bytes32,bytes,address)"              => handle_set_policy,
    "deactivatePolicy(address,bytes32,address)"             => handle_deactivate_policy,
    "getPolicyRaw(address,bytes32)"                         => handle_get_policy_raw,
    "hasPolicy(address,bytes32)"                            => handle_has_policy,
    "identityRegistry()"                                    => handle_identity_registry,
    "hashSetPolicy(address,bytes32,bytes)"                  => handle_hash_set_policy,
    "hashDeactivatePolicy(address,bytes32)"                 => handle_hash_deactivate_policy,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn policy_key(target_hps: &[u8; 20], policy_id: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"pol:")
        .push(target_hps)
        .push(policy_id)
}

fn validate_and_verify_spec(registry: &[u8; 20], raw_spec: &[u8]) -> Result<PolicySpec, i32> {
    if raw_spec.is_empty() || raw_spec.len() > MAX_ENCODED_POLICY_BYTES {
        return Err(ERR_POLICY_INVALID);
    }
    let spec = PolicySpec::decode(raw_spec).ok_or(ERR_POLICY_INVALID)?;
    let mut s = 0;
    while s < spec.stage_count {
        let st = &spec.stages[s];
        let mut m = 0;
        while m < st.member_count {
            require_valid_identity(registry, &st.members[m].identity)?;
            m += 1;
        }
        s += 1;
    }
    Ok(spec)
}

fn store_policy(target_hps: &[u8; 20], policy_id: &[u8; 32], raw_spec: &[u8], spec: &PolicySpec) {
    let pk = policy_key(target_hps, policy_id);
    storage::set(pk.as_slice(), raw_spec);
    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&(spec.stage_count as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&spec.overall_expiry_blocks.to_be_bytes());
    events::emit(&[POLICY_SET, addr_topic(target_hps), *policy_id], &ev);
}

fn compute_set_policy_hash(
    target_hps: &[u8; 20],
    policy_id: &[u8; 32],
    raw_spec: &[u8],
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &TAG_SET_POLICY)
        .push_address(target_hps)
        .push_bytes32(policy_id)
        .push_bytes_digest(raw_spec)
        .finish()
}

fn compute_deactivate_hash(target_hps: &[u8; 20], policy_id: &[u8; 32]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &TAG_DEACTIVATE_POLICY)
        .push_address(target_hps)
        .push_bytes32(policy_id)
        .finish()
}

fn ensure_initialized_and_valid_caller() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-57)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, caller))
}

/// Genesis initializer:
/// `initialPoliciesBlob` format:
/// `[count: u16 BE]` + `count` × `[target_hps: 20B][policy_id: 32B][spec_len: u16 BE][spec: spec_len]`
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58); // already initialized
    }
    let registry = args.address(0).ok_or(-3)?;
    let blob = args.dynamic_bytes(1).ok_or(-3)?;
    if registry == [0u8; 20] || blob.len() < 2 {
        return Err(-59);
    }

    // Calling initializer MUST itself be a valid Identity in `IdentityRegistry`.
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let count = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    if count == 0 {
        return Err(-59);
    }

    let me = context::self_address();
    let mut has_super = false;
    let mut pos = 2usize;
    let mut i = 0usize;
    while i < count {
        if pos + 54 > blob.len() {
            return Err(-59);
        }
        let mut target_hps = [0u8; 20];
        target_hps.copy_from_slice(&blob[pos..pos + 20]);
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&blob[pos + 20..pos + 52]);
        let spec_len = u16::from_be_bytes([blob[pos + 52], blob[pos + 53]]) as usize;
        pos += 54;

        if policy_id == [0u8; 32] || pos + spec_len > blob.len() {
            return Err(-59);
        }
        let raw_spec = &blob[pos..pos + spec_len];
        pos += spec_len;

        let spec = validate_and_verify_spec(&registry, raw_spec)?;
        store_policy(&target_hps, &policy_id, raw_spec, &spec);

        if policy_id == POLICY_SUPER_GOVERNANCE && (target_hps == me || target_hps == [0u8; 20]) {
            has_super = true;
        }
        i += 1;
    }

    if pos != blob.len() || !has_super {
        return Err(-60); // trailing bytes or missing SUPER_GOVERNANCE policy
    }

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_u64(KEY_INIT, 1);

    events::emit(
        &[CONSTITUTION_INITIALIZED, addr_topic(&registry)],
        &(count as u64).to_be_bytes(),
    );
    Ok(())
}

fn handle_set_policy(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let raw_spec = args.dynamic_bytes(2).ok_or(-3)?;
    let super_auth = args.address(3).ok_or(-3)?;
    if policy_id == [0u8; 32] {
        return Err(-59);
    }

    let spec = validate_and_verify_spec(&registry, raw_spec)?;
    let action_hash = compute_set_policy_hash(&target_hps, &policy_id, raw_spec);
    let me = context::self_address();
    verify_and_consume_auth(
        &super_auth,
        &me,
        &POLICY_SUPER_GOVERNANCE,
        &action_hash,
        &caller,
    )?;

    store_policy(&target_hps, &policy_id, raw_spec, &spec);
    ret::write_bool(true);
    Ok(())
}

fn handle_deactivate_policy(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let super_auth = args.address(2).ok_or(-3)?;

    let me = context::self_address();
    if policy_id == POLICY_SUPER_GOVERNANCE && (target_hps == me || target_hps == [0u8; 20]) {
        return Err(-61); // cannot delete SUPER_GOVERNANCE; amend via setPolicy instead
    }

    let pk = policy_key(&target_hps, &policy_id);
    if !storage::exists(pk.as_slice()) {
        return Err(-62);
    }

    let action_hash = compute_deactivate_hash(&target_hps, &policy_id);
    verify_and_consume_auth(
        &super_auth,
        &me,
        &POLICY_SUPER_GOVERNANCE,
        &action_hash,
        &caller,
    )?;

    storage::set(pk.as_slice(), &[]);
    events::emit(&[POLICY_DEACTIVATED, addr_topic(&target_hps), policy_id], &[]);
    ret::write_bool(true);
    Ok(())
}

fn resolve_policy_into(
    target_hps: &[u8; 20],
    policy_id: &[u8; 32],
    buf: &mut [u8; MAX_ENCODED_POLICY_BYTES],
) -> Option<usize> {
    let pk = policy_key(target_hps, policy_id);
    if let Some(n) = storage::get_into(pk.as_slice(), buf) {
        if n <= MAX_ENCODED_POLICY_BYTES {
            return Some(n);
        }
    }
    if *target_hps != [0u8; 20] {
        let global_pk = policy_key(&[0u8; 20], policy_id);
        if let Some(n) = storage::get_into(global_pk.as_slice(), buf) {
            if n <= MAX_ENCODED_POLICY_BYTES {
                return Some(n);
            }
        }
    }
    None
}

fn handle_get_policy_raw(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let mut buf = [0u8; MAX_ENCODED_POLICY_BYTES];
    let n = resolve_policy_into(&target_hps, &policy_id, &mut buf).ok_or(-62)?;
    ret::write_abi_bytes(&buf[..n]);
    Ok(())
}

fn handle_has_policy(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        ret::write_bool(false);
        return Ok(());
    }
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let pk = policy_key(&target_hps, &policy_id);
    let found = storage::exists(pk.as_slice())
        || (target_hps != [0u8; 20] && storage::exists(policy_key(&[0u8; 20], &policy_id).as_slice()));
    ret::write_bool(found);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_hash_set_policy(args: &CalldataReader) -> Result<(), i32> {
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let raw_spec = args.dynamic_bytes(2).ok_or(-3)?;
    ret::write_word(&compute_set_policy_hash(&target_hps, &policy_id, raw_spec));
    Ok(())
}

fn handle_hash_deactivate_policy(args: &CalldataReader) -> Result<(), i32> {
    let target_hps = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    ret::write_word(&compute_deactivate_hash(&target_hps, &policy_id));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::governance::{ACTION_ISSUE, StageSpec};
    use hps_sdk::{mock, selector};

    mod reg_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("isValidIdentity(address)") {
                let a = args.address(0).unwrap();
                ret::write_bool(a[0] != 0xEE && a != [0u8; 20]);
                return 0;
            }
            -2
        }
    }

    #[test]
    fn constitution_stores_and_resolves_sequential_weighted_policies() {
        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let board_1 = [0xA1; 20];
        let board_2 = [0xA2; 20];
        let grp_a = [0xB1; 20];
        let grp_b = [0xB2; 20];

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con, dispatch_calldata);

        // SUPER_GOVERNANCE: joint weighted 3-weight stage (board_1 weight=2 + board_2 weight=1)
        let super_spec = PolicySpec::new(100)
            .add_stage(
                StageSpec::new(3, 50)
                    .add_member(board_1, 2)
                    .unwrap()
                    .add_member(board_2, 1)
                    .unwrap(),
            )
            .unwrap();
        // ISSUE: sequential 2-stage (Stage 0 = grp_a within 10 blocks -> Stage 1 = grp_b within 10 blocks)
        let issue_spec = PolicySpec::new(25)
            .add_stage(StageSpec::new(1, 10).add_member(grp_a, 1).unwrap())
            .unwrap()
            .add_stage(StageSpec::new(1, 10).add_member(grp_b, 1).unwrap())
            .unwrap();

        let mut buf_s = [0u8; 512];
        let len_s = super_spec.encode(&mut buf_s).unwrap();
        let mut buf_i = [0u8; 512];
        let len_i = issue_spec.encode(&mut buf_i).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(&2u16.to_be_bytes());
        // Entry 0: global SUPER_GOVERNANCE
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&POLICY_SUPER_GOVERNANCE);
        blob.extend_from_slice(&(len_s as u16).to_be_bytes());
        blob.extend_from_slice(&buf_s[..len_s]);
        // Entry 1: global ACTION_ISSUE
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&ACTION_ISSUE);
        blob.extend_from_slice(&(len_i as u16).to_be_bytes());
        blob.extend_from_slice(&buf_i[..len_i]);

        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("initialize(address,bytes)"));
        let mut rw = [0u8; 32];
        rw[12..32].copy_from_slice(&reg);
        cd.extend_from_slice(&rw);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        cd.extend_from_slice(&off);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(blob.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(&blob);
        cd.resize(cd.len() + (32 - blob.len() % 32) % 32, 0);

        mock::transact_as(board_1, con, &cd).unwrap();

        // Fetch ACTION_ISSUE for a specific ledger (resolves global fallback cleanly)
        let ledger = [0x55; 20];
        let get_cd = CallEncoder::<96>::new(selector("getPolicyRaw(address,bytes32)"))
            .push_address(&ledger)
            .push_bytes32(&ACTION_ISSUE);
        let ret_bytes = mock::transact_as(board_1, con, get_cd.as_slice()).unwrap();
        let rlen = u64::from_be_bytes(ret_bytes[56..64].try_into().unwrap()) as usize;
        let decoded = PolicySpec::decode(&ret_bytes[64..64 + rlen]).unwrap();
        assert_eq!(decoded, issue_spec);
    }
}
