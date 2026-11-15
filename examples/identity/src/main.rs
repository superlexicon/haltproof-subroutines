//! On-Chain Identity **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! All state-changing interactions with `IdentityRegistry`, `Constitution`, `Authorization`,
//! `AssetLedger`, and `AssetPair_OTC` occur through a verified `Identity` HPS instance so
//! `context::msg_sender()` inside those target subroutines is always the calling Identity's
//! 20-byte HPS address (`context::self_address()`).
//!
//! Provides both general-purpose `execute(address targetHps, bytes callData)` forwarding and
//! ergonomic typed entrypoints for authorization workflows and asset ledger operations.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const IDENTITY_INITIALIZED: [u8; 32] = event_topic("IdentityInitialized(address,string)");
const DELEGATE_UPDATED: [u8; 32] = event_topic("DelegateUpdated(address,bool)");
const EXECUTED_CALL: [u8; 32] = event_topic("Executed(address,bytes4)");
const AUTH_SIGNED: [u8; 32] = event_topic("AuthorizationSigned(address,uint64)");

const KEY_INIT: &[u8] = b"id:init";
const KEY_OWNER: &[u8] = b"id:owner";
const KEY_HANDLE: &[u8] = b"id:handle";

hps_entry! {
    "initialize(address,string)"                                                      => handle_initialize,
    "setDelegate(address,bool)"                                                       => handle_set_delegate,
    "transferOwnership(address)"                                                      => handle_transfer_ownership,
    "execute(address,bytes)"                                                          => handle_execute,
    "initConstitutionAuth(address,address,address,address,bytes32,bytes32)"           => handle_init_constitution_auth,
    "initOracleAuth(address,address,address,address,bytes32,uint64)"                  => handle_init_oracle_auth,
    "approveAuth(address)"                                                            => handle_approve_auth,
    "approveAndFinalizeAuth(address)"                                                 => handle_approve_and_finalize_auth,
    "finalizeAuth(address)"                                                           => handle_finalize_auth,
    "issueAsset(address,address,uint64,address)"                                      => handle_issue_asset,
    "cancelAsset(address,address,uint64,address)"                                     => handle_cancel_asset,
    "transferAsset(address,address,address,uint64,address)"                           => handle_transfer_asset,
    "approveAsset(address,address,uint64,address)"                                    => handle_approve_asset,
    "owner()"                                                                         => handle_owner,
    "isAuthorized(address)"                                                           => handle_is_authorized,
    "hasApprovedAuth(address)"                                                        => handle_has_approved_auth,
    "handle()"                                                                        => handle_handle,
    "balanceIn(address)"                                                              => handle_balance_in,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn delegate_key(actor: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"del:").push(actor)
}

fn auth_stamp_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"ast:").push(auth_obj)
}

fn check_owner(actor: &[u8; 20]) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let owner = storage::get_address(KEY_OWNER).ok_or(-20)?;
    if *actor == owner {
        Ok(())
    } else {
        Err(-21)
    }
}

fn is_actor_authorized(actor: &[u8; 20]) -> bool {
    if storage::get_u64(KEY_INIT) != 1 {
        return false;
    }
    if let Some(owner) = storage::get_address(KEY_OWNER) {
        if *actor == owner {
            return true;
        }
    }
    let dk = delegate_key(actor);
    storage::get_u64(dk.as_slice()) == 1
}

fn require_authorized() -> Result<(), i32> {
    let caller = context::msg_sender();
    if is_actor_authorized(&caller) {
        Ok(())
    } else {
        Err(-21)
    }
}

fn stamp_auth_approval(auth_obj: &[u8; 20]) {
    let now = context::block_number();
    let sk = auth_stamp_key(auth_obj);
    storage::set_u64(sk.as_slice(), now.saturating_add(1));
    events::emit(&[AUTH_SIGNED, addr_topic(auth_obj)], &now.to_be_bytes());
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-22); // already initialized
    }
    let owner = args.address(0).ok_or(-3)?;
    let handle_str = args.dynamic_bytes(1).ok_or(-3)?;
    if owner == [0u8; 20] || handle_str.is_empty() || handle_str.len() > 64 {
        return Err(-23);
    }

    storage::set_address(KEY_OWNER, &owner);
    storage::set(KEY_HANDLE, handle_str);
    storage::set_u64(KEY_INIT, 1);

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    Ok(())
}

fn handle_set_delegate(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let delegate = args.address(0).ok_or(-3)?;
    let allowed = args.bool(1).ok_or(-3)?;
    if delegate == [0u8; 20] {
        return Err(-23);
    }

    let dk = delegate_key(&delegate);
    storage::set_u64(dk.as_slice(), if allowed { 1 } else { 0 });
    events::emit(
        &[DELEGATE_UPDATED, addr_topic(&delegate)],
        &[u8::from(allowed)],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_transfer_ownership(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let new_owner = args.address(0).ok_or(-3)?;
    if new_owner == [0u8; 20] {
        return Err(-23);
    }
    storage::set_address(KEY_OWNER, &new_owner);
    ret::write_bool(true);
    Ok(())
}

/// Universal Identity call gateway (`msg.sender` inside `target` becomes `self_address()`).
fn handle_execute(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let target = args.address(0).ok_or(-3)?;
    let sub_cd = args.dynamic_bytes(1).ok_or(-3)?;
    if sub_cd.len() < 4 {
        return Err(-25);
    }

    let sel = [sub_cd[0], sub_cd[1], sub_cd[2], sub_cd[3]];
    if sel == selector("approve()") || sel == selector("approveAndFinalize()") {
        stamp_auth_approval(&target);
    }

    let out = call::call_raw(&target, sub_cd)?;
    events::emit(&[EXECUTED_CALL, addr_topic(&target)], &sel);
    ret::write(out);
    Ok(())
}

fn handle_init_constitution_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let constitution = args.address(2).ok_or(-3)?;
    let target_hps = args.address(3).ok_or(-3)?;
    let policy_id = args.bytes32(4).ok_or(-3)?;
    let action_hash = args.bytes32(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<192>::new(selector(
        "initializeFromConstitution(address,address,address,bytes32,bytes32)",
    ))
    .push_address(&registry)
    .push_address(&constitution)
    .push_address(&target_hps)
    .push_bytes32(&policy_id)
    .push_bytes32(&action_hash);

    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_init_oracle_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let oracle_id = args.address(2).ok_or(-3)?;
    let target_hps = args.address(3).ok_or(-3)?;
    let action_hash = args.bytes32(4).ok_or(-3)?;
    let expiry_blocks = args.u64(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<192>::new(selector(
        "initializeOracle(address,address,address,bytes32,uint64)",
    ))
    .push_address(&registry)
    .push_address(&oracle_id)
    .push_address(&target_hps)
    .push_bytes32(&action_hash)
    .push_u64(expiry_blocks);

    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_approve_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<16>::new(selector("approve()"));
    let stages_done = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    ret::write_bool(stages_done);
    Ok(())
}

fn handle_approve_and_finalize_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<16>::new(selector("approveAndFinalize()"));
    let finalized = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    ret::write_bool(finalized);
    Ok(())
}

fn handle_finalize_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let sub_cd = CallEncoder::<16>::new(selector("finalize()"));
    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_issue_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let to_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(selector("issue(address,uint64,address)"))
        .push_address(&to_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let new_bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(new_bal);
    Ok(())
}

fn handle_cancel_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let from_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(selector("cancel(address,uint64,address)"))
        .push_address(&from_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let new_bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(new_bal);
    Ok(())
}

fn handle_transfer_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let from_identity = args.address(1).ok_or(-3)?;
    let to_identity = args.address(2).ok_or(-3)?;
    let amount = args.u64(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let sub_cd = CallEncoder::<160>::new(selector("transfer(address,address,uint64,address)"))
        .push_address(&from_identity)
        .push_address(&to_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let ok = call::call_bool(&ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_approve_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let spender = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(selector("approve(address,uint64,address)"))
        .push_address(&spender)
        .push_u64(amount)
        .push_address(&auth_obj);
    let ok = call::call_bool(&ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_owner(_args: &CalldataReader) -> Result<(), i32> {
    let owner = storage::get_address(KEY_OWNER).unwrap_or([0u8; 20]);
    ret::write_address(&owner);
    Ok(())
}

fn handle_is_authorized(args: &CalldataReader) -> Result<(), i32> {
    let actor = args.address(0).ok_or(-3)?;
    ret::write_bool(is_actor_authorized(&actor));
    Ok(())
}

fn handle_has_approved_auth(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    let sk = auth_stamp_key(&auth_obj);
    ret::write_bool(storage::get_u64(sk.as_slice()) > 0);
    Ok(())
}

fn handle_handle(_args: &CalldataReader) -> Result<(), i32> {
    match storage::get_ref(KEY_HANDLE) {
        Some(h) => ret::write_abi_bytes(h),
        None => ret::write_abi_bytes(&[]),
    }
    Ok(())
}

fn handle_balance_in(args: &CalldataReader) -> Result<(), i32> {
    let ledger = args.address(0).ok_or(-3)?;
    let me = context::self_address();
    let sub_cd = CallEncoder::<64>::new(selector("balanceOf(address)")).push_address(&me);
    let bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(bal);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    fn init_identity_cd(owner: [u8; 20], handle: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("initialize(address,string)"));
        let mut ow = [0u8; 32];
        ow[12..32].copy_from_slice(&owner);
        cd.extend_from_slice(&ow);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        cd.extend_from_slice(&off);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(handle.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(handle);
        cd.resize(cd.len() + (32 - handle.len() % 32) % 32, 0);
        cd
    }

    #[test]
    fn owner_and_delegates_authorize_cleanly() {
        mock::reset();
        let id_hps = [0xAA; 20];
        let owner_eoa = [0x01; 20];
        let delegate_eoa = [0x02; 20];
        let stranger = [0x99; 20];
        mock::register_hps(id_hps, dispatch_calldata);

        mock::transact_as(owner_eoa, id_hps, &init_identity_cd(owner_eoa, b"alice.id")).unwrap();

        let q_stranger =
            CallEncoder::<64>::new(selector("isAuthorized(address)")).push_address(&stranger);
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, q_stranger.as_slice()).unwrap()[31],
            0
        );

        let set_del = CallEncoder::<96>::new(selector("setDelegate(address,bool)"))
            .push_address(&delegate_eoa)
            .push_bool(true);
        assert_eq!(
            mock::transact_as(stranger, id_hps, set_del.as_slice()),
            Err(-21)
        );

        mock::transact_as(owner_eoa, id_hps, set_del.as_slice()).unwrap();
        let q_del =
            CallEncoder::<64>::new(selector("isAuthorized(address)")).push_address(&delegate_eoa);
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, q_del.as_slice()).unwrap()[31],
            1
        );
    }
}
