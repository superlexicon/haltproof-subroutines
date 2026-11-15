//! Verified Identity Register **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Acts as the canonical on-chain root of trust for verified Identity and Authorization HPS instances:
//! - Maintains governance-managed allowlists of approved **WASM bytecode hashes (`code_hash`)** for both
//!   `Identity` subroutines (`isAllowedIdentityCodeHash`) and `Authorization` subroutines
//!   (`isAllowedAuthCodeHash`), verified live via `context::code_hash_of` (`host_get_code_hash`).
//! - Rejects raw EOAs and malicious/cloned `Identity` or `Authorization` subroutines whose deployed
//!   `keccak256(wasm)` bytecode hash is not in the Registry's allowlist (`ERR_UNAPPROVED_CODE_HASH`).
//! - Every state-changing call into `Constitution`, `Authorization`, `AssetLedger`, `AssetPair_OTC`,
//!   and `IdentityRegistry` itself must originate from an active Identity HPS (`status == 1` **and**
//!   approved `code_hash`) verified via `isValidIdentity(address)`.
//! - Every state-changing function requires a finalized, timely, **one-time-use `Authorization` HPS**
//!   object (`authObj`) whose own bytecode hash is verified via `isValidAuthorizationHps(address)`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::governance::{
    oracle_policy_id, verify_and_consume_auth, ActionHasher, ERR_INVALID_IDENTITY,
    ERR_UNAPPROVED_CODE_HASH,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const STATUS_UNREGISTERED: u64 = 0;
pub const STATUS_ACTIVE: u64 = 1;
pub const STATUS_SUSPENDED: u64 = 2;
pub const STATUS_REVOKED: u64 = 3;

const REGISTRY_INITIALIZED: [u8; 32] =
    event_topic("RegistryInitialized(address,bytes32,bytes32,uint64)");
const IDENTITY_STATUS_CHANGED: [u8; 32] =
    event_topic("IdentityStatusChanged(address,uint64,uint64,address)");
const GOVERNANCE_UPDATED: [u8; 32] = event_topic("RegistryGovernanceUpdated(address,bytes32)");
const CODE_HASH_ALLOWLIST_UPDATED: [u8; 32] =
    event_topic("CodeHashAllowlistUpdated(bytes32,uint64,bool)");

const TAG_REGISTER: [u8; 32] = keccak256(b"REGISTRY_REGISTER_IDENTITY");
const TAG_SUSPEND: [u8; 32] = keccak256(b"REGISTRY_SUSPEND_IDENTITY");
const TAG_REINSTATE: [u8; 32] = keccak256(b"REGISTRY_REINSTATE_IDENTITY");
const TAG_REVOKE: [u8; 32] = keccak256(b"REGISTRY_REVOKE_IDENTITY");
const TAG_ROTATE_ADMIN: [u8; 32] = keccak256(b"REGISTRY_ROTATE_ADMIN");
const TAG_SET_GOV: [u8; 32] = keccak256(b"REGISTRY_SET_GOVERNANCE");
const TAG_ALLOW_ID_CODE: [u8; 32] = keccak256(b"REGISTRY_SET_ALLOWED_ID_CODE_HASH");
const TAG_ALLOW_AUTH_CODE: [u8; 32] = keccak256(b"REGISTRY_SET_ALLOWED_AUTH_CODE_HASH");

const KEY_INIT: &[u8] = b"reg:init";
const KEY_ADMIN: &[u8] = b"reg:admin";
const KEY_GOV_CONSTITUTION: &[u8] = b"reg:gov_const";
const KEY_GOV_POLICY: &[u8] = b"reg:gov_pol";
const KEY_ACTIVE_COUNT: &[u8] = b"reg:active_cnt";

hps_entry! {
    "initialize(address,bytes32,bytes32,bytes)"                 => handle_initialize,
    "registerIdentity(address,address)"                         => handle_register_identity,
    "suspendIdentity(address,address)"                          => handle_suspend_identity,
    "reinstateIdentity(address,address)"                        => handle_reinstate_identity,
    "revokeIdentity(address,address)"                           => handle_revoke_identity,
    "rotateAdmin(address,address)"                              => handle_rotate_admin,
    "setGovernancePolicy(address,bytes32,address)"              => handle_set_governance_policy,
    "setAllowedIdentityCodeHash(bytes32,bool,address)"          => handle_set_allowed_id_code_hash,
    "setAllowedAuthCodeHash(bytes32,bool,address)"              => handle_set_allowed_auth_code_hash,
    "isValidIdentity(address)"                                  => handle_is_valid_identity,
    "isValidAuthorizationHps(address)"                          => handle_is_valid_auth_hps,
    "isAllowedIdentityCodeHash(bytes32)"                        => handle_is_allowed_id_code_hash,
    "isAllowedAuthCodeHash(bytes32)"                            => handle_is_allowed_auth_code_hash,
    "identityStatus(address)"                                   => handle_identity_status,
    "adminIdentity()"                                           => handle_admin_identity,
    "governancePolicy()"                                        => handle_governance_policy,
    "activeCount()"                                             => handle_active_count,
    "hashRegisterIdentity(address)"                             => handle_hash_register,
    "hashSuspendIdentity(address)"                              => handle_hash_suspend,
    "hashReinstateIdentity(address)"                            => handle_hash_reinstate,
    "hashRevokeIdentity(address)"                               => handle_hash_revoke,
    "hashRotateAdmin(address)"                                  => handle_hash_rotate_admin,
    "hashSetGovernancePolicy(address,bytes32)"                  => handle_hash_set_gov,
    "hashSetAllowedIdentityCodeHash(bytes32,bool)"              => handle_hash_allow_id_code,
    "hashSetAllowedAuthCodeHash(bytes32,bool)"                  => handle_hash_allow_auth_code,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn status_key(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"st:").push(identity)
}

fn allowed_id_code_key(code_hash: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"allow:id:").push(code_hash)
}

fn allowed_auth_code_key(code_hash: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"allow:au:").push(code_hash)
}

fn is_allowed_id_code(code_hash: &[u8; 32]) -> bool {
    if *code_hash == [0u8; 32] {
        return false;
    }
    let k = allowed_id_code_key(code_hash);
    storage::get_u64(k.as_slice()) == 1
}

fn is_allowed_auth_code(code_hash: &[u8; 32]) -> bool {
    if *code_hash == [0u8; 32] {
        return false;
    }
    let k = allowed_auth_code_key(code_hash);
    storage::get_u64(k.as_slice()) == 1
}

fn has_allowed_identity_code(candidate: &[u8; 20]) -> bool {
    if *candidate == [0u8; 20] {
        return false;
    }
    match context::code_hash_of(candidate) {
        Some(h) => is_allowed_id_code(&h),
        None => false,
    }
}

fn require_allowed_identity_code(candidate: &[u8; 20]) -> Result<(), i32> {
    if has_allowed_identity_code(candidate) {
        Ok(())
    } else {
        Err(ERR_UNAPPROVED_CODE_HASH)
    }
}

fn has_allowed_auth_code(auth_obj: &[u8; 20]) -> bool {
    if *auth_obj == [0u8; 20] {
        return false;
    }
    match context::code_hash_of(auth_obj) {
        Some(h) => is_allowed_auth_code(&h),
        None => false,
    }
}

fn get_status(identity: &[u8; 20]) -> u64 {
    if *identity == [0u8; 20] {
        return STATUS_UNREGISTERED;
    }
    let sk = status_key(identity);
    storage::get_u64(sk.as_slice())
}

fn is_valid_identity_internal(identity: &[u8; 20]) -> bool {
    get_status(identity) == STATUS_ACTIVE && has_allowed_identity_code(identity)
}

fn set_status_internal(identity: &[u8; 20], new_status: u64, auth_obj: &[u8; 20]) {
    let sk = status_key(identity);
    let prev = storage::get_u64(sk.as_slice());
    storage::set_u64(sk.as_slice(), new_status);

    let active = storage::get_u64(KEY_ACTIVE_COUNT);
    if prev != STATUS_ACTIVE && new_status == STATUS_ACTIVE {
        storage::set_u64(KEY_ACTIVE_COUNT, active + 1);
    } else if prev == STATUS_ACTIVE && new_status != STATUS_ACTIVE {
        storage::set_u64(KEY_ACTIVE_COUNT, active.saturating_sub(1));
    }

    let mut data = [0u8; 36];
    data[0..8].copy_from_slice(&prev.to_be_bytes());
    data[8..16].copy_from_slice(&new_status.to_be_bytes());
    data[16..36].copy_from_slice(auth_obj);
    events::emit(&[IDENTITY_STATUS_CHANGED, addr_topic(identity)], &data);
}

fn ensure_initialized_and_valid_caller() -> Result<[u8; 20], i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-50);
    }
    let caller = context::msg_sender();
    if !is_valid_identity_internal(&caller) {
        return Err(ERR_INVALID_IDENTITY);
    }
    Ok(caller)
}

fn consume_registry_auth(
    auth_obj: &[u8; 20],
    action_hash: &[u8; 32],
    caller_identity: &[u8; 20],
) -> Result<(), i32> {
    if !has_allowed_auth_code(auth_obj) {
        return Err(ERR_UNAPPROVED_CODE_HASH);
    }
    let gov_const = storage::get_address(KEY_GOV_CONSTITUTION).unwrap_or([0u8; 20]);
    let gov_pol = storage::get_bytes32(KEY_GOV_POLICY).ok_or(-50)?;
    let self_addr = context::self_address();
    verify_and_consume_auth(
        &self_addr,
        auth_obj,
        &gov_const,
        &gov_pol,
        action_hash,
        caller_identity,
    )
}

fn compute_subject_hash(tag: &[u8; 32], subject: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), tag)
        .push_address(subject)
        .finish()
}

fn compute_gov_hash(constitution: &[u8; 20], policy_id: &[u8; 32]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &TAG_SET_GOV)
        .push_address(constitution)
        .push_bytes32(policy_id)
        .finish()
}

fn compute_code_hash_update(tag: &[u8; 32], code_hash: &[u8; 32], allowed: bool) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), tag)
        .push_bytes32(code_hash)
        .push_u64(u64::from(allowed))
        .finish()
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-51); // already initialized
    }
    let admin_id = args.address(0).ok_or(-3)?;
    let initial_id_code_hash = args.bytes32(1).ok_or(-3)?;
    let initial_auth_code_hash = args.bytes32(2).ok_or(-3)?;
    let initial_packed = args.dynamic_bytes(3).ok_or(-3)?;

    if admin_id == [0u8; 20]
        || initial_id_code_hash == [0u8; 32]
        || initial_auth_code_hash == [0u8; 32]
        || initial_packed.len() % 20 != 0
    {
        return Err(-52);
    }

    // Seed initial approved WASM bytecode hashes for Identity and Authorization subroutines.
    let id_ck = allowed_id_code_key(&initial_id_code_hash);
    storage::set_u64(id_ck.as_slice(), 1);
    let au_ck = allowed_auth_code_key(&initial_auth_code_hash);
    storage::set_u64(au_ck.as_slice(), 1);

    // Attest that `admin_id` AND every genesis Identity is deployed from `initial_id_code_hash`!
    require_allowed_identity_code(&admin_id)?;

    // Default governance: single-account-admin/oracle Authorization bound to `admin_id`.
    let oracle_pol = oracle_policy_id(&admin_id);
    storage::set_address(KEY_ADMIN, &admin_id);
    storage::set_address(KEY_GOV_CONSTITUTION, &[0u8; 20]);
    storage::set(KEY_GOV_POLICY, &oracle_pol);

    // Activate adminIdentity + any packed initial valid identities.
    set_status_internal(&admin_id, STATUS_ACTIVE, &[0u8; 20]);
    let mut offset = 0usize;
    while offset < initial_packed.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&initial_packed[offset..offset + 20]);
        if id == [0u8; 20] {
            return Err(-52);
        }
        require_allowed_identity_code(&id)?;
        set_status_internal(&id, STATUS_ACTIVE, &[0u8; 20]);
        offset += 20;
    }

    storage::set_u64(KEY_INIT, 1);
    let total = storage::get_u64(KEY_ACTIVE_COUNT);
    events::emit(
        &[
            REGISTRY_INITIALIZED,
            addr_topic(&admin_id),
            initial_id_code_hash,
            initial_auth_code_hash,
        ],
        &total.to_be_bytes(),
    );
    Ok(())
}

fn handle_register_identity(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let subject = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if subject == [0u8; 20] {
        return Err(-52);
    }
    // Reject EOAs and malicious/cloned Identity subroutines whose WASM code_hash is not allowed!
    require_allowed_identity_code(&subject)?;

    let cur = get_status(&subject);
    if cur == STATUS_ACTIVE || cur == STATUS_REVOKED {
        return Err(-53); // already active or permanently revoked
    }

    let action_hash = compute_subject_hash(&TAG_REGISTER, &subject);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    set_status_internal(&subject, STATUS_ACTIVE, &auth_obj);
    ret::write_bool(true);
    Ok(())
}

fn handle_suspend_identity(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let subject = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if get_status(&subject) != STATUS_ACTIVE {
        return Err(-54); // must be currently active to suspend
    }

    let action_hash = compute_subject_hash(&TAG_SUSPEND, &subject);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    set_status_internal(&subject, STATUS_SUSPENDED, &auth_obj);
    ret::write_bool(true);
    Ok(())
}

fn handle_reinstate_identity(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let subject = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if get_status(&subject) != STATUS_SUSPENDED {
        return Err(-55); // only suspended identities can be reinstated
    }
    require_allowed_identity_code(&subject)?;

    let action_hash = compute_subject_hash(&TAG_REINSTATE, &subject);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    set_status_internal(&subject, STATUS_ACTIVE, &auth_obj);
    ret::write_bool(true);
    Ok(())
}

fn handle_revoke_identity(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let subject = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    let cur = get_status(&subject);
    if cur == STATUS_UNREGISTERED || cur == STATUS_REVOKED {
        return Err(-56);
    }

    let action_hash = compute_subject_hash(&TAG_REVOKE, &subject);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    set_status_internal(&subject, STATUS_REVOKED, &auth_obj);
    ret::write_bool(true);
    Ok(())
}

fn handle_rotate_admin(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let new_admin = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if !is_valid_identity_internal(&new_admin) {
        return Err(ERR_INVALID_IDENTITY); // new admin must itself be a valid active Identity with approved code_hash
    }

    let action_hash = compute_subject_hash(&TAG_ROTATE_ADMIN, &new_admin);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    storage::set_address(KEY_ADMIN, &new_admin);
    let gov_const = storage::get_address(KEY_GOV_CONSTITUTION).unwrap_or([0u8; 20]);
    if gov_const == [0u8; 20] {
        let new_pol = oracle_policy_id(&new_admin);
        storage::set(KEY_GOV_POLICY, &new_pol);
        events::emit(&[GOVERNANCE_UPDATED, addr_topic(&[0u8; 20]), new_pol], &[]);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_set_governance_policy(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let constitution = args.address(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if policy_id == [0u8; 32] {
        return Err(-52);
    }

    let action_hash = compute_gov_hash(&constitution, &policy_id);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    storage::set_address(KEY_GOV_CONSTITUTION, &constitution);
    storage::set(KEY_GOV_POLICY, &policy_id);
    events::emit(
        &[GOVERNANCE_UPDATED, addr_topic(&constitution), policy_id],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_set_allowed_id_code_hash(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let code_hash = args.bytes32(0).ok_or(-3)?;
    let allowed = args.bool(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if code_hash == [0u8; 32] {
        return Err(-52);
    }

    let action_hash = compute_code_hash_update(&TAG_ALLOW_ID_CODE, &code_hash, allowed);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    let ck = allowed_id_code_key(&code_hash);
    storage::set_u64(ck.as_slice(), u64::from(allowed));
    let mut ev = [0u8; 9];
    ev[0..8].copy_from_slice(&1u64.to_be_bytes()); // kind 1 = Identity
    ev[8] = u8::from(allowed);
    events::emit(&[CODE_HASH_ALLOWLIST_UPDATED, code_hash], &ev);
    ret::write_bool(true);
    Ok(())
}

fn handle_set_allowed_auth_code_hash(args: &CalldataReader) -> Result<(), i32> {
    let caller = ensure_initialized_and_valid_caller()?;
    let code_hash = args.bytes32(0).ok_or(-3)?;
    let allowed = args.bool(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if code_hash == [0u8; 32] {
        return Err(-52);
    }

    let action_hash = compute_code_hash_update(&TAG_ALLOW_AUTH_CODE, &code_hash, allowed);
    consume_registry_auth(&auth_obj, &action_hash, &caller)?;

    let ck = allowed_auth_code_key(&code_hash);
    storage::set_u64(ck.as_slice(), u64::from(allowed));
    let mut ev = [0u8; 9];
    ev[0..8].copy_from_slice(&2u64.to_be_bytes()); // kind 2 = Authorization
    ev[8] = u8::from(allowed);
    events::emit(&[CODE_HASH_ALLOWLIST_UPDATED, code_hash], &ev);
    ret::write_bool(true);
    Ok(())
}

fn handle_is_valid_identity(args: &CalldataReader) -> Result<(), i32> {
    let id = args.address(0).ok_or(-3)?;
    ret::write_bool(is_valid_identity_internal(&id));
    Ok(())
}

fn handle_is_valid_auth_hps(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    ret::write_bool(has_allowed_auth_code(&auth_obj));
    Ok(())
}

fn handle_is_allowed_id_code_hash(args: &CalldataReader) -> Result<(), i32> {
    let h = args.bytes32(0).ok_or(-3)?;
    ret::write_bool(is_allowed_id_code(&h));
    Ok(())
}

fn handle_is_allowed_auth_code_hash(args: &CalldataReader) -> Result<(), i32> {
    let h = args.bytes32(0).ok_or(-3)?;
    ret::write_bool(is_allowed_auth_code(&h));
    Ok(())
}

fn handle_identity_status(args: &CalldataReader) -> Result<(), i32> {
    let id = args.address(0).ok_or(-3)?;
    ret::write_u64_word(get_status(&id));
    Ok(())
}

fn handle_admin_identity(_args: &CalldataReader) -> Result<(), i32> {
    let admin = storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]);
    ret::write_address(&admin);
    Ok(())
}

fn handle_governance_policy(_args: &CalldataReader) -> Result<(), i32> {
    let gov_const = storage::get_address(KEY_GOV_CONSTITUTION).unwrap_or([0u8; 20]);
    let gov_pol = storage::get_bytes32(KEY_GOV_POLICY).unwrap_or([0u8; 32]);
    let mut out = [0u8; 64];
    out[12..32].copy_from_slice(&gov_const);
    out[32..64].copy_from_slice(&gov_pol);
    ret::write(&out);
    Ok(())
}

fn handle_active_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ACTIVE_COUNT));
    Ok(())
}

fn handle_hash_register(args: &CalldataReader) -> Result<(), i32> {
    let subject = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_subject_hash(&TAG_REGISTER, &subject));
    Ok(())
}

fn handle_hash_suspend(args: &CalldataReader) -> Result<(), i32> {
    let subject = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_subject_hash(&TAG_SUSPEND, &subject));
    Ok(())
}

fn handle_hash_reinstate(args: &CalldataReader) -> Result<(), i32> {
    let subject = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_subject_hash(&TAG_REINSTATE, &subject));
    Ok(())
}

fn handle_hash_revoke(args: &CalldataReader) -> Result<(), i32> {
    let subject = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_subject_hash(&TAG_REVOKE, &subject));
    Ok(())
}

fn handle_hash_rotate_admin(args: &CalldataReader) -> Result<(), i32> {
    let subject = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_subject_hash(&TAG_ROTATE_ADMIN, &subject));
    Ok(())
}

fn handle_hash_set_gov(args: &CalldataReader) -> Result<(), i32> {
    let c = args.address(0).ok_or(-3)?;
    let p = args.bytes32(1).ok_or(-3)?;
    ret::write_word(&compute_gov_hash(&c, &p));
    Ok(())
}

fn handle_hash_allow_id_code(args: &CalldataReader) -> Result<(), i32> {
    let h = args.bytes32(0).ok_or(-3)?;
    let a = args.bool(1).ok_or(-3)?;
    ret::write_word(&compute_code_hash_update(&TAG_ALLOW_ID_CODE, &h, a));
    Ok(())
}

fn handle_hash_allow_auth_code(args: &CalldataReader) -> Result<(), i32> {
    let h = args.bytes32(0).ok_or(-3)?;
    let a = args.bool(1).ok_or(-3)?;
    ret::write_word(&compute_code_hash_update(&TAG_ALLOW_AUTH_CODE, &h, a));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const CANONICAL_ID_HASH: [u8; 32] = [0x11; 32];
    const CANONICAL_AUTH_HASH: [u8; 32] = [0x22; 32];
    const MALICIOUS_ID_HASH: [u8; 32] = [0xDE; 32];
    const MALICIOUS_AUTH_HASH: [u8; 32] = [0xAD; 32];

    fn dummy_identity_dispatch(_raw: &[u8]) -> i32 {
        0
    }

    mod simple_oracle_auth {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{context, ret, selector, storage};

        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == selector("setup(address,bytes32,bytes32)") {
                storage::set_address(b"target", &args.address(0).unwrap());
                storage::set(b"pol", &args.bytes32(1).unwrap());
                storage::set(b"hash", &args.bytes32(2).unwrap());
                storage::set_u64(b"used", 0);
                return 0;
            }
            if sel == selector("consume(address,bytes32,bytes32,address)") {
                if storage::get_u64(b"used") != 0 {
                    return -68;
                }
                if context::msg_sender() != storage::get_address(b"target").unwrap() {
                    return -65;
                }
                if args.address(0).unwrap() != [0u8; 20] {
                    return -66;
                }
                if args.bytes32(1).unwrap() != storage::get_bytes32(b"pol").unwrap() {
                    return -66;
                }
                if args.bytes32(2).unwrap() != storage::get_bytes32(b"hash").unwrap() {
                    return -67;
                }
                storage::set_u64(b"used", 1);
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    mod evil_auth_clone {
        use hps_sdk::{ret, selector};
        pub fn dispatch(raw: &[u8]) -> i32 {
            if raw.len() >= 4 && raw[..4] == selector("consume(address,bytes32,bytes32,address)") {
                ret::write_bool(true); // tries to bypass all checks!
                return 0;
            }
            0
        }
    }

    fn encode_init(
        admin: [u8; 20],
        id_code_hash: [u8; 32],
        auth_code_hash: [u8; 32],
        extras: &[[u8; 20]],
    ) -> Vec<u8> {
        let mut packed = Vec::new();
        for a in extras {
            packed.extend_from_slice(a);
        }
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("initialize(address,bytes32,bytes32,bytes)"));
        let mut aw = [0u8; 32];
        aw[12..32].copy_from_slice(&admin);
        cd.extend_from_slice(&aw);
        cd.extend_from_slice(&id_code_hash);
        cd.extend_from_slice(&auth_code_hash);
        let mut off = [0u8; 32];
        off[31] = 0x80; // 4 head words = 128 bytes
        cd.extend_from_slice(&off);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(packed.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(&packed);
        cd.resize(cd.len() + (32 - packed.len() % 32) % 32, 0);
        cd
    }

    #[test]
    fn register_suspend_reinstate_and_reject_malicious_clones_by_code_hash() {
        mock::reset();
        let reg = [0x10; 20];
        let admin_id = [0xA1; 20];
        let alice_id = [0xA2; 20];
        let bob_id = [0xB1; 20];
        let evil_id_clone = [0xE1; 20];
        let raw_eoa = [0xE2; 20]; // not registered as HPS -> no code_hash!
        let stranger = [0xEE; 20];
        let auth1 = [0xC1; 20];
        let auth2 = [0xC2; 20];
        let auth3 = [0xC3; 20];
        let auth_for_evil = [0xC4; 20];
        let auth_for_eoa = [0xC5; 20];
        let evil_auth = [0xF1; 20];

        mock::register_hps(reg, dispatch_calldata);
        for id in [admin_id, alice_id, bob_id] {
            mock::register_hps_with_code_hash(id, CANONICAL_ID_HASH, dummy_identity_dispatch);
        }
        mock::register_hps_with_code_hash(evil_id_clone, MALICIOUS_ID_HASH, dummy_identity_dispatch);

        for au in [auth1, auth2, auth3, auth_for_evil, auth_for_eoa] {
            mock::register_hps_with_code_hash(au, CANONICAL_AUTH_HASH, simple_oracle_auth::dispatch);
        }
        mock::register_hps_with_code_hash(evil_auth, MALICIOUS_AUTH_HASH, evil_auth_clone::dispatch);

        // Genesis initialization with a malicious clone in initialIdentities MUST fail!
        assert_eq!(
            mock::transact_as(
                admin_id,
                reg,
                &encode_init(admin_id, CANONICAL_ID_HASH, CANONICAL_AUTH_HASH, &[evil_id_clone])
            ),
            Err(ERR_UNAPPROVED_CODE_HASH)
        );

        // Valid genesis initialization succeeds
        mock::transact_as(
            admin_id,
            reg,
            &encode_init(admin_id, CANONICAL_ID_HASH, CANONICAL_AUTH_HASH, &[alice_id]),
        )
        .unwrap();

        let is_valid = |who: [u8; 20]| -> bool {
            let q = CallEncoder::<64>::new(selector("isValidIdentity(address)")).push_address(&who);
            mock::transact_as(admin_id, reg, q.as_slice()).unwrap()[31] == 1
        };
        assert!(is_valid(admin_id));
        assert!(is_valid(alice_id));
        assert!(!is_valid(bob_id));
        assert!(!is_valid(evil_id_clone));
        assert!(!is_valid(raw_eoa));

        let oracle_pol = oracle_policy_id(&admin_id);

        // 1. Attempting to register `evil_id_clone` (wrong WASM code_hash) MUST reject with ERR_UNAPPROVED_CODE_HASH!
        let h_evil: [u8; 32] = mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<64>::new(selector("hashRegisterIdentity(address)"))
                .push_address(&evil_id_clone)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            admin_id,
            auth_for_evil,
            CallEncoder::<128>::new(selector("setup(address,bytes32,bytes32)"))
                .push_address(&reg)
                .push_bytes32(&oracle_pol)
                .push_bytes32(&h_evil)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            mock::transact_as(
                admin_id,
                reg,
                CallEncoder::<96>::new(selector("registerIdentity(address,address)"))
                    .push_address(&evil_id_clone)
                    .push_address(&auth_for_evil)
                    .as_slice(),
            ),
            Err(ERR_UNAPPROVED_CODE_HASH)
        );

        // 2. Attempting to register a raw EOA (no WASM code_hash) MUST reject with ERR_UNAPPROVED_CODE_HASH!
        let h_eoa: [u8; 32] = mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<64>::new(selector("hashRegisterIdentity(address)"))
                .push_address(&raw_eoa)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            admin_id,
            auth_for_eoa,
            CallEncoder::<128>::new(selector("setup(address,bytes32,bytes32)"))
                .push_address(&reg)
                .push_bytes32(&oracle_pol)
                .push_bytes32(&h_eoa)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            mock::transact_as(
                admin_id,
                reg,
                CallEncoder::<96>::new(selector("registerIdentity(address,address)"))
                    .push_address(&raw_eoa)
                    .push_address(&auth_for_eoa)
                    .as_slice(),
            ),
            Err(ERR_UNAPPROVED_CODE_HASH)
        );

        // 3. Attempting to register canonical `bob_id` using `evil_auth` (spoofed Authorization clone) MUST reject!
        assert_eq!(
            mock::transact_as(
                admin_id,
                reg,
                CallEncoder::<96>::new(selector("registerIdentity(address,address)"))
                    .push_address(&bob_id)
                    .push_address(&evil_auth)
                    .as_slice(),
            ),
            Err(ERR_UNAPPROVED_CODE_HASH)
        );

        // 4. Registering canonical `bob_id` with canonical `auth1` succeeds!
        let h_reg: [u8; 32] = mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<64>::new(selector("hashRegisterIdentity(address)"))
                .push_address(&bob_id)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            admin_id,
            auth1,
            CallEncoder::<128>::new(selector("setup(address,bytes32,bytes32)"))
                .push_address(&reg)
                .push_bytes32(&oracle_pol)
                .push_bytes32(&h_reg)
                .as_slice(),
        )
        .unwrap();

        let reg_cd = CallEncoder::<96>::new(selector("registerIdentity(address,address)"))
            .push_address(&bob_id)
            .push_address(&auth1);
        assert_eq!(
            mock::transact_as(stranger, reg, reg_cd.as_slice()),
            Err(ERR_INVALID_IDENTITY)
        );
        mock::transact_as(admin_id, reg, reg_cd.as_slice()).unwrap();
        assert!(is_valid(bob_id));

        // Replaying auth1 fails
        assert!(mock::transact_as(admin_id, reg, reg_cd.as_slice()).is_err());

        // Suspend Bob using auth2, then reinstate using auth3
        let h_sus: [u8; 32] = mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<64>::new(selector("hashSuspendIdentity(address)"))
                .push_address(&bob_id)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            admin_id,
            auth2,
            CallEncoder::<128>::new(selector("setup(address,bytes32,bytes32)"))
                .push_address(&reg)
                .push_bytes32(&oracle_pol)
                .push_bytes32(&h_sus)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<96>::new(selector("suspendIdentity(address,address)"))
                .push_address(&bob_id)
                .push_address(&auth2)
                .as_slice(),
        )
        .unwrap();
        assert!(!is_valid(bob_id));

        let h_rein: [u8; 32] = mock::transact_as(
            admin_id,
            reg,
            CallEncoder::<64>::new(selector("hashReinstateIdentity(address)"))
                .push_address(&bob_id)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            admin_id,
            auth3,
            CallEncoder::<128>::new(selector("setup(address,bytes32,bytes32)"))
                .push_address(&reg)
                .push_bytes32(&oracle_pol)
                .push_bytes32(&h_rein)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            alice_id,
            reg,
            CallEncoder::<96>::new(selector("reinstateIdentity(address,address)"))
                .push_address(&bob_id)
                .push_address(&auth3)
                .as_slice(),
        )
        .unwrap();
        assert!(is_valid(bob_id));
    }
}
