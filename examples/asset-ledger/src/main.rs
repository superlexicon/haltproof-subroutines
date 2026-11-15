//! Institutional Asset Ledger **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Implements the four core Asset Ledger capabilities across the HPS governance suite:
//! 1. **Verified Identity Ownership Map**: Maps valid `Identity` HPS addresses (verified live
//!    against `IdentityRegistry.isValidIdentity(address)`) to integer `u64` asset balances.
//!    All state-changing calls must originate from a valid `Identity` HPS (`msg.sender`).
//! 2. **Process-Driven Permissions / Authorizations Map**: Maps each state-changing action key
//!    (`ACTION_ISSUE`, `ACTION_CANCEL`, `ACTION_TRANSFER`, `ACTION_APPROVE`, `ACTION_SUPER`)
//!    to `(constitutionHps, policyId)` — supporting multi-stage sequential (`Group A -> Group B`)
//!    and weighted-joint processes defined in `Constitution`, single-oracle policies, and
//!    `POLICY_HOLDER_SELF` holder-signed one-time authorizations.
//! 3. **Private Generic Internal `internal_debit` & `internal_credit` Primitives**: Unexported
//!    internal balance primitives invoked exclusively by public functions (`issue`, `cancel`,
//!    `transfer`, and allowance-backed `transferFrom`). Every public state-changing invocation
//!    requires and consumes a specific, finalized, timely, **one-time-use `Authorization` HPS**.
//! 4. **Genesis Allocations & `SUPER`-Authorized Governance**: Supports initializing with an
//!    initial map of valid Identities + balances AND a complete setup of permissions, plus
//!    updating any permission rule (`setPermission`) gated by a `SUPER` `Authorization` process.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::governance::{
    oracle_policy_id, require_valid_identity, verify_and_consume_auth, ActionHasher,
    ACTION_APPROVE, ACTION_CANCEL, ACTION_ISSUE, ACTION_SUPER, ACTION_TRANSFER,
    POLICY_HOLDER_SELF,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const LEDGER_INITIALIZED: [u8; 32] = event_topic("LedgerInitialized(address,uint64,uint64)");
const CREDIT_TOPIC: [u8; 32] = event_topic("Credited(address,uint64,uint64)");
const DEBIT_TOPIC: [u8; 32] = event_topic("Debited(address,uint64,uint64)");
const ISSUED_TOPIC: [u8; 32] = event_topic("AssetIssued(address,uint64,uint64,address)");
const CANCELLED_TOPIC: [u8; 32] = event_topic("AssetCancelled(address,uint64,uint64,address)");
const TRANSFER_TOPIC: [u8; 32] = event_topic("Transfer(address,address,uint64)");
const APPROVAL_TOPIC: [u8; 32] = event_topic("Approval(address,address,uint64)");
const PERMISSION_SET_TOPIC: [u8; 32] =
    event_topic("PermissionUpdated(bytes32,address,bytes32,address)");

const KEY_INIT: &[u8] = b"meta:init";
const KEY_REGISTRY: &[u8] = b"meta:registry";
const KEY_SYMBOL: &[u8] = b"meta:symbol";
const KEY_DECIMALS: &[u8] = b"meta:decimals";
const KEY_SUPPLY: &[u8] = b"meta:supply";
const KEY_HOLDER_COUNT: &[u8] = b"meta:holders";

hps_entry! {
    "initialize(address,string,uint64,bytes,bytes)"         => handle_initialize,
    "issue(address,uint64,address)"                         => handle_issue,
    "cancel(address,uint64,address)"                        => handle_cancel,
    "transfer(address,address,uint64,address)"              => handle_transfer,
    "approve(address,uint64,address)"                       => handle_approve,
    "transferFrom(address,address,uint64)"                  => handle_transfer_from,
    "setPermission(bytes32,address,bytes32,address)"        => handle_set_permission,
    "balanceOf(address)"                                    => handle_balance_of,
    "allowance(address,address)"                            => handle_allowance,
    "totalSupply()"                                         => handle_total_supply,
    "totalOutstanding()"                                    => handle_total_supply,
    "holderCount()"                                         => handle_holder_count,
    "decimals()"                                            => handle_decimals,
    "symbol()"                                              => handle_symbol,
    "identityRegistry()"                                    => handle_identity_registry,
    "getPermission(bytes32)"                                => handle_get_permission,
    "hashIssue(address,uint64)"                             => handle_hash_issue,
    "hashCancel(address,uint64)"                            => handle_hash_cancel,
    "hashTransfer(address,address,uint64)"                  => handle_hash_transfer,
    "hashApprove(address,address,uint64)"                   => handle_hash_approve,
    "hashSetPermission(bytes32,address,bytes32)"            => handle_hash_set_permission,
}

#[derive(Clone, Copy)]
struct PermissionRule {
    configured: bool,
    constitution: [u8; 20],
    policy_id: [u8; 32],
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn balance_key(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"bal:").push(identity)
}

fn holder_seen_key(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"hld:").push(identity)
}

fn allowance_key(owner: &[u8; 20], spender: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"alw:")
        .push(owner)
        .push(spender)
}

fn perm_key(action_key: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"prm:").push(action_key)
}

fn load_permission(action_key: &[u8; 32]) -> Option<PermissionRule> {
    let pk = perm_key(action_key);
    let mut raw = [0u8; 53];
    match storage::get_into(pk.as_slice(), &mut raw) {
        Some(53) if raw[0] == 1 => {
            let mut constitution = [0u8; 20];
            constitution.copy_from_slice(&raw[1..21]);
            let mut policy_id = [0u8; 32];
            policy_id.copy_from_slice(&raw[21..53]);
            Some(PermissionRule {
                configured: true,
                constitution,
                policy_id,
            })
        }
        _ => None,
    }
}

fn store_permission(action_key: &[u8; 32], constitution: &[u8; 20], policy_id: &[u8; 32]) {
    let pk = perm_key(action_key);
    let mut raw = [0u8; 53];
    raw[0] = 1;
    raw[1..21].copy_from_slice(constitution);
    raw[21..53].copy_from_slice(policy_id);
    storage::set(pk.as_slice(), &raw);
}

// ============================================================================
// Private Generic Internal `internal_credit` and `internal_debit` Primitives
// (Never exported in `hps_entry!`; callable solely by authorized public entrypoints)
// ============================================================================

fn internal_credit(identity: &[u8; 20], amount: u64) -> Result<u64, i32> {
    if *identity == [0u8; 20] || amount == 0 {
        return Err(-14);
    }
    let bk = balance_key(identity);
    let prev = storage::get_u64(bk.as_slice());
    let next = prev.checked_add(amount).ok_or(-15)?;
    storage::set_u64(bk.as_slice(), next);

    let hk = holder_seen_key(identity);
    if storage::get_u64(hk.as_slice()) == 0 {
        storage::set_u64(hk.as_slice(), 1);
        let cnt = storage::get_u64(KEY_HOLDER_COUNT);
        storage::set_u64(KEY_HOLDER_COUNT, cnt + 1);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&next.to_be_bytes());
    events::emit(&[CREDIT_TOPIC, addr_topic(identity)], &ev);
    Ok(next)
}

fn internal_debit(identity: &[u8; 20], amount: u64) -> Result<u64, i32> {
    if *identity == [0u8; 20] || amount == 0 {
        return Err(-14);
    }
    let bk = balance_key(identity);
    let prev = storage::get_u64(bk.as_slice());
    if prev < amount {
        return Err(-16); // insufficient balance
    }
    let next = prev - amount;
    storage::set_u64(bk.as_slice(), next);

    if next == 0 {
        let hk = holder_seen_key(identity);
        if storage::get_u64(hk.as_slice()) == 1 {
            storage::set_u64(hk.as_slice(), 0);
            let cnt = storage::get_u64(KEY_HOLDER_COUNT);
            storage::set_u64(KEY_HOLDER_COUNT, cnt.saturating_sub(1));
        }
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&next.to_be_bytes());
    events::emit(&[DEBIT_TOPIC, addr_topic(identity)], &ev);
    Ok(next)
}

// ============================================================================
// Action-Hash Commitments & Authorization Verification
// ============================================================================

fn compute_issue_hash(to_identity: &[u8; 20], amount: u64) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_ISSUE)
        .push_address(to_identity)
        .push_u64(amount)
        .finish()
}

fn compute_cancel_hash(from_identity: &[u8; 20], amount: u64) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_CANCEL)
        .push_address(from_identity)
        .push_u64(amount)
        .finish()
}

fn compute_transfer_hash(
    from_identity: &[u8; 20],
    to_identity: &[u8; 20],
    amount: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_TRANSFER)
        .push_address(from_identity)
        .push_address(to_identity)
        .push_u64(amount)
        .finish()
}

fn compute_approve_hash(
    owner_identity: &[u8; 20],
    spender: &[u8; 20],
    amount: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_APPROVE)
        .push_address(owner_identity)
        .push_address(spender)
        .push_u64(amount)
        .finish()
}

fn compute_set_perm_hash(
    action_key: &[u8; 32],
    constitution: &[u8; 20],
    policy_id: &[u8; 32],
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_SUPER)
        .push_bytes32(action_key)
        .push_address(constitution)
        .push_bytes32(policy_id)
        .finish()
}

fn ensure_initialized_and_valid_caller() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, caller))
}

fn require_and_consume_permission(
    registry: &[u8; 20],
    action_key: &[u8; 32],
    subject_holder: Option<&[u8; 20]>,
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
    caller_identity: &[u8; 20],
) -> Result<(), i32> {
    let rule = load_permission(action_key).ok_or(-13)?; // permission not configured for action
    let (expected_con, expected_pol) =
        if rule.constitution == [0u8; 20] && rule.policy_id == POLICY_HOLDER_SELF {
            let holder = subject_holder.ok_or(-13)?;
            ([0u8; 20], oracle_policy_id(holder))
        } else {
            (rule.constitution, rule.policy_id)
        };
    verify_and_consume_auth(
        registry,
        auth_obj,
        &expected_con,
        &expected_pol,
        action_hash,
        caller_identity,
    )
}

// ============================================================================
// Public Entrypoints
// ============================================================================

/// Initialize Asset Ledger with:
/// - `identityRegistry`: Verified Identity Register HPS address
/// - `symbol`: UTF-8 asset ticker (`1..=32` bytes)
/// - `decimals`: integer display decimals
/// - `initialAllocations`: `N * 28` bytes of `[identity: 20B][balance: u64 BE]`
/// - `initialPermissions`: `M * 84` bytes of `[actionKey: 32B][constitution: 20B][policyId: 32B]`
///   (must include `ACTION_SUPER` so future permission updates require `SUPER` authorization).
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11); // already initialized
    }
    let registry = args.address(0).ok_or(-3)?;
    let symbol = args.dynamic_bytes(1).ok_or(-3)?;
    let decimals = args.u64(2).ok_or(-3)?;
    let initial_allocs = args.dynamic_bytes(3).ok_or(-3)?;
    let initial_perms = args.dynamic_bytes(4).ok_or(-3)?;

    if registry == [0u8; 20]
        || symbol.is_empty()
        || symbol.len() > 32
        || initial_allocs.len() % 28 != 0
        || initial_perms.is_empty()
        || initial_perms.len() % 84 != 0
    {
        return Err(-12);
    }

    // Calling initializer must itself be a valid Identity in `IdentityRegistry`.
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    // 1. Validate & populate initial permissions map (must configure ACTION_SUPER).
    let mut has_super = false;
    let mut p_off = 0usize;
    while p_off < initial_perms.len() {
        let mut act = [0u8; 32];
        act.copy_from_slice(&initial_perms[p_off..p_off + 32]);
        let mut con = [0u8; 20];
        con.copy_from_slice(&initial_perms[p_off + 32..p_off + 52]);
        let mut pol = [0u8; 32];
        pol.copy_from_slice(&initial_perms[p_off + 52..p_off + 84]);
        p_off += 84;

        if act == [0u8; 32] || pol == [0u8; 32] {
            return Err(-12);
        }
        if act == ACTION_SUPER {
            if pol == POLICY_HOLDER_SELF {
                return Err(-12); // SUPER cannot use dynamic holder-self sentinel
            }
            has_super = true;
        }
        store_permission(&act, &con, &pol);
    }
    if !has_super {
        return Err(-18); // ACTION_SUPER permission must be defined at initialization
    }

    // 2. Validate & credit initial Identity allocations via `internal_credit`.
    let mut total_supply: u64 = 0;
    let mut a_off = 0usize;
    while a_off < initial_allocs.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&initial_allocs[a_off..a_off + 20]);
        let mut bb = [0u8; 8];
        bb.copy_from_slice(&initial_allocs[a_off + 20..a_off + 28]);
        let bal = u64::from_be_bytes(bb);
        a_off += 28;

        require_valid_identity(&registry, &id)?;
        if bal > 0 {
            internal_credit(&id, bal)?;
            total_supply = total_supply.checked_add(bal).ok_or(-15)?;
        }
    }

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set(KEY_SYMBOL, symbol);
    storage::set_u64(KEY_DECIMALS, decimals);
    storage::set_u64(KEY_SUPPLY, total_supply);
    storage::set_u64(KEY_INIT, 1);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&total_supply.to_be_bytes());
    ev[8..16].copy_from_slice(&((initial_perms.len() / 84) as u64).to_be_bytes());
    events::emit(&[LEDGER_INITIALIZED, addr_topic(&registry)], &ev);
    Ok(())
}

/// Issue (`mint`) `amount` new units to valid Identity `toIdentity`, increasing total outstanding supply.
/// Requires a finalized, one-time-use `Authorization` object matching `ACTION_ISSUE`.
fn handle_issue(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let to_identity = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    require_valid_identity(&registry, &to_identity)?;
    let action_hash = compute_issue_hash(&to_identity, amount);
    require_and_consume_permission(&registry, &ACTION_ISSUE, None, &action_hash, &auth_obj, &caller)?;

    let new_supply = storage::get_u64(KEY_SUPPLY)
        .checked_add(amount)
        .ok_or(-15)?;
    let new_bal = internal_credit(&to_identity, amount)?;
    storage::set_u64(KEY_SUPPLY, new_supply);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_supply.to_be_bytes());
    events::emit(
        &[ISSUED_TOPIC, addr_topic(&to_identity), addr_topic(&auth_obj)],
        &ev,
    );
    events::emit(
        &[TRANSFER_TOPIC, addr_topic(&[0u8; 20]), addr_topic(&to_identity)],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(new_bal);
    Ok(())
}

/// Cancel (`burn`) `amount` units from valid Identity `fromIdentity`, decreasing total outstanding supply.
/// Requires a finalized, one-time-use `Authorization` object matching `ACTION_CANCEL`.
fn handle_cancel(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let from_identity = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    require_valid_identity(&registry, &from_identity)?;
    let action_hash = compute_cancel_hash(&from_identity, amount);
    require_and_consume_permission(
        &registry,
        &ACTION_CANCEL,
        Some(&from_identity),
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    let cur_supply = storage::get_u64(KEY_SUPPLY);
    if cur_supply < amount {
        return Err(-16);
    }
    let new_bal = internal_debit(&from_identity, amount)?;
    let new_supply = cur_supply - amount;
    storage::set_u64(KEY_SUPPLY, new_supply);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_supply.to_be_bytes());
    events::emit(
        &[
            CANCELLED_TOPIC,
            addr_topic(&from_identity),
            addr_topic(&auth_obj),
        ],
        &ev,
    );
    events::emit(
        &[TRANSFER_TOPIC, addr_topic(&from_identity), addr_topic(&[0u8; 20])],
        &amount.to_be_bytes(),
    );
    ret::write_u64_word(new_bal);
    Ok(())
}

/// Move `amount` units from valid Identity `fromIdentity` to valid Identity `toIdentity`
/// via `internal_debit` + `internal_credit`.
/// Requires a finalized, one-time-use `Authorization` object matching `ACTION_TRANSFER`.
fn handle_transfer(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let from_identity = args.address(0).ok_or(-3)?;
    let to_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;
    if amount == 0 || from_identity == to_identity {
        return Err(-14);
    }

    require_valid_identity(&registry, &from_identity)?;
    require_valid_identity(&registry, &to_identity)?;

    let action_hash = compute_transfer_hash(&from_identity, &to_identity, amount);
    require_and_consume_permission(
        &registry,
        &ACTION_TRANSFER,
        Some(&from_identity),
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    internal_debit(&from_identity, amount)?;
    internal_credit(&to_identity, amount)?;

    events::emit(
        &[
            TRANSFER_TOPIC,
            addr_topic(&from_identity),
            addr_topic(&to_identity),
        ],
        &amount.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Authorize a settlement contract `spender` (such as `AssetPair_OTC`) to debit up to `amount`
/// from the calling valid Identity's balance. Requires a one-time `Authorization` object matching `ACTION_APPROVE`.
fn handle_approve(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let spender = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;
    if spender == [0u8; 20] {
        return Err(-14);
    }

    let action_hash = compute_approve_hash(&caller, &spender, amount);
    require_and_consume_permission(
        &registry,
        &ACTION_APPROVE,
        Some(&caller),
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    let ak = allowance_key(&caller, &spender);
    storage::set_u64(ak.as_slice(), amount);

    events::emit(
        &[APPROVAL_TOPIC, addr_topic(&caller), addr_topic(&spender)],
        &amount.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Execute an allowance-backed settlement transfer (e.g., invoked atomically by `AssetPair_OTC`),
/// verifying both `fromIdentity` and `toIdentity` in `IdentityRegistry` and using `internal_debit` / `internal_credit`.
fn handle_transfer_from(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let from_identity = args.address(0).ok_or(-3)?;
    let to_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    if amount == 0 || from_identity == to_identity {
        return Err(-14);
    }

    require_valid_identity(&registry, &from_identity)?;
    require_valid_identity(&registry, &to_identity)?;

    let spender = context::msg_sender();
    let ak = allowance_key(&from_identity, &spender);
    let allowed = storage::get_u64(ak.as_slice());
    if allowed < amount {
        return Err(-17); // insufficient allowance
    }
    storage::set_u64(ak.as_slice(), allowed - amount);

    internal_debit(&from_identity, amount)?;
    internal_credit(&to_identity, amount)?;

    events::emit(
        &[
            TRANSFER_TOPIC,
            addr_topic(&from_identity),
            addr_topic(&to_identity),
        ],
        &amount.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Update or add a permission rule for `actionKey`.
/// Requires a finalized, one-time-use **`SUPER`** `Authorization` HPS object fulfilling `ACTION_SUPER`.
fn handle_set_permission(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let action_key = args.bytes32(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let policy_id = args.bytes32(2).ok_or(-3)?;
    let super_auth = args.address(3).ok_or(-3)?;

    if action_key == [0u8; 32]
        || policy_id == [0u8; 32]
        || (action_key == ACTION_SUPER && policy_id == POLICY_HOLDER_SELF)
    {
        return Err(-12);
    }

    let action_hash = compute_set_perm_hash(&action_key, &constitution, &policy_id);
    require_and_consume_permission(&registry, &ACTION_SUPER, None, &action_hash, &super_auth, &caller)?;

    store_permission(&action_key, &constitution, &policy_id);

    events::emit(
        &[
            PERMISSION_SET_TOPIC,
            action_key,
            addr_topic(&constitution),
            policy_id,
        ],
        &super_auth,
    );
    ret::write_bool(true);
    Ok(())
}

// ============================================================================
// Read-Only Queries & Action-Hash Helpers
// ============================================================================

fn handle_balance_of(args: &CalldataReader) -> Result<(), i32> {
    let holder = args.address(0).ok_or(-3)?;
    let bk = balance_key(&holder);
    ret::write_u64_word(storage::get_u64(bk.as_slice()));
    Ok(())
}

fn handle_allowance(args: &CalldataReader) -> Result<(), i32> {
    let owner = args.address(0).ok_or(-3)?;
    let spender = args.address(1).ok_or(-3)?;
    let ak = allowance_key(&owner, &spender);
    ret::write_u64_word(storage::get_u64(ak.as_slice()));
    Ok(())
}

fn handle_total_supply(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_SUPPLY));
    Ok(())
}

fn handle_holder_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_HOLDER_COUNT));
    Ok(())
}

fn handle_decimals(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_DECIMALS));
    Ok(())
}

fn handle_symbol(_args: &CalldataReader) -> Result<(), i32> {
    match storage::get_ref(KEY_SYMBOL) {
        Some(sym) => ret::write_abi_bytes(sym),
        None => ret::write_abi_bytes(&[]),
    }
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_get_permission(args: &CalldataReader) -> Result<(), i32> {
    let action_key = args.bytes32(0).ok_or(-3)?;
    let mut out = [0u8; 96];
    if let Some(rule) = load_permission(&action_key) {
        out[12..32].copy_from_slice(&rule.constitution);
        out[32..64].copy_from_slice(&rule.policy_id);
        out[95] = u8::from(rule.configured);
    }
    ret::write(&out);
    Ok(())
}

fn handle_hash_issue(args: &CalldataReader) -> Result<(), i32> {
    let to = args.address(0).ok_or(-3)?;
    let amt = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_issue_hash(&to, amt));
    Ok(())
}

fn handle_hash_cancel(args: &CalldataReader) -> Result<(), i32> {
    let from = args.address(0).ok_or(-3)?;
    let amt = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_cancel_hash(&from, amt));
    Ok(())
}

fn handle_hash_transfer(args: &CalldataReader) -> Result<(), i32> {
    let from = args.address(0).ok_or(-3)?;
    let to = args.address(1).ok_or(-3)?;
    let amt = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_transfer_hash(&from, &to, amt));
    Ok(())
}

fn handle_hash_approve(args: &CalldataReader) -> Result<(), i32> {
    let owner = args.address(0).ok_or(-3)?;
    let spender = args.address(1).ok_or(-3)?;
    let amt = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_approve_hash(&owner, &spender, amt));
    Ok(())
}

fn handle_hash_set_permission(args: &CalldataReader) -> Result<(), i32> {
    let act = args.bytes32(0).ok_or(-3)?;
    let con = args.address(1).ok_or(-3)?;
    let pol = args.bytes32(2).ok_or(-3)?;
    ret::write_word(&compute_set_perm_hash(&act, &con, &pol));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::governance::ERR_INVALID_IDENTITY;
    use hps_sdk::{mock, selector};

    mod sim_suite {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{context, ret, selector, storage};

        pub fn reg_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("isValidIdentity(address)") {
                let id = args.address(0).unwrap();
                ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                return 0;
            }
            if sel == selector("isValidAuthorizationHps(address)") {
                let au = args.address(0).unwrap();
                let expected = hps_sdk::mock::dispatch_code_hash(auth_dispatch);
                ret::write_bool(context::code_hash_of(&au) == Some(expected));
                return 0;
            }
            -2
        }

        pub fn auth_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("arm(address,address,bytes32,bytes32)") {
                storage::set_address(b"target", &args.address(0).unwrap());
                storage::set_address(b"con", &args.address(1).unwrap());
                storage::set(b"pol", &args.bytes32(2).unwrap());
                storage::set(b"hash", &args.bytes32(3).unwrap());
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
                if args.address(0).unwrap() != storage::get_address(b"con").unwrap() {
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

    fn encode_ledger_init(
        reg: [u8; 20],
        sym: &[u8],
        decimals: u64,
        allocs: &[([u8; 20], u64)],
        perms: &[([u8; 32], [u8; 20], [u8; 32])],
    ) -> Vec<u8> {
        let mut alloc_bytes = Vec::new();
        for (id, bal) in allocs {
            alloc_bytes.extend_from_slice(id);
            alloc_bytes.extend_from_slice(&bal.to_be_bytes());
        }
        let mut perm_bytes = Vec::new();
        for (act, con, pol) in perms {
            perm_bytes.extend_from_slice(act);
            perm_bytes.extend_from_slice(con);
            perm_bytes.extend_from_slice(pol);
        }

        // Head = 5 words (160 bytes = 0xA0)
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("initialize(address,string,uint64,bytes,bytes)"));

        let pad_len = |n: usize| n + (32 - n % 32) % 32;
        let sym_off = 160u64;
        let alloc_off = sym_off + 32 + (pad_len(sym.len()) as u64);
        let perm_off = alloc_off + 32 + (pad_len(alloc_bytes.len()) as u64);

        let push_u64_w = |v: &mut Vec<u8>, n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&w);
        };
        let push_dyn = |v: &mut Vec<u8>, b: &[u8]| {
            let mut lw = [0u8; 32];
            lw[24..32].copy_from_slice(&(b.len() as u64).to_be_bytes());
            v.extend_from_slice(&lw);
            v.extend_from_slice(b);
            v.resize(v.len() + (32 - b.len() % 32) % 32, 0);
        };

        let mut rw = [0u8; 32];
        rw[12..32].copy_from_slice(&reg);
        cd.extend_from_slice(&rw);
        push_u64_w(&mut cd, sym_off);
        push_u64_w(&mut cd, decimals);
        push_u64_w(&mut cd, alloc_off);
        push_u64_w(&mut cd, perm_off);

        push_dyn(&mut cd, sym);
        push_dyn(&mut cd, &alloc_bytes);
        push_dyn(&mut cd, &perm_bytes);
        cd
    }

    #[test]
    fn genesis_issue_cancel_transfer_and_super_permission_rotation() {
        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let con_v2 = [0x21; 20];
        let ledger = [0x30; 20];

        let treasury_id = [0xA1; 20];
        let alice_id = [0xA2; 20];
        let bob_id = [0xA3; 20];
        let unverified = [0xEE; 20];

        let auth_issue = [0xC1; 20];
        let auth_transfer = [0xC2; 20];
        let auth_cancel = [0xC3; 20];
        let auth_super = [0xC4; 20];
        let auth_issue_v2 = [0xC5; 20];

        mock::register_hps(reg, sim_suite::reg_dispatch);
        mock::register_hps(ledger, dispatch_calldata);
        for a in [auth_issue, auth_transfer, auth_cancel, auth_super, auth_issue_v2] {
            mock::register_hps(a, sim_suite::auth_dispatch);
        }

        let init_cd = encode_ledger_init(
            reg,
            b"BOND26",
            2,
            &[(treasury_id, 1_000), (alice_id, 250)],
            &[
                (ACTION_SUPER, con, ACTION_SUPER),
                (ACTION_ISSUE, con, ACTION_ISSUE),
                (ACTION_CANCEL, con, ACTION_CANCEL),
                (ACTION_TRANSFER, [0u8; 20], POLICY_HOLDER_SELF),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(treasury_id, ledger, &init_cd).unwrap();

        let bal_of = |who: [u8; 20]| -> u64 {
            let out = mock::transact_as(
                treasury_id,
                ledger,
                CallEncoder::<64>::new(selector("balanceOf(address)"))
                    .push_address(&who)
                    .as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };
        let supply = || -> u64 {
            let out = mock::transact_as(
                treasury_id,
                ledger,
                CallEncoder::<16>::new(selector("totalOutstanding()")).as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };

        assert_eq!(bal_of(treasury_id), 1_000);
        assert_eq!(bal_of(alice_id), 250);
        assert_eq!(supply(), 1_250);

        // 1. Issue 500 to Bob using one-time Constitution-backed auth_issue
        let h_iss: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<96>::new(selector("hashIssue(address,uint64)"))
                .push_address(&bob_id)
                .push_u64(500)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            treasury_id,
            auth_issue,
            CallEncoder::<160>::new(selector("arm(address,address,bytes32,bytes32)"))
                .push_address(&ledger)
                .push_address(&con)
                .push_bytes32(&ACTION_ISSUE)
                .push_bytes32(&h_iss)
                .as_slice(),
        )
        .unwrap();

        let iss_cd = CallEncoder::<128>::new(selector("issue(address,uint64,address)"))
            .push_address(&bob_id)
            .push_u64(500)
            .push_address(&auth_issue);
        // Unverified caller is rejected before consuming auth_issue!
        assert_eq!(
            mock::transact_as(unverified, ledger, iss_cd.as_slice()),
            Err(ERR_INVALID_IDENTITY)
        );
        mock::transact_as(treasury_id, ledger, iss_cd.as_slice()).unwrap();
        assert_eq!(bal_of(bob_id), 500);
        assert_eq!(supply(), 1_750);
        // One-time replay of auth_issue MUST fail!
        assert_eq!(
            mock::transact_as(treasury_id, ledger, iss_cd.as_slice()),
            Err(-68)
        );

        // 2. Transfer 100 from Alice -> Bob via Alice's one-time POLICY_HOLDER_SELF auth_transfer
        let h_tf: [u8; 32] = mock::transact_as(
            alice_id,
            ledger,
            CallEncoder::<128>::new(selector("hashTransfer(address,address,uint64)"))
                .push_address(&alice_id)
                .push_address(&bob_id)
                .push_u64(100)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            alice_id,
            auth_transfer,
            CallEncoder::<160>::new(selector("arm(address,address,bytes32,bytes32)"))
                .push_address(&ledger)
                .push_address(&[0u8; 20])
                .push_bytes32(&oracle_policy_id(&alice_id))
                .push_bytes32(&h_tf)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            alice_id,
            ledger,
            CallEncoder::<160>::new(selector("transfer(address,address,uint64,address)"))
                .push_address(&alice_id)
                .push_address(&bob_id)
                .push_u64(100)
                .push_address(&auth_transfer)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(alice_id), 150);
        assert_eq!(bal_of(bob_id), 600);
        assert_eq!(supply(), 1_750);

        // 3. Cancel 200 from Treasury using one-time auth_cancel
        let h_can: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<96>::new(selector("hashCancel(address,uint64)"))
                .push_address(&treasury_id)
                .push_u64(200)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            treasury_id,
            auth_cancel,
            CallEncoder::<160>::new(selector("arm(address,address,bytes32,bytes32)"))
                .push_address(&ledger)
                .push_address(&con)
                .push_bytes32(&ACTION_CANCEL)
                .push_bytes32(&h_can)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<128>::new(selector("cancel(address,uint64,address)"))
                .push_address(&treasury_id)
                .push_u64(200)
                .push_address(&auth_cancel)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(treasury_id), 800);
        assert_eq!(supply(), 1_550);

        // 4. Rotate ACTION_ISSUE permission to `con_v2` using a SUPER authorization object!
        let new_pol = [0x99; 32];
        let h_perm: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<128>::new(selector("hashSetPermission(bytes32,address,bytes32)"))
                .push_bytes32(&ACTION_ISSUE)
                .push_address(&con_v2)
                .push_bytes32(&new_pol)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            treasury_id,
            auth_super,
            CallEncoder::<160>::new(selector("arm(address,address,bytes32,bytes32)"))
                .push_address(&ledger)
                .push_address(&con)
                .push_bytes32(&ACTION_SUPER)
                .push_bytes32(&h_perm)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<160>::new(selector("setPermission(bytes32,address,bytes32,address)"))
                .push_bytes32(&ACTION_ISSUE)
                .push_address(&con_v2)
                .push_bytes32(&new_pol)
                .push_address(&auth_super)
                .as_slice(),
        )
        .unwrap();

        // Old `con` policy for issue is now rejected; `con_v2` + `new_pol` succeeds!
        let h_iss2: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<96>::new(selector("hashIssue(address,uint64)"))
                .push_address(&alice_id)
                .push_u64(50)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            treasury_id,
            auth_issue_v2,
            CallEncoder::<160>::new(selector("arm(address,address,bytes32,bytes32)"))
                .push_address(&ledger)
                .push_address(&con_v2)
                .push_bytes32(&new_pol)
                .push_bytes32(&h_iss2)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<128>::new(selector("issue(address,uint64,address)"))
                .push_address(&alice_id)
                .push_u64(50)
                .push_address(&auth_issue_v2)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(alice_id), 200);
        assert_eq!(supply(), 1_600);
    }
}
