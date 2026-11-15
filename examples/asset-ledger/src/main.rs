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
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    oracle_policy_id, require_valid_identity, verify_and_consume_auction_auth,
    verify_and_consume_auth, ActionHasher, AuctionOrder, ACTION_APPROVE, ACTION_CANCEL,
    ACTION_ISSUE, ACTION_SUPER, ACTION_TRANSFER, ERR_CONSTITUTION_MISMATCH, ERR_NO_CROSSING_ORDERS,
    MAX_AUCTION_ORDERS, POLICY_HOLDER_SELF, POLICY_SHARE_TRANSFER_AUCTION,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const LEDGER_INITIALIZED: [u8; 32] = event_topic("LedgerInitialized(address,uint64,uint64)");
const CONSTITUTION_PINNED: [u8; 32] = event_topic("ConstitutionPinned(address)");
const CREDIT_TOPIC: [u8; 32] = event_topic("Credited(address,uint64,uint64)");
const DEBIT_TOPIC: [u8; 32] = event_topic("Debited(address,uint64,uint64)");
const ISSUED_TOPIC: [u8; 32] = event_topic("AssetIssued(address,uint64,uint64,address)");
const CANCELLED_TOPIC: [u8; 32] = event_topic("AssetCancelled(address,uint64,uint64,address)");
const TRANSFER_TOPIC: [u8; 32] = event_topic("Transfer(address,address,uint64)");
const APPROVAL_TOPIC: [u8; 32] = event_topic("Approval(address,address,uint64)");
const PERMISSION_SET_TOPIC: [u8; 32] =
    event_topic("PermissionUpdated(bytes32,address,bytes32,address)");
const AUCTION_SETTLED_TOPIC: [u8; 32] =
    event_topic("AuctionTransferSettled(address,uint64,uint64,uint64,uint64,uint64,uint64)");
const AUCTION_BUYER_FILLED: [u8; 32] =
    event_topic("AuctionBuyerFilled(address,uint64,uint64,uint64)");
const AUCTION_SELLER_FILLED: [u8; 32] =
    event_topic("AuctionSellerFilled(address,uint64,uint64,uint64,uint64)");

const KEY_INIT: &[u8] = b"meta:init";
const KEY_REGISTRY: &[u8] = b"meta:registry";
const KEY_CONSTITUTION: &[u8] = b"meta:constitution";
const KEY_SYMBOL: &[u8] = b"meta:symbol";
const KEY_DECIMALS: &[u8] = b"meta:decimals";
const KEY_SUPPLY: &[u8] = b"meta:supply";
const KEY_HOLDER_COUNT: &[u8] = b"meta:holders";
const KEY_LAST_AUC_PRICE: &[u8] = b"meta:auc_price";
const KEY_LAST_AUC_QTY: &[u8] = b"meta:auc_qty";
const KEY_LAST_AUC_BUY_DEMAND: &[u8] = b"meta:auc_buy_q";
const KEY_LAST_AUC_SELL_SUPPLY: &[u8] = b"meta:auc_sell_q";

hps_entry! {
    "initialize(address,string,uint64,bytes,bytes)"         => handle_initialize,
    "issue(address,uint64,address)"                         => handle_issue,
    "cancel(address,uint64,address)"                        => handle_cancel,
    "transfer(address,address,uint64,address)"              => handle_transfer,
    "transferDirect(address,uint64)"                        => handle_transfer_direct,
    "constitutionClearTransfer(address,address,uint64)"     => handle_constitution_clear_transfer,
    "settleTransferAuction(address)"                        => handle_settle_transfer_auction,
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
    "associatedConstitution()"                              => handle_associated_constitution,
    "getPermission(bytes32)"                                => handle_get_permission,
    "lastAuctionSettlement()"                               => handle_last_auction_settlement,
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
    let pinned_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    if !(pinned_con != [0u8; 20] && caller == pinned_con) {
        require_valid_identity(&registry, &caller)?;
    }
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
    if *action_key == ACTION_TRANSFER
        && rule.constitution == [0u8; 20]
        && rule.policy_id == POLICY_HOLDER_SELF
        && *auth_obj == [0u8; 20]
    {
        // On bank-account ledgers (`POLICY_HOLDER_SELF`), a verified client Identity can sign and
        // submit a transfer directly (`authObj == 0x0`) when `caller == fromIdentity`.
        let holder = subject_holder.ok_or(-13)?;
        if caller_identity == holder {
            return Ok(());
        }
        return Err(-65);
    }
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

    // 1. Validate & populate initial permissions map (must configure ACTION_SUPER and bind at most ONE Constitution HPS).
    let mut has_super = false;
    let mut pinned_constitution = [0u8; 20];
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
        if con != [0u8; 20] {
            if pinned_constitution == [0u8; 20] {
                pinned_constitution = con;
            } else if pinned_constitution != con {
                return Err(ERR_CONSTITUTION_MISMATCH); // AssetLedger can ONLY be associated with a single Constitution HPS
            }
        }
        if act == ACTION_SUPER {
            if pol == POLICY_HOLDER_SELF || con == [0u8; 20] {
                return Err(-12); // SUPER cannot use dynamic holder-self sentinel
            }
            has_super = true;
        }
        store_permission(&act, &con, &pol);
    }
    if !has_super || pinned_constitution == [0u8; 20] {
        return Err(-18); // ACTION_SUPER permission and single Constitution must be defined at initialization
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
    storage::set_address(KEY_CONSTITUTION, &pinned_constitution);
    storage::set(KEY_SYMBOL, symbol);
    storage::set_u64(KEY_DECIMALS, decimals);
    storage::set_u64(KEY_SUPPLY, total_supply);
    storage::set_u64(KEY_INIT, 1);

    events::emit(&[CONSTITUTION_PINNED, addr_topic(&pinned_constitution)], &[]);
    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&total_supply.to_be_bytes());
    ev[8..16].copy_from_slice(&((initial_perms.len() / 84) as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&storage::get_u64(KEY_HOLDER_COUNT).to_be_bytes());
    events::emit(
        &[
            LEDGER_INITIALIZED,
            addr_topic(&registry),
            addr_topic(&pinned_constitution),
        ],
        &ev,
    );
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

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_supply.to_be_bytes());
    ev[16..24].copy_from_slice(&new_bal.to_be_bytes());
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

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_supply.to_be_bytes());
    ev[16..24].copy_from_slice(&new_bal.to_be_bytes());
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
/// via `internal_debit` + `internal_credit`, OR settle a finalized 3-step share-transfer auction
/// when `ACTION_TRANSFER` is governed by `POLICY_SHARE_TRANSFER_AUCTION` (or when `fromIdentity`
/// and `toIdentity` are zero and `amount == 0`).
/// Requires a finalized, one-time-use `Authorization` object matching `ACTION_TRANSFER`.
fn handle_transfer(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let from_identity = args.address(0).ok_or(-3)?;
    let to_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let rule = load_permission(&ACTION_TRANSFER).ok_or(-12)?;
    if rule.policy_id == POLICY_SHARE_TRANSFER_AUCTION
        || (from_identity == [0u8; 20] && to_identity == [0u8; 20] && amount == 0)
    {
        execute_transfer_auction_settlement(&registry, &caller, &auth_obj)?;
        ret::write_bool(true);
        return Ok(());
    }

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

/// Simple client-signed direct transfer (`toIdentity`, `amount`) for bank-account AssetLedgers
/// where `ACTION_TRANSFER` is governed by `POLICY_HOLDER_SELF`.
fn handle_transfer_direct(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let to_identity = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;
    if amount == 0 || caller == to_identity {
        return Err(-14);
    }

    let rule = load_permission(&ACTION_TRANSFER).ok_or(-12)?;
    if !(rule.constitution == [0u8; 20] && rule.policy_id == POLICY_HOLDER_SELF) {
        return Err(-13);
    }

    require_valid_identity(&registry, &to_identity)?;
    internal_debit(&caller, amount)?;
    internal_credit(&to_identity, amount)?;

    events::emit(
        &[TRANSFER_TOPIC, addr_topic(&caller), addr_topic(&to_identity)],
        &amount.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Clearing & escrow transfer invoked exclusively by this ledger's single `associatedConstitution()`
/// to move bank-account sub-account balances between buyers, sellers, and the Constitution's
/// special clearing account during a 3-step share transfer auction.
fn handle_constitution_clear_transfer(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let pinned_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    if pinned_con == [0u8; 20] || context::msg_sender() != pinned_con {
        return Err(ERR_CONSTITUTION_MISMATCH);
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

/// Settle a finalized 3-step Call-Auction `Authorization` HPS (`POLICY_SHARE_TRANSFER_AUCTION`)
/// for the AssetLedger's own shares, returning `(uint64 clearingPrice, uint64 matchedQuantity,
/// uint64 crossingBuyDemand, uint64 crossingSellSupply)`.
fn handle_settle_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let (clearing_price, matched_qty, buy_demand, sell_supply) =
        execute_transfer_auction_settlement(&registry, &caller, &auth_obj)?;
    let mut out = [0u8; 128];
    out[24..32].copy_from_slice(&clearing_price.to_be_bytes());
    out[56..64].copy_from_slice(&matched_qty.to_be_bytes());
    out[88..96].copy_from_slice(&buy_demand.to_be_bytes());
    out[120..128].copy_from_slice(&sell_supply.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Core single-price call-auction clearing and pro-rata settlement engine:
/// 1. Consumes the finalized one-time `Authorization` HPS via `verify_and_consume_auction_auth`.
/// 2. Snapshots every participating seller's pre-settlement shareholding (`balanceOf(seller)`).
/// 3. Identifies the single best clearing price `P*` that maximizes matched volume
///    `min(D(P), S(P))` across crossing orders (`buy.price >= P* >= sell.price`).
/// 4. Allocates fills across crossing buyers and sellers:
///    - If `crossing_buy_qty > crossing_sell_qty`: all crossing sell orders fill 100%, and crossing
///      buy orders are filled **pro-rata to their original buy order quantities**.
///    - If `crossing_sell_qty > crossing_buy_qty`: all crossing buy orders fill 100%, and crossing
///      sell orders are filled **pro-rata to the percentage of existing holding (`balanceOf(seller)`)
///      of that particular shareholder (NOT the sell order quantity)**.
///    - If `crossing_buy_qty == crossing_sell_qty`: all crossing buy and sell orders fill 100%.
/// 5. Executes `internal_debit` on filled sellers and `internal_credit` on filled buyers, emitting
///    per-order and summary settlement logs.
fn execute_transfer_auction_settlement(
    registry: &[u8; 20],
    caller: &[u8; 20],
    auth_obj: &[u8; 20],
) -> Result<(u64, u64, u64, u64), i32> {
    let rule = load_permission(&ACTION_TRANSFER).ok_or(-12)?;
    if !rule.configured || rule.constitution == [0u8; 20] {
        return Err(-12);
    }
    let pinned_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    if pinned_con != [0u8; 20] && rule.constitution != pinned_con {
        return Err(ERR_CONSTITUTION_MISMATCH);
    }

    let book = verify_and_consume_auction_auth(
        registry,
        auth_obj,
        &rule.constitution,
        &rule.policy_id,
        caller,
    )?;

    if book.order_count == 0 {
        return Err(ERR_NO_CROSSING_ORDERS);
    }

    let mut buy_orders = [AuctionOrder::default(); MAX_AUCTION_ORDERS];
    let mut buy_count = 0usize;

    let mut sell_orders = [AuctionOrder::default(); MAX_AUCTION_ORDERS];
    let mut sell_holdings = [0u64; MAX_AUCTION_ORDERS];
    let mut sell_count = 0usize;

    // Track unique sellers' pre-settlement balances and remaining sellable balance so a seller
    // can never offer more than their actual existing holding.
    let mut unique_sellers = [[0u8; 20]; MAX_AUCTION_ORDERS];
    let mut unique_init_bal = [0u64; MAX_AUCTION_ORDERS];
    let mut unique_rem_bal = [0u64; MAX_AUCTION_ORDERS];
    let mut unique_seller_count = 0usize;

    let mut idx = 0usize;
    while idx < book.order_count {
        let ord = book.orders[idx];
        if ord.is_cancelled() {
            idx += 1;
            continue;
        }
        require_valid_identity(registry, &ord.trader)?;
        if ord.price == 0 || ord.quantity == 0 {
            return Err(-14);
        }
        if ord.is_buy() {
            buy_orders[buy_count] = ord;
            buy_count += 1;
        } else if ord.is_sell() {
            // Find or snapshot this seller's pre-settlement existing holding
            let mut s_idx = 0usize;
            while s_idx < unique_seller_count {
                if unique_sellers[s_idx] == ord.trader {
                    break;
                }
                s_idx += 1;
            }
            if s_idx == unique_seller_count {
                let bk = balance_key(&ord.trader);
                let bal = storage::get_u64(bk.as_slice());
                if bal == 0 {
                    return Err(-16);
                }
                unique_sellers[s_idx] = ord.trader;
                unique_init_bal[s_idx] = bal;
                unique_rem_bal[s_idx] = bal;
                unique_seller_count += 1;
            }
            let capped_qty = if ord.quantity <= unique_rem_bal[s_idx] {
                ord.quantity
            } else {
                unique_rem_bal[s_idx]
            };
            if capped_qty > 0 {
                unique_rem_bal[s_idx] -= capped_qty;
                let mut capped_ord = ord;
                capped_ord.quantity = capped_qty;
                sell_orders[sell_count] = capped_ord;
                sell_holdings[sell_count] = unique_init_bal[s_idx];
                sell_count += 1;
            }
        }
        idx += 1;
    }

    if buy_count == 0 || sell_count == 0 {
        return Err(ERR_NO_CROSSING_ORDERS);
    }

    // Collect sorted unique candidate prices from all buy and sell orders
    let mut candidates = [0u64; MAX_AUCTION_ORDERS];
    let mut cand_count = 0usize;
    let mut i = 0usize;
    while i < buy_count {
        let p = buy_orders[i].price;
        let mut exists = false;
        let mut k = 0usize;
        while k < cand_count {
            if candidates[k] == p {
                exists = true;
                break;
            }
            k += 1;
        }
        if !exists {
            candidates[cand_count] = p;
            cand_count += 1;
        }
        i += 1;
    }
    i = 0;
    while i < sell_count {
        let p = sell_orders[i].price;
        let mut exists = false;
        let mut k = 0usize;
        while k < cand_count {
            if candidates[k] == p {
                exists = true;
                break;
            }
            k += 1;
        }
        if !exists {
            candidates[cand_count] = p;
            cand_count += 1;
        }
        i += 1;
    }

    // Insertion-sort candidate prices ascending
    i = 1;
    while i < cand_count {
        let key = candidates[i];
        let mut j = i;
        while j > 0 && candidates[j - 1] > key {
            candidates[j] = candidates[j - 1];
            j -= 1;
        }
        candidates[j] = key;
        i += 1;
    }

    // Evaluate aggregate demand D(P), aggregate supply S(P), and matched volume V(P) = min(D(P), S(P))
    // at each candidate price P to determine the single best clearing price P*:
    // 1. Maximize matched trade volume V(P) = min(D(P), S(P)).
    // 2. Among candidate prices achieving max V(P), maximize total crossing participation D(P) + S(P)
    //    so all crossing buyers/sellers participate in pro-rata allocation.
    let mut best_vol = 0u64;
    let mut best_participation = 0u64;
    let mut best_min_price = 0u64;
    let mut best_max_price = 0u64;
    let mut best_demand = 0u64;
    let mut best_supply = 0u64;

    i = 0;
    while i < cand_count {
        let p = candidates[i];
        let mut d = 0u64;
        let mut b = 0usize;
        while b < buy_count {
            if buy_orders[b].price >= p {
                d = d.saturating_add(buy_orders[b].quantity);
            }
            b += 1;
        }
        let mut s = 0u64;
        let mut sl = 0usize;
        while sl < sell_count {
            if sell_orders[sl].price <= p {
                s = s.saturating_add(sell_orders[sl].quantity);
            }
            sl += 1;
        }
        let vol = if d < s { d } else { s };
        if vol > 0 {
            let part = d.saturating_add(s);
            if vol > best_vol || (vol == best_vol && part > best_participation) {
                best_vol = vol;
                best_participation = part;
                best_min_price = p;
                best_max_price = p;
                best_demand = d;
                best_supply = s;
            } else if vol == best_vol && part == best_participation {
                best_max_price = p;
            }
        }
        i += 1;
    }

    if best_vol == 0 {
        return Err(ERR_NO_CROSSING_ORDERS);
    }

    let clearing_price = if best_demand > best_supply {
        best_max_price
    } else if best_supply > best_demand {
        best_min_price
    } else {
        best_min_price + (best_max_price - best_min_price) / 2
    };

    // Recompute exact crossing sets at `clearing_price`
    let mut crossing_buy_qty = 0u64;
    let mut b = 0usize;
    while b < buy_count {
        if buy_orders[b].price >= clearing_price {
            crossing_buy_qty = crossing_buy_qty.saturating_add(buy_orders[b].quantity);
        }
        b += 1;
    }
    let mut crossing_sell_qty = 0u64;
    let mut sl = 0usize;
    while sl < sell_count {
        if sell_orders[sl].price <= clearing_price {
            crossing_sell_qty = crossing_sell_qty.saturating_add(sell_orders[sl].quantity);
        }
        sl += 1;
    }

    let matched_qty = if crossing_buy_qty < crossing_sell_qty {
        crossing_buy_qty
    } else {
        crossing_sell_qty
    };
    if matched_qty == 0 {
        return Err(ERR_NO_CROSSING_ORDERS);
    }

    let mut buy_fills = [0u64; MAX_AUCTION_ORDERS];
    let mut sell_fills = [0u64; MAX_AUCTION_ORDERS];

    if crossing_buy_qty > crossing_sell_qty {
        // Total buying quantity > total selling quantity:
        // 1. Fill all crossing sell orders 100%.
        sl = 0;
        while sl < sell_count {
            if sell_orders[sl].price <= clearing_price {
                sell_fills[sl] = sell_orders[sl].quantity;
            }
            sl += 1;
        }

        // 2. Fill crossing buy orders pro-rated to their original buy order quantities.
        let mut allocated = 0u64;
        let mut remainders = [0u128; MAX_AUCTION_ORDERS];
        b = 0;
        while b < buy_count {
            if buy_orders[b].price >= clearing_price {
                let num = (matched_qty as u128) * (buy_orders[b].quantity as u128);
                let den = crossing_buy_qty as u128;
                let share = (num / den) as u64;
                buy_fills[b] = share;
                remainders[b] = num % den;
                allocated = allocated.saturating_add(share);
            }
            b += 1;
        }
        let mut rem_shares = matched_qty.saturating_sub(allocated);
        while rem_shares > 0 {
            let mut best_b = usize::MAX;
            let mut best_rem = 0u128;
            b = 0;
            while b < buy_count {
                if buy_orders[b].price >= clearing_price
                    && buy_fills[b] < buy_orders[b].quantity
                    && (best_b == usize::MAX || remainders[b] > best_rem)
                {
                    best_b = b;
                    best_rem = remainders[b];
                }
                b += 1;
            }
            if best_b == usize::MAX {
                break;
            }
            buy_fills[best_b] += 1;
            remainders[best_b] = 0;
            rem_shares -= 1;
        }
    } else if crossing_sell_qty > crossing_buy_qty {
        // Total selling quantity > total buying quantity:
        // 1. Fill all crossing buy orders 100%.
        b = 0;
        while b < buy_count {
            if buy_orders[b].price >= clearing_price {
                buy_fills[b] = buy_orders[b].quantity;
            }
            b += 1;
        }

        // 2. Fill crossing sell orders pro-rated to the percentage of existing holding
        //    (`sell_holdings[sl] == balanceOf(seller)`) of that particular shareholder
        //    (NOT the sell order quantity!), capped at each seller's offered quantity.
        let mut uncapped = [false; MAX_AUCTION_ORDERS];
        sl = 0;
        while sl < sell_count {
            if sell_orders[sl].price <= clearing_price {
                uncapped[sl] = true;
            }
            sl += 1;
        }

        let mut rem_to_fill = matched_qty;
        loop {
            let mut weight_sum = 0u128;
            sl = 0;
            while sl < sell_count {
                if uncapped[sl] {
                    weight_sum += sell_holdings[sl] as u128;
                }
                sl += 1;
            }
            if weight_sum == 0 || rem_to_fill == 0 {
                break;
            }

            let mut any_capped = false;
            sl = 0;
            while sl < sell_count {
                if uncapped[sl] {
                    let provisional =
                        ((rem_to_fill as u128) * (sell_holdings[sl] as u128)) / weight_sum;
                    if provisional >= (sell_orders[sl].quantity as u128) {
                        sell_fills[sl] = sell_orders[sl].quantity;
                        rem_to_fill = rem_to_fill.saturating_sub(sell_orders[sl].quantity);
                        uncapped[sl] = false;
                        any_capped = true;
                    }
                }
                sl += 1;
            }

            if !any_capped {
                let mut allocated = 0u64;
                let mut remainders = [0u128; MAX_AUCTION_ORDERS];
                sl = 0;
                while sl < sell_count {
                    if uncapped[sl] {
                        let num = (rem_to_fill as u128) * (sell_holdings[sl] as u128);
                        let share = (num / weight_sum) as u64;
                        sell_fills[sl] = share;
                        remainders[sl] = num % weight_sum;
                        allocated = allocated.saturating_add(share);
                    }
                    sl += 1;
                }
                let mut rem_shares = rem_to_fill.saturating_sub(allocated);
                while rem_shares > 0 {
                    let mut best_sl = usize::MAX;
                    let mut best_rem = 0u128;
                    sl = 0;
                    while sl < sell_count {
                        if uncapped[sl]
                            && sell_fills[sl] < sell_orders[sl].quantity
                            && (best_sl == usize::MAX || remainders[sl] > best_rem)
                        {
                            best_sl = sl;
                            best_rem = remainders[sl];
                        }
                        sl += 1;
                    }
                    if best_sl == usize::MAX {
                        break;
                    }
                    sell_fills[best_sl] += 1;
                    remainders[best_sl] = 0;
                    rem_shares -= 1;
                }
                break;
            }
        }
    } else {
        // Exact match (`crossing_buy_qty == crossing_sell_qty`): fill all crossing orders 100%.
        b = 0;
        while b < buy_count {
            if buy_orders[b].price >= clearing_price {
                buy_fills[b] = buy_orders[b].quantity;
            }
            b += 1;
        }
        sl = 0;
        while sl < sell_count {
            if sell_orders[sl].price <= clearing_price {
                sell_fills[sl] = sell_orders[sl].quantity;
            }
            sl += 1;
        }
    }

    // Debit all filled sellers first
    let mut filled_seller_count = 0u64;
    sl = 0;
    while sl < sell_count {
        let fill = sell_fills[sl];
        if fill > 0 {
            internal_debit(&sell_orders[sl].trader, fill)?;
            filled_seller_count += 1;
            let mut log_data = [0u8; 32];
            log_data[0..8].copy_from_slice(&clearing_price.to_be_bytes());
            log_data[8..16].copy_from_slice(&sell_orders[sl].quantity.to_be_bytes());
            log_data[16..24].copy_from_slice(&sell_holdings[sl].to_be_bytes());
            log_data[24..32].copy_from_slice(&fill.to_be_bytes());
            events::emit(
                &[
                    AUCTION_SELLER_FILLED,
                    addr_topic(&sell_orders[sl].trader),
                    addr_topic(auth_obj),
                ],
                &log_data,
            );
        }
        sl += 1;
    }

    // Credit all filled buyers
    let mut filled_buyer_count = 0u64;
    b = 0;
    while b < buy_count {
        let fill = buy_fills[b];
        if fill > 0 {
            internal_credit(&buy_orders[b].trader, fill)?;
            filled_buyer_count += 1;
            let mut log_data = [0u8; 24];
            log_data[0..8].copy_from_slice(&clearing_price.to_be_bytes());
            log_data[8..16].copy_from_slice(&buy_orders[b].quantity.to_be_bytes());
            log_data[16..24].copy_from_slice(&fill.to_be_bytes());
            events::emit(
                &[
                    AUCTION_BUYER_FILLED,
                    addr_topic(&buy_orders[b].trader),
                    addr_topic(auth_obj),
                ],
                &log_data,
            );
        }
        b += 1;
    }

    // If the bound Constitution escrowed buyer funds in its bank balance ledger (`hasEscrowedAuction(authObj)`),
    // automatically disburse `clearing_price * fill` to filled sellers and refund any unspent escrow
    // (`order.price * order.quantity - clearing_price * fill`) back to buyers!
    if rule.constitution != [0u8; 20] {
        let q_cd = CallEncoder::<64>::new(const { selector("hasEscrowedAuction(address)") })
            .push_address(auth_obj);
        if let Ok(true) = call::call_bool(&rule.constitution, q_cd.as_slice()) {
            sl = 0;
            while sl < sell_count {
                let fill = sell_fills[sl];
                if fill > 0 {
                    let proceeds = clearing_price.checked_mul(fill).ok_or(-15)?;
                    let pay_cd = CallEncoder::<160>::new(const { selector("disburseAuctionCash(address,address,uint64,bool)") })
                    .push_address(auth_obj)
                    .push_address(&sell_orders[sl].trader)
                    .push_u64(proceeds)
                    .push_bool(true);
                    let ok = call::call_bool(&rule.constitution, pay_cd.as_slice())?;
                    if !ok {
                        return Err(-16);
                    }
                }
                sl += 1;
            }

            b = 0;
            while b < buy_count {
                let escrowed = buy_orders[b]
                    .price
                    .checked_mul(buy_orders[b].quantity)
                    .ok_or(-15)?;
                let spent = clearing_price.checked_mul(buy_fills[b]).ok_or(-15)?;
                let refund = escrowed.saturating_sub(spent);
                if refund > 0 {
                    let ref_cd = CallEncoder::<160>::new(const { selector("disburseAuctionCash(address,address,uint64,bool)") })
                    .push_address(auth_obj)
                    .push_address(&buy_orders[b].trader)
                    .push_u64(refund)
                    .push_bool(false);
                    let ok = call::call_bool(&rule.constitution, ref_cd.as_slice())?;
                    if !ok {
                        return Err(-16);
                    }
                }
                b += 1;
            }
        }
    }

    storage::set_u64(KEY_LAST_AUC_PRICE, clearing_price);
    storage::set_u64(KEY_LAST_AUC_QTY, matched_qty);
    storage::set_u64(KEY_LAST_AUC_BUY_DEMAND, crossing_buy_qty);
    storage::set_u64(KEY_LAST_AUC_SELL_SUPPLY, crossing_sell_qty);

    let mut summary = [0u8; 48];
    summary[0..8].copy_from_slice(&clearing_price.to_be_bytes());
    summary[8..16].copy_from_slice(&matched_qty.to_be_bytes());
    summary[16..24].copy_from_slice(&crossing_buy_qty.to_be_bytes());
    summary[24..32].copy_from_slice(&crossing_sell_qty.to_be_bytes());
    summary[32..40].copy_from_slice(&filled_buyer_count.to_be_bytes());
    summary[40..48].copy_from_slice(&filled_seller_count.to_be_bytes());
    events::emit(&[AUCTION_SETTLED_TOPIC, addr_topic(auth_obj)], &summary);

    Ok((
        clearing_price,
        matched_qty,
        crossing_buy_qty,
        crossing_sell_qty,
    ))
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
/// Enforces the Single-Constitution Restriction (`constitution` MUST match `associatedConstitution()`
/// or be `([0u8; 20], POLICY_HOLDER_SELF)`) and requires a finalized, one-time-use **`SUPER`**
/// `Authorization` HPS object fulfilling `ACTION_SUPER`.
fn handle_set_permission(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let action_key = args.bytes32(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let policy_id = args.bytes32(2).ok_or(-3)?;
    let super_auth = args.address(3).ok_or(-3)?;

    if action_key == [0u8; 32]
        || policy_id == [0u8; 32]
        || (action_key == ACTION_SUPER && (policy_id == POLICY_HOLDER_SELF || constitution == [0u8; 20]))
    {
        return Err(-12);
    }

    let pinned_con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    if constitution == [0u8; 20] {
        if policy_id != POLICY_HOLDER_SELF {
            return Err(ERR_CONSTITUTION_MISMATCH);
        }
    } else if pinned_con != [0u8; 20] && constitution != pinned_con {
        return Err(ERR_CONSTITUTION_MISMATCH); // AssetLedger is locked to its single Constitution HPS
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

fn handle_associated_constitution(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]));
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

fn handle_last_auction_settlement(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 128];
    out[24..32].copy_from_slice(&storage::get_u64(KEY_LAST_AUC_PRICE).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(KEY_LAST_AUC_QTY).to_be_bytes());
    out[88..96].copy_from_slice(&storage::get_u64(KEY_LAST_AUC_BUY_DEMAND).to_be_bytes());
    out[120..128].copy_from_slice(&storage::get_u64(KEY_LAST_AUC_SELL_SUPPLY).to_be_bytes());
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
            if sel == const { selector("isValidIdentity(address)") } {
                let id = args.address(0).unwrap();
                ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                return 0;
            }
            if sel == const { selector("isValidAuthorizationHps(address)") } {
                let au = args.address(0).unwrap();
                let expected = hps_sdk::mock::dispatch_code_hash(auth_dispatch);
                ret::write_bool(context::code_hash_of(&au) == Some(expected));
                return 0;
            }
            -2
        }

        pub fn auth_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("arm(address,address,bytes32,bytes32)") } {
                storage::set_address(b"target", &args.address(0).unwrap());
                storage::set_address(b"con", &args.address(1).unwrap());
                storage::set(b"pol", &args.bytes32(2).unwrap());
                storage::set(b"hash", &args.bytes32(3).unwrap());
                storage::set_u64(b"used", 0);
                return 0;
            }
            if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
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
        cd.extend_from_slice(&const { selector("initialize(address,string,uint64,bytes,bytes)") });

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
                CallEncoder::<64>::new(const { selector("balanceOf(address)") })
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
                CallEncoder::<16>::new(const { selector("totalOutstanding()") }).as_slice(),
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
            CallEncoder::<96>::new(const { selector("hashIssue(address,uint64)") })
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
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
                .push_address(&ledger)
                .push_address(&con)
                .push_bytes32(&ACTION_ISSUE)
                .push_bytes32(&h_iss)
                .as_slice(),
        )
        .unwrap();

        let iss_cd = CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
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
            CallEncoder::<128>::new(const { selector("hashTransfer(address,address,uint64)") })
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
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
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
            CallEncoder::<160>::new(const { selector("transfer(address,address,uint64,address)") })
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
            CallEncoder::<96>::new(const { selector("hashCancel(address,uint64)") })
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
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
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
            CallEncoder::<128>::new(const { selector("cancel(address,uint64,address)") })
                .push_address(&treasury_id)
                .push_u64(200)
                .push_address(&auth_cancel)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(treasury_id), 800);
        assert_eq!(supply(), 1_550);

        // 4. Single-Constitution Restriction: attempting to associate a second Constitution (`con_v2 != con`)
        // in `setPermission` MUST be rejected with ERR_CONSTITUTION_MISMATCH (-19)!
        let new_pol = [0x99; 32];
        assert_eq!(
            mock::transact_as(
                treasury_id,
                ledger,
                CallEncoder::<160>::new(const { selector("setPermission(bytes32,address,bytes32,address)") })
                    .push_bytes32(&ACTION_ISSUE)
                    .push_address(&con_v2)
                    .push_bytes32(&new_pol)
                    .push_address(&auth_super)
                    .as_slice(),
            ),
            Err(ERR_CONSTITUTION_MISMATCH)
        );

        // Rotate ACTION_ISSUE permission to `new_pol` within the single pinned `con` using a SUPER authorization object!
        let h_perm: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<128>::new(const { selector("hashSetPermission(bytes32,address,bytes32)") })
                .push_bytes32(&ACTION_ISSUE)
                .push_address(&con)
                .push_bytes32(&new_pol)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            treasury_id,
            auth_super,
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
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
            CallEncoder::<160>::new(const { selector("setPermission(bytes32,address,bytes32,address)") })
                .push_bytes32(&ACTION_ISSUE)
                .push_address(&con)
                .push_bytes32(&new_pol)
                .push_address(&auth_super)
                .as_slice(),
        )
        .unwrap();

        // Old `ACTION_ISSUE` policy ID is now rejected; `(con, new_pol)` succeeds!
        let h_iss2: [u8; 32] = mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<96>::new(const { selector("hashIssue(address,uint64)") })
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
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
                .push_address(&ledger)
                .push_address(&con)
                .push_bytes32(&new_pol)
                .push_bytes32(&h_iss2)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            treasury_id,
            ledger,
            CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
                .push_address(&alice_id)
                .push_u64(50)
                .push_address(&auth_issue_v2)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(alice_id), 200);
        assert_eq!(supply(), 1_600);
    }

    #[test]
    fn superlexicon_singapore_pte_ltd_private_equity_cap_table_and_governance() {
        use hps_sdk::governance::{
            PolicySpec, StageSpec, POLICY_BOARD_RESOLUTION, POLICY_SHAREHOLDER_SUPERMAJORITY,
            POLICY_SUPER_GOVERNANCE,
        };

        // Full in-memory Constitution + Authorization FSM dispatchers so the 49-shareholder
        // Superlexicon Pte. Ltd. lifecycle, positive & negative tests, and event logs run in <50ms.
        mod pe_sim {
            use super::*;
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::{
                oracle_policy_id, PolicySpec, StageSpec, ERR_INVALID_IDENTITY,
                MAX_ENCODED_POLICY_BYTES,
            };
            use hps_sdk::storage::KeyBuilder;
            use hps_sdk::{call, context, events, ret, selector, storage};

            const STATE_UNINITIALIZED: u64 = 0;
            const STATE_IN_PROGRESS: u64 = 1;
            const STATE_FINALIZED: u64 = 2;
            const STATE_CONSUMED: u64 = 3;
            const STATE_EXPIRED: u64 = 4;

            const ERR_AUTH_NOT_FINALIZED: i32 = -62;
            const ERR_AUTH_EXPIRED: i32 = -63;
            const ERR_AUTH_TARGET_MISMATCH: i32 = -65;
            const ERR_AUTH_POLICY_MISMATCH: i32 = -66;
            const ERR_AUTH_ACTION_MISMATCH: i32 = -67;
            const ERR_AUTH_ALREADY_CONSUMED: i32 = -68;
            const ERR_NOT_STAGE_MEMBER: i32 = -70;

            pub fn con_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("setPolicyRaw(address,bytes32,bytes)") } {
                    let target = args.address(0).unwrap();
                    let pol = args.bytes32(1).unwrap();
                    let spec_bytes = args.dynamic_bytes(2).unwrap();
                    let pk = KeyBuilder::<64>::new().push(b"pol:").push(&target).push(&pol);
                    storage::set(pk.as_slice(), spec_bytes);
                    return 0;
                }
                if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                    let target = args.address(0).unwrap();
                    let pol = args.bytes32(1).unwrap();
                    let pk = KeyBuilder::<64>::new().push(b"pol:").push(&target).push(&pol);
                    let mut buf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    if let Some(n) = storage::get_into(pk.as_slice(), &mut buf) {
                        ret::write_abi_bytes(&buf[..n]);
                        return 0;
                    }
                    let gpk = KeyBuilder::<64>::new().push(b"pol:").push(&[0u8; 20]).push(&pol);
                    if let Some(n) = storage::get_into(gpk.as_slice(), &mut buf) {
                        ret::write_abi_bytes(&buf[..n]);
                        return 0;
                    }
                    return -62;
                }
                -2
            }

            pub fn fsm_auth_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("initialize(address,address,address,bytes32,bytes32)") } {
                    if storage::get_u64(b"state") != STATE_UNINITIALIZED {
                        return -60; // cannot overwrite an initialized Authorization HPS
                    }
                    let reg = args.address(0).unwrap();
                    let con = args.address(1).unwrap();
                    let target = args.address(2).unwrap();
                    let pol = args.bytes32(3).unwrap();
                    let act_hash = args.bytes32(4).unwrap();
                    let caller = context::msg_sender();
                    let valid = call::call_bool(
                        &reg,
                        CallEncoder::<64>::new(const { selector("isValidIdentity(address)") })
                            .push_address(&caller)
                            .as_slice(),
                    )
                    .unwrap_or(false);
                    if !valid {
                        return ERR_INVALID_IDENTITY;
                    }

                    let mut spec_buf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    let spec = if con == [0u8; 20] {
                        if pol != oracle_policy_id(&caller) {
                            return ERR_AUTH_POLICY_MISMATCH;
                        }
                        PolicySpec::new(100)
                            .add_stage(StageSpec::new(1, 100).add_member(caller, 1).unwrap())
                            .unwrap()
                    } else {
                        let get_cd = CallEncoder::<96>::new(const { selector("getPolicyRaw(address,bytes32)") })
                            .push_address(&target)
                            .push_bytes32(&pol);
                        let ret_slice = call::call_raw(&con, get_cd.as_slice()).unwrap();
                        let len = u64::from_be_bytes(ret_slice[56..64].try_into().unwrap()) as usize;
                        assert!(64 + len <= ret_slice.len());
                        PolicySpec::decode(&ret_slice[64..64 + len]).unwrap()
                    };
                    let slen = spec.encode(&mut spec_buf).unwrap();
                    storage::set(b"spec", &spec_buf[..slen]);
                    storage::set_address(b"reg", &reg);
                    storage::set_address(b"con", &con);
                    storage::set_address(b"target", &target);
                    storage::set(b"pol", &pol);
                    storage::set(b"hash", &act_hash);
                    storage::set_u64(b"state", STATE_IN_PROGRESS);
                    storage::set_u64(b"cur_stage", 0);
                    let now = context::block_number();
                    storage::set_u64(b"stage_start", now);
                    storage::set_u64(b"overall_dl", now + spec.overall_expiry_blocks);
                    return 0;
                }
                if sel == const { selector("approve(uint64)") } {
                    let expected_stage = args.u64(0).unwrap();
                    let reg = storage::get_address(b"reg").unwrap();
                    let caller = context::msg_sender();
                    let valid = call::call_bool(
                        &reg,
                        CallEncoder::<64>::new(const { selector("isValidIdentity(address)") })
                            .push_address(&caller)
                            .as_slice(),
                    )
                    .unwrap_or(false);
                    if !valid {
                        return ERR_INVALID_IDENTITY;
                    }
                    if storage::get_u64(b"state") != STATE_IN_PROGRESS {
                        return -61;
                    }
                    let mut sbuf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    let slen = storage::get_into(b"spec", &mut sbuf).unwrap();
                    let spec = PolicySpec::decode(&sbuf[..slen]).unwrap();
                    let cur = storage::get_u64(b"cur_stage") as usize;
                    if cur >= spec.stage_count || (cur as u64) != expected_stage {
                        return -61;
                    }
                    let now = context::block_number();
                    let st_dl = storage::get_u64(b"stage_start") + spec.stages[cur].expiry_blocks;
                    if now > storage::get_u64(b"overall_dl") || now > st_dl {
                        storage::set_u64(b"state", STATE_EXPIRED);
                        return ERR_AUTH_EXPIRED;
                    }
                    let Some(weight) = spec.stages[cur].member_weight(&caller) else {
                        return ERR_NOT_STAGE_MEMBER;
                    };
                    let sig_k = KeyBuilder::<48>::new()
                        .push(b"sig:")
                        .push_u64_be(cur as u64)
                        .push(&caller);
                    if storage::get_u64(sig_k.as_slice()) != 0 {
                        return -69; // ERR_ALREADY_SIGNED
                    }
                    storage::set_u64(sig_k.as_slice(), 1);
                    let wk = KeyBuilder::<24>::new().push(b"wt:").push_u64_be(cur as u64);
                    let accum = storage::get_u64(wk.as_slice()) + weight;
                    storage::set_u64(wk.as_slice(), accum);
                    if accum >= spec.stages[cur].required_weight {
                        storage::set_u64(b"cur_stage", (cur + 1) as u64);
                        storage::set_u64(b"stage_start", now);
                    }
                    ret::write_u64_word(accum);
                    return 0;
                }
                if sel == const { selector("finalize()") } {
                    let st = storage::get_u64(b"state");
                    if st == STATE_FINALIZED {
                        ret::write_bool(true);
                        return 0;
                    }
                    if st != STATE_IN_PROGRESS {
                        return ERR_AUTH_NOT_FINALIZED;
                    }
                    let mut sbuf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    let slen = storage::get_into(b"spec", &mut sbuf).unwrap();
                    let spec = PolicySpec::decode(&sbuf[..slen]).unwrap();
                    if (storage::get_u64(b"cur_stage") as usize) < spec.stage_count {
                        return ERR_AUTH_NOT_FINALIZED;
                    }
                    if context::block_number() > storage::get_u64(b"overall_dl") {
                        storage::set_u64(b"state", STATE_EXPIRED);
                        return ERR_AUTH_EXPIRED;
                    }
                    storage::set_u64(b"state", STATE_FINALIZED);
                    ret::write_bool(true);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    let st = storage::get_u64(b"state");
                    if st == STATE_CONSUMED {
                        return ERR_AUTH_ALREADY_CONSUMED;
                    }
                    if st == STATE_EXPIRED || context::block_number() > storage::get_u64(b"overall_dl") {
                        storage::set_u64(b"state", STATE_EXPIRED);
                        return ERR_AUTH_EXPIRED;
                    }
                    if st != STATE_FINALIZED {
                        return ERR_AUTH_NOT_FINALIZED;
                    }
                    if context::msg_sender() != storage::get_address(b"target").unwrap() {
                        return ERR_AUTH_TARGET_MISMATCH;
                    }
                    if args.address(0).unwrap() != storage::get_address(b"con").unwrap()
                        || args.bytes32(1).unwrap() != storage::get_bytes32(b"pol").unwrap()
                    {
                        return ERR_AUTH_POLICY_MISMATCH;
                    }
                    if args.bytes32(2).unwrap() != storage::get_bytes32(b"hash").unwrap() {
                        return ERR_AUTH_ACTION_MISMATCH;
                    }
                    storage::set_u64(b"state", STATE_CONSUMED);
                    events::emit(&[event_topic("AuthorizationConsumed(address,address,bytes32)")], &[]);
                    ret::write_bool(true);
                    return 0;
                }
                if sel == const { selector("state()") } {
                    ret::write_u64_word(storage::get_u64(b"state"));
                    return 0;
                }
                -2
            }

            pub fn pe_reg_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("isValidIdentity(address)") } {
                    let id = args.address(0).unwrap();
                    ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                    return 0;
                }
                if sel == const { selector("isValidAuthorizationHps(address)") } {
                    let au = args.address(0).unwrap();
                    let expected = hps_sdk::mock::dispatch_code_hash(fsm_auth_dispatch);
                    ret::write_bool(context::code_hash_of(&au) == Some(expected));
                    return 0;
                }
                -2
            }

            pub fn cloned_auth_dispatch(raw: &[u8]) -> i32 {
                let _ = raw;
                ret::write_bool(true);
                0
            }
        }

        mock::reset();
        mock::set_block_number(1_000);

        let reg = [0x10; 20];
        let slx_con = [0x20; 20];
        let rogue_con = [0x21; 20];
        let slx_ledger = [0x30; 20];
        let ext_treasury_ledger = [0x31; 20];

        // 2 Directors of Superlexicon Pte. Ltd.:
        // Director 1 & Founding Shareholder #1: Manogaran Thanabalan (50,000 shares)
        let manogaran_id = [0xA1; 20];
        // Director 2: Evelyn Tan Wei Ling (non-shareholder independent director)
        let evelyn_director_id = [0xA2; 20];
        // Corporate Identity of Superlexicon Pte. Ltd. (owner of assets in `ext_treasury_ledger`)
        let superlexicon_company_id = [0xA0; 20];

        // 49 Shareholders in total:
        // Shareholder #1 = Manogaran Thanabalan (50,000 shares)
        // Shareholders #2..#49 = 48 minority shareholders holding the remaining 50,000 shares:
        //   - 16 shareholders (#2..#17) hold 1,250 shares each = 20,000 shares
        //   - 16 shareholders (#18..#33) hold 1,000 shares each = 16,000 shares
        //   - 16 shareholders (#34..#49) hold 875 shares each   = 14,000 shares
        //   Total across 48 other shareholders = 20,000 + 16,000 + 14,000 = 50,000 shares!
        //   Grand total across all 49 shareholders = 100,000 shares (1:1 voting rights).
        let mut cap_table: Vec<([u8; 20], u64)> = Vec::with_capacity(49);
        cap_table.push((manogaran_id, 50_000));
        for idx in 0..48usize {
            let mut sh_id = [0xB0; 20];
            sh_id[19] = (idx + 2) as u8;
            let shares = if idx < 16 {
                1_250u64
            } else if idx < 32 {
                1_000u64
            } else {
                875u64
            };
            cap_table.push((sh_id, shares));
        }
        assert_eq!(cap_table.len(), 49);
        let total_genesis_shares: u64 = cap_table.iter().map(|(_, s)| *s).sum();
        assert_eq!(total_genesis_shares, 100_000);

        mock::register_hps(reg, pe_sim::pe_reg_dispatch);
        mock::register_hps(slx_con, pe_sim::con_dispatch);
        mock::register_hps(rogue_con, pe_sim::con_dispatch);
        mock::register_hps(slx_ledger, dispatch_calldata);
        mock::register_hps(ext_treasury_ledger, dispatch_calldata);

        // Build the Singapore Pte. Ltd. Constitution policies:
        // 1. Shareholder Super-Majority Policy (>= 75% of 100,000 = 75,000 votes, 1:1 voting weight)
        let mut sh_stage = StageSpec::new(75_000, 50);
        for (sh_id, shares) in &cap_table {
            sh_stage = sh_stage.add_member(*sh_id, *shares).unwrap();
        }
        let sh_supermajority_spec = PolicySpec::new(100).add_stage(sh_stage).unwrap();
        let mut sh_spec_bytes = [0u8; 2048];
        let sh_spec_len = sh_supermajority_spec.encode(&mut sh_spec_bytes).unwrap();

        // 2. Board of Directors Resolution Policy (both Directors: Manogaran + Evelyn Tan, weight 1 each, required = 2)
        let board_stage = StageSpec::new(2, 50)
            .add_member(manogaran_id, 1)
            .unwrap()
            .add_member(evelyn_director_id, 1)
            .unwrap();
        let board_spec = PolicySpec::new(100).add_stage(board_stage).unwrap();
        let mut board_spec_bytes = [0u8; 512];
        let board_spec_len = board_spec.encode(&mut board_spec_bytes).unwrap();

        let store_con_policy = |target: [u8; 20], pol: [u8; 32], raw_spec: &[u8]| {
            let mut cd = Vec::new();
            cd.extend_from_slice(&const { selector("setPolicyRaw(address,bytes32,bytes)") });
            let mut tw = [0u8; 32];
            tw[12..32].copy_from_slice(&target);
            cd.extend_from_slice(&tw);
            cd.extend_from_slice(&pol);
            let mut off = [0u8; 32];
            off[31] = 0x60;
            cd.extend_from_slice(&off);
            let mut lw = [0u8; 32];
            lw[24..32].copy_from_slice(&(raw_spec.len() as u64).to_be_bytes());
            cd.extend_from_slice(&lw);
            cd.extend_from_slice(raw_spec);
            cd.resize(cd.len() + (32 - raw_spec.len() % 32) % 32, 0);
            mock::transact_as(manogaran_id, slx_con, &cd).unwrap();
        };
        store_con_policy([0u8; 20], POLICY_SUPER_GOVERNANCE, &sh_spec_bytes[..sh_spec_len]);
        store_con_policy(slx_ledger, POLICY_SHAREHOLDER_SUPERMAJORITY, &sh_spec_bytes[..sh_spec_len]);
        store_con_policy([0u8; 20], POLICY_BOARD_RESOLUTION, &board_spec_bytes[..board_spec_len]);

        // Negative Test N1: Attempting to initialize `slx_ledger` with two different Constitutions MUST revert (-19)!
        let bad_init_cd = encode_ledger_init(
            reg,
            b"SLX-COMMON",
            0,
            &cap_table,
            &[
                (ACTION_SUPER, slx_con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, rogue_con, POLICY_SHAREHOLDER_SUPERMAJORITY),
            ],
        );
        assert_eq!(
            mock::transact_as(manogaran_id, slx_ledger, &bad_init_cd),
            Err(ERR_CONSTITUTION_MISMATCH)
        );

        // Positive Test P1: Initialize `slx_ledger` with the 49-shareholder cap table (100,000 shares)
        // pinned exclusively to `slx_con`.
        let init_cd = encode_ledger_init(
            reg,
            b"SLX-COMMON",
            0,
            &cap_table,
            &[
                (ACTION_SUPER, slx_con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, slx_con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_CANCEL, slx_con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_TRANSFER, [0u8; 20], POLICY_HOLDER_SELF),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(manogaran_id, slx_ledger, &init_cd).unwrap();

        // Verify `ConstitutionPinned` and `LedgerInitialized` events were emitted!
        let evs = mock::events();
        assert!(evs.iter().any(|e| e.address == slx_ledger && e.topics[0] == CONSTITUTION_PINNED));
        assert!(evs.iter().any(|e| e.address == slx_ledger && e.topics[0] == LEDGER_INITIALIZED));

        // Verify associatedConstitution() == slx_con, holderCount() == 49, totalOutstanding() == 100,000,
        // and Manogaran's balance == 50,000 (50.00%).
        let assoc_con_out = mock::transact_as(
            manogaran_id,
            slx_ledger,
            CallEncoder::<16>::new(const { selector("associatedConstitution()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(&assoc_con_out[12..32], &slx_con);

        let hc_out = mock::transact_as(
            manogaran_id,
            slx_ledger,
            CallEncoder::<16>::new(const { selector("holderCount()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(hc_out[24..32].try_into().unwrap()), 49);

        let bal_of = |ledger: [u8; 20], who: [u8; 20]| -> u64 {
            let out = mock::transact_as(
                manogaran_id,
                ledger,
                CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                    .push_address(&who)
                    .as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };
        let supply_of = |ledger: [u8; 20]| -> u64 {
            let out = mock::transact_as(
                manogaran_id,
                ledger,
                CallEncoder::<16>::new(const { selector("totalOutstanding()") }).as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };
        assert_eq!(bal_of(slx_ledger, manogaran_id), 50_000);
        assert_eq!(supply_of(slx_ledger), 100_000);

        // Compute actionHash for issuing 100,000 new shares to Manogaran Thanabalan
        // (increasing his balance from 50,000 -> 150,000 out of 200,000 total = 75.00% super-majority!)
        let issue_amount = 100_000u64;
        let h_issue_mano: [u8; 32] = mock::transact_as(
            manogaran_id,
            slx_ledger,
            CallEncoder::<96>::new(const { selector("hashIssue(address,uint64)") })
                .push_address(&manogaran_id)
                .push_u64(issue_amount)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        // Deploy `auth_issue_mano` Authorization HPS and initialize it from `slx_con`
        let auth_issue_mano = [0xD1; 20];
        mock::register_hps(auth_issue_mano, pe_sim::fsm_auth_dispatch);
        let init_auth_cd =
            CallEncoder::<192>::new(const { selector("initialize(address,address,address,bytes32,bytes32)") })
                .push_address(&reg)
                .push_address(&slx_con)
                .push_address(&slx_ledger)
                .push_bytes32(&POLICY_SHAREHOLDER_SUPERMAJORITY)
                .push_bytes32(&h_issue_mano);
        mock::transact_as(manogaran_id, auth_issue_mano, init_auth_cd.as_slice()).unwrap();

        // Negative Test N2: Attempting to overwrite/re-initialize `auth_issue_mano` MUST revert (-60)!
        assert_eq!(
            mock::transact_as(manogaran_id, auth_issue_mano, init_auth_cd.as_slice()),
            Err(-60)
        );

        // Manogaran votes first with his 50,000 shares (50.00% < 75.00% super-majority threshold of 75,000)
        let approve_st0 = CallEncoder::<64>::new(const { selector("approve(uint64)") }).push_u64(0);
        let w1 = mock::transact_as(manogaran_id, auth_issue_mano, approve_st0.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(w1[24..32].try_into().unwrap()), 50_000);

        // Negative Test N3: Duplicate vote by Manogaran to inflate weight MUST revert (-69)!
        assert_eq!(
            mock::transact_as(manogaran_id, auth_issue_mano, approve_st0.as_slice()),
            Err(-69)
        );

        // Negative Test N4: Attempting `finalize()` with only 50,000 / 75,000 votes MUST revert (-62)!
        assert_eq!(
            mock::transact_as(
                manogaran_id,
                auth_issue_mano,
                CallEncoder::<16>::new(const { selector("finalize()") }).as_slice(),
            ),
            Err(-62)
        );

        // Negative Test N5: Passing an unfinalized `auth_issue_mano` to `slx_ledger.issue` MUST revert (-62)!
        let issue_cd = CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
            .push_address(&manogaran_id)
            .push_u64(issue_amount)
            .push_address(&auth_issue_mano);
        assert_eq!(
            mock::transact_as(manogaran_id, slx_ledger, issue_cd.as_slice()),
            Err(-62)
        );

        // Negative Test N6: Passing an arbitrary finalized Authorization (e.g. a 2-of-2 Board Resolution
        // instead of Shareholder Super-Majority, or wrong action hash, or unapproved clone) MUST revert!
        let auth_board_wrong_pol = [0xD2; 20];
        mock::register_hps(auth_board_wrong_pol, pe_sim::fsm_auth_dispatch);
        mock::transact_as(
            manogaran_id,
            auth_board_wrong_pol,
            CallEncoder::<192>::new(const { selector("initialize(address,address,address,bytes32,bytes32)") })
                .push_address(&reg)
                .push_address(&slx_con)
                .push_address(&slx_ledger)
                .push_bytes32(&POLICY_BOARD_RESOLUTION)
                .push_bytes32(&h_issue_mano)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(manogaran_id, auth_board_wrong_pol, approve_st0.as_slice()).unwrap();
        mock::transact_as(evelyn_director_id, auth_board_wrong_pol, approve_st0.as_slice()).unwrap();
        mock::transact_as(
            manogaran_id,
            auth_board_wrong_pol,
            CallEncoder::<16>::new(const { selector("finalize()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(
            mock::transact_as(
                manogaran_id,
                slx_ledger,
                CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
                    .push_address(&manogaran_id)
                    .push_u64(issue_amount)
                    .push_address(&auth_board_wrong_pol)
                    .as_slice(),
            ),
            Err(-66) // ERR_AUTH_POLICY_MISMATCH: Board resolution cannot authorize Share Issuance!
        );

        // Negative Test N7: Passing a maliciously cloned Authorization HPS with unapproved bytecode hash MUST revert (-73)!
        let auth_malicious_clone = [0xD3; 20];
        mock::register_hps(auth_malicious_clone, pe_sim::cloned_auth_dispatch);
        assert_eq!(
            mock::transact_as(
                manogaran_id,
                slx_ledger,
                CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
                    .push_address(&manogaran_id)
                    .push_u64(issue_amount)
                    .push_address(&auth_malicious_clone)
                    .as_slice(),
            ),
            Err(hps_sdk::governance::ERR_UNAPPROVED_CODE_HASH)
        );

        // Now accumulate >= 25,000 more shareholder votes from Shareholders #2..#22
        // (16 * 1,250 + 5 * 1,000 = 20,000 + 5,000 = 25,000 votes)
        // so cumulative weight reaches exactly 75,000 (75.00% Super-Majority)!
        let mut running_weight = 50_000u64;
        for (sh_id, sh_votes) in cap_table.iter().skip(1).take(21) {
            let out = mock::transact_as(*sh_id, auth_issue_mano, approve_st0.as_slice()).unwrap();
            running_weight += *sh_votes;
            assert_eq!(u64::from_be_bytes(out[24..32].try_into().unwrap()), running_weight);
        }
        assert_eq!(running_weight, 75_000);

        // Negative Test N8: Even after 75,000 votes are accumulated, passing `auth_issue_mano` BEFORE
        // calling `finalize()` MUST still revert (-62)!
        assert_eq!(
            mock::transact_as(manogaran_id, slx_ledger, issue_cd.as_slice()),
            Err(-62)
        );

        // Positive Test P2: Finalize `auth_issue_mano` and invoke `slx_ledger.issue(manogaran_id, 100_000, auth_issue_mano)`
        mock::transact_as(
            manogaran_id,
            auth_issue_mano,
            CallEncoder::<16>::new(const { selector("finalize()") }).as_slice(),
        )
        .unwrap();
        mock::transact_as(manogaran_id, slx_ledger, issue_cd.as_slice()).unwrap();

        // Verify Manogaran Thanabalan now owns 150,000 / 200,000 shares = 75.00% Super-Majority!
        assert_eq!(bal_of(slx_ledger, manogaran_id), 150_000);
        assert_eq!(supply_of(slx_ledger), 200_000);
        assert_eq!(bal_of(slx_ledger, manogaran_id) * 100 / supply_of(slx_ledger), 75);

        // Verify `Issued` event was emitted with `to = manogaran_id`, `auth = auth_issue_mano`,
        // `amount = 100,000`, `new_balance = 150,000`, `new_supply = 200,000`.
        let issued_ev = mock::events()
            .into_iter()
            .find(|e| e.address == slx_ledger && e.topics[0] == ISSUED_TOPIC)
            .expect("Issued event must be emitted");
        assert_eq!(&issued_ev.topics[1][12..32], &manogaran_id);
        assert_eq!(&issued_ev.topics[2][12..32], &auth_issue_mano);
        assert_eq!(u64::from_be_bytes(issued_ev.data[0..8].try_into().unwrap()), 100_000);
        assert_eq!(u64::from_be_bytes(issued_ev.data[8..16].try_into().unwrap()), 200_000);
        assert_eq!(u64::from_be_bytes(issued_ev.data[16..24].try_into().unwrap()), 150_000);

        // Negative Test N9: Re-passing the already-consumed `auth_issue_mano` for a duplicate `issue` call MUST revert (-68)!
        assert_eq!(
            mock::transact_as(manogaran_id, slx_ledger, issue_cd.as_slice()),
            Err(-68)
        );
        assert_eq!(bal_of(slx_ledger, manogaran_id), 150_000);
        assert_eq!(supply_of(slx_ledger), 200_000);

        // Positive Test P3: Board of Directors Resolution (Manogaran + Evelyn Tan, 2-of-2 Directors)
        // authorizing a `transfer` in another AssetLedger (`ext_treasury_ledger`) where Superlexicon's
        // corporate identity (`superlexicon_company_id`) is the owner of the assets!
        let ext_init_cd = encode_ledger_init(
            reg,
            b"USD-TREASURY",
            2,
            &[(superlexicon_company_id, 250_000)],
            &[
                (ACTION_SUPER, slx_con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, slx_con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_CANCEL, slx_con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_TRANSFER, slx_con, POLICY_BOARD_RESOLUTION),
                (ACTION_APPROVE, slx_con, POLICY_BOARD_RESOLUTION),
            ],
        );
        mock::transact_as(superlexicon_company_id, ext_treasury_ledger, &ext_init_cd).unwrap();
        assert_eq!(bal_of(ext_treasury_ledger, superlexicon_company_id), 250_000);

        let recipient_sh = cap_table[1].0;
        let h_board_tf: [u8; 32] = mock::transact_as(
            superlexicon_company_id,
            ext_treasury_ledger,
            CallEncoder::<128>::new(const { selector("hashTransfer(address,address,uint64)") })
                .push_address(&superlexicon_company_id)
                .push_address(&recipient_sh)
                .push_u64(50_000)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        let auth_board_tf = [0xD4; 20];
        mock::register_hps(auth_board_tf, pe_sim::fsm_auth_dispatch);
        mock::transact_as(
            manogaran_id,
            auth_board_tf,
            CallEncoder::<192>::new(const { selector("initialize(address,address,address,bytes32,bytes32)") })
                .push_address(&reg)
                .push_address(&slx_con)
                .push_address(&ext_treasury_ledger)
                .push_bytes32(&POLICY_BOARD_RESOLUTION)
                .push_bytes32(&h_board_tf)
                .as_slice(),
        )
        .unwrap();

        // Director 1 (Manogaran) approves -> 1 of 2 directors
        mock::transact_as(manogaran_id, auth_board_tf, approve_st0.as_slice()).unwrap();
        // Negative Test N10: 1-of-2 director alone cannot finalize a 2-of-2 Board Resolution!
        assert_eq!(
            mock::transact_as(
                manogaran_id,
                auth_board_tf,
                CallEncoder::<16>::new(const { selector("finalize()") }).as_slice(),
            ),
            Err(-62)
        );
        // Director 2 (Evelyn Tan) approves -> 2 of 2 directors -> finalize -> company identity executes transfer!
        mock::transact_as(evelyn_director_id, auth_board_tf, approve_st0.as_slice()).unwrap();
        mock::transact_as(
            manogaran_id,
            auth_board_tf,
            CallEncoder::<16>::new(const { selector("finalize()") }).as_slice(),
        )
        .unwrap();
        mock::transact_as(
            superlexicon_company_id,
            ext_treasury_ledger,
            CallEncoder::<160>::new(const { selector("transfer(address,address,uint64,address)") })
                .push_address(&superlexicon_company_id)
                .push_address(&recipient_sh)
                .push_u64(50_000)
                .push_address(&auth_board_tf)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(ext_treasury_ledger, superlexicon_company_id), 200_000);
        assert_eq!(bal_of(ext_treasury_ledger, recipient_sh), 50_000);
    }

    #[test]
    fn three_step_share_transfer_auction_clearing_and_prorata_regimes() {
        use hps_sdk::governance::{
            ERR_STEP2_SELLER_INELIGIBLE_STEP3, ERR_WRONG_AUCTION_STEP,
            POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SUPER_GOVERNANCE,
        };

        mod auc_full_sim {
            use super::*;
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::{
                share_transfer_auction_policy_spec, AuctionBook, AuctionOrder,
                ERR_NOT_EXISTING_SHAREHOLDER, ERR_STEP2_SELLER_INELIGIBLE_STEP3,
                ERR_WRONG_AUCTION_STEP, MAX_ENCODED_AUCTION_BOOK_BYTES, MAX_ENCODED_POLICY_BYTES,
                ORDER_SIDE_BUY_STEP1, ORDER_SIDE_BUY_STEP3, ORDER_SIDE_SELL_STEP2,
            };
            use hps_sdk::storage::KeyBuilder;
            use hps_sdk::{call, context, ret, selector, storage};

            pub fn reg_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("isValidIdentity(address)") } {
                    let id = args.address(0).unwrap();
                    ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                    return 0;
                }
                if sel == const { selector("isValidAuthorizationHps(address)") } {
                    let au = args.address(0).unwrap();
                    let expected = hps_sdk::mock::dispatch_code_hash(auction_auth_dispatch);
                    ret::write_bool(context::code_hash_of(&au) == Some(expected));
                    return 0;
                }
                -2
            }

            pub fn con_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("getPolicyRaw(address,bytes32)") } {
                    let spec = share_transfer_auction_policy_spec([0xA1; 20], 10, 10, 10, 50).unwrap();
                    let mut buf = [0u8; MAX_ENCODED_POLICY_BYTES];
                    let n = spec.encode(&mut buf).unwrap();
                    ret::write_abi_bytes(&buf[..n]);
                    return 0;
                }
                -2
            }

            pub fn auction_auth_dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("initializeTransferAuction(address,address,address)") } {
                    if storage::get_u64(b"state") != 0 {
                        return -50;
                    }
                    let reg = args.address(0).unwrap();
                    let con = args.address(1).unwrap();
                    let target = args.address(2).unwrap();
                    storage::set_address(b"reg", &reg);
                    storage::set_address(b"con", &con);
                    storage::set_address(b"target", &target);
                    storage::set(b"pol", &POLICY_SHARE_TRANSFER_AUCTION);
                    storage::set_u64(b"state", 1); // PENDING
                    let book = AuctionBook::new();
                    let mut bbuf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
                    let blen = book.encode(&mut bbuf).unwrap();
                    storage::set(b"book", &bbuf[..blen]);
                    ret::write_bool(true);
                    return 0;
                }
                if sel == const { selector("placeBuyOrder(uint64,uint64)") } {
                    let price = args.u64(0).unwrap();
                    let qty = args.u64(1).unwrap();
                    let caller = context::msg_sender();
                    let now = context::block_number();
                    let mut bbuf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
                    let blen = storage::get_into(b"book", &mut bbuf).unwrap();
                    let mut book = AuctionBook::decode(&bbuf[..blen]).unwrap();

                    let side = if storage::get_u64(b"started") == 0 {
                        storage::set_u64(b"started", 1);
                        storage::set_u64(b"s1", now + 10);
                        storage::set_u64(b"s2", now + 20);
                        storage::set_u64(b"s3", now + 30);
                        storage::set_u64(b"ov", now + 80);
                        ORDER_SIDE_BUY_STEP1
                    } else {
                        let s1 = storage::get_u64(b"s1");
                        let s2 = storage::get_u64(b"s2");
                        let s3 = storage::get_u64(b"s3");
                        if now <= s1 {
                            ORDER_SIDE_BUY_STEP1
                        } else if now <= s2 {
                            return ERR_WRONG_AUCTION_STEP;
                        } else if now <= s3 {
                            let sk = KeyBuilder::<32>::new().push(b"s2s:").push(&caller);
                            if storage::get_u64(sk.as_slice()) != 0 {
                                return ERR_STEP2_SELLER_INELIGIBLE_STEP3;
                            }
                            let target = storage::get_address(b"target").unwrap();
                            let bal = call::call_u64(
                                &target,
                                CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                                    .push_address(&caller)
                                    .as_slice(),
                            )
                            .unwrap_or(0);
                            if bal == 0 {
                                return ERR_NOT_EXISTING_SHAREHOLDER;
                            }
                            ORDER_SIDE_BUY_STEP3
                        } else {
                            return ERR_WRONG_AUCTION_STEP;
                        }
                    };
                    let idx = book.order_count as u64;
                    book.push(AuctionOrder {
                        side,
                        trader: caller,
                        price,
                        quantity: qty,
                    });
                    let n = book.encode(&mut bbuf).unwrap();
                    storage::set(b"book", &bbuf[..n]);
                    ret::write_u64_word(idx);
                    return 0;
                }
                if sel == const { selector("placeSellOrder(uint64,uint64)") } {
                    if storage::get_u64(b"started") == 0 {
                        return ERR_WRONG_AUCTION_STEP;
                    }
                    let price = args.u64(0).unwrap();
                    let qty = args.u64(1).unwrap();
                    let caller = context::msg_sender();
                    let now = context::block_number();
                    let s1 = storage::get_u64(b"s1");
                    let s2 = storage::get_u64(b"s2");
                    if now <= s1 || now > s2 {
                        return ERR_WRONG_AUCTION_STEP;
                    }
                    let target = storage::get_address(b"target").unwrap();
                    let bal = call::call_u64(
                        &target,
                        CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                            .push_address(&caller)
                            .as_slice(),
                    )
                    .unwrap_or(0);
                    if bal == 0 {
                        return ERR_NOT_EXISTING_SHAREHOLDER;
                    }
                    if qty > bal {
                        return -16;
                    }
                    let sk = KeyBuilder::<32>::new().push(b"s2s:").push(&caller);
                    storage::set_u64(sk.as_slice(), 1);
                    let mut bbuf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
                    let blen = storage::get_into(b"book", &mut bbuf).unwrap();
                    let mut book = AuctionBook::decode(&bbuf[..blen]).unwrap();
                    let idx = book.order_count as u64;
                    book.push(AuctionOrder {
                        side: ORDER_SIDE_SELL_STEP2,
                        trader: caller,
                        price,
                        quantity: qty,
                    });
                    let n = book.encode(&mut bbuf).unwrap();
                    storage::set(b"book", &bbuf[..n]);
                    ret::write_u64_word(idx);
                    return 0;
                }
                if sel == const { selector("consumeAuction(address,bytes32,address)") } {
                    if storage::get_u64(b"used") != 0 {
                        return -56;
                    }
                    if storage::get_u64(b"started") == 0 {
                        return -57;
                    }
                    let now = context::block_number();
                    if now <= storage::get_u64(b"s3") {
                        return ERR_WRONG_AUCTION_STEP;
                    }
                    if now > storage::get_u64(b"ov") {
                        return -55;
                    }
                    if context::msg_sender() != storage::get_address(b"target").unwrap() {
                        return -58;
                    }
                    if args.address(0).unwrap() != storage::get_address(b"con").unwrap()
                        || args.bytes32(1).unwrap() != storage::get_bytes32(b"pol").unwrap()
                    {
                        return -59;
                    }
                    storage::set_u64(b"used", 1);
                    let mut bbuf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
                    let blen = storage::get_into(b"book", &mut bbuf).unwrap();
                    ret::write_abi_bytes(&bbuf[..blen]);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let ledger_a = [0x31; 20];
        let ledger_b = [0x32; 20];
        let auth_auc_a = [0x41; 20];
        let auth_auc_b = [0x42; 20];

        mock::register_hps(reg, auc_full_sim::reg_dispatch);
        mock::register_hps(con, auc_full_sim::con_dispatch);
        mock::register_hps(ledger_a, dispatch_calldata);
        mock::register_hps(ledger_b, dispatch_calldata);
        mock::register_hps(auth_auc_a, auc_full_sim::auction_auth_dispatch);
        mock::register_hps(auth_auc_b, auc_full_sim::auction_auth_dispatch);

        let bal_of = |ledger: [u8; 20], who: [u8; 20]| -> u64 {
            let out = mock::transact_as(
                who,
                ledger,
                CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                    .push_address(&who)
                    .as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };

        // =========================================================================
        // REGIME A: Total Buying Quantity (20,000) > Total Selling Quantity (10,000)
        // -> Fill crossing sell orders 100%, and pro-rate crossing buy orders
        //    proportional to their ORIGINAL BUY ORDER QUANTITIES!
        // =========================================================================
        let seller_a = [0xA1; 20]; // 50,000 shares
        let seller_b = [0xA2; 20]; // 20,000 shares
        let seller_high = [0xA3; 20]; // 10,000 shares (asks too high a price)
        let sh_buyer_3 = [0xA4; 20]; // 20,000 shares (does NOT sell in Step 2 -> buys in Step 3)
        let buyer_1 = [0xB1; 20]; // external investor (0 shares)
        let buyer_2 = [0xB2; 20]; // external investor (0 shares)
        let buyer_low = [0xB3; 20]; // external investor (0 shares, bids too low a price)

        let init_a = encode_ledger_init(
            reg,
            b"SLX-COMMON",
            0,
            &[
                (seller_a, 50_000),
                (seller_b, 20_000),
                (seller_high, 10_000),
                (sh_buyer_3, 20_000),
            ],
            &[
                (ACTION_SUPER, con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_CANCEL, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_TRANSFER, con, POLICY_SHARE_TRANSFER_AUCTION),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(seller_a, ledger_a, &init_a).unwrap();

        mock::set_block_number(100);
        mock::transact_as(
            buyer_1,
            auth_auc_a,
            CallEncoder::<128>::new(const { selector("initializeTransferAuction(address,address,address)") })
            .push_address(&reg)
            .push_address(&con)
            .push_address(&ledger_a)
            .as_slice(),
        )
        .unwrap();

        let buy_cd = |price: u64, qty: u64| {
            CallEncoder::<96>::new(const { selector("placeBuyOrder(uint64,uint64)") })
                .push_u64(price)
                .push_u64(qty)
        };
        let sell_cd = |price: u64, qty: u64| {
            CallEncoder::<96>::new(const { selector("placeSellOrder(uint64,uint64)") })
                .push_u64(price)
                .push_u64(qty)
        };

        // Step 1 (blocks 100..=110): First potential buyer starts clock; interested buyers place orders
        mock::transact_as(buyer_1, auth_auc_a, buy_cd(120, 6_000).as_slice()).unwrap();
        mock::set_block_number(105);
        mock::transact_as(buyer_2, auth_auc_a, buy_cd(110, 8_000).as_slice()).unwrap();
        mock::transact_as(buyer_low, auth_auc_a, buy_cd(90, 5_000).as_slice()).unwrap();

        // Step 2 (blocks 111..=120): Existing shareholders place sell orders
        mock::set_block_number(112);
        mock::transact_as(seller_a, auth_auc_a, sell_cd(100, 6_000).as_slice()).unwrap();
        mock::transact_as(seller_b, auth_auc_a, sell_cd(110, 4_000).as_slice()).unwrap();
        mock::transact_as(seller_high, auth_auc_a, sell_cd(140, 3_000).as_slice()).unwrap();

        // Step 3 (blocks 121..=130): Remaining non-selling shareholder `sh_buyer_3` places buy order
        mock::set_block_number(125);
        assert_eq!(
            mock::transact_as(seller_a, auth_auc_a, buy_cd(115, 2_000).as_slice()),
            Err(ERR_STEP2_SELLER_INELIGIBLE_STEP3)
        );
        mock::transact_as(sh_buyer_3, auth_auc_a, buy_cd(115, 6_000).as_slice()).unwrap();

        // Premature settlement before Step 3 ends (block 130 <= 130) MUST revert!
        mock::set_block_number(130);
        assert_eq!(
            mock::transact_as(
                buyer_1,
                ledger_a,
                CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") })
                    .push_address(&auth_auc_a)
                    .as_slice(),
            ),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // Step 4 (block 131 > 130): Settle auction on `ledger_a`!
        mock::set_block_number(131);
        let settle_out = mock::transact_as(
            buyer_1,
            ledger_a,
            CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") })
                .push_address(&auth_auc_a)
                .as_slice(),
        )
        .unwrap();
        let clearing_price_a = u64::from_be_bytes(settle_out[24..32].try_into().unwrap());
        let matched_qty_a = u64::from_be_bytes(settle_out[56..64].try_into().unwrap());
        let buy_demand_a = u64::from_be_bytes(settle_out[88..96].try_into().unwrap());
        let sell_supply_a = u64::from_be_bytes(settle_out[120..128].try_into().unwrap());

        assert_eq!(clearing_price_a, 110);
        assert_eq!(matched_qty_a, 10_000);
        assert_eq!(buy_demand_a, 20_000);
        assert_eq!(sell_supply_a, 10_000);

        // Verify Regime A balances:
        // - Crossing sellers (`seller_a` 6,000, `seller_b` 4,000) filled 100%
        // - Non-crossing seller (`seller_high` @ 140) untouched
        // - Crossing buyers (`buyer_1` 6,000, `buyer_2` 8,000, `sh_buyer_3` 6,000) pro-rated
        //   by original buy order quantities (30% : 40% : 30% of 10,000 = 3,000 : 4,000 : 3,000)
        // - Non-crossing buyer (`buyer_low` @ 90) receives 0
        assert_eq!(bal_of(ledger_a, seller_a), 44_000);
        assert_eq!(bal_of(ledger_a, seller_b), 16_000);
        assert_eq!(bal_of(ledger_a, seller_high), 10_000);
        assert_eq!(bal_of(ledger_a, buyer_1), 3_000);
        assert_eq!(bal_of(ledger_a, buyer_2), 4_000);
        assert_eq!(bal_of(ledger_a, sh_buyer_3), 23_000);
        assert_eq!(bal_of(ledger_a, buyer_low), 0);

        // =========================================================================
        // REGIME B: Total Selling Quantity (45,000) > Total Buying Quantity (10,000)
        // -> Fill crossing buy orders 100%, and pro-rate crossing sell orders
        //    to the PERCENTAGE OF EXISTING HOLDING of each shareholder
        //    (60,000 : 20,000 : 20,000 = 60% : 20% : 20%), NOT their equal 15,000 order quantities!
        // =========================================================================
        let sh_1 = [0xC1; 20]; // holds 60,000 shares (60% of selling shareholders' holdings)
        let sh_2 = [0xC2; 20]; // holds 20,000 shares (20% of selling shareholders' holdings)
        let sh_3 = [0xC3; 20]; // holds 20,000 shares (20% of selling shareholders' holdings)
        let sh_4 = [0xC4; 20]; // holds 10,000 shares (does not sell in Step 2 -> buys in Step 3)
        let ext_buyer = [0xD1; 20]; // external investor (0 shares)

        let init_b = encode_ledger_init(
            reg,
            b"SLX-COMMON",
            0,
            &[
                (sh_1, 60_000),
                (sh_2, 20_000),
                (sh_3, 20_000),
                (sh_4, 10_000),
            ],
            &[
                (ACTION_SUPER, con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_CANCEL, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_TRANSFER, con, POLICY_SHARE_TRANSFER_AUCTION),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(sh_1, ledger_b, &init_b).unwrap();

        mock::set_block_number(200);
        mock::transact_as(
            ext_buyer,
            auth_auc_b,
            CallEncoder::<128>::new(const { selector("initializeTransferAuction(address,address,address)") })
            .push_address(&reg)
            .push_address(&con)
            .push_address(&ledger_b)
            .as_slice(),
        )
        .unwrap();

        // Step 1 (blocks 200..=210): `ext_buyer` places buy order for 7,000 shares @ 100
        mock::transact_as(ext_buyer, auth_auc_b, buy_cd(100, 7_000).as_slice()).unwrap();

        // Step 2 (blocks 211..=220): `sh_1`, `sh_2`, `sh_3` each place an IDENTICAL sell order
        // for 15,000 shares @ 100 (total selling quantity = 45,000).
        mock::set_block_number(215);
        mock::transact_as(sh_1, auth_auc_b, sell_cd(100, 15_000).as_slice()).unwrap();
        mock::transact_as(sh_2, auth_auc_b, sell_cd(100, 15_000).as_slice()).unwrap();
        mock::transact_as(sh_3, auth_auc_b, sell_cd(100, 15_000).as_slice()).unwrap();

        // Step 3 (blocks 221..=230): non-selling shareholder `sh_4` places buy order for 3,000 shares @ 100
        // (total buying quantity = 7,000 + 3,000 = 10,000 < 45,000 selling quantity).
        mock::set_block_number(225);
        mock::transact_as(sh_4, auth_auc_b, buy_cd(100, 3_000).as_slice()).unwrap();

        // Step 4 (block 231 > 230): Pass `auth_auc_b` directly to `ledger_b.transfer(...)`!
        mock::set_block_number(231);
        mock::transact_as(
            sh_1,
            ledger_b,
            CallEncoder::<160>::new(const { selector("transfer(address,address,uint64,address)") })
                .push_address(&[0u8; 20])
                .push_address(&[0u8; 20])
                .push_u64(0)
                .push_address(&auth_auc_b)
                .as_slice(),
        )
        .unwrap();

        // Verify Regime B balances:
        // - Crossing buyers filled 100%: `ext_buyer` gets 7,000, `sh_4` gets 3,000 (10,000 -> 13,000).
        // - Crossing sellers filled pro-rata to EXISTING HOLDING (60,000 : 20,000 : 20,000 = 60% : 20% : 20%),
        //   NOT their equal 15,000 sell order quantities:
        //   * `sh_1` sells 6,000 shares (60,000 -> 54,000)
        //   * `sh_2` sells 2,000 shares (20,000 -> 18,000)
        //   * `sh_3` sells 2,000 shares (20,000 -> 18,000)
        assert_eq!(bal_of(ledger_b, ext_buyer), 7_000);
        assert_eq!(bal_of(ledger_b, sh_4), 13_000);
        assert_eq!(bal_of(ledger_b, sh_1), 54_000);
        assert_eq!(bal_of(ledger_b, sh_2), 18_000);
        assert_eq!(bal_of(ledger_b, sh_3), 18_000);
    }

    #[test]
    fn bank_account_ledgers_and_escrowed_share_transfer_auction_settlement() {
        use hps_sdk::governance::{
            POLICY_BANK_ORACLE, POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SHARE_TRANSFER_AUCTION,
            POLICY_SUPER_GOVERNANCE,
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

        mod auth_stub_3 {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("arm(address,address,bytes32,bytes32)") } {
                    storage::set_address(b"con", &args.address(1).unwrap());
                    storage::set(b"pol", &args.bytes32(2).unwrap());
                    storage::set(b"hash", &args.bytes32(3).unwrap());
                    storage::set_u64(b"used", 0);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    if storage::get_u64(b"used") != 0 {
                        return -68;
                    }
                    if args.address(0).unwrap() != storage::get_address(b"con").unwrap()
                        || args.bytes32(1).unwrap() != storage::get_bytes32(b"pol").unwrap()
                        || args.bytes32(2).unwrap() != storage::get_bytes32(b"hash").unwrap()
                    {
                        return -67;
                    }
                    storage::set_u64(b"used", 1);
                    ret::write_bool(true);
                    return 0;
                }
                -2
            }
        }

        mod con_escrow_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::call::{self, CallEncoder};
            use hps_sdk::{ret, selector, storage};

            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("setup(address,address)") } {
                    storage::set_address(b"bank_led", &args.address(0).unwrap());
                    storage::set_address(b"clear_acct", &args.address(1).unwrap());
                    return 0;
                }
                if sel == const { selector("hasEscrowedAuction(address)") } {
                    ret::write_bool(true);
                    return 0;
                }
                if sel == const { selector("disburseAuctionCash(address,address,uint64,bool)") } {
                    let recipient = args.address(1).unwrap();
                    let amount = args.u64(2).unwrap();
                    let bank_led = storage::get_address(b"bank_led").unwrap();
                    let clear_acct = storage::get_address(b"clear_acct").unwrap();
                    let xfer = CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
                    .push_address(&clear_acct)
                    .push_address(&recipient)
                    .push_u64(amount);
                    let ok = call::call_bool(&bank_led, xfer.as_slice()).unwrap_or(false);
                    if !ok {
                        return -16;
                    }
                    ret::write_bool(true);
                    return 0;
                }
                -2
            }
        }

        mod auc_book_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::{
                AuctionBook, AuctionOrder, MAX_ENCODED_AUCTION_BOOK_BYTES, ORDER_SIDE_BUY_STEP1,
                ORDER_SIDE_BUY_STEP3, ORDER_SIDE_CANCELLED, ORDER_SIDE_SELL_STEP2,
            };
            use hps_sdk::{ret, selector, storage};

            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, _args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("consumeAuction(address,bytes32,address)") } {
                    if storage::get_u64(b"used") != 0 {
                        return -68;
                    }
                    storage::set_u64(b"used", 1);
                    let mut book = AuctionBook::new();
                    // Order 0: Cancelled Step 1 buy order (must be ignored by settlement!)
                    book.push(AuctionOrder {
                        side: ORDER_SIDE_CANCELLED,
                        trader: [0xB1; 20],
                        price: 200,
                        quantity: 0,
                    });
                    // Order 1: Active Step 1 buy order by buyer_1 ([0xB1; 20]) for 6,000 shares @ 110 (escrowed 660,000)
                    book.push(AuctionOrder {
                        side: ORDER_SIDE_BUY_STEP1,
                        trader: [0xB1; 20],
                        price: 110,
                        quantity: 6_000,
                    });
                    // Order 2: Active Step 2 sell order by sh_1 ([0xA1; 20]) for 5,000 shares @ 100
                    book.push(AuctionOrder {
                        side: ORDER_SIDE_SELL_STEP2,
                        trader: [0xA1; 20],
                        price: 100,
                        quantity: 5_000,
                    });
                    // Order 3: Active Step 3 buy order by sh_2 ([0xA2; 20]) for 4,000 shares @ 100 (escrowed 400,000)
                    book.push(AuctionOrder {
                        side: ORDER_SIDE_BUY_STEP3,
                        trader: [0xA2; 20],
                        price: 100,
                        quantity: 4_000,
                    });
                    let mut buf = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
                    let len = book.encode(&mut buf).unwrap();
                    ret::write_abi_bytes(&buf[..len]);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let bank_ledger = [0x31; 20];
        let share_ledger = [0x32; 20];
        let oracle_auth_1 = [0x41; 20];
        let oracle_auth_2 = [0x42; 20];
        let auc_auth = [0x43; 20];
        let bank_oracle_id = [0x91; 20];
        let clearing_acct = [0x99; 20];
        let sh_1 = [0xA1; 20];
        let sh_2 = [0xA2; 20];
        let buyer_1 = [0xB1; 20];
        let payee_1 = [0xB2; 20];

        mock::register_hps(reg, reg_stub_3::dispatch);
        mock::register_hps(con, con_escrow_stub::dispatch);
        mock::register_hps(bank_ledger, dispatch_calldata);
        mock::register_hps(share_ledger, dispatch_calldata);
        mock::register_hps(oracle_auth_1, auth_stub_3::dispatch);
        mock::register_hps(oracle_auth_2, auth_stub_3::dispatch);
        mock::register_hps(auc_auth, auc_book_stub::dispatch);

        // 1. Initialize Bank Account AssetLedger (`SLX-DBS-SGD`):
        // - ACTION_ISSUE & ACTION_CANCEL governed by `(con, POLICY_BANK_ORACLE)`
        // - ACTION_TRANSFER governed by `([0u8; 20], POLICY_HOLDER_SELF)` (simple client-signed transfers!)
        let init_bank = encode_ledger_init(
            reg,
            b"SLX-DBS-SGD",
            2,
            &[(buyer_1, 700_000), (sh_2, 500_000)],
            &[
                (ACTION_SUPER, con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, con, POLICY_BANK_ORACLE),
                (ACTION_CANCEL, con, POLICY_BANK_ORACLE),
                (ACTION_TRANSFER, [0u8; 20], POLICY_HOLDER_SELF),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(sh_1, bank_ledger, &init_bank).unwrap();

        let bal_of = |led: [u8; 20], id: [u8; 20]| -> u64 {
            let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(&id);
            let out = mock::transact_as(sh_1, led, cd.as_slice()).unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };

        // 2. Bank Oracle (`bank_oracle_id`) credits an incoming deposit of 200,000 to `buyer_1` (`issue`)
        // and debits an outgoing withdrawal of 40,000 from `buyer_1` (`cancel`):
        let h_dep: [u8; 32] = mock::transact_as(
            bank_oracle_id,
            bank_ledger,
            CallEncoder::<96>::new(const { selector("hashIssue(address,uint64)") })
                .push_address(&buyer_1)
                .push_u64(200_000)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            bank_oracle_id,
            oracle_auth_1,
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
                .push_address(&bank_ledger)
                .push_address(&con)
                .push_bytes32(&POLICY_BANK_ORACLE)
                .push_bytes32(&h_dep)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            bank_oracle_id,
            bank_ledger,
            CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
                .push_address(&buyer_1)
                .push_u64(200_000)
                .push_address(&oracle_auth_1)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(bank_ledger, buyer_1), 900_000);

        let h_wd: [u8; 32] = mock::transact_as(
            bank_oracle_id,
            bank_ledger,
            CallEncoder::<96>::new(const { selector("hashCancel(address,uint64)") })
                .push_address(&buyer_1)
                .push_u64(40_000)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            bank_oracle_id,
            oracle_auth_2,
            CallEncoder::<160>::new(const { selector("arm(address,address,bytes32,bytes32)") })
                .push_address(&bank_ledger)
                .push_address(&con)
                .push_bytes32(&POLICY_BANK_ORACLE)
                .push_bytes32(&h_wd)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            bank_oracle_id,
            bank_ledger,
            CallEncoder::<128>::new(const { selector("cancel(address,uint64,address)") })
                .push_address(&buyer_1)
                .push_u64(40_000)
                .push_address(&oracle_auth_2)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(bank_ledger, buyer_1), 860_000);

        // 3. Simple client-signed transfer on `bank_ledger` (`transferDirect` and `transfer(..., 0x0)`):
        // `buyer_1` signs a direct transfer of 50,000 to `payee_1` without needing an Authorization HPS!
        mock::transact_as(
            buyer_1,
            bank_ledger,
            CallEncoder::<96>::new(const { selector("transferDirect(address,uint64)") })
                .push_address(&payee_1)
                .push_u64(50_000)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(bank_ledger, buyer_1), 810_000);
        assert_eq!(bal_of(bank_ledger, payee_1), 50_000);

        // 4. End-of-Auction Share + Bank Balance Settlement:
        // Setup `con` with `(bank_ledger, clearing_acct)` and clear buyer escrows into `clearing_acct`:
        // - `buyer_1` escrows `110 * 6,000 = 660,000` (leaving `810,000 - 660,000 = 150,000` in `buyer_1`)
        // - `sh_2` escrows `100 * 4,000 = 400,000` (leaving `500,000 - 400,000 = 100,000` in `sh_2`)
        // Total in `clearing_acct` = 1,060,000.
        mock::transact_as(
            sh_1,
            con,
            CallEncoder::<96>::new(const { selector("setup(address,address)") })
                .push_address(&bank_ledger)
                .push_address(&clearing_acct)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            con,
            bank_ledger,
            CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
            .push_address(&buyer_1)
            .push_address(&clearing_acct)
            .push_u64(660_000)
            .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            con,
            bank_ledger,
            CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
            .push_address(&sh_2)
            .push_address(&clearing_acct)
            .push_u64(400_000)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(bal_of(bank_ledger, clearing_acct), 1_060_000);

        // Initialize `share_ledger` (`sh_1` holds 50,000 shares, `sh_2` holds 10,000 shares)
        let init_shares = encode_ledger_init(
            reg,
            b"SLX-COMMON",
            0,
            &[(sh_1, 50_000), (sh_2, 10_000)],
            &[
                (ACTION_SUPER, con, POLICY_SUPER_GOVERNANCE),
                (ACTION_ISSUE, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_CANCEL, con, POLICY_SHAREHOLDER_SUPERMAJORITY),
                (ACTION_TRANSFER, con, POLICY_SHARE_TRANSFER_AUCTION),
                (ACTION_APPROVE, [0u8; 20], POLICY_HOLDER_SELF),
            ],
        );
        mock::transact_as(sh_1, share_ledger, &init_shares).unwrap();

        // Settle auction on `share_ledger`:
        // - Crossing price P* = 100 (demand = 6,000 + 4,000 = 10,000 > supply = 5,000)
        // - Buyers pro-rated 60% / 40%:
        //   * `buyer_1` receives 3,000 shares @ P*=100 (cost = 300,000; refund from 660,000 escrow = 360,000 -> final bank bal = 150,000 + 360,000 = 510,000)
        //   * `sh_2` receives 2,000 shares @ P*=100 (cost = 200,000; refund from 400,000 escrow = 200,000 -> final bank bal = 100,000 + 200,000 = 300,000)
        // - Seller `sh_1` sells 5,000 shares @ P*=100 and receives 500,000 in `bank_ledger`!
        // - `clearing_acct` balance returns to 0!
        let settle_out = mock::transact_as(
            sh_1,
            share_ledger,
            CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") })
                .push_address(&auc_auth)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(settle_out[24..32].try_into().unwrap()), 100);
        assert_eq!(u64::from_be_bytes(settle_out[56..64].try_into().unwrap()), 5_000);

        // Verify share balances
        assert_eq!(bal_of(share_ledger, sh_1), 45_000);
        assert_eq!(bal_of(share_ledger, buyer_1), 3_000);
        assert_eq!(bal_of(share_ledger, sh_2), 12_000);

        // Verify bank sub-account balances after DvP cash settlement & refunds
        assert_eq!(bal_of(bank_ledger, sh_1), 500_000);
        assert_eq!(bal_of(bank_ledger, buyer_1), 510_000);
        assert_eq!(bal_of(bank_ledger, sh_2), 300_000);
        assert_eq!(bal_of(bank_ledger, clearing_acct), 0);
    }
}
