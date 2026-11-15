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
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    oracle_policy_id, require_valid_identity, verify_and_consume_auth, ActionHasher, PolicySpec,
    ShareClassSpec, StageSpec, ACTION_ADD_DIRECTOR, ACTION_REGISTER_SHARE_CLASS,
    ACTION_REMOVE_DIRECTOR, ACTION_SET_BANK_ORACLE, ACTION_SET_CLEARING_ACCOUNT,
    ACTION_SET_PRODUCT_ORACLE, ERR_POLICY_INVALID, MAX_ENCODED_POLICY_BYTES, MAX_MEMBERS_PER_STAGE,
    MAX_SHARE_CLASSES, POLICY_BANK_ORACLE, POLICY_BOARD_RESOLUTION, POLICY_PRODUCT_ORACLE,
    POLICY_SUPER_GOVERNANCE,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const CONSTITUTION_INITIALIZED: [u8; 32] = event_topic("ConstitutionInitialized(address,uint64)");
const POLICY_SET: [u8; 32] = event_topic("PolicySet(address,bytes32,uint64,uint64)");
const POLICY_DEACTIVATED: [u8; 32] = event_topic("PolicyDeactivated(address,bytes32)");
const DIRECTOR_ADDED: [u8; 32] = event_topic("DirectorAdded(address,uint64,address)");
const DIRECTOR_REMOVED: [u8; 32] = event_topic("DirectorRemoved(address,uint64,address)");
const BANK_ORACLE_SET: [u8; 32] = event_topic("BankOracleSet(address,address,address)");
const PRODUCT_ORACLE_SET: [u8; 32] = event_topic("ProductOracleSet(address,address,address)");
const CLEARING_ACCOUNT_SET: [u8; 32] = event_topic("ClearingAccountSet(address,address)");
const AUCTION_BUY_ORDER_CLEARED: [u8; 32] =
    event_topic("AuctionBuyOrderCleared(address,address,uint64)");
const AUCTION_BUY_ORDER_REFUNDED: [u8; 32] =
    event_topic("AuctionBuyOrderRefunded(address,address,uint64)");
const AUCTION_CASH_SETTLED: [u8; 32] =
    event_topic("AuctionCashSettled(address,address,uint64,bool)");
const PRODUCT_PAYMENT_CLEARED: [u8; 32] =
    event_topic("ProductPaymentCleared(address,address,uint64)");
const SHARE_CLASS_REGISTERED: [u8; 32] =
    event_topic("ShareClassRegistered(address,uint64,uint64,uint64)");

const TAG_SET_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_SET_POLICY");
const TAG_DEACTIVATE_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_DEACTIVATE_POLICY");

const KEY_INIT: &[u8] = b"con:init";
const KEY_REGISTRY: &[u8] = b"con:reg";
const KEY_DIRECTORS_BLOB: &[u8] = b"con:directors";
const KEY_BOARD_EXPIRY: &[u8] = b"con:board_exp";
const KEY_CLEARING_ACCOUNT: &[u8] = b"con:clear_acct";
const KEY_DEFAULT_BANK_LEDGER: &[u8] = b"con:bank_led";
const KEY_SHARE_CLASSES_BLOB: &[u8] = b"con:sh_classes";

hps_entry! {
    "initialize(address,bytes)"                                           => handle_initialize,
    "setPolicy(address,bytes32,bytes,address)"                            => handle_set_policy,
    "deactivatePolicy(address,bytes32,address)"                           => handle_deactivate_policy,
    "addDirector(address,address)"                                        => handle_add_director,
    "removeDirector(address,address)"                                     => handle_remove_director,
    "isDirector(address)"                                                 => handle_is_director,
    "directorCount()"                                                     => handle_director_count,
    "setBankOracle(address,address,uint64,address)"                       => handle_set_bank_oracle,
    "setProductOracle(address,address,uint64,address)"                    => handle_set_product_oracle,
    "setClearingAccount(address,address,address)"                         => handle_set_clearing_account,
    "bankOracleOf(address)"                                               => handle_bank_oracle_of,
    "productOracleOf(address)"                                            => handle_product_oracle_of,
    "clearingAccount()"                                                   => handle_clearing_account,
    "defaultBankLedger()"                                                 => handle_default_bank_ledger,
    "settleProductPayment(address,uint64)"                                => handle_settle_product_payment,
    "placeBuyOrder(address,uint64,uint64)"                                => handle_place_buy_order,
    "cancelBuyOrder(address,uint64)"                                      => handle_cancel_buy_order,
    "placeSellOrder(address,uint64,uint64)"                               => handle_place_sell_order,
    "settleShareTransferAuction(address,address)"                         => handle_settle_share_transfer_auction,
    "hasEscrowedAuction(address)"                                         => handle_has_escrowed_auction,
    "escrowedCashOf(address)"                                             => handle_escrowed_cash_of,
    "disburseAuctionCash(address,address,uint64,bool)"                    => handle_disburse_auction_cash,
    "registerShareClass(address,uint64,uint64,uint64,address)"            => handle_register_share_class,
    "shareClassCount()"                                                   => handle_share_class_count,
    "getShareClass(uint64)"                                               => handle_get_share_class,
    "shareholderVotingPower(address)"                                     => handle_shareholder_voting_power,
    "getPolicyRaw(address,bytes32)"                                       => handle_get_policy_raw,
    "hasPolicy(address,bytes32)"                                          => handle_has_policy,
    "identityRegistry()"                                                  => handle_identity_registry,
    "hashSetPolicy(address,bytes32,bytes)"                                => handle_hash_set_policy,
    "hashDeactivatePolicy(address,bytes32)"                               => handle_hash_deactivate_policy,
    "hashAddDirector(address)"                                            => handle_hash_add_director,
    "hashRemoveDirector(address)"                                         => handle_hash_remove_director,
    "hashSetBankOracle(address,address,uint64)"                           => handle_hash_set_bank_oracle,
    "hashSetProductOracle(address,address,uint64)"                        => handle_hash_set_product_oracle,
    "hashSetClearingAccount(address,address)"                             => handle_hash_set_clearing_account,
    "hashRegisterShareClass(address,uint64,uint64,uint64)"                => handle_hash_register_share_class,
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

fn validate_and_verify_spec_cached(
    registry: &[u8; 20],
    raw_spec: &[u8],
    verified: &mut [[u8; 20]; MAX_MEMBERS_PER_STAGE],
    verified_len: &mut usize,
) -> Result<PolicySpec, i32> {
    if raw_spec.is_empty() || raw_spec.len() > MAX_ENCODED_POLICY_BYTES {
        return Err(ERR_POLICY_INVALID);
    }
    let spec = PolicySpec::decode(raw_spec).ok_or(ERR_POLICY_INVALID)?;
    let mut s = 0;
    while s < spec.stage_count {
        let st = &spec.stages[s];
        let mut m = 0;
        while m < st.member_count {
            let id = &st.members[m].identity;
            let mut seen = false;
            let mut k = 0;
            while k < *verified_len {
                if &verified[k] == id {
                    seen = true;
                    break;
                }
                k += 1;
            }
            if !seen {
                require_valid_identity(registry, id)?;
                if *verified_len < MAX_MEMBERS_PER_STAGE {
                    verified[*verified_len] = *id;
                    *verified_len += 1;
                }
            }
            m += 1;
        }
        s += 1;
    }
    Ok(spec)
}

fn validate_and_verify_spec(registry: &[u8; 20], raw_spec: &[u8]) -> Result<PolicySpec, i32> {
    let mut verified = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let mut verified_len = 0usize;
    validate_and_verify_spec_cached(registry, raw_spec, &mut verified, &mut verified_len)
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

fn compute_add_director_hash(director: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_ADD_DIRECTOR)
        .push_address(director)
        .finish()
}

fn compute_remove_director_hash(director: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_REMOVE_DIRECTOR)
        .push_address(director)
        .finish()
}

fn compute_set_bank_oracle_hash(
    bank_ledger: &[u8; 20],
    oracle_identity: &[u8; 20],
    expiry_blocks: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_BANK_ORACLE)
        .push_address(bank_ledger)
        .push_address(oracle_identity)
        .push_u64(expiry_blocks)
        .finish()
}

fn compute_set_product_oracle_hash(
    product_ledger: &[u8; 20],
    oracle_identity: &[u8; 20],
    expiry_blocks: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_PRODUCT_ORACLE)
        .push_address(product_ledger)
        .push_address(oracle_identity)
        .push_u64(expiry_blocks)
        .finish()
}

fn compute_set_clearing_account_hash(
    bank_ledger: &[u8; 20],
    clearing_account: &[u8; 20],
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_CLEARING_ACCOUNT)
        .push_address(bank_ledger)
        .push_address(clearing_account)
        .finish()
}

fn compute_register_share_class_hash(
    share_ledger: &[u8; 20],
    votes_per_share: u64,
    conversion_numer: u64,
    conversion_denom: u64,
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_REGISTER_SHARE_CLASS)
        .push_address(share_ledger)
        .push_u64(votes_per_share)
        .push_u64(conversion_numer)
        .push_u64(conversion_denom)
        .finish()
}

fn bank_oracle_key(bank_ledger: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"bora:").push(bank_ledger)
}

fn product_oracle_key(product_ledger: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"pora:").push(product_ledger)
}

fn auc_escrow_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"aesc:").push(auth_obj)
}

fn auc_escrow_active_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"aact:").push(auth_obj)
}

fn load_share_classes(out: &mut [ShareClassSpec; MAX_SHARE_CLASSES]) -> usize {
    let mut raw = [0u8; MAX_SHARE_CLASSES * ShareClassSpec::ENCODED_LEN];
    let Some(n) = storage::get_into(KEY_SHARE_CLASSES_BLOB, &mut raw) else {
        return 0;
    };
    let count = (n / ShareClassSpec::ENCODED_LEN).min(MAX_SHARE_CLASSES);
    let mut i = 0;
    while i < count {
        let base = i * ShareClassSpec::ENCODED_LEN;
        let Some(spec) = ShareClassSpec::decode(&raw[base..base + ShareClassSpec::ENCODED_LEN])
        else {
            return i;
        };
        out[i] = spec;
        i += 1;
    }
    count
}

fn save_share_classes(classes: &[ShareClassSpec; MAX_SHARE_CLASSES], count: usize) {
    let mut raw = [0u8; MAX_SHARE_CLASSES * ShareClassSpec::ENCODED_LEN];
    let mut i = 0;
    while i < count {
        let base = i * ShareClassSpec::ENCODED_LEN;
        let enc = classes[i].encode();
        raw[base..base + ShareClassSpec::ENCODED_LEN].copy_from_slice(&enc);
        i += 1;
    }
    storage::set(
        KEY_SHARE_CLASSES_BLOB,
        &raw[..count * ShareClassSpec::ENCODED_LEN],
    );
}

fn load_directors(out: &mut [[u8; 20]; MAX_MEMBERS_PER_STAGE]) -> usize {
    let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
    let Some(n) = storage::get_into(KEY_DIRECTORS_BLOB, &mut raw) else {
        return 0;
    };
    let count = (n / 20).min(MAX_MEMBERS_PER_STAGE);
    let mut i = 0;
    while i < count {
        out[i].copy_from_slice(&raw[i * 20..(i + 1) * 20]);
        i += 1;
    }
    count
}

fn save_directors_and_sync_board_policy(
    directors: &[[u8; 20]; MAX_MEMBERS_PER_STAGE],
    count: usize,
    expiry_blocks: u64,
) -> Result<(), i32> {
    let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
    let mut i = 0;
    while i < count {
        raw[i * 20..(i + 1) * 20].copy_from_slice(&directors[i]);
        i += 1;
    }
    storage::set(KEY_DIRECTORS_BLOB, &raw[..count * 20]);
    storage::set_u64(KEY_BOARD_EXPIRY, expiry_blocks);

    if count > 0 {
        let exp = if expiry_blocks == 0 { 50 } else { expiry_blocks };
        let mut stage = StageSpec::new(count as u64, exp);
        let mut j = 0;
        while j < count {
            stage = stage
                .add_member(directors[j], 1)
                .ok_or(ERR_POLICY_INVALID)?;
            j += 1;
        }
        let spec = PolicySpec::new(exp * 2)
            .add_stage(stage)
            .ok_or(ERR_POLICY_INVALID)?;
        let mut enc = [0u8; MAX_ENCODED_POLICY_BYTES];
        let enc_len = spec.encode(&mut enc).ok_or(ERR_POLICY_INVALID)?;
        store_policy(&[0u8; 20], &POLICY_BOARD_RESOLUTION, &enc[..enc_len], &spec);
    }
    Ok(())
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
    let mut verified = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    verified[0] = caller;
    let mut verified_len = 1usize;
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

        let spec =
            validate_and_verify_spec_cached(&registry, raw_spec, &mut verified, &mut verified_len)?;
        store_policy(&target_hps, &policy_id, raw_spec, &spec);

        if policy_id == POLICY_BOARD_RESOLUTION && spec.stage_count > 0 {
            let st0 = &spec.stages[0];
            let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
            let mut m = 0;
            while m < st0.member_count {
                dirs[m] = st0.members[m].identity;
                m += 1;
            }
            let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
            let mut k = 0;
            while k < st0.member_count {
                raw[k * 20..(k + 1) * 20].copy_from_slice(&dirs[k]);
                k += 1;
            }
            storage::set(KEY_DIRECTORS_BLOB, &raw[..st0.member_count * 20]);
            storage::set_u64(KEY_BOARD_EXPIRY, st0.expiry_blocks);
        }

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
        &registry,
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
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
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
        &registry,
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

/// Add a new company Director Identity to the Board of Directors.
/// Requires a finalized, one-time-use Shareholder Super-Majority (`POLICY_SUPER_GOVERNANCE`)
/// `Authorization` HPS object. Automatically updates `POLICY_BOARD_RESOLUTION` to require all directors.
fn handle_add_director(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let new_director = args.address(0).ok_or(-3)?;
    let super_auth = args.address(1).ok_or(-3)?;

    require_valid_identity(&registry, &new_director)?;

    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    if count >= MAX_MEMBERS_PER_STAGE {
        return Err(-61);
    }
    let mut i = 0;
    while i < count {
        if dirs[i] == new_director {
            return Err(-61); // already an active director
        }
        i += 1;
    }

    let action_hash = compute_add_director_hash(&new_director);
    let me = context::self_address();
    verify_and_consume_auth(
        &registry,
        &super_auth,
        &me,
        &POLICY_SUPER_GOVERNANCE,
        &action_hash,
        &caller,
    )?;

    dirs[count] = new_director;
    let new_count = count + 1;
    let exp = storage::get_u64(KEY_BOARD_EXPIRY);
    save_directors_and_sync_board_policy(&dirs, new_count, if exp == 0 { 50 } else { exp })?;

    events::emit(
        &[
            DIRECTOR_ADDED,
            addr_topic(&new_director),
            addr_topic(&super_auth),
        ],
        &(new_count as u64).to_be_bytes(),
    );
    ret::write_u64_word(new_count as u64);
    Ok(())
}

/// Remove an existing Director Identity from the Board of Directors.
/// Requires a finalized, one-time-use Shareholder Super-Majority (`POLICY_SUPER_GOVERNANCE`)
/// `Authorization` HPS object. Automatically updates `POLICY_BOARD_RESOLUTION` to require all remaining directors.
fn handle_remove_director(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let director = args.address(0).ok_or(-3)?;
    let super_auth = args.address(1).ok_or(-3)?;

    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    if count <= 1 {
        return Err(-61); // cannot remove the last remaining director
    }
    let mut found_idx: Option<usize> = None;
    let mut i = 0;
    while i < count {
        if dirs[i] == director {
            found_idx = Some(i);
            break;
        }
        i += 1;
    }
    let idx = found_idx.ok_or(-62)?;

    let action_hash = compute_remove_director_hash(&director);
    let me = context::self_address();
    verify_and_consume_auth(
        &registry,
        &super_auth,
        &me,
        &POLICY_SUPER_GOVERNANCE,
        &action_hash,
        &caller,
    )?;

    let mut j = idx;
    while j + 1 < count {
        dirs[j] = dirs[j + 1];
        j += 1;
    }
    dirs[count - 1] = [0u8; 20];
    let new_count = count - 1;
    let exp = storage::get_u64(KEY_BOARD_EXPIRY);
    save_directors_and_sync_board_policy(&dirs, new_count, if exp == 0 { 50 } else { exp })?;

    events::emit(
        &[
            DIRECTOR_REMOVED,
            addr_topic(&director),
            addr_topic(&super_auth),
        ],
        &(new_count as u64).to_be_bytes(),
    );
    ret::write_u64_word(new_count as u64);
    Ok(())
}

fn handle_is_director(args: &CalldataReader) -> Result<(), i32> {
    let candidate = args.address(0).ok_or(-3)?;
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    let mut i = 0;
    while i < count {
        if dirs[i] == candidate {
            ret::write_bool(true);
            return Ok(());
        }
        i += 1;
    }
    ret::write_bool(false);
    Ok(())
}

fn handle_director_count(_args: &CalldataReader) -> Result<(), i32> {
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    ret::write_u64_word(count as u64);
    Ok(())
}

/// Set or rotate the Bank Oracle backend Identity (`oracleIdentity`) for a company bank-account
/// `AssetLedger` (`bankLedger`).
/// Requires a finalized, one-time-use **Board Resolution** (`POLICY_BOARD_RESOLUTION`)
/// `Authorization` HPS object.
/// Automatically writes a 1-stage `PolicySpec` under `(bankLedger, POLICY_BANK_ORACLE)` and
/// `(bankLedger, oracle_policy_id(&oracleIdentity))` so the bank API oracle backend can authorize
/// incoming deposit credits (`issue`) and outgoing withdrawal debits (`cancel`).
fn handle_set_bank_oracle(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let oracle_identity = args.address(1).ok_or(-3)?;
    let expiry_blocks = args.u64(2).ok_or(-3)?;
    let board_auth = args.address(3).ok_or(-3)?;
    if bank_ledger == [0u8; 20] {
        return Err(-59);
    }

    require_valid_identity(&registry, &oracle_identity)?;

    let action_hash = compute_set_bank_oracle_hash(&bank_ledger, &oracle_identity, expiry_blocks);
    let me = context::self_address();
    verify_and_consume_auth(
        &registry,
        &board_auth,
        &me,
        &POLICY_BOARD_RESOLUTION,
        &action_hash,
        &caller,
    )?;

    let exp = if expiry_blocks == 0 { 50 } else { expiry_blocks };
    let stage = StageSpec::new(1, exp)
        .add_member(oracle_identity, 1)
        .ok_or(ERR_POLICY_INVALID)?;
    let spec = PolicySpec::new(exp.saturating_mul(2))
        .add_stage(stage)
        .ok_or(ERR_POLICY_INVALID)?;
    let mut enc = [0u8; MAX_ENCODED_POLICY_BYTES];
    let enc_len = spec.encode(&mut enc).ok_or(ERR_POLICY_INVALID)?;

    store_policy(&bank_ledger, &POLICY_BANK_ORACLE, &enc[..enc_len], &spec);
    let dyn_pol = oracle_policy_id(&oracle_identity);
    store_policy(&bank_ledger, &dyn_pol, &enc[..enc_len], &spec);

    let ok = bank_oracle_key(&bank_ledger);
    storage::set_address(ok.as_slice(), &oracle_identity);
    if storage::get_address(KEY_DEFAULT_BANK_LEDGER).is_none() {
        storage::set_address(KEY_DEFAULT_BANK_LEDGER, &bank_ledger);
    }

    events::emit(
        &[
            BANK_ORACLE_SET,
            addr_topic(&bank_ledger),
            addr_topic(&oracle_identity),
            addr_topic(&board_auth),
        ],
        &exp.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Configure the Constitution's special clearing account (`clearingAccount`) and default bank
/// balance `AssetLedger` (`bankLedger`) used to clear & settle share transfer auctions.
/// Requires a finalized **Board Resolution** (`POLICY_BOARD_RESOLUTION`) `Authorization` HPS object
/// (or initial setup by an active Director when `boardAuth == 0x0` and no clearing account is set yet).
fn handle_set_clearing_account(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let clearing_account = args.address(1).ok_or(-3)?;
    let board_auth = args.address(2).ok_or(-3)?;
    if bank_ledger == [0u8; 20] || clearing_account == [0u8; 20] {
        return Err(-59);
    }

    require_valid_identity(&registry, &clearing_account)?;

    if board_auth == [0u8; 20] && storage::get_address(KEY_CLEARING_ACCOUNT).is_none() {
        // Initial bootstrap allowed by an active company director
        let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let count = load_directors(&mut dirs);
        let mut is_dir = false;
        let mut i = 0;
        while i < count {
            if dirs[i] == caller {
                is_dir = true;
                break;
            }
            i += 1;
        }
        if !is_dir && count > 0 {
            return Err(-61);
        }
    } else {
        let action_hash = compute_set_clearing_account_hash(&bank_ledger, &clearing_account);
        let me = context::self_address();
        verify_and_consume_auth(
            &registry,
            &board_auth,
            &me,
            &POLICY_BOARD_RESOLUTION,
            &action_hash,
            &caller,
        )?;
    }

    storage::set_address(KEY_DEFAULT_BANK_LEDGER, &bank_ledger);
    storage::set_address(KEY_CLEARING_ACCOUNT, &clearing_account);

    events::emit(
        &[
            CLEARING_ACCOUNT_SET,
            addr_topic(&bank_ledger),
            addr_topic(&clearing_account),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_bank_oracle_of(args: &CalldataReader) -> Result<(), i32> {
    let bank_ledger = args.address(0).ok_or(-3)?;
    let ok = bank_oracle_key(&bank_ledger);
    let oracle = storage::get_address(ok.as_slice()).unwrap_or([0u8; 20]);
    ret::write_address(&oracle);
    Ok(())
}

/// Appoint or rotate the Product Catalog Manager / Oracle `Identity` (`oracleIdentity`) authorized
/// to manage products, inventory units, and prices in a company `ProductLedger` (`productLedger`).
/// Requires a finalized **Board Resolution** (`POLICY_BOARD_RESOLUTION`) `Authorization` HPS object.
fn handle_set_product_oracle(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let oracle_identity = args.address(1).ok_or(-3)?;
    let expiry_blocks = args.u64(2).ok_or(-3)?;
    let board_auth = args.address(3).ok_or(-3)?;
    if product_ledger == [0u8; 20] || oracle_identity == [0u8; 20] {
        return Err(-59);
    }

    require_valid_identity(&registry, &oracle_identity)?;

    let action_hash =
        compute_set_product_oracle_hash(&product_ledger, &oracle_identity, expiry_blocks);
    let me = context::self_address();
    verify_and_consume_auth(
        &registry,
        &board_auth,
        &me,
        &POLICY_BOARD_RESOLUTION,
        &action_hash,
        &caller,
    )?;

    let exp = if expiry_blocks == 0 { 50 } else { expiry_blocks };
    let stage = StageSpec::new(1, exp)
        .add_member(oracle_identity, 1)
        .ok_or(ERR_POLICY_INVALID)?;
    let spec = PolicySpec::new(exp.saturating_mul(2))
        .add_stage(stage)
        .ok_or(ERR_POLICY_INVALID)?;
    let mut enc = [0u8; MAX_ENCODED_POLICY_BYTES];
    let enc_len = spec.encode(&mut enc).ok_or(ERR_POLICY_INVALID)?;

    store_policy(&product_ledger, &POLICY_PRODUCT_ORACLE, &enc[..enc_len], &spec);
    let dyn_pol = oracle_policy_id(&oracle_identity);
    store_policy(&product_ledger, &dyn_pol, &enc[..enc_len], &spec);

    let pk = product_oracle_key(&product_ledger);
    storage::set_address(pk.as_slice(), &oracle_identity);

    events::emit(
        &[
            PRODUCT_ORACLE_SET,
            addr_topic(&product_ledger),
            addr_topic(&oracle_identity),
            addr_topic(&board_auth),
        ],
        &exp.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_product_oracle_of(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let pk = product_oracle_key(&product_ledger);
    let oracle = storage::get_address(pk.as_slice()).unwrap_or([0u8; 20]);
    ret::write_address(&oracle);
    Ok(())
}

/// Invoked by an owned `ProductLedger` during `buyProduct` to atomically clear `totalCost` from
/// `buyer`'s sub-account in the company's Bank Balance `AssetLedger` into the Constitution's
/// clearing/revenue account. Reverts if the buyer has insufficient bank balance.
fn handle_settle_product_payment(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let buyer = args.address(0).ok_or(-3)?;
    let total_cost = args.u64(1).ok_or(-3)?;
    if buyer == [0u8; 20] || total_cost == 0 {
        return Err(-59);
    }

    // Verify caller is a registered ProductLedger controlled by this Constitution
    let product_ledger = context::msg_sender();
    let pk = product_oracle_key(&product_ledger);
    if storage::get_address(pk.as_slice()).is_none() {
        return Err(-62);
    }

    let bank_ledger = storage::get_address(KEY_DEFAULT_BANK_LEDGER).ok_or(-63)?;
    let clearing_acct = storage::get_address(KEY_CLEARING_ACCOUNT).ok_or(-63)?;

    let xfer_cd = CallEncoder::<128>::new(const {
        const { selector("constitutionClearTransfer(address,address,uint64)") }
    })
    .push_address(&buyer)
    .push_address(&clearing_acct)
    .push_u64(total_cost);
    let ok = call::call_bool(&bank_ledger, xfer_cd.as_slice())?;
    if !ok {
        return Err(-16);
    }

    events::emit(
        &[
            PRODUCT_PAYMENT_CLEARED,
            addr_topic(&product_ledger),
            addr_topic(&buyer),
        ],
        &total_cost.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_clearing_account(_args: &CalldataReader) -> Result<(), i32> {
    let acct = storage::get_address(KEY_CLEARING_ACCOUNT).unwrap_or([0u8; 20]);
    ret::write_address(&acct);
    Ok(())
}

fn handle_default_bank_ledger(_args: &CalldataReader) -> Result<(), i32> {
    let led = storage::get_address(KEY_DEFAULT_BANK_LEDGER).unwrap_or([0u8; 20]);
    ret::write_address(&led);
    Ok(())
}

/// Place a buy order (`price`, `quantity`) in a 3-step share transfer auction `Authorization` HPS
/// (`authObj`) via the `Constitution`:
/// 1. Clears `price * quantity` from the buyer's sub-account in the company's bank balance
///    `AssetLedger` to the `Constitution`'s special clearing account (`clearingAccount()`).
///    Reverts (`Err(-16)`) if the buyer has insufficient bank balance.
/// 2. Records the buy order in `authObj` via `placeBuyOrderFor(buyer, price, quantity)` (which
///    enforces Step 1 / Step 3 timing and non-participation rules).
fn handle_place_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, buyer) = ensure_initialized_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    if price == 0 || quantity == 0 {
        return Err(-14);
    }
    let escrow_cash = price.checked_mul(quantity).ok_or(-15)?;

    let bank_ledger = storage::get_address(KEY_DEFAULT_BANK_LEDGER).ok_or(-63)?;
    let clearing_acct = storage::get_address(KEY_CLEARING_ACCOUNT).ok_or(-63)?;

    // 1. Clear required balance from buyer's bank account into Constitution's clearing account
    let clear_cd = CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
    .push_address(&buyer)
    .push_address(&clearing_acct)
    .push_u64(escrow_cash);
    let cleared = call::call_bool(&bank_ledger, clear_cd.as_slice())?;
    if !cleared {
        return Err(-16);
    }

    // 2. Record buy order in the auction Authorization HPS
    let order_cd = CallEncoder::<128>::new(const { selector("placeBuyOrderFor(address,uint64,uint64)") })
        .push_address(&buyer)
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, order_cd.as_slice())?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    storage::set_u64(ek.as_slice(), cur_escrow.saturating_add(escrow_cash));
    let ak = auc_escrow_active_key(&auth_obj);
    storage::set_u64(ak.as_slice(), 1);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&price.to_be_bytes());
    ev[8..16].copy_from_slice(&quantity.to_be_bytes());
    ev[16..24].copy_from_slice(&escrow_cash.to_be_bytes());
    events::emit(
        &[
            AUCTION_BUY_ORDER_CLEARED,
            addr_topic(&auth_obj),
            addr_topic(&buyer),
        ],
        &ev,
    );

    ret::write_u64_word(order_idx);
    Ok(())
}

/// Cancel a previously placed buy order (`orderIndex`) via the `Constitution`:
/// - Calls `authObj.cancelBuyOrderFor(buyer, orderIndex)` which strictly enforces that a buy order
///   can ONLY be cancelled in the exact step in which it was placed (`Step 1` orders only during
///   `Step 1`; `Step 3` orders only during `Step 3`).
/// - Transfers the cleared balance (`price * quantity`) from the `Constitution`'s special clearing
///   account back to the user's sub-account in the bank balance `AssetLedger`.
fn handle_cancel_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, buyer) = ensure_initialized_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let order_index = args.u64(1).ok_or(-3)?;

    let bank_ledger = storage::get_address(KEY_DEFAULT_BANK_LEDGER).ok_or(-63)?;
    let clearing_acct = storage::get_address(KEY_CLEARING_ACCOUNT).ok_or(-63)?;

    let cancel_cd = CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
        .push_address(&buyer)
        .push_u64(order_index);
    let raw = call::call_raw(&auth_obj, cancel_cd.as_slice())?;
    if raw.len() < 64 {
        return Err(-65);
    }
    let mut w_price = [0u8; 8];
    w_price.copy_from_slice(&raw[24..32]);
    let mut w_qty = [0u8; 8];
    w_qty.copy_from_slice(&raw[56..64]);
    let price = u64::from_be_bytes(w_price);
    let quantity = u64::from_be_bytes(w_qty);
    let refund_cash = price.checked_mul(quantity).ok_or(-15)?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    if cur_escrow < refund_cash {
        return Err(-16);
    }
    storage::set_u64(ek.as_slice(), cur_escrow - refund_cash);

    let refund_cd = CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
    .push_address(&clearing_acct)
    .push_address(&buyer)
    .push_u64(refund_cash);
    let refunded = call::call_bool(&bank_ledger, refund_cd.as_slice())?;
    if !refunded {
        return Err(-16);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&order_index.to_be_bytes());
    ev[8..16].copy_from_slice(&refund_cash.to_be_bytes());
    events::emit(
        &[
            AUCTION_BUY_ORDER_REFUNDED,
            addr_topic(&auth_obj),
            addr_topic(&buyer),
        ],
        &ev,
    );

    ret::write_u64_word(refund_cash);
    Ok(())
}

/// Place a sell order (`price`, `quantity`) during Step 2 via the `Constitution`.
fn handle_place_sell_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, seller) = ensure_initialized_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    let order_cd = CallEncoder::<128>::new(const { selector("placeSellOrderFor(address,uint64,uint64)") })
        .push_address(&seller)
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, order_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

/// Finalize and settle a completed 3-step share transfer auction (`authObj`) on `shareLedger`:
/// determines the single clearing price, executes pro-rated share transfers on `shareLedger`, and
/// settles cleared bank balances from the `Constitution` clearing account to sellers' bank
/// sub-accounts (while refunding any unspent buyer escrow).
fn handle_settle_share_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _caller) = ensure_initialized_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let settle_cd =
        CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") }).push_address(&auth_obj);
    let out = call::call_raw(&share_ledger, settle_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_has_escrowed_auction(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    let ak = auc_escrow_active_key(&auth_obj);
    ret::write_bool(storage::get_u64(ak.as_slice()) == 1);
    Ok(())
}

fn handle_escrowed_cash_of(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    let ek = auc_escrow_key(&auth_obj);
    ret::write_u64_word(storage::get_u64(ek.as_slice()));
    Ok(())
}

/// Callback invoked by the target share `AssetLedger` during `execute_transfer_auction_settlement`
/// to disburse seller trade proceeds (`clearingPrice * filledQty`) and refund any unspent buyer
/// escrow (`(limitPrice * orderQty) - (clearingPrice * filledQty)`) from the `Constitution`
/// clearing account to `recipient`'s sub-account in the bank balance `AssetLedger`.
fn handle_disburse_auction_cash(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let auth_obj = args.address(0).ok_or(-3)?;
    let recipient = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let is_seller_proceeds = args.bool(3).ok_or(-3)?;
    if amount == 0 {
        ret::write_bool(true);
        return Ok(());
    }

    // Verify caller is the exact target share AssetLedger bound to `auth_obj`
    let caller = context::msg_sender();
    let target_cd = CallEncoder::<16>::new(const { selector("targetHps()") });
    let Ok(raw_target) = call::call_raw(&auth_obj, target_cd.as_slice()) else {
        return Err(-62);
    };
    if raw_target.len() < 32 {
        return Err(-62);
    }
    let mut expected_ledger = [0u8; 20];
    expected_ledger.copy_from_slice(&raw_target[12..32]);
    if caller != expected_ledger {
        return Err(-62);
    }

    let bank_ledger = storage::get_address(KEY_DEFAULT_BANK_LEDGER).ok_or(-63)?;
    let clearing_acct = storage::get_address(KEY_CLEARING_ACCOUNT).ok_or(-63)?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    if cur_escrow < amount {
        return Err(-16);
    }
    storage::set_u64(ek.as_slice(), cur_escrow - amount);

    let xfer_cd = CallEncoder::<128>::new(const { selector("constitutionClearTransfer(address,address,uint64)") })
    .push_address(&clearing_acct)
    .push_address(&recipient)
    .push_u64(amount);
    let ok = call::call_bool(&bank_ledger, xfer_cd.as_slice())?;
    if !ok {
        return Err(-16);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[15] = u8::from(is_seller_proceeds);
    events::emit(
        &[
            AUCTION_CASH_SETTLED,
            addr_topic(&auth_obj),
            addr_topic(&recipient),
        ],
        &ev,
    );
    ret::write_bool(true);
    Ok(())
}

/// Register or update a share-class `AssetLedger` owned/controlled by this `Constitution` with its
/// per-share voting multiplier (`votesPerShare`) and conversion ratio (`conversionNumer / conversionDenom`)
/// to Common Shares.
/// Requires a finalized `POLICY_SUPER_GOVERNANCE` `Authorization` HPS object (or initial bootstrap
/// by an active Director when `superAuth == 0x0` for a newly registered share class).
fn handle_register_share_class(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let votes_per_share = args.u64(1).ok_or(-3)?;
    let conversion_numer = args.u64(2).ok_or(-3)?;
    let conversion_denom = args.u64(3).ok_or(-3)?;
    let super_auth = args.address(4).ok_or(-3)?;

    if share_ledger == [0u8; 20] || conversion_numer == 0 || conversion_denom == 0 {
        return Err(-59);
    }

    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);
    let mut existing_idx: Option<usize> = None;
    let mut i = 0;
    while i < count {
        if classes[i].ledger == share_ledger {
            existing_idx = Some(i);
            break;
        }
        i += 1;
    }

    if super_auth == [0u8; 20] && existing_idx.is_none() {
        let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let dcount = load_directors(&mut dirs);
        let mut is_dir = false;
        let mut d = 0;
        while d < dcount {
            if dirs[d] == caller {
                is_dir = true;
                break;
            }
            d += 1;
        }
        if !is_dir && dcount > 0 {
            return Err(-61);
        }
    } else {
        let action_hash = compute_register_share_class_hash(
            &share_ledger,
            votes_per_share,
            conversion_numer,
            conversion_denom,
        );
        let me = context::self_address();
        verify_and_consume_auth(
            &registry,
            &super_auth,
            &me,
            &POLICY_SUPER_GOVERNANCE,
            &action_hash,
            &caller,
        )?;
    }

    let spec = ShareClassSpec {
        ledger: share_ledger,
        votes_per_share,
        conversion_numer,
        conversion_denom,
    };
    let new_count = if let Some(idx) = existing_idx {
        classes[idx] = spec;
        count
    } else {
        if count >= MAX_SHARE_CLASSES {
            return Err(-61);
        }
        classes[count] = spec;
        count + 1
    };
    save_share_classes(&classes, new_count);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&votes_per_share.to_be_bytes());
    ev[8..16].copy_from_slice(&conversion_numer.to_be_bytes());
    ev[16..24].copy_from_slice(&conversion_denom.to_be_bytes());
    events::emit(&[SHARE_CLASS_REGISTERED, addr_topic(&share_ledger)], &ev);

    ret::write_u64_word(new_count as u64);
    Ok(())
}

fn handle_share_class_count(_args: &CalldataReader) -> Result<(), i32> {
    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);
    ret::write_u64_word(count as u64);
    Ok(())
}

fn handle_get_share_class(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);
    if idx >= count {
        return Err(-62);
    }
    let c = &classes[idx];
    let mut out = [0u8; 128];
    out[12..32].copy_from_slice(&c.ledger);
    out[56..64].copy_from_slice(&c.votes_per_share.to_be_bytes());
    out[88..96].copy_from_slice(&c.conversion_numer.to_be_bytes());
    out[120..128].copy_from_slice(&c.conversion_denom.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Tabulate a shareholder's combined voting power and converted common-share equivalent across ALL
/// share-class `AssetLedger`s registered with this `Constitution`:
/// Returns `(voterVotingPower, totalCompanyVotingPower, requiredSuperMajorityPower, voterConvertedCommonShares)`.
fn handle_shareholder_voting_power(args: &CalldataReader) -> Result<(), i32> {
    let voter = args.address(0).ok_or(-3)?;
    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);

    let mut voter_power = 0u64;
    let mut total_power = 0u64;
    let mut voter_common = 0u64;

    let mut i = 0;
    while i < count {
        let c = &classes[i];
        let bal_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(&voter);
        let bal = call::call_u64(&c.ledger, bal_cd.as_slice()).unwrap_or(0);
        let sup_cd = CallEncoder::<16>::new(const { selector("totalOutstanding()") });
        let supply = call::call_u64(&c.ledger, sup_cd.as_slice()).unwrap_or(0);

        voter_power = voter_power.saturating_add(c.voting_power(bal));
        total_power = total_power.saturating_add(c.voting_power(supply));
        voter_common = voter_common.saturating_add(c.converted_common_shares(bal));
        i += 1;
    }

    // 75% super-majority threshold rounded up: ceil(0.75 * total_power)
    let required_supermajority = if total_power == 0 {
        0
    } else {
        (total_power.saturating_mul(75).saturating_add(99)) / 100
    };

    let mut out = [0u8; 128];
    out[24..32].copy_from_slice(&voter_power.to_be_bytes());
    out[56..64].copy_from_slice(&total_power.to_be_bytes());
    out[88..96].copy_from_slice(&required_supermajority.to_be_bytes());
    out[120..128].copy_from_slice(&voter_common.to_be_bytes());
    ret::write(&out);
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

fn handle_hash_add_director(args: &CalldataReader) -> Result<(), i32> {
    let director = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_add_director_hash(&director));
    Ok(())
}

fn handle_hash_remove_director(args: &CalldataReader) -> Result<(), i32> {
    let director = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_remove_director_hash(&director));
    Ok(())
}

fn handle_hash_set_bank_oracle(args: &CalldataReader) -> Result<(), i32> {
    let bank_ledger = args.address(0).ok_or(-3)?;
    let oracle_identity = args.address(1).ok_or(-3)?;
    let expiry_blocks = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_set_bank_oracle_hash(
        &bank_ledger,
        &oracle_identity,
        expiry_blocks,
    ));
    Ok(())
}

fn handle_hash_set_product_oracle(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let oracle_identity = args.address(1).ok_or(-3)?;
    let expiry_blocks = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_set_product_oracle_hash(
        &product_ledger,
        &oracle_identity,
        expiry_blocks,
    ));
    Ok(())
}

fn handle_hash_set_clearing_account(args: &CalldataReader) -> Result<(), i32> {
    let bank_ledger = args.address(0).ok_or(-3)?;
    let clearing_account = args.address(1).ok_or(-3)?;
    ret::write_word(&compute_set_clearing_account_hash(
        &bank_ledger,
        &clearing_account,
    ));
    Ok(())
}

fn handle_hash_register_share_class(args: &CalldataReader) -> Result<(), i32> {
    let share_ledger = args.address(0).ok_or(-3)?;
    let votes_per_share = args.u64(1).ok_or(-3)?;
    let conversion_numer = args.u64(2).ok_or(-3)?;
    let conversion_denom = args.u64(3).ok_or(-3)?;
    ret::write_word(&compute_register_share_class_hash(
        &share_ledger,
        votes_per_share,
        conversion_numer,
        conversion_denom,
    ));
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
            if sel == const { selector("isValidIdentity(address)") } {
                let a = args.address(0).unwrap();
                ret::write_bool(a[0] != 0xEE && a != [0u8; 20]);
                return 0;
            }
            if sel == const { selector("isValidAuthorizationHps(address)") } {
                let a = args.address(0).unwrap();
                ret::write_bool(hps_sdk::context::code_hash_of(&a).is_some());
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
        cd.extend_from_slice(&const { selector("initialize(address,bytes)") });
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
        let get_cd = CallEncoder::<96>::new(const { selector("getPolicyRaw(address,bytes32)") })
            .push_address(&ledger)
            .push_bytes32(&ACTION_ISSUE);
        let ret_bytes = mock::transact_as(board_1, con, get_cd.as_slice()).unwrap();
        let rlen = u64::from_be_bytes(ret_bytes[56..64].try_into().unwrap()) as usize;
        let decoded = PolicySpec::decode(&ret_bytes[64..64 + rlen]).unwrap();
        assert_eq!(decoded, issue_spec);
    }

    #[test]
    fn add_and_remove_directors_with_shareholder_supermajority() {
        use hps_sdk::governance::POLICY_BOARD_RESOLUTION;

        mod auth_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("arm(bytes32)") } {
                    storage::set(b"hash", &args.bytes32(0).unwrap());
                    storage::set_u64(b"used", 0);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    if storage::get_u64(b"used") != 0 {
                        return -68;
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

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let manogaran = [0xA1; 20];
        let evelyn = [0xA2; 20];
        let third_dir = [0xA3; 20];
        let auth_add = [0xC1; 20];
        let auth_rem = [0xC2; 20];

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con, dispatch_calldata);
        mock::register_hps(auth_add, auth_stub::dispatch);
        mock::register_hps(auth_rem, auth_stub::dispatch);

        let super_spec = PolicySpec::new(100)
            .add_stage(StageSpec::new(75_000, 50).add_member(manogaran, 75_000).unwrap())
            .unwrap();
        let board_spec = PolicySpec::new(100)
            .add_stage(
                StageSpec::new(2, 50)
                    .add_member(manogaran, 1)
                    .unwrap()
                    .add_member(evelyn, 1)
                    .unwrap(),
            )
            .unwrap();

        let mut buf_s = [0u8; 512];
        let len_s = super_spec.encode(&mut buf_s).unwrap();
        let mut buf_b = [0u8; 512];
        let len_b = board_spec.encode(&mut buf_b).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(&2u16.to_be_bytes());
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&POLICY_SUPER_GOVERNANCE);
        blob.extend_from_slice(&(len_s as u16).to_be_bytes());
        blob.extend_from_slice(&buf_s[..len_s]);
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&POLICY_BOARD_RESOLUTION);
        blob.extend_from_slice(&(len_b as u16).to_be_bytes());
        blob.extend_from_slice(&buf_b[..len_b]);

        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("initialize(address,bytes)") });
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
        mock::transact_as(manogaran, con, &cd).unwrap();

        let dir_count = || -> u64 {
            let out = mock::transact_as(
                manogaran,
                con,
                CallEncoder::<16>::new(const { selector("directorCount()") }).as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };
        assert_eq!(dir_count(), 2);

        // Add 3rd director via Shareholder Super-Majority resolution
        let h_add: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("hashAddDirector(address)") })
                .push_address(&third_dir)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            auth_add,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_add)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("addDirector(address,address)") })
                .push_address(&third_dir)
                .push_address(&auth_add)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(dir_count(), 3);

        // Remove 3rd director via Shareholder Super-Majority resolution
        let h_rem: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("hashRemoveDirector(address)") })
                .push_address(&third_dir)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            auth_rem,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_rem)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("removeDirector(address,address)") })
                .push_address(&third_dir)
                .push_address(&auth_rem)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(dir_count(), 2);
    }

    #[test]
    fn bank_oracles_clearing_escrow_same_step_cancellation_and_multiclass_voting() {
        use hps_sdk::governance::{
            ERR_WRONG_AUCTION_STEP, POLICY_BANK_ORACLE, POLICY_BOARD_RESOLUTION,
        };

        mod auth_stub_2 {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::ERR_WRONG_AUCTION_STEP;
            use hps_sdk::{context, ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("arm(bytes32)") } {
                    storage::set(b"hash", &args.bytes32(0).unwrap());
                    storage::set_u64(b"used", 0);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    if storage::get_u64(b"used") != 0 {
                        return -68;
                    }
                    if args.bytes32(2).unwrap() != storage::get_bytes32(b"hash").unwrap() {
                        return -67;
                    }
                    storage::set_u64(b"used", 1);
                    ret::write_bool(true);
                    return 0;
                }
                if sel == const { selector("setTarget(address)") } {
                    storage::set_address(b"target", &args.address(0).unwrap());
                    return 0;
                }
                if sel == const { selector("targetHps()") } {
                    ret::write_address(&storage::get_address(b"target").unwrap_or([0u8; 20]));
                    return 0;
                }
                if sel == const { selector("placeBuyOrderFor(address,uint64,uint64)") } {
                    let price = args.u64(1).unwrap();
                    let qty = args.u64(2).unwrap();
                    let idx = storage::get_u64(b"cnt");
                    storage::set_u64(b"cnt", idx + 1);
                    storage::set_u64(b"o_price", price);
                    storage::set_u64(b"o_qty", qty);
                    storage::set_u64(b"o_blk", context::block_number());
                    ret::write_u64_word(idx);
                    return 0;
                }
                if sel == const { selector("cancelBuyOrderFor(address,uint64)") } {
                    let now = context::block_number();
                    if now > 110 {
                        return ERR_WRONG_AUCTION_STEP;
                    }
                    let mut out = [0u8; 64];
                    out[24..32].copy_from_slice(&storage::get_u64(b"o_price").to_be_bytes());
                    out[56..64].copy_from_slice(&storage::get_u64(b"o_qty").to_be_bytes());
                    ret::write(&out);
                    return 0;
                }
                -2
            }
        }

        mod ledger_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::storage::KeyBuilder;
            use hps_sdk::{ret, selector, storage};
            fn bkey(id: &[u8; 20]) -> KeyBuilder<32> {
                KeyBuilder::<32>::new().push(b"b:").push(id)
            }
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("setBal(address,uint64,uint64)") } {
                    let id = args.address(0).unwrap();
                    let bal = args.u64(1).unwrap();
                    let sup = args.u64(2).unwrap();
                    storage::set_u64(bkey(&id).as_slice(), bal);
                    storage::set_u64(b"sup", sup);
                    return 0;
                }
                if sel == const { selector("balanceOf(address)") } {
                    let id = args.address(0).unwrap();
                    ret::write_u64_word(storage::get_u64(bkey(&id).as_slice()));
                    return 0;
                }
                if sel == const { selector("totalOutstanding()") } {
                    ret::write_u64_word(storage::get_u64(b"sup"));
                    return 0;
                }
                if sel == const { selector("constitutionClearTransfer(address,address,uint64)") } {
                    let from = args.address(0).unwrap();
                    let to = args.address(1).unwrap();
                    let amt = args.u64(2).unwrap();
                    let fbal = storage::get_u64(bkey(&from).as_slice());
                    if fbal < amt {
                        return -16;
                    }
                    storage::set_u64(bkey(&from).as_slice(), fbal - amt);
                    let tbal = storage::get_u64(bkey(&to).as_slice());
                    storage::set_u64(bkey(&to).as_slice(), tbal + amt);
                    ret::write_bool(true);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let manogaran = [0xA1; 20];
        let evelyn = [0xA2; 20];
        let bank_oracle_1 = [0xB1; 20];
        let clearing_acct = [0xB9; 20];
        let buyer_1 = [0xD1; 20];
        let seller_1 = [0xD2; 20];
        let bank_ledger = [0x50; 20];
        let common_ledger = [0x51; 20];
        let pref_a_ledger = [0x52; 20];
        let class_b_ledger = [0x53; 20];
        let non_voting_ledger = [0x54; 20];
        let board_auth_1 = [0xC1; 20];
        let auc_auth = [0xC2; 20];

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con, dispatch_calldata);
        mock::register_hps(board_auth_1, auth_stub_2::dispatch);
        mock::register_hps(auc_auth, auth_stub_2::dispatch);
        mock::register_hps(bank_ledger, ledger_stub::dispatch);
        mock::register_hps(common_ledger, ledger_stub::dispatch);
        mock::register_hps(pref_a_ledger, ledger_stub::dispatch);
        mock::register_hps(class_b_ledger, ledger_stub::dispatch);
        mock::register_hps(non_voting_ledger, ledger_stub::dispatch);

        let super_spec = PolicySpec::new(100)
            .add_stage(StageSpec::new(75_000, 50).add_member(manogaran, 75_000).unwrap())
            .unwrap();
        let board_spec = PolicySpec::new(100)
            .add_stage(
                StageSpec::new(2, 50)
                    .add_member(manogaran, 1)
                    .unwrap()
                    .add_member(evelyn, 1)
                    .unwrap(),
            )
            .unwrap();
        let mut buf_s = [0u8; 512];
        let len_s = super_spec.encode(&mut buf_s).unwrap();
        let mut buf_b = [0u8; 512];
        let len_b = board_spec.encode(&mut buf_b).unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u16.to_be_bytes());
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&POLICY_SUPER_GOVERNANCE);
        blob.extend_from_slice(&(len_s as u16).to_be_bytes());
        blob.extend_from_slice(&buf_s[..len_s]);
        blob.extend_from_slice(&[0u8; 20]);
        blob.extend_from_slice(&POLICY_BOARD_RESOLUTION);
        blob.extend_from_slice(&(len_b as u16).to_be_bytes());
        blob.extend_from_slice(&buf_b[..len_b]);

        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("initialize(address,bytes)") });
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
        mock::transact_as(manogaran, con, &cd).unwrap();

        // 1. Board Resolution sets bank oracle `bank_oracle_1` on `bank_ledger`
        let h_ora: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<128>::new(const { selector("hashSetBankOracle(address,address,uint64)") })
                .push_address(&bank_ledger)
                .push_address(&bank_oracle_1)
                .push_u64(40)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            board_auth_1,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_ora)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<160>::new(const { selector("setBankOracle(address,address,uint64,address)") })
            .push_address(&bank_ledger)
            .push_address(&bank_oracle_1)
            .push_u64(40)
            .push_address(&board_auth_1)
            .as_slice(),
        )
        .unwrap();

        // Verify `bankOracleOf(bank_ledger) == bank_oracle_1` and `(bank_ledger, POLICY_BANK_ORACLE)` is active
        let ora_out = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("bankOracleOf(address)") })
                .push_address(&bank_ledger)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&ora_out[12..32], &bank_oracle_1);
        let has_pol = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("hasPolicy(address,bytes32)") })
                .push_address(&bank_ledger)
                .push_bytes32(&POLICY_BANK_ORACLE)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(has_pol[31], 1);

        // 2. Configure Constitution's special clearing account & fund buyer_1 with 500,000 in bank_ledger
        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<128>::new(const { selector("setClearingAccount(address,address,address)") })
                .push_address(&bank_ledger)
                .push_address(&clearing_acct)
                .push_address(&[0u8; 20])
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            bank_ledger,
            CallEncoder::<128>::new(const { selector("setBal(address,uint64,uint64)") })
                .push_address(&buyer_1)
                .push_u64(500_000)
                .push_u64(500_000)
                .as_slice(),
        )
        .unwrap();

        let bank_bal = |who: [u8; 20]| -> u64 {
            let out = mock::transact_as(
                manogaran,
                bank_ledger,
                CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                    .push_address(&who)
                    .as_slice(),
            )
            .unwrap();
            u64::from_be_bytes(out[24..32].try_into().unwrap())
        };

        // 3. Placing a buy order exceeding buyer_1's bank balance (6,000 shares @ 100 = 600,000 > 500,000) MUST fail!
        mock::set_block_number(100);
        assert_eq!(
            mock::transact_as(
                buyer_1,
                con,
                CallEncoder::<128>::new(const { selector("placeBuyOrder(address,uint64,uint64)") })
                    .push_address(&auc_auth)
                    .push_u64(100)
                    .push_u64(6_000)
                    .as_slice(),
            ),
            Err(-16)
        );
        assert_eq!(bank_bal(buyer_1), 500_000);
        assert_eq!(bank_bal(clearing_acct), 0);

        // Placing a valid buy order (3,000 shares @ 100 = 300,000) clears 300,000 into clearing_acct
        mock::transact_as(
            buyer_1,
            con,
            CallEncoder::<128>::new(const { selector("placeBuyOrder(address,uint64,uint64)") })
                .push_address(&auc_auth)
                .push_u64(100)
                .push_u64(3_000)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bank_bal(buyer_1), 200_000);
        assert_eq!(bank_bal(clearing_acct), 300_000);

        // Cancelling in the SAME step (block 105 <= 110) refunds 300,000 back to buyer_1!
        mock::set_block_number(105);
        mock::transact_as(
            buyer_1,
            con,
            CallEncoder::<96>::new(const { selector("cancelBuyOrder(address,uint64)") })
                .push_address(&auc_auth)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bank_bal(buyer_1), 500_000);
        assert_eq!(bank_bal(clearing_acct), 0);

        // Place another buy order (4,000 shares @ 100 = 400,000), then advance past Step 1 (block 115 > 110):
        // Cancelling a Step 1 order in Step 2 MUST fail with ERR_WRONG_AUCTION_STEP (-74)!
        mock::set_block_number(108);
        mock::transact_as(
            buyer_1,
            con,
            CallEncoder::<128>::new(const { selector("placeBuyOrder(address,uint64,uint64)") })
                .push_address(&auc_auth)
                .push_u64(100)
                .push_u64(4_000)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(bank_bal(buyer_1), 100_000);
        assert_eq!(bank_bal(clearing_acct), 400_000);

        mock::set_block_number(115);
        assert_eq!(
            mock::transact_as(
                buyer_1,
                con,
                CallEncoder::<96>::new(const { selector("cancelBuyOrder(address,uint64)") })
                    .push_address(&auc_auth)
                    .push_u64(1)
                    .as_slice(),
            ),
            Err(ERR_WRONG_AUCTION_STEP)
        );

        // Settle cash via disburseAuctionCash from the bound `common_ledger`
        mock::transact_as(
            manogaran,
            auc_auth,
            CallEncoder::<64>::new(const { selector("setTarget(address)") })
                .push_address(&common_ledger)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            common_ledger,
            con,
            CallEncoder::<160>::new(const { selector("disburseAuctionCash(address,address,uint64,bool)") })
            .push_address(&auc_auth)
            .push_address(&seller_1)
            .push_u64(400_000)
            .push_bool(true)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(bank_bal(seller_1), 400_000);
        assert_eq!(bank_bal(clearing_acct), 0);

        // 4. Multi-Class Share Ledgers & Cross-Ledger Voting Power Tabulation:
        // - Common Shares (`common_ledger`): 1 vote/share, 1:1 conversion (total 100,000, Manogaran holds 50,000)
        // - Preferred Series A (`pref_a_ledger`): 1 vote/converted common share, 2:1 conversion (total 20,000 -> 40,000 votes, Evelyn holds 20,000 -> 40,000 votes)
        // - Class B Founders (`class_b_ledger`): 10 votes/share, 1:1 conversion (total 6,000 -> 60,000 votes, Manogaran holds 6,000 -> 60,000 votes)
        // - Non-Voting Preferred (`non_voting_ledger`): 0 votes/share, 1:1 conversion (total 50,000 -> 0 votes, Buyer 1 holds 50,000 -> 0 votes)
        // Total company voting power = 100,000 + 40,000 + 60,000 + 0 = 200,000 votes!
        // 75% Super-Majority threshold = 150,000 votes!
        // Manogaran's voting power = 50,000 (Common) + 60,000 (Class B) = 110,000 votes (55%), converted common = 56,000
        // Evelyn's voting power = 40,000 (Preferred A) = 40,000 votes (20%), converted common = 40,000
        // Together Manogaran + Evelyn = 150,000 votes = exact 75% super-majority!
        for (led, vps, cn, cd_denom) in [
            (common_ledger, 1u64, 1u64, 1u64),
            (pref_a_ledger, 1u64, 2u64, 1u64),
            (class_b_ledger, 10u64, 1u64, 1u64),
            (non_voting_ledger, 0u64, 1u64, 1u64),
        ] {
            mock::transact_as(
                manogaran,
                con,
                CallEncoder::<192>::new(const { selector("registerShareClass(address,uint64,uint64,uint64,address)") })
                .push_address(&led)
                .push_u64(vps)
                .push_u64(cn)
                .push_u64(cd_denom)
                .push_address(&[0u8; 20])
                .as_slice(),
            )
            .unwrap();
        }
        mock::transact_as(
            manogaran,
            common_ledger,
            CallEncoder::<128>::new(const { selector("setBal(address,uint64,uint64)") })
                .push_address(&manogaran)
                .push_u64(50_000)
                .push_u64(100_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            pref_a_ledger,
            CallEncoder::<128>::new(const { selector("setBal(address,uint64,uint64)") })
                .push_address(&evelyn)
                .push_u64(20_000)
                .push_u64(20_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            class_b_ledger,
            CallEncoder::<128>::new(const { selector("setBal(address,uint64,uint64)") })
                .push_address(&manogaran)
                .push_u64(6_000)
                .push_u64(6_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            non_voting_ledger,
            CallEncoder::<128>::new(const { selector("setBal(address,uint64,uint64)") })
                .push_address(&buyer_1)
                .push_u64(50_000)
                .push_u64(50_000)
                .as_slice(),
        )
        .unwrap();

        let mano_vp = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("shareholderVotingPower(address)") })
                .push_address(&manogaran)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(mano_vp[24..32].try_into().unwrap()), 110_000);
        assert_eq!(u64::from_be_bytes(mano_vp[56..64].try_into().unwrap()), 200_000);
        assert_eq!(u64::from_be_bytes(mano_vp[88..96].try_into().unwrap()), 150_000);
        assert_eq!(u64::from_be_bytes(mano_vp[120..128].try_into().unwrap()), 56_000);

        let evelyn_vp = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("shareholderVotingPower(address)") })
                .push_address(&evelyn)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(evelyn_vp[24..32].try_into().unwrap()), 40_000);
        assert_eq!(u64::from_be_bytes(evelyn_vp[120..128].try_into().unwrap()), 40_000);

        let buyer_vp = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<64>::new(const { selector("shareholderVotingPower(address)") })
                .push_address(&buyer_1)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(buyer_vp[24..32].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(buyer_vp[120..128].try_into().unwrap()), 50_000);
    }
}
