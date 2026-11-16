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
    oracle_policy_id, require_valid_identity, verify_and_consume_auth, ActionHasher,
    FunctionAuthRule, PolicySpec, ShareClassSpec, StageSpec, ACTION_ACTIVATE_CONSTITUTION,
    ACTION_ADD_DIRECTOR, ACTION_AUTHORIZE_FUTURES_UNDERWRITING, ACTION_DEFINE_ROLE,
    ACTION_GRANT_ROLE, ACTION_REGISTER_SHARE_CLASS, ACTION_REMOVE_DIRECTOR, ACTION_RESTOCK_PRODUCT,
    ACTION_REVOKE_ROLE, ACTION_SET_BANK_ORACLE, ACTION_SET_CLEARING_ACCOUNT,
    ACTION_SET_FUNCTION_AUTH, ACTION_SET_PRODUCT_ORACLE, ACTION_SET_PRODUCT_PRICE,
    ACTION_UPSERT_PRODUCT, CONSTITUTION_STATE_ACTIVE, CONSTITUTION_STATE_PENDING_RATIFICATION,
    CONSTITUTION_STATE_UNINITIALIZED, ERR_AUTH_CONSUME_FAILED, ERR_CONSTITUTION_ALREADY_ACTIVE,
    ERR_CONSTITUTION_NOT_ACTIVE, ERR_FUNCTION_AUTH_NOT_SET, ERR_FUTURES_CAP_EXCEEDED,
    ERR_INVALID_FUTURES_CONFIG, ERR_MISSING_ROLE, ERR_POLICY_INVALID, ERR_ROLE_NOT_DEFINED,
    MAX_DEFINED_ROLES, MAX_ENCODED_POLICY_BYTES, MAX_MEMBERS_PER_STAGE, MAX_SHARE_CLASSES,
    POLICY_BANK_ORACLE, POLICY_BOARD_RESOLUTION, POLICY_FIRST_SHAREHOLDER_RESOLUTION,
    POLICY_PRODUCT_MANAGEMENT, POLICY_PRODUCT_ORACLE, POLICY_SHAREHOLDER_SUPERMAJORITY,
    POLICY_SUPER_GOVERNANCE, ROLE_BANK_ORACLE, ROLE_DIRECTOR, ROLE_PRODUCT_MANAGER,
    ROLE_SHAREHOLDER, ROLE_TREASURY_MANAGER,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const CONSTITUTION_INITIALIZED: [u8; 32] = event_topic("ConstitutionInitialized(address,uint64)");
const CONSTITUTION_ACTIVATED: [u8; 32] =
    event_topic("ConstitutionActivated(address,address,uint64)");
const POLICY_SET: [u8; 32] = event_topic("PolicySet(address,bytes32,uint64,uint64)");
const POLICY_DEACTIVATED: [u8; 32] = event_topic("PolicyDeactivated(address,bytes32)");
const DIRECTOR_ADDED: [u8; 32] = event_topic("DirectorAdded(address,uint64,address)");
const DIRECTOR_REMOVED: [u8; 32] = event_topic("DirectorRemoved(address,uint64,address)");
const ROLE_DEFINED: [u8; 32] = event_topic("RoleDefined(bytes32,address,uint64)");
const ROLE_GRANTED: [u8; 32] = event_topic("RoleGranted(bytes32,address,address,uint64)");
const ROLE_REVOKED: [u8; 32] = event_topic("RoleRevoked(bytes32,address,address,uint64)");
const FUNCTION_AUTH_UPDATED: [u8; 32] =
    event_topic("FunctionAuthUpdated(bytes4,bytes32,bytes32,address)");
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
const FUTURES_UNDERWRITING_AUTHORIZED: [u8; 32] =
    event_topic("FuturesUnderwritingAuthorized(address,uint64,uint64,address)");
const FUTURES_UNDERWRITTEN: [u8; 32] =
    event_topic("FuturesUnderwritten(address,address,uint64,uint64,uint64)");
const FUTURES_CLOSED: [u8; 32] =
    event_topic("FuturesClosed(address,address,uint64,uint64)");

const TAG_SET_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_SET_POLICY");
const TAG_DEACTIVATE_POLICY: [u8; 32] = keccak256(b"CONSTITUTION_DEACTIVATE_POLICY");

const SEL_ACTIVATE_CONSTITUTION: [u8; 4] = selector("activateConstitution(address)");
const SEL_SET_FUNCTION_AUTH: [u8; 4] = selector("setFunctionAuth(bytes4,bytes32,address)");
const SEL_DEFINE_ROLE: [u8; 4] = selector("defineRole(bytes32,address)");
const SEL_SET_POLICY: [u8; 4] = selector("setPolicy(address,bytes32,bytes,address)");
const SEL_DEACTIVATE_POLICY: [u8; 4] = selector("deactivatePolicy(address,bytes32,address)");
const SEL_ADD_DIRECTOR: [u8; 4] = selector("addDirector(address,address)");
const SEL_REMOVE_DIRECTOR: [u8; 4] = selector("removeDirector(address,address)");
const SEL_GRANT_ROLE: [u8; 4] = selector("grantRole(bytes32,address,address)");
const SEL_REVOKE_ROLE: [u8; 4] = selector("revokeRole(bytes32,address,address)");
const SEL_UPSERT_PRODUCT: [u8; 4] =
    selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)");
const SEL_RESTOCK_PRODUCT: [u8; 4] =
    selector("restockProduct(address,bytes32,uint64,uint64,address)");
const SEL_SET_PRODUCT_PRICE: [u8; 4] = selector("setProductPrice(address,bytes32,uint64,address)");
const SEL_SET_BANK_ORACLE: [u8; 4] = selector("setBankOracle(address,address,uint64,address)");
const SEL_SET_PRODUCT_ORACLE: [u8; 4] =
    selector("setProductOracle(address,address,uint64,address)");
const SEL_SET_CLEARING_ACCOUNT: [u8; 4] = selector("setClearingAccount(address,address,address)");
const SEL_REGISTER_SHARE_CLASS: [u8; 4] =
    selector("registerShareClass(address,uint64,uint64,uint64,address)");
const SEL_AUTHORIZE_FUTURES: [u8; 4] =
    selector("authorizeFuturesUnderwriting(address,uint64,address)");

const KEY_INIT: &[u8] = b"con:init";
const KEY_STATE: &[u8] = b"con:state";
const KEY_STRICT_FN_AUTH: &[u8] = b"con:strict_fn";
const KEY_ACTIVATED_BLOCK: &[u8] = b"con:act_blk";
const KEY_ACTIVATION_AUTH: &[u8] = b"con:act_auth";
const KEY_DEFINED_ROLES_COUNT: &[u8] = b"con:role_cnt";
const KEY_REGISTRY: &[u8] = b"con:reg";
const KEY_DIRECTORS_BLOB: &[u8] = b"con:directors";
const KEY_BOARD_EXPIRY: &[u8] = b"con:board_exp";
const KEY_CLEARING_ACCOUNT: &[u8] = b"con:clear_acct";
const KEY_DEFAULT_BANK_LEDGER: &[u8] = b"con:bank_led";
const KEY_SHARE_CLASSES_BLOB: &[u8] = b"con:sh_classes";
const KEY_FUTURES_LEDGER: &[u8] = b"con:fut_led";
const KEY_FUTURES_PCT: &[u8] = b"con:fut_pct";

hps_entry! {
    "initialize(address,bytes)"                                           => handle_initialize,
    "initializeWithGovernance(address,bytes,bytes,bytes,bytes)"           => handle_initialize_with_governance,
    "activateConstitution(address)"                                       => handle_activate_constitution,
    "state()"                                                             => handle_state,
    "isActive()"                                                          => handle_is_active,
    "isValid()"                                                           => handle_is_active,
    "activatedAtBlock()"                                                  => handle_activated_at_block,
    "setFunctionAuth(bytes4,bytes32,address)"                             => handle_set_function_auth,
    "getFunctionAuth(bytes4)"                                             => handle_get_function_auth,
    "defineRole(bytes32,address)"                                         => handle_define_role,
    "isRoleDefined(bytes32)"                                              => handle_is_role_defined,
    "definedRoleCount()"                                                  => handle_defined_role_count,
    "definedRoleAt(uint64)"                                               => handle_defined_role_at,
    "setPolicy(address,bytes32,bytes,address)"                            => handle_set_policy,
    "deactivatePolicy(address,bytes32,address)"                           => handle_deactivate_policy,
    "addDirector(address,address)"                                        => handle_add_director,
    "removeDirector(address,address)"                                     => handle_remove_director,
    "isDirector(address)"                                                 => handle_is_director,
    "directorCount()"                                                     => handle_director_count,
    "grantRole(bytes32,address,address)"                                  => handle_grant_role,
    "revokeRole(bytes32,address,address)"                                 => handle_revoke_role,
    "hasRole(bytes32,address)"                                            => handle_has_role,
    "roleMemberCount(bytes32)"                                            => handle_role_member_count,
    "roleMemberAt(bytes32,uint64)"                                        => handle_role_member_at,
    "upsertProduct(address,bytes32,uint64,uint64,bytes,address)"          => handle_con_upsert_product,
    "restockProduct(address,bytes32,uint64,uint64,address)"               => handle_con_restock_product,
    "setProductPrice(address,bytes32,uint64,address)"                     => handle_con_set_product_price,
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
    "authorizeFuturesUnderwriting(address,uint64,address)"                => handle_authorize_futures_underwriting,
    "underwriteFutures(uint64)"                                           => handle_underwrite_futures,
    "closeUnderwrittenFutures(uint64)"                                    => handle_close_underwritten_futures,
    "futuresLedger()"                                                     => handle_futures_ledger,
    "futuresUnderwritePct()"                                              => handle_futures_underwrite_pct,
    "futuresUnderwrittenBy(address)"                                      => handle_futures_underwritten_by,
    "futuresAllowanceOf(address)"                                         => handle_futures_allowance_of,
    "getPolicyRaw(address,bytes32)"                                       => handle_get_policy_raw,
    "hasPolicy(address,bytes32)"                                          => handle_has_policy,
    "identityRegistry()"                                                  => handle_identity_registry,
    "hashActivateConstitution()"                                          => handle_hash_activate_constitution,
    "hashSetFunctionAuth(bytes4,bytes32)"                                 => handle_hash_set_function_auth,
    "hashDefineRole(bytes32)"                                             => handle_hash_define_role,
    "hashSetPolicy(address,bytes32,bytes)"                                => handle_hash_set_policy,
    "hashDeactivatePolicy(address,bytes32)"                               => handle_hash_deactivate_policy,
    "hashAddDirector(address)"                                            => handle_hash_add_director,
    "hashRemoveDirector(address)"                                         => handle_hash_remove_director,
    "hashGrantRole(bytes32,address)"                                      => handle_hash_grant_role,
    "hashRevokeRole(bytes32,address)"                                     => handle_hash_revoke_role,
    "hashConUpsertProduct(address,bytes32,uint64,uint64,bytes)"           => handle_hash_con_upsert_product,
    "hashConRestockProduct(address,bytes32,uint64,uint64)"                => handle_hash_con_restock_product,
    "hashConSetProductPrice(address,bytes32,uint64)"                     => handle_hash_con_set_product_price,
    "hashSetBankOracle(address,address,uint64)"                           => handle_hash_set_bank_oracle,
    "hashSetProductOracle(address,address,uint64)"                        => handle_hash_set_product_oracle,
    "hashSetClearingAccount(address,address)"                             => handle_hash_set_clearing_account,
    "hashRegisterShareClass(address,uint64,uint64,uint64)"                => handle_hash_register_share_class,
    "hashAuthorizeFuturesUnderwriting(address,uint64)"                    => handle_hash_authorize_futures_underwriting,
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

fn fn_auth_key(fn_selector: &[u8; 4]) -> KeyBuilder<16> {
    KeyBuilder::<16>::new().push(b"fnau:").push(fn_selector)
}

fn fn_explicit_key(fn_selector: &[u8; 4]) -> KeyBuilder<16> {
    KeyBuilder::<16>::new().push(b"fnex:").push(fn_selector)
}

fn store_function_auth(fn_selector: &[u8; 4], policy_id: &[u8; 32], explicit: bool) {
    storage::set(fn_auth_key(fn_selector).as_slice(), policy_id);
    if explicit {
        storage::set_u64(fn_explicit_key(fn_selector).as_slice(), 1);
    }
}

fn get_function_auth(fn_selector: &[u8; 4]) -> Option<[u8; 32]> {
    storage::get_bytes32(fn_auth_key(fn_selector).as_slice())
}

fn require_function_auth(fn_selector: &[u8; 4]) -> Result<[u8; 32], i32> {
    get_function_auth(fn_selector).ok_or(ERR_FUNCTION_AUTH_NOT_SET)
}

fn is_fn_auth_explicit(fn_selector: &[u8; 4]) -> bool {
    storage::get_u64(fn_explicit_key(fn_selector).as_slice()) == 1
        || storage::get_u64(KEY_STRICT_FN_AUTH) == 1
}

fn policy_exists_for(me: &[u8; 20], policy_id: &[u8; 32]) -> bool {
    storage::exists(policy_key(me, policy_id).as_slice())
        || storage::exists(policy_key(&[0u8; 20], policy_id).as_slice())
}

fn role_defined_key(role_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rdef:").push(role_id)
}

fn defined_role_at_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"ridx:")
        .push_u64_be(idx)
}

fn is_role_defined(role_id: &[u8; 32]) -> bool {
    *role_id != [0u8; 32] && storage::get_u64(role_defined_key(role_id).as_slice()) == 1
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
        // Every role required by any stage MUST already be defined in this Constitution!
        let mut r = 0;
        while r < st.role_count {
            if !is_role_defined(&st.roles[r].role_id) {
                return Err(ERR_ROLE_NOT_DEFINED);
            }
            r += 1;
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

fn compute_activate_constitution_hash() -> [u8; 32] {
    ActionHasher::<96>::new(&context::self_address(), &ACTION_ACTIVATE_CONSTITUTION).finish()
}

fn compute_set_function_auth_hash(fn_selector: &[u8; 4], policy_id: &[u8; 32]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_FUNCTION_AUTH)
        .push_raw(fn_selector)
        .push_bytes32(policy_id)
        .finish()
}

fn compute_define_role_hash(role_id: &[u8; 32]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_DEFINE_ROLE)
        .push_bytes32(role_id)
        .finish()
}

fn compute_con_upsert_product_hash(
    product_ledger: &[u8; 20],
    product_id: &[u8; 32],
    units: u64,
    price: u64,
    name: &[u8],
) -> [u8; 32] {
    ActionHasher::<224>::new(&context::self_address(), &ACTION_UPSERT_PRODUCT)
        .push_address(product_ledger)
        .push_bytes32(product_id)
        .push_u64(units)
        .push_u64(price)
        .push_bytes_digest(name)
        .finish()
}

fn compute_con_restock_product_hash(
    product_ledger: &[u8; 20],
    product_id: &[u8; 32],
    units_to_add: u64,
    new_price: u64,
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_RESTOCK_PRODUCT)
        .push_address(product_ledger)
        .push_bytes32(product_id)
        .push_u64(units_to_add)
        .push_u64(new_price)
        .finish()
}

fn compute_con_set_product_price_hash(
    product_ledger: &[u8; 20],
    product_id: &[u8; 32],
    new_price: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_PRODUCT_PRICE)
        .push_address(product_ledger)
        .push_bytes32(product_id)
        .push_u64(new_price)
        .finish()
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

fn compute_grant_role_hash(role_id: &[u8; 32], account: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_GRANT_ROLE)
        .push_bytes32(role_id)
        .push_address(account)
        .finish()
}

fn compute_revoke_role_hash(role_id: &[u8; 32], account: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_REVOKE_ROLE)
        .push_bytes32(role_id)
        .push_address(account)
        .finish()
}

fn compute_authorize_futures_underwriting_hash(
    futures_ledger: &[u8; 20],
    underwrite_pct: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(
        &context::self_address(),
        &ACTION_AUTHORIZE_FUTURES_UNDERWRITING,
    )
    .push_address(futures_ledger)
    .push_u64(underwrite_pct)
    .finish()
}

fn futures_underwritten_key(futures_ledger: &[u8; 20], shareholder: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"fuw:")
        .push(futures_ledger)
        .push(shareholder)
}

/// Apply the authorized futures underwriting percentage (`pct`) to `converted_common_shares`:
/// - `1..=100` is interpreted as whole percentage `pct / 100` (e.g., `10` = `10%`).
/// - `101..=10_000` is interpreted as basis points `pct / 10_000` (e.g., `1_000` = `10.00%`).
fn apply_futures_pct(converted_common_shares: u64, pct: u64) -> u64 {
    if pct == 0 || converted_common_shares == 0 {
        return 0;
    }
    let denom = if pct <= 100 { 100u128 } else { 10_000u128 };
    (((converted_common_shares as u128) * (pct as u128)) / denom) as u64
}

/// Compute `(shareholder_converted_common_shares, company_total_converted_common_shares)` summed
/// across all registered share classes in this `Constitution`.
fn compute_converted_common_totals(shareholder: &[u8; 20]) -> (u64, u64) {
    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);
    let mut holder_common = 0u64;
    let mut total_common = 0u64;
    let mut i = 0;
    while i < count {
        let c = &classes[i];
        if *shareholder != [0u8; 20] {
            let bal_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                .push_address(shareholder);
            let bal = call::call_u64(&c.ledger, bal_cd.as_slice()).unwrap_or(0);
            holder_common = holder_common.saturating_add(c.converted_common_shares(bal));
        }
        let sup_cd = CallEncoder::<16>::new(const { selector("totalOutstanding()") });
        let supply = call::call_u64(&c.ledger, sup_cd.as_slice()).unwrap_or(0);
        total_common = total_common.saturating_add(c.converted_common_shares(supply));
        i += 1;
    }
    (holder_common, total_common)
}

fn role_members_key(role_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rmem:").push(role_id)
}

fn role_has_key(role_id: &[u8; 32], account: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"rhas:")
        .push(role_id)
        .push(account)
}

fn load_role_members(role_id: &[u8; 32], out: &mut [[u8; 20]; MAX_MEMBERS_PER_STAGE]) -> usize {
    let rk = role_members_key(role_id);
    let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
    let Some(n) = storage::get_into(rk.as_slice(), &mut raw) else {
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

/// Define a role in the Constitution (`rdef:<role_id> = 1`) and ensure a role-backed 1-of-N
/// `PolicySpec` (`StageSpec::for_role(*role_id, 1, exp)`) is registered under `([0u8; 20], role_id)`
/// even when `0` identities currently hold `role_id`.
fn define_role_internal(role_id: &[u8; 32], expiry_blocks: u64) -> Result<bool, i32> {
    if *role_id == [0u8; 32] {
        return Err(-59);
    }
    let exp = if expiry_blocks == 0 { 50 } else { expiry_blocks };
    let newly_defined = if !is_role_defined(role_id) {
        let cnt = storage::get_u64(KEY_DEFINED_ROLES_COUNT);
        if (cnt as usize) >= MAX_DEFINED_ROLES {
            return Err(-61);
        }
        storage::set_u64(role_defined_key(role_id).as_slice(), 1);
        storage::set(defined_role_at_key(cnt).as_slice(), role_id);
        storage::set_u64(KEY_DEFINED_ROLES_COUNT, cnt + 1);
        true
    } else {
        false
    };

    // Ensure a role-backed default policy exists under `([0u8; 20], role_id)` if none was set yet
    let pk = policy_key(&[0u8; 20], role_id);
    if !storage::exists(pk.as_slice()) {
        let stage = StageSpec::for_role(*role_id, 1, exp).ok_or(ERR_POLICY_INVALID)?;
        let spec = PolicySpec::new(exp.saturating_mul(2))
            .add_stage(stage)
            .ok_or(ERR_POLICY_INVALID)?;
        let mut enc = [0u8; MAX_ENCODED_POLICY_BYTES];
        let enc_len = spec.encode(&mut enc).ok_or(ERR_POLICY_INVALID)?;
        store_policy(&[0u8; 20], role_id, &enc[..enc_len], &spec);
        if *role_id == ROLE_PRODUCT_MANAGER
            && !storage::exists(policy_key(&[0u8; 20], &POLICY_PRODUCT_ORACLE).as_slice())
        {
            store_policy(&[0u8; 20], &POLICY_PRODUCT_ORACLE, &enc[..enc_len], &spec);
        }
    }
    Ok(newly_defined)
}

fn save_role_members(
    role_id: &[u8; 32],
    members: &[[u8; 20]; MAX_MEMBERS_PER_STAGE],
    count: usize,
) -> Result<(), i32> {
    let rk = role_members_key(role_id);
    if count == 0 {
        storage::set(rk.as_slice(), &[]);
    } else {
        let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
        let mut i = 0;
        while i < count {
            raw[i * 20..(i + 1) * 20].copy_from_slice(&members[i]);
            i += 1;
        }
        storage::set(rk.as_slice(), &raw[..count * 20]);
    }

    // Ensure the role remains defined and its role-backed PolicySpec remains intact even at count == 0
    let exp = {
        let bexp = storage::get_u64(KEY_BOARD_EXPIRY);
        if bexp == 0 { 50 } else { bexp }
    };
    let _ = define_role_internal(role_id, exp)?;
    Ok(())
}

fn grant_role_internal(role_id: &[u8; 32], account: &[u8; 20]) -> Result<usize, i32> {
    if !is_role_defined(role_id) {
        return Err(ERR_ROLE_NOT_DEFINED);
    }
    let mut members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_role_members(role_id, &mut members);
    let mut i = 0;
    while i < count {
        if &members[i] == account {
            storage::set_u64(role_has_key(role_id, account).as_slice(), 1);
            return Ok(count);
        }
        i += 1;
    }
    if count >= MAX_MEMBERS_PER_STAGE {
        return Err(-61);
    }
    members[count] = *account;
    let new_count = count + 1;
    storage::set_u64(role_has_key(role_id, account).as_slice(), 1);
    save_role_members(role_id, &members, new_count)?;
    Ok(new_count)
}

fn has_active_role(registry: &[u8; 20], role_id: &[u8; 32], account: &[u8; 20]) -> bool {
    if *account == [0u8; 20] {
        return false;
    }
    if storage::get_u64(role_has_key(role_id, account).as_slice()) != 1 {
        return false;
    }
    require_valid_identity(registry, account).is_ok()
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

fn sync_director_role_members(
    directors: &[[u8; 20]; MAX_MEMBERS_PER_STAGE],
    count: usize,
) -> Result<(), i32> {
    let mut prev_members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let prev_cnt = load_role_members(&ROLE_DIRECTOR, &mut prev_members);
    let mut p = 0;
    while p < prev_cnt {
        storage::set_u64(role_has_key(&ROLE_DIRECTOR, &prev_members[p]).as_slice(), 0);
        p += 1;
    }
    let mut i = 0;
    while i < count {
        storage::set_u64(role_has_key(&ROLE_DIRECTOR, &directors[i]).as_slice(), 1);
        i += 1;
    }
    save_role_members(&ROLE_DIRECTOR, directors, count)
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
    sync_director_role_members(directors, count)?;

    if count > 0 {
        // Preserve custom role-backed POLICY_BOARD_RESOLUTION if one was defined at construction
        let mut existing_buf = [0u8; MAX_ENCODED_POLICY_BYTES];
        let keep_role_backed = if let Some(n) = storage::get_into(
            policy_key(&[0u8; 20], &POLICY_BOARD_RESOLUTION).as_slice(),
            &mut existing_buf,
        ) {
            if let Some(existing_spec) = PolicySpec::decode(&existing_buf[..n]) {
                existing_spec.stage_count > 0 && existing_spec.stages[0].role_count > 0
            } else {
                false
            }
        } else {
            false
        };

        if !keep_role_backed {
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
    }
    Ok(())
}

/// Seed default `fn_selector -> policy_id` mappings for any governed function not yet explicitly
/// configured in `fnau:<selector>`, choosing from policies defined on this `Constitution`.
fn seed_default_function_auths(me: &[u8; 20]) {
    let super_pol = if policy_exists_for(me, &POLICY_SUPER_GOVERNANCE) {
        POLICY_SUPER_GOVERNANCE
    } else if policy_exists_for(me, &POLICY_SHAREHOLDER_SUPERMAJORITY) {
        POLICY_SHAREHOLDER_SUPERMAJORITY
    } else {
        [0u8; 32]
    };

    let activate_pol = if policy_exists_for(me, &POLICY_FIRST_SHAREHOLDER_RESOLUTION) {
        POLICY_FIRST_SHAREHOLDER_RESOLUTION
    } else if policy_exists_for(me, &POLICY_SHAREHOLDER_SUPERMAJORITY) {
        POLICY_SHAREHOLDER_SUPERMAJORITY
    } else {
        super_pol
    };

    let board_pol = if policy_exists_for(me, &POLICY_BOARD_RESOLUTION) {
        POLICY_BOARD_RESOLUTION
    } else {
        super_pol
    };

    let prod_pol = if policy_exists_for(me, &POLICY_PRODUCT_MANAGEMENT) {
        POLICY_PRODUCT_MANAGEMENT
    } else if policy_exists_for(me, &ROLE_PRODUCT_MANAGER) {
        ROLE_PRODUCT_MANAGER
    } else {
        board_pol
    };

    let defaults: [([u8; 4], [u8; 32]); 17] = [
        (SEL_ACTIVATE_CONSTITUTION, activate_pol),
        (SEL_SET_FUNCTION_AUTH, super_pol),
        (SEL_DEFINE_ROLE, super_pol),
        (SEL_SET_POLICY, super_pol),
        (SEL_DEACTIVATE_POLICY, super_pol),
        (SEL_ADD_DIRECTOR, super_pol),
        (SEL_REMOVE_DIRECTOR, super_pol),
        (SEL_REGISTER_SHARE_CLASS, super_pol),
        (SEL_AUTHORIZE_FUTURES, super_pol),
        (SEL_GRANT_ROLE, board_pol),
        (SEL_REVOKE_ROLE, board_pol),
        (SEL_SET_BANK_ORACLE, board_pol),
        (SEL_SET_PRODUCT_ORACLE, board_pol),
        (SEL_SET_CLEARING_ACCOUNT, board_pol),
        (SEL_UPSERT_PRODUCT, prod_pol),
        (SEL_RESTOCK_PRODUCT, prod_pol),
        (SEL_SET_PRODUCT_PRICE, prod_pol),
    ];

    let mut i = 0;
    while i < defaults.len() {
        let (sel, pol) = defaults[i];
        if pol != [0u8; 32] && get_function_auth(&sel).is_none() {
            store_function_auth(&sel, &pol, false);
        }
        i += 1;
    }
}

fn ensure_initialized_any_state_caller() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-57)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, caller))
}

fn ensure_initialized_and_valid_caller() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    if storage::get_u64(KEY_STATE) != CONSTITUTION_STATE_ACTIVE {
        return Err(ERR_CONSTITUTION_NOT_ACTIVE);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-57)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, caller))
}

fn parse_and_store_policies_blob(
    registry: &[u8; 20],
    blob: &[u8],
    verified: &mut [[u8; 20]; MAX_MEMBERS_PER_STAGE],
    verified_len: &mut usize,
) -> Result<(usize, bool), i32> {
    if blob.len() < 2 {
        return Err(-59);
    }
    let count = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    if count == 0 {
        return Err(-59);
    }

    let me = context::self_address();
    let mut has_super_or_sh = false;
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
            validate_and_verify_spec_cached(registry, raw_spec, verified, verified_len)?;
        store_policy(&target_hps, &policy_id, raw_spec, &spec);

        if policy_id == POLICY_BOARD_RESOLUTION && spec.stage_count > 0 {
            let st0 = &spec.stages[0];
            storage::set_u64(KEY_BOARD_EXPIRY, st0.expiry_blocks);
            if st0.member_count > 0 {
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
                sync_director_role_members(&dirs, st0.member_count)?;
            }
        }

        if (policy_id == POLICY_SUPER_GOVERNANCE
            || policy_id == POLICY_SHAREHOLDER_SUPERMAJORITY
            || policy_id == POLICY_FIRST_SHAREHOLDER_RESOLUTION)
            && (target_hps == me || target_hps == [0u8; 20])
        {
            has_super_or_sh = true;
        }
        i += 1;
    }

    if pos != blob.len() {
        return Err(-60);
    }
    Ok((count, has_super_or_sh))
}

/// Genesis initializer (2-argument form with default canonical roles and default per-function
/// authorization mappings).
/// Starts in `CONSTITUTION_STATE_PENDING_RATIFICATION (1)` — a First Shareholder Resolution
/// (`activateConstitution(address)`) MUST be passed to activate this Constitution!
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58); // already initialized
    }
    let registry = args.address(0).ok_or(-3)?;
    let blob = args.dynamic_bytes(1).ok_or(-3)?;
    if registry == [0u8; 20] || blob.len() < 2 {
        return Err(-59);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    // Pre-define canonical corporate & administrative roles at construction (initially 0 members)
    for canonical_role in [
        ROLE_SHAREHOLDER,
        ROLE_DIRECTOR,
        ROLE_PRODUCT_MANAGER,
        ROLE_TREASURY_MANAGER,
        ROLE_BANK_ORACLE,
    ] {
        define_role_internal(&canonical_role, 50)?;
    }

    let mut verified = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    verified[0] = caller;
    let mut verified_len = 1usize;
    let (count, has_super) =
        parse_and_store_policies_blob(&registry, blob, &mut verified, &mut verified_len)?;
    if !has_super {
        return Err(-60);
    }

    let me = context::self_address();
    seed_default_function_auths(&me);

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, CONSTITUTION_STATE_PENDING_RATIFICATION);

    events::emit(
        &[CONSTITUTION_INITIALIZED, addr_topic(&registry)],
        &(count as u64).to_be_bytes(),
    );
    Ok(())
}

/// Full institutional constructor defining at construction:
/// 1. `registry`: `IdentityRegistry` HPS address.
/// 2. `rolesBlob`: `[role_count: u16 BE]` + per role `[role_id: 32B][member_count: u16 BE][members: member_count * 20B]`
///    (`member_count` MAY be `0` so all roles required by authorization processes are defined up front
///    even before identities are assigned to those roles).
/// 3. `policiesBlob`: `[policy_count: u16 BE]` + per policy `[target_hps: 20B][policy_id: 32B][spec_len: u16 BE][spec]`
///    (every `StageRole.role_id` referenced in any stage MUST be defined in `rolesBlob`).
/// 4. `functionAuthsBlob`: `[fn_count: u16 BE]` + `fn_count` × `FunctionAuthRule` (`[fn_selector: 4B][policy_id: 32B]`,
///    specifying for each function which authorization object `policy_id` is required).
/// 5. `shareClassesBlob`: empty `&[]` OR `[class_count: u16 BE]` + `class_count * 44B` (`ShareClassSpec`).
///
/// Leaves the Constitution in `CONSTITUTION_STATE_PENDING_RATIFICATION (1)` (`isActive() == false`)
/// until the First Shareholder Resolution (`activateConstitution(address)`) is passed!
fn handle_initialize_with_governance(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58);
    }
    let registry = args.address(0).ok_or(-3)?;
    let roles_blob = args.dynamic_bytes(1).ok_or(-3)?;
    let policies_blob = args.dynamic_bytes(2).ok_or(-3)?;
    let fn_auths_blob = args.dynamic_bytes(3).ok_or(-3)?;
    let share_classes_blob = args.dynamic_bytes(4).ok_or(-3)?;

    if registry == [0u8; 20] || roles_blob.len() < 2 || policies_blob.len() < 2 {
        return Err(-59);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let mut verified = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    verified[0] = caller;
    let mut verified_len = 1usize;

    // 1. Parse & register all defined roles (even roles with `member_count == 0`!)
    let role_count = u16::from_be_bytes([roles_blob[0], roles_blob[1]]) as usize;
    if role_count == 0 || role_count > MAX_DEFINED_ROLES {
        return Err(-59);
    }
    let mut rpos = 2usize;
    let mut r = 0usize;
    while r < role_count {
        if rpos + 34 > roles_blob.len() {
            return Err(-59);
        }
        let mut role_id = [0u8; 32];
        role_id.copy_from_slice(&roles_blob[rpos..rpos + 32]);
        let m_cnt = u16::from_be_bytes([roles_blob[rpos + 32], roles_blob[rpos + 33]]) as usize;
        rpos += 34;

        if role_id == [0u8; 32]
            || is_role_defined(&role_id)
            || m_cnt > MAX_MEMBERS_PER_STAGE
            || rpos + m_cnt * 20 > roles_blob.len()
        {
            return Err(-59);
        }

        define_role_internal(&role_id, 50)?;

        let mut members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let mut m = 0usize;
        while m < m_cnt {
            let mut acct = [0u8; 20];
            acct.copy_from_slice(&roles_blob[rpos..rpos + 20]);
            rpos += 20;
            if acct == [0u8; 20] {
                return Err(-59);
            }
            let mut dup = false;
            let mut prev = 0;
            while prev < m {
                if members[prev] == acct {
                    dup = true;
                    break;
                }
                prev += 1;
            }
            if dup {
                return Err(-59);
            }

            let mut seen = false;
            let mut k = 0;
            while k < verified_len {
                if verified[k] == acct {
                    seen = true;
                    break;
                }
                k += 1;
            }
            if !seen {
                require_valid_identity(&registry, &acct)?;
                if verified_len < MAX_MEMBERS_PER_STAGE {
                    verified[verified_len] = acct;
                    verified_len += 1;
                }
            }
            members[m] = acct;
            storage::set_u64(role_has_key(&role_id, &acct).as_slice(), 1);
            m += 1;
        }
        save_role_members(&role_id, &members, m_cnt)?;

        if role_id == ROLE_DIRECTOR && m_cnt > 0 {
            let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
            let mut k = 0;
            while k < m_cnt {
                raw[k * 20..(k + 1) * 20].copy_from_slice(&members[k]);
                k += 1;
            }
            storage::set(KEY_DIRECTORS_BLOB, &raw[..m_cnt * 20]);
        }
        r += 1;
    }
    if rpos != roles_blob.len() {
        return Err(-60);
    }

    // 2. Parse & store all authorization object policies (verifying every stage role is defined!)
    let (pol_count, _has_super) =
        parse_and_store_policies_blob(&registry, policies_blob, &mut verified, &mut verified_len)?;

    let me = context::self_address();

    // 3. Parse & store explicit per-function required authorization object mappings
    if !fn_auths_blob.is_empty() {
        if fn_auths_blob.len() < 2 {
            return Err(-59);
        }
        let fn_count = u16::from_be_bytes([fn_auths_blob[0], fn_auths_blob[1]]) as usize;
        if 2 + fn_count * FunctionAuthRule::ENCODED_LEN != fn_auths_blob.len() {
            return Err(-60);
        }
        let mut fpos = 2usize;
        let mut f = 0usize;
        while f < fn_count {
            let rule = FunctionAuthRule::decode(
                &fn_auths_blob[fpos..fpos + FunctionAuthRule::ENCODED_LEN],
            )
            .ok_or(ERR_POLICY_INVALID)?;
            if !policy_exists_for(&me, &rule.policy_id) {
                return Err(ERR_POLICY_INVALID);
            }
            store_function_auth(&rule.fn_selector, &rule.policy_id, true);
            fpos += FunctionAuthRule::ENCODED_LEN;
            f += 1;
        }
    }

    seed_default_function_auths(&me);

    // Ensure both `activateConstitution` and `setFunctionAuth` have valid defined policies
    let act_pol = require_function_auth(&SEL_ACTIVATE_CONSTITUTION)?;
    let gov_pol = require_function_auth(&SEL_SET_FUNCTION_AUTH)?;
    if !policy_exists_for(&me, &act_pol) || !policy_exists_for(&me, &gov_pol) {
        return Err(ERR_POLICY_INVALID);
    }

    // 4. Optional initial share classes (so multi-class shareholders can immediately vote on the
    //    First Shareholder Resolution to activate the Constitution!)
    if !share_classes_blob.is_empty() {
        if share_classes_blob.len() < 2 {
            return Err(-59);
        }
        let sc_count = u16::from_be_bytes([share_classes_blob[0], share_classes_blob[1]]) as usize;
        if sc_count > MAX_SHARE_CLASSES
            || 2 + sc_count * ShareClassSpec::ENCODED_LEN != share_classes_blob.len()
        {
            return Err(-60);
        }
        let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
        let mut spos = 2usize;
        let mut s = 0usize;
        while s < sc_count {
            let spec = ShareClassSpec::decode(
                &share_classes_blob[spos..spos + ShareClassSpec::ENCODED_LEN],
            )
            .ok_or(-59)?;
            if spec.ledger == [0u8; 20] || spec.conversion_numer == 0 || spec.conversion_denom == 0
            {
                return Err(-59);
            }
            classes[s] = spec;
            spos += ShareClassSpec::ENCODED_LEN;
            s += 1;
        }
        save_share_classes(&classes, sc_count);
    }

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_u64(KEY_STRICT_FN_AUTH, 1);
    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, CONSTITUTION_STATE_PENDING_RATIFICATION);

    events::emit(
        &[CONSTITUTION_INITIALIZED, addr_topic(&registry)],
        &(pol_count as u64).to_be_bytes(),
    );
    Ok(())
}

/// Pass the **First Shareholder Resolution** to ratify and activate a newly created `Constitution`,
/// transitioning its state from `CONSTITUTION_STATE_PENDING_RATIFICATION (1)` to
/// `CONSTITUTION_STATE_ACTIVE (2)`.
fn handle_activate_constitution(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_any_state_caller()?;
    let st = storage::get_u64(KEY_STATE);
    if st == CONSTITUTION_STATE_ACTIVE {
        return Err(ERR_CONSTITUTION_ALREADY_ACTIVE);
    }
    if st != CONSTITUTION_STATE_PENDING_RATIFICATION {
        return Err(ERR_CONSTITUTION_NOT_ACTIVE);
    }

    let shareholder_auth = args.address(0).ok_or(-3)?;
    let req_pol = require_function_auth(&SEL_ACTIVATE_CONSTITUTION)?;
    let action_hash = compute_activate_constitution_hash();
    let me = context::self_address();

    verify_and_consume_auth(
        &registry,
        &shareholder_auth,
        &me,
        &req_pol,
        &action_hash,
        &caller,
    )?;

    let now = context::block_number();
    storage::set_u64(KEY_STATE, CONSTITUTION_STATE_ACTIVE);
    storage::set_u64(KEY_ACTIVATED_BLOCK, now);
    storage::set_address(KEY_ACTIVATION_AUTH, &shareholder_auth);

    events::emit(
        &[
            CONSTITUTION_ACTIVATED,
            addr_topic(&shareholder_auth),
            addr_topic(&caller),
        ],
        &now.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_state(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        ret::write_u64_word(CONSTITUTION_STATE_UNINITIALIZED);
    } else {
        ret::write_u64_word(storage::get_u64(KEY_STATE));
    }
    Ok(())
}

fn handle_is_active(_args: &CalldataReader) -> Result<(), i32> {
    let active =
        storage::get_u64(KEY_INIT) == 1 && storage::get_u64(KEY_STATE) == CONSTITUTION_STATE_ACTIVE;
    ret::write_bool(active);
    Ok(())
}

fn handle_activated_at_block(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ACTIVATED_BLOCK));
    Ok(())
}

/// Update which authorization process (`newPolicyId`) is required to invoke `fnSelector` on this
/// `Constitution`. Calling `setFunctionAuth` itself requires and consumes an `Authorization` object
/// (`authObj`) satisfying `getFunctionAuth(selector("setFunctionAuth(bytes4,bytes32,address)"))`.
fn handle_set_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let fn_selector = args.bytes4(0).ok_or(-3)?;
    let new_policy_id = args.bytes32(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    if fn_selector == [0u8; 4] || new_policy_id == [0u8; 32] {
        return Err(-59);
    }
    let me = context::self_address();
    if !policy_exists_for(&me, &new_policy_id) {
        return Err(ERR_POLICY_INVALID);
    }

    let gov_policy = require_function_auth(&SEL_SET_FUNCTION_AUTH)?;
    let action_hash = compute_set_function_auth_hash(&fn_selector, &new_policy_id);
    verify_and_consume_auth(&registry, &auth_obj, &me, &gov_policy, &action_hash, &caller)?;

    let old_policy = get_function_auth(&fn_selector).unwrap_or([0u8; 32]);
    store_function_auth(&fn_selector, &new_policy_id, true);

    let mut sel_topic = [0u8; 32];
    sel_topic[0..4].copy_from_slice(&fn_selector);
    events::emit(
        &[FUNCTION_AUTH_UPDATED, sel_topic, old_policy, new_policy_id],
        &auth_obj,
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_get_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let fn_selector = args.bytes4(0).ok_or(-3)?;
    let pol = get_function_auth(&fn_selector).unwrap_or([0u8; 32]);
    ret::write_word(&pol);
    Ok(())
}

/// Define a new role (`roleId`) in an active `Constitution` (initially with 0 assigned members),
/// requiring and consuming an `Authorization` object matching `getFunctionAuth(SEL_DEFINE_ROLE)`.
fn handle_define_role(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let role_id = args.bytes32(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if role_id == [0u8; 32] {
        return Err(-59);
    }

    let req_pol = require_function_auth(&SEL_DEFINE_ROLE)?;
    let action_hash = compute_define_role_hash(&role_id);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &auth_obj, &me, &req_pol, &action_hash, &caller)?;

    let exp = storage::get_u64(KEY_BOARD_EXPIRY);
    define_role_internal(&role_id, if exp == 0 { 50 } else { exp })?;
    let total_roles = storage::get_u64(KEY_DEFINED_ROLES_COUNT);

    events::emit(
        &[ROLE_DEFINED, role_id, addr_topic(&auth_obj)],
        &total_roles.to_be_bytes(),
    );
    ret::write_u64_word(total_roles);
    Ok(())
}

fn handle_is_role_defined(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    ret::write_bool(is_role_defined(&role_id));
    Ok(())
}

fn handle_defined_role_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_DEFINED_ROLES_COUNT));
    Ok(())
}

fn handle_defined_role_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)?;
    let cnt = storage::get_u64(KEY_DEFINED_ROLES_COUNT);
    if idx >= cnt {
        return Err(-62);
    }
    let rid = storage::get_bytes32(defined_role_at_key(idx).as_slice()).ok_or(-62)?;
    ret::write_word(&rid);
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
    let req_pol = require_function_auth(&SEL_SET_POLICY)?;
    let action_hash = compute_set_policy_hash(&target_hps, &policy_id, raw_spec);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

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
    let set_fn_pol = get_function_auth(&SEL_SET_FUNCTION_AUTH).unwrap_or(POLICY_SUPER_GOVERNANCE);
    if (policy_id == POLICY_SUPER_GOVERNANCE || policy_id == set_fn_pol)
        && (target_hps == me || target_hps == [0u8; 20])
    {
        return Err(-61); // cannot delete active governance root policy; amend via setPolicy instead
    }

    let pk = policy_key(&target_hps, &policy_id);
    if !storage::exists(pk.as_slice()) {
        return Err(-62);
    }

    let req_pol = require_function_auth(&SEL_DEACTIVATE_POLICY)?;
    let action_hash = compute_deactivate_hash(&target_hps, &policy_id);
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

    storage::set(pk.as_slice(), &[]);
    events::emit(&[POLICY_DEACTIVATED, addr_topic(&target_hps), policy_id], &[]);
    ret::write_bool(true);
    Ok(())
}

/// Add a new company Director Identity to the Board of Directors.
/// Requires a finalized, one-time-use `Authorization` HPS object matching `getFunctionAuth(SEL_ADD_DIRECTOR)`.
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

    let req_pol = require_function_auth(&SEL_ADD_DIRECTOR)?;
    let action_hash = compute_add_director_hash(&new_director);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

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
/// Requires a finalized, one-time-use `Authorization` HPS object matching `getFunctionAuth(SEL_REMOVE_DIRECTOR)`.
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

    let req_pol = require_function_auth(&SEL_REMOVE_DIRECTOR)?;
    let action_hash = compute_remove_director_hash(&director);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

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

/// Assign a defined role (`roleId`) to a verified `Identity` HPS (`accountIdentity`).
/// Requires `isRoleDefined(roleId) == true` and consumes `boardAuth` matching `getFunctionAuth(SEL_GRANT_ROLE)`.
fn handle_grant_role(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let role_id = args.bytes32(0).ok_or(-3)?;
    let account = args.address(1).ok_or(-3)?;
    let board_auth = args.address(2).ok_or(-3)?;
    if role_id == [0u8; 32] || account == [0u8; 20] {
        return Err(-59);
    }
    if !is_role_defined(&role_id) {
        return Err(ERR_ROLE_NOT_DEFINED);
    }

    require_valid_identity(&registry, &account)?;

    let req_pol = require_function_auth(&SEL_GRANT_ROLE)?;
    let action_hash = compute_grant_role_hash(&role_id, &account);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &board_auth, &me, &req_pol, &action_hash, &caller)?;

    let new_count = grant_role_internal(&role_id, &account)?;

    events::emit(
        &[
            ROLE_GRANTED,
            role_id,
            addr_topic(&account),
            addr_topic(&board_auth),
        ],
        &(new_count as u64).to_be_bytes(),
    );
    ret::write_u64_word(new_count as u64);
    Ok(())
}

/// Revoke a defined role (`roleId`) from `accountIdentity`, consuming `boardAuth` matching
/// `getFunctionAuth(SEL_REVOKE_ROLE)`.
fn handle_revoke_role(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let role_id = args.bytes32(0).ok_or(-3)?;
    let account = args.address(1).ok_or(-3)?;
    let board_auth = args.address(2).ok_or(-3)?;
    if role_id == [0u8; 32] || account == [0u8; 20] {
        return Err(-59);
    }
    if !is_role_defined(&role_id) {
        return Err(ERR_ROLE_NOT_DEFINED);
    }

    let req_pol = require_function_auth(&SEL_REVOKE_ROLE)?;
    let action_hash = compute_revoke_role_hash(&role_id, &account);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &board_auth, &me, &req_pol, &action_hash, &caller)?;

    let mut members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_role_members(&role_id, &mut members);
    let mut found_idx: Option<usize> = None;
    let mut i = 0;
    while i < count {
        if members[i] == account {
            found_idx = Some(i);
            break;
        }
        i += 1;
    }
    let idx = found_idx.ok_or(-62)?;
    let mut j = idx;
    while j + 1 < count {
        members[j] = members[j + 1];
        j += 1;
    }
    let new_count = count - 1;
    members[new_count] = [0u8; 20];
    storage::set_u64(role_has_key(&role_id, &account).as_slice(), 0);
    save_role_members(&role_id, &members, new_count)?;

    events::emit(
        &[
            ROLE_REVOKED,
            role_id,
            addr_topic(&account),
            addr_topic(&board_auth),
        ],
        &(new_count as u64).to_be_bytes(),
    );
    ret::write_u64_word(new_count as u64);
    Ok(())
}

/// Returns `true` iff `accountIdentity` holds `roleId` in this `Constitution` AND is currently
/// an active, bytecode-hash-verified `Identity` in `IdentityRegistry`.
fn handle_has_role(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        ret::write_bool(false);
        return Ok(());
    }
    let Some(registry) = storage::get_address(KEY_REGISTRY) else {
        ret::write_bool(false);
        return Ok(());
    };
    let role_id = args.bytes32(0).ok_or(-3)?;
    let account = args.address(1).ok_or(-3)?;
    ret::write_bool(has_active_role(&registry, &role_id, &account));
    Ok(())
}

fn handle_role_member_count(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    let mut members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_role_members(&role_id, &mut members);
    ret::write_u64_word(count as u64);
    Ok(())
}

fn handle_role_member_at(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    let idx = args.u64(1).ok_or(-3)? as usize;
    let mut members = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_role_members(&role_id, &mut members);
    if idx >= count {
        return Err(-62);
    }
    ret::write_address(&members[idx]);
    Ok(())
}

fn verify_function_auth_or_role(
    registry: &[u8; 20],
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
    caller: &[u8; 20],
) -> Result<(), i32> {
    let req_pol = require_function_auth(fn_selector)?;
    let me = context::self_address();
    if *auth_obj == [0u8; 20] {
        if is_fn_auth_explicit(fn_selector) {
            return Err(ERR_AUTH_CONSUME_FAILED);
        }
        if is_role_defined(&req_pol) && has_active_role(registry, &req_pol, caller) {
            return Ok(());
        }
        return Err(ERR_MISSING_ROLE);
    }
    verify_and_consume_auth(registry, auth_obj, &me, &req_pol, action_hash, caller)
}

/// Administer product listing creation/update on `productLedger` via the `Constitution`,
/// governed by `getFunctionAuth(SEL_UPSERT_PRODUCT)`.
fn handle_con_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let units = args.u64(2).ok_or(-3)?;
    let price = args.u64(3).ok_or(-3)?;
    let name = args.dynamic_bytes(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let action_hash =
        compute_con_upsert_product_hash(&product_ledger, &product_id, units, price, name);
    verify_function_auth_or_role(
        &registry,
        &SEL_UPSERT_PRODUCT,
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    let cd = CallEncoder::<512>::new(const {
        selector("upsertProduct(bytes32,uint64,uint64,bytes,address)")
    })
    .push_bytes32(&product_id)
    .push_u64(units)
    .push_u64(price)
    .push_u64(160)
    .push_address(&[0u8; 20])
    .push_dynamic_bytes_tail(name);
    let out = call::call_raw(&product_ledger, cd.as_slice())?;
    ret::write(out);
    Ok(())
}

/// Administer product inventory restock/adjustment on `productLedger` via the `Constitution`,
/// governed by `getFunctionAuth(SEL_RESTOCK_PRODUCT)`.
fn handle_con_restock_product(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let units_to_add = args.u64(2).ok_or(-3)?;
    let new_price = args.u64(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let action_hash = compute_con_restock_product_hash(
        &product_ledger,
        &product_id,
        units_to_add,
        new_price,
    );
    verify_function_auth_or_role(
        &registry,
        &SEL_RESTOCK_PRODUCT,
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    let cd = CallEncoder::<160>::new(const {
        selector("restockProduct(bytes32,uint64,uint64,address)")
    })
    .push_bytes32(&product_id)
    .push_u64(units_to_add)
    .push_u64(new_price)
    .push_address(&[0u8; 20]);
    let out = call::call_raw(&product_ledger, cd.as_slice())?;
    ret::write(out);
    Ok(())
}

/// Administer product unit price update on `productLedger` via the `Constitution`,
/// governed by `getFunctionAuth(SEL_SET_PRODUCT_PRICE)`.
fn handle_con_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let action_hash = compute_con_set_product_price_hash(&product_ledger, &product_id, new_price);
    verify_function_auth_or_role(
        &registry,
        &SEL_SET_PRODUCT_PRICE,
        &action_hash,
        &auth_obj,
        &caller,
    )?;

    let cd = CallEncoder::<128>::new(const { selector("setProductPrice(bytes32,uint64,address)") })
        .push_bytes32(&product_id)
        .push_u64(new_price)
        .push_address(&[0u8; 20]);
    let out = call::call_raw(&product_ledger, cd.as_slice())?;
    ret::write(out);
    Ok(())
}

/// Set or rotate the Bank Oracle backend Identity (`oracleIdentity`) for a company bank-account
/// `AssetLedger` (`bankLedger`), governed by `getFunctionAuth(SEL_SET_BANK_ORACLE)`.
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

    let req_pol = require_function_auth(&SEL_SET_BANK_ORACLE)?;
    let action_hash = compute_set_bank_oracle_hash(&bank_ledger, &oracle_identity, expiry_blocks);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &board_auth, &me, &req_pol, &action_hash, &caller)?;

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
    if is_role_defined(&ROLE_BANK_ORACLE) {
        let _ = grant_role_internal(&ROLE_BANK_ORACLE, &oracle_identity);
    }

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
/// balance `AssetLedger` (`bankLedger`), governed by `getFunctionAuth(SEL_SET_CLEARING_ACCOUNT)`.
fn handle_set_clearing_account(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let clearing_account = args.address(1).ok_or(-3)?;
    let board_auth = args.address(2).ok_or(-3)?;
    if bank_ledger == [0u8; 20] || clearing_account == [0u8; 20] {
        return Err(-59);
    }

    require_valid_identity(&registry, &clearing_account)?;

    if board_auth == [0u8; 20]
        && storage::get_address(KEY_CLEARING_ACCOUNT).is_none()
        && !is_fn_auth_explicit(&SEL_SET_CLEARING_ACCOUNT)
    {
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
        let req_pol = require_function_auth(&SEL_SET_CLEARING_ACCOUNT)?;
        let action_hash = compute_set_clearing_account_hash(&bank_ledger, &clearing_account);
        let me = context::self_address();
        verify_and_consume_auth(&registry, &board_auth, &me, &req_pol, &action_hash, &caller)?;
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

/// Appoint or rotate the Product Catalog Manager / Oracle `Identity` (`oracleIdentity`),
/// governed by `getFunctionAuth(SEL_SET_PRODUCT_ORACLE)`.
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

    let req_pol = require_function_auth(&SEL_SET_PRODUCT_ORACLE)?;
    let action_hash =
        compute_set_product_oracle_hash(&product_ledger, &oracle_identity, expiry_blocks);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &board_auth, &me, &req_pol, &action_hash, &caller)?;

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
    let _ = grant_role_internal(&ROLE_PRODUCT_MANAGER, &oracle_identity);

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
    if storage::get_u64(KEY_STATE) != CONSTITUTION_STATE_ACTIVE {
        return Err(ERR_CONSTITUTION_NOT_ACTIVE);
    }
    let buyer = args.address(0).ok_or(-3)?;
    let total_cost = args.u64(1).ok_or(-3)?;
    if buyer == [0u8; 20] || total_cost == 0 {
        return Err(-59);
    }

    // Verify caller is a ProductLedger controlled by this Constitution
    let product_ledger = context::msg_sender();
    let pk = product_oracle_key(&product_ledger);
    if storage::get_address(pk.as_slice()).is_none() {
        let assoc_cd = CallEncoder::<16>::new(const { selector("associatedConstitution()") });
        let Ok(raw_assoc) = call::call_raw(&product_ledger, assoc_cd.as_slice()) else {
            return Err(-62);
        };
        if raw_assoc.len() < 32 || raw_assoc[12..32] != context::self_address() {
            return Err(-62);
        }
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
    if storage::get_u64(KEY_STATE) != CONSTITUTION_STATE_ACTIVE {
        return Err(ERR_CONSTITUTION_NOT_ACTIVE);
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

    if super_auth == [0u8; 20]
        && existing_idx.is_none()
        && !is_fn_auth_explicit(&SEL_REGISTER_SHARE_CLASS)
    {
        // Allow founder/director initial share-class registration (including during
        // PENDING_RATIFICATION so multi-class shareholders can vote on `activateConstitution`)
        let (_registry, caller) = ensure_initialized_any_state_caller()?;
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
        let (registry, caller) = ensure_initialized_and_valid_caller()?;
        let req_pol = require_function_auth(&SEL_REGISTER_SHARE_CLASS)?;
        let action_hash = compute_register_share_class_hash(
            &share_ledger,
            votes_per_share,
            conversion_numer,
            conversion_denom,
        );
        let me = context::self_address();
        verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;
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

/// Constitutional process to authorize a predetermined percentage (`underwritePct`) of total
/// outstanding shares (converted to common-share equivalents across all registered share classes)
/// to be underwritten as a single class of futures contracts in `futuresLedger`.
/// Requires a finalized Shareholder Super-Majority `Authorization` HPS (`POLICY_SUPER_GOVERNANCE`
/// or `POLICY_SHAREHOLDER_SUPERMAJORITY`).
fn handle_authorize_futures_underwriting(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let futures_ledger = args.address(0).ok_or(-3)?;
    let underwrite_pct = args.u64(1).ok_or(-3)?;
    let super_auth = args.address(2).ok_or(-3)?;

    if futures_ledger == [0u8; 20] || underwrite_pct == 0 || underwrite_pct > 10_000 {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let me = context::self_address();
    let assoc_cd = CallEncoder::<16>::new(const { selector("associatedConstitution()") });
    let Ok(raw_assoc) = call::call_raw(&futures_ledger, assoc_cd.as_slice()) else {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    };
    if raw_assoc.len() < 32 || raw_assoc[12..32] != me {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let action_hash =
        compute_authorize_futures_underwriting_hash(&futures_ledger, underwrite_pct);
    let cfg_pol = require_function_auth(&SEL_AUTHORIZE_FUTURES)?;
    let expected_pol = if !is_fn_auth_explicit(&SEL_AUTHORIZE_FUTURES)
        && policy_exists_for(&me, &POLICY_SHAREHOLDER_SUPERMAJORITY)
    {
        let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
        if let Ok(raw_pid) = call::call_raw(&super_auth, pid_cd.as_slice()) {
            if raw_pid.len() >= 32 && raw_pid[..32] == POLICY_SHAREHOLDER_SUPERMAJORITY {
                POLICY_SHAREHOLDER_SUPERMAJORITY
            } else {
                cfg_pol
            }
        } else {
            cfg_pol
        }
    } else {
        cfg_pol
    };
    verify_and_consume_auth(
        &registry,
        &super_auth,
        &me,
        &expected_pol,
        &action_hash,
        &caller,
    )?;

    storage::set_address(KEY_FUTURES_LEDGER, &futures_ledger);
    storage::set_u64(KEY_FUTURES_PCT, underwrite_pct);

    let (_holder_common, total_common) = compute_converted_common_totals(&[0u8; 20]);
    let company_max_cap = apply_futures_pct(total_common, underwrite_pct);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&underwrite_pct.to_be_bytes());
    ev[8..16].copy_from_slice(&company_max_cap.to_be_bytes());
    events::emit(
        &[
            FUTURES_UNDERWRITING_AUTHORIZED,
            addr_topic(&futures_ledger),
            addr_topic(&super_auth),
        ],
        &ev,
    );
    ret::write_u64_word(company_max_cap);
    Ok(())
}

/// Underwrite (create) `amount` units of the company's single-class futures contract on
/// `futuresLedger()`.
/// Enforces that the calling shareholder's cumulative underwritten futures contracts do not exceed
/// `underwritePct` of their converted common-share holdings across all registered share classes
/// (e.g., `100,000` Preferred Shares A at `50%` conversion = `50,000` common-equivalent shares;
/// at `10%` underwriting limit, max `5,000` futures units), and that total outstanding futures
/// do not exceed `underwritePct` of the company's total converted common shares.
fn handle_underwrite_futures(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let amount = args.u64(0).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    let futures_ledger =
        storage::get_address(KEY_FUTURES_LEDGER).ok_or(ERR_INVALID_FUTURES_CONFIG)?;
    let pct = storage::get_u64(KEY_FUTURES_PCT);
    if pct == 0 {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let (holder_common, total_common) = compute_converted_common_totals(&caller);
    let holder_max_allowance = apply_futures_pct(holder_common, pct);
    let company_max_cap = apply_futures_pct(total_common, pct);

    let uk = futures_underwritten_key(&futures_ledger, &caller);
    let already_underwritten = storage::get_u64(uk.as_slice());
    let new_underwritten = already_underwritten
        .checked_add(amount)
        .ok_or(ERR_FUTURES_CAP_EXCEEDED)?;
    if new_underwritten > holder_max_allowance {
        return Err(ERR_FUTURES_CAP_EXCEEDED);
    }

    let sup_cd = CallEncoder::<16>::new(const { selector("totalOutstanding()") });
    let cur_futures_supply = call::call_u64(&futures_ledger, sup_cd.as_slice()).unwrap_or(0);
    if cur_futures_supply.saturating_add(amount) > company_max_cap {
        return Err(ERR_FUTURES_CAP_EXCEEDED);
    }

    storage::set_u64(uk.as_slice(), new_underwritten);

    let issue_cd = CallEncoder::<96>::new(const { selector("constitutionIssue(address,uint64)") })
        .push_address(&caller)
        .push_u64(amount);
    let _new_bal = call::call_u64(&futures_ledger, issue_cd.as_slice())?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_underwritten.to_be_bytes());
    ev[16..24].copy_from_slice(&holder_max_allowance.to_be_bytes());
    events::emit(
        &[
            FUTURES_UNDERWRITTEN,
            addr_topic(&futures_ledger),
            addr_topic(&caller),
        ],
        &ev,
    );
    ret::write_u64_word(new_underwritten);
    Ok(())
}

/// Close/burn `amount` units of previously underwritten futures contracts from the caller's
/// balance in `futuresLedger()`, restoring `amount` of their underwriting allowance.
fn handle_close_underwritten_futures(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let amount = args.u64(0).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    let futures_ledger =
        storage::get_address(KEY_FUTURES_LEDGER).ok_or(ERR_INVALID_FUTURES_CONFIG)?;
    let uk = futures_underwritten_key(&futures_ledger, &caller);
    let already_underwritten = storage::get_u64(uk.as_slice());
    if already_underwritten < amount {
        return Err(-16);
    }

    let cancel_cd =
        CallEncoder::<96>::new(const { selector("constitutionCancel(address,uint64)") })
            .push_address(&caller)
            .push_u64(amount);
    let _new_bal = call::call_u64(&futures_ledger, cancel_cd.as_slice())?;

    let rem_underwritten = already_underwritten - amount;
    storage::set_u64(uk.as_slice(), rem_underwritten);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&rem_underwritten.to_be_bytes());
    events::emit(
        &[
            FUTURES_CLOSED,
            addr_topic(&futures_ledger),
            addr_topic(&caller),
        ],
        &ev,
    );
    ret::write_u64_word(rem_underwritten);
    Ok(())
}

fn handle_futures_ledger(_args: &CalldataReader) -> Result<(), i32> {
    let led = storage::get_address(KEY_FUTURES_LEDGER).unwrap_or([0u8; 20]);
    ret::write_address(&led);
    Ok(())
}

fn handle_futures_underwrite_pct(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_FUTURES_PCT));
    Ok(())
}

fn handle_futures_underwritten_by(args: &CalldataReader) -> Result<(), i32> {
    let shareholder = args.address(0).ok_or(-3)?;
    let Some(futures_ledger) = storage::get_address(KEY_FUTURES_LEDGER) else {
        ret::write_u64_word(0);
        return Ok(());
    };
    let uk = futures_underwritten_key(&futures_ledger, &shareholder);
    ret::write_u64_word(storage::get_u64(uk.as_slice()));
    Ok(())
}

/// Returns `(uint64 convertedCommonShares, uint64 maxFuturesAllowance, uint64 alreadyUnderwritten,
/// uint64 remainingAllowance, uint64 companyMaxFuturesCap)` for `shareholder`.
fn handle_futures_allowance_of(args: &CalldataReader) -> Result<(), i32> {
    let shareholder = args.address(0).ok_or(-3)?;
    let pct = storage::get_u64(KEY_FUTURES_PCT);
    let (holder_common, total_common) = compute_converted_common_totals(&shareholder);
    let max_allowance = apply_futures_pct(holder_common, pct);
    let company_cap = apply_futures_pct(total_common, pct);
    let already_underwritten =
        if let Some(futures_ledger) = storage::get_address(KEY_FUTURES_LEDGER) {
            storage::get_u64(futures_underwritten_key(&futures_ledger, &shareholder).as_slice())
        } else {
            0
        };
    let remaining = max_allowance.saturating_sub(already_underwritten);

    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&holder_common.to_be_bytes());
    out[56..64].copy_from_slice(&max_allowance.to_be_bytes());
    out[88..96].copy_from_slice(&already_underwritten.to_be_bytes());
    out[120..128].copy_from_slice(&remaining.to_be_bytes());
    out[152..160].copy_from_slice(&company_cap.to_be_bytes());
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

fn handle_hash_activate_constitution(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&compute_activate_constitution_hash());
    Ok(())
}

fn handle_hash_set_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let fn_selector = args.bytes4(0).ok_or(-3)?;
    let policy_id = args.bytes32(1).ok_or(-3)?;
    ret::write_word(&compute_set_function_auth_hash(&fn_selector, &policy_id));
    Ok(())
}

fn handle_hash_define_role(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    ret::write_word(&compute_define_role_hash(&role_id));
    Ok(())
}

fn handle_hash_con_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let units = args.u64(2).ok_or(-3)?;
    let price = args.u64(3).ok_or(-3)?;
    let name = args.dynamic_bytes(4).ok_or(-3)?;
    ret::write_word(&compute_con_upsert_product_hash(
        &product_ledger,
        &product_id,
        units,
        price,
        name,
    ));
    Ok(())
}

fn handle_hash_con_restock_product(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let units_to_add = args.u64(2).ok_or(-3)?;
    let new_price = args.u64(3).ok_or(-3)?;
    ret::write_word(&compute_con_restock_product_hash(
        &product_ledger,
        &product_id,
        units_to_add,
        new_price,
    ));
    Ok(())
}

fn handle_hash_con_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_con_set_product_price_hash(
        &product_ledger,
        &product_id,
        new_price,
    ));
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

fn handle_hash_grant_role(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    let account = args.address(1).ok_or(-3)?;
    ret::write_word(&compute_grant_role_hash(&role_id, &account));
    Ok(())
}

fn handle_hash_revoke_role(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    let account = args.address(1).ok_or(-3)?;
    ret::write_word(&compute_revoke_role_hash(&role_id, &account));
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

fn handle_hash_authorize_futures_underwriting(args: &CalldataReader) -> Result<(), i32> {
    let futures_ledger = args.address(0).ok_or(-3)?;
    let underwrite_pct = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_authorize_futures_underwriting_hash(
        &futures_ledger,
        underwrite_pct,
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

    mod first_sh_auth_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("arm(bytes32,bytes32)") } {
                storage::set(b"pol", &args.bytes32(0).unwrap());
                storage::set(b"hash", &args.bytes32(1).unwrap());
                storage::set_u64(b"used", 0);
                return 0;
            }
            if sel == const { selector("policyId()") } {
                let pol = storage::get_bytes32(b"pol").unwrap_or([0u8; 32]);
                ret::write_word(&pol);
                return 0;
            }
            if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                if storage::get_u64(b"used") == 1 {
                    return -68;
                }
                let expected_pol = args.bytes32(1).unwrap();
                let expected_hash = args.bytes32(2).unwrap();
                if storage::get_bytes32(b"pol") != Some(expected_pol) {
                    return -66;
                }
                if storage::get_bytes32(b"hash") != Some(expected_hash) {
                    return -67;
                }
                storage::set_u64(b"used", 1);
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    fn ratify_constitution_in_test(caller: [u8; 20], con: [u8; 20], auth_addr: [u8; 20]) {
        mock::register_hps(auth_addr, first_sh_auth_stub::dispatch);
        mock::set_code_hash(auth_addr, [0x99; 32]);

        // Verify Constitution starts in PENDING_RATIFICATION (1) and isActive() == false
        let st_before = mock::transact_as(
            caller,
            con,
            CallEncoder::<16>::new(const { selector("state()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(st_before[24..32].try_into().unwrap()),
            CONSTITUTION_STATE_PENDING_RATIFICATION
        );
        let act_before = mock::transact_as(
            caller,
            con,
            CallEncoder::<16>::new(const { selector("isActive()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(act_before[31], 0);

        let req_pol: [u8; 32] = mock::transact_as(
            caller,
            con,
            CallEncoder::<64>::new(const { selector("getFunctionAuth(bytes4)") })
                .push_bytes4(&SEL_ACTIVATE_CONSTITUTION)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let h_act: [u8; 32] = mock::transact_as(
            caller,
            con,
            CallEncoder::<16>::new(const { selector("hashActivateConstitution()") }).as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        mock::transact_as(
            caller,
            auth_addr,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&req_pol)
                .push_bytes32(&h_act)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            caller,
            con,
            CallEncoder::<64>::new(const { selector("activateConstitution(address)") })
                .push_address(&auth_addr)
                .as_slice(),
        )
        .unwrap();

        let st_after = mock::transact_as(
            caller,
            con,
            CallEncoder::<16>::new(const { selector("state()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(st_after[24..32].try_into().unwrap()),
            CONSTITUTION_STATE_ACTIVE
        );
        let act_after = mock::transact_as(
            caller,
            con,
            CallEncoder::<16>::new(const { selector("isActive()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(act_after[31], 1);
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
        ratify_constitution_in_test(manogaran, con, [0xCF; 20]);

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
        ratify_constitution_in_test(manogaran, con, [0xCF; 20]);

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

    #[test]
    fn director_assigned_roles_and_product_manager_administration() {
        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let manogaran = [0xA1; 20];
        let evelyn = [0xA2; 20];
        let prod_mgr = [0xB7; 20];
        let outsider = [0xB8; 20];
        let prod_ledger = [0xD1; 20];
        let auth_grant = [0xC1; 20];
        let auth_revoke = [0xC2; 20];

        mod board_auth_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::POLICY_BOARD_RESOLUTION;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("arm(bytes32)") } {
                    storage::set(b"hash", &args.bytes32(0).unwrap());
                    storage::set_u64(b"used", 0);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    if storage::get_u64(b"used") == 1 {
                        return -66;
                    }
                    let pol = args.bytes32(1).unwrap();
                    let h = args.bytes32(2).unwrap();
                    if pol != POLICY_BOARD_RESOLUTION
                        || storage::get_bytes32(b"hash").as_ref() != Some(&h)
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

        mod prod_ledger_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("upsertProduct(bytes32,uint64,uint64,bytes,address)") } {
                    storage::set_u64(b"units", args.u64(1).unwrap());
                    storage::set_u64(b"price", args.u64(2).unwrap());
                    ret::write_u64_word(1);
                    return 0;
                }
                if sel == const { selector("restockProduct(bytes32,uint64,uint64,address)") } {
                    let u = storage::get_u64(b"units") + args.u64(1).unwrap();
                    storage::set_u64(b"units", u);
                    let np = args.u64(2).unwrap();
                    if np > 0 {
                        storage::set_u64(b"price", np);
                    }
                    ret::write_u64_word(u);
                    return 0;
                }
                if sel == const { selector("setProductPrice(bytes32,uint64,address)") } {
                    let np = args.u64(1).unwrap();
                    storage::set_u64(b"price", np);
                    ret::write_u64_word(np);
                    return 0;
                }
                -2
            }
        }

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con, dispatch_calldata);
        mock::register_hps(auth_grant, board_auth_stub::dispatch);
        mock::register_hps(auth_revoke, board_auth_stub::dispatch);
        mock::set_code_hash(auth_grant, [0x99; 32]);
        mock::set_code_hash(auth_revoke, [0x99; 32]);
        mock::register_hps(prod_ledger, prod_ledger_stub::dispatch);

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
        ratify_constitution_in_test(manogaran, con, [0xCF; 20]);

        let sku = keccak256(b"SKU_ENTERPRISE_NODE");

        // Before role is granted, prod_mgr cannot administer product listings via Constitution
        let upsert_cd = CallEncoder::<512>::new(const {
            selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)")
        })
        .push_address(&prod_ledger)
        .push_bytes32(&sku)
        .push_u64(25)
        .push_u64(1_200)
        .push_u64(192)
        .push_address(&[0u8; 20])
        .push_dynamic_bytes_tail(b"Enterprise Node");
        let err = mock::transact_as(prod_mgr, con, upsert_cd.as_slice()).unwrap_err();
        assert_eq!(err, ERR_MISSING_ROLE);

        // Directors grant ROLE_PRODUCT_MANAGER to prod_mgr via Board Resolution
        let h_grant: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("hashGrantRole(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            auth_grant,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_grant)
                .as_slice(),
        )
        .unwrap();
        let cnt_out = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<128>::new(const { selector("grantRole(bytes32,address,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .push_address(&auth_grant)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(cnt_out[24..32].try_into().unwrap()), 1);

        // Verify hasRole(ROLE_PRODUCT_MANAGER, prod_mgr) == true and outsider == false
        let has_pm = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(has_pm[31], 1);

        let has_out = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&outsider)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(has_out[31], 0);

        // prod_mgr can now upsertProduct, restockProduct, and setProductPrice via Constitution
        let up_res = mock::transact_as(prod_mgr, con, upsert_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(up_res[24..32].try_into().unwrap()), 1);

        let restock_res = mock::transact_as(
            prod_mgr,
            con,
            CallEncoder::<192>::new(const {
                selector("restockProduct(address,bytes32,uint64,uint64,address)")
            })
            .push_address(&prod_ledger)
            .push_bytes32(&sku)
            .push_u64(10)
            .push_u64(1_300)
            .push_address(&[0u8; 20])
            .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(restock_res[24..32].try_into().unwrap()), 35);

        let price_res = mock::transact_as(
            prod_mgr,
            con,
            CallEncoder::<160>::new(const {
                selector("setProductPrice(address,bytes32,uint64,address)")
            })
            .push_address(&prod_ledger)
            .push_bytes32(&sku)
            .push_u64(1_400)
            .push_address(&[0u8; 20])
            .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(price_res[24..32].try_into().unwrap()), 1_400);

        // Outsider still rejected with ERR_MISSING_ROLE
        let out_err = mock::transact_as(outsider, con, upsert_cd.as_slice()).unwrap_err();
        assert_eq!(out_err, ERR_MISSING_ROLE);

        // Directors revoke ROLE_PRODUCT_MANAGER from prod_mgr via Board Resolution
        let h_revoke: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const { selector("hashRevokeRole(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            auth_revoke,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_revoke)
                .as_slice(),
        )
        .unwrap();
        let rev_out = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<128>::new(const { selector("revokeRole(bytes32,address,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .push_address(&auth_revoke)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rev_out[24..32].try_into().unwrap()), 0);

        // After revocation, prod_mgr is rejected with ERR_MISSING_ROLE
        let rev_err = mock::transact_as(prod_mgr, con, upsert_cd.as_slice()).unwrap_err();
        assert_eq!(rev_err, ERR_MISSING_ROLE);
    }

    #[test]
    fn constitutional_futures_underwriting_across_share_classes_and_caps() {
        mock::reset();
        let reg = [0x10; 20];
        let con = [0x20; 20];
        let manogaran = [0xA1; 20];
        let evelyn = [0xA2; 20];
        let pref_a_holder = [0xB5; 20];
        let common_ledger = [0xE1; 20];
        let pref_a_ledger = [0xE2; 20];
        let futures_ledger = [0xE3; 20];
        let super_auth = [0xC9; 20];

        mod super_auth_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::governance::POLICY_SUPER_GOVERNANCE;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("arm(bytes32)") } {
                    storage::set(b"hash", &args.bytes32(0).unwrap());
                    storage::set_u64(b"used", 0);
                    return 0;
                }
                if sel == const { selector("policyId()") } {
                    ret::write_word(&POLICY_SUPER_GOVERNANCE);
                    return 0;
                }
                if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                    if storage::get_u64(b"used") == 1 {
                        return -68;
                    }
                    let pol = args.bytes32(1).unwrap();
                    let h = args.bytes32(2).unwrap();
                    if pol != POLICY_SUPER_GOVERNANCE
                        || storage::get_bytes32(b"hash").as_ref() != Some(&h)
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

        mod share_and_futures_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::storage::KeyBuilder;
            use hps_sdk::{ret, selector, storage};
            fn bkey(id: &[u8; 20]) -> KeyBuilder<32> {
                KeyBuilder::<32>::new().push(b"b:").push(id)
            }
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
                if sel == const { selector("setCon(address)") } {
                    storage::set_address(b"con", &args.address(0).unwrap());
                    return 0;
                }
                if sel == const { selector("associatedConstitution()") } {
                    ret::write_address(&storage::get_address(b"con").unwrap_or([0u8; 20]));
                    return 0;
                }
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
                if sel == const { selector("constitutionIssue(address,uint64)") } {
                    let to = args.address(0).unwrap();
                    let amt = args.u64(1).unwrap();
                    let nb = storage::get_u64(bkey(&to).as_slice()) + amt;
                    storage::set_u64(bkey(&to).as_slice(), nb);
                    storage::set_u64(b"sup", storage::get_u64(b"sup") + amt);
                    ret::write_u64_word(nb);
                    return 0;
                }
                if sel == const { selector("constitutionCancel(address,uint64)") } {
                    let from = args.address(0).unwrap();
                    let amt = args.u64(1).unwrap();
                    let cur = storage::get_u64(bkey(&from).as_slice());
                    if cur < amt {
                        return -16;
                    }
                    let nb = cur - amt;
                    storage::set_u64(bkey(&from).as_slice(), nb);
                    storage::set_u64(b"sup", storage::get_u64(b"sup") - amt);
                    ret::write_u64_word(nb);
                    return 0;
                }
                -2
            }
        }

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con, dispatch_calldata);
        mock::register_hps(super_auth, super_auth_stub::dispatch);
        mock::set_code_hash(super_auth, [0x99; 32]);
        mock::register_hps(common_ledger, share_and_futures_stub::dispatch);
        mock::register_hps(pref_a_ledger, share_and_futures_stub::dispatch);
        mock::register_hps(futures_ledger, share_and_futures_stub::dispatch);

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

        // Pin futures_ledger to Constitution
        mock::transact_as(
            manogaran,
            futures_ledger,
            CallEncoder::<64>::new(const { selector("setCon(address)") })
                .push_address(&con)
                .as_slice(),
        )
        .unwrap();

        // Register 2 share classes:
        // 1. Common Shares (`common_ledger`): 1:1 voting, 1:1 conversion to common (100,000 total outstanding, Manogaran holds 50,000)
        // 2. Preferred Shares A (`pref_a_ledger`): 1:1 voting, 50% conversion to common (`conversionNumer = 1, conversionDenom = 2`),
        //    `pref_a_holder` holds 100,000 Preferred Shares A (and 0 Common Shares)
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
                .push_address(&pref_a_holder)
                .push_u64(100_000)
                .push_u64(100_000)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<192>::new(const {
                selector("registerShareClass(address,uint64,uint64,uint64,address)")
            })
            .push_address(&common_ledger)
            .push_u64(1)
            .push_u64(1)
            .push_u64(1)
            .push_address(&[0u8; 20])
            .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            manogaran,
            con,
            CallEncoder::<192>::new(const {
                selector("registerShareClass(address,uint64,uint64,uint64,address)")
            })
            .push_address(&pref_a_ledger)
            .push_u64(1)
            .push_u64(1)
            .push_u64(2) // 50% conversion rate to Common Shares!
            .push_address(&[0u8; 20])
            .as_slice(),
        )
        .unwrap();

        // Pass First Shareholder Resolution to activate the Constitution after registering share classes
        ratify_constitution_in_test(manogaran, con, [0xCF; 20]);

        // Authorize 10% (`underwritePct = 10`) of total outstanding shares to be underwritten as
        // a single class of futures contracts (`futures_ledger`) via Shareholder Super-Majority Authorization
        let h_fut: [u8; 32] = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<96>::new(const {
                selector("hashAuthorizeFuturesUnderwriting(address,uint64)")
            })
            .push_address(&futures_ledger)
            .push_u64(10)
            .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            manogaran,
            super_auth,
            CallEncoder::<64>::new(const { selector("arm(bytes32)") })
                .push_bytes32(&h_fut)
                .as_slice(),
        )
        .unwrap();
        let cap_out = mock::transact_as(
            manogaran,
            con,
            CallEncoder::<128>::new(const {
                selector("authorizeFuturesUnderwriting(address,uint64,address)")
            })
            .push_address(&futures_ledger)
            .push_u64(10) // 10%
            .push_address(&super_auth)
            .as_slice(),
        )
        .unwrap();
        // Total company converted common shares = 100,000 (Common) + 50,000 (100k Pref A @ 50%) = 150,000
        // 10% of 150,000 = 15,000 company-wide futures cap
        assert_eq!(u64::from_be_bytes(cap_out[24..32].try_into().unwrap()), 15_000);

        // Verify `pref_a_holder` (with ONLY 100,000 Preferred Shares A @ 50% conversion = 50,000 common-equivalent)
        // has a max futures underwriting allowance of 10% * 50,000 = 5,000 units!
        let alw = mock::transact_as(
            pref_a_holder,
            con,
            CallEncoder::<64>::new(const { selector("futuresAllowanceOf(address)") })
                .push_address(&pref_a_holder)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(alw[24..32].try_into().unwrap()), 50_000); // convertedCommonShares
        assert_eq!(u64::from_be_bytes(alw[56..64].try_into().unwrap()), 5_000);  // maxFuturesAllowance
        assert_eq!(u64::from_be_bytes(alw[88..96].try_into().unwrap()), 0);      // alreadyUnderwritten
        assert_eq!(u64::from_be_bytes(alw[120..128].try_into().unwrap()), 5_000);// remainingAllowance
        assert_eq!(u64::from_be_bytes(alw[152..160].try_into().unwrap()), 15_000);// companyMaxFuturesCap

        // `pref_a_holder` underwrites 5,000 units of futures contract -> succeeds!
        let uw_out = mock::transact_as(
            pref_a_holder,
            con,
            CallEncoder::<64>::new(const { selector("underwriteFutures(uint64)") })
                .push_u64(5_000)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(uw_out[24..32].try_into().unwrap()), 5_000);

        // Verify `pref_a_holder` now holds 5,000 units in `futures_ledger`
        let fut_bal = mock::transact_as(
            pref_a_holder,
            futures_ledger,
            CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                .push_address(&pref_a_holder)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(fut_bal[24..32].try_into().unwrap()), 5_000);

        // Negative test: `pref_a_holder` attempting to underwrite even 1 more unit (5,001 > 5,000) MUST revert with ERR_FUTURES_CAP_EXCEEDED (-87)!
        let over_err = mock::transact_as(
            pref_a_holder,
            con,
            CallEncoder::<64>::new(const { selector("underwriteFutures(uint64)") })
                .push_u64(1)
                .as_slice(),
        )
        .unwrap_err();
        assert_eq!(over_err, ERR_FUTURES_CAP_EXCEEDED);

        // Closing 2,000 units burns 2,000 futures contracts and restores 2,000 of allowance
        let close_out = mock::transact_as(
            pref_a_holder,
            con,
            CallEncoder::<64>::new(const { selector("closeUnderwrittenFutures(uint64)") })
                .push_u64(2_000)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(close_out[24..32].try_into().unwrap()), 3_000);
    }

    #[test]
    fn initialize_with_governance_predefines_unassigned_roles_function_auth_rotation_and_shareholder_activation(
    ) {
        use hps_sdk::governance::ROLE_ALL_MEMBERS_WEIGHT;

        fn encode_init_with_gov(
            reg: [u8; 20],
            roles_blob: &[u8],
            policies_blob: &[u8],
            fn_auths_blob: &[u8],
            share_classes_blob: &[u8],
        ) -> Vec<u8> {
            let mut cd = Vec::new();
            cd.extend_from_slice(&const {
                selector("initializeWithGovernance(address,bytes,bytes,bytes,bytes)")
            });
            let pad_len = |n: usize| n + (32 - n % 32) % 32;
            let push_u64_w = |v: &mut Vec<u8>, n: u64| {
                let mut w = [0u8; 32];
                w[24..32].copy_from_slice(&n.to_be_bytes());
                v.extend_from_slice(&w);
            };
            let push_dyn = |v: &mut Vec<u8>, b: &[u8]| {
                push_u64_w(v, b.len() as u64);
                v.extend_from_slice(b);
                v.resize(v.len() + (32 - b.len() % 32) % 32, 0);
            };

            let off_roles = 160u64;
            let off_pols = off_roles + 32 + pad_len(roles_blob.len()) as u64;
            let off_fns = off_pols + 32 + pad_len(policies_blob.len()) as u64;
            let off_scs = off_fns + 32 + pad_len(fn_auths_blob.len()) as u64;

            let mut rw = [0u8; 32];
            rw[12..32].copy_from_slice(&reg);
            cd.extend_from_slice(&rw);
            push_u64_w(&mut cd, off_roles);
            push_u64_w(&mut cd, off_pols);
            push_u64_w(&mut cd, off_fns);
            push_u64_w(&mut cd, off_scs);

            push_dyn(&mut cd, roles_blob);
            push_dyn(&mut cd, policies_blob);
            push_dyn(&mut cd, fn_auths_blob);
            push_dyn(&mut cd, share_classes_blob);
            cd
        }

        mod prod_stub {
            use hps_sdk::abi::CalldataReader;
            use hps_sdk::{ret, selector, storage};
            pub fn dispatch(raw: &[u8]) -> i32 {
                let Some((sel, args)) = CalldataReader::parse(raw) else {
                    return -1;
                };
                if sel == const { selector("upsertProduct(bytes32,uint64,uint64,bytes,address)") }
                {
                    let next = storage::get_u64(b"cnt") + 1;
                    storage::set_u64(b"cnt", next);
                    storage::set_u64(b"last_px", args.u64(2).unwrap());
                    ret::write_u64_word(next);
                    return 0;
                }
                -2
            }
        }

        mock::reset();
        let reg = [0x10; 20];
        let con_bad = [0x19; 20];
        let con = [0x20; 20];
        let prod_ledger = [0x30; 20];

        let shareholder_1 = [0xA1; 20];
        let shareholder_2 = [0xA2; 20];
        let dir_1 = [0xB1; 20];
        let dir_2 = [0xB2; 20];
        let prod_mgr = [0xD1; 20];
        let compliance_officer = [0xD2; 20];

        let auth_activate = [0xC1; 20];
        let auth_grant_pm = [0xC2; 20];
        let auth_upsert_pm = [0xC3; 20];
        let auth_rotate_fn = [0xC4; 20];
        let auth_stale_pm = [0xC5; 20];
        let auth_upsert_dual = [0xC6; 20];
        let auth_def_role = [0xC7; 20];

        mock::register_hps(reg, reg_stub::dispatch);
        mock::register_hps(con_bad, dispatch_calldata);
        mock::register_hps(con, dispatch_calldata);
        mock::register_hps(prod_ledger, prod_stub::dispatch);

        for au in [
            auth_activate,
            auth_grant_pm,
            auth_upsert_pm,
            auth_rotate_fn,
            auth_stale_pm,
            auth_upsert_dual,
            auth_def_role,
        ] {
            mock::register_hps(au, first_sh_auth_stub::dispatch);
            mock::set_code_hash(au, [0x99; 32]);
        }

        let role_compliance = keccak256(b"ROLE_COMPLIANCE_OFFICER");
        let role_auditor = keccak256(b"ROLE_EXTERNAL_AUDITOR");
        let policy_dual_review = keccak256(b"POLICY_DUAL_PRODUCT_COMPLIANCE");

        // Build `rolesBlob`:
        // - `ROLE_SHAREHOLDER`: [shareholder_1, shareholder_2]
        // - `ROLE_DIRECTOR`: [dir_1, dir_2]
        // - `ROLE_PRODUCT_MANAGER`: [] (0 identities assigned at construction!)
        // - `ROLE_TREASURY_MANAGER`: [] (0 identities assigned at construction!)
        // - `role_compliance`: [] (0 identities assigned at construction!)
        let pack_role = |rid: [u8; 32], members: &[[u8; 20]]| -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&rid);
            v.extend_from_slice(&(members.len() as u16).to_be_bytes());
            for m in members {
                v.extend_from_slice(m);
            }
            v
        };
        let mut roles_blob = Vec::new();
        roles_blob.extend_from_slice(&5u16.to_be_bytes());
        roles_blob.extend_from_slice(&pack_role(ROLE_SHAREHOLDER, &[shareholder_1, shareholder_2]));
        roles_blob.extend_from_slice(&pack_role(ROLE_DIRECTOR, &[dir_1, dir_2]));
        roles_blob.extend_from_slice(&pack_role(ROLE_PRODUCT_MANAGER, &[]));
        roles_blob.extend_from_slice(&pack_role(ROLE_TREASURY_MANAGER, &[]));
        roles_blob.extend_from_slice(&pack_role(role_compliance, &[]));

        // Build role-backed `PolicySpec`s at construction (even though 3 of the roles have 0 members!)
        let first_sh_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_SHAREHOLDER, 2, 50).unwrap())
            .unwrap();
        let super_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_SHAREHOLDER, 2, 50).unwrap())
            .unwrap();
        let board_spec = PolicySpec::new(100)
            .add_stage(
                StageSpec::for_role(ROLE_DIRECTOR, ROLE_ALL_MEMBERS_WEIGHT, 50).unwrap(),
            )
            .unwrap();
        let prod_mgmt_spec = PolicySpec::new(80)
            .add_stage(StageSpec::for_role(ROLE_PRODUCT_MANAGER, 1, 40).unwrap())
            .unwrap();
        let dual_review_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_PRODUCT_MANAGER, 1, 40).unwrap())
            .unwrap()
            .add_stage(StageSpec::for_role(role_compliance, 1, 40).unwrap())
            .unwrap();

        let pack_pol_entry = |pol_id: [u8; 32], spec: &PolicySpec| -> Vec<u8> {
            let mut buf = [0u8; 512];
            let n = spec.encode(&mut buf).unwrap();
            let mut v = Vec::new();
            v.extend_from_slice(&[0u8; 20]);
            v.extend_from_slice(&pol_id);
            v.extend_from_slice(&(n as u16).to_be_bytes());
            v.extend_from_slice(&buf[..n]);
            v
        };

        // Negative test 1: Policy referencing an UNDEFINED role (`role_auditor`) at construction MUST fail with ERR_ROLE_NOT_DEFINED (-93)!
        let bad_spec = PolicySpec::new(80)
            .add_stage(StageSpec::for_role(role_auditor, 1, 40).unwrap())
            .unwrap();
        let mut bad_pols = Vec::new();
        bad_pols.extend_from_slice(&2u16.to_be_bytes());
        bad_pols.extend_from_slice(&pack_pol_entry(POLICY_SUPER_GOVERNANCE, &super_spec));
        bad_pols.extend_from_slice(&pack_pol_entry(keccak256(b"BAD_POL"), &bad_spec));
        let bad_cd = encode_init_with_gov(reg, &roles_blob, &bad_pols, &[], &[]);
        assert_eq!(
            mock::transact_as(shareholder_1, con_bad, &bad_cd).unwrap_err(),
            ERR_ROLE_NOT_DEFINED
        );

        // Valid `policiesBlob`
        let mut policies_blob = Vec::new();
        policies_blob.extend_from_slice(&5u16.to_be_bytes());
        policies_blob.extend_from_slice(&pack_pol_entry(
            POLICY_FIRST_SHAREHOLDER_RESOLUTION,
            &first_sh_spec,
        ));
        policies_blob.extend_from_slice(&pack_pol_entry(POLICY_SUPER_GOVERNANCE, &super_spec));
        policies_blob.extend_from_slice(&pack_pol_entry(POLICY_BOARD_RESOLUTION, &board_spec));
        policies_blob.extend_from_slice(&pack_pol_entry(
            POLICY_PRODUCT_MANAGEMENT,
            &prod_mgmt_spec,
        ));
        policies_blob.extend_from_slice(&pack_pol_entry(policy_dual_review, &dual_review_spec));

        // Explicit per-function required authorization object bindings at construction
        let fn_rules = [
            FunctionAuthRule::new(
                SEL_ACTIVATE_CONSTITUTION,
                POLICY_FIRST_SHAREHOLDER_RESOLUTION,
            ),
            FunctionAuthRule::new(SEL_SET_FUNCTION_AUTH, POLICY_SUPER_GOVERNANCE),
            FunctionAuthRule::new(SEL_DEFINE_ROLE, POLICY_SUPER_GOVERNANCE),
            FunctionAuthRule::new(SEL_GRANT_ROLE, POLICY_BOARD_RESOLUTION),
            FunctionAuthRule::new(SEL_REVOKE_ROLE, POLICY_BOARD_RESOLUTION),
            FunctionAuthRule::new(SEL_UPSERT_PRODUCT, POLICY_PRODUCT_MANAGEMENT),
            FunctionAuthRule::new(SEL_RESTOCK_PRODUCT, POLICY_PRODUCT_MANAGEMENT),
            FunctionAuthRule::new(SEL_SET_PRODUCT_PRICE, POLICY_PRODUCT_MANAGEMENT),
        ];
        let mut fn_auths_blob = Vec::new();
        fn_auths_blob.extend_from_slice(&(fn_rules.len() as u16).to_be_bytes());
        for rule in &fn_rules {
            fn_auths_blob.extend_from_slice(&rule.encode());
        }

        let init_cd = encode_init_with_gov(reg, &roles_blob, &policies_blob, &fn_auths_blob, &[]);
        mock::transact_as(shareholder_1, con, &init_cd).unwrap();

        // Verify roles & authorization objects are already defined at construction (even with 0 members),
        // AND Constitution is in PENDING_RATIFICATION (1) (`isActive() == false`)!
        let is_def = |rid: [u8; 32]| -> bool {
            mock::transact_as(
                shareholder_1,
                con,
                CallEncoder::<64>::new(const { selector("isRoleDefined(bytes32)") })
                    .push_bytes32(&rid)
                    .as_slice(),
            )
            .unwrap()[31]
                == 1
        };
        assert!(is_def(ROLE_PRODUCT_MANAGER));
        assert!(is_def(ROLE_TREASURY_MANAGER));
        assert!(is_def(role_compliance));
        assert!(!is_def(role_auditor));

        let pm_cnt = mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<64>::new(const { selector("roleMemberCount(bytes32)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(pm_cnt[24..32].try_into().unwrap()), 0);

        // Negative test 2: Calling `grantRole` or `setFunctionAuth` BEFORE First Shareholder Resolution MUST fail with ERR_CONSTITUTION_NOT_ACTIVE (-91)!
        let grant_before_cd =
            CallEncoder::<128>::new(const { selector("grantRole(bytes32,address,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .push_address(&auth_grant_pm);
        assert_eq!(
            mock::transact_as(dir_1, con, grant_before_cd.as_slice()).unwrap_err(),
            ERR_CONSTITUTION_NOT_ACTIVE
        );

        // Pass the First Shareholder Resolution (`POLICY_FIRST_SHAREHOLDER_RESOLUTION`) to activate the Constitution!
        ratify_constitution_in_test(shareholder_1, con, auth_activate);

        // Negative test 3: Passing `activateConstitution` a second time MUST fail with ERR_CONSTITUTION_ALREADY_ACTIVE (-92)
        assert_eq!(
            mock::transact_as(
                shareholder_1,
                con,
                CallEncoder::<64>::new(const { selector("activateConstitution(address)") })
                    .push_address(&auth_activate)
                    .as_slice()
            )
            .unwrap_err(),
            ERR_CONSTITUTION_ALREADY_ACTIVE
        );

        // Directors grant `ROLE_PRODUCT_MANAGER` to `prod_mgr` using `POLICY_BOARD_RESOLUTION`
        let h_grant: [u8; 32] = mock::transact_as(
            dir_1,
            con,
            CallEncoder::<96>::new(const { selector("hashGrantRole(bytes32,address)") })
                .push_bytes32(&ROLE_PRODUCT_MANAGER)
                .push_address(&prod_mgr)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            dir_1,
            auth_grant_pm,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&POLICY_BOARD_RESOLUTION)
                .push_bytes32(&h_grant)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(dir_1, con, grant_before_cd.as_slice()).unwrap();

        // Execute `upsertProduct` using the configured `POLICY_PRODUCT_MANAGEMENT` Authorization object!
        let sku = keccak256(b"SKU_QUANTUM_HSM");
        let h_upsert: [u8; 32] = mock::transact_as(
            prod_mgr,
            con,
            CallEncoder::<512>::new(const {
                selector("hashConUpsertProduct(address,bytes32,uint64,uint64,bytes)")
            })
            .push_address(&prod_ledger)
            .push_bytes32(&sku)
            .push_u64(15)
            .push_u64(8_000)
            .push_u64(160)
            .push_dynamic_bytes_tail(b"Quantum HSM")
            .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        // Calling with `authObj == 0x0` in strict governance mode is rejected!
        let upsert_zero_cd = CallEncoder::<512>::new(const {
            selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)")
        })
        .push_address(&prod_ledger)
        .push_bytes32(&sku)
        .push_u64(15)
        .push_u64(8_000)
        .push_u64(192)
        .push_address(&[0u8; 20])
        .push_dynamic_bytes_tail(b"Quantum HSM");
        assert_eq!(
            mock::transact_as(prod_mgr, con, upsert_zero_cd.as_slice()).unwrap_err(),
            ERR_AUTH_CONSUME_FAILED
        );

        mock::transact_as(
            prod_mgr,
            auth_upsert_pm,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&POLICY_PRODUCT_MANAGEMENT)
                .push_bytes32(&h_upsert)
                .as_slice(),
        )
        .unwrap();
        let upsert_pm_cd = CallEncoder::<512>::new(const {
            selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)")
        })
        .push_address(&prod_ledger)
        .push_bytes32(&sku)
        .push_u64(15)
        .push_u64(8_000)
        .push_u64(192)
        .push_address(&auth_upsert_pm)
        .push_dynamic_bytes_tail(b"Quantum HSM");
        let res1 = mock::transact_as(prod_mgr, con, upsert_pm_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(res1[24..32].try_into().unwrap()), 1);

        // Now rotate `SEL_UPSERT_PRODUCT`'s required authorization object from `POLICY_PRODUCT_MANAGEMENT`
        // to `policy_dual_review` via `setFunctionAuth`, consuming `POLICY_SUPER_GOVERNANCE`!
        let h_set_fn: [u8; 32] = mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<96>::new(const { selector("hashSetFunctionAuth(bytes4,bytes32)") })
                .push_bytes4(&SEL_UPSERT_PRODUCT)
                .push_bytes32(&policy_dual_review)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            shareholder_1,
            auth_rotate_fn,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&POLICY_SUPER_GOVERNANCE)
                .push_bytes32(&h_set_fn)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<128>::new(const {
                selector("setFunctionAuth(bytes4,bytes32,address)")
            })
            .push_bytes4(&SEL_UPSERT_PRODUCT)
            .push_bytes32(&policy_dual_review)
            .push_address(&auth_rotate_fn)
            .as_slice(),
        )
        .unwrap();

        let cur_fn_pol: [u8; 32] = mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<64>::new(const { selector("getFunctionAuth(bytes4)") })
                .push_bytes4(&SEL_UPSERT_PRODUCT)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(cur_fn_pol, policy_dual_review);

        // Old `POLICY_PRODUCT_MANAGEMENT` auth object is now REJECTED (`-66`) on `upsertProduct`!
        mock::transact_as(
            prod_mgr,
            auth_stale_pm,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&POLICY_PRODUCT_MANAGEMENT)
                .push_bytes32(&h_upsert)
                .as_slice(),
        )
        .unwrap();
        let upsert_stale_cd = CallEncoder::<512>::new(const {
            selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)")
        })
        .push_address(&prod_ledger)
        .push_bytes32(&sku)
        .push_u64(15)
        .push_u64(8_000)
        .push_u64(192)
        .push_address(&auth_stale_pm)
        .push_dynamic_bytes_tail(b"Quantum HSM");
        assert_eq!(
            mock::transact_as(prod_mgr, con, upsert_stale_cd.as_slice()).unwrap_err(),
            -66
        );

        // New `policy_dual_review` auth object SUCCEEDS!
        mock::transact_as(
            compliance_officer,
            auth_upsert_dual,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&policy_dual_review)
                .push_bytes32(&h_upsert)
                .as_slice(),
        )
        .unwrap();
        let upsert_dual_cd = CallEncoder::<512>::new(const {
            selector("upsertProduct(address,bytes32,uint64,uint64,bytes,address)")
        })
        .push_address(&prod_ledger)
        .push_bytes32(&sku)
        .push_u64(15)
        .push_u64(8_000)
        .push_u64(192)
        .push_address(&auth_upsert_dual)
        .push_dynamic_bytes_tail(b"Quantum HSM");
        let res2 = mock::transact_as(compliance_officer, con, upsert_dual_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(res2[24..32].try_into().unwrap()), 2);

        // Define `role_auditor` post-activation via `defineRole` (consuming `POLICY_SUPER_GOVERNANCE`)
        let h_def_role: [u8; 32] = mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<64>::new(const { selector("hashDefineRole(bytes32)") })
                .push_bytes32(&role_auditor)
                .as_slice(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        mock::transact_as(
            shareholder_1,
            auth_def_role,
            CallEncoder::<96>::new(const { selector("arm(bytes32,bytes32)") })
                .push_bytes32(&POLICY_SUPER_GOVERNANCE)
                .push_bytes32(&h_def_role)
                .as_slice(),
        )
        .unwrap();
        let role_cnt_out = mock::transact_as(
            shareholder_1,
            con,
            CallEncoder::<96>::new(const { selector("defineRole(bytes32,address)") })
                .push_bytes32(&role_auditor)
                .push_address(&auth_def_role)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(role_cnt_out[24..32].try_into().unwrap()), 6);
        assert!(is_def(role_auditor));
    }
}
