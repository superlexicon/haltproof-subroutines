//! Corporate Charter **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Pure constitutional & corporate governance root of trust for an institutional entity:
//! 1. **Ratification Lifecycle State**: Starts in `CHARTER_STATE_PENDING_RATIFICATION (1)` upon
//!    construction (`initialize` or `initializeWithGovernance`). All non-ratification governance
//!    mutations and sibling-module operations remain inactive until the **First Shareholder Resolution**
//!    (`activateCharter(address)`) transitions the Charter to `CHARTER_STATE_ACTIVE (2)`.
//! 2. **Authorized Share Capital Structure (Option 4A)**: Stores authorized `ShareClassSpec`s
//!    (share `AssetLedger` address, `votesPerShare`, and `conversionNumer / conversionDenom` to
//!    Common Shares) and computes cross-class `shareholderVotingPower` & `convertedCommonTotals`.
//! 3. **Corporate Organs & Pre-Defined Roles**: Manages the Board of Directors (`addDirector`,
//!    `removeDirector`) and organizational roles (`defineRole`, `grantRole`, `revokeRole`, `hasRole`),
//!    supporting roles defined at construction with `0` initial members.
//! 4. **Bylaw Policies & Scoped Per-Function Authority Matrix**: Stores sequential/weighted/role-backed
//!    `PolicySpec`s and maps `(targetHps, fnSelector) -> policyId` (`setFunctionAuth` / `getFunctionAuth`)
//!    both for `CorporateCharter` itself and for attached company subroutines (`ShareCapital`,
//!    `ProductLedger`, `AccountingLedger`, `AssetLedger`).
//! 5. **Authorized Company Module Registry**: Tracks governed module capabilities
//!    (`authorizeModule` / `isAuthorizedModule`, e.g. `CAP_EQUITY_SETTLEMENT` for `ShareCapital`,
//!    `CAP_MERCHANT_PAYMENT` for `ProductLedger`) so pinned `AssetLedger` and `Authorization`
//!    instances preserve single-Charter pinning without commingling operational state into the Charter.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    compute_sha_doc_hash, require_valid_authorization_hps, require_valid_identity,
    verify_and_consume_auth, ActionHasher, AuthorizedModuleSpec, FunctionAuthRule, PolicySpec,
    ShareClassSpec, StageSpec, ACTION_ACTIVATE_CHARTER, ACTION_ADD_DIRECTOR,
    ACTION_AUTHORIZE_MODULE, ACTION_DEFINE_ROLE, ACTION_GRANT_ROLE, ACTION_REGISTER_SHARE_CLASS,
    ACTION_REMOVE_DIRECTOR, ACTION_REVOKE_ROLE, ACTION_SET_FUNCTION_AUTH, CAP_EQUITY_SETTLEMENT,
    CHARTER_STATE_ACTIVE, CHARTER_STATE_PENDING_RATIFICATION, CHARTER_STATE_UNINITIALIZED,
    ERR_CHARTER_ALREADY_ACTIVE, ERR_CHARTER_NOT_ACTIVE, ERR_DIRECTOR_CONSENT_REQUIRED,
    ERR_FUNCTION_AUTH_NOT_SET, ERR_NO_BIDS_IN_STAGE, ERR_POLICY_INVALID, ERR_ROLE_NOT_DEFINED,
    ERR_SHA_SIGNATURE_REQUIRED, ERR_UNAUTHORIZED_MODULE, MAX_AUTHORIZED_MODULES, MAX_DEFINED_ROLES,
    MAX_ENCODED_POLICY_BYTES, MAX_MEMBERS_PER_STAGE, MAX_SHARE_CLASSES, POLICY_BANK_ORACLE,
    POLICY_BOARD_RESOLUTION, POLICY_FIRST_SHAREHOLDER_RESOLUTION, POLICY_PRODUCT_MANAGEMENT,
    POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SHARE_ISSUANCE_AUCTION,
    POLICY_SHARE_TRANSFER_AUCTION, POLICY_SUPER_GOVERNANCE, ROLE_BANK_ORACLE, ROLE_DIRECTOR,
    ROLE_PRODUCT_MANAGER, ROLE_SHAREHOLDER, ROLE_TREASURY_MANAGER,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const CHARTER_INITIALIZED: [u8; 32] = event_topic("CharterInitialized(address,uint64)");
const CHARTER_ACTIVATED: [u8; 32] = event_topic("CharterActivated(address,address,uint64)");
const POLICY_SET: [u8; 32] = event_topic("PolicySet(address,bytes32,uint64,uint64)");
const POLICY_DEACTIVATED: [u8; 32] = event_topic("PolicyDeactivated(address,bytes32)");
const DIRECTOR_ADDED: [u8; 32] = event_topic("DirectorAdded(address,uint64,address)");
const DIRECTOR_REMOVED: [u8; 32] = event_topic("DirectorRemoved(address,uint64,address)");
const DIRECTOR_CONSENTED: [u8; 32] = event_topic("DirectorConsented(address,uint64)");
const DIRECTOR_PENDING_CONSENT: [u8; 32] =
    event_topic("DirectorPendingConsent(address,address,uint64)");
const ROLE_DEFINED: [u8; 32] = event_topic("RoleDefined(bytes32,address,uint64)");
const ROLE_GRANTED: [u8; 32] = event_topic("RoleGranted(bytes32,address,address,uint64)");
const ROLE_REVOKED: [u8; 32] = event_topic("RoleRevoked(bytes32,address,address,uint64)");
const FUNCTION_AUTH_UPDATED: [u8; 32] =
    event_topic("FunctionAuthUpdated(address,bytes4,bytes32,bytes32)");
const MODULE_AUTHORIZED: [u8; 32] = event_topic("ModuleAuthorized(address,bytes32,bool,address)");
const SHARE_CLASS_REGISTERED: [u8; 32] =
    event_topic("ShareClassRegistered(address,uint64,uint64,uint64)");

const TAG_SET_POLICY: [u8; 32] = keccak256(b"CHARTER_SET_POLICY");
const TAG_DEACTIVATE_POLICY: [u8; 32] = keccak256(b"CHARTER_DEACTIVATE_POLICY");

const SEL_ACTIVATE_CHARTER: [u8; 4] = selector("activateCharter(address)");
const SEL_SET_FUNCTION_AUTH: [u8; 4] =
    selector("setFunctionAuth(address,bytes4,bytes32,address)");
const SEL_AUTHORIZE_MODULE: [u8; 4] =
    selector("authorizeModule(address,bytes32,bool,address)");
const SEL_DEFINE_ROLE: [u8; 4] = selector("defineRole(bytes32,address)");
const SEL_SET_POLICY: [u8; 4] = selector("setPolicy(address,bytes32,bytes,address)");
const SEL_DEACTIVATE_POLICY: [u8; 4] = selector("deactivatePolicy(address,bytes32,address)");
const SEL_ADD_DIRECTOR: [u8; 4] = selector("addDirector(address,address)");
const SEL_REMOVE_DIRECTOR: [u8; 4] = selector("removeDirector(address,address)");
const SEL_GRANT_ROLE: [u8; 4] = selector("grantRole(bytes32,address,address)");
const SEL_REVOKE_ROLE: [u8; 4] = selector("revokeRole(bytes32,address,address)");
const SEL_REGISTER_SHARE_CLASS: [u8; 4] =
    selector("registerShareClass(address,uint64,uint64,uint64,address)");

const KEY_INIT: &[u8] = b"chr:init";
const KEY_STATE: &[u8] = b"chr:state";
const KEY_ACTIVATED_BLOCK: &[u8] = b"chr:act_blk";
const KEY_ACTIVATION_AUTH: &[u8] = b"chr:act_auth";
const KEY_DEFINED_ROLES_COUNT: &[u8] = b"chr:role_cnt";
const KEY_REGISTRY: &[u8] = b"chr:reg";
const KEY_INITIALIZER: &[u8] = b"chr:init_by";
const KEY_DIRECTORS_BLOB: &[u8] = b"chr:directors";
const KEY_PENDING_DIRECTORS_BLOB: &[u8] = b"chr:dpend_list";
const KEY_BOARD_EXPIRY: &[u8] = b"chr:board_exp";
const KEY_SHARE_CLASSES_BLOB: &[u8] = b"chr:sh_classes";

hps_entry! {
    "initialize(address,bytes)"                                                 => handle_initialize,
    "initializeWithGovernance(address,bytes,bytes,bytes,bytes)"                 => handle_initialize_with_governance_5,
    "initializeWithGovernance(address,bytes,bytes,bytes,bytes,bytes)"           => handle_initialize_with_governance_6,
    "activateCharter(address)"                                                  => handle_activate_charter,
    "state()"                                                                   => handle_state,
    "isActive()"                                                                => handle_is_active,
    "isValid()"                                                                 => handle_is_active,
    "activatedAtBlock()"                                                        => handle_activated_at_block,
    "setFunctionAuth(address,bytes4,bytes32,address)"                           => handle_set_function_auth,
    "getFunctionAuth(address,bytes4)"                                           => handle_get_function_auth,
    "authorizeModule(address,bytes32,bool,address)"                             => handle_authorize_module,
    "isAuthorizedModule(address,bytes32)"                                       => handle_is_authorized_module,
    "defineRole(bytes32,address)"                                               => handle_define_role,
    "isRoleDefined(bytes32)"                                                    => handle_is_role_defined,
    "definedRoleCount()"                                                        => handle_defined_role_count,
    "definedRoleAt(uint64)"                                                     => handle_defined_role_at,
    "setPolicy(address,bytes32,bytes,address)"                                  => handle_set_policy,
    "deactivatePolicy(address,bytes32,address)"                                 => handle_deactivate_policy,
    "addDirector(address,address)"                                              => handle_add_director,
    "removeDirector(address,address)"                                           => handle_remove_director,
    "consentToDirectorship()"                                                   => handle_consent_to_directorship,
    "hasDirectorConsented(address)"                                             => handle_has_director_consented,
    "allDirectorsConsented()"                                                   => handle_all_directors_consented,
    "unconsentedDirectorCount()"                                                => handle_unconsented_director_count,
    "isDirector(address)"                                                       => handle_is_director,
    "directorCount()"                                                           => handle_director_count,
    "directorAt(uint64)"                                                        => handle_director_at,
    "isPendingDirector(address)"                                                => handle_is_pending_director,
    "pendingDirectorCount()"                                                    => handle_pending_director_count,
    "pendingDirectorAt(uint64)"                                                 => handle_pending_director_at,
    "grantRole(bytes32,address,address)"                                        => handle_grant_role,
    "revokeRole(bytes32,address,address)"                                       => handle_revoke_role,
    "hasRole(bytes32,address)"                                                  => handle_has_role,
    "roleMemberCount(bytes32)"                                                  => handle_role_member_count,
    "roleMemberAt(bytes32,uint64)"                                              => handle_role_member_at,
    "registerShareClass(address,uint64,uint64,uint64,address)"                  => handle_register_share_class,
    "moduleEnsureShareClass(address,uint64,uint64,uint64)"                      => handle_module_ensure_share_class,
    "moduleSetShareClassLabel(address,bytes32)"                                 => handle_module_set_share_class_label,
    "shareClassLabel(address)"                                                  => handle_share_class_label,
    "moduleRecordShareholdersAgreement(address,bytes32)"                        => handle_module_record_sha,
    "signShareholdersAgreement(bytes32)"                                        => handle_sign_sha_direct,
    "hasSignedShareholdersAgreement(address)"                                   => handle_has_signed_sha,
    "shaDocumentHash()"                                                         => handle_sha_document_hash,
    "shareClassCount()"                                                         => handle_share_class_count,
    "getShareClass(uint64)"                                                     => handle_get_share_class,
    "shareholderVotingPower(address)"                                           => handle_shareholder_voting_power,
    "convertedCommonTotals(address)"                                            => handle_converted_common_totals,
    "getPolicyRaw(address,bytes32)"                                             => handle_get_policy_raw,
    "hasPolicy(address,bytes32)"                                                => handle_has_policy,
    "validateCapitalProcessAuth(address)"                                       => handle_validate_capital_process_auth,
    "identityRegistry()"                                                        => handle_identity_registry,
    "hashActivateCharter()"                                                     => handle_hash_activate_charter,
    "hashSetFunctionAuth(address,bytes4,bytes32)"                               => handle_hash_set_function_auth,
    "hashAuthorizeModule(address,bytes32,bool)"                                 => handle_hash_authorize_module,
    "hashDefineRole(bytes32)"                                                   => handle_hash_define_role,
    "hashSetPolicy(address,bytes32,bytes)"                                      => handle_hash_set_policy,
    "hashDeactivatePolicy(address,bytes32)"                                     => handle_hash_deactivate_policy,
    "hashAddDirector(address)"                                                  => handle_hash_add_director,
    "hashRemoveDirector(address)"                                               => handle_hash_remove_director,
    "hashGrantRole(bytes32,address)"                                            => handle_hash_grant_role,
    "hashRevokeRole(bytes32,address)"                                           => handle_hash_revoke_role,
    "hashRegisterShareClass(address,uint64,uint64,uint64)"                      => handle_hash_register_share_class,
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

fn fn_auth_key(target_hps: &[u8; 20], fn_selector: &[u8; 4]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"fnau:")
        .push(target_hps)
        .push(fn_selector)
}

fn fn_auth_explicit_key(target_hps: &[u8; 20], fn_selector: &[u8; 4]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"fnex:")
        .push(target_hps)
        .push(fn_selector)
}

fn module_auth_key(module_hps: &[u8; 20], capability: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"mod:")
        .push(module_hps)
        .push(capability)
}

fn module_configured_key(module_hps: &[u8; 20], capability: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"mcfg:")
        .push(module_hps)
        .push(capability)
}

fn normalize_target(target_hps: &[u8; 20], me: &[u8; 20]) -> [u8; 20] {
    if target_hps == me {
        [0u8; 20]
    } else {
        *target_hps
    }
}

fn store_function_auth(
    target_hps: &[u8; 20],
    fn_selector: &[u8; 4],
    policy_id: &[u8; 32],
    explicit: bool,
) {
    let me = context::self_address();
    let norm = normalize_target(target_hps, &me);
    storage::set(fn_auth_key(&norm, fn_selector).as_slice(), policy_id);
    if explicit {
        storage::set_u64(fn_auth_explicit_key(&norm, fn_selector).as_slice(), 1);
    }
}

fn is_fn_auth_explicit(target_hps: &[u8; 20], fn_selector: &[u8; 4]) -> bool {
    let me = context::self_address();
    let norm = normalize_target(target_hps, &me);
    storage::get_u64(fn_auth_explicit_key(&norm, fn_selector).as_slice()) == 1
}

fn get_function_auth(target_hps: &[u8; 20], fn_selector: &[u8; 4]) -> Option<[u8; 32]> {
    let me = context::self_address();
    let norm = normalize_target(target_hps, &me);
    if let Some(p) = storage::get_bytes32(fn_auth_key(&norm, fn_selector).as_slice()) {
        if p != [0u8; 32] {
            return Some(p);
        }
    }
    if norm != [0u8; 20] {
        if let Some(p) = storage::get_bytes32(fn_auth_key(&[0u8; 20], fn_selector).as_slice()) {
            if p != [0u8; 32] {
                return Some(p);
            }
        }
    }
    None
}

fn require_charter_function_auth(fn_selector: &[u8; 4]) -> Result<[u8; 32], i32> {
    get_function_auth(&[0u8; 20], fn_selector).ok_or(ERR_FUNCTION_AUTH_NOT_SET)
}

fn policy_exists_for(target_hps: &[u8; 20], policy_id: &[u8; 32]) -> bool {
    if *policy_id == [0u8; 32] {
        return false;
    }
    storage::exists(policy_key(target_hps, policy_id).as_slice())
        || (*target_hps != [0u8; 20]
            && storage::exists(policy_key(&[0u8; 20], policy_id).as_slice()))
}

fn role_defined_key(role_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rdef:").push(role_id)
}

fn defined_role_at_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"ridx:").push_u64_be(idx)
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
        // Every role required by any stage MUST already be defined in this CorporateCharter
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

fn compute_activate_charter_hash() -> [u8; 32] {
    ActionHasher::<96>::new(&context::self_address(), &ACTION_ACTIVATE_CHARTER).finish()
}

fn compute_set_function_auth_hash(
    target_hps: &[u8; 20],
    fn_selector: &[u8; 4],
    policy_id: &[u8; 32],
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_SET_FUNCTION_AUTH)
        .push_address(target_hps)
        .push_raw(fn_selector)
        .push_bytes32(policy_id)
        .finish()
}

fn compute_authorize_module_hash(
    module_hps: &[u8; 20],
    capability: &[u8; 32],
    active: bool,
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_AUTHORIZE_MODULE)
        .push_address(module_hps)
        .push_bytes32(capability)
        .push_u64(u64::from(active))
        .finish()
}

fn compute_define_role_hash(role_id: &[u8; 32]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &ACTION_DEFINE_ROLE)
        .push_bytes32(role_id)
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

/// Compute `(shareholder_converted_common_shares, company_total_converted_common_shares)` summed
/// across all registered share classes in this `CorporateCharter`.
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

/// Define a role in the CorporateCharter (`rdef:<role_id> = 1`) and ensure a role-backed 1-of-N
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

    let stage = StageSpec::for_role(*role_id, 1, exp).ok_or(ERR_POLICY_INVALID)?;
    let spec = PolicySpec::new(exp.saturating_mul(2))
        .add_stage(stage)
        .ok_or(ERR_POLICY_INVALID)?;
    let mut enc = [0u8; MAX_ENCODED_POLICY_BYTES];
    let enc_len = spec.encode(&mut enc).ok_or(ERR_POLICY_INVALID)?;

    let pk = policy_key(&[0u8; 20], role_id);
    if !storage::exists(pk.as_slice()) {
        store_policy(&[0u8; 20], role_id, &enc[..enc_len], &spec);
    }
    if *role_id == ROLE_PRODUCT_MANAGER
        && !storage::exists(policy_key(&[0u8; 20], &POLICY_PRODUCT_MANAGEMENT).as_slice())
    {
        store_policy(
            &[0u8; 20],
            &POLICY_PRODUCT_MANAGEMENT,
            &enc[..enc_len],
            &spec,
        );
    }
    if *role_id == ROLE_BANK_ORACLE
        && !storage::exists(policy_key(&[0u8; 20], &POLICY_BANK_ORACLE).as_slice())
    {
        store_policy(&[0u8; 20], &POLICY_BANK_ORACLE, &enc[..enc_len], &spec);
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

fn director_consent_key(account: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"chr:dcon:").push(account)
}

fn director_pending_key(account: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"chr:dpend:").push(account)
}

fn director_pending_auth_key(account: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"chr:dpaut:").push(account)
}

fn has_director_consented(account: &[u8; 20]) -> bool {
    *account != [0u8; 20] && storage::get_u64(director_consent_key(account).as_slice()) == 1
}

fn set_director_consented(account: &[u8; 20], consented: bool) {
    storage::set_u64(
        director_consent_key(account).as_slice(),
        u64::from(consented),
    );
}

fn load_pending_directors(out: &mut [[u8; 20]; MAX_MEMBERS_PER_STAGE]) -> usize {
    let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
    let Some(n) = storage::get_into(KEY_PENDING_DIRECTORS_BLOB, &mut raw) else {
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

fn save_pending_directors(pending: &[[u8; 20]; MAX_MEMBERS_PER_STAGE], count: usize) {
    if count == 0 {
        storage::set(KEY_PENDING_DIRECTORS_BLOB, &[]);
    } else {
        let mut raw = [0u8; MAX_MEMBERS_PER_STAGE * 20];
        let mut i = 0;
        while i < count {
            raw[i * 20..(i + 1) * 20].copy_from_slice(&pending[i]);
            i += 1;
        }
        storage::set(KEY_PENDING_DIRECTORS_BLOB, &raw[..count * 20]);
    }
}

fn remove_pending_director(account: &[u8; 20]) -> bool {
    storage::set_u64(director_pending_key(account).as_slice(), 0);
    let mut pending = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_pending_directors(&mut pending);
    let mut found: Option<usize> = None;
    let mut i = 0;
    while i < count {
        if &pending[i] == account {
            found = Some(i);
            break;
        }
        i += 1;
    }
    if let Some(idx) = found {
        let mut j = idx;
        while j + 1 < count {
            pending[j] = pending[j + 1];
            j += 1;
        }
        pending[count - 1] = [0u8; 20];
        save_pending_directors(&pending, count - 1);
        true
    } else {
        false
    }
}

fn seed_initial_director_consents(caller: &[u8; 20]) {
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    let now = context::block_number();
    let mut i = 0;
    while i < count {
        if &dirs[i] == caller {
            set_director_consented(caller, true);
            events::emit(&[DIRECTOR_CONSENTED, addr_topic(caller)], &now.to_be_bytes());
        } else {
            events::emit(
                &[
                    DIRECTOR_PENDING_CONSENT,
                    addr_topic(&dirs[i]),
                    addr_topic(&[0u8; 20]),
                ],
                &now.to_be_bytes(),
            );
        }
        i += 1;
    }
}

fn count_unconsented_directors() -> usize {
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    let mut missing = 0usize;
    let mut i = 0;
    while i < count {
        if !has_director_consented(&dirs[i]) {
            missing += 1;
        }
        i += 1;
    }
    missing
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

/// Seed default `([0u8; 20], fn_selector) -> policy_id` mappings for Charter governance functions
/// not explicitly overridden at construction.
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

    let defaults: [([u8; 4], [u8; 32]); 12] = [
        (SEL_ACTIVATE_CHARTER, activate_pol),
        (SEL_SET_FUNCTION_AUTH, super_pol),
        (SEL_AUTHORIZE_MODULE, board_pol),
        (SEL_DEFINE_ROLE, super_pol),
        (SEL_SET_POLICY, super_pol),
        (SEL_DEACTIVATE_POLICY, super_pol),
        (SEL_ADD_DIRECTOR, super_pol),
        (SEL_REMOVE_DIRECTOR, super_pol),
        (SEL_REGISTER_SHARE_CLASS, super_pol),
        (SEL_GRANT_ROLE, board_pol),
        (SEL_REVOKE_ROLE, board_pol),
        (
            const { selector("authorizeFuturesUnderwriting(address,uint64,address)") },
            super_pol,
        ),
    ];

    let mut i = 0;
    while i < defaults.len() {
        let (sel, pol) = defaults[i];
        if pol != [0u8; 32] && get_function_auth(&[0u8; 20], &sel).is_none() {
            store_function_auth(&[0u8; 20], &sel, &pol, false);
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
    if storage::get_u64(KEY_STATE) != CHARTER_STATE_ACTIVE {
        return Err(ERR_CHARTER_NOT_ACTIVE);
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
    let count = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    if count == 0 || count > 64 {
        return Err(-59);
    }

    let me = context::self_address();
    let mut pos = 2usize;
    let mut has_super = false;
    let mut i = 0;

    while i < count {
        if pos + 54 > blob.len() {
            return Err(-60);
        }
        let mut target = [0u8; 20];
        target.copy_from_slice(&blob[pos..pos + 20]);
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&blob[pos + 20..pos + 52]);
        let spec_len = u16::from_be_bytes([blob[pos + 52], blob[pos + 53]]) as usize;
        pos += 54;

        if policy_id == [0u8; 32] || pos + spec_len > blob.len() {
            return Err(-60);
        }
        let raw_spec = &blob[pos..pos + spec_len];
        pos += spec_len;

        let spec = validate_and_verify_spec_cached(registry, raw_spec, verified, verified_len)?;
        if (policy_id == POLICY_SUPER_GOVERNANCE || policy_id == POLICY_SHAREHOLDER_SUPERMAJORITY)
            && (target == [0u8; 20] || target == me)
        {
            has_super = true;
        }
        store_policy(&target, &policy_id, raw_spec, &spec);

        if policy_id == POLICY_BOARD_RESOLUTION
            && (target == [0u8; 20] || target == me)
            && spec.stage_count >= 1
            && spec.stages[0].member_count > 0
        {
            let st0 = &spec.stages[0];
            let mut init_dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
            let mut d = 0;
            while d < st0.member_count {
                init_dirs[d] = st0.members[d].identity;
                d += 1;
            }
            let mut raw_dirs = [0u8; MAX_MEMBERS_PER_STAGE * 20];
            let mut r = 0;
            while r < st0.member_count {
                raw_dirs[r * 20..(r + 1) * 20].copy_from_slice(&init_dirs[r]);
                r += 1;
            }
            storage::set(KEY_DIRECTORS_BLOB, &raw_dirs[..st0.member_count * 20]);
            storage::set_u64(KEY_BOARD_EXPIRY, st0.expiry_blocks);
            sync_director_role_members(&init_dirs, st0.member_count)?;
        }
        i += 1;
    }

    if pos != blob.len() {
        return Err(-60);
    }
    Ok((count, has_super))
}

/// Genesis initializer (2-argument form with canonical pre-defined roles and default per-function
/// authorization mappings).
/// Starts in `CHARTER_STATE_PENDING_RATIFICATION (1)` — a First Shareholder Resolution
/// (`activateCharter(address)`) MUST be passed to activate this CorporateCharter!
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58);
    }
    let registry = args.address(0).ok_or(-3)?;
    let blob = args.dynamic_bytes(1).ok_or(-3)?;
    if registry == [0u8; 20] || blob.len() < 2 {
        return Err(-59);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

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
    storage::set_address(KEY_INITIALIZER, &caller);
    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, CHARTER_STATE_PENDING_RATIFICATION);
    seed_initial_director_consents(&caller);

    events::emit(
        &[CHARTER_INITIALIZED, addr_topic(&registry)],
        &(count as u64).to_be_bytes(),
    );
    Ok(())
}

fn handle_initialize_with_governance_5(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let roles_blob = args.dynamic_bytes(1).ok_or(-3)?;
    let policies_blob = args.dynamic_bytes(2).ok_or(-3)?;
    let fn_auths_blob = args.dynamic_bytes(3).ok_or(-3)?;
    let share_classes_blob = args.dynamic_bytes(4).ok_or(-3)?;
    execute_initialize_with_governance(
        &registry,
        roles_blob,
        policies_blob,
        fn_auths_blob,
        share_classes_blob,
        &[],
    )
}

fn handle_initialize_with_governance_6(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let roles_blob = args.dynamic_bytes(1).ok_or(-3)?;
    let policies_blob = args.dynamic_bytes(2).ok_or(-3)?;
    let fn_auths_blob = args.dynamic_bytes(3).ok_or(-3)?;
    let share_classes_blob = args.dynamic_bytes(4).ok_or(-3)?;
    let modules_blob = args.dynamic_bytes(5).ok_or(-3)?;
    execute_initialize_with_governance(
        &registry,
        roles_blob,
        policies_blob,
        fn_auths_blob,
        share_classes_blob,
        modules_blob,
    )
}

/// Full institutional constructor defining at construction:
/// 1. `registry`: `IdentityRegistry` HPS address.
/// 2. `roles_blob`: `[role_count: u16 BE]` + per role `[role_id: 32B][member_count: u16 BE][members: member_count * 20B]`
///    (`member_count` MAY be `0` so all roles required by authorization processes are defined up front).
/// 3. `policies_blob`: `[policy_count: u16 BE]` + per policy `[target_hps: 20B][policy_id: 32B][spec_len: u16 BE][spec]`.
/// 4. `fn_auths_blob`: `[fn_count: u16 BE]` + `fn_count * 56B` (`FunctionAuthRule`: `[target_hps: 20B][fn_selector: 4B][policy_id: 32B]`).
/// 5. `share_classes_blob`: empty `&[]` OR `[class_count: u16 BE]` + `class_count * 44B` (`ShareClassSpec`).
/// 6. `modules_blob`: empty `&[]` OR `[mod_count: u16 BE]` + `mod_count * 52B` (`AuthorizedModuleSpec`).
///
/// Leaves `CorporateCharter` in `CHARTER_STATE_PENDING_RATIFICATION (1)` until `activateCharter(address)` passes!
fn execute_initialize_with_governance(
    registry: &[u8; 20],
    roles_blob: &[u8],
    policies_blob: &[u8],
    fn_auths_blob: &[u8],
    share_classes_blob: &[u8],
    modules_blob: &[u8],
) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58);
    }
    if *registry == [0u8; 20] || roles_blob.len() < 2 || policies_blob.len() < 2 {
        return Err(-59);
    }

    let caller = context::msg_sender();
    require_valid_identity(registry, &caller)?;

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
                require_valid_identity(registry, &acct)?;
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
            let mut raw_dirs = [0u8; MAX_MEMBERS_PER_STAGE * 20];
            let mut d = 0;
            while d < m_cnt {
                raw_dirs[d * 20..(d + 1) * 20].copy_from_slice(&members[d]);
                d += 1;
            }
            storage::set(KEY_DIRECTORS_BLOB, &raw_dirs[..m_cnt * 20]);
            storage::set_u64(KEY_BOARD_EXPIRY, 50);
        }
        r += 1;
    }
    if rpos != roles_blob.len() {
        return Err(-60);
    }

    // 2. Parse & store all policies (verifying every StageRole is defined in this CorporateCharter!)
    let (pol_count, _has_super) =
        parse_and_store_policies_blob(registry, policies_blob, &mut verified, &mut verified_len)?;

    let me = context::self_address();

    // 3. Parse & store explicit scoped per-function authorization rules `(targetHps, fnSelector) -> policyId`
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
            let check_target = if rule.target_hps == [0u8; 20] {
                me
            } else {
                rule.target_hps
            };
            if !policy_exists_for(&check_target, &rule.policy_id) {
                return Err(ERR_POLICY_INVALID);
            }
            store_function_auth(&rule.target_hps, &rule.fn_selector, &rule.policy_id, true);
            fpos += FunctionAuthRule::ENCODED_LEN;
            f += 1;
        }
    }

    seed_default_function_auths(&me);

    let act_pol = require_charter_function_auth(&SEL_ACTIVATE_CHARTER)?;
    let gov_pol = require_charter_function_auth(&SEL_SET_FUNCTION_AUTH)?;
    if !policy_exists_for(&me, &act_pol) || !policy_exists_for(&me, &gov_pol) {
        return Err(ERR_POLICY_INVALID);
    }

    // 4. Optional initial authorized share classes (Option 4A)
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

    // 5. Optional initial authorized sibling company modules (`ShareCapital`, `ProductLedger`, etc.)
    if !modules_blob.is_empty() {
        if modules_blob.len() < 2 {
            return Err(-59);
        }
        let mod_count = u16::from_be_bytes([modules_blob[0], modules_blob[1]]) as usize;
        if mod_count > MAX_AUTHORIZED_MODULES
            || 2 + mod_count * AuthorizedModuleSpec::ENCODED_LEN != modules_blob.len()
        {
            return Err(-60);
        }
        let mut mpos = 2usize;
        let mut m = 0usize;
        while m < mod_count {
            let spec = AuthorizedModuleSpec::decode(
                &modules_blob[mpos..mpos + AuthorizedModuleSpec::ENCODED_LEN],
            )
            .ok_or(-59)?;
            storage::set_u64(
                module_auth_key(&spec.module_hps, &spec.capability).as_slice(),
                1,
            );
            storage::set_u64(
                module_configured_key(&spec.module_hps, &spec.capability).as_slice(),
                1,
            );
            mpos += AuthorizedModuleSpec::ENCODED_LEN;
            m += 1;
        }
    }

    storage::set_address(KEY_REGISTRY, registry);
    storage::set_address(KEY_INITIALIZER, &caller);
    storage::set_u64(KEY_INIT, 1);
    storage::set_u64(KEY_STATE, CHARTER_STATE_PENDING_RATIFICATION);
    seed_initial_director_consents(&caller);

    events::emit(
        &[CHARTER_INITIALIZED, addr_topic(registry)],
        &(pol_count as u64).to_be_bytes(),
    );
    Ok(())
}

/// Pass the **First Shareholder Resolution** to ratify and activate a newly created `CorporateCharter`,
/// transitioning its state from `CHARTER_STATE_PENDING_RATIFICATION (1)` to `CHARTER_STATE_ACTIVE (2)`.
///
/// Constitutional Rule: In addition to the required Shareholder Super-Majority (`shareholder_auth`),
/// **every named Initial Director** must have signed `consentToDirectorship()` (the incorporating
/// `caller` is auto-consented at construction; any additional Initial Directors must consent on-chain).
/// Minority non-director shareholders do not block activation once `>= 75%` shareholders ratify.
fn handle_activate_charter(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_any_state_caller()?;
    let st = storage::get_u64(KEY_STATE);
    if st == CHARTER_STATE_ACTIVE {
        return Err(ERR_CHARTER_ALREADY_ACTIVE);
    }
    if st != CHARTER_STATE_PENDING_RATIFICATION {
        return Err(ERR_CHARTER_NOT_ACTIVE);
    }

    // If caller happens to be an initial director invoking activateCharter directly, count their signature as consent too
    let mut init_dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let init_dir_cnt = load_directors(&mut init_dirs);
    let mut d = 0;
    while d < init_dir_cnt {
        if init_dirs[d] == caller && !has_director_consented(&caller) {
            set_director_consented(&caller, true);
            events::emit(
                &[DIRECTOR_CONSENTED, addr_topic(&caller)],
                &context::block_number().to_be_bytes(),
            );
        }
        d += 1;
    }

    if count_unconsented_directors() > 0 {
        return Err(ERR_DIRECTOR_CONSENT_REQUIRED);
    }

    let shareholder_auth = args.address(0).ok_or(-3)?;
    let req_pol = require_charter_function_auth(&SEL_ACTIVATE_CHARTER)?;
    let action_hash = compute_activate_charter_hash();
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
    storage::set_u64(KEY_STATE, CHARTER_STATE_ACTIVE);
    storage::set_u64(KEY_ACTIVATED_BLOCK, now);
    storage::set_address(KEY_ACTIVATION_AUTH, &shareholder_auth);

    events::emit(
        &[
            CHARTER_ACTIVATED,
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
        ret::write_u64_word(CHARTER_STATE_UNINITIALIZED);
    } else {
        ret::write_u64_word(storage::get_u64(KEY_STATE));
    }
    Ok(())
}

fn handle_is_active(_args: &CalldataReader) -> Result<(), i32> {
    let active =
        storage::get_u64(KEY_INIT) == 1 && storage::get_u64(KEY_STATE) == CHARTER_STATE_ACTIVE;
    ret::write_bool(active);
    Ok(())
}

fn handle_activated_at_block(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ACTIVATED_BLOCK));
    Ok(())
}

/// Update which authorization process (`newPolicyId`) is required to invoke `(targetHps, fnSelector)`.
/// Calling `setFunctionAuth` itself requires and consumes an `Authorization` object (`authObj`)
/// satisfying `getFunctionAuth(self, SEL_SET_FUNCTION_AUTH)`.
fn handle_set_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let target_hps = args.address(0).ok_or(-3)?;
    let fn_selector = args.bytes4(1).ok_or(-3)?;
    let new_policy_id = args.bytes32(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    if fn_selector == [0u8; 4] || new_policy_id == [0u8; 32] {
        return Err(-59);
    }
    let me = context::self_address();
    let check_target = if target_hps == [0u8; 20] {
        me
    } else {
        target_hps
    };
    if !policy_exists_for(&check_target, &new_policy_id) {
        return Err(ERR_POLICY_INVALID);
    }

    let gov_policy = require_charter_function_auth(&SEL_SET_FUNCTION_AUTH)?;
    let action_hash = compute_set_function_auth_hash(&target_hps, &fn_selector, &new_policy_id);
    verify_and_consume_auth(&registry, &auth_obj, &me, &gov_policy, &action_hash, &caller)?;

    let old_policy = get_function_auth(&target_hps, &fn_selector).unwrap_or([0u8; 32]);
    store_function_auth(&target_hps, &fn_selector, &new_policy_id, true);

    let mut sel_data = [0u8; 52];
    sel_data[0..4].copy_from_slice(&fn_selector);
    sel_data[4..36].copy_from_slice(&old_policy);
    sel_data[36..52].copy_from_slice(&auth_obj[0..16]);
    events::emit(
        &[FUNCTION_AUTH_UPDATED, addr_topic(&target_hps), new_policy_id],
        &sel_data,
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_get_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let target_hps = args.address(0).ok_or(-3)?;
    let fn_selector = args.bytes4(1).ok_or(-3)?;
    let pol = get_function_auth(&target_hps, &fn_selector).unwrap_or([0u8; 32]);
    ret::write_word(&pol);
    Ok(())
}

/// Grant or revoke a governed capability (`capability`, e.g., `CAP_EQUITY_SETTLEMENT` or
/// `CAP_MERCHANT_PAYMENT`) for a sibling company HPS (`moduleHps`).
fn handle_authorize_module(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let module_hps = args.address(0).ok_or(-3)?;
    let capability = args.bytes32(1).ok_or(-3)?;
    let active = args.bool(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    if module_hps == [0u8; 20] || capability == [0u8; 32] {
        return Err(-59);
    }

    let cfg_key = module_configured_key(&module_hps, &capability);
    if auth_obj == [0u8; 20]
        && active
        && storage::get_u64(cfg_key.as_slice()) == 0
        && !is_fn_auth_explicit(&[0u8; 20], &SEL_AUTHORIZE_MODULE)
    {
        // Initial bootstrap binding by an active Director (or Charter initializer if 0 directors)
        let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let count = load_directors(&mut dirs);
        if count > 0 {
            let mut is_dir = false;
            let mut i = 0;
            while i < count {
                if dirs[i] == caller {
                    is_dir = true;
                    break;
                }
                i += 1;
            }
            if !is_dir {
                return Err(-61);
            }
        } else {
            let init_by = storage::get_address(KEY_INITIALIZER).unwrap_or([0u8; 20]);
            if caller != init_by {
                return Err(-61);
            }
        }
    } else {
        let req_pol = require_charter_function_auth(&SEL_AUTHORIZE_MODULE)?;
        let action_hash = compute_authorize_module_hash(&module_hps, &capability, active);
        let me = context::self_address();
        verify_and_consume_auth(&registry, &auth_obj, &me, &req_pol, &action_hash, &caller)?;
    }

    storage::set_u64(
        module_auth_key(&module_hps, &capability).as_slice(),
        u64::from(active),
    );
    storage::set_u64(cfg_key.as_slice(), 1);

    events::emit(
        &[
            MODULE_AUTHORIZED,
            addr_topic(&module_hps),
            capability,
            addr_topic(&auth_obj),
        ],
        &[u8::from(active)],
    );
    ret::write_bool(true);
    Ok(())
}

/// Returns `true` iff this `CorporateCharter` is `ACTIVE` and `(moduleHps, capability)` is authorized.
fn handle_is_authorized_module(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 || storage::get_u64(KEY_STATE) != CHARTER_STATE_ACTIVE {
        ret::write_bool(false);
        return Ok(());
    }
    let module_hps = args.address(0).ok_or(-3)?;
    let capability = args.bytes32(1).ok_or(-3)?;
    let ok = storage::get_u64(module_auth_key(&module_hps, &capability).as_slice()) == 1;
    ret::write_bool(ok);
    Ok(())
}

fn handle_define_role(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let role_id = args.bytes32(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    if role_id == [0u8; 32] {
        return Err(-59);
    }

    let req_pol = require_charter_function_auth(&SEL_DEFINE_ROLE)?;
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
    let req_pol = require_charter_function_auth(&SEL_SET_POLICY)?;
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
    let set_fn_pol =
        get_function_auth(&[0u8; 20], &SEL_SET_FUNCTION_AUTH).unwrap_or(POLICY_SUPER_GOVERNANCE);
    if (policy_id == POLICY_SUPER_GOVERNANCE || policy_id == set_fn_pol)
        && (target_hps == me || target_hps == [0u8; 20])
    {
        return Err(-61);
    }

    let pk = policy_key(&target_hps, &policy_id);
    if !storage::exists(pk.as_slice()) {
        return Err(-62);
    }

    let req_pol = require_charter_function_auth(&SEL_DEACTIVATE_POLICY)?;
    let action_hash = compute_deactivate_hash(&target_hps, &policy_id);
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

    storage::set(pk.as_slice(), &[]);
    events::emit(&[POLICY_DEACTIVATED, addr_topic(&target_hps), policy_id], &[]);
    ret::write_bool(true);
    Ok(())
}

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
            return Err(-61);
        }
        i += 1;
    }
    if storage::get_u64(director_pending_key(&new_director).as_slice()) == 1 {
        return Err(-61);
    }

    let req_pol = require_charter_function_auth(&SEL_ADD_DIRECTOR)?;
    let action_hash = compute_add_director_hash(&new_director);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

    let now = context::block_number();
    if new_director == caller {
        set_director_consented(&new_director, true);
        events::emit(
            &[DIRECTOR_CONSENTED, addr_topic(&new_director)],
            &now.to_be_bytes(),
        );
    }

    if has_director_consented(&new_director) {
        dirs[count] = new_director;
        let new_count = count + 1;
        let exp = storage::get_u64(KEY_BOARD_EXPIRY);
        save_directors_and_sync_board_policy(&dirs, new_count, if exp == 0 { 50 } else { exp })?;

        events::emit(
            &[DIRECTOR_ADDED, addr_topic(&new_director), addr_topic(&super_auth)],
            &(new_count as u64).to_be_bytes(),
        );
        ret::write_u64_word(new_count as u64);
    } else {
        // Nominee has NOT consented yet — record pending appointment until `consentToDirectorship()` is signed by `new_director`!
        let mut pending = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let p_cnt = load_pending_directors(&mut pending);
        if p_cnt >= MAX_MEMBERS_PER_STAGE {
            return Err(-61);
        }
        pending[p_cnt] = new_director;
        save_pending_directors(&pending, p_cnt + 1);
        storage::set_u64(director_pending_key(&new_director).as_slice(), 1);
        storage::set_address(director_pending_auth_key(&new_director).as_slice(), &super_auth);

        events::emit(
            &[
                DIRECTOR_PENDING_CONSENT,
                addr_topic(&new_director),
                addr_topic(&super_auth),
            ],
            &now.to_be_bytes(),
        );
        ret::write_u64_word(count as u64);
    }
    Ok(())
}

fn handle_remove_director(args: &CalldataReader) -> Result<(), i32> {
    let (registry, caller) = ensure_initialized_and_valid_caller()?;
    let director = args.address(0).ok_or(-3)?;
    let super_auth = args.address(1).ok_or(-3)?;

    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);

    let mut found_idx: Option<usize> = None;
    let mut i = 0;
    while i < count {
        if dirs[i] == director {
            found_idx = Some(i);
            break;
        }
        i += 1;
    }

    let is_pending = storage::get_u64(director_pending_key(&director).as_slice()) == 1;
    if found_idx.is_none() && !is_pending {
        return Err(-62);
    }
    if found_idx.is_some() && count <= 1 {
        return Err(-61);
    }

    let req_pol = require_charter_function_auth(&SEL_REMOVE_DIRECTOR)?;
    let action_hash = compute_remove_director_hash(&director);
    let me = context::self_address();
    verify_and_consume_auth(&registry, &super_auth, &me, &req_pol, &action_hash, &caller)?;

    set_director_consented(&director, false);
    let _ = remove_pending_director(&director);

    let out_count = if let Some(idx) = found_idx {
        let mut j = idx;
        while j + 1 < count {
            dirs[j] = dirs[j + 1];
            j += 1;
        }
        let new_count = count - 1;
        dirs[new_count] = [0u8; 20];
        let exp = storage::get_u64(KEY_BOARD_EXPIRY);
        save_directors_and_sync_board_policy(&dirs, new_count, if exp == 0 { 50 } else { exp })?;
        new_count
    } else {
        count
    };

    events::emit(
        &[DIRECTOR_REMOVED, addr_topic(&director), addr_topic(&super_auth)],
        &(out_count as u64).to_be_bytes(),
    );
    ret::write_u64_word(out_count as u64);
    Ok(())
}

/// Sign personal **Consent to Act as Director** from the calling `Identity` HPS:
/// 1. While `PENDING_RATIFICATION`, records consent so `activateCharter` can transition the
///    `CorporateCharter` to `ACTIVE` once all named Initial Directors have consented and `>= 75%`
///    Shareholders ratify.
/// 2. While `ACTIVE`, if `caller` has an approved `addDirector` appointment awaiting consent
///    (`isPendingDirector(caller) == true`), immediately seats `caller` onto the Board of Directors
///    and emits `DirectorAdded`!
fn handle_consent_to_directorship(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_any_state_caller()?;
    let now = context::block_number();

    set_director_consented(&caller, true);
    events::emit(&[DIRECTOR_CONSENTED, addr_topic(&caller)], &now.to_be_bytes());

    if storage::get_u64(KEY_STATE) == CHARTER_STATE_ACTIVE
        && storage::get_u64(director_pending_key(&caller).as_slice()) == 1
    {
        let super_auth =
            storage::get_address(director_pending_auth_key(&caller).as_slice()).unwrap_or([0u8; 20]);
        let _ = remove_pending_director(&caller);

        let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
        let count = load_directors(&mut dirs);
        let mut already = false;
        let mut i = 0;
        while i < count {
            if dirs[i] == caller {
                already = true;
                break;
            }
            i += 1;
        }
        if !already && count < MAX_MEMBERS_PER_STAGE {
            dirs[count] = caller;
            let new_count = count + 1;
            let exp = storage::get_u64(KEY_BOARD_EXPIRY);
            save_directors_and_sync_board_policy(
                &dirs,
                new_count,
                if exp == 0 { 50 } else { exp },
            )?;
            events::emit(
                &[DIRECTOR_ADDED, addr_topic(&caller), addr_topic(&super_auth)],
                &(new_count as u64).to_be_bytes(),
            );
        }
    }

    ret::write_bool(true);
    Ok(())
}

fn handle_has_director_consented(args: &CalldataReader) -> Result<(), i32> {
    let candidate = args.address(0).ok_or(-3)?;
    ret::write_bool(has_director_consented(&candidate));
    Ok(())
}

fn handle_all_directors_consented(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_bool(count_unconsented_directors() == 0);
    Ok(())
}

fn handle_unconsented_director_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(count_unconsented_directors() as u64);
    Ok(())
}

fn handle_is_director(args: &CalldataReader) -> Result<(), i32> {
    let candidate = args.address(0).ok_or(-3)?;
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    let mut found = false;
    let mut i = 0;
    while i < count {
        if dirs[i] == candidate {
            found = true;
            break;
        }
        i += 1;
    }
    ret::write_bool(found);
    Ok(())
}

fn handle_director_count(_args: &CalldataReader) -> Result<(), i32> {
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    ret::write_u64_word(count as u64);
    Ok(())
}

fn handle_director_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let mut dirs = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_directors(&mut dirs);
    if idx >= count {
        return Err(-62);
    }
    ret::write_address(&dirs[idx]);
    Ok(())
}

fn handle_is_pending_director(args: &CalldataReader) -> Result<(), i32> {
    let candidate = args.address(0).ok_or(-3)?;
    let pending = candidate != [0u8; 20]
        && storage::get_u64(director_pending_key(&candidate).as_slice()) == 1;
    ret::write_bool(pending);
    Ok(())
}

fn handle_pending_director_count(_args: &CalldataReader) -> Result<(), i32> {
    let mut pending = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_pending_directors(&mut pending);
    ret::write_u64_word(count as u64);
    Ok(())
}

fn handle_pending_director_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let mut pending = [[0u8; 20]; MAX_MEMBERS_PER_STAGE];
    let count = load_pending_directors(&mut pending);
    if idx >= count {
        return Err(-62);
    }
    ret::write_address(&pending[idx]);
    Ok(())
}

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

    let req_pol = require_charter_function_auth(&SEL_GRANT_ROLE)?;
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

    let req_pol = require_charter_function_auth(&SEL_REVOKE_ROLE)?;
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

/// Register or amend an authorized share-class `AssetLedger` in this `CorporateCharter` with its
/// per-share voting multiplier (`votesPerShare`) and conversion ratio (`conversionNumer / conversionDenom`)
/// to Common Shares.
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
        && !is_fn_auth_explicit(&[0u8; 20], &SEL_REGISTER_SHARE_CLASS)
    {
        // Founder/director initial share-class registration (permitted during PENDING_RATIFICATION
        // when shareClassesBlob was omitted, or post-activation when adding a bootstrap class)
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
        let req_pol = require_charter_function_auth(&SEL_REGISTER_SHARE_CLASS)?;
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
/// share-class `AssetLedger`s registered in this `CorporateCharter`:
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
        let bal_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
            .push_address(&voter);
        let bal = call::call_u64(&c.ledger, bal_cd.as_slice()).unwrap_or(0);
        let sup_cd = CallEncoder::<16>::new(const { selector("totalOutstanding()") });
        let supply = call::call_u64(&c.ledger, sup_cd.as_slice()).unwrap_or(0);

        voter_power = voter_power.saturating_add(c.voting_power(bal));
        total_power = total_power.saturating_add(c.voting_power(supply));
        voter_common = voter_common.saturating_add(c.converted_common_shares(bal));
        i += 1;
    }

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

/// Returns `(uint64 holderConvertedCommonShares, uint64 companyTotalConvertedCommonShares)` summed
/// across all authorized share classes in this `CorporateCharter`.
fn handle_converted_common_totals(args: &CalldataReader) -> Result<(), i32> {
    let shareholder = args.address(0).ok_or(-3)?;
    let (holder_common, total_common) = compute_converted_common_totals(&shareholder);
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&holder_common.to_be_bytes());
    out[56..64].copy_from_slice(&total_common.to_be_bytes());
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

/// Constitutional validation gate invoked before enacting any Share Transfer (`POLICY_SHARE_TRANSFER_AUCTION`)
/// or New Share Issuance (`POLICY_SHARE_ISSUANCE_AUCTION`) `Authorization` (`authObj`):
/// - Rejects with `ERR_CHARTER_NOT_ACTIVE (-91)` if this `CorporateCharter` is not `ACTIVE`.
/// - Rejects with `ERR_NO_BIDS_IN_STAGE (-97)` if the Bids Stage expired without `>= 1` active bid!
fn handle_validate_capital_process_auth(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 || storage::get_u64(KEY_STATE) != CHARTER_STATE_ACTIVE {
        return Err(ERR_CHARTER_NOT_ACTIVE);
    }
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-57)?;
    require_valid_authorization_hps(&registry, &auth_obj)?;

    let chr_cd = CallEncoder::<16>::new(const { selector("charter()") });
    let raw_chr = call::call_raw(&auth_obj, chr_cd.as_slice())?;
    if raw_chr.len() < 32 || raw_chr[12..32] != context::self_address() {
        return Err(-19);
    }

    let pol_cd = CallEncoder::<16>::new(const { selector("policyId()") });
    let raw_pol = call::call_raw(&auth_obj, pol_cd.as_slice())?;
    if raw_pol.len() < 32 {
        return Err(ERR_POLICY_INVALID);
    }
    let mut pid = [0u8; 32];
    pid.copy_from_slice(&raw_pol[0..32]);
    if pid != POLICY_SHARE_TRANSFER_AUCTION && pid != POLICY_SHARE_ISSUANCE_AUCTION {
        return Err(ERR_POLICY_INVALID);
    }

    let failed_cd = CallEncoder::<16>::new(const { selector("hasFailedBidsStage()") });
    if matches!(call::call_bool(&auth_obj, failed_cd.as_slice()), Ok(true)) {
        return Err(ERR_NO_BIDS_IN_STAGE);
    }

    let bids_cd = CallEncoder::<16>::new(const { selector("activeStep1BidCount()") });
    if call::call_u64(&auth_obj, bids_cd.as_slice()).unwrap_or(0) == 0 {
        return Err(ERR_NO_BIDS_IN_STAGE);
    }

    // For Equity Financing (`POLICY_SHARE_ISSUANCE_AUCTION` with `isEquityFinancing == 1`),
    // constitutionally enforce `subscribedAtOrAboveOffer >= targetShares`!
    if pid == POLICY_SHARE_ISSUANCE_AUCTION {
        let eq_cd = CallEncoder::<16>::new(const { selector("equityFinancingTerms()") });
        if let Ok(eq_raw) = call::call_raw(&auth_obj, eq_cd.as_slice()) {
            if eq_raw.len() >= 9 * 32 {
                let mut w_flag = [0u8; 8];
                let mut w_tgt = [0u8; 8];
                let mut w_sub = [0u8; 8];
                w_flag.copy_from_slice(&eq_raw[24..32]);
                w_tgt.copy_from_slice(&eq_raw[5 * 32 + 24..6 * 32]);
                w_sub.copy_from_slice(&eq_raw[8 * 32 + 24..9 * 32]);
                let is_eqf = u64::from_be_bytes(w_flag);
                let tgt_sh = u64::from_be_bytes(w_tgt);
                let sub_sh = u64::from_be_bytes(w_sub);
                if is_eqf == 1 && (tgt_sh == 0 || sub_sh < tgt_sh) {
                    return Err(ERR_NO_BIDS_IN_STAGE);
                }
            }
        }
    }

    let ready_cd = CallEncoder::<16>::new(const { selector("isReadyToConsume()") });
    if !matches!(call::call_bool(&auth_obj, ready_cd.as_slice()), Ok(true)) {
        return Err(-62);
    }

    ret::write_bool(true);
    Ok(())
}

fn sha_signed_charter_key(account: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"chr:sha:").push(account)
}

fn require_equity_settlement_module() -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 || storage::get_u64(KEY_STATE) != CHARTER_STATE_ACTIVE {
        return Err(ERR_CHARTER_NOT_ACTIVE);
    }
    let caller = context::msg_sender();
    if storage::get_u64(module_auth_key(&caller, &CAP_EQUITY_SETTLEMENT).as_slice()) != 1 {
        return Err(ERR_UNAUTHORIZED_MODULE);
    }
    Ok(())
}

fn handle_sha_document_hash(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&compute_sha_doc_hash(&context::self_address()));
    Ok(())
}

fn handle_has_signed_sha(args: &CalldataReader) -> Result<(), i32> {
    let who = args.address(0).ok_or(-3)?;
    let signed = storage::get_u64(sha_signed_charter_key(&who).as_slice()) == 1
        || storage::get_u64(role_has_key(&ROLE_SHAREHOLDER, &who).as_slice()) == 1;
    ret::write_bool(signed);
    Ok(())
}

fn handle_sign_sha_direct(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let sha_hash = args.bytes32(0).ok_or(-3)?;
    let expected = compute_sha_doc_hash(&context::self_address());
    if sha_hash != expected {
        return Err(ERR_SHA_SIGNATURE_REQUIRED);
    }
    storage::set_u64(sha_signed_charter_key(&caller).as_slice(), 1);
    if is_role_defined(&ROLE_SHAREHOLDER)
        && storage::get_u64(role_has_key(&ROLE_SHAREHOLDER, &caller).as_slice()) == 0
    {
        let _ = grant_role_internal(&ROLE_SHAREHOLDER, &caller);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_module_record_sha(args: &CalldataReader) -> Result<(), i32> {
    require_equity_settlement_module()?;
    let shareholder = args.address(0).ok_or(-3)?;
    let sha_hash = args.bytes32(1).ok_or(-3)?;
    if shareholder == [0u8; 20] || sha_hash != compute_sha_doc_hash(&context::self_address()) {
        return Err(ERR_SHA_SIGNATURE_REQUIRED);
    }
    storage::set_u64(sha_signed_charter_key(&shareholder).as_slice(), 1);
    if is_role_defined(&ROLE_SHAREHOLDER)
        && storage::get_u64(role_has_key(&ROLE_SHAREHOLDER, &shareholder).as_slice()) == 0
    {
        let _ = grant_role_internal(&ROLE_SHAREHOLDER, &shareholder);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_module_ensure_share_class(args: &CalldataReader) -> Result<(), i32> {
    require_equity_settlement_module()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let votes_per_share = args.u64(1).ok_or(-3)?;
    let conversion_numer = args.u64(2).ok_or(-3)?;
    let conversion_denom = args.u64(3).ok_or(-3)?;
    if share_ledger == [0u8; 20]
        || votes_per_share == 0
        || conversion_numer == 0
        || conversion_denom == 0
    {
        return Err(-59);
    }

    let mut classes = [ShareClassSpec::empty(); MAX_SHARE_CLASSES];
    let count = load_share_classes(&mut classes);
    let mut i = 0;
    while i < count {
        if classes[i].ledger == share_ledger {
            ret::write_u64_word(count as u64);
            return Ok(());
        }
        i += 1;
    }
    if count >= MAX_SHARE_CLASSES {
        return Err(-61);
    }
    classes[count] = ShareClassSpec {
        ledger: share_ledger,
        votes_per_share,
        conversion_numer,
        conversion_denom,
    };
    let new_count = count + 1;
    save_share_classes(&classes, new_count);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&votes_per_share.to_be_bytes());
    ev[8..16].copy_from_slice(&conversion_numer.to_be_bytes());
    ev[16..24].copy_from_slice(&conversion_denom.to_be_bytes());
    events::emit(&[SHARE_CLASS_REGISTERED, addr_topic(&share_ledger)], &ev);

    ret::write_u64_word(new_count as u64);
    Ok(())
}

fn share_class_label_key(ledger: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"chr:scl:").push(ledger)
}

fn handle_module_set_share_class_label(args: &CalldataReader) -> Result<(), i32> {
    require_equity_settlement_module()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let label = args.bytes32(1).ok_or(-3)?;
    if share_ledger == [0u8; 20] {
        return Err(-59);
    }
    storage::set(share_class_label_key(&share_ledger).as_slice(), &label);
    ret::write_bool(true);
    Ok(())
}

fn handle_share_class_label(args: &CalldataReader) -> Result<(), i32> {
    let share_ledger = args.address(0).ok_or(-3)?;
    let lbl = storage::get_bytes32(share_class_label_key(&share_ledger).as_slice())
        .unwrap_or([0u8; 32]);
    ret::write_word(&lbl);
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
        || (target_hps != [0u8; 20]
            && storage::exists(policy_key(&[0u8; 20], &policy_id).as_slice()));
    ret::write_bool(found);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_hash_activate_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&compute_activate_charter_hash());
    Ok(())
}

fn handle_hash_set_function_auth(args: &CalldataReader) -> Result<(), i32> {
    let target_hps = args.address(0).ok_or(-3)?;
    let fn_selector = args.bytes4(1).ok_or(-3)?;
    let policy_id = args.bytes32(2).ok_or(-3)?;
    ret::write_word(&compute_set_function_auth_hash(
        &target_hps,
        &fn_selector,
        &policy_id,
    ));
    Ok(())
}

fn handle_hash_authorize_module(args: &CalldataReader) -> Result<(), i32> {
    let module_hps = args.address(0).ok_or(-3)?;
    let capability = args.bytes32(1).ok_or(-3)?;
    let active = args.bool(2).ok_or(-3)?;
    ret::write_word(&compute_authorize_module_hash(
        &module_hps,
        &capability,
        active,
    ));
    Ok(())
}

fn handle_hash_define_role(args: &CalldataReader) -> Result<(), i32> {
    let role_id = args.bytes32(0).ok_or(-3)?;
    ret::write_word(&compute_define_role_hash(&role_id));
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
    use hps_sdk::governance::{CAP_EQUITY_SETTLEMENT, CAP_MERCHANT_PAYMENT, ROLE_ALL_MEMBERS_WEIGHT};
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
                ret::write_bool(a[0] == 0xA0);
                return 0;
            }
            -2
        }
    }

    mod auth_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{context, ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                if storage::get_u64(b"used") != 0 {
                    return -67;
                }
                let expected_target = storage::get_address(b"target").unwrap();
                let expected_pol = storage::get_bytes32(b"pol").unwrap();
                let expected_hash = storage::get_bytes32(b"hash").unwrap();
                if context::msg_sender() != expected_target {
                    return -66;
                }
                if args.bytes32(1).unwrap() != expected_pol
                    || args.bytes32(2).unwrap() != expected_hash
                {
                    return -66;
                }
                storage::set_u64(b"used", 1);
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    mod share_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("balanceOf(address)") } {
                let holder = args.address(0).unwrap();
                ret::write_u64_word(storage::get_u64(&holder));
                return 0;
            }
            if sel == const { selector("totalOutstanding()") } {
                ret::write_u64_word(storage::get_u64(b"supply"));
                return 0;
            }
            -2
        }
    }

    #[test]
    fn corporate_charter_lifecycle_scoped_fn_auth_roles_share_classes_and_modules() {
        mock::reset();
        let charter_addr = [0xC0; 20];
        let reg_addr = [0xB0; 20];
        let share_capital_hps = [0x5C; 20];
        let product_ledger_hps = [0x9D; 20];
        let pref_a_ledger = [0x5A; 20];
        let founder = [0x01; 20];
        let dir_2 = [0x02; 20];
        let pm_user = [0x03; 20];
        let role_cfo = keccak256(b"ROLE_CFO");
        let pol_dual_pm_cfo = keccak256(b"POLICY_DUAL_PM_CFO");

        mock::register_hps(reg_addr, reg_stub::dispatch);
        mock::register_hps(pref_a_ledger, share_stub::dispatch);

        // Seed 100,000 Preferred Shares A (50% conversion -> 50,000 common equiv; 1 vote per common)
        mock::set_self_address(pref_a_ledger);
        storage::set_u64(&founder, 100_000);
        storage::set_u64(b"supply", 200_000);

        let mut roles_blob = Vec::new();
        roles_blob.extend_from_slice(&4u16.to_be_bytes());
        // ROLE_SHAREHOLDER (0 explicit members), ROLE_DIRECTOR (2 members), ROLE_PRODUCT_MANAGER (0), ROLE_CFO (0)
        for (rid, members) in [
            (ROLE_SHAREHOLDER, &[][..]),
            (ROLE_DIRECTOR, &[founder, dir_2][..]),
            (ROLE_PRODUCT_MANAGER, &[][..]),
            (role_cfo, &[][..]),
        ] {
            roles_blob.extend_from_slice(&rid);
            roles_blob.extend_from_slice(&(members.len() as u16).to_be_bytes());
            for m in members {
                roles_blob.extend_from_slice(m);
            }
        }

        let sh_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_SHAREHOLDER, 75, 50).unwrap())
            .unwrap();
        let board_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_DIRECTOR, ROLE_ALL_MEMBERS_WEIGHT, 50).unwrap())
            .unwrap();
        let pm_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_PRODUCT_MANAGER, 1, 50).unwrap())
            .unwrap();
        let dual_spec = PolicySpec::new(100)
            .add_stage(StageSpec::for_role(ROLE_PRODUCT_MANAGER, 1, 50).unwrap())
            .unwrap()
            .add_stage(StageSpec::for_role(role_cfo, 1, 50).unwrap())
            .unwrap();

        let mut policies_blob = Vec::new();
        let pols = [
            (POLICY_FIRST_SHAREHOLDER_RESOLUTION, &sh_spec),
            (POLICY_SUPER_GOVERNANCE, &sh_spec),
            (POLICY_BOARD_RESOLUTION, &board_spec),
            (POLICY_PRODUCT_MANAGEMENT, &pm_spec),
            (pol_dual_pm_cfo, &dual_spec),
        ];
        policies_blob.extend_from_slice(&(pols.len() as u16).to_be_bytes());
        for (pid, sp) in pols {
            let mut enc = [0u8; 512];
            let n = sp.encode(&mut enc).unwrap();
            policies_blob.extend_from_slice(&[0u8; 20]);
            policies_blob.extend_from_slice(&pid);
            policies_blob.extend_from_slice(&(n as u16).to_be_bytes());
            policies_blob.extend_from_slice(&enc[..n]);
        }

        let sel_prod_set_price = selector("setProductPrice(bytes32,uint64,address)");
        let fn_rules = [
            FunctionAuthRule::for_charter(SEL_ACTIVATE_CHARTER, POLICY_FIRST_SHAREHOLDER_RESOLUTION),
            FunctionAuthRule::for_charter(SEL_SET_FUNCTION_AUTH, POLICY_SUPER_GOVERNANCE),
            FunctionAuthRule::for_charter(SEL_GRANT_ROLE, POLICY_BOARD_RESOLUTION),
            FunctionAuthRule::for_target(
                product_ledger_hps,
                sel_prod_set_price,
                POLICY_PRODUCT_MANAGEMENT,
            ),
        ];
        let mut fn_auths_blob = Vec::new();
        fn_auths_blob.extend_from_slice(&(fn_rules.len() as u16).to_be_bytes());
        for r in &fn_rules {
            fn_auths_blob.extend_from_slice(&r.encode());
        }

        let mut sc_blob = Vec::new();
        sc_blob.extend_from_slice(&1u16.to_be_bytes());
        sc_blob.extend_from_slice(
            &ShareClassSpec {
                ledger: pref_a_ledger,
                votes_per_share: 1,
                conversion_numer: 1,
                conversion_denom: 2,
            }
            .encode(),
        );

        let mut mods_blob = Vec::new();
        mods_blob.extend_from_slice(&2u16.to_be_bytes());
        mods_blob.extend_from_slice(
            &AuthorizedModuleSpec::new(share_capital_hps, CAP_EQUITY_SETTLEMENT).encode(),
        );
        mods_blob.extend_from_slice(
            &AuthorizedModuleSpec::new(product_ledger_hps, CAP_MERCHANT_PAYMENT).encode(),
        );

        // Initialize CorporateCharter via 6-arg `initializeWithGovernance`
        mock::set_self_address(charter_addr);
        mock::set_sender(founder);
        mock::set_block_number(10);

        let mut init_cd = Vec::new();
        init_cd.extend_from_slice(&selector(
            "initializeWithGovernance(address,bytes,bytes,bytes,bytes,bytes)",
        ));
        let mut head = [0u8; 32 * 6];
        head[12..32].copy_from_slice(&reg_addr);
        let blobs: [&[u8]; 5] = [
            &roles_blob,
            &policies_blob,
            &fn_auths_blob,
            &sc_blob,
            &mods_blob,
        ];
        let mut tail = Vec::new();
        for (i, b) in blobs.iter().enumerate() {
            let off = (32 * 6 + tail.len()) as u64;
            head[(i + 1) * 32 + 24..(i + 1) * 32 + 32].copy_from_slice(&off.to_be_bytes());
            let mut lword = [0u8; 32];
            lword[24..32].copy_from_slice(&(b.len() as u64).to_be_bytes());
            tail.extend_from_slice(&lword);
            let padded = (b.len() + 31) & !31;
            let start = tail.len();
            tail.resize(start + padded, 0);
            tail[start..start + b.len()].copy_from_slice(b);
        }
        init_cd.extend_from_slice(&head);
        init_cd.extend_from_slice(&tail);
        assert_eq!(dispatch_calldata(&init_cd), 0);

        // Pre-activation: state == PENDING_RATIFICATION (1), isAuthorizedModule == false!
        assert_eq!(dispatch_calldata(&selector("state()")), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            CHARTER_STATE_PENDING_RATIFICATION
        );
        let mod_chk_cd = CallEncoder::<96>::new(selector("isAuthorizedModule(address,bytes32)"))
            .push_address(&share_capital_hps)
            .push_bytes32(&CAP_EQUITY_SETTLEMENT);
        assert_eq!(dispatch_calldata(mod_chk_cd.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 0);

        // Mutations (e.g. grantRole) MUST revert with ERR_CHARTER_NOT_ACTIVE (-91) before activation!
        let grant_cd = CallEncoder::<128>::new(SEL_GRANT_ROLE)
            .push_bytes32(&ROLE_PRODUCT_MANAGER)
            .push_address(&pm_user)
            .push_address(&[0xA0; 20]);
        assert_eq!(dispatch_calldata(grant_cd.as_slice()), ERR_CHARTER_NOT_ACTIVE);

        // Pass First Shareholder Resolution (`activateCharter`)
        assert_eq!(dispatch_calldata(&selector("hashActivateCharter()")), 0);
        let act_hash: [u8; 32] = mock::take_return_data().try_into().unwrap();
        let auth_act = [0xA0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        mock::register_hps(auth_act, auth_stub::dispatch);
        mock::set_self_address(auth_act);
        storage::set_address(b"target", &charter_addr);
        storage::set(b"pol", &POLICY_FIRST_SHAREHOLDER_RESOLUTION);
        storage::set(b"hash", &act_hash);

        mock::set_self_address(charter_addr);
        mock::set_sender(founder);
        let act_cd = CallEncoder::<64>::new(SEL_ACTIVATE_CHARTER).push_address(&auth_act);
        // `dir_2` was named as an Initial Director by `founder`, so `activateCharter` MUST revert
        // with `ERR_DIRECTOR_CONSENT_REQUIRED (-96)` until `dir_2` signs `consentToDirectorship()`!
        assert_eq!(
            dispatch_calldata(act_cd.as_slice()),
            ERR_DIRECTOR_CONSENT_REQUIRED
        );
        assert_eq!(dispatch_calldata(&selector("unconsentedDirectorCount()")), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            1
        );

        // `dir_2` signs personal `consentToDirectorship()`
        mock::set_sender(dir_2);
        assert_eq!(dispatch_calldata(&selector("consentToDirectorship()")), 0);
        assert_eq!(mock::take_return_data()[31], 1);
        assert_eq!(dispatch_calldata(&selector("allDirectorsConsented()")), 0);
        assert_eq!(mock::take_return_data()[31], 1);

        // Now `activateCharter` succeeds (even without minority non-director shareholders blocking!)
        mock::set_sender(founder);
        assert_eq!(dispatch_calldata(act_cd.as_slice()), 0);
        assert_eq!(dispatch_calldata(&selector("isActive()")), 0);
        assert_eq!(mock::take_return_data()[31], 1);

        // Post-activation `addDirector` for an external nominee (`dir_3`) MUST await `dir_3`'s consent!
        let dir_3 = [0x04; 20];
        let h_add_cd =
            CallEncoder::<64>::new(selector("hashAddDirector(address)")).push_address(&dir_3);
        assert_eq!(dispatch_calldata(h_add_cd.as_slice()), 0);
        let add_hash: [u8; 32] = mock::take_return_data().try_into().unwrap();
        let auth_add = [0xA0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        mock::register_hps(auth_add, auth_stub::dispatch);
        mock::set_self_address(auth_add);
        storage::set_address(b"target", &charter_addr);
        storage::set(b"pol", &POLICY_SUPER_GOVERNANCE);
        storage::set(b"hash", &add_hash);

        mock::set_self_address(charter_addr);
        mock::set_sender(founder);
        let add_dir_cd = CallEncoder::<96>::new(SEL_ADD_DIRECTOR)
            .push_address(&dir_3)
            .push_address(&auth_add);
        assert_eq!(dispatch_calldata(add_dir_cd.as_slice()), 0);
        // Active directorCount is still 2 while `dir_3` is pending consent!
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            2
        );
        let chk_dir3 =
            CallEncoder::<64>::new(selector("isDirector(address)")).push_address(&dir_3);
        assert_eq!(dispatch_calldata(chk_dir3.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 0);
        let chk_pend3 =
            CallEncoder::<64>::new(selector("isPendingDirector(address)")).push_address(&dir_3);
        assert_eq!(dispatch_calldata(chk_pend3.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 1);

        // Once `dir_3` signs `consentToDirectorship()`, they immediately join the active Board!
        mock::set_sender(dir_3);
        assert_eq!(dispatch_calldata(&selector("consentToDirectorship()")), 0);
        assert_eq!(dispatch_calldata(chk_dir3.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 1);
        assert_eq!(dispatch_calldata(chk_pend3.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 0);
        assert_eq!(dispatch_calldata(&selector("directorCount()")), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            3
        );
        mock::set_sender(founder);

        // Modules pre-registered at construction are now active!
        assert_eq!(dispatch_calldata(mod_chk_cd.as_slice()), 0);
        assert_eq!(mock::take_return_data()[31], 1);

        // Check convertedCommonTotals: founder has 100k Pref A @ 1/2 = 50k common; company has 200k @ 1/2 = 100k common
        let tot_cd = CallEncoder::<64>::new(selector("convertedCommonTotals(address)"))
            .push_address(&founder);
        assert_eq!(dispatch_calldata(tot_cd.as_slice()), 0);
        let tot_ret = mock::take_return_data();
        assert_eq!(u64::from_be_bytes(tot_ret[24..32].try_into().unwrap()), 50_000);
        assert_eq!(u64::from_be_bytes(tot_ret[56..64].try_into().unwrap()), 100_000);

        // Rotate `(product_ledger_hps, sel_prod_set_price)` from POLICY_PRODUCT_MANAGEMENT -> pol_dual_pm_cfo
        let h_rot_cd =
            CallEncoder::<128>::new(selector("hashSetFunctionAuth(address,bytes4,bytes32)"))
                .push_address(&product_ledger_hps)
                .push_bytes4(&sel_prod_set_price)
                .push_bytes32(&pol_dual_pm_cfo);
        assert_eq!(dispatch_calldata(h_rot_cd.as_slice()), 0);
        let rot_hash: [u8; 32] = mock::take_return_data().try_into().unwrap();

        let auth_rot = [0xA0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        mock::register_hps(auth_rot, auth_stub::dispatch);
        mock::set_self_address(auth_rot);
        storage::set_address(b"target", &charter_addr);
        storage::set(b"pol", &POLICY_SUPER_GOVERNANCE);
        storage::set(b"hash", &rot_hash);

        mock::set_self_address(charter_addr);
        let rot_cd = CallEncoder::<160>::new(SEL_SET_FUNCTION_AUTH)
            .push_address(&product_ledger_hps)
            .push_bytes4(&sel_prod_set_price)
            .push_bytes32(&pol_dual_pm_cfo)
            .push_address(&auth_rot);
        assert_eq!(dispatch_calldata(rot_cd.as_slice()), 0);

        let q_fn = CallEncoder::<96>::new(selector("getFunctionAuth(address,bytes4)"))
            .push_address(&product_ledger_hps)
            .push_bytes4(&sel_prod_set_price);
        assert_eq!(dispatch_calldata(q_fn.as_slice()), 0);
        assert_eq!(mock::take_return_data(), pol_dual_pm_cfo);
    }
}
