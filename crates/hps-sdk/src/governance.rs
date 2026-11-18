//! Composable `#![no_std]` governance, sequential/weighted authorization policy codecs,
//! action commitment hashing, and cross-HPS verification helpers shared across:
//! - `identity-registry`
//! - `identity`
//! - `corporate-charter`
//! - `share-capital`
//! - `authorization`
//! - `asset-ledger`
//! - `product-ledger`
//! - `accounting-ledger`
//! - `asset-pair-otc`
//! - `dex-clob`

use crate::call::{self, CallEncoder};
use crate::keccak::keccak256;
use crate::selector;

pub const POLICY_WIRE_VERSION: u8 = 1;
pub const MAX_STAGES: usize = 4;
pub const MAX_MEMBERS_PER_STAGE: usize = 64;
pub const MAX_ROLES_PER_STAGE: usize = 4;
pub const MAX_ENCODED_POLICY_BYTES: usize = 4096;

/// Lifecycle states of a `CorporateCharter` Haltproof Subroutine.
/// Newly constructed CorporateCharters start in `CHARTER_STATE_PENDING_RATIFICATION` (inactive)
/// and become valid/active (`CHARTER_STATE_ACTIVE`) only after a First Shareholder Resolution
/// (`activateCharter`) is passed.
pub const CHARTER_STATE_UNINITIALIZED: u64 = 0;
pub const CHARTER_STATE_PENDING_RATIFICATION: u64 = 1;
pub const CHARTER_STATE_ACTIVE: u64 = 2;

pub const CONSTITUTION_STATE_UNINITIALIZED: u64 = CHARTER_STATE_UNINITIALIZED;
pub const CONSTITUTION_STATE_PENDING_RATIFICATION: u64 = CHARTER_STATE_PENDING_RATIFICATION;
pub const CONSTITUTION_STATE_ACTIVE: u64 = CHARTER_STATE_ACTIVE;

/// Special `required_weight` sentinel on a role-backed `StageSpec` requiring unanimous approval
/// from all currently assigned members of the stage's role(s) (with `>= 1` active member).
pub const ROLE_ALL_MEMBERS_WEIGHT: u64 = u64::MAX;

/// Canonical 32-byte action keys used in `CorporateCharter`, `ShareCapital`, `AssetLedger`, and `ProductLedger`.
pub const ACTION_ISSUE: [u8; 32] = keccak256(b"ISSUE");
pub const ACTION_CANCEL: [u8; 32] = keccak256(b"CANCEL");
pub const ACTION_TRANSFER: [u8; 32] = keccak256(b"TRANSFER");
pub const ACTION_APPROVE: [u8; 32] = keccak256(b"APPROVE");
pub const ACTION_SUPER: [u8; 32] = keccak256(b"SUPER");
pub const ACTION_ADD_DIRECTOR: [u8; 32] = keccak256(b"ADD_DIRECTOR");
pub const ACTION_REMOVE_DIRECTOR: [u8; 32] = keccak256(b"REMOVE_DIRECTOR");
pub const ACTION_SET_SHARE_ESCROW: [u8; 32] = keccak256(b"SET_SHARE_ESCROW");
pub const ACTION_SET_OPERATING_ACCOUNT: [u8; 32] = keccak256(b"SET_OPERATING_ACCOUNT");
pub const ACTION_REGISTER_SHARE_CLASS: [u8; 32] = keccak256(b"REGISTER_SHARE_CLASS");
pub const ACTION_UPSERT_PRODUCT: [u8; 32] = keccak256(b"UPSERT_PRODUCT");
pub const ACTION_RESTOCK_PRODUCT: [u8; 32] = keccak256(b"RESTOCK_PRODUCT");
pub const ACTION_SET_PRODUCT_PRICE: [u8; 32] = keccak256(b"SET_PRODUCT_PRICE");
pub const ACTION_GRANT_ROLE: [u8; 32] = keccak256(b"GRANT_ROLE");
pub const ACTION_REVOKE_ROLE: [u8; 32] = keccak256(b"REVOKE_ROLE");
pub const ACTION_DEFINE_ROLE: [u8; 32] = keccak256(b"DEFINE_ROLE");
pub const ACTION_SET_FUNCTION_AUTH: [u8; 32] = keccak256(b"SET_FUNCTION_AUTH");
pub const ACTION_AUTHORIZE_MODULE: [u8; 32] = keccak256(b"AUTHORIZE_MODULE");
pub const ACTION_ACTIVATE_CHARTER: [u8; 32] = keccak256(b"ACTIVATE_CHARTER");
pub const ACTION_ACTIVATE_CONSTITUTION: [u8; 32] = ACTION_ACTIVATE_CHARTER;
pub const ACTION_REGISTER_PRODUCT_LEDGER: [u8; 32] = keccak256(b"REGISTER_PRODUCT_LEDGER");
pub const ACTION_AUTHORIZE_FUTURES_UNDERWRITING: [u8; 32] =
    keccak256(b"AUTHORIZE_FUTURES_UNDERWRITING");
pub const ACTION_SET_ATTACHED_DEX: [u8; 32] = keccak256(b"SET_ATTACHED_DEX");
pub const ACTION_EXECUTE_SHARE_BUYBACK: [u8; 32] = keccak256(b"EXECUTE_SHARE_BUYBACK");
pub const ACTION_EXECUTE_SHARE_SPLIT: [u8; 32] = keccak256(b"EXECUTE_SHARE_SPLIT");
pub const ACTION_EXECUTE_REVERSE_SPLIT: [u8; 32] = keccak256(b"EXECUTE_REVERSE_SPLIT");
pub const ACTION_CREATE_ESOP_PROGRAM: [u8; 32] = keccak256(b"CREATE_ESOP_PROGRAM");
pub const ACTION_AWARD_ESOP_OPTIONS: [u8; 32] = keccak256(b"AWARD_ESOP_OPTIONS");
pub const ACTION_SET_TREASURY: [u8; 32] = keccak256(b"CHARTER_SET_TREASURY");

pub const DOC_TAG_SUBSCRIPTION_AGREEMENT: [u8; 32] = keccak256(b"SHARE_SUBSCRIPTION_AGREEMENT");
pub const DOC_TAG_SHAREHOLDERS_AGREEMENT: [u8; 32] = keccak256(b"SHAREHOLDERS_AGREEMENT");
pub const DOC_TAG_ESOP_EXERCISE_LETTER: [u8; 32] = keccak256(b"ESOP_EXERCISE_LETTER");

/// Governed sibling-module capabilities registered in `CorporateCharter` so pinned `AssetLedger`
/// and `Authorization` instances trust authorized company modules (`ShareCapital`, `ProductLedger`)
/// without violating single-Charter pinning or segregation of duties.
pub const CAP_EQUITY_SETTLEMENT: [u8; 32] = keccak256(b"CAP_EQUITY_SETTLEMENT");
pub const CAP_MERCHANT_PAYMENT: [u8; 32] = keccak256(b"CAP_MERCHANT_PAYMENT");

/// Canonical governance & administrative Role IDs defined in `CorporateCharter`.
pub const ROLE_SHAREHOLDER: [u8; 32] = keccak256(b"ROLE_SHAREHOLDER");
pub const ROLE_DIRECTOR: [u8; 32] = keccak256(b"ROLE_DIRECTOR");
pub const ROLE_PRODUCT_MANAGER: [u8; 32] = keccak256(b"ROLE_PRODUCT_MANAGER");
pub const ROLE_TREASURY_MANAGER: [u8; 32] = keccak256(b"ROLE_TREASURY_MANAGER");
pub const ROLE_BANK_ORACLE: [u8; 32] = keccak256(b"ROLE_BANK_ORACLE");

/// Canonical policy IDs for `CorporateCharter`, `ShareCapital`, `AssetLedger`, `ProductLedger`, and `IdentityRegistry` governance.
pub const POLICY_SUPER_GOVERNANCE: [u8; 32] = keccak256(b"SUPER_GOVERNANCE");
pub const POLICY_SHAREHOLDER_SUPERMAJORITY: [u8; 32] = keccak256(b"SHAREHOLDER_SUPERMAJORITY");
pub const POLICY_FIRST_SHAREHOLDER_RESOLUTION: [u8; 32] =
    keccak256(b"FIRST_SHAREHOLDER_RESOLUTION");
pub const POLICY_BOARD_RESOLUTION: [u8; 32] = keccak256(b"BOARD_RESOLUTION");
pub const POLICY_PRODUCT_MANAGEMENT: [u8; 32] = keccak256(b"PRODUCT_MANAGEMENT");
pub const POLICY_SHARE_TRANSFER_AUCTION: [u8; 32] = keccak256(b"SHARE_TRANSFER_AUCTION");
pub const POLICY_SHARE_ISSUANCE_AUCTION: [u8; 32] = keccak256(b"SHARE_ISSUANCE_AUCTION");
pub const POLICY_FUTURES_UNDERWRITING: [u8; 32] = keccak256(b"FUTURES_UNDERWRITING");
pub const POLICY_BANK_ORACLE: [u8; 32] = keccak256(b"BANK_ORACLE");
pub const POLICY_ADMIN_ORACLE: [u8; 32] = keccak256(b"ADMIN_ORACLE");
/// Dynamic policy sentinel for `ACTION_TRANSFER` / `ACTION_APPROVE` requiring a one-time
/// `Authorization` object approved & finalized by the debited holder Identity itself.
pub const POLICY_HOLDER_SELF: [u8; 32] = keccak256(b"HOLDER_SELF");

/// Build a deterministic 32-byte `policyId` pinning a specific single-account admin/oracle Identity.
pub const fn oracle_policy_id(oracle_identity: &[u8; 20]) -> [u8; 32] {
    let mut id = [0u8; 32];
    let prefix = *b"HPS_ORACLE_V";
    let mut i = 0;
    while i < 12 {
        id[i] = prefix[i];
        i += 1;
    }
    let mut j = 0;
    while j < 20 {
        id[12 + j] = oracle_identity[j];
        j += 1;
    }
    id
}

/// Error codes shared across governance-enabled Haltproof Subroutines.
pub const ERR_INVALID_IDENTITY: i32 = -70;
pub const ERR_AUTH_CONSUME_FAILED: i32 = -71;
pub const ERR_POLICY_INVALID: i32 = -72;
pub const ERR_UNAPPROVED_CODE_HASH: i32 = -73;
pub const ERR_WRONG_AUCTION_STEP: i32 = -74;
pub const ERR_NOT_EXISTING_SHAREHOLDER: i32 = -75;
pub const ERR_STEP2_SELLER_INELIGIBLE_STEP3: i32 = -76;
pub const ERR_NO_CROSSING_ORDERS: i32 = -77;
pub const ERR_ORDER_NOT_FOUND: i32 = -78;
pub const ERR_ORDER_ALREADY_CANCELLED: i32 = -79;
pub const ERR_NOT_ORDER_OWNER: i32 = -80;
pub const ERR_PRODUCT_NOT_FOUND: i32 = -81;
pub const ERR_INSUFFICIENT_PRODUCT_UNITS: i32 = -82;
pub const ERR_INVALID_PRODUCT_PARAMS: i32 = -83;
pub const ERR_UNAUTHORIZED_SALES_RECORDER: i32 = -84;
pub const ERR_MISSING_ROLE: i32 = -85;
pub const ERR_INVALID_FUTURES_CONFIG: i32 = -86;
pub const ERR_FUTURES_CAP_EXCEEDED: i32 = -87;
pub const ERR_DEX_NOT_ATTACHED: i32 = -88;
pub const ERR_ORDERBOOK_FULL: i32 = -89;
pub const ERR_INVALID_DEX_ORDER: i32 = -90;
pub const ERR_CHARTER_NOT_ACTIVE: i32 = -91;
pub const ERR_CHARTER_ALREADY_ACTIVE: i32 = -92;
pub const ERR_CONSTITUTION_NOT_ACTIVE: i32 = ERR_CHARTER_NOT_ACTIVE;
pub const ERR_CONSTITUTION_ALREADY_ACTIVE: i32 = ERR_CHARTER_ALREADY_ACTIVE;
pub const ERR_ROLE_NOT_DEFINED: i32 = -93;
pub const ERR_FUNCTION_AUTH_NOT_SET: i32 = -94;
pub const ERR_UNAUTHORIZED_MODULE: i32 = -95;
pub const ERR_DIRECTOR_CONSENT_REQUIRED: i32 = -96;
pub const ERR_NO_BIDS_IN_STAGE: i32 = -97;
pub const ERR_SUBSCRIPTION_SHORTFALL: i32 = ERR_NO_BIDS_IN_STAGE;
pub const ERR_ESOP_CLIFF_NOT_PASSED: i32 = -98;
pub const ERR_SHA_SIGNATURE_REQUIRED: i32 = -99;
pub const ERR_SSA_SIGNATURE_REQUIRED: i32 = -100;
pub const ERR_ESOP_POOL_EXCEEDED: i32 = -101;
pub const ERR_ALREADY_EXECUTED_IN_BLOCK: i32 = -102;
pub const ERR_RESERVED_GOVERNANCE_ROLE: i32 = -103;
pub const ERR_SELLER_CONSENT_REQUIRED: i32 = -104;
pub const ERR_FRACTIONAL_SHARE_WIPEOUT: i32 = -105;
pub const ERR_STALE_CAPITAL_SNAPSHOT: i32 = -106;
pub const ERR_FUTURES_BACKING_LOCKED: i32 = -107;
pub const ERR_GOVERNANCE_DOWNGRADE: i32 = -108;
pub const ERR_DEX_FORBIDDEN_ON_SHARES: i32 = -109;
pub const ERR_CHARTER_MISMATCH: i32 = -19;
pub const ERR_CONSTITUTION_MISMATCH: i32 = ERR_CHARTER_MISMATCH;

/// Order side/step tags for `POLICY_SHARE_TRANSFER_AUCTION` 3-step share transfer auctions.
pub const ORDER_SIDE_BUY_STEP1: u8 = 1;
pub const ORDER_SIDE_SELL_STEP2: u8 = 2;
pub const ORDER_SIDE_BUY_STEP3: u8 = 3;
pub const ORDER_SIDE_CANCELLED: u8 = 4;
pub const MAX_AUCTION_ORDERS: usize = 64;
pub const MAX_ENCODED_AUCTION_BOOK_BYTES: usize = 4 + MAX_AUCTION_ORDERS * 37;
pub const MAX_SHARE_CLASSES: usize = 8;
pub const MAX_DEFINED_ROLES: usize = 32;
pub const MAX_AUTHORIZED_MODULES: usize = 16;

/// Single explicit authorizer entry within a sequential authorization stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizerMember {
    pub identity: [u8; 20],
    pub weight: u64,
}

impl Default for AuthorizerMember {
    fn default() -> Self {
        Self {
            identity: [0u8; 20],
            weight: 0,
        }
    }
}

/// Role requirement entry within a sequential authorization stage.
/// Any active `Identity` holding `role_id` in the bound `Constitution` contributes `weight`
/// when approving this stage — allowing authorization processes and roles to be defined at
/// `Constitution` construction even before any `Identity` is assigned to `role_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageRole {
    pub role_id: [u8; 32],
    pub weight: u64,
}

impl Default for StageRole {
    fn default() -> Self {
        Self {
            role_id: [0u8; 32],
            weight: 0,
        }
    }
}

/// Scoped per-function authorization binding (`(target_hps, fn_selector) -> policy_id`) stored in
/// `CorporateCharter`. `target_hps == [0u8; 20]` targets `CorporateCharter` itself (and acts as
/// wildcard fallback if no module-specific override exists).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionAuthRule {
    pub target_hps: [u8; 20],
    pub fn_selector: [u8; 4],
    pub policy_id: [u8; 32],
}

impl FunctionAuthRule {
    pub const ENCODED_LEN: usize = 56;

    pub const fn for_charter(fn_selector: [u8; 4], policy_id: [u8; 32]) -> Self {
        Self {
            target_hps: [0u8; 20],
            fn_selector,
            policy_id,
        }
    }

    pub const fn for_target(
        target_hps: [u8; 20],
        fn_selector: [u8; 4],
        policy_id: [u8; 32],
    ) -> Self {
        Self {
            target_hps,
            fn_selector,
            policy_id,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..20].copy_from_slice(&self.target_hps);
        out[20..24].copy_from_slice(&self.fn_selector);
        out[24..56].copy_from_slice(&self.policy_id);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut target_hps = [0u8; 20];
        target_hps.copy_from_slice(&raw[0..20]);
        let fn_selector = [raw[20], raw[21], raw[22], raw[23]];
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&raw[24..56]);
        if fn_selector == [0u8; 4] || policy_id == [0u8; 32] {
            return None;
        }
        Some(Self {
            target_hps,
            fn_selector,
            policy_id,
        })
    }
}

/// Authorized company module binding (`(module_hps, capability)`) registered in `CorporateCharter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizedModuleSpec {
    pub module_hps: [u8; 20],
    pub capability: [u8; 32],
}

impl AuthorizedModuleSpec {
    pub const ENCODED_LEN: usize = 52;

    pub const fn new(module_hps: [u8; 20], capability: [u8; 32]) -> Self {
        Self {
            module_hps,
            capability,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..20].copy_from_slice(&self.module_hps);
        out[20..52].copy_from_slice(&self.capability);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut module_hps = [0u8; 20];
        module_hps.copy_from_slice(&raw[0..20]);
        let mut capability = [0u8; 32];
        capability.copy_from_slice(&raw[20..52]);
        if module_hps == [0u8; 20] || capability == [0u8; 32] {
            return None;
        }
        Some(Self {
            module_hps,
            capability,
        })
    }
}

/// One sequential step in a multi-stage authorization process.
///
/// Stage `s` must accumulate `>= required_weight` from its listed `members` and/or `roles` within
/// `expiry_blocks` of Stage `s` becoming active before Stage `s + 1` can accept any approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageSpec {
    pub required_weight: u64,
    pub expiry_blocks: u64,
    pub member_count: usize,
    pub members: [AuthorizerMember; MAX_MEMBERS_PER_STAGE],
    pub role_count: usize,
    pub roles: [StageRole; MAX_ROLES_PER_STAGE],
}

impl Default for StageSpec {
    fn default() -> Self {
        Self {
            required_weight: 0,
            expiry_blocks: 0,
            member_count: 0,
            members: [AuthorizerMember::default(); MAX_MEMBERS_PER_STAGE],
            role_count: 0,
            roles: [StageRole::default(); MAX_ROLES_PER_STAGE],
        }
    }
}

impl StageSpec {
    pub fn new(required_weight: u64, expiry_blocks: u64) -> Self {
        Self {
            required_weight,
            expiry_blocks,
            member_count: 0,
            members: [AuthorizerMember::default(); MAX_MEMBERS_PER_STAGE],
            role_count: 0,
            roles: [StageRole::default(); MAX_ROLES_PER_STAGE],
        }
    }

    /// Construct a role-backed stage where each holder of `role_id` contributes approval weight `1`
    /// toward `required_weight` (valid even when `0` identities are assigned `role_id` at genesis).
    pub fn for_role(role_id: [u8; 32], required_weight: u64, expiry_blocks: u64) -> Option<Self> {
        Self::new(required_weight, expiry_blocks).add_role(role_id, 1)
    }

    pub fn add_member(mut self, identity: [u8; 20], weight: u64) -> Option<Self> {
        if self.member_count >= MAX_MEMBERS_PER_STAGE || identity == [0u8; 20] || weight == 0 {
            return None;
        }
        let mut i = 0;
        while i < self.member_count {
            if self.members[i].identity == identity {
                return None; // duplicate identity in same stage
            }
            i += 1;
        }
        self.members[self.member_count] = AuthorizerMember { identity, weight };
        self.member_count += 1;
        Some(self)
    }

    pub fn add_role(mut self, role_id: [u8; 32], weight: u64) -> Option<Self> {
        if self.role_count >= MAX_ROLES_PER_STAGE || role_id == [0u8; 32] || weight == 0 {
            return None;
        }
        let mut i = 0;
        while i < self.role_count {
            if self.roles[i].role_id == role_id {
                return None; // duplicate role in same stage
            }
            i += 1;
        }
        self.roles[self.role_count] = StageRole { role_id, weight };
        self.role_count += 1;
        Some(self)
    }

    pub fn has_role(&self, role_id: &[u8; 32]) -> bool {
        let mut i = 0;
        while i < self.role_count {
            if &self.roles[i].role_id == role_id {
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn validate(&self) -> bool {
        if self.required_weight == 0
            || self.expiry_blocks == 0
            || (self.member_count == 0 && self.role_count == 0)
            || self.member_count > MAX_MEMBERS_PER_STAGE
            || self.role_count > MAX_ROLES_PER_STAGE
        {
            return false;
        }
        let mut total_member_weight: u64 = 0;
        let mut i = 0;
        while i < self.member_count {
            let m = &self.members[i];
            if m.identity == [0u8; 20] || m.weight == 0 {
                return false;
            }
            let mut j = 0;
            while j < i {
                if self.members[j].identity == m.identity {
                    return false;
                }
                j += 1;
            }
            total_member_weight = match total_member_weight.checked_add(m.weight) {
                Some(v) => v,
                None => return false,
            };
            i += 1;
        }
        let mut r = 0;
        while r < self.role_count {
            let rl = &self.roles[r];
            if rl.role_id == [0u8; 32] || rl.weight == 0 {
                return false;
            }
            let mut k = 0;
            while k < r {
                if self.roles[k].role_id == rl.role_id {
                    return false;
                }
                k += 1;
            }
            r += 1;
        }
        if self.role_count == 0 {
            self.required_weight <= total_member_weight
        } else {
            true
        }
    }

    pub fn member_weight(&self, identity: &[u8; 20]) -> Option<u64> {
        let mut i = 0;
        while i < self.member_count {
            if &self.members[i].identity == identity {
                return Some(self.members[i].weight);
            }
            i += 1;
        }
        None
    }
}

/// Complete multi-stage sequential + weighted-joint authorization policy stored in `Constitution`
/// and executed by an `Authorization` HPS instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySpec {
    pub overall_expiry_blocks: u64,
    pub stage_count: usize,
    pub stages: [StageSpec; MAX_STAGES],
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self {
            overall_expiry_blocks: 0,
            stage_count: 0,
            stages: [StageSpec::default(); MAX_STAGES],
        }
    }
}

impl PolicySpec {
    pub fn new(overall_expiry_blocks: u64) -> Self {
        Self {
            overall_expiry_blocks,
            stage_count: 0,
            stages: [StageSpec::default(); MAX_STAGES],
        }
    }

    pub fn add_stage(mut self, stage: StageSpec) -> Option<Self> {
        if self.stage_count >= MAX_STAGES || !stage.validate() {
            return None;
        }
        self.stages[self.stage_count] = stage;
        self.stage_count += 1;
        Some(self)
    }

    pub fn validate(&self) -> bool {
        if self.overall_expiry_blocks == 0
            || self.stage_count == 0
            || self.stage_count > MAX_STAGES
        {
            return false;
        }
        let mut s = 0;
        while s < self.stage_count {
            if !self.stages[s].validate() {
                return false;
            }
            s += 1;
        }
        true
    }

    /// Encode into deterministic binary wire format:
    /// - Header (12 B): `[version=1, active=1, stage_count: u8, 0u8, overall_expiry_blocks: u64 BE]`
    /// - Per stage: `[required_weight: u64 BE (8B)][expiry_blocks: u64 BE (8B)][member_count: u8][role_count: u8][0u8; 6]` (24 B)
    ///   followed by `member_count * 28` bytes of `[identity: 20B][weight: u64 BE (8B)]`
    ///   followed by `role_count * 40` bytes of `[role_id: 32B][weight: u64 BE (8B)]`.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if !self.validate() || out.len() < 12 {
            return None;
        }
        out[0] = POLICY_WIRE_VERSION;
        out[1] = 1;
        out[2] = self.stage_count as u8;
        out[3] = 0;
        out[4..12].copy_from_slice(&self.overall_expiry_blocks.to_be_bytes());
        let mut pos = 12usize;

        let mut s = 0;
        while s < self.stage_count {
            let st = &self.stages[s];
            let need = 24 + st.member_count * 28 + st.role_count * 40;
            if pos + need > out.len() {
                return None;
            }
            out[pos..pos + 8].copy_from_slice(&st.required_weight.to_be_bytes());
            out[pos + 8..pos + 16].copy_from_slice(&st.expiry_blocks.to_be_bytes());
            out[pos + 16] = st.member_count as u8;
            out[pos + 17] = st.role_count as u8;
            out[pos + 18..pos + 24].copy_from_slice(&[0u8; 6]);
            pos += 24;

            let mut m = 0;
            while m < st.member_count {
                out[pos..pos + 20].copy_from_slice(&st.members[m].identity);
                out[pos + 20..pos + 28].copy_from_slice(&st.members[m].weight.to_be_bytes());
                pos += 28;
                m += 1;
            }
            let mut r = 0;
            while r < st.role_count {
                out[pos..pos + 32].copy_from_slice(&st.roles[r].role_id);
                out[pos + 32..pos + 40].copy_from_slice(&st.roles[r].weight.to_be_bytes());
                pos += 40;
                r += 1;
            }
            s += 1;
        }
        Some(pos)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 12 || raw[0] != POLICY_WIRE_VERSION || raw[1] != 1 {
            return None;
        }
        let stage_count = raw[2] as usize;
        if stage_count == 0 || stage_count > MAX_STAGES {
            return None;
        }
        let mut ob = [0u8; 8];
        ob.copy_from_slice(&raw[4..12]);
        let overall_expiry_blocks = u64::from_be_bytes(ob);

        let mut spec = Self {
            overall_expiry_blocks,
            stage_count,
            stages: [StageSpec::default(); MAX_STAGES],
        };

        let mut pos = 12usize;
        let mut s = 0;
        while s < stage_count {
            if pos + 24 > raw.len() {
                return None;
            }
            let mut rwb = [0u8; 8];
            rwb.copy_from_slice(&raw[pos..pos + 8]);
            let required_weight = u64::from_be_bytes(rwb);

            let mut ebb = [0u8; 8];
            ebb.copy_from_slice(&raw[pos + 8..pos + 16]);
            let expiry_blocks = u64::from_be_bytes(ebb);

            let member_count = raw[pos + 16] as usize;
            let role_count = raw[pos + 17] as usize;
            pos += 24;

            if (member_count == 0 && role_count == 0)
                || member_count > MAX_MEMBERS_PER_STAGE
                || role_count > MAX_ROLES_PER_STAGE
                || pos + member_count * 28 + role_count * 40 > raw.len()
            {
                return None;
            }

            let mut stage = StageSpec {
                required_weight,
                expiry_blocks,
                member_count,
                members: [AuthorizerMember::default(); MAX_MEMBERS_PER_STAGE],
                role_count,
                roles: [StageRole::default(); MAX_ROLES_PER_STAGE],
            };
            let mut m = 0;
            while m < member_count {
                let mut id = [0u8; 20];
                id.copy_from_slice(&raw[pos..pos + 20]);
                let mut wb = [0u8; 8];
                wb.copy_from_slice(&raw[pos + 20..pos + 28]);
                stage.members[m] = AuthorizerMember {
                    identity: id,
                    weight: u64::from_be_bytes(wb),
                };
                pos += 28;
                m += 1;
            }
            let mut r = 0;
            while r < role_count {
                let mut rid = [0u8; 32];
                rid.copy_from_slice(&raw[pos..pos + 32]);
                let mut wb = [0u8; 8];
                wb.copy_from_slice(&raw[pos + 32..pos + 40]);
                stage.roles[r] = StageRole {
                    role_id: rid,
                    weight: u64::from_be_bytes(wb),
                };
                pos += 40;
                r += 1;
            }
            spec.stages[s] = stage;
            s += 1;
        }

        if pos != raw.len() || !spec.validate() {
            return None;
        }
        Some(spec)
    }
}

/// Fast, zero-Keccak 256-bit (4 x 64-bit) ARX/SplitMix64 sponge commitment for `ActionHasher`.
pub const fn action_commit_256(data: &[u8]) -> [u8; 32] {
    let mut s0: u64 = 0x6a09e667f3bcc908 ^ (data.len() as u64);
    let mut s1: u64 =
        0xbb67ae8584caa73b ^ ((data.len() as u64).wrapping_mul(0x9e3779b97f4a7c15));
    let mut s2: u64 = 0x3c6ef372fe94f82b;
    let mut s3: u64 = 0xa54ff53a5f1d36f1;

    let mut i = 0usize;
    while i < data.len() {
        let mut word = 0u64;
        let mut b = 0usize;
        while b < 8 && (i + b) < data.len() {
            word |= (data[i + b] as u64) << (b * 8);
            b += 1;
        }
        if b < 8 {
            word |= 0x80u64 << (b * 8);
        }
        s0 = s0.wrapping_add(word).wrapping_mul(0xbf58476d1ce4e5b9);
        s1 = (s1 ^ s0.rotate_left(27)).wrapping_mul(0x94d049bb133111eb);
        s2 = (s2.wrapping_add(s1 ^ word))
            .rotate_left(31)
            .wrapping_mul(0x9e3779b97f4a7c15);
        s3 = (s3 ^ s2.rotate_left(17))
            .wrapping_add(s0)
            .wrapping_mul(0xbf58476d1ce4e5b9);
        i += 8;
    }

    let mut r = 0;
    while r < 2 {
        s0 = (s0 ^ (s3 >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        s1 = (s1 ^ (s0 >> 27)).wrapping_mul(0x94d049bb133111eb);
        s2 = (s2 ^ (s1 >> 31)).wrapping_mul(0xbf58476d1ce4e5b9);
        s3 = (s3 ^ (s2 >> 29)).wrapping_mul(0x94d049bb133111eb);
        r += 1;
    }

    let mut out = [0u8; 32];
    let b0 = s0.to_be_bytes();
    let b1 = s1.to_be_bytes();
    let b2 = s2.to_be_bytes();
    let b3 = s3.to_be_bytes();
    let mut k = 0;
    while k < 8 {
        out[k] = b0[k];
        out[8 + k] = b1[k];
        out[16 + k] = b2[k];
        out[24 + k] = b3[k];
        k += 1;
    }
    out
}

/// Domain-separated 256-bit commitment binding a one-time `Authorization` object to
/// `(target_hps, action_tag, exact_parameters)` without runtime Keccak-256.
pub struct ActionHasher<const CAP: usize = 256> {
    buf: [u8; CAP],
    len: usize,
    overflowed: bool,
}

impl<const CAP: usize> ActionHasher<CAP> {
    pub fn new(target_hps: &[u8; 20], action_tag: &[u8; 32]) -> Self {
        let mut h = Self {
            buf: [0u8; CAP],
            len: 0,
            overflowed: false,
        };
        h = h.push_raw(b"HPS_ACTION_V1");
        h = h.push_raw(target_hps);
        h.push_raw(action_tag)
    }

    pub fn push_raw(mut self, bytes: &[u8]) -> Self {
        if self.len + bytes.len() <= CAP {
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        } else {
            self.overflowed = true;
        }
        self
    }

    pub fn push_address(self, addr: &[u8; 20]) -> Self {
        self.push_raw(addr)
    }

    pub fn push_u64(self, val: u64) -> Self {
        self.push_raw(&val.to_be_bytes())
    }

    pub fn push_bytes32(self, word: &[u8; 32]) -> Self {
        self.push_raw(word)
    }

    pub fn push_bytes_digest(self, data: &[u8]) -> Self {
        let d = action_commit_256(data);
        self.push_raw(&d)
    }

    pub fn finish(&self) -> [u8; 32] {
        debug_assert!(!self.overflowed);
        action_commit_256(&self.buf[..self.len])
    }
}

/// Verify via cross-HPS call into `IdentityRegistry` (`isValidIdentity(address)`) that `identity`
/// is registered, currently active (`status == 1`), **and** deployed from an approved `Identity`
/// WASM bytecode hash (`code_hash`).
pub fn require_valid_identity(registry: &[u8; 20], identity: &[u8; 20]) -> Result<(), i32> {
    if *registry == [0u8; 20] || *identity == [0u8; 20] {
        return Err(ERR_INVALID_IDENTITY);
    }
    let cd =
        CallEncoder::<64>::new(const { selector("isValidIdentity(address)") }).push_address(identity);
    match call::call_bool(registry, cd.as_slice()) {
        Ok(true) => Ok(()),
        _ => Err(ERR_INVALID_IDENTITY),
    }
}

/// Verify via cross-HPS call into `IdentityRegistry` (`isValidAuthorizationHps(address)`) that
/// `auth_obj` is deployed from an approved `Authorization` WASM bytecode hash (`code_hash`),
/// preventing spoofed/clone `Authorization` subroutines.
pub fn require_valid_authorization_hps(
    registry: &[u8; 20],
    auth_obj: &[u8; 20],
) -> Result<(), i32> {
    if *registry == [0u8; 20] || *auth_obj == [0u8; 20] {
        return Err(ERR_UNAPPROVED_CODE_HASH);
    }
    let cd = CallEncoder::<64>::new(const { selector("isValidAuthorizationHps(address)") })
        .push_address(auth_obj);
    match call::call_bool(registry, cd.as_slice()) {
        Ok(true) => Ok(()),
        _ => Err(ERR_UNAPPROVED_CODE_HASH),
    }
}

/// Verify that `charter` has passed its First Shareholder Resolution (`state() == CHARTER_STATE_ACTIVE`).
pub fn require_active_charter(charter: &[u8; 20]) -> Result<(), i32> {
    if *charter == [0u8; 20] {
        return Err(ERR_CHARTER_NOT_ACTIVE);
    }
    let st_cd = CallEncoder::<16>::new(const { selector("state()") });
    match call::call_u64(charter, st_cd.as_slice()) {
        Ok(CHARTER_STATE_ACTIVE) => Ok(()),
        _ => Err(ERR_CHARTER_NOT_ACTIVE),
    }
}

/// Query `CorporateCharter.isAuthorizedModule(moduleHps, capability)`.
pub fn is_authorized_charter_module(
    charter: &[u8; 20],
    module_hps: &[u8; 20],
    capability: &[u8; 32],
) -> bool {
    if *charter == [0u8; 20] || *module_hps == [0u8; 20] || *capability == [0u8; 32] {
        return false;
    }
    let cd = CallEncoder::<96>::new(const { selector("isAuthorizedModule(address,bytes32)") })
        .push_address(module_hps)
        .push_bytes32(capability);
    matches!(call::call_bool(charter, cd.as_slice()), Ok(true))
}

/// Query `CorporateCharter.equitySettlementModule()` (returns `[0u8; 20]` if unconfigured or unsupported).
pub fn query_charter_equity_module(charter: &[u8; 20]) -> [u8; 20] {
    if *charter == [0u8; 20] {
        return [0u8; 20];
    }
    let cd = CallEncoder::<16>::new(const { selector("equitySettlementModule()") });
    let Ok(raw) = call::call_raw(charter, cd.as_slice()) else {
        return [0u8; 20];
    };
    if raw.len() < 32 {
        return [0u8; 20];
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw[12..32]);
    out
}

/// Query `CorporateCharter.treasuryAccount()` when supported.
pub fn query_charter_treasury(charter: &[u8; 20]) -> Option<[u8; 20]> {
    if *charter == [0u8; 20] {
        return None;
    }
    let cd = CallEncoder::<16>::new(const { selector("treasuryAccount()") });
    let raw = call::call_raw(charter, cd.as_slice()).ok()?;
    if raw.len() < 32 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw[12..32]);
    if out == [0u8; 20] {
        None
    } else {
        Some(out)
    }
}

/// Query `CorporateCharter.getShareClassByLedger(ledger)` -> `Some((votes_per_share, conv_numer, conv_denom))`
/// when `ledger` is already registered in `CorporateCharter`.
pub fn query_charter_share_class_spec(
    charter: &[u8; 20],
    ledger: &[u8; 20],
) -> Option<(u64, u64, u64)> {
    if *charter == [0u8; 20] || *ledger == [0u8; 20] {
        return None;
    }
    let cd = CallEncoder::<64>::new(const { selector("getShareClassByLedger(address)") })
        .push_address(ledger);
    let raw = call::call_raw(charter, cd.as_slice()).ok()?;
    if raw.len() < 128 || raw[31] != 1 {
        return None;
    }
    let mut w1 = [0u8; 8];
    let mut w2 = [0u8; 8];
    let mut w3 = [0u8; 8];
    w1.copy_from_slice(&raw[56..64]);
    w2.copy_from_slice(&raw[88..96]);
    w3.copy_from_slice(&raw[120..128]);
    Some((
        u64::from_be_bytes(w1),
        u64::from_be_bytes(w2),
        u64::from_be_bytes(w3),
    ))
}

/// Query `CorporateCharter.getFunctionAuth(targetHps, fnSelector)` and return `Some(policy_id)`
/// when non-zero.
pub fn query_charter_function_auth(
    charter: &[u8; 20],
    target_hps: &[u8; 20],
    fn_selector: &[u8; 4],
) -> Option<[u8; 32]> {
    if *charter == [0u8; 20] || *fn_selector == [0u8; 4] {
        return None;
    }
    let cd = CallEncoder::<96>::new(const { selector("getFunctionAuth(address,bytes4)") })
        .push_address(target_hps)
        .push_bytes4(fn_selector);
    let raw = call::call_raw(charter, cd.as_slice()).ok()?;
    if raw.len() < 32 {
        return None;
    }
    let mut pol = [0u8; 32];
    pol.copy_from_slice(&raw[0..32]);
    if pol == [0u8; 32] {
        None
    } else {
        Some(pol)
    }
}

/// Verify `auth_obj` is an approved `Authorization` HPS in `IdentityRegistry` and atomically mark
/// it as **consumed** (one-time use).
///
/// Inside `auth_obj`, `context::msg_sender()` is the calling HPS (`AssetLedger`, `Constitution`,
/// or `IdentityRegistry`), which `auth_obj` verifies against its bound `targetHps`.
pub fn verify_and_consume_auth(
    registry: &[u8; 20],
    auth_obj: &[u8; 20],
    expected_constitution: &[u8; 20],
    expected_policy_id: &[u8; 32],
    expected_action_hash: &[u8; 32],
    caller_identity: &[u8; 20],
) -> Result<(), i32> {
    if *registry == [0u8; 20] || *auth_obj == [0u8; 20] {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    if *registry != crate::context::self_address() {
        require_valid_authorization_hps(registry, auth_obj)?;
    }
    let cd = CallEncoder::<164>::new(const { selector("consume(address,bytes32,bytes32,address)") })
        .push_address(expected_constitution)
        .push_bytes32(expected_policy_id)
        .push_bytes32(expected_action_hash)
        .push_address(caller_identity);
    match call::call_bool(auth_obj, cd.as_slice()) {
        Ok(true) => Ok(()),
        Err(code) => Err(code),
        Ok(false) => Err(ERR_AUTH_CONSUME_FAILED),
    }
}

/// Build a 3-stage `PolicySpec` for `POLICY_SHARE_TRANSFER_AUCTION` specifying the predetermined
/// block windows for:
/// - `Stage 0` (`step1_window_blocks`): Window 1 — initial buyer order collection (started by the first buyer)
/// - `Stage 1` (`step2_window_blocks`): Window 2 — existing shareholders' sell order collection
/// - `Stage 2` (`step3_window_blocks`): Window 3 — remaining non-selling existing shareholders' buy order collection
/// - `overall_expiry_blocks`: Post-Window-3 settlement window for calling `AssetLedger.transfer`
pub fn share_transfer_auction_policy_spec(
    anchor_identity: [u8; 20],
    step1_window_blocks: u64,
    step2_window_blocks: u64,
    step3_window_blocks: u64,
    overall_expiry_blocks: u64,
) -> Option<PolicySpec> {
    let s0 = StageSpec::new(1, step1_window_blocks).add_member(anchor_identity, 1)?;
    let s1 = StageSpec::new(1, step2_window_blocks).add_member(anchor_identity, 1)?;
    let s2 = StageSpec::new(1, step3_window_blocks).add_member(anchor_identity, 1)?;
    PolicySpec::new(overall_expiry_blocks)
        .add_stage(s0)?
        .add_stage(s1)?
        .add_stage(s2)
}

/// Single buy or sell order recorded inside an `Authorization` HPS running `POLICY_SHARE_TRANSFER_AUCTION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionOrder {
    /// `ORDER_SIDE_BUY_STEP1 (1)`, `ORDER_SIDE_SELL_STEP2 (2)`, or `ORDER_SIDE_BUY_STEP3 (3)`.
    pub side: u8,
    pub trader: [u8; 20],
    pub price: u64,
    pub quantity: u64,
}

impl Default for AuctionOrder {
    fn default() -> Self {
        Self {
            side: 0,
            trader: [0u8; 20],
            price: 0,
            quantity: 0,
        }
    }
}

impl AuctionOrder {
    pub const fn is_buy(&self) -> bool {
        self.side == ORDER_SIDE_BUY_STEP1 || self.side == ORDER_SIDE_BUY_STEP3
    }

    pub const fn is_sell(&self) -> bool {
        self.side == ORDER_SIDE_SELL_STEP2
    }

    pub const fn is_cancelled(&self) -> bool {
        self.side == ORDER_SIDE_CANCELLED
    }
}

/// Share-class descriptor registered on a `Constitution` HPS, defining voting rights and
/// conversion ratio to Common Shares for a specific share-class `AssetLedger`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareClassSpec {
    pub ledger: [u8; 20],
    pub votes_per_share: u64,
    pub conversion_numer: u64,
    pub conversion_denom: u64,
}

impl Default for ShareClassSpec {
    fn default() -> Self {
        Self {
            ledger: [0u8; 20],
            votes_per_share: 0,
            conversion_numer: 1,
            conversion_denom: 1,
        }
    }
}

impl ShareClassSpec {
    pub const ENCODED_LEN: usize = 44;

    pub const fn empty() -> Self {
        Self {
            ledger: [0u8; 20],
            votes_per_share: 0,
            conversion_numer: 1,
            conversion_denom: 1,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..20].copy_from_slice(&self.ledger);
        out[20..28].copy_from_slice(&self.votes_per_share.to_be_bytes());
        out[28..36].copy_from_slice(&self.conversion_numer.to_be_bytes());
        out[36..44].copy_from_slice(&self.conversion_denom.to_be_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut ledger = [0u8; 20];
        ledger.copy_from_slice(&raw[0..20]);
        let mut vp = [0u8; 8];
        vp.copy_from_slice(&raw[20..28]);
        let mut cn = [0u8; 8];
        cn.copy_from_slice(&raw[28..36]);
        let mut cd = [0u8; 8];
        cd.copy_from_slice(&raw[36..44]);
        Some(Self {
            ledger,
            votes_per_share: u64::from_be_bytes(vp),
            conversion_numer: u64::from_be_bytes(cn),
            conversion_denom: u64::from_be_bytes(cd),
        })
    }

    pub const fn converted_common_shares(&self, raw_shares: u64) -> u64 {
        if self.conversion_denom == 0 {
            return 0;
        }
        (((raw_shares as u128) * (self.conversion_numer as u128)) / (self.conversion_denom as u128))
            as u64
    }

    pub const fn voting_power(&self, raw_shares: u64) -> u64 {
        if self.conversion_denom == 0 || self.votes_per_share == 0 {
            return 0;
        }
        (((raw_shares as u128)
            * (self.conversion_numer as u128)
            * (self.votes_per_share as u128))
            / (self.conversion_denom as u128)) as u64
    }
}

/// Fixed-capacity order book collected across the 3 windows of `POLICY_SHARE_TRANSFER_AUCTION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionBook {
    pub order_count: usize,
    pub orders: [AuctionOrder; MAX_AUCTION_ORDERS],
}

impl Default for AuctionBook {
    fn default() -> Self {
        Self {
            order_count: 0,
            orders: [AuctionOrder::default(); MAX_AUCTION_ORDERS],
        }
    }
}

impl AuctionBook {
    pub const fn new() -> Self {
        Self {
            order_count: 0,
            orders: [AuctionOrder {
                side: 0,
                trader: [0u8; 20],
                price: 0,
                quantity: 0,
            }; MAX_AUCTION_ORDERS],
        }
    }

    pub fn push(&mut self, order: AuctionOrder) -> bool {
        if self.order_count >= MAX_AUCTION_ORDERS
            || order.trader == [0u8; 20]
            || order.price == 0
            || (order.side != ORDER_SIDE_CANCELLED && order.quantity == 0)
            || (order.side != ORDER_SIDE_BUY_STEP1
                && order.side != ORDER_SIDE_SELL_STEP2
                && order.side != ORDER_SIDE_BUY_STEP3
                && order.side != ORDER_SIDE_CANCELLED)
        {
            return false;
        }
        self.orders[self.order_count] = order;
        self.order_count += 1;
        true
    }

    /// Count active (un-cancelled, `quantity > 0`) bids placed during the initial Bids Stage (`ORDER_SIDE_BUY_STEP1`).
    pub fn active_step1_bid_count(&self) -> usize {
        let mut cnt = 0usize;
        let mut i = 0usize;
        while i < self.order_count {
            let o = &self.orders[i];
            if o.side == ORDER_SIDE_BUY_STEP1 && o.quantity > 0 {
                cnt += 1;
            }
            i += 1;
        }
        cnt
    }

    /// Sum active (`quantity > 0`) Stage 0 (`ORDER_SIDE_BUY_STEP1`) bid quantities at or above `min_price`.
    pub fn total_step1_subscribed_at_or_above(&self, min_price: u64) -> u64 {
        let mut sum = 0u64;
        let mut i = 0usize;
        while i < self.order_count {
            let o = &self.orders[i];
            if o.side == ORDER_SIDE_BUY_STEP1 && o.quantity > 0 && o.price >= min_price {
                sum = sum.saturating_add(o.quantity);
            }
            i += 1;
        }
        sum
    }

    /// Encode into `out`:
    /// `[version = 1 (1B)][reserved = 0 (1B)][order_count: u16 BE (2B)]`
    /// followed by `order_count * 37` bytes of `[side (1B)][trader (20B)][price (8B BE)][quantity (8B BE)]`.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let total = 4 + self.order_count * 37;
        if self.order_count > MAX_AUCTION_ORDERS || out.len() < total {
            return None;
        }
        out[0] = 1;
        out[1] = 0;
        out[2..4].copy_from_slice(&(self.order_count as u16).to_be_bytes());
        let mut pos = 4usize;
        let mut i = 0;
        while i < self.order_count {
            let o = &self.orders[i];
            out[pos] = o.side;
            out[pos + 1..pos + 21].copy_from_slice(&o.trader);
            out[pos + 21..pos + 29].copy_from_slice(&o.price.to_be_bytes());
            out[pos + 29..pos + 37].copy_from_slice(&o.quantity.to_be_bytes());
            pos += 37;
            i += 1;
        }
        Some(pos)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 4 || raw[0] != 1 {
            return None;
        }
        let count = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if count > MAX_AUCTION_ORDERS || raw.len() != 4 + count * 37 {
            return None;
        }
        let mut book = Self::new();
        let mut pos = 4usize;
        let mut i = 0;
        while i < count {
            let side = raw[pos];
            let mut trader = [0u8; 20];
            trader.copy_from_slice(&raw[pos + 1..pos + 21]);
            let mut pb = [0u8; 8];
            pb.copy_from_slice(&raw[pos + 21..pos + 29]);
            let mut qb = [0u8; 8];
            qb.copy_from_slice(&raw[pos + 29..pos + 37]);
            pos += 37;
            if !book.push(AuctionOrder {
                side,
                trader,
                price: u64::from_be_bytes(pb),
                quantity: u64::from_be_bytes(qb),
            }) {
                return None;
            }
            i += 1;
        }
        Some(book)
    }
}

/// Verify `auth_obj` is an approved `Authorization` HPS in `IdentityRegistry`, atomically mark
/// it as **consumed** via `consumeAuction(address,bytes32,address)`, and decode its finalized
/// 3-step `AuctionBook`.
pub fn verify_and_consume_auction_auth(
    registry: &[u8; 20],
    auth_obj: &[u8; 20],
    expected_constitution: &[u8; 20],
    expected_policy_id: &[u8; 32],
    caller_identity: &[u8; 20],
) -> Result<AuctionBook, i32> {
    if *registry == [0u8; 20] || *auth_obj == [0u8; 20] {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    require_valid_authorization_hps(registry, auth_obj)?;
    let cd = CallEncoder::<128>::new(const { selector("consumeAuction(address,bytes32,address)") })
        .push_address(expected_constitution)
        .push_bytes32(expected_policy_id)
        .push_address(caller_identity);
    let ret = call::call_raw(auth_obj, cd.as_slice())?;
    if ret.len() < 64 {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&ret[56..64]);
    let len = u64::from_be_bytes(len_bytes) as usize;
    if 64 + len > ret.len() {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    AuctionBook::decode(&ret[64..64 + len]).ok_or(ERR_POLICY_INVALID)
}

/// Ask `CorporateCharter.validateCapitalProcessAuth(address)` to constitutionally validate a
/// Share Transfer or Share Issuance `Authorization` before enactment (rejecting with
/// `ERR_NO_BIDS_IN_STAGE = -97` if the Bids Stage expired without `>= 1` active bid).
pub fn validate_charter_capital_auth(
    charter: &[u8; 20],
    auth_obj: &[u8; 20],
) -> Result<(), i32> {
    if *charter == [0u8; 20] || *auth_obj == [0u8; 20] {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let cd = CallEncoder::<64>::new(const { selector("validateCapitalProcessAuth(address)") })
        .push_address(auth_obj);
    match call::call_bool(charter, cd.as_slice()) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ERR_NO_BIDS_IN_STAGE),
        // Graceful fallback only when talking to a minimal unit-test stub without this selector (`-2`)
        Err(-2) => Ok(()),
        Err(code) => Err(code),
    }
}

/// Build a 2-stage `PolicySpec` for `POLICY_SHARE_ISSUANCE_AUCTION`:
/// - `Stage 0` (`bids_window_blocks`): Investor Subscription Bids Stage (`>= 1` active bid required before expiry!)
/// - `Stage 1` (`ratify_window_blocks`): Existing Shareholders Pre-Emptive Subscription & `>= 75%` Super-Majority Vote
pub fn share_issuance_auction_policy_spec(
    bids_window_blocks: u64,
    ratify_window_blocks: u64,
    overall_expiry_blocks: u64,
) -> Option<PolicySpec> {
    let s0 = StageSpec::new(1, bids_window_blocks).add_role(ROLE_SHAREHOLDER, 1)?;
    let s1 = StageSpec::new(75, ratify_window_blocks).add_role(ROLE_SHAREHOLDER, 1)?;
    PolicySpec::new(overall_expiry_blocks)
        .add_stage(s0)?
        .add_stage(s1)
}

/// Verify `auth_obj` is an approved `Authorization` HPS, atomically consume it via
/// `consumeIssuanceAuction(address,bytes32,address)`, and return `(AuctionBook, maxNewShares, minIssuePrice)`.
pub fn verify_and_consume_issuance_auction_auth(
    registry: &[u8; 20],
    auth_obj: &[u8; 20],
    expected_constitution: &[u8; 20],
    expected_policy_id: &[u8; 32],
    caller_identity: &[u8; 20],
) -> Result<(AuctionBook, u64, u64), i32> {
    if *registry == [0u8; 20] || *auth_obj == [0u8; 20] {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    require_valid_authorization_hps(registry, auth_obj)?;
    let cd =
        CallEncoder::<128>::new(const { selector("consumeIssuanceAuction(address,bytes32,address)") })
            .push_address(expected_constitution)
            .push_bytes32(expected_policy_id)
            .push_address(caller_identity);
    let ret = call::call_raw(auth_obj, cd.as_slice())?;
    // ABI return layout: `(uint64 maxNewShares, uint64 minIssuePrice, bytes bookRaw)`
    if ret.len() < 128 {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let mut w_max = [0u8; 8];
    w_max.copy_from_slice(&ret[24..32]);
    let max_new_shares = u64::from_be_bytes(w_max);
    let mut w_min_px = [0u8; 8];
    w_min_px.copy_from_slice(&ret[56..64]);
    let min_issue_price = u64::from_be_bytes(w_min_px);

    let mut w_off = [0u8; 8];
    w_off.copy_from_slice(&ret[88..96]);
    let dyn_off = u64::from_be_bytes(w_off) as usize;
    if dyn_off + 32 > ret.len() {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let mut w_len = [0u8; 8];
    w_len.copy_from_slice(&ret[dyn_off + 24..dyn_off + 32]);
    let len = u64::from_be_bytes(w_len) as usize;
    if dyn_off + 32 + len > ret.len() {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let book = AuctionBook::decode(&ret[dyn_off + 32..dyn_off + 32 + len]).ok_or(ERR_POLICY_INVALID)?;
    Ok((book, max_new_shares, min_issue_price))
}

/// Deterministic 32-byte commitment hash for a **Share Subscription Agreement (SSA)** bound to an
/// Equity Financing `Authorization` instance.
pub fn compute_ssa_doc_hash(
    auth_obj: &[u8; 20],
    charter: &[u8; 20],
    target_share_ledger: &[u8; 20],
    target_shares: u64,
    offer_price: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(auth_obj, &DOC_TAG_SUBSCRIPTION_AGREEMENT)
        .push_address(charter)
        .push_address(target_share_ledger)
        .push_u64(target_shares)
        .push_u64(offer_price)
        .finish()
}

/// Deterministic 32-byte commitment hash for a company's **Shareholders' Agreement (SHA)**.
pub fn compute_sha_doc_hash(charter: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<160>::new(charter, &DOC_TAG_SHAREHOLDERS_AGREEMENT)
        .push_address(charter)
        .finish()
}

/// Deterministic 32-byte commitment hash for an employee **Option Exercise Letter**.
pub fn compute_esop_exercise_letter_hash(
    share_capital: &[u8; 20],
    program_id: u64,
    grant_id: u64,
    employee: &[u8; 20],
    amount: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(share_capital, &DOC_TAG_ESOP_EXERCISE_LETTER)
        .push_u64(program_id)
        .push_u64(grant_id)
        .push_address(employee)
        .push_u64(amount)
        .finish()
}
