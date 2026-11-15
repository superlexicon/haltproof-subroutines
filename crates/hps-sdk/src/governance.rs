//! Composable `#![no_std]` governance, sequential/weighted authorization policy codecs,
//! action commitment hashing, and cross-HPS verification helpers shared across:
//! - `identity-registry`
//! - `identity`
//! - `constitution`
//! - `authorization`
//! - `asset-ledger`
//! - `asset-pair-otc`

use crate::call::{self, CallEncoder};
use crate::keccak::keccak256;
use crate::selector;

pub const POLICY_WIRE_VERSION: u8 = 1;
pub const MAX_STAGES: usize = 8;
pub const MAX_MEMBERS_PER_STAGE: usize = 16;
pub const MAX_ENCODED_POLICY_BYTES: usize = 4096;

/// Canonical 32-byte action keys used in `AssetLedger` permissions and `Constitution` policies.
pub const ACTION_ISSUE: [u8; 32] = keccak256(b"ISSUE");
pub const ACTION_CANCEL: [u8; 32] = keccak256(b"CANCEL");
pub const ACTION_TRANSFER: [u8; 32] = keccak256(b"TRANSFER");
pub const ACTION_APPROVE: [u8; 32] = keccak256(b"APPROVE");
pub const ACTION_SUPER: [u8; 32] = keccak256(b"SUPER");

/// Canonical policy IDs for `Constitution`, `AssetLedger`, and `IdentityRegistry` governance.
pub const POLICY_SUPER_GOVERNANCE: [u8; 32] = keccak256(b"SUPER_GOVERNANCE");
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

/// Single authorizer entry within a sequential authorization stage.
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

/// One sequential step in a multi-stage authorization process.
///
/// Stage `s` must accumulate `>= required_weight` from its listed `members` within
/// `expiry_blocks` of Stage `s` becoming active before Stage `s + 1` can accept any approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageSpec {
    pub required_weight: u64,
    pub expiry_blocks: u64,
    pub member_count: usize,
    pub members: [AuthorizerMember; MAX_MEMBERS_PER_STAGE],
}

impl Default for StageSpec {
    fn default() -> Self {
        Self {
            required_weight: 0,
            expiry_blocks: 0,
            member_count: 0,
            members: [AuthorizerMember::default(); MAX_MEMBERS_PER_STAGE],
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
        }
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

    pub fn validate(&self) -> bool {
        if self.required_weight == 0
            || self.expiry_blocks == 0
            || self.member_count == 0
            || self.member_count > MAX_MEMBERS_PER_STAGE
        {
            return false;
        }
        let mut total_weight: u64 = 0;
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
            total_weight = match total_weight.checked_add(m.weight) {
                Some(v) => v,
                None => return false,
            };
            i += 1;
        }
        self.required_weight <= total_weight
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
    /// - Per stage: `[required_weight: u64 BE (8B)][expiry_blocks: u64 BE (8B)][member_count: u8][0u8; 7]` (24 B)
    ///   followed by `member_count * 28` bytes of `[identity: 20B][weight: u64 BE (8B)]`.
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
            let need = 24 + st.member_count * 28;
            if pos + need > out.len() {
                return None;
            }
            out[pos..pos + 8].copy_from_slice(&st.required_weight.to_be_bytes());
            out[pos + 8..pos + 16].copy_from_slice(&st.expiry_blocks.to_be_bytes());
            out[pos + 16] = st.member_count as u8;
            out[pos + 17..pos + 24].copy_from_slice(&[0u8; 7]);
            pos += 24;

            let mut m = 0;
            while m < st.member_count {
                out[pos..pos + 20].copy_from_slice(&st.members[m].identity);
                out[pos + 20..pos + 28].copy_from_slice(&st.members[m].weight.to_be_bytes());
                pos += 28;
                m += 1;
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
            pos += 24;

            if member_count == 0
                || member_count > MAX_MEMBERS_PER_STAGE
                || pos + member_count * 28 > raw.len()
            {
                return None;
            }

            let mut stage = StageSpec {
                required_weight,
                expiry_blocks,
                member_count,
                members: [AuthorizerMember::default(); MAX_MEMBERS_PER_STAGE],
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
            spec.stages[s] = stage;
            s += 1;
        }

        if pos != raw.len() || !spec.validate() {
            return None;
        }
        Some(spec)
    }
}

/// Domain-separated Keccak-256 commitment binding a one-time `Authorization` object to
/// `(target_hps, action_tag, exact_parameters)`.
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
        let d = keccak256(data);
        self.push_raw(&d)
    }

    pub fn finish(&self) -> [u8; 32] {
        debug_assert!(!self.overflowed);
        keccak256(&self.buf[..self.len])
    }
}

/// Verify via cross-HPS call into `IdentityRegistry` (`isValidIdentity(address)`) that `identity`
/// is registered, currently active (`status == 1`), **and** deployed from an approved `Identity`
/// WASM bytecode hash (`code_hash`).
pub fn require_valid_identity(registry: &[u8; 20], identity: &[u8; 20]) -> Result<(), i32> {
    if *registry == [0u8; 20] || *identity == [0u8; 20] {
        return Err(ERR_INVALID_IDENTITY);
    }
    let cd = CallEncoder::<64>::new(selector("isValidIdentity(address)")).push_address(identity);
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
    let cd = CallEncoder::<64>::new(selector("isValidAuthorizationHps(address)"))
        .push_address(auth_obj);
    match call::call_bool(registry, cd.as_slice()) {
        Ok(true) => Ok(()),
        _ => Err(ERR_UNAPPROVED_CODE_HASH),
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
    let cd = CallEncoder::<164>::new(selector("consume(address,bytes32,bytes32,address)"))
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
