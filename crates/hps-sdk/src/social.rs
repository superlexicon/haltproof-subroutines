//! Composable `#![no_std]` Radio-Bounded Social Network capabilities, standing codecs,
//! and synchronous cross-HPS helpers shared across:
//! - `social-charter` (`SocialCharter` — Root of Trust, Radio Presence, Web-of-Trust & Module Registry)
//! - `social-relationships` (`SocialRelationships` — `2.4 GHz` Encounter Graph & Relationship Tiers)
//! - `social-feed` (`SocialFeed` — Scoped Wall Posts, Comments, Reactions & Proximity DMs)
//! - `social-events` (`SocialEvents` — Neighborhood Meetups & `<=150m` RF Proof-of-Attendance)
//! - `social-marketplace` (`SocialMarketplace` — Verified-Citizen Listings & `<=150m` RF Handover)
//! - `messaging` (`Messaging` — Protected Attributed Social Channels & High-TPS Message Ledger)

use crate::call::{self, CallEncoder};
use crate::context;
use crate::keccak::keccak256;
use crate::selector;

/// Governed sibling-module capabilities registered in `SocialCharter` (mirroring `CorporateCharter`).
pub const CAP_SOCIAL_RELATIONSHIPS: [u8; 32] = keccak256(b"CAP_SOCIAL_RELATIONSHIPS");
pub const CAP_SOCIAL_MESSAGING: [u8; 32] = keccak256(b"CAP_SOCIAL_MESSAGING");
pub const CAP_SOCIAL_EVENTS: [u8; 32] = keccak256(b"CAP_SOCIAL_EVENTS");
pub const CAP_SOCIAL_MARKETPLACE: [u8; 32] = keccak256(b"CAP_SOCIAL_MARKETPLACE");

/// Relationship tiers managed by `SocialRelationships`.
pub const REL_NONE: u64 = 0;
pub const REL_NEIGHBOR: u64 = 1;
pub const REL_FRIEND: u64 = 2;
pub const REL_CLOSE_CIRCLE: u64 = 3;
pub const REL_BLOCKED: u64 = 99;

/// Feed / Event visibility scopes.
pub const SCOPE_SUBNET_COMMONS: u64 = 0;
pub const SCOPE_FRIENDS_ONLY: u64 = 1;
pub const SCOPE_CLOSE_CIRCLE: u64 = 2;

/// Deterministic error codes shared across the modular Social HFS suite.
pub const ERR_SOCIAL_UNINITIALIZED: i32 = -40;
pub const ERR_SOCIAL_ALREADY_INIT: i32 = -41;
pub const ERR_SOCIAL_OUTSIDE_SUBNET: i32 = -42;
pub const ERR_SOCIAL_DORMANT: i32 = -43;
pub const ERR_SOCIAL_PEER_DORMANT: i32 = -44;
pub const ERR_SOCIAL_OUTSIDE_RF_RANGE: i32 = -45;
pub const ERR_SOCIAL_INSUFFICIENT_TRUST: i32 = -46;
pub const ERR_SOCIAL_SANCTIONED: i32 = -47;
pub const ERR_SOCIAL_NOT_REGISTERED: i32 = -48;
pub const ERR_SOCIAL_UNAUTHORIZED_MODULE: i32 = -49;
pub const ERR_SOCIAL_UNAPPROVED_CODE_HASH: i32 = -50;
pub const ERR_SOCIAL_NOT_CONNECTED: i32 = -51;
pub const ERR_SOCIAL_INVALID_ARGS: i32 = -52;
pub const ERR_SOCIAL_CAPACITY_FULL: i32 = -53;
pub const ERR_SOCIAL_HANDSHAKE_INVALID: i32 = -54;
pub const ERR_SOCIAL_DUPLICATE_ACTION: i32 = -55;
pub const ERR_SOCIAL_EVENT_WINDOW: i32 = -56;

/// Unpacked `SocialCharter.memberStanding(address)` 64-bit word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberStanding {
    pub registered: bool,
    pub is_active: bool,
    pub sanctioned: bool,
    pub trust_score: u8,
    pub uid: u8,
}

impl MemberStanding {
    pub const fn pack(self) -> u64 {
        let mut w: u64 = 0;
        if self.registered {
            w |= 1u64 << 40;
        }
        if self.is_active {
            w |= 1u64 << 32;
        }
        if self.sanctioned {
            w |= 1u64 << 24;
        }
        w |= (self.trust_score as u64) << 8;
        w |= self.uid as u64;
        w
    }

    pub const fn unpack(w: u64) -> Self {
        Self {
            registered: ((w >> 40) & 1) == 1,
            is_active: ((w >> 32) & 1) == 1,
            sanctioned: ((w >> 24) & 1) == 1,
            trust_score: ((w >> 8) & 0xFF) as u8,
            uid: (w & 0xFF) as u8,
        }
    }
}

/// Query `SocialCharter.memberStanding(user)` via `host_call_contract`.
pub fn query_member_standing(
    charter: &[u8; 20],
    user: &[u8; 20],
) -> Result<MemberStanding, i32> {
    let cd = CallEncoder::<68>::new(const { selector("memberStanding(address)") })
        .push_address(user);
    let packed = call::call_u64(charter, cd.as_slice())?;
    Ok(MemberStanding::unpack(packed))
}

/// Require `user` to be registered, unsanctioned, Active In-Subnet (inside `Sub-GHz` radius + fresh
/// radio heartbeat), and holding `>= min_trust` Web-of-Trust standing.
pub fn require_active_member(
    charter: &[u8; 20],
    user: &[u8; 20],
    min_trust: u8,
) -> Result<MemberStanding, i32> {
    let st = query_member_standing(charter, user)?;
    if !st.registered {
        return Err(ERR_SOCIAL_NOT_REGISTERED);
    }
    if st.sanctioned {
        return Err(ERR_SOCIAL_SANCTIONED);
    }
    if !st.is_active {
        return Err(ERR_SOCIAL_DORMANT);
    }
    if st.trust_score < min_trust {
        return Err(ERR_SOCIAL_INSUFFICIENT_TRUST);
    }
    Ok(st)
}

/// Require both `a` and `b` to be Active In-Subnet AND physically within `SocialCharter`'s
/// `2.4 GHz` Direct RF Encounter range (`<= rf_encounter_range_m`).
pub fn require_mutual_rf_proximity(
    charter: &[u8; 20],
    a: &[u8; 20],
    b: &[u8; 20],
) -> Result<(), i32> {
    let cd = CallEncoder::<100>::new(const {
        selector("checkMutualRfProximity(address,address)")
    })
    .push_address(a)
    .push_address(b);
    let ok = call::call_bool(charter, cd.as_slice())?;
    if ok {
        Ok(())
    } else {
        Err(ERR_SOCIAL_OUTSIDE_RF_RANGE)
    }
}

/// Require `user` to be Active In-Subnet AND physically within `<= rf_encounter_range_m` of `(x_m, y_m)`.
pub fn require_venue_rf_proximity(
    charter: &[u8; 20],
    user: &[u8; 20],
    x_m: u64,
    y_m: u64,
) -> Result<(), i32> {
    let cd = CallEncoder::<132>::new(const {
        selector("checkVenueRfProximity(address,uint64,uint64)")
    })
    .push_address(user)
    .push_u64(x_m)
    .push_u64(y_m);
    let ok = call::call_bool(charter, cd.as_slice())?;
    if ok {
        Ok(())
    } else {
        Err(ERR_SOCIAL_OUTSIDE_RF_RANGE)
    }
}

/// Adjust `user`'s Civic Trust Score on `SocialCharter` from an authorized Social Module.
pub fn adjust_standing_from_module(
    charter: &[u8; 20],
    user: &[u8; 20],
    amount: u64,
    increase: bool,
) -> Result<(), i32> {
    let cd = CallEncoder::<132>::new(const {
        selector("adjustStandingFromModule(address,uint64,bool)")
    })
    .push_address(user)
    .push_u64(amount)
    .push_bool(increase);
    call::call_raw(charter, cd.as_slice())?;
    Ok(())
}

/// Query `SocialRelationships.areActiveConnected(a, b, minTier)` — returns `true` iff `a` and `b`
/// hold an RF-verified relationship `>= min_tier` AND both are currently Active In-Subnet!
pub fn query_active_connected(
    relationships: &[u8; 20],
    a: &[u8; 20],
    b: &[u8; 20],
    min_tier: u64,
) -> Result<bool, i32> {
    let cd = CallEncoder::<132>::new(const {
        selector("areActiveConnected(address,address,uint64)")
    })
    .push_address(a)
    .push_address(b)
    .push_u64(min_tier);
    call::call_bool(relationships, cd.as_slice())
}

/// Canonical deterministic DM channel hash between two addresses scoped to `charter`.
pub fn canonical_dm_channel(charter: &[u8; 20], a: &[u8; 20], b: &[u8; 20]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut pre = [0u8; 12 + 20 + 20 + 20];
    pre[0..12].copy_from_slice(b"SLX_DM_CH_V1");
    pre[12..32].copy_from_slice(charter);
    pre[32..52].copy_from_slice(lo);
    pre[52..72].copy_from_slice(hi);
    keccak256(&pre)
}

/// Derive a deterministic module-owned channel hash (`prefix || charter || id`).
pub fn derive_social_channel(prefix: &[u8; 12], charter: &[u8; 20], id: u64) -> [u8; 32] {
    let mut pre = [0u8; 40];
    pre[0..12].copy_from_slice(prefix);
    pre[12..32].copy_from_slice(charter);
    pre[32..40].copy_from_slice(&id.to_be_bytes());
    keccak256(&pre)
}

/// Bind `channel` to `self_address()` on `Messaging` (if not yet bound) and append `payload`
/// attributed to `author` via `Messaging.postAttributedMessage`.
pub fn messaging_post_attributed<const CAP: usize>(
    messaging_hps: &[u8; 20],
    channel: &[u8; 32],
    author: &[u8; 20],
    payload: &[u8],
) -> Result<(), i32> {
    let me = context::self_address();

    // Check current controller of `channel`
    let q_cd = CallEncoder::<68>::new(const { selector("channelController(bytes32)") })
        .push_bytes32(channel);
    let ctl_raw = call::call_raw(messaging_hps, q_cd.as_slice())?;
    if ctl_raw.len() >= 32 && ctl_raw[12..32] == [0u8; 20] {
        let bind_cd = CallEncoder::<100>::new(const {
            selector("bindChannelController(bytes32,address)")
        })
        .push_bytes32(channel)
        .push_address(&me);
        call::call_raw(messaging_hps, bind_cd.as_slice())?;
    }

    let post_cd = CallEncoder::<CAP>::new(const {
        selector("postAttributedMessage(bytes32,address,bytes)")
    })
    .push_bytes32(channel)
    .push_address(author)
    .push_u64(0x60)
    .push_dynamic_bytes_tail(payload);
    call::call_raw(messaging_hps, post_cd.as_slice())?;
    Ok(())
}

/// Read recent messages from `Messaging.getRecentMessages(channel, max_count)` into `out`.
pub fn messaging_get_recent_into(
    messaging_hps: &[u8; 20],
    channel: &[u8; 32],
    max_count: u64,
    out: &mut [u8],
) -> Result<usize, i32> {
    let cd = CallEncoder::<100>::new(const { selector("getRecentMessages(bytes32,uint64)") })
        .push_bytes32(channel)
        .push_u64(max_count);
    call::call_into(messaging_hps, cd.as_slice(), out)
}
