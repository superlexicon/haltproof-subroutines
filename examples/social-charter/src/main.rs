//! # `SocialCharter` — Radio-Bounded Social Root of Trust (`social-charter` — HPS #14A)
//!
//! Direct architectural counterpart to `CorporateCharter` for a physical-radio-bounded
//! neighborhood social network built on SuperLexicon's `Identity`, `IdentityRegistry`,
//! `Messaging`, and `ProductLedger` Haltproof Subroutines:
//!
//! 1. **Verified `Identity` HFS Membership (`IdentityRegistry`-Pinned)**:
//!    - Every participant on `SocialCharter` MUST be an active `Identity` HFS (`identity.wasm`)
//!      verified via `IdentityRegistry.isValidIdentity(caller)` (`require_valid_identity`).
//! 2. **Constitutional Radio & Subnet Parameters**:
//!    - Stores `subnetRadiusM` (`Sub-GHz`), `rfEncounterRangeM` (`2.4 GHz`),
//!      `heartbeatLeaseBlocks`, `identityRegistry`, and `messagingHps`.
//! 3. **Identity-Owned `ProductLedger` Storefront Directory (`attachProductLedger`)**:
//!    - Verified Citizens (`Trust >= 60`) attach their personal `Identity`-owned `ProductLedger`
//!      HFS (`ProductLedger.ownerIdentity() == callerIdentity`), enabling decentralized
//!      peer-to-peer & local-merchant marketplace discovery with `<=150m` `2.4 GHz` RF checkout.
//! 4. **Authorized Social Module Registry (`code_hash`-verified)**:
//!    - Governs sibling modules (`SocialRelationships`, `SocialFeed`, `SocialEvents`) verified
//!      live via `context::code_hash_of`.
//! 5. **Physical Web-of-Trust Vouching & Co-Signed Accountability**:
//!    - Enforces `<=150m` in-person vouches and slashes reckless co-signing vouchers (`-18 Trust`)
//!      when `>= 2` verified neighbors flag a fake or abusive `Identity`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::require_valid_identity;
use hps_sdk::social::{
    MemberStanding, CAP_SOCIAL_EVENTS, CAP_SOCIAL_MARKETPLACE, CAP_SOCIAL_MESSAGING,
    CAP_SOCIAL_RELATIONSHIPS, ERR_SOCIAL_ALREADY_INIT, ERR_SOCIAL_CAPACITY_FULL,
    ERR_SOCIAL_DORMANT, ERR_SOCIAL_DUPLICATE_ACTION, ERR_SOCIAL_INSUFFICIENT_TRUST,
    ERR_SOCIAL_INVALID_ARGS, ERR_SOCIAL_NOT_REGISTERED, ERR_SOCIAL_OUTSIDE_RF_RANGE,
    ERR_SOCIAL_OUTSIDE_SUBNET, ERR_SOCIAL_PEER_DORMANT, ERR_SOCIAL_SANCTIONED,
    ERR_SOCIAL_UNAPPROVED_CODE_HASH, ERR_SOCIAL_UNAUTHORIZED_MODULE, ERR_SOCIAL_UNINITIALIZED,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const MAX_MEMBERS: usize = 64;
pub const MAX_VOUCHERS: usize = 4;
pub const MAX_META_LEN: usize = 160;
pub const SUBNET_CENTER_X: u32 = 1500;
pub const SUBNET_CENTER_Y: u32 = 1500;
pub const MAX_COORD_M: u64 = 10_000;

pub const FOUNDER_INITIAL_TRUST: u8 = 88;
pub const NEWCOMER_INITIAL_TRUST: u8 = 35;
pub const MIN_TRUST_TO_VOUCH: u8 = 60;
pub const MIN_TRUST_TO_FLAG: u8 = 55;
pub const SANCTION_TRUST_FLOOR: u8 = 15;

const EV_CHARTER_INITIALIZED: [u8; 32] =
    event_topic("SocialCharterInitialized(address,address,address,uint64,uint64)");
const EV_MODULE_AUTHORIZED: [u8; 32] =
    event_topic("SocialModuleAuthorized(address,bytes32,bytes32,bool)");
const EV_MEMBER_REGISTERED: [u8; 32] =
    event_topic("SocialMemberRegistered(address,uint64,uint64,uint64)");
const EV_STOREFRONT_ATTACHED: [u8; 32] =
    event_topic("IdentityProductLedgerAttached(address,address)");
const EV_NEIGHBOR_VOUCHED: [u8; 32] = event_topic("NeighborVouched(address,address,uint64)");
const EV_ACCOUNTABILITY_FLAGGED: [u8; 32] =
    event_topic("AccountabilityFlagged(address,address,uint64,uint64)");
const EV_VOUCHER_SLASHED: [u8; 32] = event_topic("VoucherSlashed(address,address,uint64)");

const KEY_HDR: &[u8] = b"sc:hdr";
const KEY_MOD_SLOTS: &[u8] = b"sc:mslots";

static mut SNAP_OUT: [u8; 24_576] = [0u8; 24_576];

hps_entry! {
    "initialize(address,address,uint64,uint64,uint64,bytes)" => handle_initialize,
    "authorizeModule(address,bytes32,bytes32,bool)"          => handle_authorize_module,
    "isAuthorizedModule(address,bytes32)"                    => handle_is_authorized_module,
    "registerProfile(uint64,uint64,bytes)"                   => handle_register_profile,
    "syncVerifiedIdentity(address)"                          => handle_sync_verified_identity,
    "attachProductLedger(address)"                           => handle_attach_product_ledger,
    "productLedgerOf(address)"                               => handle_product_ledger_of,
    "pingPresence(uint64,uint64)"                            => handle_ping_presence,
    "vouchNeighbor(address)"                                 => handle_vouch_neighbor,
    "flagAccountability(address,uint64)"                     => handle_flag_accountability,
    "adjustStandingFromModule(address,uint64,bool)"          => handle_adjust_standing,
    "memberStanding(address)"                                => handle_member_standing,
    "checkMutualRfProximity(address,address)"                => handle_check_mutual_rf,
    "checkVenueRfProximity(address,uint64,uint64)"           => handle_check_venue_rf,
    "identityRegistry()"                                     => handle_identity_registry,
    "messagingHps()"                                         => handle_messaging_hps,
    "getCharterSnapshot()"                                   => handle_get_snapshot,
}

#[derive(Clone, Copy)]
struct CharterHeader {
    initialized: u8,
    member_count: u8,
    founder_identity: [u8; 20],
    identity_registry: [u8; 20],
    messaging_hps: [u8; 20],
    subnet_radius_m: u32,
    rf_encounter_range_m: u32,
    heartbeat_lease_blocks: u32,
    total_slashes: u32,
}

impl CharterHeader {
    fn save(&self) {
        let mut b = [0u8; 84];
        b[0] = self.initialized;
        b[1] = self.member_count;
        b[4..24].copy_from_slice(&self.founder_identity);
        b[24..44].copy_from_slice(&self.identity_registry);
        b[44..64].copy_from_slice(&self.messaging_hps);
        b[64..68].copy_from_slice(&self.subnet_radius_m.to_le_bytes());
        b[68..72].copy_from_slice(&self.rf_encounter_range_m.to_le_bytes());
        b[72..76].copy_from_slice(&self.heartbeat_lease_blocks.to_le_bytes());
        b[76..80].copy_from_slice(&self.total_slashes.to_le_bytes());
        storage::set(KEY_HDR, &b);
    }

    fn load() -> Result<Self, i32> {
        let mut b = [0u8; 84];
        if storage::get_into(KEY_HDR, &mut b) != Some(84) || b[0] != 1 {
            return Err(ERR_SOCIAL_UNINITIALIZED);
        }
        let mut founder_identity = [0u8; 20];
        founder_identity.copy_from_slice(&b[4..24]);
        let mut identity_registry = [0u8; 20];
        identity_registry.copy_from_slice(&b[24..44]);
        let mut messaging_hps = [0u8; 20];
        messaging_hps.copy_from_slice(&b[44..64]);

        Ok(Self {
            initialized: 1,
            member_count: b[1],
            founder_identity,
            identity_registry,
            messaging_hps,
            subnet_radius_m: u32::from_le_bytes([b[64], b[65], b[66], b[67]]),
            rf_encounter_range_m: u32::from_le_bytes([b[68], b[69], b[70], b[71]]),
            heartbeat_lease_blocks: u32::from_le_bytes([b[72], b[73], b[74], b[75]]),
            total_slashes: u32::from_le_bytes([b[76], b[77], b[78], b[79]]),
        })
    }
}

#[derive(Clone, Copy)]
struct MemberRecord {
    identity: [u8; 20],
    product_ledger: [u8; 20],
    uid: u8,
    trust_score: u8,
    sanctioned: u8,
    voucher_count: u8,
    vouchers: [u8; MAX_VOUCHERS],
    vouchers_slashed: u8,
    slash_count: u8,
    last_flag_reason: u8,
    x_m: u16,
    y_m: u16,
    last_heartbeat_block: u64,
    flagged_by_mask: u64,
    meta_len: u8,
    meta: [u8; MAX_META_LEN],
}

impl MemberRecord {
    fn save(&self) {
        let mut b = [0u8; 76 + MAX_META_LEN];
        b[0..20].copy_from_slice(&self.identity);
        b[20..40].copy_from_slice(&self.product_ledger);
        b[40] = self.uid;
        b[41] = self.trust_score;
        b[42] = self.sanctioned;
        b[43] = self.voucher_count;
        b[44..48].copy_from_slice(&self.vouchers);
        b[48] = self.vouchers_slashed;
        b[49] = self.slash_count;
        b[50] = self.last_flag_reason;
        let mlen = (self.meta_len as usize).min(MAX_META_LEN);
        b[51] = mlen as u8;
        b[52..54].copy_from_slice(&self.x_m.to_le_bytes());
        b[54..56].copy_from_slice(&self.y_m.to_le_bytes());
        b[56..64].copy_from_slice(&self.last_heartbeat_block.to_le_bytes());
        b[64..72].copy_from_slice(&self.flagged_by_mask.to_le_bytes());
        b[76..76 + mlen].copy_from_slice(&self.meta[..mlen]);

        let k = key_member(self.uid);
        storage::set(k.as_slice(), &b[..76 + mlen]);
    }

    fn load(uid: u8) -> Option<Self> {
        let k = key_member(uid);
        let mut b = [0u8; 76 + MAX_META_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < 76 {
            return None;
        }
        let mlen = (b[51] as usize).min(MAX_META_LEN).min(n - 76);
        let mut meta = [0u8; MAX_META_LEN];
        meta[..mlen].copy_from_slice(&b[76..76 + mlen]);
        let mut identity = [0u8; 20];
        identity.copy_from_slice(&b[0..20]);
        let mut product_ledger = [0u8; 20];
        product_ledger.copy_from_slice(&b[20..40]);
        let mut vouchers = [0u8; 4];
        vouchers.copy_from_slice(&b[44..48]);

        Some(Self {
            identity,
            product_ledger,
            uid: b[40],
            trust_score: b[41],
            sanctioned: b[42],
            voucher_count: b[43],
            vouchers,
            vouchers_slashed: b[48],
            slash_count: b[49],
            last_flag_reason: b[50],
            x_m: u16::from_le_bytes([b[52], b[53]]),
            y_m: u16::from_le_bytes([b[54], b[55]]),
            last_heartbeat_block: u64::from_le_bytes(b[56..64].try_into().ok()?),
            flagged_by_mask: u64::from_le_bytes(b[64..72].try_into().ok()?),
            meta_len: mlen as u8,
            meta,
        })
    }
}

fn key_uid(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sc:u:").push(identity)
}

fn key_member(uid: u8) -> KeyBuilder<16> {
    KeyBuilder::<16>::new().push(b"sc:m:").push(&[uid])
}

fn key_store_owner(product_ledger: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sc:pl:").push(product_ledger)
}

fn key_mod_auth(module_hps: &[u8; 20], cap: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"sc:mod:")
        .push(module_hps)
        .push(cap)
}

fn lookup_uid(identity: &[u8; 20]) -> Option<u8> {
    let v = storage::get_u64(key_uid(identity).as_slice());
    if v == 0 {
        None
    } else {
        Some((v - 1) as u8)
    }
}

#[inline]
fn dist_sq(x1: u64, y1: u64, x2: u64, y2: u64) -> u64 {
    let dx = if x1 >= x2 { x1 - x2 } else { x2 - x1 };
    let dy = if y1 >= y2 { y1 - y2 } else { y2 - y1 };
    dx * dx + dy * dy
}

#[inline]
fn inside_subnet(x: u64, y: u64, radius_m: u32) -> bool {
    let r = radius_m as u64;
    dist_sq(x, y, SUBNET_CENTER_X as u64, SUBNET_CENTER_Y as u64) <= r * r
}

#[inline]
fn is_active_now(m: &MemberRecord, hdr: &CharterHeader, blk: u64) -> bool {
    if m.sanctioned != 0 || m.trust_score < SANCTION_TRUST_FLOOR {
        return false;
    }
    if !inside_subnet(m.x_m as u64, m.y_m as u64, hdr.subnet_radius_m) {
        return false;
    }
    blk.saturating_sub(m.last_heartbeat_block) <= (hdr.heartbeat_lease_blocks as u64)
}

fn verify_module_cap(module_hps: &[u8; 20], cap: &[u8; 32]) -> Result<bool, i32> {
    let k = key_mod_auth(module_hps, cap);
    let mut raw = [0u8; 33];
    if storage::get_into(k.as_slice(), &mut raw) != Some(33) || raw[0] != 1 {
        return Ok(false);
    }
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&raw[1..33]);
    if expected_hash != [0u8; 32] {
        match context::code_hash_of(module_hps) {
            Some(actual) if actual == expected_hash => Ok(true),
            _ => Err(ERR_SOCIAL_UNAPPROVED_CODE_HASH),
        }
    } else {
        Ok(true)
    }
}

fn is_authorized_standing_adjuster(candidate: &[u8; 20]) -> Result<bool, i32> {
    for cap in [
        CAP_SOCIAL_RELATIONSHIPS,
        CAP_SOCIAL_MESSAGING,
        CAP_SOCIAL_EVENTS,
        CAP_SOCIAL_MARKETPLACE,
    ] {
        if verify_module_cap(candidate, &cap)? {
            return Ok(true);
        }
    }
    // Also trust any attached Identity-owned `ProductLedger` storefront!
    if storage::get_u64(key_store_owner(candidate).as_slice()) == 1 {
        return Ok(true);
    }
    Ok(false)
}

fn load_mod_slots() -> [[u8; 20]; 3] {
    let mut raw = [0u8; 60];
    let mut out = [[0u8; 20]; 3];
    if storage::get_into(KEY_MOD_SLOTS, &mut raw) == Some(60) {
        let mut i = 0;
        while i < 3 {
            out[i].copy_from_slice(&raw[i * 20..(i + 1) * 20]);
            i += 1;
        }
    }
    out
}

fn save_mod_slots(slots: &[[u8; 20]; 3]) {
    let mut raw = [0u8; 60];
    let mut i = 0;
    while i < 3 {
        raw[i * 20..(i + 1) * 20].copy_from_slice(&slots[i]);
        i += 1;
    }
    storage::set(KEY_MOD_SLOTS, &raw);
}

// ---------------------------------------------------------------------------
// Entrypoints
// ---------------------------------------------------------------------------

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if CharterHeader::load().is_ok() {
        return Err(ERR_SOCIAL_ALREADY_INIT);
    }
    let identity_registry = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let messaging_hps = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let radius_m = args.u64(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?.clamp(300, 5000) as u32;
    let rf_range_m = args.u64(3).ok_or(ERR_SOCIAL_INVALID_ARGS)?.clamp(30, 500) as u32;
    let lease_blks = args.u64(4).ok_or(ERR_SOCIAL_INVALID_ARGS)?.clamp(3, 500_000) as u32;
    let founder_meta = args.dynamic_bytes(5).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if identity_registry == [0u8; 20]
        || messaging_hps == [0u8; 20]
        || founder_meta.len() > MAX_META_LEN
    {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let founder_identity = context::msg_sender();
    require_valid_identity(&identity_registry, &founder_identity)?;
    let blk = context::block_number();

    let hdr = CharterHeader {
        initialized: 1,
        member_count: 1,
        founder_identity,
        identity_registry,
        messaging_hps,
        subnet_radius_m: radius_m,
        rf_encounter_range_m: rf_range_m,
        heartbeat_lease_blocks: lease_blks,
        total_slashes: 0,
    };
    hdr.save();

    let mut meta = [0u8; MAX_META_LEN];
    meta[..founder_meta.len()].copy_from_slice(founder_meta);
    let m0 = MemberRecord {
        identity: founder_identity,
        product_ledger: [0u8; 20],
        uid: 0,
        trust_score: FOUNDER_INITIAL_TRUST,
        sanctioned: 0,
        voucher_count: 0,
        vouchers: [0u8; 4],
        vouchers_slashed: 0,
        slash_count: 0,
        last_flag_reason: 0,
        x_m: SUBNET_CENTER_X as u16,
        y_m: SUBNET_CENTER_Y as u16,
        last_heartbeat_block: blk,
        flagged_by_mask: 0,
        meta_len: founder_meta.len() as u8,
        meta,
    };
    m0.save();
    storage::set_u64(key_uid(&founder_identity).as_slice(), 1);

    let mut ev = [0u8; 76];
    ev[0..20].copy_from_slice(&founder_identity);
    ev[20..40].copy_from_slice(&identity_registry);
    ev[40..60].copy_from_slice(&messaging_hps);
    ev[60..68].copy_from_slice(&(radius_m as u64).to_be_bytes());
    ev[68..76].copy_from_slice(&(rf_range_m as u64).to_be_bytes());
    events::emit(&[EV_CHARTER_INITIALIZED], &ev);
    Ok(())
}

fn handle_authorize_module(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    if context::msg_sender() != hdr.founder_identity {
        return Err(ERR_SOCIAL_UNAUTHORIZED_MODULE);
    }
    let module_hps = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let cap = args.bytes32(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let expected_hash = args.bytes32(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let allowed = args.bool(3).ok_or(ERR_SOCIAL_INVALID_ARGS)?;

    if allowed && expected_hash != [0u8; 32] {
        match context::code_hash_of(&module_hps) {
            Some(actual) if actual == expected_hash => {}
            _ => return Err(ERR_SOCIAL_UNAPPROVED_CODE_HASH),
        }
    }

    let mut rec = [0u8; 33];
    rec[0] = u8::from(allowed);
    rec[1..33].copy_from_slice(&expected_hash);
    storage::set(key_mod_auth(&module_hps, &cap).as_slice(), &rec);

    let mut slots = load_mod_slots();
    let slot_val = if allowed { module_hps } else { [0u8; 20] };
    if cap == CAP_SOCIAL_RELATIONSHIPS {
        slots[0] = slot_val;
    } else if cap == CAP_SOCIAL_MESSAGING {
        slots[1] = slot_val;
    } else if cap == CAP_SOCIAL_EVENTS {
        slots[2] = slot_val;
    }
    save_mod_slots(&slots);

    let mut ev = [0u8; 53];
    ev[0..20].copy_from_slice(&module_hps);
    ev[20..52].copy_from_slice(&expected_hash);
    ev[52] = u8::from(allowed);
    events::emit(&[EV_MODULE_AUTHORIZED, cap], &ev);
    Ok(())
}

fn handle_is_authorized_module(args: &CalldataReader) -> Result<(), i32> {
    let _hdr = CharterHeader::load()?;
    let module_hps = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let cap = args.bytes32(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let ok = verify_module_cap(&module_hps, &cap).unwrap_or(false);
    ret::write_bool(ok);
    Ok(())
}

fn handle_register_profile(args: &CalldataReader) -> Result<(), i32> {
    let mut hdr = CharterHeader::load()?;
    let x_m = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let y_m = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let profile_meta = args.dynamic_bytes(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if x_m > MAX_COORD_M || y_m > MAX_COORD_M || profile_meta.len() > MAX_META_LEN {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    if !inside_subnet(x_m, y_m, hdr.subnet_radius_m) {
        return Err(ERR_SOCIAL_OUTSIDE_SUBNET);
    }

    let caller_identity = context::msg_sender();
    // Enforce verified `Identity` HFS registered in `IdentityRegistry`!
    require_valid_identity(&hdr.identity_registry, &caller_identity)?;

    let blk = context::block_number();

    if let Some(uid) = lookup_uid(&caller_identity) {
        let mut m = MemberRecord::load(uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
        if m.sanctioned != 0 {
            return Err(ERR_SOCIAL_SANCTIONED);
        }
        m.x_m = x_m as u16;
        m.y_m = y_m as u16;
        m.last_heartbeat_block = blk;
        m.meta = [0u8; MAX_META_LEN];
        m.meta[..profile_meta.len()].copy_from_slice(profile_meta);
        m.meta_len = profile_meta.len() as u8;
        m.save();
        return Ok(());
    }

    if (hdr.member_count as usize) >= MAX_MEMBERS {
        return Err(ERR_SOCIAL_CAPACITY_FULL);
    }

    let uid = hdr.member_count;
    hdr.member_count += 1;
    hdr.save();

    let mut meta = [0u8; MAX_META_LEN];
    meta[..profile_meta.len()].copy_from_slice(profile_meta);
    let m = MemberRecord {
        identity: caller_identity,
        product_ledger: [0u8; 20],
        uid,
        trust_score: NEWCOMER_INITIAL_TRUST,
        sanctioned: 0,
        voucher_count: 0,
        vouchers: [0u8; 4],
        vouchers_slashed: 0,
        slash_count: 0,
        last_flag_reason: 0,
        x_m: x_m as u16,
        y_m: y_m as u16,
        last_heartbeat_block: blk,
        flagged_by_mask: 0,
        meta_len: profile_meta.len() as u8,
        meta,
    };
    m.save();
    storage::set_u64(key_uid(&caller_identity).as_slice(), (uid as u64) + 1);

    let mut ev = [0u8; 44];
    ev[0..20].copy_from_slice(&caller_identity);
    ev[20..28].copy_from_slice(&(uid as u64).to_be_bytes());
    ev[28..36].copy_from_slice(&x_m.to_be_bytes());
    ev[36..44].copy_from_slice(&y_m.to_be_bytes());
    events::emit(&[EV_MEMBER_REGISTERED], &ev);
    Ok(())
}

fn decode_abi_bytes_slice(raw: &[u8]) -> &[u8] {
    if raw.len() < 64 {
        return &[];
    }
    let len = u64::from_be_bytes([
        raw[56], raw[57], raw[58], raw[59], raw[60], raw[61], raw[62], raw[63],
    ]) as usize;
    let avail = raw.len() - 64;
    let take = len.min(avail);
    &raw[64..64 + take]
}

fn push_capped(dst: &mut [u8], pos: &mut usize, src: &[u8]) {
    let rem = dst.len().saturating_sub(*pos);
    let n = src.len().min(rem);
    if n > 0 {
        dst[*pos..*pos + n].copy_from_slice(&src[..n]);
        *pos += n;
    }
}

/// Permissionlessly onboard or refresh any verified `Identity` HFS (`IdentityRegistry.isValidIdentity`)
/// using its canonical on-chain `nickname()` and `handle()` so peers can initiate connection handshakes
/// even before that Captain opens the Comms sidebar!
fn handle_sync_verified_identity(args: &CalldataReader) -> Result<(), i32> {
    let mut hdr = CharterHeader::load()?;
    let target_identity = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if target_identity == [0u8; 20] {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    require_valid_identity(&hdr.identity_registry, &target_identity)?;
    let blk = context::block_number();

    if let Some(uid) = lookup_uid(&target_identity) {
        let mut m = MemberRecord::load(uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
        if m.sanctioned != 0 {
            return Err(ERR_SOCIAL_SANCTIONED);
        }
        if !is_active_now(&m, &hdr, blk) {
            if !inside_subnet(m.x_m as u64, m.y_m as u64, hdr.subnet_radius_m) {
                m.x_m = SUBNET_CENTER_X as u16;
                m.y_m = SUBNET_CENTER_Y as u16;
            }
            m.last_heartbeat_block = blk;
            m.save();
        }
        return Ok(());
    }

    if (hdr.member_count as usize) >= MAX_MEMBERS {
        return Err(ERR_SOCIAL_CAPACITY_FULL);
    }

    let nick_cd = CallEncoder::<16>::new(const { selector("nickname()") });
    let handle_cd = CallEncoder::<16>::new(const { selector("handle()") });

    let mut meta = [0u8; MAX_META_LEN];
    let mut pos = 0usize;

    if let Ok(n_raw) = call::call_raw(&target_identity, nick_cd.as_slice()) {
        let n_bytes = decode_abi_bytes_slice(n_raw);
        if !n_bytes.is_empty() {
            push_capped(&mut meta, &mut pos, n_bytes);
        }
    }
    if pos == 0 {
        push_capped(&mut meta, &mut pos, b"Captain");
    }
    push_capped(&mut meta, &mut pos, b"|@");
    let after_at = pos;
    if let Ok(h_raw) = call::call_raw(&target_identity, handle_cd.as_slice()) {
        let mut h_bytes = decode_abi_bytes_slice(h_raw);
        if !h_bytes.is_empty() && h_bytes[0] == b'@' {
            h_bytes = &h_bytes[1..];
        }
        if !h_bytes.is_empty() {
            push_capped(&mut meta, &mut pos, h_bytes);
        }
    }
    if pos == after_at {
        push_capped(&mut meta, &mut pos, b"captain");
    }
    push_capped(&mut meta, &mut pos, b"|Fleet Captain|Naval VHF");

    let uid = hdr.member_count;
    hdr.member_count += 1;
    hdr.save();

    let m = MemberRecord {
        identity: target_identity,
        product_ledger: [0u8; 20],
        uid,
        trust_score: NEWCOMER_INITIAL_TRUST,
        sanctioned: 0,
        voucher_count: 0,
        vouchers: [0u8; 4],
        vouchers_slashed: 0,
        slash_count: 0,
        last_flag_reason: 0,
        x_m: SUBNET_CENTER_X as u16,
        y_m: SUBNET_CENTER_Y as u16,
        last_heartbeat_block: blk,
        flagged_by_mask: 0,
        meta_len: pos as u8,
        meta,
    };
    m.save();
    storage::set_u64(key_uid(&target_identity).as_slice(), (uid as u64) + 1);

    let mut ev = [0u8; 44];
    ev[0..20].copy_from_slice(&target_identity);
    ev[20..28].copy_from_slice(&(uid as u64).to_be_bytes());
    ev[28..36].copy_from_slice(&(SUBNET_CENTER_X as u64).to_be_bytes());
    ev[36..44].copy_from_slice(&(SUBNET_CENTER_Y as u64).to_be_bytes());
    events::emit(&[EV_MEMBER_REGISTERED], &ev);
    Ok(())
}

/// Attach the calling `Identity` HFS's own `ProductLedger` storefront (`ProductLedger.ownerIdentity() == caller`).
fn handle_attach_product_ledger(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let product_ledger = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if product_ledger == [0u8; 20] {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller_identity = context::msg_sender();
    require_valid_identity(&hdr.identity_registry, &caller_identity)?;

    let uid = lookup_uid(&caller_identity).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let mut m = MemberRecord::load(uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    if !is_active_now(&m, &hdr, context::block_number()) {
        return Err(ERR_SOCIAL_DORMANT);
    }
    if m.trust_score < MIN_TRUST_TO_VOUCH {
        return Err(ERR_SOCIAL_INSUFFICIENT_TRUST);
    }

    // Verify `ProductLedger.ownerIdentity() == caller_identity` AND `associatedCharter() == self`!
    let owner_cd = CallEncoder::<16>::new(const { selector("ownerIdentity()") });
    let owner_raw = call::call_raw(&product_ledger, owner_cd.as_slice())?;
    if owner_raw.len() < 32 || owner_raw[12..32] != caller_identity {
        return Err(ERR_SOCIAL_UNAUTHORIZED_MODULE);
    }

    let chr_cd = CallEncoder::<16>::new(const { selector("associatedCharter()") });
    let chr_raw = call::call_raw(&product_ledger, chr_cd.as_slice())?;
    if chr_raw.len() < 32 || chr_raw[12..32] != context::self_address() {
        return Err(ERR_SOCIAL_UNAUTHORIZED_MODULE);
    }

    m.product_ledger = product_ledger;
    m.save();
    storage::set_u64(key_store_owner(&product_ledger).as_slice(), 1);

    let mut ev = [0u8; 40];
    ev[0..20].copy_from_slice(&caller_identity);
    ev[20..40].copy_from_slice(&product_ledger);
    events::emit(&[EV_STOREFRONT_ATTACHED], &ev);
    Ok(())
}

fn handle_product_ledger_of(args: &CalldataReader) -> Result<(), i32> {
    let _hdr = CharterHeader::load()?;
    let identity = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let pl = lookup_uid(&identity)
        .and_then(MemberRecord::load)
        .map(|m| m.product_ledger)
        .unwrap_or([0u8; 20]);
    ret::write_address(&pl);
    Ok(())
}

fn handle_ping_presence(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let x_m = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let y_m = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if x_m > MAX_COORD_M || y_m > MAX_COORD_M {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    require_valid_identity(&hdr.identity_registry, &caller)?;
    let uid = lookup_uid(&caller).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let mut m = MemberRecord::load(uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    if m.sanctioned != 0 {
        return Err(ERR_SOCIAL_SANCTIONED);
    }
    m.x_m = x_m as u16;
    m.y_m = y_m as u16;
    m.last_heartbeat_block = context::block_number();
    m.save();
    Ok(())
}

fn handle_vouch_neighbor(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let subj_addr = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();
    if caller == subj_addr {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    require_valid_identity(&hdr.identity_registry, &caller)?;

    let blk = context::block_number();
    let v_uid = lookup_uid(&caller).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let s_uid = lookup_uid(&subj_addr).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;

    let voucher = MemberRecord::load(v_uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let mut subject = MemberRecord::load(s_uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;

    if !is_active_now(&voucher, &hdr, blk) {
        return Err(ERR_SOCIAL_DORMANT);
    }
    if !is_active_now(&subject, &hdr, blk) {
        return Err(ERR_SOCIAL_PEER_DORMANT);
    }
    if voucher.trust_score < MIN_TRUST_TO_VOUCH {
        return Err(ERR_SOCIAL_INSUFFICIENT_TRUST);
    }

    let max_rf = hdr.rf_encounter_range_m as u64;
    if dist_sq(
        voucher.x_m as u64,
        voucher.y_m as u64,
        subject.x_m as u64,
        subject.y_m as u64,
    ) > max_rf * max_rf
    {
        return Err(ERR_SOCIAL_OUTSIDE_RF_RANGE);
    }

    let vc = subject.voucher_count as usize;
    if vc >= MAX_VOUCHERS {
        return Err(ERR_SOCIAL_CAPACITY_FULL);
    }
    let mut i = 0;
    while i < vc {
        if subject.vouchers[i] == v_uid {
            return Err(ERR_SOCIAL_DUPLICATE_ACTION);
        }
        i += 1;
    }

    let boost: u8 = if vc == 0 { 25 } else { 12 };
    subject.vouchers[vc] = v_uid;
    subject.voucher_count += 1;
    subject.trust_score = subject.trust_score.saturating_add(boost).min(100);
    subject.save();

    let mut ev = [0u8; 48];
    ev[0..20].copy_from_slice(&caller);
    ev[20..40].copy_from_slice(&subj_addr);
    ev[40..48].copy_from_slice(&(subject.trust_score as u64).to_be_bytes());
    events::emit(&[EV_NEIGHBOR_VOUCHED], &ev);
    Ok(())
}

fn handle_flag_accountability(args: &CalldataReader) -> Result<(), i32> {
    let mut hdr = CharterHeader::load()?;
    let offender_addr = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let reason = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();
    if caller == offender_addr {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    require_valid_identity(&hdr.identity_registry, &caller)?;

    let blk = context::block_number();
    let rep_uid = lookup_uid(&caller).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let off_uid = lookup_uid(&offender_addr).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;

    let reporter = MemberRecord::load(rep_uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let mut offender = MemberRecord::load(off_uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;

    if !is_active_now(&reporter, &hdr, blk) {
        return Err(ERR_SOCIAL_DORMANT);
    }
    if reporter.trust_score < MIN_TRUST_TO_FLAG {
        return Err(ERR_SOCIAL_INSUFFICIENT_TRUST);
    }
    if (offender.flagged_by_mask & (1u64 << rep_uid)) != 0 {
        return Err(ERR_SOCIAL_DUPLICATE_ACTION);
    }

    offender.flagged_by_mask |= 1u64 << rep_uid;
    offender.last_flag_reason = (reason & 0xFF) as u8;
    offender.trust_score = offender.trust_score.saturating_sub(15);

    if offender.vouchers_slashed == 0 && offender.flagged_by_mask.count_ones() >= 2 {
        offender.vouchers_slashed = 1;
        offender.trust_score = offender.trust_score.saturating_sub(25);

        let vc = (offender.voucher_count as usize).min(MAX_VOUCHERS);
        let mut i = 0;
        while i < vc {
            let v_uid = offender.vouchers[i];
            if let Some(mut vm) = MemberRecord::load(v_uid) {
                vm.trust_score = vm.trust_score.saturating_sub(18);
                vm.slash_count = vm.slash_count.saturating_add(1);
                if vm.trust_score < SANCTION_TRUST_FLOOR {
                    vm.sanctioned = 1;
                }
                vm.save();
                hdr.total_slashes = hdr.total_slashes.saturating_add(1);

                let mut sev = [0u8; 48];
                sev[0..20].copy_from_slice(&vm.identity);
                sev[20..40].copy_from_slice(&offender_addr);
                sev[40..48].copy_from_slice(&(vm.trust_score as u64).to_be_bytes());
                events::emit(&[EV_VOUCHER_SLASHED], &sev);
            }
            i += 1;
        }
        hdr.save();
    }

    if offender.trust_score < SANCTION_TRUST_FLOOR {
        offender.sanctioned = 1;
    }
    offender.save();

    let mut ev = [0u8; 56];
    ev[0..20].copy_from_slice(&caller);
    ev[20..40].copy_from_slice(&offender_addr);
    ev[40..48].copy_from_slice(&reason.to_be_bytes());
    ev[48..56].copy_from_slice(&(offender.trust_score as u64).to_be_bytes());
    events::emit(&[EV_ACCOUNTABILITY_FLAGGED], &ev);
    Ok(())
}

fn handle_adjust_standing(args: &CalldataReader) -> Result<(), i32> {
    let _hdr = CharterHeader::load()?;
    let caller = context::msg_sender();
    if !is_authorized_standing_adjuster(&caller)? {
        return Err(ERR_SOCIAL_UNAUTHORIZED_MODULE);
    }

    let user = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let amount = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?.min(25) as u8;
    let increase = args.bool(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;

    let uid = lookup_uid(&user).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    let mut m = MemberRecord::load(uid).ok_or(ERR_SOCIAL_NOT_REGISTERED)?;
    if increase {
        if m.sanctioned == 0 {
            m.trust_score = m.trust_score.saturating_add(amount).min(100);
        }
    } else {
        m.trust_score = m.trust_score.saturating_sub(amount);
        if m.trust_score < SANCTION_TRUST_FLOOR {
            m.sanctioned = 1;
        }
    }
    m.save();
    Ok(())
}

fn handle_member_standing(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let user = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let blk = context::block_number();

    let Some(uid) = lookup_uid(&user) else {
        ret::write_u64_word(0);
        return Ok(());
    };
    let Some(m) = MemberRecord::load(uid) else {
        ret::write_u64_word(0);
        return Ok(());
    };

    let st = MemberStanding {
        registered: true,
        is_active: is_active_now(&m, &hdr, blk),
        sanctioned: m.sanctioned != 0,
        trust_score: m.trust_score,
        uid: m.uid,
    };
    ret::write_u64_word(st.pack());
    Ok(())
}

fn handle_check_mutual_rf(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let a = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let b = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let blk = context::block_number();

    let (Some(ua), Some(ub)) = (lookup_uid(&a), lookup_uid(&b)) else {
        ret::write_bool(false);
        return Ok(());
    };
    let (Some(ma), Some(mb)) = (MemberRecord::load(ua), MemberRecord::load(ub)) else {
        ret::write_bool(false);
        return Ok(());
    };
    if !is_active_now(&ma, &hdr, blk) || !is_active_now(&mb, &hdr, blk) {
        ret::write_bool(false);
        return Ok(());
    }
    let r = hdr.rf_encounter_range_m as u64;
    let ok = dist_sq(ma.x_m as u64, ma.y_m as u64, mb.x_m as u64, mb.y_m as u64) <= r * r;
    ret::write_bool(ok);
    Ok(())
}

fn handle_check_venue_rf(args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    let user = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let vx = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let vy = args.u64(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let blk = context::block_number();

    let Some(uid) = lookup_uid(&user) else {
        ret::write_bool(false);
        return Ok(());
    };
    let Some(m) = MemberRecord::load(uid) else {
        ret::write_bool(false);
        return Ok(());
    };
    if !is_active_now(&m, &hdr, blk) {
        ret::write_bool(false);
        return Ok(());
    }
    let r = hdr.rf_encounter_range_m as u64;
    let ok = dist_sq(m.x_m as u64, m.y_m as u64, vx, vy) <= r * r;
    ret::write_bool(ok);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    ret::write_address(&hdr.identity_registry);
    Ok(())
}

fn handle_messaging_hps(_args: &CalldataReader) -> Result<(), i32> {
    let hdr = CharterHeader::load()?;
    ret::write_address(&hdr.messaging_hps);
    Ok(())
}

fn handle_get_snapshot(_args: &CalldataReader) -> Result<i32, i32> {
    let Ok(hdr) = CharterHeader::load() else {
        ret::write(&[]);
        return Ok(0);
    };
    let blk = context::block_number();
    let slots = load_mod_slots();

    unsafe {
        // Header (136 bytes):
        // [0]=1, [1]=member_count, [4..8]=radius, [8..12]=rf_range, [12..16]=lease,
        // [16..20]=center_x, [20..24]=center_y, [24..32]=current_block, [32..36]=total_slashes,
        // [36..56]=identity_registry, [56..76]=messaging_hps, [76..96]=relationships_hps,
        // [96..116]=feed_hps, [116..136]=events_hps
        let out = &mut *core::ptr::addr_of_mut!(SNAP_OUT);
        out[0..136].fill(0);
        out[0] = 1;
        out[1] = hdr.member_count;
        out[4..8].copy_from_slice(&hdr.subnet_radius_m.to_le_bytes());
        out[8..12].copy_from_slice(&hdr.rf_encounter_range_m.to_le_bytes());
        out[12..16].copy_from_slice(&hdr.heartbeat_lease_blocks.to_le_bytes());
        out[16..20].copy_from_slice(&SUBNET_CENTER_X.to_le_bytes());
        out[20..24].copy_from_slice(&SUBNET_CENTER_Y.to_le_bytes());
        out[24..32].copy_from_slice(&blk.to_le_bytes());
        out[32..36].copy_from_slice(&hdr.total_slashes.to_le_bytes());
        out[36..56].copy_from_slice(&hdr.identity_registry);
        out[56..76].copy_from_slice(&hdr.messaging_hps);
        out[76..96].copy_from_slice(&slots[0]);
        out[96..116].copy_from_slice(&slots[1]);
        out[116..136].copy_from_slice(&slots[2]);

        let mut pos: usize = 136;
        let mut uid: u8 = 0;
        while uid < hdr.member_count {
            if let Some(m) = MemberRecord::load(uid) {
                let mlen = m.meta_len as usize;
                if pos + 72 + mlen > out.len() {
                    break;
                }
                // Member entry (72 B prefix + meta):
                // [0..20]=identity_hps, [20..40]=product_ledger_hps,
                // [40]=uid, [41]=trust, [42]=sanctioned, [43]=is_active,
                // [44..46]=x_m, [46..48]=y_m, [48..56]=last_hb_blk, [56..64]=flagged_by_mask,
                // [64]=voucher_count, [65..69]=vouchers, [69]=vouchers_slashed, [70]=slash_count, [71]=meta_len
                out[pos..pos + 20].copy_from_slice(&m.identity);
                out[pos + 20..pos + 40].copy_from_slice(&m.product_ledger);
                out[pos + 40] = m.uid;
                out[pos + 41] = m.trust_score;
                out[pos + 42] = m.sanctioned;
                out[pos + 43] = u8::from(is_active_now(&m, &hdr, blk));
                out[pos + 44..pos + 46].copy_from_slice(&m.x_m.to_le_bytes());
                out[pos + 46..pos + 48].copy_from_slice(&m.y_m.to_le_bytes());
                out[pos + 48..pos + 56].copy_from_slice(&m.last_heartbeat_block.to_le_bytes());
                out[pos + 56..pos + 64].copy_from_slice(&m.flagged_by_mask.to_le_bytes());
                out[pos + 64] = m.voucher_count;
                out[pos + 65..pos + 69].copy_from_slice(&m.vouchers);
                out[pos + 69] = m.vouchers_slashed;
                out[pos + 70] = m.slash_count;
                out[pos + 71] = m.meta_len;
                pos += 72;
                out[pos..pos + mlen].copy_from_slice(&m.meta[..mlen]);
                pos += mlen;
            }
            uid += 1;
        }

        ret::write(&out[..pos]);
        Ok(pos as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::ERR_INVALID_IDENTITY;
    use hps_sdk::mock;

    #[test]
    fn charter_requires_verified_identity_hps_attaches_product_ledger_and_slashes_vouchers() {
        mock::reset();
        const CHARTER: [u8; 20] = [0xC1; 20];
        const ALICE_ID: [u8; 20] = [0xA1; 20];
        const UNVERIFIED_EOA: [u8; 20] = [0xEE; 20];

        let id_reg = [0x11; 20];
        let charter = CHARTER;
        let msg_hps = [0x10; 20];
        let rel_mod = [0x21; 20];
        let alice_store = [0x51; 20];
        let approved_hash = [0x77; 32];

        let alice_id = ALICE_ID;
        let bob_id = [0xA2; 20];
        let carol_id = [0xA3; 20];
        let sock_id = [0xA9; 20];
        let unverified_eoa = UNVERIFIED_EOA;

        mock::register_hps(id_reg, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                let who = args.address(0).unwrap();
                ret::write_bool(who != UNVERIFIED_EOA);
                0
            } else {
                -2
            }
        });

        mock::register_hps(alice_store, |raw| {
            let Some((sel, _)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("ownerIdentity()") } {
                ret::write_address(&ALICE_ID);
                0
            } else if sel == const { selector("associatedCharter()") } {
                ret::write_address(&CHARTER);
                0
            } else {
                -1
            }
        });

        mock::register_hps(charter, dispatch_calldata);
        mock::set_code_hash(rel_mod, approved_hash);
        mock::set_block_number(100);

        mock::transact_as(
            alice_id,
            charter,
            CallEncoder::<512>::new(const {
                selector("initialize(address,address,uint64,uint64,uint64,bytes)")
            })
            .push_address(&id_reg)
            .push_address(&msg_hps)
            .push_u64(1200)
            .push_u64(150)
            .push_u64(12)
            .push_u64(0xC0)
            .push_dynamic_bytes_tail(b"Alice|@alextan|Slate")
            .as_slice(),
        )
        .unwrap();

        // Raw EOA (not registered in IdentityRegistry) is rejected even inside subnet!
        assert_eq!(
            mock::transact_as(
                unverified_eoa,
                charter,
                CallEncoder::<256>::new(const {
                    selector("registerProfile(uint64,uint64,bytes)")
                })
                .push_u64(1510)
                .push_u64(1510)
                .push_u64(0x60)
                .push_dynamic_bytes_tail(b"RawEoa|Fake|Web")
                .as_slice(),
            ),
            Err(ERR_INVALID_IDENTITY)
        );

        // Alice attaches her Identity-owned ProductLedger storefront!
        mock::transact_as(
            alice_id,
            charter,
            CallEncoder::<96>::new(const { selector("attachProductLedger(address)") })
                .push_address(&alice_store)
                .as_slice(),
        )
        .unwrap();

        for who in [bob_id, carol_id, sock_id] {
            mock::transact_as(
                who,
                charter,
                CallEncoder::<256>::new(const {
                    selector("registerProfile(uint64,uint64,bytes)")
                })
                .push_u64(1540)
                .push_u64(1520)
                .push_u64(0x60)
                .push_dynamic_bytes_tail(b"Neighbor|@handle|Watch")
                .as_slice(),
            )
            .unwrap();
        }

        for target in [bob_id, carol_id] {
            mock::transact_as(
                alice_id,
                charter,
                CallEncoder::<96>::new(const { selector("vouchNeighbor(address)") })
                    .push_address(&target)
                    .as_slice(),
            )
            .unwrap();
        }

        mock::transact_as(
            bob_id,
            charter,
            CallEncoder::<96>::new(const { selector("vouchNeighbor(address)") })
                .push_address(&sock_id)
                .as_slice(),
        )
        .unwrap();

        for rep in [alice_id, carol_id] {
            mock::transact_as(
                rep,
                charter,
                CallEncoder::<96>::new(const { selector("flagAccountability(address,uint64)") })
                    .push_address(&sock_id)
                    .push_u64(1)
                    .as_slice(),
            )
            .unwrap();
        }

        let snap = mock::transact_as(
            alice_id,
            charter,
            CallEncoder::<64>::new(const { selector("getCharterSnapshot()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u32::from_le_bytes([snap[32], snap[33], snap[34], snap[35]]), 1);
        assert_eq!(&snap[136 + 20..136 + 40], &alice_store);
    }
}
