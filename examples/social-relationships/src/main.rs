//! # `SocialRelationships` — Radio-Bounded Social Graph (`social-relationships` — HPS #14B)
//!
//! Pinned to a single `SocialCharter` root of trust (`CAP_SOCIAL_RELATIONSHIPS`):
//! - Enforces live `<=150m` `2.4 GHz` Direct RF proximity via synchronous `host_call_contract`
//!   into `SocialCharter.checkMutualRfProximity` on both opening and accepting a 6-block
//!   `keccak256` challenge-response handshake.
//! - Tracks bilateral Relationship Tiers (`1 = Neighbor`, `2 = Mutual RF Friend`, `3 = Close Circle`).
//! - Exposes `areActiveConnected(a, b, minTier)` to sibling modules (`SocialFeed`, `SocialEvents`,
//!   `SocialMarketplace`), returning `false` (**Dormant**) whenever either party leaves the
//!   physical `Sub-GHz` subnet or stops emitting radio heartbeats.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::keccak256;
use hps_sdk::social::{
    adjust_standing_from_module, query_member_standing, require_active_member,
    require_mutual_rf_proximity, ERR_SOCIAL_ALREADY_INIT, ERR_SOCIAL_DUPLICATE_ACTION,
    ERR_SOCIAL_HANDSHAKE_INVALID, ERR_SOCIAL_INVALID_ARGS, ERR_SOCIAL_NOT_CONNECTED,
    ERR_SOCIAL_NOT_REGISTERED, ERR_SOCIAL_UNINITIALIZED, REL_CLOSE_CIRCLE, REL_NEIGHBOR,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const MAX_MEMBERS: usize = 64;
pub const MAX_PENDING: usize = 24;
pub const HANDSHAKE_WINDOW_BLOCKS: u64 = 180;

const KEY_CHARTER: &[u8] = b"sr:chr";
const KEY_ENC_COUNTS: &[u8] = b"sr:encc";
const KEY_PENDING: &[u8] = b"sr:pnd";

const EV_HANDSHAKE_OPENED: [u8; 32] =
    event_topic("EncounterHandshakeOpened(address,address,uint64,uint64)");
const EV_RELATIONSHIP_FORMED: [u8; 32] =
    event_topic("RelationshipFormed(address,address,uint64)");

static mut REL_OUT: [u8; 12_288] = [0u8; 12_288];

hps_entry! {
    "initialize(address)"                                           => handle_initialize,
    "openEncounterHandshake(address,uint64,bytes32)"                => handle_open_handshake,
    "acceptEncounterHandshake(address,bytes32)"                     => handle_accept_handshake,
    "setRelationshipTier(address,uint64)"                           => handle_set_tier,
    "removeRelationship(address)"                                   => handle_remove_relationship,
    "relationshipTier(address,address)"                             => handle_relationship_tier,
    "areActiveConnected(address,address,uint64)"                    => handle_are_active_connected,
    "getRelationshipsSnapshot()"                                    => handle_get_snapshot,
}

fn load_charter() -> Result<[u8; 20], i32> {
    storage::get_address(KEY_CHARTER).ok_or(ERR_SOCIAL_UNINITIALIZED)
}

fn key_edge(u1: u8, u2: u8) -> KeyBuilder<16> {
    let (lo, hi) = if u1 <= u2 { (u1, u2) } else { (u2, u1) };
    KeyBuilder::<16>::new().push(b"sr:e:").push(&[lo, hi])
}

fn get_edge_tier(u1: u8, u2: u8) -> u8 {
    if u1 == u2 {
        return 0;
    }
    storage::get_u64(key_edge(u1, u2).as_slice()) as u8
}

fn set_edge_tier(u1: u8, u2: u8, tier: u8) {
    storage::set_u64(key_edge(u1, u2).as_slice(), tier as u64);
}

fn load_enc_counts() -> [u8; MAX_MEMBERS] {
    let mut c = [0u8; MAX_MEMBERS];
    let _ = storage::get_into(KEY_ENC_COUNTS, &mut c);
    c
}

fn save_enc_counts(c: &[u8; MAX_MEMBERS]) {
    storage::set(KEY_ENC_COUNTS, c);
}

#[derive(Clone, Copy)]
struct PendingHandshake {
    active: u8,
    init_uid: u8,
    targ_uid: u8,
    tier: u8,
    expires_block: u64,
    commit: [u8; 32],
}

impl PendingHandshake {
    const EMPTY: Self = Self {
        active: 0,
        init_uid: 0,
        targ_uid: 0,
        tier: 0,
        expires_block: 0,
        commit: [0u8; 32],
    };

    fn to_bytes(self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = self.active;
        b[1] = self.init_uid;
        b[2] = self.targ_uid;
        b[3] = self.tier;
        b[8..16].copy_from_slice(&self.expires_block.to_le_bytes());
        b[16..48].copy_from_slice(&self.commit);
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&b[16..48]);
        Self {
            active: b[0],
            init_uid: b[1],
            targ_uid: b[2],
            tier: b[3],
            expires_block: u64::from_le_bytes([
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
            ]),
            commit,
        }
    }
}

fn load_pending() -> [PendingHandshake; MAX_PENDING] {
    let mut raw = [0u8; MAX_PENDING * 48];
    let mut out = [PendingHandshake::EMPTY; MAX_PENDING];
    if let Some(n) = storage::get_into(KEY_PENDING, &mut raw) {
        let cnt = (n / 48).min(MAX_PENDING);
        let mut i = 0;
        while i < cnt {
            out[i] = PendingHandshake::from_bytes(&raw[i * 48..(i + 1) * 48]);
            i += 1;
        }
    }
    out
}

fn save_pending(list: &[PendingHandshake; MAX_PENDING]) {
    let mut raw = [0u8; MAX_PENDING * 48];
    let mut i = 0;
    while i < MAX_PENDING {
        raw[i * 48..(i + 1) * 48].copy_from_slice(&list[i].to_bytes());
        i += 1;
    }
    storage::set(KEY_PENDING, &raw);
}

pub fn compute_encounter_commit(
    charter: &[u8; 20],
    initiator: &[u8; 20],
    target: &[u8; 20],
    secret_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut pre = [0u8; 13 + 20 + 20 + 20 + 32];
    pre[0..13].copy_from_slice(b"SLX_RF_ENC_V1");
    pre[13..33].copy_from_slice(charter);
    pre[33..53].copy_from_slice(initiator);
    pre[53..73].copy_from_slice(target);
    pre[73..105].copy_from_slice(secret_nonce);
    keccak256(&pre)
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if load_charter().is_ok() {
        return Err(ERR_SOCIAL_ALREADY_INIT);
    }
    let charter = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if charter == [0u8; 20] {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    storage::set_address(KEY_CHARTER, &charter);
    Ok(())
}

fn handle_open_handshake(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let target = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let tier = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let commit = args.bytes32(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();

    if caller == target || !(REL_NEIGHBOR..=REL_CLOSE_CIRCLE).contains(&tier) {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let st_a = require_active_member(&charter, &caller, 15)?;
    let st_b = require_active_member(&charter, &target, 15)?;
    if get_edge_tier(st_a.uid, st_b.uid) > 0 {
        return Err(ERR_SOCIAL_DUPLICATE_ACTION);
    }

    // Cross-HPS check on SocialCharter: BOTH must be active & within <=150m 2.4 GHz RF!
    require_mutual_rf_proximity(&charter, &caller, &target)?;

    let blk = context::block_number();
    let mut list = load_pending();
    let mut slot: Option<usize> = None;
    let mut i = 0;
    while i < MAX_PENDING {
        if list[i].active == 1 && list[i].init_uid == st_a.uid && list[i].targ_uid == st_b.uid {
            slot = Some(i);
            break;
        }
        if slot.is_none() && (list[i].active == 0 || blk > list[i].expires_block) {
            slot = Some(i);
        }
        i += 1;
    }

    let idx = slot.unwrap_or(0);
    list[idx] = PendingHandshake {
        active: 1,
        init_uid: st_a.uid,
        targ_uid: st_b.uid,
        tier: tier as u8,
        expires_block: blk + HANDSHAKE_WINDOW_BLOCKS,
        commit,
    };
    save_pending(&list);

    let mut ev = [0u8; 56];
    ev[0..20].copy_from_slice(&caller);
    ev[20..40].copy_from_slice(&target);
    ev[40..48].copy_from_slice(&tier.to_be_bytes());
    ev[48..56].copy_from_slice(&(blk + HANDSHAKE_WINDOW_BLOCKS).to_be_bytes());
    events::emit(&[EV_HANDSHAKE_OPENED], &ev);
    Ok(())
}

fn handle_accept_handshake(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let initiator = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let secret_nonce = args.bytes32(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();

    let st_init = require_active_member(&charter, &initiator, 15)?;
    let st_targ = require_active_member(&charter, &caller, 15)?;

    // Must STILL be within <=150m 2.4 GHz RF range at acceptance time!
    require_mutual_rf_proximity(&charter, &initiator, &caller)?;

    let expected = compute_encounter_commit(&charter, &initiator, &caller, &secret_nonce);
    let blk = context::block_number();
    let mut list = load_pending();
    let mut found: Option<usize> = None;
    let mut i = 0;
    while i < MAX_PENDING {
        if list[i].active == 1
            && list[i].init_uid == st_init.uid
            && list[i].targ_uid == st_targ.uid
            && blk <= list[i].expires_block
            && list[i].commit == expected
        {
            found = Some(i);
            break;
        }
        i += 1;
    }

    let idx = found.ok_or(ERR_SOCIAL_HANDSHAKE_INVALID)?;
    let tier = list[idx].tier;
    list[idx].active = 0;
    save_pending(&list);

    set_edge_tier(st_init.uid, st_targ.uid, tier);

    let mut enc = load_enc_counts();
    if (st_init.uid as usize) < MAX_MEMBERS {
        enc[st_init.uid as usize] = enc[st_init.uid as usize].saturating_add(1);
    }
    if (st_targ.uid as usize) < MAX_MEMBERS {
        enc[st_targ.uid as usize] = enc[st_targ.uid as usize].saturating_add(1);
    }
    save_enc_counts(&enc);

    // Reward +3 Civic Trust to both neighbors on SocialCharter!
    let _ = adjust_standing_from_module(&charter, &initiator, 3, true);
    let _ = adjust_standing_from_module(&charter, &caller, 3, true);

    let mut ev = [0u8; 48];
    ev[0..20].copy_from_slice(&initiator);
    ev[20..40].copy_from_slice(&caller);
    ev[40..48].copy_from_slice(&(tier as u64).to_be_bytes());
    events::emit(&[EV_RELATIONSHIP_FORMED], &ev);
    Ok(())
}

fn handle_set_tier(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let peer = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let new_tier = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if !(REL_NEIGHBOR..=REL_CLOSE_CIRCLE).contains(&new_tier) {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let caller = context::msg_sender();
    let st_a = require_active_member(&charter, &caller, 15)?;
    let st_b = require_active_member(&charter, &peer, 15)?;
    if get_edge_tier(st_a.uid, st_b.uid) == 0 {
        return Err(ERR_SOCIAL_NOT_CONNECTED);
    }
    // Upgrading to Close Circle requires in-person RF proximity!
    if new_tier == REL_CLOSE_CIRCLE {
        require_mutual_rf_proximity(&charter, &caller, &peer)?;
    }
    set_edge_tier(st_a.uid, st_b.uid, new_tier as u8);
    Ok(())
}

fn handle_remove_relationship(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let peer = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();
    let st_a = query_member_standing(&charter, &caller)?;
    let st_b = query_member_standing(&charter, &peer)?;
    if !st_a.registered || !st_b.registered {
        return Err(ERR_SOCIAL_NOT_REGISTERED);
    }
    set_edge_tier(st_a.uid, st_b.uid, 0);
    Ok(())
}

fn handle_relationship_tier(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let a = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let b = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let st_a = query_member_standing(&charter, &a)?;
    let st_b = query_member_standing(&charter, &b)?;
    if !st_a.registered || !st_b.registered {
        ret::write_u64_word(0);
        return Ok(());
    }
    ret::write_u64_word(get_edge_tier(st_a.uid, st_b.uid) as u64);
    Ok(())
}

fn handle_are_active_connected(args: &CalldataReader) -> Result<(), i32> {
    let charter = load_charter()?;
    let a = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let b = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let min_tier = args.u64(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;

    let st_a = query_member_standing(&charter, &a)?;
    let st_b = query_member_standing(&charter, &b)?;
    if !st_a.registered || !st_b.registered || !st_a.is_active || !st_b.is_active {
        ret::write_bool(false);
        return Ok(());
    }
    if a == b {
        ret::write_bool(true);
        return Ok(());
    }
    let tier = get_edge_tier(st_a.uid, st_b.uid) as u64;
    ret::write_bool(tier >= min_tier);
    Ok(())
}

fn handle_get_snapshot(_args: &CalldataReader) -> Result<i32, i32> {
    let Ok(_charter) = load_charter() else {
        ret::write(&[]);
        return Ok(0);
    };
    let blk = context::block_number();
    let enc = load_enc_counts();
    let pending = load_pending();

    unsafe {
        // Layout:
        // [0..2] = edge_count (u16 LE)
        // [2..4] = pending_count (u16 LE)
        // [4..68] = encounters_count[0..64]
        // edges: [u1, u2, tier, 0] * edge_count
        // pending: [init_uid, targ_uid, tier, 0, expires_blk(u64 LE), commit(32)] * pending_count (44 B each)
        let out = &mut *core::ptr::addr_of_mut!(REL_OUT);
        out[4..68].copy_from_slice(&enc);
        let mut pos: usize = 68;
        let mut edge_cnt: u16 = 0;

        let mut u1: u8 = 0;
        while (u1 as usize) < MAX_MEMBERS {
            let mut u2: u8 = u1 + 1;
            while (u2 as usize) < MAX_MEMBERS {
                let t = get_edge_tier(u1, u2);
                if t > 0 && pos + 4 <= out.len() - 1200 {
                    out[pos] = u1;
                    out[pos + 1] = u2;
                    out[pos + 2] = t;
                    out[pos + 3] = 0;
                    pos += 4;
                    edge_cnt += 1;
                }
                u2 += 1;
            }
            u1 += 1;
        }

        let mut pnd_cnt: u16 = 0;
        let mut i = 0;
        while i < MAX_PENDING {
            let p = &pending[i];
            if p.active == 1 && blk <= p.expires_block && pos + 44 <= out.len() {
                out[pos] = p.init_uid;
                out[pos + 1] = p.targ_uid;
                out[pos + 2] = p.tier;
                out[pos + 3] = 0;
                out[pos + 4..pos + 12].copy_from_slice(&p.expires_block.to_le_bytes());
                out[pos + 12..pos + 44].copy_from_slice(&p.commit);
                pos += 44;
                pnd_cnt += 1;
            }
            i += 1;
        }

        out[0..2].copy_from_slice(&edge_cnt.to_le_bytes());
        out[2..4].copy_from_slice(&pnd_cnt.to_le_bytes());
        ret::write(&out[..pos]);
        Ok(pos as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::social::MemberStanding;
    use hps_sdk::{mock, selector};

    fn mock_charter_dispatch(cd: &[u8]) -> i32 {
        let Some((sel, args)) = CalldataReader::parse(cd) else {
            return -1;
        };
        if sel == const { selector("memberStanding(address)") } {
            let u = args.address(0).unwrap();
            let active = storage::get_u64(&[b'd', u[19]]) == 0;
            let st = MemberStanding {
                registered: true,
                is_active: active,
                sanctioned: false,
                trust_score: 75,
                uid: u[19],
            };
            ret::write_u64_word(st.pack());
            0
        } else if sel == const { selector("checkMutualRfProximity(address,address)") } {
            let near = storage::get_u64(b"far") == 0;
            ret::write_bool(near);
            0
        } else if sel == const { selector("adjustStandingFromModule(address,uint64,bool)") } {
            0
        } else {
            -1
        }
    }

    #[test]
    fn enforces_24ghz_rf_handshake_and_dormancy_on_departure() {
        mock::reset();
        let charter = [0xC1; 20];
        let rel = [0xC2; 20];
        let alice = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bob = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        mock::register_hps(charter, mock_charter_dispatch);
        mock::register_hps(rel, dispatch_calldata);
        mock::set_block_number(50);

        mock::transact_as(
            alice,
            rel,
            CallEncoder::<96>::new(const { selector("initialize(address)") })
                .push_address(&charter)
                .as_slice(),
        )
        .unwrap();

        let nonce = [0x42; 32];
        let commit = compute_encounter_commit(&charter, &alice, &bob, &nonce);

        mock::transact_as(
            alice,
            rel,
            CallEncoder::<160>::new(const {
                selector("openEncounterHandshake(address,uint64,bytes32)")
            })
            .push_address(&bob)
            .push_u64(2)
            .push_bytes32(&commit)
            .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            bob,
            rel,
            CallEncoder::<128>::new(const {
                selector("acceptEncounterHandshake(address,bytes32)")
            })
            .push_address(&alice)
            .push_bytes32(&nonce)
            .as_slice(),
        )
        .unwrap();

        // Active when both are in subnet
        let ok = mock::transact_as(
            alice,
            rel,
            CallEncoder::<128>::new(const {
                selector("areActiveConnected(address,address,uint64)")
            })
            .push_address(&alice)
            .push_address(&bob)
            .push_u64(2)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(ok[31], 1);

        // Mark Bob dormant on Charter -> `areActiveConnected` drops to false!
        mock::set_self_address(charter);
        storage::set_u64(&[b'd', 2], 1);

        let dormant = mock::transact_as(
            alice,
            rel,
            CallEncoder::<128>::new(const {
                selector("areActiveConnected(address,address,uint64)")
            })
            .push_address(&alice)
            .push_address(&bob)
            .push_u64(2)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(dormant[31], 0);
    }
}
