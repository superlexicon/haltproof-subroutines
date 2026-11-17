//! # Dead Drop: Leak Hunt (`dead-drop`) — Haltproof Subroutine (HPS #12)
//!
//! RF-proximity spy vs. counter-intelligence smuggling multiplayer game designed
//! for SuperLexicon's `1-Node-1-Vote`, `$0`-gas radio mesh (`~4.3s` blocks).
//!
//! ## Core Cryptographic & Spatial Mechanics (Pure `#![no_std]` `keccak256`)
//! 1. **True Hidden Spy Selection via `$0`-Gas Anonymous Slots**:
//!    - Step 1 (`joinMatch`): All `N` players lock `identityCommit` and `seedCommit`
//!      from their public `agent` addresses before any ephemeral Spy key touches the chain.
//!      - `ticket_hash = keccak256("DD_TICKET_V1" || matchId || spy_eoa)`
//!      - `identityCommit = keccak256("DD_ID_V1" || matchId || agent || ticket_hash || idSalt)`
//!      - `seedCommit = keccak256("DD_SEED_V1" || matchId || seed)`
//!    - Step 2 (`registerAnonymousSlot`): Once `N` players have joined, each player submits
//!      a zero-balance (`$0` gas) transaction from their ephemeral `spy_eoa` into `anon_slots[0..N-1]`.
//!    - Step 3 (`revealSeed`): After verifying their `spy_eoa` is in `anon_slots`, all `N` players
//!      reveal `seed`. On the `N`-th reveal, `match_rand = keccak256(entropy || block_number)`
//!      selects `authorized_spy_eoa = anon_slots[u64(match_rand[0..8]) % N]`.
//! 2. **Hypergeometric On-Crack Vault Sampling (Zero Pre-Crack Node Leakage)**:
//!    - Out of `6` Marine Crescent RF Vault Beacons, `2` yield **Real Intel** and `4` are **Decoys**,
//!      sampled hypergeometrically at crack-time using `block_number` so even local node operators
//!      cannot pre-compute which vaults hold Real Intel before the Spy physically cracks them.
//! 3. **Mandatory Location-Pinging Stolen Intel (Dead-Man's Heartbeat Lease)**:
//!    - Once stolen, Intel enters `INTEL_CARRIED` and MUST emit a `25m`-sector radar ping every
//!      `<= leaseBlocks` (`pingIntelHeartbeat`, speed-clamped to `<= 2` sectors/block).
//!    - Muting the radio / Faraday-bagging past `leaseBlocks` lets any Detective call
//!      `claimLeaseExpired` to self-destruct the stolen Intel (`2` burned Intels = Detective win).
//!    - Spy has a `1x` `triggerDecoyJammer` gadget that pins public radar to a decoy sector for 4 blocks.
//! 4. **Coastal Pier Exfiltration Uplink vs. `<= 12m` Unfudgeable Frisk & Emergency Tribunal**:
//!    - Spy reaches Coastal Exfil Pier (`sector (22, 7)`), calls `startExfilUpload`, survives
//!      `uplinkBlocks` while broadcasting a pier alarm, and calls `completeExfilLeak` to win.
//!    - Detectives close within `<= 12m` (`friskSuspect`, 2 charges each) or convict via
//!      `callEmergencyMeeting` + `castTrialVote` + `tallyTrialVotes`, forcing an unfudgeable
//!      4-block `respondFrisk(matchId, mySpyEoa, idSalt)` verified against `identityCommit`
//!      AND `anon_slots[0..N-1]`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Bounded Halt-Free Constants
// ---------------------------------------------------------------------------

pub const MIN_PLAYERS: u64 = 3;
pub const MAX_PLAYERS: u64 = 16;
pub const VAULT_COUNT: u64 = 6;
pub const REAL_INTEL_TOTAL: u64 = 2;

pub const ARENA_MAX_X: u64 = 600;
pub const ARENA_MAX_Y: u64 = 400;
pub const SECTOR_SIZE: u64 = 25;
pub const MAX_SECTOR_X: u64 = 23; // 600 / 25 - 1
pub const MAX_SECTOR_Y: u64 = 15; // 400 / 25 - 1

/// Coastal Exfil Pier (`x = 555, y = 195` -> sector `(22, 7)`).
pub const EXFIL_X: u64 = 555;
pub const EXFIL_Y: u64 = 195;
pub const EXFIL_SECTOR_X: u64 = 22;
pub const EXFIL_SECTOR_Y: u64 = 7;

/// Central HQ Courtyard spawn (`x = 295, y = 195`).
pub const SPAWN_X: u64 = 295;
pub const SPAWN_Y: u64 = 195;

/// Max public movement speed per block (`45m` per block) and Frisk range (`12m`).
pub const MAX_STEP_METERS_PER_BLOCK: u64 = 45;
pub const FRISK_MAX_DIST_SQ: u64 = 144; // 12m * 12m
pub const FRISK_DEADLINE_BLOCKS: u64 = 4;
pub const MEETING_BLOCKS: u64 = 6;
pub const JAMMER_BLOCKS: u64 = 4;

/// Comms ring-buffer bounds.
pub const MAX_COMMS_SLOTS: u64 = 16;
pub const MAX_COMMS_MSG_LEN: usize = 160;

/// Match phases.
pub const PHASE_NONE: u64 = 0;
pub const PHASE_LOBBY: u64 = 1;
pub const PHASE_ACTIVE: u64 = 2;
pub const PHASE_ENDED: u64 = 3;

/// Match winners & win reasons.
pub const WINNER_NONE: u64 = 0;
pub const WINNER_DETECTIVES: u64 = 1;
pub const WINNER_SPY: u64 = 2;

pub const REASON_NONE: u64 = 0;
pub const REASON_FRISK_CAUGHT: u64 = 1;
pub const REASON_FRISK_TIMEOUT: u64 = 2;
pub const REASON_TRIBUNAL_CAUGHT: u64 = 3;
pub const REASON_ALL_INTEL_BURNED: u64 = 4;
pub const REASON_EXFIL_COMPLETE: u64 = 5;
pub const REASON_DETECTIVES_DEPLETED: u64 = 6;
pub const REASON_LOBBY_ABORTED: u64 = 7;

/// Stolen Intel states.
pub const INTEL_NONE: u64 = 0;
pub const INTEL_CARRIED: u64 = 1;
pub const INTEL_UPLOADING: u64 = 2;

/// Player statuses.
pub const PLAYER_ACTIVE: u8 = 1;
pub const PLAYER_CLEARED: u8 = 2;
pub const PLAYER_EJECTED: u8 = 3;
pub const PLAYER_CAUGHT_SPY: u8 = 4;

/// Vault states.
pub const VAULT_UNTOUCHED: u8 = 0;
pub const VAULT_CRACKED_DECOY: u8 = 1;
pub const VAULT_CRACKED_INTEL: u8 = 2;

/// Fixed Marine Crescent RF Vault Beacon coordinates `(x_meters, y_meters)`.
pub const VAULT_COORDS: [(u64, u64); 6] = [
    (95, 80),   // Vault 0: Blk 28 Rooftop Relay Locker -> sector (3, 3)
    (95, 305),  // Vault 1: Blk 29 Void-Deck Comms Box  -> sector (3, 12)
    (250, 85),  // Vault 2: North Footbridge Junction   -> sector (10, 3)
    (295, 315), // Vault 3: South Park Substation       -> sector (11, 12)
    (445, 80),  // Vault 4: Blk 33 Lift-Shaft Terminal  -> sector (17, 3)
    (445, 305), // Vault 5: Blk 35 Service Trench       -> sector (17, 12)
];

// ---------------------------------------------------------------------------
// Indexed Events
// ---------------------------------------------------------------------------

const EV_MATCH_CREATED: [u8; 32] = event_topic("MatchCreated(bytes32,uint64,uint64,uint64)");
const EV_MATCH_STARTED: [u8; 32] = event_topic("MatchStarted(bytes32,address,uint64)");
const EV_VAULT_CRACKED: [u8; 32] = event_topic("VaultCracked(bytes32,uint64,bool,uint64)");
const EV_INTEL_PINGED: [u8; 32] = event_topic("IntelPinged(bytes32,uint64,uint64,uint64,bool)");
const EV_INTEL_BURNED: [u8; 32] = event_topic("IntelBurned(bytes32,uint64,uint64)");
const EV_EXFIL_STARTED: [u8; 32] = event_topic("ExfilStarted(bytes32,uint64)");
const EV_FRISK_OPENED: [u8; 32] = event_topic("FriskOpened(bytes32,address,address,uint64)");
const EV_FRISK_RESOLVED: [u8; 32] = event_topic("FriskResolved(bytes32,address,bool)");
const EV_MEETING_CALLED: [u8; 32] = event_topic("MeetingCalled(bytes32,address,uint64)");
const EV_MATCH_ENDED: [u8; 32] = event_topic("MatchEnded(bytes32,uint64,uint64)");
const EV_COMMS_POSTED: [u8; 32] = event_topic("CommsPosted(bytes32,address,uint64,bytes)");

// ---------------------------------------------------------------------------
// HPS Entrypoint Table
// ---------------------------------------------------------------------------

hps_entry! {
    "createMatch(bytes32,uint64,uint64,uint64)"     => handle_create_match,
    "joinMatch(bytes32,bytes32,bytes32)"            => handle_join_match,
    "registerAnonymousSlot(bytes32)"                => handle_register_anon_slot,
    "abortCorruptedLobby(bytes32,address,bytes32)"  => handle_abort_corrupted_lobby,
    "revealSeed(bytes32,bytes32)"                   => handle_reveal_seed,
    "reportPosition(bytes32,uint64,uint64,uint64)"  => handle_report_position,
    "crackVault(bytes32,uint64)"                    => handle_crack_vault,
    "pingIntelHeartbeat(bytes32,uint64,uint64)"     => handle_ping_heartbeat,
    "triggerDecoyJammer(bytes32,uint64,uint64)"     => handle_trigger_jammer,
    "claimLeaseExpired(bytes32)"                    => handle_claim_lease_expired,
    "startExfilUpload(bytes32)"                     => handle_start_exfil_upload,
    "completeExfilLeak(bytes32)"                    => handle_complete_exfil_leak,
    "friskSuspect(bytes32,address)"                 => handle_frisk_suspect,
    "respondFrisk(bytes32,address,bytes32)"         => handle_respond_frisk,
    "claimFriskTimeout(bytes32)"                    => handle_claim_frisk_timeout,
    "callEmergencyMeeting(bytes32)"                 => handle_call_meeting,
    "castTrialVote(bytes32,address)"                => handle_cast_vote,
    "tallyTrialVotes(bytes32)"                      => handle_tally_votes,
    "postComms(bytes32,bytes)"                      => handle_post_comms,
    "getMatchSnapshot(bytes32)"                     => handle_get_snapshot,
    "getRecentComms(bytes32)"                       => handle_get_recent_comms,
}

// ---------------------------------------------------------------------------
// Compact Match & Player State Records
// ---------------------------------------------------------------------------

/// Fixed 264-byte match state record stored under `"m:hdr:" || matchId`.
#[derive(Clone, Copy)]
struct MatchState {
    phase: u64,
    winner: u64,
    win_reason: u64,
    player_target: u64,
    join_count: u64,
    anon_count: u64,
    seed_reveal_count: u64,
    lease_blocks: u64,
    uplink_blocks: u64,
    intel_state: u64,
    last_ping_block: u64,
    upload_start_block: u64,
    jammer_until_block: u64,
    radar_x: u64,
    radar_y: u64,
    burned_intel_count: u64,
    spy_sector_x: u64,
    spy_sector_y: u64,
    spy_last_move_block: u64,
    uncracked_vaults: u64,
    remaining_real_intel: u64,
    pending_deadline: u64,
    meeting_deadline: u64,
    authorized_spy_eoa: [u8; 20],
    pending_suspect: [u8; 20],
    rolling_entropy: [u8; 32],
    vault_states: [u8; 6],
    jammer_used: u8,
    pending_is_tribunal: u8,
}

const MATCH_STATE_LEN: usize = 264;

impl MatchState {
    fn encode(&self) -> [u8; MATCH_STATE_LEN] {
        let mut b = [0u8; MATCH_STATE_LEN];
        let words = [
            self.phase,
            self.winner,
            self.win_reason,
            self.player_target,
            self.join_count,
            self.anon_count,
            self.seed_reveal_count,
            self.lease_blocks,
            self.uplink_blocks,
            self.intel_state,
            self.last_ping_block,
            self.upload_start_block,
            self.jammer_until_block,
            self.radar_x,
            self.radar_y,
            self.burned_intel_count,
            self.spy_sector_x,
            self.spy_sector_y,
            self.spy_last_move_block,
            self.uncracked_vaults,
            self.remaining_real_intel,
            self.pending_deadline,
            self.meeting_deadline,
        ];
        let mut i = 0;
        while i < words.len() {
            b[i * 8..(i + 1) * 8].copy_from_slice(&words[i].to_be_bytes());
            i += 1;
        }
        b[184..204].copy_from_slice(&self.authorized_spy_eoa);
        b[204..224].copy_from_slice(&self.pending_suspect);
        b[224..256].copy_from_slice(&self.rolling_entropy);
        b[256..262].copy_from_slice(&self.vault_states);
        b[262] = self.jammer_used;
        b[263] = self.pending_is_tribunal;
        b
    }

    fn decode(b: &[u8; MATCH_STATE_LEN]) -> Self {
        let rd = |idx: usize| -> u64 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[idx * 8..(idx + 1) * 8]);
            u64::from_be_bytes(w)
        };
        let mut spy = [0u8; 20];
        spy.copy_from_slice(&b[184..204]);
        let mut susp = [0u8; 20];
        susp.copy_from_slice(&b[204..224]);
        let mut ent = [0u8; 32];
        ent.copy_from_slice(&b[224..256]);
        let mut vs = [0u8; 6];
        vs.copy_from_slice(&b[256..262]);

        Self {
            phase: rd(0),
            winner: rd(1),
            win_reason: rd(2),
            player_target: rd(3),
            join_count: rd(4),
            anon_count: rd(5),
            seed_reveal_count: rd(6),
            lease_blocks: rd(7),
            uplink_blocks: rd(8),
            intel_state: rd(9),
            last_ping_block: rd(10),
            upload_start_block: rd(11),
            jammer_until_block: rd(12),
            radar_x: rd(13),
            radar_y: rd(14),
            burned_intel_count: rd(15),
            spy_sector_x: rd(16),
            spy_sector_y: rd(17),
            spy_last_move_block: rd(18),
            uncracked_vaults: rd(19),
            remaining_real_intel: rd(20),
            pending_deadline: rd(21),
            meeting_deadline: rd(22),
            authorized_spy_eoa: spy,
            pending_suspect: susp,
            rolling_entropy: ent,
            vault_states: vs,
            jammer_used: b[262],
            pending_is_tribunal: b[263],
        }
    }
}

/// Fixed 112-byte player record stored under `"m:plr:" || matchId || idx(u64 BE)`.
#[derive(Clone, Copy)]
struct PlayerRecord {
    addr: [u8; 20],
    x: u32,
    y: u32,
    zone: u8,
    status: u8,
    frisk_charges: u8,
    has_meeting_call: u8,
    seed_revealed: u8,
    voted_in_meeting: u8,
    vote_target_idx: u8, // 0..15 = player index, 255 = skip
    last_move_block: u64,
    id_commit: [u8; 32],
    seed_commit: [u8; 32],
}

const PLAYER_REC_LEN: usize = 112;

impl PlayerRecord {
    fn encode(&self) -> [u8; PLAYER_REC_LEN] {
        let mut b = [0u8; PLAYER_REC_LEN];
        b[0..20].copy_from_slice(&self.addr);
        b[20..24].copy_from_slice(&self.x.to_be_bytes());
        b[24..28].copy_from_slice(&self.y.to_be_bytes());
        b[28] = self.zone;
        b[29] = self.status;
        b[30] = self.frisk_charges;
        b[31] = self.has_meeting_call;
        b[32] = self.seed_revealed;
        b[33] = self.voted_in_meeting;
        b[34] = self.vote_target_idx;
        b[35] = 0;
        b[40..48].copy_from_slice(&self.last_move_block.to_be_bytes());
        b[48..80].copy_from_slice(&self.id_commit);
        b[80..112].copy_from_slice(&self.seed_commit);
        b
    }

    fn decode(b: &[u8; PLAYER_REC_LEN]) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&b[0..20]);
        let mut xb = [0u8; 4];
        xb.copy_from_slice(&b[20..24]);
        let mut yb = [0u8; 4];
        yb.copy_from_slice(&b[24..28]);
        let mut lmb = [0u8; 8];
        lmb.copy_from_slice(&b[40..48]);
        let mut idc = [0u8; 32];
        idc.copy_from_slice(&b[48..80]);
        let mut sdc = [0u8; 32];
        sdc.copy_from_slice(&b[80..112]);

        Self {
            addr,
            x: u32::from_be_bytes(xb),
            y: u32::from_be_bytes(yb),
            zone: b[28],
            status: b[29],
            frisk_charges: b[30],
            has_meeting_call: b[31],
            seed_revealed: b[32],
            voted_in_meeting: b[33],
            vote_target_idx: b[34],
            last_move_block: u64::from_be_bytes(lmb),
            id_commit: idc,
            seed_commit: sdc,
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Key Builders & Helpers
// ---------------------------------------------------------------------------

fn match_key(match_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"m:hdr:").push(match_id)
}

fn player_key(match_id: &[u8; 32], idx: u64) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"m:plr:")
        .push(match_id)
        .push_u64_be(idx)
}

fn anon_slot_key(match_id: &[u8; 32], idx: u64) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"m:ano:")
        .push(match_id)
        .push_u64_be(idx)
}

fn comms_count_key(match_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"m:cmc:").push(match_id)
}

fn comms_slot_key(match_id: &[u8; 32], slot: u64) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"m:cms:")
        .push(match_id)
        .push_u64_be(slot)
}

fn load_match(match_id: &[u8; 32]) -> Option<MatchState> {
    let k = match_key(match_id);
    let mut buf = [0u8; MATCH_STATE_LEN];
    match storage::get_into(k.as_slice(), &mut buf) {
        Some(MATCH_STATE_LEN) => Some(MatchState::decode(&buf)),
        _ => None,
    }
}

fn save_match(match_id: &[u8; 32], st: &MatchState) {
    let k = match_key(match_id);
    let enc = st.encode();
    storage::set(k.as_slice(), &enc);
}

fn load_player(match_id: &[u8; 32], idx: u64) -> Option<PlayerRecord> {
    let k = player_key(match_id, idx);
    let mut buf = [0u8; PLAYER_REC_LEN];
    match storage::get_into(k.as_slice(), &mut buf) {
        Some(PLAYER_REC_LEN) => Some(PlayerRecord::decode(&buf)),
        _ => None,
    }
}

fn save_player(match_id: &[u8; 32], idx: u64, rec: &PlayerRecord) {
    let k = player_key(match_id, idx);
    let enc = rec.encode();
    storage::set(k.as_slice(), &enc);
}

fn find_player(match_id: &[u8; 32], count: u64, addr: &[u8; 20]) -> Option<(u64, PlayerRecord)> {
    let capped = count.min(MAX_PLAYERS);
    let mut i = 0u64;
    while i < capped {
        if let Some(p) = load_player(match_id, i) {
            if &p.addr == addr {
                return Some((i, p));
            }
        }
        i += 1;
    }
    None
}

fn is_in_anon_slots(match_id: &[u8; 32], anon_count: u64, target: &[u8; 20]) -> bool {
    let capped = anon_count.min(MAX_PLAYERS);
    let mut i = 0u64;
    while i < capped {
        let k = anon_slot_key(match_id, i);
        if let Some(a) = storage::get_address(k.as_slice()) {
            if &a == target {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Compute `ticket_hash = keccak256("DD_TICKET_V1" || matchId || spy_eoa)`.
pub fn compute_ticket_hash(match_id: &[u8; 32], spy_eoa: &[u8; 20]) -> [u8; 32] {
    let mut pre = [0u8; 64];
    pre[0..12].copy_from_slice(b"DD_TICKET_V1");
    pre[12..44].copy_from_slice(match_id);
    pre[44..64].copy_from_slice(spy_eoa);
    keccak256(&pre)
}

/// Compute `identityCommit = keccak256("DD_ID_V1" || matchId || agent || ticket_hash || idSalt)`.
pub fn compute_identity_commit(
    match_id: &[u8; 32],
    agent: &[u8; 20],
    spy_eoa: &[u8; 20],
    id_salt: &[u8; 32],
) -> [u8; 32] {
    let ticket = compute_ticket_hash(match_id, spy_eoa);
    let mut pre = [0u8; 124];
    pre[0..8].copy_from_slice(b"DD_ID_V1");
    pre[8..40].copy_from_slice(match_id);
    pre[40..60].copy_from_slice(agent);
    pre[60..92].copy_from_slice(&ticket);
    pre[92..124].copy_from_slice(id_salt);
    keccak256(&pre)
}

/// Compute `seedCommit = keccak256("DD_SEED_V1" || matchId || seed)`.
pub fn compute_seed_commit(match_id: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
    let mut pre = [0u8; 74];
    pre[0..10].copy_from_slice(b"DD_SEED_V1");
    pre[10..42].copy_from_slice(match_id);
    pre[42..74].copy_from_slice(seed);
    keccak256(&pre)
}

fn abs_diff(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        b - a
    }
}

fn sector_center_x(sx: u64) -> u64 {
    sx.saturating_mul(SECTOR_SIZE).saturating_add(12).min(ARENA_MAX_X)
}

fn sector_center_y(sy: u64) -> u64 {
    sy.saturating_mul(SECTOR_SIZE).saturating_add(12).min(ARENA_MAX_Y)
}

fn end_match(match_id: &[u8; 32], st: &mut MatchState, winner: u64, reason: u64) {
    st.phase = PHASE_ENDED;
    st.winner = winner;
    st.win_reason = reason;
    st.pending_suspect = [0u8; 20];
    st.pending_deadline = 0;
    st.meeting_deadline = 0;

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&winner.to_be_bytes());
    ev[8..16].copy_from_slice(&reason.to_be_bytes());
    events::emit(&[EV_MATCH_ENDED, *match_id], &ev);
}

fn count_active_players(match_id: &[u8; 32], join_count: u64) -> u64 {
    let capped = join_count.min(MAX_PLAYERS);
    let mut active = 0u64;
    let mut i = 0u64;
    while i < capped {
        if let Some(p) = load_player(match_id, i) {
            if p.status == PLAYER_ACTIVE || p.status == PLAYER_CLEARED {
                active += 1;
            }
        }
        i += 1;
    }
    active
}

// ---------------------------------------------------------------------------
// 1. Lobby Lifecycle Handlers
// ---------------------------------------------------------------------------

fn handle_create_match(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let player_target = args.u64(1).ok_or(-10)?;
    let lease_blocks = args.u64(2).ok_or(-10)?;
    let uplink_blocks = args.u64(3).ok_or(-10)?;

    if player_target < MIN_PLAYERS || player_target > MAX_PLAYERS {
        return Err(-11);
    }
    if lease_blocks < 2 || lease_blocks > 12 {
        return Err(-12);
    }
    if uplink_blocks < 3 || uplink_blocks > 16 {
        return Err(-13);
    }
    if load_match(&match_id).is_some() {
        return Err(-14); // matchId already exists
    }

    let st = MatchState {
        phase: PHASE_LOBBY,
        winner: WINNER_NONE,
        win_reason: REASON_NONE,
        player_target,
        join_count: 0,
        anon_count: 0,
        seed_reveal_count: 0,
        lease_blocks,
        uplink_blocks,
        intel_state: INTEL_NONE,
        last_ping_block: 0,
        upload_start_block: 0,
        jammer_until_block: 0,
        radar_x: 0,
        radar_y: 0,
        burned_intel_count: 0,
        spy_sector_x: 0,
        spy_sector_y: 0,
        spy_last_move_block: 0,
        uncracked_vaults: VAULT_COUNT,
        remaining_real_intel: REAL_INTEL_TOTAL,
        pending_deadline: 0,
        meeting_deadline: 0,
        authorized_spy_eoa: [0u8; 20],
        pending_suspect: [0u8; 20],
        rolling_entropy: match_id,
        vault_states: [VAULT_UNTOUCHED; 6],
        jammer_used: 0,
        pending_is_tribunal: 0,
    };
    save_match(&match_id, &st);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&player_target.to_be_bytes());
    ev[8..16].copy_from_slice(&lease_blocks.to_be_bytes());
    ev[16..24].copy_from_slice(&uplink_blocks.to_be_bytes());
    events::emit(&[EV_MATCH_CREATED, match_id], &ev);

    Ok(())
}

fn handle_join_match(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let id_commit = args.bytes32(1).ok_or(-10)?;
    let seed_commit = args.bytes32(2).ok_or(-10)?;

    if id_commit == [0u8; 32] || seed_commit == [0u8; 32] {
        return Err(-15);
    }

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_LOBBY || st.join_count >= st.player_target {
        return Err(-17);
    }

    let sender = context::msg_sender();
    if sender == [0u8; 20] {
        return Err(-18);
    }
    if find_player(&match_id, st.join_count, &sender).is_some() {
        return Err(-19); // duplicate join
    }

    let idx = st.join_count;
    // Spread spawns slightly in a ring around Central HQ Courtyard `(295, 195)`
    let offset_x = ((idx % 4) * 4) as u32;
    let offset_y = ((idx / 4) * 4) as u32;
    let rec = PlayerRecord {
        addr: sender,
        x: (SPAWN_X as u32 - 6) + offset_x,
        y: (SPAWN_Y as u32 - 6) + offset_y,
        zone: 2,
        status: PLAYER_ACTIVE,
        frisk_charges: 2,
        has_meeting_call: 1,
        seed_revealed: 0,
        voted_in_meeting: 0,
        vote_target_idx: 255,
        last_move_block: context::block_number(),
        id_commit,
        seed_commit,
    };

    save_player(&match_id, idx, &rec);
    st.join_count += 1;
    save_match(&match_id, &st);
    Ok(())
}

/// Step 2 of Lobby: Submitted from each player's zero-balance `$0`-gas `spy_eoa` AFTER all `N`
/// public `identityCommit` entries have been locked on-chain.
fn handle_register_anon_slot(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    // Strictly enforce Step 1 completion before Step 2 begins!
    if st.phase != PHASE_LOBBY || st.join_count != st.player_target {
        return Err(-20);
    }
    if st.anon_count >= st.player_target {
        return Err(-21);
    }

    let spy_eoa = context::msg_sender();
    if spy_eoa == [0u8; 20] {
        return Err(-22);
    }
    // Reject if caller used their public agent address instead of an ephemeral key
    if find_player(&match_id, st.join_count, &spy_eoa).is_some() {
        return Err(-23);
    }
    // Reject duplicate ephemeral slot
    if is_in_anon_slots(&match_id, st.anon_count, &spy_eoa) {
        return Err(-24);
    }

    let k = anon_slot_key(&match_id, st.anon_count);
    storage::set_address(k.as_slice(), &spy_eoa);
    st.anon_count += 1;
    save_match(&match_id, &st);
    Ok(())
}

/// Grief protection: If a malicious lobby participant stuffed `anon_slots` with 2 ephemeral keys
/// so an honest committed player's `mySpyEoa` was excluded, that honest player proves exclusion
/// before `revealSeed` finishes, cleanly aborting the corrupted lobby.
fn handle_abort_corrupted_lobby(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let my_spy_eoa = args.address(1).ok_or(-10)?;
    let id_salt = args.bytes32(2).ok_or(-10)?;

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_LOBBY || st.anon_count != st.player_target {
        return Err(-25);
    }

    let caller = context::msg_sender();
    let (_, rec) = find_player(&match_id, st.join_count, &caller).ok_or(-26)?;
    let expected = compute_identity_commit(&match_id, &caller, &my_spy_eoa, &id_salt);
    if expected != rec.id_commit {
        return Err(-27);
    }
    if is_in_anon_slots(&match_id, st.anon_count, &my_spy_eoa) {
        return Err(-28); // caller's slot IS present; lobby is not corrupted
    }

    end_match(&match_id, &mut st, WINNER_NONE, REASON_LOBBY_ABORTED);
    save_match(&match_id, &st);
    Ok(())
}

/// Step 3 of Lobby: Players reveal `seed`. Once all `N` seeds are revealed, the contract
/// mixes `rolling_entropy` with `block_number` and selects `authorized_spy_eoa`.
fn handle_reveal_seed(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let seed = args.bytes32(1).ok_or(-10)?;

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_LOBBY
        || st.join_count != st.player_target
        || st.anon_count != st.player_target
    {
        return Err(-30);
    }

    let sender = context::msg_sender();
    let (idx, mut rec) = find_player(&match_id, st.join_count, &sender).ok_or(-31)?;
    if rec.seed_revealed != 0 {
        return Err(-32);
    }
    if compute_seed_commit(&match_id, &seed) != rec.seed_commit {
        return Err(-33);
    }

    rec.seed_revealed = 1;
    save_player(&match_id, idx, &rec);

    // Fold seed + sender into rolling_entropy
    let mut mix = [0u8; 84];
    mix[0..32].copy_from_slice(&st.rolling_entropy);
    mix[32..64].copy_from_slice(&seed);
    mix[64..84].copy_from_slice(&sender);
    st.rolling_entropy = keccak256(&mix);
    st.seed_reveal_count += 1;

    if st.seed_reveal_count == st.player_target {
        let blk = context::block_number();
        let mut final_mix = [0u8; 40];
        final_mix[0..32].copy_from_slice(&st.rolling_entropy);
        final_mix[32..40].copy_from_slice(&blk.to_be_bytes());
        let match_rand = keccak256(&final_mix);
        st.rolling_entropy = match_rand;

        let mut rw = [0u8; 8];
        rw.copy_from_slice(&match_rand[0..8]);
        let spy_slot = u64::from_be_bytes(rw) % st.player_target;
        let sk = anon_slot_key(&match_id, spy_slot);
        let spy_eoa = storage::get_address(sk.as_slice()).ok_or(-34)?;

        st.authorized_spy_eoa = spy_eoa;
        st.phase = PHASE_ACTIVE;
        st.spy_last_move_block = blk;

        let mut ev = [0u8; 28];
        ev[0..20].copy_from_slice(&spy_eoa);
        ev[20..28].copy_from_slice(&blk.to_be_bytes());
        events::emit(&[EV_MATCH_STARTED, match_id], &ev);
    }

    save_match(&match_id, &st);
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Public Movement & Spy Smuggling / Heartbeat Handlers
// ---------------------------------------------------------------------------

fn handle_report_position(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let zone = args.u64(1).ok_or(-10)?;
    let x = args.u64(2).ok_or(-10)?;
    let y = args.u64(3).ok_or(-10)?;

    if zone > 5 || x > ARENA_MAX_X || y > ARENA_MAX_Y {
        return Err(-40);
    }

    let st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-41);
    }
    if st.meeting_deadline != 0 {
        return Err(-42); // movement frozen during Emergency Tribunal
    }

    let sender = context::msg_sender();
    let (idx, mut rec) = find_player(&match_id, st.join_count, &sender).ok_or(-43)?;
    if rec.status != PLAYER_ACTIVE && rec.status != PLAYER_CLEARED {
        return Err(-44);
    }

    let blk = context::block_number();
    let dt = blk.saturating_sub(rec.last_move_block).max(1).min(16);
    let max_dist = MAX_STEP_METERS_PER_BLOCK.saturating_mul(dt);
    let dx = abs_diff(x, rec.x as u64);
    let dy = abs_diff(y, rec.y as u64);
    if dx.saturating_mul(dx).saturating_add(dy.saturating_mul(dy)) > max_dist.saturating_mul(max_dist)
    {
        return Err(-45); // speed clamp exceeded
    }

    rec.zone = zone as u8;
    rec.x = x as u32;
    rec.y = y as u32;
    rec.last_move_block = blk;
    save_player(&match_id, idx, &rec);
    Ok(())
}

/// Called from `msg.sender = authorized_spy_eoa` to probe/crack one of the 6 RF Vault Beacons.
fn handle_crack_vault(args: &CalldataReader) -> Result<i32, i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let vault_id = args.u64(1).ok_or(-10)?;

    if vault_id >= VAULT_COUNT {
        return Err(-50);
    }

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-51);
    }
    if context::msg_sender() != st.authorized_spy_eoa {
        return Err(-52); // only the hidden Spy EOA can crack vaults
    }
    if st.intel_state != INTEL_NONE {
        return Err(-53); // already carrying/uploading stolen Intel
    }
    if st.meeting_deadline != 0 || st.pending_deadline != 0 {
        return Err(-54);
    }
    let v_idx = vault_id as usize;
    if st.vault_states[v_idx] != VAULT_UNTOUCHED || st.uncracked_vaults == 0 {
        return Err(-55); // vault already cracked
    }

    let blk = context::block_number();

    // Hypergeometric on-crack roll: exactly 2 of the 6 vaults yield Real Intel,
    // unpredictable prior to the block in which the Spy cracks the vault!
    let is_real = if st.remaining_real_intel == 0 {
        false
    } else if st.uncracked_vaults <= st.remaining_real_intel {
        true
    } else {
        let mut pre = [0u8; 60];
        pre[0..12].copy_from_slice(b"DD_CRACK_V1:");
        pre[12..44].copy_from_slice(&st.rolling_entropy);
        pre[44..52].copy_from_slice(&vault_id.to_be_bytes());
        pre[52..60].copy_from_slice(&blk.to_be_bytes());
        let h = keccak256(&pre);
        let mut rw = [0u8; 8];
        rw.copy_from_slice(&h[0..8]);
        (u64::from_be_bytes(rw) % st.uncracked_vaults) < st.remaining_real_intel
    };

    st.uncracked_vaults = st.uncracked_vaults.saturating_sub(1);

    let (vx, vy) = VAULT_COORDS[v_idx];
    let sx = vx / SECTOR_SIZE;
    let sy = vy / SECTOR_SIZE;

    if is_real {
        st.remaining_real_intel = st.remaining_real_intel.saturating_sub(1);
        st.vault_states[v_idx] = VAULT_CRACKED_INTEL;
        st.intel_state = INTEL_CARRIED;
        st.last_ping_block = blk;
        st.spy_sector_x = sx;
        st.spy_sector_y = sy;
        st.spy_last_move_block = blk;
        st.radar_x = sector_center_x(sx);
        st.radar_y = sector_center_y(sy);

        let mut ping_ev = [0u8; 25];
        ping_ev[0..8].copy_from_slice(&st.radar_x.to_be_bytes());
        ping_ev[8..16].copy_from_slice(&st.radar_y.to_be_bytes());
        ping_ev[16..24].copy_from_slice(&blk.to_be_bytes());
        ping_ev[24] = 0; // real ping (not jammed)
        events::emit(&[EV_INTEL_PINGED, match_id], &ping_ev);
    } else {
        st.vault_states[v_idx] = VAULT_CRACKED_DECOY;
    }

    let mut ev = [0u8; 17];
    ev[0..8].copy_from_slice(&vault_id.to_be_bytes());
    ev[8] = if is_real { 1 } else { 0 };
    ev[9..17].copy_from_slice(&blk.to_be_bytes());
    events::emit(&[EV_VAULT_CRACKED, match_id], &ev);

    save_match(&match_id, &st);
    ret::write_bool(is_real);
    Ok(if is_real { 1 } else { 0 })
}

/// Mandatory Dead-Man's Heartbeat Ping (`msg.sender = authorized_spy_eoa`).
/// Reports only coarse `25m` sector coordinates `(sectorX, sectorY)` so exact sub-cell
/// coordinates never appear in raw transaction calldata!
fn handle_ping_heartbeat(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let sector_x = args.u64(1).ok_or(-10)?;
    let sector_y = args.u64(2).ok_or(-10)?;

    if sector_x > MAX_SECTOR_X || sector_y > MAX_SECTOR_Y {
        return Err(-60);
    }

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-61);
    }
    if context::msg_sender() != st.authorized_spy_eoa {
        return Err(-62);
    }
    if st.intel_state != INTEL_CARRIED && st.intel_state != INTEL_UPLOADING {
        return Err(-63);
    }

    let blk = context::block_number();
    if blk > st.last_ping_block.saturating_add(st.lease_blocks) {
        return Err(-64); // lease already expired!
    }

    // While uploading at Coastal Exfil Pier, Spy must stay within 1 sector of `(22, 7)`
    if st.intel_state == INTEL_UPLOADING {
        if abs_diff(sector_x, EXFIL_SECTOR_X) > 1 || abs_diff(sector_y, EXFIL_SECTOR_Y) > 1 {
            return Err(-65);
        }
    }

    // Enforce Spy physical movement speed (`<= 2` 25m sectors per elapsed block)
    let dt = blk.saturating_sub(st.spy_last_move_block).max(1).min(12);
    let max_sector_step = 2u64.saturating_mul(dt);
    if abs_diff(sector_x, st.spy_sector_x) > max_sector_step
        || abs_diff(sector_y, st.spy_sector_y) > max_sector_step
    {
        return Err(-66);
    }

    st.spy_sector_x = sector_x;
    st.spy_sector_y = sector_y;
    st.spy_last_move_block = blk;
    st.last_ping_block = blk;

    let jammed = blk < st.jammer_until_block;
    if !jammed {
        st.radar_x = sector_center_x(sector_x);
        st.radar_y = sector_center_y(sector_y);
    }

    let mut ev = [0u8; 25];
    ev[0..8].copy_from_slice(&st.radar_x.to_be_bytes());
    ev[8..16].copy_from_slice(&st.radar_y.to_be_bytes());
    ev[16..24].copy_from_slice(&blk.to_be_bytes());
    ev[24] = if jammed { 1 } else { 0 };
    events::emit(&[EV_INTEL_PINGED, match_id], &ev);

    save_match(&match_id, &st);
    Ok(())
}

/// `1x` per match Spy gadget: refreshes the heartbeat lease while pinning the public radar
/// ring to `(fakeSectorX, fakeSectorY)` for `4` blocks without revealing the Spy's true sector!
fn handle_trigger_jammer(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let fake_sx = args.u64(1).ok_or(-10)?;
    let fake_sy = args.u64(2).ok_or(-10)?;

    if fake_sx > MAX_SECTOR_X || fake_sy > MAX_SECTOR_Y {
        return Err(-60);
    }

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE || context::msg_sender() != st.authorized_spy_eoa {
        return Err(-67);
    }
    if st.intel_state != INTEL_CARRIED || st.jammer_used != 0 {
        return Err(-68);
    }

    let blk = context::block_number();
    if blk > st.last_ping_block.saturating_add(st.lease_blocks) {
        return Err(-64);
    }

    st.jammer_used = 1;
    st.jammer_until_block = blk.saturating_add(JAMMER_BLOCKS);
    st.last_ping_block = blk;
    st.radar_x = sector_center_x(fake_sx);
    st.radar_y = sector_center_y(fake_sy);

    let mut ev = [0u8; 25];
    ev[0..8].copy_from_slice(&st.radar_x.to_be_bytes());
    ev[8..16].copy_from_slice(&st.radar_y.to_be_bytes());
    ev[16..24].copy_from_slice(&blk.to_be_bytes());
    ev[24] = 1;
    events::emit(&[EV_INTEL_PINGED, match_id], &ev);

    save_match(&match_id, &st);
    Ok(())
}

/// Callable by anyone when the Spy misses the mandatory Heartbeat Lease (`block > last_ping + lease`).
/// Burns the carried Intel; if all Real Intel items are burned and none remain in vaults, Detectives win!
fn handle_claim_lease_expired(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-70);
    }
    if st.intel_state != INTEL_CARRIED && st.intel_state != INTEL_UPLOADING {
        return Err(-71);
    }

    let blk = context::block_number();
    if blk <= st.last_ping_block.saturating_add(st.lease_blocks) {
        return Err(-72); // lease is still valid
    }

    st.intel_state = INTEL_NONE;
    st.upload_start_block = 0;
    st.burned_intel_count += 1;

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&st.burned_intel_count.to_be_bytes());
    ev[8..16].copy_from_slice(&blk.to_be_bytes());
    events::emit(&[EV_INTEL_BURNED, match_id], &ev);

    if st.burned_intel_count >= REAL_INTEL_TOTAL || st.remaining_real_intel == 0 && st.uncracked_vaults == 0 {
        end_match(
            &match_id,
            &mut st,
            WINNER_DETECTIVES,
            REASON_ALL_INTEL_BURNED,
        );
    }

    save_match(&match_id, &st);
    Ok(())
}

/// Spy initiates multi-block Exfiltration Uplink at Coastal Exfil Pier (`sector (22, 7)`).
fn handle_start_exfil_upload(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    if st.phase != PHASE_ACTIVE || context::msg_sender() != st.authorized_spy_eoa {
        return Err(-75);
    }
    if st.intel_state != INTEL_CARRIED {
        return Err(-76);
    }
    if st.meeting_deadline != 0 || st.pending_deadline != 0 {
        return Err(-77);
    }

    let blk = context::block_number();
    if blk > st.last_ping_block.saturating_add(st.lease_blocks) {
        return Err(-64);
    }
    // Spy's verified sector must be within 1 sector of Coastal Exfil Pier `(22, 7)`
    let dt = blk.saturating_sub(st.spy_last_move_block).max(1).min(12);
    let max_step = 2u64.saturating_mul(dt);
    if abs_diff(EXFIL_SECTOR_X, st.spy_sector_x) > max_step
        || abs_diff(EXFIL_SECTOR_Y, st.spy_sector_y) > max_step
    {
        return Err(-78); // too far from Coastal Exfil Pier
    }

    st.spy_sector_x = EXFIL_SECTOR_X;
    st.spy_sector_y = EXFIL_SECTOR_Y;
    st.spy_last_move_block = blk;
    st.intel_state = INTEL_UPLOADING;
    st.upload_start_block = blk;
    st.last_ping_block = blk;
    st.jammer_until_block = 0; // Pier uplink broadcasts a loud unjammable signal!
    st.radar_x = EXFIL_X;
    st.radar_y = EXFIL_Y;

    events::emit(&[EV_EXFIL_STARTED, match_id], &blk.to_be_bytes());
    save_match(&match_id, &st);
    Ok(())
}

/// Spy finalizes the leak after surviving `uplink_blocks` at Coastal Exfil Pier!
fn handle_complete_exfil_leak(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    if st.phase != PHASE_ACTIVE || context::msg_sender() != st.authorized_spy_eoa {
        return Err(-80);
    }
    if st.intel_state != INTEL_UPLOADING {
        return Err(-81);
    }
    if st.pending_deadline != 0 || st.meeting_deadline != 0 {
        return Err(-82); // cannot complete leak while frisked or in tribunal!
    }

    let blk = context::block_number();
    if blk > st.last_ping_block.saturating_add(st.lease_blocks) {
        return Err(-64); // missed heartbeat during upload
    }
    if blk < st.upload_start_block.saturating_add(st.uplink_blocks) {
        return Err(-83); // upload still in progress
    }

    end_match(&match_id, &mut st, WINNER_SPY, REASON_EXFIL_COMPLETE);
    save_match(&match_id, &st);
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Counter-Intel Proximity Frisk & Emergency Tribunal Handlers
// ---------------------------------------------------------------------------

/// Active Detective within `<= 12m` (`dist_sq <= 144`) spends 1 of 2 Frisk charges to force
/// `suspect` to cryptographically prove whether their committed `spy_eoa` is `authorized_spy_eoa`.
fn handle_frisk_suspect(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let suspect = args.address(1).ok_or(-10)?;

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-85);
    }
    if st.pending_deadline != 0 || st.meeting_deadline != 0 {
        return Err(-86);
    }

    let caller = context::msg_sender();
    if caller == suspect {
        return Err(-87);
    }

    let (c_idx, mut caller_rec) = find_player(&match_id, st.join_count, &caller).ok_or(-88)?;
    let (_, suspect_rec) = find_player(&match_id, st.join_count, &suspect).ok_or(-89)?;

    if caller_rec.status != PLAYER_ACTIVE && caller_rec.status != PLAYER_CLEARED {
        return Err(-90);
    }
    if caller_rec.frisk_charges == 0 {
        return Err(-91);
    }
    // Suspect must be active (not already cleared or ejected)
    if suspect_rec.status != PLAYER_ACTIVE {
        return Err(-92);
    }

    let dx = abs_diff(caller_rec.x as u64, suspect_rec.x as u64);
    let dy = abs_diff(caller_rec.y as u64, suspect_rec.y as u64);
    if dx.saturating_mul(dx).saturating_add(dy.saturating_mul(dy)) > FRISK_MAX_DIST_SQ {
        return Err(-93); // out of 12m RF proximity frisk range!
    }

    let blk = context::block_number();
    caller_rec.frisk_charges -= 1;
    save_player(&match_id, c_idx, &caller_rec);

    st.pending_suspect = suspect;
    st.pending_deadline = blk.saturating_add(FRISK_DEADLINE_BLOCKS);
    st.pending_is_tribunal = 0;

    // Extend Spy heartbeat lease by FRISK_DEADLINE_BLOCKS so a Frisk on an innocent bystander
    // cannot unfairly starve the Spy's timer during resolution.
    if st.intel_state != INTEL_NONE {
        st.last_ping_block = st.last_ping_block.saturating_add(FRISK_DEADLINE_BLOCKS);
    }

    let mut ev = [0u8; 48];
    ev[0..20].copy_from_slice(&caller);
    ev[20..40].copy_from_slice(&suspect);
    ev[40..48].copy_from_slice(&st.pending_deadline.to_be_bytes());
    events::emit(&[EV_FRISK_OPENED, match_id], &ev);

    save_match(&match_id, &st);
    Ok(())
}

/// Suspect responds to an open `PendingFrisk` (from either proximity Frisk or Tribunal conviction)
/// by revealing `(mySpyEoa, idSalt)`.
fn handle_respond_frisk(args: &CalldataReader) -> Result<i32, i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let my_spy_eoa = args.address(1).ok_or(-10)?;
    let id_salt = args.bytes32(2).ok_or(-10)?;

    let mut st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE || st.pending_deadline == 0 {
        return Err(-95);
    }

    let caller = context::msg_sender();
    if caller != st.pending_suspect {
        return Err(-96);
    }

    let (s_idx, mut suspect_rec) = find_player(&match_id, st.join_count, &caller).ok_or(-97)?;

    // 1. Verify salted keccak256 identity commitment locked in Lobby Step 1
    let expected = compute_identity_commit(&match_id, &caller, &my_spy_eoa, &id_salt);
    if expected != suspect_rec.id_commit {
        return Err(-98);
    }

    // 2. Verify `my_spy_eoa` is genuinely one of the N registered anonymous slots from Lobby Step 2
    if !is_in_anon_slots(&match_id, st.anon_count, &my_spy_eoa) {
        return Err(-99);
    }

    let is_spy = my_spy_eoa == st.authorized_spy_eoa;
    let was_tribunal = st.pending_is_tribunal != 0;

    st.pending_suspect = [0u8; 20];
    st.pending_deadline = 0;
    st.pending_is_tribunal = 0;

    let mut ev = [0u8; 21];
    ev[0..20].copy_from_slice(&caller);
    ev[20] = if is_spy { 1 } else { 0 };
    events::emit(&[EV_FRISK_RESOLVED, match_id], &ev);

    if is_spy {
        suspect_rec.status = PLAYER_CAUGHT_SPY;
        save_player(&match_id, s_idx, &suspect_rec);
        let reason = if was_tribunal {
            REASON_TRIBUNAL_CAUGHT
        } else {
            REASON_FRISK_CAUGHT
        };
        end_match(&match_id, &mut st, WINNER_DETECTIVES, reason);
    } else if was_tribunal {
        // Falsely ejecting an innocent Detective in Tribunal sidelines them!
        suspect_rec.status = PLAYER_EJECTED;
        save_player(&match_id, s_idx, &suspect_rec);
        if count_active_players(&match_id, st.join_count) <= 2 {
            end_match(&match_id, &mut st, WINNER_SPY, REASON_DETECTIVES_DEPLETED);
        }
    } else {
        // Proximity frisk cleared an innocent Detective!
        suspect_rec.status = PLAYER_CLEARED;
        save_player(&match_id, s_idx, &suspect_rec);
    }

    save_match(&match_id, &st);
    ret::write_bool(is_spy);
    Ok(if is_spy { 1 } else { 0 })
}

/// If `pending_suspect` stonewalls past `pending_deadline`, Detectives win automatically!
fn handle_claim_frisk_timeout(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    if st.phase != PHASE_ACTIVE || st.pending_deadline == 0 {
        return Err(-100);
    }
    if context::block_number() <= st.pending_deadline {
        return Err(-101);
    }

    if let Some((idx, mut rec)) = find_player(&match_id, st.join_count, &st.pending_suspect) {
        rec.status = PLAYER_CAUGHT_SPY;
        save_player(&match_id, idx, &rec);
    }

    end_match(&match_id, &mut st, WINNER_DETECTIVES, REASON_FRISK_TIMEOUT);
    save_match(&match_id, &st);
    Ok(())
}

/// Emergency Tribunal (`1` call per active player): pauses hunt movement for `6` blocks so
/// players can debate & vote to eject a suspect.
fn handle_call_meeting(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    if st.phase != PHASE_ACTIVE || st.pending_deadline != 0 || st.meeting_deadline != 0 {
        return Err(-110);
    }

    let caller = context::msg_sender();
    let (c_idx, mut caller_rec) = find_player(&match_id, st.join_count, &caller).ok_or(-111)?;
    if (caller_rec.status != PLAYER_ACTIVE && caller_rec.status != PLAYER_CLEARED)
        || caller_rec.has_meeting_call == 0
    {
        return Err(-112);
    }

    caller_rec.has_meeting_call = 0;
    save_player(&match_id, c_idx, &caller_rec);

    // Reset per-player vote flags
    let capped = st.join_count.min(MAX_PLAYERS);
    let mut i = 0u64;
    while i < capped {
        if let Some(mut p) = load_player(&match_id, i) {
            p.voted_in_meeting = 0;
            p.vote_target_idx = 255;
            if i == c_idx {
                p.has_meeting_call = 0;
            }
            save_player(&match_id, i, &p);
        }
        i += 1;
    }

    let blk = context::block_number();
    st.meeting_deadline = blk.saturating_add(MEETING_BLOCKS);
    if st.intel_state != INTEL_NONE {
        st.last_ping_block = st.last_ping_block.saturating_add(MEETING_BLOCKS);
    }
    if st.intel_state == INTEL_UPLOADING {
        st.upload_start_block = st.upload_start_block.saturating_add(MEETING_BLOCKS);
    }

    let mut ev = [0u8; 28];
    ev[0..20].copy_from_slice(&caller);
    ev[20..28].copy_from_slice(&st.meeting_deadline.to_be_bytes());
    events::emit(&[EV_MEETING_CALLED, match_id], &ev);

    save_match(&match_id, &st);
    Ok(())
}

/// Cast a Tribunal vote (`suspect = 0x00..00` means Skip Vote).
fn handle_cast_vote(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let suspect = args.address(1).ok_or(-10)?;

    let st = load_match(&match_id).ok_or(-16)?;
    if st.phase != PHASE_ACTIVE || st.meeting_deadline == 0 {
        return Err(-115);
    }
    if context::block_number() > st.meeting_deadline {
        return Err(-116);
    }

    let caller = context::msg_sender();
    let (v_idx, mut voter) = find_player(&match_id, st.join_count, &caller).ok_or(-117)?;
    if (voter.status != PLAYER_ACTIVE && voter.status != PLAYER_CLEARED)
        || voter.voted_in_meeting != 0
    {
        return Err(-118);
    }

    let target_idx = if suspect == [0u8; 20] {
        255u8
    } else {
        let (t_idx, target_rec) = find_player(&match_id, st.join_count, &suspect).ok_or(-119)?;
        if target_rec.status != PLAYER_ACTIVE {
            return Err(-120); // cannot vote for already cleared/ejected players
        }
        t_idx as u8
    };

    voter.voted_in_meeting = 1;
    voter.vote_target_idx = target_idx;
    save_player(&match_id, v_idx, &voter);
    Ok(())
}

/// Tally Tribunal votes once `block > meeting_deadline` OR all active players have voted.
fn handle_tally_votes(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let mut st = load_match(&match_id).ok_or(-16)?;

    if st.phase != PHASE_ACTIVE || st.meeting_deadline == 0 {
        return Err(-121);
    }

    let capped = st.join_count.min(MAX_PLAYERS);
    let mut tallies = [0u8; 16];
    let mut skip_votes = 0u8;
    let mut active_voters = 0u8;
    let mut cast_votes = 0u8;

    let mut i = 0u64;
    while i < capped {
        if let Some(p) = load_player(&match_id, i) {
            if p.status == PLAYER_ACTIVE || p.status == PLAYER_CLEARED {
                active_voters += 1;
                if p.voted_in_meeting != 0 {
                    cast_votes += 1;
                    if p.vote_target_idx < 16 {
                        tallies[p.vote_target_idx as usize] += 1;
                    } else {
                        skip_votes += 1;
                    }
                }
            }
        }
        i += 1;
    }

    let blk = context::block_number();
    if blk <= st.meeting_deadline && cast_votes < active_voters {
        return Err(-122); // voting still open
    }

    // Find top candidate and check strict plurality > skip_votes and >= 2 votes
    let mut top_idx: Option<usize> = None;
    let mut top_count: u8 = 0;
    let mut tied = false;

    let mut c = 0usize;
    while c < (capped as usize) {
        let v = tallies[c];
        if v > top_count {
            top_count = v;
            top_idx = Some(c);
            tied = false;
        } else if v > 0 && v == top_count {
            tied = true;
        }
        c += 1;
    }

    st.meeting_deadline = 0;

    if let Some(win_idx) = top_idx {
        if !tied && top_count > skip_votes && top_count >= 2 {
            if let Some(suspect_rec) = load_player(&match_id, win_idx as u64) {
                st.pending_suspect = suspect_rec.addr;
                st.pending_deadline = blk.saturating_add(FRISK_DEADLINE_BLOCKS);
                st.pending_is_tribunal = 1;
                if st.intel_state != INTEL_NONE {
                    st.last_ping_block = st.last_ping_block.saturating_add(FRISK_DEADLINE_BLOCKS);
                }
            }
        }
    }

    save_match(&match_id, &st);
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. State-Synced Comms Ring Buffer & Zero-Middleware Local Views
// ---------------------------------------------------------------------------

fn handle_post_comms(args: &CalldataReader) -> Result<(), i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let msg = args.dynamic_bytes(1).ok_or(-10)?;
    if msg.is_empty() || msg.len() > MAX_COMMS_MSG_LEN {
        return Err(-130);
    }

    let st = load_match(&match_id).ok_or(-16)?;
    let sender = context::msg_sender();
    if find_player(&match_id, st.join_count, &sender).is_none() {
        return Err(-131);
    }

    let blk = context::block_number();
    let ck = comms_count_key(&match_id);
    let seq = storage::get_u64(ck.as_slice());
    let slot = seq % MAX_COMMS_SLOTS;

    // Entry layout: `[seq (8B BE)][block (8B BE)][sender (20B)][len (1B)][msg...]`
    let mut entry = [0u8; 37 + MAX_COMMS_MSG_LEN];
    entry[0..8].copy_from_slice(&seq.to_be_bytes());
    entry[8..16].copy_from_slice(&blk.to_be_bytes());
    entry[16..36].copy_from_slice(&sender);
    entry[36] = msg.len() as u8;
    entry[37..37 + msg.len()].copy_from_slice(msg);

    let sk = comms_slot_key(&match_id, slot);
    storage::set(sk.as_slice(), &entry[..37 + msg.len()]);
    storage::set_u64(ck.as_slice(), seq + 1);

    events::emit(&[EV_COMMS_POSTED, match_id], &entry[8..37 + msg.len()]);
    Ok(())
}

/// Returns the entire public match snapshot in a single zero-middleware local-node `eth_call`:
/// - `[0..128]`  16 × `u64 BE` core match words
/// - `[128..148]` `authorized_spy_eoa` (`20B`, zero until `PHASE_ACTIVE`)
/// - `[148..168]` `pending_suspect` (`20B`)
/// - `[168..176]` `pending_deadline` (`u64 BE`)
/// - `[176..184]` `meeting_deadline` (`u64 BE`)
/// - `[184..190]` `vault_states[0..6]` (`6B`)
/// - `[190]`      `jammer_used` (`u8`)
/// - `[191]`      `pending_is_tribunal` (`u8`)
/// - `[192 .. 192 + join_count*48]` per-player public records (`48B` each)
/// - `[192 + join_count*48 .. + anon_count*20]` registered `anon_slots` (`20B` each)
fn handle_get_snapshot(args: &CalldataReader) -> Result<i32, i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let Some(st) = load_match(&match_id) else {
        ret::write(&[]);
        return Ok(0);
    };

    let mut out = [0u8; 192 + (MAX_PLAYERS as usize) * 48 + (MAX_PLAYERS as usize) * 20];
    let head_words = [
        st.phase,
        st.winner,
        st.win_reason,
        st.player_target,
        st.join_count,
        st.anon_count,
        st.seed_reveal_count,
        st.lease_blocks,
        st.uplink_blocks,
        st.intel_state,
        st.last_ping_block,
        st.upload_start_block,
        st.jammer_until_block,
        st.radar_x,
        st.radar_y,
        st.burned_intel_count,
    ];
    let mut i = 0usize;
    while i < 16 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&head_words[i].to_be_bytes());
        i += 1;
    }
    out[128..148].copy_from_slice(&st.authorized_spy_eoa);
    out[148..168].copy_from_slice(&st.pending_suspect);
    out[168..176].copy_from_slice(&st.pending_deadline.to_be_bytes());
    out[176..184].copy_from_slice(&st.meeting_deadline.to_be_bytes());
    out[184..190].copy_from_slice(&st.vault_states);
    out[190] = st.jammer_used;
    out[191] = st.pending_is_tribunal;

    let mut pos = 192usize;
    let jc = st.join_count.min(MAX_PLAYERS);
    let mut p = 0u64;
    while p < jc {
        if let Some(rec) = load_player(&match_id, p) {
            out[pos..pos + 20].copy_from_slice(&rec.addr);
            out[pos + 20..pos + 24].copy_from_slice(&rec.x.to_be_bytes());
            out[pos + 24..pos + 28].copy_from_slice(&rec.y.to_be_bytes());
            out[pos + 28] = rec.zone;
            out[pos + 29] = rec.status;
            out[pos + 30] = rec.frisk_charges;
            out[pos + 31] = rec.has_meeting_call;
            out[pos + 32] = rec.seed_revealed;
            out[pos + 33] = rec.voted_in_meeting;
            out[pos + 34] = rec.vote_target_idx;
            out[pos + 40..pos + 48].copy_from_slice(&rec.last_move_block.to_be_bytes());
        }
        pos += 48;
        p += 1;
    }

    let ac = st.anon_count.min(MAX_PLAYERS);
    let mut a = 0u64;
    while a < ac {
        let ak = anon_slot_key(&match_id, a);
        if let Some(addr) = storage::get_address(ak.as_slice()) {
            out[pos..pos + 20].copy_from_slice(&addr);
        }
        pos += 20;
        a += 1;
    }

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

fn handle_get_recent_comms(args: &CalldataReader) -> Result<i32, i32> {
    let match_id = args.bytes32(0).ok_or(-10)?;
    let ck = comms_count_key(&match_id);
    let total = storage::get_u64(ck.as_slice());
    let count = total.min(MAX_COMMS_SLOTS);
    let start_seq = total.saturating_sub(count);

    let mut out = [0u8; 8 + (MAX_COMMS_SLOTS as usize) * (37 + MAX_COMMS_MSG_LEN)];
    out[0..8].copy_from_slice(&count.to_be_bytes());
    let mut pos = 8usize;

    let mut i = 0u64;
    while i < count {
        let seq = start_seq + i;
        let sk = comms_slot_key(&match_id, seq % MAX_COMMS_SLOTS);
        let mut entry = [0u8; 37 + MAX_COMMS_MSG_LEN];
        if let Some(n) = storage::get_into(sk.as_slice(), &mut entry) {
            if n >= 37 {
                let mlen = (entry[36] as usize).min(MAX_COMMS_MSG_LEN).min(n - 37);
                let frame_len = 37 + mlen;
                out[pos..pos + frame_len].copy_from_slice(&entry[..frame_len]);
                pos += frame_len;
            }
        }
        i += 1;
    }

    ret::write(&out[..pos]);
    Ok(count as i32)
}

// ---------------------------------------------------------------------------
// Native Unit & Adversarial Security Tests (`cargo test -p dead-drop`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const CONTRACT: [u8; 20] = [0xDD; 20];

    struct TestPlayer {
        agent: [u8; 20],
        spy_eoa: [u8; 20],
        id_salt: [u8; 32],
        seed: [u8; 32],
    }

    impl TestPlayer {
        fn new(tag: u8) -> Self {
            Self {
                agent: [tag; 20],
                spy_eoa: [tag.wrapping_add(0x80); 20],
                id_salt: [tag.wrapping_add(0x20); 32],
                seed: [tag.wrapping_add(0x40); 32],
            }
        }
    }

    fn setup_active_match(match_id: [u8; 32], players: &[TestPlayer]) -> ([u8; 20], usize) {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(100);

        // 1. Create match (N players, 4-block heartbeat lease, 6-block pier uplink)
        let cd_create = CallEncoder::<256>::new(selector("createMatch(bytes32,uint64,uint64,uint64)"))
            .push_bytes32(&match_id)
            .push_u64(players.len() as u64)
            .push_u64(4)
            .push_u64(6);
        mock::transact_as(players[0].agent, CONTRACT, cd_create.as_slice()).unwrap();

        // 2. All N players lock `identityCommit` & `seedCommit` BEFORE any anon slot is revealed
        for p in players {
            let idc = compute_identity_commit(&match_id, &p.agent, &p.spy_eoa, &p.id_salt);
            let sdc = compute_seed_commit(&match_id, &p.seed);
            let cd_join = CallEncoder::<256>::new(selector("joinMatch(bytes32,bytes32,bytes32)"))
                .push_bytes32(&match_id)
                .push_bytes32(&idc)
                .push_bytes32(&sdc);
            mock::transact_as(p.agent, CONTRACT, cd_join.as_slice()).unwrap();
        }

        // 3. All N players register their `$0`-gas anonymous Spy EOA slots
        for p in players.iter().rev() {
            let cd_anon = CallEncoder::<256>::new(selector("registerAnonymousSlot(bytes32)"))
                .push_bytes32(&match_id);
            mock::transact_as(p.spy_eoa, CONTRACT, cd_anon.as_slice()).unwrap();
        }

        // 4. Reveal seeds -> selects hidden Spy EOA!
        mock::set_block_number(102);
        for p in players {
            let cd_rev = CallEncoder::<256>::new(selector("revealSeed(bytes32,bytes32)"))
                .push_bytes32(&match_id)
                .push_bytes32(&p.seed);
            mock::transact_as(p.agent, CONTRACT, cd_rev.as_slice()).unwrap();
        }

        // Read snapshot to inspect `authorized_spy_eoa`
        let cd_snap =
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)")).push_bytes32(&match_id);
        let snap = mock::transact_as(players[0].agent, CONTRACT, cd_snap.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(snap[0..8].try_into().unwrap()), PHASE_ACTIVE);
        let mut spy_eoa = [0u8; 20];
        spy_eoa.copy_from_slice(&snap[128..148]);
        let spy_idx = players
            .iter()
            .position(|p| p.spy_eoa == spy_eoa)
            .expect("spy must be one of the registered players");
        (spy_eoa, spy_idx)
    }

    fn crack_until_real_intel(match_id: [u8; 32], spy_eoa: [u8; 20]) -> u64 {
        for v in 0..VAULT_COUNT {
            let cd = CallEncoder::<256>::new(selector("crackVault(bytes32,uint64)"))
                .push_bytes32(&match_id)
                .push_u64(v);
            match mock::transact_as(spy_eoa, CONTRACT, cd.as_slice()) {
                Ok(res) if res[31] == 1 => return v,
                Ok(_) | Err(-55) => continue,
                Err(e) => panic!("unexpected crackVault error: {e}"),
            }
        }
        panic!("hypergeometric guarantee violated: at least 2 of 6 vaults must hold real intel!");
    }

    #[test]
    fn full_spy_smuggle_heartbeat_jammer_and_exfil_victory() {
        let match_id = [0x11; 32];
        let players = [
            TestPlayer::new(1),
            TestPlayer::new(2),
            TestPlayer::new(3),
            TestPlayer::new(4),
        ];
        let (spy_eoa, _spy_idx) = setup_active_match(match_id, &players);

        // Non-spy cannot crack vaults
        let cd_bad = CallEncoder::<256>::new(selector("crackVault(bytes32,uint64)"))
            .push_bytes32(&match_id)
            .push_u64(0);
        assert_eq!(
            mock::transact_as(players[0].agent, CONTRACT, cd_bad.as_slice()),
            Err(-52)
        );

        // Spy cracks vaults until finding Real Intel
        mock::set_block_number(103);
        let real_v = crack_until_real_intel(match_id, spy_eoa);
        let (vx, vy) = VAULT_COORDS[real_v as usize];
        let mut sx = vx / SECTOR_SIZE;
        let mut sy = vy / SECTOR_SIZE;

        // Spy triggers 1x Decoy Jammer to spoof public radar at `(2, 14)` while moving toward Exfil `(22, 7)`
        mock::set_block_number(105);
        let cd_jam = CallEncoder::<256>::new(selector("triggerDecoyJammer(bytes32,uint64,uint64)"))
            .push_bytes32(&match_id)
            .push_u64(2)
            .push_u64(14);
        mock::transact_as(spy_eoa, CONTRACT, cd_jam.as_slice()).unwrap();

        // Walk Spy's sector step-by-step (`<= 2` sectors/block) to Coastal Exfil Pier `(22, 7)`
        let mut blk = 107u64;
        while abs_diff(sx, EXFIL_SECTOR_X) > 1 || abs_diff(sy, EXFIL_SECTOR_Y) > 1 {
            mock::set_block_number(blk);
            if sx + 2 <= EXFIL_SECTOR_X {
                sx += 2;
            } else if sx < EXFIL_SECTOR_X {
                sx = EXFIL_SECTOR_X;
            }
            if sy + 2 <= EXFIL_SECTOR_Y {
                sy += 2;
            } else if sy > EXFIL_SECTOR_Y + 2 {
                sy -= 2;
            } else {
                sy = EXFIL_SECTOR_Y;
            }
            let cd_ping =
                CallEncoder::<256>::new(selector("pingIntelHeartbeat(bytes32,uint64,uint64)"))
                    .push_bytes32(&match_id)
                    .push_u64(sx)
                    .push_u64(sy);
            mock::transact_as(spy_eoa, CONTRACT, cd_ping.as_slice()).unwrap();
            blk += 2;
        }

        // Start 6-block Exfiltration Upload at Pier!
        mock::set_block_number(blk);
        let cd_start =
            CallEncoder::<256>::new(selector("startExfilUpload(bytes32)")).push_bytes32(&match_id);
        mock::transact_as(spy_eoa, CONTRACT, cd_start.as_slice()).unwrap();

        // Too early to complete after 3 blocks -> keep heartbeat alive!
        mock::set_block_number(blk + 3);
        let cd_done =
            CallEncoder::<256>::new(selector("completeExfilLeak(bytes32)")).push_bytes32(&match_id);
        assert_eq!(
            mock::transact_as(spy_eoa, CONTRACT, cd_done.as_slice()),
            Err(-83)
        );
        let cd_keepalive =
            CallEncoder::<256>::new(selector("pingIntelHeartbeat(bytes32,uint64,uint64)"))
                .push_bytes32(&match_id)
                .push_u64(EXFIL_SECTOR_X)
                .push_u64(EXFIL_SECTOR_Y);
        mock::transact_as(spy_eoa, CONTRACT, cd_keepalive.as_slice()).unwrap();

        // Block `blk + 6`: Exfiltration Uplink complete -> SPY WINS!
        mock::set_block_number(blk + 6);
        mock::transact_as(spy_eoa, CONTRACT, cd_done.as_slice()).unwrap();

        let snap = mock::transact_as(
            players[0].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(snap[0..8].try_into().unwrap()), PHASE_ENDED);
        assert_eq!(u64::from_be_bytes(snap[8..16].try_into().unwrap()), WINNER_SPY);
        assert_eq!(
            u64::from_be_bytes(snap[16..24].try_into().unwrap()),
            REASON_EXFIL_COMPLETE
        );
    }

    #[test]
    fn dead_mans_heartbeat_lease_prevents_radio_mute_and_burns_intel() {
        let match_id = [0x22; 32];
        let players = [TestPlayer::new(1), TestPlayer::new(2), TestPlayer::new(3)];
        let (spy_eoa, _) = setup_active_match(match_id, &players);

        // Steal 1st Real Intel at block 105, then mute radio past 4-block lease (block 110)
        mock::set_block_number(105);
        let _ = crack_until_real_intel(match_id, spy_eoa);

        mock::set_block_number(109); // 105 + 4 = still valid on block 109
        let cd_exp =
            CallEncoder::<256>::new(selector("claimLeaseExpired(bytes32)")).push_bytes32(&match_id);
        assert_eq!(
            mock::transact_as(players[0].agent, CONTRACT, cd_exp.as_slice()),
            Err(-72)
        );

        mock::set_block_number(110); // 110 > 105 + 4 -> EXPIRED!
        mock::transact_as(players[0].agent, CONTRACT, cd_exp.as_slice()).unwrap();

        // Steal 2nd Real Intel at block 111 and let it expire too -> Detectives win!
        mock::set_block_number(111);
        let _ = crack_until_real_intel(match_id, spy_eoa);
        mock::set_block_number(116);
        mock::transact_as(players[0].agent, CONTRACT, cd_exp.as_slice()).unwrap();

        let snap = mock::transact_as(
            players[0].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(snap[8..16].try_into().unwrap()),
            WINNER_DETECTIVES
        );
        assert_eq!(
            u64::from_be_bytes(snap[16..24].try_into().unwrap()),
            REASON_ALL_INTEL_BURNED
        );
    }

    #[test]
    fn proximity_frisk_clears_innocent_and_catches_real_spy_unfudgeably() {
        let match_id = [0x33; 32];
        let players = [
            TestPlayer::new(1),
            TestPlayer::new(2),
            TestPlayer::new(3),
            TestPlayer::new(4),
        ];
        let (_spy_eoa, spy_idx) = setup_active_match(match_id, &players);

        let det_idx = (spy_idx + 1) % 4;
        let inno_idx = (spy_idx + 2) % 4;

        // All spawn within ~8m around (295, 195), so Detective is within 12m Frisk range!
        mock::set_block_number(104);
        let cd_frisk_inno = CallEncoder::<256>::new(selector("friskSuspect(bytes32,address)"))
            .push_bytes32(&match_id)
            .push_address(&players[inno_idx].agent);
        mock::transact_as(players[det_idx].agent, CONTRACT, cd_frisk_inno.as_slice()).unwrap();

        // Innocent responds with valid `(spy_eoa, id_salt)` -> cleared, game continues!
        mock::set_block_number(105);
        let cd_resp_inno =
            CallEncoder::<256>::new(selector("respondFrisk(bytes32,address,bytes32)"))
                .push_bytes32(&match_id)
                .push_address(&players[inno_idx].spy_eoa)
                .push_bytes32(&players[inno_idx].id_salt);
        let out_inno = mock::transact_as(
            players[inno_idx].agent,
            CONTRACT,
            cd_resp_inno.as_slice(),
        )
        .unwrap();
        assert_eq!(out_inno[31], 0); // not spy!

        // Now Detective uses 2nd charge to frisk the REAL Spy!
        mock::set_block_number(106);
        let cd_frisk_spy = CallEncoder::<256>::new(selector("friskSuspect(bytes32,address)"))
            .push_bytes32(&match_id)
            .push_address(&players[spy_idx].agent);
        mock::transact_as(players[det_idx].agent, CONTRACT, cd_frisk_spy.as_slice()).unwrap();

        // Spy tries to lie with a fake EOA -> rejected by `keccak256` identityCommit check!
        let fake_eoa = [0xFE; 20];
        let cd_lie = CallEncoder::<256>::new(selector("respondFrisk(bytes32,address,bytes32)"))
            .push_bytes32(&match_id)
            .push_address(&fake_eoa)
            .push_bytes32(&players[spy_idx].id_salt);
        assert_eq!(
            mock::transact_as(players[spy_idx].agent, CONTRACT, cd_lie.as_slice()),
            Err(-98)
        );

        // Spy submits real reveal -> CAUGHT RED-HANDED (`WINNER_DETECTIVES`)!
        let cd_truth = CallEncoder::<256>::new(selector("respondFrisk(bytes32,address,bytes32)"))
            .push_bytes32(&match_id)
            .push_address(&players[spy_idx].spy_eoa)
            .push_bytes32(&players[spy_idx].id_salt);
        let out_spy = mock::transact_as(players[spy_idx].agent, CONTRACT, cd_truth.as_slice()).unwrap();
        assert_eq!(out_spy[31], 1);

        let snap = mock::transact_as(
            players[det_idx].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(snap[8..16].try_into().unwrap()),
            WINNER_DETECTIVES
        );
        assert_eq!(
            u64::from_be_bytes(snap[16..24].try_into().unwrap()),
            REASON_FRISK_CAUGHT
        );
    }

    #[test]
    fn emergency_tribunal_vote_convicts_spy_and_comms_sync() {
        let match_id = [0x44; 32];
        let players = [
            TestPlayer::new(1),
            TestPlayer::new(2),
            TestPlayer::new(3),
            TestPlayer::new(4),
        ];
        let (_, spy_idx) = setup_active_match(match_id, &players);
        let d1 = (spy_idx + 1) % 4;
        let d2 = (spy_idx + 2) % 4;
        let d3 = (spy_idx + 3) % 4;

        // Post state-synced comms alert
        mock::set_block_number(104);
        let cd_comms = CallEncoder::<256>::new(selector("postComms(bytes32,bytes)"))
            .push_u64(0) // placeholder overwritten cleanly below via manual ABI encode
            ;
        let _ = cd_comms;
        let mut raw_comms = Vec::new();
        raw_comms.extend_from_slice(&selector("postComms(bytes32,bytes)"));
        raw_comms.extend_from_slice(&match_id);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        raw_comms.extend_from_slice(&off);
        let msg = b"Saw Agent near Blk 33 Vault right before radar ping!";
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(msg.len() as u64).to_be_bytes());
        raw_comms.extend_from_slice(&lw);
        raw_comms.extend_from_slice(msg);
        raw_comms.resize(raw_comms.len() + (32 - msg.len() % 32) % 32, 0);
        mock::transact_as(players[d1].agent, CONTRACT, &raw_comms).unwrap();

        let comms_out = mock::transact_as(
            players[d2].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getRecentComms(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(comms_out[0..8].try_into().unwrap()), 1);

        // Call Emergency Tribunal Meeting
        mock::transact_as(
            players[d1].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("callEmergencyMeeting(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();

        // 3 Detectives vote for `spy_idx`, Spy votes for `d1` -> all 4 cast, tally immediately!
        for voter in [d1, d2, d3] {
            mock::transact_as(
                players[voter].agent,
                CONTRACT,
                CallEncoder::<256>::new(selector("castTrialVote(bytes32,address)"))
                    .push_bytes32(&match_id)
                    .push_address(&players[spy_idx].agent)
                    .as_slice(),
            )
            .unwrap();
        }
        mock::transact_as(
            players[spy_idx].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("castTrialVote(bytes32,address)"))
                .push_bytes32(&match_id)
                .push_address(&players[d1].agent)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            players[d1].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("tallyTrialVotes(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();

        // Suppose Spy stonewalls the Tribunal reveal past 4 blocks -> auto-busted!
        mock::set_block_number(109);
        mock::transact_as(
            players[d1].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("claimFriskTimeout(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();

        let snap = mock::transact_as(
            players[d1].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(snap[8..16].try_into().unwrap()),
            WINNER_DETECTIVES
        );
        assert_eq!(
            u64::from_be_bytes(snap[16..24].try_into().unwrap()),
            REASON_FRISK_TIMEOUT
        );
    }

    #[test]
    fn abort_corrupted_lobby_blocks_anon_slot_stuffing_grief() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(50);

        let match_id = [0x55; 32];
        let p1 = TestPlayer::new(1);
        let p2 = TestPlayer::new(2);
        let malory = TestPlayer::new(3);

        mock::transact_as(
            p1.agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("createMatch(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&match_id)
                .push_u64(3)
                .push_u64(4)
                .push_u64(6)
                .as_slice(),
        )
        .unwrap();

        for p in [&p1, &p2, &malory] {
            let idc = compute_identity_commit(&match_id, &p.agent, &p.spy_eoa, &p.id_salt);
            let sdc = compute_seed_commit(&match_id, &p.seed);
            mock::transact_as(
                p.agent,
                CONTRACT,
                CallEncoder::<256>::new(selector("joinMatch(bytes32,bytes32,bytes32)"))
                    .push_bytes32(&match_id)
                    .push_bytes32(&idc)
                    .push_bytes32(&sdc)
                    .as_slice(),
            )
            .unwrap();
        }

        // Malory griefs Step 2 by stuffing TWO ephemeral addresses (`malory.spy_eoa` + `[0xEE; 20]`),
        // crowding out `p2.spy_eoa`.
        for slot_sender in [p1.spy_eoa, malory.spy_eoa, [0xEE; 20]] {
            mock::transact_as(
                slot_sender,
                CONTRACT,
                CallEncoder::<256>::new(selector("registerAnonymousSlot(bytes32)"))
                    .push_bytes32(&match_id)
                    .as_slice(),
            )
            .unwrap();
        }

        // `p1` cannot falsely abort because `p1.spy_eoa` IS in `anon_slots`
        assert_eq!(
            mock::transact_as(
                p1.agent,
                CONTRACT,
                CallEncoder::<256>::new(selector("abortCorruptedLobby(bytes32,address,bytes32)"))
                    .push_bytes32(&match_id)
                    .push_address(&p1.spy_eoa)
                    .push_bytes32(&p1.id_salt)
                    .as_slice(),
            ),
            Err(-28)
        );

        // Excluded `p2` proves their pre-committed `p2.spy_eoa` was crowded out -> lobby cleanly aborts!
        mock::transact_as(
            p2.agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("abortCorruptedLobby(bytes32,address,bytes32)"))
                .push_bytes32(&match_id)
                .push_address(&p2.spy_eoa)
                .push_bytes32(&p2.id_salt)
                .as_slice(),
        )
        .unwrap();

        let snap = mock::transact_as(
            p1.agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("getMatchSnapshot(bytes32)"))
                .push_bytes32(&match_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(snap[0..8].try_into().unwrap()), PHASE_ENDED);
        assert_eq!(
            u64::from_be_bytes(snap[16..24].try_into().unwrap()),
            REASON_LOBBY_ABORTED
        );
    }

    #[test]
    fn speed_clamps_and_out_of_range_frisk_rejected() {
        let match_id = [0x66; 32];
        let players = [TestPlayer::new(1), TestPlayer::new(2), TestPlayer::new(3)];
        let (spy_eoa, spy_idx) = setup_active_match(match_id, &players);
        let det_idx = (spy_idx + 1) % 3;

        // Public cross-map teleport in 1 block (`289 -> 580`) rejected (`Err(-45)`)
        mock::set_block_number(103);
        assert_eq!(
            mock::transact_as(
                players[det_idx].agent,
                CONTRACT,
                CallEncoder::<256>::new(selector("reportPosition(bytes32,uint64,uint64,uint64)"))
                    .push_bytes32(&match_id)
                    .push_u64(5)
                    .push_u64(580)
                    .push_u64(195)
                    .as_slice(),
            ),
            Err(-45)
        );

        // Valid 30m step moves Detective `> 12m` away from Spy -> Frisk out of range (`Err(-93)`)
        mock::transact_as(
            players[det_idx].agent,
            CONTRACT,
            CallEncoder::<256>::new(selector("reportPosition(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&match_id)
                .push_u64(2)
                .push_u64(325)
                .push_u64(195)
                .as_slice(),
        )
        .unwrap();

        assert_eq!(
            mock::transact_as(
                players[det_idx].agent,
                CONTRACT,
                CallEncoder::<256>::new(selector("friskSuspect(bytes32,address)"))
                    .push_bytes32(&match_id)
                    .push_address(&players[spy_idx].agent)
                    .as_slice(),
            ),
            Err(-93)
        );

        // Spy steals Intel and tries to teleport across 10 sectors in 1 block -> rejected (`Err(-66)`)
        let v = crack_until_real_intel(match_id, spy_eoa);
        let (vx, _) = VAULT_COORDS[v as usize];
        let bad_sx = if vx / SECTOR_SIZE < 10 { 22 } else { 0 };
        mock::set_block_number(104);
        assert_eq!(
            mock::transact_as(
                spy_eoa,
                CONTRACT,
                CallEncoder::<256>::new(selector("pingIntelHeartbeat(bytes32,uint64,uint64)"))
                    .push_bytes32(&match_id)
                    .push_u64(bad_sx)
                    .push_u64(7)
                    .as_slice(),
            ),
            Err(-66)
        );
    }
}
