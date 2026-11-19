//! # Fractured Hegemony: Simultaneous-Epoch Sovereign Conquest (`hegemony` — HPS #15)
//!
//! 100% original SuperLexicon grand-strategy Haltproof Subroutine:
//! 1. **36 Sovereign Sectors across 6 Tectonic Confederations + 3 Aether Relays + 3 Sub-Orbital Warp Gates**.
//! 2. **Simultaneous Block-Cycle Resolution** (`$0`-gas, zero sequential turn-order advantage):
//!    - Sovereigns stage Reinforcements + Vector Strikes in parallel within the same cycle window.
//!    - Opposing Vector Strikes along the same corridor trigger a **Corridor Clash** before reaching the target sector.
//!    - Multi-faction sieges resolve deterministically via on-chain `keccak256` tactical entropy, with `+20%` Citadel fortification defense.
//! 3. **Instant Drop-In Uprising (`launchUprising`)**:
//!    - Zero lobby wait: claims a 3-sector enclave (Command Citadel + up to 2 flanking sectors) from Autonomous Wardens or overextended empires.
//!    - Eliminated Sovereigns (`0` sectors) can immediately launch a fresh Uprising reusing their Hall-of-Sovereigns seat.
//! 4. **On-Chain Diplomacy & Oathbreaker Penalties (`proposeCompact`, `ratifyCompact`)**:
//!    - Bilateral 6-Cycle Non-Aggression Compacts; breaking a ratified compact emits `OathBroken`, increments the traitor's oathbreaker tally, and transfers `+6` Emergency Supply to the betrayed Sovereign.
//! 5. **Perpetual Epoch Hall of Sovereigns (`>= 24 / 36` Sectors)**:
//!    - Controlling `24` or more Sectors crowns the **Epoch Hegemon**, logs `EpochConquered`, increments `epochs_won`, and fractures the map into `epoch + 1` while preserving all registered Sovereigns.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Bounded World & Protocol Constants
// ---------------------------------------------------------------------------

pub const SECTOR_COUNT: usize = 36;
pub const REGION_COUNT: usize = 6;
pub const OWNER_WARDEN: u8 = 255;

pub const MAX_SOVEREIGNS: usize = 24;
pub const MAX_COMPACTS: usize = 24;
pub const MAX_DEPLOY_OPS: usize = 6;
pub const MAX_STRIKE_OPS: usize = 6;
pub const MAX_STRIKES_TOTAL: usize = MAX_SOVEREIGNS * MAX_STRIKE_OPS;

pub const HEGEMONY_VICTORY_SECTORS: u8 = 24; // 2/3 of 36 Sovereign Sectors
pub const MIN_BLOCKS_PER_CYCLE: u64 = 2;
pub const COMPACT_DURATION_CYCLES: u32 = 6;
pub const OATHBREAKER_EMERGENCY_SUPPLY: u16 = 6;

pub const FLAG_CITADEL: u8 = 0x01;
pub const FLAG_CONTESTED: u8 = 0x02;
pub const FLAG_RELAY: u8 = 0x04;

/// 3 Strategic Aether Relays granting `+2` extra Supply per Cycle.
pub const RELAY_SECTORS: [u8; 3] = [13, 21, 29];

/// 6 Tectonic Confederations (`(mask, bonus_supply)`):
/// - `0`: Boreal Crown (`0..=5`, `6` sectors, `+4` Supply)
/// - `1`: Solstice Meridian (`6..=10`, `5` sectors, `+3` Supply)
/// - `2`: Obsidian Reach (`11..=17`, `7` sectors, `+6` Supply)
/// - `3`: Verdant Expanse (`18..=23`, `6` sectors, `+4` Supply)
/// - `4`: Zephyr Archipelago (`24..=28`, `5` sectors, `+3` Supply)
/// - `5`: Aetherium Core (`29..=35`, `7` sectors, `+5` Supply)
pub const REGION_MASKS: [u64; REGION_COUNT] = [
    0x3Fu64 << 0,   // Boreal Crown (0..5)
    0x1Fu64 << 6,   // Solstice Meridian (6..10)
    0x7Fu64 << 11,  // Obsidian Reach (11..17)
    0x3Fu64 << 18,  // Verdant Expanse (18..23)
    0x1Fu64 << 24,  // Zephyr Archipelago (24..28)
    0x7Fu64 << 29,  // Aetherium Core (29..35)
];
pub const REGION_BONUSES: [u16; REGION_COUNT] = [4, 3, 6, 4, 3, 5];

/// Undirected sector links (intra-confederation corridors, cross-plate bridges, and 3 Sub-Orbital Warp Gates).
const EDGES: &[(u8, u8)] = &[
    // Boreal Atlantic / North America (0..5)
    (0, 1), (0, 3), (1, 2), (1, 3), (1, 4), (2, 4), (3, 4), (3, 5), (4, 5),
    // Andean & Austral / South America (6..10)
    (6, 7), (6, 8), (7, 8), (7, 9), (8, 9), (9, 10),
    // Northern Eurasia & Steppe (11..17) — 13 is Baikal Relay
    (11, 12), (12, 13), (13, 14), (13, 15), (14, 15), (14, 16), (15, 17), (16, 17),
    // Afro-Mediterranean League (18..23) — 21 is Nile Nexus Relay
    (18, 19), (18, 21), (19, 20), (19, 21), (20, 21), (20, 22), (21, 23), (22, 23),
    // Indo-Pacific Archipelago (24..28)
    (24, 25), (24, 26), (25, 26), (26, 27), (26, 28), (27, 28),
    // Continental Core & Silk Crossroads (29..35) — 29 is Geneva Prime Relay
    (29, 30), (30, 31), (30, 32), (31, 32), (31, 33), (32, 33), (32, 34), (33, 34), (33, 35), (34, 35),
    // Real-World Land Isthmuses & Sea Straits
    (5, 6),   // Sierra Isthmus <-> Orinoco Delta (Panama)
    (2, 11),  // Thule Station <-> Nordkapp (North Atlantic)
    (8, 18),  // Amazonia <-> Atlas Littoral (Mid-Atlantic Narrows)
    (11, 29), // Nordkapp <-> Geneva Prime (North Sea)
    (11, 30), // Nordkapp <-> Danube Bastion (Baltic)
    (12, 30), // Ural Frontier <-> Danube Bastion (East European Plain)
    (12, 32), // Ural Frontier <-> Caspian Gate (Steppe)
    (13, 34), // Baikal Relay <-> Yangtze Heartland (Mongolian Corridor)
    (14, 34), // Amur Basin <-> Yangtze Heartland (North China Plain)
    (16, 25), // Kuroshio Arc <-> Luzon Trench (East China Sea)
    (18, 29), // Atlas Littoral <-> Geneva Prime (Gibraltar)
    (21, 31), // Nile Nexus <-> Levant Crossroads (Suez)
    (23, 24), // Malagasy Reef <-> Sunda Strait (Indian Ocean Lane)
    (24, 35), // Sunda Strait <-> Mekong Delta (Malacca Strait)
    (25, 35), // Luzon Trench <-> Mekong Delta (South China Sea)
    // 3 Trans-Oceanic Sub-Orbital Warp Gates (wrap-around East-West & Southern Polar)
    (0, 17),  // Yukon Spire <-> Bering Watch (Bering Trans-Pacific Gate)
    (3, 16),  // Cascadia <-> Kuroshio Arc (North Pacific Slip Gate)
    (10, 28), // Tierra Austral <-> Zealandia Spire (Southern Polar Gate)
];

const fn build_adj() -> [u64; SECTOR_COUNT] {
    let mut adj = [0u64; SECTOR_COUNT];
    let mut i = 0;
    while i < EDGES.len() {
        let (a, b) = EDGES[i];
        adj[a as usize] |= 1u64 << b;
        adj[b as usize] |= 1u64 << a;
        i += 1;
    }
    adj
}

pub const ADJ: [u64; SECTOR_COUNT] = build_adj();

const fn is_relay_sector(s: u8) -> bool {
    s == RELAY_SECTORS[0] || s == RELAY_SECTORS[1] || s == RELAY_SECTORS[2]
}

// ---------------------------------------------------------------------------
// Indexed Events
// ---------------------------------------------------------------------------

const EV_REALM_CREATED: [u8; 32] = event_topic("RealmCreated(bytes32,uint64)");
const EV_SOVEREIGN_JOINED: [u8; 32] =
    event_topic("SovereignJoined(bytes32,address,uint64,uint64,uint64)");
const EV_DIRECTIVES_STAGED: [u8; 32] =
    event_topic("DirectivesStaged(bytes32,address,uint64,uint64,uint64,uint64)");
const EV_SECTOR_CLASH: [u8; 32] = event_topic(
    "SectorClash(bytes32,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64)",
);
const EV_CYCLE_RESOLVED: [u8; 32] =
    event_topic("CycleResolved(bytes32,uint64,uint64,uint64)");
const EV_EPOCH_CONQUERED: [u8; 32] =
    event_topic("EpochConquered(bytes32,address,uint64,uint64,uint64)");
const EV_COMPACT_PROPOSED: [u8; 32] =
    event_topic("CompactProposed(bytes32,uint64,uint64,uint64)");
const EV_COMPACT_RATIFIED: [u8; 32] =
    event_topic("CompactRatified(bytes32,uint64,uint64,uint64)");
const EV_OATH_BROKEN: [u8; 32] =
    event_topic("OathBroken(bytes32,uint64,uint64,uint64)");

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn push_u64_word(out: &mut [u8], idx: usize, val: u64) {
    let start = idx * 32;
    out[start..start + 24].fill(0);
    out[start + 24..start + 32].copy_from_slice(&val.to_be_bytes());
}

// ---------------------------------------------------------------------------
// HPS Entrypoints
// ---------------------------------------------------------------------------

hps_entry! {
    "getActiveRealmId()"                           => handle_get_active_realm_id,
    "createRealm(bytes32)"                         => handle_create_realm,
    "launchUprising(bytes32,address,uint64)"       => handle_launch_uprising,
    "stageDirectives(bytes32,bytes)"               => handle_stage_directives,
    "resolveCycle(bytes32)"                        => handle_resolve_cycle,
    "proposeCompact(bytes32,uint64)"               => handle_propose_compact,
    "ratifyCompact(bytes32,uint64)"                => handle_ratify_compact,
    "getRealmState(bytes32)"                       => handle_get_realm_state,
}

// ---------------------------------------------------------------------------
// Persistent Records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct RealmHeader {
    active: u8,
    sovereign_count: u8,
    compact_count: u8,
    last_hegemon_sid: u8,
    epoch: u32,
    cycle: u32,
    last_resolved_block: u64,
    total_clashes: u32,
    staged_mask: u32,
}

const HDR_LEN: usize = 32;

impl RealmHeader {
    fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0] = self.active;
        b[1] = self.sovereign_count;
        b[2] = self.compact_count;
        b[3] = self.last_hegemon_sid;
        b[4..8].copy_from_slice(&self.epoch.to_be_bytes());
        b[8..12].copy_from_slice(&self.cycle.to_be_bytes());
        b[12..20].copy_from_slice(&self.last_resolved_block.to_be_bytes());
        b[20..24].copy_from_slice(&self.total_clashes.to_be_bytes());
        b[24..28].copy_from_slice(&self.staged_mask.to_be_bytes());
        b
    }

    fn decode(b: &[u8; HDR_LEN]) -> Self {
        Self {
            active: b[0],
            sovereign_count: b[1],
            compact_count: b[2],
            last_hegemon_sid: b[3],
            epoch: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            cycle: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            last_resolved_block: u64::from_be_bytes(b[12..20].try_into().unwrap()),
            total_clashes: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
            staged_mask: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
        }
    }
}

#[derive(Clone, Copy)]
struct SectorRec {
    owner: u8,
    legions: u16,
    flags: u8,
}

type WorldSectors = [SectorRec; SECTOR_COUNT];

#[derive(Clone, Copy)]
struct SovereignRec {
    addr: [u8; 20],
    identity_addr: [u8; 20],
    citadel_sector: u8,
    sector_count: u8,
    supply: u16,
    epochs_won: u16,
    peak_sectors: u16,
    vanquished: u32,
    oaths_broken: u16,
}

const SOV_LEN: usize = 56;

impl SovereignRec {
    fn encode(&self) -> [u8; SOV_LEN] {
        let mut b = [0u8; SOV_LEN];
        b[0..20].copy_from_slice(&self.addr);
        b[20..40].copy_from_slice(&self.identity_addr);
        b[40] = self.citadel_sector;
        b[41] = self.sector_count;
        b[42..44].copy_from_slice(&self.supply.to_be_bytes());
        b[44..46].copy_from_slice(&self.epochs_won.to_be_bytes());
        b[46..48].copy_from_slice(&self.peak_sectors.to_be_bytes());
        b[48..52].copy_from_slice(&self.vanquished.to_be_bytes());
        b[52..54].copy_from_slice(&self.oaths_broken.to_be_bytes());
        b
    }

    fn decode(b: &[u8; SOV_LEN]) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&b[0..20]);
        let mut id = [0u8; 20];
        id.copy_from_slice(&b[20..40]);
        Self {
            addr,
            identity_addr: id,
            citadel_sector: b[40],
            sector_count: b[41],
            supply: u16::from_be_bytes([b[42], b[43]]),
            epochs_won: u16::from_be_bytes([b[44], b[45]]),
            peak_sectors: u16::from_be_bytes([b[46], b[47]]),
            vanquished: u32::from_be_bytes([b[48], b[49], b[50], b[51]]),
            oaths_broken: u16::from_be_bytes([b[52], b[53]]),
        }
    }
}

#[derive(Clone, Copy)]
struct CompactRec {
    sid_a: u8,
    sid_b: u8,
    proposer: u8,
    status: u8, // 0=none, 1=proposed, 2=ratified, 3=broken
    expires_cycle: u32,
}

const CMP_LEN: usize = 8;

impl CompactRec {
    fn encode(&self) -> [u8; CMP_LEN] {
        let mut b = [0u8; CMP_LEN];
        b[0] = self.sid_a;
        b[1] = self.sid_b;
        b[2] = self.proposer;
        b[3] = self.status;
        b[4..8].copy_from_slice(&self.expires_cycle.to_be_bytes());
        b
    }

    fn decode(b: &[u8; CMP_LEN]) -> Self {
        Self {
            sid_a: b[0],
            sid_b: b[1],
            proposer: b[2],
            status: b[3],
            expires_cycle: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Helpers
// ---------------------------------------------------------------------------

const KEY_ACTIVE_REALM: &[u8] = b"h:active_realm";

fn key_hdr(rid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"h:hdr:").push(rid)
}

fn key_map(rid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"h:map:").push(rid)
}

fn key_sov(rid: &[u8; 32], sid: u8) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"h:sov:").push(rid).push(&[sid])
}

fn key_sov_by_addr(rid: &[u8; 32], addr: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"h:idx:").push(rid).push(addr)
}

fn key_dir(rid: &[u8; 32], cycle: u32, sid: u8) -> KeyBuilder<64> {
    KeyBuilder::new()
        .push(b"h:dir:")
        .push(rid)
        .push(&cycle.to_be_bytes())
        .push(&[sid])
}

fn key_compacts(rid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"h:cmp:").push(rid)
}

fn load_hdr(rid: &[u8; 32]) -> Option<RealmHeader> {
    let mut buf = [0u8; HDR_LEN];
    match storage::get_into(key_hdr(rid).as_slice(), &mut buf) {
        Some(HDR_LEN) => Some(RealmHeader::decode(&buf)),
        _ => None,
    }
}

fn save_hdr(rid: &[u8; 32], hdr: &RealmHeader) {
    storage::set(key_hdr(rid).as_slice(), &hdr.encode());
}

fn load_world(rid: &[u8; 32]) -> WorldSectors {
    let mut raw = [0u8; SECTOR_COUNT * 4];
    let mut world = [SectorRec {
        owner: OWNER_WARDEN,
        legions: 3,
        flags: 0,
    }; SECTOR_COUNT];
    if storage::get_into(key_map(rid).as_slice(), &mut raw) == Some(SECTOR_COUNT * 4) {
        let mut i = 0;
        while i < SECTOR_COUNT {
            let off = i * 4;
            world[i] = SectorRec {
                owner: raw[off],
                legions: u16::from_be_bytes([raw[off + 1], raw[off + 2]]),
                flags: raw[off + 3],
            };
            i += 1;
        }
    } else {
        let mut i = 0;
        while i < SECTOR_COUNT {
            if is_relay_sector(i as u8) {
                world[i].flags |= FLAG_RELAY;
                world[i].legions = 4;
            }
            i += 1;
        }
    }
    world
}

fn save_world(rid: &[u8; 32], world: &WorldSectors) {
    let mut raw = [0u8; SECTOR_COUNT * 4];
    let mut i = 0;
    while i < SECTOR_COUNT {
        let off = i * 4;
        let mut flags = world[i].flags & (FLAG_CITADEL | FLAG_CONTESTED);
        if is_relay_sector(i as u8) {
            flags |= FLAG_RELAY;
        }
        raw[off] = world[i].owner;
        let lb = world[i].legions.to_be_bytes();
        raw[off + 1] = lb[0];
        raw[off + 2] = lb[1];
        raw[off + 3] = flags;
        i += 1;
    }
    storage::set(key_map(rid).as_slice(), &raw);
}

fn load_sovereign(rid: &[u8; 32], sid: u8) -> Option<SovereignRec> {
    let mut buf = [0u8; SOV_LEN];
    match storage::get_into(key_sov(rid, sid).as_slice(), &mut buf) {
        Some(SOV_LEN) => Some(SovereignRec::decode(&buf)),
        _ => None,
    }
}

fn save_sovereign(rid: &[u8; 32], sid: u8, sov: &SovereignRec) {
    storage::set(key_sov(rid, sid).as_slice(), &sov.encode());
}

fn find_sovereign_sid(rid: &[u8; 32], addr: &[u8; 20]) -> Option<u8> {
    let mut b = [0u8; 1];
    match storage::get_into(key_sov_by_addr(rid, addr).as_slice(), &mut b) {
        Some(1) => Some(b[0]),
        _ => None,
    }
}

fn load_compacts(rid: &[u8; 32], count: u8) -> ([CompactRec; MAX_COMPACTS], usize) {
    let n = (count as usize).min(MAX_COMPACTS);
    let mut arr = [CompactRec {
        sid_a: 0,
        sid_b: 0,
        proposer: 0,
        status: 0,
        expires_cycle: 0,
    }; MAX_COMPACTS];
    if n == 0 {
        return (arr, 0);
    }
    let mut raw = [0u8; MAX_COMPACTS * CMP_LEN];
    if let Some(read_len) = storage::get_into(key_compacts(rid).as_slice(), &mut raw) {
        let valid = (read_len / CMP_LEN).min(n);
        let mut i = 0;
        while i < valid {
            let mut slice = [0u8; CMP_LEN];
            slice.copy_from_slice(&raw[i * CMP_LEN..(i + 1) * CMP_LEN]);
            arr[i] = CompactRec::decode(&slice);
            i += 1;
        }
        return (arr, valid);
    }
    (arr, 0)
}

fn save_compacts(rid: &[u8; 32], arr: &[CompactRec; MAX_COMPACTS], count: usize) {
    if count == 0 {
        storage::set(key_compacts(rid).as_slice(), &[]);
        return;
    }
    let mut raw = [0u8; MAX_COMPACTS * CMP_LEN];
    let mut i = 0;
    while i < count {
        raw[i * CMP_LEN..(i + 1) * CMP_LEN].copy_from_slice(&arr[i].encode());
        i += 1;
    }
    storage::set(key_compacts(rid).as_slice(), &raw[..count * CMP_LEN]);
}

fn recompute_counts_and_citadels(
    rid: &[u8; 32],
    sovereign_count: u8,
    world: &mut WorldSectors,
    sovs: &mut [SovereignRec; MAX_SOVEREIGNS],
) {
    let n = (sovereign_count as usize).min(MAX_SOVEREIGNS);
    let mut counts = [0u8; MAX_SOVEREIGNS];
    let mut best_sec = [255u8; MAX_SOVEREIGNS];
    let mut best_leg = [0u16; MAX_SOVEREIGNS];

    let mut s = 0;
    while s < SECTOR_COUNT {
        world[s].flags &= !FLAG_CITADEL;
        let ow = world[s].owner as usize;
        if ow < n {
            counts[ow] = counts[ow].saturating_add(1);
            if world[s].legions >= best_leg[ow] {
                best_leg[ow] = world[s].legions;
                best_sec[ow] = s as u8;
            }
        }
        s += 1;
    }

    let mut i = 0;
    while i < n {
        sovs[i].sector_count = counts[i];
        if (counts[i] as u16) > sovs[i].peak_sectors {
            sovs[i].peak_sectors = counts[i] as u16;
        }
        if counts[i] > 0 {
            let cap = sovs[i].citadel_sector as usize;
            if cap >= SECTOR_COUNT || world[cap].owner != (i as u8) {
                sovs[i].citadel_sector = best_sec[i];
            }
            let cidx = sovs[i].citadel_sector as usize;
            if cidx < SECTOR_COUNT {
                world[cidx].flags |= FLAG_CITADEL;
            }
        } else {
            sovs[i].citadel_sector = 255;
        }
        save_sovereign(rid, i as u8, &sovs[i]);
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Entrypoint Implementations
// ---------------------------------------------------------------------------

fn handle_get_active_realm_id(_args: &CalldataReader) -> Result<i32, i32> {
    let rid = storage::get_bytes32(KEY_ACTIVE_REALM).unwrap_or([0u8; 32]);
    ret::write_word(&rid);
    Ok(32)
}

fn handle_create_realm(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    if rid == [0u8; 32] {
        return Err(-11);
    }
    if load_hdr(&rid).is_some() {
        return Err(-12);
    }

    let blk = context::block_number();
    let hdr = RealmHeader {
        active: 1,
        sovereign_count: 0,
        compact_count: 0,
        last_hegemon_sid: 255,
        epoch: 1,
        cycle: 1,
        last_resolved_block: blk,
        total_clashes: 0,
        staged_mask: 0,
    };
    let mut world = [SectorRec {
        owner: OWNER_WARDEN,
        legions: 3,
        flags: 0,
    }; SECTOR_COUNT];
    let mut i = 0;
    while i < SECTOR_COUNT {
        if is_relay_sector(i as u8) {
            world[i].legions = 4;
            world[i].flags = FLAG_RELAY;
        }
        i += 1;
    }

    save_hdr(&rid, &hdr);
    save_world(&rid, &world);
    storage::set(KEY_ACTIVE_REALM, &rid);

    let mut ev_data = [0u8; 32];
    push_u64_word(&mut ev_data, 0, blk);
    events::emit(&[EV_REALM_CREATED, rid], &ev_data);

    ret::write_u64_word(1);
    Ok(32)
}

fn pick_uprising_enclave(
    rid: &[u8; 32],
    caller: &[u8; 20],
    preferred: u64,
    sovereign_count: u8,
    world: &WorldSectors,
) -> Option<(u8, u8, u8)> {
    let mut counts = [0u8; MAX_SOVEREIGNS];
    let mut s = 0;
    while s < SECTOR_COUNT {
        let ow = world[s].owner as usize;
        if ow < (sovereign_count as usize) {
            counts[ow] = counts[ow].saturating_add(1);
        }
        s += 1;
    }

    let mut seed_in = [0u8; 60];
    seed_in[0..32].copy_from_slice(rid);
    seed_in[32..52].copy_from_slice(caller);
    seed_in[52..60].copy_from_slice(&context::block_number().to_be_bytes());
    let h = keccak256(&seed_in);
    let start_off = (h[0] as usize) % SECTOR_COUNT;

    // Candidate score for primary Citadel:
    // 3 = Autonomous Warden (`owner == 255`) with >=1 Warden neighbor
    // 2 = Autonomous Warden
    // 1 = Non-Citadel sector owned by an empire with >= 4 sectors (preferring largest empire)
    let mut best_cap: Option<u8> = None;
    let mut best_score: u16 = 0;

    let check_candidate = |sec: usize| -> u16 {
        let ow = world[sec].owner;
        if ow == OWNER_WARDEN {
            let mut warden_nb = 0u16;
            let mask = ADJ[sec];
            let mut j = 0;
            while j < SECTOR_COUNT {
                if ((mask >> j) & 1) != 0 && world[j].owner == OWNER_WARDEN {
                    warden_nb += 1;
                }
                j += 1;
            }
            300 + warden_nb
        } else if (ow as usize) < (sovereign_count as usize)
            && (world[sec].flags & FLAG_CITADEL) == 0
            && counts[ow as usize] >= 4
        {
            100 + (counts[ow as usize] as u16)
        } else {
            0
        }
    };

    if (preferred as usize) < SECTOR_COUNT {
        let sc = check_candidate(preferred as usize);
        if sc >= 100 {
            best_cap = Some(preferred as u8);
            best_score = sc + 50;
        }
    }

    let mut k = 0;
    while k < SECTOR_COUNT {
        let sec = (start_off + k) % SECTOR_COUNT;
        let sc = check_candidate(sec);
        if sc > best_score {
            best_score = sc;
            best_cap = Some(sec as u8);
        }
        k += 1;
    }

    // Fallback if every empire is small (<4 sectors) and zero wardens left: pick largest empire's non-citadel tile
    if best_cap.is_none() {
        let mut k2 = 0;
        while k2 < SECTOR_COUNT {
            let sec = (start_off + k2) % SECTOR_COUNT;
            let ow = world[sec].owner as usize;
            if ow < (sovereign_count as usize)
                && (world[sec].flags & FLAG_CITADEL) == 0
                && counts[ow] >= 2
            {
                best_cap = Some(sec as u8);
                break;
            }
            k2 += 1;
        }
    }

    let cap = best_cap?;
    let adj_mask = ADJ[cap as usize];
    let mut f1 = 255u8;
    let mut f2 = 255u8;

    // Prefer Warden neighbors first, then non-citadel neighbors of empires with >= 4 sectors
    let mut pass = 0;
    while pass < 2 {
        let mut j = 0;
        while j < SECTOR_COUNT {
            let nb = (start_off + j) % SECTOR_COUNT;
            if nb != (cap as usize) && ((adj_mask >> nb) & 1) != 0 {
                let ow = world[nb].owner;
                let eligible = if pass == 0 {
                    ow == OWNER_WARDEN
                } else {
                    ow != OWNER_WARDEN
                        && (ow as usize) < (sovereign_count as usize)
                        && (world[nb].flags & FLAG_CITADEL) == 0
                        && counts[ow as usize] >= 5
                };
                if eligible && nb as u8 != f1 && nb as u8 != f2 {
                    if f1 == 255 {
                        f1 = nb as u8;
                    } else if f2 == 255 {
                        f2 = nb as u8;
                        break;
                    }
                }
            }
            j += 1;
        }
        if f2 != 255 {
            break;
        }
        pass += 1;
    }

    Some((cap, f1, f2))
}

fn handle_launch_uprising(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let identity_addr = args.address(1).ok_or(-10)?;
    let preferred = args.u64(2).ok_or(-10)?;

    let mut hdr = load_hdr(&rid).ok_or(-13)?;
    if hdr.active == 0 {
        return Err(-14);
    }

    let caller = context::msg_sender();
    let mut world = load_world(&rid);

    let mut sovs = [SovereignRec {
        addr: [0u8; 20],
        identity_addr: [0u8; 20],
        citadel_sector: 255,
        sector_count: 0,
        supply: 0,
        epochs_won: 0,
        peak_sectors: 0,
        vanquished: 0,
        oaths_broken: 0,
    }; MAX_SOVEREIGNS];
    let mut i = 0;
    while i < (hdr.sovereign_count as usize).min(MAX_SOVEREIGNS) {
        if let Some(sv) = load_sovereign(&rid, i as u8) {
            sovs[i] = sv;
        }
        i += 1;
    }

    let sid: u8 = if let Some(existing_sid) = find_sovereign_sid(&rid, &caller) {
        let idx = existing_sid as usize;
        if identity_addr != [0u8; 20] {
            sovs[idx].identity_addr = identity_addr;
        }
        // Check if currently holding sectors — if still alive on the map, update identity & return idempotently
        let mut owned = 0u8;
        let mut s = 0;
        while s < SECTOR_COUNT {
            if world[s].owner == existing_sid {
                owned += 1;
            }
            s += 1;
        }
        if owned > 0 {
            save_sovereign(&rid, existing_sid, &sovs[idx]);
            ret::write_u64_word(existing_sid as u64);
            return Ok(32);
        }
        existing_sid
    } else {
        if (hdr.sovereign_count as usize) >= MAX_SOVEREIGNS {
            return Err(-15);
        }
        let new_sid = hdr.sovereign_count;
        hdr.sovereign_count += 1;
        storage::set(key_sov_by_addr(&rid, &caller).as_slice(), &[new_sid]);
        sovs[new_sid as usize].addr = caller;
        sovs[new_sid as usize].identity_addr = identity_addr;
        new_sid
    };

    let (cap, f1, f2) =
        pick_uprising_enclave(&rid, &caller, preferred, hdr.sovereign_count, &world).ok_or(-16)?;

    world[cap as usize].owner = sid;
    world[cap as usize].legions = 8;
    world[cap as usize].flags |= FLAG_CITADEL;
    let mut claimed = 1u64;
    if f1 != 255 {
        world[f1 as usize].owner = sid;
        world[f1 as usize].legions = 5;
        claimed += 1;
    }
    if f2 != 255 {
        world[f2 as usize].owner = sid;
        world[f2 as usize].legions = 5;
        claimed += 1;
    }

    sovs[sid as usize].citadel_sector = cap;
    sovs[sid as usize].supply = 8;

    recompute_counts_and_citadels(&rid, hdr.sovereign_count, &mut world, &mut sovs);
    save_world(&rid, &world);
    save_hdr(&rid, &hdr);

    let mut ev_data = [0u8; 96];
    push_u64_word(&mut ev_data, 0, sid as u64);
    push_u64_word(&mut ev_data, 1, cap as u64);
    push_u64_word(&mut ev_data, 2, claimed);
    events::emit(&[EV_SOVEREIGN_JOINED, rid, addr_topic(&caller)], &ev_data);

    ret::write_u64_word(sid as u64);
    Ok(32)
}

fn handle_stage_directives(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let raw_orders = args.dynamic_bytes(1).ok_or(-10)?;

    let mut hdr = load_hdr(&rid).ok_or(-13)?;
    if hdr.active == 0 {
        return Err(-14);
    }

    let caller = context::msg_sender();
    let sid = find_sovereign_sid(&rid, &caller).ok_or(-20)?;
    let sov = load_sovereign(&rid, sid).ok_or(-20)?;
    if sov.sector_count == 0 {
        return Err(-21);
    }

    let world = load_world(&rid);

    // Parse `[deploy_count: u8][deploy_ops: N * 3][strike_count: u8][strike_ops: M * 4]`
    if raw_orders.is_empty() {
        return Err(-22);
    }
    let dep_n = raw_orders[0] as usize;
    if dep_n > MAX_DEPLOY_OPS {
        return Err(-23);
    }
    let strike_hdr_off = 1 + dep_n * 3;
    if raw_orders.len() < strike_hdr_off + 1 {
        return Err(-22);
    }
    let str_n = raw_orders[strike_hdr_off] as usize;
    if str_n > MAX_STRIKE_OPS {
        return Err(-24);
    }
    let expected_len = strike_hdr_off + 1 + str_n * 4;
    if raw_orders.len() != expected_len {
        return Err(-22);
    }

    let mut clean_buf = [0u8; 64];
    let mut rem_supply = sov.supply;
    let mut valid_dep = 0usize;
    let mut dep_pos = 1usize;

    let mut i = 0;
    while i < dep_n {
        let off = 1 + i * 3;
        let sec = raw_orders[off] as usize;
        let cnt = u16::from_be_bytes([raw_orders[off + 1], raw_orders[off + 2]]);
        if sec >= SECTOR_COUNT || cnt == 0 {
            return Err(-25);
        }
        if world[sec].owner == sid && rem_supply > 0 {
            let give = cnt.min(rem_supply);
            rem_supply -= give;
            clean_buf[dep_pos] = sec as u8;
            let gb = give.to_be_bytes();
            clean_buf[dep_pos + 1] = gb[0];
            clean_buf[dep_pos + 2] = gb[1];
            dep_pos += 3;
            valid_dep += 1;
        }
        i += 1;
    }
    clean_buf[0] = valid_dep as u8;

    let str_cnt_pos = dep_pos;
    let mut str_pos = str_cnt_pos + 1;
    let mut valid_str = 0usize;

    let mut j = 0;
    while j < str_n {
        let off = strike_hdr_off + 1 + j * 4;
        let from_s = raw_orders[off] as usize;
        let to_s = raw_orders[off + 1] as usize;
        let cnt = u16::from_be_bytes([raw_orders[off + 2], raw_orders[off + 3]]);
        if from_s >= SECTOR_COUNT
            || to_s >= SECTOR_COUNT
            || from_s == to_s
            || ((ADJ[from_s] >> to_s) & 1) == 0
            || cnt == 0
        {
            return Err(-27);
        }
        if world[from_s].owner == sid {
            clean_buf[str_pos] = from_s as u8;
            clean_buf[str_pos + 1] = to_s as u8;
            let cb = cnt.to_be_bytes();
            clean_buf[str_pos + 2] = cb[0];
            clean_buf[str_pos + 3] = cb[1];
            str_pos += 4;
            valid_str += 1;
        }
        j += 1;
    }
    clean_buf[str_cnt_pos] = valid_str as u8;

    storage::set(
        key_dir(&rid, hdr.cycle, sid).as_slice(),
        &clean_buf[..str_pos],
    );
    if (sid as u32) < 32 {
        hdr.staged_mask |= 1u32 << sid;
    }
    save_hdr(&rid, &hdr);

    let mut ev_data = [0u8; 128];
    push_u64_word(&mut ev_data, 0, sid as u64);
    push_u64_word(&mut ev_data, 1, hdr.cycle as u64);
    push_u64_word(&mut ev_data, 2, valid_dep as u64);
    push_u64_word(&mut ev_data, 3, valid_str as u64);
    events::emit(&[EV_DIRECTIVES_STAGED, rid, addr_topic(&caller)], &ev_data);

    ret::write_u64_word(1);
    Ok(32)
}

#[derive(Clone, Copy)]
struct StrikeOp {
    active: u8,
    sid: u8,
    from: u8,
    to: u8,
    legions: u16,
}

fn tactical_roll(rid: &[u8; 32], cycle: u32, blk: u64, salt_a: u8, salt_b: u8) -> u32 {
    let mut buf = [0u8; 46];
    buf[0..32].copy_from_slice(rid);
    buf[32..36].copy_from_slice(&cycle.to_be_bytes());
    buf[36..44].copy_from_slice(&blk.to_be_bytes());
    buf[44] = salt_a;
    buf[45] = salt_b;
    let h = keccak256(&buf);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

fn reset_for_next_epoch(
    rid: &[u8; 32],
    hdr: &mut RealmHeader,
    sovs: &mut [SovereignRec; MAX_SOVEREIGNS],
    blk: u64,
) -> WorldSectors {
    let mut world = [SectorRec {
        owner: OWNER_WARDEN,
        legions: 3,
        flags: 0,
    }; SECTOR_COUNT];
    let mut i = 0;
    while i < SECTOR_COUNT {
        if is_relay_sector(i as u8) {
            world[i].legions = 4;
            world[i].flags = FLAG_RELAY;
        }
        i += 1;
    }

    let n = (hdr.sovereign_count as usize).min(MAX_SOVEREIGNS);
    // Distribute evenly spaced 2-sector homelands for up to 12 active Sovereigns
    let seeded = n.min(12);
    let stride = if seeded > 0 { SECTOR_COUNT / seeded } else { 6 };
    let epoch_shift = ((hdr.epoch as usize) * 5) % SECTOR_COUNT;

    let mut idx = 0;
    while idx < n {
        if idx < seeded {
            let base = (epoch_shift + idx * stride) % SECTOR_COUNT;
            let mut cap = base;
            while world[cap].owner != OWNER_WARDEN {
                cap = (cap + 1) % SECTOR_COUNT;
            }
            world[cap].owner = idx as u8;
            world[cap].legions = 7;
            world[cap].flags |= FLAG_CITADEL;
            sovs[idx].citadel_sector = cap as u8;
            sovs[idx].supply = 6;

            // Give 1 adjacent sector
            let mask = ADJ[cap];
            let mut nb = 0;
            while nb < SECTOR_COUNT {
                if ((mask >> nb) & 1) != 0 && world[nb].owner == OWNER_WARDEN {
                    world[nb].owner = idx as u8;
                    world[nb].legions = 4;
                    break;
                }
                nb += 1;
            }
        } else {
            sovs[idx].citadel_sector = 255;
            sovs[idx].supply = 0;
        }
        idx += 1;
    }

    hdr.compact_count = 0;
    hdr.cycle = 1;
    hdr.staged_mask = 0;
    hdr.last_resolved_block = blk;
    save_compacts(
        rid,
        &[CompactRec {
            sid_a: 0,
            sid_b: 0,
            proposer: 0,
            status: 0,
            expires_cycle: 0,
        }; MAX_COMPACTS],
        0,
    );
    recompute_counts_and_citadels(rid, hdr.sovereign_count, &mut world, sovs);
    world
}

fn handle_resolve_cycle(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&rid).ok_or(-13)?;
    if hdr.active == 0 {
        return Err(-14);
    }

    let blk = context::block_number();
    if blk < hdr.last_resolved_block.saturating_add(MIN_BLOCKS_PER_CYCLE) {
        return Err(-30);
    }

    let sov_n = (hdr.sovereign_count as usize).min(MAX_SOVEREIGNS);
    let mut world = load_world(&rid);
    let mut s = 0;
    while s < SECTOR_COUNT {
        world[s].flags &= !FLAG_CONTESTED;
        s += 1;
    }

    let mut sovs = [SovereignRec {
        addr: [0u8; 20],
        identity_addr: [0u8; 20],
        citadel_sector: 255,
        sector_count: 0,
        supply: 0,
        epochs_won: 0,
        peak_sectors: 0,
        vanquished: 0,
        oaths_broken: 0,
    }; MAX_SOVEREIGNS];
    let mut i = 0;
    while i < sov_n {
        if let Some(sv) = load_sovereign(&rid, i as u8) {
            sovs[i] = sv;
        }
        i += 1;
    }

    let (mut compacts, cmp_n) = load_compacts(&rid, hdr.compact_count);

    // Gather all staged directives for `hdr.cycle`
    let mut strikes = [StrikeOp {
        active: 0,
        sid: 0,
        from: 0,
        to: 0,
        legions: 0,
    }; MAX_STRIKES_TOTAL];
    let mut strike_count = 0usize;

    let mut sid = 0usize;
    while sid < sov_n {
        let mut dir_buf = [0u8; 64];
        let k = key_dir(&rid, hdr.cycle, sid as u8);
        if let Some(dlen) = storage::get_into(k.as_slice(), &mut dir_buf) {
            storage::set(k.as_slice(), &[]);
            if dlen >= 2 && dlen <= 64 {
                let dep_n = (dir_buf[0] as usize).min(MAX_DEPLOY_OPS);
                let strike_off = 1 + dep_n * 3;
                if strike_off < dlen {
                    // Phase 1: Reinforce owned sectors
                    let mut d = 0;
                    while d < dep_n {
                        let off = 1 + d * 3;
                        let sec = dir_buf[off] as usize;
                        let req = u16::from_be_bytes([dir_buf[off + 1], dir_buf[off + 2]]);
                        if sec < SECTOR_COUNT && world[sec].owner == (sid as u8) && sovs[sid].supply > 0 {
                            let give = req.min(sovs[sid].supply);
                            sovs[sid].supply -= give;
                            world[sec].legions = world[sec].legions.saturating_add(give).min(999);
                        }
                        d += 1;
                    }

                    // Record Strike Ops
                    let str_n = (dir_buf[strike_off] as usize).min(MAX_STRIKE_OPS);
                    let mut m = 0;
                    while m < str_n && strike_off + 1 + (m + 1) * 4 <= dlen {
                        let off = strike_off + 1 + m * 4;
                        let from_s = dir_buf[off];
                        let to_s = dir_buf[off + 1];
                        let req = u16::from_be_bytes([dir_buf[off + 2], dir_buf[off + 3]]);
                        if (from_s as usize) < SECTOR_COUNT
                            && (to_s as usize) < SECTOR_COUNT
                            && from_s != to_s
                            && ((ADJ[from_s as usize] >> to_s) & 1) != 0
                            && world[from_s as usize].owner == (sid as u8)
                            && req > 0
                            && strike_count < MAX_STRIKES_TOTAL
                        {
                            strikes[strike_count] = StrikeOp {
                                active: 1,
                                sid: sid as u8,
                                from: from_s,
                                to: to_s,
                                legions: req,
                            };
                            strike_count += 1;
                        }
                        m += 1;
                    }
                }
            }
        }
        sid += 1;
    }

    // Phase 2: Deduct departing legions (always keeping >= 1 garrison legion in origin sector)
    let mut k = 0;
    while k < strike_count {
        let from_idx = strikes[k].from as usize;
        if world[from_idx].owner == strikes[k].sid && world[from_idx].legions > 1 {
            let avail = world[from_idx].legions - 1;
            let send = strikes[k].legions.min(avail);
            world[from_idx].legions -= send;
            strikes[k].legions = send;
        } else {
            strikes[k].active = 0;
            strikes[k].legions = 0;
        }
        k += 1;
    }

    // Phase 2B: Friendly transfers reinforce friendly destination immediately, AND check Non-Aggression Compacts
    let mut k2 = 0;
    while k2 < strike_count {
        if strikes[k2].active != 0 {
            let to_idx = strikes[k2].to as usize;
            let target_owner = world[to_idx].owner;
            let att_sid = strikes[k2].sid;
            if target_owner == att_sid {
                world[to_idx].legions = world[to_idx]
                    .legions
                    .saturating_add(strikes[k2].legions)
                    .min(999);
                strikes[k2].active = 0;
            } else if (target_owner as usize) < sov_n {
                // Check if active ratified compact exists between `att_sid` and `target_owner`
                let lo = att_sid.min(target_owner);
                let hi = att_sid.max(target_owner);
                let mut ci = 0;
                while ci < cmp_n {
                    if compacts[ci].sid_a == lo
                        && compacts[ci].sid_b == hi
                        && compacts[ci].status == 2
                        && compacts[ci].expires_cycle > hdr.cycle
                    {
                        compacts[ci].status = 3; // Broken!
                        sovs[att_sid as usize].oaths_broken =
                            sovs[att_sid as usize].oaths_broken.saturating_add(1);
                        sovs[target_owner as usize].supply = sovs[target_owner as usize]
                            .supply
                            .saturating_add(OATHBREAKER_EMERGENCY_SUPPLY)
                            .min(150);

                        let mut ev_oath = [0u8; 96];
                        push_u64_word(&mut ev_oath, 0, att_sid as u64);
                        push_u64_word(&mut ev_oath, 1, target_owner as u64);
                        push_u64_word(&mut ev_oath, 2, hdr.cycle as u64);
                        events::emit(&[EV_OATH_BROKEN, rid], &ev_oath);
                    }
                    ci += 1;
                }
            }
        }
        k2 += 1;
    }

    // Phase 3: Corridor Head-On Clashes (`A -> B` vs `B -> A`)
    let mut a = 0;
    while a < strike_count {
        if strikes[a].active != 0 {
            let mut b = a + 1;
            while b < strike_count {
                if strikes[b].active != 0
                    && strikes[a].from == strikes[b].to
                    && strikes[a].to == strikes[b].from
                    && strikes[a].sid != strikes[b].sid
                {
                    let roll = tactical_roll(&rid, hdr.cycle, blk, strikes[a].from, strikes[a].to);
                    let pow_a = (strikes[a].legions as u32) * (90 + (roll % 21));
                    let pow_b = (strikes[b].legions as u32) * (90 + ((roll >> 8) % 21));
                    if pow_a > pow_b {
                        let loss = ((strikes[b].legions as u32) * 85 / 100) as u16;
                        let surv = strikes[a].legions.saturating_sub(loss).max(1);
                        let killed_a = strikes[a].legions - surv;
                        sovs[strikes[a].sid as usize].vanquished = sovs[strikes[a].sid as usize]
                            .vanquished
                            .saturating_add(strikes[b].legions as u32);
                        sovs[strikes[b].sid as usize].vanquished = sovs[strikes[b].sid as usize]
                            .vanquished
                            .saturating_add(killed_a as u32);
                        strikes[a].legions = surv;
                        strikes[b].active = 0;
                    } else if pow_b > pow_a {
                        let loss = ((strikes[a].legions as u32) * 85 / 100) as u16;
                        let surv = strikes[b].legions.saturating_sub(loss).max(1);
                        let killed_b = strikes[b].legions - surv;
                        sovs[strikes[b].sid as usize].vanquished = sovs[strikes[b].sid as usize]
                            .vanquished
                            .saturating_add(strikes[a].legions as u32);
                        sovs[strikes[a].sid as usize].vanquished = sovs[strikes[a].sid as usize]
                            .vanquished
                            .saturating_add(killed_b as u32);
                        strikes[b].legions = surv;
                        strikes[a].active = 0;
                        break;
                    } else {
                        // Mutual annihilation in corridor
                        sovs[strikes[a].sid as usize].vanquished = sovs[strikes[a].sid as usize]
                            .vanquished
                            .saturating_add(strikes[b].legions as u32);
                        sovs[strikes[b].sid as usize].vanquished = sovs[strikes[b].sid as usize]
                            .vanquished
                            .saturating_add(strikes[a].legions as u32);
                        strikes[a].active = 0;
                        strikes[b].active = 0;
                        break;
                    }
                }
                b += 1;
            }
        }
        a += 1;
    }

    // Phase 4: Sector Sieges (supports multi-sovereign simultaneous sieges on the same sector)
    let mut clashes_this_cycle = 0u32;
    let mut t = 0usize;
    while t < SECTOR_COUNT {
        let mut incoming_by_sov = [0u16; MAX_SOVEREIGNS];
        let mut any_attack = false;
        let mut primary_att = 255u8;
        let mut primary_att_troops = 0u16;

        let mut si = 0;
        while si < strike_count {
            if strikes[si].active != 0 && (strikes[si].to as usize) == t {
                let asid = strikes[si].sid as usize;
                if asid < sov_n && world[t].owner != (asid as u8) {
                    incoming_by_sov[asid] = incoming_by_sov[asid]
                        .saturating_add(strikes[si].legions)
                        .min(999);
                    if incoming_by_sov[asid] > primary_att_troops {
                        primary_att_troops = incoming_by_sov[asid];
                        primary_att = asid as u8;
                    }
                    any_attack = true;
                }
            }
            si += 1;
        }

        if any_attack {
            clashes_this_cycle += 1;
            world[t].flags |= FLAG_CONTESTED;

            let def_owner = world[t].owner;
            let def_troops = world[t].legions;
            let citadel_bonus: u32 = if (world[t].flags & FLAG_CITADEL) != 0 {
                20
            } else {
                0
            };
            let def_roll = tactical_roll(&rid, hdr.cycle, blk, t as u8, 250) % 25;
            let def_pow: u32 =
                (def_troops as u32) * (98 + citadel_bonus + def_roll) / 100;

            let mut best_sid = def_owner;
            let mut best_pow = def_pow;
            let mut best_raw = def_troops;
            let mut second_pow = 0u32;
            let mut total_attackers = 0u32;

            let mut c = 0;
            while c < sov_n {
                let att_tr = incoming_by_sov[c];
                if att_tr > 0 {
                    total_attackers += att_tr as u32;
                    let r = tactical_roll(&rid, hdr.cycle, blk, t as u8, c as u8) % 29;
                    let p = (att_tr as u32) * (88 + r) / 100;
                    if p > best_pow {
                        second_pow = best_pow;
                        best_pow = p;
                        best_sid = c as u8;
                        best_raw = att_tr;
                    } else if p > second_pow {
                        second_pow = p;
                    }
                }
                c += 1;
            }

            let attrition = ((second_pow * 78) / 100) as u16;
            let survivors = best_raw.saturating_sub(attrition).max(1);

            if best_sid == def_owner {
                // Defender holds the sector!
                world[t].legions = survivors;
                if (def_owner as usize) < sov_n {
                    sovs[def_owner as usize].vanquished = sovs[def_owner as usize]
                        .vanquished
                        .saturating_add(total_attackers);
                }
                if (primary_att as usize) < sov_n {
                    let def_lost = def_troops.saturating_sub(survivors) as u32;
                    sovs[primary_att as usize].vanquished = sovs[primary_att as usize]
                        .vanquished
                        .saturating_add(def_lost);
                }
            } else {
                // Attacker `best_sid` conquers sector `t`!
                world[t].owner = best_sid;
                world[t].legions = survivors;

                let vanquished_here = (def_troops as u32)
                    .saturating_add(total_attackers.saturating_sub(best_raw as u32));
                sovs[best_sid as usize].vanquished = sovs[best_sid as usize]
                    .vanquished
                    .saturating_add(vanquished_here);

                if (def_owner as usize) < sov_n {
                    let att_lost = best_raw.saturating_sub(survivors) as u32;
                    sovs[def_owner as usize].vanquished = sovs[def_owner as usize]
                        .vanquished
                        .saturating_add(att_lost);

                    // If Citadel fell, seize 50% of defender's unspent Supply!
                    if (world[t].flags & FLAG_CITADEL) != 0 {
                        let plunder = sovs[def_owner as usize].supply / 2;
                        sovs[def_owner as usize].supply -= plunder;
                        sovs[best_sid as usize].supply = sovs[best_sid as usize]
                            .supply
                            .saturating_add(plunder)
                            .min(150);
                    }
                }
            }

            let mut ev_clash = [0u8; 256];
            push_u64_word(&mut ev_clash, 0, hdr.cycle as u64);
            push_u64_word(&mut ev_clash, 1, t as u64);
            push_u64_word(&mut ev_clash, 2, primary_att as u64);
            push_u64_word(&mut ev_clash, 3, def_owner as u64);
            push_u64_word(&mut ev_clash, 4, primary_att_troops as u64);
            push_u64_word(&mut ev_clash, 5, def_troops as u64);
            push_u64_word(&mut ev_clash, 6, best_sid as u64);
            push_u64_word(&mut ev_clash, 7, survivors as u64);
            events::emit(&[EV_SECTOR_CLASH, rid], &ev_clash);
        }
        t += 1;
    }

    hdr.total_clashes = hdr.total_clashes.saturating_add(clashes_this_cycle);
    recompute_counts_and_citadels(&rid, hdr.sovereign_count, &mut world, &mut sovs);

    // Phase 5: Check Epoch Hegemony (`>= 24 / 36` Sectors)
    let mut hegemon_sid = 255u8;
    let mut hegemon_secs = 0u8;
    let mut c = 0;
    while c < sov_n {
        if sovs[c].sector_count >= HEGEMONY_VICTORY_SECTORS && sovs[c].sector_count > hegemon_secs {
            hegemon_secs = sovs[c].sector_count;
            hegemon_sid = c as u8;
        }
        c += 1;
    }

    if hegemon_sid != 255 {
        let won_epoch = hdr.epoch;
        let victor_addr = sovs[hegemon_sid as usize].addr;
        sovs[hegemon_sid as usize].epochs_won =
            sovs[hegemon_sid as usize].epochs_won.saturating_add(1);
        hdr.last_hegemon_sid = hegemon_sid;
        hdr.epoch = hdr.epoch.saturating_add(1);

        let next_world = reset_for_next_epoch(&rid, &mut hdr, &mut sovs, blk);
        save_world(&rid, &next_world);
        save_hdr(&rid, &hdr);

        let mut ev_win = [0u8; 96];
        push_u64_word(&mut ev_win, 0, hegemon_sid as u64);
        push_u64_word(&mut ev_win, 1, won_epoch as u64);
        push_u64_word(&mut ev_win, 2, hegemon_secs as u64);
        events::emit(
            &[EV_EPOCH_CONQUERED, rid, addr_topic(&victor_addr)],
            &ev_win,
        );

        ret::write_u64_word(hdr.cycle as u64);
        return Ok(32);
    }

    // Normal Cycle Supply Income: Base (`max(3, sectors / 3)`) + Confederation Hegemony + Aether Relays (`+2` each)
    let mut owned_mask = [0u64; MAX_SOVEREIGNS];
    let mut sec = 0;
    while sec < SECTOR_COUNT {
        let ow = world[sec].owner as usize;
        if ow < sov_n {
            owned_mask[ow] |= 1u64 << sec;
        }
        sec += 1;
    }

    let mut idx = 0;
    while idx < sov_n {
        if sovs[idx].sector_count > 0 {
            let mut inc: u16 = ((sovs[idx].sector_count as u16) / 3).max(3);
            let m = owned_mask[idx];
            let mut r = 0;
            while r < REGION_COUNT {
                if (m & REGION_MASKS[r]) == REGION_MASKS[r] {
                    inc += REGION_BONUSES[r];
                }
                r += 1;
            }
            let mut rl = 0;
            while rl < RELAY_SECTORS.len() {
                if ((m >> RELAY_SECTORS[rl]) & 1) != 0 {
                    inc += 2;
                }
                rl += 1;
            }
            sovs[idx].supply = sovs[idx].supply.saturating_add(inc).min(120);
            save_sovereign(&rid, idx as u8, &sovs[idx]);
        }
        idx += 1;
    }

    // Prune expired compacts
    let next_cycle = hdr.cycle.saturating_add(1);
    let mut kept = [CompactRec {
        sid_a: 0,
        sid_b: 0,
        proposer: 0,
        status: 0,
        expires_cycle: 0,
    }; MAX_COMPACTS];
    let mut kept_n = 0usize;
    let mut ci = 0;
    while ci < cmp_n {
        if (compacts[ci].status == 1 || compacts[ci].status == 2)
            && compacts[ci].expires_cycle > next_cycle
        {
            kept[kept_n] = compacts[ci];
            kept_n += 1;
        }
        ci += 1;
    }
    hdr.compact_count = kept_n as u8;
    hdr.cycle = next_cycle;
    hdr.staged_mask = 0;
    hdr.last_resolved_block = blk;

    save_compacts(&rid, &kept, kept_n);
    save_world(&rid, &world);
    save_hdr(&rid, &hdr);

    let mut ev_cyc = [0u8; 96];
    push_u64_word(&mut ev_cyc, 0, hdr.epoch as u64);
    push_u64_word(&mut ev_cyc, 1, hdr.cycle as u64);
    push_u64_word(&mut ev_cyc, 2, clashes_this_cycle as u64);
    events::emit(&[EV_CYCLE_RESOLVED, rid], &ev_cyc);

    ret::write_u64_word(hdr.cycle as u64);
    Ok(32)
}

fn handle_propose_compact(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let target_u64 = args.u64(1).ok_or(-10)?;

    let mut hdr = load_hdr(&rid).ok_or(-13)?;
    if target_u64 >= (hdr.sovereign_count as u64) {
        return Err(-40);
    }
    let target_sid = target_u64 as u8;
    let caller = context::msg_sender();
    let caller_sid = find_sovereign_sid(&rid, &caller).ok_or(-20)?;
    if caller_sid == target_sid {
        return Err(-41);
    }

    let lo = caller_sid.min(target_sid);
    let hi = caller_sid.max(target_sid);
    let (mut compacts, mut cmp_n) = load_compacts(&rid, hdr.compact_count);

    let mut found = None;
    let mut i = 0;
    while i < cmp_n {
        if compacts[i].sid_a == lo && compacts[i].sid_b == hi {
            found = Some(i);
            break;
        }
        i += 1;
    }

    let slot = if let Some(idx) = found {
        if compacts[idx].status == 2 && compacts[idx].expires_cycle > hdr.cycle {
            return Err(-42); // Already active
        }
        idx
    } else {
        if cmp_n >= MAX_COMPACTS {
            return Err(-43);
        }
        let idx = cmp_n;
        cmp_n += 1;
        hdr.compact_count = cmp_n as u8;
        idx
    };

    compacts[slot] = CompactRec {
        sid_a: lo,
        sid_b: hi,
        proposer: caller_sid,
        status: 1,
        expires_cycle: hdr.cycle.saturating_add(4),
    };
    save_compacts(&rid, &compacts, cmp_n);
    save_hdr(&rid, &hdr);

    let mut ev = [0u8; 96];
    push_u64_word(&mut ev, 0, caller_sid as u64);
    push_u64_word(&mut ev, 1, target_sid as u64);
    push_u64_word(&mut ev, 2, hdr.cycle as u64);
    events::emit(&[EV_COMPACT_PROPOSED, rid], &ev);

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_ratify_compact(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let proposer_u64 = args.u64(1).ok_or(-10)?;

    let hdr = load_hdr(&rid).ok_or(-13)?;
    if proposer_u64 >= (hdr.sovereign_count as u64) {
        return Err(-40);
    }
    let proposer_sid = proposer_u64 as u8;
    let caller = context::msg_sender();
    let caller_sid = find_sovereign_sid(&rid, &caller).ok_or(-20)?;
    if caller_sid == proposer_sid {
        return Err(-41);
    }

    let lo = caller_sid.min(proposer_sid);
    let hi = caller_sid.max(proposer_sid);
    let (mut compacts, cmp_n) = load_compacts(&rid, hdr.compact_count);

    let mut idx = 0;
    while idx < cmp_n {
        if compacts[idx].sid_a == lo
            && compacts[idx].sid_b == hi
            && compacts[idx].status == 1
            && compacts[idx].proposer == proposer_sid
            && compacts[idx].expires_cycle >= hdr.cycle
        {
            let exp = hdr.cycle.saturating_add(COMPACT_DURATION_CYCLES);
            compacts[idx].status = 2;
            compacts[idx].expires_cycle = exp;
            save_compacts(&rid, &compacts, cmp_n);

            let mut ev = [0u8; 96];
            push_u64_word(&mut ev, 0, lo as u64);
            push_u64_word(&mut ev, 1, hi as u64);
            push_u64_word(&mut ev, 2, exp as u64);
            events::emit(&[EV_COMPACT_RATIFIED, rid], &ev);

            ret::write_u64_word(exp as u64);
            return Ok(32);
        }
        idx += 1;
    }

    Err(-44)
}

fn handle_get_realm_state(args: &CalldataReader) -> Result<i32, i32> {
    let rid = args.bytes32(0).ok_or(-10)?;
    let Some(hdr) = load_hdr(&rid) else {
        ret::write(&[]);
        return Ok(0);
    };

    const MAX_OUT: usize =
        HDR_LEN + SECTOR_COUNT * 4 + MAX_SOVEREIGNS * SOV_LEN + MAX_COMPACTS * CMP_LEN;
    let mut out = [0u8; MAX_OUT];
    out[0..HDR_LEN].copy_from_slice(&hdr.encode());
    let mut pos = HDR_LEN;

    let world = load_world(&rid);
    let mut s = 0;
    while s < SECTOR_COUNT {
        let mut flags = world[s].flags & (FLAG_CITADEL | FLAG_CONTESTED);
        if is_relay_sector(s as u8) {
            flags |= FLAG_RELAY;
        }
        out[pos] = world[s].owner;
        let lb = world[s].legions.to_be_bytes();
        out[pos + 1] = lb[0];
        out[pos + 2] = lb[1];
        out[pos + 3] = flags;
        pos += 4;
        s += 1;
    }

    let sov_n = (hdr.sovereign_count as usize).min(MAX_SOVEREIGNS);
    let mut i = 0;
    while i < sov_n {
        let sv = load_sovereign(&rid, i as u8).unwrap_or(SovereignRec {
            addr: [0u8; 20],
            identity_addr: [0u8; 20],
            citadel_sector: 255,
            sector_count: 0,
            supply: 0,
            epochs_won: 0,
            peak_sectors: 0,
            vanquished: 0,
            oaths_broken: 0,
        });
        out[pos..pos + SOV_LEN].copy_from_slice(&sv.encode());
        pos += SOV_LEN;
        i += 1;
    }

    let (compacts, cmp_n) = load_compacts(&rid, hdr.compact_count);
    out[2] = cmp_n as u8;
    let mut c = 0;
    while c < cmp_n {
        out[pos..pos + CMP_LEN].copy_from_slice(&compacts[c].encode());
        pos += CMP_LEN;
        c += 1;
    }

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

// ---------------------------------------------------------------------------
// Native Unit Tests (`cargo test -p hegemony`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const REALM_ADDR: [u8; 20] = [0x51; 20];
    const ALICE: [u8; 20] = [0xA1; 20];
    const BOB: [u8; 20] = [0xB2; 20];

    #[test]
    fn graph_is_symmetric_and_connected() {
        for a in 0..SECTOR_COUNT {
            assert_eq!((ADJ[a] >> a) & 1, 0, "no self-loops");
            for b in 0..SECTOR_COUNT {
                let ab = (ADJ[a] >> b) & 1;
                let ba = (ADJ[b] >> a) & 1;
                assert_eq!(ab, ba, "symmetric edge {a}<->{b}");
            }
        }
        // BFS from sector 0 must reach all 36 sectors
        let mut visited = 1u64;
        let mut frontier = 1u64;
        while frontier != 0 {
            let s = frontier.trailing_zeros() as usize;
            frontier &= !(1u64 << s);
            let next = ADJ[s] & !visited;
            visited |= next;
            frontier |= next;
        }
        assert_eq!(visited, (1u64 << SECTOR_COUNT) - 1);
    }

    #[test]
    fn uprising_directives_compact_and_cycle_resolution() {
        mock::reset();
        mock::register_hps(REALM_ADDR, dispatch_calldata);
        mock::set_block_number(100);

        let rid = [0x77; 32];
        let cd_create = CallEncoder::<256>::new(selector("createRealm(bytes32)"))
            .push_bytes32(&rid)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, REALM_ADDR, &cd_create).unwrap();

        // Alice & Bob launch uprisings
        let cd_join_a = CallEncoder::<256>::new(selector("launchUprising(bytes32,address,uint64)"))
            .push_bytes32(&rid)
            .push_address(&[0x11; 20])
            .push_u64(0)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, REALM_ADDR, &cd_join_a).unwrap();

        let cd_join_b = CallEncoder::<256>::new(selector("launchUprising(bytes32,address,uint64)"))
            .push_bytes32(&rid)
            .push_address(&[0x22; 20])
            .push_u64(20)
            .as_slice()
            .to_vec();
        mock::transact_as(BOB, REALM_ADDR, &cd_join_b).unwrap();

        // Propose & ratify Non-Aggression Compact
        let cd_prop = CallEncoder::<256>::new(selector("proposeCompact(bytes32,uint64)"))
            .push_bytes32(&rid)
            .push_u64(1)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, REALM_ADDR, &cd_prop).unwrap();

        let cd_rat = CallEncoder::<256>::new(selector("ratifyCompact(bytes32,uint64)"))
            .push_bytes32(&rid)
            .push_u64(0)
            .as_slice()
            .to_vec();
        mock::transact_as(BOB, REALM_ADDR, &cd_rat).unwrap();

        // Alice deploys 8 supply to Citadel (sector 0) & strikes adjacent Warden sector
        let mut target_warden = 255u8;
        for nb in 0..SECTOR_COUNT {
            if ((ADJ[0] >> nb) & 1) != 0 {
                // Read state to find a non-Alice neighbor
                target_warden = nb as u8;
            }
        }
        assert_ne!(target_warden, 255);
        let orders = [1u8, 0u8, 0u8, 8u8, 1u8, 0u8, target_warden, 0u8, 6u8];
        let cd_stage = CallEncoder::<256>::new(selector("stageDirectives(bytes32,bytes)"))
            .push_bytes32(&rid)
            .push_u64(64)
            .push_dynamic_bytes_tail(&orders)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, REALM_ADDR, &cd_stage).unwrap();

        mock::set_block_number(102);
        let cd_res = CallEncoder::<256>::new(selector("resolveCycle(bytes32)"))
            .push_bytes32(&rid)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, REALM_ADDR, &cd_res).unwrap();

        let cd_state = CallEncoder::<256>::new(selector("getRealmState(bytes32)"))
            .push_bytes32(&rid)
            .as_slice()
            .to_vec();
        let st = mock::transact_as(ALICE, REALM_ADDR, &cd_state).unwrap();
        assert_eq!(st[1], 2); // 2 sovereigns
        assert_eq!(st[2], 1); // 1 ratified compact
        assert_eq!(u32::from_be_bytes([st[8], st[9], st[10], st[11]]), 2); // Cycle 2
    }
}
