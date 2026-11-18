//! # Phantom Fleet: 100-Player Red vs. Blue Naval Warfare & Economy (`battleship` — HPS #13)
//!
//! Designed for SuperLexicon's live Subnet 1 ledger:
//! 1. **Up to 100 Captains (`50 Red vs. 50 Blue`)** with strict on-chain team balancing
//!    (`|red_count - blue_count| <= 1`) and **`1,000 Credits (CR)`** starting bankroll.
//! 2. **Dynamic High-Resolution Ocean Grid (`40x25` -> `189x118`)**.
//! 3. **8-Direction Compass + Percentage Throttle Navigation (`25% / 50% / 75% / 100%` Max Speed)**:
//!    - HFS computes target grid coordinates from `(dir8, speedPct)` and emits `ShipMoved` so clients
//!      teleport ships directly to the HFS-verified coordinates from the transaction receipt log.
//! 4. **Crisp 1-Hit (`100%`) Per-Square Hull Destruction**:
//!    - Every weapon impact on an intact ship square immediately destroys that square (`100%`),
//!      awarding `+120 CR` per square destroyed + `CLASS_BOUNTY` when all squares of the ship are hit.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Halt-Free Bounded Constants
// ---------------------------------------------------------------------------

pub const MAX_PLAYERS: u64 = 100;
pub const SHIPS_PER_PLAYER: u64 = 3;
pub const MAX_SHIPS: usize = 300;
pub const MAX_INFLIGHT_SHELLS: usize = 128;

pub const STARTING_CREDITS: u64 = 1000;
pub const EMERGENCY_GUNBOAT_FLOOR: u64 = 200;
pub const CREDITS_PER_CELL_HIT: u64 = 120;
pub const REPAIR_COST_PER_CELL: u64 = 100;

pub const TEAM_RED: u8 = 0;
pub const TEAM_BLUE: u8 = 1;

pub const BASE_GRID_W: u8 = 40;
pub const BASE_GRID_H: u8 = 25;
pub const MAX_GRID_W: u8 = 200;
pub const MAX_GRID_H: u8 = 125;

/// Ship classes (`0..=3`): Gunboat (`2x1`), Frigate (`3x1`), Cruiser (`4x1`), Dreadnought (`5x2`).
pub const CLASS_COUNT: usize = 4;
pub const CLASS_LEN: [u8; 4] = [2, 3, 4, 5];
pub const CLASS_WID: [u8; 4] = [1, 1, 1, 2];
pub const CLASS_CELLS: [u8; 4] = [2, 3, 4, 10];
pub const CLASS_COST: [u64; 4] = [200, 350, 550, 1100];
pub const CLASS_BOUNTY: [u64; 4] = [120, 200, 320, 600];
/// Base Max Speed at `100%` throttle (in grid squares per move):
/// Gunboat = 12 sq, Frigate = 8 sq, Heavy Cruiser = 6 sq, Dreadnought = 4 sq.
pub const CLASS_MAX_SPEED: [u8; 4] = [12, 8, 6, 4];
pub const CLASS_SINK_CELLS: [u8; 4] = [2, 3, 4, 10];

/// Weapon systems (`0..=4`) — instant `100%` destruction on every hit square in the blast pattern!
pub const GUN_COUNT: usize = 5;
pub const GUN_MIN_CLASS: [u8; 5] = [0, 0, 1, 2, 3]; // S=0, M=1, L=2, XL=3
pub const GUN_COST: [u64; 5] = [0, 250, 450, 700, 1100];
pub const GUN_RANGE: [u16; 5] = [10, 9, 14, 18, 30];
pub const GUN_PATTERN: [u8; 5] = [0, 1, 2, 1, 0]; // 0 = 1x1, 1 = 2x2, 2 = '+' 5-cell cross
pub const GUN_FLIGHT_BLOCKS: [u8; 5] = [0, 0, 0, 0, 0];

/// Engine / Turbine upgrade tiers (`0..=2`, stored in `ship.armor_tier` for binary compatibility).
pub const ENGINE_MAX_TIER: u8 = 2;
pub const ENGINE_UPGRADE_COST: [u64; 2] = [200, 450];
pub const ENGINE_SPEED_BONUS: [u8; 3] = [0, 2, 4];

/// 8 Compass Directions (`0..=7`: N, NE, E, SE, S, SW, W, NW).
const DIR8_DX: [i16; 8] = [0, 1, 1, 1, 0, -1, -1, -1];
const DIR8_DY: [i16; 8] = [-1, -1, 0, 1, 1, 1, 0, -1];

// ---------------------------------------------------------------------------
// Indexed Events
// ---------------------------------------------------------------------------

const EV_BATTLE_CREATED: [u8; 32] = event_topic("BattleCreated(bytes32,uint64)");
const EV_PLAYER_JOINED: [u8; 32] = event_topic("PlayerJoined(bytes32,address,uint64,uint64,uint64)");
const EV_SHIP_COMMISSIONED: [u8; 32] =
    event_topic("ShipCommissioned(bytes32,uint64,uint64,uint64,uint64,uint64)");
const EV_SHIP_MOVED: [u8; 32] = event_topic(
    "ShipMoved(bytes32,address,uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64)",
);
const EV_WEAPON_FIRED: [u8; 32] =
    event_topic("WeaponFired(bytes32,uint64,uint64,uint64,uint64,uint64)");
const EV_SHIP_SUNK: [u8; 32] = event_topic("ShipSunk(bytes32,uint64,uint64,uint64)");

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

// ---------------------------------------------------------------------------
// HPS Entrypoint Table
// ---------------------------------------------------------------------------

hps_entry! {
    "createBattle(bytes32)"                                       => handle_create_battle,
    "joinBattle(bytes32,uint64)"                                  => handle_join_battle,
    "joinAndDeploy(bytes32,uint64,uint64,uint64,uint64)"          => handle_join_and_deploy,
    "buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"         => handle_buy_ship,
    "moveShip(bytes32,uint64,uint64,uint64)"                      => handle_move_ship,
    "fireWeapon(bytes32,uint64,uint64,uint64)"                    => handle_fire_weapon,
    "upgradeGun(bytes32,uint64,uint64)"                           => handle_upgrade_gun,
    "upgradeArmor(bytes32,uint64)"                                => handle_upgrade_engine,
    "repairShip(bytes32,uint64)"                                  => handle_repair_ship,
    "resolvePendingShells(bytes32)"                               => handle_resolve_shells,
    "getBattleState(bytes32)"                                     => handle_get_battle_state,
    "getPlayersSlice(bytes32,uint64,uint64)"                      => handle_get_players_slice,
}

// ---------------------------------------------------------------------------
// State Records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct BattleHeader {
    active: u8,
    player_count: u8,
    red_count: u8,
    blue_count: u8,
    grid_w: u8,
    grid_h: u8,
    shell_count: u16,
    red_kills: u32,
    blue_kills: u32,
    last_resolved_block: u64,
    total_shots_fired: u64,
}

const HDR_LEN: usize = 32;

impl BattleHeader {
    fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0] = self.active;
        b[1] = self.player_count;
        b[2] = self.red_count;
        b[3] = self.blue_count;
        b[4] = self.grid_w;
        b[5] = self.grid_h;
        b[6..8].copy_from_slice(&self.shell_count.to_be_bytes());
        b[8..12].copy_from_slice(&self.red_kills.to_be_bytes());
        b[12..16].copy_from_slice(&self.blue_kills.to_be_bytes());
        b[16..24].copy_from_slice(&self.last_resolved_block.to_be_bytes());
        b[24..32].copy_from_slice(&self.total_shots_fired.to_be_bytes());
        b
    }

    fn decode(b: &[u8; HDR_LEN]) -> Self {
        Self {
            active: b[0],
            player_count: b[1],
            red_count: b[2],
            blue_count: b[3],
            grid_w: b[4],
            grid_h: b[5],
            shell_count: u16::from_be_bytes([b[6], b[7]]),
            red_kills: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            blue_kills: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            last_resolved_block: u64::from_be_bytes(b[16..24].try_into().unwrap()),
            total_shots_fired: u64::from_be_bytes(b[24..32].try_into().unwrap()),
        }
    }
}

#[derive(Clone, Copy)]
struct PlayerRec {
    addr: [u8; 20],
    team: u8,
    kills: u16,
    pad: u8,
    credits: u64,
    score: u64,
}

const PLR_LEN: usize = 40;

impl PlayerRec {
    fn encode(&self) -> [u8; PLR_LEN] {
        let mut b = [0u8; PLR_LEN];
        b[0..20].copy_from_slice(&self.addr);
        b[20] = self.team;
        b[21..23].copy_from_slice(&self.kills.to_be_bytes());
        b[23] = self.pad;
        b[24..32].copy_from_slice(&self.credits.to_be_bytes());
        b[32..40].copy_from_slice(&self.score.to_be_bytes());
        b
    }

    fn decode(b: &[u8; PLR_LEN]) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&b[0..20]);
        Self {
            addr,
            team: b[20],
            kills: u16::from_be_bytes([b[21], b[22]]),
            pad: b[23],
            credits: u64::from_be_bytes(b[24..32].try_into().unwrap()),
            score: u64::from_be_bytes(b[32..40].try_into().unwrap()),
        }
    }
}

/// Fixed 32-byte ship record under `"n:shp:" || battleId || ship_global_idx(u16 BE)`.
#[derive(Clone, Copy)]
struct ShipRec {
    alive: u8,
    owner_pid: u8,
    team: u8,
    class_id: u8,
    gun_id: u8,
    armor_tier: u8, // Engine / Turbine tier (`0..=2`, `+0/+2/+4` squares max speed)
    dir: u8,        // 0 = Horizontal (L along X, W along Y), 1 = Vertical (L along Y, W along X)
    x: u8,
    y: u8,
    pad: u8,        // Stores last compass heading `dir8` (`0..=7`)
    cell_dmg: [u8; 10], // Binary: `0` = Intact, `100` = Destroyed (100% hit)!
    last_move_block: u32,
    last_fire_block: u32,
    flash_x: u8,
    flash_y: u8,
    pad2: [u8; 2],
}

const SHP_LEN: usize = 32;

impl ShipRec {
    fn empty() -> Self {
        Self {
            alive: 0,
            owner_pid: 0,
            team: 0,
            class_id: 0,
            gun_id: 0,
            armor_tier: 0,
            dir: 0,
            x: 0,
            y: 0,
            pad: 2,
            cell_dmg: [0; 10],
            last_move_block: 0,
            last_fire_block: 0,
            flash_x: 255,
            flash_y: 255,
            pad2: [0; 2],
        }
    }

    fn encode(&self) -> [u8; SHP_LEN] {
        let mut b = [0u8; SHP_LEN];
        b[0] = self.alive;
        b[1] = self.owner_pid;
        b[2] = self.team;
        b[3] = self.class_id;
        b[4] = self.gun_id;
        b[5] = self.armor_tier;
        b[6] = self.dir;
        b[7] = self.x;
        b[8] = self.y;
        b[9] = self.pad;
        b[10..20].copy_from_slice(&self.cell_dmg);
        b[20..24].copy_from_slice(&self.last_move_block.to_be_bytes());
        b[24..28].copy_from_slice(&self.last_fire_block.to_be_bytes());
        b[28] = self.flash_x;
        b[29] = self.flash_y;
        b[30..32].copy_from_slice(&self.pad2);
        b
    }

    fn decode(b: &[u8; SHP_LEN]) -> Self {
        let mut cd = [0u8; 10];
        cd.copy_from_slice(&b[10..20]);
        Self {
            alive: b[0],
            owner_pid: b[1],
            team: b[2],
            class_id: b[3],
            gun_id: b[4],
            armor_tier: b[5],
            dir: b[6],
            x: b[7],
            y: b[8],
            pad: b[9],
            cell_dmg: cd,
            last_move_block: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
            last_fire_block: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
            flash_x: b[28],
            flash_y: b[29],
            pad2: [b[30], b[31]],
        }
    }
}

#[derive(Clone, Copy)]
struct PendingShell {
    active: u8,
    attacker_pid: u8,
    attacker_team: u8,
    gun_id: u8,
    tx: u8,
    ty: u8,
    impact_block: u64,
}

const SHL_LEN: usize = 16;

impl PendingShell {
    fn encode(&self) -> [u8; SHL_LEN] {
        let mut b = [0u8; SHL_LEN];
        b[0] = self.active;
        b[1] = self.attacker_pid;
        b[2] = self.attacker_team;
        b[3] = self.gun_id;
        b[4] = self.tx;
        b[5] = self.ty;
        b[8..16].copy_from_slice(&self.impact_block.to_be_bytes());
        b
    }

    fn decode(b: &[u8; SHL_LEN]) -> Self {
        Self {
            active: b[0],
            attacker_pid: b[1],
            attacker_team: b[2],
            gun_id: b[3],
            tx: b[4],
            ty: b[5],
            impact_block: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Key Helpers
// ---------------------------------------------------------------------------

fn hdr_key(bid: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"n:hdr:").push(bid)
}

fn plr_key(bid: &[u8; 32], pid: u8) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"n:plr:").push(bid).push(&[pid])
}

fn addr_pid_key(bid: &[u8; 32], addr: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new().push(b"n:idx:").push(bid).push(addr)
}

fn ship_key(bid: &[u8; 32], gidx: u16) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"n:shp:")
        .push(bid)
        .push(&gidx.to_be_bytes())
}

fn shell_key(bid: &[u8; 32], idx: u16) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"n:shl:")
        .push(bid)
        .push(&idx.to_be_bytes())
}

fn load_hdr(bid: &[u8; 32]) -> Option<BattleHeader> {
    let k = hdr_key(bid);
    let mut b = [0u8; HDR_LEN];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(HDR_LEN) => Some(BattleHeader::decode(&b)),
        _ => None,
    }
}

fn save_hdr(bid: &[u8; 32], h: &BattleHeader) {
    storage::set(hdr_key(bid).as_slice(), &h.encode());
}

fn load_plr(bid: &[u8; 32], pid: u8) -> Option<PlayerRec> {
    let k = plr_key(bid, pid);
    let mut b = [0u8; PLR_LEN];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(PLR_LEN) => Some(PlayerRec::decode(&b)),
        _ => None,
    }
}

fn save_plr(bid: &[u8; 32], pid: u8, p: &PlayerRec) {
    storage::set(plr_key(bid, pid).as_slice(), &p.encode());
}

fn find_pid(bid: &[u8; 32], addr: &[u8; 20]) -> Option<u8> {
    let k = addr_pid_key(bid, addr);
    let mut b = [0u8; 1];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(1) => Some(b[0]),
        _ => None,
    }
}

fn load_ship(bid: &[u8; 32], gidx: u16) -> ShipRec {
    let k = ship_key(bid, gidx);
    let mut b = [0u8; SHP_LEN];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(SHP_LEN) => ShipRec::decode(&b),
        _ => ShipRec::empty(),
    }
}

fn save_ship(bid: &[u8; 32], gidx: u16, s: &ShipRec) {
    storage::set(ship_key(bid, gidx).as_slice(), &s.encode());
}

fn load_shell(bid: &[u8; 32], idx: u16) -> Option<PendingShell> {
    let k = shell_key(bid, idx);
    let mut b = [0u8; SHL_LEN];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(SHL_LEN) => Some(PendingShell::decode(&b)),
        _ => None,
    }
}

fn save_shell(bid: &[u8; 32], idx: u16, sh: &PendingShell) {
    storage::set(shell_key(bid, idx).as_slice(), &sh.encode());
}

// ---------------------------------------------------------------------------
// Dynamic Grid Math, Geometry, & Instant 100% Square Hit Resolution
// ---------------------------------------------------------------------------

pub fn compute_dynamic_grid_dims(player_count: u8) -> (u8, u8) {
    if player_count <= 4 {
        return (BASE_GRID_W, BASE_GRID_H);
    }
    let extra = (player_count as u32).saturating_sub(4);
    let target_tiles = 1000u32 + 220u32 * extra;
    let mut h = BASE_GRID_H as u32;
    let mut w = BASE_GRID_W as u32;
    while w * h < target_tiles && h < (MAX_GRID_H as u32) {
        h += 1;
        w = ((h * 8 + 4) / 5).min(MAX_GRID_W as u32);
    }
    (w as u8, h as u8)
}

fn ship_dims(class_id: u8, dir: u8) -> (u8, u8) {
    let l = CLASS_LEN[class_id as usize];
    let w = CLASS_WID[class_id as usize];
    if dir == 0 {
        (l, w)
    } else {
        (w, l)
    }
}

fn effective_max_speed(ship: &ShipRec) -> u8 {
    let base = CLASS_MAX_SPEED[(ship.class_id as usize).min(CLASS_COUNT - 1)];
    let bonus = ENGINE_SPEED_BONUS[(ship.armor_tier as usize).min(2)];
    base.saturating_add(bonus)
}

fn cell_index_on_ship(ship: &ShipRec, cx: u8, cy: u8) -> Option<usize> {
    if ship.alive == 0 {
        return None;
    }
    let l = CLASS_LEN[ship.class_id as usize];
    let w = CLASS_WID[ship.class_id as usize];
    let (dx_max, dy_max) = if ship.dir == 0 { (l, w) } else { (w, l) };
    if cx < ship.x || cy < ship.y {
        return None;
    }
    let rx = cx - ship.x;
    let ry = cy - ship.y;
    if rx >= dx_max || ry >= dy_max {
        return None;
    }
    let idx = if ship.dir == 0 {
        (ry as usize) * (l as usize) + (rx as usize)
    } else {
        (rx as usize) * (l as usize) + (ry as usize)
    };
    Some(idx)
}

fn ships_overlap(a: &ShipRec, b: &ShipRec) -> bool {
    let (aw, ah) = ship_dims(a.class_id, a.dir);
    let (bw, bh) = ship_dims(b.class_id, b.dir);
    let a_right = a.x.saturating_add(aw);
    let a_bot = a.y.saturating_add(ah);
    let b_right = b.x.saturating_add(bw);
    let b_bot = b.y.saturating_add(bh);
    !(a_right <= b.x || b_right <= a.x || a_bot <= b.y || b_bot <= a.y)
}

fn check_ship_placement_free(
    bid: &[u8; 32],
    player_count: u8,
    grid_w: u8,
    grid_h: u8,
    ignore_gidx: u16,
    cand: &ShipRec,
) -> bool {
    let (w, h) = ship_dims(cand.class_id, cand.dir);
    if (cand.x as u16) + (w as u16) > (grid_w as u16)
        || (cand.y as u16) + (h as u16) > (grid_h as u16)
    {
        return false;
    }
    let total_slots = (player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut g = 0u16;
    while g < total_slots {
        if g != ignore_gidx {
            let other = load_ship(bid, g);
            if other.alive != 0 && ships_overlap(cand, &other) {
                return false;
            }
        }
        g += 1;
    }
    true
}

/// Every hit on an intact ship square deals instant `100%` square destruction (`cell_dmg = 100`),
/// awarding `CREDITS_PER_CELL_HIT` (`+120 CR`) + `CLASS_BOUNTY` when all hull squares are hit!
fn detonate_salvo_at(
    bid: &[u8; 32],
    hdr: &mut BattleHeader,
    attacker_pid: u8,
    attacker_team: u8,
    gun_id: u8,
    tx: u8,
    ty: u8,
) {
    let g = gun_id as usize;
    let pattern = GUN_PATTERN[g];

    let mut cells = [(0u8, 0u8); 5];
    let mut cell_n = 0usize;

    let gw = hdr.grid_w as i16;
    let gh = hdr.grid_h as i16;
    let mut push_cell = |cx: i16, cy: i16| {
        if cx >= 0 && cy >= 0 && cx < gw && cy < gh && cell_n < 5 {
            cells[cell_n] = (cx as u8, cy as u8);
            cell_n += 1;
        }
    };

    if pattern == 0 {
        push_cell(tx as i16, ty as i16);
    } else if pattern == 1 {
        push_cell(tx as i16, ty as i16);
        push_cell(tx as i16 + 1, ty as i16);
        push_cell(tx as i16, ty as i16 + 1);
        push_cell(tx as i16 + 1, ty as i16 + 1);
    } else {
        push_cell(tx as i16, ty as i16);
        push_cell(tx as i16 + 1, ty as i16);
        push_cell(tx as i16 - 1, ty as i16);
        push_cell(tx as i16, ty as i16 + 1);
        push_cell(tx as i16, ty as i16 - 1);
    }

    let mut credits_earned = 0u64;
    let mut kills_scored = 0u16;

    let total_ships = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut s_idx = 0u16;
    while s_idx < total_ships {
        let mut ship = load_ship(bid, s_idx);
        if ship.alive != 0 && ship.team != attacker_team {
            let mut touched = false;
            let mut c = 0usize;
            while c < cell_n {
                let (ix, iy) = cells[c];
                if let Some(h_idx) = cell_index_on_ship(&ship, ix, iy) {
                    if ship.cell_dmg[h_idx] < 100 {
                        ship.cell_dmg[h_idx] = 100; // 100% square hit!
                        credits_earned += CREDITS_PER_CELL_HIT;
                        touched = true;
                    }
                }
                c += 1;
            }

            if touched {
                let n_cells = CLASS_CELLS[ship.class_id as usize] as usize;
                let mut breached = 0u8;
                let mut k = 0usize;
                while k < n_cells {
                    if ship.cell_dmg[k] >= 100 {
                        breached += 1;
                    }
                    k += 1;
                }
                if breached >= CLASS_SINK_CELLS[ship.class_id as usize] {
                    ship.alive = 0;
                    let bounty = CLASS_BOUNTY[ship.class_id as usize];
                    credits_earned += bounty;
                    kills_scored += 1;
                    if attacker_team == TEAM_RED {
                        hdr.red_kills += 1;
                    } else {
                        hdr.blue_kills += 1;
                    }

                    let mut sev = [0u8; 24];
                    sev[0..8].copy_from_slice(&(s_idx as u64).to_be_bytes());
                    sev[8..16].copy_from_slice(&(attacker_pid as u64).to_be_bytes());
                    sev[16..24].copy_from_slice(&bounty.to_be_bytes());
                    events::emit(&[EV_SHIP_SUNK, *bid], &sev);
                }
                save_ship(bid, s_idx, &ship);
            }
        }
        s_idx += 1;
    }

    if credits_earned > 0 || kills_scored > 0 {
        if let Some(mut att) = load_plr(bid, attacker_pid) {
            att.credits = att.credits.saturating_add(credits_earned);
            att.score = att.score.saturating_add(credits_earned);
            att.kills = att.kills.saturating_add(kills_scored);
            save_plr(bid, attacker_pid, &att);
        }
    }
}

fn sync_pending_shells(bid: &[u8; 32], hdr: &mut BattleHeader) {
    let blk = context::block_number();
    if blk <= hdr.last_resolved_block {
        return;
    }
    let count = (hdr.shell_count as usize).min(MAX_INFLIGHT_SHELLS);
    let mut write_idx = 0u16;
    let mut i = 0usize;
    while i < count {
        if let Some(sh) = load_shell(bid, i as u16) {
            if sh.active != 0 {
                if blk >= sh.impact_block {
                    detonate_salvo_at(
                        bid,
                        hdr,
                        sh.attacker_pid,
                        sh.attacker_team,
                        sh.gun_id,
                        sh.tx,
                        sh.ty,
                    );
                } else {
                    if write_idx != (i as u16) {
                        save_shell(bid, write_idx, &sh);
                    }
                    write_idx += 1;
                }
            }
        }
        i += 1;
    }
    hdr.shell_count = write_idx;
    hdr.last_resolved_block = blk;
}

// ---------------------------------------------------------------------------
// ABI Handlers
// ---------------------------------------------------------------------------

fn handle_create_battle(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    if load_hdr(&bid).is_some() {
        return Err(-11);
    }

    let blk = context::block_number();
    let hdr = BattleHeader {
        active: 1,
        player_count: 0,
        red_count: 0,
        blue_count: 0,
        grid_w: BASE_GRID_W,
        grid_h: BASE_GRID_H,
        shell_count: 0,
        red_kills: 0,
        blue_kills: 0,
        last_resolved_block: blk,
        total_shots_fired: 0,
    };
    save_hdr(&bid, &hdr);
    events::emit(&[EV_BATTLE_CREATED, bid], &(BASE_GRID_W as u64).to_be_bytes());
    Ok(())
}

fn join_player_internal(
    bid: &[u8; 32],
    hdr: &mut BattleHeader,
    caller: [u8; 20],
    preferred_team: u64,
) -> Result<(u8, u8), i32> {
    if preferred_team > 1 {
        return Err(-12);
    }
    if caller == [0u8; 20] {
        return Err(-15);
    }
    if let Some(existing_pid) = find_pid(bid, &caller) {
        let plr = load_plr(bid, existing_pid).ok_or(-15)?;
        return Ok((existing_pid, plr.team));
    }
    if (hdr.player_count as u64) >= MAX_PLAYERS {
        return Err(-14);
    }

    let assigned_team = if hdr.red_count > hdr.blue_count {
        TEAM_BLUE
    } else if hdr.blue_count > hdr.red_count {
        TEAM_RED
    } else {
        preferred_team as u8
    };

    let pid = hdr.player_count;
    hdr.player_count += 1;
    if assigned_team == TEAM_RED {
        hdr.red_count += 1;
    } else {
        hdr.blue_count += 1;
    }

    let (new_w, new_h) = compute_dynamic_grid_dims(hdr.player_count);
    if new_w > hdr.grid_w || new_h > hdr.grid_h {
        let dx = (new_w.saturating_sub(hdr.grid_w)) / 2;
        let dy = (new_h.saturating_sub(hdr.grid_h)) / 2;
        if dx > 0 || dy > 0 {
            let existing_ships = (pid as u16) * 3;
            let mut s = 0u16;
            while s < existing_ships {
                let mut sh = load_ship(bid, s);
                if sh.alive != 0 {
                    sh.x = sh.x.saturating_add(dx);
                    sh.y = sh.y.saturating_add(dy);
                    if sh.flash_x < 250 {
                        sh.flash_x = sh.flash_x.saturating_add(dx);
                        sh.flash_y = sh.flash_y.saturating_add(dy);
                    }
                    save_ship(bid, s, &sh);
                }
                s += 1;
            }
            let sc = (hdr.shell_count as usize).min(MAX_INFLIGHT_SHELLS);
            let mut q = 0usize;
            while q < sc {
                if let Some(mut shl) = load_shell(bid, q as u16) {
                    if shl.active != 0 {
                        shl.tx = shl.tx.saturating_add(dx);
                        shl.ty = shl.ty.saturating_add(dy);
                        save_shell(bid, q as u16, &shl);
                    }
                }
                q += 1;
            }
        }
        hdr.grid_w = new_w;
        hdr.grid_h = new_h;
    }

    let rec = PlayerRec {
        addr: caller,
        team: assigned_team,
        kills: 0,
        pad: 0,
        credits: STARTING_CREDITS,
        score: 0,
    };
    save_plr(bid, pid, &rec);
    storage::set(addr_pid_key(bid, &caller).as_slice(), &[pid]);

    let mut ev = [0u8; 44];
    ev[0..20].copy_from_slice(&caller);
    ev[20..28].copy_from_slice(&(pid as u64).to_be_bytes());
    ev[28..36].copy_from_slice(&(assigned_team as u64).to_be_bytes());
    ev[36..44].copy_from_slice(&(((hdr.grid_w as u64) << 8) | (hdr.grid_h as u64)).to_be_bytes());
    events::emit(&[EV_PLAYER_JOINED, *bid], &ev);

    Ok((pid, assigned_team))
}

fn handle_join_battle(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let preferred_team = args.u64(1).ok_or(-10)?;
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    if find_pid(&bid, &caller).is_some() {
        return Err(-15);
    }
    let (_pid, assigned_team) = join_player_internal(&bid, &mut hdr, caller, preferred_team)?;
    save_hdr(&bid, &hdr);

    ret::write_u64_word(assigned_team as u64);
    Ok(assigned_team as i32)
}

/// 1-Block Atomic Onboarding: joins battle (if not already joined) and auto-spawns up to 3 starter
/// ships (`s0, s1, s2`, pass `255` for empty slot) in unobstructed team-side coordinates!
fn handle_join_and_deploy(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let preferred_team = args.u64(1).ok_or(-10)?;
    let s0 = args.u64(2).ok_or(-10)?;
    let s1 = args.u64(3).ok_or(-10)?;
    let s2 = args.u64(4).ok_or(-10)?;

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let (pid, team) = join_player_internal(&bid, &mut hdr, caller, preferred_team)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;

    let classes = [s0, s1, s2];
    let half = hdr.grid_w / 2;
    let mut slot = 0usize;
    while slot < 3 {
        let cid = classes[slot];
        if cid < (CLASS_COUNT as u64) {
            let gidx = (pid as u16) * 3 + (slot as u16);
            let existing = load_ship(&bid, gidx);
            let cost = CLASS_COST[cid as usize];
            if existing.alive == 0 && plr.credits >= cost {
                let l = CLASS_LEN[cid as usize];
                let w = CLASS_WID[cid as usize];
                let (x_start, x_end) = if team == TEAM_RED {
                    (2u8, half.saturating_sub(l + 1))
                } else {
                    (half + 2, hdr.grid_w.saturating_sub(l + 1))
                };

                let mut placed = false;
                let y_seed = ((pid as u16 * 5 + slot as u16 * 4 + 2) % (hdr.grid_h.saturating_sub(w + 2).max(1) as u16)) as u8 + 1;
                let mut dy_off = 0u8;
                while dy_off < hdr.grid_h && !placed {
                    let y = 1 + ((y_seed + dy_off) % hdr.grid_h.saturating_sub(w + 1).max(1));
                    let mut x = x_start;
                    while x <= x_end {
                        let cand = ShipRec {
                            alive: 1,
                            owner_pid: pid,
                            team,
                            class_id: cid as u8,
                            gun_id: 0,
                            armor_tier: 0,
                            dir: 0,
                            x,
                            y,
                            pad: if team == TEAM_RED { 2 } else { 6 },
                            cell_dmg: [0; 10],
                            last_move_block: 0,
                            last_fire_block: 0,
                            flash_x: 255,
                            flash_y: 255,
                            pad2: [0; 2],
                        };
                        if check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand) {
                            plr.credits -= cost;
                            save_ship(&bid, gidx, &cand);
                            let mut ev = [0u8; 40];
                            ev[0..8].copy_from_slice(&(gidx as u64).to_be_bytes());
                            ev[8..16].copy_from_slice(&(team as u64).to_be_bytes());
                            ev[16..24].copy_from_slice(&cid.to_be_bytes());
                            ev[24..32].copy_from_slice(&(x as u64).to_be_bytes());
                            ev[32..40].copy_from_slice(&(y as u64).to_be_bytes());
                            events::emit(&[EV_SHIP_COMMISSIONED, bid], &ev);
                            placed = true;
                            break;
                        }
                        x += 2;
                    }
                    dy_off += 2;
                }
            }
        }
        slot += 1;
    }

    save_plr(&bid, pid, &plr);
    save_hdr(&bid, &hdr);
    ret::write_u64_word(team as u64);
    Ok(team as i32)
}

fn handle_buy_ship(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let class_id = args.u64(2).ok_or(-10)?;
    let x = args.u64(3).ok_or(-10)?;
    let y = args.u64(4).ok_or(-10)?;
    let dir = args.u64(5).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER || class_id >= (CLASS_COUNT as u64) || dir > 1 {
        return Err(-20);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;

    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let existing = load_ship(&bid, gidx);
    if existing.alive != 0 {
        return Err(-22);
    }

    if class_id == 0 && plr.credits < EMERGENCY_GUNBOAT_FLOOR {
        let s0 = load_ship(&bid, (pid as u16) * 3).alive;
        let s1 = load_ship(&bid, (pid as u16) * 3 + 1).alive;
        let s2 = load_ship(&bid, (pid as u16) * 3 + 2).alive;
        if s0 == 0 && s1 == 0 && s2 == 0 {
            plr.credits = EMERGENCY_GUNBOAT_FLOOR;
        }
    }

    let cost = CLASS_COST[class_id as usize];
    if plr.credits < cost {
        return Err(-23);
    }

    if x >= (hdr.grid_w as u64) || y >= (hdr.grid_h as u64) {
        return Err(-24);
    }

    let half = hdr.grid_w / 2;
    if plr.team == TEAM_RED && (x as u8) >= half {
        return Err(-25);
    }
    if plr.team == TEAM_BLUE && (x as u8) < half {
        return Err(-25);
    }

    let cand = ShipRec {
        alive: 1,
        owner_pid: pid,
        team: plr.team,
        class_id: class_id as u8,
        gun_id: 0,
        armor_tier: 0,
        dir: dir as u8,
        x: x as u8,
        y: y as u8,
        pad: if plr.team == TEAM_RED { 2 } else { 6 },
        cell_dmg: [0; 10],
        last_move_block: 0,
        last_fire_block: 0,
        flash_x: 255,
        flash_y: 255,
        pad2: [0; 2],
    };

    if !check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand) {
        return Err(-26);
    }

    plr.credits -= cost;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &cand);
    save_hdr(&bid, &hdr);

    let mut ev = [0u8; 40];
    ev[0..8].copy_from_slice(&(gidx as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&(plr.team as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&class_id.to_be_bytes());
    ev[24..32].copy_from_slice(&x.to_be_bytes());
    ev[32..40].copy_from_slice(&y.to_be_bytes());
    events::emit(&[EV_SHIP_COMMISSIONED, bid], &ev);
    Ok(())
}

/// 8-Compass-Direction (`dir8`: `0..=7` = N, NE, E, SE, S, SW, W, NW) + Percentage Throttle
/// (`speed_pct`: `25`, `50`, `75`, or `100`) navigation!
/// Calculates the destination coordinates on-chain inside the HFS and emits `ShipMoved` so the
/// client teleports the ship straight to `(final_x, final_y)` from the receipt log!
fn handle_move_ship(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let dir8 = args.u64(2).ok_or(-10)?;
    let speed_pct = args.u64(3).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER || dir8 > 7 {
        return Err(-30);
    }
    if speed_pct != 25 && speed_pct != 50 && speed_pct != 75 && speed_pct != 100 {
        return Err(-34);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);
    if ship.alive == 0 {
        return Err(-31);
    }

    let blk = context::block_number() as u32;
    if ship.last_move_block == blk {
        return Err(-32);
    }

    let max_spd = effective_max_speed(&ship);
    let target_steps = (((max_spd as u32) * (speed_pct as u32) + 50) / 100).max(1) as i16;

    let dx = DIR8_DX[dir8 as usize];
    let dy = DIR8_DY[dir8 as usize];
    let from_x = ship.x;
    let from_y = ship.y;

    // Align hull orientation (`0` = E/W horizontal, `1` = N/S vertical) for pure cardinal headings if free
    let preferred_hull_dir = if dir8 == 0 || dir8 == 4 {
        1u8
    } else if dir8 == 2 || dir8 == 6 {
        0u8
    } else {
        ship.dir
    };

    let mut best_x = from_x;
    let mut best_y = from_y;
    let mut best_dir = ship.dir;
    let mut actual_steps = 0u64;

    let mut step = 1i16;
    while step <= target_steps {
        let nx = (from_x as i16) + dx * step;
        let ny = (from_y as i16) + dy * step;
        if nx < 0 || ny < 0 || nx >= (hdr.grid_w as i16) || ny >= (hdr.grid_h as i16) {
            break;
        }
        let mut cand = ship;
        cand.x = nx as u8;
        cand.y = ny as u8;
        cand.dir = preferred_hull_dir;
        if check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand) {
            best_x = nx as u8;
            best_y = ny as u8;
            best_dir = preferred_hull_dir;
            actual_steps = step as u64;
        } else if preferred_hull_dir != ship.dir {
            cand.dir = ship.dir;
            if check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand)
            {
                best_x = nx as u8;
                best_y = ny as u8;
                best_dir = ship.dir;
                actual_steps = step as u64;
            } else {
                break;
            }
        } else {
            break;
        }
        step += 1;
    }

    if actual_steps == 0 {
        return Err(-35); // blocked immediately in chosen heading!
    }

    ship.x = best_x;
    ship.y = best_y;
    ship.dir = best_dir;
    ship.pad = dir8 as u8;
    ship.last_move_block = blk;

    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);

    // Emit 8-word (64-byte) `ShipMoved` payload so UI teleports directly from the HFS event log!
    let mut ev = [0u8; 64];
    ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
    ev[8..16].copy_from_slice(&(from_x as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&(from_y as u64).to_be_bytes());
    ev[24..32].copy_from_slice(&(best_x as u64).to_be_bytes());
    ev[32..40].copy_from_slice(&(best_y as u64).to_be_bytes());
    ev[40..48].copy_from_slice(&(best_dir as u64).to_be_bytes());
    ev[48..56].copy_from_slice(&dir8.to_be_bytes());
    ev[56..64].copy_from_slice(&actual_steps.to_be_bytes());
    events::emit(&[EV_SHIP_MOVED, bid, addr_topic(&caller)], &ev);

    let packed = ((best_x as u64) << 8) | (best_y as u64);
    ret::write_u64_word(packed);
    Ok(packed as i32)
}

fn handle_fire_weapon(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let tx = args.u64(2).ok_or(-10)?;
    let ty = args.u64(3).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-40);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    if tx >= (hdr.grid_w as u64) || ty >= (hdr.grid_h as u64) {
        return Err(-41);
    }

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);
    if ship.alive == 0 {
        return Err(-42);
    }

    let blk = context::block_number();
    let blk32 = blk as u32;
    if ship.last_fire_block == blk32 {
        return Err(-43);
    }

    let (w, h) = ship_dims(ship.class_id, ship.dir);
    let cx = (ship.x as i32) + ((w as i32) / 2);
    let cy = (ship.y as i32) + ((h as i32) / 2);
    let dx = (tx as i32) - cx;
    let dy = (ty as i32) - cy;
    let rng = GUN_RANGE[ship.gun_id as usize] as i32;
    if dx * dx + dy * dy > rng * rng {
        return Err(-44);
    }

    ship.last_fire_block = blk32;
    ship.flash_x = cx as u8;
    ship.flash_y = cy as u8;
    save_ship(&bid, gidx, &ship);

    let delay = GUN_FLIGHT_BLOCKS[ship.gun_id as usize];
    if delay == 0 {
        detonate_salvo_at(&bid, &mut hdr, pid, ship.team, ship.gun_id, tx as u8, ty as u8);
    } else if (hdr.shell_count as usize) < MAX_INFLIGHT_SHELLS {
        let shl = PendingShell {
            active: 1,
            attacker_pid: pid,
            attacker_team: ship.team,
            gun_id: ship.gun_id,
            tx: tx as u8,
            ty: ty as u8,
            impact_block: blk.saturating_add(delay as u64),
        };
        save_shell(&bid, hdr.shell_count, &shl);
        hdr.shell_count += 1;
    }

    hdr.total_shots_fired += 1;
    save_hdr(&bid, &hdr);

    let mut ev = [0u8; 40];
    ev[0..8].copy_from_slice(&(gidx as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&(ship.gun_id as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&tx.to_be_bytes());
    ev[24..32].copy_from_slice(&ty.to_be_bytes());
    ev[32..40].copy_from_slice(&(delay as u64).to_be_bytes());
    events::emit(&[EV_WEAPON_FIRED, bid], &ev);
    Ok(())
}

fn handle_upgrade_gun(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let gun_id = args.u64(2).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER || gun_id >= (GUN_COUNT as u64) {
        return Err(-50);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);

    if ship.alive == 0 {
        return Err(-51);
    }
    if ship.gun_id == (gun_id as u8) {
        return Err(-52);
    }
    if ship.class_id < GUN_MIN_CLASS[gun_id as usize] {
        return Err(-53);
    }

    let cost = GUN_COST[gun_id as usize];
    if plr.credits < cost {
        return Err(-54);
    }

    plr.credits -= cost;
    ship.gun_id = gun_id as u8;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);
    Ok(())
}

fn handle_upgrade_engine(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-60);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);

    if ship.alive == 0 || ship.armor_tier >= ENGINE_MAX_TIER {
        return Err(-61);
    }

    let cost = ENGINE_UPGRADE_COST[ship.armor_tier as usize];
    if plr.credits < cost {
        return Err(-62);
    }

    plr.credits -= cost;
    ship.armor_tier += 1;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);
    Ok(())
}

/// Repairs destroyed hull squares (`100` -> `0`) at `100 CR` per square restored!
fn handle_repair_ship(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-70);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);

    if ship.alive == 0 || plr.credits < REPAIR_COST_PER_CELL {
        return Err(-71);
    }

    let blk32 = context::block_number() as u32;
    if ship.last_move_block == blk32 || ship.last_fire_block == blk32 {
        return Err(-72);
    }

    let n_cells = CLASS_CELLS[ship.class_id as usize] as usize;
    let mut cells_repaired = 0u64;
    let mut i = 0usize;
    while i < n_cells && plr.credits >= REPAIR_COST_PER_CELL {
        if ship.cell_dmg[i] >= 100 {
            ship.cell_dmg[i] = 0;
            plr.credits -= REPAIR_COST_PER_CELL;
            cells_repaired += 1;
        }
        i += 1;
    }

    if cells_repaired == 0 {
        return Err(-73);
    }

    ship.last_move_block = blk32;
    ship.last_fire_block = blk32;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);

    ret::write_u64_word(cells_repaired);
    Ok(cells_repaired as i32)
}

fn handle_resolve_shells(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);
    save_hdr(&bid, &hdr);
    Ok(())
}

// ---------------------------------------------------------------------------
// Zero-Middleware Local-Node Views (`getBattleState` & `getPlayersSlice`)
// ---------------------------------------------------------------------------

fn handle_get_battle_state(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let Some(hdr) = load_hdr(&bid) else {
        ret::write(&[]);
        return Ok(0);
    };

    let mut out = [0u8; 36 + MAX_SHIPS * 34 + MAX_INFLIGHT_SHELLS * 16];
    out[0..32].copy_from_slice(&hdr.encode());

    let mut pos = 36usize;
    let mut alive_n = 0u16;
    let total_slots = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut g = 0u16;
    while g < total_slots {
        let sh = load_ship(&bid, g);
        if sh.alive != 0 {
            out[pos..pos + 2].copy_from_slice(&g.to_be_bytes());
            out[pos + 2..pos + 34].copy_from_slice(&sh.encode());
            pos += 34;
            alive_n += 1;
        }
        g += 1;
    }

    let sc = (hdr.shell_count as usize).min(MAX_INFLIGHT_SHELLS);
    let mut active_shl = 0u16;
    let mut q = 0usize;
    while q < sc {
        if let Some(shl) = load_shell(&bid, q as u16) {
            if shl.active != 0 {
                out[pos..pos + 16].copy_from_slice(&shl.encode());
                pos += 16;
                active_shl += 1;
            }
        }
        q += 1;
    }

    out[32..34].copy_from_slice(&alive_n.to_be_bytes());
    out[34..36].copy_from_slice(&active_shl.to_be_bytes());

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

fn handle_get_players_slice(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let offset = args.u64(1).ok_or(-10)?;
    let limit = args.u64(2).ok_or(-10)?.min(MAX_PLAYERS);

    let Some(hdr) = load_hdr(&bid) else {
        ret::write(&[]);
        return Ok(0);
    };

    let total = hdr.player_count as u64;
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let count = end - start;

    let mut out = [0u8; 8 + (MAX_PLAYERS as usize) * PLR_LEN];
    out[0..8].copy_from_slice(&count.to_be_bytes());
    let mut pos = 8usize;

    let mut p = start;
    while p < end {
        if let Some(rec) = load_plr(&bid, p as u8) {
            out[pos..pos + PLR_LEN].copy_from_slice(&rec.encode());
            pos += PLR_LEN;
        }
        p += 1;
    }

    ret::write(&out[..pos]);
    Ok(count as i32)
}

// ---------------------------------------------------------------------------
// Native Unit Tests (`cargo test -p battleship`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const CONTRACT: [u8; 20] = [0xB6; 20];

    #[test]
    fn hundred_player_team_autobalance_and_dynamic_grid_expansion() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(500);

        let bid = [0x11; 32];
        let host = [0x01; 20];
        mock::transact_as(
            host,
            CONTRACT,
            CallEncoder::<128>::new(selector("createBattle(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();

        for i in 0u8..20u8 {
            let mut addr = [0u8; 20];
            addr[0] = 0x10;
            addr[19] = i + 1;
            mock::transact_as(
                addr,
                CONTRACT,
                CallEncoder::<128>::new(selector("joinBattle(bytes32,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .as_slice(),
            )
            .unwrap();
        }

        let st = mock::transact_as(
            host,
            CONTRACT,
            CallEncoder::<128>::new(selector("getBattleState(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();

        assert_eq!(st[1], 20);
        assert_eq!(st[2], 10);
        assert_eq!(st[3], 10);
        assert!(st[4] > st[5] && st[4] >= 80);
        assert_eq!(compute_dynamic_grid_dims(100), (189, 118));
    }

    #[test]
    fn speed_throttle_8_directions_ship_moved_log_and_100pct_hits() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(600);

        let bid = [0x22; 32];
        let red_p = [0xA1; 20];
        let blue_p = [0xB2; 20];

        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("createBattle(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();

        // Red joins & deploys Cruiser (class 2, 4x1, max speed 6) + Gunboat (class 0, 2x1, max speed 12)
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("joinBattle(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("joinBattle(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();

        // Red places Gunboat (Max Speed = 12) at (3, 18)
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(0) // Gunboat (speed 12)
                .push_u64(3)
                .push_u64(18)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Move Gunboat NE (`dir8 = 1`, dx=+1, dy=-1) at `50%` throttle (`6` squares) -> `(9, 12)`!
        mock::set_block_number(601);
        let mv_out = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)  // slot 0
                .push_u64(1)  // NE
                .push_u64(50) // 50% of 12 = 6 squares
                .as_slice(),
        )
        .unwrap();
        let packed = u64::from_be_bytes(mv_out[24..32].try_into().unwrap());
        assert_eq!(packed >> 8, 9);
        assert_eq!(packed & 0xff, 12);

        // Blue places Cruiser (4x1, 4 cells) at (20, 12)
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2)
                .push_u64(20)
                .push_u64(12)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Red moves Gunboat E (`dir8 = 2`) at `25%` (`3` squares -> `(12, 12)`) and fires Autocannon (`range 10`) at `(20, 12)`!
        mock::set_block_number(602);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2)  // E
                .push_u64(25) // 25% of 12 = 3 squares -> (12, 12)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(20)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();

        // Verify cell 0 of Blue's Cruiser is immediately 100% destroyed (`cell_dmg[0] == 100`)!
        let st = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("getBattleState(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();
        // Second alive ship starts at 36 + 34 = 70; ship record starts at 72; cell_dmg[0] is at 72 + 10 = 82
        assert_eq!(st[82], 100);
    }
}
