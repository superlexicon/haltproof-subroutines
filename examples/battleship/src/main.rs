//! # Phantom Fleet: 100-Player Red vs. Blue Naval Warfare & Economy (`battleship` — HPS #13)
//!
//! Designed specifically for SuperLexicon's **public, `$0.00`-gas, `~4.3s`-block ledger**:
//! 1. **Up to 100 Captains (`50 Red vs. 50 Blue`)** with strict on-chain team balancing
//!    (`|red_count - blue_count| <= 1`) and **`1,000 Credits (CR)`** starting bankroll.
//! 2. **Dynamic High-Resolution Ocean Grid (`32x32` -> `149x149`)**:
//!    Automatically expands outward symmetrically as more captains join so crowded seas open up
//!    without disrupting ongoing ship coordinates or in-flight shells.
//! 3. **4 Multi-Cell Warship Classes (`up to 3 active ships per player = 300 ships max`)**:
//!    - `0` Gunboat (`2x1`, `2` cells, `200 CR`, Speed `3`, Max Mount `S`, Base Armor `10%`)
//!    - `1` Frigate (`3x1`, `3` cells, `350 CR`, Speed `2`, Max Mount `M`, Base Armor `20%`)
//!    - `2` Heavy Cruiser (`4x1`, `4` cells, `550 CR`, Speed `2`, Max Mount `L`, Base Armor `30%`)
//!    - `3` Dreadnought (`5x2`, `10` cells, `1100 CR`, Speed `1`, Max Mount `XL`, Base Armor `45%`)
//! 4. **5 Upgradable Weapons (Gated by Credits AND Hull Mount Size)**:
//!    - `0` Deck Autocannon (`S`, `0 CR`, Range `9`, `1x1`, `38%` dmg, `0`-blk instant)
//!    - `1` Twin Flak Mortar (`S`, `250 CR`, Range `8`, `2x2` area, `28%` dmg, `0`-blk instant)
//!    - `2` Cluster Rocket Pod (`M`, `450 CR`, Range `13`, `+` 5-cell cross, `36%/22%` dmg, `1`-blk ToF)
//!    - `3` Broadside Howitzer (`L`, `700 CR`, Range `16`, `2x2` area, `54%` dmg, `1`-blk ToF)
//!    - `4` Siege Railgun (`XL`, `1100 CR`, Range `30`, `1x1` AP, `92%` dmg, pierces 1/2 armor, `1`-blk ToF)
//! 5. **Per-Cell `0%–100%` Structural Damage, Armor Plating, Combat Credits & Paid Repairs**:
//!    - Earn `+2 CR` per `1%` hull damage inflicted + `40%` hull-cost Kill Bounties.
//!    - Spend Credits to buy replacement ships, upgrade guns/armor (`+15%` / `+30%`), or pay
//!      `1 CR` per `1%` cell damage restored (`repairShip`, up to `40%` per cell while cutting engines).

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

pub const TEAM_RED: u8 = 0;
pub const TEAM_BLUE: u8 = 1;

pub const BASE_GRID_W: u8 = 40;
pub const BASE_GRID_H: u8 = 25;
pub const MAX_GRID_W: u8 = 200;
pub const MAX_GRID_H: u8 = 125;

/// Ship classes (`0..=3`).
pub const CLASS_COUNT: usize = 4;
pub const CLASS_LEN: [u8; 4] = [2, 3, 4, 5];
pub const CLASS_WID: [u8; 4] = [1, 1, 1, 2];
pub const CLASS_CELLS: [u8; 4] = [2, 3, 4, 10];
pub const CLASS_COST: [u64; 4] = [200, 350, 550, 1100];
pub const CLASS_BOUNTY: [u64; 4] = [80, 140, 220, 440];
pub const CLASS_SPEED: [u8; 4] = [3, 2, 2, 1];
pub const CLASS_BASE_ARMOR: [u8; 4] = [10, 20, 30, 45];
pub const CLASS_SINK_CELLS: [u8; 4] = [2, 3, 3, 8]; // >= 75% cells at 100% damage sinks ship

/// Weapon systems (`0..=4`).
pub const GUN_COUNT: usize = 5;
pub const GUN_MIN_CLASS: [u8; 5] = [0, 0, 1, 2, 3]; // S=0, M=1, L=2, XL=3
pub const GUN_COST: [u64; 5] = [0, 250, 450, 700, 1100];
pub const GUN_RANGE: [u16; 5] = [9, 8, 13, 16, 30];
pub const GUN_PRIMARY_DMG: [u8; 5] = [38, 28, 36, 54, 92];
pub const GUN_SPLASH_DMG: [u8; 5] = [0, 28, 22, 54, 0];
pub const GUN_PATTERN: [u8; 5] = [0, 1, 2, 1, 0]; // 0 = 1x1, 1 = 2x2, 2 = '+' 5-cell cross
pub const GUN_FLIGHT_BLOCKS: [u8; 5] = [0, 0, 1, 1, 1];

/// Armor upgrade tiers (`0..=2`).
pub const ARMOR_MAX_TIER: u8 = 2;
pub const ARMOR_UPGRADE_COST: [u64; 2] = [200, 450]; // 0->1 costs 200, 1->2 costs 450
pub const ARMOR_BONUS: [u8; 3] = [0, 15, 30];

// ---------------------------------------------------------------------------
// Indexed Events
// ---------------------------------------------------------------------------

const EV_BATTLE_CREATED: [u8; 32] = event_topic("BattleCreated(bytes32,uint64)");
const EV_PLAYER_JOINED: [u8; 32] = event_topic("PlayerJoined(bytes32,address,uint64,uint64,uint64)");
const EV_SHIP_COMMISSIONED: [u8; 32] =
    event_topic("ShipCommissioned(bytes32,uint64,uint64,uint64,uint64,uint64)");
const EV_WEAPON_FIRED: [u8; 32] =
    event_topic("WeaponFired(bytes32,uint64,uint64,uint64,uint64,uint64)");
const EV_SHIP_SUNK: [u8; 32] = event_topic("ShipSunk(bytes32,uint64,uint64,uint64)");

// ---------------------------------------------------------------------------
// HPS Entrypoint Table
// ---------------------------------------------------------------------------

hps_entry! {
    "createBattle(bytes32)"                                       => handle_create_battle,
    "joinBattle(bytes32,uint64)"                                  => handle_join_battle,
    "buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"         => handle_buy_ship,
    "moveShip(bytes32,uint64,uint64,uint64,uint64)"               => handle_move_ship,
    "fireWeapon(bytes32,uint64,uint64,uint64)"                    => handle_fire_weapon,
    "upgradeGun(bytes32,uint64,uint64)"                           => handle_upgrade_gun,
    "upgradeArmor(bytes32,uint64)"                                => handle_upgrade_armor,
    "repairShip(bytes32,uint64)"                                  => handle_repair_ship,
    "resolvePendingShells(bytes32)"                               => handle_resolve_shells,
    "getBattleState(bytes32)"                                     => handle_get_battle_state,
    "getPlayersSlice(bytes32,uint64,uint64)"                      => handle_get_players_slice,
}

// ---------------------------------------------------------------------------
// State Records
// ---------------------------------------------------------------------------

/// Fixed 64-byte battle header under `"n:hdr:" || battleId`.
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

/// Fixed 40-byte player record under `"n:plr:" || battleId || pid(1B)`.
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
/// `ship_global_idx = player_id * 3 + slot_idx` (`0..299`).
#[derive(Clone, Copy)]
struct ShipRec {
    alive: u8,
    owner_pid: u8,
    team: u8,
    class_id: u8,
    gun_id: u8,
    armor_tier: u8,
    dir: u8, // 0 = Horizontal (L along X, W along Y), 1 = Vertical (L along Y, W along X)
    x: u8,
    y: u8,
    pad: u8,
    cell_dmg: [u8; 10], // 0..=100 percentage damage for each of up to 10 hull grid cells!
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
            pad: 0,
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

/// Fixed 16-byte in-flight shell record under `"n:shl:" || battleId || idx(u16 BE)`.
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
// Dynamic Grid Math, Geometry, & Damage Resolution
// ---------------------------------------------------------------------------

/// Dynamic `16:10` widescreen landscape grid (`40x25` at `<=4` players up to `190x118` at `100` players).
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

/// Check if `(cx, cy)` lies inside `ship`'s footprint, returning cell index `0..(cells-1)`.
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

fn abs_u8(a: u8, b: u8) -> u8 {
    if a >= b {
        a - b
    } else {
        b - a
    }
}

/// Apply a weapon detonation at `(tx, ty)` against all enemy ships, awarding `+2 CR` per `1%`
/// hull damage dealt + `CLASS_BOUNTY` on sinks!
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
    let prim = GUN_PRIMARY_DMG[g];
    let splash = GUN_SPLASH_DMG[g];

    // Up to 5 impact cells `(ix, iy, raw_dmg)`
    let mut cells = [(0u8, 0u8, 0u8); 5];
    let mut cell_n = 0usize;

    let gw = hdr.grid_w as i16;
    let gh = hdr.grid_h as i16;
    let mut push_cell = |cx: i16, cy: i16, dmg: u8| {
        if cx >= 0 && cy >= 0 && cx < gw && cy < gh && dmg > 0 && cell_n < 5 {
            cells[cell_n] = (cx as u8, cy as u8, dmg);
            cell_n += 1;
        }
    };

    if pattern == 0 {
        // 1x1 pinpoint
        push_cell(tx as i16, ty as i16, prim);
    } else if pattern == 1 {
        // 2x2 area spread
        push_cell(tx as i16, ty as i16, prim);
        push_cell(tx as i16 + 1, ty as i16, splash);
        push_cell(tx as i16, ty as i16 + 1, splash);
        push_cell(tx as i16 + 1, ty as i16 + 1, splash);
    } else {
        // '+' 5-cell cross
        push_cell(tx as i16, ty as i16, prim);
        push_cell(tx as i16 + 1, ty as i16, splash);
        push_cell(tx as i16 - 1, ty as i16, splash);
        push_cell(tx as i16, ty as i16 + 1, splash);
        push_cell(tx as i16, ty as i16 - 1, splash);
    }

    let mut credits_earned = 0u64;
    let mut kills_scored = 0u16;

    let total_ships = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut s_idx = 0u16;
    while s_idx < total_ships {
        let mut ship = load_ship(bid, s_idx);
        if ship.alive != 0 && ship.team != attacker_team {
            let mut touched = false;
            let base_arm = CLASS_BASE_ARMOR[ship.class_id as usize];
            let bonus_arm = ARMOR_BONUS[(ship.armor_tier as usize).min(2)];
            let mut eff_armor = (base_arm + bonus_arm).min(70) as u32;
            if gun_id == 4 {
                // Siege Railgun pierces half of armor!
                eff_armor /= 2;
            }

            let mut c = 0usize;
            while c < cell_n {
                let (ix, iy, raw_dmg) = cells[c];
                if let Some(h_idx) = cell_index_on_ship(&ship, ix, iy) {
                    let prev = ship.cell_dmg[h_idx];
                    if prev < 100 {
                        let mitigated = ((raw_dmg as u32) * (100 - eff_armor) / 100).max(5) as u8;
                        let next = prev.saturating_add(mitigated).min(100);
                        let delta = (next - prev) as u64;
                        ship.cell_dmg[h_idx] = next;
                        credits_earned += delta * 2; // +2 CR per 1% hull damage dealt!
                        touched = true;
                    }
                }
                c += 1;
            }

            if touched {
                // Count breached (`100%` damaged) cells to check sink threshold!
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

/// Piggybacked block-tick resolver: detonates any queued `1`-block Time-of-Flight shells
/// whose `impact_block <= current_block`.
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

/// Join Red (`0`) or Blue (`1`) up to `100` players.
/// Enforces `|red_count - blue_count| <= 1` and dynamically expands `grid_size` outward!
fn handle_join_battle(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let preferred_team = args.u64(1).ok_or(-10)?;
    if preferred_team > 1 {
        return Err(-12);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    if (hdr.player_count as u64) >= MAX_PLAYERS {
        return Err(-14); // 100/100 full!
    }

    let caller = context::msg_sender();
    if caller == [0u8; 20] || find_pid(&bid, &caller).is_some() {
        return Err(-15);
    }

    // Strict on-chain team auto-balance: allow at most +1 player imbalance!
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

    // Dynamic Landscape Ocean Expansion: shift existing ships & in-flight shells symmetrically outward!
    let (new_w, new_h) = compute_dynamic_grid_dims(hdr.player_count);
    if new_w > hdr.grid_w || new_h > hdr.grid_h {
        let dx = (new_w.saturating_sub(hdr.grid_w)) / 2;
        let dy = (new_h.saturating_sub(hdr.grid_h)) / 2;
        if dx > 0 || dy > 0 {
            let existing_ships = (pid as u16) * 3;
            let mut s = 0u16;
            while s < existing_ships {
                let mut sh = load_ship(&bid, s);
                if sh.alive != 0 {
                    sh.x = sh.x.saturating_add(dx);
                    sh.y = sh.y.saturating_add(dy);
                    if sh.flash_x < 250 {
                        sh.flash_x = sh.flash_x.saturating_add(dx);
                        sh.flash_y = sh.flash_y.saturating_add(dy);
                    }
                    save_ship(&bid, s, &sh);
                }
                s += 1;
            }
            let sc = (hdr.shell_count as usize).min(MAX_INFLIGHT_SHELLS);
            let mut q = 0usize;
            while q < sc {
                if let Some(mut shl) = load_shell(&bid, q as u16) {
                    if shl.active != 0 {
                        shl.tx = shl.tx.saturating_add(dx);
                        shl.ty = shl.ty.saturating_add(dy);
                        save_shell(&bid, q as u16, &shl);
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
    save_plr(&bid, pid, &rec);
    storage::set(addr_pid_key(&bid, &caller).as_slice(), &[pid]);
    save_hdr(&bid, &hdr);

    let mut ev = [0u8; 44];
    ev[0..20].copy_from_slice(&caller);
    ev[20..28].copy_from_slice(&(pid as u64).to_be_bytes());
    ev[28..36].copy_from_slice(&(assigned_team as u64).to_be_bytes());
    ev[36..44].copy_from_slice(&(((hdr.grid_w as u64) << 8) | (hdr.grid_h as u64)).to_be_bytes());
    events::emit(&[EV_PLAYER_JOINED, bid], &ev);

    ret::write_u64_word(assigned_team as u64);
    Ok(assigned_team as i32)
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
        return Err(-22); // slot already has an active ship!
    }

    // Emergency Gunboat stipend if all 3 slots are sunk and player has < 200 CR
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
        return Err(-23); // insufficient Credits!
    }

    if x >= (hdr.grid_w as u64) || y >= (hdr.grid_h as u64) {
        return Err(-24);
    }

    // Spawn must be on player's team side of the ocean (`Red = West half`, `Blue = East half`)
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
        gun_id: 0, // starts with Deck Autocannon
        armor_tier: 0,
        dir: dir as u8,
        x: x as u8,
        y: y as u8,
        pad: 0,
        cell_dmg: [0; 10],
        last_move_block: 0,
        last_fire_block: 0,
        flash_x: 255,
        flash_y: 255,
        pad2: [0; 2],
    };

    if !check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand) {
        return Err(-26); // out of bounds or collides with another ship!
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

fn handle_move_ship(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let new_x = args.u64(2).ok_or(-10)?;
    let new_y = args.u64(3).ok_or(-10)?;
    let new_dir = args.u64(4).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER || new_dir > 1 {
        return Err(-30);
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
        return Err(-32); // already moved or repaired this block!
    }

    if new_x >= (hdr.grid_w as u64) || new_y >= (hdr.grid_h as u64) {
        return Err(-33);
    }

    // Check effective speed (if stern cell [0] is 100% damaged, engine speed is halved -> min 1)
    let base_spd = CLASS_SPEED[ship.class_id as usize];
    let eff_spd = if ship.cell_dmg[0] >= 100 {
        (base_spd / 2).max(1)
    } else {
        base_spd
    };

    let dist = abs_u8(ship.x, new_x as u8).saturating_add(abs_u8(ship.y, new_y as u8));
    let rot_cost = if ship.dir != (new_dir as u8) { 1u8 } else { 0u8 };
    if dist.saturating_add(rot_cost) > eff_spd {
        return Err(-34); // exceeds ship's per-block cruising speed!
    }

    ship.x = new_x as u8;
    ship.y = new_y as u8;
    ship.dir = new_dir as u8;
    ship.last_move_block = blk;

    if !check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &ship) {
        return Err(-35); // collision!
    }

    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);
    Ok(())
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
        return Err(-43); // weapon on cooldown this block!
    }

    // Compute distance from ship center to `(tx, ty)` and verify `<= GUN_RANGE[gun_id]`
    let (w, h) = ship_dims(ship.class_id, ship.dir);
    let cx = (ship.x as i32) + ((w as i32) / 2);
    let cy = (ship.y as i32) + ((h as i32) / 2);
    let dx = (tx as i32) - cx;
    let dy = (ty as i32) - cy;
    let rng = GUN_RANGE[ship.gun_id as usize] as i32;
    if dx * dx + dy * dy > rng * rng {
        return Err(-44); // target out of gun range!
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

/// Upgrade weapon on `slotIdx` — checks BOTH `ship.class_id >= GUN_MIN_CLASS[gunId]` AND `credits >= GUN_COST[gunId]`.
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
    // Check ship hull is large enough to mount this weapon!
    if ship.class_id < GUN_MIN_CLASS[gun_id as usize] {
        return Err(-53); // ship hull too small for this gun caliber!
    }

    let cost = GUN_COST[gun_id as usize];
    if plr.credits < cost {
        return Err(-54); // insufficient Credits!
    }

    plr.credits -= cost;
    ship.gun_id = gun_id as u8;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);
    Ok(())
}

fn handle_upgrade_armor(args: &CalldataReader) -> Result<(), i32> {
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

    if ship.alive == 0 || ship.armor_tier >= ARMOR_MAX_TIER {
        return Err(-61);
    }

    let cost = ARMOR_UPGRADE_COST[ship.armor_tier as usize];
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

/// Paid Field Repair: restores up to `40%` damage on each damaged cell of `slotIdx` at `1 CR` per `1%`
/// restored, cutting engines & weapons on that ship for the current block!
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

    if ship.alive == 0 || plr.credits == 0 {
        return Err(-71);
    }

    let blk32 = context::block_number() as u32;
    if ship.last_move_block == blk32 || ship.last_fire_block == blk32 {
        return Err(-72); // must cut engines & hold fire this block to repair!
    }

    let n_cells = CLASS_CELLS[ship.class_id as usize] as usize;
    let mut total_repaired = 0u64;
    let mut i = 0usize;
    while i < n_cells && plr.credits > 0 {
        let cur = ship.cell_dmg[i];
        if cur > 0 {
            let max_affordable = plr.credits.min(40).min(cur as u64) as u8;
            if max_affordable > 0 {
                ship.cell_dmg[i] -= max_affordable;
                plr.credits -= max_affordable as u64;
                total_repaired += max_affordable as u64;
            }
        }
        i += 1;
    }

    if total_repaired == 0 {
        return Err(-73); // ship already at 0% damage!
    }

    ship.last_move_block = blk32;
    ship.last_fire_block = blk32;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);

    ret::write_u64_word(total_repaired);
    Ok(total_repaired as i32)
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

/// Returns `[header (32B)][alive_ship_count (2B BE)][shell_count (2B BE)][alive_ships * 34B][shells * 16B]`.
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

        // Even if ALL 20 players request TEAM_RED (`0`), contract strictly alternates whenever Red > Blue!
        for i in 0u8..20u8 {
            let mut addr = [0u8; 20];
            addr[0] = 0x10;
            addr[19] = i + 1;
            mock::transact_as(
                addr,
                CONTRACT,
                CallEncoder::<128>::new(selector("joinBattle(bytes32,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0) // everyone begs for Red!
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

        assert_eq!(st[1], 20); // 20 players joined
        assert_eq!(st[2], 10); // 10 Red
        assert_eq!(st[3], 10); // 10 Blue (`|Red - Blue| <= 1`!)
        assert!(st[4] > st[5] && st[4] >= 80); // landscape rectangle (`grid_w > grid_h`)!
        assert_eq!(compute_dynamic_grid_dims(100), (189, 118)); // 100 players -> widescreen landscape!
    }

    #[test]
    fn gun_mount_restrictions_aoe_cell_damage_credits_armor_and_paid_repairs() {
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

        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("joinBattle(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("joinBattle(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();

        // Red buys 1 Heavy Cruiser (`550 CR`, class 2, 4x1) at `(12, 15)` + 1 Gunboat (`200 CR`, class 0) at `(8, 10)`
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2) // Heavy Cruiser (4x1, Max Mount L = 2)
                .push_u64(11)
                .push_u64(15)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .push_u64(0) // Gunboat (2x1, Max Mount S = 0)
                .push_u64(15)
                .push_u64(12)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Gunboat CANNOT mount Cluster Rocket Pod (`M = 1`) -> rejected with `Err(-53)`!
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<128>::new(selector("upgradeGun(bytes32,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(1)
                    .push_u64(2)
                    .as_slice(),
            ),
            Err(-53)
        );

        // Gunboat CAN mount Twin Flak Mortar (`S = 0`, `250 CR`, `2x2` area)!
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("upgradeGun(bytes32,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();

        // Blue buys Heavy Cruiser (`550 CR`) at `(20, 12)` (East half of 40x25) and upgrades Armor Tier 1 (`200 CR`)!
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
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("upgradeArmor(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Red's Gunboat at `(15, 12)` fires `2x2` Twin Flak Mortar at `(20, 12)` -> hits BOTH `(20,12)` & `(21,12)`!
        mock::set_block_number(601);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .push_u64(20)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();

        // Check Red earned Credits (`+2 CR` per `1%` damage across 2 cells!)
        let plrs = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("getPlayersSlice(bytes32,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2)
                .as_slice(),
        )
        .unwrap();
        let red_credits = u64::from_be_bytes(plrs[8 + 24..8 + 32].try_into().unwrap());
        let red_score = u64::from_be_bytes(plrs[8 + 32..8 + 40].try_into().unwrap());
        assert!(red_score > 0);
        assert_eq!(red_credits, red_score); // started with 1000, spent 550+200+250=1000, earned `red_score`!

        // On block 602, Blue pays Credits to `repairShip` on its Cruiser!
        mock::set_block_number(602);
        let rep = mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("repairShip(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        let repaired_pct = u64::from_be_bytes(rep[24..32].try_into().unwrap());
        assert!(repaired_pct > 0);
    }
}
