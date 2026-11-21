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
use hps_sdk::governance::ERR_ALREADY_EXECUTED_IN_BLOCK;
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
pub const CREDITS_PER_CELL_HIT: u64 = 120;
pub const REPAIR_COST_PER_CELL: u64 = 100;

/// Combat Score points (tracked independently from spendable `Credits`!):
/// - `+100 pts` per enemy hull square destroyed
/// - `+250 / +450 / +750 / +1,500 pts` sink bonus by class
pub const SCORE_PER_CELL_HIT: u64 = 100;
pub const CLASS_SCORE_BONUS: [u64; 4] = [250, 450, 750, 1500];

pub const TEAM_RED: u8 = 0;
pub const TEAM_BLUE: u8 = 1;

pub const SHIP_DEAD: u8 = 0;
pub const SHIP_ALIVE: u8 = 1;
pub const SHIP_DOCKED: u8 = 2;
pub const SHIP_RECALLING_VIEW: u8 = 3;

/// Number of blocks (~13s) required for Open-Sea Out-of-Combat Recall AND post-fire/hit/sortie cooldowns.
pub const BASE_RECALL_BLOCKS: u32 = 3;
pub const BASE_COOLDOWN_BLOCKS: u32 = 3;

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
const EV_VESSEL_COLLISION: [u8; 32] = event_topic(
    "VesselCollision(bytes32,uint64,uint64,uint64,uint64,uint64,uint64,uint64)",
);
const EV_WEAPON_FIRED: [u8; 32] =
    event_topic("WeaponFired(bytes32,uint64,uint64,uint64,uint64,uint64)");
const EV_SHIP_SUNK: [u8; 32] = event_topic("ShipSunk(bytes32,uint64,uint64,uint64)");
const EV_PLAYER_RESTARTED: [u8; 32] =
    event_topic("PlayerRestarted(bytes32,address,uint64,uint64,uint64)");
const EV_SHIP_DOCKED: [u8; 32] =
    event_topic("ShipDocked(bytes32,address,uint64,uint64,uint64)");
const EV_SHIP_RECALL_STARTED: [u8; 32] =
    event_topic("ShipRecallStarted(bytes32,address,uint64,uint64)");
const EV_SHIP_RECALL_CANCELLED: [u8; 32] =
    event_topic("ShipRecallCancelled(bytes32,uint64,uint64)");
const EV_SHIP_SORTIED: [u8; 32] =
    event_topic("ShipSortied(bytes32,address,uint64,uint64,uint64,uint64)");

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

// ---------------------------------------------------------------------------
// HPS Entrypoint Table
// ---------------------------------------------------------------------------

hps_entry! {
    "createBattle(bytes32)"                                                       => handle_create_battle,
    "joinBattle(bytes32,uint64)"                                                  => handle_join_battle,
    "joinAndDeploy(bytes32,uint64,uint64,uint64,uint64)"                          => handle_join_and_deploy,
    "joinAndDeployWithIdentity(bytes32,uint64,address,uint64,uint64,uint64)"      => handle_join_and_deploy_with_identity,
    "setPlayerIdentity(bytes32,address)"                                          => handle_set_player_identity,
    "startAnew(bytes32,uint64,uint64,uint64)"                                     => handle_start_anew,
    "buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"                         => handle_buy_ship,
    "moveShip(bytes32,uint64,uint64,uint64,uint64)"               => handle_move_ship,
    "fireWeapon(bytes32,uint64,uint64,uint64)"                    => handle_fire_weapon,
    "upgradeGun(bytes32,uint64,uint64)"                           => handle_upgrade_gun,
    "upgradeArmor(bytes32,uint64)"                                => handle_upgrade_engine,
    "repairShip(bytes32,uint64)"                                  => handle_repair_ship,
    "returnShipToBase(bytes32,uint64)"                            => handle_return_ship_to_base,
    "returnFleetToBase(bytes32)"                                  => handle_return_fleet_to_base,
    "sortieShipFromBase(bytes32,uint64)"                          => handle_sortie_ship_from_base,
    "sortieFleetFromBase(bytes32)"                                => handle_sortie_fleet_from_base,
    "cancelRecall(bytes32,uint64)"                                => handle_cancel_recall,
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
    restarts: u8,
    credits: u64,
    score: u64,
    identity_addr: [u8; 20],
    best_score: u64,
}

const PLR_LEN: usize = 68;

impl PlayerRec {
    fn encode(&self) -> [u8; PLR_LEN] {
        let mut b = [0u8; PLR_LEN];
        b[0..20].copy_from_slice(&self.addr);
        b[20] = self.team;
        b[21..23].copy_from_slice(&self.kills.to_be_bytes());
        b[23] = self.restarts;
        b[24..32].copy_from_slice(&self.credits.to_be_bytes());
        b[32..40].copy_from_slice(&self.score.to_be_bytes());
        b[40..60].copy_from_slice(&self.identity_addr);
        b[60..68].copy_from_slice(&self.best_score.to_be_bytes());
        b
    }

    fn decode(b: &[u8; PLR_LEN]) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&b[0..20]);
        let mut id_addr = [0u8; 20];
        id_addr.copy_from_slice(&b[40..60]);
        Self {
            addr,
            team: b[20],
            kills: u16::from_be_bytes([b[21], b[22]]),
            restarts: b[23],
            credits: u64::from_be_bytes(b[24..32].try_into().unwrap()),
            score: u64::from_be_bytes(b[32..40].try_into().unwrap()),
            identity_addr: id_addr,
            best_score: u64::from_be_bytes(b[60..68].try_into().unwrap()),
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

/// Per-ship Naval Base & anti-abuse tracking (`12 bytes` under `"n:bas:" || bid || gidx`).
#[derive(Clone, Copy, Default)]
struct ShipBaseMeta {
    recall_ready_block: u32,
    last_hit_block: u32,
    last_sortie_block: u32,
}

const BAS_LEN: usize = 12;

impl ShipBaseMeta {
    fn empty() -> Self {
        Self {
            recall_ready_block: 0,
            last_hit_block: 0,
            last_sortie_block: 0,
        }
    }

    fn encode(&self) -> [u8; BAS_LEN] {
        let mut b = [0u8; BAS_LEN];
        b[0..4].copy_from_slice(&self.recall_ready_block.to_be_bytes());
        b[4..8].copy_from_slice(&self.last_hit_block.to_be_bytes());
        b[8..12].copy_from_slice(&self.last_sortie_block.to_be_bytes());
        b
    }

    fn decode(b: &[u8; BAS_LEN]) -> Self {
        Self {
            recall_ready_block: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            last_hit_block: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            last_sortie_block: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        }
    }
}

fn base_meta_key(bid: &[u8; 32], gidx: u16) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"n:bas:")
        .push(bid)
        .push(&gidx.to_be_bytes())
}

fn load_base_meta(bid: &[u8; 32], gidx: u16) -> ShipBaseMeta {
    let k = base_meta_key(bid, gidx);
    let mut b = [0u8; BAS_LEN];
    match storage::get_into(k.as_slice(), &mut b) {
        Some(BAS_LEN) => ShipBaseMeta::decode(&b),
        _ => ShipBaseMeta::empty(),
    }
}

fn save_base_meta(bid: &[u8; 32], gidx: u16, m: &ShipBaseMeta) {
    storage::set(base_meta_key(bid, gidx).as_slice(), &m.encode());
}

/// Returns `(x0, y0, x1_incl, y1_incl)` for `team`'s fortified `4×5` corner Naval Base harbor basin:
/// - Red (`TEAM_RED = 0`): North-West Harbor `x = 0..=3`, `y = 0..=4`
/// - Blue (`TEAM_BLUE = 1`): South-East Harbor `x = grid_w-4 ..= grid_w-1`, `y = grid_h-5 ..= grid_h-1`
pub fn naval_base_rect(team: u8, grid_w: u8, grid_h: u8) -> (u8, u8, u8, u8) {
    if team == TEAM_RED {
        (
            0,
            0,
            3.min(grid_w.saturating_sub(1)),
            4.min(grid_h.saturating_sub(1)),
        )
    } else {
        (
            grid_w.saturating_sub(4),
            grid_h.saturating_sub(5),
            grid_w.saturating_sub(1),
            grid_h.saturating_sub(1),
        )
    }
}

fn ship_overlaps_rect(ship: &ShipRec, x0: u8, y0: u8, x1: u8, y1: u8) -> bool {
    let (w, h) = ship_dims(ship.class_id, ship.dir);
    let sx1 = ship.x.saturating_add(w).saturating_sub(1);
    let sy1 = ship.y.saturating_add(h).saturating_sub(1);
    !(sx1 < x0 || ship.x > x1 || sy1 < y0 || ship.y > y1)
}

fn ship_in_friendly_base(ship: &ShipRec, grid_w: u8, grid_h: u8) -> bool {
    let (x0, y0, x1, y1) = naval_base_rect(ship.team, grid_w, grid_h);
    ship_overlaps_rect(ship, x0, y0, x1, y1)
}

fn ship_in_enemy_base(ship: &ShipRec, grid_w: u8, grid_h: u8) -> bool {
    let enemy_team = if ship.team == TEAM_RED { TEAM_BLUE } else { TEAM_RED };
    let (x0, y0, x1, y1) = naval_base_rect(enemy_team, grid_w, grid_h);
    ship_overlaps_rect(ship, x0, y0, x1, y1)
}

/// If `ship` is at sea (`SHIP_ALIVE`) with a matured Out-of-Combat Recall (`blk32 >= recall_ready_block`),
/// atomically promotes it to `SHIP_DOCKED` (`2`) so a player who closed their browser after clicking
/// "Return to Base" is guaranteed 100% drydock immunity as soon as the 3-block tow completes!
fn promote_matured_recall(
    bid: &[u8; 32],
    gidx: u16,
    ship: &mut ShipRec,
    blk32: u32,
) -> ShipBaseMeta {
    let mut meta = load_base_meta(bid, gidx);
    if ship.alive == SHIP_ALIVE && meta.recall_ready_block > 0 && blk32 >= meta.recall_ready_block {
        let ready_blk = meta.recall_ready_block;
        let (bx0, by0, bx1, by1) = naval_base_rect(ship.team, BASE_GRID_W, BASE_GRID_H);
        let _ = (bx1, by1);
        ship.alive = SHIP_DOCKED;
        ship.x = bx0;
        ship.y = by0;
        meta.recall_ready_block = 0;
        save_ship(bid, gidx, ship);
        save_base_meta(bid, gidx, &meta);
        if let Some(plr) = load_plr(bid, ship.owner_pid) {
            let slot_idx = (gidx % 3) as u64;
            let mut ev = [0u8; 24];
            ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
            ev[8..16].copy_from_slice(&1u64.to_be_bytes()); // mode = 1 (recall tow completed)
            ev[16..24].copy_from_slice(&(ready_blk as u64).to_be_bytes());
            events::emit(&[EV_SHIP_DOCKED, *bid, addr_topic(&plr.addr)], &ev);
        }
    }
    meta
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
    if ship.alive != SHIP_ALIVE {
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
    let blk32 = context::block_number() as u32;
    let total_slots = (player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut g = 0u16;
    while g < total_slots {
        if g != ignore_gidx {
            let mut other = load_ship(bid, g);
            if other.alive == SHIP_ALIVE {
                let _ = promote_matured_recall(bid, g, &mut other, blk32);
            }
            if other.alive == SHIP_ALIVE && ships_overlap(cand, &other) {
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
    let mut score_earned = 0u64;
    let mut kills_scored = 0u16;

    let blk32 = context::block_number() as u32;
    let total_ships = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut s_idx = 0u16;
    while s_idx < total_ships {
        let mut ship = load_ship(bid, s_idx);
        if ship.alive == SHIP_ALIVE {
            let _ = promote_matured_recall(bid, s_idx, &mut ship, blk32);
        }
        if ship.alive == SHIP_ALIVE && ship.team != attacker_team {
            let mut touched = false;
            let mut c = 0usize;
            while c < cell_n {
                let (ix, iy) = cells[c];
                if let Some(h_idx) = cell_index_on_ship(&ship, ix, iy) {
                    touched = true;
                    if ship.cell_dmg[h_idx] < 100 {
                        ship.cell_dmg[h_idx] = 100; // 100% square hit!
                        credits_earned += CREDITS_PER_CELL_HIT;
                        score_earned += SCORE_PER_CELL_HIT;
                    }
                }
                c += 1;
            }

            if touched {
                let mut meta = load_base_meta(bid, s_idx);
                meta.last_hit_block = blk32;
                if meta.recall_ready_block > blk32 {
                    meta.recall_ready_block = 0;
                    let mut cev = [0u8; 16];
                    cev[0..8].copy_from_slice(&(s_idx as u64).to_be_bytes());
                    cev[8..16].copy_from_slice(&(attacker_pid as u64).to_be_bytes());
                    events::emit(&[EV_SHIP_RECALL_CANCELLED, *bid], &cev);
                }
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
                    meta = ShipBaseMeta::empty();
                    let bounty = CLASS_BOUNTY[ship.class_id as usize];
                    let score_bonus = CLASS_SCORE_BONUS[ship.class_id as usize];
                    credits_earned += bounty;
                    score_earned += score_bonus;
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
                save_base_meta(bid, s_idx, &meta);
                save_ship(bid, s_idx, &ship);
            }
        }
        s_idx += 1;
    }

    if credits_earned > 0 || score_earned > 0 || kills_scored > 0 {
        if let Some(mut att) = load_plr(bid, attacker_pid) {
            att.credits = att.credits.saturating_add(credits_earned);
            att.score = att.score.saturating_add(score_earned);
            if att.score > att.best_score {
                att.best_score = att.score;
            }
            att.kills = att.kills.saturating_add(kills_scored);
            save_plr(bid, attacker_pid, &att);
        }
    }
}

fn sync_pending_shells(bid: &[u8; 32], hdr: &mut BattleHeader) {
    let blk = context::block_number();
    let blk32 = blk as u32;
    if blk <= hdr.last_resolved_block {
        return;
    }
    let total_ships = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut g = 0u16;
    while g < total_ships {
        let mut sh = load_ship(bid, g);
        if sh.alive == SHIP_ALIVE {
            let _ = promote_matured_recall(bid, g, &mut sh, blk32);
        }
        g += 1;
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
                if sh.alive == SHIP_ALIVE {
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
        restarts: 0,
        credits: STARTING_CREDITS,
        score: 0,
        identity_addr: [0u8; 20],
        best_score: 0,
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

fn spawn_starter_ships_internal(
    bid: &[u8; 32],
    hdr: &BattleHeader,
    pid: u8,
    team: u8,
    plr: &mut PlayerRec,
    classes: [u64; 3],
    seed_salt: u16,
) {
    let mut slot = 0usize;
    while slot < 3 {
        let cid = classes[slot];
        if cid < (CLASS_COUNT as u64) {
            let gidx = (pid as u16) * 3 + (slot as u16);
            let existing = load_ship(bid, gidx);
            let cost = CLASS_COST[cid as usize];
            if existing.alive == 0 && plr.credits >= cost {
                let l = CLASS_LEN[cid as usize];
                let w = CLASS_WID[cid as usize];
                let max_x_span = hdr.grid_w.saturating_sub(l + 2).max(1);
                let max_y_span = hdr.grid_h.saturating_sub(w + 2).max(1);

                let x_seed =
                    (((pid as u16) * 11 + (slot as u16) * 7 + 3 + seed_salt) % (max_x_span as u16)) as u8;
                let y_seed =
                    (((pid as u16) * 7 + (slot as u16) * 5 + 2 + seed_salt) % (max_y_span as u16)) as u8;

                let mut placed = false;
                let mut dy_off = 0u8;
                while dy_off < max_y_span && !placed {
                    let y = 1 + ((y_seed + dy_off) % max_y_span);
                    let mut dx_off = 0u8;
                    while dx_off < max_x_span {
                        let x = 1 + ((x_seed + dx_off) % max_x_span);
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
                        if !ship_in_enemy_base(&cand, hdr.grid_w, hdr.grid_h)
                            && check_ship_placement_free(
                                bid,
                                hdr.player_count,
                                hdr.grid_w,
                                hdr.grid_h,
                                gidx,
                                &cand,
                            )
                        {
                            plr.credits -= cost;
                            save_ship(bid, gidx, &cand);
                            save_base_meta(bid, gidx, &ShipBaseMeta::empty());
                            let mut ev = [0u8; 40];
                            ev[0..8].copy_from_slice(&(gidx as u64).to_be_bytes());
                            ev[8..16].copy_from_slice(&(team as u64).to_be_bytes());
                            ev[16..24].copy_from_slice(&cid.to_be_bytes());
                            ev[24..32].copy_from_slice(&(x as u64).to_be_bytes());
                            ev[32..40].copy_from_slice(&(y as u64).to_be_bytes());
                            events::emit(&[EV_SHIP_COMMISSIONED, *bid], &ev);
                            placed = true;
                            break;
                        }
                        dx_off = dx_off.saturating_add(3);
                    }
                    dy_off = dy_off.saturating_add(2);
                }
            }
        }
        slot += 1;
    }
}

fn join_and_deploy_common(
    bid: [u8; 32],
    preferred_team: u64,
    identity_addr: [u8; 20],
    classes: [u64; 3],
) -> Result<i32, i32> {
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let (pid, team) = join_player_internal(&bid, &mut hdr, caller, preferred_team)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;
    if identity_addr != [0u8; 20] {
        plr.identity_addr = identity_addr;
    }

    spawn_starter_ships_internal(&bid, &hdr, pid, team, &mut plr, classes, 0);

    save_plr(&bid, pid, &plr);
    save_hdr(&bid, &hdr);
    ret::write_u64_word(team as u64);
    Ok(team as i32)
}

/// True Game-Over Restart (`startAnew`):
/// - Allowed STRICTLY when the player has `0` alive ships AND `credits < 200` (cannot buy any vessel).
/// - Locks Peak High Score (`best_score`), applies `-50%` penalty to `score` (`score / 2`),
///   increments `restarts`, grants a fresh `1,000 CR` bankroll, and spawns up to 3 starter ships!
fn handle_start_anew(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let s0 = args.u64(1).ok_or(-10)?;
    let s1 = args.u64(2).ok_or(-10)?;
    let s2 = args.u64(3).ok_or(-10)?;

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;

    // Must have 0 alive ships
    let sh0 = load_ship(&bid, (pid as u16) * 3).alive;
    let sh1 = load_ship(&bid, (pid as u16) * 3 + 1).alive;
    let sh2 = load_ship(&bid, (pid as u16) * 3 + 2).alive;
    if sh0 != 0 || sh1 != 0 || sh2 != 0 {
        return Err(-27);
    }

    // Must have < 200 CR (cannot buy even the cheapest Patrol Gunboat)
    if plr.credits >= CLASS_COST[0] {
        return Err(-28);
    }

    if plr.score > plr.best_score {
        plr.best_score = plr.score;
    }
    plr.score /= 2; // -50% Current Score penalty!
    plr.restarts = plr.restarts.saturating_add(1);
    plr.credits = STARTING_CREDITS;

    let salt = ((context::block_number() as u16).wrapping_mul(5)).wrapping_add((plr.restarts as u16) * 13);
    spawn_starter_ships_internal(&bid, &hdr, pid, plr.team, &mut plr, [s0, s1, s2], salt);

    save_plr(&bid, pid, &plr);
    save_hdr(&bid, &hdr);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&plr.score.to_be_bytes());
    ev[8..16].copy_from_slice(&plr.best_score.to_be_bytes());
    ev[16..24].copy_from_slice(&(plr.restarts as u64).to_be_bytes());
    events::emit(&[EV_PLAYER_RESTARTED, bid, addr_topic(&caller)], &ev);

    ret::write_u64_word(plr.score);
    Ok(plr.team as i32)
}

/// 1-Block Atomic Onboarding: joins battle (if not already joined) and auto-spawns up to 3 starter
/// ships (`s0, s1, s2`, pass `255` for empty slot) anywhere across the open ocean!
fn handle_join_and_deploy(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let preferred_team = args.u64(1).ok_or(-10)?;
    let s0 = args.u64(2).ok_or(-10)?;
    let s1 = args.u64(3).ok_or(-10)?;
    let s2 = args.u64(4).ok_or(-10)?;
    join_and_deploy_common(bid, preferred_team, [0u8; 20], [s0, s1, s2])
}

/// 1-Block Atomic Onboarding with Identity HFS binding (`identity_addr` exposed in `getPlayersSlice`
/// so all peers resolve `Identity.nickname()` for every vessel on the ocean!).
fn handle_join_and_deploy_with_identity(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let preferred_team = args.u64(1).ok_or(-10)?;
    let identity_addr = args.address(2).ok_or(-10)?;
    let s0 = args.u64(3).ok_or(-10)?;
    let s1 = args.u64(4).ok_or(-10)?;
    let s2 = args.u64(5).ok_or(-10)?;
    join_and_deploy_common(bid, preferred_team, identity_addr, [s0, s1, s2])
}

fn handle_set_player_identity(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let identity_addr = args.address(1).ok_or(-10)?;
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let mut plr = load_plr(&bid, pid).ok_or(-21)?;
    plr.identity_addr = identity_addr;
    save_plr(&bid, pid, &plr);
    Ok(())
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

    let cost = CLASS_COST[class_id as usize];
    if plr.credits < cost {
        return Err(-23);
    }

    if x >= (hdr.grid_w as u64) || y >= (hdr.grid_h as u64) {
        return Err(-24);
    }

    // Full-board deployment: vessels are free to deploy anywhere across the ocean!
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

    if ship_in_enemy_base(&cand, hdr.grid_w, hdr.grid_h) {
        return Err(-29);
    }

    if !check_ship_placement_free(&bid, hdr.player_count, hdr.grid_w, hdr.grid_h, gidx, &cand) {
        return Err(-26);
    }

    plr.credits -= cost;
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &cand);
    save_base_meta(&bid, gidx, &ShipBaseMeta::empty());
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

fn in_ocean_bounds(grid_w: u8, grid_h: u8, class_id: u8, dir: u8, x: i16, y: i16) -> bool {
    if x < 0 || y < 0 {
        return false;
    }
    let (w, h) = ship_dims(class_id, dir);
    (x as u16) + (w as u16) <= (grid_w as u16) && (y as u16) + (h as u16) <= (grid_h as u16)
}

fn count_breached_cells(ship: &ShipRec) -> u8 {
    let n_cells = CLASS_CELLS[ship.class_id as usize] as usize;
    let mut breached = 0u8;
    let mut k = 0usize;
    while k < n_cells {
        if ship.cell_dmg[k] >= 100 {
            breached += 1;
        }
        k += 1;
    }
    breached
}

/// Resolves vessel-to-vessel hull collisions whenever `ship` ends up occupying grid square(s)
/// overlapping any other alive vessel(s): every overlapping square takes instant `100%` damage on
/// BOTH vessels, sinking either (or both) if all of its squares are breached!
fn resolve_vessel_collisions(
    bid: &[u8; 32],
    hdr: &mut BattleHeader,
    mover_pid: u8,
    mover_gidx: u16,
    ship: &mut ShipRec,
) {
    let (sw, sh) = ship_dims(ship.class_id, ship.dir);
    let total_slots = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut mover_credits_earned = 0u64;
    let mut mover_score_earned = 0u64;
    let mut mover_kills = 0u16;
    let mut last_enemy_collider: Option<(u8, u8)> = None;

    let blk32 = context::block_number() as u32;
    let mut other_gidx = 0u16;
    while other_gidx < total_slots {
        if other_gidx != mover_gidx {
            let mut other = load_ship(bid, other_gidx);
            if other.alive == SHIP_ALIVE {
                let _ = promote_matured_recall(bid, other_gidx, &mut other, blk32);
            }
            if other.alive == SHIP_ALIVE && ships_overlap(ship, &other) {
                let is_enemy = ship.team != other.team;
                if is_enemy {
                    last_enemy_collider = Some((other.owner_pid, other.team));
                    let mut o_meta = load_base_meta(bid, other_gidx);
                    o_meta.last_hit_block = blk32;
                    if o_meta.recall_ready_block > blk32 {
                        o_meta.recall_ready_block = 0;
                        let mut cev = [0u8; 16];
                        cev[0..8].copy_from_slice(&(other_gidx as u64).to_be_bytes());
                        cev[8..16].copy_from_slice(&(mover_pid as u64).to_be_bytes());
                        events::emit(&[EV_SHIP_RECALL_CANCELLED, *bid], &cev);
                    }
                    save_base_meta(bid, other_gidx, &o_meta);

                    let mut m_meta = load_base_meta(bid, mover_gidx);
                    m_meta.last_hit_block = blk32;
                    m_meta.recall_ready_block = 0;
                    save_base_meta(bid, mover_gidx, &m_meta);
                }

                let mut overlap_squares = 0u64;
                let mut other_credits_earned = 0u64;
                let mut other_score_earned = 0u64;

                let mut ry = 0u8;
                while ry < sh {
                    let mut rx = 0u8;
                    while rx < sw {
                        let cx = ship.x.saturating_add(rx);
                        let cy = ship.y.saturating_add(ry);
                        if let (Some(s_idx), Some(o_idx)) = (
                            cell_index_on_ship(ship, cx, cy),
                            cell_index_on_ship(&other, cx, cy),
                        ) {
                            overlap_squares += 1;
                            if ship.cell_dmg[s_idx] < 100 {
                                ship.cell_dmg[s_idx] = 100;
                                if is_enemy {
                                    other_credits_earned += CREDITS_PER_CELL_HIT;
                                    other_score_earned += SCORE_PER_CELL_HIT;
                                }
                            }
                            if other.cell_dmg[o_idx] < 100 {
                                other.cell_dmg[o_idx] = 100;
                                if is_enemy {
                                    mover_credits_earned += CREDITS_PER_CELL_HIT;
                                    mover_score_earned += SCORE_PER_CELL_HIT;
                                }
                            }
                        }
                        rx += 1;
                    }
                    ry += 1;
                }

                if overlap_squares > 0 {
                    let mut other_sunk = 0u64;
                    if count_breached_cells(&other) >= CLASS_SINK_CELLS[other.class_id as usize] {
                        other.alive = 0;
                        other_sunk = 1;
                        let bounty = if is_enemy {
                            let b = CLASS_BOUNTY[other.class_id as usize];
                            mover_credits_earned += b;
                            mover_score_earned += CLASS_SCORE_BONUS[other.class_id as usize];
                            mover_kills += 1;
                            if ship.team == TEAM_RED {
                                hdr.red_kills += 1;
                            } else {
                                hdr.blue_kills += 1;
                            }
                            b
                        } else {
                            0
                        };
                        let mut sev = [0u8; 24];
                        sev[0..8].copy_from_slice(&(other_gidx as u64).to_be_bytes());
                        sev[8..16].copy_from_slice(&(mover_pid as u64).to_be_bytes());
                        sev[16..24].copy_from_slice(&bounty.to_be_bytes());
                        events::emit(&[EV_SHIP_SUNK, *bid], &sev);
                    }
                    save_ship(bid, other_gidx, &other);

                    if other_credits_earned > 0 || other_score_earned > 0 {
                        if let Some(mut oplr) = load_plr(bid, other.owner_pid) {
                            oplr.credits = oplr.credits.saturating_add(other_credits_earned);
                            oplr.score = oplr.score.saturating_add(other_score_earned);
                            if oplr.score > oplr.best_score {
                                oplr.best_score = oplr.score;
                            }
                            save_plr(bid, other.owner_pid, &oplr);
                        }
                    }

                    let mover_will_sink =
                        count_breached_cells(ship) >= CLASS_SINK_CELLS[ship.class_id as usize];
                    let mut cev = [0u8; 56];
                    cev[0..8].copy_from_slice(&(mover_gidx as u64).to_be_bytes());
                    cev[8..16].copy_from_slice(&(other_gidx as u64).to_be_bytes());
                    cev[16..24].copy_from_slice(&(ship.x as u64).to_be_bytes());
                    cev[24..32].copy_from_slice(&(ship.y as u64).to_be_bytes());
                    cev[32..40].copy_from_slice(&overlap_squares.to_be_bytes());
                    cev[40..48].copy_from_slice(&(if mover_will_sink { 1u64 } else { 0u64 }).to_be_bytes());
                    cev[48..56].copy_from_slice(&other_sunk.to_be_bytes());
                    events::emit(&[EV_VESSEL_COLLISION, *bid], &cev);
                }
            }
        }
        other_gidx += 1;
    }

    if count_breached_cells(ship) >= CLASS_SINK_CELLS[ship.class_id as usize] {
        ship.alive = 0;
        let (killer_pid, bounty) = if let Some((enemy_pid, enemy_team)) = last_enemy_collider {
            let b = CLASS_BOUNTY[ship.class_id as usize];
            let sb = CLASS_SCORE_BONUS[ship.class_id as usize];
            if enemy_team == TEAM_RED {
                hdr.red_kills += 1;
            } else {
                hdr.blue_kills += 1;
            }
            if let Some(mut eplr) = load_plr(bid, enemy_pid) {
                eplr.credits = eplr.credits.saturating_add(b);
                eplr.score = eplr.score.saturating_add(sb);
                if eplr.score > eplr.best_score {
                    eplr.best_score = eplr.score;
                }
                eplr.kills = eplr.kills.saturating_add(1);
                save_plr(bid, enemy_pid, &eplr);
            }
            (enemy_pid, b)
        } else {
            (mover_pid, 0)
        };
        let mut sev = [0u8; 24];
        sev[0..8].copy_from_slice(&(mover_gidx as u64).to_be_bytes());
        sev[8..16].copy_from_slice(&(killer_pid as u64).to_be_bytes());
        sev[16..24].copy_from_slice(&bounty.to_be_bytes());
        events::emit(&[EV_SHIP_SUNK, *bid], &sev);
    }

    if mover_credits_earned > 0 || mover_score_earned > 0 || mover_kills > 0 {
        if let Some(mut mplr) = load_plr(bid, mover_pid) {
            mplr.credits = mplr.credits.saturating_add(mover_credits_earned);
            mplr.score = mplr.score.saturating_add(mover_score_earned);
            if mplr.score > mplr.best_score {
                mplr.best_score = mplr.score;
            }
            mplr.kills = mplr.kills.saturating_add(mover_kills);
            save_plr(bid, mover_pid, &mplr);
        }
    }
}

fn heading8_from_delta(dx: i32, dy: i32, fallback: u8) -> u8 {
    if dx == 0 && dy == 0 {
        return fallback;
    }
    let ax = dx.abs();
    let ay = dy.abs();
    if ay * 100 >= ax * 241 {
        if dy < 0 { 0 } else { 4 }
    } else if ax * 100 >= ay * 241 {
        if dx > 0 { 2 } else { 6 }
    } else if dx > 0 {
        if dy < 0 { 1 } else { 3 }
    } else if dy > 0 {
        5
    } else {
        7
    }
}

fn isqrt_u64(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Free 2D single-click navigation anywhere inside the vessel's max range circle (`dx^2 + dy^2 <= max_range^2`)!
/// `hull_dir`: `0` = horizontal, `1` = vertical, `2` = auto-orient from movement vector.
/// Bounded by ocean edges; if the vessel ends up in overlapping grid squares with another
/// vessel, mutual `100%` square collision damage is applied!
fn handle_move_ship(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let dest_x = args.u64(2).ok_or(-10)?;
    let dest_y = args.u64(3).ok_or(-10)?;
    let hull_dir = args.u64(4).ok_or(-10)?;

    if slot_idx >= SHIPS_PER_PLAYER || hull_dir > 2 {
        return Err(-30);
    }

    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);

    if dest_x >= (hdr.grid_w as u64) || dest_y >= (hdr.grid_h as u64) {
        return Err(-33);
    }

    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(&bid, gidx);
    let blk = context::block_number() as u32;
    let mut meta = promote_matured_recall(&bid, gidx, &mut ship, blk);
    if ship.alive != SHIP_ALIVE {
        return Err(-31);
    }

    if ship.last_move_block == blk {
        return Err(-32);
    }

    let from_x = ship.x;
    let from_y = ship.y;
    let (w, h) = ship_dims(ship.class_id, ship.dir);
    let from_cx = (from_x as i32) + ((w as i32) / 2);
    let from_cy = (from_y as i32) + ((h as i32) / 2);

    let best_dir = if hull_dir <= 1 {
        hull_dir as u8
    } else {
        let raw_dx = ((dest_x as i32) - (from_x as i32)).abs();
        let raw_dy = ((dest_y as i32) - (from_y as i32)).abs();
        if raw_dx > raw_dy {
            0
        } else if raw_dy > raw_dx {
            1
        } else {
            ship.dir
        }
    };

    let best_x = dest_x as u8;
    let best_y = dest_y as u8;
    if !in_ocean_bounds(hdr.grid_w, hdr.grid_h, ship.class_id, best_dir, best_x as i16, best_y as i16) {
        return Err(-33);
    }
    if best_x == from_x && best_y == from_y && best_dir == ship.dir {
        return Err(-35);
    }

    let (dw, dh) = ship_dims(ship.class_id, best_dir);
    let dest_cx = (best_x as i32) + ((dw as i32) / 2);
    let dest_cy = (best_y as i32) + ((dh as i32) / 2);
    let dx = dest_cx - from_cx;
    let dy = dest_cy - from_cy;
    let dist_sq = (dx * dx + dy * dy) as u64;
    let max_rng = effective_max_speed(&ship) as u64;
    if dist_sq > max_rng * max_rng {
        return Err(-34);
    }

    let heading8 = heading8_from_delta(dx, dy, ship.pad);
    let dist_tiles = isqrt_u64(dist_sq).max(1);

    ship.x = best_x;
    ship.y = best_y;
    ship.dir = best_dir;
    if ship_in_enemy_base(&ship, hdr.grid_w, hdr.grid_h) {
        return Err(-36);
    }
    ship.pad = heading8;
    ship.last_move_block = blk;
    if meta.recall_ready_block > 0 {
        meta.recall_ready_block = 0;
        save_base_meta(&bid, gidx, &meta);
    }

    // Emit 8-word (64-byte) `ShipMoved` payload first so UI always teleports to `(best_x, best_y)`!
    let mut ev = [0u8; 64];
    ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
    ev[8..16].copy_from_slice(&(from_x as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&(from_y as u64).to_be_bytes());
    ev[24..32].copy_from_slice(&(best_x as u64).to_be_bytes());
    ev[32..40].copy_from_slice(&(best_y as u64).to_be_bytes());
    ev[40..48].copy_from_slice(&(best_dir as u64).to_be_bytes());
    ev[48..56].copy_from_slice(&(heading8 as u64).to_be_bytes());
    ev[56..64].copy_from_slice(&dist_tiles.to_be_bytes());
    events::emit(&[EV_SHIP_MOVED, bid, addr_topic(&caller)], &ev);

    // Resolve vessel-to-vessel hull collisions if 2+ vessels now overlap grid squares!
    resolve_vessel_collisions(&bid, &mut hdr, pid, gidx, &mut ship);

    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);

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
    let blk = context::block_number();
    let blk32 = blk as u32;
    let meta = promote_matured_recall(&bid, gidx, &mut ship, blk32);
    if ship.alive != SHIP_ALIVE {
        return Err(-42);
    }
    if meta.recall_ready_block > blk32 {
        return Err(-84);
    }
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
/// Uses its own per-block cooldown (`ship.pad2`) so a captain can Move, Fire, Heal, and Upgrade
/// all in the same round/block (`<= 1` pending tx per action type)!
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

    let blk_tag = ((context::block_number() % 65535) as u16) + 1;
    let last_rep_tag = u16::from_be_bytes(ship.pad2);
    if last_rep_tag == blk_tag {
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

    ship.pad2 = blk_tag.to_be_bytes();
    save_plr(&bid, pid, &plr);
    save_ship(&bid, gidx, &ship);
    save_hdr(&bid, &hdr);

    ret::write_u64_word(cells_repaired);
    Ok(cells_repaired as i32)
}

/// Core per-ship Naval Base entry logic with anti-abuse protections:
/// - Returns `Ok(1)` if docked immediately (inside friendly Naval Base zone),
/// - Returns `Ok(2)` if a `BASE_RECALL_BLOCKS` (`3`-block) Out-of-Combat Recall started,
/// - Returns `Err(...)`:
///     `-80` = ship is dead/empty,
///     `-81` = already docked or recall already active,
///     `-82` = post-sortie cooldown (`< 3` blocks since undocking),
///     `-83` = in-combat cooldown (fired or took enemy damage within last `3` blocks).
fn return_ship_internal(
    bid: &[u8; 32],
    hdr: &BattleHeader,
    caller: &[u8; 20],
    pid: u8,
    slot_idx: u64,
    blk32: u32,
) -> Result<u64, i32> {
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(bid, gidx);
    let mut meta = promote_matured_recall(bid, gidx, &mut ship, blk32);
    if ship.alive == SHIP_DEAD {
        return Err(-80);
    }
    if ship.alive == SHIP_DOCKED || meta.recall_ready_block > blk32 {
        return Err(-81);
    }

    // Anti-Sniping Rule: must stay at sea >= 3 blocks after undocking before re-entering Base
    if meta.last_sortie_block > 0
        && blk32 < meta.last_sortie_block.saturating_add(BASE_COOLDOWN_BLOCKS)
    {
        return Err(-82);
    }

    if ship_in_friendly_base(&ship, hdr.grid_w, hdr.grid_h) {
        // Inside friendly Naval Base: instant 1-block docking, provided ship didn't fire this block!
        if ship.last_fire_block > 0 && ship.last_fire_block == blk32 {
            return Err(-83);
        }
        let (bx0, by0, _, _) = naval_base_rect(ship.team, hdr.grid_w, hdr.grid_h);
        ship.alive = SHIP_DOCKED;
        ship.x = bx0;
        ship.y = by0;
        meta.recall_ready_block = 0;
        save_ship(bid, gidx, &ship);
        save_base_meta(bid, gidx, &meta);

        let mut ev = [0u8; 24];
        ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
        ev[8..16].copy_from_slice(&0u64.to_be_bytes()); // mode = 0 (instant harbor dock)
        ev[16..24].copy_from_slice(&(blk32 as u64).to_be_bytes());
        events::emit(&[EV_SHIP_DOCKED, *bid, addr_topic(caller)], &ev);
        Ok(1)
    } else {
        // Open-Sea Recall: strictly requires being Out of Combat (no shots fired & no hits taken in last 3 blocks)
        if ship.last_fire_block > 0
            && blk32 < ship.last_fire_block.saturating_add(BASE_COOLDOWN_BLOCKS)
        {
            return Err(-83);
        }
        if meta.last_hit_block > 0
            && blk32 < meta.last_hit_block.saturating_add(BASE_COOLDOWN_BLOCKS)
        {
            return Err(-83);
        }
        let ready_blk = blk32.saturating_add(BASE_RECALL_BLOCKS);
        meta.recall_ready_block = ready_blk;
        save_base_meta(bid, gidx, &meta);

        let mut ev = [0u8; 16];
        ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
        ev[8..16].copy_from_slice(&(ready_blk as u64).to_be_bytes());
        events::emit(&[EV_SHIP_RECALL_STARTED, *bid, addr_topic(caller)], &ev);
        Ok(2)
    }
}

/// Launches a drydocked ship (`SHIP_DOCKED`) onto a clear coastal launch tile near its Team's Naval Base.
/// Scans outward across the entire home coast (`12` columns deep × full grid height) so enemy blockades
/// can NEVER trap or spawn-camp a returning player!
fn sortie_ship_internal(
    bid: &[u8; 32],
    hdr: &BattleHeader,
    caller: &[u8; 20],
    pid: u8,
    slot_idx: u64,
    blk32: u32,
) -> Result<(u8, u8), i32> {
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let mut ship = load_ship(bid, gidx);
    let mut meta = promote_matured_recall(bid, gidx, &mut ship, blk32);
    if ship.alive != SHIP_DOCKED {
        return Err(-85);
    }

    let (w, h) = ship_dims(ship.class_id, 0);
    let (_bx0, by0, _bx1, by1) = naval_base_rect(ship.team, hdr.grid_w, hdr.grid_h);
    let mid_y = ((by0 as u16 + by1 as u16) / 2) as i16;
    let max_y = (hdr.grid_h.saturating_sub(h)) as i16;
    let max_x = (hdr.grid_w.saturating_sub(w)) as i16;

    let mut chosen: Option<(u8, u8)> = None;
    let mut col_step = 0i16;
    while col_step <= max_x && chosen.is_none() {
        let cand_x = if ship.team == TEAM_RED {
            col_step
        } else {
            (max_x - col_step).max(0)
        };
        let mut dy_mag = 0i16;
        while dy_mag <= (hdr.grid_h as i16) {
            let signs: [i16; 2] = if dy_mag == 0 { [0, 0] } else { [-1, 1] };
            let sign_count = if dy_mag == 0 { 1usize } else { 2usize };
            let mut si = 0usize;
            while si < sign_count {
                let cy = mid_y + signs[si] * dy_mag + (slot_idx as i16 - 1);
                if cy >= 0 && cy <= max_y && cand_x >= 0 && cand_x <= max_x {
                    let mut cand = ship;
                    cand.alive = SHIP_ALIVE;
                    cand.dir = 0;
                    cand.x = cand_x as u8;
                    cand.y = cy as u8;
                    cand.pad = if ship.team == TEAM_RED { 2 } else { 6 };
                    if !ship_in_enemy_base(&cand, hdr.grid_w, hdr.grid_h)
                        && check_ship_placement_free(
                            bid,
                            hdr.player_count,
                            hdr.grid_w,
                            hdr.grid_h,
                            gidx,
                            &cand,
                        )
                    {
                        chosen = Some((cand.x, cand.y));
                        break;
                    }
                }
                si += 1;
            }
            if chosen.is_some() {
                break;
            }
            dy_mag += 1;
        }
        col_step += 1;
    }

    let (sx, sy) = chosen.ok_or(-86)?;
    ship.alive = SHIP_ALIVE;
    ship.dir = 0;
    ship.x = sx;
    ship.y = sy;
    ship.pad = if ship.team == TEAM_RED { 2 } else { 6 };
    ship.last_move_block = blk32;
    ship.flash_x = 255;
    ship.flash_y = 255;
    meta.recall_ready_block = 0;
    meta.last_sortie_block = blk32;

    save_ship(bid, gidx, &ship);
    save_base_meta(bid, gidx, &meta);

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&slot_idx.to_be_bytes());
    ev[8..16].copy_from_slice(&(sx as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&(sy as u64).to_be_bytes());
    ev[24..32].copy_from_slice(&(ship.pad as u64).to_be_bytes());
    events::emit(&[EV_SHIP_SORTIED, *bid, addr_topic(caller)], &ev);
    Ok((sx, sy))
}

fn handle_return_ship_to_base(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-80);
    }
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let blk32 = context::block_number() as u32;
    let mode = return_ship_internal(&bid, &hdr, &caller, pid, slot_idx, blk32)?;
    save_hdr(&bid, &hdr);
    ret::write_u64_word(mode);
    Ok(mode as i32)
}

fn handle_return_fleet_to_base(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let blk32 = context::block_number() as u32;

    let mut processed = 0u64;
    let mut last_err: i32 = -80;
    let mut slot = 0u64;
    while slot < SHIPS_PER_PLAYER {
        match return_ship_internal(&bid, &hdr, &caller, pid, slot, blk32) {
            Ok(_) => processed += 1,
            Err(e) => {
                if e != -80 && e != -81 {
                    last_err = e;
                } else if last_err == -80 {
                    last_err = e;
                }
            }
        }
        slot += 1;
    }
    if processed == 0 {
        return Err(last_err);
    }
    save_hdr(&bid, &hdr);
    ret::write_u64_word(processed);
    Ok(processed as i32)
}

fn handle_sortie_ship_from_base(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-85);
    }
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let blk32 = context::block_number() as u32;
    let (sx, sy) = sortie_ship_internal(&bid, &hdr, &caller, pid, slot_idx, blk32)?;
    save_hdr(&bid, &hdr);
    let packed = ((sx as u64) << 8) | (sy as u64);
    ret::write_u64_word(packed);
    Ok(packed as i32)
}

fn handle_sortie_fleet_from_base(args: &CalldataReader) -> Result<i32, i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    sync_pending_shells(&bid, &mut hdr);
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let blk32 = context::block_number() as u32;

    let mut launched = 0u64;
    let mut slot = 0u64;
    while slot < SHIPS_PER_PLAYER {
        if sortie_ship_internal(&bid, &hdr, &caller, pid, slot, blk32).is_ok() {
            launched += 1;
        }
        slot += 1;
    }
    if launched == 0 {
        return Err(-85);
    }
    save_hdr(&bid, &hdr);
    ret::write_u64_word(launched);
    Ok(launched as i32)
}

fn handle_cancel_recall(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    if slot_idx >= SHIPS_PER_PLAYER {
        return Err(-80);
    }
    let caller = context::msg_sender();
    let pid = find_pid(&bid, &caller).ok_or(-21)?;
    let gidx = (pid as u16) * 3 + (slot_idx as u16);
    let blk32 = context::block_number() as u32;
    let mut ship = load_ship(&bid, gidx);
    let mut meta = promote_matured_recall(&bid, gidx, &mut ship, blk32);
    if ship.alive != SHIP_ALIVE || meta.recall_ready_block <= blk32 {
        return Err(-87);
    }
    meta.recall_ready_block = 0;
    save_base_meta(&bid, gidx, &meta);
    Ok(())
}

/// Permissionless periodic shell-resolution sweep (no authentication or authorization required;
/// guarded against being called more than once per block per battle).
fn handle_resolve_shells(args: &CalldataReader) -> Result<(), i32> {
    let bid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&bid).ok_or(-13)?;
    let now = context::block_number();
    let set_key = KeyBuilder::<48>::new().push(b"b:rs_s:").push(&bid);
    let blk_key = KeyBuilder::<48>::new().push(b"b:rs_b:").push(&bid);
    if storage::get_u64(set_key.as_slice()) == 1 && storage::get_u64(blk_key.as_slice()) == now {
        return Err(ERR_ALREADY_EXECUTED_IN_BLOCK);
    }
    storage::set_u64(set_key.as_slice(), 1);
    storage::set_u64(blk_key.as_slice(), now);
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

    let blk32 = context::block_number() as u32;
    let mut pos = 36usize;
    let mut alive_n = 0u16;
    let total_slots = (hdr.player_count as u16).min(MAX_PLAYERS as u16) * 3;
    let mut g = 0u16;
    while g < total_slots {
        let mut sh = load_ship(&bid, g);
        if sh.alive != 0 {
            if sh.alive == SHIP_ALIVE {
                let meta = load_base_meta(&bid, g);
                if meta.recall_ready_block > 0 {
                    if blk32 >= meta.recall_ready_block {
                        let (bx0, by0, _, _) = naval_base_rect(sh.team, hdr.grid_w, hdr.grid_h);
                        sh.alive = SHIP_DOCKED;
                        sh.x = bx0;
                        sh.y = by0;
                    } else {
                        sh.alive = SHIP_RECALLING_VIEW;
                        sh.flash_x = (meta.recall_ready_block - blk32).min(250) as u8;
                    }
                }
            } else if sh.alive == SHIP_DOCKED {
                let (bx0, by0, _, _) = naval_base_rect(sh.team, hdr.grid_w, hdr.grid_h);
                sh.x = bx0;
                sh.y = by0;
            }
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

        // Verify destination outside max range circle (`max_rng = 12`) is rejected (`-34`)!
        mock::set_block_number(601);
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .push_u64(25) // dx=22 > 12!
                    .push_u64(18)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(-34)
        );

        // Free 2D move inside Gunboat's 12-tile circle (even off-axis, e.g. `(3, 18) -> (9, 12)`, `dx=6, dy=-6`, `dist_sq=72 <= 144`)!
        let mv_out = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0) // slot 0
                .push_u64(9)
                .push_u64(12)
                .push_u64(0)
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

        // Red moves Gunboat directly to `(12, 12)` and fires Autocannon (`range 10`) at `(20, 12)`!
        mock::set_block_number(602);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(12)
                .push_u64(12)
                .push_u64(0)
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

        // Blue can Upgrade Engine + Move + Fire + Repair ALL in the SAME block (603), while a 2nd Move or 2nd Repair in block 603 is rejected!
        mock::set_block_number(603);
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("upgradeArmor(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(16)
                .push_u64(12)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(12)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("repairShip(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Verify a 2nd moveShip in the same block 603 is rejected (-32)
        assert_eq!(
            mock::transact_as(
                blue_p,
                CONTRACT,
                CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .push_u64(14)
                    .push_u64(12)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(-32)
        );
    }

    #[test]
    fn full_board_placement_and_vessel_ramming_collision() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(700);

        let bid = [0x33; 32];
        let red_p = [0xC1; 20];
        let blue_p = [0xD2; 20];

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

        // 1. Full-board placement: Red places Cruiser (4x1) on the EAST half (x=28, y=10) & Blue places Gunboat (2x1) at (34, 10)!
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2) // Cruiser (4x1, max speed 6)
                .push_u64(28)
                .push_u64(10)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(0) // Gunboat (2x1)
                .push_u64(34)
                .push_u64(10)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // 2. Red moves Cruiser directly to `(34, 10)` inside its 6-tile max range, overlapping Blue's Gunboat at `(34..36, 10)`!
        mock::set_block_number(701);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("moveShip(bytes32,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(34)
                .push_u64(10)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        let st = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("getBattleState(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();

        // Blue's Gunboat had both squares crushed (sunk -> alive_n == 1, red_kills == 1)!
        let alive_n = u16::from_be_bytes([st[32], st[33]]);
        let red_kills = u32::from_be_bytes([st[8], st[9], st[10], st[11]]);
        assert_eq!(alive_n, 1);
        assert_eq!(red_kills, 1);

        // Red's Cruiser survived at (34, 10) with cells 0 & 1 destroyed (100) and cells 2 & 3 intact (0)!
        assert_eq!(st[38 + 7], 34);
        assert_eq!(st[38 + 8], 10);
        assert_eq!(st[38 + 10], 100);
        assert_eq!(st[38 + 11], 100);
        assert_eq!(st[38 + 12], 0);
        assert_eq!(st[38 + 13], 0);
    }

    #[test]
    fn game_over_start_anew_applies_50_pct_score_penalty_and_preserves_best_score() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(900);

        let bid = [0x99; 32];
        let red_p = [0xA1; 20];
        let blue_p = [0xB1; 20];

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

        // Red spends 900 CR (`1000 -> 100 CR`) on Cruiser (550) + Frigate (350) — wait: let's buy 1 Cruiser (550) + upgrade gun Howitzer (450) = 1000 CR (`0 CR` left)!
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2) // Cruiser (550 CR, 4x1)
                .push_u64(10)
                .push_u64(10)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("upgradeGun(bytes32,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2) // Howitzer (450 CR) -> Red now has 0 CR!
                .as_slice(),
        )
        .unwrap();

        // Blue buys 2 Gunboats at (15, 10) and (25, 10)
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(0)
                .push_u64(15)
                .push_u64(10)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .push_u64(2) // Cruiser + Howitzer to sink Red
                .push_u64(10)
                .push_u64(16)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Red sinks Blue's Gunboat #0 at (15..16, 10) with Howitzer (`+` cross):
        // -> Red earns `2 * 120 + 120 = 360 CR`, and Score = `2 * 100 + 250 = 450 pts` (best_score = 450)!
        mock::set_block_number(901);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(15)
                .push_u64(10)
                .as_slice(),
        )
        .unwrap();

        // Red spends 200 CR on Engine Tier 1 -> 160 CR (< 200 CR!)
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<160>::new(selector("upgradeArmor(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // `startAnew` while Red still has an alive ship MUST fail with `-27`!
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<192>::new(selector("startAnew(bytes32,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(1)
                    .push_u64(255)
                    .push_u64(255)
                    .as_slice(),
            ),
            Err(-27)
        );

        // Blue destroys all 4 cells of Red's Cruiser across 4 blocks -> Red has 0 alive ships & 160 CR (< 200 CR)!
        for (idx, cx) in [10u64, 11, 12, 13].iter().enumerate() {
            mock::set_block_number(902 + idx as u64);
            mock::transact_as(
                blue_p,
                CONTRACT,
                CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(1)
                    .push_u64(*cx)
                    .push_u64(10)
                    .as_slice(),
            )
            .unwrap();
        }

        // Buying a Gunboat directly MUST fail (`-23`) because free stipend is removed (true Game Over)!
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .push_u64(0)
                    .push_u64(5)
                    .push_u64(5)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(-23)
        );

        // Now `startAnew` succeeds: score `450 -> 225` (-50%), `best_score == 450`, `restarts == 1`, `credits == 1000 - 350 == 650`!
        mock::set_block_number(910);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("startAnew(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1) // Frigate (350 CR)
                .push_u64(255)
                .push_u64(255)
                .as_slice(),
        )
        .unwrap();

        let plrs_raw = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<160>::new(selector("getPlayersSlice(bytes32,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(10)
                .as_slice(),
        )
        .unwrap();
        let rec0 = PlayerRec::decode(plrs_raw[8..8 + PLR_LEN].try_into().unwrap());
        assert_eq!(rec0.restarts, 1);
        assert_eq!(rec0.credits, 650);
        assert_eq!(rec0.score, 225);
        assert_eq!(rec0.best_score, 450);

        // Permissionless `resolvePendingShells` succeeds once in block #910, and rejects a second call in #910!
        let res_cd = CallEncoder::<64>::new(selector("resolvePendingShells(bytes32)")).push_bytes32(&bid);
        mock::transact_as([0xEE; 20], CONTRACT, res_cd.as_slice()).unwrap();
        assert_eq!(
            mock::transact_as([0xEE; 20], CONTRACT, res_cd.as_slice()),
            Err(ERR_ALREADY_EXECUTED_IN_BLOCK)
        );
    }

    #[test]
    fn naval_base_dock_out_of_combat_recall_and_anti_teleport_abuse() {
        mock::reset();
        mock::register_hps(CONTRACT, dispatch_calldata);
        mock::set_block_number(1000);

        let bid = [0x77; 32];
        let red_p = [0xC1; 20];
        let blue_p = [0xD2; 20];

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

        // 1. Enemy harbor exclusion: Red cannot deploy inside Blue's SE Harbor (`x=36..=39, y=20..=24`)!
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .push_u64(0)
                    .push_u64(37)
                    .push_u64(22)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(-29)
        );

        // 2. Red deploys Slot 0 inside Red NW Harbor `(1, 2)` and Slot 1 mid-ocean `(15, 12)`
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(1) // Frigate
                .push_u64(1)
                .push_u64(2)
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
                .push_u64(2) // Cruiser (4 cells)
                .push_u64(15)
                .push_u64(12)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // Blue deploys Cruiser within gun range at `(21, 12)`
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<256>::new(selector("buyShip(bytes32,uint64,uint64,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(2)
                .push_u64(21)
                .push_u64(12)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();

        // 3. Inside Harbor: Slot 0 docks INSTANTLY (`mode = 1 -> SHIP_DOCKED = 2`)!
        let dock0 = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("returnShipToBase(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(dock0[24..32].try_into().unwrap()), 1);

        // 4. Anti-Panic-Teleport: Blue hits Red's mid-ocean Slot 1 at block 1001 -> Red CANNOT recall (`-83`)!
        mock::set_block_number(1001);
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(15)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<128>::new(selector("returnShipToBase(bytes32,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(1)
                    .as_slice(),
            ),
            Err(-83)
        );

        // 5. After 3 quiet blocks (`1004 >= 1001 + 3`), Red starts Out-of-Combat Recall (`mode = 2`, ready at 1007)!
        mock::set_block_number(1004);
        let rec1 = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("returnShipToBase(bytes32,uint64)"))
                .push_bytes32(&bid)
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rec1[24..32].try_into().unwrap()), 2);

        // While recalling (block 1005), Red Slot 1 cannot fire (`-84`), and if Blue hits it at 1005, recall CANCELS!
        mock::set_block_number(1005);
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(1)
                    .push_u64(21)
                    .push_u64(12)
                    .as_slice(),
            ),
            Err(-84)
        );
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(16)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();
        let read_ship_from_state = |target_gidx: u16| -> ShipRec {
            let st = mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<128>::new(selector("getBattleState(bytes32)"))
                    .push_bytes32(&bid)
                    .as_slice(),
            )
            .unwrap();
            let count = u16::from_be_bytes([st[32], st[33]]) as usize;
            let mut pos = 36usize;
            for _ in 0..count {
                let g = u16::from_be_bytes([st[pos], st[pos + 1]]);
                let sh = ShipRec::decode(st[pos + 2..pos + 34].try_into().unwrap());
                if g == target_gidx {
                    return sh;
                }
                pos += 34;
            }
            ShipRec::empty()
        };

        // Verify recall was cancelled (still `SHIP_ALIVE == 1` even at block 1008!)
        mock::set_block_number(1008);
        assert_eq!(read_ship_from_state(1).alive, SHIP_ALIVE);

        // 6. Out-of-combat again at block 1009 (`>= 1005 + 3`): 1-click `returnFleetToBase` starts tow -> matures at 1012!
        mock::set_block_number(1009);
        mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("returnFleetToBase(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();
        // At block 1010 (`2` blocks remaining), view reports `SHIP_RECALLING_VIEW == 3` with `flash_x == 2`!
        mock::set_block_number(1010);
        let towing_sh = read_ship_from_state(1);
        assert_eq!(towing_sh.alive, SHIP_RECALLING_VIEW);
        assert_eq!(towing_sh.flash_x, 2);

        // Even with ZERO transactions from Red after block 1009, Blue shooting `(17, 12)` at block 1012 deals 0 damage because Slot 1 auto-docked!
        mock::set_block_number(1012);
        mock::transact_as(
            blue_p,
            CONTRACT,
            CallEncoder::<192>::new(selector("fireWeapon(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&bid)
                .push_u64(0)
                .push_u64(17)
                .push_u64(12)
                .as_slice(),
        )
        .unwrap();
        let docked_sh = read_ship_from_state(1);
        assert_eq!(docked_sh.alive, SHIP_DOCKED);
        assert_eq!(docked_sh.cell_dmg[2], 0); // Intact!

        // 7. 1-click `sortieFleetFromBase` launches both Red ships (`Slot 0` and `Slot 1`) back to sea, and blocks immediate re-dock (`-82`)!
        mock::set_block_number(1015);
        let sort_out = mock::transact_as(
            red_p,
            CONTRACT,
            CallEncoder::<128>::new(selector("sortieFleetFromBase(bytes32)"))
                .push_bytes32(&bid)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(sort_out[24..32].try_into().unwrap()), 2);
        assert_eq!(read_ship_from_state(0).alive, SHIP_ALIVE);
        assert_eq!(read_ship_from_state(1).alive, SHIP_ALIVE);

        // Anti-Sniping: immediate re-dock right after sortie MUST fail (`-82`)!
        assert_eq!(
            mock::transact_as(
                red_p,
                CONTRACT,
                CallEncoder::<128>::new(selector("returnShipToBase(bytes32,uint64)"))
                    .push_bytes32(&bid)
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(-82)
        );
    }
}
