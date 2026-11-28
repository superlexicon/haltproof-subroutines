//! # Haltfree Ecosystem v2.0 (`haltfree-ecosystem` — HPS #29)
//!
//! Turn-Based On-Chain Closed-Loop Permaculture, Polyculture Aquaculture & Biospheric Game
//! Halt-Free Subroutine (`$0.00` gas on Subnet 1).
//!
//! Every single season (`Round 1..=8`) is an authentic on-chain state transition:
//! 1. Player calls `startRun(arenaId, identity)` -> HFS initializes an 8-season expedition on-chain
//!    and emits `RunStarted(identity, RoundSnapshot64)`.
//! 2. Each season, the player selects ONE tactical action — either stocking/upgrading one of the
//!    6 ecological niches (`actionKind = 0`) or executing a seasonal stewardship move
//!    (`actionKind = 1`: Dredge Silt, Bio-Aerate, or Autonomous Hands-Off Loop) — and submits
//!    `playRound(identity, actionKind, target, choice)`.
//! 3. When the Subnet 1 block confirms, the HFS resolves trophic food-web couplings, weather
//!    hazards, symbiosis combos, toxin debt, harvest yield, and halt/victory conditions, then
//!    emits `RoundResolved(identity, RoundSnapshot64)` for the 60-FPS `<canvas>` to animate!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::{context, event_topic, events, hps_entry, keccak, ret, selector, storage};

pub const NUM_ARENAS: usize = 4;
pub const NUM_SLOTS: usize = 6;
pub const NUM_CHOICES: usize = 4; // 0 = Unstocked wild baseline, 1..=3 = Player choices
pub const MAX_ROUNDS: u8 = 8;
pub const MAX_LEADERBOARD: usize = 16;
pub const MAX_RECENT_LOGS: usize = 12;

// Run status codes
pub const STATUS_NONE: u8 = 0;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_HALTED: u8 = 2;
pub const STATUS_VICTORY: u8 = 3;

// Diagnostic Halt Codes (`0` = Healthy / Perpetual Halt-Free Loop!)
pub const HALT_NONE: u8 = 0;
pub const HALT_EUTROPHICATION: u8 = 1;
pub const HALT_HYPOXIA: u8 = 2;
pub const HALT_AMMONIA_TOXICITY: u8 = 3;
pub const HALT_TROPHIC_PREDATION: u8 = 4;
pub const HALT_NUTRIENT_STARVATION: u8 = 5;
pub const HALT_EXTERNAL_DEPENDENCY: u8 = 6;

// Seasonal Weather Codes (`0..=5`)
pub const WEATHER_SUNNY: u8 = 0;
pub const WEATHER_ALGAE_SURGE: u8 = 1;
pub const WEATHER_MONSOON: u8 = 2;
pub const WEATHER_HEATWAVE: u8 = 3;
pub const WEATHER_HARVEST_BREEZE: u8 = 4;
pub const WEATHER_SOLAR_DIM: u8 = 5;

// Symbiosis & Tactical Combo Codes (`0..=8`)
pub const COMBO_NONE: u8 = 0;
pub const COMBO_CANOPY_SYMBIOSIS: u8 = 1;
pub const COMBO_WATER_STRATA_GUILD: u8 = 2;
pub const COMBO_BENTHIC_RETURN: u8 = 3;
pub const COMBO_ROOT_SHIELD: u8 = 4;
pub const COMBO_BLOOM_FEAST: u8 = 5;
pub const COMBO_FULL_SIX_LOOP: u8 = 6;
pub const COMBO_AUTONOMOUS_INFINITE: u8 = 7;
pub const COMBO_STEWARD_RESCUE: u8 = 8;

// Unlockable Eco-Scholar Badges (`u8` bitmask)
pub const BADGE_SANGJI_MASTER: u8 = 1 << 0;
pub const BADGE_AXOLOTL_GUARDIAN: u8 = 1 << 1;
pub const BADGE_NITROGEN_ALCHEMIST: u8 = 1 << 2;
pub const BADGE_MARS_PIONEER: u8 = 1 << 3;
pub const BADGE_HANDS_FREE_LOOP: u8 = 1 << 4;
pub const BADGE_GRAND_PERMACULTURIST: u8 = 1 << 5;

// Niche ecological classification flags
const KIND_EMPTY: u8 = 0;
const KIND_LOOP: u8 = 1;
const KIND_MISMATCH: u8 = 2;
const KIND_PREDATOR: u8 = 3;
const KIND_SHORTCUT: u8 = 4;

const KEY_META: &[u8] = b"hfe2:meta";
const KEY_GLOBAL: &[u8] = b"hfe2:global";
const KEY_LEADERS: &[u8] = b"hfe2:leaders";
const KEY_LOGS: &[u8] = b"hfe2:logs";

pub const EV_RUN_STARTED: [u8; 32] = event_topic("RunStarted(address,bytes)");
pub const EV_ROUND_RESOLVED: [u8; 32] = event_topic("RoundResolved(address,bytes)");

const SEL_ID_OWNER: [u8; 4] = selector("owner()");
const SEL_ID_IS_DEVICE: [u8; 4] = selector("isOwnerDevice(address)");

#[derive(Clone, Copy)]
pub struct NicheSpec {
    pub d_o2: i16,
    pub d_clarity: i16,
    pub d_fertility: i16,
    pub d_clean: i16,
    pub base_yield: u16,
    pub kind: u8,
}

const fn sp(
    d_o2: i16,
    d_clarity: i16,
    d_fertility: i16,
    d_clean: i16,
    base_yield: u16,
    kind: u8,
) -> NicheSpec {
    NicheSpec {
        d_o2,
        d_clarity,
        d_fertility,
        d_clean,
        base_yield,
        kind,
    }
}

/// Starting `(o2, clarity, fertility, cleanliness)` per Arena (`0..=3`).
pub const ARENA_START_VITALS: [[u8; 4]; NUM_ARENAS] = [
    [68, 62, 52, 70], // Arena 0: Mulberry-Dyke Pond (Beginner ★☆☆☆)
    [62, 58, 48, 64], // Arena 1: Aztec Chinampa & Axolotl Canal (Intermediate ★★☆☆)
    [58, 62, 44, 58], // Arena 2: Solar Aquaponics Bio-Dome (Advanced ★★★☆)
    [54, 58, 42, 52], // Arena 3: Sealed Martian Biosphere BIOS-IV (Master ★★★★)
];

/// Optimal Closed-Loop Choice (`1..=3`) per `(arena, slot)`:
/// - Arena 0: `[2, 1, 3, 1, 2, 3]`
/// - Arena 1: `[1, 3, 1, 2, 3, 1]`
/// - Arena 2: `[2, 1, 3, 1, 2, 2]`
/// - Arena 3: `[3, 1, 2, 2, 2, 1]`
pub const ECOLOGY_SPECS: [[[NicheSpec; NUM_CHOICES]; NUM_SLOTS]; NUM_ARENAS] = [
    // =========================================================================
    // ARENA 0: 2,400-Year-Old Mulberry-Dyke Carp Polyculture (Sangji Yutang)
    // =========================================================================
    [
        // Z0 Shoreline Dyke: 0 Bare, 1 Pine Conifers, 2 Mulberry Trees ✅, 3 Pesticide Cash-Corn ⚠️
        [
            sp(-1, -3, -2, -1, 0, KIND_EMPTY),
            sp(2, -4, -6, -3, 14, KIND_MISMATCH),
            sp(6, 5, 4, 4, 34, KIND_LOOP),
            sp(-3, -8, -8, -16, 72, KIND_SHORTCUT),
        ],
        // Z1 Tree Canopy: 0 Empty, 1 Silkworm Colony ✅, 2 Locust Swarm ❌, 3 Diesel Pellet Feeder ⚠️
        [
            sp(0, -1, -2, 0, 0, KIND_EMPTY),
            sp(1, -2, 8, 2, 36, KIND_LOOP),
            sp(-3, -5, -14, -4, 24, KIND_PREDATOR),
            sp(-6, -10, 4, -14, 64, KIND_SHORTCUT),
        ],
        // Z2 Surface Water (0-0.5m): 0 Bare, 1 Snakehead Predator ❌, 2 Overcrowded Koi, 3 Grass Carp & Duckweed ✅
        [
            sp(-2, -2, -1, 0, 0, KIND_EMPTY),
            sp(-3, 0, -12, -4, 16, KIND_PREDATOR),
            sp(-16, -5, -2, -6, 20, KIND_MISMATCH),
            sp(8, 2, 6, 2, 38, KIND_LOOP),
        ],
        // Z3 Upper-Mid (0.5-1.5m): 0 Empty, 1 Silver Carp ✅, 2 Copper Algicide ⚠️, 3 Cold-River Trout
        [
            sp(-1, -4, 0, -1, 0, KIND_EMPTY),
            sp(4, 14, 2, 4, 40, KIND_LOOP),
            sp(-6, 12, -14, -20, 12, KIND_SHORTCUT),
            sp(-14, -2, -3, -4, 15, KIND_MISMATCH),
        ],
        // Z4 Lower-Mid (1.5-2.5m): 0 Empty, 1 Northern Pike ❌, 2 Bighead Carp ✅, 3 Saltwater Krill
        [
            sp(-1, -2, -1, -2, 0, KIND_EMPTY),
            sp(-2, -2, -12, -4, 16, KIND_PREDATOR),
            sp(3, 10, 3, 6, 42, KIND_LOOP),
            sp(-8, -6, -4, -12, 8, KIND_MISMATCH),
        ],
        // Z5 Pond Floor & Loop (2.5-3.5m): 0 Raw Sludge, 1 Concrete Liner, 2 River Flush ⚠️, 3 Black Carp + Silt-to-Dyke ✅
        [
            sp(-2, -1, -2, -4, 0, KIND_EMPTY),
            sp(-2, 4, -14, -8, 10, KIND_MISMATCH),
            sp(2, 5, -18, 6, 12, KIND_SHORTCUT),
            sp(4, 5, 12, 14, 44, KIND_LOOP),
        ],
    ],
    // =========================================================================
    // ARENA 1: Floating Chinampa Island & Axolotl Canal (1150 CE, Xochimilco)
    // =========================================================================
    [
        // Z0 Perimeter: 0 Unanchored, 1 Ahuejote Willows ✅, 2 Eucalyptus, 3 Corroding Sheet Metal ⚠️
        [
            sp(-1, -4, -3, -1, 0, KIND_EMPTY),
            sp(6, 7, 4, 5, 34, KIND_LOOP),
            sp(1, -3, -12, -8, 14, KIND_MISMATCH),
            sp(-2, -4, -5, -15, 18, KIND_SHORTCUT),
        ],
        // Z1 Crop Bed: 0 Bare, 1 Monocrop Wheat, 2 Pesticide Tomatoes ⚠️, 3 Three Sisters ✅
        [
            sp(0, -1, -3, 0, 0, KIND_EMPTY),
            sp(1, 0, -14, -2, 26, KIND_MISMATCH),
            sp(-3, -6, -6, -18, 68, KIND_SHORTCUT),
            sp(4, 2, 12, 3, 46, KIND_LOOP),
        ],
        // Z2 Canal Surface: 0 Bare, 1 Azolla & Duckweed ✅, 2 Water Hyacinth ❌, 3 Mosquito Oil Film ⚠️
        [
            sp(-3, -3, -1, -1, 0, KIND_EMPTY),
            sp(10, 6, 7, 4, 34, KIND_LOOP),
            sp(-22, -12, -4, -6, 10, KIND_PREDATOR),
            sp(-20, -8, -6, -18, 8, KIND_SHORTCUT),
        ],
        // Z3 Mid-Canal: 0 Empty, 1 Invasive Bottom Carp, 2 Native Acocil Crayfish ✅, 3 Piranha Pack ❌
        [
            sp(-1, -3, -1, -2, 0, KIND_EMPTY),
            sp(-4, -18, -4, -8, 22, KIND_MISMATCH),
            sp(4, 10, 4, 10, 38, KIND_LOOP),
            sp(-4, -4, -14, -6, 14, KIND_PREDATOR),
        ],
        // Z4 Bio-Indicator: 0 None, 1 Cane Toads ❌, 2 Chlorine Pump ⚠️, 3 Axolotl & Tree Frogs ✅
        [
            sp(-1, -1, -2, -2, 0, KIND_EMPTY),
            sp(-3, -4, -8, -16, 8, KIND_PREDATOR),
            sp(-6, 8, -16, -18, 10, KIND_SHORTCUT),
            sp(5, 6, 4, 8, 44, KIND_LOOP),
        ],
        // Z5 Fertility Loop: 0 Sink Muck, 1 Scoop Muck + Tule Reeds ✅, 2 Synthetic NPK ⚠️, 3 Burn Stalks
        [
            sp(-2, -2, -4, -4, 0, KIND_EMPTY),
            sp(4, 8, 14, 15, 44, KIND_LOOP),
            sp(-6, -18, 8, -16, 66, KIND_SHORTCUT),
            sp(-10, -6, -14, -6, 12, KIND_MISMATCH),
        ],
    ],
    // =========================================================================
    // ARENA 2: Solar Aquaponics & Microbial Nitrification Bio-Dome
    // =========================================================================
    [
        // Z0 Fish Tank: 0 Empty, 1 Ocean Bluefin Tuna, 2 Nile Tilapia School ✅, 3 5x Catfish Jam ⚠️
        [
            sp(0, 0, -5, 0, 0, KIND_EMPTY),
            sp(-22, -6, -4, -12, 12, KIND_MISMATCH),
            sp(-3, -2, 10, -3, 44, KIND_LOOP),
            sp(-18, -12, 8, -20, 66, KIND_SHORTCUT),
        ],
        // Z1 Solids Separator: 0 Raw Sludge, 1 Swirl Clarifier + Red Worms ✅, 2 Bleach Filter ⚠️, 3 Sewer Flush ⚠️
        [
            sp(-2, -4, -2, -4, 0, KIND_EMPTY),
            sp(3, 10, 9, 9, 34, KIND_LOOP),
            sp(-8, 6, -18, -22, 6, KIND_SHORTCUT),
            sp(1, 6, -18, 4, 10, KIND_SHORTCUT),
        ],
        // Z2 Bio-Reactor: 0 Smooth Marbles, 1 Stagnant Mud, 2 UV on Bio-Media, 3 Clay + Nitrifying Microbes ✅
        [
            sp(-1, -2, -2, -4, 0, KIND_EMPTY),
            sp(-10, -10, -4, -14, 6, KIND_MISMATCH),
            sp(-2, 4, -12, -14, 10, KIND_MISMATCH),
            sp(3, 8, 12, 18, 38, KIND_LOOP),
        ],
        // Z3 Hydroponic Rafts: 0 Empty Rafts, 1 Basil/Lettuce/Strawberries ✅, 2 Oak Saplings, 3 Plastic Plants
        [
            sp(-1, -4, 0, -2, 0, KIND_EMPTY),
            sp(6, 12, 2, 10, 56, KIND_LOOP),
            sp(1, -8, -8, -4, 14, KIND_MISMATCH),
            sp(-2, -12, -4, -10, 0, KIND_MISMATCH),
        ],
        // Z4 O2 & Pollination: 0 Still Water, 1 Diesel Compressor ⚠️, 2 Solar Venturi + Bees ✅, 3 Pure CO2 Bubbler
        [
            sp(-5, -1, -1, -1, 0, KIND_EMPTY),
            sp(8, -4, -2, -14, 24, KIND_SHORTCUT),
            sp(18, 6, 4, 5, 42, KIND_LOOP),
            sp(-22, -2, -4, -8, 8, KIND_MISMATCH),
        ],
        // Z5 Sump & pH Loop: 0 One-Way Drain, 1 Table Salt NaCl, 2 Recirc Sump + Eggshell/Kelp ✅, 3 Sulfuric Acid ⚠️
        [
            sp(-1, -1, -3, -2, 0, KIND_EMPTY),
            sp(-4, -4, -20, -12, 6, KIND_MISMATCH),
            sp(6, 6, 10, 10, 36, KIND_LOOP),
            sp(-6, 2, -14, -20, 8, KIND_SHORTCUT),
        ],
    ],
    // =========================================================================
    // ARENA 3: Sealed Martian Biospheric Habitat ("BIOS-IV")
    // =========================================================================
    [
        // Z0 Primary O2 Reactor: 0 Dormant, 1 Chemical O2 Candles ⚠️, 2 Slow Cacti, 3 Spirulina Photobioreactor ✅
        [
            sp(-6, -1, -2, -1, 0, KIND_EMPTY),
            sp(10, -4, -10, -12, 18, KIND_SHORTCUT),
            sp(-12, 0, -4, 0, 12, KIND_MISMATCH),
            sp(18, 5, 5, 5, 46, KIND_LOOP),
        ],
        // Z1 Aquatic Mini-Loop: 0 Dry Basin, 1 Azolla + Medaka/Loach ✅, 2 Tank Sharks ❌, 3 Stagnant Greywater
        [
            sp(-1, -3, -3, -2, 0, KIND_EMPTY),
            sp(6, 10, 10, 7, 42, KIND_LOOP),
            sp(-24, -8, -12, -10, 10, KIND_PREDATOR),
            sp(-6, -14, -4, -16, 4, KIND_MISMATCH),
        ],
        // Z2 Crop Terrace: 0 Fallow, 1 Thirsty Almonds, 2 Dwarf Wheat + Sweet Potato + Soy ✅, 3 Sugar Cane Only
        [
            sp(-2, -1, -2, -1, 0, KIND_EMPTY),
            sp(-8, -4, -14, -2, 18, KIND_MISMATCH),
            sp(8, 4, 8, 4, 54, KIND_LOOP),
            sp(2, -4, -16, -4, 26, KIND_MISMATCH),
        ],
        // Z3 Stalk Recycler: 0 Pile Straw, 1 Incinerator Furnace, 2 Oyster Mushrooms + Worms ✅, 3 Airlock Jettison ⚠️
        [
            sp(-1, -2, -3, -2, 0, KIND_EMPTY),
            sp(-22, -16, -8, -10, 8, KIND_MISMATCH),
            sp(2, 6, 14, 10, 44, KIND_LOOP),
            sp(-4, 2, -20, 2, 6, KIND_SHORTCUT),
        ],
        // Z4 Waste & Water Recovery: 0 Holding Tank, 1 Raw Vent, 2 Soldier-Fly + Condenser ✅, 3 Lye Boil ⚠️
        [
            sp(-2, -4, -2, -5, 0, KIND_EMPTY),
            sp(-12, -12, -6, -20, 4, KIND_MISMATCH),
            sp(5, 14, 8, 12, 40, KIND_LOOP),
            sp(-8, 4, -10, -18, 10, KIND_SHORTCUT),
        ],
        // Z5 Regolith Detox: 0 Raw Mars Dust, 1 Perchlorate Bacteria + Mycorrhizae ✅, 2 Unwashed Regolith, 3 Resupply Rocket ⚠️
        [
            sp(-1, -2, -2, -5, 0, KIND_EMPTY),
            sp(8, 6, 12, 18, 40, KIND_LOOP),
            sp(-6, -8, -10, -24, 6, KIND_MISMATCH),
            sp(2, 2, -10, -10, 50, KIND_SHORTCUT),
        ],
    ],
];

/// Persistent Career Passport per Identity (`40 bytes` serialized).
#[derive(Clone, Copy)]
pub struct PlayerProgress {
    pub identity: [u8; 20],
    pub best_stars: [u8; NUM_ARENAS],
    pub best_yield: [u16; NUM_ARENAS],
    pub total_xp: u32,
    pub runs_started: u16,
    pub runs_won: u16,
    pub badges: u8,
    pub best_streak: u8,
    pub solved_mask: u8,
}

impl PlayerProgress {
    pub fn empty(identity: [u8; 20]) -> Self {
        Self {
            identity,
            best_stars: [0; NUM_ARENAS],
            best_yield: [0; NUM_ARENAS],
            total_xp: 0,
            runs_started: 0,
            runs_won: 0,
            badges: 0,
            best_streak: 0,
            solved_mask: 0,
        }
    }

    pub fn total_stars(&self) -> u8 {
        self.best_stars[0] + self.best_stars[1] + self.best_stars[2] + self.best_stars[3]
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..20].copy_from_slice(&self.identity);
        b[20..24].copy_from_slice(&self.best_stars);
        b[24..26].copy_from_slice(&self.best_yield[0].to_be_bytes());
        b[26..28].copy_from_slice(&self.best_yield[1].to_be_bytes());
        b[28..30].copy_from_slice(&self.best_yield[2].to_be_bytes());
        b[30..32].copy_from_slice(&self.best_yield[3].to_be_bytes());
        b[32..36].copy_from_slice(&self.total_xp.to_be_bytes());
        b[36..38].copy_from_slice(&self.runs_started.to_be_bytes());
        b[38] = self.badges;
        b[39] = self.solved_mask | ((self.best_streak & 0x0f) << 4);
        b
    }

    pub fn from_bytes(identity: [u8; 20], b: &[u8]) -> Self {
        if b.len() < 40 {
            return Self::empty(identity);
        }
        let mut p = Self::empty(identity);
        p.best_stars.copy_from_slice(&b[20..24]);
        p.best_yield[0] = u16::from_be_bytes([b[24], b[25]]);
        p.best_yield[1] = u16::from_be_bytes([b[26], b[27]]);
        p.best_yield[2] = u16::from_be_bytes([b[28], b[29]]);
        p.best_yield[3] = u16::from_be_bytes([b[30], b[31]]);
        p.total_xp = u32::from_be_bytes([b[32], b[33], b[34], b[35]]);
        p.runs_started = u16::from_be_bytes([b[36], b[37]]);
        p.badges = b[38];
        p.solved_mask = b[39] & 0x0f;
        p.best_streak = (b[39] >> 4) & 0x0f;
        p
    }
}

/// Exact `64-byte` live expedition state & event snapshot (`RoundSnapshot`).
#[derive(Clone, Copy)]
pub struct RunState {
    pub status: u8,
    pub arena_id: u8,
    pub round: u8,
    pub last_round_played: u8,
    pub slots: [u8; NUM_SLOTS],
    pub o2: u8,
    pub clarity: u8,
    pub fertility: u8,
    pub cleanliness: u8,
    pub prev_o2: u8,
    pub prev_clarity: u8,
    pub prev_fertility: u8,
    pub prev_cleanliness: u8,
    pub weather_applied: u8,
    pub upcoming_weather: u8,
    pub last_action_kind: u8,
    pub last_action_target: u8,
    pub last_action_choice: u8,
    pub combo_id: u8,
    pub halt_reason: u8,
    pub loop_links: u8,
    pub stars_earned: u8,
    pub combo_streak: u8,
    pub autonomous_cycles: u8,
    pub toxin_debt: u8,
    pub last_yield: u32,
    pub total_harvest: u32,
    pub xp_gained: u32,
    pub run_number: u32,
    pub badges_unlocked_now: u8,
    pub shortcut_count: u8,
}

impl RunState {
    pub fn empty() -> Self {
        Self {
            status: STATUS_NONE,
            arena_id: 0,
            round: 0,
            last_round_played: 0,
            slots: [0; NUM_SLOTS],
            o2: 0,
            clarity: 0,
            fertility: 0,
            cleanliness: 0,
            prev_o2: 0,
            prev_clarity: 0,
            prev_fertility: 0,
            prev_cleanliness: 0,
            weather_applied: 0,
            upcoming_weather: 0,
            last_action_kind: 255,
            last_action_target: 0,
            last_action_choice: 0,
            combo_id: 0,
            halt_reason: 0,
            loop_links: 0,
            stars_earned: 0,
            combo_streak: 0,
            autonomous_cycles: 0,
            toxin_debt: 0,
            last_yield: 0,
            total_harvest: 0,
            xp_gained: 0,
            run_number: 0,
            badges_unlocked_now: 0,
            shortcut_count: 0,
        }
    }

    pub fn new_expedition(arena_id: usize, run_number: u32, first_weather: u8) -> Self {
        let a = arena_id.min(NUM_ARENAS - 1);
        let sv = ARENA_START_VITALS[a];
        Self {
            status: STATUS_ACTIVE,
            arena_id: a as u8,
            round: 1,
            last_round_played: 0,
            slots: [0; NUM_SLOTS],
            o2: sv[0],
            clarity: sv[1],
            fertility: sv[2],
            cleanliness: sv[3],
            prev_o2: sv[0],
            prev_clarity: sv[1],
            prev_fertility: sv[2],
            prev_cleanliness: sv[3],
            weather_applied: WEATHER_SUNNY,
            upcoming_weather: first_weather % 2, // Season 1 starts Sunny or Warm Bloom
            last_action_kind: 255,
            last_action_target: 0,
            last_action_choice: 0,
            combo_id: COMBO_NONE,
            halt_reason: HALT_NONE,
            loop_links: 0,
            stars_earned: 0,
            combo_streak: 0,
            autonomous_cycles: 0,
            toxin_debt: if a == 3 { 8 } else { 0 }, // Latent Mars regolith trace perchlorate!
            last_yield: 0,
            total_harvest: 0,
            xp_gained: 0,
            run_number,
            badges_unlocked_now: 0,
            shortcut_count: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0] = 2; // Wire schema v2
        b[1] = self.status;
        b[2] = self.arena_id;
        b[3] = self.round;
        b[4] = self.last_round_played;
        b[5] = MAX_ROUNDS;
        b[6..12].copy_from_slice(&self.slots);
        b[12] = self.o2;
        b[13] = self.clarity;
        b[14] = self.fertility;
        b[15] = self.cleanliness;
        b[16] = self.prev_o2;
        b[17] = self.prev_clarity;
        b[18] = self.prev_fertility;
        b[19] = self.prev_cleanliness;
        b[20] = self.weather_applied;
        b[21] = self.upcoming_weather;
        b[22] = self.last_action_kind;
        b[23] = self.last_action_target;
        b[24] = self.last_action_choice;
        b[25] = self.combo_id;
        b[26] = self.halt_reason;
        b[27] = self.loop_links;
        b[28] = self.stars_earned;
        b[29] = self.combo_streak;
        b[30] = self.autonomous_cycles;
        b[31] = self.toxin_debt;
        b[32..36].copy_from_slice(&self.last_yield.to_be_bytes());
        b[36..40].copy_from_slice(&self.total_harvest.to_be_bytes());
        b[40..44].copy_from_slice(&self.xp_gained.to_be_bytes());
        b[44..48].copy_from_slice(&self.run_number.to_be_bytes());
        b[48] = self.badges_unlocked_now;
        b[49] = self.shortcut_count;
        b
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        if b.len() < 64 || b[0] != 2 {
            return Self::empty();
        }
        let mut r = Self::empty();
        r.status = b[1];
        r.arena_id = b[2];
        r.round = b[3];
        r.last_round_played = b[4];
        r.slots.copy_from_slice(&b[6..12]);
        r.o2 = b[12];
        r.clarity = b[13];
        r.fertility = b[14];
        r.cleanliness = b[15];
        r.prev_o2 = b[16];
        r.prev_clarity = b[17];
        r.prev_fertility = b[18];
        r.prev_cleanliness = b[19];
        r.weather_applied = b[20];
        r.upcoming_weather = b[21];
        r.last_action_kind = b[22];
        r.last_action_target = b[23];
        r.last_action_choice = b[24];
        r.combo_id = b[25];
        r.halt_reason = b[26];
        r.loop_links = b[27];
        r.stars_earned = b[28];
        r.combo_streak = b[29];
        r.autonomous_cycles = b[30];
        r.toxin_debt = b[31];
        r.last_yield = u32::from_be_bytes([b[32], b[33], b[34], b[35]]);
        r.total_harvest = u32::from_be_bytes([b[36], b[37], b[38], b[39]]);
        r.xp_gained = u32::from_be_bytes([b[40], b[41], b[42], b[43]]);
        r.run_number = u32::from_be_bytes([b[44], b[45], b[46], b[47]]);
        r.badges_unlocked_now = b[48];
        r.shortcut_count = b[49];
        r
    }
}

#[inline]
fn clamp_pct(v: i16) -> u8 {
    if v <= 0 {
        0
    } else if v >= 100 {
        100
    } else {
        v as u8
    }
}

fn roll_next_weather(arena_id: u8, next_round: u8, seed_byte: u8) -> u8 {
    if next_round <= 1 {
        return WEATHER_SUNNY;
    }
    // Rich seasonal variety tailored to Arena biome
    let pool: [u8; 6] = match arena_id {
        0 => [
            WEATHER_SUNNY,
            WEATHER_ALGAE_SURGE,
            WEATHER_MONSOON,
            WEATHER_HEATWAVE,
            WEATHER_HARVEST_BREEZE,
            WEATHER_ALGAE_SURGE,
        ],
        1 => [
            WEATHER_SUNNY,
            WEATHER_MONSOON,
            WEATHER_ALGAE_SURGE,
            WEATHER_HEATWAVE,
            WEATHER_HARVEST_BREEZE,
            WEATHER_MONSOON,
        ],
        2 => [
            WEATHER_SUNNY,
            WEATHER_HEATWAVE,
            WEATHER_ALGAE_SURGE,
            WEATHER_SOLAR_DIM,
            WEATHER_HARVEST_BREEZE,
            WEATHER_HEATWAVE,
        ],
        _ => [
            WEATHER_SUNNY,
            WEATHER_SOLAR_DIM,
            WEATHER_HEATWAVE,
            WEATHER_SOLAR_DIM,
            WEATHER_HARVEST_BREEZE,
            WEATHER_ALGAE_SURGE,
        ],
    };
    let idx = ((seed_byte as usize) + (next_round as usize) * 3) % 6;
    pool[idx]
}

/// Core deterministic single-season on-chain resolution engine.
pub fn step_ecosystem_round(
    run: &mut RunState,
    action_kind: u8,
    target: u8,
    choice: u8,
    next_weather_seed: u8,
) -> Result<(), i32> {
    if run.status != STATUS_ACTIVE || run.round == 0 || run.round > MAX_ROUNDS {
        return Err(-15);
    }

    let arena = (run.arena_id as usize).min(NUM_ARENAS - 1);
    let cur_round = run.round;

    // Snapshot previous vitals for smooth UI transition & delta badges
    run.prev_o2 = run.o2;
    run.prev_clarity = run.clarity;
    run.prev_fertility = run.fertility;
    run.prev_cleanliness = run.cleanliness;
    run.badges_unlocked_now = 0;
    run.xp_gained = 0;

    let mut d_o2: i16 = 0;
    let mut d_clarity: i16 = 0;
    let mut d_fertility: i16 = 0;
    let mut d_clean: i16 = 0;
    let mut season_yield: u32 = 0;
    let mut combo: u8 = COMBO_NONE;

    let min_before = run.o2.min(run.clarity).min(run.fertility).min(run.cleanliness);

    // 1. Apply Player's Chosen Round Action
    if action_kind == 0 {
        let z = target as usize;
        if z >= NUM_SLOTS || choice == 0 || (choice as usize) >= NUM_CHOICES {
            return Err(-16);
        }
        run.slots[z] = choice;
        run.last_action_kind = 0;
        run.last_action_target = target;
        run.last_action_choice = choice;

        // Immediate deployment boost for newly placed Loop Symbiont
        let placed = ECOLOGY_SPECS[arena][z][choice as usize];
        if placed.kind == KIND_LOOP {
            season_yield += 18;
        } else if placed.kind == KIND_SHORTCUT {
            run.toxin_debt = run.toxin_debt.saturating_add(16).min(100);
        }
    } else if action_kind == 1 {
        if target < 1 || target > 3 {
            return Err(-17);
        }
        run.last_action_kind = 1;
        run.last_action_target = target;
        run.last_action_choice = 0;

        match target {
            // Steward 1: Dredge & Cycle Benthic Silt / Compost
            1 => {
                d_clean += 22;
                d_fertility += 22;
                d_clarity += 6;
                run.toxin_debt = run.toxin_debt.saturating_sub(18);
                season_yield += 35;
                if min_before < 40 {
                    combo = COMBO_STEWARD_RESCUE;
                    season_yield += 25;
                }
            }
            // Steward 2: Solar / Bamboo Splash-Wheel Bio-Aeration
            2 => {
                d_o2 += 28;
                d_clarity += 12;
                d_clean += 6;
                season_yield += 22;
                if min_before < 40 {
                    combo = COMBO_STEWARD_RESCUE;
                    season_yield += 25;
                }
            }
            // Steward 3: Hands-Off Autonomous Closed-Loop Season (resolved after loop count!)
            3 => {}
            _ => return Err(-17),
        }
    } else {
        return Err(-18);
    }

    // 2. Tally Active Guilds Across All 6 Ecological Zones
    let mut loop_links: u8 = 0;
    let mut shortcut_count: u8 = 0;
    let mut predator_count: u8 = 0;
    let mut zone_is_loop = [false; NUM_SLOTS];

    let mut z = 0usize;
    while z < NUM_SLOTS {
        let c = (run.slots[z] as usize).min(NUM_CHOICES - 1);
        let spec = ECOLOGY_SPECS[arena][z][c];
        d_o2 += spec.d_o2;
        d_clarity += spec.d_clarity;
        d_fertility += spec.d_fertility;
        d_clean += spec.d_clean;
        season_yield += spec.base_yield as u32;

        match spec.kind {
            KIND_LOOP => {
                loop_links += 1;
                zone_is_loop[z] = true;
            }
            KIND_SHORTCUT => {
                shortcut_count += 1;
                run.toxin_debt = run.toxin_debt.saturating_add(10).min(100);
            }
            KIND_PREDATOR => {
                predator_count += 1;
            }
            KIND_EMPTY => {
                // Year 2 (`cur_round >= 5`) gently increases pressure on neglected empty niches
                if cur_round >= 5 {
                    d_clarity -= 2;
                    d_fertility -= 2;
                }
            }
            _ => {}
        }
        z += 1;
    }

    run.loop_links = loop_links;
    run.shortcut_count = shortcut_count;

    // Predators eat stocked fish/yield in other niches!
    if predator_count > 0 {
        let penalty = (predator_count as u32) * 28;
        season_yield = season_yield.saturating_sub(penalty);
        d_fertility -= (predator_count as i16) * 5;
    }

    // Persistent chemical/ammonia toxin debt corrodes Cleanliness & O2 every season!
    if run.toxin_debt > 0 {
        d_clean -= (run.toxin_debt as i16) / 2;
        d_o2 -= (run.toxin_debt as i16) / 5;
    }

    // Arena-specific coupled chemistry nuances:
    // - Arena 2 (Aquaponics): Stocked Tilapia (`Z0 == 2`) without Nitrifying Bacteria (`Z2 == 3`) builds NH3!
    if arena == 2 && run.slots[0] == 2 && !zone_is_loop[2] && cur_round >= 3 {
        d_clean -= 9;
    }
    // - Arena 1 (Chinampa): Axolotls (`Z4 == 3`) thrive in clean water (`>= 60`), stress in dirty water (`< 38`)
    if arena == 1 && zone_is_loop[4] {
        if run.cleanliness >= 60 {
            season_yield += 20;
        } else if run.cleanliness < 38 {
            d_clean -= 6;
        }
    }

    // 3. Apply Current Season's Weather & Symbiotic Weather Shields
    let weather = run.upcoming_weather;
    run.weather_applied = weather;
    match weather {
        WEATHER_SUNNY => {
            d_o2 += 2;
            d_clarity -= 2;
        }
        WEATHER_ALGAE_SURGE => {
            if zone_is_loop[3] {
                // Filter-feeder (Silver Carp / Crayfish / Strawberries / Mushrooms) feasts on surge!
                d_clarity += 3;
                season_yield += 32;
                if combo == COMBO_NONE {
                    combo = COMBO_BLOOM_FEAST;
                }
            } else {
                d_clarity -= 11;
                d_o2 -= 4;
            }
        }
        WEATHER_MONSOON => {
            if zone_is_loop[0] {
                // Deep shoreline roots (Mulberry / Ahuejote Willows) shield bank & drink rain!
                d_clarity += 3;
                d_fertility += 5;
                season_yield += 30;
                if combo == COMBO_NONE {
                    combo = COMBO_ROOT_SHIELD;
                }
            } else {
                d_clarity -= 12;
                d_fertility -= 6;
                d_clean -= 3;
            }
        }
        WEATHER_HEATWAVE => {
            if zone_is_loop[2] || (arena >= 2 && zone_is_loop[4]) {
                d_o2 -= 3;
            } else {
                d_o2 -= 12;
                d_clarity -= 4;
            }
        }
        WEATHER_HARVEST_BREEZE => {
            d_o2 += 4;
            d_clarity += 3;
            season_yield += (loop_links as u32) * 10;
        }
        WEATHER_SOLAR_DIM => {
            if (arena == 3 && zone_is_loop[0]) || (arena == 2 && zone_is_loop[4]) {
                d_o2 -= 2;
            } else {
                d_o2 -= 10;
                d_fertility -= 4;
            }
        }
        _ => {}
    }

    // 4. Evaluate Trophic Symbiosis Guild Combos
    if zone_is_loop[0] && zone_is_loop[1] {
        // Producer + Canopy/Primary Symbiont (e.g. Mulberry + Silkworms!)
        season_yield += 34;
        d_fertility += 5;
        if combo == COMBO_NONE {
            combo = COMBO_CANOPY_SYMBIOSIS;
        }
    }
    if zone_is_loop[2] && zone_is_loop[3] && zone_is_loop[4] {
        // Multi-depth Water Guild (e.g. Grass + Silver + Bighead Carp!)
        season_yield += 46;
        d_clarity += 6;
        d_o2 += 4;
        combo = COMBO_WATER_STRATA_GUILD;
    }
    if zone_is_loop[0] && zone_is_loop[5] {
        // Benthic-to-Root Nutrient Return Loop!
        season_yield += 38;
        d_clean += 6;
        d_fertility += 6;
        run.toxin_debt = run.toxin_debt.saturating_sub(12);
        if combo == COMBO_NONE || combo == COMBO_CANOPY_SYMBIOSIS {
            combo = COMBO_BENTHIC_RETURN;
        }
    }
    if loop_links == (NUM_SLOTS as u8) && shortcut_count == 0 {
        season_yield += 70;
        d_o2 += 5;
        d_clarity += 5;
        d_fertility += 5;
        d_clean += 6;
        run.toxin_debt = run.toxin_debt.saturating_sub(20);
        combo = COMBO_FULL_SIX_LOOP;
    }

    // Resolve Steward 3: Hands-Off Autonomous Closed-Loop Season
    if action_kind == 1 && target == 3 {
        if loop_links == (NUM_SLOTS as u8) && shortcut_count == 0 {
            run.autonomous_cycles = run.autonomous_cycles.saturating_add(1);
            season_yield = season_yield.saturating_mul(2).saturating_add(130);
            d_o2 += 6;
            d_clarity += 6;
            d_fertility += 6;
            d_clean += 6;
            combo = COMBO_AUTONOMOUS_INFINITE;
        } else if loop_links >= 4 && shortcut_count == 0 {
            season_yield += 25;
        } else {
            // Unfinished loop left unattended drifts faster!
            d_clarity -= 5;
            d_fertility -= 5;
        }
    }

    run.combo_id = combo;
    if combo != COMBO_NONE {
        run.combo_streak = run.combo_streak.saturating_add(1);
        season_yield += (run.combo_streak as u32) * 8;
    } else if shortcut_count > 0 || predator_count > 0 {
        run.combo_streak = 0;
    }

    // 5. Commit New Vitals (`0..=100`)
    run.o2 = clamp_pct((run.o2 as i16) + d_o2);
    run.clarity = clamp_pct((run.clarity as i16) + d_clarity);
    run.fertility = clamp_pct((run.fertility as i16) + d_fertility);
    run.cleanliness = clamp_pct((run.cleanliness as i16) + d_clean);
    run.last_round_played = cur_round;

    // 6. Check Mid-Run Ecological Halt Conditions (`0%` Vital Crash)
    if run.cleanliness == 0 {
        run.status = STATUS_HALTED;
        run.halt_reason = HALT_AMMONIA_TOXICITY;
        run.last_yield = 0;
        run.xp_gained = 15;
        return Ok(());
    }
    if run.o2 == 0 {
        run.status = STATUS_HALTED;
        run.halt_reason = HALT_HYPOXIA;
        run.last_yield = 0;
        run.xp_gained = 15;
        return Ok(());
    }
    if run.clarity == 0 {
        run.status = STATUS_HALTED;
        run.halt_reason = HALT_EUTROPHICATION;
        run.last_yield = 0;
        run.xp_gained = 15;
        return Ok(());
    }
    if run.fertility == 0 {
        run.status = STATUS_HALTED;
        run.halt_reason = if predator_count > 0 {
            HALT_TROPHIC_PREDATION
        } else {
            HALT_NUTRIENT_STARVATION
        };
        run.last_yield = 0;
        run.xp_gained = 15;
        return Ok(());
    }

    // Predation collapse if multiple predators overrun pond by Year 2
    if predator_count >= 2 && cur_round >= 3 {
        run.status = STATUS_HALTED;
        run.halt_reason = HALT_TROPHIC_PREDATION;
        run.last_yield = 0;
        run.xp_gained = 15;
        return Ok(());
    }

    // Add healthy season harvest!
    run.last_yield = season_yield;
    run.total_harvest = run.total_harvest.saturating_add(season_yield);

    // 7. Check End-of-Year-2 (Round 8) Completion vs Advance to Next Season
    if cur_round >= MAX_ROUNDS {
        if shortcut_count >= 2 || (shortcut_count >= 1 && run.toxin_debt >= 35) {
            run.status = STATUS_HALTED;
            run.halt_reason = HALT_EXTERNAL_DEPENDENCY;
            run.xp_gained = 25;
            return Ok(());
        }

        run.status = STATUS_VICTORY;
        run.halt_reason = HALT_NONE;
        let min_vital = run.o2.min(run.clarity).min(run.fertility).min(run.cleanliness);
        run.stars_earned = if loop_links == (NUM_SLOTS as u8) && shortcut_count == 0 && min_vital >= 55 {
            3
        } else if loop_links >= 5 && shortcut_count == 0 && min_vital >= 40 {
            2
        } else {
            1
        };
        run.xp_gained = 80 + (run.stars_earned as u32) * 50 + (run.autonomous_cycles as u32) * 40;
    } else {
        run.round = cur_round + 1;
        run.upcoming_weather = roll_next_weather(run.arena_id, run.round, next_weather_seed);
        run.xp_gained = 10 + (loop_links as u32) * 2;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Storage Helpers
// ---------------------------------------------------------------------------

fn player_key(identity: &[u8; 20]) -> [u8; 27] {
    let mut k = [0u8; 27];
    k[0..7].copy_from_slice(b"hfe2:p:");
    k[7..27].copy_from_slice(identity);
    k
}

fn run_key(identity: &[u8; 20]) -> [u8; 27] {
    let mut k = [0u8; 27];
    k[0..7].copy_from_slice(b"hfe2:r:");
    k[7..27].copy_from_slice(identity);
    k
}

fn load_player(identity: &[u8; 20]) -> PlayerProgress {
    if *identity == [0u8; 20] {
        return PlayerProgress::empty(*identity);
    }
    let key = player_key(identity);
    let mut raw = [0u8; 40];
    match storage::get_into(&key, &mut raw) {
        Some(n) if n >= 40 => PlayerProgress::from_bytes(*identity, &raw),
        _ => PlayerProgress::empty(*identity),
    }
}

fn save_player(p: &PlayerProgress) {
    let key = player_key(&p.identity);
    storage::set(&key, &p.to_bytes());
}

fn load_run(identity: &[u8; 20]) -> RunState {
    if *identity == [0u8; 20] {
        return RunState::empty();
    }
    let key = run_key(identity);
    let mut raw = [0u8; 64];
    match storage::get_into(&key, &mut raw) {
        Some(n) if n >= 64 => RunState::from_bytes(&raw),
        _ => RunState::empty(),
    }
}

fn save_run(identity: &[u8; 20], run: &RunState) {
    let key = run_key(identity);
    storage::set(&key, &run.to_bytes());
}

fn bump_global_runs() -> u32 {
    let mut buf = [0u8; 4];
    let prev = match storage::get_into(KEY_GLOBAL, &mut buf) {
        Some(4) => u32::from_be_bytes(buf),
        _ => 0,
    };
    let next = prev.saturating_add(1);
    storage::set(KEY_GLOBAL, &next.to_be_bytes());
    next
}

fn read_global_runs() -> u32 {
    let mut buf = [0u8; 4];
    match storage::get_into(KEY_GLOBAL, &mut buf) {
        Some(4) => u32::from_be_bytes(buf),
        _ => 0,
    }
}

fn compute_entropy_byte(identity: &[u8; 20], extra: u32) -> u8 {
    let mut seed = [0u8; 56];
    seed[0..8].copy_from_slice(&context::block_number().to_be_bytes());
    seed[8..28].copy_from_slice(&context::msg_sender());
    seed[28..48].copy_from_slice(identity);
    seed[48..52].copy_from_slice(&extra.to_be_bytes());
    seed[52..56].copy_from_slice(&read_global_runs().to_be_bytes());
    let digest = keccak::keccak256(&seed);
    digest[0] ^ digest[17]
}

fn update_leaderboard(p: &PlayerProgress) {
    if p.solved_mask == 0 {
        return;
    }
    // 28B entry: 20B identity + 1B stars + 1B solved_mask + 1B badges + 1B streak + 4B total_harvest_sum/xp
    let mut raw = [0u8; 1 + MAX_LEADERBOARD * 28];
    let n = storage::get_into(KEY_LEADERS, &mut raw).unwrap_or(0);
    let mut count = if n >= 1 {
        (raw[0] as usize).min(MAX_LEADERBOARD)
    } else {
        0
    };

    let mut entries = [[0u8; 28]; MAX_LEADERBOARD];
    let mut i = 0usize;
    while i < count && (1 + (i + 1) * 28) <= n {
        entries[i].copy_from_slice(&raw[1 + i * 28..1 + (i + 1) * 28]);
        i += 1;
    }
    count = i;

    let total_yield_sum: u32 = (p.best_yield[0] as u32)
        + (p.best_yield[1] as u32)
        + (p.best_yield[2] as u32)
        + (p.best_yield[3] as u32);

    let mut my_entry = [0u8; 28];
    my_entry[0..20].copy_from_slice(&p.identity);
    my_entry[20] = p.total_stars();
    my_entry[21] = p.solved_mask;
    my_entry[22] = p.badges;
    my_entry[23] = p.best_streak;
    my_entry[24..28].copy_from_slice(&total_yield_sum.to_be_bytes());

    let mut found = false;
    i = 0;
    while i < count {
        if entries[i][0..20] == p.identity {
            entries[i] = my_entry;
            found = true;
            break;
        }
        i += 1;
    }
    if !found {
        if count < MAX_LEADERBOARD {
            entries[count] = my_entry;
            count += 1;
        } else {
            entries[MAX_LEADERBOARD - 1] = my_entry;
        }
    }

    // Insertion sort descending by `(total_stars, total_yield_sum)`
    let mut a = 1usize;
    while a < count {
        let cur = entries[a];
        let cur_s = cur[20];
        let cur_y = u32::from_be_bytes([cur[24], cur[25], cur[26], cur[27]]);
        let mut b = a;
        while b > 0 {
            let prev = entries[b - 1];
            let prev_s = prev[20];
            let prev_y = u32::from_be_bytes([prev[24], prev[25], prev[26], prev[27]]);
            if cur_s > prev_s || (cur_s == prev_s && cur_y > prev_y) {
                entries[b] = prev;
                b -= 1;
            } else {
                break;
            }
        }
        entries[b] = cur;
        a += 1;
    }

    let mut out = [0u8; 1 + MAX_LEADERBOARD * 28];
    out[0] = count as u8;
    i = 0;
    while i < count {
        out[1 + i * 28..1 + (i + 1) * 28].copy_from_slice(&entries[i]);
        i += 1;
    }
    storage::set(KEY_LEADERS, &out[0..1 + count * 28]);
}

fn push_activity_log(identity: &[u8; 20], run: &RunState) {
    // 28B log: 20B identity + 1B arena_id + 1B status + 1B halt_reason + 1B stars + 1B round + 1B loop_links + 2B harvest
    let mut raw = [0u8; 1 + MAX_RECENT_LOGS * 28];
    let n = storage::get_into(KEY_LOGS, &mut raw).unwrap_or(0);
    let mut count = if n >= 1 {
        (raw[0] as usize).min(MAX_RECENT_LOGS)
    } else {
        0
    };
    let mut items = [[0u8; 28]; MAX_RECENT_LOGS];
    let mut i = 0usize;
    while i < count && (1 + (i + 1) * 28) <= n {
        items[i].copy_from_slice(&raw[1 + i * 28..1 + (i + 1) * 28]);
        i += 1;
    }
    count = i;

    let mut rec = [0u8; 28];
    rec[0..20].copy_from_slice(identity);
    rec[20] = run.arena_id;
    rec[21] = run.status;
    rec[22] = run.halt_reason;
    rec[23] = run.stars_earned;
    rec[24] = run.last_round_played;
    rec[25] = run.loop_links;
    let capped_h = (run.total_harvest.min(65535)) as u16;
    rec[26..28].copy_from_slice(&capped_h.to_be_bytes());

    if count == MAX_RECENT_LOGS {
        let mut k = 0usize;
        while k + 1 < MAX_RECENT_LOGS {
            items[k] = items[k + 1];
            k += 1;
        }
        items[MAX_RECENT_LOGS - 1] = rec;
    } else {
        items[count] = rec;
        count += 1;
    }

    let mut out = [0u8; 1 + MAX_RECENT_LOGS * 28];
    out[0] = count as u8;
    i = 0;
    while i < count {
        out[1 + i * 28..1 + (i + 1) * 28].copy_from_slice(&items[i]);
        i += 1;
    }
    storage::set(KEY_LOGS, &out[0..1 + count * 28]);
}

/// Strict on-chain Identity HFS authorization check (`Err(-40)` if unauthorized).
fn is_authorized_for_identity(caller: &[u8; 20], identity_addr: &[u8; 20]) -> bool {
    if *identity_addr == [0u8; 20] {
        return false;
    }
    if caller == identity_addr && context::code_hash_of(identity_addr).is_some() {
        return true;
    }
    let owner_cd = CallEncoder::<16>::new(SEL_ID_OWNER);
    if let Ok(raw) = call::call_raw(identity_addr, owner_cd.as_slice()) {
        if raw.len() >= 32 && raw[0..12] == [0u8; 12] && &raw[12..32] == caller {
            return true;
        }
    }
    let dev_cd = CallEncoder::<64>::new(SEL_ID_IS_DEVICE).push_address(caller);
    if let Ok(true) = call::call_bool(identity_addr, dev_cd.as_slice()) {
        return true;
    }
    false
}

fn emit_run_event(topic0: [u8; 32], identity: &[u8; 20], snap: &[u8; 64]) {
    let mut id_topic = [0u8; 32];
    id_topic[12..32].copy_from_slice(identity);
    events::emit(&[topic0, id_topic], snap);
}

// ---------------------------------------------------------------------------
// ABI Entrypoints (`hps_entry!`)
// ---------------------------------------------------------------------------

hps_entry! {
    "initialize(string)" => handle_initialize,
    "startRun(uint64,address)" => handle_start_run,
    "playRound(address,uint64,uint64,uint64)" => handle_play_round,
    "getOverview(address)" => handle_get_overview,
}

fn handle_initialize(args: &CalldataReader) -> Result<i32, i32> {
    let label = args.dynamic_bytes(0).unwrap_or(b"Haltfree Ecosystem Sanctuary");
    let len = label.len().min(64);
    let mut meta = [0u8; 65];
    meta[0] = len as u8;
    meta[1..1 + len].copy_from_slice(&label[..len]);
    storage::set(KEY_META, &meta[..1 + len]);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_start_run(args: &CalldataReader) -> Result<i32, i32> {
    let arena_id = (args.u64(0).ok_or(-10)? as usize).min(NUM_ARENAS - 1);
    let identity = args.address(1).ok_or(-11)?;

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &identity) {
        return Err(-40);
    }

    let run_num = bump_global_runs();
    let seed = compute_entropy_byte(&identity, run_num);
    let run = RunState::new_expedition(arena_id, run_num, seed);

    let mut player = load_player(&identity);
    player.runs_started = player.runs_started.saturating_add(1);
    save_player(&player);
    save_run(&identity, &run);

    let snap = run.to_bytes();
    emit_run_event(EV_RUN_STARTED, &identity, &snap);
    ret::write(&snap);
    Ok(64)
}

fn handle_play_round(args: &CalldataReader) -> Result<i32, i32> {
    let identity = args.address(0).ok_or(-10)?;
    let action_kind = args.u64(1).ok_or(-11)? as u8;
    let target = args.u64(2).ok_or(-12)? as u8;
    let choice = args.u64(3).ok_or(-13)? as u8;

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &identity) {
        return Err(-40);
    }

    let mut run = load_run(&identity);
    let seed = compute_entropy_byte(&identity, (run.round as u32) * 97 + run.total_harvest);
    step_ecosystem_round(&mut run, action_kind, target, choice, seed)?;

    let mut player = load_player(&identity);
    player.total_xp = player.total_xp.saturating_add(run.xp_gained);
    if run.combo_streak > player.best_streak {
        player.best_streak = run.combo_streak.min(15);
    }

    let mut newly_unlocked: u8 = 0;
    if run.combo_id == COMBO_AUTONOMOUS_INFINITE && (player.badges & BADGE_HANDS_FREE_LOOP) == 0 {
        newly_unlocked |= BADGE_HANDS_FREE_LOOP;
    }

    if run.status == STATUS_VICTORY {
        let a = (run.arena_id as usize).min(NUM_ARENAS - 1);
        player.runs_won = player.runs_won.saturating_add(1);
        player.solved_mask |= 1 << a;
        if run.stars_earned > player.best_stars[a] {
            player.best_stars[a] = run.stars_earned;
        }
        let capped_yield = (run.total_harvest.min(65535)) as u16;
        if capped_yield > player.best_yield[a] {
            player.best_yield[a] = capped_yield;
        }

        // Check Arena Mastery Badges
        if a == 0 && run.loop_links == 6 && (player.badges & BADGE_SANGJI_MASTER) == 0 {
            newly_unlocked |= BADGE_SANGJI_MASTER;
        }
        if a == 1 && run.cleanliness >= 75 && (player.badges & BADGE_AXOLOTL_GUARDIAN) == 0 {
            newly_unlocked |= BADGE_AXOLOTL_GUARDIAN;
        }
        if a == 2 && run.toxin_debt == 0 && (player.badges & BADGE_NITROGEN_ALCHEMIST) == 0 {
            newly_unlocked |= BADGE_NITROGEN_ALCHEMIST;
        }
        if a == 3 && (player.badges & BADGE_MARS_PIONEER) == 0 {
            newly_unlocked |= BADGE_MARS_PIONEER;
        }
        player.badges |= newly_unlocked;
        if player.total_stars() >= 12 && (player.badges & BADGE_GRAND_PERMACULTURIST) == 0 {
            newly_unlocked |= BADGE_GRAND_PERMACULTURIST;
            player.badges |= BADGE_GRAND_PERMACULTURIST;
        }

        update_leaderboard(&player);
        push_activity_log(&identity, &run);
    } else {
        player.badges |= newly_unlocked;
        if run.status == STATUS_HALTED {
            push_activity_log(&identity, &run);
        }
    }

    run.badges_unlocked_now = newly_unlocked;
    save_player(&player);
    save_run(&identity, &run);

    let snap = run.to_bytes();
    emit_run_event(EV_ROUND_RESOLVED, &identity, &snap);
    ret::write(&snap);
    Ok(64)
}

fn handle_get_overview(args: &CalldataReader) -> Result<i32, i32> {
    let viewer = args.address(0).unwrap_or([0u8; 20]);
    let player = load_player(&viewer);
    let run = load_run(&viewer);

    let mut leaders_raw = [0u8; 1 + MAX_LEADERBOARD * 28];
    let l_n = storage::get_into(KEY_LEADERS, &mut leaders_raw).unwrap_or(0);
    let l_cnt = if l_n >= 1 {
        (leaders_raw[0] as usize).min(MAX_LEADERBOARD)
    } else {
        0
    };

    let mut logs_raw = [0u8; 1 + MAX_RECENT_LOGS * 28];
    let g_n = storage::get_into(KEY_LOGS, &mut logs_raw).unwrap_or(0);
    let g_cnt = if g_n >= 1 {
        (logs_raw[0] as usize).min(MAX_RECENT_LOGS)
    } else {
        0
    };

    // Header (16B) + PlayerProgress (40B) + RunSnapshot (64B) = 120B fixed prefix
    let mut out = [0u8; 120 + MAX_LEADERBOARD * 28 + MAX_RECENT_LOGS * 28];
    out[0] = 2; // Overview schema v2
    out[1] = l_cnt as u8;
    out[2] = g_cnt as u8;
    out[4..12].copy_from_slice(&context::block_number().to_be_bytes());
    out[12..16].copy_from_slice(&read_global_runs().to_be_bytes());
    out[16..56].copy_from_slice(&player.to_bytes());
    out[56..120].copy_from_slice(&run.to_bytes());

    let mut pos = 120;
    if l_cnt > 0 && l_n >= 1 + l_cnt * 28 {
        out[pos..pos + l_cnt * 28].copy_from_slice(&leaders_raw[1..1 + l_cnt * 28]);
        pos += l_cnt * 28;
    }
    if g_cnt > 0 && g_n >= 1 + g_cnt * 28 {
        out[pos..pos + g_cnt * 28].copy_from_slice(&logs_raw[1..1 + g_cnt * 28]);
        pos += g_cnt * 28;
    }

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIMAL_GENOMES: [[u8; NUM_SLOTS]; NUM_ARENAS] = [
        [2, 1, 3, 1, 2, 3], // Arena 0: 2,400-yr Chinese Mulberry-Dyke Carp Polyculture
        [1, 3, 1, 2, 3, 1], // Arena 1: Aztec Chinampa & Axolotl Canal
        [2, 1, 3, 1, 2, 2], // Arena 2: Solar Aquaponics & Nitrification Dome
        [3, 1, 2, 2, 2, 1], // Arena 3: Sealed Martian Biosphere BIOS-IV
    ];

    #[test]
    fn eight_round_turn_by_turn_expedition_wins_3_stars_across_all_4_arenas() {
        for (arena_id, genome) in OPTIMAL_GENOMES.iter().enumerate() {
            let mut run = RunState::new_expedition(arena_id, 1, 0);
            // Rounds 1..=6: Stock the 6 symbiotic niches one per round!
            for z in 0..NUM_SLOTS {
                assert_eq!(run.status, STATUS_ACTIVE);
                step_ecosystem_round(&mut run, 0, z as u8, genome[z], (z as u8) * 7).unwrap();
            }
            assert_eq!(run.loop_links, 6, "Arena {} should have 6/6 loop links after Round 6", arena_id);

            // Rounds 7 & 8: Run Hands-Off Autonomous Closed-Loop Seasons (`action_kind=1, target=3`)!
            step_ecosystem_round(&mut run, 1, 3, 0, 19).unwrap();
            assert_eq!(run.combo_id, COMBO_AUTONOMOUS_INFINITE);
            assert_eq!(run.status, STATUS_ACTIVE);

            step_ecosystem_round(&mut run, 1, 3, 0, 31).unwrap();
            assert_eq!(
                run.status, STATUS_VICTORY,
                "Arena {} did not achieve Victory on Round 8: halt={}, o2={}, clar={}, fert={}, clean={}",
                arena_id, run.halt_reason, run.o2, run.clarity, run.fertility, run.cleanliness
            );
            assert_eq!(run.stars_earned, 3, "Arena {} expected 3 stars!", arena_id);
            assert_eq!(run.autonomous_cycles, 2);
            assert!(run.total_harvest >= 1400, "Arena {} harvest={} too low", arena_id, run.total_harvest);
        }
    }

    #[test]
    fn early_mistake_plus_steward_rescue_recovers_and_completes_expedition() {
        let mut run = RunState::new_expedition(0, 2, 1);
        // Round 1: Accidentally stock Overcrowded Koi in Z2!
        step_ecosystem_round(&mut run, 0, 2, 2, 3).unwrap();
        assert!(run.o2 < run.prev_o2);
        // Round 2: Rescue O2 with Bamboo Splash-Wheel Aerator (`action=1, target=2`)!
        step_ecosystem_round(&mut run, 1, 2, 0, 5).unwrap();
        // Rounds 3..=8: Build all 6 Mulberry-Dyke niches (overwriting Z2 Koi with Grass Carp!)
        let g = OPTIMAL_GENOMES[0];
        for z in 0..NUM_SLOTS {
            step_ecosystem_round(&mut run, 0, z as u8, g[z], (z as u8) * 11).unwrap();
        }
        assert_eq!(run.status, STATUS_VICTORY);
        assert!(run.stars_earned >= 2);
    }

    #[test]
    fn chemical_shortcuts_and_hypoxia_traps_halt_mid_expedition() {
        // 1. Chemical shortcut spam (Pesticide Corn + Copper Algicide + Diesel Feeder) -> Toxic Halt!
        let mut toxic_run = RunState::new_expedition(0, 3, 0);
        let bad_actions = [(0u8, 0u8, 3u8), (0, 3, 2), (0, 1, 3), (1, 3, 0), (1, 3, 0)];
        for (ak, t, c) in bad_actions {
            if toxic_run.status == STATUS_ACTIVE {
                step_ecosystem_round(&mut toxic_run, ak, t, c, 2).unwrap();
            }
        }
        assert_eq!(toxic_run.status, STATUS_HALTED);
        assert_eq!(toxic_run.halt_reason, HALT_AMMONIA_TOXICITY);

        // 2. Invasive Water Hyacinth + Burn Stalks in Chinampa -> Hypoxia Halt!
        let mut hypoxia_run = RunState::new_expedition(1, 4, 1);
        let o2_crash = [(0u8, 2u8, 2u8), (0, 5, 3), (1, 3, 0), (1, 3, 0)];
        for (ak, t, c) in o2_crash {
            if hypoxia_run.status == STATUS_ACTIVE {
                step_ecosystem_round(&mut hypoxia_run, ak, t, c, 3).unwrap();
            }
        }
        assert_eq!(hypoxia_run.status, STATUS_HALTED);
        assert_eq!(hypoxia_run.halt_reason, HALT_HYPOXIA);
    }
}
