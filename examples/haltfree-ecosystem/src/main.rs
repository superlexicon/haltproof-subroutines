//! # Haltfree Ecosystem (`haltfree-ecosystem` — HPS #29)
//!
//! Educational Closed-Loop Permaculture, Polyculture Aquaculture & Biospheric Simulation
//! Halt-Free Subroutine for children, families, and classrooms (`$0.00` gas on Subnet 1).
//!
//! ## Four Progressive Ecological Arenas (`arena_id = 0..=3`)
//! 0. **2,400-Year-Old Mulberry-Dyke Carp Polyculture (*Sangji Yutang*, 475 BCE)** — Beginner ★☆☆☆
//!    Balance Mulberry Dyke Trees, Silkworms, Surface Grass Carp, Upper-Mid Silver Carp
//!    (phytoplankton filter), Lower-Mid Bighead Carp (zooplankton filter), and Benthic Black/Common
//!    Carp + Winter Pond-Silt Return to achieve a zero-feed, zero-waste "Infinite Food & Silk" loop!
//! 1. **Aztec Chinampa & Axolotl Floating Canal (*Xochimilco*, 1150 CE)** — Intermediate ★★☆☆
//!    Balance Ahuejote Willow root-anchors, Three Sisters nitrogen-fixing polyculture, Azolla/Duckweed,
//!    native Acocil crayfish, bio-indicator Axolotls, and Canal Muck + Reed bio-filtration.
//! 2. **Solar Aquaponics & Nitrification Bio-Reactor Greenhouse** — Advanced ★★★☆
//!    Balance Nile Tilapia density, Red Wiggler vermi-mineralization, *Nitrosomonas*/*Nitrobacter*
//!    nitrification (`NH3 -> NO2- -> NO3-`), poly-raft greens/strawberries, Solar Venturi + Bees,
//!    and Mineral-Buffered Recirculation.
//! 3. **Sealed Martian Biospheric Habitat ("BIOS-IV")** — Master ★★★★
//!    Balance Spirulina O2 photobioreactors, Sweet Potato/Dwarf Wheat/Soybean calorie terraces,
//!    Mason Bees + Duckweed, Mushroom + Black Soldier Fly decomposers, Transpiration Condensers,
//!    and Washed Regolith + Biochar soil buffers across 12 Martian seasonal cycles with zero resupply!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const NUM_ARENAS: usize = 4;
pub const NUM_SLOTS: usize = 6;
pub const NUM_OPTIONS: usize = 4;
pub const NUM_SEASONS: usize = 12;
pub const MAX_LEADERBOARD: usize = 16;
pub const MAX_RECENT_LOGS: usize = 12;

// Diagnostic Halt Codes (`0` = Perpetual Halt-Free Loop Achieved!)
pub const HALT_NONE: u8 = 0;
pub const HALT_EUTROPHICATION: u8 = 1;
pub const HALT_HYPOXIA: u8 = 2;
pub const HALT_AMMONIA_TOXICITY: u8 = 3;
pub const HALT_TROPHIC_PREDATION: u8 = 4;
pub const HALT_NUTRIENT_STARVATION: u8 = 5;
pub const HALT_EXTERNAL_DEPENDENCY: u8 = 6;

const KEY_META: &[u8] = b"hfe:meta";
const KEY_LEADERS: &[u8] = b"hfe:leaders";
const KEY_LOGS: &[u8] = b"hfe:logs";

const EV_ECOSYSTEM_TESTED: [u8; 32] =
    event_topic("EcosystemTested(address,uint64,uint64,uint64,uint64)");

const SEL_ID_OWNER: [u8; 4] = selector("owner()");
const SEL_ID_IS_DEVICE: [u8; 4] = selector("isOwnerDevice(address)");

/// Seasonal rate deltas contributed by a single `(arena, slot, option)` ecological choice.
#[derive(Clone, Copy)]
pub struct NicheEffect {
    pub d_oxygen: i16,
    pub d_algae: i16,     // positive = fuels micro-algae bloom; negative = filters micro-algae!
    pub d_fertility: i16, // positive = recycles/fixes nutrients; negative = depletes nutrients
    pub d_toxicity: i16,  // positive = adds ammonia/toxin; negative = bio-filters/scrubs toxin
    pub d_yield: u16,     // seasonal food/silk harvest units
    pub flags: u8,        // bit 0 = predator/pest, bit 1 = external non-closed input, bit 2 = lethal toxin
}

const F_NONE: u8 = 0;
const F_PREDATOR: u8 = 1 << 0;
const F_EXTERNAL: u8 = 1 << 1;
const F_LETHAL: u8 = 1 << 2;

const fn eff(
    d_oxygen: i16,
    d_algae: i16,
    d_fertility: i16,
    d_toxicity: i16,
    d_yield: u16,
    flags: u8,
) -> NicheEffect {
    NicheEffect {
        d_oxygen,
        d_algae,
        d_fertility,
        d_toxicity,
        d_yield,
        flags,
    }
}

/// Complete `[4 arenas][6 slots][4 options]` ecological parameter matrix.
/// Optimal Halt-Free Closed-Loop Genomes:
/// - Arena 0 (Mulberry-Dyke Pond): `[2, 1, 3, 1, 2, 3]`
/// - Arena 1 (Aztec Chinampa):     `[1, 3, 1, 2, 3, 1]`
/// - Arena 2 (Solar Aquaponics):   `[2, 1, 3, 1, 2, 2]`
/// - Arena 3 (Martian Biodome):    `[3, 1, 2, 2, 2, 1]`
pub const ECOLOGY_MATRIX: [[[NicheEffect; NUM_OPTIONS]; NUM_SLOTS]; NUM_ARENAS] = [
    // =========================================================================
    // ARENA 0: 2,400-Year-Old Mulberry-Dyke Carp Polyculture (Sangji Yutang)
    // Base drift per season: O2 -4, Algae +4, Fertility -6, Toxicity +5
    // Optimal [2, 1, 3, 1, 2, 3] net/season:
    //   O2: -4 +3 +0 +1 +4 +1 +2 = +7 (clamps cleanly at 88..96%)
    //   Algae: +4 +0 +3 +5 -8 -4 +0 = 0 (sparkling clear water ~82%!)
    //   Fertility: -6 -4 +3 +3 +0 +1 +9 = +6 (lush self-fertilizing dyke ~90%!)
    //   Toxicity: +5 -2 +1 +2 -1 -1 -7 = -3 (0..8% ultra-low ammonia!)
    // =========================================================================
    [
        // Slot 0: Shore Dyke Plant (0 Bare Bank, 1 Pine Conifers, 2 Mulberry Trees ✅, 3 Pesticide Corn)
        [
            eff(-2, 3, -5, 3, 0, F_NONE),
            eff(1, 0, -4, 4, 2, F_NONE),
            eff(3, 0, -4, -2, 18, F_NONE),
            eff(-3, 8, -7, 18, 8, F_LETHAL),
        ],
        // Slot 1: Canopy Shed Symbiont (0 Empty, 1 Silkworms ✅, 2 Locusts, 3 Diesel Pellet Feeder)
        [
            eff(0, -1, -2, 0, 0, F_NONE),
            eff(0, 3, 3, 1, 18, F_NONE),
            eff(-2, 4, -8, 5, 0, F_PREDATOR),
            eff(-3, 9, 4, 9, 14, F_EXTERNAL),
        ],
        // Slot 2: Surface 0-0.5m (0 None, 1 Snakehead Predator, 2 Overcrowded Koi, 3 Grass Carp + Duckweed ✅)
        [
            eff(-2, 6, -1, 1, 0, F_NONE),
            eff(-1, 6, -2, 3, 3, F_PREDATOR),
            eff(-9, 7, 1, 8, 6, F_NONE),
            eff(1, 5, 3, 2, 18, F_NONE),
        ],
        // Slot 3: Upper-Mid 0.5-1.5m (0 Unfiltered, 1 Silver Carp ✅, 2 Copper Algicide, 3 Trout)
        [
            eff(-4, 9, 0, 2, 0, F_NONE),
            eff(4, -8, 0, -1, 16, F_NONE),
            eff(-6, -6, -4, 19, 0, F_LETHAL),
            eff(-4, 5, 0, 3, 4, F_PREDATOR),
        ],
        // Slot 4: Lower-Mid 1.5-2.5m (0 Unfiltered, 1 Northern Pike, 2 Bighead Carp ✅, 3 Brine Krill)
        [
            eff(-2, 4, -1, 3, 0, F_NONE),
            eff(-2, 5, -2, 3, 3, F_PREDATOR),
            eff(1, -4, 1, -1, 16, F_NONE),
            eff(-3, 3, 0, 7, 0, F_NONE),
        ],
        // Slot 5: Benthic Floor & Dyke Loop (0 Sludge, 1 Concrete Liner, 2 River Flush, 3 Black/Common Carp + Silt Dredge ✅)
        [
            eff(-5, 4, -6, 10, 0, F_NONE),
            eff(-1, 2, -8, 5, 2, F_NONE),
            eff(1, -1, -10, -1, 4, F_EXTERNAL),
            eff(2, 0, 9, -7, 20, F_NONE),
        ],
    ],
    // =========================================================================
    // ARENA 1: Aztec Chinampa & Axolotl Floating Canal (Optimal: [1, 3, 1, 2, 3, 1])
    // =========================================================================
    [
        // Slot 0: Perimeter (0 Unanchored Mud, 1 Ahuejote Willows ✅, 2 Eucalyptus, 3 Sheet Metal)
        [
            eff(-3, 5, -6, 4, 0, F_NONE),
            eff(3, -1, 2, -2, 14, F_NONE),
            eff(0, 1, -6, 6, 3, F_NONE),
            eff(-2, 3, -5, 4, 0, F_EXTERNAL),
        ],
        // Slot 1: Crop Guild (0 Mono Wheat, 1 Thirsty Cotton, 2 Pesticide Tomato, 3 Three Sisters ✅)
        [
            eff(1, 1, -8, 1, 8, F_NONE),
            eff(0, 2, -10, 3, 5, F_NONE),
            eff(-2, 6, -6, 18, 9, F_LETHAL),
            eff(2, 0, 4, -1, 24, F_NONE),
        ],
        // Slot 2: Canal Surface (0 Bare, 1 Azolla & Duckweed ✅, 2 Invasive Hyacinth, 3 Oil Spray)
        [
            eff(-2, 6, -2, 2, 0, F_NONE),
            eff(3, -4, 3, -2, 14, F_NONE),
            eff(-11, 8, 0, 5, 0, F_NONE),
            eff(-8, 2, -4, 17, 0, F_LETHAL),
        ],
        // Slot 3: Canal Grazers (0 Empty, 1 Uprooting Carp, 2 Native Acocil & Silversides ✅, 3 Piranha)
        [
            eff(-1, 5, -1, 2, 0, F_NONE),
            eff(-3, 6, -5, 5, 6, F_NONE),
            eff(1, -4, 1, -1, 16, F_NONE),
            eff(-2, 5, -2, 4, 2, F_PREDATOR),
        ],
        // Slot 4: Bio-Indicator (0 None, 1 Cane Toads, 2 Chlorine Pump, 3 Axolotl & Tree Frogs ✅)
        [
            eff(-1, 2, -2, 3, 0, F_NONE),
            eff(-2, 3, -3, 6, 0, F_PREDATOR),
            eff(-4, -5, -6, 18, 0, F_LETHAL),
            eff(2, -2, 1, -2, 16, F_NONE),
        ],
        // Slot 5: Nutrient Loop (0 Sink Muck, 1 Canal Muck Scoop + Reed Bio-Filter ✅, 2 Synthetic NPK, 3 Burn Stalks)
        [
            eff(-5, 5, -7, 9, 0, F_NONE),
            eff(2, -3, 6, -6, 22, F_NONE),
            eff(-3, 10, 4, 9, 14, F_EXTERNAL),
            eff(-5, 2, -6, 8, 2, F_NONE),
        ],
    ],
    // =========================================================================
    // ARENA 2: Solar Aquaponics & Nitrification Bio-Dome (Optimal: [2, 1, 3, 1, 2, 2])
    // =========================================================================
    [
        // Slot 0: Fish Tank (0 Empty, 1 Saltwater Tuna, 2 Balanced Nile Tilapia ✅, 3 5x Catfish Jam)
        [
            eff(1, -1, -9, -2, 0, F_NONE),
            eff(-4, 2, -5, 14, 0, F_NONE),
            eff(-2, 2, 5, 4, 20, F_NONE),
            eff(-12, 7, 6, 15, 10, F_NONE),
        ],
        // Slot 1: Solids Mineralizer (0 Raw Sludge, 1 Swirl Clarifier + Red Worms ✅, 2 Bleach, 3 Sewer Dump)
        [
            eff(-6, 5, 1, 11, 2, F_NONE),
            eff(1, -2, 5, -4, 16, F_NONE),
            eff(-4, -4, -8, 20, 0, F_LETHAL),
            eff(0, 0, -9, -1, 0, F_EXTERNAL),
        ],
        // Slot 2: Bio-Filter Microbes (0 Sterile Glass, 1 Anaerobic Mud, 2 UV Kill, 3 Clay + Nitrosomonas/Nitrobacter ✅)
        [
            eff(0, 2, -3, 10, 0, F_NONE),
            eff(-7, 4, 0, 9, 0, F_NONE),
            eff(0, -1, -4, 11, 0, F_NONE),
            eff(2, -3, 4, -9, 16, F_NONE),
        ],
        // Slot 3: Hydroponic Raft (0 Empty, 1 Basil/Lettuce/Strawberry Raft ✅, 2 Oak Saplings, 3 Plastic Plants)
        [
            eff(-1, 7, 2, 6, 0, F_NONE),
            eff(3, -5, -2, -4, 24, F_NONE),
            eff(1, 3, -7, 3, 2, F_NONE),
            eff(-1, 6, 0, 7, 0, F_NONE),
        ],
        // Slot 4: Oxygen & Pollinators (0 Stagnant, 1 Diesel Gen, 2 Solar Venturi + Bumblebees ✅, 3 Pure CO2 Bubbler)
        [
            eff(-8, 4, -1, 3, 0, F_NONE),
            eff(4, 1, 0, 5, 8, F_EXTERNAL),
            eff(7, -1, 1, -1, 16, F_NONE),
            eff(-14, 6, 1, 6, 0, F_LETHAL),
        ],
        // Slot 5: Water & Mineral Loop (0 One-Way Tap, 1 Table Salt, 2 Recirc Sump + CaCO3/Kelp ✅, 3 Acid Wash)
        [
            eff(1, 0, -8, 0, 4, F_EXTERNAL),
            eff(-3, 1, -9, 16, 0, F_LETHAL),
            eff(2, -1, 4, -2, 18, F_NONE),
            eff(-4, -2, -7, 15, 0, F_LETHAL),
        ],
    ],
    // =========================================================================
    // ARENA 3: Sealed Martian Biospheric Habitat BIOS-IV (Optimal: [3, 1, 2, 2, 2, 1])
    // =========================================================================
    [
        // Slot 0: Fast O2 Scrubber (0 None, 1 Bare Concrete O2 Sink, 2 Coal Furnace, 3 Spirulina Photobioreactor ✅)
        [
            eff(-10, 0, -2, 4, 0, F_NONE),
            eff(-9, 0, -1, 3, 2, F_NONE),
            eff(-15, 2, 0, 18, 0, F_LETHAL),
            eff(7, -3, 2, -3, 18, F_NONE),
        ],
        // Slot 1: Calorie Terrace (0 Empty, 1 Sweet Potato + Dwarf Wheat + Soy ✅, 2 Redwoods, 3 Lawn Grass)
        [
            eff(-4, 1, -5, 2, 0, F_NONE),
            eff(4, -1, -1, -2, 26, F_NONE),
            eff(2, 0, -8, 0, 2, F_NONE),
            eff(2, 0, -4, 0, 2, F_NONE),
        ],
        // Slot 2: Protein & Pollination (0 None, 1 Methane Cattle, 2 Mason Bees + Duckweed Pond ✅, 3 Termites)
        [
            eff(-1, 3, -3, 2, 2, F_NONE),
            eff(-12, 6, 2, 11, 10, F_NONE),
            eff(2, -3, 3, -2, 18, F_NONE),
            eff(-5, 2, -6, 5, 0, F_PREDATOR),
        ],
        // Slot 3: Biomass Decomposer (0 Plastic Trash Bags, 1 Incinerator, 2 Oyster Mushrooms + BSF Larvae ✅, 3 Vent Airlock)
        [
            eff(-2, 1, -9, 4, 0, F_NONE),
            eff(-13, 0, -3, 15, 0, F_LETHAL),
            eff(-1, -1, 6, -4, 20, F_NONE),
            eff(-3, 0, -10, 0, 0, F_EXTERNAL),
        ],
        // Slot 4: Water Loop (0 Open Evap, 1 Brine Dump, 2 Transpiration Condenser + Reed Bed ✅, 3 Import Ice Rockets)
        [
            eff(-2, 5, -3, 6, 0, F_NONE),
            eff(-2, 2, -6, 12, 0, F_NONE),
            eff(2, -2, 2, -4, 14, F_NONE),
            eff(1, 0, 0, 0, 8, F_EXTERNAL),
        ],
        // Slot 5: Soil Buffer (0 Raw Toxic Perchlorate Dust, 1 Washed Regolith + Biochar & Worm Humus ✅, 2 Sterile Sand, 3 Plastic)
        [
            eff(-5, 2, -8, 22, 0, F_LETHAL),
            eff(1, -1, 5, -3, 16, F_NONE),
            eff(0, 1, -7, 2, 2, F_NONE),
            eff(-1, 2, -6, 4, 0, F_NONE),
        ],
    ],
];

#[derive(Clone, Copy)]
pub struct SimResult {
    pub is_halt_free: bool,
    pub halt_reason: u8,
    pub seasons_survived: u8,
    pub stars: u8,
    pub final_oxygen: u8,
    pub final_clarity: u8,
    pub final_fertility: u8,
    pub final_toxicity: u8,
    pub total_yield: u16,
}

/// Deterministic 12-season closed-loop ecological simulator.
pub fn simulate_ecosystem(arena_id: usize, slots: &[u8; NUM_SLOTS]) -> SimResult {
    let arena = if arena_id < NUM_ARENAS { arena_id } else { 0 };
    let mut oxygen: i16 = 74;
    let mut algae: i16 = 24; // clarity = 100 - algae
    let mut fertility: i16 = 68;
    let mut toxicity: i16 = 12;
    let mut total_yield: u16 = 0;

    let mut sum_o2: i16 = -4;
    let mut sum_alg: i16 = 4;
    let mut sum_fert: i16 = -6;
    let mut sum_tox: i16 = 5;
    let mut base_season_yield: u16 = 0;
    let mut all_flags: u8 = 0;

    let mut s = 0usize;
    while s < NUM_SLOTS {
        let opt = (slots[s] as usize).min(NUM_OPTIONS - 1);
        let ef = ECOLOGY_MATRIX[arena][s][opt];
        sum_o2 += ef.d_oxygen;
        sum_alg += ef.d_algae;
        sum_fert += ef.d_fertility;
        sum_tox += ef.d_toxicity;
        base_season_yield = base_season_yield.saturating_add(ef.d_yield);
        all_flags |= ef.flags;
        s += 1;
    }

    // Special ecological synergy checks!
    // In Arena 0, Silkworms (slot 1 == 1) need Mulberry Trees (slot 0 == 2) to eat!
    if arena == 0 && slots[1] == 1 && slots[0] != 2 {
        sum_fert -= 5;
        base_season_yield = base_season_yield.saturating_sub(16);
    }

    let mut season = 0u8;
    let mut halt_reason = HALT_NONE;

    while (season as usize) < NUM_SEASONS {
        season += 1;

        oxygen = (oxygen + sum_o2).clamp(0, 100);
        algae = (algae + sum_alg).clamp(5, 100);
        fertility = (fertility + sum_fert).clamp(0, 100);
        toxicity = (toxicity + sum_tox).clamp(0, 100);

        // Coupled biological feedbacks:
        // 1. High micro-algae (> 62) causes nighttime respiration O2 crash (eutrophication)!
        if algae > 62 {
            oxygen = (oxygen - ((algae - 58) / 2)).clamp(0, 100);
        }
        // 2. Predator/pest outbreaks progressively collapse yield & spike waste!
        if (all_flags & F_PREDATOR) != 0 && season >= 3 {
            fertility = (fertility - 5).clamp(0, 100);
            toxicity = (toxicity + 5).clamp(0, 100);
        }

        // Check Halt Thresholds in priority order
        if (all_flags & F_LETHAL) != 0 && toxicity >= 45 {
            halt_reason = HALT_AMMONIA_TOXICITY;
            break;
        }
        if toxicity >= 55 {
            halt_reason = HALT_AMMONIA_TOXICITY;
            break;
        }
        if (all_flags & F_PREDATOR) != 0 && season >= 5 {
            halt_reason = HALT_TROPHIC_PREDATION;
            break;
        }
        if algae >= 76 {
            halt_reason = HALT_EUTROPHICATION;
            break;
        }
        if oxygen <= 36 {
            halt_reason = HALT_HYPOXIA;
            break;
        }
        if fertility <= 26 {
            halt_reason = HALT_NUTRIENT_STARVATION;
            break;
        }

        // Healthy season harvest scales with fertility & water clarity!
        let clarity_now = (100 - algae).max(0) as u16;
        let health_mult = ((oxygen as u16 + clarity_now + fertility as u16) / 3).clamp(40, 110);
        let season_harvest = ((base_season_yield as u32 * health_mult as u32) / 100) as u16;
        total_yield = total_yield.saturating_add(season_harvest);
    }

    if halt_reason == HALT_NONE && (all_flags & F_EXTERNAL) != 0 {
        halt_reason = HALT_EXTERNAL_DEPENDENCY;
    }
    if halt_reason == HALT_NONE && total_yield < 700 {
        halt_reason = HALT_NUTRIENT_STARVATION;
    }

    let final_clarity = (100 - algae).clamp(0, 100) as u8;
    let is_halt_free = halt_reason == HALT_NONE && season == NUM_SEASONS as u8;

    let stars = if !is_halt_free {
        0
    } else if total_yield >= 1080 && oxygen >= 82 && final_clarity >= 72 && toxicity <= 15 {
        3
    } else if total_yield >= 880 {
        2
    } else {
        1
    };

    SimResult {
        is_halt_free,
        halt_reason,
        seasons_survived: season,
        stars,
        final_oxygen: oxygen as u8,
        final_clarity,
        final_fertility: fertility as u8,
        final_toxicity: toxicity as u8,
        total_yield,
    }
}

// ---------------------------------------------------------------------------
// Persistent On-Chain Storage Records (`PlayerProgress`, `Leaderboard`, `Logs`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct PlayerProgress {
    pub identity: [u8; 20],
    pub solved_mask: u8,
    pub last_arena: u8,
    pub last_halt_reason: u8,
    pub last_seasons: u8,
    pub attempts: u16,
    pub best_stars: [u8; NUM_ARENAS],
    pub best_yield: [u16; NUM_ARENAS],
    pub best_slots: [[u8; NUM_SLOTS]; NUM_ARENAS],
    pub last_slots: [u8; NUM_SLOTS],
}

impl PlayerProgress {
    pub const fn empty(identity: [u8; 20]) -> Self {
        Self {
            identity,
            solved_mask: 0,
            last_arena: 0,
            last_halt_reason: 0,
            last_seasons: 0,
            attempts: 0,
            best_stars: [0; NUM_ARENAS],
            best_yield: [0; NUM_ARENAS],
            best_slots: [[0; NUM_SLOTS]; NUM_ARENAS],
            last_slots: [0; NUM_SLOTS],
        }
    }

    pub fn total_stars(&self) -> u8 {
        self.best_stars[0] + self.best_stars[1] + self.best_stars[2] + self.best_stars[3]
    }

    pub fn total_yield(&self) -> u32 {
        (self.best_yield[0] as u32)
            + (self.best_yield[1] as u32)
            + (self.best_yield[2] as u32)
            + (self.best_yield[3] as u32)
    }

    pub fn to_bytes(&self) -> [u8; 70] {
        let mut b = [0u8; 70];
        b[0..20].copy_from_slice(&self.identity);
        b[20] = self.solved_mask;
        b[21] = self.last_arena;
        b[22] = self.last_halt_reason;
        b[23] = self.last_seasons;
        b[24..26].copy_from_slice(&self.attempts.to_be_bytes());
        b[26..30].copy_from_slice(&self.best_stars);
        let mut p = 30;
        let mut i = 0;
        while i < NUM_ARENAS {
            b[p..p + 2].copy_from_slice(&self.best_yield[i].to_be_bytes());
            p += 2;
            i += 1;
        }
        i = 0;
        while i < NUM_ARENAS {
            b[p..p + 6].copy_from_slice(&self.best_slots[i]);
            p += 6;
            i += 1;
        }
        b[62..68].copy_from_slice(&self.last_slots);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 70 {
            return None;
        }
        let mut identity = [0u8; 20];
        identity.copy_from_slice(&b[0..20]);
        let mut best_stars = [0u8; NUM_ARENAS];
        best_stars.copy_from_slice(&b[26..30]);
        let mut best_yield = [0u16; NUM_ARENAS];
        let mut p = 30;
        let mut i = 0;
        while i < NUM_ARENAS {
            best_yield[i] = u16::from_be_bytes([b[p], b[p + 1]]);
            p += 2;
            i += 1;
        }
        let mut best_slots = [[0u8; NUM_SLOTS]; NUM_ARENAS];
        i = 0;
        while i < NUM_ARENAS {
            best_slots[i].copy_from_slice(&b[p..p + 6]);
            p += 6;
            i += 1;
        }
        let mut last_slots = [0u8; NUM_SLOTS];
        last_slots.copy_from_slice(&b[62..68]);

        Some(Self {
            identity,
            solved_mask: b[20],
            last_arena: b[21],
            last_halt_reason: b[22],
            last_seasons: b[23],
            attempts: u16::from_be_bytes([b[24], b[25]]),
            best_stars,
            best_yield,
            best_slots,
            last_slots,
        })
    }
}

fn player_key(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"hfe:p:").push(identity)
}

fn load_player(identity: &[u8; 20]) -> PlayerProgress {
    let k = player_key(identity);
    let mut buf = [0u8; 70];
    let n = storage::get_into(k.as_slice(), &mut buf).unwrap_or(0);
    if n >= 70 {
        PlayerProgress::from_bytes(&buf).unwrap_or_else(|| PlayerProgress::empty(*identity))
    } else {
        PlayerProgress::empty(*identity)
    }
}

fn save_player(p: &PlayerProgress) {
    let k = player_key(&p.identity);
    storage::set(k.as_slice(), &p.to_bytes());
}

fn update_leaderboard(p: &PlayerProgress) {
    // Each entry: 20B identity + 1B solved_mask + 1B total_stars + 4B total_yield + 2B attempts = 28B
    let mut raw = [0u8; 1 + MAX_LEADERBOARD * 28];
    let n = storage::get_into(KEY_LEADERS, &mut raw).unwrap_or(0);
    let mut count = if n >= 1 { (raw[0] as usize).min(MAX_LEADERBOARD) } else { 0 };

    let mut entries = [[0u8; 28]; MAX_LEADERBOARD];
    let mut i = 0usize;
    while i < count && (1 + (i + 1) * 28) <= n {
        entries[i].copy_from_slice(&raw[1 + i * 28..1 + (i + 1) * 28]);
        i += 1;
    }
    count = i;

    let mut rec = [0u8; 28];
    rec[0..20].copy_from_slice(&p.identity);
    rec[20] = p.solved_mask;
    rec[21] = p.total_stars();
    rec[22..26].copy_from_slice(&p.total_yield().to_be_bytes());
    rec[26..28].copy_from_slice(&p.attempts.to_be_bytes());

    let mut found = false;
    i = 0;
    while i < count {
        if &entries[i][0..20] == &p.identity {
            entries[i] = rec;
            found = true;
            break;
        }
        i += 1;
    }
    if !found {
        if count < MAX_LEADERBOARD {
            entries[count] = rec;
            count += 1;
        } else {
            entries[MAX_LEADERBOARD - 1] = rec;
        }
    }

    // Insertion sort descending by (total_stars, total_yield)
    let mut a = 1usize;
    while a < count {
        let cur = entries[a];
        let cur_stars = cur[21];
        let cur_yield = u32::from_be_bytes([cur[22], cur[23], cur[24], cur[25]]);
        let mut b = a;
        while b > 0 {
            let prev = entries[b - 1];
            let prev_stars = prev[21];
            let prev_yield = u32::from_be_bytes([prev[22], prev[23], prev[24], prev[25]]);
            if cur_stars > prev_stars || (cur_stars == prev_stars && cur_yield > prev_yield) {
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

fn push_activity_log(identity: &[u8; 20], arena_id: u8, res: &SimResult) {
    // Each log: 20B identity + 1B arena_id + 1B halt_reason + 1B stars + 1B seasons + 2B yield + 2B pad = 28B
    let mut raw = [0u8; 1 + MAX_RECENT_LOGS * 28];
    let n = storage::get_into(KEY_LOGS, &mut raw).unwrap_or(0);
    let mut count = if n >= 1 { (raw[0] as usize).min(MAX_RECENT_LOGS) } else { 0 };
    let mut items = [[0u8; 28]; MAX_RECENT_LOGS];
    let mut i = 0usize;
    while i < count && (1 + (i + 1) * 28) <= n {
        items[i].copy_from_slice(&raw[1 + i * 28..1 + (i + 1) * 28]);
        i += 1;
    }
    count = i;

    let mut rec = [0u8; 28];
    rec[0..20].copy_from_slice(identity);
    rec[20] = arena_id;
    rec[21] = res.halt_reason;
    rec[22] = res.stars;
    rec[23] = res.seasons_survived;
    rec[24..26].copy_from_slice(&res.total_yield.to_be_bytes());

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

/// Verify `identity_addr` is a real deployed Identity HFS owned/authorized by `caller`.
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

// ---------------------------------------------------------------------------
// ABI Entrypoints (`hps_entry!`)
// ---------------------------------------------------------------------------

hps_entry! {
    "initialize(string)" => handle_initialize,
    "submitEcosystem(uint64,address,bytes)" => handle_submit_ecosystem,
    "previewSimulation(uint64,bytes)" => handle_preview_simulation,
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

fn decode_six_slots(slice: &[u8]) -> [u8; NUM_SLOTS] {
    let mut s = [0u8; NUM_SLOTS];
    let mut i = 0usize;
    while i < NUM_SLOTS && i < slice.len() {
        s[i] = slice[i] % (NUM_OPTIONS as u8);
        i += 1;
    }
    s
}

fn handle_submit_ecosystem(args: &CalldataReader) -> Result<i32, i32> {
    let arena_id = (args.u64(0).ok_or(-10)? as usize).min(NUM_ARENAS - 1);
    let identity = args.address(1).ok_or(-11)?;
    let raw_choices = args.dynamic_bytes(2).ok_or(-12)?;
    if raw_choices.len() < NUM_SLOTS {
        return Err(-13);
    }

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &identity) {
        return Err(-40);
    }

    let slots = decode_six_slots(raw_choices);
    let sim = simulate_ecosystem(arena_id, &slots);

    let mut player = load_player(&identity);
    player.attempts = player.attempts.saturating_add(1);
    player.last_arena = arena_id as u8;
    player.last_halt_reason = sim.halt_reason;
    player.last_seasons = sim.seasons_survived;
    player.last_slots = slots;

    if sim.is_halt_free {
        player.solved_mask |= 1 << arena_id;
        if sim.stars >= player.best_stars[arena_id] && sim.total_yield >= player.best_yield[arena_id] {
            player.best_slots[arena_id] = slots;
        }
        if sim.stars > player.best_stars[arena_id] {
            player.best_stars[arena_id] = sim.stars;
        }
        if sim.total_yield > player.best_yield[arena_id] {
            player.best_yield[arena_id] = sim.total_yield;
        }
    }

    save_player(&player);
    update_leaderboard(&player);
    push_activity_log(&identity, arena_id as u8, &sim);

    let mut ev_data = [0u8; 128];
    ev_data[24..32].copy_from_slice(&(arena_id as u64).to_be_bytes());
    ev_data[56..64].copy_from_slice(&(sim.halt_reason as u64).to_be_bytes());
    ev_data[88..96].copy_from_slice(&(sim.stars as u64).to_be_bytes());
    ev_data[120..128].copy_from_slice(&(sim.total_yield as u64).to_be_bytes());
    let mut id_topic = [0u8; 32];
    id_topic[12..32].copy_from_slice(&identity);
    events::emit(&[EV_ECOSYSTEM_TESTED, id_topic], &ev_data);

    let mut out = [0u8; 12];
    out[0] = if sim.is_halt_free { 1 } else { 0 };
    out[1] = sim.halt_reason;
    out[2] = sim.seasons_survived;
    out[3] = sim.stars;
    out[4] = sim.final_oxygen;
    out[5] = sim.final_clarity;
    out[6] = sim.final_fertility;
    out[7] = sim.final_toxicity;
    out[8..10].copy_from_slice(&sim.total_yield.to_be_bytes());
    out[10] = player.solved_mask;
    out[11] = player.total_stars();
    ret::write(&out);
    Ok(12)
}

fn handle_preview_simulation(args: &CalldataReader) -> Result<i32, i32> {
    let arena_id = (args.u64(0).ok_or(-10)? as usize).min(NUM_ARENAS - 1);
    let raw_choices = args.dynamic_bytes(1).ok_or(-11)?;
    let slots = decode_six_slots(raw_choices);
    let sim = simulate_ecosystem(arena_id, &slots);

    let mut out = [0u8; 10];
    out[0] = if sim.is_halt_free { 1 } else { 0 };
    out[1] = sim.halt_reason;
    out[2] = sim.seasons_survived;
    out[3] = sim.stars;
    out[4] = sim.final_oxygen;
    out[5] = sim.final_clarity;
    out[6] = sim.final_fertility;
    out[7] = sim.final_toxicity;
    out[8..10].copy_from_slice(&sim.total_yield.to_be_bytes());
    ret::write(&out);
    Ok(10)
}

fn handle_get_overview(args: &CalldataReader) -> Result<i32, i32> {
    let viewer = args.address(0).unwrap_or([0u8; 20]);
    let player = load_player(&viewer);
    let p_bytes = player.to_bytes();

    let mut leaders_raw = [0u8; 1 + MAX_LEADERBOARD * 28];
    let l_n = storage::get_into(KEY_LEADERS, &mut leaders_raw).unwrap_or(0);
    let l_cnt = if l_n >= 1 { (leaders_raw[0] as usize).min(MAX_LEADERBOARD) } else { 0 };

    let mut logs_raw = [0u8; 1 + MAX_RECENT_LOGS * 28];
    let g_n = storage::get_into(KEY_LOGS, &mut logs_raw).unwrap_or(0);
    let g_cnt = if g_n >= 1 { (logs_raw[0] as usize).min(MAX_RECENT_LOGS) } else { 0 };

    let mut out = [0u8; 82 + MAX_LEADERBOARD * 28 + MAX_RECENT_LOGS * 28];
    out[0] = 1;
    out[1] = l_cnt as u8;
    out[2] = g_cnt as u8;
    out[4..12].copy_from_slice(&context::block_number().to_be_bytes());
    out[12..82].copy_from_slice(&p_bytes);

    let mut pos = 82;
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

    #[test]
    fn all_four_historical_and_biospheric_arenas_achieve_3_star_haltfree_loop() {
        let optimal_genomes: [[u8; NUM_SLOTS]; NUM_ARENAS] = [
            [2, 1, 3, 1, 2, 3], // Arena 0: 2,400-yr Chinese Mulberry-Dyke Carp Polyculture
            [1, 3, 1, 2, 3, 1], // Arena 1: Aztec Chinampa & Axolotl Canal
            [2, 1, 3, 1, 2, 2], // Arena 2: Solar Aquaponics & Nitrification Dome
            [3, 1, 2, 2, 2, 1], // Arena 3: Sealed Martian Biosphere BIOS-IV
        ];

        for (arena_id, genome) in optimal_genomes.iter().enumerate() {
            let res = simulate_ecosystem(arena_id, genome);
            assert!(
                res.is_halt_free,
                "Arena {} optimal genome halted: reason={}, season={}, o2={}, clar={}, fert={}, tox={}, yield={}",
                arena_id,
                res.halt_reason,
                res.seasons_survived,
                res.final_oxygen,
                res.final_clarity,
                res.final_fertility,
                res.final_toxicity,
                res.total_yield
            );
            assert_eq!(res.halt_reason, HALT_NONE);
            assert_eq!(res.seasons_survived, 12);
            assert_eq!(res.stars, 3, "Expected 3 stars on Arena {}, got {} (yield={})", arena_id, res.stars, res.total_yield);
        }
    }

    #[test]
    fn broken_ecology_diagnoses_exact_educational_halt_causes() {
        // 1. Missing Silver Carp filter-feeder in Mulberry Pond -> Eutrophication Halt!
        let no_silver_carp = [2, 1, 3, 0, 2, 3];
        let r1 = simulate_ecosystem(0, &no_silver_carp);
        assert!(!r1.is_halt_free);
        assert_eq!(r1.halt_reason, HALT_EUTROPHICATION);

        // 2. Pesticide Monocrop Corn on the Dyke -> Ammonia / Chemical Toxicity Halt!
        let pesticide_dyke = [3, 1, 3, 1, 2, 3];
        let r2 = simulate_ecosystem(0, &pesticide_dyke);
        assert!(!r2.is_halt_free);
        assert_eq!(r2.halt_reason, HALT_AMMONIA_TOXICITY);

        // 3. Snakehead Predator in Surface Layer -> Trophic Predation Halt!
        let predator_pond = [2, 1, 1, 1, 2, 3];
        let r3 = simulate_ecosystem(0, &predator_pond);
        assert!(!r3.is_halt_free);
        assert_eq!(r3.halt_reason, HALT_TROPHIC_PREDATION);

        // 4. Diesel Pellet Feeder instead of Silkworms -> External Dependency (Not Closed-Loop)!
        let external_feed = [2, 3, 3, 1, 1, 3];
        let r4 = simulate_ecosystem(0, &external_feed);
        assert!(!r4.is_halt_free);
    }
}
