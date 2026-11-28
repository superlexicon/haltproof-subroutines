//! # Jones in the Blockchain (`jones-blockchain` — HPS #24)
//!
//! Cozy, family-friendly, slow-paced turn-based life-simulation & career/education strategy
//! Haltproof Subroutine inspired by the classic early-PC game *Jones in the Fast Lane*,
//! designed for `1..=4` seats (Solo vs. AI Rival **"Jones"** + quirky town bots, OR `2..=4`
//! player family/friends PvP tables that persist indefinitely on-chain).
//!
//! ## Core Mechanics
//! 1. **Four Victory Pillars (`0..=100%` each — first player at `100%` in all four wins!)**:
//!    - **Wealth**: Cash + First Consensus Bank Savings (`2%`/wk yield) + Dynamic Town Stocks - Rent Debt.
//!    - **Happiness**: Earned from milestones, diplomas, home appliances, plaza picnics, good outfits, and cozy living.
//!    - **Education**: `4` Degree Tracks at **Haltproof University** (`10` study credits per degree; `Home Computer` doubles study speed!).
//!    - **Career**: `12` progressive town jobs across `6` workplaces + Career Experience & Dependability.
//! 2. **12 Perimeter Town Buildings (`0..=11`) & `60`-Hour Weekly Pocket-Watch**:
//!    - `0` Apartments (`Shady Acres` vs. bandit-proof `LeSecurity Condo`), `1` Burger Bytes Diner,
//!      `2` Z-Mart Discount Depot, `3` CryptoThreads Clothing, `4` Socket City Tech & Appliances,
//!      `5` Haltproof University, `6` Employment Office, `7` SuperLexicon Foundry,
//!      `8` First Consensus Bank & Brokerage, `9` FreshBlock Market, `10` Rent & Civic Commons,
//!      `11` Hashrate Pawn & Repair Shop.
//! 3. **Zero-Tx-Fatigue Atomic Weeks (`submitWeekPlan`)**:
//!    - Players plan and stroll around town at 0ms in the UI during their 60-hour week (`64h` with a
//!      Microwave!) and commit their entire week's `[op, arg]` steps + *"Oh, What a Weekend!"* event +
//!      AI Rival **"Jones"** turns + Macroeconomic Boom/Normal/Crunch drift in **one `$0`-gas transaction**.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::KeccakHasher;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Bounded Protocol Constants
// ---------------------------------------------------------------------------

pub const MAX_SEATS: usize = 4;
pub const NUM_BUILDINGS: u8 = 12;
pub const BASE_HOURS_PER_WEEK: u8 = 60;
pub const MICROWAVE_BONUS_HOURS: u8 = 4;
pub const NUM_DEGREES: usize = 4;
pub const CREDITS_PER_DEGREE: u8 = 10;
pub const NUM_JOBS: usize = 12;
pub const NUM_APPLIANCES: usize = 6;
pub const NUM_STOCKS: usize = 3;
pub const MAX_PLAN_STEPS: usize = 32;
pub const LOG_WINDOW: usize = 16;
pub const MAX_LISTED_GAMES: usize = 16;

pub const PHASE_LOBBY: u8 = 1;
pub const PHASE_ACTIVE: u8 = 2;
pub const PHASE_FINISHED: u8 = 3;

// Town Building Indices (0..=11 around the perimeter ring)
pub const BLD_APARTMENTS: u8 = 0;
pub const BLD_BURGERS: u8 = 1;
pub const BLD_ZMART: u8 = 2;
pub const BLD_CLOTHING: u8 = 3;
pub const BLD_TECH: u8 = 4;
pub const BLD_UNIVERSITY: u8 = 5;
pub const BLD_EMPLOYMENT: u8 = 6;
pub const BLD_FOUNDRY: u8 = 7;
pub const BLD_BANK: u8 = 8;
pub const BLD_MARKET: u8 = 9;
pub const BLD_RENT_CIVIC: u8 = 10;
pub const BLD_PAWN_REPAIR: u8 = 11;

// Appliances Bitmask Indices (0..=5)
pub const APP_FRIDGE: u8 = 0;
pub const APP_FREEZER: u8 = 1;
pub const APP_MICROWAVE: u8 = 2;
pub const APP_STEREO_TV: u8 = 3;
pub const APP_COMPUTER: u8 = 4;
pub const APP_SCOOTER: u8 = 5;

const APP_BASE_PRICES: [u32; NUM_APPLIANCES] = [320, 280, 220, 360, 540, 420];
const APP_HAP_BONUS: [u16; NUM_APPLIANCES] = [5, 5, 4, 8, 8, 6];

// Degree Indices (0..=3)
pub const DEG_JR_COLLEGE: u8 = 0;
pub const DEG_ELECTRONICS: u8 = 1;
pub const DEG_BUSINESS: u8 = 2;
pub const DEG_PROTOCOL_ARCH: u8 = 3;

// Action Plan Opcodes (`[op, arg]` pairs in `submitWeekPlan`)
pub const OP_MOVE: u8 = 1;
pub const OP_WORK: u8 = 2;
pub const OP_STUDY: u8 = 3;
pub const OP_APPLY_JOB: u8 = 4;
pub const OP_ASK_RAISE: u8 = 5;
pub const OP_BUY_FOOD: u8 = 6;
pub const OP_BUY_CLOTHES: u8 = 7;
pub const OP_BUY_APPLIANCE: u8 = 8;
pub const OP_BANK_DEPOSIT: u8 = 9;
pub const OP_BANK_WITHDRAW: u8 = 10;
pub const OP_BUY_STOCK: u8 = 11;
pub const OP_SELL_STOCK: u8 = 12;
pub const OP_PAY_RENT: u8 = 13;
pub const OP_SWITCH_APT: u8 = 14;
pub const OP_RELAX: u8 = 15;
pub const OP_REPAIR_PAWN: u8 = 16;

// Weekend Gazette Event IDs (`1..=12` — wholesome, humorous, family-friendly!)
pub const WKND_COZY_QUIET: u8 = 1;
pub const WKND_SNEAKY_SAM: u8 = 2;
pub const WKND_CONDO_FOILED_SAM: u8 = 3;
pub const WKND_HUNGRY_RUMBLE: u8 = 4;
pub const WKND_FOOD_SPOILED: u8 = 5;
pub const WKND_AUNT_GIFT: u8 = 6;
pub const WKND_BLOCK_PARTY: u8 = 7;
pub const WKND_TAX_REBATE: u8 = 8;
pub const WKND_APPLIANCE_HICCUP: u8 = 9;
pub const WKND_COMPUTER_TIPS: u8 = 10;
pub const WKND_RENT_BILLED: u8 = 11;
pub const WKND_VICTORY_BELLS: u8 = 12;

const KEY_GAME_LIST: &[u8] = b"jones:games";

const EV_GAME_UPDATED: [u8; 32] = event_topic("JonesGameUpdated(bytes32,uint64,uint64,uint64)");
const EV_JONES_VICTORY: [u8; 32] = event_topic("JonesVictory(bytes32,address,uint64,uint64)");

// ---------------------------------------------------------------------------
// Career Catalog (`job_id` 1..=12; `0` = Unemployed)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct JobSpec {
    pub workplace: u8,
    pub base_wage: u16,
    pub dress_tier: u8,
    pub req_deg_mask: u8,
    pub any_adv_deg: bool, // for Adjunct Lecturer: requires Jr College + (Electronics OR Business)
    pub req_exp: u8,
    pub req_dep: u8,
    pub rank: u8, // 1..=10
}

const JOBS: [JobSpec; NUM_JOBS] = [
    // 1: Fry Cook @ Burger Bytes
    JobSpec { workplace: BLD_BURGERS, base_wage: 8, dress_tier: 1, req_deg_mask: 0, any_adv_deg: false, req_exp: 0, req_dep: 0, rank: 1 },
    // 2: Stock Clerk @ Z-Mart
    JobSpec { workplace: BLD_ZMART, base_wage: 9, dress_tier: 1, req_deg_mask: 0, any_adv_deg: false, req_exp: 0, req_dep: 0, rank: 1 },
    // 3: Foundry Custodian @ SuperLexicon Foundry
    JobSpec { workplace: BLD_FOUNDRY, base_wage: 10, dress_tier: 1, req_deg_mask: 0, any_adv_deg: false, req_exp: 4, req_dep: 15, rank: 2 },
    // 4: Shift Supervisor @ Burger Bytes
    JobSpec { workplace: BLD_BURGERS, base_wage: 13, dress_tier: 1, req_deg_mask: 0b0001, any_adv_deg: false, req_exp: 10, req_dep: 20, rank: 3 },
    // 5: Gadget Bench Tech @ Socket City
    JobSpec { workplace: BLD_TECH, base_wage: 16, dress_tier: 1, req_deg_mask: 0b0010, any_adv_deg: false, req_exp: 12, req_dep: 25, rank: 4 },
    // 6: Assistant Buyer @ Z-Mart
    JobSpec { workplace: BLD_ZMART, base_wage: 17, dress_tier: 2, req_deg_mask: 0b0001, any_adv_deg: false, req_exp: 14, req_dep: 25, rank: 4 },
    // 7: Bank Ledger Teller @ First Consensus Bank
    JobSpec { workplace: BLD_BANK, base_wage: 20, dress_tier: 2, req_deg_mask: 0b0100, any_adv_deg: false, req_exp: 18, req_dep: 30, rank: 5 },
    // 8: Assembly Line Engineer @ SuperLexicon Foundry
    JobSpec { workplace: BLD_FOUNDRY, base_wage: 24, dress_tier: 2, req_deg_mask: 0b0011, any_adv_deg: false, req_exp: 24, req_dep: 35, rank: 6 },
    // 9: Adjunct Lecturer @ Haltproof University
    JobSpec { workplace: BLD_UNIVERSITY, base_wage: 27, dress_tier: 2, req_deg_mask: 0b0001, any_adv_deg: true, req_exp: 30, req_dep: 40, rank: 7 },
    // 10: Investment Analyst @ First Consensus Bank
    JobSpec { workplace: BLD_BANK, base_wage: 32, dress_tier: 3, req_deg_mask: 0b0101, any_adv_deg: false, req_exp: 36, req_dep: 45, rank: 8 },
    // 11: Chief Wasm Architect @ SuperLexicon Foundry
    JobSpec { workplace: BLD_FOUNDRY, base_wage: 38, dress_tier: 3, req_deg_mask: 0b1011, any_adv_deg: false, req_exp: 44, req_dep: 50, rank: 9 },
    // 12: Bank President / Dean @ First Consensus Bank
    JobSpec { workplace: BLD_BANK, base_wage: 45, dress_tier: 3, req_deg_mask: 0b1111, any_adv_deg: false, req_exp: 52, req_dep: 55, rank: 10 },
];

#[inline]
pub fn job_spec(job_id: u8) -> Option<JobSpec> {
    if job_id >= 1 && (job_id as usize) <= NUM_JOBS {
        Some(JOBS[(job_id - 1) as usize])
    } else {
        None
    }
}

#[inline]
pub fn ring_distance(a: u8, b: u8) -> u8 {
    let ca = a % NUM_BUILDINGS;
    let cb = b % NUM_BUILDINGS;
    let diff = if ca >= cb { ca - cb } else { cb - ca };
    if diff <= NUM_BUILDINGS - diff {
        diff
    } else {
        NUM_BUILDINGS - diff
    }
}

#[inline]
pub fn scaled_price(base: u32, econ_idx: u16) -> u32 {
    let v = (base as u64).saturating_mul(econ_idx as u64) / 100;
    (v as u32).max(1)
}

// ---------------------------------------------------------------------------
// Per-Seat & Per-Game Compact Persistent State
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SeatState {
    pub eoa: [u8; 20],
    pub identity: [u8; 20],
    pub is_bot: u8, // 0 = human, 1 = Rival Jones, 2 = Penny Hodl, 3 = Sunny Wheeler
    pub location: u8,
    pub hours_left: u8,
    pub cash: u32,
    pub savings: u32,
    pub rent_debt: u32,
    pub happiness: u16,
    pub dependability: u8,
    pub experience: u8,
    pub job_id: u8,
    pub hourly_wage: u16,
    pub apt_tier: u8, // 0 = Shady Acres ($165/mo), 1 = LeSecurity Condo ($340/mo)
    pub clothes_tier: u8, // 0 = Tattered, 1 = Casual, 2 = Smart Dress, 3 = Executive Suit
    pub clothes_weeks: u8,
    pub food_weeks: u8,
    pub degrees_mask: u8,
    pub study_credits: [u8; NUM_DEGREES],
    pub appliances_mask: u8,
    pub appliances_broken_mask: u8,
    pub stocks: [u16; NUM_STOCKS],
    pub raise_asked_this_week: u8,
    pub last_weekend_event: u8,
    pub last_weekend_delta: i16,
    pub wins: u16,
}

impl SeatState {
    pub const fn empty() -> Self {
        Self {
            eoa: [0u8; 20],
            identity: [0u8; 20],
            is_bot: 0,
            location: BLD_APARTMENTS,
            hours_left: BASE_HOURS_PER_WEEK,
            cash: 200,
            savings: 0,
            rent_debt: 0,
            happiness: 12,
            dependability: 25,
            experience: 0,
            job_id: 0,
            hourly_wage: 0,
            apt_tier: 0,
            clothes_tier: 1,
            clothes_weeks: 5,
            food_weeks: 1,
            degrees_mask: 0,
            study_credits: [0; NUM_DEGREES],
            appliances_mask: 0,
            appliances_broken_mask: 0,
            stocks: [0; NUM_STOCKS],
            raise_asked_this_week: 0,
            last_weekend_event: WKND_COZY_QUIET,
            last_weekend_delta: 0,
            wins: 0,
        }
    }

    pub fn reset_for_new_game(&mut self) {
        self.location = BLD_APARTMENTS;
        self.hours_left = BASE_HOURS_PER_WEEK;
        self.cash = 240;
        self.savings = 0;
        self.rent_debt = 0;
        self.happiness = 12;
        self.dependability = 25;
        self.experience = 0;
        self.job_id = 0;
        self.hourly_wage = 0;
        self.apt_tier = 0;
        self.clothes_tier = 1;
        self.clothes_weeks = 6;
        self.food_weeks = 1;
        self.degrees_mask = 0;
        self.study_credits = [0; NUM_DEGREES];
        self.appliances_mask = 0;
        self.appliances_broken_mask = 0;
        self.stocks = [0; NUM_STOCKS];
        self.raise_asked_this_week = 0;
        self.last_weekend_event = WKND_COZY_QUIET;
        self.last_weekend_delta = 0;
    }

    #[inline]
    pub fn has_working_appliance(&self, app_id: u8) -> bool {
        let bit = 1u8 << app_id;
        (self.appliances_mask & bit) != 0 && (self.appliances_broken_mask & bit) == 0
    }

    #[inline]
    pub fn weekly_max_hours(&self) -> u8 {
        if self.has_working_appliance(APP_MICROWAVE) {
            BASE_HOURS_PER_WEEK + MICROWAVE_BONUS_HOURS
        } else {
            BASE_HOURS_PER_WEEK
        }
    }

    #[inline]
    pub fn effective_clothes_tier(&self) -> u8 {
        if self.clothes_weeks == 0 {
            0
        } else {
            self.clothes_tier
        }
    }

    pub fn portfolio_value(&self, prices: &[u16; NUM_STOCKS]) -> u32 {
        let mut total = 0u32;
        let mut i = 0;
        while i < NUM_STOCKS {
            total = total.saturating_add((self.stocks[i] as u32).saturating_mul(prices[i] as u32));
            i += 1;
        }
        total
    }

    pub fn net_liquid_wealth(&self, prices: &[u16; NUM_STOCKS]) -> u32 {
        self.cash
            .saturating_add(self.savings)
            .saturating_add(self.portfolio_value(prices))
            .saturating_sub(self.rent_debt)
    }

    pub fn total_edu_credits(&self) -> u16 {
        let mut c = 0u16;
        let mut d = 0;
        while d < NUM_DEGREES {
            if (self.degrees_mask & (1u8 << d)) != 0 {
                c += CREDITS_PER_DEGREE as u16;
            } else {
                c += (self.study_credits[d].min(CREDITS_PER_DEGREE - 1)) as u16;
            }
            d += 1;
        }
        c
    }

    pub fn career_points(&self) -> u16 {
        let rank_pts = match job_spec(self.job_id) {
            Some(js) => (js.rank as u16) * 7,
            None => 0,
        };
        let dep_pts = (self.dependability.min(100) as u16) / 5;
        let exp_pts = (self.experience.min(100) as u16) / 5;
        rank_pts + dep_pts + exp_pts
    }

    pub fn qualifies_for_job(&self, job_id: u8) -> bool {
        let Some(js) = job_spec(job_id) else {
            return false;
        };
        if (self.degrees_mask & js.req_deg_mask) != js.req_deg_mask {
            return false;
        }
        if js.any_adv_deg && (self.degrees_mask & 0b0110) == 0 {
            return false;
        }
        if self.experience < js.req_exp || self.dependability < js.req_dep {
            return false;
        }
        if self.effective_clothes_tier() < js.dress_tier {
            return false;
        }
        true
    }

    pub fn qualifies_for_degree(&self, deg_id: u8) -> bool {
        if deg_id as usize >= NUM_DEGREES {
            return false;
        }
        if (self.degrees_mask & (1u8 << deg_id)) != 0 {
            return false;
        }
        if deg_id == DEG_PROTOCOL_ARCH {
            // Requires Junior College + (Electronics OR Business)
            (self.degrees_mask & 0b0001) != 0 && (self.degrees_mask & 0b0110) != 0
        } else {
            true
        }
    }
}

#[derive(Clone, Copy)]
pub struct GazetteLog {
    pub week: u16,
    pub seat: u8,
    pub event_id: u8,
    pub delta: i16,
    pub aux: u16,
}

impl GazetteLog {
    pub const fn empty() -> Self {
        Self {
            week: 0,
            seat: 0xFF,
            event_id: 0,
            delta: 0,
            aux: 0,
        }
    }
}

pub struct GameState {
    pub phase: u8,
    pub seat_count: u8,
    pub turn_seat: u8,
    pub winner_seat: u8,
    pub week_number: u16,
    pub economy_index: u16, // 75..=135 (100 = Normal)
    pub economy_trend: i8,  // -1 = Cooling, 0 = Steady, +1 = Sunny Boom
    pub wealth_goal: u32,
    pub hap_goal: u16,
    pub edu_goal: u16,    // in study credits (10..=40)
    pub career_goal: u16, // in career points (25..=95)
    pub stock_prices: [u16; NUM_STOCKS],
    pub rng_nonce: u64,
    pub entropy_seed: [u8; 32],
    pub log_count: u8,
    pub logs: [GazetteLog; LOG_WINDOW],
    pub seats: [SeatState; MAX_SEATS],
}

impl GameState {
    pub const fn new_lobby(
        wealth_goal: u32,
        hap_goal: u16,
        edu_goal: u16,
        career_goal: u16,
        seed: [u8; 32],
    ) -> Self {
        Self {
            phase: PHASE_LOBBY,
            seat_count: 0,
            turn_seat: 0,
            winner_seat: 0xFF,
            week_number: 1,
            economy_index: 100,
            economy_trend: 1,
            wealth_goal,
            hap_goal,
            edu_goal,
            career_goal,
            stock_prices: [100, 150, 220],
            rng_nonce: 1,
            entropy_seed: seed,
            log_count: 0,
            logs: [GazetteLog::empty(); LOG_WINDOW],
            seats: [SeatState::empty(); MAX_SEATS],
        }
    }

    pub fn next_rand_u64(&mut self) -> u64 {
        let mut h = KeccakHasher::new();
        h.update(&self.entropy_seed);
        h.update(&self.rng_nonce.to_be_bytes());
        h.update(&context::block_number().to_be_bytes());
        let d = h.finalize();
        self.rng_nonce = self.rng_nonce.wrapping_add(1);
        self.entropy_seed = d;
        let mut b = [0u8; 8];
        b.copy_from_slice(&d[0..8]);
        u64::from_be_bytes(b)
    }

    pub fn find_seat_by_eoa(&self, eoa: &[u8; 20]) -> Option<usize> {
        if *eoa == [0u8; 20] {
            return None;
        }
        let sc = (self.seat_count as usize).min(MAX_SEATS);
        let mut i = 0;
        while i < sc {
            if self.seats[i].is_bot == 0 && self.seats[i].eoa == *eoa {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    pub fn human_count(&self) -> usize {
        let sc = (self.seat_count as usize).min(MAX_SEATS);
        let mut c = 0;
        let mut i = 0;
        while i < sc {
            if self.seats[i].is_bot == 0 {
                c += 1;
            }
            i += 1;
        }
        c
    }

    pub fn push_log(&mut self, seat: u8, event_id: u8, delta: i16, aux: u16) {
        let n = self.log_count as usize;
        let entry = GazetteLog {
            week: self.week_number,
            seat,
            event_id,
            delta,
            aux,
        };
        if n < LOG_WINDOW {
            self.logs[n] = entry;
            self.log_count = (n + 1) as u8;
        } else {
            let mut i = 0;
            while i + 1 < LOG_WINDOW {
                self.logs[i] = self.logs[i + 1];
                i += 1;
            }
            self.logs[LOG_WINDOW - 1] = entry;
        }
    }

    pub fn goal_pcts(&self, seat_idx: usize) -> [u8; 4] {
        let s = &self.seats[seat_idx];
        let w = ((s.net_liquid_wealth(&self.stock_prices) as u64) * 100
            / (self.wealth_goal.max(100) as u64))
            .min(100) as u8;
        let h = ((s.happiness as u64) * 100 / (self.hap_goal.max(10) as u64)).min(100) as u8;
        let e =
            ((s.total_edu_credits() as u64) * 100 / (self.edu_goal.max(10) as u64)).min(100) as u8;
        let c =
            ((s.career_points() as u64) * 100 / (self.career_goal.max(10) as u64)).min(100) as u8;
        [w, h, e, c]
    }

    pub fn has_seat_won(&self, seat_idx: usize) -> bool {
        let p = self.goal_pcts(seat_idx);
        p[0] >= 100 && p[1] >= 100 && p[2] >= 100 && p[3] >= 100
    }
}

// ---------------------------------------------------------------------------
// Storage Serialization (`jones:g:<gameId>`)
// ---------------------------------------------------------------------------

const SEAT_BYTES: usize = 84;
const LOG_BYTES: usize = 8;
const GAME_BLOB_LEN: usize = 76 + (MAX_SEATS * SEAT_BYTES) + (LOG_WINDOW * LOG_BYTES); // 540 bytes

fn game_key(gid: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"jones:g:").push(gid)
}

fn save_game(gid: &[u8; 32], st: &GameState) {
    let mut buf = [0u8; GAME_BLOB_LEN];
    buf[0] = 1; // schema v1
    buf[1] = st.phase;
    buf[2] = st.seat_count;
    buf[3] = st.turn_seat;
    buf[4] = st.winner_seat;
    buf[5] = st.economy_trend as u8;
    buf[6..8].copy_from_slice(&st.week_number.to_be_bytes());
    buf[8..10].copy_from_slice(&st.economy_index.to_be_bytes());
    buf[10..14].copy_from_slice(&st.wealth_goal.to_be_bytes());
    buf[14..16].copy_from_slice(&st.hap_goal.to_be_bytes());
    buf[16..18].copy_from_slice(&st.edu_goal.to_be_bytes());
    buf[18..20].copy_from_slice(&st.career_goal.to_be_bytes());
    buf[20..22].copy_from_slice(&st.stock_prices[0].to_be_bytes());
    buf[22..24].copy_from_slice(&st.stock_prices[1].to_be_bytes());
    buf[24..26].copy_from_slice(&st.stock_prices[2].to_be_bytes());
    buf[26] = st.log_count;
    buf[27] = 0;
    buf[28..36].copy_from_slice(&st.rng_nonce.to_be_bytes());
    buf[36..68].copy_from_slice(&st.entropy_seed);
    // 68..76 reserved

    let mut pos = 76;
    let mut i = 0;
    while i < MAX_SEATS {
        let s = &st.seats[i];
        buf[pos..pos + 20].copy_from_slice(&s.eoa);
        buf[pos + 20..pos + 40].copy_from_slice(&s.identity);
        buf[pos + 40] = s.is_bot;
        buf[pos + 41] = s.location;
        buf[pos + 42] = s.hours_left;
        buf[pos + 43..47 + pos].copy_from_slice(&s.cash.to_be_bytes());
        buf[pos + 47..51 + pos].copy_from_slice(&s.savings.to_be_bytes());
        buf[pos + 51..55 + pos].copy_from_slice(&s.rent_debt.to_be_bytes());
        buf[pos + 55..57 + pos].copy_from_slice(&s.happiness.to_be_bytes());
        buf[pos + 57] = s.dependability;
        buf[pos + 58] = s.experience;
        buf[pos + 59] = s.job_id;
        buf[pos + 60..62 + pos].copy_from_slice(&s.hourly_wage.to_be_bytes());
        buf[pos + 62] = s.apt_tier;
        buf[pos + 63] = s.clothes_tier;
        buf[pos + 64] = s.clothes_weeks;
        buf[pos + 65] = s.food_weeks;
        buf[pos + 66] = s.degrees_mask;
        buf[pos + 67..71 + pos].copy_from_slice(&s.study_credits);
        buf[pos + 71] = s.appliances_mask;
        buf[pos + 72] = s.appliances_broken_mask;
        buf[pos + 73..75 + pos].copy_from_slice(&s.stocks[0].to_be_bytes());
        buf[pos + 75..77 + pos].copy_from_slice(&s.stocks[1].to_be_bytes());
        buf[pos + 77..79 + pos].copy_from_slice(&s.stocks[2].to_be_bytes());
        buf[pos + 79] = s.raise_asked_this_week;
        buf[pos + 80] = s.last_weekend_event;
        buf[pos + 81..83 + pos].copy_from_slice(&s.last_weekend_delta.to_be_bytes());
        buf[pos + 83] = (s.wins.min(255)) as u8;
        pos += SEAT_BYTES;
        i += 1;
    }

    let mut li = 0;
    while li < LOG_WINDOW {
        let lg = &st.logs[li];
        buf[pos..pos + 2].copy_from_slice(&lg.week.to_be_bytes());
        buf[pos + 2] = lg.seat;
        buf[pos + 3] = lg.event_id;
        buf[pos + 4..pos + 6].copy_from_slice(&lg.delta.to_be_bytes());
        buf[pos + 6..pos + 8].copy_from_slice(&lg.aux.to_be_bytes());
        pos += LOG_BYTES;
        li += 1;
    }

    let key = game_key(gid);
    storage::set(key.as_slice(), &buf);
}

fn load_game(gid: &[u8; 32]) -> Option<GameState> {
    let key = game_key(gid);
    let mut buf = [0u8; GAME_BLOB_LEN];
    let n = storage::get_into(key.as_slice(), &mut buf)?;
    if n < GAME_BLOB_LEN || buf[0] != 1 {
        return None;
    }

    let mut u16b = [0u8; 2];
    let mut u32b = [0u8; 4];
    let mut u64b = [0u8; 8];
    let mut seed = [0u8; 32];

    u16b.copy_from_slice(&buf[6..8]);
    let week_number = u16::from_be_bytes(u16b);
    u16b.copy_from_slice(&buf[8..10]);
    let economy_index = u16::from_be_bytes(u16b);
    u32b.copy_from_slice(&buf[10..14]);
    let wealth_goal = u32::from_be_bytes(u32b);
    u16b.copy_from_slice(&buf[14..16]);
    let hap_goal = u16::from_be_bytes(u16b);
    u16b.copy_from_slice(&buf[16..18]);
    let edu_goal = u16::from_be_bytes(u16b);
    u16b.copy_from_slice(&buf[18..20]);
    let career_goal = u16::from_be_bytes(u16b);

    let mut stock_prices = [100u16; NUM_STOCKS];
    u16b.copy_from_slice(&buf[20..22]);
    stock_prices[0] = u16::from_be_bytes(u16b);
    u16b.copy_from_slice(&buf[22..24]);
    stock_prices[1] = u16::from_be_bytes(u16b);
    u16b.copy_from_slice(&buf[24..26]);
    stock_prices[2] = u16::from_be_bytes(u16b);

    u64b.copy_from_slice(&buf[28..36]);
    let rng_nonce = u64::from_be_bytes(u64b);
    seed.copy_from_slice(&buf[36..68]);

    let mut st = GameState::new_lobby(wealth_goal, hap_goal, edu_goal, career_goal, seed);
    st.phase = buf[1];
    st.seat_count = buf[2];
    st.turn_seat = buf[3];
    st.winner_seat = buf[4];
    st.economy_trend = buf[5] as i8;
    st.week_number = week_number;
    st.economy_index = economy_index;
    st.stock_prices = stock_prices;
    st.rng_nonce = rng_nonce;
    st.log_count = buf[26].min(LOG_WINDOW as u8);

    let mut pos = 76;
    let mut i = 0;
    while i < MAX_SEATS {
        let mut s = SeatState::empty();
        s.eoa.copy_from_slice(&buf[pos..pos + 20]);
        s.identity.copy_from_slice(&buf[pos + 20..pos + 40]);
        s.is_bot = buf[pos + 40];
        s.location = buf[pos + 41];
        s.hours_left = buf[pos + 42];
        u32b.copy_from_slice(&buf[pos + 43..pos + 47]);
        s.cash = u32::from_be_bytes(u32b);
        u32b.copy_from_slice(&buf[pos + 47..pos + 51]);
        s.savings = u32::from_be_bytes(u32b);
        u32b.copy_from_slice(&buf[pos + 51..pos + 55]);
        s.rent_debt = u32::from_be_bytes(u32b);
        u16b.copy_from_slice(&buf[pos + 55..pos + 57]);
        s.happiness = u16::from_be_bytes(u16b);
        s.dependability = buf[pos + 57];
        s.experience = buf[pos + 58];
        s.job_id = buf[pos + 59];
        u16b.copy_from_slice(&buf[pos + 60..pos + 62]);
        s.hourly_wage = u16::from_be_bytes(u16b);
        s.apt_tier = buf[pos + 62];
        s.clothes_tier = buf[pos + 63];
        s.clothes_weeks = buf[pos + 64];
        s.food_weeks = buf[pos + 65];
        s.degrees_mask = buf[pos + 66];
        s.study_credits.copy_from_slice(&buf[pos + 67..pos + 71]);
        s.appliances_mask = buf[pos + 71];
        s.appliances_broken_mask = buf[pos + 72];
        u16b.copy_from_slice(&buf[pos + 73..pos + 75]);
        s.stocks[0] = u16::from_be_bytes(u16b);
        u16b.copy_from_slice(&buf[pos + 75..pos + 77]);
        s.stocks[1] = u16::from_be_bytes(u16b);
        u16b.copy_from_slice(&buf[pos + 77..pos + 79]);
        s.stocks[2] = u16::from_be_bytes(u16b);
        s.raise_asked_this_week = buf[pos + 79];
        s.last_weekend_event = buf[pos + 80];
        u16b.copy_from_slice(&buf[pos + 81..pos + 83]);
        s.last_weekend_delta = i16::from_be_bytes(u16b);
        s.wins = buf[pos + 83] as u16;
        st.seats[i] = s;
        pos += SEAT_BYTES;
        i += 1;
    }

    let mut li = 0;
    while li < LOG_WINDOW {
        u16b.copy_from_slice(&buf[pos..pos + 2]);
        let week = u16::from_be_bytes(u16b);
        let seat = buf[pos + 2];
        let event_id = buf[pos + 3];
        u16b.copy_from_slice(&buf[pos + 4..pos + 6]);
        let delta = i16::from_be_bytes(u16b);
        u16b.copy_from_slice(&buf[pos + 6..pos + 8]);
        let aux = u16::from_be_bytes(u16b);
        st.logs[li] = GazetteLog {
            week,
            seat,
            event_id,
            delta,
            aux,
        };
        pos += LOG_BYTES;
        li += 1;
    }

    Some(st)
}

fn register_game_in_directory(gid: &[u8; 32]) {
    let mut buf = [0u8; 1 + MAX_LISTED_GAMES * 32];
    let n = storage::get_into(KEY_GAME_LIST, &mut buf).unwrap_or(0);
    let mut cnt = if n >= 1 {
        (buf[0] as usize).min(MAX_LISTED_GAMES)
    } else {
        0
    };

    let mut i = 0;
    while i < cnt {
        let off = 1 + i * 32;
        if &buf[off..off + 32] == gid {
            return;
        }
        i += 1;
    }

    if cnt < MAX_LISTED_GAMES {
        let off = 1 + cnt * 32;
        buf[off..off + 32].copy_from_slice(gid);
        cnt += 1;
        buf[0] = cnt as u8;
    } else {
        let mut j = 0;
        while j + 1 < MAX_LISTED_GAMES {
            let src_off = 1 + (j + 1) * 32;
            let dst_off = 1 + j * 32;
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&buf[src_off..src_off + 32]);
            buf[dst_off..dst_off + 32].copy_from_slice(&tmp);
            j += 1;
        }
        let last_off = 1 + (MAX_LISTED_GAMES - 1) * 32;
        buf[last_off..last_off + 32].copy_from_slice(gid);
        buf[0] = MAX_LISTED_GAMES as u8;
    }
    storage::set(KEY_GAME_LIST, &buf[..1 + cnt * 32]);
}

fn derive_seed(gid: &[u8; 32], caller: &[u8; 20]) -> [u8; 32] {
    let mut h = KeccakHasher::new();
    h.update(b"JONES_IN_THE_BLOCKCHAIN_V1");
    h.update(gid);
    h.update(caller);
    h.update(&context::block_number().to_be_bytes());
    h.finalize()
}

fn emit_game_updated(gid: &[u8; 32], st: &GameState) {
    let mut data = [0u8; 96];
    data[31] = st.phase;
    data[56..64].copy_from_slice(&(st.week_number as u64).to_be_bytes());
    data[95] = st.turn_seat;
    events::emit(&[EV_GAME_UPDATED, *gid], &data);
}

fn emit_victory(gid: &[u8; 32], winner_eoa: &[u8; 20], seat: u8, week: u16) {
    let mut w_topic = [0u8; 32];
    w_topic[12..32].copy_from_slice(winner_eoa);
    let mut data = [0u8; 64];
    data[31] = seat;
    data[56..64].copy_from_slice(&(week as u64).to_be_bytes());
    events::emit(&[EV_JONES_VICTORY, *gid, w_topic], &data);
}

// ---------------------------------------------------------------------------
// Core Game Engine: Step Execution, Weekend Resolution & AI Rival "Jones"
// ---------------------------------------------------------------------------

fn execute_plan_step(st: &mut GameState, seat: usize, op: u8, arg: u8) {
    let econ = st.economy_index;
    match op {
        OP_MOVE => {
            let target = arg % NUM_BUILDINGS;
            let cur = st.seats[seat].location;
            if cur == target {
                return;
            }
            let dist = ring_distance(cur, target);
            let per_step = if st.seats[seat].has_working_appliance(APP_SCOOTER) {
                1u8
            } else {
                2u8
            };
            let cost = dist.saturating_mul(per_step);
            if st.seats[seat].hours_left >= cost {
                st.seats[seat].hours_left -= cost;
                st.seats[seat].location = target;
            }
        }
        OP_WORK => {
            let Some(js) = job_spec(st.seats[seat].job_id) else {
                return;
            };
            if st.seats[seat].location != js.workplace {
                return;
            }
            if st.seats[seat].effective_clothes_tier() < js.dress_tier {
                return;
            }
            let shifts = arg.clamp(1, 10);
            let mut k = 0;
            while k < shifts {
                if st.seats[seat].hours_left < 6 {
                    break;
                }
                st.seats[seat].hours_left -= 6;
                let base_pay = (st.seats[seat].hourly_wage.max(js.base_wage) as u32) * 6;
                let pay = scaled_price(base_pay, econ);
                st.seats[seat].cash = st.seats[seat].cash.saturating_add(pay);
                st.seats[seat].experience = st.seats[seat].experience.saturating_add(2).min(100);
                st.seats[seat].dependability =
                    st.seats[seat].dependability.saturating_add(2).min(100);
                k += 1;
            }
        }
        OP_STUDY => {
            if st.seats[seat].location != BLD_UNIVERSITY {
                return;
            }
            let deg = arg;
            if !st.seats[seat].qualifies_for_degree(deg) {
                return;
            }
            let tuition = scaled_price(45, econ);
            if st.seats[seat].hours_left < 6 || st.seats[seat].cash < tuition {
                return;
            }
            st.seats[seat].hours_left -= 6;
            st.seats[seat].cash -= tuition;
            let gain = if st.seats[seat].has_working_appliance(APP_COMPUTER) {
                2u8
            } else {
                1u8
            };
            let idx = deg as usize;
            let next_cred = st.seats[seat].study_credits[idx].saturating_add(gain);
            if next_cred >= CREDITS_PER_DEGREE {
                st.seats[seat].study_credits[idx] = CREDITS_PER_DEGREE;
                st.seats[seat].degrees_mask |= 1u8 << deg;
                st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(8);
            } else {
                st.seats[seat].study_credits[idx] = next_cred;
                st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(1);
            }
        }
        OP_APPLY_JOB => {
            if st.seats[seat].location != BLD_EMPLOYMENT {
                return;
            }
            if st.seats[seat].hours_left < 4 {
                return;
            }
            let jid = arg;
            let Some(js) = job_spec(jid) else {
                return;
            };
            st.seats[seat].hours_left -= 4;
            if st.seats[seat].qualifies_for_job(jid) {
                let was_lower = match job_spec(st.seats[seat].job_id) {
                    Some(prev) => js.rank > prev.rank,
                    None => true,
                };
                st.seats[seat].job_id = jid;
                st.seats[seat].hourly_wage = js.base_wage;
                if was_lower {
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(3);
                }
            }
        }
        OP_ASK_RAISE => {
            if st.seats[seat].location != BLD_EMPLOYMENT || st.seats[seat].job_id == 0 {
                return;
            }
            if st.seats[seat].raise_asked_this_week != 0 || st.seats[seat].hours_left < 4 {
                return;
            }
            st.seats[seat].hours_left -= 4;
            st.seats[seat].raise_asked_this_week = 1;
            if let Some(js) = job_spec(st.seats[seat].job_id) {
                let cap = js.base_wage.saturating_add(12);
                if st.seats[seat].dependability >= 55 && st.seats[seat].hourly_wage < cap {
                    st.seats[seat].hourly_wage = (st.seats[seat].hourly_wage + 2).min(cap);
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                }
            }
        }
        OP_BUY_FOOD => {
            let loc = st.seats[seat].location;
            if st.seats[seat].hours_left < 2 {
                return;
            }
            match (loc, arg) {
                (BLD_BURGERS, 0) => {
                    let p = scaled_price(15, econ);
                    if st.seats[seat].cash >= p {
                        st.seats[seat].cash -= p;
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].food_weeks = st.seats[seat].food_weeks.saturating_add(1).min(8);
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                    }
                }
                (BLD_BURGERS, 1) => {
                    let p = scaled_price(28, econ);
                    if st.seats[seat].cash >= p {
                        st.seats[seat].cash -= p;
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].food_weeks = st.seats[seat].food_weeks.saturating_add(2).min(8);
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(4);
                    }
                }
                (BLD_MARKET, 2) => {
                    let p = scaled_price(22, econ);
                    if st.seats[seat].cash >= p {
                        st.seats[seat].cash -= p;
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].food_weeks = st.seats[seat].food_weeks.saturating_add(1).min(8);
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(1);
                    }
                }
                (BLD_MARKET, 3) => {
                    if !st.seats[seat].has_working_appliance(APP_FRIDGE) {
                        return;
                    }
                    let p = scaled_price(38, econ);
                    if st.seats[seat].cash >= p {
                        st.seats[seat].cash -= p;
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].food_weeks = st.seats[seat].food_weeks.saturating_add(2).min(8);
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                    }
                }
                (BLD_MARKET, 4) => {
                    if !st.seats[seat].has_working_appliance(APP_FRIDGE)
                        || !st.seats[seat].has_working_appliance(APP_FREEZER)
                    {
                        return;
                    }
                    let p = scaled_price(68, econ);
                    if st.seats[seat].cash >= p {
                        st.seats[seat].cash -= p;
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].food_weeks = st.seats[seat].food_weeks.saturating_add(4).min(8);
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(4);
                    }
                }
                _ => {}
            }
        }
        OP_BUY_CLOTHES => {
            let loc = st.seats[seat].location;
            if st.seats[seat].hours_left < 2 {
                return;
            }
            if loc == BLD_ZMART && arg == 1 {
                let p = scaled_price(35, econ);
                if st.seats[seat].cash >= p {
                    st.seats[seat].cash -= p;
                    st.seats[seat].hours_left -= 2;
                    if st.seats[seat].clothes_tier < 1 {
                        st.seats[seat].clothes_tier = 1;
                    }
                    st.seats[seat].clothes_weeks = st.seats[seat].clothes_weeks.max(5);
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(1);
                }
            } else if loc == BLD_CLOTHING {
                let (tier, base_p, wks, hap) = match arg {
                    1 => (1u8, 45u32, 6u8, 1u16),
                    2 => (2u8, 95u32, 7u8, 3u16),
                    3 => (3u8, 195u32, 8u8, 6u16),
                    _ => return,
                };
                let p = scaled_price(base_p, econ);
                if st.seats[seat].cash >= p {
                    st.seats[seat].cash -= p;
                    st.seats[seat].hours_left -= 2;
                    if st.seats[seat].clothes_tier < tier || st.seats[seat].clothes_weeks == 0 {
                        st.seats[seat].clothes_tier = tier;
                    } else if tier >= st.seats[seat].clothes_tier {
                        st.seats[seat].clothes_tier = tier;
                    }
                    st.seats[seat].clothes_weeks = st.seats[seat].clothes_weeks.max(wks);
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(hap);
                }
            }
        }
        OP_BUY_APPLIANCE => {
            let app_id = arg;
            if (app_id as usize) >= NUM_APPLIANCES || st.seats[seat].hours_left < 2 {
                return;
            }
            if app_id == APP_FREEZER && (st.seats[seat].appliances_mask & (1u8 << APP_FRIDGE)) == 0 {
                return;
            }
            let loc = st.seats[seat].location;
            let base = if loc == BLD_TECH {
                APP_BASE_PRICES[app_id as usize]
            } else if loc == BLD_ZMART
                && (app_id == APP_FRIDGE || app_id == APP_MICROWAVE || app_id == APP_STEREO_TV)
            {
                // Z-Mart carries 15%-off Refurbished Specials on Fridge, Microwave & Stereo TV!
                (APP_BASE_PRICES[app_id as usize] * 85) / 100
            } else {
                return;
            };
            let bit = 1u8 << app_id;
            if (st.seats[seat].appliances_mask & bit) != 0
                && (st.seats[seat].appliances_broken_mask & bit) == 0
            {
                return;
            }
            let p = scaled_price(base, econ);
            if st.seats[seat].cash >= p {
                st.seats[seat].cash -= p;
                st.seats[seat].hours_left -= 2;
                let first_time = (st.seats[seat].appliances_mask & bit) == 0;
                st.seats[seat].appliances_mask |= bit;
                st.seats[seat].appliances_broken_mask &= !bit;
                if first_time {
                    st.seats[seat].happiness = st.seats[seat]
                        .happiness
                        .saturating_add(APP_HAP_BONUS[app_id as usize]);
                } else {
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                }
            }
        }
        OP_BANK_DEPOSIT => {
            if st.seats[seat].location != BLD_BANK || st.seats[seat].hours_left < 1 {
                return;
            }
            let amt = if arg == 0 {
                st.seats[seat].cash.saturating_sub(40)
            } else {
                ((arg as u32) * 50).min(st.seats[seat].cash)
            };
            if amt > 0 {
                st.seats[seat].hours_left -= 1;
                st.seats[seat].cash -= amt;
                st.seats[seat].savings = st.seats[seat].savings.saturating_add(amt);
            }
        }
        OP_BANK_WITHDRAW => {
            if st.seats[seat].location != BLD_BANK || st.seats[seat].hours_left < 1 {
                return;
            }
            let amt = if arg == 0 {
                st.seats[seat].savings
            } else {
                ((arg as u32) * 50).min(st.seats[seat].savings)
            };
            if amt > 0 {
                st.seats[seat].hours_left -= 1;
                st.seats[seat].savings -= amt;
                st.seats[seat].cash = st.seats[seat].cash.saturating_add(amt);
            }
        }
        OP_BUY_STOCK => {
            if st.seats[seat].location != BLD_BANK || st.seats[seat].hours_left < 1 {
                return;
            }
            let sid = ((arg >> 4) & 0x0F) as usize;
            let qty = (arg & 0x0F).max(1) as u32;
            if sid >= NUM_STOCKS {
                return;
            }
            let price = st.stock_prices[sid] as u32;
            let total = price.saturating_mul(qty);
            if st.seats[seat].cash >= total {
                st.seats[seat].hours_left -= 1;
                st.seats[seat].cash -= total;
                st.seats[seat].stocks[sid] =
                    st.seats[seat].stocks[sid].saturating_add(qty as u16).min(9999);
            }
        }
        OP_SELL_STOCK => {
            if st.seats[seat].location != BLD_BANK || st.seats[seat].hours_left < 1 {
                return;
            }
            let sid = ((arg >> 4) & 0x0F) as usize;
            if sid >= NUM_STOCKS {
                return;
            }
            let owned = st.seats[seat].stocks[sid];
            if owned == 0 {
                return;
            }
            let raw_qty = arg & 0x0F;
            let qty = if raw_qty == 0 {
                owned
            } else {
                (raw_qty as u16).min(owned)
            };
            let proceeds = (st.stock_prices[sid] as u32).saturating_mul(qty as u32);
            st.seats[seat].hours_left -= 1;
            st.seats[seat].stocks[sid] -= qty;
            st.seats[seat].cash = st.seats[seat].cash.saturating_add(proceeds);
        }
        OP_PAY_RENT => {
            if st.seats[seat].location != BLD_RENT_CIVIC || st.seats[seat].hours_left < 2 {
                return;
            }
            if st.seats[seat].rent_debt > 0 && st.seats[seat].cash > 0 {
                let pay = st.seats[seat].rent_debt.min(st.seats[seat].cash);
                st.seats[seat].hours_left -= 2;
                st.seats[seat].cash -= pay;
                st.seats[seat].rent_debt -= pay;
                if st.seats[seat].rent_debt == 0 {
                    st.seats[seat].dependability =
                        st.seats[seat].dependability.saturating_add(2).min(100);
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                }
            }
        }
        OP_SWITCH_APT => {
            if st.seats[seat].location != BLD_RENT_CIVIC || st.seats[seat].hours_left < 4 {
                return;
            }
            let target_apt = arg.min(1);
            if target_apt == st.seats[seat].apt_tier {
                return;
            }
            if target_apt == 1 {
                let dep = scaled_price(340, econ);
                if st.seats[seat].cash >= dep && st.seats[seat].rent_debt == 0 {
                    st.seats[seat].hours_left -= 4;
                    st.seats[seat].cash -= dep;
                    st.seats[seat].apt_tier = 1;
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(6);
                }
            } else {
                st.seats[seat].hours_left -= 4;
                st.seats[seat].apt_tier = 0;
            }
        }
        OP_RELAX => {
            let loc = st.seats[seat].location;
            match (loc, arg) {
                (BLD_APARTMENTS, 0) => {
                    if st.seats[seat].hours_left >= 6 {
                        st.seats[seat].hours_left -= 6;
                        let gain = if st.seats[seat].has_working_appliance(APP_STEREO_TV) {
                            5u16
                        } else {
                            3u16
                        };
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(gain);
                    }
                }
                (BLD_RENT_CIVIC, 1) => {
                    if st.seats[seat].hours_left >= 6 {
                        st.seats[seat].hours_left -= 6;
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(4);
                    }
                }
                (BLD_ZMART, 2) => {
                    let ticket = scaled_price(15, econ);
                    if st.seats[seat].hours_left >= 2 && st.seats[seat].cash >= ticket {
                        st.seats[seat].hours_left -= 2;
                        st.seats[seat].cash -= ticket;
                        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(3);
                        let r = st.next_rand_u64() % 8;
                        if r == 0 {
                            st.seats[seat].cash = st.seats[seat].cash.saturating_add(200);
                            st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(4);
                        }
                    }
                }
                _ => {}
            }
        }
        OP_REPAIR_PAWN => {
            if st.seats[seat].location != BLD_PAWN_REPAIR || st.seats[seat].hours_left < 3 {
                return;
            }
            let mode = (arg >> 4) & 0x0F;
            let app_id = arg & 0x0F;
            if (app_id as usize) >= NUM_APPLIANCES {
                return;
            }
            let bit = 1u8 << app_id;
            if mode == 0 {
                // Repair damaged appliance
                let cost = scaled_price(55, econ);
                if (st.seats[seat].appliances_broken_mask & bit) != 0 && st.seats[seat].cash >= cost
                {
                    st.seats[seat].hours_left -= 3;
                    st.seats[seat].cash -= cost;
                    st.seats[seat].appliances_broken_mask &= !bit;
                    st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
                }
            } else if mode == 1 {
                // Sell/Pawn appliance for 55% emergency cash
                if (st.seats[seat].appliances_mask & bit) != 0 {
                    let refund = scaled_price((APP_BASE_PRICES[app_id as usize] * 55) / 100, econ);
                    st.seats[seat].hours_left -= 3;
                    st.seats[seat].appliances_mask &= !bit;
                    st.seats[seat].appliances_broken_mask &= !bit;
                    st.seats[seat].cash = st.seats[seat].cash.saturating_add(refund);
                }
            }
        }
        _ => {}
    }
}

fn resolve_seat_weekend(st: &mut GameState, seat: usize) {
    let mut evt = WKND_COZY_QUIET;
    let mut delta: i16 = 0;

    // 1) Savings compound interest (2% per week)
    if st.seats[seat].savings > 0 {
        let interest = (st.seats[seat].savings / 50).max(1);
        st.seats[seat].savings = st.seats[seat].savings.saturating_add(interest);
    }

    // 2) Home Computer passive node tips ($25/wk) + LeSecurity Condo cozy bonus (+2 Hap)
    if st.seats[seat].has_working_appliance(APP_COMPUTER) {
        st.seats[seat].cash = st.seats[seat].cash.saturating_add(25);
        evt = WKND_COMPUTER_TIPS;
        delta = 25;
    }
    if st.seats[seat].apt_tier == 1 {
        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
    }

    // 3) Weekly Meal Consumption & Storage Check
    if st.seats[seat].food_weeks > 0 {
        st.seats[seat].food_weeks -= 1;
        // Check Fridge/Freezer capacity for leftover stored weeks
        let cap = if st.seats[seat].has_working_appliance(APP_FRIDGE) {
            if st.seats[seat].has_working_appliance(APP_FREEZER) {
                6u8
            } else {
                2u8
            }
        } else {
            0u8
        };
        if st.seats[seat].food_weeks > cap {
            st.seats[seat].food_weeks = cap;
            evt = WKND_FOOD_SPOILED;
            delta = -10;
        }
    } else {
        // Forgot to eat this week! Emergency corner-sandwich delivery + rumble penalty
        let emergency = 20u32.min(st.seats[seat].cash);
        st.seats[seat].cash -= emergency;
        st.seats[seat].happiness = st.seats[seat].happiness.saturating_sub(4);
        st.seats[seat].dependability = st.seats[seat].dependability.saturating_sub(3);
        evt = WKND_HUNGRY_RUMBLE;
        delta = -(emergency as i16);
    }

    // 4) Wardrobe Wear (every 2 weeks clothes wear down by 1 notch)
    if st.week_number % 2 == 0 && st.seats[seat].clothes_weeks > 0 {
        st.seats[seat].clothes_weeks -= 1;
        if st.seats[seat].clothes_weeks == 0 && st.seats[seat].clothes_tier > 1 {
            st.seats[seat].clothes_tier = 1;
            st.seats[seat].clothes_weeks = 2;
        }
    }

    // 5) Monthly Rent Check (billed every 4th week: Week 4, 8, 12...)
    if st.week_number % 4 == 0 {
        let base_rent = if st.seats[seat].apt_tier == 1 { 340 } else { 165 };
        let rent = scaled_price(base_rent, st.economy_index);
        if st.seats[seat].cash >= rent && st.seats[seat].rent_debt == 0 {
            // Auto-pay smoothly if liquid cash covers monthly rent, else add to rent_debt!
            st.seats[seat].cash -= rent;
            evt = WKND_RENT_BILLED;
            delta = -(rent as i16);
        } else {
            st.seats[seat].rent_debt = st.seats[seat].rent_debt.saturating_add(rent);
            st.seats[seat].dependability = st.seats[seat].dependability.saturating_sub(2);
            evt = WKND_RENT_BILLED;
            delta = -(rent as i16);
        }
    }

    // 6) "Oh, What a Weekend!" Random Event (if nothing urgent overrode it)
    let roll = (st.next_rand_u64() % 100) as u8;
    if st.seats[seat].cash > 260 && roll < 22 {
        if st.seats[seat].apt_tier == 0 {
            // Sneaky Sam tiptoes into Shady Acres and swipes 35% of unbanked pocket cash!
            let swiped = ((st.seats[seat].cash * 35) / 100).clamp(35, 350);
            st.seats[seat].cash -= swiped;
            st.seats[seat].happiness = st.seats[seat].happiness.saturating_sub(2);
            evt = WKND_SNEAKY_SAM;
            delta = -(swiped as i16);
        } else {
            // LeSecurity Condo's friendly robo-doorman sends Sneaky Sam packing!
            st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
            evt = WKND_CONDO_FOILED_SAM;
            delta = 2;
        }
    } else if roll >= 22 && roll < 36 {
        let gift = 45u32 + ((roll as u32 % 4) * 15);
        st.seats[seat].cash = st.seats[seat].cash.saturating_add(gift);
        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(2);
        evt = WKND_AUNT_GIFT;
        delta = gift as i16;
    } else if roll >= 36 && roll < 50 {
        st.seats[seat].happiness = st.seats[seat].happiness.saturating_add(3);
        evt = WKND_BLOCK_PARTY;
        delta = 3;
    } else if roll >= 50 && roll < 60 {
        let rebate = 60u32;
        st.seats[seat].cash = st.seats[seat].cash.saturating_add(rebate);
        evt = WKND_TAX_REBATE;
        delta = rebate as i16;
    } else if roll >= 60 && roll < 67 && st.seats[seat].appliances_mask != 0 {
        // Playful minor gadget hiccup on one owned appliance (excluding Fridge so groceries stay safe)
        let candidates = st.seats[seat].appliances_mask & !1u8;
        if candidates != 0 {
            let mut b = 1u8;
            while b < (NUM_APPLIANCES as u8) {
                if (candidates & (1u8 << b)) != 0 {
                    st.seats[seat].appliances_broken_mask |= 1u8 << b;
                    evt = WKND_APPLIANCE_HICCUP;
                    delta = -(b as i16);
                    break;
                }
                b += 1;
            }
        }
    }

    // 7) Prepare seat for their next week back home at Apartments!
    st.seats[seat].last_weekend_event = evt;
    st.seats[seat].last_weekend_delta = delta;
    st.seats[seat].location = BLD_APARTMENTS;
    st.seats[seat].raise_asked_this_week = 0;
    st.seats[seat].hours_left = st.seats[seat].weekly_max_hours();
    st.push_log(seat as u8, evt, delta, st.seats[seat].happiness);
}

fn roll_town_macroeconomy(st: &mut GameState) {
    st.week_number = st.week_number.saturating_add(1);
    let r = st.next_rand_u64();

    // Gentle macroeconomic cycle between 78 and 128
    let shift = ((r % 9) as i16) - 4 + (st.economy_trend as i16 * 2);
    let next_econ = ((st.economy_index as i16) + shift).clamp(78, 128) as u16;
    st.economy_index = next_econ;
    if next_econ >= 122 {
        st.economy_trend = -1;
    } else if next_econ <= 84 {
        st.economy_trend = 1;
    } else if (r >> 8) % 5 == 0 {
        st.economy_trend = match (r >> 16) % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        };
    }

    // Update the 3 Town Securities:
    // 0: T-Bills (steady +1..+3), 1: Burger Bytes (-5..+8), 2: QuantumChip (-14..+18)
    let t_delta = (((r >> 20) % 3) as i32) + 1;
    st.stock_prices[0] = ((st.stock_prices[0] as i32 + t_delta).clamp(85, 400)) as u16;

    let b_delta = (((r >> 28) % 13) as i32) - 5 + (st.economy_trend as i32);
    st.stock_prices[1] = ((st.stock_prices[1] as i32 + b_delta).clamp(60, 650)) as u16;

    let q_delta = (((r >> 36) % 31) as i32) - 13 + ((st.economy_trend as i32) * 3);
    st.stock_prices[2] = ((st.stock_prices[2] as i32 + q_delta).clamp(70, 950)) as u16;
}

/// Deterministic, competitive-yet-fair AI planner for Rival **"Jones"** (`1`),
/// **Penny Hodl** (`2`), and **Sunny Wheeler** (`3`).
fn run_bot_week(st: &mut GameState, seat: usize) {
    let persona = st.seats[seat].is_bot;
    let pcts = st.goal_pcts(seat);

    // 1) Pay rent if owed and affordable
    if st.seats[seat].rent_debt > 0 && st.seats[seat].cash >= 80 {
        execute_plan_step(st, seat, OP_MOVE, BLD_RENT_CIVIC);
        execute_plan_step(st, seat, OP_PAY_RENT, 0);
    }

    // 2) Ensure clothes aren't tattered & upgrade wardrobe for higher careers
    let target_dress = if st.seats[seat].degrees_mask.count_ones() >= 2 && st.seats[seat].cash >= 320
    {
        3u8
    } else if st.seats[seat].degrees_mask != 0 && st.seats[seat].cash >= 180 {
        2u8
    } else {
        1u8
    };
    if st.seats[seat].clothes_weeks <= 1 || st.seats[seat].effective_clothes_tier() < target_dress {
        if target_dress == 1 && persona == 2 {
            execute_plan_step(st, seat, OP_MOVE, BLD_ZMART);
            execute_plan_step(st, seat, OP_BUY_CLOTHES, 1);
        } else {
            execute_plan_step(st, seat, OP_MOVE, BLD_CLOTHING);
            execute_plan_step(st, seat, OP_BUY_CLOTHES, target_dress);
        }
    }

    // 3) Ensure food for the week!
    if st.seats[seat].food_weeks == 0 {
        if st.seats[seat].has_working_appliance(APP_FRIDGE) && st.seats[seat].cash >= 60 {
            execute_plan_step(st, seat, OP_MOVE, BLD_MARKET);
            if st.seats[seat].has_working_appliance(APP_FREEZER) && st.seats[seat].cash >= 100 {
                execute_plan_step(st, seat, OP_BUY_FOOD, 4);
            } else {
                execute_plan_step(st, seat, OP_BUY_FOOD, 3);
            }
        } else {
            execute_plan_step(st, seat, OP_MOVE, BLD_BURGERS);
            if st.seats[seat].cash >= 50 && pcts[1] < 100 {
                execute_plan_step(st, seat, OP_BUY_FOOD, 1);
            } else {
                execute_plan_step(st, seat, OP_BUY_FOOD, 0);
            }
        }
    }

    // 4) Repair broken appliance if affordable
    if st.seats[seat].appliances_broken_mask != 0 && st.seats[seat].cash >= 100 {
        let mut a = 0u8;
        while (a as usize) < NUM_APPLIANCES {
            if (st.seats[seat].appliances_broken_mask & (1u8 << a)) != 0 {
                execute_plan_step(st, seat, OP_MOVE, BLD_PAWN_REPAIR);
                execute_plan_step(st, seat, OP_REPAIR_PAWN, a);
                break;
            }
            a += 1;
        }
    }

    // 5) Check if a strictly better job is available at Employment Office!
    let mut best_job = st.seats[seat].job_id;
    let cur_rank = job_spec(best_job).map(|j| j.rank).unwrap_or(0);
    let mut jid = NUM_JOBS as u8;
    while jid >= 1 {
        if st.seats[seat].qualifies_for_job(jid) {
            if let Some(js) = job_spec(jid) {
                if js.rank > cur_rank {
                    best_job = jid;
                    break;
                }
            }
        }
        jid -= 1;
    }
    if best_job != st.seats[seat].job_id {
        execute_plan_step(st, seat, OP_MOVE, BLD_EMPLOYMENT);
        execute_plan_step(st, seat, OP_APPLY_JOB, best_job);
    }

    // 6) Smart Tech & Lifestyle Upgrades when flush with cash
    if st.seats[seat].cash >= 720 && !st.seats[seat].has_working_appliance(APP_COMPUTER) && pcts[2] < 100 {
        execute_plan_step(st, seat, OP_MOVE, BLD_TECH);
        execute_plan_step(st, seat, OP_BUY_APPLIANCE, APP_COMPUTER);
    } else if st.seats[seat].cash >= 560 && !st.seats[seat].has_working_appliance(APP_SCOOTER) && persona != 2 {
        execute_plan_step(st, seat, OP_MOVE, BLD_TECH);
        execute_plan_step(st, seat, OP_BUY_APPLIANCE, APP_SCOOTER);
    } else if st.seats[seat].cash >= 450 && !st.seats[seat].has_working_appliance(APP_FRIDGE) {
        execute_plan_step(st, seat, OP_MOVE, BLD_ZMART);
        execute_plan_step(st, seat, OP_BUY_APPLIANCE, APP_FRIDGE);
    } else if st.seats[seat].cash >= 380 && !st.seats[seat].has_working_appliance(APP_MICROWAVE) {
        execute_plan_step(st, seat, OP_MOVE, BLD_ZMART);
        execute_plan_step(st, seat, OP_BUY_APPLIANCE, APP_MICROWAVE);
    } else if st.seats[seat].apt_tier == 0 && st.seats[seat].cash >= 900 && st.seats[seat].rent_debt == 0 {
        execute_plan_step(st, seat, OP_MOVE, BLD_RENT_CIVIC);
        execute_plan_step(st, seat, OP_SWITCH_APT, 1);
    }

    // 7) Study at Haltproof University if Education goal < 100% (1-2 lectures per week)
    if pcts[2] < 100 && st.seats[seat].cash >= 140 && st.seats[seat].hours_left >= 18 {
        let deg_order: [u8; 4] = if persona == 2 {
            [DEG_JR_COLLEGE, DEG_BUSINESS, DEG_ELECTRONICS, DEG_PROTOCOL_ARCH]
        } else {
            [DEG_JR_COLLEGE, DEG_ELECTRONICS, DEG_BUSINESS, DEG_PROTOCOL_ARCH]
        };
        let mut target_deg = 0xFFu8;
        let mut di = 0;
        while di < 4 {
            let d = deg_order[di];
            if st.seats[seat].qualifies_for_degree(d) {
                target_deg = d;
                break;
            }
            di += 1;
        }
        if target_deg < 4 {
            execute_plan_step(st, seat, OP_MOVE, BLD_UNIVERSITY);
            execute_plan_step(st, seat, OP_STUDY, target_deg);
            if st.seats[seat].cash >= 160 && st.seats[seat].hours_left >= 24 && pcts[0] >= 50 {
                execute_plan_step(st, seat, OP_STUDY, target_deg);
            }
        }
    }

    // 8) Work shifts at workplace to build cash, experience & dependability!
    if let Some(js) = job_spec(st.seats[seat].job_id) {
        let reserve_for_relax = if pcts[1] < 85 && pcts[0] >= 80 { 10u8 } else { 4u8 };
        if st.seats[seat].hours_left > reserve_for_relax + 6 {
            execute_plan_step(st, seat, OP_MOVE, js.workplace);
            let avail_shifts = (st.seats[seat].hours_left.saturating_sub(reserve_for_relax)) / 6;
            if avail_shifts > 0 {
                execute_plan_step(st, seat, OP_WORK, avail_shifts);
            }
        }
    }

    // 9) Bank excess cash (safe from Sneaky Sam!) or buy a share
    if st.seats[seat].cash >= 320 && st.seats[seat].hours_left >= 5 {
        execute_plan_step(st, seat, OP_MOVE, BLD_BANK);
        if persona == 1 && st.seats[seat].cash >= 450 && st.seats[seat].hours_left >= 2 {
            execute_plan_step(st, seat, OP_BUY_STOCK, (1u8 << 4) | 1);
        } else if persona == 2 && st.seats[seat].cash >= 400 && st.seats[seat].hours_left >= 2 {
            execute_plan_step(st, seat, OP_BUY_STOCK, (0u8 << 4) | 2);
        }
        if st.seats[seat].cash > 180 && st.seats[seat].hours_left >= 1 {
            let units = ((st.seats[seat].cash - 150) / 50).min(40) as u8;
            if units > 0 {
                execute_plan_step(st, seat, OP_BANK_DEPOSIT, units);
            }
        }
    }

    // 10) Spend remaining hours relaxing for Happiness if needed!
    if pcts[1] < 100 && st.seats[seat].hours_left >= 8 {
        if st.seats[seat].location == BLD_RENT_CIVIC {
            execute_plan_step(st, seat, OP_RELAX, 1);
        } else {
            execute_plan_step(st, seat, OP_MOVE, BLD_APARTMENTS);
            while st.seats[seat].hours_left >= 6 {
                execute_plan_step(st, seat, OP_RELAX, 0);
            }
        }
    }
}

fn finish_turn_and_advance(gid: &[u8; 32], st: &mut GameState) {
    let sc = (st.seat_count as usize).clamp(1, MAX_SEATS);
    let mut safety = 0usize;

    loop {
        let cur = st.turn_seat as usize;
        resolve_seat_weekend(st, cur);

        if st.has_seat_won(cur) {
            st.phase = PHASE_FINISHED;
            st.winner_seat = cur as u8;
            st.seats[cur].wins = st.seats[cur].wins.saturating_add(1);
            st.push_log(cur as u8, WKND_VICTORY_BELLS, 100, st.week_number);
            let w_eoa = st.seats[cur].eoa;
            emit_victory(gid, &w_eoa, cur as u8, st.week_number);
            break;
        }

        let next = (cur + 1) % sc;
        if next == 0 {
            roll_town_macroeconomy(st);
        }
        st.turn_seat = next as u8;

        // If the next seat is a human player, stop and wait for their turn!
        if st.seats[next].is_bot == 0 || safety >= MAX_SEATS {
            break;
        }
        run_bot_week(st, next);
        safety += 1;
    }
}

fn preset_goals(preset: u64) -> (u32, u16, u16, u16) {
    match preset {
        // 0: Quick Afternoon Stroll (~12-18 weeks — great for kids & quick sessions!)
        0 => (2_500, 40, 20, 35),
        // 2: Long-Haul Tycoon (~45-70 weeks — epic slow-burn career!)
        2 => (10_000, 100, 40, 90),
        // 1 (default): Classic Fast-Lane (~25-35 weeks)
        _ => (5_000, 65, 30, 60),
    }
}

fn bot_synthetic_eoa(persona: u8, slot: usize) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr[0] = 0xB0;
    addr[1] = 0x70;
    addr[18] = persona;
    addr[19] = slot as u8;
    addr
}

// ---------------------------------------------------------------------------
// ABI Entrypoints (`hps_entry!`)
// ---------------------------------------------------------------------------

hps_entry! {
    "quickStartSolo(bytes32,address,uint64,uint64)" => handle_quick_start_solo,
    "createGame(bytes32,address,uint64,uint64,uint64,uint64)" => handle_create_game,
    "joinGame(bytes32,address)" => handle_join_game,
    "startGame(bytes32,uint64)" => handle_start_game,
    "submitWeekPlan(bytes32,bytes)" => handle_submit_week_plan,
    "rematchGame(bytes32,uint64)" => handle_rematch_game,
    "getGameState(bytes32,address)" => handle_get_game_state,
    "listGames()" => handle_list_games,
}

fn handle_quick_start_solo(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).ok_or(-11)?;
    let bot_count = args.u64(2).unwrap_or(1).clamp(1, 3) as usize;
    let preset = args.u64(3).unwrap_or(1);

    if load_game(&gid).is_some() {
        return Err(-20); // gameId already exists
    }

    let caller = context::msg_sender();
    let (w_goal, h_goal, e_goal, c_goal) = preset_goals(preset);
    let mut st = GameState::new_lobby(w_goal, h_goal, e_goal, c_goal, derive_seed(&gid, &caller));

    st.seats[0].reset_for_new_game();
    st.seats[0].eoa = caller;
    st.seats[0].identity = identity;
    st.seats[0].is_bot = 0;

    let mut b = 0usize;
    while b < bot_count && (1 + b) < MAX_SEATS {
        let persona = (b + 1) as u8; // 1 = Jones, 2 = Penny Hodl, 3 = Sunny Wheeler
        st.seats[1 + b].reset_for_new_game();
        st.seats[1 + b].eoa = bot_synthetic_eoa(persona, 1 + b);
        st.seats[1 + b].is_bot = persona;
        b += 1;
    }

    st.seat_count = (1 + bot_count) as u8;
    st.phase = PHASE_ACTIVE;
    st.turn_seat = 0;
    st.push_log(0, WKND_COZY_QUIET, 0, st.seats[0].happiness);

    save_game(&gid, &st);
    register_game_in_directory(&gid);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(st.seat_count as u64);
    Ok(32)
}

fn handle_create_game(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).ok_or(-11)?;
    let w_goal = args.u64(2).unwrap_or(5_000).clamp(1_000, 50_000) as u32;
    let h_goal = args.u64(3).unwrap_or(65).clamp(25, 200) as u16;
    let e_goal = args.u64(4).unwrap_or(30).clamp(10, 40) as u16;
    let c_goal = args.u64(5).unwrap_or(60).clamp(20, 100) as u16;

    if load_game(&gid).is_some() {
        return Err(-20);
    }

    let caller = context::msg_sender();
    let mut st = GameState::new_lobby(w_goal, h_goal, e_goal, c_goal, derive_seed(&gid, &caller));
    st.seats[0].reset_for_new_game();
    st.seats[0].eoa = caller;
    st.seats[0].identity = identity;
    st.seat_count = 1;

    save_game(&gid, &st);
    register_game_in_directory(&gid);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_join_game(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).ok_or(-11)?;
    let mut st = load_game(&gid).ok_or(-21)?;
    if st.phase != PHASE_LOBBY {
        return Err(-22);
    }
    let caller = context::msg_sender();
    if st.find_seat_by_eoa(&caller).is_some() {
        return Err(-23);
    }
    let sc = st.seat_count as usize;
    if sc >= MAX_SEATS {
        return Err(-24);
    }
    st.seats[sc].reset_for_new_game();
    st.seats[sc].eoa = caller;
    st.seats[sc].identity = identity;
    st.seats[sc].is_bot = 0;
    st.seat_count = (sc + 1) as u8;

    save_game(&gid, &st);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(st.seat_count as u64);
    Ok(32)
}

fn handle_start_game(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let fill_to = args.u64(1).unwrap_or(2).clamp(2, MAX_SEATS as u64) as usize;
    let mut st = load_game(&gid).ok_or(-21)?;
    if st.phase != PHASE_LOBBY {
        return Err(-22);
    }
    let caller = context::msg_sender();
    if st.seats[0].eoa != caller {
        return Err(-25); // only host starts lobby
    }

    let mut sc = st.seat_count as usize;
    let mut persona = 1u8;
    while sc < fill_to && sc < MAX_SEATS {
        st.seats[sc].reset_for_new_game();
        st.seats[sc].eoa = bot_synthetic_eoa(persona, sc);
        st.seats[sc].is_bot = persona;
        persona = if persona < 3 { persona + 1 } else { 1 };
        sc += 1;
    }
    if sc < 2 {
        return Err(-26);
    }
    st.seat_count = sc as u8;
    st.phase = PHASE_ACTIVE;
    st.turn_seat = 0;
    st.push_log(0, WKND_COZY_QUIET, 0, st.seats[0].happiness);

    save_game(&gid, &st);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(st.seat_count as u64);
    Ok(32)
}

fn handle_submit_week_plan(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let actions = args.dynamic_bytes(1).ok_or(-12)?;
    if actions.len() > MAX_PLAN_STEPS * 2 || actions.len() % 2 != 0 {
        return Err(-13);
    }

    let mut st = load_game(&gid).ok_or(-21)?;
    if st.phase != PHASE_ACTIVE {
        return Err(-30);
    }

    let caller = context::msg_sender();
    let seat = st.turn_seat as usize;
    if seat >= (st.seat_count as usize) || st.seats[seat].is_bot != 0 || st.seats[seat].eoa != caller
    {
        return Err(-31); // not caller's turn!
    }

    let steps = (actions.len() / 2).min(MAX_PLAN_STEPS);
    let mut i = 0;
    while i < steps {
        let op = actions[i * 2];
        let arg = actions[i * 2 + 1];
        execute_plan_step(&mut st, seat, op, arg);
        i += 1;
    }

    finish_turn_and_advance(&gid, &mut st);
    save_game(&gid, &st);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(st.week_number as u64);
    Ok(32)
}

fn handle_rematch_game(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let preset = args.u64(1).unwrap_or(1);
    let mut st = load_game(&gid).ok_or(-21)?;
    if st.phase != PHASE_FINISHED {
        return Err(-32);
    }
    let caller = context::msg_sender();
    if st.find_seat_by_eoa(&caller).is_none() {
        return Err(-33);
    }

    let (w_goal, h_goal, e_goal, c_goal) = preset_goals(preset);
    st.wealth_goal = w_goal;
    st.hap_goal = h_goal;
    st.edu_goal = e_goal;
    st.career_goal = c_goal;
    st.phase = PHASE_ACTIVE;
    st.turn_seat = 0;
    st.winner_seat = 0xFF;
    st.week_number = 1;
    st.economy_index = 100;
    st.economy_trend = 1;
    st.stock_prices = [100, 150, 220];
    st.log_count = 0;

    let sc = (st.seat_count as usize).min(MAX_SEATS);
    let mut i = 0;
    while i < sc {
        st.seats[i].reset_for_new_game();
        i += 1;
    }
    st.push_log(0, WKND_COZY_QUIET, 0, st.seats[0].happiness);

    save_game(&gid, &st);
    emit_game_updated(&gid, &st);
    ret::write_u64_word(1);
    Ok(32)
}

/// Binary Snapshot Layout (`getGameState(bytes32 gameId, address viewer)`):
/// - `[0..36]` Header (`36` bytes):
///   - `0`: schema (`1`)
///   - `1`: `phase` (`1`=Lobby, `2`=Active, `3`=Finished)
///   - `2`: `seat_count`
///   - `3`: `turn_seat`
///   - `4`: `winner_seat` (`0..3` or `0xFF`)
///   - `5`: `viewer_seat` (`0..3` or `0xFF`)
///   - `6`: `economy_trend` (`i8` as `u8`)
///   - `7`: `log_count`
///   - `8..10`: `week_number` (`u16` BE)
///   - `10..12`: `economy_index` (`u16` BE)
///   - `12..16`: `wealth_goal` (`u32` BE)
///   - `16..18`: `hap_goal` (`u16` BE)
///   - `18..20`: `edu_goal` (`u16` BE)
///   - `20..22`: `career_goal` (`u16` BE)
///   - `22..24`: `stock_prices[0]` (`u16` BE)
///   - `24..26`: `stock_prices[1]` (`u16` BE)
///   - `26..28`: `stock_prices[2]` (`u16` BE)
///   - `28..36`: `current_block` (`u64` BE)
/// - `[36..36 + seat_count * 92]` Per-Seat Records (`92` bytes each):
///   - `0..20`: `eoa`
///   - `20..40`: `identity`
///   - `40`: `is_bot` (`0`=human, `1`=Jones, `2`=Penny, `3`=Sunny)
///   - `41`: `location` (`0..11`)
///   - `42`: `hours_left`
///   - `43`: `max_hours`
///   - `44..48`: `cash` (`u32` BE)
///   - `48..52`: `savings` (`u32` BE)
///   - `52..56`: `rent_debt` (`u32` BE)
///   - `56..60`: `net_wealth` (`u32` BE)
///   - `60..62`: `happiness` (`u16` BE)
///   - `62`: `dependability`
///   - `63`: `experience`
///   - `64`: `job_id`
///   - `65..67`: `hourly_wage` (`u16` BE)
///   - `67`: `apt_tier`
///   - `68`: `clothes_tier`
///   - `69`: `clothes_weeks`
///   - `70`: `food_weeks`
///   - `71`: `degrees_mask`
///   - `72..76`: `study_credits[4]`
///   - `76`: `appliances_mask`
///   - `77`: `appliances_broken_mask`
///   - `78..80`: `stocks[0]` (`u16` BE)
///   - `80..82`: `stocks[1]` (`u16` BE)
///   - `82..84`: `stocks[2]` (`u16` BE)
///   - `84..88`: `goal_pcts[4]` (`wealth%`, `hap%`, `edu%`, `career%`)
///   - `88`: `last_weekend_event`
///   - `89..91`: `last_weekend_delta` (`i16` BE)
///   - `91`: `wins`
/// - Next: `logs[log_count]` (`8` bytes each: `week u16`, `seat u8`, `event_id u8`, `delta i16`, `aux u16`)
fn handle_get_game_state(args: &CalldataReader) -> Result<i32, i32> {
    let gid = args.bytes32(0).ok_or(-10)?;
    let viewer = args.address(1).unwrap_or([0u8; 20]);
    let Some(st) = load_game(&gid) else {
        ret::write(&[]);
        return Ok(0);
    };

    let sc = (st.seat_count as usize).min(MAX_SEATS);
    let viewer_seat = st.find_seat_by_eoa(&viewer).map(|x| x as u8).unwrap_or(0xFF);
    let mut out = [0u8; 600];

    out[0] = 1;
    out[1] = st.phase;
    out[2] = sc as u8;
    out[3] = st.turn_seat;
    out[4] = st.winner_seat;
    out[5] = viewer_seat;
    out[6] = st.economy_trend as u8;
    out[7] = st.log_count;
    out[8..10].copy_from_slice(&st.week_number.to_be_bytes());
    out[10..12].copy_from_slice(&st.economy_index.to_be_bytes());
    out[12..16].copy_from_slice(&st.wealth_goal.to_be_bytes());
    out[16..18].copy_from_slice(&st.hap_goal.to_be_bytes());
    out[18..20].copy_from_slice(&st.edu_goal.to_be_bytes());
    out[20..22].copy_from_slice(&st.career_goal.to_be_bytes());
    out[22..24].copy_from_slice(&st.stock_prices[0].to_be_bytes());
    out[24..26].copy_from_slice(&st.stock_prices[1].to_be_bytes());
    out[26..28].copy_from_slice(&st.stock_prices[2].to_be_bytes());
    out[28..36].copy_from_slice(&context::block_number().to_be_bytes());

    let mut pos = 36;
    let mut i = 0;
    while i < sc {
        let s = &st.seats[i];
        let pcts = st.goal_pcts(i);
        let nw = s.net_liquid_wealth(&st.stock_prices);

        out[pos..pos + 20].copy_from_slice(&s.eoa);
        out[pos + 20..pos + 40].copy_from_slice(&s.identity);
        out[pos + 40] = s.is_bot;
        out[pos + 41] = s.location;
        out[pos + 42] = s.hours_left;
        out[pos + 43] = s.weekly_max_hours();
        out[pos + 44..pos + 48].copy_from_slice(&s.cash.to_be_bytes());
        out[pos + 48..pos + 52].copy_from_slice(&s.savings.to_be_bytes());
        out[pos + 52..pos + 56].copy_from_slice(&s.rent_debt.to_be_bytes());
        out[pos + 56..pos + 60].copy_from_slice(&nw.to_be_bytes());
        out[pos + 60..pos + 62].copy_from_slice(&s.happiness.to_be_bytes());
        out[pos + 62] = s.dependability;
        out[pos + 63] = s.experience;
        out[pos + 64] = s.job_id;
        out[pos + 65..pos + 67].copy_from_slice(&s.hourly_wage.to_be_bytes());
        out[pos + 67] = s.apt_tier;
        out[pos + 68] = s.clothes_tier;
        out[pos + 69] = s.clothes_weeks;
        out[pos + 70] = s.food_weeks;
        out[pos + 71] = s.degrees_mask;
        out[pos + 72..pos + 76].copy_from_slice(&s.study_credits);
        out[pos + 76] = s.appliances_mask;
        out[pos + 77] = s.appliances_broken_mask;
        out[pos + 78..pos + 80].copy_from_slice(&s.stocks[0].to_be_bytes());
        out[pos + 80..pos + 82].copy_from_slice(&s.stocks[1].to_be_bytes());
        out[pos + 82..pos + 84].copy_from_slice(&s.stocks[2].to_be_bytes());
        out[pos + 84..pos + 88].copy_from_slice(&pcts);
        out[pos + 88] = s.last_weekend_event;
        out[pos + 89..pos + 91].copy_from_slice(&s.last_weekend_delta.to_be_bytes());
        out[pos + 91] = (s.wins.min(255)) as u8;
        pos += 92;
        i += 1;
    }

    let ln = (st.log_count as usize).min(LOG_WINDOW);
    let mut li = 0;
    while li < ln {
        let lg = &st.logs[li];
        out[pos..pos + 2].copy_from_slice(&lg.week.to_be_bytes());
        out[pos + 2] = lg.seat;
        out[pos + 3] = lg.event_id;
        out[pos + 4..pos + 6].copy_from_slice(&lg.delta.to_be_bytes());
        out[pos + 6..pos + 8].copy_from_slice(&lg.aux.to_be_bytes());
        pos += 8;
        li += 1;
    }

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

fn handle_list_games(_args: &CalldataReader) -> Result<i32, i32> {
    let mut buf = [0u8; 1 + MAX_LISTED_GAMES * 32];
    let n = storage::get_into(KEY_GAME_LIST, &mut buf).unwrap_or(0);
    if n < 1 {
        ret::write(&[0u8]);
        return Ok(1);
    }
    let cnt = (buf[0] as usize).min(MAX_LISTED_GAMES);
    let mut out = [0u8; 1 + MAX_LISTED_GAMES * 40];
    out[0] = cnt as u8;
    let mut pos = 1;
    let mut i = 0;
    while i < cnt {
        let off = 1 + i * 32;
        let mut gid = [0u8; 32];
        gid.copy_from_slice(&buf[off..off + 32]);
        out[pos..pos + 32].copy_from_slice(&gid);
        if let Some(st) = load_game(&gid) {
            out[pos + 32] = st.phase;
            out[pos + 33] = st.seat_count;
            out[pos + 34] = st.human_count() as u8;
            out[pos + 35] = st.turn_seat;
            out[pos + 36..pos + 38].copy_from_slice(&st.week_number.to_be_bytes());
            out[pos + 38..pos + 40].copy_from_slice(&((st.wealth_goal / 100) as u16).to_be_bytes());
        }
        pos += 40;
        i += 1;
    }
    ret::write(&out[..pos]);
    Ok(pos as i32)
}

// ---------------------------------------------------------------------------
// Native Unit Tests (`cargo test -p jones-blockchain`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const JONES_ADDR: [u8; 20] = [0x44; 20];
    const ALICE: [u8; 20] = [0xA1; 20];
    const BOB: [u8; 20] = [0xB2; 20];

    #[test]
    fn solo_vs_jones_submits_atomic_week_and_advances_ai_rival() {
        mock::reset();
        mock::register_hps(JONES_ADDR, dispatch_calldata);
        mock::set_block_number(100);

        let gid = [0x11; 32];
        let cd_start = CallEncoder::<256>::new(selector(
            "quickStartSolo(bytes32,address,uint64,uint64)",
        ))
        .push_bytes32(&gid)
        .push_address(&[0xAA; 20])
        .push_u64(1) // Alice vs. Rival Jones
        .push_u64(0) // Quick Afternoon Stroll preset
        .as_slice()
        .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_start).unwrap();

        // Alice plans Week 1:
        // 1) Move to Employment Office (6 -> 6 steps = 12h), apply for Stock Clerk (job 2, 4h)
        // 2) Move to Z-Mart (2 -> 4 steps = 8h), work 4 shifts (24h, +$216!), buy Casual outfit ($35, 2h)
        // 3) Move to Burger Bytes (1 -> 1 step = 2h), buy Burger Meal ($15, 2h)
        let plan: [u8; 14] = [
            OP_MOVE,
            BLD_EMPLOYMENT,
            OP_APPLY_JOB,
            2,
            OP_MOVE,
            BLD_ZMART,
            OP_WORK,
            4,
            OP_BUY_CLOTHES,
            1,
            OP_MOVE,
            BLD_BURGERS,
            OP_BUY_FOOD,
            0,
        ];
        let cd_week =
            CallEncoder::<256>::new(selector("submitWeekPlan(bytes32,bytes)"))
                .push_bytes32(&gid)
                .push_u64(64)
                .push_dynamic_bytes_tail(&plan)
                .as_slice()
                .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_week).unwrap();

        let cd_get = CallEncoder::<256>::new(selector("getGameState(bytes32,address)"))
            .push_bytes32(&gid)
            .push_address(&ALICE)
            .as_slice()
            .to_vec();
        let snap = mock::transact_as(ALICE, JONES_ADDR, &cd_get).unwrap();

        assert_eq!(snap[1], PHASE_ACTIVE);
        assert_eq!(snap[2], 2); // 2 seats (Alice + Jones)
        assert_eq!(snap[3], 0); // Back to Alice's turn after Jones played Week 1!
        assert_eq!(u16::from_be_bytes([snap[8], snap[9]]), 2); // Week 2!

        // Check Alice's seat record (offset 36): job_id == 2 (Stock Clerk), back at Apartments (0)
        let alice_off = 36;
        assert_eq!(snap[alice_off + 41], BLD_APARTMENTS);
        assert_eq!(snap[alice_off + 64], 2); // Stock Clerk
        assert!(snap[alice_off + 63] >= 8); // +8 experience from 4 shifts

        // Check Rival Jones's seat record (offset 36 + 92): Jones also took action in Week 1!
        let jones_off = 36 + 92;
        assert_eq!(snap[jones_off + 40], 1); // is_bot == 1 ("Jones")
        assert!(snap[jones_off + 64] >= 1 || snap[jones_off + 72] >= 1);
    }

    #[test]
    fn home_computer_doubles_study_and_four_pillars_trigger_victory() {
        mock::reset();
        mock::register_hps(JONES_ADDR, dispatch_calldata);
        mock::set_self_address(JONES_ADDR);
        mock::set_block_number(250);

        let gid = [0x33; 32];
        let mut st = GameState::new_lobby(2_500, 40, 20, 35, [0x77; 32]);
        st.seats[0].reset_for_new_game();
        st.seats[0].eoa = ALICE;
        st.seats[0].cash = 3_200;
        st.seats[0].happiness = 38;
        st.seats[0].degrees_mask = 0b0001; // Junior College completed (10 credits)
        st.seats[0].study_credits[1] = 8; // 8/10 credits in Electronics
        st.seats[0].appliances_mask = (1u8 << APP_COMPUTER) | (1u8 << APP_SCOOTER);
        st.seats[0].job_id = 5; // Gadget Bench Tech (rank 4 -> 28 pts + dep/exp >= 35)
        st.seats[0].hourly_wage = 16;
        st.seats[0].dependability = 50;
        st.seats[0].experience = 30;
        st.seats[0].apt_tier = 1; // LeSecurity Condo

        st.seats[1].reset_for_new_game();
        st.seats[1].eoa = BOB;
        st.seat_count = 2;
        st.phase = PHASE_ACTIVE;
        save_game(&gid, &st);

        // Alice scooters to University (5 steps * 1h = 5h) and studies Electronics once (6h -> +2 credits with Home Computer -> graduates!)
        let plan: [u8; 4] = [OP_MOVE, BLD_UNIVERSITY, OP_STUDY, DEG_ELECTRONICS];
        let cd_week =
            CallEncoder::<256>::new(selector("submitWeekPlan(bytes32,bytes)"))
                .push_bytes32(&gid)
                .push_u64(64)
                .push_dynamic_bytes_tail(&plan)
                .as_slice()
                .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_week).unwrap();

        mock::set_self_address(JONES_ADDR);
        let after = load_game(&gid).unwrap();
        assert_eq!(after.phase, PHASE_FINISHED);
        assert_eq!(after.winner_seat, 0);
        assert_eq!(after.seats[0].wins, 1);
    }

    #[test]
    fn pvp_lobby_banking_stocks_and_rematch_work_end_to_end() {
        mock::reset();
        mock::register_hps(JONES_ADDR, dispatch_calldata);
        mock::set_block_number(400);

        let gid = [0x55; 32];
        // Alice creates a 2-player family PvP board
        let cd_create = CallEncoder::<256>::new(selector(
            "createGame(bytes32,address,uint64,uint64,uint64,uint64)",
        ))
        .push_bytes32(&gid)
        .push_address(&[0xAA; 20])
        .push_u64(3_000)
        .push_u64(45)
        .push_u64(20)
        .push_u64(35)
        .as_slice()
        .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_create).unwrap();

        // Bob joins Seat 1
        let cd_join = CallEncoder::<256>::new(selector("joinGame(bytes32,address)"))
            .push_bytes32(&gid)
            .push_address(&[0xBB; 20])
            .as_slice()
            .to_vec();
        mock::transact_as(BOB, JONES_ADDR, &cd_join).unwrap();

        // Alice starts game (2 human seats, 0 bots added)
        let cd_start = CallEncoder::<128>::new(selector("startGame(bytes32,uint64)"))
            .push_bytes32(&gid)
            .push_u64(2)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_start).unwrap();

        // Alice goes to Bank (8 -> 4 steps ccw = 8h), buys 1 share of T-Bills ($100) and deposits $100 into Savings
        let alice_plan: [u8; 6] = [
            OP_MOVE,
            BLD_BANK,
            OP_BUY_STOCK,
            0x01, // stock 0 (T-Bills), qty 1
            OP_BANK_DEPOSIT,
            2, // 2 * $50 = $100
        ];
        let cd_alice = CallEncoder::<256>::new(selector("submitWeekPlan(bytes32,bytes)"))
            .push_bytes32(&gid)
            .push_u64(64)
            .push_dynamic_bytes_tail(&alice_plan)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, JONES_ADDR, &cd_alice).unwrap();

        mock::set_self_address(JONES_ADDR);
        let mid = load_game(&gid).unwrap();
        assert_eq!(mid.turn_seat, 1); // Now Bob's turn!
        assert_eq!(mid.seats[0].stocks[0], 1);
        assert_eq!(mid.seats[0].savings, 102); // $100 + 2% weekend compound interest!
    }
}
