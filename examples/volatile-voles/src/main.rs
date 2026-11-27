//! # Volatile Voles: Chaotic Burrow Sabotage (`volatile-voles` — HPS #22)
//!
//! Deterministic, 100% bounded Haltproof Subroutine implementing tactical creature-collection
//! & out-of-turn counter-stack sabotage for `2..=5` players (Human PvP, Co-Op, or Solo vs.
//! On-Chain Tactical AI Bots):
//!
//! 1. **Zones & Deck (`25` Unique Card Archetypes, `68`-Card Main Deck + `8`-Card Baby Nest)**:
//!    - **Baby Voles (`0..=4`)**: Live in **The Nest**. Every seat begins with `1` Baby Vole in
//!      their Burrow + `5` cards in Hand. Baby Voles destroyed, sacrificed, or bounced always
//!      return to **The Nest** rather than the Scrap Heap or a player's Hand.
//!    - **Basic Voles (`5..=7`)**: Reliable Burrow builders (`12` cards).
//!    - **Volatile Mutant Voles (`8..=14`)**: Enter-the-Burrow & Dawn-of-Turn abilities (`21` cards):
//!      Chainsaw Berserker, Klepto-Magnet, Necro-Spore, Siren Hypno-Vole, Hazmat Bunker (Spell/Destroy
//!      Immune), Broodmother Mech-Vole, and Alpha Warlord.
//!    - **Chaos Spells (`15..=18`)**: One-shot explosive sabotage (`12` cards): Two-For-One Tunnel
//!      Collapse, Grand Burrow Heist (Hand Swap), Vole-nado Vortex, and Doomsday EMP Reset.
//!    - **Perks (`19..=20`)**: Persistent positive Burrow attachments (`6` cards): Overclocked
//!      Hamster Wheel (`2` plays per Action Phase) & Titanium Faraday Dome (`SQUEAK-NO!` & Perk shield).
//!    - **Hexes (`21..=22`)**: Persistent curses played into opponents' Burrows (`6` cards):
//!      Hallucinogenic Truffles ("Potato Delusion" — caps effective Victory Voles at `5`!) &
//!      Tin-Foil Muzzle (blocks `SQUEAK-NO!` Instants and Dawn bonus draws).
//!    - **Instants (`23..=24`)**: Out-of-turn counter-stack reactions (`11` cards): `SQUEAK-NO!`
//!      (counterable stack veto) & `APEX SQUEAK-NO!` (unstoppable veto piercing Faraday Dome).
//! 2. **4-Phase Turn Loop + `SQUEAK-NO!` Counter-Stack**:
//!    - Dawn of Turn -> Draw `1` -> Action Phase (Play Card(s) or Forage `+1` Card) -> `SQUEAK-NO!`
//!      Reaction Stack -> End-of-Turn `7`-Card Hand Limit -> Victory Check (`>= target_voles`, default `7`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::{keccak256, KeccakHasher};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Bounded Protocol Constants
// ---------------------------------------------------------------------------

pub const MAX_SEATS: usize = 5;
pub const MIN_SEATS: usize = 2;
pub const DEFAULT_TARGET_VOLES: u8 = 7;
pub const MIN_TARGET_VOLES: u8 = 5;
pub const MAX_TARGET_VOLES: u8 = 8;

pub const INITIAL_HAND_SIZE: usize = 5;
pub const HAND_LIMIT: usize = 7;
pub const MAX_HAND: usize = 16;
pub const MAX_BURROW_VOLES: usize = 12;
pub const MAX_BURROW_MODS: usize = 8;
pub const MAX_DECK: usize = 72;
pub const MAX_NEST: usize = 8;
pub const MAX_SCRAP: usize = 72;
pub const LOG_WINDOW: usize = 16;
pub const MAX_LISTED_TABLES: usize = 16;

pub const CARD_NONE: u8 = 0xFF;
pub const CARD_MASKED_BACK: u8 = 0xFE;

pub const PHASE_LOBBY: u8 = 1;
pub const PHASE_ACTION: u8 = 2;
pub const PHASE_REACTION: u8 = 3;
pub const PHASE_DISCARD: u8 = 4;
pub const PHASE_FINISHED: u8 = 5;

pub const REACTION_WINDOW_BLOCKS: u64 = 4;
pub const MAX_AUTO_BOT_STEPS: usize = 14;

// Card ID Ranges (0..=24)
pub const BABY_START: u8 = 0;
pub const BABY_END: u8 = 4;
pub const BASIC_START: u8 = 5;
pub const BASIC_END: u8 = 7;
pub const MUTANT_START: u8 = 8;
pub const MUTANT_END: u8 = 14;
pub const SPELL_START: u8 = 15;
pub const SPELL_END: u8 = 18;
pub const PERK_START: u8 = 19;
pub const PERK_END: u8 = 20;
pub const HEX_START: u8 = 21;
pub const HEX_END: u8 = 22;
pub const INSTANT_SQUEAK_NO: u8 = 23;
pub const INSTANT_APEX_SQUEAK: u8 = 24;

// Specific Mutant / Spell / Perk / Hex Card IDs
pub const CARD_CHAINSAW_VOLE: u8 = 8;
pub const CARD_KLEPTO_VOLE: u8 = 9;
pub const CARD_NECRO_VOLE: u8 = 10;
pub const CARD_SIREN_VOLE: u8 = 11;
pub const CARD_HAZMAT_VOLE: u8 = 12;
pub const CARD_BROODMOTHER_VOLE: u8 = 13;
pub const CARD_WARLORD_VOLE: u8 = 14;

pub const CARD_SPELL_COLLAPSE: u8 = 15;
pub const CARD_SPELL_HEIST: u8 = 16;
pub const CARD_SPELL_VOLENADO: u8 = 17;
pub const CARD_SPELL_EMP_RESET: u8 = 18;

pub const CARD_PERK_WHEEL: u8 = 19;
pub const CARD_PERK_DOME: u8 = 20;

pub const CARD_HEX_TRUFFLES: u8 = 21;
pub const CARD_HEX_MUZZLE: u8 = 22;

// Log Event Kinds (`log[i].kind`)
pub const LOG_MATCH_STARTED: u8 = 1;
pub const LOG_DAWN_BONUS: u8 = 2;
pub const LOG_FORAGED: u8 = 3;
pub const LOG_CARD_STAGED: u8 = 4;
pub const LOG_SQUEAK_NO: u8 = 5;
pub const LOG_CARD_FIZZLED: u8 = 6;
pub const LOG_CARD_RESOLVED: u8 = 7;
pub const LOG_DISCARDED: u8 = 8;
pub const LOG_VICTORY: u8 = 9;

//Canonical 8-Baby Nest & 68-Card Main Deck
const CANONICAL_NEST: [u8; MAX_NEST] = [0, 1, 2, 3, 4, 0, 1, 2];

const CANONICAL_DECK_LEN: usize = 68;
const CANONICAL_DECK: [u8; CANONICAL_DECK_LEN] = [
    // 12 Basic Voles (5..=7 x4)
    5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    // 21 Volatile Mutant Voles (8..=14 x3)
    8, 8, 8, 9, 9, 9, 10, 10, 10, 11, 11, 11, 12, 12, 12, 13, 13, 13, 14, 14, 14,
    // 12 Chaos Spells (15..=18 x3)
    15, 15, 15, 16, 16, 16, 17, 17, 17, 18, 18, 18,
    // 6 Perks (19..=20 x3)
    19, 19, 19, 20, 20, 20,
    // 6 Hexes (21..=22 x3)
    21, 21, 21, 22, 22, 22,
    // 11 Instants: 8x SQUEAK-NO! (23) + 3x APEX SQUEAK-NO! (24)
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24,
];

// Event Topics
const EV_TABLE_UPDATED: [u8; 32] = event_topic("TableUpdated(bytes32,uint64,uint64)");
const EV_SQUEAK_ALERT: [u8; 32] = event_topic("SqueakAlert(bytes32,uint64,uint64,uint64)");
const EV_BURROW_VICTORY: [u8; 32] = event_topic("BurrowVictory(bytes32,address,uint64)");

// ---------------------------------------------------------------------------
// Card Classification Helpers
// ---------------------------------------------------------------------------

#[inline]
pub const fn is_baby_vole(c: u8) -> bool {
    c <= BABY_END
}

#[inline]
pub const fn is_vole(c: u8) -> bool {
    c <= MUTANT_END
}

#[inline]
pub const fn is_spell(c: u8) -> bool {
    c >= SPELL_START && c <= SPELL_END
}

#[inline]
pub const fn is_perk(c: u8) -> bool {
    c >= PERK_START && c <= PERK_END
}

#[inline]
pub const fn is_hex(c: u8) -> bool {
    c >= HEX_START && c <= HEX_END
}

#[inline]
pub const fn is_instant(c: u8) -> bool {
    c == INSTANT_SQUEAK_NO || c == INSTANT_APEX_SQUEAK
}

// ---------------------------------------------------------------------------
// Compact In-Memory Table State (Persisted Cleanly per `table_id`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SeatState {
    eoa: [u8; 20],
    identity: [u8; 20],
    is_bot: u8,
    wins: u16,
    hand_len: u8,
    hand: [u8; MAX_HAND],
    voles_len: u8,
    voles: [u8; MAX_BURROW_VOLES],
    mods_len: u8,
    mods: [u8; MAX_BURROW_MODS],
}

impl SeatState {
    const fn empty() -> Self {
        Self {
            eoa: [0u8; 20],
            identity: [0u8; 20],
            is_bot: 0,
            wins: 0,
            hand_len: 0,
            hand: [CARD_NONE; MAX_HAND],
            voles_len: 0,
            voles: [CARD_NONE; MAX_BURROW_VOLES],
            mods_len: 0,
            mods: [CARD_NONE; MAX_BURROW_MODS],
        }
    }

    fn has_mod(&self, card_id: u8) -> bool {
        let n = (self.mods_len as usize).min(MAX_BURROW_MODS);
        let mut i = 0;
        while i < n {
            if self.mods[i] == card_id {
                return true;
            }
            i += 1;
        }
        false
    }

    fn count_vole_type(&self, card_id: u8) -> usize {
        let n = (self.voles_len as usize).min(MAX_BURROW_VOLES);
        let mut cnt = 0;
        let mut i = 0;
        while i < n {
            if self.voles[i] == card_id {
                cnt += 1;
            }
            i += 1;
        }
        cnt
    }

    fn effective_vole_count(&self) -> u8 {
        let raw = self.voles_len;
        if self.has_mod(CARD_HEX_TRUFFLES) && raw > 5 {
            5
        } else {
            raw
        }
    }

    fn push_hand(&mut self, card: u8) -> bool {
        let n = self.hand_len as usize;
        if n >= MAX_HAND {
            return false;
        }
        self.hand[n] = card;
        self.hand_len = (n + 1) as u8;
        true
    }

    fn remove_hand_at(&mut self, idx: usize) -> Option<u8> {
        let n = self.hand_len as usize;
        if idx >= n || n > MAX_HAND {
            return None;
        }
        let c = self.hand[idx];
        let mut i = idx;
        while i + 1 < n {
            self.hand[i] = self.hand[i + 1];
            i += 1;
        }
        self.hand[n - 1] = CARD_NONE;
        self.hand_len = (n - 1) as u8;
        Some(c)
    }

    fn push_vole(&mut self, card: u8) -> bool {
        let n = self.voles_len as usize;
        if n >= MAX_BURROW_VOLES {
            return false;
        }
        self.voles[n] = card;
        self.voles_len = (n + 1) as u8;
        true
    }

    fn remove_vole_at(&mut self, idx: usize) -> Option<u8> {
        let n = self.voles_len as usize;
        if idx >= n || n > MAX_BURROW_VOLES {
            return None;
        }
        let c = self.voles[idx];
        let mut i = idx;
        while i + 1 < n {
            self.voles[i] = self.voles[i + 1];
            i += 1;
        }
        self.voles[n - 1] = CARD_NONE;
        self.voles_len = (n - 1) as u8;
        Some(c)
    }

    fn push_mod(&mut self, card: u8) -> bool {
        let n = self.mods_len as usize;
        if n >= MAX_BURROW_MODS {
            return false;
        }
        self.mods[n] = card;
        self.mods_len = (n + 1) as u8;
        true
    }

    fn remove_mod_at(&mut self, idx: usize) -> Option<u8> {
        let n = self.mods_len as usize;
        if idx >= n || n > MAX_BURROW_MODS {
            return None;
        }
        let c = self.mods[idx];
        let mut i = idx;
        while i + 1 < n {
            self.mods[i] = self.mods[i + 1];
            i += 1;
        }
        self.mods[n - 1] = CARD_NONE;
        self.mods_len = (n - 1) as u8;
        Some(c)
    }
}

#[derive(Clone, Copy)]
struct PendingPlay {
    active: u8,
    actor_seat: u8,
    card_id: u8,
    target_seat: u8,
    target_slot: u8,
    aux_idx: u8,
    squeak_depth: u8,
    last_squeaker_seat: u8,
    passed_mask: u8,
    opened_block: u64,
    expires_block: u64,
}

impl PendingPlay {
    const fn empty() -> Self {
        Self {
            active: 0,
            actor_seat: 0xFF,
            card_id: CARD_NONE,
            target_seat: 0xFF,
            target_slot: 0xFF,
            aux_idx: 0xFF,
            squeak_depth: 0,
            last_squeaker_seat: 0xFF,
            passed_mask: 0,
            opened_block: 0,
            expires_block: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct LogEntry {
    turn: u16,
    actor_seat: u8,
    kind: u8,
    card_id: u8,
    target_seat: u8,
    aux_card: u8,
    flags: u8,
}

impl LogEntry {
    const fn empty() -> Self {
        Self {
            turn: 0,
            actor_seat: 0xFF,
            kind: 0,
            card_id: CARD_NONE,
            target_seat: 0xFF,
            aux_card: CARD_NONE,
            flags: 0,
        }
    }
}

struct TableState {
    phase: u8,
    seat_count: u8,
    turn_seat: u8,
    plays_remaining: u8,
    target_voles: u8,
    winner_seat: u8,
    turn_number: u16,
    rng_nonce: u64,
    entropy_seed: [u8; 32],
    deck_len: u8,
    deck: [u8; MAX_DECK],
    nest_len: u8,
    nest: [u8; MAX_NEST],
    scrap_len: u8,
    scrap: [u8; MAX_SCRAP],
    pending: PendingPlay,
    log_count: u8,
    logs: [LogEntry; LOG_WINDOW],
    seats: [SeatState; MAX_SEATS],
}

impl TableState {
    const fn new_lobby(target_voles: u8, seed: [u8; 32]) -> Self {
        Self {
            phase: PHASE_LOBBY,
            seat_count: 0,
            turn_seat: 0,
            plays_remaining: 1,
            target_voles,
            winner_seat: 0xFF,
            turn_number: 0,
            rng_nonce: 1,
            entropy_seed: seed,
            deck_len: 0,
            deck: [CARD_NONE; MAX_DECK],
            nest_len: 0,
            nest: [CARD_NONE; MAX_NEST],
            scrap_len: 0,
            scrap: [CARD_NONE; MAX_SCRAP],
            pending: PendingPlay::empty(),
            log_count: 0,
            logs: [LogEntry::empty(); LOG_WINDOW],
            seats: [SeatState::empty(); MAX_SEATS],
        }
    }

    fn next_rand_u64(&mut self) -> u64 {
        let mut h = KeccakHasher::new();
        h.update(&self.entropy_seed);
        h.update(&context::block_number().to_be_bytes());
        h.update(&self.rng_nonce.to_be_bytes());
        let digest = h.finalize();
        self.entropy_seed = digest;
        self.rng_nonce = self.rng_nonce.wrapping_add(1);
        u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ])
    }

    fn mix_player_entropy(&mut self, addr: &[u8; 20], extra: &[u8]) {
        let mut h = KeccakHasher::new();
        h.update(&self.entropy_seed);
        h.update(addr);
        h.update(&context::block_number().to_be_bytes());
        h.update(extra);
        self.entropy_seed = h.finalize();
    }

    fn push_log(
        &mut self,
        actor_seat: u8,
        kind: u8,
        card_id: u8,
        target_seat: u8,
        aux_card: u8,
        flags: u8,
    ) {
        let entry = LogEntry {
            turn: self.turn_number,
            actor_seat,
            kind,
            card_id,
            target_seat,
            aux_card,
            flags,
        };
        let n = self.log_count as usize;
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

    fn push_scrap_or_nest(&mut self, card: u8) {
        if card == CARD_NONE {
            return;
        }
        if is_baby_vole(card) {
            let n = self.nest_len as usize;
            if n < MAX_NEST {
                self.nest[n] = card;
                self.nest_len = (n + 1) as u8;
            }
        } else {
            let n = self.scrap_len as usize;
            if n < MAX_SCRAP {
                self.scrap[n] = card;
                self.scrap_len = (n + 1) as u8;
            }
        }
    }

    fn pop_nest(&mut self) -> Option<u8> {
        let n = self.nest_len as usize;
        if n == 0 || n > MAX_NEST {
            return None;
        }
        let c = self.nest[n - 1];
        self.nest[n - 1] = CARD_NONE;
        self.nest_len = (n - 1) as u8;
        Some(c)
    }

    fn draw_card_for_seat(&mut self, seat_idx: usize) -> Option<u8> {
        if seat_idx >= (self.seat_count as usize) {
            return None;
        }
        if self.seats[seat_idx].hand_len as usize >= MAX_HAND {
            return None;
        }
        if self.deck_len == 0 && self.scrap_len > 0 {
            // Reshuffle Scrap Heap into Draw Pile!
            let sn = (self.scrap_len as usize).min(MAX_DECK);
            let mut i = 0;
            while i < sn {
                self.deck[i] = self.scrap[i];
                self.scrap[i] = CARD_NONE;
                i += 1;
            }
            self.deck_len = sn as u8;
            self.scrap_len = 0;
            self.shuffle_deck();
        }
        let dn = self.deck_len as usize;
        if dn == 0 || dn > MAX_DECK {
            return None;
        }
        let c = self.deck[dn - 1];
        self.deck[dn - 1] = CARD_NONE;
        self.deck_len = (dn - 1) as u8;
        self.seats[seat_idx].push_hand(c);
        Some(c)
    }

    fn shuffle_deck(&mut self) {
        let n = (self.deck_len as usize).min(MAX_DECK);
        if n <= 1 {
            return;
        }
        let mut i = n - 1;
        while i > 0 {
            let r = (self.next_rand_u64() as usize) % (i + 1);
            let tmp = self.deck[i];
            self.deck[i] = self.deck[r];
            self.deck[r] = tmp;
            i -= 1;
        }
    }

    fn shuffle_nest(&mut self) {
        let n = (self.nest_len as usize).min(MAX_NEST);
        if n <= 1 {
            return;
        }
        let mut i = n - 1;
        while i > 0 {
            let r = (self.next_rand_u64() as usize) % (i + 1);
            let tmp = self.nest[i];
            self.nest[i] = self.nest[r];
            self.nest[r] = tmp;
            i -= 1;
        }
    }

    fn find_seat_by_eoa(&self, eoa: &[u8; 20]) -> Option<usize> {
        let sc = (self.seat_count as usize).min(MAX_SEATS);
        let mut i = 0;
        while i < sc {
            if self.seats[i].is_bot == 0 && &self.seats[i].eoa == eoa {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn human_count(&self) -> usize {
        let sc = (self.seat_count as usize).min(MAX_SEATS);
        let mut cnt = 0;
        let mut i = 0;
        while i < sc {
            if self.seats[i].is_bot == 0 {
                cnt += 1;
            }
            i += 1;
        }
        cnt
    }

    fn check_any_winner(&mut self, table_id: &[u8; 32]) -> bool {
        if self.phase == PHASE_FINISHED {
            return true;
        }
        let sc = (self.seat_count as usize).min(MAX_SEATS);
        let start = (self.turn_seat as usize) % sc.max(1);
        let mut off = 0;
        while off < sc {
            let s = (start + off) % sc;
            if self.seats[s].effective_vole_count() >= self.target_voles {
                self.phase = PHASE_FINISHED;
                self.winner_seat = s as u8;
                self.seats[s].wins = self.seats[s].wins.saturating_add(1);
                self.pending = PendingPlay::empty();
                self.push_log(
                    s as u8,
                    LOG_VICTORY,
                    CARD_NONE,
                    0xFF,
                    self.seats[s].effective_vole_count(),
                    0,
                );
                let mut ev_addr = [0u8; 32];
                ev_addr[12..32].copy_from_slice(&self.seats[s].eoa);
                let mut ev_data = [0u8; 32];
                ev_data[24..32].copy_from_slice(&(s as u64).to_be_bytes());
                events::emit(&[EV_BURROW_VICTORY, *table_id, ev_addr], &ev_data);
                return true;
            }
            off += 1;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Storage Codec (`TableState` <-> Bounded Byte Slice)
// ---------------------------------------------------------------------------

const STATE_SERIALIZED_LEN: usize = 960;

fn key_table(tid: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"vv:tbl:").push(tid)
}

const KEY_TABLE_LIST: &[u8] = b"vv:list";

fn register_table_in_index(tid: &[u8; 32]) {
    let mut buf = [0u8; 1 + MAX_LISTED_TABLES * 32];
    let n = storage::get_into(KEY_TABLE_LIST, &mut buf).unwrap_or(0);
    let mut cnt = if n >= 1 {
        (buf[0] as usize).min(MAX_LISTED_TABLES)
    } else {
        0
    };
    let mut i = 0;
    while i < cnt {
        let off = 1 + i * 32;
        if &buf[off..off + 32] == tid {
            return;
        }
        i += 1;
    }
    if cnt < MAX_LISTED_TABLES {
        let off = 1 + cnt * 32;
        buf[off..off + 32].copy_from_slice(tid);
        cnt += 1;
    } else {
        let mut j = 0;
        while j + 1 < MAX_LISTED_TABLES {
            let src = 1 + (j + 1) * 32;
            let dst = 1 + j * 32;
            buf.copy_within(src..src + 32, dst);
            j += 1;
        }
        let last = 1 + (MAX_LISTED_TABLES - 1) * 32;
        buf[last..last + 32].copy_from_slice(tid);
    }
    buf[0] = cnt as u8;
    storage::set(KEY_TABLE_LIST, &buf[..1 + cnt * 32]);
}

fn save_table(tid: &[u8; 32], st: &TableState) {
    let mut b = [0u8; STATE_SERIALIZED_LEN];
    b[0] = 1; // schema v1
    b[1] = st.phase;
    b[2] = st.seat_count;
    b[3] = st.turn_seat;
    b[4] = st.plays_remaining;
    b[5] = st.target_voles;
    b[6] = st.winner_seat;
    b[7..9].copy_from_slice(&st.turn_number.to_be_bytes());
    b[9..17].copy_from_slice(&st.rng_nonce.to_be_bytes());
    b[17..49].copy_from_slice(&st.entropy_seed);
    b[49] = st.deck_len;
    b[50..50 + MAX_DECK].copy_from_slice(&st.deck); // 50..122
    b[122] = st.nest_len;
    b[123..123 + MAX_NEST].copy_from_slice(&st.nest); // 123..131
    b[131] = st.scrap_len;
    b[132..132 + MAX_SCRAP].copy_from_slice(&st.scrap); // 132..204

    // PendingPlay (204..229 = 25 bytes)
    b[204] = st.pending.active;
    b[205] = st.pending.actor_seat;
    b[206] = st.pending.card_id;
    b[207] = st.pending.target_seat;
    b[208] = st.pending.target_slot;
    b[209] = st.pending.aux_idx;
    b[210] = st.pending.squeak_depth;
    b[211] = st.pending.last_squeaker_seat;
    b[212] = st.pending.passed_mask;
    b[213..221].copy_from_slice(&st.pending.opened_block.to_be_bytes());
    b[221..229].copy_from_slice(&st.pending.expires_block.to_be_bytes());

    // Logs (229..358 = 1 + 16*8 = 129 bytes)
    b[229] = st.log_count;
    let mut p = 230;
    let mut li = 0;
    while li < LOG_WINDOW {
        let lg = &st.logs[li];
        b[p..p + 2].copy_from_slice(&lg.turn.to_be_bytes());
        b[p + 2] = lg.actor_seat;
        b[p + 3] = lg.kind;
        b[p + 4] = lg.card_id;
        b[p + 5] = lg.target_seat;
        b[p + 6] = lg.aux_card;
        b[p + 7] = lg.flags;
        p += 8;
        li += 1;
    }

    // Seats (358..358 + 5*82 = 768)
    let mut si = 0;
    while si < MAX_SEATS {
        let s = &st.seats[si];
        b[p..p + 20].copy_from_slice(&s.eoa);
        b[p + 20..p + 40].copy_from_slice(&s.identity);
        b[p + 40] = s.is_bot;
        b[p + 41..p + 43].copy_from_slice(&s.wins.to_be_bytes());
        b[p + 43] = s.hand_len;
        b[p + 44..p + 44 + MAX_HAND].copy_from_slice(&s.hand); // +16 = 60
        b[p + 60] = s.voles_len;
        b[p + 61..p + 61 + MAX_BURROW_VOLES].copy_from_slice(&s.voles); // +12 = 73
        b[p + 73] = s.mods_len;
        b[p + 74..p + 74 + MAX_BURROW_MODS].copy_from_slice(&s.mods); // +8 = 82
        p += 82;
        si += 1;
    }

    let k = key_table(tid);
    storage::set(k.as_slice(), &b[..p]);
}

fn load_table(tid: &[u8; 32]) -> Option<TableState> {
    let k = key_table(tid);
    let mut b = [0u8; STATE_SERIALIZED_LEN];
    let n = storage::get_into(k.as_slice(), &mut b).unwrap_or(0);
    if n < 768 || b[0] != 1 {
        return None;
    }
    let mut st = TableState::new_lobby(b[5], [0u8; 32]);
    st.phase = b[1];
    st.seat_count = b[2].min(MAX_SEATS as u8);
    st.turn_seat = b[3];
    st.plays_remaining = b[4];
    st.target_voles = b[5];
    st.winner_seat = b[6];
    st.turn_number = u16::from_be_bytes([b[7], b[8]]);
    st.rng_nonce = u64::from_be_bytes([b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16]]);
    st.entropy_seed.copy_from_slice(&b[17..49]);
    st.deck_len = b[49].min(MAX_DECK as u8);
    st.deck.copy_from_slice(&b[50..50 + MAX_DECK]);
    st.nest_len = b[122].min(MAX_NEST as u8);
    st.nest.copy_from_slice(&b[123..123 + MAX_NEST]);
    st.scrap_len = b[131].min(MAX_SCRAP as u8);
    st.scrap.copy_from_slice(&b[132..132 + MAX_SCRAP]);

    st.pending = PendingPlay {
        active: b[204],
        actor_seat: b[205],
        card_id: b[206],
        target_seat: b[207],
        target_slot: b[208],
        aux_idx: b[209],
        squeak_depth: b[210],
        last_squeaker_seat: b[211],
        passed_mask: b[212],
        opened_block: u64::from_be_bytes([
            b[213], b[214], b[215], b[216], b[217], b[218], b[219], b[220],
        ]),
        expires_block: u64::from_be_bytes([
            b[221], b[222], b[223], b[224], b[225], b[226], b[227], b[228],
        ]),
    };

    st.log_count = b[229].min(LOG_WINDOW as u8);
    let mut p = 230;
    let mut li = 0;
    while li < LOG_WINDOW {
        st.logs[li] = LogEntry {
            turn: u16::from_be_bytes([b[p], b[p + 1]]),
            actor_seat: b[p + 2],
            kind: b[p + 3],
            card_id: b[p + 4],
            target_seat: b[p + 5],
            aux_card: b[p + 6],
            flags: b[p + 7],
        };
        p += 8;
        li += 1;
    }

    let mut si = 0;
    while si < MAX_SEATS {
        let mut s = SeatState::empty();
        s.eoa.copy_from_slice(&b[p..p + 20]);
        s.identity.copy_from_slice(&b[p + 20..p + 40]);
        s.is_bot = b[p + 40];
        s.wins = u16::from_be_bytes([b[p + 41], b[p + 42]]);
        s.hand_len = b[p + 43].min(MAX_HAND as u8);
        s.hand.copy_from_slice(&b[p + 44..p + 44 + MAX_HAND]);
        s.voles_len = b[p + 60].min(MAX_BURROW_VOLES as u8);
        s.voles.copy_from_slice(&b[p + 61..p + 61 + MAX_BURROW_VOLES]);
        s.mods_len = b[p + 73].min(MAX_BURROW_MODS as u8);
        s.mods.copy_from_slice(&b[p + 74..p + 74 + MAX_BURROW_MODS]);
        st.seats[si] = s;
        p += 82;
        si += 1;
    }

    Some(st)
}

fn emit_table_updated(tid: &[u8; 32], st: &TableState) {
    let mut ev = [0u8; 64];
    ev[24..32].copy_from_slice(&(st.phase as u64).to_be_bytes());
    ev[56..64].copy_from_slice(&(st.turn_number as u64).to_be_bytes());
    events::emit(&[EV_TABLE_UPDATED, *tid], &ev);
}

// ---------------------------------------------------------------------------
// Core Game Engine: Dealing, Dawn-of-Turn, Card Resolution & Reaction Stack
// ---------------------------------------------------------------------------

fn initialize_deal(st: &mut TableState) {
    let sc = (st.seat_count as usize).min(MAX_SEATS);
    st.nest = CANONICAL_NEST;
    st.nest_len = MAX_NEST as u8;
    st.shuffle_nest();

    st.deck = [CARD_NONE; MAX_DECK];
    st.deck[..CANONICAL_DECK_LEN].copy_from_slice(&CANONICAL_DECK);
    st.deck_len = CANONICAL_DECK_LEN as u8;
    st.shuffle_deck();

    st.scrap = [CARD_NONE; MAX_SCRAP];
    st.scrap_len = 0;
    st.pending = PendingPlay::empty();
    st.winner_seat = 0xFF;
    st.turn_number = 0;
    st.log_count = 0;

    let mut i = 0;
    while i < sc {
        st.seats[i].hand = [CARD_NONE; MAX_HAND];
        st.seats[i].hand_len = 0;
        st.seats[i].voles = [CARD_NONE; MAX_BURROW_VOLES];
        st.seats[i].voles_len = 0;
        st.seats[i].mods = [CARD_NONE; MAX_BURROW_MODS];
        st.seats[i].mods_len = 0;

        if let Some(baby) = st.pop_nest() {
            st.seats[i].push_vole(baby);
        }
        let mut d = 0;
        while d < INITIAL_HAND_SIZE {
            let _ = st.draw_card_for_seat(i);
            d += 1;
        }
        i += 1;
    }

    st.push_log(0, LOG_MATCH_STARTED, CARD_NONE, 0xFF, sc as u8, st.target_voles);
    begin_seat_turn(st, 0);
}

fn begin_seat_turn(st: &mut TableState, seat_idx: usize) {
    let sc = (st.seat_count as usize).min(MAX_SEATS);
    if sc == 0 {
        return;
    }
    let s = seat_idx % sc;
    st.turn_seat = s as u8;
    st.turn_number = st.turn_number.saturating_add(1);
    st.phase = PHASE_ACTION;

    // 1. Dawn of Turn triggers:
    //    - Alpha Warlord Vole (card 14): draws +1 bonus card per copy (unless Tin-Foil Muzzle card 22!)
    let muzzled = st.seats[s].has_mod(CARD_HEX_MUZZLE);
    if !muzzled {
        let warlords = st.seats[s].count_vole_type(CARD_WARLORD_VOLE);
        let mut w = 0;
        while w < warlords {
            if st.draw_card_for_seat(s).is_some() {
                st.push_log(s as u8, LOG_DAWN_BONUS, CARD_WARLORD_VOLE, s as u8, CARD_NONE, 0);
            }
            w += 1;
        }
    }

    //    - Overclocked Hamster Wheel Perk (card 19): grants 2 plays during Action Phase!
    st.plays_remaining = if st.seats[s].has_mod(CARD_PERK_WHEEL) {
        2
    } else {
        1
    };

    // 2. Mandatory Draw Phase: draw 1 card
    let _ = st.draw_card_for_seat(s);
}

fn finish_action_or_advance_turn(tid: &[u8; 32], st: &mut TableState) {
    if st.check_any_winner(tid) {
        return;
    }
    let s = st.turn_seat as usize;
    if st.plays_remaining > 0 && st.seats[s].hand_len > 0 {
        st.phase = PHASE_ACTION;
        return;
    }
    if (st.seats[s].hand_len as usize) > HAND_LIMIT {
        if st.seats[s].is_bot != 0 {
            bot_auto_discard_excess(st, s);
        } else {
            st.phase = PHASE_DISCARD;
            return;
        }
    }
    let sc = (st.seat_count as usize).max(1);
    let next_seat = (s + 1) % sc;
    begin_seat_turn(st, next_seat);
}

/// Validates and stages a card play from `actor_seat`, removing the played card (and Siren discard
/// or Collapse sacrifice cost? Note: sacrifice/discard effects happen ON RESOLUTION just like
/// Unstable Unicorns so getting SQUEAK-NO!'d doesn't also burn your extra sacrifice!).
fn validate_play_params(
    st: &TableState,
    actor: usize,
    card_id: u8,
    target_seat: u8,
    target_slot: u8,
    aux_idx: u8,
) -> Result<(), i32> {
    let sc = st.seat_count as usize;
    if is_instant(card_id) || card_id > INSTANT_APEX_SQUEAK {
        return Err(-20); // Instants can only be played via playSqueakNo!
    }
    if is_vole(card_id) {
        if (st.seats[actor].voles_len as usize) >= MAX_BURROW_VOLES {
            return Err(-21); // Burrow full
        }
        if card_id == CARD_SIREN_VOLE {
            // Requires target opponent with a non-Hazmat vole AND >=1 other card in hand to discard
            let ts = target_seat as usize;
            if ts >= sc || ts == actor {
                return Err(-22);
            }
            let slot = target_slot as usize;
            if slot >= (st.seats[ts].voles_len as usize) {
                return Err(-23);
            }
            if st.seats[ts].voles[slot] == CARD_HAZMAT_VOLE {
                return Err(-24); // Hazmat Bunker Vole is immune!
            }
            if (st.seats[actor].hand_len as usize) < 2 {
                return Err(-25); // Need at least 1 other card in hand to discard on resolution
            }
        }
        return Ok(());
    }
    if is_perk(card_id) {
        if (st.seats[actor].mods_len as usize) >= MAX_BURROW_MODS {
            return Err(-26);
        }
        return Ok(());
    }
    if is_hex(card_id) {
        let ts = target_seat as usize;
        if ts >= sc || ts == actor {
            return Err(-27); // Hex must target an opponent's Burrow
        }
        if (st.seats[ts].mods_len as usize) >= MAX_BURROW_MODS {
            return Err(-28);
        }
        return Ok(());
    }
    if is_spell(card_id) {
        match card_id {
            CARD_SPELL_COLLAPSE => {
                // Must have >= 1 card in own Burrow to sacrifice (`aux_idx`)
                let own_vole_ok = (aux_idx as usize) < (st.seats[actor].voles_len as usize);
                let own_mod_ok = aux_idx >= 100
                    && ((aux_idx - 100) as usize) < (st.seats[actor].mods_len as usize);
                if !own_vole_ok && !own_mod_ok {
                    return Err(-29);
                }
                let ts = target_seat as usize;
                if ts >= sc || ts == actor {
                    return Err(-30);
                }
            }
            CARD_SPELL_HEIST | CARD_SPELL_VOLENADO => {
                let ts = target_seat as usize;
                if ts >= sc || ts == actor {
                    return Err(-31);
                }
                if card_id == CARD_SPELL_VOLENADO {
                    let slot = target_slot as usize;
                    if slot >= (st.seats[ts].voles_len as usize) {
                        return Err(-32);
                    }
                    if st.seats[ts].voles[slot] == CARD_HAZMAT_VOLE {
                        return Err(-24);
                    }
                }
            }
            CARD_SPELL_EMP_RESET => {}
            _ => return Err(-20),
        }
        return Ok(());
    }
    Err(-20)
}

fn destroy_target_burrow_card(st: &mut TableState, ts: usize, slot_code: u8) -> Option<u8> {
    if ts >= (st.seat_count as usize) {
        return None;
    }
    if slot_code < 100 {
        let idx = slot_code as usize;
        if idx >= (st.seats[ts].voles_len as usize) {
            return None;
        }
        if st.seats[ts].voles[idx] == CARD_HAZMAT_VOLE {
            return None;
        }
        let removed = st.seats[ts].remove_vole_at(idx)?;
        st.push_scrap_or_nest(removed);
        Some(removed)
    } else {
        let idx = (slot_code - 100) as usize;
        if idx >= (st.seats[ts].mods_len as usize) {
            return None;
        }
        let target_mod = st.seats[ts].mods[idx];
        // Titanium Faraday Dome protects positive Perks from single-target destruction
        if is_perk(target_mod) && st.seats[ts].has_mod(CARD_PERK_DOME) {
            return None;
        }
        let removed = st.seats[ts].remove_mod_at(idx)?;
        st.push_scrap_or_nest(removed);
        Some(removed)
    }
}

fn execute_resolved_card(st: &mut TableState, p: PendingPlay) {
    let actor = p.actor_seat as usize;
    let sc = st.seat_count as usize;
    if actor >= sc {
        return;
    }
    let card = p.card_id;
    let mut aux_logged = CARD_NONE;

    if is_vole(card) {
        let _ = st.seats[actor].push_vole(card);
        match card {
            CARD_CHAINSAW_VOLE => {
                let ts = p.target_seat as usize;
                if ts < sc && (ts != actor || p.target_slot >= 100) {
                    if let Some(rem) = destroy_target_burrow_card(st, ts, p.target_slot) {
                        aux_logged = rem;
                    }
                }
            }
            CARD_KLEPTO_VOLE => {
                let ts = p.target_seat as usize;
                if ts < sc && ts != actor && st.seats[ts].hand_len > 0 {
                    let r = (st.next_rand_u64() as usize) % (st.seats[ts].hand_len as usize);
                    if let Some(stolen) = st.seats[ts].remove_hand_at(r) {
                        let _ = st.seats[actor].push_hand(stolen);
                        aux_logged = CARD_MASKED_BACK;
                    }
                }
            }
            CARD_NECRO_VOLE => {
                // Resurrect chosen Vole (or latest Vole) from Scrap Heap into actor's Burrow
                if (st.seats[actor].voles_len as usize) < MAX_BURROW_VOLES && st.scrap_len > 0 {
                    let sn = st.scrap_len as usize;
                    let mut chosen: Option<usize> = None;
                    let req = p.aux_idx as usize;
                    if req < sn && is_vole(st.scrap[req]) {
                        chosen = Some(req);
                    } else {
                        let mut k = sn;
                        while k > 0 {
                            k -= 1;
                            if is_vole(st.scrap[k]) {
                                chosen = Some(k);
                                break;
                            }
                        }
                    }
                    if let Some(si) = chosen {
                        let revived = st.scrap[si];
                        let mut m = si;
                        while m + 1 < sn {
                            st.scrap[m] = st.scrap[m + 1];
                            m += 1;
                        }
                        st.scrap[sn - 1] = CARD_NONE;
                        st.scrap_len = (sn - 1) as u8;
                        let _ = st.seats[actor].push_vole(revived);
                        aux_logged = revived;
                    }
                }
            }
            CARD_SIREN_VOLE => {
                let ts = p.target_seat as usize;
                let slot = p.target_slot as usize;
                if ts < sc
                    && ts != actor
                    && st.seats[actor].hand_len > 0
                    && (st.seats[actor].voles_len as usize) < MAX_BURROW_VOLES
                    && slot < (st.seats[ts].voles_len as usize)
                    && st.seats[ts].voles[slot] != CARD_HAZMAT_VOLE
                {
                    let disc_idx =
                        (p.aux_idx as usize).min((st.seats[actor].hand_len as usize) - 1);
                    if let Some(disc) = st.seats[actor].remove_hand_at(disc_idx) {
                        st.push_scrap_or_nest(disc);
                        if let Some(abducted) = st.seats[ts].remove_vole_at(slot) {
                            let _ = st.seats[actor].push_vole(abducted);
                            aux_logged = abducted;
                        }
                    }
                }
            }
            CARD_BROODMOTHER_VOLE => {
                if (st.seats[actor].voles_len as usize) < MAX_BURROW_VOLES {
                    if let Some(baby) = st.pop_nest() {
                        let _ = st.seats[actor].push_vole(baby);
                        aux_logged = baby;
                    }
                }
            }
            _ => {}
        }
    } else if is_perk(card) {
        let _ = st.seats[actor].push_mod(card);
        if card == CARD_PERK_WHEEL && st.seats[actor].hand_len == 0 {
            let _ = st.draw_card_for_seat(actor);
        }
    } else if is_hex(card) {
        let ts = p.target_seat as usize;
        if ts < sc && ts != actor {
            let _ = st.seats[ts].push_mod(card);
        } else {
            st.push_scrap_or_nest(card);
        }
    } else if is_spell(card) {
        match card {
            CARD_SPELL_COLLAPSE => {
                // Sacrifice 1 own Burrow card -> Destroy up to 2 cards in target opponent's Burrow
                let sac_done = if p.aux_idx < 100 {
                    let idx = p.aux_idx as usize;
                    if let Some(rem) = st.seats[actor].remove_vole_at(idx) {
                        st.push_scrap_or_nest(rem);
                        true
                    } else {
                        false
                    }
                } else {
                    let idx = (p.aux_idx - 100) as usize;
                    if let Some(rem) = st.seats[actor].remove_mod_at(idx) {
                        st.push_scrap_or_nest(rem);
                        true
                    } else {
                        false
                    }
                };
                if sac_done {
                    let ts = p.target_seat as usize;
                    if ts < sc && ts != actor {
                        if let Some(r1) = destroy_target_burrow_card(st, ts, p.target_slot) {
                            aux_logged = r1;
                        }
                        // Also destroy 1 additional vulnerable Vole or Mod in target's Burrow!
                        let mut second_done = false;
                        let mut vi = 0;
                        while vi < (st.seats[ts].voles_len as usize) {
                            if st.seats[ts].voles[vi] != CARD_HAZMAT_VOLE {
                                if let Some(r2) = st.seats[ts].remove_vole_at(vi) {
                                    st.push_scrap_or_nest(r2);
                                    second_done = true;
                                }
                                break;
                            }
                            vi += 1;
                        }
                        if !second_done && st.seats[ts].mods_len > 0 {
                            let _ = destroy_target_burrow_card(st, ts, 100);
                        }
                    }
                }
                st.push_scrap_or_nest(card);
            }
            CARD_SPELL_HEIST => {
                let ts = p.target_seat as usize;
                if ts < sc && ts != actor {
                    let tmp_hand = st.seats[actor].hand;
                    let tmp_len = st.seats[actor].hand_len;
                    st.seats[actor].hand = st.seats[ts].hand;
                    st.seats[actor].hand_len = st.seats[ts].hand_len;
                    st.seats[ts].hand = tmp_hand;
                    st.seats[ts].hand_len = tmp_len;
                    aux_logged = st.seats[actor].hand_len;
                }
                st.push_scrap_or_nest(card);
            }
            CARD_SPELL_VOLENADO => {
                let ts = p.target_seat as usize;
                let slot = p.target_slot as usize;
                if ts < sc && ts != actor && slot < (st.seats[ts].voles_len as usize) {
                    if st.seats[ts].voles[slot] != CARD_HAZMAT_VOLE {
                        if let Some(bounced) = st.seats[ts].remove_vole_at(slot) {
                            aux_logged = bounced;
                            if is_baby_vole(bounced)
                                || (st.seats[ts].hand_len as usize) >= MAX_HAND
                            {
                                st.push_scrap_or_nest(bounced);
                            } else {
                                let _ = st.seats[ts].push_hand(bounced);
                            }
                        }
                    }
                }
                let _ = st.draw_card_for_seat(actor);
                st.push_scrap_or_nest(card);
            }
            CARD_SPELL_EMP_RESET => {
                let mut s = 0;
                let mut wiped: u8 = 0;
                while s < sc {
                    while st.seats[s].mods_len > 0 {
                        if let Some(m) = st.seats[s].remove_mod_at(0) {
                            st.push_scrap_or_nest(m);
                            wiped = wiped.saturating_add(1);
                        } else {
                            break;
                        }
                    }
                    s += 1;
                }
                aux_logged = wiped;
                st.push_scrap_or_nest(card);
            }
            _ => {
                st.push_scrap_or_nest(card);
            }
        }
    }

    st.push_log(
        p.actor_seat,
        LOG_CARD_RESOLVED,
        card,
        p.target_seat,
        aux_logged,
        p.squeak_depth,
    );
}

fn current_stack_owner(p: &PendingPlay) -> u8 {
    if p.squeak_depth == 0 {
        p.actor_seat
    } else {
        p.last_squeaker_seat
    }
}

fn is_original_shielded_by_dome(st: &TableState, p: &PendingPlay) -> bool {
    p.squeak_depth == 0
        && (p.actor_seat as usize) < (st.seat_count as usize)
        && st.seats[p.actor_seat as usize].has_mod(CARD_PERK_DOME)
}

fn seat_can_squeak_exact(st: &TableState, seat_idx: usize, p: &PendingPlay) -> Option<usize> {
    if seat_idx >= (st.seat_count as usize) {
        return None;
    }
    if seat_idx as u8 == current_stack_owner(p) {
        return None;
    }
    let seat = &st.seats[seat_idx];
    if seat.has_mod(CARD_HEX_MUZZLE) {
        return None;
    }
    let dome_shield = is_original_shielded_by_dome(st, p);
    let hn = seat.hand_len as usize;
    let mut i = 0;
    // Prefer standard SQUEAK-NO! first unless Faraday Dome requires APEX SQUEAK-NO!
    if !dome_shield {
        while i < hn {
            if seat.hand[i] == INSTANT_SQUEAK_NO {
                return Some(i);
            }
            i += 1;
        }
    }
    let mut j = 0;
    while j < hn {
        if seat.hand[j] == INSTANT_APEX_SQUEAK {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Checks whether ANY human seat needs an interactive `PHASE_REACTION` window before `p` resolves:
/// - In multi-human PvP (`human_count >= 2`): any non-stack-owner, non-muzzled human with `>= 1`
///   card in hand who has not yet passed keeps the window open (preserving hand secrecy!).
/// - In solo vs. AI (`human_count == 1`): only pauses on an AI play when the human actually holds
///   a legal `SQUEAK-NO!` / `APEX SQUEAK-NO!` card so solo play has zero false-positive prompts!
fn any_human_eligible_to_react(st: &TableState, p: &PendingPlay) -> bool {
    let sc = st.seat_count as usize;
    let multi_human = st.human_count() >= 2;
    let stack_owner = current_stack_owner(p);
    let mut s = 0;
    while s < sc {
        if st.seats[s].is_bot == 0 && (s as u8) != stack_owner {
            let bit = 1u8 << s;
            if (p.passed_mask & bit) == 0 && !st.seats[s].has_mod(CARD_HEX_MUZZLE) {
                if multi_human {
                    if st.seats[s].hand_len > 0 {
                        return true;
                    }
                } else if seat_can_squeak_exact(st, s, p).is_some() {
                    return true;
                }
            }
        }
        s += 1;
    }
    false
}

fn bot_wants_to_squeak(st: &TableState, bot_seat: usize, p: &PendingPlay) -> bool {
    let stack_owner = current_stack_owner(p) as usize;
    if stack_owner == bot_seat {
        return false;
    }
    // If odd squeak_depth (meaning original play is currently CANCELED):
    // Only the original actor (if a bot) wants to counter-squeak to save its own play!
    if p.squeak_depth % 2 == 1 {
        return p.actor_seat as usize == bot_seat;
    }
    // Otherwise squeak_depth is even (original play by `p.actor_seat` is about to RESOLVE):
    let actor = p.actor_seat as usize;
    if actor == bot_seat || actor >= (st.seat_count as usize) {
        return false;
    }
    let actor_eff = st.seats[actor].effective_vole_count();
    let card = p.card_id;
    // Always counter game-winning or near-winning Voles (>= target_voles - 2), Broodmother, or direct attacks on this bot!
    if is_vole(card) && actor_eff + 1 >= st.target_voles.saturating_sub(1) {
        return true;
    }
    if (card == CARD_BROODMOTHER_VOLE || card == CARD_NECRO_VOLE || card == CARD_SIREN_VOLE)
        && actor_eff + 2 >= st.target_voles
    {
        return true;
    }
    if p.target_seat as usize == bot_seat
        && (is_hex(card)
            || card == CARD_CHAINSAW_VOLE
            || card == CARD_SIREN_VOLE
            || card == CARD_SPELL_COLLAPSE
            || card == CARD_SPELL_VOLENADO
            || (card == CARD_SPELL_HEIST && st.seats[bot_seat].hand_len >= 4))
    {
        return true;
    }
    if card == CARD_PERK_WHEEL || card == CARD_PERK_DOME {
        return actor_eff >= 4;
    }
    false
}

fn run_bot_squeak_reactions(tid: &[u8; 32], st: &mut TableState) -> bool {
    // Returns true if an APEX SQUEAK-NO! immediately terminated & fizzled the pending play
    let sc = st.seat_count as usize;
    let mut guard = 0;
    while guard < 6 {
        guard += 1;
        let mut triggered = false;
        let mut s = 0;
        while s < sc {
            if st.seats[s].is_bot != 0 && bot_wants_to_squeak(st, s, &st.pending) {
                if let Some(h_idx) = seat_can_squeak_exact(st, s, &st.pending) {
                    let sq_card = st.seats[s].remove_hand_at(h_idx).unwrap_or(INSTANT_SQUEAK_NO);
                    st.push_scrap_or_nest(sq_card);
                    st.pending.squeak_depth = st.pending.squeak_depth.saturating_add(1);
                    st.pending.last_squeaker_seat = s as u8;
                    st.pending.passed_mask = 0;
                    st.pending.opened_block = context::block_number();
                    st.pending.expires_block = st.pending.opened_block + REACTION_WINDOW_BLOCKS;
                    st.push_log(
                        s as u8,
                        LOG_SQUEAK_NO,
                        sq_card,
                        st.pending.actor_seat,
                        st.pending.card_id,
                        st.pending.squeak_depth,
                    );
                    emit_squeak_event(tid, s as u8, sq_card, st.pending.squeak_depth);
                    if sq_card == INSTANT_APEX_SQUEAK {
                        finalize_pending_play(tid, st);
                        return true;
                    }
                    triggered = true;
                    break;
                }
            }
            s += 1;
        }
        if !triggered {
            break;
        }
    }
    false
}

fn emit_squeak_event(tid: &[u8; 32], squeaker: u8, sq_card: u8, depth: u8) {
    let mut ev = [0u8; 96];
    ev[24..32].copy_from_slice(&(squeaker as u64).to_be_bytes());
    ev[56..64].copy_from_slice(&(sq_card as u64).to_be_bytes());
    ev[88..96].copy_from_slice(&(depth as u64).to_be_bytes());
    events::emit(&[EV_SQUEAK_ALERT, *tid], &ev);
}

fn finalize_pending_play(tid: &[u8; 32], st: &mut TableState) {
    if st.pending.active == 0 {
        return;
    }
    let p = st.pending;
    st.pending = PendingPlay::empty();

    if p.squeak_depth % 2 == 1 {
        // Canceled by SQUEAK-NO! -> played card goes straight to Scrap Heap (or Nest if Baby)
        st.push_scrap_or_nest(p.card_id);
        st.push_log(
            p.last_squeaker_seat,
            LOG_CARD_FIZZLED,
            p.card_id,
            p.actor_seat,
            CARD_NONE,
            p.squeak_depth,
        );
    } else {
        execute_resolved_card(st, p);
    }

    finish_action_or_advance_turn(tid, st);
}

fn stage_card_play(
    tid: &[u8; 32],
    st: &mut TableState,
    actor: usize,
    hand_idx: usize,
    target_seat: u8,
    target_slot: u8,
    aux_idx: u8,
) -> Result<(), i32> {
    if hand_idx >= (st.seats[actor].hand_len as usize) {
        return Err(-19);
    }
    let card_id = st.seats[actor].hand[hand_idx];
    validate_play_params(st, actor, card_id, target_seat, target_slot, aux_idx)?;

    // Remove played card from hand & consume 1 Action play
    let _ = st.seats[actor].remove_hand_at(hand_idx);
    st.plays_remaining = st.plays_remaining.saturating_sub(1);

    let now = context::block_number();
    st.pending = PendingPlay {
        active: 1,
        actor_seat: actor as u8,
        card_id,
        target_seat,
        target_slot,
        aux_idx,
        squeak_depth: 0,
        last_squeaker_seat: 0xFF,
        passed_mask: 0,
        opened_block: now,
        expires_block: now + REACTION_WINDOW_BLOCKS,
    };
    st.push_log(actor as u8, LOG_CARD_STAGED, card_id, target_seat, CARD_NONE, 0);

    // Let AI bots react immediately; if an Apex Squeak-No resolved it, we're already done!
    if run_bot_squeak_reactions(tid, st) {
        return Ok(());
    }

    // If any human seat can/may react, pause in PHASE_REACTION; else resolve immediately!
    if any_human_eligible_to_react(st, &st.pending) {
        st.phase = PHASE_REACTION;
    } else {
        finalize_pending_play(tid, st);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tactical On-Chain AI Bot Engine (Bounded Step Loop)
// ---------------------------------------------------------------------------

fn find_leading_opponent(st: &TableState, self_seat: usize) -> usize {
    let sc = st.seat_count as usize;
    let mut best_seat = (self_seat + 1) % sc.max(1);
    let mut best_score: u16 = 0;
    let mut i = 0;
    while i < sc {
        if i != self_seat {
            let sc_val = (st.seats[i].effective_vole_count() as u16) * 10
                + (st.seats[i].mods_len as u16) * 2
                + (st.seats[i].hand_len as u16);
            if sc_val >= best_score {
                best_score = sc_val;
                best_seat = i;
            }
        }
        i += 1;
    }
    best_seat
}

fn find_destructible_slot_on_rival(st: &TableState, rival: usize) -> Option<u8> {
    // Prefer destroying rival's Perks (if not Dome-shielded), else non-Hazmat Mutant Voles, else any Vole
    if !st.seats[rival].has_mod(CARD_PERK_DOME) {
        let mn = st.seats[rival].mods_len as usize;
        let mut m = 0;
        while m < mn {
            if is_perk(st.seats[rival].mods[m]) {
                return Some(100 + m as u8);
            }
            m += 1;
        }
    }
    let vn = st.seats[rival].voles_len as usize;
    let mut v = vn;
    while v > 0 {
        v -= 1;
        if st.seats[rival].voles[v] != CARD_HAZMAT_VOLE {
            return Some(v as u8);
        }
    }
    None
}

fn bot_auto_discard_excess(st: &mut TableState, bot: usize) {
    while (st.seats[bot].hand_len as usize) > HAND_LIMIT {
        // Discard lowest-priority card (keep Instants & Mutant Voles when possible)
        let hn = st.seats[bot].hand_len as usize;
        let mut pick = 0usize;
        let mut i = 0;
        while i < hn {
            let c = st.seats[bot].hand[i];
            if is_hex(c) || is_basic_card(c) {
                pick = i;
                break;
            }
            if !is_instant(c) {
                pick = i;
            }
            i += 1;
        }
        if let Some(rem) = st.seats[bot].remove_hand_at(pick) {
            st.push_scrap_or_nest(rem);
            st.push_log(bot as u8, LOG_DISCARDED, rem, 0xFF, CARD_NONE, 0);
        } else {
            break;
        }
    }
}

#[inline]
const fn is_basic_card(c: u8) -> bool {
    c >= BASIC_START && c <= BASIC_END
}

fn execute_single_bot_action(tid: &[u8; 32], st: &mut TableState, bot: usize) {
    let hn = st.seats[bot].hand_len as usize;
    let leader = find_leading_opponent(st, bot);

    // Priority 0: If cursed with Hallucinogenic Truffles or Muzzle and holding Chainsaw / Collapse, remove own Hex!
    let mut own_hex_mod: Option<u8> = None;
    let mn = st.seats[bot].mods_len as usize;
    let mut mi = 0;
    while mi < mn {
        if is_hex(st.seats[bot].mods[mi]) {
            own_hex_mod = Some(100 + mi as u8);
            break;
        }
        mi += 1;
    }

    if let Some(hex_slot) = own_hex_mod {
        let mut i = 0;
        while i < hn {
            let c = st.seats[bot].hand[i];
            if c == CARD_CHAINSAW_VOLE && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES {
                if stage_card_play(tid, st, bot, i, bot as u8, hex_slot, 0).is_ok() {
                    return;
                }
            }
            if c == CARD_SPELL_COLLAPSE {
                let r_slot = find_destructible_slot_on_rival(st, leader).unwrap_or(0);
                if stage_card_play(tid, st, bot, i, leader as u8, r_slot, hex_slot).is_ok() {
                    return;
                }
            }
            if c == CARD_SPELL_EMP_RESET {
                if stage_card_play(tid, st, bot, i, 0xFF, 0xFF, 0).is_ok() {
                    return;
                }
            }
            i += 1;
        }
    }

    // Priority 1: Play Perks (Wheel / Dome) or High-Impact Mutant Voles / Basic Voles to advance toward 7 Voles!
    let mut best_play: Option<(usize, u8, u8, u8, u8)> = None; // (hand_idx, score, target_seat, target_slot, aux)
    let mut i = 0;
    while i < hn {
        let c = st.seats[bot].hand[i];
        let mut candidate: Option<(u8, u8, u8, u8)> = None;

        if c == CARD_BROODMOTHER_VOLE
            && st.nest_len > 0
            && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES
        {
            candidate = Some((95, bot as u8, 0, 0));
        } else if c == CARD_SIREN_VOLE
            && hn >= 2
            && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES
        {
            if let Some(slot) = find_destructible_slot_on_rival(st, leader) {
                if slot < 100 {
                    let aux = if i == 0 { 0 } else { 0 };
                    candidate = Some((92, leader as u8, slot, aux));
                }
            }
        } else if c == CARD_CHAINSAW_VOLE && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES {
            let slot = find_destructible_slot_on_rival(st, leader).unwrap_or(0);
            candidate = Some((90, leader as u8, slot, 0));
        } else if c == CARD_NECRO_VOLE && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES {
            candidate = Some((88, bot as u8, 0, 0xFF));
        } else if (c == CARD_PERK_WHEEL || c == CARD_PERK_DOME)
            && !st.seats[bot].has_mod(c)
            && (st.seats[bot].mods_len as usize) < MAX_BURROW_MODS
        {
            candidate = Some((86, bot as u8, 0, 0));
        } else if is_hex(c)
            && !st.seats[leader].has_mod(c)
            && (st.seats[leader].mods_len as usize) < MAX_BURROW_MODS
        {
            let sc_hex = if st.seats[leader].effective_vole_count() >= 5 {
                94
            } else {
                76
            };
            candidate = Some((sc_hex, leader as u8, 0, 0));
        } else if c == CARD_SPELL_VOLENADO {
            if let Some(slot) = find_destructible_slot_on_rival(st, leader) {
                if slot < 100 {
                    candidate = Some((83, leader as u8, slot, 0));
                }
            }
        } else if c == CARD_SPELL_HEIST
            && st.seats[leader].hand_len > st.seats[bot].hand_len.saturating_add(1)
        {
            candidate = Some((82, leader as u8, 0, 0));
        } else if is_vole(c) && (st.seats[bot].voles_len as usize) < MAX_BURROW_VOLES {
            candidate = Some((80, leader as u8, 0, 0));
        }

        if let Some((score, ts, tslot, aux)) = candidate {
            if best_play.map_or(true, |b| score > b.1) {
                best_play = Some((i, score, ts, tslot, aux));
            }
        }
        i += 1;
    }

    if let Some((h_idx, _sc, ts, tslot, aux)) = best_play {
        if stage_card_play(tid, st, bot, h_idx, ts, tslot, aux).is_ok() {
            return;
        }
    }

    // Fallback: Forage (+1 extra card draw) and end Action Phase
    let _ = st.draw_card_for_seat(bot);
    st.plays_remaining = 0;
    st.push_log(bot as u8, LOG_FORAGED, CARD_NONE, 0xFF, CARD_NONE, 0);
    finish_action_or_advance_turn(tid, st);
}

fn drive_autonomous_bots(tid: &[u8; 32], st: &mut TableState) {
    let mut steps = 0;
    while steps < MAX_AUTO_BOT_STEPS {
        if st.phase != PHASE_ACTION {
            break;
        }
        let s = st.turn_seat as usize;
        if s >= (st.seat_count as usize) || st.seats[s].is_bot == 0 {
            break;
        }
        execute_single_bot_action(tid, st, s);
        steps += 1;
    }
}

// ---------------------------------------------------------------------------
// ABI Entrypoints
// ---------------------------------------------------------------------------

hps_entry! {
    "quickStartSolo(bytes32,address,uint64,uint64)"        => handle_quick_start_solo,
    "createTable(bytes32,address,uint64)"                  => handle_create_table,
    "joinTable(bytes32,address)"                           => handle_join_table,
    "startMatch(bytes32,uint64)"                           => handle_start_match,
    "rematchTable(bytes32)"                                => handle_rematch_table,
    "playCard(bytes32,uint64,uint64,uint64,uint64)"        => handle_play_card,
    "forageDraw(bytes32)"                                  => handle_forage_draw,
    "endActionPhase(bytes32)"                              => handle_end_action_phase,
    "playSqueakNo(bytes32,uint64)"                         => handle_play_squeak_no,
    "passReaction(bytes32)"                                => handle_pass_reaction,
    "resolveReaction(bytes32)"                             => handle_resolve_reaction,
    "discardExcess(bytes32,uint64)"                        => handle_discard_excess,
    "getTableState(bytes32,address)"                       => handle_get_table_state,
    "listTables()"                                         => handle_list_tables,
}

fn synthetic_bot_eoa(tid: &[u8; 32], seat_idx: u8) -> [u8; 20] {
    let mut h = KeccakHasher::new();
    h.update(b"vv:bot:");
    h.update(tid);
    h.update(&[seat_idx]);
    let d = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&d[12..32]);
    out
}

/// 1-Click Instant Start: Creates (or resets) `tableId`, seats `msg_sender` at Seat 0, adds `1..=4`
/// tactical AI Bot rivals, deals `1` Baby Vole + `5` cards per player, and begins Turn 1!
fn handle_quick_start_solo(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).unwrap_or([0u8; 20]);
    let bot_count = (args.u64(2).unwrap_or(3) as usize).clamp(1, MAX_SEATS - 1);
    let raw_target = args.u64(3).unwrap_or(DEFAULT_TARGET_VOLES as u64) as u8;
    let target_voles = if raw_target == 0 {
        DEFAULT_TARGET_VOLES
    } else {
        raw_target.clamp(MIN_TARGET_VOLES, MAX_TARGET_VOLES)
    };

    let caller = context::msg_sender();
    let prev_wins = load_table(&tid)
        .and_then(|old| old.find_seat_by_eoa(&caller).map(|idx| old.seats[idx].wins))
        .unwrap_or(0);

    let seed = keccak256(&tid);
    let mut st = TableState::new_lobby(target_voles, seed);
    st.mix_player_entropy(&caller, &identity);

    st.seats[0].eoa = caller;
    st.seats[0].identity = identity;
    st.seats[0].is_bot = 0;
    st.seats[0].wins = prev_wins;

    let total_seats = 1 + bot_count;
    let mut b = 1;
    while b < total_seats {
        st.seats[b].eoa = synthetic_bot_eoa(&tid, b as u8);
        st.seats[b].identity = [0u8; 20];
        st.seats[b].is_bot = 1;
        b += 1;
    }
    st.seat_count = total_seats as u8;

    initialize_deal(&mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    register_table_in_index(&tid);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.turn_number as u64);
    Ok(32)
}

fn handle_create_table(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).unwrap_or([0u8; 20]);
    let raw_target = args.u64(2).unwrap_or(DEFAULT_TARGET_VOLES as u64) as u8;
    let target_voles = if raw_target == 0 {
        DEFAULT_TARGET_VOLES
    } else {
        raw_target.clamp(MIN_TARGET_VOLES, MAX_TARGET_VOLES)
    };

    if let Some(existing) = load_table(&tid) {
        if existing.phase != PHASE_FINISHED && existing.phase != PHASE_LOBBY {
            return Err(-11); // Match currently active on this tableId
        }
    }

    let caller = context::msg_sender();
    let mut st = TableState::new_lobby(target_voles, keccak256(&tid));
    st.mix_player_entropy(&caller, &identity);
    st.seats[0].eoa = caller;
    st.seats[0].identity = identity;
    st.seats[0].is_bot = 0;
    st.seat_count = 1;

    save_table(&tid, &st);
    register_table_in_index(&tid);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(0);
    Ok(32)
}

fn handle_join_table(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let identity = args.address(1).unwrap_or([0u8; 20]);
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_LOBBY {
        return Err(-13);
    }
    let caller = context::msg_sender();
    if let Some(existing_idx) = st.find_seat_by_eoa(&caller) {
        st.seats[existing_idx].identity = identity;
        save_table(&tid, &st);
        ret::write_u64_word(existing_idx as u64);
        return Ok(32);
    }
    let sc = st.seat_count as usize;
    if sc >= MAX_SEATS {
        return Err(-14);
    }
    st.mix_player_entropy(&caller, &identity);
    st.seats[sc] = SeatState::empty();
    st.seats[sc].eoa = caller;
    st.seats[sc].identity = identity;
    st.seats[sc].is_bot = 0;
    st.seat_count = (sc + 1) as u8;

    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(sc as u64);
    Ok(32)
}

fn handle_start_match(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let fill_bots_to = (args.u64(1).unwrap_or(0) as usize).min(MAX_SEATS);
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_LOBBY {
        return Err(-13);
    }
    let caller = context::msg_sender();
    if st.find_seat_by_eoa(&caller).is_none() {
        return Err(-15);
    }

    while (st.seat_count as usize) < fill_bots_to && (st.seat_count as usize) < MAX_SEATS {
        let idx = st.seat_count as usize;
        st.seats[idx] = SeatState::empty();
        st.seats[idx].eoa = synthetic_bot_eoa(&tid, idx as u8);
        st.seats[idx].is_bot = 1;
        st.seat_count = (idx + 1) as u8;
    }

    if (st.seat_count as usize) < MIN_SEATS {
        return Err(-16); // Need at least 2 seats (or pass fill_bots_to >= 2)
    }

    st.mix_player_entropy(&caller, &[st.seat_count]);
    initialize_deal(&mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.seat_count as u64);
    Ok(32)
}

fn handle_rematch_table(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_FINISHED {
        return Err(-17);
    }
    let caller = context::msg_sender();
    if st.find_seat_by_eoa(&caller).is_none() {
        return Err(-15);
    }
    st.mix_player_entropy(&caller, &[0xA5]);
    initialize_deal(&mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.turn_number as u64);
    Ok(32)
}

fn auto_expire_reaction_if_due(tid: &[u8; 32], st: &mut TableState) {
    if st.phase == PHASE_REACTION
        && st.pending.active != 0
        && context::block_number() >= st.pending.expires_block
    {
        finalize_pending_play(tid, st);
        drive_autonomous_bots(tid, st);
    }
}

fn handle_play_card(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let hand_idx = args.u64(1).ok_or(-10)? as usize;
    let target_seat = args.u64(2).unwrap_or(0xFF) as u8;
    let target_slot = args.u64(3).unwrap_or(0) as u8;
    let aux_idx = args.u64(4).unwrap_or(0) as u8;

    let mut st = load_table(&tid).ok_or(-12)?;
    auto_expire_reaction_if_due(&tid, &mut st);
    if st.phase != PHASE_ACTION {
        return Err(-18);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    if seat != (st.turn_seat as usize) || st.plays_remaining == 0 {
        return Err(-33);
    }

    st.mix_player_entropy(&caller, &[hand_idx as u8, target_seat, target_slot]);
    stage_card_play(&tid, &mut st, seat, hand_idx, target_seat, target_slot, aux_idx)?;
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_forage_draw(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mut st = load_table(&tid).ok_or(-12)?;
    auto_expire_reaction_if_due(&tid, &mut st);
    if st.phase != PHASE_ACTION {
        return Err(-18);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    if seat != (st.turn_seat as usize) {
        return Err(-33);
    }

    st.mix_player_entropy(&caller, b"forage");
    let _ = st.draw_card_for_seat(seat);
    st.plays_remaining = 0;
    st.push_log(seat as u8, LOG_FORAGED, CARD_NONE, 0xFF, CARD_NONE, 0);
    finish_action_or_advance_turn(&tid, &mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_end_action_phase(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mut st = load_table(&tid).ok_or(-12)?;
    auto_expire_reaction_if_due(&tid, &mut st);
    if st.phase != PHASE_ACTION {
        return Err(-18);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    if seat != (st.turn_seat as usize) {
        return Err(-33);
    }
    st.plays_remaining = 0;
    finish_action_or_advance_turn(&tid, &mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_play_squeak_no(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let hand_idx = args.u64(1).ok_or(-10)? as usize;
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_REACTION || st.pending.active == 0 {
        return Err(-34);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    if seat as u8 == current_stack_owner(&st.pending) {
        return Err(-35); // Cannot counter your own top-of-stack action
    }
    if st.seats[seat].has_mod(CARD_HEX_MUZZLE) {
        return Err(-36); // Tin-Foil Muzzle blocks Instants!
    }
    if hand_idx >= (st.seats[seat].hand_len as usize) {
        return Err(-19);
    }
    let sq_card = st.seats[seat].hand[hand_idx];
    if !is_instant(sq_card) {
        return Err(-37);
    }
    if sq_card == INSTANT_SQUEAK_NO && is_original_shielded_by_dome(&st, &st.pending) {
        return Err(-38); // Titanium Faraday Dome blocks standard SQUEAK-NO!
    }

    let _ = st.seats[seat].remove_hand_at(hand_idx);
    st.push_scrap_or_nest(sq_card);
    st.pending.squeak_depth = st.pending.squeak_depth.saturating_add(1);
    st.pending.last_squeaker_seat = seat as u8;
    st.pending.passed_mask = 0;
    let now = context::block_number();
    st.pending.opened_block = now;
    st.pending.expires_block = now + REACTION_WINDOW_BLOCKS;

    st.push_log(
        seat as u8,
        LOG_SQUEAK_NO,
        sq_card,
        st.pending.actor_seat,
        st.pending.card_id,
        st.pending.squeak_depth,
    );
    emit_squeak_event(&tid, seat as u8, sq_card, st.pending.squeak_depth);

    if sq_card == INSTANT_APEX_SQUEAK {
        finalize_pending_play(&tid, &mut st);
        drive_autonomous_bots(&tid, &mut st);
    } else if !run_bot_squeak_reactions(&tid, &mut st) {
        if !any_human_eligible_to_react(&st, &st.pending) {
            finalize_pending_play(&tid, &mut st);
            drive_autonomous_bots(&tid, &mut st);
        }
    } else {
        drive_autonomous_bots(&tid, &mut st);
    }

    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_pass_reaction(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_REACTION || st.pending.active == 0 {
        ret::write_u64_word(st.phase as u64);
        return Ok(32);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    st.pending.passed_mask |= 1u8 << seat;

    if !any_human_eligible_to_react(&st, &st.pending)
        || context::block_number() >= st.pending.expires_block
    {
        finalize_pending_play(&tid, &mut st);
        drive_autonomous_bots(&tid, &mut st);
    }

    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_resolve_reaction(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_REACTION || st.pending.active == 0 {
        ret::write_u64_word(st.phase as u64);
        return Ok(32);
    }
    if context::block_number() < st.pending.expires_block
        && any_human_eligible_to_react(&st, &st.pending)
    {
        return Err(-39); // Reaction window still open
    }
    finalize_pending_play(&tid, &mut st);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

fn handle_discard_excess(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let mask = args.u64(1).ok_or(-10)? as u16;
    let mut st = load_table(&tid).ok_or(-12)?;
    if st.phase != PHASE_DISCARD {
        return Err(-40);
    }
    let caller = context::msg_sender();
    let seat = st.find_seat_by_eoa(&caller).ok_or(-15)?;
    if seat != (st.turn_seat as usize) {
        return Err(-33);
    }

    let hn = st.seats[seat].hand_len as usize;
    if hn <= HAND_LIMIT {
        finish_action_or_advance_turn(&tid, &mut st);
        drive_autonomous_bots(&tid, &mut st);
        save_table(&tid, &st);
        ret::write_u64_word(st.phase as u64);
        return Ok(32);
    }
    let required_drop = hn - HAND_LIMIT;
    let mut selected = 0usize;
    let mut bit = 0;
    while bit < hn {
        if ((mask >> bit) & 1) != 0 {
            selected += 1;
        }
        bit += 1;
    }
    if selected != required_drop {
        return Err(-41); // Must select exact excess card count to drop down to 7
    }

    // Remove from highest index downward so lower indices stay aligned
    let mut k = hn;
    while k > 0 {
        k -= 1;
        if ((mask >> k) & 1) != 0 {
            if let Some(rem) = st.seats[seat].remove_hand_at(k) {
                st.push_scrap_or_nest(rem);
                st.push_log(seat as u8, LOG_DISCARDED, rem, 0xFF, CARD_NONE, 0);
            }
        }
    }

    let sc = (st.seat_count as usize).max(1);
    begin_seat_turn(&mut st, (seat + 1) % sc);
    drive_autonomous_bots(&tid, &mut st);
    save_table(&tid, &st);
    emit_table_updated(&tid, &st);
    ret::write_u64_word(st.phase as u64);
    Ok(32)
}

/// Binary Snapshot Layout (`getTableState(bytes32 tableId, address viewer)`):
/// - `[0..32]` Header:
///   - `0`: schema (`1`)
///   - `1`: `phase`
///   - `2`: `seat_count`
///   - `3`: `turn_seat`
///   - `4`: `plays_remaining`
///   - `5`: `target_voles`
///   - `6`: `winner_seat`
///   - `7..9`: `turn_number` (`u16` BE)
///   - `9`: `deck_len`
///   - `10`: `nest_len`
///   - `11`: `scrap_len`
///   - `12`: `top_scrap_card`
///   - `13`: `log_count`
///   - `14`: `viewer_seat` (`0..4` or `0xFF`)
///   - `15`: `reserved`
///   - `16..24`: `current_block` (`u64` BE)
///   - `24..32`: `reaction_expires_block` (`u64` BE)
/// - `[32..44]` PendingPlay (`12` bytes):
///   - `32`: `active`, `33`: `actor_seat`, `34`: `card_id`, `35`: `target_seat`,
///     `36`: `target_slot`, `37`: `aux_idx`, `38`: `squeak_depth`, `39`: `last_squeaker_seat`,
///     `40`: `passed_mask`, `41`: `shielded_by_dome`, `42..44`: `0`
/// - `[44..44 + seat_count * 84]` Per-Seat Records (`84` bytes each):
///   - `0..20`: `eoa`
///   - `20..40`: `identity`
///   - `40`: `is_bot`
///   - `41..43`: `wins` (`u16` BE)
///   - `43`: `raw_voles_len`
///   - `44`: `effective_voles_len`
///   - `45`: `mods_len`
///   - `46`: `hand_len`
///   - `47`: `flags` (`bit0 = truffles_cursed`, `bit1 = muzzled`, `bit2 = wheel`, `bit3 = dome`)
///   - `48..60`: `voles[12]`
///   - `60..68`: `mods[8]`
///   - `68..84`: `hand[16]` (revealed ONLY if `seat.eoa == viewer` or `phase == PHASE_FINISHED`, else `0xFE`)
/// - Next: `nest[8]` (`8` bytes)
/// - Next: `scrap[scrap_len]` (`scrap_len` bytes)
/// - Next: `logs[log_count]` (`log_count * 8` bytes)
fn handle_get_table_state(args: &CalldataReader) -> Result<i32, i32> {
    let tid = args.bytes32(0).ok_or(-10)?;
    let viewer = args.address(1).unwrap_or([0u8; 20]);
    let Some(st) = load_table(&tid) else {
        ret::write(&[]);
        return Ok(0);
    };

    let mut out = [0u8; 768];
    let sc = (st.seat_count as usize).min(MAX_SEATS);
    let viewer_seat = st.find_seat_by_eoa(&viewer).map(|x| x as u8).unwrap_or(0xFF);
    let top_scrap = if st.scrap_len > 0 {
        st.scrap[(st.scrap_len as usize) - 1]
    } else {
        CARD_NONE
    };

    out[0] = 1;
    out[1] = st.phase;
    out[2] = sc as u8;
    out[3] = st.turn_seat;
    out[4] = st.plays_remaining;
    out[5] = st.target_voles;
    out[6] = st.winner_seat;
    out[7..9].copy_from_slice(&st.turn_number.to_be_bytes());
    out[9] = st.deck_len;
    out[10] = st.nest_len;
    out[11] = st.scrap_len;
    out[12] = top_scrap;
    out[13] = st.log_count;
    out[14] = viewer_seat;
    out[15] = 0;
    out[16..24].copy_from_slice(&context::block_number().to_be_bytes());
    out[24..32].copy_from_slice(&st.pending.expires_block.to_be_bytes());

    out[32] = st.pending.active;
    out[33] = st.pending.actor_seat;
    out[34] = st.pending.card_id;
    out[35] = st.pending.target_seat;
    out[36] = st.pending.target_slot;
    out[37] = st.pending.aux_idx;
    out[38] = st.pending.squeak_depth;
    out[39] = st.pending.last_squeaker_seat;
    out[40] = st.pending.passed_mask;
    out[41] = if is_original_shielded_by_dome(&st, &st.pending) {
        1
    } else {
        0
    };

    let mut pos = 44;
    let mut i = 0;
    while i < sc {
        let s = &st.seats[i];
        out[pos..pos + 20].copy_from_slice(&s.eoa);
        out[pos + 20..pos + 40].copy_from_slice(&s.identity);
        out[pos + 40] = s.is_bot;
        out[pos + 41..pos + 43].copy_from_slice(&s.wins.to_be_bytes());
        out[pos + 43] = s.voles_len;
        out[pos + 44] = s.effective_vole_count();
        out[pos + 45] = s.mods_len;
        out[pos + 46] = s.hand_len;
        let mut flags = 0u8;
        if s.has_mod(CARD_HEX_TRUFFLES) {
            flags |= 1;
        }
        if s.has_mod(CARD_HEX_MUZZLE) {
            flags |= 2;
        }
        if s.has_mod(CARD_PERK_WHEEL) {
            flags |= 4;
        }
        if s.has_mod(CARD_PERK_DOME) {
            flags |= 8;
        }
        out[pos + 47] = flags;
        out[pos + 48..pos + 60].copy_from_slice(&s.voles);
        out[pos + 60..pos + 68].copy_from_slice(&s.mods);

        let reveal = (s.is_bot == 0 && s.eoa == viewer && viewer != [0u8; 20])
            || st.phase == PHASE_FINISHED;
        let mut h = 0;
        while h < MAX_HAND {
            out[pos + 68 + h] = if h < (s.hand_len as usize) {
                if reveal {
                    s.hand[h]
                } else {
                    CARD_MASKED_BACK
                }
            } else {
                CARD_NONE
            };
            h += 1;
        }
        pos += 84;
        i += 1;
    }

    out[pos..pos + MAX_NEST].copy_from_slice(&st.nest);
    pos += MAX_NEST;

    let sn = (st.scrap_len as usize).min(MAX_SCRAP);
    out[pos..pos + sn].copy_from_slice(&st.scrap[..sn]);
    pos += sn;

    let ln = (st.log_count as usize).min(LOG_WINDOW);
    let mut li = 0;
    while li < ln {
        let lg = &st.logs[li];
        out[pos..pos + 2].copy_from_slice(&lg.turn.to_be_bytes());
        out[pos + 2] = lg.actor_seat;
        out[pos + 3] = lg.kind;
        out[pos + 4] = lg.card_id;
        out[pos + 5] = lg.target_seat;
        out[pos + 6] = lg.aux_card;
        out[pos + 7] = lg.flags;
        pos += 8;
        li += 1;
    }

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

fn handle_list_tables(_args: &CalldataReader) -> Result<i32, i32> {
    let mut buf = [0u8; 1 + MAX_LISTED_TABLES * 32];
    let n = storage::get_into(KEY_TABLE_LIST, &mut buf).unwrap_or(0);
    if n < 1 {
        ret::write(&[0u8]);
        return Ok(1);
    }
    let cnt = (buf[0] as usize).min(MAX_LISTED_TABLES);
    let mut out = [0u8; 1 + MAX_LISTED_TABLES * 36];
    out[0] = cnt as u8;
    let mut pos = 1;
    let mut i = 0;
    while i < cnt {
        let off = 1 + i * 32;
        let mut tid = [0u8; 32];
        tid.copy_from_slice(&buf[off..off + 32]);
        out[pos..pos + 32].copy_from_slice(&tid);
        if let Some(st) = load_table(&tid) {
            out[pos + 32] = st.phase;
            out[pos + 33] = st.seat_count;
            out[pos + 34] = st.target_voles;
            out[pos + 35] = st.human_count() as u8;
        }
        pos += 36;
        i += 1;
    }
    ret::write(&out[..pos]);
    Ok(pos as i32)
}

// ---------------------------------------------------------------------------
// Native Unit Tests (`cargo test -p volatile-voles`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const VOLES_ADDR: [u8; 20] = [0x77; 20];
    const ALICE: [u8; 20] = [0xA1; 20];
    const BOB: [u8; 20] = [0xB2; 20];
    const CAROL: [u8; 20] = [0xC3; 20];

    #[test]
    fn quick_start_solo_deals_baby_voles_masks_hands_and_plays() {
        mock::reset();
        mock::register_hps(VOLES_ADDR, dispatch_calldata);
        mock::set_block_number(500);

        let tid = [0x11; 32];
        let cd = CallEncoder::<256>::new(selector("quickStartSolo(bytes32,address,uint64,uint64)"))
            .push_bytes32(&tid)
            .push_address(&[0xAA; 20])
            .push_u64(3) // 1 human + 3 AI bots = 4 seats
            .push_u64(7)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, VOLES_ADDR, &cd).unwrap();

        let cd_get_alice = CallEncoder::<256>::new(selector("getTableState(bytes32,address)"))
            .push_bytes32(&tid)
            .push_address(&ALICE)
            .as_slice()
            .to_vec();
        let snap = mock::transact_as(ALICE, VOLES_ADDR, &cd_get_alice).unwrap();
        assert_eq!(snap[2], 4); // 4 seats
        assert_eq!(snap[5], 7); // 7 target voles
        assert_eq!(snap[14], 0); // viewer is seat 0

        // Seat 0 (Alice): hand bytes revealed (!= 0xFE), starts with 1 Baby Vole + 6 cards (5 dealt + 1 drawn on Turn 1)
        let alice_off = 44;
        assert_eq!(snap[alice_off + 43], 1); // 1 Baby Vole in Burrow
        assert!(snap[alice_off + 48] <= BABY_END);
        assert_eq!(snap[alice_off + 46], 6); // 5 initial + 1 drawn
        assert_ne!(snap[alice_off + 68], CARD_MASKED_BACK);

        // Seat 1 (Bot): hand bytes masked as 0xFE for Alice!
        let bot1_off = 44 + 84;
        assert_eq!(snap[bot1_off + 40], 1); // is_bot == 1
        assert_eq!(snap[bot1_off + 68], CARD_MASKED_BACK);

        // Alice forages (+1 card) -> AI bots automatically execute turns until it returns to Alice (or pauses for Alice's Squeak-No!)
        let cd_forage = CallEncoder::<128>::new(selector("forageDraw(bytes32)"))
            .push_bytes32(&tid)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, VOLES_ADDR, &cd_forage).unwrap();

        let snap2 = mock::transact_as(ALICE, VOLES_ADDR, &cd_get_alice).unwrap();
        assert!(snap2[1] == PHASE_ACTION || snap2[1] == PHASE_REACTION || snap2[1] == PHASE_FINISHED);
    }

    #[test]
    fn pvp_squeak_no_chain_apex_squeak_and_truffles_pandamonium_rule() {
        mock::reset();
        mock::register_hps(VOLES_ADDR, dispatch_calldata);
        mock::set_self_address(VOLES_ADDR);
        mock::set_block_number(1000);

        let tid = [0x22; 32];
        // Directly construct a controlled 2-human PvP state to test exact Squeak-No! counter-chains & Truffles victory cap
        let mut st = TableState::new_lobby(7, [0x42; 32]);
        st.seats[0].eoa = ALICE;
        st.seats[1].eoa = BOB;
        st.seat_count = 2;
        initialize_deal(&mut st);

        // Give Alice 6 Voles in Burrow + Hallucinogenic Truffles Hex (caps effective voles at 5!)
        st.seats[0].voles = [0, 5, 5, 6, 6, 7, CARD_NONE, CARD_NONE, CARD_NONE, CARD_NONE, CARD_NONE, CARD_NONE];
        st.seats[0].voles_len = 6;
        st.seats[0].mods[0] = CARD_HEX_TRUFFLES;
        st.seats[0].mods_len = 1;
        assert_eq!(st.seats[0].effective_vole_count(), 5);

        // Give Alice a Basic Vole (card 5), Chainsaw Vole (card 8), and SQUEAK-NO! (card 23)
        st.seats[0].hand[0] = 5;
        st.seats[0].hand[1] = CARD_CHAINSAW_VOLE;
        st.seats[0].hand[2] = INSTANT_SQUEAK_NO;
        st.seats[0].hand_len = 3;

        // Give Bob SQUEAK-NO! (card 23) and APEX SQUEAK-NO! (card 24)
        st.seats[1].hand[0] = INSTANT_SQUEAK_NO;
        st.seats[1].hand[1] = INSTANT_APEX_SQUEAK;
        st.seats[1].hand_len = 2;
        st.turn_seat = 0;
        st.plays_remaining = 2; // Give Alice 2 plays
        save_table(&tid, &st);

        // 1) Alice plays Basic Vole (hand_idx 0) -> enters PHASE_REACTION because Bob is human with cards
        let cd_play1 = CallEncoder::<256>::new(selector("playCard(bytes32,uint64,uint64,uint64,uint64)"))
            .push_bytes32(&tid)
            .push_u64(0)
            .push_u64(0)
            .push_u64(0)
            .push_u64(0)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, VOLES_ADDR, &cd_play1).unwrap();
        mock::set_self_address(VOLES_ADDR);
        assert_eq!(load_table(&tid).unwrap().phase, PHASE_REACTION);

        // 2) Bob counters with SQUEAK-NO! (hand_idx 0) -> depth = 1
        let cd_sq_bob = CallEncoder::<128>::new(selector("playSqueakNo(bytes32,uint64)"))
            .push_bytes32(&tid)
            .push_u64(0)
            .as_slice()
            .to_vec();
        mock::transact_as(BOB, VOLES_ADDR, &cd_sq_bob).unwrap();
        mock::set_self_address(VOLES_ADDR);
        assert_eq!(load_table(&tid).unwrap().pending.squeak_depth, 1);

        // 3) Alice counter-counters with her own SQUEAK-NO! (now at hand_idx 1 since card 0 was played) -> depth = 2!
        let cd_sq_alice = CallEncoder::<128>::new(selector("playSqueakNo(bytes32,uint64)"))
            .push_bytes32(&tid)
            .push_u64(1)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, VOLES_ADDR, &cd_sq_alice).unwrap();
        mock::set_self_address(VOLES_ADDR);
        assert_eq!(load_table(&tid).unwrap().pending.squeak_depth, 2);

        // 4) Bob passes reaction -> Alice's Basic Vole resolves (7 raw Voles!), BUT Alice has Truffles Hex so effective == 5 (NOT finished yet!)
        let cd_pass = CallEncoder::<128>::new(selector("passReaction(bytes32)"))
            .push_bytes32(&tid)
            .as_slice()
            .to_vec();
        mock::transact_as(BOB, VOLES_ADDR, &cd_pass).unwrap();
        mock::set_self_address(VOLES_ADDR);
        let after_first = load_table(&tid).unwrap();
        assert_eq!(after_first.seats[0].voles_len, 7);
        assert_eq!(after_first.seats[0].effective_vole_count(), 5);
        assert_eq!(after_first.phase, PHASE_ACTION); // Still active!

        // 5) Alice plays Chainsaw Berserker Vole targeting HER OWN Truffles Hex (target_seat=0, target_slot=100)!
        let cd_saw = CallEncoder::<256>::new(selector("playCard(bytes32,uint64,uint64,uint64,uint64)"))
            .push_bytes32(&tid)
            .push_u64(0)
            .push_u64(0)
            .push_u64(100) // mod slot 0
            .push_u64(0)
            .as_slice()
            .to_vec();
        mock::transact_as(ALICE, VOLES_ADDR, &cd_saw).unwrap();

        // Bob passes -> Chainsaw saws off Truffles Hex -> Alice's effective voles jump from 5 to 8 -> INSTANT VICTORY!
        mock::transact_as(BOB, VOLES_ADDR, &cd_pass).unwrap();
        mock::set_self_address(VOLES_ADDR);
        let finished = load_table(&tid).unwrap();
        assert_eq!(finished.phase, PHASE_FINISHED);
        assert_eq!(finished.winner_seat, 0);
        assert_eq!(finished.seats[0].wins, 1);
    }

    #[test]
    fn baby_voles_return_to_nest_and_hazmat_vole_is_immune() {
        mock::reset();
        mock::register_hps(VOLES_ADDR, dispatch_calldata);

        let mut st = TableState::new_lobby(7, [0x99; 32]);
        st.seats[0].eoa = ALICE;
        st.seats[1].eoa = BOB;
        st.seat_count = 2;
        initialize_deal(&mut st);

        // Bob has Baby Vole (slot 0) and Hazmat Vole (slot 1)
        let bob_baby = st.seats[1].voles[0];
        assert!(is_baby_vole(bob_baby));
        st.seats[1].push_vole(CARD_HAZMAT_VOLE);
        let nest_before = st.nest_len;

        // Trying to destroy Hazmat Vole (slot 1) returns None
        assert!(destroy_target_burrow_card(&mut st, 1, 1).is_none());
        assert_eq!(st.seats[1].voles_len, 2);

        // Destroying Baby Vole (slot 0) returns it to The Nest (not Scrap Heap!)
        assert_eq!(destroy_target_burrow_card(&mut st, 1, 0), Some(bob_baby));
        assert_eq!(st.nest_len, nest_before + 1);
        assert_eq!(st.scrap_len, 0);
        let _ = CAROL;
    }
}
