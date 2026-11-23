//! # Cipher Noir: Arbiter-Free Zero-Knowledge & Threshold Vault Sabotage Tribunal (`cipher-noir` — HPS #16)
//!
//! 100% Arbiter-Free, Zero-Trusted-Setup Cryptographic Deduction Haltproof Subroutine on `Edwards25519`:
//! 1. **2-Party Verifiable ElGamal Co-Shuffle (`submitInitialShuffle` + `coShuffleAndDeal`)**:
//!    - Canonical `5 + 5 + 8` Sabotage Dossiers (`0..=4` Operatives, `5..=9` Exploits, `10..=17` Sectors)
//!      are permuted & re-randomized under the 5-Validator Threshold ElGamal key (`vrf-beacon`) by two
//!      independent parties, verified on-chain via **Bulletproofs Sparse R1CS** (`P_{r,c} ∈ {0,1}`,
//!      row/column sums `= 1`) + Schwartz-Zippel ElGamal linear-combination Schnorr proofs.
//!    - `3` Incident Vectors (`1` Operative, `1` Exploit, `1` Sector) stay sealed in the Threshold Vault
//!      (**known to zero humans, zero bots, and zero individual validators**), while the remaining `15`
//!      Alibi Dossiers undergo a cross-category `15x15` ZK shuffle so category distribution is hidden.
//! 2. **DDH-Blinded Threshold Hand Delivery (`onHeDecryptionFulfilled`)**:
//!    - Each Operative registers `(ed_pk, U_{s,0..2}, T_{s,0..2})` with Schnorr PoKs. `cipher-noir` blinds
//!      `C'_{1,j} = C_{1,j} + U_{s,k}` before validator decryption, then homomorphically computes each
//!      Operative's `Bulletproofs` Pedersen commitment `V_{s,k} = M'_{j} + T_{s,k} = c_j * B + w_{s,k} * H_bp`
//!      directly on-chain with **zero post-deal transactions**.
//! 3. **Mathematically Cheat-Proof Forensic Probes**:
//!    - `passAlibiCheck`: verifies a 672-byte **Bulletproofs R1CS** proof (`16` gates) that
//!      `∏_{k=0..2, m=0..2} (c_k - p_m) * inv == 1` against `V_{s,0..2}`. Holding any probed vector makes
//!      passing algebraically impossible!
//!    - `transmitAlibiProof`: verifies a 352-byte **1-of-3 Disjunctive Schnorr/DLEQ Proof** that `V_{s,slot}`
//!      commits to a card `∈ {p_0, p_1, p_2}` AND that `(E_1, E_2)` validly ElGamal-encrypts that exact card
//!      under `prober.ed_pk` — hiding *which* of the 3 matched from all bystanders!
//! 4. **2-Party Co-Blinded 1-Bit `fileIndictment` + `coBlindIndictment`**:
//!    - Scales & re-randomizes the Fiat-Shamir Vault difference `Δ_0` by two independent non-zero scalars
//!      `ρ_A, ρ_B ∈ ℤ_ℓ^*` (`P = ρ * B != 𝒪`) before `vrf-beacon` zero-check decryption (`M == 𝒪`), so a
//!      refuted indictment leaks **strictly 0 bits** about partial card matches!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::bulletproofs::{
    self, BpCsBuilder, BP_H_BLIND_BYTES, WIRE_A_L, WIRE_A_O, WIRE_A_R, WIRE_VAR,
};
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::{keccak256, KeccakHasher};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage, vrf};

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

pub const SEAT_COUNT: usize = 5;
pub const DOSSIERS_PER_SEAT: usize = 3;
pub const HAND_POOL_COUNT: usize = SEAT_COUNT * DOSSIERS_PER_SEAT; // 15
pub const OPERATIVE_CARD_START: u8 = 0;
pub const OPERATIVE_CARD_END: u8 = 4; // 0..=4 (5 Operatives)
pub const EXPLOIT_CARD_START: u8 = 5;
pub const EXPLOIT_CARD_END: u8 = 9; // 5..=9 (5 Sabotage Exploits)
pub const SECTOR_CARD_START: u8 = 10;
pub const SECTOR_CARD_END: u8 = 17; // 10..=17 (8 Clearinghouse Sectors)
pub const TOTAL_DOSSIERS: usize = 18;

pub const PHASE_LOBBY: u8 = 1;
pub const PHASE_SHUFFLING: u8 = 2;
pub const PHASE_DEALING: u8 = 3;
pub const PHASE_ACTIVE: u8 = 4;
pub const PHASE_PROBE_PENDING: u8 = 5;
pub const PHASE_INDICTMENT_SHIELDING: u8 = 6;
pub const PHASE_INDICTMENT_DECRYPTING: u8 = 7;
pub const PHASE_UNVEILING_VAULT: u8 = 8;
pub const PHASE_SOLVED: u8 = 9;

pub const TURN_TIMEOUT_BLOCKS: u64 = 45;
pub const LOG_WINDOW: usize = 16;

/// Per-seat key & DDH/Pedersen blinding registration blob (`32 + 3 * 160 = 512` bytes).
pub const SEAT_KEY_BLOB_LEN: usize = 512;
/// AI filler seat record (`[seat_idx:1][eoa:20][identity:20][seat_key_blob:512] = 553` bytes).
pub const FILLER_SEAT_STRIDE: usize = 553;
/// `5 + 5 + 8 = 18`-card sub-deck ZK shuffle blob (`1152 + 576 + 672 + 1216 = 3616` bytes).
pub const SHUFFLE_18_BLOB_LEN: usize = 3616;
/// `15`-card cross-category hand pool ZK shuffle blob (`960 + 480 + 672 + 1024 = 3136` bytes).
pub const SHUFFLE_15_BLOB_LEN: usize = 3136;
/// `Bulletproofs` R1CS non-membership proof for `passAlibiCheck` (`n = 16` gates -> `672` bytes).
pub const PASS_R1CS_PROOF_LEN: usize = 672;
/// 1-of-3 Disjunctive Schnorr + ElGamal whisper proof (`64 + 9 * 32 = 352` bytes).
pub const WHISPER_PROOF_LEN: usize = 352;
/// Non-zero scalar ElGamal blinding proof for `fileIndictment` / `coBlindIndictment` (`64 + 32 + 96 = 192` bytes).
pub const INDICT_BLIND_BLOB_LEN: usize = 192;

/// Starting Facility Sectors for the 5 Operative Seats (`10..=17`).
pub const STARTING_SECTORS: [u8; SEAT_COUNT] = [10, 11, 13, 15, 17];

const REQ_KIND_DEAL_BATCH0: u8 = 1;
const REQ_KIND_DEAL_BATCH1: u8 = 2;
const REQ_KIND_INDICT_CHECK: u8 = 3;
const REQ_KIND_UNVEIL_VAULT: u8 = 4;

/// Check whether `to_sec` (`10..=17`) is reachable from `from_sec` (`10..=17`) on the `2x4`
/// Clearinghouse Blueprint (Manhattan distance `<= 2` OR Quantum Pneumatic Transit Tubes
/// `10 <-> 17` and `13 <-> 14`).
pub const fn is_sector_reachable(from_sec: u8, to_sec: u8, was_pulled: bool) -> bool {
    if from_sec < SECTOR_CARD_START || from_sec > SECTOR_CARD_END {
        return false;
    }
    if to_sec < SECTOR_CARD_START || to_sec > SECTOR_CARD_END {
        return false;
    }
    if from_sec == to_sec {
        return was_pulled;
    }
    if (from_sec == 10 && to_sec == 17)
        || (from_sec == 17 && to_sec == 10)
        || (from_sec == 13 && to_sec == 14)
        || (from_sec == 14 && to_sec == 13)
    {
        return true;
    }
    let idx_a = (from_sec - SECTOR_CARD_START) as i32;
    let idx_b = (to_sec - SECTOR_CARD_START) as i32;
    let ra = idx_a / 4;
    let ca = idx_a % 4;
    let rb = idx_b / 4;
    let cb = idx_b % 4;
    let dr = (ra - rb).abs();
    let dc = (ca - cb).abs();
    (dr + dc) <= 2
}

// ---------------------------------------------------------------------------
// Indexed Events
// ---------------------------------------------------------------------------

const EV_CASE_OPENED: [u8; 32] = event_topic("CaseOpened(bytes32,address,uint64)");
const EV_SEAT_CLAIMED: [u8; 32] = event_topic("SeatClaimed(bytes32,address,uint64,uint64)");
const EV_DECK_SHUFFLED: [u8; 32] = event_topic("DeckShuffled(bytes32,address,uint64)");
const EV_VAULT_SEALED: [u8; 32] = event_topic("VaultSealed(bytes32,bytes32,uint64)");
const EV_PROBE_SUBMITTED: [u8; 32] =
    event_topic("ProbeSubmitted(bytes32,uint64,uint64,uint64,uint64,uint64,uint64)");
const EV_ALIBI_PASSED: [u8; 32] = event_topic("AlibiPassed(bytes32,uint64,uint64,uint64)");
const EV_ALIBI_TRANSMITTED: [u8; 32] =
    event_topic("AlibiTransmitted(bytes32,uint64,uint64,uint64,bytes32,bytes32)");
const EV_INDICTMENT_FILED: [u8; 32] =
    event_topic("IndictmentFiled(bytes32,address,uint64,uint64,uint64,uint64)");
const EV_INDICTMENT_REFUTED: [u8; 32] =
    event_topic("IndictmentRefuted(bytes32,uint64,uint64)");
const EV_CASE_SOLVED: [u8; 32] =
    event_topic("CaseSolved(bytes32,address,uint64,uint64,uint64,uint64)");

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
    "initTribunal(address)"                                                       => handle_init_tribunal,
    "getVrfBeacon()"                                                              => handle_get_vrf_beacon,
    "getActiveCaseId()"                                                           => handle_get_active_case_id,
    "getOperativeWins(address)"                                                   => handle_get_operative_wins,
    "openCase(bytes32)"                                                           => handle_open_case,
    "claimOperativeSeat(bytes32,uint64,address,bytes)"                            => handle_claim_seat,
    "openAndClaimCase(bytes32,uint64,address,bytes,uint64,bytes)"                 => handle_open_and_claim,
    "requestVaultDeal(bytes32)"                                                   => handle_request_deal,
    "submitInitialShuffle(bytes32,bytes)"                                         => handle_submit_initial_shuffle,
    "coShuffleAndDeal(bytes32,bytes,bytes,bytes)"                                 => handle_coshuffle_and_deal,
    "submitForensicProbe(bytes32,uint64,uint64,uint64)"                           => handle_submit_probe,
    "passAlibiCheck(bytes32,bytes)"                                               => handle_pass_alibi,
    "transmitAlibiProof(bytes32,uint64,bytes)"                                    => handle_transmit_alibi,
    "fileIndictment(bytes32,uint64,uint64,uint64,bytes)"                          => handle_file_indictment,
    "coBlindIndictment(bytes32,bytes)"                                            => handle_coblind_indictment,
    "onHeDecryptionFulfilled(bytes32,bytes,uint64,uint64)"                        => handle_on_he_fulfilled,
    "advanceTimedOutTurn(bytes32)"                                                => handle_advance_timeout,
    "getCaseState(bytes32)"                                                       => handle_get_case_state,
    "getDeckCiphertexts(bytes32)"                                                 => handle_get_deck_ciphertexts,
    "getPendingIndictmentCiphertext(bytes32)"                                     => handle_get_pending_indict_ct,
}

// ---------------------------------------------------------------------------
// Persistent State Structures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CaseHeader {
    phase: u8,
    turn_seat: u8,
    responder_seat: u8,
    prober_seat: u8,
    probe_operative: u8,
    probe_exploit: u8,
    probe_sector: u8,
    indict_seat: u8,
    indict_operative: u8,
    indict_exploit: u8,
    indict_sector: u8,
    winner_seat: u8,
    sol_operative: u8,
    sol_exploit: u8,
    sol_sector: u8,
    deal_requested: u8,
    probe_count: u16,
    log_count: u16,
    deadline_block: u64,
    created_block: u32,
    epoch_id: u64,
    epoch_pk: [u8; 32],
    first_shuffler: [u8; 20],
    indict_eoa: [u8; 20],
    shuffle_count: u8,
    deal_fulfilled_mask: u8,
    vault_ciphertexts: [u8; 192],
}

const HDR_LEN: usize = 320;

impl CaseHeader {
    fn encode(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0] = self.phase;
        b[1] = self.turn_seat;
        b[2] = self.responder_seat;
        b[3] = self.prober_seat;
        b[4] = self.probe_operative;
        b[5] = self.probe_exploit;
        b[6] = self.probe_sector;
        b[7] = self.indict_seat;
        b[8] = self.indict_operative;
        b[9] = self.indict_exploit;
        b[10] = self.indict_sector;
        b[11] = self.winner_seat;
        b[12] = self.sol_operative;
        b[13] = self.sol_exploit;
        b[14] = self.sol_sector;
        b[15] = self.deal_requested;
        b[16..18].copy_from_slice(&self.probe_count.to_be_bytes());
        b[18..20].copy_from_slice(&self.log_count.to_be_bytes());
        b[20..28].copy_from_slice(&self.deadline_block.to_be_bytes());
        b[28..32].copy_from_slice(&self.created_block.to_be_bytes());
        b[32..40].copy_from_slice(&self.epoch_id.to_be_bytes());
        b[40..72].copy_from_slice(&self.epoch_pk);
        b[72..92].copy_from_slice(&self.first_shuffler);
        b[92..112].copy_from_slice(&self.indict_eoa);
        b[112] = self.shuffle_count;
        b[113] = self.deal_fulfilled_mask;
        b[128..320].copy_from_slice(&self.vault_ciphertexts);
        b
    }

    fn decode(b: &[u8; HDR_LEN]) -> Self {
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&b[40..72]);
        let mut fsh = [0u8; 20];
        fsh.copy_from_slice(&b[72..92]);
        let mut ieoa = [0u8; 20];
        ieoa.copy_from_slice(&b[92..112]);
        let mut vct = [0u8; 192];
        vct.copy_from_slice(&b[128..320]);
        Self {
            phase: b[0],
            turn_seat: b[1],
            responder_seat: b[2],
            prober_seat: b[3],
            probe_operative: b[4],
            probe_exploit: b[5],
            probe_sector: b[6],
            indict_seat: b[7],
            indict_operative: b[8],
            indict_exploit: b[9],
            indict_sector: b[10],
            winner_seat: b[11],
            sol_operative: b[12],
            sol_exploit: b[13],
            sol_sector: b[14],
            deal_requested: b[15],
            probe_count: u16::from_be_bytes([b[16], b[17]]),
            log_count: u16::from_be_bytes([b[18], b[19]]),
            deadline_block: u64::from_be_bytes(b[20..28].try_into().unwrap()),
            created_block: u32::from_be_bytes([b[28], b[29], b[30], b[31]]),
            epoch_id: u64::from_be_bytes(b[32..40].try_into().unwrap()),
            epoch_pk: epk,
            first_shuffler: fsh,
            indict_eoa: ieoa,
            shuffle_count: b[112],
            deal_fulfilled_mask: b[113],
            vault_ciphertexts: vct,
        }
    }
}

#[derive(Clone, Copy)]
struct SeatRec {
    occupied: u8, // 0=empty, 1=human, 2=AI
    revoked: u8,  // 1=indictment failed or timed out
    sector_id: u8,
    flags: u8, // bit 0 = pulled_by_probe
    eoa: [u8; 20],
    identity_addr: [u8; 20],
    ed_pk: [u8; 32],
    u_blinds: [[u8; 32]; DOSSIERS_PER_SEAT],
    /// Before `PHASE_ACTIVE`, holds `T_{s,k} = u_{s,k} * Y + w_{s,k} * H_bp`.
    /// Once `PHASE_ACTIVE` begins, holds `V_{s,k} = c_{s,k} * B + w_{s,k} * H_bp`.
    hand_commits: [[u8; 32]; DOSSIERS_PER_SEAT],
    /// DDH-blinded decrypted points `M'_{s,k} = c_{s,k} * B - u_{s,k} * Y`.
    blinded_decrypts: [[u8; 32]; DOSSIERS_PER_SEAT],
}

const SEAT_LEN: usize = 368;

impl SeatRec {
    fn empty(seat_idx: usize) -> Self {
        Self {
            occupied: 0,
            revoked: 0,
            sector_id: STARTING_SECTORS[seat_idx % SEAT_COUNT],
            flags: 0,
            eoa: [0u8; 20],
            identity_addr: [0u8; 20],
            ed_pk: [0u8; 32],
            u_blinds: [[0u8; 32]; DOSSIERS_PER_SEAT],
            hand_commits: [[0u8; 32]; DOSSIERS_PER_SEAT],
            blinded_decrypts: [[0u8; 32]; DOSSIERS_PER_SEAT],
        }
    }

    fn encode(&self) -> [u8; SEAT_LEN] {
        let mut b = [0u8; SEAT_LEN];
        b[0] = self.occupied;
        b[1] = self.revoked;
        b[2] = self.sector_id;
        b[3] = self.flags;
        b[4..24].copy_from_slice(&self.eoa);
        b[24..44].copy_from_slice(&self.identity_addr);
        b[44..76].copy_from_slice(&self.ed_pk);
        let mut k = 0;
        while k < DOSSIERS_PER_SEAT {
            b[76 + k * 32..76 + (k + 1) * 32].copy_from_slice(&self.u_blinds[k]);
            b[172 + k * 32..172 + (k + 1) * 32].copy_from_slice(&self.hand_commits[k]);
            b[268 + k * 32..268 + (k + 1) * 32].copy_from_slice(&self.blinded_decrypts[k]);
            k += 1;
        }
        b
    }

    fn decode(b: &[u8; SEAT_LEN]) -> Self {
        let mut eoa = [0u8; 20];
        eoa.copy_from_slice(&b[4..24]);
        let mut id = [0u8; 20];
        id.copy_from_slice(&b[24..44]);
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&b[44..76]);
        let mut ub = [[0u8; 32]; DOSSIERS_PER_SEAT];
        let mut hc = [[0u8; 32]; DOSSIERS_PER_SEAT];
        let mut bd = [[0u8; 32]; DOSSIERS_PER_SEAT];
        let mut k = 0;
        while k < DOSSIERS_PER_SEAT {
            ub[k].copy_from_slice(&b[76 + k * 32..76 + (k + 1) * 32]);
            hc[k].copy_from_slice(&b[172 + k * 32..172 + (k + 1) * 32]);
            bd[k].copy_from_slice(&b[268 + k * 32..268 + (k + 1) * 32]);
            k += 1;
        }
        Self {
            occupied: b[0],
            revoked: b[1],
            sector_id: b[2],
            flags: b[3],
            eoa,
            identity_addr: id,
            ed_pk: epk,
            u_blinds: ub,
            hand_commits: hc,
            blinded_decrypts: bd,
        }
    }
}

#[derive(Clone, Copy)]
struct ProbeLogEntry {
    probe_idx: u16,
    prober_seat: u8,
    operative: u8,
    exploit: u8,
    sector: u8,
    pass_mask: u8,
    disprover_seat: u8,
    disprover_slot: u8,
    status: u8, // 0=pending, 1=disproved via 1-of-3 ZK ElGamal whisper, 2=unrefuted around table
    whisper_ct: [u8; 64],
}

const LOG_ENTRY_LEN: usize = 74;

impl ProbeLogEntry {
    fn encode(&self) -> [u8; LOG_ENTRY_LEN] {
        let mut b = [0u8; LOG_ENTRY_LEN];
        b[0..2].copy_from_slice(&self.probe_idx.to_be_bytes());
        b[2] = self.prober_seat;
        b[3] = self.operative;
        b[4] = self.exploit;
        b[5] = self.sector;
        b[6] = self.pass_mask;
        b[7] = self.disprover_seat;
        b[8] = self.disprover_slot;
        b[9] = self.status;
        b[10..74].copy_from_slice(&self.whisper_ct);
        b
    }

    fn decode(b: &[u8; LOG_ENTRY_LEN]) -> Self {
        let mut w = [0u8; 64];
        w.copy_from_slice(&b[10..74]);
        Self {
            probe_idx: u16::from_be_bytes([b[0], b[1]]),
            prober_seat: b[2],
            operative: b[3],
            exploit: b[4],
            sector: b[5],
            pass_mask: b[6],
            disprover_seat: b[7],
            disprover_slot: b[8],
            status: b[9],
            whisper_ct: w,
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Keys & Helpers
// ---------------------------------------------------------------------------

const KEY_VRF_BEACON: &[u8] = b"n:vrf_beacon";
const KEY_INIT_ADMIN: &[u8] = b"n:init_admin";
const KEY_ACTIVE_CASE: &[u8] = b"n:active_case";

fn key_hdr(cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:hdr:").push(cid)
}

fn key_seat(cid: &[u8; 32], seat: u8) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:seat:").push(cid).push(&[seat])
}

fn key_log(cid: &[u8; 32], slot: u8) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:log:").push(cid).push(&[slot])
}

fn key_deck(cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:deck:").push(cid)
}

fn key_indict_ct(cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:ict:").push(cid)
}

fn key_dec_map(req_id: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:dreq:").push(req_id)
}

fn key_wins(addr: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:wins:").push(addr)
}

fn load_hdr(cid: &[u8; 32]) -> Option<CaseHeader> {
    let mut buf = [0u8; HDR_LEN];
    match storage::get_into(key_hdr(cid).as_slice(), &mut buf) {
        Some(HDR_LEN) => Some(CaseHeader::decode(&buf)),
        _ => None,
    }
}

fn save_hdr(cid: &[u8; 32], hdr: &CaseHeader) {
    storage::set(key_hdr(cid).as_slice(), &hdr.encode());
}

fn load_seat(cid: &[u8; 32], seat: u8) -> SeatRec {
    let mut buf = [0u8; SEAT_LEN];
    match storage::get_into(key_seat(cid, seat).as_slice(), &mut buf) {
        Some(SEAT_LEN) => SeatRec::decode(&buf),
        _ => SeatRec::empty(seat as usize),
    }
}

fn save_seat(cid: &[u8; 32], seat: u8, rec: &SeatRec) {
    storage::set(key_seat(cid, seat).as_slice(), &rec.encode());
}

fn load_log_slot(cid: &[u8; 32], probe_idx: u16) -> Option<ProbeLogEntry> {
    let slot = (probe_idx as usize % LOG_WINDOW) as u8;
    let mut buf = [0u8; LOG_ENTRY_LEN];
    match storage::get_into(key_log(cid, slot).as_slice(), &mut buf) {
        Some(LOG_ENTRY_LEN) => Some(ProbeLogEntry::decode(&buf)),
        _ => None,
    }
}

fn save_log_slot(cid: &[u8; 32], entry: &ProbeLogEntry) {
    let slot = (entry.probe_idx as usize % LOG_WINDOW) as u8;
    storage::set(key_log(cid, slot).as_slice(), &entry.encode());
}

fn next_active_turn_seat(cid: &[u8; 32], after_seat: u8) -> Option<u8> {
    let mut step = 1u8;
    while (step as usize) <= SEAT_COUNT {
        let cand = ((after_seat as usize + step as usize) % SEAT_COUNT) as u8;
        let s = load_seat(cid, cand);
        if s.occupied != 0 && s.revoked == 0 {
            return Some(cand);
        }
        step += 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Curve & Threshold Beacon Helpers
// ---------------------------------------------------------------------------

#[inline]
fn point_is_prime_order_non_identity(pt: &[u8; 32]) -> bool {
    if *pt == vrf::IDENTITY_POINT_BYTES || *pt == [0u8; 32] {
        return false;
    }
    let zero = [0u8; 32];
    match vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, pt, &zero, &vrf::IDENTITY_POINT_BYTES) {
        Some(chk) => chk == *pt,
        None => false,
    }
}

#[inline]
fn point_is_valid_or_identity(pt: &[u8; 32]) -> bool {
    let zero = [0u8; 32];
    match vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, pt, &zero, &vrf::IDENTITY_POINT_BYTES) {
        Some(chk) => chk == *pt,
        None => false,
    }
}

#[inline]
fn point_add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, a, &vrf::SCALAR_ONE_BYTES, b)
}

#[inline]
fn point_sub(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, a, &vrf::SCALAR_MINUS_ONE_BYTES, b)
}

#[inline]
fn card_basepoint(card_id: u8) -> Option<[u8; 32]> {
    let sc = bulletproofs::scalar_from_u64(card_id as u64);
    let zero = [0u8; 32];
    vrf::ec_elgamal_lincomb(
        &sc,
        &vrf::ED25519_BASEPOINT_BYTES,
        &zero,
        &vrf::IDENTITY_POINT_BYTES,
    )
}

fn query_beacon_active_epoch() -> Result<([u8; 20], u64, [u8; 32]), i32> {
    let beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-14)?;
    if beacon == [0u8; 20] {
        return Err(-14);
    }
    let cd = CallEncoder::<16>::new(const { selector("getActiveEpochKey()") });
    let raw = call::call_raw(&beacon, cd.as_slice()).map_err(|_| -21)?;
    if raw.len() < 48 {
        return Err(-21);
    }
    let mut snap = [0u8; 48];
    snap.copy_from_slice(&raw[0..48]);
    let epoch_id = u64::from_be_bytes(snap[0..8].try_into().unwrap());
    let mut epoch_pk = [0u8; 32];
    epoch_pk.copy_from_slice(&snap[16..48]);
    if epoch_id == 0 || !point_is_prime_order_non_identity(&epoch_pk) {
        return Err(-21);
    }
    Ok((beacon, epoch_id, epoch_pk))
}

fn request_beacon_decryption(
    beacon: &[u8; 20],
    epoch_id: u64,
    ciphertexts: &[u8],
    max_val: u64,
) -> Result<[u8; 32], i32> {
    let cd = CallEncoder::<768>::new(const {
        selector("requestThresholdDecryption(uint64,bytes,uint64,uint64)")
    })
    .push_u64(epoch_id)
    .push_u64(128)
    .push_u64(max_val)
    .push_u64(1)
    .push_dynamic_bytes_tail(ciphertexts);

    let raw = call::call_raw(beacon, cd.as_slice()).map_err(|_| -27)?;
    if raw.len() < 32 {
        return Err(-27);
    }
    let mut req_id = [0u8; 32];
    req_id.copy_from_slice(&raw[0..32]);
    Ok(req_id)
}

fn canonical_initial_deck() -> [u8; TOTAL_DOSSIERS * 64] {
    let mut out = [0u8; TOTAL_DOSSIERS * 64];
    let mut i = 0usize;
    while i < TOTAL_DOSSIERS {
        out[i * 64..i * 64 + 32].copy_from_slice(&vrf::IDENTITY_POINT_BYTES);
        let c2 = card_basepoint(i as u8).unwrap_or(vrf::IDENTITY_POINT_BYTES);
        out[i * 64 + 32..(i + 1) * 64].copy_from_slice(&c2);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Zero-Knowledge Verification Routines
// ---------------------------------------------------------------------------

/// Validates `seat_key_blob` (`512` B):
/// - `0..32`: `ed_pk` (non-identity prime-order `Edwards25519` point)
/// - `32 + k * 160` (`k = 0..2`): `[U_k:32][T_k:32][c:32][zu:32][zw:32]`
///   proving `U_k = u_k * B` (`u_k != 0`) AND `T_k = u_k * epoch_pk + w_k * H_bp`.
fn parse_and_verify_seat_keys(
    cid: &[u8; 32],
    seat_eoa: &[u8; 20],
    epoch_pk: &[u8; 32],
    blob: &[u8],
) -> Result<([u8; 32], [[u8; 32]; 3], [[u8; 32]; 3]), i32> {
    if blob.len() != SEAT_KEY_BLOB_LEN {
        return Err(-15);
    }
    let mut ed_pk = [0u8; 32];
    ed_pk.copy_from_slice(&blob[0..32]);
    if !point_is_prime_order_non_identity(&ed_pk) {
        return Err(-15);
    }

    let mut u_arr = [[0u8; 32]; 3];
    let mut t_arr = [[0u8; 32]; 3];
    let mut k = 0usize;
    while k < DOSSIERS_PER_SEAT {
        let base = 32 + k * 160;
        let mut u_k = [0u8; 32];
        let mut t_k = [0u8; 32];
        let mut c_sc = [0u8; 32];
        let mut zu_sc = [0u8; 32];
        let mut zw_sc = [0u8; 32];
        u_k.copy_from_slice(&blob[base..base + 32]);
        t_k.copy_from_slice(&blob[base + 32..base + 64]);
        c_sc.copy_from_slice(&blob[base + 64..base + 96]);
        zu_sc.copy_from_slice(&blob[base + 96..base + 128]);
        zw_sc.copy_from_slice(&blob[base + 128..base + 160]);

        if !point_is_prime_order_non_identity(&u_k)
            || !point_is_valid_or_identity(&t_k)
            || !bulletproofs::scalar_is_canonical(&c_sc)
            || !bulletproofs::scalar_is_canonical(&zu_sc)
            || !bulletproofs::scalar_is_canonical(&zw_sc)
        {
            return Err(-15);
        }

        let neg_c = bulletproofs::scalar_neg(&c_sc);
        // R_U = zu * B - c * U_k
        let r_u = vrf::ec_elgamal_lincomb(&zu_sc, &vrf::ED25519_BASEPOINT_BYTES, &neg_c, &u_k)
            .ok_or(-15)?;
        // R_T = (zu * epoch_pk + zw * H_bp) - c * T_k
        let zu_y_zw_h =
            vrf::ec_elgamal_lincomb(&zu_sc, epoch_pk, &zw_sc, &BP_H_BLIND_BYTES).ok_or(-15)?;
        let r_t =
            vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &zu_y_zw_h, &neg_c, &t_k).ok_or(-15)?;

        let mut kh = KeccakHasher::new();
        kh.update(b"NOIR_SLOT_POK_V1");
        kh.update(cid);
        kh.update(seat_eoa);
        kh.update(&[k as u8]);
        kh.update(epoch_pk);
        kh.update(&ed_pk);
        kh.update(&u_k);
        kh.update(&t_k);
        kh.update(&r_u);
        kh.update(&r_t);
        let exp_c = bulletproofs::scalar_from_hash_nonzero(&kh.finalize());
        if c_sc != exp_c {
            return Err(-15);
        }

        u_arr[k] = u_k;
        t_arr[k] = t_k;
        k += 1;
    }

    Ok((ed_pk, u_arr, t_arr))
}

/// Verifies an `M`-card ElGamal shuffle (`subdecks` inside `0..M`) via 2-challenge Grand-Product
/// Bulletproofs R1CS (`16` gates: `∏(s_c - β) == ∏(α^{r+1} - β)`) + ElGamal linear-combination Schnorr proof.
fn verify_shuffle_step<'a>(
    cid: &[u8; 32],
    step_tag: u8,
    epoch_pk: &[u8; 32],
    subdecks: &[(usize, usize)],
    total_cards: usize,
    in_cts: &[u8],
    blob: &'a [u8],
) -> Result<&'a [u8], i32> {
    const N_GATES: usize = 16;
    let ct_bytes = total_cards * 64;
    let s_comm_bytes = total_cards * 32;
    let r1cs_bytes = PASS_R1CS_PROOF_LEN; // (13 + 2 * log2(16)) * 32 = 672 bytes
    let lin_bytes = (2 + 2 * total_cards) * 32;
    if in_cts.len() != ct_bytes || blob.len() != ct_bytes + s_comm_bytes + r1cs_bytes + lin_bytes {
        return Err(-20);
    }

    let out_cts = &blob[0..ct_bytes];
    let s_comm_raw = &blob[ct_bytes..ct_bytes + s_comm_bytes];
    let r1cs_proof = &blob[ct_bytes + s_comm_bytes..ct_bytes + s_comm_bytes + r1cs_bytes];
    let lin_pok = &blob[ct_bytes + s_comm_bytes + r1cs_bytes..];

    // 1. Check no `C_1` is the identity/zero point (full torsion-free decoding of all `o1, o2`
    //    is enforced by `ec_elgamal_lincomb` when computing `L_1, L_2` below).
    let mut j = 0usize;
    while j < total_cards {
        let c1 = &out_cts[j * 64..j * 64 + 32];
        if c1 == vrf::IDENTITY_POINT_BYTES || c1 == [0u8; 32] {
            return Err(-22);
        }
        j += 1;
    }

    // 2. Derive Schwartz-Zippel challenge `alpha` strictly BEFORE reading `s_commits`
    let mut ah = KeccakHasher::new();
    ah.update(b"NOIR_SHUF_ALPHA_V1");
    ah.update(cid);
    ah.update(&[step_tag]);
    ah.update(epoch_pk);
    ah.update(in_cts);
    ah.update(out_cts);
    let alpha = bulletproofs::scalar_from_hash_nonzero(&ah.finalize());

    let mut alpha_pows = [[0u8; 32]; TOTAL_DOSSIERS];
    alpha_pows[0] = alpha;
    let mut p = 1usize;
    while p < total_cards {
        alpha_pows[p] = bulletproofs::scalar_mul(&alpha_pows[p - 1], &alpha);
        p += 1;
    }

    let mut s_commits = [[0u8; 32]; TOTAL_DOSSIERS];
    let mut i = 0usize;
    while i < total_cards {
        s_commits[i].copy_from_slice(&s_comm_raw[i * 32..(i + 1) * 32]);
        i += 1;
    }

    // 3. Derive Grand-Product root challenge `beta` AFTER `s_commits` are bound!
    let mut bh = KeccakHasher::new();
    bh.update(b"NOIR_SHUF_BETA_V1");
    bh.update(cid);
    bh.update(&[step_tag]);
    bh.update(&alpha);
    bh.update(s_comm_raw);
    let beta = bulletproofs::scalar_from_hash_nonzero(&bh.finalize());
    let neg_beta = bulletproofs::scalar_neg(&beta);

    // 4. Build 16-gate Grand-Product R1CS: for each subdeck `(start_idx, len)` (`len >= 2`),
    //    `∏_{c=0}^{len-1} (v_{start+c} - beta) == ∏_{r=0}^{len-1} (alpha^{start+r+1} - beta)`
    let mut cs = BpCsBuilder::<4096>::new(N_GATES as u16, total_cards as u16);
    let zero = [0u8; 32];
    let one = bulletproofs::scalar_from_u64(1);
    let minus_one = bulletproofs::scalar_neg_u64(1);

    let mut gate_cursor = 0u16;
    let mut sd_idx = 0usize;
    while sd_idx < subdecks.len() {
        let (start_idx, len) = subdecks[sd_idx];
        // Compute public expected grand product `k_prod = ∏_{r=0}^{len-1} (alpha_pows[start+r] - beta)`
        let mut k_prod = bulletproofs::scalar_sub(&alpha_pows[start_idx], &beta);
        let mut r = 1usize;
        while r < len {
            let term = bulletproofs::scalar_sub(&alpha_pows[start_idx + r], &beta);
            k_prod = bulletproofs::scalar_mul(&k_prod, &term);
            r += 1;
        }

        // First gate of subdeck: `(v_{start} - beta) * (v_{start+1} - beta) = a_O[gate_cursor]`
        cs.begin_constraint(&neg_beta);
        cs.push_term(WIRE_A_L, gate_cursor, &one);
        cs.push_term(WIRE_VAR, start_idx as u16, &minus_one);

        cs.begin_constraint(&neg_beta);
        cs.push_term(WIRE_A_R, gate_cursor, &one);
        cs.push_term(WIRE_VAR, (start_idx + 1) as u16, &minus_one);

        let mut step = 1usize;
        while step < len - 1 {
            let g = gate_cursor + (step as u16);
            cs.begin_constraint(&zero);
            cs.push_term(WIRE_A_L, g, &one);
            cs.push_term(WIRE_A_O, g - 1, &minus_one);

            cs.begin_constraint(&neg_beta);
            cs.push_term(WIRE_A_R, g, &one);
            cs.push_term(WIRE_VAR, (start_idx + step + 1) as u16, &minus_one);
            step += 1;
        }

        let last_g = gate_cursor + ((len - 2) as u16);
        cs.begin_constraint(&k_prod);
        cs.push_term(WIRE_A_O, last_g, &one);

        gate_cursor += (len - 1) as u16;
        sd_idx += 1;
    }

    let cs_slice = cs.as_slice().ok_or(-23)?;
    let mut r1cs_ctx = [0u8; 17 + 32 + 1 + 64];
    r1cs_ctx[0..17].copy_from_slice(b"NOIR_SHUF_R1CS_V1");
    r1cs_ctx[17..49].copy_from_slice(cid);
    r1cs_ctx[49] = step_tag;
    r1cs_ctx[50..82].copy_from_slice(&alpha);
    r1cs_ctx[82..114].copy_from_slice(&beta);

    if !bulletproofs::verify_r1cs(cs_slice, &s_commits[..total_cards], &r1cs_ctx, r1cs_proof) {
        return Err(-24); // Forged deck permutation rejected by Bulletproofs R1CS!
    }

    // 4. Verify Schwartz-Zippel ElGamal linear-combination Schnorr proof:
    //    `L = sum_j alpha^{j+1} * Out_j == sum_i s_i * In_i + (r_tot * B, r_tot * Y)`
    let mut l1 = vrf::IDENTITY_POINT_BYTES;
    let mut l2 = vrf::IDENTITY_POINT_BYTES;
    j = 0;
    while j < total_cards {
        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        o1.copy_from_slice(&out_cts[j * 64..j * 64 + 32]);
        o2.copy_from_slice(&out_cts[j * 64 + 32..(j + 1) * 64]);
        l1 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &l1, &alpha_pows[j], &o1)
            .ok_or(-25)?;
        l2 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &l2, &alpha_pows[j], &o2)
            .ok_or(-25)?;
        j += 1;
    }

    let mut c_sc = [0u8; 32];
    c_sc.copy_from_slice(&lin_pok[0..32]);
    if !bulletproofs::scalar_is_canonical(&c_sc) {
        return Err(-25);
    }
    let neg_c = bulletproofs::scalar_neg(&c_sc);

    let mut z_r = [0u8; 32];
    z_r.copy_from_slice(&lin_pok[(1 + 2 * total_cards) * 32..(2 + 2 * total_cards) * 32]);
    if !bulletproofs::scalar_is_canonical(&z_r) {
        return Err(-25);
    }

    let mut r_1_acc = vrf::ec_elgamal_lincomb(
        &z_r,
        &vrf::ED25519_BASEPOINT_BYTES,
        &neg_c,
        &l1,
    )
    .ok_or(-25)?;
    let mut r_2_acc =
        vrf::ec_elgamal_lincomb(&z_r, epoch_pk, &neg_c, &l2).ok_or(-25)?;

    let mut lh = KeccakHasher::new();
    lh.update(b"NOIR_SHUF_LIN_V1");
    lh.update(cid);
    lh.update(&[step_tag]);
    lh.update(&alpha);
    lh.update(&l1);
    lh.update(&l2);
    lh.update(s_comm_raw);

    i = 0;
    while i < total_cards {
        let mut zs_i = [0u8; 32];
        let mut zg_i = [0u8; 32];
        zs_i.copy_from_slice(&lin_pok[(1 + i) * 32..(2 + i) * 32]);
        zg_i.copy_from_slice(&lin_pok[(1 + total_cards + i) * 32..(2 + total_cards + i) * 32]);
        if !bulletproofs::scalar_is_canonical(&zs_i) || !bulletproofs::scalar_is_canonical(&zg_i)
        {
            return Err(-25);
        }

        // R_S[i] = (zs_i * B + zg_i * H_bp) - c * S_i
        let zs_b_zg_h = vrf::ec_elgamal_lincomb(
            &zs_i,
            &vrf::ED25519_BASEPOINT_BYTES,
            &zg_i,
            &BP_H_BLIND_BYTES,
        )
        .ok_or(-25)?;
        let r_s_i = vrf::ec_elgamal_lincomb(
            &vrf::SCALAR_ONE_BYTES,
            &zs_b_zg_h,
            &neg_c,
            &s_commits[i],
        )
        .ok_or(-25)?;
        lh.update(&r_s_i);

        let mut in1 = [0u8; 32];
        let mut in2 = [0u8; 32];
        in1.copy_from_slice(&in_cts[i * 64..i * 64 + 32]);
        in2.copy_from_slice(&in_cts[i * 64 + 32..(i + 1) * 64]);
        r_1_acc = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &r_1_acc, &zs_i, &in1)
            .ok_or(-25)?;
        r_2_acc = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &r_2_acc, &zs_i, &in2)
            .ok_or(-25)?;
        i += 1;
    }

    lh.update(&r_1_acc);
    lh.update(&r_2_acc);
    let exp_c = bulletproofs::scalar_from_hash_nonzero(&lh.finalize());
    if c_sc != exp_c {
        return Err(-25); // ElGamal ciphertext re-randomization mismatch rejected!
    }

    Ok(out_cts)
}

/// Verifies `passAlibiCheck`'s 672-byte Bulletproofs R1CS proof (`16` gates) that none of
/// Responder's 3 committed cards `hand_commits[0..3]` equals `(p0, p1, p2)`.
fn verify_pass_alibi_r1cs(
    cid: &[u8; 32],
    probe_idx: u16,
    responder_seat: u8,
    hand_commits: &[[u8; 32]; 3],
    probes: [u8; 3],
    proof: &[u8],
) -> bool {
    if proof.len() != PASS_R1CS_PROOF_LEN {
        return false;
    }
    let mut cs = BpCsBuilder::<4096>::new(16, 3);
    let zero = [0u8; 32];
    let one = bulletproofs::scalar_from_u64(1);
    let minus_one = bulletproofs::scalar_neg_u64(1);

    // Gate 0: (v_0 - p_0) * (v_0 - p_1) = a_O[0]
    cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[0] as u64));
    cs.push_term(WIRE_A_L, 0, &one);
    cs.push_term(WIRE_VAR, 0, &minus_one);

    cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[1] as u64));
    cs.push_term(WIRE_A_R, 0, &one);
    cs.push_term(WIRE_VAR, 0, &minus_one);

    let mut t = 1u16;
    while t <= 7 {
        let factor_idx = (t + 1) as usize;
        let k = (factor_idx / 3) as u16;
        let m = factor_idx % 3;

        cs.begin_constraint(&zero);
        cs.push_term(WIRE_A_L, t, &one);
        cs.push_term(WIRE_A_O, t - 1, &minus_one);

        cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[m] as u64));
        cs.push_term(WIRE_A_R, t, &one);
        cs.push_term(WIRE_VAR, k, &minus_one);
        t += 1;
    }

    // Gate 8: a_O[7] * inv == 1
    cs.begin_constraint(&zero);
    cs.push_term(WIRE_A_L, 8, &one);
    cs.push_term(WIRE_A_O, 7, &minus_one);

    cs.begin_constraint(&one);
    cs.push_term(WIRE_A_O, 8, &one);

    let Some(cs_bytes) = cs.as_slice() else {
        return false;
    };

    let mut ctx = [0u8; 16 + 32 + 2 + 1 + 3];
    ctx[0..16].copy_from_slice(b"NOIR_PASS_R1CS_1");
    ctx[16..48].copy_from_slice(cid);
    ctx[48..50].copy_from_slice(&probe_idx.to_be_bytes());
    ctx[50] = responder_seat;
    ctx[51..54].copy_from_slice(&probes);

    bulletproofs::verify_r1cs(cs_bytes, hand_commits, &ctx, proof)
}

/// Verifies `transmitAlibiProof`'s 352-byte 1-of-3 CDS Sigma OR-proof + ElGamal whisper ciphertext:
/// `[E_1:32][E_2:32][branch_0..2: 3 * (c_j:32 || zw_j:32 || zr_j:32)]`.
fn verify_whisper_or3(
    cid: &[u8; 32],
    probe_idx: u16,
    responder_seat: u8,
    prober_seat: u8,
    slot_idx: u8,
    v_commit: &[u8; 32],
    prober_pk: &[u8; 32],
    probes: [u8; 3],
    proof_blob: &[u8],
) -> Option<[u8; 64]> {
    if proof_blob.len() != WHISPER_PROOF_LEN {
        return None;
    }
    let mut e1 = [0u8; 32];
    let mut e2 = [0u8; 32];
    e1.copy_from_slice(&proof_blob[0..32]);
    e2.copy_from_slice(&proof_blob[32..64]);
    if !point_is_prime_order_non_identity(&e1) || !point_is_valid_or_identity(&e2) {
        return None;
    }

    let mut c_sum = [0u8; 32];
    let mut kh = KeccakHasher::new();
    kh.update(b"NOIR_WHISPER_OR3_V1");
    kh.update(cid);
    kh.update(&probe_idx.to_be_bytes());
    kh.update(&[responder_seat, prober_seat, slot_idx]);
    kh.update(v_commit);
    kh.update(prober_pk);
    kh.update(&e1);
    kh.update(&e2);
    kh.update(&probes);

    let mut m = 0usize;
    while m < 3 {
        let off = 64 + m * 96;
        let mut cj = [0u8; 32];
        let mut zwj = [0u8; 32];
        let mut zrj = [0u8; 32];
        cj.copy_from_slice(&proof_blob[off..off + 32]);
        zwj.copy_from_slice(&proof_blob[off + 32..off + 64]);
        zrj.copy_from_slice(&proof_blob[off + 64..off + 96]);
        if !bulletproofs::scalar_is_canonical(&cj)
            || !bulletproofs::scalar_is_canonical(&zwj)
            || !bulletproofs::scalar_is_canonical(&zrj)
        {
            return None;
        }
        c_sum = bulletproofs::scalar_add(&c_sum, &cj);
        let neg_cj = bulletproofs::scalar_neg(&cj);

        let pm_pt = card_basepoint(probes[m])?;
        let v_minus_pm = point_sub(v_commit, &pm_pt)?;
        let e2_minus_pm = point_sub(&e2, &pm_pt)?;

        // R_V = zw_j * H_bp - c_j * (V - p_m * B)
        let r_v = vrf::ec_elgamal_lincomb(&zwj, &BP_H_BLIND_BYTES, &neg_cj, &v_minus_pm)?;
        // R_1 = zr_j * B - c_j * E_1
        let r_1 = vrf::ec_elgamal_lincomb(&zrj, &vrf::ED25519_BASEPOINT_BYTES, &neg_cj, &e1)?;
        // R_2 = zr_j * PK_p - c_j * (E_2 - p_m * B)
        let r_2 = vrf::ec_elgamal_lincomb(&zrj, prober_pk, &neg_cj, &e2_minus_pm)?;

        kh.update(&r_v);
        kh.update(&r_1);
        kh.update(&r_2);
        m += 1;
    }

    let c_tot = bulletproofs::scalar_from_hash_nonzero(&kh.finalize());
    if c_sum != c_tot {
        return None;
    }

    let mut ct = [0u8; 64];
    ct.copy_from_slice(&proof_blob[0..64]);
    Some(ct)
}

/// Computes the deterministic Fiat-Shamir Vault difference ciphertext `Δ_0` for indictment `(op, exp, sec)`.
fn compute_indictment_delta0(
    cid: &[u8; 32],
    vault_cts: &[u8; 192],
    guesses: [u8; 3],
) -> Option<[u8; 64]> {
    let mut kh1 = KeccakHasher::new();
    kh1.update(b"NOIR_INDICT_MIX1_V1");
    kh1.update(cid);
    kh1.update(&guesses);
    kh1.update(vault_cts);
    let lam1 = bulletproofs::scalar_from_hash_nonzero(&kh1.finalize());

    let mut kh2 = KeccakHasher::new();
    kh2.update(b"NOIR_INDICT_MIX2_V1");
    kh2.update(cid);
    kh2.update(&guesses);
    kh2.update(vault_cts);
    let lam2 = bulletproofs::scalar_from_hash_nonzero(&kh2.finalize());

    let weights = [vrf::SCALAR_ONE_BYTES, lam1, lam2];
    let mut acc1 = vrf::IDENTITY_POINT_BYTES;
    let mut acc2 = vrf::IDENTITY_POINT_BYTES;
    let mut m = 0usize;
    while m < 3 {
        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];
        c1.copy_from_slice(&vault_cts[m * 64..m * 64 + 32]);
        c2.copy_from_slice(&vault_cts[m * 64 + 32..(m + 1) * 64]);
        let gm_pt = card_basepoint(guesses[m])?;
        let d2 = point_sub(&c2, &gm_pt)?;
        acc1 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &acc1, &weights[m], &c1)?;
        acc2 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &acc2, &weights[m], &d2)?;
        m += 1;
    }

    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&acc1);
    out[32..64].copy_from_slice(&acc2);
    Some(out)
}

/// Verifies non-zero scalar blinding `Δ_out = ρ * Δ_in + (r * B, r * epoch_pk)` (`ρ != 0` enforced by `P_ρ = ρ * B != 𝒪`).
/// `blob` (`192` B): `[Delta_out:64][P_rho:32][c:32][z_rho:32][z_r:32]`.
fn verify_indictment_blinding(
    cid: &[u8; 32],
    step_tag: u8,
    epoch_pk: &[u8; 32],
    delta_in: &[u8; 64],
    blob: &[u8],
) -> Option<[u8; 64]> {
    if blob.len() != INDICT_BLIND_BLOB_LEN {
        return None;
    }
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    let mut p_rho = [0u8; 32];
    let mut c_sc = [0u8; 32];
    let mut z_rho = [0u8; 32];
    let mut z_r = [0u8; 32];
    out1.copy_from_slice(&blob[0..32]);
    out2.copy_from_slice(&blob[32..64]);
    p_rho.copy_from_slice(&blob[64..96]);
    c_sc.copy_from_slice(&blob[96..128]);
    z_rho.copy_from_slice(&blob[128..160]);
    z_r.copy_from_slice(&blob[160..192]);

    // `p_rho` MUST be prime-order NON-IDENTITY, making `rho == 0` impossible!
    if !point_is_prime_order_non_identity(&p_rho)
        || !point_is_valid_or_identity(&out1)
        || !point_is_valid_or_identity(&out2)
        || !bulletproofs::scalar_is_canonical(&c_sc)
        || !bulletproofs::scalar_is_canonical(&z_rho)
        || !bulletproofs::scalar_is_canonical(&z_r)
    {
        return None;
    }

    let mut in1 = [0u8; 32];
    let mut in2 = [0u8; 32];
    in1.copy_from_slice(&delta_in[0..32]);
    in2.copy_from_slice(&delta_in[32..64]);

    let neg_c = bulletproofs::scalar_neg(&c_sc);
    // R_P = z_rho * B - c * P_rho
    let r_p = vrf::ec_elgamal_lincomb(&z_rho, &vrf::ED25519_BASEPOINT_BYTES, &neg_c, &p_rho)?;
    // R_1 = (z_rho * in1 + z_r * B) - c * out1
    let t1 = vrf::ec_elgamal_lincomb(&z_rho, &in1, &z_r, &vrf::ED25519_BASEPOINT_BYTES)?;
    let r_1 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &t1, &neg_c, &out1)?;
    // R_2 = (z_rho * in2 + z_r * Y) - c * out2
    let t2 = vrf::ec_elgamal_lincomb(&z_rho, &in2, &z_r, epoch_pk)?;
    let r_2 = vrf::ec_elgamal_lincomb(&vrf::SCALAR_ONE_BYTES, &t2, &neg_c, &out2)?;

    let mut kh = KeccakHasher::new();
    kh.update(b"NOIR_INDICT_BLIND_V1");
    kh.update(cid);
    kh.update(&[step_tag]);
    kh.update(epoch_pk);
    kh.update(delta_in);
    kh.update(&out1);
    kh.update(&out2);
    kh.update(&p_rho);
    kh.update(&r_p);
    kh.update(&r_1);
    kh.update(&r_2);
    let exp_c = bulletproofs::scalar_from_hash_nonzero(&kh.finalize());
    if c_sc != exp_c {
        return None;
    }

    let mut out = [0u8; 64];
    out.copy_from_slice(&blob[0..64]);
    Some(out)
}

// ---------------------------------------------------------------------------
// Entrypoint Implementations
// ---------------------------------------------------------------------------

fn handle_init_tribunal(args: &CalldataReader) -> Result<i32, i32> {
    let beacon = args.address(0).ok_or(-10)?;
    if beacon == [0u8; 20] {
        return Err(-11);
    }
    let caller = context::msg_sender();
    if let Some(admin) = storage::get_address(KEY_INIT_ADMIN) {
        if admin != [0u8; 20] && caller != admin {
            return Err(-12);
        }
    } else {
        storage::set_address(KEY_INIT_ADMIN, &caller);
    }
    storage::set_address(KEY_VRF_BEACON, &beacon);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_get_vrf_beacon(_args: &CalldataReader) -> Result<i32, i32> {
    let beacon = storage::get_address(KEY_VRF_BEACON).unwrap_or([0u8; 20]);
    ret::write_address(&beacon);
    Ok(32)
}

fn handle_get_active_case_id(_args: &CalldataReader) -> Result<i32, i32> {
    let cid = storage::get_bytes32(KEY_ACTIVE_CASE).unwrap_or([0u8; 32]);
    ret::write_word(&cid);
    Ok(32)
}

fn handle_get_operative_wins(args: &CalldataReader) -> Result<i32, i32> {
    let addr = args.address(0).ok_or(-10)?;
    let w = storage::get_u64(key_wins(&addr).as_slice());
    ret::write_u64_word(w);
    Ok(32)
}

fn open_case_internal(cid: &[u8; 32]) -> Result<CaseHeader, i32> {
    if *cid == [0u8; 32] {
        return Err(-11);
    }
    if load_hdr(cid).is_some() {
        return Err(-13);
    }
    let (_beacon, epoch_id, epoch_pk) = query_beacon_active_epoch()?;
    let blk = context::block_number();
    let hdr = CaseHeader {
        phase: PHASE_LOBBY,
        turn_seat: 0,
        responder_seat: 255,
        prober_seat: 255,
        probe_operative: 255,
        probe_exploit: 255,
        probe_sector: 255,
        indict_seat: 255,
        indict_operative: 255,
        indict_exploit: 255,
        indict_sector: 255,
        winner_seat: 255,
        sol_operative: 255,
        sol_exploit: 255,
        sol_sector: 255,
        deal_requested: 0,
        probe_count: 0,
        log_count: 0,
        deadline_block: blk.saturating_add(TURN_TIMEOUT_BLOCKS),
        created_block: blk as u32,
        epoch_id,
        epoch_pk,
        first_shuffler: [0u8; 20],
        indict_eoa: [0u8; 20],
        shuffle_count: 0,
        deal_fulfilled_mask: 0,
        vault_ciphertexts: [0u8; 192],
    };
    save_hdr(cid, &hdr);
    let mut s = 0;
    while s < SEAT_COUNT {
        save_seat(cid, s as u8, &SeatRec::empty(s));
        s += 1;
    }
    storage::set(KEY_ACTIVE_CASE, cid);

    let caller = context::msg_sender();
    let mut ev = [0u8; 32];
    push_u64_word(&mut ev, 0, epoch_id);
    events::emit(&[EV_CASE_OPENED, *cid, addr_topic(&caller)], &ev);
    Ok(hdr)
}

fn handle_open_case(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    open_case_internal(&cid)?;
    ret::write_u64_word(1);
    Ok(32)
}

fn claim_seat_internal(
    cid: &[u8; 32],
    hdr: &mut CaseHeader,
    caller: [u8; 20],
    preferred: u64,
    identity_addr: [u8; 20],
    seat_key_blob: &[u8],
    deal_now: bool,
) -> Result<u8, i32> {
    if hdr.phase != PHASE_LOBBY && hdr.phase != PHASE_SHUFFLING {
        return Err(-17);
    }
    let (ed_pk, u_arr, t_arr) =
        parse_and_verify_seat_keys(cid, &caller, &hdr.epoch_pk, seat_key_blob)?;

    let mut existing = None;
    let mut i = 0;
    while i < SEAT_COUNT {
        let s = load_seat(cid, i as u8);
        if s.occupied != 0 && s.eoa == caller {
            existing = Some(i as u8);
            break;
        }
        i += 1;
    }

    let chosen = if let Some(seat_idx) = existing {
        seat_idx
    } else {
        let mut pick = None;
        if (preferred as usize) < SEAT_COUNT {
            let sp = load_seat(cid, preferred as u8);
            if sp.occupied == 0 {
                pick = Some(preferred as u8);
            }
        }
        if pick.is_none() {
            let mut j = 0;
            while j < SEAT_COUNT {
                let sj = load_seat(cid, j as u8);
                if sj.occupied == 0 {
                    pick = Some(j as u8);
                    break;
                }
                j += 1;
            }
        }
        pick.ok_or(-18)?
    };

    let mut rec = load_seat(cid, chosen);
    rec.occupied = 1;
    rec.revoked = 0;
    rec.sector_id = STARTING_SECTORS[chosen as usize];
    rec.flags = 0;
    rec.eoa = caller;
    rec.identity_addr = identity_addr;
    rec.ed_pk = ed_pk;
    rec.u_blinds = u_arr;
    rec.hand_commits = t_arr;
    save_seat(cid, chosen, &rec);

    if deal_now {
        hdr.deal_requested = 1;
    }
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(cid, hdr);

    let mut ev = [0u8; 64];
    push_u64_word(&mut ev, 0, chosen as u64);
    push_u64_word(&mut ev, 1, hdr.deal_requested as u64);
    events::emit(&[EV_SEAT_CLAIMED, *cid, addr_topic(&caller)], &ev);

    Ok(chosen)
}

fn apply_initial_shuffle_internal(
    cid: &[u8; 32],
    hdr: &mut CaseHeader,
    caller: [u8; 20],
    shuffle1_blob: &[u8],
) -> Result<(), i32> {
    if hdr.phase != PHASE_LOBBY {
        return Err(-17);
    }
    let canon_deck = canonical_initial_deck();
    let subdecks = [(0usize, 5usize), (5, 5), (10, 8)];
    let out_cts = verify_shuffle_step(
        cid,
        1,
        &hdr.epoch_pk,
        &subdecks,
        TOTAL_DOSSIERS,
        &canon_deck,
        shuffle1_blob,
    )?;

    storage::set(key_deck(cid).as_slice(), out_cts);
    hdr.phase = PHASE_SHUFFLING;
    hdr.first_shuffler = caller;
    hdr.shuffle_count = 1;
    hdr.deal_requested = 1;
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(cid, hdr);

    let mut ev = [0u8; 32];
    push_u64_word(&mut ev, 0, 1);
    events::emit(&[EV_DECK_SHUFFLED, *cid, addr_topic(&caller)], &ev);
    Ok(())
}

fn handle_claim_seat(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let pref = args.u64(1).ok_or(-10)?;
    let id_addr = args.address(2).ok_or(-10)?;
    let key_blob = args.dynamic_bytes(3).ok_or(-10)?;
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    let seat = claim_seat_internal(
        &cid,
        &mut hdr,
        context::msg_sender(),
        pref,
        id_addr,
        key_blob,
        false,
    )?;
    ret::write_u64_word(seat as u64);
    Ok(32)
}

fn handle_open_and_claim(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let pref = args.u64(1).ok_or(-10)?;
    let id_addr = args.address(2).ok_or(-10)?;
    let key_blob = args.dynamic_bytes(3).ok_or(-10)?;
    let deal_now = args.u64(4).ok_or(-10)? != 0;
    let opt_shuf1 = args.dynamic_bytes(5).ok_or(-10)?;

    let mut hdr = match load_hdr(&cid) {
        Some(h) => h,
        None => open_case_internal(&cid)?,
    };
    let caller = context::msg_sender();
    let seat = claim_seat_internal(&cid, &mut hdr, caller, pref, id_addr, key_blob, deal_now)?;
    if !opt_shuf1.is_empty() {
        apply_initial_shuffle_internal(&cid, &mut hdr, caller, opt_shuf1)?;
    }
    ret::write_u64_word(seat as u64);
    Ok(32)
}

fn handle_request_deal(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_LOBBY && hdr.phase != PHASE_SHUFFLING {
        return Err(-17);
    }
    hdr.deal_requested = 1;
    save_hdr(&cid, &hdr);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_submit_initial_shuffle(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let shuf1 = args.dynamic_bytes(1).ok_or(-10)?;
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    apply_initial_shuffle_internal(&cid, &mut hdr, context::msg_sender(), shuf1)?;
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_coshuffle_and_deal(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let fillers = args.dynamic_bytes(1).ok_or(-10)?;
    let shuf2_blob = args.dynamic_bytes(2).ok_or(-10)?;
    let pool_blob = args.dynamic_bytes(3).ok_or(-10)?;

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_SHUFFLING {
        return Err(-17);
    }
    let caller = context::msg_sender();
    if caller == hdr.first_shuffler {
        return Err(-21); // Strict 2-party independence: co-shuffler MUST differ from first shuffler!
    }
    if (fillers.len() % FILLER_SEAT_STRIDE) != 0 {
        return Err(-20);
    }

    // 1. Register any filler AI seats (`occupied == 2`) with verified slot blinding PoKs
    let filler_cnt = fillers.len() / FILLER_SEAT_STRIDE;
    let mut f = 0usize;
    while f < filler_cnt {
        let base = f * FILLER_SEAT_STRIDE;
        let seat_idx = fillers[base];
        if (seat_idx as usize) >= SEAT_COUNT {
            return Err(-20);
        }
        let mut cur_seat = load_seat(&cid, seat_idx);
        if cur_seat.occupied != 0 {
            return Err(-49); // Optimistic concurrency: seat was claimed by a human!
        }
        let mut ai_eoa = [0u8; 20];
        let mut ai_id = [0u8; 20];
        ai_eoa.copy_from_slice(&fillers[base + 1..base + 21]);
        ai_id.copy_from_slice(&fillers[base + 21..base + 41]);
        if ai_eoa == [0u8; 20] {
            return Err(-23);
        }
        let (ed_pk, u_arr, t_arr) = parse_and_verify_seat_keys(
            &cid,
            &ai_eoa,
            &hdr.epoch_pk,
            &fillers[base + 41..base + FILLER_SEAT_STRIDE],
        )?;
        cur_seat.occupied = 2;
        cur_seat.revoked = 0;
        cur_seat.sector_id = STARTING_SECTORS[seat_idx as usize];
        cur_seat.flags = 0;
        cur_seat.eoa = ai_eoa;
        cur_seat.identity_addr = ai_id;
        cur_seat.ed_pk = ed_pk;
        cur_seat.u_blinds = u_arr;
        cur_seat.hand_commits = t_arr;
        save_seat(&cid, seat_idx, &cur_seat);
        f += 1;
    }

    let mut all_seats = [SeatRec::empty(0); SEAT_COUNT];
    let mut first_human: Option<u8> = None;
    let mut s = 0usize;
    while s < SEAT_COUNT {
        let sr = load_seat(&cid, s as u8);
        if sr.occupied == 0 {
            return Err(-23);
        }
        if sr.occupied == 1 && first_human.is_none() {
            first_human = Some(s as u8);
        }
        all_seats[s] = sr;
        s += 1;
    }

    // 2. Load Shuffle #1 deck and verify Shuffle #2 (`5 + 5 + 8`)
    let mut deck1 = [0u8; TOTAL_DOSSIERS * 64];
    let Some(rn) = storage::get_into(key_deck(&cid).as_slice(), &mut deck1) else {
        return Err(-22);
    };
    if rn != TOTAL_DOSSIERS * 64 {
        return Err(-22);
    }
    let subdecks = [(0usize, 5usize), (5, 5), (10, 8)];
    let deck2 = verify_shuffle_step(
        &cid,
        2,
        &hdr.epoch_pk,
        &subdecks,
        TOTAL_DOSSIERS,
        &deck1,
        shuf2_blob,
    )?;

    // 3. Extract the 3 Threshold-Sealed Case Vault cards (`[0], [5], [10]`) & 15-card hand pool
    hdr.vault_ciphertexts[0..64].copy_from_slice(&deck2[0..64]);
    hdr.vault_ciphertexts[64..128].copy_from_slice(&deck2[5 * 64..6 * 64]);
    hdr.vault_ciphertexts[128..192].copy_from_slice(&deck2[10 * 64..11 * 64]);

    let mut pool_in = [0u8; HAND_POOL_COUNT * 64];
    pool_in[0..4 * 64].copy_from_slice(&deck2[1 * 64..5 * 64]);
    pool_in[4 * 64..8 * 64].copy_from_slice(&deck2[6 * 64..10 * 64]);
    pool_in[8 * 64..15 * 64].copy_from_slice(&deck2[11 * 64..18 * 64]);

    // 4. Verify `15`-card cross-category ZK shuffle so seat category counts are completely hidden
    let pool_sub = [(0usize, HAND_POOL_COUNT)];
    let dealt_cts = verify_shuffle_step(
        &cid,
        3,
        &hdr.epoch_pk,
        &pool_sub,
        HAND_POOL_COUNT,
        &pool_in,
        pool_blob,
    )?;

    // 5. DDH-blind `C'_{1, 3s+k} = C_{1, 3s+k} + U_{s,k}` and request 2-batch Threshold Decryption!
    let mut blinded_15 = [0u8; HAND_POOL_COUNT * 64];
    s = 0;
    while s < SEAT_COUNT {
        let mut k = 0usize;
        while k < DOSSIERS_PER_SEAT {
            let idx = s * DOSSIERS_PER_SEAT + k;
            let mut c1 = [0u8; 32];
            c1.copy_from_slice(&dealt_cts[idx * 64..idx * 64 + 32]);
            let c1_blind = point_add(&c1, &all_seats[s].u_blinds[k]).ok_or(-26)?;
            blinded_15[idx * 64..idx * 64 + 32].copy_from_slice(&c1_blind);
            blinded_15[idx * 64 + 32..(idx + 1) * 64]
                .copy_from_slice(&dealt_cts[idx * 64 + 32..(idx + 1) * 64]);
            k += 1;
        }
        s += 1;
    }

    let beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-14)?;
    let req0 = request_beacon_decryption(&beacon, hdr.epoch_id, &blinded_15[0..8 * 64], 0)?;
    let req1 = request_beacon_decryption(&beacon, hdr.epoch_id, &blinded_15[8 * 64..15 * 64], 0)?;

    let mut map0 = [0u8; 33];
    map0[0] = REQ_KIND_DEAL_BATCH0;
    map0[1..33].copy_from_slice(&cid);
    storage::set(key_dec_map(&req0).as_slice(), &map0);

    let mut map1 = [0u8; 33];
    map1[0] = REQ_KIND_DEAL_BATCH1;
    map1[1..33].copy_from_slice(&cid);
    storage::set(key_dec_map(&req1).as_slice(), &map1);

    hdr.phase = PHASE_DEALING;
    hdr.shuffle_count = 2;
    hdr.deal_fulfilled_mask = 0;
    hdr.turn_seat = first_human.unwrap_or(0);
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let mut ev = [0u8; 32];
    push_u64_word(&mut ev, 0, 2);
    events::emit(&[EV_DECK_SHUFFLED, cid, addr_topic(&caller)], &ev);

    ret::write_u64_word(hdr.turn_seat as u64);
    Ok(32)
}

fn handle_submit_probe(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let op_u64 = args.u64(1).ok_or(-10)?;
    let exp_u64 = args.u64(2).ok_or(-10)?;
    let sec_u64 = args.u64(3).ok_or(-10)?;

    if op_u64 > (OPERATIVE_CARD_END as u64)
        || exp_u64 < (EXPLOIT_CARD_START as u64)
        || exp_u64 > (EXPLOIT_CARD_END as u64)
        || sec_u64 < (SECTOR_CARD_START as u64)
        || sec_u64 > (SECTOR_CARD_END as u64)
    {
        return Err(-30);
    }

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_ACTIVE {
        return Err(-31);
    }

    let turn = hdr.turn_seat;
    let mut actor = load_seat(&cid, turn);
    if actor.occupied == 0 || actor.revoked != 0 || actor.eoa != context::msg_sender() {
        return Err(-32);
    }

    let target_sec = sec_u64 as u8;
    let was_pulled = (actor.flags & 1) != 0;
    if !is_sector_reachable(actor.sector_id, target_sec, was_pulled) {
        return Err(-33);
    }

    actor.sector_id = target_sec;
    actor.flags &= !1;
    save_seat(&cid, turn, &actor);

    let named_seat = op_u64 as u8;
    if named_seat != turn && (named_seat as usize) < SEAT_COUNT {
        let mut pulled = load_seat(&cid, named_seat);
        pulled.sector_id = target_sec;
        pulled.flags |= 1;
        save_seat(&cid, named_seat, &pulled);
    }

    let probe_idx = hdr.probe_count;
    hdr.probe_count = hdr.probe_count.saturating_add(1);
    if hdr.log_count < (LOG_WINDOW as u16) {
        hdr.log_count += 1;
    }

    let first_resp = ((turn as usize + 1) % SEAT_COUNT) as u8;
    hdr.phase = PHASE_PROBE_PENDING;
    hdr.prober_seat = turn;
    hdr.responder_seat = first_resp;
    hdr.probe_operative = named_seat;
    hdr.probe_exploit = exp_u64 as u8;
    hdr.probe_sector = target_sec;
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let entry = ProbeLogEntry {
        probe_idx,
        prober_seat: turn,
        operative: named_seat,
        exploit: exp_u64 as u8,
        sector: target_sec,
        pass_mask: 0,
        disprover_seat: 255,
        disprover_slot: 255,
        status: 0,
        whisper_ct: [0u8; 64],
    };
    save_log_slot(&cid, &entry);

    let mut ev = [0u8; 192];
    push_u64_word(&mut ev, 0, probe_idx as u64);
    push_u64_word(&mut ev, 1, turn as u64);
    push_u64_word(&mut ev, 2, named_seat as u64);
    push_u64_word(&mut ev, 3, exp_u64);
    push_u64_word(&mut ev, 4, sec_u64);
    push_u64_word(&mut ev, 5, first_resp as u64);
    events::emit(&[EV_PROBE_SUBMITTED, cid], &ev);

    ret::write_u64_word(probe_idx as u64);
    Ok(32)
}

fn advance_responder_on_pass(cid: &[u8; 32], hdr: &mut CaseHeader, mark_pass_bit: bool) {
    let cur = hdr.responder_seat;
    let cur_probe_idx = hdr.probe_count.saturating_sub(1);
    if let Some(mut entry) = load_log_slot(cid, cur_probe_idx) {
        if entry.probe_idx == cur_probe_idx {
            if mark_pass_bit {
                entry.pass_mask |= 1u8 << cur;
            }
            let next_resp = ((cur as usize + 1) % SEAT_COUNT) as u8;
            if next_resp == hdr.prober_seat {
                entry.status = 2;
                save_log_slot(cid, &entry);
                hdr.phase = PHASE_ACTIVE;
                hdr.responder_seat = 255;
                if let Some(nt) = next_active_turn_seat(cid, hdr.turn_seat) {
                    hdr.turn_seat = nt;
                }
                hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
                save_hdr(cid, hdr);

                let mut ev = [0u8; 96];
                push_u64_word(&mut ev, 0, cur_probe_idx as u64);
                push_u64_word(&mut ev, 1, cur as u64);
                push_u64_word(&mut ev, 2, 255);
                events::emit(&[EV_ALIBI_PASSED, *cid], &ev);
                return;
            } else {
                save_log_slot(cid, &entry);
                hdr.responder_seat = next_resp;
                hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
                save_hdr(cid, hdr);

                let mut ev = [0u8; 96];
                push_u64_word(&mut ev, 0, cur_probe_idx as u64);
                push_u64_word(&mut ev, 1, cur as u64);
                push_u64_word(&mut ev, 2, next_resp as u64);
                events::emit(&[EV_ALIBI_PASSED, *cid], &ev);
                return;
            }
        }
    }
}

fn handle_pass_alibi(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let r1cs_proof = args.dynamic_bytes(1).ok_or(-10)?;

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_PROBE_PENDING {
        return Err(-34);
    }
    let resp_seat = hdr.responder_seat;
    let resp = load_seat(&cid, resp_seat);
    if resp.occupied == 0 || resp.eoa != context::msg_sender() {
        return Err(-35);
    }

    let cur_probe_idx = hdr.probe_count.saturating_sub(1);
    let probes = [hdr.probe_operative, hdr.probe_exploit, hdr.probe_sector];
    if !verify_pass_alibi_r1cs(
        &cid,
        cur_probe_idx,
        resp_seat,
        &resp.hand_commits,
        probes,
        r1cs_proof,
    ) {
        return Err(-38); // Cheat-proof revert: Responder holds a probed vector or invalid R1CS proof!
    }

    advance_responder_on_pass(&cid, &mut hdr, true);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_transmit_alibi(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let whisper_proof = args.dynamic_bytes(2).ok_or(-10)?;

    if slot_idx >= (DOSSIERS_PER_SEAT as u64) {
        return Err(-36);
    }

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_PROBE_PENDING {
        return Err(-34);
    }
    let resp_seat = hdr.responder_seat;
    let resp = load_seat(&cid, resp_seat);
    if resp.occupied == 0 || resp.eoa != context::msg_sender() {
        return Err(-35);
    }

    let prober_seat = hdr.prober_seat;
    let prober = load_seat(&cid, prober_seat);
    let cur_probe_idx = hdr.probe_count.saturating_sub(1);
    let probes = [hdr.probe_operative, hdr.probe_exploit, hdr.probe_sector];

    let Some(whisper_ct) = verify_whisper_or3(
        &cid,
        cur_probe_idx,
        resp_seat,
        prober_seat,
        slot_idx as u8,
        &resp.hand_commits[slot_idx as usize],
        &prober.ed_pk,
        probes,
        whisper_proof,
    ) else {
        return Err(-39); // Cheat-proof revert: forged/non-matching whisper rejected by 1-of-3 ZK proof!
    };

    let mut entry = load_log_slot(&cid, cur_probe_idx).ok_or(-37)?;
    if entry.probe_idx != cur_probe_idx {
        return Err(-37);
    }
    entry.disprover_seat = resp_seat;
    entry.disprover_slot = slot_idx as u8;
    entry.status = 1;
    entry.whisper_ct = whisper_ct;
    save_log_slot(&cid, &entry);

    hdr.phase = PHASE_ACTIVE;
    hdr.responder_seat = 255;
    if let Some(nt) = next_active_turn_seat(&cid, hdr.turn_seat) {
        hdr.turn_seat = nt;
    }
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let mut ev = [0u8; 192];
    push_u64_word(&mut ev, 0, cur_probe_idx as u64);
    push_u64_word(&mut ev, 1, resp_seat as u64);
    push_u64_word(&mut ev, 2, prober_seat as u64);
    push_u64_word(&mut ev, 3, slot_idx);
    ev[128..192].copy_from_slice(&whisper_ct);
    events::emit(&[EV_ALIBI_TRANSMITTED, cid], &ev);

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_file_indictment(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let op_u64 = args.u64(1).ok_or(-10)?;
    let exp_u64 = args.u64(2).ok_or(-10)?;
    let sec_u64 = args.u64(3).ok_or(-10)?;
    let blind1_blob = args.dynamic_bytes(4).ok_or(-10)?;

    if op_u64 > (OPERATIVE_CARD_END as u64)
        || exp_u64 < (EXPLOIT_CARD_START as u64)
        || exp_u64 > (EXPLOIT_CARD_END as u64)
        || sec_u64 < (SECTOR_CARD_START as u64)
        || sec_u64 > (SECTOR_CARD_END as u64)
    {
        return Err(-30);
    }

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_ACTIVE {
        return Err(-31);
    }

    let turn = hdr.turn_seat;
    let actor = load_seat(&cid, turn);
    let caller = context::msg_sender();
    if actor.occupied == 0 || actor.revoked != 0 || actor.eoa != caller {
        return Err(-32);
    }

    let guesses = [op_u64 as u8, exp_u64 as u8, sec_u64 as u8];
    let delta0 = compute_indictment_delta0(&cid, &hdr.vault_ciphertexts, guesses).ok_or(-40)?;
    let delta1 =
        verify_indictment_blinding(&cid, 1, &hdr.epoch_pk, &delta0, blind1_blob).ok_or(-41)?;

    storage::set(key_indict_ct(&cid).as_slice(), &delta1);
    hdr.phase = PHASE_INDICTMENT_SHIELDING;
    hdr.indict_seat = turn;
    hdr.indict_eoa = caller;
    hdr.indict_operative = guesses[0];
    hdr.indict_exploit = guesses[1];
    hdr.indict_sector = guesses[2];
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let mut ev = [0u8; 128];
    push_u64_word(&mut ev, 0, turn as u64);
    push_u64_word(&mut ev, 1, op_u64);
    push_u64_word(&mut ev, 2, exp_u64);
    push_u64_word(&mut ev, 3, sec_u64);
    events::emit(&[EV_INDICTMENT_FILED, cid, addr_topic(&caller)], &ev);

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_coblind_indictment(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let blind2_blob = args.dynamic_bytes(1).ok_or(-10)?;

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_INDICTMENT_SHIELDING {
        return Err(-40);
    }
    let caller = context::msg_sender();
    if caller == hdr.indict_eoa {
        return Err(-21); // Co-blinder MUST differ from the indicting player so neither knows `rho_A * rho_B`!
    }

    let mut delta1 = [0u8; 64];
    let Some(rn) = storage::get_into(key_indict_ct(&cid).as_slice(), &mut delta1) else {
        return Err(-40);
    };
    if rn != 64 {
        return Err(-40);
    }

    let delta2 =
        verify_indictment_blinding(&cid, 2, &hdr.epoch_pk, &delta1, blind2_blob).ok_or(-41)?;
    let beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-14)?;
    let req_id = request_beacon_decryption(&beacon, hdr.epoch_id, &delta2, 0)?;

    let mut map = [0u8; 33];
    map[0] = REQ_KIND_INDICT_CHECK;
    map[1..33].copy_from_slice(&cid);
    storage::set(key_dec_map(&req_id).as_slice(), &map);

    hdr.phase = PHASE_INDICTMENT_DECRYPTING;
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    ret::write_word(&req_id);
    Ok(32)
}

fn fetch_beacon_decrypted_points(
    beacon: &[u8; 20],
    dec_req_id: &[u8; 32],
    expected_slots: usize,
    out_m_pts: &mut [[u8; 32]; 8],
) -> Result<(), i32> {
    let cd = CallEncoder::<64>::new(const { selector("getDecryptedPoints(bytes32)") })
        .push_bytes32(dec_req_id);
    let raw = call::call_raw(beacon, cd.as_slice()).map_err(|_| -28)?;
    let need = 18 + expected_slots * 64;
    if raw.len() < need || raw[0] != 2 || (raw[1] as usize) != expected_slots {
        return Err(-28);
    }
    let mut snap = [0u8; 18 + 8 * 64];
    snap[..need].copy_from_slice(&raw[..need]);
    let mut s = 0usize;
    while s < expected_slots {
        out_m_pts[s].copy_from_slice(&snap[18 + s * 64 + 32..18 + (s + 1) * 64]);
        s += 1;
    }
    Ok(())
}

fn handle_on_he_fulfilled(args: &CalldataReader) -> Result<i32, i32> {
    let beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-14)?;
    if context::msg_sender() != beacon {
        return Err(-21);
    }
    let dec_req_id = args.bytes32(0).ok_or(-10)?;
    let tallies_packed = args.dynamic_bytes(1).ok_or(-10)?;

    let mut map = [0u8; 33];
    let Some(rn) = storage::get_into(key_dec_map(&dec_req_id).as_slice(), &mut map) else {
        return Ok(0);
    };
    if rn != 33 {
        return Ok(0);
    }
    let kind = map[0];
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&map[1..33]);
    let mut hdr = load_hdr(&cid).ok_or(-16)?;

    match kind {
        REQ_KIND_DEAL_BATCH0 | REQ_KIND_DEAL_BATCH1 => {
            if hdr.phase != PHASE_DEALING {
                return Ok(0);
            }
            let (slot_offset, slot_cnt, bit) = if kind == REQ_KIND_DEAL_BATCH0 {
                (0usize, 8usize, 1u8)
            } else {
                (8usize, 7usize, 2u8)
            };
            if (hdr.deal_fulfilled_mask & bit) != 0 {
                return Ok(0);
            }
            let mut m_pts = [[0u8; 32]; 8];
            fetch_beacon_decrypted_points(&beacon, &dec_req_id, slot_cnt, &mut m_pts)?;

            let mut idx = 0usize;
            while idx < slot_cnt {
                let global_idx = slot_offset + idx;
                let seat_idx = (global_idx / DOSSIERS_PER_SEAT) as u8;
                let hand_slot = global_idx % DOSSIERS_PER_SEAT;
                let mut seat = load_seat(&cid, seat_idx);
                // V_{s,k} = M'_{s,k} + T_{s,k} = c_{s,k} * B + w_{s,k} * H_bp
                let v_comm = point_add(&m_pts[idx], &seat.hand_commits[hand_slot]).ok_or(-29)?;
                seat.blinded_decrypts[hand_slot] = m_pts[idx];
                seat.hand_commits[hand_slot] = v_comm;
                save_seat(&cid, seat_idx, &seat);
                idx += 1;
            }

            hdr.deal_fulfilled_mask |= bit;
            if hdr.deal_fulfilled_mask == 0x03 {
                hdr.phase = PHASE_ACTIVE;
                hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
                save_hdr(&cid, &hdr);

                let vault_hash = keccak256(&hdr.vault_ciphertexts);
                let mut ev = [0u8; 32];
                push_u64_word(&mut ev, 0, hdr.turn_seat as u64);
                events::emit(&[EV_VAULT_SEALED, cid, vault_hash], &ev);
            } else {
                save_hdr(&cid, &hdr);
            }
        }
        REQ_KIND_INDICT_CHECK => {
            if hdr.phase != PHASE_INDICTMENT_DECRYPTING || tallies_packed.len() < 8 {
                return Ok(0);
            }
            let is_exact_zero = u64::from_be_bytes(tallies_packed[0..8].try_into().unwrap());
            let seat_idx = hdr.indict_seat;
            let mut actor = load_seat(&cid, seat_idx);

            if is_exact_zero == 1 {
                hdr.phase = PHASE_SOLVED;
                hdr.winner_seat = seat_idx;
                hdr.sol_operative = hdr.indict_operative;
                hdr.sol_exploit = hdr.indict_exploit;
                hdr.sol_sector = hdr.indict_sector;
                save_hdr(&cid, &hdr);

                let wins = storage::get_u64(key_wins(&actor.eoa).as_slice()).saturating_add(1);
                storage::set_u64(key_wins(&actor.eoa).as_slice(), wins);

                let mut ev = [0u8; 128];
                push_u64_word(&mut ev, 0, seat_idx as u64);
                push_u64_word(&mut ev, 1, hdr.sol_operative as u64);
                push_u64_word(&mut ev, 2, hdr.sol_exploit as u64);
                push_u64_word(&mut ev, 3, hdr.sol_sector as u64);
                events::emit(&[EV_CASE_SOLVED, cid, addr_topic(&actor.eoa)], &ev);
            } else {
                actor.revoked = 1;
                save_seat(&cid, seat_idx, &actor);

                if let Some(nt) = next_active_turn_seat(&cid, seat_idx) {
                    hdr.phase = PHASE_ACTIVE;
                    hdr.turn_seat = nt;
                    hdr.deadline_block =
                        context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
                    save_hdr(&cid, &hdr);

                    let mut ev = [0u8; 64];
                    push_u64_word(&mut ev, 0, seat_idx as u64);
                    push_u64_word(&mut ev, 1, nt as u64);
                    events::emit(&[EV_INDICTMENT_REFUTED, cid], &ev);
                } else {
                    // All 5 seats had their clearance revoked -> threshold-unveil the 3 Vault cards!
                    let unveil_req = request_beacon_decryption(
                        &beacon,
                        hdr.epoch_id,
                        &hdr.vault_ciphertexts,
                        20,
                    )?;
                    let mut umap = [0u8; 33];
                    umap[0] = REQ_KIND_UNVEIL_VAULT;
                    umap[1..33].copy_from_slice(&cid);
                    storage::set(key_dec_map(&unveil_req).as_slice(), &umap);

                    hdr.phase = PHASE_UNVEILING_VAULT;
                    hdr.deadline_block =
                        context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
                    save_hdr(&cid, &hdr);
                }
            }
        }
        REQ_KIND_UNVEIL_VAULT => {
            if hdr.phase != PHASE_UNVEILING_VAULT || tallies_packed.len() < 24 {
                return Ok(0);
            }
            let op = u64::from_be_bytes(tallies_packed[0..8].try_into().unwrap()) as u8;
            let exp = u64::from_be_bytes(tallies_packed[8..16].try_into().unwrap()) as u8;
            let sec = u64::from_be_bytes(tallies_packed[16..24].try_into().unwrap()) as u8;

            hdr.phase = PHASE_SOLVED;
            hdr.winner_seat = 255;
            hdr.sol_operative = op;
            hdr.sol_exploit = exp;
            hdr.sol_sector = sec;
            save_hdr(&cid, &hdr);

            let mut ev = [0u8; 128];
            push_u64_word(&mut ev, 0, 255);
            push_u64_word(&mut ev, 1, op as u64);
            push_u64_word(&mut ev, 2, exp as u64);
            push_u64_word(&mut ev, 3, sec as u64);
            events::emit(&[EV_CASE_SOLVED, cid, [0u8; 32]], &ev);
        }
        _ => {}
    }

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_advance_timeout(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    let blk = context::block_number();
    if blk < hdr.deadline_block {
        return Err(-45);
    }

    if hdr.phase == PHASE_ACTIVE {
        if let Some(nt) = next_active_turn_seat(&cid, hdr.turn_seat) {
            hdr.turn_seat = nt;
            hdr.deadline_block = blk.saturating_add(TURN_TIMEOUT_BLOCKS);
            save_hdr(&cid, &hdr);
            ret::write_u64_word(nt as u64);
            return Ok(32);
        }
    } else if hdr.phase == PHASE_PROBE_PENDING {
        // Disqualify unresponsive responder (`revoked = 1`) so going AFK can never win by hiding a card!
        let mut resp = load_seat(&cid, hdr.responder_seat);
        resp.revoked = 1;
        save_seat(&cid, hdr.responder_seat, &resp);
        advance_responder_on_pass(&cid, &mut hdr, false);
        ret::write_u64_word(1);
        return Ok(32);
    }

    Err(-46)
}

fn handle_get_case_state(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let Some(hdr) = load_hdr(&cid) else {
        ret::write(&[]);
        return Ok(0);
    };

    const MAX_OUT: usize = HDR_LEN + SEAT_COUNT * SEAT_LEN + LOG_WINDOW * LOG_ENTRY_LEN;
    let mut out = [0u8; MAX_OUT];
    out[0..HDR_LEN].copy_from_slice(&hdr.encode());
    let mut pos = HDR_LEN;

    let mut s = 0;
    while s < SEAT_COUNT {
        let seat = load_seat(&cid, s as u8);
        out[pos..pos + SEAT_LEN].copy_from_slice(&seat.encode());
        pos += SEAT_LEN;
        s += 1;
    }

    let total_probes = hdr.probe_count as usize;
    let n_logs = (hdr.log_count as usize).min(LOG_WINDOW).min(total_probes);
    let start_idx = total_probes.saturating_sub(n_logs);
    let mut written = 0u16;
    let mut k = 0;
    while k < n_logs {
        let pidx = (start_idx + k) as u16;
        if let Some(entry) = load_log_slot(&cid, pidx) {
            out[pos..pos + LOG_ENTRY_LEN].copy_from_slice(&entry.encode());
            pos += LOG_ENTRY_LEN;
            written += 1;
        }
        k += 1;
    }
    out[18..20].copy_from_slice(&written.to_be_bytes());

    ret::write(&out[..pos]);
    Ok(pos as i32)
}

fn handle_get_deck_ciphertexts(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let mut deck = [0u8; TOTAL_DOSSIERS * 64];
    match storage::get_into(key_deck(&cid).as_slice(), &mut deck) {
        Some(n) if n == TOTAL_DOSSIERS * 64 => {
            ret::write(&deck);
            Ok(n as i32)
        }
        _ => {
            ret::write(&[]);
            Ok(0)
        }
    }
}

fn handle_get_pending_indict_ct(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let mut ct = [0u8; 64];
    match storage::get_into(key_indict_ct(&cid).as_slice(), &mut ct) {
        Some(64) => {
            ret::write(&ct);
            Ok(64)
        }
        _ => {
            ret::write(&[]);
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// Native End-to-End ZK & Threshold Security Tests (`cargo test -p cipher-noir`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::Identity;
    use hps_sdk::bulletproofs::mock_bp;
    use hps_sdk::mock;
    use sha2::{Digest, Sha512};

    const BEACON_ADDR: [u8; 20] = [0x55; 20];
    const TRIB_ADDR: [u8; 20] = [0x61; 20];
    const HUMAN: [u8; 20] = [0xA1; 20];
    const AI1: [u8; 20] = [0xB1; 20];
    const AI2: [u8; 20] = [0xB2; 20];
    const AI3: [u8; 20] = [0xB3; 20];
    const AI4: [u8; 20] = [0xB4; 20];

    struct MockBeaconState {
        epoch_sk: Scalar,
        epoch_pk: [u8; 32],
    }

    fn mock_beacon_secret() -> MockBeaconState {
        let epoch_sk = Scalar::from(987_654_321u64);
        let epoch_pk = (&epoch_sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        MockBeaconState { epoch_sk, epoch_pk }
    }

    use std::cell::RefCell;

    thread_local! {
        static MOCK_PENDING_CB: RefCell<Vec<([u8; 20], [u8; 32], Vec<u8>)>> = const { RefCell::new(Vec::new()) };
        static MOCK_DEC_PTS: RefCell<std::collections::BTreeMap<[u8; 32], Vec<u8>>> = const { RefCell::new(std::collections::BTreeMap::new()) };
    }

    /// Lightweight `vrf-beacon` mock handler performing authentic `Edwards25519` ElGamal decryption.
    fn mock_vrf_beacon_dispatch(cd: &[u8]) -> i32 {
        let Some((sel, r)) = CalldataReader::parse(cd) else {
            return -1;
        };
        let b = mock_beacon_secret();
        let sel_ep = selector("getActiveEpochKey()");
        let sel_req = selector("requestThresholdDecryption(uint64,bytes,uint64,uint64)");
        let sel_pts = selector("getDecryptedPoints(bytes32)");

        if sel == sel_ep {
            let mut out = [0u8; 48];
            out[0..8].copy_from_slice(&1u64.to_be_bytes());
            out[8..12].copy_from_slice(&4u32.to_be_bytes());
            out[12..16].copy_from_slice(&5u32.to_be_bytes());
            out[16..48].copy_from_slice(&b.epoch_pk);
            ret::write(&out);
            return 48;
        }
        if sel == sel_req {
            let cts = r.dynamic_bytes(1).unwrap();
            let max_val = r.u64(2).unwrap();
            let seq = storage::get_u64(b"seq") + 1;
            storage::set_u64(b"seq", seq);
            let req_id = keccak256(&seq.to_be_bytes());
            let requester = context::msg_sender();

            let slots = cts.len() / 64;
            let mut pts_out = Vec::with_capacity(18 + slots * 64);
            pts_out.push(2);
            pts_out.push(slots as u8);
            pts_out.extend_from_slice(&1u64.to_be_bytes());
            pts_out.extend_from_slice(&0x1fu64.to_be_bytes());

            let mut tallies = Vec::with_capacity(slots * 8);
            for s in 0..slots {
                let c1 = CompressedEdwardsY(cts[s * 64..s * 64 + 32].try_into().unwrap())
                    .decompress()
                    .unwrap();
                let c2 = CompressedEdwardsY(cts[s * 64 + 32..(s + 1) * 64].try_into().unwrap())
                    .decompress()
                    .unwrap();
                let d_pt = b.epoch_sk * c1;
                let m_pt = c2 - d_pt;
                let d_32 = d_pt.compress().to_bytes();
                let m_32 = m_pt.compress().to_bytes();
                pts_out.extend_from_slice(&d_32);
                pts_out.extend_from_slice(&m_32);

                let t_u64 = if max_val == 0 {
                    if m_32 == vrf::IDENTITY_POINT_BYTES { 1u64 } else { 0u64 }
                } else {
                    let mut found = 0u64;
                    for v in 0..=max_val {
                        if (&Scalar::from(v) * ED25519_BASEPOINT_TABLE).compress().to_bytes() == m_32
                        {
                            found = v;
                            break;
                        }
                    }
                    found
                };
                tallies.extend_from_slice(&t_u64.to_be_bytes());
            }
            MOCK_DEC_PTS.with(|m| {
                m.borrow_mut().insert(req_id, pts_out);
            });
            MOCK_PENDING_CB.with(|q| {
                q.borrow_mut().push((requester, req_id, tallies));
            });

            ret::write_word(&req_id);
            return 32;
        }
        if sel == sel_pts {
            let req_id = r.bytes32(0).unwrap();
            let raw = MOCK_DEC_PTS.with(|m| m.borrow().get(&req_id).cloned().unwrap_or_default());
            ret::write(&raw);
            return raw.len() as i32;
        }
        -1
    }

    fn flush_beacon_callbacks() {
        let items = MOCK_PENDING_CB.with(|q| std::mem::take(&mut *q.borrow_mut()));
        for (req_addr, req_id, tallies) in items {
            let cd = CallEncoder::<512>::new(selector(
                "onHeDecryptionFulfilled(bytes32,bytes,uint64,uint64)",
            ))
            .push_bytes32(&req_id)
            .push_u64(128)
            .push_u64(1)
            .push_u64(0x1f)
            .push_dynamic_bytes_tail(&tallies)
            .as_slice()
            .to_vec();
            mock::transact_as(BEACON_ADDR, req_addr, &cd).unwrap();
        }
    }

    struct TestSeatSecrets {
        eoa: [u8; 20],
        ed_sk: Scalar,
        ed_pk: [u8; 32],
        u_sk: [Scalar; 3],
        w_sk: [Scalar; 3],
        key_blob: Vec<u8>,
    }

    fn make_seat_secrets(cid: &[u8; 32], eoa: [u8; 20], epoch_pk: &[u8; 32], tag: u8) -> TestSeatSecrets {
        let epk_pt = CompressedEdwardsY(*epoch_pk).decompress().unwrap();
        let h_pt = mock_bp::generators().h_blind;
        let sc = |sub: u8| -> Scalar {
            let mut h = Sha512::new();
            h.update([tag, sub]);
            h.update(cid);
            let mut s = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
            if s == Scalar::ZERO { s = Scalar::ONE; }
            s
        };
        let ed_sk = sc(0);
        let ed_pk = (&ed_sk * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let mut u_sk = [Scalar::ZERO; 3];
        let mut w_sk = [Scalar::ZERO; 3];
        let mut blob = Vec::with_capacity(SEAT_KEY_BLOB_LEN);
        blob.extend_from_slice(&ed_pk);
        for k in 0..3 {
            u_sk[k] = sc(10 + k as u8);
            w_sk[k] = sc(20 + k as u8);
            let u_pt = &u_sk[k] * ED25519_BASEPOINT_TABLE;
            let t_pt = u_sk[k] * epk_pt + w_sk[k] * h_pt;
            let ku = sc(30 + k as u8);
            let kw = sc(40 + k as u8);
            let r_u = (&ku * ED25519_BASEPOINT_TABLE).compress().to_bytes();
            let r_t = (ku * epk_pt + kw * h_pt).compress().to_bytes();

            let mut kh = KeccakHasher::new();
            kh.update(b"NOIR_SLOT_POK_V1");
            kh.update(cid);
            kh.update(&eoa);
            kh.update(&[k as u8]);
            kh.update(epoch_pk);
            kh.update(&ed_pk);
            kh.update(u_pt.compress().as_bytes());
            kh.update(t_pt.compress().as_bytes());
            kh.update(&r_u);
            kh.update(&r_t);
            let c_b = bulletproofs::scalar_from_hash_nonzero(&kh.finalize());
            let c = Scalar::from_canonical_bytes(c_b).unwrap();
            let zu = ku + c * u_sk[k];
            let zw = kw + c * w_sk[k];

            blob.extend_from_slice(u_pt.compress().as_bytes());
            blob.extend_from_slice(t_pt.compress().as_bytes());
            blob.extend_from_slice(c.as_bytes());
            blob.extend_from_slice(zu.as_bytes());
            blob.extend_from_slice(zw.as_bytes());
        }
        TestSeatSecrets { eoa, ed_sk, ed_pk, u_sk, w_sk, key_blob: blob }
    }

    fn build_shuffle_blob(
        cid: &[u8; 32],
        step_tag: u8,
        epoch_pk: &[u8; 32],
        subdecks: &[(usize, usize)],
        total_cards: usize,
        in_cts: &[u8],
        perm: &[usize], // out[j] comes from in[perm[j]]
        seed: u8,
    ) -> Vec<u8> {
        const N_GATES: usize = 16;
        let epk_pt = CompressedEdwardsY(*epoch_pk).decompress().unwrap();
        let sc = |tag: u8, idx: usize| -> Scalar {
            let mut h = Sha512::new();
            h.update([seed, tag]);
            h.update((idx as u32).to_be_bytes());
            let mut s = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
            if s == Scalar::ZERO { s = Scalar::ONE; }
            s
        };

        let mut r_vec = Vec::with_capacity(total_cards);
        let mut out_cts = Vec::with_capacity(total_cards * 64);
        for j in 0..total_cards {
            let src = perm[j];
            let in1 = CompressedEdwardsY(in_cts[src * 64..src * 64 + 32].try_into().unwrap())
                .decompress()
                .unwrap();
            let in2 = CompressedEdwardsY(in_cts[src * 64 + 32..(src + 1) * 64].try_into().unwrap())
                .decompress()
                .unwrap();
            let rj = sc(1, j);
            r_vec.push(rj);
            let o1 = in1 + &rj * ED25519_BASEPOINT_TABLE;
            let o2 = in2 + rj * epk_pt;
            out_cts.extend_from_slice(o1.compress().as_bytes());
            out_cts.extend_from_slice(o2.compress().as_bytes());
        }

        let mut ah = KeccakHasher::new();
        ah.update(b"NOIR_SHUF_ALPHA_V1");
        ah.update(cid);
        ah.update(&[step_tag]);
        ah.update(epoch_pk);
        ah.update(in_cts);
        ah.update(&out_cts);
        let alpha = Scalar::from_canonical_bytes(
            bulletproofs::scalar_from_hash_nonzero(&ah.finalize()),
        )
        .unwrap();

        let mut alpha_pows = Vec::with_capacity(total_cards);
        let mut cur = alpha;
        for _ in 0..total_cards {
            alpha_pows.push(cur);
            cur *= alpha;
        }

        // Compute `s_i = alpha_pows[perm^{-1}(i)]` and commit `S_i` BEFORE `beta`!
        let mut s_vals = vec![Scalar::ZERO; total_cards];
        for j in 0..total_cards {
            s_vals[perm[j]] = alpha_pows[j];
        }
        let s_blinds: Vec<Scalar> = (0..total_cards).map(|i| sc(2, i)).collect();
        let s_commits_pre: Vec<[u8; 32]> = s_vals
            .iter()
            .zip(s_blinds.iter())
            .map(|(v, b)| mock_bp::pedersen_commit(v, b))
            .collect();

        let mut bh = KeccakHasher::new();
        bh.update(b"NOIR_SHUF_BETA_V1");
        bh.update(cid);
        bh.update(&[step_tag]);
        bh.update(alpha.as_bytes());
        for c_b in &s_commits_pre {
            bh.update(c_b);
        }
        let beta_b = bulletproofs::scalar_from_hash_nonzero(&bh.finalize());
        let beta = Scalar::from_canonical_bytes(beta_b).unwrap();
        let neg_beta = bulletproofs::scalar_neg(&beta_b);

        let mut cs = BpCsBuilder::<4096>::new(N_GATES as u16, total_cards as u16);
        let zero = [0u8; 32];
        let one = bulletproofs::scalar_from_u64(1);
        let minus_one = bulletproofs::scalar_neg_u64(1);
        let mut a_l = vec![Scalar::ZERO; N_GATES];
        let mut a_r = vec![Scalar::ZERO; N_GATES];
        let mut a_o = vec![Scalar::ZERO; N_GATES];

        let mut gate_cursor = 0usize;
        for &(start_idx, len) in subdecks {
            let mut k_prod = alpha_pows[start_idx] - beta;
            for r in 1..len {
                k_prod *= alpha_pows[start_idx + r] - beta;
            }

            a_l[gate_cursor] = s_vals[start_idx] - beta;
            a_r[gate_cursor] = s_vals[start_idx + 1] - beta;
            a_o[gate_cursor] = a_l[gate_cursor] * a_r[gate_cursor];

            cs.begin_constraint(&neg_beta);
            cs.push_term(WIRE_A_L, gate_cursor as u16, &one);
            cs.push_term(WIRE_VAR, start_idx as u16, &minus_one);
            cs.begin_constraint(&neg_beta);
            cs.push_term(WIRE_A_R, gate_cursor as u16, &one);
            cs.push_term(WIRE_VAR, (start_idx + 1) as u16, &minus_one);

            for step in 1..(len - 1) {
                let g = gate_cursor + step;
                a_l[g] = a_o[g - 1];
                a_r[g] = s_vals[start_idx + step + 1] - beta;
                a_o[g] = a_l[g] * a_r[g];

                cs.begin_constraint(&zero);
                cs.push_term(WIRE_A_L, g as u16, &one);
                cs.push_term(WIRE_A_O, (g - 1) as u16, &minus_one);
                cs.begin_constraint(&neg_beta);
                cs.push_term(WIRE_A_R, g as u16, &one);
                cs.push_term(WIRE_VAR, (start_idx + step + 1) as u16, &minus_one);
            }

            let last_g = gate_cursor + len - 2;
            cs.begin_constraint(k_prod.as_bytes());
            cs.push_term(WIRE_A_O, last_g as u16, &one);

            gate_cursor += len - 1;
        }

        let mut r1cs_ctx = [0u8; 114];
        r1cs_ctx[0..17].copy_from_slice(b"NOIR_SHUF_R1CS_V1");
        r1cs_ctx[17..49].copy_from_slice(cid);
        r1cs_ctx[49] = step_tag;
        r1cs_ctx[50..82].copy_from_slice(alpha.as_bytes());
        r1cs_ctx[82..114].copy_from_slice(&beta_b);

        let (s_commits, r1cs_proof) = mock_bp::prove_r1cs(
            cs.as_slice().unwrap(),
            &s_vals,
            &s_blinds,
            &a_l,
            &a_r,
            &a_o,
            &r1cs_ctx,
            &[seed; 32],
        )
        .unwrap();

        let mut r_tot = Scalar::ZERO;
        let mut l1_pt = EdwardsPoint::identity();
        let mut l2_pt = EdwardsPoint::identity();
        for j in 0..total_cards {
            r_tot += alpha_pows[j] * r_vec[j];
            let o1 = CompressedEdwardsY(out_cts[j * 64..j * 64 + 32].try_into().unwrap())
                .decompress()
                .unwrap();
            let o2 = CompressedEdwardsY(out_cts[j * 64 + 32..(j + 1) * 64].try_into().unwrap())
                .decompress()
                .unwrap();
            l1_pt += alpha_pows[j] * o1;
            l2_pt += alpha_pows[j] * o2;
        }

        let k_s: Vec<Scalar> = (0..total_cards).map(|i| sc(3, i)).collect();
        let k_g: Vec<Scalar> = (0..total_cards).map(|i| sc(4, i)).collect();
        let k_r = sc(5, 0);
        let h_bp = mock_bp::generators().h_blind;

        let mut lh = KeccakHasher::new();
        lh.update(b"NOIR_SHUF_LIN_V1");
        lh.update(cid);
        lh.update(&[step_tag]);
        lh.update(alpha.as_bytes());
        lh.update(l1_pt.compress().as_bytes());
        lh.update(l2_pt.compress().as_bytes());
        for sc_bytes in &s_commits {
            lh.update(sc_bytes);
        }
        let mut r1_pt = &k_r * ED25519_BASEPOINT_TABLE;
        let mut r2_pt = k_r * epk_pt;
        for i in 0..total_cards {
            let rsi = &k_s[i] * ED25519_BASEPOINT_TABLE + k_g[i] * h_bp;
            lh.update(rsi.compress().as_bytes());
            let in1 = CompressedEdwardsY(in_cts[i * 64..i * 64 + 32].try_into().unwrap())
                .decompress()
                .unwrap();
            let in2 = CompressedEdwardsY(in_cts[i * 64 + 32..(i + 1) * 64].try_into().unwrap())
                .decompress()
                .unwrap();
            r1_pt += k_s[i] * in1;
            r2_pt += k_s[i] * in2;
        }
        lh.update(r1_pt.compress().as_bytes());
        lh.update(r2_pt.compress().as_bytes());
        let c = Scalar::from_canonical_bytes(
            bulletproofs::scalar_from_hash_nonzero(&lh.finalize()),
        )
        .unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(&out_cts);
        for sc_bytes in &s_commits {
            blob.extend_from_slice(sc_bytes);
        }
        blob.extend_from_slice(&r1cs_proof);
        blob.extend_from_slice(c.as_bytes());
        for i in 0..total_cards {
            blob.extend_from_slice((k_s[i] + c * s_vals[i]).as_bytes());
        }
        for i in 0..total_cards {
            blob.extend_from_slice((k_g[i] + c * s_blinds[i]).as_bytes());
        }
        blob.extend_from_slice((k_r + c * r_tot).as_bytes());
        blob
    }

    fn build_pass_r1cs_proof(
        cid: &[u8; 32],
        probe_idx: u16,
        responder_seat: u8,
        cards: [u8; 3],
        w_blinds: &[Scalar; 3],
        probes: [u8; 3],
    ) -> Option<Vec<u8>> {
        let mut cs = BpCsBuilder::<4096>::new(16, 3);
        let zero = [0u8; 32];
        let one = bulletproofs::scalar_from_u64(1);
        let minus_one = bulletproofs::scalar_neg_u64(1);

        cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[0] as u64));
        cs.push_term(WIRE_A_L, 0, &one);
        cs.push_term(WIRE_VAR, 0, &minus_one);
        cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[1] as u64));
        cs.push_term(WIRE_A_R, 0, &one);
        cs.push_term(WIRE_VAR, 0, &minus_one);
        for t in 1..=7u16 {
            let factor_idx = (t + 1) as usize;
            let k = (factor_idx / 3) as u16;
            let m = factor_idx % 3;
            cs.begin_constraint(&zero);
            cs.push_term(WIRE_A_L, t, &one);
            cs.push_term(WIRE_A_O, t - 1, &minus_one);
            cs.begin_constraint(&bulletproofs::scalar_neg_u64(probes[m] as u64));
            cs.push_term(WIRE_A_R, t, &one);
            cs.push_term(WIRE_VAR, k, &minus_one);
        }
        cs.begin_constraint(&zero);
        cs.push_term(WIRE_A_L, 8, &one);
        cs.push_term(WIRE_A_O, 7, &minus_one);
        cs.begin_constraint(&one);
        cs.push_term(WIRE_A_O, 8, &one);

        let mut diffs = Vec::with_capacity(9);
        for &c in &cards {
            for &p in &probes {
                let d = Scalar::from(c as u64) - Scalar::from(p as u64);
                if d == Scalar::ZERO {
                    return None;
                }
                diffs.push(d);
            }
        }
        let mut a_l = vec![Scalar::ZERO; 16];
        let mut a_r = vec![Scalar::ZERO; 16];
        let mut a_o = vec![Scalar::ZERO; 16];
        a_l[0] = diffs[0];
        a_r[0] = diffs[1];
        a_o[0] = a_l[0] * a_r[0];
        for t in 1..=7 {
            a_l[t] = a_o[t - 1];
            a_r[t] = diffs[t + 1];
            a_o[t] = a_l[t] * a_r[t];
        }
        a_l[8] = a_o[7];
        a_r[8] = a_o[7].invert();
        a_o[8] = Scalar::ONE;

        let mut ctx = [0u8; 54];
        ctx[0..16].copy_from_slice(b"NOIR_PASS_R1CS_1");
        ctx[16..48].copy_from_slice(cid);
        ctx[48..50].copy_from_slice(&probe_idx.to_be_bytes());
        ctx[50] = responder_seat;
        ctx[51..54].copy_from_slice(&probes);

        let vals = cards.map(|c| Scalar::from(c as u64));
        mock_bp::prove_r1cs(
            cs.as_slice()?,
            &vals,
            w_blinds,
            &a_l,
            &a_r,
            &a_o,
            &ctx,
            &[0x44; 32],
        )
        .map(|(_, prf)| prf)
    }

    fn build_whisper_or3_proof(
        cid: &[u8; 32],
        probe_idx: u16,
        responder_seat: u8,
        prober_seat: u8,
        slot_idx: u8,
        card: u8,
        w_blind: &Scalar,
        prober_pk: &[u8; 32],
        probes: [u8; 3],
    ) -> Option<Vec<u8>> {
        let true_m = probes.iter().position(|&p| p == card)?;
        let pk_p = CompressedEdwardsY(*prober_pk).decompress()?;
        let h_bp = mock_bp::generators().h_blind;
        let v_pt = &Scalar::from(card as u64) * ED25519_BASEPOINT_TABLE + w_blind * h_bp;
        let v_bytes = v_pt.compress().to_bytes();

        let r_enc = Scalar::from(555_111u64);
        let e1_pt = &r_enc * ED25519_BASEPOINT_TABLE;
        let e2_pt = &Scalar::from(card as u64) * ED25519_BASEPOINT_TABLE + r_enc * pk_p;

        let mut c_arr = [Scalar::ZERO; 3];
        let mut zw_arr = [Scalar::ZERO; 3];
        let mut zr_arr = [Scalar::ZERO; 3];
        let kw = Scalar::from(777_222u64);
        let kr = Scalar::from(888_333u64);

        let mut kh = KeccakHasher::new();
        kh.update(b"NOIR_WHISPER_OR3_V1");
        kh.update(cid);
        kh.update(&probe_idx.to_be_bytes());
        kh.update(&[responder_seat, prober_seat, slot_idx]);
        kh.update(&v_bytes);
        kh.update(prober_pk);
        kh.update(e1_pt.compress().as_bytes());
        kh.update(e2_pt.compress().as_bytes());
        kh.update(&probes);

        for m in 0..3 {
            if m == true_m {
                let rv = kw * h_bp;
                let r1 = &kr * ED25519_BASEPOINT_TABLE;
                let r2 = kr * pk_p;
                kh.update(rv.compress().as_bytes());
                kh.update(r1.compress().as_bytes());
                kh.update(r2.compress().as_bytes());
            } else {
                c_arr[m] = Scalar::from((1000 + m) as u64);
                zw_arr[m] = Scalar::from((2000 + m) as u64);
                zr_arr[m] = Scalar::from((3000 + m) as u64);
                let pm_pt = &Scalar::from(probes[m] as u64) * ED25519_BASEPOINT_TABLE;
                let rv = zw_arr[m] * h_bp - c_arr[m] * (v_pt - pm_pt);
                let r1 = &zr_arr[m] * ED25519_BASEPOINT_TABLE - c_arr[m] * e1_pt;
                let r2 = zr_arr[m] * pk_p - c_arr[m] * (e2_pt - pm_pt);
                kh.update(rv.compress().as_bytes());
                kh.update(r1.compress().as_bytes());
                kh.update(r2.compress().as_bytes());
            }
        }

        let c_tot = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            bulletproofs::scalar_from_hash_nonzero(&kh.finalize()),
        ))?;
        let mut fake_sum = Scalar::ZERO;
        for m in 0..3 {
            if m != true_m {
                fake_sum += c_arr[m];
            }
        }
        c_arr[true_m] = c_tot - fake_sum;
        zw_arr[true_m] = kw + c_arr[true_m] * w_blind;
        zr_arr[true_m] = kr + c_arr[true_m] * r_enc;

        let mut out = Vec::with_capacity(WHISPER_PROOF_LEN);
        out.extend_from_slice(e1_pt.compress().as_bytes());
        out.extend_from_slice(e2_pt.compress().as_bytes());
        for m in 0..3 {
            out.extend_from_slice(c_arr[m].as_bytes());
            out.extend_from_slice(zw_arr[m].as_bytes());
            out.extend_from_slice(zr_arr[m].as_bytes());
        }
        Some(out)
    }

    fn build_indict_blind_blob(
        cid: &[u8; 32],
        step_tag: u8,
        epoch_pk: &[u8; 32],
        delta_in: &[u8; 64],
        seed: u64,
    ) -> [u8; INDICT_BLIND_BLOB_LEN] {
        let epk_pt = CompressedEdwardsY(*epoch_pk).decompress().unwrap();
        let in1 = CompressedEdwardsY(delta_in[0..32].try_into().unwrap())
            .decompress()
            .unwrap();
        let in2 = CompressedEdwardsY(delta_in[32..64].try_into().unwrap())
            .decompress()
            .unwrap();
        let rho = Scalar::from(seed);
        let r = Scalar::from(seed + 999);
        let p_rho = &rho * ED25519_BASEPOINT_TABLE;
        let out1 = rho * in1 + &r * ED25519_BASEPOINT_TABLE;
        let out2 = rho * in2 + r * epk_pt;

        let k_rho = Scalar::from(seed + 11_111);
        let k_r = Scalar::from(seed + 22_222);
        let r_p = &k_rho * ED25519_BASEPOINT_TABLE;
        let r_1 = k_rho * in1 + &k_r * ED25519_BASEPOINT_TABLE;
        let r_2 = k_rho * in2 + k_r * epk_pt;

        let mut kh = KeccakHasher::new();
        kh.update(b"NOIR_INDICT_BLIND_V1");
        kh.update(cid);
        kh.update(&[step_tag]);
        kh.update(epoch_pk);
        kh.update(delta_in);
        kh.update(out1.compress().as_bytes());
        kh.update(out2.compress().as_bytes());
        kh.update(p_rho.compress().as_bytes());
        kh.update(r_p.compress().as_bytes());
        kh.update(r_1.compress().as_bytes());
        kh.update(r_2.compress().as_bytes());
        let c = Scalar::from_canonical_bytes(
            bulletproofs::scalar_from_hash_nonzero(&kh.finalize()),
        )
        .unwrap();

        let mut out = [0u8; INDICT_BLIND_BLOB_LEN];
        out[0..32].copy_from_slice(out1.compress().as_bytes());
        out[32..64].copy_from_slice(out2.compress().as_bytes());
        out[64..96].copy_from_slice(p_rho.compress().as_bytes());
        out[96..128].copy_from_slice(c.as_bytes());
        out[128..160].copy_from_slice((k_rho + c * rho).as_bytes());
        out[160..192].copy_from_slice((k_r + c * r).as_bytes());
        out
    }

    #[test]
    fn arbiter_free_zk_coshuffle_ddh_hands_r1cs_pass_or3_whisper_and_blind_indictment() {
        mock::reset();
        mock::register_hps(BEACON_ADDR, mock_vrf_beacon_dispatch);
        mock::register_hps(TRIB_ADDR, dispatch_calldata);
        mock::set_block_number(500);

        let bsec = mock_beacon_secret();
        let cid = [0x42; 32];

        // 1. Init Tribunal with `vrf-beacon` (NO Arbiter EOA!)
        let cd_init = CallEncoder::<128>::new(selector("initTribunal(address)"))
            .push_address(&BEACON_ADDR)
            .as_slice()
            .to_vec();
        mock::transact_as(HUMAN, TRIB_ADDR, &cd_init).unwrap();

        // 2. Human opens case, claims Seat 0, AND submits Shuffle #1 in ONE transaction!
        let s0 = make_seat_secrets(&cid, HUMAN, &bsec.epoch_pk, 1);
        let s1 = make_seat_secrets(&cid, AI1, &bsec.epoch_pk, 2);
        let s2 = make_seat_secrets(&cid, AI2, &bsec.epoch_pk, 3);
        let s3 = make_seat_secrets(&cid, AI3, &bsec.epoch_pk, 4);
        let s4 = make_seat_secrets(&cid, AI4, &bsec.epoch_pk, 5);

        let canon = canonical_initial_deck();
        let perm1: [usize; 18] = [2, 0, 1, 3, 4, 7, 5, 6, 8, 9, 14, 10, 11, 12, 13, 15, 16, 17];
        let shuf1 = build_shuffle_blob(
            &cid,
            1,
            &bsec.epoch_pk,
            &[(0, 5), (5, 5), (10, 8)],
            18,
            &canon,
            &perm1,
            11,
        );

        let cd_open = CallEncoder::<8192>::new(selector(
            "openAndClaimCase(bytes32,uint64,address,bytes,uint64,bytes)",
        ))
        .push_bytes32(&cid)
        .push_u64(0)
        .push_address(&[0x11; 20])
        .push_u64(192)
        .push_u64(1)
        .push_u64((192 + 32 + SEAT_KEY_BLOB_LEN) as u64)
        .push_dynamic_bytes_tail(&s0.key_blob)
        .push_dynamic_bytes_tail(&shuf1)
        .as_slice()
        .to_vec();
        mock::transact_as(HUMAN, TRIB_ADDR, &cd_open).unwrap();

        // Self-co-shuffling by `HUMAN` MUST revert (`Err(-21)`)!
        let cd_deck = CallEncoder::<128>::new(selector("getDeckCiphertexts(bytes32)"))
            .push_bytes32(&cid)
            .as_slice()
            .to_vec();
        let deck1 = mock::transact_as(AI1, TRIB_ADDR, &cd_deck).unwrap();

        let mut fillers = Vec::with_capacity(4 * FILLER_SEAT_STRIDE);
        for (idx, ai_s) in [(1u8, &s1), (2, &s2), (3, &s3), (4, &s4)] {
            fillers.push(idx);
            fillers.extend_from_slice(&ai_s.eoa);
            fillers.extend_from_slice(&[0x30 + idx; 20]);
            fillers.extend_from_slice(&ai_s.key_blob);
        }

        // Identity permutation in Shuffle #2 -> combined Vault is `(perm1[0]=2, perm1[5]=7, perm1[10]=14)`!
        let perm2: [usize; 18] = core::array::from_fn(|i| i);
        let shuf2 = build_shuffle_blob(
            &cid,
            2,
            &bsec.epoch_pk,
            &[(0, 5), (5, 5), (10, 8)],
            18,
            &deck1,
            &perm2,
            22,
        );
        let mut pool_in = [0u8; 15 * 64];
        pool_in[0..4 * 64].copy_from_slice(&shuf2[1 * 64..5 * 64]);
        pool_in[4 * 64..8 * 64].copy_from_slice(&shuf2[6 * 64..10 * 64]);
        pool_in[8 * 64..15 * 64].copy_from_slice(&shuf2[11 * 64..18 * 64]);

        let perm_pool: [usize; 15] = [14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let shuf_pool = build_shuffle_blob(
            &cid,
            3,
            &bsec.epoch_pk,
            &[(0, 15)],
            15,
            &pool_in,
            &perm_pool,
            33,
        );

        let pad32 = |n: usize| (n + 31) & !31;
        let off1 = 128usize;
        let off2 = off1 + 32 + pad32(fillers.len());
        let off3 = off2 + 32 + pad32(shuf2.len());
        let cd_coshuf = CallEncoder::<16384>::new(selector(
            "coShuffleAndDeal(bytes32,bytes,bytes,bytes)",
        ))
        .push_bytes32(&cid)
        .push_u64(off1 as u64)
        .push_u64(off2 as u64)
        .push_u64(off3 as u64)
        .push_dynamic_bytes_tail(&fillers)
        .push_dynamic_bytes_tail(&shuf2)
        .push_dynamic_bytes_tail(&shuf_pool)
        .as_slice()
        .to_vec();

        assert_eq!(mock::transact_as(HUMAN, TRIB_ADDR, &cd_coshuf), Err(-21));
        mock::transact_as(AI1, TRIB_ADDR, &cd_coshuf).unwrap();

        // 3. Validators fulfill DDH-blinded hand decryptions -> `PHASE_ACTIVE`!
        flush_beacon_callbacks();

        let cd_state = CallEncoder::<128>::new(selector("getCaseState(bytes32)"))
            .push_bytes32(&cid)
            .as_slice()
            .to_vec();
        let st = mock::transact_as(HUMAN, TRIB_ADDR, &cd_state).unwrap();
        assert_eq!(st[0], PHASE_ACTIVE);

        // Decrypt all 5 seats' 3 cards locally using ONLY each seat's `u_sk`!
        let all_s = [&s0, &s1, &s2, &s3, &s4];
        let epk_pt = CompressedEdwardsY(bsec.epoch_pk).decompress().unwrap();
        let mut hands = [[0u8; 3]; 5];
        for seat_i in 0..5 {
            let sr = SeatRec::decode(
                st[HDR_LEN + seat_i * SEAT_LEN..HDR_LEN + (seat_i + 1) * SEAT_LEN]
                    .try_into()
                    .unwrap(),
            );
            for k in 0..3 {
                let m_prime = CompressedEdwardsY(sr.blinded_decrypts[k]).decompress().unwrap();
                let c_pt = m_prime + all_s[seat_i].u_sk[k] * epk_pt;
                let c_b = c_pt.compress().to_bytes();
                let card = (0..18u8)
                    .find(|&cand| card_basepoint(cand).unwrap() == c_b)
                    .expect("valid card 0..17");
                hands[seat_i][k] = card;
            }
        }
        // Check Vault `(2, 7, 14)` is NOT held by ANY of the 5 players!
        for h in &hands {
            assert!(!h.contains(&2) && !h.contains(&7) && !h.contains(&14));
        }

        // 4. Seat 0 (`HUMAN`, at sector 10 -> 17) probes `(2, 7, 17)`:
        //    Check `hands[0]` = `[17, 0, 1]`, `hands[1]` = `[3, 4, 5]`, `hands[2]` = `[6, 8, 9]`!
        //    Wait: let's probe `(3, 7, 17)` so Seat 1 (`hands[1] = [3, 4, 5]`) holds `3`!
        let cd_probe1 = CallEncoder::<256>::new(selector(
            "submitForensicProbe(bytes32,uint64,uint64,uint64)",
        ))
        .push_bytes32(&cid)
        .push_u64(3)
        .push_u64(7)
        .push_u64(17)
        .as_slice()
        .to_vec();
        mock::transact_as(HUMAN, TRIB_ADDR, &cd_probe1).unwrap();

        // CHEAT TEST A: Seat 1 (`AI1`, holding card `3`) tries to `passAlibiCheck` using forged/borrowed proof -> MUST REVERT `-38`!
        let fake_pass = build_pass_r1cs_proof(&cid, 0, 1, [0, 4, 5], &s1.w_sk, [3, 7, 17]).unwrap();
        let cd_cheat_pass = CallEncoder::<1024>::new(selector("passAlibiCheck(bytes32,bytes)"))
            .push_bytes32(&cid)
            .push_u64(64)
            .push_dynamic_bytes_tail(&fake_pass)
            .as_slice()
            .to_vec();
        assert_eq!(mock::transact_as(AI1, TRIB_ADDR, &cd_cheat_pass), Err(-38));

        // CHEAT TEST B: Seat 1 tries to whisper non-matching slot `1` (card `4`) -> cannot even build OR-proof, and corrupted proof reverts `-39`!
        let mut valid_whisper =
            build_whisper_or3_proof(&cid, 0, 1, 0, 0, 3, &s1.w_sk[0], &s0.ed_pk, [3, 7, 17])
                .unwrap();
        valid_whisper[100] ^= 1;
        let cd_bad_whisper =
            CallEncoder::<1024>::new(selector("transmitAlibiProof(bytes32,uint64,bytes)"))
                .push_bytes32(&cid)
                .push_u64(0)
                .push_u64(96)
                .push_dynamic_bytes_tail(&valid_whisper)
                .as_slice()
                .to_vec();
        assert_eq!(mock::transact_as(AI1, TRIB_ADDR, &cd_bad_whisper), Err(-39));

        // HONEST WHISPER: Seat 1 whispers matching slot `0` (card `3`) -> succeeds, and Seat 0 decrypts `3`!
        valid_whisper[100] ^= 1;
        let cd_ok_whisper =
            CallEncoder::<1024>::new(selector("transmitAlibiProof(bytes32,uint64,bytes)"))
                .push_bytes32(&cid)
                .push_u64(0)
                .push_u64(96)
                .push_dynamic_bytes_tail(&valid_whisper)
                .as_slice()
                .to_vec();
        mock::transact_as(AI1, TRIB_ADDR, &cd_ok_whisper).unwrap();

        let e1 = CompressedEdwardsY(valid_whisper[0..32].try_into().unwrap())
            .decompress()
            .unwrap();
        let e2 = CompressedEdwardsY(valid_whisper[32..64].try_into().unwrap())
            .decompress()
            .unwrap();
        let dec_whisper = (e2 - s0.ed_sk * e1).compress().to_bytes();
        assert_eq!(dec_whisper, card_basepoint(3).unwrap());

        // 5. Seat 1's turn (`turn_seat == 1`): Seat 1 probes `(2, 7, 11)` (`11` is Seat 1's starting sector? Wait: Seat 1 wasn't pulled, starting sector is `11`, move `11 -> 12`!)
        let cd_probe2 = CallEncoder::<256>::new(selector(
            "submitForensicProbe(bytes32,uint64,uint64,uint64)",
        ))
        .push_bytes32(&cid)
        .push_u64(2)
        .push_u64(7)
        .push_u64(12)
        .as_slice()
        .to_vec();
        mock::transact_as(AI1, TRIB_ADDR, &cd_probe2).unwrap();

        // Seat 2 (`hands[2] = [6, 8, 9]`) holds NONE of `(2, 7, 12)` -> honest Bulletproofs R1CS `passAlibiCheck` SUCCEEDS!
        let ok_pass =
            build_pass_r1cs_proof(&cid, 1, 2, hands[2], &s2.w_sk, [2, 7, 12]).unwrap();
        let cd_ok_pass = CallEncoder::<1024>::new(selector("passAlibiCheck(bytes32,bytes)"))
            .push_bytes32(&cid)
            .push_u64(64)
            .push_dynamic_bytes_tail(&ok_pass)
            .as_slice()
            .to_vec();
        mock::transact_as(AI2, TRIB_ADDR, &cd_ok_pass).unwrap();

        // Seat 3 holds `12` -> find exact slot and whisper `12` to Seat 1!
        let slot_12 = hands[3].iter().position(|&c| c == 12).expect("seat 3 holds 12");
        let w_s3 = build_whisper_or3_proof(
            &cid,
            1,
            3,
            1,
            slot_12 as u8,
            12,
            &s3.w_sk[slot_12],
            &s1.ed_pk,
            [2, 7, 12],
        )
        .unwrap();
        let cd_w_s3 =
            CallEncoder::<1024>::new(selector("transmitAlibiProof(bytes32,uint64,bytes)"))
                .push_bytes32(&cid)
                .push_u64(slot_12 as u64)
                .push_u64(96)
                .push_dynamic_bytes_tail(&w_s3)
                .as_slice()
                .to_vec();
        mock::transact_as(AI3, TRIB_ADDR, &cd_w_s3).unwrap();

        // 6. Seat 2's turn (`turn_seat == 2`): files a WRONG Indictment `(2, 7, 15)` (partial 2-of-3 match!) -> Refuted with 0 bits leaked!
        let st_mid = mock::transact_as(HUMAN, TRIB_ADDR, &cd_state).unwrap();
        let hdr_mid = CaseHeader::decode(st_mid[0..HDR_LEN].try_into().unwrap());
        let d0_wrong =
            compute_indictment_delta0(&cid, &hdr_mid.vault_ciphertexts, [2, 7, 15]).unwrap();
        let b1_wrong = build_indict_blind_blob(&cid, 1, &bsec.epoch_pk, &d0_wrong, 401);
        let cd_ind_wrong = CallEncoder::<512>::new(selector(
            "fileIndictment(bytes32,uint64,uint64,uint64,bytes)",
        ))
        .push_bytes32(&cid)
        .push_u64(2)
        .push_u64(7)
        .push_u64(15)
        .push_u64(160)
        .push_dynamic_bytes_tail(&b1_wrong)
        .as_slice()
        .to_vec();
        mock::transact_as(AI2, TRIB_ADDR, &cd_ind_wrong).unwrap();

        let mut d1_wrong = [0u8; 64];
        d1_wrong.copy_from_slice(&b1_wrong[0..64]);
        let b2_wrong = build_indict_blind_blob(&cid, 2, &bsec.epoch_pk, &d1_wrong, 502);
        let cd_cob_wrong =
            CallEncoder::<512>::new(selector("coBlindIndictment(bytes32,bytes)"))
                .push_bytes32(&cid)
                .push_u64(64)
                .push_dynamic_bytes_tail(&b2_wrong)
                .as_slice()
                .to_vec();
        // Self-co-blinding by `AI2` MUST revert (`Err(-21)`)!
        assert_eq!(mock::transact_as(AI2, TRIB_ADDR, &cd_cob_wrong), Err(-21));
        mock::transact_as(AI3, TRIB_ADDR, &cd_cob_wrong).unwrap();
        flush_beacon_callbacks();

        let st_ref = mock::transact_as(HUMAN, TRIB_ADDR, &cd_state).unwrap();
        assert_eq!(st_ref[0], PHASE_ACTIVE);
        assert_eq!(st_ref[1], 3); // Advanced to Seat 3 (`AI3`), Seat 2 revoked!

        // 7. Seat 3 (`AI3`) files the EXACT Vault Indictment `(2, 7, 14)` -> Threshold Zero-Check solves Case!
        let d0_win =
            compute_indictment_delta0(&cid, &hdr_mid.vault_ciphertexts, [2, 7, 14]).unwrap();
        let b1_win = build_indict_blind_blob(&cid, 1, &bsec.epoch_pk, &d0_win, 601);
        let cd_ind_win = CallEncoder::<512>::new(selector(
            "fileIndictment(bytes32,uint64,uint64,uint64,bytes)",
        ))
        .push_bytes32(&cid)
        .push_u64(2)
        .push_u64(7)
        .push_u64(14)
        .push_u64(160)
        .push_dynamic_bytes_tail(&b1_win)
        .as_slice()
        .to_vec();
        mock::transact_as(AI3, TRIB_ADDR, &cd_ind_win).unwrap();

        let mut d1_win = [0u8; 64];
        d1_win.copy_from_slice(&b1_win[0..64]);
        let b2_win = build_indict_blind_blob(&cid, 2, &bsec.epoch_pk, &d1_win, 702);
        let cd_cob_win =
            CallEncoder::<512>::new(selector("coBlindIndictment(bytes32,bytes)"))
                .push_bytes32(&cid)
                .push_u64(64)
                .push_dynamic_bytes_tail(&b2_win)
                .as_slice()
                .to_vec();
        mock::transact_as(AI4, TRIB_ADDR, &cd_cob_win).unwrap();
        flush_beacon_callbacks();

        let st_fin = mock::transact_as(HUMAN, TRIB_ADDR, &cd_state).unwrap();
        assert_eq!(st_fin[0], PHASE_SOLVED);
        assert_eq!(st_fin[11], 3); // winner_seat == 3
        assert_eq!(st_fin[12..15], [2, 7, 14]);
    }
}
