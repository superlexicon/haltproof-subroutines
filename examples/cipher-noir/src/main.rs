//! # Cipher Noir: Zero-Knowledge Vault Sabotage Tribunal (`cipher-noir` — HPS #16)
//!
//! 100% original SuperLexicon cyber-espionage deduction Haltproof Subroutine:
//! 1. **18 Sabotage Dossiers (`5 Operatives + 5 Sabotage Exploits + 8 Clearinghouse Sectors`)**:
//!    - `3` Incident Vectors (`1` Operative, `1` Exploit, `1` Sector) are sealed inside a salted
//!      `keccak256` **Case Vault Commitment** (`NOIR_VAULT_V1`).
//!    - `15` Cleared Alibi Dossiers (`3` per seat across `5` Syndicate Operative Seats) are committed
//!      individually (`NOIR_DOSSIER_V1`) and delivered on-chain via **`secp256k1` ECDH** stream ciphertexts.
//! 2. **Private 1-to-1 Alibi Proof Whispers (`transmitAlibiProof`)**:
//!    - When an Operative runs a 3-Vector **Forensic Probe**, neighbors clockwise either declare a public
//!      `NoAlibiMatch` pass or transmit a 36-byte ECDH-encrypted Alibi Proof readable *only* by the
//!      probing Operative — verified client-side against on-chain `dossier_commits` while keeping the
//!      revealed dossier hidden from all other bystanders!
//! 3. **Cheat-Proof On-Chain Vault Verification (`verifyIndictment`)**:
//!    - Winning indictments (and full-elimination unveils) require the Cryptographic Arbiter to supply
//!      `(operative, exploit, sector, vaultSalt)` matching `keccak256("NOIR_VAULT_V1" || ...)` **on-chain**.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

pub const SEAT_COUNT: usize = 5;
pub const DOSSIERS_PER_SEAT: usize = 3;
pub const OPERATIVE_CARD_START: u8 = 0;
pub const OPERATIVE_CARD_END: u8 = 4;   // 0..=4 (5 Operatives)
pub const EXPLOIT_CARD_START: u8 = 5;
pub const EXPLOIT_CARD_END: u8 = 9;     // 5..=9 (5 Sabotage Exploits)
pub const SECTOR_CARD_START: u8 = 10;
pub const SECTOR_CARD_END: u8 = 17;     // 10..=17 (8 Clearinghouse Sectors)
pub const TOTAL_DOSSIERS: usize = 18;

pub const PHASE_LOBBY: u8 = 1;
pub const PHASE_ACTIVE: u8 = 2;
pub const PHASE_PROBE_PENDING: u8 = 3;
pub const PHASE_INDICTMENT_PENDING: u8 = 4;
pub const PHASE_SOLVED: u8 = 5;

pub const TURN_TIMEOUT_BLOCKS: u64 = 15;
pub const LOG_WINDOW: usize = 16;

/// Starting Facility Sectors for the 5 Operative Seats (`10..=17`).
pub const STARTING_SECTORS: [u8; SEAT_COUNT] = [10, 11, 13, 15, 17];

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
        // Staying in the same sector is permitted if pulled here since your last turn!
        return was_pulled;
    }
    // Quantum Pneumatic Transit Tubes between opposite corners of the 2x4 Clearinghouse
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
const EV_VAULT_SEALED: [u8; 32] = event_topic("VaultSealed(bytes32,bytes32,uint64)");
const EV_PROBE_SUBMITTED: [u8; 32] =
    event_topic("ProbeSubmitted(bytes32,uint64,uint64,uint64,uint64,uint64,uint64)");
const EV_ALIBI_PASSED: [u8; 32] =
    event_topic("AlibiPassed(bytes32,uint64,uint64,uint64)");
const EV_ALIBI_TRANSMITTED: [u8; 32] =
    event_topic("AlibiTransmitted(bytes32,uint64,uint64,uint64,uint64,bytes32,uint64)");
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
    "getActiveCaseId()"                                                           => handle_get_active_case_id,
    "getOperativeWins(address)"                                                   => handle_get_operative_wins,
    "openCase(bytes32,address)"                                                   => handle_open_case,
    "claimOperativeSeat(bytes32,uint64,address,bytes32,bytes32)"                  => handle_claim_seat,
    "openAndClaimCase(bytes32,uint64,address,bytes32,bytes32,uint64)"             => handle_open_and_claim,
    "requestVaultDeal(bytes32)"                                                   => handle_request_deal,
    "sealVaultAndDeal(bytes32,bytes)"                                             => handle_seal_and_deal,
    "submitForensicProbe(bytes32,uint64,uint64,uint64)"                           => handle_submit_probe,
    "passAlibiCheck(bytes32)"                                                     => handle_pass_alibi,
    "transmitAlibiProof(bytes32,uint64,bytes)"                                    => handle_transmit_alibi,
    "fileIndictment(bytes32,uint64,uint64,uint64)"                                => handle_file_indictment,
    "verifyIndictment(bytes32,uint64,uint64,uint64,uint64,bytes32)"               => handle_verify_indictment,
    "advanceTimedOutTurn(bytes32)"                                                => handle_advance_timeout,
    "getCaseState(bytes32)"                                                       => handle_get_case_state,
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
    arbiter_pub_x: [u8; 32],
    arbiter_pub_y: [u8; 32],
    vault_commit: [u8; 32],
}

const HDR_LEN: usize = 128;

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
        b[32..64].copy_from_slice(&self.arbiter_pub_x);
        b[64..96].copy_from_slice(&self.arbiter_pub_y);
        b[96..128].copy_from_slice(&self.vault_commit);
        b
    }

    fn decode(b: &[u8; HDR_LEN]) -> Self {
        let mut px = [0u8; 32];
        px.copy_from_slice(&b[32..64]);
        let mut py = [0u8; 32];
        py.copy_from_slice(&b[64..96]);
        let mut vc = [0u8; 32];
        vc.copy_from_slice(&b[96..128]);
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
            arbiter_pub_x: px,
            arbiter_pub_y: py,
            vault_commit: vc,
        }
    }
}

#[derive(Clone, Copy)]
struct SeatRec {
    occupied: u8,   // 0=empty, 1=human, 2=AI
    revoked: u8,    // 1=indictment failed (clearance revoked, still responds to alibi checks)
    sector_id: u8,  // 10..=17
    flags: u8,      // bit 0 = pulled_by_probe
    eoa: [u8; 20],
    identity_addr: [u8; 20],
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    dossier_commits: [[u8; 32]; DOSSIERS_PER_SEAT],
    encrypted_hand: [u8; 108],
}

const SEAT_LEN: usize = 312;

impl SeatRec {
    fn empty(seat_idx: usize) -> Self {
        Self {
            occupied: 0,
            revoked: 0,
            sector_id: STARTING_SECTORS[seat_idx % SEAT_COUNT],
            flags: 0,
            eoa: [0u8; 20],
            identity_addr: [0u8; 20],
            pub_x: [0u8; 32],
            pub_y: [0u8; 32],
            dossier_commits: [[0u8; 32]; DOSSIERS_PER_SEAT],
            encrypted_hand: [0u8; 108],
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
        b[44..76].copy_from_slice(&self.pub_x);
        b[76..108].copy_from_slice(&self.pub_y);
        b[108..140].copy_from_slice(&self.dossier_commits[0]);
        b[140..172].copy_from_slice(&self.dossier_commits[1]);
        b[172..204].copy_from_slice(&self.dossier_commits[2]);
        b[204..312].copy_from_slice(&self.encrypted_hand);
        b
    }

    fn decode(b: &[u8; SEAT_LEN]) -> Self {
        let mut eoa = [0u8; 20];
        eoa.copy_from_slice(&b[4..24]);
        let mut id = [0u8; 20];
        id.copy_from_slice(&b[24..44]);
        let mut px = [0u8; 32];
        px.copy_from_slice(&b[44..76]);
        let mut py = [0u8; 32];
        py.copy_from_slice(&b[76..108]);
        let mut dc = [[0u8; 32]; DOSSIERS_PER_SEAT];
        dc[0].copy_from_slice(&b[108..140]);
        dc[1].copy_from_slice(&b[140..172]);
        dc[2].copy_from_slice(&b[172..204]);
        let mut eh = [0u8; 108];
        eh.copy_from_slice(&b[204..312]);
        Self {
            occupied: b[0],
            revoked: b[1],
            sector_id: b[2],
            flags: b[3],
            eoa,
            identity_addr: id,
            pub_x: px,
            pub_y: py,
            dossier_commits: dc,
            encrypted_hand: eh,
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
    status: u8, // 0=pending, 1=disproved via ECDH proof, 2=unrefuted around table
    cipher36: [u8; 36],
}

const LOG_ENTRY_LEN: usize = 46;

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
        b[10..46].copy_from_slice(&self.cipher36);
        b
    }

    fn decode(b: &[u8; LOG_ENTRY_LEN]) -> Self {
        let mut c = [0u8; 36];
        c.copy_from_slice(&b[10..46]);
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
            cipher36: c,
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Keys & Helpers
// ---------------------------------------------------------------------------

const KEY_DEFAULT_ARBITER: &[u8] = b"n:def_arbiter";
const KEY_ACTIVE_CASE: &[u8] = b"n:active_case";

fn key_hdr(cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:hdr:").push(cid)
}

fn key_arbiter(cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:arb:").push(cid)
}

fn key_seat(cid: &[u8; 32], seat: u8) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:seat:").push(cid).push(&[seat])
}

fn key_log(cid: &[u8; 32], slot: u8) -> KeyBuilder<64> {
    KeyBuilder::new().push(b"n:log:").push(cid).push(&[slot])
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

fn compute_vault_commit(
    cid: &[u8; 32],
    operative: u8,
    exploit: u8,
    sector: u8,
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = [0u8; 80];
    preimage[0..13].copy_from_slice(b"NOIR_VAULT_V1");
    preimage[13..45].copy_from_slice(cid);
    preimage[45] = operative;
    preimage[46] = exploit;
    preimage[47] = sector;
    preimage[48..80].copy_from_slice(salt);
    keccak256(&preimage)
}

// ---------------------------------------------------------------------------
// Entrypoint Implementations
// ---------------------------------------------------------------------------

fn handle_init_tribunal(args: &CalldataReader) -> Result<i32, i32> {
    let arb = args.address(0).ok_or(-10)?;
    if arb == [0u8; 20] {
        return Err(-11);
    }
    if let Some(existing) = storage::get_address(KEY_DEFAULT_ARBITER) {
        if existing != [0u8; 20] && context::msg_sender() != existing {
            return Err(-12);
        }
    }
    storage::set_address(KEY_DEFAULT_ARBITER, &arb);
    ret::write_u64_word(1);
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

fn open_case_internal(cid: &[u8; 32], explicit_arb: [u8; 20]) -> Result<(), i32> {
    if *cid == [0u8; 32] {
        return Err(-11);
    }
    if load_hdr(cid).is_some() {
        return Err(-13);
    }
    let def_arb = storage::get_address(KEY_DEFAULT_ARBITER).unwrap_or([0u8; 20]);
    let arb = if explicit_arb != [0u8; 20] {
        explicit_arb
    } else {
        def_arb
    };
    if arb == [0u8; 20] {
        return Err(-14);
    }
    if def_arb == [0u8; 20] {
        storage::set_address(KEY_DEFAULT_ARBITER, &arb);
    }

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
        arbiter_pub_x: [0u8; 32],
        arbiter_pub_y: [0u8; 32],
        vault_commit: [0u8; 32],
    };
    save_hdr(cid, &hdr);
    storage::set_address(key_arbiter(cid).as_slice(), &arb);
    let mut s = 0;
    while s < SEAT_COUNT {
        save_seat(cid, s as u8, &SeatRec::empty(s));
        s += 1;
    }
    storage::set(KEY_ACTIVE_CASE, cid);

    let mut ev = [0u8; 32];
    push_u64_word(&mut ev, 0, blk);
    events::emit(&[EV_CASE_OPENED, *cid, addr_topic(&arb)], &ev);
    Ok(())
}

fn handle_open_case(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let arb = args.address(1).ok_or(-10)?;
    open_case_internal(&cid, arb)?;
    ret::write_u64_word(1);
    Ok(32)
}

fn claim_seat_internal(
    cid: &[u8; 32],
    caller: [u8; 20],
    preferred: u64,
    identity_addr: [u8; 20],
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    deal_now: bool,
) -> Result<u8, i32> {
    if pub_x == [0u8; 32] || pub_y == [0u8; 32] {
        return Err(-15);
    }
    let mut hdr = load_hdr(cid).ok_or(-16)?;
    if hdr.phase != PHASE_LOBBY {
        return Err(-17);
    }

    // Check if caller already claimed a seat in this case
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
    rec.occupied = 1; // Human Operative
    rec.revoked = 0;
    rec.sector_id = STARTING_SECTORS[chosen as usize];
    rec.flags = 0;
    rec.eoa = caller;
    rec.identity_addr = identity_addr;
    rec.pub_x = pub_x;
    rec.pub_y = pub_y;
    save_seat(cid, chosen, &rec);

    if deal_now {
        hdr.deal_requested = 1;
    }
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(cid, &hdr);

    let mut ev = [0u8; 64];
    push_u64_word(&mut ev, 0, chosen as u64);
    push_u64_word(&mut ev, 1, hdr.deal_requested as u64);
    events::emit(&[EV_SEAT_CLAIMED, *cid, addr_topic(&caller)], &ev);

    Ok(chosen)
}

fn handle_claim_seat(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let pref = args.u64(1).ok_or(-10)?;
    let id_addr = args.address(2).ok_or(-10)?;
    let px = args.bytes32(3).ok_or(-10)?;
    let py = args.bytes32(4).ok_or(-10)?;
    let seat = claim_seat_internal(&cid, context::msg_sender(), pref, id_addr, px, py, false)?;
    ret::write_u64_word(seat as u64);
    Ok(32)
}

fn handle_open_and_claim(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let pref = args.u64(1).ok_or(-10)?;
    let id_addr = args.address(2).ok_or(-10)?;
    let px = args.bytes32(3).ok_or(-10)?;
    let py = args.bytes32(4).ok_or(-10)?;
    let deal_now = args.u64(5).ok_or(-10)? != 0;

    if load_hdr(&cid).is_none() {
        open_case_internal(&cid, [0u8; 20])?;
    }
    let seat = claim_seat_internal(&cid, context::msg_sender(), pref, id_addr, px, py, deal_now)?;
    ret::write_u64_word(seat as u64);
    Ok(32)
}

fn handle_request_deal(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_LOBBY {
        return Err(-17);
    }
    hdr.deal_requested = 1;
    save_hdr(&cid, &hdr);
    ret::write_u64_word(1);
    Ok(32)
}

/// Payload layout (`96 + 5 * 308 = 1636` bytes):
/// - `0..32`: `arbiter_pub_x`
/// - `32..64`: `arbiter_pub_y`
/// - `64..96`: `vault_commit`
/// - For each seat `0..5` (`308` bytes):
///   - `0..20`: `expected_or_ai_eoa`
///   - `20..40`: `ai_identity`
///   - `40..72`: `ai_pub_x`
///   - `72..104`: `ai_pub_y`
///   - `104..200`: `dossier_commits` (`3 * 32`)
///   - `200..308`: `encrypted_hand` (`108`)
fn handle_seal_and_deal(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let payload = args.dynamic_bytes(1).ok_or(-10)?;
    if payload.len() != 96 + SEAT_COUNT * 308 {
        return Err(-20);
    }

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_LOBBY {
        return Err(-17);
    }
    let arb = storage::get_address(key_arbiter(&cid).as_slice()).ok_or(-14)?;
    if context::msg_sender() != arb {
        return Err(-21);
    }

    hdr.arbiter_pub_x.copy_from_slice(&payload[0..32]);
    hdr.arbiter_pub_y.copy_from_slice(&payload[32..64]);
    hdr.vault_commit.copy_from_slice(&payload[64..96]);
    if hdr.vault_commit == [0u8; 32] {
        return Err(-22);
    }

    let mut first_human: Option<u8> = None;
    let mut s = 0usize;
    while s < SEAT_COUNT {
        let base = 96 + s * 308;
        let mut exp_eoa = [0u8; 20];
        exp_eoa.copy_from_slice(&payload[base..base + 20]);

        let mut seat = load_seat(&cid, s as u8);
        if seat.occupied != 0 {
            // Optimistic concurrency check: prevent dealing AI-encrypted hand to a human who claimed seat in same block!
            if seat.eoa != exp_eoa {
                return Err(-49);
            }
            if seat.occupied == 1 && first_human.is_none() {
                first_human = Some(s as u8);
            }
        } else {
            if exp_eoa == [0u8; 20] {
                return Err(-23);
            }
            seat.occupied = 2; // AI Syndicate Operative
            seat.revoked = 0;
            seat.sector_id = STARTING_SECTORS[s];
            seat.flags = 0;
            seat.eoa = exp_eoa;
            seat.identity_addr.copy_from_slice(&payload[base + 20..base + 40]);
            seat.pub_x.copy_from_slice(&payload[base + 40..base + 72]);
            seat.pub_y.copy_from_slice(&payload[base + 72..base + 104]);
        }

        seat.dossier_commits[0].copy_from_slice(&payload[base + 104..base + 136]);
        seat.dossier_commits[1].copy_from_slice(&payload[base + 136..base + 168]);
        seat.dossier_commits[2].copy_from_slice(&payload[base + 168..base + 200]);
        seat.encrypted_hand.copy_from_slice(&payload[base + 200..base + 308]);
        save_seat(&cid, s as u8, &seat);
        s += 1;
    }

    let blk = context::block_number();
    hdr.phase = PHASE_ACTIVE;
    hdr.turn_seat = first_human.unwrap_or(0);
    hdr.deadline_block = blk.saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let mut ev = [0u8; 32];
    push_u64_word(&mut ev, 0, hdr.turn_seat as u64);
    events::emit(&[EV_VAULT_SEALED, cid, hdr.vault_commit], &ev);

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

    // Pull named Operative seat (`op_u64`) into `target_sec` if distinct from `turn`
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
        cipher36: [0u8; 36],
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

fn advance_responder_on_pass(cid: &[u8; 32], hdr: &mut CaseHeader) {
    let cur = hdr.responder_seat;
    let cur_probe_idx = hdr.probe_count.saturating_sub(1);
    if let Some(mut entry) = load_log_slot(cid, cur_probe_idx) {
        if entry.probe_idx == cur_probe_idx {
            entry.pass_mask |= 1u8 << cur;
            let next_resp = ((cur as usize + 1) % SEAT_COUNT) as u8;
            if next_resp == hdr.prober_seat {
                entry.status = 2; // Unrefuted around the entire table!
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
    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_PROBE_PENDING {
        return Err(-34);
    }
    let resp = load_seat(&cid, hdr.responder_seat);
    if resp.occupied == 0 || resp.eoa != context::msg_sender() {
        return Err(-35);
    }
    advance_responder_on_pass(&cid, &mut hdr);
    ret::write_u64_word(1);
    Ok(32)
}

fn handle_transmit_alibi(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let slot_idx = args.u64(1).ok_or(-10)?;
    let cipher = args.dynamic_bytes(2).ok_or(-10)?;

    if slot_idx >= (DOSSIERS_PER_SEAT as u64) || cipher.len() != 36 {
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

    let cur_probe_idx = hdr.probe_count.saturating_sub(1);
    let mut entry = load_log_slot(&cid, cur_probe_idx).ok_or(-37)?;
    if entry.probe_idx != cur_probe_idx {
        return Err(-37);
    }

    entry.disprover_seat = resp_seat;
    entry.disprover_slot = slot_idx as u8;
    entry.status = 1;
    entry.cipher36.copy_from_slice(cipher);
    save_log_slot(&cid, &entry);

    let prober = hdr.prober_seat;
    hdr.phase = PHASE_ACTIVE;
    hdr.responder_seat = 255;
    if let Some(nt) = next_active_turn_seat(&cid, hdr.turn_seat) {
        hdr.turn_seat = nt;
    }
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    // Emit 32+4 cipher bytes cleanly in static words (`cipher_head32` + `cipher_tail32`)
    let mut c_head = [0u8; 32];
    c_head.copy_from_slice(&cipher[0..32]);
    let mut tail_u32 = [0u8; 4];
    tail_u32.copy_from_slice(&cipher[32..36]);

    let mut ev = [0u8; 192];
    push_u64_word(&mut ev, 0, cur_probe_idx as u64);
    push_u64_word(&mut ev, 1, resp_seat as u64);
    push_u64_word(&mut ev, 2, prober as u64);
    push_u64_word(&mut ev, 3, slot_idx);
    ev[128..160].copy_from_slice(&c_head);
    push_u64_word(&mut ev, 5, u32::from_be_bytes(tail_u32) as u64);
    events::emit(&[EV_ALIBI_TRANSMITTED, cid], &ev);

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_file_indictment(args: &CalldataReader) -> Result<i32, i32> {
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
    let actor = load_seat(&cid, turn);
    if actor.occupied == 0 || actor.revoked != 0 || actor.eoa != context::msg_sender() {
        return Err(-32);
    }

    hdr.phase = PHASE_INDICTMENT_PENDING;
    hdr.indict_seat = turn;
    hdr.indict_operative = op_u64 as u8;
    hdr.indict_exploit = exp_u64 as u8;
    hdr.indict_sector = sec_u64 as u8;
    hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
    save_hdr(&cid, &hdr);

    let mut ev = [0u8; 128];
    push_u64_word(&mut ev, 0, turn as u64);
    push_u64_word(&mut ev, 1, op_u64);
    push_u64_word(&mut ev, 2, exp_u64);
    push_u64_word(&mut ev, 3, sec_u64);
    events::emit(&[EV_INDICTMENT_FILED, cid, addr_topic(&actor.eoa)], &ev);

    ret::write_u64_word(1);
    Ok(32)
}

fn handle_verify_indictment(args: &CalldataReader) -> Result<i32, i32> {
    let cid = args.bytes32(0).ok_or(-10)?;
    let is_match = args.u64(1).ok_or(-10)?;
    let sol_op = args.u64(2).ok_or(-10)? as u8;
    let sol_exp = args.u64(3).ok_or(-10)? as u8;
    let sol_sec = args.u64(4).ok_or(-10)? as u8;
    let vault_salt = args.bytes32(5).ok_or(-10)?;

    let mut hdr = load_hdr(&cid).ok_or(-16)?;
    if hdr.phase != PHASE_INDICTMENT_PENDING {
        return Err(-40);
    }
    let arb = storage::get_address(key_arbiter(&cid).as_slice()).ok_or(-14)?;
    if context::msg_sender() != arb {
        return Err(-21);
    }

    let seat_idx = hdr.indict_seat;
    let mut actor = load_seat(&cid, seat_idx);

    if is_match == 1 {
        // Must match the indicted tuple AND verify against `hdr.vault_commit` on-chain!
        if sol_op != hdr.indict_operative
            || sol_exp != hdr.indict_exploit
            || sol_sec != hdr.indict_sector
        {
            return Err(-41);
        }
        let recomputed = compute_vault_commit(&cid, sol_op, sol_exp, sol_sec, &vault_salt);
        if recomputed != hdr.vault_commit {
            return Err(-42); // Cheat-proof revert: vault commitment mismatch!
        }

        hdr.phase = PHASE_SOLVED;
        hdr.winner_seat = seat_idx;
        hdr.sol_operative = sol_op;
        hdr.sol_exploit = sol_exp;
        hdr.sol_sector = sol_sec;
        save_hdr(&cid, &hdr);

        let wins = storage::get_u64(key_wins(&actor.eoa).as_slice()).saturating_add(1);
        storage::set_u64(key_wins(&actor.eoa).as_slice(), wins);

        let mut ev = [0u8; 128];
        push_u64_word(&mut ev, 0, seat_idx as u64);
        push_u64_word(&mut ev, 1, sol_op as u64);
        push_u64_word(&mut ev, 2, sol_exp as u64);
        push_u64_word(&mut ev, 3, sol_sec as u64);
        events::emit(&[EV_CASE_SOLVED, cid, addr_topic(&actor.eoa)], &ev);

        ret::write_u64_word(1);
        return Ok(32);
    }

    // Wrong Indictment: revoke clearance for `seat_idx`
    actor.revoked = 1;
    save_seat(&cid, seat_idx, &actor);

    if let Some(nt) = next_active_turn_seat(&cid, seat_idx) {
        hdr.phase = PHASE_ACTIVE;
        hdr.turn_seat = nt;
        hdr.deadline_block = context::block_number().saturating_add(TURN_TIMEOUT_BLOCKS);
        save_hdr(&cid, &hdr);

        let mut ev = [0u8; 64];
        push_u64_word(&mut ev, 0, seat_idx as u64);
        push_u64_word(&mut ev, 1, nt as u64);
        events::emit(&[EV_INDICTMENT_REFUTED, cid], &ev);
    } else {
        // Every operative's clearance was revoked -> unveil Case Vault on-chain if salt provided
        let recomputed = compute_vault_commit(&cid, sol_op, sol_exp, sol_sec, &vault_salt);
        if recomputed != hdr.vault_commit {
            return Err(-42);
        }
        hdr.phase = PHASE_SOLVED;
        hdr.winner_seat = 255;
        hdr.sol_operative = sol_op;
        hdr.sol_exploit = sol_exp;
        hdr.sol_sector = sol_sec;
        save_hdr(&cid, &hdr);

        let mut ev = [0u8; 128];
        push_u64_word(&mut ev, 0, 255);
        push_u64_word(&mut ev, 1, sol_op as u64);
        push_u64_word(&mut ev, 2, sol_exp as u64);
        push_u64_word(&mut ev, 3, sol_sec as u64);
        events::emit(&[EV_CASE_SOLVED, cid, [0u8; 32]], &ev);
    }

    ret::write_u64_word(0);
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
        advance_responder_on_pass(&cid, &mut hdr);
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

// ---------------------------------------------------------------------------
// Native Unit Tests (`cargo test -p cipher-noir`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    const TRIB_ADDR: [u8; 20] = [0x61; 20];
    const ARBITER: [u8; 20] = [0x99; 20];
    const HUMAN: [u8; 20] = [0xA1; 20];
    const AI1: [u8; 20] = [0xB1; 20];
    const AI2: [u8; 20] = [0xB2; 20];
    const AI3: [u8; 20] = [0xB3; 20];
    const AI4: [u8; 20] = [0xB4; 20];

    #[test]
    fn full_sabotage_probe_alibi_and_vault_verification() {
        mock::reset();
        mock::register_hps(TRIB_ADDR, dispatch_calldata);
        mock::set_block_number(500);

        // 1. Init Tribunal with default Arbiter
        let cd_init = CallEncoder::<256>::new(selector("initTribunal(address)"))
            .push_address(&ARBITER)
            .as_slice()
            .to_vec();
        mock::transact_as(ARBITER, TRIB_ADDR, &cd_init).unwrap();

        // 2. Human opens & claims Seat 0 (Cipher Vex) in 1 transaction
        let cid = [0x42; 32];
        let cd_open = CallEncoder::<256>::new(selector(
            "openAndClaimCase(bytes32,uint64,address,bytes32,bytes32,uint64)",
        ))
        .push_bytes32(&cid)
        .push_u64(0)
        .push_address(&[0x11; 20])
        .push_bytes32(&[0x71; 32])
        .push_bytes32(&[0x72; 32])
        .push_u64(1)
        .as_slice()
        .to_vec();
        mock::transact_as(HUMAN, TRIB_ADDR, &cd_open).unwrap();

        // 3. Arbiter seals Case Vault (`op=2, exp=7, sec=14`) and deals 5 seats
        let vault_salt = [0xAB; 32];
        let vault_commit = compute_vault_commit(&cid, 2, 7, 14, &vault_salt);

        let mut payload = vec![0u8; 96 + SEAT_COUNT * 308];
        payload[0..32].copy_from_slice(&[0x81; 32]);
        payload[32..64].copy_from_slice(&[0x82; 32]);
        payload[64..96].copy_from_slice(&vault_commit);

        let seat_eoas = [HUMAN, AI1, AI2, AI3, AI4];
        for (i, eoa) in seat_eoas.iter().enumerate() {
            let base = 96 + i * 308;
            payload[base..base + 20].copy_from_slice(eoa);
            payload[base + 20..base + 40].copy_from_slice(&[0x33; 20]);
            payload[base + 40..base + 72].copy_from_slice(&[0x44; 32]);
            payload[base + 72..base + 104].copy_from_slice(&[0x55; 32]);
            payload[base + 104..base + 136].copy_from_slice(&[0x66; 32]);
        }

        let cd_deal = CallEncoder::<2048>::new(selector("sealVaultAndDeal(bytes32,bytes)"))
            .push_bytes32(&cid)
            .push_u64(64)
            .push_dynamic_bytes_tail(&payload)
            .as_slice()
            .to_vec();
        mock::transact_as(ARBITER, TRIB_ADDR, &cd_deal).unwrap();

        // 4. Human (at sector 10) uses Quantum Transit Tube (`10 -> 17`) and probes `(2, 7, 17)`
        let cd_probe = CallEncoder::<256>::new(selector(
            "submitForensicProbe(bytes32,uint64,uint64,uint64)",
        ))
        .push_bytes32(&cid)
        .push_u64(2)
        .push_u64(7)
        .push_u64(17)
        .as_slice()
        .to_vec();
        mock::transact_as(HUMAN, TRIB_ADDR, &cd_probe).unwrap();

        // 5. AI1 passes, AI2 transmits 36-byte ECDH alibi proof
        let cd_pass = CallEncoder::<256>::new(selector("passAlibiCheck(bytes32)"))
            .push_bytes32(&cid)
            .as_slice()
            .to_vec();
        mock::transact_as(AI1, TRIB_ADDR, &cd_pass).unwrap();

        let cipher36 = [0xEEu8; 36];
        let cd_whisper = CallEncoder::<256>::new(selector("transmitAlibiProof(bytes32,uint64,bytes)"))
            .push_bytes32(&cid)
            .push_u64(1)
            .push_u64(96)
            .push_dynamic_bytes_tail(&cipher36)
            .as_slice()
            .to_vec();
        mock::transact_as(AI2, TRIB_ADDR, &cd_whisper).unwrap();

        // 6. Now it is AI1's turn (`turn_seat == 1`): AI1 files winning Indictment `(2, 7, 14)`!
        let cd_indict =
            CallEncoder::<256>::new(selector("fileIndictment(bytes32,uint64,uint64,uint64)"))
                .push_bytes32(&cid)
                .push_u64(2)
                .push_u64(7)
                .push_u64(14)
                .as_slice()
                .to_vec();
        mock::transact_as(AI1, TRIB_ADDR, &cd_indict).unwrap();

        // Wrong salt MUST revert on-chain!
        let cd_bad_verify = CallEncoder::<256>::new(selector(
            "verifyIndictment(bytes32,uint64,uint64,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&cid)
        .push_u64(1)
        .push_u64(2)
        .push_u64(7)
        .push_u64(14)
        .push_bytes32(&[0x00; 32])
        .as_slice()
        .to_vec();
        assert_eq!(
            mock::transact_as(ARBITER, TRIB_ADDR, &cd_bad_verify),
            Err(-42)
        );

        // Authentic `vault_salt` succeeds and marks PHASE_SOLVED!
        let cd_ok_verify = CallEncoder::<256>::new(selector(
            "verifyIndictment(bytes32,uint64,uint64,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&cid)
        .push_u64(1)
        .push_u64(2)
        .push_u64(7)
        .push_u64(14)
        .push_bytes32(&vault_salt)
        .as_slice()
        .to_vec();
        mock::transact_as(ARBITER, TRIB_ADDR, &cd_ok_verify).unwrap();

        let cd_state = CallEncoder::<256>::new(selector("getCaseState(bytes32)"))
            .push_bytes32(&cid)
            .as_slice()
            .to_vec();
        let st = mock::transact_as(HUMAN, TRIB_ADDR, &cd_state).unwrap();
        assert_eq!(st[0], PHASE_SOLVED);
        assert_eq!(st[11], 1); // winner_seat == 1
        assert_eq!(st[12..15], [2, 7, 14]);
    }
}
