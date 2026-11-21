//! Quantum 4D Jackpot (`lottery`) — Provably-Fair Validator-Quorum Threshold VRF Lottery HPS.
//!
//! Showcases SuperLexicon's Wasmtime Validator-Quorum Random Number Generator (`vrf-beacon`):
//! - Players buy 4-digit tickets (`0000..=9999`) for `10 SGD` (`SGD-FIAT` via `Identity.transferBankBalance`):
//!   - `6 SGD` feeds the **100%-Rollover Grand Jackpot Pool** (exact 4D match `0000..=9999`),
//!   - `4 SGD` feeds the **Fixed-Odds Prize Reserve** (`3D = 250 SGD`, `2D = 40 SGD`, `1D = 15 SGD`).
//! - Every ticket updates a rolling `keccak256` commitment (`tickets_commitment`).
//! - Once `round_close_block` arrives, `closeAndRequestDraw()` freezes the round and requests
//!   threshold ECVRF randomness from `vrf-beacon` gated by `min_validators` active `Full` validators.
//! - When the BFT-safe supermajority (`t = N` for `N <= 4`, `⌊2N/3⌋ + 1` for `N >= 5`) submits
//!   Chaum-Pedersen DLEQ-verified partial VRF shares, `onVrfFulfilled` derives an unbiased `0000..=9999`
//!   winning 4D number via rejection sampling and **instantly transfers `SGD-FIAT` winnings** from
//!   `vaultIdentity` directly to every winning player's `Identity` account!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::require_valid_identity;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const TICKET_PRICE_SGD: u64 = 10;
pub const JACKPOT_CONTRIB_SGD: u64 = 6;
pub const RESERVE_CONTRIB_SGD: u64 = 4;

pub const PRIZE_3D_SGD: u64 = 250;
pub const PRIZE_2D_SGD: u64 = 40;
pub const PRIZE_1D_SGD: u64 = 15;

pub const MAX_PICKS_PER_TX: usize = 10;
pub const MAX_TICKETS_PER_ROUND: usize = 128;

pub const PHASE_OPEN: u8 = 1;
pub const PHASE_DRAWING: u8 = 2;

const EV_LOTTERY_INIT: [u8; 32] =
    event_topic("LotteryInitialized(address,address,address,uint64,uint64)");
const EV_POOLS_SEEDED: [u8; 32] = event_topic("LotteryPoolsSeeded(uint64,uint64,uint64,uint64)");
const EV_TICKETS_BOUGHT: [u8; 32] =
    event_topic("LotteryTicketsBought(uint64,address,uint64,uint64,bytes32)");
const EV_DRAW_REQUESTED: [u8; 32] =
    event_topic("LotteryDrawRequested(uint64,bytes32,uint64,uint64)");
const EV_ROUND_SETTLED: [u8; 32] =
    event_topic("LotteryRoundSettled(uint64,uint64,uint64,uint64,bytes32,bytes32)");
const EV_PRIZE_PAID: [u8; 32] = event_topic("LotteryPrizePaid(uint64,address,uint64,uint64)");

const KEY_INIT: &[u8] = b"lot:init";
const KEY_FIAT_LEDGER: &[u8] = b"lot:fiat";
const KEY_ID_REGISTRY: &[u8] = b"lot:idreg";
const KEY_VAULT_ID: &[u8] = b"lot:vault";
const KEY_VRF_BEACON: &[u8] = b"lot:beacon";
const KEY_MIN_VALS: &[u8] = b"lot:min_v";
const KEY_ROUND_BLOCKS: &[u8] = b"lot:r_blks";
const KEY_TITLE: &[u8] = b"lot:title";

const KEY_CUR_ROUND: &[u8] = b"lot:round";
const KEY_PHASE: &[u8] = b"lot:phase";
const KEY_OPEN_BLOCK: &[u8] = b"lot:open_b";
const KEY_CLOSE_BLOCK: &[u8] = b"lot:close_b";
const KEY_JACKPOT_POOL: &[u8] = b"lot:jp_pool";
const KEY_RESERVE_POOL: &[u8] = b"lot:rs_pool";
const KEY_TICKET_CNT: &[u8] = b"lot:t_cnt";
const KEY_COMMIT_ROOT: &[u8] = b"lot:commit";
const KEY_PENDING_REQ: &[u8] = b"lot:req_id";

const KEY_TOTAL_SOLD: &[u8] = b"lot:tot_sold";
const KEY_TOTAL_PAID: &[u8] = b"lot:tot_paid";
const KEY_SETTLED_CNT: &[u8] = b"lot:set_cnt";

hps_entry! {
    "initialize(address,address,address,address,uint64,uint64,string)"    => handle_initialize,
    "seedPools(uint64,uint64)"                                            => handle_seed_pools,
    "buyTickets(bytes)"                                                   => handle_buy_tickets,
    "closeAndRequestDraw()"                                               => handle_close_and_request_draw,
    "onVrfFulfilled(bytes32,bytes32,bytes32,uint64,uint64)"               => handle_on_vrf_fulfilled,
    "settleFromBeacon()"                                                  => handle_settle_from_beacon,
    "getLotteryState()"                                                   => handle_get_lottery_state,
    "getRoundInfo(uint64)"                                                => handle_get_round_info,
    "getRoundTickets(uint64)"                                             => handle_get_round_tickets,
    "getPlayerStats(address)"                                             => handle_get_player_stats,
    "hfsType()"                                                           => handle_hfs_type,
}

#[derive(Clone, Copy)]
struct RoundSummary {
    round_id: u64,
    winning_4d: u16,
    ticket_count: u32,
    w4d_count: u16,
    w3d_count: u16,
    w2d_count: u16,
    w1d_count: u16,
    jackpot_before: u64,
    total_paid: u64,
    settled_block: u64,
    epoch_id: u64,
    signer_bitmap: u64,
    req_id: [u8; 32],
    random_bytes: [u8; 32],
    gamma_bytes: [u8; 32],
    commit_root: [u8; 32],
}

impl RoundSummary {
    const BYTE_LEN: usize = 190;

    fn encode(&self) -> [u8; Self::BYTE_LEN] {
        let mut b = [0u8; Self::BYTE_LEN];
        b[0..8].copy_from_slice(&self.round_id.to_be_bytes());
        b[8..10].copy_from_slice(&self.winning_4d.to_be_bytes());
        b[10..14].copy_from_slice(&self.ticket_count.to_be_bytes());
        b[14..16].copy_from_slice(&self.w4d_count.to_be_bytes());
        b[16..18].copy_from_slice(&self.w3d_count.to_be_bytes());
        b[18..20].copy_from_slice(&self.w2d_count.to_be_bytes());
        b[20..22].copy_from_slice(&self.w1d_count.to_be_bytes());
        b[22..30].copy_from_slice(&self.jackpot_before.to_be_bytes());
        b[30..38].copy_from_slice(&self.total_paid.to_be_bytes());
        b[38..46].copy_from_slice(&self.settled_block.to_be_bytes());
        b[46..54].copy_from_slice(&self.epoch_id.to_be_bytes());
        b[54..62].copy_from_slice(&self.signer_bitmap.to_be_bytes());
        b[62..94].copy_from_slice(&self.req_id);
        b[94..126].copy_from_slice(&self.random_bytes);
        b[126..158].copy_from_slice(&self.gamma_bytes);
        b[158..190].copy_from_slice(&self.commit_root);
        b
    }
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn key_round_tickets(round_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"lot:tk:").push_u64_be(round_id)
}

fn key_round_summary(round_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"lot:rs:").push_u64_be(round_id)
}

fn key_player_stats(identity: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"lot:ps:").push(identity)
}

fn query_ledger_balance(fiat_ledger: &[u8; 20], holder: &[u8; 20]) -> Result<u64, i32> {
    let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(holder);
    call::call_u64(fiat_ledger, cd.as_slice())
}

fn transfer_via_identity(
    from_identity: &[u8; 20],
    fiat_ledger: &[u8; 20],
    to_identity: &[u8; 20],
    amount: u64,
) -> Result<(), i32> {
    if amount == 0 {
        return Ok(());
    }
    let cd = CallEncoder::<128>::new(const { selector("transferBankBalance(address,address,uint64)") })
        .push_address(fiat_ledger)
        .push_address(to_identity)
        .push_u64(amount);
    let ok = call::call_bool(from_identity, cd.as_slice())?;
    if !ok {
        return Err(-30);
    }
    Ok(())
}

fn add_player_stats(identity: &[u8; 20], bought_add: u64, spent_add: u64, won_add: u64, hits_add: u64) {
    let k = key_player_stats(identity);
    let mut raw = [0u8; 32];
    let _ = storage::get_into(k.as_slice(), &mut raw);
    let bought = u64::from_be_bytes([raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]])
        .saturating_add(bought_add);
    let spent = u64::from_be_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ])
    .saturating_add(spent_add);
    let won = u64::from_be_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ])
    .saturating_add(won_add);
    let hits = u64::from_be_bytes([
        raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
    ])
    .saturating_add(hits_add);
    raw[0..8].copy_from_slice(&bought.to_be_bytes());
    raw[8..16].copy_from_slice(&spent.to_be_bytes());
    raw[16..24].copy_from_slice(&won.to_be_bytes());
    raw[24..32].copy_from_slice(&hits.to_be_bytes());
    storage::set(k.as_slice(), &raw);
}

/// Unbiased rejection sampling over `[0, 60_000)` (`6 * 10_000`) -> `0..=9999` with zero modulo bias!
fn derive_unbiased_4d(random_bytes: &[u8; 32], req_id: &[u8; 32]) -> u16 {
    let mut ctr = 0u8;
    loop {
        let mut pre = [0u8; 18 + 32 + 32 + 1];
        pre[0..18].copy_from_slice(b"QUANTUM_4D_NUM_V1:");
        pre[18..50].copy_from_slice(random_bytes);
        pre[50..82].copy_from_slice(req_id);
        pre[82] = ctr;
        let digest = keccak256(&pre);
        let mut i = 0usize;
        while i + 1 < 32 {
            let v = u16::from_be_bytes([digest[i], digest[i + 1]]);
            if v < 60_000 {
                return v % 10_000;
            }
            i += 2;
        }
        if ctr == 255 {
            return u16::from_be_bytes([random_bytes[0], random_bytes[1]]) % 10_000;
        }
        ctr += 1;
    }
}

fn prize_tier_for_pick(pick: u16, win: u16) -> (u8, u64) {
    if pick == win {
        (4, 0) // Exact 4D Grand Jackpot!
    } else if (pick % 1_000) == (win % 1_000) {
        (3, PRIZE_3D_SGD)
    } else if (pick % 100) == (win % 100) {
        (2, PRIZE_2D_SGD)
    } else if (pick % 10) == (win % 10) {
        (1, PRIZE_1D_SGD)
    } else {
        (0, 0)
    }
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-10);
    }
    let fiat_ledger = args.address(0).ok_or(-3)?;
    let id_registry = args.address(1).ok_or(-3)?;
    let vault_id = args.address(2).ok_or(-3)?;
    let vrf_beacon = args.address(3).ok_or(-3)?;
    let min_vals = args.u64(4).ok_or(-3)?.max(1);
    let round_blocks = args.u64(5).ok_or(-3)?.max(2);
    let title = args.dynamic_bytes(6).ok_or(-3)?;
    if title.is_empty() || title.len() > 96 {
        return Err(-3);
    }

    require_valid_identity(&id_registry, &vault_id)?;

    let now_block = context::block_number();
    storage::set_address(KEY_FIAT_LEDGER, &fiat_ledger);
    storage::set_address(KEY_ID_REGISTRY, &id_registry);
    storage::set_address(KEY_VAULT_ID, &vault_id);
    storage::set_address(KEY_VRF_BEACON, &vrf_beacon);
    storage::set_u64(KEY_MIN_VALS, min_vals);
    storage::set_u64(KEY_ROUND_BLOCKS, round_blocks);
    storage::set(KEY_TITLE, title);

    storage::set_u64(KEY_CUR_ROUND, 1);
    storage::set_u64(KEY_PHASE, PHASE_OPEN as u64);
    storage::set_u64(KEY_OPEN_BLOCK, now_block);
    storage::set_u64(KEY_CLOSE_BLOCK, 0);
    storage::set_u64(KEY_TICKET_CNT, 0);
    storage::set(KEY_COMMIT_ROOT, &keccak256(b"QUANTUM_4D_GENESIS_ROUND_1"));
    storage::set_u64(KEY_INIT, 1);

    let mut ev = [0u8; 76];
    ev[0..20].copy_from_slice(&fiat_ledger);
    ev[20..40].copy_from_slice(&vault_id);
    ev[40..60].copy_from_slice(&vrf_beacon);
    ev[60..68].copy_from_slice(&min_vals.to_be_bytes());
    ev[68..76].copy_from_slice(&round_blocks.to_be_bytes());
    events::emit(&[EV_LOTTERY_INIT], &ev);

    ret::write_bool(true);
    Ok(())
}

/// Registers external `SGD-FIAT` transferred into `vaultIdentity` across `(jackpotAdd, reserveAdd)`,
/// verifying `fiatLedger.balanceOf(vaultIdentity) >= newJackpot + newReserve`.
fn handle_seed_pools(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let jp_add = args.u64(0).ok_or(-3)?;
    let rs_add = args.u64(1).ok_or(-3)?;
    if jp_add == 0 && rs_add == 0 {
        return Err(-3);
    }

    let fiat_ledger = storage::get_address(KEY_FIAT_LEDGER).ok_or(-11)?;
    let vault_id = storage::get_address(KEY_VAULT_ID).ok_or(-11)?;

    let new_jp = storage::get_u64(KEY_JACKPOT_POOL)
        .checked_add(jp_add)
        .ok_or(-12)?;
    let new_rs = storage::get_u64(KEY_RESERVE_POOL)
        .checked_add(rs_add)
        .ok_or(-12)?;
    let required_vault = new_jp.checked_add(new_rs).ok_or(-12)?;

    let actual_vault = query_ledger_balance(&fiat_ledger, &vault_id)?;
    if actual_vault < required_vault {
        return Err(-13); // Vault Identity does not hold enough SGD-FIAT to back the seeded pools!
    }

    storage::set_u64(KEY_JACKPOT_POOL, new_jp);
    storage::set_u64(KEY_RESERVE_POOL, new_rs);

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&jp_add.to_be_bytes());
    ev[8..16].copy_from_slice(&rs_add.to_be_bytes());
    ev[16..24].copy_from_slice(&new_jp.to_be_bytes());
    ev[24..32].copy_from_slice(&new_rs.to_be_bytes());
    events::emit(&[EV_POOLS_SEEDED], &ev);

    ret::write_u64_word(new_jp);
    Ok(())
}

/// Buys `1..=10` 4D tickets (`picks`: `2 * K` big-endian bytes, each `u16` in `0..=9999`).
/// Must be called via `buyerIdentity.execute(lotteryAddr, buyTickets(picks))` with
/// `buyerIdentity.setDelegate(lotteryAddr, true)` so `10 SGD * K` is transferred atomically
/// from `buyerIdentity` into `vaultIdentity`!
fn handle_buy_tickets(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    if storage::get_u64(KEY_PHASE) != (PHASE_OPEN as u64) {
        return Err(-14); // Draw currently in flight — wait 1 block for VRF settlement!
    }

    let picks_raw = args.dynamic_bytes(0).ok_or(-3)?;
    if picks_raw.is_empty() || (picks_raw.len() % 2) != 0 {
        return Err(-3);
    }
    let k = picks_raw.len() / 2;
    if k == 0 || k > MAX_PICKS_PER_TX {
        return Err(-15);
    }

    let cur_cnt = storage::get_u64(KEY_TICKET_CNT) as usize;
    if cur_cnt + k > MAX_TICKETS_PER_ROUND {
        return Err(-16); // Round ticket cap reached — call `closeAndRequestDraw()`!
    }

    let mut nums = [0u16; MAX_PICKS_PER_TX];
    let mut i = 0usize;
    while i < k {
        let num = u16::from_be_bytes([picks_raw[2 * i], picks_raw[2 * i + 1]]);
        if num > 9_999 {
            return Err(-17);
        }
        nums[i] = num;
        i += 1;
    }

    let buyer = context::msg_sender();
    let id_registry = storage::get_address(KEY_ID_REGISTRY).ok_or(-11)?;
    let fiat_ledger = storage::get_address(KEY_FIAT_LEDGER).ok_or(-11)?;
    let vault_id = storage::get_address(KEY_VAULT_ID).ok_or(-11)?;
    if buyer == vault_id {
        return Err(-18);
    }
    require_valid_identity(&id_registry, &buyer)?;

    let total_cost = (k as u64) * TICKET_PRICE_SGD;
    transfer_via_identity(&buyer, &fiat_ledger, &vault_id, total_cost)?;

    let round_id = storage::get_u64(KEY_CUR_ROUND);
    let now_block = context::block_number();
    if cur_cnt == 0 {
        let r_blocks = storage::get_u64(KEY_ROUND_BLOCKS);
        storage::set_u64(KEY_CLOSE_BLOCK, now_block.saturating_add(r_blocks));
    }

    // Append `k` 22-byte ticket entries (`[buyer_20 || num_be2]`) to `lot:tk:{round_id}`
    let tk_key = key_round_tickets(round_id);
    let mut round_buf = [0u8; MAX_TICKETS_PER_ROUND * 22];
    if cur_cnt > 0 {
        let _ = storage::get_into(tk_key.as_slice(), &mut round_buf[..cur_cnt * 22]);
    }
    let mut commit = storage::get_bytes32(KEY_COMMIT_ROOT).unwrap_or([0u8; 32]);
    let mut p = 0usize;
    while p < k {
        let idx = cur_cnt + p;
        let off = idx * 22;
        round_buf[off..off + 20].copy_from_slice(&buyer);
        round_buf[off + 20..off + 22].copy_from_slice(&nums[p].to_be_bytes());

        let mut cpre = [0u8; 32 + 4 + 20 + 2];
        cpre[0..32].copy_from_slice(&commit);
        cpre[32..36].copy_from_slice(&(idx as u32).to_be_bytes());
        cpre[36..56].copy_from_slice(&buyer);
        cpre[56..58].copy_from_slice(&nums[p].to_be_bytes());
        commit = keccak256(&cpre);
        p += 1;
    }
    let new_cnt = (cur_cnt + k) as u64;
    storage::set(tk_key.as_slice(), &round_buf[..(new_cnt as usize) * 22]);
    storage::set_u64(KEY_TICKET_CNT, new_cnt);
    storage::set(KEY_COMMIT_ROOT, &commit);

    let new_jp = storage::get_u64(KEY_JACKPOT_POOL).saturating_add((k as u64) * JACKPOT_CONTRIB_SGD);
    let new_rs = storage::get_u64(KEY_RESERVE_POOL).saturating_add((k as u64) * RESERVE_CONTRIB_SGD);
    storage::set_u64(KEY_JACKPOT_POOL, new_jp);
    storage::set_u64(KEY_RESERVE_POOL, new_rs);
    storage::set_u64(
        KEY_TOTAL_SOLD,
        storage::get_u64(KEY_TOTAL_SOLD).saturating_add(k as u64),
    );
    add_player_stats(&buyer, k as u64, total_cost, 0, 0);

    let mut ev = [0u8; 56];
    ev[0..8].copy_from_slice(&(k as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&total_cost.to_be_bytes());
    ev[16..24].copy_from_slice(&new_jp.to_be_bytes());
    ev[24..56].copy_from_slice(&commit);
    events::emit(
        &[
            EV_TICKETS_BOUGHT,
            keccak256(&round_id.to_be_bytes()),
            addr_topic(&buyer),
        ],
        &ev,
    );

    ret::write_u64_word(new_cnt);
    Ok(())
}

/// Freezes the current round once `round_close_block` arrives (or `MAX_TICKETS_PER_ROUND` is full)
/// and requests threshold ECVRF randomness from `vrf-beacon`.
fn handle_close_and_request_draw(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    if storage::get_u64(KEY_PHASE) != (PHASE_OPEN as u64) {
        return Err(-14);
    }
    let ticket_cnt = storage::get_u64(KEY_TICKET_CNT);
    if ticket_cnt == 0 {
        return Err(-19); // Cannot draw an empty round!
    }
    let now_block = context::block_number();
    let close_block = storage::get_u64(KEY_CLOSE_BLOCK);
    if now_block < close_block && (ticket_cnt as usize) < MAX_TICKETS_PER_ROUND {
        return Err(-20); // Sales window still open!
    }

    let round_id = storage::get_u64(KEY_CUR_ROUND);
    let commit_root = storage::get_bytes32(KEY_COMMIT_ROOT).unwrap_or([0u8; 32]);
    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    let min_vals = storage::get_u64(KEY_MIN_VALS);
    let self_addr = context::self_address();

    let mut seed_pre = [0u8; 19 + 20 + 8 + 8 + 32];
    seed_pre[0..19].copy_from_slice(b"QUANTUM_4D_DRAW_V1:");
    seed_pre[19..39].copy_from_slice(&self_addr);
    seed_pre[39..47].copy_from_slice(&round_id.to_be_bytes());
    seed_pre[47..55].copy_from_slice(&ticket_cnt.to_be_bytes());
    seed_pre[55..87].copy_from_slice(&commit_root);
    let user_seed = keccak256(&seed_pre);

    let req_cd = CallEncoder::<96>::new(const { selector("requestRandomness(bytes32,uint64)") })
        .push_bytes32(&user_seed)
        .push_u64(min_vals);
    let mut req_id = [0u8; 32];
    let n = call::call_into(&vrf_beacon, req_cd.as_slice(), &mut req_id)?;
    if n < 32 {
        return Err(-21);
    }

    storage::set_u64(KEY_PHASE, PHASE_DRAWING as u64);
    storage::set(KEY_PENDING_REQ, &req_id);

    let jp = storage::get_u64(KEY_JACKPOT_POOL);
    let mut ev = [0u8; 56];
    ev[0..8].copy_from_slice(&round_id.to_be_bytes());
    ev[8..40].copy_from_slice(&req_id);
    ev[40..48].copy_from_slice(&ticket_cnt.to_be_bytes());
    ev[48..56].copy_from_slice(&jp.to_be_bytes());
    events::emit(&[EV_DRAW_REQUESTED, req_id], &ev);

    ret::write_word(&req_id);
    Ok(())
}

fn settle_round_with_vrf(
    req_id: &[u8; 32],
    random_bytes: &[u8; 32],
    gamma_bytes: &[u8; 32],
    epoch_id: u64,
    signer_bitmap: u64,
) -> Result<u16, i32> {
    if storage::get_u64(KEY_PHASE) != (PHASE_DRAWING as u64) {
        return Err(-22);
    }
    let expected_req = storage::get_bytes32(KEY_PENDING_REQ).ok_or(-22)?;
    if *req_id != expected_req {
        return Err(-23);
    }

    let round_id = storage::get_u64(KEY_CUR_ROUND);
    let ticket_cnt = storage::get_u64(KEY_TICKET_CNT) as usize;
    let commit_root = storage::get_bytes32(KEY_COMMIT_ROOT).unwrap_or([0u8; 32]);
    let fiat_ledger = storage::get_address(KEY_FIAT_LEDGER).ok_or(-11)?;
    let vault_id = storage::get_address(KEY_VAULT_ID).ok_or(-11)?;

    let mut tickets_raw = [0u8; MAX_TICKETS_PER_ROUND * 22];
    if ticket_cnt > 0 {
        let _ = storage::get_into(
            key_round_tickets(round_id).as_slice(),
            &mut tickets_raw[..ticket_cnt * 22],
        );
    }

    let winning_4d = derive_unbiased_4d(random_bytes, req_id);

    let mut jp_pool = storage::get_u64(KEY_JACKPOT_POOL);
    let mut rs_pool = storage::get_u64(KEY_RESERVE_POOL);
    let jp_before = jp_pool;

    // Pass 1: Tally prize tiers across all tickets in the round.
    let mut w4d_cnt = 0u16;
    let mut w3d_cnt = 0u16;
    let mut w2d_cnt = 0u16;
    let mut w1d_cnt = 0u16;
    let mut raw_fixed_owed = 0u64;

    let mut tiers = [0u8; MAX_TICKETS_PER_ROUND];
    let mut fixed_amt = [0u64; MAX_TICKETS_PER_ROUND];

    let mut i = 0usize;
    while i < ticket_cnt {
        let off = i * 22;
        let pick = u16::from_be_bytes([tickets_raw[off + 20], tickets_raw[off + 21]]);
        let (tier, fp) = prize_tier_for_pick(pick, winning_4d);
        tiers[i] = tier;
        fixed_amt[i] = fp;
        match tier {
            4 => w4d_cnt += 1,
            3 => {
                w3d_cnt += 1;
                raw_fixed_owed = raw_fixed_owed.saturating_add(fp);
            }
            2 => {
                w2d_cnt += 1;
                raw_fixed_owed = raw_fixed_owed.saturating_add(fp);
            }
            1 => {
                w1d_cnt += 1;
                raw_fixed_owed = raw_fixed_owed.saturating_add(fp);
            }
            _ => {}
        }
        i += 1;
    }

    // Check actual vault balance so payouts are mathematically guaranteed solvent.
    let vault_bal = query_ledger_balance(&fiat_ledger, &vault_id)?;
    let avail_total = vault_bal.min(jp_pool.saturating_add(rs_pool));
    let avail_jp = jp_pool.min(avail_total);
    let avail_rs = rs_pool.min(avail_total.saturating_sub(avail_jp));

    let per_4d_share = if w4d_cnt > 0 {
        avail_jp / (w4d_cnt as u64)
    } else {
        0
    };

    // Consolidate payouts per unique winning `Identity` so each winner receives 1 clean transfer!
    let mut win_addrs = [[0u8; 20]; MAX_TICKETS_PER_ROUND];
    let mut win_totals = [0u64; MAX_TICKETS_PER_ROUND];
    let mut win_hits = [0u64; MAX_TICKETS_PER_ROUND];
    let mut win_best_tier = [0u64; MAX_TICKETS_PER_ROUND];
    let mut unique_winners = 0usize;

    let mut jp_paid = 0u64;
    let mut rs_paid = 0u64;

    let mut t_idx = 0usize;
    while t_idx < ticket_cnt {
        let tier = tiers[t_idx];
        if tier > 0 {
            let prize = if tier == 4 {
                jp_paid = jp_paid.saturating_add(per_4d_share);
                per_4d_share
            } else if raw_fixed_owed <= avail_rs {
                rs_paid = rs_paid.saturating_add(fixed_amt[t_idx]);
                fixed_amt[t_idx]
            } else if raw_fixed_owed > 0 {
                let scaled =
                    ((fixed_amt[t_idx] as u128) * (avail_rs as u128) / (raw_fixed_owed as u128)) as u64;
                rs_paid = rs_paid.saturating_add(scaled);
                scaled
            } else {
                0
            };

            if prize > 0 {
                let mut buyer = [0u8; 20];
                buyer.copy_from_slice(&tickets_raw[t_idx * 22..t_idx * 22 + 20]);

                let mut found = None;
                let mut u = 0usize;
                while u < unique_winners {
                    if win_addrs[u] == buyer {
                        found = Some(u);
                        break;
                    }
                    u += 1;
                }
                match found {
                    Some(pos) => {
                        win_totals[pos] = win_totals[pos].saturating_add(prize);
                        win_hits[pos] += 1;
                        if (tier as u64) > win_best_tier[pos] {
                            win_best_tier[pos] = tier as u64;
                        }
                    }
                    None => {
                        win_addrs[unique_winners] = buyer;
                        win_totals[unique_winners] = prize;
                        win_hits[unique_winners] = 1;
                        win_best_tier[unique_winners] = tier as u64;
                        unique_winners += 1;
                    }
                }
            }
        }
        t_idx += 1;
    }

    // Pay every winning Identity directly in `SGD-FIAT`!
    let mut total_paid = 0u64;
    let mut w = 0usize;
    while w < unique_winners {
        let amt = win_totals[w];
        if amt > 0 {
            transfer_via_identity(&vault_id, &fiat_ledger, &win_addrs[w], amt)?;
            total_paid = total_paid.saturating_add(amt);
            add_player_stats(&win_addrs[w], 0, 0, amt, win_hits[w]);

            let mut pev = [0u8; 24];
            pev[0..8].copy_from_slice(&round_id.to_be_bytes());
            pev[8..16].copy_from_slice(&amt.to_be_bytes());
            pev[16..24].copy_from_slice(&win_best_tier[w].to_be_bytes());
            events::emit(&[EV_PRIZE_PAID, addr_topic(&win_addrs[w])], &pev);
        }
        w += 1;
    }

    // Update pools: 100% of `jp_pool` rolls over if `w4d_cnt == 0`!
    jp_pool = jp_pool.saturating_sub(jp_paid);
    rs_pool = rs_pool.saturating_sub(rs_paid);
    if w4d_cnt > 0 && jp_pool < 1_000 && rs_pool > 2_000 {
        let reseed = (rs_pool - 2_000).min(1_000);
        rs_pool -= reseed;
        jp_pool += reseed;
    }
    storage::set_u64(KEY_JACKPOT_POOL, jp_pool);
    storage::set_u64(KEY_RESERVE_POOL, rs_pool);
    storage::set_u64(
        KEY_TOTAL_PAID,
        storage::get_u64(KEY_TOTAL_PAID).saturating_add(total_paid),
    );
    storage::set_u64(KEY_SETTLED_CNT, storage::get_u64(KEY_SETTLED_CNT).saturating_add(1));

    let now_block = context::block_number();
    let summary = RoundSummary {
        round_id,
        winning_4d,
        ticket_count: ticket_cnt as u32,
        w4d_count: w4d_cnt,
        w3d_count: w3d_cnt,
        w2d_count: w2d_cnt,
        w1d_count: w1d_cnt,
        jackpot_before: jp_before,
        total_paid,
        settled_block: now_block,
        epoch_id,
        signer_bitmap,
        req_id: *req_id,
        random_bytes: *random_bytes,
        gamma_bytes: *gamma_bytes,
        commit_root,
    };
    storage::set(key_round_summary(round_id).as_slice(), &summary.encode());

    // Open Round `round_id + 1`!
    let next_round = round_id.saturating_add(1);
    let mut next_commit_pre = [0u8; 25 + 8 + 32];
    next_commit_pre[0..25].copy_from_slice(b"QUANTUM_4D_NEXT_ROUND_V1:");
    next_commit_pre[25..33].copy_from_slice(&next_round.to_be_bytes());
    next_commit_pre[33..65].copy_from_slice(random_bytes);

    storage::set_u64(KEY_CUR_ROUND, next_round);
    storage::set_u64(KEY_PHASE, PHASE_OPEN as u64);
    storage::set_u64(KEY_OPEN_BLOCK, now_block);
    storage::set_u64(KEY_CLOSE_BLOCK, 0);
    storage::set_u64(KEY_TICKET_CNT, 0);
    storage::set(KEY_COMMIT_ROOT, &keccak256(&next_commit_pre));
    storage::set(KEY_PENDING_REQ, &[]);

    let mut sev = [0u8; 96];
    sev[0..8].copy_from_slice(&round_id.to_be_bytes());
    sev[8..16].copy_from_slice(&(winning_4d as u64).to_be_bytes());
    sev[16..24].copy_from_slice(&total_paid.to_be_bytes());
    sev[24..32].copy_from_slice(&jp_pool.to_be_bytes());
    sev[32..64].copy_from_slice(random_bytes);
    sev[64..96].copy_from_slice(gamma_bytes);
    events::emit(&[EV_ROUND_SETTLED, *req_id], &sev);

    Ok(winning_4d)
}

fn handle_on_vrf_fulfilled(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    if context::msg_sender() != vrf_beacon {
        return Err(-24); // Only our pinned `vrf-beacon` contract may push `onVrfFulfilled`!
    }
    let req_id = args.bytes32(0).ok_or(-3)?;
    let random_bytes = args.bytes32(1).ok_or(-3)?;
    let gamma_bytes = args.bytes32(2).ok_or(-3)?;
    let epoch_id = args.u64(3).ok_or(-3)?;
    let signer_bitmap = args.u64(4).ok_or(-3)?;

    let win = settle_round_with_vrf(&req_id, &random_bytes, &gamma_bytes, epoch_id, signer_bitmap)?;
    ret::write_u64_word(win as u64);
    Ok(())
}

/// Permissionless fallback settlement in case `onVrfFulfilled` did not run synchronously.
fn handle_settle_from_beacon(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    if storage::get_u64(KEY_PHASE) != (PHASE_DRAWING as u64) {
        return Err(-22);
    }
    let req_id = storage::get_bytes32(KEY_PENDING_REQ).ok_or(-22)?;
    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;

    let cd = CallEncoder::<64>::new(const { selector("getFulfilledOutput(bytes32)") })
        .push_bytes32(&req_id);
    let mut out = [0u8; 81];
    let n = call::call_into(&vrf_beacon, cd.as_slice(), &mut out)?;
    if n < 81 || out[0] != 2 {
        return Err(-25); // Beacon request not yet fulfilled!
    }
    let mut random_bytes = [0u8; 32];
    let mut gamma_bytes = [0u8; 32];
    random_bytes.copy_from_slice(&out[1..33]);
    gamma_bytes.copy_from_slice(&out[33..65]);
    let epoch_id = u64::from_be_bytes([
        out[65], out[66], out[67], out[68], out[69], out[70], out[71], out[72],
    ]);
    let signer_bitmap = u64::from_be_bytes([
        out[73], out[74], out[75], out[76], out[77], out[78], out[79], out[80],
    ]);

    let win = settle_round_with_vrf(&req_id, &random_bytes, &gamma_bytes, epoch_id, signer_bitmap)?;
    ret::write_u64_word(win as u64);
    Ok(())
}

/// Single-call binary dashboard snapshot for `web/src/lottery.js` and `ai_engines.rs`:
/// Header (`218` bytes):
/// `[round_id:8][phase:1][ticket_price:8][round_blocks:8][min_vals:8][open_blk:8][close_blk:8]`
/// `[now_blk:8][jackpot_pool:8][reserve_pool:8][cur_ticket_cnt:4][total_sold:8][total_paid:8]`
/// `[settled_cnt:8][fiat_ledger:20][vault_id:20][vrf_beacon:20][commit_root:32][pending_req:32][hist_cnt:1]`
/// Followed by `hist_cnt` (`<= 8`) most recent `RoundSummary` records (`190` bytes each),
/// Followed by `[title_len:1][title_bytes]`.
fn handle_get_lottery_state(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let round_id = storage::get_u64(KEY_CUR_ROUND);
    let phase = storage::get_u64(KEY_PHASE) as u8;
    let round_blocks = storage::get_u64(KEY_ROUND_BLOCKS);
    let min_vals = storage::get_u64(KEY_MIN_VALS);
    let open_blk = storage::get_u64(KEY_OPEN_BLOCK);
    let close_blk = storage::get_u64(KEY_CLOSE_BLOCK);
    let now_blk = context::block_number();
    let jp_pool = storage::get_u64(KEY_JACKPOT_POOL);
    let rs_pool = storage::get_u64(KEY_RESERVE_POOL);
    let cur_t_cnt = storage::get_u64(KEY_TICKET_CNT) as u32;
    let tot_sold = storage::get_u64(KEY_TOTAL_SOLD);
    let tot_paid = storage::get_u64(KEY_TOTAL_PAID);
    let settled_cnt = storage::get_u64(KEY_SETTLED_CNT);
    let fiat_ledger = storage::get_address(KEY_FIAT_LEDGER).unwrap_or([0u8; 20]);
    let vault_id = storage::get_address(KEY_VAULT_ID).unwrap_or([0u8; 20]);
    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).unwrap_or([0u8; 20]);
    let commit_root = storage::get_bytes32(KEY_COMMIT_ROOT).unwrap_or([0u8; 32]);
    let pending_req = storage::get_bytes32(KEY_PENDING_REQ).unwrap_or([0u8; 32]);

    let mut out = [0u8; 226 + 8 * RoundSummary::BYTE_LEN + 100];
    out[0..8].copy_from_slice(&round_id.to_be_bytes());
    out[8] = phase;
    out[9..17].copy_from_slice(&TICKET_PRICE_SGD.to_be_bytes());
    out[17..25].copy_from_slice(&round_blocks.to_be_bytes());
    out[25..33].copy_from_slice(&min_vals.to_be_bytes());
    out[33..41].copy_from_slice(&open_blk.to_be_bytes());
    out[41..49].copy_from_slice(&close_blk.to_be_bytes());
    out[49..57].copy_from_slice(&now_blk.to_be_bytes());
    out[57..65].copy_from_slice(&jp_pool.to_be_bytes());
    out[65..73].copy_from_slice(&rs_pool.to_be_bytes());
    out[73..77].copy_from_slice(&cur_t_cnt.to_be_bytes());
    out[77..85].copy_from_slice(&tot_sold.to_be_bytes());
    out[85..93].copy_from_slice(&tot_paid.to_be_bytes());
    out[93..101].copy_from_slice(&settled_cnt.to_be_bytes());
    out[101..121].copy_from_slice(&fiat_ledger);
    out[121..141].copy_from_slice(&vault_id);
    out[141..161].copy_from_slice(&vrf_beacon);
    out[161..193].copy_from_slice(&commit_root);
    out[193..225].copy_from_slice(&pending_req);

    let mut hist_cnt = 0u8;
    let mut cursor = 226usize;
    if round_id > 1 {
        let mut r = round_id - 1;
        while r >= 1 && hist_cnt < 8 {
            let mut sbuf = [0u8; RoundSummary::BYTE_LEN];
            if let Some(n) = storage::get_into(key_round_summary(r).as_slice(), &mut sbuf) {
                if n >= RoundSummary::BYTE_LEN {
                    out[cursor..cursor + RoundSummary::BYTE_LEN].copy_from_slice(&sbuf);
                    cursor += RoundSummary::BYTE_LEN;
                    hist_cnt += 1;
                }
            }
            if r == 1 {
                break;
            }
            r -= 1;
        }
    }
    out[225] = hist_cnt;

    let mut title_buf = [0u8; 96];
    let tlen = storage::get_into(KEY_TITLE, &mut title_buf)
        .unwrap_or(0)
        .min(96);
    out[cursor] = tlen as u8;
    cursor += 1;
    if tlen > 0 {
        out[cursor..cursor + tlen].copy_from_slice(&title_buf[..tlen]);
        cursor += tlen;
    }

    ret::write(&out[..cursor]);
    Ok(())
}

fn handle_get_round_info(args: &CalldataReader) -> Result<(), i32> {
    let round_id = args.u64(0).ok_or(-3)?;
    let mut sbuf = [0u8; RoundSummary::BYTE_LEN];
    let n = storage::get_into(key_round_summary(round_id).as_slice(), &mut sbuf).ok_or(-26)?;
    if n < RoundSummary::BYTE_LEN {
        return Err(-26);
    }
    ret::write(&sbuf);
    Ok(())
}

/// Returns `[count_u32_be][count * (buyer_20 || pick_be2)]` for `round_id`.
fn handle_get_round_tickets(args: &CalldataReader) -> Result<(), i32> {
    let round_id = args.u64(0).ok_or(-3)?;
    let mut out = [0u8; 4 + MAX_TICKETS_PER_ROUND * 22];
    let total_bytes =
        storage::get_into(key_round_tickets(round_id).as_slice(), &mut out[4..]).unwrap_or(0);
    let cnt = (total_bytes / 22).min(MAX_TICKETS_PER_ROUND);
    out[0..4].copy_from_slice(&(cnt as u32).to_be_bytes());
    ret::write(&out[..4 + cnt * 22]);
    Ok(())
}

/// Returns 32-byte player lifetime stats `[tickets_bought_be8][sgd_spent_be8][sgd_won_be8][winning_tickets_be8]`.
fn handle_get_player_stats(args: &CalldataReader) -> Result<(), i32> {
    let id = args.address(0).ok_or(-3)?;
    let mut raw = [0u8; 32];
    let _ = storage::get_into(key_player_stats(&id).as_slice(), &mut raw);
    ret::write(&raw);
    Ok(())
}

fn handle_hfs_type(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_abi_bytes(b"QUANTUM_LOTTERY");
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../vrf-beacon/src/main.rs"]
mod beacon_mod;

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;
    use hps_sdk::vrf::mock_crypto;

    fn mock_id_registry_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, reader)) = CalldataReader::parse(raw) else {
            return -1;
        };
        if sel == selector("isValidIdentity(address)") {
            let Some(addr) = reader.address(0) else {
                return -3;
            };
            let ok = storage::get_u64(KeyBuilder::<32>::new().push(b"reg:").push(&addr).as_slice()) == 1;
            ret::write_bool(ok);
            return 0;
        }
        if sel == selector("register(address)") {
            let addr = reader.address(0).unwrap();
            storage::set_u64(KeyBuilder::<32>::new().push(b"reg:").push(&addr).as_slice(), 1);
            ret::write_bool(true);
            return 0;
        }
        -2
    }

    fn mock_fiat_ledger_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, reader)) = CalldataReader::parse(raw) else {
            return -1;
        };
        if sel == selector("credit(address,uint64)") {
            let who = reader.address(0).unwrap();
            let amt = reader.u64(1).unwrap();
            let k = KeyBuilder::<32>::new().push(b"bal:").push(&who);
            storage::set_u64(k.as_slice(), storage::get_u64(k.as_slice()) + amt);
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("balanceOf(address)") {
            let who = reader.address(0).unwrap();
            let k = KeyBuilder::<32>::new().push(b"bal:").push(&who);
            ret::write_u64_word(storage::get_u64(k.as_slice()));
            return 0;
        }
        if sel == selector("transferDirect(address,uint64)") {
            let from = context::msg_sender();
            let to = reader.address(0).unwrap();
            let amt = reader.u64(1).unwrap();
            let fk = KeyBuilder::<32>::new().push(b"bal:").push(&from);
            let tk = KeyBuilder::<32>::new().push(b"bal:").push(&to);
            let fbal = storage::get_u64(fk.as_slice());
            if fbal < amt {
                return -50;
            }
            storage::set_u64(fk.as_slice(), fbal - amt);
            storage::set_u64(tk.as_slice(), storage::get_u64(tk.as_slice()) + amt);
            ret::write_bool(true);
            return 0;
        }
        -2
    }

    fn mock_identity_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, reader)) = CalldataReader::parse(raw) else {
            return -1;
        };
        if sel == selector("init(address)") {
            let owner = reader.address(0).unwrap();
            storage::set_address(b"owner", &owner);
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("setDelegate(address,bool)") {
            let d = reader.address(0).unwrap();
            let en = reader.bool(1).unwrap();
            storage::set_u64(
                KeyBuilder::<32>::new().push(b"del:").push(&d).as_slice(),
                if en { 1 } else { 0 },
            );
            ret::write_bool(true);
            return 0;
        }
        let caller = context::msg_sender();
        let owner = storage::get_address(b"owner").unwrap_or([0u8; 20]);
        let is_del =
            storage::get_u64(KeyBuilder::<32>::new().push(b"del:").push(&caller).as_slice()) == 1;
        if caller != owner && !is_del {
            return -21;
        }
        if sel == selector("transferBankBalance(address,address,uint64)") {
            let led = reader.address(0).unwrap();
            let to = reader.address(1).unwrap();
            let amt = reader.u64(2).unwrap();
            let cd = CallEncoder::<96>::new(selector("transferDirect(address,uint64)"))
                .push_address(&to)
                .push_u64(amt);
            let ok = call::call_bool(&led, cd.as_slice()).unwrap_or(false);
            if !ok {
                return -24;
            }
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("execute(address,bytes)") {
            let target = reader.address(0).unwrap();
            let inner = reader.dynamic_bytes(1).unwrap();
            match call::call_raw(&target, inner) {
                Ok(r) => {
                    ret::write(r);
                    return 0;
                }
                Err(c) => return c,
            }
        }
        -2
    }

    #[test]
    fn full_five_validator_dkg_and_4d_lottery_settlement() {
        use mock_crypto::{Scalar, SigningKey};

        mock::reset();
        mock::set_block_number(100);

        // 1. Set up 5 consensus `Full` validators (`threshold = 4` automatically!).
        let mut val_keys: Vec<SigningKey> = (0..5u8)
            .map(|i| SigningKey::from_bytes(&[i + 31; 32]))
            .collect();
        val_keys.sort_by_key(|k| k.verifying_key().to_bytes());
        let val_entries: Vec<([u8; 20], [u8; 32])> = val_keys
            .iter()
            .enumerate()
            .map(|(i, k)| ([0x80 + i as u8; 20], k.verifying_key().to_bytes()))
            .collect();
        mock_crypto::set_mock_validators(&val_entries);
        let pks: Vec<[u8; 32]> = val_entries.iter().map(|(_, pk)| *pk).collect();

        let admin_eoa = [0x01; 20];
        let alice_eoa = [0x02; 20];
        let id_reg = [0x10; 20];
        let fiat = [0x11; 20];
        let vault_id = [0x12; 20];
        let alice_id = [0x13; 20];
        let beacon = [0x14; 20];
        let lottery = [0x15; 20];

        mock::register_hps(id_reg, mock_id_registry_dispatch);
        mock::register_hps(fiat, mock_fiat_ledger_dispatch);
        mock::register_hps(vault_id, mock_identity_dispatch);
        mock::register_hps(alice_id, mock_identity_dispatch);
        mock::register_hps(beacon, beacon_mod::dispatch_calldata);
        mock::register_hps(lottery, dispatch_calldata);

        for id in [vault_id, alice_id] {
            let reg_cd = CallEncoder::<64>::new(selector("register(address)")).push_address(&id);
            mock::transact_as(admin_eoa, id_reg, reg_cd.as_slice()).unwrap();
        }
        mock::transact_as(
            admin_eoa,
            vault_id,
            CallEncoder::<64>::new(selector("init(address)"))
                .push_address(&admin_eoa)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            alice_eoa,
            alice_id,
            CallEncoder::<64>::new(selector("init(address)"))
                .push_address(&alice_eoa)
                .as_slice(),
        )
        .unwrap();

        // Grant lottery delegate rights on `vault_id` (for payouts) and `alice_id` (for 1-tx ticket buys).
        let del_cd = CallEncoder::<96>::new(selector("setDelegate(address,bool)"))
            .push_address(&lottery)
            .push_bool(true);
        mock::transact_as(admin_eoa, vault_id, del_cd.as_slice()).unwrap();
        mock::transact_as(alice_eoa, alice_id, del_cd.as_slice()).unwrap();

        // Fund vault (`40,000 SGD`) and Alice (`500 SGD`).
        mock::transact_as(
            admin_eoa,
            fiat,
            CallEncoder::<96>::new(selector("credit(address,uint64)"))
                .push_address(&vault_id)
                .push_u64(40_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            admin_eoa,
            fiat,
            CallEncoder::<96>::new(selector("credit(address,uint64)"))
                .push_address(&alice_id)
                .push_u64(500)
                .as_slice(),
        )
        .unwrap();

        // 2. Open Epoch #1 on `vrf-beacon` and have all 5 validators submit DKG deals!
        mock::transact_as(
            admin_eoa,
            beacon,
            CallEncoder::<16>::new(selector("syncEpoch()")).as_slice(),
        )
        .unwrap();
        let set_hash = mock_crypto::compute_validator_set_hash(4, &pks);
        let mut deals = Vec::new();
        for (idx, vk) in val_keys.iter().enumerate() {
            let deal =
                mock_crypto::create_validator_dkg_deal(vk, &set_hash, idx, 4, &pks, &[idx as u8 + 7; 32])
                    .unwrap();
            let mut sub_cd = CallEncoder::<2048>::new(selector("submitEpochDeal(uint64,uint64,bytes)"))
                .push_u64(1)
                .push_u64(idx as u64)
                .push_u64(96)
                .push_dynamic_bytes_tail(&deal);
            let res = mock::transact_as(val_entries[idx].0, beacon, sub_cd.as_slice()).unwrap();
            if idx == 4 {
                assert_eq!(res[31], 2, "5th deal immediately activates Epoch #1!");
            }
            let _ = &mut sub_cd;
            deals.push(deal);
        }

        // Reconstruct each validator's Epoch #1 secret share `s_{1, r}`.
        let mut epoch_secret_shares = Vec::new();
        for r in 0..5 {
            let mut sum = Scalar::ZERO;
            for d in 0..5 {
                sum += mock_crypto::decrypt_validator_dkg_share(
                    &val_keys[r],
                    &set_hash,
                    d,
                    r,
                    4,
                    &pks,
                    &deals[d],
                    &[1u8; 32],
                )
                .unwrap();
            }
            epoch_secret_shares.push(sum);
        }

        // 3. Initialize Quantum 4D Jackpot (`minValidators = 5`, `roundBlocks = 5`) and seed `25k + 15k SGD`!
        let init_cd = CallEncoder::<512>::new(selector(
            "initialize(address,address,address,address,uint64,uint64,string)",
        ))
        .push_address(&fiat)
        .push_address(&id_reg)
        .push_address(&vault_id)
        .push_address(&beacon)
        .push_u64(5)
        .push_u64(5)
        .push_u64(224)
        .push_dynamic_bytes_tail(b"Quantum 4D Jackpot #1");
        mock::transact_as(admin_eoa, lottery, init_cd.as_slice()).unwrap();

        mock::transact_as(
            admin_eoa,
            lottery,
            CallEncoder::<96>::new(selector("seedPools(uint64,uint64)"))
                .push_u64(25_000)
                .push_u64(15_000)
                .as_slice(),
        )
        .unwrap();

        // 4. Alice buys ALL 10 last-digit combinations (`0000..0009`) for `100 SGD` -> guaranteed >= 1D hit!
        let mut picks = [0u8; 20];
        for d in 0..10u16 {
            picks[2 * (d as usize)..2 * (d as usize) + 2].copy_from_slice(&(1230 + d).to_be_bytes());
        }
        let buy_inner = CallEncoder::<256>::new(selector("buyTickets(bytes)"))
            .push_u64(32)
            .push_dynamic_bytes_tail(&picks);
        let exec_buy = CallEncoder::<512>::new(selector("execute(address,bytes)"))
            .push_address(&lottery)
            .push_u64(64)
            .push_dynamic_bytes_tail(buy_inner.as_slice());
        mock::transact_as(alice_eoa, alice_id, exec_buy.as_slice()).unwrap();

        // Alice paid 100 SGD (`500 -> 400`).
        let alice_bal_after_buy = mock::transact_as(
            admin_eoa,
            fiat,
            CallEncoder::<64>::new(selector("balanceOf(address)"))
                .push_address(&alice_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(alice_bal_after_buy[24..32].try_into().unwrap()), 400);

        // 5. Advance 5 blocks -> `closeAndRequestDraw()`!
        mock::set_block_number(105);
        let req_id_vec = mock::transact_as(
            admin_eoa,
            lottery,
            CallEncoder::<16>::new(selector("closeAndRequestDraw()")).as_slice(),
        )
        .unwrap();
        let req_id: [u8; 32] = req_id_vec.try_into().unwrap();

        // Read `alpha` from `getRequestProof(req_id)` on `vrf-beacon`.
        let proof_blob = mock::transact_as(
            admin_eoa,
            beacon,
            CallEncoder::<64>::new(selector("getRequestProof(bytes32)"))
                .push_bytes32(&req_id)
                .as_slice(),
        )
        .unwrap();
        let mut alpha = [0u8; 32];
        alpha.copy_from_slice(&proof_blob[85..117]);

        // 6. All 5 validators submit VRF shares (`4th` settles Round #1, `5th` succeeds idempotently!).
        mock::set_block_number(106);
        for v in 0..5 {
            let (gamma_v, proof_v) =
                mock_crypto::compute_validator_vrf_share(&epoch_secret_shares[v], &alpha, &[v as u8 + 50; 32]);
            let share_cd =
                CallEncoder::<384>::new(selector("submitVrfShare(bytes32,uint64,bytes32,bytes)"))
                    .push_bytes32(&req_id)
                    .push_u64(v as u64)
                    .push_bytes32(&gamma_v)
                    .push_u64(128)
                    .push_dynamic_bytes_tail(&proof_v);
            mock::transact_as(val_entries[v].0, beacon, share_cd.as_slice()).unwrap();
        }

        // Verify Round #1 settled, Round #2 opened, and Alice won >= 15 SGD automatically!
        let alice_bal_final = mock::transact_as(
            admin_eoa,
            fiat,
            CallEncoder::<64>::new(selector("balanceOf(address)"))
                .push_address(&alice_id)
                .as_slice(),
        )
        .unwrap();
        let final_sgd = u64::from_be_bytes(alice_bal_final[24..32].try_into().unwrap());
        assert!(final_sgd >= 415, "Alice covered all 0..9 last digits so she MUST win >= 15 SGD (got {})!", final_sgd);

        let state_blob = mock::transact_as(
            admin_eoa,
            lottery,
            CallEncoder::<16>::new(selector("getLotteryState()")).as_slice(),
        )
        .unwrap();
        let cur_round = u64::from_be_bytes(state_blob[0..8].try_into().unwrap());
        assert_eq!(cur_round, 2, "Lottery must automatically advance to Round #2!");
        assert_eq!(state_blob[225], 1, "Round #1 summary must be recorded in recent history!");
    }
}
