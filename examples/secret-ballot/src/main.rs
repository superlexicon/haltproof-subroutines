//! CipherVote (`secret-ballot`) — Threshold Homomorphic Zero-Knowledge Secret-Ballot Governance HPS.
//!
//! Showcases SuperLexicon's Wasmtime Threshold Additive Homomorphic Encryption (`Edwards25519`
//! Exponential ElGamal + Cramer-Damgård-Schoenmakers `0/1` Disjunctive ZK Proofs + Validator-Quorum
//! Threshold Decryption):
//! - Voters cast **1-transaction encrypted one-hot ballots** `(Enc(b_yes), Enc(b_no), Enc(b_abstain))`
//!   under the subnet validator quorum's active DKG `EpochPK`.
//! - On-chain WASM verifies:
//!   1. Three 128-byte Cramer-Damgård-Schoenmakers 1-of-2 Disjunctive Schnorr proofs (`b_s ∈ {0, 1}`),
//!   2. One 64-byte Chaum-Pedersen DLEQ proof on the homomorphic sum `C_yes + C_no + C_abstain`
//!      proving `b_yes + b_no + b_abstain == 1` (`log_B(C_sum,1) == log_EpochPK(C_sum,2 - B)`).
//! - Supports both **Civic Referendums (`1-Identity = 1-Vote`)** and **Token-Weighted Shareholder Polls**
//!   (`weight = shareLedger.balanceOf(voter)`), scaling each voter's encrypted vector homomorphically
//!   via `host_he_scale_ciphertext` and accumulating into `(Acc_Yes, Acc_No, Acc_Abstain)` via
//!   `host_he_add_ciphertexts`.
//! - Individual votes are **never decrypted** — not during voting, not at tally time, and not ever
//!   afterwards. When the poll closes, the validator supermajority (`> 2/3`) threshold-decrypts
//!   **only** the 3 aggregate accumulators via `vrf-beacon`!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::require_valid_identity;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::vrf;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const WEIGHT_MODE_ONE_VOTE: u8 = 1;
pub const WEIGHT_MODE_SHARE_LEDGER: u8 = 2;

pub const POLL_OPEN: u8 = 1;
pub const POLL_DECRYPTING: u8 = 2;
pub const POLL_TALLY_VERIFIED: u8 = 3;

pub const MAX_POLLS_RETURNED: usize = 32;
pub const MAX_BALLOTS_PER_POLL: usize = 128;
pub const MAX_HE_BSGS_BOUND: u64 = 16_777_216;
pub const BALLOT_RECORD_LEN: usize = 228; // voter(20) + block(8) + weight(8) + ciphertexts(192)

const EV_BALLOT_HUB_INIT: [u8; 32] =
    event_topic("SecretBallotInitialized(address,address,address,uint64)");
const EV_POLL_CREATED: [u8; 32] =
    event_topic("SecretPollCreated(uint64,address,uint64,uint64,uint64)");
const EV_BALLOT_CAST: [u8; 32] =
    event_topic("EncryptedBallotCast(uint64,address,uint64,uint64,bytes32)");
const EV_TALLY_REQUESTED: [u8; 32] =
    event_topic("SecretPollTallyRequested(uint64,bytes32,uint64,uint64)");
const EV_TALLY_VERIFIED: [u8; 32] =
    event_topic("SecretPollTallyVerified(uint64,uint64,uint64,uint64,bytes32,uint64)");

const KEY_INIT: &[u8] = b"sb:init";
const KEY_ID_REGISTRY: &[u8] = b"sb:idreg";
const KEY_SHARE_LEDGER: &[u8] = b"sb:sled";
const KEY_VRF_BEACON: &[u8] = b"sb:beacon";
const KEY_MIN_VALS: &[u8] = b"sb:min_v";
const KEY_ORG_TITLE: &[u8] = b"sb:org";

const KEY_POLL_CNT: &[u8] = b"sb:p_cnt";
const KEY_SETTLED_CNT: &[u8] = b"sb:s_cnt";
const KEY_TOTAL_BALLOTS: &[u8] = b"sb:tot_b";

hps_entry! {
    "initialize(address,address,address,uint64,string)"                   => handle_initialize,
    "createPoll(string,string,uint64,address,uint64)"                     => handle_create_poll,
    "castEncryptedBallot(uint64,bytes,bytes,bytes)"                       => handle_cast_encrypted_ballot,
    "closeAndRequestTally(uint64)"                                        => handle_close_and_request_tally,
    "onHeDecryptionFulfilled(bytes32,bytes,uint64,uint64)"                => handle_on_he_decryption_fulfilled,
    "settlePollFromBeacon(uint64)"                                        => handle_settle_poll_from_beacon,
    "getBallotHubState()"                                                 => handle_get_ballot_hub_state,
    "getPollDetail(uint64)"                                               => handle_get_poll_detail,
    "hasVoted(uint64,address)"                                            => handle_has_voted,
    "hfsType()"                                                           => handle_hfs_type,
}

#[derive(Clone, Copy)]
struct PollMeta {
    poll_id: u64,
    status: u8,
    weight_mode: u8,
    epoch_id: u64,
    open_block: u64,
    close_block: u64,
    settled_block: u64,
    creator: [u8; 20],
    share_ledger: [u8; 20],
    epoch_pk: [u8; 32],
    ballot_count: u32,
    total_weight: u64,
    yes_tally: u64,
    no_tally: u64,
    abstain_tally: u64,
    signer_bitmap: u64,
    dec_req_id: [u8; 32],
    acc_yes: [u8; 64],
    acc_no: [u8; 64],
    acc_abstain: [u8; 64],
    ballots_commit: [u8; 32],
}

impl PollMeta {
    const BYTE_LEN: usize = 414;

    fn encode(&self) -> [u8; Self::BYTE_LEN] {
        let mut b = [0u8; Self::BYTE_LEN];
        b[0..8].copy_from_slice(&self.poll_id.to_be_bytes());
        b[8] = self.status;
        b[9] = self.weight_mode;
        b[10..18].copy_from_slice(&self.epoch_id.to_be_bytes());
        b[18..26].copy_from_slice(&self.open_block.to_be_bytes());
        b[26..34].copy_from_slice(&self.close_block.to_be_bytes());
        b[34..42].copy_from_slice(&self.settled_block.to_be_bytes());
        b[42..62].copy_from_slice(&self.creator);
        b[62..82].copy_from_slice(&self.share_ledger);
        b[82..114].copy_from_slice(&self.epoch_pk);
        b[114..118].copy_from_slice(&self.ballot_count.to_be_bytes());
        b[118..126].copy_from_slice(&self.total_weight.to_be_bytes());
        b[126..134].copy_from_slice(&self.yes_tally.to_be_bytes());
        b[134..142].copy_from_slice(&self.no_tally.to_be_bytes());
        b[142..150].copy_from_slice(&self.abstain_tally.to_be_bytes());
        b[150..158].copy_from_slice(&self.signer_bitmap.to_be_bytes());
        b[158..190].copy_from_slice(&self.dec_req_id);
        b[190..254].copy_from_slice(&self.acc_yes);
        b[254..318].copy_from_slice(&self.acc_no);
        b[318..382].copy_from_slice(&self.acc_abstain);
        b[382..414].copy_from_slice(&self.ballots_commit);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BYTE_LEN {
            return None;
        }
        let mut creator = [0u8; 20];
        let mut share_ledger = [0u8; 20];
        let mut epoch_pk = [0u8; 32];
        let mut dec_req_id = [0u8; 32];
        let mut acc_yes = [0u8; 64];
        let mut acc_no = [0u8; 64];
        let mut acc_abstain = [0u8; 64];
        let mut ballots_commit = [0u8; 32];
        creator.copy_from_slice(&b[42..62]);
        share_ledger.copy_from_slice(&b[62..82]);
        epoch_pk.copy_from_slice(&b[82..114]);
        dec_req_id.copy_from_slice(&b[158..190]);
        acc_yes.copy_from_slice(&b[190..254]);
        acc_no.copy_from_slice(&b[254..318]);
        acc_abstain.copy_from_slice(&b[318..382]);
        ballots_commit.copy_from_slice(&b[382..414]);
        Some(Self {
            poll_id: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            status: b[8],
            weight_mode: b[9],
            epoch_id: u64::from_be_bytes([b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17]]),
            open_block: u64::from_be_bytes([
                b[18], b[19], b[20], b[21], b[22], b[23], b[24], b[25],
            ]),
            close_block: u64::from_be_bytes([
                b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33],
            ]),
            settled_block: u64::from_be_bytes([
                b[34], b[35], b[36], b[37], b[38], b[39], b[40], b[41],
            ]),
            creator,
            share_ledger,
            epoch_pk,
            ballot_count: u32::from_be_bytes([b[114], b[115], b[116], b[117]]),
            total_weight: u64::from_be_bytes([
                b[118], b[119], b[120], b[121], b[122], b[123], b[124], b[125],
            ]),
            yes_tally: u64::from_be_bytes([
                b[126], b[127], b[128], b[129], b[130], b[131], b[132], b[133],
            ]),
            no_tally: u64::from_be_bytes([
                b[134], b[135], b[136], b[137], b[138], b[139], b[140], b[141],
            ]),
            abstain_tally: u64::from_be_bytes([
                b[142], b[143], b[144], b[145], b[146], b[147], b[148], b[149],
            ]),
            signer_bitmap: u64::from_be_bytes([
                b[150], b[151], b[152], b[153], b[154], b[155], b[156], b[157],
            ]),
            dec_req_id,
            acc_yes,
            acc_no,
            acc_abstain,
            ballots_commit,
        })
    }
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn u64_topic(val: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&val.to_be_bytes());
    t
}

fn key_poll(poll_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sb:pm:").push_u64_be(poll_id)
}

fn key_poll_title(poll_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sb:pt:").push_u64_be(poll_id)
}

fn key_poll_desc(poll_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sb:pd:").push_u64_be(poll_id)
}

fn key_voter_receipt(poll_id: u64, voter: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"sb:vt:")
        .push_u64_be(poll_id)
        .push(voter)
}

fn key_ballot_record(poll_id: u64, ballot_idx: u32) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"sb:bl:")
        .push_u64_be(poll_id)
        .push(&ballot_idx.to_be_bytes())
}

fn key_dec_to_poll(dec_req_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"sb:dr:").push(dec_req_id)
}

fn load_poll(poll_id: u64) -> Option<PollMeta> {
    if poll_id == 0 {
        return None;
    }
    let mut buf = [0u8; PollMeta::BYTE_LEN];
    let n = storage::get_into(key_poll(poll_id).as_slice(), &mut buf)?;
    if n < PollMeta::BYTE_LEN {
        return None;
    }
    PollMeta::decode(&buf)
}

fn save_poll(meta: &PollMeta) {
    storage::set(key_poll(meta.poll_id).as_slice(), &meta.encode());
}

fn query_share_balance(share_ledger: &[u8; 20], holder: &[u8; 20]) -> Result<u64, i32> {
    let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(holder);
    call::call_u64(share_ledger, cd.as_slice())
}

/// Builds the 68-byte domain-separated CDS `0/1` OR-proof context:
/// `"SLX_BALLOT_OR01_V1:" (19B) || ballot_addr (20B) || poll_id_be8 (8B) || voter (20B) || [slot] (1B)`.
pub fn build_ballot_or01_ctx(
    ballot_addr: &[u8; 20],
    poll_id: u64,
    voter: &[u8; 20],
    slot: u8,
) -> [u8; 68] {
    let mut ctx = [0u8; 68];
    ctx[0..19].copy_from_slice(b"SLX_BALLOT_OR01_V1:");
    ctx[19..39].copy_from_slice(ballot_addr);
    ctx[39..47].copy_from_slice(&poll_id.to_be_bytes());
    ctx[47..67].copy_from_slice(voter);
    ctx[67] = slot;
    ctx
}

/// Builds the 67-byte domain-separated one-hot `sum == 1` DLEQ proof context:
/// `"SLX_BALLOT_SUM1_V1:" (19B) || ballot_addr (20B) || poll_id_be8 (8B) || voter (20B)`.
pub fn build_ballot_sum1_ctx(
    ballot_addr: &[u8; 20],
    poll_id: u64,
    voter: &[u8; 20],
) -> [u8; 67] {
    let mut ctx = [0u8; 67];
    ctx[0..19].copy_from_slice(b"SLX_BALLOT_SUM1_V1:");
    ctx[19..39].copy_from_slice(ballot_addr);
    ctx[39..47].copy_from_slice(&poll_id.to_be_bytes());
    ctx[47..67].copy_from_slice(voter);
    ctx
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-10);
    }
    let id_registry = args.address(0).ok_or(-3)?;
    let share_ledger = args.address(1).ok_or(-3)?;
    let vrf_beacon = args.address(2).ok_or(-3)?;
    let min_vals = args.u64(3).ok_or(-3)?.max(1);
    let org_title = args.dynamic_bytes(4).ok_or(-3)?;
    if org_title.is_empty() || org_title.len() > 96 {
        return Err(-3);
    }

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_ID_REGISTRY, &id_registry);
    storage::set_address(KEY_SHARE_LEDGER, &share_ledger);
    storage::set_address(KEY_VRF_BEACON, &vrf_beacon);
    storage::set_u64(KEY_MIN_VALS, min_vals);
    storage::set(KEY_ORG_TITLE, org_title);

    let mut ev = [0u8; 68];
    ev[0..20].copy_from_slice(&id_registry);
    ev[20..40].copy_from_slice(&share_ledger);
    ev[40..60].copy_from_slice(&vrf_beacon);
    ev[60..68].copy_from_slice(&min_vals.to_be_bytes());
    events::emit(&[EV_BALLOT_HUB_INIT], &ev);

    ret::write_bool(true);
    Ok(())
}

/// Creates a new secret-ballot poll locked to the active validator quorum's `EpochPK`.
/// - `weightMode`: `1` = `1-Identity = 1-Vote`, `2` = `ShareLedger` token-weighted.
/// - `shareLedgerOverride`: optional custom `ShareLedger` (`[0u8; 20]` uses `defaultShareLedger`).
fn handle_create_poll(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let title = args.dynamic_bytes(0).ok_or(-3)?;
    let desc = args.dynamic_bytes(1).ok_or(-3)?;
    let weight_mode_u64 = args.u64(2).ok_or(-3)?;
    let share_override = args.address(3).ok_or(-3)?;
    let duration_blocks = args.u64(4).ok_or(-3)?.max(2);

    if title.is_empty() || title.len() > 96 || desc.len() > 256 {
        return Err(-3);
    }
    let weight_mode = match weight_mode_u64 {
        1 => WEIGHT_MODE_ONE_VOTE,
        2 => WEIGHT_MODE_SHARE_LEDGER,
        _ => return Err(-3),
    };

    let creator = context::msg_sender();
    let id_registry = storage::get_address(KEY_ID_REGISTRY).ok_or(-11)?;
    require_valid_identity(&id_registry, &creator)?;

    let share_ledger = if weight_mode == WEIGHT_MODE_SHARE_LEDGER {
        let chosen = if share_override != [0u8; 20] {
            share_override
        } else {
            storage::get_address(KEY_SHARE_LEDGER).unwrap_or([0u8; 20])
        };
        if chosen == [0u8; 20] {
            return Err(-12);
        }
        chosen
    } else {
        [0u8; 20]
    };

    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    let min_vals = storage::get_u64(KEY_MIN_VALS);
    let key_cd = CallEncoder::<16>::new(const { selector("getActiveEpochKey()") });
    let mut key_buf = [0u8; 48];
    let kn = call::call_into(&vrf_beacon, key_cd.as_slice(), &mut key_buf)?;
    if kn < 48 {
        return Err(-13);
    }
    let epoch_id = u64::from_be_bytes([
        key_buf[0], key_buf[1], key_buf[2], key_buf[3], key_buf[4], key_buf[5], key_buf[6],
        key_buf[7],
    ]);
    let val_count =
        u32::from_be_bytes([key_buf[12], key_buf[13], key_buf[14], key_buf[15]]) as u64;
    if val_count < min_vals {
        return Err(-14); // Active validator quorum smaller than hub's safety floor!
    }
    let mut epoch_pk = [0u8; 32];
    epoch_pk.copy_from_slice(&key_buf[16..48]);

    let now_block = context::block_number();
    let close_block = now_block.saturating_add(duration_blocks);
    let poll_id = storage::get_u64(KEY_POLL_CNT).saturating_add(1);
    storage::set_u64(KEY_POLL_CNT, poll_id);

    let meta = PollMeta {
        poll_id,
        status: POLL_OPEN,
        weight_mode,
        epoch_id,
        open_block: now_block,
        close_block,
        settled_block: 0,
        creator,
        share_ledger,
        epoch_pk,
        ballot_count: 0,
        total_weight: 0,
        yes_tally: 0,
        no_tally: 0,
        abstain_tally: 0,
        signer_bitmap: 0,
        dec_req_id: [0u8; 32],
        acc_yes: vrf::IDENTITY_CIPHERTEXT_64,
        acc_no: vrf::IDENTITY_CIPHERTEXT_64,
        acc_abstain: vrf::IDENTITY_CIPHERTEXT_64,
        ballots_commit: [0u8; 32],
    };
    save_poll(&meta);
    storage::set(key_poll_title(poll_id).as_slice(), title);
    if !desc.is_empty() {
        storage::set(key_poll_desc(poll_id).as_slice(), desc);
    }

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&(weight_mode as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&epoch_id.to_be_bytes());
    ev[16..24].copy_from_slice(&close_block.to_be_bytes());
    events::emit(
        &[EV_POLL_CREATED, u64_topic(poll_id), addr_topic(&creator)],
        &ev,
    );

    ret::write_u64_word(poll_id);
    Ok(())
}

/// Casts an encrypted one-hot ballot `(Enc(b_yes), Enc(b_no), Enc(b_abstain))` (`192` bytes)
/// verified by three 128-byte CDS `0/1` OR-proofs (`384` bytes) and one 64-byte Chaum-Pedersen
/// DLEQ proof that `b_yes + b_no + b_abstain == 1`.
fn handle_cast_encrypted_ballot(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let poll_id = args.u64(0).ok_or(-3)?;
    let ciphertexts = args.dynamic_bytes(1).ok_or(-3)?;
    let or_proofs = args.dynamic_bytes(2).ok_or(-3)?;
    let sum_proof_slice = args.dynamic_bytes(3).ok_or(-3)?;
    if ciphertexts.len() != 192 || or_proofs.len() != 384 || sum_proof_slice.len() != 64 {
        return Err(-3);
    }

    let mut poll = load_poll(poll_id).ok_or(-15)?;
    if poll.status != POLL_OPEN {
        return Err(-16); // Poll already closed for decryption!
    }
    if (poll.ballot_count as usize) >= MAX_BALLOTS_PER_POLL {
        return Err(-17);
    }

    let voter = context::msg_sender();
    let id_registry = storage::get_address(KEY_ID_REGISTRY).ok_or(-11)?;
    require_valid_identity(&id_registry, &voter)?;

    let receipt_key = key_voter_receipt(poll_id, &voter);
    if storage::exists(receipt_key.as_slice()) {
        return Err(-20); // Voter already cast an encrypted ballot in this poll!
    }

    let weight = if poll.weight_mode == WEIGHT_MODE_ONE_VOTE {
        1u64
    } else {
        let bal = query_share_balance(&poll.share_ledger, &voter)?;
        if bal == 0 {
            return Err(-22); // Voter holds 0 shares in the poll's ShareLedger!
        }
        bal
    };
    let new_total_weight = poll.total_weight.checked_add(weight).ok_or(-23)?;
    if new_total_weight > MAX_HE_BSGS_BOUND {
        return Err(-23);
    }

    let self_addr = context::self_address();
    let mut cts = [[0u8; 64]; 3];
    let mut slot = 0usize;
    while slot < 3 {
        cts[slot].copy_from_slice(&ciphertexts[slot * 64..(slot + 1) * 64]);
        let mut proof_128 = [0u8; 128];
        proof_128.copy_from_slice(&or_proofs[slot * 128..(slot + 1) * 128]);
        let or_ctx = build_ballot_or01_ctx(&self_addr, poll_id, &voter, slot as u8);
        if !vrf::he_verify_zero_or_one(&poll.epoch_pk, &cts[slot], &or_ctx, &proof_128) {
            return Err(-24); // Ciphertext slot failed CDS 0/1 zero-knowledge proof!
        }
        slot += 1;
    }

    // Homomorphically sum `C_sum = C_0 + C_1 + C_2` and verify `C_sum` encrypts `1`:
    // `log_B(C_sum,1) == log_EpochPK(C_sum,2 - B)`.
    let c01 = vrf::he_add_ciphertexts(&cts[0], &cts[1]).ok_or(-25)?;
    let c_sum = vrf::he_add_ciphertexts(&c01, &cts[2]).ok_or(-25)?;
    let mut c_sum_1 = [0u8; 32];
    let mut c_sum_2 = [0u8; 32];
    c_sum_1.copy_from_slice(&c_sum[0..32]);
    c_sum_2.copy_from_slice(&c_sum[32..64]);
    if c_sum_1 == vrf::IDENTITY_POINT_BYTES {
        return Err(-26);
    }
    let c_sum_2_minus_b = vrf::ec_elgamal_lincomb(
        &vrf::SCALAR_ONE_BYTES,
        &c_sum_2,
        &vrf::SCALAR_MINUS_ONE_BYTES,
        &vrf::ED25519_BASEPOINT_BYTES,
    )
    .ok_or(-25)?;

    let mut sum_proof_64 = [0u8; 64];
    sum_proof_64.copy_from_slice(sum_proof_slice);
    let sum_ctx = build_ballot_sum1_ctx(&self_addr, poll_id, &voter);
    if !vrf::ec_dleq_verify(
        &vrf::ED25519_BASEPOINT_BYTES,
        &c_sum_1,
        &poll.epoch_pk,
        &c_sum_2_minus_b,
        &sum_ctx,
        &sum_proof_64,
    ) {
        return Err(-26); // One-hot `b_yes + b_no + b_abstain == 1` DLEQ proof failed!
    }

    // Scale each verified `Enc(b_s)` by `weight` and homomorphically add into the 3 poll accumulators!
    let w_yes = vrf::he_scale_ciphertext(&cts[0], weight).ok_or(-27)?;
    let w_no = vrf::he_scale_ciphertext(&cts[1], weight).ok_or(-27)?;
    let w_abs = vrf::he_scale_ciphertext(&cts[2], weight).ok_or(-27)?;
    poll.acc_yes = vrf::he_add_ciphertexts(&poll.acc_yes, &w_yes).ok_or(-27)?;
    poll.acc_no = vrf::he_add_ciphertexts(&poll.acc_no, &w_no).ok_or(-27)?;
    poll.acc_abstain = vrf::he_add_ciphertexts(&poll.acc_abstain, &w_abs).ok_or(-27)?;

    let now_block = context::block_number();
    let idx = poll.ballot_count;
    poll.ballot_count = idx.saturating_add(1);
    poll.total_weight = new_total_weight;

    let mut cpre = [0u8; 21 + 32 + 20 + 8 + 192];
    cpre[0..21].copy_from_slice(b"SLX_BALLOT_COMMIT_V1:");
    cpre[21..53].copy_from_slice(&poll.ballots_commit);
    cpre[53..73].copy_from_slice(&voter);
    cpre[73..81].copy_from_slice(&weight.to_be_bytes());
    cpre[81..273].copy_from_slice(ciphertexts);
    poll.ballots_commit = keccak256(&cpre);
    save_poll(&poll);

    let mut receipt = [0u8; 20];
    receipt[0..4].copy_from_slice(&idx.to_be_bytes());
    receipt[4..12].copy_from_slice(&now_block.to_be_bytes());
    receipt[12..20].copy_from_slice(&weight.to_be_bytes());
    storage::set(receipt_key.as_slice(), &receipt);

    let mut bl_rec = [0u8; BALLOT_RECORD_LEN];
    bl_rec[0..20].copy_from_slice(&voter);
    bl_rec[20..28].copy_from_slice(&now_block.to_be_bytes());
    bl_rec[28..36].copy_from_slice(&weight.to_be_bytes());
    bl_rec[36..228].copy_from_slice(ciphertexts);
    storage::set(key_ballot_record(poll_id, idx).as_slice(), &bl_rec);

    storage::set_u64(
        KEY_TOTAL_BALLOTS,
        storage::get_u64(KEY_TOTAL_BALLOTS).saturating_add(1),
    );

    let mut ev = [0u8; 48];
    ev[0..8].copy_from_slice(&weight.to_be_bytes());
    ev[8..16].copy_from_slice(&(poll.ballot_count as u64).to_be_bytes());
    ev[16..48].copy_from_slice(&poll.ballots_commit);
    events::emit(
        &[EV_BALLOT_CAST, u64_topic(poll_id), addr_topic(&voter)],
        &ev,
    );

    ret::write_u64_word(poll.ballot_count as u64);
    Ok(())
}

/// Freezes `pollId` once `close_block` arrives (or `MAX_BALLOTS_PER_POLL` is full) and requests
/// validator-quorum threshold decryption of `(acc_yes, acc_no, acc_abstain)` from `vrf-beacon`.
fn handle_close_and_request_tally(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let poll_id = args.u64(0).ok_or(-3)?;
    let mut poll = load_poll(poll_id).ok_or(-15)?;
    if poll.status != POLL_OPEN {
        return Err(-16);
    }
    if poll.ballot_count == 0 {
        return Err(-28); // Cannot decrypt an empty poll!
    }
    let now_block = context::block_number();
    if now_block < poll.close_block && (poll.ballot_count as usize) < MAX_BALLOTS_PER_POLL {
        return Err(-29); // Voting window still open!
    }

    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    let min_vals = storage::get_u64(KEY_MIN_VALS);

    let mut packed_cts = [0u8; 192];
    packed_cts[0..64].copy_from_slice(&poll.acc_yes);
    packed_cts[64..128].copy_from_slice(&poll.acc_no);
    packed_cts[128..192].copy_from_slice(&poll.acc_abstain);

    let req_cd = CallEncoder::<512>::new(const {
        selector("requestThresholdDecryption(uint64,bytes,uint64,uint64)")
    })
    .push_u64(poll.epoch_id)
    .push_u64(128)
    .push_u64(poll.total_weight)
    .push_u64(min_vals)
    .push_dynamic_bytes_tail(&packed_cts);

    let mut dec_req_id = [0u8; 32];
    let rn = call::call_into(&vrf_beacon, req_cd.as_slice(), &mut dec_req_id)?;
    if rn < 32 {
        return Err(-30);
    }

    poll.status = POLL_DECRYPTING;
    poll.dec_req_id = dec_req_id;
    save_poll(&poll);
    storage::set_u64(key_dec_to_poll(&dec_req_id).as_slice(), poll_id);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&(poll.ballot_count as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&poll.total_weight.to_be_bytes());
    events::emit(
        &[EV_TALLY_REQUESTED, u64_topic(poll_id), dec_req_id],
        &ev,
    );

    ret::write_word(&dec_req_id);
    Ok(())
}

fn finalize_poll_tallies(
    poll: &mut PollMeta,
    dec_req_id: &[u8; 32],
    yes_tally: u64,
    no_tally: u64,
    abstain_tally: u64,
    signer_bitmap: u64,
) -> Result<(), i32> {
    if poll.status == POLL_TALLY_VERIFIED {
        return Ok(());
    }
    if poll.status != POLL_DECRYPTING || poll.dec_req_id != *dec_req_id {
        return Err(-31);
    }
    let sum = yes_tally
        .checked_add(no_tally)
        .and_then(|v| v.checked_add(abstain_tally))
        .ok_or(-32)?;
    if sum != poll.total_weight {
        return Err(-32); // Mathematical conservation invariant check!
    }

    poll.status = POLL_TALLY_VERIFIED;
    poll.yes_tally = yes_tally;
    poll.no_tally = no_tally;
    poll.abstain_tally = abstain_tally;
    poll.signer_bitmap = signer_bitmap;
    poll.settled_block = context::block_number();
    save_poll(poll);

    storage::set_u64(
        KEY_SETTLED_CNT,
        storage::get_u64(KEY_SETTLED_CNT).saturating_add(1),
    );

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&yes_tally.to_be_bytes());
    ev[8..16].copy_from_slice(&no_tally.to_be_bytes());
    ev[16..24].copy_from_slice(&abstain_tally.to_be_bytes());
    ev[24..32].copy_from_slice(&signer_bitmap.to_be_bytes());
    events::emit(
        &[EV_TALLY_VERIFIED, u64_topic(poll.poll_id), *dec_req_id],
        &ev,
    );
    Ok(())
}

/// Synchronous callback invoked by `vrf-beacon` the instant the validator supermajority (`> 2/3`)
/// submits verified partial decryption shares for `(acc_yes, acc_no, acc_abstain)`.
fn handle_on_he_decryption_fulfilled(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    if context::msg_sender() != vrf_beacon {
        return Err(-33);
    }
    let dec_req_id = args.bytes32(0).ok_or(-3)?;
    let tallies_raw = args.dynamic_bytes(1).ok_or(-3)?;
    let _epoch_id = args.u64(2).ok_or(-3)?;
    let signer_bitmap = args.u64(3).ok_or(-3)?;
    if tallies_raw.len() != 24 {
        return Err(-3);
    }

    let poll_id = storage::get_u64(key_dec_to_poll(&dec_req_id).as_slice());
    let mut poll = load_poll(poll_id).ok_or(-15)?;
    let yes_tally = u64::from_be_bytes([
        tallies_raw[0],
        tallies_raw[1],
        tallies_raw[2],
        tallies_raw[3],
        tallies_raw[4],
        tallies_raw[5],
        tallies_raw[6],
        tallies_raw[7],
    ]);
    let no_tally = u64::from_be_bytes([
        tallies_raw[8],
        tallies_raw[9],
        tallies_raw[10],
        tallies_raw[11],
        tallies_raw[12],
        tallies_raw[13],
        tallies_raw[14],
        tallies_raw[15],
    ]);
    let abstain_tally = u64::from_be_bytes([
        tallies_raw[16],
        tallies_raw[17],
        tallies_raw[18],
        tallies_raw[19],
        tallies_raw[20],
        tallies_raw[21],
        tallies_raw[22],
        tallies_raw[23],
    ]);

    finalize_poll_tallies(
        &mut poll,
        &dec_req_id,
        yes_tally,
        no_tally,
        abstain_tally,
        signer_bitmap,
    )?;
    ret::write_bool(true);
    Ok(())
}

/// Permissionless fallback settlement reader in case `onHeDecryptionFulfilled` was skipped.
fn handle_settle_poll_from_beacon(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let poll_id = args.u64(0).ok_or(-3)?;
    let mut poll = load_poll(poll_id).ok_or(-15)?;
    if poll.status == POLL_TALLY_VERIFIED {
        ret::write_bool(true);
        return Ok(());
    }
    if poll.status != POLL_DECRYPTING {
        return Err(-31);
    }

    let vrf_beacon = storage::get_address(KEY_VRF_BEACON).ok_or(-11)?;
    let cd = CallEncoder::<64>::new(const { selector("getDecryptedTallies(bytes32)") })
        .push_bytes32(&poll.dec_req_id);
    let mut raw = [0u8; 42];
    let rn = call::call_into(&vrf_beacon, cd.as_slice(), &mut raw)?;
    if rn < 42 || raw[0] != 2 || raw[1] != 3 {
        return Err(-34); // Beacon decryption not yet fulfilled!
    }
    let signer_bitmap = u64::from_be_bytes([
        raw[10], raw[11], raw[12], raw[13], raw[14], raw[15], raw[16], raw[17],
    ]);
    let yes_tally = u64::from_be_bytes([
        raw[18], raw[19], raw[20], raw[21], raw[22], raw[23], raw[24], raw[25],
    ]);
    let no_tally = u64::from_be_bytes([
        raw[26], raw[27], raw[28], raw[29], raw[30], raw[31], raw[32], raw[33],
    ]);
    let abstain_tally = u64::from_be_bytes([
        raw[34], raw[35], raw[36], raw[37], raw[38], raw[39], raw[40], raw[41],
    ]);
    let req_id = poll.dec_req_id;
    finalize_poll_tallies(
        &mut poll,
        &req_id,
        yes_tally,
        no_tally,
        abstain_tally,
        signer_bitmap,
    )?;
    ret::write_bool(true);
    Ok(())
}

/// Binary overview of CipherVote hub + up to `32` recent polls (newest first):
/// Header (`110` bytes + `org_title`):
/// `[poll_cnt:8][settled_cnt:8][tot_ballots:8][min_vals:8][now_blk:8][id_reg:20][share_led:20][beacon:20]`
/// `[org_title_len:2][returned_polls:4][reserved:4][org_title_bytes]`
/// Per-poll summary (`160 + title_len` bytes):
/// `[poll_id:8][status:1][weight_mode:1][epoch_id:8][open_blk:8][close_blk:8][settled_blk:8]`
/// `[creator:20][share_ledger:20][ballot_cnt:4][total_weight:8][yes:8][no:8][abstain:8]`
/// `[signer_bitmap:8][dec_req_id:32][title_len:2][title_bytes]`
fn handle_get_ballot_hub_state(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let poll_cnt = storage::get_u64(KEY_POLL_CNT);
    let settled_cnt = storage::get_u64(KEY_SETTLED_CNT);
    let tot_ballots = storage::get_u64(KEY_TOTAL_BALLOTS);
    let min_vals = storage::get_u64(KEY_MIN_VALS);
    let now_blk = context::block_number();
    let id_reg = storage::get_address(KEY_ID_REGISTRY).unwrap_or([0u8; 20]);
    let share_led = storage::get_address(KEY_SHARE_LEDGER).unwrap_or([0u8; 20]);
    let beacon = storage::get_address(KEY_VRF_BEACON).unwrap_or([0u8; 20]);

    let mut org_buf = [0u8; 96];
    let org_len = storage::get_into(KEY_ORG_TITLE, &mut org_buf)
        .unwrap_or(0)
        .min(96);

    let mut out = [0u8; 110 + 96 + MAX_POLLS_RETURNED * (160 + 96)];
    out[0..8].copy_from_slice(&poll_cnt.to_be_bytes());
    out[8..16].copy_from_slice(&settled_cnt.to_be_bytes());
    out[16..24].copy_from_slice(&tot_ballots.to_be_bytes());
    out[24..32].copy_from_slice(&min_vals.to_be_bytes());
    out[32..40].copy_from_slice(&now_blk.to_be_bytes());
    out[40..60].copy_from_slice(&id_reg);
    out[60..80].copy_from_slice(&share_led);
    out[80..100].copy_from_slice(&beacon);
    out[100..102].copy_from_slice(&(org_len as u16).to_be_bytes());
    out[110..110 + org_len].copy_from_slice(&org_buf[..org_len]);

    let mut cursor = 110 + org_len;
    let mut returned = 0u32;
    let mut pid = poll_cnt;
    while pid >= 1 && (returned as usize) < MAX_POLLS_RETURNED {
        if let Some(pm) = load_poll(pid) {
            let mut tbuf = [0u8; 96];
            let tlen = storage::get_into(key_poll_title(pid).as_slice(), &mut tbuf)
                .unwrap_or(0)
                .min(96);
            out[cursor..cursor + 8].copy_from_slice(&pm.poll_id.to_be_bytes());
            out[cursor + 8] = pm.status;
            out[cursor + 9] = pm.weight_mode;
            out[cursor + 10..cursor + 18].copy_from_slice(&pm.epoch_id.to_be_bytes());
            out[cursor + 18..cursor + 26].copy_from_slice(&pm.open_block.to_be_bytes());
            out[cursor + 26..cursor + 34].copy_from_slice(&pm.close_block.to_be_bytes());
            out[cursor + 34..cursor + 42].copy_from_slice(&pm.settled_block.to_be_bytes());
            out[cursor + 42..cursor + 62].copy_from_slice(&pm.creator);
            out[cursor + 62..cursor + 82].copy_from_slice(&pm.share_ledger);
            out[cursor + 82..cursor + 86].copy_from_slice(&pm.ballot_count.to_be_bytes());
            out[cursor + 86..cursor + 94].copy_from_slice(&pm.total_weight.to_be_bytes());
            out[cursor + 94..cursor + 102].copy_from_slice(&pm.yes_tally.to_be_bytes());
            out[cursor + 102..cursor + 110].copy_from_slice(&pm.no_tally.to_be_bytes());
            out[cursor + 110..cursor + 118].copy_from_slice(&pm.abstain_tally.to_be_bytes());
            out[cursor + 118..cursor + 126].copy_from_slice(&pm.signer_bitmap.to_be_bytes());
            out[cursor + 126..cursor + 158].copy_from_slice(&pm.dec_req_id);
            out[cursor + 158..cursor + 160].copy_from_slice(&(tlen as u16).to_be_bytes());
            out[cursor + 160..cursor + 160 + tlen].copy_from_slice(&tbuf[..tlen]);
            cursor += 160 + tlen;
            returned += 1;
        }
        pid -= 1;
    }
    out[102..106].copy_from_slice(&returned.to_be_bytes());

    ret::write(&out[..cursor]);
    Ok(())
}

/// Full detail & encrypted ballot box for `pollId` (enabling 1-click browser homomorphic re-summation!):
/// - `[0..414]`: `PollMeta::encode()` (`acc_yes_64`, `acc_no_64`, `acc_abstain_64`, `epoch_pk_32`, tallies, etc.)
/// - `[414..416]`: `title_len` (`u16 BE`)
/// - `[416..418]`: `desc_len` (`u16 BE`)
/// - `title` (`title_len` bytes) + `desc` (`desc_len` bytes)
/// - `ballot_count` (`<= 128`) records of `228` bytes each:
///   `[voter_20 || block_be8 || weight_be8 || ct_yes_64 || ct_no_64 || ct_abstain_64]`
fn handle_get_poll_detail(args: &CalldataReader) -> Result<(), i32> {
    let poll_id = args.u64(0).ok_or(-3)?;
    let pm = load_poll(poll_id).ok_or(-15)?;
    let mut tbuf = [0u8; 96];
    let mut dbuf = [0u8; 256];
    let tlen = storage::get_into(key_poll_title(poll_id).as_slice(), &mut tbuf)
        .unwrap_or(0)
        .min(96);
    let dlen = storage::get_into(key_poll_desc(poll_id).as_slice(), &mut dbuf)
        .unwrap_or(0)
        .min(256);

    let bcnt = (pm.ballot_count as usize).min(MAX_BALLOTS_PER_POLL);
    let mut out = [0u8; 418 + 96 + 256 + MAX_BALLOTS_PER_POLL * BALLOT_RECORD_LEN];
    out[0..414].copy_from_slice(&pm.encode());
    out[414..416].copy_from_slice(&(tlen as u16).to_be_bytes());
    out[416..418].copy_from_slice(&(dlen as u16).to_be_bytes());

    let mut cursor = 418usize;
    out[cursor..cursor + tlen].copy_from_slice(&tbuf[..tlen]);
    cursor += tlen;
    out[cursor..cursor + dlen].copy_from_slice(&dbuf[..dlen]);
    cursor += dlen;

    let mut i = 0usize;
    while i < bcnt {
        let mut rec = [0u8; BALLOT_RECORD_LEN];
        if let Some(rn) = storage::get_into(
            key_ballot_record(poll_id, i as u32).as_slice(),
            &mut rec,
        ) {
            if rn >= BALLOT_RECORD_LEN {
                out[cursor..cursor + BALLOT_RECORD_LEN].copy_from_slice(&rec);
                cursor += BALLOT_RECORD_LEN;
            }
        }
        i += 1;
    }

    ret::write(&out[..cursor]);
    Ok(())
}

/// Returns `21` bytes `[voted_u8 || ballot_idx_be4 || block_be8 || weight_be8]` for `(pollId, voter)`.
fn handle_has_voted(args: &CalldataReader) -> Result<(), i32> {
    let poll_id = args.u64(0).ok_or(-3)?;
    let voter = args.address(1).ok_or(-3)?;
    let mut out = [0u8; 21];
    let mut rec = [0u8; 20];
    if let Some(20) = storage::get_into(key_voter_receipt(poll_id, &voter).as_slice(), &mut rec) {
        out[0] = 1;
        out[1..21].copy_from_slice(&rec);
    }
    ret::write(&out);
    Ok(())
}

fn handle_hfs_type(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_abi_bytes(b"SECRET_BALLOT");
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
    use hps_sdk::vrf::mock_crypto::{self, Scalar, SigningKey};

    fn mock_id_registry_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, reader)) = CalldataReader::parse(raw) else {
            return -1;
        };
        if sel == selector("register(address)") {
            let id = reader.address(0).unwrap();
            storage::set_u64(KeyBuilder::<32>::new().push(b"id:").push(&id).as_slice(), 1);
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("isValidIdentity(address)") {
            let id = reader.address(0).unwrap();
            let ok =
                storage::get_u64(KeyBuilder::<32>::new().push(b"id:").push(&id).as_slice()) == 1;
            ret::write_bool(ok);
            return 0;
        }
        -2
    }

    fn mock_share_ledger_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, reader)) = CalldataReader::parse(raw) else {
            return -1;
        };
        if sel == selector("setShares(address,uint64)") {
            let h = reader.address(0).unwrap();
            let amt = reader.u64(1).unwrap();
            storage::set_u64(KeyBuilder::<32>::new().push(b"sh:").push(&h).as_slice(), amt);
            ret::write_bool(true);
            return 0;
        }
        if sel == selector("balanceOf(address)") {
            let h = reader.address(0).unwrap();
            let amt = storage::get_u64(KeyBuilder::<32>::new().push(b"sh:").push(&h).as_slice());
            ret::write_u64_word(amt);
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
        if sel == selector("execute(address,bytes)") {
            let caller = context::msg_sender();
            let owner = storage::get_address(b"owner").unwrap_or([0u8; 20]);
            if caller != owner {
                return -21;
            }
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

    /// Helper to encrypt a one-hot `(Yes / No / Abstain)` choice (`choice_slot in 0..3`)
    /// and construct the `192B + 384B + 64B` zero-knowledge ballot bundle.
    fn build_encrypted_one_hot_ballot(
        epoch_pk: &[u8; 32],
        ballot_addr: &[u8; 20],
        poll_id: u64,
        voter_id: &[u8; 20],
        choice_slot: usize,
        seed_byte: u8,
    ) -> ([u8; 192], [u8; 384], [u8; 64]) {
        let mut cts = [0u8; 192];
        let mut or_proofs = [0u8; 384];
        let mut r_sum = Scalar::ZERO;
        for s in 0..3usize {
            let bit = if s == choice_slot { 1u8 } else { 0u8 };
            let r = Scalar::from(10_000u64 + (seed_byte as u64) * 97 + (s as u64) * 31);
            r_sum += r;
            let or_ctx = build_ballot_or01_ctx(ballot_addr, poll_id, voter_id, s as u8);
            let (ct_64, proof_128) = mock_crypto::prove_he_zero_or_one(
                epoch_pk,
                bit,
                &r,
                &or_ctx,
                &[seed_byte.wrapping_add(s as u8); 32],
            )
            .unwrap();
            cts[s * 64..(s + 1) * 64].copy_from_slice(&ct_64);
            or_proofs[s * 128..(s + 1) * 128].copy_from_slice(&proof_128);
        }
        let sum_ctx = build_ballot_sum1_ctx(ballot_addr, poll_id, voter_id);
        let sum_proof_64 = mock_crypto::prove_he_sum_equals_one(
            epoch_pk,
            &r_sum,
            &sum_ctx,
            &[seed_byte.wrapping_add(99); 32],
        )
        .unwrap();
        (cts, or_proofs, sum_proof_64)
    }

    fn encode_cast_ballot_tx(
        ballot_addr: &[u8; 20],
        poll_id: u64,
        cts: &[u8; 192],
        or_proofs: &[u8; 384],
        sum_proof: &[u8; 64],
    ) -> CallEncoder<2048> {
        // Head of `castEncryptedBallot(uint64,bytes,bytes,bytes)` = 4 * 32 = 128 bytes:
        // - arg 0: pollId
        // - arg 1: offset of cts (128)
        // - arg 2: offset of orProofs (128 + 32 + 192 = 352)
        // - arg 3: offset of sumProof (352 + 32 + 384 = 768)
        let inner = CallEncoder::<1024>::new(selector(
            "castEncryptedBallot(uint64,bytes,bytes,bytes)",
        ))
        .push_u64(poll_id)
        .push_u64(128)
        .push_u64(352)
        .push_u64(768)
        .push_dynamic_bytes_tail(cts)
        .push_dynamic_bytes_tail(or_proofs)
        .push_dynamic_bytes_tail(sum_proof);

        CallEncoder::<2048>::new(selector("execute(address,bytes)"))
            .push_address(ballot_addr)
            .push_u64(64)
            .push_dynamic_bytes_tail(inner.as_slice())
    }

    #[test]
    fn secret_ballot_share_weighted_and_civic_polls_with_rogue_ballot_rejection() {
        mock::reset();
        mock::set_block_number(200);

        // 1. Setup 5 active `Full` validators (`threshold = 4`) and run Epoch #1 DKG on `vrf-beacon`.
        let mut raw_vals: Vec<([u8; 20], SigningKey, [u8; 32])> = (0u8..5)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i + 21;
                seed[31] = 0x55;
                let sk = SigningKey::from_bytes(&seed);
                let pk = sk.verifying_key().to_bytes();
                let mut addr = [0u8; 20];
                addr[19] = i + 1;
                (addr, sk, pk)
            })
            .collect();
        raw_vals.sort_by(|a, b| a.2.cmp(&b.2));
        let val_entries: Vec<([u8; 20], [u8; 32])> =
            raw_vals.iter().map(|(a, _, p)| (*a, *p)).collect();
        let val_keys: Vec<SigningKey> = raw_vals.iter().map(|(_, k, _)| k.clone()).collect();
        let pks: Vec<[u8; 32]> = raw_vals.iter().map(|(_, _, p)| *p).collect();
        mock_crypto::set_mock_validators(&val_entries);

        let admin_eoa = [0xA0; 20];
        let alice_eoa = [0xA1; 20];
        let bob_eoa = [0xA2; 20];
        let carol_eoa = [0xA3; 20];

        let id_reg = [0x20; 20];
        let share_led = [0x21; 20];
        let beacon = [0x22; 20];
        let ballot_hub = [0x23; 20];
        let alice_id = [0x31; 20];
        let bob_id = [0x32; 20];
        let carol_id = [0x33; 20];

        mock::register_hps(id_reg, mock_id_registry_dispatch);
        mock::register_hps(share_led, mock_share_ledger_dispatch);
        mock::register_hps(beacon, beacon_mod::dispatch_calldata);
        mock::register_hps(ballot_hub, dispatch_calldata);
        for (id, owner) in [(alice_id, alice_eoa), (bob_id, bob_eoa), (carol_id, carol_eoa)] {
            mock::register_hps(id, mock_identity_dispatch);
            mock::transact_as(
                admin_eoa,
                id_reg,
                CallEncoder::<64>::new(selector("register(address)"))
                    .push_address(&id)
                    .as_slice(),
            )
            .unwrap();
            mock::transact_as(
                owner,
                id,
                CallEncoder::<64>::new(selector("init(address)"))
                    .push_address(&owner)
                    .as_slice(),
            )
            .unwrap();
        }

        // Seed `SLX-EQ` shareholdings: Alice = 100,000, Bob = 42,500, Carol = 15,500.
        for (id, sh) in [(alice_id, 100_000u64), (bob_id, 42_500u64), (carol_id, 15_500u64)] {
            mock::transact_as(
                admin_eoa,
                share_led,
                CallEncoder::<96>::new(selector("setShares(address,uint64)"))
                    .push_address(&id)
                    .push_u64(sh)
                    .as_slice(),
            )
            .unwrap();
        }

        // Activate Epoch #1 on `vrf-beacon`.
        mock::transact_as(
            admin_eoa,
            beacon,
            CallEncoder::<16>::new(selector("syncEpoch()")).as_slice(),
        )
        .unwrap();
        let set_hash = mock_crypto::compute_validator_set_hash(4, &pks);
        let mut deals = Vec::new();
        for (idx, vk) in val_keys.iter().enumerate() {
            let deal = mock_crypto::create_validator_dkg_deal(
                vk,
                &set_hash,
                idx,
                4,
                &pks,
                &[idx as u8 + 11; 32],
            )
            .unwrap();
            let sub_cd = CallEncoder::<2048>::new(selector("submitEpochDeal(uint64,uint64,bytes)"))
                .push_u64(1)
                .push_u64(idx as u64)
                .push_u64(96)
                .push_dynamic_bytes_tail(&deal);
            mock::transact_as(val_entries[idx].0, beacon, sub_cd.as_slice()).unwrap();
            deals.push(deal);
        }
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

        // 2. Initialize CipherVote hub (`minValidators = 4`).
        let init_cd = CallEncoder::<512>::new(selector(
            "initialize(address,address,address,uint64,string)",
        ))
        .push_address(&id_reg)
        .push_address(&share_led)
        .push_address(&beacon)
        .push_u64(4)
        .push_u64(160)
        .push_dynamic_bytes_tail(b"CipherVote Threshold Homomorphic Governance");
        mock::transact_as(admin_eoa, ballot_hub, init_cd.as_slice()).unwrap();

        // 3. Alice creates Poll #1 (`Share-Weighted SLX-EQ`, `duration = 4` blocks).
        let title = b"Board Resolution #1: Authorize Sub-GHz Clearinghouse Expansion";
        let desc = b"Share-weighted encrypted vote under Validator Epoch #1 ElGamal key.";
        let t_pad = (title.len() + 31) & !31;
        let create_inner = CallEncoder::<1024>::new(selector(
            "createPoll(string,string,uint64,address,uint64)",
        ))
        .push_u64(160)
        .push_u64((160 + 32 + t_pad) as u64)
        .push_u64(2) // Share-weighted!
        .push_address(&[0u8; 20])
        .push_u64(4)
        .push_dynamic_bytes_tail(title)
        .push_dynamic_bytes_tail(desc);
        let exec_create = CallEncoder::<1536>::new(selector("execute(address,bytes)"))
            .push_address(&ballot_hub)
            .push_u64(64)
            .push_dynamic_bytes_tail(create_inner.as_slice());
        let p1_ret = mock::transact_as(alice_eoa, alice_id, exec_create.as_slice()).unwrap();
        assert_eq!(p1_ret[31], 1);

        // Fetch `epoch_pk` from Poll #1 detail.
        let detail0 = mock::transact_as(
            admin_eoa,
            ballot_hub,
            CallEncoder::<64>::new(selector("getPollDetail(uint64)"))
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();
        let mut epoch_pk = [0u8; 32];
        epoch_pk.copy_from_slice(&detail0[82..114]);

        // 4. Rogue Ballot Attack #1: Bob attempts to vote `(1, 1, 0)` (both YES and NO = 1)!
        //    Each slot passes CDS 0/1 OR-proof, but `sum == 1` DLEQ proof MUST fail (`-26`)!
        {
            let mut bad_cts = [0u8; 192];
            let mut bad_ors = [0u8; 384];
            let mut r_sum = Scalar::ZERO;
            for s in 0..3usize {
                let bit = if s < 2 { 1u8 } else { 0u8 }; // (1, 1, 0) -> sum = 2!
                let r = Scalar::from(777u64 + (s as u64) * 19);
                r_sum += r;
                let or_ctx = build_ballot_or01_ctx(&ballot_hub, 1, &bob_id, s as u8);
                let (ct, prf) =
                    mock_crypto::prove_he_zero_or_one(&epoch_pk, bit, &r, &or_ctx, &[9u8; 32])
                        .unwrap();
                bad_cts[s * 64..(s + 1) * 64].copy_from_slice(&ct);
                bad_ors[s * 128..(s + 1) * 128].copy_from_slice(&prf);
            }
            let sum_ctx = build_ballot_sum1_ctx(&ballot_hub, 1, &bob_id);
            let fake_sum_prf =
                mock_crypto::prove_he_sum_equals_one(&epoch_pk, &r_sum, &sum_ctx, &[9u8; 32])
                    .unwrap();
            let bad_tx = encode_cast_ballot_tx(&ballot_hub, 1, &bad_cts, &bad_ors, &fake_sum_prf);
            assert_eq!(
                mock::transact_as(bob_eoa, bob_id, bad_tx.as_slice()),
                Err(-26),
                "Double-vote (1,1,0) MUST be rejected by the sum==1 DLEQ verifier!"
            );
        }

        // 5. Cast valid encrypted share-weighted ballots:
        //    - Alice (`100,000` shares) -> YES (`slot 0`)
        //    - Bob   (`42,500` shares)  -> NO  (`slot 1`)
        //    - Carol (`15,500` shares)  -> YES (`slot 0`)
        for (eoa, id, choice, seed) in [
            (alice_eoa, alice_id, 0usize, 11u8),
            (bob_eoa, bob_id, 1usize, 22u8),
            (carol_eoa, carol_id, 0usize, 33u8),
        ] {
            let (cts, ors, sum_prf) =
                build_encrypted_one_hot_ballot(&epoch_pk, &ballot_hub, 1, &id, choice, seed);
            let tx = encode_cast_ballot_tx(&ballot_hub, 1, &cts, &ors, &sum_prf);
            mock::transact_as(eoa, id, tx.as_slice()).unwrap();
        }

        // Double voting by Alice must revert (`-20`)!
        let (dup_cts, dup_ors, dup_sum) =
            build_encrypted_one_hot_ballot(&epoch_pk, &ballot_hub, 1, &alice_id, 1, 44);
        let dup_tx = encode_cast_ballot_tx(&ballot_hub, 1, &dup_cts, &dup_ors, &dup_sum);
        assert_eq!(
            mock::transact_as(alice_eoa, alice_id, dup_tx.as_slice()),
            Err(-20)
        );

        // 6. Advance 4 blocks -> `closeAndRequestTally(1)`!
        mock::set_block_number(204);
        let dec_req_vec = mock::transact_as(
            admin_eoa,
            ballot_hub,
            CallEncoder::<64>::new(selector("closeAndRequestTally(uint64)"))
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();
        let dec_req_id: [u8; 32] = dec_req_vec.try_into().unwrap();

        // Read `dec_ctx` and the 3 `C1_s` points from `getDecryptionProof(dec_req_id)` on `vrf-beacon`.
        let proof_bundle = mock::transact_as(
            admin_eoa,
            beacon,
            CallEncoder::<64>::new(selector("getDecryptionProof(bytes32)"))
                .push_bytes32(&dec_req_id)
                .as_slice(),
        )
        .unwrap();
        let mut dec_ctx = [0u8; 32];
        dec_ctx.copy_from_slice(&proof_bundle[62..94]);
        let slots_base = 138 + 5 * 84;
        let mut c1s = [[0u8; 32]; 3];
        for s in 0..3 {
            c1s[s].copy_from_slice(&proof_bundle[slots_base + s * 136..slots_base + s * 136 + 32]);
        }

        // 7. Validators `0..5` submit partial decryption shares (`4th` fulfills Poll #1 synchronously, `5th` is idempotent!).
        mock::set_block_number(205);
        for v in 0..5 {
            let mut shares_288 = [0u8; 288];
            for s in 0..3usize {
                let mut slot_ctx = [0u8; 36];
                slot_ctx[0..32].copy_from_slice(&dec_ctx);
                slot_ctx[32..36].copy_from_slice(&(s as u32).to_be_bytes());
                let (d_vs, prf_vs) = mock_crypto::compute_validator_decryption_share(
                    &epoch_secret_shares[v],
                    &c1s[s],
                    &slot_ctx,
                    &[v as u8 + (s as u8) * 17 + 60; 32],
                )
                .unwrap();
                shares_288[s * 96..s * 96 + 32].copy_from_slice(&d_vs);
                shares_288[s * 96 + 32..(s + 1) * 96].copy_from_slice(&prf_vs);
            }
            let sub_cd = CallEncoder::<512>::new(selector(
                "submitDecryptionShares(bytes32,uint64,bytes)",
            ))
            .push_bytes32(&dec_req_id)
            .push_u64(v as u64)
            .push_u64(96)
            .push_dynamic_bytes_tail(&shares_288);
            mock::transact_as(val_entries[v].0, beacon, sub_cd.as_slice()).unwrap();
        }

        // 8. Verify Poll #1 final tallies: `YES = 115,500`, `NO = 42,500`, `ABSTAIN = 0`!
        let detail_final = mock::transact_as(
            admin_eoa,
            ballot_hub,
            CallEncoder::<64>::new(selector("getPollDetail(uint64)"))
                .push_u64(1)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(detail_final[8], POLL_TALLY_VERIFIED);
        let yes_tally = u64::from_be_bytes(detail_final[126..134].try_into().unwrap());
        let no_tally = u64::from_be_bytes(detail_final[134..142].try_into().unwrap());
        let abstain_tally = u64::from_be_bytes(detail_final[142..150].try_into().unwrap());
        assert_eq!(yes_tally, 115_500);
        assert_eq!(no_tally, 42_500);
        assert_eq!(abstain_tally, 0);
    }
}
