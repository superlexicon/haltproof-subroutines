//! Subnet Validator-Quorum Threshold ECVRF & DKG Randomness Beacon (`vrf-beacon`).
//!
//! Dynamically tracks the active `Full` validator set from `GlobalAccountState` via
//! `hps_sdk::vrf::active_validators()`, enforces the BFT-safe threshold `t` (`N` for `N <= 4`,
//! `⌊2N/3⌋ + 1` for `N >= 5`), coordinates non-interactive Feldman + Ephemeral-ECDH DKG epochs
//! with objective Chaum-Pedersen DLEQ dispute protection, and fulfills 1-block threshold ECVRF
//! randomness requests with synchronous `onVrfFulfilled` delivery.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::vrf::{self, MAX_VRF_VALIDATORS};
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

/// Maximum validators per beacon epoch (`32` comfortably covers SuperLexicon Sub-GHz / TCP subnets).
const MAX_EPOCH_VALIDATORS: usize = 32;
/// Maximum serialized deal byte size for `MAX_EPOCH_VALIDATORS = 32` (`t = 22`): `32 + 54*32 + 128 = 1888`.
const MAX_DEAL_BYTES: usize = 2048;
/// Grace window (in blocks) before finalizing an epoch with `threshold <= deal_count < val_count`
/// when all `val_count` deals have not yet arrived.
const DKG_GRACE_BLOCKS: u64 = 3;

const EPOCH_OPENING: u8 = 1;
const EPOCH_ACTIVE: u8 = 2;
const EPOCH_SUPERSEDED: u8 = 3;

const REQ_PENDING: u8 = 1;
const REQ_FULFILLED: u8 = 2;

pub const EV_VM_VRF_EPOCH_OPEN: [u8; 32] =
    event_topic("VmVrfEpochOpened(uint64,bytes32,uint64,uint64)");
pub const EV_VM_VRF_EPOCH_ACTIVE: [u8; 32] =
    event_topic("VmVrfEpochActivated(uint64,bytes32,bytes32,uint64)");
pub const EV_VM_VRF_DEAL_SUBMITTED: [u8; 32] =
    event_topic("VmVrfDealSubmitted(uint64,uint64,uint64)");
pub const EV_VM_VRF_DEAL_DISPUTED: [u8; 32] =
    event_topic("VmVrfDealDisputed(uint64,uint64,uint64)");
pub const EV_VM_VRF_REQUESTED: [u8; 32] =
    event_topic("VmVrfRequested(bytes32,address,uint64,bytes32)");
pub const EV_VM_VRF_SHARE_SUBMITTED: [u8; 32] =
    event_topic("VmVrfShareSubmitted(bytes32,uint64,uint64)");
pub const EV_VM_VRF_FULFILLED: [u8; 32] =
    event_topic("VmVrfFulfilled(bytes32,address,bytes32,bytes32)");

const KEY_CUR_EPOCH: &[u8] = b"vb:cur_ep";
const KEY_ACT_EPOCH: &[u8] = b"vb:act_ep";
const KEY_REQ_COUNT: &[u8] = b"vb:req_cnt";
const KEY_FULFILLED_COUNT: &[u8] = b"vb:ful_cnt";
const KEY_LAST_REQ_ID: &[u8] = b"vb:last_req";

hps_entry! {
    "syncEpoch()"                                                          => handle_sync_epoch,
    "submitEpochDeal(uint64,uint64,bytes)"                                 => handle_submit_epoch_deal,
    "disputeEpochDeal(uint64,uint64,uint64,bytes32,bytes)"                 => handle_dispute_epoch_deal,
    "requestRandomness(bytes32,uint64)"                                    => handle_request_randomness,
    "submitVrfShare(bytes32,uint64,bytes32,bytes)"                         => handle_submit_vrf_share,
    "getBeaconState()"                                                     => handle_get_beacon_state,
    "getValidatorDuty(bytes32)"                                            => handle_get_validator_duty,
    "getEpochDkgBundle(uint64)"                                            => handle_get_epoch_dkg_bundle,
    "getRequestProof(bytes32)"                                             => handle_get_request_proof,
    "getFulfilledOutput(bytes32)"                                          => handle_get_fulfilled_output,
}

#[derive(Clone, Copy)]
struct EpochMeta {
    epoch_id: u64,
    status: u8,
    val_count: u32,
    threshold: u32,
    opened_block: u64,
    deal_bitmap: u64,
    set_hash: [u8; 32],
    epoch_pk: [u8; 32],
}

impl EpochMeta {
    const BYTE_LEN: usize = 97;

    fn encode(&self) -> [u8; Self::BYTE_LEN] {
        let mut b = [0u8; Self::BYTE_LEN];
        b[0..8].copy_from_slice(&self.epoch_id.to_be_bytes());
        b[8] = self.status;
        b[9..13].copy_from_slice(&self.val_count.to_be_bytes());
        b[13..17].copy_from_slice(&self.threshold.to_be_bytes());
        b[17..25].copy_from_slice(&self.opened_block.to_be_bytes());
        b[25..33].copy_from_slice(&self.deal_bitmap.to_be_bytes());
        b[33..65].copy_from_slice(&self.set_hash);
        b[65..97].copy_from_slice(&self.epoch_pk);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BYTE_LEN {
            return None;
        }
        let mut set_hash = [0u8; 32];
        let mut epoch_pk = [0u8; 32];
        set_hash.copy_from_slice(&b[33..65]);
        epoch_pk.copy_from_slice(&b[65..97]);
        Some(Self {
            epoch_id: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            status: b[8],
            val_count: u32::from_be_bytes([b[9], b[10], b[11], b[12]]),
            threshold: u32::from_be_bytes([b[13], b[14], b[15], b[16]]),
            opened_block: u64::from_be_bytes([
                b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24],
            ]),
            deal_bitmap: u64::from_be_bytes([
                b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32],
            ]),
            set_hash,
            epoch_pk,
        })
    }
}

#[derive(Clone, Copy)]
struct RequestMeta {
    status: u8,
    epoch_id: u64,
    requested_block: u64,
    fulfilled_block: u64,
    requester: [u8; 20],
    user_seed: [u8; 32],
    alpha: [u8; 32],
    signer_bitmap: u64,
    share_count: u32,
    gamma: [u8; 32],
    random_out: [u8; 32],
}

impl RequestMeta {
    const BYTE_LEN: usize = 185;

    fn encode(&self) -> [u8; Self::BYTE_LEN] {
        let mut b = [0u8; Self::BYTE_LEN];
        b[0] = self.status;
        b[1..9].copy_from_slice(&self.epoch_id.to_be_bytes());
        b[9..17].copy_from_slice(&self.requested_block.to_be_bytes());
        b[17..25].copy_from_slice(&self.fulfilled_block.to_be_bytes());
        b[25..45].copy_from_slice(&self.requester);
        b[45..77].copy_from_slice(&self.user_seed);
        b[77..109].copy_from_slice(&self.alpha);
        b[109..117].copy_from_slice(&self.signer_bitmap.to_be_bytes());
        b[117..121].copy_from_slice(&self.share_count.to_be_bytes());
        b[121..153].copy_from_slice(&self.gamma);
        b[153..185].copy_from_slice(&self.random_out);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BYTE_LEN {
            return None;
        }
        let mut requester = [0u8; 20];
        let mut user_seed = [0u8; 32];
        let mut alpha = [0u8; 32];
        let mut gamma = [0u8; 32];
        let mut random_out = [0u8; 32];
        requester.copy_from_slice(&b[25..45]);
        user_seed.copy_from_slice(&b[45..77]);
        alpha.copy_from_slice(&b[77..109]);
        gamma.copy_from_slice(&b[121..153]);
        random_out.copy_from_slice(&b[153..185]);
        Some(Self {
            status: b[0],
            epoch_id: u64::from_be_bytes([b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8]]),
            requested_block: u64::from_be_bytes([
                b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16],
            ]),
            fulfilled_block: u64::from_be_bytes([
                b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24],
            ]),
            requester,
            user_seed,
            alpha,
            signer_bitmap: u64::from_be_bytes([
                b[109], b[110], b[111], b[112], b[113], b[114], b[115], b[116],
            ]),
            share_count: u32::from_be_bytes([b[117], b[118], b[119], b[120]]),
            gamma,
            random_out,
        })
    }
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn key_epoch(epoch_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"vb:ep:").push_u64_be(epoch_id)
}

fn key_epoch_pks(epoch_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"vb:pks:").push_u64_be(epoch_id)
}

fn key_epoch_addrs(epoch_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"vb:adr:").push_u64_be(epoch_id)
}

fn key_epoch_share_pks(epoch_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"vb:spk:").push_u64_be(epoch_id)
}

fn key_deal(epoch_id: u64, dealer_idx: u32) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"vb:dl:")
        .push_u64_be(epoch_id)
        .push(&dealer_idx.to_be_bytes())
}

fn key_req(req_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"vb:rq:").push(req_id)
}

fn key_req_share(req_id: &[u8; 32], val_idx: u32) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"vb:rs:")
        .push(req_id)
        .push(&val_idx.to_be_bytes())
}

fn load_epoch(epoch_id: u64) -> Option<EpochMeta> {
    if epoch_id == 0 {
        return None;
    }
    let mut buf = [0u8; EpochMeta::BYTE_LEN];
    let n = storage::get_into(key_epoch(epoch_id).as_slice(), &mut buf)?;
    if n < EpochMeta::BYTE_LEN {
        return None;
    }
    EpochMeta::decode(&buf)
}

fn save_epoch(meta: &EpochMeta) {
    storage::set(key_epoch(meta.epoch_id).as_slice(), &meta.encode());
}

fn load_epoch_pks(epoch_id: u64, val_count: usize, out: &mut [[u8; 32]; MAX_EPOCH_VALIDATORS]) -> bool {
    if val_count == 0 || val_count > MAX_EPOCH_VALIDATORS {
        return false;
    }
    let mut raw = [0u8; MAX_EPOCH_VALIDATORS * 32];
    let need = val_count * 32;
    let Some(n) = storage::get_into(key_epoch_pks(epoch_id).as_slice(), &mut raw[..need]) else {
        return false;
    };
    if n < need {
        return false;
    }
    let mut i = 0;
    while i < val_count {
        out[i].copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        i += 1;
    }
    true
}

fn load_epoch_share_pks(
    epoch_id: u64,
    val_count: usize,
    out: &mut [[u8; 32]; MAX_EPOCH_VALIDATORS],
) -> bool {
    if val_count == 0 || val_count > MAX_EPOCH_VALIDATORS {
        return false;
    }
    let mut raw = [0u8; MAX_EPOCH_VALIDATORS * 32];
    let need = val_count * 32;
    let Some(n) = storage::get_into(key_epoch_share_pks(epoch_id).as_slice(), &mut raw[..need])
    else {
        return false;
    };
    if n < need {
        return false;
    }
    let mut i = 0;
    while i < val_count {
        out[i].copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        i += 1;
    }
    true
}

fn load_req(req_id: &[u8; 32]) -> Option<RequestMeta> {
    let mut buf = [0u8; RequestMeta::BYTE_LEN];
    let n = storage::get_into(key_req(req_id).as_slice(), &mut buf)?;
    if n < RequestMeta::BYTE_LEN {
        return None;
    }
    RequestMeta::decode(&buf)
}

fn save_req(req_id: &[u8; 32], meta: &RequestMeta) {
    storage::set(key_req(req_id).as_slice(), &meta.encode());
}

fn try_finalize_epoch(meta: &mut EpochMeta, now_block: u64) -> bool {
    if meta.status != EPOCH_OPENING {
        return meta.status == EPOCH_ACTIVE;
    }
    let val_count = meta.val_count as usize;
    let threshold = meta.threshold as usize;
    let deal_count = meta.deal_bitmap.count_ones() as usize;
    let ready = deal_count >= val_count
        || (deal_count >= threshold && now_block >= meta.opened_block.saturating_add(DKG_GRACE_BLOCKS));
    if !ready {
        return false;
    }

    let deal_len = vrf::dkg_deal_byte_len(threshold, val_count);
    if deal_len > MAX_DEAL_BYTES || val_count > MAX_EPOCH_VALIDATORS {
        return false;
    }

    let mut packed = [0u8; MAX_EPOCH_VALIDATORS * MAX_DEAL_BYTES];
    let mut packed_count = 0usize;
    let mut idx = 0usize;
    while idx < val_count {
        if (meta.deal_bitmap & (1u64 << idx)) != 0 {
            let dst = &mut packed[packed_count * deal_len..(packed_count + 1) * deal_len];
            let Some(read_n) = storage::get_into(key_deal(meta.epoch_id, idx as u32).as_slice(), dst)
            else {
                return false;
            };
            if read_n != deal_len {
                return false;
            }
            packed_count += 1;
        }
        idx += 1;
    }
    if packed_count < threshold {
        return false;
    }

    let mut share_pks = [[0u8; 32]; MAX_VRF_VALIDATORS];
    let Some(epoch_pk) = vrf::derive_epoch_keys(
        threshold,
        val_count,
        &packed[..packed_count * deal_len],
        packed_count,
        deal_len,
        &mut share_pks,
    ) else {
        return false;
    };

    let mut spk_blob = [0u8; MAX_EPOCH_VALIDATORS * 32];
    let mut j = 0usize;
    while j < val_count {
        spk_blob[j * 32..(j + 1) * 32].copy_from_slice(&share_pks[j]);
        j += 1;
    }
    storage::set(
        key_epoch_share_pks(meta.epoch_id).as_slice(),
        &spk_blob[..val_count * 32],
    );

    meta.status = EPOCH_ACTIVE;
    meta.epoch_pk = epoch_pk;
    save_epoch(meta);
    storage::set_u64(KEY_ACT_EPOCH, meta.epoch_id);

    let mut ev = [0u8; 80];
    ev[0..8].copy_from_slice(&meta.epoch_id.to_be_bytes());
    ev[8..40].copy_from_slice(&meta.set_hash);
    ev[40..72].copy_from_slice(&meta.epoch_pk);
    ev[72..80].copy_from_slice(&meta.deal_bitmap.to_be_bytes());
    events::emit(&[EV_VM_VRF_EPOCH_ACTIVE], &ev);
    true
}

/// Synchronizes the beacon with the live consensus `Full` validator set, opening a new DKG epoch
/// automatically whenever validators join/leave (`set_hash` changes) or finalizing an `OPENING` epoch
/// once its grace window + threshold are met.
fn sync_epoch_internal() -> Result<EpochMeta, i32> {
    let live = vrf::active_validators().ok_or(-10)?;
    if live.count == 0 || live.count > MAX_EPOCH_VALIDATORS {
        return Err(-11);
    }
    let now_block = context::block_number();
    let cur_id = storage::get_u64(KEY_CUR_EPOCH);

    if let Some(mut cur) = load_epoch(cur_id) {
        if cur.set_hash == live.set_hash {
            if cur.status == EPOCH_OPENING {
                let _ = try_finalize_epoch(&mut cur, now_block);
            }
            return Ok(cur);
        }
        if cur.status == EPOCH_OPENING {
            cur.status = EPOCH_SUPERSEDED;
            save_epoch(&cur);
        }
    }

    let next_id = cur_id.saturating_add(1);
    let mut pks_blob = [0u8; MAX_EPOCH_VALIDATORS * 32];
    let mut addrs_blob = [0u8; MAX_EPOCH_VALIDATORS * 20];
    let mut i = 0usize;
    while i < live.count {
        pks_blob[i * 32..(i + 1) * 32].copy_from_slice(&live.validators[i].pubkey);
        addrs_blob[i * 20..(i + 1) * 20].copy_from_slice(&live.validators[i].address);
        i += 1;
    }
    storage::set(key_epoch_pks(next_id).as_slice(), &pks_blob[..live.count * 32]);
    storage::set(
        key_epoch_addrs(next_id).as_slice(),
        &addrs_blob[..live.count * 20],
    );

    let meta = EpochMeta {
        epoch_id: next_id,
        status: EPOCH_OPENING,
        val_count: live.count as u32,
        threshold: live.threshold as u32,
        opened_block: now_block,
        deal_bitmap: 0,
        set_hash: live.set_hash,
        epoch_pk: [0u8; 32],
    };
    save_epoch(&meta);
    storage::set_u64(KEY_CUR_EPOCH, next_id);

    let mut ev = [0u8; 56];
    ev[0..8].copy_from_slice(&next_id.to_be_bytes());
    ev[8..40].copy_from_slice(&live.set_hash);
    ev[40..48].copy_from_slice(&(live.threshold as u64).to_be_bytes());
    ev[48..56].copy_from_slice(&(live.count as u64).to_be_bytes());
    events::emit(&[EV_VM_VRF_EPOCH_OPEN], &ev);

    Ok(meta)
}

fn handle_sync_epoch(_args: &CalldataReader) -> Result<(), i32> {
    let meta = sync_epoch_internal()?;
    ret::write_u64_word(meta.epoch_id);
    Ok(())
}

fn handle_submit_epoch_deal(args: &CalldataReader) -> Result<(), i32> {
    let epoch_id = args.u64(0).ok_or(-3)?;
    let dealer_idx_u64 = args.u64(1).ok_or(-3)?;
    let deal = args.dynamic_bytes(2).ok_or(-3)?;

    let Some(mut meta) = load_epoch(epoch_id) else {
        return Err(-12);
    };
    if dealer_idx_u64 >= (meta.val_count as u64) {
        return Err(-13);
    }
    // Idempotent return if epoch already finalized or superseded, or dealer already submitted!
    if meta.status != EPOCH_OPENING {
        ret::write_u64_word(meta.status as u64);
        return Ok(());
    }
    let dealer_idx = dealer_idx_u64 as usize;
    let bit = 1u64 << dealer_idx;
    if (meta.deal_bitmap & bit) != 0 {
        ret::write_u64_word(meta.status as u64);
        return Ok(());
    }

    let val_count = meta.val_count as usize;
    let threshold = meta.threshold as usize;
    if deal.len() != vrf::dkg_deal_byte_len(threshold, val_count) || deal.len() > MAX_DEAL_BYTES {
        return Err(-14);
    }

    let mut pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    if !load_epoch_pks(epoch_id, val_count, &mut pks) {
        return Err(-15);
    }
    if !vrf::verify_dkg_deal(&meta.set_hash, dealer_idx, threshold, &pks[..val_count], deal) {
        return Err(-16);
    }

    storage::set(key_deal(epoch_id, dealer_idx as u32).as_slice(), deal);
    meta.deal_bitmap |= bit;
    save_epoch(&meta);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&epoch_id.to_be_bytes());
    ev[8..16].copy_from_slice(&dealer_idx_u64.to_be_bytes());
    ev[16..24].copy_from_slice(&(meta.deal_bitmap.count_ones() as u64).to_be_bytes());
    events::emit(&[EV_VM_VRF_DEAL_SUBMITTED], &ev);

    let now_block = context::block_number();
    let _ = try_finalize_epoch(&mut meta, now_block);
    ret::write_u64_word(meta.status as u64);
    Ok(())
}

fn handle_dispute_epoch_deal(args: &CalldataReader) -> Result<(), i32> {
    let epoch_id = args.u64(0).ok_or(-3)?;
    let dealer_idx_u64 = args.u64(1).ok_or(-3)?;
    let accuser_idx_u64 = args.u64(2).ok_or(-3)?;
    let shared_pt = args.bytes32(3).ok_or(-3)?;
    let proof = args.dynamic_bytes(4).ok_or(-3)?;
    if proof.len() != 64 {
        return Err(-3);
    }
    let mut proof_64 = [0u8; 64];
    proof_64.copy_from_slice(proof);

    let mut meta = load_epoch(epoch_id).ok_or(-12)?;
    if meta.status != EPOCH_OPENING {
        return Err(-17);
    }
    let val_count = meta.val_count as usize;
    let threshold = meta.threshold as usize;
    if dealer_idx_u64 >= (val_count as u64) || accuser_idx_u64 >= (val_count as u64) {
        return Err(-13);
    }
    let dealer_idx = dealer_idx_u64 as usize;
    let accuser_idx = accuser_idx_u64 as usize;
    let bit = 1u64 << dealer_idx;
    if (meta.deal_bitmap & bit) == 0 {
        return Err(-18);
    }

    let deal_len = vrf::dkg_deal_byte_len(threshold, val_count);
    let mut deal_buf = [0u8; MAX_DEAL_BYTES];
    let Some(read_n) = storage::get_into(
        key_deal(epoch_id, dealer_idx as u32).as_slice(),
        &mut deal_buf[..deal_len],
    ) else {
        return Err(-18);
    };
    if read_n != deal_len {
        return Err(-18);
    }

    let mut pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    if !load_epoch_pks(epoch_id, val_count, &mut pks) {
        return Err(-15);
    }
    if !vrf::verify_dkg_dispute(
        &meta.set_hash,
        dealer_idx,
        accuser_idx,
        threshold,
        &pks[..val_count],
        &deal_buf[..deal_len],
        &shared_pt,
        &proof_64,
    ) {
        return Err(-19);
    }

    // Expunge the objectively proven fraudulent deal!
    storage::set(key_deal(epoch_id, dealer_idx as u32).as_slice(), &[]);
    meta.deal_bitmap &= !bit;
    save_epoch(&meta);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&epoch_id.to_be_bytes());
    ev[8..16].copy_from_slice(&dealer_idx_u64.to_be_bytes());
    ev[16..24].copy_from_slice(&accuser_idx_u64.to_be_bytes());
    events::emit(&[EV_VM_VRF_DEAL_DISPUTED], &ev);

    ret::write_bool(true);
    Ok(())
}

fn handle_request_randomness(args: &CalldataReader) -> Result<(), i32> {
    let user_seed = args.bytes32(0).ok_or(-3)?;
    let min_validators = args.u64(1).ok_or(-3)?;

    let live = vrf::active_validators().ok_or(-10)?;
    if (live.count as u64) < min_validators {
        return Err(-20); // Validator quorum smaller than caller's safety minimum!
    }

    let cur_meta = sync_epoch_internal()?;
    if cur_meta.status != EPOCH_ACTIVE || cur_meta.set_hash != live.set_hash {
        return Err(-21); // Epoch DKG for current validator set still opening!
    }

    let requester = context::msg_sender();
    let now_block = context::block_number();
    let req_seq = storage::get_u64(KEY_REQ_COUNT).saturating_add(1);
    storage::set_u64(KEY_REQ_COUNT, req_seq);

    let mut id_pre = [0u8; 18 + 8 + 20 + 8 + 32 + 8];
    id_pre[0..18].copy_from_slice(b"SLX_BEACON_REQ_V1:");
    id_pre[18..26].copy_from_slice(&cur_meta.epoch_id.to_be_bytes());
    id_pre[26..46].copy_from_slice(&requester);
    id_pre[46..54].copy_from_slice(&now_block.to_be_bytes());
    id_pre[54..86].copy_from_slice(&user_seed);
    id_pre[86..94].copy_from_slice(&req_seq.to_be_bytes());
    let req_id = keccak256(&id_pre);

    let mut alpha_pre = [0u8; 20 + 32 + 32 + 32];
    alpha_pre[0..20].copy_from_slice(b"SLX_BEACON_ALPHA_V1:");
    alpha_pre[20..52].copy_from_slice(&req_id);
    alpha_pre[52..84].copy_from_slice(&cur_meta.set_hash);
    alpha_pre[84..116].copy_from_slice(&user_seed);
    let alpha = keccak256(&alpha_pre);

    let rmeta = RequestMeta {
        status: REQ_PENDING,
        epoch_id: cur_meta.epoch_id,
        requested_block: now_block,
        fulfilled_block: 0,
        requester,
        user_seed,
        alpha,
        signer_bitmap: 0,
        share_count: 0,
        gamma: [0u8; 32],
        random_out: [0u8; 32],
    };
    save_req(&req_id, &rmeta);
    storage::set(KEY_LAST_REQ_ID, &req_id);

    let mut ev = [0u8; 40];
    ev[0..8].copy_from_slice(&cur_meta.epoch_id.to_be_bytes());
    ev[8..40].copy_from_slice(&alpha);
    events::emit(&[EV_VM_VRF_REQUESTED, req_id, addr_topic(&requester)], &ev);

    ret::write_word(&req_id);
    Ok(())
}

fn handle_submit_vrf_share(args: &CalldataReader) -> Result<(), i32> {
    let req_id = args.bytes32(0).ok_or(-3)?;
    let val_idx_u64 = args.u64(1).ok_or(-3)?;
    let gamma_i = args.bytes32(2).ok_or(-3)?;
    let proof_slice = args.dynamic_bytes(3).ok_or(-3)?;
    if proof_slice.len() != 64 {
        return Err(-3);
    }
    let mut proof_64 = [0u8; 64];
    proof_64.copy_from_slice(proof_slice);

    let mut rmeta = load_req(&req_id).ok_or(-22)?;
    // Idempotent success for trailing shares arriving in the same block after threshold was met!
    if rmeta.status == REQ_FULFILLED {
        ret::write_u64_word(2);
        return Ok(());
    }

    let emeta = load_epoch(rmeta.epoch_id).ok_or(-12)?;
    if emeta.status != EPOCH_ACTIVE && emeta.epoch_pk == [0u8; 32] {
        return Err(-23);
    }
    let val_count = emeta.val_count as usize;
    let threshold = emeta.threshold as usize;
    if val_idx_u64 >= (val_count as u64) {
        return Err(-13);
    }
    let val_idx = val_idx_u64 as usize;
    let bit = 1u64 << val_idx;
    if (rmeta.signer_bitmap & bit) != 0 {
        ret::write_u64_word(rmeta.status as u64);
        return Ok(());
    }

    let mut share_pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    if !load_epoch_share_pks(rmeta.epoch_id, val_count, &mut share_pks) {
        return Err(-24);
    }
    if !vrf::verify_vrf_share(&share_pks[val_idx], &rmeta.alpha, &gamma_i, &proof_64) {
        return Err(-25); // Forged or corrupted VRF share rejected by Chaum-Pedersen DLEQ!
    }

    let mut share_rec = [0u8; 96];
    share_rec[0..32].copy_from_slice(&gamma_i);
    share_rec[32..96].copy_from_slice(&proof_64);
    storage::set(key_req_share(&req_id, val_idx as u32).as_slice(), &share_rec);

    rmeta.signer_bitmap |= bit;
    rmeta.share_count += 1;

    let mut sev = [0u8; 16];
    sev[0..8].copy_from_slice(&val_idx_u64.to_be_bytes());
    sev[8..16].copy_from_slice(&(rmeta.share_count as u64).to_be_bytes());
    events::emit(&[EV_VM_VRF_SHARE_SUBMITTED, req_id], &sev);

    if (rmeta.share_count as usize) < threshold {
        save_req(&req_id, &rmeta);
        ret::write_u64_word(1);
        return Ok(());
    }

    // Threshold reached (`t` verified validator shares)! Lagrange-combine over prime-order `ℤ_ℓ`.
    let mut packed_36 = [0u8; MAX_EPOCH_VALIDATORS * 36];
    let mut count = 0usize;
    let mut idx = 0usize;
    while idx < val_count && count < threshold {
        if (rmeta.signer_bitmap & (1u64 << idx)) != 0 {
            let mut rec = [0u8; 96];
            let Some(rn) = storage::get_into(key_req_share(&req_id, idx as u32).as_slice(), &mut rec)
            else {
                return Err(-26);
            };
            if rn < 96 {
                return Err(-26);
            }
            let off = count * 36;
            packed_36[off..off + 4].copy_from_slice(&(idx as u32).to_be_bytes());
            packed_36[off + 4..off + 36].copy_from_slice(&rec[0..32]);
            count += 1;
        }
        idx += 1;
    }

    let (gamma_32, random_32) = vrf::lagrange_combine(
        &emeta.epoch_pk,
        &rmeta.alpha,
        &packed_36[..count * 36],
        count,
    )
    .ok_or(-27)?;

    rmeta.status = REQ_FULFILLED;
    rmeta.fulfilled_block = context::block_number();
    rmeta.gamma = gamma_32;
    rmeta.random_out = random_32;
    save_req(&req_id, &rmeta);
    let ful_cnt = storage::get_u64(KEY_FULFILLED_COUNT).saturating_add(1);
    storage::set_u64(KEY_FULFILLED_COUNT, ful_cnt);

    let mut fev = [0u8; 80];
    fev[0..32].copy_from_slice(&gamma_32);
    fev[32..64].copy_from_slice(&random_32);
    fev[64..72].copy_from_slice(&rmeta.epoch_id.to_be_bytes());
    fev[72..80].copy_from_slice(&rmeta.signer_bitmap.to_be_bytes());
    events::emit(
        &[EV_VM_VRF_FULFILLED, req_id, addr_topic(&rmeta.requester)],
        &fev,
    );

    // Best-effort synchronous callback to requester if requester is a deployed HPS contract!
    if context::code_hash_of(&rmeta.requester).is_some() {
        let cb = CallEncoder::<196>::new(const {
            selector("onVrfFulfilled(bytes32,bytes32,bytes32,uint64,uint64)")
        })
        .push_bytes32(&req_id)
        .push_bytes32(&random_32)
        .push_bytes32(&gamma_32)
        .push_u64(rmeta.epoch_id)
        .push_u64(rmeta.signer_bitmap);
        let _ = call::call_raw(&rmeta.requester, cb.as_slice());
    }

    ret::write_u64_word(2);
    Ok(())
}

/// Binary view of current beacon state + active validator set:
/// `[cur_epoch:8][act_epoch:8][req_cnt:8][ful_cnt:8][live_val_cnt:4][live_thresh:4][live_set_hash:32]`
/// `[ep_status:1][ep_val_cnt:4][ep_thresh:4][ep_opened_blk:8][ep_deal_bitmap:8][ep_set_hash:32][ep_pk:32]`
/// `[last_req_id:32][live_val_cnt * (addr_20 || pk_32)]`
fn handle_get_beacon_state(_args: &CalldataReader) -> Result<(), i32> {
    let live = vrf::active_validators().ok_or(-10)?;
    let cur_ep = storage::get_u64(KEY_CUR_EPOCH);
    let act_ep = storage::get_u64(KEY_ACT_EPOCH);
    let req_cnt = storage::get_u64(KEY_REQ_COUNT);
    let ful_cnt = storage::get_u64(KEY_FULFILLED_COUNT);
    let last_req = storage::get_bytes32(KEY_LAST_REQ_ID).unwrap_or([0u8; 32]);

    let emeta = load_epoch(cur_ep).unwrap_or(EpochMeta {
        epoch_id: 0,
        status: 0,
        val_count: 0,
        threshold: 0,
        opened_block: 0,
        deal_bitmap: 0,
        set_hash: [0u8; 32],
        epoch_pk: [0u8; 32],
    });

    let n = live.count.min(MAX_EPOCH_VALIDATORS);
    let mut out = [0u8; 193 + MAX_EPOCH_VALIDATORS * 52];
    out[0..8].copy_from_slice(&cur_ep.to_be_bytes());
    out[8..16].copy_from_slice(&act_ep.to_be_bytes());
    out[16..24].copy_from_slice(&req_cnt.to_be_bytes());
    out[24..32].copy_from_slice(&ful_cnt.to_be_bytes());
    out[32..36].copy_from_slice(&(n as u32).to_be_bytes());
    out[36..40].copy_from_slice(&(live.threshold as u32).to_be_bytes());
    out[40..72].copy_from_slice(&live.set_hash);
    out[72] = emeta.status;
    out[73..77].copy_from_slice(&emeta.val_count.to_be_bytes());
    out[77..81].copy_from_slice(&emeta.threshold.to_be_bytes());
    out[81..89].copy_from_slice(&emeta.opened_block.to_be_bytes());
    out[89..97].copy_from_slice(&emeta.deal_bitmap.to_be_bytes());
    out[97..129].copy_from_slice(&emeta.set_hash);
    out[129..161].copy_from_slice(&emeta.epoch_pk);
    out[161..193].copy_from_slice(&last_req);

    let mut i = 0usize;
    while i < n {
        let base = 193 + i * 52;
        out[base..base + 20].copy_from_slice(&live.validators[i].address);
        out[base + 20..base + 52].copy_from_slice(&live.validators[i].pubkey);
        i += 1;
    }
    ret::write(&out[..193 + n * 52]);
    Ok(())
}

/// Lightweight duty check for validator `my_pubkey` (`bytes32`):
/// `[action:1][epoch_id:8][my_idx:4][threshold:4][val_count:4][set_hash:32][val_count * 32B pks]`
/// where `action`:
/// - `0` = no epoch action needed
/// - `1` = call `syncEpoch()` (live validator `set_hash` differs from `cur_epoch` OR grace window ready!)
/// - `2` = submit DKG deal for `(epoch_id, my_idx)`!
fn handle_get_validator_duty(args: &CalldataReader) -> Result<(), i32> {
    let my_pk = args.bytes32(0).ok_or(-3)?;
    let live = vrf::active_validators().ok_or(-10)?;
    let now_block = context::block_number();
    let cur_ep = storage::get_u64(KEY_CUR_EPOCH);

    let mut out = [0u8; 53 + MAX_EPOCH_VALIDATORS * 32];
    let Some(emeta) = load_epoch(cur_ep) else {
        out[0] = 1; // Needs initial `syncEpoch()`!
        ret::write(&out[..53]);
        return Ok(());
    };

    if emeta.set_hash != live.set_hash {
        out[0] = 1; // Validator set rotated -> trigger `syncEpoch()`!
        ret::write(&out[..53]);
        return Ok(());
    }

    if emeta.status == EPOCH_OPENING {
        let val_count = emeta.val_count as usize;
        let mut pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
        if !load_epoch_pks(cur_ep, val_count, &mut pks) {
            return Err(-15);
        }
        let mut my_idx: Option<usize> = None;
        let mut i = 0usize;
        while i < val_count {
            if pks[i] == my_pk {
                my_idx = Some(i);
                break;
            }
            i += 1;
        }
        if let Some(idx) = my_idx {
            if (emeta.deal_bitmap & (1u64 << idx)) == 0 {
                out[0] = 2;
                out[1..9].copy_from_slice(&cur_ep.to_be_bytes());
                out[9..13].copy_from_slice(&(idx as u32).to_be_bytes());
                out[13..17].copy_from_slice(&emeta.threshold.to_be_bytes());
                out[17..21].copy_from_slice(&emeta.val_count.to_be_bytes());
                out[21..53].copy_from_slice(&emeta.set_hash);
                let mut j = 0usize;
                while j < val_count {
                    out[53 + j * 32..53 + (j + 1) * 32].copy_from_slice(&pks[j]);
                    j += 1;
                }
                ret::write(&out[..53 + val_count * 32]);
                return Ok(());
            }
        }
        if (emeta.deal_bitmap.count_ones() as u32) >= emeta.threshold
            && now_block >= emeta.opened_block.saturating_add(DKG_GRACE_BLOCKS)
        {
            out[0] = 1; // Ready to finalize via `syncEpoch()` after grace window!
            out[1..9].copy_from_slice(&cur_ep.to_be_bytes());
            ret::write(&out[..53]);
            return Ok(());
        }
    }

    out[0] = 0;
    out[1..9].copy_from_slice(&cur_ep.to_be_bytes());
    ret::write(&out[..53]);
    Ok(())
}

/// Returns the complete DKG bundle for `epoch_id` so validators can reconstruct their scalar share
/// `s_{epoch, j}` on demand (including across restarts):
/// `[status:1][val_count:4][threshold:4][deal_bitmap:8][deal_len:4][set_hash:32][epoch_pk:32]`
/// `[val_count * 32B pks][for each set bit in deal_bitmap: dealer_idx_u32_be || deal_bytes]`
fn handle_get_epoch_dkg_bundle(args: &CalldataReader) -> Result<(), i32> {
    let epoch_id = args.u64(0).ok_or(-3)?;
    let emeta = load_epoch(epoch_id).ok_or(-12)?;
    let val_count = emeta.val_count as usize;
    let threshold = emeta.threshold as usize;
    let deal_len = vrf::dkg_deal_byte_len(threshold, val_count);

    let mut pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    if !load_epoch_pks(epoch_id, val_count, &mut pks) {
        return Err(-15);
    }

    let mut out = [0u8; 85 + MAX_EPOCH_VALIDATORS * 32 + MAX_EPOCH_VALIDATORS * (4 + MAX_DEAL_BYTES)];
    out[0] = emeta.status;
    out[1..5].copy_from_slice(&emeta.val_count.to_be_bytes());
    out[5..9].copy_from_slice(&emeta.threshold.to_be_bytes());
    out[9..17].copy_from_slice(&emeta.deal_bitmap.to_be_bytes());
    out[17..21].copy_from_slice(&(deal_len as u32).to_be_bytes());
    out[21..53].copy_from_slice(&emeta.set_hash);
    out[53..85].copy_from_slice(&emeta.epoch_pk);

    let mut cursor = 85usize;
    let mut i = 0usize;
    while i < val_count {
        out[cursor..cursor + 32].copy_from_slice(&pks[i]);
        cursor += 32;
        i += 1;
    }

    let mut d_idx = 0usize;
    while d_idx < val_count {
        if (emeta.deal_bitmap & (1u64 << d_idx)) != 0 {
            out[cursor..cursor + 4].copy_from_slice(&(d_idx as u32).to_be_bytes());
            cursor += 4;
            let Some(rn) = storage::get_into(
                key_deal(epoch_id, d_idx as u32).as_slice(),
                &mut out[cursor..cursor + deal_len],
            ) else {
                return Err(-18);
            };
            if rn != deal_len {
                return Err(-18);
            }
            cursor += deal_len;
        }
        d_idx += 1;
    }

    ret::write(&out[..cursor]);
    Ok(())
}

/// Full cryptographic audit bundle for browser/client-side verification of `req_id`:
/// `[status:1][epoch_id:8][val_count:4][threshold:4][req_blk:8][ful_blk:8][requester:20]`
/// `[user_seed:32][alpha:32][epoch_pk:32][gamma:32][random_out:32][signer_bitmap:8][share_count:4]`
/// `[val_count * (addr_20 || val_pk_32 || share_pk_32)]`
/// `[share_count * (val_idx_4 || gamma_i_32 || proof_64)]`
fn handle_get_request_proof(args: &CalldataReader) -> Result<(), i32> {
    let req_id = args.bytes32(0).ok_or(-3)?;
    let rmeta = load_req(&req_id).ok_or(-22)?;
    let emeta = load_epoch(rmeta.epoch_id).ok_or(-12)?;
    let val_count = emeta.val_count as usize;

    let mut val_pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    let mut share_pks = [[0u8; 32]; MAX_EPOCH_VALIDATORS];
    let mut addrs_raw = [0u8; MAX_EPOCH_VALIDATORS * 20];
    if !load_epoch_pks(rmeta.epoch_id, val_count, &mut val_pks) {
        return Err(-15);
    }
    let _ = load_epoch_share_pks(rmeta.epoch_id, val_count, &mut share_pks);
    let _ = storage::get_into(
        key_epoch_addrs(rmeta.epoch_id).as_slice(),
        &mut addrs_raw[..val_count * 20],
    );

    let mut out = [0u8; 225 + MAX_EPOCH_VALIDATORS * 84 + MAX_EPOCH_VALIDATORS * 100];
    out[0] = rmeta.status;
    out[1..9].copy_from_slice(&rmeta.epoch_id.to_be_bytes());
    out[9..13].copy_from_slice(&emeta.val_count.to_be_bytes());
    out[13..17].copy_from_slice(&emeta.threshold.to_be_bytes());
    out[17..25].copy_from_slice(&rmeta.requested_block.to_be_bytes());
    out[25..33].copy_from_slice(&rmeta.fulfilled_block.to_be_bytes());
    out[33..53].copy_from_slice(&rmeta.requester);
    out[53..85].copy_from_slice(&rmeta.user_seed);
    out[85..117].copy_from_slice(&rmeta.alpha);
    out[117..149].copy_from_slice(&emeta.epoch_pk);
    out[149..181].copy_from_slice(&rmeta.gamma);
    out[181..213].copy_from_slice(&rmeta.random_out);
    out[213..221].copy_from_slice(&rmeta.signer_bitmap.to_be_bytes());
    out[221..225].copy_from_slice(&rmeta.share_count.to_be_bytes());

    let mut cursor = 225usize;
    let mut i = 0usize;
    while i < val_count {
        out[cursor..cursor + 20].copy_from_slice(&addrs_raw[i * 20..(i + 1) * 20]);
        out[cursor + 20..cursor + 52].copy_from_slice(&val_pks[i]);
        out[cursor + 52..cursor + 84].copy_from_slice(&share_pks[i]);
        cursor += 84;
        i += 1;
    }

    let mut s_idx = 0usize;
    while s_idx < val_count {
        if (rmeta.signer_bitmap & (1u64 << s_idx)) != 0 {
            let mut rec = [0u8; 96];
            if let Some(96) =
                storage::get_into(key_req_share(&req_id, s_idx as u32).as_slice(), &mut rec)
            {
                out[cursor..cursor + 4].copy_from_slice(&(s_idx as u32).to_be_bytes());
                out[cursor + 4..cursor + 100].copy_from_slice(&rec);
                cursor += 100;
            }
        }
        s_idx += 1;
    }

    ret::write(&out[..cursor]);
    Ok(())
}

/// Compact 81-byte output reader (`[status:1][random_32][gamma_32][epoch_id_be8][signer_bitmap_be8]`)
/// for consumer contracts (`settleFromBeacon` fallback).
fn handle_get_fulfilled_output(args: &CalldataReader) -> Result<(), i32> {
    let req_id = args.bytes32(0).ok_or(-3)?;
    let rmeta = load_req(&req_id).ok_or(-22)?;
    let mut out = [0u8; 81];
    out[0] = rmeta.status;
    out[1..33].copy_from_slice(&rmeta.random_out);
    out[33..65].copy_from_slice(&rmeta.gamma);
    out[65..73].copy_from_slice(&rmeta.epoch_id.to_be_bytes());
    out[73..81].copy_from_slice(&rmeta.signer_bitmap.to_be_bytes());
    ret::write(&out);
    Ok(())
}
