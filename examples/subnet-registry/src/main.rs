//! Global On-Chain Subnet & Validator Stats Endpoint Registry (`subnet-registry`, HPS #23).
//!
//! Eliminates external `subnets.json` or centralized directory servers by storing all SuperLexicon
//! Subnets and their validator RPC / PubSub / telemetry endpoints directly on-chain:
//! - Permissionless registration of new `subnet_id`s (`msg_sender()` becomes `owner_eoa`), with
//!   strict operator/admin authorization on subsequent endpoint, coordinate, or status updates.
//! - Stores transport (`flrc` / `tcp`), RF frequency (`channel_hz`), validator count, signed
//!   `lat_e7` / `lon_e7` GPS coordinates, target `hfs_registry` contract address, operator
//!   `Identity` HFS, and structured `endpoints_json` (public WSS + LAN WS RPC/PubSub/Stats URLs).
//! - Serves all registered subnets in a single compact `eth_call` via `getSubnets(offset, limit)`.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_ARCHIVED: u8 = 2;
/// Forming / Waiting-for-Peers beacon (`< min_validators`, advertising GPS + RF frequency until quorum locks).
pub const STATUS_FORMING: u8 = 3;

const MAX_SID_LEN: usize = 32;
const MAX_NAME_LEN: usize = 80;
const MAX_TRANSPORT_LEN: usize = 16;
const MAX_ENDPOINTS_LEN: usize = 1536;
const MAX_SLICE_LIMIT: u64 = 16;

/// Fixed record header (102 bytes):
/// `[status:1][sid_len:1][name_len:1][tr_len:1][ep_len:2][val_cnt:4][lat_e7:4][lon_e7:4]`
/// `[channel_hz:8][created_blk:8][updated_blk:8][owner_eoa:20][operator_id:20][hfs_reg:20]`
const FIXED_REC_HDR: usize = 102;
const MAX_REC_BYTES: usize =
    FIXED_REC_HDR + MAX_SID_LEN + MAX_NAME_LEN + MAX_TRANSPORT_LEN + MAX_ENDPOINTS_LEN;
const SLICE_OUT_CAP: usize = 16 + (MAX_SLICE_LIMIT as usize) * (8 + MAX_REC_BYTES);

const MIN_LAT_E7: i32 = -900_000_000;
const MAX_LAT_E7: i32 = 900_000_000;
const MIN_LON_E7: i32 = -1_800_000_000;
const MAX_LON_E7: i32 = 1_800_000_000;

const KEY_INIT: &[u8] = b"subreg:init";
const KEY_ADMIN: &[u8] = b"subreg:admin";
const KEY_TOTAL: &[u8] = b"subreg:total";

const EV_INITIALIZED: [u8; 32] = event_topic("SubnetRegistryInitialized(address)");
const EV_UPSERTED: [u8; 32] =
    event_topic("SubnetUpserted(bytes32,address,address,uint64,uint64)");
const EV_STATUS_CHANGED: [u8; 32] =
    event_topic("SubnetStatusChanged(bytes32,uint64,uint64)");
const EV_OWNERSHIP_TRANSFERRED: [u8; 32] =
    event_topic("SubnetOwnershipTransferred(bytes32,address,address)");

hps_entry! {
    "initialize(address)"                                                                                  => handle_initialize,
    "rotateAdmin(address)"                                                                                 => handle_rotate_admin,
    "upsertSubnet(string,string,string,uint64,uint64,uint64,uint64,address,address,bytes)"                 => handle_upsert_subnet,
    "setSubnetStatus(string,uint64)"                                                                       => handle_set_subnet_status,
    "transferSubnetOwnership(string,address)"                                                              => handle_transfer_ownership,
    "getSubnets(uint64,uint64)"                                                                            => handle_get_subnets,
    "getSubnetById(string)"                                                                                => handle_get_subnet_by_id,
    "totalCount()"                                                                                         => handle_total_count,
    "admin()"                                                                                              => handle_admin,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn get_admin() -> [u8; 20] {
    storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20])
}

fn require_init() -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    Ok(())
}

fn require_admin() -> Result<[u8; 20], i32> {
    require_init()?;
    let caller = context::msg_sender();
    if caller != get_admin() {
        return Err(-12);
    }
    Ok(caller)
}

/// Normalize `subnet_id` by trimming ASCII whitespace and lowercasing (`a-z`, `0-9`, `-`, `_`).
fn normalize_subnet_id(raw: &[u8], out: &mut [u8; MAX_SID_LEN]) -> Result<usize, i32> {
    let mut start = 0usize;
    let mut end = raw.len();
    while start < end && raw[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let trimmed = &raw[start..end];
    if trimmed.is_empty() || trimmed.len() > MAX_SID_LEN {
        return Err(-14);
    }
    for (i, &b) in trimmed.iter().enumerate() {
        let low = b.to_ascii_lowercase();
        let ok = low.is_ascii_lowercase() || low.is_ascii_digit() || low == b'-' || low == b'_';
        if !ok {
            return Err(-14);
        }
        out[i] = low;
    }
    Ok(trimmed.len())
}

fn id_lookup_key(sid: &[u8]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new().push(b"sid:").push(sid)
}

fn item_key(idx: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"sub:").push_u64_be(idx)
}

/// Bounded `no_std` scan checking whether `endpoints` JSON marks `"forming":true` / `"forming": true`.
fn endpoints_marks_forming(endpoints: &[u8]) -> bool {
    let needle_a = br#""forming":true"#;
    let needle_b = br#""forming": true"#;
    endpoints.windows(needle_a.len()).any(|w| w == needle_a)
        || endpoints.windows(needle_b.len()).any(|w| w == needle_b)
}

#[allow(clippy::too_many_arguments)]
fn pack_subnet_record(
    status: u8,
    sid: &[u8],
    name: &[u8],
    transport: &[u8],
    endpoints: &[u8],
    validator_count: u32,
    lat_e7: i32,
    lon_e7: i32,
    channel_hz: u64,
    created_block: u64,
    updated_block: u64,
    owner_eoa: &[u8; 20],
    operator_identity: &[u8; 20],
    hfs_registry: &[u8; 20],
    out: &mut [u8; MAX_REC_BYTES],
) -> usize {
    let sid_len = sid.len().min(MAX_SID_LEN);
    let name_len = name.len().min(MAX_NAME_LEN);
    let tr_len = transport.len().min(MAX_TRANSPORT_LEN);
    let ep_len = endpoints.len().min(MAX_ENDPOINTS_LEN);

    out[0] = status;
    out[1] = sid_len as u8;
    out[2] = name_len as u8;
    out[3] = tr_len as u8;
    out[4..6].copy_from_slice(&(ep_len as u16).to_be_bytes());
    out[6..10].copy_from_slice(&validator_count.to_be_bytes());
    out[10..14].copy_from_slice(&lat_e7.to_be_bytes());
    out[14..18].copy_from_slice(&lon_e7.to_be_bytes());
    out[18..26].copy_from_slice(&channel_hz.to_be_bytes());
    out[26..34].copy_from_slice(&created_block.to_be_bytes());
    out[34..42].copy_from_slice(&updated_block.to_be_bytes());
    out[42..62].copy_from_slice(owner_eoa);
    out[62..82].copy_from_slice(operator_identity);
    out[82..102].copy_from_slice(hfs_registry);

    let mut pos = FIXED_REC_HDR;
    out[pos..pos + sid_len].copy_from_slice(&sid[..sid_len]);
    pos += sid_len;
    out[pos..pos + name_len].copy_from_slice(&name[..name_len]);
    pos += name_len;
    out[pos..pos + tr_len].copy_from_slice(&transport[..tr_len]);
    pos += tr_len;
    out[pos..pos + ep_len].copy_from_slice(&endpoints[..ep_len]);
    pos += ep_len;
    pos
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(-10);
    }
    let admin = args.address(0).ok_or(-1)?;
    if admin == [0u8; 20] {
        return Err(-2);
    }
    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_ADMIN, &admin);
    events::emit(&[EV_INITIALIZED, addr_topic(&admin)], &[]);
    Ok(())
}

fn handle_rotate_admin(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    let next_admin = args.address(0).ok_or(-1)?;
    if next_admin == [0u8; 20] {
        return Err(-2);
    }
    storage::set_address(KEY_ADMIN, &next_admin);
    Ok(())
}

fn handle_upsert_subnet(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;

    let raw_sid = args.dynamic_bytes(0).ok_or(-1)?;
    let name = args.dynamic_bytes(1).ok_or(-1)?;
    let transport = args.dynamic_bytes(2).ok_or(-1)?;
    let channel_hz = args.u64(3).ok_or(-1)?;
    let val_cnt_u64 = args.u64(4).ok_or(-1)?;
    let lat_bits = args.u64(5).ok_or(-1)?;
    let lon_bits = args.u64(6).ok_or(-1)?;
    let hfs_registry = args.address(7).ok_or(-1)?;
    let operator_identity = args.address(8).ok_or(-1)?;
    let endpoints = args.dynamic_bytes(9).ok_or(-1)?;

    let mut sid_buf = [0u8; MAX_SID_LEN];
    let sid_len = normalize_subnet_id(raw_sid, &mut sid_buf)?;
    let sid = &sid_buf[..sid_len];

    if name.is_empty()
        || name.len() > MAX_NAME_LEN
        || transport.is_empty()
        || transport.len() > MAX_TRANSPORT_LEN
        || endpoints.len() > MAX_ENDPOINTS_LEN
    {
        return Err(-16);
    }
    if lat_bits > (u32::MAX as u64) || lon_bits > (u32::MAX as u64) {
        return Err(-17);
    }
    let lat_e7 = (lat_bits as u32) as i32;
    let lon_e7 = (lon_bits as u32) as i32;
    if !(MIN_LAT_E7..=MAX_LAT_E7).contains(&lat_e7) || !(MIN_LON_E7..=MAX_LON_E7).contains(&lon_e7)
    {
        return Err(-17);
    }

    let validator_count = val_cnt_u64.min(u32::MAX as u64) as u32;
    let caller = context::msg_sender();
    let admin = get_admin();
    let now_blk = context::block_number();

    let lk = id_lookup_key(sid);
    let existing_plus_one = storage::get_u64(lk.as_slice());
    let mut rec_buf = [0u8; MAX_REC_BYTES];

    let (idx, eff_status, eff_owner, eff_op_id) = if existing_plus_one > 0 {
        let idx = existing_plus_one - 1;
        let ik = item_key(idx);
        let mut old_buf = [0u8; MAX_REC_BYTES];
        let old_len = storage::get_into(ik.as_slice(), &mut old_buf).unwrap_or(0);
        if old_len < FIXED_REC_HDR {
            return Err(-23);
        }
        let mut orig_owner = [0u8; 20];
        orig_owner.copy_from_slice(&old_buf[42..62]);
        if caller != orig_owner && caller != admin {
            return Err(-22);
        }
        let created_blk = u64::from_be_bytes([
            old_buf[26],
            old_buf[27],
            old_buf[28],
            old_buf[29],
            old_buf[30],
            old_buf[31],
            old_buf[32],
            old_buf[33],
        ]);
        let eff_id = if operator_identity != [0u8; 20] {
            operator_identity
        } else {
            let mut prev_id = [0u8; 20];
            prev_id.copy_from_slice(&old_buf[62..82]);
            prev_id
        };
        let eff_hfs_reg = if hfs_registry != [0u8; 20] {
            hfs_registry
        } else {
            let mut prev_reg = [0u8; 20];
            prev_reg.copy_from_slice(&old_buf[82..102]);
            prev_reg
        };
        let prev_st = old_buf[0];
        let st = if prev_st == STATUS_ARCHIVED {
            STATUS_ARCHIVED
        } else if endpoints_marks_forming(endpoints) {
            STATUS_FORMING
        } else if prev_st == STATUS_FORMING && validator_count >= 3 {
            // Automatically promote a forming subnet to ACTIVE once quorum (>=3) is reached!
            STATUS_ACTIVE
        } else {
            prev_st
        };
        let n = pack_subnet_record(
            st,
            sid,
            name,
            transport,
            endpoints,
            validator_count,
            lat_e7,
            lon_e7,
            channel_hz,
            created_blk,
            now_blk,
            &orig_owner,
            &eff_id,
            &eff_hfs_reg,
            &mut rec_buf,
        );
        storage::set(ik.as_slice(), &rec_buf[..n]);
        (idx, st, orig_owner, eff_id)
    } else {
        let idx = storage::get_u64(KEY_TOTAL);
        storage::set_u64(KEY_TOTAL, idx + 1);
        storage::set_u64(lk.as_slice(), idx + 1);
        let init_status = if endpoints_marks_forming(endpoints) {
            STATUS_FORMING
        } else {
            STATUS_ACTIVE
        };

        let n = pack_subnet_record(
            init_status,
            sid,
            name,
            transport,
            endpoints,
            validator_count,
            lat_e7,
            lon_e7,
            channel_hz,
            now_blk,
            now_blk,
            &caller,
            &operator_identity,
            &hfs_registry,
            &mut rec_buf,
        );
        let ik = item_key(idx);
        storage::set(ik.as_slice(), &rec_buf[..n]);
        (idx, init_status, caller, operator_identity)
    };

    let sid_hash = keccak256(sid);
    let mut ev_data = [0u8; 16];
    ev_data[0..8].copy_from_slice(&idx.to_be_bytes());
    ev_data[8..16].copy_from_slice(&(eff_status as u64).to_be_bytes());
    events::emit(
        &[
            EV_UPSERTED,
            sid_hash,
            addr_topic(&eff_owner),
            addr_topic(&eff_op_id),
        ],
        &ev_data,
    );

    ret::write_u64_word(idx);
    Ok(())
}

fn handle_set_subnet_status(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let raw_sid = args.dynamic_bytes(0).ok_or(-1)?;
    let next_status = args.u64(1).ok_or(-1)?;
    if next_status != (STATUS_ACTIVE as u64)
        && next_status != (STATUS_ARCHIVED as u64)
        && next_status != (STATUS_FORMING as u64)
    {
        return Err(-18);
    }

    let mut sid_buf = [0u8; MAX_SID_LEN];
    let sid_len = normalize_subnet_id(raw_sid, &mut sid_buf)?;
    let sid = &sid_buf[..sid_len];

    let lk = id_lookup_key(sid);
    let existing_plus_one = storage::get_u64(lk.as_slice());
    if existing_plus_one == 0 {
        return Err(-19);
    }
    let idx = existing_plus_one - 1;
    let ik = item_key(idx);

    let mut rec_buf = [0u8; MAX_REC_BYTES];
    let n = storage::get_into(ik.as_slice(), &mut rec_buf).unwrap_or(0);
    if n < FIXED_REC_HDR {
        return Err(-23);
    }

    let caller = context::msg_sender();
    let admin = get_admin();
    let mut orig_owner = [0u8; 20];
    orig_owner.copy_from_slice(&rec_buf[42..62]);
    if caller != orig_owner && caller != admin {
        return Err(-22);
    }

    rec_buf[0] = next_status as u8;
    rec_buf[34..42].copy_from_slice(&context::block_number().to_be_bytes());
    storage::set(ik.as_slice(), &rec_buf[..n]);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&idx.to_be_bytes());
    ev[8..16].copy_from_slice(&next_status.to_be_bytes());
    events::emit(&[EV_STATUS_CHANGED, keccak256(sid)], &ev);
    Ok(())
}

fn handle_transfer_ownership(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let raw_sid = args.dynamic_bytes(0).ok_or(-1)?;
    let new_owner = args.address(1).ok_or(-1)?;
    if new_owner == [0u8; 20] {
        return Err(-2);
    }

    let mut sid_buf = [0u8; MAX_SID_LEN];
    let sid_len = normalize_subnet_id(raw_sid, &mut sid_buf)?;
    let sid = &sid_buf[..sid_len];

    let lk = id_lookup_key(sid);
    let existing_plus_one = storage::get_u64(lk.as_slice());
    if existing_plus_one == 0 {
        return Err(-19);
    }
    let idx = existing_plus_one - 1;
    let ik = item_key(idx);

    let mut rec_buf = [0u8; MAX_REC_BYTES];
    let n = storage::get_into(ik.as_slice(), &mut rec_buf).unwrap_or(0);
    if n < FIXED_REC_HDR {
        return Err(-23);
    }

    let caller = context::msg_sender();
    let admin = get_admin();
    let mut prev_owner = [0u8; 20];
    prev_owner.copy_from_slice(&rec_buf[42..62]);
    if caller != prev_owner && caller != admin {
        return Err(-22);
    }

    rec_buf[42..62].copy_from_slice(&new_owner);
    rec_buf[34..42].copy_from_slice(&context::block_number().to_be_bytes());
    storage::set(ik.as_slice(), &rec_buf[..n]);

    events::emit(
        &[
            EV_OWNERSHIP_TRANSFERRED,
            keccak256(sid),
            addr_topic(&prev_owner),
            addr_topic(&new_owner),
        ],
        &[],
    );
    Ok(())
}

fn handle_get_subnets(args: &CalldataReader) -> Result<(), i32> {
    let offset = args.u64(0).ok_or(-1)?;
    let limit = args.u64(1).ok_or(-1)?.min(MAX_SLICE_LIMIT);
    let total = storage::get_u64(KEY_TOTAL);

    let mut out = [0u8; SLICE_OUT_CAP];
    out[0..8].copy_from_slice(&total.to_be_bytes());

    let mut pos = 16usize;
    let mut returned = 0u64;
    let mut i = offset;
    let end = offset.saturating_add(limit).min(total);
    let mut item_buf = [0u8; MAX_REC_BYTES];

    while i < end {
        let ik = item_key(i);
        let n = storage::get_into(ik.as_slice(), &mut item_buf).unwrap_or(0);
        if n >= FIXED_REC_HDR && pos + 8 + n <= SLICE_OUT_CAP {
            out[pos..pos + 8].copy_from_slice(&i.to_be_bytes());
            pos += 8;
            out[pos..pos + n].copy_from_slice(&item_buf[..n]);
            pos += n;
            returned += 1;
        }
        i += 1;
    }

    out[8..16].copy_from_slice(&returned.to_be_bytes());
    ret::write(&out[..pos]);
    Ok(())
}

fn handle_get_subnet_by_id(args: &CalldataReader) -> Result<(), i32> {
    let raw_sid = args.dynamic_bytes(0).ok_or(-1)?;
    let mut sid_buf = [0u8; MAX_SID_LEN];
    let sid_len = match normalize_subnet_id(raw_sid, &mut sid_buf) {
        Ok(l) => l,
        Err(_) => {
            ret::write(&[]);
            return Ok(());
        }
    };
    let lk = id_lookup_key(&sid_buf[..sid_len]);
    let existing_plus_one = storage::get_u64(lk.as_slice());
    if existing_plus_one == 0 {
        ret::write(&[]);
        return Ok(());
    }
    let idx = existing_plus_one - 1;
    let ik = item_key(idx);
    let mut item_buf = [0u8; MAX_REC_BYTES];
    let n = storage::get_into(ik.as_slice(), &mut item_buf).unwrap_or(0);
    if n < FIXED_REC_HDR {
        ret::write(&[]);
        return Ok(());
    }
    let mut out = [0u8; 8 + MAX_REC_BYTES];
    out[0..8].copy_from_slice(&idx.to_be_bytes());
    out[8..8 + n].copy_from_slice(&item_buf[..n]);
    ret::write(&out[..8 + n]);
    Ok(())
}

fn handle_total_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL));
    Ok(())
}

fn handle_admin(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&get_admin());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    #[allow(clippy::too_many_arguments)]
    fn encode_upsert(
        sid: &[u8],
        name: &[u8],
        transport: &[u8],
        channel_hz: u64,
        val_cnt: u64,
        lat_e7: i32,
        lon_e7: i32,
        hfs_reg: &[u8; 20],
        op_id: &[u8; 20],
        endpoints: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&selector(
            "upsertSubnet(string,string,string,uint64,uint64,uint64,uint64,address,address,bytes)",
        ));

        let pad_len = |l: usize| l + ((32 - (l % 32)) % 32);
        let head_bytes = 10 * 32;
        let off0 = head_bytes;
        let off1 = off0 + 32 + pad_len(sid.len());
        let off2 = off1 + 32 + pad_len(name.len());
        let off9 = off2 + 32 + pad_len(transport.len());

        let push_u64_w = |vec: &mut Vec<u8>, val: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&val.to_be_bytes());
            vec.extend_from_slice(&w);
        };
        let push_addr_w = |vec: &mut Vec<u8>, a: &[u8; 20]| {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(a);
            vec.extend_from_slice(&w);
        };
        let push_dyn = |vec: &mut Vec<u8>, d: &[u8]| {
            push_u64_w(vec, d.len() as u64);
            vec.extend_from_slice(d);
            let p = (32 - (d.len() % 32)) % 32;
            vec.extend(std::iter::repeat(0u8).take(p));
        };

        push_u64_w(&mut v, off0 as u64);
        push_u64_w(&mut v, off1 as u64);
        push_u64_w(&mut v, off2 as u64);
        push_u64_w(&mut v, channel_hz);
        push_u64_w(&mut v, val_cnt);
        push_u64_w(&mut v, (lat_e7 as u32) as u64);
        push_u64_w(&mut v, (lon_e7 as u32) as u64);
        push_addr_w(&mut v, hfs_reg);
        push_addr_w(&mut v, op_id);
        push_u64_w(&mut v, off9 as u64);

        push_dyn(&mut v, sid);
        push_dyn(&mut v, name);
        push_dyn(&mut v, transport);
        push_dyn(&mut v, endpoints);
        v
    }

    #[test]
    fn registers_updates_guards_ownership_and_slices_subnets() {
        mock::reset();
        let reg = [0xAA; 20];
        let admin = [0x01; 20];
        let op1 = [0x02; 20];
        let op2 = [0x03; 20];
        let attacker = [0x09; 20];
        let hfs_reg_s1 = [0xE1; 20];
        let op1_id = [0x12; 20];

        mock::register_hps(reg, dispatch_calldata);
        mock::set_block_number(6_500);

        let init_cd = CallEncoder::<128>::new(selector("initialize(address)")).push_address(&admin);
        assert!(mock::transact_as(admin, reg, init_cd.as_slice()).is_ok());

        // Register Subnet 1 (Singapore RF) & Subnet 2 (TCP/IP) & Subnet 3 (Southern/Western hemisphere negative coords!)
        let ep1 = br#"{"publicRpcUrls":["wss://node1.superlexicon.com/rpc","wss://node2.superlexicon.com/rpc"]}"#;
        let cd1 = encode_upsert(
            b"E40AF3DD",
            b"Subnet 1 - 915 MHz LR2021 RF",
            b"flrc",
            915_000_000,
            4,
            13_031_000,
            1_039_128_000,
            &hfs_reg_s1,
            &op1_id,
            ep1,
        );
        assert!(mock::transact_as(op1, reg, &cd1).is_ok());

        let ep2 = br#"{"publicRpcUrls":["wss://node21.superlexicon.com/rpc","wss://node22.superlexicon.com/rpc","wss://node23.superlexicon.com/rpc"]}"#;
        let cd2 = encode_upsert(
            b"6eaa3da4",
            b"Subnet 2 - Encrypted TCP/IP Mesh",
            b"tcp",
            1,
            3,
            -338_688_000,
            -706_693_000,
            &[0u8; 20],
            &[0u8; 20],
            ep2,
        );
        assert!(mock::transact_as(op2, reg, &cd2).is_ok());

        // Unauthorized attacker cannot overwrite Subnet 1's node URLs (-22)!
        let spoof_cd = encode_upsert(
            b"e40af3dd",
            b"Hijacked Subnet",
            b"tcp",
            1,
            1,
            0,
            0,
            &[0u8; 20],
            &[0u8; 20],
            br#"{"publicRpcUrls":["wss://evil.example/rpc"]}"#,
        );
        assert_eq!(mock::transact_as(attacker, reg, &spoof_cd), Err(-22));

        // Original owner CAN update Subnet 1's node URLs cleanly
        mock::set_block_number(6_510);
        let upd_cd = encode_upsert(
            b"e40af3dd",
            b"Subnet 1 - 915 MHz LR2021 RF",
            b"flrc",
            915_000_000,
            4,
            13_031_000,
            1_039_128_000,
            &[0u8; 20],
            &[0u8; 20],
            br#"{"publicRpcUrls":["wss://node1.superlexicon.com/rpc","wss://node3.superlexicon.com/rpc"]}"#,
        );
        assert!(mock::transact_as(op1, reg, &upd_cd).is_ok());

        // Query all subnets in 1 slice call
        let q_cd = CallEncoder::<128>::new(selector("getSubnets(uint64,uint64)"))
            .push_u64(0)
            .push_u64(16);
        let raw = mock::transact_as(attacker, reg, q_cd.as_slice()).unwrap();
        let total = u64::from_be_bytes(raw[0..8].try_into().unwrap());
        let returned = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        assert_eq!(total, 2);
        assert_eq!(returned, 2);

        // Verify record 0 preserved hfs_registry & op1_id on zero-address update, and normalized subnet_id
        let r0 = &raw[24..];
        assert_eq!(r0[0], STATUS_ACTIVE);
        assert_eq!(r0[1], 8); // "e40af3dd"
        assert_eq!(&r0[62..82], &op1_id);
        assert_eq!(&r0[82..102], &hfs_reg_s1);
        assert_eq!(&r0[102..110], b"e40af3dd");

        // Verify negative signed lat/lon roundtrip on record 1
        let r0_len = FIXED_REC_HDR
            + (r0[1] as usize)
            + (r0[2] as usize)
            + (r0[3] as usize)
            + (u16::from_be_bytes([r0[4], r0[5]]) as usize);
        let r1 = &raw[24 + r0_len + 8..];
        let lat1 = i32::from_be_bytes(r1[10..14].try_into().unwrap());
        let lon1 = i32::from_be_bytes(r1[14..18].try_into().unwrap());
        assert_eq!(lat1, -338_688_000);
        assert_eq!(lon1, -706_693_000);
    }

    #[test]
    fn forming_subnet_advertises_gps_and_freq_then_promotes_to_active_at_three_peers() {
        mock::reset();
        let reg = [0xBB; 20];
        let admin = [0x01; 20];
        let solo_op = [0x04; 20];

        mock::register_hps(reg, dispatch_calldata);
        mock::set_block_number(7_000);

        let init_cd = CallEncoder::<128>::new(selector("initialize(address)")).push_address(&admin);
        assert!(mock::transact_as(admin, reg, init_cd.as_slice()).is_ok());

        // 1. Solo node advertises GPS + 915.250 MHz while waiting for 2 more peers (1/3)
        let forming_ep = br#"{"forming":true,"minValidators":3,"haveValidators":1,"fuzzyRadiusM":500,"locationLabel":"Austin Hill Country, TX"}"#;
        let cd_form = encode_upsert(
            b"form-atx-915",
            b"Austin Hill Country Forming Mesh",
            b"flrc",
            915_250_000,
            1,
            302_672_000,
            -977_431_000,
            &[0u8; 20],
            &[0u8; 20],
            forming_ep,
        );
        assert!(mock::transact_as(solo_op, reg, &cd_form).is_ok());

        let get_cd = {
            let mut v = Vec::new();
            v.extend_from_slice(&selector("getSubnetById(string)"));
            let mut w = [0u8; 32];
            w[31] = 32;
            v.extend_from_slice(&w);
            let sid = b"form-atx-915";
            let mut lw = [0u8; 32];
            lw[31] = sid.len() as u8;
            v.extend_from_slice(&lw);
            v.extend_from_slice(sid);
            v.extend(std::iter::repeat(0u8).take(32 - sid.len()));
            v
        };
        let rec1 = mock::transact_as(solo_op, reg, &get_cd).unwrap();
        assert_eq!(rec1[8], STATUS_FORMING);
        assert_eq!(u32::from_be_bytes(rec1[14..18].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_be_bytes(rec1[26..34].try_into().unwrap()),
            915_250_000
        );

        // 2. Once 3/3 peers lock quorum & start Block 0, upserting with validator_count=3 & forming:false promotes to STATUS_ACTIVE!
        mock::set_block_number(7_025);
        let active_ep = br#"{"forming":false,"locationLabel":"Austin Hill Country, TX","publicRpcUrls":[]}"#;
        let cd_act = encode_upsert(
            b"form-atx-915",
            b"Austin Hill Country 915.25 MHz Mesh",
            b"flrc",
            915_250_000,
            3,
            302_672_000,
            -977_431_000,
            &[0u8; 20],
            &[0u8; 20],
            active_ep,
        );
        assert!(mock::transact_as(solo_op, reg, &cd_act).is_ok());

        let rec2 = mock::transact_as(solo_op, reg, &get_cd).unwrap();
        assert_eq!(rec2[8], STATUS_ACTIVE);
        assert_eq!(u32::from_be_bytes(rec2[14..18].try_into().unwrap()), 3);
    }
}
