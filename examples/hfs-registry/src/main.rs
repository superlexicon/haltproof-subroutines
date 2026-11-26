//! Global Haltproof Subroutine Directory (`hfs-registry`, HPS #18).
//!
//! Organizes all deployed HFS instances on Subnet 1 by logical `typeId` (`bytes32`, e.g.
//! `DEX_CLOB`, `PHANTOM_FLEET`, `CORPORATE_CHARTER`, `PRODUCT_LEDGER`, `SOCIAL_CHARTER`,
//! `FRACTURED_HEGEMONY`, `CIPHER_NOIR`) so any dApp page can render a live selector dropdown and allow users to
//! deploy & register new HFS instances directly from the browser:
//! - Verifies `context::code_hash_of(&primaryAddr)` on registration against approved WASM
//!   `code_hash` entries per `typeId` (preventing EOA or mismatched-contract spoofing).
//! - Records `creator_eoa`, `creator_identity` (`Identity` HFS for `<Nickname> · <4-char>`),
//!   `abi_version`, `created_block`, human-readable `label` (up to 64B), and `meta` (up to 512B
//!   for companion HFS addresses or arena/match IDs).
//! - Serves `getInstancesByType(bytes32,uint64,uint64)` in a single compact binary slice call.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::governance::is_confusable_superlexicon_name;
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_ARCHIVED: u8 = 2;
pub const ERR_SOVEREIGN_ALREADY_PINNED: i32 = -24;
pub const ERR_RESERVED_SUPERLEXICON_NAME: i32 = -25;

const MAX_LABEL_LEN: usize = 64;
const MAX_META_LEN: usize = 512;
const MAX_SLICE_LIMIT: u64 = 32;
/// Max serialized record size:
/// `[abi_ver:4][status:1][primary:20][code_hash:32][creator_eoa:20][creator_id:20][blk:8][lbl_len:2][meta_len:2]`
/// = 109 header bytes + 64 + 512 = 685 bytes.
const FIXED_REC_HDR: usize = 109;
const MAX_REC_BYTES: usize = FIXED_REC_HDR + MAX_LABEL_LEN + MAX_META_LEN;
const SLICE_OUT_CAP: usize = 16 + (MAX_SLICE_LIMIT as usize) * MAX_REC_BYTES;

const KEY_INIT: &[u8] = b"hfsreg:init";
const KEY_ADMIN: &[u8] = b"hfsreg:admin";
const KEY_TOTAL_COUNT: &[u8] = b"hfsreg:total";
const KEY_SOVEREIGN_CHARTER: &[u8] = b"hfsreg:sov_slx";

const EV_INITIALIZED: [u8; 32] = event_topic("HfsRegistryInitialized(address)");
const EV_SOVEREIGN_PINNED: [u8; 32] = event_topic("SovereignCharterPinned(address)");
const EV_CODE_HASH_SET: [u8; 32] =
    event_topic("HfsTypeCodeHashUpdated(bytes32,bytes32,uint64,bool)");
const EV_REGISTERED: [u8; 32] =
    event_topic("HfsInstanceRegistered(bytes32,address,address,uint64,bytes32)");
const EV_STATUS_CHANGED: [u8; 32] =
    event_topic("HfsInstanceStatusChanged(bytes32,uint64,uint64)");

hps_entry! {
    "initialize(address)"                                                  => handle_initialize,
    "rotateAdmin(address)"                                                 => handle_rotate_admin,
    "pinSovereignCharter(address)"                                         => handle_pin_sovereign_charter,
    "sovereignCharter()"                                                   => handle_sovereign_charter,
    "setTypeCodeHash(bytes32,bytes32,uint64,bool)"                         => handle_set_type_code_hash,
    "registerInstance(bytes32,address,address,string,bytes)"               => handle_register_instance,
    "setInstanceStatus(bytes32,uint64,uint64)"                             => handle_set_instance_status,
    "getInstancesByType(bytes32,uint64,uint64)"                            => handle_get_instances_by_type,
    "getTypeCount(bytes32)"                                                => handle_get_type_count,
    "totalCount()"                                                         => handle_total_count,
    "allowedAbiVersion(bytes32,bytes32)"                                   => handle_allowed_abi_version,
    "admin()"                                                              => handle_admin,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn get_admin() -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut buf = [0u8; 32];
    let n = storage::get_into(KEY_ADMIN, &mut buf).unwrap_or(0);
    if n == 20 {
        out.copy_from_slice(&buf[..20]);
    }
    out
}

fn require_admin() -> Result<[u8; 20], i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let caller = context::msg_sender();
    let admin = get_admin();
    if caller != admin {
        return Err(-12);
    }
    Ok(caller)
}

fn type_strict_key(type_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"strict:").push(type_id)
}

fn type_code_key(type_id: &[u8; 32], code_hash: &[u8; 32]) -> KeyBuilder<80> {
    KeyBuilder::<80>::new()
        .push(b"allow:")
        .push(type_id)
        .push(b":")
        .push(code_hash)
}

fn type_count_key(type_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"cnt:").push(type_id)
}

fn type_item_key(type_id: &[u8; 32], idx: u64) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"itm:")
        .push(type_id)
        .push(b":")
        .push_u64_be(idx)
}

fn dedup_key(dedup_hash: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"dup:").push(dedup_hash)
}

fn compute_dedup_hash(type_id: &[u8; 32], primary_addr: &[u8; 20], meta: &[u8]) -> [u8; 32] {
    let meta_hash = keccak256(meta);
    let mut pre = [0u8; 84];
    pre[0..32].copy_from_slice(type_id);
    pre[32..52].copy_from_slice(primary_addr);
    pre[52..84].copy_from_slice(&meta_hash);
    keccak256(&pre)
}

fn pack_record(
    abi_ver: u32,
    status: u8,
    primary_addr: &[u8; 20],
    code_hash: &[u8; 32],
    creator_eoa: &[u8; 20],
    creator_identity: &[u8; 20],
    created_block: u64,
    label: &[u8],
    meta: &[u8],
    out: &mut [u8; MAX_REC_BYTES],
) -> usize {
    let lbl_len = label.len().min(MAX_LABEL_LEN);
    let m_len = meta.len().min(MAX_META_LEN);
    out[0..4].copy_from_slice(&abi_ver.to_be_bytes());
    out[4] = status;
    out[5..25].copy_from_slice(primary_addr);
    out[25..57].copy_from_slice(code_hash);
    out[57..77].copy_from_slice(creator_eoa);
    out[77..97].copy_from_slice(creator_identity);
    out[97..105].copy_from_slice(&created_block.to_be_bytes());
    out[105..107].copy_from_slice(&(lbl_len as u16).to_be_bytes());
    out[107..109].copy_from_slice(&(m_len as u16).to_be_bytes());
    out[109..109 + lbl_len].copy_from_slice(&label[..lbl_len]);
    out[109 + lbl_len..109 + lbl_len + m_len].copy_from_slice(&meta[..m_len]);
    109 + lbl_len + m_len
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
    storage::set(KEY_ADMIN, &admin);
    events::emit(&[EV_INITIALIZED, addr_topic(&admin)], &[]);
    Ok(())
}

fn handle_rotate_admin(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    let next_admin = args.address(0).ok_or(-1)?;
    if next_admin == [0u8; 20] {
        return Err(-2);
    }
    storage::set(KEY_ADMIN, &next_admin);
    Ok(())
}

fn get_sovereign_charter() -> [u8; 20] {
    storage::get_address(KEY_SOVEREIGN_CHARTER).unwrap_or([0u8; 20])
}

/// Casts the sovereign `Superlexicon Pte. Ltd.` `CorporateCharter` address in stone (write-once).
/// Once set to a non-zero deployed WASM contract, it can NEVER be overwritten or reassigned.
fn handle_pin_sovereign_charter(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    if get_sovereign_charter() != [0u8; 20] {
        return Err(ERR_SOVEREIGN_ALREADY_PINNED);
    }
    let charter = args.address(0).ok_or(-1)?;
    if charter == [0u8; 20] {
        return Err(-2);
    }
    let ch = context::code_hash_of(&charter).ok_or(-20)?;
    if ch == [0u8; 32] {
        return Err(-20);
    }
    storage::set_address(KEY_SOVEREIGN_CHARTER, &charter);
    events::emit(&[EV_SOVEREIGN_PINNED, addr_topic(&charter)], &[]);
    ret::write_bool(true);
    Ok(())
}

fn handle_sovereign_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&get_sovereign_charter());
    Ok(())
}

fn handle_set_type_code_hash(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    let type_id = args.bytes32(0).ok_or(-1)?;
    let code_hash = args.bytes32(1).ok_or(-1)?;
    let abi_version = args.u64(2).ok_or(-1)?;
    let allowed = args.bool(3).ok_or(-1)?;

    if type_id == [0u8; 32] || code_hash == [0u8; 32] {
        return Err(-3);
    }
    let strict_k = type_strict_key(&type_id);
    storage::set_u64(strict_k.as_slice(), 1);

    let allow_k = type_code_key(&type_id, &code_hash);
    if allowed {
        let ver = abi_version.max(1).min(u32::MAX as u64);
        storage::set_u64(allow_k.as_slice(), ver);
    } else {
        storage::set_u64(allow_k.as_slice(), 0);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&abi_version.to_be_bytes());
    ev[8..16].copy_from_slice(&(if allowed { 1u64 } else { 0u64 }).to_be_bytes());
    events::emit(&[EV_CODE_HASH_SET, type_id, code_hash], &ev);
    Ok(())
}

fn handle_register_instance(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let type_id = args.bytes32(0).ok_or(-1)?;
    let primary_addr = args.address(1).ok_or(-1)?;
    let creator_identity = args.address(2).ok_or(-1)?;
    let label = args.dynamic_bytes(3).ok_or(-1)?;
    let meta = args.dynamic_bytes(4).ok_or(-1)?;

    if type_id == [0u8; 32] || primary_addr == [0u8; 20] {
        return Err(-15);
    }
    if label.is_empty() || label.len() > MAX_LABEL_LEN || meta.len() > MAX_META_LEN {
        return Err(-16);
    }

    // Verify `primary_addr` is a real deployed WASM contract and check its `code_hash`
    let actual_code_hash = context::code_hash_of(&primary_addr).ok_or(-20)?;
    if actual_code_hash == [0u8; 32] {
        return Err(-20);
    }

    let strict_k = type_strict_key(&type_id);
    let abi_ver: u32 = if storage::get_u64(strict_k.as_slice()) == 1 {
        let allow_k = type_code_key(&type_id, &actual_code_hash);
        let ver = storage::get_u64(allow_k.as_slice());
        if ver == 0 {
            return Err(-21); // Unapproved WASM code_hash for this HFS typeId!
        }
        ver as u32
    } else {
        1u32
    };

    let caller = context::msg_sender();
    let admin = get_admin();

    // Protocol-level anti-imposter reservation for `Superlexicon Pte. Ltd.` and confusable names:
    // Only the cast-in-stone `sovereignCharter()` (or registry `admin` once `sovereignCharter` is pinned)
    // may register labels matching or resembling `Superlexicon`!
    if is_confusable_superlexicon_name(label) {
        let sov = get_sovereign_charter();
        let allowed = sov != [0u8; 20] && (primary_addr == sov || caller == admin);
        if !allowed {
            return Err(ERR_RESERVED_SUPERLEXICON_NAME);
        }
    }

    let d_hash = compute_dedup_hash(&type_id, &primary_addr, meta);
    let dk = dedup_key(&d_hash);
    let existing_plus_one = storage::get_u64(dk.as_slice());

    let mut rec_buf = [0u8; MAX_REC_BYTES];

    if existing_plus_one > 0 {
        // Update existing entry's label only if caller is original creator EOA or registry admin
        let idx = existing_plus_one - 1;
        let ik = type_item_key(&type_id, idx);
        let mut old_buf = [0u8; MAX_REC_BYTES];
        let old_len = storage::get_into(ik.as_slice(), &mut old_buf).unwrap_or(0);
        if old_len < FIXED_REC_HDR {
            return Err(-23);
        }
        let mut orig_creator = [0u8; 20];
        orig_creator.copy_from_slice(&old_buf[57..77]);
        if caller != orig_creator && caller != admin {
            return Err(-22);
        }
        let orig_blk = u64::from_be_bytes([
            old_buf[97],
            old_buf[98],
            old_buf[99],
            old_buf[100],
            old_buf[101],
            old_buf[102],
            old_buf[103],
            old_buf[104],
        ]);
        let eff_id = if creator_identity != [0u8; 20] {
            creator_identity
        } else {
            let mut prev_id = [0u8; 20];
            prev_id.copy_from_slice(&old_buf[77..97]);
            prev_id
        };
        let n = pack_record(
            abi_ver,
            old_buf[4],
            &primary_addr,
            &actual_code_hash,
            &orig_creator,
            &eff_id,
            orig_blk,
            label,
            meta,
            &mut rec_buf,
        );
        storage::set(ik.as_slice(), &rec_buf[..n]);
        ret::write_u64_word(idx);
        return Ok(());
    }

    let ck = type_count_key(&type_id);
    let idx = storage::get_u64(ck.as_slice());
    storage::set_u64(ck.as_slice(), idx + 1);
    storage::set_u64(dk.as_slice(), idx + 1);

    let total = storage::get_u64(KEY_TOTAL_COUNT);
    storage::set_u64(KEY_TOTAL_COUNT, total + 1);

    let blk = context::block_number();
    let n = pack_record(
        abi_ver,
        STATUS_ACTIVE,
        &primary_addr,
        &actual_code_hash,
        &caller,
        &creator_identity,
        blk,
        label,
        meta,
        &mut rec_buf,
    );
    let ik = type_item_key(&type_id, idx);
    storage::set(ik.as_slice(), &rec_buf[..n]);

    let mut ev_data = [0u8; 40];
    ev_data[0..8].copy_from_slice(&idx.to_be_bytes());
    ev_data[8..40].copy_from_slice(&actual_code_hash);
    events::emit(
        &[
            EV_REGISTERED,
            type_id,
            addr_topic(&primary_addr),
            addr_topic(&creator_identity),
        ],
        &ev_data,
    );

    ret::write_u64_word(idx);
    Ok(())
}

fn handle_set_instance_status(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-11);
    }
    let type_id = args.bytes32(0).ok_or(-1)?;
    let idx = args.u64(1).ok_or(-1)?;
    let next_status = args.u64(2).ok_or(-1)?;
    if next_status != (STATUS_ACTIVE as u64) && next_status != (STATUS_ARCHIVED as u64) {
        return Err(-17);
    }

    let ik = type_item_key(&type_id, idx);
    let mut rec_buf = [0u8; MAX_REC_BYTES];
    let n = storage::get_into(ik.as_slice(), &mut rec_buf).unwrap_or(0);
    if n < FIXED_REC_HDR {
        return Err(-18);
    }

    let caller = context::msg_sender();
    let admin = get_admin();
    let mut orig_creator = [0u8; 20];
    orig_creator.copy_from_slice(&rec_buf[57..77]);
    if caller != orig_creator && caller != admin {
        return Err(-12);
    }

    rec_buf[4] = next_status as u8;
    storage::set(ik.as_slice(), &rec_buf[..n]);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&idx.to_be_bytes());
    ev[8..16].copy_from_slice(&next_status.to_be_bytes());
    events::emit(&[EV_STATUS_CHANGED, type_id], &ev);
    Ok(())
}

/// Returns compact binary slice:
/// - `[0..8]`: `total_count` (`u64` BE)
/// - `[8..16]`: `returned_count` (`u64` BE)
/// - Repeated `returned_count` times:
///   `[entry_idx: u64 BE (8B)][raw_record (109 + lbl_len + meta_len bytes)]`
fn handle_get_instances_by_type(args: &CalldataReader) -> Result<(), i32> {
    let type_id = args.bytes32(0).ok_or(-1)?;
    let offset = args.u64(1).ok_or(-1)?;
    let limit = args.u64(2).ok_or(-1)?.min(MAX_SLICE_LIMIT);

    let ck = type_count_key(&type_id);
    let total = storage::get_u64(ck.as_slice());

    let mut out = [0u8; SLICE_OUT_CAP];
    out[0..8].copy_from_slice(&total.to_be_bytes());

    let mut pos = 16usize;
    let mut returned = 0u64;
    let mut i = offset;
    let end = offset.saturating_add(limit).min(total);
    let mut item_buf = [0u8; MAX_REC_BYTES];

    while i < end {
        let ik = type_item_key(&type_id, i);
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

fn handle_get_type_count(args: &CalldataReader) -> Result<(), i32> {
    let type_id = args.bytes32(0).ok_or(-1)?;
    let ck = type_count_key(&type_id);
    ret::write_u64_word(storage::get_u64(ck.as_slice()));
    Ok(())
}

fn handle_total_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_COUNT));
    Ok(())
}

fn handle_allowed_abi_version(args: &CalldataReader) -> Result<(), i32> {
    let type_id = args.bytes32(0).ok_or(-1)?;
    let code_hash = args.bytes32(1).ok_or(-1)?;
    let allow_k = type_code_key(&type_id, &code_hash);
    ret::write_u64_word(storage::get_u64(allow_k.as_slice()));
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

    fn pad_type(name: &[u8]) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..name.len()].copy_from_slice(name);
        b
    }

    fn encode_register(
        type_id: &[u8; 32],
        primary: &[u8; 20],
        creator_id: &[u8; 20],
        label: &[u8],
        meta: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&selector(
            "registerInstance(bytes32,address,address,string,bytes)",
        ));
        v.extend_from_slice(type_id);
        let mut w1 = [0u8; 32];
        w1[12..32].copy_from_slice(primary);
        v.extend_from_slice(&w1);
        let mut w2 = [0u8; 32];
        w2[12..32].copy_from_slice(creator_id);
        v.extend_from_slice(&w2);

        let off_lbl: u64 = 5 * 32;
        let lbl_pad = (32 - (label.len() % 32)) % 32;
        let off_meta: u64 = off_lbl + 32 + (label.len() as u64) + (lbl_pad as u64);

        let mut w3 = [0u8; 32];
        w3[24..32].copy_from_slice(&off_lbl.to_be_bytes());
        v.extend_from_slice(&w3);

        let mut w4 = [0u8; 32];
        w4[24..32].copy_from_slice(&off_meta.to_be_bytes());
        v.extend_from_slice(&w4);

        let mut l_len = [0u8; 32];
        l_len[24..32].copy_from_slice(&(label.len() as u64).to_be_bytes());
        v.extend_from_slice(&l_len);
        v.extend_from_slice(label);
        v.extend(std::iter::repeat(0u8).take(lbl_pad));

        let meta_pad = (32 - (meta.len() % 32)) % 32;
        let mut m_len = [0u8; 32];
        m_len[24..32].copy_from_slice(&(meta.len() as u64).to_be_bytes());
        v.extend_from_slice(&m_len);
        v.extend_from_slice(meta);
        v.extend(std::iter::repeat(0u8).take(meta_pad));
        v
    }

    #[test]
    fn verifies_code_hash_and_slices_instances_by_type() {
        mock::reset();
        let reg_addr = [0xAA; 20];
        let admin = [0x01; 20];
        let user = [0x02; 20];
        let user_id = [0x12; 20];
        let dex1 = [0xD1; 20];
        let dex2 = [0xD2; 20];
        let fake_contract = [0xFF; 20];

        let dex_code_hash = [0x77; 32];
        let wrong_code_hash = [0x88; 32];

        mock::register_hps_with_code_hash(reg_addr, [0x99; 32], dispatch_calldata);
        mock::register_hps_with_code_hash(dex1, dex_code_hash, dispatch_calldata);
        mock::register_hps_with_code_hash(dex2, dex_code_hash, dispatch_calldata);
        mock::register_hps_with_code_hash(fake_contract, wrong_code_hash, dispatch_calldata);
        mock::set_block_number(34_500);

        // Initialize
        let init_cd = CallEncoder::<128>::new(selector("initialize(address)")).push_address(&admin);
        assert!(mock::transact_as(admin, reg_addr, init_cd.as_slice()).is_ok());

        // Approve DEX_CLOB code_hash (abi_version = 1)
        let t_dex = pad_type(b"DEX_CLOB");
        let allow_cd =
            CallEncoder::<192>::new(selector("setTypeCodeHash(bytes32,bytes32,uint64,bool)"))
                .push_bytes32(&t_dex)
                .push_bytes32(&dex_code_hash)
                .push_u64(1)
                .push_bool(true);
        assert!(mock::transact_as(admin, reg_addr, allow_cd.as_slice()).is_ok());

        // Rejects contract with wrong WASM code_hash (-21) and raw EOA (-20)
        let bad_cd = encode_register(&t_dex, &fake_contract, &user_id, b"Spoofed DEX", b"{}");
        assert_eq!(mock::transact_as(user, reg_addr, &bad_cd), Err(-21));
        let eoa_cd = encode_register(&t_dex, &[0x55; 20], &user_id, b"EOA DEX", b"{}");
        assert_eq!(mock::transact_as(user, reg_addr, &eoa_cd), Err(-20));

        // Registers two valid DEX_CLOB instances
        let reg1 = encode_register(
            &t_dex,
            &dex1,
            &user_id,
            b"SLX-EQ / SGD-FIAT CLOB",
            br#"{"pair":"SLX-EQ/SGD"}"#,
        );
        let reg2 = encode_register(
            &t_dex,
            &dex2,
            &user_id,
            b"SLX-TECH / SGD-FIAT CLOB",
            br#"{"pair":"SLX-TECH/SGD"}"#,
        );
        assert!(mock::transact_as(user, reg_addr, &reg1).is_ok());
        assert!(mock::transact_as(user, reg_addr, &reg2).is_ok());

        // Slice query returns both in 1 binary payload
        let q_cd =
            CallEncoder::<160>::new(selector("getInstancesByType(bytes32,uint64,uint64)"))
                .push_bytes32(&t_dex)
                .push_u64(0)
                .push_u64(20);
        let raw = mock::transact_as(user, reg_addr, q_cd.as_slice()).unwrap();
        let total = u64::from_be_bytes(raw[0..8].try_into().unwrap());
        let returned = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        assert_eq!(total, 2);
        assert_eq!(returned, 2);
        assert_eq!(&raw[16 + 8 + 5..16 + 8 + 25], &dex1);
    }

    #[test]
    fn casts_sovereign_superlexicon_charter_in_stone_and_blocks_imposters() {
        mock::reset();
        let reg_addr = [0xAA; 20];
        let admin = [0x01; 20];
        let attacker = [0x09; 20];
        let attacker_id = [0x19; 20];
        let slx_charter = [0x51; 20];
        let imposter_charter = [0x99; 20];
        let legit_charter = [0x88; 20];
        let charter_ch = [0xCC; 32];

        mock::register_hps_with_code_hash(reg_addr, [0x99; 32], dispatch_calldata);
        mock::register_hps_with_code_hash(slx_charter, charter_ch, dispatch_calldata);
        mock::register_hps_with_code_hash(imposter_charter, charter_ch, dispatch_calldata);
        mock::register_hps_with_code_hash(legit_charter, charter_ch, dispatch_calldata);

        let init_cd = CallEncoder::<64>::new(selector("initialize(address)")).push_address(&admin);
        assert!(mock::transact_as(admin, reg_addr, init_cd.as_slice()).is_ok());

        let t_chr = pad_type(b"CORPORATE_CHARTER");

        // Before sovereign charter is pinned, nobody can claim Superlexicon name
        let imp1 = encode_register(
            &t_chr,
            &imposter_charter,
            &attacker_id,
            b"Superlexicon Pte. Ltd.",
            b"{}",
        );
        assert_eq!(
            mock::transact_as(attacker, reg_addr, &imp1),
            Err(ERR_RESERVED_SUPERLEXICON_NAME)
        );

        // Pin sovereign Superlexicon charter (write-once!)
        let pin_cd = CallEncoder::<64>::new(selector("pinSovereignCharter(address)"))
            .push_address(&slx_charter);
        assert_eq!(mock::transact_as(attacker, reg_addr, pin_cd.as_slice()), Err(-12));
        assert!(mock::transact_as(admin, reg_addr, pin_cd.as_slice()).is_ok());

        // Attempting to overwrite cast-in-stone sovereign charter fails even for admin!
        let pin2_cd = CallEncoder::<64>::new(selector("pinSovereignCharter(address)"))
            .push_address(&imposter_charter);
        assert_eq!(
            mock::transact_as(admin, reg_addr, pin2_cd.as_slice()),
            Err(ERR_SOVEREIGN_ALREADY_PINNED)
        );

        // Canonical Superlexicon charter registers cleanly
        let ok_slx = encode_register(
            &t_chr,
            &slx_charter,
            &[0x11; 20],
            b"Superlexicon Pte. Ltd.",
            br#"{"jurisdiction":"SG"}"#,
        );
        assert!(mock::transact_as(attacker, reg_addr, &ok_slx).is_ok());

        // Confusable/homoglyph/typosquatted imposter charters are ALL blocked!
        for spoof in [
            "SuperLexicon Labs Inc.",
            "Super1exic0n Pte Ltd",
            "Ѕupеrlехісоn SG",
            "Super-Lexcon Corp",
        ] {
            let bad = encode_register(
                &t_chr,
                &imposter_charter,
                &attacker_id,
                spoof.as_bytes(),
                b"{}",
            );
            assert_eq!(
                mock::transact_as(attacker, reg_addr, &bad),
                Err(ERR_RESERVED_SUPERLEXICON_NAME)
            );
        }

        // Unrelated legitimate company registers cleanly
        let ok_legit = encode_register(
            &t_chr,
            &legit_charter,
            &attacker_id,
            b"Merlion Robotics Pte. Ltd.",
            b"{}",
        );
        assert!(mock::transact_as(attacker, reg_addr, &ok_legit).is_ok());
    }
}
