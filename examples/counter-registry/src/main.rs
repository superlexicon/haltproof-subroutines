//! Reference Lexicon WASM **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Supported ABI methods:
//! - `increment(bytes32,uint64)` -> increments a named counter, records `msg.sender` + `block.number`, emits `CountUpdated`
//! - `getCount(bytes32)`         -> returns 32-byte ABI uint256 word via `eth_call`
//! - `setNote(bytes32,string)`   -> stores an arbitrary UTF-8 note under `key` and emits `NoteUpdated`
//! - `getNote(bytes32)`          -> returns ABI-encoded dynamic `string`/`bytes` via `eth_call`
//! - `getLastBlock(bytes32)`     -> returns the block height at which `key` was last updated

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const COUNT_UPDATED: [u8; 32] = event_topic("CountUpdated(bytes32,address,uint64)");
const NOTE_UPDATED: [u8; 32] = event_topic("NoteUpdated(bytes32,address,uint64)");

hps_entry! {
    "increment(bytes32,uint64)" => handle_increment,
    "getCount(bytes32)"         => handle_get_count,
    "setNote(bytes32,string)"   => handle_set_note,
    "getNote(bytes32)"          => handle_get_note,
    "getLastBlock(bytes32)"     => handle_get_last_block,
}

fn handle_increment(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let delta = args.u64(1).ok_or(-3)?;
    let sender = context::msg_sender();
    let block = context::block_number();

    let cnt_key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    let blk_key = KeyBuilder::<64>::new().push(b"blk:").push(&bucket);

    let next = storage::get_u64(cnt_key.as_slice()).saturating_add(delta);
    storage::set_u64(cnt_key.as_slice(), next);
    storage::set_u64(blk_key.as_slice(), block);

    let mut log_data = [0u8; 36];
    log_data[0..20].copy_from_slice(&sender);
    log_data[20..28].copy_from_slice(&next.to_be_bytes());
    log_data[28..36].copy_from_slice(&block.to_be_bytes());
    events::emit(&[COUNT_UPDATED, bucket], &log_data);

    ret::write_u64_word(next);
    Ok(())
}

fn handle_get_count(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let cnt_key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    ret::write_u64_word(storage::get_u64(cnt_key.as_slice()));
    Ok(())
}

fn handle_set_note(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let note = args.dynamic_bytes(1).ok_or(-3)?;
    if note.len() > 8192 {
        return Err(-4);
    }

    let sender = context::msg_sender();
    let block = context::block_number();

    let note_key = KeyBuilder::<64>::new().push(b"note:").push(&bucket);
    let blk_key = KeyBuilder::<64>::new().push(b"blk:").push(&bucket);
    storage::set(note_key.as_slice(), note);
    storage::set_u64(blk_key.as_slice(), block);

    let mut log_data = [0u8; 28];
    log_data[0..20].copy_from_slice(&sender);
    log_data[20..28].copy_from_slice(&block.to_be_bytes());
    events::emit(&[NOTE_UPDATED, bucket], &log_data);

    Ok(())
}

fn handle_get_note(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let note_key = KeyBuilder::<64>::new().push(b"note:").push(&bucket);
    match storage::get_ref(note_key.as_slice()) {
        Some(bytes) => ret::write_abi_bytes(bytes),
        None => ret::write_abi_bytes(&[]),
    }
    Ok(())
}

fn handle_get_last_block(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let blk_key = KeyBuilder::<64>::new().push(b"blk:").push(&bucket);
    ret::write_u64_word(storage::get_u64(blk_key.as_slice()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::{mock, selector};

    #[test]
    fn counter_and_notes_work_in_native_unit_tests() {
        mock::reset();
        mock::set_sender([0x42; 20]);
        mock::set_block_number(12);

        let key = [0xAB; 32];
        // increment(key, 15)
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector("increment(bytes32,uint64)"));
        cd.extend_from_slice(&key);
        let mut delta = [0u8; 32];
        delta[24..32].copy_from_slice(&15u64.to_be_bytes());
        cd.extend_from_slice(&delta);
        assert_eq!(dispatch_calldata(&cd), 0);

        // getCount(key) -> 15
        let mut q = Vec::new();
        q.extend_from_slice(&selector("getCount(bytes32)"));
        q.extend_from_slice(&key);
        assert_eq!(dispatch_calldata(&q), 0);
        let ret_bytes = mock::take_return_data();
        assert_eq!(&ret_bytes[24..32], &15u64.to_be_bytes());

        // setNote(key, "hello haltproof subroutine")
        let msg = b"hello haltproof subroutine";
        let mut note_cd = Vec::new();
        note_cd.extend_from_slice(&selector("setNote(bytes32,string)"));
        note_cd.extend_from_slice(&key);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        note_cd.extend_from_slice(&off);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(msg.len() as u64).to_be_bytes());
        note_cd.extend_from_slice(&lw);
        note_cd.extend_from_slice(msg);
        note_cd.resize(note_cd.len() + (32 - msg.len() % 32) % 32, 0);
        assert_eq!(dispatch_calldata(&note_cd), 0);

        // getNote(key) -> ABI string "hello haltproof subroutine"
        let mut gn = Vec::new();
        gn.extend_from_slice(&selector("getNote(bytes32)"));
        gn.extend_from_slice(&key);
        assert_eq!(dispatch_calldata(&gn), 0);
        let note_out = mock::take_return_data();
        assert_eq!(&note_out[64..64 + msg.len()], msg);
    }
}
