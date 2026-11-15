//! High-TPS Channel Messaging **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! 100% ABI-, storage-key-, event-, and return-payload-compatible with Lexicon's
//! maximum-TPS benchmark contract (`contracts/messaging-wasm` / `tx-load-sim` / `message-testor`).
//!
//! Supported ABI methods:
//! - `postMessage(bytes32 channelHash, bytes message)` (`0x482f63b0`)
//! - `getMessages(bytes32 channelHash, uint64 blockNumber)` (`0xa8c9582d`)
//!
//! Emitted Event:
//! - `MessagePosted(bytes32,uint64,address,bytes)`
//!   - `topics`: `[MESSAGE_POSTED, channelHash]`
//!   - `data`:   `blockNumber (u64 BE, 8 B) ++ sender (20 B) ++ message`

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const MESSAGE_POSTED: [u8; 32] = event_topic("MessagePosted(bytes32,uint64,address,bytes)");
const MAX_MSG_LEN: usize = 16 * 1024;
const MAX_GROUP_RETURN_BYTES: usize = 32 * 1024;

hps_entry! {
    "postMessage(bytes32,bytes)"      => handle_post_message,
    "getMessages(bytes32,uint64)"     => handle_get_messages,
}

/// `"blk:" + channel(32) + block(u64 BE)` -> `u64 LE` message count in `(channel, block)`.
fn group_count_key(channel: &[u8; 32], block: u64) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"blk:")
        .push(channel)
        .push_u64_be(block)
}

/// `"pm:" + channel(32) + block(u64 BE) + seq(u64 LE)` -> `sender(20) ++ message`.
fn group_msg_key(channel: &[u8; 32], block: u64, seq: u64) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"pm:")
        .push(channel)
        .push_u64_be(block)
        .push_u64_le(seq)
}

/// `"cb:" + channel(32) + idx(u64 LE)` -> `block(u64 BE)`.
fn channel_block_key(channel: &[u8; 32], idx: u64) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"cb:")
        .push(channel)
        .push_u64_le(idx)
}

/// `"cc:" + channel(32)` -> `u64 LE` distinct block count for `channel`.
fn channel_block_count_key(channel: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"cc:").push(channel)
}

fn handle_post_message(args: &CalldataReader) -> Result<(), i32> {
    let channel = args.bytes32(0).ok_or(-3)?;
    let msg = args.dynamic_bytes(1).ok_or(-1)?;
    if msg.len() > MAX_MSG_LEN {
        return Err(-1);
    }

    let sender = context::msg_sender();
    let block_number = context::block_number();

    // 1. Append `sender(20) ++ msg` at `(channel, block_number, group_seq)`.
    let gk = group_count_key(&channel, block_number);
    let group_seq = storage::get_u64(gk.as_slice());

    let mut stored_val = [0u8; 20 + MAX_MSG_LEN];
    stored_val[0..20].copy_from_slice(&sender);
    stored_val[20..20 + msg.len()].copy_from_slice(msg);

    let mk = group_msg_key(&channel, block_number, group_seq);
    storage::set(mk.as_slice(), &stored_val[..20 + msg.len()]);

    // 2. Advance per-block group message count.
    storage::set_u64(gk.as_slice(), group_seq + 1);

    // 3. First message in this block for `channel` -> record `block_number` in channel's block list.
    if group_seq == 0 {
        let cck = channel_block_count_key(&channel);
        let blocks = storage::get_u64(cck.as_slice());
        let cbk = channel_block_key(&channel, blocks);
        storage::set(cbk.as_slice(), &block_number.to_be_bytes());
        storage::set_u64(cck.as_slice(), blocks + 1);
    }

    // 4. Emit `MessagePosted`: topics = [MESSAGE_POSTED, channel], data = block(8 BE) ++ sender(20) ++ msg.
    let mut ev_data = [0u8; 28 + MAX_MSG_LEN];
    ev_data[0..8].copy_from_slice(&block_number.to_be_bytes());
    ev_data[8..28].copy_from_slice(&sender);
    ev_data[28..28 + msg.len()].copy_from_slice(msg);
    events::emit(&[MESSAGE_POSTED, channel], &ev_data[..28 + msg.len()]);

    Ok(())
}

fn handle_get_messages(args: &CalldataReader) -> Result<i32, i32> {
    let channel = args.bytes32(0).ok_or(-1)?;
    let block_number = args.u64(1).ok_or(-1)?;

    let gk = group_count_key(&channel, block_number);
    let count = storage::get_u64(gk.as_slice());

    // Frame: `[u64 LE count][per msg: sender(20) ++ u64 LE len ++ bytes]`
    let mut out = [0u8; MAX_GROUP_RETURN_BYTES];
    out[0..8].copy_from_slice(&count.to_le_bytes());
    let mut pos: usize = 8;

    let mut i = 0u64;
    while i < count {
        let mk = group_msg_key(&channel, block_number, i);
        let Some(entry) = storage::get_ref(mk.as_slice()) else {
            return Err(-1);
        };
        if entry.len() < 20 {
            return Err(-1);
        }
        let msg_len = entry.len() - 20;
        if pos + 28 + msg_len > MAX_GROUP_RETURN_BYTES {
            return Err(-1);
        }
        out[pos..pos + 20].copy_from_slice(&entry[0..20]);
        pos += 20;
        out[pos..pos + 8].copy_from_slice(&(msg_len as u64).to_le_bytes());
        pos += 8;
        out[pos..pos + msg_len].copy_from_slice(&entry[20..]);
        pos += msg_len;
        i += 1;
    }

    ret::write(&out[..pos]);
    Ok(count as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::{mock, selector};

    fn encode_post(channel: [u8; 32], msg: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("postMessage(bytes32,bytes)") });
        cd.extend_from_slice(&channel);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        cd.extend_from_slice(&off);
        let mut len_w = [0u8; 32];
        len_w[24..32].copy_from_slice(&(msg.len() as u64).to_be_bytes());
        cd.extend_from_slice(&len_w);
        cd.extend_from_slice(msg);
        let pad = (32 - msg.len() % 32) % 32;
        cd.resize(cd.len() + pad, 0);
        cd
    }

    fn encode_get(channel: [u8; 32], block: u64) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("getMessages(bytes32,uint64)") });
        cd.extend_from_slice(&channel);
        let mut bw = [0u8; 32];
        bw[24..32].copy_from_slice(&block.to_be_bytes());
        cd.extend_from_slice(&bw);
        cd
    }

    #[test]
    fn matches_lexicon_messaging_wasm_wire_format() {
        mock::reset();
        let ch = [0xC0u8; 32];
        let alice = [0xAAu8; 20];
        let bob = [0xBBu8; 20];

        mock::set_block_number(100);
        mock::set_sender(alice);
        assert_eq!(dispatch_calldata(&encode_post(ch, b"msg 0")), 0);

        mock::set_sender(bob);
        assert_eq!(dispatch_calldata(&encode_post(ch, b"second in b100")), 0);

        let evs = mock::events();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].topics[0][0..4], [0xb9, 0x3e, 0x3e, 0x01]);
        assert_eq!(evs[0].topics[1], ch);
        assert_eq!(&evs[0].data[0..8], &100u64.to_be_bytes());
        assert_eq!(&evs[0].data[8..28], &alice);
        assert_eq!(&evs[0].data[28..], b"msg 0");

        let count_ret = dispatch_calldata(&encode_get(ch, 100));
        assert_eq!(count_ret, 2);
        let data = mock::take_return_data();
        assert_eq!(&data[0..8], &2u64.to_le_bytes());
        assert_eq!(&data[8..28], &alice);
        assert_eq!(&data[28..36], &5u64.to_le_bytes());
        assert_eq!(&data[36..41], b"msg 0");
        assert_eq!(&data[41..61], &bob);
        assert_eq!(&data[61..69], &14u64.to_le_bytes());
        assert_eq!(&data[69..83], b"second in b100");
    }
}
