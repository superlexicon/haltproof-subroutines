//! High-TPS Channel & Protected Social Messaging **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! - **100% ABI-, storage-key-, event-, and return-payload-compatible** with Lexicon's
//!   maximum-TPS benchmark contract (`contracts/messaging-wasm` / `tx-load-sim` / `message-testor`):
//!   - `postMessage(bytes32 channelHash, bytes message)` (`0x482f63b0`)
//!   - `getMessages(bytes32 channelHash, uint64 blockNumber)` (`0xa8c9582d`)
//! - **Extended Composable Social Channel Primitives** for modular `SocialCharter` subroutines
//!   (`SocialFeed`, `SocialEvents`, `SocialMarketplace`):
//!   - `bindChannelController(bytes32 channelHash, address controllerHps)`: Locks `channelHash`
//!     writes exclusively to an authorized Social Module HPS (`ERR_CHANNEL_PROTECTED = -31`),
//!     preventing raw callers from bypassing radio-proximity or friendship checks.
//!   - `postAttributedMessage(bytes32 channelHash, address author, bytes message)`: Allows the bound
//!     `controllerHps` (or `author == msg.sender` on open channels) to append attributed messages
//!     preserving the original end-user `author` address across `host_call_contract`.
//!   - `getRecentMessages(bytes32 channelHash, uint64 maxMessages)`: Reads up to `maxMessages` most
//!     recent messages across blocks in a single call (`[u32 LE count][block(u64 LE) ++ author(20) ++ len(u16 LE) ++ bytes]*`).
//!   - `channelController(bytes32 channelHash)` -> `address`

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const MESSAGE_POSTED: [u8; 32] = event_topic("MessagePosted(bytes32,uint64,address,bytes)");
const CHANNEL_CONTROLLER_BOUND: [u8; 32] =
    event_topic("ChannelControllerBound(bytes32,address)");

const MAX_MSG_LEN: usize = 16 * 1024;
const MAX_GROUP_RETURN_BYTES: usize = 32 * 1024;
const MAX_RECENT_RETURN_BYTES: usize = 24 * 1024;

pub const ERR_CHANNEL_PROTECTED: i32 = -31;
pub const ERR_CONTROLLER_ALREADY_BOUND: i32 = -32;

static mut OUT_SCRATCH: [u8; MAX_GROUP_RETURN_BYTES] = [0u8; MAX_GROUP_RETURN_BYTES];

hps_entry! {
    "postMessage(bytes32,bytes)"                        => handle_post_message,
    "getMessages(bytes32,uint64)"                       => handle_get_messages,
    "bindChannelController(bytes32,address)"            => handle_bind_controller,
    "postAttributedMessage(bytes32,address,bytes)"      => handle_post_attributed,
    "getRecentMessages(bytes32,uint64)"                 => handle_get_recent_messages,
    "channelController(bytes32)"                        => handle_channel_controller,
}

/// `"blk:" + channel(32) + block(u64 BE)` -> `u64 LE` message count in `(channel, block)`.
fn group_count_key(channel: &[u8; 32], block: u64) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"blk:")
        .push(channel)
        .push_u64_be(block)
}

/// `"pm:" + channel(32) + block(u64 BE) + seq(u64 LE)` -> `author(20) ++ message`.
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

/// `"ctl:" + channel(32)` -> `controller(20)` if channel is protected by a Social Module HPS.
fn channel_controller_key(channel: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"ctl:").push(channel)
}

fn append_message_internal(
    channel: &[u8; 32],
    author: &[u8; 20],
    msg: &[u8],
) -> Result<(), i32> {
    if msg.len() > MAX_MSG_LEN {
        return Err(-1);
    }
    let block_number = context::block_number();

    // 1. Append `author(20) ++ msg` at `(channel, block_number, group_seq)`.
    let gk = group_count_key(channel, block_number);
    let group_seq = storage::get_u64(gk.as_slice());

    let mut stored_val = [0u8; 20 + MAX_MSG_LEN];
    stored_val[0..20].copy_from_slice(author);
    stored_val[20..20 + msg.len()].copy_from_slice(msg);

    let mk = group_msg_key(channel, block_number, group_seq);
    storage::set(mk.as_slice(), &stored_val[..20 + msg.len()]);

    // 2. Advance per-block group message count.
    storage::set_u64(gk.as_slice(), group_seq + 1);

    // 3. First message in this block for `channel` -> record `block_number` in channel's block list.
    if group_seq == 0 {
        let cck = channel_block_count_key(channel);
        let blocks = storage::get_u64(cck.as_slice());
        let cbk = channel_block_key(channel, blocks);
        storage::set(cbk.as_slice(), &block_number.to_be_bytes());
        storage::set_u64(cck.as_slice(), blocks + 1);
    }

    // 4. Emit `MessagePosted`: topics = [MESSAGE_POSTED, channel], data = block(8 BE) ++ author(20) ++ msg.
    let mut ev_data = [0u8; 28 + MAX_MSG_LEN];
    ev_data[0..8].copy_from_slice(&block_number.to_be_bytes());
    ev_data[8..28].copy_from_slice(author);
    ev_data[28..28 + msg.len()].copy_from_slice(msg);
    events::emit(&[MESSAGE_POSTED, *channel], &ev_data[..28 + msg.len()]);

    Ok(())
}

fn handle_post_message(args: &CalldataReader) -> Result<(), i32> {
    let channel = args.bytes32(0).ok_or(-3)?;
    let msg = args.dynamic_bytes(1).ok_or(-1)?;
    let sender = context::msg_sender();

    // If channel is bound to a Social Module controller, raw external writes are blocked!
    let ck = channel_controller_key(&channel);
    if let Some(ctl) = storage::get_address(ck.as_slice()) {
        if ctl != [0u8; 20] && ctl != sender {
            return Err(ERR_CHANNEL_PROTECTED);
        }
    }

    append_message_internal(&channel, &sender, msg)
}

fn handle_bind_controller(args: &CalldataReader) -> Result<(), i32> {
    let channel = args.bytes32(0).ok_or(-1)?;
    let new_ctl = args.address(1).ok_or(-1)?;
    if new_ctl == [0u8; 20] {
        return Err(-1);
    }

    let sender = context::msg_sender();
    let ck = channel_controller_key(&channel);
    if let Some(existing) = storage::get_address(ck.as_slice()) {
        if existing != [0u8; 20] && existing != sender {
            return Err(ERR_CONTROLLER_ALREADY_BOUND);
        }
    } else if sender != new_ctl {
        // Initial bind must be performed by the controller module itself!
        return Err(ERR_CHANNEL_PROTECTED);
    }

    storage::set_address(ck.as_slice(), &new_ctl);
    events::emit(&[CHANNEL_CONTROLLER_BOUND, channel], &new_ctl);
    Ok(())
}

fn handle_post_attributed(args: &CalldataReader) -> Result<(), i32> {
    let channel = args.bytes32(0).ok_or(-3)?;
    let author = args.address(1).ok_or(-2)?;
    let msg = args.dynamic_bytes(2).ok_or(-1)?;
    let sender = context::msg_sender();

    let ck = channel_controller_key(&channel);
    if let Some(ctl) = storage::get_address(ck.as_slice()) {
        if ctl != [0u8; 20] {
            if sender != ctl {
                return Err(ERR_CHANNEL_PROTECTED);
            }
        } else if sender != author {
            return Err(ERR_CHANNEL_PROTECTED);
        }
    } else if sender != author {
        // Auto-bind to `sender` module on first attributed write when unbound?
        // Even safer: require `bindChannelController` first whenever `sender != author`!
        return Err(ERR_CHANNEL_PROTECTED);
    }

    append_message_internal(&channel, &author, msg)
}

fn handle_channel_controller(args: &CalldataReader) -> Result<(), i32> {
    let channel = args.bytes32(0).ok_or(-1)?;
    let ck = channel_controller_key(&channel);
    let ctl = storage::get_address(ck.as_slice()).unwrap_or([0u8; 20]);
    ret::write_address(&ctl);
    Ok(())
}

fn handle_get_messages(args: &CalldataReader) -> Result<i32, i32> {
    let channel = args.bytes32(0).ok_or(-1)?;
    let block_number = args.u64(1).ok_or(-1)?;

    let gk = group_count_key(&channel, block_number);
    let count = storage::get_u64(gk.as_slice());

    unsafe {
        // Frame: `[u64 LE count][per msg: sender(20) ++ u64 LE len ++ bytes]`
        let out = &mut *core::ptr::addr_of_mut!(OUT_SCRATCH);
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
    }
    Ok(count as i32)
}

fn handle_get_recent_messages(args: &CalldataReader) -> Result<i32, i32> {
    let channel = args.bytes32(0).ok_or(-1)?;
    let max_messages = args.u64(1).ok_or(-1)?.min(64) as usize;

    let cck = channel_block_count_key(&channel);
    let distinct_blocks = storage::get_u64(cck.as_slice());

    unsafe {
        // Frame: `[u32 LE count][newest-first: block(u64 LE) ++ author(20) ++ len(u16 LE) ++ bytes]`
        let out = &mut *core::ptr::addr_of_mut!(OUT_SCRATCH);
        let mut written: u32 = 0;
        let mut pos: usize = 4;

        let mut b_idx = distinct_blocks;
        while b_idx > 0 && (written as usize) < max_messages {
            b_idx -= 1;
            let cbk = channel_block_key(&channel, b_idx);
            let mut bb = [0u8; 8];
            if storage::get_into(cbk.as_slice(), &mut bb) != Some(8) {
                continue;
            }
            let blk = u64::from_be_bytes(bb);
            let gk = group_count_key(&channel, blk);
            let cnt = storage::get_u64(gk.as_slice());

            let mut seq = cnt;
            while seq > 0 && (written as usize) < max_messages {
                seq -= 1;
                let mk = group_msg_key(&channel, blk, seq);
                let Some(entry) = storage::get_ref(mk.as_slice()) else {
                    continue;
                };
                if entry.len() < 20 {
                    continue;
                }
                let msg_len = (entry.len() - 20).min(u16::MAX as usize);
                if pos + 30 + msg_len > MAX_RECENT_RETURN_BYTES {
                    b_idx = 0;
                    break;
                }
                out[pos..pos + 8].copy_from_slice(&blk.to_le_bytes());
                out[pos + 8..pos + 28].copy_from_slice(&entry[0..20]);
                out[pos + 28..pos + 30].copy_from_slice(&(msg_len as u16).to_le_bytes());
                pos += 30;
                out[pos..pos + msg_len].copy_from_slice(&entry[20..20 + msg_len]);
                pos += msg_len;
                written += 1;
            }
        }

        out[0..4].copy_from_slice(&written.to_le_bytes());
        ret::write(&out[..pos]);
        Ok(written as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
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

    #[test]
    fn protected_social_channel_controller_and_recent_messages() {
        mock::reset();
        let msg_hps = [0x10; 20];
        let feed_mod = [0x20; 20];
        let alice = [0xAA; 20];
        let attacker = [0xEE; 20];
        let dm_ch = [0xD1; 32];

        mock::register_hps(msg_hps, dispatch_calldata);
        mock::set_block_number(200);

        // `feed_mod` binds `dm_ch` to itself
        mock::transact_as(
            feed_mod,
            msg_hps,
            CallEncoder::<128>::new(const { selector("bindChannelController(bytes32,address)") })
                .push_bytes32(&dm_ch)
                .push_address(&feed_mod)
                .as_slice(),
        )
        .expect("bind controller");

        // External attacker bypassing `feed_mod` via raw `postMessage` is blocked!
        assert_eq!(
            mock::transact_as(attacker, msg_hps, &encode_post(dm_ch, b"forged dm")).unwrap_err(),
            ERR_CHANNEL_PROTECTED
        );

        // `feed_mod` appends attributed message for `alice` on block 200 and block 205
        for (blk, text) in [(200u64, b"Hey neighbor!".as_slice()), (205u64, b"See you at Blk 29!".as_slice())] {
            mock::set_block_number(blk);
            mock::transact_as(
                feed_mod,
                msg_hps,
                CallEncoder::<256>::new(const {
                    selector("postAttributedMessage(bytes32,address,bytes)")
                })
                .push_bytes32(&dm_ch)
                .push_address(&alice)
                .push_u64(0x60)
                .push_dynamic_bytes_tail(text)
                .as_slice(),
            )
            .expect("attributed post");
        }

        let recent = mock::transact_as(
            alice,
            msg_hps,
            CallEncoder::<128>::new(const { selector("getRecentMessages(bytes32,uint64)") })
                .push_bytes32(&dm_ch)
                .push_u64(10)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u32::from_le_bytes([recent[0], recent[1], recent[2], recent[3]]), 2);
        // Newest message first (block 205)
        assert_eq!(
            u64::from_le_bytes(recent[4..12].try_into().unwrap()),
            205
        );
        assert_eq!(&recent[12..32], &alice);
    }
}
