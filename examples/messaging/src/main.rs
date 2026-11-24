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
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const MESSAGE_POSTED: [u8; 32] = event_topic("MessagePosted(bytes32,uint64,address,bytes)");
const CHANNEL_CONTROLLER_BOUND: [u8; 32] =
    event_topic("ChannelControllerBound(bytes32,address)");
const ECIES_CHANNEL_CREATED: [u8; 32] =
    event_topic("EciesChannelCreated(bytes32,bytes32,address)");
const TOPIC_CREATED: [u8; 32] =
    event_topic("TopicCreated(bytes32,uint64,address,string)");
const CHANNEL_KEY_ROTATED: [u8; 32] =
    event_topic("ChannelKeyRotated(bytes32,uint64,address,uint64)");
const CHANNEL_MEMBER_UPDATED: [u8; 32] =
    event_topic("ChannelMemberUpdated(bytes32,address,uint64,uint64)");
const TOPIC_MESSAGE_POSTED: [u8; 32] =
    event_topic("TopicMessagePosted(bytes32,uint64,uint64,address)");

const MAX_MSG_LEN: usize = 16 * 1024;
const MAX_GROUP_RETURN_BYTES: usize = 32 * 1024;
const MAX_RECENT_RETURN_BYTES: usize = 24 * 1024;

const MAX_CHAN_MEMBERS: usize = 16;
const MAX_CHAN_LABEL_LEN: usize = 48;
const MAX_TOPIC_TITLE_LEN: usize = 64;
const MAX_TOPICS_PER_CHANNEL: usize = 64;
const MAX_WRAP_LEN: usize = 160;
const MAX_ECIES_CT_LEN: usize = 4096;
const MAX_ID_CHANNELS: usize = 128;

const HFS_TYPE_ECIES_MESSAGING: [u8; 32] = *b"MESSAGING_ECIES\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

pub const ERR_CHANNEL_PROTECTED: i32 = -31;
pub const ERR_CONTROLLER_ALREADY_BOUND: i32 = -32;
pub const ERR_INVALID_ROSTER: i32 = -42;
pub const ERR_INVALID_EPOCH_WRAPS: i32 = -43;
pub const ERR_DUPLICATE_ROSTER_EXISTS: i32 = -44;
pub const ERR_NOT_CHANNEL_MEMBER: i32 = -45;
pub const ERR_REKEY_REQUIRED: i32 = -46;
pub const ERR_STALE_KEY_EPOCH: i32 = -47;

static mut OUT_SCRATCH: [u8; MAX_GROUP_RETURN_BYTES] = [0u8; MAX_GROUP_RETURN_BYTES];

hps_entry! {
    "postMessage(bytes32,bytes)"                                => handle_post_message,
    "getMessages(bytes32,uint64)"                               => handle_get_messages,
    "bindChannelController(bytes32,address)"                    => handle_bind_controller,
    "postAttributedMessage(bytes32,address,bytes)"              => handle_post_attributed,
    "getRecentMessages(bytes32,uint64)"                         => handle_get_recent_messages,
    "channelController(bytes32)"                                => handle_channel_controller,
    "openChannelOrTopic(bytes,string,string,bytes)"             => handle_open_channel_or_topic,
    "createTopic(bytes32,string)"                               => handle_create_topic,
    "rotateChannelKey(bytes32,bytes)"                           => handle_rotate_channel_key,
    "addChannelMember(bytes32,address,bytes)"                   => handle_add_channel_member,
    "removeChannelMember(bytes32,address,bytes)"                => handle_remove_channel_member,
    "leaveChannel(bytes32)"                                     => handle_leave_channel,
    "postTopicMessage(bytes32,uint64,uint64,bytes)"             => handle_post_topic_message,
    "rotateAndPostTopicMessage(bytes32,uint64,bytes,bytes)"     => handle_rotate_and_post_topic_message,
    "resolveChannelByRoster(bytes)"                             => handle_resolve_channel_by_roster,
    "getIdentityChannels(address)"                              => handle_get_identity_channels,
    "getChannelDetails(bytes32,address)"                        => handle_get_channel_details,
    "getTopicMessages(bytes32,uint64,uint64)"                  => handle_get_topic_messages,
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

// ============================================================================
// ECIES Multi-Topic Identity Channels & Rolling AES-256-GCM Key Epochs (v2)
// ============================================================================

const KEY_EC_SEQ: &[u8] = b"ec:seq";

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn has_deployed_wasm(addr: &[u8; 20]) -> bool {
    if *addr == [0u8; 20] {
        return false;
    }
    match context::code_hash_of(addr) {
        Some(h) => h != [0u8; 32],
        None => false,
    }
}

fn roster_pk_key(pk_hash: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"ec:rpk:").push(pk_hash)
}

fn roster_id_key(id_hash: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"ec:rid:").push(id_hash)
}

fn chan_hdr_key(cid: &[u8; 32]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"ec:ch:").push(cid)
}

fn chan_topic_key(cid: &[u8; 32], topic_id: usize) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"ec:tp:")
        .push(cid)
        .push_u64_be(topic_id as u64)
}

fn chan_wrap_key(cid: &[u8; 32], epoch: u32, member: &[u8; 20]) -> KeyBuilder<80> {
    KeyBuilder::<80>::new()
        .push(b"ec:wk:")
        .push(cid)
        .push_u64_be(epoch as u64)
        .push(member)
}

fn member_join_epoch_key(cid: &[u8; 32], member: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"ec:je:")
        .push(cid)
        .push(member)
}

fn id_chan_count_key(id_addr: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"ec:ic:").push(id_addr)
}

fn id_chan_item_key(id_addr: &[u8; 20], idx: usize) -> KeyBuilder<40> {
    KeyBuilder::<40>::new()
        .push(b"ec:ii:")
        .push(id_addr)
        .push_u64_be(idx as u64)
}

fn id_chan_seen_key(id_addr: &[u8; 20], cid: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"ec:is:")
        .push(id_addr)
        .push(cid)
}

fn topic_msg_key(cid: &[u8; 32], topic_id: usize, seq: u32) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"ec:tm:")
        .push(cid)
        .push_u64_be(topic_id as u64)
        .push_u64_be(seq as u64)
}

const FIXED_CHAN_HDR: usize = 1 + 1 + 1 + 4 + 8 + 8 + 20 + 32 + 32 + 1; // 108B
const MAX_CHAN_HDR_LEN: usize = FIXED_CHAN_HDR + MAX_CHAN_LABEL_LEN + MAX_CHAN_MEMBERS * 20;

struct EciesChannelHdr {
    rekey_required: u8,
    member_count: u8,
    topic_count: u8,
    current_epoch: u32,
    created_block: u64,
    last_block: u64,
    creator: [u8; 20],
    pk_roster_hash: [u8; 32],
    id_roster_hash: [u8; 32],
    label_len: u8,
    label: [u8; MAX_CHAN_LABEL_LEN],
    members: [[u8; 20]; MAX_CHAN_MEMBERS],
}

impl EciesChannelHdr {
    fn save(&self, cid: &[u8; 32]) {
        let mc = (self.member_count as usize).min(MAX_CHAN_MEMBERS);
        let ll = (self.label_len as usize).min(MAX_CHAN_LABEL_LEN);
        let mut b = [0u8; MAX_CHAN_HDR_LEN];
        b[0] = self.rekey_required;
        b[1] = mc as u8;
        b[2] = self.topic_count;
        b[3..7].copy_from_slice(&self.current_epoch.to_be_bytes());
        b[7..15].copy_from_slice(&self.created_block.to_be_bytes());
        b[15..23].copy_from_slice(&self.last_block.to_be_bytes());
        b[23..43].copy_from_slice(&self.creator);
        b[43..75].copy_from_slice(&self.pk_roster_hash);
        b[75..107].copy_from_slice(&self.id_roster_hash);
        b[107] = ll as u8;
        b[108..108 + ll].copy_from_slice(&self.label[..ll]);
        let mut pos = 108 + ll;
        let mut i = 0usize;
        while i < mc {
            b[pos..pos + 20].copy_from_slice(&self.members[i]);
            pos += 20;
            i += 1;
        }
        let k = chan_hdr_key(cid);
        storage::set(k.as_slice(), &b[..pos]);
    }

    fn load(cid: &[u8; 32]) -> Option<Self> {
        let k = chan_hdr_key(cid);
        let mut b = [0u8; MAX_CHAN_HDR_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < FIXED_CHAN_HDR {
            return None;
        }
        let rekey_required = b[0];
        let mc = (b[1] as usize).min(MAX_CHAN_MEMBERS);
        let topic_count = b[2];
        let current_epoch = u32::from_be_bytes([b[3], b[4], b[5], b[6]]);
        let created_block = u64::from_be_bytes([
            b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14],
        ]);
        let last_block = u64::from_be_bytes([
            b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22],
        ]);
        let mut creator = [0u8; 20];
        creator.copy_from_slice(&b[23..43]);
        let mut pk_roster_hash = [0u8; 32];
        pk_roster_hash.copy_from_slice(&b[43..75]);
        let mut id_roster_hash = [0u8; 32];
        id_roster_hash.copy_from_slice(&b[75..107]);
        let ll = (b[107] as usize).min(MAX_CHAN_LABEL_LEN);
        if n < 108 + ll + mc * 20 {
            return None;
        }
        let mut label = [0u8; MAX_CHAN_LABEL_LEN];
        label[..ll].copy_from_slice(&b[108..108 + ll]);
        let mut members = [[0u8; 20]; MAX_CHAN_MEMBERS];
        let mut pos = 108 + ll;
        let mut i = 0usize;
        while i < mc {
            members[i].copy_from_slice(&b[pos..pos + 20]);
            pos += 20;
            i += 1;
        }
        Some(Self {
            rekey_required,
            member_count: mc as u8,
            topic_count,
            current_epoch,
            created_block,
            last_block,
            creator,
            pk_roster_hash,
            id_roster_hash,
            label_len: ll as u8,
            label,
            members,
        })
    }

    fn has_member(&self, addr: &[u8; 20]) -> bool {
        let mc = self.member_count as usize;
        let mut i = 0usize;
        while i < mc {
            if self.members[i] == *addr {
                return true;
            }
            i += 1;
        }
        false
    }
}

const FIXED_TOPIC_HDR: usize = 4 + 8 + 8 + 20 + 1; // 41B
const MAX_TOPIC_REC_LEN: usize = FIXED_TOPIC_HDR + MAX_TOPIC_TITLE_LEN;

struct TopicRec {
    msg_count: u32,
    created_block: u64,
    last_block: u64,
    creator: [u8; 20],
    title_len: u8,
    title: [u8; MAX_TOPIC_TITLE_LEN],
}

impl TopicRec {
    fn save(&self, cid: &[u8; 32], topic_id: usize) {
        let tl = (self.title_len as usize).min(MAX_TOPIC_TITLE_LEN);
        let mut b = [0u8; MAX_TOPIC_REC_LEN];
        b[0..4].copy_from_slice(&self.msg_count.to_be_bytes());
        b[4..12].copy_from_slice(&self.created_block.to_be_bytes());
        b[12..20].copy_from_slice(&self.last_block.to_be_bytes());
        b[20..40].copy_from_slice(&self.creator);
        b[40] = tl as u8;
        b[41..41 + tl].copy_from_slice(&self.title[..tl]);
        let k = chan_topic_key(cid, topic_id);
        storage::set(k.as_slice(), &b[..41 + tl]);
    }

    fn load(cid: &[u8; 32], topic_id: usize) -> Option<Self> {
        let k = chan_topic_key(cid, topic_id);
        let mut b = [0u8; MAX_TOPIC_REC_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < FIXED_TOPIC_HDR {
            return None;
        }
        let msg_count = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let created_block =
            u64::from_be_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]);
        let last_block =
            u64::from_be_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
        let mut creator = [0u8; 20];
        creator.copy_from_slice(&b[20..40]);
        let tl = (b[40] as usize)
            .min(MAX_TOPIC_TITLE_LEN)
            .min(n.saturating_sub(FIXED_TOPIC_HDR));
        let mut title = [0u8; MAX_TOPIC_TITLE_LEN];
        title[..tl].copy_from_slice(&b[41..41 + tl]);
        Some(Self {
            msg_count,
            created_block,
            last_block,
            creator,
            title_len: tl as u8,
            title,
        })
    }
}

fn fetch_member_secp_slot(member: &[u8; 20]) -> [u8; 64] {
    if has_deployed_wasm(member) {
        let q = CallEncoder::<16>::new(const { selector("secp256k1PubKey()") });
        if let Ok(raw) = call::call_raw(member, q.as_slice()) {
            if raw.len() >= 64 && raw[0..64].iter().any(|&x| x != 0) {
                let mut pk = [0u8; 64];
                pk.copy_from_slice(&raw[0..64]);
                return pk;
            }
        }
    }
    let mut fallback = [0u8; 64];
    fallback[44..64].copy_from_slice(member);
    fallback
}

/// Parses `members_packed` (`20 * M` bytes, `2 <= M <= 16`), sorts canonically, queries each
/// Identity's `secp256k1PubKey()`, and hashes the concatenated sorted public keys (`pkRosterHash`)
/// + sorted Identity addresses (`idRosterHash`) to prevent duplicate channels!
fn compute_roster_hashes(
    members_raw: &[[u8; 20]],
) -> Result<([[u8; 20]; MAX_CHAN_MEMBERS], [u8; 32], [u8; 32]), i32> {
    let m = members_raw.len();
    if m < 2 || m > MAX_CHAN_MEMBERS {
        return Err(ERR_INVALID_ROSTER);
    }

    let mut sorted_ids = [[0u8; 20]; MAX_CHAN_MEMBERS];
    let mut i = 0usize;
    while i < m {
        if members_raw[i] == [0u8; 20] {
            return Err(ERR_INVALID_ROSTER);
        }
        sorted_ids[i] = members_raw[i];
        i += 1;
    }

    // Insertion sort `sorted_ids` ascending & reject duplicates
    i = 1;
    while i < m {
        let key = sorted_ids[i];
        let mut j = i;
        while j > 0 && sorted_ids[j - 1] > key {
            sorted_ids[j] = sorted_ids[j - 1];
            j -= 1;
        }
        sorted_ids[j] = key;
        i += 1;
    }
    i = 1;
    while i < m {
        if sorted_ids[i - 1] == sorted_ids[i] {
            return Err(ERR_INVALID_ROSTER);
        }
        i += 1;
    }

    let mut pks = [[0u8; 64]; MAX_CHAN_MEMBERS];
    i = 0;
    while i < m {
        pks[i] = fetch_member_secp_slot(&sorted_ids[i]);
        i += 1;
    }

    // Insertion sort `pks` ascending & reject duplicate public keys
    i = 1;
    while i < m {
        let key = pks[i];
        let mut j = i;
        while j > 0 && pks[j - 1] > key {
            pks[j] = pks[j - 1];
            j -= 1;
        }
        pks[j] = key;
        i += 1;
    }
    i = 1;
    while i < m {
        if pks[i - 1] == pks[i] {
            return Err(ERR_INVALID_ROSTER);
        }
        i += 1;
    }

    let mut pk_pre = [0u8; 22 + MAX_CHAN_MEMBERS * 64];
    pk_pre[0..22].copy_from_slice(b"SLX_ECIES_PK_ROSTER_V1");
    i = 0;
    while i < m {
        let off = 22 + i * 64;
        pk_pre[off..off + 64].copy_from_slice(&pks[i]);
        i += 1;
    }
    let pk_hash = keccak256(&pk_pre[..22 + m * 64]);

    let mut id_pre = [0u8; 22 + MAX_CHAN_MEMBERS * 20];
    id_pre[0..22].copy_from_slice(b"SLX_ECIES_ID_ROSTER_V1");
    i = 0;
    while i < m {
        let off = 22 + i * 20;
        id_pre[off..off + 20].copy_from_slice(&sorted_ids[i]);
        i += 1;
    }
    let id_hash = keccak256(&id_pre[..22 + m * 20]);

    Ok((sorted_ids, pk_hash, id_hash))
}

fn parse_members_packed(
    members_packed: &[u8],
) -> Result<(usize, [[u8; 20]; MAX_CHAN_MEMBERS], [u8; 32], [u8; 32]), i32> {
    if members_packed.len() < 40 || members_packed.len() % 20 != 0 {
        return Err(ERR_INVALID_ROSTER);
    }
    let m = members_packed.len() / 20;
    if m < 2 || m > MAX_CHAN_MEMBERS {
        return Err(ERR_INVALID_ROSTER);
    }
    let mut raw = [[0u8; 20]; MAX_CHAN_MEMBERS];
    let mut i = 0usize;
    while i < m {
        raw[i].copy_from_slice(&members_packed[i * 20..(i + 1) * 20]);
        i += 1;
    }
    let (sorted_ids, pk_hash, id_hash) = compute_roster_hashes(&raw[..m])?;
    Ok((m, sorted_ids, pk_hash, id_hash))
}

fn lookup_active_channel_by_roster(pk_hash: &[u8; 32], id_hash: &[u8; 32]) -> Option<[u8; 32]> {
    let rpk = roster_pk_key(pk_hash);
    if let Some(cid) = storage::get_bytes32(rpk.as_slice()) {
        if cid != [0u8; 32] {
            return Some(cid);
        }
    }
    let rid = roster_id_key(id_hash);
    if let Some(cid) = storage::get_bytes32(rid.as_slice()) {
        if cid != [0u8; 32] {
            return Some(cid);
        }
    }
    None
}

fn bind_active_roster(pk_hash: &[u8; 32], id_hash: &[u8; 32], cid: &[u8; 32]) {
    let rpk = roster_pk_key(pk_hash);
    let rid = roster_id_key(id_hash);
    storage::set(rpk.as_slice(), cid);
    storage::set(rid.as_slice(), cid);
}

fn clear_active_roster(pk_hash: &[u8; 32], id_hash: &[u8; 32]) {
    let zero = [0u8; 32];
    let rpk = roster_pk_key(pk_hash);
    let rid = roster_id_key(id_hash);
    storage::set(rpk.as_slice(), &zero);
    storage::set(rid.as_slice(), &zero);
}

/// Registers `cid` under `member`'s index inside `Messaging` AND notifies `member`'s `Identity` HFS
/// (`notifyHfsAssociation`) so `member` discovers this `Messaging` HFS directly from their own
/// `Identity` HFS without any external indexer (reverting `-29` if `member` marked us `SPAM`).
fn associate_channel_with_member(member: &[u8; 20], cid: &[u8; 32]) -> Result<(), i32> {
    let sk = id_chan_seen_key(member, cid);
    if storage::get_u64(sk.as_slice()) == 0 {
        let ck = id_chan_count_key(member);
        let cnt = storage::get_u64(ck.as_slice()) as usize;
        if cnt < MAX_ID_CHANNELS {
            let ik = id_chan_item_key(member, cnt);
            storage::set(ik.as_slice(), cid);
            storage::set_u64(ck.as_slice(), (cnt + 1) as u64);
            storage::set_u64(sk.as_slice(), 1);
        }
    }

    if has_deployed_wasm(member) {
        let me = context::self_address();
        let label = b"ECIES Encrypted Channels";
        let cd = CallEncoder::<192>::new(const {
            selector("notifyHfsAssociation(address,bytes32,string)")
        })
        .push_address(&me)
        .push_bytes32(&HFS_TYPE_ECIES_MESSAGING)
        .push_u64(96)
        .push_dynamic_bytes_tail(label);
        if let Ok(raw_ret) = call::call_raw(member, cd.as_slice()) {
            if raw_ret.len() >= 32 && raw_ret[31] == 3 {
                return Err(-29); // Blocked as SPAM by recipient Identity HFS!
            }
        }
    }
    Ok(())
}

fn store_epoch_wraps_checked(
    cid: &[u8; 32],
    epoch: u32,
    active_members: &[[u8; 20]],
    wraps_packed: &[u8],
) -> Result<(), i32> {
    if wraps_packed.is_empty() {
        return Err(ERR_INVALID_EPOCH_WRAPS);
    }
    let count = wraps_packed[0] as usize;
    if count != active_members.len() {
        return Err(ERR_INVALID_EPOCH_WRAPS);
    }

    let mut seen_mask: u32 = 0;
    let mut pos = 1usize;
    let mut i = 0usize;
    while i < count {
        if pos + 22 > wraps_packed.len() {
            return Err(ERR_INVALID_EPOCH_WRAPS);
        }
        let mut m_addr = [0u8; 20];
        m_addr.copy_from_slice(&wraps_packed[pos..pos + 20]);
        let wl = u16::from_be_bytes([wraps_packed[pos + 20], wraps_packed[pos + 21]]) as usize;
        pos += 22;
        if wl == 0 || wl > MAX_WRAP_LEN || pos + wl > wraps_packed.len() {
            return Err(ERR_INVALID_EPOCH_WRAPS);
        }

        let mut found_idx: Option<usize> = None;
        let mut j = 0usize;
        while j < active_members.len() {
            if active_members[j] == m_addr {
                found_idx = Some(j);
                break;
            }
            j += 1;
        }
        let m_idx = found_idx.ok_or(ERR_INVALID_EPOCH_WRAPS)?;
        if (seen_mask & (1u32 << m_idx)) != 0 {
            return Err(ERR_INVALID_EPOCH_WRAPS);
        }
        seen_mask |= 1u32 << m_idx;

        let wk = chan_wrap_key(cid, epoch, &m_addr);
        storage::set(wk.as_slice(), &wraps_packed[pos..pos + wl]);
        pos += wl;
        i += 1;
    }

    if pos != wraps_packed.len() || seen_mask != ((1u32 << active_members.len()) - 1) {
        return Err(ERR_INVALID_EPOCH_WRAPS);
    }
    Ok(())
}

fn append_topic_internal(
    cid: &[u8; 32],
    hdr: &mut EciesChannelHdr,
    creator: &[u8; 20],
    title_raw: &[u8],
) -> Result<usize, i32> {
    let tid = hdr.topic_count as usize;
    if tid >= MAX_TOPICS_PER_CHANNEL || title_raw.len() > MAX_TOPIC_TITLE_LEN {
        return Err(-1);
    }
    let eff_title: &[u8] = if title_raw.is_empty() {
        if tid == 0 {
            b"General"
        } else {
            b"New Topic"
        }
    } else {
        title_raw
    };
    let mut title_arr = [0u8; MAX_TOPIC_TITLE_LEN];
    title_arr[..eff_title.len()].copy_from_slice(eff_title);
    let now = context::block_number();

    let trec = TopicRec {
        msg_count: 0,
        created_block: now,
        last_block: now,
        creator: *creator,
        title_len: eff_title.len() as u8,
        title: title_arr,
    };
    trec.save(cid, tid);
    hdr.topic_count = (tid + 1) as u8;
    hdr.last_block = now;

    let mut ev = [0u8; 8 + MAX_TOPIC_TITLE_LEN];
    ev[0..8].copy_from_slice(&(tid as u64).to_be_bytes());
    ev[8..8 + eff_title.len()].copy_from_slice(eff_title);
    events::emit(
        &[TOPIC_CREATED, *cid, addr_topic(creator)],
        &ev[..8 + eff_title.len()],
    );
    Ok(tid)
}

fn handle_open_channel_or_topic(args: &CalldataReader) -> Result<(), i32> {
    let members_packed = args.dynamic_bytes(0).ok_or(-3)?;
    let chan_label = args.dynamic_bytes(1).ok_or(-3)?;
    let topic_title = args.dynamic_bytes(2).ok_or(-3)?;
    let wraps_packed = args.dynamic_bytes(3).ok_or(-3)?;

    if chan_label.len() > MAX_CHAN_LABEL_LEN || topic_title.len() > MAX_TOPIC_TITLE_LEN {
        return Err(-1);
    }

    let caller = context::msg_sender();
    let (m, sorted_ids, pk_hash, id_hash) = parse_members_packed(members_packed)?;
    let mut caller_in_roster = false;
    let mut i = 0usize;
    while i < m {
        if sorted_ids[i] == caller {
            caller_in_roster = true;
            break;
        }
        i += 1;
    }
    if !caller_in_roster {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }

    // Requirement #2: If an active channel with this exact roster already exists, reuse it
    // automatically and create a NEW topic under it!
    if let Some(existing_cid) = lookup_active_channel_by_roster(&pk_hash, &id_hash) {
        let mut hdr = EciesChannelHdr::load(&existing_cid).ok_or(-1)?;
        if !hdr.has_member(&caller) {
            return Err(ERR_NOT_CHANNEL_MEMBER);
        }
        let new_tid = append_topic_internal(&existing_cid, &mut hdr, &caller, topic_title)?;
        hdr.save(&existing_cid);

        let mut ret_56 = [0u8; 56];
        ret_56[0..32].copy_from_slice(&existing_cid);
        ret_56[32..40].copy_from_slice(&(new_tid as u64).to_be_bytes());
        ret_56[40..48].copy_from_slice(&(hdr.current_epoch as u64).to_be_bytes());
        ret_56[48..56].copy_from_slice(&0u64.to_be_bytes()); // createdNewChannel = 0
        ret::write(&ret_56);
        return Ok(());
    }

    // Brand-new ECIES channel (`keyEpoch = 1`, `topicId = 0`)
    let seq = storage::get_u64(KEY_EC_SEQ) + 1;
    storage::set_u64(KEY_EC_SEQ, seq);
    let me = context::self_address();
    let mut cid_pre = [0u8; 17 + 20 + 8 + 32];
    cid_pre[0..17].copy_from_slice(b"SLX_ECIES_CHAN_V1");
    cid_pre[17..37].copy_from_slice(&me);
    cid_pre[37..45].copy_from_slice(&seq.to_be_bytes());
    cid_pre[45..77].copy_from_slice(&pk_hash);
    let cid = keccak256(&cid_pre);

    store_epoch_wraps_checked(&cid, 1, &sorted_ids[..m], wraps_packed)?;

    let now = context::block_number();
    let mut lbl_arr = [0u8; MAX_CHAN_LABEL_LEN];
    lbl_arr[..chan_label.len()].copy_from_slice(chan_label);

    let mut hdr = EciesChannelHdr {
        rekey_required: 0,
        member_count: m as u8,
        topic_count: 0,
        current_epoch: 1,
        created_block: now,
        last_block: now,
        creator: caller,
        pk_roster_hash: pk_hash,
        id_roster_hash: id_hash,
        label_len: chan_label.len() as u8,
        label: lbl_arr,
        members: sorted_ids,
    };
    let tid0 = append_topic_internal(&cid, &mut hdr, &caller, topic_title)?;
    hdr.save(&cid);
    bind_active_roster(&pk_hash, &id_hash, &cid);

    i = 0;
    while i < m {
        let jek = member_join_epoch_key(&cid, &sorted_ids[i]);
        storage::set_u64(jek.as_slice(), 1);
        associate_channel_with_member(&sorted_ids[i], &cid)?;
        i += 1;
    }

    events::emit(&[ECIES_CHANNEL_CREATED, cid, pk_hash], &caller);

    let mut ret_56 = [0u8; 56];
    ret_56[0..32].copy_from_slice(&cid);
    ret_56[32..40].copy_from_slice(&(tid0 as u64).to_be_bytes());
    ret_56[40..48].copy_from_slice(&1u64.to_be_bytes());
    ret_56[48..56].copy_from_slice(&1u64.to_be_bytes()); // createdNewChannel = 1
    ret::write(&ret_56);
    Ok(())
}

fn handle_create_topic(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let title = args.dynamic_bytes(1).ok_or(-3)?;
    if title.is_empty() || title.len() > MAX_TOPIC_TITLE_LEN {
        return Err(-1);
    }
    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }
    let tid = append_topic_internal(&cid, &mut hdr, &caller, title)?;
    hdr.save(&cid);
    ret::write_u64_word(tid as u64);
    Ok(())
}

fn rotate_key_internal(
    cid: &[u8; 32],
    hdr: &mut EciesChannelHdr,
    actor: &[u8; 20],
    wraps_packed: &[u8],
    reason: u64,
) -> Result<u32, i32> {
    let mc = hdr.member_count as usize;
    let new_epoch = hdr.current_epoch.saturating_add(1);
    store_epoch_wraps_checked(cid, new_epoch, &hdr.members[..mc], wraps_packed)?;
    hdr.current_epoch = new_epoch;
    hdr.rekey_required = 0;
    hdr.last_block = context::block_number();

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&(new_epoch as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&reason.to_be_bytes());
    events::emit(&[CHANNEL_KEY_ROTATED, *cid, addr_topic(actor)], &ev);
    Ok(new_epoch)
}

fn handle_rotate_channel_key(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let wraps_packed = args.dynamic_bytes(1).ok_or(-3)?;
    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }
    let new_epoch = rotate_key_internal(&cid, &mut hdr, &caller, wraps_packed, 1)?;
    hdr.save(&cid);
    ret::write_u64_word(new_epoch as u64);
    Ok(())
}

fn handle_add_channel_member(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let new_member = args.address(1).ok_or(-3)?;
    let wraps_packed = args.dynamic_bytes(2).ok_or(-3)?;

    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }
    let mc = hdr.member_count as usize;
    if mc >= MAX_CHAN_MEMBERS || new_member == [0u8; 20] || hdr.has_member(&new_member) {
        return Err(ERR_INVALID_ROSTER);
    }

    let mut next_raw = [[0u8; 20]; MAX_CHAN_MEMBERS];
    let mut i = 0usize;
    while i < mc {
        next_raw[i] = hdr.members[i];
        i += 1;
    }
    next_raw[mc] = new_member;
    let new_mc = mc + 1;

    let (sorted_ids, new_pk_hash, new_id_hash) = compute_roster_hashes(&next_raw[..new_mc])?;
    if let Some(conflict_cid) = lookup_active_channel_by_roster(&new_pk_hash, &new_id_hash) {
        if conflict_cid != cid {
            return Err(ERR_DUPLICATE_ROSTER_EXISTS);
        }
    }

    clear_active_roster(&hdr.pk_roster_hash, &hdr.id_roster_hash);
    hdr.members = sorted_ids;
    hdr.member_count = new_mc as u8;
    hdr.pk_roster_hash = new_pk_hash;
    hdr.id_roster_hash = new_id_hash;

    let new_epoch = rotate_key_internal(&cid, &mut hdr, &caller, wraps_packed, 2)?;
    let jek = member_join_epoch_key(&cid, &new_member);
    storage::set_u64(jek.as_slice(), new_epoch as u64);
    associate_channel_with_member(&new_member, &cid)?;
    hdr.save(&cid);
    bind_active_roster(&new_pk_hash, &new_id_hash, &cid);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&1u64.to_be_bytes()); // action = 1 (added)
    ev[8..16].copy_from_slice(&(new_epoch as u64).to_be_bytes());
    events::emit(
        &[CHANNEL_MEMBER_UPDATED, cid, addr_topic(&new_member)],
        &ev,
    );
    ret::write_u64_word(new_epoch as u64);
    Ok(())
}

fn handle_remove_channel_member(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let target_member = args.address(1).ok_or(-3)?;
    let wraps_packed = args.dynamic_bytes(2).ok_or(-3)?;

    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }
    let mc = hdr.member_count as usize;
    if mc < 2 || !hdr.has_member(&target_member) {
        return Err(ERR_INVALID_ROSTER);
    }

    let mut next_raw = [[0u8; 20]; MAX_CHAN_MEMBERS];
    let mut new_mc = 0usize;
    let mut i = 0usize;
    while i < mc {
        if hdr.members[i] != target_member {
            next_raw[new_mc] = hdr.members[i];
            new_mc += 1;
        }
        i += 1;
    }

    clear_active_roster(&hdr.pk_roster_hash, &hdr.id_roster_hash);
    if new_mc >= 2 {
        let (sorted_ids, new_pk_hash, new_id_hash) = compute_roster_hashes(&next_raw[..new_mc])?;
        if let Some(conflict_cid) = lookup_active_channel_by_roster(&new_pk_hash, &new_id_hash) {
            if conflict_cid != cid {
                return Err(ERR_DUPLICATE_ROSTER_EXISTS);
            }
        }
        hdr.members = sorted_ids;
        hdr.member_count = new_mc as u8;
        hdr.pk_roster_hash = new_pk_hash;
        hdr.id_roster_hash = new_id_hash;
        bind_active_roster(&new_pk_hash, &new_id_hash, &cid);
    } else {
        hdr.members = next_raw;
        hdr.member_count = new_mc as u8;
        hdr.pk_roster_hash = [0u8; 32];
        hdr.id_roster_hash = [0u8; 32];
    }

    let new_epoch = rotate_key_internal(&cid, &mut hdr, &caller, wraps_packed, 3)?;
    hdr.save(&cid);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&2u64.to_be_bytes()); // action = 2 (removed)
    ev[8..16].copy_from_slice(&(new_epoch as u64).to_be_bytes());
    events::emit(
        &[CHANNEL_MEMBER_UPDATED, cid, addr_topic(&target_member)],
        &ev,
    );
    ret::write_u64_word(new_epoch as u64);
    Ok(())
}

fn handle_leave_channel(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }

    let mc = hdr.member_count as usize;
    let mut next_raw = [[0u8; 20]; MAX_CHAN_MEMBERS];
    let mut new_mc = 0usize;
    let mut i = 0usize;
    while i < mc {
        if hdr.members[i] != caller {
            next_raw[new_mc] = hdr.members[i];
            new_mc += 1;
        }
        i += 1;
    }

    clear_active_roster(&hdr.pk_roster_hash, &hdr.id_roster_hash);
    if new_mc >= 2 {
        let (sorted_ids, new_pk_hash, new_id_hash) = compute_roster_hashes(&next_raw[..new_mc])?;
        hdr.members = sorted_ids;
        hdr.member_count = new_mc as u8;
        hdr.pk_roster_hash = new_pk_hash;
        hdr.id_roster_hash = new_id_hash;
        // Only bind if not colliding with an already existing pair/group channel
        if lookup_active_channel_by_roster(&new_pk_hash, &new_id_hash).is_none() {
            bind_active_roster(&new_pk_hash, &new_id_hash, &cid);
        }
    } else {
        hdr.members = next_raw;
        hdr.member_count = new_mc as u8;
        hdr.pk_roster_hash = [0u8; 32];
        hdr.id_roster_hash = [0u8; 32];
    }

    if new_mc >= 1 {
        // Departing member MUST NOT choose survivors' next key -> enforce lazy-on-next-send rekey!
        hdr.rekey_required = 1;
    }
    hdr.last_block = context::block_number();
    hdr.save(&cid);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&3u64.to_be_bytes()); // action = 3 (left)
    ev[8..16].copy_from_slice(&(hdr.rekey_required as u64).to_be_bytes());
    events::emit(&[CHANNEL_MEMBER_UPDATED, cid, addr_topic(&caller)], &ev);
    ret::write_bool(true);
    Ok(())
}

fn append_topic_ciphertext_internal(
    cid: &[u8; 32],
    hdr: &mut EciesChannelHdr,
    topic_id: usize,
    key_epoch: u32,
    author: &[u8; 20],
    ciphertext: &[u8],
) -> Result<u32, i32> {
    if topic_id >= hdr.topic_count as usize
        || ciphertext.is_empty()
        || ciphertext.len() > MAX_ECIES_CT_LEN
    {
        return Err(-1);
    }
    if hdr.rekey_required != 0 {
        return Err(ERR_REKEY_REQUIRED);
    }
    if key_epoch != hdr.current_epoch {
        return Err(ERR_STALE_KEY_EPOCH);
    }

    let mut trec = TopicRec::load(cid, topic_id).ok_or(-1)?;
    let seq = trec.msg_count;
    let now = context::block_number();

    // Stored frame (`ec:tm:<cid>:<tid>:<seq>`): `[block:8 BE][epoch:4 BE][author:20][ciphertext]`
    let mut rec = [0u8; 32 + MAX_ECIES_CT_LEN];
    rec[0..8].copy_from_slice(&now.to_be_bytes());
    rec[8..12].copy_from_slice(&key_epoch.to_be_bytes());
    rec[12..32].copy_from_slice(author);
    rec[32..32 + ciphertext.len()].copy_from_slice(ciphertext);

    let mk = topic_msg_key(cid, topic_id, seq);
    storage::set(mk.as_slice(), &rec[..32 + ciphertext.len()]);

    trec.msg_count = seq.saturating_add(1);
    trec.last_block = now;
    trec.save(cid, topic_id);
    hdr.last_block = now;

    let mut topic_idx_w = [0u8; 32];
    topic_idx_w[24..32].copy_from_slice(&(topic_id as u64).to_be_bytes());
    let mut ev = [0u8; 28];
    ev[0..8].copy_from_slice(&(key_epoch as u64).to_be_bytes());
    ev[8..28].copy_from_slice(author);
    events::emit(&[TOPIC_MESSAGE_POSTED, *cid, topic_idx_w], &ev);

    Ok(seq)
}

fn handle_post_topic_message(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let topic_id = args.u64(1).ok_or(-3)? as usize;
    let key_epoch = args.u64(2).ok_or(-3)? as u32;
    let ciphertext = args.dynamic_bytes(3).ok_or(-3)?;

    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }

    let seq = append_topic_ciphertext_internal(&cid, &mut hdr, topic_id, key_epoch, &caller, ciphertext)?;
    hdr.save(&cid);
    ret::write_u64_word(seq as u64);
    Ok(())
}

fn handle_rotate_and_post_topic_message(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let topic_id = args.u64(1).ok_or(-3)? as usize;
    let wraps_packed = args.dynamic_bytes(2).ok_or(-3)?;
    let ciphertext = args.dynamic_bytes(3).ok_or(-3)?;

    let caller = context::msg_sender();
    let mut hdr = EciesChannelHdr::load(&cid).ok_or(-1)?;
    if !hdr.has_member(&caller) {
        return Err(ERR_NOT_CHANNEL_MEMBER);
    }

    let new_epoch = rotate_key_internal(&cid, &mut hdr, &caller, wraps_packed, 4)?;
    let _seq = append_topic_ciphertext_internal(&cid, &mut hdr, topic_id, new_epoch, &caller, ciphertext)?;
    hdr.save(&cid);
    ret::write_u64_word(new_epoch as u64);
    Ok(())
}

fn handle_resolve_channel_by_roster(args: &CalldataReader) -> Result<(), i32> {
    let members_packed = args.dynamic_bytes(0).ok_or(-3)?;
    let (_, _, pk_hash, id_hash) = parse_members_packed(members_packed)?;
    let cid = lookup_active_channel_by_roster(&pk_hash, &id_hash).unwrap_or([0u8; 32]);
    ret::write(&cid);
    Ok(())
}

fn handle_get_identity_channels(args: &CalldataReader) -> Result<(), i32> {
    let id_addr = args.address(0).ok_or(-3)?;
    let ck = id_chan_count_key(&id_addr);
    let cnt = storage::get_u64(ck.as_slice()) as usize;

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(OUT_SCRATCH);
        let mut pos = 2usize;
        let mut written = 0u16;
        let mut idx = cnt;
        // Return newest-created / most-recently associated channels first
        while idx > 0 {
            idx -= 1;
            let ik = id_chan_item_key(&id_addr, idx);
            let Some(cid) = storage::get_bytes32(ik.as_slice()) else {
                continue;
            };
            let Some(hdr) = EciesChannelHdr::load(&cid) else {
                continue;
            };
            let is_active = hdr.has_member(&id_addr);
            let mc = hdr.member_count as usize;
            let tc = hdr.topic_count as usize;
            let ll = hdr.label_len as usize;

            let mut wrap_buf = [0u8; MAX_WRAP_LEN];
            let wl = if is_active {
                let wk = chan_wrap_key(&cid, hdr.current_epoch, &id_addr);
                storage::get_into(wk.as_slice(), &mut wrap_buf).unwrap_or(0)
            } else {
                0
            };

            let min_need = 32 + 4 + 4 + 8 + 32 + 1 + ll + mc * 20 + tc * 80 + 2 + wl;
            if pos + min_need > out.len() {
                break;
            }

            out[pos..pos + 32].copy_from_slice(&cid);
            out[pos + 32] = u8::from(is_active);
            out[pos + 33] = hdr.rekey_required;
            out[pos + 34] = mc as u8;
            out[pos + 35] = tc as u8;
            out[pos + 36..pos + 40].copy_from_slice(&hdr.current_epoch.to_be_bytes());
            out[pos + 40..pos + 48].copy_from_slice(&hdr.last_block.to_be_bytes());
            out[pos + 48..pos + 80].copy_from_slice(&hdr.pk_roster_hash);
            out[pos + 80] = ll as u8;
            pos += 81;
            out[pos..pos + ll].copy_from_slice(&hdr.label[..ll]);
            pos += ll;

            let mut m_i = 0usize;
            while m_i < mc {
                out[pos..pos + 20].copy_from_slice(&hdr.members[m_i]);
                pos += 20;
                m_i += 1;
            }

            let mut t_i = 0usize;
            while t_i < tc {
                if let Some(t) = TopicRec::load(&cid, t_i) {
                    let tl = t.title_len as usize;
                    out[pos..pos + 2].copy_from_slice(&(t_i as u16).to_be_bytes());
                    out[pos + 2..pos + 6].copy_from_slice(&t.msg_count.to_be_bytes());
                    out[pos + 6..pos + 14].copy_from_slice(&t.last_block.to_be_bytes());
                    out[pos + 14] = tl as u8;
                    pos += 15;
                    out[pos..pos + tl].copy_from_slice(&t.title[..tl]);
                    pos += tl;
                } else {
                    out[pos..pos + 15].fill(0);
                    out[pos..pos + 2].copy_from_slice(&(t_i as u16).to_be_bytes());
                    pos += 15;
                }
                t_i += 1;
            }

            out[pos..pos + 2].copy_from_slice(&(wl as u16).to_be_bytes());
            pos += 2;
            out[pos..pos + wl].copy_from_slice(&wrap_buf[..wl]);
            pos += wl;
            written += 1;
        }

        out[0..2].copy_from_slice(&written.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

fn handle_get_channel_details(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let viewer = args.address(1).ok_or(-3)?;

    let Some(hdr) = EciesChannelHdr::load(&cid) else {
        ret::write(&[0u8]);
        return Ok(());
    };

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(OUT_SCRATCH);
        let is_active = hdr.has_member(&viewer);
        let mc = hdr.member_count as usize;
        let tc = hdr.topic_count as usize;
        let ll = hdr.label_len as usize;

        out[0] = 1; // exists = 1
        out[1] = u8::from(is_active);
        out[2] = hdr.rekey_required;
        out[3] = mc as u8;
        out[4] = tc as u8;
        out[5..9].copy_from_slice(&hdr.current_epoch.to_be_bytes());
        out[9..17].copy_from_slice(&hdr.created_block.to_be_bytes());
        out[17..25].copy_from_slice(&hdr.last_block.to_be_bytes());
        out[25..45].copy_from_slice(&hdr.creator);
        out[45..77].copy_from_slice(&hdr.pk_roster_hash);
        out[77..109].copy_from_slice(&hdr.id_roster_hash);
        out[109] = ll as u8;
        let mut pos = 110usize;
        out[pos..pos + ll].copy_from_slice(&hdr.label[..ll]);
        pos += ll;

        let mut i = 0usize;
        while i < mc {
            out[pos..pos + 20].copy_from_slice(&hdr.members[i]);
            pos += 20;
            i += 1;
        }

        i = 0;
        while i < tc {
            if let Some(t) = TopicRec::load(&cid, i) {
                let tl = t.title_len as usize;
                out[pos..pos + 2].copy_from_slice(&(i as u16).to_be_bytes());
                out[pos + 2..pos + 6].copy_from_slice(&t.msg_count.to_be_bytes());
                out[pos + 6..pos + 14].copy_from_slice(&t.last_block.to_be_bytes());
                out[pos + 14..pos + 34].copy_from_slice(&t.creator);
                out[pos + 34] = tl as u8;
                pos += 35;
                out[pos..pos + tl].copy_from_slice(&t.title[..tl]);
                pos += tl;
            } else {
                out[pos..pos + 35].fill(0);
                out[pos..pos + 2].copy_from_slice(&(i as u16).to_be_bytes());
                pos += 35;
            }
            i += 1;
        }

        let wraps_cnt_pos = pos;
        pos += 2;
        let mut wraps_cnt = 0u16;
        if viewer != [0u8; 20] {
            let jek = member_join_epoch_key(&cid, &viewer);
            let join_ep = storage::get_u64(jek.as_slice()) as u32;
            if join_ep > 0 {
                let mut ep = join_ep;
                while ep <= hdr.current_epoch {
                    let wk = chan_wrap_key(&cid, ep, &viewer);
                    let mut wbuf = [0u8; MAX_WRAP_LEN];
                    if let Some(wl) = storage::get_into(wk.as_slice(), &mut wbuf) {
                        if wl > 0 && pos + 6 + wl <= out.len() {
                            out[pos..pos + 4].copy_from_slice(&ep.to_be_bytes());
                            out[pos + 4..pos + 6].copy_from_slice(&(wl as u16).to_be_bytes());
                            pos += 6;
                            out[pos..pos + wl].copy_from_slice(&wbuf[..wl]);
                            pos += wl;
                            wraps_cnt += 1;
                        }
                    }
                    ep += 1;
                }
            }
        }
        out[wraps_cnt_pos..wraps_cnt_pos + 2].copy_from_slice(&wraps_cnt.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

fn handle_get_topic_messages(args: &CalldataReader) -> Result<(), i32> {
    let cid = args.bytes32(0).ok_or(-3)?;
    let topic_id = args.u64(1).ok_or(-3)? as usize;
    let max_messages = args.u64(2).ok_or(-3)?.min(64) as u32;

    let Some(trec) = TopicRec::load(&cid, topic_id) else {
        ret::write(&[0u8; 8]);
        return Ok(());
    };

    let total = trec.msg_count;
    let start_seq = total.saturating_sub(max_messages);

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(OUT_SCRATCH);
        out[4..8].copy_from_slice(&total.to_be_bytes());
        let mut pos = 8usize;
        let mut written = 0u32;

        let mut seq = start_seq;
        while seq < total {
            let mk = topic_msg_key(&cid, topic_id, seq);
            if let Some(raw) = storage::get_ref(mk.as_slice()) {
                if raw.len() > 32 {
                    let ct_len = (raw.len() - 32).min(MAX_ECIES_CT_LEN);
                    if pos + 38 + ct_len > MAX_RECENT_RETURN_BYTES {
                        break;
                    }
                    out[pos..pos + 4].copy_from_slice(&seq.to_be_bytes());
                    out[pos + 4..pos + 36].copy_from_slice(&raw[0..32]); // blk(8) + epoch(4) + author(20)
                    out[pos + 36..pos + 38].copy_from_slice(&(ct_len as u16).to_be_bytes());
                    pos += 38;
                    out[pos..pos + ct_len].copy_from_slice(&raw[32..32 + ct_len]);
                    pos += ct_len;
                    written += 1;
                }
            }
            seq += 1;
        }

        out[0..4].copy_from_slice(&written.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
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

    fn abi_pad(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&lw);
        out.extend_from_slice(b);
        out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
        out
    }

    fn pack_wraps(members: &[[u8; 20]], tag: u8) -> Vec<u8> {
        let mut out = vec![members.len() as u8];
        for (i, m) in members.iter().enumerate() {
            out.extend_from_slice(m);
            let w = [tag.wrapping_add(i as u8); 96];
            out.extend_from_slice(&(w.len() as u16).to_be_bytes());
            out.extend_from_slice(&w);
        }
        out
    }

    fn mock_identity_hps(cd: &[u8]) -> i32 {
        let Some((sel, _args)) = CalldataReader::parse(cd) else {
            return -1;
        };
        let me = context::self_address();
        if sel == const { selector("secp256k1PubKey()") } {
            let mut pk = [0u8; 64];
            pk[0] = me[19];
            pk[63] = me[19] ^ 0x5A;
            ret::write(&pk);
            0
        } else if sel == const { selector("notifyHfsAssociation(address,bytes32,string)") } {
            if me[19] == 0xFF {
                ret::write_u64_word(3); // SPAM blocked!
            } else {
                storage::set_u64(b"notified", 1);
                ret::write_u64_word(1); // PENDING
            }
            0
        } else {
            -2
        }
    }

    #[test]
    fn ecies_channels_dedup_topics_hfs_discovery_and_rolling_key_epochs() {
        mock::reset();
        mock::set_block_number(300);

        let msg_hps = [0x50; 20];
        let alice = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xA1];
        let bob = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB2];
        let carol = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC3];
        let spam_blocker = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF];

        mock::register_hps(msg_hps, dispatch_calldata);
        mock::register_hps(alice, mock_identity_hps);
        mock::register_hps(bob, mock_identity_hps);
        mock::register_hps(carol, mock_identity_hps);
        mock::register_hps(spam_blocker, mock_identity_hps);

        let mk_open = |members: &[[u8; 20]], lbl: &[u8], topic: &[u8], wraps: &[u8]| -> Vec<u8> {
            let mut mp = Vec::with_capacity(members.len() * 20);
            for m in members {
                mp.extend_from_slice(m);
            }
            let t0 = abi_pad(&mp);
            let t1 = abi_pad(lbl);
            let t2 = abi_pad(topic);
            let t3 = abi_pad(wraps);
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("openChannelOrTopic(bytes,string,string,bytes)"));
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + t0.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + t0.len() + t1.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(
                &((128 + t0.len() + t1.len() + t2.len()) as u64).to_be_bytes(),
            );
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&t0);
            cd.extend_from_slice(&t1);
            cd.extend_from_slice(&t2);
            cd.extend_from_slice(&t3);
            cd
        };

        // 0. Recipient who blocked this Messaging HFS as SPAM causes openChannelOrTopic to revert -29!
        assert_eq!(
            mock::transact_as(
                alice,
                msg_hps,
                &mk_open(
                    &[alice, spam_blocker],
                    b"Blocked",
                    b"General",
                    &pack_wraps(&[alice, spam_blocker], 0x10),
                )
            ),
            Err(-29)
        );

        // 1. Open [Bob, Alice] (unsorted input!) -> creates Channel #1, Topic #0 ("General"), Epoch #1
        let r1 = mock::transact_as(
            alice,
            msg_hps,
            &mk_open(
                &[bob, alice],
                b"Core Ops",
                b"General",
                &pack_wraps(&[alice, bob], 0x10),
            ),
        )
        .unwrap();
        assert_eq!(r1.len(), 56);
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&r1[0..32]);
        assert_eq!(u64::from_be_bytes(r1[32..40].try_into().unwrap()), 0); // topicId = 0
        assert_eq!(u64::from_be_bytes(r1[40..48].try_into().unwrap()), 1); // epoch = 1
        assert_eq!(u64::from_be_bytes(r1[48..56].try_into().unwrap()), 1); // createdNewChannel = 1

        // 2. Bob tries to "re-create" a channel with [Alice, Bob] and topic "Q4 Strategy" ->
        //    automatically reuses `cid` (`createdNewChannel = 0`) and creates `topicId = 1`!
        let r2 = mock::transact_as(
            bob,
            msg_hps,
            &mk_open(&[alice, bob], b"Duplicate Try", b"Q4 Strategy", &[]),
        )
        .unwrap();
        assert_eq!(&r2[0..32], &cid);
        assert_eq!(u64::from_be_bytes(r2[32..40].try_into().unwrap()), 1); // new topicId = 1!
        assert_eq!(u64::from_be_bytes(r2[48..56].try_into().unwrap()), 0); // reused pre-existing!

        // 3. Post encrypted message in Topic #1 under Epoch #1
        let mk_post_topic = |tid: u64, ep: u64, ct: &[u8]| -> Vec<u8> {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("postTopicMessage(bytes32,uint64,uint64,bytes)"));
            cd.extend_from_slice(&cid);
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&tid.to_be_bytes());
            cd.extend_from_slice(&w);
            w[24..32].copy_from_slice(&ep.to_be_bytes());
            cd.extend_from_slice(&w);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&abi_pad(ct));
            cd
        };
        mock::transact_as(alice, msg_hps, &mk_post_topic(1, 1, &[0xDE, 0xAD, 0xBE, 0xEF])).unwrap();

        // 4. Add Carol -> atomically rotates `keyEpoch = 2`! Carol only receives wraps for epoch >= 2!
        let add_carol = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("addChannelMember(bytes32,address,bytes)"));
            cd.extend_from_slice(&cid);
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(&carol);
            cd.extend_from_slice(&w);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&96u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&abi_pad(&pack_wraps(&[alice, bob, carol], 0x20)));
            cd
        };
        let ep2 = mock::transact_as(alice, msg_hps, &add_carol).unwrap();
        assert_eq!(ep2[31], 2);

        // Stale epoch #1 post is now rejected!
        assert_eq!(
            mock::transact_as(alice, msg_hps, &mk_post_topic(1, 1, &[0x11])),
            Err(ERR_STALE_KEY_EPOCH)
        );

        // 5. Carol voluntarily leaves (`leaveChannel`) -> sets `rekeyRequired = 1`, blocking epoch #2 posts
        //    until Alice atomically executes `rotateAndPostTopicMessage` -> `keyEpoch = 3`!
        let leave_cd =
            CallEncoder::<68>::new(const { selector("leaveChannel(bytes32)") }).push_bytes32(&cid);
        mock::transact_as(carol, msg_hps, leave_cd.as_slice()).unwrap();

        assert_eq!(
            mock::transact_as(alice, msg_hps, &mk_post_topic(1, 2, &[0x22])),
            Err(ERR_REKEY_REQUIRED)
        );

        let rot_and_post = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector(
                "rotateAndPostTopicMessage(bytes32,uint64,bytes,bytes)",
            ));
            cd.extend_from_slice(&cid);
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&1u64.to_be_bytes());
            cd.extend_from_slice(&w);
            let t_w = abi_pad(&pack_wraps(&[alice, bob], 0x30));
            let t_c = abi_pad(&[0xCA, 0xFE, 0xBA, 0xBE]);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + t_w.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&t_w);
            cd.extend_from_slice(&t_c);
            cd
        };
        let ep3 = mock::transact_as(alice, msg_hps, &rot_and_post).unwrap();
        assert_eq!(ep3[31], 3);

        // Verify Carol's `getChannelDetails` has ONLY epoch 2 wrap (neither epoch 1 pre-join nor epoch 3 post-leave!)
        let det_carol = mock::transact_as(
            carol,
            msg_hps,
            CallEncoder::<100>::new(const { selector("getChannelDetails(bytes32,address)") })
                .push_bytes32(&cid)
                .push_address(&carol)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(det_carol[0], 1); // exists
        assert_eq!(det_carol[1], 0); // isActiveMember = 0 (left!)
        // Locate wraps_cnt at the tail: 1 wrap (4B epoch=2 + 2B len=96 + 96B = 102B, preceded by u16=1)
        let tail_cnt_off = det_carol.len() - 104;
        assert_eq!(
            u16::from_be_bytes([det_carol[tail_cnt_off], det_carol[tail_cnt_off + 1]]),
            1
        );
        assert_eq!(
            u32::from_be_bytes(det_carol[tail_cnt_off + 2..tail_cnt_off + 6].try_into().unwrap()),
            2
        );

        // Verify `getIdentityChannels(bob)` returns `cid` with 2 topics & active epoch #3 wrap!
        let bob_chans = mock::transact_as(
            bob,
            msg_hps,
            CallEncoder::<68>::new(const { selector("getIdentityChannels(address)") })
                .push_address(&bob)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([bob_chans[0], bob_chans[1]]), 1);
        assert_eq!(&bob_chans[2..34], &cid);
        assert_eq!(bob_chans[34], 1); // isActive = 1
        assert_eq!(bob_chans[35], 0); // rekeyRequired cleared = 0
        assert_eq!(bob_chans[37], 2); // topicCount = 2
    }
}
