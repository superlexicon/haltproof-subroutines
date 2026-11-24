//! # `SocialFeed` — Wall Feed & Proximity Messenger (`social-feed` — HPS #14C)
//!
//! Pinned to `SocialCharter`, `SocialRelationships`, and the core `Messaging` HFS:
//! - **Wall Posts, Reactions & Comments**: Enforces live subnet radio presence via `SocialCharter`
//!   and `FRIENDS_ONLY` / `CLOSE_CIRCLE` relationship checks via `SocialRelationships`, persisting
//!   wall broadcasts and comment streams into protected channels on the `Messaging` HFS.
//! - **Proximity Direct Messenger (`sendDirectMessage` / `getDirectMessages`)**: Allows DMs strictly
//!   between RF-connected peers while BOTH are Active In-Subnet, writing directly into canonical
//!   protected pair channels on the `Messaging` HFS (`ERR_CHANNEL_PROTECTED` against spoofing).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::social::{
    adjust_standing_from_module, canonical_dm_channel, derive_social_channel,
    messaging_get_recent_into, messaging_post_attributed, query_active_connected,
    require_active_member, ERR_SOCIAL_ALREADY_INIT, ERR_SOCIAL_INVALID_ARGS,
    ERR_SOCIAL_NOT_CONNECTED, ERR_SOCIAL_UNINITIALIZED, REL_CLOSE_CIRCLE, REL_FRIEND, REL_NEIGHBOR,
    SCOPE_CLOSE_CIRCLE, SCOPE_FRIENDS_ONLY,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const MAX_POST_RING: u32 = 32;
pub const MAX_POST_LEN: usize = 280;
pub const MAX_DM_LEN: usize = 768;
pub const MAX_COMMENT_LEN: usize = 160;

const KEY_CFG: &[u8] = b"sf:cfg";
const KEY_TOTAL_POSTS: &[u8] = b"sf:cnt";

const EV_POST_PUBLISHED: [u8; 32] = event_topic("SocialPostPublished(uint64,address,uint64)");
const EV_DM_SENT: [u8; 32] = event_topic("ProximityDmSent(bytes32,address,address)");

static mut FEED_OUT: [u8; 24_576] = [0u8; 24_576];
static mut CMT_TMP: [u8; 4096] = [0u8; 4096];

hps_entry! {
    "initialize(address,address,address)"                   => handle_initialize,
    "createPost(uint64,bytes)"                              => handle_create_post,
    "reactPost(uint64,uint64)"                              => handle_react_post,
    "commentPost(uint64,bytes)"                             => handle_comment_post,
    "sendDirectMessage(address,bytes)"                      => handle_send_dm,
    "getDirectMessages(address,address,uint64)"             => handle_get_dms,
    "getFeedSnapshot()"                                     => handle_get_feed_snapshot,
}

#[derive(Clone, Copy)]
struct FeedConfig {
    charter: [u8; 20],
    relationships: [u8; 20],
    messaging: [u8; 20],
}

impl FeedConfig {
    fn save(&self) {
        let mut b = [0u8; 60];
        b[0..20].copy_from_slice(&self.charter);
        b[20..40].copy_from_slice(&self.relationships);
        b[40..60].copy_from_slice(&self.messaging);
        storage::set(KEY_CFG, &b);
    }

    fn load() -> Result<Self, i32> {
        let mut b = [0u8; 60];
        if storage::get_into(KEY_CFG, &mut b) != Some(60) {
            return Err(ERR_SOCIAL_UNINITIALIZED);
        }
        let mut charter = [0u8; 20];
        let mut relationships = [0u8; 20];
        let mut messaging = [0u8; 20];
        charter.copy_from_slice(&b[0..20]);
        relationships.copy_from_slice(&b[20..40]);
        messaging.copy_from_slice(&b[40..60]);
        Ok(Self {
            charter,
            relationships,
            messaging,
        })
    }
}

struct PostMeta {
    post_id: u32,
    author: [u8; 20],
    author_uid: u8,
    visibility: u8,
    comment_count: u8,
    created_block: u64,
    liked_by_mask: u64,
    endorsed_by_mask: u64,
    content_len: u16,
    content: [u8; MAX_POST_LEN],
}

impl PostMeta {
    fn save(&self) {
        let slot = self.post_id % MAX_POST_RING;
        let clen = (self.content_len as usize).min(MAX_POST_LEN);
        let mut b = [0u8; 56 + MAX_POST_LEN];
        b[0..4].copy_from_slice(&self.post_id.to_le_bytes());
        b[4..24].copy_from_slice(&self.author);
        b[24] = self.author_uid;
        b[25] = self.visibility;
        b[26] = self.comment_count;
        b[28..30].copy_from_slice(&(clen as u16).to_le_bytes());
        b[32..40].copy_from_slice(&self.created_block.to_le_bytes());
        b[40..48].copy_from_slice(&self.liked_by_mask.to_le_bytes());
        b[48..56].copy_from_slice(&self.endorsed_by_mask.to_le_bytes());
        b[56..56 + clen].copy_from_slice(&self.content[..clen]);

        let k = key_post(slot);
        storage::set(k.as_slice(), &b[..56 + clen]);
    }

    fn load(slot: u32) -> Option<Self> {
        let k = key_post(slot);
        let mut b = [0u8; 56 + MAX_POST_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < 56 {
            return None;
        }
        let clen = (u16::from_le_bytes([b[28], b[29]]) as usize)
            .min(MAX_POST_LEN)
            .min(n - 56);
        let mut author = [0u8; 20];
        author.copy_from_slice(&b[4..24]);
        let mut content = [0u8; MAX_POST_LEN];
        content[..clen].copy_from_slice(&b[56..56 + clen]);

        Some(Self {
            post_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            author,
            author_uid: b[24],
            visibility: b[25],
            comment_count: b[26],
            created_block: u64::from_le_bytes(b[32..40].try_into().ok()?),
            liked_by_mask: u64::from_le_bytes(b[40..48].try_into().ok()?),
            endorsed_by_mask: u64::from_le_bytes(b[48..56].try_into().ok()?),
            content_len: clen as u16,
            content,
        })
    }
}

fn key_post(slot: u32) -> KeyBuilder<16> {
    KeyBuilder::<16>::new()
        .push(b"sf:p:")
        .push(&slot.to_le_bytes())
}

fn verify_scope_access(cfg: &FeedConfig, caller: &[u8; 20], post: &PostMeta) -> Result<(), i32> {
    if *caller == post.author {
        return Ok(());
    }
    match post.visibility as u64 {
        SCOPE_FRIENDS_ONLY => {
            if !query_active_connected(&cfg.relationships, caller, &post.author, REL_FRIEND)? {
                return Err(ERR_SOCIAL_NOT_CONNECTED);
            }
        }
        SCOPE_CLOSE_CIRCLE => {
            if !query_active_connected(&cfg.relationships, caller, &post.author, REL_CLOSE_CIRCLE)?
            {
                return Err(ERR_SOCIAL_NOT_CONNECTED);
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if FeedConfig::load().is_ok() {
        return Err(ERR_SOCIAL_ALREADY_INIT);
    }
    let charter = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let relationships = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let messaging = args.address(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if charter == [0u8; 20] || relationships == [0u8; 20] || messaging == [0u8; 20] {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    (FeedConfig {
        charter,
        relationships,
        messaging,
    })
    .save();
    Ok(())
}

fn handle_create_post(args: &CalldataReader) -> Result<(), i32> {
    let cfg = FeedConfig::load()?;
    let vis = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let body = args.dynamic_bytes(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if vis > SCOPE_CLOSE_CIRCLE || body.is_empty() || body.len() > MAX_POST_LEN {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let st = require_active_member(&cfg.charter, &caller, 20)?;

    // Persist into the protected Wall Feed channel on the core `Messaging` HFS!
    let wall_ch = derive_social_channel(b"SLX_WALL_CH1", &cfg.charter, vis);
    messaging_post_attributed::<512>(&cfg.messaging, &wall_ch, &caller, body)?;

    let post_id = storage::get_u64(KEY_TOTAL_POSTS) as u32;
    storage::set_u64(KEY_TOTAL_POSTS, (post_id as u64) + 1);

    let mut content = [0u8; MAX_POST_LEN];
    content[..body.len()].copy_from_slice(body);
    let post = PostMeta {
        post_id,
        author: caller,
        author_uid: st.uid,
        visibility: vis as u8,
        comment_count: 0,
        created_block: context::block_number(),
        liked_by_mask: 0,
        endorsed_by_mask: 0,
        content_len: body.len() as u16,
        content,
    };
    post.save();

    let mut ev = [0u8; 36];
    ev[0..8].copy_from_slice(&(post_id as u64).to_be_bytes());
    ev[8..28].copy_from_slice(&caller);
    ev[28..36].copy_from_slice(&vis.to_be_bytes());
    events::emit(&[EV_POST_PUBLISHED], &ev);
    Ok(())
}

fn handle_react_post(args: &CalldataReader) -> Result<(), i32> {
    let cfg = FeedConfig::load()?;
    let post_id = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)? as u32;
    let kind = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if kind != 1 && kind != 2 {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let total = storage::get_u64(KEY_TOTAL_POSTS) as u32;
    if post_id >= total {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let mut post = PostMeta::load(post_id % MAX_POST_RING).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if post.post_id != post_id {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let st = require_active_member(&cfg.charter, &caller, 15)?;
    verify_scope_access(&cfg, &caller, &post)?;

    if kind == 1 {
        post.liked_by_mask |= 1u64 << st.uid;
    } else {
        let was_set = (post.endorsed_by_mask & (1u64 << st.uid)) != 0;
        post.endorsed_by_mask |= 1u64 << st.uid;
        if !was_set && caller != post.author && st.trust_score >= 55 {
            let _ = adjust_standing_from_module(&cfg.charter, &post.author, 1, true);
        }
    }
    post.save();
    Ok(())
}

fn handle_comment_post(args: &CalldataReader) -> Result<(), i32> {
    let cfg = FeedConfig::load()?;
    let post_id = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)? as u32;
    let text = args.dynamic_bytes(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if text.is_empty() || text.len() > MAX_COMMENT_LEN {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let total = storage::get_u64(KEY_TOTAL_POSTS) as u32;
    if post_id >= total {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let mut post = PostMeta::load(post_id % MAX_POST_RING).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if post.post_id != post_id {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let _st = require_active_member(&cfg.charter, &caller, 15)?;
    verify_scope_access(&cfg, &caller, &post)?;

    // Store comment inside the core `Messaging` HFS under this post's protected comment channel!
    let cmt_ch = derive_social_channel(b"SLX_PCMT_CH1", &cfg.charter, post_id as u64);
    messaging_post_attributed::<512>(&cfg.messaging, &cmt_ch, &caller, text)?;

    post.comment_count = post.comment_count.saturating_add(1);
    post.save();
    Ok(())
}

fn handle_send_dm(args: &CalldataReader) -> Result<(), i32> {
    let cfg = FeedConfig::load()?;
    let recipient = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let msg = args.dynamic_bytes(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let caller = context::msg_sender();

    if caller == recipient || msg.is_empty() || msg.len() > MAX_DM_LEN {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let _st = require_active_member(&cfg.charter, &caller, 20)?;

    // Require BOTH an RF-verified connection AND both users Active In-Subnet!
    if !query_active_connected(&cfg.relationships, &caller, &recipient, REL_NEIGHBOR)? {
        return Err(ERR_SOCIAL_NOT_CONNECTED);
    }

    let dm_ch = canonical_dm_channel(&cfg.charter, &caller, &recipient);
    messaging_post_attributed::<1024>(&cfg.messaging, &dm_ch, &caller, msg)?;

    let mut ev = [0u8; 40];
    ev[0..20].copy_from_slice(&caller);
    ev[20..40].copy_from_slice(&recipient);
    events::emit(&[EV_DM_SENT, dm_ch], &ev);
    Ok(())
}

fn handle_get_dms(args: &CalldataReader) -> Result<i32, i32> {
    let cfg = FeedConfig::load()?;
    let peer_a = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let peer_b = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let max_count = args.u64(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?.min(32);

    let dm_ch = canonical_dm_channel(&cfg.charter, &peer_a, &peer_b);
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(FEED_OUT);
        let n = messaging_get_recent_into(&cfg.messaging, &dm_ch, max_count, out)?;
        ret::write(&out[..n]);
        Ok(n as i32)
    }
}

fn handle_get_feed_snapshot(_args: &CalldataReader) -> Result<i32, i32> {
    let Ok(cfg) = FeedConfig::load() else {
        ret::write(&[]);
        return Ok(0);
    };
    let total = storage::get_u64(KEY_TOTAL_POSTS) as u32;
    let count = total.min(MAX_POST_RING);

    unsafe {
        // Layout:
        // [0..4] = written_posts (u32 LE), [4..8] = total_posts (u32 LE)
        // Per post:
        //   post_id(4 LE) ++ author_uid(1) ++ vis(1) ++ fetched_cmts(1) ++ pad(1)
        //   ++ created_blk(8 LE) ++ liked_mask(8 LE) ++ endorsed_mask(8 LE) ++ clen(2 LE) ++ content
        //   ++ [per comment from Messaging: blk(8 LE) ++ author_addr(20) ++ len(2 LE) ++ bytes]
        let out = &mut *core::ptr::addr_of_mut!(FEED_OUT);
        let cmt_scratch = &mut *core::ptr::addr_of_mut!(CMT_TMP);
        let mut pos: usize = 8;
        let mut written: u32 = 0;

        let mut i: u32 = 0;
        while i < count {
            let pid = total - 1 - i;
            if let Some(p) = PostMeta::load(pid % MAX_POST_RING) {
                if p.post_id == pid {
                    let clen = p.content_len as usize;
                    if pos + 34 + clen + 512 > out.len() {
                        break;
                    }

                    // Fetch up to 8 comments from `Messaging` HFS!
                    let mut cmt_bytes_len = 0usize;
                    let mut cmt_cnt: u8 = 0;
                    if p.comment_count > 0 {
                        let cmt_ch =
                            derive_social_channel(b"SLX_PCMT_CH1", &cfg.charter, pid as u64);
                        if let Ok(cn) =
                            messaging_get_recent_into(&cfg.messaging, &cmt_ch, 8, cmt_scratch)
                        {
                            if cn >= 4 {
                                cmt_cnt = u32::from_le_bytes([
                                    cmt_scratch[0],
                                    cmt_scratch[1],
                                    cmt_scratch[2],
                                    cmt_scratch[3],
                                ])
                                .min(8) as u8;
                                cmt_bytes_len = cn - 4;
                            }
                        }
                    }

                    if pos + 34 + clen + cmt_bytes_len > out.len() {
                        break;
                    }

                    out[pos..pos + 4].copy_from_slice(&p.post_id.to_le_bytes());
                    out[pos + 4] = p.author_uid;
                    out[pos + 5] = p.visibility;
                    out[pos + 6] = cmt_cnt;
                    out[pos + 7] = 0;
                    out[pos + 8..pos + 16].copy_from_slice(&p.created_block.to_le_bytes());
                    out[pos + 16..pos + 24].copy_from_slice(&p.liked_by_mask.to_le_bytes());
                    out[pos + 24..pos + 32].copy_from_slice(&p.endorsed_by_mask.to_le_bytes());
                    out[pos + 32..pos + 34].copy_from_slice(&p.content_len.to_le_bytes());
                    pos += 34;
                    out[pos..pos + clen].copy_from_slice(&p.content[..clen]);
                    pos += clen;

                    if cmt_bytes_len > 0 {
                        out[pos..pos + cmt_bytes_len]
                            .copy_from_slice(&cmt_scratch[4..4 + cmt_bytes_len]);
                        pos += cmt_bytes_len;
                    }
                    written += 1;
                }
            }
            i += 1;
        }

        out[0..4].copy_from_slice(&written.to_le_bytes());
        out[4..8].copy_from_slice(&total.to_le_bytes());
        ret::write(&out[..pos]);
        Ok(pos as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::social::{MemberStanding, ERR_SOCIAL_NOT_CONNECTED};
    use hps_sdk::{mock, selector};

    fn mock_charter(cd: &[u8]) -> i32 {
        let Some((sel, args)) = CalldataReader::parse(cd) else {
            return -1;
        };
        if sel == const { selector("memberStanding(address)") } {
            let u = args.address(0).unwrap();
            ret::write_u64_word(
                (MemberStanding {
                    registered: true,
                    is_active: true,
                    sanctioned: false,
                    trust_score: 75,
                    uid: u[19],
                })
                .pack(),
            );
            0
        } else if sel == const { selector("adjustStandingFromModule(address,uint64,bool)") } {
            0
        } else {
            -1
        }
    }

    fn mock_rel(cd: &[u8]) -> i32 {
        let Some((sel, args)) = CalldataReader::parse(cd) else {
            return -1;
        };
        if sel == const { selector("areActiveConnected(address,address,uint64)") } {
            let a = args.address(0).unwrap();
            let b = args.address(1).unwrap();
            // Only uid 1 and uid 2 are RF friends!
            ret::write_bool((a[19] == 1 && b[19] == 2) || (a[19] == 2 && b[19] == 1));
            0
        } else {
            -1
        }
    }

    fn mock_msg(cd: &[u8]) -> i32 {
        let Some((sel, _)) = CalldataReader::parse(cd) else {
            return -1;
        };
        if sel == const { selector("channelController(bytes32)") } {
            ret::write_address(&[0u8; 20]);
            0
        } else if sel == const { selector("bindChannelController(bytes32,address)") }
            || sel == const { selector("postAttributedMessage(bytes32,address,bytes)") }
        {
            0
        } else if sel == const { selector("getRecentMessages(bytes32,uint64)") } {
            ret::write(&0u32.to_le_bytes());
            0
        } else {
            -1
        }
    }

    #[test]
    fn enforces_proximity_dm_and_friends_only_feed_via_messaging_hps() {
        mock::reset();
        let charter = [0xC1; 20];
        let rel = [0xC2; 20];
        let msg = [0xC3; 20];
        let feed = [0xC4; 20];
        let alice = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let bob_friend = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let stranger = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

        mock::register_hps(charter, mock_charter);
        mock::register_hps(rel, mock_rel);
        mock::register_hps(msg, mock_msg);
        mock::register_hps(feed, dispatch_calldata);

        mock::transact_as(
            alice,
            feed,
            CallEncoder::<160>::new(const { selector("initialize(address,address,address)") })
                .push_address(&charter)
                .push_address(&rel)
                .push_address(&msg)
                .as_slice(),
        )
        .unwrap();

        // Stranger without RF relationship cannot DM Alice!
        assert_eq!(
            mock::transact_as(
                stranger,
                feed,
                CallEncoder::<256>::new(const { selector("sendDirectMessage(address,bytes)") })
                    .push_address(&alice)
                    .push_u64(0x40)
                    .push_dynamic_bytes_tail(b"Cold spam DM!")
                    .as_slice(),
            ),
            Err(ERR_SOCIAL_NOT_CONNECTED)
        );

        // RF Friend Bob CAN DM Alice via Messaging HFS!
        mock::transact_as(
            bob_friend,
            feed,
            CallEncoder::<256>::new(const { selector("sendDirectMessage(address,bytes)") })
                .push_address(&alice)
                .push_u64(0x40)
                .push_dynamic_bytes_tail(b"Want Kopi at Blk 29?")
                .as_slice(),
        )
        .unwrap();
    }
}
