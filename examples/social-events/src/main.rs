//! # `SocialEvents` — Neighborhood Meetups & RF Proof-of-Attendance (`social-events` — HPS #14D)
//!
//! Pinned to `SocialCharter`, `SocialRelationships`, and the `Messaging` HFS (`CAP_SOCIAL_EVENTS`):
//! - Verified neighbors (`trust >= 50`) host local meetups/events at physical coordinates `(venue_x, venue_y)`.
//! - Active in-subnet neighbors RSVP and chat via protected `Messaging` event channels.
//! - **`checkInEvent(eventId)`**: Verifies `start_block <= block_number <= end_block` AND calls
//!   `SocialCharter.checkVenueRfProximity(caller, venue_x, venue_y)` so **only people physically
//!   standing within `<=150m` `2.4 GHz` radio range of the venue** earn Proof-of-Attendance (`+2 Trust`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::social::{
    adjust_standing_from_module, derive_social_channel, messaging_get_recent_into,
    messaging_post_attributed, query_active_connected, require_active_member,
    require_venue_rf_proximity, ERR_SOCIAL_ALREADY_INIT, ERR_SOCIAL_DUPLICATE_ACTION,
    ERR_SOCIAL_EVENT_WINDOW, ERR_SOCIAL_INVALID_ARGS, ERR_SOCIAL_NOT_CONNECTED,
    ERR_SOCIAL_UNINITIALIZED, REL_FRIEND, SCOPE_FRIENDS_ONLY,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

pub const MAX_EVENT_RING: u32 = 16;
pub const MAX_EVENT_META_LEN: usize = 220;
pub const MAX_CHAT_LEN: usize = 180;

const KEY_CFG: &[u8] = b"se:cfg";
const KEY_TOTAL_EVENTS: &[u8] = b"se:cnt";

const EV_EVENT_CREATED: [u8; 32] =
    event_topic("SocialEventCreated(uint64,address,uint64,uint64)");
const EV_EVENT_CHECKIN: [u8; 32] =
    event_topic("SocialEventCheckedIn(uint64,address,uint64)");

static mut EVT_OUT: [u8; 16_384] = [0u8; 16_384];
static mut EVT_CHAT_TMP: [u8; 2048] = [0u8; 2048];

hps_entry! {
    "initialize(address,address,address)"                                   => handle_initialize,
    "createEvent(uint64,uint64,uint64,uint64,uint64,bytes)"                 => handle_create_event,
    "rsvpEvent(uint64)"                                                     => handle_rsvp_event,
    "checkInEvent(uint64)"                                                  => handle_checkin_event,
    "postEventChat(uint64,bytes)"                                           => handle_post_chat,
    "getEventsSnapshot()"                                                   => handle_get_snapshot,
}

#[derive(Clone, Copy)]
struct EventsConfig {
    charter: [u8; 20],
    relationships: [u8; 20],
    messaging: [u8; 20],
}

impl EventsConfig {
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

struct EventRecord {
    event_id: u32,
    host: [u8; 20],
    host_uid: u8,
    visibility: u8,
    chat_count: u8,
    venue_x: u16,
    venue_y: u16,
    start_block: u64,
    end_block: u64,
    rsvp_mask: u64,
    attended_mask: u64,
    meta_len: u16,
    meta: [u8; MAX_EVENT_META_LEN],
}

impl EventRecord {
    fn save(&self) {
        let slot = self.event_id % MAX_EVENT_RING;
        let mlen = (self.meta_len as usize).min(MAX_EVENT_META_LEN);
        let mut b = [0u8; 68 + MAX_EVENT_META_LEN];
        b[0..4].copy_from_slice(&self.event_id.to_le_bytes());
        b[4..24].copy_from_slice(&self.host);
        b[24] = self.host_uid;
        b[25] = self.visibility;
        b[26] = self.chat_count;
        b[28..30].copy_from_slice(&self.venue_x.to_le_bytes());
        b[30..32].copy_from_slice(&self.venue_y.to_le_bytes());
        b[32..40].copy_from_slice(&self.start_block.to_le_bytes());
        b[40..48].copy_from_slice(&self.end_block.to_le_bytes());
        b[48..56].copy_from_slice(&self.rsvp_mask.to_le_bytes());
        b[56..64].copy_from_slice(&self.attended_mask.to_le_bytes());
        b[64..66].copy_from_slice(&(mlen as u16).to_le_bytes());
        b[68..68 + mlen].copy_from_slice(&self.meta[..mlen]);

        let k = key_event(slot);
        storage::set(k.as_slice(), &b[..68 + mlen]);
    }

    fn load(slot: u32) -> Option<Self> {
        let k = key_event(slot);
        let mut b = [0u8; 68 + MAX_EVENT_META_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < 68 {
            return None;
        }
        let mlen = (u16::from_le_bytes([b[64], b[65]]) as usize)
            .min(MAX_EVENT_META_LEN)
            .min(n - 68);
        let mut host = [0u8; 20];
        host.copy_from_slice(&b[4..24]);
        let mut meta = [0u8; MAX_EVENT_META_LEN];
        meta[..mlen].copy_from_slice(&b[68..68 + mlen]);

        Some(Self {
            event_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            host,
            host_uid: b[24],
            visibility: b[25],
            chat_count: b[26],
            venue_x: u16::from_le_bytes([b[28], b[29]]),
            venue_y: u16::from_le_bytes([b[30], b[31]]),
            start_block: u64::from_le_bytes(b[32..40].try_into().ok()?),
            end_block: u64::from_le_bytes(b[40..48].try_into().ok()?),
            rsvp_mask: u64::from_le_bytes(b[48..56].try_into().ok()?),
            attended_mask: u64::from_le_bytes(b[56..64].try_into().ok()?),
            meta_len: mlen as u16,
            meta,
        })
    }
}

fn key_event(slot: u32) -> KeyBuilder<16> {
    KeyBuilder::<16>::new()
        .push(b"se:e:")
        .push(&slot.to_le_bytes())
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if EventsConfig::load().is_ok() {
        return Err(ERR_SOCIAL_ALREADY_INIT);
    }
    let charter = args.address(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let relationships = args.address(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let messaging = args.address(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if charter == [0u8; 20] || relationships == [0u8; 20] || messaging == [0u8; 20] {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    (EventsConfig {
        charter,
        relationships,
        messaging,
    })
    .save();
    Ok(())
}

fn handle_create_event(args: &CalldataReader) -> Result<(), i32> {
    let cfg = EventsConfig::load()?;
    let vx = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let vy = args.u64(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let start_blk = args.u64(2).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let end_blk = args.u64(3).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let vis = args.u64(4).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    let meta_slice = args.dynamic_bytes(5).ok_or(ERR_SOCIAL_INVALID_ARGS)?;

    if vx > 10_000
        || vy > 10_000
        || end_blk < start_blk
        || vis > SCOPE_FRIENDS_ONLY
        || meta_slice.is_empty()
        || meta_slice.len() > MAX_EVENT_META_LEN
    {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let st = require_active_member(&cfg.charter, &caller, 50)?;

    let event_id = storage::get_u64(KEY_TOTAL_EVENTS) as u32;
    storage::set_u64(KEY_TOTAL_EVENTS, (event_id as u64) + 1);

    let ev_ch = derive_social_channel(b"SLX_EVNT_CH1", &cfg.charter, event_id as u64);
    messaging_post_attributed::<512>(&cfg.messaging, &ev_ch, &caller, meta_slice)?;

    let mut meta = [0u8; MAX_EVENT_META_LEN];
    meta[..meta_slice.len()].copy_from_slice(meta_slice);
    let rec = EventRecord {
        event_id,
        host: caller,
        host_uid: st.uid,
        visibility: vis as u8,
        chat_count: 1,
        venue_x: vx as u16,
        venue_y: vy as u16,
        start_block: start_blk,
        end_block: end_blk,
        rsvp_mask: 1u64 << st.uid,
        attended_mask: 0,
        meta_len: meta_slice.len() as u16,
        meta,
    };
    rec.save();

    let mut ev = [0u8; 44];
    ev[0..8].copy_from_slice(&(event_id as u64).to_be_bytes());
    ev[8..28].copy_from_slice(&caller);
    ev[28..36].copy_from_slice(&vx.to_be_bytes());
    ev[36..44].copy_from_slice(&vy.to_be_bytes());
    events::emit(&[EV_EVENT_CREATED], &ev);
    Ok(())
}

fn verify_event_access(cfg: &EventsConfig, caller: &[u8; 20], ev: &EventRecord) -> Result<(), i32> {
    if *caller != ev.host && (ev.visibility as u64) == SCOPE_FRIENDS_ONLY {
        if !query_active_connected(&cfg.relationships, caller, &ev.host, REL_FRIEND)? {
            return Err(ERR_SOCIAL_NOT_CONNECTED);
        }
    }
    Ok(())
}

fn handle_rsvp_event(args: &CalldataReader) -> Result<(), i32> {
    let cfg = EventsConfig::load()?;
    let event_id = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)? as u32;
    let total = storage::get_u64(KEY_TOTAL_EVENTS) as u32;
    if event_id >= total {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let mut rec = EventRecord::load(event_id % MAX_EVENT_RING).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if rec.event_id != event_id {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let st = require_active_member(&cfg.charter, &caller, 20)?;
    verify_event_access(&cfg, &caller, &rec)?;

    rec.rsvp_mask |= 1u64 << st.uid;
    rec.save();
    Ok(())
}

fn handle_checkin_event(args: &CalldataReader) -> Result<(), i32> {
    let cfg = EventsConfig::load()?;
    let event_id = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)? as u32;
    let total = storage::get_u64(KEY_TOTAL_EVENTS) as u32;
    if event_id >= total {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let mut rec = EventRecord::load(event_id % MAX_EVENT_RING).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if rec.event_id != event_id {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let blk = context::block_number();
    if blk < rec.start_block || blk > rec.end_block {
        return Err(ERR_SOCIAL_EVENT_WINDOW);
    }

    let caller = context::msg_sender();
    let st = require_active_member(&cfg.charter, &caller, 20)?;
    verify_event_access(&cfg, &caller, &rec)?;

    if (rec.attended_mask & (1u64 << st.uid)) != 0 {
        return Err(ERR_SOCIAL_DUPLICATE_ACTION);
    }

    // Physical Proof-of-Attendance: caller's radio MUST be within <=150m 2.4 GHz range of venue!
    require_venue_rf_proximity(&cfg.charter, &caller, rec.venue_x as u64, rec.venue_y as u64)?;

    rec.rsvp_mask |= 1u64 << st.uid;
    rec.attended_mask |= 1u64 << st.uid;
    rec.save();

    let _ = adjust_standing_from_module(&cfg.charter, &caller, 2, true);

    let mut ev = [0u8; 36];
    ev[0..8].copy_from_slice(&(event_id as u64).to_be_bytes());
    ev[8..28].copy_from_slice(&caller);
    ev[28..36].copy_from_slice(&blk.to_be_bytes());
    events::emit(&[EV_EVENT_CHECKIN], &ev);
    Ok(())
}

fn handle_post_chat(args: &CalldataReader) -> Result<(), i32> {
    let cfg = EventsConfig::load()?;
    let event_id = args.u64(0).ok_or(ERR_SOCIAL_INVALID_ARGS)? as u32;
    let msg = args.dynamic_bytes(1).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if msg.is_empty() || msg.len() > MAX_CHAT_LEN {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let total = storage::get_u64(KEY_TOTAL_EVENTS) as u32;
    if event_id >= total {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }
    let mut rec = EventRecord::load(event_id % MAX_EVENT_RING).ok_or(ERR_SOCIAL_INVALID_ARGS)?;
    if rec.event_id != event_id {
        return Err(ERR_SOCIAL_INVALID_ARGS);
    }

    let caller = context::msg_sender();
    let _st = require_active_member(&cfg.charter, &caller, 20)?;
    verify_event_access(&cfg, &caller, &rec)?;

    let ev_ch = derive_social_channel(b"SLX_EVNT_CH1", &cfg.charter, event_id as u64);
    messaging_post_attributed::<512>(&cfg.messaging, &ev_ch, &caller, msg)?;

    rec.chat_count = rec.chat_count.saturating_add(1);
    rec.save();
    Ok(())
}

fn handle_get_snapshot(_args: &CalldataReader) -> Result<i32, i32> {
    let Ok(cfg) = EventsConfig::load() else {
        ret::write(&[]);
        return Ok(0);
    };
    let total = storage::get_u64(KEY_TOTAL_EVENTS) as u32;
    let count = total.min(MAX_EVENT_RING);

    unsafe {
        // Layout:
        // [0..4] = written_events (u32 LE), [4..8] = total_events (u32 LE)
        // Per event:
        //   event_id(4 LE) ++ host_uid(1) ++ vis(1) ++ chat_cnt(1) ++ pad(1)
        //   ++ venue_x(2 LE) ++ venue_y(2 LE) ++ start_blk(8 LE) ++ end_blk(8 LE)
        //   ++ rsvp_mask(8 LE) ++ attended_mask(8 LE) ++ mlen(2 LE) ++ meta
        //   ++ [recent chats from Messaging: blk(8 LE) ++ author(20) ++ len(2 LE) ++ bytes]*
        let out = &mut *core::ptr::addr_of_mut!(EVT_OUT);
        let chat_tmp = &mut *core::ptr::addr_of_mut!(EVT_CHAT_TMP);
        let mut pos: usize = 8;
        let mut written: u32 = 0;

        let mut i: u32 = 0;
        while i < count {
            let eid = total - 1 - i;
            if let Some(e) = EventRecord::load(eid % MAX_EVENT_RING) {
                if e.event_id == eid {
                    let mlen = e.meta_len as usize;
                    let mut chat_cnt: u8 = 0;
                    let mut chat_bytes = 0usize;
                    if e.chat_count > 0 {
                        let ev_ch =
                            derive_social_channel(b"SLX_EVNT_CH1", &cfg.charter, eid as u64);
                        if let Ok(cn) =
                            messaging_get_recent_into(&cfg.messaging, &ev_ch, 5, chat_tmp)
                        {
                            if cn >= 4 {
                                chat_cnt = u32::from_le_bytes([
                                    chat_tmp[0],
                                    chat_tmp[1],
                                    chat_tmp[2],
                                    chat_tmp[3],
                                ])
                                .min(5) as u8;
                                chat_bytes = cn - 4;
                            }
                        }
                    }

                    if pos + 46 + mlen + chat_bytes > out.len() {
                        break;
                    }
                    out[pos..pos + 4].copy_from_slice(&e.event_id.to_le_bytes());
                    out[pos + 4] = e.host_uid;
                    out[pos + 5] = e.visibility;
                    out[pos + 6] = chat_cnt;
                    out[pos + 7] = 0;
                    out[pos + 8..pos + 10].copy_from_slice(&e.venue_x.to_le_bytes());
                    out[pos + 10..pos + 12].copy_from_slice(&e.venue_y.to_le_bytes());
                    out[pos + 12..pos + 20].copy_from_slice(&e.start_block.to_le_bytes());
                    out[pos + 20..pos + 28].copy_from_slice(&e.end_block.to_le_bytes());
                    out[pos + 28..pos + 36].copy_from_slice(&e.rsvp_mask.to_le_bytes());
                    out[pos + 36..pos + 44].copy_from_slice(&e.attended_mask.to_le_bytes());
                    out[pos + 44..pos + 46].copy_from_slice(&e.meta_len.to_le_bytes());
                    pos += 46;
                    out[pos..pos + mlen].copy_from_slice(&e.meta[..mlen]);
                    pos += mlen;
                    if chat_bytes > 0 {
                        out[pos..pos + chat_bytes].copy_from_slice(&chat_tmp[4..4 + chat_bytes]);
                        pos += chat_bytes;
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
    use hps_sdk::social::{MemberStanding, ERR_SOCIAL_OUTSIDE_RF_RANGE};
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
        } else if sel == const { selector("checkVenueRfProximity(address,uint64,uint64)") } {
            ret::write_bool(storage::get_u64(b"at_venue") == 1);
            0
        } else if sel == const { selector("adjustStandingFromModule(address,uint64,bool)") } {
            0
        } else {
            -1
        }
    }

    fn mock_rel(_cd: &[u8]) -> i32 {
        ret::write_bool(true);
        0
    }

    fn mock_msg(cd: &[u8]) -> i32 {
        let Some((sel, _)) = CalldataReader::parse(cd) else {
            return -1;
        };
        if sel == const { selector("channelController(bytes32)") } {
            ret::write_address(&[0u8; 20]);
            0
        } else {
            0
        }
    }

    #[test]
    fn event_checkin_requires_physical_rf_proximity_at_venue() {
        mock::reset();
        let charter = [0xC1; 20];
        let rel = [0xC2; 20];
        let msg = [0xC3; 20];
        let ev_mod = [0xC6; 20];
        let host = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let attendee = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        mock::register_hps(charter, mock_charter);
        mock::register_hps(rel, mock_rel);
        mock::register_hps(msg, mock_msg);
        mock::register_hps(ev_mod, dispatch_calldata);
        mock::set_block_number(100);

        mock::transact_as(
            host,
            ev_mod,
            CallEncoder::<160>::new(const { selector("initialize(address,address,address)") })
                .push_address(&charter)
                .push_address(&rel)
                .push_address(&msg)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            host,
            ev_mod,
            CallEncoder::<512>::new(const {
                selector("createEvent(uint64,uint64,uint64,uint64,uint64,bytes)")
            })
            .push_u64(1550)
            .push_u64(1500)
            .push_u64(95)
            .push_u64(130)
            .push_u64(0)
            .push_u64(0xC0)
            .push_dynamic_bytes_tail(b"Morning Tai Chi|Blk 29 Amphitheatre")
            .as_slice(),
        )
        .unwrap();

        // Far from venue -> check-in rejected!
        assert_eq!(
            mock::transact_as(
                attendee,
                ev_mod,
                CallEncoder::<96>::new(const { selector("checkInEvent(uint64)") })
                    .push_u64(0)
                    .as_slice(),
            ),
            Err(ERR_SOCIAL_OUTSIDE_RF_RANGE)
        );

        // Within <=150m 2.4 GHz of venue -> check-in succeeds!
        mock::set_self_address(charter);
        storage::set_u64(b"at_venue", 1);
        mock::transact_as(
            attendee,
            ev_mod,
            CallEncoder::<96>::new(const { selector("checkInEvent(uint64)") })
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
    }
}
