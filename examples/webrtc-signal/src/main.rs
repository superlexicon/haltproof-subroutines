//! Serverless WebRTC Voice, Video & Mesh Conference Signaling Registry (`webrtc-signal`, HPS #28).
//!
//! Replaces centralized cloud WebRTC signaling servers (Socket.io, Twilio, AWS API Gateway, Firebase)
//! with a deterministic `#![no_std]` Haltproof Subroutine on SuperLexicon:
//!
//! 1. **Identity-Authenticated Peer Directory & E2EE Signaling Keys (`registerRtcProfile`)**:
//!    - Maps a caller-verified `Identity` HFS (`msg.sender == identity` or `Identity.owner()` /
//!      `Identity.isOwnerDevice(msg.sender)`) to their compressed `secp256k1` signaling encryption
//!      public key (`secpPubX`, `secpPubParity`), human-readable call handle, STUN/LAN hint, and
//!      live availability (`Online`, `Busy`, `DND`, `Offline`).
//!    - Callers encrypt SDP Offer/Answer + ICE candidate payloads via `secp256k1` ECDH so IP
//!      addresses, UDP ports, and `ice-ufrag`/`ice-pwd` credentials remain confidential on-chain!
//!
//! 2. **Zero-CA DTLS-SRTP Identity Binding (`callerDtlsFp` & `calleeDtlsFp`)**:
//!    - Traditional WebRTC trusts a centralized signaling server not to swap `a=fingerprint:sha-256`
//!      lines in SDP (MITM attack). Here, both peers commit their 32-byte `sha-256` DTLS certificate
//!      fingerprints directly inside `placeCall` and `answerCall` under `Identity` HFS authentication.
//!    - Browsers verify `extractSdpSha256Fingerprint(remoteSdp) === onChainPeerDtlsFp` before
//!      unmuting media or opening `RTCDataChannel`, making P2P voice/video cryptographically MITM-proof!
//!
//! 3. **Sub-Block Event-Driven 1:1 Calls & Multi-Peer Mesh Rooms**:
//!    - Emits indexed EVM logs (`CallRinging`, `CallAnswered`, `CallIceUpdated`, `CallMediaUpdated`,
//!      `CallEnded`, `RoomPeerJoined`, `RoomSignalPosted`) so WebSocket `eth_subscribe("logs")`
//!      wakes peers in `< 1 block` with `$0.00` gas fees and zero polling servers.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const WEBRTC_SIGNAL_ABI_VERSION: u64 = 1;

pub const AVAIL_OFFLINE: u8 = 0;
pub const AVAIL_ONLINE: u8 = 1;
pub const AVAIL_BUSY: u8 = 2;
pub const AVAIL_DND: u8 = 3;

pub const MEDIA_VOICE: u8 = 1;
pub const MEDIA_VIDEO: u8 = 2;
pub const MEDIA_SCREEN: u8 = 3;

pub const CALL_STATUS_RINGING: u8 = 1;
pub const CALL_STATUS_ACTIVE: u8 = 2;
pub const CALL_STATUS_DECLINED: u8 = 3;
pub const CALL_STATUS_CANCELED: u8 = 4;
pub const CALL_STATUS_ENDED: u8 = 5;

pub const RENEG_NONE: u8 = 0;
pub const RENEG_CALLER_OFFER: u8 = 1;
pub const RENEG_CALLEE_OFFER: u8 = 2;
pub const RENEG_ANSWERED: u8 = 3;

pub const ROOM_STATUS_OPEN: u8 = 1;
pub const ROOM_STATUS_CLOSED: u8 = 2;

pub const MAX_DISPLAY_LABEL_LEN: usize = 48;
pub const MAX_STUN_HINT_LEN: usize = 96;
pub const MAX_SDP_ENVELOPE_BYTES: usize = 8_192;
pub const MAX_ICE_BATCH_BYTES: usize = 2_048;
pub const MAX_ICE_BATCHES_PER_SIDE: u64 = 8;
pub const MAX_RECENT_CALLS_PER_IDENTITY: u64 = 16;
pub const MAX_DIRECTORY_SLICE: u64 = 32;

pub const MAX_ROOM_TITLE_LEN: usize = 64;
pub const MAX_ROOM_PEERS: usize = 6;
pub const MAX_ROOMS_SLICE: u64 = 24;

/// Peer profile fixed header:
/// `[identity:20][secp_pub_x:32][parity:1][avail:1][updated_blk:8][total_calls:4][lbl_len:2][hint_len:2]` = 70 B
pub const PEER_REC_HDR: usize = 70;
pub const MAX_PEER_REC_BYTES: usize = PEER_REC_HDR + MAX_DISPLAY_LABEL_LEN + MAX_STUN_HINT_LEN;

/// Fixed 1:1 call metadata record:
/// `[call_id:8][caller:20][callee:20][status:1][media:1][end_reason:1][reneg_side:1]`
/// `[caller_ice_cnt:2][callee_ice_cnt:2][reneg_seq:2][reserved:2]`
/// `[caller_dtls_fp:32][callee_dtls_fp:32][created_blk:8][answered_blk:8][updated_blk:8]` = 148 B
pub const CALL_META_LEN: usize = 148;

/// Room peer entry: `[peer_identity:20][dtls_fp:32][joined_blk:8]` = 60 B
pub const ROOM_PEER_ENTRY_LEN: usize = 60;
/// Room fixed header:
/// `[room_id:8][host:20][status:1][media:1][e2ee_req:1][peer_cnt:1][created_blk:8][updated_blk:8][title_len:2]` = 50 B
pub const ROOM_HDR_LEN: usize = 50;
pub const MAX_ROOM_REC_BYTES: usize =
    ROOM_HDR_LEN + MAX_ROOM_TITLE_LEN + MAX_ROOM_PEERS * ROOM_PEER_ENTRY_LEN;

pub const ERR_BAD_ARGS: i32 = -10;
pub const ERR_ALREADY_INIT: i32 = -11;
pub const ERR_NOT_ADMIN: i32 = -12;
pub const ERR_UNAUTHORIZED_IDENTITY: i32 = -14;
pub const ERR_CALL_NOT_FOUND: i32 = -20;
pub const ERR_INVALID_CALL_STATE: i32 = -21;
pub const ERR_ICE_BATCH_LIMIT: i32 = -22;
pub const ERR_ENVELOPE_TOO_LARGE: i32 = -23;
pub const ERR_ROOM_NOT_FOUND: i32 = -30;
pub const ERR_ROOM_CLOSED: i32 = -31;
pub const ERR_ROOM_FULL: i32 = -32;
pub const ERR_NOT_IN_ROOM: i32 = -33;

const KEY_INIT: &[u8] = b"rtc:init";
const KEY_ADMIN: &[u8] = b"rtc:admin";
const KEY_TOTAL_PROFILES: &[u8] = b"rtc:tot_prof";
const KEY_TOTAL_CALLS: &[u8] = b"rtc:tot_calls";
const KEY_TOTAL_ROOMS: &[u8] = b"rtc:tot_rooms";

const SEL_ID_OWNER: [u8; 4] = selector("owner()");
const SEL_ID_IS_DEVICE: [u8; 4] = selector("isOwnerDevice(address)");

const EV_INITIALIZED: [u8; 32] = event_topic("WebRtcHubInitialized(address)");
const EV_PROFILE_UPDATED: [u8; 32] = event_topic("RtcProfileUpdated(address,uint64,bytes32)");
const EV_CALL_RINGING: [u8; 32] = event_topic("CallRinging(uint64,address,address,uint64)");
const EV_CALL_ANSWERED: [u8; 32] = event_topic("CallAnswered(uint64,address,address)");
const EV_CALL_ICE_UPDATED: [u8; 32] = event_topic("CallIceUpdated(uint64,address,uint64)");
const EV_CALL_MEDIA_UPDATED: [u8; 32] =
    event_topic("CallMediaUpdated(uint64,address,uint64,uint64,uint64)");
const EV_CALL_ENDED: [u8; 32] = event_topic("CallEnded(uint64,address,uint64,uint64)");
const EV_ROOM_CREATED: [u8; 32] = event_topic("RoomCreated(uint64,address,uint64)");
const EV_ROOM_PEER_JOINED: [u8; 32] = event_topic("RoomPeerJoined(uint64,address,uint64)");
const EV_ROOM_PEER_LEFT: [u8; 32] = event_topic("RoomPeerLeft(uint64,address,uint64)");
const EV_ROOM_SIGNAL_POSTED: [u8; 32] =
    event_topic("RoomSignalPosted(uint64,address,address)");

const OUT_SCRATCH_CAP: usize = 65_536;
static mut OUT_SCRATCH: [u8; OUT_SCRATCH_CAP] = [0u8; OUT_SCRATCH_CAP];

hps_entry! {
    "initialize(address)"                                                       => handle_initialize,
    "abiVersion()"                                                              => handle_abi_version,
    "admin()"                                                                   => handle_admin,
    "getHubOverview()"                                                          => handle_get_hub_overview,
    "registerRtcProfile(address,bytes32,uint64,uint64,string,string)"           => handle_register_rtc_profile,
    "heartbeatPresence(address,uint64)"                                         => handle_heartbeat_presence,
    "getPeerProfile(address)"                                                   => handle_get_peer_profile,
    "getDirectorySlice(uint64,uint64)"                                          => handle_get_directory_slice,
    "placeCall(address,address,uint64,bytes32,bytes)"                           => handle_place_call,
    "answerCall(uint64,address,bytes32,bytes)"                                  => handle_answer_call,
    "appendIceBatch(uint64,address,bytes)"                                      => handle_append_ice_batch,
    "renegotiateMedia(uint64,address,uint64,bool,bytes)"                        => handle_renegotiate_media,
    "endCall(uint64,address,uint64)"                                            => handle_end_call,
    "getCallSession(uint64)"                                                    => handle_get_call_session,
    "getRecentCallsForIdentity(address)"                                        => handle_get_recent_calls_for_identity,
    "createRoom(address,string,uint64,bool,bytes32)"                            => handle_create_room,
    "joinRoom(uint64,address,bytes32)"                                          => handle_join_room,
    "leaveRoom(uint64,address)"                                                 => handle_leave_room,
    "postRoomSignal(uint64,address,address,uint64,bytes)"                       => handle_post_room_signal,
    "getRoomState(uint64)"                                                      => handle_get_room_state,
    "getRoomsSlice(uint64,uint64)"                                              => handle_get_rooms_slice,
    "getPairSignal(uint64,address,address)"                                     => handle_get_pair_signal,
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

fn u64_word(val: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&val.to_be_bytes());
    w
}

fn get_admin() -> [u8; 20] {
    storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20])
}

fn is_authorized_for_identity(caller: &[u8; 20], identity_addr: &[u8; 20]) -> bool {
    if *identity_addr == [0u8; 20] {
        return false;
    }
    if caller == identity_addr {
        return true;
    }
    let owner_cd = CallEncoder::<16>::new(SEL_ID_OWNER);
    if let Ok(raw) = call::call_raw(identity_addr, owner_cd.as_slice()) {
        if raw.len() >= 32 && raw[0..12] == [0u8; 12] && &raw[12..32] == caller {
            return true;
        }
    }
    let dev_cd = CallEncoder::<64>::new(SEL_ID_IS_DEVICE).push_address(caller);
    if let Ok(true) = call::call_bool(identity_addr, dev_cd.as_slice()) {
        return true;
    }
    false
}

fn prof_idx_to_addr_key(idx: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"pi:").push_u64_be(idx)
}

fn prof_rec_key(identity: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"pr:").push(identity)
}

fn prof_seen_key(identity: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"ps:").push(identity)
}

fn call_meta_key(call_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"cm:").push_u64_be(call_id)
}

fn call_offer_key(call_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"co:").push_u64_be(call_id)
}

fn call_answer_key(call_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"ca:").push_u64_be(call_id)
}

fn call_reneg_key(call_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"cr:").push_u64_be(call_id)
}

fn call_ice_key(call_id: u64, is_callee: bool, batch_idx: u16) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(if is_callee { b"cia:" } else { b"cic:" })
        .push_u64_be(call_id)
        .push(&(batch_idx as u64).to_be_bytes())
}

fn id_recent_cnt_key(identity: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"irc:").push(identity)
}

fn id_recent_slot_key(identity: &[u8; 20], slot: u64) -> KeyBuilder<56> {
    KeyBuilder::<56>::new()
        .push(b"irs:")
        .push(identity)
        .push_u64_be(slot)
}

fn room_rec_key(room_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"rm:").push_u64_be(room_id)
}

fn pair_sig_key(room_id: u64, from_id: &[u8; 20], to_id: &[u8; 20]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new()
        .push(b"rs:")
        .push_u64_be(room_id)
        .push(from_id)
        .push(to_id)
}

#[derive(Clone, Copy)]
struct CallMeta {
    call_id: u64,
    caller: [u8; 20],
    callee: [u8; 20],
    status: u8,
    media_kind: u8,
    end_reason: u8,
    reneg_side: u8,
    caller_ice_cnt: u16,
    callee_ice_cnt: u16,
    reneg_seq: u16,
    caller_dtls_fp: [u8; 32],
    callee_dtls_fp: [u8; 32],
    created_blk: u64,
    answered_blk: u64,
    updated_blk: u64,
}

impl CallMeta {
    fn encode(&self) -> [u8; CALL_META_LEN] {
        let mut b = [0u8; CALL_META_LEN];
        b[0..8].copy_from_slice(&self.call_id.to_be_bytes());
        b[8..28].copy_from_slice(&self.caller);
        b[28..48].copy_from_slice(&self.callee);
        b[48] = self.status;
        b[49] = self.media_kind;
        b[50] = self.end_reason;
        b[51] = self.reneg_side;
        b[52..54].copy_from_slice(&self.caller_ice_cnt.to_be_bytes());
        b[54..56].copy_from_slice(&self.callee_ice_cnt.to_be_bytes());
        b[56..58].copy_from_slice(&self.reneg_seq.to_be_bytes());
        b[60..92].copy_from_slice(&self.caller_dtls_fp);
        b[92..124].copy_from_slice(&self.callee_dtls_fp);
        b[124..132].copy_from_slice(&self.created_blk.to_be_bytes());
        b[132..140].copy_from_slice(&self.answered_blk.to_be_bytes());
        b[140..148].copy_from_slice(&self.updated_blk.to_be_bytes());
        b
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < CALL_META_LEN {
            return None;
        }
        let mut u8_8 = [0u8; 8];
        let mut u8_2 = [0u8; 2];

        u8_8.copy_from_slice(&raw[0..8]);
        let call_id = u64::from_be_bytes(u8_8);
        let mut caller = [0u8; 20];
        caller.copy_from_slice(&raw[8..28]);
        let mut callee = [0u8; 20];
        callee.copy_from_slice(&raw[28..48]);

        let status = raw[48];
        let media_kind = raw[49];
        let end_reason = raw[50];
        let reneg_side = raw[51];

        u8_2.copy_from_slice(&raw[52..54]);
        let caller_ice_cnt = u16::from_be_bytes(u8_2);
        u8_2.copy_from_slice(&raw[54..56]);
        let callee_ice_cnt = u16::from_be_bytes(u8_2);
        u8_2.copy_from_slice(&raw[56..58]);
        let reneg_seq = u16::from_be_bytes(u8_2);

        let mut caller_dtls_fp = [0u8; 32];
        caller_dtls_fp.copy_from_slice(&raw[60..92]);
        let mut callee_dtls_fp = [0u8; 32];
        callee_dtls_fp.copy_from_slice(&raw[92..124]);

        u8_8.copy_from_slice(&raw[124..132]);
        let created_blk = u64::from_be_bytes(u8_8);
        u8_8.copy_from_slice(&raw[132..140]);
        let answered_blk = u64::from_be_bytes(u8_8);
        u8_8.copy_from_slice(&raw[140..148]);
        let updated_blk = u64::from_be_bytes(u8_8);

        Some(Self {
            call_id,
            caller,
            callee,
            status,
            media_kind,
            end_reason,
            reneg_side,
            caller_ice_cnt,
            callee_ice_cnt,
            reneg_seq,
            caller_dtls_fp,
            callee_dtls_fp,
            created_blk,
            answered_blk,
            updated_blk,
        })
    }
}

fn read_call_meta(call_id: u64) -> Option<CallMeta> {
    if call_id == 0 {
        return None;
    }
    let mut buf = [0u8; CALL_META_LEN];
    let n = storage::get_into(call_meta_key(call_id).as_slice(), &mut buf)?;
    if n < CALL_META_LEN {
        return None;
    }
    CallMeta::decode(&buf)
}

fn write_call_meta(m: &CallMeta) {
    let enc = m.encode();
    storage::set(call_meta_key(m.call_id).as_slice(), &enc);
}

fn record_recent_call_for_identity(identity: &[u8; 20], call_id: u64) {
    let cnt_key = id_recent_cnt_key(identity);
    let cnt = storage::get_u64(cnt_key.as_slice());
    let slot = cnt % MAX_RECENT_CALLS_PER_IDENTITY;
    storage::set_u64(id_recent_slot_key(identity, slot).as_slice(), call_id);
    storage::set_u64(cnt_key.as_slice(), cnt.saturating_add(1));

    // Also bump `total_calls` counter inside peer profile if registered
    let pkey = prof_rec_key(identity);
    let mut pbuf = [0u8; MAX_PEER_REC_BYTES];
    if let Some(plen) = storage::get_into(pkey.as_slice(), &mut pbuf) {
        if plen >= PEER_REC_HDR && plen <= MAX_PEER_REC_BYTES {
            let mut c4 = [0u8; 4];
            c4.copy_from_slice(&pbuf[62..66]);
            let next_c = u32::from_be_bytes(c4).saturating_add(1);
            pbuf[62..66].copy_from_slice(&next_c.to_be_bytes());
            storage::set(pkey.as_slice(), &pbuf[..plen]);
        }
    }
}

fn normalize_parity(parity_arg: u64) -> u8 {
    match parity_arg {
        3 | 1 => 3,
        _ => 2,
    }
}

fn normalize_avail(avail_arg: u64) -> u8 {
    match avail_arg {
        0 => AVAIL_OFFLINE,
        2 => AVAIL_BUSY,
        3 => AVAIL_DND,
        _ => AVAIL_ONLINE,
    }
}

fn normalize_media(media_arg: u64) -> u8 {
    match media_arg {
        1 => MEDIA_VOICE,
        3 => MEDIA_SCREEN,
        _ => MEDIA_VIDEO,
    }
}

fn handle_initialize(r: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(ERR_ALREADY_INIT);
    }
    let admin = r.address(0).ok_or(ERR_BAD_ARGS)?;
    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_ADMIN, &admin);
    events::emit(&[EV_INITIALIZED, addr_topic(&admin)], &[]);
    ret::write_bool(true);
    Ok(())
}

fn handle_abi_version(_r: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(WEBRTC_SIGNAL_ABI_VERSION);
    Ok(())
}

fn handle_admin(_r: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&get_admin());
    Ok(())
}

fn handle_get_hub_overview(_r: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 48];
    out[0..8].copy_from_slice(&WEBRTC_SIGNAL_ABI_VERSION.to_be_bytes());
    out[8..16].copy_from_slice(&storage::get_u64(KEY_TOTAL_PROFILES).to_be_bytes());
    out[16..24].copy_from_slice(&storage::get_u64(KEY_TOTAL_CALLS).to_be_bytes());
    out[24..32].copy_from_slice(&storage::get_u64(KEY_TOTAL_ROOMS).to_be_bytes());
    out[32..40].copy_from_slice(&context::block_number().to_be_bytes());
    out[40..48].copy_from_slice(&(MAX_ROOM_PEERS as u64).to_be_bytes());
    ret::write_abi_bytes(&out);
    Ok(())
}

fn handle_register_rtc_profile(r: &CalldataReader) -> Result<(), i32> {
    let identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let secp_pub_x = r.bytes32(1).ok_or(ERR_BAD_ARGS)?;
    let parity_arg = r.u64(2).ok_or(ERR_BAD_ARGS)?;
    let avail_arg = r.u64(3).ok_or(ERR_BAD_ARGS)?;
    let display_label = r.dynamic_bytes(4).ok_or(ERR_BAD_ARGS)?;
    let stun_hint = r.dynamic_bytes(5).ok_or(ERR_BAD_ARGS)?;

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let lbl_len = display_label.len().min(MAX_DISPLAY_LABEL_LEN);
    let hint_len = stun_hint.len().min(MAX_STUN_HINT_LEN);

    let pkey = prof_rec_key(&identity);
    let mut prev_calls: u32 = 0;
    let mut prev_buf = [0u8; PEER_REC_HDR];
    if let Some(n) = storage::get_into(pkey.as_slice(), &mut prev_buf) {
        if n >= PEER_REC_HDR {
            let mut c4 = [0u8; 4];
            c4.copy_from_slice(&prev_buf[62..66]);
            prev_calls = u32::from_be_bytes(c4);
        }
    }

    let seen_key = prof_seen_key(&identity);
    if storage::get_u64(seen_key.as_slice()) == 0 {
        let idx = storage::get_u64(KEY_TOTAL_PROFILES);
        storage::set_address(prof_idx_to_addr_key(idx).as_slice(), &identity);
        storage::set_u64(KEY_TOTAL_PROFILES, idx.saturating_add(1));
        storage::set_u64(seen_key.as_slice(), 1);
    }

    let parity = normalize_parity(parity_arg);
    let avail = normalize_avail(avail_arg);
    let blk = context::block_number();

    let mut rec = [0u8; MAX_PEER_REC_BYTES];
    rec[0..20].copy_from_slice(&identity);
    rec[20..52].copy_from_slice(&secp_pub_x);
    rec[52] = parity;
    rec[53] = avail;
    rec[54..62].copy_from_slice(&blk.to_be_bytes());
    rec[62..66].copy_from_slice(&prev_calls.to_be_bytes());
    rec[66..68].copy_from_slice(&(lbl_len as u16).to_be_bytes());
    rec[68..70].copy_from_slice(&(hint_len as u16).to_be_bytes());

    let mut pos = PEER_REC_HDR;
    rec[pos..pos + lbl_len].copy_from_slice(&display_label[..lbl_len]);
    pos += lbl_len;
    rec[pos..pos + hint_len].copy_from_slice(&stun_hint[..hint_len]);
    pos += hint_len;

    storage::set(pkey.as_slice(), &rec[..pos]);
    events::emit(
        &[
            EV_PROFILE_UPDATED,
            addr_topic(&identity),
            u64_topic(avail as u64),
            secp_pub_x,
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_heartbeat_presence(r: &CalldataReader) -> Result<(), i32> {
    let identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let avail_arg = r.u64(1).ok_or(ERR_BAD_ARGS)?;

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let pkey = prof_rec_key(&identity);
    let mut rec = [0u8; MAX_PEER_REC_BYTES];
    let avail = normalize_avail(avail_arg);
    let blk = context::block_number();

    if let Some(plen) = storage::get_into(pkey.as_slice(), &mut rec) {
        if plen >= PEER_REC_HDR && plen <= MAX_PEER_REC_BYTES {
            rec[53] = avail;
            rec[54..62].copy_from_slice(&blk.to_be_bytes());
            let mut pub_x = [0u8; 32];
            pub_x.copy_from_slice(&rec[20..52]);
            storage::set(pkey.as_slice(), &rec[..plen]);
            events::emit(
                &[
                    EV_PROFILE_UPDATED,
                    addr_topic(&identity),
                    u64_topic(avail as u64),
                    pub_x,
                ],
                &[],
            );
            ret::write_bool(true);
            return Ok(());
        }
    }

    // Minimal auto-registration if peer sends heartbeat before full profile
    let seen_key = prof_seen_key(&identity);
    if storage::get_u64(seen_key.as_slice()) == 0 {
        let idx = storage::get_u64(KEY_TOTAL_PROFILES);
        storage::set_address(prof_idx_to_addr_key(idx).as_slice(), &identity);
        storage::set_u64(KEY_TOTAL_PROFILES, idx.saturating_add(1));
        storage::set_u64(seen_key.as_slice(), 1);
    }
    rec[0..20].copy_from_slice(&identity);
    rec[52] = 2;
    rec[53] = avail;
    rec[54..62].copy_from_slice(&blk.to_be_bytes());
    storage::set(pkey.as_slice(), &rec[..PEER_REC_HDR]);
    events::emit(
        &[
            EV_PROFILE_UPDATED,
            addr_topic(&identity),
            u64_topic(avail as u64),
            [0u8; 32],
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_get_peer_profile(r: &CalldataReader) -> Result<(), i32> {
    let identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let mut rec = [0u8; MAX_PEER_REC_BYTES];
    match storage::get_into(prof_rec_key(&identity).as_slice(), &mut rec) {
        Some(n) if n >= PEER_REC_HDR && n <= MAX_PEER_REC_BYTES => {
            ret::write_abi_bytes(&rec[..n]);
        }
        _ => {
            ret::write_abi_bytes(&[]);
        }
    }
    Ok(())
}

fn handle_get_directory_slice(r: &CalldataReader) -> Result<(), i32> {
    let start = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let req_limit = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let limit = req_limit.min(MAX_DIRECTORY_SLICE);

    let total = storage::get_u64(KEY_TOTAL_PROFILES);
    unsafe {
        OUT_SCRATCH[0..8].copy_from_slice(&total.to_be_bytes());
        let mut count: u64 = 0;
        let mut pos: usize = 16;

        let mut step: u64 = 0;
        while step < MAX_DIRECTORY_SLICE {
            if step >= limit {
                break;
            }
            let idx = start.saturating_add(step);
            if idx >= total {
                break;
            }
            if let Some(addr) = storage::get_address(prof_idx_to_addr_key(idx).as_slice()) {
                let mut rec = [0u8; MAX_PEER_REC_BYTES];
                if let Some(rlen) = storage::get_into(prof_rec_key(&addr).as_slice(), &mut rec) {
                    if rlen >= PEER_REC_HDR
                        && rlen <= MAX_PEER_REC_BYTES
                        && pos + rlen <= OUT_SCRATCH_CAP
                    {
                        OUT_SCRATCH[pos..pos + rlen].copy_from_slice(&rec[..rlen]);
                        pos += rlen;
                        count += 1;
                    }
                }
            }
            step += 1;
        }
        OUT_SCRATCH[8..16].copy_from_slice(&count.to_be_bytes());
        ret::write_abi_bytes(&OUT_SCRATCH[..pos]);
    }
    Ok(())
}

fn handle_place_call(r: &CalldataReader) -> Result<(), i32> {
    let caller_identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let callee_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let media_arg = r.u64(2).ok_or(ERR_BAD_ARGS)?;
    let caller_dtls_fp = r.bytes32(3).ok_or(ERR_BAD_ARGS)?;
    let offer_env = r.dynamic_bytes(4).ok_or(ERR_BAD_ARGS)?;

    if callee_identity == [0u8; 20]
        || caller_identity == callee_identity
        || caller_dtls_fp == [0u8; 32]
        || offer_env.is_empty()
    {
        return Err(ERR_BAD_ARGS);
    }
    if offer_env.len() > MAX_SDP_ENVELOPE_BYTES {
        return Err(ERR_ENVELOPE_TOO_LARGE);
    }

    let msg_sender = context::msg_sender();
    if !is_authorized_for_identity(&msg_sender, &caller_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let call_id = storage::get_u64(KEY_TOTAL_CALLS).saturating_add(1);
    storage::set_u64(KEY_TOTAL_CALLS, call_id);

    let blk = context::block_number();
    let media_kind = normalize_media(media_arg);

    let meta = CallMeta {
        call_id,
        caller: caller_identity,
        callee: callee_identity,
        status: CALL_STATUS_RINGING,
        media_kind,
        end_reason: 0,
        reneg_side: RENEG_NONE,
        caller_ice_cnt: 0,
        callee_ice_cnt: 0,
        reneg_seq: 0,
        caller_dtls_fp,
        callee_dtls_fp: [0u8; 32],
        created_blk: blk,
        answered_blk: 0,
        updated_blk: blk,
    };
    write_call_meta(&meta);
    storage::set(call_offer_key(call_id).as_slice(), offer_env);

    record_recent_call_for_identity(&caller_identity, call_id);
    record_recent_call_for_identity(&callee_identity, call_id);

    let mut ev_data = [0u8; 64];
    ev_data[0..32].copy_from_slice(&u64_word(media_kind as u64));
    ev_data[32..64].copy_from_slice(&caller_dtls_fp);
    events::emit(
        &[
            EV_CALL_RINGING,
            u64_topic(call_id),
            addr_topic(&caller_identity),
            addr_topic(&callee_identity),
        ],
        &ev_data,
    );

    ret::write_u64_word(call_id);
    Ok(())
}

fn handle_answer_call(r: &CalldataReader) -> Result<(), i32> {
    let call_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let callee_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let callee_dtls_fp = r.bytes32(2).ok_or(ERR_BAD_ARGS)?;
    let answer_env = r.dynamic_bytes(3).ok_or(ERR_BAD_ARGS)?;

    if callee_dtls_fp == [0u8; 32] || answer_env.is_empty() {
        return Err(ERR_BAD_ARGS);
    }
    if answer_env.len() > MAX_SDP_ENVELOPE_BYTES {
        return Err(ERR_ENVELOPE_TOO_LARGE);
    }

    let mut meta = read_call_meta(call_id).ok_or(ERR_CALL_NOT_FOUND)?;
    if meta.status != CALL_STATUS_RINGING {
        return Err(ERR_INVALID_CALL_STATE);
    }
    if callee_identity != meta.callee {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let msg_sender = context::msg_sender();
    if !is_authorized_for_identity(&msg_sender, &callee_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let blk = context::block_number();
    meta.status = CALL_STATUS_ACTIVE;
    meta.callee_dtls_fp = callee_dtls_fp;
    meta.answered_blk = blk;
    meta.updated_blk = blk;
    write_call_meta(&meta);
    storage::set(call_answer_key(call_id).as_slice(), answer_env);

    events::emit(
        &[
            EV_CALL_ANSWERED,
            u64_topic(call_id),
            addr_topic(&meta.caller),
            addr_topic(&meta.callee),
        ],
        &callee_dtls_fp,
    );

    ret::write_bool(true);
    Ok(())
}

fn handle_append_ice_batch(r: &CalldataReader) -> Result<(), i32> {
    let call_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let actor_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let ice_env = r.dynamic_bytes(2).ok_or(ERR_BAD_ARGS)?;

    if ice_env.is_empty() {
        return Err(ERR_BAD_ARGS);
    }
    if ice_env.len() > MAX_ICE_BATCH_BYTES {
        return Err(ERR_ENVELOPE_TOO_LARGE);
    }

    let mut meta = read_call_meta(call_id).ok_or(ERR_CALL_NOT_FOUND)?;
    if meta.status != CALL_STATUS_RINGING && meta.status != CALL_STATUS_ACTIVE {
        return Err(ERR_INVALID_CALL_STATE);
    }

    let is_callee = if actor_identity == meta.caller {
        false
    } else if actor_identity == meta.callee {
        true
    } else {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    };

    let msg_sender = context::msg_sender();
    if !is_authorized_for_identity(&msg_sender, &actor_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let batch_idx = if is_callee {
        if (meta.callee_ice_cnt as u64) >= MAX_ICE_BATCHES_PER_SIDE {
            return Err(ERR_ICE_BATCH_LIMIT);
        }
        let idx = meta.callee_ice_cnt;
        meta.callee_ice_cnt = idx.saturating_add(1);
        idx
    } else {
        if (meta.caller_ice_cnt as u64) >= MAX_ICE_BATCHES_PER_SIDE {
            return Err(ERR_ICE_BATCH_LIMIT);
        }
        let idx = meta.caller_ice_cnt;
        meta.caller_ice_cnt = idx.saturating_add(1);
        idx
    };

    meta.updated_blk = context::block_number();
    write_call_meta(&meta);
    storage::set(call_ice_key(call_id, is_callee, batch_idx).as_slice(), ice_env);

    events::emit(
        &[
            EV_CALL_ICE_UPDATED,
            u64_topic(call_id),
            addr_topic(&actor_identity),
            u64_topic(batch_idx as u64),
        ],
        &[],
    );

    ret::write_u64_word((batch_idx as u64) + 1);
    Ok(())
}

fn handle_renegotiate_media(r: &CalldataReader) -> Result<(), i32> {
    let call_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let actor_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let media_arg = r.u64(2).ok_or(ERR_BAD_ARGS)?;
    let is_answer = r.bool(3).ok_or(ERR_BAD_ARGS)?;
    let sdp_env = r.dynamic_bytes(4).ok_or(ERR_BAD_ARGS)?;

    if sdp_env.is_empty() {
        return Err(ERR_BAD_ARGS);
    }
    if sdp_env.len() > MAX_SDP_ENVELOPE_BYTES {
        return Err(ERR_ENVELOPE_TOO_LARGE);
    }

    let mut meta = read_call_meta(call_id).ok_or(ERR_CALL_NOT_FOUND)?;
    if meta.status != CALL_STATUS_ACTIVE {
        return Err(ERR_INVALID_CALL_STATE);
    }
    if actor_identity != meta.caller && actor_identity != meta.callee {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let msg_sender = context::msg_sender();
    if !is_authorized_for_identity(&msg_sender, &actor_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    meta.media_kind = normalize_media(media_arg);
    meta.reneg_side = if is_answer {
        RENEG_ANSWERED
    } else if actor_identity == meta.caller {
        RENEG_CALLER_OFFER
    } else {
        RENEG_CALLEE_OFFER
    };
    meta.reneg_seq = meta.reneg_seq.saturating_add(1);
    meta.updated_blk = context::block_number();

    write_call_meta(&meta);
    storage::set(call_reneg_key(call_id).as_slice(), sdp_env);

    let mut ev_data = [0u8; 96];
    ev_data[0..32].copy_from_slice(&u64_word(meta.media_kind as u64));
    ev_data[32..64].copy_from_slice(&u64_word(meta.reneg_side as u64));
    ev_data[64..96].copy_from_slice(&u64_word(meta.reneg_seq as u64));
    events::emit(
        &[
            EV_CALL_MEDIA_UPDATED,
            u64_topic(call_id),
            addr_topic(&actor_identity),
        ],
        &ev_data,
    );

    ret::write_u64_word(meta.reneg_seq as u64);
    Ok(())
}

fn handle_end_call(r: &CalldataReader) -> Result<(), i32> {
    let call_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let actor_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let reason_code = r.u64(2).unwrap_or(1);

    let mut meta = read_call_meta(call_id).ok_or(ERR_CALL_NOT_FOUND)?;
    if actor_identity != meta.caller && actor_identity != meta.callee {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let msg_sender = context::msg_sender();
    if !is_authorized_for_identity(&msg_sender, &actor_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    if meta.status == CALL_STATUS_DECLINED
        || meta.status == CALL_STATUS_CANCELED
        || meta.status == CALL_STATUS_ENDED
    {
        // Idempotent close
        ret::write_bool(true);
        return Ok(());
    }

    meta.status = if meta.status == CALL_STATUS_RINGING {
        if actor_identity == meta.callee {
            CALL_STATUS_DECLINED
        } else {
            CALL_STATUS_CANCELED
        }
    } else {
        CALL_STATUS_ENDED
    };
    meta.end_reason = (reason_code.min(255)) as u8;
    meta.updated_blk = context::block_number();
    write_call_meta(&meta);

    let mut ev_data = [0u8; 64];
    ev_data[0..32].copy_from_slice(&u64_word(meta.status as u64));
    ev_data[32..64].copy_from_slice(&u64_word(meta.end_reason as u64));
    events::emit(
        &[
            EV_CALL_ENDED,
            u64_topic(call_id),
            addr_topic(&actor_identity),
        ],
        &ev_data,
    );

    ret::write_bool(true);
    Ok(())
}

fn copy_blob_with_u16_len(key: &[u8], out: &mut [u8], pos: &mut usize, max_item: usize) {
    if *pos + 2 > out.len() {
        return;
    }
    let len_pos = *pos;
    *pos += 2;
    let avail = out.len().saturating_sub(*pos).min(max_item);
    let written = match storage::get_into(key, &mut out[*pos..*pos + avail]) {
        Some(total) => total.min(avail),
        None => 0,
    };
    out[len_pos..len_pos + 2].copy_from_slice(&(written as u16).to_be_bytes());
    *pos += written;
}

fn handle_get_call_session(r: &CalldataReader) -> Result<(), i32> {
    let call_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let Some(meta) = read_call_meta(call_id) else {
        ret::write_abi_bytes(&[]);
        return Ok(());
    };

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(OUT_SCRATCH) };
    let meta_bytes = meta.encode();
    scratch[0..CALL_META_LEN].copy_from_slice(&meta_bytes);
    let mut pos = CALL_META_LEN;

    copy_blob_with_u16_len(
        call_offer_key(call_id).as_slice(),
        scratch,
        &mut pos,
        MAX_SDP_ENVELOPE_BYTES,
    );
    copy_blob_with_u16_len(
        call_answer_key(call_id).as_slice(),
        scratch,
        &mut pos,
        MAX_SDP_ENVELOPE_BYTES,
    );
    copy_blob_with_u16_len(
        call_reneg_key(call_id).as_slice(),
        scratch,
        &mut pos,
        MAX_SDP_ENVELOPE_BYTES,
    );

    let c_lim = (meta.caller_ice_cnt as u64).min(MAX_ICE_BATCHES_PER_SIDE) as u16;
    let mut ci: u16 = 0;
    while ci < (MAX_ICE_BATCHES_PER_SIDE as u16) {
        if ci >= c_lim {
            break;
        }
        copy_blob_with_u16_len(
            call_ice_key(call_id, false, ci).as_slice(),
            scratch,
            &mut pos,
            MAX_ICE_BATCH_BYTES,
        );
        ci += 1;
    }

    let a_lim = (meta.callee_ice_cnt as u64).min(MAX_ICE_BATCHES_PER_SIDE) as u16;
    let mut ai: u16 = 0;
    while ai < (MAX_ICE_BATCHES_PER_SIDE as u16) {
        if ai >= a_lim {
            break;
        }
        copy_blob_with_u16_len(
            call_ice_key(call_id, true, ai).as_slice(),
            scratch,
            &mut pos,
            MAX_ICE_BATCH_BYTES,
        );
        ai += 1;
    }

    ret::write_abi_bytes(&scratch[..pos]);
    Ok(())
}

fn handle_get_recent_calls_for_identity(r: &CalldataReader) -> Result<(), i32> {
    let identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let total_logged = storage::get_u64(id_recent_cnt_key(&identity).as_slice());
    let window = total_logged.min(MAX_RECENT_CALLS_PER_IDENTITY);

    unsafe {
        let mut count: u64 = 0;
        let mut pos: usize = 8;

        let mut step: u64 = 0;
        while step < MAX_RECENT_CALLS_PER_IDENTITY {
            if step >= window {
                break;
            }
            // Walk backwards from most recent entry
            let seq = total_logged - 1 - step;
            let slot = seq % MAX_RECENT_CALLS_PER_IDENTITY;
            let cid = storage::get_u64(id_recent_slot_key(&identity, slot).as_slice());
            if cid > 0 {
                if let Some(meta) = read_call_meta(cid) {
                    if pos + CALL_META_LEN <= OUT_SCRATCH_CAP {
                        OUT_SCRATCH[pos..pos + CALL_META_LEN].copy_from_slice(&meta.encode());
                        pos += CALL_META_LEN;
                        count += 1;
                    }
                }
            }
            step += 1;
        }

        OUT_SCRATCH[0..8].copy_from_slice(&count.to_be_bytes());
        ret::write_abi_bytes(&OUT_SCRATCH[..pos]);
    }
    Ok(())
}

// ============================================================================
// Multi-Peer Mesh Conference Rooms (up to 6 peers)
// ============================================================================

#[derive(Clone, Copy)]
struct RoomPeer {
    identity: [u8; 20],
    dtls_fp: [u8; 32],
    joined_blk: u64,
}

struct RoomRecord {
    room_id: u64,
    host: [u8; 20],
    status: u8,
    media_kind: u8,
    e2ee_req: u8,
    created_blk: u64,
    updated_blk: u64,
    title: [u8; MAX_ROOM_TITLE_LEN],
    title_len: usize,
    peers: [RoomPeer; MAX_ROOM_PEERS],
    peer_count: usize,
}

impl RoomRecord {
    fn encode_into(&self, out: &mut [u8; MAX_ROOM_REC_BYTES]) -> usize {
        out[0..8].copy_from_slice(&self.room_id.to_be_bytes());
        out[8..28].copy_from_slice(&self.host);
        out[28] = self.status;
        out[29] = self.media_kind;
        out[30] = self.e2ee_req;
        out[31] = self.peer_count as u8;
        out[32..40].copy_from_slice(&self.created_blk.to_be_bytes());
        out[40..48].copy_from_slice(&self.updated_blk.to_be_bytes());
        let tlen = self.title_len.min(MAX_ROOM_TITLE_LEN);
        out[48..50].copy_from_slice(&(tlen as u16).to_be_bytes());
        let mut pos = ROOM_HDR_LEN;
        out[pos..pos + tlen].copy_from_slice(&self.title[..tlen]);
        pos += tlen;

        let mut i = 0;
        while i < MAX_ROOM_PEERS {
            if i >= self.peer_count {
                break;
            }
            out[pos..pos + 20].copy_from_slice(&self.peers[i].identity);
            out[pos + 20..pos + 52].copy_from_slice(&self.peers[i].dtls_fp);
            out[pos + 52..pos + 60].copy_from_slice(&self.peers[i].joined_blk.to_be_bytes());
            pos += ROOM_PEER_ENTRY_LEN;
            i += 1;
        }
        pos
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < ROOM_HDR_LEN {
            return None;
        }
        let mut u8_8 = [0u8; 8];
        let mut u8_2 = [0u8; 2];

        u8_8.copy_from_slice(&raw[0..8]);
        let room_id = u64::from_be_bytes(u8_8);
        let mut host = [0u8; 20];
        host.copy_from_slice(&raw[8..28]);
        let status = raw[28];
        let media_kind = raw[29];
        let e2ee_req = raw[30];
        let peer_count = (raw[31] as usize).min(MAX_ROOM_PEERS);

        u8_8.copy_from_slice(&raw[32..40]);
        let created_blk = u64::from_be_bytes(u8_8);
        u8_8.copy_from_slice(&raw[40..48]);
        let updated_blk = u64::from_be_bytes(u8_8);
        u8_2.copy_from_slice(&raw[48..50]);
        let title_len = (u16::from_be_bytes(u8_2) as usize).min(MAX_ROOM_TITLE_LEN);

        let expected_len = ROOM_HDR_LEN + title_len + peer_count * ROOM_PEER_ENTRY_LEN;
        if raw.len() < expected_len {
            return None;
        }

        let mut title = [0u8; MAX_ROOM_TITLE_LEN];
        title[..title_len].copy_from_slice(&raw[ROOM_HDR_LEN..ROOM_HDR_LEN + title_len]);

        let mut peers = [RoomPeer {
            identity: [0u8; 20],
            dtls_fp: [0u8; 32],
            joined_blk: 0,
        }; MAX_ROOM_PEERS];

        let mut pos = ROOM_HDR_LEN + title_len;
        let mut i = 0;
        while i < MAX_ROOM_PEERS {
            if i >= peer_count {
                break;
            }
            peers[i].identity.copy_from_slice(&raw[pos..pos + 20]);
            peers[i].dtls_fp.copy_from_slice(&raw[pos + 20..pos + 52]);
            u8_8.copy_from_slice(&raw[pos + 52..pos + 60]);
            peers[i].joined_blk = u64::from_be_bytes(u8_8);
            pos += ROOM_PEER_ENTRY_LEN;
            i += 1;
        }

        Some(Self {
            room_id,
            host,
            status,
            media_kind,
            e2ee_req,
            created_blk,
            updated_blk,
            title,
            title_len,
            peers,
            peer_count,
        })
    }
}

fn read_room(room_id: u64) -> Option<RoomRecord> {
    if room_id == 0 {
        return None;
    }
    let mut buf = [0u8; MAX_ROOM_REC_BYTES];
    let n = storage::get_into(room_rec_key(room_id).as_slice(), &mut buf)?;
    RoomRecord::decode(&buf[..n.min(MAX_ROOM_REC_BYTES)])
}

fn write_room(rm: &RoomRecord) {
    let mut buf = [0u8; MAX_ROOM_REC_BYTES];
    let n = rm.encode_into(&mut buf);
    storage::set(room_rec_key(rm.room_id).as_slice(), &buf[..n]);
}

fn room_contains_peer(rm: &RoomRecord, identity: &[u8; 20]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_ROOM_PEERS {
        if i >= rm.peer_count {
            break;
        }
        if &rm.peers[i].identity == identity {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn handle_create_room(r: &CalldataReader) -> Result<(), i32> {
    let host_identity = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let title_bytes = r.dynamic_bytes(1).ok_or(ERR_BAD_ARGS)?;
    let media_arg = r.u64(2).ok_or(ERR_BAD_ARGS)?;
    let e2ee_req = r.bool(3).ok_or(ERR_BAD_ARGS)?;
    let host_dtls_fp = r.bytes32(4).ok_or(ERR_BAD_ARGS)?;

    if title_bytes.is_empty() {
        return Err(ERR_BAD_ARGS);
    }

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &host_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let room_id = storage::get_u64(KEY_TOTAL_ROOMS).saturating_add(1);
    storage::set_u64(KEY_TOTAL_ROOMS, room_id);

    let blk = context::block_number();
    let tlen = title_bytes.len().min(MAX_ROOM_TITLE_LEN);
    let mut title = [0u8; MAX_ROOM_TITLE_LEN];
    title[..tlen].copy_from_slice(&title_bytes[..tlen]);

    let mut peers = [RoomPeer {
        identity: [0u8; 20],
        dtls_fp: [0u8; 32],
        joined_blk: 0,
    }; MAX_ROOM_PEERS];
    peers[0] = RoomPeer {
        identity: host_identity,
        dtls_fp: host_dtls_fp,
        joined_blk: blk,
    };

    let media_kind = normalize_media(media_arg);
    let rm = RoomRecord {
        room_id,
        host: host_identity,
        status: ROOM_STATUS_OPEN,
        media_kind,
        e2ee_req: if e2ee_req { 1 } else { 0 },
        created_blk: blk,
        updated_blk: blk,
        title,
        title_len: tlen,
        peers,
        peer_count: 1,
    };
    write_room(&rm);

    events::emit(
        &[
            EV_ROOM_CREATED,
            u64_topic(room_id),
            addr_topic(&host_identity),
            u64_topic(media_kind as u64),
        ],
        &host_dtls_fp,
    );

    ret::write_u64_word(room_id);
    Ok(())
}

fn handle_join_room(r: &CalldataReader) -> Result<(), i32> {
    let room_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let peer_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let dtls_fp = r.bytes32(2).ok_or(ERR_BAD_ARGS)?;

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &peer_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let mut rm = read_room(room_id).ok_or(ERR_ROOM_NOT_FOUND)?;
    if rm.status != ROOM_STATUS_OPEN {
        return Err(ERR_ROOM_CLOSED);
    }

    let blk = context::block_number();
    if let Some(existing_idx) = room_contains_peer(&rm, &peer_identity) {
        if dtls_fp != [0u8; 32] {
            rm.peers[existing_idx].dtls_fp = dtls_fp;
        }
        rm.peers[existing_idx].joined_blk = blk;
    } else {
        if rm.peer_count >= MAX_ROOM_PEERS {
            return Err(ERR_ROOM_FULL);
        }
        rm.peers[rm.peer_count] = RoomPeer {
            identity: peer_identity,
            dtls_fp,
            joined_blk: blk,
        };
        rm.peer_count += 1;
    }
    rm.updated_blk = blk;
    write_room(&rm);

    events::emit(
        &[
            EV_ROOM_PEER_JOINED,
            u64_topic(room_id),
            addr_topic(&peer_identity),
            u64_topic(rm.peer_count as u64),
        ],
        &dtls_fp,
    );

    ret::write_u64_word(rm.peer_count as u64);
    Ok(())
}

fn handle_leave_room(r: &CalldataReader) -> Result<(), i32> {
    let room_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let peer_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;

    let mut rm = read_room(room_id).ok_or(ERR_ROOM_NOT_FOUND)?;
    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &peer_identity)
        && !is_authorized_for_identity(&caller, &rm.host)
    {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    if let Some(idx) = room_contains_peer(&rm, &peer_identity) {
        let mut j = idx;
        while j + 1 < MAX_ROOM_PEERS {
            if j + 1 >= rm.peer_count {
                break;
            }
            rm.peers[j] = rm.peers[j + 1];
            j += 1;
        }
        rm.peer_count = rm.peer_count.saturating_sub(1);
        if rm.peer_count == 0 {
            rm.status = ROOM_STATUS_CLOSED;
        }
        rm.updated_blk = context::block_number();
        write_room(&rm);

        events::emit(
            &[
                EV_ROOM_PEER_LEFT,
                u64_topic(room_id),
                addr_topic(&peer_identity),
                u64_topic(rm.peer_count as u64),
            ],
            &[],
        );
    }

    ret::write_bool(true);
    Ok(())
}

fn handle_post_room_signal(r: &CalldataReader) -> Result<(), i32> {
    let room_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let from_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let to_identity = r.address(2).ok_or(ERR_BAD_ARGS)?;
    let signal_type = r.u64(3).ok_or(ERR_BAD_ARGS)?;
    let env = r.dynamic_bytes(4).ok_or(ERR_BAD_ARGS)?;

    if from_identity == to_identity || env.is_empty() {
        return Err(ERR_BAD_ARGS);
    }
    if env.len() > MAX_SDP_ENVELOPE_BYTES {
        return Err(ERR_ENVELOPE_TOO_LARGE);
    }

    let caller = context::msg_sender();
    if !is_authorized_for_identity(&caller, &from_identity) {
        return Err(ERR_UNAUTHORIZED_IDENTITY);
    }

    let rm = read_room(room_id).ok_or(ERR_ROOM_NOT_FOUND)?;
    if rm.status != ROOM_STATUS_OPEN {
        return Err(ERR_ROOM_CLOSED);
    }
    if room_contains_peer(&rm, &from_identity).is_none()
        || room_contains_peer(&rm, &to_identity).is_none()
    {
        return Err(ERR_NOT_IN_ROOM);
    }

    let skey = pair_sig_key(room_id, &from_identity, &to_identity);
    let mut prev_hdr = [0u8; 19];
    let prev_seq = match storage::get_into(skey.as_slice(), &mut prev_hdr) {
        Some(n) if n >= 8 => {
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(&prev_hdr[0..8]);
            u64::from_be_bytes(b8)
        }
        _ => 0,
    };
    let seq = prev_seq.saturating_add(1);
    let blk = context::block_number();

    unsafe {
        OUT_SCRATCH[0..8].copy_from_slice(&seq.to_be_bytes());
        OUT_SCRATCH[8] = (signal_type.min(255)) as u8;
        OUT_SCRATCH[9..17].copy_from_slice(&blk.to_be_bytes());
        OUT_SCRATCH[17..19].copy_from_slice(&(env.len() as u16).to_be_bytes());
        OUT_SCRATCH[19..19 + env.len()].copy_from_slice(env);
        storage::set(skey.as_slice(), &OUT_SCRATCH[..19 + env.len()]);
    }

    let mut ev_data = [0u8; 64];
    ev_data[0..32].copy_from_slice(&u64_word(seq));
    ev_data[32..64].copy_from_slice(&u64_word(signal_type));
    events::emit(
        &[
            EV_ROOM_SIGNAL_POSTED,
            u64_topic(room_id),
            addr_topic(&from_identity),
            addr_topic(&to_identity),
        ],
        &ev_data,
    );

    ret::write_u64_word(seq);
    Ok(())
}

fn handle_get_room_state(r: &CalldataReader) -> Result<(), i32> {
    let room_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let mut buf = [0u8; MAX_ROOM_REC_BYTES];
    match storage::get_into(room_rec_key(room_id).as_slice(), &mut buf) {
        Some(n) if n >= ROOM_HDR_LEN && n <= MAX_ROOM_REC_BYTES => {
            ret::write_abi_bytes(&buf[..n]);
        }
        _ => {
            ret::write_abi_bytes(&[]);
        }
    }
    Ok(())
}

fn handle_get_rooms_slice(r: &CalldataReader) -> Result<(), i32> {
    let start = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let req_limit = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let limit = req_limit.min(MAX_ROOMS_SLICE);

    let total = storage::get_u64(KEY_TOTAL_ROOMS);
    unsafe {
        OUT_SCRATCH[0..8].copy_from_slice(&total.to_be_bytes());
        let mut count: u64 = 0;
        let mut pos: usize = 16;

        let mut step: u64 = 0;
        while step < MAX_ROOMS_SLICE {
            if step >= limit {
                break;
            }
            // Iterate newest-first from `total - start - step`
            let offset = start.saturating_add(step);
            if offset >= total {
                break;
            }
            let room_id = total - offset;
            let mut rbuf = [0u8; MAX_ROOM_REC_BYTES];
            if let Some(rlen) = storage::get_into(room_rec_key(room_id).as_slice(), &mut rbuf) {
                if rlen >= ROOM_HDR_LEN
                    && rlen <= MAX_ROOM_REC_BYTES
                    && pos + rlen <= OUT_SCRATCH_CAP
                {
                    OUT_SCRATCH[pos..pos + rlen].copy_from_slice(&rbuf[..rlen]);
                    pos += rlen;
                    count += 1;
                }
            }
            step += 1;
        }

        OUT_SCRATCH[8..16].copy_from_slice(&count.to_be_bytes());
        ret::write_abi_bytes(&OUT_SCRATCH[..pos]);
    }
    Ok(())
}

fn handle_get_pair_signal(r: &CalldataReader) -> Result<(), i32> {
    let room_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let from_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let to_identity = r.address(2).ok_or(ERR_BAD_ARGS)?;

    let skey = pair_sig_key(room_id, &from_identity, &to_identity);
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(OUT_SCRATCH) };
    match storage::get_into(skey.as_slice(), &mut scratch[..19 + MAX_SDP_ENVELOPE_BYTES]) {
        Some(n) if n >= 19 && n <= 19 + MAX_SDP_ENVELOPE_BYTES => {
            ret::write_abi_bytes(&scratch[..n]);
        }
        _ => {
            ret::write_abi_bytes(&[]);
        }
    }
    Ok(())
}

// ============================================================================
// Native Unit Tests (`cargo test -p webrtc-signal`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    const HUB_ADDR: [u8; 20] = [0x88; 20];
    const ADMIN_EOA: [u8; 20] = [0x01; 20];
    const ALICE_ID: [u8; 20] = [0xA1; 20];
    const ALICE_EOA: [u8; 20] = [0xA2; 20];
    const BOB_ID: [u8; 20] = [0xB1; 20];
    const BOB_EOA: [u8; 20] = [0xB2; 20];
    const EVE_EOA: [u8; 20] = [0xEE; 20];

    fn mock_identity_dispatch(raw: &[u8]) -> i32 {
        let Some((sel, _r)) = CalldataReader::parse(raw) else {
            return -1;
        };
        let self_addr = context::self_address();
        if sel == selector("owner()") {
            let owner = if self_addr == ALICE_ID {
                ALICE_EOA
            } else if self_addr == BOB_ID {
                BOB_EOA
            } else {
                [0u8; 20]
            };
            ret::write_address(&owner);
            return 0;
        }
        if sel == selector("isOwnerDevice(address)") {
            ret::write_bool(false);
            return 0;
        }
        -2
    }

    fn decode_abi_bytes(ret_raw: &[u8]) -> Vec<u8> {
        assert!(ret_raw.len() >= 64);
        let mut lb = [0u8; 8];
        lb.copy_from_slice(&ret_raw[56..64]);
        let len = u64::from_be_bytes(lb) as usize;
        ret_raw[64..64 + len].to_vec()
    }

    fn decode_u64(ret_raw: &[u8]) -> u64 {
        assert_eq!(ret_raw.len(), 32);
        let mut b = [0u8; 8];
        b.copy_from_slice(&ret_raw[24..32]);
        u64::from_be_bytes(b)
    }

    fn pad32(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(data.len() as u64).to_be_bytes());
        out.extend_from_slice(&lw);
        out.extend_from_slice(data);
        let rem = data.len() % 32;
        if rem != 0 {
            out.resize(out.len() + (32 - rem), 0);
        }
        out
    }

    fn setup_env() {
        mock::reset();
        mock::set_block_number(50_250);
        mock::register_hps(HUB_ADDR, dispatch_calldata);
        mock::register_hps(ALICE_ID, mock_identity_dispatch);
        mock::register_hps(BOB_ID, mock_identity_dispatch);

        let init_cd = CallEncoder::<64>::new(selector("initialize(address)")).push_address(&ADMIN_EOA);
        mock::transact_as(ADMIN_EOA, HUB_ADDR, init_cd.as_slice()).expect("init hub");
    }

    #[test]
    fn test_profile_directory_and_full_1to1_call_lifecycle() {
        setup_env();

        // 1. Register Alice & Bob RTC profiles via their owning EOAs
        let alice_pub_x = [0x11u8; 32];
        let bob_pub_x = [0x22u8; 32];

        let mut reg_alice = Vec::new();
        reg_alice.extend_from_slice(&selector(
            "registerRtcProfile(address,bytes32,uint64,uint64,string,string)",
        ));
        let lbl_tail = pad32(b"Alice @ SG");
        let hint_tail = pad32(b"LAN 192.168.50.x + STUN");
        let head_size = 6 * 32;
        let enc_head = CallEncoder::<256>::new([0; 4])
            .push_address(&ALICE_ID)
            .push_bytes32(&alice_pub_x)
            .push_u64(2)
            .push_u64(AVAIL_ONLINE as u64)
            .push_u64(head_size as u64)
            .push_u64((head_size + lbl_tail.len()) as u64);
        reg_alice.extend_from_slice(&enc_head.as_slice()[4..]);
        reg_alice.extend_from_slice(&lbl_tail);
        reg_alice.extend_from_slice(&hint_tail);

        // Unauthorized Eve cannot register Alice's Identity
        assert_eq!(
            mock::transact_as(EVE_EOA, HUB_ADDR, &reg_alice),
            Err(ERR_UNAUTHORIZED_IDENTITY)
        );
        mock::transact_as(ALICE_EOA, HUB_ADDR, &reg_alice).expect("register Alice");

        // Register Bob
        let mut reg_bob = Vec::new();
        reg_bob.extend_from_slice(&selector(
            "registerRtcProfile(address,bytes32,uint64,uint64,string,string)",
        ));
        let bob_lbl = pad32(b"Bob @ Validator2");
        let bob_hint = pad32(b"Direct Mesh");
        let bob_head = CallEncoder::<256>::new([0; 4])
            .push_address(&BOB_ID)
            .push_bytes32(&bob_pub_x)
            .push_u64(3)
            .push_u64(AVAIL_ONLINE as u64)
            .push_u64(head_size as u64)
            .push_u64((head_size + bob_lbl.len()) as u64);
        reg_bob.extend_from_slice(&bob_head.as_slice()[4..]);
        reg_bob.extend_from_slice(&bob_lbl);
        reg_bob.extend_from_slice(&bob_hint);
        mock::transact_as(BOB_EOA, HUB_ADDR, &reg_bob).expect("register Bob");

        // Verify directory slice returns 2 profiles
        let slice_cd = CallEncoder::<128>::new(selector("getDirectorySlice(uint64,uint64)"))
            .push_u64(0)
            .push_u64(10);
        let dir_raw = mock::transact_as(ALICE_EOA, HUB_ADDR, slice_cd.as_slice()).unwrap();
        let dir_bytes = decode_abi_bytes(&dir_raw);
        assert_eq!(u64::from_be_bytes(dir_bytes[0..8].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(dir_bytes[8..16].try_into().unwrap()), 2);

        // 2. Alice places an encrypted Video call to Bob with pinned DTLS fingerprint
        let alice_dtls = [0xAAu8; 32];
        let bob_dtls = [0xBBu8; 32];
        let offer_blob = b"ECDH_GZIP_SDP_OFFER_PAYLOAD_V1";

        let mut place_cd = Vec::new();
        place_cd.extend_from_slice(&selector("placeCall(address,address,uint64,bytes32,bytes)"));
        let place_head = CallEncoder::<256>::new([0; 4])
            .push_address(&ALICE_ID)
            .push_address(&BOB_ID)
            .push_u64(MEDIA_VIDEO as u64)
            .push_bytes32(&alice_dtls)
            .push_u64((5 * 32) as u64);
        place_cd.extend_from_slice(&place_head.as_slice()[4..]);
        place_cd.extend_from_slice(&pad32(offer_blob));

        let call_id_raw = mock::transact_as(ALICE_EOA, HUB_ADDR, &place_cd).expect("placeCall");
        let call_id = decode_u64(&call_id_raw);
        assert_eq!(call_id, 1);

        // 3. Eve cannot answer Bob's incoming call
        let answer_blob = b"ECDH_GZIP_SDP_ANSWER_PAYLOAD_V1";
        let mut ans_cd = Vec::new();
        ans_cd.extend_from_slice(&selector("answerCall(uint64,address,bytes32,bytes)"));
        let ans_head = CallEncoder::<256>::new([0; 4])
            .push_u64(call_id)
            .push_address(&BOB_ID)
            .push_bytes32(&bob_dtls)
            .push_u64((4 * 32) as u64);
        ans_cd.extend_from_slice(&ans_head.as_slice()[4..]);
        ans_cd.extend_from_slice(&pad32(answer_blob));

        assert_eq!(
            mock::transact_as(EVE_EOA, HUB_ADDR, &ans_cd),
            Err(ERR_UNAUTHORIZED_IDENTITY)
        );

        // Bob answers at block 50,252
        mock::set_block_number(50_252);
        mock::transact_as(BOB_EOA, HUB_ADDR, &ans_cd).expect("answerCall");

        // 4. Both Alice & Bob trickle ICE batches
        let mut ice_alice = Vec::new();
        ice_alice.extend_from_slice(&selector("appendIceBatch(uint64,address,bytes)"));
        let ice_head = CallEncoder::<128>::new([0; 4])
            .push_u64(call_id)
            .push_address(&ALICE_ID)
            .push_u64((3 * 32) as u64);
        ice_alice.extend_from_slice(&ice_head.as_slice()[4..]);
        ice_alice.extend_from_slice(&pad32(b"ICE_BATCH_ALICE_0"));
        mock::transact_as(ALICE_EOA, HUB_ADDR, &ice_alice).expect("alice ice");

        // 5. Inspect full `getCallSession(1)` binary layout
        let sess_cd = CallEncoder::<64>::new(selector("getCallSession(uint64)")).push_u64(call_id);
        let sess_raw = mock::transact_as(ALICE_EOA, HUB_ADDR, sess_cd.as_slice()).unwrap();
        let sess = decode_abi_bytes(&sess_raw);
        let meta = CallMeta::decode(&sess[..CALL_META_LEN]).expect("decode meta");
        assert_eq!(meta.call_id, 1);
        assert_eq!(meta.status, CALL_STATUS_ACTIVE);
        assert_eq!(meta.media_kind, MEDIA_VIDEO);
        assert_eq!(meta.caller_ice_cnt, 1);
        assert_eq!(meta.callee_ice_cnt, 0);
        assert_eq!(meta.caller_dtls_fp, alice_dtls);
        assert_eq!(meta.callee_dtls_fp, bob_dtls);

        let mut p = CALL_META_LEN;
        let olen = u16::from_be_bytes([sess[p], sess[p + 1]]) as usize;
        p += 2;
        assert_eq!(&sess[p..p + olen], offer_blob);
        p += olen;
        let alen = u16::from_be_bytes([sess[p], sess[p + 1]]) as usize;
        p += 2;
        assert_eq!(&sess[p..p + alen], answer_blob);

        // 6. Renegotiate to Screen Share (`MEDIA_SCREEN = 3`) + Hangup
        let mut reneg_cd = Vec::new();
        reneg_cd.extend_from_slice(&selector(
            "renegotiateMedia(uint64,address,uint64,bool,bytes)",
        ));
        let r_head = CallEncoder::<256>::new([0; 4])
            .push_u64(call_id)
            .push_address(&ALICE_ID)
            .push_u64(MEDIA_SCREEN as u64)
            .push_bool(false)
            .push_u64((5 * 32) as u64);
        reneg_cd.extend_from_slice(&r_head.as_slice()[4..]);
        reneg_cd.extend_from_slice(&pad32(b"SCREEN_SHARE_SDP_OFFER"));
        mock::transact_as(ALICE_EOA, HUB_ADDR, &reneg_cd).expect("renegotiate");

        let end_cd = CallEncoder::<128>::new(selector("endCall(uint64,address,uint64)"))
            .push_u64(call_id)
            .push_address(&BOB_ID)
            .push_u64(1);
        mock::transact_as(BOB_EOA, HUB_ADDR, end_cd.as_slice()).expect("endCall");

        let recent_cd = CallEncoder::<64>::new(selector("getRecentCallsForIdentity(address)"))
            .push_address(&BOB_ID);
        let recent_raw = mock::transact_as(BOB_EOA, HUB_ADDR, recent_cd.as_slice()).unwrap();
        let recent_bytes = decode_abi_bytes(&recent_raw);
        assert_eq!(u64::from_be_bytes(recent_bytes[0..8].try_into().unwrap()), 1);
        let ended_meta = CallMeta::decode(&recent_bytes[8..8 + CALL_META_LEN]).unwrap();
        assert_eq!(ended_meta.status, CALL_STATUS_ENDED);
        assert_eq!(ended_meta.media_kind, MEDIA_SCREEN);
    }

    #[test]
    fn test_mesh_conference_room_signaling() {
        setup_env();

        let mut create_cd = Vec::new();
        create_cd.extend_from_slice(&selector("createRoom(address,string,uint64,bool,bytes32)"));
        let c_head = CallEncoder::<256>::new([0; 4])
            .push_address(&ALICE_ID)
            .push_u64((5 * 32) as u64)
            .push_u64(MEDIA_VIDEO as u64)
            .push_bool(true)
            .push_bytes32(&[0xAA; 32]);
        create_cd.extend_from_slice(&c_head.as_slice()[4..]);
        create_cd.extend_from_slice(&pad32(b"Validator Ops Standup"));

        let rm_raw = mock::transact_as(ALICE_EOA, HUB_ADDR, &create_cd).expect("createRoom");
        let room_id = decode_u64(&rm_raw);
        assert_eq!(room_id, 1);

        let join_cd = CallEncoder::<128>::new(selector("joinRoom(uint64,address,bytes32)"))
            .push_u64(room_id)
            .push_address(&BOB_ID)
            .push_bytes32(&[0xBB; 32]);
        let cnt_raw = mock::transact_as(BOB_EOA, HUB_ADDR, join_cd.as_slice()).expect("joinRoom");
        assert_eq!(decode_u64(&cnt_raw), 2);

        // Post pairwise Offer+ICE from Bob -> Alice
        let mut sig_cd = Vec::new();
        sig_cd.extend_from_slice(&selector(
            "postRoomSignal(uint64,address,address,uint64,bytes)",
        ));
        let s_head = CallEncoder::<256>::new([0; 4])
            .push_u64(room_id)
            .push_address(&BOB_ID)
            .push_address(&ALICE_ID)
            .push_u64(4)
            .push_u64((5 * 32) as u64);
        sig_cd.extend_from_slice(&s_head.as_slice()[4..]);
        sig_cd.extend_from_slice(&pad32(b"BOB_TO_ALICE_MESH_OFFER"));
        let seq_raw = mock::transact_as(BOB_EOA, HUB_ADDR, &sig_cd).expect("postRoomSignal");
        assert_eq!(decode_u64(&seq_raw), 1);

        let get_sig_cd =
            CallEncoder::<128>::new(selector("getPairSignal(uint64,address,address)"))
                .push_u64(room_id)
                .push_address(&BOB_ID)
                .push_address(&ALICE_ID);
        let pair_raw = mock::transact_as(ALICE_EOA, HUB_ADDR, get_sig_cd.as_slice()).unwrap();
        let pair_bytes = decode_abi_bytes(&pair_raw);
        assert_eq!(u64::from_be_bytes(pair_bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(pair_bytes[8], 4);
        let env_len = u16::from_be_bytes([pair_bytes[17], pair_bytes[18]]) as usize;
        assert_eq!(&pair_bytes[19..19 + env_len], b"BOB_TO_ALICE_MESH_OFFER");
    }
}
