//! On-Chain HFS App Store & Content-Addressed UI Bundle Registry (`app-store`, HPS #27).
//!
//! Enables developers and users to publish complete `(HFS .wasm + Compressed HTML/CSS/JS UI)`
//! applications on Subnet 1 and run them from a single Host Shell (`/apps.html` or thin host stubs)
//! without redeploying the web client:
//!
//! 1. **Content-Addressed UI Bundle Store (`uiHash = keccak256(compressedPayload)`)**:
//!    - Accepts `1..=8` chunks of up to `32,768` bytes (`256 KiB` compressed ≈ `1.2+ MB` raw UI).
//!    - Upon receiving the final chunk, reassembles the payload in linear memory and enforces
//!      `keccak256(payload) == expectedUiHash` (`ERR_BUNDLE_HASH_MISMATCH = -34`).
//!    - Once sealed, a `uiHash` bundle is immutable forever and deduplicated across any number of
//!      HFS instances or app versions, and retrievable in a single `eth_call` (`getBundle(bytes32)`).
//!
//! 2. **Identity-Verified Permissionless App Catalog & Version History**:
//!    - Anyone can publish a new `slugId` (`bytes32`) bound to their `Identity` HFS (verified via
//!      `msg_sender == publisherIdentity` or `Identity.owner() / isOwnerDevice()`).
//!    - Subsequent updates to an existing `slugId` are restricted strictly to its owning publisher,
//!      incrementing `releaseCount` while preserving immutable `uiHash` content addressing.
//!    - Security invariant: Third-party publishers default to `EXEC_MODE_SANDBOX_IFRAME (0)`
//!      (opaque-origin `<iframe sandbox="allow-scripts allow-forms">`); only `admin()` can mark
//!      an app as `EXEC_MODE_VERIFIED_HOST (1)`.
//!
//! 3. **Instance-to-UI Resolution (`resolveInstance(address)`)**:
//!    - Maps deployed HFS instance addresses (`defaultHfsAddr` or user-spawned instances via
//!      `registerAppInstance`) back to `(appId, uiHash, wasmCodeHash, execMode)` so any `0x…` HFS
//!      address resolves its exact matching UI automatically.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const APP_STORE_ABI_VERSION: u64 = 1;

pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_ARCHIVED: u8 = 2;

pub const EXEC_MODE_SANDBOX_IFRAME: u8 = 0;
pub const EXEC_MODE_VERIFIED_HOST: u8 = 1;

pub const ENCODING_RAW_UTF8: u64 = 0;
pub const ENCODING_GZIP: u64 = 1;

pub const MAX_CHUNK_BYTES: usize = 32_768;
pub const MAX_CHUNKS_PER_BUNDLE: u64 = 8;
pub const MAX_BUNDLE_BYTES: usize = MAX_CHUNK_BYTES * (MAX_CHUNKS_PER_BUNDLE as usize); // 262,144 B

pub const MAX_TITLE_LEN: usize = 64;
pub const MAX_SUMMARY_LEN: usize = 240;
pub const MAX_ICON_LEN: usize = 16;
pub const MAX_VER_LEN: usize = 24;
pub const MAX_INSTANCE_LABEL_LEN: usize = 64;
pub const MAX_SLICE_APPS: u64 = 24;
pub const MAX_SLICE_INSTANCES: u64 = 32;

/// Fixed app record header size:
/// `[app_id:8][status:1][exec_mode:1][category:2][slug_id:32][publisher:20][wasm_hash:32]`
/// `[default_hfs:20][ui_hash:32][release_cnt:8][install_cnt:8][updated_blk:8]`
/// `[title_len:2][sum_len:2][icon_len:2][ver_len:2]` = 180 bytes.
pub const APP_REC_HDR: usize = 180;
pub const MAX_APP_REC_BYTES: usize =
    APP_REC_HDR + MAX_TITLE_LEN + MAX_SUMMARY_LEN + MAX_ICON_LEN + MAX_VER_LEN;

/// Fixed instance record header size:
/// `[instance_addr:20][creator:20][created_blk:8][lbl_len:2]` = 50 bytes.
pub const INST_REC_HDR: usize = 50;
pub const MAX_INST_REC_BYTES: usize = INST_REC_HDR + MAX_INSTANCE_LABEL_LEN;

pub const ERR_BAD_ARGS: i32 = -10;
pub const ERR_ALREADY_INIT: i32 = -11;
pub const ERR_NOT_ADMIN: i32 = -12;
pub const ERR_UNAUTHORIZED_PUBLISHER: i32 = -14;
pub const ERR_SLUG_OWNED_BY_OTHER: i32 = -15;
pub const ERR_INVALID_CHUNK_PARAMS: i32 = -33;
pub const ERR_BUNDLE_HASH_MISMATCH: i32 = -34;
pub const ERR_BUNDLE_NOT_SEALED: i32 = -35;
pub const ERR_WASM_HASH_MISMATCH: i32 = -36;
pub const ERR_APP_NOT_FOUND: i32 = -37;

const KEY_INIT: &[u8] = b"as:init";
const KEY_ADMIN: &[u8] = b"as:admin";
const KEY_TOTAL_APPS: &[u8] = b"as:total_apps";
const KEY_TOTAL_BUNDLES: &[u8] = b"as:total_bundles";

const SEL_ID_OWNER: [u8; 4] = selector("owner()");
const SEL_ID_IS_DEVICE: [u8; 4] = selector("isOwnerDevice(address)");

const EV_INITIALIZED: [u8; 32] = event_topic("AppStoreInitialized(address)");
const EV_BUNDLE_SEALED: [u8; 32] =
    event_topic("UiBundleSealed(bytes32,address,uint64,uint64,uint64)");
const EV_APP_PUBLISHED: [u8; 32] =
    event_topic("AppPublished(uint64,bytes32,address,bytes32,uint64)");
const EV_INSTANCE_REGISTERED: [u8; 32] =
    event_topic("AppInstanceRegistered(uint64,address,address)");

const SLICE_OUT_CAP: usize = 16 + (MAX_SLICE_APPS as usize) * MAX_APP_REC_BYTES;
static mut BUNDLE_SCRATCH: [u8; MAX_BUNDLE_BYTES] = [0u8; MAX_BUNDLE_BYTES];
static mut SLICE_OUT_SCRATCH: [u8; SLICE_OUT_CAP] = [0u8; SLICE_OUT_CAP];

hps_entry! {
    "initialize(address)"                                                                                      => handle_initialize,
    "abiVersion()"                                                                                             => handle_abi_version,
    "admin()"                                                                                                  => handle_admin,
    "rotateAdmin(address)"                                                                                     => handle_rotate_admin,
    "uploadBundleChunk(bytes32,uint64,uint64,uint64,uint64,bytes)"                                             => handle_upload_bundle_chunk,
    "hasBundle(bytes32)"                                                                                       => handle_has_bundle,
    "getBundleInfo(bytes32)"                                                                                   => handle_get_bundle_info,
    "getBundleChunk(bytes32,uint64)"                                                                           => handle_get_bundle_chunk,
    "getBundle(bytes32)"                                                                                       => handle_get_bundle,
    "publishApp(bytes32,address,bytes32,address,bytes32,uint64,uint64,string,string,string,string)"            => handle_publish_app,
    "setAppStatus(uint64,uint64,uint64)"                                                                       => handle_set_app_status,
    "registerAppInstance(uint64,address,address,string)"                                                       => handle_register_app_instance,
    "bindInstanceUi(address,uint64,bytes32)"                                                                   => handle_bind_instance_ui,
    "totalApps()"                                                                                              => handle_total_apps,
    "totalBundles()"                                                                                           => handle_total_bundles,
    "getApp(uint64)"                                                                                           => handle_get_app,
    "getAppBySlug(bytes32)"                                                                                    => handle_get_app_by_slug,
    "getAppsSlice(uint64,uint64)"                                                                              => handle_get_apps_slice,
    "getAppInstances(uint64,uint64,uint64)"                                                                    => handle_get_app_instances,
    "resolveInstance(address)"                                                                                 => handle_resolve_instance,
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

fn caller_is_admin(caller: &[u8; 20]) -> bool {
    let adm = get_admin();
    if adm == [0u8; 20] {
        return false;
    }
    is_authorized_for_identity(caller, &adm)
}

fn bundle_meta_key(ui_hash: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new().push(b"bm:").push(ui_hash)
}

fn bundle_mask_key(ui_hash: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new().push(b"bk:").push(ui_hash)
}

fn bundle_chunk_key(ui_hash: &[u8; 32], idx: u64) -> KeyBuilder<72> {
    KeyBuilder::<72>::new()
        .push(b"bc:")
        .push(ui_hash)
        .push(b":")
        .push_u64_be(idx)
}

fn app_rec_key(app_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"app:").push_u64_be(app_id)
}

fn slug_to_app_key(slug_id: &[u8; 32]) -> KeyBuilder<64> {
    KeyBuilder::<64>::new().push(b"slug:").push(slug_id)
}

fn inst_bind_key(inst_addr: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"ib:").push(inst_addr)
}

fn app_inst_cnt_key(app_id: u64) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"aic:").push_u64_be(app_id)
}

fn app_inst_item_key(app_id: u64, idx: u64) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"aii:")
        .push_u64_be(app_id)
        .push(b":")
        .push_u64_be(idx)
}

/// Bundle metadata layout (`61 bytes`):
/// `[sealed:1][total_chunks:8][compressed_len:8][uncompressed_len:8][encoding:8][uploader:20][sealed_blk:8]`
struct BundleMeta {
    sealed: u8,
    total_chunks: u64,
    compressed_len: u64,
    uncompressed_len: u64,
    encoding: u64,
    uploader: [u8; 20],
    sealed_blk: u64,
}

fn read_bundle_meta(ui_hash: &[u8; 32]) -> Option<BundleMeta> {
    let mut buf = [0u8; 61];
    let n = storage::get_into(bundle_meta_key(ui_hash).as_slice(), &mut buf)?;
    if n < 61 {
        return None;
    }
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&buf[1..9]);
    let total_chunks = u64::from_be_bytes(b8);
    b8.copy_from_slice(&buf[9..17]);
    let compressed_len = u64::from_be_bytes(b8);
    b8.copy_from_slice(&buf[17..25]);
    let uncompressed_len = u64::from_be_bytes(b8);
    b8.copy_from_slice(&buf[25..33]);
    let encoding = u64::from_be_bytes(b8);
    let mut uploader = [0u8; 20];
    uploader.copy_from_slice(&buf[33..53]);
    b8.copy_from_slice(&buf[53..61]);
    let sealed_blk = u64::from_be_bytes(b8);
    Some(BundleMeta {
        sealed: buf[0],
        total_chunks,
        compressed_len,
        uncompressed_len,
        encoding,
        uploader,
        sealed_blk,
    })
}

fn write_bundle_meta(ui_hash: &[u8; 32], m: &BundleMeta) {
    let mut buf = [0u8; 61];
    buf[0] = m.sealed;
    buf[1..9].copy_from_slice(&m.total_chunks.to_be_bytes());
    buf[9..17].copy_from_slice(&m.compressed_len.to_be_bytes());
    buf[17..25].copy_from_slice(&m.uncompressed_len.to_be_bytes());
    buf[25..33].copy_from_slice(&m.encoding.to_be_bytes());
    buf[33..53].copy_from_slice(&m.uploader);
    buf[53..61].copy_from_slice(&m.sealed_blk.to_be_bytes());
    storage::set(bundle_meta_key(ui_hash).as_slice(), &buf);
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
    ret::write_u64_word(APP_STORE_ABI_VERSION);
    Ok(())
}

fn handle_admin(_r: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&get_admin());
    Ok(())
}

fn handle_rotate_admin(r: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    if !caller_is_admin(&caller) {
        return Err(ERR_NOT_ADMIN);
    }
    let next_admin = r.address(0).ok_or(ERR_BAD_ARGS)?;
    storage::set_address(KEY_ADMIN, &next_admin);
    ret::write_bool(true);
    Ok(())
}

fn handle_upload_bundle_chunk(r: &CalldataReader) -> Result<(), i32> {
    let ui_hash = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let chunk_idx = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let total_chunks = r.u64(2).ok_or(ERR_BAD_ARGS)?;
    let encoding = r.u64(3).ok_or(ERR_BAD_ARGS)?;
    let uncompressed_len = r.u64(4).ok_or(ERR_BAD_ARGS)?;
    let chunk_data = r.dynamic_bytes(5).ok_or(ERR_BAD_ARGS)?;

    if ui_hash == [0u8; 32]
        || total_chunks == 0
        || total_chunks > MAX_CHUNKS_PER_BUNDLE
        || chunk_idx >= total_chunks
        || chunk_data.is_empty()
        || chunk_data.len() > MAX_CHUNK_BYTES
    {
        return Err(ERR_INVALID_CHUNK_PARAMS);
    }

    if let Some(existing) = read_bundle_meta(&ui_hash) {
        if existing.sealed == 1 {
            // Already verified & sealed — idempotent success!
            ret::write_bool(true);
            return Ok(());
        }
        if existing.total_chunks != total_chunks {
            return Err(ERR_INVALID_CHUNK_PARAMS);
        }
    } else {
        write_bundle_meta(
            &ui_hash,
            &BundleMeta {
                sealed: 0,
                total_chunks,
                compressed_len: 0,
                uncompressed_len,
                encoding,
                uploader: context::msg_sender(),
                sealed_blk: 0,
            },
        );
    }

    storage::set(bundle_chunk_key(&ui_hash, chunk_idx).as_slice(), chunk_data);

    let prev_mask = storage::get_u64(bundle_mask_key(&ui_hash).as_slice());
    let next_mask = prev_mask | (1u64 << chunk_idx);
    storage::set_u64(bundle_mask_key(&ui_hash).as_slice(), next_mask);

    let full_mask = (1u64 << total_chunks) - 1;
    if next_mask == full_mask {
        // Reassemble all chunks in BUNDLE_SCRATCH and verify keccak256 == ui_hash!
        let total_len = unsafe {
            let mut pos = 0usize;
            let mut i = 0u64;
            while i < total_chunks {
                let ck = bundle_chunk_key(&ui_hash, i);
                let avail = MAX_BUNDLE_BYTES.saturating_sub(pos);
                let n = storage::get_into(ck.as_slice(), &mut BUNDLE_SCRATCH[pos..pos + avail])
                    .ok_or(ERR_INVALID_CHUNK_PARAMS)?;
                if pos + n > MAX_BUNDLE_BYTES {
                    return Err(ERR_INVALID_CHUNK_PARAMS);
                }
                pos += n;
                i += 1;
            }
            let actual_hash = keccak256(&BUNDLE_SCRATCH[..pos]);
            if actual_hash != ui_hash {
                return Err(ERR_BUNDLE_HASH_MISMATCH);
            }
            pos as u64
        };

        let caller = context::msg_sender();
        let blk = context::block_number();
        write_bundle_meta(
            &ui_hash,
            &BundleMeta {
                sealed: 1,
                total_chunks,
                compressed_len: total_len,
                uncompressed_len: if uncompressed_len > 0 {
                    uncompressed_len
                } else {
                    total_len
                },
                encoding,
                uploader: caller,
                sealed_blk: blk,
            },
        );
        let cnt = storage::get_u64(KEY_TOTAL_BUNDLES) + 1;
        storage::set_u64(KEY_TOTAL_BUNDLES, cnt);

        let mut ev_data = [0u8; 96];
        ev_data[24..32].copy_from_slice(&total_len.to_be_bytes());
        ev_data[56..64].copy_from_slice(&total_chunks.to_be_bytes());
        ev_data[88..96].copy_from_slice(&encoding.to_be_bytes());
        events::emit(&[EV_BUNDLE_SEALED, ui_hash, addr_topic(&caller)], &ev_data);
    }

    ret::write_bool(true);
    Ok(())
}

fn handle_has_bundle(r: &CalldataReader) -> Result<(), i32> {
    let ui_hash = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let sealed = read_bundle_meta(&ui_hash).map(|m| m.sealed == 1).unwrap_or(false);
    ret::write_bool(sealed);
    Ok(())
}

fn handle_get_bundle_info(r: &CalldataReader) -> Result<(), i32> {
    let ui_hash = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let mut out = [0u8; 192];
    if let Some(m) = read_bundle_meta(&ui_hash) {
        out[24..32].copy_from_slice(&(m.sealed as u64).to_be_bytes());
        out[56..64].copy_from_slice(&m.total_chunks.to_be_bytes());
        out[88..96].copy_from_slice(&m.compressed_len.to_be_bytes());
        out[120..128].copy_from_slice(&m.uncompressed_len.to_be_bytes());
        out[152..160].copy_from_slice(&m.encoding.to_be_bytes());
        out[172..192].copy_from_slice(&m.uploader);
    }
    ret::write(&out);
    Ok(())
}

fn handle_get_bundle_chunk(r: &CalldataReader) -> Result<(), i32> {
    let ui_hash = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let chunk_idx = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    if let Some(slice) = storage::get_ref(bundle_chunk_key(&ui_hash, chunk_idx).as_slice()) {
        ret::write(slice);
    } else {
        ret::write(&[]);
    }
    Ok(())
}

fn handle_get_bundle(r: &CalldataReader) -> Result<(), i32> {
    let ui_hash = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let meta = match read_bundle_meta(&ui_hash) {
        Some(m) if m.sealed == 1 => m,
        _ => {
            ret::write(&[]);
            return Ok(());
        }
    };
    unsafe {
        let mut pos = 0usize;
        let mut i = 0u64;
        while i < meta.total_chunks {
            let ck = bundle_chunk_key(&ui_hash, i);
            let avail = MAX_BUNDLE_BYTES.saturating_sub(pos);
            let n = storage::get_into(ck.as_slice(), &mut BUNDLE_SCRATCH[pos..pos + avail])
                .unwrap_or(0);
            pos += n;
            i += 1;
        }
        ret::write(&BUNDLE_SCRATCH[..pos]);
    }
    Ok(())
}

fn bind_instance_internal(inst_addr: &[u8; 20], app_id: u64, ui_hash: &[u8; 32], wasm_hash: &[u8; 32], exec_mode: u8) {
    if *inst_addr == [0u8; 20] {
        return;
    }
    let mut b = [0u8; 73];
    b[0..8].copy_from_slice(&app_id.to_be_bytes());
    b[8..40].copy_from_slice(ui_hash);
    b[40..72].copy_from_slice(wasm_hash);
    b[72] = exec_mode;
    storage::set(inst_bind_key(inst_addr).as_slice(), &b);
}

fn handle_publish_app(r: &CalldataReader) -> Result<(), i32> {
    let slug_id = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let publisher_identity = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let wasm_code_hash = r.bytes32(2).ok_or(ERR_BAD_ARGS)?;
    let default_hfs_addr = r.address(3).ok_or(ERR_BAD_ARGS)?;
    let ui_hash = r.bytes32(4).ok_or(ERR_BAD_ARGS)?;
    let category = r.u64(5).ok_or(ERR_BAD_ARGS)?;
    let requested_exec_mode = r.u64(6).ok_or(ERR_BAD_ARGS)?;
    let title = r.dynamic_bytes(7).ok_or(ERR_BAD_ARGS)?;
    let summary = r.dynamic_bytes(8).ok_or(ERR_BAD_ARGS)?;
    let icon = r.dynamic_bytes(9).ok_or(ERR_BAD_ARGS)?;
    let ver_str = r.dynamic_bytes(10).ok_or(ERR_BAD_ARGS)?;

    if slug_id == [0u8; 32] || title.is_empty() {
        return Err(ERR_BAD_ARGS);
    }

    // UI bundle MUST already be uploaded & keccak256-sealed on-chain!
    let bmeta = read_bundle_meta(&ui_hash).ok_or(ERR_BUNDLE_NOT_SEALED)?;
    if bmeta.sealed != 1 {
        return Err(ERR_BUNDLE_NOT_SEALED);
    }

    let caller = context::msg_sender();
    let effective_publisher = if publisher_identity != [0u8; 20] {
        if !is_authorized_for_identity(&caller, &publisher_identity) {
            return Err(ERR_UNAUTHORIZED_PUBLISHER);
        }
        publisher_identity
    } else {
        caller
    };

    // If both defaultHfsAddr and wasmCodeHash are provided, verify on-chain code_hash matches!
    if default_hfs_addr != [0u8; 20] && wasm_code_hash != [0u8; 32] {
        if let Some(live_ch) = context::code_hash_of(&default_hfs_addr) {
            if live_ch != wasm_code_hash {
                return Err(ERR_WASM_HASH_MISMATCH);
            }
        }
    }

    // Security invariant: only store admin can grant EXEC_MODE_VERIFIED_HOST (1)
    let exec_mode: u8 = if requested_exec_mode == (EXEC_MODE_VERIFIED_HOST as u64)
        && caller_is_admin(&caller)
    {
        EXEC_MODE_VERIFIED_HOST
    } else {
        EXEC_MODE_SANDBOX_IFRAME
    };

    let existing_app_id = storage::get_u64(slug_to_app_key(&slug_id).as_slice());
    let (app_id, release_cnt, install_cnt) = if existing_app_id == 0 {
        let new_id = storage::get_u64(KEY_TOTAL_APPS) + 1;
        storage::set_u64(KEY_TOTAL_APPS, new_id);
        storage::set_u64(slug_to_app_key(&slug_id).as_slice(), new_id);
        (new_id, 1u64, 0u64)
    } else {
        let mut prev_hdr = [0u8; APP_REC_HDR];
        let n = storage::get_into(app_rec_key(existing_app_id).as_slice(), &mut prev_hdr)
            .ok_or(ERR_APP_NOT_FOUND)?;
        if n < APP_REC_HDR {
            return Err(ERR_APP_NOT_FOUND);
        }
        let mut prev_pub = [0u8; 20];
        prev_pub.copy_from_slice(&prev_hdr[44..64]);
        if prev_pub != effective_publisher && !caller_is_admin(&caller) {
            return Err(ERR_SLUG_OWNED_BY_OTHER);
        }
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&prev_hdr[148..156]);
        let prev_rel = u64::from_be_bytes(b8);
        b8.copy_from_slice(&prev_hdr[156..164]);
        let prev_inst = u64::from_be_bytes(b8);
        (existing_app_id, prev_rel + 1, prev_inst)
    };

    let t_len = title.len().min(MAX_TITLE_LEN);
    let s_len = summary.len().min(MAX_SUMMARY_LEN);
    let i_len = icon.len().min(MAX_ICON_LEN);
    let v_len = ver_str.len().min(MAX_VER_LEN);
    let blk = context::block_number();

    let mut rec = [0u8; MAX_APP_REC_BYTES];
    rec[0..8].copy_from_slice(&app_id.to_be_bytes());
    rec[8] = STATUS_ACTIVE;
    rec[9] = exec_mode;
    rec[10..12].copy_from_slice(&(category as u16).to_be_bytes());
    rec[12..44].copy_from_slice(&slug_id);
    rec[44..64].copy_from_slice(&effective_publisher);
    rec[64..96].copy_from_slice(&wasm_code_hash);
    rec[96..116].copy_from_slice(&default_hfs_addr);
    rec[116..148].copy_from_slice(&ui_hash);
    rec[148..156].copy_from_slice(&release_cnt.to_be_bytes());
    rec[156..164].copy_from_slice(&install_cnt.to_be_bytes());
    rec[164..172].copy_from_slice(&blk.to_be_bytes());
    rec[172..174].copy_from_slice(&(t_len as u16).to_be_bytes());
    rec[174..176].copy_from_slice(&(s_len as u16).to_be_bytes());
    rec[176..178].copy_from_slice(&(i_len as u16).to_be_bytes());
    rec[178..180].copy_from_slice(&(v_len as u16).to_be_bytes());

    let mut pos = APP_REC_HDR;
    rec[pos..pos + t_len].copy_from_slice(&title[..t_len]);
    pos += t_len;
    rec[pos..pos + s_len].copy_from_slice(&summary[..s_len]);
    pos += s_len;
    rec[pos..pos + i_len].copy_from_slice(&icon[..i_len]);
    pos += i_len;
    rec[pos..pos + v_len].copy_from_slice(&ver_str[..v_len]);
    pos += v_len;

    storage::set(app_rec_key(app_id).as_slice(), &rec[..pos]);
    bind_instance_internal(&default_hfs_addr, app_id, &ui_hash, &wasm_code_hash, exec_mode);

    let mut ev_data = [0u8; 64];
    ev_data[0..32].copy_from_slice(&ui_hash);
    ev_data[56..64].copy_from_slice(&release_cnt.to_be_bytes());
    events::emit(
        &[
            EV_APP_PUBLISHED,
            u64_topic(app_id),
            slug_id,
            addr_topic(&effective_publisher),
        ],
        &ev_data,
    );

    ret::write_u64_word(app_id);
    Ok(())
}

fn handle_set_app_status(r: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    let app_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let next_status = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let next_exec_mode = r.u64(2).ok_or(ERR_BAD_ARGS)?;

    let mut rec = [0u8; MAX_APP_REC_BYTES];
    let n = storage::get_into(app_rec_key(app_id).as_slice(), &mut rec).ok_or(ERR_APP_NOT_FOUND)?;
    if n < APP_REC_HDR {
        return Err(ERR_APP_NOT_FOUND);
    }
    let mut pub_addr = [0u8; 20];
    pub_addr.copy_from_slice(&rec[44..64]);
    let is_adm = caller_is_admin(&caller);
    if !is_adm && !is_authorized_for_identity(&caller, &pub_addr) && caller != pub_addr {
        return Err(ERR_NOT_ADMIN);
    }
    if next_status == (STATUS_ACTIVE as u64) || next_status == (STATUS_ARCHIVED as u64) {
        rec[8] = next_status as u8;
    }
    if is_adm {
        rec[9] = if next_exec_mode == (EXEC_MODE_VERIFIED_HOST as u64) {
            EXEC_MODE_VERIFIED_HOST
        } else {
            EXEC_MODE_SANDBOX_IFRAME
        };
    }
    storage::set(app_rec_key(app_id).as_slice(), &rec[..n]);
    ret::write_bool(true);
    Ok(())
}

fn handle_register_app_instance(r: &CalldataReader) -> Result<(), i32> {
    let app_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let inst_addr = r.address(1).ok_or(ERR_BAD_ARGS)?;
    let creator_id = r.address(2).ok_or(ERR_BAD_ARGS)?;
    let label = r.dynamic_bytes(3).ok_or(ERR_BAD_ARGS)?;

    if inst_addr == [0u8; 20] {
        return Err(ERR_BAD_ARGS);
    }
    let mut app_rec = [0u8; MAX_APP_REC_BYTES];
    let app_n =
        storage::get_into(app_rec_key(app_id).as_slice(), &mut app_rec).ok_or(ERR_APP_NOT_FOUND)?;
    if app_n < APP_REC_HDR {
        return Err(ERR_APP_NOT_FOUND);
    }

    let mut wasm_hash = [0u8; 32];
    wasm_hash.copy_from_slice(&app_rec[64..96]);
    let mut ui_hash = [0u8; 32];
    ui_hash.copy_from_slice(&app_rec[116..148]);
    let exec_mode = app_rec[9];

    if wasm_hash != [0u8; 32] {
        if let Some(live_ch) = context::code_hash_of(&inst_addr) {
            if live_ch != wasm_hash {
                return Err(ERR_WASM_HASH_MISMATCH);
            }
        }
    }

    let caller = context::msg_sender();
    let effective_creator = if creator_id != [0u8; 20] && is_authorized_for_identity(&caller, &creator_id)
    {
        creator_id
    } else {
        caller
    };

    let idx = storage::get_u64(app_inst_cnt_key(app_id).as_slice());
    storage::set_u64(app_inst_cnt_key(app_id).as_slice(), idx + 1);

    let l_len = label.len().min(MAX_INSTANCE_LABEL_LEN);
    let mut irec = [0u8; MAX_INST_REC_BYTES];
    irec[0..20].copy_from_slice(&inst_addr);
    irec[20..40].copy_from_slice(&effective_creator);
    irec[40..48].copy_from_slice(&context::block_number().to_be_bytes());
    irec[48..50].copy_from_slice(&(l_len as u16).to_be_bytes());
    irec[50..50 + l_len].copy_from_slice(&label[..l_len]);
    storage::set(
        app_inst_item_key(app_id, idx).as_slice(),
        &irec[..50 + l_len],
    );

    // Increment install_cnt in app record
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&app_rec[156..164]);
    let next_installs = u64::from_be_bytes(b8) + 1;
    app_rec[156..164].copy_from_slice(&next_installs.to_be_bytes());
    storage::set(app_rec_key(app_id).as_slice(), &app_rec[..app_n]);

    bind_instance_internal(&inst_addr, app_id, &ui_hash, &wasm_hash, exec_mode);

    events::emit(
        &[
            EV_INSTANCE_REGISTERED,
            u64_topic(app_id),
            addr_topic(&inst_addr),
            addr_topic(&effective_creator),
        ],
        &[],
    );

    ret::write_u64_word(idx + 1);
    Ok(())
}

fn handle_bind_instance_ui(r: &CalldataReader) -> Result<(), i32> {
    let inst_addr = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let app_id = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let ui_hash = r.bytes32(2).ok_or(ERR_BAD_ARGS)?;
    if inst_addr == [0u8; 20] {
        return Err(ERR_BAD_ARGS);
    }
    let bmeta = read_bundle_meta(&ui_hash).ok_or(ERR_BUNDLE_NOT_SEALED)?;
    if bmeta.sealed != 1 {
        return Err(ERR_BUNDLE_NOT_SEALED);
    }
    let mut app_rec = [0u8; MAX_APP_REC_BYTES];
    let n = storage::get_into(app_rec_key(app_id).as_slice(), &mut app_rec).ok_or(ERR_APP_NOT_FOUND)?;
    if n < APP_REC_HDR {
        return Err(ERR_APP_NOT_FOUND);
    }
    let mut pub_addr = [0u8; 20];
    pub_addr.copy_from_slice(&app_rec[44..64]);
    let caller = context::msg_sender();
    if caller != pub_addr && !is_authorized_for_identity(&caller, &pub_addr) && !caller_is_admin(&caller)
    {
        return Err(ERR_UNAUTHORIZED_PUBLISHER);
    }
    let mut wasm_hash = [0u8; 32];
    wasm_hash.copy_from_slice(&app_rec[64..96]);
    bind_instance_internal(&inst_addr, app_id, &ui_hash, &wasm_hash, app_rec[9]);
    ret::write_bool(true);
    Ok(())
}

fn handle_total_apps(_r: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_APPS));
    Ok(())
}

fn handle_total_bundles(_r: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_BUNDLES));
    Ok(())
}

fn handle_get_app(r: &CalldataReader) -> Result<(), i32> {
    let app_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    if let Some(slice) = storage::get_ref(app_rec_key(app_id).as_slice()) {
        ret::write(slice);
    } else {
        ret::write(&[]);
    }
    Ok(())
}

fn handle_get_app_by_slug(r: &CalldataReader) -> Result<(), i32> {
    let slug_id = r.bytes32(0).ok_or(ERR_BAD_ARGS)?;
    let app_id = storage::get_u64(slug_to_app_key(&slug_id).as_slice());
    if app_id == 0 {
        ret::write(&[]);
        return Ok(());
    }
    if let Some(slice) = storage::get_ref(app_rec_key(app_id).as_slice()) {
        ret::write(slice);
    } else {
        ret::write(&[]);
    }
    Ok(())
}

fn handle_get_apps_slice(r: &CalldataReader) -> Result<(), i32> {
    let offset = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let limit = r.u64(1).ok_or(ERR_BAD_ARGS)?.min(MAX_SLICE_APPS);
    let total = storage::get_u64(KEY_TOTAL_APPS);

    unsafe {
        SLICE_OUT_SCRATCH[0..8].copy_from_slice(&total.to_be_bytes());
        let mut pos = 16usize;
        let mut returned = 0u64;
        let mut cur = offset + 1;
        while cur <= total && returned < limit {
            let mut rec_buf = [0u8; MAX_APP_REC_BYTES];
            if let Some(n) = storage::get_into(app_rec_key(cur).as_slice(), &mut rec_buf) {
                let len = n.min(MAX_APP_REC_BYTES);
                if pos + len <= SLICE_OUT_CAP {
                    SLICE_OUT_SCRATCH[pos..pos + len].copy_from_slice(&rec_buf[..len]);
                    pos += len;
                    returned += 1;
                }
            }
            cur += 1;
        }
        SLICE_OUT_SCRATCH[8..16].copy_from_slice(&returned.to_be_bytes());
        ret::write(&SLICE_OUT_SCRATCH[..pos]);
    }
    Ok(())
}

fn handle_get_app_instances(r: &CalldataReader) -> Result<(), i32> {
    let app_id = r.u64(0).ok_or(ERR_BAD_ARGS)?;
    let offset = r.u64(1).ok_or(ERR_BAD_ARGS)?;
    let limit = r.u64(2).ok_or(ERR_BAD_ARGS)?.min(MAX_SLICE_INSTANCES);
    let total = storage::get_u64(app_inst_cnt_key(app_id).as_slice());

    let mut out = [0u8; 16 + (MAX_SLICE_INSTANCES as usize) * MAX_INST_REC_BYTES];
    out[0..8].copy_from_slice(&total.to_be_bytes());
    let mut pos = 16usize;
    let mut returned = 0u64;
    let mut cur = offset;
    while cur < total && returned < limit {
        let mut irec = [0u8; MAX_INST_REC_BYTES];
        if let Some(n) = storage::get_into(app_inst_item_key(app_id, cur).as_slice(), &mut irec) {
            let len = n.min(MAX_INST_REC_BYTES);
            out[pos..pos + len].copy_from_slice(&irec[..len]);
            pos += len;
            returned += 1;
        }
        cur += 1;
    }
    out[8..16].copy_from_slice(&returned.to_be_bytes());
    ret::write(&out[..pos]);
    Ok(())
}

fn handle_resolve_instance(r: &CalldataReader) -> Result<(), i32> {
    let inst_addr = r.address(0).ok_or(ERR_BAD_ARGS)?;
    let mut out = [0u8; 128];
    let mut b = [0u8; 73];
    if let Some(n) = storage::get_into(inst_bind_key(&inst_addr).as_slice(), &mut b) {
        if n >= 73 {
            out[24..32].copy_from_slice(&b[0..8]); // appId
            out[32..64].copy_from_slice(&b[8..40]); // uiHash
            out[64..96].copy_from_slice(&b[40..72]); // wasmCodeHash
            out[127] = b[72]; // execMode
        }
    }
    ret::write(&out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    fn encode_upload_chunk(
        ui_hash: [u8; 32],
        chunk_idx: u64,
        total_chunks: u64,
        encoding: u64,
        uncompressed_len: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector(
            "uploadBundleChunk(bytes32,uint64,uint64,uint64,uint64,bytes)",
        ));
        cd.extend_from_slice(&ui_hash);
        let push_u64 = |v: &mut Vec<u8>, n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&w);
        };
        push_u64(&mut cd, chunk_idx);
        push_u64(&mut cd, total_chunks);
        push_u64(&mut cd, encoding);
        push_u64(&mut cd, uncompressed_len);
        push_u64(&mut cd, 6 * 32); // dynamic offset
        push_u64(&mut cd, data.len() as u64);
        cd.extend_from_slice(data);
        while cd.len() % 32 != 4 {
            cd.push(0);
        }
        cd
    }

    fn encode_publish_app(
        slug_id: [u8; 32],
        pub_id: [u8; 20],
        wasm_hash: [u8; 32],
        def_hfs: [u8; 20],
        ui_hash: [u8; 32],
        cat: u64,
        exec_mode: u64,
        title: &str,
        summary: &str,
        icon: &str,
        ver: &str,
    ) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector(
            "publishApp(bytes32,address,bytes32,address,bytes32,uint64,uint64,string,string,string,string)",
        ));
        let push_w = |v: &mut Vec<u8>, w: [u8; 32]| v.extend_from_slice(&w);
        let addr_w = |a: [u8; 20]| {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(&a);
            w
        };
        let u64_w = |n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            w
        };

        push_w(&mut cd, slug_id);
        push_w(&mut cd, addr_w(pub_id));
        push_w(&mut cd, wasm_hash);
        push_w(&mut cd, addr_w(def_hfs));
        push_w(&mut cd, ui_hash);
        push_w(&mut cd, u64_w(cat));
        push_w(&mut cd, u64_w(exec_mode));

        let dyn_items = [
            title.as_bytes(),
            summary.as_bytes(),
            icon.as_bytes(),
            ver.as_bytes(),
        ];
        let mut cur_off = 11 * 32usize;
        let mut tail = Vec::new();
        for item in dyn_items {
            push_w(&mut cd, u64_w(cur_off as u64));
            tail.extend_from_slice(&u64_w(item.len() as u64));
            let padded = (item.len() + 31) & !31;
            let start = tail.len();
            tail.resize(start + padded, 0);
            tail[start..start + item.len()].copy_from_slice(item);
            cur_off += 32 + padded;
        }
        cd.extend_from_slice(&tail);
        cd
    }

    #[test]
    fn multi_chunk_bundle_keccak_verification_and_app_lifecycle() {
        mock::reset();
        let store_addr = [0xAA; 20];
        let admin = [0x01; 20];
        let alice = [0x02; 20];
        let bob = [0x03; 20];
        let hfs_inst = [0x77; 20];
        let wasm_hash = [0x55; 32];

        mock::register_hps(store_addr, dispatch_calldata);
        mock::set_code_hash(hfs_inst, wasm_hash);
        mock::set_block_number(420);

        let init_cd = CallEncoder::<64>::new(selector("initialize(address)")).push_address(&admin);
        mock::transact_as(admin, store_addr, init_cd.as_slice()).expect("init");

        // Build 2-chunk UI bundle and verify wrong hash reverts
        let full_ui = b"<!DOCTYPE html><html><body><h1>Mesh Poll v1</h1><script>window.slx</script></body></html>";
        let expected_hash = keccak256(full_ui);
        let wrong_hash = [0x99; 32];

        let bad_cd = encode_upload_chunk(wrong_hash, 0, 1, ENCODING_GZIP, 256, full_ui);
        assert_eq!(
            mock::transact_as(alice, store_addr, &bad_cd),
            Err(ERR_BUNDLE_HASH_MISMATCH)
        );

        // Upload as 2 valid chunks (out of order: chunk 1 then chunk 0!)
        let mid = full_ui.len() / 2;
        let c1 = encode_upload_chunk(expected_hash, 1, 2, ENCODING_GZIP, 256, &full_ui[mid..]);
        let c0 = encode_upload_chunk(expected_hash, 0, 2, ENCODING_GZIP, 256, &full_ui[..mid]);
        mock::transact_as(alice, store_addr, &c1).expect("chunk 1");
        mock::transact_as(alice, store_addr, &c0).expect("chunk 0 seals bundle");

        // Single-call getBundle returns exact bytes
        let gb_cd =
            CallEncoder::<64>::new(selector("getBundle(bytes32)")).push_bytes32(&expected_hash);
        let fetched = mock::transact_as(alice, store_addr, gb_cd.as_slice()).expect("getBundle");
        assert_eq!(fetched.as_slice(), full_ui);

        // Alice publishes app (requests exec_mode=1, downgraded to 0 SANDBOX_IFRAME since Alice != admin)
        let slug = keccak256(b"mesh-poll");
        let pub_cd = encode_publish_app(
            slug,
            [0u8; 20],
            wasm_hash,
            hfs_inst,
            expected_hash,
            2,
            1,
            "Mesh Poll",
            "Off-grid community governance poll",
            "🗳️",
            "1.0.0",
        );
        let app_id_ret = mock::transact_as(alice, store_addr, &pub_cd).expect("publish");
        assert_eq!(app_id_ret[31], 1);

        // Bob cannot hijack Alice's slug
        assert_eq!(
            mock::transact_as(bob, store_addr, &pub_cd),
            Err(ERR_SLUG_OWNED_BY_OTHER)
        );

        // Resolve instance returns appId=1, expected_hash, wasm_hash, execMode=0
        let res_cd =
            CallEncoder::<64>::new(selector("resolveInstance(address)")).push_address(&hfs_inst);
        let resolved = mock::transact_as(bob, store_addr, res_cd.as_slice()).expect("resolve");
        assert_eq!(resolved[31], 1);
        assert_eq!(&resolved[32..64], &expected_hash);
        assert_eq!(&resolved[64..96], &wasm_hash);
        assert_eq!(resolved[127], EXEC_MODE_SANDBOX_IFRAME);
    }
}
