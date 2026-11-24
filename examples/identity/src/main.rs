//! On-Chain Identity **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! All state-changing interactions with `IdentityRegistry`, `Constitution`, `Authorization`,
//! `AssetLedger`, and `AssetPair_OTC` occur through a verified `Identity` HPS instance so
//! `context::msg_sender()` inside those target subroutines is always the calling Identity's
//! 20-byte HPS address (`context::self_address()`).
//!
//! Provides both general-purpose `execute(address targetHps, bytes callData)` forwarding and
//! ergonomic typed entrypoints for authorization workflows and asset ledger operations.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::bulletproofs::{
    scalar_from_hash_nonzero, scalar_from_u64, scalar_is_canonical, scalar_neg, BP_H_BLIND_BYTES,
};
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::vrf::{
    ec_elgamal_lincomb, ED25519_BASEPOINT_BYTES, IDENTITY_POINT_BYTES, SCALAR_ONE_BYTES,
};
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const IDENTITY_INITIALIZED: [u8; 32] = event_topic("IdentityInitialized(address,string)");
const NICKNAME_UPDATED: [u8; 32] = event_topic("NicknameUpdated(address,string)");
const DELEGATE_UPDATED: [u8; 32] = event_topic("DelegateUpdated(address,bool)");
const EXECUTED_CALL: [u8; 32] = event_topic("Executed(address,bytes4)");
const AUTH_SIGNED: [u8; 32] = event_topic("AuthorizationSigned(address,uint64)");
const HFS_ASSOC_UPDATED: [u8; 32] =
    event_topic("HfsAssociationUpdated(address,bytes32,uint64)");
const HFS_ASSOC_NOTIFIED: [u8; 32] =
    event_topic("HfsAssociationNotified(address,bytes32,address)");
const DELEGATED_HFS_ASSOC_UPDATED: [u8; 32] =
    event_topic("DelegatedHfsAssociationUpdated(address,address,bytes32,uint64)");
const ENCRYPTION_KEYS_UPDATED: [u8; 32] =
    event_topic("EncryptionKeysUpdated(address,bytes32)");
const OWNER_DEVICE_UPDATED: [u8; 32] =
    event_topic("OwnerDeviceUpdated(address,uint64)");
const GUARDIAN_SLOT_ADDED: [u8; 32] =
    event_topic("GuardianSlotAdded(uint64,address,uint64)");
const GUARDIAN_SLOT_ALLOCATED: [u8; 32] =
    event_topic("GuardianSlotAllocated(uint64,address,uint64)");
const SHAMIR_CONFIGURED: [u8; 32] =
    event_topic("ShamirRecoveryConfigured(uint64,uint64,uint64)");
const RECOVERY_INITIATED: [u8; 32] =
    event_topic("RecoveryInitiated(uint64,address,bytes32)");
const RECOVERY_SHARE_SUBMITTED: [u8; 32] =
    event_topic("RecoveryShareSubmitted(uint64,uint64,uint64)");
const RECOVERY_CANCELLED: [u8; 32] =
    event_topic("RecoveryCancelled(uint64,address)");
const RECOVERY_FINALIZED: [u8; 32] =
    event_topic("RecoveryFinalized(uint64,address,uint64)");

/// Validity states for subroutines in this Identity's Associated HFS Register:
/// - `0` (`UNLISTED`): Not recorded in this Identity's register.
/// - `1` (`PENDING`): Inbound / unverified association awaiting owner review (shown in Spam/Unverified).
/// - `2` (`WHITELISTED`): Validly associated & whitelisted by owner/delegate.
/// - `3` (`SPAM`): Explicitly rejected / blocked as spam; outbound calls to this HFS revert (`-29`).
pub const HFS_STATUS_UNLISTED: u8 = 0;
pub const HFS_STATUS_PENDING: u8 = 1;
pub const HFS_STATUS_WHITELISTED: u8 = 2;
pub const HFS_STATUS_SPAM: u8 = 3;

pub const DEV_STATUS_ACTIVE: u8 = 1;
pub const DEV_STATUS_REVOKED: u8 = 2;

pub const SLOT_STATUS_ACTIVE: u8 = 1;
pub const SLOT_STATUS_SEALED_FULL: u8 = 2;
pub const SLOT_STATUS_RETIRED: u8 = 3;

pub const SHARE_KIND_GUARDIAN_SLOT: u8 = 1;
pub const SHARE_KIND_DIRECT_EOA: u8 = 2;
pub const SHARE_KIND_SELF_PASSPHRASE: u8 = 3;

pub const REC_STATUS_NONE: u8 = 0;
pub const REC_STATUS_COLLECTING: u8 = 1;
pub const REC_STATUS_TIMELOCKED: u8 = 2;
pub const REC_STATUS_FINALIZED: u8 = 3;
pub const REC_STATUS_CANCELLED: u8 = 4;

pub const IDENTITY_ABI_VERSION: u64 = 4;
const MAX_HFS_LABEL_LEN: usize = 64;
const FIXED_HFS_REC_HDR: usize = 83; // [status:1][addr:20][type_id:32][blk:8][actor:20][lbl_len:2]
const MAX_HFS_REC_BYTES: usize = FIXED_HFS_REC_HDR + MAX_HFS_LABEL_LEN;
const MAX_HFS_SLICE_LIMIT: u64 = 64;
const HFS_SLICE_OUT_CAP: usize = 16 + (MAX_HFS_SLICE_LIMIT as usize) * (8 + MAX_HFS_REC_BYTES);
const MAX_TOTAL_HFS_ENTRIES: u64 = 512;
const MAX_BATCH_ENTRIES: usize = 32;

const MAX_OWNER_DEVICES: usize = 16;
const MAX_DEV_LABEL_LEN: usize = 32;
const MAX_WRAPPED_SEED_LEN: usize = 192;
const MAX_GUARDIAN_SLOTS: usize = 32;
const MAX_SHAMIR_SHARES: usize = 8;
const MAX_SHAMIR_THRESHOLD: usize = 6;
const MAX_SHARE_ENV_LEN: usize = 320;
const BLINDED_SHARE_PROOF_LEN: usize = 416; // 13 * 32B

const KEY_INIT: &[u8] = b"id:init";
const KEY_OWNER: &[u8] = b"id:owner";
const KEY_HANDLE: &[u8] = b"id:handle";
const KEY_NICKNAME: &[u8] = b"id:nick";
const KEY_HFS_COUNT: &[u8] = b"id:hfs:cnt";
const KEY_SECP_PUB64: &[u8] = b"id:enc:secp64";
const KEY_ED_PUB32: &[u8] = b"id:enc:ed32";
const KEY_DEV_COUNT: &[u8] = b"id:dev:cnt";
const KEY_GK_COUNT: &[u8] = b"id:gk:cnt";
const KEY_REC_CFG: &[u8] = b"id:rec:cfg";
const KEY_REC_SESS: &[u8] = b"id:rec:sess";

static mut ID_VIEW_OUT: [u8; 8192] = [0u8; 8192];

hps_entry! {
    "initialize(address,string)"                                                      => handle_initialize,
    "initializeWithNickname(address,string,string)"                                   => handle_initialize_with_nickname,
    "initializeWithKeys(address,string,string,bytes,bytes32)"                         => handle_initialize_with_keys,
    "setEncryptionKeys(bytes,bytes32)"                                                => handle_set_encryption_keys,
    "setNickname(string)"                                                             => handle_set_nickname,
    "setDelegate(address,bool)"                                                       => handle_set_delegate,
    "transferOwnership(address)"                                                      => handle_transfer_ownership,
    "transferOwnershipWithKeys(address,bytes,bytes32)"                                => handle_transfer_ownership_with_keys,
    "execute(address,bytes)"                                                          => handle_execute,
    "initCharterAuth(address,address,address,address,bytes32,bytes32)"                => handle_init_constitution_auth,
    "initConstitutionAuth(address,address,address,address,bytes32,bytes32)"           => handle_init_constitution_auth,
    "initOracleAuth(address,address,address,address,bytes32,uint64)"                  => handle_init_oracle_auth,
    "initTransferAuction(address,address,address,address)"                            => handle_init_transfer_auction,
    "initShareIssuance(address,address,address,address,uint64,uint64)"                => handle_init_share_issuance,
    "approveAuth(address)"                                                            => handle_approve_auth,
    "approveAndFinalizeAuth(address)"                                                 => handle_approve_and_finalize_auth,
    "finalizeAuth(address)"                                                           => handle_finalize_auth,
    "placeBuyOrder(address,uint64,uint64)"                                            => handle_place_buy_order,
    "cancelBuyOrder(address,uint64)"                                                  => handle_cancel_buy_order,
    "placeSellOrder(address,uint64,uint64)"                                           => handle_place_sell_order,
    "settleTransferAuction(address,address)"                                          => handle_settle_transfer_auction,
    "placeBuyOrderViaShareCapital(address,address,uint64,uint64)"                     => handle_place_buy_order_via_sc,
    "cancelBuyOrderViaShareCapital(address,address,uint64)"                           => handle_cancel_buy_order_via_sc,
    "placeSellOrderViaShareCapital(address,address,uint64,uint64)"                    => handle_place_sell_order_via_sc,
    "settleAuctionViaShareCapital(address,address,address)"                           => handle_settle_auction_via_sc,
    "settleIssuanceViaShareCapital(address,address,address)"                          => handle_settle_issuance_via_sc,
    "refundFailedAuctionViaShareCapital(address,address)"                             => handle_refund_failed_auction_via_sc,
    "transferBankBalance(address,address,uint64)"                                     => handle_transfer_bank_balance,
    "setShareEscrowAccount(address,address,address,address)"                          => handle_set_share_escrow_account,
    "setOperatingAccount(address,address,address,address)"                            => handle_set_operating_account,
    "registerShareClass(address,address,uint64,uint64,uint64,address)"                => handle_register_share_class,
    "authorizeFuturesUnderwriting(address,address,uint64,address)"                    => handle_authorize_futures_underwriting,
    "underwriteFutures(address,uint64)"                                               => handle_underwrite_futures,
    "closeUnderwrittenFutures(address,uint64)"                                        => handle_close_underwritten_futures,
    "setAttachedDex(address,address,address)"                                         => handle_set_attached_dex,
    "dexPlaceBid(address,uint64,uint64)"                                              => handle_dex_place_bid,
    "dexPlaceAsk(address,uint64,uint64)"                                              => handle_dex_place_ask,
    "dexCancelOrder(address,uint64)"                                                  => handle_dex_cancel_order,
    "dexMatchBlock(address)"                                                          => handle_dex_match_block,
    "upsertProduct(address,bytes32,uint64,uint64,bytes,address)"                      => handle_upsert_product,
    "restockProduct(address,bytes32,uint64,uint64,address)"                           => handle_restock_product,
    "setProductPrice(address,bytes32,uint64,address)"                                 => handle_set_product_price,
    "buyProduct(address,bytes32,uint64)"                                              => handle_buy_product,
    "issueAsset(address,address,uint64,address)"                                      => handle_issue_asset,
    "cancelAsset(address,address,uint64,address)"                                     => handle_cancel_asset,
    "transferAsset(address,address,address,uint64,address)"                           => handle_transfer_asset,
    "approveAsset(address,address,uint64,address)"                                    => handle_approve_asset,
    "addDirector(address,address,address)"                                            => handle_add_director,
    "removeDirector(address,address,address)"                                         => handle_remove_director,
    "grantRole(address,bytes32,address,address)"                                      => handle_grant_role,
    "revokeRole(address,bytes32,address,address)"                                     => handle_revoke_role,
    "defineRole(address,bytes32,address)"                                             => handle_define_role,
    "setFunctionAuth(address,address,bytes4,bytes32,address)"                         => handle_set_function_auth,
    "authorizeModule(address,address,bytes32,bool,address)"                           => handle_authorize_module,
    "activateCharter(address,address)"                                                => handle_activate_charter,
    "identityVersion()"                                                               => handle_identity_version,
    "setHfsAssociation(address,bytes32,uint64,string)"                                => handle_set_hfs_association,
    "setHfsAssociationBatch(bytes)"                                                   => handle_set_hfs_association_batch,
    "notifyHfsAssociation(address,bytes32,string)"                                    => handle_notify_hfs_association,
    "getHfsAssociationStatus(address)"                                                => handle_get_hfs_association_status,
    "isHfsWhitelisted(address)"                                                       => handle_is_hfs_whitelisted,
    "getHfsAssociationCount()"                                                        => handle_get_hfs_association_count,
    "getHfsAssociationsSlice(uint64,uint64)"                                          => handle_get_hfs_associations_slice,
    "setDelegatedHfsAssociation(address,bytes32,uint64,string)"                       => handle_set_delegated_hfs_association,
    "setDelegatedHfsAssociationBatch(bytes)"                                          => handle_set_delegated_hfs_association_batch,
    "notifyDelegatedHfsAssociation(address,address,bytes32,string)"                   => handle_notify_delegated_hfs_association,
    "getDelegatedHfsAssociationStatus(address,address)"                               => handle_get_delegated_hfs_association_status,
    "getDelegatedHfsAssociationsSlice(address,uint64,uint64)"                         => handle_get_delegated_hfs_associations_slice,
    "owner()"                                                                         => handle_owner,
    "isAuthorized(address)"                                                           => handle_is_authorized,
    "hasApprovedAuth(address)"                                                        => handle_has_approved_auth,
    "handle()"                                                                        => handle_handle,
    "nickname()"                                                                      => handle_nickname,
    "balanceIn(address)"                                                              => handle_balance_in,
    "encryptionKeys()"                                                                => handle_encryption_keys,
    "secp256k1PubKey()"                                                               => handle_secp256k1_pubkey,
    "ed25519PubKey()"                                                                 => handle_ed25519_pubkey,
    "initializeWithKeysAndSeed(address,string,string,bytes,bytes32,bytes,bytes)"      => handle_initialize_with_keys_and_seed,
    "addOwnerDevice(address,bytes,string,bytes)"                                      => handle_add_owner_device,
    "updateDeviceWrappedSeed(address,bytes,bytes)"                                    => handle_update_device_wrapped_seed,
    "removeOwnerDevice(address,bytes,bytes32,bytes)"                                  => handle_remove_owner_device,
    "isOwnerDevice(address)"                                                          => handle_is_owner_device,
    "getOwnerDevices()"                                                               => handle_get_owner_devices,
    "addGuardianKeySlot(address,bytes32,bytes,uint64,string)"                         => handle_add_guardian_key_slot,
    "retireGuardianKeySlot(uint64)"                                                   => handle_retire_guardian_key_slot,
    "allocateGuardianSlot(address)"                                                   => handle_allocate_guardian_slot,
    "previewAvailableGuardianSlot(address)"                                           => handle_preview_available_guardian_slot,
    "getGuardianKeychain()"                                                           => handle_get_guardian_keychain,
    "configureShamirRecovery(uint64,uint64,bytes,bytes)"                              => handle_configure_shamir_recovery,
    "initiateRecovery(address,bytes,bytes32,string)"                                  => handle_initiate_recovery,
    "submitRecoveryShare(uint64,uint64,bytes)"                                        => handle_submit_recovery_share,
    "cancelRecovery()"                                                                => handle_cancel_recovery,
    "finalizeRecovery(uint64,bool,bytes)"                                             => handle_finalize_recovery,
    "getRecoveryState()"                                                              => handle_get_recovery_state,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn delegate_key(actor: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"del:").push(actor)
}

fn auth_stamp_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"ast:").push(auth_obj)
}

fn hfs_status_key(ns_id: Option<&[u8; 20]>, hfs_addr: &[u8; 20]) -> KeyBuilder<64> {
    match ns_id {
        Some(sub) => KeyBuilder::<64>::new()
            .push(b"dhfs:st:")
            .push(sub)
            .push(hfs_addr),
        None => KeyBuilder::<64>::new().push(b"id:hfs:st:").push(hfs_addr),
    }
}

fn hfs_idx_key(ns_id: Option<&[u8; 20]>, hfs_addr: &[u8; 20]) -> KeyBuilder<64> {
    match ns_id {
        Some(sub) => KeyBuilder::<64>::new()
            .push(b"dhfs:idx:")
            .push(sub)
            .push(hfs_addr),
        None => KeyBuilder::<64>::new().push(b"id:hfs:idx:").push(hfs_addr),
    }
}

fn hfs_count_key(ns_id: Option<&[u8; 20]>) -> KeyBuilder<48> {
    match ns_id {
        Some(sub) => KeyBuilder::<48>::new().push(b"dhfs:cnt:").push(sub),
        None => KeyBuilder::<48>::new().push(KEY_HFS_COUNT),
    }
}

fn hfs_item_key(ns_id: Option<&[u8; 20]>, idx: u64) -> KeyBuilder<64> {
    match ns_id {
        Some(sub) => KeyBuilder::<64>::new()
            .push(b"dhfs:itm:")
            .push(sub)
            .push_u64_be(idx),
        None => KeyBuilder::<64>::new()
            .push(b"id:hfs:itm:")
            .push_u64_be(idx),
    }
}

fn get_hfs_status_ns(ns_id: Option<&[u8; 20]>, hfs_addr: &[u8; 20]) -> u8 {
    if *hfs_addr == [0u8; 20] {
        return HFS_STATUS_UNLISTED;
    }
    let sk = hfs_status_key(ns_id, hfs_addr);
    storage::get_u64(sk.as_slice()) as u8
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

fn pack_hfs_record(
    status: u8,
    hfs_addr: &[u8; 20],
    type_id: &[u8; 32],
    updated_block: u64,
    actor: &[u8; 20],
    label: &[u8],
    out: &mut [u8; MAX_HFS_REC_BYTES],
) -> usize {
    let lbl_len = label.len().min(MAX_HFS_LABEL_LEN);
    out[0] = status;
    out[1..21].copy_from_slice(hfs_addr);
    out[21..53].copy_from_slice(type_id);
    out[53..61].copy_from_slice(&updated_block.to_be_bytes());
    out[61..81].copy_from_slice(actor);
    out[81..83].copy_from_slice(&(lbl_len as u16).to_be_bytes());
    out[83..83 + lbl_len].copy_from_slice(&label[..lbl_len]);
    83 + lbl_len
}

fn upsert_hfs_record_ns(
    ns_id: Option<&[u8; 20]>,
    hfs_addr: &[u8; 20],
    type_id: &[u8; 32],
    status: u8,
    actor: &[u8; 20],
    label: &[u8],
) -> Result<(u64, [u8; 32]), i32> {
    if *hfs_addr == [0u8; 20] {
        return Err(-23);
    }
    if status != HFS_STATUS_PENDING
        && status != HFS_STATUS_WHITELISTED
        && status != HFS_STATUS_SPAM
    {
        return Err(-26);
    }
    if label.len() > MAX_HFS_LABEL_LEN {
        return Err(-27);
    }
    if (status == HFS_STATUS_WHITELISTED || status == HFS_STATUS_PENDING)
        && !has_deployed_wasm(hfs_addr)
    {
        return Err(-28); // Must be a deployed WASM HFS subroutine (not a raw EOA)
    }

    let ik_lookup = hfs_idx_key(ns_id, hfs_addr);
    let existing_plus_one = storage::get_u64(ik_lookup.as_slice());
    let now = context::block_number();

    let mut eff_type = *type_id;
    let mut prev_label_buf = [0u8; MAX_HFS_LABEL_LEN];
    let mut prev_label_len = 0usize;

    let idx = if existing_plus_one > 0 {
        let i = existing_plus_one - 1;
        let itm_k = hfs_item_key(ns_id, i);
        let mut old_buf = [0u8; MAX_HFS_REC_BYTES];
        let old_n = storage::get_into(itm_k.as_slice(), &mut old_buf).unwrap_or(0);
        if old_n >= FIXED_HFS_REC_HDR {
            if eff_type == [0u8; 32] {
                eff_type.copy_from_slice(&old_buf[21..53]);
            }
            if label.is_empty() {
                let l_len = u16::from_be_bytes([old_buf[81], old_buf[82]]) as usize;
                let safe_l = l_len
                    .min(MAX_HFS_LABEL_LEN)
                    .min(old_n.saturating_sub(FIXED_HFS_REC_HDR));
                prev_label_buf[..safe_l]
                    .copy_from_slice(&old_buf[FIXED_HFS_REC_HDR..FIXED_HFS_REC_HDR + safe_l]);
                prev_label_len = safe_l;
            }
        }
        i
    } else {
        let ck = hfs_count_key(ns_id);
        let cnt = storage::get_u64(ck.as_slice());
        if cnt >= MAX_TOTAL_HFS_ENTRIES {
            return Err(-30);
        }
        storage::set_u64(ck.as_slice(), cnt + 1);
        storage::set_u64(ik_lookup.as_slice(), cnt + 1);
        cnt
    };

    let eff_label: &[u8] = if !label.is_empty() {
        label
    } else {
        &prev_label_buf[..prev_label_len]
    };

    let mut rec_buf = [0u8; MAX_HFS_REC_BYTES];
    let rec_len = pack_hfs_record(
        status,
        hfs_addr,
        &eff_type,
        now,
        actor,
        eff_label,
        &mut rec_buf,
    );
    let itm_k = hfs_item_key(ns_id, idx);
    storage::set(itm_k.as_slice(), &rec_buf[..rec_len]);

    let sk = hfs_status_key(ns_id, hfs_addr);
    storage::set_u64(sk.as_slice(), status as u64);

    Ok((idx, eff_type))
}

fn promote_pending_hfs_if_any(target: &[u8; 20]) {
    if get_hfs_status_ns(None, target) == HFS_STATUS_PENDING && has_deployed_wasm(target) {
        let caller = context::msg_sender();
        if let Ok((_, eff_type)) =
            upsert_hfs_record_ns(None, target, &[0u8; 32], HFS_STATUS_WHITELISTED, &caller, &[])
        {
            events::emit(
                &[HFS_ASSOC_UPDATED, addr_topic(target), eff_type],
                &(HFS_STATUS_WHITELISTED as u64).to_be_bytes(),
            );
        }
    }
}

/// Outbound execution firewall + automatic `PENDING -> WHITELISTED` promotion when an authorized
/// Identity owner/delegate actively invokes a subroutine.
fn guard_and_promote_outbound_hfs(target: &[u8; 20]) -> Result<(), i32> {
    let st = get_hfs_status_ns(None, target);
    if st == HFS_STATUS_SPAM {
        return Err(-29); // Blocked by Identity's on-chain Spam HFS firewall!
    }
    promote_pending_hfs_if_any(target);
    Ok(())
}

fn dev_status_key(actor: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"id:dev:st:").push(actor)
}

fn dev_idx_key(actor: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"id:dev:ix:").push(actor)
}

fn dev_item_key(idx: usize) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"id:dev:it:")
        .push_u64_be(idx as u64)
}

fn is_owner_eoa(actor: &[u8; 20]) -> bool {
    if storage::get_u64(KEY_INIT) != 1 || *actor == [0u8; 20] {
        return false;
    }
    let st_k = dev_status_key(actor);
    let dev_st = storage::get_u64(st_k.as_slice()) as u8;
    if dev_st == DEV_STATUS_ACTIVE {
        return true;
    }
    if dev_st == DEV_STATUS_REVOKED {
        return false;
    }
    storage::get_address(KEY_OWNER) == Some(*actor)
}

fn check_owner(actor: &[u8; 20]) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    if is_owner_eoa(actor) {
        Ok(())
    } else {
        Err(-21)
    }
}

fn is_actor_authorized(actor: &[u8; 20]) -> bool {
    if storage::get_u64(KEY_INIT) != 1 {
        return false;
    }
    if is_owner_eoa(actor) {
        return true;
    }
    let dk = delegate_key(actor);
    storage::get_u64(dk.as_slice()) == 1
}

fn require_authorized() -> Result<(), i32> {
    let caller = context::msg_sender();
    if is_actor_authorized(&caller) {
        Ok(())
    } else {
        Err(-21)
    }
}

fn stamp_auth_approval(auth_obj: &[u8; 20]) {
    let now = context::block_number();
    let sk = auth_stamp_key(auth_obj);
    storage::set_u64(sk.as_slice(), now.saturating_add(1));
    events::emit(&[AUTH_SIGNED, addr_topic(auth_obj)], &now.to_be_bytes());
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-22); // already initialized
    }
    let owner = args.address(0).ok_or(-3)?;
    let handle_str = args.dynamic_bytes(1).ok_or(-3)?;
    if owner == [0u8; 20] || handle_str.is_empty() || handle_str.len() > 64 {
        return Err(-23);
    }

    storage::set_address(KEY_OWNER, &owner);
    storage::set(KEY_HANDLE, handle_str);
    storage::set(KEY_NICKNAME, handle_str);
    storage::set_u64(KEY_INIT, 1);
    let _ = upsert_owner_device_internal(&owner, &[0u8; 64], b"Primary Device", &[]);

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    Ok(())
}

fn handle_initialize_with_nickname(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-22); // already initialized
    }
    let owner = args.address(0).ok_or(-3)?;
    let handle_str = args.dynamic_bytes(1).ok_or(-3)?;
    let nick_str = args.dynamic_bytes(2).ok_or(-3)?;
    if owner == [0u8; 20]
        || handle_str.is_empty()
        || handle_str.len() > 64
        || nick_str.is_empty()
        || nick_str.len() > 32
    {
        return Err(-23);
    }

    storage::set_address(KEY_OWNER, &owner);
    storage::set(KEY_HANDLE, handle_str);
    storage::set(KEY_NICKNAME, nick_str);
    storage::set_u64(KEY_INIT, 1);
    let _ = upsert_owner_device_internal(&owner, &[0u8; 64], b"Primary Device", &[]);

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    events::emit(&[NICKNAME_UPDATED, addr_topic(&owner)], nick_str);
    Ok(())
}

fn validate_ed25519_prime_point(pt: &[u8; 32]) -> Result<(), i32> {
    if *pt == [0u8; 32] || *pt == IDENTITY_POINT_BYTES {
        return Err(-23);
    }
    let zero_sc = [0u8; 32];
    match ec_elgamal_lincomb(&SCALAR_ONE_BYTES, pt, &zero_sc, &IDENTITY_POINT_BYTES) {
        Some(chk) if chk == *pt => Ok(()),
        _ => Err(-23),
    }
}

fn store_validated_encryption_keys(
    owner: &[u8; 20],
    secp_pub64: &[u8],
    ed_pub32: &[u8; 32],
) -> Result<(), i32> {
    if secp_pub64.len() != 64 || secp_pub64.iter().all(|&b| b == 0) {
        return Err(-23);
    }
    validate_ed25519_prime_point(ed_pub32)?;
    storage::set(KEY_SECP_PUB64, secp_pub64);
    storage::set(KEY_ED_PUB32, ed_pub32);
    events::emit(
        &[ENCRYPTION_KEYS_UPDATED, addr_topic(owner), *ed_pub32],
        secp_pub64,
    );
    Ok(())
}

fn handle_initialize_with_keys(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(-21);
    }
    let owner = args.address(0).ok_or(-3)?;
    let handle_str = args.dynamic_bytes(1).ok_or(-3)?;
    let nick_str = args.dynamic_bytes(2).ok_or(-3)?;
    let secp_pub64 = args.dynamic_bytes(3).ok_or(-3)?;
    let ed_pub32 = args.bytes32(4).ok_or(-3)?;
    if owner == [0u8; 20]
        || handle_str.is_empty()
        || handle_str.len() > 64
        || nick_str.is_empty()
        || nick_str.len() > 32
    {
        return Err(-23);
    }
    store_validated_encryption_keys(&owner, secp_pub64, &ed_pub32)?;

    storage::set_address(KEY_OWNER, &owner);
    storage::set(KEY_HANDLE, handle_str);
    storage::set(KEY_NICKNAME, nick_str);
    storage::set_u64(KEY_INIT, 1);
    let _ = upsert_owner_device_internal(&owner, secp_pub64, b"Primary Device", &[]);

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    events::emit(&[NICKNAME_UPDATED, addr_topic(&owner)], nick_str);
    Ok(())
}

fn handle_initialize_with_keys_and_seed(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(-21);
    }
    let owner = args.address(0).ok_or(-3)?;
    let handle_str = args.dynamic_bytes(1).ok_or(-3)?;
    let nick_str = args.dynamic_bytes(2).ok_or(-3)?;
    let id_secp_pub64 = args.dynamic_bytes(3).ok_or(-3)?;
    let id_ed_pub32 = args.bytes32(4).ok_or(-3)?;
    let dev_secp_pub64 = args.dynamic_bytes(5).ok_or(-3)?;
    let wrapped_seed = args.dynamic_bytes(6).ok_or(-3)?;
    if owner == [0u8; 20]
        || handle_str.is_empty()
        || handle_str.len() > 64
        || nick_str.is_empty()
        || nick_str.len() > 32
        || (!dev_secp_pub64.is_empty() && dev_secp_pub64.len() != 64)
        || wrapped_seed.len() > MAX_WRAPPED_SEED_LEN
    {
        return Err(-23);
    }
    store_validated_encryption_keys(&owner, id_secp_pub64, &id_ed_pub32)?;

    storage::set_address(KEY_OWNER, &owner);
    storage::set(KEY_HANDLE, handle_str);
    storage::set(KEY_NICKNAME, nick_str);
    storage::set_u64(KEY_INIT, 1);
    let eff_dev_pk = if dev_secp_pub64.len() == 64 {
        dev_secp_pub64
    } else {
        id_secp_pub64
    };
    upsert_owner_device_internal(&owner, eff_dev_pk, b"Primary Device", wrapped_seed)?;

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    events::emit(&[NICKNAME_UPDATED, addr_topic(&owner)], nick_str);
    Ok(())
}

fn handle_set_encryption_keys(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    let secp_pub64 = args.dynamic_bytes(0).ok_or(-3)?;
    let ed_pub32 = args.bytes32(1).ok_or(-3)?;
    let owner = storage::get_address(KEY_OWNER).unwrap_or([0u8; 20]);
    store_validated_encryption_keys(&owner, secp_pub64, &ed_pub32)?;
    ret::write_bool(true);
    Ok(())
}

fn handle_set_nickname(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let nick_str = args.dynamic_bytes(0).ok_or(-3)?;
    if nick_str.is_empty() || nick_str.len() > 32 {
        return Err(-23);
    }
    storage::set(KEY_NICKNAME, nick_str);
    let owner = storage::get_address(KEY_OWNER).unwrap_or([0u8; 20]);
    events::emit(&[NICKNAME_UPDATED, addr_topic(&owner)], nick_str);
    ret::write_bool(true);
    Ok(())
}

fn handle_set_delegate(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let delegate = args.address(0).ok_or(-3)?;
    let allowed = args.bool(1).ok_or(-3)?;
    if delegate == [0u8; 20] {
        return Err(-23);
    }

    let dk = delegate_key(&delegate);
    storage::set_u64(dk.as_slice(), if allowed { 1 } else { 0 });
    events::emit(
        &[DELEGATE_UPDATED, addr_topic(&delegate)],
        &[u8::from(allowed)],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_transfer_ownership(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let new_owner = args.address(0).ok_or(-3)?;
    if new_owner == [0u8; 20] {
        return Err(-23);
    }
    revoke_all_owner_devices_internal();
    storage::set_address(KEY_OWNER, &new_owner);
    let _ = upsert_owner_device_internal(&new_owner, &[0u8; 64], b"Primary Device", &[]);
    // Clear previous owner's encryption keys unless explicitly rotated via `transferOwnershipWithKeys`.
    storage::set(KEY_SECP_PUB64, &[0u8; 64]);
    storage::set(KEY_ED_PUB32, &[0u8; 32]);
    ret::write_bool(true);
    Ok(())
}

fn handle_transfer_ownership_with_keys(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let new_owner = args.address(0).ok_or(-3)?;
    let secp_pub64 = args.dynamic_bytes(1).ok_or(-3)?;
    let ed_pub32 = args.bytes32(2).ok_or(-3)?;
    if new_owner == [0u8; 20] {
        return Err(-23);
    }
    store_validated_encryption_keys(&new_owner, secp_pub64, &ed_pub32)?;
    revoke_all_owner_devices_internal();
    storage::set_address(KEY_OWNER, &new_owner);
    let _ = upsert_owner_device_internal(&new_owner, secp_pub64, b"Primary Device", &[]);
    ret::write_bool(true);
    Ok(())
}

/// Universal Identity call gateway (`msg.sender` inside `target` becomes `self_address()`).
fn handle_execute(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let target = args.address(0).ok_or(-3)?;
    let sub_cd = args.dynamic_bytes(1).ok_or(-3)?;
    if sub_cd.len() < 4 {
        return Err(-25);
    }
    guard_and_promote_outbound_hfs(&target)?;

    let sel = [sub_cd[0], sub_cd[1], sub_cd[2], sub_cd[3]];
    if sel == const { selector("approve()") }
        || sel == const { selector("approveAndFinalize()") }
        || sel == const { selector("placeBuyOrder(uint64,uint64)") }
        || sel == const { selector("placeSellOrder(uint64,uint64)") }
    {
        stamp_auth_approval(&target);
    }

    let out = call::call_raw(&target, sub_cd)?;
    ret::write(out);
    // If `target` called `notifyHfsAssociation` during `call_raw`, auto-promote `PENDING -> WHITELISTED`!
    promote_pending_hfs_if_any(&target);
    events::emit(&[EXECUTED_CALL, addr_topic(&target)], &sel);
    Ok(())
}

fn handle_init_constitution_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let constitution = args.address(2).ok_or(-3)?;
    let target_hps = args.address(3).ok_or(-3)?;
    let policy_id = args.bytes32(4).ok_or(-3)?;
    let action_hash = args.bytes32(5).ok_or(-3)?;
    guard_and_promote_outbound_hfs(&constitution)?;
    guard_and_promote_outbound_hfs(&target_hps)?;

    let sub_cd = CallEncoder::<192>::new(const { selector("initializeFromConstitution(address,address,address,bytes32,bytes32)") })
    .push_address(&registry)
    .push_address(&constitution)
    .push_address(&target_hps)
    .push_bytes32(&policy_id)
    .push_bytes32(&action_hash);

    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_init_oracle_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let oracle_id = args.address(2).ok_or(-3)?;
    let target_hps = args.address(3).ok_or(-3)?;
    let action_hash = args.bytes32(4).ok_or(-3)?;
    let expiry_blocks = args.u64(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<192>::new(const { selector("initializeOracle(address,address,address,bytes32,uint64)") })
    .push_address(&registry)
    .push_address(&oracle_id)
    .push_address(&target_hps)
    .push_bytes32(&action_hash)
    .push_u64(expiry_blocks);

    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_approve_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<16>::new(const { selector("approve()") });
    let stages_done = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    ret::write_bool(stages_done);
    Ok(())
}

fn handle_approve_and_finalize_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<16>::new(const { selector("approveAndFinalize()") });
    let finalized = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    ret::write_bool(finalized);
    Ok(())
}

fn handle_finalize_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let sub_cd = CallEncoder::<16>::new(const { selector("finalize()") });
    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_init_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let constitution = args.address(2).ok_or(-3)?;
    let target_ledger = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("initializeTransferAuction(address,address,address)") })
    .push_address(&registry)
    .push_address(&constitution)
    .push_address(&target_ledger);

    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_place_buy_order(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<96>::new(const { selector("placeBuyOrder(uint64,uint64)") })
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, sub_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_place_sell_order(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<96>::new(const { selector("placeSellOrder(uint64,uint64)") })
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, sub_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_settle_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let sub_cd = CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") })
        .push_address(&auth_obj);
    let out = call::call_raw(&ledger, sub_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_cancel_buy_order(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let order_index = args.u64(1).ok_or(-3)?;

    let sub_cd =
        CallEncoder::<64>::new(const { selector("cancelBuyOrder(uint64)") }).push_u64(order_index);
    let out = call::call_raw(&auth_obj, sub_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_place_buy_order_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    let price = args.u64(2).ok_or(-3)?;
    let quantity = args.u64(3).ok_or(-3)?;

    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<128>::new(const { selector("placeBuyOrder(address,uint64,uint64)") })
        .push_address(&auth_obj)
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&share_capital, sub_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_cancel_buy_order_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    let order_index = args.u64(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("cancelBuyOrder(address,uint64)") })
        .push_address(&auth_obj)
        .push_u64(order_index);
    let refunded = call::call_u64(&share_capital, sub_cd.as_slice())?;
    ret::write_u64_word(refunded);
    Ok(())
}

fn handle_place_sell_order_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;
    let price = args.u64(2).ok_or(-3)?;
    let quantity = args.u64(3).ok_or(-3)?;

    stamp_auth_approval(&auth_obj);
    let sub_cd = CallEncoder::<128>::new(const { selector("placeSellOrder(address,uint64,uint64)") })
        .push_address(&auth_obj)
        .push_u64(price)
        .push_u64(quantity);
    let order_idx = call::call_u64(&share_capital, sub_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_settle_auction_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let share_ledger = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const {
        selector("settleShareTransferAuction(address,address)")
    })
    .push_address(&share_ledger)
    .push_address(&auth_obj);
    let out = call::call_raw(&share_capital, sub_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_init_share_issuance(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let registry = args.address(1).ok_or(-3)?;
    let charter = args.address(2).ok_or(-3)?;
    let share_ledger = args.address(3).ok_or(-3)?;
    let max_new_shares = args.u64(4).ok_or(-3)?;
    let min_issue_price = args.u64(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<192>::new(const {
        selector("initializeShareIssuance(address,address,address,uint64,uint64)")
    })
    .push_address(&registry)
    .push_address(&charter)
    .push_address(&share_ledger)
    .push_u64(max_new_shares)
    .push_u64(min_issue_price);
    let ok = call::call_bool(&auth_obj, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_settle_issuance_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let share_ledger = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd =
        CallEncoder::<96>::new(const { selector("settleShareIssuance(address,address)") })
            .push_address(&share_ledger)
            .push_address(&auth_obj);
    let out = call::call_raw(&share_capital, sub_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_refund_failed_auction_via_sc(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let sub_cd =
        CallEncoder::<64>::new(const { selector("refundFailedAuction(address)") })
            .push_address(&auth_obj);
    let refunded = call::call_u64(&share_capital, sub_cd.as_slice())?;
    ret::write_u64_word(refunded);
    Ok(())
}

fn handle_transfer_bank_balance(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let to_payee = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("transferDirect(address,uint64)") })
        .push_address(&to_payee)
        .push_u64(amount);
    let ok = call::call_bool(&bank_ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_set_share_escrow_account(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let share_capital = args.address(0).ok_or(-3)?;
    let bank_ledger = args.address(1).ok_or(-3)?;
    let escrow_account = args.address(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const {
        selector("setShareEscrowAccount(address,address,address)")
    })
    .push_address(&bank_ledger)
    .push_address(&escrow_account)
    .push_address(&auth_obj);
    let ok = call::call_bool(&share_capital, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_set_operating_account(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let bank_ledger = args.address(1).ok_or(-3)?;
    let rev_account = args.address(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const {
        selector("setOperatingAccount(address,address,address)")
    })
    .push_address(&bank_ledger)
    .push_address(&rev_account)
    .push_address(&auth_obj);
    let ok = call::call_bool(&product_ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_register_share_class(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let share_ledger = args.address(1).ok_or(-3)?;
    let votes_per_share = args.u64(2).ok_or(-3)?;
    let conversion_numer = args.u64(3).ok_or(-3)?;
    let conversion_denom = args.u64(4).ok_or(-3)?;
    let super_auth = args.address(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<192>::new(const {
        const { selector("registerShareClass(address,uint64,uint64,uint64,address)") }
    })
    .push_address(&share_ledger)
    .push_u64(votes_per_share)
    .push_u64(conversion_numer)
    .push_u64(conversion_denom)
    .push_address(&super_auth);
    let count = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(count);
    Ok(())
}

fn handle_authorize_futures_underwriting(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let futures_ledger = args.address(1).ok_or(-3)?;
    let underwrite_pct = args.u64(2).ok_or(-3)?;
    let super_auth = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const {
        selector("authorizeFuturesUnderwriting(address,uint64,address)")
    })
    .push_address(&futures_ledger)
    .push_u64(underwrite_pct)
    .push_address(&super_auth);
    let cap = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(cap);
    Ok(())
}

fn handle_underwrite_futures(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;

    let sub_cd = CallEncoder::<64>::new(const { selector("underwriteFutures(uint64)") })
        .push_u64(amount);
    let total_underwritten = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(total_underwritten);
    Ok(())
}

fn handle_close_underwritten_futures(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let amount = args.u64(1).ok_or(-3)?;

    let sub_cd = CallEncoder::<64>::new(const { selector("closeUnderwrittenFutures(uint64)") })
        .push_u64(amount);
    let rem_underwritten = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(rem_underwritten);
    Ok(())
}

fn handle_set_attached_dex(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let dex_hps = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("setAttachedDex(address,address)") })
        .push_address(&dex_hps)
        .push_address(&auth_obj);
    let ok = call::call_bool(&ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_dex_place_bid(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let dex_hps = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
        .push_u64(price)
        .push_u64(quantity);
    let order_id = call::call_u64(&dex_hps, sub_cd.as_slice())?;
    ret::write_u64_word(order_id);
    Ok(())
}

fn handle_dex_place_ask(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let dex_hps = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
        .push_u64(price)
        .push_u64(quantity);
    let order_id = call::call_u64(&dex_hps, sub_cd.as_slice())?;
    ret::write_u64_word(order_id);
    Ok(())
}

fn handle_dex_cancel_order(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let dex_hps = args.address(0).ok_or(-3)?;
    let order_id = args.u64(1).ok_or(-3)?;

    let sub_cd = CallEncoder::<64>::new(const { selector("cancelOrder(uint64)") }).push_u64(order_id);
    let refunded = call::call_u64(&dex_hps, sub_cd.as_slice())?;
    ret::write_u64_word(refunded);
    Ok(())
}

fn handle_dex_match_block(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let dex_hps = args.address(0).ok_or(-3)?;

    let sub_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
    let out = call::call_raw(&dex_hps, sub_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let units_available = args.u64(2).ok_or(-3)?;
    let latest_price = args.u64(3).ok_or(-3)?;
    let name = args.dynamic_bytes(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    let sub_cd = CallEncoder::<256>::new(const {
        selector("upsertProduct(bytes32,uint64,uint64,bytes,address)")
    })
    .push_bytes32(&product_id)
    .push_u64(units_available)
    .push_u64(latest_price)
    .push_u64(160)
    .push_address(&auth_obj)
    .push_dynamic_bytes_tail(name);
    let ok = call::call_bool(&product_ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_restock_product(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let additional_units = args.u64(2).ok_or(-3)?;
    let new_price = args.u64(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let sub_cd = CallEncoder::<160>::new(const {
        const { selector("restockProduct(bytes32,uint64,uint64,address)") }
    })
    .push_bytes32(&product_id)
    .push_u64(additional_units)
    .push_u64(new_price)
    .push_address(&auth_obj);
    let new_units = call::call_u64(&product_ledger, sub_cd.as_slice())?;
    ret::write_u64_word(new_units);
    Ok(())
}

fn handle_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const {
        const { selector("setProductPrice(bytes32,uint64,address)") }
    })
    .push_bytes32(&product_id)
    .push_u64(new_price)
    .push_address(&auth_obj);
    let ok = call::call_bool(&product_ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_buy_product(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let product_id = args.bytes32(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
        .push_bytes32(&product_id)
        .push_u64(quantity);
    let sale_idx = call::call_u64(&product_ledger, sub_cd.as_slice())?;
    ret::write_u64_word(sale_idx);
    Ok(())
}

fn handle_issue_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let to_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("issue(address,uint64,address)") })
        .push_address(&to_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let new_bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(new_bal);
    Ok(())
}

fn handle_cancel_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let from_identity = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("cancel(address,uint64,address)") })
        .push_address(&from_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let new_bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(new_bal);
    Ok(())
}

fn handle_transfer_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let from_identity = args.address(1).ok_or(-3)?;
    let to_identity = args.address(2).ok_or(-3)?;
    let amount = args.u64(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let sub_cd = CallEncoder::<160>::new(const { selector("transfer(address,address,uint64,address)") })
        .push_address(&from_identity)
        .push_address(&to_identity)
        .push_u64(amount)
        .push_address(&auth_obj);
    let ok = call::call_bool(&ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_add_director(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let new_director = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("addDirector(address,address)") })
        .push_address(&new_director)
        .push_address(&auth_obj);
    let new_count = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(new_count);
    Ok(())
}

fn handle_remove_director(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let director = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("removeDirector(address,address)") })
        .push_address(&director)
        .push_address(&auth_obj);
    let new_count = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(new_count);
    Ok(())
}

fn handle_grant_role(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let role_id = args.bytes32(1).ok_or(-3)?;
    let account = args.address(2).ok_or(-3)?;
    let board_auth = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("grantRole(bytes32,address,address)") })
        .push_bytes32(&role_id)
        .push_address(&account)
        .push_address(&board_auth);
    let new_count = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(new_count);
    Ok(())
}

fn handle_revoke_role(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let role_id = args.bytes32(1).ok_or(-3)?;
    let account = args.address(2).ok_or(-3)?;
    let board_auth = args.address(3).ok_or(-3)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("revokeRole(bytes32,address,address)") })
        .push_bytes32(&role_id)
        .push_address(&account)
        .push_address(&board_auth);
    let new_count = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(new_count);
    Ok(())
}

fn handle_define_role(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let constitution = args.address(0).ok_or(-3)?;
    let role_id = args.bytes32(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let sub_cd = CallEncoder::<96>::new(const { selector("defineRole(bytes32,address)") })
        .push_bytes32(&role_id)
        .push_address(&auth_obj);
    let total_roles = call::call_u64(&constitution, sub_cd.as_slice())?;
    ret::write_u64_word(total_roles);
    Ok(())
}

fn handle_set_function_auth(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let charter = args.address(0).ok_or(-3)?;
    let target_hps = args.address(1).ok_or(-3)?;
    let fn_selector = args.bytes4(2).ok_or(-3)?;
    let policy_id = args.bytes32(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let sub_cd = CallEncoder::<160>::new(const {
        selector("setFunctionAuth(address,bytes4,bytes32,address)")
    })
    .push_address(&target_hps)
    .push_bytes4(&fn_selector)
    .push_bytes32(&policy_id)
    .push_address(&auth_obj);
    let ok = call::call_bool(&charter, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_authorize_module(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let charter = args.address(0).ok_or(-3)?;
    let module_hps = args.address(1).ok_or(-3)?;
    let capability = args.bytes32(2).ok_or(-3)?;
    let active = args.bool(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let sub_cd = CallEncoder::<160>::new(const {
        selector("authorizeModule(address,bytes32,bool,address)")
    })
    .push_address(&module_hps)
    .push_bytes32(&capability)
    .push_bool(active)
    .push_address(&auth_obj);
    let ok = call::call_bool(&charter, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_activate_charter(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let charter = args.address(0).ok_or(-3)?;
    let shareholder_auth = args.address(1).ok_or(-3)?;
    guard_and_promote_outbound_hfs(&charter)?;

    let sub_cd = CallEncoder::<64>::new(const { selector("activateCharter(address)") })
        .push_address(&shareholder_auth);
    let ok = call::call_bool(&charter, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_approve_asset(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let ledger = args.address(0).ok_or(-3)?;
    let spender = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;
    guard_and_promote_outbound_hfs(&ledger)?;

    let sub_cd = CallEncoder::<128>::new(const { selector("approve(address,uint64,address)") })
        .push_address(&spender)
        .push_u64(amount)
        .push_address(&auth_obj);
    let ok = call::call_bool(&ledger, sub_cd.as_slice())?;
    if !ok {
        return Err(-24);
    }
    ret::write_bool(true);
    Ok(())
}

fn handle_identity_version(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(IDENTITY_ABI_VERSION);
    Ok(())
}

fn handle_set_hfs_association(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let caller = context::msg_sender();
    let hfs_addr = args.address(0).ok_or(-3)?;
    let type_id = args.bytes32(1).ok_or(-3)?;
    let status_u64 = args.u64(2).ok_or(-3)?;
    let label = args.dynamic_bytes(3).ok_or(-3)?;
    if status_u64 > u8::MAX as u64 {
        return Err(-26);
    }
    let status = status_u64 as u8;
    let (_, eff_type) = upsert_hfs_record_ns(None, &hfs_addr, &type_id, status, &caller, label)?;
    events::emit(
        &[HFS_ASSOC_UPDATED, addr_topic(&hfs_addr), eff_type],
        &(status as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn apply_batch_ns(
    ns_id: Option<&[u8; 20]>,
    packed: &[u8],
    actor: &[u8; 20],
) -> Result<u64, i32> {
    if packed.len() < 2 {
        return Err(-3);
    }
    let count = u16::from_be_bytes([packed[0], packed[1]]) as usize;
    if count > MAX_BATCH_ENTRIES {
        return Err(-30);
    }
    let mut pos = 2usize;
    let mut updated = 0u64;
    let mut i = 0usize;
    while i < count {
        if pos + 54 > packed.len() {
            return Err(-3);
        }
        let mut hfs_addr = [0u8; 20];
        hfs_addr.copy_from_slice(&packed[pos..pos + 20]);
        let mut type_id = [0u8; 32];
        type_id.copy_from_slice(&packed[pos + 20..pos + 52]);
        let status = packed[pos + 52];
        let l_len = packed[pos + 53] as usize;
        pos += 54;
        if pos + l_len > packed.len() {
            return Err(-3);
        }
        let label = &packed[pos..pos + l_len];
        pos += l_len;

        let (_, eff_type) = upsert_hfs_record_ns(ns_id, &hfs_addr, &type_id, status, actor, label)?;
        match ns_id {
            Some(sub) => {
                events::emit(
                    &[
                        DELEGATED_HFS_ASSOC_UPDATED,
                        addr_topic(sub),
                        addr_topic(&hfs_addr),
                        eff_type,
                    ],
                    &(status as u64).to_be_bytes(),
                );
            }
            None => {
                events::emit(
                    &[HFS_ASSOC_UPDATED, addr_topic(&hfs_addr), eff_type],
                    &(status as u64).to_be_bytes(),
                );
            }
        }
        updated += 1;
        i += 1;
    }
    Ok(updated)
}

fn handle_set_hfs_association_batch(args: &CalldataReader) -> Result<(), i32> {
    require_authorized()?;
    let caller = context::msg_sender();
    let packed = args.dynamic_bytes(0).ok_or(-3)?;
    let updated = apply_batch_ns(None, packed, &caller)?;
    ret::write_u64_word(updated);
    Ok(())
}

fn handle_notify_hfs_association(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let caller = context::msg_sender();
    let hfs_addr = args.address(0).ok_or(-3)?;
    let type_id = args.bytes32(1).ok_or(-3)?;
    let label = args.dynamic_bytes(2).ok_or(-3)?;

    if !has_deployed_wasm(&hfs_addr) {
        return Err(-28);
    }

    if is_actor_authorized(&caller) {
        let (_, eff_type) = upsert_hfs_record_ns(
            None,
            &hfs_addr,
            &type_id,
            HFS_STATUS_WHITELISTED,
            &caller,
            label,
        )?;
        events::emit(
            &[HFS_ASSOC_UPDATED, addr_topic(&hfs_addr), eff_type],
            &(HFS_STATUS_WHITELISTED as u64).to_be_bytes(),
        );
        ret::write_u64_word(HFS_STATUS_WHITELISTED as u64);
        return Ok(());
    }

    let cur = get_hfs_status_ns(None, &hfs_addr);
    if cur != HFS_STATUS_UNLISTED {
        // Never allow an external caller to overwrite owner's existing state!
        ret::write_u64_word(cur as u64);
        return Ok(());
    }

    let (_, eff_type) =
        upsert_hfs_record_ns(None, &hfs_addr, &type_id, HFS_STATUS_PENDING, &caller, label)?;
    events::emit(
        &[HFS_ASSOC_NOTIFIED, addr_topic(&hfs_addr), eff_type],
        &caller,
    );
    ret::write_u64_word(HFS_STATUS_PENDING as u64);
    Ok(())
}

fn handle_get_hfs_association_status(args: &CalldataReader) -> Result<(), i32> {
    let hfs_addr = args.address(0).ok_or(-3)?;
    ret::write_u64_word(get_hfs_status_ns(None, &hfs_addr) as u64);
    Ok(())
}

fn handle_is_hfs_whitelisted(args: &CalldataReader) -> Result<(), i32> {
    let hfs_addr = args.address(0).ok_or(-3)?;
    ret::write_bool(get_hfs_status_ns(None, &hfs_addr) == HFS_STATUS_WHITELISTED);
    Ok(())
}

fn handle_get_hfs_association_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_HFS_COUNT));
    Ok(())
}

fn write_hfs_slice_ns(ns_id: Option<&[u8; 20]>, offset: u64, limit: u64) {
    let safe_limit = limit.min(MAX_HFS_SLICE_LIMIT);
    let ck = hfs_count_key(ns_id);
    let total = storage::get_u64(ck.as_slice());

    let mut out = [0u8; HFS_SLICE_OUT_CAP];
    out[0..8].copy_from_slice(&total.to_be_bytes());

    let mut pos = 16usize;
    let mut returned = 0u64;
    let mut i = offset;
    let end = offset.saturating_add(safe_limit).min(total);
    let mut item_buf = [0u8; MAX_HFS_REC_BYTES];

    while i < end {
        let ik = hfs_item_key(ns_id, i);
        let n = storage::get_into(ik.as_slice(), &mut item_buf).unwrap_or(0);
        if n >= FIXED_HFS_REC_HDR && pos + 8 + n <= HFS_SLICE_OUT_CAP {
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
}

fn handle_get_hfs_associations_slice(args: &CalldataReader) -> Result<(), i32> {
    let offset = args.u64(0).ok_or(-3)?;
    let limit = args.u64(1).ok_or(-3)?;
    write_hfs_slice_ns(None, offset, limit);
    Ok(())
}

// --- Delegated v1 Identity Extension Mode (`msg_sender()` = legacy v1 Identity HFS via `execute`) ---

fn require_caller_identity_hps() -> Result<[u8; 20], i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let caller = context::msg_sender();
    if !has_deployed_wasm(&caller) {
        return Err(-21);
    }
    Ok(caller)
}

fn handle_set_delegated_hfs_association(args: &CalldataReader) -> Result<(), i32> {
    let subject_id = require_caller_identity_hps()?;
    let hfs_addr = args.address(0).ok_or(-3)?;
    let type_id = args.bytes32(1).ok_or(-3)?;
    let status_u64 = args.u64(2).ok_or(-3)?;
    let label = args.dynamic_bytes(3).ok_or(-3)?;
    if status_u64 > u8::MAX as u64 {
        return Err(-26);
    }
    let status = status_u64 as u8;
    let (_, eff_type) =
        upsert_hfs_record_ns(Some(&subject_id), &hfs_addr, &type_id, status, &subject_id, label)?;
    events::emit(
        &[
            DELEGATED_HFS_ASSOC_UPDATED,
            addr_topic(&subject_id),
            addr_topic(&hfs_addr),
            eff_type,
        ],
        &(status as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_set_delegated_hfs_association_batch(args: &CalldataReader) -> Result<(), i32> {
    let subject_id = require_caller_identity_hps()?;
    let packed = args.dynamic_bytes(0).ok_or(-3)?;
    let updated = apply_batch_ns(Some(&subject_id), packed, &subject_id)?;
    ret::write_u64_word(updated);
    Ok(())
}

fn handle_notify_delegated_hfs_association(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let caller = context::msg_sender();
    let subject_id = args.address(0).ok_or(-3)?;
    let hfs_addr = args.address(1).ok_or(-3)?;
    let type_id = args.bytes32(2).ok_or(-3)?;
    let label = args.dynamic_bytes(3).ok_or(-3)?;

    if !has_deployed_wasm(&subject_id) || !has_deployed_wasm(&hfs_addr) {
        return Err(-28);
    }

    if caller == subject_id {
        let (_, eff_type) = upsert_hfs_record_ns(
            Some(&subject_id),
            &hfs_addr,
            &type_id,
            HFS_STATUS_WHITELISTED,
            &caller,
            label,
        )?;
        events::emit(
            &[
                DELEGATED_HFS_ASSOC_UPDATED,
                addr_topic(&subject_id),
                addr_topic(&hfs_addr),
                eff_type,
            ],
            &(HFS_STATUS_WHITELISTED as u64).to_be_bytes(),
        );
        ret::write_u64_word(HFS_STATUS_WHITELISTED as u64);
        return Ok(());
    }

    let cur = get_hfs_status_ns(Some(&subject_id), &hfs_addr);
    if cur != HFS_STATUS_UNLISTED {
        ret::write_u64_word(cur as u64);
        return Ok(());
    }

    let (_, eff_type) = upsert_hfs_record_ns(
        Some(&subject_id),
        &hfs_addr,
        &type_id,
        HFS_STATUS_PENDING,
        &caller,
        label,
    )?;
    events::emit(
        &[HFS_ASSOC_NOTIFIED, addr_topic(&hfs_addr), eff_type],
        &caller,
    );
    ret::write_u64_word(HFS_STATUS_PENDING as u64);
    Ok(())
}

fn handle_get_delegated_hfs_association_status(args: &CalldataReader) -> Result<(), i32> {
    let subject_id = args.address(0).ok_or(-3)?;
    let hfs_addr = args.address(1).ok_or(-3)?;
    ret::write_u64_word(get_hfs_status_ns(Some(&subject_id), &hfs_addr) as u64);
    Ok(())
}

fn handle_get_delegated_hfs_associations_slice(args: &CalldataReader) -> Result<(), i32> {
    let subject_id = args.address(0).ok_or(-3)?;
    let offset = args.u64(1).ok_or(-3)?;
    let limit = args.u64(2).ok_or(-3)?;
    write_hfs_slice_ns(Some(&subject_id), offset, limit);
    Ok(())
}

fn handle_owner(_args: &CalldataReader) -> Result<(), i32> {
    let owner = storage::get_address(KEY_OWNER).unwrap_or([0u8; 20]);
    ret::write_address(&owner);
    Ok(())
}

fn handle_is_authorized(args: &CalldataReader) -> Result<(), i32> {
    let actor = args.address(0).ok_or(-3)?;
    ret::write_bool(is_actor_authorized(&actor));
    Ok(())
}

fn handle_has_approved_auth(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    let sk = auth_stamp_key(&auth_obj);
    ret::write_bool(storage::get_u64(sk.as_slice()) > 0);
    Ok(())
}

fn handle_handle(_args: &CalldataReader) -> Result<(), i32> {
    match storage::get_ref(KEY_HANDLE) {
        Some(h) => ret::write_abi_bytes(h),
        None => ret::write_abi_bytes(&[]),
    }
    Ok(())
}

fn handle_nickname(_args: &CalldataReader) -> Result<(), i32> {
    if let Some(n) = storage::get_ref(KEY_NICKNAME) {
        ret::write_abi_bytes(n);
    } else if let Some(h) = storage::get_ref(KEY_HANDLE) {
        ret::write_abi_bytes(h);
    } else {
        ret::write_abi_bytes(&[]);
    }
    Ok(())
}

fn handle_balance_in(args: &CalldataReader) -> Result<(), i32> {
    let ledger = args.address(0).ok_or(-3)?;
    let me = context::self_address();
    let sub_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(&me);
    let bal = call::call_u64(&ledger, sub_cd.as_slice())?;
    ret::write_u64_word(bal);
    Ok(())
}

fn handle_encryption_keys(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 96];
    let mut secp = [0u8; 64];
    if storage::get_into(KEY_SECP_PUB64, &mut secp) == Some(64) {
        out[0..64].copy_from_slice(&secp);
    }
    if let Some(ed) = storage::get_bytes32(KEY_ED_PUB32) {
        out[64..96].copy_from_slice(&ed);
    }
    ret::write(&out);
    Ok(())
}

fn handle_secp256k1_pubkey(_args: &CalldataReader) -> Result<(), i32> {
    let mut secp = [0u8; 64];
    let _ = storage::get_into(KEY_SECP_PUB64, &mut secp);
    ret::write(&secp);
    Ok(())
}

fn handle_ed25519_pubkey(_args: &CalldataReader) -> Result<(), i32> {
    let ed = storage::get_bytes32(KEY_ED_PUB32).unwrap_or([0u8; 32]);
    ret::write(&ed);
    Ok(())
}

// ============================================================================
// Multi-Device Owner Ring (`Identity` v4)
// ============================================================================
//
// Per-slot storage (`id:dev:it:<idx>`):
//   [status:1][eoa:20][added_blk:8 BE][secp_pub64:64][lbl_len:1][lbl:..32][wrap_len:2 BE][wrap:..192]
const FIXED_DEV_HDR: usize = 1 + 20 + 8 + 64 + 1; // 94B
const MAX_DEV_REC_LEN: usize = FIXED_DEV_HDR + MAX_DEV_LABEL_LEN + 2 + MAX_WRAPPED_SEED_LEN;

struct OwnerDeviceRec {
    status: u8,
    eoa: [u8; 20],
    added_block: u64,
    secp_pub64: [u8; 64],
    label_len: u8,
    label: [u8; MAX_DEV_LABEL_LEN],
    wrap_len: u16,
    wrapped_seed: [u8; MAX_WRAPPED_SEED_LEN],
}

impl OwnerDeviceRec {
    fn save(&self, idx: usize) {
        let ll = (self.label_len as usize).min(MAX_DEV_LABEL_LEN);
        let wl = (self.wrap_len as usize).min(MAX_WRAPPED_SEED_LEN);
        let mut buf = [0u8; MAX_DEV_REC_LEN];
        buf[0] = self.status;
        buf[1..21].copy_from_slice(&self.eoa);
        buf[21..29].copy_from_slice(&self.added_block.to_be_bytes());
        buf[29..93].copy_from_slice(&self.secp_pub64);
        buf[93] = ll as u8;
        buf[94..94 + ll].copy_from_slice(&self.label[..ll]);
        let w_off = 94 + ll;
        buf[w_off..w_off + 2].copy_from_slice(&(wl as u16).to_be_bytes());
        buf[w_off + 2..w_off + 2 + wl].copy_from_slice(&self.wrapped_seed[..wl]);
        let k = dev_item_key(idx);
        storage::set(k.as_slice(), &buf[..w_off + 2 + wl]);
        let sk = dev_status_key(&self.eoa);
        storage::set_u64(sk.as_slice(), self.status as u64);
        let ik = dev_idx_key(&self.eoa);
        storage::set_u64(ik.as_slice(), (idx + 1) as u64);
    }

    fn load(idx: usize) -> Option<Self> {
        let k = dev_item_key(idx);
        let mut buf = [0u8; MAX_DEV_REC_LEN];
        let n = storage::get_into(k.as_slice(), &mut buf)?;
        if n < FIXED_DEV_HDR + 2 {
            return None;
        }
        let status = buf[0];
        let mut eoa = [0u8; 20];
        eoa.copy_from_slice(&buf[1..21]);
        let added_block = u64::from_be_bytes([
            buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27], buf[28],
        ]);
        let mut secp_pub64 = [0u8; 64];
        secp_pub64.copy_from_slice(&buf[29..93]);
        let ll = (buf[93] as usize).min(MAX_DEV_LABEL_LEN);
        if n < 94 + ll + 2 {
            return None;
        }
        let mut label = [0u8; MAX_DEV_LABEL_LEN];
        label[..ll].copy_from_slice(&buf[94..94 + ll]);
        let w_off = 94 + ll;
        let wl = (u16::from_be_bytes([buf[w_off], buf[w_off + 1]]) as usize)
            .min(MAX_WRAPPED_SEED_LEN)
            .min(n.saturating_sub(w_off + 2));
        let mut wrapped_seed = [0u8; MAX_WRAPPED_SEED_LEN];
        wrapped_seed[..wl].copy_from_slice(&buf[w_off + 2..w_off + 2 + wl]);
        Some(Self {
            status,
            eoa,
            added_block,
            secp_pub64,
            label_len: ll as u8,
            label,
            wrap_len: wl as u16,
            wrapped_seed,
        })
    }
}

fn ensure_primary_owner_in_ring() {
    if storage::get_u64(KEY_DEV_COUNT) > 0 {
        return;
    }
    if let Some(primary) = storage::get_address(KEY_OWNER) {
        if primary != [0u8; 20] {
            let mut secp = [0u8; 64];
            let _ = storage::get_into(KEY_SECP_PUB64, &mut secp);
            let _ = upsert_owner_device_internal(&primary, &secp, b"Primary Device", &[]);
        }
    }
}

fn upsert_owner_device_internal(
    device_eoa: &[u8; 20],
    device_secp64: &[u8],
    label: &[u8],
    wrapped_seed: &[u8],
) -> Result<usize, i32> {
    if *device_eoa == [0u8; 20]
        || (!device_secp64.is_empty() && device_secp64.len() != 64)
        || label.len() > MAX_DEV_LABEL_LEN
        || wrapped_seed.len() > MAX_WRAPPED_SEED_LEN
    {
        return Err(-23);
    }

    let ik = dev_idx_key(device_eoa);
    let existing_plus_one = storage::get_u64(ik.as_slice()) as usize;
    let cnt = storage::get_u64(KEY_DEV_COUNT) as usize;

    let mut secp = [0u8; 64];
    if device_secp64.len() == 64 {
        secp.copy_from_slice(device_secp64);
    }

    let slot_idx = if existing_plus_one > 0 && existing_plus_one - 1 < cnt {
        let idx = existing_plus_one - 1;
        if secp == [0u8; 64] {
            if let Some(prev) = OwnerDeviceRec::load(idx) {
                secp = prev.secp_pub64;
            }
        }
        idx
    } else if cnt < MAX_OWNER_DEVICES {
        storage::set_u64(KEY_DEV_COUNT, (cnt + 1) as u64);
        cnt
    } else {
        // Reuse first REVOKED slot if ring reached `MAX_OWNER_DEVICES`
        let mut reusable: Option<usize> = None;
        let mut i = 0usize;
        while i < cnt {
            if let Some(r) = OwnerDeviceRec::load(i) {
                if r.status != DEV_STATUS_ACTIVE {
                    reusable = Some(i);
                    break;
                }
            }
            i += 1;
        }
        reusable.ok_or(-32)? // ring full of active devices
    };

    let eff_lbl = if label.is_empty() {
        b"Device".as_slice()
    } else {
        label
    };
    let mut lbl_arr = [0u8; MAX_DEV_LABEL_LEN];
    lbl_arr[..eff_lbl.len()].copy_from_slice(eff_lbl);
    let mut wrap_arr = [0u8; MAX_WRAPPED_SEED_LEN];
    wrap_arr[..wrapped_seed.len()].copy_from_slice(wrapped_seed);

    let rec = OwnerDeviceRec {
        status: DEV_STATUS_ACTIVE,
        eoa: *device_eoa,
        added_block: context::block_number(),
        secp_pub64: secp,
        label_len: eff_lbl.len() as u8,
        label: lbl_arr,
        wrap_len: wrapped_seed.len() as u16,
        wrapped_seed: wrap_arr,
    };
    rec.save(slot_idx);
    Ok(slot_idx)
}

fn revoke_all_owner_devices_internal() {
    ensure_primary_owner_in_ring();
    let cnt = storage::get_u64(KEY_DEV_COUNT) as usize;
    let mut i = 0usize;
    while i < cnt {
        if let Some(mut r) = OwnerDeviceRec::load(i) {
            if r.status == DEV_STATUS_ACTIVE {
                r.status = DEV_STATUS_REVOKED;
                r.wrap_len = 0;
                r.wrapped_seed = [0u8; MAX_WRAPPED_SEED_LEN];
                r.save(i);
            }
        }
        i += 1;
    }
}

fn count_active_owner_devices() -> usize {
    ensure_primary_owner_in_ring();
    let cnt = storage::get_u64(KEY_DEV_COUNT) as usize;
    let mut active = 0usize;
    let mut i = 0usize;
    while i < cnt {
        if let Some(r) = OwnerDeviceRec::load(i) {
            if r.status == DEV_STATUS_ACTIVE {
                active += 1;
            }
        }
        i += 1;
    }
    active
}

fn handle_add_owner_device(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    ensure_primary_owner_in_ring();

    let dev_eoa = args.address(0).ok_or(-3)?;
    let dev_secp64 = args.dynamic_bytes(1).ok_or(-3)?;
    let label = args.dynamic_bytes(2).ok_or(-3)?;
    let wrapped_seed = args.dynamic_bytes(3).ok_or(-3)?;

    let idx = upsert_owner_device_internal(&dev_eoa, dev_secp64, label, wrapped_seed)?;
    events::emit(
        &[OWNER_DEVICE_UPDATED, addr_topic(&dev_eoa)],
        &(DEV_STATUS_ACTIVE as u64).to_be_bytes(),
    );
    ret::write_u64_word(idx as u64);
    Ok(())
}

fn handle_update_device_wrapped_seed(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    ensure_primary_owner_in_ring();

    let dev_eoa = args.address(0).ok_or(-3)?;
    let dev_secp64 = args.dynamic_bytes(1).ok_or(-3)?;
    let wrapped_seed = args.dynamic_bytes(2).ok_or(-3)?;
    if !is_owner_eoa(&dev_eoa)
        || (!dev_secp64.is_empty() && dev_secp64.len() != 64)
        || wrapped_seed.len() > MAX_WRAPPED_SEED_LEN
    {
        return Err(-23);
    }
    let ik = dev_idx_key(&dev_eoa);
    let idx_plus_one = storage::get_u64(ik.as_slice()) as usize;
    if idx_plus_one == 0 {
        return Err(-23);
    }
    let mut rec = OwnerDeviceRec::load(idx_plus_one - 1).ok_or(-23)?;
    if dev_secp64.len() == 64 {
        rec.secp_pub64.copy_from_slice(dev_secp64);
    }
    rec.wrap_len = wrapped_seed.len() as u16;
    rec.wrapped_seed = [0u8; MAX_WRAPPED_SEED_LEN];
    rec.wrapped_seed[..wrapped_seed.len()].copy_from_slice(wrapped_seed);
    rec.save(idx_plus_one - 1);
    ret::write_bool(true);
    Ok(())
}

fn handle_remove_owner_device(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    ensure_primary_owner_in_ring();

    let target_eoa = args.address(0).ok_or(-3)?;
    let new_id_secp64 = args.dynamic_bytes(1).ok_or(-3)?;
    let new_id_ed32 = args.bytes32(2).ok_or(-3)?;
    let rewrapped_packed = args.dynamic_bytes(3).ok_or(-3)?;

    if !is_owner_eoa(&target_eoa) {
        return Err(-23);
    }
    if count_active_owner_devices() <= 1 {
        return Err(-33); // Cannot remove the last active owner device!
    }

    let ik = dev_idx_key(&target_eoa);
    let idx_plus_one = storage::get_u64(ik.as_slice()) as usize;
    if idx_plus_one == 0 {
        return Err(-23);
    }
    let mut rec = OwnerDeviceRec::load(idx_plus_one - 1).ok_or(-23)?;
    rec.status = DEV_STATUS_REVOKED;
    rec.wrap_len = 0;
    rec.wrapped_seed = [0u8; MAX_WRAPPED_SEED_LEN];
    rec.save(idx_plus_one - 1);

    // If primary `KEY_OWNER` was revoked, promote the first surviving ACTIVE device to `KEY_OWNER`
    if storage::get_address(KEY_OWNER) == Some(target_eoa) {
        let cnt = storage::get_u64(KEY_DEV_COUNT) as usize;
        let mut i = 0usize;
        while i < cnt {
            if let Some(r) = OwnerDeviceRec::load(i) {
                if r.status == DEV_STATUS_ACTIVE {
                    storage::set_address(KEY_OWNER, &r.eoa);
                    break;
                }
            }
            i += 1;
        }
    }

    // Optional atomic canonical encryption key rotation & surviving-device re-wrap
    if !new_id_secp64.is_empty() {
        let cur_owner = storage::get_address(KEY_OWNER).unwrap_or(caller);
        store_validated_encryption_keys(&cur_owner, new_id_secp64, &new_id_ed32)?;
        if rewrapped_packed.len() >= 2 {
            let r_cnt = u16::from_be_bytes([rewrapped_packed[0], rewrapped_packed[1]]) as usize;
            let mut pos = 2usize;
            let mut j = 0usize;
            while j < r_cnt {
                if pos + 22 > rewrapped_packed.len() {
                    return Err(-3);
                }
                let mut d_eoa = [0u8; 20];
                d_eoa.copy_from_slice(&rewrapped_packed[pos..pos + 20]);
                let wl =
                    u16::from_be_bytes([rewrapped_packed[pos + 20], rewrapped_packed[pos + 21]])
                        as usize;
                pos += 22;
                if wl > MAX_WRAPPED_SEED_LEN || pos + wl > rewrapped_packed.len() {
                    return Err(-3);
                }
                let dik = dev_idx_key(&d_eoa);
                let d_plus_one = storage::get_u64(dik.as_slice()) as usize;
                if d_plus_one > 0 {
                    if let Some(mut d_rec) = OwnerDeviceRec::load(d_plus_one - 1) {
                        if d_rec.status == DEV_STATUS_ACTIVE {
                            d_rec.wrap_len = wl as u16;
                            d_rec.wrapped_seed = [0u8; MAX_WRAPPED_SEED_LEN];
                            d_rec.wrapped_seed[..wl]
                                .copy_from_slice(&rewrapped_packed[pos..pos + wl]);
                            d_rec.save(d_plus_one - 1);
                        }
                    }
                }
                pos += wl;
                j += 1;
            }
        }
    }

    events::emit(
        &[OWNER_DEVICE_UPDATED, addr_topic(&target_eoa)],
        &(DEV_STATUS_REVOKED as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_is_owner_device(args: &CalldataReader) -> Result<(), i32> {
    let actor = args.address(0).ok_or(-3)?;
    ret::write_bool(is_owner_eoa(&actor));
    Ok(())
}

fn handle_get_owner_devices(_args: &CalldataReader) -> Result<(), i32> {
    ensure_primary_owner_in_ring();
    let cnt = storage::get_u64(KEY_DEV_COUNT) as usize;
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(ID_VIEW_OUT);
        let mut pos = 2usize;
        let mut written = 0u16;
        let mut i = 0usize;
        while i < cnt {
            if let Some(r) = OwnerDeviceRec::load(i) {
                let ll = r.label_len as usize;
                let wl = r.wrap_len as usize;
                let need = 1 + 20 + 8 + 64 + 1 + ll + 2 + wl;
                if pos + need > out.len() {
                    break;
                }
                out[pos] = r.status;
                out[pos + 1..pos + 21].copy_from_slice(&r.eoa);
                out[pos + 21..pos + 29].copy_from_slice(&r.added_block.to_be_bytes());
                out[pos + 29..pos + 93].copy_from_slice(&r.secp_pub64);
                out[pos + 93] = ll as u8;
                pos += 94;
                out[pos..pos + ll].copy_from_slice(&r.label[..ll]);
                pos += ll;
                out[pos..pos + 2].copy_from_slice(&(wl as u16).to_be_bytes());
                pos += 2;
                out[pos..pos + wl].copy_from_slice(&r.wrapped_seed[..wl]);
                pos += wl;
                written += 1;
            }
            i += 1;
        }
        out[0..2].copy_from_slice(&written.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

// ============================================================================
// Capacity-Capped `GuardianKeychain` (`<= N` Shares Blast-Radius Sharding)
// ============================================================================

fn gk_slot_key(slot_id: usize) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"id:gk:sl:")
        .push_u64_be(slot_id as u64)
}

fn gk_ward_key(ward: &[u8; 20]) -> KeyBuilder<36> {
    KeyBuilder::<36>::new().push(b"id:gk:wd:").push(ward)
}

const FIXED_GK_REC_LEN: usize = 1 + 4 + 4 + 8 + 20 + 32 + 64 + 1; // 134B
const MAX_GK_REC_LEN: usize = FIXED_GK_REC_LEN + MAX_DEV_LABEL_LEN;

struct GuardianSlotRec {
    status: u8,
    assigned_count: u32,
    max_capacity: u32,
    created_block: u64,
    operator_eoa: [u8; 20],
    ed_pub32: [u8; 32],
    secp_pub64: [u8; 64],
    label_len: u8,
    label: [u8; MAX_DEV_LABEL_LEN],
}

impl GuardianSlotRec {
    fn save(&self, slot_id: usize) {
        let ll = (self.label_len as usize).min(MAX_DEV_LABEL_LEN);
        let mut buf = [0u8; MAX_GK_REC_LEN];
        buf[0] = self.status;
        buf[1..5].copy_from_slice(&self.assigned_count.to_be_bytes());
        buf[5..9].copy_from_slice(&self.max_capacity.to_be_bytes());
        buf[9..17].copy_from_slice(&self.created_block.to_be_bytes());
        buf[17..37].copy_from_slice(&self.operator_eoa);
        buf[37..69].copy_from_slice(&self.ed_pub32);
        buf[69..133].copy_from_slice(&self.secp_pub64);
        buf[133] = ll as u8;
        buf[134..134 + ll].copy_from_slice(&self.label[..ll]);
        let k = gk_slot_key(slot_id);
        storage::set(k.as_slice(), &buf[..134 + ll]);
    }

    fn load(slot_id: usize) -> Option<Self> {
        let k = gk_slot_key(slot_id);
        let mut buf = [0u8; MAX_GK_REC_LEN];
        let n = storage::get_into(k.as_slice(), &mut buf)?;
        if n < FIXED_GK_REC_LEN {
            return None;
        }
        let status = buf[0];
        let assigned_count = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let max_capacity = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let created_block = u64::from_be_bytes([
            buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16],
        ]);
        let mut operator_eoa = [0u8; 20];
        operator_eoa.copy_from_slice(&buf[17..37]);
        let mut ed_pub32 = [0u8; 32];
        ed_pub32.copy_from_slice(&buf[37..69]);
        let mut secp_pub64 = [0u8; 64];
        secp_pub64.copy_from_slice(&buf[69..133]);
        let ll = (buf[133] as usize)
            .min(MAX_DEV_LABEL_LEN)
            .min(n.saturating_sub(FIXED_GK_REC_LEN));
        let mut label = [0u8; MAX_DEV_LABEL_LEN];
        label[..ll].copy_from_slice(&buf[134..134 + ll]);
        Some(Self {
            status,
            assigned_count,
            max_capacity,
            created_block,
            operator_eoa,
            ed_pub32,
            secp_pub64,
            label_len: ll as u8,
            label,
        })
    }

    fn pack_descriptor_132(&self, slot_id: usize) -> [u8; 132] {
        let mut out = [0u8; 132];
        out[0..8].copy_from_slice(&(slot_id as u64).to_be_bytes());
        out[8..12].copy_from_slice(&self.assigned_count.to_be_bytes());
        out[12..16].copy_from_slice(&self.max_capacity.to_be_bytes());
        out[16..36].copy_from_slice(&self.operator_eoa);
        out[36..68].copy_from_slice(&self.ed_pub32);
        out[68..132].copy_from_slice(&self.secp_pub64);
        out
    }
}

fn handle_add_guardian_key_slot(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;

    let operator_eoa = args.address(0).ok_or(-3)?;
    let ed_pub32 = args.bytes32(1).ok_or(-3)?;
    let secp_pub64 = args.dynamic_bytes(2).ok_or(-3)?;
    let max_cap = args.u64(3).ok_or(-3)?;
    let label = args.dynamic_bytes(4).ok_or(-3)?;

    if operator_eoa == [0u8; 20]
        || secp_pub64.len() != 64
        || secp_pub64.iter().all(|&b| b == 0)
        || max_cap == 0
        || max_cap > 1024
        || label.len() > MAX_DEV_LABEL_LEN
    {
        return Err(-23);
    }
    validate_ed25519_prime_point(&ed_pub32)?;

    let cnt = storage::get_u64(KEY_GK_COUNT) as usize;
    if cnt >= MAX_GUARDIAN_SLOTS {
        return Err(-30);
    }

    // Enforce genuine per-slot keypair independence on-chain: reject duplicate operator EOA or pubkey!
    let mut i = 0usize;
    while i < cnt {
        if let Some(s) = GuardianSlotRec::load(i) {
            if s.operator_eoa == operator_eoa
                || s.secp_pub64.as_slice() == secp_pub64
                || s.ed_pub32 == ed_pub32
            {
                return Err(-34);
            }
        }
        i += 1;
    }

    let mut secp_arr = [0u8; 64];
    secp_arr.copy_from_slice(secp_pub64);
    let mut lbl_arr = [0u8; MAX_DEV_LABEL_LEN];
    lbl_arr[..label.len()].copy_from_slice(label);

    let rec = GuardianSlotRec {
        status: SLOT_STATUS_ACTIVE,
        assigned_count: 0,
        max_capacity: max_cap as u32,
        created_block: context::block_number(),
        operator_eoa,
        ed_pub32,
        secp_pub64: secp_arr,
        label_len: label.len() as u8,
        label: lbl_arr,
    };
    rec.save(cnt);
    storage::set_u64(KEY_GK_COUNT, (cnt + 1) as u64);

    events::emit(
        &[
            GUARDIAN_SLOT_ADDED,
            addr_topic(&operator_eoa),
            {
                let mut t = [0u8; 32];
                t[24..32].copy_from_slice(&(cnt as u64).to_be_bytes());
                t
            },
        ],
        &max_cap.to_be_bytes(),
    );
    ret::write_u64_word(cnt as u64);
    Ok(())
}

fn handle_retire_guardian_key_slot(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    let slot_id = args.u64(0).ok_or(-3)? as usize;
    let cnt = storage::get_u64(KEY_GK_COUNT) as usize;
    if slot_id >= cnt {
        return Err(-23);
    }
    let mut rec = GuardianSlotRec::load(slot_id).ok_or(-23)?;
    rec.status = SLOT_STATUS_RETIRED;
    rec.save(slot_id);
    ret::write_bool(true);
    Ok(())
}

fn find_slot_for_ward(ward: &[u8; 20]) -> Option<(usize, GuardianSlotRec, bool)> {
    let wk = gk_ward_key(ward);
    let existing_plus_one = storage::get_u64(wk.as_slice()) as usize;
    let cnt = storage::get_u64(KEY_GK_COUNT) as usize;
    if existing_plus_one > 0 && existing_plus_one - 1 < cnt {
        if let Some(rec) = GuardianSlotRec::load(existing_plus_one - 1) {
            return Some((existing_plus_one - 1, rec, true));
        }
    }
    let mut i = 0usize;
    while i < cnt {
        if let Some(rec) = GuardianSlotRec::load(i) {
            if rec.status == SLOT_STATUS_ACTIVE && rec.assigned_count < rec.max_capacity {
                return Some((i, rec, false));
            }
        }
        i += 1;
    }
    None
}

fn handle_preview_available_guardian_slot(args: &CalldataReader) -> Result<(), i32> {
    let ward = args.address(0).ok_or(-3)?;
    let (slot_id, rec, _) = find_slot_for_ward(&ward).ok_or(-35)?;
    let desc = rec.pack_descriptor_132(slot_id);
    ret::write(&desc);
    Ok(())
}

fn handle_allocate_guardian_slot(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let ward = args.address(0).ok_or(-3)?;
    let caller = context::msg_sender();
    if ward == [0u8; 20] || !has_deployed_wasm(&ward) {
        return Err(-28);
    }
    if caller != ward && !is_actor_authorized(&caller) {
        return Err(-21);
    }

    let (slot_id, mut rec, already_bound) = find_slot_for_ward(&ward).ok_or(-35)?;
    if !already_bound {
        rec.assigned_count = rec.assigned_count.saturating_add(1);
        if rec.assigned_count >= rec.max_capacity {
            rec.status = SLOT_STATUS_SEALED_FULL;
        }
        rec.save(slot_id);
        let wk = gk_ward_key(&ward);
        storage::set_u64(wk.as_slice(), (slot_id + 1) as u64);
        events::emit(
            &[
                GUARDIAN_SLOT_ALLOCATED,
                addr_topic(&ward),
                {
                    let mut t = [0u8; 32];
                    t[24..32].copy_from_slice(&(slot_id as u64).to_be_bytes());
                    t
                },
            ],
            &(rec.assigned_count as u64).to_be_bytes(),
        );
    }

    let desc = rec.pack_descriptor_132(slot_id);
    ret::write(&desc);
    Ok(())
}

fn handle_get_guardian_keychain(_args: &CalldataReader) -> Result<(), i32> {
    let cnt = storage::get_u64(KEY_GK_COUNT) as usize;
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(ID_VIEW_OUT);
        let mut pos = 2usize;
        let mut written = 0u16;
        let mut i = 0usize;
        while i < cnt {
            if let Some(r) = GuardianSlotRec::load(i) {
                let ll = r.label_len as usize;
                let need = 4 + 1 + 4 + 4 + 8 + 20 + 32 + 64 + 1 + ll;
                if pos + need > out.len() {
                    break;
                }
                out[pos..pos + 4].copy_from_slice(&(i as u32).to_be_bytes());
                out[pos + 4] = r.status;
                out[pos + 5..pos + 9].copy_from_slice(&r.assigned_count.to_be_bytes());
                out[pos + 9..pos + 13].copy_from_slice(&r.max_capacity.to_be_bytes());
                out[pos + 13..pos + 21].copy_from_slice(&r.created_block.to_be_bytes());
                out[pos + 21..pos + 41].copy_from_slice(&r.operator_eoa);
                out[pos + 41..pos + 73].copy_from_slice(&r.ed_pub32);
                out[pos + 73..pos + 137].copy_from_slice(&r.secp_pub64);
                out[pos + 137] = ll as u8;
                pos += 138;
                out[pos..pos + ll].copy_from_slice(&r.label[..ll]);
                pos += ll;
                written += 1;
            }
            i += 1;
        }
        out[0..2].copy_from_slice(&written.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

// ============================================================================
// Unhackable Pedersen-VSS Shamir Secret Sharing + Blinded Homomorphic Recovery
// ============================================================================

fn rec_share_key(idx: usize) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"id:rec:sh:")
        .push_u64_be(idx as u64)
}

fn rec_blinded_key(session_id: u64, idx: usize) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"id:rec:bl:")
        .push_u64_be(session_id)
        .push_u64_be(idx as u64)
}

struct RecoveryConfig {
    config_epoch: u64,
    threshold: u8,
    share_count: u8,
    timelock_blocks: u64,
}

impl RecoveryConfig {
    fn save(&self) {
        let mut b = [0u8; 18];
        b[0..8].copy_from_slice(&self.config_epoch.to_be_bytes());
        b[8] = self.threshold;
        b[9] = self.share_count;
        b[10..18].copy_from_slice(&self.timelock_blocks.to_be_bytes());
        storage::set(KEY_REC_CFG, &b);
    }

    fn load() -> Option<Self> {
        let mut b = [0u8; 18];
        if storage::get_into(KEY_REC_CFG, &mut b) != Some(18) {
            return None;
        }
        Some(Self {
            config_epoch: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            threshold: b[8],
            share_count: b[9],
            timelock_blocks: u64::from_be_bytes([
                b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17],
            ]),
        })
    }
}

const FIXED_SHARE_HDR: usize = 1 + 20 + 8 + 20 + 64 + 32 + 32 + 1; // 178B
const MAX_SHARE_REC_LEN: usize = FIXED_SHARE_HDR + MAX_DEV_LABEL_LEN + 2 + MAX_SHARE_ENV_LEN;

struct RecoveryShareRec {
    share_kind: u8,
    guardian_identity: [u8; 20],
    slot_id: u64,
    operator_eoa: [u8; 20],
    recipient_secp64: [u8; 64],
    p_0: [u8; 32],
    p_1: [u8; 32],
    label_len: u8,
    label: [u8; MAX_DEV_LABEL_LEN],
    env_len: u16,
    envelope: [u8; MAX_SHARE_ENV_LEN],
}

impl RecoveryShareRec {
    fn save(&self, idx: usize) {
        let ll = (self.label_len as usize).min(MAX_DEV_LABEL_LEN);
        let el = (self.env_len as usize).min(MAX_SHARE_ENV_LEN);
        let mut b = [0u8; MAX_SHARE_REC_LEN];
        b[0] = self.share_kind;
        b[1..21].copy_from_slice(&self.guardian_identity);
        b[21..29].copy_from_slice(&self.slot_id.to_be_bytes());
        b[29..49].copy_from_slice(&self.operator_eoa);
        b[49..113].copy_from_slice(&self.recipient_secp64);
        b[113..145].copy_from_slice(&self.p_0);
        b[145..177].copy_from_slice(&self.p_1);
        b[177] = ll as u8;
        b[178..178 + ll].copy_from_slice(&self.label[..ll]);
        let e_off = 178 + ll;
        b[e_off..e_off + 2].copy_from_slice(&(el as u16).to_be_bytes());
        b[e_off + 2..e_off + 2 + el].copy_from_slice(&self.envelope[..el]);
        let k = rec_share_key(idx);
        storage::set(k.as_slice(), &b[..e_off + 2 + el]);
    }

    fn load(idx: usize) -> Option<Self> {
        let k = rec_share_key(idx);
        let mut b = [0u8; MAX_SHARE_REC_LEN];
        let n = storage::get_into(k.as_slice(), &mut b)?;
        if n < FIXED_SHARE_HDR + 2 {
            return None;
        }
        let share_kind = b[0];
        let mut guardian_identity = [0u8; 20];
        guardian_identity.copy_from_slice(&b[1..21]);
        let slot_id =
            u64::from_be_bytes([b[21], b[22], b[23], b[24], b[25], b[26], b[27], b[28]]);
        let mut operator_eoa = [0u8; 20];
        operator_eoa.copy_from_slice(&b[29..49]);
        let mut recipient_secp64 = [0u8; 64];
        recipient_secp64.copy_from_slice(&b[49..113]);
        let mut p_0 = [0u8; 32];
        p_0.copy_from_slice(&b[113..145]);
        let mut p_1 = [0u8; 32];
        p_1.copy_from_slice(&b[145..177]);
        let ll = (b[177] as usize).min(MAX_DEV_LABEL_LEN);
        if n < 178 + ll + 2 {
            return None;
        }
        let mut label = [0u8; MAX_DEV_LABEL_LEN];
        label[..ll].copy_from_slice(&b[178..178 + ll]);
        let e_off = 178 + ll;
        let el = (u16::from_be_bytes([b[e_off], b[e_off + 1]]) as usize)
            .min(MAX_SHARE_ENV_LEN)
            .min(n.saturating_sub(e_off + 2));
        let mut envelope = [0u8; MAX_SHARE_ENV_LEN];
        envelope[..el].copy_from_slice(&b[e_off + 2..e_off + 2 + el]);
        Some(Self {
            share_kind,
            guardian_identity,
            slot_id,
            operator_eoa,
            recipient_secp64,
            p_0,
            p_1,
            label_len: ll as u8,
            label,
            env_len: el as u16,
            envelope,
        })
    }
}

const FIXED_SESS_LEN: usize = 8 + 1 + 1 + 8 + 8 + 8 + 20 + 32 + 64 + 1; // 151B
const MAX_SESS_LEN: usize = FIXED_SESS_LEN + MAX_DEV_LABEL_LEN;

struct RecoverySession {
    session_id: u64,
    status: u8,
    submitted_count: u8,
    initiated_block: u64,
    unlock_block: u64,
    submitted_mask: u64,
    new_owner_eoa: [u8; 20],
    new_device_ed32: [u8; 32],
    new_device_secp64: [u8; 64],
    label_len: u8,
    label: [u8; MAX_DEV_LABEL_LEN],
}

impl RecoverySession {
    fn save(&self) {
        let ll = (self.label_len as usize).min(MAX_DEV_LABEL_LEN);
        let mut b = [0u8; MAX_SESS_LEN];
        b[0..8].copy_from_slice(&self.session_id.to_be_bytes());
        b[8] = self.status;
        b[9] = self.submitted_count;
        b[10..18].copy_from_slice(&self.initiated_block.to_be_bytes());
        b[18..26].copy_from_slice(&self.unlock_block.to_be_bytes());
        b[26..34].copy_from_slice(&self.submitted_mask.to_be_bytes());
        b[34..54].copy_from_slice(&self.new_owner_eoa);
        b[54..86].copy_from_slice(&self.new_device_ed32);
        b[86..150].copy_from_slice(&self.new_device_secp64);
        b[150] = ll as u8;
        b[151..151 + ll].copy_from_slice(&self.label[..ll]);
        storage::set(KEY_REC_SESS, &b[..151 + ll]);
    }

    fn load() -> Option<Self> {
        let mut b = [0u8; MAX_SESS_LEN];
        let n = storage::get_into(KEY_REC_SESS, &mut b)?;
        if n < FIXED_SESS_LEN {
            return None;
        }
        let ll = (b[150] as usize)
            .min(MAX_DEV_LABEL_LEN)
            .min(n.saturating_sub(FIXED_SESS_LEN));
        let mut new_owner_eoa = [0u8; 20];
        new_owner_eoa.copy_from_slice(&b[34..54]);
        let mut new_device_ed32 = [0u8; 32];
        new_device_ed32.copy_from_slice(&b[54..86]);
        let mut new_device_secp64 = [0u8; 64];
        new_device_secp64.copy_from_slice(&b[86..150]);
        let mut label = [0u8; MAX_DEV_LABEL_LEN];
        label[..ll].copy_from_slice(&b[151..151 + ll]);
        Some(Self {
            session_id: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            status: b[8],
            submitted_count: b[9],
            initiated_block: u64::from_be_bytes([
                b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17],
            ]),
            unlock_block: u64::from_be_bytes([
                b[18], b[19], b[20], b[21], b[22], b[23], b[24], b[25],
            ]),
            submitted_mask: u64::from_be_bytes([
                b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33],
            ]),
            new_owner_eoa,
            new_device_ed32,
            new_device_secp64,
            label_len: ll as u8,
            label,
        })
    }
}

/// Evaluates `P(x_i) = sum_{k=0}^{t-1} (x_i)^k C_k` via Horner's rule over `<B>`.
fn eval_vss_poly_point(commits: &[[u8; 32]], t: usize, x_i: u64) -> Result<[u8; 32], i32> {
    let x_sc = scalar_from_u64(x_i);
    let mut acc = commits[t - 1];
    let mut k = t - 1;
    while k > 0 {
        k -= 1;
        acc = ec_elgamal_lincomb(&x_sc, &acc, &SCALAR_ONE_BYTES, &commits[k]).ok_or(-37)?;
    }
    Ok(acc)
}

fn handle_configure_shamir_recovery(args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    ensure_primary_owner_in_ring();

    let threshold = args.u64(0).ok_or(-3)? as usize;
    let timelock_blocks = args.u64(1).ok_or(-3)?;
    let vss_commits_packed = args.dynamic_bytes(2).ok_or(-3)?;
    let shares_packed = args.dynamic_bytes(3).ok_or(-3)?;

    if threshold < 2
        || threshold > MAX_SHAMIR_THRESHOLD
        || timelock_blocks > 100_000
        || vss_commits_packed.len() != threshold * 64
        || shares_packed.is_empty()
    {
        return Err(-23);
    }

    let share_count = shares_packed[0] as usize;
    if share_count < threshold || share_count > MAX_SHAMIR_SHARES {
        return Err(-23);
    }

    let mut commits_0 = [[0u8; 32]; MAX_SHAMIR_THRESHOLD];
    let mut commits_1 = [[0u8; 32]; MAX_SHAMIR_THRESHOLD];
    let mut k = 0usize;
    while k < threshold {
        commits_0[k].copy_from_slice(&vss_commits_packed[k * 32..(k + 1) * 32]);
        validate_ed25519_prime_point(&commits_0[k])?;
        let off1 = (threshold + k) * 32;
        commits_1[k].copy_from_slice(&vss_commits_packed[off1..off1 + 32]);
        validate_ed25519_prime_point(&commits_1[k])?;
        k += 1;
    }

    let me = context::self_address();
    let mut pos = 1usize;
    let mut idx = 0usize;
    while idx < share_count {
        // [kind:1][guardianId:20][slotId:8 BE][operatorEoa:20][secpPub64:64][lblLen:1][lbl][envLen:2 BE][env]
        if pos + 114 > shares_packed.len() {
            return Err(-3);
        }
        let kind = shares_packed[pos];
        if kind != SHARE_KIND_GUARDIAN_SLOT
            && kind != SHARE_KIND_DIRECT_EOA
            && kind != SHARE_KIND_SELF_PASSPHRASE
        {
            return Err(-23);
        }
        let mut guardian_id = [0u8; 20];
        guardian_id.copy_from_slice(&shares_packed[pos + 1..pos + 21]);
        let slot_id = u64::from_be_bytes([
            shares_packed[pos + 21],
            shares_packed[pos + 22],
            shares_packed[pos + 23],
            shares_packed[pos + 24],
            shares_packed[pos + 25],
            shares_packed[pos + 26],
            shares_packed[pos + 27],
            shares_packed[pos + 28],
        ]);
        let mut op_eoa = [0u8; 20];
        op_eoa.copy_from_slice(&shares_packed[pos + 29..pos + 49]);
        let mut rec_secp = [0u8; 64];
        rec_secp.copy_from_slice(&shares_packed[pos + 49..pos + 113]);
        let ll = shares_packed[pos + 113] as usize;
        pos += 114;
        if ll > MAX_DEV_LABEL_LEN || pos + ll + 2 > shares_packed.len() {
            return Err(-3);
        }
        let mut lbl_arr = [0u8; MAX_DEV_LABEL_LEN];
        lbl_arr[..ll].copy_from_slice(&shares_packed[pos..pos + ll]);
        pos += ll;
        let el = u16::from_be_bytes([shares_packed[pos], shares_packed[pos + 1]]) as usize;
        pos += 2;
        if el == 0 || el > MAX_SHARE_ENV_LEN || pos + el > shares_packed.len() {
            return Err(-3);
        }
        let mut env_arr = [0u8; MAX_SHARE_ENV_LEN];
        env_arr[..el].copy_from_slice(&shares_packed[pos..pos + el]);
        pos += el;

        if kind == SHARE_KIND_GUARDIAN_SLOT {
            if guardian_id == [0u8; 20] || op_eoa == [0u8; 20] {
                return Err(-23);
            }
            guard_and_promote_outbound_hfs(&guardian_id)?;
            let alloc_cd = CallEncoder::<68>::new(const {
                selector("allocateGuardianSlot(address)")
            })
            .push_address(&me);
            let raw_desc = call::call_raw(&guardian_id, alloc_cd.as_slice())?;
            if raw_desc.len() < 132 {
                return Err(-36);
            }
            let mut desc = [0u8; 132];
            desc.copy_from_slice(&raw_desc[..132]);
            let alloc_slot = u64::from_be_bytes([
                desc[0], desc[1], desc[2], desc[3], desc[4], desc[5], desc[6], desc[7],
            ]);
            if alloc_slot != slot_id
                || desc[16..36] != op_eoa
                || desc[68..132] != rec_secp
            {
                return Err(-36);
            }
        } else if kind == SHARE_KIND_DIRECT_EOA && op_eoa == [0u8; 20] {
            return Err(-23);
        }

        let x_i = (idx + 1) as u64;
        let p_0 = eval_vss_poly_point(&commits_0, threshold, x_i)?;
        let p_1 = eval_vss_poly_point(&commits_1, threshold, x_i)?;

        let rec = RecoveryShareRec {
            share_kind: kind,
            guardian_identity: guardian_id,
            slot_id,
            operator_eoa: op_eoa,
            recipient_secp64: rec_secp,
            p_0,
            p_1,
            label_len: ll as u8,
            label: lbl_arr,
            env_len: el as u16,
            envelope: env_arr,
        };
        rec.save(idx);
        idx += 1;
    }

    let prev_epoch = RecoveryConfig::load().map(|c| c.config_epoch).unwrap_or(0);
    let new_epoch = prev_epoch + 1;
    let cfg = RecoveryConfig {
        config_epoch: new_epoch,
        threshold: threshold as u8,
        share_count: share_count as u8,
        timelock_blocks,
    };
    cfg.save();

    // Cancel any pre-existing open recovery session on reconfiguration
    if let Some(mut sess) = RecoverySession::load() {
        if sess.status == REC_STATUS_COLLECTING || sess.status == REC_STATUS_TIMELOCKED {
            sess.status = REC_STATUS_CANCELLED;
            sess.save();
        }
    }

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&new_epoch.to_be_bytes());
    ev[8..16].copy_from_slice(&(threshold as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&(share_count as u64).to_be_bytes());
    events::emit(&[SHAMIR_CONFIGURED, addr_topic(&caller)], &ev);
    ret::write_u64_word(new_epoch);
    Ok(())
}

fn handle_initiate_recovery(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let cfg = RecoveryConfig::load().ok_or(-38)?;
    if cfg.threshold < 2 {
        return Err(-38);
    }

    let new_owner = args.address(0).ok_or(-3)?;
    let new_secp64 = args.dynamic_bytes(1).ok_or(-3)?;
    let new_ed32 = args.bytes32(2).ok_or(-3)?;
    let label = args.dynamic_bytes(3).ok_or(-3)?;

    let caller = context::msg_sender();
    if caller != new_owner
        || new_owner == [0u8; 20]
        || is_owner_eoa(&new_owner)
        || new_secp64.len() != 64
        || new_secp64.iter().all(|&b| b == 0)
        || label.len() > MAX_DEV_LABEL_LEN
    {
        return Err(-23);
    }
    validate_ed25519_prime_point(&new_ed32)?;

    let now = context::block_number();
    let prev_id = if let Some(prev) = RecoverySession::load() {
        // Prevent stranger from overwriting a threshold-met timelocked session before stale window
        if prev.status == REC_STATUS_TIMELOCKED && now <= prev.unlock_block.saturating_add(256) {
            return Err(-40);
        }
        prev.session_id
    } else {
        0
    };

    let session_id = prev_id + 1;
    let mut secp_arr = [0u8; 64];
    secp_arr.copy_from_slice(new_secp64);
    let eff_lbl = if label.is_empty() {
        b"Recovered Device".as_slice()
    } else {
        label
    };
    let mut lbl_arr = [0u8; MAX_DEV_LABEL_LEN];
    lbl_arr[..eff_lbl.len()].copy_from_slice(eff_lbl);

    let sess = RecoverySession {
        session_id,
        status: REC_STATUS_COLLECTING,
        submitted_count: 0,
        initiated_block: now,
        unlock_block: 0,
        submitted_mask: 0,
        new_owner_eoa: new_owner,
        new_device_ed32: new_ed32,
        new_device_secp64: secp_arr,
        label_len: eff_lbl.len() as u8,
        label: lbl_arr,
    };
    sess.save();

    events::emit(
        &[RECOVERY_INITIATED, addr_topic(&new_owner), new_ed32],
        &session_id.to_be_bytes(),
    );
    ret::write_u64_word(session_id);
    Ok(())
}

fn verify_blinded_share_proof(
    identity_addr: &[u8; 20],
    session_id: u64,
    share_idx: usize,
    new_owner_eoa: &[u8; 20],
    y_new: &[u8; 32],
    p_0: &[u8; 32],
    p_1: &[u8; 32],
    proof: &[u8],
) -> Option<[u8; 96]> {
    if proof.len() != BLINDED_SHARE_PROOF_LEN {
        return None;
    }
    let mut r_pt = [0u8; 32];
    let mut m_0 = [0u8; 32];
    let mut z_0 = [0u8; 32];
    let mut w_0 = [0u8; 32];
    let mut m_1 = [0u8; 32];
    let mut z_1 = [0u8; 32];
    let mut w_1 = [0u8; 32];
    let mut c = [0u8; 32];
    let mut u_r = [0u8; 32];
    let mut u_m0 = [0u8; 32];
    let mut u_mu0 = [0u8; 32];
    let mut u_m1 = [0u8; 32];
    let mut u_mu1 = [0u8; 32];

    r_pt.copy_from_slice(&proof[0..32]);
    m_0.copy_from_slice(&proof[32..64]);
    z_0.copy_from_slice(&proof[64..96]);
    w_0.copy_from_slice(&proof[96..128]);
    m_1.copy_from_slice(&proof[128..160]);
    z_1.copy_from_slice(&proof[160..192]);
    w_1.copy_from_slice(&proof[192..224]);
    c.copy_from_slice(&proof[224..256]);
    u_r.copy_from_slice(&proof[256..288]);
    u_m0.copy_from_slice(&proof[288..320]);
    u_mu0.copy_from_slice(&proof[320..352]);
    u_m1.copy_from_slice(&proof[352..384]);
    u_mu1.copy_from_slice(&proof[384..416]);

    if r_pt == [0u8; 32] || r_pt == IDENTITY_POINT_BYTES || !scalar_is_canonical(&c) {
        return None;
    }

    // 1. Homomorphic Pedersen VSS share verification for Limb 0 & Limb 1:
    //    `z_{i,b} * B + w_{i,b} * H_bp == M_{i,b} + P_{i,b}`
    let zw_0 = ec_elgamal_lincomb(&z_0, &ED25519_BASEPOINT_BYTES, &w_0, &BP_H_BLIND_BYTES)?;
    let mp_0 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &m_0, &SCALAR_ONE_BYTES, p_0)?;
    if zw_0 != mp_0 {
        return None;
    }

    let zw_1 = ec_elgamal_lincomb(&z_1, &ED25519_BASEPOINT_BYTES, &w_1, &BP_H_BLIND_BYTES)?;
    let mp_1 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &m_1, &SCALAR_ONE_BYTES, p_1)?;
    if zw_1 != mp_1 {
        return None;
    }

    // 2. Fiat-Shamir Schnorr proof of knowledge of `r_i` on `R_i` and `(m_{i,b}, mu_{i,b})` on `M_{i,b}`:
    let neg_c = scalar_neg(&c);
    let t_r = ec_elgamal_lincomb(&u_r, &ED25519_BASEPOINT_BYTES, &neg_c, &r_pt)?;
    let u0_pt = ec_elgamal_lincomb(&u_m0, &ED25519_BASEPOINT_BYTES, &u_mu0, &BP_H_BLIND_BYTES)?;
    let t_m0 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &u0_pt, &neg_c, &m_0)?;
    let u1_pt = ec_elgamal_lincomb(&u_m1, &ED25519_BASEPOINT_BYTES, &u_mu1, &BP_H_BLIND_BYTES)?;
    let t_m1 = ec_elgamal_lincomb(&SCALAR_ONE_BYTES, &u1_pt, &neg_c, &m_1)?;

    let mut pre = [0u8; 495];
    pre[0..23].copy_from_slice(b"SLX_SHAMIR_BLIND_POK_V1");
    pre[23..43].copy_from_slice(identity_addr);
    pre[43..51].copy_from_slice(&session_id.to_be_bytes());
    pre[51..59].copy_from_slice(&(share_idx as u64).to_be_bytes());
    pre[59..79].copy_from_slice(new_owner_eoa);
    pre[79..111].copy_from_slice(y_new);
    pre[111..143].copy_from_slice(p_0);
    pre[143..175].copy_from_slice(p_1);
    pre[175..399].copy_from_slice(&proof[0..224]);
    pre[399..431].copy_from_slice(&t_r);
    pre[431..463].copy_from_slice(&t_m0);
    pre[463..495].copy_from_slice(&t_m1);

    let expected_c = scalar_from_hash_nonzero(&keccak256(&pre));
    if c != expected_c {
        return None;
    }

    let mut stored_96 = [0u8; 96];
    stored_96[0..32].copy_from_slice(&r_pt);
    stored_96[32..64].copy_from_slice(&z_0);
    stored_96[64..96].copy_from_slice(&z_1);
    Some(stored_96)
}

fn handle_submit_recovery_share(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let cfg = RecoveryConfig::load().ok_or(-38)?;
    let mut sess = RecoverySession::load().ok_or(-38)?;

    let session_id = args.u64(0).ok_or(-3)?;
    let share_idx = args.u64(1).ok_or(-3)? as usize;
    let proof = args.dynamic_bytes(2).ok_or(-3)?;

    if sess.session_id != session_id
        || (sess.status != REC_STATUS_COLLECTING && sess.status != REC_STATUS_TIMELOCKED)
        || share_idx >= cfg.share_count as usize
        || (sess.submitted_mask & (1u64 << share_idx)) != 0
    {
        return Err(-23);
    }

    let share = RecoveryShareRec::load(share_idx).ok_or(-38)?;
    let caller = context::msg_sender();
    match share.share_kind {
        SHARE_KIND_GUARDIAN_SLOT | SHARE_KIND_DIRECT_EOA => {
            let valid_guardian_id =
                share.guardian_identity != [0u8; 20] && caller == share.guardian_identity;
            if caller != share.operator_eoa && !valid_guardian_id {
                return Err(-21);
            }
        }
        SHARE_KIND_SELF_PASSPHRASE => {
            if caller != sess.new_owner_eoa {
                return Err(-21);
            }
        }
        _ => return Err(-23),
    }

    let me = context::self_address();
    let stored_96 = verify_blinded_share_proof(
        &me,
        session_id,
        share_idx,
        &sess.new_owner_eoa,
        &sess.new_device_ed32,
        &share.p_0,
        &share.p_1,
        proof,
    )
    .ok_or(-41)?;

    let bk = rec_blinded_key(session_id, share_idx);
    storage::set(bk.as_slice(), &stored_96);

    sess.submitted_mask |= 1u64 << share_idx;
    sess.submitted_count = sess.submitted_count.saturating_add(1);
    if sess.status == REC_STATUS_COLLECTING && sess.submitted_count >= cfg.threshold {
        sess.status = REC_STATUS_TIMELOCKED;
        sess.unlock_block = context::block_number().saturating_add(cfg.timelock_blocks);
    }
    sess.save();

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&session_id.to_be_bytes());
    ev[8..16].copy_from_slice(&(share_idx as u64).to_be_bytes());
    ev[16..24].copy_from_slice(&(sess.submitted_count as u64).to_be_bytes());
    events::emit(&[RECOVERY_SHARE_SUBMITTED, addr_topic(&caller)], &ev);
    ret::write_u64_word(sess.submitted_count as u64);
    Ok(())
}

fn handle_cancel_recovery(_args: &CalldataReader) -> Result<(), i32> {
    let caller = context::msg_sender();
    check_owner(&caller)?;
    let mut sess = RecoverySession::load().ok_or(-38)?;
    if sess.status != REC_STATUS_COLLECTING && sess.status != REC_STATUS_TIMELOCKED {
        return Err(-23);
    }
    sess.status = REC_STATUS_CANCELLED;
    sess.save();
    events::emit(
        &[RECOVERY_CANCELLED, addr_topic(&caller)],
        &sess.session_id.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_finalize_recovery(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let cfg = RecoveryConfig::load().ok_or(-38)?;
    let mut sess = RecoverySession::load().ok_or(-38)?;

    let session_id = args.u64(0).ok_or(-3)?;
    let revoke_existing = args.bool(1).ok_or(-3)?;
    let wrapped_seed = args.dynamic_bytes(2).ok_or(-3)?;

    let caller = context::msg_sender();
    if sess.session_id != session_id
        || sess.status != REC_STATUS_TIMELOCKED
        || sess.submitted_count < cfg.threshold
        || caller != sess.new_owner_eoa
        || wrapped_seed.len() > MAX_WRAPPED_SEED_LEN
    {
        return Err(-21);
    }
    if context::block_number() < sess.unlock_block {
        return Err(-39); // Timelock window not yet elapsed!
    }

    ensure_primary_owner_in_ring();
    if revoke_existing {
        revoke_all_owner_devices_internal();
        storage::set_address(KEY_OWNER, &sess.new_owner_eoa);
    }

    let ll = sess.label_len as usize;
    upsert_owner_device_internal(
        &sess.new_owner_eoa,
        &sess.new_device_secp64,
        &sess.label[..ll],
        wrapped_seed,
    )?;

    sess.status = REC_STATUS_FINALIZED;
    sess.save();

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&session_id.to_be_bytes());
    ev[8..16].copy_from_slice(&(u64::from(revoke_existing)).to_be_bytes());
    events::emit(&[RECOVERY_FINALIZED, addr_topic(&sess.new_owner_eoa)], &ev);
    ret::write_bool(true);
    Ok(())
}

fn handle_get_recovery_state(_args: &CalldataReader) -> Result<(), i32> {
    let cfg = RecoveryConfig::load().unwrap_or(RecoveryConfig {
        config_epoch: 0,
        threshold: 0,
        share_count: 0,
        timelock_blocks: 0,
    });
    let sess_opt = RecoverySession::load();

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(ID_VIEW_OUT);
        out[0..8].copy_from_slice(&cfg.config_epoch.to_be_bytes());
        out[8] = cfg.threshold;
        out[9] = cfg.share_count;
        let (sess_status, sub_cnt, sess_id, init_blk, unlock_blk, sub_mask) =
            if let Some(ref s) = sess_opt {
                (
                    s.status,
                    s.submitted_count,
                    s.session_id,
                    s.initiated_block,
                    s.unlock_block,
                    s.submitted_mask,
                )
            } else {
                (REC_STATUS_NONE, 0, 0, 0, 0, 0)
            };
        out[10] = sess_status;
        out[11] = sub_cnt;
        out[12..20].copy_from_slice(&cfg.timelock_blocks.to_be_bytes());
        out[20..28].copy_from_slice(&sess_id.to_be_bytes());
        out[28..36].copy_from_slice(&init_blk.to_be_bytes());
        out[36..44].copy_from_slice(&unlock_blk.to_be_bytes());
        out[44..52].copy_from_slice(&sub_mask.to_be_bytes());
        let mut pos = 52usize;

        if let Some(ref s) = sess_opt {
            if s.session_id > 0 {
                let ll = s.label_len as usize;
                out[pos..pos + 20].copy_from_slice(&s.new_owner_eoa);
                out[pos + 20..pos + 52].copy_from_slice(&s.new_device_ed32);
                out[pos + 52..pos + 116].copy_from_slice(&s.new_device_secp64);
                out[pos + 116] = ll as u8;
                pos += 117;
                out[pos..pos + ll].copy_from_slice(&s.label[..ll]);
                pos += ll;
            }
        }

        let mut i = 0usize;
        while i < cfg.share_count as usize {
            if let Some(sh) = RecoveryShareRec::load(i) {
                let ll = sh.label_len as usize;
                let el = sh.env_len as usize;
                let has_blinded = sess_id > 0 && (sub_mask & (1u64 << i)) != 0;
                let need =
                    2 + 20 + 8 + 20 + 64 + 64 + 1 + ll + 2 + el + 1 + if has_blinded { 96 } else { 0 };
                if pos + need > out.len() {
                    break;
                }
                out[pos] = i as u8;
                out[pos + 1] = sh.share_kind;
                out[pos + 2..pos + 22].copy_from_slice(&sh.guardian_identity);
                out[pos + 22..pos + 30].copy_from_slice(&sh.slot_id.to_be_bytes());
                out[pos + 30..pos + 50].copy_from_slice(&sh.operator_eoa);
                out[pos + 50..pos + 114].copy_from_slice(&sh.recipient_secp64);
                out[pos + 114..pos + 146].copy_from_slice(&sh.p_0);
                out[pos + 146..pos + 178].copy_from_slice(&sh.p_1);
                out[pos + 178] = ll as u8;
                pos += 179;
                out[pos..pos + ll].copy_from_slice(&sh.label[..ll]);
                pos += ll;
                out[pos..pos + 2].copy_from_slice(&(el as u16).to_be_bytes());
                pos += 2;
                out[pos..pos + el].copy_from_slice(&sh.envelope[..el]);
                pos += el;
                if has_blinded {
                    let bk = rec_blinded_key(sess_id, i);
                    let mut bl = [0u8; 96];
                    if storage::get_into(bk.as_slice(), &mut bl) == Some(96) {
                        out[pos] = 1;
                        out[pos + 1..pos + 97].copy_from_slice(&bl);
                        pos += 97;
                    } else {
                        out[pos] = 0;
                        pos += 1;
                    }
                } else {
                    out[pos] = 0;
                    pos += 1;
                }
            }
            i += 1;
        }

        ret::write(&out[..pos]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    fn init_identity_cd(owner: [u8; 20], handle: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("initialize(address,string)") });
        let mut ow = [0u8; 32];
        ow[12..32].copy_from_slice(&owner);
        cd.extend_from_slice(&ow);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        cd.extend_from_slice(&off);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(handle.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(handle);
        cd.resize(cd.len() + (32 - handle.len() % 32) % 32, 0);
        cd
    }

    #[test]
    fn owner_and_delegates_authorize_cleanly() {
        mock::reset();
        let id_hps = [0xAA; 20];
        let owner_eoa = [0x01; 20];
        let delegate_eoa = [0x02; 20];
        let stranger = [0x99; 20];
        mock::register_hps(id_hps, dispatch_calldata);

        mock::transact_as(owner_eoa, id_hps, &init_identity_cd(owner_eoa, b"alice.id")).unwrap();

        let q_stranger =
            CallEncoder::<64>::new(const { selector("isAuthorized(address)") }).push_address(&stranger);
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, q_stranger.as_slice()).unwrap()[31],
            0
        );

        let set_del = CallEncoder::<96>::new(const { selector("setDelegate(address,bool)") })
            .push_address(&delegate_eoa)
            .push_bool(true);
        assert_eq!(
            mock::transact_as(stranger, id_hps, set_del.as_slice()),
            Err(-21)
        );

        mock::transact_as(owner_eoa, id_hps, set_del.as_slice()).unwrap();
        let q_del =
            CallEncoder::<64>::new(const { selector("isAuthorized(address)") }).push_address(&delegate_eoa);
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, q_del.as_slice()).unwrap()[31],
            1
        );
    }

    fn encode_notify_hfs(hfs_addr: [u8; 20], type_id: [u8; 32], label: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("notifyHfsAssociation(address,bytes32,string)") });
        let mut w0 = [0u8; 32];
        w0[12..32].copy_from_slice(&hfs_addr);
        cd.extend_from_slice(&w0);
        cd.extend_from_slice(&type_id);
        let mut w2 = [0u8; 32];
        w2[24..32].copy_from_slice(&96u64.to_be_bytes());
        cd.extend_from_slice(&w2);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(label.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(label);
        cd.resize(cd.len() + (32 - label.len() % 32) % 32, 0);
        cd
    }

    fn encode_set_hfs(
        hfs_addr: [u8; 20],
        type_id: [u8; 32],
        status: u64,
        label: &[u8],
    ) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(
            &const { selector("setHfsAssociation(address,bytes32,uint64,string)") },
        );
        let mut w0 = [0u8; 32];
        w0[12..32].copy_from_slice(&hfs_addr);
        cd.extend_from_slice(&w0);
        cd.extend_from_slice(&type_id);
        let mut w2 = [0u8; 32];
        w2[24..32].copy_from_slice(&status.to_be_bytes());
        cd.extend_from_slice(&w2);
        let mut w3 = [0u8; 32];
        w3[24..32].copy_from_slice(&128u64.to_be_bytes());
        cd.extend_from_slice(&w3);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(label.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(label);
        cd.resize(cd.len() + (32 - label.len() % 32) % 32, 0);
        cd
    }

    fn encode_exec(target: [u8; 20], inner: &[u8]) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&const { selector("execute(address,bytes)") });
        let mut w0 = [0u8; 32];
        w0[12..32].copy_from_slice(&target);
        cd.extend_from_slice(&w0);
        let mut w1 = [0u8; 32];
        w1[24..32].copy_from_slice(&64u64.to_be_bytes());
        cd.extend_from_slice(&w1);
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(inner.len() as u64).to_be_bytes());
        cd.extend_from_slice(&lw);
        cd.extend_from_slice(inner);
        cd.resize(cd.len() + (32 - inner.len() % 32) % 32, 0);
        cd
    }

    fn dummy_target_hps(_cd: &[u8]) -> i32 {
        ret::write_u64_word(42);
        0
    }

    #[test]
    fn hfs_whitelist_states_firewall_and_inbound_spam_isolation() {
        mock::reset();
        let id_hps = [0xAA; 20];
        let owner_eoa = [0x01; 20];
        let spammer_eoa = [0x66; 20];
        let valid_charter = [0xC1; 20];
        let invited_charter = [0xC2; 20];
        let spam_charter = [0xC3; 20];
        let fake_eoa = [0xEE; 20];

        mock::register_hps(id_hps, dispatch_calldata);
        mock::register_hps(valid_charter, dummy_target_hps);
        mock::register_hps(invited_charter, dummy_target_hps);
        mock::register_hps(spam_charter, dummy_target_hps);
        mock::set_block_number(90_000);

        mock::transact_as(owner_eoa, id_hps, &init_identity_cd(owner_eoa, b"alice.id")).unwrap();

        let mut t_chr = [0u8; 32];
        t_chr[..17].copy_from_slice(b"CORPORATE_CHARTER");

        // 1. Rejects non-WASM EOA addresses in notifyHfsAssociation (-28)
        assert_eq!(
            mock::transact_as(
                spammer_eoa,
                id_hps,
                &encode_notify_hfs(fake_eoa, t_chr, b"Fake EOA")
            ),
            Err(-28)
        );

        // 2. External caller notifying `invited_charter` & `spam_charter` records PENDING (1)
        let r_inv = mock::transact_as(
            spammer_eoa,
            id_hps,
            &encode_notify_hfs(invited_charter, t_chr, b"Invited Venture Pte. Ltd."),
        )
        .unwrap();
        assert_eq!(r_inv[31], HFS_STATUS_PENDING);

        let r_spm = mock::transact_as(
            spammer_eoa,
            id_hps,
            &encode_notify_hfs(spam_charter, t_chr, b"Phishing Airdrop Corp"),
        )
        .unwrap();
        assert_eq!(r_spm[31], HFS_STATUS_PENDING);

        // 3. Owner explicitly whitelists `valid_charter` (2) and blocks `spam_charter` (3)
        mock::transact_as(
            owner_eoa,
            id_hps,
            &encode_set_hfs(
                valid_charter,
                t_chr,
                HFS_STATUS_WHITELISTED as u64,
                b"Sovereign Robotics Pte. Ltd.",
            ),
        )
        .unwrap();
        mock::transact_as(
            owner_eoa,
            id_hps,
            &encode_set_hfs(spam_charter, [0u8; 32], HFS_STATUS_SPAM as u64, b""),
        )
        .unwrap();

        // 4. Spammer CANNOT overwrite SPAM (3) or WHITELISTED (2) back to PENDING!
        let r_retry = mock::transact_as(
            spammer_eoa,
            id_hps,
            &encode_notify_hfs(spam_charter, t_chr, b"Try Overwrite"),
        )
        .unwrap();
        assert_eq!(r_retry[31], HFS_STATUS_SPAM);

        // 5. On-chain firewall blocks `execute` to `spam_charter` (-29)!
        let ping_cd = [0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, &encode_exec(spam_charter, &ping_cd)),
            Err(-29)
        );

        // 6. Calling `execute` on `invited_charter` (currently PENDING = 1) succeeds AND auto-promotes to WHITELISTED (2)!
        mock::transact_as(owner_eoa, id_hps, &encode_exec(invited_charter, &ping_cd)).unwrap();
        let q_inv = CallEncoder::<64>::new(const { selector("getHfsAssociationStatus(address)") })
            .push_address(&invited_charter);
        assert_eq!(
            mock::transact_as(owner_eoa, id_hps, q_inv.as_slice()).unwrap()[31],
            HFS_STATUS_WHITELISTED
        );

        // 7. Slice query returns all 3 entries with preserved labels & exact states
        let q_slice = CallEncoder::<96>::new(
            const { selector("getHfsAssociationsSlice(uint64,uint64)") },
        )
        .push_u64(0)
        .push_u64(32);
        let raw = mock::transact_as(owner_eoa, id_hps, q_slice.as_slice()).unwrap();
        let total = u64::from_be_bytes(raw[0..8].try_into().unwrap());
        let returned = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        assert_eq!(total, 3);
        assert_eq!(returned, 3);
        assert_eq!(raw[16 + 8], HFS_STATUS_WHITELISTED); // invited_charter promoted to 2!
    }

    #[test]
    fn v3_encryption_keys_registration_and_ownership_rotation_clear() {
        mock::reset();
        let owner_a = [0x61u8; 20];
        let owner_b = [0x62u8; 20];
        let stranger = [0x99u8; 20];
        let id_hps = [0x71u8; 20];
        mock::register_hps_with_code_hash(id_hps, [0xd1; 32], dispatch_calldata);

        let secp_a = [0x44u8; 64];
        let (_sk_a, ed_a) = hps_sdk::vrf::mock_crypto::derive_ed25519_keypair(&[0x12; 32], &id_hps);

        // Initialize directly with encryption keys
        let mut init_cd = Vec::new();
        init_cd.extend_from_slice(&selector(
            "initializeWithKeys(address,string,string,bytes,bytes32)",
        ));
        let mut w_owner = [0u8; 32];
        w_owner[12..32].copy_from_slice(&owner_a);
        init_cd.extend_from_slice(&w_owner);
        // 5 head words = 160 bytes -> handle @ 160 (64B), nick @ 224 (64B), secp @ 288 (96B)
        let mut w_off = [0u8; 32];
        w_off[24..32].copy_from_slice(&160u64.to_be_bytes());
        init_cd.extend_from_slice(&w_off);
        w_off[24..32].copy_from_slice(&224u64.to_be_bytes());
        init_cd.extend_from_slice(&w_off);
        w_off[24..32].copy_from_slice(&288u64.to_be_bytes());
        init_cd.extend_from_slice(&w_off);
        init_cd.extend_from_slice(&ed_a);
        // tail 1: "alice.id" (8B)
        let mut t_len = [0u8; 32];
        t_len[24..32].copy_from_slice(&8u64.to_be_bytes());
        init_cd.extend_from_slice(&t_len);
        let mut t_val = [0u8; 32];
        t_val[0..8].copy_from_slice(b"alice.id");
        init_cd.extend_from_slice(&t_val);
        // tail 2: "Alice" (5B)
        t_len[24..32].copy_from_slice(&5u64.to_be_bytes());
        init_cd.extend_from_slice(&t_len);
        t_val = [0u8; 32];
        t_val[0..5].copy_from_slice(b"Alice");
        init_cd.extend_from_slice(&t_val);
        // tail 3: secp_a (64B)
        t_len[24..32].copy_from_slice(&64u64.to_be_bytes());
        init_cd.extend_from_slice(&t_len);
        init_cd.extend_from_slice(&secp_a);

        mock::transact_as(owner_a, id_hps, &init_cd).unwrap();

        let keys_raw =
            mock::transact_as(stranger, id_hps, &selector("encryptionKeys()")).unwrap();
        assert_eq!(keys_raw.len(), 96);
        assert_eq!(&keys_raw[0..64], &secp_a);
        assert_eq!(&keys_raw[64..96], &ed_a);

        // Stranger cannot overwrite keys
        let mut bad_set = Vec::new();
        bad_set.extend_from_slice(&selector("setEncryptionKeys(bytes,bytes32)"));
        w_off[24..32].copy_from_slice(&64u64.to_be_bytes());
        bad_set.extend_from_slice(&w_off);
        bad_set.extend_from_slice(&ed_a);
        bad_set.extend_from_slice(&t_len);
        bad_set.extend_from_slice(&[0x55u8; 64]);
        assert_eq!(mock::transact_as(stranger, id_hps, &bad_set), Err(-21));

        // Plain `transferOwnership` clears stale encryption keys automatically
        let xfer = CallEncoder::<64>::new(const { selector("transferOwnership(address)") })
            .push_address(&owner_b);
        mock::transact_as(owner_a, id_hps, xfer.as_slice()).unwrap();
        let cleared = mock::transact_as(owner_b, id_hps, &selector("ed25519PubKey()")).unwrap();
        assert_eq!(cleared.as_slice(), &[0u8; 32]);
    }

    fn abi_pad_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&lw);
        out.extend_from_slice(b);
        out.resize(out.len() + (32 - b.len() % 32) % 32, 0);
        out
    }

    fn derive_mask_pair(
        id_addr: &[u8; 20],
        session_id: u64,
        share_idx: usize,
        r_pt: &[u8; 32],
        y_new: &[u8; 32],
        k_shared: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let build = |tag: &[u8; 20]| -> [u8; 32] {
            let mut p = Vec::with_capacity(152);
            p.extend_from_slice(tag);
            p.extend_from_slice(id_addr);
            p.extend_from_slice(&session_id.to_be_bytes());
            p.extend_from_slice(&(share_idx as u64).to_be_bytes());
            p.extend_from_slice(r_pt);
            p.extend_from_slice(y_new);
            p.extend_from_slice(k_shared);
            scalar_from_hash_nonzero(&keccak256(&p))
        };
        (
            build(b"SLX_SHAMIR_MASK_M0V1"),
            build(b"SLX_SHAMIR_MASK_M1V1"),
        )
    }

    fn build_blinded_proof_416(
        id_addr: &[u8; 20],
        session_id: u64,
        share_idx: usize,
        new_owner_eoa: &[u8; 20],
        y_new: &[u8; 32],
        p_0: &[u8; 32],
        p_1: &[u8; 32],
        s_0: &[u8; 32],
        g_0: &[u8; 32],
        s_1: &[u8; 32],
        g_1: &[u8; 32],
        r_seed: u8,
    ) -> [u8; 416] {
        use hps_sdk::bulletproofs::{scalar_add, scalar_mul};
        let r_sc = scalar_from_hash_nonzero(&[r_seed; 32]);
        let zero = [0u8; 32];
        let r_pt =
            ec_elgamal_lincomb(&r_sc, &ED25519_BASEPOINT_BYTES, &zero, &IDENTITY_POINT_BYTES)
                .unwrap();
        let k_pt = ec_elgamal_lincomb(&r_sc, y_new, &zero, &IDENTITY_POINT_BYTES).unwrap();
        let (m0, m1) = derive_mask_pair(id_addr, session_id, share_idx, &r_pt, y_new, &k_pt);
        let mu0 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xA0]));
        let mu1 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xA1]));

        let m_pt0 = ec_elgamal_lincomb(&m0, &ED25519_BASEPOINT_BYTES, &mu0, &BP_H_BLIND_BYTES)
            .unwrap();
        let m_pt1 = ec_elgamal_lincomb(&m1, &ED25519_BASEPOINT_BYTES, &mu1, &BP_H_BLIND_BYTES)
            .unwrap();
        let z0 = scalar_add(s_0, &m0);
        let w0 = scalar_add(g_0, &mu0);
        let z1 = scalar_add(s_1, &m1);
        let w1 = scalar_add(g_1, &mu1);

        let kr = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xB0]));
        let km0 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xB1]));
        let kmu0 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xB2]));
        let km1 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xB3]));
        let kmu1 = scalar_from_hash_nonzero(&keccak256(&[r_seed, 0xB4]));

        let t_r =
            ec_elgamal_lincomb(&kr, &ED25519_BASEPOINT_BYTES, &zero, &IDENTITY_POINT_BYTES)
                .unwrap();
        let t_m0 = ec_elgamal_lincomb(&km0, &ED25519_BASEPOINT_BYTES, &kmu0, &BP_H_BLIND_BYTES)
            .unwrap();
        let t_m1 = ec_elgamal_lincomb(&km1, &ED25519_BASEPOINT_BYTES, &kmu1, &BP_H_BLIND_BYTES)
            .unwrap();

        let mut proof = [0u8; 416];
        proof[0..32].copy_from_slice(&r_pt);
        proof[32..64].copy_from_slice(&m_pt0);
        proof[64..96].copy_from_slice(&z0);
        proof[96..128].copy_from_slice(&w0);
        proof[128..160].copy_from_slice(&m_pt1);
        proof[160..192].copy_from_slice(&z1);
        proof[192..224].copy_from_slice(&w1);

        let mut pre = [0u8; 495];
        pre[0..23].copy_from_slice(b"SLX_SHAMIR_BLIND_POK_V1");
        pre[23..43].copy_from_slice(id_addr);
        pre[43..51].copy_from_slice(&session_id.to_be_bytes());
        pre[51..59].copy_from_slice(&(share_idx as u64).to_be_bytes());
        pre[59..79].copy_from_slice(new_owner_eoa);
        pre[79..111].copy_from_slice(y_new);
        pre[111..143].copy_from_slice(p_0);
        pre[143..175].copy_from_slice(p_1);
        pre[175..399].copy_from_slice(&proof[0..224]);
        pre[399..431].copy_from_slice(&t_r);
        pre[431..463].copy_from_slice(&t_m0);
        pre[463..495].copy_from_slice(&t_m1);

        let c = scalar_from_hash_nonzero(&keccak256(&pre));
        let ur = scalar_add(&kr, &scalar_mul(&c, &r_sc));
        let um0 = scalar_add(&km0, &scalar_mul(&c, &m0));
        let umu0 = scalar_add(&kmu0, &scalar_mul(&c, &mu0));
        let um1 = scalar_add(&km1, &scalar_mul(&c, &m1));
        let umu1 = scalar_add(&kmu1, &scalar_mul(&c, &mu1));

        proof[224..256].copy_from_slice(&c);
        proof[256..288].copy_from_slice(&ur);
        proof[288..320].copy_from_slice(&um0);
        proof[320..352].copy_from_slice(&umu0);
        proof[352..384].copy_from_slice(&um1);
        proof[384..416].copy_from_slice(&umu1);
        proof
    }

    #[test]
    fn v4_multi_device_keychain_slots_and_pedersen_vss_shamir_recovery() {
        use hps_sdk::bulletproofs::{scalar_add, scalar_mul, scalar_sub};
        mock::reset();
        mock::set_block_number(500);

        let alice_id = [0xA1; 20];
        let ward2_id = [0xA2; 20];
        let ward3_id = [0xA3; 20];
        let oracle_id = [0xB0; 20];
        let dummy_hps = [0xD0; 20];

        let dev1_eoa = [0x11; 20];
        let dev2_eoa = [0x12; 20];
        let dev3_new_eoa = [0x13; 20];
        let oracle_admin = [0x20; 20];
        let oracle_slot0_eoa = [0x21; 20];
        let oracle_slot1_eoa = [0x22; 20];
        let friend_eoa = [0x31; 20];

        mock::register_hps(alice_id, dispatch_calldata);
        mock::register_hps(ward2_id, dispatch_calldata);
        mock::register_hps(ward3_id, dispatch_calldata);
        mock::register_hps(oracle_id, dispatch_calldata);
        mock::register_hps(dummy_hps, dummy_target_hps);

        mock::transact_as(dev1_eoa, alice_id, &init_identity_cd(dev1_eoa, b"alice.id")).unwrap();
        mock::transact_as(oracle_admin, oracle_id, &init_identity_cd(oracle_admin, b"oracle.id"))
            .unwrap();

        // 1. Multi-Device Owner Ring: add `dev2_eoa`, verify `dev2_eoa` has full owner authority,
        //    remove `dev1_eoa` (auto-promotes `dev2_eoa` to primary owner), and block removing last owner (-33).
        let add_dev2 = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("addOwnerDevice(address,bytes,string,bytes)"));
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(&dev2_eoa);
            cd.extend_from_slice(&w);
            let t1 = abi_pad_bytes(&[0x72u8; 64]);
            let t2 = abi_pad_bytes(b"Phone Slate");
            let t3 = abi_pad_bytes(&[0xEEu8; 112]);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + t1.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + t1.len() + t2.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&t1);
            cd.extend_from_slice(&t2);
            cd.extend_from_slice(&t3);
            cd
        };
        mock::transact_as(dev1_eoa, alice_id, &add_dev2).unwrap();

        // Secondary device `dev2_eoa` executes HFS calls on behalf of `alice_id`!
        let r_exec = mock::transact_as(
            dev2_eoa,
            alice_id,
            &encode_exec(dummy_hps, &[0xAA, 0xBB, 0xCC, 0xDD]),
        )
        .unwrap();
        assert_eq!(r_exec[31], 42);

        // Remove `dev1_eoa` -> `dev2_eoa` promoted to primary owner; removing `dev2_eoa` now reverts -33!
        let mk_rm_dev = |target: [u8; 20]| -> Vec<u8> {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("removeOwnerDevice(address,bytes,bytes32,bytes)"));
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(&target);
            cd.extend_from_slice(&w);
            let empty_b = abi_pad_bytes(&[]);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&[0u8; 32]);
            o[24..32].copy_from_slice(&((128 + empty_b.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&empty_b);
            cd.extend_from_slice(&empty_b);
            cd
        };
        mock::transact_as(dev2_eoa, alice_id, &mk_rm_dev(dev1_eoa)).unwrap();
        assert_eq!(mock::transact_as(dev2_eoa, alice_id, &mk_rm_dev(dev2_eoa)), Err(-33));

        // 2. Stateless Biometric Oracle registers 2 isolated `GuardianKeychain` slots with `maxCapacity = 1` each!
        let (_, slot0_ed) =
            hps_sdk::vrf::mock_crypto::derive_ed25519_keypair(&[0x51; 32], b"slot0");
        let (_, slot1_ed) =
            hps_sdk::vrf::mock_crypto::derive_ed25519_keypair(&[0x52; 32], b"slot1");
        let slot0_secp = [0x81u8; 64];
        let slot1_secp = [0x82u8; 64];

        let mk_add_slot =
            |op: [u8; 20], ed: [u8; 32], secp: [u8; 64], cap: u64, lbl: &[u8]| -> Vec<u8> {
                let mut cd = Vec::new();
                cd.extend_from_slice(&selector(
                    "addGuardianKeySlot(address,bytes32,bytes,uint64,string)",
                ));
                let mut w = [0u8; 32];
                w[12..32].copy_from_slice(&op);
                cd.extend_from_slice(&w);
                cd.extend_from_slice(&ed);
                let tb1 = abi_pad_bytes(&secp);
                let tb2 = abi_pad_bytes(lbl);
                let mut o = [0u8; 32];
                o[24..32].copy_from_slice(&160u64.to_be_bytes());
                cd.extend_from_slice(&o);
                let mut cw = [0u8; 32];
                cw[24..32].copy_from_slice(&cap.to_be_bytes());
                cd.extend_from_slice(&cw);
                o[24..32].copy_from_slice(&((160 + tb1.len()) as u64).to_be_bytes());
                cd.extend_from_slice(&o);
                cd.extend_from_slice(&tb1);
                cd.extend_from_slice(&tb2);
                cd
            };

        mock::transact_as(
            oracle_admin,
            oracle_id,
            &mk_add_slot(oracle_slot0_eoa, slot0_ed, slot0_secp, 1, b"Enclave #0"),
        )
        .unwrap();
        // Reusing same keypair across slots is rejected (-34)!
        assert_eq!(
            mock::transact_as(
                oracle_admin,
                oracle_id,
                &mk_add_slot(oracle_slot0_eoa, slot0_ed, slot0_secp, 1, b"Dup"),
            ),
            Err(-34)
        );
        mock::transact_as(
            oracle_admin,
            oracle_id,
            &mk_add_slot(oracle_slot1_eoa, slot1_ed, slot1_secp, 1, b"Enclave #1"),
        )
        .unwrap();

        // 3. Split full 256-bit secret (`0xFE..` with MSB > ED25519_L!) into `2-of-3` Pedersen-VSS shares:
        //    Share #0 = Biometric Oracle Slot #0, Share #1 = Trusted Friend EOA, Share #2 = Self Passphrase
        let mut full_secret_32 = [0u8; 32];
        for (i, b) in full_secret_32.iter_mut().enumerate() {
            *b = 0xFEu8.wrapping_sub((i as u8) * 5);
        }
        let mut l0 = [0u8; 32];
        let mut l1 = [0u8; 32];
        l0[0..16].copy_from_slice(&full_secret_32[0..16]);
        l1[0..16].copy_from_slice(&full_secret_32[16..32]);

        let a0_1 = scalar_from_hash_nonzero(&[0x31; 32]);
        let g0_0 = scalar_from_hash_nonzero(&[0x32; 32]);
        let g0_1 = scalar_from_hash_nonzero(&[0x33; 32]);

        let a1_1 = scalar_from_hash_nonzero(&[0x41; 32]);
        let g1_0 = scalar_from_hash_nonzero(&[0x42; 32]);
        let g1_1 = scalar_from_hash_nonzero(&[0x43; 32]);

        let c0_0 =
            ec_elgamal_lincomb(&l0, &ED25519_BASEPOINT_BYTES, &g0_0, &BP_H_BLIND_BYTES).unwrap();
        let c0_1 =
            ec_elgamal_lincomb(&a0_1, &ED25519_BASEPOINT_BYTES, &g0_1, &BP_H_BLIND_BYTES).unwrap();
        let c1_0 =
            ec_elgamal_lincomb(&l1, &ED25519_BASEPOINT_BYTES, &g1_0, &BP_H_BLIND_BYTES).unwrap();
        let c1_1 =
            ec_elgamal_lincomb(&a1_1, &ED25519_BASEPOINT_BYTES, &g1_1, &BP_H_BLIND_BYTES).unwrap();

        let mut vss_commits = Vec::with_capacity(128);
        vss_commits.extend_from_slice(&c0_0);
        vss_commits.extend_from_slice(&c0_1);
        vss_commits.extend_from_slice(&c1_0);
        vss_commits.extend_from_slice(&c1_1);

        let eval_share = |x: u64| -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
            let xs = scalar_from_u64(x);
            let s0 = scalar_add(&l0, &scalar_mul(&a0_1, &xs));
            let gm0 = scalar_add(&g0_0, &scalar_mul(&g0_1, &xs));
            let s1 = scalar_add(&l1, &scalar_mul(&a1_1, &xs));
            let gm1 = scalar_add(&g1_0, &scalar_mul(&g1_1, &xs));
            let p0 =
                ec_elgamal_lincomb(&s0, &ED25519_BASEPOINT_BYTES, &gm0, &BP_H_BLIND_BYTES).unwrap();
            let p1 =
                ec_elgamal_lincomb(&s1, &ED25519_BASEPOINT_BYTES, &gm1, &BP_H_BLIND_BYTES).unwrap();
            (s0, gm0, s1, gm1, p0, p1)
        };
        let sh0 = eval_share(1);
        let _sh1 = eval_share(2);
        let sh2 = eval_share(3);

        let mut shares_packed = vec![3u8];
        let push_sh = |dst: &mut Vec<u8>,
                       kind: u8,
                       gid: [u8; 20],
                       slot: u64,
                       op: [u8; 20],
                       secp: [u8; 64],
                       lbl: &[u8],
                       env: &[u8]| {
            dst.push(kind);
            dst.extend_from_slice(&gid);
            dst.extend_from_slice(&slot.to_be_bytes());
            dst.extend_from_slice(&op);
            dst.extend_from_slice(&secp);
            dst.push(lbl.len() as u8);
            dst.extend_from_slice(lbl);
            dst.extend_from_slice(&(env.len() as u16).to_be_bytes());
            dst.extend_from_slice(env);
        };
        push_sh(
            &mut shares_packed,
            SHARE_KIND_GUARDIAN_SLOT,
            oracle_id,
            0,
            oracle_slot0_eoa,
            slot0_secp,
            b"Biometric Oracle",
            &[0xC0u8; 160],
        );
        push_sh(
            &mut shares_packed,
            SHARE_KIND_DIRECT_EOA,
            [0u8; 20],
            0,
            friend_eoa,
            [0x88u8; 64],
            b"Trusted Friend",
            &[0xC1u8; 160],
        );
        push_sh(
            &mut shares_packed,
            SHARE_KIND_SELF_PASSPHRASE,
            [0u8; 20],
            0,
            [0u8; 20],
            [0u8; 64],
            b"Recovery Passphrase",
            &[0xC2u8; 160],
        );

        let cfg_cd = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector(
                "configureShamirRecovery(uint64,uint64,bytes,bytes)",
            ));
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&2u64.to_be_bytes()); // threshold = 2
            cd.extend_from_slice(&w);
            w[24..32].copy_from_slice(&5u64.to_be_bytes()); // timelock = 5 blocks
            cd.extend_from_slice(&w);
            let tb1 = abi_pad_bytes(&vss_commits);
            let tb2 = abi_pad_bytes(&shares_packed);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            o[24..32].copy_from_slice(&((128 + tb1.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&tb1);
            cd.extend_from_slice(&tb2);
            cd
        };
        mock::transact_as(dev2_eoa, alice_id, &cfg_cd).unwrap();

        // Verify Slot #0 auto-sealed (`maxCapacity = 1`), so `ward2_id` rolls over to Slot #1,
        // and `ward3_id` hits `-35` (`ERR_KEYCHAIN_CAPACITY_EXHAUSTED`)!
        let alloc_w2 = CallEncoder::<68>::new(const { selector("allocateGuardianSlot(address)") })
            .push_address(&ward2_id);
        let d2 = mock::transact_as(oracle_admin, oracle_id, alloc_w2.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(d2[0..8].try_into().unwrap()), 1); // rolled over to Slot #1!
        let alloc_w3 = CallEncoder::<68>::new(const { selector("allocateGuardianSlot(address)") })
            .push_address(&ward3_id);
        assert_eq!(
            mock::transact_as(oracle_admin, oracle_id, alloc_w3.as_slice()),
            Err(-35)
        );

        // 4. First recovery attempt onto `dev3_new_eoa` -> owner `dev2_eoa` vetoes during timelock!
        let (y_new_sc, y_new_pub) =
            hps_sdk::vrf::mock_crypto::derive_ed25519_keypair(&[0x99; 32], &alice_id);
        let init_rec_cd = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("initiateRecovery(address,bytes,bytes32,string)"));
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(&dev3_new_eoa);
            cd.extend_from_slice(&w);
            let tb1 = abi_pad_bytes(&[0x73u8; 64]);
            let tb2 = abi_pad_bytes(b"New Laptop");
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&128u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&y_new_pub);
            o[24..32].copy_from_slice(&((128 + tb1.len()) as u64).to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&tb1);
            cd.extend_from_slice(&tb2);
            cd
        };
        let s1_raw = mock::transact_as(dev3_new_eoa, alice_id, &init_rec_cd).unwrap();
        assert_eq!(s1_raw[31], 1);
        mock::transact_as(dev2_eoa, alice_id, &selector("cancelRecovery()")).unwrap();

        // 5. Legitimate recovery session #2: Biometric Oracle (idx 0) + Passphrase (idx 2) submit blinded proofs!
        let s2_raw = mock::transact_as(dev3_new_eoa, alice_id, &init_rec_cd).unwrap();
        assert_eq!(s2_raw[31], 2);

        let mk_sub_cd = |sess_id: u64, idx: u64, proof: &[u8; 416]| -> Vec<u8> {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("submitRecoveryShare(uint64,uint64,bytes)"));
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&sess_id.to_be_bytes());
            cd.extend_from_slice(&w);
            w[24..32].copy_from_slice(&idx.to_be_bytes());
            cd.extend_from_slice(&w);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&96u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&abi_pad_bytes(proof));
            cd
        };

        let mut forged_proof = build_blinded_proof_416(
            &alice_id,
            2,
            0,
            &dev3_new_eoa,
            &y_new_pub,
            &sh0.4,
            &sh0.5,
            &sh0.0,
            &sh0.1,
            &sh0.2,
            &sh0.3,
            0x11,
        );
        forged_proof[64] ^= 0x01; // corrupt blinded share `z_0`
        assert_eq!(
            mock::transact_as(oracle_slot0_eoa, alice_id, &mk_sub_cd(2, 0, &forged_proof)),
            Err(-41)
        );

        let valid_proof0 = build_blinded_proof_416(
            &alice_id,
            2,
            0,
            &dev3_new_eoa,
            &y_new_pub,
            &sh0.4,
            &sh0.5,
            &sh0.0,
            &sh0.1,
            &sh0.2,
            &sh0.3,
            0x11,
        );
        mock::transact_as(oracle_slot0_eoa, alice_id, &mk_sub_cd(2, 0, &valid_proof0)).unwrap();

        let valid_proof2 = build_blinded_proof_416(
            &alice_id,
            2,
            2,
            &dev3_new_eoa,
            &y_new_pub,
            &sh2.4,
            &sh2.5,
            &sh2.0,
            &sh2.1,
            &sh2.2,
            &sh2.3,
            0x22,
        );
        mock::transact_as(dev3_new_eoa, alice_id, &mk_sub_cd(2, 2, &valid_proof2)).unwrap();

        // Unblind & Lagrange-interpolate `full_secret_32` in `Device_New` local RAM using `y_new_sc`!
        // For x_0 = 1 and x_2 = 3: lambda_0(0) = 3 / (3 - 1) = 3 * inv(2), lambda_2(0) = 1 / (1 - 3) = -inv(2)
        let y_bytes = y_new_sc.to_bytes();
        let unblind = |idx: usize, prf: &[u8; 416]| -> ([u8; 32], [u8; 32]) {
            let mut r_pt = [0u8; 32];
            r_pt.copy_from_slice(&prf[0..32]);
            let k_pt =
                ec_elgamal_lincomb(&y_bytes, &r_pt, &[0u8; 32], &IDENTITY_POINT_BYTES).unwrap();
            let (m0, m1) = derive_mask_pair(&alice_id, 2, idx, &r_pt, &y_new_pub, &k_pt);
            let mut z0 = [0u8; 32];
            let mut z1 = [0u8; 32];
            z0.copy_from_slice(&prf[64..96]);
            z1.copy_from_slice(&prf[160..192]);
            (scalar_sub(&z0, &m0), scalar_sub(&z1, &m1))
        };
        let (u0_0, u0_1) = unblind(0, &valid_proof0);
        let (u2_0, u2_1) = unblind(2, &valid_proof2);
        assert_eq!(u0_0, sh0.0);
        assert_eq!(u2_0, sh2.0);

        // `inv(2) mod ℓ = ((ℓ - 1) >> 1) + 1`
        let inv2 = {
            let mut m1 = hps_sdk::vrf::SCALAR_MINUS_ONE_BYTES;
            for i in 0..32 {
                let next_bit = if i + 1 < 32 { (m1[i + 1] & 1) << 7 } else { 0 };
                m1[i] = (m1[i] >> 1) | next_bit;
            }
            scalar_add(&m1, &SCALAR_ONE_BYTES)
        };
        let lam0 = scalar_mul(&scalar_from_u64(3), &inv2); // 3/2
        let lam2 = scalar_neg(&inv2); // -1/2
        let rec_l0 = scalar_add(&scalar_mul(&lam0, &u0_0), &scalar_mul(&lam2, &u2_0));
        let rec_l1 = scalar_add(&scalar_mul(&lam0, &u0_1), &scalar_mul(&lam2, &u2_1));
        let mut recovered_32 = [0u8; 32];
        recovered_32[0..16].copy_from_slice(&rec_l0[0..16]);
        recovered_32[16..32].copy_from_slice(&rec_l1[0..16]);
        assert_eq!(recovered_32, full_secret_32);

        // Finalizing before timelock (block 500 < 505) reverts `-39`!
        let fin_cd = {
            let mut cd = Vec::new();
            cd.extend_from_slice(&selector("finalizeRecovery(uint64,bool,bytes)"));
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&2u64.to_be_bytes());
            cd.extend_from_slice(&w);
            w = [0u8; 32];
            w[31] = 1; // revokeExistingDevices = true
            cd.extend_from_slice(&w);
            let mut o = [0u8; 32];
            o[24..32].copy_from_slice(&96u64.to_be_bytes());
            cd.extend_from_slice(&o);
            cd.extend_from_slice(&abi_pad_bytes(&[0xFAu8; 112]));
            cd
        };
        assert_eq!(mock::transact_as(dev3_new_eoa, alice_id, &fin_cd), Err(-39));

        // Advance past timelock -> `finalizeRecovery` succeeds, revokes `dev2_eoa`, promotes `dev3_new_eoa`!
        mock::set_block_number(505);
        mock::transact_as(dev3_new_eoa, alice_id, &fin_cd).unwrap();

        let own_after = mock::transact_as(dev3_new_eoa, alice_id, &selector("owner()")).unwrap();
        assert_eq!(&own_after[12..32], &dev3_new_eoa);
        assert_eq!(
            mock::transact_as(
                dev2_eoa,
                alice_id,
                &encode_exec(dummy_hps, &[0x11, 0x22, 0x33, 0x44])
            ),
            Err(-21)
        );
    }
}
