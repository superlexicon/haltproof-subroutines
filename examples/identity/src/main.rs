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
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::storage::KeyBuilder;
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

/// Validity states for subroutines in this Identity's Associated HFS Register:
/// - `0` (`UNLISTED`): Not recorded in this Identity's register.
/// - `1` (`PENDING`): Inbound / unverified association awaiting owner review (shown in Spam/Unverified).
/// - `2` (`WHITELISTED`): Validly associated & whitelisted by owner/delegate.
/// - `3` (`SPAM`): Explicitly rejected / blocked as spam; outbound calls to this HFS revert (`-29`).
pub const HFS_STATUS_UNLISTED: u8 = 0;
pub const HFS_STATUS_PENDING: u8 = 1;
pub const HFS_STATUS_WHITELISTED: u8 = 2;
pub const HFS_STATUS_SPAM: u8 = 3;

pub const IDENTITY_ABI_VERSION: u64 = 3;
const MAX_HFS_LABEL_LEN: usize = 64;
const FIXED_HFS_REC_HDR: usize = 83; // [status:1][addr:20][type_id:32][blk:8][actor:20][lbl_len:2]
const MAX_HFS_REC_BYTES: usize = FIXED_HFS_REC_HDR + MAX_HFS_LABEL_LEN;
const MAX_HFS_SLICE_LIMIT: u64 = 64;
const HFS_SLICE_OUT_CAP: usize = 16 + (MAX_HFS_SLICE_LIMIT as usize) * (8 + MAX_HFS_REC_BYTES);
const MAX_TOTAL_HFS_ENTRIES: u64 = 512;
const MAX_BATCH_ENTRIES: usize = 32;

const KEY_INIT: &[u8] = b"id:init";
const KEY_OWNER: &[u8] = b"id:owner";
const KEY_HANDLE: &[u8] = b"id:handle";
const KEY_NICKNAME: &[u8] = b"id:nick";
const KEY_HFS_COUNT: &[u8] = b"id:hfs:cnt";
const KEY_SECP_PUB64: &[u8] = b"id:enc:secp64";
const KEY_ED_PUB32: &[u8] = b"id:enc:ed32";

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

/// Outbound execution firewall + automatic `PENDING -> WHITELISTED` promotion when an authorized
/// Identity owner/delegate actively invokes a subroutine.
fn guard_and_promote_outbound_hfs(target: &[u8; 20]) -> Result<(), i32> {
    let st = get_hfs_status_ns(None, target);
    if st == HFS_STATUS_SPAM {
        return Err(-29); // Blocked by Identity's on-chain Spam HFS firewall!
    }
    if st == HFS_STATUS_PENDING && has_deployed_wasm(target) {
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
    Ok(())
}

fn check_owner(actor: &[u8; 20]) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-20);
    }
    let owner = storage::get_address(KEY_OWNER).ok_or(-20)?;
    if *actor == owner {
        Ok(())
    } else {
        Err(-21)
    }
}

fn is_actor_authorized(actor: &[u8; 20]) -> bool {
    if storage::get_u64(KEY_INIT) != 1 {
        return false;
    }
    if let Some(owner) = storage::get_address(KEY_OWNER) {
        if *actor == owner {
            return true;
        }
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

    events::emit(&[IDENTITY_INITIALIZED, addr_topic(&owner)], handle_str);
    events::emit(&[NICKNAME_UPDATED, addr_topic(&owner)], nick_str);
    Ok(())
}

fn store_validated_encryption_keys(
    owner: &[u8; 20],
    secp_pub64: &[u8],
    ed_pub32: &[u8; 32],
) -> Result<(), i32> {
    if secp_pub64.len() != 64
        || secp_pub64.iter().all(|&b| b == 0)
        || *ed_pub32 == [0u8; 32]
        || *ed_pub32 == hps_sdk::vrf::IDENTITY_POINT_BYTES
    {
        return Err(-23);
    }
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
    storage::set_address(KEY_OWNER, &new_owner);
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
    storage::set_address(KEY_OWNER, &new_owner);
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
    events::emit(&[EXECUTED_CALL, addr_topic(&target)], &sel);
    ret::write(out);
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
}
