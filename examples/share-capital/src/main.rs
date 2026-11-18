//! Share Capital **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Operational equity & share-capital administration module pinned to a single `IdentityRegistry`
//! and a single `CorporateCharter` (`associatedCharter()`):
//! 1. **Active-Charter Guard**: All state-changing operations require `CorporateCharter.state() ==
//!    CHARTER_STATE_ACTIVE` (`ERR_CHARTER_NOT_ACTIVE = -91` while pending ratification).
//! 2. **Share-Backed Futures Underwriting**: Allows a Shareholder Super-Majority resolution
//!    (`authorizeFuturesUnderwriting`) to authorize a predetermined percentage (`underwritePct`) of
//!    company-wide converted common shares (queried live from `CorporateCharter.convertedCommonTotals`)
//!    to be underwritten as a single class of futures contracts (`underwriteFutures` /
//!    `closeUnderwrittenFutures`).
//! 3. **Restricted 3-Step Share-Transfer Call Auction & Segregated Escrow**: Coordinates Step 1 /
//!    Step 2 / Step 3 share-transfer call auctions (`placeBuyOrder`, `cancelBuyOrder`,
//!    `placeSellOrder`, `settleShareTransferAuction`, `disburseAuctionCash`) using a dedicated
//!    **`shareEscrowAccount`** strictly segregated from company operating revenue.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    query_charter_function_auth, require_active_charter, require_valid_identity,
    validate_charter_capital_auth, verify_and_consume_auth, ActionHasher, AuctionBook,
    ACTION_AUTHORIZE_FUTURES_UNDERWRITING, ACTION_SET_SHARE_ESCROW, ERR_CHARTER_MISMATCH,
    ERR_FUTURES_CAP_EXCEEDED, ERR_INVALID_FUTURES_CONFIG, ERR_POLICY_INVALID,
    MAX_ENCODED_AUCTION_BOOK_BYTES, POLICY_BOARD_RESOLUTION, POLICY_SHAREHOLDER_SUPERMAJORITY,
    POLICY_SUPER_GOVERNANCE,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const SHARE_CAPITAL_INITIALIZED: [u8; 32] =
    event_topic("ShareCapitalInitialized(address,address,address,address)");
const SHARE_ESCROW_SET: [u8; 32] = event_topic("ShareEscrowAccountSet(address,address,address)");
const FUTURES_UNDERWRITING_AUTHORIZED: [u8; 32] =
    event_topic("FuturesUnderwritingAuthorized(address,uint64,uint64,address)");
const FUTURES_UNDERWRITTEN: [u8; 32] =
    event_topic("FuturesUnderwritten(address,address,uint64,uint64,uint64)");
const FUTURES_CLOSED: [u8; 32] =
    event_topic("FuturesClosed(address,address,uint64,uint64)");
const AUCTION_BUY_ORDER_CLEARED: [u8; 32] =
    event_topic("AuctionBuyOrderCleared(address,address,uint64)");
const AUCTION_BUY_ORDER_REFUNDED: [u8; 32] =
    event_topic("AuctionBuyOrderRefunded(address,address,uint64)");
const AUCTION_CASH_SETTLED: [u8; 32] =
    event_topic("AuctionCashSettled(address,address,uint64,bool)");

const SEL_SET_SHARE_ESCROW: [u8; 4] = selector("setShareEscrowAccount(address,address,address)");
const SEL_AUTHORIZE_FUTURES: [u8; 4] =
    selector("authorizeFuturesUnderwriting(address,uint64,address)");

const KEY_INIT: &[u8] = b"shc:init";
const KEY_REGISTRY: &[u8] = b"shc:reg";
const KEY_CHARTER: &[u8] = b"shc:chr";
const KEY_INITIALIZER: &[u8] = b"shc:init_by";
const KEY_BANK_LEDGER: &[u8] = b"shc:bank_led";
const KEY_SHARE_ESCROW_ACCT: &[u8] = b"shc:escrow_acct";
const KEY_FUTURES_LEDGER: &[u8] = b"shc:fut_led";
const KEY_FUTURES_PCT: &[u8] = b"shc:fut_pct";

hps_entry! {
    "initialize(address,address,address,address)"                               => handle_initialize,
    "setShareEscrowAccount(address,address,address)"                            => handle_set_share_escrow_account,
    "associatedCharter()"                                                       => handle_associated_charter,
    "associatedConstitution()"                                                  => handle_associated_charter,
    "identityRegistry()"                                                        => handle_identity_registry,
    "bankLedger()"                                                              => handle_bank_ledger,
    "shareEscrowAccount()"                                                      => handle_share_escrow_account,
    "treasuryRecipient()"                                                       => handle_treasury_recipient,
    "authorizeFuturesUnderwriting(address,uint64,address)"                      => handle_authorize_futures_underwriting,
    "underwriteFutures(uint64)"                                                 => handle_underwrite_futures,
    "closeUnderwrittenFutures(uint64)"                                          => handle_close_underwritten_futures,
    "futuresLedger()"                                                           => handle_futures_ledger,
    "futuresUnderwritePct()"                                                    => handle_futures_underwrite_pct,
    "futuresUnderwrittenBy(address)"                                            => handle_futures_underwritten_by,
    "futuresAllowanceOf(address)"                                               => handle_futures_allowance_of,
    "placeBuyOrder(address,uint64,uint64)"                                      => handle_place_buy_order,
    "cancelBuyOrder(address,uint64)"                                            => handle_cancel_buy_order,
    "placeSellOrder(address,uint64,uint64)"                                     => handle_place_sell_order,
    "settleShareTransferAuction(address,address)"                               => handle_settle_share_transfer_auction,
    "settleShareIssuance(address,address)"                                      => handle_settle_share_issuance,
    "refundFailedAuction(address)"                                              => handle_refund_failed_auction,
    "hasEscrowedAuction(address)"                                               => handle_has_escrowed_auction,
    "escrowedCashOf(address)"                                                   => handle_escrowed_cash_of,
    "disburseAuctionCash(address,address,uint64,bool)"                          => handle_disburse_auction_cash,
    "hashSetShareEscrowAccount(address,address)"                                => handle_hash_set_share_escrow,
    "hashAuthorizeFuturesUnderwriting(address,uint64)"                          => handle_hash_authorize_futures,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn auc_escrow_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"aesc:").push(auth_obj)
}

fn auc_escrow_active_key(auth_obj: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"aact:").push(auth_obj)
}

fn futures_underwritten_key(futures_ledger: &[u8; 20], shareholder: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new()
        .push(b"fuw:")
        .push(futures_ledger)
        .push(shareholder)
}

fn compute_set_share_escrow_hash(bank_ledger: &[u8; 20], escrow_acct: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_SHARE_ESCROW)
        .push_address(bank_ledger)
        .push_address(escrow_acct)
        .finish()
}

fn compute_authorize_futures_hash(futures_ledger: &[u8; 20], underwrite_pct: u64) -> [u8; 32] {
    ActionHasher::<160>::new(
        &context::self_address(),
        &ACTION_AUTHORIZE_FUTURES_UNDERWRITING,
    )
    .push_address(futures_ledger)
    .push_u64(underwrite_pct)
    .finish()
}

/// Apply `pct` (`1..=100` whole percent or `101..=10_000` basis points) to `converted_common_shares`.
fn apply_futures_pct(converted_common_shares: u64, pct: u64) -> u64 {
    if pct == 0 || converted_common_shares == 0 {
        return 0;
    }
    let denom = if pct <= 100 { 100u128 } else { 10_000u128 };
    (((converted_common_shares as u128) * (pct as u128)) / denom) as u64
}

fn query_converted_common_totals(charter: &[u8; 20], shareholder: &[u8; 20]) -> Result<(u64, u64), i32> {
    let cd = CallEncoder::<64>::new(const { selector("convertedCommonTotals(address)") })
        .push_address(shareholder);
    let raw = call::call_raw(charter, cd.as_slice())?;
    if raw.len() < 64 {
        return Err(-65);
    }
    let mut w_holder = [0u8; 8];
    let mut w_total = [0u8; 8];
    w_holder.copy_from_slice(&raw[24..32]);
    w_total.copy_from_slice(&raw[56..64]);
    Ok((u64::from_be_bytes(w_holder), u64::from_be_bytes(w_total)))
}

fn ensure_active_and_valid_caller() -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-57)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(-57)?;
    require_active_charter(&charter)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, charter, caller))
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-58);
    }
    let registry = args.address(0).ok_or(-3)?;
    let charter = args.address(1).ok_or(-3)?;
    let bank_ledger = args.address(2).ok_or(-3)?;
    let share_escrow_acct = args.address(3).ok_or(-3)?;

    if registry == [0u8; 20] || charter == [0u8; 20] {
        return Err(ERR_CHARTER_MISMATCH);
    }
    if (bank_ledger == [0u8; 20]) != (share_escrow_acct == [0u8; 20]) {
        return Err(-59);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    if share_escrow_acct != [0u8; 20] {
        require_valid_identity(&registry, &share_escrow_acct)?;
        storage::set_address(KEY_BANK_LEDGER, &bank_ledger);
        storage::set_address(KEY_SHARE_ESCROW_ACCT, &share_escrow_acct);
    }

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_CHARTER, &charter);
    storage::set_address(KEY_INITIALIZER, &caller);

    events::emit(
        &[
            SHARE_CAPITAL_INITIALIZED,
            addr_topic(&charter),
            addr_topic(&bank_ledger),
            addr_topic(&share_escrow_acct),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_set_share_escrow_account(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let share_escrow_acct = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    if bank_ledger == [0u8; 20] || share_escrow_acct == [0u8; 20] {
        return Err(-59);
    }
    require_valid_identity(&registry, &share_escrow_acct)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, &SEL_SET_SHARE_ESCROW);
    if auth_obj == [0u8; 20]
        && storage::get_address(KEY_SHARE_ESCROW_ACCT).is_none()
        && explicit_pol.is_none()
    {
        let is_dir_cd = CallEncoder::<64>::new(const { selector("isDirector(address)") })
            .push_address(&caller);
        let is_dir = matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true));
        let init_by = storage::get_address(KEY_INITIALIZER).unwrap_or([0u8; 20]);
        if !is_dir && caller != init_by {
            return Err(-61);
        }
    } else {
        let req_pol = explicit_pol.unwrap_or(POLICY_BOARD_RESOLUTION);
        let action_hash = compute_set_share_escrow_hash(&bank_ledger, &share_escrow_acct);
        verify_and_consume_auth(&registry, &auth_obj, &charter, &req_pol, &action_hash, &caller)?;
    }

    storage::set_address(KEY_BANK_LEDGER, &bank_ledger);
    storage::set_address(KEY_SHARE_ESCROW_ACCT, &share_escrow_acct);

    events::emit(
        &[
            SHARE_ESCROW_SET,
            addr_topic(&bank_ledger),
            addr_topic(&share_escrow_acct),
            addr_topic(&auth_obj),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_associated_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_bank_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_BANK_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_share_escrow_account(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_SHARE_ESCROW_ACCT).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_treasury_recipient(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_INITIALIZER).unwrap_or([0u8; 20]));
    Ok(())
}

/// Authorize `underwritePct` (`1..=100` whole `%` or `101..=10_000` bps) of company-wide converted
/// common shares to be underwritten as a single class of futures contracts in `futuresLedger`.
fn handle_authorize_futures_underwriting(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let futures_ledger = args.address(0).ok_or(-3)?;
    let underwrite_pct = args.u64(1).ok_or(-3)?;
    let super_auth = args.address(2).ok_or(-3)?;

    if futures_ledger == [0u8; 20] || underwrite_pct == 0 || underwrite_pct > 10_000 {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let assoc_cd = CallEncoder::<16>::new(const { selector("associatedCharter()") });
    let Ok(raw_assoc) = call::call_raw(&futures_ledger, assoc_cd.as_slice()) else {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    };
    if raw_assoc.len() < 32 || raw_assoc[12..32] != charter {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let me = context::self_address();
    let cfg_pol = query_charter_function_auth(&charter, &me, &SEL_AUTHORIZE_FUTURES)
        .unwrap_or(POLICY_SUPER_GOVERNANCE);
    let expected_pol = if cfg_pol == POLICY_SUPER_GOVERNANCE {
        let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
        if let Ok(raw_pid) = call::call_raw(&super_auth, pid_cd.as_slice()) {
            if raw_pid.len() >= 32 && raw_pid[..32] == POLICY_SHAREHOLDER_SUPERMAJORITY {
                POLICY_SHAREHOLDER_SUPERMAJORITY
            } else {
                cfg_pol
            }
        } else {
            cfg_pol
        }
    } else {
        cfg_pol
    };

    let action_hash = compute_authorize_futures_hash(&futures_ledger, underwrite_pct);
    verify_and_consume_auth(
        &registry,
        &super_auth,
        &charter,
        &expected_pol,
        &action_hash,
        &caller,
    )?;

    storage::set_address(KEY_FUTURES_LEDGER, &futures_ledger);
    storage::set_u64(KEY_FUTURES_PCT, underwrite_pct);

    let (_holder_common, total_common) = query_converted_common_totals(&charter, &[0u8; 20])?;
    let company_max_cap = apply_futures_pct(total_common, underwrite_pct);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&underwrite_pct.to_be_bytes());
    ev[8..16].copy_from_slice(&company_max_cap.to_be_bytes());
    events::emit(
        &[
            FUTURES_UNDERWRITING_AUTHORIZED,
            addr_topic(&futures_ledger),
            addr_topic(&super_auth),
        ],
        &ev,
    );
    ret::write_u64_word(company_max_cap);
    Ok(())
}

/// Underwrite (mint) `amount` units of futures contracts on `futuresLedger()`, bounded by
/// `underwritePct` of the calling shareholder's converted common shares in `CorporateCharter`.
fn handle_underwrite_futures(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, caller) = ensure_active_and_valid_caller()?;
    let amount = args.u64(0).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    let futures_ledger =
        storage::get_address(KEY_FUTURES_LEDGER).ok_or(ERR_INVALID_FUTURES_CONFIG)?;
    let pct = storage::get_u64(KEY_FUTURES_PCT);
    if pct == 0 {
        return Err(ERR_INVALID_FUTURES_CONFIG);
    }

    let (holder_common, total_common) = query_converted_common_totals(&charter, &caller)?;
    let holder_max_allowance = apply_futures_pct(holder_common, pct);
    let company_max_cap = apply_futures_pct(total_common, pct);

    let uk = futures_underwritten_key(&futures_ledger, &caller);
    let already_underwritten = storage::get_u64(uk.as_slice());
    let new_underwritten = already_underwritten
        .checked_add(amount)
        .ok_or(ERR_FUTURES_CAP_EXCEEDED)?;
    if new_underwritten > holder_max_allowance {
        return Err(ERR_FUTURES_CAP_EXCEEDED);
    }

    let sup_cd = CallEncoder::<16>::new(const { selector("totalOutstanding()") });
    let cur_futures_supply = call::call_u64(&futures_ledger, sup_cd.as_slice()).unwrap_or(0);
    if cur_futures_supply.saturating_add(amount) > company_max_cap {
        return Err(ERR_FUTURES_CAP_EXCEEDED);
    }

    storage::set_u64(uk.as_slice(), new_underwritten);

    let issue_cd =
        CallEncoder::<96>::new(const { selector("charterModuleIssue(address,uint64)") })
            .push_address(&caller)
            .push_u64(amount);
    let _new_bal = call::call_u64(&futures_ledger, issue_cd.as_slice())?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&new_underwritten.to_be_bytes());
    ev[16..24].copy_from_slice(&holder_max_allowance.to_be_bytes());
    events::emit(
        &[
            FUTURES_UNDERWRITTEN,
            addr_topic(&futures_ledger),
            addr_topic(&caller),
        ],
        &ev,
    );
    ret::write_u64_word(new_underwritten);
    Ok(())
}

/// Close/burn `amount` units of previously underwritten futures contracts from the caller's
/// balance in `futuresLedger()`, restoring `amount` of their underwriting allowance.
fn handle_close_underwritten_futures(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, caller) = ensure_active_and_valid_caller()?;
    let amount = args.u64(0).ok_or(-3)?;
    if amount == 0 {
        return Err(-14);
    }

    let futures_ledger =
        storage::get_address(KEY_FUTURES_LEDGER).ok_or(ERR_INVALID_FUTURES_CONFIG)?;
    let uk = futures_underwritten_key(&futures_ledger, &caller);
    let already_underwritten = storage::get_u64(uk.as_slice());
    if already_underwritten < amount {
        return Err(-16);
    }

    let cancel_cd =
        CallEncoder::<96>::new(const { selector("charterModuleCancel(address,uint64)") })
            .push_address(&caller)
            .push_u64(amount);
    let _new_bal = call::call_u64(&futures_ledger, cancel_cd.as_slice())?;

    let rem_underwritten = already_underwritten - amount;
    storage::set_u64(uk.as_slice(), rem_underwritten);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[8..16].copy_from_slice(&rem_underwritten.to_be_bytes());
    events::emit(
        &[
            FUTURES_CLOSED,
            addr_topic(&futures_ledger),
            addr_topic(&caller),
        ],
        &ev,
    );
    ret::write_u64_word(rem_underwritten);
    Ok(())
}

fn handle_futures_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_FUTURES_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_futures_underwrite_pct(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_FUTURES_PCT));
    Ok(())
}

fn handle_futures_underwritten_by(args: &CalldataReader) -> Result<(), i32> {
    let shareholder = args.address(0).ok_or(-3)?;
    let Some(futures_ledger) = storage::get_address(KEY_FUTURES_LEDGER) else {
        ret::write_u64_word(0);
        return Ok(());
    };
    let uk = futures_underwritten_key(&futures_ledger, &shareholder);
    ret::write_u64_word(storage::get_u64(uk.as_slice()));
    Ok(())
}

/// Returns `(uint64 convertedCommonShares, uint64 maxFuturesAllowance, uint64 alreadyUnderwritten,
/// uint64 remainingAllowance, uint64 companyMaxFuturesCap)` for `shareholder`.
fn handle_futures_allowance_of(args: &CalldataReader) -> Result<(), i32> {
    let shareholder = args.address(0).ok_or(-3)?;
    let charter = storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]);
    let pct = storage::get_u64(KEY_FUTURES_PCT);
    let (holder_common, total_common) = if charter == [0u8; 20] {
        (0, 0)
    } else {
        query_converted_common_totals(&charter, &shareholder).unwrap_or((0, 0))
    };
    let max_allowance = apply_futures_pct(holder_common, pct);
    let company_cap = apply_futures_pct(total_common, pct);
    let already_underwritten =
        if let Some(futures_ledger) = storage::get_address(KEY_FUTURES_LEDGER) {
            storage::get_u64(futures_underwritten_key(&futures_ledger, &shareholder).as_slice())
        } else {
            0
        };
    let remaining = max_allowance.saturating_sub(already_underwritten);

    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&holder_common.to_be_bytes());
    out[56..64].copy_from_slice(&max_allowance.to_be_bytes());
    out[88..96].copy_from_slice(&already_underwritten.to_be_bytes());
    out[120..128].copy_from_slice(&remaining.to_be_bytes());
    out[152..160].copy_from_slice(&company_cap.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Place a buy order (`price`, `quantity`) in a 3-step share transfer auction `Authorization` HPS
/// (`authObj`), escrowing `price * quantity` into `ShareCapital`'s dedicated **`shareEscrowAccount`**
/// (segregated from corporate operating revenue).
fn handle_place_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, buyer) = ensure_active_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    if price == 0 || quantity == 0 {
        return Err(-14);
    }
    let escrow_cash = price.checked_mul(quantity).ok_or(-15)?;

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
    let escrow_acct = storage::get_address(KEY_SHARE_ESCROW_ACCT).ok_or(-63)?;

    let clear_cd = CallEncoder::<128>::new(const {
        selector("charterModuleClearTransfer(address,address,uint64)")
    })
    .push_address(&buyer)
    .push_address(&escrow_acct)
    .push_u64(escrow_cash);
    let cleared = call::call_bool(&bank_ledger, clear_cd.as_slice())?;
    if !cleared {
        return Err(-16);
    }

    let order_cd =
        CallEncoder::<128>::new(const { selector("placeBuyOrderFor(address,uint64,uint64)") })
            .push_address(&buyer)
            .push_u64(price)
            .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, order_cd.as_slice())?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    storage::set_u64(ek.as_slice(), cur_escrow.saturating_add(escrow_cash));
    storage::set_u64(auc_escrow_active_key(&auth_obj).as_slice(), 1);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&price.to_be_bytes());
    ev[8..16].copy_from_slice(&quantity.to_be_bytes());
    ev[16..24].copy_from_slice(&escrow_cash.to_be_bytes());
    events::emit(
        &[
            AUCTION_BUY_ORDER_CLEARED,
            addr_topic(&auth_obj),
            addr_topic(&buyer),
        ],
        &ev,
    );

    ret::write_u64_word(order_idx);
    Ok(())
}

/// Cancel a previously placed buy order (`orderIndex`) in the same auction step and refund
/// `price * quantity` from **`shareEscrowAccount`** back to `buyer`.
fn handle_cancel_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, buyer) = ensure_active_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let order_index = args.u64(1).ok_or(-3)?;

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
    let escrow_acct = storage::get_address(KEY_SHARE_ESCROW_ACCT).ok_or(-63)?;

    let cancel_cd = CallEncoder::<96>::new(const { selector("cancelBuyOrderFor(address,uint64)") })
        .push_address(&buyer)
        .push_u64(order_index);
    let raw = call::call_raw(&auth_obj, cancel_cd.as_slice())?;
    if raw.len() < 64 {
        return Err(-65);
    }
    let mut w_price = [0u8; 8];
    w_price.copy_from_slice(&raw[24..32]);
    let mut w_qty = [0u8; 8];
    w_qty.copy_from_slice(&raw[56..64]);
    let price = u64::from_be_bytes(w_price);
    let quantity = u64::from_be_bytes(w_qty);
    let refund_cash = price.checked_mul(quantity).ok_or(-15)?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    if cur_escrow < refund_cash {
        return Err(-16);
    }
    storage::set_u64(ek.as_slice(), cur_escrow - refund_cash);

    let refund_cd = CallEncoder::<128>::new(const {
        selector("charterModuleClearTransfer(address,address,uint64)")
    })
    .push_address(&escrow_acct)
    .push_address(&buyer)
    .push_u64(refund_cash);
    let refunded = call::call_bool(&bank_ledger, refund_cd.as_slice())?;
    if !refunded {
        return Err(-16);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&order_index.to_be_bytes());
    ev[8..16].copy_from_slice(&refund_cash.to_be_bytes());
    events::emit(
        &[
            AUCTION_BUY_ORDER_REFUNDED,
            addr_topic(&auth_obj),
            addr_topic(&buyer),
        ],
        &ev,
    );

    ret::write_u64_word(refund_cash);
    Ok(())
}

fn handle_place_sell_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, seller) = ensure_active_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;

    let order_cd =
        CallEncoder::<128>::new(const { selector("placeSellOrderFor(address,uint64,uint64)") })
            .push_address(&seller)
            .push_u64(price)
            .push_u64(quantity);
    let order_idx = call::call_u64(&auth_obj, order_cd.as_slice())?;
    ret::write_u64_word(order_idx);
    Ok(())
}

fn handle_settle_share_transfer_auction(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, _caller) = ensure_active_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    validate_charter_capital_auth(&charter, &auth_obj)?;

    let settle_cd = CallEncoder::<64>::new(const { selector("settleTransferAuction(address)") })
        .push_address(&auth_obj);
    let out = call::call_raw(&share_ledger, settle_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_settle_share_issuance(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, _caller) = ensure_active_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    validate_charter_capital_auth(&charter, &auth_obj)?;

    let settle_cd = CallEncoder::<64>::new(const { selector("settleIssuanceAuction(address)") })
        .push_address(&auth_obj);
    let out = call::call_raw(&share_ledger, settle_cd.as_slice())?;
    ret::write(out);
    Ok(())
}

fn handle_refund_failed_auction(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) = ensure_active_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    if cur_escrow == 0 {
        ret::write_u64_word(0);
        return Ok(());
    }

    let st_cd = CallEncoder::<16>::new(const { selector("status()") });
    let st = call::call_u64(&auth_obj, st_cd.as_slice())?;
    // Only refund an expired/failed (`3`) unconsumed auction!
    if st != 3 {
        return Err(-62);
    }

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
    let escrow_acct = storage::get_address(KEY_SHARE_ESCROW_ACCT).ok_or(-63)?;

    let ord_cd = CallEncoder::<16>::new(const { selector("getOrdersRaw()") });
    let mut raw_book = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
    let n = call::call_abi_bytes_into(&auth_obj, ord_cd.as_slice(), &mut raw_book)?;
    let book = AuctionBook::decode(&raw_book[..n]).ok_or(ERR_POLICY_INVALID)?;

    let mut total_refunded = 0u64;
    let mut i = 0usize;
    while i < book.order_count {
        let ord = book.orders[i];
        if !ord.is_cancelled() && ord.is_buy() && ord.quantity > 0 {
            let refund = ord.price.checked_mul(ord.quantity).ok_or(-15)?;
            if refund > 0 {
                let xfer_cd = CallEncoder::<128>::new(const {
                    selector("charterModuleClearTransfer(address,address,uint64)")
                })
                .push_address(&escrow_acct)
                .push_address(&ord.trader)
                .push_u64(refund);
                let ok = call::call_bool(&bank_ledger, xfer_cd.as_slice())?;
                if !ok {
                    return Err(-16);
                }
                total_refunded = total_refunded.saturating_add(refund);
            }
        }
        i += 1;
    }

    storage::set_u64(ek.as_slice(), cur_escrow.saturating_sub(total_refunded));
    storage::set_u64(auc_escrow_active_key(&auth_obj).as_slice(), 0);
    ret::write_u64_word(total_refunded);
    Ok(())
}

fn handle_has_escrowed_auction(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    ret::write_bool(storage::get_u64(auc_escrow_active_key(&auth_obj).as_slice()) == 1);
    Ok(())
}

fn handle_escrowed_cash_of(args: &CalldataReader) -> Result<(), i32> {
    let auth_obj = args.address(0).ok_or(-3)?;
    ret::write_u64_word(storage::get_u64(auc_escrow_key(&auth_obj).as_slice()));
    Ok(())
}

/// Callback invoked by the target share `AssetLedger` during `settleTransferAuction` to disburse
/// seller proceeds and refund unspent buyer escrow from `ShareCapital`'s **`shareEscrowAccount`**.
fn handle_disburse_auction_cash(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-57);
    }
    let charter = storage::get_address(KEY_CHARTER).ok_or(-57)?;
    require_active_charter(&charter)?;

    let auth_obj = args.address(0).ok_or(-3)?;
    let recipient = args.address(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let is_seller_proceeds = args.bool(3).ok_or(-3)?;
    if amount == 0 {
        ret::write_bool(true);
        return Ok(());
    }

    let caller = context::msg_sender();
    let target_cd = CallEncoder::<16>::new(const { selector("targetHps()") });
    let Ok(raw_target) = call::call_raw(&auth_obj, target_cd.as_slice()) else {
        return Err(-62);
    };
    if raw_target.len() < 32 || raw_target[12..32] != caller {
        return Err(-62);
    }

    let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
    let escrow_acct = storage::get_address(KEY_SHARE_ESCROW_ACCT).ok_or(-63)?;

    let ek = auc_escrow_key(&auth_obj);
    let cur_escrow = storage::get_u64(ek.as_slice());
    if cur_escrow < amount {
        return Err(-16);
    }
    storage::set_u64(ek.as_slice(), cur_escrow - amount);

    let xfer_cd = CallEncoder::<128>::new(const {
        selector("charterModuleClearTransfer(address,address,uint64)")
    })
    .push_address(&escrow_acct)
    .push_address(&recipient)
    .push_u64(amount);
    let ok = call::call_bool(&bank_ledger, xfer_cd.as_slice())?;
    if !ok {
        return Err(-16);
    }

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&amount.to_be_bytes());
    ev[15] = u8::from(is_seller_proceeds);
    events::emit(
        &[
            AUCTION_CASH_SETTLED,
            addr_topic(&auth_obj),
            addr_topic(&recipient),
        ],
        &ev,
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_hash_set_share_escrow(args: &CalldataReader) -> Result<(), i32> {
    let bank_ledger = args.address(0).ok_or(-3)?;
    let escrow_acct = args.address(1).ok_or(-3)?;
    ret::write_word(&compute_set_share_escrow_hash(&bank_ledger, &escrow_acct));
    Ok(())
}

fn handle_hash_authorize_futures(args: &CalldataReader) -> Result<(), i32> {
    let futures_ledger = args.address(0).ok_or(-3)?;
    let underwrite_pct = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_authorize_futures_hash(
        &futures_ledger,
        underwrite_pct,
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::{
        CHARTER_STATE_ACTIVE, CHARTER_STATE_PENDING_RATIFICATION, ERR_CHARTER_NOT_ACTIVE,
    };
    use hps_sdk::{mock, selector};

    mod reg_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                let a = args.address(0).unwrap();
                ret::write_bool(a != [0u8; 20] && a[0] != 0xEE);
                return 0;
            }
            if sel == const { selector("isValidAuthorizationHps(address)") } {
                ret::write_bool(args.address(0).unwrap()[0] == 0xA0);
                return 0;
            }
            -2
        }
    }

    mod charter_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("state()") } {
                ret::write_u64_word(storage::get_u64(b"state"));
                return 0;
            }
            if sel == const { selector("getFunctionAuth(address,bytes4)") } {
                ret::write_word(&[0u8; 32]);
                return 0;
            }
            if sel == const { selector("convertedCommonTotals(address)") } {
                let holder = args.address(0).unwrap();
                let mut out = [0u8; 64];
                out[24..32].copy_from_slice(&storage::get_u64(&holder).to_be_bytes());
                out[56..64].copy_from_slice(&storage::get_u64(b"total_common").to_be_bytes());
                ret::write(&out);
                return 0;
            }
            -2
        }
    }

    mod auth_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{context, ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("policyId()") } {
                ret::write_word(&storage::get_bytes32(b"pol").unwrap_or([0u8; 32]));
                return 0;
            }
            if sel == const { selector("consume(address,bytes32,bytes32,address)") } {
                if context::msg_sender() != storage::get_address(b"target").unwrap() {
                    return -66;
                }
                if args.address(0).unwrap() != storage::get_address(b"charter").unwrap()
                    || args.bytes32(1).unwrap() != storage::get_bytes32(b"pol").unwrap()
                    || args.bytes32(2).unwrap() != storage::get_bytes32(b"hash").unwrap()
                {
                    return -66;
                }
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    mod futures_stub {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::{ret, selector, storage};
        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("associatedCharter()") } {
                ret::write_address(&storage::get_address(b"charter").unwrap());
                return 0;
            }
            if sel == const { selector("totalOutstanding()") } {
                ret::write_u64_word(storage::get_u64(b"supply"));
                return 0;
            }
            if sel == const { selector("charterModuleIssue(address,uint64)") } {
                let to = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let nb = storage::get_u64(&to) + amt;
                storage::set_u64(&to, nb);
                storage::set_u64(b"supply", storage::get_u64(b"supply") + amt);
                ret::write_u64_word(nb);
                return 0;
            }
            if sel == const { selector("charterModuleCancel(address,uint64)") } {
                let from = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let cur = storage::get_u64(&from);
                if cur < amt {
                    return -16;
                }
                let nb = cur - amt;
                storage::set_u64(&from, nb);
                storage::set_u64(b"supply", storage::get_u64(b"supply") - amt);
                ret::write_u64_word(nb);
                return 0;
            }
            -2
        }
    }

    #[test]
    fn share_capital_enforces_active_charter_and_preferred_share_futures_cap() {
        mock::reset();
        let sc_addr = [0x5C; 20];
        let reg_addr = [0xB0; 20];
        let charter_addr = [0xC0; 20];
        let bank_addr = [0xBA; 20];
        let escrow_acct = [0xE5; 20];
        let fut_addr = [0xF0; 20];
        let pref_holder = [0x11; 20];

        mock::register_hps(reg_addr, reg_stub::dispatch);
        mock::register_hps(charter_addr, charter_stub::dispatch);
        mock::register_hps(fut_addr, futures_stub::dispatch);

        // Charter starts PENDING_RATIFICATION: holder has 100k Pref A @ 50% = 50,000 common equiv
        mock::set_self_address(charter_addr);
        storage::set_u64(b"state", CHARTER_STATE_PENDING_RATIFICATION);
        storage::set_u64(&pref_holder, 50_000);
        storage::set_u64(b"total_common", 150_000);

        mock::set_self_address(fut_addr);
        storage::set_address(b"charter", &charter_addr);

        mock::set_self_address(sc_addr);
        mock::set_sender(pref_holder);
        let init_cd = CallEncoder::<160>::new(selector("initialize(address,address,address,address)"))
            .push_address(&reg_addr)
            .push_address(&charter_addr)
            .push_address(&bank_addr)
            .push_address(&escrow_acct);
        assert_eq!(dispatch_calldata(init_cd.as_slice()), 0);

        let h_cd = CallEncoder::<96>::new(selector("hashAuthorizeFuturesUnderwriting(address,uint64)"))
            .push_address(&fut_addr)
            .push_u64(10);
        assert_eq!(dispatch_calldata(h_cd.as_slice()), 0);
        let auth_hash: [u8; 32] = mock::take_return_data().try_into().unwrap();

        let auth_fut = [0xA0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        mock::register_hps(auth_fut, auth_stub::dispatch);
        mock::set_self_address(auth_fut);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_SUPER_GOVERNANCE);
        storage::set(b"hash", &auth_hash);

        // Must revert with ERR_CHARTER_NOT_ACTIVE while Charter is unratified!
        mock::set_self_address(sc_addr);
        let authz_cd = CallEncoder::<128>::new(SEL_AUTHORIZE_FUTURES)
            .push_address(&fut_addr)
            .push_u64(10)
            .push_address(&auth_fut);
        assert_eq!(dispatch_calldata(authz_cd.as_slice()), ERR_CHARTER_NOT_ACTIVE);

        // Activate Charter
        mock::set_self_address(charter_addr);
        storage::set_u64(b"state", CHARTER_STATE_ACTIVE);

        // Now authorize 10% futures underwriting -> company max cap = 15,000; pref_holder max = 5,000!
        mock::set_self_address(sc_addr);
        assert_eq!(dispatch_calldata(authz_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            15_000
        );

        // Exceeding 5,000 units MUST revert with ERR_FUTURES_CAP_EXCEEDED
        let over_cd = CallEncoder::<64>::new(selector("underwriteFutures(uint64)")).push_u64(5_001);
        assert_eq!(dispatch_calldata(over_cd.as_slice()), ERR_FUTURES_CAP_EXCEEDED);

        // Underwriting 5,000 units succeeds, and closing 2,000 restores allowance!
        let ok_cd = CallEncoder::<64>::new(selector("underwriteFutures(uint64)")).push_u64(5_000);
        assert_eq!(dispatch_calldata(ok_cd.as_slice()), 0);
        let close_cd =
            CallEncoder::<64>::new(selector("closeUnderwrittenFutures(uint64)")).push_u64(2_000);
        assert_eq!(dispatch_calldata(close_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            3_000
        );
    }
}
