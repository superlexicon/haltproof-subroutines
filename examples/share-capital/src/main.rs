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
    compute_esop_exercise_letter_hash, compute_sha_doc_hash, query_charter_function_auth,
    require_active_charter, require_valid_identity, validate_charter_capital_auth,
    verify_and_consume_auth, ActionHasher, AuctionBook, ACTION_AUTHORIZE_FUTURES_UNDERWRITING,
    ACTION_AWARD_ESOP_OPTIONS, ACTION_CREATE_ESOP_PROGRAM, ACTION_EXECUTE_REVERSE_SPLIT,
    ACTION_EXECUTE_SHARE_BUYBACK, ACTION_EXECUTE_SHARE_SPLIT, ACTION_SET_SHARE_ESCROW,
    ERR_CHARTER_MISMATCH, ERR_ESOP_CLIFF_NOT_PASSED, ERR_ESOP_POOL_EXCEEDED,
    ERR_FUTURES_CAP_EXCEEDED, ERR_INVALID_FUTURES_CONFIG, ERR_POLICY_INVALID,
    ERR_SHA_SIGNATURE_REQUIRED, MAX_ENCODED_AUCTION_BOOK_BYTES, POLICY_BOARD_RESOLUTION,
    POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SUPER_GOVERNANCE,
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
const SHARE_BUYBACK_EXECUTED: [u8; 32] =
    event_topic("ShareBuybackExecuted(address,address,uint64,uint64,uint64)");
const ESOP_PROGRAM_CREATED: [u8; 32] =
    event_topic("EsopProgramCreated(uint64,address,address,uint64,uint64)");
const ESOP_GRANT_AWARDED: [u8; 32] =
    event_topic("EsopGrantAwarded(uint64,uint64,address,uint64,uint64)");
const ESOP_OPTIONS_ISSUED: [u8; 32] =
    event_topic("EsopOptionsIssued(uint64,uint64,address,uint64,uint64)");
const ESOP_OPTIONS_EXERCISED: [u8; 32] =
    event_topic("EsopOptionsExercised(uint64,uint64,address,uint64,bool)");

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
const KEY_ESOP_PROG_CNT: &[u8] = b"shc:esop_pcnt";
const KEY_ESOP_GRANT_CNT: &[u8] = b"shc:esop_gcnt";

const MAX_ESOP_TRANCHES: usize = 24;

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
    "placeSubscriptionOrder(address,uint64,uint64,bytes32)"                    => handle_place_subscription_order,
    "cancelBuyOrder(address,uint64)"                                            => handle_cancel_buy_order,
    "placeSellOrder(address,uint64,uint64)"                                     => handle_place_sell_order,
    "settleShareTransferAuction(address,address)"                               => handle_settle_share_transfer_auction,
    "settleShareIssuance(address,address)"                                      => handle_settle_share_issuance,
    "refundFailedAuction(address)"                                              => handle_refund_failed_auction,
    "executeShareBuyback(address,address,uint64,uint64,address)"                => handle_execute_share_buyback,
    "executeShareSplit(address,uint64,address)"                                 => handle_execute_share_split,
    "executeReverseShareSplit(address,uint64,address)"                          => handle_execute_reverse_share_split,
    "createEsopProgram(address,address,uint64,uint64,uint64,uint64,address)"    => handle_create_esop_program,
    "awardEmployeeOptions(uint64,address,uint64,uint64,bytes,address)"          => handle_award_employee_options,
    "processDueEsopIssuances()"                                                 => handle_process_due_esop_issuances,
    "dueEsopIssuanceCount()"                                                    => handle_due_esop_issuance_count,
    "exerciseEmployeeOptions(uint64,uint64,uint64,bytes32,bytes32)"             => handle_exercise_employee_options,
    "expectedExerciseLetterHash(uint64,uint64,address,uint64)"                  => handle_expected_exercise_letter_hash,
    "esopProgramCount()"                                                        => handle_esop_program_count,
    "getEsopProgram(uint64)"                                                    => handle_get_esop_program,
    "esopGrantCount()"                                                          => handle_esop_grant_count,
    "getEsopGrant(uint64)"                                                      => handle_get_esop_grant,
    "getEsopGrantScheduleRaw(uint64)"                                           => handle_get_esop_grant_schedule_raw,
    "hasEscrowedAuction(address)"                                               => handle_has_escrowed_auction,
    "escrowedCashOf(address)"                                                   => handle_escrowed_cash_of,
    "disburseAuctionCash(address,address,uint64,bool)"                          => handle_disburse_auction_cash,
    "hashSetShareEscrowAccount(address,address)"                                => handle_hash_set_share_escrow,
    "hashAuthorizeFuturesUnderwriting(address,uint64)"                          => handle_hash_authorize_futures,
    "hashExecuteShareBuyback(address,address,uint64,uint64)"                    => handle_hash_execute_share_buyback,
    "hashExecuteShareSplit(address,uint64)"                                     => handle_hash_execute_share_split,
    "hashExecuteReverseShareSplit(address,uint64)"                              => handle_hash_execute_reverse_share_split,
    "hashCreateEsopProgram(address,address,uint64,uint64,uint64,uint64)"        => handle_hash_create_esop_program,
    "hashAwardEmployeeOptions(uint64,address,uint64,uint64,bytes)"              => handle_hash_award_employee_options,
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

    // Check if this issuance is a multi-class Equity Financing (`isEquityFinancing == 1`);
    // if so, ensure `share_ledger` is registered as a ShareClass on `CorporateCharter` before minting,
    // and snapshot subscriber addresses so allotted new shareholders are recorded in the SHA registry!
    let mut is_eqf = false;
    let mut conv_rate = 1u64;
    let eq_cd = CallEncoder::<16>::new(const { selector("equityFinancingTerms()") });
    if let Ok(eq_raw) = call::call_raw(&auth_obj, eq_cd.as_slice()) {
        if eq_raw.len() >= 9 * 32 {
            let mut w_eq = [0u8; 8];
            let mut w_cv = [0u8; 8];
            w_eq.copy_from_slice(&eq_raw[24..32]);
            w_cv.copy_from_slice(&eq_raw[2 * 32 + 24..3 * 32]);
            is_eqf = u64::from_be_bytes(w_eq) == 1;
            conv_rate = u64::from_be_bytes(w_cv).max(1);
        }
    }

    let mut pre_book = AuctionBook::new();
    if is_eqf {
        let ord_cd = CallEncoder::<16>::new(const { selector("getOrdersRaw()") });
        let mut raw_book = [0u8; MAX_ENCODED_AUCTION_BOOK_BYTES];
        if let Ok(n) = call::call_abi_bytes_into(&auth_obj, ord_cd.as_slice(), &mut raw_book) {
            if let Some(b) = AuctionBook::decode(&raw_book[..n]) {
                pre_book = b;
            }
        }
        let ens_cd = CallEncoder::<160>::new(const {
            selector("moduleEnsureShareClass(address,uint64,uint64,uint64)")
        })
        .push_address(&share_ledger)
        .push_u64(1)
        .push_u64(conv_rate)
        .push_u64(1);
        let _ = call::call_raw(&charter, ens_cd.as_slice());
    }

    let settle_cd = CallEncoder::<64>::new(const { selector("settleIssuanceAuction(address)") })
        .push_address(&auth_obj);
    let out_raw = call::call_raw(&share_ledger, settle_cd.as_slice())?;
    let mut out_copy = [0u8; 160];
    let out_len = out_raw.len().min(160);
    out_copy[..out_len].copy_from_slice(&out_raw[..out_len]);

    if is_eqf {
        let sha_hash = compute_sha_doc_hash(&charter);
        let mut i = 0usize;
        while i < pre_book.order_count {
            let ord = pre_book.orders[i];
            if !ord.is_cancelled() && ord.is_buy() && ord.quantity > 0 {
                let bal_cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
                    .push_address(&ord.trader);
                if call::call_u64(&share_ledger, bal_cd.as_slice()).unwrap_or(0) > 0 {
                    let rec_cd = CallEncoder::<128>::new(const {
                        selector("moduleRecordShareholdersAgreement(address,bytes32)")
                    })
                    .push_address(&ord.trader)
                    .push_bytes32(&sha_hash);
                    let _ = call::call_raw(&charter, rec_cd.as_slice());
                }
            }
            i += 1;
        }
    }

    ret::write(&out_copy[..out_len]);
    Ok(())
}

/// Place a prospective investor subscription order (`price`, `quantity`) with a signed
/// **Share Subscription Agreement (`ssaDocHash`)**, escrowing `price * quantity` SGD into `shareEscrowAccount`.
fn handle_place_subscription_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, buyer) = ensure_active_and_valid_caller()?;
    let auth_obj = args.address(0).ok_or(-3)?;
    let price = args.u64(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let ssa_doc_hash = args.bytes32(3).ok_or(-3)?;
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

    let order_cd = CallEncoder::<160>::new(const {
        selector("placeSubscriptionOrderFor(address,uint64,uint64,bytes32)")
    })
    .push_address(&buyer)
    .push_u64(price)
    .push_u64(quantity)
    .push_bytes32(&ssa_doc_hash);
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

// ============================================================================
// Corporate Cap-Table Actions: Share Buybacks, Share Splits & Reverse Splits
// ============================================================================

fn consume_shareholder_super_auth(
    registry: &[u8; 20],
    charter: &[u8; 20],
    auth_obj: &[u8; 20],
    action_hash: &[u8; 32],
    caller: &[u8; 20],
) -> Result<(), i32> {
    let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
    let expected_pol = if let Ok(raw_pid) = call::call_raw(auth_obj, pid_cd.as_slice()) {
        if raw_pid.len() >= 32 && raw_pid[..32] == POLICY_SHAREHOLDER_SUPERMAJORITY {
            POLICY_SHAREHOLDER_SUPERMAJORITY
        } else {
            POLICY_SUPER_GOVERNANCE
        }
    } else {
        POLICY_SHAREHOLDER_SUPERMAJORITY
    };
    verify_and_consume_auth(registry, auth_obj, charter, &expected_pol, action_hash, caller)
}

fn consume_board_auth(
    registry: &[u8; 20],
    charter: &[u8; 20],
    auth_obj: &[u8; 20],
    action_hash: &[u8; 32],
    caller: &[u8; 20],
) -> Result<(), i32> {
    verify_and_consume_auth(
        registry,
        auth_obj,
        charter,
        &POLICY_BOARD_RESOLUTION,
        action_hash,
        caller,
    )
}

fn verify_ledger_pinned_to_charter(ledger: &[u8; 20], charter: &[u8; 20]) -> Result<(), i32> {
    let assoc_cd = CallEncoder::<16>::new(const { selector("associatedCharter()") });
    let Ok(raw_assoc) = call::call_raw(ledger, assoc_cd.as_slice()) else {
        return Err(ERR_CHARTER_MISMATCH);
    };
    if raw_assoc.len() < 32 || &raw_assoc[12..32] != charter {
        return Err(ERR_CHARTER_MISMATCH);
    }
    Ok(())
}

fn compute_share_buyback_hash(
    share_ledger: &[u8; 20],
    seller: &[u8; 20],
    shares: u64,
    price_per_share: u64,
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_EXECUTE_SHARE_BUYBACK)
        .push_address(share_ledger)
        .push_address(seller)
        .push_u64(shares)
        .push_u64(price_per_share)
        .finish()
}

fn compute_share_split_hash(share_ledger: &[u8; 20], multiplier: u64) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_EXECUTE_SHARE_SPLIT)
        .push_address(share_ledger)
        .push_u64(multiplier)
        .finish()
}

fn compute_reverse_split_hash(share_ledger: &[u8; 20], divisor: u64) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_EXECUTE_REVERSE_SPLIT)
        .push_address(share_ledger)
        .push_u64(divisor)
        .finish()
}

fn handle_hash_execute_share_buyback(args: &CalldataReader) -> Result<(), i32> {
    let share_ledger = args.address(0).ok_or(-3)?;
    let seller = args.address(1).ok_or(-3)?;
    let shares = args.u64(2).ok_or(-3)?;
    let price_per_share = args.u64(3).ok_or(-3)?;
    ret::write_word(&compute_share_buyback_hash(
        &share_ledger,
        &seller,
        shares,
        price_per_share,
    ));
    Ok(())
}

fn handle_hash_execute_share_split(args: &CalldataReader) -> Result<(), i32> {
    let share_ledger = args.address(0).ok_or(-3)?;
    let multiplier = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_share_split_hash(&share_ledger, multiplier));
    Ok(())
}

fn handle_hash_execute_reverse_share_split(args: &CalldataReader) -> Result<(), i32> {
    let share_ledger = args.address(0).ok_or(-3)?;
    let divisor = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_reverse_split_hash(&share_ledger, divisor));
    Ok(())
}

/// Repurchase `shares` from `seller` at `pricePerShare` SGD out of Company Treasury (`treasuryRecipient()`)
/// and retire/cancel them on `shareLedger`, increasing remaining shareholders' ownership `%`.
fn handle_execute_share_buyback(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let seller = args.address(1).ok_or(-3)?;
    let shares = args.u64(2).ok_or(-3)?;
    let price_per_share = args.u64(3).ok_or(-3)?;
    let super_auth = args.address(4).ok_or(-3)?;

    if share_ledger == [0u8; 20] || seller == [0u8; 20] || shares == 0 {
        return Err(-14);
    }
    require_valid_identity(&registry, &seller)?;
    verify_ledger_pinned_to_charter(&share_ledger, &charter)?;

    let action_hash = compute_share_buyback_hash(&share_ledger, &seller, shares, price_per_share);
    consume_shareholder_super_auth(&registry, &charter, &super_auth, &action_hash, &caller)?;

    // Ensure at least 1 share remains outstanding in the company or in this class if sole class!
    let (_, total_common) = query_converted_common_totals(&charter, &[0u8; 20]).unwrap_or((0, 0));
    if total_common > 0 && shares >= total_common {
        return Err(-16); // Cannot buy back 100% of company voting shares
    }

    let total_paid = shares.checked_mul(price_per_share).ok_or(-15)?;
    if total_paid > 0 {
        let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
        let treasury = storage::get_address(KEY_INITIALIZER)
            .or_else(|| storage::get_address(KEY_SHARE_ESCROW_ACCT))
            .ok_or(-63)?;
        if treasury != seller {
            let pay_cd = CallEncoder::<128>::new(const {
                selector("charterModuleClearTransfer(address,address,uint64)")
            })
            .push_address(&treasury)
            .push_address(&seller)
            .push_u64(total_paid);
            let ok = call::call_bool(&bank_ledger, pay_cd.as_slice())?;
            if !ok {
                return Err(-16);
            }
        }
    }

    let cancel_cd = CallEncoder::<96>::new(const { selector("charterModuleCancel(address,uint64)") })
        .push_address(&seller)
        .push_u64(shares);
    let rem_bal = call::call_u64(&share_ledger, cancel_cd.as_slice())?;

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&shares.to_be_bytes());
    ev[8..16].copy_from_slice(&price_per_share.to_be_bytes());
    ev[16..24].copy_from_slice(&total_paid.to_be_bytes());
    events::emit(
        &[
            SHARE_BUYBACK_EXECUTED,
            addr_topic(&share_ledger),
            addr_topic(&seller),
        ],
        &ev,
    );

    ret::write_u64_word(rem_bal);
    Ok(())
}

fn handle_execute_share_split(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let multiplier = args.u64(1).ok_or(-3)?;
    let super_auth = args.address(2).ok_or(-3)?;

    if share_ledger == [0u8; 20] || multiplier < 2 || multiplier > 100 {
        return Err(-14);
    }
    verify_ledger_pinned_to_charter(&share_ledger, &charter)?;

    let action_hash = compute_share_split_hash(&share_ledger, multiplier);
    consume_shareholder_super_auth(&registry, &charter, &super_auth, &action_hash, &caller)?;

    let split_cd =
        CallEncoder::<64>::new(const { selector("charterModuleSplit(uint64)") }).push_u64(multiplier);
    let new_supply = call::call_u64(&share_ledger, split_cd.as_slice())?;
    ret::write_u64_word(new_supply);
    Ok(())
}

fn handle_execute_reverse_share_split(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let share_ledger = args.address(0).ok_or(-3)?;
    let divisor = args.u64(1).ok_or(-3)?;
    let super_auth = args.address(2).ok_or(-3)?;

    if share_ledger == [0u8; 20] || divisor < 2 || divisor > 100 {
        return Err(-14);
    }
    verify_ledger_pinned_to_charter(&share_ledger, &charter)?;

    let action_hash = compute_reverse_split_hash(&share_ledger, divisor);
    consume_shareholder_super_auth(&registry, &charter, &super_auth, &action_hash, &caller)?;

    let rev_cd = CallEncoder::<64>::new(const { selector("charterModuleReverseSplit(uint64)") })
        .push_u64(divisor);
    let new_supply = call::call_u64(&share_ledger, rev_cd.as_slice())?;
    ret::write_u64_word(new_supply);
    Ok(())
}

// ============================================================================
// Master ESOP Programmes, Board Option Grants, Periodic Vesting & Exercise
// ============================================================================

#[derive(Clone, Copy)]
struct EsopProgramRec {
    option_ledger: [u8; 20],
    underlying_ledger: [u8; 20],
    class_code: u64,
    conversion_rate: u64,
    authorized_shares: u64,
    exercise_price: u64,
    committed_shares: u64,
    issued_options: u64,
    exercised_options: u64,
}

#[derive(Clone, Copy)]
struct EsopGrantRec {
    program_id: u64,
    employee: [u8; 20],
    cliff_block: u64,
    cliff_timestamp: u64,
    total_awarded: u64,
    issued_options: u64,
    exercised_options: u64,
    tranche_count: u16,
}

fn esop_prog_key(program_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"esop:p:").push_u64_le(program_id)
}

fn esop_grant_key(grant_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"esop:g:").push_u64_le(grant_id)
}

fn esop_grant_sched_key(grant_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"esop:s:").push_u64_le(grant_id)
}

fn save_esop_program(program_id: u64, rec: &EsopProgramRec) {
    let mut b = [0u8; 96];
    b[0..20].copy_from_slice(&rec.option_ledger);
    b[20..40].copy_from_slice(&rec.underlying_ledger);
    b[40..48].copy_from_slice(&rec.class_code.to_be_bytes());
    b[48..56].copy_from_slice(&rec.conversion_rate.to_be_bytes());
    b[56..64].copy_from_slice(&rec.authorized_shares.to_be_bytes());
    b[64..72].copy_from_slice(&rec.exercise_price.to_be_bytes());
    b[72..80].copy_from_slice(&rec.committed_shares.to_be_bytes());
    b[80..88].copy_from_slice(&rec.issued_options.to_be_bytes());
    b[88..96].copy_from_slice(&rec.exercised_options.to_be_bytes());
    storage::set(esop_prog_key(program_id).as_slice(), &b);
}

fn load_esop_program(program_id: u64) -> Option<EsopProgramRec> {
    let mut b = [0u8; 96];
    if storage::get_into(esop_prog_key(program_id).as_slice(), &mut b)? != 96 {
        return None;
    }
    let mut option_ledger = [0u8; 20];
    let mut underlying_ledger = [0u8; 20];
    option_ledger.copy_from_slice(&b[0..20]);
    underlying_ledger.copy_from_slice(&b[20..40]);
    let rd = |off: usize| -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(w)
    };
    Some(EsopProgramRec {
        option_ledger,
        underlying_ledger,
        class_code: rd(40),
        conversion_rate: rd(48),
        authorized_shares: rd(56),
        exercise_price: rd(64),
        committed_shares: rd(72),
        issued_options: rd(80),
        exercised_options: rd(88),
    })
}

fn save_esop_grant(grant_id: u64, rec: &EsopGrantRec) {
    let mut b = [0u8; 70];
    b[0..8].copy_from_slice(&rec.program_id.to_be_bytes());
    b[8..28].copy_from_slice(&rec.employee);
    b[28..36].copy_from_slice(&rec.cliff_block.to_be_bytes());
    b[36..44].copy_from_slice(&rec.cliff_timestamp.to_be_bytes());
    b[44..52].copy_from_slice(&rec.total_awarded.to_be_bytes());
    b[52..60].copy_from_slice(&rec.issued_options.to_be_bytes());
    b[60..68].copy_from_slice(&rec.exercised_options.to_be_bytes());
    b[68..70].copy_from_slice(&rec.tranche_count.to_be_bytes());
    storage::set(esop_grant_key(grant_id).as_slice(), &b);
}

fn load_esop_grant(grant_id: u64) -> Option<EsopGrantRec> {
    let mut b = [0u8; 70];
    if storage::get_into(esop_grant_key(grant_id).as_slice(), &mut b)? != 70 {
        return None;
    }
    let rd = |off: usize| -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[off..off + 8]);
        u64::from_be_bytes(w)
    };
    let mut employee = [0u8; 20];
    employee.copy_from_slice(&b[8..28]);
    let tranche_count = u16::from_be_bytes([b[68], b[69]]);
    Some(EsopGrantRec {
        program_id: rd(0),
        employee,
        cliff_block: rd(28),
        cliff_timestamp: rd(36),
        total_awarded: rd(44),
        issued_options: rd(52),
        exercised_options: rd(60),
        tranche_count,
    })
}

fn compute_create_esop_program_hash(
    option_ledger: &[u8; 20],
    underlying_ledger: &[u8; 20],
    class_code: u64,
    conversion_rate: u64,
    authorized_shares: u64,
    exercise_price: u64,
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_CREATE_ESOP_PROGRAM)
        .push_address(option_ledger)
        .push_address(underlying_ledger)
        .push_u64(class_code)
        .push_u64(conversion_rate)
        .push_u64(authorized_shares)
        .push_u64(exercise_price)
        .finish()
}

fn compute_award_esop_options_hash(
    program_id: u64,
    employee: &[u8; 20],
    cliff_block: u64,
    cliff_timestamp: u64,
    schedule_blob: &[u8],
) -> [u8; 32] {
    let sched_hash = hps_sdk::keccak::keccak256(schedule_blob);
    ActionHasher::<192>::new(&context::self_address(), &ACTION_AWARD_ESOP_OPTIONS)
        .push_u64(program_id)
        .push_address(employee)
        .push_u64(cliff_block)
        .push_u64(cliff_timestamp)
        .push_bytes32(&sched_hash)
        .finish()
}

fn handle_hash_create_esop_program(args: &CalldataReader) -> Result<(), i32> {
    let option_ledger = args.address(0).ok_or(-3)?;
    let underlying_ledger = args.address(1).ok_or(-3)?;
    let class_code = args.u64(2).ok_or(-3)?;
    let conversion_rate = args.u64(3).ok_or(-3)?;
    let authorized_shares = args.u64(4).ok_or(-3)?;
    let exercise_price = args.u64(5).ok_or(-3)?;
    ret::write_word(&compute_create_esop_program_hash(
        &option_ledger,
        &underlying_ledger,
        class_code,
        conversion_rate,
        authorized_shares,
        exercise_price,
    ));
    Ok(())
}

fn handle_hash_award_employee_options(args: &CalldataReader) -> Result<(), i32> {
    let program_id = args.u64(0).ok_or(-3)?;
    let employee = args.address(1).ok_or(-3)?;
    let cliff_block = args.u64(2).ok_or(-3)?;
    let cliff_timestamp = args.u64(3).ok_or(-3)?;
    let schedule_blob = args.dynamic_bytes(4).ok_or(-3)?;
    ret::write_word(&compute_award_esop_options_hash(
        program_id,
        &employee,
        cliff_block,
        cliff_timestamp,
        schedule_blob,
    ));
    Ok(())
}

fn handle_create_esop_program(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let option_ledger = args.address(0).ok_or(-3)?;
    let underlying_ledger = args.address(1).ok_or(-3)?;
    let class_code = args.u64(2).ok_or(-3)?;
    let conversion_rate = args.u64(3).ok_or(-3)?;
    let authorized_shares = args.u64(4).ok_or(-3)?;
    let exercise_price = args.u64(5).ok_or(-3)?;
    let super_auth = args.address(6).ok_or(-3)?;

    if option_ledger == [0u8; 20]
        || underlying_ledger == [0u8; 20]
        || option_ledger == underlying_ledger
        || conversion_rate == 0
        || authorized_shares == 0
    {
        return Err(-14);
    }
    if class_code == 0 && conversion_rate != 1 {
        return Err(-14);
    }
    verify_ledger_pinned_to_charter(&option_ledger, &charter)?;
    verify_ledger_pinned_to_charter(&underlying_ledger, &charter)?;

    let action_hash = compute_create_esop_program_hash(
        &option_ledger,
        &underlying_ledger,
        class_code,
        conversion_rate,
        authorized_shares,
        exercise_price,
    );
    consume_shareholder_super_auth(&registry, &charter, &super_auth, &action_hash, &caller)?;

    let ens_cd = CallEncoder::<160>::new(const {
        selector("moduleEnsureShareClass(address,uint64,uint64,uint64)")
    })
    .push_address(&underlying_ledger)
    .push_u64(1)
    .push_u64(conversion_rate)
    .push_u64(1);
    let _ = call::call_raw(&charter, ens_cd.as_slice());

    let program_id = storage::get_u64(KEY_ESOP_PROG_CNT);
    let rec = EsopProgramRec {
        option_ledger,
        underlying_ledger,
        class_code,
        conversion_rate,
        authorized_shares,
        exercise_price,
        committed_shares: 0,
        issued_options: 0,
        exercised_options: 0,
    };
    save_esop_program(program_id, &rec);
    storage::set_u64(KEY_ESOP_PROG_CNT, program_id + 1);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&program_id.to_be_bytes());
    ev[8..16].copy_from_slice(&authorized_shares.to_be_bytes());
    ev[16..24].copy_from_slice(&exercise_price.to_be_bytes());
    events::emit(
        &[
            ESOP_PROGRAM_CREATED,
            addr_topic(&option_ledger),
            addr_topic(&underlying_ledger),
        ],
        &ev,
    );

    ret::write_u64_word(program_id);
    Ok(())
}

fn handle_award_employee_options(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let program_id = args.u64(0).ok_or(-3)?;
    let employee = args.address(1).ok_or(-3)?;
    let cliff_block = args.u64(2).ok_or(-3)?;
    let cliff_timestamp = args.u64(3).ok_or(-3)?;
    let schedule_blob = args.dynamic_bytes(4).ok_or(-3)?;
    let board_auth = args.address(5).ok_or(-3)?;

    require_valid_identity(&registry, &employee)?;
    let mut prog = load_esop_program(program_id).ok_or(-62)?;

    if schedule_blob.len() < 2 {
        return Err(-14);
    }
    let tranche_count = u16::from_be_bytes([schedule_blob[0], schedule_blob[1]]) as usize;
    if tranche_count == 0
        || tranche_count > MAX_ESOP_TRANCHES
        || schedule_blob.len() != 2 + tranche_count * 24
    {
        return Err(-14);
    }

    let mut stored_sched = [0u8; 2 + MAX_ESOP_TRANCHES * 25];
    stored_sched[0..2].copy_from_slice(&(tranche_count as u16).to_be_bytes());
    let mut total_award = 0u64;
    let mut t = 0usize;
    while t < tranche_count {
        let in_off = 2 + t * 24;
        let mut w_amt = [0u8; 8];
        w_amt.copy_from_slice(&schedule_blob[in_off + 16..in_off + 24]);
        let amt = u64::from_be_bytes(w_amt);
        if amt == 0 {
            return Err(-14);
        }
        total_award = total_award.checked_add(amt).ok_or(-15)?;

        let out_off = 2 + t * 25;
        stored_sched[out_off] = 0; // `issued = 0`
        stored_sched[out_off + 1..out_off + 25]
            .copy_from_slice(&schedule_blob[in_off..in_off + 24]);
        t += 1;
    }

    let next_committed = prog.committed_shares.checked_add(total_award).ok_or(-15)?;
    if next_committed > prog.authorized_shares {
        return Err(ERR_ESOP_POOL_EXCEEDED);
    }

    let action_hash = compute_award_esop_options_hash(
        program_id,
        &employee,
        cliff_block,
        cliff_timestamp,
        schedule_blob,
    );
    consume_board_auth(&registry, &charter, &board_auth, &action_hash, &caller)?;

    prog.committed_shares = next_committed;
    save_esop_program(program_id, &prog);

    let grant_id = storage::get_u64(KEY_ESOP_GRANT_CNT);
    let g_rec = EsopGrantRec {
        program_id,
        employee,
        cliff_block,
        cliff_timestamp,
        total_awarded: total_award,
        issued_options: 0,
        exercised_options: 0,
        tranche_count: tranche_count as u16,
    };
    save_esop_grant(grant_id, &g_rec);
    storage::set(
        esop_grant_sched_key(grant_id).as_slice(),
        &stored_sched[..2 + tranche_count * 25],
    );
    storage::set_u64(KEY_ESOP_GRANT_CNT, grant_id + 1);

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&program_id.to_be_bytes());
    ev[8..16].copy_from_slice(&grant_id.to_be_bytes());
    ev[16..24].copy_from_slice(&total_award.to_be_bytes());
    ev[24..32].copy_from_slice(&cliff_block.to_be_bytes());
    events::emit(&[ESOP_GRANT_AWARDED, addr_topic(&employee)], &ev);

    ret::write_u64_word(grant_id);
    Ok(())
}

/// Periodic digitized vesting sweep (callable hourly / weekly / monthly / every few blocks by
/// keeper or any verified Identity): issues due option tranches onto each Master ESOP Program's
/// dedicated `optionLedger`.
fn handle_process_due_esop_issuances(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, _charter, _caller) = ensure_active_and_valid_caller()?;
    let now = context::block_number();
    let grant_cnt = storage::get_u64(KEY_ESOP_GRANT_CNT);

    let mut newly_issued_total = 0u64;
    let mut g_id = 0u64;
    while g_id < grant_cnt {
        if let Some(mut g) = load_esop_grant(g_id) {
            if g.issued_options < g.total_awarded {
                let mut sched = [0u8; 2 + MAX_ESOP_TRANCHES * 25];
                let expected_len = 2 + (g.tranche_count as usize) * 25;
                if storage::get_into(esop_grant_sched_key(g_id).as_slice(), &mut sched)
                    == Some(expected_len)
                {
                    if let Some(mut prog) = load_esop_program(g.program_id) {
                        let mut changed = false;
                        let mut t = 0usize;
                        while t < (g.tranche_count as usize) {
                            let off = 2 + t * 25;
                            if sched[off] == 0 {
                                let mut w_due = [0u8; 8];
                                let mut w_amt = [0u8; 8];
                                w_due.copy_from_slice(&sched[off + 1..off + 9]);
                                w_amt.copy_from_slice(&sched[off + 17..off + 25]);
                                let due_blk = u64::from_be_bytes(w_due);
                                let amt = u64::from_be_bytes(w_amt);
                                if now >= due_blk && amt > 0 {
                                    let iss_cd = CallEncoder::<96>::new(const {
                                        selector("charterModuleIssue(address,uint64)")
                                    })
                                    .push_address(&g.employee)
                                    .push_u64(amt);
                                    let _ = call::call_u64(&prog.option_ledger, iss_cd.as_slice())?;
                                    sched[off] = 1;
                                    g.issued_options = g.issued_options.saturating_add(amt);
                                    prog.issued_options = prog.issued_options.saturating_add(amt);
                                    newly_issued_total = newly_issued_total.saturating_add(amt);
                                    changed = true;

                                    let mut ev = [0u8; 32];
                                    ev[0..8].copy_from_slice(&g.program_id.to_be_bytes());
                                    ev[8..16].copy_from_slice(&g_id.to_be_bytes());
                                    ev[16..24].copy_from_slice(&(t as u64).to_be_bytes());
                                    ev[24..32].copy_from_slice(&amt.to_be_bytes());
                                    events::emit(
                                        &[ESOP_OPTIONS_ISSUED, addr_topic(&g.employee)],
                                        &ev,
                                    );
                                }
                            }
                            t += 1;
                        }
                        if changed {
                            save_esop_grant(g_id, &g);
                            save_esop_program(g.program_id, &prog);
                            storage::set(
                                esop_grant_sched_key(g_id).as_slice(),
                                &sched[..expected_len],
                            );
                        }
                    }
                }
            }
        }
        g_id += 1;
    }

    ret::write_u64_word(newly_issued_total);
    Ok(())
}

fn handle_due_esop_issuance_count(_args: &CalldataReader) -> Result<(), i32> {
    let now = context::block_number();
    let grant_cnt = storage::get_u64(KEY_ESOP_GRANT_CNT);
    let mut due_tranches = 0u64;
    let mut g_id = 0u64;
    while g_id < grant_cnt {
        if let Some(g) = load_esop_grant(g_id) {
            if g.issued_options < g.total_awarded {
                let mut sched = [0u8; 2 + MAX_ESOP_TRANCHES * 25];
                let expected_len = 2 + (g.tranche_count as usize) * 25;
                if storage::get_into(esop_grant_sched_key(g_id).as_slice(), &mut sched)
                    == Some(expected_len)
                {
                    let mut t = 0usize;
                    while t < (g.tranche_count as usize) {
                        let off = 2 + t * 25;
                        if sched[off] == 0 {
                            let mut w_due = [0u8; 8];
                            w_due.copy_from_slice(&sched[off + 1..off + 9]);
                            if now >= u64::from_be_bytes(w_due) {
                                due_tranches += 1;
                            }
                        }
                        t += 1;
                    }
                }
            }
        }
        g_id += 1;
    }
    ret::write_u64_word(due_tranches);
    Ok(())
}

/// Exercise `amount` vested options under `(programId, grantId)`:
/// 1. Requires `block_number() >= grant.cliffBlock` (`ERR_ESOP_CLIFF_NOT_PASSED = -98`).
/// 2. Requires signed `exerciseLetterHash == expectedExerciseLetterHash(...)`.
/// 3. If this is the **first time** `employee` will become a shareholder in the company, requires
///    `shaDocHash == shaDocumentHash(charter)` (`ERR_SHA_SIGNATURE_REQUIRED = -99`) and records SHA!
/// 4. Collects `amount * exercisePrice` SGD (if `exercisePrice > 0`), burns `amount` options on
///    `optionLedger`, and mints `amount` underlying shares on `underlyingShareLedger`!
fn handle_exercise_employee_options(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, caller) = ensure_active_and_valid_caller()?;
    let program_id = args.u64(0).ok_or(-3)?;
    let grant_id = args.u64(1).ok_or(-3)?;
    let amount = args.u64(2).ok_or(-3)?;
    let exercise_letter_hash = args.bytes32(3).ok_or(-3)?;
    let sha_doc_hash = args.bytes32(4).ok_or(-3)?;

    if amount == 0 {
        return Err(-14);
    }
    let mut g = load_esop_grant(grant_id).ok_or(-62)?;
    if g.program_id != program_id || g.employee != caller {
        return Err(-61);
    }
    if context::block_number() < g.cliff_block {
        return Err(ERR_ESOP_CLIFF_NOT_PASSED);
    }
    let next_ex = g.exercised_options.checked_add(amount).ok_or(-15)?;
    if next_ex > g.issued_options {
        return Err(-16); // Cannot exercise un-issued / unvested options
    }

    let expected_letter = compute_esop_exercise_letter_hash(
        &context::self_address(),
        program_id,
        grant_id,
        &caller,
        amount,
    );
    if exercise_letter_hash != expected_letter {
        return Err(-67);
    }

    let mut prog = load_esop_program(program_id).ok_or(-62)?;

    // First-time shareholder check: does `caller` already hold any company shares or signed SHA?
    let (holder_common, _) = query_converted_common_totals(&charter, &caller).unwrap_or((0, 0));
    let sha_q = CallEncoder::<64>::new(const { selector("hasSignedShareholdersAgreement(address)") })
        .push_address(&caller);
    let already_signed_sha = call::call_bool(&charter, sha_q.as_slice()).unwrap_or(false);
    let first_time_shareholder = holder_common == 0 && !already_signed_sha;

    if first_time_shareholder {
        let expected_sha = compute_sha_doc_hash(&charter);
        if sha_doc_hash != expected_sha {
            return Err(ERR_SHA_SIGNATURE_REQUIRED);
        }
        let rec_cd = CallEncoder::<128>::new(const {
            selector("moduleRecordShareholdersAgreement(address,bytes32)")
        })
        .push_address(&caller)
        .push_bytes32(&sha_doc_hash);
        let ok = call::call_bool(&charter, rec_cd.as_slice())?;
        if !ok {
            return Err(ERR_SHA_SIGNATURE_REQUIRED);
        }
    }

    if prog.exercise_price > 0 {
        let strike_total = amount.checked_mul(prog.exercise_price).ok_or(-15)?;
        let bank_ledger = storage::get_address(KEY_BANK_LEDGER).ok_or(-63)?;
        let treasury = storage::get_address(KEY_INITIALIZER)
            .or_else(|| storage::get_address(KEY_SHARE_ESCROW_ACCT))
            .ok_or(-63)?;
        if treasury != caller {
            let pay_cd = CallEncoder::<128>::new(const {
                selector("charterModuleClearTransfer(address,address,uint64)")
            })
            .push_address(&caller)
            .push_address(&treasury)
            .push_u64(strike_total);
            let ok = call::call_bool(&bank_ledger, pay_cd.as_slice())?;
            if !ok {
                return Err(-16);
            }
        }
    }

    // Burn options on `optionLedger` & mint underlying shares on `underlyingShareLedger`!
    let burn_cd = CallEncoder::<96>::new(const { selector("charterModuleCancel(address,uint64)") })
        .push_address(&caller)
        .push_u64(amount);
    let _ = call::call_u64(&prog.option_ledger, burn_cd.as_slice())?;

    let mint_cd = CallEncoder::<96>::new(const { selector("charterModuleIssue(address,uint64)") })
        .push_address(&caller)
        .push_u64(amount);
    let _ = call::call_u64(&prog.underlying_ledger, mint_cd.as_slice())?;

    g.exercised_options = next_ex;
    prog.exercised_options = prog.exercised_options.saturating_add(amount);
    save_esop_grant(grant_id, &g);
    save_esop_program(program_id, &prog);

    let mut ev = [0u8; 32];
    ev[0..8].copy_from_slice(&program_id.to_be_bytes());
    ev[8..16].copy_from_slice(&grant_id.to_be_bytes());
    ev[16..24].copy_from_slice(&amount.to_be_bytes());
    ev[31] = u8::from(first_time_shareholder);
    events::emit(&[ESOP_OPTIONS_EXERCISED, addr_topic(&caller)], &ev);

    ret::write_u64_word(next_ex);
    Ok(())
}

fn handle_expected_exercise_letter_hash(args: &CalldataReader) -> Result<(), i32> {
    let program_id = args.u64(0).ok_or(-3)?;
    let grant_id = args.u64(1).ok_or(-3)?;
    let employee = args.address(2).ok_or(-3)?;
    let amount = args.u64(3).ok_or(-3)?;
    ret::write_word(&compute_esop_exercise_letter_hash(
        &context::self_address(),
        program_id,
        grant_id,
        &employee,
        amount,
    ));
    Ok(())
}

fn handle_esop_program_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ESOP_PROG_CNT));
    Ok(())
}

fn handle_get_esop_program(args: &CalldataReader) -> Result<(), i32> {
    let pid = args.u64(0).ok_or(-3)?;
    let p = load_esop_program(pid).ok_or(-62)?;
    let mut out = [0u8; 9 * 32];
    out[12..32].copy_from_slice(&p.option_ledger);
    out[32 + 12..64].copy_from_slice(&p.underlying_ledger);
    let nums = [
        p.class_code,
        p.conversion_rate,
        p.authorized_shares,
        p.exercise_price,
        p.committed_shares,
        p.issued_options,
        p.exercised_options,
    ];
    let mut i = 0usize;
    while i < nums.len() {
        out[(i + 2) * 32 + 24..(i + 3) * 32].copy_from_slice(&nums[i].to_be_bytes());
        i += 1;
    }
    ret::write(&out);
    Ok(())
}

fn handle_esop_grant_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ESOP_GRANT_CNT));
    Ok(())
}

fn handle_get_esop_grant(args: &CalldataReader) -> Result<(), i32> {
    let gid = args.u64(0).ok_or(-3)?;
    let g = load_esop_grant(gid).ok_or(-62)?;
    let mut out = [0u8; 8 * 32];
    out[24..32].copy_from_slice(&g.program_id.to_be_bytes());
    out[32 + 12..64].copy_from_slice(&g.employee);
    let nums = [
        g.cliff_block,
        g.cliff_timestamp,
        g.total_awarded,
        g.issued_options,
        g.exercised_options,
        g.tranche_count as u64,
    ];
    let mut i = 0usize;
    while i < nums.len() {
        out[(i + 2) * 32 + 24..(i + 3) * 32].copy_from_slice(&nums[i].to_be_bytes());
        i += 1;
    }
    ret::write(&out);
    Ok(())
}

fn handle_get_esop_grant_schedule_raw(args: &CalldataReader) -> Result<(), i32> {
    let gid = args.u64(0).ok_or(-3)?;
    let g = load_esop_grant(gid).ok_or(-62)?;
    let mut sched = [0u8; 2 + MAX_ESOP_TRANCHES * 25];
    let expected_len = 2 + (g.tranche_count as usize) * 25;
    let n = storage::get_into(esop_grant_sched_key(gid).as_slice(), &mut sched).ok_or(-62)?;
    if n != expected_len {
        return Err(-62);
    }
    ret::write_abi_bytes(&sched[..n]);
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
            if sel == const { selector("hasSignedShareholdersAgreement(address)") } {
                let who = args.address(0).unwrap();
                let mut k = [0u8; 24];
                k[0..4].copy_from_slice(b"sha:");
                k[4..24].copy_from_slice(&who);
                ret::write_bool(storage::get_u64(&k) == 1);
                return 0;
            }
            if sel == const { selector("moduleRecordShareholdersAgreement(address,bytes32)") } {
                let who = args.address(0).unwrap();
                let mut k = [0u8; 24];
                k[0..4].copy_from_slice(b"sha:");
                k[4..24].copy_from_slice(&who);
                storage::set_u64(&k, 1);
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("moduleEnsureShareClass(address,uint64,uint64,uint64)") } {
                ret::write_u64_word(1);
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
            if sel == const { selector("charterModuleClearTransfer(address,address,uint64)") } {
                let from = args.address(0).unwrap();
                let to = args.address(1).unwrap();
                let amt = args.u64(2).unwrap();
                let cur = storage::get_u64(&from);
                if cur < amt {
                    return -16;
                }
                storage::set_u64(&from, cur - amt);
                storage::set_u64(&to, storage::get_u64(&to) + amt);
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("charterModuleSplit(uint64)") } {
                let m = args.u64(0).unwrap();
                let ns = storage::get_u64(b"supply") * m;
                storage::set_u64(b"supply", ns);
                ret::write_u64_word(ns);
                return 0;
            }
            if sel == const { selector("charterModuleReverseSplit(uint64)") } {
                let d = args.u64(0).unwrap();
                let ns = storage::get_u64(b"supply") / d;
                storage::set_u64(b"supply", ns);
                ret::write_u64_word(ns);
                return 0;
            }
            if sel == const { selector("balanceOf(address)") } {
                let who = args.address(0).unwrap();
                ret::write_u64_word(storage::get_u64(&who));
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

    #[test]
    fn esop_program_vesting_cliff_first_time_sha_and_cap_table_splits_buyback() {
        mock::reset();
        let sc_addr = [0x5C; 20];
        let reg_addr = [0xB0; 20];
        let charter_addr = [0xC0; 20];
        let bank_addr = [0xBA; 20];
        let escrow_acct = [0xE5; 20];
        let share_led = [0x51; 20];
        let opt_led = [0x52; 20];
        let founder = [0x11; 20];
        let employee = [0x22; 20];

        mock::register_hps(reg_addr, reg_stub::dispatch);
        mock::register_hps(charter_addr, charter_stub::dispatch);
        mock::register_hps(bank_addr, futures_stub::dispatch);
        mock::register_hps(share_led, futures_stub::dispatch);
        mock::register_hps(opt_led, futures_stub::dispatch);

        mock::set_self_address(charter_addr);
        storage::set_u64(b"state", CHARTER_STATE_ACTIVE);
        storage::set_u64(&founder, 100_000);
        storage::set_u64(b"total_common", 100_000);

        for led in [share_led, opt_led, bank_addr] {
            mock::set_self_address(led);
            storage::set_address(b"charter", &charter_addr);
        }
        mock::set_self_address(share_led);
        storage::set_u64(&founder, 100_000);
        storage::set_u64(b"supply", 100_000);

        mock::set_self_address(bank_addr);
        storage::set_u64(&founder, 2_000_000);
        storage::set_u64(&employee, 100_000);

        mock::set_self_address(sc_addr);
        mock::set_sender(founder);
        mock::set_block_number(10);
        let init_cd = CallEncoder::<160>::new(selector("initialize(address,address,address,address)"))
            .push_address(&reg_addr)
            .push_address(&charter_addr)
            .push_address(&bank_addr)
            .push_address(&escrow_acct);
        assert_eq!(dispatch_calldata(init_cd.as_slice()), 0);

        // 1. Create Master ESOP Program (10,000 Common options @ 20 SGD strike)
        let h_prog = compute_create_esop_program_hash(&opt_led, &share_led, 0, 1, 10_000, 20);
        let auth_prog = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10];
        mock::register_hps(auth_prog, auth_stub::dispatch);
        mock::set_self_address(auth_prog);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_SHAREHOLDER_SUPERMAJORITY);
        storage::set(b"hash", &h_prog);

        mock::set_self_address(sc_addr);
        let create_cd = CallEncoder::<256>::new(selector(
            "createEsopProgram(address,address,uint64,uint64,uint64,uint64,address)",
        ))
        .push_address(&opt_led)
        .push_address(&share_led)
        .push_u64(0)
        .push_u64(1)
        .push_u64(10_000)
        .push_u64(20)
        .push_address(&auth_prog);
        assert_eq!(dispatch_calldata(create_cd.as_slice()), 0);

        // 2. Board Resolution awards 2 tranches (`due=12: 1,000`, `due=20: 1,500`, `cliff=15`)
        let mut sched = [0u8; 2 + 2 * 24];
        sched[0..2].copy_from_slice(&2u16.to_be_bytes());
        sched[2..10].copy_from_slice(&12u64.to_be_bytes());
        sched[10..18].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        sched[18..26].copy_from_slice(&1_000u64.to_be_bytes());
        sched[26..34].copy_from_slice(&20u64.to_be_bytes());
        sched[34..42].copy_from_slice(&1_702_600_000u64.to_be_bytes());
        sched[42..50].copy_from_slice(&1_500u64.to_be_bytes());

        let h_award = compute_award_esop_options_hash(0, &employee, 15, 1_701_000_000, &sched);
        let auth_award = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11];
        mock::register_hps(auth_award, auth_stub::dispatch);
        mock::set_self_address(auth_award);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_BOARD_RESOLUTION);
        storage::set(b"hash", &h_award);

        mock::set_self_address(sc_addr);
        let mut award_cd = Vec::new();
        award_cd.extend_from_slice(&selector(
            "awardEmployeeOptions(uint64,address,uint64,uint64,bytes,address)",
        ));
        let mut head = [0u8; 6 * 32];
        head[24..32].copy_from_slice(&0u64.to_be_bytes());
        head[32 + 12..64].copy_from_slice(&employee);
        head[64 + 24..96].copy_from_slice(&15u64.to_be_bytes());
        head[96 + 24..128].copy_from_slice(&1_701_000_000u64.to_be_bytes());
        head[128 + 24..160].copy_from_slice(&192u64.to_be_bytes());
        head[160 + 12..192].copy_from_slice(&auth_award);
        award_cd.extend_from_slice(&head);
        let mut dyn_len = [0u8; 32];
        dyn_len[24..32].copy_from_slice(&(sched.len() as u64).to_be_bytes());
        award_cd.extend_from_slice(&dyn_len);
        award_cd.extend_from_slice(&sched);
        award_cd.resize(award_cd.len() + (32 - sched.len() % 32) % 32, 0);
        assert_eq!(dispatch_calldata(&award_cd), 0);

        // 3. Periodic sweep at block #13 issues Tranche #0 (`1,000` options onto `opt_led`)!
        mock::set_block_number(13);
        let sweep_cd = CallEncoder::<16>::new(selector("processDueEsopIssuances()"));
        assert_eq!(dispatch_calldata(sweep_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            1_000
        );

        // 4. Attempting exercise BEFORE cliff (#13 < #15) MUST revert with ERR_ESOP_CLIFF_NOT_PASSED (-98)!
        mock::set_sender(employee);
        let letter_hash = compute_esop_exercise_letter_hash(&sc_addr, 0, 0, &employee, 600);
        let sha_hash = compute_sha_doc_hash(&charter_addr);
        let ex_cd_pre = CallEncoder::<192>::new(selector(
            "exerciseEmployeeOptions(uint64,uint64,uint64,bytes32,bytes32)",
        ))
        .push_u64(0)
        .push_u64(0)
        .push_u64(600)
        .push_bytes32(&letter_hash)
        .push_bytes32(&sha_hash);
        assert_eq!(dispatch_calldata(ex_cd_pre.as_slice()), ERR_ESOP_CLIFF_NOT_PASSED);

        // 5. At block #16 (cliff passed!), omitting SHA for first-time shareholder MUST revert with ERR_SHA_SIGNATURE_REQUIRED (-99)!
        mock::set_block_number(16);
        let ex_cd_no_sha = CallEncoder::<192>::new(selector(
            "exerciseEmployeeOptions(uint64,uint64,uint64,bytes32,bytes32)",
        ))
        .push_u64(0)
        .push_u64(0)
        .push_u64(600)
        .push_bytes32(&letter_hash)
        .push_bytes32(&[0u8; 32]);
        assert_eq!(dispatch_calldata(ex_cd_no_sha.as_slice()), ERR_SHA_SIGNATURE_REQUIRED);

        // 6. Providing signed Exercise Letter + signed SHA converts 600 options into 600 underlying shares!
        assert_eq!(dispatch_calldata(ex_cd_pre.as_slice()), 0);

        // 7. Subsequent exercise (`400` options) succeeds WITHOUT needing to re-sign SHA!
        let letter_hash_2 = compute_esop_exercise_letter_hash(&sc_addr, 0, 0, &employee, 400);
        let ex_cd_second = CallEncoder::<192>::new(selector(
            "exerciseEmployeeOptions(uint64,uint64,uint64,bytes32,bytes32)",
        ))
        .push_u64(0)
        .push_u64(0)
        .push_u64(400)
        .push_bytes32(&letter_hash_2)
        .push_bytes32(&[0u8; 32]);
        assert_eq!(dispatch_calldata(ex_cd_second.as_slice()), 0);

        // 8. Share Split (2-for-1) & Reverse Split (1-for-2) & Share Buyback (`1,000` shares @ `50` SGD)
        mock::set_sender(founder);
        let h_split = compute_share_split_hash(&share_led, 2);
        let auth_split = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12];
        mock::register_hps(auth_split, auth_stub::dispatch);
        mock::set_self_address(auth_split);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_SHAREHOLDER_SUPERMAJORITY);
        storage::set(b"hash", &h_split);

        mock::set_self_address(sc_addr);
        let split_cd = CallEncoder::<128>::new(selector("executeShareSplit(address,uint64,address)"))
            .push_address(&share_led)
            .push_u64(2)
            .push_address(&auth_split);
        assert_eq!(dispatch_calldata(split_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            202_000
        );

        let h_rev = compute_reverse_split_hash(&share_led, 2);
        let auth_rev = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13];
        mock::register_hps(auth_rev, auth_stub::dispatch);
        mock::set_self_address(auth_rev);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_SHAREHOLDER_SUPERMAJORITY);
        storage::set(b"hash", &h_rev);

        mock::set_self_address(sc_addr);
        let rev_cd =
            CallEncoder::<128>::new(selector("executeReverseShareSplit(address,uint64,address)"))
                .push_address(&share_led)
                .push_u64(2)
                .push_address(&auth_rev);
        assert_eq!(dispatch_calldata(rev_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            101_000
        );

        let h_bb = compute_share_buyback_hash(&share_led, &employee, 500, 50);
        let auth_bb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14];
        mock::register_hps(auth_bb, auth_stub::dispatch);
        mock::set_self_address(auth_bb);
        storage::set_address(b"target", &sc_addr);
        storage::set_address(b"charter", &charter_addr);
        storage::set(b"pol", &POLICY_SHAREHOLDER_SUPERMAJORITY);
        storage::set(b"hash", &h_bb);

        mock::set_self_address(sc_addr);
        let bb_cd = CallEncoder::<192>::new(selector(
            "executeShareBuyback(address,address,uint64,uint64,address)",
        ))
        .push_address(&share_led)
        .push_address(&employee)
        .push_u64(500)
        .push_u64(50)
        .push_address(&auth_bb);
        assert_eq!(dispatch_calldata(bb_cd.as_slice()), 0);
        assert_eq!(
            u64::from_be_bytes(mock::take_return_data()[24..32].try_into().unwrap()),
            500
        );
    }
}
