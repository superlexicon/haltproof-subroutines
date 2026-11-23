//! Confidential Category Roll-Up & Shielded Settlement **Haltproof Subroutine (HPS)** (`confidential-ledger`).
//!
//! Composable sibling module to `AccountingLedger` (`HFS_TYPE_CONF_LEDGER`) enforcing:
//! 1. **Generalized Confidential Category Roll-Ups** across Monthly Payroll (`6100`/`2100`/`1010`),
//!    B2B & Defense Service Contracts (`1800`/`2300`/`1100`/`4000`), Enterprise Trade AR (`1100`/`4000`),
//!    and Vendor & R&D OpEx (`6400`/`2010`/`1010`).
//! 2. **Dual Roll-Up Timing Modes**:
//!    - `CONF_MODE_BATCH_OR_EPOCH (1)`: Hides BOTH individual amounts and counterparties; staged
//!      encrypted commitments update public GL totals only upon multi-slot batch or epoch flush.
//!    - `CONF_MODE_LIVE_COUNTERPARTY_SHIELDED (2)`: Updates public category totals live while hiding
//!      counterparty identity and line breakdown.
//! 3. **Zero-Value Dummy Commitment Padding** (`minSlots = 4` by default) preventing single-contract
//!    size inference and employee headcount side-channel leaks.
//! 4. **Trustless On-Chain Cryptographic Soundness** via Wasmtime native `Edwards25519` HE/EC syscalls:
//!    24-bit non-negative range proofs (`verify_he_range_u24`), Chaum-Pedersen DLEQ sum conservation
//!    (`verify_he_sum_equals_u64`), Stealth Schnorr bilateral co-signing (`verify_ed25519_schnorr`),
//!    and `IAS 24` Charter Insider Non-Membership Proofs (`verify_stealth_non_insider`).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    query_charter_function_auth, require_active_charter, require_valid_identity,
    verify_and_consume_auth, ActionHasher, ACTION_CONFIDENTIAL_BATCH,
    ACTION_CONFIDENTIAL_RECEIVABLE, ACTION_IFRS_DISBURSE, ERR_AUTH_CONSUME_FAILED,
    ERR_MISSING_ROLE, HFS_TYPE_CONF_LEDGER, POLICY_ACCOUNTING_OPS, POLICY_BOARD_RESOLUTION,
    ROLE_CHIEF_ACCOUNTANT, ROLE_TREASURY_MANAGER,
};
use hps_sdk::ifrs::{
    CONF_CAT_DEFENSE_B2B, CONF_CAT_PAYROLL, CONF_CAT_TRADE_AR, CONF_CAT_VENDOR_OPEX,
    CONF_MODE_BATCH_OR_EPOCH, CONF_MODE_LIVE_COUNTERPARTY_SHIELDED, ERR_IFRS_BANK_CASH_SHORTFALL,
    ERR_IFRS_CONF_AUDIT_KEY_UNSET, ERR_IFRS_CONF_CATEGORY_INVALID, ERR_IFRS_CONF_PADDING_TOO_SMALL,
    ERR_IFRS_CONF_PROOF_INVALID, ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED,
    ERR_IFRS_INVALID_CONTRACT_DURATION, ERR_IFRS_NOTHING_TO_POST,
    ERR_IFRS_RELATED_PARTY_CREDIT_BANNED, ERR_IFRS_SUBLEDGER_FULL, ERR_IFRS_SUBLEDGER_NOT_FOUND,
    MAX_SERVICE_CONTRACT_MONTHS, MAX_SERVICE_MONTH_BLOCKS, MIN_SERVICE_CONTRACT_MONTHS,
    MIN_SERVICE_MONTH_BLOCKS,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::vrf::{
    he_add_ciphertexts, he_scale_ciphertext, verify_ed25519_schnorr, verify_he_range_u24,
    verify_he_sum_equals_u64, verify_stealth_non_insider, CONF_MIN_PADDED_SLOTS,
    CONF_RANGE_PROOF_BYTES, IDENTITY_CIPHERTEXT_64, IDENTITY_POINT_BYTES,
};
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const EV_INITIALIZED: [u8; 32] =
    event_topic("ConfidentialLedgerInitialized(address,address,address)");
const EV_CONF_BATCH_POSTED: [u8; 32] =
    event_topic("IfrsConfidentialBatchPosted(uint64,bytes32,bytes32,uint64)");
const EV_CONF_REC_UPDATED: [u8; 32] =
    event_topic("IfrsConfidentialReceivableUpdated(uint64,bytes32,uint64,uint64)");

const KEY_INIT: &[u8] = b"conf:init";
const KEY_REGISTRY: &[u8] = b"conf:reg";
const KEY_HFS_REGISTRY: &[u8] = b"conf:hfsreg";
const KEY_CHARTER: &[u8] = b"conf:chr";
const KEY_ACC_LEDGER: &[u8] = b"conf:acc";

const KEY_CONF_CAT_SEEDED: &[u8] = b"conf:cc:seed";
const KEY_CONF_CAT_CNT: &[u8] = b"conf:cc:cnt";
const KEY_CONF_BATCH_CNT: &[u8] = b"conf:cb:cnt";
const KEY_CONF_REC_CNT: &[u8] = b"conf:cr:cnt";

const MAX_CONF_CATEGORIES: u64 = 32;
const MAX_CONF_BATCH_SLOTS: usize = 10;
const MAX_CONF_AUDIT_CIPHER: usize = 2048;
const MAX_CONF_LINE_ENV: usize = 256;
const MAX_CONF_REC_ENV: usize = 1024;
const MAX_IAS24_INSIDER_PKS: usize = 64;

static mut SLICE_BUF: [u8; 24576] = [0u8; 24576];

pub const CAT_ID_PAYROLL: [u8; 32] = keccak256(b"CONF_CAT:MONTHLY_PAYROLL");
pub const CAT_ID_DEFENSE_B2B: [u8; 32] = keccak256(b"CONF_CAT:DEFENSE_B2B_CONTRACTS");
pub const CAT_ID_DEFENSE_LIVE: [u8; 32] = keccak256(b"CONF_CAT:DEFENSE_B2B_LIVE");
pub const CAT_ID_TRADE_AR: [u8; 32] = keccak256(b"CONF_CAT:CONFIDENTIAL_TRADE_AR");
pub const CAT_ID_VENDOR_OPEX: [u8; 32] = keccak256(b"CONF_CAT:CONFIDENTIAL_VENDOR_OPEX");

/// Roll-up posting kinds forwarded to `AccountingLedger.bookConfidentialRollupFromModule`.
pub const ROLLUP_PAYROLL_RUN: u64 = 1;
pub const ROLLUP_PAYROLL_SETTLE: u64 = 2;
pub const ROLLUP_VENDOR_OPEX: u64 = 3;
pub const ROLLUP_PAYABLE_SETTLE: u64 = 4;
pub const ROLLUP_DEFENSE_BACKLOG: u64 = 5;
pub const ROLLUP_DEFENSE_LIVE: u64 = 6;
pub const ROLLUP_DEFENSE_BILLING: u64 = 7;
pub const ROLLUP_TRADE_AR: u64 = 8;
pub const ROLLUP_CASH_SWEEP: u64 = 9;

const SEL_DEF_CONF_CAT: [u8; 4] =
    selector("defineConfidentialCategory(bytes32,uint64,uint64,uint64,string,address)");
const SEL_POST_CONF_PAY: [u8; 4] = selector(
    "postConfidentialPayableBatch(bytes32,bytes32,uint64,bool,bytes,bytes,bytes,bytes,address)",
);
const SEL_SETTLE_CONF_PAY: [u8; 4] =
    selector("settleAccruedConfidentialBatch(uint64,address)");
const SEL_PROP_CONF_REC: [u8; 4] = selector(
    "proposeConfidentialReceivable(bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes,bytes,bytes,address)",
);
const SEL_FLUSH_CONF_REC: [u8; 4] = selector(
    "flushConfidentialReceivableEpoch(bytes32,bytes32,uint64,bytes,bytes,bytes,bytes,address)",
);
const SEL_BILL_CONF_CAT: [u8; 4] = selector(
    "billConfidentialCategoryEpoch(bytes32,bytes32,uint64,bytes,bytes,bytes,bytes,address)",
);
const SEL_SWEEP_CONF_CASH: [u8; 4] =
    selector("sweepConfidentialCategoryCash(bytes32,bytes32,uint64,bytes,bytes,address)");

hps_entry! {
    "hfsType()"                                                                         => handle_hfs_type,
    "initialize(address,address,address,address)"                                       => handle_initialize,
    "associatedCharter()"                                                               => handle_associated_charter,
    "accountingLedger()"                                                                => handle_accounting_ledger,
    "identityRegistry()"                                                                => handle_identity_registry,
    "hfsRegistry()"                                                                     => handle_hfs_registry,
    "defineConfidentialCategory(bytes32,uint64,uint64,uint64,string,address)"           => handle_define_confidential_category,
    "postConfidentialPayableBatch(bytes32,bytes32,uint64,bool,bytes,bytes,bytes,bytes,address)" => handle_post_confidential_payable_batch,
    "settleAccruedConfidentialBatch(uint64,address)"                                    => handle_settle_accrued_confidential_batch,
    "proposeConfidentialReceivable(bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes,bytes,bytes,address)" => handle_propose_confidential_receivable,
    "hashProposeConfidentialReceivable(bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32)" => handle_hash_propose_confidential_receivable,
    "stealthCosignConfidentialReceivable(uint64,uint64,bytes,bytes,bytes)"              => handle_stealth_cosign_confidential_receivable,
    "flushConfidentialReceivableEpoch(bytes32,bytes32,uint64,bytes,bytes,bytes,bytes,address)" => handle_flush_confidential_receivable_epoch,
    "billConfidentialCategoryEpoch(bytes32,bytes32,uint64,bytes,bytes,bytes,bytes,address)"   => handle_bill_confidential_category_epoch,
    "sweepConfidentialCategoryCash(bytes32,bytes32,uint64,bytes,bytes,address)"         => handle_sweep_confidential_category_cash,
    "getConfidentialCategories()"                                                       => handle_get_confidential_categories,
    "getConfidentialBatchesSlice(uint64,uint64)"                                        => handle_get_confidential_batches_slice,
    "getConfidentialReceivablesSlice(uint64,uint64)"                                    => handle_get_confidential_receivables_slice,
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

fn read_u64_be(src: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[off..off + 8]);
    u64::from_be_bytes(b)
}

fn handle_hfs_type(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_word(&HFS_TYPE_CONF_LEDGER);
    Ok(())
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let hfs_reg = args.address(1).ok_or(-3)?;
    let charter = args.address(2).ok_or(-3)?;
    let acc_ledger = args.address(3).ok_or(-3)?;

    if registry == [0u8; 20] || charter == [0u8; 20] || acc_ledger == [0u8; 20] {
        return Err(-3);
    }
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let chr_cd = CallEncoder::<16>::new(const { selector("associatedCharter()") });
    let acc_chr_raw = call::call_raw(&acc_ledger, chr_cd.as_slice())?;
    if acc_chr_raw.len() < 32 || acc_chr_raw[12..32] != charter {
        return Err(-12);
    }

    storage::set_address(KEY_REGISTRY, &registry);
    if hfs_reg != [0u8; 20] {
        storage::set_address(KEY_HFS_REGISTRY, &hfs_reg);
    }
    storage::set_address(KEY_CHARTER, &charter);
    storage::set_address(KEY_ACC_LEDGER, &acc_ledger);
    storage::set_u64(KEY_INIT, 1);
    ensure_default_conf_categories();

    events::emit(
        &[
            EV_INITIALIZED,
            addr_topic(&charter),
            addr_topic(&acc_ledger),
            addr_topic(&caller),
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
fn handle_accounting_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ACC_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}
fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}
fn handle_hfs_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_HFS_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn ensure_active() -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(-10)?;
    let acc = storage::get_address(KEY_ACC_LEDGER).ok_or(-10)?;
    require_active_charter(&charter)?;
    Ok((registry, charter, acc))
}

fn require_accounting_ops_auth(
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
) -> Result<([u8; 20], [u8; 20], [u8; 20], [u8; 20]), i32> {
    let (registry, charter, acc) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, fn_selector);
    if *auth_obj != [0u8; 20] {
        let req_pol = explicit_pol.unwrap_or(POLICY_ACCOUNTING_OPS);
        verify_and_consume_auth(&registry, auth_obj, &charter, &req_pol, action_hash, &caller)?;
        return Ok((registry, charter, acc, caller));
    }
    if let Some(pol) = explicit_pol {
        if pol != POLICY_ACCOUNTING_OPS
            && pol != ROLE_CHIEF_ACCOUNTANT
            && pol != ROLE_TREASURY_MANAGER
        {
            return Err(ERR_AUTH_CONSUME_FAILED);
        }
    }
    let check_role = |role_id: &[u8; 32]| -> bool {
        let cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
            .push_bytes32(role_id)
            .push_address(&caller);
        matches!(call::call_bool(&charter, cd.as_slice()), Ok(true))
    };
    if check_role(&ROLE_CHIEF_ACCOUNTANT) || check_role(&ROLE_TREASURY_MANAGER) {
        return Ok((registry, charter, acc, caller));
    }
    let dcnt_cd = CallEncoder::<16>::new(const { selector("directorCount()") });
    let dcnt = call::call_u64(&charter, dcnt_cd.as_slice()).unwrap_or(0);
    let is_dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(&caller);
    if dcnt == 1 && matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true)) {
        return Ok((registry, charter, acc, caller));
    }
    Err(ERR_MISSING_ROLE)
}

fn require_board_level_auth(
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
) -> Result<([u8; 20], [u8; 20], [u8; 20], [u8; 20]), i32> {
    let (registry, charter, acc) = ensure_active()?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, fn_selector);
    if *auth_obj != [0u8; 20] {
        let req_pol = explicit_pol.unwrap_or(POLICY_BOARD_RESOLUTION);
        verify_and_consume_auth(&registry, auth_obj, &charter, &req_pol, action_hash, &caller)?;
        return Ok((registry, charter, acc, caller));
    }
    if explicit_pol.is_some() {
        return Err(ERR_AUTH_CONSUME_FAILED);
    }
    let dcnt_cd = CallEncoder::<16>::new(const { selector("directorCount()") });
    let dcnt = call::call_u64(&charter, dcnt_cd.as_slice()).unwrap_or(0);
    let is_dir_cd =
        CallEncoder::<64>::new(const { selector("isDirector(address)") }).push_address(&caller);
    if dcnt == 1 && matches!(call::call_bool(&charter, is_dir_cd.as_slice()), Ok(true)) {
        return Ok((registry, charter, acc, caller));
    }
    Err(ERR_AUTH_CONSUME_FAILED)
}

fn query_accounting_bank_and_treasury(acc: &[u8; 20]) -> Result<([u8; 20], [u8; 20]), i32> {
    let b_cd = CallEncoder::<16>::new(const { selector("operatingBankLedger()") });
    let b_raw = call::call_raw(acc, b_cd.as_slice())?;
    if b_raw.len() < 32 {
        return Err(-10);
    }
    let mut bank = [0u8; 20];
    bank.copy_from_slice(&b_raw[12..32]);

    let t_cd = CallEncoder::<16>::new(const { selector("treasuryIdentity()") });
    let t_raw = call::call_raw(acc, t_cd.as_slice())?;
    if t_raw.len() < 32 {
        return Err(-10);
    }
    let mut treas = [0u8; 20];
    treas.copy_from_slice(&t_raw[12..32]);
    Ok((bank, treas))
}

fn call_book_rollup_on_accounting(
    acc: &[u8; 20],
    rollup_kind: u64,
    total_amount: u64,
    is_paid_or_cash: bool,
) -> Result<u64, i32> {
    let cd = CallEncoder::<128>::new(const {
        selector("bookConfidentialRollupFromModule(uint64,uint64,bool)")
    })
    .push_u64(rollup_kind)
    .push_u64(total_amount)
    .push_bool(is_paid_or_cash);
    call::call_u64(acc, cd.as_slice())
}

fn call_fund_shielded_batch_on_accounting(
    acc: &[u8; 20],
    batch_tag32: &[u8; 32],
    total_amount: u64,
    audit_pk: &[u8; 32],
    sum_dleq: &[u8; 64],
    packed_notes: &[u8],
) -> Result<u64, i32> {
    const MAX_PACKED: usize = 2 + MAX_CONF_BATCH_SLOTS * (98 + MAX_CONF_LINE_ENV);
    if packed_notes.len() > MAX_PACKED {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let pn_pad = (32 - (packed_notes.len() % 32)) % 32;
    let total_len = 4 + 160 + 96 + 32 + packed_notes.len() + pn_pad;
    unsafe {
        let buf = &mut *core::ptr::addr_of_mut!(SLICE_BUF);
        for b in &mut buf[..total_len] {
            *b = 0;
        }
        buf[0..4].copy_from_slice(&selector(
            "fundShieldedBatchFromModule(bytes32,uint64,bytes32,bytes,bytes)",
        ));
        buf[4..36].copy_from_slice(batch_tag32);
        buf[60..68].copy_from_slice(&total_amount.to_be_bytes());
        buf[68..100].copy_from_slice(audit_pk);
        buf[124..132].copy_from_slice(&160u64.to_be_bytes());
        buf[156..164].copy_from_slice(&256u64.to_be_bytes());
        buf[188..196].copy_from_slice(&64u64.to_be_bytes());
        buf[196..260].copy_from_slice(sum_dleq);
        buf[284..292].copy_from_slice(&(packed_notes.len() as u64).to_be_bytes());
        buf[292..292 + packed_notes.len()].copy_from_slice(packed_notes);
        call::call_u64(acc, &buf[..total_len])
    }
}

#[derive(Clone, Copy)]
struct ConfCategoryMeta {
    category_id: [u8; 32],
    kind: u8,
    mode: u8,
    min_slots: u8,
    batch_count: u32,
    total_posted: u64,
    active_backlog: u64,
    open_ar_or_ap: u64,
    settled_cash: u64,
    label_len: u8,
    label: [u8; 48],
}

fn conf_cat_idx_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cc:i:").push_u64_be(idx)
}
fn conf_cat_key(cat_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"cc:m:").push(cat_id)
}
fn conf_batch_hdr_key(batch_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cb:h:").push_u64_be(batch_id)
}
fn conf_batch_aud_key(batch_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cb:a:").push_u64_be(batch_id)
}
fn conf_batch_slots_key(batch_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cb:s:").push_u64_be(batch_id)
}
fn conf_rec_hdr_key(rec_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cr:h:").push_u64_be(rec_id)
}
fn conf_rec_aud_key(rec_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cr:a:").push_u64_be(rec_id)
}
fn conf_rec_cli_key(rec_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new().push(b"cr:c:").push_u64_be(rec_id)
}

const FIXED_CONF_CAT_BYTES: usize = 120;

fn encode_conf_cat(meta: &ConfCategoryMeta) -> [u8; FIXED_CONF_CAT_BYTES] {
    let mut b = [0u8; FIXED_CONF_CAT_BYTES];
    b[0..32].copy_from_slice(&meta.category_id);
    b[32] = meta.kind;
    b[33] = meta.mode;
    b[34] = meta.min_slots;
    b[35] = meta.label_len;
    b[36..40].copy_from_slice(&meta.batch_count.to_be_bytes());
    b[40..48].copy_from_slice(&meta.total_posted.to_be_bytes());
    b[48..56].copy_from_slice(&meta.active_backlog.to_be_bytes());
    b[56..64].copy_from_slice(&meta.open_ar_or_ap.to_be_bytes());
    b[64..72].copy_from_slice(&meta.settled_cash.to_be_bytes());
    b[72..120].copy_from_slice(&meta.label);
    b
}

fn decode_conf_cat(raw: &[u8; FIXED_CONF_CAT_BYTES]) -> ConfCategoryMeta {
    let mut category_id = [0u8; 32];
    category_id.copy_from_slice(&raw[0..32]);
    let mut bc = [0u8; 4];
    bc.copy_from_slice(&raw[36..40]);
    let mut label = [0u8; 48];
    label.copy_from_slice(&raw[72..120]);
    ConfCategoryMeta {
        category_id,
        kind: raw[32],
        mode: raw[33],
        min_slots: raw[34],
        label_len: raw[35].min(48),
        batch_count: u32::from_be_bytes(bc),
        total_posted: read_u64_be(raw, 40),
        active_backlog: read_u64_be(raw, 48),
        open_ar_or_ap: read_u64_be(raw, 56),
        settled_cash: read_u64_be(raw, 64),
        label,
    }
}

fn preset_conf_cat(idx: usize) -> Option<ConfCategoryMeta> {
    let (id, kind, mode, lbl): ([u8; 32], u8, u8, &[u8]) = match idx {
        0 => (
            CAT_ID_PAYROLL,
            CONF_CAT_PAYROLL,
            CONF_MODE_BATCH_OR_EPOCH,
            b"Monthly Salaries & Payroll",
        ),
        1 => (
            CAT_ID_DEFENSE_B2B,
            CONF_CAT_DEFENSE_B2B,
            CONF_MODE_BATCH_OR_EPOCH,
            b"B2B Defense Contracts (Epoch)",
        ),
        2 => (
            CAT_ID_DEFENSE_LIVE,
            CONF_CAT_DEFENSE_B2B,
            CONF_MODE_LIVE_COUNTERPARTY_SHIELDED,
            b"B2B Defense (Counterparty-Shielded)",
        ),
        3 => (
            CAT_ID_TRADE_AR,
            CONF_CAT_TRADE_AR,
            CONF_MODE_BATCH_OR_EPOCH,
            b"Confidential Enterprise AR",
        ),
        4 => (
            CAT_ID_VENDOR_OPEX,
            CONF_CAT_VENDOR_OPEX,
            CONF_MODE_BATCH_OR_EPOCH,
            b"Confidential Vendor & R&D OpEx",
        ),
        _ => return None,
    };
    let mut label = [0u8; 48];
    let n = lbl.len().min(48);
    label[..n].copy_from_slice(&lbl[..n]);
    Some(ConfCategoryMeta {
        category_id: id,
        kind,
        mode,
        min_slots: CONF_MIN_PADDED_SLOTS as u8,
        batch_count: 0,
        total_posted: 0,
        active_backlog: 0,
        open_ar_or_ap: 0,
        settled_cash: 0,
        label_len: n as u8,
        label,
    })
}

fn ensure_default_conf_categories() {
    if storage::get_u64(KEY_CONF_CAT_SEEDED) == 1 {
        return;
    }
    let mut cnt = storage::get_u64(KEY_CONF_CAT_CNT);
    let mut i = 0usize;
    while let Some(meta) = preset_conf_cat(i) {
        let ck = conf_cat_key(&meta.category_id);
        if !storage::exists(ck.as_slice()) && cnt < MAX_CONF_CATEGORIES {
            storage::set(conf_cat_idx_key(cnt).as_slice(), &meta.category_id);
            storage::set(ck.as_slice(), &encode_conf_cat(&meta));
            cnt += 1;
        }
        i += 1;
    }
    storage::set_u64(KEY_CONF_CAT_CNT, cnt);
    storage::set_u64(KEY_CONF_CAT_SEEDED, 1);
}

fn load_conf_cat(cat_id: &[u8; 32]) -> Option<ConfCategoryMeta> {
    let ck = conf_cat_key(cat_id);
    let mut raw = [0u8; FIXED_CONF_CAT_BYTES];
    if storage::get_into(ck.as_slice(), &mut raw) == Some(FIXED_CONF_CAT_BYTES) {
        return Some(decode_conf_cat(&raw));
    }
    let mut i = 0usize;
    while let Some(meta) = preset_conf_cat(i) {
        if &meta.category_id == cat_id {
            return Some(meta);
        }
        i += 1;
    }
    None
}

fn save_conf_cat(meta: &ConfCategoryMeta) -> Result<(), i32> {
    ensure_default_conf_categories();
    let ck = conf_cat_key(&meta.category_id);
    if !storage::exists(ck.as_slice()) {
        let cnt = storage::get_u64(KEY_CONF_CAT_CNT);
        if cnt >= MAX_CONF_CATEGORIES {
            return Err(ERR_IFRS_SUBLEDGER_FULL);
        }
        storage::set(conf_cat_idx_key(cnt).as_slice(), &meta.category_id);
        storage::set_u64(KEY_CONF_CAT_CNT, cnt + 1);
    }
    storage::set(ck.as_slice(), &encode_conf_cat(meta));
    Ok(())
}

fn query_charter_audit_epoch(charter: &[u8; 20]) -> Result<(u64, [u8; 32]), i32> {
    let cd = CallEncoder::<16>::new(const { selector("getAuditEpochState()") });
    let raw = call::call_raw(charter, cd.as_slice()).map_err(|_| ERR_IFRS_CONF_AUDIT_KEY_UNSET)?;
    if raw.len() < 40 {
        return Err(ERR_IFRS_CONF_AUDIT_KEY_UNSET);
    }
    let ep = read_u64_be(raw, 0);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[8..40]);
    if ep == 0 || pk == [0u8; 32] || pk == IDENTITY_POINT_BYTES {
        return Err(ERR_IFRS_CONF_AUDIT_KEY_UNSET);
    }
    Ok((ep, pk))
}

fn query_charter_audit_pk_for_epoch(charter: &[u8; 20], epoch: u64) -> Result<[u8; 32], i32> {
    let cd = CallEncoder::<64>::new(const { selector("getAuditPubKey(uint64)") }).push_u64(epoch);
    let raw = call::call_raw(charter, cd.as_slice()).map_err(|_| ERR_IFRS_CONF_AUDIT_KEY_UNSET)?;
    if raw.len() != 32 {
        return Err(ERR_IFRS_CONF_AUDIT_KEY_UNSET);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(raw);
    if pk == [0u8; 32] || pk == IDENTITY_POINT_BYTES {
        return Err(ERR_IFRS_CONF_AUDIT_KEY_UNSET);
    }
    Ok(pk)
}

fn query_charter_insider_pks(
    charter: &[u8; 20],
    out_pks: &mut [[u8; 32]; MAX_IAS24_INSIDER_PKS],
) -> Result<usize, i32> {
    let cd = CallEncoder::<16>::new(const { selector("getIas24InsiderEdPubKeys()") });
    let raw = call::call_raw(charter, cd.as_slice())?;
    if raw.len() < 2 {
        return Ok(0);
    }
    let cnt = (u16::from_be_bytes([raw[0], raw[1]]) as usize).min(MAX_IAS24_INSIDER_PKS);
    if raw.len() < 2 + cnt * 52 {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let mut i = 0usize;
    while i < cnt {
        let off = 2 + i * 52;
        out_pks[i].copy_from_slice(&raw[off + 20..off + 52]);
        i += 1;
    }
    Ok(cnt)
}

fn compute_batch_tag(batch_id: u64) -> [u8; 32] {
    let mut pre = [0u8; 44];
    pre[0..16].copy_from_slice(b"SLX_CONF_BTAG_1:");
    pre[16..36].copy_from_slice(&context::self_address());
    pre[36..44].copy_from_slice(&batch_id.to_be_bytes());
    keccak256(&pre)
}

fn handle_define_confidential_category(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let kind_u64 = args.u64(1).ok_or(-3)?;
    let mode_u64 = args.u64(2).ok_or(-3)?;
    let min_slots_u64 = args.u64(3).ok_or(-3)?;
    let label_raw = args.dynamic_bytes(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    if category_id == [0u8; 32]
        || !(1..=4).contains(&kind_u64)
        || !(1..=2).contains(&mode_u64)
        || !(2..=MAX_CONF_BATCH_SLOTS as u64).contains(&min_slots_u64)
        || label_raw.is_empty()
        || label_raw.len() > 48
    {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }
    let ah = ActionHasher::<160>::new(&context::self_address(), &ACTION_CONFIDENTIAL_BATCH)
        .push_bytes32(&category_id)
        .push_u64(kind_u64)
        .push_u64(mode_u64)
        .push_u64(min_slots_u64)
        .finish();
    let _ = require_accounting_ops_auth(&SEL_DEF_CONF_CAT, &ah, &auth_obj)?;

    let mut label = [0u8; 48];
    label[..label_raw.len()].copy_from_slice(label_raw);
    let existing = load_conf_cat(&category_id);
    let meta = ConfCategoryMeta {
        category_id,
        kind: kind_u64 as u8,
        mode: mode_u64 as u8,
        min_slots: min_slots_u64 as u8,
        batch_count: existing.map(|e| e.batch_count).unwrap_or(0),
        total_posted: existing.map(|e| e.total_posted).unwrap_or(0),
        active_backlog: existing.map(|e| e.active_backlog).unwrap_or(0),
        open_ar_or_ap: existing.map(|e| e.open_ar_or_ap).unwrap_or(0),
        settled_cash: existing.map(|e| e.settled_cash).unwrap_or(0),
        label_len: label_raw.len() as u8,
        label,
    };
    save_conf_cat(&meta)?;
    ret::write_bool(true);
    Ok(())
}

const FIXED_CONF_BATCH_HDR: usize = 244;

#[allow(clippy::too_many_arguments)]
fn save_conf_batch_record(
    batch_id: u64,
    cat_id: &[u8; 32],
    period_tag: &[u8; 32],
    audit_epoch: u64,
    cat_kind: u8,
    batch_type: u8,
    is_paid: bool,
    slot_cnt: u8,
    total_amount: u64,
    first_note_id: u64,
    journal_id: u64,
    c_sum: &[u8; 64],
    sum_dleq: &[u8; 64],
    audit_cipher: &[u8],
    packed_slots: &[u8],
) {
    let mut hdr = [0u8; FIXED_CONF_BATCH_HDR];
    hdr[0..32].copy_from_slice(cat_id);
    hdr[32..64].copy_from_slice(period_tag);
    hdr[64..72].copy_from_slice(&audit_epoch.to_be_bytes());
    hdr[72] = cat_kind;
    hdr[73] = batch_type;
    hdr[74] = u8::from(is_paid);
    hdr[75] = slot_cnt;
    hdr[76..84].copy_from_slice(&total_amount.to_be_bytes());
    hdr[84..92].copy_from_slice(&first_note_id.to_be_bytes());
    hdr[92..100].copy_from_slice(&journal_id.to_be_bytes());
    hdr[100..108].copy_from_slice(&context::block_number().to_be_bytes());
    hdr[108..172].copy_from_slice(c_sum);
    hdr[172..236].copy_from_slice(sum_dleq);

    storage::set(conf_batch_hdr_key(batch_id).as_slice(), &hdr);
    if !audit_cipher.is_empty() {
        storage::set(conf_batch_aud_key(batch_id).as_slice(), audit_cipher);
    }
    if !packed_slots.is_empty() {
        storage::set(conf_batch_slots_key(batch_id).as_slice(), packed_slots);
    }
    storage::set_u64(KEY_CONF_BATCH_CNT, batch_id + 1);
    events::emit(
        &[
            EV_CONF_BATCH_POSTED,
            u64_topic(batch_id),
            *cat_id,
            *period_tag,
        ],
        &total_amount.to_be_bytes(),
    );
}

fn handle_post_confidential_payable_batch(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let period_tag = args.bytes32(1).ok_or(-3)?;
    let total_amount = args.u64(2).ok_or(-3)?;
    let is_paid_now = args.bool(3).ok_or(-3)?;
    let range_proofs = args.dynamic_bytes(4).ok_or(-3)?;
    let sum_dleq_slice = args.dynamic_bytes(5).ok_or(-3)?;
    let audit_cipher = args.dynamic_bytes(6).ok_or(-3)?;
    let locks_and_envs = args.dynamic_bytes(7).ok_or(-3)?;
    let auth_obj = args.address(8).ok_or(-3)?;

    if total_amount == 0
        || sum_dleq_slice.len() != 64
        || audit_cipher.len() > MAX_CONF_AUDIT_CIPHER
        || locks_and_envs.len() < 2
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let ah = ActionHasher::<192>::new(&context::self_address(), &ACTION_CONFIDENTIAL_BATCH)
        .push_bytes32(&category_id)
        .push_bytes32(&period_tag)
        .push_u64(total_amount)
        .push_u64(u64::from(is_paid_now))
        .finish();
    let (_registry, charter, acc, _caller) =
        require_accounting_ops_auth(&SEL_POST_CONF_PAY, &ah, &auth_obj)?;

    let mut cat = load_conf_cat(&category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;
    if cat.kind != CONF_CAT_PAYROLL && cat.kind != CONF_CAT_VENDOR_OPEX {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }
    let (audit_epoch, audit_pk) = query_charter_audit_epoch(&charter)?;

    let slot_count = u16::from_be_bytes([locks_and_envs[0], locks_and_envs[1]]) as usize;
    if slot_count < (cat.min_slots as usize) {
        return Err(ERR_IFRS_CONF_PADDING_TOO_SMALL);
    }
    if slot_count > MAX_CONF_BATCH_SLOTS || range_proofs.len() != slot_count * CONF_RANGE_PROOF_BYTES
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    let batch_id = storage::get_u64(KEY_CONF_BATCH_CNT);
    let me = context::self_address();
    let mut ctx_prefix = [0u8; 108];
    ctx_prefix[0..16].copy_from_slice(b"SLX_CONF_PBAT_1:");
    ctx_prefix[16..36].copy_from_slice(&me);
    ctx_prefix[36..68].copy_from_slice(&category_id);
    ctx_prefix[68..100].copy_from_slice(&period_tag);
    ctx_prefix[100..108].copy_from_slice(&batch_id.to_be_bytes());

    let mut slot_cts = [[0u8; 64]; MAX_CONF_BATCH_SLOTS];
    let mut c_sum = IDENTITY_CIPHERTEXT_64;
    let mut s = 0usize;
    while s < slot_count {
        let p_off = s * CONF_RANGE_PROOF_BYTES;
        let ct_i = verify_he_range_u24(
            &audit_pk,
            &ctx_prefix,
            s as u32,
            &range_proofs[p_off..p_off + CONF_RANGE_PROOF_BYTES],
        )
        .ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        c_sum = he_add_ciphertexts(&c_sum, &ct_i).ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        slot_cts[s] = ct_i;
        s += 1;
    }

    let (_bank, treas) = query_accounting_bank_and_treasury(&acc)?;
    let batch_tag32 = compute_batch_tag(batch_id);
    // Note: `acc` (`AccountingLedger`) is `verifier_hfs` inside `AssetLedger.fundVerifiedShieldedBatch`,
    // so `sum_ctx` binds `acc` (`[16..36]`) + `treas` (`[36..56]`) + `batch_tag32` + `total_amount`!
    let mut sum_ctx = [0u8; 96];
    sum_ctx[0..16].copy_from_slice(b"SLX_CONF_BSUM_1:");
    sum_ctx[16..36].copy_from_slice(&acc);
    sum_ctx[36..56].copy_from_slice(&treas);
    sum_ctx[56..88].copy_from_slice(&batch_tag32);
    sum_ctx[88..96].copy_from_slice(&total_amount.to_be_bytes());

    let mut sum_dleq = [0u8; 64];
    sum_dleq.copy_from_slice(sum_dleq_slice);
    if !verify_he_sum_equals_u64(&audit_pk, &c_sum, total_amount, &sum_ctx, &sum_dleq) {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    const MAX_PACKED_SLOTS: usize = 2 + MAX_CONF_BATCH_SLOTS * (98 + MAX_CONF_LINE_ENV);
    let mut packed_slots = [0u8; MAX_PACKED_SLOTS];
    packed_slots[0..2].copy_from_slice(&(slot_count as u16).to_be_bytes());
    let mut in_pos = 2usize;
    let mut out_pos = 2usize;
    let mut idx = 0usize;
    while idx < slot_count {
        if in_pos + 34 > locks_and_envs.len() {
            return Err(ERR_IFRS_CONF_PROOF_INVALID);
        }
        let elen =
            u16::from_be_bytes([locks_and_envs[in_pos + 32], locks_and_envs[in_pos + 33]]) as usize;
        if elen > MAX_CONF_LINE_ENV
            || in_pos + 34 + elen > locks_and_envs.len()
            || out_pos + 98 + elen > MAX_PACKED_SLOTS
        {
            return Err(ERR_IFRS_CONF_PROOF_INVALID);
        }
        packed_slots[out_pos..out_pos + 32]
            .copy_from_slice(&locks_and_envs[in_pos..in_pos + 32]);
        packed_slots[out_pos + 32..out_pos + 96].copy_from_slice(&slot_cts[idx]);
        packed_slots[out_pos + 96..out_pos + 98].copy_from_slice(&(elen as u16).to_be_bytes());
        packed_slots[out_pos + 98..out_pos + 98 + elen]
            .copy_from_slice(&locks_and_envs[in_pos + 34..in_pos + 34 + elen]);
        in_pos += 34 + elen;
        out_pos += 98 + elen;
        idx += 1;
    }

    let first_note_id = if is_paid_now {
        call_fund_shielded_batch_on_accounting(
            &acc,
            &batch_tag32,
            total_amount,
            &audit_pk,
            &sum_dleq,
            &packed_slots[..out_pos],
        )?
    } else {
        u64::MAX
    };

    let rollup_kind = if cat.kind == CONF_CAT_PAYROLL {
        ROLLUP_PAYROLL_RUN
    } else {
        ROLLUP_VENDOR_OPEX
    };
    let j_id = call_book_rollup_on_accounting(&acc, rollup_kind, total_amount, is_paid_now)?;

    cat.batch_count = cat.batch_count.saturating_add(1);
    cat.total_posted = cat.total_posted.saturating_add(total_amount);
    if is_paid_now {
        cat.settled_cash = cat.settled_cash.saturating_add(total_amount);
    } else {
        cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_add(total_amount);
    }
    save_conf_cat(&cat)?;

    save_conf_batch_record(
        batch_id,
        &category_id,
        &period_tag,
        audit_epoch,
        cat.kind,
        1,
        is_paid_now,
        slot_count as u8,
        total_amount,
        first_note_id,
        j_id,
        &c_sum,
        &sum_dleq,
        audit_cipher,
        &packed_slots[..out_pos],
    );

    ret::write_u64_word(batch_id);
    Ok(())
}

fn handle_settle_accrued_confidential_batch(args: &CalldataReader) -> Result<(), i32> {
    let batch_id = args.u64(0).ok_or(-3)?;
    let auth_obj = args.address(1).ok_or(-3)?;

    let mut hdr = [0u8; FIXED_CONF_BATCH_HDR];
    if storage::get_into(conf_batch_hdr_key(batch_id).as_slice(), &mut hdr)
        != Some(FIXED_CONF_BATCH_HDR)
    {
        return Err(ERR_IFRS_SUBLEDGER_NOT_FOUND);
    }
    if hdr[73] != 1 || hdr[74] != 0 {
        return Err(ERR_IFRS_NOTHING_TO_POST);
    }
    let total_amount = read_u64_be(&hdr, 76);
    let ah = ActionHasher::<128>::new(&context::self_address(), &ACTION_IFRS_DISBURSE)
        .push_u64(batch_id)
        .push_u64(total_amount)
        .finish();
    let (_registry, charter, acc, _caller) =
        require_accounting_ops_auth(&SEL_SETTLE_CONF_PAY, &ah, &auth_obj)?;

    let audit_epoch = read_u64_be(&hdr, 64);
    let audit_pk = query_charter_audit_pk_for_epoch(&charter, audit_epoch)?;
    let mut sum_dleq = [0u8; 64];
    sum_dleq.copy_from_slice(&hdr[172..236]);

    const MAX_PACKED_SLOTS: usize = 2 + MAX_CONF_BATCH_SLOTS * (98 + MAX_CONF_LINE_ENV);
    let mut packed_slots = [0u8; MAX_PACKED_SLOTS];
    let n = storage::get_into(conf_batch_slots_key(batch_id).as_slice(), &mut packed_slots)
        .ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;

    let batch_tag32 = compute_batch_tag(batch_id);
    let first_note_id = call_fund_shielded_batch_on_accounting(
        &acc,
        &batch_tag32,
        total_amount,
        &audit_pk,
        &sum_dleq,
        &packed_slots[..n],
    )?;

    let rollup_kind = if hdr[72] == CONF_CAT_PAYROLL {
        ROLLUP_PAYROLL_SETTLE
    } else {
        ROLLUP_PAYABLE_SETTLE
    };
    let _ = call_book_rollup_on_accounting(&acc, rollup_kind, total_amount, true)?;

    hdr[74] = 1;
    hdr[84..92].copy_from_slice(&first_note_id.to_be_bytes());
    storage::set(conf_batch_hdr_key(batch_id).as_slice(), &hdr);

    let mut cat_id = [0u8; 32];
    cat_id.copy_from_slice(&hdr[0..32]);
    if let Some(mut cat) = load_conf_cat(&cat_id) {
        cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_sub(total_amount);
        cat.settled_cash = cat.settled_cash.saturating_add(total_amount);
        let _ = save_conf_cat(&cat);
    }

    ret::write_u64_word(first_note_id);
    Ok(())
}

const FIXED_CONF_REC_HDR: usize = 324;

#[derive(Clone, Copy)]
struct ConfReceivableRow {
    category_id: [u8; 32],
    period_tag: [u8; 32],
    audit_epoch: u64,
    status: u8,
    total_months: u32,
    billed_months: u32,
    month_blocks: u64,
    start_block: u64,
    stealth_h: [u8; 32],
    blind_pk: [u8; 32],
    claim_lock: [u8; 32],
    c_monthly: [u8; 64],
    c_backlog: [u8; 64],
}

fn save_conf_rec_hdr(rec_id: u64, row: &ConfReceivableRow) {
    let mut b = [0u8; FIXED_CONF_REC_HDR];
    b[0..32].copy_from_slice(&row.category_id);
    b[32..64].copy_from_slice(&row.period_tag);
    b[64..72].copy_from_slice(&row.audit_epoch.to_be_bytes());
    b[72] = row.status;
    b[76..80].copy_from_slice(&row.total_months.to_be_bytes());
    b[80..84].copy_from_slice(&row.billed_months.to_be_bytes());
    b[84..92].copy_from_slice(&row.month_blocks.to_be_bytes());
    b[92..100].copy_from_slice(&row.start_block.to_be_bytes());
    b[100..132].copy_from_slice(&row.stealth_h);
    b[132..164].copy_from_slice(&row.blind_pk);
    b[164..196].copy_from_slice(&row.claim_lock);
    b[196..260].copy_from_slice(&row.c_monthly);
    b[260..324].copy_from_slice(&row.c_backlog);
    storage::set(conf_rec_hdr_key(rec_id).as_slice(), &b);
}

fn load_conf_rec_hdr(rec_id: u64) -> Option<ConfReceivableRow> {
    if rec_id >= storage::get_u64(KEY_CONF_REC_CNT) {
        return None;
    }
    let mut b = [0u8; FIXED_CONF_REC_HDR];
    if storage::get_into(conf_rec_hdr_key(rec_id).as_slice(), &mut b) != Some(FIXED_CONF_REC_HDR) {
        return None;
    }
    let mut category_id = [0u8; 32];
    let mut period_tag = [0u8; 32];
    let mut tm = [0u8; 4];
    let mut bm = [0u8; 4];
    let mut stealth_h = [0u8; 32];
    let mut blind_pk = [0u8; 32];
    let mut claim_lock = [0u8; 32];
    let mut c_monthly = [0u8; 64];
    let mut c_backlog = [0u8; 64];
    category_id.copy_from_slice(&b[0..32]);
    period_tag.copy_from_slice(&b[32..64]);
    tm.copy_from_slice(&b[76..80]);
    bm.copy_from_slice(&b[80..84]);
    stealth_h.copy_from_slice(&b[100..132]);
    blind_pk.copy_from_slice(&b[132..164]);
    claim_lock.copy_from_slice(&b[164..196]);
    c_monthly.copy_from_slice(&b[196..260]);
    c_backlog.copy_from_slice(&b[260..324]);
    Some(ConfReceivableRow {
        category_id,
        period_tag,
        audit_epoch: read_u64_be(&b, 64),
        status: b[72],
        total_months: u32::from_be_bytes(tm),
        billed_months: u32::from_be_bytes(bm),
        month_blocks: read_u64_be(&b, 84),
        start_block: read_u64_be(&b, 92),
        stealth_h,
        blind_pk,
        claim_lock,
        c_monthly,
        c_backlog,
    })
}

fn compute_propose_conf_rec_hash(
    category_id: &[u8; 32],
    period_tag: &[u8; 32],
    total_months: u64,
    month_blocks: u64,
    stealth_h: &[u8; 32],
    blind_pk: &[u8; 32],
    claim_lock: &[u8; 32],
) -> [u8; 32] {
    ActionHasher::<256>::new(&context::self_address(), &ACTION_CONFIDENTIAL_RECEIVABLE)
        .push_bytes32(category_id)
        .push_bytes32(period_tag)
        .push_u64(total_months)
        .push_u64(month_blocks)
        .push_bytes32(stealth_h)
        .push_bytes32(blind_pk)
        .push_bytes32(claim_lock)
        .finish()
}

fn handle_hash_propose_confidential_receivable(args: &CalldataReader) -> Result<(), i32> {
    let cat = args.bytes32(0).ok_or(-3)?;
    let per = args.bytes32(1).ok_or(-3)?;
    let tm = args.u64(2).ok_or(-3)?;
    let mb = args.u64(3).ok_or(-3)?;
    let sh = args.bytes32(4).ok_or(-3)?;
    let bp = args.bytes32(5).ok_or(-3)?;
    let cl = args.bytes32(6).ok_or(-3)?;
    ret::write_word(&compute_propose_conf_rec_hash(
        &cat, &per, tm, mb, &sh, &bp, &cl,
    ));
    Ok(())
}

fn handle_propose_confidential_receivable(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let period_tag = args.bytes32(1).ok_or(-3)?;
    let total_months = args.u64(2).ok_or(-3)?;
    let month_blocks = args.u64(3).ok_or(-3)?;
    let stealth_h = args.bytes32(4).ok_or(-3)?;
    let blind_pk = args.bytes32(5).ok_or(-3)?;
    let claim_lock = args.bytes32(6).ok_or(-3)?;
    let monthly_range_proof = args.dynamic_bytes(7).ok_or(-3)?;
    let audit_env = args.dynamic_bytes(8).ok_or(-3)?;
    let client_env = args.dynamic_bytes(9).ok_or(-3)?;
    let auth_obj = args.address(10).ok_or(-3)?;

    if stealth_h == [0u8; 32]
        || stealth_h == IDENTITY_POINT_BYTES
        || blind_pk == [0u8; 32]
        || blind_pk == IDENTITY_POINT_BYTES
        || claim_lock == [0u8; 32]
        || claim_lock == IDENTITY_POINT_BYTES
        || monthly_range_proof.len() != CONF_RANGE_PROOF_BYTES
        || audit_env.len() > MAX_CONF_REC_ENV
        || client_env.len() > MAX_CONF_REC_ENV
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    let ah = compute_propose_conf_rec_hash(
        &category_id,
        &period_tag,
        total_months,
        month_blocks,
        &stealth_h,
        &blind_pk,
        &claim_lock,
    );
    let (_registry, charter, _acc, _caller) =
        require_board_level_auth(&SEL_PROP_CONF_REC, &ah, &auth_obj)?;

    let cat = load_conf_cat(&category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;
    if cat.kind == CONF_CAT_DEFENSE_B2B {
        if !(MIN_SERVICE_CONTRACT_MONTHS..=MAX_SERVICE_CONTRACT_MONTHS).contains(&total_months)
            || !(MIN_SERVICE_MONTH_BLOCKS..=MAX_SERVICE_MONTH_BLOCKS).contains(&month_blocks)
        {
            return Err(ERR_IFRS_INVALID_CONTRACT_DURATION);
        }
    } else if cat.kind == CONF_CAT_TRADE_AR {
        if total_months != 1
            || !(MIN_SERVICE_MONTH_BLOCKS..=MAX_SERVICE_MONTH_BLOCKS).contains(&month_blocks)
        {
            return Err(ERR_IFRS_INVALID_CONTRACT_DURATION);
        }
    } else {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }

    let (audit_epoch, audit_pk) = query_charter_audit_epoch(&charter)?;
    let rec_id = storage::get_u64(KEY_CONF_REC_CNT);

    let me = context::self_address();
    let mut ctx_prefix = [0u8; 108];
    ctx_prefix[0..16].copy_from_slice(b"SLX_CONF_RPRP_1:");
    ctx_prefix[16..36].copy_from_slice(&me);
    ctx_prefix[36..68].copy_from_slice(&category_id);
    ctx_prefix[68..100].copy_from_slice(&period_tag);
    ctx_prefix[100..108].copy_from_slice(&rec_id.to_be_bytes());

    let c_monthly = verify_he_range_u24(&audit_pk, &ctx_prefix, rec_id as u32, monthly_range_proof)
        .ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
    let c_backlog = if total_months == 1 {
        c_monthly
    } else {
        he_scale_ciphertext(&c_monthly, total_months).ok_or(ERR_IFRS_CONF_PROOF_INVALID)?
    };

    let row = ConfReceivableRow {
        category_id,
        period_tag,
        audit_epoch,
        status: 1,
        total_months: total_months as u32,
        billed_months: 0,
        month_blocks,
        start_block: 0,
        stealth_h,
        blind_pk,
        claim_lock,
        c_monthly,
        c_backlog,
    };
    save_conf_rec_hdr(rec_id, &row);
    if !audit_env.is_empty() {
        storage::set(conf_rec_aud_key(rec_id).as_slice(), audit_env);
    }
    if !client_env.is_empty() {
        storage::set(conf_rec_cli_key(rec_id).as_slice(), client_env);
    }
    storage::set_u64(KEY_CONF_REC_CNT, rec_id + 1);

    events::emit(
        &[EV_CONF_REC_UPDATED, u64_topic(rec_id), category_id],
        &1u64.to_be_bytes(),
    );
    ret::write_u64_word(rec_id);
    Ok(())
}

fn handle_stealth_cosign_confidential_receivable(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, charter, acc) = ensure_active()?;
    let rec_id = args.u64(0).ok_or(-3)?;
    let public_live_total = args.u64(1).ok_or(-3)?;
    let cosign_sig_slice = args.dynamic_bytes(2).ok_or(-3)?;
    let ias24_proof_blob = args.dynamic_bytes(3).ok_or(-3)?;
    let live_dleq_slice = args.dynamic_bytes(4).ok_or(-3)?;

    if cosign_sig_slice.len() != 64 {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let mut row = load_conf_rec_hdr(rec_id).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
    if row.status != 1 {
        return Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
    }
    let mut cat = load_conf_cat(&row.category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;

    let me = context::self_address();
    let mut cosign_ctx = [0u8; 108];
    cosign_ctx[0..16].copy_from_slice(b"SLX_CONF_RCOS_1:");
    cosign_ctx[16..36].copy_from_slice(&me);
    cosign_ctx[36..44].copy_from_slice(&rec_id.to_be_bytes());
    cosign_ctx[44..108].copy_from_slice(&row.c_backlog);

    let mut cosign_sig = [0u8; 64];
    cosign_sig.copy_from_slice(cosign_sig_slice);
    if !verify_ed25519_schnorr(&row.stealth_h, &row.blind_pk, &cosign_ctx, &cosign_sig) {
        return Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED);
    }

    let mut insider_pks = [[0u8; 32]; MAX_IAS24_INSIDER_PKS];
    let ins_cnt = query_charter_insider_pks(&charter, &mut insider_pks)?;
    let mut ias_ctx = [0u8; 44];
    ias_ctx[0..16].copy_from_slice(b"SLX_CONF_RIAS_1:");
    ias_ctx[16..36].copy_from_slice(&me);
    ias_ctx[36..44].copy_from_slice(&rec_id.to_be_bytes());

    if !verify_stealth_non_insider(
        &row.stealth_h,
        &row.blind_pk,
        &insider_pks[..ins_cnt],
        &ias_ctx,
        ias24_proof_blob,
    ) {
        return Err(ERR_IFRS_RELATED_PARTY_CREDIT_BANNED);
    }

    row.start_block = context::block_number();

    if cat.mode == CONF_MODE_BATCH_OR_EPOCH {
        if public_live_total != 0 || !live_dleq_slice.is_empty() {
            return Err(ERR_IFRS_CONF_PROOF_INVALID);
        }
        row.status = 2;
        save_conf_rec_hdr(rec_id, &row);
        events::emit(
            &[EV_CONF_REC_UPDATED, u64_topic(rec_id), row.category_id],
            &2u64.to_be_bytes(),
        );
        ret::write_u64_word(2);
        return Ok(());
    }

    if public_live_total == 0 || live_dleq_slice.len() != 64 {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let audit_pk = query_charter_audit_pk_for_epoch(&charter, row.audit_epoch)?;
    let mut live_ctx = [0u8; 52];
    live_ctx[0..16].copy_from_slice(b"SLX_CONF_RLIV_1:");
    live_ctx[16..36].copy_from_slice(&me);
    live_ctx[36..44].copy_from_slice(&rec_id.to_be_bytes());
    live_ctx[44..52].copy_from_slice(&public_live_total.to_be_bytes());

    let mut live_dleq = [0u8; 64];
    live_dleq.copy_from_slice(live_dleq_slice);
    if !verify_he_sum_equals_u64(&audit_pk, &row.c_backlog, public_live_total, &live_ctx, &live_dleq)
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    let rollup_kind = if cat.kind == CONF_CAT_DEFENSE_B2B {
        row.status = 3;
        cat.active_backlog = cat.active_backlog.saturating_add(public_live_total);
        ROLLUP_DEFENSE_LIVE
    } else {
        row.status = 4;
        cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_add(public_live_total);
        ROLLUP_TRADE_AR
    };
    save_conf_rec_hdr(rec_id, &row);

    let j_id = call_book_rollup_on_accounting(&acc, rollup_kind, public_live_total, false)?;
    cat.batch_count = cat.batch_count.saturating_add(1);
    cat.total_posted = cat.total_posted.saturating_add(public_live_total);
    save_conf_cat(&cat)?;

    let batch_id = storage::get_u64(KEY_CONF_BATCH_CNT);
    save_conf_batch_record(
        batch_id,
        &row.category_id,
        &row.period_tag,
        row.audit_epoch,
        cat.kind,
        2,
        false,
        cat.min_slots,
        public_live_total,
        u64::MAX,
        j_id,
        &row.c_backlog,
        &live_dleq,
        &[],
        &[],
    );

    events::emit(
        &[EV_CONF_REC_UPDATED, u64_topic(rec_id), row.category_id],
        &(row.status as u64).to_be_bytes(),
    );
    ret::write_u64_word(j_id);
    Ok(())
}

fn verify_and_sum_dummy_padded_epoch(
    audit_pk: &[u8; 32],
    c_real_sum: &[u8; 64],
    dummy_tag16: &[u8; 16],
    sum_tag16: &[u8; 16],
    category_id: &[u8; 32],
    period_tag: &[u8; 32],
    batch_id: u64,
    public_total: u64,
    dummy_proofs: &[u8],
    sum_dleq_slice: &[u8],
) -> Result<([u8; 64], [u8; 64]), i32> {
    let dummy_cnt = dummy_proofs.len() / CONF_RANGE_PROOF_BYTES;
    let me = context::self_address();
    let mut dummy_prefix = [0u8; 108];
    dummy_prefix[0..16].copy_from_slice(dummy_tag16);
    dummy_prefix[16..36].copy_from_slice(&me);
    dummy_prefix[36..68].copy_from_slice(category_id);
    dummy_prefix[68..100].copy_from_slice(period_tag);
    dummy_prefix[100..108].copy_from_slice(&batch_id.to_be_bytes());

    let mut c_sum = *c_real_sum;
    let mut d = 0usize;
    while d < dummy_cnt {
        let off = d * CONF_RANGE_PROOF_BYTES;
        let dct = verify_he_range_u24(
            audit_pk,
            &dummy_prefix,
            d as u32,
            &dummy_proofs[off..off + CONF_RANGE_PROOF_BYTES],
        )
        .ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        c_sum = he_add_ciphertexts(&c_sum, &dct).ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        d += 1;
    }

    let mut sum_ctx = [0u8; 116];
    sum_ctx[0..16].copy_from_slice(sum_tag16);
    sum_ctx[16..36].copy_from_slice(&me);
    sum_ctx[36..68].copy_from_slice(category_id);
    sum_ctx[68..100].copy_from_slice(period_tag);
    sum_ctx[100..108].copy_from_slice(&batch_id.to_be_bytes());
    sum_ctx[108..116].copy_from_slice(&public_total.to_be_bytes());

    let mut sum_dleq = [0u8; 64];
    sum_dleq.copy_from_slice(sum_dleq_slice);
    if !verify_he_sum_equals_u64(audit_pk, &c_sum, public_total, &sum_ctx, &sum_dleq) {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    Ok((c_sum, sum_dleq))
}

fn handle_flush_confidential_receivable_epoch(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let period_tag = args.bytes32(1).ok_or(-3)?;
    let public_rollup_total = args.u64(2).ok_or(-3)?;
    let staged_ids_raw = args.dynamic_bytes(3).ok_or(-3)?;
    let dummy_proofs = args.dynamic_bytes(4).ok_or(-3)?;
    let sum_dleq_slice = args.dynamic_bytes(5).ok_or(-3)?;
    let audit_cipher = args.dynamic_bytes(6).ok_or(-3)?;
    let auth_obj = args.address(7).ok_or(-3)?;

    if public_rollup_total == 0
        || staged_ids_raw.is_empty()
        || staged_ids_raw.len() % 8 != 0
        || dummy_proofs.len() % CONF_RANGE_PROOF_BYTES != 0
        || sum_dleq_slice.len() != 64
        || audit_cipher.len() > MAX_CONF_AUDIT_CIPHER
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let ah = ActionHasher::<192>::new(&context::self_address(), &ACTION_CONFIDENTIAL_BATCH)
        .push_bytes32(&category_id)
        .push_bytes32(&period_tag)
        .push_u64(public_rollup_total)
        .push_bytes32(&keccak256(staged_ids_raw))
        .finish();
    let (_registry, charter, acc, _caller) =
        require_accounting_ops_auth(&SEL_FLUSH_CONF_REC, &ah, &auth_obj)?;

    let mut cat = load_conf_cat(&category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;
    if cat.kind != CONF_CAT_DEFENSE_B2B && cat.kind != CONF_CAT_TRADE_AR {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }

    let real_cnt = staged_ids_raw.len() / 8;
    let dummy_cnt = dummy_proofs.len() / CONF_RANGE_PROOF_BYTES;
    let total_slots = real_cnt + dummy_cnt;
    if total_slots < (cat.min_slots as usize) {
        return Err(ERR_IFRS_CONF_PADDING_TOO_SMALL);
    }
    if total_slots > MAX_CONF_BATCH_SLOTS {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    let mut ids = [0u64; MAX_CONF_BATCH_SLOTS];
    let mut c_sum_real = IDENTITY_CIPHERTEXT_64;
    let mut epoch_used = 0u64;
    let mut i = 0usize;
    while i < real_cnt {
        let rid = read_u64_be(staged_ids_raw, i * 8);
        let mut p = 0usize;
        while p < i {
            if ids[p] == rid {
                return Err(ERR_IFRS_CONF_PROOF_INVALID);
            }
            p += 1;
        }
        let r = load_conf_rec_hdr(rid).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
        if r.status != 2 || r.category_id != category_id {
            return Err(ERR_IFRS_NOTHING_TO_POST);
        }
        if i == 0 {
            epoch_used = r.audit_epoch;
        } else if r.audit_epoch != epoch_used {
            return Err(ERR_IFRS_CONF_PROOF_INVALID);
        }
        c_sum_real = he_add_ciphertexts(&c_sum_real, &r.c_backlog).ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        ids[i] = rid;
        i += 1;
    }

    let audit_pk = query_charter_audit_pk_for_epoch(&charter, epoch_used)?;
    let batch_id = storage::get_u64(KEY_CONF_BATCH_CNT);
    let (c_sum, sum_dleq) = verify_and_sum_dummy_padded_epoch(
        &audit_pk,
        &c_sum_real,
        b"SLX_CONF_EFLS_1:",
        b"SLX_CONF_ESUM_1:",
        &category_id,
        &period_tag,
        batch_id,
        public_rollup_total,
        dummy_proofs,
        sum_dleq_slice,
    )?;

    let next_status = if cat.kind == CONF_CAT_DEFENSE_B2B { 3 } else { 4 };
    i = 0;
    while i < real_cnt {
        if let Some(mut r) = load_conf_rec_hdr(ids[i]) {
            r.status = next_status;
            save_conf_rec_hdr(ids[i], &r);
            events::emit(
                &[EV_CONF_REC_UPDATED, u64_topic(ids[i]), category_id],
                &(next_status as u64).to_be_bytes(),
            );
        }
        i += 1;
    }

    let rollup_kind = if cat.kind == CONF_CAT_DEFENSE_B2B {
        cat.active_backlog = cat.active_backlog.saturating_add(public_rollup_total);
        ROLLUP_DEFENSE_BACKLOG
    } else {
        cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_add(public_rollup_total);
        ROLLUP_TRADE_AR
    };
    let j_id = call_book_rollup_on_accounting(&acc, rollup_kind, public_rollup_total, false)?;

    cat.batch_count = cat.batch_count.saturating_add(1);
    cat.total_posted = cat.total_posted.saturating_add(public_rollup_total);
    save_conf_cat(&cat)?;

    save_conf_batch_record(
        batch_id,
        &category_id,
        &period_tag,
        epoch_used,
        cat.kind,
        2,
        false,
        total_slots as u8,
        public_rollup_total,
        u64::MAX,
        j_id,
        &c_sum,
        &sum_dleq,
        audit_cipher,
        staged_ids_raw,
    );

    ret::write_u64_word(batch_id);
    Ok(())
}

fn handle_bill_confidential_category_epoch(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let period_tag = args.bytes32(1).ok_or(-3)?;
    let public_billed_total = args.u64(2).ok_or(-3)?;
    let rec_ids_raw = args.dynamic_bytes(3).ok_or(-3)?;
    let dummy_proofs = args.dynamic_bytes(4).ok_or(-3)?;
    let sum_dleq_slice = args.dynamic_bytes(5).ok_or(-3)?;
    let audit_cipher = args.dynamic_bytes(6).ok_or(-3)?;
    let auth_obj = args.address(7).ok_or(-3)?;

    if public_billed_total == 0
        || rec_ids_raw.is_empty()
        || rec_ids_raw.len() % 8 != 0
        || dummy_proofs.len() % CONF_RANGE_PROOF_BYTES != 0
        || sum_dleq_slice.len() != 64
        || audit_cipher.len() > MAX_CONF_AUDIT_CIPHER
    {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let ah = ActionHasher::<192>::new(&context::self_address(), &ACTION_CONFIDENTIAL_BATCH)
        .push_bytes32(&category_id)
        .push_bytes32(&period_tag)
        .push_u64(public_billed_total)
        .push_bytes32(&keccak256(rec_ids_raw))
        .finish();
    let (_registry, charter, acc, _caller) =
        require_accounting_ops_auth(&SEL_BILL_CONF_CAT, &ah, &auth_obj)?;

    let mut cat = load_conf_cat(&category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;
    if cat.kind != CONF_CAT_DEFENSE_B2B {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }

    let real_cnt = rec_ids_raw.len() / 8;
    let dummy_cnt = dummy_proofs.len() / CONF_RANGE_PROOF_BYTES;
    let total_slots = real_cnt + dummy_cnt;
    if total_slots < (cat.min_slots as usize) {
        return Err(ERR_IFRS_CONF_PADDING_TOO_SMALL);
    }
    if total_slots > MAX_CONF_BATCH_SLOTS {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }

    let now_block = context::block_number();
    let mut ids = [0u64; MAX_CONF_BATCH_SLOTS];
    let mut c_sum_real = IDENTITY_CIPHERTEXT_64;
    let mut epoch_used = 0u64;
    let mut i = 0usize;
    while i < real_cnt {
        let rid = read_u64_be(rec_ids_raw, i * 8);
        let mut p = 0usize;
        while p < i {
            if ids[p] == rid {
                return Err(ERR_IFRS_CONF_PROOF_INVALID);
            }
            p += 1;
        }
        let r = load_conf_rec_hdr(rid).ok_or(ERR_IFRS_SUBLEDGER_NOT_FOUND)?;
        if r.status != 3 || r.category_id != category_id || r.billed_months >= r.total_months {
            return Err(ERR_IFRS_NOTHING_TO_POST);
        }
        let next_m = (r.billed_months as u64) + 1;
        if now_block < r.start_block.saturating_add(next_m.saturating_mul(r.month_blocks)) {
            return Err(ERR_IFRS_NOTHING_TO_POST);
        }
        if i == 0 {
            epoch_used = r.audit_epoch;
        } else if r.audit_epoch != epoch_used {
            return Err(ERR_IFRS_CONF_PROOF_INVALID);
        }
        c_sum_real = he_add_ciphertexts(&c_sum_real, &r.c_monthly).ok_or(ERR_IFRS_CONF_PROOF_INVALID)?;
        ids[i] = rid;
        i += 1;
    }

    let audit_pk = query_charter_audit_pk_for_epoch(&charter, epoch_used)?;
    let batch_id = storage::get_u64(KEY_CONF_BATCH_CNT);
    let (c_sum, sum_dleq) = verify_and_sum_dummy_padded_epoch(
        &audit_pk,
        &c_sum_real,
        b"SLX_CONF_EBIL_1:",
        b"SLX_CONF_BILS_1:",
        &category_id,
        &period_tag,
        batch_id,
        public_billed_total,
        dummy_proofs,
        sum_dleq_slice,
    )?;

    i = 0;
    while i < real_cnt {
        if let Some(mut r) = load_conf_rec_hdr(ids[i]) {
            r.billed_months += 1;
            if r.billed_months >= r.total_months {
                r.status = 4;
            }
            save_conf_rec_hdr(ids[i], &r);
            events::emit(
                &[EV_CONF_REC_UPDATED, u64_topic(ids[i]), category_id],
                &(r.status as u64).to_be_bytes(),
            );
        }
        i += 1;
    }

    let j_id = call_book_rollup_on_accounting(&acc, ROLLUP_DEFENSE_BILLING, public_billed_total, false)?;

    cat.batch_count = cat.batch_count.saturating_add(1);
    cat.active_backlog = cat.active_backlog.saturating_sub(public_billed_total);
    cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_add(public_billed_total);
    save_conf_cat(&cat)?;

    save_conf_batch_record(
        batch_id,
        &category_id,
        &period_tag,
        epoch_used,
        cat.kind,
        3,
        false,
        total_slots as u8,
        public_billed_total,
        u64::MAX,
        j_id,
        &c_sum,
        &sum_dleq,
        audit_cipher,
        rec_ids_raw,
    );

    ret::write_u64_word(batch_id);
    Ok(())
}

fn handle_sweep_confidential_category_cash(args: &CalldataReader) -> Result<(), i32> {
    let category_id = args.bytes32(0).ok_or(-3)?;
    let period_tag = args.bytes32(1).ok_or(-3)?;
    let total_sweep_amt = args.u64(2).ok_or(-3)?;
    let note_ids_raw = args.dynamic_bytes(3).ok_or(-3)?;
    let sigs_and_sum = args.dynamic_bytes(4).ok_or(-3)?;
    let auth_obj = args.address(5).ok_or(-3)?;

    if total_sweep_amt == 0 || note_ids_raw.is_empty() || note_ids_raw.len() % 8 != 0 {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let ah = ActionHasher::<192>::new(&context::self_address(), &ACTION_CONFIDENTIAL_BATCH)
        .push_bytes32(&category_id)
        .push_bytes32(&period_tag)
        .push_u64(total_sweep_amt)
        .push_bytes32(&keccak256(note_ids_raw))
        .finish();
    let (_registry, charter, acc, _caller) =
        require_accounting_ops_auth(&SEL_SWEEP_CONF_CASH, &ah, &auth_obj)?;

    let mut cat = load_conf_cat(&category_id).ok_or(ERR_IFRS_CONF_CATEGORY_INVALID)?;
    if cat.kind != CONF_CAT_DEFENSE_B2B && cat.kind != CONF_CAT_TRADE_AR {
        return Err(ERR_IFRS_CONF_CATEGORY_INVALID);
    }
    let (audit_epoch, audit_pk) = query_charter_audit_epoch(&charter)?;
    let (bank, treas) = query_accounting_bank_and_treasury(&acc)?;

    const MAX_NIDS: usize = MAX_CONF_BATCH_SLOTS * 8;
    const MAX_SIGS: usize = MAX_CONF_BATCH_SLOTS * 64 + 64;
    if note_ids_raw.len() > MAX_NIDS || sigs_and_sum.len() > MAX_SIGS {
        return Err(ERR_IFRS_CONF_PROOF_INVALID);
    }
    let n_pad = (32 - (note_ids_raw.len() % 32)) % 32;
    let s_pad = (32 - (sigs_and_sum.len() % 32)) % 32;
    let t2_off = 160 + 32 + note_ids_raw.len() + n_pad;
    let cd_len = t2_off + 32 + sigs_and_sum.len() + s_pad;

    let swept = unsafe {
        let cd = &mut *core::ptr::addr_of_mut!(SLICE_BUF);
        for b in &mut cd[..4 + cd_len] {
            *b = 0;
        }
        cd[0..4].copy_from_slice(&selector(
            "sweepShieldedNotes(bytes,uint64,address,bytes32,bytes)",
        ));
        cd[28..36].copy_from_slice(&160u64.to_be_bytes());
        cd[60..68].copy_from_slice(&total_sweep_amt.to_be_bytes());
        cd[80..100].copy_from_slice(&treas);
        cd[100..132].copy_from_slice(&audit_pk);
        cd[156..164].copy_from_slice(&(t2_off as u64).to_be_bytes());
        cd[188..196].copy_from_slice(&(note_ids_raw.len() as u64).to_be_bytes());
        cd[196..196 + note_ids_raw.len()].copy_from_slice(note_ids_raw);
        let t2_start = 4 + t2_off;
        cd[t2_start + 24..t2_start + 32].copy_from_slice(&(sigs_and_sum.len() as u64).to_be_bytes());
        cd[t2_start + 32..t2_start + 32 + sigs_and_sum.len()].copy_from_slice(sigs_and_sum);
        call::call_u64(&bank, &cd[..4 + cd_len])?
    };
    if swept != total_sweep_amt {
        return Err(ERR_IFRS_BANK_CASH_SHORTFALL);
    }

    let j_id = call_book_rollup_on_accounting(&acc, ROLLUP_CASH_SWEEP, total_sweep_amt, true)?;

    cat.batch_count = cat.batch_count.saturating_add(1);
    cat.open_ar_or_ap = cat.open_ar_or_ap.saturating_sub(total_sweep_amt);
    cat.settled_cash = cat.settled_cash.saturating_add(total_sweep_amt);
    save_conf_cat(&cat)?;

    let batch_id = storage::get_u64(KEY_CONF_BATCH_CNT);
    let mut sum_dleq = [0u8; 64];
    if sigs_and_sum.len() >= 64 {
        sum_dleq.copy_from_slice(&sigs_and_sum[sigs_and_sum.len() - 64..]);
    }
    save_conf_batch_record(
        batch_id,
        &category_id,
        &period_tag,
        audit_epoch,
        cat.kind,
        4,
        true,
        (note_ids_raw.len() / 8) as u8,
        total_sweep_amt,
        u64::MAX,
        j_id,
        &IDENTITY_CIPHERTEXT_64,
        &sum_dleq,
        &[],
        note_ids_raw,
    );

    ret::write_u64_word(j_id);
    Ok(())
}

fn handle_get_confidential_categories(_args: &CalldataReader) -> Result<(), i32> {
    let seeded = storage::get_u64(KEY_CONF_CAT_SEEDED) == 1;
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SLICE_BUF);
        let mut count = 0usize;
        if seeded {
            let total = storage::get_u64(KEY_CONF_CAT_CNT).min(MAX_CONF_CATEGORIES);
            let mut i = 0u64;
            while i < total {
                if let Some(cid) = storage::get_bytes32(conf_cat_idx_key(i).as_slice()) {
                    if let Some(meta) = load_conf_cat(&cid) {
                        let enc = encode_conf_cat(&meta);
                        let off = 4 + count * FIXED_CONF_CAT_BYTES;
                        out[off..off + FIXED_CONF_CAT_BYTES].copy_from_slice(&enc);
                        count += 1;
                    }
                }
                i += 1;
            }
        } else {
            let mut i = 0usize;
            while let Some(meta) = preset_conf_cat(i) {
                let enc = encode_conf_cat(&meta);
                let off = 4 + count * FIXED_CONF_CAT_BYTES;
                out[off..off + FIXED_CONF_CAT_BYTES].copy_from_slice(&enc);
                count += 1;
                i += 1;
            }
        }
        out[0..4].copy_from_slice(&(count as u32).to_be_bytes());
        ret::write(&out[..4 + count * FIXED_CONF_CAT_BYTES]);
    }
    Ok(())
}

fn handle_get_confidential_batches_slice(args: &CalldataReader) -> Result<(), i32> {
    let offset = args.u64(0).ok_or(-3)?;
    let limit = args.u64(1).ok_or(-3)?.min(6);
    let total = storage::get_u64(KEY_CONF_BATCH_CNT);
    let end = offset.saturating_add(limit).min(total);

    const MAX_SLOTS_BLOB: usize = 2 + MAX_CONF_BATCH_SLOTS * (98 + MAX_CONF_LINE_ENV);
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SLICE_BUF);
        let out_cap = out.len();
        out[0..8].copy_from_slice(&total.to_be_bytes());

        let mut pos = 16usize;
        let mut returned = 0u64;
        let mut cur = offset;
        while cur < end {
            let mut hdr = [0u8; FIXED_CONF_BATCH_HDR];
            if storage::get_into(conf_batch_hdr_key(cur).as_slice(), &mut hdr)
                == Some(FIXED_CONF_BATCH_HDR)
            {
                let mut aud = [0u8; MAX_CONF_AUDIT_CIPHER];
                let alen =
                    storage::get_into(conf_batch_aud_key(cur).as_slice(), &mut aud).unwrap_or(0);
                let mut sl = [0u8; MAX_SLOTS_BLOB];
                let slen =
                    storage::get_into(conf_batch_slots_key(cur).as_slice(), &mut sl).unwrap_or(0);
                let need = 8 + FIXED_CONF_BATCH_HDR + 4 + alen + slen;
                if pos + need <= out_cap {
                    out[pos..pos + 8].copy_from_slice(&cur.to_be_bytes());
                    pos += 8;
                    out[pos..pos + FIXED_CONF_BATCH_HDR].copy_from_slice(&hdr);
                    pos += FIXED_CONF_BATCH_HDR;
                    out[pos..pos + 2].copy_from_slice(&(alen as u16).to_be_bytes());
                    out[pos + 2..pos + 4].copy_from_slice(&(slen as u16).to_be_bytes());
                    pos += 4;
                    if alen > 0 {
                        out[pos..pos + alen].copy_from_slice(&aud[..alen]);
                        pos += alen;
                    }
                    if slen > 0 {
                        out[pos..pos + slen].copy_from_slice(&sl[..slen]);
                        pos += slen;
                    }
                    returned += 1;
                }
            }
            cur += 1;
        }
        out[8..16].copy_from_slice(&returned.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

fn handle_get_confidential_receivables_slice(args: &CalldataReader) -> Result<(), i32> {
    let offset = args.u64(0).ok_or(-3)?;
    let limit = args.u64(1).ok_or(-3)?.min(8);
    let total = storage::get_u64(KEY_CONF_REC_CNT);
    let end = offset.saturating_add(limit).min(total);

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(SLICE_BUF);
        let out_cap = out.len();
        out[0..8].copy_from_slice(&total.to_be_bytes());

        let mut pos = 16usize;
        let mut returned = 0u64;
        let mut cur = offset;
        while cur < end {
            let mut hdr = [0u8; FIXED_CONF_REC_HDR];
            if storage::get_into(conf_rec_hdr_key(cur).as_slice(), &mut hdr)
                == Some(FIXED_CONF_REC_HDR)
            {
                let mut aud = [0u8; MAX_CONF_REC_ENV];
                let alen =
                    storage::get_into(conf_rec_aud_key(cur).as_slice(), &mut aud).unwrap_or(0);
                let mut cli = [0u8; MAX_CONF_REC_ENV];
                let clen =
                    storage::get_into(conf_rec_cli_key(cur).as_slice(), &mut cli).unwrap_or(0);
                let need = 8 + FIXED_CONF_REC_HDR + 4 + alen + clen;
                if pos + need <= out_cap {
                    out[pos..pos + 8].copy_from_slice(&cur.to_be_bytes());
                    pos += 8;
                    out[pos..pos + FIXED_CONF_REC_HDR].copy_from_slice(&hdr);
                    pos += FIXED_CONF_REC_HDR;
                    out[pos..pos + 2].copy_from_slice(&(alen as u16).to_be_bytes());
                    out[pos + 2..pos + 4].copy_from_slice(&(clen as u16).to_be_bytes());
                    pos += 4;
                    if alen > 0 {
                        out[pos..pos + alen].copy_from_slice(&aud[..alen]);
                        pos += alen;
                    }
                    if clen > 0 {
                        out[pos..pos + clen].copy_from_slice(&cli[..clen]);
                        pos += clen;
                    }
                    returned += 1;
                }
            }
            cur += 1;
        }
        out[8..16].copy_from_slice(&returned.to_be_bytes());
        ret::write(&out[..pos]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::CHARTER_STATE_ACTIVE;
    use hps_sdk::mock;
    use hps_sdk::vrf::mock_crypto::{
        derive_ed25519_keypair, prove_ed25519_schnorr, prove_he_range_u24, prove_he_sum_equals_u64,
        prove_stealth_non_insider, Scalar,
    };
    use std::cell::RefCell;

    thread_local! {
        static MOCK_AUDIT_PK: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static MOCK_INSIDER_PK: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static LAST_ROLLUP_TOTAL: RefCell<u64> = const { RefCell::new(0) };
        static SHIELDED_FUNDED_TOTAL: RefCell<u64> = const { RefCell::new(0) };
    }

    fn pad_bytes_tail(out: &mut Vec<u8>, data: &[u8]) {
        let mut lw = [0u8; 32];
        lw[24..32].copy_from_slice(&(data.len() as u64).to_be_bytes());
        out.extend_from_slice(&lw);
        out.extend_from_slice(data);
        let pad = (32 - (data.len() % 32)) % 32;
        if pad > 0 {
            out.extend(std::iter::repeat_n(0u8, pad));
        }
    }

    #[test]
    fn confidential_payroll_and_defense_epoch_rollup_end_to_end() {
        mock::reset();
        mock::set_block_number(100);

        let reg = [0x01u8; 20];
        let charter = [0x02u8; 20];
        let acc = [0x03u8; 20];
        let _bank = [0x04u8; 20];
        let treas = [0x05u8; 20];
        let conf = [0x06u8; 20];
        let dir1 = [0x11u8; 20];
        let ephem_relayer = [0xeeu8; 20]; // $0-gas ephemeral EOA (NOT a registered Identity!)

        let (_sk_audit, pk_audit) = derive_ed25519_keypair(&[0xa1; 32], b"AUDIT_EP1");
        let (sk_dir1, pk_dir1) = derive_ed25519_keypair(&[0xb1; 32], b"DIR1_INSIDER");
        let (sk_def_a, pk_def_a) = derive_ed25519_keypair(&[0xc1; 32], b"DEFENSE_CLIENT_A");
        let (sk_def_b, pk_def_b) = derive_ed25519_keypair(&[0xc2; 32], b"DEFENSE_CLIENT_B");

        MOCK_AUDIT_PK.with(|p| *p.borrow_mut() = pk_audit);
        MOCK_INSIDER_PK.with(|p| *p.borrow_mut() = pk_dir1);
        LAST_ROLLUP_TOTAL.with(|v| *v.borrow_mut() = 0);
        SHIELDED_FUNDED_TOTAL.with(|v| *v.borrow_mut() = 0);

        // Mock IdentityRegistry (`dir1` is a valid Identity; `ephem_relayer` is NOT!)
        mock::register_hps(reg, |cd| {
            let Some((sel, r)) = CalldataReader::parse(cd) else {
                return -1;
            };
            if sel == selector("isValidIdentity(address)") {
                let who = r.address(0).unwrap_or([0u8; 20]);
                ret::write_bool(who == [0x11u8; 20]);
                return 0;
            }
            -2
        });

        // Mock CorporateCharter (sole director `dir1`, Epoch 1 `pk_audit`, insider `[dir1]`)
        mock::register_hps(charter, |cd| {
            let Some((sel, _r)) = CalldataReader::parse(cd) else {
                return -1;
            };
            if sel == selector("state()") {
                ret::write_u64_word(CHARTER_STATE_ACTIVE);
                return 0;
            }
            if sel == selector("directorCount()") {
                ret::write_u64_word(1);
                return 0;
            }
            if sel == selector("isDirector(address)") {
                ret::write_bool(true);
                return 0;
            }
            if sel == selector("hasRole(bytes32,address)") {
                ret::write_bool(false);
                return 0;
            }
            if sel == selector("getFunctionAuth(address,bytes4)") {
                ret::write(&[0u8; 64]);
                return 0;
            }
            if sel == selector("getAuditEpochState()") {
                let mut out = [0u8; 48];
                out[0..8].copy_from_slice(&1u64.to_be_bytes());
                MOCK_AUDIT_PK.with(|p| out[8..40].copy_from_slice(&*p.borrow()));
                ret::write(&out);
                return 0;
            }
            if sel == selector("getAuditPubKey(uint64)") {
                MOCK_AUDIT_PK.with(|p| ret::write(&*p.borrow()));
                return 0;
            }
            if sel == selector("getIas24InsiderEdPubKeys()") {
                let mut out = [0u8; 54];
                out[0..2].copy_from_slice(&1u16.to_be_bytes());
                out[2..22].copy_from_slice(&[0x11u8; 20]);
                MOCK_INSIDER_PK.with(|p| out[22..54].copy_from_slice(&*p.borrow()));
                ret::write(&out);
                return 0;
            }
            -2
        });

        // Mock AccountingLedger
        mock::register_hps(acc, |cd| {
            let Some((sel, r)) = CalldataReader::parse(cd) else {
                return -1;
            };
            if sel == selector("associatedCharter()") {
                ret::write_address(&[0x02u8; 20]);
                return 0;
            }
            if sel == selector("operatingBankLedger()") {
                ret::write_address(&[0x04u8; 20]);
                return 0;
            }
            if sel == selector("treasuryIdentity()") {
                ret::write_address(&[0x05u8; 20]);
                return 0;
            }
            if sel == selector("fundShieldedBatchFromModule(bytes32,uint64,bytes32,bytes,bytes)") {
                let amt = r.u64(1).unwrap();
                SHIELDED_FUNDED_TOTAL.with(|v| *v.borrow_mut() += amt);
                ret::write_u64_word(0);
                return 0;
            }
            if sel == selector("bookConfidentialRollupFromModule(uint64,uint64,bool)") {
                let amt = r.u64(1).unwrap();
                LAST_ROLLUP_TOTAL.with(|v| *v.borrow_mut() = amt);
                ret::write_u64_word(1);
                return 0;
            }
            -2
        });

        mock::register_hps(conf, dispatch_calldata);

        // Initialize ConfidentialLedger
        let init_cd = CallEncoder::<160>::new(const {
            selector("initialize(address,address,address,address)")
        })
        .push_address(&reg)
        .push_address(&[0u8; 20])
        .push_address(&charter)
        .push_address(&acc);
        mock::transact_as(dir1, conf, init_cd.as_slice()).unwrap();

        // 1. Confidential Monthly Payroll Batch (3 employees + 1 zero-value dummy = 4 slots)
        let period = *b"FY2026_M11_PAYROLL______________";
        let salaries = [14_000u64, 19_500u64, 11_500u64, 0u64];
        let total_payroll: u64 = salaries.iter().sum();

        let mut pbat_prefix = [0u8; 108];
        pbat_prefix[0..16].copy_from_slice(b"SLX_CONF_PBAT_1:");
        pbat_prefix[16..36].copy_from_slice(&conf);
        pbat_prefix[36..68].copy_from_slice(&CAT_ID_PAYROLL);
        pbat_prefix[68..100].copy_from_slice(&period);
        pbat_prefix[100..108].copy_from_slice(&0u64.to_be_bytes());

        let mut proofs_blob = Vec::new();
        let mut locks_blob = Vec::new();
        locks_blob.extend_from_slice(&4u16.to_be_bytes());
        let mut r_sum = Scalar::ZERO;
        for (idx, &sal) in salaries.iter().enumerate() {
            let mut ent = [0x31u8; 32];
            ent[0] = idx as u8;
            let (_ct, r_i, pf) =
                prove_he_range_u24(&pk_audit, sal, &pbat_prefix, idx as u32, &ent).unwrap();
            proofs_blob.extend_from_slice(&pf);
            r_sum += r_i;
            let (_lk_s, lk_pk) = derive_ed25519_keypair(&ent, b"CLAIM_LOCK");
            locks_blob.extend_from_slice(&lk_pk);
            locks_blob.extend_from_slice(&4u16.to_be_bytes());
            locks_blob.extend_from_slice(b"MEMO");
        }

        let mut btag_pre = [0u8; 44];
        btag_pre[0..16].copy_from_slice(b"SLX_CONF_BTAG_1:");
        btag_pre[16..36].copy_from_slice(&conf);
        btag_pre[36..44].copy_from_slice(&0u64.to_be_bytes());
        let batch_tag32 = keccak256(&btag_pre);

        let mut sum_ctx = [0u8; 96];
        sum_ctx[0..16].copy_from_slice(b"SLX_CONF_BSUM_1:");
        sum_ctx[16..36].copy_from_slice(&acc);
        sum_ctx[36..56].copy_from_slice(&treas);
        sum_ctx[56..88].copy_from_slice(&batch_tag32);
        sum_ctx[88..96].copy_from_slice(&total_payroll.to_be_bytes());
        let sum_dleq = prove_he_sum_equals_u64(&pk_audit, &r_sum, &sum_ctx, &[0x44; 32]).unwrap();

        let mut pay_cd = Vec::new();
        pay_cd.extend_from_slice(&SEL_POST_CONF_PAY);
        pay_cd.extend_from_slice(&CAT_ID_PAYROLL);
        pay_cd.extend_from_slice(&period);
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&total_payroll.to_be_bytes());
        pay_cd.extend_from_slice(&w);
        w = [0u8; 32];
        w[31] = 1; // isPaidNow = true
        pay_cd.extend_from_slice(&w);
        // 9 head words = 288 bytes
        let off4 = 288u64;
        let off5 = off4 + 32 + ((proofs_blob.len() + 31) & !31) as u64;
        let off6 = off5 + 32 + 64;
        let off7 = off6 + 32 + 32;
        for off in [off4, off5, off6, off7] {
            w = [0u8; 32];
            w[24..32].copy_from_slice(&off.to_be_bytes());
            pay_cd.extend_from_slice(&w);
        }
        pay_cd.extend_from_slice(&[0u8; 32]); // authObj = 0x0
        pad_bytes_tail(&mut pay_cd, &proofs_blob);
        pad_bytes_tail(&mut pay_cd, &sum_dleq);
        pad_bytes_tail(&mut pay_cd, b"AUDIT_CIPHER");
        pad_bytes_tail(&mut pay_cd, &locks_blob);

        mock::transact_as(dir1, conf, &pay_cd).unwrap();
        assert_eq!(SHIELDED_FUNDED_TOTAL.with(|v| *v.borrow()), 45_000);
        assert_eq!(LAST_ROLLUP_TOTAL.with(|v| *v.borrow()), 45_000);

        // 2. Propose 2 Confidential Defense Contracts (Mode 1 Epoch Staged) + Stealth Co-Sign via ephemeral EOA
        let def_period = *b"FY2026_Q4_DEFENSE_______________";
        let monthly_vals = [30_000u64, 50_000u64];
        let months = 6u64;
        let client_keys = [(sk_def_a, pk_def_a), (sk_def_b, pk_def_b)];
        let mut r_backlogs = Vec::new();

        for (i, &(ref sk_cli, pk_cli)) in client_keys.iter().enumerate() {
            let rec_id = i as u64;
            let mut ias_ctx = [0u8; 44];
            ias_ctx[0..16].copy_from_slice(b"SLX_CONF_RIAS_1:");
            ias_ctx[16..36].copy_from_slice(&conf);
            ias_ctx[36..44].copy_from_slice(&rec_id.to_be_bytes());

            let (rho, _) = derive_ed25519_keypair(&[0x70 + i as u8; 32], b"RHO");
            let (h_32, blind_pk_32, neq_blob) =
                prove_stealth_non_insider(&rho, &pk_cli, &[pk_dir1], &ias_ctx, &[0x81; 32])
                    .unwrap();
            let (_k_rec, claim_lock) = derive_ed25519_keypair(&[0x90 + i as u8; 32], b"REC_LOCK");

            let mut rprp_prefix = [0u8; 108];
            rprp_prefix[0..16].copy_from_slice(b"SLX_CONF_RPRP_1:");
            rprp_prefix[16..36].copy_from_slice(&conf);
            rprp_prefix[36..68].copy_from_slice(&CAT_ID_DEFENSE_B2B);
            rprp_prefix[68..100].copy_from_slice(&def_period);
            rprp_prefix[100..108].copy_from_slice(&rec_id.to_be_bytes());

            let (_c_m, r_m, m_pf) = prove_he_range_u24(
                &pk_audit,
                monthly_vals[i],
                &rprp_prefix,
                rec_id as u32,
                &[0x61 + i as u8; 32],
            )
            .unwrap();
            r_backlogs.push(r_m * Scalar::from(months));

            let mut prop_cd = Vec::new();
            prop_cd.extend_from_slice(&SEL_PROP_CONF_REC);
            prop_cd.extend_from_slice(&CAT_ID_DEFENSE_B2B);
            prop_cd.extend_from_slice(&def_period);
            w = [0u8; 32];
            w[24..32].copy_from_slice(&months.to_be_bytes());
            prop_cd.extend_from_slice(&w);
            w[24..32].copy_from_slice(&20u64.to_be_bytes());
            prop_cd.extend_from_slice(&w);
            prop_cd.extend_from_slice(&h_32);
            prop_cd.extend_from_slice(&blind_pk_32);
            prop_cd.extend_from_slice(&claim_lock);
            // 11 head words = 352 bytes
            let o7 = 352u64;
            let o8 = o7 + 32 + ((m_pf.len() + 31) & !31) as u64;
            let o9 = o8 + 64;
            for off in [o7, o8, o9] {
                w = [0u8; 32];
                w[24..32].copy_from_slice(&off.to_be_bytes());
                prop_cd.extend_from_slice(&w);
            }
            prop_cd.extend_from_slice(&[0u8; 32]); // authObj = 0x0 (sole director)
            pad_bytes_tail(&mut prop_cd, &m_pf);
            pad_bytes_tail(&mut prop_cd, b"AUD");
            pad_bytes_tail(&mut prop_cd, b"CLI");

            mock::transact_as(dir1, conf, &prop_cd).unwrap();

            // Read back stored `c_backlog` from slice to sign stealth co-sign from `ephem_relayer`!
            let sl_cd = CallEncoder::<96>::new(const {
                selector("getConfidentialReceivablesSlice(uint64,uint64)")
            })
            .push_u64(rec_id)
            .push_u64(1);
            let sl_raw = mock::transact_as(ephem_relayer, conf, sl_cd.as_slice()).unwrap();
            let mut c_backlog = [0u8; 64];
            c_backlog.copy_from_slice(&sl_raw[16 + 8 + 260..16 + 8 + 324]);

            let mut cosign_ctx = [0u8; 108];
            cosign_ctx[0..16].copy_from_slice(b"SLX_CONF_RCOS_1:");
            cosign_ctx[16..36].copy_from_slice(&conf);
            cosign_ctx[36..44].copy_from_slice(&rec_id.to_be_bytes());
            cosign_ctx[44..108].copy_from_slice(&c_backlog);
            let cosign_sig =
                prove_ed25519_schnorr(sk_cli, &h_32, &cosign_ctx, &[0x99; 32]).unwrap();

            // Insider (`sk_dir1`) spoof attempt MUST fail!
            let bad_sig = prove_ed25519_schnorr(&sk_dir1, &h_32, &cosign_ctx, &[0x99; 32]).unwrap();
            let build_cosign = |sig: &[u8; 64]| -> Vec<u8> {
                let mut v = Vec::new();
                v.extend_from_slice(&selector(
                    "stealthCosignConfidentialReceivable(uint64,uint64,bytes,bytes,bytes)",
                ));
                let mut wd = [0u8; 32];
                wd[24..32].copy_from_slice(&rec_id.to_be_bytes());
                v.extend_from_slice(&wd);
                v.extend_from_slice(&[0u8; 32]); // Mode 1 -> publicLiveTotal = 0
                let c2 = 160u64;
                let c3 = c2 + 96;
                let c4 = c3 + 32 + ((neq_blob.len() + 31) & !31) as u64;
                for off in [c2, c3, c4] {
                    wd = [0u8; 32];
                    wd[24..32].copy_from_slice(&off.to_be_bytes());
                    v.extend_from_slice(&wd);
                }
                pad_bytes_tail(&mut v, sig);
                pad_bytes_tail(&mut v, &neq_blob);
                pad_bytes_tail(&mut v, &[]);
                v
            };
            assert_eq!(
                mock::transact_as(ephem_relayer, conf, &build_cosign(&bad_sig)),
                Err(ERR_IFRS_COUNTERPARTY_CONSENT_REQUIRED)
            );

            // Real client stealth co-signs via `ephem_relayer` -> succeeds with ZERO change to public GL yet!
            LAST_ROLLUP_TOTAL.with(|v| *v.borrow_mut() = 0);
            mock::transact_as(ephem_relayer, conf, &build_cosign(&cosign_sig)).unwrap();
            assert_eq!(LAST_ROLLUP_TOTAL.with(|v| *v.borrow()), 0);
        }

        // 3. Flush Defense Epoch Roll-Up (2 staged contracts + 2 dummy zero commitments = 4 slots -> 480,000 SGD!)
        let flush_batch_id = 1u64;
        let mut efls_prefix = [0u8; 108];
        efls_prefix[0..16].copy_from_slice(b"SLX_CONF_EFLS_1:");
        efls_prefix[16..36].copy_from_slice(&conf);
        efls_prefix[36..68].copy_from_slice(&CAT_ID_DEFENSE_B2B);
        efls_prefix[68..100].copy_from_slice(&def_period);
        efls_prefix[100..108].copy_from_slice(&flush_batch_id.to_be_bytes());

        let mut dummy_blob = Vec::new();
        let mut r_epoch = r_backlogs[0] + r_backlogs[1];
        for d in 0..2u32 {
            let (_dct, dr, dpf) =
                prove_he_range_u24(&pk_audit, 0, &efls_prefix, d, &[0xa0 + d as u8; 32]).unwrap();
            dummy_blob.extend_from_slice(&dpf);
            r_epoch += dr;
        }
        let rollup_total: u64 = (30_000 + 50_000) * 6;
        let mut esum_ctx = [0u8; 116];
        esum_ctx[0..16].copy_from_slice(b"SLX_CONF_ESUM_1:");
        esum_ctx[16..36].copy_from_slice(&conf);
        esum_ctx[36..68].copy_from_slice(&CAT_ID_DEFENSE_B2B);
        esum_ctx[68..100].copy_from_slice(&def_period);
        esum_ctx[100..108].copy_from_slice(&flush_batch_id.to_be_bytes());
        esum_ctx[108..116].copy_from_slice(&rollup_total.to_be_bytes());
        let esum_dleq =
            prove_he_sum_equals_u64(&pk_audit, &r_epoch, &esum_ctx, &[0xb5; 32]).unwrap();

        let mut staged_ids = Vec::new();
        staged_ids.extend_from_slice(&0u64.to_be_bytes());
        staged_ids.extend_from_slice(&1u64.to_be_bytes());

        let mut fl_cd = Vec::new();
        fl_cd.extend_from_slice(&SEL_FLUSH_CONF_REC);
        fl_cd.extend_from_slice(&CAT_ID_DEFENSE_B2B);
        fl_cd.extend_from_slice(&def_period);
        w = [0u8; 32];
        w[24..32].copy_from_slice(&rollup_total.to_be_bytes());
        fl_cd.extend_from_slice(&w);
        // 8 head words = 256 bytes
        let f3 = 256u64;
        let f4 = f3 + 64;
        let f5 = f4 + 32 + ((dummy_blob.len() + 31) & !31) as u64;
        let f6 = f5 + 96;
        for off in [f3, f4, f5, f6] {
            w = [0u8; 32];
            w[24..32].copy_from_slice(&off.to_be_bytes());
            fl_cd.extend_from_slice(&w);
        }
        fl_cd.extend_from_slice(&[0u8; 32]); // authObj = 0x0
        pad_bytes_tail(&mut fl_cd, &staged_ids);
        pad_bytes_tail(&mut fl_cd, &dummy_blob);
        pad_bytes_tail(&mut fl_cd, &esum_dleq);
        pad_bytes_tail(&mut fl_cd, b"EPOCH_SUMMARY");

        mock::transact_as(dir1, conf, &fl_cd).unwrap();
        assert_eq!(LAST_ROLLUP_TOTAL.with(|v| *v.borrow()), 480_000);
    }
}
