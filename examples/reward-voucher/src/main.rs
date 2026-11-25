//! Hardware-Gated `SLXR` Paid Voucher, 3-Month (`90-Day`) Active Validator Maturity &
//! Audited Cash-Back Redemption **Haltproof Subroutine (HPS #25)** (`reward-voucher`).
//!
//! End-to-end enforcement of SuperLexicon's 4 `SLXR` Reward Policies:
//! 1. **Automatic Issuance ONLY on Settled Payment (`BankingOracle` -> `issuePaidVoucher`):**
//!    - Zero factory key escrow: EMS factories hold zero signing keys.
//!    - Only settled fiat/stablecoin orders verified by the Banking & Payments Oracle (or
//!      authorized `ProductLedger` checkout module) create a `PaidVoucher`, keyed idempotently
//!      by `paymentRefHash = keccak256(oracleSalt || externalPaymentId)` (zero PII on-chain).
//!    - Pre-activation refunds/chargebacks (`revokeRefundedVoucher`) cleanly cancel unclaimed
//!      vouchers before any `SLXR` is minted.
//! 2. **Privacy-Preserving, Front-Run-Proof Voucher Ownership (`voucherCommitment`):**
//!    - At checkout, the buyer generates a local `Edwards25519` Voucher Keypair `(sk_v, PK_v)` and
//!      submits only `voucherCommitment = keccak256("SLXR_VOUCHER_V1" || PK_v)`.
//!    - Claiming requires a valid Schnorr signature under `PK_v` binding `(paymentRefHash,
//!      validatorPubKey, recipientIdentity, ethRecipient)` — 100% immune to mempool front-running.
//! 3. **3-Month (`90` Daily Epochs) Active Mesh Validator Anti-Hoarding Gate:**
//!    - Default `minActiveEpochs = 90` (`90` distinct daily validator epochs, spaced by at least
//!      `minEpochSpacingBlocks = 20_000` blocks ~= 24h at ~4.3s/block => `~1,800,000` blocks over
//!      3 months) inside a real `>= 3`-validator BFT subnet:
//!        (a) **Local-Subnet Mode (`recordLocalValidatorEpoch`):** Verifies directly via
//!            `hps_sdk::vrf::active_validators()` that `count >= 3` and `validatorPubKey` is an
//!            active `Full` BFT validator.
//!        (b) **Foreign/Field-Subnet Mode (`recordForeignSubnetEpoch`):** Verifies `>= 3` distinct
//!            sorted peer `Edwards25519` Schnorr signatures (`including validatorPubKey`) plus
//!            anchor-chain `minEpochSpacingBlocks` spacing so private subnets cannot fast-forward time.
//!    - Strictly `1 Validator <-> 1 Device Voucher` (`validatorUsed[validatorPubKey] = 1`): buying
//!      10 devices requires running 10 distinct active validators for 3 months.
//! 4. **Transparent Prevailing Cash-Back Redemption & Dual-Chain Readiness:**
//!    - Mints `SLXR` via `slxrAssetLedger.charterModuleIssue` (tradable at `$0.00` gas on `DexClob`
//!      HFS) and emits `EthereumMintAuthorized` for optional 1:1 Ethereum Mainnet `DiscreteTimeCLOB.sol`
//!      claims.
//!    - `redeemSlxrForCashBack` computes `PrevailingRate = VaultBalance / UnredeemedActiveSLXR`
//!      (`$0.00` floor if cost buffers were fully consumed), burns `SLXR` (`charterModuleCancel`),
//!      and transfers pro-rata cash-back (`charterModuleClearTransfer`) atomically.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::vrf::{active_validators, verify_ed25519_schnorr, ED25519_BASEPOINT_BYTES};
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const VOUCHER_NONE: u8 = 0;
pub const VOUCHER_ISSUED_AWAITING_VALIDATOR: u8 = 1;
pub const VOUCHER_CLAIMED: u8 = 2;
pub const VOUCHER_REVOKED_REFUNDED: u8 = 3;

pub const SKU_DONGLE: u64 = 1; // $178.00 -> KS 20% = 35,600,000 SLXR | Retail 5% = 8,900,000 SLXR
pub const SKU_WATCH: u64 = 2;  // $688.00 -> KS 20% = 137,600,000 SLXR | Retail 5% = 34,400,000 SLXR
pub const SKU_SLATE: u64 = 3;  // $1,198.00 -> KS 20% = 239,600,000 SLXR | Retail 5% = 59,900,000 SLXR

pub const TIER_KICKSTARTER_BPS: u64 = 2_000; // 20.00%
pub const TIER_RETAIL_BPS: u64 = 500;        // 5.00%

/// Default 3-month active validator maturity: 90 daily epochs x 20,000 blocks/day (~4.3s/blk) = 1,800,000 blocks.
pub const DEFAULT_MIN_ACTIVE_EPOCHS: u64 = 90;
pub const DEFAULT_MIN_EPOCH_SPACING_BLOCKS: u64 = 20_000;
pub const MIN_SUBNET_BFT_PEERS: usize = 3;
pub const MAX_FOREIGN_QUORUM_SIGNERS: usize = 16;

const KEY_INIT: &[u8] = b"rv:init";
const KEY_ADMIN: &[u8] = b"rv:admin";
const KEY_ORACLE: &[u8] = b"rv:oracle";
const KEY_PRODUCT_HOOK: &[u8] = b"rv:prd_hook";
const KEY_SLXR_LEDGER: &[u8] = b"rv:slxr_led";
const KEY_CASH_LEDGER: &[u8] = b"rv:cash_led";
const KEY_VAULT_ACCOUNT: &[u8] = b"rv:vault_acc";
const KEY_MIN_EPOCHS: &[u8] = b"rv:min_ep";
const KEY_EPOCH_SPACING: &[u8] = b"rv:ep_spc";

const KEY_TOTAL_ISSUED_VOUCHERS: &[u8] = b"rv:tot_iss";
const KEY_TOTAL_CLAIMED_VOUCHERS: &[u8] = b"rv:tot_clm";
const KEY_TOTAL_REVOKED_VOUCHERS: &[u8] = b"rv:tot_rev";
const KEY_UNREDEEMED_SLXR: &[u8] = b"rv:unred_slxr";
const KEY_REDEEMED_SLXR: &[u8] = b"rv:red_slxr";
const KEY_VAULT_CASH_BAL: &[u8] = b"rv:vault_bal";
const KEY_TOTAL_CASH_PAID: &[u8] = b"rv:cash_paid";

const DOMAIN_COMMITMENT: &[u8] = b"SLXR_VOUCHER_V1";
const DOMAIN_CLAIM: &[u8] = b"SLXR_CLAIM_V1";
const DOMAIN_FOREIGN_EPOCH: &[u8] = b"SLX_FOREIGN_EPOCH_V1";

const SEL_CHARTER_ISSUE: [u8; 4] = selector("charterModuleIssue(address,uint64)");
const SEL_CHARTER_CANCEL: [u8; 4] = selector("charterModuleCancel(address,uint64)");
const SEL_CHARTER_CLEAR_TRANSFER: [u8; 4] =
    selector("charterModuleClearTransfer(address,address,uint64)");

const EV_INITIALIZED: [u8; 32] =
    event_topic("RewardVoucherInitialized(address,address,uint64,uint64)");
const EV_VOUCHER_ISSUED: [u8; 32] =
    event_topic("PaidVoucherIssued(bytes32,bytes32,uint64,uint64,uint64)");
const EV_VOUCHER_REVOKED: [u8; 32] = event_topic("PaidVoucherRevoked(bytes32,uint64)");
const EV_VALIDATOR_EPOCH: [u8; 32] =
    event_topic("ValidatorEpochCredited(bytes32,bytes32,uint64,uint64)");
const EV_REWARD_CLAIMED: [u8; 32] =
    event_topic("ValidatedRewardClaimed(bytes32,bytes32,address,address,uint64)");
const EV_ETH_MINT_AUTHORIZED: [u8; 32] =
    event_topic("EthereumMintAuthorized(bytes32,bytes32,address,uint64,uint64)");
const EV_BUFFER_DEPOSITED: [u8; 32] = event_topic("BufferSavingsDeposited(address,uint64,uint64)");
const EV_CASHBACK_REDEEMED: [u8; 32] =
    event_topic("CashBackRedeemed(address,uint64,uint64,uint64)");

/// Fixed 160-byte `VoucherRecord`:
/// `[0]      status (u8)`
/// `[1..9]   sku_code (u64 BE)`
/// `[9..17]  tier_bps (u64 BE)`
/// `[17..25] price_usd_micros (u64 BE)`
/// `[25..33] slxr_amount (u64 BE)`
/// `[33..41] issued_block (u64 BE)`
/// `[41..49] claimed_or_revoked_block (u64 BE)`
/// `[49..81] voucher_commitment (bytes32)`
/// `[81..113] claimed_validator_pk (bytes32)`
/// `[113..133] claimed_recipient_identity (address)`
/// `[133..153] claimed_eth_recipient (address)`
/// `[153..160] reserved`
const VOUCHER_REC_LEN: usize = 160;

/// Fixed 64-byte `ValidatorMaturityRecord`:
/// `[0..8]   active_epochs_completed (u64 BE)`
/// `[8..16]  cumulative_blocks_validated (u64 BE)`
/// `[16..24] last_credited_anchor_block (u64 BE)`
/// `[24..56] last_subnet_id (bytes32)`
/// `[56]     claimed_voucher_flag (u8: 0 = unused, 1 = permanently bound to a claimed voucher)`
/// `[57..64] reserved`
const MATURITY_REC_LEN: usize = 64;

hps_entry! {
    "initialize(address,address,address,address,address,uint64,uint64)"                         => handle_initialize,
    "setBankingOracle(address)"                                                                 => handle_set_oracle,
    "setProductCheckoutHook(address)"                                                           => handle_set_product_hook,
    "issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)"                                    => handle_issue_paid_voucher,
    "revokeRefundedVoucher(bytes32)"                                                            => handle_revoke_voucher,
    "recordLocalValidatorEpoch(bytes32)"                                                        => handle_record_local_epoch,
    "recordForeignSubnetEpoch(bytes32,bytes32,uint64,bytes)"                                    => handle_record_foreign_epoch,
    "claimValidatedReward(bytes32,bytes32,bytes32,address,address,bytes)"                       => handle_claim_reward,
    "depositRealizedBufferSavings(uint64)"                                                      => handle_deposit_buffer_savings,
    "redeemSlxrForCashBack(uint64)"                                                             => handle_redeem_cashback,
    "getVoucher(bytes32)"                                                                       => handle_get_voucher,
    "getValidatorMaturity(bytes32)"                                                             => handle_get_validator_maturity,
    "getPoolStats()"                                                                            => handle_get_pool_stats,
    "computeCommitment(bytes32)"                                                                => handle_compute_commitment,
}

fn addr_topic(a: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(a);
    t
}

fn require_init() -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    Ok(())
}

fn require_admin() -> Result<[u8; 20], i32> {
    require_init()?;
    let caller = context::msg_sender();
    let admin = storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]);
    if caller != admin {
        return Err(-11);
    }
    Ok(caller)
}

fn require_oracle_or_hook() -> Result<[u8; 20], i32> {
    require_init()?;
    let caller = context::msg_sender();
    let oracle = storage::get_address(KEY_ORACLE).unwrap_or([0u8; 20]);
    let admin = storage::get_address(KEY_ADMIN).unwrap_or([0u8; 20]);
    let hook = storage::get_address(KEY_PRODUCT_HOOK).unwrap_or([0u8; 20]);
    if caller != oracle && caller != admin && (hook == [0u8; 20] || caller != hook) {
        return Err(-12);
    }
    Ok(caller)
}

fn voucher_key(payment_ref: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"vch:").push(payment_ref)
}

fn maturity_key(validator_pk: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"mat:").push(validator_pk)
}

fn standalone_slxr_bal_key(holder: &[u8; 20]) -> KeyBuilder<40> {
    KeyBuilder::<40>::new().push(b"sbal:").push(holder)
}

pub fn voucher_commitment_for_pk(voucher_pk32: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 47];
    buf[0..15].copy_from_slice(DOMAIN_COMMITMENT);
    buf[15..47].copy_from_slice(voucher_pk32);
    keccak256(&buf)
}

pub fn default_sku_price_micros(sku_code: u64) -> Option<u64> {
    match sku_code {
        SKU_DONGLE => Some(178_000_000),    // $178.00
        SKU_WATCH => Some(688_000_000),     // $688.00
        SKU_SLATE => Some(1_198_000_000),   // $1,198.00
        _ => None,
    }
}

fn load_maturity(validator_pk: &[u8; 32]) -> [u8; MATURITY_REC_LEN] {
    let mk = maturity_key(validator_pk);
    let mut buf = [0u8; MATURITY_REC_LEN];
    let _ = storage::get_into(mk.as_slice(), &mut buf);
    buf
}

fn save_maturity(validator_pk: &[u8; 32], buf: &[u8; MATURITY_REC_LEN]) {
    let mk = maturity_key(validator_pk);
    storage::set(mk.as_slice(), buf);
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) == 1 {
        return Err(-13);
    }
    let admin = args.address(0).ok_or(-1)?;
    let banking_oracle = args.address(1).ok_or(-1)?;
    let slxr_ledger = args.address(2).ok_or(-1)?;
    let cash_ledger = args.address(3).ok_or(-1)?;
    let vault_account = args.address(4).ok_or(-1)?;
    let min_epochs_arg = args.u64(5).ok_or(-1)?;
    let spacing_arg = args.u64(6).ok_or(-1)?;

    if admin == [0u8; 20] || banking_oracle == [0u8; 20] {
        return Err(-2);
    }

    let min_epochs = if min_epochs_arg == 0 {
        DEFAULT_MIN_ACTIVE_EPOCHS
    } else {
        min_epochs_arg
    };
    let epoch_spacing = if spacing_arg == 0 {
        DEFAULT_MIN_EPOCH_SPACING_BLOCKS
    } else {
        spacing_arg
    };

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_ADMIN, &admin);
    storage::set_address(KEY_ORACLE, &banking_oracle);
    storage::set_address(KEY_SLXR_LEDGER, &slxr_ledger);
    storage::set_address(KEY_CASH_LEDGER, &cash_ledger);
    storage::set_address(KEY_VAULT_ACCOUNT, &vault_account);
    storage::set_u64(KEY_MIN_EPOCHS, min_epochs);
    storage::set_u64(KEY_EPOCH_SPACING, epoch_spacing);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&min_epochs.to_be_bytes());
    ev[8..16].copy_from_slice(&epoch_spacing.to_be_bytes());
    events::emit(
        &[EV_INITIALIZED, addr_topic(&admin), addr_topic(&banking_oracle)],
        &ev,
    );
    Ok(())
}

fn handle_set_oracle(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    let next = args.address(0).ok_or(-1)?;
    if next == [0u8; 20] {
        return Err(-2);
    }
    storage::set_address(KEY_ORACLE, &next);
    Ok(())
}

fn handle_set_product_hook(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_admin()?;
    let hook = args.address(0).ok_or(-1)?;
    storage::set_address(KEY_PRODUCT_HOOK, &hook);
    Ok(())
}

/// Automatically invoked by the Banking & Payments Oracle upon settled fiat/card/wire/Kickstarter/USDC payment.
fn handle_issue_paid_voucher(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_oracle_or_hook()?;

    let payment_ref = args.bytes32(0).ok_or(-1)?;
    let sku_code = args.u64(1).ok_or(-1)?;
    let tier_bps = args.u64(2).ok_or(-1)?;
    let explicit_price_micros = args.u64(3).ok_or(-1)?;
    let commitment = args.bytes32(4).ok_or(-1)?;

    if payment_ref == [0u8; 32] || commitment == [0u8; 32] {
        return Err(-14);
    }
    if tier_bps == 0 || tier_bps > 5_000 {
        return Err(-15); // Reward rate capped <= 50%
    }

    let vk = voucher_key(&payment_ref);
    let mut existing = [0u8; VOUCHER_REC_LEN];
    if storage::get_into(vk.as_slice(), &mut existing).unwrap_or(0) >= VOUCHER_REC_LEN
        && existing[0] != VOUCHER_NONE
    {
        return Err(-16); // Idempotency guard: duplicate paymentRefHash!
    }

    let price_micros = if explicit_price_micros > 0 {
        explicit_price_micros
    } else {
        default_sku_price_micros(sku_code).ok_or(-17)?
    };

    // Exact Slide 08 formula: e.g. $1,198 (1,198,000,000 micro-USD) * 2000 bps / 10,000 = 239,600,000 SLXR!
    let slxr_amount = ((price_micros as u128)
        .checked_mul(tier_bps as u128)
        .ok_or(-18)?
        / 10_000u128) as u64;
    if slxr_amount == 0 {
        return Err(-18);
    }

    let now_blk = context::block_number();
    let mut rec = [0u8; VOUCHER_REC_LEN];
    rec[0] = VOUCHER_ISSUED_AWAITING_VALIDATOR;
    rec[1..9].copy_from_slice(&sku_code.to_be_bytes());
    rec[9..17].copy_from_slice(&tier_bps.to_be_bytes());
    rec[17..25].copy_from_slice(&price_micros.to_be_bytes());
    rec[25..33].copy_from_slice(&slxr_amount.to_be_bytes());
    rec[33..41].copy_from_slice(&now_blk.to_be_bytes());
    rec[49..81].copy_from_slice(&commitment);
    storage::set(vk.as_slice(), &rec);

    let tot = storage::get_u64(KEY_TOTAL_ISSUED_VOUCHERS);
    storage::set_u64(KEY_TOTAL_ISSUED_VOUCHERS, tot + 1);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&sku_code.to_be_bytes());
    ev[8..16].copy_from_slice(&tier_bps.to_be_bytes());
    ev[16..24].copy_from_slice(&slxr_amount.to_be_bytes());
    events::emit(&[EV_VOUCHER_ISSUED, payment_ref, commitment], &ev);

    ret::write_u64_word(slxr_amount);
    Ok(())
}

/// Invoked by Banking & Payments Oracle if an order is refunded/chargebacked BEFORE validation claim.
fn handle_revoke_voucher(args: &CalldataReader) -> Result<(), i32> {
    let _ = require_oracle_or_hook()?;
    let payment_ref = args.bytes32(0).ok_or(-1)?;
    let vk = voucher_key(&payment_ref);
    let mut rec = [0u8; VOUCHER_REC_LEN];
    let n = storage::get_into(vk.as_slice(), &mut rec).unwrap_or(0);
    if n < VOUCHER_REC_LEN || rec[0] == VOUCHER_NONE {
        return Err(-19);
    }
    if rec[0] != VOUCHER_ISSUED_AWAITING_VALIDATOR {
        // Already claimed or already revoked!
        return Err(-20);
    }
    let now_blk = context::block_number();
    rec[0] = VOUCHER_REVOKED_REFUNDED;
    rec[41..49].copy_from_slice(&now_blk.to_be_bytes());
    storage::set(vk.as_slice(), &rec);

    let rev = storage::get_u64(KEY_TOTAL_REVOKED_VOUCHERS);
    storage::set_u64(KEY_TOTAL_REVOKED_VOUCHERS, rev + 1);

    events::emit(&[EV_VOUCHER_REVOKED, payment_ref], &now_blk.to_be_bytes());
    ret::write_bool(true);
    Ok(())
}

/// Path A (Local Subnet): Credits 1 active daily epoch (`1..90`) by verifying directly against
/// `hps_sdk::vrf::active_validators()` that `validatorPubKey` is an active `Full` BFT validator
/// in a `>= 3`-validator subnet and at least `minEpochSpacingBlocks` have elapsed since the previous epoch.
fn handle_record_local_epoch(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let validator_pk = args.bytes32(0).ok_or(-1)?;
    if validator_pk == [0u8; 32] {
        return Err(-14);
    }

    let val_set = active_validators().ok_or(-21)?;
    if val_set.count < MIN_SUBNET_BFT_PEERS {
        return Err(-22); // Must be a real >= 3-peer BFT subnet (blocks 1-node localtestnet hoarding!)
    }
    let mut is_active_full = false;
    let mut i = 0;
    while i < val_set.count {
        if val_set.validators[i].pubkey == validator_pk {
            is_active_full = true;
            break;
        }
        i += 1;
    }
    if !is_active_full {
        return Err(-23); // Validator is not an active Full BFT validator on this subnet
    }

    credit_validator_epoch(&validator_pk, &val_set.set_hash, storage::get_u64(KEY_EPOCH_SPACING))
}

/// Path B (Foreign / Field Subnet): Credits 1 active daily epoch (`1..90`) for a validator running
/// on another RF/TCP subnet by verifying `>= 3` distinct sorted `Edwards25519` Schnorr signatures
/// (`[signer_pk_32 || sig_64] * M`, including `validatorPubKey`) AND enforcing anchor-chain block spacing!
fn handle_record_foreign_epoch(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let subnet_id = args.bytes32(0).ok_or(-1)?;
    let validator_pk = args.bytes32(1).ok_or(-1)?;
    let epoch_blocks = args.u64(2).ok_or(-1)?;
    let quorum_blob = args.dynamic_bytes(3).ok_or(-1)?;

    if subnet_id == [0u8; 32] || validator_pk == [0u8; 32] {
        return Err(-14);
    }
    let spacing = storage::get_u64(KEY_EPOCH_SPACING);
    if epoch_blocks < spacing {
        return Err(-24);
    }

    // `quorum_blob` = `M` packed 96-byte records `[signer_pk_32][schnorr_sig_64]`, `3 <= M <= 16`
    if quorum_blob.len() % 96 != 0 {
        return Err(-25);
    }
    let m = quorum_blob.len() / 96;
    if !(MIN_SUBNET_BFT_PEERS..=MAX_FOREIGN_QUORUM_SIGNERS).contains(&m) {
        return Err(-22);
    }

    let cur_mat = load_maturity(&validator_pk);
    let next_epoch_idx = u64::from_be_bytes([
        cur_mat[0], cur_mat[1], cur_mat[2], cur_mat[3], cur_mat[4], cur_mat[5], cur_mat[6],
        cur_mat[7],
    ]) + 1;

    // Canonical epoch digest signed by the >=3 subnet peers
    let mut msg = [0u8; 108];
    msg[0..20].copy_from_slice(DOMAIN_FOREIGN_EPOCH);
    msg[20..40].copy_from_slice(&context::self_address());
    msg[40..72].copy_from_slice(&subnet_id);
    msg[72..80].copy_from_slice(&next_epoch_idx.to_be_bytes());
    msg[80..100].copy_from_slice(&validator_pk[0..20]);
    msg[100..108].copy_from_slice(&epoch_blocks.to_be_bytes());
    let digest = keccak256(&msg);

    let mut prev_pk = [0u8; 32];
    let mut has_prev = false;
    let mut includes_target_validator = false;
    let mut k = 0usize;
    while k < m {
        let off = k * 96;
        let mut pk = [0u8; 32];
        let mut sig = [0u8; 64];
        pk.copy_from_slice(&quorum_blob[off..off + 32]);
        sig.copy_from_slice(&quorum_blob[off + 32..off + 96]);

        // Enforce strict ascending byte order to guarantee all M signers are distinct in O(M)
        if has_prev && pk <= prev_pk {
            return Err(-26);
        }
        prev_pk = pk;
        has_prev = true;

        if pk == validator_pk {
            includes_target_validator = true;
        }
        if !verify_ed25519_schnorr(&ED25519_BASEPOINT_BYTES, &pk, &digest, &sig) {
            return Err(-27);
        }
        k += 1;
    }
    if !includes_target_validator {
        return Err(-28);
    }

    credit_validator_epoch(&validator_pk, &subnet_id, epoch_blocks)
}

fn credit_validator_epoch(
    validator_pk: &[u8; 32],
    subnet_id: &[u8; 32],
    blocks_delta: u64,
) -> Result<(), i32> {
    let spacing = storage::get_u64(KEY_EPOCH_SPACING);
    let now_blk = context::block_number();

    let mut mat = load_maturity(validator_pk);
    let prev_epochs = u64::from_be_bytes([
        mat[0], mat[1], mat[2], mat[3], mat[4], mat[5], mat[6], mat[7],
    ]);
    let prev_blocks = u64::from_be_bytes([
        mat[8], mat[9], mat[10], mat[11], mat[12], mat[13], mat[14], mat[15],
    ]);
    let last_anchor_blk = u64::from_be_bytes([
        mat[16], mat[17], mat[18], mat[19], mat[20], mat[21], mat[22], mat[23],
    ]);

    // Enforce real-time epoch spacing (e.g. 20,000 anchor blocks ~= 24 hours between daily epochs)
    if prev_epochs > 0 && now_blk < last_anchor_blk.saturating_add(spacing) {
        return Err(-29); // Epoch cooldown not yet elapsed!
    }

    let next_epochs = prev_epochs.saturating_add(1);
    let next_blocks = prev_blocks.saturating_add(blocks_delta.max(spacing));

    mat[0..8].copy_from_slice(&next_epochs.to_be_bytes());
    mat[8..16].copy_from_slice(&next_blocks.to_be_bytes());
    mat[16..24].copy_from_slice(&now_blk.to_be_bytes());
    mat[24..56].copy_from_slice(subnet_id);
    save_maturity(validator_pk, &mat);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&next_epochs.to_be_bytes());
    ev[8..16].copy_from_slice(&next_blocks.to_be_bytes());
    events::emit(&[EV_VALIDATOR_EPOCH, *validator_pk, *subnet_id], &ev);

    ret::write_u64_word(next_epochs);
    Ok(())
}

/// Claim `SLXR` once:
///  (1) `paymentRefHash` corresponds to an unclaimed, unrevoked Paid Voucher,
///  (2) `voucherPk32` hashes to `voucherCommitment` and signed this exact claim (`0` front-running),
///  (3) `validatorPubKey` has completed `>= minActiveEpochs` (default `90` days = 3 months!) AND
///      has never been used to unlock another voucher (`1 Validator <-> 1 Device`).
fn handle_claim_reward(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;

    let payment_ref = args.bytes32(0).ok_or(-1)?;
    let voucher_pk32 = args.bytes32(1).ok_or(-1)?;
    let validator_pk = args.bytes32(2).ok_or(-1)?;
    let recipient_id = args.address(3).ok_or(-1)?;
    let eth_recipient = args.address(4).ok_or(-1)?;
    let sig_bytes = args.dynamic_bytes(5).ok_or(-1)?;

    if recipient_id == [0u8; 20] || sig_bytes.len() != 64 {
        return Err(-14);
    }
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(sig_bytes);

    let vk = voucher_key(&payment_ref);
    let mut rec = [0u8; VOUCHER_REC_LEN];
    let n = storage::get_into(vk.as_slice(), &mut rec).unwrap_or(0);
    if n < VOUCHER_REC_LEN || rec[0] == VOUCHER_NONE {
        return Err(-19);
    }
    if rec[0] != VOUCHER_ISSUED_AWAITING_VALIDATOR {
        return Err(-30); // Already claimed or refunded!
    }

    // 1. Verify privacy-preserving checkout commitment
    let mut stored_commit = [0u8; 32];
    stored_commit.copy_from_slice(&rec[49..81]);
    if voucher_commitment_for_pk(&voucher_pk32) != stored_commit {
        return Err(-31); // Wrong voucher key!
    }

    // 2. Verify front-run-proof Schnorr signature binding recipient_id + eth_recipient + validator_pk
    let mut claim_ctx = [0u8; 137];
    claim_ctx[0..13].copy_from_slice(DOMAIN_CLAIM);
    claim_ctx[13..33].copy_from_slice(&context::self_address());
    claim_ctx[33..65].copy_from_slice(&payment_ref);
    claim_ctx[65..97].copy_from_slice(&validator_pk);
    claim_ctx[97..117].copy_from_slice(&recipient_id);
    claim_ctx[117..137].copy_from_slice(&eth_recipient);
    if !verify_ed25519_schnorr(&ED25519_BASEPOINT_BYTES, &voucher_pk32, &claim_ctx, &sig64) {
        return Err(-32);
    }

    // 3. Verify 3-month (90-day) validator maturity & strict 1-validator-per-device uniqueness!
    let mut mat = load_maturity(&validator_pk);
    if mat[56] != 0 {
        return Err(-33); // This validator node has ALREADY unlocked a device voucher!
    }
    let completed_epochs = u64::from_be_bytes([
        mat[0], mat[1], mat[2], mat[3], mat[4], mat[5], mat[6], mat[7],
    ]);
    let min_epochs = storage::get_u64(KEY_MIN_EPOCHS);
    if completed_epochs < min_epochs {
        return Err(-34); // 3-month (90-epoch) validator maturity gate not yet met!
    }

    let slxr_amount = u64::from_be_bytes([
        rec[25], rec[26], rec[27], rec[28], rec[29], rec[30], rec[31], rec[32],
    ]);
    let now_blk = context::block_number();

    // Mark validator permanently used & voucher claimed BEFORE external calls (checks-effects-interactions)
    mat[56] = 1;
    save_maturity(&validator_pk, &mat);

    rec[0] = VOUCHER_CLAIMED;
    rec[41..49].copy_from_slice(&now_blk.to_be_bytes());
    rec[81..113].copy_from_slice(&validator_pk);
    rec[113..133].copy_from_slice(&recipient_id);
    rec[133..153].copy_from_slice(&eth_recipient);
    storage::set(vk.as_slice(), &rec);

    storage::set_u64(
        KEY_TOTAL_CLAIMED_VOUCHERS,
        storage::get_u64(KEY_TOTAL_CLAIMED_VOUCHERS) + 1,
    );
    let new_unred = storage::get_u64(KEY_UNREDEEMED_SLXR)
        .checked_add(slxr_amount)
        .ok_or(-18)?;
    storage::set_u64(KEY_UNREDEEMED_SLXR, new_unred);

    // Mint `SLXR` on the attached `AssetLedger` HFS (or standalone balance map when `[0; 20]`)
    let slxr_ledger = storage::get_address(KEY_SLXR_LEDGER).unwrap_or([0u8; 20]);
    if slxr_ledger != [0u8; 20] {
        let cd = CallEncoder::<128>::new(SEL_CHARTER_ISSUE)
            .push_address(&recipient_id)
            .push_u64(slxr_amount);
        if call::call_raw(&slxr_ledger, cd.as_slice()).is_err() {
            return Err(-35);
        }
    } else {
        let sbk = standalone_slxr_bal_key(&recipient_id);
        let prev = storage::get_u64(sbk.as_slice());
        storage::set_u64(sbk.as_slice(), prev.saturating_add(slxr_amount));
    }

    let mut ev_claim = [0u8; 28];
    ev_claim[0..20].copy_from_slice(&eth_recipient);
    ev_claim[20..28].copy_from_slice(&slxr_amount.to_be_bytes());
    events::emit(
        &[
            EV_REWARD_CLAIMED,
            payment_ref,
            validator_pk,
            addr_topic(&recipient_id),
        ],
        &ev_claim,
    );

    if eth_recipient != [0u8; 20] {
        let mut ev_eth = [0u8; 16];
        ev_eth[0..8].copy_from_slice(&slxr_amount.to_be_bytes());
        ev_eth[8..16].copy_from_slice(&completed_epochs.to_be_bytes());
        events::emit(
            &[
                EV_ETH_MINT_AUTHORIZED,
                payment_ref,
                validator_pk,
                addr_topic(&eth_recipient),
            ],
            &ev_eth,
        );
    }

    ret::write_u64_word(slxr_amount);
    Ok(())
}

/// Deposit audited realized manufacturing/COGS/freight/tariff buffer savings into the Cash-Back Pool.
fn handle_deposit_buffer_savings(args: &CalldataReader) -> Result<(), i32> {
    let caller = require_oracle_or_hook()?;
    let cash_amount = args.u64(0).ok_or(-1)?;
    if cash_amount == 0 {
        return Err(-14);
    }

    let next_bal = storage::get_u64(KEY_VAULT_CASH_BAL)
        .checked_add(cash_amount)
        .ok_or(-18)?;
    storage::set_u64(KEY_VAULT_CASH_BAL, next_bal);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&cash_amount.to_be_bytes());
    ev[8..16].copy_from_slice(&next_bal.to_be_bytes());
    events::emit(&[EV_BUFFER_DEPOSITED, addr_topic(&caller)], &ev);

    ret::write_u64_word(next_bal);
    Ok(())
}

/// Redeem `slxrAmount` directly with the company at the transparent Prevailing Redemption Rate:
/// `payout = (slxrAmount * vaultCashBalance) / unredeemedActiveSlxr` (reverts if rate == $0.00).
/// Permanently burns `slxrAmount` and transfers `payout` cash-back atomically.
fn handle_redeem_cashback(args: &CalldataReader) -> Result<(), i32> {
    require_init()?;
    let slxr_amount = args.u64(0).ok_or(-1)?;
    if slxr_amount == 0 {
        return Err(-14);
    }
    let redeemer = context::msg_sender();
    let unred = storage::get_u64(KEY_UNREDEEMED_SLXR);
    let vault_bal = storage::get_u64(KEY_VAULT_CASH_BAL);
    if unred == 0 || slxr_amount > unred {
        return Err(-36);
    }
    if vault_bal == 0 {
        return Err(-37); // Worst-case Prevailing Redemption Rate is currently $0.00
    }

    let payout_cash = ((slxr_amount as u128)
        .checked_mul(vault_bal as u128)
        .ok_or(-18)?
        / (unred as u128)) as u64;
    if payout_cash == 0 {
        return Err(-37);
    }

    let next_unred = unred - slxr_amount;
    let next_vault = vault_bal - payout_cash;
    storage::set_u64(KEY_UNREDEEMED_SLXR, next_unred);
    storage::set_u64(KEY_VAULT_CASH_BAL, next_vault);
    storage::set_u64(
        KEY_REDEEMED_SLXR,
        storage::get_u64(KEY_REDEEMED_SLXR).saturating_add(slxr_amount),
    );
    storage::set_u64(
        KEY_TOTAL_CASH_PAID,
        storage::get_u64(KEY_TOTAL_CASH_PAID).saturating_add(payout_cash),
    );

    let slxr_ledger = storage::get_address(KEY_SLXR_LEDGER).unwrap_or([0u8; 20]);
    if slxr_ledger != [0u8; 20] {
        let burn_cd = CallEncoder::<128>::new(SEL_CHARTER_CANCEL)
            .push_address(&redeemer)
            .push_u64(slxr_amount);
        if call::call_raw(&slxr_ledger, burn_cd.as_slice()).is_err() {
            return Err(-38);
        }
    } else {
        let sbk = standalone_slxr_bal_key(&redeemer);
        let cur = storage::get_u64(sbk.as_slice());
        if cur < slxr_amount {
            return Err(-38);
        }
        storage::set_u64(sbk.as_slice(), cur - slxr_amount);
    }

    let cash_ledger = storage::get_address(KEY_CASH_LEDGER).unwrap_or([0u8; 20]);
    let vault_acc = storage::get_address(KEY_VAULT_ACCOUNT).unwrap_or([0u8; 20]);
    if cash_ledger != [0u8; 20] && vault_acc != [0u8; 20] {
        let pay_cd = CallEncoder::<128>::new(SEL_CHARTER_CLEAR_TRANSFER)
            .push_address(&vault_acc)
            .push_address(&redeemer)
            .push_u64(payout_cash);
        if call::call_raw(&cash_ledger, pay_cd.as_slice()).is_err() {
            return Err(-39);
        }
    }

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&slxr_amount.to_be_bytes());
    ev[8..16].copy_from_slice(&payout_cash.to_be_bytes());
    ev[16..24].copy_from_slice(&next_vault.to_be_bytes());
    events::emit(&[EV_CASHBACK_REDEEMED, addr_topic(&redeemer)], &ev);

    ret::write_u64_word(payout_cash);
    Ok(())
}

fn handle_get_voucher(args: &CalldataReader) -> Result<(), i32> {
    let payment_ref = args.bytes32(0).ok_or(-1)?;
    let vk = voucher_key(&payment_ref);
    let mut rec = [0u8; VOUCHER_REC_LEN];
    let n = storage::get_into(vk.as_slice(), &mut rec).unwrap_or(0);
    if n < VOUCHER_REC_LEN {
        ret::write(&[0u8; VOUCHER_REC_LEN]);
    } else {
        ret::write(&rec);
    }
    Ok(())
}

fn handle_get_validator_maturity(args: &CalldataReader) -> Result<(), i32> {
    let validator_pk = args.bytes32(0).ok_or(-1)?;
    let mat = load_maturity(&validator_pk);
    let min_ep = storage::get_u64(KEY_MIN_EPOCHS);
    let spacing = storage::get_u64(KEY_EPOCH_SPACING);
    let mut out = [0u8; 80];
    out[0..64].copy_from_slice(&mat);
    out[64..72].copy_from_slice(&min_ep.to_be_bytes());
    out[72..80].copy_from_slice(&spacing.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_get_pool_stats(_args: &CalldataReader) -> Result<(), i32> {
    let min_ep = storage::get_u64(KEY_MIN_EPOCHS);
    let spacing = storage::get_u64(KEY_EPOCH_SPACING);
    let issued = storage::get_u64(KEY_TOTAL_ISSUED_VOUCHERS);
    let claimed = storage::get_u64(KEY_TOTAL_CLAIMED_VOUCHERS);
    let revoked = storage::get_u64(KEY_TOTAL_REVOKED_VOUCHERS);
    let unred_slxr = storage::get_u64(KEY_UNREDEEMED_SLXR);
    let red_slxr = storage::get_u64(KEY_REDEEMED_SLXR);
    let vault_bal = storage::get_u64(KEY_VAULT_CASH_BAL);
    let cash_paid = storage::get_u64(KEY_TOTAL_CASH_PAID);
    // Prevailing rate scaled by 1e12 (micro-USD per 1e12 SLXR)
    let rate_e12 = if unred_slxr > 0 {
        (((vault_bal as u128) * 1_000_000_000_000u128) / (unred_slxr as u128)) as u64
    } else {
        0
    };

    let mut out = [0u8; 80];
    out[0..8].copy_from_slice(&min_ep.to_be_bytes());
    out[8..16].copy_from_slice(&spacing.to_be_bytes());
    out[16..24].copy_from_slice(&issued.to_be_bytes());
    out[24..32].copy_from_slice(&claimed.to_be_bytes());
    out[32..40].copy_from_slice(&revoked.to_be_bytes());
    out[40..48].copy_from_slice(&unred_slxr.to_be_bytes());
    out[48..56].copy_from_slice(&red_slxr.to_be_bytes());
    out[56..64].copy_from_slice(&vault_bal.to_be_bytes());
    out[64..72].copy_from_slice(&cash_paid.to_be_bytes());
    out[72..80].copy_from_slice(&rate_e12.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_compute_commitment(args: &CalldataReader) -> Result<(), i32> {
    let pk32 = args.bytes32(0).ok_or(-1)?;
    ret::write_word(&voucher_commitment_for_pk(&pk32));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::vrf::mock_crypto;
    use hps_sdk::{mock, selector};

    fn kp(seed: u8) -> (mock_crypto::Scalar, [u8; 32]) {
        mock_crypto::derive_ed25519_keypair(&[seed; 32], b"rv_test")
    }

    fn schnorr_sign(sk: &mock_crypto::Scalar, msg: &[u8]) -> [u8; 64] {
        mock_crypto::prove_ed25519_schnorr(sk, &ED25519_BASEPOINT_BYTES, msg, &[0x77; 32]).unwrap()
    }

    fn encode_claim(
        payment_ref: &[u8; 32],
        voucher_pk32: &[u8; 32],
        validator_pk: &[u8; 32],
        recipient_id: &[u8; 20],
        eth_recipient: &[u8; 20],
        sig64: &[u8; 64],
    ) -> Vec<u8> {
        let mut cd = Vec::new();
        cd.extend_from_slice(&selector(
            "claimValidatedReward(bytes32,bytes32,bytes32,address,address,bytes)",
        ));
        cd.extend_from_slice(payment_ref);
        cd.extend_from_slice(voucher_pk32);
        cd.extend_from_slice(validator_pk);
        let mut r_w = [0u8; 32];
        r_w[12..32].copy_from_slice(recipient_id);
        cd.extend_from_slice(&r_w);
        let mut e_w = [0u8; 32];
        e_w[12..32].copy_from_slice(eth_recipient);
        cd.extend_from_slice(&e_w);
        let mut off_w = [0u8; 32];
        off_w[30..32].copy_from_slice(&(6u16 * 32).to_be_bytes());
        cd.extend_from_slice(&off_w);
        let mut len_w = [0u8; 32];
        len_w[31] = 64;
        cd.extend_from_slice(&len_w);
        cd.extend_from_slice(sig64);
        cd
    }

    #[test]
    fn full_three_month_ninety_epoch_paid_voucher_to_cashback_and_anti_sybil_lifecycle() {
        mock::reset();
        let rv_hps = [0xD5; 20];
        let admin = [0x01; 20];
        let banking_oracle = [0x02; 20];
        let buyer_identity = [0xB1; 20];
        let mev_frontrunner = [0xEE; 20];
        let buyer_eth_wallet = [0xE1; 20];

        mock::register_hps(rv_hps, dispatch_calldata);
        mock::set_block_number(100);

        // Initialize with production 90-day (3-month) active validator maturity & 20,000 blocks/day!
        let init_cd = CallEncoder::<256>::new(selector(
            "initialize(address,address,address,address,address,uint64,uint64)",
        ))
        .push_address(&admin)
        .push_address(&banking_oracle)
        .push_address(&[0u8; 20])
        .push_address(&[0u8; 20])
        .push_address(&[0u8; 20])
        .push_u64(0) // defaults to 90 daily epochs (3 months)
        .push_u64(0); // defaults to 20,000 blocks/day
        assert!(mock::transact_as(admin, rv_hps, init_cd.as_slice()).is_ok());

        // 1. Buyer generates local Voucher Keypair `(sk_v, PK_v)` at checkout & sends only `commitment`
        let (sk_v, pk_v) = kp(42);
        let commitment = voucher_commitment_for_pk(&pk_v);
        let stripe_payment_ref = keccak256(b"stripe:pi_3Q9abc_slate_ks_order_1001");

        // Non-oracle cannot issue vouchers (-12)
        let issue_cd = CallEncoder::<256>::new(selector(
            "issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&stripe_payment_ref)
        .push_u64(SKU_SLATE)
        .push_u64(TIER_KICKSTARTER_BPS)
        .push_u64(0) // uses canonical $1,198.00 Slate price -> 239,600,000 SLXR!
        .push_bytes32(&commitment);
        assert_eq!(
            mock::transact_as(mev_frontrunner, rv_hps, issue_cd.as_slice()),
            Err(-12)
        );

        // Banking Oracle settles payment -> mints PaidVoucher (239,600,000 SLXR awaiting 90-day validation)
        let out_amt = mock::transact_as(banking_oracle, rv_hps, issue_cd.as_slice()).unwrap();
        assert_eq!(
            u64::from_be_bytes(out_amt[24..32].try_into().unwrap()),
            239_600_000
        );
        // Duplicate webhook replay is deterministically rejected (-16)
        assert_eq!(
            mock::transact_as(banking_oracle, rv_hps, issue_cd.as_slice()),
            Err(-16)
        );

        // 2. Register 3 active BFT validators on the subnet (`count = 3 >= MIN_SUBNET_BFT_PEERS`)
        let (_, val_pk1) = kp(101);
        let (_, val_pk2) = kp(102);
        let (_, val_pk3) = kp(103);
        mock_crypto::set_mock_validators(&[
            ([0x11; 20], val_pk1),
            ([0x12; 20], val_pk2),
            ([0x13; 20], val_pk3),
        ]);

        // Build buyer's valid Schnorr claim signature binding `buyer_identity` + `buyer_eth_wallet` + `val_pk1`
        let mut claim_ctx = [0u8; 137];
        claim_ctx[0..13].copy_from_slice(DOMAIN_CLAIM);
        claim_ctx[13..33].copy_from_slice(&rv_hps);
        claim_ctx[33..65].copy_from_slice(&stripe_payment_ref);
        claim_ctx[65..97].copy_from_slice(&val_pk1);
        claim_ctx[97..117].copy_from_slice(&buyer_identity);
        claim_ctx[117..137].copy_from_slice(&buyer_eth_wallet);
        let valid_sig = schnorr_sign(&sk_v, &claim_ctx);

        // Attempting to claim at Day 0 (or Day 89!) MUST fail with -34 (90-day gate not yet met)!
        let claim_cd = encode_claim(
            &stripe_payment_ref,
            &pk_v,
            &val_pk1,
            &buyer_identity,
            &buyer_eth_wallet,
            &valid_sig,
        );
        assert_eq!(
            mock::transact_as(buyer_identity, rv_hps, &claim_cd),
            Err(-34)
        );

        let ep_cd = CallEncoder::<128>::new(selector("recordLocalValidatorEpoch(bytes32)"))
            .push_bytes32(&val_pk1);

        // Complete 89 active daily epochs (with 20,000-block spacing enforced!)
        for day in 0..89u64 {
            let blk = 1_000 + day * 20_000;
            mock::set_block_number(blk);
            assert!(mock::transact_as(buyer_identity, rv_hps, ep_cd.as_slice()).is_ok());
            // Trying to rush a second epoch 500 blocks later on the same day MUST fail (-29)!
            mock::set_block_number(blk + 500);
            assert_eq!(
                mock::transact_as(buyer_identity, rv_hps, ep_cd.as_slice()),
                Err(-29)
            );
        }

        // At 89/90 days, claim STILL fails (-34)!
        assert_eq!(
            mock::transact_as(buyer_identity, rv_hps, &claim_cd),
            Err(-34)
        );

        // Day 90 (1,800,000 cumulative blocks validated across 3 months!):
        mock::set_block_number(1_000 + 89 * 20_000);
        let ep90 = mock::transact_as(buyer_identity, rv_hps, ep_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(ep90[24..32].try_into().unwrap()), 90);

        // 3. MEV frontrunner copying `(pk_v, valid_sig)` and swapping `recipient_id` to `mev_frontrunner` FAILS (-32)!
        let frontrun_cd = encode_claim(
            &stripe_payment_ref,
            &pk_v,
            &val_pk1,
            &mev_frontrunner,
            &buyer_eth_wallet,
            &valid_sig,
        );
        assert_eq!(
            mock::transact_as(mev_frontrunner, rv_hps, &frontrun_cd),
            Err(-32)
        );

        // 4. Legitimate claim succeeds -> mints 239,600,000 SLXR & emits EthereumMintAuthorized!
        let claimed = mock::transact_as(buyer_identity, rv_hps, &claim_cd).unwrap();
        assert_eq!(
            u64::from_be_bytes(claimed[24..32].try_into().unwrap()),
            239_600_000
        );

        // 5. Re-using the SAME validator (`val_pk1`) to unlock a 2nd bought Dongle voucher FAILS (-33)!
        let (sk_v2, pk_v2) = kp(43);
        let ref2 = keccak256(b"stripe:pi_second_dongle_1002");
        let issue2 = CallEncoder::<256>::new(selector(
            "issuePaidVoucher(bytes32,uint64,uint64,uint64,bytes32)",
        ))
        .push_bytes32(&ref2)
        .push_u64(SKU_DONGLE)
        .push_u64(TIER_RETAIL_BPS)
        .push_u64(0)
        .push_bytes32(&voucher_commitment_for_pk(&pk_v2));
        assert!(mock::transact_as(banking_oracle, rv_hps, issue2.as_slice()).is_ok());

        let mut ctx2 = [0u8; 137];
        ctx2[0..13].copy_from_slice(DOMAIN_CLAIM);
        ctx2[13..33].copy_from_slice(&rv_hps);
        ctx2[33..65].copy_from_slice(&ref2);
        ctx2[65..97].copy_from_slice(&val_pk1);
        ctx2[97..117].copy_from_slice(&buyer_identity);
        ctx2[117..137].copy_from_slice(&buyer_eth_wallet);
        let sig2 = schnorr_sign(&sk_v2, &ctx2);
        let reuse_val_cd = encode_claim(
            &ref2,
            &pk_v2,
            &val_pk1,
            &buyer_identity,
            &buyer_eth_wallet,
            &sig2,
        );
        assert_eq!(
            mock::transact_as(buyer_identity, rv_hps, &reuse_val_cd),
            Err(-33)
        );

        // 6. Pre-activation refund revokes `ref2` cleanly, whereas already-claimed `stripe_payment_ref` cannot be revoked!
        let rev1 = CallEncoder::<128>::new(selector("revokeRefundedVoucher(bytes32)"))
            .push_bytes32(&stripe_payment_ref);
        assert_eq!(
            mock::transact_as(banking_oracle, rv_hps, rev1.as_slice()),
            Err(-20)
        );
        let rev2 =
            CallEncoder::<128>::new(selector("revokeRefundedVoucher(bytes32)")).push_bytes32(&ref2);
        assert!(mock::transact_as(banking_oracle, rv_hps, rev2.as_slice()).is_ok());

        // 7. Cash-back redemption: before buffer deposit, rate is $0.00 (-37); after $119.80 (119,800,000 micro-USD)
        //    realized COGS savings deposit, redeeming 50% (119,800,000 SLXR) pays out exact $59.90 (59,900,000 micro-USD)!
        let red_half = CallEncoder::<128>::new(selector("redeemSlxrForCashBack(uint64)"))
            .push_u64(119_800_000);
        assert_eq!(
            mock::transact_as(buyer_identity, rv_hps, red_half.as_slice()),
            Err(-37)
        );

        let dep_cd = CallEncoder::<128>::new(selector("depositRealizedBufferSavings(uint64)"))
            .push_u64(119_800_000);
        assert!(mock::transact_as(banking_oracle, rv_hps, dep_cd.as_slice()).is_ok());

        let payout = mock::transact_as(buyer_identity, rv_hps, red_half.as_slice()).unwrap();
        assert_eq!(
            u64::from_be_bytes(payout[24..32].try_into().unwrap()),
            59_900_000
        );
    }

    #[test]
    fn foreign_three_node_rf_subnet_quorum_epoch_attestation_verifies_and_enforces_spacing() {
        mock::reset();
        let rv_hps = [0xD6; 20];
        let admin = [0x01; 20];
        let oracle = [0x02; 20];
        mock::register_hps(rv_hps, dispatch_calldata);
        mock::set_block_number(5_000);

        let init_cd = CallEncoder::<256>::new(selector(
            "initialize(address,address,address,address,address,uint64,uint64)",
        ))
        .push_address(&admin)
        .push_address(&oracle)
        .push_address(&[0u8; 20])
        .push_address(&[0u8; 20])
        .push_address(&[0u8; 20])
        .push_u64(90)
        .push_u64(20_000);
        assert!(mock::transact_as(admin, rv_hps, init_cd.as_slice()).is_ok());

        let mut peers = [kp(11), kp(22), kp(33)];
        peers.sort_by(|a, b| a.1.cmp(&b.1));
        let target_val_pk = peers[1].1;
        let foreign_sid = keccak256(b"sahara-solar-rf-subnet-915");
        let epoch_blocks = 20_100u64;

        let mut msg = [0u8; 108];
        msg[0..20].copy_from_slice(DOMAIN_FOREIGN_EPOCH);
        msg[20..40].copy_from_slice(&rv_hps);
        msg[40..72].copy_from_slice(&foreign_sid);
        msg[72..80].copy_from_slice(&1u64.to_be_bytes());
        msg[80..100].copy_from_slice(&target_val_pk[0..20]);
        msg[100..108].copy_from_slice(&epoch_blocks.to_be_bytes());
        let digest = keccak256(&msg);

        let mut blob = Vec::with_capacity(3 * 96);
        for (sk, pk) in &peers {
            let sig = schnorr_sign(sk, &digest);
            blob.extend_from_slice(pk);
            blob.extend_from_slice(&sig);
        }

        let mut cd = Vec::new();
        cd.extend_from_slice(&selector(
            "recordForeignSubnetEpoch(bytes32,bytes32,uint64,bytes)",
        ));
        cd.extend_from_slice(&foreign_sid);
        cd.extend_from_slice(&target_val_pk);
        let mut eb_w = [0u8; 32];
        eb_w[24..32].copy_from_slice(&epoch_blocks.to_be_bytes());
        cd.extend_from_slice(&eb_w);
        let mut off_w = [0u8; 32];
        off_w[31] = 128;
        cd.extend_from_slice(&off_w);
        let mut len_w = [0u8; 32];
        len_w[30..32].copy_from_slice(&(blob.len() as u16).to_be_bytes());
        cd.extend_from_slice(&len_w);
        cd.extend_from_slice(&blob);
        let pad = (32 - (blob.len() % 32)) % 32;
        cd.extend(std::iter::repeat(0u8).take(pad));

        let res = mock::transact_as(admin, rv_hps, &cd).unwrap();
        assert_eq!(u64::from_be_bytes(res[24..32].try_into().unwrap()), 1);
    }
}
