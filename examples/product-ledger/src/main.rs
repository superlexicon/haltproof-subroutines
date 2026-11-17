//! Product Ledger **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Institutional product inventory, catalog, and checkout ledger pinned to a single
//! `IdentityRegistry`, a single `CorporateCharter`, and an `AccountingLedger`:
//! - Catalog & inventory updates (`upsertProduct`, `restockProduct`, `setProductPrice`) are invoked
//!   directly on `ProductLedger` and governed by `CorporateCharter.getFunctionAuth(self, selector)`
//!   (defaulting to `POLICY_PRODUCT_MANAGEMENT` / `ROLE_PRODUCT_MANAGER`).
//! - Customer checkout (`buyProduct(bytes32 productId, uint64 quantity)`):
//!   1. Verifies `CorporateCharter` is `ACTIVE` and `buyer` is an active `Identity`.
//!   2. Reverts with `ERR_INSUFFICIENT_PRODUCT_UNITS (-82)` if `unitsAvailable < quantity`.
//!   3. Settles `quantity * latestPrice` from `buyer` directly into `ProductLedger`'s configured
//!      **`operatingRevenueAccount`** (segregated from `ShareCapital`'s shareholder auction escrow)
//!      on `operatingBankLedger` via `charterModuleClearTransfer` (`CAP_MERCHANT_PAYMENT`).
//!   4. Decrements `unitsAvailable` and logs the immutable sale entry in `AccountingLedger.recordSale`
//!      (preserving strict accounting segregation of duties).

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    query_charter_function_auth, require_active_charter, require_valid_identity,
    verify_and_consume_auth, ActionHasher, ACTION_RESTOCK_PRODUCT, ACTION_SET_OPERATING_ACCOUNT,
    ACTION_SET_PRODUCT_PRICE, ACTION_UPSERT_PRODUCT, ERR_AUTH_CONSUME_FAILED, ERR_CHARTER_MISMATCH,
    ERR_INSUFFICIENT_PRODUCT_UNITS, ERR_INVALID_PRODUCT_PARAMS, ERR_MISSING_ROLE,
    ERR_PRODUCT_NOT_FOUND, POLICY_BOARD_RESOLUTION, POLICY_PRODUCT_MANAGEMENT,
    ROLE_PRODUCT_MANAGER,
};
use hps_sdk::social::{
    adjust_standing_from_module, require_active_member, require_mutual_rf_proximity,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const PRODUCT_LEDGER_INITIALIZED: [u8; 32] =
    event_topic("ProductLedgerInitialized(address,address,uint64)");
const OPERATING_ACCOUNT_SET: [u8; 32] =
    event_topic("OperatingAccountSet(address,address,address)");
const PRODUCT_UPSERTED: [u8; 32] =
    event_topic("ProductUpserted(bytes32,uint64,uint64,address)");
const PRODUCT_RESTOCKED: [u8; 32] =
    event_topic("ProductRestocked(bytes32,uint64,uint64,uint64,address)");
const PRODUCT_PRICE_UPDATED: [u8; 32] =
    event_topic("ProductPriceUpdated(bytes32,uint64,uint64,address)");
const PRODUCT_PURCHASED: [u8; 32] = event_topic(
    "ProductPurchased(bytes32,address,uint64,uint64,uint64,uint64,uint64)",
);

const SEL_SET_OPERATING_ACCOUNT: [u8; 4] =
    selector("setOperatingAccount(address,address,address)");
const SEL_UPSERT_PRODUCT: [u8; 4] =
    selector("upsertProduct(bytes32,uint64,uint64,bytes,address)");
const SEL_RESTOCK_PRODUCT: [u8; 4] = selector("restockProduct(bytes32,uint64,uint64,address)");
const SEL_SET_PRODUCT_PRICE: [u8; 4] = selector("setProductPrice(bytes32,uint64,address)");

const KEY_INIT: &[u8] = b"prd:init";
const KEY_REGISTRY: &[u8] = b"prd:reg";
const KEY_CHARTER: &[u8] = b"prd:chr";
const KEY_INITIALIZER: &[u8] = b"prd:init_by";
const KEY_ACCOUNTING: &[u8] = b"prd:acc";
const KEY_OP_BANK_LEDGER: &[u8] = b"prd:bank_led";
const KEY_OP_REV_ACCOUNT: &[u8] = b"prd:rev_acct";
const KEY_PRODUCT_COUNT: &[u8] = b"prd:cnt";
const KEY_OWNER_IDENTITY: &[u8] = b"prd:owner_id";
const KEY_SOCIAL_SALES_CNT: &[u8] = b"prd:soc_scnt";

pub const MODE_CORPORATE_CHARTER: u64 = 1;
pub const MODE_IDENTITY_SOCIAL: u64 = 2;

static mut CATALOG_SNAP_BUF: [u8; 8192] = [0u8; 8192];

const PRODUCT_ROW_LEN: usize = 58;
const GENESIS_PRODUCT_PACK_LEN: usize = 80;

#[derive(Clone, Copy)]
struct ProductRow {
    active: bool,
    name_len: u8,
    units_available: u64,
    latest_price: u64,
    total_units_sold: u64,
    name: [u8; 32],
}

impl ProductRow {
    fn encode(&self) -> [u8; PRODUCT_ROW_LEN] {
        let mut out = [0u8; PRODUCT_ROW_LEN];
        out[0] = u8::from(self.active);
        out[1] = self.name_len.min(32);
        out[2..10].copy_from_slice(&self.units_available.to_be_bytes());
        out[10..18].copy_from_slice(&self.latest_price.to_be_bytes());
        out[18..26].copy_from_slice(&self.total_units_sold.to_be_bytes());
        out[26..58].copy_from_slice(&self.name);
        out
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < PRODUCT_ROW_LEN {
            return None;
        }
        let active = raw[0] == 1;
        let name_len = raw[1].min(32);
        let mut ua = [0u8; 8];
        ua.copy_from_slice(&raw[2..10]);
        let mut lp = [0u8; 8];
        lp.copy_from_slice(&raw[10..18]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&raw[18..26]);
        let mut name = [0u8; 32];
        name.copy_from_slice(&raw[26..58]);
        Some(Self {
            active,
            name_len,
            units_available: u64::from_be_bytes(ua),
            latest_price: u64::from_be_bytes(lp),
            total_units_sold: u64::from_be_bytes(ts),
            name,
        })
    }
}

hps_entry! {
    "initialize(address,address,address,bytes)"                                 => handle_initialize_4,
    "initializeWithBank(address,address,address,address,address,bytes)"         => handle_initialize_6,
    "initializeForIdentity(address,address,address,bytes)"                      => handle_initialize_for_identity,
    "setOperatingAccount(address,address,address)"                              => handle_set_operating_account,
    "upsertProduct(bytes32,uint64,uint64,bytes,address)"                        => handle_upsert_product,
    "restockProduct(bytes32,uint64,uint64,address)"                             => handle_restock_product,
    "setProductPrice(bytes32,uint64,address)"                                   => handle_set_product_price,
    "buyProduct(bytes32,uint64)"                                                => handle_buy_product,
    "getProduct(bytes32)"                                                       => handle_get_product,
    "getCatalogSnapshot()"                                                      => handle_get_catalog_snapshot,
    "ownerIdentity()"                                                           => handle_owner_identity,
    "ledgerMode()"                                                              => handle_ledger_mode,
    "unitsAvailableOf(bytes32)"                                                 => handle_units_available_of,
    "latestPriceOf(bytes32)"                                                    => handle_latest_price_of,
    "productCount()"                                                            => handle_product_count,
    "productIdAt(uint64)"                                                       => handle_product_id_at,
    "associatedCharter()"                                                       => handle_associated_charter,
    "associatedConstitution()"                                                  => handle_associated_charter,
    "accountingLedger()"                                                        => handle_accounting_ledger,
    "operatingBankLedger()"                                                     => handle_operating_bank_ledger,
    "operatingRevenueAccount()"                                                 => handle_operating_revenue_account,
    "identityRegistry()"                                                        => handle_identity_registry,
    "hashSetOperatingAccount(address,address)"                                  => handle_hash_set_operating_account,
    "hashUpsertProduct(bytes32,uint64,uint64,bytes)"                            => handle_hash_upsert_product,
    "hashRestockProduct(bytes32,uint64,uint64)"                                 => handle_hash_restock_product,
    "hashSetProductPrice(bytes32,uint64)"                                       => handle_hash_set_product_price,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn product_key(product_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"prd:row:").push(product_id)
}

fn product_seen_key(product_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"prd:seen:").push(product_id)
}

fn product_index_key(idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"prd:idx:")
        .push_u64_be(idx)
}

fn load_product(product_id: &[u8; 32]) -> Option<ProductRow> {
    let pk = product_key(product_id);
    let mut raw = [0u8; PRODUCT_ROW_LEN];
    let n = storage::get_into(pk.as_slice(), &mut raw)?;
    ProductRow::decode(&raw[..n])
}

fn save_product(product_id: &[u8; 32], row: &ProductRow) {
    let pk = product_key(product_id);
    let enc = row.encode();
    storage::set(pk.as_slice(), &enc);

    let sk = product_seen_key(product_id);
    if storage::get_u64(sk.as_slice()) == 0 {
        storage::set_u64(sk.as_slice(), 1);
        let cnt = storage::get_u64(KEY_PRODUCT_COUNT);
        let ik = product_index_key(cnt);
        storage::set(ik.as_slice(), product_id);
        storage::set_u64(KEY_PRODUCT_COUNT, cnt + 1);
    }
}

fn compute_set_operating_account_hash(
    bank_ledger: &[u8; 20],
    revenue_account: &[u8; 20],
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_OPERATING_ACCOUNT)
        .push_address(bank_ledger)
        .push_address(revenue_account)
        .finish()
}

fn compute_upsert_hash(
    product_id: &[u8; 32],
    units_available: u64,
    latest_price: u64,
    name: &[u8],
) -> [u8; 32] {
    ActionHasher::<192>::new(&context::self_address(), &ACTION_UPSERT_PRODUCT)
        .push_bytes32(product_id)
        .push_u64(units_available)
        .push_u64(latest_price)
        .push_bytes_digest(name)
        .finish()
}

fn compute_restock_hash(
    product_id: &[u8; 32],
    additional_units: u64,
    new_price: u64,
) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_RESTOCK_PRODUCT)
        .push_bytes32(product_id)
        .push_u64(additional_units)
        .push_u64(new_price)
        .finish()
}

fn compute_set_price_hash(product_id: &[u8; 32], new_price: u64) -> [u8; 32] {
    ActionHasher::<160>::new(&context::self_address(), &ACTION_SET_PRODUCT_PRICE)
        .push_bytes32(product_id)
        .push_u64(new_price)
        .finish()
}

fn ensure_active_and_valid_caller() -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let charter = storage::get_address(KEY_CHARTER).ok_or(-10)?;
    require_active_charter(&charter)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, charter, caller))
}

/// Verify catalog mutation authorization against `CorporateCharter.getFunctionAuth(self, fnSelector)`:
/// - If `auth_obj != 0x0`, consumes `auth_obj` matching `(charter, req_pol, action_hash)`.
/// - If `auth_obj == 0x0`, permits direct role-holder execution ONLY when `req_pol` is
///   `POLICY_PRODUCT_MANAGEMENT` (`ROLE_PRODUCT_MANAGER`) or a defined single role in `CorporateCharter`;
///   if `CorporateCharter` configured a custom multi-stage policy (e.g., `POLICY_DUAL_PRODUCT_CFO`),
///   `auth_obj == 0x0` is rejected so multi-stage governance cannot be bypassed!
fn require_product_catalog_auth(
    registry: &[u8; 20],
    charter: &[u8; 20],
    fn_selector: &[u8; 4],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
    caller: &[u8; 20],
) -> Result<(), i32> {
    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(charter, &me, fn_selector);

    if *auth_obj != [0u8; 20] {
        let req_pol = if let Some(pol) = explicit_pol {
            pol
        } else {
            let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
            if let Ok(raw_pid) = call::call_raw(auth_obj, pid_cd.as_slice()) {
                if raw_pid.len() >= 32 && raw_pid[..32] == ROLE_PRODUCT_MANAGER {
                    ROLE_PRODUCT_MANAGER
                } else {
                    POLICY_PRODUCT_MANAGEMENT
                }
            } else {
                POLICY_PRODUCT_MANAGEMENT
            }
        };
        return verify_and_consume_auth(registry, auth_obj, charter, &req_pol, action_hash, caller);
    }

    let role_to_check = match explicit_pol {
        None | Some(POLICY_PRODUCT_MANAGEMENT) => ROLE_PRODUCT_MANAGER,
        Some(pol) => {
            let def_cd = CallEncoder::<64>::new(const { selector("isRoleDefined(bytes32)") })
                .push_bytes32(&pol);
            if !matches!(call::call_bool(charter, def_cd.as_slice()), Ok(true)) {
                return Err(ERR_AUTH_CONSUME_FAILED);
            }
            pol
        }
    };

    let role_cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
        .push_bytes32(&role_to_check)
        .push_address(caller);
    if matches!(call::call_bool(charter, role_cd.as_slice()), Ok(true)) {
        Ok(())
    } else {
        Err(ERR_MISSING_ROLE)
    }
}

fn execute_initialize(
    registry: &[u8; 20],
    charter: &[u8; 20],
    accounting_ledger: &[u8; 20],
    op_bank_ledger: &[u8; 20],
    op_rev_account: &[u8; 20],
    initial_products: &[u8],
) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    if *registry == [0u8; 20]
        || *charter == [0u8; 20]
        || *accounting_ledger == [0u8; 20]
        || initial_products.len() % GENESIS_PRODUCT_PACK_LEN != 0
        || ((*op_bank_ledger == [0u8; 20]) != (*op_rev_account == [0u8; 20]))
    {
        return Err(ERR_CHARTER_MISMATCH);
    }

    let caller = context::msg_sender();
    require_valid_identity(registry, &caller)?;
    if *op_rev_account != [0u8; 20] {
        require_valid_identity(registry, op_rev_account)?;
        storage::set_address(KEY_OP_BANK_LEDGER, op_bank_ledger);
        storage::set_address(KEY_OP_REV_ACCOUNT, op_rev_account);
    }

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_REGISTRY, registry);
    storage::set_address(KEY_CHARTER, charter);
    storage::set_address(KEY_INITIALIZER, &caller);
    storage::set_address(KEY_ACCOUNTING, accounting_ledger);
    storage::set_u64(KEY_PRODUCT_COUNT, 0);

    let count = initial_products.len() / GENESIS_PRODUCT_PACK_LEN;
    let mut i = 0usize;
    while i < count {
        let base = i * GENESIS_PRODUCT_PACK_LEN;
        let mut product_id = [0u8; 32];
        product_id.copy_from_slice(&initial_products[base..base + 32]);
        let mut ub = [0u8; 8];
        ub.copy_from_slice(&initial_products[base + 32..base + 40]);
        let units_available = u64::from_be_bytes(ub);
        let mut pb = [0u8; 8];
        pb.copy_from_slice(&initial_products[base + 40..base + 48]);
        let latest_price = u64::from_be_bytes(pb);
        let mut name = [0u8; 32];
        name.copy_from_slice(&initial_products[base + 48..base + 80]);

        if product_id == [0u8; 32] || latest_price == 0 {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }
        let mut name_len = 32usize;
        while name_len > 0 && name[name_len - 1] == 0 {
            name_len -= 1;
        }
        let row = ProductRow {
            active: true,
            name_len: name_len as u8,
            units_available,
            latest_price,
            total_units_sold: 0,
            name,
        };
        save_product(&product_id, &row);

        let mut ev = [0u8; 16];
        ev[0..8].copy_from_slice(&units_available.to_be_bytes());
        ev[8..16].copy_from_slice(&latest_price.to_be_bytes());
        events::emit(&[PRODUCT_UPSERTED, product_id, addr_topic(&caller)], &ev);
        i += 1;
    }

    events::emit(
        &[
            PRODUCT_LEDGER_INITIALIZED,
            addr_topic(charter),
            addr_topic(accounting_ledger),
        ],
        &(count as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_initialize_4(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let charter = args.address(1).ok_or(-3)?;
    let accounting_ledger = args.address(2).ok_or(-3)?;
    let initial_products = args.dynamic_bytes(3).ok_or(-3)?;
    execute_initialize(
        &registry,
        &charter,
        &accounting_ledger,
        &[0u8; 20],
        &[0u8; 20],
        initial_products,
    )
}

fn handle_initialize_6(args: &CalldataReader) -> Result<(), i32> {
    let registry = args.address(0).ok_or(-3)?;
    let charter = args.address(1).ok_or(-3)?;
    let accounting_ledger = args.address(2).ok_or(-3)?;
    let op_bank_ledger = args.address(3).ok_or(-3)?;
    let op_rev_account = args.address(4).ok_or(-3)?;
    let initial_products = args.dynamic_bytes(5).ok_or(-3)?;
    execute_initialize(
        &registry,
        &charter,
        &accounting_ledger,
        &op_bank_ledger,
        &op_rev_account,
        initial_products,
    )
}

/// Initialize a Personal / Identity-Owned `ProductLedger` storefront pinned to an `Identity` HFS
/// (`ownerIdentity`), `IdentityRegistry`, and a neighborhood `SocialCharter` (`MODE_IDENTITY_SOCIAL`).
fn handle_initialize_for_identity(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let owner_identity = args.address(1).ok_or(-3)?;
    let social_charter = args.address(2).ok_or(-3)?;
    let initial_products = args.dynamic_bytes(3).ok_or(-3)?;

    if registry == [0u8; 20]
        || owner_identity == [0u8; 20]
        || social_charter == [0u8; 20]
        || initial_products.len() % GENESIS_PRODUCT_PACK_LEN != 0
    {
        return Err(ERR_CHARTER_MISMATCH);
    }

    require_valid_identity(&registry, &owner_identity)?;
    let caller = context::msg_sender();
    if caller != owner_identity {
        return Err(ERR_MISSING_ROLE);
    }

    // Owner Identity must be an Active In-Subnet Verified Citizen (`Trust >= 60`) on `SocialCharter`!
    require_active_member(&social_charter, &owner_identity, 60)?;

    storage::set_u64(KEY_INIT, MODE_IDENTITY_SOCIAL);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_OWNER_IDENTITY, &owner_identity);
    storage::set_address(KEY_CHARTER, &social_charter);
    storage::set_address(KEY_INITIALIZER, &owner_identity);
    storage::set_u64(KEY_PRODUCT_COUNT, 0);

    let count = initial_products.len() / GENESIS_PRODUCT_PACK_LEN;
    let mut i = 0usize;
    while i < count {
        let base = i * GENESIS_PRODUCT_PACK_LEN;
        let mut product_id = [0u8; 32];
        product_id.copy_from_slice(&initial_products[base..base + 32]);
        let mut ub = [0u8; 8];
        ub.copy_from_slice(&initial_products[base + 32..base + 40]);
        let units_available = u64::from_be_bytes(ub);
        let mut pb = [0u8; 8];
        pb.copy_from_slice(&initial_products[base + 40..base + 48]);
        let latest_price = u64::from_be_bytes(pb);
        let mut name = [0u8; 32];
        name.copy_from_slice(&initial_products[base + 48..base + 80]);

        if product_id == [0u8; 32] {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }
        let mut name_len = 32usize;
        while name_len > 0 && name[name_len - 1] == 0 {
            name_len -= 1;
        }
        let row = ProductRow {
            active: true,
            name_len: name_len as u8,
            units_available,
            latest_price,
            total_units_sold: 0,
            name,
        };
        save_product(&product_id, &row);

        let mut ev = [0u8; 16];
        ev[0..8].copy_from_slice(&units_available.to_be_bytes());
        ev[8..16].copy_from_slice(&latest_price.to_be_bytes());
        events::emit(&[PRODUCT_UPSERTED, product_id, addr_topic(&owner_identity)], &ev);
        i += 1;
    }

    events::emit(
        &[
            PRODUCT_LEDGER_INITIALIZED,
            addr_topic(&social_charter),
            addr_topic(&owner_identity),
        ],
        &(count as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

fn ensure_owner_identity_seller() -> Result<([u8; 20], [u8; 20]), i32> {
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let owner_id = storage::get_address(KEY_OWNER_IDENTITY).ok_or(-10)?;
    let social_charter = storage::get_address(KEY_CHARTER).ok_or(-10)?;
    let caller = context::msg_sender();
    if caller != owner_id {
        return Err(ERR_MISSING_ROLE);
    }
    require_valid_identity(&registry, &caller)?;
    require_active_member(&social_charter, &caller, 60)?;
    Ok((owner_id, social_charter))
}

fn handle_set_operating_account(args: &CalldataReader) -> Result<(), i32> {
    let (registry, charter, caller) = ensure_active_and_valid_caller()?;
    let bank_ledger = args.address(0).ok_or(-3)?;
    let rev_account = args.address(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    if bank_ledger == [0u8; 20] || rev_account == [0u8; 20] {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }
    require_valid_identity(&registry, &rev_account)?;

    let me = context::self_address();
    let explicit_pol = query_charter_function_auth(&charter, &me, &SEL_SET_OPERATING_ACCOUNT);
    if auth_obj == [0u8; 20]
        && storage::get_address(KEY_OP_REV_ACCOUNT).is_none()
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
        let action_hash = compute_set_operating_account_hash(&bank_ledger, &rev_account);
        verify_and_consume_auth(&registry, &auth_obj, &charter, &req_pol, &action_hash, &caller)?;
    }

    storage::set_address(KEY_OP_BANK_LEDGER, &bank_ledger);
    storage::set_address(KEY_OP_REV_ACCOUNT, &rev_account);

    events::emit(
        &[
            OPERATING_ACCOUNT_SET,
            addr_topic(&bank_ledger),
            addr_topic(&rev_account),
            addr_topic(&auth_obj),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    let mode = storage::get_u64(KEY_INIT);
    let product_id = args.bytes32(0).ok_or(-3)?;
    let units_available = args.u64(1).ok_or(-3)?;
    let latest_price = args.u64(2).ok_or(-3)?;
    let raw_name = args.dynamic_bytes(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    let caller = if mode == MODE_IDENTITY_SOCIAL {
        if product_id == [0u8; 32] || raw_name.is_empty() || raw_name.len() > 32 {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }
        let (owner_id, _sc) = ensure_owner_identity_seller()?;
        owner_id
    } else {
        let (registry, charter, c) = ensure_active_and_valid_caller()?;
        if product_id == [0u8; 32] || latest_price == 0 || raw_name.is_empty() || raw_name.len() > 32
        {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }
        let action_hash = compute_upsert_hash(&product_id, units_available, latest_price, raw_name);
        require_product_catalog_auth(
            &registry,
            &charter,
            &SEL_UPSERT_PRODUCT,
            &action_hash,
            &auth_obj,
            &c,
        )?;
        c
    };

    let prev_sold = load_product(&product_id)
        .map(|r| r.total_units_sold)
        .unwrap_or(0);
    let mut name = [0u8; 32];
    name[..raw_name.len()].copy_from_slice(raw_name);

    let row = ProductRow {
        active: true,
        name_len: raw_name.len() as u8,
        units_available,
        latest_price,
        total_units_sold: prev_sold,
        name,
    };
    save_product(&product_id, &row);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&units_available.to_be_bytes());
    ev[8..16].copy_from_slice(&latest_price.to_be_bytes());
    events::emit(&[PRODUCT_UPSERTED, product_id, addr_topic(&caller)], &ev);

    ret::write_bool(true);
    Ok(())
}

fn handle_restock_product(args: &CalldataReader) -> Result<(), i32> {
    let mode = storage::get_u64(KEY_INIT);
    let product_id = args.bytes32(0).ok_or(-3)?;
    let additional_units = args.u64(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    if additional_units == 0 && new_price == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }

    let caller = if mode == MODE_IDENTITY_SOCIAL {
        let (owner_id, _sc) = ensure_owner_identity_seller()?;
        owner_id
    } else {
        let (registry, charter, c) = ensure_active_and_valid_caller()?;
        let action_hash = compute_restock_hash(&product_id, additional_units, new_price);
        require_product_catalog_auth(
            &registry,
            &charter,
            &SEL_RESTOCK_PRODUCT,
            &action_hash,
            &auth_obj,
            &c,
        )?;
        c
    };

    row.units_available = row
        .units_available
        .checked_add(additional_units)
        .ok_or(-15)?;
    if new_price > 0 {
        row.latest_price = new_price;
    }
    save_product(&product_id, &row);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&additional_units.to_be_bytes());
    ev[8..16].copy_from_slice(&row.units_available.to_be_bytes());
    ev[16..24].copy_from_slice(&row.latest_price.to_be_bytes());
    events::emit(&[PRODUCT_RESTOCKED, product_id, addr_topic(&caller)], &ev);

    ret::write_u64_word(row.units_available);
    Ok(())
}

fn handle_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    let mode = storage::get_u64(KEY_INIT);
    let product_id = args.bytes32(0).ok_or(-3)?;
    let new_price = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }

    let caller = if mode == MODE_IDENTITY_SOCIAL {
        let (owner_id, _sc) = ensure_owner_identity_seller()?;
        owner_id
    } else {
        let (registry, charter, c) = ensure_active_and_valid_caller()?;
        if new_price == 0 {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }
        let action_hash = compute_set_price_hash(&product_id, new_price);
        require_product_catalog_auth(
            &registry,
            &charter,
            &SEL_SET_PRODUCT_PRICE,
            &action_hash,
            &auth_obj,
            &c,
        )?;
        c
    };

    let old_price = row.latest_price;
    row.latest_price = new_price;
    save_product(&product_id, &row);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&old_price.to_be_bytes());
    ev[8..16].copy_from_slice(&new_price.to_be_bytes());
    events::emit(&[PRODUCT_PRICE_UPDATED, product_id, addr_topic(&caller)], &ev);

    ret::write_bool(true);
    Ok(())
}

fn handle_buy_product(args: &CalldataReader) -> Result<(), i32> {
    let mode = storage::get_u64(KEY_INIT);
    let product_id = args.bytes32(0).ok_or(-3)?;
    let quantity = args.u64(1).ok_or(-3)?;
    if quantity == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    if mode == MODE_IDENTITY_SOCIAL {
        let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
        let owner_id = storage::get_address(KEY_OWNER_IDENTITY).ok_or(-10)?;
        let social_charter = storage::get_address(KEY_CHARTER).ok_or(-10)?;
        let buyer = context::msg_sender();
        if buyer == owner_id {
            return Err(ERR_INVALID_PRODUCT_PARAMS);
        }

        // Both Buyer and Seller MUST be verified `Identity` HFS instances & Active In-Subnet!
        require_valid_identity(&registry, &buyer)?;
        require_active_member(&social_charter, &owner_id, 60)?;
        require_active_member(&social_charter, &buyer, 25)?;

        // Physical Marketplace Anti-Scam Rule: Seller & Buyer MUST be within <=150m 2.4 GHz RF!
        require_mutual_rf_proximity(&social_charter, &owner_id, &buyer)?;

        let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
        if !row.active {
            return Err(ERR_PRODUCT_NOT_FOUND);
        }
        if row.units_available < quantity {
            return Err(ERR_INSUFFICIENT_PRODUCT_UNITS);
        }

        let unit_price = row.latest_price;
        let total_cost = quantity.checked_mul(unit_price).ok_or(-15)?;

        row.units_available -= quantity;
        row.total_units_sold = row.total_units_sold.saturating_add(quantity);
        save_product(&product_id, &row);

        let sale_idx = storage::get_u64(KEY_SOCIAL_SALES_CNT);
        storage::set_u64(KEY_SOCIAL_SALES_CNT, sale_idx + 1);

        let _ = adjust_standing_from_module(&social_charter, &owner_id, 2, true);
        let _ = adjust_standing_from_module(&social_charter, &buyer, 2, true);

        let mut ev = [0u8; 40];
        ev[0..8].copy_from_slice(&quantity.to_be_bytes());
        ev[8..16].copy_from_slice(&unit_price.to_be_bytes());
        ev[16..24].copy_from_slice(&total_cost.to_be_bytes());
        ev[24..32].copy_from_slice(&row.units_available.to_be_bytes());
        ev[32..40].copy_from_slice(&sale_idx.to_be_bytes());
        events::emit(&[PRODUCT_PURCHASED, product_id, addr_topic(&buyer)], &ev);

        ret::write_u64_word(sale_idx);
        return Ok(());
    }

    let (_registry, _charter, buyer) = ensure_active_and_valid_caller()?;
    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }
    if row.units_available < quantity {
        return Err(ERR_INSUFFICIENT_PRODUCT_UNITS);
    }

    let unit_price = row.latest_price;
    let total_cost = quantity.checked_mul(unit_price).ok_or(-15)?;

    let bank_ledger = storage::get_address(KEY_OP_BANK_LEDGER).ok_or(-63)?;
    let rev_account = storage::get_address(KEY_OP_REV_ACCOUNT).ok_or(-63)?;

    // 1. Settle payment from buyer's bank sub-account directly into `operatingRevenueAccount`
    let pay_cd = CallEncoder::<128>::new(const {
        selector("charterModuleClearTransfer(address,address,uint64)")
    })
    .push_address(&buyer)
    .push_address(&rev_account)
    .push_u64(total_cost);
    let paid = call::call_bool(&bank_ledger, pay_cd.as_slice())?;
    if !paid {
        return Err(-16);
    }

    // 2. Decrement available inventory units and increment cumulative units sold
    row.units_available -= quantity;
    row.total_units_sold = row.total_units_sold.saturating_add(quantity);
    save_product(&product_id, &row);

    // 3. Record sale entry in the linked AccountingLedger (bookkeeping only)
    let accounting = storage::get_address(KEY_ACCOUNTING).ok_or(-10)?;
    let rec_cd = CallEncoder::<192>::new(const {
        selector("recordSale(bytes32,address,uint64,uint64,uint64)")
    })
    .push_bytes32(&product_id)
    .push_address(&buyer)
    .push_u64(quantity)
    .push_u64(unit_price)
    .push_u64(total_cost);
    let sale_idx = call::call_u64(&accounting, rec_cd.as_slice())?;

    let mut ev = [0u8; 40];
    ev[0..8].copy_from_slice(&quantity.to_be_bytes());
    ev[8..16].copy_from_slice(&unit_price.to_be_bytes());
    ev[16..24].copy_from_slice(&total_cost.to_be_bytes());
    ev[24..32].copy_from_slice(&row.units_available.to_be_bytes());
    ev[32..40].copy_from_slice(&sale_idx.to_be_bytes());
    events::emit(&[PRODUCT_PURCHASED, product_id, addr_topic(&buyer)], &ev);

    ret::write_u64_word(sale_idx);
    Ok(())
}

fn handle_owner_identity(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_OWNER_IDENTITY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_ledger_mode(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_INIT));
    Ok(())
}

fn handle_get_catalog_snapshot(_args: &CalldataReader) -> Result<i32, i32> {
    let count = storage::get_u64(KEY_PRODUCT_COUNT).min(64) as usize;
    unsafe {
        // Frame: `[u32 LE written][20B ownerIdentity][per SKU (90B): id(32) ++ units(8 LE) ++ price(8 LE) ++ sold(8 LE) ++ active(1) ++ nlen(1) ++ name(32)]`
        let out = &mut *core::ptr::addr_of_mut!(CATALOG_SNAP_BUF);
        let owner_id = storage::get_address(KEY_OWNER_IDENTITY).unwrap_or([0u8; 20]);
        out[4..24].copy_from_slice(&owner_id);
        let mut pos: usize = 24;
        let mut written: u32 = 0;

        let mut idx = 0usize;
        while idx < count {
            let ik = product_index_key(idx as u64);
            let mut pid = [0u8; 32];
            if storage::get_into(ik.as_slice(), &mut pid) == Some(32) {
                if let Some(row) = load_product(&pid) {
                    if pos + 90 > out.len() {
                        break;
                    }
                    out[pos..pos + 32].copy_from_slice(&pid);
                    out[pos + 32..pos + 40].copy_from_slice(&row.units_available.to_le_bytes());
                    out[pos + 40..pos + 48].copy_from_slice(&row.latest_price.to_le_bytes());
                    out[pos + 48..pos + 56].copy_from_slice(&row.total_units_sold.to_le_bytes());
                    out[pos + 56] = u8::from(row.active);
                    out[pos + 57] = row.name_len;
                    out[pos + 58..pos + 90].copy_from_slice(&row.name);
                    pos += 90;
                    written += 1;
                }
            }
            idx += 1;
        }

        out[0..4].copy_from_slice(&written.to_le_bytes());
        ret::write(&out[..pos]);
        Ok(pos as i32)
    }
}

fn handle_get_product(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&row.units_available.to_be_bytes());
    out[56..64].copy_from_slice(&row.latest_price.to_be_bytes());
    out[88..96].copy_from_slice(&row.total_units_sold.to_be_bytes());
    out[127] = u8::from(row.active);
    out[128..160].copy_from_slice(&row.name);
    ret::write(&out);
    Ok(())
}

fn handle_units_available_of(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let units = load_product(&product_id)
        .filter(|r| r.active)
        .map(|r| r.units_available)
        .unwrap_or(0);
    ret::write_u64_word(units);
    Ok(())
}

fn handle_latest_price_of(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let price = load_product(&product_id)
        .filter(|r| r.active)
        .map(|r| r.latest_price)
        .unwrap_or(0);
    ret::write_u64_word(price);
    Ok(())
}

fn handle_product_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_PRODUCT_COUNT));
    Ok(())
}

fn handle_product_id_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)?;
    if idx >= storage::get_u64(KEY_PRODUCT_COUNT) {
        return Err(-62);
    }
    let ik = product_index_key(idx);
    let mut id = [0u8; 32];
    let Some(n) = storage::get_into(ik.as_slice(), &mut id) else {
        return Err(-62);
    };
    if n < 32 {
        return Err(-62);
    }
    ret::write_word(&id);
    Ok(())
}

fn handle_associated_charter(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_CHARTER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_accounting_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_operating_bank_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_OP_BANK_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_operating_revenue_account(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_OP_REV_ACCOUNT).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_hash_set_operating_account(args: &CalldataReader) -> Result<(), i32> {
    let bank_ledger = args.address(0).ok_or(-3)?;
    let rev_account = args.address(1).ok_or(-3)?;
    ret::write_word(&compute_set_operating_account_hash(
        &bank_ledger,
        &rev_account,
    ));
    Ok(())
}

fn handle_hash_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let units_available = args.u64(1).ok_or(-3)?;
    let latest_price = args.u64(2).ok_or(-3)?;
    let raw_name = args.dynamic_bytes(3).ok_or(-3)?;
    ret::write_word(&compute_upsert_hash(
        &product_id,
        units_available,
        latest_price,
        raw_name,
    ));
    Ok(())
}

fn handle_hash_restock_product(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let additional_units = args.u64(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    ret::write_word(&compute_restock_hash(
        &product_id,
        additional_units,
        new_price,
    ));
    Ok(())
}

fn handle_hash_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let new_price = args.u64(1).ok_or(-3)?;
    ret::write_word(&compute_set_price_hash(&product_id, new_price));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::governance::CHARTER_STATE_ACTIVE;
    use hps_sdk::keccak::keccak256;
    use hps_sdk::{mock, selector};

    fn pack_genesis_product(
        product_id: [u8; 32],
        units: u64,
        price: u64,
        name: &[u8],
    ) -> [u8; GENESIS_PRODUCT_PACK_LEN] {
        let mut out = [0u8; GENESIS_PRODUCT_PACK_LEN];
        out[0..32].copy_from_slice(&product_id);
        out[32..40].copy_from_slice(&units.to_be_bytes());
        out[40..48].copy_from_slice(&price.to_be_bytes());
        out[48..48 + name.len()].copy_from_slice(name);
        out
    }

    #[test]
    fn immediate_fulfilment_buy_order_clears_operating_bank_and_records_accounting_journal() {
        mock::reset();
        let registry = [0x10; 20];
        let charter = [0x20; 20];
        let accounting = [0x30; 20];
        let product_ledger = [0x40; 20];
        let bank_ledger = [0x60; 20];
        let rev_account = [0x70; 20];
        let catalog_mgr = [0x50; 20];
        let founder = [0x01; 20];
        let buyer_1 = [0x02; 20];
        let buyer_2 = [0x03; 20];

        mock::register_hps(registry, |raw| {
            let Some((sel, _)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                ret::write_bool(true);
                return 0;
            }
            -2
        });

        mock::register_hps(charter, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("state()") } {
                ret::write_u64_word(CHARTER_STATE_ACTIVE);
                return 0;
            }
            if sel == const { selector("getFunctionAuth(address,bytes4)") } {
                ret::write_word(&[0u8; 32]);
                return 0;
            }
            if sel == const { selector("hasRole(bytes32,address)") } {
                let rid = args.bytes32(0).unwrap();
                let who = args.address(1).unwrap();
                ret::write_bool(rid == ROLE_PRODUCT_MANAGER && who == [0x50; 20]);
                return 0;
            }
            -2
        });

        mock::register_hps(bank_ledger, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("setBal(address,uint64)") } {
                let who = args.address(0).unwrap();
                let bal = args.u64(1).unwrap();
                storage::set_u64(&who, bal);
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("balOf(address)") } {
                ret::write_u64_word(storage::get_u64(&args.address(0).unwrap()));
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
            -2
        });

        mock::register_hps(accounting, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("recordSale(bytes32,address,uint64,uint64,uint64)") } {
                let qty = args.u64(2).unwrap();
                let total = args.u64(4).unwrap();
                let idx = storage::get_u64(b"macc:cnt");
                storage::set_u64(b"macc:cnt", idx + 1);
                storage::set_u64(b"macc:rev", storage::get_u64(b"macc:rev") + total);
                storage::set_u64(b"macc:units", storage::get_u64(b"macc:units") + qty);
                ret::write_u64_word(idx);
                return 0;
            }
            if sel == const { selector("totalRevenue()") } {
                ret::write_u64_word(storage::get_u64(b"macc:rev"));
                return 0;
            }
            -2
        });

        mock::register_hps(product_ledger, dispatch_calldata);

        let sku_radio = keccak256(b"SLX-LR2021-RADIO");
        let sku_appliance = keccak256(b"SLX-VALIDATOR-APPLIANCE");
        let mut init_bytes = Vec::new();
        init_bytes.extend_from_slice(&pack_genesis_product(
            sku_radio,
            10,
            2_500,
            b"SLX-LR2021-RADIO",
        ));
        init_bytes.extend_from_slice(&pack_genesis_product(
            sku_appliance,
            4,
            12_000,
            b"SLX-VALIDATOR-APPLIANCE",
        ));

        mock::transact_as(
            founder,
            product_ledger,
            CallEncoder::<512>::new(const {
                selector("initializeWithBank(address,address,address,address,address,bytes)")
            })
            .push_address(&registry)
            .push_address(&charter)
            .push_address(&accounting)
            .push_address(&bank_ledger)
            .push_address(&rev_account)
            .push_u64(192)
            .push_dynamic_bytes_tail(&init_bytes)
            .as_slice(),
        )
        .unwrap();

        for (who, bal) in [(buyer_1, 30_000u64), (buyer_2, 20_000u64)] {
            mock::transact_as(
                founder,
                bank_ledger,
                CallEncoder::<96>::new(const { selector("setBal(address,uint64)") })
                    .push_address(&who)
                    .push_u64(bal)
                    .as_slice(),
            )
            .unwrap();
        }

        let sale_0 = mock::transact_as(
            buyer_1,
            product_ledger,
            CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                .push_bytes32(&sku_radio)
                .push_u64(3)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(sale_0[24..32].try_into().unwrap()), 0);

        assert_eq!(
            mock::transact_as(
                buyer_1,
                product_ledger,
                CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                    .push_bytes32(&sku_appliance)
                    .push_u64(5)
                    .as_slice(),
            ),
            Err(ERR_INSUFFICIENT_PRODUCT_UNITS)
        );
        assert_eq!(
            mock::transact_as(
                buyer_2,
                product_ledger,
                CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                    .push_bytes32(&sku_appliance)
                    .push_u64(2)
                    .as_slice(),
            ),
            Err(-16)
        );

        // Unauthorized caller without ROLE_PRODUCT_MANAGER cannot restock
        assert_eq!(
            mock::transact_as(
                founder,
                product_ledger,
                CallEncoder::<160>::new(const {
                    selector("restockProduct(bytes32,uint64,uint64,address)")
                })
                .push_bytes32(&sku_radio)
                .push_u64(5)
                .push_u64(3_000)
                .push_address(&[0u8; 20])
                .as_slice(),
            ),
            Err(ERR_MISSING_ROLE)
        );

        // `catalog_mgr` holding `ROLE_PRODUCT_MANAGER` restocks +5 @ 3,000 SGD
        mock::transact_as(
            catalog_mgr,
            product_ledger,
            CallEncoder::<160>::new(const {
                selector("restockProduct(bytes32,uint64,uint64,address)")
            })
            .push_bytes32(&sku_radio)
            .push_u64(5)
            .push_u64(3_000)
            .push_address(&[0u8; 20])
            .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            buyer_2,
            product_ledger,
            CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                .push_bytes32(&sku_radio)
                .push_u64(4)
                .as_slice(),
        )
        .unwrap();

        let rev_bal = mock::transact_as(
            founder,
            bank_ledger,
            CallEncoder::<64>::new(const { selector("balOf(address)") })
                .push_address(&rev_account)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rev_bal[24..32].try_into().unwrap()), 19_500);

        let tot_rev = mock::transact_as(
            founder,
            accounting,
            CallEncoder::<16>::new(const { selector("totalRevenue()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(tot_rev[24..32].try_into().unwrap()), 19_500);
    }

    #[test]
    fn identity_owned_social_storefront_enforces_verified_standing_and_rf_proximity() {
        use hps_sdk::social::{MemberStanding, ERR_SOCIAL_OUTSIDE_RF_RANGE};

        mock::reset();
        let registry = [0x10; 20];
        let social_charter = [0x20; 20];
        let store_ledger = [0x45; 20];
        let seller_id = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let buyer_id = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        mock::register_hps(registry, |raw| {
            let Some((sel, _)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("isValidIdentity(address)") } {
                ret::write_bool(true);
                0
            } else {
                -2
            }
        });

        mock::register_hps(social_charter, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == const { selector("memberStanding(address)") } {
                let u = args.address(0).unwrap();
                ret::write_u64_word(
                    (MemberStanding {
                        registered: true,
                        is_active: true,
                        sanctioned: false,
                        trust_score: if u[19] == 1 { 82 } else { 60 },
                        uid: u[19],
                    })
                    .pack(),
                );
                0
            } else if sel == const { selector("checkMutualRfProximity(address,address)") } {
                ret::write_bool(storage::get_u64(b"far") == 0);
                0
            } else if sel == const { selector("adjustStandingFromModule(address,uint64,bool)") } {
                0
            } else {
                -1
            }
        });

        mock::register_hps(store_ledger, dispatch_calldata);

        // Seller Identity initializes its personal ProductLedger storefront
        mock::transact_as(
            seller_id,
            store_ledger,
            CallEncoder::<256>::new(const {
                selector("initializeForIdentity(address,address,address,bytes)")
            })
            .push_address(&registry)
            .push_address(&seller_id)
            .push_address(&social_charter)
            .push_u64(0x80)
            .push_dynamic_bytes_tail(&[])
            .as_slice(),
        )
        .unwrap();

        let sku = keccak256(b"SOON_KUEH_BOX");
        mock::transact_as(
            seller_id,
            store_ledger,
            CallEncoder::<256>::new(const {
                selector("upsertProduct(bytes32,uint64,uint64,bytes,address)")
            })
            .push_bytes32(&sku)
            .push_u64(10)
            .push_u64(12)
            .push_u64(160)
            .push_address(&[0u8; 20])
            .push_dynamic_bytes_tail(b"Soon Kueh Box (12pc)")
            .as_slice(),
        )
        .unwrap();

        // Out of <=150m 2.4 GHz range -> `buyProduct` rejected!
        mock::set_self_address(social_charter);
        storage::set_u64(b"far", 1);
        assert_eq!(
            mock::transact_as(
                buyer_id,
                store_ledger,
                CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                    .push_bytes32(&sku)
                    .push_u64(2)
                    .as_slice(),
            ),
            Err(ERR_SOCIAL_OUTSIDE_RF_RANGE)
        );

        // Within <=150m 2.4 GHz range -> `buyProduct` decrements ProductLedger inventory `10 -> 8`!
        mock::set_self_address(social_charter);
        storage::set_u64(b"far", 0);
        mock::transact_as(
            buyer_id,
            store_ledger,
            CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                .push_bytes32(&sku)
                .push_u64(2)
                .as_slice(),
        )
        .unwrap();

        let rem = mock::transact_as(
            buyer_id,
            store_ledger,
            CallEncoder::<64>::new(const { selector("unitsAvailableOf(bytes32)") })
                .push_bytes32(&sku)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rem[24..32].try_into().unwrap()), 8);
    }
}
