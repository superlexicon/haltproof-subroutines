//! Product Ledger **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Represents an institutional product inventory & catalog ledger owned/controlled by a single
//! `Constitution` HPS and paired with an `AccountingLedger` HPS:
//! - Each row in `ProductLedger` represents a product (`productId`), its `unitsAvailable` for sale,
//!   its `latestPrice`, its cumulative `totalUnitsSold`, and its 32-byte UTF-8 SKU/name label.
//! - Catalog & inventory updates (`upsertProduct`, `restockProduct`, `setProductPrice`) are governed
//!   by the Board-appointed Product Oracle / Catalog Manager Identity (`POLICY_PRODUCT_ORACLE` on
//!   the pinned `Constitution` HPS).
//! - Any verified buyer `Identity` can place an immediate-fulfilment buy order via
//!   `buyProduct(bytes32 productId, uint64 quantity)`:
//!   1. Reverts immediately with `ERR_INSUFFICIENT_PRODUCT_UNITS (-82)` if `unitsAvailable < quantity`.
//!   2. Atomically clears `quantity * latestPrice` from the buyer's sub-account in the company's
//!      Bank Balance `AssetLedger` into the `Constitution`'s clearing/revenue account (reverting
//!      if the buyer has insufficient bank balance).
//!   3. Decrements `unitsAvailable` by `quantity` and increments `totalUnitsSold`.
//!   4. Records the sale and increments `totalRevenue` in the linked `AccountingLedger` HPS.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    require_valid_identity, verify_and_consume_auth, ActionHasher, ACTION_RESTOCK_PRODUCT,
    ACTION_SET_PRODUCT_PRICE, ACTION_UPSERT_PRODUCT, ERR_CONSTITUTION_MISMATCH,
    ERR_INSUFFICIENT_PRODUCT_UNITS, ERR_INVALID_PRODUCT_PARAMS, ERR_MISSING_ROLE,
    ERR_PRODUCT_NOT_FOUND, POLICY_PRODUCT_ORACLE, ROLE_PRODUCT_MANAGER,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const PRODUCT_LEDGER_INITIALIZED: [u8; 32] =
    event_topic("ProductLedgerInitialized(address,address,uint64)");
const PRODUCT_UPSERTED: [u8; 32] =
    event_topic("ProductUpserted(bytes32,uint64,uint64,address)");
const PRODUCT_RESTOCKED: [u8; 32] =
    event_topic("ProductRestocked(bytes32,uint64,uint64,uint64,address)");
const PRODUCT_PRICE_UPDATED: [u8; 32] =
    event_topic("ProductPriceUpdated(bytes32,uint64,uint64,address)");
const PRODUCT_PURCHASED: [u8; 32] = event_topic(
    "ProductPurchased(bytes32,address,uint64,uint64,uint64,uint64,uint64)",
);

const KEY_INIT: &[u8] = b"prd:init";
const KEY_REGISTRY: &[u8] = b"prd:reg";
const KEY_CONSTITUTION: &[u8] = b"prd:con";
const KEY_ACCOUNTING: &[u8] = b"prd:acc";
const KEY_PRODUCT_COUNT: &[u8] = b"prd:cnt";

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
    "initialize(address,address,address,bytes)"                         => handle_initialize,
    "upsertProduct(bytes32,uint64,uint64,bytes,address)"                => handle_upsert_product,
    "restockProduct(bytes32,uint64,uint64,address)"                     => handle_restock_product,
    "setProductPrice(bytes32,uint64,address)"                           => handle_set_product_price,
    "buyProduct(bytes32,uint64)"                                        => handle_buy_product,
    "getProduct(bytes32)"                                               => handle_get_product,
    "unitsAvailableOf(bytes32)"                                         => handle_units_available_of,
    "latestPriceOf(bytes32)"                                            => handle_latest_price_of,
    "productCount()"                                                    => handle_product_count,
    "productIdAt(uint64)"                                               => handle_product_id_at,
    "associatedConstitution()"                                          => handle_associated_constitution,
    "accountingLedger()"                                                => handle_accounting_ledger,
    "identityRegistry()"                                                => handle_identity_registry,
    "hashUpsertProduct(bytes32,uint64,uint64,bytes)"                    => handle_hash_upsert_product,
    "hashRestockProduct(bytes32,uint64,uint64)"                         => handle_hash_restock_product,
    "hashSetProductPrice(bytes32,uint64)"                               => handle_hash_set_product_price,
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

fn ensure_initialized_and_valid_caller() -> Result<([u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let constitution = storage::get_address(KEY_CONSTITUTION).ok_or(-10)?;
    let caller = context::msg_sender();
    if caller != constitution {
        require_valid_identity(&registry, &caller)?;
    }
    Ok((registry, constitution, caller))
}

/// Verify that a catalog/inventory mutation is authorized by an `Identity` holding
/// `ROLE_PRODUCT_MANAGER` on the pinned `Constitution` HPS (or the per-ledger Product Oracle):
/// - If `caller == constitution` (invoked via `Constitution.upsertProduct` / `restockProduct` /
///   `setProductPrice`), `Constitution` has already verified `ROLE_PRODUCT_MANAGER`.
/// - If `auth_obj != 0x0`, atomically verifies and consumes the one-time `Authorization` HPS object
///   under `ROLE_PRODUCT_MANAGER` (or `POLICY_PRODUCT_ORACLE`).
/// - If `auth_obj == 0x0`, checks `constitution.hasRole(ROLE_PRODUCT_MANAGER, caller)` first,
///   falling back to `constitution.productOracleOf(self_address) == caller`, and returning
///   `Err(ERR_MISSING_ROLE)` (`-85`) otherwise.
fn require_product_oracle_auth(
    registry: &[u8; 20],
    constitution: &[u8; 20],
    action_hash: &[u8; 32],
    auth_obj: &[u8; 20],
    caller: &[u8; 20],
) -> Result<(), i32> {
    if *caller == *constitution {
        return Ok(());
    }

    if *auth_obj != [0u8; 20] {
        let pid_cd = CallEncoder::<16>::new(const { selector("policyId()") });
        let policy_id = if let Ok(raw_pid) = call::call_raw(auth_obj, pid_cd.as_slice()) {
            if raw_pid.len() >= 32 && raw_pid[..32] == ROLE_PRODUCT_MANAGER {
                ROLE_PRODUCT_MANAGER
            } else {
                POLICY_PRODUCT_ORACLE
            }
        } else {
            POLICY_PRODUCT_ORACLE
        };
        return verify_and_consume_auth(
            registry,
            auth_obj,
            constitution,
            &policy_id,
            action_hash,
            caller,
        );
    }

    let role_cd = CallEncoder::<96>::new(const { selector("hasRole(bytes32,address)") })
        .push_bytes32(&ROLE_PRODUCT_MANAGER)
        .push_address(caller);
    if let Ok(true) = call::call_bool(constitution, role_cd.as_slice()) {
        return Ok(());
    }

    let me = context::self_address();
    let ora_cd =
        CallEncoder::<64>::new(const { selector("productOracleOf(address)") }).push_address(&me);
    let Ok(raw_ora) = call::call_raw(constitution, ora_cd.as_slice()) else {
        return Err(ERR_MISSING_ROLE);
    };
    if raw_ora.len() < 32 {
        return Err(ERR_MISSING_ROLE);
    }
    let mut appointed_oracle = [0u8; 20];
    appointed_oracle.copy_from_slice(&raw_ora[12..32]);
    if appointed_oracle == [0u8; 20] || *caller != appointed_oracle {
        return Err(ERR_MISSING_ROLE);
    }
    Ok(())
}

/// Initialize `ProductLedger` pinned to a single `IdentityRegistry`, single `Constitution`, and
/// single `AccountingLedger`, optionally seeding initial product rows (`N * 80` bytes of
/// `[productId: 32B][unitsAvailable: u64 BE (8B)][latestPrice: u64 BE (8B)][name: 32B]`).
fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let accounting_ledger = args.address(2).ok_or(-3)?;
    let initial_products = args.dynamic_bytes(3).ok_or(-3)?;

    if registry == [0u8; 20]
        || constitution == [0u8; 20]
        || accounting_ledger == [0u8; 20]
        || initial_products.len() % GENESIS_PRODUCT_PACK_LEN != 0
    {
        return Err(ERR_CONSTITUTION_MISMATCH);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_CONSTITUTION, &constitution);
    storage::set_address(KEY_ACCOUNTING, &accounting_ledger);
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
            addr_topic(&constitution),
            addr_topic(&accounting_ledger),
        ],
        &(count as u64).to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Add a new product or overwrite an existing product's available units, price, and name.
/// Governed by `POLICY_PRODUCT_ORACLE` (Board-appointed Product Oracle / Catalog Manager).
fn handle_upsert_product(args: &CalldataReader) -> Result<(), i32> {
    let (registry, constitution, caller) = ensure_initialized_and_valid_caller()?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let units_available = args.u64(1).ok_or(-3)?;
    let latest_price = args.u64(2).ok_or(-3)?;
    let raw_name = args.dynamic_bytes(3).ok_or(-3)?;
    let auth_obj = args.address(4).ok_or(-3)?;

    if product_id == [0u8; 32] || latest_price == 0 || raw_name.is_empty() || raw_name.len() > 32 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let action_hash = compute_upsert_hash(&product_id, units_available, latest_price, raw_name);
    require_product_oracle_auth(&registry, &constitution, &action_hash, &auth_obj, &caller)?;

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

/// Restock `additionalUnits` for an existing product (and optionally update `latestPrice` if
/// `newPrice > 0`). Governed by `POLICY_PRODUCT_ORACLE`.
fn handle_restock_product(args: &CalldataReader) -> Result<(), i32> {
    let (registry, constitution, caller) = ensure_initialized_and_valid_caller()?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let additional_units = args.u64(1).ok_or(-3)?;
    let new_price = args.u64(2).ok_or(-3)?;
    let auth_obj = args.address(3).ok_or(-3)?;

    if additional_units == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }
    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }

    let action_hash = compute_restock_hash(&product_id, additional_units, new_price);
    require_product_oracle_auth(&registry, &constitution, &action_hash, &auth_obj, &caller)?;

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

/// Update `latestPrice` for an existing product. Governed by `POLICY_PRODUCT_ORACLE`.
fn handle_set_product_price(args: &CalldataReader) -> Result<(), i32> {
    let (registry, constitution, caller) = ensure_initialized_and_valid_caller()?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let new_price = args.u64(1).ok_or(-3)?;
    let auth_obj = args.address(2).ok_or(-3)?;

    if new_price == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }
    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }

    let action_hash = compute_set_price_hash(&product_id, new_price);
    require_product_oracle_auth(&registry, &constitution, &action_hash, &auth_obj, &caller)?;

    let prev_price = row.latest_price;
    row.latest_price = new_price;
    save_product(&product_id, &row);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&prev_price.to_be_bytes());
    ev[8..16].copy_from_slice(&new_price.to_be_bytes());
    events::emit(
        &[PRODUCT_PRICE_UPDATED, product_id, addr_topic(&caller)],
        &ev,
    );
    ret::write_bool(true);
    Ok(())
}

/// Immediate-fulfilment buy order (`productId`, `quantity`):
/// 1. Verifies `buyer` is an active Identity in `IdentityRegistry`.
/// 2. Checks that the product exists and `unitsAvailable >= quantity` (reverts with
///    `ERR_INSUFFICIENT_PRODUCT_UNITS (-82)` if stock is insufficient).
/// 3. Clears `totalCost = quantity * latestPrice` from `buyer`'s sub-account in the company's
///    Bank Balance `AssetLedger` via `Constitution.settleProductPayment(buyer, totalCost)`.
/// 4. Decrements `unitsAvailable` and increments `totalUnitsSold`.
/// 5. Records the sale and updates `totalRevenue` in `AccountingLedger`.
fn handle_buy_product(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, constitution, buyer) = ensure_initialized_and_valid_caller()?;
    let product_id = args.bytes32(0).ok_or(-3)?;
    let quantity = args.u64(1).ok_or(-3)?;
    if quantity == 0 {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let mut row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    if !row.active {
        return Err(ERR_PRODUCT_NOT_FOUND);
    }
    if row.units_available < quantity {
        return Err(ERR_INSUFFICIENT_PRODUCT_UNITS);
    }

    let unit_price = row.latest_price;
    let total_cost = quantity.checked_mul(unit_price).ok_or(-15)?;

    // 1. Settle payment from buyer's bank sub-account into Constitution's clearing/revenue account
    let pay_cd = CallEncoder::<96>::new(const {
        const { selector("settleProductPayment(address,uint64)") }
    })
    .push_address(&buyer)
    .push_u64(total_cost);
    let paid = call::call_bool(&constitution, pay_cd.as_slice())?;
    if !paid {
        return Err(-16);
    }

    // 2. Decrement available inventory units and increment cumulative units sold
    row.units_available -= quantity;
    row.total_units_sold = row.total_units_sold.saturating_add(quantity);
    save_product(&product_id, &row);

    // 3. Record sale and increment totalRevenue in the linked AccountingLedger
    let accounting = storage::get_address(KEY_ACCOUNTING).ok_or(-10)?;
    let rec_cd = CallEncoder::<192>::new(const {
        const { selector("recordSale(bytes32,address,uint64,uint64,uint64)") }
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

fn handle_get_product(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let row = load_product(&product_id).ok_or(ERR_PRODUCT_NOT_FOUND)?;
    // 5 ABI words (160 B): (uint64 unitsAvailable, uint64 latestPrice, uint64 totalUnitsSold, bool active, bytes32 nameWord)
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

fn handle_associated_constitution(_args: &CalldataReader) -> Result<(), i32> {
    let con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    ret::write_address(&con);
    Ok(())
}

fn handle_accounting_ledger(_args: &CalldataReader) -> Result<(), i32> {
    let acc = storage::get_address(KEY_ACCOUNTING).unwrap_or([0u8; 20]);
    ret::write_address(&acc);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    let reg = storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]);
    ret::write_address(&reg);
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
    fn immediate_fulfilment_buy_order_clears_bank_updates_inventory_and_accounting_revenue() {
        mock::reset();
        let registry = [0x10; 20];
        let constitution = [0x20; 20];
        let accounting = [0x30; 20];
        let product_ledger = [0x40; 20];
        let catalog_oracle = [0x50; 20];
        let founder = [0x01; 20];
        let buyer_1 = [0x02; 20];
        let buyer_2 = [0x03; 20];

        mock::register_hps(registry, |raw| {
            let Some((sel, _)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("isValidIdentity(address)") } {
                ret::write_bool(true);
                return 0;
            }
            -2
        });

        // Mock Constitution tracking buyer bank balances & appointed Product Oracle
        mock::register_hps(constitution, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("setBankBal(address,uint64)") } {
                let who = args.address(0).unwrap();
                let bal = args.u64(1).unwrap();
                let k = KeyBuilder::<32>::new().push(b"mbal:").push(&who);
                storage::set_u64(k.as_slice(), bal);
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("bankBalOf(address)") } {
                let who = args.address(0).unwrap();
                let k = KeyBuilder::<32>::new().push(b"mbal:").push(&who);
                ret::write_u64_word(storage::get_u64(k.as_slice()));
                return 0;
            }
            if sel == const { selector("productOracleOf(address)") } {
                ret::write_address(&[0x50; 20]);
                return 0;
            }
            if sel == const { selector("settleProductPayment(address,uint64)") } {
                let buyer = args.address(0).unwrap();
                let cost = args.u64(1).unwrap();
                let k = KeyBuilder::<32>::new().push(b"mbal:").push(&buyer);
                let cur = storage::get_u64(k.as_slice());
                if cur < cost {
                    return -16;
                }
                storage::set_u64(k.as_slice(), cur - cost);
                let ck = b"mbal:clearing";
                storage::set_u64(ck, storage::get_u64(ck) + cost);
                ret::write_bool(true);
                return 0;
            }
            -2
        });

        // Mock AccountingLedger recording sales & revenue
        mock::register_hps(accounting, |raw| {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
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
            if sel == const { selector("saleCount()") } {
                ret::write_u64_word(storage::get_u64(b"macc:cnt"));
                return 0;
            }
            -2
        });

        mock::register_hps(product_ledger, dispatch_calldata);

        // Seed 2 initial products:
        // 1. SLX-LR2021-RADIO: 10 units @ 2,500 SGD
        // 2. SLX-VALIDATOR-APPLIANCE: 4 units @ 12,000 SGD
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
            CallEncoder::<384>::new(const {
                selector("initialize(address,address,address,bytes)")
            })
            .push_address(&registry)
            .push_address(&constitution)
            .push_address(&accounting)
            .push_u64(128)
            .push_dynamic_bytes_tail(&init_bytes)
            .as_slice(),
        )
        .unwrap();

        // Fund buyer_1 with 30,000 SGD and buyer_2 with 20,000 SGD
        mock::transact_as(
            founder,
            constitution,
            CallEncoder::<96>::new(const { selector("setBankBal(address,uint64)") })
                .push_address(&buyer_1)
                .push_u64(30_000)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            founder,
            constitution,
            CallEncoder::<96>::new(const { selector("setBankBal(address,uint64)") })
                .push_address(&buyer_2)
                .push_u64(20_000)
                .as_slice(),
        )
        .unwrap();

        // 1. Buyer 1 buys 3 units of SLX-LR2021-RADIO @ 2,500 = 7,500 SGD -> immediate fulfilment!
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

        // Verify unitsAvailable dropped from 10 -> 7 and AccountingLedger revenue == 7,500
        let rem_radio = mock::transact_as(
            founder,
            product_ledger,
            CallEncoder::<64>::new(const { selector("unitsAvailableOf(bytes32)") })
                .push_bytes32(&sku_radio)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rem_radio[24..32].try_into().unwrap()), 7);

        // 2. Attempting to buy 5 units of SLX-VALIDATOR-APPLIANCE when only 4 are available MUST revert with ERR_INSUFFICIENT_PRODUCT_UNITS (-82)
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

        // 3. Attempting to buy 2 units of SLX-VALIDATOR-APPLIANCE (24,000 SGD) by buyer_2 (who only has 20,000 SGD) MUST revert with -16!
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

        // 4. Product Oracle updates price of SLX-LR2021-RADIO to 3,000 SGD and restocks +5 units (7 -> 12)
        mock::transact_as(
            catalog_oracle,
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

        // 5. Buyer 2 buys 4 units of SLX-LR2021-RADIO at the new price 3,000 = 12,000 SGD
        mock::transact_as(
            buyer_2,
            product_ledger,
            CallEncoder::<96>::new(const { selector("buyProduct(bytes32,uint64)") })
                .push_bytes32(&sku_radio)
                .push_u64(4)
                .as_slice(),
        )
        .unwrap();

        // Verify remaining units = 12 - 4 = 8, and total AccountingLedger revenue = 7,500 + 12,000 = 19,500 SGD across 2 sales
        let rem_radio_after = mock::transact_as(
            founder,
            product_ledger,
            CallEncoder::<64>::new(const { selector("unitsAvailableOf(bytes32)") })
                .push_bytes32(&sku_radio)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(rem_radio_after[24..32].try_into().unwrap()),
            8
        );

        let tot_rev = mock::transact_as(
            founder,
            accounting,
            CallEncoder::<16>::new(const { selector("totalRevenue()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(
            u64::from_be_bytes(tot_rev[24..32].try_into().unwrap()),
            19_500
        );
    }
}
