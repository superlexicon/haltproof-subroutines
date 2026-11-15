//! Accounting Ledger **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Tracks all fulfilled product sales and cumulative company revenue across one or more
//! authorized `ProductLedger` subroutines controlled by the company's `Constitution` HPS:
//! - Pinned to a single `IdentityRegistry` and a single `Constitution` HPS (`associatedConstitution()`).
//! - Accepts `recordSale(...)` exclusively from authorized `ProductLedger` instances (or the pinned
//!   `Constitution` HPS), rejecting unauthorized callers with `ERR_UNAUTHORIZED_SALES_RECORDER (-84)`.
//! - Maintains:
//!   - `totalRevenue()`: cumulative revenue across all sales
//!   - `totalUnitsSold()`: cumulative units sold across all products
//!   - `saleCount()` & `getSale(uint64)`: append-only audit log of every sale (`productId`, `buyer`,
//!     `quantity`, `unitPrice`, `totalAmount`, `blockNumber`, `productLedger`)
//!   - `productSalesOf(bytes32)`: per-product `(unitsSold, revenue)` aggregates
//!   - `buyerPurchasesOf(address)`: per-buyer `(unitsBought, totalSpent)` aggregates

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::governance::{
    require_valid_identity, verify_and_consume_auth, ActionHasher, ERR_CONSTITUTION_MISMATCH,
    ERR_INVALID_PRODUCT_PARAMS, ERR_UNAUTHORIZED_SALES_RECORDER, POLICY_BOARD_RESOLUTION,
};
use hps_sdk::keccak::keccak256;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const ACCOUNTING_INITIALIZED: [u8; 32] =
    event_topic("AccountingLedgerInitialized(address,address)");
const PRODUCT_LEDGER_AUTHORIZED: [u8; 32] =
    event_topic("ProductLedgerAuthorized(address,address)");
const SALE_RECORDED: [u8; 32] = event_topic(
    "SaleRecorded(bytes32,address,address,uint64,uint64,uint64,uint64,uint64)",
);

const TAG_AUTHORIZE_PRODUCT_LEDGER: [u8; 32] =
    keccak256(b"ACCOUNTING_AUTHORIZE_PRODUCT_LEDGER");

const KEY_INIT: &[u8] = b"acc:init";
const KEY_REGISTRY: &[u8] = b"acc:reg";
const KEY_CONSTITUTION: &[u8] = b"acc:con";
const KEY_INITIALIZER: &[u8] = b"acc:init_by";
const KEY_HAS_AUTH_LEDGER: &[u8] = b"acc:has_pl";
const KEY_TOTAL_REVENUE: &[u8] = b"acc:tot_rev";
const KEY_TOTAL_UNITS: &[u8] = b"acc:tot_units";
const KEY_SALE_COUNT: &[u8] = b"acc:sale_cnt";

const SALE_RECORD_LEN: usize = 104;

hps_entry! {
    "initialize(address,address,address)"                               => handle_initialize,
    "authorizeProductLedger(address,address)"                           => handle_authorize_product_ledger,
    "isAuthorizedProductLedger(address)"                                => handle_is_authorized_product_ledger,
    "recordSale(bytes32,address,uint64,uint64,uint64)"                  => handle_record_sale,
    "totalRevenue()"                                                    => handle_total_revenue,
    "totalUnitsSold()"                                                  => handle_total_units_sold,
    "saleCount()"                                                       => handle_sale_count,
    "getSale(uint64)"                                                   => handle_get_sale,
    "productSalesOf(bytes32)"                                           => handle_product_sales_of,
    "buyerPurchasesOf(address)"                                         => handle_buyer_purchases_of,
    "associatedConstitution()"                                          => handle_associated_constitution,
    "identityRegistry()"                                                => handle_identity_registry,
    "hashAuthorizeProductLedger(address)"                               => handle_hash_authorize_product_ledger,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn auth_ledger_key(product_ledger: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"acc:pl:").push(product_ledger)
}

fn sale_key(sale_idx: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"acc:s:")
        .push_u64_be(sale_idx)
}

fn product_stats_key(product_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"acc:ps:").push(product_id)
}

fn buyer_stats_key(buyer: &[u8; 20]) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(b"acc:bs:").push(buyer)
}

fn compute_authorize_ledger_hash(product_ledger: &[u8; 20]) -> [u8; 32] {
    ActionHasher::<128>::new(&context::self_address(), &TAG_AUTHORIZE_PRODUCT_LEDGER)
        .push_address(product_ledger)
        .finish()
}

fn load_pair_u64(key: &[u8]) -> (u64, u64) {
    let mut buf = [0u8; 16];
    let Some(n) = storage::get_into(key, &mut buf) else {
        return (0, 0);
    };
    if n < 16 {
        return (0, 0);
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[0..8]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[8..16]);
    (u64::from_be_bytes(a), u64::from_be_bytes(b))
}

fn store_pair_u64(key: &[u8], first: u64, second: u64) {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&first.to_be_bytes());
    buf[8..16].copy_from_slice(&second.to_be_bytes());
    storage::set(key, &buf);
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let constitution = args.address(1).ok_or(-3)?;
    let initial_product_ledger = args.address(2).ok_or(-3)?;
    if registry == [0u8; 20] || constitution == [0u8; 20] {
        return Err(ERR_CONSTITUTION_MISMATCH);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;

    storage::set_u64(KEY_INIT, 1);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_CONSTITUTION, &constitution);
    storage::set_address(KEY_INITIALIZER, &caller);
    storage::set_u64(KEY_TOTAL_REVENUE, 0);
    storage::set_u64(KEY_TOTAL_UNITS, 0);
    storage::set_u64(KEY_SALE_COUNT, 0);

    if initial_product_ledger != [0u8; 20] {
        let alk = auth_ledger_key(&initial_product_ledger);
        storage::set_u64(alk.as_slice(), 1);
        storage::set_u64(KEY_HAS_AUTH_LEDGER, 1);
    }

    events::emit(
        &[
            ACCOUNTING_INITIALIZED,
            addr_topic(&constitution),
            addr_topic(&initial_product_ledger),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

/// Authorize a `ProductLedger` to record sales on this `AccountingLedger`.
/// Requires a finalized `POLICY_BOARD_RESOLUTION` `Authorization` HPS object (or initial bootstrap
/// by the initializer Identity when no `ProductLedger` was configured at genesis and `boardAuth == 0x0`).
fn handle_authorize_product_ledger(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let constitution = storage::get_address(KEY_CONSTITUTION).ok_or(-10)?;
    let product_ledger = args.address(0).ok_or(-3)?;
    let board_auth = args.address(1).ok_or(-3)?;
    if product_ledger == [0u8; 20] {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let caller = context::msg_sender();
    if caller != constitution {
        require_valid_identity(&registry, &caller)?;
        let init_by = storage::get_address(KEY_INITIALIZER).unwrap_or([0u8; 20]);
        if board_auth == [0u8; 20]
            && storage::get_u64(KEY_HAS_AUTH_LEDGER) == 0
            && caller == init_by
        {
            // Initial bootstrap allowed by genesis initializer when initialProductLedger was 0x0
        } else {
            let action_hash = compute_authorize_ledger_hash(&product_ledger);
            verify_and_consume_auth(
                &registry,
                &board_auth,
                &constitution,
                &POLICY_BOARD_RESOLUTION,
                &action_hash,
                &caller,
            )?;
        }
    }

    let alk = auth_ledger_key(&product_ledger);
    storage::set_u64(alk.as_slice(), 1);
    storage::set_u64(KEY_HAS_AUTH_LEDGER, 1);

    events::emit(
        &[
            PRODUCT_LEDGER_AUTHORIZED,
            addr_topic(&product_ledger),
            addr_topic(&board_auth),
        ],
        &[],
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_is_authorized_product_ledger(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    let alk = auth_ledger_key(&product_ledger);
    ret::write_bool(storage::get_u64(alk.as_slice()) == 1);
    Ok(())
}

/// Record a fulfilled product sale and update `totalRevenue`, `totalUnitsSold`, per-product sales,
/// and per-buyer spend. Callable exclusively by an authorized `ProductLedger` (or the pinned
/// `Constitution` HPS).
fn handle_record_sale(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let caller = context::msg_sender();
    let constitution = storage::get_address(KEY_CONSTITUTION).ok_or(-10)?;
    let alk = auth_ledger_key(&caller);
    if caller != constitution && storage::get_u64(alk.as_slice()) != 1 {
        return Err(ERR_UNAUTHORIZED_SALES_RECORDER);
    }

    let product_id = args.bytes32(0).ok_or(-3)?;
    let buyer = args.address(1).ok_or(-3)?;
    let quantity = args.u64(2).ok_or(-3)?;
    let unit_price = args.u64(3).ok_or(-3)?;
    let total_amount = args.u64(4).ok_or(-3)?;

    let expected_total = quantity
        .checked_mul(unit_price)
        .ok_or(ERR_INVALID_PRODUCT_PARAMS)?;
    if product_id == [0u8; 32]
        || buyer == [0u8; 20]
        || quantity == 0
        || unit_price == 0
        || total_amount != expected_total
    {
        return Err(ERR_INVALID_PRODUCT_PARAMS);
    }

    let sale_idx = storage::get_u64(KEY_SALE_COUNT);
    let next_revenue = storage::get_u64(KEY_TOTAL_REVENUE)
        .checked_add(total_amount)
        .ok_or(-15)?;
    let next_units = storage::get_u64(KEY_TOTAL_UNITS)
        .checked_add(quantity)
        .ok_or(-15)?;

    storage::set_u64(KEY_SALE_COUNT, sale_idx + 1);
    storage::set_u64(KEY_TOTAL_REVENUE, next_revenue);
    storage::set_u64(KEY_TOTAL_UNITS, next_units);

    let psk = product_stats_key(&product_id);
    let (prod_units, prod_rev) = load_pair_u64(psk.as_slice());
    store_pair_u64(
        psk.as_slice(),
        prod_units.saturating_add(quantity),
        prod_rev.saturating_add(total_amount),
    );

    let bsk = buyer_stats_key(&buyer);
    let (buyer_units, buyer_spent) = load_pair_u64(bsk.as_slice());
    store_pair_u64(
        bsk.as_slice(),
        buyer_units.saturating_add(quantity),
        buyer_spent.saturating_add(total_amount),
    );

    let block_no = context::block_number();
    let mut rec = [0u8; SALE_RECORD_LEN];
    rec[0..32].copy_from_slice(&product_id);
    rec[32..52].copy_from_slice(&buyer);
    rec[52..72].copy_from_slice(&caller);
    rec[72..80].copy_from_slice(&quantity.to_be_bytes());
    rec[80..88].copy_from_slice(&unit_price.to_be_bytes());
    rec[88..96].copy_from_slice(&total_amount.to_be_bytes());
    rec[96..104].copy_from_slice(&block_no.to_be_bytes());
    let sk = sale_key(sale_idx);
    storage::set(sk.as_slice(), &rec);

    let mut ev = [0u8; 40];
    ev[0..8].copy_from_slice(&sale_idx.to_be_bytes());
    ev[8..16].copy_from_slice(&quantity.to_be_bytes());
    ev[16..24].copy_from_slice(&unit_price.to_be_bytes());
    ev[24..32].copy_from_slice(&total_amount.to_be_bytes());
    ev[32..40].copy_from_slice(&next_revenue.to_be_bytes());
    events::emit(
        &[
            SALE_RECORDED,
            product_id,
            addr_topic(&buyer),
            addr_topic(&caller),
        ],
        &ev,
    );

    ret::write_u64_word(sale_idx);
    Ok(())
}

fn handle_total_revenue(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_REVENUE));
    Ok(())
}

fn handle_total_units_sold(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_TOTAL_UNITS));
    Ok(())
}

fn handle_sale_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_SALE_COUNT));
    Ok(())
}

fn handle_get_sale(args: &CalldataReader) -> Result<(), i32> {
    let sale_idx = args.u64(0).ok_or(-3)?;
    if sale_idx >= storage::get_u64(KEY_SALE_COUNT) {
        return Err(-62);
    }
    let sk = sale_key(sale_idx);
    let mut rec = [0u8; SALE_RECORD_LEN];
    let Some(n) = storage::get_into(sk.as_slice(), &mut rec) else {
        return Err(-62);
    };
    if n < SALE_RECORD_LEN {
        return Err(-62);
    }

    // 7 ABI words (224 B): (bytes32 productId, address buyer, uint64 quantity, uint64 unitPrice, uint64 totalAmount, uint64 blockNumber, address productLedger)
    let mut out = [0u8; 224];
    out[0..32].copy_from_slice(&rec[0..32]);
    out[44..64].copy_from_slice(&rec[32..52]);
    out[88..96].copy_from_slice(&rec[72..80]);
    out[120..128].copy_from_slice(&rec[80..88]);
    out[152..160].copy_from_slice(&rec[88..96]);
    out[184..192].copy_from_slice(&rec[96..104]);
    out[204..224].copy_from_slice(&rec[52..72]);
    ret::write(&out);
    Ok(())
}

fn handle_product_sales_of(args: &CalldataReader) -> Result<(), i32> {
    let product_id = args.bytes32(0).ok_or(-3)?;
    let psk = product_stats_key(&product_id);
    let (units, rev) = load_pair_u64(psk.as_slice());
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&units.to_be_bytes());
    out[56..64].copy_from_slice(&rev.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_buyer_purchases_of(args: &CalldataReader) -> Result<(), i32> {
    let buyer = args.address(0).ok_or(-3)?;
    let bsk = buyer_stats_key(&buyer);
    let (units, spent) = load_pair_u64(bsk.as_slice());
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&units.to_be_bytes());
    out[56..64].copy_from_slice(&spent.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_associated_constitution(_args: &CalldataReader) -> Result<(), i32> {
    let con = storage::get_address(KEY_CONSTITUTION).unwrap_or([0u8; 20]);
    ret::write_address(&con);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    let reg = storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]);
    ret::write_address(&reg);
    Ok(())
}

fn handle_hash_authorize_product_ledger(args: &CalldataReader) -> Result<(), i32> {
    let product_ledger = args.address(0).ok_or(-3)?;
    ret::write_word(&compute_authorize_ledger_hash(&product_ledger));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::call::CallEncoder;
    use hps_sdk::{mock, selector};

    #[test]
    fn accounting_ledger_tracks_sales_revenue_and_rejects_unauthorized_recorders() {
        mock::reset();
        let registry = [0x10; 20];
        let constitution = [0x20; 20];
        let product_ledger = [0x30; 20];
        let founder = [0x01; 20];
        let buyer_1 = [0x02; 20];
        let buyer_2 = [0x03; 20];
        let rogue = [0x99; 20];
        let accounting = [0x40; 20];

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
        mock::register_hps(accounting, dispatch_calldata);

        // Initialize AccountingLedger pinned to `constitution` and authorizing `product_ledger`
        mock::transact_as(
            founder,
            accounting,
            CallEncoder::<128>::new(const {
                const { selector("initialize(address,address,address)") }
            })
            .push_address(&registry)
            .push_address(&constitution)
            .push_address(&product_ledger)
            .as_slice(),
        )
        .unwrap();

        let sku_a = keccak256(b"SLX-HARDWARE-NODE-V1");
        let sku_b = keccak256(b"SLX-ENTERPRISE-LICENSE");

        // Unauthorized caller cannot record sales
        assert_eq!(
            mock::transact_as(
                rogue,
                accounting,
                CallEncoder::<192>::new(const {
                    const { selector("recordSale(bytes32,address,uint64,uint64,uint64)") }
                })
                .push_bytes32(&sku_a)
                .push_address(&buyer_1)
                .push_u64(2)
                .push_u64(1_500)
                .push_u64(3_000)
                .as_slice(),
            ),
            Err(ERR_UNAUTHORIZED_SALES_RECORDER)
        );

        // Record Sale #0: buyer_1 buys 2 units of SKU A @ 1,500 = 3,000
        mock::set_block_number(200);
        let s0 = mock::transact_as(
            product_ledger,
            accounting,
            CallEncoder::<192>::new(const {
                const { selector("recordSale(bytes32,address,uint64,uint64,uint64)") }
            })
            .push_bytes32(&sku_a)
            .push_address(&buyer_1)
            .push_u64(2)
            .push_u64(1_500)
            .push_u64(3_000)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(s0[24..32].try_into().unwrap()), 0);

        // Record Sale #1: buyer_2 buys 5 units of SKU B @ 800 = 4,000
        mock::set_block_number(205);
        let s1 = mock::transact_as(
            product_ledger,
            accounting,
            CallEncoder::<192>::new(const {
                const { selector("recordSale(bytes32,address,uint64,uint64,uint64)") }
            })
            .push_bytes32(&sku_b)
            .push_address(&buyer_2)
            .push_u64(5)
            .push_u64(800)
            .push_u64(4_000)
            .as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(s1[24..32].try_into().unwrap()), 1);

        // Verify totalRevenue == 7,000, totalUnitsSold == 7, saleCount == 2
        let rev = mock::transact_as(
            founder,
            accounting,
            CallEncoder::<16>::new(const { selector("totalRevenue()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(rev[24..32].try_into().unwrap()), 7_000);

        let units = mock::transact_as(
            founder,
            accounting,
            CallEncoder::<16>::new(const { selector("totalUnitsSold()") }).as_slice(),
        )
        .unwrap();
        assert_eq!(u64::from_be_bytes(units[24..32].try_into().unwrap()), 7);

        let sale_0 = mock::transact_as(
            founder,
            accounting,
            CallEncoder::<64>::new(const { selector("getSale(uint64)") })
                .push_u64(0)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&sale_0[0..32], &sku_a);
        assert_eq!(&sale_0[44..64], &buyer_1);
        assert_eq!(u64::from_be_bytes(sale_0[88..96].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(sale_0[120..128].try_into().unwrap()), 1_500);
        assert_eq!(u64::from_be_bytes(sale_0[152..160].try_into().unwrap()), 3_000);
        assert_eq!(u64::from_be_bytes(sale_0[184..192].try_into().unwrap()), 200);
        assert_eq!(&sale_0[204..224], &product_ledger);
    }
}
