//! `AssetPair_OTC` **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Pairs a **Base Asset Ledger** and a **Quote Asset Ledger** across verified `Identity` HPS accounts:
//! 1. **Verified Identity Gate**: All state-changing interactions (`initialize`, `placeAskOrder`,
//!    `cancelAskOrder`, `buyOrder`) must originate from a valid `Identity` HPS (`context::msg_sender()`)
//!    verified against `IdentityRegistry.isValidIdentity(address)`.
//! 2. **Seller Ask Orders**: The seller/owner Identity (`sellerIdentity`) places sell (`ask`) orders
//!    for keyed items (`itemId`) at a specific Quote Asset unit price (`placeAskOrder`), after
//!    authorizing `AssetPair_OTC` on `baseLedger` using a one-time `Authorization` HPS object.
//! 3. **Atomic Dual-Ledger Settlement**: A valid buyer Identity (`buyerIdentity`) first authorizes
//!    `AssetPair_OTC` on `quoteLedger` for `baseQty * unitPriceQuote` (via a one-time `Authorization`
//!    object), then invokes `buyOrder(itemId, baseQty)` via `buyerIdentity.execute(...)` — atomically
//!    debiting Quote Asset from `buyerIdentity` -> `sellerIdentity` AND debiting Base Asset from
//!    `sellerIdentity` -> `buyerIdentity` via `AssetLedger`'s internal debit/credit primitives.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::require_valid_identity;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

const PAIR_INITIALIZED: [u8; 32] =
    event_topic("PairInitialized(address,address,address,address)");
const ASK_PLACED: [u8; 32] =
    event_topic("AskOrderPlaced(bytes32,address,uint64,uint64)");
const ASK_CANCELLED: [u8; 32] = event_topic("AskOrderCancelled(bytes32)");
const BUY_SETTLED: [u8; 32] =
    event_topic("BuyOrderSettled(bytes32,address,address,uint64,uint64,uint64)");

const KEY_INIT: &[u8] = b"otc:init";
const KEY_REGISTRY: &[u8] = b"otc:registry";
const KEY_SELLER_ID: &[u8] = b"otc:seller_id";
const KEY_BASE_LEDGER: &[u8] = b"otc:base";
const KEY_QUOTE_LEDGER: &[u8] = b"otc:quote";

hps_entry! {
    "initialize(address,address,address,address)"        => handle_initialize,
    "placeAskOrder(bytes32,uint64,uint64)"               => handle_place_ask_order,
    "cancelAskOrder(bytes32)"                            => handle_cancel_ask_order,
    "buyOrder(bytes32,uint64)"                           => handle_buy_order,
    "getAskPrice(bytes32)"                               => handle_get_ask_price,
    "getAskAvailable(bytes32)"                           => handle_get_ask_available,
    "getAskOrder(bytes32)"                               => handle_get_ask_order,
    "identityRegistry()"                                 => handle_identity_registry,
    "baseLedger()"                                       => handle_base_ledger,
    "quoteLedger()"                                      => handle_quote_ledger,
    "sellerIdentity()"                                   => handle_seller_identity,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

#[derive(Clone, Copy, Default)]
struct AskOrder {
    available_base: u64,
    unit_price_quote: u64,
    active: bool,
}

fn ask_key(item_id: &[u8; 32]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"ask:").push(item_id)
}

fn load_ask(item_id: &[u8; 32]) -> AskOrder {
    let key = ask_key(item_id);
    let mut raw = [0u8; 24];
    match storage::get_into(key.as_slice(), &mut raw) {
        Some(24) => AskOrder {
            available_base: u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]),
            unit_price_quote: u64::from_le_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]),
            active: u64::from_le_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]) != 0,
        },
        _ => AskOrder::default(),
    }
}

fn save_ask(item_id: &[u8; 32], ask: &AskOrder) {
    let key = ask_key(item_id);
    let mut raw = [0u8; 24];
    raw[0..8].copy_from_slice(&ask.available_base.to_le_bytes());
    raw[8..16].copy_from_slice(&ask.unit_price_quote.to_le_bytes());
    raw[16..24].copy_from_slice(&u64::from(ask.active).to_le_bytes());
    storage::set(key.as_slice(), &raw);
}

fn ensure_initialized_and_valid_caller(
) -> Result<([u8; 20], [u8; 20], [u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-30);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-30)?;
    let seller_id = storage::get_address(KEY_SELLER_ID).ok_or(-30)?;
    let base = storage::get_address(KEY_BASE_LEDGER).ok_or(-30)?;
    let quote = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-30)?;

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, seller_id, base, quote, caller))
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-32); // already initialized
    }
    let registry = args.address(0).ok_or(-3)?;
    let seller_id = args.address(1).ok_or(-3)?;
    let base_ledger = args.address(2).ok_or(-3)?;
    let quote_ledger = args.address(3).ok_or(-3)?;

    if registry == [0u8; 20]
        || seller_id == [0u8; 20]
        || base_ledger == [0u8; 20]
        || quote_ledger == [0u8; 20]
        || base_ledger == quote_ledger
    {
        return Err(-33);
    }

    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    require_valid_identity(&registry, &seller_id)?;

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_SELLER_ID, &seller_id);
    storage::set_address(KEY_BASE_LEDGER, &base_ledger);
    storage::set_address(KEY_QUOTE_LEDGER, &quote_ledger);
    storage::set_u64(KEY_INIT, 1);

    let mut ev_data = [0u8; 40];
    ev_data[0..20].copy_from_slice(&registry);
    ev_data[20..40].copy_from_slice(&seller_id);
    events::emit(
        &[
            PAIR_INITIALIZED,
            addr_topic(&base_ledger),
            addr_topic(&quote_ledger),
        ],
        &ev_data,
    );
    Ok(())
}

fn handle_place_ask_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, seller_id, base_ledger, _quote_ledger, caller) =
        ensure_initialized_and_valid_caller()?;
    if caller != seller_id {
        return Err(-31); // only sellerIdentity may place ask orders
    }

    let item_id = args.bytes32(0).ok_or(-3)?;
    let base_qty = args.u64(1).ok_or(-3)?;
    let unit_price_quote = args.u64(2).ok_or(-3)?;
    if base_qty == 0 || unit_price_quote == 0 {
        return Err(-34);
    }

    let otc_self = context::self_address();
    let bal_q = CallEncoder::<64>::new(selector("balanceOf(address)")).push_address(&seller_id);
    let seller_bal = call::call_u64(&base_ledger, bal_q.as_slice())?;
    if seller_bal < base_qty {
        return Err(-35);
    }

    let alw_q = CallEncoder::<96>::new(selector("allowance(address,address)"))
        .push_address(&seller_id)
        .push_address(&otc_self);
    let seller_alw = call::call_u64(&base_ledger, alw_q.as_slice())?;
    if seller_alw < base_qty {
        return Err(-36);
    }

    let order = AskOrder {
        available_base: base_qty,
        unit_price_quote,
        active: true,
    };
    save_ask(&item_id, &order);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&base_qty.to_be_bytes());
    ev[8..16].copy_from_slice(&unit_price_quote.to_be_bytes());
    events::emit(&[ASK_PLACED, item_id, addr_topic(&seller_id)], &ev);
    ret::write_bool(true);
    Ok(())
}

fn handle_cancel_ask_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, seller_id, _, _, caller) = ensure_initialized_and_valid_caller()?;
    if caller != seller_id {
        return Err(-31);
    }

    let item_id = args.bytes32(0).ok_or(-3)?;
    let mut order = load_ask(&item_id);
    if !order.active {
        return Err(-37);
    }
    order.available_base = 0;
    order.active = false;
    save_ask(&item_id, &order);

    events::emit(&[ASK_CANCELLED, item_id], &[]);
    ret::write_bool(true);
    Ok(())
}

/// Invoked by a valid Buyer Identity HPS (`buyerIdentity.execute(otc, buyOrder(itemId, qty))`).
fn handle_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let (registry, seller_id, base_ledger, quote_ledger, buyer_identity) =
        ensure_initialized_and_valid_caller()?;
    require_valid_identity(&registry, &seller_id)?;

    let item_id = args.bytes32(0).ok_or(-3)?;
    let base_qty = args.u64(1).ok_or(-3)?;
    if base_qty == 0 || buyer_identity == seller_id {
        return Err(-34);
    }

    let mut ask = load_ask(&item_id);
    if !ask.active || ask.available_base < base_qty {
        return Err(-38);
    }

    let total_quote = base_qty.checked_mul(ask.unit_price_quote).ok_or(-39)?;

    // Leg 1: Debit Buyer's Quote Asset balance and credit Seller's Identity in `quoteLedger`.
    let quote_tf = CallEncoder::<128>::new(selector("transferFrom(address,address,uint64)"))
        .push_address(&buyer_identity)
        .push_address(&seller_id)
        .push_u64(total_quote);
    if !call::call_bool(&quote_ledger, quote_tf.as_slice())? {
        return Err(-40);
    }

    // Leg 2: Debit Seller's Base Asset balance and credit Buyer's Identity in `baseLedger`.
    let base_tf = CallEncoder::<128>::new(selector("transferFrom(address,address,uint64)"))
        .push_address(&seller_id)
        .push_address(&buyer_identity)
        .push_u64(base_qty);
    if !call::call_bool(&base_ledger, base_tf.as_slice())? {
        return Err(-41);
    }

    ask.available_base -= base_qty;
    if ask.available_base == 0 {
        ask.active = false;
    }
    save_ask(&item_id, &ask);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&base_qty.to_be_bytes());
    ev[8..16].copy_from_slice(&ask.unit_price_quote.to_be_bytes());
    ev[16..24].copy_from_slice(&total_quote.to_be_bytes());
    events::emit(
        &[
            BUY_SETTLED,
            item_id,
            addr_topic(&buyer_identity),
            addr_topic(&seller_id),
        ],
        &ev,
    );

    ret::write_u64_word(total_quote);
    Ok(())
}

fn handle_get_ask_price(args: &CalldataReader) -> Result<(), i32> {
    let item_id = args.bytes32(0).ok_or(-3)?;
    let ask = load_ask(&item_id);
    ret::write_u64_word(if ask.active { ask.unit_price_quote } else { 0 });
    Ok(())
}

fn handle_get_ask_available(args: &CalldataReader) -> Result<(), i32> {
    let item_id = args.bytes32(0).ok_or(-3)?;
    let ask = load_ask(&item_id);
    ret::write_u64_word(if ask.active { ask.available_base } else { 0 });
    Ok(())
}

fn handle_get_ask_order(args: &CalldataReader) -> Result<(), i32> {
    let item_id = args.bytes32(0).ok_or(-3)?;
    let ask = load_ask(&item_id);
    let mut words = [0u8; 96];
    words[24..32].copy_from_slice(&ask.available_base.to_be_bytes());
    words[56..64].copy_from_slice(&ask.unit_price_quote.to_be_bytes());
    words[95] = u8::from(ask.active);
    ret::write(&words);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_base_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_BASE_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_quote_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_seller_identity(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_SELLER_ID).unwrap_or([0u8; 20]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::governance::ERR_INVALID_IDENTITY;
    use hps_sdk::mock;

    mod ledger_and_reg_sim {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::storage::KeyBuilder;
        use hps_sdk::{context, ret, selector, storage};

        pub fn reg_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("isValidIdentity(address)") {
                let id = args.address(0).unwrap();
                ret::write_bool(id == [0x11; 20] || id == [0x22; 20]);
                return 0;
            }
            -2
        }

        pub fn ledger_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else { return -1; };
            if sel == selector("seed(address,uint64)") {
                let to = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let bk = KeyBuilder::<32>::new().push(b"bal:").push(&to);
                storage::set_u64(bk.as_slice(), amt);
                return 0;
            }
            if sel == selector("approve(address,uint64)") {
                let owner = context::msg_sender();
                let spender = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let ak = KeyBuilder::<64>::new().push(b"alw:").push(&owner).push(&spender);
                storage::set_u64(ak.as_slice(), amt);
                ret::write_bool(true);
                return 0;
            }
            if sel == selector("balanceOf(address)") {
                let who = args.address(0).unwrap();
                let bk = KeyBuilder::<32>::new().push(b"bal:").push(&who);
                ret::write_u64_word(storage::get_u64(bk.as_slice()));
                return 0;
            }
            if sel == selector("allowance(address,address)") {
                let owner = args.address(0).unwrap();
                let spender = args.address(1).unwrap();
                let ak = KeyBuilder::<64>::new().push(b"alw:").push(&owner).push(&spender);
                ret::write_u64_word(storage::get_u64(ak.as_slice()));
                return 0;
            }
            if sel == selector("transferFrom(address,address,uint64)") {
                let from = args.address(0).unwrap();
                let to = args.address(1).unwrap();
                let amt = args.u64(2).unwrap();
                let spender = context::msg_sender();
                let ak = KeyBuilder::<64>::new().push(b"alw:").push(&from).push(&spender);
                let alw = storage::get_u64(ak.as_slice());
                if alw < amt {
                    return -17;
                }
                let fk = KeyBuilder::<32>::new().push(b"bal:").push(&from);
                let fbal = storage::get_u64(fk.as_slice());
                if fbal < amt {
                    return -16;
                }
                storage::set_u64(ak.as_slice(), alw - amt);
                storage::set_u64(fk.as_slice(), fbal - amt);
                let tk = KeyBuilder::<32>::new().push(b"bal:").push(&to);
                storage::set_u64(tk.as_slice(), storage::get_u64(tk.as_slice()) + amt);
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    #[test]
    fn otc_enforces_verified_identities_and_atomic_settlement() {
        mock::reset();
        let reg = [0x10; 20];
        let seller_id = [0x11; 20];
        let buyer_id = [0x22; 20];
        let unverified = [0xEE; 20];
        let base_ledger = [0xB0; 20];
        let quote_ledger = [0xD0; 20];
        let otc = [0xCC; 20];

        mock::register_hps(reg, ledger_and_reg_sim::reg_dispatch);
        mock::register_hps(base_ledger, ledger_and_reg_sim::ledger_dispatch);
        mock::register_hps(quote_ledger, ledger_and_reg_sim::ledger_dispatch);
        mock::register_hps(otc, dispatch_calldata);

        mock::transact_as(
            seller_id,
            base_ledger,
            CallEncoder::<96>::new(selector("seed(address,uint64)"))
                .push_address(&seller_id)
                .push_u64(500)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            buyer_id,
            quote_ledger,
            CallEncoder::<96>::new(selector("seed(address,uint64)"))
                .push_address(&buyer_id)
                .push_u64(50_000)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            seller_id,
            otc,
            CallEncoder::<160>::new(selector("initialize(address,address,address,address)"))
                .push_address(&reg)
                .push_address(&seller_id)
                .push_address(&base_ledger)
                .push_address(&quote_ledger)
                .as_slice(),
        )
        .unwrap();

        mock::transact_as(
            seller_id,
            base_ledger,
            CallEncoder::<96>::new(selector("approve(address,uint64)"))
                .push_address(&otc)
                .push_u64(200)
                .as_slice(),
        )
        .unwrap();

        let item_id = [0x77; 32];
        mock::transact_as(
            seller_id,
            otc,
            CallEncoder::<128>::new(selector("placeAskOrder(bytes32,uint64,uint64)"))
                .push_bytes32(&item_id)
                .push_u64(200)
                .push_u64(100)
                .as_slice(),
        )
        .unwrap();

        // Unverified identity cannot buy!
        let buy_cd = CallEncoder::<96>::new(selector("buyOrder(bytes32,uint64)"))
            .push_bytes32(&item_id)
            .push_u64(25);
        assert_eq!(
            mock::transact_as(unverified, otc, buy_cd.as_slice()),
            Err(ERR_INVALID_IDENTITY)
        );

        // Verified buyer authorizes quote debit & settles atomically
        mock::transact_as(
            buyer_id,
            quote_ledger,
            CallEncoder::<96>::new(selector("approve(address,uint64)"))
                .push_address(&otc)
                .push_u64(2_500)
                .as_slice(),
        )
        .unwrap();
        let paid = mock::transact_as(buyer_id, otc, buy_cd.as_slice()).unwrap();
        assert_eq!(&paid[24..32], &2_500u64.to_be_bytes());
    }
}
