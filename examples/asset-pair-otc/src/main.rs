//! `AssetPair_OTC` **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Implements a deterministic Over-The-Counter (OTC) venue across Identity and Asset Ledger HPSes:
//! 1. **Asset Pairing**: Pairs a **Base Asset Ledger** (`baseLedger`) and a **Quote Asset Ledger**
//!    (`quoteLedger`), bound to the contract `owner` and the owner/seller's `Identity` HPS (`sellerIdentity`).
//! 2. **Owner Ask Orders**: Allows the contract owner (or `sellerIdentity`) to place sell (`ask`)
//!    orders for named/keyed items (`itemId`) specifying available Base Asset quantity and the
//!    prevailing unit price in the Quote Asset (`placeAskOrder`).
//! 3. **Atomic Buyer Settlement**: Allows buyers to fill at the prevailing ask price (`buyOrder` /
//!    `buyOrderWithIdentity`) after first authorizing `AssetPair_OTC` to debit their Quote Asset
//!    balance in `quoteLedger` (`Identity.approveAsset(quoteLedger, otcAddress, quoteAmount)`):
//!    - Debits `quantity * unitPriceQuote` from `buyerIdentity` and credits `sellerIdentity` in `quoteLedger`.
//!    - Atomically debits `quantity` of Base Asset from `sellerIdentity` and credits `buyerIdentity` in `baseLedger`.
//!    - If either ledger debit/credit fails, the entire transaction reverts atomically.
//!
//! Supported ABI methods:
//! - `initialize(address owner, address sellerIdentity, address baseLedger, address quoteLedger)`
//! - `placeAskOrder(bytes32 itemId, uint64 baseQuantity, uint64 unitPriceQuote)`
//! - `cancelAskOrder(bytes32 itemId)`
//! - `buyOrder(bytes32 itemId, uint64 baseQuantity)` (caller `msg.sender` is the Buyer's Identity HPS)
//! - `buyOrderWithIdentity(bytes32 itemId, address buyerIdentity, uint64 baseQuantity)` (verifies `buyerIdentity.isAuthorized(msg.sender)`)
//! - `getAskPrice(bytes32 itemId)` -> `uint256`
//! - `getAskAvailable(bytes32 itemId)` -> `uint256`
//! - `getAskOrder(bytes32 itemId)` -> `(uint256 availableBase, uint256 unitPriceQuote, uint256 active)`
//! - `baseLedger()` -> `address`
//! - `quoteLedger()` -> `address`
//! - `sellerIdentity()` -> `address`
//! - `owner()` -> `address`

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
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
const KEY_OWNER: &[u8] = b"otc:owner";
const KEY_SELLER_ID: &[u8] = b"otc:seller_id";
const KEY_BASE_LEDGER: &[u8] = b"otc:base";
const KEY_QUOTE_LEDGER: &[u8] = b"otc:quote";

hps_entry! {
    "initialize(address,address,address,address)"        => handle_initialize,
    "placeAskOrder(bytes32,uint64,uint64)"               => handle_place_ask_order,
    "cancelAskOrder(bytes32)"                            => handle_cancel_ask_order,
    "buyOrder(bytes32,uint64)"                           => handle_buy_order,
    "buyOrderWithIdentity(bytes32,address,uint64)"       => handle_buy_order_with_identity,
    "getAskPrice(bytes32)"                               => handle_get_ask_price,
    "getAskAvailable(bytes32)"                           => handle_get_ask_available,
    "getAskOrder(bytes32)"                               => handle_get_ask_order,
    "baseLedger()"                                       => handle_base_ledger,
    "quoteLedger()"                                      => handle_quote_ledger,
    "sellerIdentity()"                                   => handle_seller_identity,
    "owner()"                                            => handle_owner,
}

fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

/// Stored 24-byte packed Ask Order record: `[available_base: u64 LE][unit_price_quote: u64 LE][active: u64 LE]`.
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

fn ensure_initialized() -> Result<([u8; 20], [u8; 20], [u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-30);
    }
    let owner = storage::get_address(KEY_OWNER).ok_or(-30)?;
    let seller_id = storage::get_address(KEY_SELLER_ID).ok_or(-30)?;
    let base = storage::get_address(KEY_BASE_LEDGER).ok_or(-30)?;
    let quote = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-30)?;
    Ok((owner, seller_id, base, quote))
}

fn require_owner_or_seller(caller: &[u8; 20], owner: &[u8; 20], seller_id: &[u8; 20]) -> Result<(), i32> {
    if caller == owner || caller == seller_id {
        return Ok(());
    }
    // Also permit a delegate authorized on `sellerIdentity`.
    let q = CallEncoder::<64>::new(selector("isAuthorized(address)")).push_address(caller);
    if call::call_bool(seller_id, q.as_slice()).unwrap_or(false) {
        return Ok(());
    }
    Err(-31) // unauthorized: only contract owner or seller identity
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-32); // already initialized
    }
    let owner = args.address(0).ok_or(-3)?;
    let seller_id = args.address(1).ok_or(-3)?;
    let base_ledger = args.address(2).ok_or(-3)?;
    let quote_ledger = args.address(3).ok_or(-3)?;

    if owner == [0u8; 20]
        || seller_id == [0u8; 20]
        || base_ledger == [0u8; 20]
        || quote_ledger == [0u8; 20]
        || base_ledger == quote_ledger
    {
        return Err(-33);
    }

    storage::set_address(KEY_OWNER, &owner);
    storage::set_address(KEY_SELLER_ID, &seller_id);
    storage::set_address(KEY_BASE_LEDGER, &base_ledger);
    storage::set_address(KEY_QUOTE_LEDGER, &quote_ledger);
    storage::set_u64(KEY_INIT, 1);

    let mut ev_data = [0u8; 40];
    ev_data[0..20].copy_from_slice(&owner);
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
    let (owner, seller_id, base_ledger, _quote_ledger) = ensure_initialized()?;
    let caller = context::msg_sender();
    require_owner_or_seller(&caller, &owner, &seller_id)?;

    let item_id = args.bytes32(0).ok_or(-3)?;
    let base_qty = args.u64(1).ok_or(-3)?;
    let unit_price_quote = args.u64(2).ok_or(-3)?;
    if base_qty == 0 || unit_price_quote == 0 {
        return Err(-34);
    }

    // Verify `sellerIdentity` currently holds >= `base_qty` and has authorized `AssetPair_OTC`
    // to transfer at least `base_qty` on `baseLedger`.
    let otc_self = context::self_address();
    let bal_q = CallEncoder::<64>::new(selector("balanceOf(address)")).push_address(&seller_id);
    let seller_bal = call::call_u64(&base_ledger, bal_q.as_slice())?;
    if seller_bal < base_qty {
        return Err(-35); // insufficient seller base balance
    }

    let alw_q = CallEncoder::<96>::new(selector("allowance(address,address)"))
        .push_address(&seller_id)
        .push_address(&otc_self);
    let seller_alw = call::call_u64(&base_ledger, alw_q.as_slice())?;
    if seller_alw < base_qty {
        return Err(-36); // sellerIdentity must approve AssetPair_OTC on baseLedger
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
    let (owner, seller_id, _, _) = ensure_initialized()?;
    let caller = context::msg_sender();
    require_owner_or_seller(&caller, &owner, &seller_id)?;

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

fn settle_buy(item_id: [u8; 32], buyer_identity: [u8; 20], base_qty: u64) -> Result<(), i32> {
    let (_owner, seller_id, base_ledger, quote_ledger) = ensure_initialized()?;
    if base_qty == 0 || buyer_identity == [0u8; 20] || buyer_identity == seller_id {
        return Err(-34);
    }

    let mut ask = load_ask(&item_id);
    if !ask.active || ask.available_base < base_qty {
        return Err(-38); // ask inactive or insufficient available quantity
    }

    let total_quote = base_qty.checked_mul(ask.unit_price_quote).ok_or(-39)?;

    // Leg 1: Debit Buyer's Quote Asset balance (via Buyer's prior `approve` authorization)
    //        and credit Seller/Owner's Identity in `quoteLedger`.
    let quote_tf = CallEncoder::<128>::new(selector("transferFrom(address,address,uint64)"))
        .push_address(&buyer_identity)
        .push_address(&seller_id)
        .push_u64(total_quote);
    let quote_ok = call::call_bool(&quote_ledger, quote_tf.as_slice())?;
    if !quote_ok {
        return Err(-40);
    }

    // Leg 2: Debit Seller's Base Asset balance and credit Buyer's Identity in `baseLedger`.
    let base_tf = CallEncoder::<128>::new(selector("transferFrom(address,address,uint64)"))
        .push_address(&seller_id)
        .push_address(&buyer_identity)
        .push_u64(base_qty);
    let base_ok = call::call_bool(&base_ledger, base_tf.as_slice())?;
    if !base_ok {
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

/// Invoked directly by a Buyer's Identity HPS (`Identity.execute(otc, buyOrder(itemId, qty))`).
fn handle_buy_order(args: &CalldataReader) -> Result<(), i32> {
    let item_id = args.bytes32(0).ok_or(-3)?;
    let base_qty = args.u64(1).ok_or(-3)?;
    let buyer_identity = context::msg_sender();
    settle_buy(item_id, buyer_identity, base_qty)
}

/// Invoked from a Buyer's wallet EOA; verifies `buyerIdentity.isAuthorized(msg.sender)` on-chain
/// before settling between `buyerIdentity` and `sellerIdentity`.
fn handle_buy_order_with_identity(args: &CalldataReader) -> Result<(), i32> {
    let item_id = args.bytes32(0).ok_or(-3)?;
    let buyer_identity = args.address(1).ok_or(-3)?;
    let base_qty = args.u64(2).ok_or(-3)?;

    let caller = context::msg_sender();
    if caller != buyer_identity {
        let auth_q = CallEncoder::<64>::new(selector("isAuthorized(address)")).push_address(&caller);
        if !call::call_bool(&buyer_identity, auth_q.as_slice()).unwrap_or(false) {
            return Err(-42); // caller is not authorized for buyerIdentity
        }
    }
    settle_buy(item_id, buyer_identity, base_qty)
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

fn handle_owner(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_OWNER).unwrap_or([0u8; 20]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    // Minimal self-contained ledger & identity mock handlers for unit-testing atomic OTC settlement
    mod ledger_sim {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::storage::KeyBuilder;
        use hps_sdk::{context, ret, selector, storage};

        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == selector("mint(address,uint64)") {
                let to = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let bk = KeyBuilder::<32>::new().push(b"bal:").push(&to);
                storage::set_u64(bk.as_slice(), storage::get_u64(bk.as_slice()) + amt);
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

    mod id_sim {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::call::{self, CallEncoder};
        use hps_sdk::{context, ret, selector, storage};

        pub fn dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == selector("init(address)") {
                storage::set_address(b"owner", &args.address(0).unwrap());
                return 0;
            }
            if sel == selector("isAuthorized(address)") {
                let owner = storage::get_address(b"owner").unwrap_or([0u8; 20]);
                ret::write_bool(args.address(0).unwrap() == owner);
                return 0;
            }
            if sel == selector("approveAsset(address,address,uint64)") {
                let owner = storage::get_address(b"owner").unwrap_or([0u8; 20]);
                if context::msg_sender() != owner {
                    return -21;
                }
                let ledger = args.address(0).unwrap();
                let spender = args.address(1).unwrap();
                let amt = args.u64(2).unwrap();
                let cd = CallEncoder::<128>::new(selector("approve(address,uint64)"))
                    .push_address(&spender)
                    .push_u64(amt);
                return match call::call_bool(&ledger, cd.as_slice()) {
                    Ok(true) => {
                        ret::write_bool(true);
                        0
                    }
                    _ => -24,
                };
            }
            -2
        }
    }

    fn read_bal(ledger: [u8; 20], holder: [u8; 20]) -> u64 {
        let out = mock::transact_as(
            [0x01; 20],
            ledger,
            CallEncoder::<64>::new(selector("balanceOf(address)"))
                .push_address(&holder)
                .as_slice(),
        )
        .unwrap();
        u64::from_be_bytes(out[24..32].try_into().unwrap())
    }

    #[test]
    fn full_otc_ask_and_buy_flow_with_atomic_rollback() {
        mock::reset();
        let owner_eoa = [0x01; 20];
        let buyer_eoa = [0x02; 20];
        let seller_id = [0x11; 20];
        let buyer_id = [0x22; 20];
        let base_ledger = [0xB0; 20];
        let quote_ledger = [0xD0; 20];
        let otc = [0xCC; 20];

        mock::register_hps(seller_id, id_sim::dispatch);
        mock::register_hps(buyer_id, id_sim::dispatch);
        mock::register_hps(base_ledger, ledger_sim::dispatch);
        mock::register_hps(quote_ledger, ledger_sim::dispatch);
        mock::register_hps(otc, dispatch_calldata);

        // 1. Initialize Seller & Buyer Identities
        mock::transact_as(
            owner_eoa,
            seller_id,
            CallEncoder::<64>::new(selector("init(address)"))
                .push_address(&owner_eoa)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            buyer_eoa,
            buyer_id,
            CallEncoder::<64>::new(selector("init(address)"))
                .push_address(&buyer_eoa)
                .as_slice(),
        )
        .unwrap();

        // 2. Mint 500 Base Asset to Seller Identity, 50,000 Quote Asset to Buyer Identity
        mock::transact_as(
            owner_eoa,
            base_ledger,
            CallEncoder::<96>::new(selector("mint(address,uint64)"))
                .push_address(&seller_id)
                .push_u64(500)
                .as_slice(),
        )
        .unwrap();
        mock::transact_as(
            owner_eoa,
            quote_ledger,
            CallEncoder::<96>::new(selector("mint(address,uint64)"))
                .push_address(&buyer_id)
                .push_u64(50_000)
                .as_slice(),
        )
        .unwrap();

        // 3. Initialize AssetPair_OTC pairing base_ledger & quote_ledger
        mock::transact_as(
            owner_eoa,
            otc,
            CallEncoder::<160>::new(selector("initialize(address,address,address,address)"))
                .push_address(&owner_eoa)
                .push_address(&seller_id)
                .push_address(&base_ledger)
                .push_address(&quote_ledger)
                .as_slice(),
        )
        .unwrap();

        // 4. Seller authorizes OTC for 200 Base Asset and Owner places Ask Order (200 @ 100 Quote/unit)
        mock::transact_as(
            owner_eoa,
            seller_id,
            CallEncoder::<128>::new(selector("approveAsset(address,address,uint64)"))
                .push_address(&base_ledger)
                .push_address(&otc)
                .push_u64(200)
                .as_slice(),
        )
        .unwrap();

        let item_id = [0x77; 32];
        mock::transact_as(
            owner_eoa,
            otc,
            CallEncoder::<128>::new(selector("placeAskOrder(bytes32,uint64,uint64)"))
                .push_bytes32(&item_id)
                .push_u64(200)
                .push_u64(100)
                .as_slice(),
        )
        .unwrap();

        // 5. Buying BEFORE authorizing Quote Asset debit fails cleanly with zero balance changes
        let buy_cd = CallEncoder::<128>::new(selector("buyOrderWithIdentity(bytes32,address,uint64)"))
            .push_bytes32(&item_id)
            .push_address(&buyer_id)
            .push_u64(25);
        assert_eq!(mock::transact_as(buyer_eoa, otc, buy_cd.as_slice()), Err(-17));
        assert_eq!(read_bal(quote_ledger, buyer_id), 50_000);
        assert_eq!(read_bal(base_ledger, seller_id), 500);

        // 6. Buyer authorizes debit of 2,500 Quote Asset via BuyerIdentity
        mock::transact_as(
            buyer_eoa,
            buyer_id,
            CallEncoder::<128>::new(selector("approveAsset(address,address,uint64)"))
                .push_address(&quote_ledger)
                .push_address(&otc)
                .push_u64(2_500)
                .as_slice(),
        )
        .unwrap();

        // 7. Buyer places Buy Order for 25 Base units at prevailing price (100 Quote/unit = 2,500 Quote)
        let paid = mock::transact_as(buyer_eoa, otc, buy_cd.as_slice()).unwrap();
        assert_eq!(&paid[24..32], &2_500u64.to_be_bytes());

        // Verify atomic dual-ledger settlement across Identities:
        assert_eq!(read_bal(quote_ledger, buyer_id), 47_500);
        assert_eq!(read_bal(quote_ledger, seller_id), 2_500);
        assert_eq!(read_bal(base_ledger, seller_id), 475);
        assert_eq!(read_bal(base_ledger, buyer_id), 25);

        // Remaining ask quantity = 175
        let rem = mock::transact_as(
            buyer_eoa,
            otc,
            CallEncoder::<64>::new(selector("getAskAvailable(bytes32)"))
                .push_bytes32(&item_id)
                .as_slice(),
        )
        .unwrap();
        assert_eq!(&rem[24..32], &175u64.to_be_bytes());
    }
}
