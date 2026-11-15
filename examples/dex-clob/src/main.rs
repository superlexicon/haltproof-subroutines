//! Discrete-Time FIFO Central Limit Orderbook (CLOB) DEX **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Can be attached to any `AssetLedger` (via `AssetLedger.setAttachedDex(dexHps, authObj)`) to turn
//! that ledger into its own exchange.
//!
//! ### Matching Engine Design
//! 1. **Order Intake (`placeBid`, `placeAsk`)**:
//!    - Verified `Identity` traders submit limit Bid (`placeBid(price, quantity)`) or Ask
//!      (`placeAsk(price, quantity)`) orders.
//!    - Each order is stamped with `context::block_number()` (`arrival_block`), assigned a sequential
//!      `orderId`, and appended to the pending intake queue.
//!    - To guarantee halt-free settlement, `placeAsk` escrows `quantity` of the base asset in
//!      `assetLedger` into `escrowIdentity` (via `dexTransfer`), and `placeBid` escrows
//!      `price * quantity` in `quoteLedger` into `escrowIdentity` (when `quoteLedger != 0x0`).
//! 2. **Per-Block Ordered List Ingestion (`matchBlock()`)**:
//!    - Iterates through all pending intake orders received until the last block (`order.block_number < current_block`,
//!      or `<= current_block` when no earlier-block intake orders are pending) and inserts them into:
//!      - **Ordered Bid List**: ordered by **price descending** first, and within each price level
//!        sub-ordered by **block number ascending** (`block_number ASC`, earliest block first).
//!      - **Ordered Ask List**: ordered by **price ascending** first, and within each price level
//!        sub-ordered by **block number ascending** (`block_number ASC`, earliest block first).
//! 3. **Single Clearing Price & Price-Then-Block Priority with Same-Block Pro-Rata Fills**:
//!    - Checks for crossing Bid and Ask prices (`best_bid.price >= best_ask.price`).
//!    - Determines a **single clearing price `P*`** that maximizes matched volume
//!      `V* = min(D(P*), S(P*))` across crossing bids (`bid.price >= P*`) and crossing asks
//!      (`ask.price <= P*`).
//!    - Fills crossing Bids up to `V*` in strict `(price DESC, block_number ASC)` cohort order, and
//!      crossing Asks up to `V*` in strict `(price ASC, block_number ASC)` cohort order.
//!    - **Equal-Priority Same-Block Pro-Rata Rule**: Orders with the **same price** that arrived at
//!      the **same block** (`(price, block_number)` cohort) have equal priority. When the remaining
//!      volume to fill at the marginal `(price, block_number)` cohort is less than the cohort's total
//!      remaining quantity, the fill is **pro-rated across all orders in that cohort** proportional to
//!      their order quantities (with largest-fractional-remainder rounding for integer units).
//!    - Settles base asset transfers to buyers and quote cash transfers to sellers (plus refunding
//!      `(bid.price - P*) * fill` price improvement back to filled buyers), updates remaining order
//!      quantities, and removes fully filled orders from the ordered lists.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    require_valid_identity, ERR_INVALID_DEX_ORDER, ERR_NOT_ORDER_OWNER, ERR_NO_CROSSING_ORDERS,
    ERR_ORDERBOOK_FULL, ERR_ORDER_ALREADY_CANCELLED, ERR_ORDER_NOT_FOUND,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const MAX_DEX_ORDERS: usize = 64;

pub const SIDE_BID: u8 = 1;
pub const SIDE_ASK: u8 = 2;

pub const STATUS_PENDING: u8 = 0;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_FILLED: u8 = 2;
pub const STATUS_CANCELLED: u8 = 3;

const DEX_INITIALIZED: [u8; 32] = event_topic("DexInitialized(address,address,address,address)");
const ORDER_PLACED: [u8; 32] =
    event_topic("OrderPlaced(uint64,address,uint8,uint64,uint64,uint64)");
const ORDER_CANCELLED: [u8; 32] = event_topic("OrderCancelled(uint64,address,uint64)");
const ORDER_INGESTED: [u8; 32] = event_topic("OrderIngested(uint64,uint8,uint64,uint64)");
const ORDER_FILLED: [u8; 32] =
    event_topic("OrderFilled(uint64,address,uint8,uint64,uint64,uint64)");
const BLOCK_MATCHED: [u8; 32] =
    event_topic("BlockMatched(uint64,uint64,uint64,uint64,uint64,uint64)");

const KEY_INIT: &[u8] = b"dex:init";
const KEY_REGISTRY: &[u8] = b"dex:reg";
const KEY_ASSET_LEDGER: &[u8] = b"dex:asset";
const KEY_QUOTE_LEDGER: &[u8] = b"dex:quote";
const KEY_ESCROW_ID: &[u8] = b"dex:escrow";

const KEY_ORDER_COUNT: &[u8] = b"dex:ord_cnt";
const KEY_PENDING_LIST: &[u8] = b"dex:pending";
const KEY_BID_LIST: &[u8] = b"dex:bids";
const KEY_ASK_LIST: &[u8] = b"dex:asks";

const KEY_LAST_MATCH_BLOCK: &[u8] = b"dex:lm_blk";
const KEY_LAST_PRICE: &[u8] = b"dex:lm_px";
const KEY_LAST_VOL: &[u8] = b"dex:lm_vol";
const KEY_LAST_INGESTED: &[u8] = b"dex:lm_ing";
const KEY_LAST_FILLED_BIDS: &[u8] = b"dex:lm_fb";
const KEY_LAST_FILLED_ASKS: &[u8] = b"dex:lm_fa";

hps_entry! {
    "initialize(address,address,address,address)" => handle_initialize,
    "placeBid(uint64,uint64)"                     => handle_place_bid,
    "placeAsk(uint64,uint64)"                     => handle_place_ask,
    "cancelOrder(uint64)"                         => handle_cancel_order,
    "matchBlock()"                                => handle_match_block,
    "getOrder(uint64)"                            => handle_get_order,
    "orderCount()"                                => handle_order_count,
    "bookDepth()"                                 => handle_book_depth,
    "bestBidAndAsk()"                             => handle_best_bid_and_ask,
    "getOrderedBidAt(uint64)"                     => handle_get_ordered_bid_at,
    "getOrderedAskAt(uint64)"                     => handle_get_ordered_ask_at,
    "lastMatchSummary()"                          => handle_last_match_summary,
    "assetLedger()"                               => handle_asset_ledger,
    "quoteLedger()"                               => handle_quote_ledger,
    "escrowIdentity()"                            => handle_escrow_identity,
    "identityRegistry()"                          => handle_identity_registry,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DexOrder {
    pub order_id: u64,
    pub trader: [u8; 20],
    pub side: u8,
    pub status: u8,
    pub price: u64,
    pub orig_qty: u64,
    pub rem_qty: u64,
    pub block_number: u64,
}

impl Default for DexOrder {
    fn default() -> Self {
        Self {
            order_id: 0,
            trader: [0u8; 20],
            side: 0,
            status: 0,
            price: 0,
            orig_qty: 0,
            rem_qty: 0,
            block_number: 0,
        }
    }
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

fn order_key(order_id: u64) -> KeyBuilder<24> {
    KeyBuilder::<24>::new()
        .push(b"dex:ord:")
        .push_u64_be(order_id)
}

fn store_order(ord: &DexOrder) {
    let mut raw = [0u8; 62];
    raw[0..8].copy_from_slice(&ord.order_id.to_be_bytes());
    raw[8..28].copy_from_slice(&ord.trader);
    raw[28] = ord.side;
    raw[29] = ord.status;
    raw[30..38].copy_from_slice(&ord.price.to_be_bytes());
    raw[38..46].copy_from_slice(&ord.orig_qty.to_be_bytes());
    raw[46..54].copy_from_slice(&ord.rem_qty.to_be_bytes());
    raw[54..62].copy_from_slice(&ord.block_number.to_be_bytes());
    let ok = order_key(ord.order_id);
    storage::set(ok.as_slice(), &raw);
}

fn load_order(order_id: u64) -> Option<DexOrder> {
    let ok = order_key(order_id);
    let mut raw = [0u8; 62];
    match storage::get_into(ok.as_slice(), &mut raw) {
        Some(62) => {
            let id = u64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            if id == 0 {
                return None;
            }
            let mut trader = [0u8; 20];
            trader.copy_from_slice(&raw[8..28]);
            let side = raw[28];
            let status = raw[29];
            let price = u64::from_be_bytes([
                raw[30], raw[31], raw[32], raw[33], raw[34], raw[35], raw[36], raw[37],
            ]);
            let orig_qty = u64::from_be_bytes([
                raw[38], raw[39], raw[40], raw[41], raw[42], raw[43], raw[44], raw[45],
            ]);
            let rem_qty = u64::from_be_bytes([
                raw[46], raw[47], raw[48], raw[49], raw[50], raw[51], raw[52], raw[53],
            ]);
            let block_number = u64::from_be_bytes([
                raw[54], raw[55], raw[56], raw[57], raw[58], raw[59], raw[60], raw[61],
            ]);
            Some(DexOrder {
                order_id: id,
                trader,
                side,
                status,
                price,
                orig_qty,
                rem_qty,
                block_number,
            })
        }
        _ => None,
    }
}

fn load_id_list(key: &[u8]) -> ([u64; MAX_DEX_ORDERS], usize) {
    let mut ids = [0u64; MAX_DEX_ORDERS];
    let mut raw = [0u8; MAX_DEX_ORDERS * 8];
    let Some(len) = storage::get_into(key, &mut raw) else {
        return (ids, 0);
    };
    let count = (len / 8).min(MAX_DEX_ORDERS);
    let mut i = 0usize;
    while i < count {
        let base = i * 8;
        ids[i] = u64::from_be_bytes([
            raw[base],
            raw[base + 1],
            raw[base + 2],
            raw[base + 3],
            raw[base + 4],
            raw[base + 5],
            raw[base + 6],
            raw[base + 7],
        ]);
        i += 1;
    }
    (ids, count)
}

fn store_id_list(key: &[u8], ids: &[u64; MAX_DEX_ORDERS], count: usize) {
    let mut raw = [0u8; MAX_DEX_ORDERS * 8];
    let n = count.min(MAX_DEX_ORDERS);
    let mut i = 0usize;
    while i < n {
        let base = i * 8;
        raw[base..base + 8].copy_from_slice(&ids[i].to_be_bytes());
        i += 1;
    }
    storage::set(key, &raw[..n * 8]);
}

/// Ordered insertion into the Bid list:
/// Primary sort: `price` DESCENDING (highest bid first).
/// Secondary sort within the same price: `block_number` ASCENDING (earliest block first).
/// Tie-breaker within the same `(price, block_number)` cohort: `order_id` ASCENDING.
fn insert_ordered_bid(
    bid_ids: &mut [u64; MAX_DEX_ORDERS],
    bid_count: &mut usize,
    new_ord: &DexOrder,
) -> Result<(), i32> {
    if *bid_count >= MAX_DEX_ORDERS {
        return Err(ERR_ORDERBOOK_FULL);
    }
    let mut pos = *bid_count;
    let mut i = 0usize;
    while i < *bid_count {
        if let Some(existing) = load_order(bid_ids[i]) {
            let higher_price = new_ord.price > existing.price;
            let same_price_earlier_block =
                new_ord.price == existing.price && new_ord.block_number < existing.block_number;
            let same_cohort_earlier_id = new_ord.price == existing.price
                && new_ord.block_number == existing.block_number
                && new_ord.order_id < existing.order_id;
            if higher_price || same_price_earlier_block || same_cohort_earlier_id {
                pos = i;
                break;
            }
        }
        i += 1;
    }
    let mut j = *bid_count;
    while j > pos {
        bid_ids[j] = bid_ids[j - 1];
        j -= 1;
    }
    bid_ids[pos] = new_ord.order_id;
    *bid_count += 1;
    Ok(())
}

/// Ordered insertion into the Ask list:
/// Primary sort: `price` ASCENDING (lowest ask first).
/// Secondary sort within the same price: `block_number` ASCENDING (earliest block first).
/// Tie-breaker within the same `(price, block_number)` cohort: `order_id` ASCENDING.
fn insert_ordered_ask(
    ask_ids: &mut [u64; MAX_DEX_ORDERS],
    ask_count: &mut usize,
    new_ord: &DexOrder,
) -> Result<(), i32> {
    if *ask_count >= MAX_DEX_ORDERS {
        return Err(ERR_ORDERBOOK_FULL);
    }
    let mut pos = *ask_count;
    let mut i = 0usize;
    while i < *ask_count {
        if let Some(existing) = load_order(ask_ids[i]) {
            let lower_price = new_ord.price < existing.price;
            let same_price_earlier_block =
                new_ord.price == existing.price && new_ord.block_number < existing.block_number;
            let same_cohort_earlier_id = new_ord.price == existing.price
                && new_ord.block_number == existing.block_number
                && new_ord.order_id < existing.order_id;
            if lower_price || same_price_earlier_block || same_cohort_earlier_id {
                pos = i;
                break;
            }
        }
        i += 1;
    }
    let mut j = *ask_count;
    while j > pos {
        ask_ids[j] = ask_ids[j - 1];
        j -= 1;
    }
    ask_ids[pos] = new_ord.order_id;
    *ask_count += 1;
    Ok(())
}

fn ensure_initialized_and_valid_caller() -> Result<([u8; 20], [u8; 20]), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).ok_or(-10)?;
    let caller = context::msg_sender();
    require_valid_identity(&registry, &caller)?;
    Ok((registry, caller))
}

fn call_dex_transfer(
    ledger: &[u8; 20],
    from_identity: &[u8; 20],
    to_identity: &[u8; 20],
    amount: u64,
) -> Result<(), i32> {
    if amount == 0 || from_identity == to_identity {
        return Ok(());
    }
    let cd = CallEncoder::<128>::new(const { selector("dexTransfer(address,address,uint64)") })
        .push_address(from_identity)
        .push_address(to_identity)
        .push_u64(amount);
    let ok = call::call_bool(ledger, cd.as_slice())?;
    if !ok {
        return Err(-16);
    }
    Ok(())
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let asset_ledger = args.address(1).ok_or(-3)?;
    let quote_ledger = args.address(2).ok_or(-3)?;
    let escrow_identity = args.address(3).ok_or(-3)?;

    if registry == [0u8; 20]
        || asset_ledger == [0u8; 20]
        || escrow_identity == [0u8; 20]
        || asset_ledger == quote_ledger
    {
        return Err(ERR_INVALID_DEX_ORDER);
    }

    require_valid_identity(&registry, &escrow_identity)?;

    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_ASSET_LEDGER, &asset_ledger);
    storage::set_address(KEY_QUOTE_LEDGER, &quote_ledger);
    storage::set_address(KEY_ESCROW_ID, &escrow_identity);
    storage::set_u64(KEY_INIT, 1);

    let mut ev = [0u8; 40];
    ev[0..20].copy_from_slice(&quote_ledger);
    ev[20..40].copy_from_slice(&escrow_identity);
    events::emit(
        &[
            DEX_INITIALIZED,
            addr_topic(&registry),
            addr_topic(&asset_ledger),
        ],
        &ev,
    );
    ret::write_bool(true);
    Ok(())
}

fn place_order_internal(side: u8, args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let price = args.u64(0).ok_or(-3)?;
    let quantity = args.u64(1).ok_or(-3)?;
    if price == 0 || quantity == 0 {
        return Err(ERR_INVALID_DEX_ORDER);
    }

    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    if caller == escrow_id {
        return Err(ERR_INVALID_DEX_ORDER);
    }

    let (mut pending_ids, mut pending_count) = load_id_list(KEY_PENDING_LIST);
    if pending_count >= MAX_DEX_ORDERS {
        return Err(ERR_ORDERBOOK_FULL);
    }

    let prev_count = storage::get_u64(KEY_ORDER_COUNT);
    if (prev_count as usize) >= MAX_DEX_ORDERS * 4 {
        return Err(ERR_ORDERBOOK_FULL);
    }

    // Escrow funds/assets into `escrowIdentity`
    if side == SIDE_BID {
        let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
        if quote_ledger != [0u8; 20] {
            let cost = price.checked_mul(quantity).ok_or(-15)?;
            call_dex_transfer(&quote_ledger, &caller, &escrow_id, cost)?;
        }
    } else {
        let asset_ledger = storage::get_address(KEY_ASSET_LEDGER).ok_or(-10)?;
        call_dex_transfer(&asset_ledger, &caller, &escrow_id, quantity)?;
    }

    let order_id = prev_count + 1;
    let arrival_block = context::block_number();
    let ord = DexOrder {
        order_id,
        trader: caller,
        side,
        status: STATUS_PENDING,
        price,
        orig_qty: quantity,
        rem_qty: quantity,
        block_number: arrival_block,
    };
    store_order(&ord);
    storage::set_u64(KEY_ORDER_COUNT, order_id);

    pending_ids[pending_count] = order_id;
    pending_count += 1;
    store_id_list(KEY_PENDING_LIST, &pending_ids, pending_count);

    let mut ev = [0u8; 32];
    ev[0] = side;
    ev[8..16].copy_from_slice(&price.to_be_bytes());
    ev[16..24].copy_from_slice(&quantity.to_be_bytes());
    ev[24..32].copy_from_slice(&arrival_block.to_be_bytes());
    events::emit(
        &[ORDER_PLACED, u64_topic(order_id), addr_topic(&caller)],
        &ev,
    );

    ret::write_u64_word(order_id);
    Ok(())
}

fn handle_place_bid(args: &CalldataReader) -> Result<(), i32> {
    place_order_internal(SIDE_BID, args)
}

fn handle_place_ask(args: &CalldataReader) -> Result<(), i32> {
    place_order_internal(SIDE_ASK, args)
}

fn handle_cancel_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let order_id = args.u64(0).ok_or(-3)?;
    let mut ord = load_order(order_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if ord.trader != caller {
        return Err(ERR_NOT_ORDER_OWNER);
    }
    if ord.status == STATUS_CANCELLED || ord.status == STATUS_FILLED || ord.rem_qty == 0 {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }

    let refund_qty = ord.rem_qty;
    let prev_status = ord.status;
    ord.status = STATUS_CANCELLED;
    ord.rem_qty = 0;
    store_order(&ord);

    if prev_status == STATUS_PENDING {
        let (pending_ids, pending_count) = load_id_list(KEY_PENDING_LIST);
        let mut next_ids = [0u64; MAX_DEX_ORDERS];
        let mut next_count = 0usize;
        let mut i = 0usize;
        while i < pending_count {
            if pending_ids[i] != order_id {
                next_ids[next_count] = pending_ids[i];
                next_count += 1;
            }
            i += 1;
        }
        store_id_list(KEY_PENDING_LIST, &next_ids, next_count);
    } else if ord.side == SIDE_BID {
        let (bid_ids, bid_count) = load_id_list(KEY_BID_LIST);
        let mut next_ids = [0u64; MAX_DEX_ORDERS];
        let mut next_count = 0usize;
        let mut i = 0usize;
        while i < bid_count {
            if bid_ids[i] != order_id {
                next_ids[next_count] = bid_ids[i];
                next_count += 1;
            }
            i += 1;
        }
        store_id_list(KEY_BID_LIST, &next_ids, next_count);
    } else {
        let (ask_ids, ask_count) = load_id_list(KEY_ASK_LIST);
        let mut next_ids = [0u64; MAX_DEX_ORDERS];
        let mut next_count = 0usize;
        let mut i = 0usize;
        while i < ask_count {
            if ask_ids[i] != order_id {
                next_ids[next_count] = ask_ids[i];
                next_count += 1;
            }
            i += 1;
        }
        store_id_list(KEY_ASK_LIST, &next_ids, next_count);
    }

    // Refund remaining escrow back to the trader
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    if ord.side == SIDE_BID {
        let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
        if quote_ledger != [0u8; 20] {
            let refund_quote = ord.price.checked_mul(refund_qty).ok_or(-15)?;
            call_dex_transfer(&quote_ledger, &escrow_id, &caller, refund_quote)?;
        }
    } else {
        let asset_ledger = storage::get_address(KEY_ASSET_LEDGER).ok_or(-10)?;
        call_dex_transfer(&asset_ledger, &escrow_id, &caller, refund_qty)?;
    }

    events::emit(
        &[ORDER_CANCELLED, u64_topic(order_id), addr_topic(&caller)],
        &refund_qty.to_be_bytes(),
    );
    ret::write_u64_word(refund_qty);
    Ok(())
}

/// Allocate fills across crossing orders (`orders[0..crossing_count]`) for `target_volume`
/// following strict `(price, block_number)` cohort order and pro-rating within any marginal
/// `(price, block_number)` cohort where multiple orders share the exact same price and arrival block.
fn allocate_cohort_fills(
    orders: &[DexOrder; MAX_DEX_ORDERS],
    crossing_count: usize,
    target_volume: u64,
) -> [u64; MAX_DEX_ORDERS] {
    let mut fills = [0u64; MAX_DEX_ORDERS];
    let mut rem_to_fill = target_volume;
    let mut idx = 0usize;

    while idx < crossing_count && rem_to_fill > 0 {
        let cohort_price = orders[idx].price;
        let cohort_block = orders[idx].block_number;

        let mut end = idx + 1;
        while end < crossing_count
            && orders[end].price == cohort_price
            && orders[end].block_number == cohort_block
        {
            end += 1;
        }

        let mut cohort_qty = 0u64;
        let mut k = idx;
        while k < end {
            cohort_qty = cohort_qty.saturating_add(orders[k].rem_qty);
            k += 1;
        }

        if cohort_qty == 0 {
            idx = end;
            continue;
        }

        if rem_to_fill >= cohort_qty {
            // Entire `(price, block_number)` cohort fills 100%
            k = idx;
            while k < end {
                fills[k] = orders[k].rem_qty;
                k += 1;
            }
            rem_to_fill -= cohort_qty;
        } else {
            // Marginal `(price, block_number)` cohort: all orders in `[idx..end]` have the exact
            // same price and arrived at the exact same block -> equal priority -> pro-rata fill!
            // Note: Exact integer floor `floor(rem_to_fill * rem_qty_k / cohort_qty)` is used without
            // assigning leftover 1-unit rounding dust by intra-block transaction index, so intra-block
            // transaction ordering has ZERO effect on any order's fill (strictly MEV-proof).
            k = idx;
            while k < end {
                let num = (rem_to_fill as u128) * (orders[k].rem_qty as u128);
                let fl = (num / (cohort_qty as u128)) as u64;
                fills[k] = fl;
                k += 1;
            }
            rem_to_fill = 0;
        }

        idx = end;
    }

    fills
}

/// Per-block discrete-time FIFO CLOB matching engine entrypoint:
/// 1. Iterates through all pending orders received until the last block (`order.block_number < current_block`)
///    and inserts them into the ordered Bid list (`price DESC, block_number ASC`) and ordered Ask list
///    (`price ASC, block_number ASC`). Orders placed in `current_block` are NEVER ingested in `current_block`,
///    preventing intra-block front-running, back-running, or sandwiching.
/// 2. Checks for crossing Bid and Ask prices (`best_bid.price >= best_ask.price`).
/// 3. Determines a single clearing price `P*` maximizing matched volume `V* = min(D(P*), S(P*))`.
/// 4. Fills crossing Bids and Asks in order of price first and earliest block second, pro-rating fills
///    among orders with the same price that arrived at the same block.
/// 5. Settles base asset and quote cash balances via `AssetLedger.dexTransfer`.
fn handle_match_block(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let current_block = context::block_number();

    let (pending_ids, pending_count) = load_id_list(KEY_PENDING_LIST);
    let (mut bid_ids, mut bid_count) = load_id_list(KEY_BID_LIST);
    let (mut ask_ids, mut ask_count) = load_id_list(KEY_ASK_LIST);

    let mut rem_pending = [0u64; MAX_DEX_ORDERS];
    let mut rem_pending_count = 0usize;
    let mut ingested_count = 0u64;

    let mut i = 0usize;
    while i < pending_count {
        let oid = pending_ids[i];
        if let Some(mut ord) = load_order(oid) {
            if ord.status == STATUS_PENDING && ord.rem_qty > 0 {
                // Strictly ingest only orders received until the last block (`block_number < current_block`)
                if ord.block_number < current_block {
                    ord.status = STATUS_ACTIVE;
                    store_order(&ord);
                    if ord.side == SIDE_BID {
                        insert_ordered_bid(&mut bid_ids, &mut bid_count, &ord)?;
                    } else {
                        insert_ordered_ask(&mut ask_ids, &mut ask_count, &ord)?;
                    }
                    ingested_count += 1;
                    let mut ev = [0u8; 24];
                    ev[0] = ord.side;
                    ev[8..16].copy_from_slice(&ord.price.to_be_bytes());
                    ev[16..24].copy_from_slice(&ord.block_number.to_be_bytes());
                    events::emit(&[ORDER_INGESTED, u64_topic(ord.order_id)], &ev);
                } else {
                    rem_pending[rem_pending_count] = oid;
                    rem_pending_count += 1;
                }
            }
        }
        i += 1;
    }

    store_id_list(KEY_PENDING_LIST, &rem_pending, rem_pending_count);

    // Load active ordered Bids and Asks
    let mut bids = [DexOrder::default(); MAX_DEX_ORDERS];
    let mut active_bid_count = 0usize;
    i = 0;
    while i < bid_count {
        if let Some(ord) = load_order(bid_ids[i]) {
            if ord.status == STATUS_ACTIVE && ord.rem_qty > 0 {
                bids[active_bid_count] = ord;
                active_bid_count += 1;
            }
        }
        i += 1;
    }

    let mut asks = [DexOrder::default(); MAX_DEX_ORDERS];
    let mut active_ask_count = 0usize;
    i = 0;
    while i < ask_count {
        if let Some(ord) = load_order(ask_ids[i]) {
            if ord.status == STATUS_ACTIVE && ord.rem_qty > 0 {
                asks[active_ask_count] = ord;
                active_ask_count += 1;
            }
        }
        i += 1;
    }

    // If no crossing orders exist (`best_bid.price < best_ask.price`), persist the ordered lists
    // and return `(0, 0, ingested_count, 0, 0)`.
    if active_bid_count == 0
        || active_ask_count == 0
        || bids[0].price < asks[0].price
    {
        let mut next_bid_ids = [0u64; MAX_DEX_ORDERS];
        i = 0;
        while i < active_bid_count {
            next_bid_ids[i] = bids[i].order_id;
            i += 1;
        }
        store_id_list(KEY_BID_LIST, &next_bid_ids, active_bid_count);

        let mut next_ask_ids = [0u64; MAX_DEX_ORDERS];
        i = 0;
        while i < active_ask_count {
            next_ask_ids[i] = asks[i].order_id;
            i += 1;
        }
        store_id_list(KEY_ASK_LIST, &next_ask_ids, active_ask_count);

        storage::set_u64(KEY_LAST_MATCH_BLOCK, current_block);
        storage::set_u64(KEY_LAST_PRICE, 0);
        storage::set_u64(KEY_LAST_VOL, 0);
        storage::set_u64(KEY_LAST_INGESTED, ingested_count);
        storage::set_u64(KEY_LAST_FILLED_BIDS, 0);
        storage::set_u64(KEY_LAST_FILLED_ASKS, 0);

        let mut out = [0u8; 160];
        out[88..96].copy_from_slice(&ingested_count.to_be_bytes());
        ret::write(&out);
        return Ok(());
    }

    // Collect sorted unique candidate prices within the crossing range `[asks[0].price ..= bids[0].price]`
    let min_cross_px = asks[0].price;
    let max_cross_px = bids[0].price;
    let mut candidates = [0u64; MAX_DEX_ORDERS * 2];
    let mut cand_count = 0usize;

    i = 0;
    while i < active_bid_count {
        let p = bids[i].price;
        if p >= min_cross_px && p <= max_cross_px {
            let mut exists = false;
            let mut k = 0usize;
            while k < cand_count {
                if candidates[k] == p {
                    exists = true;
                    break;
                }
                k += 1;
            }
            if !exists {
                candidates[cand_count] = p;
                cand_count += 1;
            }
        }
        i += 1;
    }
    i = 0;
    while i < active_ask_count {
        let p = asks[i].price;
        if p >= min_cross_px && p <= max_cross_px {
            let mut exists = false;
            let mut k = 0usize;
            while k < cand_count {
                if candidates[k] == p {
                    exists = true;
                    break;
                }
                k += 1;
            }
            if !exists {
                candidates[cand_count] = p;
                cand_count += 1;
            }
        }
        i += 1;
    }

    // Insertion-sort candidate prices ascending
    i = 1;
    while i < cand_count {
        let key = candidates[i];
        let mut j = i;
        while j > 0 && candidates[j - 1] > key {
            candidates[j] = candidates[j - 1];
            j -= 1;
        }
        candidates[j] = key;
        i += 1;
    }

    // Determine single clearing price P* maximizing matched volume V(P) = min(D(P), S(P)),
    // tie-breaking by minimum absolute imbalance |D(P) - S(P)|, then midpoint.
    let mut best_vol = 0u64;
    let mut best_imbalance = u64::MAX;
    let mut best_min_price = 0u64;
    let mut best_max_price = 0u64;
    let mut best_demand = 0u64;
    let mut best_supply = 0u64;

    i = 0;
    while i < cand_count {
        let p = candidates[i];
        let mut d = 0u64;
        let mut b = 0usize;
        while b < active_bid_count {
            if bids[b].price >= p {
                d = d.saturating_add(bids[b].rem_qty);
            }
            b += 1;
        }
        let mut s = 0u64;
        let mut a = 0usize;
        while a < active_ask_count {
            if asks[a].price <= p {
                s = s.saturating_add(asks[a].rem_qty);
            }
            a += 1;
        }
        let vol = if d < s { d } else { s };
        if vol > 0 {
            let imb = if d >= s { d - s } else { s - d };
            if vol > best_vol || (vol == best_vol && imb < best_imbalance) {
                best_vol = vol;
                best_imbalance = imb;
                best_min_price = p;
                best_max_price = p;
                best_demand = d;
                best_supply = s;
            } else if vol == best_vol && imb == best_imbalance {
                best_max_price = p;
            }
        }
        i += 1;
    }

    if best_vol == 0 {
        return Err(ERR_NO_CROSSING_ORDERS);
    }

    let clearing_price = if best_demand > best_supply {
        best_max_price
    } else if best_supply > best_demand {
        best_min_price
    } else {
        best_min_price + (best_max_price - best_min_price) / 2
    };

    // Since `bids` is ordered by `price DESC` and `asks` is ordered by `price ASC`,
    // all crossing bids (`price >= clearing_price`) form a contiguous prefix `bids[0..crossing_bid_count]`
    // and all crossing asks (`price <= clearing_price`) form a contiguous prefix `asks[0..crossing_ask_count]`.
    let mut crossing_bid_count = 0usize;
    let mut total_bid_cross = 0u64;
    while crossing_bid_count < active_bid_count && bids[crossing_bid_count].price >= clearing_price
    {
        total_bid_cross = total_bid_cross.saturating_add(bids[crossing_bid_count].rem_qty);
        crossing_bid_count += 1;
    }

    let mut crossing_ask_count = 0usize;
    let mut total_ask_cross = 0u64;
    while crossing_ask_count < active_ask_count && asks[crossing_ask_count].price <= clearing_price
    {
        total_ask_cross = total_ask_cross.saturating_add(asks[crossing_ask_count].rem_qty);
        crossing_ask_count += 1;
    }

    let matched_volume = if total_bid_cross < total_ask_cross {
        total_bid_cross
    } else {
        total_ask_cross
    };

    // Compute fills in `(price, block_number)` priority order with same-block pro-rata allocation.
    // Because we use exact integer floor `floor(target * rem_qty / cohort_qty)` without assigning
    // rounding dust by intra-block transaction order, the sum of pro-rated fills on the rationed side
    // may be up to `cohort_size - 1` units less than `matched_volume`; we therefore re-align both sides
    // to the exact integer-feasible `actual_matched = min(sum(bid_fills), sum(ask_fills))` so total buyer
    // fills and total seller fills are always 100% balanced AND strictly permutation-invariant.
    let mut bid_fills = allocate_cohort_fills(&bids, crossing_bid_count, matched_volume);
    let mut ask_fills = allocate_cohort_fills(&asks, crossing_ask_count, matched_volume);

    let mut sum_bid_fills = 0u64;
    i = 0;
    while i < crossing_bid_count {
        sum_bid_fills = sum_bid_fills.saturating_add(bid_fills[i]);
        i += 1;
    }
    let mut sum_ask_fills = 0u64;
    i = 0;
    while i < crossing_ask_count {
        sum_ask_fills = sum_ask_fills.saturating_add(ask_fills[i]);
        i += 1;
    }
    let matched_volume = if sum_bid_fills < sum_ask_fills {
        ask_fills = allocate_cohort_fills(&asks, crossing_ask_count, sum_bid_fills);
        let mut s = 0u64;
        i = 0;
        while i < crossing_ask_count {
            s = s.saturating_add(ask_fills[i]);
            i += 1;
        }
        s
    } else if sum_ask_fills < sum_bid_fills {
        bid_fills = allocate_cohort_fills(&bids, crossing_bid_count, sum_ask_fills);
        let mut s = 0u64;
        i = 0;
        while i < crossing_bid_count {
            s = s.saturating_add(bid_fills[i]);
            i += 1;
        }
        s
    } else {
        sum_bid_fills
    };

    let asset_ledger = storage::get_address(KEY_ASSET_LEDGER).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;

    // Settle filled Bids: transfer base asset from `escrow_id` to buyer, and refund any price
    // improvement (`(bid.price - clearing_price) * fill`) in `quote_ledger` back to the buyer.
    let mut filled_bid_orders = 0u64;
    i = 0;
    while i < crossing_bid_count {
        let fill = bid_fills[i];
        if fill > 0 {
            filled_bid_orders += 1;
            call_dex_transfer(&asset_ledger, &escrow_id, &bids[i].trader, fill)?;
            if quote_ledger != [0u8; 20] && bids[i].price > clearing_price {
                let price_improvement = (bids[i].price - clearing_price)
                    .checked_mul(fill)
                    .ok_or(-15)?;
                call_dex_transfer(&quote_ledger, &escrow_id, &bids[i].trader, price_improvement)?;
            }
            bids[i].rem_qty = bids[i].rem_qty.saturating_sub(fill);
            if bids[i].rem_qty == 0 {
                bids[i].status = STATUS_FILLED;
            }
            store_order(&bids[i]);

            let mut ev = [0u8; 32];
            ev[0] = SIDE_BID;
            ev[8..16].copy_from_slice(&clearing_price.to_be_bytes());
            ev[16..24].copy_from_slice(&fill.to_be_bytes());
            ev[24..32].copy_from_slice(&bids[i].rem_qty.to_be_bytes());
            events::emit(
                &[
                    ORDER_FILLED,
                    u64_topic(bids[i].order_id),
                    addr_topic(&bids[i].trader),
                ],
                &ev,
            );
        }
        i += 1;
    }

    // Settle filled Asks: transfer quote proceeds (`clearing_price * fill`) from `escrow_id` to seller.
    let mut filled_ask_orders = 0u64;
    i = 0;
    while i < crossing_ask_count {
        let fill = ask_fills[i];
        if fill > 0 {
            filled_ask_orders += 1;
            if quote_ledger != [0u8; 20] {
                let proceeds = clearing_price.checked_mul(fill).ok_or(-15)?;
                call_dex_transfer(&quote_ledger, &escrow_id, &asks[i].trader, proceeds)?;
            }
            asks[i].rem_qty = asks[i].rem_qty.saturating_sub(fill);
            if asks[i].rem_qty == 0 {
                asks[i].status = STATUS_FILLED;
            }
            store_order(&asks[i]);

            let mut ev = [0u8; 32];
            ev[0] = SIDE_ASK;
            ev[8..16].copy_from_slice(&clearing_price.to_be_bytes());
            ev[16..24].copy_from_slice(&fill.to_be_bytes());
            ev[24..32].copy_from_slice(&asks[i].rem_qty.to_be_bytes());
            events::emit(
                &[
                    ORDER_FILLED,
                    u64_topic(asks[i].order_id),
                    addr_topic(&asks[i].trader),
                ],
                &ev,
            );
        }
        i += 1;
    }

    // Compact remaining active (unfilled or partially filled) orders back into the ordered lists,
    // preserving their exact `(price, block_number)` priority for subsequent blocks.
    let mut next_bid_ids = [0u64; MAX_DEX_ORDERS];
    let mut next_bid_count = 0usize;
    i = 0;
    while i < active_bid_count {
        if bids[i].status == STATUS_ACTIVE && bids[i].rem_qty > 0 {
            next_bid_ids[next_bid_count] = bids[i].order_id;
            next_bid_count += 1;
        }
        i += 1;
    }
    store_id_list(KEY_BID_LIST, &next_bid_ids, next_bid_count);

    let mut next_ask_ids = [0u64; MAX_DEX_ORDERS];
    let mut next_ask_count = 0usize;
    i = 0;
    while i < active_ask_count {
        if asks[i].status == STATUS_ACTIVE && asks[i].rem_qty > 0 {
            next_ask_ids[next_ask_count] = asks[i].order_id;
            next_ask_count += 1;
        }
        i += 1;
    }
    store_id_list(KEY_ASK_LIST, &next_ask_ids, next_ask_count);

    storage::set_u64(KEY_LAST_MATCH_BLOCK, current_block);
    storage::set_u64(KEY_LAST_PRICE, clearing_price);
    storage::set_u64(KEY_LAST_VOL, matched_volume);
    storage::set_u64(KEY_LAST_INGESTED, ingested_count);
    storage::set_u64(KEY_LAST_FILLED_BIDS, filled_bid_orders);
    storage::set_u64(KEY_LAST_FILLED_ASKS, filled_ask_orders);

    let mut summary = [0u8; 40];
    summary[0..8].copy_from_slice(&clearing_price.to_be_bytes());
    summary[8..16].copy_from_slice(&matched_volume.to_be_bytes());
    summary[16..24].copy_from_slice(&ingested_count.to_be_bytes());
    summary[24..32].copy_from_slice(&filled_bid_orders.to_be_bytes());
    summary[32..40].copy_from_slice(&filled_ask_orders.to_be_bytes());
    events::emit(&[BLOCK_MATCHED, u64_topic(current_block)], &summary);

    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&clearing_price.to_be_bytes());
    out[56..64].copy_from_slice(&matched_volume.to_be_bytes());
    out[88..96].copy_from_slice(&ingested_count.to_be_bytes());
    out[120..128].copy_from_slice(&filled_bid_orders.to_be_bytes());
    out[152..160].copy_from_slice(&filled_ask_orders.to_be_bytes());
    ret::write(&out);
    Ok(())
}

// ============================================================================
// Read-Only Queries
// ============================================================================

fn write_order_tuple(ord: &DexOrder) {
    let mut out = [0u8; 256];
    out[24..32].copy_from_slice(&ord.order_id.to_be_bytes());
    out[44..64].copy_from_slice(&ord.trader);
    out[95] = ord.side;
    out[127] = ord.status;
    out[152..160].copy_from_slice(&ord.price.to_be_bytes());
    out[184..192].copy_from_slice(&ord.orig_qty.to_be_bytes());
    out[216..224].copy_from_slice(&ord.rem_qty.to_be_bytes());
    out[248..256].copy_from_slice(&ord.block_number.to_be_bytes());
    ret::write(&out);
}

fn handle_get_order(args: &CalldataReader) -> Result<(), i32> {
    let order_id = args.u64(0).ok_or(-3)?;
    let ord = load_order(order_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    write_order_tuple(&ord);
    Ok(())
}

fn handle_order_count(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_ORDER_COUNT));
    Ok(())
}

fn handle_book_depth(_args: &CalldataReader) -> Result<(), i32> {
    let (_p, pending_count) = load_id_list(KEY_PENDING_LIST);
    let (_b, bid_count) = load_id_list(KEY_BID_LIST);
    let (_a, ask_count) = load_id_list(KEY_ASK_LIST);
    let mut out = [0u8; 96];
    out[24..32].copy_from_slice(&(pending_count as u64).to_be_bytes());
    out[56..64].copy_from_slice(&(bid_count as u64).to_be_bytes());
    out[88..96].copy_from_slice(&(ask_count as u64).to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_best_bid_and_ask(_args: &CalldataReader) -> Result<(), i32> {
    let (bid_ids, bid_count) = load_id_list(KEY_BID_LIST);
    let (ask_ids, ask_count) = load_id_list(KEY_ASK_LIST);
    let best_bid = if bid_count > 0 {
        load_order(bid_ids[0]).map(|o| o.price).unwrap_or(0)
    } else {
        0
    };
    let best_ask = if ask_count > 0 {
        load_order(ask_ids[0]).map(|o| o.price).unwrap_or(0)
    } else {
        0
    };
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&best_bid.to_be_bytes());
    out[56..64].copy_from_slice(&best_ask.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_get_ordered_bid_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let (bid_ids, bid_count) = load_id_list(KEY_BID_LIST);
    if idx >= bid_count {
        return Err(ERR_ORDER_NOT_FOUND);
    }
    let ord = load_order(bid_ids[idx]).ok_or(ERR_ORDER_NOT_FOUND)?;
    write_order_tuple(&ord);
    Ok(())
}

fn handle_get_ordered_ask_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let (ask_ids, ask_count) = load_id_list(KEY_ASK_LIST);
    if idx >= ask_count {
        return Err(ERR_ORDER_NOT_FOUND);
    }
    let ord = load_order(ask_ids[idx]).ok_or(ERR_ORDER_NOT_FOUND)?;
    write_order_tuple(&ord);
    Ok(())
}

fn handle_last_match_summary(_args: &CalldataReader) -> Result<(), i32> {
    let mut out = [0u8; 192];
    out[24..32].copy_from_slice(&storage::get_u64(KEY_LAST_MATCH_BLOCK).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(KEY_LAST_PRICE).to_be_bytes());
    out[88..96].copy_from_slice(&storage::get_u64(KEY_LAST_VOL).to_be_bytes());
    out[120..128].copy_from_slice(&storage::get_u64(KEY_LAST_INGESTED).to_be_bytes());
    out[152..160].copy_from_slice(&storage::get_u64(KEY_LAST_FILLED_BIDS).to_be_bytes());
    out[184..192].copy_from_slice(&storage::get_u64(KEY_LAST_FILLED_ASKS).to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_asset_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ASSET_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_quote_ledger(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_escrow_identity(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]));
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_address(&storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    mod sim_ledgers {
        use hps_sdk::abi::CalldataReader;
        use hps_sdk::storage::KeyBuilder;
        use hps_sdk::{ret, selector, storage};

        pub fn reg_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("isValidIdentity(address)") } {
                let id = args.address(0).unwrap();
                ret::write_bool(id != [0u8; 20] && id[0] != 0xEE);
                return 0;
            }
            -2
        }

        fn bal_key(holder: &[u8; 20]) -> KeyBuilder<32> {
            KeyBuilder::<32>::new().push(b"bal:").push(holder)
        }

        pub fn ledger_dispatch(raw: &[u8]) -> i32 {
            let Some((sel, args)) = CalldataReader::parse(raw) else {
                return -1;
            };
            if sel == const { selector("seed(address,uint64)") } {
                let h = args.address(0).unwrap();
                let amt = args.u64(1).unwrap();
                let bk = bal_key(&h);
                storage::set_u64(bk.as_slice(), amt);
                ret::write_bool(true);
                return 0;
            }
            if sel == const { selector("balanceOf(address)") } {
                let h = args.address(0).unwrap();
                let bk = bal_key(&h);
                ret::write_u64_word(storage::get_u64(bk.as_slice()));
                return 0;
            }
            if sel == const { selector("dexTransfer(address,address,uint64)") } {
                let from = args.address(0).unwrap();
                let to = args.address(1).unwrap();
                let amt = args.u64(2).unwrap();
                let fk = bal_key(&from);
                let tk = bal_key(&to);
                let fb = storage::get_u64(fk.as_slice());
                if fb < amt {
                    return -16;
                }
                storage::set_u64(fk.as_slice(), fb - amt);
                let tb = storage::get_u64(tk.as_slice());
                storage::set_u64(tk.as_slice(), tb + amt);
                ret::write_bool(true);
                return 0;
            }
            -2
        }
    }

    fn seed_balance(ledger: [u8; 20], holder: [u8; 20], amount: u64) {
        let cd = CallEncoder::<96>::new(const { selector("seed(address,uint64)") })
            .push_address(&holder)
            .push_u64(amount);
        mock::transact_as([0x01; 20], ledger, cd.as_slice()).unwrap();
    }

    fn balance_of(ledger: [u8; 20], holder: [u8; 20]) -> u64 {
        let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") })
            .push_address(&holder);
        let out = mock::transact_as([0x01; 20], ledger, cd.as_slice()).unwrap();
        u64::from_be_bytes(out[24..32].try_into().unwrap())
    }

    #[test]
    fn discrete_time_fifo_clob_orders_by_price_then_block_and_prorates_same_block_cohorts() {
        mock::reset();
        let reg = [0x10; 20];
        let asset_ledger = [0x20; 20];
        let quote_ledger = [0x30; 20];
        let dex = [0x40; 20];
        let escrow_id = [0x90; 20];

        let buyer_early = [0xA1; 20];
        let buyer_same_blk_1 = [0xA2; 20];
        let buyer_same_blk_2 = [0xA3; 20];
        let buyer_high_px = [0xA4; 20];
        let seller_1 = [0xB1; 20];
        let seller_2 = [0xB2; 20];

        mock::register_hps(reg, sim_ledgers::reg_dispatch);
        mock::register_hps(asset_ledger, sim_ledgers::ledger_dispatch);
        mock::register_hps(quote_ledger, sim_ledgers::ledger_dispatch);
        mock::register_hps(dex, dispatch_calldata);

        // Initialize DEX attached to `asset_ledger` and `quote_ledger`
        let init_cd = CallEncoder::<160>::new(const {
            selector("initialize(address,address,address,address)")
        })
        .push_address(&reg)
        .push_address(&asset_ledger)
        .push_address(&quote_ledger)
        .push_address(&escrow_id);
        mock::transact_as(buyer_early, dex, init_cd.as_slice()).unwrap();

        // Seed quote cash for buyers and base assets for sellers
        seed_balance(quote_ledger, buyer_early, 100_000);
        seed_balance(quote_ledger, buyer_same_blk_1, 100_000);
        seed_balance(quote_ledger, buyer_same_blk_2, 100_000);
        seed_balance(quote_ledger, buyer_high_px, 100_000);
        seed_balance(asset_ledger, seller_1, 1_000);
        seed_balance(asset_ledger, seller_2, 1_000);

        // --- Block 10: `buyer_early` places Bid @ $10 for 100 units ---
        mock::set_block_number(10);
        let bid1_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(10)
            .push_u64(100);
        mock::transact_as(buyer_early, dex, bid1_cd.as_slice()).unwrap();

        // --- Block 11:
        //   - `buyer_same_blk_1` places Bid @ $10 for 100 units (same price $10, later block 11)
        //   - `buyer_same_blk_2` places Bid @ $10 for 300 units (same price $10, same block 11)
        //   - `buyer_high_px` places Bid @ $12 for 50 units (higher price $12, block 11)
        //   - `seller_1` places Ask @ $10 for 200 units (block 11)
        //   - `seller_2` places Ask @ $9 for 150 units (lower ask price $9, block 11)
        mock::set_block_number(11);
        let b2_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(10)
            .push_u64(100);
        mock::transact_as(buyer_same_blk_1, dex, b2_cd.as_slice()).unwrap();

        let b3_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(10)
            .push_u64(300);
        mock::transact_as(buyer_same_blk_2, dex, b3_cd.as_slice()).unwrap();

        let b4_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(12)
            .push_u64(50);
        mock::transact_as(buyer_high_px, dex, b4_cd.as_slice()).unwrap();

        let a1_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(10)
            .push_u64(200);
        mock::transact_as(seller_1, dex, a1_cd.as_slice()).unwrap();

        let a2_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(9)
            .push_u64(150);
        mock::transact_as(seller_2, dex, a2_cd.as_slice()).unwrap();

        // --- Block 12: Call `matchBlock()` to ingest all orders from blocks 10 & 11 and match ---
        // Total crossing supply at P* = $10 is 150 (@ $9) + 200 (@ $10) = 350 units.
        // Total crossing demand at P* = $10 is 50 (@ $12) + 100 (@ $10, blk 10) + 400 (@ $10, blk 11) = 550 units.
        // Matched volume V* = 350 units at single clearing price P* = $10:
        //   1. `buyer_high_px` (Bid @ $12, blk 11, qty 50) -> Price priority! Fills 100% = 50 units (rem 300).
        //      Also receives ($12 - $10) * 50 = $100 price improvement refund!
        //   2. `buyer_early` (Bid @ $10, blk 10, qty 100) -> Earliest block at price $10! Fills 100% = 100 units (rem 200).
        //   3. Marginal cohort `(price = $10, block = 11)` has `buyer_same_blk_1` (100) and `buyer_same_blk_2` (300)
        //      for total cohort qty = 400, with 200 units remaining to fill -> Equal priority pro-rata (50% each):
        //      - `buyer_same_blk_1` gets 200 * 100 / 400 = 50 units (50 remaining on book)
        //      - `buyer_same_blk_2` gets 200 * 300 / 400 = 150 units (150 remaining on book)
        //   4. On the Ask side, `seller_2` (Ask @ $9, qty 150) + `seller_1` (Ask @ $10, qty 200) = 350 units -> both fill 100%!
        mock::set_block_number(12);
        let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
        let match_out = mock::transact_as(buyer_early, dex, match_cd.as_slice()).unwrap();
        let clearing_px = u64::from_be_bytes(match_out[24..32].try_into().unwrap());
        let matched_vol = u64::from_be_bytes(match_out[56..64].try_into().unwrap());
        let ingested = u64::from_be_bytes(match_out[88..96].try_into().unwrap());
        let filled_bids = u64::from_be_bytes(match_out[120..128].try_into().unwrap());
        let filled_asks = u64::from_be_bytes(match_out[152..160].try_into().unwrap());

        assert_eq!(clearing_px, 10);
        assert_eq!(matched_vol, 350);
        assert_eq!(ingested, 6);
        assert_eq!(filled_bids, 4);
        assert_eq!(filled_asks, 2);

        // Verify base asset balances received by buyers
        assert_eq!(balance_of(asset_ledger, buyer_high_px), 50);
        assert_eq!(balance_of(asset_ledger, buyer_early), 100);
        assert_eq!(balance_of(asset_ledger, buyer_same_blk_1), 50);
        assert_eq!(balance_of(asset_ledger, buyer_same_blk_2), 150);

        // Verify `buyer_high_px` paid clearing price $10 * 50 = $500 (escrowed $600, refunded $100 -> 99_500 remaining)
        assert_eq!(balance_of(quote_ledger, buyer_high_px), 99_500);
        // Verify sellers received $10 * 150 = $1_500 and $10 * 200 = $2_000
        assert_eq!(balance_of(quote_ledger, seller_2), 1_500);
        assert_eq!(balance_of(quote_ledger, seller_1), 2_000);

        // Verify the two partially filled block-11 bids remain resting on the ordered Bid book
        let depth_cd = CallEncoder::<16>::new(const { selector("bookDepth()") });
        let depth_out = mock::transact_as(buyer_early, dex, depth_cd.as_slice()).unwrap();
        let pending_cnt = u64::from_be_bytes(depth_out[24..32].try_into().unwrap());
        let bid_cnt = u64::from_be_bytes(depth_out[56..64].try_into().unwrap());
        let ask_cnt = u64::from_be_bytes(depth_out[88..96].try_into().unwrap());
        assert_eq!((pending_cnt, bid_cnt, ask_cnt), (0, 2, 0));
    }

    #[test]
    fn mev_invariance_under_intra_block_tx_reordering_and_same_block_match_isolation() {
        // Run the exact same block-level order flow under two reversed intra-block transaction
        // orderings (A before B vs. B before A) AND with an attacker attempting to call `matchBlock()`
        // in the same block as their front-run/sandwich order. Verify that every trader's fill and
        // balance is 100% identical regardless of transaction ordering inside the block.
        let run_with_order = |b_first: bool| -> (u64, u64, u64, u64, u64, u64) {
            mock::reset();
            let reg = [0x10; 20];
            let asset_ledger = [0x20; 20];
            let quote_ledger = [0x30; 20];
            let dex = [0x40; 20];
            let escrow_id = [0x90; 20];

            let trader_a = [0xA1; 20];
            let trader_b = [0xA2; 20];
            let seller = [0xB1; 20];

            mock::register_hps(reg, sim_ledgers::reg_dispatch);
            mock::register_hps(asset_ledger, sim_ledgers::ledger_dispatch);
            mock::register_hps(quote_ledger, sim_ledgers::ledger_dispatch);
            mock::register_hps(dex, dispatch_calldata);

            let init_cd = CallEncoder::<160>::new(const {
                selector("initialize(address,address,address,address)")
            })
            .push_address(&reg)
            .push_address(&asset_ledger)
            .push_address(&quote_ledger)
            .push_address(&escrow_id);
            mock::transact_as(trader_a, dex, init_cd.as_slice()).unwrap();

            seed_balance(quote_ledger, trader_a, 10_000);
            seed_balance(quote_ledger, trader_b, 10_000);
            seed_balance(asset_ledger, seller, 1_000);

            // Block 50: Both `trader_a` and `trader_b` submit identical Bid @ $10 for 100 units,
            // and `seller` submits Ask @ $10 for 101 units (creating an indivisible 1-unit remainder
            // when pro-rating 101 across 100 + 100 = 200!).
            mock::set_block_number(50);
            let bid_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
                .push_u64(10)
                .push_u64(100);
            let ask_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
                .push_u64(10)
                .push_u64(101);

            if !b_first {
                mock::transact_as(trader_a, dex, bid_cd.as_slice()).unwrap();
                // Attacker tries calling `matchBlock()` in the SAME block 50 right after `trader_a`:
                // must ingest 0 orders and match 0 volume because Block 50 is not yet closed!
                let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
                let early_out = mock::transact_as(trader_a, dex, match_cd.as_slice()).unwrap();
                assert_eq!(u64::from_be_bytes(early_out[56..64].try_into().unwrap()), 0);
                assert_eq!(u64::from_be_bytes(early_out[88..96].try_into().unwrap()), 0);

                mock::transact_as(trader_b, dex, bid_cd.as_slice()).unwrap();
                mock::transact_as(seller, dex, ask_cd.as_slice()).unwrap();
            } else {
                mock::transact_as(seller, dex, ask_cd.as_slice()).unwrap();
                mock::transact_as(trader_b, dex, bid_cd.as_slice()).unwrap();
                mock::transact_as(trader_a, dex, bid_cd.as_slice()).unwrap();
            }

            // Block 51: Call `matchBlock()` to ingest Block 50 orders and clear
            mock::set_block_number(51);
            let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
            mock::transact_as(trader_a, dex, match_cd.as_slice()).unwrap();

            (
                balance_of(asset_ledger, trader_a),
                balance_of(asset_ledger, trader_b),
                balance_of(quote_ledger, trader_a),
                balance_of(quote_ledger, trader_b),
                balance_of(asset_ledger, seller),
                balance_of(quote_ledger, seller),
            )
        };

        let out_a_first = run_with_order(false);
        let out_b_first = run_with_order(true);
        assert_eq!(
            out_a_first, out_b_first,
            "intra-block tx ordering must have zero effect on fills or balances"
        );
        // Each buyer receives exactly floor(101 * 100 / 200) = 50 units (total 100 units matched)
        assert_eq!(out_a_first.0, 50);
        assert_eq!(out_a_first.1, 50);
        assert_eq!(out_a_first.5, 1_000); // seller received 100 * $10 = $1,000
    }

    #[test]
    fn ask_side_cohort_prorata_multi_block_resting_carryover_and_order_cancellation() {
        mock::reset();
        let reg = [0x10; 20];
        let asset_ledger = [0x20; 20];
        let quote_ledger = [0x30; 20];
        let dex = [0x40; 20];
        let escrow_id = [0x90; 20];

        let seller_early = [0xB1; 20];
        let seller_same_1 = [0xB2; 20];
        let seller_same_2 = [0xB3; 20];
        let seller_low_px = [0xB4; 20];
        let buyer_1 = [0xA1; 20];
        let buyer_2 = [0xA2; 20];

        mock::register_hps(reg, sim_ledgers::reg_dispatch);
        mock::register_hps(asset_ledger, sim_ledgers::ledger_dispatch);
        mock::register_hps(quote_ledger, sim_ledgers::ledger_dispatch);
        mock::register_hps(dex, dispatch_calldata);

        let init_cd = CallEncoder::<160>::new(const {
            selector("initialize(address,address,address,address)")
        })
        .push_address(&reg)
        .push_address(&asset_ledger)
        .push_address(&quote_ledger)
        .push_address(&escrow_id);
        mock::transact_as(buyer_1, dex, init_cd.as_slice()).unwrap();

        seed_balance(asset_ledger, seller_early, 1_000);
        seed_balance(asset_ledger, seller_same_1, 1_000);
        seed_balance(asset_ledger, seller_same_2, 1_000);
        seed_balance(asset_ledger, seller_low_px, 1_000);
        seed_balance(quote_ledger, buyer_1, 100_000);
        seed_balance(quote_ledger, buyer_2, 100_000);

        // Block 20: `seller_early` places Ask @ $20 for 100 units
        mock::set_block_number(20);
        let a1 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(20)
            .push_u64(100);
        mock::transact_as(seller_early, dex, a1.as_slice()).unwrap();

        // Block 21:
        //   - `seller_same_1` places Ask @ $20 for 100 units (blk 21)
        //   - `seller_same_2` places Ask @ $20 for 300 units (blk 21)
        //   - `seller_low_px` places Ask @ $18 for 50 units (blk 21, better/lower ask price!)
        //   - `buyer_1` places Bid @ $20 for 350 units (blk 21)
        mock::set_block_number(21);
        let a2 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(20)
            .push_u64(100);
        mock::transact_as(seller_same_1, dex, a2.as_slice()).unwrap();

        let a3 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(20)
            .push_u64(300);
        mock::transact_as(seller_same_2, dex, a3.as_slice()).unwrap();

        let a4 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(18)
            .push_u64(50);
        mock::transact_as(seller_low_px, dex, a4.as_slice()).unwrap();

        let b1 = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(20)
            .push_u64(350);
        mock::transact_as(buyer_1, dex, b1.as_slice()).unwrap();

        // Block 22: `matchBlock()` clears 350 units @ P* = $20:
        //   - `seller_low_px` (Ask @ $18, blk 21, qty 50) -> 100% fill (50 units @ $20 = $1,000!)
        //   - `seller_early` (Ask @ $20, blk 20, qty 100) -> 100% fill (100 units @ $20 = $2,000!)
        //   - Marginal Ask cohort `(price = $20, block = 21)` has `seller_same_1` (100) + `seller_same_2` (300) = 400
        //     competing for remaining 200 units -> pro-rated 50% each:
        //       * `seller_same_1`: 50 filled ($1,000), 50 remaining on book
        //       * `seller_same_2`: 150 filled ($3,000), 150 remaining on book
        mock::set_block_number(22);
        let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
        let out22 = mock::transact_as(buyer_1, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(out22[24..32].try_into().unwrap()), 20);
        assert_eq!(u64::from_be_bytes(out22[56..64].try_into().unwrap()), 350);

        assert_eq!(balance_of(quote_ledger, seller_low_px), 1_000);
        assert_eq!(balance_of(quote_ledger, seller_early), 2_000);
        assert_eq!(balance_of(quote_ledger, seller_same_1), 1_000);
        assert_eq!(balance_of(quote_ledger, seller_same_2), 3_000);
        assert_eq!(balance_of(asset_ledger, buyer_1), 350);

        // Still in Block 22:
        //   - `seller_same_1` cancels their partially filled order #2 (refunds remaining 50 units -> 950 total)
        //   - `buyer_2` places a new Bid @ $20 for 150 units to buy `seller_same_2`'s resting 150 units
        let cancel_cd =
            CallEncoder::<64>::new(const { selector("cancelOrder(uint64)") }).push_u64(2);
        let cancel_out = mock::transact_as(seller_same_1, dex, cancel_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(cancel_out[24..32].try_into().unwrap()), 50);
        assert_eq!(balance_of(asset_ledger, seller_same_1), 950);

        let b2 = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(20)
            .push_u64(150);
        mock::transact_as(buyer_2, dex, b2.as_slice()).unwrap();

        // Block 23: `matchBlock()` ingests `buyer_2`'s Bid from Block 22 and matches it against
        // `seller_same_2`'s resting Ask from Block 21 (150 units @ $20)!
        mock::set_block_number(23);
        let out23 = mock::transact_as(buyer_2, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(out23[24..32].try_into().unwrap()), 20);
        assert_eq!(u64::from_be_bytes(out23[56..64].try_into().unwrap()), 150);
        assert_eq!(balance_of(asset_ledger, buyer_2), 150);
        assert_eq!(balance_of(quote_ledger, seller_same_2), 6_000);
    }
}
