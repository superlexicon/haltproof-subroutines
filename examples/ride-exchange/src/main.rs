//! # `ride-exchange` (`ride_exchange.wasm`) — Multi-Regime Discrete-Time AON Ride Service Futures Exchange
//!
//! Class II Multi-Parameter Haltproof Matching Engine built on `hps-sdk`:
//! 1. **Single-Metro Multi-Regime Price-Sorted Order Books (`Z = 6` Regimes)**:
//!    - Each Price Regime (`CBD`, `City Fringe`, `Changi/East`, `Remote`, `Jurong/West`, `Heartland`)
//!      maintains its own `AskBook` (`ask_per_km ASC`, FIFO) and `BidBook` (`bid_per_km DESC`, FIFO)
//!      backed by static arena AVL trees (`PriceLevelArena`) + intrusive doubly-linked order queues.
//!    - All $Z$ sub-books share **one atomic Driver Inventory pool**, preventing physical car
//!      double-booking while allowing border-adjacent drivers (`cross_border = true`) to serve
//!      neighboring regimes seamlessly.
//! 2. **"Meter Starts at Pickup" Billable Quantity (`Q_billed = trip_m`) + All-Or-Nothing (AON) Gate**:
//!    - Billable clean fare applies strictly to customer trip distance $L_{\text{trip}}$ (`from -> to`),
//!      excluding initial pickup approach $L_{\text{pickup}}$, so **lowest `ask_per_km` strictly equals
//!      lowest total customer fare**.
//!    - `L_pickup` acts as a hard physical feasibility & tie-breaking gate:
//!      `pickup_m <= min(rider.max_pickup_m, driver.max_pickup_m)` and
//!      `pickup_m + trip_m <= driver.max_distance_m` (All-Or-Nothing single-car sufficiency), with
//!      same-price ties broken by closest physical car (`min pickup_m`).
//! 3. **"Clean Rate vs. Dirty Invoice" Statutory Tolls & Destination Basis**:
//!    - Books match on clean per-km rates (`cents / km`), adding `remote_basis_cents` when
//!      `dest_regime == REGIME_REMOTE` and passing through statutory route tolls (`ERP` / `Airport`)
//!      as a separate invoice line item.
//! 4. **Resting-Maker Clearing Price & Physically-Settled Service Futures Escrow**:
//!    - Crossing orders execute at the **Resting Maker's** rate (`earlier seniority_block`).
//!    - Excess Rider margin is refunded immediately on `matchBlock()`, while the matched contract
//!      notional (`clean_fare + toll`) remains locked in `escrow_identity` on `AssetLedger` until
//!      the customer signs `completeRide(futuresId)` confirming physical ride completion!

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    require_valid_identity, ERR_ALREADY_EXECUTED_IN_BLOCK, ERR_INVALID_DEX_ORDER,
    ERR_NOT_ORDER_OWNER, ERR_ORDERBOOK_FULL, ERR_ORDER_ALREADY_CANCELLED, ERR_ORDER_NOT_FOUND,
};
use hps_sdk::spatial::singapore::{
    classify_sg_regime, default_sg_toll_cents, REGIME_REMOTE, SG_ADJACENT_MASKS, SG_COS_LAT_BPS,
    SG_REGIME_COUNT, SG_ROAD_FACTOR_BPS,
};
use hps_sdk::spatial::{compute_trip_fare_ceil, road_distance_m, GeoCoord};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

pub const NUM_REGIMES: usize = SG_REGIME_COUNT as usize; // 6
pub const MAX_PRICE_LEVELS_PER_BOOK: usize = 64;
pub const MAX_ACTIVE_ASKS: usize = 192;
pub const MAX_ACTIVE_BIDS: usize = 192;
pub const MAX_PENDING_ORDERS: usize = 128;

pub const DEMO_FAUCET_GRANT_CENTS: u64 = 25_000; // $250.00 SGD per claim
pub const CANCEL_GRACE_BLOCKS: u64 = 15;
pub const MAX_APPROACH_BREAK_FEE_CENTS: u64 = 300; // $3.00 SGD cap

const NONE_LVL: u16 = 0;
const NONE_ORD: u64 = 0;

pub const SIDE_BID: u8 = 1;
pub const SIDE_ASK: u8 = 2;

pub const ORD_STATUS_PENDING: u8 = 0;
pub const ORD_STATUS_ACTIVE: u8 = 1;
pub const ORD_STATUS_MATCHED: u8 = 2;
pub const ORD_STATUS_CANCELLED: u8 = 3;

pub const FUT_STATUS_MATCHED: u8 = 1;
pub const FUT_STATUS_IN_PROGRESS: u8 = 2;
pub const FUT_STATUS_SETTLED: u8 = 3;
pub const FUT_STATUS_CANCELLED: u8 = 4;

pub const MAKER_RIDER: u8 = 1;
pub const MAKER_DRIVER: u8 = 2;

pub const ERR_ACTOR_BUSY: i32 = -41;
pub const ERR_INVALID_COORDS: i32 = -42;
pub const ERR_FUTURES_NOT_FOUND: i32 = -43;
pub const ERR_FUTURES_WRONG_STATE: i32 = -44;
pub const ERR_NOT_FUTURES_PARTY: i32 = -45;
pub const ERR_FAUCET_DEPLETED: i32 = -46;

const EV_METRO_INITIALIZED: [u8; 32] =
    event_topic("RideExchangeInitialized(address,address,address)");
const EV_DRIVER_ASK_POSTED: [u8; 32] =
    event_topic("DriverAskPosted(uint64,address,uint64,uint64,uint64)");
const EV_DRIVER_LOC_UPDATED: [u8; 32] =
    event_topic("DriverLocationUpdated(uint64,address,uint64,uint64)");
const EV_RIDER_BID_POSTED: [u8; 32] =
    event_topic("RiderBidPosted(uint64,address,uint64,uint64,uint64)");
const EV_ORDER_CANCELLED: [u8; 32] =
    event_topic("RideOrderCancelled(uint64,address,uint64)");
const EV_RIDE_MATCHED: [u8; 32] =
    event_topic("RideFuturesMatched(uint64,address,address,uint64,uint64)");
const EV_RIDE_PICKUP: [u8; 32] =
    event_topic("RidePickupConfirmed(uint64,address,uint64)");
const EV_RIDE_COMPLETED: [u8; 32] =
    event_topic("RideFuturesSettled(uint64,address,address,uint64)");
const EV_RIDE_CANCELLED: [u8; 32] =
    event_topic("RideFuturesCancelled(uint64,address,uint64,uint64)");
const EV_BLOCK_MATCHED: [u8; 32] =
    event_topic("RideBlockMatched(uint64,uint64,uint64,uint64)");

const KEY_INIT: &[u8] = b"rx:init";
const KEY_ADMIN: &[u8] = b"rx:admin";
const KEY_REGISTRY: &[u8] = b"rx:reg";
const KEY_QUOTE_LEDGER: &[u8] = b"rx:quote";
const KEY_ESCROW_ID: &[u8] = b"rx:escrow";
const KEY_METRO_NAME: &[u8] = b"rx:name";
const KEY_COS_LAT_BPS: &[u8] = b"rx:cos_bps";
const KEY_ROAD_BPS: &[u8] = b"rx:road_bps";

const KEY_LOCKED_ESCROW: &[u8] = b"rx:locked";
const KEY_ORDER_SEQ: &[u8] = b"rx:ord_seq";
const KEY_FUTURES_SEQ: &[u8] = b"rx:fut_seq";
const KEY_SETTLED_CNT: &[u8] = b"rx:stl_cnt";
const KEY_SETTLED_VOL: &[u8] = b"rx:stl_vol";

const KEY_PENDING_HEAD: &[u8] = b"rx:p_head";
const KEY_PENDING_TAIL: &[u8] = b"rx:p_tail";
const KEY_PENDING_CNT: &[u8] = b"rx:p_cnt";
const KEY_ACTIVE_ASK_CNT: &[u8] = b"rx:aa_cnt";
const KEY_ACTIVE_BID_CNT: &[u8] = b"rx:ab_cnt";

const KEY_LAST_MATCH_SET: &[u8] = b"rx:lm_set";
const KEY_LAST_MATCH_BLK: &[u8] = b"rx:lm_blk";

const TREE_HEADER_BYTES: usize = 12;
const LEVEL_NODE_BYTES: usize = 48;
const MAX_TREE_BYTES: usize = TREE_HEADER_BYTES + MAX_PRICE_LEVELS_PER_BOOK * LEVEL_NODE_BYTES;

const ORDER_STORAGE_BYTES: usize = 144;
const FUTURES_STORAGE_BYTES: usize = 148;

static mut VIEW_SCRATCH: [u8; 65_536] = [0u8; 65_536];
static mut MATCH_BID_IDS: [u64; MAX_ACTIVE_BIDS] = [0u64; MAX_ACTIVE_BIDS];
static mut MATCH_BID_RATES: [u64; MAX_ACTIVE_BIDS] = [0u64; MAX_ACTIVE_BIDS];
static mut MATCH_BID_BLKS: [u64; MAX_ACTIVE_BIDS] = [0u64; MAX_ACTIVE_BIDS];

hps_entry! {
    "initialize(address,address,address,string,uint64,uint64)" => handle_initialize,
    "setToll(uint64,uint64,uint64)"                            => handle_set_toll,
    "claimDemoMargin()"                                        => handle_claim_demo_margin,
    "upsertDriverAsk(uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)" => handle_upsert_driver_ask,
    "updateDriverLocation(uint64,uint64)"                      => handle_update_driver_location,
    "cancelDriverAsk()"                                        => handle_cancel_driver_ask,
    "postRiderBid(uint64,uint64,uint64,uint64,uint64,uint64)"  => handle_post_rider_bid,
    "cancelRiderBid(uint64)"                                   => handle_cancel_rider_bid,
    "matchBlock()"                                             => handle_match_block,
    "confirmPickup(uint64)"                                    => handle_confirm_pickup,
    "completeRide(uint64)"                                     => handle_complete_ride,
    "cancelRideFutures(uint64)"                                => handle_cancel_ride_futures,
    "getMetroOverview()"                                       => handle_get_metro_overview,
    "getActiveBookSnapshot()"                                  => handle_get_active_book_snapshot,
    "getFuturesSlice(uint64,uint64)"                           => handle_get_futures_slice,
    "getFutures(uint64)"                                       => handle_get_futures,
    "getActorState(address)"                                   => handle_get_actor_state,
    "quoteTripPreview(uint64,uint64,uint64,uint64)"            => handle_quote_trip_preview,
    "quoteLedger()"                                            => handle_quote_ledger,
    "escrowIdentity()"                                         => handle_escrow_identity,
    "identityRegistry()"                                       => handle_identity_registry,
    "lastMatchedBlock()"                                       => handle_last_matched_block,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PriceLevelNode {
    pub price: u64,
    pub total_qty: u64,
    pub head_order_id: u64,
    pub tail_order_id: u64,
    pub left: u16,
    pub right: u16,
    pub parent: u16,
    pub prev_better: u16,
    pub next_worse: u16,
    pub order_count: u16,
    pub height: u8,
}

pub struct PriceLevelArena {
    pub is_bid: bool,
    pub root: u16,
    pub best_head: u16,
    pub worst_tail: u16,
    pub active_levels: u16,
    pub high_water: u16,
    pub free_head: u16,
    pub nodes: [PriceLevelNode; MAX_PRICE_LEVELS_PER_BOOK],
}

impl PriceLevelArena {
    pub fn new(is_bid: bool) -> Self {
        Self {
            is_bid,
            root: NONE_LVL,
            best_head: NONE_LVL,
            worst_tail: NONE_LVL,
            active_levels: 0,
            high_water: 0,
            free_head: NONE_LVL,
            nodes: [PriceLevelNode::default(); MAX_PRICE_LEVELS_PER_BOOK],
        }
    }

    #[inline]
    pub fn is_better(&self, a: u64, b: u64) -> bool {
        if self.is_bid {
            a > b
        } else {
            a < b
        }
    }

    #[inline]
    pub fn node(&self, idx: u16) -> &PriceLevelNode {
        &self.nodes[(idx - 1) as usize]
    }

    #[inline]
    pub fn node_mut(&mut self, idx: u16) -> &mut PriceLevelNode {
        &mut self.nodes[(idx - 1) as usize]
    }

    #[inline]
    fn height_of(&self, idx: u16) -> i16 {
        if idx == NONE_LVL {
            0
        } else {
            self.node(idx).height as i16
        }
    }

    #[inline]
    fn update_height(&mut self, idx: u16) {
        let hl = self.height_of(self.node(idx).left);
        let hr = self.height_of(self.node(idx).right);
        self.node_mut(idx).height = (1 + if hl > hr { hl } else { hr }) as u8;
    }

    #[inline]
    fn balance_factor(&self, idx: u16) -> i16 {
        self.height_of(self.node(idx).left) - self.height_of(self.node(idx).right)
    }

    fn alloc_node(&mut self, price: u64) -> Result<u16, i32> {
        let idx = if self.free_head != NONE_LVL {
            let recycled = self.free_head;
            self.free_head = self.node(recycled).next_worse;
            recycled
        } else {
            if (self.high_water as usize) >= MAX_PRICE_LEVELS_PER_BOOK {
                return Err(ERR_ORDERBOOK_FULL);
            }
            self.high_water += 1;
            self.high_water
        };
        *self.node_mut(idx) = PriceLevelNode {
            price,
            height: 1,
            ..PriceLevelNode::default()
        };
        self.active_levels += 1;
        Ok(idx)
    }

    fn free_node(&mut self, idx: u16) {
        let next_free = self.free_head;
        *self.node_mut(idx) = PriceLevelNode {
            next_worse: next_free,
            height: 0,
            ..PriceLevelNode::default()
        };
        self.free_head = idx;
        self.active_levels = self.active_levels.saturating_sub(1);
        if self.active_levels == 0 {
            self.root = NONE_LVL;
            self.best_head = NONE_LVL;
            self.worst_tail = NONE_LVL;
            self.high_water = 0;
            self.free_head = NONE_LVL;
        }
    }

    pub fn find_price(&self, price: u64) -> u16 {
        let mut cur = self.root;
        let mut guard = 0usize;
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS_PER_BOOK {
            let cur_px = self.node(cur).price;
            if price == cur_px {
                return cur;
            }
            cur = if self.is_better(price, cur_px) {
                self.node(cur).left
            } else {
                self.node(cur).right
            };
            guard += 1;
        }
        NONE_LVL
    }

    pub fn find_or_insert(&mut self, price: u64) -> Result<u16, i32> {
        if self.root == NONE_LVL {
            let idx = self.alloc_node(price)?;
            self.root = idx;
            self.best_head = idx;
            self.worst_tail = idx;
            return Ok(idx);
        }

        let mut cur = self.root;
        let mut parent = NONE_LVL;
        let mut go_left = false;
        let mut guard = 0usize;
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS_PER_BOOK {
            let cur_px = self.node(cur).price;
            if price == cur_px {
                return Ok(cur);
            }
            parent = cur;
            if self.is_better(price, cur_px) {
                go_left = true;
                cur = self.node(cur).left;
            } else {
                go_left = false;
                cur = self.node(cur).right;
            }
            guard += 1;
        }

        let new_idx = self.alloc_node(price)?;
        self.node_mut(new_idx).parent = parent;
        if go_left {
            self.node_mut(parent).left = new_idx;
            let prev = self.node(parent).prev_better;
            self.node_mut(new_idx).prev_better = prev;
            self.node_mut(new_idx).next_worse = parent;
            self.node_mut(parent).prev_better = new_idx;
            if prev != NONE_LVL {
                self.node_mut(prev).next_worse = new_idx;
            } else {
                self.best_head = new_idx;
            }
        } else {
            self.node_mut(parent).right = new_idx;
            let next = self.node(parent).next_worse;
            self.node_mut(new_idx).prev_better = parent;
            self.node_mut(new_idx).next_worse = next;
            self.node_mut(parent).next_worse = new_idx;
            if next != NONE_LVL {
                self.node_mut(next).prev_better = new_idx;
            } else {
                self.worst_tail = new_idx;
            }
        }
        self.rebalance_up(parent);
        Ok(new_idx)
    }

    pub fn remove_node(&mut self, z: u16) {
        if z == NONE_LVL {
            return;
        }
        let prev = self.node(z).prev_better;
        let next = self.node(z).next_worse;
        if prev != NONE_LVL {
            self.node_mut(prev).next_worse = next;
        } else {
            self.best_head = next;
        }
        if next != NONE_LVL {
            self.node_mut(next).prev_better = prev;
        } else {
            self.worst_tail = prev;
        }

        let rebalance_start: u16;
        let z_left = self.node(z).left;
        let z_right = self.node(z).right;

        if z_left == NONE_LVL {
            rebalance_start = self.node(z).parent;
            self.transplant(z, z_right);
        } else if z_right == NONE_LVL {
            rebalance_start = self.node(z).parent;
            self.transplant(z, z_left);
        } else {
            let mut y = z_right;
            let mut guard = 0usize;
            while self.node(y).left != NONE_LVL && guard < MAX_PRICE_LEVELS_PER_BOOK {
                y = self.node(y).left;
                guard += 1;
            }
            let y_right = self.node(y).right;
            if self.node(y).parent == z {
                rebalance_start = y;
            } else {
                rebalance_start = self.node(y).parent;
                self.transplant(y, y_right);
                let zr = self.node(z).right;
                self.node_mut(y).right = zr;
                if zr != NONE_LVL {
                    self.node_mut(zr).parent = y;
                }
            }
            self.transplant(z, y);
            let zl = self.node(z).left;
            self.node_mut(y).left = zl;
            if zl != NONE_LVL {
                self.node_mut(zl).parent = y;
            }
            self.update_height(y);
        }

        self.free_node(z);
        if self.active_levels > 0 && rebalance_start != NONE_LVL {
            self.rebalance_up(rebalance_start);
        }
    }

    fn transplant(&mut self, u: u16, v: u16) {
        let up = self.node(u).parent;
        if up == NONE_LVL {
            self.root = v;
        } else if self.node(up).left == u {
            self.node_mut(up).left = v;
        } else {
            self.node_mut(up).right = v;
        }
        if v != NONE_LVL {
            self.node_mut(v).parent = up;
        }
    }

    fn rotate_left(&mut self, x: u16) -> u16 {
        let y = self.node(x).right;
        let b = self.node(y).left;
        let xp = self.node(x).parent;

        self.node_mut(x).right = b;
        if b != NONE_LVL {
            self.node_mut(b).parent = x;
        }
        self.node_mut(y).parent = xp;
        if xp == NONE_LVL {
            self.root = y;
        } else if self.node(xp).left == x {
            self.node_mut(xp).left = y;
        } else {
            self.node_mut(xp).right = y;
        }
        self.node_mut(y).left = x;
        self.node_mut(x).parent = y;

        self.update_height(x);
        self.update_height(y);
        y
    }

    fn rotate_right(&mut self, x: u16) -> u16 {
        let y = self.node(x).left;
        let b = self.node(y).right;
        let xp = self.node(x).parent;

        self.node_mut(x).left = b;
        if b != NONE_LVL {
            self.node_mut(b).parent = x;
        }
        self.node_mut(y).parent = xp;
        if xp == NONE_LVL {
            self.root = y;
        } else if self.node(xp).left == x {
            self.node_mut(xp).left = y;
        } else {
            self.node_mut(xp).right = y;
        }
        self.node_mut(y).right = x;
        self.node_mut(x).parent = y;

        self.update_height(x);
        self.update_height(y);
        y
    }

    fn rebalance_up(&mut self, mut cur: u16) {
        let mut guard = 0usize;
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS_PER_BOOK {
            self.update_height(cur);
            let bf = self.balance_factor(cur);
            let next_parent = if bf > 1 {
                let left = self.node(cur).left;
                if self.balance_factor(left) < 0 {
                    self.rotate_left(left);
                }
                let sub_root = self.rotate_right(cur);
                self.node(sub_root).parent
            } else if bf < -1 {
                let right = self.node(cur).right;
                if self.balance_factor(right) > 0 {
                    self.rotate_right(right);
                }
                let sub_root = self.rotate_left(cur);
                self.node(sub_root).parent
            } else {
                self.node(cur).parent
            };
            cur = next_parent;
            guard += 1;
        }
    }
}

/// Unified Order Record (`144` bytes) for both Driver Asks (`SIDE_ASK`) and Customer Bids (`SIDE_BID`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RideOrder {
    pub order_id: u64,
    pub actor: [u8; 20],
    pub side: u8,
    pub status: u8,
    pub orig_regime: u8,
    pub dest_regime: u8,
    pub cross_border: u8,
    pub dest_mask: u32,
    pub lat_e6: i32,
    pub lon_e6: i32,
    pub to_lat_e6: i32,
    pub to_lon_e6: i32,
    pub rate_per_km_cents: u64,
    pub remote_basis_cents: u64,
    pub max_distance_m: u64, // For Ask: max total driven m; For Bid: computed trip_m
    pub max_pickup_m: u64,
    pub escrowed_cents: u64,
    pub toll_cents: u64,
    pub seniority_block: u64,
    pub prev_order_id: u64,
    pub next_order_id: u64,
}

/// Physically-Settled Ride Service Futures Contract (`148` bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RideFuturesContract {
    pub futures_id: u64,
    pub bid_order_id: u64,
    pub ask_order_id: u64,
    pub rider: [u8; 20],
    pub driver: [u8; 20],
    pub status: u8,
    pub orig_regime: u8,
    pub dest_regime: u8,
    pub maker_side: u8,
    pub driver_start_lat_e6: i32,
    pub driver_start_lon_e6: i32,
    pub from_lat_e6: i32,
    pub from_lon_e6: i32,
    pub to_lat_e6: i32,
    pub to_lon_e6: i32,
    pub pickup_m: u64,
    pub trip_m: u64,
    pub clearing_rate_cents: u64,
    pub clean_fare_cents: u64,
    pub toll_cents: u64,
    pub matched_block: u64,
    pub settled_block: u64,
}

#[inline]
fn decode_coord_u64(v: u64) -> i32 {
    (v as u32) as i32
}

#[inline]
fn u64_topic(val: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[24..32].copy_from_slice(&val.to_be_bytes());
    t
}

#[inline]
fn addr_topic(addr: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..32].copy_from_slice(addr);
    t
}

fn tree_key(is_bid: bool, regime: u8) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(if is_bid { b"rx:bt:" } else { b"rx:at:" })
        .push(&[regime])
}

fn regime_stat_key(prefix: &[u8], regime: u8) -> KeyBuilder<32> {
    KeyBuilder::<32>::new().push(prefix).push(&[regime])
}

fn toll_key(orig: u8, dest: u8) -> KeyBuilder<32> {
    KeyBuilder::<32>::new()
        .push(b"rx:toll:")
        .push(&[orig, dest])
}

fn get_toll_cents(orig: u8, dest: u8) -> u64 {
    let k = toll_key(orig, dest);
    let mut buf = [0u8; 8];
    match storage::get_into(k.as_slice(), &mut buf) {
        Some(8) => u64::from_le_bytes(buf),
        _ => default_sg_toll_cents(orig, dest),
    }
}

fn load_tree(is_bid: bool, regime: u8) -> PriceLevelArena {
    let mut tree = PriceLevelArena::new(is_bid);
    let mut buf = [0u8; MAX_TREE_BYTES];
    let k = tree_key(is_bid, regime);
    let Some(len) = storage::get_into(k.as_slice(), &mut buf) else {
        return tree;
    };
    if len < TREE_HEADER_BYTES {
        return tree;
    }
    tree.root = u16::from_le_bytes([buf[0], buf[1]]);
    tree.best_head = u16::from_le_bytes([buf[2], buf[3]]);
    tree.worst_tail = u16::from_le_bytes([buf[4], buf[5]]);
    tree.active_levels = u16::from_le_bytes([buf[6], buf[7]]);
    tree.high_water = u16::from_le_bytes([buf[8], buf[9]]);
    tree.free_head = u16::from_le_bytes([buf[10], buf[11]]);

    let hw = (tree.high_water as usize).min(MAX_PRICE_LEVELS_PER_BOOK);
    tree.high_water = hw as u16;
    let mut i = 0usize;
    while i < hw {
        let off = TREE_HEADER_BYTES + i * LEVEL_NODE_BYTES;
        if off + LEVEL_NODE_BYTES > len {
            break;
        }
        let s = &buf[off..off + LEVEL_NODE_BYTES];
        tree.nodes[i] = PriceLevelNode {
            price: u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
            total_qty: u64::from_le_bytes([s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15]]),
            head_order_id: u64::from_le_bytes([
                s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23],
            ]),
            tail_order_id: u64::from_le_bytes([
                s[24], s[25], s[26], s[27], s[28], s[29], s[30], s[31],
            ]),
            left: u16::from_le_bytes([s[32], s[33]]),
            right: u16::from_le_bytes([s[34], s[35]]),
            parent: u16::from_le_bytes([s[36], s[37]]),
            prev_better: u16::from_le_bytes([s[38], s[39]]),
            next_worse: u16::from_le_bytes([s[40], s[41]]),
            order_count: u16::from_le_bytes([s[42], s[43]]),
            height: s[44],
        };
        i += 1;
    }
    tree
}

fn store_tree(is_bid: bool, regime: u8, tree: &PriceLevelArena) {
    let k = tree_key(is_bid, regime);
    if tree.active_levels == 0 {
        storage::set(k.as_slice(), &[]);
        return;
    }
    let hw = (tree.high_water as usize).min(MAX_PRICE_LEVELS_PER_BOOK);
    let total_len = TREE_HEADER_BYTES + hw * LEVEL_NODE_BYTES;
    let mut buf = [0u8; MAX_TREE_BYTES];
    buf[0..2].copy_from_slice(&tree.root.to_le_bytes());
    buf[2..4].copy_from_slice(&tree.best_head.to_le_bytes());
    buf[4..6].copy_from_slice(&tree.worst_tail.to_le_bytes());
    buf[6..8].copy_from_slice(&tree.active_levels.to_le_bytes());
    buf[8..10].copy_from_slice(&(hw as u16).to_le_bytes());
    buf[10..12].copy_from_slice(&tree.free_head.to_le_bytes());

    let mut i = 0usize;
    while i < hw {
        let n = &tree.nodes[i];
        let off = TREE_HEADER_BYTES + i * LEVEL_NODE_BYTES;
        let d = &mut buf[off..off + LEVEL_NODE_BYTES];
        d[0..8].copy_from_slice(&n.price.to_le_bytes());
        d[8..16].copy_from_slice(&n.total_qty.to_le_bytes());
        d[16..24].copy_from_slice(&n.head_order_id.to_le_bytes());
        d[24..32].copy_from_slice(&n.tail_order_id.to_le_bytes());
        d[32..34].copy_from_slice(&n.left.to_le_bytes());
        d[34..36].copy_from_slice(&n.right.to_le_bytes());
        d[36..38].copy_from_slice(&n.parent.to_le_bytes());
        d[38..40].copy_from_slice(&n.prev_better.to_le_bytes());
        d[40..42].copy_from_slice(&n.next_worse.to_le_bytes());
        d[42..44].copy_from_slice(&n.order_count.to_le_bytes());
        d[44] = n.height;
        i += 1;
    }
    storage::set(k.as_slice(), &buf[..total_len]);
}

fn store_order(ord: &RideOrder) {
    let key = KeyBuilder::<32>::new()
        .push(b"rx:ord:")
        .push_u64_be(ord.order_id);
    let mut b = [0u8; ORDER_STORAGE_BYTES];
    b[0..8].copy_from_slice(&ord.order_id.to_le_bytes());
    b[8..28].copy_from_slice(&ord.actor);
    b[28] = ord.side;
    b[29] = ord.status;
    b[30] = ord.orig_regime;
    b[31] = ord.dest_regime;
    b[32] = ord.cross_border;
    b[36..40].copy_from_slice(&ord.dest_mask.to_le_bytes());
    b[40..44].copy_from_slice(&ord.lat_e6.to_le_bytes());
    b[44..48].copy_from_slice(&ord.lon_e6.to_le_bytes());
    b[48..52].copy_from_slice(&ord.to_lat_e6.to_le_bytes());
    b[52..56].copy_from_slice(&ord.to_lon_e6.to_le_bytes());
    b[56..64].copy_from_slice(&ord.rate_per_km_cents.to_le_bytes());
    b[64..72].copy_from_slice(&ord.remote_basis_cents.to_le_bytes());
    b[72..80].copy_from_slice(&ord.max_distance_m.to_le_bytes());
    b[80..88].copy_from_slice(&ord.max_pickup_m.to_le_bytes());
    b[88..96].copy_from_slice(&ord.escrowed_cents.to_le_bytes());
    b[96..104].copy_from_slice(&ord.toll_cents.to_le_bytes());
    b[104..112].copy_from_slice(&ord.seniority_block.to_le_bytes());
    b[112..120].copy_from_slice(&ord.prev_order_id.to_le_bytes());
    b[120..128].copy_from_slice(&ord.next_order_id.to_le_bytes());
    storage::set(key.as_slice(), &b);
}

fn load_order(order_id: u64) -> Option<RideOrder> {
    if order_id == NONE_ORD {
        return None;
    }
    let key = KeyBuilder::<32>::new()
        .push(b"rx:ord:")
        .push_u64_be(order_id);
    let mut b = [0u8; ORDER_STORAGE_BYTES];
    if storage::get_into(key.as_slice(), &mut b)? < ORDER_STORAGE_BYTES {
        return None;
    }
    let mut actor = [0u8; 20];
    actor.copy_from_slice(&b[8..28]);
    Some(RideOrder {
        order_id: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        actor,
        side: b[28],
        status: b[29],
        orig_regime: b[30],
        dest_regime: b[31],
        cross_border: b[32],
        dest_mask: u32::from_le_bytes([b[36], b[37], b[38], b[39]]),
        lat_e6: i32::from_le_bytes([b[40], b[41], b[42], b[43]]),
        lon_e6: i32::from_le_bytes([b[44], b[45], b[46], b[47]]),
        to_lat_e6: i32::from_le_bytes([b[48], b[49], b[50], b[51]]),
        to_lon_e6: i32::from_le_bytes([b[52], b[53], b[54], b[55]]),
        rate_per_km_cents: u64::from_le_bytes([
            b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63],
        ]),
        remote_basis_cents: u64::from_le_bytes([
            b[64], b[65], b[66], b[67], b[68], b[69], b[70], b[71],
        ]),
        max_distance_m: u64::from_le_bytes([
            b[72], b[73], b[74], b[75], b[76], b[77], b[78], b[79],
        ]),
        max_pickup_m: u64::from_le_bytes([b[80], b[81], b[82], b[83], b[84], b[85], b[86], b[87]]),
        escrowed_cents: u64::from_le_bytes([
            b[88], b[89], b[90], b[91], b[92], b[93], b[94], b[95],
        ]),
        toll_cents: u64::from_le_bytes([
            b[96], b[97], b[98], b[99], b[100], b[101], b[102], b[103],
        ]),
        seniority_block: u64::from_le_bytes([
            b[104], b[105], b[106], b[107], b[108], b[109], b[110], b[111],
        ]),
        prev_order_id: u64::from_le_bytes([
            b[112], b[113], b[114], b[115], b[116], b[117], b[118], b[119],
        ]),
        next_order_id: u64::from_le_bytes([
            b[120], b[121], b[122], b[123], b[124], b[125], b[126], b[127],
        ]),
    })
}

fn store_futures(f: &RideFuturesContract) {
    let key = KeyBuilder::<32>::new()
        .push(b"rx:fut:")
        .push_u64_be(f.futures_id);
    let mut b = [0u8; FUTURES_STORAGE_BYTES];
    encode_futures_be(f, &mut b);
    storage::set(key.as_slice(), &b);
}

fn load_futures(futures_id: u64) -> Option<RideFuturesContract> {
    if futures_id == 0 {
        return None;
    }
    let key = KeyBuilder::<32>::new()
        .push(b"rx:fut:")
        .push_u64_be(futures_id);
    let mut b = [0u8; FUTURES_STORAGE_BYTES];
    if storage::get_into(key.as_slice(), &mut b)? < FUTURES_STORAGE_BYTES {
        return None;
    }
    Some(decode_futures_be(&b))
}

fn encode_futures_be(f: &RideFuturesContract, b: &mut [u8; FUTURES_STORAGE_BYTES]) {
    b[0..8].copy_from_slice(&f.futures_id.to_be_bytes());
    b[8..16].copy_from_slice(&f.bid_order_id.to_be_bytes());
    b[16..24].copy_from_slice(&f.ask_order_id.to_be_bytes());
    b[24..44].copy_from_slice(&f.rider);
    b[44..64].copy_from_slice(&f.driver);
    b[64] = f.status;
    b[65] = f.orig_regime;
    b[66] = f.dest_regime;
    b[67] = f.maker_side;
    b[68..72].copy_from_slice(&f.driver_start_lat_e6.to_be_bytes());
    b[72..76].copy_from_slice(&f.driver_start_lon_e6.to_be_bytes());
    b[76..80].copy_from_slice(&f.from_lat_e6.to_be_bytes());
    b[80..84].copy_from_slice(&f.from_lon_e6.to_be_bytes());
    b[84..88].copy_from_slice(&f.to_lat_e6.to_be_bytes());
    b[88..92].copy_from_slice(&f.to_lon_e6.to_be_bytes());
    b[92..100].copy_from_slice(&f.pickup_m.to_be_bytes());
    b[100..108].copy_from_slice(&f.trip_m.to_be_bytes());
    b[108..116].copy_from_slice(&f.clearing_rate_cents.to_be_bytes());
    b[116..124].copy_from_slice(&f.clean_fare_cents.to_be_bytes());
    b[124..132].copy_from_slice(&f.toll_cents.to_be_bytes());
    b[132..140].copy_from_slice(&f.matched_block.to_be_bytes());
    b[140..148].copy_from_slice(&f.settled_block.to_be_bytes());
}

fn decode_futures_be(b: &[u8; FUTURES_STORAGE_BYTES]) -> RideFuturesContract {
    let mut rider = [0u8; 20];
    let mut driver = [0u8; 20];
    rider.copy_from_slice(&b[24..44]);
    driver.copy_from_slice(&b[44..64]);
    RideFuturesContract {
        futures_id: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        bid_order_id: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        ask_order_id: u64::from_be_bytes([
            b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
        ]),
        rider,
        driver,
        status: b[64],
        orig_regime: b[65],
        dest_regime: b[66],
        maker_side: b[67],
        driver_start_lat_e6: i32::from_be_bytes([b[68], b[69], b[70], b[71]]),
        driver_start_lon_e6: i32::from_be_bytes([b[72], b[73], b[74], b[75]]),
        from_lat_e6: i32::from_be_bytes([b[76], b[77], b[78], b[79]]),
        from_lon_e6: i32::from_be_bytes([b[80], b[81], b[82], b[83]]),
        to_lat_e6: i32::from_be_bytes([b[84], b[85], b[86], b[87]]),
        to_lon_e6: i32::from_be_bytes([b[88], b[89], b[90], b[91]]),
        pickup_m: u64::from_be_bytes([b[92], b[93], b[94], b[95], b[96], b[97], b[98], b[99]]),
        trip_m: u64::from_be_bytes([
            b[100], b[101], b[102], b[103], b[104], b[105], b[106], b[107],
        ]),
        clearing_rate_cents: u64::from_be_bytes([
            b[108], b[109], b[110], b[111], b[112], b[113], b[114], b[115],
        ]),
        clean_fare_cents: u64::from_be_bytes([
            b[116], b[117], b[118], b[119], b[120], b[121], b[122], b[123],
        ]),
        toll_cents: u64::from_be_bytes([
            b[124], b[125], b[126], b[127], b[128], b[129], b[130], b[131],
        ]),
        matched_block: u64::from_be_bytes([
            b[132], b[133], b[134], b[135], b[136], b[137], b[138], b[139],
        ]),
        settled_block: u64::from_be_bytes([
            b[140], b[141], b[142], b[143], b[144], b[145], b[146], b[147],
        ]),
    }
}

fn actor_ask_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:drv_ask:").push(actor)
}
fn actor_bid_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:rdr_bid:").push(actor)
}
fn actor_drv_fut_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:drv_fut:").push(actor)
}
fn actor_rdr_fut_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:rdr_fut:").push(actor)
}
fn actor_rides_done_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:done:").push(actor)
}
fn actor_earned_key(actor: &[u8; 20]) -> KeyBuilder<48> {
    KeyBuilder::<48>::new().push(b"rx:earn:").push(actor)
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

fn call_balance_of(ledger: &[u8; 20], holder: &[u8; 20]) -> Result<u64, i32> {
    let cd = CallEncoder::<64>::new(const { selector("balanceOf(address)") }).push_address(holder);
    call::call_u64(ledger, cd.as_slice())
}

fn append_to_pending(ord: &mut RideOrder) {
    let old_tail = storage::get_u64(KEY_PENDING_TAIL);
    ord.status = ORD_STATUS_PENDING;
    ord.prev_order_id = old_tail;
    ord.next_order_id = NONE_ORD;

    if old_tail != NONE_ORD {
        if let Some(mut tail_ord) = load_order(old_tail) {
            tail_ord.next_order_id = ord.order_id;
            store_order(&tail_ord);
        }
    } else {
        storage::set_u64(KEY_PENDING_HEAD, ord.order_id);
    }
    store_order(ord);
    storage::set_u64(KEY_PENDING_TAIL, ord.order_id);
    storage::set_u64(KEY_PENDING_CNT, storage::get_u64(KEY_PENDING_CNT) + 1);
}

fn unlink_from_pending(ord: &RideOrder) {
    let prev_id = ord.prev_order_id;
    let next_id = ord.next_order_id;
    if prev_id != NONE_ORD {
        if let Some(mut p_ord) = load_order(prev_id) {
            p_ord.next_order_id = next_id;
            store_order(&p_ord);
        }
    } else {
        storage::set_u64(KEY_PENDING_HEAD, next_id);
    }

    if next_id != NONE_ORD {
        if let Some(mut n_ord) = load_order(next_id) {
            n_ord.prev_order_id = prev_id;
            store_order(&n_ord);
        }
    } else {
        storage::set_u64(KEY_PENDING_TAIL, prev_id);
    }
    storage::set_u64(
        KEY_PENDING_CNT,
        storage::get_u64(KEY_PENDING_CNT).saturating_sub(1),
    );
}

fn insert_order_into_tree(tree: &mut PriceLevelArena, ord: &mut RideOrder) -> Result<(), i32> {
    let lvl_idx = tree.find_or_insert(ord.rate_per_km_cents)?;
    let old_tail = tree.node(lvl_idx).tail_order_id;

    ord.status = ORD_STATUS_ACTIVE;
    ord.prev_order_id = old_tail;
    ord.next_order_id = NONE_ORD;

    if old_tail != NONE_ORD {
        if let Some(mut tail_ord) = load_order(old_tail) {
            tail_ord.next_order_id = ord.order_id;
            store_order(&tail_ord);
        }
    } else {
        tree.node_mut(lvl_idx).head_order_id = ord.order_id;
    }

    let lvl = tree.node_mut(lvl_idx);
    lvl.tail_order_id = ord.order_id;
    lvl.total_qty = lvl.total_qty.saturating_add(ord.max_distance_m);
    lvl.order_count = lvl.order_count.saturating_add(1);
    store_order(ord);
    Ok(())
}

fn unlink_order_from_tree(tree: &mut PriceLevelArena, ord: &RideOrder) {
    let lvl_idx = tree.find_price(ord.rate_per_km_cents);
    if lvl_idx == NONE_LVL {
        return;
    }
    let prev_id = ord.prev_order_id;
    let next_id = ord.next_order_id;
    if prev_id != NONE_ORD {
        if let Some(mut p_ord) = load_order(prev_id) {
            p_ord.next_order_id = next_id;
            store_order(&p_ord);
        }
    } else {
        tree.node_mut(lvl_idx).head_order_id = next_id;
    }

    if next_id != NONE_ORD {
        if let Some(mut n_ord) = load_order(next_id) {
            n_ord.prev_order_id = prev_id;
            store_order(&n_ord);
        }
    } else {
        tree.node_mut(lvl_idx).tail_order_id = prev_id;
    }

    let lvl = tree.node_mut(lvl_idx);
    lvl.total_qty = lvl.total_qty.saturating_sub(ord.max_distance_m);
    lvl.order_count = lvl.order_count.saturating_sub(1);
    if lvl.order_count == 0 {
        tree.remove_node(lvl_idx);
    }
}

fn handle_initialize(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 0 {
        return Err(-11);
    }
    let registry = args.address(0).ok_or(-3)?;
    let quote_ledger = args.address(1).ok_or(-3)?;
    let escrow_identity = args.address(2).ok_or(-3)?;
    let metro_name = args.dynamic_bytes(3).unwrap_or(b"Singapore Metro");
    let cos_lat_bps = args.u64(4).unwrap_or(SG_COS_LAT_BPS as u64) as u32;
    let road_bps = args.u64(5).unwrap_or(SG_ROAD_FACTOR_BPS as u64) as u32;

    if registry == [0u8; 20] || quote_ledger == [0u8; 20] || escrow_identity == [0u8; 20] {
        return Err(ERR_INVALID_DEX_ORDER);
    }
    require_valid_identity(&registry, &escrow_identity)?;

    let admin = context::msg_sender();
    storage::set_address(KEY_ADMIN, &admin);
    storage::set_address(KEY_REGISTRY, &registry);
    storage::set_address(KEY_QUOTE_LEDGER, &quote_ledger);
    storage::set_address(KEY_ESCROW_ID, &escrow_identity);

    let safe_name = if metro_name.is_empty() {
        b"Singapore Metro" as &[u8]
    } else if metro_name.len() > 64 {
        &metro_name[..64]
    } else {
        metro_name
    };
    storage::set(KEY_METRO_NAME, safe_name);
    storage::set_u64(
        KEY_COS_LAT_BPS,
        (if cos_lat_bps == 0 {
            SG_COS_LAT_BPS
        } else {
            cos_lat_bps.clamp(1_000, 10_000)
        }) as u64,
    );
    storage::set_u64(
        KEY_ROAD_BPS,
        (if road_bps == 0 {
            SG_ROAD_FACTOR_BPS
        } else {
            road_bps.clamp(10_000, 25_000)
        }) as u64,
    );
    storage::set_u64(KEY_INIT, 1);

    events::emit(
        &[
            EV_METRO_INITIALIZED,
            addr_topic(&registry),
            addr_topic(&quote_ledger),
            addr_topic(&escrow_identity),
        ],
        safe_name,
    );
    ret::write_bool(true);
    Ok(())
}

fn handle_set_toll(args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let admin = storage::get_address(KEY_ADMIN).ok_or(-10)?;
    if context::msg_sender() != admin {
        return Err(-12);
    }
    let orig = args.u64(0).ok_or(-3)? as u8;
    let dest = args.u64(1).ok_or(-3)? as u8;
    let cents = args.u64(2).ok_or(-3)?;
    if (orig as usize) >= NUM_REGIMES || (dest as usize) >= NUM_REGIMES || cents > 50_000 {
        return Err(ERR_INVALID_DEX_ORDER);
    }
    let k = toll_key(orig, dest);
    storage::set(k.as_slice(), &cents.to_le_bytes());
    ret::write_bool(true);
    Ok(())
}

/// Transfers `$250.00 SGD` (`25_000` cents) from `escrow_identity`'s unencumbered liquidity pool
/// (`balanceOf(escrow_id) - locked_escrow_cents`) to the calling Identity HFS so any customer can
/// test placing escrowed Ride Futures bids in 1 click without touching locked customer escrow!
fn handle_claim_demo_margin(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    if caller == escrow_id {
        return Err(ERR_INVALID_DEX_ORDER);
    }
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;
    let escrow_bal = call_balance_of(&quote_ledger, &escrow_id)?;
    let locked = storage::get_u64(KEY_LOCKED_ESCROW);
    let free_pool = escrow_bal.saturating_sub(locked);
    if free_pool < DEMO_FAUCET_GRANT_CENTS {
        return Err(ERR_FAUCET_DEPLETED);
    }
    call_dex_transfer(&quote_ledger, &escrow_id, &caller, DEMO_FAUCET_GRANT_CENTS)?;
    ret::write_u64_word(DEMO_FAUCET_GRANT_CENTS);
    Ok(())
}

/// Posts or updates the calling Driver Identity's single active Ask order:
/// - `lat_u32`, `lon_u32`: current vehicle microdegrees
/// - `ask_per_km_cents`: Clean rate in cents/km
/// - `max_distance_m`: Maximum total driven distance (`pickup_m + trip_m`) in meters
/// - `max_pickup_m`: Maximum unpaid approach distance (`pickup_m`) in meters
/// - `dest_mask`: Bitmask of accepted destination regimes (`0` defaults to all `0x3F`)
/// - `remote_basis_cents`: Extra cents/km required if `dest_regime == REGIME_REMOTE`
/// - `cross_border`: Whether adjacent regimes may match this car within `max_pickup_m`
fn handle_upsert_driver_ask(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    if caller == escrow_id {
        return Err(ERR_INVALID_DEX_ORDER);
    }
    // Single-Car Physical Inventory Invariant: cannot list an Ask while driving an active Futures contract!
    if storage::get_u64(actor_drv_fut_key(&caller).as_slice()) != 0 {
        return Err(ERR_ACTOR_BUSY);
    }

    let lat_e6 = decode_coord_u64(args.u64(0).ok_or(-3)?);
    let lon_e6 = decode_coord_u64(args.u64(1).ok_or(-3)?);
    let ask_per_km = args.u64(2).ok_or(-3)?;
    let max_distance_m = args.u64(3).ok_or(-3)?;
    let max_pickup_m = args.u64(4).ok_or(-3)?;
    let raw_mask = args.u64(5).ok_or(-3)? as u32;
    let remote_basis = args.u64(6).ok_or(-3)?;
    let cross_border = args.bool(7).unwrap_or(true);

    let coord = GeoCoord::new(lat_e6, lon_e6);
    if !coord.is_valid() || ask_per_km == 0 || max_distance_m < 500 || max_pickup_m < 100 {
        return Err(ERR_INVALID_COORDS);
    }
    let dest_mask = if (raw_mask & 0x3F) == 0 {
        0x3F
    } else {
        raw_mask & 0x3F
    };
    let regime = classify_sg_regime(coord);
    let now_blk = context::block_number();

    let existing_id = storage::get_u64(actor_ask_key(&caller).as_slice());
    if existing_id != NONE_ORD {
        if let Some(mut old) = load_order(existing_id) {
            if old.status == ORD_STATUS_ACTIVE {
                let mut old_tree = load_tree(false, old.orig_regime);
                unlink_order_from_tree(&mut old_tree, &old);
                store_tree(false, old.orig_regime, &old_tree);

                // If price improved or stayed equal (`ask_per_km <= old.rate_per_km_cents`), preserve
                // active resting status & seniority_block! If raised price, re-enter Pending Intake!
                old.orig_regime = regime;
                old.lat_e6 = lat_e6;
                old.lon_e6 = lon_e6;
                old.max_distance_m = max_distance_m;
                old.max_pickup_m = max_pickup_m;
                old.dest_mask = dest_mask;
                old.remote_basis_cents = remote_basis;
                old.cross_border = if cross_border { 1 } else { 0 };

                if ask_per_km <= old.rate_per_km_cents {
                    old.rate_per_km_cents = ask_per_km;
                    let mut new_tree = load_tree(false, regime);
                    insert_order_into_tree(&mut new_tree, &mut old)?;
                    store_tree(false, regime, &new_tree);
                    ret::write_u64_word(old.order_id);
                    return Ok(());
                } else {
                    storage::set_u64(
                        KEY_ACTIVE_ASK_CNT,
                        storage::get_u64(KEY_ACTIVE_ASK_CNT).saturating_sub(1),
                    );
                    old.rate_per_km_cents = ask_per_km;
                    old.seniority_block = now_blk;
                    append_to_pending(&mut old);
                    ret::write_u64_word(old.order_id);
                    return Ok(());
                }
            } else if old.status == ORD_STATUS_PENDING {
                old.orig_regime = regime;
                old.lat_e6 = lat_e6;
                old.lon_e6 = lon_e6;
                old.rate_per_km_cents = ask_per_km;
                old.max_distance_m = max_distance_m;
                old.max_pickup_m = max_pickup_m;
                old.dest_mask = dest_mask;
                old.remote_basis_cents = remote_basis;
                old.cross_border = if cross_border { 1 } else { 0 };
                old.seniority_block = now_blk;
                store_order(&old);
                ret::write_u64_word(old.order_id);
                return Ok(());
            }
        }
    }

    if (storage::get_u64(KEY_PENDING_CNT) as usize) >= MAX_PENDING_ORDERS
        || (storage::get_u64(KEY_ACTIVE_ASK_CNT) as usize) >= MAX_ACTIVE_ASKS
    {
        return Err(ERR_ORDERBOOK_FULL);
    }

    let order_id = storage::get_u64(KEY_ORDER_SEQ).checked_add(1).ok_or(-15)?;
    storage::set_u64(KEY_ORDER_SEQ, order_id);

    let mut ord = RideOrder {
        order_id,
        actor: caller,
        side: SIDE_ASK,
        status: ORD_STATUS_PENDING,
        orig_regime: regime,
        dest_regime: 0,
        cross_border: if cross_border { 1 } else { 0 },
        dest_mask,
        lat_e6,
        lon_e6,
        to_lat_e6: 0,
        to_lon_e6: 0,
        rate_per_km_cents: ask_per_km,
        remote_basis_cents: remote_basis,
        max_distance_m,
        max_pickup_m,
        escrowed_cents: 0,
        toll_cents: 0,
        seniority_block: now_blk,
        prev_order_id: NONE_ORD,
        next_order_id: NONE_ORD,
    };

    append_to_pending(&mut ord);
    storage::set_u64(actor_ask_key(&caller).as_slice(), order_id);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&(regime as u64).to_be_bytes());
    ev[8..16].copy_from_slice(&ask_per_km.to_be_bytes());
    ev[16..24].copy_from_slice(&max_distance_m.to_be_bytes());
    events::emit(
        &[EV_DRIVER_ASK_POSTED, u64_topic(order_id), addr_topic(&caller)],
        &ev,
    );
    ret::write_u64_word(order_id);
    Ok(())
}

/// $O(1)$ Driver GPS Heartbeat: updates vehicle coordinates (moving across Regime Ask Books if the
/// car crossed a regime boundary) while **preserving `seniority_block` and `ask_per_km`**!
fn handle_update_driver_location(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let lat_e6 = decode_coord_u64(args.u64(0).ok_or(-3)?);
    let lon_e6 = decode_coord_u64(args.u64(1).ok_or(-3)?);
    let coord = GeoCoord::new(lat_e6, lon_e6);
    if !coord.is_valid() {
        return Err(ERR_INVALID_COORDS);
    }
    let ask_id = storage::get_u64(actor_ask_key(&caller).as_slice());
    let mut ord = load_order(ask_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if ord.actor != caller
        || (ord.status != ORD_STATUS_ACTIVE && ord.status != ORD_STATUS_PENDING)
    {
        return Err(ERR_ORDER_NOT_FOUND);
    }

    let new_regime = classify_sg_regime(coord);
    if ord.status == ORD_STATUS_ACTIVE && new_regime != ord.orig_regime {
        let mut old_tree = load_tree(false, ord.orig_regime);
        unlink_order_from_tree(&mut old_tree, &ord);
        store_tree(false, ord.orig_regime, &old_tree);

        ord.orig_regime = new_regime;
        ord.lat_e6 = lat_e6;
        ord.lon_e6 = lon_e6;

        let mut new_tree = load_tree(false, new_regime);
        insert_order_into_tree(&mut new_tree, &mut ord)?;
        store_tree(false, new_regime, &new_tree);
    } else {
        ord.orig_regime = new_regime;
        ord.lat_e6 = lat_e6;
        ord.lon_e6 = lon_e6;
        store_order(&ord);
    }

    let mut ev = [0u8; 16];
    ev[0..4].copy_from_slice(&lat_e6.to_be_bytes());
    ev[4..8].copy_from_slice(&lon_e6.to_be_bytes());
    ev[8..16].copy_from_slice(&(new_regime as u64).to_be_bytes());
    events::emit(
        &[EV_DRIVER_LOC_UPDATED, u64_topic(ask_id), addr_topic(&caller)],
        &ev,
    );
    ret::write_u64_word(new_regime as u64);
    Ok(())
}

fn handle_cancel_driver_ask(_args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let ask_id = storage::get_u64(actor_ask_key(&caller).as_slice());
    let mut ord = load_order(ask_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if ord.actor != caller {
        return Err(ERR_NOT_ORDER_OWNER);
    }
    if ord.status != ORD_STATUS_PENDING && ord.status != ORD_STATUS_ACTIVE {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }

    if ord.status == ORD_STATUS_PENDING {
        unlink_from_pending(&ord);
    } else {
        let mut tree = load_tree(false, ord.orig_regime);
        unlink_order_from_tree(&mut tree, &ord);
        store_tree(false, ord.orig_regime, &tree);
        storage::set_u64(
            KEY_ACTIVE_ASK_CNT,
            storage::get_u64(KEY_ACTIVE_ASK_CNT).saturating_sub(1),
        );
    }

    ord.status = ORD_STATUS_CANCELLED;
    ord.prev_order_id = NONE_ORD;
    ord.next_order_id = NONE_ORD;
    store_order(&ord);
    storage::set_u64(actor_ask_key(&caller).as_slice(), NONE_ORD);

    events::emit(
        &[EV_ORDER_CANCELLED, u64_topic(ask_id), addr_topic(&caller)],
        &0u64.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Posts a Customer Ride Bid (`from -> to`) at `bid_per_km_cents` (`$/trip_km`, excluding `L_pickup`)
/// and escrows `ceil(bid_per_km_cents * trip_m / 1000) + StatutoryToll(orig, dest)` into `escrow_id`.
fn handle_post_rider_bid(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    if caller == escrow_id {
        return Err(ERR_INVALID_DEX_ORDER);
    }
    if storage::get_u64(actor_bid_key(&caller).as_slice()) != NONE_ORD
        || storage::get_u64(actor_rdr_fut_key(&caller).as_slice()) != 0
    {
        return Err(ERR_ACTOR_BUSY);
    }

    let from_lat = decode_coord_u64(args.u64(0).ok_or(-3)?);
    let from_lon = decode_coord_u64(args.u64(1).ok_or(-3)?);
    let to_lat = decode_coord_u64(args.u64(2).ok_or(-3)?);
    let to_lon = decode_coord_u64(args.u64(3).ok_or(-3)?);
    let bid_per_km = args.u64(4).ok_or(-3)?;
    let max_pickup_m = args.u64(5).ok_or(-3)?;

    let c_from = GeoCoord::new(from_lat, from_lon);
    let c_to = GeoCoord::new(to_lat, to_lon);
    if !c_from.is_valid() || !c_to.is_valid() || c_from == c_to || bid_per_km == 0 || max_pickup_m < 100
    {
        return Err(ERR_INVALID_COORDS);
    }

    if (storage::get_u64(KEY_PENDING_CNT) as usize) >= MAX_PENDING_ORDERS
        || (storage::get_u64(KEY_ACTIVE_BID_CNT) as usize) >= MAX_ACTIVE_BIDS
    {
        return Err(ERR_ORDERBOOK_FULL);
    }

    let cos_bps = storage::get_u64(KEY_COS_LAT_BPS) as u32;
    let road_bps = storage::get_u64(KEY_ROAD_BPS) as u32;
    let trip_m = road_distance_m(c_from, c_to, cos_bps, road_bps);
    if trip_m < 200 {
        return Err(ERR_INVALID_COORDS);
    }

    let orig_regime = classify_sg_regime(c_from);
    let dest_regime = classify_sg_regime(c_to);
    let clean_max_cents = compute_trip_fare_ceil(bid_per_km, trip_m).ok_or(-15)?;
    let toll_cents = get_toll_cents(orig_regime, dest_regime);
    let escrowed_cents = clean_max_cents.checked_add(toll_cents).ok_or(-15)?;

    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;
    call_dex_transfer(&quote_ledger, &caller, &escrow_id, escrowed_cents)?;
    storage::set_u64(
        KEY_LOCKED_ESCROW,
        storage::get_u64(KEY_LOCKED_ESCROW)
            .checked_add(escrowed_cents)
            .ok_or(-15)?,
    );

    let order_id = storage::get_u64(KEY_ORDER_SEQ).checked_add(1).ok_or(-15)?;
    storage::set_u64(KEY_ORDER_SEQ, order_id);
    let now_blk = context::block_number();

    let mut ord = RideOrder {
        order_id,
        actor: caller,
        side: SIDE_BID,
        status: ORD_STATUS_PENDING,
        orig_regime,
        dest_regime,
        cross_border: 0,
        dest_mask: 0,
        lat_e6: from_lat,
        lon_e6: from_lon,
        to_lat_e6: to_lat,
        to_lon_e6: to_lon,
        rate_per_km_cents: bid_per_km,
        remote_basis_cents: 0,
        max_distance_m: trip_m,
        max_pickup_m,
        escrowed_cents,
        toll_cents,
        seniority_block: now_blk,
        prev_order_id: NONE_ORD,
        next_order_id: NONE_ORD,
    };

    append_to_pending(&mut ord);
    storage::set_u64(actor_bid_key(&caller).as_slice(), order_id);

    let mut ev = [0u8; 24];
    ev[0..8].copy_from_slice(&bid_per_km.to_be_bytes());
    ev[8..16].copy_from_slice(&trip_m.to_be_bytes());
    ev[16..24].copy_from_slice(&escrowed_cents.to_be_bytes());
    events::emit(
        &[EV_RIDER_BID_POSTED, u64_topic(order_id), addr_topic(&caller)],
        &ev,
    );
    ret::write_u64_word(order_id);
    Ok(())
}

fn handle_cancel_rider_bid(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let arg_id = args.u64(0).unwrap_or(0);
    let bid_id = if arg_id != 0 {
        arg_id
    } else {
        storage::get_u64(actor_bid_key(&caller).as_slice())
    };
    let mut ord = load_order(bid_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if ord.actor != caller || ord.side != SIDE_BID {
        return Err(ERR_NOT_ORDER_OWNER);
    }
    if ord.status != ORD_STATUS_PENDING && ord.status != ORD_STATUS_ACTIVE {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }

    if ord.status == ORD_STATUS_PENDING {
        unlink_from_pending(&ord);
    } else {
        let mut tree = load_tree(true, ord.orig_regime);
        unlink_order_from_tree(&mut tree, &ord);
        store_tree(true, ord.orig_regime, &tree);
        storage::set_u64(
            KEY_ACTIVE_BID_CNT,
            storage::get_u64(KEY_ACTIVE_BID_CNT).saturating_sub(1),
        );
    }

    let refund = ord.escrowed_cents;
    ord.status = ORD_STATUS_CANCELLED;
    ord.escrowed_cents = 0;
    ord.prev_order_id = NONE_ORD;
    ord.next_order_id = NONE_ORD;
    store_order(&ord);
    storage::set_u64(actor_bid_key(&caller).as_slice(), NONE_ORD);

    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;
    storage::set_u64(
        KEY_LOCKED_ESCROW,
        storage::get_u64(KEY_LOCKED_ESCROW).saturating_sub(refund),
    );
    call_dex_transfer(&quote_ledger, &escrow_id, &caller, refund)?;

    events::emit(
        &[EV_ORDER_CANCELLED, u64_topic(bid_id), addr_topic(&caller)],
        &refund.to_be_bytes(),
    );
    ret::write_u64_word(refund);
    Ok(())
}

/// Permissionless Discrete-Time Multi-Regime AON Ride Futures Matcher (`matchBlock()`):
/// 1. Ingests all Pending Asks & Bids with `seniority_block < current_block` into their Regime
///    `AskTree` (`ask_per_km ASC`) or `BidTree` (`bid_per_km DESC`).
/// 2. Evaluates active Bids in strict `(bid_per_km DESC, seniority_block ASC, order_id ASC)` order.
/// 3. Walks the Origin Regime (+ border-adjacent `cross_border`) `AskTree` upward from lowest
///    `ask_per_km` (early-stopping once `base_ask > bid_per_km`), enforcing:
///    - Destination Regime mask `(d.dest_mask & (1 << dest_regime)) != 0`
///    - Effective rate `a_eff = d.ask_per_km + (dest == REMOTE ? d.remote_basis : 0) <= r.bid_per_km`
///    - Pickup radius `pickup_m <= min(r.max_pickup_m, d.max_pickup_m)`
///    - All-Or-Nothing (AON) single-car range `pickup_m + r.trip_m <= d.max_distance_m`
/// 4. Picks minimum `a_eff` (breaking same-price ties by closest car `min pickup_m`, then FIFO),
///    executes at the **Resting Maker's** rate over **`trip_m` ONLY** (`pickup_m` excluded!),
///    refunds unused Rider margin immediately, and locks the `RideFuturesContract` in escrow!
fn handle_match_block(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let current_block = context::block_number();
    if storage::get_u64(KEY_LAST_MATCH_SET) == 1
        && storage::get_u64(KEY_LAST_MATCH_BLK) == current_block
    {
        return Err(ERR_ALREADY_EXECUTED_IN_BLOCK);
    }
    storage::set_u64(KEY_LAST_MATCH_SET, 1);
    storage::set_u64(KEY_LAST_MATCH_BLK, current_block);

    let mut bid_trees = [
        load_tree(true, 0),
        load_tree(true, 1),
        load_tree(true, 2),
        load_tree(true, 3),
        load_tree(true, 4),
        load_tree(true, 5),
    ];
    let mut ask_trees = [
        load_tree(false, 0),
        load_tree(false, 1),
        load_tree(false, 2),
        load_tree(false, 3),
        load_tree(false, 4),
        load_tree(false, 5),
    ];

    let mut pending_head = storage::get_u64(KEY_PENDING_HEAD);
    let mut pending_tail = storage::get_u64(KEY_PENDING_TAIL);
    let mut pending_cnt = storage::get_u64(KEY_PENDING_CNT);
    let mut active_asks = storage::get_u64(KEY_ACTIVE_ASK_CNT);
    let mut active_bids = storage::get_u64(KEY_ACTIVE_BID_CNT);
    let mut ingested = 0u64;

    let mut p_guard = 0usize;
    while pending_head != NONE_ORD && p_guard < MAX_PENDING_ORDERS {
        let Some(mut ord) = load_order(pending_head) else {
            pending_head = NONE_ORD;
            pending_tail = NONE_ORD;
            pending_cnt = 0;
            break;
        };
        if ord.seniority_block >= current_block {
            break;
        }
        let next_p = ord.next_order_id;
        let z = (ord.orig_regime as usize).min(NUM_REGIMES - 1);
        if ord.side == SIDE_BID {
            insert_order_into_tree(&mut bid_trees[z], &mut ord)?;
            active_bids += 1;
        } else {
            insert_order_into_tree(&mut ask_trees[z], &mut ord)?;
            active_asks += 1;
        }
        pending_head = next_p;
        pending_cnt = pending_cnt.saturating_sub(1);
        ingested += 1;
        p_guard += 1;
    }

    if pending_head == NONE_ORD {
        pending_tail = NONE_ORD;
        pending_cnt = 0;
    } else if ingested > 0 {
        if let Some(mut h_ord) = load_order(pending_head) {
            h_ord.prev_order_id = NONE_ORD;
            store_order(&h_ord);
        }
    }
    storage::set_u64(KEY_PENDING_HEAD, pending_head);
    storage::set_u64(KEY_PENDING_TAIL, pending_tail);
    storage::set_u64(KEY_PENDING_CNT, pending_cnt);

    // Collect all active Rider Bids across the 6 Regime Bid Books and order globally by
    // `(bid_per_km DESC, seniority_block ASC, order_id ASC)`.
    let mut total_bids = 0usize;
    unsafe {
        let mut z = 0usize;
        while z < NUM_REGIMES {
            let mut lvl = bid_trees[z].best_head;
            let mut l_guard = 0usize;
            while lvl != NONE_LVL && l_guard < MAX_PRICE_LEVELS_PER_BOOK {
                let mut oid = bid_trees[z].node(lvl).head_order_id;
                let mut o_guard = 0usize;
                while oid != NONE_ORD && total_bids < MAX_ACTIVE_BIDS && o_guard < MAX_ACTIVE_BIDS {
                    let Some(bo) = load_order(oid) else { break };
                    MATCH_BID_IDS[total_bids] = bo.order_id;
                    MATCH_BID_RATES[total_bids] = bo.rate_per_km_cents;
                    MATCH_BID_BLKS[total_bids] = bo.seniority_block;
                    total_bids += 1;
                    oid = bo.next_order_id;
                    o_guard += 1;
                }
                lvl = bid_trees[z].node(lvl).next_worse;
                l_guard += 1;
            }
            z += 1;
        }

        // Bounded insertion sort on `total_bids <= 192`
        let mut i = 1usize;
        while i < total_bids {
            let id_v = MATCH_BID_IDS[i];
            let rt_v = MATCH_BID_RATES[i];
            let bk_v = MATCH_BID_BLKS[i];
            let mut j = i;
            while j > 0 {
                let prev_rt = MATCH_BID_RATES[j - 1];
                let prev_bk = MATCH_BID_BLKS[j - 1];
                let prev_id = MATCH_BID_IDS[j - 1];
                let better = rt_v > prev_rt
                    || (rt_v == prev_rt && (bk_v < prev_bk || (bk_v == prev_bk && id_v < prev_id)));
                if !better {
                    break;
                }
                MATCH_BID_IDS[j] = prev_id;
                MATCH_BID_RATES[j] = prev_rt;
                MATCH_BID_BLKS[j] = prev_bk;
                j -= 1;
            }
            MATCH_BID_IDS[j] = id_v;
            MATCH_BID_RATES[j] = rt_v;
            MATCH_BID_BLKS[j] = bk_v;
            i += 1;
        }
    }

    let cos_bps = storage::get_u64(KEY_COS_LAT_BPS) as u32;
    let road_bps = storage::get_u64(KEY_ROAD_BPS) as u32;
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;
    let mut locked_escrow = storage::get_u64(KEY_LOCKED_ESCROW);
    let mut futures_seq = storage::get_u64(KEY_FUTURES_SEQ);
    let mut matched_in_block = 0u64;
    let mut matched_notional_in_block = 0u64;

    let mut b_idx = 0usize;
    while b_idx < total_bids {
        let bid_id = unsafe { MATCH_BID_IDS[b_idx] };
        b_idx += 1;
        let Some(mut bid) = load_order(bid_id) else {
            continue;
        };
        if bid.status != ORD_STATUS_ACTIVE {
            continue;
        }

        let z_orig = (bid.orig_regime as usize).min(NUM_REGIMES - 1);
        let z_dest = bid.dest_regime;
        let adj_mask = SG_ADJACENT_MASKS[z_orig];
        let r_from = GeoCoord::new(bid.lat_e6, bid.lon_e6);
        let trip_m = bid.max_distance_m;

        // Best feasible Driver candidate: `(a_eff ASC, pickup_m ASC, seniority_block ASC, order_id ASC)`
        let mut best_drv: Option<(RideOrder, u64, u64)> = None; // (drv_ord, a_eff, pickup_m)

        let mut cand_z = 0usize;
        while cand_z < NUM_REGIMES {
            if (adj_mask & (1 << cand_z)) == 0 {
                cand_z += 1;
                continue;
            }
            let same_regime = cand_z == z_orig;
            let mut lvl = ask_trees[cand_z].best_head;
            let mut l_guard = 0usize;

            while lvl != NONE_LVL && l_guard < MAX_PRICE_LEVELS_PER_BOOK {
                let base_ask = ask_trees[cand_z].node(lvl).price;
                // Early termination! `ask_trees[cand_z]` is sorted by `base_ask ASC`, and since
                // `a_eff >= base_ask`, once `base_ask > bid.rate_per_km_cents` (or `> best_a_eff`),
                // NO further level in this Ask Tree can cross or beat `best_drv`!
                if base_ask > bid.rate_per_km_cents {
                    break;
                }
                if let Some((_, best_aeff, _)) = best_drv {
                    if base_ask > best_aeff {
                        break;
                    }
                }

                let mut a_oid = ask_trees[cand_z].node(lvl).head_order_id;
                let mut o_guard = 0usize;
                while a_oid != NONE_ORD && o_guard < MAX_ACTIVE_ASKS {
                    let Some(drv) = load_order(a_oid) else { break };
                    a_oid = drv.next_order_id;
                    o_guard += 1;

                    if drv.status != ORD_STATUS_ACTIVE || drv.actor == bid.actor {
                        continue;
                    }
                    if !same_regime && drv.cross_border == 0 {
                        continue;
                    }
                    if (drv.dest_mask & (1u32 << z_dest)) == 0 {
                        continue;
                    }

                    let a_eff = if z_dest == REGIME_REMOTE {
                        drv.rate_per_km_cents.saturating_add(drv.remote_basis_cents)
                    } else {
                        drv.rate_per_km_cents
                    };
                    if a_eff > bid.rate_per_km_cents {
                        continue;
                    }
                    if let Some((_, best_aeff, _)) = best_drv {
                        if a_eff > best_aeff {
                            continue;
                        }
                    }

                    let d_coord = GeoCoord::new(drv.lat_e6, drv.lon_e6);
                    let pickup_m = road_distance_m(d_coord, r_from, cos_bps, road_bps);
                    if pickup_m > bid.max_pickup_m || pickup_m > drv.max_pickup_m {
                        continue;
                    }
                    // All-Or-Nothing (AON) single-car total driven distance check!
                    if pickup_m.saturating_add(trip_m) > drv.max_distance_m {
                        continue;
                    }

                    let replace = match best_drv {
                        None => true,
                        Some((ref prev_d, prev_aeff, prev_pk)) => {
                            a_eff < prev_aeff
                                || (a_eff == prev_aeff
                                    && (pickup_m < prev_pk
                                        || (pickup_m == prev_pk
                                            && (drv.seniority_block < prev_d.seniority_block
                                                || (drv.seniority_block == prev_d.seniority_block
                                                    && drv.order_id < prev_d.order_id)))))
                        }
                    };
                    if replace {
                        best_drv = Some((drv, a_eff, pickup_m));
                    }
                }

                lvl = ask_trees[cand_z].node(lvl).next_worse;
                l_guard += 1;
            }
            cand_z += 1;
        }

        let Some((mut drv, a_eff, pickup_m)) = best_drv else {
            continue;
        };

        // Unlink both matched orders from their Regime AVL books
        unlink_order_from_tree(&mut bid_trees[z_orig], &bid);
        let d_reg = (drv.orig_regime as usize).min(NUM_REGIMES - 1);
        unlink_order_from_tree(&mut ask_trees[d_reg], &drv);
        active_bids = active_bids.saturating_sub(1);
        active_asks = active_asks.saturating_sub(1);

        // Resting-Maker Clearing Price Rule: whichever order rested earlier sets `clearing_rate`!
        let driver_is_maker = drv.seniority_block < bid.seniority_block
            || (drv.seniority_block == bid.seniority_block && drv.order_id < bid.order_id);
        let (clearing_rate, maker_side) = if driver_is_maker {
            (a_eff, MAKER_DRIVER)
        } else {
            (bid.rate_per_km_cents, MAKER_RIDER)
        };

        // Bill strictly on customer trip distance `trip_m` (excluding `pickup_m`!) + statutory toll
        let clean_fare_cents = compute_trip_fare_ceil(clearing_rate, trip_m).ok_or(-15)?;
        let toll_cents = bid.toll_cents;
        let contract_total_cents = clean_fare_cents.checked_add(toll_cents).ok_or(-15)?;
        let refund_cents = bid.escrowed_cents.saturating_sub(contract_total_cents);

        if refund_cents > 0 {
            locked_escrow = locked_escrow.saturating_sub(refund_cents);
            call_dex_transfer(&quote_ledger, &escrow_id, &bid.actor, refund_cents)?;
        }

        bid.status = ORD_STATUS_MATCHED;
        bid.escrowed_cents = contract_total_cents;
        bid.prev_order_id = NONE_ORD;
        bid.next_order_id = NONE_ORD;
        store_order(&bid);

        drv.status = ORD_STATUS_MATCHED;
        drv.prev_order_id = NONE_ORD;
        drv.next_order_id = NONE_ORD;
        store_order(&drv);

        storage::set_u64(actor_bid_key(&bid.actor).as_slice(), NONE_ORD);
        storage::set_u64(actor_ask_key(&drv.actor).as_slice(), NONE_ORD);

        futures_seq = futures_seq.checked_add(1).ok_or(-15)?;
        let fut = RideFuturesContract {
            futures_id: futures_seq,
            bid_order_id: bid.order_id,
            ask_order_id: drv.order_id,
            rider: bid.actor,
            driver: drv.actor,
            status: FUT_STATUS_MATCHED,
            orig_regime: bid.orig_regime,
            dest_regime: bid.dest_regime,
            maker_side,
            driver_start_lat_e6: drv.lat_e6,
            driver_start_lon_e6: drv.lon_e6,
            from_lat_e6: bid.lat_e6,
            from_lon_e6: bid.lon_e6,
            to_lat_e6: bid.to_lat_e6,
            to_lon_e6: bid.to_lon_e6,
            pickup_m,
            trip_m,
            clearing_rate_cents: clearing_rate,
            clean_fare_cents,
            toll_cents,
            matched_block: current_block,
            settled_block: 0,
        };
        store_futures(&fut);
        storage::set_u64(actor_rdr_fut_key(&bid.actor).as_slice(), futures_seq);
        storage::set_u64(actor_drv_fut_key(&drv.actor).as_slice(), futures_seq);

        storage::set_u64(
            regime_stat_key(b"rx:last_px:", bid.orig_regime).as_slice(),
            clearing_rate,
        );
        let r_cnt_k = regime_stat_key(b"rx:m_cnt:", bid.orig_regime);
        storage::set_u64(r_cnt_k.as_slice(), storage::get_u64(r_cnt_k.as_slice()) + 1);

        matched_in_block += 1;
        matched_notional_in_block = matched_notional_in_block.saturating_add(contract_total_cents);

        let mut ev = [0u8; 32];
        ev[0..8].copy_from_slice(&clearing_rate.to_be_bytes());
        ev[8..16].copy_from_slice(&contract_total_cents.to_be_bytes());
        ev[16..24].copy_from_slice(&pickup_m.to_be_bytes());
        ev[24..32].copy_from_slice(&trip_m.to_be_bytes());
        events::emit(
            &[
                EV_RIDE_MATCHED,
                u64_topic(futures_seq),
                addr_topic(&bid.actor),
                addr_topic(&drv.actor),
            ],
            &ev,
        );
    }

    let mut z = 0usize;
    while z < NUM_REGIMES {
        store_tree(true, z as u8, &bid_trees[z]);
        store_tree(false, z as u8, &ask_trees[z]);
        z += 1;
    }
    storage::set_u64(KEY_ACTIVE_BID_CNT, active_bids);
    storage::set_u64(KEY_ACTIVE_ASK_CNT, active_asks);
    storage::set_u64(KEY_LOCKED_ESCROW, locked_escrow);
    storage::set_u64(KEY_FUTURES_SEQ, futures_seq);

    let mut blk_ev = [0u8; 24];
    blk_ev[0..8].copy_from_slice(&ingested.to_be_bytes());
    blk_ev[8..16].copy_from_slice(&matched_in_block.to_be_bytes());
    blk_ev[16..24].copy_from_slice(&matched_notional_in_block.to_be_bytes());
    events::emit(&[EV_BLOCK_MATCHED, u64_topic(current_block)], &blk_ev);

    ret::write_u64_word(matched_in_block);
    Ok(())
}

/// Marks passenger boarding (`FUT_STATUS_MATCHED -> FUT_STATUS_IN_PROGRESS`), callable by either
/// the assigned Driver Identity or Customer Identity.
fn handle_confirm_pickup(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let futures_id = args.u64(0).ok_or(-3)?;
    let mut fut = load_futures(futures_id).ok_or(ERR_FUTURES_NOT_FOUND)?;
    if caller != fut.driver && caller != fut.rider {
        return Err(ERR_NOT_FUTURES_PARTY);
    }
    if fut.status != FUT_STATUS_MATCHED {
        return Err(ERR_FUTURES_WRONG_STATE);
    }
    fut.status = FUT_STATUS_IN_PROGRESS;
    store_futures(&fut);

    let blk = context::block_number();
    events::emit(
        &[EV_RIDE_PICKUP, u64_topic(futures_id), addr_topic(&caller)],
        &blk.to_be_bytes(),
    );
    ret::write_bool(true);
    Ok(())
}

/// Physical Delivery Settlement (`completeRide(futuresId)`):
/// Callable **exclusively** by the Customer's `Identity` HFS (`caller == fut.rider`) to confirm
/// physical delivery of the taxi service, releasing `clean_fare_cents + toll_cents` from
/// `escrow_identity` into `fut.driver` on `AssetLedger`!
fn handle_complete_ride(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let futures_id = args.u64(0).ok_or(-3)?;
    let mut fut = load_futures(futures_id).ok_or(ERR_FUTURES_NOT_FOUND)?;
    if caller != fut.rider {
        return Err(ERR_NOT_FUTURES_PARTY);
    }
    if fut.status != FUT_STATUS_MATCHED && fut.status != FUT_STATUS_IN_PROGRESS {
        return Err(ERR_FUTURES_WRONG_STATE);
    }

    let payout = fut.clean_fare_cents.checked_add(fut.toll_cents).ok_or(-15)?;
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;

    storage::set_u64(
        KEY_LOCKED_ESCROW,
        storage::get_u64(KEY_LOCKED_ESCROW).saturating_sub(payout),
    );
    call_dex_transfer(&quote_ledger, &escrow_id, &fut.driver, payout)?;

    let blk = context::block_number();
    fut.status = FUT_STATUS_SETTLED;
    fut.settled_block = blk;
    store_futures(&fut);

    storage::set_u64(actor_rdr_fut_key(&fut.rider).as_slice(), 0);
    storage::set_u64(actor_drv_fut_key(&fut.driver).as_slice(), 0);

    let d_done_k = actor_rides_done_key(&fut.driver);
    storage::set_u64(d_done_k.as_slice(), storage::get_u64(d_done_k.as_slice()) + 1);
    let r_done_k = actor_rides_done_key(&fut.rider);
    storage::set_u64(r_done_k.as_slice(), storage::get_u64(r_done_k.as_slice()) + 1);
    let earn_k = actor_earned_key(&fut.driver);
    storage::set_u64(
        earn_k.as_slice(),
        storage::get_u64(earn_k.as_slice()).saturating_add(payout),
    );

    storage::set_u64(KEY_SETTLED_CNT, storage::get_u64(KEY_SETTLED_CNT) + 1);
    storage::set_u64(
        KEY_SETTLED_VOL,
        storage::get_u64(KEY_SETTLED_VOL).saturating_add(payout),
    );

    events::emit(
        &[
            EV_RIDE_COMPLETED,
            u64_topic(futures_id),
            addr_topic(&fut.rider),
            addr_topic(&fut.driver),
        ],
        &payout.to_be_bytes(),
    );
    ret::write_u64_word(payout);
    Ok(())
}

/// Pre-boarding cancellation (`FUT_STATUS_MATCHED` only):
/// - If Driver cancels, 100% of escrowed fare refunds to Rider.
/// - If Rider cancels within `CANCEL_GRACE_BLOCKS` (`15` blocks), 100% refunds to Rider; if after
///   `15` blocks, Driver receives a 10% approach break-fee (capped at `$3.00`) and Rider gets the rest.
fn handle_cancel_ride_futures(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let futures_id = args.u64(0).ok_or(-3)?;
    let mut fut = load_futures(futures_id).ok_or(ERR_FUTURES_NOT_FOUND)?;
    if caller != fut.driver && caller != fut.rider {
        return Err(ERR_NOT_FUTURES_PARTY);
    }
    if fut.status != FUT_STATUS_MATCHED {
        return Err(ERR_FUTURES_WRONG_STATE);
    }

    let total_locked = fut.clean_fare_cents.checked_add(fut.toll_cents).ok_or(-15)?;
    let now_blk = context::block_number();
    let break_fee = if caller == fut.rider
        && now_blk > fut.matched_block.saturating_add(CANCEL_GRACE_BLOCKS)
    {
        (total_locked / 10).min(MAX_APPROACH_BREAK_FEE_CENTS)
    } else {
        0
    };
    let rider_refund = total_locked.saturating_sub(break_fee);

    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).ok_or(-10)?;
    storage::set_u64(
        KEY_LOCKED_ESCROW,
        storage::get_u64(KEY_LOCKED_ESCROW).saturating_sub(total_locked),
    );
    if rider_refund > 0 {
        call_dex_transfer(&quote_ledger, &escrow_id, &fut.rider, rider_refund)?;
    }
    if break_fee > 0 {
        call_dex_transfer(&quote_ledger, &escrow_id, &fut.driver, break_fee)?;
    }

    fut.status = FUT_STATUS_CANCELLED;
    fut.settled_block = now_blk;
    store_futures(&fut);

    storage::set_u64(actor_rdr_fut_key(&fut.rider).as_slice(), 0);
    storage::set_u64(actor_drv_fut_key(&fut.driver).as_slice(), 0);

    let mut ev = [0u8; 16];
    ev[0..8].copy_from_slice(&rider_refund.to_be_bytes());
    ev[8..16].copy_from_slice(&break_fee.to_be_bytes());
    events::emit(
        &[EV_RIDE_CANCELLED, u64_topic(futures_id), addr_topic(&caller)],
        &ev,
    );
    ret::write_u64_word(rider_refund);
    Ok(())
}

fn handle_get_metro_overview(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let registry = storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]);
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
    let escrow_id = storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]);

    let mut name_buf = [0u8; 64];
    let name_len = storage::get_into(KEY_METRO_NAME, &mut name_buf).unwrap_or(0).min(64);

    // Count pending orders per regime so the UI shows Pending Intake badges per regime!
    let mut pending_by_reg = [0u16; NUM_REGIMES];
    let mut p_cur = storage::get_u64(KEY_PENDING_HEAD);
    let mut p_guard = 0usize;
    while p_cur != NONE_ORD && p_guard < MAX_PENDING_ORDERS {
        let Some(po) = load_order(p_cur) else { break };
        let z = (po.orig_regime as usize).min(NUM_REGIMES - 1);
        pending_by_reg[z] = pending_by_reg[z].saturating_add(1);
        p_cur = po.next_order_id;
        p_guard += 1;
    }

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(VIEW_SCRATCH);
        out[0..20].copy_from_slice(&registry);
        out[20..40].copy_from_slice(&quote_ledger);
        out[40..60].copy_from_slice(&escrow_id);
        out[60..68].copy_from_slice(&storage::get_u64(KEY_LOCKED_ESCROW).to_be_bytes());
        out[68..76].copy_from_slice(&storage::get_u64(KEY_ORDER_SEQ).to_be_bytes());
        out[76..84].copy_from_slice(&storage::get_u64(KEY_FUTURES_SEQ).to_be_bytes());
        out[84..92].copy_from_slice(&storage::get_u64(KEY_SETTLED_CNT).to_be_bytes());
        out[92..100].copy_from_slice(&storage::get_u64(KEY_SETTLED_VOL).to_be_bytes());
        out[100..108].copy_from_slice(&storage::get_u64(KEY_LAST_MATCH_BLK).to_be_bytes());
        out[108..112].copy_from_slice(&(storage::get_u64(KEY_COS_LAT_BPS) as u32).to_be_bytes());
        out[112..116].copy_from_slice(&(storage::get_u64(KEY_ROAD_BPS) as u32).to_be_bytes());
        out[116] = NUM_REGIMES as u8;
        out[117..119].copy_from_slice(&(name_len as u16).to_be_bytes());

        let mut off = 119usize;
        let mut z = 0usize;
        while z < NUM_REGIMES {
            let bt = load_tree(true, z as u8);
            let at = load_tree(false, z as u8);

            let mut b_cnt = 0u16;
            let mut l = bt.best_head;
            let mut g = 0usize;
            while l != NONE_LVL && g < MAX_PRICE_LEVELS_PER_BOOK {
                b_cnt = b_cnt.saturating_add(bt.node(l).order_count);
                l = bt.node(l).next_worse;
                g += 1;
            }
            let mut a_cnt = 0u16;
            l = at.best_head;
            g = 0;
            while l != NONE_LVL && g < MAX_PRICE_LEVELS_PER_BOOK {
                a_cnt = a_cnt.saturating_add(at.node(l).order_count);
                l = at.node(l).next_worse;
                g += 1;
            }

            let best_bid = if bt.best_head != NONE_LVL {
                bt.node(bt.best_head).price
            } else {
                0
            };
            let best_ask = if at.best_head != NONE_LVL {
                at.node(at.best_head).price
            } else {
                0
            };
            let last_px = storage::get_u64(regime_stat_key(b"rx:last_px:", z as u8).as_slice());
            let m_cnt = storage::get_u64(regime_stat_key(b"rx:m_cnt:", z as u8).as_slice());

            out[off] = z as u8;
            out[off + 1..off + 3].copy_from_slice(&b_cnt.to_be_bytes());
            out[off + 3..off + 5].copy_from_slice(&a_cnt.to_be_bytes());
            out[off + 5..off + 7].copy_from_slice(&pending_by_reg[z].to_be_bytes());
            out[off + 7] = 0;
            out[off + 8..off + 16].copy_from_slice(&best_bid.to_be_bytes());
            out[off + 16..off + 24].copy_from_slice(&best_ask.to_be_bytes());
            out[off + 24..off + 32].copy_from_slice(&last_px.to_be_bytes());
            out[off + 32..off + 40].copy_from_slice(&m_cnt.to_be_bytes());
            off += 40;
            z += 1;
        }

        let mut o = 0u8;
        while (o as usize) < NUM_REGIMES {
            let mut d = 0u8;
            while (d as usize) < NUM_REGIMES {
                out[off..off + 8].copy_from_slice(&get_toll_cents(o, d).to_be_bytes());
                off += 8;
                d += 1;
            }
            o += 1;
        }

        out[off..off + name_len].copy_from_slice(&name_buf[..name_len]);
        off += name_len;
        ret::write_abi_bytes(&out[..off]);
    }
    Ok(())
}

fn encode_ask_wire(ord: &RideOrder, d: &mut [u8]) {
    d[0..8].copy_from_slice(&ord.order_id.to_be_bytes());
    d[8..28].copy_from_slice(&ord.actor);
    d[28] = ord.status;
    d[29] = ord.orig_regime;
    d[30] = ord.cross_border;
    d[31] = 0;
    d[32..36].copy_from_slice(&ord.lat_e6.to_be_bytes());
    d[36..40].copy_from_slice(&ord.lon_e6.to_be_bytes());
    d[40..48].copy_from_slice(&ord.rate_per_km_cents.to_be_bytes());
    d[48..56].copy_from_slice(&ord.max_distance_m.to_be_bytes());
    d[56..64].copy_from_slice(&ord.max_pickup_m.to_be_bytes());
    d[64..72].copy_from_slice(&ord.remote_basis_cents.to_be_bytes());
    d[72..76].copy_from_slice(&ord.dest_mask.to_be_bytes());
    d[76..84].copy_from_slice(&ord.seniority_block.to_be_bytes());
}

fn encode_bid_wire(ord: &RideOrder, d: &mut [u8]) {
    d[0..8].copy_from_slice(&ord.order_id.to_be_bytes());
    d[8..28].copy_from_slice(&ord.actor);
    d[28] = ord.status;
    d[29] = ord.orig_regime;
    d[30] = ord.dest_regime;
    d[31] = 0;
    d[32..36].copy_from_slice(&ord.lat_e6.to_be_bytes());
    d[36..40].copy_from_slice(&ord.lon_e6.to_be_bytes());
    d[40..44].copy_from_slice(&ord.to_lat_e6.to_be_bytes());
    d[44..48].copy_from_slice(&ord.to_lon_e6.to_be_bytes());
    d[48..56].copy_from_slice(&ord.max_distance_m.to_be_bytes());
    d[56..64].copy_from_slice(&ord.rate_per_km_cents.to_be_bytes());
    d[64..72].copy_from_slice(&ord.max_pickup_m.to_be_bytes());
    d[72..80].copy_from_slice(&ord.escrowed_cents.to_be_bytes());
    d[80..88].copy_from_slice(&ord.toll_cents.to_be_bytes());
    d[88..96].copy_from_slice(&ord.seniority_block.to_be_bytes());
}

fn handle_get_active_book_snapshot(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(VIEW_SCRATCH);
        let mut off = 4usize;
        let mut ask_cnt = 0u16;
        let mut bid_cnt = 0u16;

        // 1. Resting Active Asks across all 6 Regimes (ordered `ask_per_km ASC` within each regime)
        let mut z = 0usize;
        while z < NUM_REGIMES {
            let at = load_tree(false, z as u8);
            let mut l = at.best_head;
            let mut lg = 0usize;
            while l != NONE_LVL && lg < MAX_PRICE_LEVELS_PER_BOOK {
                let mut oid = at.node(l).head_order_id;
                let mut og = 0usize;
                while oid != NONE_ORD && og < MAX_ACTIVE_ASKS && off + 84 <= 48_000 {
                    let Some(ao) = load_order(oid) else { break };
                    encode_ask_wire(&ao, &mut out[off..off + 84]);
                    off += 84;
                    ask_cnt += 1;
                    oid = ao.next_order_id;
                    og += 1;
                }
                l = at.node(l).next_worse;
                lg += 1;
            }
            z += 1;
        }

        // Pending Asks
        let mut p_cur = storage::get_u64(KEY_PENDING_HEAD);
        let mut pg = 0usize;
        while p_cur != NONE_ORD && pg < MAX_PENDING_ORDERS && off + 84 <= 48_000 {
            let Some(po) = load_order(p_cur) else { break };
            if po.side == SIDE_ASK && po.status == ORD_STATUS_PENDING {
                encode_ask_wire(&po, &mut out[off..off + 84]);
                off += 84;
                ask_cnt += 1;
            }
            p_cur = po.next_order_id;
            pg += 1;
        }

        // 2. Resting Active Bids across all 6 Regimes (ordered `bid_per_km DESC` within each regime)
        z = 0;
        while z < NUM_REGIMES {
            let bt = load_tree(true, z as u8);
            let mut l = bt.best_head;
            let mut lg = 0usize;
            while l != NONE_LVL && lg < MAX_PRICE_LEVELS_PER_BOOK {
                let mut oid = bt.node(l).head_order_id;
                let mut og = 0usize;
                while oid != NONE_ORD && og < MAX_ACTIVE_BIDS && off + 96 <= 64_000 {
                    let Some(bo) = load_order(oid) else { break };
                    encode_bid_wire(&bo, &mut out[off..off + 96]);
                    off += 96;
                    bid_cnt += 1;
                    oid = bo.next_order_id;
                    og += 1;
                }
                l = bt.node(l).next_worse;
                lg += 1;
            }
            z += 1;
        }

        // Pending Bids
        p_cur = storage::get_u64(KEY_PENDING_HEAD);
        pg = 0;
        while p_cur != NONE_ORD && pg < MAX_PENDING_ORDERS && off + 96 <= 64_000 {
            let Some(po) = load_order(p_cur) else { break };
            if po.side == SIDE_BID && po.status == ORD_STATUS_PENDING {
                encode_bid_wire(&po, &mut out[off..off + 96]);
                off += 96;
                bid_cnt += 1;
            }
            p_cur = po.next_order_id;
            pg += 1;
        }

        out[0..2].copy_from_slice(&ask_cnt.to_be_bytes());
        out[2..4].copy_from_slice(&bid_cnt.to_be_bytes());
        ret::write_abi_bytes(&out[..off]);
    }
    Ok(())
}

/// Returns Ride Futures contracts newest-first (`offset = 0` starts at `total_futures`).
fn handle_get_futures_slice(args: &CalldataReader) -> Result<(), i32> {
    let offset = args.u64(0).unwrap_or(0);
    let limit = args.u64(1).unwrap_or(32).min(64);
    let total = storage::get_u64(KEY_FUTURES_SEQ);

    unsafe {
        let out = &mut *core::ptr::addr_of_mut!(VIEW_SCRATCH);
        out[0..8].copy_from_slice(&total.to_be_bytes());
        let mut off = 10usize;
        let mut cnt = 0u16;

        if offset < total && limit > 0 {
            let mut fid = total - offset;
            while fid >= 1 && (cnt as u64) < limit && off + FUTURES_STORAGE_BYTES <= 64_000 {
                if let Some(f) = load_futures(fid) {
                    let mut rec = [0u8; FUTURES_STORAGE_BYTES];
                    encode_futures_be(&f, &mut rec);
                    out[off..off + FUTURES_STORAGE_BYTES].copy_from_slice(&rec);
                    off += FUTURES_STORAGE_BYTES;
                    cnt += 1;
                }
                if fid == 1 {
                    break;
                }
                fid -= 1;
            }
        }
        out[8..10].copy_from_slice(&cnt.to_be_bytes());
        ret::write_abi_bytes(&out[..off]);
    }
    Ok(())
}

fn handle_get_futures(args: &CalldataReader) -> Result<(), i32> {
    let fid = args.u64(0).ok_or(-3)?;
    let f = load_futures(fid).ok_or(ERR_FUTURES_NOT_FOUND)?;
    let mut rec = [0u8; FUTURES_STORAGE_BYTES];
    encode_futures_be(&f, &mut rec);
    ret::write_abi_bytes(&rec);
    Ok(())
}

/// Returns `(active_ask_id, active_bid_id, active_driver_futures_id, active_rider_futures_id,
/// completed_rides, total_driver_earned_cents)` for `identityAddr` (`6 * 32B = 192` bytes).
fn handle_get_actor_state(args: &CalldataReader) -> Result<(), i32> {
    let actor = args.address(0).ok_or(-3)?;
    let mut out = [0u8; 192];
    out[24..32].copy_from_slice(&storage::get_u64(actor_ask_key(&actor).as_slice()).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(actor_bid_key(&actor).as_slice()).to_be_bytes());
    out[88..96]
        .copy_from_slice(&storage::get_u64(actor_drv_fut_key(&actor).as_slice()).to_be_bytes());
    out[120..128]
        .copy_from_slice(&storage::get_u64(actor_rdr_fut_key(&actor).as_slice()).to_be_bytes());
    out[152..160]
        .copy_from_slice(&storage::get_u64(actor_rides_done_key(&actor).as_slice()).to_be_bytes());
    out[184..192]
        .copy_from_slice(&storage::get_u64(actor_earned_key(&actor).as_slice()).to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// On-chain route preview returning `(orig_regime, dest_regime, trip_m, toll_cents, best_feasible_ask_per_km)`
/// (`5 * 32B = 160` bytes).
fn handle_quote_trip_preview(args: &CalldataReader) -> Result<(), i32> {
    let from_lat = decode_coord_u64(args.u64(0).ok_or(-3)?);
    let from_lon = decode_coord_u64(args.u64(1).ok_or(-3)?);
    let to_lat = decode_coord_u64(args.u64(2).ok_or(-3)?);
    let to_lon = decode_coord_u64(args.u64(3).ok_or(-3)?);

    let c_from = GeoCoord::new(from_lat, from_lon);
    let c_to = GeoCoord::new(to_lat, to_lon);
    let cos_bps = storage::get_u64(KEY_COS_LAT_BPS) as u32;
    let road_bps = storage::get_u64(KEY_ROAD_BPS) as u32;
    let trip_m = road_distance_m(c_from, c_to, cos_bps, road_bps);
    let orig = classify_sg_regime(c_from);
    let dest = classify_sg_regime(c_to);
    let toll = get_toll_cents(orig, dest);

    let adj_mask = SG_ADJACENT_MASKS[(orig as usize).min(NUM_REGIMES - 1)];
    let mut best_ask_eff = 0u64;

    let mut cz = 0usize;
    while cz < NUM_REGIMES {
        if (adj_mask & (1 << cz)) == 0 {
            cz += 1;
            continue;
        }
        let at = load_tree(false, cz as u8);
        let mut l = at.best_head;
        let mut lg = 0usize;
        while l != NONE_LVL && lg < MAX_PRICE_LEVELS_PER_BOOK {
            let mut oid = at.node(l).head_order_id;
            let mut og = 0usize;
            while oid != NONE_ORD && og < MAX_ACTIVE_ASKS {
                let Some(drv) = load_order(oid) else { break };
                oid = drv.next_order_id;
                og += 1;
                if (cz as u8) != orig && drv.cross_border == 0 {
                    continue;
                }
                if (drv.dest_mask & (1u32 << dest)) == 0 {
                    continue;
                }
                let pk_m = road_distance_m(
                    GeoCoord::new(drv.lat_e6, drv.lon_e6),
                    c_from,
                    cos_bps,
                    road_bps,
                );
                if pk_m <= drv.max_pickup_m && pk_m.saturating_add(trip_m) <= drv.max_distance_m {
                    let a_eff = if dest == REGIME_REMOTE {
                        drv.rate_per_km_cents.saturating_add(drv.remote_basis_cents)
                    } else {
                        drv.rate_per_km_cents
                    };
                    if best_ask_eff == 0 || a_eff < best_ask_eff {
                        best_ask_eff = a_eff;
                    }
                }
            }
            l = at.node(l).next_worse;
            lg += 1;
        }
        cz += 1;
    }

    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&(orig as u64).to_be_bytes());
    out[56..64].copy_from_slice(&(dest as u64).to_be_bytes());
    out[88..96].copy_from_slice(&trip_m.to_be_bytes());
    out[120..128].copy_from_slice(&toll.to_be_bytes());
    out[152..160].copy_from_slice(&best_ask_eff.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_quote_ledger(_args: &CalldataReader) -> Result<(), i32> {
    let addr = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
    ret::write_address(&addr);
    Ok(())
}

fn handle_escrow_identity(_args: &CalldataReader) -> Result<(), i32> {
    let addr = storage::get_address(KEY_ESCROW_ID).unwrap_or([0u8; 20]);
    ret::write_address(&addr);
    Ok(())
}

fn handle_identity_registry(_args: &CalldataReader) -> Result<(), i32> {
    let addr = storage::get_address(KEY_REGISTRY).unwrap_or([0u8; 20]);
    ret::write_address(&addr);
    Ok(())
}

fn handle_last_matched_block(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_LAST_MATCH_BLK));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::mock;

    const REG_ADDR: [u8; 20] = [0x11; 20];
    const LEDGER_ADDR: [u8; 20] = [0x22; 20];
    const ESCROW_ID: [u8; 20] = [0x33; 20];
    const EXCH_ADDR: [u8; 20] = [0x44; 20];

    const DRV_FAR_CHEAP: [u8; 20] = [0xA1; 20];
    const DRV_CLOSE_TIED: [u8; 20] = [0xA2; 20];
    const DRV_SHORT_RANGE: [u8; 20] = [0xA3; 20];
    const RIDER_1: [u8; 20] = [0xB1; 20];
    const RIDER_2: [u8; 20] = [0xB2; 20];

    fn mock_registry(cd: &[u8]) -> i32 {
        let sel = selector("isValidIdentity(address)");
        if cd.len() >= 36 && cd[0..4] == sel {
            ret::write_bool(true);
            return 32;
        }
        -1
    }

    fn mock_ledger(cd: &[u8]) -> i32 {
        let sel_tx = selector("dexTransfer(address,address,uint64)");
        let sel_bal = selector("balanceOf(address)");
        if cd.len() >= 100 && cd[0..4] == sel_tx {
            let mut from = [0u8; 20];
            let mut to = [0u8; 20];
            from.copy_from_slice(&cd[16..36]);
            to.copy_from_slice(&cd[48..68]);
            let mut ab = [0u8; 8];
            ab.copy_from_slice(&cd[92..100]);
            let amt = u64::from_be_bytes(ab);

            let fk = KeyBuilder::<32>::new().push(b"bal:").push(&from);
            let tk = KeyBuilder::<32>::new().push(b"bal:").push(&to);
            let fb = storage::get_u64(fk.as_slice());
            if fb < amt {
                return -20;
            }
            storage::set_u64(fk.as_slice(), fb - amt);
            storage::set_u64(tk.as_slice(), storage::get_u64(tk.as_slice()) + amt);
            ret::write_bool(true);
            return 32;
        }
        if cd.len() >= 36 && cd[0..4] == sel_bal {
            let mut who = [0u8; 20];
            who.copy_from_slice(&cd[16..36]);
            let k = KeyBuilder::<32>::new().push(b"bal:").push(&who);
            ret::write_u64_word(storage::get_u64(k.as_slice()));
            return 32;
        }
        if cd.len() >= 68 && cd[0..4] == selector("mint(address,uint64)") {
            let mut who = [0u8; 20];
            who.copy_from_slice(&cd[16..36]);
            let mut ab = [0u8; 8];
            ab.copy_from_slice(&cd[60..68]);
            let amt = u64::from_be_bytes(ab);
            let k = KeyBuilder::<32>::new().push(b"bal:").push(&who);
            storage::set_u64(k.as_slice(), storage::get_u64(k.as_slice()) + amt);
            ret::write_bool(true);
            return 32;
        }
        -1
    }

    fn ledger_bal(who: [u8; 20]) -> u64 {
        let cd = CallEncoder::<64>::new(selector("balanceOf(address)")).push_address(&who);
        let res = mock::transact_as(who, LEDGER_ADDR, cd.as_slice()).unwrap();
        let mut b = [0u8; 8];
        b.copy_from_slice(&res[24..32]);
        u64::from_be_bytes(b)
    }

    fn mint_bal(who: [u8; 20], cents: u64) {
        let cd = CallEncoder::<96>::new(selector("mint(address,uint64)"))
            .push_address(&who)
            .push_u64(cents);
        mock::transact_as(who, LEDGER_ADDR, cd.as_slice()).unwrap();
    }

    #[inline]
    fn enc_i32(v: i32) -> u64 {
        (v as u32) as u64
    }

    #[test]
    fn test_aon_matching_resting_maker_and_service_futures_escrow() {
        mock::reset();
        mock::set_self_address(EXCH_ADDR);
        mock::register_hps(REG_ADDR, mock_registry);
        mock::register_hps(LEDGER_ADDR, mock_ledger);
        mock::register_hps(EXCH_ADDR, dispatch_calldata);

        mint_bal(ESCROW_ID, 500_000);
        mint_bal(RIDER_1, 100_000);
        mint_bal(RIDER_2, 100_000);

        mock::set_block_number(10);
        let init_cd = CallEncoder::<256>::new(selector(
            "initialize(address,address,address,string,uint64,uint64)",
        ))
        .push_address(&REG_ADDR)
        .push_address(&LEDGER_ADDR)
        .push_address(&ESCROW_ID)
        .push_u64(192) // dynamic string offset = 6 * 32
        .push_u64(SG_COS_LAT_BPS as u64)
        .push_u64(SG_ROAD_FACTOR_BPS as u64)
        .push_dynamic_bytes_tail(b"Singapore Metro");
        mock::transact_as(ESCROW_ID, EXCH_ADDR, init_cd.as_slice()).unwrap();

        // Marina Bay (1.2834, 103.8607) -> Changi T3 (1.3562, 103.9885) (~21.9 km, CBD ERP = $3.00 = 300c)
        let mb_lat = enc_i32(1_283_400);
        let mb_lon = enc_i32(103_860_700);
        let ch_lat = enc_i32(1_356_200);
        let ch_lon = enc_i32(103_988_500);

        // Block 11: Post 3 Driver Asks in CBD:
        // 1) DRV_SHORT_RANGE asks $1.00/km (100c), max_distance = 10 km -> MUST FAIL AON on a 21.9 km trip!
        let ask_short = CallEncoder::<320>::new(selector(
            "upsertDriverAsk(uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)",
        ))
        .push_u64(mb_lat)
        .push_u64(mb_lon)
        .push_u64(100) // $1.00/km
        .push_u64(10_000) // 10 km cap (< 21.9 km trip!)
        .push_u64(4_000)
        .push_u64(0x3F)
        .push_u64(40)
        .push_bool(true);
        mock::set_block_number(11);
        mock::transact_as(DRV_SHORT_RANGE, EXCH_ADDR, ask_short.as_slice()).unwrap();

        // 2) DRV_FAR_CHEAP asks $1.40/km (140c), ~1.5 km away from Marina Bay, max_distance = 35 km
        let ask_far = CallEncoder::<320>::new(selector(
            "upsertDriverAsk(uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)",
        ))
        .push_u64(enc_i32(1_275_000))
        .push_u64(enc_i32(103_852_000))
        .push_u64(140)
        .push_u64(35_000)
        .push_u64(5_000)
        .push_u64(0x3F)
        .push_u64(40)
        .push_bool(true);
        mock::transact_as(DRV_FAR_CHEAP, EXCH_ADDR, ask_far.as_slice()).unwrap();

        // 3) DRV_CLOSE_TIED ALSO asks $1.40/km (140c), 100 m away from Marina Bay -> MUST WIN TIE BY PROXIMITY!
        let ask_close = CallEncoder::<320>::new(selector(
            "upsertDriverAsk(uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)",
        ))
        .push_u64(enc_i32(1_283_500))
        .push_u64(enc_i32(103_860_800))
        .push_u64(140)
        .push_u64(35_000)
        .push_u64(5_000)
        .push_u64(0x3F)
        .push_u64(40)
        .push_bool(true);
        mock::transact_as(DRV_CLOSE_TIED, EXCH_ADDR, ask_close.as_slice()).unwrap();

        // Block 12: Ingest resting Driver Asks into CBD AskBook
        mock::set_block_number(12);
        let mb_cd = CallEncoder::<32>::new(selector("matchBlock()"));
        mock::transact_as(ESCROW_ID, EXCH_ADDR, mb_cd.as_slice()).unwrap();

        // Block 13: RIDER_1 (Taker!) bids $2.00/km (200c) for Marina Bay -> Changi T3
        mock::set_block_number(13);
        let bid_cd = CallEncoder::<256>::new(selector(
            "postRiderBid(uint64,uint64,uint64,uint64,uint64,uint64)",
        ))
        .push_u64(mb_lat)
        .push_u64(mb_lon)
        .push_u64(ch_lat)
        .push_u64(ch_lon)
        .push_u64(200) // $2.00/km bid (crosses resting $1.40/km ask!)
        .push_u64(4_000);
        mock::transact_as(RIDER_1, EXCH_ADDR, bid_cd.as_slice()).unwrap();

        let bal_after_bid = ledger_bal(RIDER_1);
        assert!(bal_after_bid < 100_000);

        // Block 14: Run matchBlock() -> DRV_SHORT_RANGE ($1.00/km, 10 km cap) skipped by AON;
        // DRV_CLOSE_TIED ($1.40/km, 100m away) beats DRV_FAR_CHEAP ($1.40/km, 1.5km away) on proximity;
        // Executes at Resting Maker rate ($1.40/km = 140c) * trip_m ONLY + 300c ERP toll!
        mock::set_block_number(14);
        let m_out = mock::transact_as(ESCROW_ID, EXCH_ADDR, mb_cd.as_slice()).unwrap();
        assert_eq!(m_out[31], 1); // 1 ride matched!

        let fut = load_futures(1).expect("futures #1");
        assert_eq!(fut.driver, DRV_CLOSE_TIED);
        assert_eq!(fut.rider, RIDER_1);
        assert_eq!(fut.maker_side, MAKER_DRIVER);
        assert_eq!(fut.clearing_rate_cents, 140);
        assert_eq!(fut.toll_cents, 300);
        assert_eq!(fut.status, FUT_STATUS_MATCHED);

        // Verify Rider immediately received the ($2.00 - $1.40)/km price-improvement refund,
        // AND Driver has received $0.00 so far because the Ride Futures contract is NOT settled yet!
        let expected_locked = fut.clean_fare_cents + fut.toll_cents;
        assert_eq!(ledger_bal(RIDER_1), 100_000 - expected_locked);
        assert_eq!(ledger_bal(DRV_CLOSE_TIED), 0);

        // Non-rider (e.g. Driver) CANNOT forge `completeRide`!
        let comp_cd = CallEncoder::<64>::new(selector("completeRide(uint64)")).push_u64(1);
        assert_eq!(
            mock::transact_as(DRV_CLOSE_TIED, EXCH_ADDR, comp_cd.as_slice()),
            Err(ERR_NOT_FUTURES_PARTY)
        );

        // Customer signs `completeRide(1)` -> escrowed funds release atomically to DRV_CLOSE_TIED!
        mock::set_block_number(18);
        mock::transact_as(RIDER_1, EXCH_ADDR, comp_cd.as_slice()).unwrap();
        assert_eq!(ledger_bal(DRV_CLOSE_TIED), expected_locked);
        assert_eq!(load_futures(1).unwrap().status, FUT_STATUS_SETTLED);
    }

    #[test]
    fn test_driver_taker_crosses_resting_rider_bid_and_remote_basis() {
        mock::reset();
        mock::set_self_address(EXCH_ADDR);
        mock::register_hps(REG_ADDR, mock_registry);
        mock::register_hps(LEDGER_ADDR, mock_ledger);
        mock::register_hps(EXCH_ADDR, dispatch_calldata);

        mint_bal(ESCROW_ID, 500_000);
        mint_bal(RIDER_2, 100_000);

        mock::set_block_number(5);
        let init_cd = CallEncoder::<256>::new(selector(
            "initialize(address,address,address,string,uint64,uint64)",
        ))
        .push_address(&REG_ADDR)
        .push_address(&LEDGER_ADDR)
        .push_address(&ESCROW_ID)
        .push_u64(192)
        .push_u64(SG_COS_LAT_BPS as u64)
        .push_u64(SG_ROAD_FACTOR_BPS as u64)
        .push_dynamic_bytes_tail(b"Singapore Metro");
        mock::transact_as(ESCROW_ID, EXCH_ADDR, init_cd.as_slice()).unwrap();

        // Jurong East (1.3329, 103.7436) -> Tuas South Remote (1.2950, 103.6360)
        let je_lat = enc_i32(1_332_900);
        let je_lon = enc_i32(103_743_600);
        let tu_lat = enc_i32(1_295_000);
        let tu_lon = enc_i32(103_636_000);

        // Block 6: RIDER_2 posts Resting Bid @ $2.40/km (240c) for Jurong East -> Tuas Remote
        mock::set_block_number(6);
        let bid_cd = CallEncoder::<256>::new(selector(
            "postRiderBid(uint64,uint64,uint64,uint64,uint64,uint64)",
        ))
        .push_u64(je_lat)
        .push_u64(je_lon)
        .push_u64(tu_lat)
        .push_u64(tu_lon)
        .push_u64(240)
        .push_u64(4_000);
        mock::transact_as(RIDER_2, EXCH_ADDR, bid_cd.as_slice()).unwrap();

        // Block 7: Ingest RIDER_2's bid as Resting Maker in Jurong West BidBook
        let mb_cd = CallEncoder::<32>::new(selector("matchBlock()"));
        mock::set_block_number(7);
        mock::transact_as(ESCROW_ID, EXCH_ADDR, mb_cd.as_slice()).unwrap();

        // Block 8: Driver arrives later (Taker!) asking $1.50/km base + $0.50/km remote basis ($2.00/km eff <= $2.40/km)
        mock::set_block_number(8);
        let ask_cd = CallEncoder::<320>::new(selector(
            "upsertDriverAsk(uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)",
        ))
        .push_u64(enc_i32(1_333_200))
        .push_u64(enc_i32(103_744_000))
        .push_u64(150) // base $1.50/km
        .push_u64(30_000)
        .push_u64(4_000)
        .push_u64(0x3F) // accepts Remote
        .push_u64(50) // +$0.50/km remote basis -> $2.00/km eff
        .push_bool(true);
        mock::transact_as(DRV_FAR_CHEAP, EXCH_ADDR, ask_cd.as_slice()).unwrap();

        // Block 9: matchBlock() -> RIDER_2 was Resting Maker (blk 6 < blk 8), so clearing_rate MUST be 240c!
        mock::set_block_number(9);
        let m_out = mock::transact_as(ESCROW_ID, EXCH_ADDR, mb_cd.as_slice()).unwrap();
        assert_eq!(m_out[31], 1);

        let fut = load_futures(1).expect("futures #1");
        assert_eq!(fut.maker_side, MAKER_RIDER);
        assert_eq!(fut.clearing_rate_cents, 240);
        assert_eq!(fut.toll_cents, 400); // Remote gate surcharge
    }
}
