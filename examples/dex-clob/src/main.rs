//! Discrete-Time FIFO Central Limit Orderbook (CLOB) DEX **Haltproof Subroutine (HPS)** built with `hps-sdk`.
//!
//! Can be attached to any `AssetLedger` (via `AssetLedger.setAttachedDex(dexHps, authObj)`) to turn
//! that ledger into its own exchange.
//!
//! ### Two-Tier Institutional Orderbook Data Structure (Zero Element Shifting)
//! 1. **Tier 1 — Static Arena AVL Price-Level Tree (`PriceLevelArena`)**:
//!    - Distinct active prices on each side (Bids `price DESC`, Asks `price ASC`) are stored in a
//!      fixed-capacity arena-backed **AVL Balanced Binary Search Tree** (`MAX_PRICE_LEVELS = 128` per
//!      side) augmented with threaded `best_head <-> next_worse / prev_better <-> worst_tail` links
//!      and an $O(1)$ **free-list** (`free_head`) that recycles emptied price-level slots indefinitely.
//!    - Hitting an existing price level takes $O(\log M)$ comparisons in WASM RAM with **0 rotations
//!      and 0 element shifts**. Opening or removing a price level takes $O(\log M)$ comparisons and
//!      at most $\le 2$ pointer rotations (**0 element shifts**).
//! 2. **Tier 2 — Intrusive Doubly-Linked FIFO Order Queues (`prev_order_id`, `next_order_id`)**:
//!    - Both the Pending Intake Queue (`KEY_PENDING_HEAD`..`KEY_PENDING_TAIL`) and each Price Level's
//!      resting order queue (`head_order_id`..`tail_order_id`) are intrusive doubly-linked lists.
//!    - Because block numbers increase monotonically over time, newly ingested orders at any price
//!      level **always append to the tail in $O(1)$** (zero middle insertions, zero shifts).
//!    - Cancelling any pending or resting order anywhere in the book unlinks `prev <-> next` in **$O(1)$**
//!      (zero array scans, zero element shifts).
//!    - Top-of-book clearing (`matchBlock()`) checks `best_head` in $O(1)$, computes the single
//!      clearing price $P^*$ purely from crossing `PriceLevelNode` aggregates in $O(M_{\text{cross}})$
//!      without reading non-crossing orders, and loads crossing orders only up to the marginal
//!      `(price, block_number)` cohort.
//!
//! ### MEV-Proof Matching Rules
//! - **Strict Prior-Block Cutoff**: `matchBlock()` only ingests pending orders with
//!   `order.block_number < current_block`, preventing intra-block front-running, back-running, and
//!   sandwiching.
//! - **Single Clearing Price & Cohort Pro-Rata**: Crossing orders execute at a single clearing price
//!   $P^*$ in strict `(price, block_number)` cohort priority. Orders sharing the marginal
//!   `(price, block_number)` cohort have equal priority and are filled pro-rata via exact
//!   permutation-invariant integer floor $\lfloor \text{rem} \times \text{qty}_i / Q_{\text{cohort}} \rfloor$.

#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::call::{self, CallEncoder};
use hps_sdk::governance::{
    require_valid_identity, ERR_ALREADY_EXECUTED_IN_BLOCK, ERR_INVALID_DEX_ORDER,
    ERR_NOT_ORDER_OWNER, ERR_NO_CROSSING_ORDERS, ERR_ORDERBOOK_FULL, ERR_ORDER_ALREADY_CANCELLED,
    ERR_ORDER_NOT_FOUND,
};
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, selector, storage};

/// Maximum distinct active price levels per side (128 Bid levels + 128 Ask levels = 256 levels).
pub const MAX_PRICE_LEVELS: usize = 128;
/// Maximum concurrently active resting orders per side (slots recycle as orders fill or cancel).
pub const MAX_ACTIVE_ORDERS: usize = 256;
/// Maximum pending orders awaiting next-block ingestion.
pub const MAX_PENDING_ORDERS: usize = 128;

const NONE_LVL: u16 = 0;
const NONE_ORD: u64 = 0;

const TREE_HEADER_BYTES: usize = 12;
const LEVEL_NODE_BYTES: usize = 48;
const MAX_TREE_BYTES: usize = TREE_HEADER_BYTES + MAX_PRICE_LEVELS * LEVEL_NODE_BYTES;
const ORDER_RECORD_BYTES: usize = 78;

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
const KEY_PENDING_HEAD: &[u8] = b"dex:p_head";
const KEY_PENDING_TAIL: &[u8] = b"dex:p_tail";
const KEY_PENDING_COUNT: &[u8] = b"dex:p_cnt";
const KEY_ACTIVE_BIDS: &[u8] = b"dex:ab_cnt";
const KEY_ACTIVE_ASKS: &[u8] = b"dex:aa_cnt";
const KEY_BID_TREE: &[u8] = b"dex:bid_tree";
const KEY_ASK_TREE: &[u8] = b"dex:ask_tree";

const KEY_SETTLED_SET: &[u8] = b"dex:st_set";
const KEY_SETTLED_BLOCK: &[u8] = b"dex:st_blk";
const KEY_LAST_MATCH_EXEC_SET: &[u8] = b"dex:lm_set";
const KEY_EXPLICIT_MATCH_BLOCK: &[u8] = b"dex:em_blk";
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
    "lastMatchedBlock()"                          => handle_last_matched_block,
    "getOrder(uint64)"                            => handle_get_order,
    "orderCount()"                                => handle_order_count,
    "bookDepth()"                                 => handle_book_depth,
    "priceLevelDepth()"                           => handle_price_level_depth,
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
    pub prev_order_id: u64,
    pub next_order_id: u64,
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
            prev_order_id: 0,
            next_order_id: 0,
        }
    }
}

/// Arena node in the static AVL Price-Level Tree (`1`-based indices; `0 = NONE_LVL`).
/// Left child holds strictly *better* prices (`price > self.price` for Bids, `price < self.price`
/// for Asks); Right child holds strictly *worse* prices.
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
    pub nodes: [PriceLevelNode; MAX_PRICE_LEVELS],
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
            nodes: [PriceLevelNode::default(); MAX_PRICE_LEVELS],
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
            if (self.high_water as usize) >= MAX_PRICE_LEVELS {
                return Err(ERR_ORDERBOOK_FULL);
            }
            self.high_water += 1;
            self.high_water
        };

        *self.node_mut(idx) = PriceLevelNode {
            price,
            total_qty: 0,
            head_order_id: NONE_ORD,
            tail_order_id: NONE_ORD,
            left: NONE_LVL,
            right: NONE_LVL,
            parent: NONE_LVL,
            prev_better: NONE_LVL,
            next_worse: NONE_LVL,
            order_count: 0,
            height: 1,
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

    /// $O(\log M)$ AVL lookup of an existing price level.
    pub fn find_price(&self, price: u64) -> u16 {
        let mut cur = self.root;
        let mut guard = 0usize;
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS {
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

    /// $O(\log M)$ AVL lookup or insertion of `price` with zero array shifting.
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
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS {
            let cur_px = self.node(cur).price;
            if price == cur_px {
                return Ok(cur);
            }
            parent = cur;
            go_left = self.is_better(price, cur_px);
            cur = if go_left {
                self.node(cur).left
            } else {
                self.node(cur).right
            };
            guard += 1;
        }

        let idx = self.alloc_node(price)?;
        self.node_mut(idx).parent = parent;
        if go_left {
            // `idx` is immediately better than `parent` in priority order
            let pred = self.node(parent).prev_better;
            self.node_mut(parent).left = idx;
            self.node_mut(idx).prev_better = pred;
            self.node_mut(idx).next_worse = parent;
            self.node_mut(parent).prev_better = idx;
            if pred != NONE_LVL {
                self.node_mut(pred).next_worse = idx;
            } else {
                self.best_head = idx;
            }
        } else {
            // `idx` is immediately worse than `parent` in priority order
            let succ = self.node(parent).next_worse;
            self.node_mut(parent).right = idx;
            self.node_mut(idx).prev_better = parent;
            self.node_mut(idx).next_worse = succ;
            self.node_mut(parent).next_worse = idx;
            if succ != NONE_LVL {
                self.node_mut(succ).prev_better = idx;
            } else {
                self.worst_tail = idx;
            }
        }

        self.rebalance_up(parent);
        Ok(idx)
    }

    fn rotate_left(&mut self, x: u16) -> u16 {
        let y = self.node(x).right;
        let yl = self.node(y).left;
        let xp = self.node(x).parent;

        self.node_mut(x).right = yl;
        if yl != NONE_LVL {
            self.node_mut(yl).parent = x;
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
        let yr = self.node(y).right;
        let xp = self.node(x).parent;

        self.node_mut(x).left = yr;
        if yr != NONE_LVL {
            self.node_mut(yr).parent = x;
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
        while cur != NONE_LVL && guard < MAX_PRICE_LEVELS {
            self.update_height(cur);
            let bf = self.balance_factor(cur);
            let sub_root = if bf > 1 {
                let lc = self.node(cur).left;
                if self.balance_factor(lc) < 0 {
                    self.rotate_left(lc);
                }
                self.rotate_right(cur)
            } else if bf < -1 {
                let rc = self.node(cur).right;
                if self.balance_factor(rc) > 0 {
                    self.rotate_right(rc);
                }
                self.rotate_left(cur)
            } else {
                cur
            };
            cur = self.node(sub_root).parent;
            guard += 1;
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

    fn minimum_in_subtree(&self, mut idx: u16) -> u16 {
        let mut guard = 0usize;
        while self.node(idx).left != NONE_LVL && guard < MAX_PRICE_LEVELS {
            idx = self.node(idx).left;
            guard += 1;
        }
        idx
    }

    /// $O(\log M)$ AVL removal of an emptied price level + $O(1)$ threaded unlink & slot recycle.
    pub fn remove_node(&mut self, z: u16) {
        if z == NONE_LVL {
            return;
        }

        // 1. Unlink `z` from threaded priority list in O(1)
        let pb = self.node(z).prev_better;
        let nw = self.node(z).next_worse;
        if pb != NONE_LVL {
            self.node_mut(pb).next_worse = nw;
        } else {
            self.best_head = nw;
        }
        if nw != NONE_LVL {
            self.node_mut(nw).prev_better = pb;
        } else {
            self.worst_tail = pb;
        }

        // 2. Remove `z` from AVL BST by index (preserving all other node indices)
        let zl = self.node(z).left;
        let zr = self.node(z).right;
        let rebalance_start = if zl == NONE_LVL {
            let zp = self.node(z).parent;
            self.transplant(z, zr);
            zp
        } else if zr == NONE_LVL {
            let zp = self.node(z).parent;
            self.transplant(z, zl);
            zp
        } else {
            let y = self.minimum_in_subtree(zr);
            let yp = self.node(y).parent;
            let yr = self.node(y).right;
            let zh = self.node(z).height;
            if yp == z {
                self.transplant(z, y);
                self.node_mut(y).left = zl;
                self.node_mut(zl).parent = y;
                self.node_mut(y).height = zh;
                y
            } else {
                self.transplant(y, yr);
                self.node_mut(y).right = zr;
                self.node_mut(zr).parent = y;
                self.transplant(z, y);
                self.node_mut(y).left = zl;
                self.node_mut(zl).parent = y;
                self.node_mut(y).height = zh;
                yp
            }
        };

        self.rebalance_up(rebalance_start);
        self.free_node(z);
    }
}

fn load_tree(key: &[u8], is_bid: bool) -> PriceLevelArena {
    let mut tree = PriceLevelArena::new(is_bid);
    let mut raw = [0u8; MAX_TREE_BYTES];
    let Some(len) = storage::get_into(key, &mut raw) else {
        return tree;
    };
    if len < TREE_HEADER_BYTES {
        return tree;
    }
    tree.root = u16::from_be_bytes([raw[0], raw[1]]);
    tree.best_head = u16::from_be_bytes([raw[2], raw[3]]);
    tree.worst_tail = u16::from_be_bytes([raw[4], raw[5]]);
    tree.active_levels = u16::from_be_bytes([raw[6], raw[7]]);
    let hw = (u16::from_be_bytes([raw[8], raw[9]]) as usize).min(MAX_PRICE_LEVELS);
    tree.high_water = hw as u16;
    tree.free_head = u16::from_be_bytes([raw[10], raw[11]]);

    let avail_nodes = (len - TREE_HEADER_BYTES) / LEVEL_NODE_BYTES;
    let count = hw.min(avail_nodes);
    let mut i = 0usize;
    while i < count {
        let b = TREE_HEADER_BYTES + i * LEVEL_NODE_BYTES;
        tree.nodes[i] = PriceLevelNode {
            price: u64::from_be_bytes([
                raw[b],
                raw[b + 1],
                raw[b + 2],
                raw[b + 3],
                raw[b + 4],
                raw[b + 5],
                raw[b + 6],
                raw[b + 7],
            ]),
            total_qty: u64::from_be_bytes([
                raw[b + 8],
                raw[b + 9],
                raw[b + 10],
                raw[b + 11],
                raw[b + 12],
                raw[b + 13],
                raw[b + 14],
                raw[b + 15],
            ]),
            head_order_id: u64::from_be_bytes([
                raw[b + 16],
                raw[b + 17],
                raw[b + 18],
                raw[b + 19],
                raw[b + 20],
                raw[b + 21],
                raw[b + 22],
                raw[b + 23],
            ]),
            tail_order_id: u64::from_be_bytes([
                raw[b + 24],
                raw[b + 25],
                raw[b + 26],
                raw[b + 27],
                raw[b + 28],
                raw[b + 29],
                raw[b + 30],
                raw[b + 31],
            ]),
            left: u16::from_be_bytes([raw[b + 32], raw[b + 33]]),
            right: u16::from_be_bytes([raw[b + 34], raw[b + 35]]),
            parent: u16::from_be_bytes([raw[b + 36], raw[b + 37]]),
            prev_better: u16::from_be_bytes([raw[b + 38], raw[b + 39]]),
            next_worse: u16::from_be_bytes([raw[b + 40], raw[b + 41]]),
            order_count: u16::from_be_bytes([raw[b + 42], raw[b + 43]]),
            height: raw[44 + b],
        };
        i += 1;
    }
    tree
}

fn store_tree(key: &[u8], tree: &PriceLevelArena) {
    let mut raw = [0u8; MAX_TREE_BYTES];
    let hw = (tree.high_water as usize).min(MAX_PRICE_LEVELS);
    raw[0..2].copy_from_slice(&tree.root.to_be_bytes());
    raw[2..4].copy_from_slice(&tree.best_head.to_be_bytes());
    raw[4..6].copy_from_slice(&tree.worst_tail.to_be_bytes());
    raw[6..8].copy_from_slice(&tree.active_levels.to_be_bytes());
    raw[8..10].copy_from_slice(&(hw as u16).to_be_bytes());
    raw[10..12].copy_from_slice(&tree.free_head.to_be_bytes());

    let mut i = 0usize;
    while i < hw {
        let b = TREE_HEADER_BYTES + i * LEVEL_NODE_BYTES;
        let n = &tree.nodes[i];
        raw[b..b + 8].copy_from_slice(&n.price.to_be_bytes());
        raw[b + 8..b + 16].copy_from_slice(&n.total_qty.to_be_bytes());
        raw[b + 16..b + 24].copy_from_slice(&n.head_order_id.to_be_bytes());
        raw[b + 24..b + 32].copy_from_slice(&n.tail_order_id.to_be_bytes());
        raw[b + 32..b + 34].copy_from_slice(&n.left.to_be_bytes());
        raw[b + 34..b + 36].copy_from_slice(&n.right.to_be_bytes());
        raw[b + 36..b + 38].copy_from_slice(&n.parent.to_be_bytes());
        raw[b + 38..b + 40].copy_from_slice(&n.prev_better.to_be_bytes());
        raw[b + 40..b + 42].copy_from_slice(&n.next_worse.to_be_bytes());
        raw[b + 42..b + 44].copy_from_slice(&n.order_count.to_be_bytes());
        raw[b + 44] = n.height;
        i += 1;
    }
    let total_len = TREE_HEADER_BYTES + hw * LEVEL_NODE_BYTES;
    storage::set(key, &raw[..total_len]);
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
    let mut raw = [0u8; ORDER_RECORD_BYTES];
    raw[0..8].copy_from_slice(&ord.order_id.to_be_bytes());
    raw[8..28].copy_from_slice(&ord.trader);
    raw[28] = ord.side;
    raw[29] = ord.status;
    raw[30..38].copy_from_slice(&ord.price.to_be_bytes());
    raw[38..46].copy_from_slice(&ord.orig_qty.to_be_bytes());
    raw[46..54].copy_from_slice(&ord.rem_qty.to_be_bytes());
    raw[54..62].copy_from_slice(&ord.block_number.to_be_bytes());
    raw[62..70].copy_from_slice(&ord.prev_order_id.to_be_bytes());
    raw[70..78].copy_from_slice(&ord.next_order_id.to_be_bytes());
    let ok = order_key(ord.order_id);
    storage::set(ok.as_slice(), &raw);
}

fn load_order(order_id: u64) -> Option<DexOrder> {
    if order_id == NONE_ORD {
        return None;
    }
    let ok = order_key(order_id);
    let mut raw = [0u8; ORDER_RECORD_BYTES];
    match storage::get_into(ok.as_slice(), &mut raw) {
        Some(ORDER_RECORD_BYTES) => {
            let id = u64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            if id == NONE_ORD {
                return None;
            }
            let mut trader = [0u8; 20];
            trader.copy_from_slice(&raw[8..28]);
            Some(DexOrder {
                order_id: id,
                trader,
                side: raw[28],
                status: raw[29],
                price: u64::from_be_bytes([
                    raw[30], raw[31], raw[32], raw[33], raw[34], raw[35], raw[36], raw[37],
                ]),
                orig_qty: u64::from_be_bytes([
                    raw[38], raw[39], raw[40], raw[41], raw[42], raw[43], raw[44], raw[45],
                ]),
                rem_qty: u64::from_be_bytes([
                    raw[46], raw[47], raw[48], raw[49], raw[50], raw[51], raw[52], raw[53],
                ]),
                block_number: u64::from_be_bytes([
                    raw[54], raw[55], raw[56], raw[57], raw[58], raw[59], raw[60], raw[61],
                ]),
                prev_order_id: u64::from_be_bytes([
                    raw[62], raw[63], raw[64], raw[65], raw[66], raw[67], raw[68], raw[69],
                ]),
                next_order_id: u64::from_be_bytes([
                    raw[70], raw[71], raw[72], raw[73], raw[74], raw[75], raw[76], raw[77],
                ]),
            })
        }
        _ => None,
    }
}

/// $O(1)$ tail append onto a `PriceLevelNode`'s intrusive doubly-linked FIFO order queue.
/// Because block numbers increase monotonically over time, newly ingested orders at any price
/// level ALWAYS belong at the tail — zero middle insertions and zero element shifts.
fn append_order_to_level(tree: &mut PriceLevelArena, lvl_idx: u16, ord: &mut DexOrder) {
    let old_tail = tree.node(lvl_idx).tail_order_id;
    ord.status = STATUS_ACTIVE;
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
    lvl.total_qty = lvl.total_qty.saturating_add(ord.rem_qty);
    lvl.order_count = lvl.order_count.saturating_add(1);
    store_order(ord);
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

/// $O(1)$ order placement: escrows funds/assets and appends directly to `KEY_PENDING_TAIL`
/// in the intrusive doubly-linked Pending Queue without reading or shifting any array.
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

    let pending_count = storage::get_u64(KEY_PENDING_COUNT);
    if (pending_count as usize) >= MAX_PENDING_ORDERS {
        return Err(ERR_ORDERBOOK_FULL);
    }

    let active_side_cnt = if side == SIDE_BID {
        storage::get_u64(KEY_ACTIVE_BIDS)
    } else {
        storage::get_u64(KEY_ACTIVE_ASKS)
    };
    if (active_side_cnt as usize) >= MAX_ACTIVE_ORDERS {
        return Err(ERR_ORDERBOOK_FULL);
    }

    // Escrow quote cash (Bids) or base asset units (Asks) into `escrowIdentity`
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

    let order_id = storage::get_u64(KEY_ORDER_COUNT)
        .checked_add(1)
        .ok_or(-15)?;
    let arrival_block = context::block_number();
    let old_tail = storage::get_u64(KEY_PENDING_TAIL);

    let ord = DexOrder {
        order_id,
        trader: caller,
        side,
        status: STATUS_PENDING,
        price,
        orig_qty: quantity,
        rem_qty: quantity,
        block_number: arrival_block,
        prev_order_id: old_tail,
        next_order_id: NONE_ORD,
    };

    if old_tail != NONE_ORD {
        if let Some(mut tail_ord) = load_order(old_tail) {
            tail_ord.next_order_id = order_id;
            store_order(&tail_ord);
        }
    } else {
        storage::set_u64(KEY_PENDING_HEAD, order_id);
    }

    store_order(&ord);
    storage::set_u64(KEY_PENDING_TAIL, order_id);
    storage::set_u64(KEY_PENDING_COUNT, pending_count + 1);
    storage::set_u64(KEY_ORDER_COUNT, order_id);

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

/// $O(1)$ intrusive doubly-linked list unlink (+ $O(\log M)$ AVL delete only if the price level
/// becomes empty) and immediate escrow refund.
///
/// **Last-Look MEV Prevention**: If `order_id` was placed in a prior block (`ord.block_number < current_block`),
/// any sealed prior-block (`< current_block`) cohorts are atomically settled *first* via
/// `settle_prior_cohorts_if_needed(current_block)` before unlinking — guaranteeing `[cancelOrder, matchBlock]`
/// and `[matchBlock, cancelOrder]` produce bit-for-bit identical fills regardless of canonical `(from, nonce)`
/// intra-block transaction ordering.
fn handle_cancel_order(args: &CalldataReader) -> Result<(), i32> {
    let (_registry, caller) = ensure_initialized_and_valid_caller()?;
    let order_id = args.u64(0).ok_or(-3)?;
    let pre_ord = load_order(order_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if pre_ord.trader != caller {
        return Err(ERR_NOT_ORDER_OWNER);
    }
    if pre_ord.status == STATUS_CANCELLED || pre_ord.status == STATUS_FILLED || pre_ord.rem_qty == 0
    {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }

    let current_block = context::block_number();
    if pre_ord.block_number < current_block {
        settle_prior_cohorts_if_needed(current_block)?;
    }

    let mut ord = load_order(order_id).ok_or(ERR_ORDER_NOT_FOUND)?;
    if ord.status == STATUS_FILLED || ord.rem_qty == 0 {
        // Order filled completely during sealed prior-block cohort clearing; keep fills committed!
        ret::write_u64_word(0);
        return Ok(());
    }
    if ord.status == STATUS_CANCELLED {
        return Err(ERR_ORDER_ALREADY_CANCELLED);
    }

    let refund_qty = ord.rem_qty;
    let prev_status = ord.status;
    let prev_id = ord.prev_order_id;
    let next_id = ord.next_order_id;

    if prev_status == STATUS_PENDING {
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

        let p_cnt = storage::get_u64(KEY_PENDING_COUNT);
        storage::set_u64(KEY_PENDING_COUNT, p_cnt.saturating_sub(1));
    } else {
        let (tree_key, cnt_key, is_bid) = if ord.side == SIDE_BID {
            (KEY_BID_TREE, KEY_ACTIVE_BIDS, true)
        } else {
            (KEY_ASK_TREE, KEY_ACTIVE_ASKS, false)
        };
        let mut tree = load_tree(tree_key, is_bid);
        let lvl_idx = tree.find_price(ord.price);
        if lvl_idx != NONE_LVL {
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
            lvl.total_qty = lvl.total_qty.saturating_sub(refund_qty);
            lvl.order_count = lvl.order_count.saturating_sub(1);
            if lvl.order_count == 0 || lvl.total_qty == 0 {
                tree.remove_node(lvl_idx);
            }
            store_tree(tree_key, &tree);
        }
        let act_cnt = storage::get_u64(cnt_key);
        storage::set_u64(cnt_key, act_cnt.saturating_sub(1));
    }

    ord.status = STATUS_CANCELLED;
    ord.rem_qty = 0;
    ord.prev_order_id = NONE_ORD;
    ord.next_order_id = NONE_ORD;
    store_order(&ord);

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

/// Load crossing orders from `tree` (starting at `tree.best_head`) ONLY up to and including the
/// marginal `(price, block_number)` cohort needed to satisfy `max_target_volume`.
/// Orders at non-crossing levels or worse cohorts beyond the marginal cohort are never read.
fn load_crossing_cohorts(
    tree: &PriceLevelArena,
    clearing_price: u64,
    max_target_volume: u64,
    out_orders: &mut [DexOrder; MAX_ACTIVE_ORDERS],
    out_lvl_idxs: &mut [u16; MAX_ACTIVE_ORDERS],
) -> usize {
    let mut count = 0usize;
    let mut accum_qty = 0u64;
    let mut lvl_idx = tree.best_head;
    let mut lvl_guard = 0usize;

    while lvl_idx != NONE_LVL && accum_qty < max_target_volume && lvl_guard < MAX_PRICE_LEVELS {
        let lvl = tree.node(lvl_idx);
        let crosses = if tree.is_bid {
            lvl.price >= clearing_price
        } else {
            lvl.price <= clearing_price
        };
        if !crosses {
            break;
        }

        let mut oid = lvl.head_order_id;
        while oid != NONE_ORD && accum_qty < max_target_volume && count < MAX_ACTIVE_ORDERS {
            let Some(first_ord) = load_order(oid) else {
                break;
            };
            let cohort_block = first_ord.block_number;
            let mut cohort_qty = first_ord.rem_qty;
            let mut next_oid = first_ord.next_order_id;
            out_orders[count] = first_ord;
            out_lvl_idxs[count] = lvl_idx;
            count += 1;

            // Load any remaining orders in the exact same `(price, block_number)` cohort so
            // equal-priority pro-rata has the full cohort total.
            while next_oid != NONE_ORD && count < MAX_ACTIVE_ORDERS {
                let Some(next_ord) = load_order(next_oid) else {
                    next_oid = NONE_ORD;
                    break;
                };
                if next_ord.block_number != cohort_block {
                    break;
                }
                cohort_qty = cohort_qty.saturating_add(next_ord.rem_qty);
                next_oid = next_ord.next_order_id;
                out_orders[count] = next_ord;
                out_lvl_idxs[count] = lvl_idx;
                count += 1;
            }

            accum_qty = accum_qty.saturating_add(cohort_qty);
            oid = next_oid;
        }

        lvl_idx = lvl.next_worse;
        lvl_guard += 1;
    }

    count
}

/// Allocate fills across loaded crossing orders (`orders[0..count]`) for `target_volume`
/// following strict `(price, block_number)` cohort priority and exact integer-floor pro-rata
/// within any marginal `(price, block_number)` cohort.
fn allocate_cohort_fills(
    orders: &[DexOrder; MAX_ACTIVE_ORDERS],
    count: usize,
    target_volume: u64,
    fills: &mut [u64; MAX_ACTIVE_ORDERS],
) -> u64 {
    let mut z = 0usize;
    while z < count {
        fills[z] = 0;
        z += 1;
    }

    let mut rem_to_fill = target_volume;
    let mut total_filled = 0u64;
    let mut idx = 0usize;

    while idx < count && rem_to_fill > 0 {
        let cohort_price = orders[idx].price;
        let cohort_block = orders[idx].block_number;

        let mut end = idx + 1;
        while end < count
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
            k = idx;
            while k < end {
                fills[k] = orders[k].rem_qty;
                total_filled = total_filled.saturating_add(fills[k]);
                k += 1;
            }
            rem_to_fill -= cohort_qty;
        } else {
            // Marginal `(price, block_number)` cohort: equal priority -> permutation-invariant
            // pro-rata fill using exact integer floor `floor(rem_to_fill * rem_qty_k / cohort_qty)`.
            k = idx;
            while k < end {
                let num = (rem_to_fill as u128) * (orders[k].rem_qty as u128);
                let fl = (num / (cohort_qty as u128)) as u64;
                fills[k] = fl;
                total_filled = total_filled.saturating_add(fl);
                k += 1;
            }
            rem_to_fill = 0;
        }

        idx = end;
    }

    total_filled
}

/// Apply updated order states for a loaded prefix `orders[0..count]` back to `tree` and KV storage,
/// relinking surviving partially-filled orders to any unloaded tail orders (`rest_head`) at each
/// touched price level and removing emptied price levels from the AVL tree in $O(\log M)$.
fn commit_filled_prefix_to_tree(
    tree: &mut PriceLevelArena,
    orders: &mut [DexOrder; MAX_ACTIVE_ORDERS],
    lvl_idxs: &[u16; MAX_ACTIVE_ORDERS],
    fills: &[u64; MAX_ACTIVE_ORDERS],
    count: usize,
    active_side_cnt: &mut u64,
) {
    let mut seg_start = 0usize;
    while seg_start < count {
        let lvl_idx = lvl_idxs[seg_start];
        let mut seg_end = seg_start + 1;
        while seg_end < count && lvl_idxs[seg_end] == lvl_idx {
            seg_end += 1;
        }

        // `rest_head` is the first unloaded order in `lvl_idx` after our loaded prefix (if any).
        let rest_head = orders[seg_end - 1].next_order_id;

        let mut total_lvl_filled = 0u64;
        let mut removed_orders = 0u16;
        let mut surv_idxs = [0usize; MAX_ACTIVE_ORDERS];
        let mut surv_cnt = 0usize;

        let mut k = seg_start;
        while k < seg_end {
            let fl = fills[k];
            total_lvl_filled = total_lvl_filled.saturating_add(fl);
            orders[k].rem_qty = orders[k].rem_qty.saturating_sub(fl);
            if orders[k].rem_qty == 0 {
                orders[k].status = STATUS_FILLED;
                orders[k].prev_order_id = NONE_ORD;
                orders[k].next_order_id = NONE_ORD;
                store_order(&orders[k]);
                removed_orders += 1;
                *active_side_cnt = active_side_cnt.saturating_sub(1);
            } else {
                surv_idxs[surv_cnt] = k;
                surv_cnt += 1;
            }
            k += 1;
        }

        if surv_cnt > 0 {
            let mut s = 0usize;
            while s < surv_cnt {
                let cur_k = surv_idxs[s];
                orders[cur_k].prev_order_id = if s == 0 {
                    NONE_ORD
                } else {
                    orders[surv_idxs[s - 1]].order_id
                };
                orders[cur_k].next_order_id = if s + 1 < surv_cnt {
                    orders[surv_idxs[s + 1]].order_id
                } else {
                    rest_head
                };
                if fills[cur_k] > 0 || s == 0 || s + 1 == surv_cnt {
                    store_order(&orders[cur_k]);
                }
                s += 1;
            }

            let first_surv_id = orders[surv_idxs[0]].order_id;
            let last_surv_id = orders[surv_idxs[surv_cnt - 1]].order_id;
            let lvl = tree.node_mut(lvl_idx);
            lvl.head_order_id = first_surv_id;
            lvl.total_qty = lvl.total_qty.saturating_sub(total_lvl_filled);
            lvl.order_count = lvl.order_count.saturating_sub(removed_orders);

            if rest_head != NONE_ORD {
                if let Some(mut r_ord) = load_order(rest_head) {
                    if r_ord.prev_order_id != last_surv_id {
                        r_ord.prev_order_id = last_surv_id;
                        store_order(&r_ord);
                    }
                }
            } else {
                tree.node_mut(lvl_idx).tail_order_id = last_surv_id;
            }
        } else if rest_head != NONE_ORD {
            let lvl = tree.node_mut(lvl_idx);
            lvl.head_order_id = rest_head;
            lvl.total_qty = lvl.total_qty.saturating_sub(total_lvl_filled);
            lvl.order_count = lvl.order_count.saturating_sub(removed_orders);
            if let Some(mut r_ord) = load_order(rest_head) {
                r_ord.prev_order_id = NONE_ORD;
                store_order(&r_ord);
            }
        } else {
            // Entire price level exhausted -> remove from AVL tree & push slot to free-list!
            tree.remove_node(lvl_idx);
        }

        seg_start = seg_end;
    }
}

/// Per-block discrete-time FIFO CLOB matching engine entrypoint:
/// 1. Walks the Pending Queue from `KEY_PENDING_HEAD` while `ord.block_number < current_block`,
///    inserting each order into `bid_tree` / `ask_tree` ($O(\log M)$ AVL lookup/insert, $O(1)$ tail
///    append, **0 element shifts**). Stops as soon as it reaches the first `current_block` order.
/// 2. Checks `bid_tree.best_head` vs `ask_tree.best_head` in $O(1)$.
/// 3. Computes the single clearing price $P^*$ purely from crossing `PriceLevelNode` aggregates in
///    $O(M_{\text{cross}})$ (two-pointer merge, zero order storage reads).
/// 4. Loads crossing cohorts only up to the marginal `(price, block_number)` cohort, computes
///    permutation-invariant fills, settles transfers, and updates/prunes price levels in $O(\log M)$.
/// Permissionless periodic orderbook matcher (no authentication or authorization required;
/// guarded against being called more than once per block).
/// Idempotently settles all sealed prior-block (`ord.block_number < current_block`) cohorts at most
/// once per block ($O(1)$ early return if already settled in `current_block`).
fn settle_prior_cohorts_if_needed(current_block: u64) -> Result<(), i32> {
    if storage::get_u64(KEY_SETTLED_SET) == 1
        && storage::get_u64(KEY_SETTLED_BLOCK) == current_block
    {
        return Ok(());
    }
    storage::set_u64(KEY_SETTLED_SET, 1);
    storage::set_u64(KEY_SETTLED_BLOCK, current_block);

    let mut pending_head = storage::get_u64(KEY_PENDING_HEAD);
    let mut pending_tail = storage::get_u64(KEY_PENDING_TAIL);
    let mut pending_count = storage::get_u64(KEY_PENDING_COUNT);
    let mut active_bids = storage::get_u64(KEY_ACTIVE_BIDS);
    let mut active_asks = storage::get_u64(KEY_ACTIVE_ASKS);

    let mut bid_tree = load_tree(KEY_BID_TREE, true);
    let mut ask_tree = load_tree(KEY_ASK_TREE, false);

    let mut ingested_count = 0u64;
    let mut guard = 0usize;
    while pending_head != NONE_ORD && guard < MAX_PENDING_ORDERS {
        let Some(mut ord) = load_order(pending_head) else {
            pending_head = NONE_ORD;
            pending_tail = NONE_ORD;
            pending_count = 0;
            break;
        };

        // Strict prior-block cutoff: stop at the first order placed in `current_block`
        if ord.block_number >= current_block {
            if ord.prev_order_id != NONE_ORD {
                ord.prev_order_id = NONE_ORD;
                store_order(&ord);
            }
            break;
        }

        let next_pending = ord.next_order_id;
        pending_count = pending_count.saturating_sub(1);

        if ord.status == STATUS_PENDING && ord.rem_qty > 0 {
            if ord.side == SIDE_BID {
                if (active_bids as usize) >= MAX_ACTIVE_ORDERS {
                    return Err(ERR_ORDERBOOK_FULL);
                }
                let lvl_idx = bid_tree.find_or_insert(ord.price)?;
                append_order_to_level(&mut bid_tree, lvl_idx, &mut ord);
                active_bids += 1;
            } else {
                if (active_asks as usize) >= MAX_ACTIVE_ORDERS {
                    return Err(ERR_ORDERBOOK_FULL);
                }
                let lvl_idx = ask_tree.find_or_insert(ord.price)?;
                append_order_to_level(&mut ask_tree, lvl_idx, &mut ord);
                active_asks += 1;
            }

            ingested_count += 1;
            let mut ev = [0u8; 24];
            ev[0] = ord.side;
            ev[8..16].copy_from_slice(&ord.price.to_be_bytes());
            ev[16..24].copy_from_slice(&ord.block_number.to_be_bytes());
            events::emit(&[ORDER_INGESTED, u64_topic(ord.order_id)], &ev);
        }

        pending_head = next_pending;
        guard += 1;
    }

    if pending_head == NONE_ORD {
        pending_tail = NONE_ORD;
        pending_count = 0;
    }
    storage::set_u64(KEY_PENDING_HEAD, pending_head);
    storage::set_u64(KEY_PENDING_TAIL, pending_tail);
    storage::set_u64(KEY_PENDING_COUNT, pending_count);

    // O(1) top-of-book cross check
    let no_cross = bid_tree.best_head == NONE_LVL
        || ask_tree.best_head == NONE_LVL
        || bid_tree.node(bid_tree.best_head).price < ask_tree.node(ask_tree.best_head).price;

    if no_cross {
        if ingested_count > 0 {
            store_tree(KEY_BID_TREE, &bid_tree);
            store_tree(KEY_ASK_TREE, &ask_tree);
            storage::set_u64(KEY_ACTIVE_BIDS, active_bids);
            storage::set_u64(KEY_ACTIVE_ASKS, active_asks);
        }

        storage::set_u64(KEY_LAST_MATCH_BLOCK, current_block);
        storage::set_u64(KEY_LAST_PRICE, 0);
        storage::set_u64(KEY_LAST_VOL, 0);
        storage::set_u64(KEY_LAST_INGESTED, ingested_count);
        storage::set_u64(KEY_LAST_FILLED_BIDS, 0);
        storage::set_u64(KEY_LAST_FILLED_ASKS, 0);
        return Ok(());
    }

    // Collect crossing price levels ONLY (`ask.price <= bid_best` and `bid.price >= ask_best`)
    let max_cross_px = bid_tree.node(bid_tree.best_head).price;
    let min_cross_px = ask_tree.node(ask_tree.best_head).price;

    let mut cb_prices = [0u64; MAX_PRICE_LEVELS];
    let mut cb_qtys = [0u64; MAX_PRICE_LEVELS];
    let mut cb_len = 0usize;
    let mut cur = bid_tree.best_head;
    while cur != NONE_LVL && cb_len < MAX_PRICE_LEVELS {
        let lvl = bid_tree.node(cur);
        if lvl.price < min_cross_px {
            break;
        }
        cb_prices[cb_len] = lvl.price; // descending
        cb_qtys[cb_len] = lvl.total_qty;
        cb_len += 1;
        cur = lvl.next_worse;
    }

    let mut ca_prices = [0u64; MAX_PRICE_LEVELS];
    let mut ca_qtys = [0u64; MAX_PRICE_LEVELS];
    let mut ca_len = 0usize;
    cur = ask_tree.best_head;
    while cur != NONE_LVL && ca_len < MAX_PRICE_LEVELS {
        let lvl = ask_tree.node(cur);
        if lvl.price > max_cross_px {
            break;
        }
        ca_prices[ca_len] = lvl.price; // ascending
        ca_qtys[ca_len] = lvl.total_qty;
        ca_len += 1;
        cur = lvl.next_worse;
    }

    // O(M_cross) two-pointer merge of `cb_prices` (iterated backwards -> ascending) and
    // `ca_prices` (ascending) into sorted unique candidate clearing prices — zero sorting needed!
    let mut candidates = [0u64; MAX_PRICE_LEVELS * 2];
    let mut cand_count = 0usize;
    let mut bi = cb_len; // `cb_prices[bi - 1]` is smallest crossing bid price
    let mut ai = 0usize;
    while bi > 0 || ai < ca_len {
        let next_p = if bi > 0 && (ai >= ca_len || cb_prices[bi - 1] <= ca_prices[ai]) {
            let p = cb_prices[bi - 1];
            if ai < ca_len && ca_prices[ai] == p {
                ai += 1;
            }
            bi -= 1;
            p
        } else {
            let p = ca_prices[ai];
            ai += 1;
            p
        };
        if cand_count == 0 || candidates[cand_count - 1] != next_p {
            candidates[cand_count] = next_p;
            cand_count += 1;
        }
    }

    // O(M_cross) linear sweep across sorted `candidates` to find single clearing price P*
    // maximizing matched volume V(P) = min(D(P), S(P)) (tie-broken by minimum |D(P) - S(P)|).
    let mut cum_demand = 0u64;
    let mut k = 0usize;
    while k < cb_len {
        cum_demand = cum_demand.saturating_add(cb_qtys[k]);
        k += 1;
    }
    let mut cum_supply = 0u64;
    let mut b_tail = cb_len; // bids in `0..b_tail` have `price >= p`
    let mut a_head = 0usize; // asks in `0..a_head` have `price <= p`

    let mut best_vol = 0u64;
    let mut best_imbalance = u64::MAX;
    let mut best_min_price = 0u64;
    let mut best_max_price = 0u64;
    let mut best_demand = 0u64;
    let mut best_supply = 0u64;

    let mut ci = 0usize;
    while ci < cand_count {
        let p = candidates[ci];
        while b_tail > 0 && cb_prices[b_tail - 1] < p {
            b_tail -= 1;
            cum_demand = cum_demand.saturating_sub(cb_qtys[b_tail]);
        }
        while a_head < ca_len && ca_prices[a_head] <= p {
            cum_supply = cum_supply.saturating_add(ca_qtys[a_head]);
            a_head += 1;
        }

        let vol = if cum_demand < cum_supply {
            cum_demand
        } else {
            cum_supply
        };
        if vol > 0 {
            let imb = if cum_demand >= cum_supply {
                cum_demand - cum_supply
            } else {
                cum_supply - cum_demand
            };
            if vol > best_vol || (vol == best_vol && imb < best_imbalance) {
                best_vol = vol;
                best_imbalance = imb;
                best_min_price = p;
                best_max_price = p;
                best_demand = cum_demand;
                best_supply = cum_supply;
            } else if vol == best_vol && imb == best_imbalance {
                best_max_price = p;
            }
        }
        ci += 1;
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

    // Exact crossing volume `max_target_vol` at `clearing_price` from level aggregates
    let mut total_bid_cross = 0u64;
    k = 0;
    while k < cb_len && cb_prices[k] >= clearing_price {
        total_bid_cross = total_bid_cross.saturating_add(cb_qtys[k]);
        k += 1;
    }
    let mut total_ask_cross = 0u64;
    k = 0;
    while k < ca_len && ca_prices[k] <= clearing_price {
        total_ask_cross = total_ask_cross.saturating_add(ca_qtys[k]);
        k += 1;
    }
    let max_target_vol = if total_bid_cross < total_ask_cross {
        total_bid_cross
    } else {
        total_ask_cross
    };

    // Load ONLY crossing cohorts up to `max_target_vol`
    let mut bid_orders = [DexOrder::default(); MAX_ACTIVE_ORDERS];
    let mut bid_lvl_idxs = [NONE_LVL; MAX_ACTIVE_ORDERS];
    let loaded_bids = load_crossing_cohorts(
        &bid_tree,
        clearing_price,
        max_target_vol,
        &mut bid_orders,
        &mut bid_lvl_idxs,
    );

    let mut ask_orders = [DexOrder::default(); MAX_ACTIVE_ORDERS];
    let mut ask_lvl_idxs = [NONE_LVL; MAX_ACTIVE_ORDERS];
    let loaded_asks = load_crossing_cohorts(
        &ask_tree,
        clearing_price,
        max_target_vol,
        &mut ask_orders,
        &mut ask_lvl_idxs,
    );

    // Allocate cohort fills and align both sides to the exact integer-feasible matched volume
    let mut bid_fills = [0u64; MAX_ACTIVE_ORDERS];
    let mut ask_fills = [0u64; MAX_ACTIVE_ORDERS];
    let sum_bid = allocate_cohort_fills(&bid_orders, loaded_bids, max_target_vol, &mut bid_fills);
    let sum_ask = allocate_cohort_fills(&ask_orders, loaded_asks, max_target_vol, &mut ask_fills);

    let matched_volume = if sum_bid < sum_ask {
        allocate_cohort_fills(&ask_orders, loaded_asks, sum_bid, &mut ask_fills)
    } else if sum_ask < sum_bid {
        allocate_cohort_fills(&bid_orders, loaded_bids, sum_ask, &mut bid_fills)
    } else {
        sum_bid
    };

    let asset_ledger = storage::get_address(KEY_ASSET_LEDGER).ok_or(-10)?;
    let quote_ledger = storage::get_address(KEY_QUOTE_LEDGER).unwrap_or([0u8; 20]);
    let escrow_id = storage::get_address(KEY_ESCROW_ID).ok_or(-10)?;

    // Settle filled Bids (base asset + buyer price-improvement refund)
    let mut filled_bid_orders = 0u64;
    let mut i = 0usize;
    while i < loaded_bids {
        let fill = bid_fills[i];
        if fill > 0 {
            filled_bid_orders += 1;
            call_dex_transfer(&asset_ledger, &escrow_id, &bid_orders[i].trader, fill)?;
            if quote_ledger != [0u8; 20] && bid_orders[i].price > clearing_price {
                let price_improvement = (bid_orders[i].price - clearing_price)
                    .checked_mul(fill)
                    .ok_or(-15)?;
                call_dex_transfer(
                    &quote_ledger,
                    &escrow_id,
                    &bid_orders[i].trader,
                    price_improvement,
                )?;
            }
            let rem_after = bid_orders[i].rem_qty.saturating_sub(fill);
            let mut ev = [0u8; 32];
            ev[0] = SIDE_BID;
            ev[8..16].copy_from_slice(&clearing_price.to_be_bytes());
            ev[16..24].copy_from_slice(&fill.to_be_bytes());
            ev[24..32].copy_from_slice(&rem_after.to_be_bytes());
            events::emit(
                &[
                    ORDER_FILLED,
                    u64_topic(bid_orders[i].order_id),
                    addr_topic(&bid_orders[i].trader),
                ],
                &ev,
            );
        }
        i += 1;
    }

    // Settle filled Asks (quote proceeds `clearing_price * fill` to sellers)
    let mut filled_ask_orders = 0u64;
    i = 0;
    while i < loaded_asks {
        let fill = ask_fills[i];
        if fill > 0 {
            filled_ask_orders += 1;
            if quote_ledger != [0u8; 20] {
                let proceeds = clearing_price.checked_mul(fill).ok_or(-15)?;
                call_dex_transfer(&quote_ledger, &escrow_id, &ask_orders[i].trader, proceeds)?;
            }
            let rem_after = ask_orders[i].rem_qty.saturating_sub(fill);
            let mut ev = [0u8; 32];
            ev[0] = SIDE_ASK;
            ev[8..16].copy_from_slice(&clearing_price.to_be_bytes());
            ev[16..24].copy_from_slice(&fill.to_be_bytes());
            ev[24..32].copy_from_slice(&rem_after.to_be_bytes());
            events::emit(
                &[
                    ORDER_FILLED,
                    u64_topic(ask_orders[i].order_id),
                    addr_topic(&ask_orders[i].trader),
                ],
                &ev,
            );
        }
        i += 1;
    }

    // Commit updated order chains and prune exhausted price levels in AVL trees
    commit_filled_prefix_to_tree(
        &mut bid_tree,
        &mut bid_orders,
        &bid_lvl_idxs,
        &bid_fills,
        loaded_bids,
        &mut active_bids,
    );
    commit_filled_prefix_to_tree(
        &mut ask_tree,
        &mut ask_orders,
        &ask_lvl_idxs,
        &ask_fills,
        loaded_asks,
        &mut active_asks,
    );

    store_tree(KEY_BID_TREE, &bid_tree);
    store_tree(KEY_ASK_TREE, &ask_tree);
    storage::set_u64(KEY_ACTIVE_BIDS, active_bids);
    storage::set_u64(KEY_ACTIVE_ASKS, active_asks);

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
    Ok(())
}

/// Permissionless periodic orderbook matcher (no authentication or authorization required;
/// guarded against being called more than once per block).
fn handle_match_block(_args: &CalldataReader) -> Result<(), i32> {
    if storage::get_u64(KEY_INIT) != 1 {
        return Err(-10);
    }
    let current_block = context::block_number();
    if storage::get_u64(KEY_LAST_MATCH_EXEC_SET) == 1
        && storage::get_u64(KEY_EXPLICIT_MATCH_BLOCK) == current_block
    {
        return Err(ERR_ALREADY_EXECUTED_IN_BLOCK);
    }
    storage::set_u64(KEY_LAST_MATCH_EXEC_SET, 1);
    storage::set_u64(KEY_EXPLICIT_MATCH_BLOCK, current_block);

    settle_prior_cohorts_if_needed(current_block)?;

    let mut out = [0u8; 160];
    out[24..32].copy_from_slice(&storage::get_u64(KEY_LAST_PRICE).to_be_bytes());
    out[56..64].copy_from_slice(&storage::get_u64(KEY_LAST_VOL).to_be_bytes());
    out[88..96].copy_from_slice(&storage::get_u64(KEY_LAST_INGESTED).to_be_bytes());
    out[120..128].copy_from_slice(&storage::get_u64(KEY_LAST_FILLED_BIDS).to_be_bytes());
    out[152..160].copy_from_slice(&storage::get_u64(KEY_LAST_FILLED_ASKS).to_be_bytes());
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
    let pending_count = storage::get_u64(KEY_PENDING_COUNT);
    let bid_count = storage::get_u64(KEY_ACTIVE_BIDS);
    let ask_count = storage::get_u64(KEY_ACTIVE_ASKS);
    let mut out = [0u8; 96];
    out[24..32].copy_from_slice(&pending_count.to_be_bytes());
    out[56..64].copy_from_slice(&bid_count.to_be_bytes());
    out[88..96].copy_from_slice(&ask_count.to_be_bytes());
    ret::write(&out);
    Ok(())
}

fn handle_price_level_depth(_args: &CalldataReader) -> Result<(), i32> {
    let bid_tree = load_tree(KEY_BID_TREE, true);
    let ask_tree = load_tree(KEY_ASK_TREE, false);
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&(bid_tree.active_levels as u64).to_be_bytes());
    out[56..64].copy_from_slice(&(ask_tree.active_levels as u64).to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// $O(1)$ top-of-book query directly from `best_head` of `bid_tree` and `ask_tree`.
fn handle_best_bid_and_ask(_args: &CalldataReader) -> Result<(), i32> {
    let bid_tree = load_tree(KEY_BID_TREE, true);
    let ask_tree = load_tree(KEY_ASK_TREE, false);
    let best_bid = if bid_tree.best_head != NONE_LVL {
        bid_tree.node(bid_tree.best_head).price
    } else {
        0
    };
    let best_ask = if ask_tree.best_head != NONE_LVL {
        ask_tree.node(ask_tree.best_head).price
    } else {
        0
    };
    let mut out = [0u8; 64];
    out[24..32].copy_from_slice(&best_bid.to_be_bytes());
    out[56..64].copy_from_slice(&best_ask.to_be_bytes());
    ret::write(&out);
    Ok(())
}

/// Skips entire `PriceLevelNode`s in $O(M)$ using `level.order_count`, loading orders only inside
/// the single target price level.
fn get_ordered_at_in_tree(tree: &PriceLevelArena, mut idx: usize) -> Result<DexOrder, i32> {
    let mut cur_lvl = tree.best_head;
    let mut guard = 0usize;
    while cur_lvl != NONE_LVL && guard < MAX_PRICE_LEVELS {
        let lvl = tree.node(cur_lvl);
        let cnt = lvl.order_count as usize;
        if idx < cnt {
            let mut oid = lvl.head_order_id;
            let mut step = 0usize;
            while oid != NONE_ORD && step < cnt {
                let ord = load_order(oid).ok_or(ERR_ORDER_NOT_FOUND)?;
                if step == idx {
                    return Ok(ord);
                }
                oid = ord.next_order_id;
                step += 1;
            }
            return Err(ERR_ORDER_NOT_FOUND);
        }
        idx -= cnt;
        cur_lvl = lvl.next_worse;
        guard += 1;
    }
    Err(ERR_ORDER_NOT_FOUND)
}

fn handle_get_ordered_bid_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let bid_tree = load_tree(KEY_BID_TREE, true);
    let ord = get_ordered_at_in_tree(&bid_tree, idx)?;
    write_order_tuple(&ord);
    Ok(())
}

fn handle_get_ordered_ask_at(args: &CalldataReader) -> Result<(), i32> {
    let idx = args.u64(0).ok_or(-3)? as usize;
    let ask_tree = load_tree(KEY_ASK_TREE, false);
    let ord = get_ordered_at_in_tree(&ask_tree, idx)?;
    write_order_tuple(&ord);
    Ok(())
}

fn handle_last_matched_block(_args: &CalldataReader) -> Result<(), i32> {
    ret::write_u64_word(storage::get_u64(KEY_LAST_MATCH_BLOCK));
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

    fn check_avl_subtree(
        tree: &PriceLevelArena,
        idx: u16,
        expected_parent: u16,
        inorder_out: &mut Vec<u16>,
    ) -> u8 {
        if idx == NONE_LVL {
            return 0;
        }
        let n = tree.node(idx);
        assert_eq!(n.parent, expected_parent, "parent mismatch at node {idx}");
        let lh = check_avl_subtree(tree, n.left, idx, inorder_out);
        if let Some(&prev_idx) = inorder_out.last() {
            assert!(
                tree.is_better(tree.node(prev_idx).price, n.price),
                "BST priority order violated between {prev_idx} and {idx}"
            );
        }
        inorder_out.push(idx);
        let rh = check_avl_subtree(tree, n.right, idx, inorder_out);
        let bf = (lh as i16) - (rh as i16);
        assert!(
            (-1..=1).contains(&bf),
            "AVL balance factor out of range ({bf}) at node {idx}"
        );
        let expected_h = 1 + lh.max(rh);
        assert_eq!(n.height, expected_h, "height mismatch at node {idx}");
        expected_h
    }

    fn assert_avl_invariants(tree: &PriceLevelArena) {
        let mut inorder = Vec::new();
        let root_h = check_avl_subtree(tree, tree.root, NONE_LVL, &mut inorder);
        assert_eq!(inorder.len(), tree.active_levels as usize);
        if tree.active_levels == 0 {
            assert_eq!(tree.root, NONE_LVL);
            assert_eq!(tree.best_head, NONE_LVL);
            assert_eq!(tree.worst_tail, NONE_LVL);
            return;
        }
        // Logarithmic height bound: h <= 10 for N <= 128
        assert!(root_h <= 10, "AVL height {root_h} exceeded log bound");

        // Verify forward threaded links (`best_head -> ... -> worst_tail`) match BST in-order
        let mut fwd = Vec::new();
        let mut cur = tree.best_head;
        while cur != NONE_LVL {
            fwd.push(cur);
            cur = tree.node(cur).next_worse;
        }
        assert_eq!(fwd, inorder, "forward threaded list mismatch");
        assert_eq!(*fwd.last().unwrap(), tree.worst_tail);

        // Verify backward threaded links (`worst_tail -> ... -> best_head`)
        let mut bwd = Vec::new();
        cur = tree.worst_tail;
        while cur != NONE_LVL {
            bwd.push(cur);
            cur = tree.node(cur).prev_better;
        }
        bwd.reverse();
        assert_eq!(bwd, inorder, "backward threaded list mismatch");
    }

    #[test]
    fn avl_price_level_tree_maintains_balance_threads_and_recycles_freed_slots() {
        for is_bid in [true, false] {
            let mut tree = PriceLevelArena::new(is_bid);

            // Insert all 128 price levels in adversarial interleaved order
            let mut inserted_prices = Vec::new();
            for step in 0..MAX_PRICE_LEVELS {
                let px = (((step * 73) + 19) % 997 + 1) as u64 + (step as u64) * 1000;
                tree.find_or_insert(px).unwrap();
                inserted_prices.push(px);
                assert_avl_invariants(&tree);
            }
            assert_eq!(tree.active_levels as usize, MAX_PRICE_LEVELS);
            assert_eq!(tree.find_or_insert(999_999_999), Err(ERR_ORDERBOOK_FULL));

            // Remove 100 price levels (leaves, internal nodes, and root) and verify invariants every step
            for &px in &inserted_prices[..100] {
                let idx = tree.find_price(px);
                assert_ne!(idx, NONE_LVL);
                tree.remove_node(idx);
                assert_eq!(tree.find_price(px), NONE_LVL);
                assert_avl_invariants(&tree);
            }
            assert_eq!(tree.active_levels, 28);

            // Insert 100 brand-new price levels (228 distinct lifetime levels inside a 128-slot arena!)
            // proving O(1) free-list recycling without shifting or exhausting capacity.
            for extra in 0..100u64 {
                let px = 5_000_000 + extra * 17;
                let idx = tree.find_or_insert(px).unwrap();
                assert_ne!(idx, NONE_LVL);
                assert_avl_invariants(&tree);
            }
            assert_eq!(tree.active_levels as usize, MAX_PRICE_LEVELS);
        }
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

        let init_cd = CallEncoder::<160>::new(const {
            selector("initialize(address,address,address,address)")
        })
        .push_address(&reg)
        .push_address(&asset_ledger)
        .push_address(&quote_ledger)
        .push_address(&escrow_id);
        mock::transact_as(buyer_early, dex, init_cd.as_slice()).unwrap();

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

        assert_eq!(balance_of(asset_ledger, buyer_high_px), 50);
        assert_eq!(balance_of(asset_ledger, buyer_early), 100);
        assert_eq!(balance_of(asset_ledger, buyer_same_blk_1), 50);
        assert_eq!(balance_of(asset_ledger, buyer_same_blk_2), 150);

        assert_eq!(balance_of(quote_ledger, buyer_high_px), 99_500);
        assert_eq!(balance_of(quote_ledger, seller_2), 1_500);
        assert_eq!(balance_of(quote_ledger, seller_1), 2_000);

        let depth_cd = CallEncoder::<16>::new(const { selector("bookDepth()") });
        let depth_out = mock::transact_as(buyer_early, dex, depth_cd.as_slice()).unwrap();
        let pending_cnt = u64::from_be_bytes(depth_out[24..32].try_into().unwrap());
        let bid_cnt = u64::from_be_bytes(depth_out[56..64].try_into().unwrap());
        let ask_cnt = u64::from_be_bytes(depth_out[88..96].try_into().unwrap());
        assert_eq!((pending_cnt, bid_cnt, ask_cnt), (0, 2, 0));

        // Only 1 active Bid price level ($10) and 0 active Ask price levels remain in the AVL trees
        let lvl_cd = CallEncoder::<16>::new(const { selector("priceLevelDepth()") });
        let lvl_out = mock::transact_as(buyer_early, dex, lvl_cd.as_slice()).unwrap();
        let bid_lvls = u64::from_be_bytes(lvl_out[24..32].try_into().unwrap());
        let ask_lvls = u64::from_be_bytes(lvl_out[56..64].try_into().unwrap());
        assert_eq!((bid_lvls, ask_lvls), (1, 0));
    }

    #[test]
    fn mev_invariance_under_intra_block_tx_reordering_and_same_block_match_isolation() {
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

            mock::set_block_number(50);
            let bid_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
                .push_u64(10)
                .push_u64(100);
            let ask_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
                .push_u64(10)
                .push_u64(101);

            if !b_first {
                mock::transact_as(trader_a, dex, bid_cd.as_slice()).unwrap();
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
        assert_eq!(out_a_first.0, 50);
        assert_eq!(out_a_first.1, 50);
        assert_eq!(out_a_first.5, 1_000);
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

        mock::set_block_number(20);
        let a1 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(20)
            .push_u64(100);
        mock::transact_as(seller_early, dex, a1.as_slice()).unwrap();

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

        let cancel_cd =
            CallEncoder::<64>::new(const { selector("cancelOrder(uint64)") }).push_u64(2);
        let cancel_out = mock::transact_as(seller_same_1, dex, cancel_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(cancel_out[24..32].try_into().unwrap()), 50);
        assert_eq!(balance_of(asset_ledger, seller_same_1), 950);

        let b2 = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(20)
            .push_u64(150);
        mock::transact_as(buyer_2, dex, b2.as_slice()).unwrap();

        mock::set_block_number(23);
        let out23 = mock::transact_as(buyer_2, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(out23[24..32].try_into().unwrap()), 20);
        assert_eq!(u64::from_be_bytes(out23[56..64].try_into().unwrap()), 150);
        assert_eq!(balance_of(asset_ledger, buyer_2), 150);
        assert_eq!(balance_of(quote_ledger, seller_same_2), 6_000);
    }

    #[test]
    fn pending_order_cancellation_and_unbounded_lifetime_throughput_across_blocks() {
        mock::reset();
        let reg = [0x10; 20];
        let asset_ledger = [0x20; 20];
        let quote_ledger = [0x30; 20];
        let dex = [0x40; 20];
        let escrow_id = [0x90; 20];

        let buyer = [0xA1; 20];
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
        mock::transact_as(buyer, dex, init_cd.as_slice()).unwrap();

        seed_balance(quote_ledger, buyer, 10_000_000);
        seed_balance(asset_ledger, seller, 10_000_000);

        // Place 3 pending orders in Block 1 and cancel the middle one (`orderId = 2`) in O(1)
        mock::set_block_number(1);
        let bid_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(15)
            .push_u64(10);
        mock::transact_as(buyer, dex, bid_cd.as_slice()).unwrap(); // #1
        mock::transact_as(buyer, dex, bid_cd.as_slice()).unwrap(); // #2 (middle)
        let ask_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(15)
            .push_u64(20);
        mock::transact_as(seller, dex, ask_cd.as_slice()).unwrap(); // #3

        let cancel_mid =
            CallEncoder::<64>::new(const { selector("cancelOrder(uint64)") }).push_u64(2);
        mock::transact_as(buyer, dex, cancel_mid.as_slice()).unwrap();

        mock::set_block_number(2);
        let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
        let m_out = mock::transact_as(buyer, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(m_out[56..64].try_into().unwrap()), 10);
        assert_eq!(u64::from_be_bytes(m_out[88..96].try_into().unwrap()), 2);

        // Now execute 300+ more orders across 160 blocks (exceeding `MAX_ACTIVE_ORDERS = 256`
        // and `MAX_PRICE_LEVELS = 128` over time) to prove slots recycle cleanly forever!
        for blk in 10..170u64 {
            mock::set_block_number(blk);
            let px = 10 + (blk % 200);
            let b_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
                .push_u64(px)
                .push_u64(5);
            let a_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
                .push_u64(px)
                .push_u64(5);
            mock::transact_as(buyer, dex, b_cd.as_slice()).unwrap();
            mock::transact_as(seller, dex, a_cd.as_slice()).unwrap();

            mock::set_block_number(blk + 1);
            let out = mock::transact_as(buyer, dex, match_cd.as_slice()).unwrap();
            assert!(u64::from_be_bytes(out[56..64].try_into().unwrap()) >= 5);
        }

        let cnt_cd = CallEncoder::<16>::new(const { selector("orderCount()") });
        let cnt_out = mock::transact_as(buyer, dex, cnt_cd.as_slice()).unwrap();
        let total_orders = u64::from_be_bytes(cnt_out[24..32].try_into().unwrap());
        assert_eq!(total_orders, 323);
    }

    #[test]
    fn match_block_is_permissionless_and_enforces_once_per_block_safeguard() {
        mock::reset();
        let reg = [0x10; 20];
        let asset_ledger = [0x20; 20];
        let quote_ledger = [0x30; 20];
        let dex = [0x40; 20];
        let escrow_id = [0x90; 20];

        let buyer = [0xA1; 20];
        let seller = [0xB1; 20];
        // `[0xEE; 20]` is explicitly rejected by `sim_ledgers::reg_dispatch::isValidIdentity`!
        let unauthenticated_sim_eoa = [0xEE; 20];

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
        mock::transact_as(buyer, dex, init_cd.as_slice()).unwrap();

        seed_balance(quote_ledger, buyer, 100_000);
        seed_balance(asset_ledger, seller, 1_000);

        mock::set_block_number(5);
        let bid_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(25)
            .push_u64(40);
        let ask_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(25)
            .push_u64(40);
        mock::transact_as(buyer, dex, bid_cd.as_slice()).unwrap();
        mock::transact_as(seller, dex, ask_cd.as_slice()).unwrap();

        mock::set_block_number(6);
        let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
        // 1. Unauthenticated simulator EOA (`[0xEE; 20]`) calls `matchBlock()` directly without Identity!
        let out = mock::transact_as(unauthenticated_sim_eoa, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(out[56..64].try_into().unwrap()), 40);

        // 2. Second `matchBlock()` call in the SAME block (#6) is rejected!
        assert_eq!(
            mock::transact_as(unauthenticated_sim_eoa, dex, match_cd.as_slice()),
            Err(ERR_ALREADY_EXECUTED_IN_BLOCK)
        );
        assert_eq!(
            mock::transact_as(buyer, dex, match_cd.as_slice()),
            Err(ERR_ALREADY_EXECUTED_IN_BLOCK)
        );

        // 3. Advancing to the next block (#7) permits `matchBlock()` again!
        mock::set_block_number(7);
        assert!(mock::transact_as(unauthenticated_sim_eoa, dex, match_cd.as_slice()).is_ok());
    }

    #[test]
    fn last_look_cancel_cannot_frontrun_prior_block_cohort_clearing() {
        // Run BOTH intra-block permutations at Block #11:
        //   Perm A: Low-EOA Maker `cancelOrder(ask_id)` FIRST, then Keeper `matchBlock()`
        //   Perm B: Keeper `matchBlock()` FIRST, then High-EOA Maker `cancelOrder(ask_id)`
        // Assert identical fills, clearing price, and final balances!
        fn run_permutation(cancel_first: bool) -> (u64, u64, u64, u64, u64, u64) {
            mock::reset();
            let reg = [0x10; 20];
            let asset_ledger = [0x20; 20];
            let quote_ledger = [0x30; 20];
            let dex = [0x40; 20];
            let escrow_id = [0x90; 20];

            let buyer = [0xA1; 20];
            let low_eoa_maker = [0x01; 20]; // vanity low address attempting Last-Look cancel
            let keeper = [0xEE; 20];

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
            mock::transact_as(buyer, dex, init_cd.as_slice()).unwrap();

            seed_balance(quote_ledger, buyer, 10_000);
            seed_balance(asset_ledger, low_eoa_maker, 100);

            // Block #9: Warmup matchBlock so KEY_LAST_MATCH_EXEC_SET is already 1
            mock::set_block_number(9);
            let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
            mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();

            // Block #10: Buyer bids 60 @ $50; Maker asks 100 @ $50 (partial fill = 60, rem = 40)
            mock::set_block_number(10);
            let bid_cd = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
                .push_u64(50)
                .push_u64(60);
            let ask_cd = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
                .push_u64(50)
                .push_u64(100);
            mock::transact_as(buyer, dex, bid_cd.as_slice()).unwrap();
            let ask_ret = mock::transact_as(low_eoa_maker, dex, ask_cd.as_slice()).unwrap();
            let ask_id = u64::from_be_bytes(ask_ret[24..32].try_into().unwrap());

            // Block #11: External price jumps; Maker tries to cancel before `matchBlock()`!
            mock::set_block_number(11);
            let cancel_cd = CallEncoder::<64>::new(const { selector("cancelOrder(uint64)") })
                .push_u64(ask_id);

            let match_vol;
            if cancel_first {
                let cancel_ret =
                    mock::transact_as(low_eoa_maker, dex, cancel_cd.as_slice()).unwrap();
                let refunded = u64::from_be_bytes(cancel_ret[24..32].try_into().unwrap());
                assert_eq!(refunded, 40, "only unfilled remainder (40) may be cancelled");

                let m_ret = mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();
                match_vol = u64::from_be_bytes(m_ret[56..64].try_into().unwrap());
            } else {
                let m_ret = mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();
                match_vol = u64::from_be_bytes(m_ret[56..64].try_into().unwrap());

                let cancel_ret =
                    mock::transact_as(low_eoa_maker, dex, cancel_cd.as_slice()).unwrap();
                let refunded = u64::from_be_bytes(cancel_ret[24..32].try_into().unwrap());
                assert_eq!(refunded, 40);
            }

            (
                match_vol,
                balance_of(asset_ledger, buyer),
                balance_of(quote_ledger, buyer),
                balance_of(asset_ledger, low_eoa_maker),
                balance_of(quote_ledger, low_eoa_maker),
                balance_of(asset_ledger, escrow_id),
            )
        }

        let perm_cancel_first = run_permutation(true);
        let perm_match_first = run_permutation(false);
        assert_eq!(perm_cancel_first, perm_match_first);
        assert_eq!(perm_cancel_first.0, 60); // 60 units matched despite Last-Look cancel attempt!
        assert_eq!(perm_cancel_first.1, 60); // buyer received 60 base units
        assert_eq!(perm_cancel_first.3, 40); // maker got 40 base units back, sold 60
        assert_eq!(perm_cancel_first.4, 3000); // maker received 60 * $50 = $3000
        assert_eq!(perm_cancel_first.5, 0); // escrow cleanly drained
    }

    #[test]
    fn intra_block_sandwich_and_vanity_address_priority_yield_zero_mev() {
        mock::reset();
        let reg = [0x10; 20];
        let asset_ledger = [0x20; 20];
        let quote_ledger = [0x30; 20];
        let dex = [0x40; 20];
        let escrow_id = [0x90; 20];

        let mev_front_eoa = [0x01; 20]; // lowest address (executes 1st in block)
        let victim = [0x77; 20]; // middle address
        let mev_back_eoa = [0xFE; 20]; // highest address (executes last in block)
        let resting_seller = [0xB2; 20];
        let keeper = [0xEE; 20];

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
        mock::transact_as(victim, dex, init_cd.as_slice()).unwrap();

        seed_balance(asset_ledger, resting_seller, 100);
        seed_balance(quote_ledger, mev_front_eoa, 50_000);
        seed_balance(asset_ledger, mev_back_eoa, 500);
        seed_balance(quote_ledger, victim, 50_000);

        // Block #1: Resting seller posts 100 units @ $100; ingested at Block #2
        mock::set_block_number(1);
        let ask100 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(100)
            .push_u64(100);
        mock::transact_as(resting_seller, dex, ask100.as_slice()).unwrap();

        mock::set_block_number(2);
        let match_cd = CallEncoder::<16>::new(const { selector("matchBlock()") });
        mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();

        // Block #3: Victim submits Bid 100 @ $105.
        // Insider validator MEV bot sees it in mempool and brackets Victim in Block #3:
        //   1. `mev_front_eoa` places Bid 100 @ $105 AHEAD of Victim (hoping to steal 100% of resting $100 ask)
        //   2. Victim places Bid 100 @ $105
        //   3. `mev_back_eoa` places Ask 100 @ $105 BEHIND Victim (hoping to dump onto Victim @ $105!)
        mock::set_block_number(3);
        let bid105 = CallEncoder::<96>::new(const { selector("placeBid(uint64,uint64)") })
            .push_u64(105)
            .push_u64(100);
        let ask105 = CallEncoder::<96>::new(const { selector("placeAsk(uint64,uint64)") })
            .push_u64(105)
            .push_u64(100);

        mock::transact_as(mev_front_eoa, dex, bid105.as_slice()).unwrap();
        mock::transact_as(victim, dex, bid105.as_slice()).unwrap();
        mock::transact_as(mev_back_eoa, dex, ask105.as_slice()).unwrap();

        // Attempt intra-block `matchBlock()` in Block #3 -> 0 volume matched (strict prior-block cutoff!)
        let m3 = mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();
        assert_eq!(u64::from_be_bytes(m3[56..64].try_into().unwrap()), 0);

        // Block #4: Cohort #3 clears!
        // Look what happens to the sandwich:
        // Total demand @ <=105 is 200 (100 bot + 100 victim); total supply is 200 (100 @ $100 + 100 @ $105).
        // Even if `mev_back_eoa` had NOT posted the back-run ask (only 100 supply @ $100), both `mev_front_eoa`
        // and `victim` share Cohort #3 and split 50/50 pro-rata — `mev_front_eoa` gets ZERO FIFO priority!
        // And WITH the back-run ask @ $105, `mev_front_eoa` and `mev_back_eoa` net 0 MEV profit (`paid $105, sold $105 = $0`)!
        mock::set_block_number(4);
        let m4 = mock::transact_as(keeper, dex, match_cd.as_slice()).unwrap();
        let px = u64::from_be_bytes(m4[24..32].try_into().unwrap());
        let vol = u64::from_be_bytes(m4[56..64].try_into().unwrap());
        assert_eq!(vol, 200);
        // Combined MEV adversary net quote profit across `mev_front_eoa` + `mev_back_eoa` when round-tripping 100 units:
        let bot_quote_after =
            balance_of(quote_ledger, mev_front_eoa) + balance_of(quote_ledger, mev_back_eoa);
        let bot_asset_after =
            balance_of(asset_ledger, mev_front_eoa) + balance_of(asset_ledger, mev_back_eoa);
        assert_eq!(bot_asset_after, 500, "sandwich bot ended flat in base asset");
        assert_eq!(
            bot_quote_after, 50_000,
            "sandwich bot extracted ZERO net quote profit (clearing_px={px})"
        );
    }
}
