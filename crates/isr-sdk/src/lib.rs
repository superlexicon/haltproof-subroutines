//! # `isr-sdk`
//!
//! Ergonomic `#![no_std]` guest SDK for authoring WebAssembly (`wasm32-unknown-unknown`)
//! **Immortal Subroutines (ISRs)** targeting Lexicon's `WasmtimeAdapter`.
//!
//! - Hides all fixed linear-memory host buffers (`0x10000..0x70000`) and raw `env` imports.
//! - Provides compile-time `const fn` Keccak-256 selectors (`selector("fn(bytes32,uint64)")`)
//!   and event topic hashes (`event_topic("Updated(bytes32,uint64)")`).
//! - Provides safe wrappers for ISR persistent state (`storage`), execution context (`context`),
//!   ABI calldata decoding (`abi::CalldataReader`), structured return payloads (`ret`),
//!   and indexed event emission (`events`).
//! - Includes an in-memory host simulator (`mock`) on non-`wasm32` targets so Immortal Subroutines
//!   can be unit-tested natively with `cargo test` in milliseconds.

#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod keccak;

/// Fixed linear-memory layout expected by Lexicon's `WasmtimeAdapter`.
pub mod layout {
    pub const CALLDATA_BUF: usize = 0x10000;
    pub const CALLDATA_CAP: usize = 0x10000; // 64 KiB
    pub const SENDER_BUF: usize = 0x20000;
    pub const KEY_BUF: usize = 0x30000;
    pub const KEY_CAP: usize = 0x10000;
    /// Fixed address where `WasmtimeAdapter::host_state_get` writes retrieved values.
    pub const VAL_BUF: usize = 0x40000;
    pub const VAL_CAP: usize = 0x10000;
    pub const EVENT_BUF: usize = 0x50000;
    pub const EVENT_CAP: usize = 0x10000;
    pub const TOPIC_BUF: usize = 0x60000;
    pub const TOPIC_CAP: usize = 0x1000;
    /// Fixed address where `WasmtimeAdapter` reads `[u32 LE len][payload]` on `ret >= 0`.
    pub const RETURN_BUF: usize = 0x70000;
    pub const RETURN_CAP: usize = 0x80000; // up to 512 KiB
}

#[cfg(target_arch = "wasm32")]
mod sys {
    #[link(wasm_import_module = "env")]
    extern "C" {
        pub fn host_state_get(key_ptr: i32, key_len: i32) -> i32;
        pub fn host_state_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32);
        pub fn host_state_exists(key_ptr: i32, key_len: i32) -> i32;
        pub fn get_calldata(buf_ptr: i32) -> i32;
        pub fn get_msg_sender(buf_ptr: i32);
        pub fn get_block_number(buf_ptr: i32);
        pub fn host_emit_event(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32);
    }
}

/// Native in-memory host simulator enabled automatically during `cargo test` on host targets.
#[cfg(not(target_arch = "wasm32"))]
pub mod mock {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EmittedEvent {
        pub topics: Vec<[u8; 32]>,
        pub data: Vec<u8>,
    }

    #[derive(Default)]
    pub(crate) struct MockHost {
        pub state: BTreeMap<Vec<u8>, Vec<u8>>,
        pub calldata: Vec<u8>,
        pub sender: [u8; 20],
        pub block_number: u64,
        pub events: Vec<EmittedEvent>,
        pub return_data: Vec<u8>,
    }

    thread_local! {
        pub(crate) static HOST: RefCell<MockHost> = RefCell::new(MockHost::default());
    }

    pub fn reset() {
        HOST.with(|h| *h.borrow_mut() = MockHost::default());
    }

    pub fn set_sender(sender: [u8; 20]) {
        HOST.with(|h| h.borrow_mut().sender = sender);
    }

    pub fn set_block_number(block_number: u64) {
        HOST.with(|h| h.borrow_mut().block_number = block_number);
    }

    pub fn set_calldata(calldata: &[u8]) {
        HOST.with(|h| {
            let mut b = h.borrow_mut();
            b.calldata = calldata.to_vec();
            b.return_data.clear();
        });
    }

    pub fn take_return_data() -> Vec<u8> {
        HOST.with(|h| std::mem::take(&mut h.borrow_mut().return_data))
    }

    pub fn events() -> Vec<EmittedEvent> {
        HOST.with(|h| h.borrow().events.clone())
    }
}

/// Compute a 4-byte ISR function selector at compile time.
///
/// Example:
/// ```
/// use isr_sdk::selector;
/// const TRANSFER: [u8; 4] = selector("transfer(address,uint256)");
/// assert_eq!(TRANSFER, [0xa9, 0x05, 0x9c, 0xbb]);
/// ```
pub const fn selector(signature: &str) -> [u8; 4] {
    let h = keccak::keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Compute a 32-byte Keccak-256 event signature topic at compile time.
pub const fn event_topic(signature: &str) -> [u8; 32] {
    keccak::keccak256(signature.as_bytes())
}

/// Execution context queries (`msg.sender`, `block.number`, and `calldata`).
pub mod context {
    #[cfg(target_arch = "wasm32")]
    use crate::{layout, sys};

    /// Copy transaction calldata into guest linear memory and return a slice over it.
    pub fn calldata() -> &'static [u8] {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            core::ptr::write_unaligned(layout::RETURN_BUF as *mut u32, 0u32);
            let len = sys::get_calldata(layout::CALLDATA_BUF as i32);
            if len <= 0 {
                return &[];
            }
            let capped = (len as usize).min(layout::CALLDATA_CAP);
            core::slice::from_raw_parts(layout::CALLDATA_BUF as *const u8, capped)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| {
                let b = h.borrow();
                if b.calldata.is_empty() {
                    &[] as &'static [u8]
                } else {
                    Box::leak(b.calldata.clone().into_boxed_slice()) as &'static [u8]
                }
            })
        }
    }

    /// Return the 20-byte caller address (`msg.sender`).
    pub fn msg_sender() -> [u8; 20] {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            sys::get_msg_sender(layout::SENDER_BUF as i32);
            let mut out = [0u8; 20];
            core::ptr::copy_nonoverlapping(layout::SENDER_BUF as *const u8, out.as_mut_ptr(), 20);
            out
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| h.borrow().sender)
        }
    }

    /// Return the chain-assigned block height of the current block.
    pub fn block_number() -> u64 {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let mut buf = [0u8; 8];
            sys::get_block_number(buf.as_mut_ptr() as i32);
            u64::from_be_bytes(buf)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| h.borrow().block_number)
        }
    }
}

/// Per-ISR persistent key-value slot storage backed by `FlatKvDb` & rooted `StorageTree`.
pub mod storage {
    #[cfg(target_arch = "wasm32")]
    use crate::{layout, sys};

    /// Check whether `key` exists in this ISR's persistent state.
    pub fn exists(key: &[u8]) -> bool {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            sys::host_state_exists(key.as_ptr() as i32, key.len() as i32) != 0
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| h.borrow().state.contains_key(key))
        }
    }

    /// Read `key` from ISR state into `VAL_BUF` and copy up to `out.len()` bytes into `out`.
    /// Returns `Some(total_stored_len)` if present (`> 0` bytes), or `None` if absent.
    pub fn get_into(key: &[u8], out: &mut [u8]) -> Option<usize> {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let len = sys::host_state_get(key.as_ptr() as i32, key.len() as i32);
            if len <= 0 {
                return None;
            }
            let total = len as usize;
            let n = total.min(out.len()).min(layout::VAL_CAP);
            core::ptr::copy_nonoverlapping(layout::VAL_BUF as *const u8, out.as_mut_ptr(), n);
            Some(total)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| {
                let b = h.borrow();
                let v = b.state.get(key)?;
                if v.is_empty() {
                    return None;
                }
                let n = v.len().min(out.len());
                out[..n].copy_from_slice(&v[..n]);
                Some(v.len())
            })
        }
    }

    /// Read `key` into `VAL_BUF` (`0x40000`) and borrow the result directly.
    ///
    /// Note: the returned slice points to `VAL_BUF` and is overwritten by the next
    /// `storage::get_ref` or `storage::get_*` call, so consume or copy it before the next read.
    pub fn get_ref(key: &[u8]) -> Option<&'static [u8]> {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let len = sys::host_state_get(key.as_ptr() as i32, key.len() as i32);
            if len <= 0 {
                return None;
            }
            let n = (len as usize).min(layout::VAL_CAP);
            Some(core::slice::from_raw_parts(layout::VAL_BUF as *const u8, n))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| {
                let b = h.borrow();
                let v = b.state.get(key)?;
                if v.is_empty() {
                    return None;
                }
                Some(Box::leak(v.clone().into_boxed_slice()) as &'static [u8])
            })
        }
    }

    /// Write `val` under `key` in ISR storage. Passing `val = &[]` clears the entry.
    pub fn set(key: &[u8], val: &[u8]) {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            sys::host_state_set(
                key.as_ptr() as i32,
                key.len() as i32,
                val.as_ptr() as i32,
                val.len() as i32,
            );
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| {
                let mut b = h.borrow_mut();
                if val.is_empty() {
                    b.state.remove(key);
                } else {
                    b.state.insert(key.to_vec(), val.to_vec());
                }
            });
        }
    }

    /// Read a little-endian `u64` counter/value, defaulting to `0` if unset.
    pub fn get_u64(key: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        match get_into(key, &mut buf) {
            Some(n) if n >= 8 => u64::from_le_bytes(buf),
            _ => 0,
        }
    }

    /// Write a little-endian `u64` counter/value under `key`.
    pub fn set_u64(key: &[u8], val: u64) {
        set(key, &val.to_le_bytes());
    }

    /// Read a fixed 32-byte word under `key`.
    pub fn get_bytes32(key: &[u8]) -> Option<[u8; 32]> {
        let mut buf = [0u8; 32];
        match get_into(key, &mut buf) {
            Some(32) => Some(buf),
            _ => None,
        }
    }

    /// Helper for building composite storage keys (`prefix || segment1 || segment2`) on the stack
    /// without heap allocation.
    pub struct KeyBuilder<const CAP: usize = 128> {
        buf: [u8; CAP],
        len: usize,
    }

    impl<const CAP: usize> KeyBuilder<CAP> {
        pub const fn new() -> Self {
            Self {
                buf: [0u8; CAP],
                len: 0,
            }
        }

        pub fn push(mut self, bytes: &[u8]) -> Self {
            let avail = CAP.saturating_sub(self.len);
            let n = bytes.len().min(avail);
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            self
        }

        pub fn push_u64_be(self, val: u64) -> Self {
            self.push(&val.to_be_bytes())
        }

        pub fn as_slice(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }
}

/// Structured return-buffer helpers for `eth_call` and ISR return data.
pub mod ret {
    #[cfg(target_arch = "wasm32")]
    use crate::layout;

    /// Write raw return bytes into `RETURN_BUF` (`[u32 LE len][payload]`).
    pub fn write(payload: &[u8]) {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let n = payload.len().min(layout::RETURN_CAP - 4);
            let len_bytes = (n as u32).to_le_bytes();
            core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), layout::RETURN_BUF as *mut u8, 4);
            if n > 0 {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    (layout::RETURN_BUF + 4) as *mut u8,
                    n,
                );
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| h.borrow_mut().return_data = payload.to_vec());
        }
    }

    /// Return an ABI-encoded 32-byte big-endian `uint64` / `uint256` word.
    pub fn write_u64_word(val: u64) {
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&val.to_be_bytes());
        write(&word);
    }

    /// Return an ABI-encoded 32-byte word (`bytes32` or left-padded `address`).
    pub fn write_word(word: &[u8; 32]) {
        write(word);
    }

    /// Return ABI-encoded dynamic `bytes` / `string` (`[offset=0x20][len][padded_data]`).
    pub fn write_abi_bytes(data: &[u8]) {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let pad = (32 - (data.len() % 32)) % 32;
            let total = 64 + data.len() + pad;
            if total + 4 > layout::RETURN_CAP {
                return;
            }
            let len_le = (total as u32).to_le_bytes();
            core::ptr::copy_nonoverlapping(len_le.as_ptr(), layout::RETURN_BUF as *mut u8, 4);

            let out = (layout::RETURN_BUF + 4) as *mut u8;
            core::ptr::write_bytes(out, 0, total);
            *out.add(31) = 0x20;
            let dl_be = (data.len() as u64).to_be_bytes();
            core::ptr::copy_nonoverlapping(dl_be.as_ptr(), out.add(32 + 24), 8);
            if !data.is_empty() {
                core::ptr::copy_nonoverlapping(data.as_ptr(), out.add(64), data.len());
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let pad = (32 - (data.len() % 32)) % 32;
            let mut buf = vec![0u8; 64 + data.len() + pad];
            buf[31] = 0x20;
            buf[56..64].copy_from_slice(&(data.len() as u64).to_be_bytes());
            buf[64..64 + data.len()].copy_from_slice(data);
            write(&buf);
        }
    }
}

/// Indexed ISR event logs (`eth_getLogs` & WebSocket `logs`).
pub mod events {
    #[cfg(target_arch = "wasm32")]
    use crate::{layout, sys};

    /// Emit a log with up to 4 32-byte indexed `topics` and arbitrary `data` payload.
    pub fn emit(topics: &[[u8; 32]], data: &[u8]) {
        #[cfg(target_arch = "wasm32")]
        unsafe {
            let topic_count = topics.len().min(4);
            let topics_bytes_len = topic_count * 32;
            for (i, t) in topics.iter().take(topic_count).enumerate() {
                core::ptr::copy_nonoverlapping(
                    t.as_ptr(),
                    (layout::TOPIC_BUF + i * 32) as *mut u8,
                    32,
                );
            }
            sys::host_emit_event(
                layout::TOPIC_BUF as i32,
                topics_bytes_len as i32,
                data.as_ptr() as i32,
                data.len() as i32,
            );
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::mock::HOST.with(|h| {
                h.borrow_mut().events.push(crate::mock::EmittedEvent {
                    topics: topics.iter().take(4).copied().collect(),
                    data: data.to_vec(),
                });
            });
        }
    }
}

/// Safe ABI calldata decoder for WASM32 guests (guards against 32-bit `usize` truncation).
pub mod abi {
    pub struct CalldataReader<'a> {
        /// Calldata slice *after* the 4-byte function selector.
        args: &'a [u8],
    }

    impl<'a> CalldataReader<'a> {
        /// Split raw calldata into `(4-byte selector, CalldataReader)`.
        pub fn parse(calldata: &'a [u8]) -> Option<([u8; 4], Self)> {
            if calldata.len() < 4 {
                return None;
            }
            let sel = [calldata[0], calldata[1], calldata[2], calldata[3]];
            Some((sel, Self { args: &calldata[4..] }))
        }

        /// Read static 32-byte head word `index` (`0`, `1`, ...).
        pub fn word(&self, index: usize) -> Option<[u8; 32]> {
            let start = index.checked_mul(32)?;
            let end = start.checked_add(32)?;
            if end > self.args.len() {
                return None;
            }
            let mut w = [0u8; 32];
            w.copy_from_slice(&self.args[start..end]);
            Some(w)
        }

        /// Read `bytes32` at argument position `index`.
        pub fn bytes32(&self, index: usize) -> Option<[u8; 32]> {
            self.word(index)
        }

        /// Read 20-byte `address` at argument position `index` (validates upper 12 zero bytes).
        pub fn address(&self, index: usize) -> Option<[u8; 20]> {
            let w = self.word(index)?;
            if w[0..12] != [0u8; 12] {
                return None;
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&w[12..32]);
            Some(addr)
        }

        /// Read `uint64` at argument position `index` (validates upper 24 zero bytes).
        pub fn u64(&self, index: usize) -> Option<u64> {
            let w = self.word(index)?;
            if w[0..24] != [0u8; 24] {
                return None;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&w[24..32]);
            Some(u64::from_be_bytes(b))
        }

        /// Read `bool` at argument position `index`.
        pub fn bool(&self, index: usize) -> Option<bool> {
            match self.u64(index)? {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            }
        }

        /// Read dynamic `bytes` or `string` whose head offset word is at argument `index`.
        /// Protects against 32-bit `usize` overflow on `wasm32`.
        pub fn dynamic_bytes(&self, index: usize) -> Option<&'a [u8]> {
            let offset_u64 = self.u64(index)?;
            if offset_u64 > (self.args.len() as u64) {
                return None;
            }
            let offset = offset_u64 as usize;
            let len_end = offset.checked_add(32)?;
            if len_end > self.args.len() {
                return None;
            }
            if self.args[offset..offset + 24] != [0u8; 24] {
                return None;
            }
            let mut lb = [0u8; 8];
            lb.copy_from_slice(&self.args[offset + 24..len_end]);
            let data_len_u64 = u64::from_be_bytes(lb);
            let data_end_u64 = (len_end as u64).checked_add(data_len_u64)?;
            if data_end_u64 > (self.args.len() as u64) {
                return None;
            }
            Some(&self.args[len_end..data_end_u64 as usize])
        }
    }
}

/// Declare the Immortal Subroutine (`ISR`) entrypoint (`main`) and `#![no_std]` panic handler,
/// routing 4-byte ABI function selectors to Rust handler functions.
///
/// Example:
/// ```ignore
/// isr_sdk::isr_entry! {
///     "increment(bytes32,uint64)" => handle_increment,
///     "getCount(bytes32)"         => handle_get_count,
/// }
/// ```
#[macro_export]
macro_rules! isr_entry {
    ( $( $sig:literal => $handler:ident ),+ $(,)? ) => {
        #[cfg(target_arch = "wasm32")]
        #[panic_handler]
        fn _isr_panic(_info: &core::panic::PanicInfo) -> ! {
            core::arch::wasm32::unreachable()
        }

        /// ISR dispatch function (callable both from Wasmtime `main` and native `cargo test`).
        pub fn dispatch_calldata(raw: &[u8]) -> i32 {
            let Some((sel, reader)) = $crate::abi::CalldataReader::parse(raw) else {
                return -1;
            };
            $(
                {
                    const SEL: [u8; 4] = $crate::selector($sig);
                    if sel == SEL {
                        return match $handler(&reader) {
                            Ok(()) => 0,
                            Err(code) => if code < 0 { code } else { -code.max(1) },
                        };
                    }
                }
            )+
            -2
        }

        #[cfg(target_arch = "wasm32")]
        #[no_mangle]
        pub extern "C" fn main(_argc: i32, _argv: i32) -> i32 {
            let cd = $crate::context::calldata();
            dispatch_calldata(cd)
        }

        #[cfg(not(target_arch = "wasm32"))]
        fn main() {
            let cd = $crate::context::calldata();
            let _ = dispatch_calldata(cd);
        }
    };
}
