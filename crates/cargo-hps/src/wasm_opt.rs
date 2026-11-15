//! Pure-Rust WASM binary optimizer & ABI validator for Lexicon's `WasmtimeAdapter`.
//!
//! 1. Strips custom `.debug_*` / `producers` / `name` sections (`sec_id == 0`) to shrink
//!    over-the-air radio bytecode payloads.
//! 2. Trims leading and trailing zero-filled runs in active WASM Data segments (`sec_id == 11`)
//!    since WASM linear memory is already zero-initialized by specification.
//! 3. Validates that the compiled module:
//!    - Exports `"memory"` with at least 16 initial 64 KiB pages (`>= 1 MiB`) so fixed host
//!      buffers (`0x10000..0x7ffff`) are always valid.
//!    - Exports `"main"`.
//!    - Only imports supported `env::*` host functions wired by `WasmtimeAdapter`.

use anyhow::{anyhow, bail, Result};

const ALLOWED_ENV_IMPORTS: &[&str] = &[
    "host_state_get",
    "host_state_set",
    "host_state_exists",
    "get_calldata",
    "get_msg_sender",
    "get_self_address",
    "host_get_code_hash",
    "get_block_number",
    "host_emit_event",
    "host_call_contract",
];

#[derive(Debug, Clone)]
pub struct WasmArtifactReport {
    pub raw_size: usize,
    pub optimized_size: usize,
    pub initial_memory_pages: u32,
    pub max_memory_pages: Option<u32>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

fn read_uleb(buf: &[u8], mut pos: usize) -> Result<(u64, usize)> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= buf.len() {
            bail!("unexpected EOF reading unsigned LEB128");
        }
        let b = buf[pos];
        pos += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok((val, pos));
        }
        shift += 7;
        if shift >= 64 {
            bail!("unsigned LEB128 overflow");
        }
    }
}

fn read_sleb_i32(buf: &[u8], mut pos: usize) -> Result<(i32, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut byte;
    loop {
        if pos >= buf.len() {
            bail!("unexpected EOF reading signed LEB128");
        }
        byte = buf[pos];
        pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift >= 35 {
            bail!("signed i32 LEB128 overflow");
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok((result as i32, pos))
}

fn write_uleb(mut val: usize, out: &mut Vec<u8>) {
    loop {
        let b = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            break;
        }
    }
}

fn write_sleb_i32(mut val: i32, out: &mut Vec<u8>) {
    loop {
        let b = (val & 0x7f) as u8;
        val >>= 7;
        if (val == 0 && (b & 0x40) == 0) || (val == -1 && (b & 0x40) != 0) {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn read_name<'a>(buf: &'a [u8], pos: usize) -> Result<(&'a str, usize)> {
    let (len, p) = read_uleb(buf, pos)?;
    let end = p + (len as usize);
    if end > buf.len() {
        bail!("name length out of bounds");
    }
    let s = std::str::from_utf8(&buf[p..end]).map_err(|e| anyhow!("invalid utf8 name: {e}"))?;
    Ok((s, end))
}

/// Optimize and validate a raw `wasm32-unknown-unknown` binary for Lexicon deployment.
pub fn optimize_and_validate_wasm(raw: &[u8], strip_custom_sections: bool) -> Result<(Vec<u8>, WasmArtifactReport)> {
    if raw.len() < 8 || &raw[0..4] != b"\0asm" || &raw[4..8] != &[1, 0, 0, 0] {
        bail!("input is not a valid WebAssembly v1 binary module");
    }

    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(&raw[0..8]);

    let mut pos = 8usize;
    let mut initial_memory_pages: Option<u32> = None;
    let mut max_memory_pages: Option<u32> = None;
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    while pos < raw.len() {
        let sec_id = raw[pos];
        pos += 1;
        let (sec_size_u64, next_pos) = read_uleb(raw, pos)?;
        let sec_size = sec_size_u64 as usize;
        pos = next_pos;
        if pos + sec_size > raw.len() {
            bail!("section {sec_id} truncated");
        }
        let body = &raw[pos..pos + sec_size];
        pos += sec_size;

        match sec_id {
            // Custom sections (`name`, `producers`, `.debug_*`, `target_features`)
            0 if strip_custom_sections => {
                continue;
            }
            // Import section (`sec_id == 2`)
            2 => {
                let (count, mut p) = read_uleb(body, 0)?;
                for _ in 0..count {
                    let (module, p1) = read_name(body, p)?;
                    let (field, p2) = read_name(body, p1)?;
                    if p2 >= body.len() {
                        bail!("truncated import descriptor");
                    }
                    let kind = body[p2];
                    p = p2 + 1;
                    match kind {
                        0 => {
                            // func typeidx
                            let (_, pn) = read_uleb(body, p)?;
                            p = pn;
                        }
                        1 => {
                            // table: reftype + limits
                            p += 1;
                            let (flags, pn) = read_uleb(body, p)?;
                            let (_, pn2) = read_uleb(body, pn)?;
                            p = if (flags & 1) != 0 {
                                read_uleb(body, pn2)?.1
                            } else {
                                pn2
                            };
                        }
                        2 => {
                            // memory limits
                            let (flags, pn) = read_uleb(body, p)?;
                            let (_, pn2) = read_uleb(body, pn)?;
                            p = if (flags & 1) != 0 {
                                read_uleb(body, pn2)?.1
                            } else {
                                pn2
                            };
                        }
                        3 => {
                            // global: valtype + mut
                            p += 2;
                        }
                        other => bail!("unsupported WASM import kind {other}"),
                    }

                    if module != "env" || !ALLOWED_ENV_IMPORTS.contains(&field) {
                        bail!(
                            "HPS imports unsupported host function `{module}::{field}`.\n\
                             Allowed Lexicon WasmtimeAdapter imports: env::{{{}}}",
                            ALLOWED_ENV_IMPORTS.join(", ")
                        );
                    }
                    imports.push(format!("{module}::{field}"));
                }
                out.push(sec_id);
                write_uleb(body.len(), &mut out);
                out.extend_from_slice(body);
            }
            // Memory section (`sec_id == 5`)
            5 => {
                let (count, mut p) = read_uleb(body, 0)?;
                if count >= 1 {
                    let (flags, p1) = read_uleb(body, p)?;
                    let (min_pages, p2) = read_uleb(body, p1)?;
                    initial_memory_pages = Some(min_pages as u32);
                    if (flags & 1) != 0 {
                        let (max_p, _p3) = read_uleb(body, p2)?;
                        max_memory_pages = Some(max_p as u32);
                    }
                    let _ = &mut p;
                }
                out.push(sec_id);
                write_uleb(body.len(), &mut out);
                out.extend_from_slice(body);
            }
            // Export section (`sec_id == 7`)
            7 => {
                let (count, mut p) = read_uleb(body, 0)?;
                for _ in 0..count {
                    let (name, p1) = read_name(body, p)?;
                    if p1 >= body.len() {
                        bail!("truncated export entry");
                    }
                    let _kind = body[p1];
                    let (_, p2) = read_uleb(body, p1 + 1)?;
                    p = p2;
                    exports.push(name.to_string());
                }
                out.push(sec_id);
                write_uleb(body.len(), &mut out);
                out.extend_from_slice(body);
            }
            // Data section (`sec_id == 11`): strip leading & trailing zero runs in active segments
            11 => {
                if let Ok(rewritten) = trim_active_data_section(body) {
                    if !rewritten.is_empty() {
                        out.push(11);
                        write_uleb(rewritten.len(), &mut out);
                        out.extend_from_slice(&rewritten);
                    }
                } else {
                    out.push(11);
                    write_uleb(body.len(), &mut out);
                    out.extend_from_slice(body);
                }
            }
            // DataCount section (`sec_id == 12`): omit if present so trimmed empty segments stay valid
            12 => {
                continue;
            }
            _ => {
                out.push(sec_id);
                write_uleb(body.len(), &mut out);
                out.extend_from_slice(body);
            }
        }
    }

    if !exports.iter().any(|e| e == "memory") {
        bail!("compiled WASM module does not export `memory`");
    }
    if !exports.iter().any(|e| e == "main") {
        bail!(
            "compiled WASM module does not export `main(i32, i32) -> i32` \
             (use `hps_sdk::hps_entry! {{ ... }}`)"
        );
    }
    let min_pages = initial_memory_pages.unwrap_or(0);
    if min_pages < 16 {
        bail!(
            "compiled WASM linear memory has only {min_pages} initial page(s) ({} KiB); \
             Lexicon requires >= 16 pages (>= 1 MiB) so fixed buffers at 0x10000..0x70000 are in-bounds",
            min_pages * 64
        );
    }

    Ok((
        out.clone(),
        WasmArtifactReport {
            raw_size: raw.len(),
            optimized_size: out.len(),
            initial_memory_pages: min_pages,
            max_memory_pages,
            imports,
            exports,
        },
    ))
}

fn trim_active_data_section(body: &[u8]) -> Result<Vec<u8>> {
    let (count, mut p) = read_uleb(body, 0)?;
    let mut kept_segments: Vec<(i32, &[u8])> = Vec::new();

    for _ in 0..count {
        let (flags, p1) = read_uleb(body, p)?;
        if flags != 0 {
            bail!("non-zero data segment flags ({flags})");
        }
        if p1 >= body.len() || body[p1] != 0x41 {
            bail!("unsupported data segment offset expr");
        }
        let (offset, p2) = read_sleb_i32(body, p1 + 1)?;
        if p2 >= body.len() || body[p2] != 0x0b {
            bail!("missing end opcode in data segment offset expr");
        }
        let (seg_len_u64, p3) = read_uleb(body, p2 + 1)?;
        let seg_len = seg_len_u64 as usize;
        if p3 + seg_len > body.len() {
            bail!("data segment payload truncated");
        }
        let seg = &body[p3..p3 + seg_len];
        p = p3 + seg_len;

        // Trim leading zeros (advancing segment offset) and trailing zeros.
        let lead = seg.iter().take_while(|&&b| b == 0).count();
        if lead == seg.len() {
            continue;
        }
        let trimmed_lead = &seg[lead..];
        let trail = trimmed_lead.iter().rev().take_while(|&&b| b == 0).count();
        let kept = &trimmed_lead[..trimmed_lead.len() - trail];
        let new_offset = offset
            .checked_add(lead as i32)
            .ok_or_else(|| anyhow!("segment offset overflow"))?;
        kept_segments.push((new_offset, kept));
    }

    if kept_segments.is_empty() {
        return Ok(Vec::new());
    }

    let mut sec = Vec::new();
    write_uleb(kept_segments.len(), &mut sec);
    for (off, bytes) in kept_segments {
        write_uleb(0, &mut sec);
        sec.push(0x41);
        write_sleb_i32(off, &mut sec);
        sec.push(0x0b);
        write_uleb(bytes.len(), &mut sec);
        sec.extend_from_slice(bytes);
    }
    Ok(sec)
}
