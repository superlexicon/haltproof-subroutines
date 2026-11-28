//! `cargo hps studio` — Full-Stack HFS Rust Compiler, Unit-Test Runner & Web IDE Daemon.
//!
//! Supports two operating modes from a single codebase:
//! 1. **Local Developer Mode (`cargo hps studio`)**:
//!    - Pre-warms `libhps_sdk.rlib` (`wasm32-unknown-unknown`) for sub-second `rustc` compilation.
//!    - Runs native `#[cfg(test)]` unit tests against `hps_sdk::mock` (`POST /api/test`).
//!    - Browses workspace `examples/*` crates and saves full `cargo-hps` projects locally.
//!    - Serves the standalone HFS Studio Web IDE at `http://127.0.0.1:4770/`.
//! 2. **Hosted Stateless Sandbox Mode (`cargo hps studio --sandbox`)**:
//!    - Enforces strict `#![no_std]` single-file source sanitization (blocks `include!`,
//!      `include_bytes!`, `include_str!`, `env!`, `#[path]`, and external crates).
//!    - Compiles `main.rs` -> `.wasm` via isolated `rustc` with concurrency limits & timeouts
//!      without ever executing untrusted native host binaries on the server.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use hps_client::abi::keccak256;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command as TokioCommand;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use crate::bundler::{
    create_app_bundle, deterministic_gzip, gunzip_utf8, sanitize_slug, BundleOptions,
    APP_STORE_CHUNK_BYTES,
};
use crate::wasm_opt;
use crate::MAX_LEXICON_BYTECODE_BYTES;

const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB max request body
const MAX_RUST_SOURCE_BYTES: usize = 256 * 1024; // 256 KiB max single-file HFS source
const COMPILE_TIMEOUT_SECS: u64 = 20;
const TEST_TIMEOUT_SECS: u64 = 25;

static BUILD_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct StudioOptions {
    pub bind: String,
    pub sandbox: bool,
    pub workspace_root: PathBuf,
    pub ui_bundle_path: Option<PathBuf>,
}

pub struct StudioState {
    pub sandbox: bool,
    pub workspace_root: PathBuf,
    pub sdk_src_dir: PathBuf,
    pub wasm_sdk_rlib: PathBuf,
    pub cache_dir: PathBuf,
    pub ui_bundle_path: Option<PathBuf>,
    pub rustc_version: String,
    pub compile_sem: Semaphore,
    pub test_lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompilerDiagnostic {
    pub level: String,
    pub message: String,
    pub code: Option<String>,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub rendered: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbiParamSpec {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbiFunctionSpec {
    pub signature: String,
    pub name: String,
    pub handler: String,
    pub selector: String,
    pub mutability: String,
    pub return_hint: String,
    pub inputs: Vec<AbiParamSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbiEventSpec {
    pub signature: String,
    pub name: String,
    pub constant_name: String,
    pub topic0: String,
    pub inputs: Vec<AbiParamSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedHpsAbi {
    pub functions: Vec<AbiFunctionSpec>,
    pub events: Vec<AbiEventSpec>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileResultPayload {
    pub ok: bool,
    pub elapsed_ms: u64,
    pub wasm_base64: Option<String>,
    pub code_hash: Option<String>,
    pub raw_size: usize,
    pub optimized_size: usize,
    pub max_bytecode_bytes: usize,
    pub initial_memory_pages: u32,
    pub max_memory_pages: Option<u32>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub abi: ExtractedHpsAbi,
    pub diagnostics: Vec<CompilerDiagnostic>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompileRequest {
    #[serde(default)]
    name: String,
    rust_source: String,
    #[serde(default = "default_true")]
    strip_custom_sections: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleRequest {
    slug: String,
    title: String,
    #[serde(default = "default_ver")]
    version: String,
    #[serde(default = "default_cat")]
    category: u16,
    #[serde(default = "default_icon")]
    icon: String,
    #[serde(default)]
    summary: String,
    index_html: String,
    #[serde(default)]
    styles_css: String,
    #[serde(default)]
    app_js: String,
    #[serde(default)]
    auto_bridge_js: String,
    #[serde(default)]
    allow_external_urls: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveLocalRequest {
    slug: String,
    title: String,
    #[serde(default = "default_ver")]
    version: String,
    #[serde(default = "default_cat")]
    category: u16,
    #[serde(default = "default_icon")]
    icon: String,
    #[serde(default)]
    summary: String,
    rust_source: String,
    index_html: String,
    #[serde(default)]
    styles_css: String,
    #[serde(default)]
    app_js: String,
    #[serde(default)]
    auto_bridge_js: String,
    #[serde(default)]
    wasm_base64: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_ver() -> String {
    "1.0.0".to_string()
}
fn default_cat() -> u16 {
    6
}
fn default_icon() -> String {
    "⚡".to_string()
}

pub fn resolve_default_workspace_root() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        for anc in cwd.ancestors() {
            if anc.join("crates/hps-sdk/src/lib.rs").exists() {
                return anc.to_path_buf();
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn resolve_default_ui_bundle(workspace_root: &Path) -> Option<PathBuf> {
    let candidates = [
        workspace_root.join("../lexicon-client-web/public/app-bundles/hfs-ide.html.gz"),
        workspace_root.join("../superlexicon-slides/client/public/app-bundles/hfs-ide.html.gz"),
        workspace_root.join("dist/hfs-ide.html.gz"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let mut lut = [255u8; 256];
    for (i, &b) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        lut[b as usize] = i as u8;
    }
    let clean: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 4 {
            bail!("invalid base64 length");
        }
        let c0 = lut[chunk[0] as usize];
        let c1 = lut[chunk[1] as usize];
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        let c2 = if pad2 { 0 } else { lut[chunk[2] as usize] };
        let c3 = if pad3 { 0 } else { lut[chunk[3] as usize] };
        if c0 == 255 || c1 == 255 || c2 == 255 || c3 == 255 {
            bail!("invalid base64 character");
        }
        let triple = ((c0 as u32) << 18) | ((c1 as u32) << 12) | ((c2 as u32) << 6) | (c3 as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if !pad3 {
            out.push((triple & 0xFF) as u8);
        }
    }
    Ok(out)
}

fn newest_mtime_in_dir(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = entry.metadata().ok()?;
        let t = if meta.is_dir() {
            newest_mtime_in_dir(&path)
        } else {
            meta.modified().ok()
        };
        if let Some(ts) = t {
            newest = Some(match newest {
                Some(cur) if cur >= ts => cur,
                _ => ts,
            });
        }
    }
    newest
}

/// Pre-compiles `crates/hps-sdk` for `wasm32-unknown-unknown` into `libhps_sdk.rlib` with embedded
/// LLVM bitcode so single-file `rustc -C lto=fat` compilations complete in ~250–600ms with zero
/// Cargo lock contention.
pub fn ensure_prebuilt_wasm_sdk(sdk_src_dir: &Path, cache_dir: &Path) -> Result<(PathBuf, String)> {
    let lib_rs = sdk_src_dir.join("src/lib.rs");
    if !lib_rs.exists() {
        bail!(
            "cannot locate hps-sdk at '{}'",
            lib_rs.display()
        );
    }
    fs::create_dir_all(cache_dir)?;

    let ver_out = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .context("failed to run `rustc --version` — ensure Rust toolchain is installed")?;
    let rustc_ver = String::from_utf8_lossy(&ver_out.stdout).trim().to_string();

    let rlib_path = cache_dir.join("libhps_sdk_wasm32.rlib");
    let stamp_path = cache_dir.join("rustc_version.txt");

    let up_to_date = if rlib_path.exists() && stamp_path.exists() {
        let saved_ver = fs::read_to_string(&stamp_path).unwrap_or_default();
        let rlib_mtime = fs::metadata(&rlib_path).and_then(|m| m.modified()).ok();
        let src_mtime = newest_mtime_in_dir(&sdk_src_dir.join("src"));
        match (rlib_mtime, src_mtime) {
            (Some(rm), Some(sm)) => saved_ver.trim() == rustc_ver && rm >= sm,
            _ => false,
        }
    } else {
        false
    };

    if !up_to_date {
        println!(
            "[studio] Pre-compiling `hps-sdk` (wasm32-unknown-unknown, -Oz + bitcode) into {}...",
            rlib_path.display()
        );
        let out = std::process::Command::new("rustc")
            .arg("--crate-name")
            .arg("hps_sdk")
            .arg("--edition=2021")
            .arg(&lib_rs)
            .arg("--crate-type")
            .arg("rlib")
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .arg("-C")
            .arg("opt-level=z")
            .arg("-C")
            .arg("panic=abort")
            .arg("-C")
            .arg("codegen-units=1")
            .arg("-C")
            .arg("embed-bitcode=yes")
            .arg("-o")
            .arg(&rlib_path)
            .output()
            .context("failed to invoke `rustc` for `hps-sdk` wasm32 pre-warm")?;
        if !out.status.success() {
            bail!(
                "failed to pre-compile `hps-sdk` for wasm32-unknown-unknown:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let _ = fs::write(&stamp_path, &rustc_ver);
    }

    Ok((rlib_path, rustc_ver))
}

/// Rejects host-filesystem macros and external crates when running in `--sandbox` mode.
pub fn validate_sandbox_rust_source(src: &str) -> Result<()> {
    if src.len() > MAX_RUST_SOURCE_BYTES {
        bail!(
            "Rust source ({} bytes) exceeds maximum allowed size ({} KiB)",
            src.len(),
            MAX_RUST_SOURCE_BYTES / 1024
        );
    }
    // Strip line and block comments before checking restricted macro/attribute tokens
    let stripped = strip_rust_comments(src);
    let forbidden_patterns = [
        ("include!(", "`include!` macro is disabled in sandbox mode"),
        ("include_bytes!(", "`include_bytes!` macro is disabled in sandbox mode"),
        ("include_str!(", "`include_str!` macro is disabled in sandbox mode"),
        ("env!(", "`env!` macro is disabled in sandbox mode"),
        ("option_env!(", "`option_env!` macro is disabled in sandbox mode"),
        ("#[path", "`#[path = ...]` module redirection is disabled in sandbox mode"),
        ("#![path", "`#![path = ...]` attribute is disabled in sandbox mode"),
        ("std::fs", "`std::fs` is not available in `#![no_std]` HFS subroutines"),
        ("std::process", "`std::process` is not available in `#![no_std]` HFS subroutines"),
        ("std::net", "`std::net` is not available in `#![no_std]` HFS subroutines"),
    ];
    let compact: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
    for (needle, reason) in forbidden_patterns {
        if compact.contains(needle) {
            bail!("Sandbox security policy: {reason}");
        }
    }
    Ok(())
}

fn strip_rust_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut in_str = false;
    while i < bytes.len() {
        if in_str {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i] as char);
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_str = false;
            }
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        if bytes[i] == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            let mut depth = 1usize;
            while i + 1 < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_fn_body<'a>(clean_src: &'a str, fn_name: &str) -> Option<&'a str> {
    let needle = format!("fn {fn_name}");
    let mut search_from = 0usize;
    while let Some(rel) = clean_src[search_from..].find(&needle) {
        let pos = search_from + rel;
        let after = pos + needle.len();
        if after < clean_src.len() {
            let next_ch = clean_src.as_bytes()[after];
            if next_ch.is_ascii_alphanumeric() || next_ch == b'_' {
                search_from = after;
                continue;
            }
        }
        if let Some(brace_rel) = clean_src[after..].find('{') {
            let start = after + brace_rel;
            let bytes = clean_src.as_bytes();
            let mut depth = 0usize;
            for (idx, &b) in bytes[start..].iter().enumerate() {
                if b == b'{' {
                    depth += 1;
                } else if b == b'}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(&clean_src[start..start + idx + 1]);
                    }
                }
            }
        }
        break;
    }
    None
}

fn infer_param_names_from_handler(body: Option<&str>, types: &[String]) -> Vec<AbiParamSpec> {
    let mut names: HashMap<usize, String> = HashMap::new();
    if let Some(b) = body {
        // Look for patterns like `let <ident> = <reader>.<method>(<idx>)`
        for line in b.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("let ") {
                let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim();
                let ident: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if ident.is_empty() || ident.starts_with('_') {
                    continue;
                }
                for method in [
                    ".u64(",
                    ".u256_be(",
                    ".address(",
                    ".bytes32(",
                    ".word(",
                    ".bool(",
                    ".bytes4(",
                    ".dynamic_bytes(",
                ] {
                    if let Some(mpos) = rest.find(method) {
                        let idx_part = &rest[mpos + method.len()..];
                        let digits: String =
                            idx_part.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if let Ok(idx) = digits.parse::<usize>() {
                            names.entry(idx).or_insert(ident.clone());
                        }
                    }
                }
            }
        }
    }

    types
        .iter()
        .enumerate()
        .map(|(idx, kind)| AbiParamSpec {
            name: names.remove(&idx).unwrap_or_else(|| format!("arg{idx}")),
            kind: kind.clone(),
        })
        .collect()
}

fn parse_sig_name_and_types(sig: &str) -> Option<(String, Vec<String>)> {
    let open = sig.find('(')?;
    let close = sig.rfind(')')?;
    if close < open {
        return None;
    }
    let name = sig[..open].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let inside = sig[open + 1..close].trim();
    let types = if inside.is_empty() {
        Vec::new()
    } else {
        inside
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    };
    Some((name, types))
}

/// Parses `hps_entry! { ... }` and `event_topic("...")` declarations from Rust HFS source code
/// so the Web IDE can auto-generate the interactive ABI Workbench and typed `window.HFS` client.
pub fn extract_hps_abi(rust_source: &str) -> ExtractedHpsAbi {
    let clean = strip_rust_comments(rust_source);
    let mut functions = Vec::new();
    let mut events = Vec::new();

    // 1. Parse `hps_entry! { "sig" => handler, ... }`
    if let Some(entry_idx) = clean.find("hps_entry!") {
        let after_macro = &clean[entry_idx + "hps_entry!".len()..];
        if let Some(open_brace) = after_macro.find('{') {
            let block_start = &after_macro[open_brace + 1..];
            let mut depth = 1usize;
            let mut end_idx = block_start.len();
            for (i, ch) in block_start.char_indices() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = i;
                        break;
                    }
                }
            }
            let block = &block_start[..end_idx];
            let mut cursor = block;
            while let Some(q1) = cursor.find('"') {
                let after_q1 = &cursor[q1 + 1..];
                let Some(q2) = after_q1.find('"') else {
                    break;
                };
                let sig = after_q1[..q2].trim();
                let after_sig = &after_q1[q2 + 1..];
                let mut handler_name = String::new();
                if let Some(arrow) = after_sig.find("=>") {
                    let rhs = after_sig[arrow + 2..].trim_start();
                    handler_name = rhs
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                        .collect();
                }
                if let Some((fn_name, param_types)) = parse_sig_name_and_types(sig) {
                    let hash = keccak256(sig.as_bytes());
                    let selector = format!("0x{}", hex::encode(&hash[0..4]));
                    let short_handler = handler_name
                        .rsplit("::")
                        .next()
                        .unwrap_or(&handler_name);
                    let fn_body = find_fn_body(&clean, short_handler);
                    let inputs = infer_param_names_from_handler(fn_body, &param_types);

                    let lower_name = fn_name.to_ascii_lowercase();
                    let looks_view_by_name = lower_name.starts_with("get")
                        || lower_name.starts_with("is")
                        || lower_name.starts_with("has")
                        || lower_name.starts_with("can")
                        || lower_name.starts_with("total")
                        || lower_name.starts_with("read")
                        || lower_name.starts_with("query")
                        || lower_name.starts_with("list")
                        || lower_name.starts_with("resolve")
                        || lower_name.starts_with("preview")
                        || lower_name.starts_with("count")
                        || lower_name.starts_with("balance")
                        || lower_name == "owner"
                        || lower_name == "admin"
                        || lower_name == "version"
                        || lower_name == "abiversion";

                    let body_mutates = fn_body
                        .map(|b| {
                            b.contains("storage::set")
                                || b.contains("events::emit")
                                || b.contains("host_state_set")
                                || b.contains("host_emit_event")
                        })
                        .unwrap_or(false);

                    let mutability = if body_mutates {
                        "nonpayable"
                    } else if looks_view_by_name
                        || fn_body
                            .map(|b| b.contains("ret::write") && !b.contains("call::"))
                            .unwrap_or(false)
                    {
                        "view"
                    } else {
                        "nonpayable"
                    };

                    let return_hint = match fn_body {
                        Some(b) if b.contains("ret::write_u64_word") => "uint64",
                        Some(b) if b.contains("ret::write_bool") => "bool",
                        Some(b) if b.contains("ret::write_address") => "address",
                        Some(b) if b.contains("ret::write_abi_bytes") => "bytes",
                        Some(b) if b.contains("ret::write_word") => "bytes32",
                        Some(b) if b.contains("ret::write(") => "bytes",
                        _ => "void",
                    }
                    .to_string();

                    functions.push(AbiFunctionSpec {
                        signature: sig.to_string(),
                        name: fn_name,
                        handler: handler_name,
                        selector,
                        mutability: mutability.to_string(),
                        return_hint,
                        inputs,
                    });
                }
                cursor = after_sig;
            }
        }
    }

    // 2. Parse `event_topic("EventName(t1,t2)")`
    let mut ev_cursor: &str = &clean;
    while let Some(pos) = ev_cursor.find("event_topic(") {
        let prefix = &ev_cursor[..pos];
        let const_name = prefix
            .lines()
            .last()
            .and_then(|line| {
                let l = line.trim();
                let after_const = l.strip_prefix("pub const ").or_else(|| l.strip_prefix("const "))?;
                Some(
                    after_const
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect::<String>(),
                )
            })
            .unwrap_or_default();

        let after = &ev_cursor[pos + "event_topic(".len()..];
        if let Some(q1) = after.find('"') {
            let s1 = &after[q1 + 1..];
            if let Some(q2) = s1.find('"') {
                let ev_sig = s1[..q2].trim();
                if let Some((ev_name, ev_types)) = parse_sig_name_and_types(ev_sig) {
                    let topic0 = format!("0x{}", hex::encode(keccak256(ev_sig.as_bytes())));
                    let inputs = ev_types
                        .into_iter()
                        .enumerate()
                        .map(|(i, k)| AbiParamSpec {
                            name: format!("field{i}"),
                            kind: k,
                        })
                        .collect();
                    events.push(AbiEventSpec {
                        signature: ev_sig.to_string(),
                        name: ev_name,
                        constant_name: const_name,
                        topic0,
                        inputs,
                    });
                }
                ev_cursor = &s1[q2 + 1..];
                continue;
            }
        }
        ev_cursor = after;
    }

    ExtractedHpsAbi { functions, events }
}

fn parse_rustc_json_diagnostics(stderr_bytes: &[u8]) -> Vec<CompilerDiagnostic> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(stderr_bytes);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(level) = val.get("level").and_then(|v| v.as_str()) else {
            continue;
        };
        if level != "error" && level != "warning" {
            continue;
        }
        let message = val
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if message.starts_with("aborting due to") || message.contains("warnings emitted") {
            continue;
        }
        let code = val
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let rendered = val
            .get("rendered")
            .and_then(|v| v.as_str())
            .unwrap_or(&message)
            .to_string();

        let mut line_start = 1usize;
        let mut col_start = 1usize;
        let mut line_end = 1usize;
        let mut col_end = 1usize;

        if let Some(spans) = val.get("spans").and_then(|s| s.as_array()) {
            let chosen = spans
                .iter()
                .find(|s| s.get("is_primary").and_then(|b| b.as_bool()) == Some(true))
                .or_else(|| spans.first());
            if let Some(sp) = chosen {
                line_start = sp.get("line_start").and_then(|n| n.as_u64()).unwrap_or(1) as usize;
                col_start = sp.get("column_start").and_then(|n| n.as_u64()).unwrap_or(1) as usize;
                line_end = sp
                    .get("line_end")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(line_start as u64) as usize;
                col_end = sp
                    .get("column_end")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(col_start as u64) as usize;
            }
        }

        out.push(CompilerDiagnostic {
            level: level.to_string(),
            message,
            code,
            line: line_start,
            column: col_start,
            end_line: line_end,
            end_column: col_end,
            rendered,
        });
    }
    out
}

/// Compiles a single-file `#![no_std]` Rust HFS source string into an optimized, validated
/// Lexicon `.wasm` binary using the pre-warmed `libhps_sdk.rlib`.
pub async fn compile_rust_hfs_source(
    state: &StudioState,
    crate_label: &str,
    rust_source: &str,
    strip_custom_sections: bool,
) -> CompileResultPayload {
    let started = Instant::now();
    let abi = extract_hps_abi(rust_source);

    if state.sandbox {
        if let Err(err) = validate_sandbox_rust_source(rust_source) {
            return CompileResultPayload {
                ok: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
                wasm_base64: None,
                code_hash: None,
                raw_size: 0,
                optimized_size: 0,
                max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                initial_memory_pages: 0,
                max_memory_pages: None,
                imports: Vec::new(),
                exports: Vec::new(),
                abi,
                diagnostics: vec![CompilerDiagnostic {
                    level: "error".to_string(),
                    message: err.to_string(),
                    code: Some("SANDBOX_POLICY".to_string()),
                    line: 1,
                    column: 1,
                    end_line: 1,
                    end_column: 1,
                    rendered: err.to_string(),
                }],
                error: Some(err.to_string()),
            };
        }
    } else if rust_source.len() > MAX_RUST_SOURCE_BYTES * 4 {
        let msg = "Rust source exceeds 1 MiB limit".to_string();
        return CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: 0,
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics: Vec::new(),
            error: Some(msg),
        };
    }

    let Ok(_permit) = state.compile_sem.acquire().await else {
        return CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: 0,
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics: Vec::new(),
            error: Some("compiler semaphore closed".to_string()),
        };
    };

    let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
    let build_dir = state
        .cache_dir
        .join("builds")
        .join(format!("job_{}_{}", std::process::id(), seq));
    if let Err(e) = fs::create_dir_all(&build_dir) {
        return CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: 0,
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics: Vec::new(),
            error: Some(format!("failed to create temp build dir: {e}")),
        };
    }

    let src_path = build_dir.join("main.rs");
    let out_wasm_path = build_dir.join("contract.wasm");
    let clean_crate: String = sanitize_slug(crate_label)
        .replace('-', "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let crate_ident = if clean_crate.is_empty() || clean_crate.as_bytes()[0].is_ascii_digit() {
        format!("hfs_{clean_crate}")
    } else {
        clean_crate
    };

    if let Err(e) = fs::write(&src_path, rust_source) {
        let _ = fs::remove_dir_all(&build_dir);
        return CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: 0,
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics: Vec::new(),
            error: Some(format!("failed writing temp main.rs: {e}")),
        };
    }

    let mut cmd = TokioCommand::new("rustc");
    cmd.arg("--crate-name")
        .arg(&crate_ident)
        .arg("--edition=2021")
        .arg(&src_path)
        .arg("--crate-type")
        .arg("bin")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("-C")
        .arg("opt-level=z")
        .arg("-C")
        .arg("lto=fat")
        .arg("-C")
        .arg("codegen-units=1")
        .arg("-C")
        .arg("panic=abort")
        .arg("-C")
        .arg("strip=symbols")
        .arg("-C")
        .arg("link-arg=--initial-memory=2097152")
        .arg("-C")
        .arg("link-arg=--max-memory=4194304")
        .arg("--extern")
        .arg(format!("hps_sdk={}", state.wasm_sdk_rlib.display()))
        .arg("--error-format=json")
        .arg("-o")
        .arg(&out_wasm_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let run_res = timeout(Duration::from_secs(COMPILE_TIMEOUT_SECS), cmd.output()).await;
    let output = match run_res {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            let _ = fs::remove_dir_all(&build_dir);
            return CompileResultPayload {
                ok: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
                wasm_base64: None,
                code_hash: None,
                raw_size: 0,
                optimized_size: 0,
                max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                initial_memory_pages: 0,
                max_memory_pages: None,
                imports: Vec::new(),
                exports: Vec::new(),
                abi,
                diagnostics: Vec::new(),
                error: Some(format!("failed to invoke rustc: {e}")),
            };
        }
        Err(_) => {
            let _ = fs::remove_dir_all(&build_dir);
            return CompileResultPayload {
                ok: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
                wasm_base64: None,
                code_hash: None,
                raw_size: 0,
                optimized_size: 0,
                max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                initial_memory_pages: 0,
                max_memory_pages: None,
                imports: Vec::new(),
                exports: Vec::new(),
                abi,
                diagnostics: Vec::new(),
                error: Some(format!(
                    "compilation timed out after {COMPILE_TIMEOUT_SECS}s"
                )),
            };
        }
    };

    let diagnostics = parse_rustc_json_diagnostics(&output.stderr);
    if !output.status.success() {
        let fallback_err = diagnostics
            .iter()
            .find(|d| d.level == "error")
            .map(|d| format!("Line {}: {}", d.line, d.message))
            .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string());
        let _ = fs::remove_dir_all(&build_dir);
        return CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: 0,
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics,
            error: Some(fallback_err),
        };
    }

    let raw_bytes = match fs::read(&out_wasm_path) {
        Ok(b) => b,
        Err(e) => {
            let _ = fs::remove_dir_all(&build_dir);
            return CompileResultPayload {
                ok: false,
                elapsed_ms: started.elapsed().as_millis() as u64,
                wasm_base64: None,
                code_hash: None,
                raw_size: 0,
                optimized_size: 0,
                max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                initial_memory_pages: 0,
                max_memory_pages: None,
                imports: Vec::new(),
                exports: Vec::new(),
                abi,
                diagnostics,
                error: Some(format!("missing compiled wasm output: {e}")),
            };
        }
    };
    let _ = fs::remove_dir_all(&build_dir);

    match wasm_opt::optimize_and_validate_wasm(&raw_bytes, strip_custom_sections) {
        Ok((opt_bytes, report)) => {
            if opt_bytes.len() > MAX_LEXICON_BYTECODE_BYTES {
                let err_msg = format!(
                    "Optimized WASM ({} bytes) exceeds Lexicon radio bytecode limit ({} bytes)",
                    opt_bytes.len(),
                    MAX_LEXICON_BYTECODE_BYTES
                );
                return CompileResultPayload {
                    ok: false,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    wasm_base64: None,
                    code_hash: None,
                    raw_size: report.raw_size,
                    optimized_size: report.optimized_size,
                    max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                    initial_memory_pages: report.initial_memory_pages,
                    max_memory_pages: report.max_memory_pages,
                    imports: report.imports,
                    exports: report.exports,
                    abi,
                    diagnostics,
                    error: Some(err_msg),
                };
            }
            let code_hash = format!("0x{}", hex::encode(keccak256(&opt_bytes)));
            CompileResultPayload {
                ok: true,
                elapsed_ms: started.elapsed().as_millis() as u64,
                wasm_base64: Some(base64_encode(&opt_bytes)),
                code_hash: Some(code_hash),
                raw_size: report.raw_size,
                optimized_size: report.optimized_size,
                max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
                initial_memory_pages: report.initial_memory_pages,
                max_memory_pages: report.max_memory_pages,
                imports: report.imports,
                exports: report.exports,
                abi,
                diagnostics,
                error: None,
            }
        }
        Err(val_err) => CompileResultPayload {
            ok: false,
            elapsed_ms: started.elapsed().as_millis() as u64,
            wasm_base64: None,
            code_hash: None,
            raw_size: raw_bytes.len(),
            optimized_size: 0,
            max_bytecode_bytes: MAX_LEXICON_BYTECODE_BYTES,
            initial_memory_pages: 0,
            max_memory_pages: None,
            imports: Vec::new(),
            exports: Vec::new(),
            abi,
            diagnostics: vec![CompilerDiagnostic {
                level: "error".to_string(),
                message: val_err.to_string(),
                code: Some("HFS_WASM_ABI".to_string()),
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 1,
                rendered: val_err.to_string(),
            }],
            error: Some(val_err.to_string()),
        },
    }
}

async fn run_local_unit_tests(state: &StudioState, rust_source: &str) -> Value {
    let started = Instant::now();
    if state.sandbox {
        return json!({
            "ok": false,
            "sandboxRestricted": true,
            "elapsedMs": 0,
            "error": "Native host `cargo test` execution is disabled on shared `--sandbox` servers. Use the In-Browser WASM VM right inside the IDE, or run `cargo hps studio` locally on Linux/macOS to run `#[test]` suites."
        });
    }

    let _guard = state.test_lock.lock().await;
    let harness_dir = state.cache_dir.join("test_harness");
    let src_dir = harness_dir.join("src");
    if let Err(e) = fs::create_dir_all(&src_dir) {
        return json!({ "ok": false, "error": format!("failed to prepare test harness: {e}") });
    }

    let cargo_toml = format!(
        r#"[workspace]

[package]
name = "hps-studio-test-runner"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "hps_studio_test_runner"
path = "src/main.rs"

[dependencies]
hps-sdk = {{ path = "{}" }}
"#,
        state.sdk_src_dir.display()
    );

    let toml_path = harness_dir.join("Cargo.toml");
    if fs::read_to_string(&toml_path).unwrap_or_default() != cargo_toml {
        let _ = fs::write(&toml_path, &cargo_toml);
        // Copy workspace Cargo.lock if present so offline dependency resolution is instant
        let ws_lock = state.workspace_root.join("Cargo.lock");
        if ws_lock.exists() && !harness_dir.join("Cargo.lock").exists() {
            let _ = fs::copy(&ws_lock, harness_dir.join("Cargo.lock"));
        }
    }

    if let Err(e) = fs::write(src_dir.join("main.rs"), rust_source) {
        return json!({ "ok": false, "error": format!("failed to write test main.rs: {e}") });
    }

    let mut cmd = TokioCommand::new("cargo");
    cmd.arg("test")
        .arg("--manifest-path")
        .arg(&toml_path)
        .arg("--color=never")
        .arg("--")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    match timeout(Duration::from_secs(TEST_TIMEOUT_SECS), cmd.output()).await {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let mut tests = Vec::new();
            let mut passed = 0usize;
            let mut failed = 0usize;
            for line in stdout.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("test ") {
                    if let Some(name) = rest.strip_suffix(" ... ok") {
                        passed += 1;
                        tests.push(json!({ "name": name.trim(), "status": "ok" }));
                    } else if let Some(name) = rest.strip_suffix(" ... FAILED") {
                        failed += 1;
                        tests.push(json!({ "name": name.trim(), "status": "FAILED" }));
                    }
                }
            }
            json!({
                "ok": out.status.success(),
                "elapsedMs": started.elapsed().as_millis() as u64,
                "passed": passed,
                "failed": failed,
                "tests": tests,
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        Ok(Err(e)) => json!({
            "ok": false,
            "elapsedMs": started.elapsed().as_millis() as u64,
            "error": format!("failed to execute `cargo test`: {e}")
        }),
        Err(_) => json!({
            "ok": false,
            "elapsedMs": started.elapsed().as_millis() as u64,
            "error": format!("unit tests timed out after {TEST_TIMEOUT_SECS}s")
        }),
    }
}

fn list_workspace_examples(workspace_root: &Path) -> Vec<Value> {
    let examples_dir = workspace_root.join("examples");
    let dist_dir = workspace_root.join("dist");
    let Ok(entries) = fs::read_dir(&examples_dir) else {
        return Vec::new();
    };
    let mut items = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let main_rs = dir.join("src/main.rs");
        if !main_rs.exists() {
            continue;
        }
        let Some(name) = dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let stem = name.replace('-', "_");
        let wasm_path = dist_dir.join(format!("{stem}.wasm"));
        let wasm_bytes = fs::metadata(&wasm_path).map(|m| m.len()).unwrap_or(0);
        let desc = fs::read_to_string(dir.join("Cargo.toml"))
            .ok()
            .and_then(|toml| {
                toml.lines().find_map(|l| {
                    let t = l.trim();
                    t.strip_prefix("description =")
                        .map(|r| r.trim().trim_matches('"').to_string())
                })
            })
            .unwrap_or_default();
        items.push(json!({
            "name": name,
            "wasmBytes": wasm_bytes,
            "description": desc,
        }));
    }
    items.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });
    items
}

fn load_workspace_example(workspace_root: &Path, pkg_name: &str) -> Result<Value> {
    let safe_name: String = pkg_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_name.is_empty() {
        bail!("invalid example package name");
    }
    let dir = workspace_root.join("examples").join(&safe_name);
    let main_rs = dir.join("src/main.rs");
    if !main_rs.exists() {
        bail!("example '{safe_name}' not found");
    }
    let rust_source = fs::read_to_string(&main_rs)?;
    let abi = extract_hps_abi(&rust_source);

    let stem = safe_name.replace('-', "_");
    let wasm_path = workspace_root.join("dist").join(format!("{stem}.wasm"));
    let (wasm_base64, code_hash, wasm_size) = if let Ok(bytes) = fs::read(&wasm_path) {
        let h = format!("0x{}", hex::encode(keccak256(&bytes)));
        (Some(base64_encode(&bytes)), Some(h), bytes.len())
    } else {
        (None, None, 0)
    };

    Ok(json!({
        "ok": true,
        "name": safe_name,
        "rustSource": rust_source,
        "wasmBase64": wasm_base64,
        "codeHash": code_hash,
        "wasmSize": wasm_size,
        "abi": abi,
    }))
}

fn compose_inlined_app_html(
    index_html: &str,
    styles_css: &str,
    auto_bridge_js: &str,
    app_js: &str,
) -> String {
    let safe_css = styles_css.replace("</style", "<\\/style");
    let safe_bridge = auto_bridge_js.replace("</script", "<\\/script");
    let safe_js = app_js.replace("</script", "<\\/script");

    let mut html = index_html.to_string();

    // Replace `./styles.css` or `styles.css` link tag if present, else inject into `<head>`
    let style_block = format!("<style>\n{safe_css}\n</style>");
    let mut replaced_css = false;
    for pat in [
        r#"<link rel="stylesheet" href="./styles.css" />"#,
        r#"<link rel="stylesheet" href="./styles.css">"#,
        r#"<link rel="stylesheet" href="styles.css" />"#,
        r#"<link rel="stylesheet" href="styles.css">"#,
    ] {
        if html.contains(pat) {
            html = html.replacen(pat, &style_block, 1);
            replaced_css = true;
            break;
        }
    }
    if !replaced_css && !styles_css.trim().is_empty() {
        if let Some(idx) = html.find("</head>") {
            html.insert_str(idx, &format!("{style_block}\n"));
        } else {
            html = format!("{style_block}\n{html}");
        }
    }

    let combined_scripts = if safe_bridge.trim().is_empty() {
        format!("<script type=\"module\">\n{safe_js}\n</script>")
    } else {
        format!(
            "<script>\n{safe_bridge}\n</script>\n<script type=\"module\">\n{safe_js}\n</script>"
        )
    };

    let mut replaced_js = false;
    for pat in [
        r#"<script type="module" src="./app.js"></script>"#,
        r#"<script src="./app.js"></script>"#,
        r#"<script type="module" src="app.js"></script>"#,
        r#"<script src="app.js"></script>"#,
    ] {
        if html.contains(pat) {
            html = html.replacen(pat, &combined_scripts, 1);
            replaced_js = true;
            break;
        }
    }
    if !replaced_js {
        if let Some(idx) = html.rfind("</body>") {
            html.insert_str(idx, &format!("{combined_scripts}\n"));
        } else {
            html.push_str(&format!("\n{combined_scripts}"));
        }
    }

    html
}

fn handle_bundle_request(req: BundleRequest) -> Result<Value> {
    let _slug = sanitize_slug(&req.slug);
    let inlined = compose_inlined_app_html(
        &req.index_html,
        &req.styles_css,
        &req.auto_bridge_js,
        &req.app_js,
    );
    let gz_bytes = deterministic_gzip(inlined.as_bytes())?;
    let ui_hash = format!("0x{}", hex::encode(keccak256(&gz_bytes)));
    let chunks = gz_bytes.len().div_ceil(APP_STORE_CHUNK_BYTES).max(1);

    Ok(json!({
        "ok": true,
        "slug": sanitize_slug(&req.slug),
        "title": req.title,
        "version": req.version,
        "category": req.category,
        "icon": req.icon,
        "summary": req.summary,
        "uiHash": ui_hash,
        "uncompressedBytes": inlined.len(),
        "compressedBytes": gz_bytes.len(),
        "chunkCount": chunks,
        "gzBase64": base64_encode(&gz_bytes),
        "inlinedHtml": inlined,
        "allowExternalUrls": req.allow_external_urls,
    }))
}

fn handle_save_local_project(state: &StudioState, req: SaveLocalRequest) -> Result<Value> {
    if state.sandbox {
        bail!("saving directly to server disk is disabled in `--sandbox` mode (use Download Bundle instead)");
    }
    let slug = sanitize_slug(&req.slug);
    let bin_name = slug.replace('-', "_");
    let proj_dir = state.workspace_root.join("studio-projects").join(&slug);
    fs::create_dir_all(proj_dir.join("src"))?;
    fs::create_dir_all(proj_dir.join("ui"))?;
    fs::create_dir_all(proj_dir.join(".cargo"))?;
    fs::create_dir_all(proj_dir.join("dist"))?;

    let cargo_toml = format!(
        r#"[workspace]

[package]
name = "{slug}"
version = "{}"
edition = "2021"

[[bin]]
name = "{bin_name}"
path = "src/main.rs"

[dependencies]
hps-sdk = {{ path = "{}" }}

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#,
        req.version,
        state.sdk_src_dir.display()
    );
    let cargo_cfg = r#"[target.wasm32-unknown-unknown]
rustflags = [
  "-C", "link-arg=--initial-memory=2097152",
  "-C", "link-arg=--max-memory=4194304",
]
"#;
    let app_json = json!({
        "slug": slug,
        "title": req.title,
        "version": req.version,
        "category": req.category,
        "icon": req.icon,
        "summary": req.summary,
        "ui_entry": "ui/index.html",
    });

    fs::write(proj_dir.join("Cargo.toml"), cargo_toml)?;
    fs::write(proj_dir.join(".cargo/config.toml"), cargo_cfg)?;
    fs::write(
        proj_dir.join("app.json"),
        serde_json::to_string_pretty(&app_json)? + "\n",
    )?;
    fs::write(proj_dir.join("src/main.rs"), &req.rust_source)?;
    fs::write(proj_dir.join("ui/index.html"), &req.index_html)?;
    fs::write(proj_dir.join("ui/styles.css"), &req.styles_css)?;
    let combined_js = if req.auto_bridge_js.trim().is_empty() {
        req.app_js.clone()
    } else {
        format!("{}\n\n{}", req.auto_bridge_js, req.app_js)
    };
    fs::write(proj_dir.join("ui/app.js"), combined_js)?;

    let mut wasm_artifact = None;
    let mut wasm_hash = None;
    let mut wasm_len = None;
    if let Some(ref b64) = req.wasm_base64 {
        if !b64.trim().is_empty() {
            let bytes = base64_decode(b64)?;
            let out_wasm = proj_dir.join("dist").join(format!("{bin_name}.wasm"));
            let h = format!("0x{}", hex::encode(keccak256(&bytes)));
            wasm_len = Some(bytes.len());
            wasm_hash = Some(h);
            fs::write(&out_wasm, &bytes)?;
            wasm_artifact = Some(out_wasm);
        }
    }

    let bundle_out = create_app_bundle(&BundleOptions {
        ui_entry: proj_dir.join("ui/index.html"),
        out_dir: proj_dir.join("dist"),
        slug: slug.clone(),
        title: if req.title.trim().is_empty() {
            slug.clone()
        } else {
            req.title
        },
        version: req.version,
        category: req.category.clamp(1, 6),
        icon: req.icon,
        summary: req.summary,
        wasm_artifact,
        wasm_code_hash: wasm_hash,
        wasm_bytes_len: wasm_len,
        allow_external_urls: true,
    })?;

    Ok(json!({
        "ok": true,
        "projectDir": proj_dir.display().to_string(),
        "bundle": bundle_out,
    }))
}

fn load_standalone_ide_html(state: &StudioState) -> String {
    let bundle_candidate = state
        .ui_bundle_path
        .clone()
        .or_else(|| resolve_default_ui_bundle(&state.workspace_root));
    if let Some(path) = bundle_candidate {
        if let Ok(bytes) = fs::read(&path) {
            if bytes.starts_with(&[0x1f, 0x8b]) {
                if let Ok(html) = gunzip_utf8(&bytes) {
                    return html;
                }
            } else if let Ok(html) = String::from_utf8(bytes) {
                return html;
            }
        }
    }
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>cargo hps studio</title></head>
<body style="background:#050a14;color:#e2e8f0;font-family:monospace;padding:32px;">
  <h2>🛠️ cargo hps studio daemon is running</h2>
  <p>Compiler: <code>{}</code> | Mode: <code>{}</code></p>
  <p>Open <code>/hfs-ide.html</code> in your SuperLexicon Web Client — it will auto-connect to this compiler daemon!</p>
</body>
</html>"#,
        state.rustc_version,
        if state.sandbox { "sandbox" } else { "local" }
    )
}

pub async fn run_studio_server(opts: StudioOptions) -> Result<()> {
    let sdk_src_dir = opts.workspace_root.join("crates/hps-sdk");
    let cache_dir = opts.workspace_root.join("target/hps-studio-cache");
    let (wasm_sdk_rlib, rustc_version) = ensure_prebuilt_wasm_sdk(&sdk_src_dir, &cache_dir)?;

    let state = Arc::new(StudioState {
        sandbox: opts.sandbox,
        workspace_root: opts.workspace_root.clone(),
        sdk_src_dir,
        wasm_sdk_rlib,
        cache_dir,
        ui_bundle_path: opts.ui_bundle_path,
        rustc_version: rustc_version.clone(),
        compile_sem: Semaphore::new(4),
        test_lock: Mutex::new(()),
    });

    let listener = TcpListener::bind(&opts.bind)
        .await
        .with_context(|| format!("failed to bind HFS Studio server on {}", opts.bind))?;
    let local_addr = listener.local_addr()?;

    println!("==================================================================");
    println!("  🛠️  SuperLexicon HFS Studio Daemon (`cargo hps studio`)");
    println!("  Listening   : http://{local_addr}");
    println!(
        "  Mode        : {}",
        if opts.sandbox {
            "SANDBOX (stateless single-file #![no_std] rustc)"
        } else {
            "LOCAL DEV (rustc + native `cargo test` + project save)"
        }
    );
    println!("  Toolchain   : {rustc_version}");
    println!("  Workspace   : {}", opts.workspace_root.display());
    println!("==================================================================");

    loop {
        let (stream, _) = listener.accept().await?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_http_conn(stream, st).await;
        });
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<Option<(String, String, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let header_end: usize;

    loop {
        let n = timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            bail!("unexpected EOF before HTTP headers completed");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 32 * 1024 {
            bail!("HTTP request headers too large");
        }
    }

    let head_str = std::str::from_utf8(&buf[..header_end - 4])?;
    let mut lines = head_str.lines();
    let req_line = lines.next().ok_or_else(|| anyhow!("empty HTTP request"))?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let raw_target = parts.next().unwrap_or("/").to_string();

    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    if content_len > MAX_HTTP_BODY_BYTES {
        bail!("HTTP body exceeds {MAX_HTTP_BODY_BYTES} byte limit");
    }

    let mut body = Vec::with_capacity(content_len);
    body.extend_from_slice(&buf[header_end..]);
    while body.len() < content_len {
        let n = timeout(Duration::from_secs(15), stream.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);

    Ok(Some((method, raw_target, body)))
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Access-Control-Allow-Private-Network: true\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_json(stream: &mut TcpStream, status: u16, payload: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(payload)?;
    let text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    write_http_response(
        stream,
        status,
        text,
        "application/json; charset=utf-8",
        &bytes,
    )
    .await
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(url_decode(v));
            }
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

async fn handle_http_conn(mut stream: TcpStream, state: Arc<StudioState>) -> Result<()> {
    let Some((method, target, body)) = read_http_request(&mut stream).await? else {
        return Ok(());
    };

    if method == "OPTIONS" {
        return write_http_response(&mut stream, 204, "No Content", "text/plain", b"").await;
    }

    let (raw_path, query) = target.split_once('?').unwrap_or((&target, ""));
    // Support optional `/hps-studio-api` prefix when reverse-proxied behind Nginx
    let path = raw_path
        .strip_prefix("/hps-studio-api")
        .unwrap_or(raw_path);
    let path = if path.is_empty() { "/" } else { path };

    match (method.as_str(), path) {
        ("GET", "/") | ("GET", "/index.html") | ("GET", "/hfs-ide.html") => {
            let html = load_standalone_ide_html(&state);
            write_http_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
            )
            .await
        }
        ("GET", "/api/health") => {
            let examples = list_workspace_examples(&state.workspace_root);
            write_json(
                &mut stream,
                200,
                &json!({
                    "ok": true,
                    "service": "cargo-hps-studio",
                    "version": env!("CARGO_PKG_VERSION"),
                    "sandbox": state.sandbox,
                    "rustcVersion": state.rustc_version,
                    "exampleCount": examples.len(),
                }),
            )
            .await
        }
        ("GET", "/api/examples") => {
            let examples = list_workspace_examples(&state.workspace_root);
            write_json(&mut stream, 200, &json!({ "ok": true, "examples": examples })).await
        }
        ("GET", "/api/example") => {
            let Some(name) = parse_query_param(query, "name") else {
                return write_json(
                    &mut stream,
                    400,
                    &json!({ "ok": false, "error": "missing `?name=<example>` parameter" }),
                )
                .await;
            };
            match load_workspace_example(&state.workspace_root, &name) {
                Ok(payload) => write_json(&mut stream, 200, &payload).await,
                Err(e) => {
                    write_json(&mut stream, 404, &json!({ "ok": false, "error": e.to_string() }))
                        .await
                }
            }
        }
        ("POST", "/api/abi") => {
            let src = String::from_utf8_lossy(&body);
            let abi = extract_hps_abi(&src);
            write_json(&mut stream, 200, &json!({ "ok": true, "abi": abi })).await
        }
        ("POST", "/api/compile") => {
            let req: CompileRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return write_json(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("invalid JSON request: {e}") }),
                    )
                    .await;
                }
            };
            let label = if req.name.trim().is_empty() {
                "hfs_studio_contract"
            } else {
                req.name.trim()
            };
            let res =
                compile_rust_hfs_source(&state, label, &req.rust_source, req.strip_custom_sections)
                    .await;
            let payload = serde_json::to_value(&res)?;
            write_json(&mut stream, 200, &payload).await
        }
        ("POST", "/api/test") => {
            let req: CompileRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return write_json(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("invalid JSON request: {e}") }),
                    )
                    .await;
                }
            };
            let res = run_local_unit_tests(&state, &req.rust_source).await;
            write_json(&mut stream, 200, &res).await
        }
        ("POST", "/api/bundle") => {
            let req: BundleRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return write_json(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("invalid JSON request: {e}") }),
                    )
                    .await;
                }
            };
            match handle_bundle_request(req) {
                Ok(res) => write_json(&mut stream, 200, &res).await,
                Err(e) => {
                    write_json(&mut stream, 400, &json!({ "ok": false, "error": e.to_string() }))
                        .await
                }
            }
        }
        ("POST", "/api/save-local") => {
            let req: SaveLocalRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return write_json(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("invalid JSON request: {e}") }),
                    )
                    .await;
                }
            };
            match handle_save_local_project(&state, req) {
                Ok(res) => write_json(&mut stream, 200, &res).await,
                Err(e) => {
                    let code = if state.sandbox { 403 } else { 400 };
                    write_json(&mut stream, code, &json!({ "ok": false, "error": e.to_string() }))
                        .await
                }
            }
        }
        _ => {
            write_json(
                &mut stream,
                404,
                &json!({ "ok": false, "error": format!("unknown studio route: {method} {path}") }),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hps_abi_functions_param_names_and_events() {
        let src = r#"
            const UPDATED: [u8; 32] = event_topic("ScoreUpdated(address,uint64)");

            hps_entry! {
                "submitScore(bytes32,uint64)" => handle_submit,
                "getScore(bytes32)"           => handle_get,
            }

            fn handle_submit(args: &CalldataReader) -> Result<(), i32> {
                let arena_key = args.bytes32(0).ok_or(-3)?;
                let points = args.u64(1).ok_or(-3)?;
                storage::set_u64(&arena_key, points);
                events::emit(&[UPDATED], &[]);
                ret::write_u64_word(points);
                Ok(())
            }

            fn handle_get(args: &CalldataReader) -> Result<(), i32> {
                let arena_key = args.bytes32(0).ok_or(-3)?;
                ret::write_u64_word(storage::get_u64(&arena_key));
                Ok(())
            }
        "#;

        let abi = extract_hps_abi(src);
        assert_eq!(abi.functions.len(), 2);
        assert_eq!(abi.functions[0].name, "submitScore");
        assert_eq!(abi.functions[0].mutability, "nonpayable");
        assert_eq!(abi.functions[0].inputs[0].name, "arena_key");
        assert_eq!(abi.functions[0].inputs[1].name, "points");

        assert_eq!(abi.functions[1].name, "getScore");
        assert_eq!(abi.functions[1].mutability, "view");
        assert_eq!(abi.functions[1].return_hint, "uint64");
        assert_eq!(abi.functions[1].inputs[0].name, "arena_key");

        assert_eq!(abi.events.len(), 1);
        assert_eq!(abi.events[0].name, "ScoreUpdated");
        assert_eq!(abi.events[0].constant_name, "UPDATED");
    }

    #[test]
    fn sandbox_guard_blocks_host_file_macros() {
        assert!(validate_sandbox_rust_source("fn ok() {}").is_ok());
        assert!(validate_sandbox_rust_source(r#"let s = include_str!("/etc/passwd");"#).is_err());
        assert!(validate_sandbox_rust_source(r#"let b = include_bytes!("foo");"#).is_err());
        assert!(validate_sandbox_rust_source(r#"#[path = "/tmp/x.rs"] mod x;"#).is_err());
    }

    #[tokio::test]
    async fn compiles_rust_source_to_valid_lexicon_wasm() {
        let ws = resolve_default_workspace_root();
        let sdk_dir = ws.join("crates/hps-sdk");
        let cache_dir = ws.join("target/hps-studio-cache-test");
        let (rlib, ver) = ensure_prebuilt_wasm_sdk(&sdk_dir, &cache_dir).unwrap();
        let state = StudioState {
            sandbox: true,
            workspace_root: ws,
            sdk_src_dir: sdk_dir,
            wasm_sdk_rlib: rlib,
            cache_dir,
            ui_bundle_path: None,
            rustc_version: ver,
            compile_sem: Semaphore::new(2),
            test_lock: Mutex::new(()),
        };

        let sample = r#"#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]
use hps_sdk::abi::CalldataReader;
use hps_sdk::{hps_entry, ret, storage};

hps_entry! {
    "ping(uint64)" => handle_ping,
}

fn handle_ping(r: &CalldataReader) -> Result<(), i32> {
    let v = r.u64(0).ok_or(-3)?;
    storage::set_u64(b"k", v);
    ret::write_u64_word(v + 1);
    Ok(())
}
"#;
        let res = compile_rust_hfs_source(&state, "ping-test", sample, true).await;
        assert!(res.ok, "expected compile ok, got error: {:?}", res.error);
        assert!(res.optimized_size > 100 && res.optimized_size < 10_000);
        assert!(res.exports.contains(&"main".to_string()));
        assert!(res.exports.contains(&"memory".to_string()));
    }
}
