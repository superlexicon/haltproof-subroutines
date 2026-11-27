use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};
use hps_client::abi::keccak256;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Matches `app_store.wasm` (`MAX_CHUNK_BYTES = 32_768`, `MAX_CHUNKS_PER_BUNDLE = 8`).
pub const APP_STORE_CHUNK_BYTES: usize = 32_768;
pub const APP_STORE_MAX_CHUNKS: usize = 8;
pub const APP_STORE_MAX_BUNDLE_BYTES: usize = APP_STORE_CHUNK_BYTES * APP_STORE_MAX_CHUNKS; // 262,144 B

pub const MAX_TITLE_LEN: usize = 64;
pub const MAX_SUMMARY_LEN: usize = 240;
pub const MAX_ICON_LEN: usize = 16;
pub const MAX_VER_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfigFile {
    pub slug: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    pub category: Option<u16>,
    pub icon: Option<String>,
    pub summary: Option<String>,
    pub ui_entry: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BundleOptions {
    pub ui_entry: PathBuf,
    pub out_dir: PathBuf,
    pub slug: String,
    pub title: String,
    pub version: String,
    pub category: u16,
    pub icon: String,
    pub summary: String,
    pub wasm_artifact: Option<PathBuf>,
    pub wasm_code_hash: Option<String>,
    pub wasm_bytes_len: Option<usize>,
    pub allow_external_urls: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleOutput {
    pub slug: String,
    pub slug_id: String,
    pub title: String,
    pub version: String,
    pub category: u16,
    pub icon: String,
    pub summary: String,
    pub ui_archive: String,
    pub unpacked_html: String,
    pub ui_hash: String,
    pub uncompressed_bytes: usize,
    pub compressed_bytes: usize,
    pub chunk_count: usize,
    pub rf_offline_ready: bool,
    pub external_urls: Vec<String>,
    pub wasm_artifact: Option<String>,
    pub wasm_code_hash: String,
    pub wasm_bytes: usize,
}

pub fn sanitize_slug(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.trim().chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || lower == '_' || lower == '-' {
            out.push(lower);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "my-hfs-app".to_string()
    } else {
        out
    }
}

/// Deterministic RFC 1952 GZIP (`mtime = 0`, `OS = 255`, `Compression::best()` / level 9).
/// Produces bit-for-bit reproducible `.html.gz` archives across platforms so any auditor
/// can reproduce the exact on-chain `uiHash = keccak256(gz_bytes)` from Git source.
pub fn deterministic_gzip(raw_utf8: &[u8]) -> Result<Vec<u8>> {
    let mut encoder: GzEncoder<Vec<u8>> = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::with_capacity(raw_utf8.len() / 2 + 64), Compression::best());
    encoder
        .write_all(raw_utf8)
        .context("failed to write bytes to gzip encoder")?;
    encoder.finish().context("failed to finalize gzip archive")
}

/// Verify roundtrip decompression of a `.gz` payload.
pub fn gunzip_utf8(gz_bytes: &[u8]) -> Result<String> {
    let mut decoder = flate2::read::GzDecoder::new(gz_bytes);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .context("failed to gunzip UTF-8 HTML bundle")?;
    Ok(out)
}

fn extract_attr<'a>(tag: &'a str, attr_name: &str) -> Option<(usize, usize, &'a str)> {
    let lower = tag.to_ascii_lowercase();
    let needle_dq = format!("{attr_name}=\"");
    let needle_sq = format!("{attr_name}='");

    if let Some(pos) = lower.find(&needle_dq) {
        let val_start = pos + needle_dq.len();
        if let Some(end_rel) = tag[val_start..].find('"') {
            return Some((pos, val_start + end_rel + 1, &tag[val_start..val_start + end_rel]));
        }
    }
    if let Some(pos) = lower.find(&needle_sq) {
        let val_start = pos + needle_sq.len();
        if let Some(end_rel) = tag[val_start..].find('\'') {
            return Some((pos, val_start + end_rel + 1, &tag[val_start..val_start + end_rel]));
        }
    }
    None
}

fn is_remote_or_data_ref(href: &str) -> bool {
    let h = href.trim().to_ascii_lowercase();
    h.starts_with("http://")
        || h.starts_with("https://")
        || h.starts_with("//")
        || h.starts_with("data:")
        || h.starts_with("blob:")
        || h.starts_with("mailto:")
        || h.starts_with('#')
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

fn mime_for_asset(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("svg") => Some("image/svg+xml"),
        Some("png") => Some("image/png"),
        Some("jpg") | Some("jpeg") => Some("image/jpeg"),
        Some("webp") => Some("image/webp"),
        Some("gif") => Some("image/gif"),
        Some("ico") => Some("image/x-icon"),
        Some("woff2") => Some("font/woff2"),
        _ => None,
    }
}

/// Inlines local `<link rel="stylesheet" href="...">`, `<script src="..."></script>`,
/// and `<img src="...">` files into a single self-contained HTML document.
pub fn inline_html_assets(entry_html_path: &Path) -> Result<String> {
    let base_dir = entry_html_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut html = fs::read_to_string(entry_html_path).with_context(|| {
        format!(
            "failed to read UI entry HTML '{}'",
            entry_html_path.display()
        )
    })?;

    // 1. Inline local `<link ... rel="stylesheet" ... href="...">`
    let mut out = String::with_capacity(html.len() + 4096);
    let mut cursor = 0;
    while let Some(rel_start) = html[cursor..].find("<link") {
        let tag_start = cursor + rel_start;
        out.push_str(&html[cursor..tag_start]);
        let Some(rel_end) = html[tag_start..].find('>') else {
            out.push_str(&html[tag_start..]);
            cursor = html.len();
            break;
        };
        let tag_end = tag_start + rel_end + 1;
        let tag = &html[tag_start..tag_end];
        let is_stylesheet = extract_attr(tag, "rel")
            .map(|(_, _, v)| v.eq_ignore_ascii_case("stylesheet"))
            .unwrap_or(false);
        if is_stylesheet {
            if let Some((_, _, href)) = extract_attr(tag, "href") {
                if !is_remote_or_data_ref(href) {
                    let clean_rel = href.split('?').next().unwrap_or(href).trim_start_matches('/');
                    let css_path = if href.starts_with('/') {
                        base_dir.join(clean_rel)
                    } else {
                        base_dir.join(href.split('?').next().unwrap_or(href))
                    };
                    let css = fs::read_to_string(&css_path).with_context(|| {
                        format!(
                            "failed to inline stylesheet '{}' referenced from '{}'",
                            css_path.display(),
                            entry_html_path.display()
                        )
                    })?;
                    let safe_css = css.replace("</style", "<\\/style");
                    out.push_str("<style>\n");
                    out.push_str(&safe_css);
                    if !safe_css.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str("</style>");
                    cursor = tag_end;
                    continue;
                }
            }
        }
        out.push_str(tag);
        cursor = tag_end;
    }
    out.push_str(&html[cursor..]);
    html = out;

    // 2. Inline local `<script ... src="..."></script>`
    let mut out_js = String::with_capacity(html.len() + 8192);
    cursor = 0;
    while let Some(rel_start) = html[cursor..].find("<script") {
        let tag_start = cursor + rel_start;
        out_js.push_str(&html[cursor..tag_start]);
        let Some(open_end_rel) = html[tag_start..].find('>') else {
            out_js.push_str(&html[tag_start..]);
            cursor = html.len();
            break;
        };
        let open_end = tag_start + open_end_rel + 1;
        let open_tag = &html[tag_start..open_end];

        if let Some((attr_s, attr_e, src_val)) = extract_attr(open_tag, "src") {
            if !is_remote_or_data_ref(src_val) {
                // Consume matching `</script>`
                let close_needle = "</script>";
                let Some(close_rel) = html[open_end..].to_ascii_lowercase().find(close_needle)
                else {
                    bail!(
                        "unclosed <script src=\"{src_val}\"> tag in '{}'",
                        entry_html_path.display()
                    );
                };
                let after_close = open_end + close_rel + close_needle.len();

                let clean_src = src_val.split('?').next().unwrap_or(src_val);
                let js_path = if clean_src.starts_with('/') {
                    base_dir.join(clean_src.trim_start_matches('/'))
                } else {
                    base_dir.join(clean_src)
                };
                let js_code = fs::read_to_string(&js_path).with_context(|| {
                    format!(
                        "failed to inline script '{}' referenced from '{}'",
                        js_path.display(),
                        entry_html_path.display()
                    )
                })?;

                // Rebuild `<script ...>` without `src="..."` and without self-closing `/`
                let mut rebuilt_open = String::new();
                rebuilt_open.push_str(&open_tag[..attr_s]);
                rebuilt_open.push_str(&open_tag[attr_e..]);
                if rebuilt_open.ends_with("/>") {
                    let trimmed_len = rebuilt_open.len() - 2;
                    rebuilt_open.truncate(trimmed_len);
                    rebuilt_open.push('>');
                }

                // Prevent accidental `</script` termination inside string literals
                let safe_js = js_code.replace("</script", "<\\/script");
                out_js.push_str(&rebuilt_open);
                out_js.push('\n');
                out_js.push_str(&safe_js);
                if !safe_js.ends_with('\n') {
                    out_js.push('\n');
                }
                out_js.push_str("</script>");
                cursor = after_close;
                continue;
            }
        }

        out_js.push_str(open_tag);
        cursor = open_end;
    }
    out_js.push_str(&html[cursor..]);
    html = out_js;

    // 3. Inline local `<img ... src="...">` as `data:` URIs when supported
    let mut out_img = String::with_capacity(html.len());
    cursor = 0;
    while let Some(rel_start) = html[cursor..].find("<img") {
        let tag_start = cursor + rel_start;
        out_img.push_str(&html[cursor..tag_start]);
        let Some(rel_end) = html[tag_start..].find('>') else {
            out_img.push_str(&html[tag_start..]);
            cursor = html.len();
            break;
        };
        let tag_end = tag_start + rel_end + 1;
        let tag = &html[tag_start..tag_end];
        if let Some((attr_s, attr_e, src_val)) = extract_attr(tag, "src") {
            if !is_remote_or_data_ref(src_val) {
                let clean_src = src_val.split('?').next().unwrap_or(src_val);
                let img_path = if clean_src.starts_with('/') {
                    base_dir.join(clean_src.trim_start_matches('/'))
                } else {
                    base_dir.join(clean_src)
                };
                if let Some(mime) = mime_for_asset(&img_path) {
                    if let Ok(bytes) = fs::read(&img_path) {
                        let data_uri = format!("src=\"data:{mime};base64,{}\"", base64_encode(&bytes));
                        out_img.push_str(&tag[..attr_s]);
                        out_img.push_str(&data_uri);
                        out_img.push_str(&tag[attr_e..]);
                        cursor = tag_end;
                        continue;
                    }
                }
            }
        }
        out_img.push_str(tag);
        cursor = tag_end;
    }
    out_img.push_str(&html[cursor..]);

    Ok(out_img)
}

/// Scans bundled HTML for external runtime dependencies (`<script src="https://...">`,
/// `<link rel="stylesheet" href="https://...">`, `<img src="https://...">`, CSS `@import`)
/// that would fail when running offline over `LR2021` Sub-GHz RF without internet access.
pub fn audit_external_runtime_urls(html: &str) -> Vec<String> {
    let mut found = Vec::new();
    let lower = html.to_ascii_lowercase();

    for tag_prefix in ["<script", "<link", "<img", "<iframe"] {
        let mut cursor = 0;
        while let Some(rel) = lower[cursor..].find(tag_prefix) {
            let start = cursor + rel;
            let Some(end_rel) = lower[start..].find('>') else {
                break;
            };
            let tag = &html[start..start + end_rel + 1];
            let attr = if tag_prefix == "<link" { "href" } else { "src" };
            if let Some((_, _, val)) = extract_attr(tag, attr) {
                let v = val.trim();
                let vl = v.to_ascii_lowercase();
                // Ignore `<link rel="icon">` or `<link rel="preconnect">`? Still external on RF if stylesheet/font!
                let is_non_blocking_preconnect = tag_prefix == "<link"
                    && extract_attr(tag, "rel")
                        .map(|(_, _, r)| r.eq_ignore_ascii_case("preconnect") || r.eq_ignore_ascii_case("dns-prefetch"))
                        .unwrap_or(false);
                if !is_non_blocking_preconnect
                    && (vl.starts_with("http://") || vl.starts_with("https://") || vl.starts_with("//"))
                    && !found.contains(&v.to_string())
                {
                    found.push(v.to_string());
                }
            }
            cursor = start + end_rel + 1;
        }
    }

    // Also check CSS `@import url("https://...")` or `@import "https://..."`
    let mut idx = 0;
    while let Some(rel) = lower[idx..].find("@import") {
        let start = idx + rel;
        let line_end = lower[start..]
            .find(';')
            .map(|e| start + e)
            .unwrap_or(html.len().min(start + 200));
        let snippet = &html[start..line_end];
        if snippet.contains("http://") || snippet.contains("https://") {
            let clean = snippet.trim().to_string();
            if !found.contains(&clean) {
                found.push(clean);
            }
        }
        idx = line_end;
    }

    found
}

pub fn create_app_bundle(opts: &BundleOptions) -> Result<BundleOutput> {
    let slug = sanitize_slug(&opts.slug);
    if opts.title.trim().is_empty() || opts.title.len() > MAX_TITLE_LEN {
        bail!("app title must be 1..={MAX_TITLE_LEN} bytes");
    }
    if opts.summary.len() > MAX_SUMMARY_LEN {
        bail!("app summary exceeds {MAX_SUMMARY_LEN} bytes");
    }
    if opts.version.trim().is_empty() || opts.version.len() > MAX_VER_LEN {
        bail!("app version must be 1..={MAX_VER_LEN} bytes");
    }
    if opts.icon.len() > MAX_ICON_LEN {
        bail!("app icon exceeds {MAX_ICON_LEN} UTF-8 bytes");
    }
    if !(1..=6).contains(&opts.category) {
        bail!("app category must be 1..=6 (1=Markets, 2=Governance/IFRS, 3=Commerce, 4=Social/Comms, 5=Games/VRF, 6=Utilities)");
    }

    let inlined_html = inline_html_assets(&opts.ui_entry)?;
    let external_urls = audit_external_runtime_urls(&inlined_html);
    if !external_urls.is_empty() && !opts.allow_external_urls {
        bail!(
            "UI bundle references {} external internet URL(s) that will fail offline over Sub-GHz RF:\n  - {}\nInline all CSS/JS/assets locally (or pass `--allow-external-urls` to override).",
            external_urls.len(),
            external_urls.join("\n  - ")
        );
    }

    let raw_bytes = inlined_html.as_bytes();
    let gz_bytes = deterministic_gzip(raw_bytes)?;
    if gz_bytes.len() > APP_STORE_MAX_BUNDLE_BYTES {
        bail!(
            "compressed `.html.gz` archive ({} bytes / {:.1} KiB) exceeds `app_store.wasm` maximum ({} bytes / 256 KiB)",
            gz_bytes.len(),
            gz_bytes.len() as f64 / 1024.0,
            APP_STORE_MAX_BUNDLE_BYTES
        );
    }

    // Roundtrip sanity verification
    let unpacked_check = gunzip_utf8(&gz_bytes)?;
    if unpacked_check != inlined_html {
        return Err(anyhow!("internal error: gzip roundtrip mismatch"));
    }

    let ui_hash = format!("0x{}", hex::encode(keccak256(&gz_bytes)));
    let slug_id = format!("0x{}", hex::encode(keccak256(slug.as_bytes())));
    let chunk_count = gz_bytes.len().div_ceil(APP_STORE_CHUNK_BYTES).max(1);

    fs::create_dir_all(&opts.out_dir)?;
    let out_gz_path = opts.out_dir.join(format!("{slug}.html.gz"));
    let out_html_path = opts.out_dir.join(format!("{slug}.bundle.html"));
    let out_manifest_path = opts.out_dir.join(format!("{slug}.manifest.json"));

    fs::write(&out_gz_path, &gz_bytes)?;
    fs::write(&out_html_path, &inlined_html)?;

    let wasm_code_hash = opts
        .wasm_code_hash
        .clone()
        .unwrap_or_else(|| format!("0x{}", "00".repeat(32)));
    let wasm_bytes = opts.wasm_bytes_len.unwrap_or(0);

    let output = BundleOutput {
        slug: slug.clone(),
        slug_id,
        title: opts.title.trim().to_string(),
        version: opts.version.trim().to_string(),
        category: opts.category,
        icon: opts.icon.trim().to_string(),
        summary: opts.summary.trim().to_string(),
        ui_archive: out_gz_path.display().to_string(),
        unpacked_html: out_html_path.display().to_string(),
        ui_hash,
        uncompressed_bytes: raw_bytes.len(),
        compressed_bytes: gz_bytes.len(),
        chunk_count,
        rf_offline_ready: external_urls.is_empty(),
        external_urls,
        wasm_artifact: opts.wasm_artifact.as_ref().map(|p| p.display().to_string()),
        wasm_code_hash,
        wasm_bytes,
    };

    fs::write(&out_manifest_path, serde_json::to_string_pretty(&output)?)?;
    Ok(output)
}

pub fn scaffold_ui_files(target_dir: &Path, name: &str) -> Result<()> {
    let slug = sanitize_slug(name);
    let title = name
        .split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let ui_dir = target_dir.join("ui");
    fs::create_dir_all(&ui_dir)?;

    let app_json = json!({
        "slug": slug,
        "title": if title.is_empty() { "My Zero-Server App".to_string() } else { title.clone() },
        "version": "1.0.0",
        "category": 6,
        "icon": "⚡",
        "summary": "Zero-server SuperLexicon application powered by a Halt-Free Subroutine (.wasm) and deterministic .html.gz UI bundle.",
        "ui_entry": "ui/index.html"
    });
    fs::write(
        target_dir.join("app.json"),
        serde_json::to_string_pretty(&app_json)? + "\n",
    )?;

    let styles_css = r#"* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  background: #050b16;
  color: #f8fafc;
  font-family: system-ui, -apple-system, sans-serif;
}
.card {
  max-width: 680px;
  margin: 0 auto;
  padding: 24px;
  border-radius: 18px;
  background: rgba(15, 23, 42, 0.92);
  border: 1px solid rgba(56, 189, 248, 0.35);
  box-shadow: 0 18px 40px rgba(0, 0, 0, 0.45);
}
.pill {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(16, 185, 129, 0.16);
  border: 1px solid rgba(52, 211, 153, 0.45);
  color: #6ee7b7;
  font-family: ui-monospace, monospace;
  font-size: 11px;
  font-weight: 700;
}
.row {
  display: flex;
  gap: 8px;
  margin-top: 14px;
}
input {
  flex: 1;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid #334155;
  background: #020617;
  color: #f8fafc;
  font-family: ui-monospace, monospace;
}
button {
  padding: 10px 16px;
  border-radius: 10px;
  border: none;
  background: #0ea5e9;
  color: #020617;
  font-weight: 800;
  cursor: pointer;
}
button:hover { background: #38bdf8; }
.meta {
  margin-top: 12px;
  font-family: ui-monospace, monospace;
  font-size: 12px;
  color: #94a3b8;
}
"#;

    let app_js = r#"const BUCKET_HEX = '0x' + '11'.repeat(32);

async function refreshCount() {
  try {
    const rawHex = await window.slx.callContract('getCount(bytes32)', [['bytes32', BUCKET_HEX]]);
    const count = rawHex && rawHex !== '0x' ? BigInt(rawHex).toString() : '0';
    document.getElementById('countValue').textContent = count;
  } catch (err) {
    document.getElementById('statusLine').textContent = 'Read note: ' + (err.message || err);
  }
}

async function boot() {
  const ctx = await window.slx.getContext();
  document.getElementById('identityLine').textContent =
    `Identity: ${ctx.user.nickname} · ${ctx.user.tag4} | Block #${ctx.blockNumber}`;
  await refreshCount();
}

document.getElementById('btnIncrement').addEventListener('click', async () => {
  const delta = Number(document.getElementById('inDelta').value || 1);
  if (!Number.isFinite(delta) || delta <= 0) return;
  document.getElementById('statusLine').textContent = 'Submitting $0.00-gas HFS transaction…';
  try {
    const receipt = await window.slx.sendTransaction({
      fnSig: 'increment(bytes32,uint64)',
      args: [
        ['bytes32', BUCKET_HEX],
        ['uint64', delta],
      ],
      summary: `Increment counter by +${delta}`,
    });
    document.getElementById('statusLine').textContent = `Confirmed in tx ${String(receipt.txHash).slice(0, 14)}…`;
    await refreshCount();
  } catch (err) {
    document.getElementById('statusLine').textContent = 'Tx cancelled or failed: ' + (err.message || err);
  }
});

boot();
"#;

    let index_html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{}</title>
  <link rel="stylesheet" href="./styles.css" />
</head>
<body>
  <div class="card">
    <span class="pill">0 Servers • 0 Databases • $0.00 Gas • 100% RF Offline</span>
    <h2 style="margin: 12px 0 4px;">⚡ {}</h2>
    <div id="identityLine" class="meta">Connecting to window.slx…</div>
    <div style="margin-top: 18px; font-size: 28px; font-weight: 900;">
      Counter: <span id="countValue" style="color: #38bdf8;">0</span>
    </div>
    <div class="row">
      <input id="inDelta" type="number" min="1" value="1" />
      <button id="btnIncrement" type="button">+ Increment ($0 Gas)</button>
    </div>
    <div id="statusLine" class="meta"></div>
  </div>
  <script type="module" src="./app.js"></script>
</body>
</html>
"#,
        if title.is_empty() { "Zero-Server HFS App" } else { &title },
        if title.is_empty() { "Zero-Server HFS App" } else { &title }
    );

    fs::write(ui_dir.join("styles.css"), styles_css)?;
    fs::write(ui_dir.join("app.js"), app_js)?;
    fs::write(ui_dir.join("index.html"), index_html)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inlines_local_css_and_js_and_produces_deterministic_gzip() {
        let tmp = std::env::temp_dir().join(format!("hps_bundle_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("ui")).unwrap();
        fs::create_dir_all(tmp.join("dist")).unwrap();

        fs::write(tmp.join("ui/styles.css"), "body { background: #000; }").unwrap();
        fs::write(
            tmp.join("ui/app.js"),
            "console.log('hello </script> world');",
        )
        .unwrap();
        fs::write(
            tmp.join("ui/index.html"),
            r#"<!DOCTYPE html><html><head><link rel="stylesheet" href="./styles.css"></head><body><script type="module" src="./app.js"></script></body></html>"#,
        )
        .unwrap();

        let opts = BundleOptions {
            ui_entry: tmp.join("ui/index.html"),
            out_dir: tmp.join("dist"),
            slug: "Demo App!".to_string(),
            title: "Demo App".to_string(),
            version: "1.0.0".to_string(),
            category: 6,
            icon: "⚡".to_string(),
            summary: "Test bundle".to_string(),
            wasm_artifact: None,
            wasm_code_hash: None,
            wasm_bytes_len: None,
            allow_external_urls: false,
        };

        let res1 = create_app_bundle(&opts).unwrap();
        let gz1 = fs::read(&res1.ui_archive).unwrap();
        assert_eq!(&gz1[0..2], &[0x1f, 0x8b]); // RFC 1952 gzip magic
        assert_eq!(&gz1[4..8], &[0, 0, 0, 0]); // mtime == 0!
        assert_eq!(gz1[9], 255); // OS == 255 deterministic!

        let res2 = create_app_bundle(&opts).unwrap();
        let gz2 = fs::read(&res2.ui_archive).unwrap();
        assert_eq!(gz1, gz2);
        assert_eq!(res1.ui_hash, res2.ui_hash);
        assert!(res1.rf_offline_ready);

        let unpacked = gunzip_utf8(&gz1).unwrap();
        assert!(unpacked.contains("<style>\nbody { background: #000; }\n</style>"));
        assert!(unpacked.contains("<\\/script>"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_external_cdn_scripts_by_default() {
        let html = r#"<html><head><script src="https://cdn.jsdelivr.net/npm/vue@3"></script></head><body></body></html>"#;
        let urls = audit_external_runtime_urls(html);
        assert_eq!(urls, vec!["https://cdn.jsdelivr.net/npm/vue@3".to_string()]);
    }
}
