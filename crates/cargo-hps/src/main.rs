mod wasm_opt;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hps_client::abi::{
    encode_call_from_strings, keccak256, try_decode_abi_bytes, try_decode_u256,
};
use hps_client::{
    parse_address, HpsClient, HpsSigner, DEFAULT_CHAIN_ID, DEFAULT_DEV_PRIVATE_KEY,
};
use serde_json::json;

const MAX_LEXICON_BYTECODE_BYTES: usize = 100_000;

#[derive(Parser)]
#[command(
    name = "cargo-hps",
    bin_name = "cargo hps",
    version,
    about = "Build, validate, deploy, and invoke Lexicon Wasmtime Haltproof Subroutines (HPS)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scaffold a new Lexicon WASM Haltproof Subroutine (HPS) project
    New {
        /// Project / crate name (e.g. my-counter)
        name: String,
        /// Target directory (defaults to ./<name>)
        #[arg(long)]
        path: Option<PathBuf>,
    },

    /// Compile an HPS crate to wasm32-unknown-unknown, strip zero-data segments, and validate ABI
    Build {
        /// Path to Cargo.toml (defaults to ./Cargo.toml)
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Specific package in a Cargo workspace
        #[arg(short, long)]
        package: Option<String>,
        /// Output directory for optimized .wasm and .meta.json artifacts
        #[arg(short, long, default_value = "dist")]
        out_dir: PathBuf,
        /// Keep custom WASM debug/name sections
        #[arg(long)]
        keep_custom_sections: bool,
    },

    /// Execute Lexicon's 2-step HPS deployment (store_bytecode + instantiate) in a single command
    Deploy {
        /// Path to the compiled .wasm artifact (e.g. dist/counter_registry.wasm)
        wasm_path: PathBuf,
        /// JSON-RPC endpoint URL
        #[arg(long, env = "LEXICON_RPC_URL", default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Secp256k1 private key hex (defaults to localtestnet dev key)
        #[arg(long, env = "LEXICON_PRIVATE_KEY", default_value = DEFAULT_DEV_PRIVATE_KEY)]
        private_key: String,
        /// Chain ID
        #[arg(long, env = "LEXICON_CHAIN_ID", default_value_t = DEFAULT_CHAIN_ID)]
        chain_id: u64,
        /// Optional hex-encoded initialization arguments
        #[arg(long, default_value = "")]
        init_args: String,
        /// Optional path to write deployment receipt JSON
        #[arg(long)]
        save: Option<PathBuf>,
    },

    /// Submit a stateful Haltproof Subroutine (HPS) invocation and wait for block confirmation
    Send {
        /// Deployed 20-byte HPS address (0x...)
        hps: String,
        /// Function signature, e.g. "increment(bytes32,uint64)"
        signature: String,
        /// Function arguments matching the signature types
        args: Vec<String>,
        /// Additional HPS addresses touched via cross-HPS calls (`--touch 0x...`)
        #[arg(long = "touch")]
        touch: Vec<String>,
        /// JSON-RPC endpoint URL
        #[arg(long, env = "LEXICON_RPC_URL", default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Secp256k1 private key hex (defaults to localtestnet dev key)
        #[arg(long, env = "LEXICON_PRIVATE_KEY", default_value = DEFAULT_DEV_PRIVATE_KEY)]
        private_key: String,
        /// Chain ID
        #[arg(long, env = "LEXICON_CHAIN_ID", default_value_t = DEFAULT_CHAIN_ID)]
        chain_id: u64,
    },

    /// Execute a read-only `eth_call` against committed Haltproof Subroutine (HPS) state
    Call {
        /// Deployed 20-byte HPS address (0x...)
        hps: String,
        /// Function signature, e.g. "getCount(bytes32)"
        signature: String,
        /// Function arguments matching the signature types
        args: Vec<String>,
        /// JSON-RPC endpoint URL
        #[arg(long, env = "LEXICON_RPC_URL", default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Generate a fresh secp256k1 developer account (or display the built-in localtestnet dev key)
    Keygen {
        /// Show the built-in default `--localtestnet` developer key instead of generating a new one
        #[arg(long)]
        dev: bool,
    },

    /// Check node health, current block height, and validator mode
    Status {
        /// JSON-RPC endpoint URL
        #[arg(long, env = "LEXICON_RPC_URL", default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Support both `cargo hps <cmd>` (where cargo passes "hps" as arg[1])
    // and direct `cargo-hps <cmd>` invocation.
    let mut raw_args: Vec<String> = env::args().collect();
    if raw_args.get(1).map(|s| s.as_str()) == Some("hps") {
        raw_args.remove(1);
    }
    let cli = Cli::parse_from(raw_args);

    match cli.command {
        Commands::New { name, path } => cmd_new(&name, path),
        Commands::Build {
            manifest_path,
            package,
            out_dir,
            keep_custom_sections,
        } => cmd_build(manifest_path, package, &out_dir, !keep_custom_sections),
        Commands::Deploy {
            wasm_path,
            rpc,
            private_key,
            chain_id,
            init_args,
            save,
        } => cmd_deploy(&wasm_path, &rpc, &private_key, chain_id, &init_args, save).await,
        Commands::Send {
            hps,
            signature,
            args,
            touch,
            rpc,
            private_key,
            chain_id,
        } => cmd_send(&hps, &signature, &args, &touch, &rpc, &private_key, chain_id).await,
        Commands::Call {
            hps,
            signature,
            args,
            rpc,
        } => cmd_call(&hps, &signature, &args, &rpc).await,
        Commands::Keygen { dev } => cmd_keygen(dev),
        Commands::Status { rpc } => cmd_status(&rpc).await,
    }
}

fn cmd_new(name: &str, path: Option<PathBuf>) -> Result<()> {
    let target_dir = path.unwrap_or_else(|| PathBuf::from(name));
    if target_dir.exists() {
        bail!("target directory '{}' already exists", target_dir.display());
    }
    let bin_name = name.replace('-', "_");
    let sdk_dep = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("crates/hps-sdk"))
        .filter(|p| p.exists())
        .map(|p| format!("{{ path = \"{}\" }}", p.display()))
        .unwrap_or_else(|| "{ git = \"https://github.com/superlexicon/haltproof-subroutines.git\" }".to_string());

    fs::create_dir_all(target_dir.join("src"))?;
    fs::create_dir_all(target_dir.join(".cargo"))?;

    let cargo_toml = format!(
        r#"[workspace]

[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "{bin_name}"
path = "src/main.rs"

[dependencies]
hps-sdk = {sdk_dep}

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
"#
    );

    let cargo_config = r#"[target.wasm32-unknown-unknown]
rustflags = [
  "-C", "link-arg=--initial-memory=2097152",
  "-C", "link-arg=--max-memory=4194304",
]
"#;

    let starter_src = r#"#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use hps_sdk::abi::CalldataReader;
use hps_sdk::storage::KeyBuilder;
use hps_sdk::{context, event_topic, events, hps_entry, ret, storage};

const COUNT_UPDATED: [u8; 32] = event_topic("CountUpdated(bytes32,address,uint64)");

hps_entry! {
    "increment(bytes32,uint64)" => handle_increment,
    "getCount(bytes32)"         => handle_get_count,
}

fn handle_increment(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let delta = args.u64(1).ok_or(-3)?;
    let sender = context::msg_sender();

    let key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    let next = storage::get_u64(key.as_slice()).saturating_add(delta);
    storage::set_u64(key.as_slice(), next);

    let mut log_data = [0u8; 28];
    log_data[0..20].copy_from_slice(&sender);
    log_data[20..28].copy_from_slice(&next.to_be_bytes());
    events::emit(&[COUNT_UPDATED, bucket], &log_data);

    ret::write_u64_word(next);
    Ok(())
}

fn handle_get_count(args: &CalldataReader) -> Result<(), i32> {
    let bucket = args.bytes32(0).ok_or(-3)?;
    let key = KeyBuilder::<64>::new().push(b"cnt:").push(&bucket);
    let current = storage::get_u64(key.as_slice());
    ret::write_u64_word(current);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hps_sdk::{mock, selector};

    #[test]
    fn increments_and_reads_back() {
        mock::reset();
        mock::set_sender([0xAA; 20]);
        mock::set_block_number(7);

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&selector("increment(bytes32,uint64)"));
        calldata.extend_from_slice(&[0x11; 32]);
        let mut delta_word = [0u8; 32];
        delta_word[24..32].copy_from_slice(&5u64.to_be_bytes());
        calldata.extend_from_slice(&delta_word);

        assert_eq!(dispatch_calldata(&calldata), 0);
        assert_eq!(mock::events().len(), 1);

        let mut get_cd = Vec::new();
        get_cd.extend_from_slice(&selector("getCount(bytes32)"));
        get_cd.extend_from_slice(&[0x11; 32]);
        assert_eq!(dispatch_calldata(&get_cd), 0);
        let out = mock::take_return_data();
        assert_eq!(&out[24..32], &5u64.to_be_bytes());
    }
}
"#;

    fs::write(target_dir.join("Cargo.toml"), cargo_toml)?;
    fs::write(target_dir.join(".cargo/config.toml"), cargo_config)?;
    fs::write(target_dir.join("src/main.rs"), starter_src)?;

    println!("Scaffolded new Haltproof Subroutine (HPS) at {}", target_dir.display());
    println!("Next steps:");
    println!("  cd {}", target_dir.display());
    println!("  cargo test                                  # fast native unit tests");
    println!("  cargo hps build                             # compile & strip WASM");
    println!("  cargo hps deploy dist/{bin_name}.wasm       # deploy to --localtestnet");
    Ok(())
}

fn cmd_build(
    manifest_path: Option<PathBuf>,
    package: Option<String>,
    out_dir: &Path,
    strip_custom_sections: bool,
) -> Result<()> {
    let manifest = manifest_path.unwrap_or_else(|| PathBuf::from("Cargo.toml"));
    if !manifest.exists() {
        bail!("Cargo manifest not found at '{}'", manifest.display());
    }

    let mut meta_cmd = Command::new("cargo");
    meta_cmd
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version=1")
        .arg("--manifest-path")
        .arg(&manifest);
    let meta_out = meta_cmd.output().context("failed to run `cargo metadata`")?;
    if !meta_out.status.success() {
        bail!(
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&meta_out.stderr)
        );
    }
    let meta: serde_json::Value = serde_json::from_slice(&meta_out.stdout)?;
    let target_root = PathBuf::from(
        meta["target_directory"]
            .as_str()
            .ok_or_else(|| anyhow!("missing target_directory in cargo metadata"))?,
    );

    let packages = meta["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("missing packages in cargo metadata"))?;
    let selected_pkg = if let Some(ref pkg_name) = package {
        packages
            .iter()
            .find(|p| p["name"].as_str() == Some(pkg_name.as_str()))
            .ok_or_else(|| anyhow!("package '{pkg_name}' not found in workspace"))?
    } else if packages.len() == 1 {
        &packages[0]
    } else {
        bail!(
            "workspace contains multiple packages; pass `-p <package>` (available: {})",
            packages
                .iter()
                .filter_map(|p| p["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };

    let bin_target = selected_pkg["targets"]
        .as_array()
        .and_then(|ts| {
            ts.iter().find(|t| {
                t["kind"]
                    .as_array()
                    .map(|k| k.iter().any(|v| v.as_str() == Some("bin") || v.as_str() == Some("cdylib")))
                    .unwrap_or(false)
            })
        })
        .ok_or_else(|| anyhow!("selected crate has no `[[bin]]` or `cdylib` target"))?;
    let artifact_stem = bin_target["name"]
        .as_str()
        .ok_or_else(|| anyhow!("missing target name"))?
        .replace('-', "_");

    println!(
        "Compiling HPS `{}` for wasm32-unknown-unknown (release, 2 MiB linear memory)...",
        selected_pkg["name"].as_str().unwrap_or(&artifact_stem)
    );

    let mut build_cmd = Command::new("cargo");
    build_cmd
        .arg("build")
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest);
    if let Some(ref pkg_name) = package {
        build_cmd.arg("-p").arg(pkg_name);
    }
    build_cmd.env(
        "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS",
        "-C link-arg=--initial-memory=2097152 -C link-arg=--max-memory=4194304",
    );

    let status = build_cmd
        .status()
        .context("failed to execute `cargo build --target wasm32-unknown-unknown`")?;
    if !status.success() {
        bail!(
            "WASM build failed (tip: ensure `rustup target add wasm32-unknown-unknown` is installed)"
        );
    }

    let raw_wasm_path = target_root
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(format!("{artifact_stem}.wasm"));
    let raw_bytes = fs::read(&raw_wasm_path)
        .with_context(|| format!("expected compiled WASM at '{}'", raw_wasm_path.display()))?;

    let (optimized_bytes, report) =
        wasm_opt::optimize_and_validate_wasm(&raw_bytes, strip_custom_sections)?;

    if optimized_bytes.len() > MAX_LEXICON_BYTECODE_BYTES {
        bail!(
            "optimized WASM size ({} bytes) exceeds Lexicon max_bytecode_size ({} bytes)",
            optimized_bytes.len(),
            MAX_LEXICON_BYTECODE_BYTES
        );
    }

    fs::create_dir_all(out_dir)?;
    let out_wasm = out_dir.join(format!("{artifact_stem}.wasm"));
    let out_meta = out_dir.join(format!("{artifact_stem}.meta.json"));

    let code_hash = format!("0x{}", hex::encode(keccak256(&optimized_bytes)));
    fs::write(&out_wasm, &optimized_bytes)?;

    let meta_json = json!({
        "hps": selected_pkg["name"],
        "artifact": out_wasm.display().to_string(),
        "code_hash": code_hash,
        "raw_wasm_bytes": report.raw_size,
        "optimized_wasm_bytes": report.optimized_size,
        "initial_memory_pages": report.initial_memory_pages,
        "max_memory_pages": report.max_memory_pages,
        "imports": report.imports,
        "exports": report.exports,
    });
    fs::write(&out_meta, serde_json::to_string_pretty(&meta_json)?)?;

    println!("Build succeeded:");
    println!("  Artifact   : {}", out_wasm.display());
    println!(
        "  Bytecode   : {} bytes (raw {} bytes)",
        report.optimized_size, report.raw_size
    );
    println!("  Code Hash  : {code_hash}");
    println!("  Metadata   : {}", out_meta.display());
    Ok(())
}

async fn cmd_deploy(
    wasm_path: &Path,
    rpc: &str,
    private_key: &str,
    chain_id: u64,
    init_args_hex: &str,
    save: Option<PathBuf>,
) -> Result<()> {
    let wasm_bytes =
        fs::read(wasm_path).with_context(|| format!("cannot read '{}'", wasm_path.display()))?;
    let (_, _report) = wasm_opt::optimize_and_validate_wasm(&wasm_bytes, false)
        .context("WASM validation failed prior to deployment")?;

    let clean_args = init_args_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(init_args_hex.trim());
    let init_args = if clean_args.is_empty() {
        Vec::new()
    } else {
        hex::decode(clean_args).context("invalid hex in --init-args")?
    };

    let signer = HpsSigner::from_hex(private_key, chain_id)?;
    let client = HpsClient::new(rpc);

    println!(
        "Deploying HPS {} ({} bytes) to {}...",
        wasm_path.display(),
        wasm_bytes.len(),
        rpc
    );
    println!("  Deployer   : {}", signer.address_hex());

    let receipt = client
        .deploy_hps(&signer, &wasm_bytes, &init_args)
        .await?;

    println!("Deployment confirmed in block #{}:", receipt.block_number);
    println!("  HPS Addr   : {}", receipt.hps_address);
    println!("  Code Hash  : {}", receipt.code_hash);
    println!("  Store Tx   : {}", receipt.store_tx_hash);
    println!("  Deploy Tx  : {}", receipt.deploy_tx_hash);
    println!("  Gas Used   : {}", receipt.deploy_gas_used);

    if let Some(save_path) = save {
        fs::write(&save_path, serde_json::to_string_pretty(&receipt)?)?;
        println!("  Saved      : {}", save_path.display());
    }
    Ok(())
}

async fn cmd_send(
    hps_str: &str,
    signature: &str,
    args: &[String],
    touch_strs: &[String],
    rpc: &str,
    private_key: &str,
    chain_id: u64,
) -> Result<()> {
    let hps = parse_address(hps_str)?;
    let mut extra_targets = Vec::with_capacity(touch_strs.len());
    for t in touch_strs {
        extra_targets.push(parse_address(t)?);
    }
    let calldata = encode_call_from_strings(signature, args)?;
    let signer = HpsSigner::from_hex(private_key, chain_id)?;
    let client = HpsClient::new(rpc);

    println!(
        "Invoking `{signature}` on HPS {hps_str} from {}...",
        signer.address_hex()
    );
    let outcome = client
        .send_call_with_targets(&signer, hps, &calldata, &extra_targets)
        .await?;
    println!("Transaction confirmed:");
    println!("  Tx Hash    : {}", outcome.tx_hash);
    println!(
        "  Status     : {}",
        if outcome.status {
            "SUCCESS (0x1)"
        } else {
            "FAILED (0x0)"
        }
    );
    println!("  Block      : #{}", outcome.block_number);
    println!("  Gas Used   : {}", outcome.gas_used);
    println!("  Logs       : {}", outcome.logs.len());
    for (idx, log) in outcome.logs.iter().enumerate() {
        println!(
            "    [{}] topics={} data={}",
            idx,
            log["topics"],
            log["data"].as_str().unwrap_or("0x")
        );
    }
    if !outcome.status {
        bail!("HPS execution reverted / failed");
    }
    Ok(())
}

async fn cmd_call(
    hps_str: &str,
    signature: &str,
    args: &[String],
    rpc: &str,
) -> Result<()> {
    let hps = parse_address(hps_str)?;
    let calldata = encode_call_from_strings(signature, args)?;
    let client = HpsClient::new(rpc);

    let ret = client.read_call(None, hps, &calldata).await?;
    println!("Raw Return   : 0x{}", hex::encode(&ret));
    if let Some(bytes_slice) = try_decode_abi_bytes(&ret) {
        if let Ok(utf8) = std::str::from_utf8(bytes_slice) {
            println!("Decoded UTF8 : \"{utf8}\"");
        } else {
            println!("Decoded Bytes: 0x{}", hex::encode(bytes_slice));
        }
    } else if let Some(val) = try_decode_u256(&ret) {
        println!("Decoded Uint : {val}");
    }
    Ok(())
}

fn cmd_keygen(dev: bool) -> Result<()> {
    if dev {
        let signer = HpsSigner::from_hex(DEFAULT_DEV_PRIVATE_KEY, DEFAULT_CHAIN_ID)?;
        println!("Built-in `--localtestnet` Developer Account:");
        println!("  Address     : {}", signer.address_hex());
        println!("  Private Key : {DEFAULT_DEV_PRIVATE_KEY}");
    } else {
        let (priv_hex, signer) = HpsSigner::generate_random(DEFAULT_CHAIN_ID);
        println!("Generated New Lexicon Account:");
        println!("  Address     : {}", signer.address_hex());
        println!("  Private Key : {priv_hex}");
    }
    Ok(())
}

async fn cmd_status(rpc: &str) -> Result<()> {
    let client = HpsClient::new(rpc);
    let height = client.block_number().await?;
    let role = client.rpc_call("slx_role", json!([])).await.unwrap_or(json!(null));
    println!("Connected to Lexicon JSON-RPC at {rpc}");
    println!("  Block Height : #{height}");
    if !role.is_null() {
        println!("  Node Role    : {role}");
    }
    Ok(())
}
