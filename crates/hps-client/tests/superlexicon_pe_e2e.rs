//! Live Wasmtime End-to-End Test: **Superlexicon Pte. Ltd. (Singapore Private Equity Asset Ledger)**
//!
//! Exercises the complete Singapore Private Limited Liability Company (`Pte. Ltd.`) cap table,
//! corporate governance bylaws, single-Constitution pinning, shareholder super-majority share
//! issuance, board-of-directors asset transfer resolution, event log verification, and negative
//! security test cases on an isolated `lexicon-node --localtestnet`:
//!
//! 1. **Company Profile & Genesis Capitalisation Table (`SLX-COMMON`)**:
//!    - **2 Directors**:
//!      - `Manogaran Thanabalan` (`manogaran.thanabalan`) — Director #1 & Founding Shareholder #1
//!      - `Evelyn Tan Wei Ling` (`evelyn.tan.director`) — Director #2 (independent non-shareholder director)
//!    - **49 Shareholders** holding **100,000 `SLX-COMMON` common shares** with **1:1 voting rights**:
//!      - Shareholder #1 (`Manogaran Thanabalan`): **50,000 shares** (`50.00%`)
//!      - Shareholders #2..#17 (16 shareholders): **1,250 shares each** (`20,000 shares`)
//!      - Shareholders #18..#33 (16 shareholders): **1,000 shares each** (`16,000 shares`)
//!      - Shareholders #34..#49 (16 shareholders): **875 shares each** (`14,000 shares`)
//!      - Total across 49 shareholders = **100,000 shares** (`100.00%`).
//!    - **Corporate Identity**: `Superlexicon Pte. Ltd.` (`superlexicon.pte.ltd`) holding **250,000**
//!      units in an external `AssetLedger` (`USD-TREASURY`).
//! 2. **Deployment Sequence & Single-Constitution Restriction**:
//!    - Deploys all Directors', Shareholders', and Company `Identity` HPSes (52 total) and registers
//!      them in `IdentityRegistry` with live WASM `code_hash` attestation.
//!    - Deploys the `SLX-COMMON` `AssetLedger` HPS with the 49-shareholder initial cap table pinned
//!      exclusively to the single Superlexicon `Constitution` HPS address.
//!    - Deploys the Superlexicon `Constitution` HPS defining:
//!      - `POLICY_SHAREHOLDER_SUPERMAJORITY` / `POLICY_SUPER_GOVERNANCE` ($\ge 75\%$ = `75,000` of
//!        `100,000` votes across all 49 shareholders) for `issue`, `cancel`, `addDirector`,
//!        `removeDirector`, and bylaw amendments.
//!      - `POLICY_BOARD_RESOLUTION` (`2-of-2` unanimous Directors: `Manogaran Thanabalan` +
//!        `Evelyn Tan Wei Ling`) for invoking `transfer` in another `AssetLedger` (`USD-TREASURY`)
//!        where Superlexicon's corporate `Identity` is the asset owner.
//! 3. **Share Issuance to Make Manogaran Thanabalan the Super-Majority ($\ge 75\%$) Shareholder**:
//!    - Deploys an `Authorization` HPS initialized from the Superlexicon `Constitution` for issuing
//!      **100,000 new `SLX-COMMON` shares** to `Manogaran Thanabalan`.
//!    - Accumulates `75,000` votes (`Manogaran`'s `50,000` votes + 21 minority shareholders'
//!      `25,000` votes), transitions the `Authorization` HPS to `STATE_FINALIZED`, and invokes
//!      `SLX-COMMON.issue`, bringing `Manogaran Thanabalan` to **150,000 / 200,000 shares (75.00%)**.
//! 4. **Event Log & Negative Security Verification**:
//!    - Verifies emitted topics and data payloads in transaction receipts (`TxOutcome.logs`).
//!    - Verifies that unfinalized, under-threshold, duplicate-vote, wrong-policy (Board instead of
//!      Shareholder Super-Majority), wrong-action, unapproved-bytecode-clone, and replayed
//!      (already-consumed) `Authorization` objects are deterministically rejected.
//!
//! Run with:
//! ```bash
//! cargo test -p hps-client --test superlexicon_pe_e2e -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ethereum_types::{H160, U256};
use hps_client::abi::{encode_values, keccak256, try_decode_u256, AbiValue};
use hps_client::{
    compute_hps_address, HpsClient, HpsSigner, TxOutcome, DEFAULT_CHAIN_ID, DEFAULT_DEV_PRIVATE_KEY,
};
use hps_sdk::governance::{
    share_transfer_auction_policy_spec, PolicySpec, StageSpec, ACTION_APPROVE, ACTION_CANCEL,
    ACTION_ISSUE, ACTION_SUPER, ACTION_TRANSFER, POLICY_BOARD_RESOLUTION, POLICY_HOLDER_SELF,
    POLICY_SHAREHOLDER_SUPERMAJORITY, POLICY_SHARE_TRANSFER_AUCTION, POLICY_SUPER_GOVERNANCE,
};

const STATE_PENDING: u64 = 1;
const STATE_FINALIZED: u64 = 2;
const STATE_CONSUMED: u64 = 4;

const TEST_RPC_PORT: u16 = 18565;
const TEST_WS_PORT: u16 = 18566;
const TEST_HTTP_PORT: u16 = 18090;
const TEST_P2P_PORT: u16 = 40313;

struct NodeGuard {
    child: Child,
    temp_dir: PathBuf,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn find_lexicon_node_bin() -> PathBuf {
    if let Ok(p) = std::env::var("LEXICON_NODE_BIN") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return pb;
        }
    }
    let candidates = [
        "/home/mano/Projects/lexicon-bin/bin/lexicon-node",
        "/home/mano/Projects/lexicon/target/release/superlexicon-app",
    ];
    for c in candidates {
        let pb = PathBuf::from(c);
        if pb.exists() {
            return pb;
        }
    }
    panic!("Could not find lexicon-node binary; set LEXICON_NODE_BIN=/path/to/lexicon-node");
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn spawn_isolated_localtestnet() -> NodeGuard {
    let bin = find_lexicon_node_bin();
    let temp_dir = std::env::temp_dir().join(format!("hps-slx-pe-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let db_path = temp_dir.join("localtestnet.db");
    let log_path = temp_dir.join("node.log");
    let cfg_path = temp_dir.join("local-config.json");

    let cfg_json = serde_json::json!({
        "app_name": "HPS-Superlexicon-PE-E2E",
        "version": "1.0.0",
        "server": { "host": "127.0.0.1", "port": TEST_HTTP_PORT, "max_connections": 32 },
        "database": { "consensus_db_path": db_path.to_string_lossy() },
        "logging": { "level": "warn", "file": log_path.to_string_lossy() },
        "features": { "enable_metrics": false, "enable_cache": true, "cache_ttl_seconds": 3600 },
        "p2p": {
            "listen_address": "127.0.0.1",
            "listen_port": TEST_P2P_PORT,
            "max_peers": 4,
            "min_peers": 0,
            "bootstrap_nodes": [],
            "network_id": DEFAULT_CHAIN_ID,
            "protocol_version": 66,
            "discovery_enabled": false,
            "mdns_enabled": false,
            "discv5_enabled": false,
            "connection_retry_delay_ms": 5000,
            "max_connection_attempts": 1,
            "bootstrap_interval_seconds": 30,
            "idle_connection_timeout_seconds": 10,
            "kademlia_enabled": false,
            "kademlia_protocol": "/superlexicon/kad/1.0.0",
            "initial_validators": [],
            "validator_peer_mappings": {},
            "private_key": "1111111111111111111111111111111111111111111111111111111111111111"
        },
        "api": {
            "jsonrpc": {
                "enabled": true,
                "host": "127.0.0.1",
                "port": TEST_RPC_PORT,
                "max_connections": 64,
                "cors_enabled": true,
                "allowed_origins": ["*"]
            },
            "graphql": {
                "enabled": false,
                "host": "127.0.0.1",
                "port": 18548,
                "playground": false,
                "max_complexity": 100,
                "max_depth": 15
            },
            "grpc": {
                "enabled": false,
                "host": "127.0.0.1",
                "port": 58052,
                "reflection": false,
                "tls_enabled": false,
                "cert_path": null,
                "key_path": null
            },
            "websocket": {
                "enabled": true,
                "host": "127.0.0.1",
                "port": TEST_WS_PORT,
                "max_connections": 32
            }
        },
        "genesis": {
            "transport_selection": {
                "peer_exchange": "Flrc",
                "transaction": "Flrc",
                "block_proposal": "Flrc",
                "final_block": "Flrc",
                "receipt": "Flrc",
                "contract_state": "Flrc",
                "db_sync": "Flrc",
                "bytecode_sync": "Flrc",
                "role_proposal": "Flrc",
                "finalized_role": "Flrc"
            },
            "validator_promotion_threshold": 100,
            "block_gas_limit": 300000000,
            "max_transaction_gas_limit": 25000000,
            "max_bytecode_size": 100000,
            "max_constructor_args_size": 32768,
            "max_nonce_gap": 128,
            "max_txs_per_origin_node": 200,
            "reputation_account_threshold": -100,
            "reputation_node_threshold": -1000,
            "reputation_success_delta": 1,
            "reputation_failure_delta": 1,
            "reputation_blacklist_enabled": false,
            "block_interval_ms": 1000,
            "pre_phase1_ms": 500,
            "consensus_phase1_ms": 8000,
            "pre_phase2_ms": 4000,
            "consensus_phase2_ms": 5000,
            "pre_phase3_ms": 3000,
            "consensus_block_broadcast_ms": 4000,
            "timestamp": 0,
            "chain_id": DEFAULT_CHAIN_ID,
            "contract_creation_gas_per_byte": 1,
            "max_parallel_execution_groups": 8,
            "mempool_exchange_timeout_ms": 10000,
            "block_proposal_timeout_ms": 15000,
            "insufficient_participation_timeout_ms": 30000,
            "post_byzantine_mempool_timeout_ms": 3000,
            "post_byzantine_proposal_timeout_ms": 2000,
            "network_thread_pool_size": 4,
            "network_thread_replicas_size": 3,
            "threadpool_consensus_threshold_percentage": 0.67
        },
        "lr2021": {
            "enabled": false,
            "serial_port": "/dev/null",
            "baud_rate": 115200,
            "frequency_hz": 867100000,
            "bandwidth_hz": 1200000,
            "coding_rate": 1,
            "tx_power_dbm": 22,
            "sync_word": "0x12345690",
            "tx_ingress_mode": "rpc",
            "client_radio": null
        }
    });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg_json).unwrap()).unwrap();

    let child = Command::new(&bin)
        .arg("--localtestnet")
        .arg("--db-path")
        .arg(&db_path)
        .arg("--config")
        .arg(&cfg_path)
        .current_dir(&temp_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn lexicon-node --localtestnet");

    NodeGuard { child, temp_dir }
}

fn h160_bytes(a: H160) -> [u8; 20] {
    let mut b = [0u8; 20];
    b.copy_from_slice(a.as_bytes());
    b
}

fn topic_hex(sig: &str) -> String {
    format!("0x{}", hex::encode(keccak256(sig.as_bytes())))
}

fn has_log_topic(rcpt: &TxOutcome, sig: &str) -> bool {
    let want = topic_hex(sig);
    rcpt.logs.iter().any(|l| {
        l["topics"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|t| t.as_str().map(|s| s.eq_ignore_ascii_case(&want)).unwrap_or(false))
            })
            .unwrap_or(false)
    })
}

fn encode_constitution_entry(target: H160, policy_id: [u8; 32], spec: &PolicySpec) -> Vec<u8> {
    let mut spec_buf = [0u8; 4096];
    let n = spec.encode(&mut spec_buf).expect("encode PolicySpec");
    let mut out = Vec::with_capacity(20 + 32 + 2 + n);
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(&policy_id);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&spec_buf[..n]);
    out
}

fn pack_permission(action: [u8; 32], constitution: H160, policy_id: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(84);
    out.extend_from_slice(&action);
    out.extend_from_slice(constitution.as_bytes());
    out.extend_from_slice(&policy_id);
    out
}

async fn read_u64(client: &HpsClient, hps: H160, sig: &str, args: &[AbiValue]) -> u64 {
    let cd = encode_values(sig, args);
    let ret = client.read_call(None, hps, &cd).await.expect("eth_call");
    try_decode_u256(&ret)
        .unwrap_or_else(|| panic!("expected 32B uint return from {sig}, got {}B", ret.len()))
        .low_u64()
}

async fn read_address(client: &HpsClient, hps: H160, sig: &str, args: &[AbiValue]) -> H160 {
    let cd = encode_values(sig, args);
    let ret = client.read_call(None, hps, &cd).await.expect("eth_call");
    assert_eq!(ret.len(), 32, "expected 32B address word from {sig}");
    H160::from_slice(&ret[12..32])
}

async fn read_b32(client: &HpsClient, hps: H160, sig: &str, args: &[AbiValue]) -> [u8; 32] {
    let cd = encode_values(sig, args);
    let ret = client.read_call(None, hps, &cd).await.expect("eth_call");
    assert_eq!(ret.len(), 32, "expected 32B bytes32 from {sig}");
    let mut out = [0u8; 32];
    out.copy_from_slice(&ret);
    out
}

#[tokio::test]
#[ignore = "requires local lexicon-node binary; run with --ignored"]
async fn superlexicon_singapore_pte_ltd_private_equity_e2e_on_localtestnet() {
    let _node = spawn_isolated_localtestnet();
    let rpc_url = format!("http://127.0.0.1:{TEST_RPC_PORT}");
    let client = HpsClient::new(&rpc_url);

    for _ in 0..40 {
        if client.block_number().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let start_height = client.block_number().await.expect("localtestnet RPC reachable");
    println!(
        "[1/9] Isolated lexicon-node --localtestnet online at {rpc_url} (block #{start_height})"
    );

    // Load compiled WASM subroutines from dist/
    let dist = workspace_root().join("dist");
    let identity_wasm = std::fs::read(dist.join("identity.wasm")).expect("dist/identity.wasm");
    let registry_wasm =
        std::fs::read(dist.join("identity_registry.wasm")).expect("dist/identity_registry.wasm");
    let constitution_wasm =
        std::fs::read(dist.join("constitution.wasm")).expect("dist/constitution.wasm");
    let auth_wasm =
        std::fs::read(dist.join("authorization.wasm")).expect("dist/authorization.wasm");
    let ledger_wasm =
        std::fs::read(dist.join("asset_ledger.wasm")).expect("dist/asset_ledger.wasm");
    let messaging_wasm =
        std::fs::read(dist.join("messaging.wasm")).expect("dist/messaging.wasm");

    let mut deployer = HpsSigner::from_hex(DEFAULT_DEV_PRIVATE_KEY, DEFAULT_CHAIN_ID).unwrap();
    deployer.default_gas_limit = U256::from(4_000_000u64);

    // Store WASM bytecodes once in the content-addressed bytecode store (0x000...0100)
    let id_code = client.store_bytecode(&deployer, &identity_wasm).await.unwrap();
    let auth_code = client.store_bytecode(&deployer, &auth_wasm).await.unwrap();
    let ledger_code = client.store_bytecode(&deployer, &ledger_wasm).await.unwrap();
    let con_code = client
        .store_bytecode(&deployer, &constitution_wasm)
        .await
        .unwrap();

    // =========================================================================
    // STEP 1: Deploy & Initialize all 52 Identity HPSes + IdentityRegistry
    //   - ids[0]    = Manogaran Thanabalan (Director #1 & Shareholder #1: 50,000 shares)
    //   - ids[1]    = Evelyn Tan Wei Ling (Director #2, non-shareholder independent director)
    //   - ids[2]    = Superlexicon Pte. Ltd. corporate identity (owner of USD-TREASURY assets)
    //   - ids[3..51]= 48 Minority Shareholders (Shareholders #2..#49 holding 50,000 shares total)
    //   - ids[51]   = Dr. Rajesh Nair (Director #3 candidate to be appointed via Shareholder Super-Majority)
    // =========================================================================
    let id_specs_batch1: Vec<_> = (0..26).map(|_| (id_code, Vec::new())).collect();
    let id_specs_batch2: Vec<_> = (0..26).map(|_| (id_code, Vec::new())).collect();
    let mut ids = client
        .instantiate_batch(&deployer, &id_specs_batch1)
        .await
        .unwrap();
    ids.extend(
        client
            .instantiate_batch(&deployer, &id_specs_batch2)
            .await
            .unwrap(),
    );
    assert_eq!(ids.len(), 52);

    let manogaran_id = ids[0];
    let evelyn_director_id = ids[1];
    let superlexicon_company_id = ids[2];
    let minority_shareholder_ids: Vec<H160> = ids[3..51].to_vec();
    let third_director_id = ids[51];
    assert_eq!(minority_shareholder_ids.len(), 48);

    // Initialize all 52 Identity HPSes in 2 pipelined batches (controlled by `deployer` EOA for test orchestration)
    let mut init_calls_1 = Vec::with_capacity(26);
    let mut init_calls_2 = Vec::with_capacity(26);
    for (idx, id_hps) in ids.iter().enumerate() {
        let handle = match idx {
            0 => "manogaran.thanabalan".to_string(),
            1 => "evelyn.tan.director".to_string(),
            2 => "superlexicon.pte.ltd".to_string(),
            51 => "rajesh.nair.director3".to_string(),
            _ => format!("shareholder.{:02}", idx - 1),
        };
        let cd = encode_values(
            "initialize(address,string)",
            &[
                AbiValue::Address(deployer.address()),
                AbiValue::Bytes(handle.into_bytes()),
            ],
        );
        if idx < 26 {
            init_calls_1.push((*id_hps, cd, Vec::new()));
        } else {
            init_calls_2.push((*id_hps, cd, Vec::new()));
        }
    }
    for rcpt in client.send_call_batch(&deployer, &init_calls_1).await.unwrap() {
        assert!(rcpt.status, "Identity init batch 1 must succeed");
        assert!(
            has_log_topic(&rcpt, "IdentityInitialized(address,string)"),
            "IdentityInitialized event must be emitted"
        );
    }
    for rcpt in client.send_call_batch(&deployer, &init_calls_2).await.unwrap() {
        assert!(rcpt.status, "Identity init batch 2 must succeed");
        assert!(
            has_log_topic(&rcpt, "IdentityInitialized(address,string)"),
            "IdentityInitialized event must be emitted"
        );
    }

    deployer.default_gas_limit = U256::from(15_000_000u64);

    // Deploy & initialize IdentityRegistry with all 52 verified Identities and approved WASM bytecode hashes
    let reg_deploy = client
        .deploy_hps(&deployer, &registry_wasm, &[])
        .await
        .unwrap();
    let registry = hps_client::parse_address(&reg_deploy.hps_address).unwrap();

    let mut initial_packed_ids = Vec::with_capacity(51 * 20);
    for id_hps in &ids[1..] {
        initial_packed_ids.extend_from_slice(id_hps.as_bytes());
    }
    let reg_init_cd = encode_values(
        "initialize(address,bytes32,bytes32,bytes)",
        &[
            AbiValue::Address(manogaran_id),
            AbiValue::Bytes32(*id_code.as_fixed_bytes()),
            AbiValue::Bytes32(*auth_code.as_fixed_bytes()),
            AbiValue::Bytes(initial_packed_ids),
        ],
    );
    let mut reg_targets = vec![manogaran_id];
    reg_targets.extend_from_slice(&ids[1..]);
    let reg_init_rcpt = client
        .send_call_with_targets(&deployer, registry, &reg_init_cd, &reg_targets)
        .await
        .unwrap();
    assert!(reg_init_rcpt.status, "IdentityRegistry initialize must succeed");
    assert!(
        has_log_topic(
            &reg_init_rcpt,
            "RegistryInitialized(address,bytes32,bytes32,uint64)"
        ),
        "RegistryInitialized event must be emitted"
    );
    assert_eq!(read_u64(&client, registry, "activeCount()", &[]).await, 52);
    println!(
        "[2/9] Deployed & verified 52 Identity HPSes (2 Directors, 49 Shareholders, 1 Corporate Identity, 1 Director Candidate) in IdentityRegistry ({})",
        reg_deploy.hps_address
    );

    // =========================================================================
    // STEP 2: Deploy `SLX-COMMON` AssetLedger with 49-Shareholder Cap Table
    //         (100,000 shares, Manogaran = 50,000, 48 others = 50,000)
    //         AND verify Single-Constitution Restriction!
    // =========================================================================
    // Build the 49-shareholder initial cap table:
    //   - Shareholder #1 (Manogaran Thanabalan): 50,000 shares (50.00%)
    //   - Shareholders #2..#5 (4 lead minority shareholders): 6,500, 6,500, 6,000, 6,000 = 25,000 shares (25.00%)
    //   - Shareholders #6..#25 (20 minority shareholders): 650 shares each = 13,000 shares (13.00%)
    //   - Shareholders #26..#49 (24 minority shareholders): 500 shares each = 12,000 shares (12.00%)
    //   Total across 49 shareholders = 100,000 shares (1:1 voting weight).
    let mut cap_table: Vec<(H160, u64)> = Vec::with_capacity(49);
    cap_table.push((manogaran_id, 50_000));
    for (idx, sh_id) in minority_shareholder_ids.iter().enumerate() {
        let shares = match idx {
            0 | 1 => 6_500u64,
            2 | 3 => 6_000u64,
            4..=23 => 650u64,
            _ => 500u64,
        };
        cap_table.push((*sh_id, shares));
    }
    assert_eq!(cap_table.len(), 49);
    let genesis_supply: u64 = cap_table.iter().map(|(_, s)| *s).sum();
    assert_eq!(genesis_supply, 100_000);

    let mut alloc_blob = Vec::with_capacity(49 * 28);
    for (holder, amount) in &cap_table {
        alloc_blob.extend_from_slice(holder.as_bytes());
        alloc_blob.extend_from_slice(&amount.to_be_bytes());
    }

    // Instantiate `slx_ledger` (`SLX-COMMON`), `ext_treasury_ledger` (`USD-TREASURY`),
    // and pre-compute the deterministic address of `slx_constitution` so `slx_ledger`
    // is initialized FIRST and pinned to `slx_constitution` before `slx_constitution` is initialized!
    let slx_ledger = client
        .instantiate_hps(&deployer, ledger_code, &[])
        .await
        .unwrap();
    let ext_treasury_ledger = client
        .instantiate_hps(&deployer, ledger_code, &[])
        .await
        .unwrap();

    // Pre-compute deterministic address where `slx_constitution` will be instantiated after `slx_ledger` is initialized:
    // Next transactions from `deployer`:
    //   - nonce N:   negative test `slx_ledger.initialize` with 2 different Constitutions (reverts!)
    //   - nonce N+1: positive `slx_ledger.initialize` pinned exclusively to `slx_constitution`
    //   - nonce N+2: `instantiate_hps(con_code)` -> `slx_constitution`!
    let cur_nonce = client.get_nonce(deployer.address()).await.unwrap();
    let slx_constitution_expected = compute_hps_address(deployer.address(), cur_nonce + 2);
    let rogue_constitution = H160::repeat_byte(0xCC);

    // Negative Test N1: Attempting to initialize `slx_ledger` with two different Constitutions
    // (`slx_constitution_expected` and `rogue_constitution`) MUST revert (`ERR_CONSTITUTION_MISMATCH`)!
    let mut bad_perms_blob = Vec::new();
    bad_perms_blob.extend_from_slice(&pack_permission(
        ACTION_SUPER,
        slx_constitution_expected,
        POLICY_SUPER_GOVERNANCE,
    ));
    bad_perms_blob.extend_from_slice(&pack_permission(
        ACTION_ISSUE,
        rogue_constitution,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
    ));
    let bad_ledger_init_cd = encode_values(
        "initialize(address,string,uint64,bytes,bytes)",
        &[
            AbiValue::Address(registry),
            AbiValue::Bytes(b"SLX-COMMON".to_vec()),
            AbiValue::Uint(U256::from(0u64)),
            AbiValue::Bytes(alloc_blob.clone()),
            AbiValue::Bytes(bad_perms_blob),
        ],
    );
    let mut ledger_init_targets: Vec<H160> = vec![slx_ledger, registry];
    for (h, _) in &cap_table {
        ledger_init_targets.push(*h);
    }
    let bad_ledger_exec_cd = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Bytes(bad_ledger_init_cd),
        ],
    );
    let bad_init_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &bad_ledger_exec_cd,
            &ledger_init_targets,
        )
        .await
        .unwrap();
    assert!(
        !bad_init_rcpt.status,
        "Negative Test N1: AssetLedger initialize with 2 different Constitutions MUST revert"
    );

    // Positive Test P1: Initialize `slx_ledger` (`SLX-COMMON`) with the 49-shareholder cap table
    // pinned exclusively to `slx_constitution_expected`!
    let mut slx_perms_blob = Vec::new();
    slx_perms_blob.extend_from_slice(&pack_permission(
        ACTION_SUPER,
        slx_constitution_expected,
        POLICY_SUPER_GOVERNANCE,
    ));
    slx_perms_blob.extend_from_slice(&pack_permission(
        ACTION_ISSUE,
        slx_constitution_expected,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
    ));
    slx_perms_blob.extend_from_slice(&pack_permission(
        ACTION_CANCEL,
        slx_constitution_expected,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
    ));
    slx_perms_blob.extend_from_slice(&pack_permission(
        ACTION_TRANSFER,
        slx_constitution_expected,
        POLICY_SHARE_TRANSFER_AUCTION,
    ));
    slx_perms_blob.extend_from_slice(&pack_permission(
        ACTION_APPROVE,
        H160::zero(),
        POLICY_HOLDER_SELF,
    ));

    let slx_init_cd = encode_values(
        "initialize(address,string,uint64,bytes,bytes)",
        &[
            AbiValue::Address(registry),
            AbiValue::Bytes(b"SLX-COMMON".to_vec()),
            AbiValue::Uint(U256::from(0u64)),
            AbiValue::Bytes(alloc_blob),
            AbiValue::Bytes(slx_perms_blob),
        ],
    );
    let slx_init_exec_cd = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(slx_ledger), AbiValue::Bytes(slx_init_cd)],
    );
    let slx_init_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &slx_init_exec_cd,
            &ledger_init_targets,
        )
        .await
        .unwrap();
    assert!(slx_init_rcpt.status, "SLX-COMMON AssetLedger initialize must succeed");
    assert!(
        has_log_topic(&slx_init_rcpt, "ConstitutionPinned(address)"),
        "ConstitutionPinned event must be emitted"
    );
    assert!(
        has_log_topic(&slx_init_rcpt, "LedgerInitialized(address,uint64,uint64)"),
        "LedgerInitialized event must be emitted"
    );
    assert_eq!(
        read_address(&client, slx_ledger, "associatedConstitution()", &[]).await,
        slx_constitution_expected
    );
    assert_eq!(
        read_u64(&client, slx_ledger, "totalOutstanding()", &[]).await,
        100_000
    );
    assert_eq!(read_u64(&client, slx_ledger, "holderCount()", &[]).await, 49);
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(manogaran_id)]
        )
        .await,
        50_000
    );
    println!(
        "[3/9] Deployed SLX-COMMON AssetLedger (0x{}) with 49 shareholders, 100,000 total shares (Manogaran = 50,000), pinned to single Constitution 0x{}",
        hex::encode(slx_ledger.as_bytes()),
        hex::encode(slx_constitution_expected.as_bytes())
    );

    // =========================================================================
    // STEP 3: Deploy & Initialize Superlexicon `Constitution` HPS at `slx_constitution_expected`
    // =========================================================================
    let slx_constitution = client
        .instantiate_hps(&deployer, con_code, &[])
        .await
        .unwrap();
    assert_eq!(
        slx_constitution, slx_constitution_expected,
        "Constitution address must match single pinned Constitution in SLX-COMMON AssetLedger"
    );

    // Policy 1: Shareholder Super-Majority Resolution (>= 75% of 100,000 = 75,000 votes, 1:1 voting rights)
    let mut sh_stage = StageSpec::new(75_000, 100);
    for (sh_id, shares) in &cap_table {
        sh_stage = sh_stage.add_member(h160_bytes(*sh_id), *shares).unwrap();
    }
    let sh_supermajority_spec = PolicySpec::new(200).add_stage(sh_stage).unwrap();

    // Policy 2: Board of Directors Resolution (unanimous 2-of-2 Directors: Manogaran + Evelyn Tan)
    let board_stage = StageSpec::new(2, 100)
        .add_member(h160_bytes(manogaran_id), 1)
        .unwrap()
        .add_member(h160_bytes(evelyn_director_id), 1)
        .unwrap();
    let board_resolution_spec = PolicySpec::new(200).add_stage(board_stage).unwrap();

    // Policy 3: 3-Step Call-Auction Share Transfer Policy (`POLICY_SHARE_TRANSFER_AUCTION`)
    // Window 1 (buyers) = 3 blocks, Window 2 (existing shareholders sell) = 3 blocks,
    // Window 3 (non-participating existing shareholders buy) = 3 blocks, overall settlement window = 50 blocks.
    let transfer_auction_spec =
        share_transfer_auction_policy_spec(h160_bytes(manogaran_id), 3, 3, 3, 50).unwrap();

    let mut con_blob = Vec::new();
    con_blob.extend_from_slice(&4u16.to_be_bytes());
    con_blob.extend_from_slice(&encode_constitution_entry(
        H160::zero(),
        POLICY_SUPER_GOVERNANCE,
        &sh_supermajority_spec,
    ));
    con_blob.extend_from_slice(&encode_constitution_entry(
        slx_ledger,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
        &sh_supermajority_spec,
    ));
    con_blob.extend_from_slice(&encode_constitution_entry(
        H160::zero(),
        POLICY_BOARD_RESOLUTION,
        &board_resolution_spec,
    ));
    con_blob.extend_from_slice(&encode_constitution_entry(
        slx_ledger,
        POLICY_SHARE_TRANSFER_AUCTION,
        &transfer_auction_spec,
    ));

    let con_init_cd = encode_values(
        "initialize(address,bytes)",
        &[AbiValue::Address(registry), AbiValue::Bytes(con_blob)],
    );
    let con_init_exec_cd = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(slx_constitution),
            AbiValue::Bytes(con_init_cd),
        ],
    );
    let mut con_targets = vec![slx_constitution, registry, manogaran_id, evelyn_director_id];
    for (sh_id, _) in &cap_table[1..] {
        con_targets.push(*sh_id);
    }
    let con_init_rcpt = client
        .send_call_with_targets(&deployer, manogaran_id, &con_init_exec_cd, &con_targets)
        .await
        .unwrap();
    assert!(
        con_init_rcpt.status,
        "Superlexicon Constitution initialize must succeed"
    );
    assert!(
        has_log_topic(&con_init_rcpt, "ConstitutionInitialized(address,uint64)"),
        "ConstitutionInitialized event must be emitted"
    );
    assert!(
        has_log_topic(
            &con_init_rcpt,
            "PolicySet(address,bytes32,uint64,uint64)"
        ),
        "PolicySet event must be emitted"
    );
    assert_eq!(
        read_u64(&client, slx_constitution, "directorCount()", &[]).await,
        2
    );
    println!(
        "[4/9] Deployed & initialized Superlexicon Constitution (0x{}) with 49-shareholder Super-Majority (>=75,000/100,000 votes) and 2-of-2 Board of Directors policies",
        hex::encode(slx_constitution.as_bytes())
    );
    deployer.default_gas_limit = U256::from(5_000_000u64);

    // Also initialize `ext_treasury_ledger` (`USD-TREASURY`) where `superlexicon_company_id` owns 250,000 units,
    // and `ACTION_TRANSFER` is governed by `POLICY_BOARD_RESOLUTION` (requiring both Directors to authorize!)
    let mut ext_alloc = Vec::with_capacity(28);
    ext_alloc.extend_from_slice(superlexicon_company_id.as_bytes());
    ext_alloc.extend_from_slice(&250_000u64.to_be_bytes());
    let mut ext_perms = Vec::new();
    ext_perms.extend_from_slice(&pack_permission(
        ACTION_SUPER,
        slx_constitution,
        POLICY_SUPER_GOVERNANCE,
    ));
    ext_perms.extend_from_slice(&pack_permission(
        ACTION_ISSUE,
        slx_constitution,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
    ));
    ext_perms.extend_from_slice(&pack_permission(
        ACTION_CANCEL,
        slx_constitution,
        POLICY_SHAREHOLDER_SUPERMAJORITY,
    ));
    ext_perms.extend_from_slice(&pack_permission(
        ACTION_TRANSFER,
        slx_constitution,
        POLICY_BOARD_RESOLUTION,
    ));
    ext_perms.extend_from_slice(&pack_permission(
        ACTION_APPROVE,
        slx_constitution,
        POLICY_BOARD_RESOLUTION,
    ));
    let ext_init_cd = encode_values(
        "initialize(address,string,uint64,bytes,bytes)",
        &[
            AbiValue::Address(registry),
            AbiValue::Bytes(b"USD-TREASURY".to_vec()),
            AbiValue::Uint(U256::from(2u64)),
            AbiValue::Bytes(ext_alloc),
            AbiValue::Bytes(ext_perms),
        ],
    );
    let ext_init_exec_cd = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(ext_treasury_ledger),
            AbiValue::Bytes(ext_init_cd),
        ],
    );
    let ext_init_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &ext_init_exec_cd,
            &[ext_treasury_ledger, registry, superlexicon_company_id],
        )
        .await
        .unwrap();
    assert!(ext_init_rcpt.status, "USD-TREASURY AssetLedger initialize must succeed");

    // =========================================================================
    // STEP 4: Batch-Instantiate Authorization HPSes + Malicious Clone for Testing
    // =========================================================================
    let auth_specs: Vec<_> = (0..5).map(|_| (auth_code, Vec::new())).collect();
    let auths = client.instantiate_batch(&deployer, &auth_specs).await.unwrap();
    let (
        auth_issue_mano,
        auth_board_wrong_pol,
        auth_board_transfer,
        auth_add_director,
        auth_transfer_auction,
    ) = (auths[0], auths[1], auths[2], auths[3], auths[4]);

    // Also deploy a maliciously cloned Authorization WASM (`messaging.wasm` masquerading as an Authorization HPS)
    let clone_deploy = client
        .deploy_hps(&deployer, &messaging_wasm, &[])
        .await
        .unwrap();
    let malicious_auth_clone = hps_client::parse_address(&clone_deploy.hps_address).unwrap();

    // Compute actionHash for issuing 100,000 new shares to Manogaran Thanabalan:
    // Post-issuance: Manogaran holds 150,000 / 200,000 shares = 75.00% super-majority!
    let issue_amount = 100_000u64;
    let h_issue_mano = read_b32(
        &client,
        slx_ledger,
        "hashIssue(address,uint64)",
        &[
            AbiValue::Address(manogaran_id),
            AbiValue::Uint(U256::from(issue_amount)),
        ],
    )
    .await;

    // Initialize `auth_issue_mano` via `manogaran_id`
    let init_auth_issue_cd = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_issue_mano),
            AbiValue::Address(registry),
            AbiValue::Address(slx_constitution),
            AbiValue::Address(slx_ledger),
            AbiValue::Bytes32(POLICY_SHAREHOLDER_SUPERMAJORITY),
            AbiValue::Bytes32(h_issue_mano),
        ],
    );
    let init_auth_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &init_auth_issue_cd,
            &[auth_issue_mano, registry, slx_constitution, slx_ledger],
        )
        .await
        .unwrap();
    assert!(init_auth_rcpt.status, "auth_issue_mano initialize must succeed");
    assert!(
        has_log_topic(
            &init_auth_rcpt,
            "AuthorizationInitialized(address,address,bytes32,bytes32)"
        ),
        "AuthorizationInitialized event must be emitted"
    );
    assert_eq!(
        read_u64(&client, auth_issue_mano, "status()", &[]).await,
        STATE_PENDING
    );

    // =========================================================================
    // STEP 5: Negative Security Test Cases (Before Super-Majority Finalization)
    // =========================================================================
    // Negative Test N2: Attempting to overwrite/re-initialize `auth_issue_mano` MUST revert!
    let overwrite_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &init_auth_issue_cd,
            &[auth_issue_mano, registry, slx_constitution, slx_ledger],
        )
        .await
        .unwrap();
    assert!(
        !overwrite_rcpt.status,
        "Negative Test N2: Overwriting an initialized Authorization HPS MUST revert"
    );

    // Manogaran casts his 50,000 votes (50.00% < 75.00% required super-majority of 75,000)
    let approve_stage0_cd = encode_values(
        "approveAuth(address)",
        &[AbiValue::Address(auth_issue_mano)],
    );
    let mano_vote_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &approve_stage0_cd,
            &[auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(mano_vote_rcpt.status, "Manogaran's 50,000-vote approval must succeed");
    assert!(
        has_log_topic(
            &mano_vote_rcpt,
            "StageApproved(address,uint64,uint64,uint64)"
        ),
        "StageApproved event must be emitted"
    );
    assert_eq!(
        read_u64(
            &client,
            auth_issue_mano,
            "stageWeight(uint64)",
            &[AbiValue::Uint(U256::from(0u64))]
        )
        .await,
        50_000
    );

    // Negative Test N3: Duplicate vote by Manogaran on the same Authorization MUST revert!
    let dup_vote_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &approve_stage0_cd,
            &[auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(
        !dup_vote_rcpt.status,
        "Negative Test N3: Duplicate shareholder vote MUST revert"
    );

    // Negative Test N4: Attempting to finalize `auth_issue_mano` with only 50,000 / 75,000 votes MUST revert!
    let finalize_auth_cd = encode_values(
        "finalizeAuth(address)",
        &[AbiValue::Address(auth_issue_mano)],
    );
    let early_fin_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &finalize_auth_cd,
            &[auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(
        !early_fin_rcpt.status,
        "Negative Test N4: Finalizing before reaching 75,000 super-majority votes MUST revert"
    );

    // Negative Test N5: Passing an unfinalized `auth_issue_mano` to `SLX-COMMON.issue` MUST revert!
    let issue_via_id_cd = encode_values(
        "issueAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Address(manogaran_id),
            AbiValue::Uint(U256::from(issue_amount)),
            AbiValue::Address(auth_issue_mano),
        ],
    );
    let unfinalized_issue_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &issue_via_id_cd,
            &[slx_ledger, auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(
        !unfinalized_issue_rcpt.status,
        "Negative Test N5: Calling issue() with an unfinalized Authorization HPS MUST revert"
    );

    // Negative Test N6: Passing a finalized Board of Directors Authorization (`POLICY_BOARD_RESOLUTION`)
    // instead of a Shareholder Super-Majority Authorization (`POLICY_SHAREHOLDER_SUPERMAJORITY`) to `issue` MUST revert!
    let init_wrong_pol_cd = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_board_wrong_pol),
            AbiValue::Address(registry),
            AbiValue::Address(slx_constitution),
            AbiValue::Address(slx_ledger),
            AbiValue::Bytes32(POLICY_BOARD_RESOLUTION),
            AbiValue::Bytes32(h_issue_mano),
        ],
    );
    client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &init_wrong_pol_cd,
            &[auth_board_wrong_pol, registry, slx_constitution, slx_ledger],
        )
        .await
        .unwrap();
    let approve_wrong_cd = encode_values(
        "approveAuth(address)",
        &[AbiValue::Address(auth_board_wrong_pol)],
    );
    let fin_wrong_cd = encode_values(
        "finalizeAuth(address)",
        &[AbiValue::Address(auth_board_wrong_pol)],
    );
    let board_wrong_batch = vec![
        (
            manogaran_id,
            approve_wrong_cd.clone(),
            vec![auth_board_wrong_pol, registry],
        ),
        (
            evelyn_director_id,
            approve_wrong_cd,
            vec![auth_board_wrong_pol, registry],
        ),
        (
            manogaran_id,
            fin_wrong_cd,
            vec![auth_board_wrong_pol, registry],
        ),
    ];
    for r in client
        .send_call_batch(&deployer, &board_wrong_batch)
        .await
        .unwrap()
    {
        assert!(r.status);
    }
    let wrong_pol_issue_cd = encode_values(
        "issueAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Address(manogaran_id),
            AbiValue::Uint(U256::from(issue_amount)),
            AbiValue::Address(auth_board_wrong_pol),
        ],
    );
    let wrong_pol_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &wrong_pol_issue_cd,
            &[slx_ledger, auth_board_wrong_pol, registry],
        )
        .await
        .unwrap();
    assert!(
        !wrong_pol_rcpt.status,
        "Negative Test N6: Passing a Board Resolution Authorization to Shareholder-gated issue() MUST revert"
    );

    // Negative Test N7: Passing a maliciously cloned Authorization HPS with unapproved WASM `code_hash` MUST revert!
    let clone_issue_cd = encode_values(
        "issueAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Address(manogaran_id),
            AbiValue::Uint(U256::from(issue_amount)),
            AbiValue::Address(malicious_auth_clone),
        ],
    );
    let clone_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &clone_issue_cd,
            &[slx_ledger, malicious_auth_clone, registry],
        )
        .await
        .unwrap();
    assert!(
        !clone_rcpt.status,
        "Negative Test N7: Passing an unapproved-code-hash Authorization clone MUST revert"
    );
    println!(
        "[5/9] Verified Negative Tests N1..N7 (multi-Constitution init, auth overwrite, duplicate vote, under-threshold finalize, unfinalized issue, Board policy mismatch, and malicious bytecode clone rejected)"
    );

    // =========================================================================
    // STEP 6: Accumulate >= 75,000 Shareholder Votes, Finalize Authorization,
    //         and Issue 100,000 New Shares to Make Manogaran 75.00% Super-Majority!
    // =========================================================================
    // Cast the 4 lead minority shareholder votes in 1 pipelined batch:
    //   - Shareholder #2: 6,500 votes
    //   - Shareholder #3: 6,500 votes
    //   - Shareholder #4: 6,000 votes
    //   - Shareholder #5: 6,000 votes
    //   Total minority votes = 25,000 + Manogaran's 50,000 = 75,000 votes (75.00% Super-Majority!)
    let mut minority_vote_calls = Vec::with_capacity(4);
    for (sh_id, _) in cap_table.iter().skip(1).take(4) {
        minority_vote_calls.push((
            *sh_id,
            approve_stage0_cd.clone(),
            vec![auth_issue_mano, registry],
        ));
    }
    let vote_rcpts = client
        .send_call_batch(&deployer, &minority_vote_calls)
        .await
        .unwrap();
    for r in &vote_rcpts {
        assert!(r.status, "Minority shareholder vote must succeed");
        assert!(
            has_log_topic(r, "StageApproved(address,uint64,uint64,uint64)"),
            "StageApproved event must be emitted for each shareholder vote"
        );
    }
    assert!(
        has_log_topic(
            vote_rcpts.last().unwrap(),
            "StageThresholdReached(uint64,uint64,uint64)"
        ),
        "StageThresholdReached event must be emitted when 75,000-vote threshold is reached"
    );
    assert_eq!(
        read_u64(
            &client,
            auth_issue_mano,
            "stageWeight(uint64)",
            &[AbiValue::Uint(U256::from(0u64))]
        )
        .await,
        75_000
    );

    // Negative Test N8: Passing `auth_issue_mano` after 75,000 votes are reached but BEFORE calling `finalize()` MUST revert!
    let pre_finalize_issue_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &issue_via_id_cd,
            &[slx_ledger, auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(
        !pre_finalize_issue_rcpt.status,
        "Negative Test N8: Calling issue() before finalize() is called on Authorization MUST revert"
    );

    // Finalize `auth_issue_mano` -> transitions to `STATE_FINALIZED` (2)
    let fin_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &finalize_auth_cd,
            &[auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(fin_rcpt.status, "finalizeAuthorization must succeed");
    assert!(
        has_log_topic(&fin_rcpt, "AuthorizationFinalized(address,uint64)"),
        "AuthorizationFinalized event must be emitted"
    );
    assert_eq!(
        read_u64(&client, auth_issue_mano, "status()", &[]).await,
        STATE_FINALIZED
    );

    // Invoke `SLX-COMMON.issue(manogaran_id, 100_000, auth_issue_mano)`!
    let issue_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &issue_via_id_cd,
            &[slx_ledger, auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(issue_rcpt.status, "Share issuance of 100,000 shares to Manogaran must succeed");
    assert!(
        has_log_topic(
            &issue_rcpt,
            "AuthorizationConsumed(address,address,bytes32)"
        ),
        "AuthorizationConsumed event must be emitted"
    );
    assert!(
        has_log_topic(&issue_rcpt, "AssetIssued(address,uint64,uint64,address)"),
        "AssetIssued event must be emitted"
    );
    assert!(
        has_log_topic(&issue_rcpt, "Credited(address,uint64,uint64)"),
        "Credited event must be emitted"
    );
    assert!(
        has_log_topic(&issue_rcpt, "Transfer(address,address,uint64)"),
        "Transfer (mint) event must be emitted"
    );

    let new_mano_bal = read_u64(
        &client,
        slx_ledger,
        "balanceOf(address)",
        &[AbiValue::Address(manogaran_id)],
    )
    .await;
    let new_total_supply = read_u64(&client, slx_ledger, "totalOutstanding()", &[]).await;
    assert_eq!(new_mano_bal, 150_000);
    assert_eq!(new_total_supply, 200_000);
    assert_eq!(new_mano_bal * 100 / new_total_supply, 75);
    assert_eq!(
        read_u64(&client, auth_issue_mano, "status()", &[]).await,
        STATE_CONSUMED
    );
    println!(
        "[6/9] Issued 100,000 new SLX-COMMON shares to Manogaran Thanabalan -> balance = {new_mano_bal} / {new_total_supply} (75.00% Super-Majority Shareholder!)"
    );

    // =========================================================================
    // STEP 7: Negative Replay & Single-Constitution Enforcement Tests
    // =========================================================================
    // Negative Test N9: Re-passing the already-consumed `auth_issue_mano` to invoke a duplicate `issue` MUST revert!
    let replay_issue_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &issue_via_id_cd,
            &[slx_ledger, auth_issue_mano, registry],
        )
        .await
        .unwrap();
    assert!(
        !replay_issue_rcpt.status,
        "Negative Test N9: Re-using a consumed Authorization HPS for a duplicate issue() call MUST revert"
    );
    assert_eq!(
        read_u64(&client, slx_ledger, "totalOutstanding()", &[]).await,
        200_000
    );

    // Negative Test N10: Attempting to associate a second Constitution with `slx_ledger` via `setPermission` MUST revert!
    let set_rogue_con_cd = encode_values(
        "setPermission(bytes32,address,bytes32,address)",
        &[
            AbiValue::Bytes32(ACTION_ISSUE),
            AbiValue::Address(rogue_constitution),
            AbiValue::Bytes32(POLICY_SHAREHOLDER_SUPERMAJORITY),
            AbiValue::Address(auth_issue_mano),
        ],
    );
    let rogue_con_via_id = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Bytes(set_rogue_con_cd),
        ],
    );
    let rogue_con_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &rogue_con_via_id,
            &[slx_ledger, registry],
        )
        .await
        .unwrap();
    assert!(
        !rogue_con_rcpt.status,
        "Negative Test N10: Attempting to associate a second Constitution via setPermission MUST revert"
    );
    println!(
        "[7/9] Verified Negative Tests N8..N10 (pre-finalize rejection, one-time Authorization replay rejection, and Single-Constitution pinning in setPermission)"
    );

    // =========================================================================
    // STEP 8: Board of Directors Resolution (2-of-2 Directors: Manogaran + Evelyn Tan)
    //         to Transfer Company-Owned Assets in `USD-TREASURY`
    // =========================================================================
    let dividend_recipient = minority_shareholder_ids[0];
    let treasury_transfer_amt = 50_000u64;
    let h_board_tf = read_b32(
        &client,
        ext_treasury_ledger,
        "hashTransfer(address,address,uint64)",
        &[
            AbiValue::Address(superlexicon_company_id),
            AbiValue::Address(dividend_recipient),
            AbiValue::Uint(U256::from(treasury_transfer_amt)),
        ],
    )
    .await;

    let init_board_tf_cd = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_board_transfer),
            AbiValue::Address(registry),
            AbiValue::Address(slx_constitution),
            AbiValue::Address(ext_treasury_ledger),
            AbiValue::Bytes32(POLICY_BOARD_RESOLUTION),
            AbiValue::Bytes32(h_board_tf),
        ],
    );
    client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &init_board_tf_cd,
            &[
                auth_board_transfer,
                registry,
                slx_constitution,
                ext_treasury_ledger,
            ],
        )
        .await
        .unwrap();

    let approve_board_cd = encode_values(
        "approveAuth(address)",
        &[AbiValue::Address(auth_board_transfer)],
    );
    let fin_board_cd = encode_values(
        "finalizeAuth(address)",
        &[AbiValue::Address(auth_board_transfer)],
    );

    // Director #1 (Manogaran) approves -> 1 of 2 directors
    let d1_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &approve_board_cd,
            &[auth_board_transfer, registry],
        )
        .await
        .unwrap();
    assert!(d1_rcpt.status);

    // Negative Test N11: 1-of-2 Director alone cannot finalize a 2-of-2 Board Resolution!
    let d1_only_fin_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &fin_board_cd,
            &[auth_board_transfer, registry],
        )
        .await
        .unwrap();
    assert!(
        !d1_only_fin_rcpt.status,
        "Negative Test N11: 1-of-2 Director cannot finalize a 2-of-2 Board Resolution"
    );

    // Director #2 (Evelyn Tan) approves -> finalize -> `superlexicon_company_id` executes `transfer`!
    let transfer_company_asset_cd = encode_values(
        "transferAsset(address,address,address,uint64,address)",
        &[
            AbiValue::Address(ext_treasury_ledger),
            AbiValue::Address(superlexicon_company_id),
            AbiValue::Address(dividend_recipient),
            AbiValue::Uint(U256::from(treasury_transfer_amt)),
            AbiValue::Address(auth_board_transfer),
        ],
    );
    let board_exec_batch = vec![
        (
            evelyn_director_id,
            approve_board_cd,
            vec![auth_board_transfer, registry],
        ),
        (
            manogaran_id,
            fin_board_cd,
            vec![auth_board_transfer, registry],
        ),
        (
            superlexicon_company_id,
            transfer_company_asset_cd,
            vec![
                ext_treasury_ledger,
                auth_board_transfer,
                registry,
                dividend_recipient,
            ],
        ),
    ];
    let board_rcpts = client
        .send_call_batch(&deployer, &board_exec_batch)
        .await
        .unwrap();
    for r in &board_rcpts {
        assert!(r.status, "Board resolution approval, finalization, and transfer must succeed");
    }
    assert!(
        has_log_topic(&board_rcpts[2], "Transfer(address,address,uint64)"),
        "Transfer event must be emitted on USD-TREASURY ledger"
    );
    assert_eq!(
        read_u64(
            &client,
            ext_treasury_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(superlexicon_company_id)]
        )
        .await,
        200_000
    );
    assert_eq!(
        read_u64(
            &client,
            ext_treasury_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(dividend_recipient)]
        )
        .await,
        50_000
    );
    println!(
        "[8/9] Executed 2-of-2 Board of Directors Resolution (Manogaran + Evelyn Tan) transferring 50,000 USD-TREASURY owned by Superlexicon Pte. Ltd."
    );

    // =========================================================================
    // STEP 9: Add 3rd Director (`Dr. Rajesh Nair`) via Shareholder Super-Majority Resolution
    // =========================================================================
    let h_add_dir = read_b32(
        &client,
        slx_constitution,
        "hashAddDirector(address)",
        &[AbiValue::Address(third_director_id)],
    )
    .await;
    let init_add_dir_cd = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_add_director),
            AbiValue::Address(registry),
            AbiValue::Address(slx_constitution),
            AbiValue::Address(slx_constitution),
            AbiValue::Bytes32(POLICY_SUPER_GOVERNANCE),
            AbiValue::Bytes32(h_add_dir),
        ],
    );
    client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &init_add_dir_cd,
            &[auth_add_director, registry, slx_constitution],
        )
        .await
        .unwrap();

    let approve_add_dir_cd = encode_values(
        "approveAuth(address)",
        &[AbiValue::Address(auth_add_director)],
    );
    let mut add_dir_votes = Vec::with_capacity(5);
    add_dir_votes.push((
        manogaran_id,
        approve_add_dir_cd.clone(),
        vec![auth_add_director, registry],
    ));
    for (sh_id, _) in cap_table.iter().skip(1).take(4) {
        add_dir_votes.push((
            *sh_id,
            approve_add_dir_cd.clone(),
            vec![auth_add_director, registry],
        ));
    }
    for r in client
        .send_call_batch(&deployer, &add_dir_votes)
        .await
        .unwrap()
    {
        assert!(r.status);
    }

    let fin_add_dir_cd = encode_values(
        "finalizeAuth(address)",
        &[AbiValue::Address(auth_add_director)],
    );
    let exec_add_dir_cd = encode_values(
        "addDirector(address,address,address)",
        &[
            AbiValue::Address(slx_constitution),
            AbiValue::Address(third_director_id),
            AbiValue::Address(auth_add_director),
        ],
    );
    let add_dir_exec = vec![
        (
            manogaran_id,
            fin_add_dir_cd,
            vec![auth_add_director, registry],
        ),
        (
            manogaran_id,
            exec_add_dir_cd,
            vec![
                slx_constitution,
                auth_add_director,
                registry,
                third_director_id,
            ],
        ),
    ];
    let add_dir_rcpts = client
        .send_call_batch(&deployer, &add_dir_exec)
        .await
        .unwrap();
    assert!(add_dir_rcpts[0].status && add_dir_rcpts[1].status);
    assert!(
        has_log_topic(&add_dir_rcpts[1], "DirectorAdded(address,uint64,address)"),
        "DirectorAdded event must be emitted"
    );
    assert_eq!(
        read_u64(&client, slx_constitution, "directorCount()", &[]).await,
        3
    );
    println!(
        "[9/10] Appointed 3rd Director (Dr. Rajesh Nair) via Shareholder Super-Majority Resolution -> directorCount() = 3"
    );

    // =========================================================================
    // STEP 10: 3-Step Share Transfer Call-Auction (`POLICY_SHARE_TRANSFER_AUCTION`)
    //          on `SLX-COMMON` with Clearing Price Discovery & Pro-Rata Allocation
    // =========================================================================
    let init_auc_cd = encode_values(
        "initTransferAuction(address,address,address,address)",
        &[
            AbiValue::Address(auth_transfer_auction),
            AbiValue::Address(registry),
            AbiValue::Address(slx_constitution),
            AbiValue::Address(slx_ledger),
        ],
    );
    let init_auc_rcpt = client
        .send_call_with_targets(
            &deployer,
            evelyn_director_id,
            &init_auc_cd,
            &[
                auth_transfer_auction,
                registry,
                slx_constitution,
                slx_ledger,
            ],
        )
        .await
        .unwrap();
    assert!(
        init_auc_rcpt.status,
        "initializeTransferAuction must succeed"
    );

    let place_buy_cd = |price: u64, qty: u64| {
        encode_values(
            "placeBuyOrder(address,uint64,uint64)",
            &[
                AbiValue::Address(auth_transfer_auction),
                AbiValue::Uint(U256::from(price)),
                AbiValue::Uint(U256::from(qty)),
            ],
        )
    };
    let place_sell_cd = |price: u64, qty: u64| {
        encode_values(
            "placeSellOrder(address,uint64,uint64)",
            &[
                AbiValue::Address(auth_transfer_auction),
                AbiValue::Uint(U256::from(price)),
                AbiValue::Uint(U256::from(qty)),
            ],
        )
    };

    // --- Step 1 (Initial Buyers' Window: 3 blocks) ---
    // Triggered by first potential buyer (`evelyn_director_id` placing buy order for 1,400 shares @ 100),
    // followed by `third_director_id` placing a buy order for 600 shares @ 100.
    let step1_buy_batch = vec![
        (
            evelyn_director_id,
            place_buy_cd(100, 1_400),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
        (
            third_director_id,
            place_buy_cd(100, 600),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
    ];
    let step1_rcpts = client
        .send_call_batch(&deployer, &step1_buy_batch)
        .await
        .unwrap();
    assert!(step1_rcpts[0].status && step1_rcpts[1].status);
    assert!(
        has_log_topic(
            &step1_rcpts[0],
            "AuctionStep1Started(address,uint64,uint64,uint64,uint64,uint64)"
        ),
        "AuctionStep1Started event must be emitted by the first buyer"
    );
    assert!(
        has_log_topic(&step1_rcpts[0], "BuyOrderPlaced(address,uint64,uint64,uint64)"),
        "BuyOrderPlaced event must be emitted"
    );

    // Read `(step1_dl, step2_dl, step3_dl, overall_dl)`
    let dls_raw = client
        .read_call(
            None,
            auth_transfer_auction,
            &encode_values("auctionDeadlines()", &[]),
        )
        .await
        .unwrap();
    let step1_dl = u64::from_be_bytes(dls_raw[24..32].try_into().unwrap());
    let step2_dl = u64::from_be_bytes(dls_raw[56..64].try_into().unwrap());
    let step3_dl = u64::from_be_bytes(dls_raw[88..96].try_into().unwrap());

    // Negative Test N12: Existing shareholder (`manogaran_id`) attempting to place a sell order
    // during Step 1 (`now <= step1_dl`) MUST revert!
    while client.block_number().await.unwrap() < step1_dl {
        let early_sell_rcpt = client
            .send_call_with_targets(
                &deployer,
                manogaran_id,
                &place_sell_cd(100, 5_000),
                &[auth_transfer_auction, registry, slx_ledger],
            )
            .await
            .unwrap();
        assert!(
            !early_sell_rcpt.status,
            "Negative Test N12: Sell order during Step 1 MUST revert"
        );
    }

    // --- Step 2 (Existing Shareholders' Sell Window: `step1_dl < now <= step2_dl`) ---
    // Two existing shareholders place identical 5,000-share sell orders @ 100:
    //   - `manogaran_id` (existing holding = 150,000 shares)
    //   - `minority_shareholder_ids[2]` (existing holding = 6,000 shares)
    // Combined existing holding of participating sellers = 156,000 shares (25 : 1 ratio).
    let seller_2 = minority_shareholder_ids[2];
    let step2_sell_batch = vec![
        (
            manogaran_id,
            place_sell_cd(100, 5_000),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
        (
            seller_2,
            place_sell_cd(100, 5_000),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
    ];
    let step2_rcpts = client
        .send_call_batch(&deployer, &step2_sell_batch)
        .await
        .unwrap();
    assert!(step2_rcpts[0].status && step2_rcpts[1].status);
    assert!(
        has_log_topic(
            &step2_rcpts[0],
            "SellOrderPlaced(address,uint64,uint64,uint64)"
        ),
        "SellOrderPlaced event must be emitted"
    );

    // Negative Test N13: Placing a buy order during Step 2 (`step1_dl < now <= step2_dl`) MUST revert!
    while client.block_number().await.unwrap() < step2_dl {
        let step2_buy_rcpt = client
            .send_call_with_targets(
                &deployer,
                evelyn_director_id,
                &place_buy_cd(100, 500),
                &[auth_transfer_auction, registry, slx_ledger],
            )
            .await
            .unwrap();
        assert!(
            !step2_buy_rcpt.status,
            "Negative Test N13: Buy order during Step 2 MUST revert"
        );
    }

    // --- Step 3 (Non-Participating Existing Shareholders' Buy Window: `step2_dl < now <= step3_dl`) ---
    // Negative Test N14: `manogaran_id` participated as a seller in Step 2 -> ineligible to place a buy order in Step 3!
    // Positive Step 3 Buy Order: `minority_shareholder_ids[0]` (holding 6,500 shares, did NOT sell in Step 2)
    // places a buy order for 600 shares @ 100 (bringing total buying quantity to 1,400 + 600 + 600 = 2,600 shares).
    let step3_buyer = minority_shareholder_ids[0];
    let step3_batch = vec![
        (
            manogaran_id,
            place_buy_cd(100, 500),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
        (
            step3_buyer,
            place_buy_cd(100, 600),
            vec![auth_transfer_auction, registry, slx_ledger],
        ),
    ];
    let step3_rcpts = client
        .send_call_batch(&deployer, &step3_batch)
        .await
        .unwrap();
    assert!(
        !step3_rcpts[0].status,
        "Negative Test N14: Step 2 seller attempting to buy in Step 3 MUST revert"
    );
    assert!(
        step3_rcpts[1].status,
        "Non-participating existing shareholder buy order in Step 3 must succeed"
    );

    // Negative Test N15: Attempting to settle the auction on `SLX-COMMON` before Step 3 ends (`now <= step3_dl`) MUST revert!
    let settle_via_transfer_cd = encode_values(
        "transferAsset(address,address,address,uint64,address)",
        &[
            AbiValue::Address(slx_ledger),
            AbiValue::Address(H160::zero()),
            AbiValue::Address(H160::zero()),
            AbiValue::Uint(U256::from(0u64)),
            AbiValue::Address(auth_transfer_auction),
        ],
    );
    let settle_targets = vec![
        slx_ledger,
        auth_transfer_auction,
        registry,
        manogaran_id,
        seller_2,
        evelyn_director_id,
        third_director_id,
        step3_buyer,
    ];
    while client.block_number().await.unwrap() < step3_dl {
        let early_settle_rcpt = client
            .send_call_with_targets(
                &deployer,
                manogaran_id,
                &settle_via_transfer_cd,
                &settle_targets,
            )
            .await
            .unwrap();
        assert!(
            !early_settle_rcpt.status,
            "Negative Test N15: Settling auction before Step 3 period ends MUST revert"
        );
    }

    // --- Step 4 (After Step 3 Ends: `now > step3_dl`): Finalize & Settle in `SLX-COMMON.transfer` ---
    let settle_rcpt = client
        .send_call_with_targets(
            &deployer,
            manogaran_id,
            &settle_via_transfer_cd,
            &settle_targets,
        )
        .await
        .unwrap();
    assert!(
        settle_rcpt.status,
        "Post-Step-3 Share Transfer Auction settlement via SLX-COMMON.transfer must succeed"
    );
    assert!(
        has_log_topic(
            &settle_rcpt,
            "AuctionTransferSettled(address,uint64,uint64,uint64,uint64,uint64,uint64)"
        ),
        "AuctionTransferSettled event must be emitted"
    );
    assert!(
        has_log_topic(
            &settle_rcpt,
            "AuctionSellerFilled(address,uint64,uint64,uint64,uint64)"
        ),
        "AuctionSellerFilled event must be emitted"
    );
    assert!(
        has_log_topic(
            &settle_rcpt,
            "AuctionBuyerFilled(address,uint64,uint64,uint64)"
        ),
        "AuctionBuyerFilled event must be emitted"
    );

    // Verify post-auction balances:
    // Total buying quantity (2,600) < Total selling quantity (10,000) at clearing price 100:
    // - All 3 buyers fill 100%:
    //   * `evelyn_director_id`: 0 -> 1,400
    //   * `third_director_id`: 0 -> 600
    //   * `step3_buyer` (`minority_shareholder_ids[0]`): 6,500 -> 7,100
    // - Both sellers are filled pro-rata to their EXISTING SHAREHOLDING (150,000 : 6,000 = 25 : 1),
    //   NOT their equal 5,000 order quantities:
    //   * `manogaran_id` sells 2,500 shares (150,000 -> 147,500)
    //   * `seller_2` (`minority_shareholder_ids[2]`) sells 100 shares (6,000 -> 5,900)
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(evelyn_director_id)]
        )
        .await,
        1_400
    );
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(third_director_id)]
        )
        .await,
        600
    );
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(step3_buyer)]
        )
        .await,
        7_100
    );
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(manogaran_id)]
        )
        .await,
        147_500
    );
    assert_eq!(
        read_u64(
            &client,
            slx_ledger,
            "balanceOf(address)",
            &[AbiValue::Address(seller_2)]
        )
        .await,
        5_900
    );
    assert_eq!(
        read_u64(&client, slx_ledger, "totalOutstanding()", &[]).await,
        200_000
    );
    println!(
        "[10/10] Settled 3-Step Call-Auction on SLX-COMMON at price=100, matched=2,600 shares (pro-rated sellers by existing holdings 150,000:6,000 -> Manogaran -2,500, Shareholder#4 -100; buyers +1,400/+600/+600). All 10 steps & 15 negative security tests passed!"
    );
}
