//! Full end-to-end live Wasmtime integration test against `lexicon-node --localtestnet`
//! exercising the complete institutional Haltproof Subroutine (HPS) stack:
//!
//! 1. `Identity` (`examples/identity`) — verified on-chain identity accounts controlled by distinct EOAs
//! 2. `IdentityRegistry` (`examples/identity-registry`) — verified identity register gated by one-time oracle `Authorization`
//! 3. `Constitution` (`examples/constitution`) — institutional policies/bylaws supporting sequential stages + weighted thresholds + block expiry
//! 4. `Authorization` (`examples/authorization`) — per-invocation stateful process engine with strict stage order, weights, block-height expiry, finalization, and one-time consumption
//! 5. `AssetLedger` (`examples/asset-ledger`) — verified-identity ownership map, private `debit`/`credit`, `issue`/`cancel`/`transfer`/`approve`/`transferFrom`, genesis state, and `SUPER`-gated permission updates
//! 6. `AssetPair_OTC` (`examples/asset-pair-otc`) — verified-identity atomic Delivery-vs-Payment OTC settlement
//!
//! Run with:
//! ```bash
//! cargo test -p hps-client --test live_governance_e2e -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ethereum_types::{H160, U256};
use hps_client::abi::{encode_values, try_decode_u256, AbiValue};
use hps_client::{HpsClient, HpsSigner, DEFAULT_CHAIN_ID, DEFAULT_DEV_PRIVATE_KEY};
use hps_sdk::governance::{
    PolicySpec, StageSpec, ACTION_APPROVE, ACTION_CANCEL, ACTION_ISSUE, ACTION_SUPER,
    ACTION_TRANSFER, POLICY_HOLDER_SELF, POLICY_SUPER_GOVERNANCE,
};

const TEST_RPC_PORT: u16 = 18555;
const TEST_WS_PORT: u16 = 18556;
const TEST_HTTP_PORT: u16 = 18080;
const TEST_P2P_PORT: u16 = 40303;

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
    let temp_dir = std::env::temp_dir().join(format!("hps-gov-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let db_path = temp_dir.join("localtestnet.db");
    let log_path = temp_dir.join("node.log");
    let cfg_path = temp_dir.join("local-config.json");

    let cfg_json = serde_json::json!({
        "app_name": "HPS-Gov-E2E",
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
                "port": 18547,
                "playground": false,
                "max_complexity": 100,
                "max_depth": 15
            },
            "grpc": {
                "enabled": false,
                "host": "127.0.0.1",
                "port": 58051,
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
            "block_gas_limit": 200000000,
            "max_transaction_gas_limit": 25000000,
            "max_bytecode_size": 100000,
            "max_constructor_args_size": 32768,
            "max_nonce_gap": 64,
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
async fn full_institutional_governance_ledger_and_otc_on_localtestnet() {
    let _node = spawn_isolated_localtestnet();
    let rpc_url = format!("http://127.0.0.1:{TEST_RPC_PORT}");
    let client = HpsClient::new(&rpc_url);

    // Wait for JSON-RPC to come up
    for _ in 0..40 {
        if client.block_number().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let start_height = client.block_number().await.expect("localtestnet RPC reachable");
    println!("[1/10] Isolated lexicon-node --localtestnet online at {rpc_url} (block #{start_height})");

    // Load compiled WASM artifacts from dist/
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
    let otc_wasm =
        std::fs::read(dist.join("asset_pair_otc.wasm")).expect("dist/asset_pair_otc.wasm");
    let messaging_wasm =
        std::fs::read(dist.join("messaging.wasm")).expect("dist/messaging.wasm");

    // Deployer + 9 distinct EOAs controlling 9 distinct Identity HPS instances
    let mut deployer = HpsSigner::from_hex(DEFAULT_DEV_PRIVATE_KEY, DEFAULT_CHAIN_ID).unwrap();
    deployer.default_gas_limit = U256::from(12_000_000u64);

    let mk_signer = || {
        let (_pk, mut s) = HpsSigner::generate_random(DEFAULT_CHAIN_ID);
        s.default_gas_limit = U256::from(12_000_000u64);
        s
    };
    let admin_eoa = mk_signer();
    let group_a_eoa = mk_signer();
    let group_b_lead_eoa = mk_signer();
    let group_b_officer_eoa = mk_signer();
    let super1_eoa = mk_signer();
    let super2_eoa = mk_signer();
    let seller_eoa = mk_signer();
    let buyer_eoa = mk_signer();
    let new_member_eoa = mk_signer();

    // Store shared bytecodes once, then batch-instantiate all 9 Identity HPS contracts + 8 one-time Authorization HPS contracts!
    let id_code = client.store_bytecode(&deployer, &identity_wasm).await.unwrap();
    let auth_code = client.store_bytecode(&deployer, &auth_wasm).await.unwrap();
    let ledger_code = client.store_bytecode(&deployer, &ledger_wasm).await.unwrap();

    let id_specs: Vec<_> = (0..9).map(|_| (id_code, Vec::new())).collect();
    let ids = client.instantiate_batch(&deployer, &id_specs).await.unwrap();
    let (
        admin_id,
        group_a_id,
        group_b_lead_id,
        group_b_officer_id,
        super1_id,
        super2_id,
        seller_id,
        buyer_id,
        new_member_id,
    ) = (
        ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], ids[8],
    );

    // Initialize all 9 Identity HPS contracts in 1 pipelined block!
    let base_nonce = client.get_nonce(deployer.address()).await.unwrap();
    let id_owners = [
        (admin_id, admin_eoa.address(), "AdminOracle"),
        (group_a_id, group_a_eoa.address(), "GroupA_Officer"),
        (group_b_lead_id, group_b_lead_eoa.address(), "GroupB_Lead"),
        (group_b_officer_id, group_b_officer_eoa.address(), "GroupB_Officer"),
        (super1_id, super1_eoa.address(), "SuperBoard_1"),
        (super2_id, super2_eoa.address(), "SuperBoard_2"),
        (seller_id, seller_eoa.address(), "SellerVault"),
        (buyer_id, buyer_eoa.address(), "BuyerVault"),
        (new_member_id, new_member_eoa.address(), "NewMemberVault"),
    ];
    let mut init_id_hashes = Vec::new();
    for (idx, (id_hps, owner_addr, handle)) in id_owners.iter().enumerate() {
        let cd = encode_values(
            "initialize(address,string)",
            &[
                AbiValue::Address(*owner_addr),
                AbiValue::Bytes(handle.as_bytes().to_vec()),
            ],
        );
        let raw = deployer
            .build_call_tx(base_nonce + idx as u64, *id_hps, &cd)
            .unwrap();
        init_id_hashes.push(client.send_raw_transaction(&raw).await.unwrap());
    }
    for h in init_id_hashes {
        assert!(client.wait_for_receipt(&h).await.unwrap().status, "Identity.initialize failed");
    }
    println!("[2/10] Instantiated & initialized 9 Identity HPS contracts (Admin={admin_id:?}, Seller={seller_id:?}, Buyer={buyer_id:?})");

    // Batch-instantiate 9 fresh one-time Authorization HPS instances up front for all test phases
    let auth_specs: Vec<_> = (0..9).map(|_| (auth_code, Vec::new())).collect();
    let auths = client.instantiate_batch(&deployer, &auth_specs).await.unwrap();
    let (
        auth_reg_new_member,
        auth_issue_gold,
        auth_expired,
        auth_cancel_gold,
        auth_transfer_gold,
        auth_super_perm,
        auth_super_const,
        auth_approve_gold,
        auth_approve_usd,
    ) = (
        auths[0], auths[1], auths[2], auths[3], auths[4], auths[5], auths[6], auths[7], auths[8],
    );

    // -------------------------------------------------------------------------
    // STEP 3: Deploy & initialize IdentityRegistry with canonical WASM code_hashes
    // -------------------------------------------------------------------------
    let reg_rcpt = client.deploy_hps(&deployer, &registry_wasm, &[]).await.unwrap();
    let registry_hps: H160 = reg_rcpt.hps_address.parse().unwrap();

    // Deploy an unapproved subroutine (`messaging.wasm`) to simulate a malicious Identity / Authorization clone!
    let clone_rcpt = client.deploy_hps(&deployer, &messaging_wasm, &[]).await.unwrap();
    let malicious_clone_hps: H160 = clone_rcpt.hps_address.parse().unwrap();

    let mut initial_valid = Vec::new();
    for valid_id in [
        admin_id,
        group_a_id,
        group_b_lead_id,
        group_b_officer_id,
        super1_id,
        super2_id,
        seller_id,
        buyer_id,
    ] {
        initial_valid.extend_from_slice(valid_id.as_bytes());
    }
    let init_reg_cd = encode_values(
        "initialize(address,bytes32,bytes32,bytes)",
        &[
            AbiValue::Address(admin_id),
            AbiValue::Bytes32(*id_code.as_fixed_bytes()),
            AbiValue::Bytes32(*auth_code.as_fixed_bytes()),
            AbiValue::Bytes(initial_valid),
        ],
    );
    let rcpt = client.send_call(&deployer, registry_hps, &init_reg_cd).await.unwrap();
    assert!(rcpt.status, "IdentityRegistry.initialize failed");
    assert_eq!(
        read_u64(&client, registry_hps, "isValidIdentity(address)", &[AbiValue::Address(seller_id)]).await,
        1
    );
    assert_eq!(
        read_u64(&client, registry_hps, "isValidIdentity(address)", &[AbiValue::Address(new_member_id)]).await,
        0
    );
    assert_eq!(
        read_u64(&client, registry_hps, "isValidAuthorizationHps(address)", &[AbiValue::Address(auth_reg_new_member)]).await,
        1
    );
    assert_eq!(
        read_u64(&client, registry_hps, "isValidAuthorizationHps(address)", &[AbiValue::Address(malicious_clone_hps)]).await,
        0
    );

    // 3a. Attempting to register a malicious Identity clone OR a raw EOA MUST revert on-chain!
    let bad_clone_reg_inner = encode_values(
        "registerIdentity(address,address)",
        &[AbiValue::Address(malicious_clone_hps), AbiValue::Address(auth_reg_new_member)],
    );
    let bad_clone_rcpt = client
        .send_call(
            &admin_eoa,
            admin_id,
            &encode_values(
                "execute(address,bytes)",
                &[AbiValue::Address(registry_hps), AbiValue::Bytes(bad_clone_reg_inner)],
            ),
        )
        .await
        .unwrap();
    assert!(!bad_clone_rcpt.status, "registering a malicious Identity clone MUST revert!");

    let bad_eoa_reg_inner = encode_values(
        "registerIdentity(address,address)",
        &[AbiValue::Address(new_member_eoa.address()), AbiValue::Address(auth_reg_new_member)],
    );
    let bad_eoa_rcpt = client
        .send_call(
            &admin_eoa,
            admin_id,
            &encode_values(
                "execute(address,bytes)",
                &[AbiValue::Address(registry_hps), AbiValue::Bytes(bad_eoa_reg_inner)],
            ),
        )
        .await
        .unwrap();
    assert!(!bad_eoa_rcpt.status, "registering a raw EOA MUST revert!");

    // 3b. Register canonical NewMemberId via AdminId + single-account oracle Authorization (one-time use!)
    let reg_action_hash = read_b32(
        &client,
        registry_hps,
        "hashRegisterIdentity(address)",
        &[AbiValue::Address(new_member_id)],
    )
    .await;

    let init_oracle_cd = encode_values(
        "initOracleAuth(address,address,address,address,bytes32,uint64)",
        &[
            AbiValue::Address(auth_reg_new_member),
            AbiValue::Address(registry_hps),
            AbiValue::Address(admin_id),
            AbiValue::Address(registry_hps),
            AbiValue::Bytes32(reg_action_hash),
            AbiValue::Uint(U256::from(30u64)),
        ],
    );
    assert!(
        client.send_call(&admin_eoa, admin_id, &init_oracle_cd).await.unwrap().status,
        "AdminId.initOracleAuth failed"
    );
    let fin_oracle_cd = encode_values(
        "approveAndFinalizeAuth(address)",
        &[AbiValue::Address(auth_reg_new_member)],
    );
    assert!(
        client.send_call(&admin_eoa, admin_id, &fin_oracle_cd).await.unwrap().status,
        "AdminId.approveAndFinalizeAuth failed"
    );
    assert_eq!(read_u64(&client, auth_reg_new_member, "isReadyToConsume()", &[]).await, 1);

    let reg_inner = encode_values(
        "registerIdentity(address,address)",
        &[AbiValue::Address(new_member_id), AbiValue::Address(auth_reg_new_member)],
    );
    let exec_reg = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(registry_hps), AbiValue::Bytes(reg_inner.clone())],
    );
    assert!(
        client.send_call(&admin_eoa, admin_id, &exec_reg).await.unwrap().status,
        "IdentityRegistry.registerIdentity failed"
    );
    assert_eq!(
        read_u64(&client, registry_hps, "isValidIdentity(address)", &[AbiValue::Address(new_member_id)]).await,
        1
    );
    assert_eq!(read_u64(&client, auth_reg_new_member, "status()", &[]).await, 4); // STATE_CONSUMED

    // Replay of consumed `auth_reg_new_member` MUST revert!
    let replay_rcpt = client.send_call(&admin_eoa, admin_id, &exec_reg).await.unwrap();
    assert!(!replay_rcpt.status, "replaying one-time Authorization MUST revert");
    println!("[3/10] IdentityRegistry verified: NewMemberId registered via Admin oracle Auth & replay rejected");

    // -------------------------------------------------------------------------
    // STEP 4: Deploy & initialize Constitution with sequential + weighted policies
    // -------------------------------------------------------------------------
    let const_rcpt = client.deploy_hps(&deployer, &constitution_wasm, &[]).await.unwrap();
    let constitution_hps: H160 = const_rcpt.hps_address.parse().unwrap();

    // 1. POLICY_SUPER_GOVERNANCE: Joint weighted (SuperBoard1 w=2 + SuperBoard2 w=1, required=3, expiry=30 blocks)
    let super_stage = StageSpec::new(3, 30)
        .add_member(h160_bytes(super1_id), 2)
        .unwrap()
        .add_member(h160_bytes(super2_id), 1)
        .unwrap();
    let super_spec = PolicySpec::new(30).add_stage(super_stage).unwrap();

    // 2. ACTION_ISSUE: Strict 2-stage sequential + weighted process:
    //    Stage 0 (Group A): GroupA_Officer (w=1), required_weight=1, stage_expiry=20 blocks
    //    Stage 1 (Group B): GroupB_Lead (w=2) + GroupB_Officer (w=1), required_weight=3, stage_expiry=20 blocks
    let st0 = StageSpec::new(1, 20)
        .add_member(h160_bytes(group_a_id), 1)
        .unwrap();
    let st1 = StageSpec::new(3, 20)
        .add_member(h160_bytes(group_b_lead_id), 2)
        .unwrap()
        .add_member(h160_bytes(group_b_officer_id), 1)
        .unwrap();
    let issue_spec = PolicySpec::new(40).add_stage(st0).unwrap().add_stage(st1).unwrap();

    // 3. ACTION_CANCEL: 2-stage sequential process:
    //    Stage 0: GroupA_Officer (w=1, req=1) -> Stage 1: GroupB_Lead (w=2, req=2)
    let cst0 = StageSpec::new(1, 20)
        .add_member(h160_bytes(group_a_id), 1)
        .unwrap();
    let cst1 = StageSpec::new(2, 20)
        .add_member(h160_bytes(group_b_lead_id), 2)
        .unwrap();
    let cancel_spec = PolicySpec::new(40).add_stage(cst0).unwrap().add_stage(cst1).unwrap();

    let mut genesis_policies = Vec::new();
    genesis_policies.extend_from_slice(&3u16.to_be_bytes());
    genesis_policies.extend_from_slice(&encode_constitution_entry(H160::zero(), POLICY_SUPER_GOVERNANCE, &super_spec));
    genesis_policies.extend_from_slice(&encode_constitution_entry(H160::zero(), ACTION_ISSUE, &issue_spec));
    genesis_policies.extend_from_slice(&encode_constitution_entry(H160::zero(), ACTION_CANCEL, &cancel_spec));

    let init_const_inner = encode_values(
        "initialize(address,bytes)",
        &[AbiValue::Address(registry_hps), AbiValue::Bytes(genesis_policies)],
    );
    let exec_init_const = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(constitution_hps), AbiValue::Bytes(init_const_inner)],
    );
    assert!(
        client.send_call(&super1_eoa, super1_id, &exec_init_const).await.unwrap().status,
        "Constitution.initialize via SuperBoard1_Id failed"
    );
    assert_eq!(
        read_u64(
            &client,
            constitution_hps,
            "hasPolicy(address,bytes32)",
            &[AbiValue::Address(H160::zero()), AbiValue::Bytes32(ACTION_ISSUE)]
        )
        .await,
        1
    );
    println!("[4/10] Constitution initialized with SUPER_GOVERNANCE, 2-stage weighted ACTION_ISSUE, and 2-stage ACTION_CANCEL");

    // -------------------------------------------------------------------------
    // STEP 5: Instantiate & initialize GOLD and USD AssetLedgers with genesis balances & permissions
    // -------------------------------------------------------------------------
    let ledgers = client
        .instantiate_batch(&deployer, &[(ledger_code, Vec::new()), (ledger_code, Vec::new())])
        .await
        .unwrap();
    let (gold_ledger, usd_ledger) = (ledgers[0], ledgers[1]);

    let mut perms_blob = Vec::new();
    perms_blob.extend_from_slice(&pack_permission(ACTION_SUPER, constitution_hps, POLICY_SUPER_GOVERNANCE));
    perms_blob.extend_from_slice(&pack_permission(ACTION_ISSUE, constitution_hps, ACTION_ISSUE));
    perms_blob.extend_from_slice(&pack_permission(ACTION_CANCEL, constitution_hps, ACTION_CANCEL));
    perms_blob.extend_from_slice(&pack_permission(ACTION_TRANSFER, H160::zero(), POLICY_HOLDER_SELF));
    perms_blob.extend_from_slice(&pack_permission(ACTION_APPROVE, H160::zero(), POLICY_HOLDER_SELF));

    // GOLD genesis: SellerId = 1,000, BuyerId = 100 (total = 1,100)
    let mut gold_alloc = Vec::new();
    gold_alloc.extend_from_slice(seller_id.as_bytes());
    gold_alloc.extend_from_slice(&1_000u64.to_be_bytes());
    gold_alloc.extend_from_slice(buyer_id.as_bytes());
    gold_alloc.extend_from_slice(&100u64.to_be_bytes());

    let init_gold_inner = encode_values(
        "initialize(address,string,uint64,bytes,bytes)",
        &[
            AbiValue::Address(registry_hps),
            AbiValue::Bytes(b"GOLD".to_vec()),
            AbiValue::Uint(U256::from(2u64)),
            AbiValue::Bytes(gold_alloc),
            AbiValue::Bytes(perms_blob.clone()),
        ],
    );
    let exec_init_gold = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(gold_ledger), AbiValue::Bytes(init_gold_inner)],
    );
    assert!(client.send_call(&seller_eoa, seller_id, &exec_init_gold).await.unwrap().status);

    // USD genesis: BuyerId = 50,000, SellerId = 5,000 (total = 55,000)
    let mut usd_alloc = Vec::new();
    usd_alloc.extend_from_slice(buyer_id.as_bytes());
    usd_alloc.extend_from_slice(&50_000u64.to_be_bytes());
    usd_alloc.extend_from_slice(seller_id.as_bytes());
    usd_alloc.extend_from_slice(&5_000u64.to_be_bytes());

    let init_usd_inner = encode_values(
        "initialize(address,string,uint64,bytes,bytes)",
        &[
            AbiValue::Address(registry_hps),
            AbiValue::Bytes(b"USD".to_vec()),
            AbiValue::Uint(U256::from(2u64)),
            AbiValue::Bytes(usd_alloc),
            AbiValue::Bytes(perms_blob),
        ],
    );
    let exec_init_usd = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(usd_ledger), AbiValue::Bytes(init_usd_inner)],
    );
    assert!(client.send_call(&seller_eoa, seller_id, &exec_init_usd).await.unwrap().status);

    assert_eq!(read_u64(&client, gold_ledger, "totalOutstanding()", &[]).await, 1_100);
    assert_eq!(read_u64(&client, usd_ledger, "totalOutstanding()", &[]).await, 55_000);
    println!("[5/10] GOLD (supply=1100) & USD (supply=55000) AssetLedgers initialized with verified allocations & permissions");

    // -------------------------------------------------------------------------
    // STEP 6: Sequential + Weighted Issuance Process (including out-of-order rejection!)
    // -------------------------------------------------------------------------
    let issue_hash = read_b32(
        &client,
        gold_ledger,
        "hashIssue(address,uint64)",
        &[AbiValue::Address(new_member_id), AbiValue::Uint(U256::from(500u64))],
    )
    .await;

    let init_issue_auth = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_issue_gold),
            AbiValue::Address(registry_hps),
            AbiValue::Address(constitution_hps),
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(ACTION_ISSUE),
            AbiValue::Bytes32(issue_hash),
        ],
    );
    assert!(client.send_call(&group_a_eoa, group_a_id, &init_issue_auth).await.unwrap().status);

    // 6a. Out-of-order check: Group B Lead tries to approve BEFORE Group A completes Stage 0 -> MUST REVERT!
    let approve_auth_cd = encode_values("approveAuth(address)", &[AbiValue::Address(auth_issue_gold)]);
    let early_b = client
        .send_call(&group_b_lead_eoa, group_b_lead_id, &approve_auth_cd)
        .await
        .unwrap();
    assert!(!early_b.status, "Group B approval before Stage 0 (Group A) MUST revert!");
    assert_eq!(read_u64(&client, auth_issue_gold, "currentStage()", &[]).await, 0);

    // 6b. Stage 0: Group A Officer approves (weight 1/1 -> advances to Stage 1!)
    assert!(client.send_call(&group_a_eoa, group_a_id, &approve_auth_cd).await.unwrap().status);
    assert_eq!(read_u64(&client, auth_issue_gold, "currentStage()", &[]).await, 1);

    // 6c. Stage 1: Group B Lead approves (weight 2/3 -> still at Stage 1, cannot finalize yet!)
    assert!(
        client
            .send_call(&group_b_lead_eoa, group_b_lead_id, &approve_auth_cd)
            .await
            .unwrap()
            .status
    );
    assert_eq!(
        read_u64(&client, auth_issue_gold, "stageWeight(uint64)", &[AbiValue::Uint(U256::from(1u64))]).await,
        2
    );
    let premature_fin = encode_values("finalizeAuth(address)", &[AbiValue::Address(auth_issue_gold)]);
    assert!(
        !client.send_call(&group_b_lead_eoa, group_b_lead_id, &premature_fin).await.unwrap().status,
        "premature finalize at weight 2/3 MUST revert"
    );

    // 6d. Stage 1 completion + finalization: Group B Officer (weight 1 -> total 3/3) approves & finalizes!
    let approve_and_fin = encode_values(
        "approveAndFinalizeAuth(address)",
        &[AbiValue::Address(auth_issue_gold)],
    );
    assert!(
        client
            .send_call(&group_b_officer_eoa, group_b_officer_id, &approve_and_fin)
            .await
            .unwrap()
            .status
    );
    assert_eq!(read_u64(&client, auth_issue_gold, "isReadyToConsume()", &[]).await, 1);

    // 6e. Passing a spoofed Authorization clone (`malicious_clone_hps`) MUST revert on-chain!
    let spoofed_issue_cd = encode_values(
        "issueAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Address(new_member_id),
            AbiValue::Uint(U256::from(500u64)),
            AbiValue::Address(malicious_clone_hps),
        ],
    );
    assert!(
        !client.send_call(&seller_eoa, seller_id, &spoofed_issue_cd).await.unwrap().status,
        "passing spoofed Authorization clone to AssetLedger.issue MUST revert!"
    );

    // 6f. Execute `GOLD.issue(NewMemberId, 500, auth_issue_gold)` via `SellerId.issueAsset(...)`
    let issue_cd = encode_values(
        "issueAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Address(new_member_id),
            AbiValue::Uint(U256::from(500u64)),
            AbiValue::Address(auth_issue_gold),
        ],
    );
    assert!(client.send_call(&seller_eoa, seller_id, &issue_cd).await.unwrap().status);
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(new_member_id)]).await,
        500
    );
    assert_eq!(read_u64(&client, gold_ledger, "totalOutstanding()", &[]).await, 1_600);

    // Replaying `auth_issue_gold` MUST revert!
    assert!(!client.send_call(&seller_eoa, seller_id, &issue_cd).await.unwrap().status);
    println!("[6/10] 2-stage sequential + weighted GOLD issuance (+500 -> supply=1600) succeeded; spoofed Auth clone, out-of-order & replay rejected");

    // -------------------------------------------------------------------------
    // STEP 7: Block-Height Expiry Enforcement on `Authorization`
    // -------------------------------------------------------------------------
    let short_stage = StageSpec::new(1, 1)
        .add_member(h160_bytes(group_a_id), 1)
        .unwrap();
    let short_spec = PolicySpec::new(1).add_stage(short_stage).unwrap(); // expires 1 block after initialization!
    let mut short_buf = [0u8; 256];
    let short_n = short_spec.encode(&mut short_buf).unwrap();

    let init_exp_inner = encode_values(
        "initializeCustom(address,address,bytes32,bytes32,bytes)",
        &[
            AbiValue::Address(registry_hps),
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(ACTION_ISSUE),
            AbiValue::Bytes32(issue_hash),
            AbiValue::Bytes(short_buf[..short_n].to_vec()),
        ],
    );
    let exec_init_exp = encode_values(
        "execute(address,bytes)",
        &[AbiValue::Address(auth_expired), AbiValue::Bytes(init_exp_inner)],
    );
    let init_exp_rcpt = client.send_call(&group_a_eoa, group_a_id, &exec_init_exp).await.unwrap();
    assert!(init_exp_rcpt.status);
    let target_height = init_exp_rcpt.block_number + 2;
    while client.block_number().await.unwrap() < target_height {
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let approve_exp_cd = encode_values(
        "approveAndFinalizeAuth(address)",
        &[AbiValue::Address(auth_expired)],
    );
    let exp_rcpt = client.send_call(&group_a_eoa, group_a_id, &approve_exp_cd).await.unwrap();
    assert!(!exp_rcpt.status, "approving an expired Authorization MUST revert!");
    println!("[7/10] Block-height expiry verified: approval past block deadline deterministically rejected");

    // -------------------------------------------------------------------------
    // STEP 8: `cancel` (2-stage) & `transfer` (holder one-time Authorization)
    // -------------------------------------------------------------------------
    let cancel_hash = read_b32(
        &client,
        gold_ledger,
        "hashCancel(address,uint64)",
        &[AbiValue::Address(new_member_id), AbiValue::Uint(U256::from(200u64))],
    )
    .await;
    let init_cancel_auth = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_cancel_gold),
            AbiValue::Address(registry_hps),
            AbiValue::Address(constitution_hps),
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(ACTION_CANCEL),
            AbiValue::Bytes32(cancel_hash),
        ],
    );
    assert!(client.send_call(&group_a_eoa, group_a_id, &init_cancel_auth).await.unwrap().status);
    assert!(
        client
            .send_call(
                &group_a_eoa,
                group_a_id,
                &encode_values("approveAuth(address)", &[AbiValue::Address(auth_cancel_gold)])
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &group_b_lead_eoa,
                group_b_lead_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_cancel_gold)])
            )
            .await
            .unwrap()
            .status
    );
    let cancel_cd = encode_values(
        "cancelAsset(address,address,uint64,address)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Address(new_member_id),
            AbiValue::Uint(U256::from(200u64)),
            AbiValue::Address(auth_cancel_gold),
        ],
    );
    assert!(client.send_call(&seller_eoa, seller_id, &cancel_cd).await.unwrap().status);
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(new_member_id)]).await,
        300
    );
    assert_eq!(read_u64(&client, gold_ledger, "totalOutstanding()", &[]).await, 1_400);

    // Holder-authorized `transfer`: NewMemberId transfers 125 GOLD -> BuyerId
    let transfer_hash = read_b32(
        &client,
        gold_ledger,
        "hashTransfer(address,address,uint64)",
        &[
            AbiValue::Address(new_member_id),
            AbiValue::Address(buyer_id),
            AbiValue::Uint(U256::from(125u64)),
        ],
    )
    .await;
    let init_xfer_auth = encode_values(
        "initOracleAuth(address,address,address,address,bytes32,uint64)",
        &[
            AbiValue::Address(auth_transfer_gold),
            AbiValue::Address(registry_hps),
            AbiValue::Address(new_member_id),
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(transfer_hash),
            AbiValue::Uint(U256::from(30u64)),
        ],
    );
    assert!(client.send_call(&new_member_eoa, new_member_id, &init_xfer_auth).await.unwrap().status);
    assert!(
        client
            .send_call(
                &new_member_eoa,
                new_member_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_transfer_gold)])
            )
            .await
            .unwrap()
            .status
    );
    let xfer_cd = encode_values(
        "transferAsset(address,address,address,uint64,address)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Address(new_member_id),
            AbiValue::Address(buyer_id),
            AbiValue::Uint(U256::from(125u64)),
            AbiValue::Address(auth_transfer_gold),
        ],
    );
    assert!(client.send_call(&new_member_eoa, new_member_id, &xfer_cd).await.unwrap().status);
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(new_member_id)]).await,
        175
    );
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(buyer_id)]).await,
        225
    );
    println!("[8/10] GOLD cancel (-200 -> supply=1400) and verified-identity transfer (125 GOLD -> Buyer=225) succeeded");

    // -------------------------------------------------------------------------
    // STEP 9: SUPER Governance — amending Constitution policy & rotating AssetLedger permission
    // -------------------------------------------------------------------------
    let new_policy_id = [0x77u8; 32];
    let cc_stage = StageSpec::new(2, 30)
        .add_member(h160_bytes(group_b_lead_id), 2)
        .unwrap();
    let custom_cancel_spec = PolicySpec::new(30).add_stage(cc_stage).unwrap();
    let mut cc_buf = [0u8; 256];
    let cc_len = custom_cancel_spec.encode(&mut cc_buf).unwrap();

    // 9a. Amend Constitution via joint weighted SUPER_GOVERNANCE (SuperBoard1 w=2 + SuperBoard2 w=1 = 3)
    let set_pol_hash = read_b32(
        &client,
        constitution_hps,
        "hashSetPolicy(address,bytes32,bytes)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(new_policy_id),
            AbiValue::Bytes(cc_buf[..cc_len].to_vec()),
        ],
    )
    .await;
    let init_super_const = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_super_const),
            AbiValue::Address(registry_hps),
            AbiValue::Address(constitution_hps),
            AbiValue::Address(constitution_hps),
            AbiValue::Bytes32(POLICY_SUPER_GOVERNANCE),
            AbiValue::Bytes32(set_pol_hash),
        ],
    );
    assert!(client.send_call(&super1_eoa, super1_id, &init_super_const).await.unwrap().status);
    assert!(
        client
            .send_call(
                &super1_eoa,
                super1_id,
                &encode_values("approveAuth(address)", &[AbiValue::Address(auth_super_const)])
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &super2_eoa,
                super2_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_super_const)])
            )
            .await
            .unwrap()
            .status
    );
    let set_pol_inner = encode_values(
        "setPolicy(address,bytes32,bytes,address)",
        &[
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(new_policy_id),
            AbiValue::Bytes(cc_buf[..cc_len].to_vec()),
            AbiValue::Address(auth_super_const),
        ],
    );
    assert!(
        client
            .send_call(
                &super1_eoa,
                super1_id,
                &encode_values(
                    "execute(address,bytes)",
                    &[AbiValue::Address(constitution_hps), AbiValue::Bytes(set_pol_inner)]
                )
            )
            .await
            .unwrap()
            .status
    );

    // 9b. Rotate GOLD's ACTION_CANCEL permission to `new_policy_id` via SUPER Authorization!
    let set_perm_hash = read_b32(
        &client,
        gold_ledger,
        "hashSetPermission(bytes32,address,bytes32)",
        &[
            AbiValue::Bytes32(ACTION_CANCEL),
            AbiValue::Address(constitution_hps),
            AbiValue::Bytes32(new_policy_id),
        ],
    )
    .await;
    let init_super_perm = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_super_perm),
            AbiValue::Address(registry_hps),
            AbiValue::Address(constitution_hps),
            AbiValue::Address(gold_ledger),
            AbiValue::Bytes32(POLICY_SUPER_GOVERNANCE),
            AbiValue::Bytes32(set_perm_hash),
        ],
    );
    assert!(client.send_call(&super1_eoa, super1_id, &init_super_perm).await.unwrap().status);
    assert!(
        client
            .send_call(
                &super1_eoa,
                super1_id,
                &encode_values("approveAuth(address)", &[AbiValue::Address(auth_super_perm)])
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &super2_eoa,
                super2_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_super_perm)])
            )
            .await
            .unwrap()
            .status
    );
    let set_perm_inner = encode_values(
        "setPermission(bytes32,address,bytes32,address)",
        &[
            AbiValue::Bytes32(ACTION_CANCEL),
            AbiValue::Address(constitution_hps),
            AbiValue::Bytes32(new_policy_id),
            AbiValue::Address(auth_super_perm),
        ],
    );
    assert!(
        client
            .send_call(
                &super1_eoa,
                super1_id,
                &encode_values(
                    "execute(address,bytes)",
                    &[AbiValue::Address(gold_ledger), AbiValue::Bytes(set_perm_inner)]
                )
            )
            .await
            .unwrap()
            .status
    );
    println!("[9/10] SUPER governance verified: Constitution.setPolicy & AssetLedger.setPermission rotated via SuperBoard 2-of-2 weighted Auth");

    // -------------------------------------------------------------------------
    // STEP 10: AssetPair_OTC Atomic Settlement Between Verified Identities
    // -------------------------------------------------------------------------
    let otc_rcpt = client.deploy_hps(&deployer, &otc_wasm, &[]).await.unwrap();
    let otc_hps: H160 = otc_rcpt.hps_address.parse().unwrap();

    let init_otc_inner = encode_values(
        "initialize(address,address,address,address)",
        &[
            AbiValue::Address(registry_hps),
            AbiValue::Address(seller_id),
            AbiValue::Address(gold_ledger),
            AbiValue::Address(usd_ledger),
        ],
    );
    assert!(
        client
            .send_call(
                &seller_eoa,
                seller_id,
                &encode_values(
                    "execute(address,bytes)",
                    &[AbiValue::Address(otc_hps), AbiValue::Bytes(init_otc_inner)]
                )
            )
            .await
            .unwrap()
            .status
    );

    // Seller approves OTC for 50 GOLD via one-time holder Authorization + places Ask Order (50 GOLD @ 200 USD/GOLD)
    let approve_gold_hash = read_b32(
        &client,
        gold_ledger,
        "hashApprove(address,address,uint64)",
        &[
            AbiValue::Address(seller_id),
            AbiValue::Address(otc_hps),
            AbiValue::Uint(U256::from(50u64)),
        ],
    )
    .await;
    assert!(
        client
            .send_call(
                &seller_eoa,
                seller_id,
                &encode_values(
                    "initOracleAuth(address,address,address,address,bytes32,uint64)",
                    &[
                        AbiValue::Address(auth_approve_gold),
                        AbiValue::Address(registry_hps),
                        AbiValue::Address(seller_id),
                        AbiValue::Address(gold_ledger),
                        AbiValue::Bytes32(approve_gold_hash),
                        AbiValue::Uint(U256::from(30u64)),
                    ]
                )
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &seller_eoa,
                seller_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_approve_gold)])
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &seller_eoa,
                seller_id,
                &encode_values(
                    "approveAsset(address,address,uint64,address)",
                    &[
                        AbiValue::Address(gold_ledger),
                        AbiValue::Address(otc_hps),
                        AbiValue::Uint(U256::from(50u64)),
                        AbiValue::Address(auth_approve_gold),
                    ]
                )
            )
            .await
            .unwrap()
            .status
    );

    let item_id = [0xABu8; 32];
    let place_ask = encode_values(
        "placeAskOrder(bytes32,uint64,uint64)",
        &[
            AbiValue::Bytes32(item_id),
            AbiValue::Uint(U256::from(50u64)),
            AbiValue::Uint(U256::from(200u64)),
        ],
    );
    assert!(
        client
            .send_call(
                &seller_eoa,
                seller_id,
                &encode_values("execute(address,bytes)", &[AbiValue::Address(otc_hps), AbiValue::Bytes(place_ask)])
            )
            .await
            .unwrap()
            .status
    );

    // Buyer approves OTC for 4,000 USD (20 GOLD * 200 USD) via one-time holder Authorization + executes buyOrder(20)
    let approve_usd_hash = read_b32(
        &client,
        usd_ledger,
        "hashApprove(address,address,uint64)",
        &[
            AbiValue::Address(buyer_id),
            AbiValue::Address(otc_hps),
            AbiValue::Uint(U256::from(4_000u64)),
        ],
    )
    .await;
    assert!(
        client
            .send_call(
                &buyer_eoa,
                buyer_id,
                &encode_values(
                    "initOracleAuth(address,address,address,address,bytes32,uint64)",
                    &[
                        AbiValue::Address(auth_approve_usd),
                        AbiValue::Address(registry_hps),
                        AbiValue::Address(buyer_id),
                        AbiValue::Address(usd_ledger),
                        AbiValue::Bytes32(approve_usd_hash),
                        AbiValue::Uint(U256::from(30u64)),
                    ]
                )
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &buyer_eoa,
                buyer_id,
                &encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_approve_usd)])
            )
            .await
            .unwrap()
            .status
    );
    assert!(
        client
            .send_call(
                &buyer_eoa,
                buyer_id,
                &encode_values(
                    "approveAsset(address,address,uint64,address)",
                    &[
                        AbiValue::Address(usd_ledger),
                        AbiValue::Address(otc_hps),
                        AbiValue::Uint(U256::from(4_000u64)),
                        AbiValue::Address(auth_approve_usd),
                    ]
                )
            )
            .await
            .unwrap()
            .status
    );

    let buy_cd = encode_values(
        "buyOrder(bytes32,uint64)",
        &[AbiValue::Bytes32(item_id), AbiValue::Uint(U256::from(20u64))],
    );
    assert!(
        client
            .send_call(
                &buyer_eoa,
                buyer_id,
                &encode_values("execute(address,bytes)", &[AbiValue::Address(otc_hps), AbiValue::Bytes(buy_cd)])
            )
            .await
            .unwrap()
            .status
    );

    // Final ledger assertions:
    // Seller GOLD: 1,000 - 20 = 980; Buyer GOLD: 225 + 20 = 245
    // Buyer USD: 50,000 - 4,000 = 46,000; Seller USD: 5,000 + 4,000 = 9,000
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(seller_id)]).await,
        980
    );
    assert_eq!(
        read_u64(&client, gold_ledger, "balanceOf(address)", &[AbiValue::Address(buyer_id)]).await,
        245
    );
    assert_eq!(
        read_u64(&client, usd_ledger, "balanceOf(address)", &[AbiValue::Address(buyer_id)]).await,
        46_000
    );
    assert_eq!(
        read_u64(&client, usd_ledger, "balanceOf(address)", &[AbiValue::Address(seller_id)]).await,
        9_000
    );
    println!("[10/10] AssetPair_OTC DvP trade settled atomically! Seller=(980 GOLD, 9000 USD), Buyer=(245 GOLD, 46000 USD)");
}

fn calc_intrinsic(cd: &[u8]) -> u64 {
    let mut g = 21_000u64;
    for &b in cd {
        g += if b == 0 { 4 } else { 16 };
    }
    g
}

#[tokio::test]
#[ignore = "requires local lexicon-node binary; run with --ignored"]
async fn simplex_hps_gas_usage_profile_on_localtestnet() {
    let _node = spawn_isolated_localtestnet();
    let rpc_url = format!("http://127.0.0.1:{TEST_RPC_PORT}");
    let client = HpsClient::new(&rpc_url);

    for _ in 0..40 {
        if client.block_number().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let dist = workspace_root().join("dist");
    let identity_wasm = std::fs::read(dist.join("identity.wasm")).unwrap();
    let registry_wasm = std::fs::read(dist.join("identity_registry.wasm")).unwrap();
    let constitution_wasm = std::fs::read(dist.join("constitution.wasm")).unwrap();
    let auth_wasm = std::fs::read(dist.join("authorization.wasm")).unwrap();
    let ledger_wasm = std::fs::read(dist.join("asset_ledger.wasm")).unwrap();
    let messaging_wasm = std::fs::read(dist.join("messaging.wasm")).unwrap();

    let mut deployer = HpsSigner::from_hex(DEFAULT_DEV_PRIVATE_KEY, DEFAULT_CHAIN_ID).unwrap();
    deployer.default_gas_limit = U256::from(5_000_000u64);

    let id_code = client.store_bytecode(&deployer, &identity_wasm).await.unwrap();
    let reg_code = client.store_bytecode(&deployer, &registry_wasm).await.unwrap();
    let con_code = client.store_bytecode(&deployer, &constitution_wasm).await.unwrap();
    let auth_code = client.store_bytecode(&deployer, &auth_wasm).await.unwrap();
    let led_code = client.store_bytecode(&deployer, &ledger_wasm).await.unwrap();
    let msg_code = client.store_bytecode(&deployer, &messaging_wasm).await.unwrap();

    let insts = client
        .instantiate_batch(
            &deployer,
            &[
                (id_code, Vec::new()),
                (id_code, Vec::new()),
                (reg_code, Vec::new()),
                (con_code, Vec::new()),
                (auth_code, Vec::new()),
                (led_code, Vec::new()),
                (msg_code, Vec::new()),
            ],
        )
        .await
        .unwrap();
    let alice_id = insts[0];
    let bob_id = insts[1];
    let registry = insts[2];
    let constitution = insts[3];
    let auth_hps = insts[4];
    let bank_ledger = insts[5];
    let msg_hps = insts[6];

    // Batch 1: Initialize Alice & Bob Identity HPSes + Messaging postMessage + pure view/hash calls as transactions
    let cd_init_alice = encode_values(
        "initialize(address,string)",
        &[
            AbiValue::Address(deployer.address()),
            AbiValue::Bytes(b"alice.id".to_vec()),
        ],
    );
    let cd_init_bob = encode_values(
        "initialize(address,string)",
        &[
            AbiValue::Address(deployer.address()),
            AbiValue::Bytes(b"bob.id".to_vec()),
        ],
    );
    let cd_post_msg = encode_values(
        "postMessage(bytes32,bytes)",
        &[
            AbiValue::Bytes32([0xAA; 32]),
            AbiValue::Bytes(b"hello".to_vec()),
        ],
    );
    let b1 = client
        .send_call_batch(
            &deployer,
            &[
                (alice_id, cd_init_alice.clone(), vec![]),
                (bob_id, cd_init_bob.clone(), vec![]),
                (msg_hps, cd_post_msg.clone(), vec![]),
            ],
        )
        .await
        .unwrap();

    // Batch 2: Simple calls on Identity (`owner()`, `isAuthorized(address)`, `setDelegate(address,bool)` cold, `transferOwnership(address)`)
    // + Initialize IdentityRegistry
    let cd_id_owner = encode_values("owner()", &[]);
    let cd_id_is_auth = encode_values("isAuthorized(address)", &[AbiValue::Address(deployer.address())]);
    let cd_id_set_del = encode_values(
        "setDelegate(address,bool)",
        &[AbiValue::Address(H160::repeat_byte(0x77)), AbiValue::Bool(true)],
    );
    let cd_reg_init = encode_values(
        "initialize(address,bytes32,bytes32,bytes)",
        &[
            AbiValue::Address(alice_id),
            AbiValue::Bytes32(*id_code.as_fixed_bytes()),
            AbiValue::Bytes32(*auth_code.as_fixed_bytes()),
            AbiValue::Bytes(bob_id.as_bytes().to_vec()),
        ],
    );
    let b2 = client
        .send_call_batch(
            &deployer,
            &[
                (alice_id, cd_id_owner.clone(), vec![]),
                (alice_id, cd_id_is_auth.clone(), vec![]),
                (alice_id, cd_id_set_del.clone(), vec![]),
                (registry, cd_reg_init.clone(), vec![alice_id, bob_id]),
            ],
        )
        .await
        .unwrap();

    // Batch 3: Simple calls on Identity (`setDelegate` warm modify), IdentityRegistry (`activeCount()`, `isValidIdentity(address)`, `isValidAuthorizationHps(address)`),
    // Constitution (`initialize`, `hashAddDirector(address)`), and Bank AssetLedger (`initialize`)
    let cd_id_set_del_warm = encode_values(
        "setDelegate(address,bool)",
        &[AbiValue::Address(H160::repeat_byte(0x77)), AbiValue::Bool(false)],
    );
    let cd_reg_active = encode_values("activeCount()", &[]);
    let cd_reg_valid_id = encode_values("isValidIdentity(address)", &[AbiValue::Address(alice_id)]);
    let cd_reg_valid_auth = encode_values("isValidAuthorizationHps(address)", &[AbiValue::Address(auth_hps)]);

    let super_spec = PolicySpec::new(100)
        .add_stage(StageSpec::new(1, 50).add_member(h160_bytes(alice_id), 1).unwrap())
        .unwrap();
    let mut con_blob = Vec::new();
    con_blob.extend_from_slice(&1u16.to_be_bytes());
    con_blob.extend_from_slice(&encode_constitution_entry(
        H160::zero(),
        POLICY_SUPER_GOVERNANCE,
        &super_spec,
    ));
    let cd_con_init = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(constitution),
            AbiValue::Bytes(encode_values(
                "initialize(address,bytes)",
                &[AbiValue::Address(registry), AbiValue::Bytes(con_blob)],
            )),
        ],
    );

    let mut bank_alloc = Vec::with_capacity(56);
    bank_alloc.extend_from_slice(alice_id.as_bytes());
    bank_alloc.extend_from_slice(&10_000u64.to_be_bytes());
    bank_alloc.extend_from_slice(bob_id.as_bytes());
    bank_alloc.extend_from_slice(&5_000u64.to_be_bytes());
    let mut bank_perms = Vec::new();
    for (act, con_a, pol) in [
        (ACTION_SUPER, constitution, POLICY_SUPER_GOVERNANCE),
        (ACTION_ISSUE, constitution, POLICY_SUPER_GOVERNANCE),
        (ACTION_CANCEL, constitution, POLICY_SUPER_GOVERNANCE),
        (ACTION_TRANSFER, H160::zero(), POLICY_HOLDER_SELF),
        (ACTION_APPROVE, H160::zero(), POLICY_HOLDER_SELF),
    ] {
        bank_perms.extend_from_slice(&pack_permission(act, con_a, pol));
    }
    let cd_led_init = encode_values(
        "execute(address,bytes)",
        &[
            AbiValue::Address(bank_ledger),
            AbiValue::Bytes(encode_values(
                "initialize(address,string,uint64,bytes,bytes)",
                &[
                    AbiValue::Address(registry),
                    AbiValue::Bytes(b"SGD".to_vec()),
                    AbiValue::Uint(U256::from(2u64)),
                    AbiValue::Bytes(bank_alloc),
                    AbiValue::Bytes(bank_perms),
                ],
            )),
        ],
    );

    let b3 = client
        .send_call_batch(
            &deployer,
            &[
                (alice_id, cd_id_set_del_warm.clone(), vec![]),
                (registry, cd_reg_active.clone(), vec![]),
                (registry, cd_reg_valid_id.clone(), vec![alice_id]),
                (registry, cd_reg_valid_auth.clone(), vec![auth_hps]),
                (alice_id, cd_con_init.clone(), vec![constitution, registry]),
                (alice_id, cd_led_init.clone(), vec![bank_ledger, registry, bob_id]),
            ],
        )
        .await
        .unwrap();

    // Batch 4: Simplest calls on Constitution (`directorCount()`, `hasPolicy`, `hashAddDirector`),
    // Authorization (`initConstitutionAuth`, `state()`), and AssetLedger (`totalOutstanding()`, `balanceOf(address)`,
    // and `transferBankBalance` / `transferDirect` between existing holders!)
    let cd_con_dircount = encode_values("directorCount()", &[]);
    let cd_con_haspol = encode_values(
        "hasPolicy(address,bytes32)",
        &[
            AbiValue::Address(H160::zero()),
            AbiValue::Bytes32(POLICY_SUPER_GOVERNANCE),
        ],
    );
    let cd_con_hash_add = encode_values("hashAddDirector(address)", &[AbiValue::Address(bob_id)]);
    let cd_led_supply = encode_values("totalOutstanding()", &[]);
    let cd_led_bal = encode_values("balanceOf(address)", &[AbiValue::Address(alice_id)]);
    let cd_bank_xfer_warm = encode_values(
        "transferBankBalance(address,address,uint64)",
        &[
            AbiValue::Address(bank_ledger),
            AbiValue::Address(bob_id),
            AbiValue::Uint(U256::from(100u64)),
        ],
    );
    let cd_auth_init = encode_values(
        "initConstitutionAuth(address,address,address,address,bytes32,bytes32)",
        &[
            AbiValue::Address(auth_hps),
            AbiValue::Address(registry),
            AbiValue::Address(constitution),
            AbiValue::Address(constitution),
            AbiValue::Bytes32(POLICY_SUPER_GOVERNANCE),
            AbiValue::Bytes32([0x55; 32]),
        ],
    );

    let b4 = client
        .send_call_batch(
            &deployer,
            &[
                (constitution, cd_con_dircount.clone(), vec![]),
                (constitution, cd_con_haspol.clone(), vec![]),
                (constitution, cd_con_hash_add.clone(), vec![]),
                (bank_ledger, cd_led_supply.clone(), vec![]),
                (bank_ledger, cd_led_bal.clone(), vec![]),
                (alice_id, cd_bank_xfer_warm.clone(), vec![bank_ledger, registry, bob_id]),
                (alice_id, cd_auth_init.clone(), vec![auth_hps, registry, constitution]),
            ],
        )
        .await
        .unwrap();

    // Batch 5: Authorization `status()` + `approveAndFinalizeAuth` + Constitution `clearingAccount()`
    let cd_auth_state = encode_values("status()", &[]);
    let cd_con_clearing = encode_values("clearingAccount()", &[]);
    let cd_auth_approve_fin = encode_values("approveAndFinalizeAuth(address)", &[AbiValue::Address(auth_hps)]);
    let b5 = client
        .send_call_batch(
            &deployer,
            &[
                (auth_hps, cd_auth_state.clone(), vec![]),
                (alice_id, cd_auth_approve_fin.clone(), vec![auth_hps, registry, constitution]),
                (constitution, cd_con_clearing.clone(), vec![]),
            ],
        )
        .await
        .unwrap();

    let rows = vec![
        ("Identity", "owner() [view]", &cd_id_owner, &b2[0]),
        ("Identity", "isAuthorized(address) [view]", &cd_id_is_auth, &b2[1]),
        ("Identity", "initialize(address,string) [cold 3 slots + event]", &cd_init_alice, &b1[0]),
        ("Identity", "setDelegate(address,bool) [cold new slot + event]", &cd_id_set_del, &b2[2]),
        ("Identity", "setDelegate(address,bool) [warm slot modify + event]", &cd_id_set_del_warm, &b3[0]),
        ("IdentityRegistry", "activeCount() [view]", &cd_reg_active, &b3[1]),
        ("IdentityRegistry", "isValidIdentity(address) [status + code_hash check]", &cd_reg_valid_id, &b3[2]),
        ("IdentityRegistry", "isValidAuthorizationHps(address) [code_hash check]", &cd_reg_valid_auth, &b3[3]),
        ("IdentityRegistry", "initialize(admin,idCode,authCode,1 id)", &cd_reg_init, &b2[3]),
        ("Constitution", "clearingAccount() [view]", &cd_con_clearing, &b5[2]),
        ("Constitution", "directorCount() [view]", &cd_con_dircount, &b4[0]),
        ("Constitution", "hasPolicy(address,bytes32) [view]", &cd_con_haspol, &b4[1]),
        ("Constitution", "hashAddDirector(address) [pure action_commit_256]", &cd_con_hash_add, &b4[2]),
        ("Constitution", "initialize(registry, 1 policy) [via Identity]", &cd_con_init, &b3[4]),
        ("Authorization", "status() [view]", &cd_auth_state, &b5[0]),
        ("Authorization", "initConstitutionAuth(...) [via Identity]", &cd_auth_init, &b4[6]),
        ("Authorization", "approveAndFinalizeAuth(...) [1-stage via Identity]", &cd_auth_approve_fin, &b5[1]),
        ("AssetLedger", "totalOutstanding() [view]", &cd_led_supply, &b4[3]),
        ("AssetLedger", "balanceOf(address) [view]", &cd_led_bal, &b4[4]),
        ("AssetLedger", "transferBankBalance / transferDirect [warm via Identity]", &cd_bank_xfer_warm, &b4[5]),
        ("AssetLedger", "initialize(SGD, 2 holders, 5 perms) [via Identity]", &cd_led_init, &b3[5]),
        ("Messaging", "postMessage(bytes32, \"hello\")", &cd_post_msg, &b1[2]),
    ];

    println!("\n=== HALTPROOF SUBROUTINES GAS USAGE PROFILE ===");
    println!(
        "| {:<18} | {:<52} | {:>10} | {:>10} | {:>10} |",
        "Subroutine", "Function / Call Path", "Intrinsic", "WASM+Host", "Total Gas"
    );
    println!("|--------------------|------------------------------------------------------|------------|------------|------------|");
    for (hps_name, fn_name, cd, rcpt) in rows {
        assert!(rcpt.status, "{hps_name}::{fn_name} failed");
        let intr = calc_intrinsic(cd);
        let exec = rcpt.gas_used.saturating_sub(intr);
        println!(
            "| {:<18} | {:<52} | {:>10} | {:>10} | {:>10} |",
            hps_name, fn_name, intr, exec, rcpt.gas_used
        );
    }
}
