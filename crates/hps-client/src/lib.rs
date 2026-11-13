//! # `hps-client`
//!
//! Pure-Rust transaction signer, 2-step WASM **Haltproof Subroutine (HPS)** deployer,
//! ABI encoder, and JSON-RPC client for Lexicon (`--localtestnet` and multi-node radio subnets).

pub mod abi;

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ethereum_types::{H160, H256, U256};
use reqwest::Client;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

/// Default Lexicon chain ID (`1337`).
pub const DEFAULT_CHAIN_ID: u64 = 1337;

/// Deterministic local development private key (for `--localtestnet` convenience).
/// Never use on production subnets.
pub const DEFAULT_DEV_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Sentinel address (`0x0000000000000000000000000000000000000100`) where Step 1 of
/// Lexicon's content-addressed deployment stores `[32-byte keccak256(wasm)] || [wasm]`.
pub const BYTECODE_STORE_ADDRESS: H160 = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
]);

/// Compute deterministic Haltproof Subroutine (HPS) address from `(sender, nonce)`.
pub fn compute_hps_address(sender: H160, nonce: u64) -> H160 {
    let mut stream = RlpStream::new();
    stream.begin_list(2);
    stream.append(&sender);
    stream.append(&nonce);
    let digest = Keccak256::digest(stream.out());
    H160::from_slice(&digest[12..])
}

/// EIP-155 transaction signer using Lexicon's 10-field RLP wire format.
#[derive(Clone)]
pub struct HpsSigner {
    secret_key: SecretKey,
    address: H160,
    pub chain_id: u64,
    pub gas_price: U256,
    pub default_gas_limit: U256,
}

impl HpsSigner {
    pub fn from_hex(private_key_hex: &str, chain_id: u64) -> Result<Self> {
        let clean = private_key_hex.trim().strip_prefix("0x").unwrap_or(private_key_hex.trim());
        let bytes = hex::decode(clean).context("invalid hex private key")?;
        if bytes.len() != 32 {
            bail!("private key must be 32 bytes (got {})", bytes.len());
        }
        let secret_key = SecretKey::from_slice(&bytes).context("invalid secp256k1 secret key")?;
        let secp = Secp256k1::new();
        let pubkey = secret_key.public_key(&secp).serialize_uncompressed();
        let digest = Keccak256::digest(&pubkey[1..]);
        let address = H160::from_slice(&digest[12..]);
        Ok(Self {
            secret_key,
            address,
            chain_id,
            // Nominal non-zero RLP gas_price required by `transaction_parser.rs`
            // (no balance is required or deducted on-chain).
            gas_price: U256::from(1_000_000_000u64),
            default_gas_limit: U256::from(5_000_000u64),
        })
    }

    /// Generate a brand-new random secp256k1 keypair, returning `(private_key_hex, signer)`.
    pub fn generate_random(chain_id: u64) -> (String, Self) {
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let hex_key = format!("0x{}", hex::encode(secret_key.secret_bytes()));
        let signer = Self::from_hex(&hex_key, chain_id).expect("valid generated key");
        (hex_key, signer)
    }

    pub fn address(&self) -> H160 {
        self.address
    }

    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address.as_bytes()))
    }

    /// Sign and RLP-encode a raw Lexicon transaction (`0x...` hex).
    pub fn sign_raw_tx(
        &self,
        nonce: u64,
        to: Option<H160>,
        value: U256,
        data: &[u8],
        gas_limit: Option<U256>,
    ) -> Result<String> {
        let gas_limit = gas_limit.unwrap_or(self.default_gas_limit);
        let target_addresses: Vec<H160> = to.into_iter().collect();

        // 1. Lexicon 10-field EIP-155 signing preimage:
        // [nonce, gas_price, gas_limit, to, value, data, target_addresses, chain_id, 0, 0]
        let mut sig_stream = RlpStream::new();
        sig_stream.begin_list(10);
        sig_stream.append(&nonce);
        sig_stream.append(&self.gas_price);
        sig_stream.append(&gas_limit);
        match &to {
            Some(addr) => sig_stream.append(addr),
            None => sig_stream.append_empty_data(),
        };
        sig_stream.append(&value);
        sig_stream.append(&data);
        sig_stream.append_list(&target_addresses);
        sig_stream.append(&self.chain_id);
        sig_stream.append(&0u8);
        sig_stream.append(&0u8);

        let sighash = Keccak256::digest(sig_stream.out());
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&sighash).map_err(|e| anyhow!("sighash: {e}"))?;
        let rec_sig = secp.sign_ecdsa_recoverable(&msg, &self.secret_key);
        let (rec_id, compact) = rec_sig.serialize_compact();

        let r = U256::from_big_endian(&compact[0..32]);
        let s = U256::from_big_endian(&compact[32..64]);
        let v = (rec_id.to_i32() as u64) + self.chain_id * 2 + 35;

        // 2. Lexicon 10-field wire RLP:
        // [nonce, gas_price, gas_limit, to, value, data, v, r, s, target_addresses]
        let mut wire = RlpStream::new();
        wire.begin_list(10);
        wire.append(&nonce);
        wire.append(&self.gas_price);
        wire.append(&gas_limit);
        match &to {
            Some(addr) => wire.append(addr),
            None => wire.append_empty_data(),
        };
        wire.append(&value);
        wire.append(&data);
        wire.append(&v);
        wire.append(&r);
        wire.append(&s);
        wire.append_list(&target_addresses);

        Ok(format!("0x{}", hex::encode(wire.out())))
    }

    /// Build Step 1 of 2-step HPS deployment (`store_bytecode` to `0x000...0100`).
    pub fn build_store_bytecode_tx(&self, nonce: u64, wasm_bytes: &[u8]) -> Result<(H256, String)> {
        let code_hash_bytes = abi::keccak256(wasm_bytes);
        let mut data = Vec::with_capacity(32 + wasm_bytes.len());
        data.extend_from_slice(&code_hash_bytes);
        data.extend_from_slice(wasm_bytes);
        let gas = U256::from(8_000_000u64);
        let raw = self.sign_raw_tx(nonce, Some(BYTECODE_STORE_ADDRESS), U256::zero(), &data, Some(gas))?;
        Ok((H256::from(code_hash_bytes), raw))
    }

    /// Build Step 2 of 2-step HPS instantiation (`to = None`, `data = code_hash || init_args`).
    pub fn build_instantiate_tx(
        &self,
        nonce: u64,
        code_hash: H256,
        init_args: &[u8],
    ) -> Result<(H160, String)> {
        let mut data = Vec::with_capacity(32 + init_args.len());
        data.extend_from_slice(code_hash.as_bytes());
        data.extend_from_slice(init_args);
        let derived_addr = compute_hps_address(self.address, nonce);
        let raw = self.sign_raw_tx(nonce, None, U256::zero(), &data, Some(self.default_gas_limit))?;
        Ok((derived_addr, raw))
    }

    /// Build a signed HPS invocation transaction.
    pub fn build_call_tx(&self, nonce: u64, hps: H160, calldata: &[u8]) -> Result<String> {
        self.sign_raw_tx(nonce, Some(hps), U256::zero(), calldata, Some(self.default_gas_limit))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpsDeployReceipt {
    pub code_hash: String,
    pub hps_address: String,
    pub store_tx_hash: String,
    pub deploy_tx_hash: String,
    pub block_number: u64,
    pub deploy_gas_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutcome {
    pub tx_hash: String,
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
    pub hps_address: Option<String>,
    pub logs: Vec<Value>,
    pub raw: Value,
}

/// Async JSON-RPC client for interacting with `lexicon-node` (`--localtestnet` or live subnets).
#[derive(Clone)]
pub struct HpsClient {
    http: Client,
    rpc_url: String,
    pub receipt_timeout: Duration,
}

impl HpsClient {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("build reqwest client");
        Self {
            http,
            rpc_url: rpc_url.into(),
            receipt_timeout: Duration::from_secs(30),
        }
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub async fn rpc_call(&self, method: &str, params: Value) -> Result<Value> {
        let resp: Value = self
            .http
            .post(&self.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to reach Lexicon JSON-RPC at {} (is `lexicon-node --localtestnet` running?)",
                    self.rpc_url
                )
            })?
            .json()
            .await
            .context("invalid JSON-RPC response")?;

        if let Some(err) = resp.get("error") {
            bail!("JSON-RPC {method} error: {err}");
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn block_number(&self) -> Result<u64> {
        let v = self.rpc_call("eth_blockNumber", json!([])).await?;
        parse_hex_u64(v.as_str().unwrap_or("0x0"))
    }

    pub async fn get_nonce(&self, address: H160) -> Result<u64> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let v = self
            .rpc_call("eth_getTransactionCount", json!([addr_hex, "latest"]))
            .await?;
        parse_hex_u64(v.as_str().unwrap_or("0x0"))
    }

    pub async fn send_raw_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let v = self
            .rpc_call("eth_sendRawTransaction", json!([raw_tx_hex]))
            .await?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("unexpected eth_sendRawTransaction result: {v}"))
    }

    pub async fn wait_for_receipt(&self, tx_hash: &str) -> Result<TxOutcome> {
        let deadline = Instant::now() + self.receipt_timeout;
        while Instant::now() < deadline {
            let r = self
                .rpc_call("eth_getTransactionReceipt", json!([tx_hash]))
                .await?;
            if !r.is_null() {
                let status = r["status"].as_str().unwrap_or("0x0") == "0x1";
                let block_number = parse_hex_u64(r["blockNumber"].as_str().unwrap_or("0x0")).unwrap_or(0);
                let gas_used = parse_hex_u64(r["gasUsed"].as_str().unwrap_or("0x0")).unwrap_or(0);
                // Underlying JSON-RPC wire field is named `contractAddress` for Ethereum RPC compatibility.
                let hps_address = r["contractAddress"].as_str().map(|s| s.to_string());
                let logs = r["logs"].as_array().cloned().unwrap_or_default();
                return Ok(TxOutcome {
                    tx_hash: tx_hash.to_string(),
                    status,
                    block_number,
                    gas_used,
                    hps_address,
                    logs,
                    raw: r,
                });
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        bail!(
            "timed out after {:?} waiting for transaction receipt {tx_hash}",
            self.receipt_timeout
        );
    }

    /// Deploy a compiled WASM Haltproof Subroutine (HPS) in one function call!
    ///
    /// Automatically submits Step 1 (`store_bytecode` at `nonce`) and Step 2 (`instantiate`
    /// at `nonce + 1`) back-to-back so on `--localtestnet` both confirm in the very same 4s block!
    pub async fn deploy_hps(
        &self,
        signer: &HpsSigner,
        wasm_bytes: &[u8],
        init_args: &[u8],
    ) -> Result<HpsDeployReceipt> {
        let nonce = self.get_nonce(signer.address()).await?;
        let (code_hash, store_raw) = signer.build_store_bytecode_tx(nonce, wasm_bytes)?;
        let (expected_addr, deploy_raw) =
            signer.build_instantiate_tx(nonce + 1, code_hash, init_args)?;

        let store_tx_hash = self.send_raw_transaction(&store_raw).await?;
        let deploy_tx_hash = self.send_raw_transaction(&deploy_raw).await?;

        let store_rcpt = self.wait_for_receipt(&store_tx_hash).await?;
        if !store_rcpt.status {
            bail!("store_bytecode transaction {store_tx_hash} failed: {}", store_rcpt.raw);
        }
        let deploy_rcpt = self.wait_for_receipt(&deploy_tx_hash).await?;
        if !deploy_rcpt.status {
            bail!("instantiate transaction {deploy_tx_hash} failed: {}", deploy_rcpt.raw);
        }

        let hps_address = deploy_rcpt
            .hps_address
            .unwrap_or_else(|| format!("0x{}", hex::encode(expected_addr.as_bytes())));

        Ok(HpsDeployReceipt {
            code_hash: format!("0x{}", hex::encode(code_hash.as_bytes())),
            hps_address,
            store_tx_hash,
            deploy_tx_hash,
            block_number: deploy_rcpt.block_number,
            deploy_gas_used: deploy_rcpt.gas_used,
        })
    }

    /// Sign, submit, and await confirmation of a stateful HPS invocation.
    pub async fn send_call(
        &self,
        signer: &HpsSigner,
        hps: H160,
        calldata: &[u8],
    ) -> Result<TxOutcome> {
        let nonce = self.get_nonce(signer.address()).await?;
        let raw_tx = signer.build_call_tx(nonce, hps, calldata)?;
        let tx_hash = self.send_raw_transaction(&raw_tx).await?;
        self.wait_for_receipt(&tx_hash).await
    }

    /// Execute a read-only `eth_call` against committed HPS state (consumes 0 blocks / 0 txns).
    pub async fn read_call(
        &self,
        from: Option<H160>,
        hps: H160,
        calldata: &[u8],
    ) -> Result<Vec<u8>> {
        let to_hex = format!("0x{}", hex::encode(hps.as_bytes()));
        let data_hex = format!("0x{}", hex::encode(calldata));
        let mut req_obj = json!({
            "to": to_hex,
            "data": data_hex,
        });
        if let Some(f) = from {
            req_obj["from"] = json!(format!("0x{}", hex::encode(f.as_bytes())));
        }
        let v = self.rpc_call("eth_call", json!([req_obj, "latest"])).await?;
        let hex_str = v
            .as_str()
            .ok_or_else(|| anyhow!("unexpected eth_call result: {v}"))?;
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if clean.is_empty() {
            return Ok(Vec::new());
        }
        Ok(hex::decode(clean).context("invalid hex in eth_call response")?)
    }

    /// Relay a signed transaction to a foreign 4-byte subnet ID (`subnet_sendTransaction`).
    pub async fn send_foreign_subnet_transaction(
        &self,
        target_subnet_hex: &str,
        raw_tx_hex: &str,
    ) -> Result<Value> {
        self.rpc_call(
            "subnet_sendTransaction",
            json!([target_subnet_hex, raw_tx_hex]),
        )
        .await
    }
}

pub fn parse_address(s: &str) -> Result<H160> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(clean).with_context(|| format!("invalid hex address '{s}'"))?;
    if bytes.len() != 20 {
        bail!("address must be 20 bytes (got {})", bytes.len());
    }
    Ok(H160::from_slice(&bytes))
}

fn parse_hex_u64(s: &str) -> Result<u64> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if clean.is_empty() {
        return Ok(0);
    }
    Ok(u64::from_str_radix(clean, 16)?)
}
