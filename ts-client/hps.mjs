/**
 * @lexicon/hps — Lightweight JavaScript/TypeScript client for Lexicon Haltproof Subroutines (HPS)
 *
 * Implements Lexicon's 10-field EIP-155 RLP transaction encoding, 2-step WASM
 * HPS deployment (`0x000...0100` store + instantiate),
 * read-only `eth_call` queries, and receipt polling.
 *
 * Works with `ethers` v6 (`SigningKey`, `keccak256`, `encodeRlp`, `AbiCoder`, `id`)
 * or any secp256k1 signing primitive.
 */

export const DEFAULT_CHAIN_ID = 1337n;
export const BYTECODE_STORE_ADDRESS = "0x0000000000000000000000000000000000000100";
export const DEFAULT_DEV_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function bigIntToMinimalBytes(v) {
  const n = BigInt(v);
  if (n === 0n) return "0x";
  let hex = n.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  return "0x" + hex;
}

/**
 * Sign and RLP-encode a Lexicon 10-field zero-balance transaction using an `ethers` v6 utilities object
 * (`{ SigningKey, keccak256, encodeRlp, computeAddress }`).
 */
export function signLexiconTransaction(ethersUtils, {
  privateKey,
  nonce,
  to = null,
  value = 0n,
  data = "0x",
  gasLimit = 5_000_000n,
  gasPrice = 1_000_000_000n,
  chainId = DEFAULT_CHAIN_ID,
}) {
  const { SigningKey, keccak256, encodeRlp } = ethersUtils;
  const signingKey = new SigningKey(privateKey);
  const toRlp = to ? to.toLowerCase() : "0x";
  const targetAddresses = to ? [to.toLowerCase()] : [];

  // 10-item EIP-155 signing preimage:
  // [nonce, gas_price, gas_limit, to, value, data, target_addresses, chain_id, 0, 0]
  const preimage = encodeRlp([
    bigIntToMinimalBytes(nonce),
    bigIntToMinimalBytes(gasPrice),
    bigIntToMinimalBytes(gasLimit),
    toRlp,
    bigIntToMinimalBytes(value),
    data,
    targetAddresses,
    bigIntToMinimalBytes(chainId),
    "0x",
    "0x",
  ]);

  const digest = keccak256(preimage);
  const sig = signingKey.sign(digest); // { r, s, yParity }
  const v = BigInt(sig.yParity) + BigInt(chainId) * 2n + 35n;

  // 10-item Lexicon wire RLP:
  // [nonce, gas_price, gas_limit, to, value, data, v, r, s, target_addresses]
  return encodeRlp([
    bigIntToMinimalBytes(nonce),
    bigIntToMinimalBytes(gasPrice),
    bigIntToMinimalBytes(gasLimit),
    toRlp,
    bigIntToMinimalBytes(value),
    data,
    bigIntToMinimalBytes(v),
    bigIntToMinimalBytes(BigInt(sig.r)),
    bigIntToMinimalBytes(BigInt(sig.s)),
    targetAddresses,
  ]);
}

export class HpsRpcClient {
  constructor(rpcUrl = "http://127.0.0.1:8545") {
    this.rpcUrl = rpcUrl;
  }

  async rpc(method, params = []) {
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const json = await res.json();
    if (json.error) {
      throw new Error(`Lexicon RPC ${method} failed: ${JSON.stringify(json.error)}`);
    }
    return json.result;
  }

  async blockNumber() {
    const hex = await this.rpc("eth_blockNumber");
    return Number(BigInt(hex));
  }

  async getNonce(address) {
    const hex = await this.rpc("eth_getTransactionCount", [address, "latest"]);
    return BigInt(hex);
  }

  async sendRawTransaction(rawTxHex) {
    return this.rpc("eth_sendRawTransaction", [rawTxHex]);
  }

  async readCall(to, data, from = undefined) {
    const req = from ? { to, data, from } : { to, data };
    return this.rpc("eth_call", [req, "latest"]);
  }

  async waitForReceipt(txHash, timeoutMs = 30_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const rcpt = await this.rpc("eth_getTransactionReceipt", [txHash]);
      if (rcpt) return rcpt;
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`Timed out waiting for receipt ${txHash}`);
  }

  /**
   * 2-step content-addressed WASM Haltproof Subroutine (HPS) deployment (store_bytecode + instantiate in 1 call).
   */
  async deployHps(ethersUtils, privateKey, wasmHex, initArgsHex = "0x") {
    const address = ethersUtils.computeAddress(privateKey);
    const nonce = await this.getNonce(address);
    const cleanWasm = wasmHex.startsWith("0x") ? wasmHex.slice(2) : wasmHex;
    const codeHash = ethersUtils.keccak256("0x" + cleanWasm);
    const cleanArgs = initArgsHex.startsWith("0x") ? initArgsHex.slice(2) : initArgsHex;

    const storeTx = signLexiconTransaction(ethersUtils, {
      privateKey,
      nonce,
      to: BYTECODE_STORE_ADDRESS,
      data: codeHash + cleanWasm,
      gasLimit: 8_000_000n,
    });
    const deployTx = signLexiconTransaction(ethersUtils, {
      privateKey,
      nonce: nonce + 1n,
      to: null,
      data: codeHash + cleanArgs,
      gasLimit: 5_000_000n,
    });

    const storeTxHash = await this.sendRawTransaction(storeTx);
    const deployTxHash = await this.sendRawTransaction(deployTx);

    const storeReceipt = await this.waitForReceipt(storeTxHash);
    if (storeReceipt.status !== "0x1") {
      throw new Error(`store_bytecode reverted: ${JSON.stringify(storeReceipt)}`);
    }
    const deployReceipt = await this.waitForReceipt(deployTxHash);
    if (deployReceipt.status !== "0x1") {
      throw new Error(`instantiate reverted: ${JSON.stringify(deployReceipt)}`);
    }

    return {
      codeHash,
      hpsAddress: deployReceipt.contractAddress,
      storeTxHash,
      deployTxHash,
      blockNumber: Number(BigInt(deployReceipt.blockNumber)),
    };
  }
}
