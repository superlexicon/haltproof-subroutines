export declare const DEFAULT_CHAIN_ID: bigint;
export declare const BYTECODE_STORE_ADDRESS: string;
export declare const DEFAULT_DEV_PRIVATE_KEY: string;

export interface EthersV6Utils {
  SigningKey: new (privateKey: string) => {
    sign(digest: string): { r: string; s: string; yParity: 0 | 1 };
  };
  keccak256(data: string | Uint8Array): string;
  encodeRlp(object: unknown): string;
  computeAddress(key: string): string;
}

export interface SignLexiconTxParams {
  privateKey: string;
  nonce: bigint | number;
  to?: string | null;
  value?: bigint | number;
  data?: string;
  gasLimit?: bigint | number;
  gasPrice?: bigint | number;
  chainId?: bigint | number;
}

export declare function signLexiconTransaction(
  ethersUtils: EthersV6Utils,
  params: SignLexiconTxParams
): string;

export declare class IsrRpcClient {
  rpcUrl: string;
  constructor(rpcUrl?: string);
  rpc(method: string, params?: unknown[]): Promise<any>;
  blockNumber(): Promise<number>;
  getNonce(address: string): Promise<bigint>;
  sendRawTransaction(rawTxHex: string): Promise<string>;
  readCall(to: string, data: string, from?: string): Promise<string>;
  waitForReceipt(txHash: string, timeoutMs?: number): Promise<any>;
  deployIsr(
    ethersUtils: EthersV6Utils,
    privateKey: string,
    wasmHex: string,
    initArgsHex?: string
  ): Promise<{
    codeHash: string;
    isrAddress: string;
    storeTxHash: string;
    deployTxHash: string;
    blockNumber: number;
  }>;
}
