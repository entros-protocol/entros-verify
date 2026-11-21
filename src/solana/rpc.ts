import {
  type AccountOwnerLike,
  type AddressInput,
  SolanaAddress,
} from "./address";
import { RPC_TIMEOUT_MS } from "./constants";

export type SolanaCommitment = "confirmed" | "finalized";

export interface RawAccountInfoLike {
  data: Uint8Array | readonly [string, string];
  executable?: boolean;
  lamports?: number;
  owner?: AccountOwnerLike;
  rentEpoch?: number;
}

export interface NormalizedAccountInfo {
  data: Uint8Array;
  executable: boolean;
  lamports: number;
  owner?: AccountOwnerLike;
}

export interface SignatureStatusLike {
  slot: number;
  confirmations?: number | null;
  err: unknown;
  confirmationStatus?: string | null;
}

export interface SignatureInfoLike {
  signature: string;
  slot?: number;
  err: unknown;
  memo?: string | null;
  blockTime?: number | null;
  confirmationStatus?: string | null;
}

export interface ParsedAccountKeyLike {
  pubkey: AddressInput;
  signer: boolean;
  writable?: boolean;
}

export interface PartiallyDecodedInstructionLike {
  programId: AddressInput;
  accounts: readonly AddressInput[];
  data: string;
}

export interface ParsedOnlyInstructionLike {
  programId: AddressInput;
  parsed: unknown;
  program?: string;
}

export type TransactionInstructionLike =
  | PartiallyDecodedInstructionLike
  | ParsedOnlyInstructionLike;

export interface ParsedTransactionLike {
  slot: number;
  blockTime?: number | null;
  version?: "legacy" | number;
  meta: { err: unknown } | null;
  transaction: {
    signatures: readonly string[];
    message: {
      accountKeys: readonly ParsedAccountKeyLike[];
      instructions: readonly TransactionInstructionLike[];
    };
  };
}

export interface RpcContextResponse<T> {
  context: { slot: number };
  value: T;
}

/**
 * Duck-typed Solana connection surface compatible with `@solana/web3.js` `Connection`
 * and `createSolanaRpcClient`.
 */
export interface SolanaConnectionLike {
  getGenesisHash?: () => Promise<string>;
  getSignatureStatuses?: (
    signatures: string[],
    config?: { searchTransactionHistory?: boolean },
  ) => Promise<RpcContextResponse<(SignatureStatusLike | null)[]>>;
  getParsedTransaction?: (
    signature: string,
    config?: {
      commitment?: SolanaCommitment;
      maxSupportedTransactionVersion?: number;
    },
  ) => Promise<ParsedTransactionLike | null>;
  getAccountInfoAndContext?: (
    address: SolanaAddress,
    config?: {
      commitment?: SolanaCommitment;
      minContextSlot?: number;
    },
  ) => Promise<RpcContextResponse<RawAccountInfoLike | null>>;
  getMultipleAccountsInfoAndContext?: (
    addresses: SolanaAddress[],
    config?: {
      commitment?: SolanaCommitment;
      minContextSlot?: number;
    },
  ) => Promise<RpcContextResponse<(RawAccountInfoLike | null)[]>>;
  getMultipleAccountsInfo?: (
    addresses: SolanaAddress[],
    commitment?: SolanaCommitment,
  ) => Promise<(RawAccountInfoLike | null)[]>;
  getAccountInfo?: (
    address: SolanaAddress,
    commitment?: SolanaCommitment,
  ) => Promise<RawAccountInfoLike | null>;
  getSignaturesForAddress?: (
    address: SolanaAddress,
    options?: { limit?: number; before?: string },
    commitment?: SolanaCommitment,
  ) => Promise<SignatureInfoLike[]>;
}

/** Configuration for the built-in zero-dependency JSON-RPC transport. */
export interface SolanaRpcConfig {
  endpoint: string;
  fetch?: typeof globalThis.fetch;
  headers?: Record<string, string>;
}

/** Minimal JSON-RPC client implementing the full reader connection surface. */
export type SolanaRpcClient = Required<SolanaConnectionLike>;

/**
 * Any supported Solana transport: an RPC endpoint URL string, a `SolanaRpcConfig`,
 * or a duck-typed `@solana/web3.js` `Connection`-compatible object.
 */
export type SolanaTransport = string | SolanaRpcConfig | SolanaConnectionLike;

const BASE64_LOOKUP = new Int16Array(128).fill(-1);
{
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < chars.length; i += 1) {
    BASE64_LOOKUP[chars.charCodeAt(i)] = i;
  }
}

/** Decodes RFC 4648 base64 into bytes without depending on Node `Buffer`. */
export function decodeBase64(input: string): Uint8Array | null {
  if (input.length === 0) return new Uint8Array(0);
  if (input.length % 4 !== 0) return null;

  let padding = 0;
  if (input.endsWith("==")) padding = 2;
  else if (input.endsWith("=")) padding = 1;

  const outLength = (input.length / 4) * 3 - padding;
  const output = new Uint8Array(outLength);
  let outOffset = 0;

  for (let i = 0; i < input.length; i += 4) {
    const c0 = input.charCodeAt(i);
    const c1 = input.charCodeAt(i + 1);
    const c2 = input.charCodeAt(i + 2);
    const c3 = input.charCodeAt(i + 3);

    const v0 = c0 < 128 ? (BASE64_LOOKUP[c0] ?? -1) : -1;
    const v1 = c1 < 128 ? (BASE64_LOOKUP[c1] ?? -1) : -1;
    if (v0 < 0 || v1 < 0) return null;

    const isLast = i + 4 === input.length;
    const pad2 = isLast && padding === 2 && c2 === 61;
    const pad3 = isLast && padding >= 1 && c3 === 61;

    const v2 = pad2 ? 0 : c2 < 128 ? (BASE64_LOOKUP[c2] ?? -1) : -1;
    const v3 = pad3 ? 0 : c3 < 128 ? (BASE64_LOOKUP[c3] ?? -1) : -1;
    if (v2 < 0 || v3 < 0) return null;

    const triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
    output[outOffset] = (triple >>> 16) & 0xff;
    outOffset += 1;
    if (!pad2 && outOffset < outLength) {
      output[outOffset] = (triple >>> 8) & 0xff;
      outOffset += 1;
    }
    if (!pad3 && outOffset < outLength) {
      output[outOffset] = triple & 0xff;
      outOffset += 1;
    }
  }
  return output;
}

/** Normalizes raw `Uint8Array`, `Buffer`, or JSON-RPC `[base64, "base64"]` account data. */
export function normalizeAccountData(
  data: Uint8Array | readonly [string, string] | unknown,
): Uint8Array | null {
  if (data instanceof Uint8Array) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (
    Array.isArray(data) &&
    data.length === 2 &&
    typeof data[0] === "string" &&
    data[1] === "base64"
  ) {
    return decodeBase64(data[0]);
  }
  return null;
}

/** Normalizes a raw account info object from web3.js or JSON-RPC. */
export function normalizeAccountInfo(
  account: RawAccountInfoLike | null | undefined,
): NormalizedAccountInfo | null {
  if (!account || typeof account !== "object") return null;
  const data = normalizeAccountData(account.data);
  if (!data) return null;
  return {
    data,
    executable: account.executable === true,
    lamports: typeof account.lamports === "number" ? account.lamports : 0,
    owner: account.owner,
  };
}

/** Rejects after `timeoutMs` (default 3000 ms) so one stalled RPC call cannot hang a reader. */
export async function boundedRpc<T>(
  operation: Promise<T>,
  timeoutMs = RPC_TIMEOUT_MS,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Evidence RPC deadline exceeded")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function isRpcConfig(value: unknown): value is SolanaRpcConfig {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).endpoint === "string"
  );
}

/**
 * Creates a minimal zero-dependency Solana JSON-RPC client backed by `fetch`.
 * Covers the read methods used by Entros verification and agent-state readers.
 */
export function createSolanaRpcClient(
  input: string | SolanaRpcConfig,
): SolanaRpcClient {
  const endpoint = typeof input === "string" ? input : input.endpoint;
  if (typeof endpoint !== "string" || endpoint.trim().length === 0) {
    throw new TypeError("Solana RPC endpoint must be a non-empty URL string");
  }
  const fetchFn =
    typeof input === "string" ? globalThis.fetch : (input.fetch ?? globalThis.fetch);
  if (typeof fetchFn !== "function") {
    throw new Error("A Fetch API implementation is required for Solana JSON-RPC");
  }
  const customHeaders = typeof input === "string" ? undefined : input.headers;
  let nextId = 1;

  async function callRpc<T>(method: string, params: unknown[]): Promise<T> {
    const id = nextId;
    nextId += 1;
    const response = await fetchFn(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...customHeaders,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method,
        params,
      }),
    });
    if (!response.ok) {
      throw new Error(`Solana RPC HTTP ${response.status} for ${method}`);
    }
    const payload = (await response.json()) as {
      id?: unknown;
      result?: T;
      error?: { code?: unknown; message?: unknown };
    };
    if (!payload || typeof payload !== "object") {
      throw new Error(`Malformed Solana RPC response for ${method}`);
    }
    if (payload.error !== undefined && payload.error !== null) {
      throw new Error(
        `Solana RPC error for ${method}: ${String(payload.error.message ?? payload.error.code ?? "unknown")}`,
      );
    }
    if (payload.id !== id || !("result" in payload)) {
      throw new Error(`Unexpected Solana RPC envelope for ${method}`);
    }
    return payload.result as T;
  }

  return {
    async getGenesisHash(): Promise<string> {
      const result = await callRpc<unknown>("getGenesisHash", []);
      if (typeof result !== "string") {
        throw new Error("Invalid getGenesisHash response");
      }
      return result;
    },

    async getSignatureStatuses(
      signatures: string[],
      config?: { searchTransactionHistory?: boolean },
    ): Promise<RpcContextResponse<(SignatureStatusLike | null)[]>> {
      const params: unknown[] =
        config !== undefined ? [signatures, config] : [signatures];
      return callRpc<RpcContextResponse<(SignatureStatusLike | null)[]>>(
        "getSignatureStatuses",
        params,
      );
    },

    async getParsedTransaction(
      signature: string,
      config?: {
        commitment?: SolanaCommitment;
        maxSupportedTransactionVersion?: number;
      },
    ): Promise<ParsedTransactionLike | null> {
      return callRpc<ParsedTransactionLike | null>("getTransaction", [
        signature,
        {
          encoding: "jsonParsed",
          commitment: config?.commitment ?? "confirmed",
          maxSupportedTransactionVersion:
            config?.maxSupportedTransactionVersion ?? 0,
        },
      ]);
    },

    async getAccountInfoAndContext(
      address: SolanaAddress,
      config?: {
        commitment?: SolanaCommitment;
        minContextSlot?: number;
      },
    ): Promise<RpcContextResponse<RawAccountInfoLike | null>> {
      const rpcConfig: Record<string, unknown> = {
        encoding: "base64",
        commitment: config?.commitment ?? "confirmed",
      };
      if (config?.minContextSlot !== undefined) {
        rpcConfig.minContextSlot = config.minContextSlot;
      }
      return callRpc<RpcContextResponse<RawAccountInfoLike | null>>(
        "getAccountInfo",
        [address.toBase58(), rpcConfig],
      );
    },

    async getMultipleAccountsInfoAndContext(
      addresses: SolanaAddress[],
      config?: {
        commitment?: SolanaCommitment;
        minContextSlot?: number;
      },
    ): Promise<RpcContextResponse<(RawAccountInfoLike | null)[]>> {
      const rpcConfig: Record<string, unknown> = {
        encoding: "base64",
        commitment: config?.commitment ?? "confirmed",
      };
      if (config?.minContextSlot !== undefined) {
        rpcConfig.minContextSlot = config.minContextSlot;
      }
      return callRpc<RpcContextResponse<(RawAccountInfoLike | null)[]>>(
        "getMultipleAccounts",
        [addresses.map((address) => address.toBase58()), rpcConfig],
      );
    },

    async getMultipleAccountsInfo(
      addresses: SolanaAddress[],
      commitment: SolanaCommitment = "confirmed",
    ): Promise<(RawAccountInfoLike | null)[]> {
      const response = await callRpc<
        RpcContextResponse<(RawAccountInfoLike | null)[]>
      >("getMultipleAccounts", [
        addresses.map((address) => address.toBase58()),
        { encoding: "base64", commitment },
      ]);
      return response.value;
    },

    async getAccountInfo(
      address: SolanaAddress,
      commitment: SolanaCommitment = "confirmed",
    ): Promise<RawAccountInfoLike | null> {
      const response = await callRpc<
        RpcContextResponse<RawAccountInfoLike | null>
      >("getAccountInfo", [
        address.toBase58(),
        { encoding: "base64", commitment },
      ]);
      return response.value;
    },

    async getSignaturesForAddress(
      address: SolanaAddress,
      options?: { limit?: number; before?: string },
      commitment: SolanaCommitment = "confirmed",
    ): Promise<SignatureInfoLike[]> {
      const rpcConfig: Record<string, unknown> = { commitment };
      if (options?.limit !== undefined) rpcConfig.limit = options.limit;
      if (options?.before !== undefined) rpcConfig.before = options.before;
      return callRpc<SignatureInfoLike[]>("getSignaturesForAddress", [
        address.toBase58(),
        rpcConfig,
      ]);
    },
  };
}

/** Resolves a URL string, `SolanaRpcConfig`, or duck-typed connection into a connection object. */
export function resolveSolanaConnection(
  transport: SolanaTransport,
): SolanaConnectionLike {
  if (typeof transport === "string" || isRpcConfig(transport)) {
    return createSolanaRpcClient(transport);
  }
  return transport;
}
