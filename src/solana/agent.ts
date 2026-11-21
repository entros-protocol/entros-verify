import type {
  AgentStateEvidence,
  AgentStateFailureReason,
  AgentStateReadResult,
  AgentWalletStatus,
} from "../agent-permit";
import {
  base58Encode,
  canonicalKeyBytes,
  deriveAgentAccountPda,
  ownerMatches,
  SolanaAddress,
} from "./address";
import {
  AGENT_REGISTRY_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
} from "./constants";
import {
  boundedRpc,
  normalizeAccountInfo,
  resolveSolanaConnection,
  type RawAccountInfoLike,
  type SolanaTransport,
} from "./rpc";

export type {
  AgentStateEvidence,
  AgentStateFailureReason,
  AgentStateReadResult,
  AgentWalletStatus,
};

export interface ReadAgentStateInput {
  /** Metaplex Core asset address of the agent. */
  agent: string;
  /** RPC endpoint URL, RPC config, or duck-typed `@solana/web3.js` Connection. */
  connection: SolanaTransport;
  minContextSlot?: number;
}

const AGENT_ACCOUNT_DISCRIMINATOR = Uint8Array.from([
  0xf1, 0x77, 0x45, 0x8c, 0xe9, 0x09, 0x70, 0x32,
]);
const AGENT_ACCOUNT_LENGTH = 748;
const CORE_KEY_UNINITIALIZED = 0;
const CORE_KEY_ASSET = 1;
const CORE_UPDATE_AUTHORITY_COLLECTION = 2;

const COLLECTION_BYTES = new SolanaAddress(
  AGENT_REGISTRY_DEVNET_CONFIG.collection,
).toBytes();

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function readLength(data: Uint8Array, offset: number): number | null {
  if (offset + 4 > data.length) return null;
  return new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(
    0,
    true,
  );
}

type CoreAssetDecoding =
  | { owner: Uint8Array }
  | { reason: "agent_missing" | "agent_invalid" | "agent_unregistered" };

/** Decodes the Metaplex Core `AssetV1` prefix. Trailing plugin data stays unread. */
function decodeCoreAsset(
  rawAccount: RawAccountInfoLike | null,
  coreProgram: SolanaAddress,
  collection: Uint8Array,
): CoreAssetDecoding {
  if (!rawAccount) return { reason: "agent_missing" };
  const account = normalizeAccountInfo(rawAccount);
  if (!account) return { reason: "agent_invalid" };
  if (account.executable || !ownerMatches(account.owner, coreProgram)) {
    return { reason: "agent_invalid" };
  }
  const data = account.data;
  // Core shrinks a burned asset to one uninitialized byte so it cannot be recreated.
  if (data.length === 1 && data[0] === CORE_KEY_UNINITIALIZED) {
    return { reason: "agent_missing" };
  }
  if (data.length < 34 || data[0] !== CORE_KEY_ASSET) {
    return { reason: "agent_invalid" };
  }
  const owner = data.subarray(1, 33);
  const updateAuthority = data[33];
  if (updateAuthority === 0 || updateAuthority === 1) {
    return { reason: "agent_unregistered" };
  }
  if (
    updateAuthority !== CORE_UPDATE_AUTHORITY_COLLECTION ||
    data.length < 66
  ) {
    return { reason: "agent_invalid" };
  }
  if (!equalBytes(data.subarray(34, 66), collection)) {
    return { reason: "agent_unregistered" };
  }
  let offset = 66;
  for (let field = 0; field < 2; field += 1) {
    const length = readLength(data, offset);
    if (length === null || offset + 4 + length > data.length) {
      return { reason: "agent_invalid" };
    }
    offset += 4 + length;
  }
  const sequence = data[offset];
  if (sequence !== 0 && !(sequence === 1 && offset + 9 <= data.length)) {
    return { reason: "agent_invalid" };
  }
  return { owner };
}

/** Decodes the fixed prefix of the 8004 registry `AgentAccount` through the agent wallet. */
function decodeAgentAccount(
  rawAccount: RawAccountInfoLike | null,
  registry: SolanaAddress,
  asset: Uint8Array,
  collection: Uint8Array,
  bump: number,
): { cachedOwner: Uint8Array; agentWallet: Uint8Array | null } | null {
  if (!rawAccount) return null;
  const account = normalizeAccountInfo(rawAccount);
  if (
    !account ||
    account.executable ||
    !ownerMatches(account.owner, registry) ||
    account.data.length !== AGENT_ACCOUNT_LENGTH
  ) {
    return null;
  }
  const data = account.data;
  if (
    !equalBytes(data.subarray(0, 8), AGENT_ACCOUNT_DISCRIMINATOR) ||
    !equalBytes(data.subarray(8, 40), collection) ||
    !equalBytes(data.subarray(104, 136), asset) ||
    data[136] !== bump ||
    (data[137] !== 0 && data[137] !== 1)
  ) {
    return null;
  }
  const walletTag = data[138];
  if (walletTag !== 0 && walletTag !== 1) return null;
  return {
    cachedOwner: data.subarray(72, 104),
    agentWallet: walletTag === 1 ? data.subarray(139, 171) : null,
  };
}

/**
 * Reads a Metaplex Core asset and its 8004 registry `AgentAccount` at one confirmed slot.
 * The Core asset decides `owner`. The registry decides `agentWallet` only while its
 * cached owner matches `owner`.
 */
export async function readAgentState(
  input: ReadAgentStateInput,
): Promise<AgentStateReadResult> {
  const invalid = (reason: AgentStateFailureReason): AgentStateReadResult => ({
    status: "invalid",
    reason,
  });
  const assetBytes = canonicalKeyBytes(input.agent);
  if (!assetBytes) return invalid("invalid_request");
  const minContextSlot = input.minContextSlot;
  if (
    minContextSlot !== undefined &&
    (!Number.isSafeInteger(minContextSlot) || minContextSlot < 0)
  ) {
    return invalid("invalid_request");
  }

  const connection = resolveSolanaConnection(input.connection);
  if (
    typeof connection.getGenesisHash !== "function" ||
    typeof connection.getMultipleAccountsInfoAndContext !== "function"
  ) {
    return { status: "unavailable", reason: "rpc_unavailable" };
  }

  const asset = new SolanaAddress(assetBytes);
  const registry = new SolanaAddress(AGENT_REGISTRY_DEVNET_CONFIG.programId);
  const coreProgram = new SolanaAddress(
    AGENT_REGISTRY_DEVNET_CONFIG.coreProgramId,
  );
  const [agentAccountAddress, bump] = deriveAgentAccountPda(asset, registry);
  const agentAccount = new SolanaAddress(agentAccountAddress);

  let genesisHash: string;
  let slot: number;
  let accounts: (RawAccountInfoLike | null)[];
  try {
    const [genesis, read] = await Promise.all([
      boundedRpc(connection.getGenesisHash()),
      boundedRpc(
        connection.getMultipleAccountsInfoAndContext([asset, agentAccount], {
          commitment: "confirmed",
          ...(minContextSlot === undefined ? {} : { minContextSlot }),
        }),
      ),
    ]);
    genesisHash = genesis;
    slot = read.context.slot;
    accounts = read.value;
  } catch {
    return { status: "unavailable", reason: "rpc_unavailable" };
  }

  if (genesisHash !== SOLANA_DEVNET_GENESIS_HASH) {
    return invalid("wrong_cluster");
  }
  if (
    !Number.isSafeInteger(slot) ||
    slot < (minContextSlot ?? 0) ||
    accounts.length !== 2
  ) {
    return invalid("agent_invalid");
  }

  const core = decodeCoreAsset(
    accounts[0] ?? null,
    coreProgram,
    COLLECTION_BYTES,
  );
  if ("reason" in core) return invalid(core.reason);

  const registered = decodeAgentAccount(
    accounts[1] ?? null,
    registry,
    assetBytes,
    COLLECTION_BYTES,
    bump,
  );
  if (!registered) return invalid("agent_invalid");

  const owner = base58Encode(core.owner);
  const cachedOwner = base58Encode(registered.cachedOwner);
  const agentWallet = registered.agentWallet
    ? base58Encode(registered.agentWallet)
    : null;

  return {
    status: "available",
    evidence: {
      cluster: "devnet",
      genesisHash,
      coreProgram: AGENT_REGISTRY_DEVNET_CONFIG.coreProgramId,
      agentRegistryProgram: AGENT_REGISTRY_DEVNET_CONFIG.programId,
      agentCollection: AGENT_REGISTRY_DEVNET_CONFIG.collection,
      agent: input.agent,
      agentAccount: agentAccount.toBase58(),
      owner,
      cachedOwner,
      agentWallet,
      agentWalletStatus:
        cachedOwner !== owner
          ? "stale"
          : agentWallet === null
            ? "unbound"
            : "bound",
      readContextSlot: slot,
    },
  };
}
