import type {
  PolicyAttestation,
  PolicyEvidence,
  PolicyProgramIds,
} from "../policy";
import {
  base58Decode,
  canonicalKeyBytes,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveMintPda,
  deriveSasAttestationPda,
  ownerMatches,
  parseSolanaAddress,
  SolanaAddress,
} from "./address";
import {
  decodeIdentityState,
  readMigrationRecord,
  SUPPORTED_IDENTITY_STATE_LENGTHS,
  type MigrationRecordRead,
} from "./accounts";
import {
  BLOCK_TIME_TOLERANCE_SECONDS,
  BN254_SCALAR_FIELD,
  CLOCK_CATCH_UP_SECONDS,
  HIGHEST_SUPPORTED_PROJECTION_VERSION,
  SAS_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_PROGRAM_IDS,
  SYSTEM_PROGRAM_ID,
} from "./constants";
import {
  boundedRpc,
  normalizeAccountInfo,
  resolveSolanaConnection,
  type RawAccountInfoLike,
  type SolanaTransport,
} from "./rpc";
import {
  commitmentHex,
  qualifyingTransaction,
  type IntegratorTransactionEvidence,
} from "./transaction";

export type IntegratorIdentityEvidence = PolicyEvidence["identity"];
export type IntegratorAttestationEvidence = PolicyAttestation;
export type IntegratorEvidence = PolicyEvidence;
export type { IntegratorTransactionEvidence };

export type IntegratorEvidenceFailureReason =
  | "unsupported_deployment"
  | "invalid_request"
  | "wrong_cluster"
  | "identity_missing"
  | "identity_invalid"
  | "transaction_invalid"
  | "transaction_unavailable"
  | "snapshot_unavailable"
  | "rpc_unavailable";

export type IntegratorEvidenceReadResult =
  | { status: "available"; evidence: IntegratorEvidence }
  | {
      status: "invalid" | "unavailable";
      reason: IntegratorEvidenceFailureReason;
    };

export interface RequestBoundDeploymentConfig {
  generation: string;
  consumerProgram: string;
  verifierProgram: string;
  deploymentDomain: string;
  genesisHash: string;
}

export interface ReadIntegratorEvidenceInput {
  /** Official policy evidence does not support isolated deployments. */
  deployment?: RequestBoundDeploymentConfig;
  walletPubkey: string;
  transactionSignature: string;
  /** RPC endpoint URL, RPC config, or duck-typed `@solana/web3.js` Connection. */
  connection: SolanaTransport;
  /** Supply a clock callback for live reads, or a fixed timestamp for deterministic snapshots. */
  nowSeconds: number | (() => number);
}

export type VerificationTransactionSearchResult =
  | { status: "found"; signature: string }
  | { status: "none" | "invalid" | "unavailable" };

export interface FindLatestVerificationTransactionInput {
  walletPubkey: string;
  /** RPC endpoint URL, RPC config, or duck-typed `@solana/web3.js` Connection. */
  connection: SolanaTransport;
  /** Without `verifiedAt`: signatures to inspect, newest first. From 1 to 25, default 10. */
  limit?: number;
  /**
   * The identity's last verification time in seconds. The search pages back to it
   * and fetches only transactions whose block time lies within the tolerance of it.
   */
  verifiedAt?: number;
  /**
   * Untrusted candidate signatures to check before paging history, up to 10.
   * Requires `verifiedAt`.
   */
  candidateSignatures?: readonly string[];
}

type ChainTimeSource = "transaction" | "identity" | "attestation";

const SIGNATURE_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{64,88}$/;
const ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/i;
const WALLET_CONNECTED_MODE = new TextEncoder().encode("wallet-connected");
const CREDENTIAL_BYTES = new SolanaAddress(
  SAS_DEVNET_CONFIG.entrosCredentialPda,
).toBytes();
const SCHEMA_BYTES = new SolanaAddress(
  SAS_DEVNET_CONFIG.entrosSchemaPda,
).toBytes();

const SEARCH_PAGE_SIZE = 1_000;
const SEARCH_MAX_PAGES = 5;
const SEARCH_MAX_CANDIDATES = 50;
const MAX_CANDIDATE_SIGNATURES = 10;

function integer(
  value: unknown,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function checkDeployment(
  deployment?: RequestBoundDeploymentConfig,
): { isolated: boolean } {
  if (deployment === undefined) return { isolated: false };
  if (typeof deployment !== "object" || deployment === null) {
    throw new Error("Invalid deployment");
  }
  const {
    generation,
    consumerProgram,
    verifierProgram,
    deploymentDomain,
    genesisHash,
  } = deployment;
  if (generation !== "request-bound-v1") {
    throw new Error("Unsupported proof deployment generation");
  }
  if (
    typeof deploymentDomain !== "string" ||
    !HEX64_PATTERN.test(deploymentDomain)
  ) {
    throw new Error("Invalid deployment domain");
  }
  if (
    typeof consumerProgram !== "string" ||
    typeof verifierProgram !== "string" ||
    !ADDRESS_PATTERN.test(consumerProgram) ||
    !ADDRESS_PATTERN.test(verifierProgram)
  ) {
    throw new Error("Invalid deployment program address");
  }
  const officialAnchor = consumerProgram === SOLANA_PROGRAM_IDS.anchor;
  const officialVerifier = verifierProgram === SOLANA_PROGRAM_IDS.verifier;
  if (
    officialAnchor !== officialVerifier ||
    consumerProgram === verifierProgram ||
    consumerProgram === SOLANA_PROGRAM_IDS.verifier ||
    verifierProgram === SOLANA_PROGRAM_IDS.anchor
  ) {
    throw new Error("Deployment requires a distinct paired Anchor and verifier");
  }
  const isolated = !officialAnchor;
  if (isolated && genesisHash !== SOLANA_DEVNET_GENESIS_HASH) {
    throw new Error("Isolated deployments require Solana devnet");
  }
  return { isolated };
}

function strictIdentity(
  rawAccount: RawAccountInfoLike,
  wallet: SolanaAddress,
  identityPda: SolanaAddress,
): IntegratorIdentityEvidence | null {
  const account = normalizeAccountInfo(rawAccount);
  if (!account) return null;
  if (
    account.executable ||
    !ownerMatches(account.owner, SOLANA_PROGRAM_IDS.anchor)
  ) {
    return null;
  }
  if (
    !(SUPPORTED_IDENTITY_STATE_LENGTHS as readonly number[]).includes(
      account.data.length,
    )
  ) {
    return null;
  }
  const state = decodeIdentityState(account.data);
  if (!state || state.owner !== wallet.toBase58()) return null;
  const commitment = commitmentHex(state.currentCommitment);
  const lastRebaseline = state.lastRebaselineTimestamp;
  if (
    !commitment ||
    lastRebaseline === undefined ||
    BigInt("0x" + commitment) === 0n ||
    BigInt("0x" + commitment) >= BN254_SCALAR_FIELD
  ) {
    return null;
  }
  if (
    !integer(state.creationTimestamp, 1) ||
    !integer(state.lastVerificationTimestamp, state.creationTimestamp)
  ) {
    return null;
  }
  if (
    !integer(state.verificationCount, 0, 0xffffffff) ||
    !integer(state.trustScore, 0, 10000)
  ) {
    return null;
  }
  if (
    !integer(state.projectionVersion, 0, HIGHEST_SUPPORTED_PROJECTION_VERSION)
  ) {
    return null;
  }
  if (
    !integer(state.lastResetTimestamp, 0, state.lastVerificationTimestamp) ||
    !integer(lastRebaseline, 0, state.lastVerificationTimestamp)
  ) {
    return null;
  }
  if (
    state.lastResetTimestamp !== 0 &&
    state.lastResetTimestamp < state.creationTimestamp
  ) {
    return null;
  }
  if (lastRebaseline !== 0 && lastRebaseline < state.creationTimestamp) {
    return null;
  }
  const [mint] = deriveMintPda(wallet);
  if (state.mint !== mint) return null;
  return {
    walletPubkey: wallet.toBase58(),
    identityPda: identityPda.toBase58(),
    creationTimestamp: state.creationTimestamp,
    lastVerificationTimestamp: state.lastVerificationTimestamp,
    verificationCount: state.verificationCount,
    trustScore: state.trustScore,
    currentCommitment: commitment,
    projectionVersion: state.projectionVersion,
    lastResetTimestamp: state.lastResetTimestamp,
    lastRebaselineTimestamp: lastRebaseline,
    mint: state.mint,
  };
}

interface AttestationContext {
  creationTimestamp: number;
  lastResetTimestamp: number;
  migration: MigrationRecordRead;
}

function strictAttestation(
  rawAccount: RawAccountInfoLike | null,
  wallet: SolanaAddress,
  address: SolanaAddress,
  slot: number,
  now: number,
  context: AttestationContext,
  onFutureAttestation: (verifiedAt: number) => void,
): IntegratorAttestationEvidence {
  if (!rawAccount) return { status: "missing" };
  const invalid = { status: "invalid" } as const;
  const account = normalizeAccountInfo(rawAccount);
  if (!account) return invalid;

  // Anyone can send lamports to this address, creating an empty System Program account.
  if (
    !account.executable &&
    ownerMatches(account.owner, SYSTEM_PROGRAM_ID) &&
    account.data.length === 0
  ) {
    return { status: "missing" };
  }
  if (
    account.executable ||
    !ownerMatches(account.owner, SAS_DEVNET_CONFIG.programId)
  ) {
    return invalid;
  }
  const raw = account.data;
  if (raw.length < 173 || raw[0] !== 2) return invalid;
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const length = view.getUint32(97, true);
  if (
    length !== 15 + WALLET_CONNECTED_MODE.length ||
    raw.length !== 173 + length
  ) {
    return invalid;
  }
  if (!equalBytes(raw.subarray(1, 33), wallet.toBytes())) return invalid;
  if (!equalBytes(raw.subarray(33, 65), CREDENTIAL_BYTES)) return invalid;
  if (!equalBytes(raw.subarray(65, 97), SCHEMA_BYTES)) return invalid;
  if (
    raw[101] !== 1 ||
    view.getUint16(102, true) > 10000 ||
    view.getUint32(112, true) !== WALLET_CONNECTED_MODE.length
  ) {
    return invalid;
  }
  if (
    !WALLET_CONNECTED_MODE.every((byte, index) => raw[116 + index] === byte)
  ) {
    return invalid;
  }
  const verifiedAt = Number(view.getBigInt64(104, true));
  const expiry = Number(view.getBigInt64(133 + length, true));
  if (!integer(verifiedAt, 1) || !integer(expiry)) return invalid;
  if (expiry !== 0 && expiry <= verifiedAt) return invalid;
  if (raw.subarray(101 + length, 133 + length).every((byte) => byte === 0)) {
    return invalid;
  }
  if (!raw.subarray(141 + length).every((byte) => byte === 0)) return invalid;
  if (context.migration.status === "invalid") return invalid;
  if (verifiedAt > now) {
    onFutureAttestation(verifiedAt);
    return invalid;
  }

  // Well-formed attestations that no longer stand for the wallet's current identity read as missing.
  if (expiry !== 0 && expiry <= now) return { status: "missing" };
  if (verifiedAt < context.lastResetTimestamp) return { status: "missing" };
  if (verifiedAt < context.creationTimestamp) return { status: "missing" };
  if (
    context.migration.status === "migrated" &&
    verifiedAt <= context.migration.migratedAt
  ) {
    return { status: "missing" };
  }
  return {
    status: "present",
    address: address.toBase58(),
    readContextSlot: slot,
    expiresAt: expiry === 0 ? null : expiry,
  };
}

async function readOnce(
  input: ReadIntegratorEvidenceInput,
  readNow: () => number | null,
  onFutureTime: (source: ChainTimeSource, time: number) => void,
): Promise<IntegratorEvidenceReadResult> {
  const { transactionSignature: signature } = input;
  let now = readNow();
  if (
    now === null ||
    typeof signature !== "string" ||
    !SIGNATURE_PATTERN.test(signature)
  ) {
    return { status: "invalid", reason: "invalid_request" };
  }
  const walletBytes = canonicalKeyBytes(input.walletPubkey);
  const signatureBytes = base58Decode(signature);
  if (!walletBytes || !signatureBytes || signatureBytes.length !== 64) {
    return { status: "invalid", reason: "invalid_request" };
  }
  const wallet = new SolanaAddress(walletBytes);
  const connection = resolveSolanaConnection(input.connection);
  if (
    typeof connection.getGenesisHash !== "function" ||
    typeof connection.getSignatureStatuses !== "function" ||
    typeof connection.getParsedTransaction !== "function" ||
    typeof connection.getAccountInfoAndContext !== "function"
  ) {
    return { status: "unavailable", reason: "rpc_unavailable" };
  }

  const [identityAddress] = deriveIdentityPda(wallet);
  const identityPda = new SolanaAddress(identityAddress);

  const [genesisHash, statuses, parsed] = await Promise.all([
    boundedRpc(connection.getGenesisHash()),
    boundedRpc(
      connection.getSignatureStatuses([signature], {
        searchTransactionHistory: true,
      }),
    ),
    boundedRpc(
      connection.getParsedTransaction(signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      }),
    ),
  ]);
  now = readNow();
  if (now === null) return { status: "invalid", reason: "invalid_request" };
  if (genesisHash !== SOLANA_DEVNET_GENESIS_HASH) {
    return { status: "invalid", reason: "wrong_cluster" };
  }
  const status = statuses.value[0];
  if (
    !status ||
    !parsed ||
    !["confirmed", "finalized"].includes(status.confirmationStatus ?? "")
  ) {
    return { status: "unavailable", reason: "transaction_unavailable" };
  }
  if (
    status.err !== null ||
    parsed.meta?.err !== null ||
    status.slot !== parsed.slot
  ) {
    return { status: "invalid", reason: "transaction_invalid" };
  }
  if (parsed.blockTime == null) {
    return { status: "unavailable", reason: "transaction_unavailable" };
  }
  if (!integer(parsed.blockTime, 1) || !integer(parsed.slot, 1)) {
    return { status: "invalid", reason: "transaction_invalid" };
  }
  const qualifying = qualifyingTransaction(
    parsed,
    signature,
    wallet,
    identityPda,
  );
  if (!qualifying) return { status: "invalid", reason: "transaction_invalid" };
  if (parsed.blockTime > now) {
    onFutureTime("transaction", parsed.blockTime);
    return { status: "invalid", reason: "transaction_invalid" };
  }
  const { projectionVersion: transactionProjection, ...transaction } =
    qualifying;

  const snapshot = await boundedRpc(
    connection.getAccountInfoAndContext(identityPda, {
      commitment: "confirmed",
      minContextSlot: transaction.slot,
    }),
  );
  now = readNow();
  if (now === null) return { status: "invalid", reason: "invalid_request" };
  if (!integer(snapshot.context.slot, transaction.slot)) {
    return { status: "unavailable", reason: "snapshot_unavailable" };
  }
  if (!snapshot.value) return { status: "invalid", reason: "identity_missing" };
  const identity = strictIdentity(snapshot.value, wallet, identityPda);
  if (!identity) return { status: "invalid", reason: "identity_invalid" };

  // The program stores its own clock, which can trail or lead RPC block time.
  const earliestClock = transaction.blockTime - BLOCK_TIME_TOLERANCE_SECONDS;
  const latestClock = transaction.blockTime + BLOCK_TIME_TOLERANCE_SECONDS;
  if (
    (transactionProjection !== undefined &&
      transactionProjection !== identity.projectionVersion) ||
    identity.lastRebaselineTimestamp >
      (transaction.kind === "rebaseline" ? latestClock : earliestClock) ||
    identity.currentCommitment !== transaction.commitment ||
    identity.lastResetTimestamp >= earliestClock ||
    identity.lastVerificationTimestamp < earliestClock ||
    identity.creationTimestamp > latestClock
  ) {
    return { status: "invalid", reason: "transaction_invalid" };
  }
  if (
    identity.verificationCount === 0 &&
    !(
      transaction.kind === "mint" &&
      identity.trustScore === 0 &&
      identity.creationTimestamp === identity.lastVerificationTimestamp &&
      identity.lastVerificationTimestamp >= earliestClock &&
      identity.lastVerificationTimestamp <= latestClock &&
      identity.lastResetTimestamp === 0 &&
      identity.lastRebaselineTimestamp === 0
    )
  ) {
    return { status: "invalid", reason: "identity_invalid" };
  }
  if (identity.lastVerificationTimestamp > now) {
    onFutureTime("identity", identity.lastVerificationTimestamp);
    return { status: "invalid", reason: "identity_invalid" };
  }

  const [attestationAddress] = deriveSasAttestationPda(wallet);
  const attestationPda = new SolanaAddress(attestationAddress);
  const [migrationAddress] = deriveMigrationRecordPda(wallet);
  const migrationPda = new SolanaAddress(migrationAddress);
  const anchorProgram = new SolanaAddress(SOLANA_PROGRAM_IDS.anchor);

  let attestation: IntegratorAttestationEvidence;
  try {
    const [account, migration] = await Promise.all([
      boundedRpc(
        connection.getAccountInfoAndContext(attestationPda, {
          commitment: "confirmed",
          minContextSlot: snapshot.context.slot,
        }),
      ),
      boundedRpc(
        connection.getAccountInfoAndContext(migrationPda, {
          commitment: "confirmed",
          minContextSlot: snapshot.context.slot,
        }),
      ),
    ]);
    now = readNow();
    if (now === null) return { status: "invalid", reason: "invalid_request" };
    attestation =
      integer(account.context.slot, snapshot.context.slot) &&
      integer(migration.context.slot, snapshot.context.slot)
        ? strictAttestation(
            account.value,
            wallet,
            attestationPda,
            account.context.slot,
            now,
            {
              creationTimestamp: identity.creationTimestamp,
              lastResetTimestamp: identity.lastResetTimestamp,
              migration: readMigrationRecord(migration.value, anchorProgram),
            },
            (verifiedAt) => onFutureTime("attestation", verifiedAt),
          )
        : { status: "unavailable" };
  } catch {
    attestation = { status: "unavailable" };
  }
  if (readNow() === null) {
    return { status: "invalid", reason: "invalid_request" };
  }
  const programIds: PolicyProgramIds = { ...SOLANA_PROGRAM_IDS };
  return {
    status: "available",
    evidence: {
      identity,
      transaction,
      attestation,
      readContextSlot: snapshot.context.slot,
      genesisHash,
      cluster: "devnet",
      assuranceTier: "browser_unattested",
      uniquenessStatus: "unmeasured",
      programIds,
    },
  };
}

/** Waits for the local clock to reach a chain time within one shared budget. */
async function waitForChainClock(
  target: number,
  readNow: () => number | null,
  startedAt: number,
): Promise<"ready" | "timeout" | "invalid"> {
  const budgetMs = CLOCK_CATCH_UP_SECONDS * 1000;
  while (true) {
    const now = readNow();
    if (now === null) return "invalid";
    const remainingMs = budgetMs - (performance.now() - startedAt);
    if (remainingMs < 0 || (target - now) * 1000 > remainingMs) {
      return "timeout";
    }
    if (now >= target) return "ready";
    await new Promise<void>((resolve) => {
      setTimeout(resolve, Math.min(remainingMs, (target - now) * 1000));
    });
  }
}

/**
 * Reads confirmed Solana devnet verification evidence for a wallet and
 * transaction without submitting transactions or modifying on-chain state.
 */
export async function readIntegratorEvidence(
  input: ReadIntegratorEvidenceInput,
): Promise<IntegratorEvidenceReadResult> {
  try {
    if (checkDeployment(input.deployment).isolated) {
      return { status: "invalid", reason: "unsupported_deployment" };
    }
  } catch {
    return { status: "invalid", reason: "invalid_request" };
  }
  let previousNow = 0;
  const readNow = (): number | null => {
    try {
      const now =
        typeof input.nowSeconds === "function"
          ? input.nowSeconds()
          : input.nowSeconds;
      if (!integer(now, 1) || now < previousNow) return null;
      previousNow = now;
      return now;
    } catch {
      return null;
    }
  };
  let propagationRetried = false;
  const waited = new Set<ChainTimeSource>();
  let clockStartedAt: number | null = null;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      const pending: { source: ChainTimeSource; time: number }[] = [];
      const result = await readOnce(input, readNow, (source, time) => {
        pending.push({ source, time });
      });
      const future = pending[0];
      if (
        future !== undefined &&
        typeof input.nowSeconds === "function" &&
        !waited.has(future.source)
      ) {
        waited.add(future.source);
        clockStartedAt ??= performance.now();
        const clock = await waitForChainClock(
          future.time,
          readNow,
          clockStartedAt,
        );
        if (clock === "invalid") {
          return { status: "invalid", reason: "invalid_request" };
        }
        if (clock === "ready") continue;
        return result;
      }
      if (result.status === "invalid") return result;
      if (result.status !== "unavailable" || propagationRetried) return result;
      propagationRetried = true;
    } catch {
      return { status: "unavailable", reason: "rpc_unavailable" };
    }
  }
  return { status: "unavailable", reason: "rpc_unavailable" };
}

/**
 * Finds the newest confirmed Entros transaction that qualifies as verification
 * evidence for a wallet. Pass the returned signature to `readIntegratorEvidence`.
 */
export async function findLatestVerificationTransaction(
  input: FindLatestVerificationTransactionInput,
): Promise<VerificationTransactionSearchResult> {
  const limit = input.limit ?? 10;
  if (!integer(limit, 1, 25)) return { status: "invalid" };
  const { verifiedAt, candidateSignatures = [] } = input;
  if (verifiedAt !== undefined && !integer(verifiedAt, 1)) {
    return { status: "invalid" };
  }
  if (
    !Array.isArray(candidateSignatures) ||
    candidateSignatures.length > MAX_CANDIDATE_SIGNATURES ||
    (candidateSignatures.length > 0 && verifiedAt === undefined) ||
    !candidateSignatures.every(
      (signature) =>
        typeof signature === "string" && SIGNATURE_PATTERN.test(signature),
    )
  ) {
    return { status: "invalid" };
  }
  const wallet = parseSolanaAddress(input.walletPubkey);
  if (!wallet || wallet.toBase58() !== input.walletPubkey) {
    return { status: "invalid" };
  }
  const connection = resolveSolanaConnection(input.connection);
  if (
    typeof connection.getSignaturesForAddress !== "function" ||
    typeof connection.getParsedTransaction !== "function"
  ) {
    return { status: "unavailable" };
  }
  const [identityAddress] = deriveIdentityPda(wallet);
  const identityPda = new SolanaAddress(identityAddress);

  const qualifyingAt = async (signature: string): Promise<number | null> => {
    const parsed = await boundedRpc(
      connection.getParsedTransaction!(signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      }),
    );
    if (parsed === null) return null;
    const qualifying = qualifyingTransaction(
      parsed,
      signature,
      wallet,
      identityPda,
    );
    return qualifying === null ? null : qualifying.blockTime;
  };
  const qualifies = async (signature: string): Promise<boolean> =>
    (await qualifyingAt(signature)) !== null;

  if (verifiedAt !== undefined) {
    for (const signature of candidateSignatures) {
      try {
        const blockTime = await qualifyingAt(signature);
        if (
          blockTime !== null &&
          Math.abs(blockTime - verifiedAt) <= BLOCK_TIME_TOLERANCE_SECONDS
        ) {
          return { status: "found", signature };
        }
      } catch {
        // Untrusted candidate failures fall through to history search.
      }
    }
  }

  try {
    if (verifiedAt === undefined) {
      const signatures = await boundedRpc(
        connection.getSignaturesForAddress(identityPda, { limit }, "confirmed"),
      );
      for (const entry of signatures.slice(0, limit)) {
        if (entry.err === null && (await qualifies(entry.signature))) {
          return { status: "found", signature: entry.signature };
        }
      }
      return { status: "none" };
    }

    const earliest = verifiedAt - BLOCK_TIME_TOLERANCE_SECONDS;
    const latest = verifiedAt + BLOCK_TIME_TOLERANCE_SECONDS;
    let before: string | undefined;
    let candidates = 0;
    for (let page = 0; page < SEARCH_MAX_PAGES; page += 1) {
      const signatures = await boundedRpc(
        connection.getSignaturesForAddress(
          identityPda,
          { limit: SEARCH_PAGE_SIZE, before },
          "confirmed",
        ),
      );
      for (const entry of signatures) {
        if (entry.blockTime == null) continue;
        if (entry.blockTime < earliest) return { status: "none" };
        if (entry.blockTime > latest || entry.err !== null) continue;
        if (candidates >= SEARCH_MAX_CANDIDATES) {
          return { status: "unavailable" };
        }
        candidates += 1;
        if (await qualifies(entry.signature)) {
          return { status: "found", signature: entry.signature };
        }
      }
      const last = signatures[signatures.length - 1];
      if (signatures.length < SEARCH_PAGE_SIZE || last === undefined) {
        return { status: "none" };
      }
      before = last.signature;
    }
    return { status: "unavailable" };
  } catch {
    return { status: "unavailable" };
  }
}
