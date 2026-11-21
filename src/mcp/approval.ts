import {
  AGENT_PERMIT_LIMITS,
  agentPermitId,
  createAgentPermitRequest,
  encodeAgentPermitFragment,
  evaluateAgentPermit,
  parseAgentPermitSettlement,
  precheckAgentPermit,
  renderAgentPermitMessage,
  type AgentPermitDenyReason,
  type AgentPermitRequest,
  type AgentStateEvidence,
  type AgentStateReadResult,
} from "../agent-permit";
import {
  encodePolicyRequest,
  normalizePolicyRequest,
  policyResultToWire,
  type PolicyEvidenceReadResult,
  type PolicyRequest,
  type PolicyRequestInput,
  type PolicyResult,
  type PolicyWireResult,
} from "../policy";
import {
  readAgentState as defaultReadAgentState,
  readIntegratorEvidence as defaultReadIntegratorEvidence,
  type SolanaTransport,
} from "../solana";
import {
  canonicalizeMcpAction,
  type CanonicalMcpAction,
  type McpToolActionInput,
} from "./canonical";
import type { McpNonceStore } from "./nonce-store";

export const DEFAULT_MCP_APPROVAL_BASE_URL = "https://entros.io/agents";
export const DEFAULT_MCP_LIFETIME_SECONDS = 300;
export const MCP_ASSURANCE_NOTICE =
  "Owner-signed approval under browser_unattested assurance. Grants authority for one later action and does not prove human presence at agent execution time.";

export interface McpApprovalAssuranceDisclosure {
  tier: "browser_unattested";
  uniqueness: "unmeasured";
  executionPresenceProven: false;
  notice: string;
}

export interface McpActorIdentity {
  /** 8004 Metaplex Core asset address. */
  agent: string;
  /** Bound 8004 agent signing wallet address. */
  agentWallet: string;
}

export interface McpApprovalChallenge {
  version: 1;
  permitId: string;
  nonce: string;
  /** Owner wallet controlling the 8004 Metaplex Core asset. */
  subject: string;
  /** Registered 8004 agent identity and bound signing wallet. */
  actor: McpActorIdentity;
  audience: string;
  cluster: "devnet";
  action: CanonicalMcpAction;
  policy: PolicyRequest;
  issuedAt: number;
  expiresAt: number;
  request: AgentPermitRequest;
  /** Seventeen-line ASCII permit message signed by the owner wallet. */
  message: string;
  /** URL fragment (`request=...`) for the Entros signing page. */
  fragment: string;
  /** Full signing URL combining `approvalBaseUrl` and `fragment`. */
  approvalUrl: string;
  assurance: McpApprovalAssuranceDisclosure;
}

export interface CreateMcpApprovalChallengeInput {
  /**
   * Owner wallet controlling the 8004 Core asset. Required when neither
   * `connection` nor `readAgentState` is provided; verified against live Core
   * ownership when a chain reader is provided.
   */
  subject?: string;
  actor: {
    /** Metaplex Core asset address of the 8004 agent. */
    agent: string;
    /** Bound agent wallet address. Required offline; verified on-chain when reading live state. */
    agentWallet?: string;
  };
  /** Strict HTTPS or `http://127.0.0.1` audience URL (<= 200 chars). */
  audience: string;
  /** MCP tool invocation to bind to the permit's `action.sha256`. */
  action: McpToolActionInput;
  /** Integrator Policy v1 requirements. Defaults to normalized devnet policy if omitted. */
  policy?: PolicyRequestInput;
  /** Permit lifetime in seconds (`30..900`). Default 300. */
  lifetimeSeconds?: number;
  /** Current Unix timestamp in seconds or clock callback. Defaults to `Math.floor(Date.now() / 1000)`. */
  nowSeconds?: number | (() => number);
  /** Optional 64-hex random nonce override (for deterministic testing). */
  nonce?: string;
  /** Signing page base URL. Default `"https://entros.io/agents"`. */
  approvalBaseUrl?: string;
  /** Optional Solana transport for live 8004 agent lookup at challenge creation. */
  connection?: SolanaTransport;
  /** Optional custom `readAgentState` reader overriding `connection`. */
  readAgentState?: (input: { agent: string }) => Promise<AgentStateReadResult>;
  /** Optional nonce store to register the pending challenge atomically. */
  nonceStore?: McpNonceStore;
}

export type McpApprovalDenyReason =
  | AgentPermitDenyReason
  | "invalid_request"
  | "nonce_not_found"
  | "nonce_replayed"
  | "audience_mismatch"
  | "action_mismatch"
  | "subject_mismatch"
  | "actor_mismatch"
  | "approval_rejected";

export type McpApprovalUnavailableReason =
  | "agent_unavailable"
  | "state_unavailable";

export interface McpApprovalSettlementAllow {
  decision: "allow";
  reason: "accepted";
  permitId: string;
  nonce: string;
  subject: string;
  actor: McpActorIdentity;
  audience: string;
  action: CanonicalMcpAction;
  /** Original `IdentityState.lastVerificationTimestamp`. Never reset by permit issuance. */
  verifiedAt: number;
  /** Conservative evidence timestamp (`min(lastVerificationTimestamp, transaction.blockTime)`). */
  evidenceTimestamp: number;
  evaluatedAt: number;
  expiresAt: number;
  trustScore: number;
  assuranceTier: "browser_unattested";
  uniquenessStatus: "unmeasured";
  executionPresenceProven: false;
  agentState: AgentStateEvidence;
  policy: PolicyResult & { decision: "allow" };
  policyWire: PolicyWireResult;
}

export interface McpApprovalSettlementDeny {
  decision: "deny";
  reason: McpApprovalDenyReason;
  permitId: string | null;
  nonce: string | null;
  evaluatedAt: number | null;
  agentState: AgentStateEvidence | null;
  policy: PolicyResult | null;
}

export interface McpApprovalSettlementUnavailable {
  decision: "unavailable";
  reason: McpApprovalUnavailableReason;
  permitId: string | null;
  nonce: string | null;
  evaluatedAt: number | null;
  agentState: AgentStateEvidence | null;
  policy: PolicyResult | null;
}

export type McpApprovalSettlementResult =
  | McpApprovalSettlementAllow
  | McpApprovalSettlementDeny
  | McpApprovalSettlementUnavailable;

export interface VerifyMcpApprovalSettlementInput {
  /** Settlement bundle (`version`, `nonce`, `operatorSignature`, `presentationSignature`, `verifiedTransaction`) as object or JSON string. */
  settlement: unknown;
  /** Atomic single-use nonce store holding the issued challenge. */
  nonceStore: McpNonceStore;
  /** Optional explicit challenge cross-check against the stored record. */
  challenge?: McpApprovalChallenge;
  /** Expected audience URL; rejects settlement if the stored challenge differs. */
  expectedAudience?: string;
  /** Expected tool invocation; recomputes canonical `action.sha256` and rejects any modification. */
  expectedAction?: McpToolActionInput;
  /** Expected owner wallet (`subject`). */
  expectedSubject?: string;
  /** Expected 8004 agent (`actor`). */
  expectedActor?: { agent: string; agentWallet?: string };
  /** Expected Integrator Policy v1 requirements. */
  expectedPolicy?: PolicyRequestInput;
  /** Solana transport used by default live `readAgentState` and `readIntegratorEvidence`. */
  connection?: SolanaTransport;
  /** Custom agent state reader (defaults to `@entros/verify/solana` `readAgentState` using `connection`). */
  readAgentState?: (input: { agent: string }) => Promise<AgentStateReadResult>;
  /** Custom operator evidence reader (defaults to `@entros/verify/solana` `readIntegratorEvidence` using `connection`). */
  readIntegratorEvidence?: (input: {
    walletPubkey: string;
    transactionSignature: string;
    nowSeconds: number | (() => number);
  }) => Promise<PolicyEvidenceReadResult>;
  /** Current Unix timestamp in seconds or monotonic clock callback. Defaults to `() => Math.floor(Date.now() / 1000)`. */
  nowSeconds?: number | (() => number);
}

export class McpApprovalError extends Error {
  constructor(
    public readonly reason: string,
    message?: string,
  ) {
    super(message ?? `MCP approval error: ${reason}`);
    this.name = "McpApprovalError";
  }
}

function readClockValue(
  clock?: number | (() => number),
  previous = 0,
): number | null {
  try {
    const value =
      clock === undefined
        ? Math.floor(Date.now() / 1000)
        : typeof clock === "function"
          ? clock()
          : clock;
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < AGENT_PERMIT_LIMITS.minTimeSeconds ||
      value > AGENT_PERMIT_LIMITS.maxTimeSeconds ||
      value < previous
    ) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

function normalizeApprovalBaseUrl(value?: string): string {
  const raw = value ?? DEFAULT_MCP_APPROVAL_BASE_URL;
  if (typeof raw !== "string" || raw.includes("#")) {
    throw new McpApprovalError("invalid_approval_url");
  }
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new McpApprovalError("invalid_approval_url");
  }
  const isHttps = parsed.protocol === "https:";
  const isLoopback =
    parsed.protocol === "http:" && parsed.hostname === "127.0.0.1";
  if (!isHttps && !isLoopback) {
    throw new McpApprovalError("invalid_approval_url");
  }
  return raw;
}

/**
 * Creates a single-use `AgentPermit` v1 approval challenge bound to an MCP tool
 * call's canonical `action.sha256`, subject (Core asset owner), actor (8004 asset
 * and bound agent wallet), audience, devnet policy, and `<= 900 s` expiry.
 */
export async function createMcpApprovalChallenge(
  input: CreateMcpApprovalChallengeInput,
): Promise<McpApprovalChallenge> {
  const issuedAt = readClockValue(input.nowSeconds);
  if (issuedAt === null) {
    throw new McpApprovalError("invalid_clock", "Invalid challenge clock");
  }

  const lifetimeSeconds = input.lifetimeSeconds ?? DEFAULT_MCP_LIFETIME_SECONDS;
  if (
    typeof lifetimeSeconds !== "number" ||
    !Number.isSafeInteger(lifetimeSeconds) ||
    lifetimeSeconds < AGENT_PERMIT_LIMITS.minLifetimeSeconds ||
    lifetimeSeconds > AGENT_PERMIT_LIMITS.maxLifetimeSeconds
  ) {
    throw new McpApprovalError(
      "invalid_lifetime",
      `Permit lifetime must be between ${AGENT_PERMIT_LIMITS.minLifetimeSeconds} and ${AGENT_PERMIT_LIMITS.maxLifetimeSeconds} seconds`,
    );
  }

  const action = canonicalizeMcpAction(input.action);
  const policy = normalizePolicyRequest(input.policy);
  const approvalBaseUrl = normalizeApprovalBaseUrl(input.approvalBaseUrl);

  let subject = input.subject;
  let agentWallet = input.actor.agentWallet;

  const agentReader =
    input.readAgentState ??
    (input.connection !== undefined
      ? ({ agent }: { agent: string }) =>
          defaultReadAgentState({ agent, connection: input.connection! })
      : undefined);

  if (agentReader !== undefined) {
    let state: AgentStateReadResult;
    try {
      state = await agentReader({ agent: input.actor.agent });
    } catch {
      throw new McpApprovalError("agent_unavailable");
    }
    if (state.status === "unavailable") {
      throw new McpApprovalError("agent_unavailable");
    }
    if (state.status !== "available") {
      throw new McpApprovalError(state.reason);
    }
    const { evidence } = state;
    if (evidence.agent !== input.actor.agent) {
      throw new McpApprovalError("agent_invalid");
    }
    if (evidence.agentWalletStatus === "stale") {
      throw new McpApprovalError("agent_wallet_stale");
    }
    if (
      evidence.agentWalletStatus === "unbound" ||
      evidence.agentWallet === null
    ) {
      throw new McpApprovalError("agent_wallet_unbound");
    }
    if (subject !== undefined && subject !== evidence.owner) {
      throw new McpApprovalError("owner_changed");
    }
    if (agentWallet !== undefined && agentWallet !== evidence.agentWallet) {
      throw new McpApprovalError("agent_wallet_changed");
    }
    subject = evidence.owner;
    agentWallet = evidence.agentWallet;
  }

  if (subject === undefined || agentWallet === undefined) {
    throw new McpApprovalError(
      "invalid_request",
      "Both subject and actor.agentWallet are required when no Solana reader is provided",
    );
  }

  const request = createAgentPermitRequest({
    agent: input.actor.agent,
    agentWallet,
    operator: subject,
    audience: input.audience,
    action: { label: action.label, sha256: action.sha256 },
    policy,
    issuedAt,
    lifetimeSeconds,
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
  });

  const message = renderAgentPermitMessage(request);
  const permitId = agentPermitId(request);
  const fragment = encodeAgentPermitFragment(request);

  const challenge: McpApprovalChallenge = {
    version: 1,
    permitId,
    nonce: request.nonce,
    subject: request.operator,
    actor: {
      agent: request.agent,
      agentWallet: request.agentWallet,
    },
    audience: request.audience,
    cluster: "devnet",
    action,
    policy: request.policy,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    request,
    message,
    fragment,
    approvalUrl: `${approvalBaseUrl}#${fragment}`,
    assurance: {
      tier: "browser_unattested",
      uniqueness: "unmeasured",
      executionPresenceProven: false,
      notice: MCP_ASSURANCE_NOTICE,
    },
  };

  if (input.nonceStore !== undefined) {
    await input.nonceStore.register(challenge);
  }

  return challenge;
}

/**
 * Verifies an MCP approval settlement bundle before resuming a paused tool call.
 *
 * All non-mutating checks (bundle shape, expected audience/action/subject/actor/policy,
 * expiry, strict Ed25519 signatures, live Metaplex Core ownership, current Entros
 * evidence, and policy evaluation) run before atomic nonce consumption so failed
 * or forged attempts cannot burn a valid pending nonce.
 */
export async function verifyMcpApprovalSettlement(
  input: VerifyMcpApprovalSettlementInput,
): Promise<McpApprovalSettlementResult> {
  const deny = (
    reason: McpApprovalDenyReason,
    context: {
      permitId?: string | null;
      nonce?: string | null;
      evaluatedAt?: number | null;
      agentState?: AgentStateEvidence | null;
      policy?: PolicyResult | null;
    } = {},
  ): McpApprovalSettlementDeny => ({
    decision: "deny",
    reason,
    permitId: context.permitId ?? null,
    nonce: context.nonce ?? null,
    evaluatedAt: context.evaluatedAt ?? null,
    agentState: context.agentState ?? null,
    policy: context.policy ?? null,
  });

  const unavailable = (
    reason: McpApprovalUnavailableReason,
    context: {
      permitId?: string | null;
      nonce?: string | null;
      evaluatedAt?: number | null;
      agentState?: AgentStateEvidence | null;
      policy?: PolicyResult | null;
    } = {},
  ): McpApprovalSettlementUnavailable => ({
    decision: "unavailable",
    reason,
    permitId: context.permitId ?? null,
    nonce: context.nonce ?? null,
    evaluatedAt: context.evaluatedAt ?? null,
    agentState: context.agentState ?? null,
    policy: context.policy ?? null,
  });

  const precheckNow = readClockValue(input.nowSeconds);
  if (precheckNow === null) {
    return deny("invalid_request");
  }

  const bundle = parseAgentPermitSettlement(input.settlement);
  if (!bundle) {
    return deny("invalid_request", { evaluatedAt: precheckNow });
  }

  if (
    !input.nonceStore ||
    typeof input.nonceStore.peek !== "function" ||
    typeof input.nonceStore.consume !== "function"
  ) {
    return deny("invalid_request", {
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  let storedRecord;
  try {
    storedRecord = await input.nonceStore.peek(bundle.nonce);
  } catch {
    return unavailable("state_unavailable", {
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  if (!storedRecord) {
    return deny("nonce_not_found", {
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }
  if (storedRecord.consumedAt !== null) {
    return deny("nonce_replayed", {
      permitId: storedRecord.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  const challenge = storedRecord.challenge;
  if (
    input.challenge !== undefined &&
    (input.challenge.nonce !== storedRecord.nonce ||
      input.challenge.permitId !== storedRecord.permitId ||
      input.challenge.action.sha256 !== challenge.action.sha256 ||
      input.challenge.audience !== challenge.audience ||
      input.challenge.subject !== challenge.subject ||
      input.challenge.actor.agent !== challenge.actor.agent ||
      input.challenge.actor.agentWallet !== challenge.actor.agentWallet)
  ) {
    return deny("request_mismatch", {
      permitId: storedRecord.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  // Validate non-mutating expected bindings before any RPC call or nonce consumption.
  if (
    input.expectedAudience !== undefined &&
    (input.expectedAudience !== challenge.audience ||
      input.expectedAudience !== challenge.request.audience)
  ) {
    return deny("audience_mismatch", {
      permitId: challenge.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  if (
    input.expectedSubject !== undefined &&
    (input.expectedSubject !== challenge.subject ||
      input.expectedSubject !== challenge.request.operator)
  ) {
    return deny("subject_mismatch", {
      permitId: challenge.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  if (input.expectedActor !== undefined) {
    if (
      input.expectedActor.agent !== challenge.actor.agent ||
      input.expectedActor.agent !== challenge.request.agent
    ) {
      return deny("actor_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
    if (
      input.expectedActor.agentWallet !== undefined &&
      (input.expectedActor.agentWallet !== challenge.actor.agentWallet ||
        input.expectedActor.agentWallet !== challenge.request.agentWallet)
    ) {
      return deny("actor_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
  }

  if (input.expectedAction !== undefined) {
    let expectedCanonical: CanonicalMcpAction;
    try {
      expectedCanonical = canonicalizeMcpAction(input.expectedAction);
    } catch {
      return deny("action_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
    if (
      expectedCanonical.sha256 !== challenge.action.sha256 ||
      expectedCanonical.sha256 !== challenge.request.action.sha256
    ) {
      return deny("action_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
  }

  if (input.expectedPolicy !== undefined) {
    let expectedEncoded: string;
    try {
      expectedEncoded = encodePolicyRequest(
        normalizePolicyRequest(input.expectedPolicy),
      );
    } catch {
      return deny("request_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
    if (expectedEncoded !== encodePolicyRequest(challenge.request.policy)) {
      return deny("request_mismatch", {
        permitId: challenge.permitId,
        nonce: bundle.nonce,
        evaluatedAt: precheckNow,
      });
    }
  }

  const signatures = {
    operatorSignature: bundle.operatorSignature,
    presentationSignature: bundle.presentationSignature,
  };

  // Zero-RPC precheck catches expired or forged permits without touching chain or nonce state.
  const precheck = precheckAgentPermit({
    request: challenge.request,
    ...signatures,
    nowSeconds: precheckNow,
  });
  if (!precheck.ok) {
    return deny(precheck.reason, {
      permitId: precheck.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }
  if (
    precheck.permitId !== challenge.permitId ||
    precheck.permitId !== storedRecord.permitId
  ) {
    return deny("request_mismatch", {
      permitId: precheck.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  const agentReader =
    input.readAgentState ??
    (input.connection !== undefined
      ? ({ agent }: { agent: string }) =>
          defaultReadAgentState({ agent, connection: input.connection! })
      : undefined);

  const evidenceReader =
    input.readIntegratorEvidence ??
    (input.connection !== undefined
      ? ({
          walletPubkey,
          transactionSignature,
          nowSeconds,
        }: {
          walletPubkey: string;
          transactionSignature: string;
          nowSeconds: number | (() => number);
        }) =>
          defaultReadIntegratorEvidence({
            walletPubkey,
            transactionSignature,
            connection: input.connection!,
            nowSeconds,
          })
      : undefined);

  if (!agentReader || !evidenceReader) {
    return unavailable("state_unavailable", {
      permitId: precheck.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  const liveClock: number | (() => number) =
    input.nowSeconds ?? (() => Math.floor(Date.now() / 1000));

  let agentState: AgentStateReadResult;
  let operatorEvidence: PolicyEvidenceReadResult;
  try {
    [agentState, operatorEvidence] = await Promise.all([
      agentReader({ agent: challenge.request.agent }),
      evidenceReader({
        walletPubkey: challenge.request.operator,
        transactionSignature: bundle.verifiedTransaction,
        nowSeconds: liveClock,
      }),
    ]);
  } catch {
    return unavailable("state_unavailable", {
      permitId: precheck.permitId,
      nonce: bundle.nonce,
      evaluatedAt: precheckNow,
    });
  }

  // Sample the clock again after async chain reads so permits that expired mid-flight fail.
  const postReadNow = readClockValue(input.nowSeconds, precheckNow);
  if (postReadNow === null) {
    return deny("invalid_request", {
      permitId: precheck.permitId,
      nonce: bundle.nonce,
    });
  }

  const evaluation = evaluateAgentPermit({
    request: challenge.request,
    ...signatures,
    agentState,
    operatorEvidence,
    nowSeconds: postReadNow,
    expected: {
      nonce: challenge.nonce,
      agent: challenge.actor.agent,
      operator: challenge.subject,
      audience: challenge.audience,
      action: {
        label: challenge.action.label,
        sha256: challenge.action.sha256,
      },
      policy: challenge.policy,
    },
  });

  if (evaluation.decision === "unavailable") {
    return unavailable(evaluation.reason, {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }
  if (evaluation.decision !== "allow") {
    return deny(evaluation.reason, {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }

  if (
    evaluation.permitId === null ||
    evaluation.agentState === null ||
    evaluation.policy === null ||
    evaluation.policy.decision !== "allow" ||
    evaluation.expiresAt === null ||
    evaluation.policy.evidenceTimestamp === null
  ) {
    return deny("invalid_evidence", {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }

  // Every check passed. Consume the single-use nonce atomically last.
  let consumed;
  try {
    consumed = await input.nonceStore.consume({
      nonce: bundle.nonce,
      permitId: evaluation.permitId,
      nowSeconds: postReadNow,
    });
  } catch {
    return unavailable("state_unavailable", {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }

  if (consumed.status === "already_consumed") {
    return deny("nonce_replayed", {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }
  if (consumed.status === "expired") {
    return deny("permit_expired", {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }
  if (consumed.status !== "consumed") {
    return deny("nonce_not_found", {
      permitId: evaluation.permitId,
      nonce: bundle.nonce,
      evaluatedAt: evaluation.evaluatedAt,
      agentState: evaluation.agentState,
      policy: evaluation.policy,
    });
  }

  return {
    decision: "allow",
    reason: "accepted",
    permitId: evaluation.permitId,
    nonce: bundle.nonce,
    subject: challenge.request.operator,
    actor: {
      agent: challenge.request.agent,
      agentWallet: challenge.request.agentWallet,
    },
    audience: challenge.request.audience,
    action: challenge.action,
    verifiedAt: evaluation.policy.evidence.identity.lastVerificationTimestamp,
    evidenceTimestamp: evaluation.policy.evidenceTimestamp,
    evaluatedAt: evaluation.evaluatedAt,
    expiresAt: evaluation.expiresAt,
    trustScore: evaluation.policy.evidence.identity.trustScore,
    assuranceTier: "browser_unattested",
    uniquenessStatus: "unmeasured",
    executionPresenceProven: false,
    agentState: evaluation.agentState,
    policy: evaluation.policy,
    policyWire: policyResultToWire(evaluation.policy),
  };
}
