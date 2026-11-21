import type { AgentStateReadResult } from "../agent-permit";
import type { PolicyEvidenceReadResult, PolicyRequestInput } from "../policy";
import type { SolanaTransport } from "../solana";
import {
  createMcpApprovalChallenge,
  McpApprovalError,
  verifyMcpApprovalSettlement,
  type CreateMcpApprovalChallengeInput,
  type McpApprovalChallenge,
  type McpApprovalSettlementResult,
  type VerifyMcpApprovalSettlementInput,
} from "./approval";
import { canonicalizeJson, type McpToolActionInput } from "./canonical";
import { createInMemoryNonceStore, type McpNonceStore } from "./nonce-store";

/** OpenAI Responses API `mcp_approval_request` item. */
export interface OpenAiMcpApprovalRequest {
  type: "mcp_approval_request";
  id: string;
  server_label: string;
  name: string;
  /** JSON-encoded arguments object for the MCP tool call. */
  arguments: string;
}

/** OpenAI Responses API `mcp_approval_response` item. */
export interface OpenAiMcpApprovalResponse {
  type: "mcp_approval_response";
  approval_request_id: string;
  approve: boolean;
  reason?: string;
}

export interface OpenAiMcpApprovalChallengeEnvelope {
  approvalRequestId: string;
  approvalRequest: OpenAiMcpApprovalRequest;
  challenge: McpApprovalChallenge;
}

export interface OpenAiMcpApprovalSettlementEnvelope {
  approvalRequestId: string;
  settlement: McpApprovalSettlementResult;
  response: OpenAiMcpApprovalResponse;
}

/** HumanLayer (Apache-2.0) paused function call specification. */
export interface HumanLayerEntrosState {
  version: 1;
  permitId: string;
  nonce: string;
  approvalUrl: string;
  expiresAt: number;
  actionSha256: string;
  cluster: "devnet";
  assuranceTier: "browser_unattested";
  uniquenessStatus: "unmeasured";
  executionPresenceProven: false;
}

export interface HumanLayerApprovalCall {
  run_id: string;
  call_id: string;
  spec: {
    fn: string;
    kwargs: Record<string, unknown>;
    state: Record<string, unknown> & { entros: HumanLayerEntrosState };
  };
}

export interface HumanLayerCallbackPayload {
  run_id: string;
  call_id: string;
  spec: {
    fn: string;
    kwargs: Record<string, unknown>;
    state?: Record<string, unknown>;
  };
  status: {
    approved: boolean | null;
    comment?: string | null;
    responded_at?: string | null;
    entrosSettlement?: unknown;
    metadata?: Record<string, unknown>;
  };
}

export interface HumanLayerCallbackVerificationResult {
  runId: string;
  callId: string;
  resume: boolean;
  settlement: McpApprovalSettlementResult;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function parseOpenAiArguments(raw: unknown): Record<string, unknown> | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  return isPlainRecord(parsed) ? parsed : null;
}

function parseOpenAiRequestAction(
  request: unknown,
): { id: string; action: McpToolActionInput } | null {
  if (!isPlainRecord(request)) return null;
  if (
    request.type !== "mcp_approval_request" ||
    typeof request.id !== "string" ||
    request.id.trim().length === 0 ||
    typeof request.server_label !== "string" ||
    typeof request.name !== "string"
  ) {
    return null;
  }
  const args = parseOpenAiArguments(request.arguments);
  if (!args) return null;
  return {
    id: request.id,
    action: {
      server: request.server_label,
      tool: request.name,
      arguments: args,
    },
  };
}

/**
 * Formats an Entros MCP approval challenge as an OpenAI `mcp_approval_request`.
 */
export function toOpenAiMcpApprovalRequest(
  challenge: McpApprovalChallenge,
  options?: { id?: string },
): OpenAiMcpApprovalRequest {
  return {
    type: "mcp_approval_request",
    id: options?.id ?? `mcpr_${challenge.permitId.slice(0, 24)}`,
    server_label: challenge.action.server,
    name: challenge.action.tool,
    arguments: canonicalizeJson(challenge.action.arguments),
  };
}

/**
 * Creates an Entros single-use `AgentPermit` challenge from an OpenAI
 * `mcp_approval_request`, binding the server label, tool name, and arguments.
 */
export async function createChallengeFromOpenAiMcpRequest(
  approvalRequest: OpenAiMcpApprovalRequest,
  options: Omit<CreateMcpApprovalChallengeInput, "action"> & { label?: string },
): Promise<OpenAiMcpApprovalChallengeEnvelope> {
  const parsed = parseOpenAiRequestAction(approvalRequest);
  if (!parsed) {
    throw new McpApprovalError(
      "invalid_request",
      "Invalid OpenAI mcp_approval_request payload",
    );
  }
  const challenge = await createMcpApprovalChallenge({
    ...options,
    action: {
      ...parsed.action,
      ...(options.label !== undefined ? { label: options.label } : {}),
    },
  });
  return {
    approvalRequestId: parsed.id,
    approvalRequest: {
      type: "mcp_approval_request",
      id: parsed.id,
      server_label: challenge.action.server,
      name: challenge.action.tool,
      arguments: canonicalizeJson(challenge.action.arguments),
    },
    challenge,
  };
}

/**
 * Verifies an Entros settlement bundle against an OpenAI `mcp_approval_request`
 * and returns a ready-to-send OpenAI `mcp_approval_response`.
 */
export async function settleOpenAiMcpApproval(
  input: Omit<VerifyMcpApprovalSettlementInput, "expectedAction"> & {
    approvalRequest: OpenAiMcpApprovalRequest;
  },
): Promise<OpenAiMcpApprovalSettlementEnvelope> {
  const parsed = parseOpenAiRequestAction(input.approvalRequest);
  if (!parsed) {
    const requestId =
      isPlainRecord(input.approvalRequest) &&
      typeof input.approvalRequest.id === "string"
        ? input.approvalRequest.id
        : "";
    const denied: McpApprovalSettlementResult = {
      decision: "deny",
      reason: "invalid_request",
      permitId: null,
      nonce: null,
      evaluatedAt: null,
      agentState: null,
      policy: null,
    };
    return {
      approvalRequestId: requestId,
      settlement: denied,
      response: {
        type: "mcp_approval_response",
        approval_request_id: requestId,
        approve: false,
        reason: "invalid_request",
      },
    };
  }

  const settlement = await verifyMcpApprovalSettlement({
    ...input,
    expectedAction: parsed.action,
  });

  return {
    approvalRequestId: parsed.id,
    settlement,
    response:
      settlement.decision === "allow"
        ? {
            type: "mcp_approval_response",
            approval_request_id: parsed.id,
            approve: true,
          }
        : {
            type: "mcp_approval_response",
            approval_request_id: parsed.id,
            approve: false,
            reason: settlement.reason,
          },
  };
}

/**
 * Wraps an Entros MCP approval challenge into a HumanLayer-compatible pause
 * payload carrying the signing URL, permit ID, expiry, and action digest.
 */
export function createHumanLayerApprovalCall(
  challenge: McpApprovalChallenge,
  options: {
    runId: string;
    callId?: string;
    state?: Record<string, unknown>;
  },
): HumanLayerApprovalCall {
  if (typeof options.runId !== "string" || options.runId.trim().length === 0) {
    throw new McpApprovalError("invalid_request", "HumanLayer runId is required");
  }
  const callId =
    options.callId !== undefined && options.callId.trim().length > 0
      ? options.callId
      : `hl_${challenge.permitId.slice(0, 24)}`;

  return {
    run_id: options.runId,
    call_id: callId,
    spec: {
      fn: `${challenge.action.server}.${challenge.action.tool}`,
      kwargs: structuredClone(challenge.action.arguments),
      state: {
        ...(options.state ? structuredClone(options.state) : {}),
        entros: {
          version: 1,
          permitId: challenge.permitId,
          nonce: challenge.nonce,
          approvalUrl: challenge.approvalUrl,
          expiresAt: challenge.expiresAt,
          actionSha256: challenge.action.sha256,
          cluster: "devnet",
          assuranceTier: "browser_unattested",
          uniquenessStatus: "unmeasured",
          executionPresenceProven: false,
        },
      },
    },
  };
}

function splitHumanLayerFn(
  fn: string,
  explicitServer?: string,
  explicitTool?: string,
): { server: string; tool: string } | null {
  if (explicitServer !== undefined && explicitTool !== undefined) {
    return { server: explicitServer, tool: explicitTool };
  }
  const separator = fn.indexOf(".");
  if (separator <= 0 || separator === fn.length - 1) return null;
  return {
    server: fn.slice(0, separator),
    tool: fn.slice(separator + 1),
  };
}

/**
 * Verifies a HumanLayer pause/resume callback together with the Entros
 * single-use `AgentPermit` settlement bundle before allowing tool resumption.
 */
export async function verifyHumanLayerApprovalCallback(
  input: Omit<VerifyMcpApprovalSettlementInput, "settlement" | "expectedAction"> & {
    callback: HumanLayerCallbackPayload;
    /** Explicit settlement bundle; falls back to `callback.status.entrosSettlement` or `callback.status.metadata.entrosSettlement`. */
    settlement?: unknown;
    /** Optional explicit server label when `callback.spec.fn` does not use `server.tool` naming. */
    server?: string;
    /** Optional explicit tool name when `callback.spec.fn` does not use `server.tool` naming. */
    tool?: string;
  },
): Promise<HumanLayerCallbackVerificationResult> {
  const cb = input.callback;
  const runId =
    isPlainRecord(cb) && typeof cb.run_id === "string" ? cb.run_id : "";
  const callId =
    isPlainRecord(cb) && typeof cb.call_id === "string" ? cb.call_id : "";

  const fail = (
    reason: "invalid_request" | "approval_rejected",
  ): HumanLayerCallbackVerificationResult => ({
    runId,
    callId,
    resume: false,
    settlement: {
      decision: "deny",
      reason,
      permitId: null,
      nonce: null,
      evaluatedAt: null,
      agentState: null,
      policy: null,
    },
  });

  if (
    !isPlainRecord(cb) ||
    runId.trim().length === 0 ||
    callId.trim().length === 0 ||
    !isPlainRecord(cb.spec) ||
    typeof cb.spec.fn !== "string" ||
    !isPlainRecord(cb.spec.kwargs) ||
    !isPlainRecord(cb.status)
  ) {
    return fail("invalid_request");
  }

  if (cb.status.approved !== true) {
    return fail("approval_rejected");
  }

  const parsedFn = splitHumanLayerFn(cb.spec.fn, input.server, input.tool);
  if (!parsedFn) {
    return fail("invalid_request");
  }

  const metadata = isPlainRecord(cb.status.metadata)
    ? cb.status.metadata
    : undefined;
  const settlementBundle =
    input.settlement ??
    cb.status.entrosSettlement ??
    metadata?.entrosSettlement;

  const settlement = await verifyMcpApprovalSettlement({
    ...input,
    settlement: settlementBundle,
    expectedAction: {
      server: parsedFn.server,
      tool: parsedFn.tool,
      arguments: cb.spec.kwargs,
    },
  });

  return {
    runId,
    callId,
    resume: settlement.decision === "allow",
    settlement,
  };
}

export interface McpApprovalGateConfig {
  audience: string;
  policy?: PolicyRequestInput;
  lifetimeSeconds?: number;
  approvalBaseUrl?: string;
  nonceStore?: McpNonceStore;
  connection?: SolanaTransport;
  readAgentState?: (input: { agent: string }) => Promise<AgentStateReadResult>;
  readIntegratorEvidence?: (input: {
    walletPubkey: string;
    transactionSignature: string;
    nowSeconds: number | (() => number);
  }) => Promise<PolicyEvidenceReadResult>;
  nowSeconds?: number | (() => number);
}

/**
 * Stateful convenience wrapper binding one MCP server's audience, policy,
 * nonce store, and Solana reader across challenge creation and settlement.
 */
export function createMcpApprovalGate(config: McpApprovalGateConfig) {
  const nonceStore = config.nonceStore ?? createInMemoryNonceStore();

  return {
    nonceStore,

    createChallenge(
      input: Omit<
        CreateMcpApprovalChallengeInput,
        | "audience"
        | "policy"
        | "lifetimeSeconds"
        | "approvalBaseUrl"
        | "nonceStore"
        | "connection"
        | "readAgentState"
        | "nowSeconds"
      > & {
        policy?: PolicyRequestInput;
        lifetimeSeconds?: number;
        nowSeconds?: number | (() => number);
      },
    ): Promise<McpApprovalChallenge> {
      return createMcpApprovalChallenge({
        audience: config.audience,
        policy: input.policy ?? config.policy,
        lifetimeSeconds: input.lifetimeSeconds ?? config.lifetimeSeconds,
        approvalBaseUrl: config.approvalBaseUrl,
        nonceStore,
        connection: config.connection,
        readAgentState: config.readAgentState,
        nowSeconds: input.nowSeconds ?? config.nowSeconds,
        ...input,
      });
    },

    verifySettlement(
      input: Omit<
        VerifyMcpApprovalSettlementInput,
        | "nonceStore"
        | "expectedAudience"
        | "connection"
        | "readAgentState"
        | "readIntegratorEvidence"
        | "nowSeconds"
      > & {
        nowSeconds?: number | (() => number);
      },
    ): Promise<McpApprovalSettlementResult> {
      return verifyMcpApprovalSettlement({
        nonceStore,
        expectedAudience: config.audience,
        connection: config.connection,
        readAgentState: config.readAgentState,
        readIntegratorEvidence: config.readIntegratorEvidence,
        nowSeconds: input.nowSeconds ?? config.nowSeconds,
        ...input,
      });
    },
  };
}
