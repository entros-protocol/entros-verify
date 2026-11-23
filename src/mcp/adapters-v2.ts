/**
 * Framework and Voice-AI adapters for `Entros-Agent-Permit-v2`:
 * - OpenAI Responses API v2 (`mcp_approval_request` / `mcp_approval_response`)
 * - Vercel AI SDK `toolApproval` (`"user-approval"`)
 * - LiveKit, Vapi, and Retell voice-agent webhook tool guards with graceful
 *   step-up routing on `suspicious` or `insufficient_signal`.
 */

import { hashActionV2 } from "../permit/canonical";
import type {
  CreateStepUpResponseV2,
  PermitApiClient,
  StepUpModeV2,
} from "../permit/client";
import { isPlainRecord } from "../permit/encoding";
import { verifyAgentPermitV2 } from "../permit/policy";
import type {
  CanonicalActionV2Input,
  JwksSource,
  PermitActorV2,
  PermitNonceStoreV2,
  PolicyV2,
  VerifyAgentPermitV2Result,
  VoiceLivenessVerdictClaims,
  WebAuthnVerifyOptions,
} from "../permit/types";
import { verifyVoiceLivenessVerdict } from "../voice/verdict";
import type {
  OpenAiMcpApprovalRequest,
  OpenAiMcpApprovalResponse,
} from "./adapters";
import {
  createStatelessMcpApprovalGate,
  type McpInputRequiredResult,
  type StatelessMcpApprovalGateConfig,
} from "./mrtr";
import { createInMemoryPermitNonceStoreV2 } from "./nonce-store-v2";

function parseOpenAiToolArgs(raw: unknown): Record<string, unknown> | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export interface OpenAiMcpApprovalV2ChallengeEnvelope {
  approvalRequestId: string;
  approvalRequest: OpenAiMcpApprovalRequest;
  inputRequired: McpInputRequiredResult;
}

export interface OpenAiMcpApprovalV2SettlementEnvelope {
  approvalRequestId: string;
  verification: VerifyAgentPermitV2Result;
  response: OpenAiMcpApprovalResponse;
}

/**
 * Formats an `Entros-Agent-Permit-v2` canonical action as an OpenAI Responses
 * API `mcp_approval_request` item.
 */
export function toOpenAiMcpApprovalRequestV2(
  action: CanonicalActionV2Input,
  options?: { id?: string },
): OpenAiMcpApprovalRequest {
  const { requestDigest } = hashActionV2(action);
  return {
    type: "mcp_approval_request",
    id: options?.id ?? `mcpr_${requestDigest.slice(0, 24)}`,
    server_label: action.server,
    name: action.tool,
    arguments: JSON.stringify(action.arguments),
  };
}

/**
 * Creates a stateless MCP 2026-07-28 `InputRequiredResult` challenge from an
 * OpenAI Responses API `mcp_approval_request` item bound via RFC 8785 JCS.
 */
export async function createV2ChallengeFromOpenAiMcpRequest(
  approvalRequest: OpenAiMcpApprovalRequest,
  gateConfig: StatelessMcpApprovalGateConfig,
  options?: {
    jti?: string;
    approvalUrl?: string;
    summary?: string;
    nowSeconds?: number | (() => number);
  },
): Promise<OpenAiMcpApprovalV2ChallengeEnvelope> {
  if (
    !isPlainRecord(approvalRequest) ||
    approvalRequest.type !== "mcp_approval_request" ||
    typeof approvalRequest.id !== "string" ||
    approvalRequest.id.trim().length === 0 ||
    typeof approvalRequest.server_label !== "string" ||
    typeof approvalRequest.name !== "string"
  ) {
    throw new Error("Invalid OpenAI mcp_approval_request payload");
  }
  const args = parseOpenAiToolArgs(approvalRequest.arguments);
  if (!args) {
    throw new Error("OpenAI mcp_approval_request arguments must be a JSON object");
  }
  const action: CanonicalActionV2Input = {
    kind: "mcp.tool_call",
    server: approvalRequest.server_label,
    tool: approvalRequest.name,
    arguments: args,
  };
  const gate = createStatelessMcpApprovalGate(gateConfig);
  const inputRequired = await gate.createInputRequiredResult({
    action,
    jti: options?.jti,
    approvalUrl: options?.approvalUrl,
    summary: options?.summary,
    nowSeconds: options?.nowSeconds,
  });
  return {
    approvalRequestId: approvalRequest.id,
    approvalRequest,
    inputRequired,
  };
}

/**
 * Verifies an `Entros-Agent-Permit-v2` against an OpenAI Responses API
 * `mcp_approval_request` and emits a ready-to-send `mcp_approval_response`.
 */
export async function settleOpenAiMcpApprovalV2(input: {
  approvalRequest: OpenAiMcpApprovalRequest;
  permitJws: string;
  policy: PolicyV2;
  expectedAudience: string;
  jwks: JwksSource;
  voiceJwks?: JwksSource;
  scittJwks?: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  nonceStore?: PermitNonceStoreV2;
  requireRegisteredNonce?: boolean;
  dpop?: { proof: string; htm: string; htu: string; maxAgeSeconds?: number };
  webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
  nowSeconds?: number | (() => number);
}): Promise<OpenAiMcpApprovalV2SettlementEnvelope> {
  const requestId =
    isPlainRecord(input.approvalRequest) &&
    typeof input.approvalRequest.id === "string"
      ? input.approvalRequest.id
      : "";
  const args =
    isPlainRecord(input.approvalRequest) &&
    input.approvalRequest.type === "mcp_approval_request"
      ? parseOpenAiToolArgs(input.approvalRequest.arguments)
      : null;

  if (
    !args ||
    requestId.trim().length === 0 ||
    typeof input.approvalRequest.server_label !== "string" ||
    typeof input.approvalRequest.name !== "string"
  ) {
    const verification: VerifyAgentPermitV2Result = {
      decision: "deny",
      reason: "invalid_permit",
      detail: "Invalid OpenAI mcp_approval_request payload",
      permit: null,
      evaluatedAt: Math.floor(Date.now() / 1000),
    };
    return {
      approvalRequestId: requestId,
      verification,
      response: {
        type: "mcp_approval_response",
        approval_request_id: requestId,
        approve: false,
        reason: verification.reason,
      },
    };
  }

  const verification = await verifyAgentPermitV2({
    permitJws: input.permitJws,
    policy: input.policy,
    expectedAudience: input.expectedAudience,
    action: {
      kind: "mcp.tool_call",
      server: input.approvalRequest.server_label,
      tool: input.approvalRequest.name,
      arguments: args,
    },
    jwks: input.jwks,
    voiceJwks: input.voiceJwks,
    scittJwks: input.scittJwks,
    revokedKids: input.revokedKids,
    nonceStore: input.nonceStore,
    requireRegisteredNonce: input.requireRegisteredNonce,
    dpop: input.dpop,
    webauthn: input.webauthn,
    nowSeconds: input.nowSeconds,
  });

  return {
    approvalRequestId: requestId,
    verification,
    response:
      verification.decision === "allow"
        ? {
            type: "mcp_approval_response",
            approval_request_id: requestId,
            approve: true,
          }
        : {
            type: "mcp_approval_response",
            approval_request_id: requestId,
            approve: false,
            reason: verification.reason,
          },
  };
}

// ============================================================================
// Vercel AI SDK `toolApproval` ("user-approval") Adapter
// ============================================================================

export type VercelToolApprovalMode = "user-approval";

export interface VercelToolApprovalGateConfig {
  audience: string;
  policy: PolicyV2;
  jwks: JwksSource;
  voiceJwks?: JwksSource;
  scittJwks?: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  nonceStore?: PermitNonceStoreV2;
  requireRegisteredNonce?: boolean;
  nowSeconds?: number | (() => number);
}

/**
 * Creates a Vercel AI SDK tool-approval gate targeting `toolApproval: "user-approval"`.
 * Verifies a single-use `Entros-Agent-Permit-v2` bound to the exact tool arguments
 * before invoking the underlying tool handler.
 */
export function createVercelToolApprovalGate(
  config: VercelToolApprovalGateConfig,
) {
  const nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();

  async function verifyToolApproval(input: {
    server: string;
    tool: string;
    arguments: Record<string, unknown>;
    permitJws: string;
    dpop?: { proof: string; htm: string; htu: string; maxAgeSeconds?: number };
    webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
    nowSeconds?: number | (() => number);
  }): Promise<VerifyAgentPermitV2Result> {
    return verifyAgentPermitV2({
      permitJws: input.permitJws,
      policy: config.policy,
      expectedAudience: config.audience,
      action: {
        kind: "mcp.tool_call",
        server: input.server,
        tool: input.tool,
        arguments: input.arguments,
      },
      jwks: config.jwks,
      voiceJwks: config.voiceJwks,
      scittJwks: config.scittJwks,
      revokedKids: config.revokedKids,
      nonceStore,
      requireRegisteredNonce: config.requireRegisteredNonce,
      dpop: input.dpop,
      webauthn: input.webauthn,
      nowSeconds: input.nowSeconds ?? config.nowSeconds,
    });
  }

  return {
    /** Canonical Vercel AI SDK approval setting (replaces deprecated `needsApproval`). */
    toolApproval: "user-approval" as VercelToolApprovalMode,
    nonceStore,
    verifyToolApproval,

    /**
     * Wraps a Vercel AI SDK tool definition with `toolApproval: "user-approval"`
     * and enforces `Entros-Agent-Permit-v2` verification inside `execute`.
     */
    wrapTool<TArgs extends Record<string, unknown>, TResult>(toolDef: {
      server: string;
      tool: string;
      description?: string;
      execute: (
        args: TArgs,
        context: {
          permit: Extract<VerifyAgentPermitV2Result, { decision: "allow" }>;
        },
      ) => Promise<TResult> | TResult;
    }) {
      return {
        description: toolDef.description,
        toolApproval: "user-approval" as VercelToolApprovalMode,
        execute: async (
          args: TArgs,
          approval: {
            permitJws: string;
            dpop?: { proof: string; htm: string; htu: string };
            webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
            nowSeconds?: number | (() => number);
          },
        ): Promise<
          | { ok: true; result: TResult; verification: Extract<VerifyAgentPermitV2Result, { decision: "allow" }> }
          | { ok: false; verification: Exclude<VerifyAgentPermitV2Result, { decision: "allow" }> }
        > => {
          const verification = await verifyToolApproval({
            server: toolDef.server,
            tool: toolDef.tool,
            arguments: args,
            permitJws: approval.permitJws,
            dpop: approval.dpop,
            webauthn: approval.webauthn,
            nowSeconds: approval.nowSeconds,
          });
          if (verification.decision !== "allow") {
            return { ok: false, verification };
          }
          const result = await toolDef.execute(args, { permit: verification });
          return { ok: true, result, verification };
        },
      };
    },
  };
}

// ============================================================================
// LiveKit, Vapi, and Retell Voice-AI Webhook Tool Guards
// ============================================================================

export interface VoiceWebhookGuardConfig {
  server: string;
  audience: string;
  policy: PolicyV2;
  jwks: JwksSource;
  voiceJwks?: JwksSource;
  scittJwks?: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  nonceStore?: PermitNonceStoreV2;
  requireRegisteredNonce?: boolean;
  /** Optional Permit API client to trigger `POST /v1/permits/step-up` automatically. */
  permitClient?: PermitApiClient;
  /** Default step-up mode when voice returns `suspicious` or `insufficient_signal`. Default `"oidc_ciba"`. */
  stepUpMode?: StepUpModeV2;
  nowSeconds?: number | (() => number);
}

export type VoiceWebhookGuardResult =
  | {
      status: "allow";
      sessionId: string;
      requestDigest: string;
      verification: Extract<VerifyAgentPermitV2Result, { decision: "allow" }>;
    }
  | {
      status: "step_up_required";
      sessionId: string;
      requestDigest: string;
      reason:
        | "voice_verdict_missing"
        | "voice_suspicious"
        | "voice_insufficient_signal"
        | "passkey_required";
      voiceVerdict: VoiceLivenessVerdictClaims | null;
      stepUp?: CreateStepUpResponseV2;
    }
  | {
      status: "permit_required";
      sessionId: string;
      requestDigest: string;
      voiceVerdict: VoiceLivenessVerdictClaims;
    }
  | {
      status: "deny";
      sessionId: string;
      requestDigest: string | null;
      reason: string;
      verification?: VerifyAgentPermitV2Result;
    };

export async function evaluateVoiceWebhookToolGuard(
  config: VoiceWebhookGuardConfig,
  call: {
    sessionId: string;
    tool: string;
    arguments: Record<string, unknown>;
    permitJws?: string;
    voiceVerdictJws?: string;
    sub?: string;
    actor?: PermitActorV2;
    dpop?: { proof: string; htm: string; htu: string };
    webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
    nowSeconds?: number | (() => number);
  },
): Promise<VoiceWebhookGuardResult> {
  const action: CanonicalActionV2Input = {
    kind: "voice.tool_call",
    server: config.server,
    tool: call.tool,
    arguments: call.arguments,
  };

  let requestDigest: string;
  try {
    requestDigest = hashActionV2(action).requestDigest;
  } catch {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest: null,
      reason: "request_digest_mismatch",
    };
  }

  // If the caller already holds a signed AgentPermit v2, verify it directly.
  if (call.permitJws) {
    const verification = await verifyAgentPermitV2({
      permitJws: call.permitJws,
      policy: config.policy,
      expectedAudience: config.audience,
      action,
      jwks: config.jwks,
      voiceJwks: config.voiceJwks,
      scittJwks: config.scittJwks,
      revokedKids: config.revokedKids,
      nonceStore: config.nonceStore,
      requireRegisteredNonce: config.requireRegisteredNonce,
      dpop: call.dpop,
      webauthn: call.webauthn,
      nowSeconds: call.nowSeconds ?? config.nowSeconds,
    });
    if (verification.decision === "allow") {
      return {
        status: "allow",
        sessionId: call.sessionId,
        requestDigest,
        verification,
      };
    }
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: verification.reason,
      verification,
    };
  }

  const triggerStepUp = async (
    reason:
      | "voice_verdict_missing"
      | "voice_suspicious"
      | "voice_insufficient_signal"
      | "passkey_required",
    voiceVerdict: VoiceLivenessVerdictClaims | null,
  ): Promise<VoiceWebhookGuardResult> => {
    let stepUp: CreateStepUpResponseV2 | undefined;
    if (config.permitClient && call.sub && call.actor) {
      stepUp = await config.permitClient.createStepUp({
        mode: config.stepUpMode ?? "oidc_ciba",
        sub: call.sub,
        actor: call.actor,
        aud: config.audience,
        policy_id: config.policy.policy_id,
        action,
        request_digest: requestDigest,
        session_id: call.sessionId,
        voice_verdict_jws: call.voiceVerdictJws ?? null,
      });
    }
    return {
      status: "step_up_required",
      sessionId: call.sessionId,
      requestDigest,
      reason,
      voiceVerdict,
      ...(stepUp !== undefined ? { stepUp } : {}),
    };
  };

  if (!call.voiceVerdictJws) {
    return triggerStepUp("voice_verdict_missing", null);
  }

  const verdictRes = await verifyVoiceLivenessVerdict({
    jws: call.voiceVerdictJws,
    jwks: config.voiceJwks ?? config.jwks,
    revokedKids: config.revokedKids,
    nowSeconds: call.nowSeconds ?? config.nowSeconds,
  });
  if (!verdictRes.ok) {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: verdictRes.reason,
    };
  }

  const claims = verdictRes.claims;
  if (claims.session_id !== call.sessionId) {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: "continuity_broken",
    };
  }

  if (claims.verdict === "likely_synthetic") {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: "voice_verdict_not_allowed",
    };
  }

  // Graceful abstention and suspicious routing -> Passkey step-up.
  if (claims.verdict === "suspicious") {
    return triggerStepUp("voice_suspicious", claims);
  }
  if (claims.verdict === "insufficient_signal") {
    return triggerStepUp("voice_insufficient_signal", claims);
  }

  const maxSpans = config.policy.voice_rules?.max_partial_spoof_spans ?? 0;
  if (claims.partial_spoof_spans.length > maxSpans) {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: "partial_spoof_detected",
    };
  }
  if (
    config.policy.voice_rules?.reject_on_consistency_drift !== false &&
    claims.consistency_drift.status === "elevated"
  ) {
    return {
      status: "deny",
      sessionId: call.sessionId,
      requestDigest,
      reason: "consistency_drift_exceeded",
    };
  }

  if (config.policy.required_modalities.includes("webauthn_uv")) {
    return triggerStepUp("passkey_required", claims);
  }

  return {
    status: "permit_required",
    sessionId: call.sessionId,
    requestDigest,
    voiceVerdict: claims,
  };
}

/**
 * LiveKit voice agent tool guard checking active session `VoiceLivenessVerdict`
 * or `Entros-Agent-Permit-v2` and routing uncertain audio to Passkey step-up.
 */
export function createLiveKitToolGuard(config: VoiceWebhookGuardConfig) {
  const nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();
  const effectiveConfig = { ...config, nonceStore };
  return {
    nonceStore,
    guardToolCall(payload: {
      roomName: string;
      participantIdentity: string;
      sessionId?: string;
      toolName: string;
      args: Record<string, unknown>;
      permitJws?: string;
      voiceVerdictJws?: string;
      sub?: string;
      actor?: PermitActorV2;
      nowSeconds?: number | (() => number);
    }): Promise<VoiceWebhookGuardResult> {
      const sessionId =
        payload.sessionId ?? `${payload.roomName}:${payload.participantIdentity}`;
      return evaluateVoiceWebhookToolGuard(effectiveConfig, {
        sessionId,
        tool: payload.toolName,
        arguments: payload.args,
        permitJws: payload.permitJws,
        voiceVerdictJws: payload.voiceVerdictJws,
        sub: payload.sub,
        actor: payload.actor,
        nowSeconds: payload.nowSeconds,
      });
    },
  };
}

export interface VapiToolCallWebhookPayload {
  message: {
    type: "tool-calls";
    call?: { id?: string };
    toolCallList?: Array<{
      id: string;
      name: string;
      arguments: Record<string, unknown> | string;
    }>;
  };
}

/**
 * Vapi webhook tool guard extracting `call.id` and `toolCallList` items,
 * checking voice liveness or `AgentPermit` v2, and routing step-up when needed.
 */
export function createVapiWebhookGuard(config: VoiceWebhookGuardConfig) {
  const nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();
  const effectiveConfig = { ...config, nonceStore };
  return {
    nonceStore,
    async guardWebhook(input: {
      payload: VapiToolCallWebhookPayload;
      voiceVerdictJws?: string;
      permitsByToolCallId?: Record<string, string>;
      sub?: string;
      actor?: PermitActorV2;
      nowSeconds?: number | (() => number);
    }): Promise<Array<{ toolCallId: string; result: VoiceWebhookGuardResult }>> {
      const sessionId = input.payload?.message?.call?.id ?? "";
      const list = input.payload?.message?.toolCallList ?? [];
      const results: Array<{
        toolCallId: string;
        result: VoiceWebhookGuardResult;
      }> = [];

      for (const item of list) {
        const parsedArgs =
          typeof item.arguments === "string"
            ? parseOpenAiToolArgs(item.arguments)
            : isPlainRecord(item.arguments)
              ? item.arguments
              : null;
        if (!parsedArgs || sessionId.length === 0) {
          results.push({
            toolCallId: item.id,
            result: {
              status: "deny",
              sessionId,
              requestDigest: null,
              reason: "invalid_permit",
            },
          });
          continue;
        }
        const res = await evaluateVoiceWebhookToolGuard(effectiveConfig, {
          sessionId,
          tool: item.name,
          arguments: parsedArgs,
          permitJws: input.permitsByToolCallId?.[item.id],
          voiceVerdictJws: input.voiceVerdictJws,
          sub: input.sub,
          actor: input.actor,
          nowSeconds: input.nowSeconds,
        });
        results.push({ toolCallId: item.id, result: res });
      }
      return results;
    },
  };
}

export interface RetellToolWebhookPayload {
  call: { call_id: string };
  name: string;
  args: Record<string, unknown>;
}

/**
 * Retell custom-function webhook guard checking active `call.call_id` voice
 * liveness or `AgentPermit` v2 and triggering Passkey step-up on abstention.
 */
export function createRetellWebhookGuard(config: VoiceWebhookGuardConfig) {
  const nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();
  const effectiveConfig = { ...config, nonceStore };
  return {
    nonceStore,
    guardWebhook(input: {
      payload: RetellToolWebhookPayload;
      voiceVerdictJws?: string;
      permitJws?: string;
      sub?: string;
      actor?: PermitActorV2;
      nowSeconds?: number | (() => number);
    }): Promise<VoiceWebhookGuardResult> {
      const sessionId = input.payload?.call?.call_id ?? "";
      if (
        sessionId.length === 0 ||
        typeof input.payload?.name !== "string" ||
        !isPlainRecord(input.payload?.args)
      ) {
        return Promise.resolve({
          status: "deny",
          sessionId,
          requestDigest: null,
          reason: "invalid_permit",
        });
      }
      return evaluateVoiceWebhookToolGuard(effectiveConfig, {
        sessionId,
        tool: input.payload.name,
        arguments: input.payload.args,
        permitJws: input.permitJws,
        voiceVerdictJws: input.voiceVerdictJws,
        sub: input.sub,
        actor: input.actor,
        nowSeconds: input.nowSeconds,
      });
    },
  };
}
