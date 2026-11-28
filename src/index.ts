/**
 * `@entros/verify` headless root public surface.
 *
 * Zero React dependency and zero `"use client"` directive. Runs cleanly in
 * Node.js, Bun, Deno, Cloudflare Workers, Vercel Edge, and browsers.
 * Import React UI components from `@entros/verify/react`.
 */

import {
  createInMemoryPermitNonceStoreV2,
  InMemoryPermitNonceStoreV2,
} from "./mcp/nonce-store-v2";
import {
  createPermitApiClient,
  PermitApiClient,
  type CompleteStepUpRequestV2,
  type CompleteStepUpResponseV2,
  type CreateStepUpRequestV2,
  type CreateStepUpResponseV2,
  type FetchScittReceiptOptionsV2,
  type FetchScittReceiptResponseV2,
  type IssuePermitRequestV2,
  type IssuePermitResponseV2,
  type PollStepUpResponseV2,
  type VerifyPermitOnlineRequestV2,
  type VerifyPermitOnlineResponseV2,
} from "./permit/client";
import { createJwksCache, JwksCache } from "./permit/jwks";
import { evaluatePolicyV2, verifyAgentPermitV2 } from "./permit/policy";
import { verifyScittReceipt } from "./permit/scitt";
import type {
  JwksSource,
  PermitNonceStoreV2,
  VerifyAgentPermitV2Input,
  VerifyAgentPermitV2Result,
} from "./permit/types";
import {
  createVoiceLivenessClient,
  VoiceLivenessClient,
  type AnalyzeVoiceInput,
  type AnalyzeVoiceResponse,
  type VoiceClientDebugEvent,
  type VoiceStreamHandle,
  type VoiceStreamOptions,
  type WebSocketFactory,
  type WebSocketLikeConstructor,
} from "./voice/client";
import {
  verifyVoiceLivenessVerdict,
  type VerifyVoiceLivenessVerdictInput,
  type VerifyVoiceLivenessVerdictResult,
} from "./voice/verdict";

export interface EntrosClientConfig {
  /** Base HTTPS URI for the Entros Firewall API (or http://127.0.0.1 for local tests). */
  baseUrl?: string;
  /** Optional Bearer API key for hosted or VPC firewall API calls. */
  apiKey?: string;
  /** Optional explicit JWKS URL override. Defaults to `<baseUrl>/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** Optional static or custom JWKS resolver overriding remote JWKS discovery. */
  jwks?: JwksSource;
  /** Optional local revoked kid list. */
  revokedKids?: ReadonlySet<string> | readonly string[];
  /** Optional custom fetch implementation. */
  fetch?: typeof globalThis.fetch;
  /** Optional custom WebSocket constructor for voice streaming. */
  webSocketCtor?: WebSocketLikeConstructor;
  /** Optional custom WebSocket factory receiving HTTP upgrade headers. */
  webSocketFactory?: WebSocketFactory;
  /** Optional extra HTTP upgrade headers for WebSocket voice streams. */
  webSocketHeaders?: Record<string, string>;
  /** Request timeout in milliseconds. Default 10,000. */
  timeoutMs?: number;
  /** Optional atomic nonce store for single-use permit verification. */
  nonceStore?: PermitNonceStoreV2;
  /** Optional clock callback returning Unix seconds. */
  nowSeconds?: () => number;
  /** Optional metadata-only debug hook for voice transport events. */
  onVoiceDebug?: (event: VoiceClientDebugEvent) => void;
}

const DEFAULT_ENTROS_API_BASE_URL = "https://api.entros.io";

/**
 * Unified headless client combining Voice Liveness REST/WebSocket screening,
 * `Entros-Agent-Permit-v2` API calls, bounded Ed25519 JWKS caching, and offline
 * permit, voice verdict, and SCITT receipt verification.
 */
export class EntrosClient {
  readonly voice: VoiceLivenessClient;
  readonly permits: PermitApiClient;
  readonly jwks: JwksSource;
  readonly nonceStore: PermitNonceStoreV2;
  readonly #revokedKids?: ReadonlySet<string> | readonly string[];
  readonly #nowSeconds?: () => number;

  constructor(config: EntrosClientConfig = {}) {
    const baseUrl = (config.baseUrl ?? DEFAULT_ENTROS_API_BASE_URL).replace(
      /\/+$/,
      "",
    );
    this.voice = createVoiceLivenessClient({
      baseUrl,
      apiKey: config.apiKey,
      fetch: config.fetch,
      webSocketCtor: config.webSocketCtor,
      webSocketFactory: config.webSocketFactory,
      webSocketHeaders: config.webSocketHeaders,
      timeoutMs: config.timeoutMs,
      onDebug: config.onVoiceDebug,
    });
    this.permits = createPermitApiClient({
      baseUrl,
      apiKey: config.apiKey,
      fetch: config.fetch,
      timeoutMs: config.timeoutMs,
    });
    this.jwks =
      config.jwks ??
      createJwksCache({
        jwksUrl: config.jwksUrl ?? `${baseUrl}/.well-known/jwks.json`,
        revokedKids: config.revokedKids,
        fetch: config.fetch,
        nowSeconds: config.nowSeconds,
        timeoutMs: config.timeoutMs,
      });
    this.nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();
    this.#revokedKids = config.revokedKids;
    this.#nowSeconds = config.nowSeconds;
  }

  analyzeVoice(input: AnalyzeVoiceInput): Promise<AnalyzeVoiceResponse> {
    return this.voice.analyze({
      verifyWithJwks: this.jwks,
      revokedKids: this.#revokedKids,
      nowSeconds: this.#nowSeconds,
      ...input,
    });
  }

  connectVoiceStream(options: VoiceStreamOptions): VoiceStreamHandle {
    return this.voice.connectStream({
      verifyWithJwks: this.jwks,
      revokedKids: this.#revokedKids,
      nowSeconds: this.#nowSeconds,
      ...options,
    });
  }

  issuePermit(
    input: IssuePermitRequestV2,
    signal?: AbortSignal,
  ): Promise<IssuePermitResponseV2> {
    return this.permits.issuePermit(input, signal);
  }

  createStepUp(
    input: CreateStepUpRequestV2,
    signal?: AbortSignal,
  ): Promise<CreateStepUpResponseV2> {
    return this.permits.createStepUp(input, signal);
  }

  pollStepUp(
    jti: string,
    signal?: AbortSignal,
  ): Promise<PollStepUpResponseV2> {
    return this.permits.pollStepUp(jti, signal);
  }

  completeStepUp(
    input: CompleteStepUpRequestV2,
    signal?: AbortSignal,
  ): Promise<CompleteStepUpResponseV2> {
    return this.permits.completeStepUp(input, signal);
  }

  verifyPermitOnline(
    input: VerifyPermitOnlineRequestV2,
    signal?: AbortSignal,
  ): Promise<VerifyPermitOnlineResponseV2> {
    return this.permits.verifyPermitOnline(input, signal);
  }

  fetchScittReceipt(
    jti: string,
    signalOrOptions?: AbortSignal | FetchScittReceiptOptionsV2,
  ): Promise<FetchScittReceiptResponseV2> {
    const normalized: FetchScittReceiptOptionsV2 =
      signalOrOptions !== undefined && "aborted" in signalOrOptions
        ? { signal: signalOrOptions }
        : (signalOrOptions ?? {});
    const verifyWithJwks =
      "verifyWithJwks" in normalized ? normalized.verifyWithJwks : this.jwks;
    return this.permits.fetchScittReceipt(jti, {
      revokedKids: this.#revokedKids,
      ...normalized,
      verifyWithJwks,
    });
  }

  verifyVoiceLivenessVerdict(
    input: Omit<VerifyVoiceLivenessVerdictInput, "jwks"> & { jwks?: JwksSource },
  ): Promise<VerifyVoiceLivenessVerdictResult> {
    return verifyVoiceLivenessVerdict({
      jwks: input.jwks ?? this.jwks,
      revokedKids: input.revokedKids ?? this.#revokedKids,
      nowSeconds: input.nowSeconds ?? this.#nowSeconds,
      jws: input.jws,
      expectedIssuer: input.expectedIssuer,
    });
  }

  verifyAgentPermitV2(
    input: Omit<VerifyAgentPermitV2Input, "jwks"> & { jwks?: JwksSource },
  ): Promise<VerifyAgentPermitV2Result> {
    return verifyAgentPermitV2({
      ...input,
      jwks: input.jwks ?? this.jwks,
      revokedKids: input.revokedKids ?? this.#revokedKids,
      nonceStore: input.nonceStore ?? this.nonceStore,
      nowSeconds: input.nowSeconds ?? this.#nowSeconds,
    });
  }

  verifyScittReceipt(receipt: string | Uint8Array) {
    return verifyScittReceipt({
      receipt,
      jwks: this.jwks,
      revokedKids: this.#revokedKids,
    });
  }
}

export function createEntrosClient(config?: EntrosClientConfig): EntrosClient {
  return new EntrosClient(config);
}

// Core v2 verification, JCS, JWKS, WebAuthn, DPoP, SCITT, and Policy v2 exports
export {
  evaluatePolicyV2,
  verifyAgentPermitV2,
  verifyScittReceipt,
  verifyVoiceLivenessVerdict,
  createJwksCache,
  JwksCache,
  createPermitApiClient,
  PermitApiClient,
  createVoiceLivenessClient,
  VoiceLivenessClient,
  createInMemoryPermitNonceStoreV2,
  InMemoryPermitNonceStoreV2,
};

export {
  canonicalizeJcs,
  CanonicalJsonError,
  hashActionV2,
  parseStrictJson,
  validateActionV2,
} from "./permit/canonical";
export {
  computeWebAuthnAssertionDigestV2,
  deriveWebAuthnChallengeV2,
  verifyWebAuthnAssertionV2,
} from "./permit/webauthn";
export {
  computeJwkThumbprint,
  InMemoryDpopJtiStore,
  verifyDpopProofV2,
} from "./permit/dpop";
export { createStaticJwksResolver } from "./permit/jwks";
export {
  AGENT_PERMIT_V2_DOMAIN,
  AGENT_PERMIT_V2_TYP,
  ALL_ASSURANCE_TIERS_V2,
  ALL_VOICE_ABSTAIN_REASONS,
  PERMIT_V2_LIMITS,
  VOICE_VERDICT_TYP,
  WEBAUTHN_ASSERTION_V2_DOMAIN,
  WEBAUTHN_CHALLENGE_V2_DOMAIN,
} from "./permit/types";

export type {
  ActionKindV2,
  AgentPermitV2Claims,
  AssuranceTierV2,
  CanonicalActionV2Input,
  CanonicalActionV2Result,
  ConsistencyDrift,
  ContinuityModeV2,
  DpopJtiStore,
  DpopVerifyOptions,
  DpopVerifyResult,
  EcP256Jwk,
  Ed25519Jwk,
  JwkLookupResult,
  JwksDocument,
  JwksResolver,
  JwksSource,
  PartialSpoofSpan,
  PermitActorV2,
  PermitCnfV2,
  PermitContinuityV2,
  PermitNonceStoreV2,
  PermitNonceV2ConsumeInput,
  PermitNonceV2ConsumeResult,
  PermitNonceV2Record,
  PermitV2DenyCode,
  PermitV2RefusalCode,
  PermitV2UnavailableCode,
  PolicyV2,
  ScittDecisionStatement,
  ScittVerificationResult,
  UniquenessRequirementV2,
  UniquenessStatusV2,
  VerifiedScittReceipt,
  VerifyAgentPermitV2Input,
  VerifyAgentPermitV2Result,
  VoiceAbstainReason,
  VoiceLivenessVerdictClaims,
  VoiceOperatingProfile,
  VoicePolicyRulesV2,
  VoiceSignalQuality,
  VoiceVerdictDecision,
  WebAuthnAssertionInput,
  WebAuthnVerifyOptions,
  WebAuthnVerifyResult,
} from "./permit/types";
export type { EvaluatePolicyV2Input, EvaluatePolicyV2Result } from "./permit/policy";
export type {
  VerifyVoiceLivenessVerdictInput,
  VerifyVoiceLivenessVerdictReason,
  VerifyVoiceLivenessVerdictResult,
} from "./voice/verdict";

// Preserved headless v1 warm-policy reuse helper and pure types (zero React)
export { evaluateWarmPolicyReuse } from "./warm-policy";
export type {
  WarmPolicyReuseBaseInput,
  WarmPolicyReuseInput,
  WarmPolicyReuseObservationInput,
  WarmPolicyReuseReaderInput,
  WarmPolicyReuseResult,
  WarmVerificationLookup,
} from "./warm-policy";
export type {
  PolicyReason,
  PolicyRequest,
  PolicyRequestInput,
  PolicyResult,
} from "./policy";
export type {
  Cluster,
  EntrosVerifyError,
  EntrosVerifyErrorReason,
  EntrosVerifyProgress,
  EntrosVerifyProgressStatus,
  EntrosVerifyResult,
} from "./types";
