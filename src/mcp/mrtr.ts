/**
 * MCP 2026-07-28 Stateless Multi Round-Trip Request (MRTR) `InputRequiredResult`
 * approval gate with HMAC-SHA256 authenticated `requestState`.
 *
 * Keeps WebAuthn and voice biometric inputs completely out-of-band from LLM
 * context while scaling horizontally across stateless MCP server replicas.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalizeJcs, hashActionV2, parseStrictJson } from "../permit/canonical";
import {
  base64UrlDecodeStrict,
  base64UrlEncode,
  constantTimeEqual,
  constantTimeEqualString,
  decodeUtf8Strict,
  isCanonicalAudUri,
  isLowerHex64NonZero,
  isPlainRecord,
  isStrictHttpsOrLoopbackUri,
  isValidUnixSeconds,
  randomHex32Bytes,
  utf8Encoder,
} from "../permit/encoding";
import { verifyAgentPermitV2 } from "../permit/policy";
import {
  PERMIT_V2_LIMITS,
  type CanonicalActionV2Input,
  type JwksSource,
  type PermitNonceStoreV2,
  type PolicyV2,
  type VerifyAgentPermitV2Result,
  type WebAuthnVerifyOptions,
} from "../permit/types";
import { createInMemoryPermitNonceStoreV2 } from "./nonce-store-v2";

const MRTR_STATE_DOMAIN = "Entros-MCP-MRTR-State-v2";
const DEFAULT_MRTR_APPROVAL_BASE_URL = "https://approve.entros.io/step-up";

export interface MrtrRequestStateClaims {
  v: 2;
  jti: string;
  request_digest: string;
  aud: string;
  policy_id: string;
  iat: number;
  exp: number;
}

export interface MrtrUrlInputRequest {
  mode: "url";
  elicitationId: string;
  url: string;
  message: string;
  cacheable: false;
}

export interface McpInputRequiredResult {
  resultType: "input_required";
  inputRequests: [MrtrUrlInputRequest];
  requestState: string;
  metadata: {
    jti: string;
    request_digest: string;
    aud: string;
    policy_id: string;
    iat: number;
    exp: number;
  };
}

export interface MrtrInputResponseItem {
  elicitationId?: string;
  permitJws?: string;
  permit_jws?: string;
  content?: {
    permit_jws?: string;
    permitJws?: string;
  };
}

export interface StatelessMcpApprovalGateConfig {
  /** Canonical RFC 8707 MCP resource URI matching permit `aud`. */
  audience: string;
  /** Policy v2 contract governing tool execution. */
  policy: PolicyV2;
  /** Ed25519 JWKS for offline permit verification. */
  jwks: JwksSource;
  /** Optional separate JWKS for embedded VoiceLivenessVerdict JWS. */
  voiceJwks?: JwksSource;
  /** Optional separate JWKS for embedded IETF SCITT receipts. */
  scittJwks?: JwksSource;
  /** Optional local key revocation list. */
  revokedKids?: ReadonlySet<string> | readonly string[];
  /** Shared HMAC-SHA256 secret (>= 32 bytes) authenticating stateless `requestState` across replicas. */
  stateSecret: Uint8Array | string;
  /** Out-of-band approval base URL. Default `"https://approve.entros.io/step-up"`. */
  approvalBaseUrl?: string;
  /** Default challenge lifetime in seconds (30..900). Default 300. */
  lifetimeSeconds?: number;
  /** Atomic post-precheck nonce store. Defaults to `InMemoryPermitNonceStoreV2`. */
  nonceStore?: PermitNonceStoreV2;
  /** When true, requires `nonceStore.register()` before settlement. Default false for stateless replicas. */
  requireRegisteredNonce?: boolean;
  /** Optional clock returning Unix seconds. */
  nowSeconds?: number | (() => number);
}

function normalizeStateSecret(secret: Uint8Array | string): Uint8Array {
  const bytes =
    secret instanceof Uint8Array ? secret : utf8Encoder.encode(secret);
  if (bytes.length < 32) {
    throw new Error(
      "MRTR stateSecret must be at least 32 bytes for HMAC-SHA256 security",
    );
  }
  return bytes;
}

function readNow(clock?: number | (() => number)): number {
  const val =
    clock === undefined
      ? Math.floor(Date.now() / 1000)
      : typeof clock === "function"
        ? clock()
        : clock;
  if (!isValidUnixSeconds(val)) {
    throw new Error("Invalid MRTR clock timestamp");
  }
  return val;
}

/**
 * Signs an HMAC-SHA256 authenticated stateless `requestState` token committing
 * `(jti, request_digest, aud, policy_id, iat, exp)`.
 */
export function signMrtrRequestState(
  claims: MrtrRequestStateClaims,
  stateSecret: Uint8Array | string,
): string {
  const secretBytes = normalizeStateSecret(stateSecret);
  const payloadB64u = base64UrlEncode(
    utf8Encoder.encode(canonicalizeJcs(claims)),
  );
  const mac = hmac(
    sha256,
    secretBytes,
    utf8Encoder.encode(`${MRTR_STATE_DOMAIN}\n${payloadB64u}`),
  );
  return `${payloadB64u}.${base64UrlEncode(mac)}`;
}

/**
 * Verifies an HMAC-SHA256 authenticated `requestState` token and checks expiry.
 */
export function verifyMrtrRequestState(
  requestState: unknown,
  stateSecret: Uint8Array | string,
  nowSeconds: number,
):
  | { ok: true; claims: MrtrRequestStateClaims }
  | { ok: false; reason: "invalid_request_state" | "state_expired" } {
  if (typeof requestState !== "string" || requestState.length === 0) {
    return { ok: false, reason: "invalid_request_state" };
  }
  const parts = requestState.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { ok: false, reason: "invalid_request_state" };
  }
  const [payloadB64u, macB64u] = parts;
  const presentedMac = base64UrlDecodeStrict(macB64u);
  if (!presentedMac || presentedMac.length !== 32) {
    return { ok: false, reason: "invalid_request_state" };
  }

  const secretBytes = normalizeStateSecret(stateSecret);
  const expectedMac = hmac(
    sha256,
    secretBytes,
    utf8Encoder.encode(`${MRTR_STATE_DOMAIN}\n${payloadB64u}`),
  );
  if (!constantTimeEqual(presentedMac, expectedMac)) {
    return { ok: false, reason: "invalid_request_state" };
  }

  const payloadBytes = base64UrlDecodeStrict(payloadB64u);
  if (!payloadBytes) return { ok: false, reason: "invalid_request_state" };
  const payloadText = decodeUtf8Strict(payloadBytes);
  if (payloadText === null) {
    return { ok: false, reason: "invalid_request_state" };
  }

  let parsed: unknown;
  try {
    parsed = parseStrictJson(payloadText);
  } catch {
    return { ok: false, reason: "invalid_request_state" };
  }
  if (!isPlainRecord(parsed)) {
    return { ok: false, reason: "invalid_request_state" };
  }
  if (
    parsed.v !== 2 ||
    !isLowerHex64NonZero(parsed.jti) ||
    !isLowerHex64NonZero(parsed.request_digest) ||
    !isCanonicalAudUri(parsed.aud) ||
    typeof parsed.policy_id !== "string" ||
    parsed.policy_id.length === 0 ||
    !isValidUnixSeconds(parsed.iat) ||
    !isValidUnixSeconds(parsed.exp)
  ) {
    return { ok: false, reason: "invalid_request_state" };
  }
  if (parsed.iat > nowSeconds + PERMIT_V2_LIMITS.clockSkewSeconds) {
    return { ok: false, reason: "invalid_request_state" };
  }
  if (nowSeconds >= parsed.exp) {
    return { ok: false, reason: "state_expired" };
  }

  return {
    ok: true,
    claims: {
      v: 2,
      jti: parsed.jti,
      request_digest: parsed.request_digest,
      aud: parsed.aud,
      policy_id: parsed.policy_id,
      iat: parsed.iat,
      exp: parsed.exp,
    },
  };
}

function extractPermitJws(
  inputResponses: unknown,
  expectedElicitationId: string,
): string | null {
  if (typeof inputResponses === "string" && inputResponses.length > 0) {
    return inputResponses;
  }
  const items = Array.isArray(inputResponses)
    ? inputResponses
    : isPlainRecord(inputResponses)
      ? [inputResponses]
      : null;
  if (!items) return null;

  for (const item of items) {
    if (!isPlainRecord(item)) continue;
    const candidate = item as MrtrInputResponseItem;
    if (
      candidate.elicitationId !== undefined &&
      candidate.elicitationId !== expectedElicitationId
    ) {
      continue;
    }
    const token =
      candidate.permitJws ??
      candidate.permit_jws ??
      candidate.content?.permit_jws ??
      candidate.content?.permitJws;
    if (typeof token === "string" && token.length > 0) {
      return token;
    }
  }
  return null;
}

/**
 * Creates a stateless MCP 2026-07-28 `InputRequiredResult` MRTR approval gate.
 */
export function createStatelessMcpApprovalGate(
  config: StatelessMcpApprovalGateConfig,
) {
  if (!isCanonicalAudUri(config.audience)) {
    throw new Error("MCP gate audience must be a canonical RFC 8707 URI");
  }
  const secretBytes = normalizeStateSecret(config.stateSecret);
  const approvalBaseUrl =
    config.approvalBaseUrl ?? DEFAULT_MRTR_APPROVAL_BASE_URL;
  if (!isStrictHttpsOrLoopbackUri(approvalBaseUrl)) {
    throw new Error(
      "MCP gate approvalBaseUrl must be a strict HTTPS URI (or http://127.0.0.1)",
    );
  }
  const defaultLifetime = Math.min(
    config.lifetimeSeconds ?? 300,
    config.policy.max_permit_lifetime_seconds,
  );
  if (
    defaultLifetime < PERMIT_V2_LIMITS.minLifetimeSeconds ||
    defaultLifetime > PERMIT_V2_LIMITS.maxLifetimeSeconds
  ) {
    throw new Error("MCP gate lifetimeSeconds must be between 30 and 900");
  }
  const nonceStore = config.nonceStore ?? createInMemoryPermitNonceStoreV2();

  return {
    nonceStore,

    /**
     * Round 1: Emits a stateless MCP 2026-07-28 `InputRequiredResult` carrying
     * an opaque `jti`, out-of-band approval URL, and HMAC-authenticated `requestState`.
     */
    async createInputRequiredResult(input: {
      action: CanonicalActionV2Input;
      summary?: string;
      jti?: string;
      approvalUrl?: string;
      lifetimeSeconds?: number;
      nowSeconds?: number | (() => number);
    }): Promise<McpInputRequiredResult> {
      const now = readNow(input.nowSeconds ?? config.nowSeconds);
      const lifetime = input.lifetimeSeconds ?? defaultLifetime;
      if (
        !Number.isSafeInteger(lifetime) ||
        lifetime < PERMIT_V2_LIMITS.minLifetimeSeconds ||
        lifetime > PERMIT_V2_LIMITS.maxLifetimeSeconds ||
        lifetime > config.policy.max_permit_lifetime_seconds
      ) {
        throw new Error("Challenge lifetime exceeds policy bounds");
      }

      const { requestDigest } = hashActionV2(input.action);
      const jti = input.jti ?? randomHex32Bytes();
      if (!isLowerHex64NonZero(jti)) {
        throw new Error("Challenge jti must be a non-zero 64-hex string");
      }

      const exp = now + lifetime;
      const approvalUrl =
        input.approvalUrl ??
        `${approvalBaseUrl.replace(/\/+$/, "")}/${encodeURIComponent(jti)}`;
      if (!isStrictHttpsOrLoopbackUri(approvalUrl)) {
        throw new Error("Approval URL must be strict HTTPS (or loopback)");
      }

      const claims: MrtrRequestStateClaims = {
        v: 2,
        jti,
        request_digest: requestDigest,
        aud: config.audience,
        policy_id: config.policy.policy_id,
        iat: now,
        exp,
      };
      const requestState = signMrtrRequestState(claims, secretBytes);

      if (config.requireRegisteredNonce) {
        await nonceStore.register({
          jti,
          requestDigest,
          aud: config.audience,
          policyId: config.policy.policy_id,
          issuedAt: now,
          expiresAt: exp,
        });
      }

      const message =
        input.summary ??
        `Approve ${input.action.server}.${input.action.tool} out of band`;

      return {
        resultType: "input_required",
        inputRequests: [
          {
            mode: "url",
            elicitationId: jti,
            url: approvalUrl,
            message,
            cacheable: false,
          },
        ],
        requestState,
        metadata: {
          jti,
          request_digest: requestDigest,
          aud: config.audience,
          policy_id: config.policy.policy_id,
          iat: now,
          exp,
        },
      };
    },

    /**
     * Round 2: Verifies `requestState` HMAC, recomputes `request_digest` from the
     * retried tool invocation, validates the presented `Entros-Agent-Permit-v2`,
     * and consumes `jti` atomically only after all prechecks pass.
     */
    async verifyInputResponse(input: {
      action: CanonicalActionV2Input;
      requestState: string;
      inputResponses: unknown;
      dpop?: { proof: string; htm: string; htu: string; maxAgeSeconds?: number };
      webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
      nowSeconds?: number | (() => number);
    }): Promise<VerifyAgentPermitV2Result> {
      const now = readNow(input.nowSeconds ?? config.nowSeconds);
      const stateCheck = verifyMrtrRequestState(
        input.requestState,
        secretBytes,
        now,
      );
      if (!stateCheck.ok) {
        return {
          decision: "deny",
          reason:
            stateCheck.reason === "state_expired"
              ? "permit_expired"
              : "invalid_permit",
          detail: `MRTR requestState failed verification: ${stateCheck.reason}`,
          permit: null,
          evaluatedAt: now,
        };
      }

      const state = stateCheck.claims;
      if (state.aud !== config.audience) {
        return {
          decision: "deny",
          reason: "audience_mismatch",
          detail: "MRTR requestState aud does not match MCP gate audience",
          permit: null,
          evaluatedAt: now,
        };
      }
      if (state.policy_id !== config.policy.policy_id) {
        return {
          decision: "deny",
          reason: "policy_mismatch",
          detail: "MRTR requestState policy_id does not match MCP gate policy",
          permit: null,
          evaluatedAt: now,
        };
      }

      let liveDigest: string;
      try {
        liveDigest = hashActionV2(input.action).requestDigest;
      } catch {
        return {
          decision: "deny",
          reason: "request_digest_mismatch",
          detail: "Failed to canonicalize retried MCP action",
          permit: null,
          evaluatedAt: now,
        };
      }
      if (!constantTimeEqualString(liveDigest, state.request_digest)) {
        return {
          decision: "deny",
          reason: "request_digest_mismatch",
          detail: "Retried tool action differs from original MRTR requestState",
          permit: null,
          evaluatedAt: now,
        };
      }

      const permitJws = extractPermitJws(input.inputResponses, state.jti);
      if (!permitJws) {
        return {
          decision: "deny",
          reason: "invalid_jws",
          detail: "MRTR inputResponses did not carry an Entros-Agent-Permit-v2 JWS",
          permit: null,
          evaluatedAt: now,
        };
      }

      // Run full permit verification; validate jti binding to requestState before atomic consume.
      const jtiBoundStore: PermitNonceStoreV2 = {
        register: (rec) => nonceStore.register(rec),
        peek: (jti) => nonceStore.peek(jti),
        consume: (consumeInput) => {
          if (!constantTimeEqualString(consumeInput.jti, state.jti)) {
            return { status: "not_found" };
          }
          return nonceStore.consume(consumeInput);
        },
      };

      return verifyAgentPermitV2({
        permitJws,
        policy: config.policy,
        expectedAudience: config.audience,
        action: input.action,
        expectedRequestDigest: state.request_digest,
        jwks: config.jwks,
        voiceJwks: config.voiceJwks,
        scittJwks: config.scittJwks,
        revokedKids: config.revokedKids,
        nowSeconds: input.nowSeconds ?? config.nowSeconds ?? now,
        dpop: input.dpop,
        webauthn: input.webauthn,
        nonceStore: jtiBoundStore,
        requireRegisteredNonce: config.requireRegisteredNonce,
      });
    },
  };
}
