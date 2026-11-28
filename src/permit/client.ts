/**
 * REST client for Entros Firewall API permit endpoints:
 * - `POST /v1/permits/issue`
 * - `POST /v1/permits/step-up` (`operation: "create" | "poll" | "complete"`)
 * - `POST /v1/permits/verify`
 * - `GET /v1/permits/receipt/{jti}`
 * - `GET /.well-known/jwks.json`
 */

import { hashActionV2 } from "./canonical";
import {
  base64UrlEncode,
  isLowerHex64NonZero,
  isPlainRecord,
  isStrictHttpsOrLoopbackUri,
} from "./encoding";
import { createJwksCache, type JwksCache } from "./jwks";
import { verifyScittReceipt } from "./scitt";
import {
  ALL_ASSURANCE_TIERS_V2,
  type AssuranceTierV2,
  type CanonicalActionV2Input,
  type EcP256Jwk,
  type Ed25519Jwk,
  type JwksDocument,
  type JwksSource,
  type PermitActorV2,
  type PolicyV2,
  type UniquenessStatusV2,
  type VerifiedScittReceipt,
  type WebAuthnAssertionInput,
} from "./types";

const ASSURANCE_SET: ReadonlySet<string> = new Set(ALL_ASSURANCE_TIERS_V2);
const STEP_UP_PROTOCOLS = new Set<StepUpProtocolV2>([
  "mcp_mrtr",
  "sep_1036",
  "oidc_ciba",
]);

export interface PermitApiClientConfig {
  /** Base HTTPS URI (or http://127.0.0.1 for local tests). */
  baseUrl: string;
  /** Optional Bearer API key. */
  apiKey?: string;
  /** Optional custom fetch implementation. */
  fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds. Default 10,000. */
  timeoutMs?: number;
}

export interface WireWebAuthnEvidenceV2 {
  credential_id: string | Uint8Array;
  authenticator_data: string | Uint8Array;
  client_data_json: string | Uint8Array;
  signature: string | Uint8Array;
  public_key: EcP256Jwk | string;
  expected_rp_id: string;
  expected_origin: string;
  stored_sign_count?: number;
  allow_cross_origin?: boolean;
  challenge_jti?: string;
}

export interface IssuePermitEvidenceV2 {
  voice_verdict_jws?: string | null;
  webauthn_assertion?: WireWebAuthnEvidenceV2;
}

export interface IssuePermitRequestV2 {
  sub: string;
  actor: PermitActorV2;
  aud: string;
  ttl_seconds?: number;
  action: CanonicalActionV2Input;
  policy: PolicyV2;
  evidence?: IssuePermitEvidenceV2;
  uniqueness_status?: UniquenessStatusV2;
  session_id?: string;
  authorization_details?: unknown[];
  txn?: string;
}

export interface IssuedPermitResponseV2 {
  status: "issued";
  jti: string;
  request_digest: string;
  assurance_tier: AssuranceTierV2;
  permit_jws: string;
  scitt_receipt: string;
  expires_at: number;
}

export interface StepUpRequiredIssueResponseV2 {
  status: "step_up_required";
  reason: string;
  required_assurance_tier: AssuranceTierV2;
  request_digest: string;
  recommended_step_up_endpoint: string;
}

export type IssuePermitResponseV2 =
  | IssuedPermitResponseV2
  | StepUpRequiredIssueResponseV2;

export type StepUpProtocolV2 = "mcp_mrtr" | "sep_1036" | "oidc_ciba";
export type StepUpModeV2 = StepUpProtocolV2;

export interface CreateStepUpRequestV2 {
  protocol: StepUpProtocolV2;
  sub: string;
  actor: PermitActorV2;
  aud: string;
  policy_id: string;
  action?: CanonicalActionV2Input;
  request_digest?: string;
  uniqueness_status?: UniquenessStatusV2;
  session_id?: string;
  voice_verdict_jws?: string | null;
  ttl_seconds?: number;
  summary?: string;
  authorization_details?: unknown[];
  txn?: string;
}

export interface McpInputRequiredWireV2 {
  resultType: string;
  requestState: string;
  inputRequests: Array<{
    mode: string;
    elicitationId: string;
    url: string;
    message: string;
    cacheable: boolean;
  }>;
}

export interface Sep1036ElicitationWireV2 {
  method: string;
  mode: string;
  elicitationId: string;
  url: string;
  message: string;
  expires_at: number;
}

export interface OidcCibaWireV2 {
  auth_req_id: string;
  expires_in: number;
  interval: number;
}

export interface CreateStepUpResponseV2 {
  jti: string;
  protocol: StepUpProtocolV2;
  approval_url: string;
  challenge_b64url: string;
  expires_at: number;
  mcp_input_required?: McpInputRequiredWireV2;
  sep_1036?: Sep1036ElicitationWireV2;
  ciba?: OidcCibaWireV2;
}

export interface CompleteStepUpRequestV2 {
  jti: string;
  webauthn_assertion: WebAuthnAssertionInput;
  public_key: EcP256Jwk | string;
  expected_rp_id: string;
  expected_origin: string;
  stored_sign_count?: number;
  allow_cross_origin?: boolean;
}

export interface CompleteStepUpResponseV2 {
  jti: string;
  request_digest: string;
  assurance_tier: AssuranceTierV2;
  freshness_verified_at: number;
  expires_at: number;
  webauthn_assertion_digest: string;
  permit_jws: string;
  scitt_receipt: string;
}

export type PollStepUpResponseV2 =
  | { status: "pending"; jti: string; expires_at: number }
  | ({ status: "completed" } & CompleteStepUpResponseV2)
  | { status: "expired"; jti: string; expires_at: number };

export interface VerifyPermitOnlineRequestV2 {
  permit_jws: string;
  expected_aud: string;
  action: CanonicalActionV2Input;
  policy: PolicyV2;
  dpop_proof_jws?: string;
  dpop_htm?: string;
  dpop_htu?: string;
  webauthn?: WireWebAuthnEvidenceV2;
}

export interface VerifyPermitOnlineResponseV2 {
  verified: boolean;
  ok: boolean;
  decision: "allow" | "deny";
  reason: string | null;
  refusal_code: string | null;
  message: string | null;
  jti: string | null;
  assurance_tier: AssuranceTierV2 | null;
  freshness_verified_at: number | null;
  consumed_at: number | null;
  scitt_receipt: string | null;
}

export interface FetchScittReceiptOptionsV2 {
  signal?: AbortSignal;
  /**
   * JWKS source used to verify the SCITT receipt offline. On `EntrosClient`,
   * defaults to `this.jwks`; pass `false` or `null` to opt out.
   */
  verifyWithJwks?: JwksSource | false | null;
  revokedKids?: ReadonlySet<string> | readonly string[];
}

export interface FetchScittReceiptResponseV2 {
  jti: string;
  contentType: string;
  receiptBytes: Uint8Array | null;
  receiptB64Url: string | null;
  verifiedReceipt: VerifiedScittReceipt | null;
}

export class PermitApiError extends Error {
  constructor(
    public readonly code:
      | "invalid_config"
      | "invalid_input"
      | "http_error"
      | "invalid_response"
      | "receipt_verification_failed",
    message: string,
    public readonly status?: number,
    public readonly refusalCode?: string,
  ) {
    super(message);
    this.name = "PermitApiError";
  }
}

function isSafeInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isAssuranceTier(value: unknown): value is AssuranceTierV2 {
  return typeof value === "string" && ASSURANCE_SET.has(value);
}

function isStepUpProtocol(value: unknown): value is StepUpProtocolV2 {
  return (
    typeof value === "string" &&
    STEP_UP_PROTOCOLS.has(value as StepUpProtocolV2)
  );
}

function encodeAssertionBytes(value: string | Uint8Array): string {
  return value instanceof Uint8Array ? base64UrlEncode(value) : value;
}

function serializeWebAuthnAssertion(
  assertion: WebAuthnAssertionInput,
): Record<string, string> {
  return {
    credential_id: encodeAssertionBytes(assertion.credential_id),
    authenticator_data: encodeAssertionBytes(assertion.authenticator_data),
    client_data_json: encodeAssertionBytes(assertion.client_data_json),
    signature: encodeAssertionBytes(assertion.signature),
  };
}

function serializeWireWebAuthnEvidence(
  evidence: WireWebAuthnEvidenceV2,
): Record<string, unknown> {
  return {
    ...serializeWebAuthnAssertion(evidence),
    public_key: evidence.public_key,
    expected_rp_id: evidence.expected_rp_id,
    expected_origin: evidence.expected_origin,
    ...(evidence.stored_sign_count !== undefined
      ? { stored_sign_count: evidence.stored_sign_count }
      : {}),
    ...(evidence.allow_cross_origin !== undefined
      ? { allow_cross_origin: evidence.allow_cross_origin }
      : {}),
    ...(evidence.challenge_jti !== undefined
      ? { challenge_jti: evidence.challenge_jti }
      : {}),
  };
}

function validateJwksDocument(raw: unknown): JwksDocument {
  if (!isPlainRecord(raw) || !Array.isArray(raw.keys)) {
    throw new PermitApiError(
      "invalid_response",
      "JWKS document missing keys array",
    );
  }
  const keys: Ed25519Jwk[] = [];
  for (const item of raw.keys) {
    if (!isPlainRecord(item)) continue;
    if (
      item.kty === "OKP" &&
      item.crv === "Ed25519" &&
      typeof item.kid === "string" &&
      typeof item.x === "string"
    ) {
      keys.push({
        kty: "OKP",
        crv: "Ed25519",
        kid: item.kid,
        x: item.x,
        ...(item.use === "sig" ? { use: "sig" } : {}),
        ...(item.alg === "EdDSA" ? { alg: "EdDSA" } : {}),
        ...(typeof item.status === "string" ? { status: item.status } : {}),
      });
    }
  }
  return { keys };
}

function validateIssueResponse(raw: unknown): IssuePermitResponseV2 {
  if (!isPlainRecord(raw)) {
    throw new PermitApiError(
      "invalid_response",
      "Permit issue response must be a JSON object",
    );
  }
  if (raw.status === "step_up_required") {
    if (
      typeof raw.reason !== "string" ||
      !isAssuranceTier(raw.required_assurance_tier) ||
      typeof raw.request_digest !== "string" ||
      typeof raw.recommended_step_up_endpoint !== "string"
    ) {
      throw new PermitApiError(
        "invalid_response",
        "Permit step_up_required response missing required fields",
      );
    }
    return {
      status: "step_up_required",
      reason: raw.reason,
      required_assurance_tier: raw.required_assurance_tier,
      request_digest: raw.request_digest,
      recommended_step_up_endpoint: raw.recommended_step_up_endpoint,
    };
  }
  if (
    raw.status !== "issued" ||
    typeof raw.jti !== "string" ||
    typeof raw.request_digest !== "string" ||
    !isAssuranceTier(raw.assurance_tier) ||
    typeof raw.permit_jws !== "string" ||
    typeof raw.scitt_receipt !== "string" ||
    !isSafeInt(raw.expires_at)
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Permit issue response missing required fields",
    );
  }
  return {
    status: "issued",
    jti: raw.jti,
    request_digest: raw.request_digest,
    assurance_tier: raw.assurance_tier,
    permit_jws: raw.permit_jws,
    scitt_receipt: raw.scitt_receipt,
    expires_at: raw.expires_at,
  };
}

function validateMcpInputRequiredWire(
  raw: unknown,
): McpInputRequiredWireV2 | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (
    !isPlainRecord(raw) ||
    typeof raw.resultType !== "string" ||
    typeof raw.requestState !== "string" ||
    !Array.isArray(raw.inputRequests)
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Invalid mcp_input_required payload in step-up response",
    );
  }
  const inputRequests: McpInputRequiredWireV2["inputRequests"] = [];
  for (const item of raw.inputRequests) {
    if (
      !isPlainRecord(item) ||
      typeof item.mode !== "string" ||
      typeof item.elicitationId !== "string" ||
      typeof item.url !== "string" ||
      typeof item.message !== "string" ||
      typeof item.cacheable !== "boolean"
    ) {
      throw new PermitApiError(
        "invalid_response",
        "Invalid inputRequests item in step-up response",
      );
    }
    inputRequests.push({
      mode: item.mode,
      elicitationId: item.elicitationId,
      url: item.url,
      message: item.message,
      cacheable: item.cacheable,
    });
  }
  return {
    resultType: raw.resultType,
    requestState: raw.requestState,
    inputRequests,
  };
}

function validateSep1036Wire(raw: unknown): Sep1036ElicitationWireV2 | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (
    !isPlainRecord(raw) ||
    typeof raw.method !== "string" ||
    typeof raw.mode !== "string" ||
    typeof raw.elicitationId !== "string" ||
    typeof raw.url !== "string" ||
    typeof raw.message !== "string" ||
    !isSafeInt(raw.expires_at)
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Invalid sep_1036 payload in step-up response",
    );
  }
  return {
    method: raw.method,
    mode: raw.mode,
    elicitationId: raw.elicitationId,
    url: raw.url,
    message: raw.message,
    expires_at: raw.expires_at,
  };
}

function validateOidcCibaWire(raw: unknown): OidcCibaWireV2 | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (
    !isPlainRecord(raw) ||
    typeof raw.auth_req_id !== "string" ||
    !isSafeInt(raw.expires_in) ||
    !isSafeInt(raw.interval)
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Invalid ciba payload in step-up response",
    );
  }
  return {
    auth_req_id: raw.auth_req_id,
    expires_in: raw.expires_in,
    interval: raw.interval,
  };
}

function validateCreateStepUpResponse(raw: unknown): CreateStepUpResponseV2 {
  if (
    !isPlainRecord(raw) ||
    typeof raw.jti !== "string" ||
    !isStepUpProtocol(raw.protocol) ||
    typeof raw.approval_url !== "string" ||
    typeof raw.challenge_b64url !== "string" ||
    !isSafeInt(raw.expires_at)
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Create step-up response missing required fields",
    );
  }
  const mcp_input_required = validateMcpInputRequiredWire(
    raw.mcp_input_required,
  );
  const sep_1036 = validateSep1036Wire(raw.sep_1036);
  const ciba = validateOidcCibaWire(raw.ciba);
  return {
    jti: raw.jti,
    protocol: raw.protocol,
    approval_url: raw.approval_url,
    challenge_b64url: raw.challenge_b64url,
    expires_at: raw.expires_at,
    ...(mcp_input_required !== undefined ? { mcp_input_required } : {}),
    ...(sep_1036 !== undefined ? { sep_1036 } : {}),
    ...(ciba !== undefined ? { ciba } : {}),
  };
}

function validateCompleteStepUpResponse(raw: unknown): CompleteStepUpResponseV2 {
  if (
    !isPlainRecord(raw) ||
    typeof raw.jti !== "string" ||
    typeof raw.request_digest !== "string" ||
    !isAssuranceTier(raw.assurance_tier) ||
    !isSafeInt(raw.freshness_verified_at) ||
    !isSafeInt(raw.expires_at) ||
    typeof raw.webauthn_assertion_digest !== "string" ||
    typeof raw.permit_jws !== "string" ||
    typeof raw.scitt_receipt !== "string"
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Complete step-up response missing required fields",
    );
  }
  return {
    jti: raw.jti,
    request_digest: raw.request_digest,
    assurance_tier: raw.assurance_tier,
    freshness_verified_at: raw.freshness_verified_at,
    expires_at: raw.expires_at,
    webauthn_assertion_digest: raw.webauthn_assertion_digest,
    permit_jws: raw.permit_jws,
    scitt_receipt: raw.scitt_receipt,
  };
}

function validatePollStepUpResponse(raw: unknown): PollStepUpResponseV2 {
  if (!isPlainRecord(raw) || typeof raw.status !== "string") {
    throw new PermitApiError(
      "invalid_response",
      "Poll step-up response missing status field",
    );
  }
  if (raw.status === "pending" || raw.status === "expired") {
    if (typeof raw.jti !== "string" || !isSafeInt(raw.expires_at)) {
      throw new PermitApiError(
        "invalid_response",
        `Poll step-up '${raw.status}' response missing jti or expires_at`,
      );
    }
    return {
      status: raw.status,
      jti: raw.jti,
      expires_at: raw.expires_at,
    };
  }
  if (raw.status === "completed") {
    return {
      status: "completed",
      ...validateCompleteStepUpResponse(raw),
    };
  }
  throw new PermitApiError(
    "invalid_response",
    `Unknown poll step-up status '${raw.status}'`,
  );
}

function validateVerifyOnlineResponse(
  raw: unknown,
  httpStatus: number,
): VerifyPermitOnlineResponseV2 {
  if (!isPlainRecord(raw)) {
    throw new PermitApiError(
      "invalid_response",
      "Verify permit response must be a JSON object",
      httpStatus,
    );
  }
  const hasVerified = typeof raw.verified === "boolean";
  const hasOk = typeof raw.ok === "boolean";
  if (hasVerified && hasOk && raw.verified !== raw.ok) {
    throw new PermitApiError(
      "invalid_response",
      "Verify permit response has contradictory verified and ok fields",
      httpStatus,
    );
  }
  const verified = hasVerified
    ? (raw.verified as boolean)
    : hasOk
      ? (raw.ok as boolean)
      : null;
  if (verified === null) {
    throw new PermitApiError(
      "invalid_response",
      "Verify permit response missing boolean verified field",
      httpStatus,
    );
  }
  if (
    raw.decision !== undefined &&
    raw.decision !== "allow" &&
    raw.decision !== "deny"
  ) {
    throw new PermitApiError(
      "invalid_response",
      "Verify permit response has invalid decision field",
      httpStatus,
    );
  }
  const decision: "allow" | "deny" =
    raw.decision === "allow" || raw.decision === "deny"
      ? raw.decision
      : verified
        ? "allow"
        : "deny";
  if (verified !== (decision === "allow")) {
    throw new PermitApiError(
      "invalid_response",
      "Verify permit response verified and decision fields disagree",
      httpStatus,
    );
  }
  if (httpStatus >= 400 && (verified || decision === "allow")) {
    throw new PermitApiError(
      "invalid_response",
      `Verify permit HTTP ${httpStatus} response cannot report allow`,
      httpStatus,
    );
  }
  const refusalCode =
    typeof raw.refusal_code === "string"
      ? raw.refusal_code
      : typeof raw.reason === "string"
        ? raw.reason
        : null;
  const message = typeof raw.message === "string" ? raw.message : null;
  return {
    verified,
    ok: verified,
    decision,
    reason: refusalCode,
    refusal_code: refusalCode,
    message,
    jti: typeof raw.jti === "string" ? raw.jti : null,
    assurance_tier: isAssuranceTier(raw.assurance_tier)
      ? raw.assurance_tier
      : null,
    freshness_verified_at: isSafeInt(raw.freshness_verified_at)
      ? raw.freshness_verified_at
      : null,
    consumed_at: isSafeInt(raw.consumed_at) ? raw.consumed_at : null,
    scitt_receipt:
      typeof raw.scitt_receipt === "string" ? raw.scitt_receipt : null,
  };
}

export class PermitApiClient {
  readonly #baseUrl: string;
  readonly #apiKey?: string;
  readonly #fetchImpl: typeof globalThis.fetch;
  readonly #timeoutMs: number;
  #jwksCache: JwksCache | null = null;

  constructor(config: PermitApiClientConfig) {
    if (!isStrictHttpsOrLoopbackUri(config.baseUrl)) {
      throw new PermitApiError(
        "invalid_config",
        "Permit API baseUrl must be a strict HTTPS URI (or http://127.0.0.1 for local tests)",
      );
    }
    const fetchImpl = config.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new PermitApiError(
        "invalid_config",
        "A fetch implementation is required for PermitApiClient",
      );
    }
    this.#baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.#apiKey = config.apiKey;
    this.#fetchImpl = fetchImpl;
    this.#timeoutMs = config.timeoutMs ?? 10_000;
  }

  get jwksCache(): JwksCache {
    if (!this.#jwksCache) {
      this.#jwksCache = createJwksCache({
        jwksUrl: `${this.#baseUrl}/.well-known/jwks.json`,
        fetch: this.#fetchImpl,
        timeoutMs: this.#timeoutMs,
      });
    }
    return this.#jwksCache;
  }

  async #requestJson<T>(
    method: "GET" | "POST",
    path: string,
    validate: (raw: unknown, httpStatus: number) => T,
    body?: Record<string, unknown>,
    signal?: AbortSignal,
    allowedNon2xxStatuses?: ReadonlySet<number>,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const headers: Record<string, string> = {
        accept: "application/json",
      };
      if (body !== undefined) {
        headers["content-type"] = "application/json";
      }
      if (this.#apiKey) {
        headers.authorization = `Bearer ${this.#apiKey}`;
      }

      const response = await this.#fetchImpl(`${this.#baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const acceptStatus =
        response.ok ||
        (allowedNon2xxStatuses !== undefined &&
          allowedNon2xxStatuses.has(response.status));

      if (!acceptStatus) {
        let refusalCode: string | undefined;
        try {
          const errBody: unknown = await response.json();
          if (isPlainRecord(errBody)) {
            if (typeof errBody.refusal_code === "string") {
              refusalCode = errBody.refusal_code;
            } else if (typeof errBody.error === "string") {
              refusalCode = errBody.error;
            }
          }
        } catch {
          // Ignore non-JSON error payload.
        }
        throw new PermitApiError(
          "http_error",
          `Permit API ${method} ${path} failed with HTTP ${response.status}`,
          response.status,
          refusalCode,
        );
      }

      let rawJson: unknown;
      try {
        rawJson = await response.json();
      } catch {
        throw new PermitApiError(
          "invalid_response",
          `Permit API ${method} ${path} returned non-JSON response`,
          response.status,
        );
      }
      return validate(rawJson, response.status);
    } catch (error) {
      if (error instanceof PermitApiError) throw error;
      throw new PermitApiError(
        "http_error",
        error instanceof Error ? error.message : "Permit API transport error",
      );
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  async fetchJwks(signal?: AbortSignal): Promise<JwksDocument> {
    return this.#requestJson(
      "GET",
      "/.well-known/jwks.json",
      validateJwksDocument,
      undefined,
      signal,
    );
  }

  async issuePermit(
    input: IssuePermitRequestV2,
    signal?: AbortSignal,
  ): Promise<IssuePermitResponseV2> {
    try {
      hashActionV2(input.action);
    } catch {
      throw new PermitApiError(
        "invalid_input",
        "issuePermit action failed RFC 8785 canonical validation",
      );
    }

    const evidencePayload: Record<string, unknown> = {};
    if (input.evidence?.voice_verdict_jws !== undefined) {
      evidencePayload.voice_verdict_jws = input.evidence.voice_verdict_jws;
    }
    if (input.evidence?.webauthn_assertion !== undefined) {
      evidencePayload.webauthn_assertion = serializeWireWebAuthnEvidence(
        input.evidence.webauthn_assertion,
      );
    }

    const body: Record<string, unknown> = {
      sub: input.sub,
      actor: input.actor,
      aud: input.aud,
      ttl_seconds: input.ttl_seconds ?? 300,
      action: input.action,
      policy: input.policy,
      evidence: evidencePayload,
      ...(input.uniqueness_status !== undefined
        ? { uniqueness_status: input.uniqueness_status }
        : {}),
      ...(input.session_id !== undefined ? { session_id: input.session_id } : {}),
      ...(input.authorization_details !== undefined
        ? { authorization_details: input.authorization_details }
        : {}),
      ...(input.txn !== undefined ? { txn: input.txn } : {}),
    };

    return this.#requestJson(
      "POST",
      "/v1/permits/issue",
      validateIssueResponse,
      body,
      signal,
    );
  }

  async createStepUp(
    input: CreateStepUpRequestV2,
    signal?: AbortSignal,
  ): Promise<CreateStepUpResponseV2> {
    const requestDigest =
      input.request_digest ??
      (input.action ? hashActionV2(input.action).requestDigest : undefined);
    if (!requestDigest || !isLowerHex64NonZero(requestDigest)) {
      throw new PermitApiError(
        "invalid_input",
        "createStepUp requires either action or a valid 64-hex request_digest",
      );
    }

    const body: Record<string, unknown> = {
      operation: "create",
      protocol: input.protocol,
      sub: input.sub,
      actor: input.actor,
      aud: input.aud,
      request_digest: requestDigest,
      policy_id: input.policy_id,
      ttl_seconds: input.ttl_seconds ?? 300,
      ...(input.uniqueness_status !== undefined
        ? { uniqueness_status: input.uniqueness_status }
        : {}),
      ...(input.session_id !== undefined ? { session_id: input.session_id } : {}),
      ...(input.voice_verdict_jws !== undefined
        ? { voice_verdict_jws: input.voice_verdict_jws }
        : {}),
      ...(input.summary !== undefined ? { summary: input.summary } : {}),
      ...(input.authorization_details !== undefined
        ? { authorization_details: input.authorization_details }
        : {}),
      ...(input.txn !== undefined ? { txn: input.txn } : {}),
    };

    return this.#requestJson(
      "POST",
      "/v1/permits/step-up",
      validateCreateStepUpResponse,
      body,
      signal,
    );
  }

  async pollStepUp(
    jti: string,
    signal?: AbortSignal,
  ): Promise<PollStepUpResponseV2> {
    if (!isLowerHex64NonZero(jti)) {
      throw new PermitApiError(
        "invalid_input",
        "pollStepUp requires a non-zero 64-char lowercase hex jti",
      );
    }
    return this.#requestJson(
      "POST",
      "/v1/permits/step-up",
      validatePollStepUpResponse,
      { operation: "poll", jti },
      signal,
    );
  }

  async completeStepUp(
    input: CompleteStepUpRequestV2,
    signal?: AbortSignal,
  ): Promise<CompleteStepUpResponseV2> {
    if (!isLowerHex64NonZero(input.jti)) {
      throw new PermitApiError(
        "invalid_input",
        "completeStepUp requires a non-zero 64-char lowercase hex jti",
      );
    }
    const body: Record<string, unknown> = {
      operation: "complete",
      jti: input.jti,
      webauthn_assertion: serializeWebAuthnAssertion(input.webauthn_assertion),
      public_key: input.public_key,
      expected_rp_id: input.expected_rp_id,
      expected_origin: input.expected_origin,
      ...(input.stored_sign_count !== undefined
        ? { stored_sign_count: input.stored_sign_count }
        : {}),
      ...(input.allow_cross_origin !== undefined
        ? { allow_cross_origin: input.allow_cross_origin }
        : {}),
    };
    return this.#requestJson(
      "POST",
      "/v1/permits/step-up",
      validateCompleteStepUpResponse,
      body,
      signal,
    );
  }

  async verifyPermitOnline(
    input: VerifyPermitOnlineRequestV2,
    signal?: AbortSignal,
  ): Promise<VerifyPermitOnlineResponseV2> {
    try {
      hashActionV2(input.action);
    } catch {
      throw new PermitApiError(
        "invalid_input",
        "verifyPermitOnline action failed RFC 8785 canonical validation",
      );
    }

    const body: Record<string, unknown> = {
      permit_jws: input.permit_jws,
      expected_aud: input.expected_aud,
      action: input.action,
      policy: input.policy,
      ...(input.dpop_proof_jws !== undefined
        ? { dpop_proof_jws: input.dpop_proof_jws }
        : {}),
      ...(input.dpop_htm !== undefined ? { dpop_htm: input.dpop_htm } : {}),
      ...(input.dpop_htu !== undefined ? { dpop_htu: input.dpop_htu } : {}),
      ...(input.webauthn !== undefined
        ? { webauthn: serializeWireWebAuthnEvidence(input.webauthn) }
        : {}),
    };

    return this.#requestJson(
      "POST",
      "/v1/permits/verify",
      validateVerifyOnlineResponse,
      body,
      signal,
      new Set([403, 409]),
    );
  }

  async fetchScittReceipt(
    jti: string,
    signalOrOptions?: AbortSignal | FetchScittReceiptOptionsV2,
  ): Promise<FetchScittReceiptResponseV2> {
    if (!isLowerHex64NonZero(jti)) {
      throw new PermitApiError(
        "invalid_input",
        "fetchScittReceipt requires a non-zero 64-char lowercase hex jti",
      );
    }

    const opts: FetchScittReceiptOptionsV2 =
      signalOrOptions !== undefined && "aborted" in signalOrOptions
        ? { signal: signalOrOptions }
        : (signalOrOptions ?? {});

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const onAbort = () => controller.abort();
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const headers: Record<string, string> = {
        accept: "application/scitt-receipt+cose, application/json",
      };
      if (this.#apiKey) {
        headers.authorization = `Bearer ${this.#apiKey}`;
      }
      const response = await this.#fetchImpl(
        `${this.#baseUrl}/v1/permits/receipt/${encodeURIComponent(jti)}`,
        {
          method: "GET",
          headers,
          signal: controller.signal,
        },
      );
      if (!response.ok) {
        throw new PermitApiError(
          "http_error",
          `SCITT receipt fetch failed with HTTP ${response.status}`,
          response.status,
        );
      }
      const contentType =
        response.headers?.get("content-type") ?? "application/json";
      let receiptBytes: Uint8Array | null = null;
      let receiptB64Url: string | null = null;

      if (contentType.toLowerCase().includes("application/json")) {
        const json: unknown = await response.json();
        if (!isPlainRecord(json) || typeof json.scitt_receipt !== "string") {
          throw new PermitApiError(
            "invalid_response",
            "SCITT receipt JSON envelope missing scitt_receipt",
            response.status,
          );
        }
        if (typeof json.jti === "string" && json.jti !== jti) {
          throw new PermitApiError(
            "invalid_response",
            "SCITT receipt envelope jti does not match requested jti",
            response.status,
          );
        }
        receiptB64Url = json.scitt_receipt;
      } else {
        receiptBytes = new Uint8Array(await response.arrayBuffer());
      }

      let verifiedReceipt: VerifiedScittReceipt | null = null;
      if (opts.verifyWithJwks) {
        const rawReceipt = receiptBytes ?? receiptB64Url;
        if (!rawReceipt) {
          throw new PermitApiError(
            "invalid_response",
            "SCITT receipt response contained no receipt payload",
          );
        }
        const verified = await verifyScittReceipt({
          receipt: rawReceipt,
          jwks: opts.verifyWithJwks,
          revokedKids: opts.revokedKids,
          expectedJti: jti,
        });
        if (!verified.ok) {
          throw new PermitApiError(
            "receipt_verification_failed",
            `SCITT receipt verification failed: ${verified.detail}`,
          );
        }
        verifiedReceipt = verified.receipt;
      }

      return {
        jti,
        contentType,
        receiptBytes,
        receiptB64Url,
        verifiedReceipt,
      };
    } catch (error) {
      if (error instanceof PermitApiError) throw error;
      throw new PermitApiError(
        "http_error",
        error instanceof Error ? error.message : "SCITT receipt fetch failed",
      );
    } finally {
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
    }
  }
}

export function createPermitApiClient(
  config: PermitApiClientConfig,
): PermitApiClient {
  return new PermitApiClient(config);
}
