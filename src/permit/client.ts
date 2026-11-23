/**
 * REST client for Entros Firewall API permit endpoints:
 * - `POST /v1/permits/issue`
 * - `POST /v1/permits/step-up`
 * - `POST /v1/permits/verify`
 * - `GET /v1/permits/receipt/{jti}`
 * - `GET /.well-known/jwks.json`
 */

import { hashActionV2 } from "./canonical";
import {
  isLowerHex64NonZero,
  isPlainRecord,
  isStrictHttpsOrLoopbackUri,
} from "./encoding";
import { createJwksCache, type JwksCache } from "./jwks";
import type {
  CanonicalActionV2Input,
  JwksDocument,
  PermitActorV2,
  PermitContinuityV2,
  PolicyV2,
  WebAuthnAssertionInput,
} from "./types";

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

export interface IssuePermitRequestV2 {
  sub: string;
  actor: PermitActorV2;
  aud: string;
  policy_id: string;
  action?: CanonicalActionV2Input;
  request_digest?: string;
  continuity?: PermitContinuityV2;
  voice_verdict_jws?: string | null;
  webauthn_assertion?: WebAuthnAssertionInput;
  lifetime_seconds?: number;
  authorization_details?: unknown[];
  txn?: string;
}

export interface IssuePermitResponseV2 {
  permit_jws: string;
  jti: string;
  request_digest: string;
  expires_at: number;
  scitt_receipt?: string | null;
}

export type StepUpModeV2 = "mcp_mrtr" | "sep_1036" | "oidc_ciba";

export interface CreateStepUpRequestV2 {
  mode: StepUpModeV2;
  sub: string;
  actor: PermitActorV2;
  aud: string;
  policy_id: string;
  action?: CanonicalActionV2Input;
  request_digest?: string;
  session_id?: string;
  voice_verdict_jws?: string | null;
  lifetime_seconds?: number;
  binding_message?: string;
}

export interface CreateStepUpResponseV2 {
  jti: string;
  request_digest: string;
  mode: StepUpModeV2;
  approval_url: string;
  challenge_b64url: string;
  expires_at: number;
  auth_req_id?: string;
}

export interface VerifyPermitOnlineRequestV2 {
  permit_jws: string;
  aud: string;
  action?: CanonicalActionV2Input;
  request_digest?: string;
  policy?: PolicyV2;
  policy_id?: string;
  dpop_proof?: string;
  htm?: string;
  htu?: string;
}

export interface VerifyPermitOnlineResponseV2 {
  decision: "allow" | "deny" | "unavailable";
  reason: string;
  jti?: string | null;
  scitt_receipt?: string | null;
}

export interface FetchScittReceiptResponseV2 {
  jti: string;
  contentType: string;
  receiptBytes: Uint8Array | null;
  receiptB64Url: string | null;
}

export class PermitApiError extends Error {
  constructor(
    public readonly code: "invalid_config" | "invalid_input" | "http_error" | "invalid_response",
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "PermitApiError";
  }
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
    body?: Record<string, unknown>,
    signal?: AbortSignal,
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

      if (!response.ok) {
        throw new PermitApiError(
          "http_error",
          `Permit API ${method} ${path} failed with HTTP ${response.status}`,
          response.status,
        );
      }

      try {
        return (await response.json()) as T;
      } catch {
        throw new PermitApiError(
          "invalid_response",
          `Permit API ${method} ${path} returned non-JSON response`,
          response.status,
        );
      }
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
    return this.#requestJson<JwksDocument>(
      "GET",
      "/.well-known/jwks.json",
      undefined,
      signal,
    );
  }

  async issuePermit(
    input: IssuePermitRequestV2,
    signal?: AbortSignal,
  ): Promise<IssuePermitResponseV2> {
    const requestDigest =
      input.request_digest ??
      (input.action ? hashActionV2(input.action).requestDigest : undefined);
    if (!requestDigest || !isLowerHex64NonZero(requestDigest)) {
      throw new PermitApiError(
        "invalid_input",
        "issuePermit requires either action or a valid 64-hex request_digest",
      );
    }
    return this.#requestJson<IssuePermitResponseV2>(
      "POST",
      "/v1/permits/issue",
      {
        ...input,
        request_digest: requestDigest,
      },
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
    return this.#requestJson<CreateStepUpResponseV2>(
      "POST",
      "/v1/permits/step-up",
      {
        ...input,
        request_digest: requestDigest,
      },
      signal,
    );
  }

  async verifyPermitOnline(
    input: VerifyPermitOnlineRequestV2,
    signal?: AbortSignal,
  ): Promise<VerifyPermitOnlineResponseV2> {
    const requestDigest =
      input.request_digest ??
      (input.action ? hashActionV2(input.action).requestDigest : undefined);
    return this.#requestJson<VerifyPermitOnlineResponseV2>(
      "POST",
      "/v1/permits/verify",
      {
        ...input,
        ...(requestDigest !== undefined ? { request_digest: requestDigest } : {}),
      },
      signal,
    );
  }

  async fetchScittReceipt(
    jti: string,
    signal?: AbortSignal,
  ): Promise<FetchScittReceiptResponseV2> {
    if (!isLowerHex64NonZero(jti)) {
      throw new PermitApiError(
        "invalid_input",
        "fetchScittReceipt requires a non-zero 64-char lowercase hex jti",
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });

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
      if (contentType.includes("application/json")) {
        const json: unknown = await response.json();
        if (!isPlainRecord(json) || typeof json.scitt_receipt !== "string") {
          throw new PermitApiError(
            "invalid_response",
            "SCITT receipt JSON envelope missing scitt_receipt",
            response.status,
          );
        }
        return {
          jti,
          contentType,
          receiptBytes: null,
          receiptB64Url: json.scitt_receipt,
        };
      }
      const buf = new Uint8Array(await response.arrayBuffer());
      return {
        jti,
        contentType,
        receiptBytes: buf,
        receiptB64Url: null,
      };
    } catch (error) {
      if (error instanceof PermitApiError) throw error;
      throw new PermitApiError(
        "http_error",
        error instanceof Error ? error.message : "SCITT receipt fetch failed",
      );
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }
}

export function createPermitApiClient(
  config: PermitApiClientConfig,
): PermitApiClient {
  return new PermitApiClient(config);
}
