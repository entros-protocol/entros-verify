/**
 * MCP 2025-11-25 URL-Mode Elicitation (`SEP-1036`) and OAuth 2.1 HTTP 403
 * `insufficient_scope` step-up helpers.
 *
 * Credentials and WebAuthn assertions are never collected via Form-Mode
 * Elicitation so sensitive proof bytes stay outside LLM context.
 */

import {
  isLowerHex64NonZero,
  isPrintableAscii,
  isStrictHttpsOrLoopbackUri,
} from "../permit/encoding";

export const DEFAULT_STEP_UP_SCOPE = "entros:permit:step_up";

export interface UrlElicitationChallengeInput {
  /** Opaque single-use challenge jti (64 lowercase hex). */
  jti: string;
  /** Out-of-band HTTPS approval URL (keyed by opaque jti, never raw secrets). */
  approvalUrl: string;
  /** Human-readable approval summary displayed by the MCP client. */
  message: string;
}

export interface McpUrlElicitationRequest {
  method: "elicitation/create";
  params: {
    mode: "url";
    elicitationId: string;
    url: string;
    message: string;
  };
}

/**
 * Formats an MCP 2025-11-25 (`SEP-1036`) URL-Mode Elicitation request.
 * Always emits `mode: "url"` and rejects non-HTTPS URLs or malformed `jti`.
 */
export function createUrlElicitationChallenge(
  input: UrlElicitationChallengeInput,
): McpUrlElicitationRequest {
  if (!isLowerHex64NonZero(input.jti)) {
    throw new Error("SEP-1036 elicitationId (jti) must be 64 lowercase hex");
  }
  if (!isStrictHttpsOrLoopbackUri(input.approvalUrl)) {
    throw new Error(
      "SEP-1036 approvalUrl must be a strict HTTPS URI (or http://127.0.0.1)",
    );
  }
  if (
    typeof input.message !== "string" ||
    input.message.trim().length === 0 ||
    input.message.length > 512
  ) {
    throw new Error("SEP-1036 message must be a non-empty string (<= 512 chars)");
  }
  return {
    method: "elicitation/create",
    params: {
      mode: "url",
      elicitationId: input.jti,
      url: input.approvalUrl,
      message: input.message.trim(),
    },
  };
}

export interface InsufficientScopeHeaderOptions {
  /** Existing OAuth scopes already granted to the caller (preserved via scope-union). */
  existingScopes?: string | readonly string[];
  /** Step-up scope to append. Default `"entros:permit:step_up"`. */
  stepUpScope?: string;
  /** Optional OAuth realm value. */
  realm?: string;
  /** Optional RFC 9728 Protected Resource Metadata URI (`resource_metadata`). */
  resourceMetadataUrl?: string;
  /** Optional human-readable error_description. */
  errorDescription?: string;
}

function sanitizeHeaderParam(value: string): string {
  if (!isPrintableAscii(value) || value.includes('"') || value.includes("\\")) {
    throw new Error("WWW-Authenticate parameter contains invalid characters");
  }
  return value;
}

/**
 * Formats an HTTP `403 Forbidden` `WWW-Authenticate` header for OAuth-layer
 * step-up preserving scope-union semantics:
 * `Bearer error="insufficient_scope", scope="<existing_scopes> entros:permit:step_up"`.
 */
export function formatInsufficientScopeHeader(
  options: InsufficientScopeHeaderOptions = {},
): string {
  const stepUpScope = (options.stepUpScope ?? DEFAULT_STEP_UP_SCOPE).trim();
  if (stepUpScope.length === 0 || /\s/.test(stepUpScope)) {
    throw new Error("stepUpScope must be a single non-empty scope token");
  }

  const rawScopes = Array.isArray(options.existingScopes)
    ? options.existingScopes
    : typeof options.existingScopes === "string"
      ? options.existingScopes.split(/\s+/)
      : [];

  const merged: string[] = [];
  const seen = new Set<string>();
  for (const token of [...rawScopes, stepUpScope]) {
    const trimmed = token.trim();
    if (trimmed.length === 0) continue;
    sanitizeHeaderParam(trimmed);
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      merged.push(trimmed);
    }
  }

  const params: string[] = [];
  if (options.realm !== undefined) {
    params.push(`realm="${sanitizeHeaderParam(options.realm)}"`);
  }
  params.push('error="insufficient_scope"');
  params.push(`scope="${merged.join(" ")}"`);
  if (options.resourceMetadataUrl !== undefined) {
    if (!isStrictHttpsOrLoopbackUri(options.resourceMetadataUrl)) {
      throw new Error("resourceMetadataUrl must be strict HTTPS (or loopback)");
    }
    params.push(
      `resource_metadata="${sanitizeHeaderParam(options.resourceMetadataUrl)}"`,
    );
  }
  if (options.errorDescription !== undefined) {
    params.push(
      `error_description="${sanitizeHeaderParam(options.errorDescription)}"`,
    );
  }

  return `Bearer ${params.join(", ")}`;
}
