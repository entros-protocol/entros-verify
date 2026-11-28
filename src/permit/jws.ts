/**
 * Strict RFC 7515 EdDSA compact JWS verifier enforcing RFC 8032 / FIPS 186-5
 * (`zip215: false`) verification, header allowlisting, and key revocation checks.
 */

import { ed25519 } from "@noble/curves/ed25519.js";

import { parseStrictJson } from "./canonical";
import {
  base64UrlDecodeStrict,
  constantTimeEqual,
  decodeUtf8Strict,
  isPlainRecord,
  utf8Encoder,
} from "./encoding";
import { normalizeJwksSource } from "./jwks";
import type { JwksSource } from "./types";

const ED25519_ORDER_L =
  0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

const FORBIDDEN_JWS_HEADERS = ["jwk", "jku", "x5u", "x5c", "crit"] as const;

export interface ParsedCompactJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInputBytes: Uint8Array;
  signatureBytes: Uint8Array;
}

export type VerifyEdDsaJwsResult =
  | {
      ok: true;
      header: Record<string, unknown>;
      payload: Record<string, unknown>;
      kid: string;
    }
  | {
      ok: false;
      reason:
        | "invalid_jws"
        | "unsupported_alg"
        | "invalid_typ"
        | "unknown_kid"
        | "revoked_kid"
        | "invalid_signature"
        | "state_unavailable";
      detail: string;
    };

function decodeLittleEndian256(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 31; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[offset + i]!);
  }
  return value;
}

/**
 * Verifies an Ed25519 signature strictly under RFC 8032 / FIPS 186-5 (`zip215: false`).
 * Rejects small-order public keys, non-canonical point encodings, and S >= L.
 */
export function verifyStrictEd25519Signature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (
    !(signature instanceof Uint8Array) ||
    signature.length !== 64 ||
    !(publicKey instanceof Uint8Array) ||
    publicKey.length !== 32
  ) {
    return false;
  }
  try {
    const pubPoint = ed25519.Point.fromBytes(publicKey, false);
    if (pubPoint.isSmallOrder()) return false;
    if (!constantTimeEqual(pubPoint.toBytes(), publicKey)) return false;

    const rBytes = signature.subarray(0, 32);
    const rPoint = ed25519.Point.fromBytes(rBytes, false);
    if (rPoint.isSmallOrder()) return false;
    if (!constantTimeEqual(rPoint.toBytes(), rBytes)) return false;
  } catch {
    return false;
  }
  const scalarS = decodeLittleEndian256(signature, 32);
  if (scalarS >= ED25519_ORDER_L) return false;

  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Parses a compact 3-part JWS strictly without accepting Base64URL padding,
 * invalid UTF-8, duplicate JSON keys, or non-object headers/payloads.
 */
export function parseCompactJws(jws: unknown): ParsedCompactJws | null {
  if (typeof jws !== "string" || jws.length === 0) return null;
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  const [rawHeader, rawPayload, rawSignature] = parts;
  if (!rawHeader || !rawPayload || !rawSignature) return null;

  const headerBytes = base64UrlDecodeStrict(rawHeader);
  const payloadBytes = base64UrlDecodeStrict(rawPayload);
  const signatureBytes = base64UrlDecodeStrict(rawSignature);
  if (!headerBytes || !payloadBytes || !signatureBytes) return null;

  const headerText = decodeUtf8Strict(headerBytes);
  const payloadText = decodeUtf8Strict(payloadBytes);
  if (headerText === null || payloadText === null) return null;

  let header: unknown;
  let payload: unknown;
  try {
    header = parseStrictJson(headerText);
    payload = parseStrictJson(payloadText);
  } catch {
    return null;
  }
  if (!isPlainRecord(header) || !isPlainRecord(payload)) return null;

  return {
    header,
    payload,
    signingInputBytes: utf8Encoder.encode(`${rawHeader}.${rawPayload}`),
    signatureBytes,
  };
}

/**
 * Verifies a compact EdDSA JWS in strict precheck order (Steps 1 through 6):
 * structure, alg & forbidden headers, typ, kid resolution, revocation, and
 * strict RFC 8032 Ed25519 signature verification.
 */
export async function verifyEdDsaJws(input: {
  jws: unknown;
  expectedTyp: string;
  jwks: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
}): Promise<VerifyEdDsaJwsResult> {
  // Step 1: Compact JWS structure and JSON parsing.
  const parsed = parseCompactJws(input.jws);
  if (!parsed) {
    return {
      ok: false,
      reason: "invalid_jws",
      detail: "Malformed compact JWS or invalid unpadded Base64URL/JSON",
    };
  }

  // Step 2: Strict alg === "EdDSA" and forbidden header rejection.
  if (parsed.header.alg !== "EdDSA") {
    return {
      ok: false,
      reason: "unsupported_alg",
      detail: `Expected alg 'EdDSA', received '${String(parsed.header.alg)}'`,
    };
  }
  for (const forbidden of FORBIDDEN_JWS_HEADERS) {
    if (Object.prototype.hasOwnProperty.call(parsed.header, forbidden)) {
      return {
        ok: false,
        reason: "unsupported_alg",
        detail: `Forbidden JWS header '${forbidden}' is not permitted`,
      };
    }
  }

  // Step 3: Exact typ match.
  if (parsed.header.typ !== input.expectedTyp) {
    return {
      ok: false,
      reason: "invalid_typ",
      detail: `Expected typ '${input.expectedTyp}', received '${String(parsed.header.typ)}'`,
    };
  }

  // Step 4: Resolve kid from JWKS.
  const kid = parsed.header.kid;
  if (typeof kid !== "string" || kid.trim().length === 0) {
    return {
      ok: false,
      reason: "unknown_kid",
      detail: "JWS protected header is missing a valid kid",
    };
  }

  let lookup;
  try {
    const resolver = normalizeJwksSource(input.jwks, input.revokedKids);
    lookup = await resolver.resolveEd25519Key(kid);
  } catch (error) {
    return {
      ok: false,
      reason: "state_unavailable",
      detail:
        error instanceof Error ? error.message : "JWKS resolver unavailable",
    };
  }

  if (lookup.status === "unavailable") {
    return {
      ok: false,
      reason: "state_unavailable",
      detail: lookup.detail,
    };
  }
  if (lookup.status === "unknown") {
    return {
      ok: false,
      reason: "unknown_kid",
      detail: `Unknown JWS kid '${kid}'`,
    };
  }

  // Step 5: Revoked kid check.
  if (lookup.status === "revoked") {
    return {
      ok: false,
      reason: "revoked_kid",
      detail: `Signing key '${kid}' is revoked`,
    };
  }

  // Step 6: Strict RFC 8032 Ed25519 verification (zip215: false).
  if (
    !verifyStrictEd25519Signature(
      parsed.signatureBytes,
      parsed.signingInputBytes,
      lookup.publicKey,
    )
  ) {
    return {
      ok: false,
      reason: "invalid_signature",
      detail: "Strict Ed25519 signature verification failed",
    };
  }

  return {
    ok: true,
    header: parsed.header,
    payload: parsed.payload,
    kid,
  };
}
