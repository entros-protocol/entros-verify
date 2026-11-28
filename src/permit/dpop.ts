/**
 * RFC 9449 DPoP (`dpop+jwt`) sender-constraint proof verifier.
 *
 * Binds permit presentation to `cnf.jkt` (RFC 7638 JWK thumbprint), HTTP method
 * (`htm`), canonical target URI (`htu`), permit access-token hash (`ath`), and
 * proof freshness (`iat`).
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalizeJcs } from "./canonical";
import {
  base64UrlDecodeStrict,
  base64UrlEncode,
  concatBytes,
  constantTimeEqualString,
  isPlainRecord,
  isValidUnixSeconds,
  utf8Encoder,
} from "./encoding";
import { parseCompactJws, verifyStrictEd25519Signature } from "./jws";
import {
  PERMIT_V2_LIMITS,
  type DpopJtiStore,
  type DpopVerifyOptions,
  type DpopVerifyResult,
} from "./types";

const DEFAULT_DPOP_MAX_AGE_SECONDS = 60;
const LAZY_PRUNE_INTERVAL_SECONDS = 10;
const FORBIDDEN_DPOP_HEADERS = ["crit", "jku", "x5u", "x5c"] as const;
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export type JwkThumbprintInput = Readonly<Record<string, unknown>>;

/**
 * Strips query and fragment from an HTTP URI per RFC 9449 §4.2, rejecting
 * non-HTTP schemes and embedded userinfo credentials.
 */
export function normalizeDpopHtu(uri: string): string | null {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    if (parsed.username !== "" || parsed.password !== "") {
      return null;
    }
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return null;
  }
}

function extractThumbprintMembers(
  jwk: JwkThumbprintInput,
): Record<string, string> {
  if (!isPlainRecord(jwk)) {
    throw new Error("JWK must be a plain object");
  }
  const kty = jwk.kty;
  const requireStr = (field: string): string => {
    const val = jwk[field];
    if (typeof val !== "string" || val.length === 0) {
      throw new Error(`JWK missing required string member '${field}'`);
    }
    return val;
  };
  if (kty === "OKP") {
    return { crv: requireStr("crv"), kty: "OKP", x: requireStr("x") };
  }
  if (kty === "EC") {
    return {
      crv: requireStr("crv"),
      kty: "EC",
      x: requireStr("x"),
      y: requireStr("y"),
    };
  }
  if (kty === "RSA") {
    return { e: requireStr("e"), kty: "RSA", n: requireStr("n") };
  }
  if (kty === "oct") {
    return { k: requireStr("k"), kty: "oct" };
  }
  throw new Error(`Unsupported JWK kty '${String(kty)}'`);
}

/**
 * Computes an RFC 7638 SHA-256 JWK thumbprint using canonical JCS serialization.
 */
export async function computeJwkThumbprint(
  jwk: JwkThumbprintInput,
): Promise<string> {
  const members = extractThumbprintMembers(jwk);
  return base64UrlEncode(sha256(utf8Encoder.encode(canonicalizeJcs(members))));
}

/**
 * Bounded single-process DPoP `jti` replay cache implementing `DpopJtiStore`.
 */
export class InMemoryDpopJtiStore implements DpopJtiStore {
  readonly #entries = new Map<string, number>();
  readonly #maxEntries: number;
  #lastPruneAt: number | null = null;

  constructor(maxEntries = 10_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error("maxEntries must be a positive integer");
    }
    this.#maxEntries = maxEntries;
  }

  #prune(nowSeconds: number): void {
    for (const [key, exp] of this.#entries) {
      if (nowSeconds >= exp) {
        this.#entries.delete(key);
      }
    }
    this.#lastPruneAt = nowSeconds;
  }

  consume(jti: string, expiresAt: number, nowSeconds: number): boolean {
    if (typeof jti !== "string" || jti.trim().length === 0) return false;
    if (!Number.isFinite(expiresAt) || !Number.isFinite(nowSeconds)) {
      return false;
    }
    const existing = this.#entries.get(jti);
    if (existing !== undefined) {
      if (nowSeconds < existing) {
        return false;
      }
      this.#entries.delete(jti);
    }
    const shouldPrune =
      this.#entries.size >= this.#maxEntries ||
      (this.#entries.size > 0 &&
        this.#lastPruneAt !== null &&
        nowSeconds - this.#lastPruneAt >= LAZY_PRUNE_INTERVAL_SECONDS);
    if (shouldPrune) {
      this.#prune(nowSeconds);
    } else if (this.#lastPruneAt === null) {
      this.#lastPruneAt = nowSeconds;
    }
    // Fail closed rather than evicting active unexpired proof jtis.
    if (this.#entries.size >= this.#maxEntries) {
      return false;
    }
    this.#entries.set(jti, expiresAt);
    return true;
  }
}

function hasPrivateJwkField(jwk: Record<string, unknown>): boolean {
  return PRIVATE_JWK_FIELDS.some((field) =>
    Object.prototype.hasOwnProperty.call(jwk, field),
  );
}

function verifyDpopSignature(
  alg: string,
  jwk: Record<string, unknown>,
  signingInput: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (alg === "ES256") {
    if (
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      typeof jwk.x !== "string" ||
      typeof jwk.y !== "string" ||
      hasPrivateJwkField(jwk)
    ) {
      return false;
    }
    const x = base64UrlDecodeStrict(jwk.x);
    const y = base64UrlDecodeStrict(jwk.y);
    if (!x || !y || x.length !== 32 || y.length !== 32) return false;
    if (signature.length !== 64) return false;
    const pubKey = concatBytes(Uint8Array.of(0x04), x, y);
    try {
      return p256.verify(signature, signingInput, pubKey, {
        format: "compact",
        lowS: false,
        prehash: true,
      });
    } catch {
      return false;
    }
  }
  if (alg === "EdDSA") {
    if (
      jwk.kty !== "OKP" ||
      jwk.crv !== "Ed25519" ||
      typeof jwk.x !== "string" ||
      hasPrivateJwkField(jwk)
    ) {
      return false;
    }
    const pubKey = base64UrlDecodeStrict(jwk.x);
    if (!pubKey || pubKey.length !== 32) return false;
    return verifyStrictEd25519Signature(signature, signingInput, pubKey);
  }
  return false;
}

/**
 * Verifies an RFC 9449 `dpop+jwt` proof bound to a permit JWS and `cnf.jkt`.
 */
export async function verifyDpopProofV2(
  options: DpopVerifyOptions,
): Promise<DpopVerifyResult> {
  const fail = (detail: string): DpopVerifyResult => ({
    ok: false,
    reason: "dpop_proof_invalid",
    detail,
  });

  const parsed = parseCompactJws(options.proof);
  if (!parsed) {
    return fail("Malformed compact DPoP JWT");
  }

  const { header, payload } = parsed;
  for (const forbidden of FORBIDDEN_DPOP_HEADERS) {
    if (Object.prototype.hasOwnProperty.call(header, forbidden)) {
      return fail(`Forbidden DPoP header '${forbidden}' is not permitted`);
    }
  }
  if (header.typ !== "dpop+jwt") {
    return fail("DPoP header typ must equal 'dpop+jwt'");
  }
  if (header.alg !== "ES256" && header.alg !== "EdDSA") {
    return fail(`Unsupported DPoP alg '${String(header.alg)}'`);
  }
  if (!isPlainRecord(header.jwk) || hasPrivateJwkField(header.jwk)) {
    return fail("DPoP header must embed a public JWK without private key fields");
  }

  let thumbprint: string;
  try {
    thumbprint = await computeJwkThumbprint(header.jwk);
  } catch {
    return fail("Unable to compute RFC 7638 thumbprint for embedded DPoP JWK");
  }
  if (!constantTimeEqualString(thumbprint, options.expectedJkt)) {
    return fail("DPoP JWK thumbprint does not match cnf.jkt");
  }

  if (
    !verifyDpopSignature(
      header.alg,
      header.jwk,
      parsed.signingInputBytes,
      parsed.signatureBytes,
    )
  ) {
    return fail("DPoP signature verification failed");
  }

  if (typeof payload.jti !== "string" || payload.jti.trim().length === 0) {
    return fail("DPoP payload missing non-empty jti");
  }
  const expectedHtm = options.expectedHtm.toUpperCase();
  if (
    typeof payload.htm !== "string" ||
    payload.htm.toUpperCase() !== expectedHtm
  ) {
    return fail("DPoP htm mismatch");
  }

  if (
    typeof payload.htu !== "string" ||
    payload.htu.includes("?") ||
    payload.htu.includes("#")
  ) {
    return fail("DPoP payload htu must not contain query or fragment parts");
  }
  const expectedHtu = normalizeDpopHtu(options.expectedHtu);
  const actualHtu = normalizeDpopHtu(payload.htu);
  if (!expectedHtu || !actualHtu || actualHtu !== expectedHtu) {
    return fail("DPoP htu mismatch");
  }

  if (!isValidUnixSeconds(options.nowSeconds)) {
    return fail("DPoP verifier clock timestamp is invalid");
  }
  if (!isValidUnixSeconds(payload.iat)) {
    return fail("DPoP iat is invalid");
  }
  const maxAge = options.maxAgeSeconds ?? DEFAULT_DPOP_MAX_AGE_SECONDS;
  if (!Number.isFinite(maxAge) || maxAge < 1) {
    return fail("DPoP maxAgeSeconds must be a finite positive number");
  }
  if (payload.iat > options.nowSeconds + PERMIT_V2_LIMITS.clockSkewSeconds) {
    return fail("DPoP iat exceeds allowed forward clock skew");
  }
  if (options.nowSeconds - payload.iat > maxAge) {
    return fail("DPoP proof is stale");
  }

  const expectedAth = base64UrlEncode(
    sha256(utf8Encoder.encode(options.permitJws)),
  );
  if (
    typeof payload.ath !== "string" ||
    !constantTimeEqualString(payload.ath, expectedAth)
  ) {
    return fail("DPoP ath does not match permit JWS SHA-256 digest");
  }

  if (options.jtiStore !== undefined) {
    const fresh = await options.jtiStore.consume(
      payload.jti,
      payload.iat + maxAge + PERMIT_V2_LIMITS.clockSkewSeconds,
      options.nowSeconds,
    );
    if (!fresh) {
      return fail("DPoP proof jti has already been used");
    }
  }

  return {
    ok: true,
    jkt: thumbprint,
    jti: payload.jti,
    iat: payload.iat,
    htm: expectedHtm,
    htu: expectedHtu,
    ath: expectedAth,
  };
}
