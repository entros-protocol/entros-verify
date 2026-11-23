/**
 * RFC 9449 DPoP (`dpop+jwt`) sender-constraint proof verifier.
 *
 * Binds permit presentation to `cnf.jkt` (RFC 7638 JWK thumbprint), HTTP method
 * (`htm`), canonical target URI (`htu`), permit access-token hash (`ath`), and
 * proof freshness (`iat`).
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { calculateJwkThumbprint, type JWK } from "jose";

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
  type DpopVerifyOptions,
  type DpopVerifyResult,
} from "./types";

const DEFAULT_DPOP_MAX_AGE_SECONDS = 60;

/**
 * Strips query and fragment from an HTTP URI per RFC 9449 §4.2.
 */
export function normalizeDpopHtu(uri: string): string | null {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return null;
    }
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return null;
  }
}

/**
 * Computes an RFC 7638 SHA-256 JWK thumbprint using `jose`.
 */
export async function computeJwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
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
      "d" in jwk
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
      "d" in jwk
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
  if (header.typ !== "dpop+jwt") {
    return fail("DPoP header typ must equal 'dpop+jwt'");
  }
  if (header.alg !== "ES256" && header.alg !== "EdDSA") {
    return fail(`Unsupported DPoP alg '${String(header.alg)}'`);
  }
  if (!isPlainRecord(header.jwk) || "d" in header.jwk) {
    return fail("DPoP header must embed a public JWK without private key fields");
  }

  let thumbprint: string;
  try {
    thumbprint = await computeJwkThumbprint(header.jwk as JWK);
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

  const expectedHtu = normalizeDpopHtu(options.expectedHtu);
  const actualHtu =
    typeof payload.htu === "string" ? normalizeDpopHtu(payload.htu) : null;
  if (!expectedHtu || !actualHtu || actualHtu !== expectedHtu) {
    return fail("DPoP htu mismatch");
  }

  if (!isValidUnixSeconds(payload.iat)) {
    return fail("DPoP iat is invalid");
  }
  const maxAge = options.maxAgeSeconds ?? DEFAULT_DPOP_MAX_AGE_SECONDS;
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
