/**
 * Zero-CBOR hardware Passkey (WebAuthn UV) assertion verifier.
 *
 * Parses raw `authenticatorData` (>= 37 bytes) and `clientDataJSON`, verifies
 * ASN.1 DER ECDSA P-256 signatures with `{ format: "der", lowS: false, prehash: true }`
 * so valid high-S hardware signatures (Apple Secure Enclave, YubiKey, Windows Hello,
 * Android Keystore) are accepted, and computes the domain-separated
 * `webauthn_assertion_digest`.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { canonicalizeJcs, parseStrictJson } from "./canonical";
import {
  base64UrlDecodeStrict,
  base64UrlEncode,
  bytesToHex,
  concatBytes,
  constantTimeEqual,
  constantTimeEqualString,
  decodeUtf8Strict,
  hexToBytes,
  isLowerHex64NonZero,
  isPlainRecord,
  utf8Encoder,
} from "./encoding";
import {
  WEBAUTHN_ASSERTION_V2_DOMAIN,
  WEBAUTHN_CHALLENGE_V2_DOMAIN,
  type EcP256Jwk,
  type WebAuthnVerifyOptions,
  type WebAuthnVerifyResult,
} from "./types";

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

export interface DerivedWebAuthnChallenge {
  challengeBytes: Uint8Array;
  challengeHex: string;
  challengeBase64Url: string;
}

export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  userPresent: boolean;
  userVerified: boolean;
  signCount: number;
}

function toBytesStrict(value: string | Uint8Array): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string") return base64UrlDecodeStrict(value);
  return null;
}

function decodeP256PublicKey(
  input: Uint8Array | string | EcP256Jwk,
): Uint8Array | null {
  if (input instanceof Uint8Array) {
    return input.length === 65 && input[0] === 0x04 ? input : null;
  }
  if (typeof input === "string") {
    if (input.length === 130 && /^[0-9a-fA-F]{130}$/.test(input)) {
      const bytes = hexToBytes(input);
      return bytes && bytes.length === 65 && bytes[0] === 0x04 ? bytes : null;
    }
    const decoded = base64UrlDecodeStrict(input);
    return decoded && decoded.length === 65 && decoded[0] === 0x04
      ? decoded
      : null;
  }
  if (
    isPlainRecord(input) &&
    input.kty === "EC" &&
    input.crv === "P-256" &&
    typeof input.x === "string" &&
    typeof input.y === "string"
  ) {
    const x = base64UrlDecodeStrict(input.x);
    const y = base64UrlDecodeStrict(input.y);
    if (!x || !y || x.length !== 32 || y.length !== 32) return null;
    return concatBytes(Uint8Array.of(0x04), x, y);
  }
  return null;
}

/**
 * Derives the exact 32-byte WebAuthn challenge bound to a permit `jti` and
 * RFC 8785 `request_digest`:
 * `SHA-256("Entros-WebAuthn-Challenge-v2\n" || jti || "\n" || request_digest)`.
 */
export function deriveWebAuthnChallengeV2(
  jti: string,
  requestDigest: string,
): DerivedWebAuthnChallenge {
  if (!isLowerHex64NonZero(jti)) {
    throw new Error("Permit jti must be a non-zero 64-char lowercase hex string");
  }
  if (!isLowerHex64NonZero(requestDigest)) {
    throw new Error(
      "Permit request_digest must be a non-zero 64-char lowercase hex string",
    );
  }
  const challengeBytes = sha256(
    utf8Encoder.encode(
      `${WEBAUTHN_CHALLENGE_V2_DOMAIN}\n${jti}\n${requestDigest}`,
    ),
  );
  return {
    challengeBytes,
    challengeHex: bytesToHex(challengeBytes),
    challengeBase64Url: base64UrlEncode(challengeBytes),
  };
}

/**
 * Parses raw `authenticatorData` (>= 37 bytes) without any CBOR dependency.
 */
export function parseAuthenticatorData(
  bytes: Uint8Array,
): ParsedAuthenticatorData | null {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) return null;
  const rpIdHash = bytes.subarray(0, 32);
  const flags = bytes[32]!;
  const signCount =
    ((bytes[33]! << 24) |
      (bytes[34]! << 16) |
      (bytes[35]! << 8) |
      bytes[36]!) >>>
    0;
  return {
    rpIdHash,
    flags,
    userPresent: (flags & FLAG_UP) === FLAG_UP,
    userVerified: (flags & FLAG_UV) === FLAG_UV,
    signCount,
  };
}

/**
 * Computes the canonical `webauthn_assertion_digest` over the JCS digest tuple
 * prefixed with `"Entros-WebAuthn-Assertion-v2\n"`.
 */
export function computeWebAuthnAssertionDigestV2(input: {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  credentialId: Uint8Array;
  signature: Uint8Array;
}): string {
  if (input.authenticatorData.length < 37) {
    throw new Error("authenticatorData must be at least 37 bytes");
  }
  const rpIdHash = input.authenticatorData.subarray(0, 32);
  const clientDataHash = sha256(input.clientDataJSON);
  const tuple = canonicalizeJcs({
    auth_data_sha256: bytesToHex(sha256(input.authenticatorData)),
    client_data_sha256: bytesToHex(clientDataHash),
    credential_id: base64UrlEncode(input.credentialId),
    rp_id_hash: bytesToHex(rpIdHash),
    signature_sha256: bytesToHex(sha256(input.signature)),
  });
  return bytesToHex(
    sha256(utf8Encoder.encode(`${WEBAUTHN_ASSERTION_V2_DOMAIN}\n${tuple}`)),
  );
}

/**
 * Verifies a WebAuthn `navigator.credentials.get()` P-256 assertion without CBOR.
 *
 * Accepts both low-S (`s <= n/2`) and high-S (`s > n/2`) ASN.1 DER signatures
 * emitted by hardware FIDO2 authenticators via `{ format: "der", lowS: false, prehash: true }`.
 */
export function verifyWebAuthnAssertionV2(
  options: WebAuthnVerifyOptions,
): WebAuthnVerifyResult {
  const failInvalid = (detail: string): WebAuthnVerifyResult => ({
    ok: false,
    reason: "webauthn_assertion_invalid",
    detail,
  });

  if (!options || !isPlainRecord(options.assertion)) {
    return failInvalid("Missing WebAuthn assertion payload");
  }

  const publicKeyBytes = decodeP256PublicKey(options.publicKey);
  if (!publicKeyBytes) {
    return failInvalid("Invalid uncompressed P-256 public key");
  }

  const authData = toBytesStrict(options.assertion.authenticator_data);
  const clientDataBytes = toBytesStrict(options.assertion.client_data_json);
  const signatureBytes = toBytesStrict(options.assertion.signature);
  const credentialIdBytes = toBytesStrict(options.assertion.credential_id);

  if (
    !authData ||
    !clientDataBytes ||
    !signatureBytes ||
    !credentialIdBytes ||
    credentialIdBytes.length === 0
  ) {
    return failInvalid("Malformed Base64URL WebAuthn assertion field");
  }

  const parsedAuth = parseAuthenticatorData(authData);
  if (!parsedAuth) {
    return failInvalid("authenticatorData must be at least 37 bytes");
  }

  // Verify rpIdHash with constant-time equality.
  const expectedRpIdHash = sha256(utf8Encoder.encode(options.expectedRpId));
  if (!constantTimeEqual(parsedAuth.rpIdHash, expectedRpIdHash)) {
    return failInvalid("authenticatorData rpIdHash mismatch");
  }

  // Parse and validate strict UTF-8 clientDataJSON.
  const clientDataText = decodeUtf8Strict(clientDataBytes);
  if (clientDataText === null) {
    return failInvalid("clientDataJSON is not valid UTF-8");
  }
  let clientData: unknown;
  try {
    clientData = parseStrictJson(clientDataText);
  } catch {
    return failInvalid("clientDataJSON is not valid JSON");
  }
  if (!isPlainRecord(clientData)) {
    return failInvalid("clientDataJSON must be a JSON object");
  }
  if (clientData.type !== "webauthn.get") {
    return failInvalid("clientDataJSON.type must equal 'webauthn.get'");
  }
  if (
    typeof clientData.origin !== "string" ||
    !constantTimeEqualString(clientData.origin, options.expectedOrigin)
  ) {
    return failInvalid("clientDataJSON.origin mismatch");
  }

  const expectedChallengeB64u =
    options.expectedChallenge instanceof Uint8Array
      ? base64UrlEncode(options.expectedChallenge)
      : options.expectedChallenge;
  if (
    typeof clientData.challenge !== "string" ||
    !constantTimeEqualString(clientData.challenge, expectedChallengeB64u)
  ) {
    return failInvalid("clientDataJSON.challenge mismatch");
  }

  if (clientData.crossOrigin === true && options.allowCrossOrigin !== true) {
    return failInvalid("Cross-origin WebAuthn assertion is not allowed");
  }

  // Reject signCount rollback whenever storedSignCount > 0 (including rollback to 0).
  if (
    options.storedSignCount !== undefined &&
    options.storedSignCount > 0 &&
    parsedAuth.signCount <= options.storedSignCount
  ) {
    return failInvalid("WebAuthn signCount rollback detected");
  }

  // Verify ASN.1 DER P-256 signature with explicit lowS: false.
  const clientDataHash = sha256(clientDataBytes);
  const signedData = concatBytes(authData, clientDataHash);

  let sigOk = false;
  try {
    sigOk = p256.verify(signatureBytes, signedData, publicKeyBytes, {
      format: "der",
      lowS: false,
      prehash: true,
    });
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return failInvalid("WebAuthn P-256 DER signature verification failed");
  }

  // Enforce UP=1 and UV=1 bits (fails closed with webauthn_uv_required).
  if (!parsedAuth.userPresent || !parsedAuth.userVerified) {
    return {
      ok: false,
      reason: "webauthn_uv_required",
      detail: "WebAuthn authenticatorData requires both UP=1 and UV=1 flags",
    };
  }

  const assertionDigest = computeWebAuthnAssertionDigestV2({
    authenticatorData: authData,
    clientDataJSON: clientDataBytes,
    credentialId: credentialIdBytes,
    signature: signatureBytes,
  });

  return {
    ok: true,
    assertionDigest,
    signCount: parsedAuth.signCount,
    userPresent: true,
    userVerified: true,
    rpIdHashHex: bytesToHex(parsedAuth.rpIdHash),
  };
}
