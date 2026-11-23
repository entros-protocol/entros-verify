/**
 * Pure runtime-portable encoding, constant-time comparison, and strict grammar
 * utilities shared across `@entros/verify` v2 modules.
 */

import { PERMIT_V2_LIMITS } from "./types";

const HEX_64 = /^[0-9a-f]{64}$/;
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LABEL = "(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])";
const FINAL = "(?:[a-z]|[a-z][a-z0-9-]{0,61}[a-z0-9])";
const PORT = "(?::([1-9][0-9]{0,4}))?";
const PATH = "(/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*/?)?)";
const HTTPS_AUD = new RegExp(`^https://((?:${LABEL}\\.)+${FINAL})${PORT}${PATH}$`);
const LOOPBACK_AUD = new RegExp(`^http://(127\\.0\\.0\\.1)${PORT}${PATH}$`);

const B64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_DECODE_TABLE = new Int16Array(128).fill(-1);
for (let i = 0; i < B64URL_ALPHABET.length; i += 1) {
  B64URL_DECODE_TABLE[B64URL_ALPHABET.charCodeAt(i)] = i;
}

export const utf8Encoder = new TextEncoder();
export const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function isPrintableAscii(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

export function isLowerHex64(value: unknown): value is string {
  return typeof value === "string" && HEX_64.test(value);
}

export function isLowerHex64NonZero(value: unknown): value is string {
  return isLowerHex64(value) && !/^0+$/.test(value);
}

export function isVoiceJti(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    (HEX_64.test(value) || UUID_V7.test(value))
  );
}

export function isValidUnixSeconds(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= PERMIT_V2_LIMITS.minTimeSeconds &&
    value <= PERMIT_V2_LIMITS.maxTimeSeconds
  );
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

export function constantTimeEqualString(a: string, b: string): boolean {
  return constantTimeEqual(utf8Encoder.encode(a), utf8Encoder.encode(b));
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      B64URL_ALPHABET[(n >>> 18) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 12) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 6) & 0x3f]! +
      B64URL_ALPHABET[n & 0x3f]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out +=
      B64URL_ALPHABET[(n >>> 18) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 12) & 0x3f]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      B64URL_ALPHABET[(n >>> 18) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 12) & 0x3f]! +
      B64URL_ALPHABET[(n >>> 6) & 0x3f]!;
  }
  return out;
}

/**
 * Decodes unpadded RFC 4648 Base64URL strictly. Rejects `=` padding, whitespace,
 * invalid characters, impossible mod-4 lengths, and non-zero trailing bits.
 */
export function base64UrlDecodeStrict(value: string): Uint8Array | null {
  if (typeof value !== "string") return null;
  const len = value.length;
  const rem = len % 4;
  if (rem === 1) return null;

  const byteLen = Math.floor(len / 4) * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(byteLen);
  let outPos = 0;

  const decodeChar = (idx: number): number => {
    const code = value.charCodeAt(idx);
    if (code >= 128) return -1;
    return B64URL_DECODE_TABLE[code]!;
  };

  let i = 0;
  for (; i + 3 < len; i += 4) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    const c3 = decodeChar(i + 3);
    if ((c0 | c1 | c2 | c3) < 0) return null;
    const n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[outPos++] = (n >>> 16) & 0xff;
    out[outPos++] = (n >>> 8) & 0xff;
    out[outPos++] = n & 0xff;
  }

  if (rem === 2) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    if ((c0 | c1) < 0) return null;
    if ((c1 & 0x0f) !== 0) return null; // non-canonical trailing bits
    out[outPos++] = (c0 << 2) | (c1 >>> 4);
  } else if (rem === 3) {
    const c0 = decodeChar(i);
    const c1 = decodeChar(i + 1);
    const c2 = decodeChar(i + 2);
    if ((c0 | c1 | c2) < 0) return null;
    if ((c2 & 0x03) !== 0) return null; // non-canonical trailing bits
    out[outPos++] = (c0 << 2) | (c1 >>> 4);
    out[outPos++] = ((c1 & 0x0f) << 4) | (c2 >>> 2);
  }

  return out;
}

export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Validates canonical RFC 8707 `aud` URI grammar: strict HTTPS or
 * `http://127.0.0.1`, canonical WHATWG `URL.href` equality, no `..`/`.` segments,
 * no default port, and no `--` in label positions 3 and 4 except `xn--`.
 */
export function isCanonicalAudUri(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > PERMIT_V2_LIMITS.maxUriLength
  ) {
    return false;
  }
  const httpsMatch = HTTPS_AUD.exec(value);
  const match = httpsMatch ?? LOOPBACK_AUD.exec(value);
  if (!match) return false;
  const [, host, port, path] = match;
  if (!host || !path) return false;
  for (const label of host.split(".")) {
    if (
      label.length >= 4 &&
      label[2] === "-" &&
      label[3] === "-" &&
      !label.startsWith("xn--")
    ) {
      return false;
    }
  }
  if (port !== undefined) {
    const num = Number(port);
    if (!Number.isSafeInteger(num) || num < 1 || num > 65535) return false;
    if (num === (httpsMatch ? 443 : 80)) return false;
  }
  if (path.split("/").some((segment) => segment === "." || segment === "..")) {
    return false;
  }
  try {
    return new URL(value).href === value;
  } catch {
    return false;
  }
}

/**
 * Validates strict HTTPS URI (or `http://127.0.0.1` loopback for local tests),
 * length <= 200, with no userinfo or fragment. Used for `iss` and JWKS URLs.
 */
export function isStrictHttpsOrLoopbackUri(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > PERMIT_V2_LIMITS.maxUriLength ||
    !isPrintableAscii(value) ||
    value !== value.trim()
  ) {
    return false;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") {
    return false;
  }
  if (parsed.protocol === "https:") return parsed.hostname.length > 0;
  if (parsed.protocol === "http:" && parsed.hostname === "127.0.0.1") {
    return true;
  }
  return false;
}

export function randomHex32Bytes(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
    throw new Error("Web Crypto getRandomValues is unavailable");
  }
  const bytes = new Uint8Array(32);
  cryptoApi.getRandomValues(bytes);
  return bytesToHex(bytes);
}
