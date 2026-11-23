/**
 * Internal compatibility bridge allowing untouched v1 modules that import
 * extensionless `@noble/curves/ed25519` to run cleanly on `@noble/curves@^2.4.0`.
 */

import { ed25519 as nobleEd25519 } from "@noble/curves/ed25519.js";

const ED25519_ORDER_L =
  0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

function decodeLittleEndian256(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 31; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[offset + i]!);
  }
  return value;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function strictFromBytes(bytes: Uint8Array, zip215 = true) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error("Expected 32-byte Ed25519 point encoding");
  }
  const point = nobleEd25519.Point.fromBytes(bytes, zip215);
  if (zip215 === false) {
    // Reject non-canonical encodings (including y >= p and negative zero x).
    if (!bytesEqual(point.toBytes(), bytes)) {
      throw new Error("Non-canonical Ed25519 point encoding");
    }
  }
  return point;
}

const PointCompat = {
  CURVE: nobleEd25519.Point.CURVE,
  BASE: nobleEd25519.Point.BASE,
  ZERO: nobleEd25519.Point.ZERO,
  Fp: nobleEd25519.Point.Fp,
  Fn: nobleEd25519.Point.Fn,
  fromAffine: nobleEd25519.Point.fromAffine.bind(nobleEd25519.Point),
  fromHex: nobleEd25519.Point.fromHex.bind(nobleEd25519.Point),
  fromBytes: strictFromBytes,
};

export const ed25519 = {
  keygen: nobleEd25519.keygen,
  getPublicKey: nobleEd25519.getPublicKey,
  sign: nobleEd25519.sign,
  lengths: nobleEd25519.lengths,
  utils: nobleEd25519.utils,
  Point: PointCompat,
  verify(
    sig: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
    options?: { zip215?: boolean },
  ): boolean {
    if (!(sig instanceof Uint8Array) || sig.length !== 64) return false;
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
      return false;
    }
    if (options?.zip215 === false) {
      try {
        const pubPoint = strictFromBytes(publicKey, false);
        if (pubPoint.isSmallOrder()) return false;
        strictFromBytes(sig.subarray(0, 32), false);
      } catch {
        return false;
      }
      const s = decodeLittleEndian256(sig, 32);
      if (s >= ED25519_ORDER_L) return false;
    }
    return nobleEd25519.verify(sig, message, publicKey, options);
  },
};
