/**
 * Zero-dependency definite-length CBOR subset codec and IETF SCITT (RFC 9943) /
 * COSE Receipts (RFC 9942) Tag 18 `COSE_Sign1` verifier.
 *
 * Enforces definite-length CBOR (RFC 8949), protected headers `{ 1: -8, 4: kid, 395: 1 }`,
 * unprotected header `{ 396: { -1: [tree_size, leaf_index, audit_path] } }`,
 * RFC 9162 §2.1.3.2 SHA-256 Merkle inclusion folding over `0x00 || payload_bstr`,
 * and strict Ed25519 (`zip215: false`) signature verification over COSE `Sig_structure`.
 */

import { sha256 } from "@noble/hashes/sha2.js";

import { parseStrictJson } from "./canonical";
import {
  base64UrlDecodeStrict,
  bytesToHex,
  concatBytes,
  decodeUtf8Strict,
  isCanonicalAudUri,
  isLowerHex64,
  isLowerHex64NonZero,
  isPlainRecord,
  isValidUnixSeconds,
  utf8Encoder,
} from "./encoding";
import { normalizeJwksSource } from "./jwks";
import { verifyStrictEd25519Signature } from "./jws";
import {
  ALL_ASSURANCE_TIERS_V2,
  type AssuranceTierV2,
  type JwksSource,
  type ScittDecisionStatement,
  type ScittVerificationResult,
} from "./types";

const MAX_CBOR_DEPTH = 16;
const ASSURANCE_SET: ReadonlySet<string> = new Set(ALL_ASSURANCE_TIERS_V2);

export type CborValue =
  | number
  | Uint8Array
  | string
  | CborValue[]
  | CborMap
  | CborTagged;

export interface CborMap {
  readonly kind: "map";
  readonly entries: readonly [CborValue, CborValue][];
}

export interface CborTagged {
  readonly kind: "tag";
  readonly tag: number;
  readonly value: CborValue;
}

class CborDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborDecodeError";
  }
}

/**
 * Decodes a single definite-length CBOR item (RFC 8949 subset covering
 * integers, byte strings, text strings, arrays, maps, and tags).
 * Rejects indefinite-length items (additional info 31) and trailing bytes.
 */
export function decodeDefiniteCbor(bytes: Uint8Array): CborValue {
  let offset = 0;

  function readUint(addl: number): number {
    if (addl < 24) return addl;
    if (addl === 24) {
      if (offset + 1 > bytes.length) throw new CborDecodeError("Unexpected EOF");
      return bytes[offset++]!;
    }
    if (addl === 25) {
      if (offset + 2 > bytes.length) throw new CborDecodeError("Unexpected EOF");
      const val = (bytes[offset]! << 8) | bytes[offset + 1]!;
      offset += 2;
      return val;
    }
    if (addl === 26) {
      if (offset + 4 > bytes.length) throw new CborDecodeError("Unexpected EOF");
      const val =
        ((bytes[offset]! << 24) |
          (bytes[offset + 1]! << 16) |
          (bytes[offset + 2]! << 8) |
          bytes[offset + 3]!) >>>
        0;
      offset += 4;
      return val;
    }
    if (addl === 27) {
      if (offset + 8 > bytes.length) throw new CborDecodeError("Unexpected EOF");
      let big = 0n;
      for (let i = 0; i < 8; i += 1) {
        big = (big << 8n) | BigInt(bytes[offset + i]!);
      }
      offset += 8;
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new CborDecodeError("CBOR integer exceeds MAX_SAFE_INTEGER");
      }
      return Number(big);
    }
    if (addl === 31) {
      throw new CborDecodeError("Indefinite-length CBOR is forbidden");
    }
    throw new CborDecodeError(`Invalid CBOR additional info ${addl}`);
  }

  function decodeItem(depth: number): CborValue {
    if (depth > MAX_CBOR_DEPTH) {
      throw new CborDecodeError("CBOR nesting depth exceeded");
    }
    if (offset >= bytes.length) {
      throw new CborDecodeError("Unexpected EOF");
    }
    const initial = bytes[offset++]!;
    const major = initial >>> 5;
    const addl = initial & 0x1f;

    switch (major) {
      case 0:
        return readUint(addl);
      case 1: {
        const val = readUint(addl);
        return -1 - val;
      }
      case 2: {
        const len = readUint(addl);
        if (offset + len > bytes.length) {
          throw new CborDecodeError("Byte string length exceeds buffer");
        }
        const slice = bytes.subarray(offset, offset + len);
        offset += len;
        return slice;
      }
      case 3: {
        const len = readUint(addl);
        if (offset + len > bytes.length) {
          throw new CborDecodeError("Text string length exceeds buffer");
        }
        const text = decodeUtf8Strict(bytes.subarray(offset, offset + len));
        if (text === null) {
          throw new CborDecodeError("Invalid UTF-8 in CBOR text string");
        }
        offset += len;
        return text;
      }
      case 4: {
        const count = readUint(addl);
        if (count > 1024) {
          throw new CborDecodeError("CBOR array exceeds safe element cap");
        }
        const items: CborValue[] = [];
        for (let i = 0; i < count; i += 1) {
          items.push(decodeItem(depth + 1));
        }
        return items;
      }
      case 5: {
        const count = readUint(addl);
        if (count > 1024) {
          throw new CborDecodeError("CBOR map exceeds safe entry cap");
        }
        const entries: [CborValue, CborValue][] = [];
        for (let i = 0; i < count; i += 1) {
          const k = decodeItem(depth + 1);
          const v = decodeItem(depth + 1);
          entries.push([k, v]);
        }
        return { kind: "map", entries };
      }
      case 6: {
        const tag = readUint(addl);
        const value = decodeItem(depth + 1);
        return { kind: "tag", tag, value };
      }
      default:
        throw new CborDecodeError(`Unsupported CBOR major type ${major}`);
    }
  }

  const value = decodeItem(0);
  if (offset !== bytes.length) {
    throw new CborDecodeError("Trailing bytes after CBOR item");
  }
  return value;
}

function encodeCborHead(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  if (n < 0x100) return Uint8Array.of(m | 24, n);
  if (n < 0x10000) return Uint8Array.of(m | 25, (n >>> 8) & 0xff, n & 0xff);
  if (n < 0x100000000) {
    return Uint8Array.of(
      m | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    );
  }
  const big = BigInt(n);
  const out = new Uint8Array(9);
  out[0] = m | 27;
  for (let i = 0; i < 8; i += 1) {
    out[8 - i] = Number((big >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

function encodeCborBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeCborHead(2, bytes.length), bytes);
}

function encodeCborText(text: string): Uint8Array {
  const bytes = utf8Encoder.encode(text);
  return concatBytes(encodeCborHead(3, bytes.length), bytes);
}

function encodeCborSigStructure(
  protectedBstr: Uint8Array,
  merkleRoot: Uint8Array,
): Uint8Array {
  // RFC 9052 §4.4 Sig_structure: ["Signature1", body_protected, external_aad, payload]
  return concatBytes(
    encodeCborHead(4, 4),
    encodeCborText("Signature1"),
    encodeCborBytes(protectedBstr),
    encodeCborBytes(new Uint8Array(0)),
    encodeCborBytes(merkleRoot),
  );
}

function isCborMap(value: CborValue | undefined): value is CborMap {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array) &&
    "kind" in value &&
    value.kind === "map"
  );
}

function isCborTagged(value: CborValue | undefined): value is CborTagged {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Uint8Array) &&
    "kind" in value &&
    value.kind === "tag"
  );
}

function assertUniqueMapKeys(map: CborMap): void {
  const seen = new Set<string>();
  for (const [k] of map.entries) {
    let keyRepr: string;
    if (typeof k === "number") {
      keyRepr = `n:${k}`;
    } else if (typeof k === "string") {
      keyRepr = `s:${k}`;
    } else if (k instanceof Uint8Array) {
      keyRepr = `b:${bytesToHex(k)}`;
    } else {
      throw new CborDecodeError("Unsupported non-scalar CBOR map key");
    }
    if (seen.has(keyRepr)) {
      throw new CborDecodeError("Duplicate CBOR map key");
    }
    seen.add(keyRepr);
  }
}

function findIntKey(map: CborMap, target: number): CborValue | undefined {
  let found: CborValue | undefined;
  for (const [k, v] of map.entries) {
    if (k === target) {
      if (found !== undefined) {
        throw new CborDecodeError(`Duplicate CBOR map key ${target}`);
      }
      found = v;
    }
  }
  return found;
}

/**
 * Folds an RFC 9162 §2.1.3.2 SHA-256 Merkle inclusion proof from
 * `leaf = SHA-256(0x00 || payload_bstr)` and `auditPath` to the tree root.
 */
function foldRfc9162InclusionRoot(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: readonly Uint8Array[],
): Uint8Array | null {
  if (
    !Number.isSafeInteger(treeSize) ||
    treeSize < 1 ||
    !Number.isSafeInteger(leafIndex) ||
    leafIndex < 0 ||
    leafIndex >= treeSize
  ) {
    return null;
  }

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;

  for (const sibling of auditPath) {
    if (sibling.length !== 32) return null;
    if (sn === 0) return null; // excess audit path nodes
    if ((fn & 1) === 1 || fn === sn) {
      r = sha256(concatBytes(Uint8Array.of(0x01), sibling, r));
      while ((fn & 1) === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = sha256(concatBytes(Uint8Array.of(0x01), r, sibling));
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  if (sn !== 0) return null; // incomplete audit path
  return r;
}

function parseScittStatement(
  payloadBytes: Uint8Array,
): ScittDecisionStatement | null {
  const text = decodeUtf8Strict(payloadBytes);
  if (text === null) return null;
  let parsed: unknown;
  try {
    parsed = parseStrictJson(text);
  } catch {
    return null;
  }
  if (!isPlainRecord(parsed)) return null;
  if (parsed.schema !== "entros-scitt-permit-v2") return null;
  if (!isLowerHex64NonZero(parsed.jti)) return null;
  if (!isLowerHex64NonZero(parsed.request_digest)) return null;
  if (typeof parsed.policy_id !== "string" || parsed.policy_id.length === 0) {
    return null;
  }
  if (!isCanonicalAudUri(parsed.aud)) return null;
  if (parsed.decision !== "allow" && parsed.decision !== "deny") return null;
  if (typeof parsed.reason !== "string" || parsed.reason.length === 0) {
    return null;
  }
  if (
    typeof parsed.assurance_tier !== "string" ||
    !ASSURANCE_SET.has(parsed.assurance_tier)
  ) {
    return null;
  }
  if (
    !Array.isArray(parsed.modality) ||
    parsed.modality.length === 0 ||
    !parsed.modality.every((m) => typeof m === "string" && m.length > 0)
  ) {
    return null;
  }
  if (
    !isValidUnixSeconds(parsed.freshness_verified_at) ||
    !isValidUnixSeconds(parsed.evaluated_at)
  ) {
    return null;
  }
  if (
    parsed.model_version !== null &&
    !isLowerHex64(parsed.model_version)
  ) {
    return null;
  }
  if (parsed.retention !== "memory_only") return null;

  return {
    schema: "entros-scitt-permit-v2",
    jti: parsed.jti,
    request_digest: parsed.request_digest,
    policy_id: parsed.policy_id,
    aud: parsed.aud,
    decision: parsed.decision,
    reason: parsed.reason,
    assurance_tier: parsed.assurance_tier as AssuranceTierV2,
    modality: [...(parsed.modality as string[])],
    freshness_verified_at: parsed.freshness_verified_at,
    evaluated_at: parsed.evaluated_at,
    model_version: parsed.model_version,
    retention: "memory_only",
  };
}

export interface VerifyScittReceiptOptions {
  receipt: string | Uint8Array;
  jwks: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  expectedJti?: string;
  expectedRequestDigest?: string;
  expectedPolicyId?: string;
  expectedAud?: string;
  expectedDecision?: "allow" | "deny";
}

/**
 * Verifies an IETF SCITT (RFC 9943) / COSE Receipts (RFC 9942) Tag 18
 * `COSE_Sign1` transparency receipt offline using zero CBOR dependencies.
 */
export async function verifyScittReceipt(
  options: VerifyScittReceiptOptions,
): Promise<ScittVerificationResult> {
  const fail = (detail: string): ScittVerificationResult => ({
    ok: false,
    reason: "scitt_receipt_invalid",
    detail,
  });

  const rawBytes =
    options.receipt instanceof Uint8Array
      ? options.receipt
      : typeof options.receipt === "string"
        ? base64UrlDecodeStrict(options.receipt)
        : null;
  if (!rawBytes || rawBytes.length === 0) {
    return fail("Malformed Base64URL or empty SCITT receipt");
  }

  let decoded: CborValue;
  try {
    decoded = decodeDefiniteCbor(rawBytes);
  } catch (error) {
    return fail(
      error instanceof Error ? error.message : "Invalid definite-length CBOR",
    );
  }

  if (!isCborTagged(decoded) || decoded.tag !== 18) {
    return fail("SCITT receipt must be a CBOR Tag 18 COSE_Sign1 envelope");
  }
  if (!Array.isArray(decoded.value) || decoded.value.length !== 4) {
    return fail("COSE_Sign1 envelope must be a 4-element CBOR array");
  }

  const [protectedBstr, unprotectedMap, payloadBstr, signatureBstr] =
    decoded.value;
  if (
    !(protectedBstr instanceof Uint8Array) ||
    !isCborMap(unprotectedMap) ||
    !(payloadBstr instanceof Uint8Array) ||
    !(signatureBstr instanceof Uint8Array) ||
    signatureBstr.length !== 64
  ) {
    return fail("COSE_Sign1 elements have invalid types or signature length");
  }

  let protectedDecoded: CborValue;
  try {
    protectedDecoded = decodeDefiniteCbor(protectedBstr);
  } catch {
    return fail("COSE_Sign1 protected header is invalid CBOR");
  }
  if (!isCborMap(protectedDecoded)) {
    return fail("COSE_Sign1 protected header must be a CBOR map");
  }

  let alg: CborValue | undefined;
  let crit: CborValue | undefined;
  let unprotectedCrit: CborValue | undefined;
  let kidVal: CborValue | undefined;
  let vds: CborValue | undefined;
  let vdp: CborValue | undefined;
  try {
    assertUniqueMapKeys(protectedDecoded);
    assertUniqueMapKeys(unprotectedMap);
    alg = findIntKey(protectedDecoded, 1);
    crit = findIntKey(protectedDecoded, 2);
    unprotectedCrit = findIntKey(unprotectedMap, 2);
    kidVal = findIntKey(protectedDecoded, 4);
    vds = findIntKey(protectedDecoded, 395);
    vdp = findIntKey(unprotectedMap, 396);
  } catch (error) {
    return fail(
      error instanceof Error ? error.message : "Duplicate COSE header key",
    );
  }

  if (crit !== undefined) {
    return fail("COSE_Sign1 protected header contains unsupported crit (2) header");
  }
  if (unprotectedCrit !== undefined) {
    return fail(
      "COSE_Sign1 unprotected header contains forbidden crit (2) header",
    );
  }
  if (alg !== -8) {
    return fail("COSE_Sign1 protected header alg (1) must equal -8 (EdDSA)");
  }
  if (!(kidVal instanceof Uint8Array) || kidVal.length === 0) {
    return fail("COSE_Sign1 protected header kid (4) must be a non-empty bstr");
  }
  const kid = decodeUtf8Strict(kidVal);
  if (kid === null || kid.trim().length === 0) {
    return fail("COSE_Sign1 kid must be valid non-empty UTF-8");
  }
  if (vds !== 1) {
    return fail("COSE_Sign1 protected header vds (395) must equal 1");
  }

  if (!isCborMap(vdp)) {
    return fail("COSE_Sign1 unprotected header vdp (396) must be a CBOR map");
  }
  let inclusionProof: CborValue | undefined;
  try {
    assertUniqueMapKeys(vdp);
    inclusionProof = findIntKey(vdp, -1);
  } catch {
    return fail("Duplicate inclusion proof entry in vdp");
  }
  if (!Array.isArray(inclusionProof) || inclusionProof.length !== 3) {
    return fail("vdp inclusion proof (-1) must be [tree_size, leaf_index, audit_path]");
  }

  const [treeSize, leafIndex, auditPathRaw] = inclusionProof;
  if (
    typeof treeSize !== "number" ||
    typeof leafIndex !== "number" ||
    !Array.isArray(auditPathRaw)
  ) {
    return fail("Invalid inclusion proof tuple element types");
  }
  const auditPath: Uint8Array[] = [];
  for (const node of auditPathRaw) {
    if (!(node instanceof Uint8Array) || node.length !== 32) {
      return fail("Every Merkle audit_path entry must be a 32-byte bstr");
    }
    auditPath.push(node);
  }

  const statement = parseScittStatement(payloadBstr);
  if (!statement) {
    return fail("SCITT payload_bstr failed canonical metadata-only schema validation");
  }

  if (
    options.expectedJti !== undefined &&
    statement.jti !== options.expectedJti
  ) {
    return fail("SCITT statement jti mismatch");
  }
  if (
    options.expectedRequestDigest !== undefined &&
    statement.request_digest !== options.expectedRequestDigest
  ) {
    return fail("SCITT statement request_digest mismatch");
  }
  if (
    options.expectedPolicyId !== undefined &&
    statement.policy_id !== options.expectedPolicyId
  ) {
    return fail("SCITT statement policy_id mismatch");
  }
  if (
    options.expectedAud !== undefined &&
    statement.aud !== options.expectedAud
  ) {
    return fail("SCITT statement aud mismatch");
  }
  if (
    options.expectedDecision !== undefined &&
    statement.decision !== options.expectedDecision
  ) {
    return fail("SCITT statement decision mismatch");
  }

  const leafHash = sha256(concatBytes(Uint8Array.of(0x00), payloadBstr));
  const merkleRoot = foldRfc9162InclusionRoot(
    leafHash,
    leafIndex,
    treeSize,
    auditPath,
  );
  if (!merkleRoot) {
    return fail("Invalid RFC 9162 Merkle inclusion proof");
  }

  let lookup;
  try {
    const resolver = normalizeJwksSource(options.jwks, options.revokedKids);
    lookup = await resolver.resolveEd25519Key(kid);
  } catch (error) {
    return {
      ok: false,
      reason: "state_unavailable",
      detail:
        error instanceof Error ? error.message : "SCITT JWKS lookup failed",
    };
  }
  if (lookup.status === "unavailable") {
    return { ok: false, reason: "state_unavailable", detail: lookup.detail };
  }
  if (lookup.status !== "found") {
    return fail(`SCITT transparency key '${kid}' is ${lookup.status}`);
  }

  const sigStructure = encodeCborSigStructure(protectedBstr, merkleRoot);
  if (!verifyStrictEd25519Signature(signatureBstr, sigStructure, lookup.publicKey)) {
    return fail("SCITT COSE_Sign1 Ed25519 signature verification failed");
  }

  return {
    ok: true,
    receipt: {
      kid,
      vds: 1,
      treeSize,
      leafIndex,
      leafHashHex: bytesToHex(leafHash),
      merkleRootHex: bytesToHex(merkleRoot),
      statement,
    },
  };
}
