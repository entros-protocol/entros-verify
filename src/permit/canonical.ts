/**
 * Zero-dependency RFC 8785 JSON Canonicalization Scheme (JCS) implementation
 * and Entros-Agent-Permit-v2 `request_digest` computation.
 */

import { sha256 } from "@noble/hashes/sha2.js";

import {
  bytesToHex,
  isPlainRecord,
  isPrintableAscii,
  utf8Encoder,
} from "./encoding";
import {
  AGENT_PERMIT_V2_DOMAIN,
  PERMIT_V2_LIMITS,
  type ActionKindV2,
  type CanonicalActionV2Input,
  type CanonicalActionV2Result,
} from "./types";

const ALLOWED_ACTION_KINDS: ReadonlySet<string> = new Set<ActionKindV2>([
  "mcp.tool_call",
  "voice.tool_call",
  "http.action",
]);

export type CanonicalJsonErrorCode =
  | "invalid_surrogate"
  | "non_finite_number"
  | "max_depth_exceeded"
  | "circular_reference"
  | "sparse_array"
  | "duplicate_key"
  | "unsupported_value"
  | "invalid_action"
  | "invalid_kind"
  | "invalid_server"
  | "invalid_tool"
  | "invalid_arguments"
  | "invalid_rar_details";

export class CanonicalJsonError extends Error {
  constructor(
    public readonly code: CanonicalJsonErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CanonicalJsonError";
  }
}

/**
 * Validates that a JavaScript string contains no unpaired UTF-16 surrogates
 * (`0xD800..0xDFFF`) and formats it with RFC 8785 minimal escaping.
 */
function serializeJcsString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= value.length) {
        throw new CanonicalJsonError(
          "invalid_surrogate",
          "Lone high UTF-16 surrogate is forbidden in RFC 8785 JCS",
        );
      }
      const next = value.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new CanonicalJsonError(
          "invalid_surrogate",
          "Unpaired high UTF-16 surrogate is forbidden in RFC 8785 JCS",
        );
      }
      out += value[i]! + value[i + 1]!;
      i += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalJsonError(
        "invalid_surrogate",
        "Lone low UTF-16 surrogate is forbidden in RFC 8785 JCS",
      );
    }
    switch (code) {
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += "\\\\";
        break;
      case 0x08:
        out += "\\b";
        break;
      case 0x0c:
        out += "\\f";
        break;
      case 0x0a:
        out += "\\n";
        break;
      case 0x0d:
        out += "\\r";
        break;
      case 0x09:
        out += "\\t";
        break;
      default:
        if (code < 0x20) {
          out += `\\u${code.toString(16).padStart(4, "0")}`;
        } else {
          out += value[i]!;
        }
    }
  }
  out += '"';
  return out;
}

function serializeJcsNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalJsonError(
      "non_finite_number",
      "Non-finite IEEE-754 numbers (NaN, Infinity, -Infinity) are forbidden in RFC 8785 JCS",
    );
  }
  if (Object.is(value, -0) || value === 0) return "0";
  // ECMA-262 Number::toString matches RFC 8785 §3.2.2.3 exactly.
  return String(value);
}

function serializeJcsValue(
  value: unknown,
  depth: number,
  ancestors: Set<object>,
): string {
  if (depth > PERMIT_V2_LIMITS.maxCanonicalDepth) {
    throw new CanonicalJsonError(
      "max_depth_exceeded",
      `JSON nesting exceeds maximum depth of ${PERMIT_V2_LIMITS.maxCanonicalDepth}`,
    );
  }
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeJcsNumber(value);
  if (typeof value === "string") return serializeJcsString(value);

  if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new CanonicalJsonError(
        "circular_reference",
        "Circular references are forbidden in RFC 8785 JCS",
      );
    }
    ancestors.add(value);
    try {
      const items: string[] = [];
      for (let i = 0; i < value.length; i += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, i)) {
          throw new CanonicalJsonError(
            "sparse_array",
            "Sparse arrays are forbidden in RFC 8785 JCS",
          );
        }
        items.push(serializeJcsValue(value[i], depth + 1, ancestors));
      }
      return `[${items.join(",")}]`;
    } finally {
      ancestors.delete(value);
    }
  }

  if (isPlainRecord(value)) {
    if (ancestors.has(value)) {
      throw new CanonicalJsonError(
        "circular_reference",
        "Circular references are forbidden in RFC 8785 JCS",
      );
    }
    ancestors.add(value);
    try {
      // JavaScript `<` / `>` compares strings strictly by UTF-16 code units,
      // matching RFC 8785 §3.2.3 (e.g., U+1D11E sorts before U+E000).
      const keys = Object.keys(value).sort((a, b) =>
        a < b ? -1 : a > b ? 1 : 0,
      );
      const entries: string[] = [];
      for (const key of keys) {
        const entry = value[key];
        if (entry === undefined) {
          throw new CanonicalJsonError(
            "unsupported_value",
            `Object property '${key}' must not be undefined`,
          );
        }
        entries.push(
          `${serializeJcsString(key)}:${serializeJcsValue(entry, depth + 1, ancestors)}`,
        );
      }
      return `{${entries.join(",")}}`;
    } finally {
      ancestors.delete(value);
    }
  }

  throw new CanonicalJsonError(
    "unsupported_value",
    `Unsupported value type for RFC 8785 JCS: ${typeof value}`,
  );
}

/**
 * Serializes a JSON-compatible value strictly according to RFC 8785 (JCS).
 * Sorts keys by UTF-16 code unit order, normalizes `-0` to `0`, rejects lone
 * UTF-16 surrogates, non-finite floats, `undefined`, sparse arrays, cycles,
 * non-plain prototypes, and nesting depth above 32.
 */
export function canonicalizeJcs(value: unknown): string {
  return serializeJcsValue(value, 0, new Set<object>());
}

/**
 * Parses a JSON text strictly, rejecting duplicate object keys at any level
 * and rejecting lone UTF-16 surrogates or nesting depth above 32.
 */
export function parseStrictJson(text: string): unknown {
  let cursor = 0;
  const len = text.length;

  function skipWs(): void {
    while (cursor < len) {
      const c = text.charCodeAt(cursor);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        cursor += 1;
      } else {
        break;
      }
    }
  }

  function parseString(): string {
    if (text.charCodeAt(cursor) !== 0x22) {
      throw new CanonicalJsonError("unsupported_value", "Expected string");
    }
    const start = cursor;
    cursor += 1;
    while (cursor < len) {
      const c = text.charCodeAt(cursor);
      if (c === 0x5c) {
        cursor += 2;
        continue;
      }
      if (c === 0x22) {
        cursor += 1;
        const parsed = JSON.parse(text.slice(start, cursor)) as string;
        serializeJcsString(parsed); // verifies no lone surrogates
        return parsed;
      }
      if (c < 0x20) {
        throw new CanonicalJsonError(
          "unsupported_value",
          "Unescaped control character in JSON string",
        );
      }
      cursor += 1;
    }
    throw new CanonicalJsonError("unsupported_value", "Unterminated JSON string");
  }

  function parseValue(depth: number): unknown {
    if (depth > PERMIT_V2_LIMITS.maxCanonicalDepth) {
      throw new CanonicalJsonError(
        "max_depth_exceeded",
        `JSON nesting exceeds maximum depth of ${PERMIT_V2_LIMITS.maxCanonicalDepth}`,
      );
    }
    skipWs();
    if (cursor >= len) {
      throw new CanonicalJsonError("unsupported_value", "Unexpected end of JSON");
    }
    const ch = text[cursor];
    if (ch === "{") {
      cursor += 1;
      skipWs();
      const obj: Record<string, unknown> = {};
      if (text[cursor] === "}") {
        cursor += 1;
        return obj;
      }
      const seen = new Set<string>();
      while (true) {
        skipWs();
        const key = parseString();
        if (seen.has(key)) {
          throw new CanonicalJsonError(
            "duplicate_key",
            `Duplicate JSON object key '${key}'`,
          );
        }
        seen.add(key);
        skipWs();
        if (text[cursor] !== ":") {
          throw new CanonicalJsonError("unsupported_value", "Expected ':'");
        }
        cursor += 1;
        obj[key] = parseValue(depth + 1);
        skipWs();
        if (text[cursor] === "}") {
          cursor += 1;
          return obj;
        }
        if (text[cursor] !== ",") {
          throw new CanonicalJsonError("unsupported_value", "Expected ',' or '}'");
        }
        cursor += 1;
      }
    }
    if (ch === "[") {
      cursor += 1;
      skipWs();
      const arr: unknown[] = [];
      if (text[cursor] === "]") {
        cursor += 1;
        return arr;
      }
      while (true) {
        arr.push(parseValue(depth + 1));
        skipWs();
        if (text[cursor] === "]") {
          cursor += 1;
          return arr;
        }
        if (text[cursor] !== ",") {
          throw new CanonicalJsonError("unsupported_value", "Expected ',' or ']'");
        }
        cursor += 1;
      }
    }
    if (ch === '"') return parseString();
    if (text.startsWith("true", cursor)) {
      cursor += 4;
      return true;
    }
    if (text.startsWith("false", cursor)) {
      cursor += 5;
      return false;
    }
    if (text.startsWith("null", cursor)) {
      cursor += 4;
      return null;
    }
    const numMatch = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      text.slice(cursor),
    );
    if (!numMatch) {
      throw new CanonicalJsonError("unsupported_value", "Invalid JSON token");
    }
    cursor += numMatch[0].length;
    const num = Number(numMatch[0]);
    if (!Number.isFinite(num)) {
      throw new CanonicalJsonError("non_finite_number", "Non-finite JSON number");
    }
    return num;
  }

  const result = parseValue(0);
  skipWs();
  if (cursor !== len) {
    throw new CanonicalJsonError("unsupported_value", "Trailing characters in JSON");
  }
  return result;
}

function validateIdentifier(
  value: unknown,
  field: "server" | "tool",
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > PERMIT_V2_LIMITS.maxIdentifierLength ||
    value !== value.trim() ||
    !isPrintableAscii(value)
  ) {
    throw new CanonicalJsonError(
      field === "server" ? "invalid_server" : "invalid_tool",
      `Action ${field} must be trimmed printable ASCII (1..${PERMIT_V2_LIMITS.maxIdentifierLength} chars)`,
    );
  }
  return value;
}

/**
 * Validates an Entros-Agent-Permit-v2 canonical action object and rejects
 * invalid kinds, untrimmed identifiers, non-object arguments, or `null` rar_details.
 */
export function validateActionV2(input: unknown): CanonicalActionV2Input {
  if (!isPlainRecord(input)) {
    throw new CanonicalJsonError("invalid_action", "Action must be a plain object");
  }
  const allowedKeys = new Set([
    "kind",
    "server",
    "tool",
    "arguments",
    "rar_details",
  ]);
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) {
      throw new CanonicalJsonError(
        "invalid_action",
        `Unexpected action property '${key}'`,
      );
    }
  }
  if (typeof input.kind !== "string" || !ALLOWED_ACTION_KINDS.has(input.kind)) {
    throw new CanonicalJsonError(
      "invalid_kind",
      "Action kind must be 'mcp.tool_call', 'voice.tool_call', or 'http.action'",
    );
  }
  const server = validateIdentifier(input.server, "server");
  const tool = validateIdentifier(input.tool, "tool");
  if (!isPlainRecord(input.arguments)) {
    throw new CanonicalJsonError(
      "invalid_arguments",
      "Action arguments must be a plain JSON object",
    );
  }
  const hasRar = Object.prototype.hasOwnProperty.call(input, "rar_details");
  if (hasRar && input.rar_details !== undefined) {
    if (!Array.isArray(input.rar_details)) {
      throw new CanonicalJsonError(
        "invalid_rar_details",
        "Action rar_details must be an array when present (omit when unused)",
      );
    }
    return {
      kind: input.kind as ActionKindV2,
      server,
      tool,
      arguments: input.arguments,
      rar_details: input.rar_details,
    };
  }
  return {
    kind: input.kind as ActionKindV2,
    server,
    tool,
    arguments: input.arguments,
  };
}

/**
 * Canonicalizes and hashes an Entros-Agent-Permit-v2 action object using
 * `SHA-256("Entros-Agent-Permit-v2\n" || UTF8(JCS(action)))`.
 */
export function hashActionV2(
  input: CanonicalActionV2Input,
): CanonicalActionV2Result {
  const validated = validateActionV2(input);
  const canonicalJson = canonicalizeJcs(validated);
  const preimage = utf8Encoder.encode(
    `${AGENT_PERMIT_V2_DOMAIN}\n${canonicalJson}`,
  );
  const requestDigest = bytesToHex(sha256(preimage));
  return {
    action: validated,
    canonicalJson,
    requestDigest,
  };
}
