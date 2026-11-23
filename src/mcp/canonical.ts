import { sha256 } from "@noble/hashes/sha2.js";

import type { AgentPermitAction } from "../agent-permit";

const MCP_ACTION_DOMAIN = "Entros-MCP-Action-v1";
const MAX_CANONICAL_DEPTH = 32;
const MAX_LABEL_LENGTH = 96;
const MAX_IDENTIFIER_LENGTH = 128;
const encoder = new TextEncoder();

export interface McpToolActionInput {
  /** MCP server identifier or label (printable ASCII, 1 to 128 chars). */
  server: string;
  /** MCP tool name (printable ASCII, 1 to 128 chars). */
  tool: string;
  /** Tool arguments object (plain JSON-compatible record). */
  arguments: Record<string, unknown>;
  /** Optional custom human-readable label (printable ASCII, 1 to 96 chars). */
  label?: string;
}

export interface CanonicalMcpAction {
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
  /** Deterministic canonical JSON of `{ server, tool, arguments }`. */
  canonicalJson: string;
  /** Human-readable action label carried inside the signed permit. */
  label: string;
  /** Lowercase 64-hex SHA-256 of the domain-separated canonical action payload. */
  sha256: string;
}

export class McpActionValidationError extends Error {
  constructor(
    public readonly field: string,
    message?: string,
  ) {
    super(message ?? `Invalid MCP action: ${field}`);
    this.name = "McpActionValidationError";
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isPrintableAscii(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

function validateIdentifier(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_IDENTIFIER_LENGTH ||
    value !== value.trim() ||
    !isPrintableAscii(value)
  ) {
    throw new McpActionValidationError(field);
  }
  return value;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function serializeValue(
  value: unknown,
  depth: number,
  ancestors: Set<object>,
): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new McpActionValidationError(
      "arguments",
      "MCP action nesting exceeds maximum depth",
    );
  }
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new McpActionValidationError(
        "arguments",
        "MCP action numbers must be finite",
      );
    }
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new McpActionValidationError(
        "arguments",
        "MCP action contains a circular reference",
      );
    }
    ancestors.add(value);
    try {
      const items: string[] = [];
      for (let i = 0; i < value.length; i += 1) {
        if (!Object.prototype.hasOwnProperty.call(value, i)) {
          throw new McpActionValidationError(
            "arguments",
            "MCP action arrays must not contain sparse holes",
          );
        }
        items.push(serializeValue(value[i], depth + 1, ancestors));
      }
      return `[${items.join(",")}]`;
    } finally {
      ancestors.delete(value);
    }
  }
  if (isPlainRecord(value)) {
    if (ancestors.has(value)) {
      throw new McpActionValidationError(
        "arguments",
        "MCP action contains a circular reference",
      );
    }
    ancestors.add(value);
    try {
      const keys = Object.keys(value).sort((a, b) =>
        a < b ? -1 : a > b ? 1 : 0,
      );
      const entries = keys.map((key) => {
        const entry = value[key];
        if (entry === undefined) {
          throw new McpActionValidationError(
            "arguments",
            `MCP action argument '${key}' must not be undefined`,
          );
        }
        return `${JSON.stringify(key)}:${serializeValue(entry, depth + 1, ancestors)}`;
      });
      return `{${entries.join(",")}}`;
    } finally {
      ancestors.delete(value);
    }
  }
  throw new McpActionValidationError(
    "arguments",
    `Unsupported value type in MCP action: ${typeof value}`,
  );
}

/**
 * Produces deterministic canonical JSON with keys sorted by UTF-16 code unit order.
 * Rejects `undefined`, non-finite numbers, non-plain objects, cycles, and deep nesting.
 */
export function canonicalizeJson(value: unknown): string {
  return serializeValue(value, 0, new Set<object>());
}

function defaultActionLabel(server: string, tool: string): string {
  const full = `MCP ${server}:${tool}`;
  if (full.length <= MAX_LABEL_LENGTH) return full;
  return `${full.slice(0, MAX_LABEL_LENGTH - 3).trimEnd()}...`;
}

/**
 * Validates, canonicalizes, and hashes an MCP tool invocation into a detached
 * canonical action record suitable for binding to an `AgentPermitRequest`.
 */
export function canonicalizeMcpAction(
  input: McpToolActionInput,
): CanonicalMcpAction {
  if (!isPlainRecord(input)) {
    throw new McpActionValidationError("action");
  }
  const server = validateIdentifier(input.server, "server");
  const tool = validateIdentifier(input.tool, "tool");
  if (!isPlainRecord(input.arguments)) {
    throw new McpActionValidationError(
      "arguments",
      "MCP action arguments must be a plain object",
    );
  }
  let label: string;
  if (input.label !== undefined) {
    if (
      typeof input.label !== "string" ||
      input.label.length < 1 ||
      input.label.length > MAX_LABEL_LENGTH ||
      input.label !== input.label.trim() ||
      !isPrintableAscii(input.label)
    ) {
      throw new McpActionValidationError("label");
    }
    label = input.label;
  } else {
    label = defaultActionLabel(server, tool);
  }

  const canonicalArgsJson = canonicalizeJson(input.arguments);
  const canonicalArgs = JSON.parse(canonicalArgsJson) as Record<string, unknown>;
  const canonicalJson = canonicalizeJson({
    arguments: canonicalArgs,
    server,
    tool,
  });
  const digest = bytesToHex(
    sha256(encoder.encode(`${MCP_ACTION_DOMAIN}\n${canonicalJson}`)),
  );

  return {
    server,
    tool,
    arguments: canonicalArgs,
    canonicalJson,
    label,
    sha256: digest,
  };
}

/** Computes the domain-separated lowercase 64-hex SHA-256 digest of an MCP tool action. */
export function hashMcpAction(input: McpToolActionInput): string {
  return canonicalizeMcpAction(input).sha256;
}

/** Builds the `AgentPermitAction` (`label` + `sha256`) for an MCP tool invocation. */
export function createMcpPermitAction(
  input: McpToolActionInput,
): AgentPermitAction {
  const canonical = canonicalizeMcpAction(input);
  return {
    label: canonical.label,
    sha256: canonical.sha256,
  };
}
