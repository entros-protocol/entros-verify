/**
 * Agent Operator Permit v1. Pure grammar, signatures and settlement evaluation.
 * Chain reads come from a trusted reader such as `readAgentState` and
 * `readIntegratorEvidence` in `@entros/pulse-sdk`.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";

import { base58Decode, base58Encode, canonicalKeyBytes } from "./base58";
import {
  encodePolicyRequest,
  evaluatePolicy,
  normalizePolicyRequest,
  POLICY_NETWORK,
  type PolicyEvidenceReadResult,
  type PolicyRequest,
  type PolicyResult,
} from "./policy";

export const AGENT_PERMIT_VERSION_LINE = "Entros-Agent-Permit-v1";
export const AGENT_PERMIT_NOTICE_LINE =
  "Sign only to let this agent perform the action below. This is not a transaction.";
export const AGENT_PERMIT_PRESENTATION_LINE =
  "Entros-Agent-Permit-Presentation-v1";

export const AGENT_PERMIT_NETWORK = Object.freeze({
  cluster: "devnet",
  genesisHash: POLICY_NETWORK.genesisHash,
  entrosAnchorProgram: POLICY_NETWORK.programIds.anchor,
  agentRegistryProgram: "8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C",
  agentCollection: "6CTyGPcn8dMwKEqgtvx2XCpkGUd7uqCVK6937RSM5bhA",
  coreProgram: "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
} as const);

export const AGENT_PERMIT_LIMITS = Object.freeze({
  minLifetimeSeconds: 30,
  maxLifetimeSeconds: 900,
  clockSkewSeconds: 30,
  maxAudienceLength: 200,
  maxLabelLength: 96,
  // 2000-01-01T00:00:00Z to 9999-12-31T23:59:59Z. `toISOString` writes six-digit years past 9999.
  minTimeSeconds: 946684800,
  maxTimeSeconds: 253402300799,
});

export interface AgentPermitAction {
  label: string;
  /** Lowercase hex SHA-256 of the consumer's own action record. */
  sha256: string;
}

export interface AgentPermitRequest {
  version: 1;
  agent: string;
  agentWallet: string;
  operator: string;
  audience: string;
  action: AgentPermitAction;
  policy: PolicyRequest;
  cluster: "devnet";
  genesisHash: string;
  entrosAnchorProgram: string;
  agentRegistryProgram: string;
  agentCollection: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

export interface CreateAgentPermitRequestInput {
  agent: string;
  agentWallet: string;
  operator: string;
  audience: string;
  action: AgentPermitAction;
  policy: PolicyRequest;
  issuedAt: number;
  lifetimeSeconds: number;
  /** Omit to draw 32 random bytes from `crypto.getRandomValues`. */
  nonce?: string;
}

export type AgentWalletStatus = "bound" | "unbound" | "stale";

export interface AgentStateEvidence {
  cluster: "devnet";
  genesisHash: string;
  coreProgram: string;
  agentRegistryProgram: string;
  agentCollection: string;
  agent: string;
  agentAccount: string;
  /** Owner field of the Metaplex Core asset. The only owner source. */
  owner: string;
  /** Registry cache. Informational, and the agent wallet counts only when it matches. */
  cachedOwner: string;
  agentWallet: string | null;
  agentWalletStatus: AgentWalletStatus;
  readContextSlot: number;
}

export type AgentStateFailureReason =
  | "invalid_request"
  | "wrong_cluster"
  | "agent_missing"
  | "agent_invalid"
  | "agent_unregistered"
  | "rpc_unavailable";

export type AgentStateReadResult =
  | { status: "available"; evidence: AgentStateEvidence }
  | { status: "invalid" | "unavailable"; reason: AgentStateFailureReason };

export type AgentPermitReason =
  | "accepted"
  | "invalid_permit"
  | "permit_expired"
  | "invalid_signature"
  | "invalid_presentation"
  | "wrong_cluster"
  | "agent_missing"
  | "agent_invalid"
  | "agent_unregistered"
  | "agent_unavailable"
  | "owner_changed"
  | "agent_wallet_stale"
  | "agent_wallet_unbound"
  | "agent_wallet_changed"
  | "score_below_minimum"
  | "verification_stale"
  | "attestation_required"
  | "invalid_evidence"
  | "state_unavailable";

export type AgentPermitDenyReason = Exclude<
  AgentPermitReason,
  "accepted" | "agent_unavailable" | "state_unavailable"
>;

export type AgentPermitPrecheck =
  | { ok: true; request: AgentPermitRequest; permitId: string }
  | {
      ok: false;
      reason:
        | "invalid_permit"
        | "permit_expired"
        | "invalid_signature"
        | "invalid_presentation";
      request: AgentPermitRequest | null;
      permitId: string | null;
    };

interface AgentPermitResultBase {
  permitId: string | null;
  request: AgentPermitRequest | null;
  evaluatedAt: number;
  expiresAt: number | null;
  agentState: AgentStateEvidence | null;
  policy: PolicyResult | null;
}

export type AgentPermitResult = AgentPermitResultBase &
  (
    | { decision: "allow"; reason: "accepted" }
    | { decision: "deny"; reason: AgentPermitDenyReason }
    | {
        decision: "unavailable";
        reason: "agent_unavailable" | "state_unavailable";
      }
  );

export interface AgentPermitSignatures {
  operatorSignature: string;
  presentationSignature: string;
}

export interface AgentPermitEvaluationInput extends AgentPermitSignatures {
  request: AgentPermitRequest;
  agentState: AgentStateReadResult;
  operatorEvidence: PolicyEvidenceReadResult;
  nowSeconds: number;
}

export interface AgentPermitApproval {
  version: 1;
  permitId: string;
  operatorSignature: string;
  verifiedTransaction: string;
}

export interface AgentPermitSettlementBundle extends AgentPermitSignatures {
  version: 1;
  nonce: string;
  verifiedTransaction: string;
}

export class AgentPermitValidationError extends Error {
  constructor(public readonly field: string) {
    super(`Invalid agent permit: ${field}`);
    this.name = "AgentPermitValidationError";
  }
}

const FIELD_KEYS = [
  "agent",
  "agent_wallet",
  "operator",
  "audience",
  "action",
  "action_sha256",
  "policy",
  "cluster",
  "genesis",
  "entros_anchor",
  "agent_registry",
  "agent_collection",
  "issued_at",
  "expires_at",
  "nonce",
] as const;

const REQUEST_KEYS = [
  "version",
  "agent",
  "agentWallet",
  "operator",
  "audience",
  "action",
  "policy",
  "cluster",
  "genesisHash",
  "entrosAnchorProgram",
  "agentRegistryProgram",
  "agentCollection",
  "issuedAt",
  "expiresAt",
  "nonce",
] as const;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const LABEL = "(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])";
const FINAL = "(?:[a-z]|[a-z][a-z0-9-]{0,61}[a-z0-9])";
const PORT = "(?::([1-9][0-9]{0,4}))?";
const PATH = "(/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*/?)?)";
const HTTPS_AUDIENCE = new RegExp(
  `^https://((?:${LABEL}\\.)+${FINAL})${PORT}${PATH}$`,
);
const LOOPBACK_AUDIENCE = new RegExp(`^http://(127\\.0\\.0\\.1)${PORT}${PATH}$`);
const MAX_POLICY_LENGTH = 512;
const encoder = new TextEncoder();

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  return (
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function integer(value: unknown, minimum: number, maximum: number): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function printable(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

function digestHex(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value) && !/^0+$/.test(value);
}

/** A canonical Ed25519 point that is not of small order. */
function strictPublicKey(bytes: Uint8Array): boolean {
  try {
    return !ed25519.Point.fromBytes(bytes, false).isSmallOrder();
  } catch {
    return false;
  }
}

function signingKey(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const bytes = canonicalKeyBytes(value);
  return bytes !== null && strictPublicKey(bytes);
}

function address(value: unknown): value is string {
  return typeof value === "string" && canonicalKeyBytes(value) !== null;
}

/** Accepts only URLs that already equal their WHATWG `URL.href`. */
export function isAgentPermitAudience(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length > AGENT_PERMIT_LIMITS.maxAudienceLength
  )
    return false;
  const https = HTTPS_AUDIENCE.exec(value);
  const match = https ?? LOOPBACK_AUDIENCE.exec(value);
  if (!match) return false;
  const [, host, port, path] = match;
  if (host === undefined || path === undefined) return false;
  if (
    host
      .split(".")
      .some((label) => label.length >= 4 && label[2] === "-" && label[3] === "-")
  )
    return false;
  if (port !== undefined) {
    const number = Number(port);
    if (number > 65535 || number === (https ? 443 : 80)) return false;
  }
  return path.split("/").every((segment) => segment !== "." && segment !== "..");
}

function actionLabel(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= AGENT_PERMIT_LIMITS.maxLabelLength &&
    printable(value) &&
    value === value.trim()
  );
}

function unixSeconds(value: unknown): value is number {
  return integer(
    value,
    AGENT_PERMIT_LIMITS.minTimeSeconds,
    AGENT_PERMIT_LIMITS.maxTimeSeconds,
  );
}

function formatTime(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

function parseTime(value: string): number | null {
  if (!TIME.test(value)) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || milliseconds % 1000 !== 0) return null;
  const seconds = milliseconds / 1000;
  return unixSeconds(seconds) && formatTime(seconds) === value ? seconds : null;
}

function policyRequest(value: unknown): PolicyRequest | null {
  try {
    const policy = normalizePolicyRequest(value);
    return encodePolicyRequest(policy) === JSON.stringify(value) ? policy : null;
  } catch {
    return null;
  }
}

/** Validates every field and returns a detached copy. Throws `AgentPermitValidationError`. */
export function normalizeAgentPermitRequest(value: unknown): AgentPermitRequest {
  if (!record(value) || !exactKeys(value, REQUEST_KEYS))
    throw new AgentPermitValidationError("request");
  const {
    version,
    agent,
    agentWallet,
    operator,
    audience,
    action,
    issuedAt,
    expiresAt,
    nonce,
  } = value;
  if (version !== 1) throw new AgentPermitValidationError("version");
  if (!address(agent)) throw new AgentPermitValidationError("agent");
  if (!signingKey(agentWallet)) throw new AgentPermitValidationError("agentWallet");
  if (!signingKey(operator)) throw new AgentPermitValidationError("operator");
  if (!isAgentPermitAudience(audience)) throw new AgentPermitValidationError("audience");
  if (
    !record(action) ||
    !exactKeys(action, ["label", "sha256"]) ||
    !actionLabel(action.label) ||
    !digestHex(action.sha256)
  )
    throw new AgentPermitValidationError("action");
  const policy = policyRequest(value.policy);
  if (!policy) throw new AgentPermitValidationError("policy");
  if (
    value.cluster !== AGENT_PERMIT_NETWORK.cluster ||
    value.genesisHash !== AGENT_PERMIT_NETWORK.genesisHash ||
    value.entrosAnchorProgram !== AGENT_PERMIT_NETWORK.entrosAnchorProgram ||
    value.agentRegistryProgram !== AGENT_PERMIT_NETWORK.agentRegistryProgram ||
    value.agentCollection !== AGENT_PERMIT_NETWORK.agentCollection
  )
    throw new AgentPermitValidationError("deployment");
  if (!unixSeconds(issuedAt) || !unixSeconds(expiresAt))
    throw new AgentPermitValidationError("time");
  const lifetime = expiresAt - issuedAt;
  if (
    lifetime < AGENT_PERMIT_LIMITS.minLifetimeSeconds ||
    lifetime > AGENT_PERMIT_LIMITS.maxLifetimeSeconds
  )
    throw new AgentPermitValidationError("lifetime");
  if (!digestHex(nonce)) throw new AgentPermitValidationError("nonce");
  return {
    version: 1,
    agent,
    agentWallet,
    operator,
    audience,
    action: { label: action.label, sha256: action.sha256 },
    policy,
    cluster: AGENT_PERMIT_NETWORK.cluster,
    genesisHash: AGENT_PERMIT_NETWORK.genesisHash,
    entrosAnchorProgram: AGENT_PERMIT_NETWORK.entrosAnchorProgram,
    agentRegistryProgram: AGENT_PERMIT_NETWORK.agentRegistryProgram,
    agentCollection: AGENT_PERMIT_NETWORK.agentCollection,
    issuedAt,
    expiresAt,
    nonce,
  };
}

function randomNonce(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function")
    throw new AgentPermitValidationError("nonce");
  const bytes = new Uint8Array(32);
  cryptoApi.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/** Builds a permit request for the consumer to store and render. */
export function createAgentPermitRequest(
  input: CreateAgentPermitRequestInput,
): AgentPermitRequest {
  if (!integer(input.lifetimeSeconds, 1, AGENT_PERMIT_LIMITS.maxLifetimeSeconds))
    throw new AgentPermitValidationError("lifetime");
  return normalizeAgentPermitRequest({
    version: 1,
    agent: input.agent,
    agentWallet: input.agentWallet,
    operator: input.operator,
    audience: input.audience,
    action: { label: input.action.label, sha256: input.action.sha256 },
    policy: normalizePolicyRequest(input.policy),
    cluster: AGENT_PERMIT_NETWORK.cluster,
    genesisHash: AGENT_PERMIT_NETWORK.genesisHash,
    entrosAnchorProgram: AGENT_PERMIT_NETWORK.entrosAnchorProgram,
    agentRegistryProgram: AGENT_PERMIT_NETWORK.agentRegistryProgram,
    agentCollection: AGENT_PERMIT_NETWORK.agentCollection,
    issuedAt: input.issuedAt,
    expiresAt: input.issuedAt + input.lifetimeSeconds,
    nonce: input.nonce ?? randomNonce(),
  });
}

function renderNormalized(value: AgentPermitRequest): string {
  const fields = [
    value.agent,
    value.agentWallet,
    value.operator,
    value.audience,
    value.action.label,
    value.action.sha256,
    encodePolicyRequest(value.policy),
    value.cluster,
    value.genesisHash,
    value.entrosAnchorProgram,
    value.agentRegistryProgram,
    value.agentCollection,
    formatTime(value.issuedAt),
    formatTime(value.expiresAt),
    value.nonce,
  ];
  return [
    AGENT_PERMIT_VERSION_LINE,
    AGENT_PERMIT_NOTICE_LINE,
    ...FIELD_KEYS.map((key, index) => `${key}:${fields[index]}`),
  ].join("\n");
}

function permitIdOf(message: string): string {
  return bytesToHex(sha256(encoder.encode(message)));
}

/** Renders the seventeen-line text that the operator signs. */
export function renderAgentPermitMessage(request: AgentPermitRequest): string {
  return renderNormalized(normalizeAgentPermitRequest(request));
}

/** Parses a permit request and requires byte equality with its own rendering. */
export function parseAgentPermitMessage(text: unknown): AgentPermitRequest {
  if (typeof text !== "string" || text.length > 4096)
    throw new AgentPermitValidationError("message");
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code !== 0x0a && (code < 0x20 || code > 0x7e))
      throw new AgentPermitValidationError("message");
  }
  const lines = text.split("\n");
  if (
    lines.length !== FIELD_KEYS.length + 2 ||
    lines[0] !== AGENT_PERMIT_VERSION_LINE ||
    lines[1] !== AGENT_PERMIT_NOTICE_LINE
  )
    throw new AgentPermitValidationError("message");
  const values = new Map<string, string>();
  FIELD_KEYS.forEach((key, index) => {
    const line = lines[index + 2] ?? "";
    if (!line.startsWith(`${key}:`))
      throw new AgentPermitValidationError(key);
    values.set(key, line.slice(key.length + 1));
  });
  const field = (key: (typeof FIELD_KEYS)[number]): string => values.get(key) ?? "";
  const policyText = field("policy");
  if (policyText.length > MAX_POLICY_LENGTH)
    throw new AgentPermitValidationError("policy");
  let policy: unknown;
  try {
    policy = JSON.parse(policyText);
  } catch {
    throw new AgentPermitValidationError("policy");
  }
  const issuedAt = parseTime(field("issued_at"));
  const expiresAt = parseTime(field("expires_at"));
  if (issuedAt === null || expiresAt === null)
    throw new AgentPermitValidationError("time");
  const request = normalizeAgentPermitRequest({
    version: 1,
    agent: field("agent"),
    agentWallet: field("agent_wallet"),
    operator: field("operator"),
    audience: field("audience"),
    action: { label: field("action"), sha256: field("action_sha256") },
    policy,
    cluster: field("cluster"),
    genesisHash: field("genesis"),
    entrosAnchorProgram: field("entros_anchor"),
    agentRegistryProgram: field("agent_registry"),
    agentCollection: field("agent_collection"),
    issuedAt,
    expiresAt,
    nonce: field("nonce"),
  });
  if (renderNormalized(request) !== text)
    throw new AgentPermitValidationError("message");
  return request;
}

/** Lowercase hex SHA-256 of the permit request text. */
export function agentPermitId(request: AgentPermitRequest): string {
  return permitIdOf(renderAgentPermitMessage(request));
}

/** The two-line text that the agent wallet signs. */
export function renderAgentPermitPresentation(permitId: string): string {
  if (!HEX64.test(permitId)) throw new AgentPermitValidationError("permitId");
  return `${AGENT_PERMIT_PRESENTATION_LINE}\npermit:${permitId}`;
}

function strictVerify(
  signature: unknown,
  message: Uint8Array,
  publicKey: string,
): boolean {
  if (typeof signature !== "string" || !HEX128.test(signature)) return false;
  const key = canonicalKeyBytes(publicKey);
  if (!key) return false;
  try {
    // The library default, zip215 true, accepts small-order keys that verify any message.
    return ed25519.verify(hexToBytes(signature), message, key, { zip215: false });
  } catch {
    return false;
  }
}

function verifyNormalized(
  value: AgentPermitRequest,
  signatures: { operatorSignature: unknown; presentationSignature: unknown },
): { permitId: string; operator: boolean; presentation: boolean } {
  const message = renderNormalized(value);
  const permitId = permitIdOf(message);
  return {
    permitId,
    operator: strictVerify(
      signatures.operatorSignature,
      encoder.encode(message),
      value.operator,
    ),
    presentation: strictVerify(
      signatures.presentationSignature,
      encoder.encode(renderAgentPermitPresentation(permitId)),
      value.agentWallet,
    ),
  };
}

/** Checks the operator signature and the agent wallet presentation with strict rules. */
export function verifyAgentPermitSignatures(
  request: AgentPermitRequest,
  signatures: { operatorSignature: unknown; presentationSignature: unknown },
): { operator: boolean; presentation: boolean } {
  const { operator, presentation } = verifyNormalized(
    normalizeAgentPermitRequest(request),
    signatures,
  );
  return { operator, presentation };
}

function settlementClock(nowSeconds: number): number {
  if (!integer(nowSeconds, 1, AGENT_PERMIT_LIMITS.maxTimeSeconds))
    throw new AgentPermitValidationError("clock");
  return nowSeconds;
}

/**
 * Runs every check that needs no chain read: request shape, clock, expiry and both signatures.
 * Call it before reading chain state so an expired or forged permit costs no RPC request.
 */
export function precheckAgentPermit(input: {
  request: unknown;
  operatorSignature: unknown;
  presentationSignature: unknown;
  nowSeconds: number;
}): AgentPermitPrecheck {
  const now = settlementClock(input.nowSeconds);
  let request: AgentPermitRequest;
  try {
    request = normalizeAgentPermitRequest(input.request);
  } catch {
    return { ok: false, reason: "invalid_permit", request: null, permitId: null };
  }
  const signatures = verifyNormalized(request, input);
  const { permitId } = signatures;
  if (request.issuedAt > now + AGENT_PERMIT_LIMITS.clockSkewSeconds)
    return { ok: false, reason: "invalid_permit", request, permitId };
  if (now >= request.expiresAt)
    return { ok: false, reason: "permit_expired", request, permitId };
  if (!signatures.operator)
    return { ok: false, reason: "invalid_signature", request, permitId };
  if (!signatures.presentation)
    return { ok: false, reason: "invalid_presentation", request, permitId };
  return { ok: true, request, permitId };
}

/** Strict shape check for agent state from a trusted reader. */
export function isAgentStateEvidence(value: unknown): value is AgentStateEvidence {
  if (
    !record(value) ||
    !exactKeys(value, [
      "cluster",
      "genesisHash",
      "coreProgram",
      "agentRegistryProgram",
      "agentCollection",
      "agent",
      "agentAccount",
      "owner",
      "cachedOwner",
      "agentWallet",
      "agentWalletStatus",
      "readContextSlot",
    ])
  )
    return false;
  if (
    value.cluster !== AGENT_PERMIT_NETWORK.cluster ||
    value.genesisHash !== AGENT_PERMIT_NETWORK.genesisHash ||
    value.coreProgram !== AGENT_PERMIT_NETWORK.coreProgram ||
    value.agentRegistryProgram !== AGENT_PERMIT_NETWORK.agentRegistryProgram ||
    value.agentCollection !== AGENT_PERMIT_NETWORK.agentCollection ||
    !address(value.agent) ||
    !address(value.agentAccount) ||
    !address(value.owner) ||
    !address(value.cachedOwner) ||
    (value.agentWallet !== null && !address(value.agentWallet)) ||
    !integer(value.readContextSlot, 0, Number.MAX_SAFE_INTEGER)
  )
    return false;
  const expected: AgentWalletStatus =
    value.cachedOwner !== value.owner
      ? "stale"
      : value.agentWallet === null
        ? "unbound"
        : "bound";
  return value.agentWalletStatus === expected;
}

function agentStateReason(
  reason: unknown,
): "wrong_cluster" | "agent_missing" | "agent_unregistered" | "agent_invalid" {
  return reason === "wrong_cluster" ||
    reason === "agent_missing" ||
    reason === "agent_unregistered"
    ? reason
    : "agent_invalid";
}

/**
 * Evaluates a permit at settlement against agent state and operator evidence read after the
 * precheck. Pass a clock value sampled after those reads complete.
 */
export function evaluateAgentPermit(
  input: AgentPermitEvaluationInput,
): AgentPermitResult {
  const now = settlementClock(input.nowSeconds);
  const precheck = precheckAgentPermit(input);
  const base: AgentPermitResultBase = {
    permitId: precheck.permitId,
    request: precheck.request,
    evaluatedAt: now,
    expiresAt: precheck.request?.expiresAt ?? null,
    agentState: null,
    policy: null,
  };
  const deny = (reason: AgentPermitDenyReason): AgentPermitResult => ({
    ...base,
    decision: "deny",
    reason,
  });
  if (!precheck.ok) return deny(precheck.reason);
  const { request } = precheck;

  const state: unknown = input.agentState;
  if (!record(state)) return deny("agent_invalid");
  if (state.status === "unavailable")
    return { ...base, decision: "unavailable", reason: "agent_unavailable" };
  if (state.status !== "available") return deny(agentStateReason(state.reason));
  if (!isAgentStateEvidence(state.evidence) || state.evidence.agent !== request.agent)
    return deny("agent_invalid");
  const evidence = state.evidence;
  base.agentState = evidence;
  if (evidence.owner !== request.operator) return deny("owner_changed");
  if (evidence.agentWalletStatus === "stale") return deny("agent_wallet_stale");
  if (evidence.agentWalletStatus === "unbound") return deny("agent_wallet_unbound");
  if (evidence.agentWallet !== request.agentWallet)
    return deny("agent_wallet_changed");

  let policy: PolicyResult;
  try {
    policy = evaluatePolicy(request.policy, input.operatorEvidence, now);
  } catch {
    return deny("invalid_evidence");
  }
  base.policy = policy;
  if (policy.decision === "unavailable")
    return { ...base, decision: "unavailable", reason: "state_unavailable" };
  if (policy.decision === "deny") {
    const reason = policy.reason;
    return deny(
      reason === "score_below_minimum" ||
        reason === "verification_stale" ||
        reason === "attestation_required"
        ? reason
        : "invalid_evidence",
    );
  }
  if (policy.evidence.identity.walletPubkey !== request.operator)
    return deny("invalid_evidence");
  base.expiresAt = Math.min(request.expiresAt, policy.expiresAt);
  if (now >= base.expiresAt) return deny("permit_expired");
  return { ...base, decision: "allow", reason: "accepted" };
}

function transactionSignature(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 64 || value.length > 88)
    return false;
  const bytes = base58Decode(value);
  return bytes !== null && bytes.length === 64 && base58Encode(bytes) === value;
}

function jsonRecord(input: unknown): Record<string, unknown> | null {
  let value: unknown = input;
  if (typeof input === "string") {
    if (input.length > 1024) return null;
    try {
      value = JSON.parse(input);
    } catch {
      return null;
    }
  }
  return record(value) ? value : null;
}

/** Serializes the approval that the signing page hands to the agent. */
export function encodeAgentPermitApproval(
  approval: Omit<AgentPermitApproval, "version">,
): string {
  const value = parseAgentPermitApproval({ version: 1, ...approval });
  if (!value) throw new AgentPermitValidationError("approval");
  return JSON.stringify({
    version: 1,
    permitId: value.permitId,
    operatorSignature: value.operatorSignature,
    verifiedTransaction: value.verifiedTransaction,
  });
}

export function parseAgentPermitApproval(
  input: unknown,
): AgentPermitApproval | null {
  const value = jsonRecord(input);
  if (
    !value ||
    !exactKeys(value, ["version", "permitId", "operatorSignature", "verifiedTransaction"]) ||
    value.version !== 1 ||
    typeof value.permitId !== "string" ||
    !HEX64.test(value.permitId) ||
    typeof value.operatorSignature !== "string" ||
    !HEX128.test(value.operatorSignature) ||
    !transactionSignature(value.verifiedTransaction)
  )
    return null;
  return {
    version: 1,
    permitId: value.permitId,
    operatorSignature: value.operatorSignature,
    verifiedTransaction: value.verifiedTransaction,
  };
}

/** Serializes the bundle that the agent sends to the consumer. */
export function encodeAgentPermitSettlement(
  bundle: Omit<AgentPermitSettlementBundle, "version">,
): string {
  const value = parseAgentPermitSettlement({ version: 1, ...bundle });
  if (!value) throw new AgentPermitValidationError("settlement");
  return JSON.stringify({
    version: 1,
    nonce: value.nonce,
    operatorSignature: value.operatorSignature,
    presentationSignature: value.presentationSignature,
    verifiedTransaction: value.verifiedTransaction,
  });
}

export function parseAgentPermitSettlement(
  input: unknown,
): AgentPermitSettlementBundle | null {
  const value = jsonRecord(input);
  if (
    !value ||
    !exactKeys(value, [
      "version",
      "nonce",
      "operatorSignature",
      "presentationSignature",
      "verifiedTransaction",
    ]) ||
    value.version !== 1 ||
    !digestHex(value.nonce) ||
    typeof value.operatorSignature !== "string" ||
    !HEX128.test(value.operatorSignature) ||
    typeof value.presentationSignature !== "string" ||
    !HEX128.test(value.presentationSignature) ||
    !transactionSignature(value.verifiedTransaction)
  )
    return null;
  return {
    version: 1,
    nonce: value.nonce,
    operatorSignature: value.operatorSignature,
    presentationSignature: value.presentationSignature,
    verifiedTransaction: value.verifiedTransaction,
  };
}

function base64UrlEncode(text: string): string {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): string | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    return atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  } catch {
    return null;
  }
}

/** URL fragment for the signing page, without the leading `#`. */
export function encodeAgentPermitFragment(request: AgentPermitRequest): string {
  return `request=${base64UrlEncode(renderAgentPermitMessage(request))}`;
}

/** Parses a `request=` fragment. Returns null for anything else. */
export function parseAgentPermitFragment(
  fragment: string,
): { request: AgentPermitRequest; message: string } | null {
  const body = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  if (!body.startsWith("request=") || body.length > 8192) return null;
  const message = base64UrlDecode(body.slice("request=".length));
  if (message === null) return null;
  try {
    return { request: parseAgentPermitMessage(message), message };
  } catch {
    return null;
  }
}
