/** Pure policy evaluation. RPC evidence must come from a trusted account reader. */
export interface PolicyRequest {
  id: string;
  version: 1;
  minTrustScore: number;
  maxVerificationAgeSeconds: number;
  maxEvaluationAgeSeconds: number;
  requiredAssurance: "browser_unattested";
  uniquenessRequirement: "allow_unmeasured";
  requireAttestation: boolean;
  cluster: "devnet";
}

export type PolicyRequestInput = Omit<
  PolicyRequest,
  "maxEvaluationAgeSeconds" | "requireAttestation"
> &
  Partial<
    Pick<PolicyRequest, "maxEvaluationAgeSeconds" | "requireAttestation">
  >;

export interface PolicyProgramIds {
  anchor: string;
  verifier: string;
  registry: string;
  sas: string;
  credential: string;
  schema: string;
}

export const POLICY_NETWORK = Object.freeze({
  genesisHash: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  programIds: Object.freeze({
    anchor: "GZYwTp2ozeuRA5Gof9vs4ya961aANcJBdUzB7LN6q4b2",
    verifier: "4F97jNoxQzT2qRbkWpW3ztC3Nz2TtKj3rnKG8ExgnrfV",
    registry: "6VBs3zr9KrfFPGd6j7aGBPQWwZa5tajVfA7HN6MMV9VW",
    sas: "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG",
    credential: "AMBtabCgRFwGLjoZ21Z2LhSKJ6c47NckxUkMogJ3Lpuw",
    schema: "5LNc7syFW7USPLveVLcNcjjY1xqS7QTXVjHZ7CQCbAMQ",
  } satisfies PolicyProgramIds),
});

export type PolicyAttestation =
  | {
      status: "present";
      address: string;
      readContextSlot: number;
      expiresAt: number | null;
    }
  | { status: "missing" | "invalid" | "unavailable" };

export interface PolicyEvidence {
  cluster: "devnet";
  genesisHash: string;
  programIds: PolicyProgramIds;
  assuranceTier: "browser_unattested";
  uniquenessStatus: "unmeasured";
  readContextSlot: number;
  identity: {
    walletPubkey: string;
    identityPda: string;
    creationTimestamp: number;
    lastVerificationTimestamp: number;
    verificationCount: number;
    trustScore: number;
    currentCommitment: string;
    projectionVersion: number;
    lastResetTimestamp: number;
    lastRebaselineTimestamp: number;
    mint: string;
  };
  transaction: {
    signature: string;
    slot: number;
    blockTime: number;
    commitment: string;
    kind: "mint" | "update" | "rebaseline";
  };
  attestation: PolicyAttestation;
}

export type PolicyEvidenceReadResult =
  | { status: "available"; evidence: PolicyEvidence }
  | { status: "invalid" | "unavailable"; reason: string };

export type PolicyReason =
  | "accepted"
  | "score_below_minimum"
  | "verification_stale"
  | "attestation_required"
  | "unsupported_policy"
  | "unsupported_assurance"
  | "unsupported_uniqueness"
  | "invalid_evidence"
  | "state_unavailable";

interface PolicyResultBase {
  policyId: string;
  policyVersion: 1;
  requirements: PolicyRequest;
  evaluatedAt: number;
  expiresAt: number;
  evidenceTimestamp: number | null;
  evaluatedAgeSeconds: number | null;
}

export type PolicyResult = PolicyResultBase &
  (
    | { decision: "allow"; reason: "accepted"; evidence: PolicyEvidence }
    | {
        decision: "deny";
        reason: Exclude<PolicyReason, "accepted" | "state_unavailable">;
        evidence: PolicyEvidence | null;
      }
    | {
        decision: "unavailable";
        reason: "state_unavailable";
        evidence: PolicyEvidence | null;
      }
  );

export class PolicyValidationError extends Error {
  constructor(public readonly reason: PolicyReason) {
    super(`Invalid verification policy: ${reason}`);
    this.name = "PolicyValidationError";
  }
}

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

function integer(
  value: unknown,
  minimum = 0,
  maximum = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

const REQUEST_KEYS = [
  "id",
  "version",
  "minTrustScore",
  "maxVerificationAgeSeconds",
  "maxEvaluationAgeSeconds",
  "requiredAssurance",
  "uniquenessRequirement",
  "requireAttestation",
  "cluster",
] as const;

/** Canonical defaults are applied before a request leaves the consumer. */
export function normalizePolicyRequest(
  input?: unknown,
  legacyMinTrustScore?: number,
): PolicyRequest {
  if (
    legacyMinTrustScore !== undefined &&
    !integer(legacyMinTrustScore, 0, 10000)
  ) {
    throw new PolicyValidationError("unsupported_policy");
  }
  const value: unknown =
    input === undefined
      ? {
          id: "entros-verify-default",
          version: 1,
          minTrustScore: legacyMinTrustScore ?? 0,
          maxVerificationAgeSeconds: 86400,
          requiredAssurance: "browser_unattested",
          uniquenessRequirement: "allow_unmeasured",
          cluster: "devnet",
        }
      : input;
  if (
    !record(value) ||
    Object.keys(value).some(
      (key) => !REQUEST_KEYS.includes(key as (typeof REQUEST_KEYS)[number]),
    )
  ) {
    throw new PolicyValidationError("unsupported_policy");
  }
  if (value.requiredAssurance !== "browser_unattested")
    throw new PolicyValidationError("unsupported_assurance");
  if (value.uniquenessRequirement !== "allow_unmeasured")
    throw new PolicyValidationError("unsupported_uniqueness");
  if (
    typeof value.id !== "string" ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(value.id) ||
    value.version !== 1 ||
    !integer(value.minTrustScore, 0, 10000) ||
    !integer(value.maxVerificationAgeSeconds, 1, 31536000) ||
    !integer(
      value.maxEvaluationAgeSeconds === undefined
        ? 90
        : value.maxEvaluationAgeSeconds,
      1,
      90,
    ) ||
    (value.requireAttestation !== undefined &&
      typeof value.requireAttestation !== "boolean") ||
    value.cluster !== "devnet" ||
    (legacyMinTrustScore !== undefined &&
      value.minTrustScore !== legacyMinTrustScore)
  ) {
    throw new PolicyValidationError("unsupported_policy");
  }
  return {
    id: value.id,
    version: 1,
    minTrustScore: value.minTrustScore,
    maxVerificationAgeSeconds: value.maxVerificationAgeSeconds,
    maxEvaluationAgeSeconds: (value.maxEvaluationAgeSeconds ?? 90) as number,
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    requireAttestation: value.requireAttestation === true,
    cluster: "devnet",
  };
}

export function encodePolicyRequest(request: PolicyRequest): string {
  return JSON.stringify(normalizePolicyRequest(request));
}

/** Legacy callers require a real attestation because their result type cannot represent absence. */
export function parsePolicyParameters(
  params: URLSearchParams,
  legacyMinTrustScore?: number,
): { policy: PolicyRequest; negotiated: boolean } {
  for (const key of ["policy", "policy_version", "min_trust_score"]) {
    if (params.getAll(key).length > 1)
      throw new PolicyValidationError("unsupported_policy");
  }
  const floorText = params.get("min_trust_score");
  if (floorText !== null) {
    if (
      !/^(0|[1-9][0-9]{0,4})$/.test(floorText) ||
      !integer(Number(floorText), 0, 10000) ||
      (legacyMinTrustScore !== undefined &&
        legacyMinTrustScore !== Number(floorText))
    )
      throw new PolicyValidationError("unsupported_policy");
    legacyMinTrustScore = Number(floorText);
  }
  const encoded = params.get("policy");
  const marker = params.get("policy_version");
  if (encoded === null && marker === null) {
    return {
      negotiated: false,
      policy: {
        ...normalizePolicyRequest(undefined, legacyMinTrustScore),
        requireAttestation: true,
      },
    };
  }
  if (marker !== "1" || encoded === null || encoded.length > 2048)
    throw new PolicyValidationError("unsupported_policy");
  let raw: unknown;
  try {
    raw = JSON.parse(encoded);
  } catch {
    throw new PolicyValidationError("unsupported_policy");
  }
  const policy = normalizePolicyRequest(raw, legacyMinTrustScore);
  if (encodePolicyRequest(policy) !== encoded)
    throw new PolicyValidationError("unsupported_policy");
  return { negotiated: true, policy };
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Bytes(value: unknown, expected: number): value is string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > expected * 2
  )
    return false;
  let number = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) return false;
    number = number * 58n + BigInt(digit);
  }
  let bytes = 0;
  while (number > 0n) {
    bytes++;
    number >>= 8n;
  }
  let zeros = 0;
  while (value[zeros] === "1") zeros++;
  return bytes + zeros === expected;
}

function commitment(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{64}$/.test(value) &&
    !/^0+$/.test(value)
  );
}

export function isPolicyAttestation(
  value: unknown,
): value is PolicyAttestation {
  if (!record(value)) return false;
  if (value.status === "present") {
    return (
      exactKeys(value, ["status", "address", "readContextSlot", "expiresAt"]) &&
      base58Bytes(value.address, 32) &&
      integer(value.readContextSlot) &&
      (value.expiresAt === null || integer(value.expiresAt, 1))
    );
  }
  return (
    exactKeys(value, ["status"]) &&
    ["missing", "invalid", "unavailable"].includes(String(value.status))
  );
}

export function isPolicyEvidence(value: unknown): value is PolicyEvidence {
  if (
    !record(value) ||
    !exactKeys(value, [
      "cluster",
      "genesisHash",
      "programIds",
      "assuranceTier",
      "uniquenessStatus",
      "readContextSlot",
      "identity",
      "transaction",
      "attestation",
    ])
  )
    return false;
  if (
    value.cluster !== "devnet" ||
    value.genesisHash !== POLICY_NETWORK.genesisHash ||
    value.assuranceTier !== "browser_unattested" ||
    value.uniquenessStatus !== "unmeasured" ||
    !integer(value.readContextSlot)
  )
    return false;
  const programs = value.programIds;
  if (
    !record(programs) ||
    !exactKeys(programs, Object.keys(POLICY_NETWORK.programIds)) ||
    Object.entries(POLICY_NETWORK.programIds).some(
      ([key, id]) => programs[key] !== id,
    )
  )
    return false;
  const identity = value.identity;
  const transaction = value.transaction;
  if (
    !record(identity) ||
    !exactKeys(identity, [
      "walletPubkey",
      "identityPda",
      "creationTimestamp",
      "lastVerificationTimestamp",
      "verificationCount",
      "trustScore",
      "currentCommitment",
      "projectionVersion",
      "lastResetTimestamp",
      "lastRebaselineTimestamp",
      "mint",
    ]) ||
    !base58Bytes(identity.walletPubkey, 32) ||
    !base58Bytes(identity.identityPda, 32) ||
    !base58Bytes(identity.mint, 32) ||
    !integer(identity.creationTimestamp, 1) ||
    !integer(identity.lastVerificationTimestamp, identity.creationTimestamp) ||
    !integer(identity.verificationCount, 0, 0xffffffff) ||
    !integer(identity.trustScore, 0, 10000) ||
    !commitment(identity.currentCommitment) ||
    !integer(identity.projectionVersion, 0, 2) ||
    !integer(identity.lastResetTimestamp) ||
    !integer(identity.lastRebaselineTimestamp)
  )
    return false;
  if (
    !record(transaction) ||
    !exactKeys(transaction, [
      "signature",
      "slot",
      "blockTime",
      "commitment",
      "kind",
    ]) ||
    !base58Bytes(transaction.signature, 64) ||
    !integer(transaction.slot) ||
    !integer(transaction.blockTime, identity.creationTimestamp) ||
    !commitment(transaction.commitment) ||
    !["mint", "update", "rebaseline"].includes(String(transaction.kind))
  )
    return false;
  return isPolicyAttestation(value.attestation);
}

/** Evaluates application requirements. It does not authenticate browser-supplied evidence. */
export function evaluatePolicy(
  request: PolicyRequest,
  observation: PolicyEvidenceReadResult,
  nowSeconds: number,
): PolicyResult {
  const requirements = normalizePolicyRequest(request);
  if (
    !integer(nowSeconds, 1) ||
    nowSeconds > Number.MAX_SAFE_INTEGER - 31536000
  )
    throw new PolicyValidationError("invalid_evidence");
  const base: PolicyResultBase = {
    policyId: requirements.id,
    policyVersion: 1,
    requirements,
    evaluatedAt: nowSeconds,
    expiresAt: nowSeconds,
    evidenceTimestamp: null,
    evaluatedAgeSeconds: null,
  };
  if (record(observation) && observation.status === "unavailable")
    return {
      ...base,
      decision: "unavailable",
      reason: "state_unavailable",
      evidence: null,
    };
  if (
    !record(observation) ||
    observation.status !== "available" ||
    !isPolicyEvidence(observation.evidence)
  ) {
    return {
      ...base,
      decision: "deny",
      reason: "invalid_evidence",
      evidence: null,
    };
  }
  const evidence = observation.evidence;
  const { identity, transaction, attestation } = evidence;
  const deny = (
    reason: Exclude<PolicyReason, "accepted" | "state_unavailable">,
  ): PolicyResult => ({ ...base, decision: "deny", reason, evidence });
  const freshMint =
    transaction.kind === "mint" &&
    identity.verificationCount === 0 &&
    identity.trustScore === 0 &&
    identity.creationTimestamp === transaction.blockTime &&
    identity.lastVerificationTimestamp === transaction.blockTime &&
    identity.lastResetTimestamp === 0 &&
    identity.lastRebaselineTimestamp === 0;
  if (
    (identity.verificationCount === 0 && !freshMint) ||
    identity.currentCommitment !== transaction.commitment ||
    identity.lastResetTimestamp >= transaction.blockTime ||
    identity.lastResetTimestamp > identity.lastVerificationTimestamp ||
    identity.lastRebaselineTimestamp > identity.lastVerificationTimestamp ||
    identity.lastRebaselineTimestamp > transaction.blockTime ||
    identity.lastVerificationTimestamp > nowSeconds ||
    transaction.blockTime > nowSeconds ||
    evidence.readContextSlot < transaction.slot ||
    attestation.status === "invalid" ||
    (attestation.status === "present" &&
      (attestation.readContextSlot < transaction.slot ||
        (attestation.expiresAt !== null &&
          attestation.expiresAt <= nowSeconds)))
  ) {
    return deny("invalid_evidence");
  }
  base.evidenceTimestamp = Math.min(
    identity.lastVerificationTimestamp,
    transaction.blockTime,
  );
  base.evaluatedAgeSeconds = nowSeconds - base.evidenceTimestamp;
  base.expiresAt = Math.min(
    base.evidenceTimestamp + requirements.maxVerificationAgeSeconds,
    nowSeconds + requirements.maxEvaluationAgeSeconds,
  );
  if (
    requirements.requireAttestation &&
    attestation.status === "present" &&
    attestation.expiresAt !== null
  )
    base.expiresAt = Math.min(base.expiresAt, attestation.expiresAt);
  if (identity.trustScore < requirements.minTrustScore)
    return deny("score_below_minimum");
  if (nowSeconds >= base.expiresAt) return deny("verification_stale");
  if (requirements.requireAttestation && attestation.status === "missing")
    return deny("attestation_required");
  if (requirements.requireAttestation && attestation.status === "unavailable")
    return {
      ...base,
      decision: "unavailable",
      reason: "state_unavailable",
      evidence,
    };
  return { ...base, decision: "allow", reason: "accepted", evidence };
}

export interface PolicyWireResult {
  policy_id: string;
  policy_version: 1;
  decision: PolicyResult["decision"];
  reason: PolicyReason;
  requirements: PolicyRequest;
  evaluated_at: number;
  expires_at: number;
  evidence_timestamp: number | null;
  evaluated_age_seconds: number | null;
  wallet_pubkey: string | null;
  identity_pda: string | null;
  verified_transaction: {
    signature: string;
    slot: number;
    block_time: number;
    commitment: string;
    kind: "mint" | "update" | "rebaseline";
  } | null;
  verification_timestamp: number | null;
  trust_score: number | null;
  anchor_created_at: number | null;
  verification_count: number | null;
  current_commitment: string | null;
  projection_version: number | null;
  last_reset_timestamp: number | null;
  last_rebaseline_timestamp: number | null;
  mint: string | null;
  uniqueness_status: "unmeasured" | null;
  assurance_tier: "browser_unattested" | null;
  cluster: "devnet" | null;
  genesis_hash: string | null;
  program_ids: PolicyProgramIds | null;
  read_context_slot: number | null;
  attestation:
    | {
        status: "present";
        address: string;
        read_context_slot: number;
        expires_at: number | null;
      }
    | { status: "missing" | "invalid" | "unavailable" }
    | null;
}

export function policyResultToWire(result: PolicyResult): PolicyWireResult {
  const e = result.evidence;
  return {
    policy_id: result.policyId,
    policy_version: 1,
    decision: result.decision,
    reason: result.reason,
    requirements: result.requirements,
    evaluated_at: result.evaluatedAt,
    expires_at: result.expiresAt,
    evidence_timestamp: result.evidenceTimestamp,
    evaluated_age_seconds: result.evaluatedAgeSeconds,
    wallet_pubkey: e?.identity.walletPubkey ?? null,
    identity_pda: e?.identity.identityPda ?? null,
    verified_transaction: e
      ? {
          signature: e.transaction.signature,
          slot: e.transaction.slot,
          block_time: e.transaction.blockTime,
          commitment: e.transaction.commitment,
          kind: e.transaction.kind,
        }
      : null,
    verification_timestamp: e?.identity.lastVerificationTimestamp ?? null,
    trust_score: e?.identity.trustScore ?? null,
    anchor_created_at: e?.identity.creationTimestamp ?? null,
    verification_count: e?.identity.verificationCount ?? null,
    current_commitment: e?.identity.currentCommitment ?? null,
    projection_version: e?.identity.projectionVersion ?? null,
    last_reset_timestamp: e?.identity.lastResetTimestamp ?? null,
    last_rebaseline_timestamp: e?.identity.lastRebaselineTimestamp ?? null,
    mint: e?.identity.mint ?? null,
    uniqueness_status: e?.uniquenessStatus ?? null,
    assurance_tier: e?.assuranceTier ?? null,
    cluster: e?.cluster ?? null,
    genesis_hash: e?.genesisHash ?? null,
    program_ids: e?.programIds ?? null,
    read_context_slot: e?.readContextSlot ?? null,
    attestation: e
      ? e.attestation.status === "present"
        ? {
            status: "present",
            address: e.attestation.address,
            read_context_slot: e.attestation.readContextSlot,
            expires_at: e.attestation.expiresAt,
          }
        : e.attestation
      : null,
  };
}

/** Recompute every derived field before accepting a remote decision. */
export function parsePolicyWireResult(input: unknown): PolicyResult | null {
  if (!record(input) || !integer(input.evaluated_at, 1)) return null;
  try {
    const requirements = normalizePolicyRequest(input.requirements);
    let observation: PolicyEvidenceReadResult;
    if (input.wallet_pubkey === null) {
      observation =
        input.decision === "unavailable"
          ? { status: "unavailable", reason: "state_unavailable" }
          : { status: "invalid", reason: "invalid_evidence" };
    } else {
      const tx = input.verified_transaction;
      const sas = input.attestation;
      if (!record(tx) || !record(sas)) return null;
      const evidence: unknown = {
        cluster: input.cluster,
        genesisHash: input.genesis_hash,
        programIds: input.program_ids,
        assuranceTier: input.assurance_tier,
        uniquenessStatus: input.uniqueness_status,
        readContextSlot: input.read_context_slot,
        identity: {
          walletPubkey: input.wallet_pubkey,
          identityPda: input.identity_pda,
          creationTimestamp: input.anchor_created_at,
          lastVerificationTimestamp: input.verification_timestamp,
          verificationCount: input.verification_count,
          trustScore: input.trust_score,
          currentCommitment: input.current_commitment,
          projectionVersion: input.projection_version,
          lastResetTimestamp: input.last_reset_timestamp,
          lastRebaselineTimestamp: input.last_rebaseline_timestamp,
          mint: input.mint,
        },
        transaction: {
          signature: tx.signature,
          slot: tx.slot,
          blockTime: tx.block_time,
          commitment: tx.commitment,
          kind: tx.kind,
        },
        attestation:
          sas.status === "present"
            ? {
                status: "present",
                address: sas.address,
                readContextSlot: sas.read_context_slot,
                expiresAt: sas.expires_at,
              }
            : { status: sas.status },
      };
      if (!isPolicyEvidence(evidence)) return null;
      observation = { status: "available", evidence };
    }
    const result = evaluatePolicy(
      requirements,
      observation,
      input.evaluated_at,
    );
    return canonicalEqual(input, policyResultToWire(result)) ? result : null;
  } catch {
    return null;
  }
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (!record(left) || !record(right)) return false;
  return (
    exactKeys(left, Object.keys(right)) &&
    Object.keys(right).every((key) => canonicalEqual(left[key], right[key]))
  );
}

export function isPolicyReason(value: unknown): value is PolicyReason {
  return (
    typeof value === "string" &&
    [
      "accepted",
      "score_below_minimum",
      "verification_stale",
      "attestation_required",
      "unsupported_policy",
      "unsupported_assurance",
      "unsupported_uniqueness",
      "invalid_evidence",
      "state_unavailable",
    ].includes(value)
  );
}

export function validatePolicyVerifiedPayload(
  payload: unknown,
  requestedPolicy: PolicyRequest,
  nowSeconds: number,
):
  | { ok: true; result: PolicyResult & { decision: "allow" } }
  | { ok: false; reason: PolicyReason } {
  if (!record(payload)) return { ok: false, reason: "invalid_evidence" };
  if (!Object.prototype.hasOwnProperty.call(payload, "policy"))
    return { ok: false, reason: "unsupported_policy" };
  const result = parsePolicyWireResult(payload.policy);
  if (
    !result ||
    !canonicalEqual(
      result.requirements,
      normalizePolicyRequest(requestedPolicy),
    )
  )
    return { ok: false, reason: "invalid_evidence" };
  if (result.decision !== "allow") return { ok: false, reason: result.reason };
  if (
    !integer(nowSeconds, 1) ||
    result.evaluatedAt > nowSeconds ||
    nowSeconds >= result.expiresAt
  )
    return { ok: false, reason: "verification_stale" };
  const current = evaluatePolicy(
    requestedPolicy,
    { status: "available", evidence: result.evidence },
    nowSeconds,
  );
  if (current.decision !== "allow")
    return { ok: false, reason: current.reason };
  const e = result.evidence;
  const address =
    e.attestation.status === "present" ? e.attestation.address : null;
  if (
    payload.wallet_pubkey !== e.identity.walletPubkey ||
    payload.trust_score !== e.identity.trustScore ||
    payload.cluster !== e.cluster ||
    payload.tx_sig !== e.transaction.signature ||
    payload.attestation_pda !== address
  )
    return { ok: false, reason: "invalid_evidence" };
  return { ok: true, result };
}
