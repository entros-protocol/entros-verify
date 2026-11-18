/**
 * Standalone reference consumer built strictly against published
 * `@entros/pulse-sdk@4.17.0` and `@entros/verify@0.5.0` exports.
 *
 * Implements:
 *   1. Warm policy reuse before capture (0 SOL, zero rounds, preserved original verifiedAt)
 *   2. Integrator Policy v1 protected action consumer (origin allowlist, one-use challenges,
 *      atomic replay defense, mint/update/reset/rebaseline evidence)
 *   3. Agent Operator Permit pause-and-approve workflow (subject owner + actor agent,
 *      0-RPC precheck, live settlement checks, post-transfer refusal)
 *   4. Realms voter-weight pre-flight and atomic transaction verification
 *   5. Cold vs warm latency and failure/abandonment telemetry
 */

import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import {
  findLatestVerificationTransaction,
  readAgentState,
  readIntegratorEvidence,
} from "@entros/pulse-sdk";
import {
  evaluatePolicy,
  normalizePolicyRequest,
  policyResultToWire,
} from "@entros/verify/policy";
import {
  agentPermitId,
  createAgentPermitRequest,
  encodeAgentPermitFragment,
  evaluateAgentPermit,
  parseAgentPermitSettlement,
  precheckAgentPermit,
  renderAgentPermitMessage,
} from "@entros/verify/agent-permit";
import {
  buildAtomicRealmsGovernanceTransaction,
  deriveIdentityPda,
  parseIdentityForRealms,
  preflightRealmsVoterWeight,
  verifyAtomicRealmsGovernanceTransaction,
} from "./realms-check.mjs";
import { ReferenceTelemetryCollector } from "./telemetry.mjs";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_CHALLENGE_LIFETIME_SECONDS = 120;
const MAX_PENDING = 1000;
const ALLOWED_RESOURCE = "reference-vault";
const LOOPBACK_AUDIENCE =
  /^http:\/\/127\.0\.0\.1(?::[1-9][0-9]{0,4})?\/[a-z0-9-]+$/;

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function decodeCanonicalWallet(walletPubkey) {
  if (typeof walletPubkey !== "string") throw new Error("Invalid wallet");
  const key = new PublicKey(walletPubkey);
  if (key.toBase58() !== walletPubkey) throw new Error("Non-canonical wallet");
  return key.toBytes();
}

export function canonicalAction(value) {
  if (
    !exactKeys(value, ["kind", "resource", "durationSeconds"]) ||
    value.kind !== "grant_access" ||
    value.resource !== ALLOWED_RESOURCE ||
    !Number.isSafeInteger(value.durationSeconds) ||
    value.durationSeconds < 1 ||
    value.durationSeconds > 3600
  ) {
    throw new Error("Invalid protected action");
  }
  return Object.freeze({
    kind: value.kind,
    resource: value.resource,
    durationSeconds: value.durationSeconds,
  });
}

export function permitActionDescriptor(agent, action) {
  const checked = canonicalAction(action);
  const record = JSON.stringify({
    domain: "entros-reference-consumer-agent-action",
    version: 1,
    agent,
    action: checked,
  });
  return {
    label: `Grant ${checked.resource} for ${checked.durationSeconds}s`,
    sha256: createHash("sha256").update(record, "utf8").digest("hex"),
  };
}

export function actionChallengeSigningBytes(challenge) {
  if (
    !exactKeys(challenge, [
      "version",
      "wallet",
      "action",
      "audience",
      "nonce",
      "issuedAt",
      "expiresAt",
    ]) ||
    challenge.version !== 1 ||
    typeof challenge.wallet !== "string" ||
    typeof challenge.audience !== "string" ||
    typeof challenge.nonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(challenge.nonce) ||
    !Number.isSafeInteger(challenge.issuedAt) ||
    !Number.isSafeInteger(challenge.expiresAt) ||
    challenge.issuedAt < 1 ||
    challenge.expiresAt <= challenge.issuedAt
  ) {
    throw new Error("Invalid action challenge");
  }
  return Buffer.from(
    JSON.stringify({
      domain: "entros-reference-consumer-action",
      version: challenge.version,
      wallet: challenge.wallet,
      action: canonicalAction(challenge.action),
      audience: challenge.audience,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
    }),
    "utf8",
  );
}

/**
 * Evaluates warm policy reuse using only published `@entros/pulse-sdk@4.17.0`
 * and `@entros/verify@0.5.0` exports. Preserves the original `verifiedAt`
 * timestamp and charges 0 SOL / zero capture rounds when existing evidence
 * satisfies the application policy.
 */
export async function checkWarmPolicyReuse({
  walletPubkey,
  policy,
  connection,
  nowSeconds,
  candidateSignatures = [],
  requireLegacyAttestation = false,
}) {
  const normalized = normalizePolicyRequest(policy);
  const effectivePolicy =
    requireLegacyAttestation && policy === undefined
      ? { ...normalized, requireAttestation: true }
      : normalized;

  try {
    decodeCanonicalWallet(walletPubkey);
  } catch {
    return {
      status: "needs_capture",
      reason: "invalid_evidence",
      policy: null,
    };
  }

  let verifiedAt;
  try {
    const identityInfo = await connection.getAccountInfo(
      deriveIdentityPda(walletPubkey),
    );
    if (!identityInfo) {
      return {
        status: "needs_capture",
        reason: "evidence_not_found",
        policy: null,
      };
    }
    const parsedIdentity = parseIdentityForRealms(identityInfo);
    if (!parsedIdentity || parsedIdentity.owner !== walletPubkey) {
      return {
        status: "needs_capture",
        reason: "invalid_evidence",
        policy: null,
      };
    }
    verifiedAt = parsedIdentity.lastVerificationTimestamp;
  } catch {
    return {
      status: "needs_capture",
      reason: "state_unavailable",
      policy: null,
    };
  }

  const lookup = await findLatestVerificationTransaction({
    walletPubkey,
    connection,
    verifiedAt,
    candidateSignatures,
  });

  if (lookup.status === "none") {
    return {
      status: "needs_capture",
      reason: "evidence_not_found",
      policy: null,
    };
  }
  if (lookup.status === "unavailable") {
    return {
      status: "needs_capture",
      reason: "state_unavailable",
      policy: null,
    };
  }
  if (lookup.status !== "found") {
    return {
      status: "needs_capture",
      reason: "invalid_evidence",
      policy: null,
    };
  }

  const readClock = () =>
    typeof nowSeconds === "function" ? nowSeconds() : nowSeconds;

  let observation;
  try {
    observation = await readIntegratorEvidence({
      walletPubkey,
      transactionSignature: lookup.signature,
      connection,
      nowSeconds: readClock,
    });
  } catch {
    return {
      status: "needs_capture",
      reason: "state_unavailable",
      policy: null,
    };
  }

  const evaluatedNow = readClock();
  const result = evaluatePolicy(effectivePolicy, observation, evaluatedNow);

  if (
    result.evidence &&
    result.evidence.identity.walletPubkey !== walletPubkey
  ) {
    return {
      status: "needs_capture",
      reason: "invalid_evidence",
      policy: null,
    };
  }

  if (result.decision !== "allow") {
    return {
      status: "needs_capture",
      reason: result.reason,
      policy: result,
    };
  }

  return {
    status: "reused",
    feeLamports: 0,
    captureRounds: 0,
    verifiedAt: result.evidence.identity.lastVerificationTimestamp,
    verifiedTransaction: result.evidence.transaction.signature,
    attestationPda:
      result.evidence.attestation.status === "present"
        ? result.evidence.attestation.address
        : null,
    policy: result,
  };
}

export class ReferenceConsumerService {
  #policy;
  #agentPolicy;
  #actionAudience;
  #agentAudience;
  #allowedOrigins;
  #connection;
  #clock;
  #agentPermitLifetimeSeconds;
  #pendingActions = new Map();
  #pendingPermits = new Map();
  #executedActions = [];
  #telemetry;

  constructor({
    policy,
    agentPolicy = policy,
    actionAudience = "http://127.0.0.1:43211/action-settlements",
    agentAudience = "http://127.0.0.1:43211/agent-permit-settlements",
    allowedOrigins = ["http://127.0.0.1:43211"],
    connection,
    nowSeconds,
    agentPermitLifetimeSeconds = 600,
    telemetry = new ReferenceTelemetryCollector(),
  }) {
    if (
      typeof actionAudience !== "string" ||
      !LOOPBACK_AUDIENCE.test(actionAudience) ||
      typeof agentAudience !== "string" ||
      !LOOPBACK_AUDIENCE.test(agentAudience)
    ) {
      throw new Error("Only loopback reference consumer audiences are supported");
    }
    this.#policy = normalizePolicyRequest(policy);
    this.#agentPolicy = normalizePolicyRequest(agentPolicy);
    this.#actionAudience = actionAudience;
    this.#agentAudience = agentAudience;
    this.#allowedOrigins = new Set(allowedOrigins);
    this.#connection = connection;
    this.#clock = nowSeconds;
    this.#agentPermitLifetimeSeconds = agentPermitLifetimeSeconds;
    this.#telemetry = telemetry;
  }

  #now() {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < 1) {
      throw new Error("Invalid server clock");
    }
    return now;
  }

  #originAllowed(origin) {
    return typeof origin === "string" && this.#allowedOrigins.has(origin);
  }

  /** Checks whether existing devnet evidence already satisfies the policy before capture. */
  async checkWarmPolicy({
    walletPubkey,
    origin,
    candidateSignatures = [],
    requireLegacyAttestation = false,
  }) {
    if (origin !== undefined && !this.#originAllowed(origin)) {
      return { ok: false, reason: "origin_invalid" };
    }
    const result = await checkWarmPolicyReuse({
      walletPubkey,
      policy: this.#policy,
      connection: this.#connection,
      nowSeconds: () => this.#now(),
      candidateSignatures,
      requireLegacyAttestation,
    });
    if (result.status === "reused") {
      return {
        ok: true,
        status: "reused",
        feeLamports: 0,
        captureRounds: 0,
        verifiedAt: result.verifiedAt,
        verifiedTransaction: result.verifiedTransaction,
        attestationPda: result.attestationPda,
        policy: policyResultToWire(result.policy),
      };
    }
    return {
      ok: false,
      status: "needs_capture",
      reason: result.reason,
      policy: result.policy ? policyResultToWire(result.policy) : null,
    };
  }

  issueActionChallenge({ wallet, action, origin }) {
    if (!this.#originAllowed(origin)) {
      return { ok: false, reason: "origin_invalid" };
    }
    let checkedAction;
    try {
      decodeCanonicalWallet(wallet);
      checkedAction = canonicalAction(action);
    } catch {
      return { ok: false, reason: "invalid_request" };
    }
    const now = this.#now();
    for (const [nonce, entry] of this.#pendingActions) {
      if (entry.challenge.expiresAt <= now) this.#pendingActions.delete(nonce);
    }
    if (this.#pendingActions.size >= MAX_PENDING) {
      return { ok: false, reason: "capacity_reached" };
    }
    const challenge = Object.freeze({
      version: 1,
      wallet,
      action: checkedAction,
      audience: this.#actionAudience,
      nonce: randomBytes(32).toString("hex"),
      issuedAt: now,
      expiresAt: now + MAX_CHALLENGE_LIFETIME_SECONDS,
    });
    this.#pendingActions.set(challenge.nonce, {
      challenge,
      bytes: actionChallengeSigningBytes(challenge),
    });
    return { ok: true, challenge: structuredClone(challenge) };
  }

  async settleAction({ challenge, signature, verifiedTransaction, origin }) {
    if (!this.#originAllowed(origin)) {
      return { ok: false, reason: "origin_invalid" };
    }
    if (
      !exactKeys(challenge, [
        "version",
        "wallet",
        "action",
        "audience",
        "nonce",
        "issuedAt",
        "expiresAt",
      ])
    ) {
      return { ok: false, reason: "invalid_request" };
    }
    const pending = this.#pendingActions.get(challenge.nonce);
    if (!pending) return { ok: false, reason: "nonce_unavailable" };

    let bytes;
    try {
      bytes = actionChallengeSigningBytes(challenge);
    } catch {
      return { ok: false, reason: "invalid_request" };
    }
    if (!bytes.equals(pending.bytes)) {
      return { ok: false, reason: "challenge_mismatch" };
    }
    if (this.#now() >= pending.challenge.expiresAt) {
      this.#pendingActions.delete(challenge.nonce);
      return { ok: false, reason: "challenge_expired" };
    }
    if (typeof signature !== "string" || !/^[a-f0-9]{128}$/.test(signature)) {
      return { ok: false, reason: "invalid_signature" };
    }
    const publicKey = createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        decodeCanonicalWallet(pending.challenge.wallet),
      ]),
      format: "der",
      type: "spki",
    });
    if (!verify(null, bytes, publicKey, Buffer.from(signature, "hex"))) {
      return { ok: false, reason: "invalid_signature" };
    }
    if (
      typeof verifiedTransaction !== "string" ||
      verifiedTransaction.length < 64 ||
      verifiedTransaction.length > 88
    ) {
      return { ok: false, reason: "invalid_transaction" };
    }

    let observation;
    try {
      observation = await readIntegratorEvidence({
        walletPubkey: pending.challenge.wallet,
        transactionSignature: verifiedTransaction,
        connection: this.#connection,
        nowSeconds: () => this.#now(),
      });
    } catch {
      return { ok: false, reason: "state_unavailable" };
    }

    const now = this.#now();
    const policyResult = evaluatePolicy(this.#policy, observation, now);
    if (policyResult.decision !== "allow") {
      return { ok: false, reason: policyResult.reason };
    }
    if (
      policyResult.evidence.identity.walletPubkey !== pending.challenge.wallet ||
      policyResult.evidence.transaction.signature !== verifiedTransaction ||
      now >= policyResult.expiresAt
    ) {
      return { ok: false, reason: "invalid_evidence" };
    }
    if (now >= pending.challenge.expiresAt) {
      this.#pendingActions.delete(challenge.nonce);
      return { ok: false, reason: "challenge_expired" };
    }
    if (this.#pendingActions.get(pending.challenge.nonce) !== pending) {
      return { ok: false, reason: "nonce_unavailable" };
    }

    // Atomic single-use nonce consumption and action execution in one synchronous step.
    this.#pendingActions.delete(pending.challenge.nonce);
    const executed = Object.freeze({
      id: this.#executedActions.length + 1,
      flow: "protected_action",
      wallet: pending.challenge.wallet,
      ...pending.challenge.action,
      verifiedTransaction,
      verifiedAt: policyResult.evidence.identity.lastVerificationTimestamp,
      transactionKind: policyResult.evidence.transaction.kind,
      settledAt: now,
      policy: policyResultToWire(policyResult),
    });
    this.#executedActions.push(executed);
    return { ok: true, action: structuredClone(executed) };
  }

  /**
   * Agent Operator Permit pause-and-approve workflow:
   * reads live 8004 agent state, binds `subject` (owner) and `actor` (agent wallet),
   * and returns the permit request for owner approval.
   */
  async requestAgentPermit({ agent, action, origin }) {
    if (!this.#originAllowed(origin)) {
      return { ok: false, reason: "origin_invalid" };
    }
    let checkedAction;
    let actionMeta;
    try {
      checkedAction = canonicalAction(action);
      actionMeta = permitActionDescriptor(agent, checkedAction);
    } catch {
      return { ok: false, reason: "invalid_request" };
    }

    const now = this.#now();
    for (const [nonce, entry] of this.#pendingPermits) {
      if (entry.request.expiresAt <= now) this.#pendingPermits.delete(nonce);
    }
    if (this.#pendingPermits.size >= MAX_PENDING) {
      return { ok: false, reason: "capacity_reached" };
    }

    let state;
    try {
      state = await readAgentState({ agent, connection: this.#connection });
    } catch {
      return { ok: false, reason: "agent_unavailable" };
    }
    if (state?.status === "unavailable") {
      return { ok: false, reason: "agent_unavailable" };
    }
    if (state?.status !== "available") {
      return { ok: false, reason: state?.reason ?? "agent_invalid" };
    }
    const { evidence } = state;
    if (evidence.agent !== agent) return { ok: false, reason: "agent_invalid" };
    if (evidence.agentWalletStatus === "stale") {
      return { ok: false, reason: "agent_wallet_stale" };
    }
    if (evidence.agentWalletStatus === "unbound") {
      return { ok: false, reason: "agent_wallet_unbound" };
    }

    const issuedNow = this.#now();
    let request;
    try {
      request = createAgentPermitRequest({
        agent,
        agentWallet: evidence.agentWallet,
        operator: evidence.owner,
        audience: this.#agentAudience,
        action: actionMeta,
        policy: this.#agentPolicy,
        issuedAt: issuedNow,
        lifetimeSeconds: this.#agentPermitLifetimeSeconds,
      });
    } catch {
      return { ok: false, reason: "agent_invalid" };
    }

    const message = renderAgentPermitMessage(request);
    const permitId = agentPermitId(request);
    this.#pendingPermits.set(
      request.nonce,
      Object.freeze({ request, message, action: checkedAction }),
    );
    return {
      ok: true,
      status: "paused_for_owner_approval",
      permitId,
      nonce: request.nonce,
      subject: request.operator,
      actor: request.agentWallet,
      agent: request.agent,
      message,
      fragment: encodeAgentPermitFragment(request),
    };
  }

  /**
   * Settles a signed Agent Operator Permit bundle:
   * runs 0-RPC precheck first, then live `readAgentState` + `readIntegratorEvidence`,
   * then `evaluateAgentPermit`, then atomic single-use nonce deletion.
   */
  async settleAgentPermit(input, { origin }) {
    if (!this.#originAllowed(origin)) {
      return { ok: false, reason: "origin_invalid" };
    }
    const bundle = parseAgentPermitSettlement(input);
    if (!bundle) return { ok: false, reason: "invalid_request" };

    const entry = this.#pendingPermits.get(bundle.nonce);
    if (!entry) return { ok: false, reason: "nonce_unavailable" };

    const signatures = {
      operatorSignature: bundle.operatorSignature,
      presentationSignature: bundle.presentationSignature,
    };

    // 0-RPC precheck rejects expired or forged permits before touching the RPC connection.
    const precheck = precheckAgentPermit({
      request: entry.request,
      ...signatures,
      nowSeconds: this.#now(),
    });
    if (!precheck.ok) {
      if (precheck.reason === "permit_expired") {
        this.#pendingPermits.delete(bundle.nonce);
      }
      return { ok: false, reason: precheck.reason, chainReads: 0 };
    }

    let agentState;
    let operatorEvidence;
    try {
      [agentState, operatorEvidence] = await Promise.all([
        readAgentState({
          agent: entry.request.agent,
          connection: this.#connection,
        }),
        readIntegratorEvidence({
          walletPubkey: entry.request.operator,
          transactionSignature: bundle.verifiedTransaction,
          connection: this.#connection,
          nowSeconds: () => this.#now(),
        }),
      ]);
    } catch {
      return { ok: false, reason: "state_unavailable" };
    }

    const now = this.#now();
    const result = evaluateAgentPermit({
      request: entry.request,
      ...signatures,
      agentState,
      operatorEvidence,
      nowSeconds: now,
      expected: {
        nonce: entry.request.nonce,
        agent: entry.request.agent,
        operator: entry.request.operator,
        audience: this.#agentAudience,
        action: entry.request.action,
        policy: this.#agentPolicy,
      },
    });

    if (result.decision !== "allow") {
      if (result.reason === "permit_expired") {
        this.#pendingPermits.delete(bundle.nonce);
      }
      return { ok: false, reason: result.reason };
    }

    if (this.#pendingPermits.get(bundle.nonce) !== entry) {
      return { ok: false, reason: "nonce_unavailable" };
    }
    this.#pendingPermits.delete(bundle.nonce);

    const executed = Object.freeze({
      id: this.#executedActions.length + 1,
      flow: "agent_permit",
      permitId: result.permitId,
      agent: entry.request.agent,
      subject: entry.request.operator,
      actor: entry.request.agentWallet,
      ...entry.action,
      verifiedTransaction: bundle.verifiedTransaction,
      verifiedAt: result.policy.evidence.identity.lastVerificationTimestamp,
      ownerReadSlot: result.agentState.readContextSlot,
      settledAt: now,
      policy: policyResultToWire(result.policy),
    });
    this.#executedActions.push(executed);
    return { ok: true, action: structuredClone(executed) };
  }

  /** Runs Realms voter-weight pre-flight before prompting a wallet signature. */
  async preflightRealms({
    realm,
    governingTokenMint,
    voter,
    action,
    actionTarget,
    origin,
  }) {
    if (origin !== undefined && !this.#originAllowed(origin)) {
      return { eligible: false, reason: "origin_invalid" };
    }
    return preflightRealmsVoterWeight({
      connection: this.#connection,
      realm,
      governingTokenMint,
      voter,
      action,
      actionTarget,
      nowSeconds: this.#now(),
    });
  }

  buildAtomicRealmsTransaction(params) {
    return buildAtomicRealmsGovernanceTransaction(params);
  }

  verifyAtomicRealmsTransaction(params) {
    return verifyAtomicRealmsGovernanceTransaction(params);
  }

  recordTelemetry(event) {
    this.#telemetry.recordRun(event);
  }

  telemetrySummary() {
    return this.#telemetry.summarize();
  }

  actions() {
    return structuredClone(this.#executedActions);
  }
}
