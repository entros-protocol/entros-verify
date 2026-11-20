/**
 * Warm policy reuse helper for `@entros/verify`.
 *
 * Evaluates current chain evidence before browser capture starts. When existing
 * evidence already satisfies the policy, the caller completes verification at
 * 0 SOL and zero capture rounds while preserving the original verification time.
 */

import { canonicalKeyBytes } from "./base58";
import {
  evaluatePolicy,
  normalizePolicyRequest,
  PolicyValidationError,
  type PolicyEvidence,
  type PolicyEvidenceReadResult,
  type PolicyReason,
  type PolicyRequest,
  type PolicyRequestInput,
  type PolicyResult,
} from "./policy";

export type WarmVerificationLookup =
  | { status: "found"; signature: string }
  | { status: "none" | "invalid" | "unavailable" };

export interface WarmPolicyReuseBaseInput {
  /** Base58 Solana wallet address requesting verification. */
  walletPubkey: string;
  /** Application policy requirements. Omitting this uses the default policy. */
  policy?: PolicyRequestInput;
  /** Legacy Trust Score floor. Must match `policy.minTrustScore` when both exist. */
  minTrustScore?: number;
  /**
   * Current Unix timestamp in seconds, or a clock callback sampled after
   * asynchronous chain reads complete.
   */
  nowSeconds: number | (() => number);
  /**
   * Legacy callers without a negotiated policy cannot represent an absent
   * attestation. When true and `policy` is omitted, reuse requires a present
   * attestation.
   */
  requireLegacyAttestation?: boolean;
}

export type WarmPolicyReuseObservationInput = WarmPolicyReuseBaseInput & {
  /** Evidence observation from a trusted chain reader, or null when absent. */
  observation: PolicyEvidenceReadResult | null;
  findVerification?: never;
  readEvidence?: never;
};

export type WarmPolicyReuseReaderInput = WarmPolicyReuseBaseInput & {
  observation?: never;
  /**
   * Optional lookup for the wallet's newest qualifying verification transaction.
   * Accepts a lookup status object or a transaction signature string.
   */
  findVerification?: (input: {
    walletPubkey: string;
  }) => Promise<WarmVerificationLookup | string | null>;
  /** Reads current on-chain evidence from a trusted RPC connection. */
  readEvidence: (input: {
    walletPubkey: string;
    transactionSignature?: string;
  }) => Promise<PolicyEvidenceReadResult | null>;
};

export type WarmPolicyReuseInput =
  | WarmPolicyReuseObservationInput
  | WarmPolicyReuseReaderInput;

export type WarmPolicyReuseResult =
  | {
      status: "reused";
      policy: PolicyResult & { decision: "allow" };
      evidence: PolicyEvidence;
    }
  | {
      status: "needs_capture";
      policy: PolicyResult | null;
      reason: PolicyReason | "evidence_not_found";
    };

function readClock(nowSeconds: number | (() => number)): number {
  const value = typeof nowSeconds === "function" ? nowSeconds() : nowSeconds;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > Number.MAX_SAFE_INTEGER - 31536000
  ) {
    throw new PolicyValidationError("invalid_evidence");
  }
  return value;
}

function needsCapture(
  reason: PolicyReason | "evidence_not_found",
  policy: PolicyResult | null = null,
): WarmPolicyReuseResult {
  return { status: "needs_capture", policy, reason };
}

/**
 * Checks whether existing on-chain verification evidence already satisfies an
 * application policy without running browser capture or refreshing `verifiedAt`.
 */
export async function evaluateWarmPolicyReuse(
  input: WarmPolicyReuseInput,
): Promise<WarmPolicyReuseResult> {
  const normalized = normalizePolicyRequest(input.policy, input.minTrustScore);
  const requireLegacy =
    input.requireLegacyAttestation === true && input.policy === undefined;
  const effectivePolicy: PolicyRequest = requireLegacy
    ? { ...normalized, requireAttestation: true }
    : normalized;

  if (typeof input.nowSeconds !== "function") {
    readClock(input.nowSeconds);
  }

  if (
    typeof input.walletPubkey !== "string" ||
    canonicalKeyBytes(input.walletPubkey) === null
  ) {
    return needsCapture("invalid_evidence");
  }

  let observation: PolicyEvidenceReadResult | null;
  let expectedSignature: string | undefined;

  if (input.observation !== undefined) {
    observation = input.observation;
  } else if (typeof input.readEvidence === "function") {
    if (typeof input.findVerification === "function") {
      let lookup: WarmVerificationLookup | string | null;
      try {
        lookup = await input.findVerification({
          walletPubkey: input.walletPubkey,
        });
      } catch {
        return needsCapture("state_unavailable");
      }

      if (lookup === null) {
        return needsCapture("evidence_not_found");
      }

      if (typeof lookup === "string") {
        if (lookup.length === 0) {
          return needsCapture("evidence_not_found");
        }
        expectedSignature = lookup;
      } else if (lookup.status === "found") {
        if (
          typeof lookup.signature !== "string" ||
          lookup.signature.length === 0
        ) {
          return needsCapture("invalid_evidence");
        }
        expectedSignature = lookup.signature;
      } else if (lookup.status === "none") {
        return needsCapture("evidence_not_found");
      } else if (lookup.status === "unavailable") {
        return needsCapture("state_unavailable");
      } else {
        return needsCapture("invalid_evidence");
      }
    }

    try {
      observation = await input.readEvidence(
        expectedSignature === undefined
          ? { walletPubkey: input.walletPubkey }
          : {
              walletPubkey: input.walletPubkey,
              transactionSignature: expectedSignature,
            },
      );
    } catch {
      return needsCapture("state_unavailable");
    }
  } else {
    return needsCapture("evidence_not_found");
  }

  if (observation === null) {
    return needsCapture("evidence_not_found");
  }

  const evaluatedNow = readClock(input.nowSeconds);
  const policy = evaluatePolicy(effectivePolicy, observation, evaluatedNow);

  if (
    policy.evidence !== null &&
    policy.evidence.identity.walletPubkey !== input.walletPubkey
  ) {
    return needsCapture("invalid_evidence");
  }

  if (
    expectedSignature !== undefined &&
    policy.evidence !== null &&
    policy.evidence.transaction.signature !== expectedSignature
  ) {
    return needsCapture("invalid_evidence");
  }

  if (policy.decision !== "allow") {
    return needsCapture(policy.reason, policy);
  }

  if (requireLegacy && policy.evidence.attestation.status !== "present") {
    return needsCapture("attestation_required");
  }

  return {
    status: "reused",
    policy,
    evidence: policy.evidence,
  };
}
