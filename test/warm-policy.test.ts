import { describe, expect, it, vi } from "vitest";
import { evaluateWarmPolicyReuse } from "../src/index";
import {
  normalizePolicyRequest,
  POLICY_NETWORK,
  PolicyValidationError,
  type PolicyEvidence,
  type PolicyRequestInput,
} from "../src/policy";
import { makePolicyEvidence } from "./policy-fixtures";

const NOW = 1800000000;
const WALLET = "11111111111111111111111111111111";
const OTHER_WALLET = POLICY_NETWORK.programIds.anchor;
const ATTESTATION_PDA = POLICY_NETWORK.programIds.verifier;

function makeAgedEvidence(
  verifiedAt: number,
  overrides: Partial<PolicyEvidence> = {},
): PolicyEvidence {
  const base = makePolicyEvidence(NOW);
  return {
    ...base,
    ...overrides,
    identity: {
      ...base.identity,
      creationTimestamp: verifiedAt - 86400,
      lastVerificationTimestamp: verifiedAt,
      ...(overrides.identity ?? {}),
    },
    transaction: {
      ...base.transaction,
      blockTime: verifiedAt,
      ...(overrides.transaction ?? {}),
    },
  };
}

describe("evaluateWarmPolicyReuse", () => {
  it("reuses valid evidence and preserves the original verifiedAt timestamp", async () => {
    const originalVerifiedAt = NOW - 600;
    const evidence = makeAgedEvidence(originalVerifiedAt);
    const policy: PolicyRequestInput = {
      id: "warm-access",
      version: 1,
      minTrustScore: 200,
      maxVerificationAgeSeconds: 3600,
      maxEvaluationAgeSeconds: 90,
      requiredAssurance: "browser_unattested",
      uniquenessRequirement: "allow_unmeasured",
      requireAttestation: false,
      cluster: "devnet",
    };

    const result = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      policy,
      observation: { status: "available", evidence },
      nowSeconds: NOW,
    });

    expect(result.status).toBe("reused");
    if (result.status !== "reused") throw new Error("expected reused");
    expect(result.policy.decision).toBe("allow");
    expect(result.policy.reason).toBe("accepted");
    expect(result.evidence.identity.lastVerificationTimestamp).toBe(
      originalVerifiedAt,
    );
    expect(result.policy.evidenceTimestamp).toBe(originalVerifiedAt);
    expect(result.policy.evaluatedAt).toBe(NOW);
    expect(result.policy.evaluatedAgeSeconds).toBe(600);
    expect(result.policy.expiresAt).toBe(NOW + 90);
    expect(evidence.identity.lastVerificationTimestamp).toBe(
      originalVerifiedAt,
    );
  });

  it("returns evidence_not_found when observation is null", async () => {
    const result = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      observation: null,
      nowSeconds: NOW,
    });

    expect(result).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "evidence_not_found",
    });
  });

  it("rejects walletPubkey mismatch even when evidence would otherwise allow or fail score", async () => {
    const allowing = makeAgedEvidence(NOW - 30);
    const allowedMismatch = await evaluateWarmPolicyReuse({
      walletPubkey: OTHER_WALLET,
      observation: { status: "available", evidence: allowing },
      nowSeconds: NOW,
    });
    expect(allowedMismatch).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "invalid_evidence",
    });

    const lowScore = makeAgedEvidence(NOW - 30, {
      identity: { ...makePolicyEvidence(NOW).identity, trustScore: 50 },
    });
    const deniedMismatch = await evaluateWarmPolicyReuse({
      walletPubkey: OTHER_WALLET,
      minTrustScore: 200,
      observation: { status: "available", evidence: lowScore },
      nowSeconds: NOW,
    });
    expect(deniedMismatch).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "invalid_evidence",
    });
  });

  it("rejects malformed walletPubkey without calling readers", async () => {
    const findVerification = vi.fn();
    const readEvidence = vi.fn();

    const result = await evaluateWarmPolicyReuse({
      walletPubkey: "not-a-valid-pubkey",
      findVerification,
      readEvidence,
      nowSeconds: NOW,
    });

    expect(result).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "invalid_evidence",
    });
    expect(findVerification).not.toHaveBeenCalled();
    expect(readEvidence).not.toHaveBeenCalled();
  });

  it("routes stale and below-floor evidence to capture", async () => {
    const stale = makeAgedEvidence(NOW - 300);
    const staleResult = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      policy: {
        ...normalizePolicyRequest(),
        maxVerificationAgeSeconds: 300,
      },
      observation: { status: "available", evidence: stale },
      nowSeconds: NOW,
    });
    expect(staleResult.status).toBe("needs_capture");
    expect(staleResult.reason).toBe("verification_stale");
    expect(staleResult.policy?.decision).toBe("deny");

    const lowScore = makeAgedEvidence(NOW - 10, {
      identity: { ...makePolicyEvidence(NOW).identity, trustScore: 199 },
    });
    const floorResult = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      minTrustScore: 200,
      observation: { status: "available", evidence: lowScore },
      nowSeconds: NOW,
    });
    expect(floorResult.status).toBe("needs_capture");
    expect(floorResult.reason).toBe("score_below_minimum");
    expect(floorResult.policy?.decision).toBe("deny");
  });

  it("routes post-reset evidence to capture and accepts valid rebaseline or mint evidence", async () => {
    const base = makeAgedEvidence(NOW - 30);
    const postReset = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      observation: {
        status: "available",
        evidence: {
          ...base,
          identity: {
            ...base.identity,
            lastResetTimestamp: NOW - 30,
          },
        },
      },
      nowSeconds: NOW,
    });
    expect(postReset.status).toBe("needs_capture");
    expect(postReset.reason).toBe("invalid_evidence");

    const rebaseline = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      observation: {
        status: "available",
        evidence: {
          ...base,
          identity: {
            ...base.identity,
            lastRebaselineTimestamp: NOW - 30,
          },
          transaction: {
            ...base.transaction,
            kind: "rebaseline",
          },
        },
      },
      nowSeconds: NOW,
    });
    expect(rebaseline.status).toBe("reused");

    const mintTime = NOW - 20;
    const freshMint = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      observation: {
        status: "available",
        evidence: {
          ...base,
          identity: {
            ...base.identity,
            creationTimestamp: mintTime,
            lastVerificationTimestamp: mintTime,
            verificationCount: 0,
            trustScore: 0,
            lastResetTimestamp: 0,
            lastRebaselineTimestamp: 0,
          },
          transaction: {
            ...base.transaction,
            blockTime: mintTime,
            kind: "mint",
          },
        },
      },
      nowSeconds: NOW,
    });
    expect(freshMint.status).toBe("reused");
  });

  it("requires a present attestation for legacy callers when requireLegacyAttestation is true", async () => {
    const missingAttestation = makeAgedEvidence(NOW - 30, {
      attestation: { status: "missing" },
    });

    const denied = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      requireLegacyAttestation: true,
      observation: { status: "available", evidence: missingAttestation },
      nowSeconds: NOW,
    });
    expect(denied.status).toBe("needs_capture");
    expect(denied.reason).toBe("attestation_required");

    const presentAttestation = makeAgedEvidence(NOW - 30, {
      attestation: {
        status: "present",
        address: ATTESTATION_PDA,
        readContextSlot: 100,
        expiresAt: NOW + 3600,
      },
    });
    const allowed = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      requireLegacyAttestation: true,
      observation: { status: "available", evidence: presentAttestation },
      nowSeconds: NOW,
    });
    expect(allowed.status).toBe("reused");
    if (allowed.status !== "reused") throw new Error("expected reused");
    expect(allowed.policy.requirements.requireAttestation).toBe(true);
    expect(allowed.evidence.attestation.status).toBe("present");

    const negotiatedOptional = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      policy: {
        ...normalizePolicyRequest(),
        requireAttestation: false,
      },
      requireLegacyAttestation: true,
      observation: { status: "available", evidence: missingAttestation },
      nowSeconds: NOW,
    });
    expect(negotiatedOptional.status).toBe("reused");
  });

  it("throws PolicyValidationError on invalid policy or clock before calling readers", async () => {
    const findVerification = vi.fn();
    const readEvidence = vi.fn();

    await expect(
      evaluateWarmPolicyReuse({
        walletPubkey: WALLET,
        policy: {
          ...normalizePolicyRequest(),
          requiredAssurance: "native" as "browser_unattested",
        },
        findVerification,
        readEvidence,
        nowSeconds: NOW,
      }),
    ).rejects.toThrow(PolicyValidationError);

    await expect(
      evaluateWarmPolicyReuse({
        walletPubkey: WALLET,
        policy: normalizePolicyRequest(undefined, 200),
        minTrustScore: 300,
        findVerification,
        readEvidence,
        nowSeconds: NOW,
      }),
    ).rejects.toThrow(PolicyValidationError);

    await expect(
      evaluateWarmPolicyReuse({
        walletPubkey: WALLET,
        findVerification,
        readEvidence,
        nowSeconds: 0,
      }),
    ).rejects.toThrow(PolicyValidationError);

    expect(findVerification).not.toHaveBeenCalled();
    expect(readEvidence).not.toHaveBeenCalled();
  });

  it("supports async findVerification and readEvidence callbacks and samples the clock after reads", async () => {
    const originalVerifiedAt = NOW - 50;
    const evidence = makeAgedEvidence(originalVerifiedAt);
    let clock = NOW;

    const findVerification = vi.fn(async () => ({
      status: "found" as const,
      signature: evidence.transaction.signature,
    }));
    const readEvidence = vi.fn(async () => {
      clock += 20;
      return { status: "available" as const, evidence };
    });

    const allowed = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      policy: {
        ...normalizePolicyRequest(),
        maxVerificationAgeSeconds: 120,
      },
      findVerification,
      readEvidence,
      nowSeconds: () => clock,
    });

    expect(findVerification).toHaveBeenCalledWith({ walletPubkey: WALLET });
    expect(readEvidence).toHaveBeenCalledWith({
      walletPubkey: WALLET,
      transactionSignature: evidence.transaction.signature,
    });
    expect(allowed.status).toBe("reused");
    if (allowed.status !== "reused") throw new Error("expected reused");
    expect(allowed.policy.evaluatedAt).toBe(NOW + 20);
    expect(allowed.policy.evidenceTimestamp).toBe(originalVerifiedAt);
    expect(allowed.policy.evaluatedAgeSeconds).toBe(70);

    // If the clock advances past maxVerificationAgeSeconds during the read, reuse denies.
    const expired = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      policy: {
        ...normalizePolicyRequest(),
        maxVerificationAgeSeconds: 60,
      },
      readEvidence: async () => {
        clock = originalVerifiedAt + 60;
        return { status: "available", evidence };
      },
      nowSeconds: () => clock,
    });
    expect(expired.status).toBe("needs_capture");
    expect(expired.reason).toBe("verification_stale");
  });

  it("handles lookup misses, reader failures, and mismatched signatures safely", async () => {
    const readEvidence = vi.fn();

    const notFound = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      findVerification: async () => ({ status: "none" }),
      readEvidence,
      nowSeconds: NOW,
    });
    expect(notFound).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "evidence_not_found",
    });
    expect(readEvidence).not.toHaveBeenCalled();

    const unavailableLookup = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      findVerification: async () => {
        throw new Error("rpc down");
      },
      readEvidence,
      nowSeconds: NOW,
    });
    expect(unavailableLookup).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "state_unavailable",
    });

    const invalidLookup = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      findVerification: async () => ({ status: "invalid" }),
      readEvidence,
      nowSeconds: NOW,
    });
    expect(invalidLookup).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "invalid_evidence",
    });

    const throwingReader = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      findVerification: async () => "2".repeat(64),
      readEvidence: async () => {
        throw new Error("timeout");
      },
      nowSeconds: NOW,
    });
    expect(throwingReader).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "state_unavailable",
    });

    const mismatchedTx = await evaluateWarmPolicyReuse({
      walletPubkey: WALLET,
      findVerification: async () => ({
        status: "found",
        signature: "2".repeat(64),
      }),
      readEvidence: async () => ({
        status: "available",
        evidence: makeAgedEvidence(NOW - 10),
      }),
      nowSeconds: NOW,
    });
    expect(mismatchedTx).toEqual({
      status: "needs_capture",
      policy: null,
      reason: "invalid_evidence",
    });
  });
});
