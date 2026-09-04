import { describe, expect, it } from "vitest";
import {
  encodePolicyRequest,
  evaluatePolicy,
  isPolicyEvidence,
  normalizePolicyRequest,
  parsePolicyParameters,
  parsePolicyWireResult,
  policyResultToWire,
  validatePolicyVerifiedPayload,
  type PolicyEvidence,
  type PolicyRequest,
} from "../src/policy";
import { makePolicyEvidence, makePolicyPayload } from "./policy-fixtures";
import { isVerifiedPayload } from "../src/messaging";

const NOW = 1800000000;
const policy = normalizePolicyRequest(undefined, 200);
const evaluate = (
  evidence = makePolicyEvidence(NOW),
  request: PolicyRequest = policy,
  now = NOW,
) => evaluatePolicy(request, { status: "available", evidence }, now);

describe("policy request", () => {
  it("freezes explicit defaults without mutating the caller", () => {
    const request = normalizePolicyRequest();
    expect(request).toMatchObject({
      id: "entros-verify-default",
      minTrustScore: 0,
      maxVerificationAgeSeconds: 86400,
      maxEvaluationAgeSeconds: 90,
      requireAttestation: false,
    });
    expect(normalizePolicyRequest(undefined, 10000).minTrustScore).toBe(10000);
    expect(
      normalizePolicyRequest({
        ...request,
        maxVerificationAgeSeconds: 31536000,
      }),
    ).toMatchObject({ maxVerificationAgeSeconds: 31536000 });
  });

  it.each([
    null,
    [],
    { ...policy, version: 2 },
    { ...policy, extra: true },
    { ...policy, id: "bad id" },
    { ...policy, id: "a".repeat(65) },
    { ...policy, minTrustScore: -1 },
    { ...policy, minTrustScore: 10001 },
    { ...policy, minTrustScore: 0.5 },
    { ...policy, maxVerificationAgeSeconds: 0 },
    { ...policy, maxVerificationAgeSeconds: 31536001 },
    { ...policy, maxEvaluationAgeSeconds: 91 },
    { ...policy, maxEvaluationAgeSeconds: null },
    { ...policy, requireAttestation: "false" },
    { ...policy, requiredAssurance: "native" },
    { ...policy, uniquenessRequirement: "unique" },
    { ...policy, cluster: "mainnet-beta" },
    { ...policy, minTrustScore: Number.NaN },
  ])("rejects unsupported request %#", (request) => {
    expect(() => normalizePolicyRequest(request)).toThrow();
  });

  it("rejects conflicting legacy floors", () => {
    expect(() => normalizePolicyRequest(policy, 201)).toThrow();
    expect(() => normalizePolicyRequest(undefined, -1)).toThrow();
    expect(normalizePolicyRequest(policy, 200)).toEqual(policy);
  });

  it("negotiates only a complete canonical policy", () => {
    const params = new URLSearchParams({
      policy_version: "1",
      policy: encodePolicyRequest(policy),
      min_trust_score: "200",
    });
    expect(parsePolicyParameters(params)).toEqual({ negotiated: true, policy });
    expect(
      parsePolicyParameters(new URLSearchParams("min_trust_score=200")),
    ).toEqual({
      negotiated: false,
      policy: { ...policy, requireAttestation: true },
    });
    params.append("policy", encodePolicyRequest(policy));
    expect(() => parsePolicyParameters(params)).toThrow();
  });

  it.each([
    "policy_version=1",
    "policy_version=2",
    "policy={}",
    "min_trust_score=1&min_trust_score=1",
    "min_trust_score=01",
    "min_trust_score=1.0",
    "min_trust_score=10001",
    "min_trust_score=NaN",
  ])("rejects ambiguous query %s", (query) =>
    expect(() => parsePolicyParameters(new URLSearchParams(query))).toThrow(),
  );

  it("rejects duplicate JSON keys and noncanonical encodings", () => {
    const valid = encodePolicyRequest(policy);
    for (const encoded of [
      valid.replace('"version":1', '"version":1,"version":1'),
      ` ${valid}`,
      valid.replace('"id"', '"\\u0069d"'),
    ]) {
      expect(() =>
        parsePolicyParameters(
          new URLSearchParams({ policy_version: "1", policy: encoded }),
        ),
      ).toThrow();
    }
  });
});

describe("policy decisions", () => {
  it("binds the complete RPC genesis hash and rejects its truncated chain reference", () => {
    const evidence = makePolicyEvidence(NOW);
    expect(evidence.genesisHash).toBe(
      "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
    );
    expect(evaluate(evidence).decision).toBe("allow");
    evidence.genesisHash = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    expect(evaluate(evidence).reason).toBe("invalid_evidence");
  });
  it("allows exact score equality and explicit unmeasured browser evidence", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.identity.trustScore = 200;
    const result = evaluate(evidence);
    expect(result).toMatchObject({
      decision: "allow",
      reason: "accepted",
      evidenceTimestamp: NOW - 10,
      evaluatedAgeSeconds: 10,
      expiresAt: NOW + 90,
    });
    expect(result.evidence).toMatchObject({
      assuranceTier: "browser_unattested",
      uniquenessStatus: "unmeasured",
    });
  });

  it("rejects a score below the floor", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.identity.trustScore = 199;
    expect(evaluate(evidence)).toMatchObject({
      decision: "deny",
      reason: "score_below_minimum",
    });
  });

  it("rejects the exact freshness expiry and future observations", () => {
    expect(
      evaluate(makePolicyEvidence(NOW), {
        ...policy,
        maxVerificationAgeSeconds: 10,
      }),
    ).toMatchObject({ reason: "verification_stale" });
    const evidence = makePolicyEvidence(NOW);
    evidence.transaction.blockTime = NOW + 1;
    expect(evaluate(evidence)).toMatchObject({ reason: "invalid_evidence" });
    evidence.transaction.blockTime = NOW;
    evidence.identity.lastVerificationTimestamp = NOW + 1;
    expect(evaluate(evidence)).toMatchObject({ reason: "invalid_evidence" });
  });

  it("uses the earlier transaction time after a later identity update", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.identity.lastVerificationTimestamp = NOW;
    evidence.transaction.blockTime = NOW - 100;
    expect(
      evaluate(evidence, { ...policy, maxVerificationAgeSeconds: 50 }),
    ).toMatchObject({
      reason: "verification_stale",
      evidenceTimestamp: NOW - 100,
    });
  });

  it("refuses old transactions paired with a fresh reset or changed commitment", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.identity.lastResetTimestamp = NOW - 5;
    evidence.identity.lastVerificationTimestamp = NOW - 5;
    expect(evaluate(evidence)).toMatchObject({ reason: "invalid_evidence" });
    evidence.identity.lastResetTimestamp = 0;
    evidence.identity.currentCommitment = "02".repeat(32);
    expect(evaluate(evidence)).toMatchObject({ reason: "invalid_evidence" });
  });

  it("permits zero history only for the exact fresh mint exception", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.transaction.kind = "mint";
    evidence.identity.creationTimestamp = NOW - 10;
    evidence.identity.verificationCount = 0;
    evidence.identity.trustScore = 0;
    const zeroFloor = { ...policy, minTrustScore: 0 };
    expect(evaluate(evidence, zeroFloor).decision).toBe("allow");
    expect(evaluate(evidence).reason).toBe("score_below_minimum");
    for (const kind of ["update", "rebaseline"] as const) {
      evidence.transaction.kind = kind;
      expect(evaluate(evidence, zeroFloor).reason).toBe("invalid_evidence");
    }
    evidence.transaction.kind = "mint";
    evidence.identity.lastRebaselineTimestamp = NOW - 10;
    expect(evaluate(evidence, zeroFloor).reason).toBe("invalid_evidence");
  });

  it("allows a qualifying rebaseline without upgrading assurance", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.transaction.kind = "rebaseline";
    evidence.identity.lastRebaselineTimestamp = NOW - 10;
    expect(evaluate(evidence)).toMatchObject({
      decision: "allow",
      evidence: { assuranceTier: "browser_unattested" },
    });
    evidence.identity.lastRebaselineTimestamp = NOW - 5;
    evidence.identity.lastVerificationTimestamp = NOW - 5;
    expect(evaluate(evidence).reason).toBe("invalid_evidence");
  });

  it.each(["missing", "unavailable"] as const)(
    "allows optional %s SAS without an issued address",
    (status) => {
      const evidence = makePolicyEvidence(NOW);
      evidence.attestation = { status };
      expect(evaluate(evidence)).toMatchObject({
        decision: "allow",
        evidence: { attestation: { status } },
      });
    },
  );

  it.each([
    ["missing", "deny", "attestation_required"],
    ["unavailable", "unavailable", "state_unavailable"],
    ["invalid", "deny", "invalid_evidence"],
  ] as const)(
    "fails a required %s SAS observation",
    (status, decision, reason) => {
      const evidence = makePolicyEvidence(NOW);
      evidence.attestation = { status };
      expect(
        evaluate(evidence, { ...policy, requireAttestation: true }),
      ).toMatchObject({ decision, reason });
    },
  );

  it("rejects invalid optional SAS and includes required expiry", () => {
    const evidence = makePolicyEvidence(NOW);
    evidence.attestation = { status: "invalid" };
    expect(evaluate(evidence).reason).toBe("invalid_evidence");
    evidence.attestation = {
      status: "present",
      address: evidence.identity.identityPda,
      readContextSlot: 100,
      expiresAt: NOW + 2,
    };
    expect(
      evaluate(evidence, { ...policy, requireAttestation: true }).expiresAt,
    ).toBe(NOW + 2);
    expect(evaluate(evidence, policy, NOW + 2).reason).toBe("invalid_evidence");
    evidence.attestation.expiresAt = null;
    expect(
      evaluate(evidence, { ...policy, requireAttestation: true }).expiresAt,
    ).toBe(NOW + 90);
  });

  it("distinguishes unavailable observations from a real zero score", () => {
    expect(
      evaluatePolicy(
        policy,
        { status: "unavailable", reason: "rpc_failed" },
        NOW,
      ),
    ).toMatchObject({
      decision: "unavailable",
      evidence: null,
      evidenceTimestamp: null,
    });
    expect(
      evaluatePolicy(
        policy,
        { status: "invalid", reason: "identity_missing" },
        NOW,
      ),
    ).toMatchObject({ decision: "deny", evidence: null });
  });

  const corruptions: [string, (e: PolicyEvidence) => void][] = [
    [
      "wrong genesis",
      (e) => {
        e.genesisHash = "other";
      },
    ],
    [
      "wrong program",
      (e) => {
        e.programIds.anchor = e.programIds.registry;
      },
    ],
    [
      "bad wallet",
      (e) => {
        e.identity.walletPubkey = "wallet";
      },
    ],
    [
      "bad signature",
      (e) => {
        e.transaction.signature = "abcd";
      },
    ],
    [
      "unsafe timestamp",
      (e) => {
        e.identity.lastVerificationTimestamp = Number.MAX_SAFE_INTEGER + 1;
      },
    ],
    [
      "negative count",
      (e) => {
        e.identity.verificationCount = -1;
      },
    ],
    [
      "oversized count",
      (e) => {
        e.identity.verificationCount = 2 ** 32;
      },
    ],
    [
      "fractional score",
      (e) => {
        e.identity.trustScore = 0.5;
      },
    ],
    [
      "unrecognized projection",
      (e) => {
        e.identity.projectionVersion = 3;
      },
    ],
    [
      "zero commitment",
      (e) => {
        e.identity.currentCommitment = "00".repeat(32);
      },
    ],
    [
      "older snapshot",
      (e) => {
        e.readContextSlot = 99;
      },
    ],
    [
      "later reset",
      (e) => {
        e.identity.lastResetTimestamp = NOW;
      },
    ],
  ];
  it.each(corruptions)("rejects %s", (_name, corrupt) => {
    const evidence = makePolicyEvidence(NOW);
    corrupt(evidence);
    expect(evaluate(evidence).reason).toBe("invalid_evidence");
  });
});

describe("policy wire boundary", () => {
  it.each([undefined, null, "unknown", "issued", "revoked"])(
    "rejects absent or unsupported attestation status %s",
    (status) => {
      const payload = makePolicyPayload(policy, NOW);
      const modified = {
        ...payload,
        policy: { ...payload.policy, attestation: { status } },
      };
      expect(validatePolicyVerifiedPayload(modified, policy, NOW)).toEqual({
        ok: false,
        reason: "invalid_evidence",
      });
    },
  );

  it.each(["assurance_tier", "uniqueness_status"])(
    "rejects absent %s",
    (field) => {
      const wire: Record<string, unknown> = {
        ...policyResultToWire(evaluate()),
      };
      delete wire[field];
      expect(parsePolicyWireResult(wire)).toBeNull();
    },
  );

  it("retains legacy string payload compatibility only for an actual present attestation", () => {
    const request = { ...policy, requireAttestation: true };
    const evidence = makePolicyEvidence(NOW);
    evidence.attestation = {
      status: "present",
      address: evidence.identity.identityPda,
      readContextSlot: 100,
      expiresAt: NOW + 2,
    };
    const result = evaluate(evidence, request);
    const payload = {
      ...makePolicyPayload(request, NOW),
      attestation_pda: evidence.attestation.address,
      policy: policyResultToWire(result),
    };
    expect(isVerifiedPayload(payload)).toBe(true);
    expect(validatePolicyVerifiedPayload(payload, request, NOW).ok).toBe(true);
    expect(validatePolicyVerifiedPayload(payload, request, NOW + 2)).toEqual({
      ok: false,
      reason: "verification_stale",
    });
    expect(isVerifiedPayload(makePolicyPayload(policy, NOW))).toBe(false);
  });
  it("round-trips allowed, denied, and unavailable observations", () => {
    for (const result of [
      evaluate(),
      evaluate(makePolicyEvidence(NOW), { ...policy, minTrustScore: 999 }),
      evaluatePolicy(policy, { status: "unavailable", reason: "rpc" }, NOW),
    ]) {
      expect(parsePolicyWireResult(policyResultToWire(result))).toEqual(result);
    }
  });

  it("rejects unknown fields in evidence", () => {
    expect(
      isPolicyEvidence({ ...makePolicyEvidence(NOW), unknown: true }),
    ).toBe(false);
  });

  it.each([
    "policy_id",
    "policy_version",
    "decision",
    "reason",
    "expires_at",
    "evidence_timestamp",
    "evaluated_age_seconds",
    "uniqueness_status",
    "assurance_tier",
    "program_ids",
  ])("rejects changed %s", (field) => {
    const wire = policyResultToWire(evaluate());
    expect(
      parsePolicyWireResult({ ...wire, [field]: "unexpected" }),
    ).toBeNull();
  });

  it("rejects missing policy and mismatched requirements", () => {
    const payload = makePolicyPayload(policy, NOW);
    const { policy: _policy, ...legacy } = payload;
    expect(validatePolicyVerifiedPayload(legacy, policy, NOW)).toEqual({
      ok: false,
      reason: "unsupported_policy",
    });
    expect(
      validatePolicyVerifiedPayload(
        payload,
        { ...policy, minTrustScore: 201 },
        NOW,
      ).ok,
    ).toBe(false);
    expect(validatePolicyVerifiedPayload(payload, policy, NOW)).toMatchObject({
      ok: true,
    });
  });

  it.each([
    "wallet_pubkey",
    "trust_score",
    "cluster",
    "tx_sig",
    "attestation_pda",
  ])("rejects mismatched top-level %s", (field) => {
    expect(
      validatePolicyVerifiedPayload(
        { ...makePolicyPayload(policy, NOW), [field]: "other" },
        policy,
        NOW,
      ),
    ).toEqual({ ok: false, reason: "invalid_evidence" });
  });

  it("rejects stale and future evaluation clocks without refreshing cached expiry", () => {
    const payload = makePolicyPayload(policy, NOW);
    expect(validatePolicyVerifiedPayload(payload, policy, NOW + 89).ok).toBe(
      true,
    );
    expect(validatePolicyVerifiedPayload(payload, policy, NOW + 90)).toEqual({
      ok: false,
      reason: "verification_stale",
    });
    expect(validatePolicyVerifiedPayload(payload, policy, NOW - 1)).toEqual({
      ok: false,
      reason: "verification_stale",
    });
  });

  it("bounds deterministic evaluation under concurrent consumer work", async () => {
    const expected = JSON.stringify(evaluate());
    for (const concurrency of [1, 4, 8, 16, 30]) {
      await Promise.all(
        Array.from({ length: concurrency }, async () => {
          for (let i = 0; i < 100; i++)
            expect(JSON.stringify(evaluate())).toBe(expected);
        }),
      );
    }
  });
});
