// @vitest-environment node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import {
  InMemoryPermitNonceStoreV2,
} from "../src/mcp/nonce-store-v2";
import {
  canonicalizeJcs,
  CanonicalJsonError,
  hashActionV2,
  parseStrictJson,
} from "../src/permit/canonical";
import {
  base64UrlDecodeStrict,
  concatBytes,
} from "../src/permit/encoding";
import { verifyEdDsaJws } from "../src/permit/jws";
import { verifyAgentPermitV2 } from "../src/permit/policy";
import { verifyScittReceipt } from "../src/permit/scitt";
import type {
  CanonicalActionV2Input,
  EcP256Jwk,
  JwksDocument,
  PolicyV2,
  WebAuthnAssertionInput,
} from "../src/permit/types";
import {
  deriveWebAuthnChallengeV2,
  verifyWebAuthnAssertionV2,
} from "../src/permit/webauthn";
import { verifyVoiceLivenessVerdict } from "../src/voice/verdict";

const VECTORS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../spec/vectors/agent-permit-v2",
);

function loadVectorFile<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(VECTORS_DIR, name), "utf-8")) as T;
}

describe("Shared parity vectors: RFC 8785 JCS (jcs-vectors.json)", () => {
  const vectors = loadVectorFile<{
    domain_prefix: string;
    valid: Array<{
      id: string;
      input: CanonicalActionV2Input;
      raw_json?: string;
      expected_canonical_json: string;
      expected_request_digest: string;
    }>;
    reject: Array<{
      id: string;
      case_type: string;
      code_unit_hex?: string;
      value_kind?: string;
      depth?: number;
      input?: unknown;
    }>;
  }>("jcs-vectors.json");

  for (const vec of vectors.valid) {
    it(`matches canonical JSON and SHA-256 request_digest for ${vec.id}`, () => {
      const result = hashActionV2(vec.input);
      expect(result.canonicalJson).toBe(vec.expected_canonical_json);
      expect(result.requestDigest).toBe(vec.expected_request_digest);

      if (vec.raw_json) {
        const parsed = parseStrictJson(vec.raw_json) as CanonicalActionV2Input;
        const fromRaw = hashActionV2(parsed);
        expect(fromRaw.canonicalJson).toBe(vec.expected_canonical_json);
        expect(fromRaw.requestDigest).toBe(vec.expected_request_digest);
      }
    });
  }

  for (const rej of vectors.reject) {
    it(`rejects ${rej.id}`, () => {
      if (
        rej.case_type === "lone_high_surrogate" ||
        rej.case_type === "lone_low_surrogate"
      ) {
        const lone = String.fromCharCode(Number.parseInt(rej.code_unit_hex!, 16));
        expect(() => canonicalizeJcs({ text: lone })).toThrow(CanonicalJsonError);
        expect(() =>
          canonicalizeJcs({ [lone]: 1 }),
        ).toThrow(CanonicalJsonError);
        return;
      }
      if (rej.case_type === "non_finite_number") {
        const num =
          rej.value_kind === "NaN"
            ? Number.NaN
            : rej.value_kind === "Infinity"
              ? Number.POSITIVE_INFINITY
              : Number.NEGATIVE_INFINITY;
        expect(() => canonicalizeJcs({ n: num })).toThrow(CanonicalJsonError);
        return;
      }
      if (rej.case_type === "max_depth_exceeded") {
        let nested: Record<string, unknown> = { leaf: 1 };
        for (let i = 0; i < (rej.depth ?? 33); i += 1) {
          nested = { next: nested };
        }
        expect(() => canonicalizeJcs(nested)).toThrow(CanonicalJsonError);
        return;
      }
      if (rej.case_type === "action_validation") {
        expect(() =>
          hashActionV2(rej.input as CanonicalActionV2Input),
        ).toThrow(CanonicalJsonError);
      }
    });
  }

  it("rejects cycles, sparse arrays, undefined values, non-plain prototypes, and duplicate keys", () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(() => canonicalizeJcs(cycle)).toThrow(CanonicalJsonError);

    // eslint-disable-next-line no-sparse-arrays
    const sparse = [1, , 3];
    expect(() => canonicalizeJcs(sparse)).toThrow(CanonicalJsonError);

    expect(() => canonicalizeJcs({ a: undefined })).toThrow(CanonicalJsonError);
    expect(() => canonicalizeJcs(new Date())).toThrow(CanonicalJsonError);
    expect(() => parseStrictJson('{"a":1,"a":2}')).toThrow(CanonicalJsonError);
  });
});

describe("Shared parity vectors: EdDSA JWS (jws-eddsa-vectors.json)", () => {
  const vectors = loadVectorFile<{
    now_seconds: number;
    jwks: JwksDocument;
    valid_voice_verdict: {
      id: string;
      expected_typ: string;
      jws: string;
      expected_claims: Record<string, unknown>;
    };
    valid_voice_abstain: {
      id: string;
      expected_typ: string;
      jws: string;
      expected_claims: Record<string, unknown>;
    };
    valid_agent_permit: {
      id: string;
      expected_typ: string;
      jws: string;
      expected_claims: Record<string, unknown>;
    };
    invalid_cases: Array<{
      id: string;
      expected_typ: string;
      jws: string;
      expected_reason: string;
    }>;
  }>("jws-eddsa-vectors.json");

  it("verifies valid_voice_verdict and valid_voice_abstain (including packet_loss)", async () => {
    const humanRes = await verifyVoiceLivenessVerdict({
      jws: vectors.valid_voice_verdict.jws,
      jwks: vectors.jwks,
      nowSeconds: vectors.now_seconds,
    });
    expect(humanRes.ok).toBe(true);
    if (humanRes.ok) {
      expect(humanRes.claims).toEqual(vectors.valid_voice_verdict.expected_claims);
    }

    const abstainRes = await verifyVoiceLivenessVerdict({
      jws: vectors.valid_voice_abstain.jws,
      jwks: vectors.jwks,
      nowSeconds: vectors.now_seconds,
    });
    expect(abstainRes.ok).toBe(true);
    if (abstainRes.ok) {
      expect(abstainRes.claims.verdict).toBe("insufficient_signal");
      expect(abstainRes.claims.abstain_reason).toBe("packet_loss");
      expect(abstainRes.claims.calibrated_llr).toBeNull();
    }
  });

  it("verifies valid_agent_permit compact EdDSA JWS strictly", async () => {
    const res = await verifyEdDsaJws({
      jws: vectors.valid_agent_permit.jws,
      expectedTyp: vectors.valid_agent_permit.expected_typ,
      jwks: vectors.jwks,
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.payload).toEqual(vectors.valid_agent_permit.expected_claims);
    }
  });

  for (const bad of vectors.invalid_cases) {
    it(`rejects ${bad.id} with ${bad.expected_reason}`, async () => {
      if (bad.expected_typ === "entros-voice-liveness+jwt") {
        const res = await verifyVoiceLivenessVerdict({
          jws: bad.jws,
          jwks: vectors.jwks,
          nowSeconds: vectors.now_seconds,
        });
        expect(res.ok).toBe(false);
        if (!res.ok) {
          expect(res.reason).toBe(bad.expected_reason);
        }
      } else {
        const res = await verifyEdDsaJws({
          jws: bad.jws,
          expectedTyp: bad.expected_typ,
          jwks: vectors.jwks,
        });
        expect(res.ok).toBe(false);
        if (!res.ok) {
          expect(res.reason).toBe(bad.expected_reason);
        }
      }
    });
  }
});

describe("Shared parity vectors: WebAuthn P-256 (webauthn-p256-vectors.json)", () => {
  const vectors = loadVectorFile<{
    challenge_derivation: {
      jti: string;
      request_digest: string;
      expected_challenge_hex: string;
      expected_challenge_b64url: string;
    };
    public_key: {
      uncompressed_hex: string;
      uncompressed_b64url: string;
      jwk: EcP256Jwk;
    };
    expected_rp_id: string;
    expected_origin: string;
    valid: Array<{
      id: string;
      stored_sign_count: number;
      expected_assertion_digest: string;
      assertion: WebAuthnAssertionInput;
      is_high_s: boolean;
    }>;
    invalid: Array<{
      id: string;
      stored_sign_count?: number;
      expected_reason: string;
      assertion: WebAuthnAssertionInput;
    }>;
  }>("webauthn-p256-vectors.json");

  it("derives exact ADR challenge hex and base64url", () => {
    const derived = deriveWebAuthnChallengeV2(
      vectors.challenge_derivation.jti,
      vectors.challenge_derivation.request_digest,
    );
    expect(derived.challengeHex).toBe(
      vectors.challenge_derivation.expected_challenge_hex,
    );
    expect(derived.challengeBase64Url).toBe(
      vectors.challenge_derivation.expected_challenge_b64url,
    );
  });

  for (const vec of vectors.valid) {
    it(`accepts ${vec.id} (highS=${vec.is_high_s}) with hex, b64url, and JWK keys`, () => {
      for (const key of [
        vectors.public_key.uncompressed_hex,
        vectors.public_key.uncompressed_b64url,
        vectors.public_key.jwk,
      ]) {
        const res = verifyWebAuthnAssertionV2({
          assertion: vec.assertion,
          publicKey: key,
          expectedRpId: vectors.expected_rp_id,
          expectedOrigin: vectors.expected_origin,
          expectedChallenge: vectors.challenge_derivation.expected_challenge_b64url,
          storedSignCount: vec.stored_sign_count,
        });
        expect(res.ok).toBe(true);
        if (res.ok) {
          expect(res.assertionDigest).toBe(vec.expected_assertion_digest);
          expect(res.userPresent).toBe(true);
          expect(res.userVerified).toBe(true);
        }
      }

      if (vec.is_high_s) {
        // Prove default lowS:true would falsely reject this valid hardware signature.
        const authData = base64UrlDecodeStrict(
          vec.assertion.authenticator_data as string,
        )!;
        const clientData = base64UrlDecodeStrict(
          vec.assertion.client_data_json as string,
        )!;
        const derSig = base64UrlDecodeStrict(vec.assertion.signature as string)!;
        const pubBytes = base64UrlDecodeStrict(
          vectors.public_key.uncompressed_b64url,
        )!;
        const signed = concatBytes(authData, sha256(clientData));
        expect(
          p256.verify(derSig, signed, pubBytes, {
            format: "der",
            lowS: true,
            prehash: true,
          }),
        ).toBe(false);
      }
    });
  }

  for (const bad of vectors.invalid) {
    it(`rejects ${bad.id} with ${bad.expected_reason}`, () => {
      const res = verifyWebAuthnAssertionV2({
        assertion: bad.assertion,
        publicKey: vectors.public_key.jwk,
        expectedRpId: vectors.expected_rp_id,
        expectedOrigin: vectors.expected_origin,
        expectedChallenge: vectors.challenge_derivation.expected_challenge_b64url,
        storedSignCount: bad.stored_sign_count,
      });
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.reason).toBe(bad.expected_reason);
      }
    });
  }
});

describe("Shared parity vectors: IETF SCITT COSE_Sign1 (scitt-receipt-vectors.json)", () => {
  const vectors = loadVectorFile<{
    jwks: JwksDocument;
    valid: Array<{
      id: string;
      receipt_b64url: string;
      expected_merkle_root_hex: string;
      expected_leaf_hash_hex: string;
      expected_tree_size: number;
      expected_leaf_index: number;
      expected_kid: string;
      expected_statement: Record<string, unknown>;
    }>;
    invalid: Array<{
      id: string;
      expected_reason: string;
      receipt_b64url: string;
    }>;
  }>("scitt-receipt-vectors.json");

  for (const vec of vectors.valid) {
    it(`verifies ${vec.id}`, async () => {
      const res = await verifyScittReceipt({
        receipt: vec.receipt_b64url,
        jwks: vectors.jwks,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.receipt.kid).toBe(vec.expected_kid);
        expect(res.receipt.treeSize).toBe(vec.expected_tree_size);
        expect(res.receipt.leafIndex).toBe(vec.expected_leaf_index);
        expect(res.receipt.leafHashHex).toBe(vec.expected_leaf_hash_hex);
        expect(res.receipt.merkleRootHex).toBe(vec.expected_merkle_root_hex);
        expect(res.receipt.statement).toEqual(vec.expected_statement);
      }
    });
  }

  for (const bad of vectors.invalid) {
    it(`rejects ${bad.id} with ${bad.expected_reason}`, async () => {
      const res = await verifyScittReceipt({
        receipt: bad.receipt_b64url,
        jwks: vectors.jwks,
      });
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.reason).toBe(bad.expected_reason);
      }
    });
  }
});

describe("Shared parity vectors: Policy v2 & Concurrency (policy-v2-vectors.json)", () => {
  const vectors = loadVectorFile<{
    all_assurance_tiers: string[];
    jwks: JwksDocument;
    cases: Array<{
      id: string;
      policy: PolicyV2;
      action: CanonicalActionV2Input;
      expected_audience: string;
      now_seconds: number;
      permit_jws: string;
      dpop_proof?: string;
      dpop_htm?: string;
      dpop_htu?: string;
      expected_decision: "allow" | "deny";
      expected_reason: string;
    }>;
    non_mutating_precheck_scenario: {
      jti: string;
      policy: PolicyV2;
      expected_audience: string;
      now_seconds: number;
      invalid_probes: Array<{
        id: string;
        permit_jws: string;
        action: CanonicalActionV2Input;
        dpop_proof: string;
        dpop_htm: string;
        dpop_htu: string;
        expected_reason: string;
      }>;
      final_valid_attempt: {
        permit_jws: string;
        action: CanonicalActionV2Input;
        dpop_proof: string;
        dpop_htm: string;
        dpop_htu: string;
        expected_decision: "allow";
        expected_reason: "accepted";
      };
    };
    concurrent_replay_scenario: {
      concurrency: number;
      expected_allows: number;
      expected_nonce_replayed: number;
      jti: string;
      policy: PolicyV2;
      action: CanonicalActionV2Input;
      expected_audience: string;
      now_seconds: number;
      permit_jws: string;
      dpop_proof: string;
      dpop_htm: string;
      dpop_htu: string;
    };
  }>("policy-v2-vectors.json");

  for (const tc of vectors.cases) {
    it(`evaluates ${tc.id} -> ${tc.expected_decision} (${tc.expected_reason})`, async () => {
      const res = await verifyAgentPermitV2({
        permitJws: tc.permit_jws,
        policy: tc.policy,
        expectedAudience: tc.expected_audience,
        action: tc.action,
        jwks: vectors.jwks,
        nowSeconds: tc.now_seconds,
        ...(tc.dpop_proof
          ? {
              dpop: {
                proof: tc.dpop_proof,
                htm: tc.dpop_htm!,
                htu: tc.dpop_htu!,
              },
            }
          : {}),
      });
      expect(res.decision).toBe(tc.expected_decision);
      expect(res.reason).toBe(tc.expected_reason);
    });
  }

  it("executes non_mutating_precheck_scenario without burning the pending jti", async () => {
    const scenario = vectors.non_mutating_precheck_scenario;
    const store = new InMemoryPermitNonceStoreV2();
    const { requestDigest } = hashActionV2(scenario.final_valid_attempt.action);
    store.register({
      jti: scenario.jti,
      requestDigest,
      aud: scenario.expected_audience,
      policyId: scenario.policy.policy_id,
      issuedAt: scenario.now_seconds - 40,
      expiresAt: scenario.now_seconds + 260,
    });

    for (const probe of scenario.invalid_probes) {
      const res = await verifyAgentPermitV2({
        permitJws: probe.permit_jws,
        policy: scenario.policy,
        expectedAudience: scenario.expected_audience,
        action: probe.action,
        jwks: vectors.jwks,
        nowSeconds: scenario.now_seconds,
        dpop: {
          proof: probe.dpop_proof,
          htm: probe.dpop_htm,
          htu: probe.dpop_htu,
        },
        nonceStore: store,
        requireRegisteredNonce: true,
      });
      expect(res.decision, probe.id).toBe("deny");
      expect(res.reason, probe.id).toBe(probe.expected_reason);
      // Pending nonce must remain completely unconsumed.
      expect(store.peek(scenario.jti)?.consumedAt).toBeNull();
    }

    const validRes = await verifyAgentPermitV2({
      permitJws: scenario.final_valid_attempt.permit_jws,
      policy: scenario.policy,
      expectedAudience: scenario.expected_audience,
      action: scenario.final_valid_attempt.action,
      jwks: vectors.jwks,
      nowSeconds: scenario.now_seconds,
      dpop: {
        proof: scenario.final_valid_attempt.dpop_proof,
        htm: scenario.final_valid_attempt.dpop_htm,
        htu: scenario.final_valid_attempt.dpop_htu,
      },
      nonceStore: store,
      requireRegisteredNonce: true,
    });
    expect(validRes.decision).toBe("allow");
    expect(validRes.reason).toBe("accepted");
    expect(store.peek(scenario.jti)?.consumedAt).toBe(scenario.now_seconds);
  });

  it("enforces atomic 1-of-32 settlement under concurrent jti replay storm", async () => {
    const scenario = vectors.concurrent_replay_scenario;
    const store = new InMemoryPermitNonceStoreV2();
    const { requestDigest } = hashActionV2(scenario.action);
    store.register({
      jti: scenario.jti,
      requestDigest,
      aud: scenario.expected_audience,
      policyId: scenario.policy.policy_id,
      issuedAt: scenario.now_seconds - 40,
      expiresAt: scenario.now_seconds + 260,
    });

    const results = await Promise.all(
      Array.from({ length: scenario.concurrency }, () =>
        verifyAgentPermitV2({
          permitJws: scenario.permit_jws,
          policy: scenario.policy,
          expectedAudience: scenario.expected_audience,
          action: scenario.action,
          jwks: vectors.jwks,
          nowSeconds: scenario.now_seconds,
          dpop: {
            proof: scenario.dpop_proof,
            htm: scenario.dpop_htm,
            htu: scenario.dpop_htu,
          },
          nonceStore: store,
          requireRegisteredNonce: true,
        }),
      ),
    );

    const allows = results.filter((r) => r.decision === "allow");
    const replays = results.filter(
      (r) => r.decision === "deny" && r.reason === "nonce_replayed",
    );
    expect(allows).toHaveLength(scenario.expected_allows);
    expect(replays).toHaveLength(scenario.expected_nonce_replayed);
  });
});
