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
  signMrtrRequestState,
  verifyMrtrRequestState,
  type MrtrRequestStateClaims,
} from "../src/mcp/mrtr";
import {
  canonicalizeJcs,
  CanonicalJsonError,
  hashActionV2,
  parseStrictJson,
} from "../src/permit/canonical";
import {
  createPermitApiClient,
} from "../src/permit/client";
import {
  base64Encode,
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
import {
  createVoiceLivenessClient,
  type VoiceAudioCodec,
  type WebSocketLike,
} from "../src/voice/client";
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

  it("derives exact v2 challenge hex and base64url", () => {
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

describe("Shared parity vectors: Wire contracts & MRTR requestState (wire-contracts.json)", () => {
  const wire = loadVectorFile<{
    voice_analyze: {
      path: string;
      audio_hex: string;
      audio_b64_standard: string;
      codec_mappings: Array<{
        sdk_codec: VoiceAudioCodec;
        wire_encoding: string;
        sample_rate_hz: number | null;
      }>;
    };
    voice_stream: {
      path: string;
      default_query_adapter: string;
      auth_header: string;
      auth_scheme: string;
      forbidden_subprotocol_prefix: string;
      start_frame_example: {
        type: "start";
        session_id: string;
        codec: string;
        sample_rate_hz: number;
        operating_profile: string;
      };
      control_frames: Record<string, { type: string }>;
      inbound_error_variants: Array<{
        type: "error";
        code?: string;
        error_code?: string;
        message: string;
      }>;
    };
    permits_issue: {
      path: string;
      default_ttl_seconds: number;
      canonical_action: CanonicalActionV2Input;
      expected_request_digest: string;
      response_200_issued: Record<string, unknown>;
      response_202_step_up_required: Record<string, unknown>;
    };
    permits_step_up: {
      path: string;
      create_status: number;
      create_response_201: Record<string, unknown>;
      poll_request: { operation: "poll"; jti: string };
      poll_response_pending: Record<string, unknown>;
      poll_response_completed: Record<string, unknown>;
      complete_response_200: Record<string, unknown>;
    };
    permits_verify: {
      path: string;
      response_200_allow: Record<string, unknown>;
      response_403_deny: Record<string, unknown>;
      response_409_replay: Record<string, unknown>;
    };
    permits_receipt: {
      valid_jti: string;
      invalid_jtis: string[];
    };
    mrtr_request_state: {
      secret_utf8: string;
      short_secret_utf8: string;
      claims: MrtrRequestStateClaims;
      now_valid: number;
      now_expired: number;
      expected_token: string;
    };
  }>("wire-contracts.json");

  const jwsVectors = loadVectorFile<{
    now_seconds: number;
    jwks: JwksDocument;
    valid_voice_verdict: { jws: string };
  }>("jws-eddsa-vectors.json");

  it("matches exact MRTR requestState HMAC-SHA256 token byte-for-byte with Python/Rust", () => {
    const mrtr = wire.mrtr_request_state;
    const token = signMrtrRequestState(mrtr.claims, mrtr.secret_utf8);
    expect(token).toBe(mrtr.expected_token);

    const verified = verifyMrtrRequestState(
      mrtr.expected_token,
      mrtr.secret_utf8,
      mrtr.now_valid,
    );
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.claims).toEqual(mrtr.claims);
    }

    const expired = verifyMrtrRequestState(
      mrtr.expected_token,
      mrtr.secret_utf8,
      mrtr.now_expired,
    );
    expect(expired.ok).toBe(false);

    expect(() =>
      signMrtrRequestState(mrtr.claims, mrtr.short_secret_utf8),
    ).toThrow(/at least 32 bytes/);
  });

  it("encodes standard Base64 audio_b64 and maps all voice analyze codecs to b2b-api wire contract", async () => {
    const audioBytes = new Uint8Array(
      wire.voice_analyze.audio_hex.match(/.{2}/g)!.map((h) => Number.parseInt(h, 16)),
    );
    expect(base64Encode(audioBytes)).toBe(wire.voice_analyze.audio_b64_standard);

    for (const mapping of wire.voice_analyze.codec_mappings) {
      let seenBody: Record<string, unknown> | null = null;
      let seenUrl = "";
      const client = createVoiceLivenessClient({
        baseUrl: "https://api.entros.io",
        apiKey: "entros_test_key",
        fetch: (async (url: RequestInfo | URL, init?: RequestInit) => {
          seenUrl = String(url);
          seenBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
          return new Response(
            JSON.stringify({
              request_id: "req_wire_codec",
              verdict: "likely_human",
              verdict_jws: jwsVectors.valid_voice_verdict.jws,
              inference_ms: 14.2,
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }) as typeof fetch,
      });

      const res = await client.analyze({
        sessionId: "lk_room_bank_8831_caller_01",
        audio: audioBytes,
        codec: mapping.sdk_codec,
        operatingProfile: "wideband_clean",
        verifyWithJwks: jwsVectors.jwks,
        nowSeconds: jwsVectors.now_seconds,
      });
      expect(seenUrl).toBe(`https://api.entros.io${wire.voice_analyze.path}`);
      expect(seenBody).not.toBeNull();
      expect(seenBody!["audio_b64"]).toBe(wire.voice_analyze.audio_b64_standard);
      expect(seenBody!["encoding"]).toBe(mapping.wire_encoding);
      if (mapping.sample_rate_hz === null) {
        expect("sample_rate_hz" in seenBody!).toBe(false);
      } else {
        expect(seenBody!["sample_rate_hz"]).toBe(mapping.sample_rate_hz);
      }
      expect(res.inferenceMs).toBe(14.2);
      expect(res.verdict?.verdict).toBe("likely_human");
    }
  });

  it("aligns WebSocket stream Authorization header, start/control frames, and inbound error variants", async () => {
    const sentFrames: Array<string | Uint8Array | ArrayBuffer> = [];
    const seenHeaders: Record<string, string>[] = [];
    const seenUrls: string[] = [];
    const target = new EventTarget();

    class WireFakeWs implements WebSocketLike {
      readyState = 1;
      send(data: string | Uint8Array | ArrayBuffer) {
        sentFrames.push(data);
      }
      close() {}
      addEventListener(type: string, listener: (ev: unknown) => void) {
        target.addEventListener(type, listener as EventListener);
      }
    }

    const errors: Array<{ code: string; serverCode?: string; message: string }> = [];
    const client = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      apiKey: "secret-api-key",
      webSocketFactory: (url, opts) => {
        seenUrls.push(url);
        seenHeaders.push(opts.headers);
        expect("protocols" in opts).toBe(false);
        return new WireFakeWs();
      },
    });

    const stream = client.connectStream({
      sessionId: wire.voice_stream.start_frame_example.session_id,
      codec: "pcm16_16k",
      operatingProfile: "telephony_8k",
      onVerdict: () => {},
      onError: (err) =>
        errors.push({
          code: err.code,
          serverCode: err.serverCode,
          message: err.message,
        }),
    });

    expect(seenUrls[0]).toBe(
      `wss://api.entros.io${wire.voice_stream.path}?adapter=${wire.voice_stream.default_query_adapter}`,
    );
    expect(seenHeaders[0]?.[wire.voice_stream.auth_header]).toBe(
      `${wire.voice_stream.auth_scheme} secret-api-key`,
    );
    expect(JSON.parse(String(sentFrames[0]))).toEqual(
      wire.voice_stream.start_frame_example,
    );

    stream.flush();
    stream.pause();
    stream.resume();
    stream.stop();
    expect(JSON.parse(String(sentFrames[1]))).toEqual(
      wire.voice_stream.control_frames.flush,
    );
    expect(JSON.parse(String(sentFrames[2]))).toEqual(
      wire.voice_stream.control_frames.pause,
    );
    expect(JSON.parse(String(sentFrames[3]))).toEqual(
      wire.voice_stream.control_frames.resume,
    );
    expect(JSON.parse(String(sentFrames[4]))).toEqual(
      wire.voice_stream.control_frames.stop,
    );

    for (const errFrame of wire.voice_stream.inbound_error_variants) {
      target.dispatchEvent(
        new MessageEvent("message", { data: JSON.stringify(errFrame) }),
      );
    }
    expect(errors).toHaveLength(2);
    expect(errors[0]?.code).toBe("stream_error");
    expect(errors[0]?.serverCode).toBe("frame_too_large");
    expect(errors[1]?.serverCode).toBe("session_rate_limited");
  });

  it("aligns PermitApiClient issue (200/202), step-up (create/poll/complete), verify (200/403/409), and receipt jti validation", async () => {
    expect(hashActionV2(wire.permits_issue.canonical_action).requestDigest).toBe(
      wire.permits_issue.expected_request_digest,
    );

    const policy: PolicyV2 = {
      policy_id: "pol_wire_v2",
      version: 2,
      allowed_assurance_tiers: ["voice_liveness_webrtc"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      required_modalities: ["voice_liveness"],
      require_continuity: false,
      require_dpop: false,
      require_scitt_receipt: false,
    };

    const requests: Array<{ url: string; body: Record<string, unknown> | null }> = [];
    const responses: Array<{ status: number; body: Record<string, unknown> }> = [
      { status: 200, body: wire.permits_issue.response_200_issued },
      { status: 202, body: wire.permits_issue.response_202_step_up_required },
      { status: wire.permits_step_up.create_status, body: wire.permits_step_up.create_response_201 },
      { status: 200, body: wire.permits_step_up.poll_response_pending },
      { status: 200, body: wire.permits_step_up.poll_response_completed },
      { status: 200, body: wire.permits_step_up.complete_response_200 },
      { status: 200, body: wire.permits_verify.response_200_allow },
      { status: 403, body: wire.permits_verify.response_403_deny },
      { status: 409, body: wire.permits_verify.response_409_replay },
    ];
    let idx = 0;

    const api = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      apiKey: "entros_api_key",
      fetch: (async (url: RequestInfo | URL, init?: RequestInit) => {
        requests.push({
          url: String(url),
          body: init?.body
            ? (JSON.parse(String(init.body)) as Record<string, unknown>)
            : null,
        });
        const next = responses[idx++]!;
        return new Response(JSON.stringify(next.body), {
          status: next.status,
          headers: { "content-type": "application/json" },
        });
      }) as typeof fetch,
    });

    const issued = await api.issuePermit({
      sub: "usr_01",
      actor: { id: "spiffe://acme/agent" },
      aud: "https://mcp.example.com/tools",
      action: wire.permits_issue.canonical_action,
      policy,
      evidence: { voice_verdict_jws: jwsVectors.valid_voice_verdict.jws },
    });
    expect(issued.status).toBe("issued");
    expect(requests[0]?.body?.["ttl_seconds"]).toBe(
      wire.permits_issue.default_ttl_seconds,
    );

    const stepUpReq = await api.issuePermit({
      sub: "usr_01",
      actor: { id: "spiffe://acme/agent" },
      aud: "https://mcp.example.com/tools",
      action: wire.permits_issue.canonical_action,
      policy,
      evidence: {},
    });
    expect(stepUpReq.status).toBe("step_up_required");

    const created = await api.createStepUp({
      protocol: "mcp_mrtr",
      sub: "usr_01",
      actor: { id: "spiffe://acme/agent" },
      aud: "https://mcp.example.com/tools",
      request_digest: wire.permits_issue.expected_request_digest,
      policy_id: "pol_wire_v2",
    });
    expect(requests[2]?.body?.["operation"]).toBe("create");
    expect(created.protocol).toBe("mcp_mrtr");

    const pollPending = await api.pollStepUp(wire.permits_step_up.poll_request.jti);
    expect(requests[3]?.body).toEqual(wire.permits_step_up.poll_request);
    expect(pollPending.status).toBe("pending");

    const pollDone = await api.pollStepUp(wire.permits_step_up.poll_request.jti);
    expect(pollDone.status).toBe("completed");

    const completed = await api.completeStepUp({
      jti: wire.permits_step_up.poll_request.jti,
      webauthn_assertion: {
        credential_id: "cred_1",
        authenticator_data: "AQID",
        client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
        signature: "MEUC",
      },
      public_key: "04" + "11".repeat(64),
      expected_rp_id: "approve.entros.io",
      expected_origin: "https://approve.entros.io",
    });
    expect(requests[5]?.body?.["operation"]).toBe("complete");
    expect(completed.jti).toBe(wire.permits_step_up.poll_request.jti);
    expect(completed.assurance_tier).toBe("voice_plus_passkey");

    const verifiedAllow = await api.verifyPermitOnline({
      permit_jws: "header.payload.sig",
      expected_aud: "https://mcp.example.com/tools",
      action: wire.permits_issue.canonical_action,
      policy,
    });
    expect(verifiedAllow.verified).toBe(true);
    expect(verifiedAllow.reason).toBeNull();

    const verified403 = await api.verifyPermitOnline({
      permit_jws: "header.payload.sig",
      expected_aud: "https://mcp.example.com/tools",
      action: wire.permits_issue.canonical_action,
      policy,
    });
    expect(verified403.verified).toBe(false);
    expect(verified403.reason).toBe("assurance_downgrade");

    const verified409 = await api.verifyPermitOnline({
      permit_jws: "header.payload.sig",
      expected_aud: "https://mcp.example.com/tools",
      action: wire.permits_issue.canonical_action,
      policy,
    });
    expect(verified409.verified).toBe(false);
    expect(verified409.reason).toBe("nonce_replayed");

    for (const badJti of wire.permits_receipt.invalid_jtis) {
      await expect(api.fetchScittReceipt(badJti)).rejects.toThrow(
        /64-char lowercase hex/,
      );
    }
  });
});
