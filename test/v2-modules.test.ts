// @vitest-environment node
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import {
  collectPassiveBrowserSignals,
  createPassiveBrowserSignalEnvelope,
  isPassiveBrowserSignalEnvelope,
  PASSIVE_BROWSER_RISK_TIER,
} from "../src/browser-signals";
import { createEntrosClient, evaluatePolicyV2 } from "../src/index";
import {
  createLiveKitToolGuard,
  createRetellWebhookGuard,
  createStatelessMcpApprovalGate,
  createUrlElicitationChallenge,
  createV2ChallengeFromOpenAiMcpRequest,
  createVapiWebhookGuard,
  createVercelToolApprovalGate,
  formatInsufficientScopeHeader,
  InMemoryPermitNonceStoreV2,
  settleOpenAiMcpApprovalV2,
  signMrtrRequestState,
  verifyMrtrRequestState,
} from "../src/mcp";
import {
  base64Encode,
  base64UrlDecodeStrict,
  base64UrlEncode,
  canonicalizeJcs,
  CanonicalJsonError,
  computeJwkThumbprint,
  createJwksCache,
  createPermitApiClient,
  hashActionV2,
  InMemoryDpopJtiStore,
  parseStrictJson,
  verifyAgentPermitV2,
  verifyDpopProofV2,
  verifyEdDsaJws,
  verifyScittReceipt,
  verifyWebAuthnAssertionV2,
  type CanonicalActionV2Input,
  type JwksDocument,
  type PolicyV2,
} from "../src/permit";
import {
  createVoiceLivenessClient,
  VoiceClientError,
  type VoiceClientDebugEvent,
  type WebSocketLike,
} from "../src/voice";

const VECTORS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../spec/vectors/agent-permit-v2",
);

const jwsVectors = JSON.parse(
  readFileSync(resolve(VECTORS_DIR, "jws-eddsa-vectors.json"), "utf-8"),
) as {
  now_seconds: number;
  jwks: JwksDocument;
  valid_voice_verdict: { jws: string };
  valid_voice_abstain: { jws: string };
  valid_agent_permit: { jws: string; expected_claims: { jti: string; request_digest: string } };
};

const policyVectors = JSON.parse(
  readFileSync(resolve(VECTORS_DIR, "policy-v2-vectors.json"), "utf-8"),
) as {
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
  }>;
  concurrent_replay_scenario: {
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
};

const webauthnVectors = JSON.parse(
  readFileSync(resolve(VECTORS_DIR, "webauthn-p256-vectors.json"), "utf-8"),
) as {
  challenge_derivation: {
    jti: string;
    request_digest: string;
    expected_challenge_b64url: string;
  };
  public_key: { jwk: { kty: "EC"; crv: "P-256"; x: string; y: string } };
  expected_rp_id: string;
  expected_origin: string;
  valid: Array<{
    id: string;
    assertion: {
      credential_id: string;
      authenticator_data: string;
      client_data_json: string;
      signature: string;
    };
  }>;
};

describe("JwksCache TTL, negative cache floor, revocation, and failure handling", () => {
  it("enforces <= 300s TTL, >= 10s negative cache, single refresh on unknown kid, and revoked status", async () => {
    expect(() =>
      createJwksCache({
        jwksUrl: "http://example.com/.well-known/jwks.json",
      }),
    ).toThrow();
    expect(() =>
      createJwksCache({
        jwksUrl: "https://api.entros.io/.well-known/jwks.json",
        ttlSeconds: 301,
      }),
    ).toThrow();
    expect(() =>
      createJwksCache({
        jwksUrl: "https://api.entros.io/.well-known/jwks.json",
        negativeCacheSeconds: 9,
      }),
    ).toThrow();

    let now = 1795450000;
    let fetchCount = 0;
    let currentKeys = jwsVectors.jwks.keys.filter(
      (k) => k.kid === "entros-voice-2026-11-a",
    );

    const mockFetch = vi.fn(async () => {
      fetchCount += 1;
      return new Response(JSON.stringify({ keys: currentKeys }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    const cache = createJwksCache({
      jwksUrl: "https://api.entros.io/.well-known/jwks.json",
      ttlSeconds: 300,
      negativeCacheSeconds: 10,
      fetch: mockFetch as unknown as typeof fetch,
      nowSeconds: () => now,
    });

    const hit1 = await cache.resolveEd25519Key("entros-voice-2026-11-a");
    expect(hit1.status).toBe("found");
    expect(fetchCount).toBe(1);

    // Unknown kid within 10s negative cache floor must NOT hammer origin.
    const miss1 = await cache.resolveEd25519Key("entros-permit-2026-11-a");
    expect(miss1.status).toBe("unknown");
    expect(fetchCount).toBe(1);

    // Advance 11 seconds; rotate key into JWKS and trigger single refresh.
    now += 11;
    currentKeys = jwsVectors.jwks.keys;
    const hit2 = await cache.resolveEd25519Key("entros-permit-2026-11-a");
    expect(hit2.status).toBe("found");
    expect(fetchCount).toBe(2);

    const revoked = await cache.resolveEd25519Key("entros-revoked-2026-11-a");
    expect(revoked.status).toBe("revoked");
  });

  it("maps JWKS and nonce-store infrastructure errors to state_unavailable", async () => {
    const scenario = policyVectors.concurrent_replay_scenario;
    const brokenCache = createJwksCache({
      jwksUrl: "https://api.entros.io/.well-known/jwks.json",
      fetch: (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });
    const jwksDown = await verifyAgentPermitV2({
      permitJws: scenario.permit_jws,
      policy: scenario.policy,
      expectedAudience: scenario.expected_audience,
      action: scenario.action,
      jwks: brokenCache,
      nowSeconds: scenario.now_seconds,
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
    });
    expect(jwksDown.decision).toBe("unavailable");
    expect(jwksDown.reason).toBe("state_unavailable");

    const storeDown = await verifyAgentPermitV2({
      permitJws: scenario.permit_jws,
      policy: scenario.policy,
      expectedAudience: scenario.expected_audience,
      action: scenario.action,
      jwks: policyVectors.jwks,
      nowSeconds: scenario.now_seconds,
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
      nonceStore: {
        register: () => {},
        peek: () => null,
        consume: async () => {
          throw new Error("Redis timeout");
        },
      },
    });
    expect(storeDown.decision).toBe("unavailable");
    expect(storeDown.reason).toBe("state_unavailable");
  });
});

describe("VoiceLivenessClient REST + WebSocket with zero audio leakage", () => {
  it("analyzes PCM16/Opus/mulaw audio, verifies returned verdict JWS, and never leaks audio in errors/debug", async () => {
    const secretAudio = new Uint8Array(256);
    for (let i = 0; i < secretAudio.length; i += 1) {
      secretAudio[i] = (i * 17 + 3) & 0xff;
    }
    const secretAudioB64 = base64Encode(secretAudio);
    const debugEvents: VoiceClientDebugEvent[] = [];

    const mockFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const parsed = JSON.parse(String(init?.body)) as {
        audio_b64: string;
        encoding: string;
        sample_rate_hz: number;
      };
      expect(parsed.audio_b64).toBe(secretAudioB64);
      expect(parsed.encoding).toBe("pcm16");
      expect(parsed.sample_rate_hz).toBe(16000);
      return new Response(
        JSON.stringify({
          verdict_jws: jwsVectors.valid_voice_verdict.jws,
          request_id: "req_voice_01",
          verdict: "likely_human",
          inference_ms: 11.4,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });

    const client = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      apiKey: "test-key",
      fetch: mockFetch as unknown as typeof fetch,
      onDebug: (ev) => debugEvents.push(ev),
    });

    const res = await client.analyze({
      sessionId: "lk_room_bank_8831_caller_01",
      audio: secretAudio,
      codec: "pcm16_16k",
      verifyWithJwks: jwsVectors.jwks,
      nowSeconds: jwsVectors.now_seconds,
    });
    expect(res.verdict?.verdict).toBe("likely_human");
    expect(res.requestId).toBe("req_voice_01");
    // Debug events must contain zero raw audio or base64 strings.
    expect(JSON.stringify(debugEvents)).not.toContain(secretAudioB64.slice(0, 32));

    // Error transport containing a long base64 token must redact it.
    const failingClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () => {
        throw new Error(`socket failed with payload ${secretAudioB64}`);
      }) as unknown as typeof fetch,
    });
    await expect(
      failingClient.analyze({
        sessionId: "sess_err",
        audio: secretAudio,
        codec: "mulaw_8k",
      }),
    ).rejects.toThrow("[redacted]");
  });

  it("streams binary audio over WebSocket and verifies rolling verdict frames from real MessageEvent and CloseEvent instances", async () => {
    const sent: Array<string | Uint8Array | ArrayBuffer> = [];
    const target = new EventTarget();

    class FakeWebSocket implements WebSocketLike {
      readyState = 1;
      constructor(
        public readonly url: string,
        public readonly protocols?:
          | string
          | string[]
          | { headers?: Record<string, string> },
      ) {}
      send(data: string | Uint8Array | ArrayBuffer) {
        sent.push(data);
      }
      close(code?: number, reason?: string) {
        target.dispatchEvent(
          new CloseEvent("close", {
            code: code ?? 1000,
            reason: reason ?? "normal_shutdown",
          }),
        );
      }
      addEventListener(type: string, listener: (ev: unknown) => void) {
        target.addEventListener(type, listener as EventListener);
      }
    }

    const client = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      webSocketCtor: FakeWebSocket,
    });

    const verdicts: string[] = [];
    const closeEvents: Array<{ code?: number; reason?: string }> = [];
    const stream = client.connectStream({
      sessionId: "lk_room_bank_8831_caller_01",
      codec: "opus_16k",
      verifyWithJwks: jwsVectors.jwks,
      nowSeconds: jwsVectors.now_seconds,
      onVerdict: ({ claims }) => {
        if (claims) verdicts.push(claims.verdict);
      },
      onClose: (info) => closeEvents.push(info),
    });

    stream.sendAudioChunk(new Uint8Array([1, 2, 3, 4]));
    stream.flush();

    const frameJson = JSON.stringify({
      verdict_jws: jwsVectors.valid_voice_verdict.jws,
    });
    // Dispatch real DOM/Node MessageEvent (string payload) and binary Uint8Array/ArrayBuffer payloads.
    target.dispatchEvent(new MessageEvent("message", { data: frameJson }));
    const encoded = new TextEncoder().encode(frameJson);
    target.dispatchEvent(new MessageEvent("message", { data: encoded }));
    target.dispatchEvent(
      new MessageEvent("message", { data: encoded.buffer.slice(0) }),
    );

    await new Promise((r) => setTimeout(r, 30));
    expect(verdicts).toEqual(["likely_human", "likely_human", "likely_human"]);
    expect(JSON.parse(String(sent[0]))).toEqual({
      type: "start",
      session_id: "lk_room_bank_8831_caller_01",
      codec: "opus",
      sample_rate_hz: 16000,
      operating_profile: "webrtc_16k",
    });
    expect(sent[1]).toBeInstanceOf(Uint8Array);
    expect(JSON.parse(String(sent[2]))).toEqual({ type: "flush" });
    stream.close(1000, "stream_complete");
    expect(stream.closed).toBe(true);
    expect(closeEvents).toEqual([{ code: 1000, reason: "stream_complete" }]);
  });
});

describe("MCP 2026-07-28 MRTR, SEP-1036, HTTP 403, OpenAI v2, Vercel toolApproval, and Voice webhook guards", () => {
  const scenario = policyVectors.concurrent_replay_scenario;
  const secret = "0123456789abcdef0123456789abcdef-mrtr-secret";

  it("runs stateless MCP 2026-07-28 MRTR across two independent server replicas", async () => {
    const sharedNonceStore = new InMemoryPermitNonceStoreV2();
    const replicaA = createStatelessMcpApprovalGate({
      audience: scenario.expected_audience,
      policy: scenario.policy,
      jwks: policyVectors.jwks,
      stateSecret: secret,
      nonceStore: sharedNonceStore,
      nowSeconds: scenario.now_seconds,
    });
    const replicaB = createStatelessMcpApprovalGate({
      audience: scenario.expected_audience,
      policy: scenario.policy,
      jwks: policyVectors.jwks,
      stateSecret: secret,
      nonceStore: sharedNonceStore,
      nowSeconds: scenario.now_seconds,
    });

    const round1 = await replicaA.createInputRequiredResult({
      action: scenario.action,
      jti: scenario.jti,
      summary: "Approve $250 USD wire transfer to acct_9942",
    });
    expect(round1.resultType).toBe("input_required");
    expect(round1.inputRequests[0].mode).toBe("url");
    expect(round1.inputRequests[0].cacheable).toBe(false);

    // Tampered requestState HMAC must fail.
    const badState = verifyMrtrRequestState(
      `${round1.requestState.slice(0, -2)}AA`,
      secret,
      scenario.now_seconds,
    );
    expect(badState.ok).toBe(false);

    // Round 2 with tampered arguments fails request_digest_mismatch without burning jti.
    const tamperedRound2 = await replicaB.verifyInputResponse({
      action: {
        ...scenario.action,
        arguments: { ...scenario.action.arguments, amount: 99999 },
      },
      requestState: round1.requestState,
      inputResponses: [
        { elicitationId: scenario.jti, permit_jws: scenario.permit_jws },
      ],
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
    });
    expect(tamperedRound2.decision).toBe("deny");
    expect(tamperedRound2.reason).toBe("request_digest_mismatch");

    // Legitimate Round 2 on Replica B succeeds once and rejects replay.
    const okRound2 = await replicaB.verifyInputResponse({
      action: scenario.action,
      requestState: round1.requestState,
      inputResponses: [
        { elicitationId: scenario.jti, permit_jws: scenario.permit_jws },
      ],
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
    });
    expect(okRound2.decision).toBe("allow");

    const replayRound2 = await replicaB.verifyInputResponse({
      action: scenario.action,
      requestState: round1.requestState,
      inputResponses: [
        { elicitationId: scenario.jti, permit_jws: scenario.permit_jws },
      ],
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
    });
    expect(replayRound2.decision).toBe("deny");
    expect(replayRound2.reason).toBe("nonce_replayed");

    // Also validate signMrtrRequestState direct helper round-trip.
    const directToken = signMrtrRequestState(
      {
        v: 2,
        jti: scenario.jti,
        request_digest: hashActionV2(scenario.action).requestDigest,
        aud: scenario.expected_audience,
        policy_id: scenario.policy.policy_id,
        iat: scenario.now_seconds,
        exp: scenario.now_seconds + 120,
      },
      secret,
    );
    expect(verifyMrtrRequestState(directToken, secret, scenario.now_seconds).ok).toBe(
      true,
    );
  });

  it("formats SEP-1036 URL-Mode Elicitation and HTTP 403 insufficient_scope with scope-union", () => {
    const elicit = createUrlElicitationChallenge({
      jti: scenario.jti,
      approvalUrl: `https://approve.entros.io/step-up/${scenario.jti}`,
      message: "Confirm $250 transfer with Passkey",
    });
    expect(elicit.method).toBe("elicitation/create");
    expect(elicit.params.mode).toBe("url");
    expect(elicit.params.elicitationId).toBe(scenario.jti);

    const header = formatInsufficientScopeHeader({
      existingScopes: "mcp:tools:read mcp:tools:write mcp:tools:read",
      resourceMetadataUrl:
        "https://mcp.acme-bank.example/.well-known/oauth-protected-resource",
    });
    expect(header).toBe(
      'Bearer error="insufficient_scope", scope="mcp:tools:read mcp:tools:write entros:permit:step_up", resource_metadata="https://mcp.acme-bank.example/.well-known/oauth-protected-resource"',
    );
  });

  it("handles OpenAI Responses v2 and Vercel AI SDK toolApproval ('user-approval')", async () => {
    const openaiReq = {
      type: "mcp_approval_request" as const,
      id: "mcpr_v2_01",
      server_label: scenario.action.server,
      name: scenario.action.tool,
      arguments: JSON.stringify(scenario.action.arguments),
    };
    const envelope = await createV2ChallengeFromOpenAiMcpRequest(openaiReq, {
      audience: scenario.expected_audience,
      policy: scenario.policy,
      jwks: policyVectors.jwks,
      stateSecret: secret,
      nowSeconds: scenario.now_seconds,
    });
    expect(envelope.inputRequired.resultType).toBe("input_required");

    const settled = await settleOpenAiMcpApprovalV2({
      approvalRequest: openaiReq,
      permitJws: scenario.permit_jws,
      policy: scenario.policy,
      expectedAudience: scenario.expected_audience,
      jwks: policyVectors.jwks,
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
      nowSeconds: scenario.now_seconds,
    });
    expect(settled.response).toEqual({
      type: "mcp_approval_response",
      approval_request_id: "mcpr_v2_01",
      approve: true,
    });

    const vercelGate = createVercelToolApprovalGate({
      audience: scenario.expected_audience,
      policy: scenario.policy,
      jwks: policyVectors.jwks,
      nowSeconds: scenario.now_seconds,
    });
    expect(vercelGate.toolApproval).toBe("user-approval");
    const wrapped = vercelGate.wrapTool({
      server: scenario.action.server,
      tool: scenario.action.tool,
      execute: async (args) => ({ transferred: args.amount }),
    });
    expect(wrapped.toolApproval).toBe("user-approval");
    expect("needsApproval" in wrapped).toBe(false);

    const execOk = await wrapped.execute(scenario.action.arguments, {
      permitJws: scenario.permit_jws,
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
    });
    expect(execOk.ok).toBe(true);
    if (execOk.ok) {
      expect(execOk.result).toEqual({ transferred: 250 });
    }
  });

  it("guards LiveKit, Vapi, and Retell voice tool calls and routes abstention to step-up", async () => {
    const stepUpFetch = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          jti: scenario.jti,
          protocol: "oidc_ciba",
          approval_url: `https://approve.entros.io/step-up/${scenario.jti}`,
          challenge_b64url:
            webauthnVectors.challenge_derivation.expected_challenge_b64url,
          expires_at: scenario.now_seconds + 180,
          ciba: {
            auth_req_id: "ciba_req_01",
            expires_in: 180,
            interval: 2,
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    const permitClient = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      fetch: stepUpFetch as unknown as typeof fetch,
    });
    const voiceOnlyPolicy = policyVectors.cases.find(
      (c) => c.id === "allow-voice-liveness-webrtc",
    )!.policy;

    const livekitGuard = createLiveKitToolGuard({
      server: "voice-banking",
      audience: scenario.expected_audience,
      policy: voiceOnlyPolicy,
      jwks: policyVectors.jwks,
      permitClient,
      nowSeconds: scenario.now_seconds,
    });
    const abstainRes = await livekitGuard.guardToolCall({
      roomName: "bank_room",
      participantIdentity: "caller_01",
      sessionId: "lk_room_bank_8831_caller_01",
      toolName: "transfer_funds",
      args: { amount: 250 },
      voiceVerdictJws: jwsVectors.valid_voice_abstain.jws,
      sub: "usr_01",
      actor: { id: "spiffe://acme/voice-agent" },
    });
    expect(abstainRes.status).toBe("step_up_required");
    if (abstainRes.status === "step_up_required") {
      expect(abstainRes.reason).toBe("voice_insufficient_signal");
      expect(abstainRes.stepUp?.ciba?.auth_req_id).toBe("ciba_req_01");
    }

    const vapiGuard = createVapiWebhookGuard({
      server: "voice-banking",
      audience: scenario.expected_audience,
      policy: voiceOnlyPolicy,
      jwks: policyVectors.jwks,
      nowSeconds: scenario.now_seconds,
    });
    const vapiRes = await vapiGuard.guardWebhook({
      payload: {
        message: {
          type: "tool-calls",
          call: { id: "lk_room_bank_8831_caller_01" },
          toolCallList: [
            { id: "tc_1", name: "transfer_funds", arguments: { amount: 250 } },
          ],
        },
      },
      voiceVerdictJws: jwsVectors.valid_voice_verdict.jws,
    });
    expect(vapiRes).toHaveLength(1);
    expect(vapiRes[0]?.result.status).toBe("permit_required");

    const retellGuard = createRetellWebhookGuard({
      server: "voice-banking",
      audience: scenario.expected_audience,
      policy: voiceOnlyPolicy,
      jwks: policyVectors.jwks,
      nowSeconds: scenario.now_seconds,
    });
    const retellRes = await retellGuard.guardWebhook({
      payload: {
        call: { call_id: "lk_room_bank_8831_caller_01" },
        name: "transfer_funds",
        args: { amount: 250 },
      },
      voiceVerdictJws: jwsVectors.valid_voice_abstain.jws,
    });
    expect(retellRes.status).toBe("step_up_required");
  });
});

describe("Browser signals, EntrosClient, and React EntrosPasskeyApprove", () => {
  it("tags passive browser telemetry as passive_browser_risk with standalone_consent=false", () => {
    const signals = collectPassiveBrowserSignals({
      navigator: {
        webdriver: false,
        hardwareConcurrency: 8,
        maxTouchPoints: 0,
        credentials: { get: () => Promise.resolve(null) },
      },
      window: {
        innerWidth: 1440,
        innerHeight: 900,
        isSecureContext: true,
      },
    });
    const envelope = createPassiveBrowserSignalEnvelope(signals, {
      nowSeconds: 1795450150,
    });
    expect(envelope.assurance_tier).toBe(PASSIVE_BROWSER_RISK_TIER);
    expect(envelope.standalone_consent).toBe(false);
    expect(isPassiveBrowserSignalEnvelope(envelope)).toBe(true);

    // Pure Policy v2 evaluator must never accept passive_browser_risk for Passkey policy.
    const passkeyCase = policyVectors.cases.find(
      (c) => c.id === "allow-passkey-webauthn-uv-only",
    )!;
    const evalRes = evaluatePolicyV2({
      permit: {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent" },
        aud: passkeyCase.expected_audience,
        jti: jwsVectors.valid_agent_permit.expected_claims.jti,
        iat: 1795450110,
        exp: 1795450410,
        request_digest: hashActionV2(passkeyCase.action).requestDigest,
        assurance_tier: envelope.assurance_tier,
        modality: ["passive_browser_risk"],
        freshness_verified_at: 1795450100,
        continuity: { session_id: "s1", mode: "stateless" },
        uniqueness_status: "unmeasured",
        voice_verdict_jws: null,
        webauthn_assertion_digest: null,
        policy_id: passkeyCase.policy.policy_id,
        scitt_receipt: null,
      },
      policy: passkeyCase.policy,
      expectedAudience: passkeyCase.expected_audience,
      expectedRequestDigest: hashActionV2(passkeyCase.action).requestDigest,
      nowSeconds: 1795450150,
    });
    expect(evalRes.decision).toBe("deny");
    if (evalRes.decision === "deny") {
      expect(evalRes.reason).toBe("assurance_downgrade");
    }
  });

  it("verifies permits with raw WebAuthn assertion via unified headless EntrosClient", async () => {
    const scenario = policyVectors.concurrent_replay_scenario;
    const lowS = webauthnVectors.valid.find(
      (v) => v.id === "webauthn-valid-low-s",
    )!;
    const client = createEntrosClient({
      baseUrl: "https://api.entros.io",
      jwks: policyVectors.jwks,
      nowSeconds: () => scenario.now_seconds,
    });

    const res = await client.verifyAgentPermitV2({
      permitJws: scenario.permit_jws,
      policy: scenario.policy,
      expectedAudience: scenario.expected_audience,
      action: scenario.action,
      dpop: {
        proof: scenario.dpop_proof,
        htm: scenario.dpop_htm,
        htu: scenario.dpop_htu,
      },
      webauthn: {
        assertion: lowS.assertion,
        publicKey: webauthnVectors.public_key.jwk,
        expectedRpId: webauthnVectors.expected_rp_id,
        expectedOrigin: webauthnVectors.expected_origin,
      },
    });
    expect(res.decision).toBe("allow");
    if (res.decision === "allow") {
      expect(res.webauthn?.userVerified).toBe(true);
      expect(res.scittReceipt?.treeSize).toBe(5);
    }
  });
});

describe("Security hardening regressions (crypto, DPoP, SCITT, WebAuthn, JWKS, voice, guards)", () => {
  const encoder = new TextEncoder();

  function signEd25519Jws(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    secretKey: Uint8Array,
  ): string {
    const h = base64UrlEncode(encoder.encode(canonicalizeJcs(header)));
    const p = base64UrlEncode(encoder.encode(canonicalizeJcs(payload)));
    const sig = ed25519.sign(encoder.encode(`${h}.${p}`), secretKey);
    return `${h}.${p}.${base64UrlEncode(sig)}`;
  }

  function cborUint(major: number, val: number): Uint8Array {
    const prefix = major << 5;
    if (val < 24) return Uint8Array.of(prefix | val);
    if (val < 256) return Uint8Array.of(prefix | 24, val);
    return Uint8Array.of(prefix | 25, (val >> 8) & 0xff, val & 0xff);
  }

  function cborBytes(bytes: Uint8Array): Uint8Array {
    const head = cborUint(2, bytes.length);
    const out = new Uint8Array(head.length + bytes.length);
    out.set(head, 0);
    out.set(bytes, head.length);
    return out;
  }

  function cborText(text: string): Uint8Array {
    const bytes = encoder.encode(text);
    const head = cborUint(3, bytes.length);
    const out = new Uint8Array(head.length + bytes.length);
    out.set(head, 0);
    out.set(bytes, head.length);
    return out;
  }

  function cborNegInt(value: number): Uint8Array {
    return cborUint(1, -1 - value);
  }

  function concatAll(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((acc, p) => acc + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  function buildScittReceipt(opts: {
    secretKey: Uint8Array;
    kid: string;
    statement: Record<string, unknown>;
    extraProtectedEntries?: Uint8Array[];
    duplicateProtectedKey?: boolean;
  }): string {
    const entries: Uint8Array[] = [
      concatAll([cborUint(0, 1), cborNegInt(-8)]), // alg: EdDSA (-8)
      concatAll([cborUint(0, 4), cborBytes(encoder.encode(opts.kid))]),
      concatAll([cborUint(0, 395), cborUint(0, 1)]), // vds: RFC 9162 SHA-256 (1)
      ...(opts.extraProtectedEntries ?? []),
    ];
    if (opts.duplicateProtectedKey) {
      entries.push(concatAll([cborUint(0, 1), cborNegInt(-8)]));
    }
    const protectedBytes = concatAll([cborUint(5, entries.length), ...entries]);
    const payloadBytes = encoder.encode(canonicalizeJcs(opts.statement));

    // Single-leaf RFC 9162 tree: tree_size=1, leaf_index=0, audit_path=[]
    const leafHash = sha256(concatAll([Uint8Array.of(0x00), payloadBytes]));
    const inclusionTuple = concatAll([
      cborUint(4, 3),
      cborUint(0, 1),
      cborUint(0, 0),
      cborUint(4, 0),
    ]);
    const vdpMap = concatAll([cborUint(5, 1), cborNegInt(-1), inclusionTuple]);
    const unprotected = concatAll([cborUint(5, 1), cborUint(0, 396), vdpMap]);

    const sigStructure = concatAll([
      cborUint(4, 4),
      cborText("Signature1"),
      cborBytes(protectedBytes),
      cborBytes(new Uint8Array(0)),
      cborBytes(leafHash),
    ]);
    const sig = ed25519.sign(sigStructure, opts.secretKey);
    const coseSign1 = concatAll([
      Uint8Array.of(0xd2), // Tag 18
      cborUint(4, 4),
      cborBytes(protectedBytes),
      unprotected,
      cborBytes(payloadBytes),
      cborBytes(sig),
    ]);
    return base64UrlEncode(coseSign1);
  }

  it("rejects Ed25519 JWS signatures with a small-order R point", async () => {
    const sk = new Uint8Array(32).fill(7);
    const pk = ed25519.getPublicKey(sk);
    const jwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "k1", x: base64UrlEncode(pk) }],
    };
    const h = base64UrlEncode(
      encoder.encode(canonicalizeJcs({ alg: "EdDSA", typ: "entros-agent-permit+jwt", kid: "k1" })),
    );
    const p = base64UrlEncode(encoder.encode(canonicalizeJcs({ hello: "world" })));
    // Identity point encoding (small order 1): [1, 0, ..., 0] for R and zero S
    const forgedSig = new Uint8Array(64);
    forgedSig[0] = 1;
    const res = await verifyEdDsaJws({
      jws: `${h}.${p}.${base64UrlEncode(forgedSig)}`,
      expectedTyp: "entros-agent-permit+jwt",
      jwks,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("invalid_signature");
    }
  });

  it("rejects WebAuthn signCount rollback to 0 when storedSignCount > 0", () => {
    const priv = new Uint8Array(32).fill(11);
    const pub = p256.getPublicKey(priv, false);
    const rpIdHash = sha256(encoder.encode("approve.entros.io"));
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = 0x05; // UP | UV
    // signCount = 0 (bytes 33..36 all zero)
    const challenge = webauthnVectors.challenge_derivation.expected_challenge_b64url;
    const clientDataBytes = encoder.encode(
      JSON.stringify({
        type: "webauthn.get",
        challenge,
        origin: "https://approve.entros.io",
        crossOrigin: false,
      }),
    );
    const signed = new Uint8Array(authData.length + 32);
    signed.set(authData, 0);
    signed.set(sha256(clientDataBytes), authData.length);
    const derSig = p256.sign(signed, priv, { format: "der", lowS: true, prehash: true });

    const res = verifyWebAuthnAssertionV2({
      assertion: {
        credential_id: base64UrlEncode(new Uint8Array([1, 2, 3, 4])),
        authenticator_data: base64UrlEncode(authData),
        client_data_json: base64UrlEncode(clientDataBytes),
        signature: base64UrlEncode(derSig),
      },
      publicKey: base64UrlEncode(pub),
      expectedRpId: "approve.entros.io",
      expectedOrigin: "https://approve.entros.io",
      expectedChallenge: challenge,
      storedSignCount: 5,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toBe("webauthn_assertion_invalid");
      expect(res.detail).toContain("signCount rollback");
    }
  });

  it("rejects SCITT COSE crit headers, duplicate CBOR map keys, and decision='deny' receipts in Step 28", async () => {
    const sk = new Uint8Array(32).fill(13);
    const pk = ed25519.getPublicKey(sk);
    const kid = "entros-scitt-test-1";
    const jwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid, x: base64UrlEncode(pk) }],
    };
    const action: CanonicalActionV2Input = {
      kind: "mcp.tool_call",
      server: "payments",
      tool: "wire_transfer",
      arguments: { amount: 100 },
    };
    const requestDigest = hashActionV2(action).requestDigest;
    const jti = "c".repeat(64);
    const now = 1795450100;
    const baseStatement = {
      schema: "entros-scitt-permit-v2",
      jti,
      request_digest: requestDigest,
      policy_id: "pol_scitt_deny",
      decision: "allow",
      reason: "accepted",
      assurance_tier: "passkey_webauthn_uv",
      modality: ["passkey_webauthn_uv"],
      aud: "https://mcp.example.com/tools",
      freshness_verified_at: now - 5,
      evaluated_at: now - 2,
      model_version: null,
      retention: "memory_only",
    };

    // COSE protected header label 2 (crit) must fail.
    const critReceipt = buildScittReceipt({
      secretKey: sk,
      kid,
      statement: baseStatement,
      extraProtectedEntries: [
        concatAll([cborUint(0, 2), cborUint(4, 1), cborUint(0, 99)]),
      ],
    });
    const critRes = await verifyScittReceipt({ receipt: critReceipt, jwks });
    expect(critRes.ok).toBe(false);
    if (!critRes.ok) {
      expect(critRes.reason).toBe("scitt_receipt_invalid");
    }

    // Duplicate CBOR map key in protected header must fail.
    const dupReceipt = buildScittReceipt({
      secretKey: sk,
      kid,
      statement: baseStatement,
      duplicateProtectedKey: true,
    });
    const dupRes = await verifyScittReceipt({ receipt: dupReceipt, jwks });
    expect(dupRes.ok).toBe(false);

    // Valid SCITT receipt with decision="deny" must be rejected by verifyAgentPermitV2 Step 28.
    const denyReceipt = buildScittReceipt({
      secretKey: sk,
      kid,
      statement: { ...baseStatement, decision: "deny", reason: "policy_denied" },
    });
    const standaloneDeny = await verifyScittReceipt({ receipt: denyReceipt, jwks });
    expect(standaloneDeny.ok).toBe(true);

    const permitJws = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-agent-permit+jwt", kid },
      {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent" },
        aud: "https://mcp.example.com/tools",
        jti,
        iat: now - 2,
        exp: now + 120,
        request_digest: requestDigest,
        assurance_tier: "passkey_webauthn_uv",
        modality: ["passkey_webauthn_uv"],
        freshness_verified_at: now - 5,
        continuity: { session_id: "sess_1", mode: "stateless" },
        uniqueness_status: "unmeasured",
        voice_verdict_jws: null,
        webauthn_assertion_digest: "f".repeat(64),
        policy_id: "pol_scitt_deny",
        scitt_receipt: denyReceipt,
      },
      sk,
    );
    const verifyRes = await verifyAgentPermitV2({
      permitJws,
      policy: {
        policy_id: "pol_scitt_deny",
        version: 2,
        allowed_assurance_tiers: ["passkey_webauthn_uv"],
        max_evidence_age_seconds: 120,
        max_permit_lifetime_seconds: 300,
        required_modalities: ["passkey_webauthn_uv"],
        require_continuity: false,
        require_dpop: false,
        require_scitt_receipt: true,
      },
      expectedAudience: "https://mcp.example.com/tools",
      action,
      jwks,
      nowSeconds: now,
    });
    expect(verifyRes.decision).toBe("deny");
    expect(verifyRes.reason).toBe("scitt_receipt_invalid");
  });

  it("hardens DPoP against forbidden headers, query/fragment in htu, userinfo, default ports, and jti replay", async () => {
    const sk = new Uint8Array(32).fill(19);
    const pk = ed25519.getPublicKey(sk);
    const jwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: base64UrlEncode(pk) };
    const jkt = await computeJwkThumbprint(jwk);
    const now = 1795450200;
    const permitJws = "stub.permit.jws";
    const ath = base64UrlEncode(sha256(encoder.encode(permitJws)));

    // Default port :443 normalization & query/fragment stripping on expectedHtu succeeds.
    const validProof = signEd25519Jws(
      { typ: "dpop+jwt", alg: "EdDSA", jwk },
      { jti: "dpop-jti-1", htm: "POST", htu: "https://api.example.com/tools", iat: now, ath },
      sk,
    );
    const jtiStore = new InMemoryDpopJtiStore();
    const ok = await verifyDpopProofV2({
      proof: validProof,
      permitJws,
      expectedHtm: "POST",
      expectedHtu: "https://api.example.com:443/tools?x=1#frag",
      expectedJkt: jkt,
      nowSeconds: now,
      jtiStore,
    });
    expect(ok.ok).toBe(true);

    // Replaying the same DPoP proof jti must fail closed.
    const replay = await verifyDpopProofV2({
      proof: validProof,
      permitJws,
      expectedHtm: "POST",
      expectedHtu: "https://api.example.com/tools",
      expectedJkt: jkt,
      nowSeconds: now,
      jtiStore,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.reason).toBe("dpop_proof_invalid");
    }

    // Query/fragment inside payload.htu must be rejected per RFC 9449 Section 4.2.
    const queryInPayload = signEd25519Jws(
      { typ: "dpop+jwt", alg: "EdDSA", jwk },
      { jti: "dpop-jti-2", htm: "POST", htu: "https://api.example.com/tools?leak=1", iat: now, ath },
      sk,
    );
    const badHtu = await verifyDpopProofV2({
      proof: queryInPayload,
      permitJws,
      expectedHtm: "POST",
      expectedHtu: "https://api.example.com/tools",
      expectedJkt: jkt,
      nowSeconds: now,
    });
    expect(badHtu.ok).toBe(false);

    // Forbidden headers (crit, jku, x5u, x5c) must be rejected.
    for (const forbidden of [
      { crit: ["exp"] },
      { jku: "https://evil.example/jwks.json" },
      { x5u: "https://evil.example/cert.pem" },
      { x5c: ["MIIB"] },
    ]) {
      const badHeaderProof = signEd25519Jws(
        { typ: "dpop+jwt", alg: "EdDSA", jwk, ...forbidden },
        { jti: "dpop-jti-3", htm: "POST", htu: "https://api.example.com/tools", iat: now, ath },
        sk,
      );
      const res = await verifyDpopProofV2({
        proof: badHeaderProof,
        permitJws,
        expectedHtm: "POST",
        expectedHtu: "https://api.example.com/tools",
        expectedJkt: jkt,
        nowSeconds: now,
      });
      expect(res.ok).toBe(false);
    }

    // Userinfo in htu must be rejected.
    const userinfoProof = signEd25519Jws(
      { typ: "dpop+jwt", alg: "EdDSA", jwk },
      { jti: "dpop-jti-4", htm: "POST", htu: "https://user:pass@api.example.com/tools", iat: now, ath },
      sk,
    );
    const userinfoRes = await verifyDpopProofV2({
      proof: userinfoProof,
      permitJws,
      expectedHtm: "POST",
      expectedHtu: "https://user:pass@api.example.com/tools",
      expectedJkt: jkt,
      nowSeconds: now,
    });
    expect(userinfoRes.ok).toBe(false);
  });

  it("enforces nonce-store policyId binding and bounds JWKS negative cache", async () => {
    const store = new InMemoryPermitNonceStoreV2();
    const jti = "d".repeat(64);
    store.register({
      jti,
      requestDigest: "e".repeat(64),
      aud: "https://mcp.example.com/tools",
      policyId: "pol_expected",
      issuedAt: 1795450000,
      expiresAt: 1795450300,
    });
    const wrongPolicy = store.consume({
      jti,
      nowSeconds: 1795450010,
      expiresAt: 1795450300,
      requireRegistered: true,
      requestDigest: "e".repeat(64),
      aud: "https://mcp.example.com/tools",
      policyId: "pol_other",
    });
    expect(wrongPolicy.status).toBe("not_found");

    // Bound JWKS negative cache under 5000 distinct unknown kids without hammering origin.
    let fetches = 0;
    const cache = createJwksCache({
      jwksUrl: "https://api.entros.io/.well-known/jwks.json",
      negativeCacheSeconds: 30,
      nowSeconds: () => 1795450000,
      fetch: (async () => {
        fetches += 1;
        return new Response(JSON.stringify(jwsVectors.jwks), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as typeof fetch,
    });
    for (let i = 0; i < 4200; i += 1) {
      const r = await cache.resolveEd25519Key(`unknown-kid-${i}`);
      expect(r.status).toBe("unknown");
    }
    expect(fetches).toBe(1);
  });

  it("forwards revokedKids in EntrosClient, enforces voice session_id & continuity binding, and hardens WS errors/limits", async () => {
    const client = createEntrosClient({
      baseUrl: "https://api.entros.io",
      apiKey: "test-key",
      jwks: jwsVectors.jwks,
      revokedKids: ["entros-voice-2026-11-a"],
      nowSeconds: () => jwsVectors.now_seconds,
      fetch: (async () =>
        new Response(
          JSON.stringify({
            request_id: "req_1",
            verdict: "likely_human",
            verdict_jws: jwsVectors.valid_voice_verdict.jws,
            inference_ms: 8.5,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )) as typeof fetch,
    });
    await expect(
      client.analyzeVoice({
        sessionId: "lk_room_bank_8831_caller_01",
        audio: new Uint8Array([1, 2, 3, 4]),
        codec: "pcm16_16k",
      }),
    ).rejects.toThrow(/revoked_kid/);

    // Session ID mismatch on REST analyze must throw verdict_invalid.
    const voiceClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () =>
        new Response(
          JSON.stringify({
            request_id: "req_2",
            verdict: "likely_human",
            verdict_jws: jwsVectors.valid_voice_verdict.jws,
            inference_ms: 8.5,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        )) as typeof fetch,
    });
    await expect(
      voiceClient.analyze({
        sessionId: "different_session_id",
        audio: new Uint8Array([1, 2, 3, 4]),
        codec: "pcm16_16k",
        verifyWithJwks: jwsVectors.jwks,
        nowSeconds: jwsVectors.now_seconds,
      }),
    ).rejects.toThrow(/session_id does not match/);

    // Voice stream: oversized message, session_id mismatch, async verify rejection, and open timeout.
    const wsTarget = new EventTarget();
    const wsSent: unknown[] = [];
    class ConnectingWs implements WebSocketLike {
      readyState = 0; // CONNECTING
      send(data: string | Uint8Array | ArrayBuffer) {
        wsSent.push(data);
      }
      close() {
        this.readyState = 3;
      }
      addEventListener(type: string, listener: (ev: unknown) => void) {
        wsTarget.addEventListener(type, listener as EventListener);
      }
    }
    const streamErrors: Array<{ code: string; message: string }> = [];
    const wsClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      webSocketCtor: ConnectingWs,
    });
    const wsStream = wsClient.connectStream({
      sessionId: "different_session_id",
      codec: "pcm16_16k",
      maxInboundMessageBytes: 64,
      openTimeoutMs: 25,
      verifyWithJwks: {
        resolveEd25519Key: async () => {
          throw new Error("boom-jwks");
        },
      },
      onVerdict: () => {},
      onError: (err) => streamErrors.push({ code: err.code, message: err.message }),
    });
    // Sending audio while socket is still CONNECTING must throw ws_error instead of calling ws.send.
    expect(() => wsStream.sendAudioChunk(new Uint8Array([1, 2]))).toThrow(/not open/);
    expect(wsSent).toHaveLength(0);

    // Oversized message must report protocol_error.
    wsTarget.dispatchEvent(new MessageEvent("message", { data: "x".repeat(128) }));
    // Async verification rejection must route to onError via .catch() (no unhandled rejection).
    wsTarget.dispatchEvent(
      new MessageEvent("message", { data: JSON.stringify({ verdict_jws: "a.b.c" }) }),
    );
    await new Promise((r) => setTimeout(r, 45));
    expect(
      streamErrors.some(
        (e) =>
          e.code === "invalid_response" &&
          e.message.includes("maximum allowed size"),
      ),
    ).toBe(true);
    expect(
      streamErrors.some((e) => e.code === "verdict_verification_failed"),
    ).toBe(true);
    expect(
      streamErrors.some(
        (e) =>
          e.code === "stream_error" && e.message.includes("open timed out"),
      ),
    ).toBe(true);

    // OpenAI adapter must reject duplicate JSON keys in tool arguments.
    await expect(
      createV2ChallengeFromOpenAiMcpRequest(
        {
          type: "mcp_approval_request",
          id: "mcpr_dup",
          server_label: "payments",
          name: "wire_transfer",
          arguments: '{"amount":10,"amount":99999}',
        },
        {
          audience: "https://mcp.example.com/tools",
          policy: policyVectors.concurrent_replay_scenario.policy,
          jwks: policyVectors.jwks,
          stateSecret: "0123456789abcdef0123456789abcdef",
        },
      ),
    ).rejects.toThrow(/JSON object/);

    // LiveKit / voice webhook guard must reject permit whose continuity.session_id mismatches call.sessionId.
    const guardSk = new Uint8Array(32).fill(29);
    const guardPk = ed25519.getPublicKey(guardSk);
    const guardKid = "lk-guard-key-1";
    const guardJwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: guardKid, x: base64UrlEncode(guardPk) }],
    };
    const guardNow = 1795450200;
    const guardAction: CanonicalActionV2Input = {
      kind: "voice.tool_call",
      server: "voice-banking",
      tool: "transfer_funds",
      arguments: { amount: 250 },
    };
    const guardDigest = hashActionV2(guardAction).requestDigest;
    const guardPolicy: PolicyV2 = {
      policy_id: "pol_voice_guard",
      version: 2,
      allowed_assurance_tiers: ["passkey_webauthn_uv"],
      required_modalities: ["passkey_webauthn_uv"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      require_continuity: false,
      require_dpop: false,
      require_scitt_receipt: false,
    };
    const guardPermit = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-agent-permit+jwt", kid: guardKid },
      {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/voice-agent" },
        aud: "https://mcp.example.com/tools",
        jti: "e".repeat(64),
        iat: guardNow - 2,
        exp: guardNow + 120,
        request_digest: guardDigest,
        assurance_tier: "passkey_webauthn_uv",
        modality: ["passkey_webauthn_uv"],
        freshness_verified_at: guardNow - 5,
        continuity: { session_id: "lk_room_real_session", mode: "stateless" },
        uniqueness_status: "unmeasured",
        voice_verdict_jws: null,
        webauthn_assertion_digest: "f".repeat(64),
        policy_id: "pol_voice_guard",
        scitt_receipt: null,
      },
      guardSk,
    );
    const lkGuard = createLiveKitToolGuard({
      server: "voice-banking",
      audience: "https://mcp.example.com/tools",
      policy: guardPolicy,
      jwks: guardJwks,
      nowSeconds: guardNow,
    });
    const wrongSessionRes = await lkGuard.guardToolCall({
      roomName: "bank_room",
      participantIdentity: "caller_wrong",
      sessionId: "wrong_session_id_mismatch",
      toolName: "transfer_funds",
      args: { amount: 250 },
      permitJws: guardPermit,
    });
    expect(wrongSessionRes.status).toBe("deny");
    if (wrongSessionRes.status === "deny") {
      expect(wrongSessionRes.reason).toBe("continuity_broken");
    }
    // Same permit on the matching session_id succeeds!
    const okSessionRes = await lkGuard.guardToolCall({
      roomName: "bank_room",
      participantIdentity: "caller_ok",
      sessionId: "lk_room_real_session",
      toolName: "transfer_funds",
      args: { amount: 250 },
      permitJws: guardPermit,
    });
    expect(okSessionRes.status).toBe("allow");

    // PermitApiClient.fetchScittReceipt rejects runtime shape violations and statement.jti mismatch.
    const badShapeApi = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () =>
        new Response(JSON.stringify({ unexpected: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        })) as typeof fetch,
    });
    await expect(badShapeApi.fetchScittReceipt("a".repeat(64))).rejects.toThrow(
      /scitt_receipt/,
    );

    const sk = new Uint8Array(32).fill(23);
    const pk = ed25519.getPublicKey(sk);
    const kid = "scitt-jti-check";
    const scittJwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid, x: base64UrlEncode(pk) }],
    };
    const receiptForB = buildScittReceipt({
      secretKey: sk,
      kid,
      statement: {
        schema: "entros-scitt-permit-v2",
        jti: "b".repeat(64),
        request_digest: "c".repeat(64),
        policy_id: "pol_1",
        decision: "allow",
        reason: "accepted",
        assurance_tier: "passkey_webauthn_uv",
        modality: ["passkey_webauthn_uv"],
        aud: "https://mcp.example.com/tools",
        freshness_verified_at: 1795450000,
        evaluated_at: 1795450001,
        model_version: null,
        retention: "memory_only",
      },
    });
    const mismatchApi = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () =>
        new Response(JSON.stringify({ scitt_receipt: receiptForB }), {
          status: 200,
          headers: { "content-type": "application/json" },
        })) as typeof fetch,
    });
    await expect(
      mismatchApi.fetchScittReceipt("a".repeat(64), { verifyWithJwks: scittJwks }),
    ).rejects.toThrow(/SCITT statement jti mismatch/);
  });

  it("prevents JWKS sliding-window negative-cache starvation and preserves revoked duplicate kids", async () => {
    const sk1 = new Uint8Array(32).fill(31);
    const pk1 = ed25519.getPublicKey(sk1);
    const sk2 = new Uint8Array(32).fill(32);
    const pk2 = ed25519.getPublicKey(sk2);
    let now = 1795450000;
    let fetches = 0;
    let keys: JwksDocument["keys"] = [
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "dup-rev", status: "revoked", x: base64UrlEncode(pk1) },
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "dup-rev", x: base64UrlEncode(pk1) },
    ];

    const cache = createJwksCache({
      jwksUrl: "https://api.entros.io/.well-known/jwks.json",
      ttlSeconds: 300,
      negativeCacheSeconds: 10,
      nowSeconds: () => now,
      fetch: (async () => {
        fetches += 1;
        return new Response(JSON.stringify({ keys }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }) as typeof fetch,
    });

    // Duplicate kid with earlier revoked=true must remain revoked.
    expect((await cache.resolveEd25519Key("dup-rev")).status).toBe("revoked");
    expect(fetches).toBe(1);

    // Rotated key queried before published triggers refresh and negative-caches at t=1795450000.
    now += 15;
    expect((await cache.resolveEd25519Key("rotated-k2")).status).toBe("unknown");
    expect(fetches).toBe(2);

    // Repeated lookups during the 10s cooldown must NOT extend the negative-cache window.
    keys = [
      ...keys,
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "rotated-k2", x: base64UrlEncode(pk2) },
    ];
    now += 5;
    expect((await cache.resolveEd25519Key("rotated-k2")).status).toBe("unknown");
    now += 4;
    expect((await cache.resolveEd25519Key("rotated-k2")).status).toBe("unknown");
    expect(fetches).toBe(2);

    // At t + 11s from the actual refresh, rotated-k2 resolves immediately.
    now += 2;
    expect((await cache.resolveEd25519Key("rotated-k2")).status).toBe("found");
    expect(fetches).toBe(3);
  });

  it("keeps parseStrictJson prototype-safe on __proto__ and wraps bad escapes in CanonicalJsonError", () => {
    const parsed = parseStrictJson('{"__proto__":{"polluted":true},"ok":1}') as Record<
      string,
      unknown
    >;
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(parsed, "__proto__")).toBe(true);
    expect((parsed["__proto__"] as Record<string, unknown>)["polluted"]).toBe(true);

    expect(() => parseStrictJson('{"bad":"\\u123"}')).toThrow(CanonicalJsonError);

    const nums = Array.from({ length: 2000 }, (_, i) => i * 0.25).join(",");
    const arr = parseStrictJson(`[${nums}]`) as number[];
    expect(arr).toHaveLength(2000);
    expect(arr[1999]).toBe(1999 * 0.25);
  });

  it("enforces Step 19-24 before Step 25, defers DPoP consume past Step 28, fails closed when DPoP store is full, and validates bounds", async () => {
    const sk = new Uint8Array(32).fill(41);
    const pk = ed25519.getPublicKey(sk);
    const jwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: base64UrlEncode(pk) };
    const jkt = await computeJwkThumbprint(jwk);
    const kid = "order-k1";
    const jwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid, x: base64UrlEncode(pk) }],
    };
    const now = 1795450500;
    const action: CanonicalActionV2Input = {
      kind: "mcp.tool_call",
      server: "payments",
      tool: "wire_transfer",
      arguments: { amount: 500 },
    };
    const digest = hashActionV2(action).requestDigest;

    // 1. voice_plus_passkey with bad voice verdict AND missing webauthn must report voice error first (Step 19..24 < Step 25).
    const badVoiceJws = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-voice-liveness+jwt", kid },
      {
        iss: "https://api.entros.io",
        jti: "1".repeat(64),
        iat: now - 5,
        exp: now + 100,
        session_id: "sess-order",
        verdict: "likely_synthetic",
        calibrated_llr: -4.2,
        operating_profile: "webrtc_16k",
        model_version: "0".repeat(64),
        signal_quality: { snr_db: 22, speech_ms: 2000, clipping: 0, codec_bandwidth_hz: 8000 },
        partial_spoof_spans: [],
        consistency_drift: {
          status: "evaluated",
          windows_evaluated: 3,
          floor_spread_db: 1,
          tail_decay_spread_db: 1,
          spectral_tilt_drift: 0.1,
          reason: null,
        },
        abstain_reason: null,
        retention: "memory_only",
      },
      sk,
    );
    const combinedPermit = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-agent-permit+jwt", kid },
      {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent", key_jkt: jkt },
        aud: "https://mcp.example.com/tools",
        jti: "2".repeat(64),
        iat: now - 5,
        exp: now + 295,
        request_digest: digest,
        assurance_tier: "voice_plus_passkey",
        modality: ["voice_liveness", "webauthn_uv"],
        freshness_verified_at: now - 5,
        continuity: { session_id: "sess-order", mode: "call_session", call_continuity_verified: true },
        uniqueness_status: "enterprise_idp_subject",
        voice_verdict_jws: badVoiceJws,
        webauthn_assertion_digest: "f".repeat(64),
        policy_id: "pol_order",
        scitt_receipt: null,
        cnf: { jkt },
      },
      sk,
    );
    const orderPolicy: PolicyV2 = {
      policy_id: "pol_order",
      version: 2,
      allowed_assurance_tiers: ["voice_plus_passkey"],
      required_modalities: ["voice_liveness", "webauthn_uv"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      require_continuity: true,
      require_dpop: false,
      require_scitt_receipt: false,
    };
    const stepOrderRes = await verifyAgentPermitV2({
      permitJws: combinedPermit,
      policy: orderPolicy,
      expectedAudience: "https://mcp.example.com/tools",
      action,
      jwks,
      nowSeconds: now,
    });
    expect(stepOrderRes.decision).toBe("deny");
    expect(stepOrderRes.reason).toBe("voice_verdict_not_allowed");

    // 2. Failed Step 28 SCITT must NOT consume DPoP jti; throwing DPoP store maps to unavailable/state_unavailable.
    const dpopPolicy: PolicyV2 = {
      policy_id: "pol_dpop_order",
      version: 2,
      allowed_assurance_tiers: ["passkey_webauthn_uv"],
      required_modalities: ["webauthn_uv"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      require_continuity: false,
      require_dpop: true,
      require_scitt_receipt: true,
    };
    const dpopPermit = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-agent-permit+jwt", kid },
      {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent", key_jkt: jkt },
        aud: "https://mcp.example.com/tools",
        jti: "3".repeat(64),
        iat: now - 5,
        exp: now + 295,
        request_digest: digest,
        assurance_tier: "passkey_webauthn_uv",
        modality: ["webauthn_uv"],
        freshness_verified_at: now - 5,
        continuity: { session_id: "sess-dpop", mode: "stateless" },
        uniqueness_status: "unmeasured",
        voice_verdict_jws: null,
        webauthn_assertion_digest: "f".repeat(64),
        policy_id: "pol_dpop_order",
        scitt_receipt: "invalid-cbor-receipt",
        cnf: { jkt },
      },
      sk,
    );
    const ath = base64UrlEncode(sha256(encoder.encode(dpopPermit)));
    const dpopProof = signEd25519Jws(
      { typ: "dpop+jwt", alg: "EdDSA", jwk },
      { jti: "dpop-unburned-1", htm: "POST", htu: "https://mcp.example.com/tools", iat: now, ath },
      sk,
    );
    const dpopStore = new InMemoryDpopJtiStore(2);
    const failedScitt = await verifyAgentPermitV2({
      permitJws: dpopPermit,
      policy: dpopPolicy,
      expectedAudience: "https://mcp.example.com/tools",
      action,
      jwks,
      nowSeconds: now,
      dpop: { proof: dpopProof, htm: "POST", htu: "https://mcp.example.com/tools", jtiStore: dpopStore },
    });
    expect(failedScitt.decision).toBe("deny");
    expect(failedScitt.reason).toBe("scitt_receipt_invalid");
    // DPoP jti was NOT burned because Step 28 failed.
    expect(dpopStore.consume("dpop-unburned-1", now + 60, now)).toBe(true);

    const throwingStoreRes = await verifyAgentPermitV2({
      permitJws: dpopPermit,
      policy: { ...dpopPolicy, require_scitt_receipt: false },
      expectedAudience: "https://mcp.example.com/tools",
      action,
      jwks,
      nowSeconds: now,
      dpop: {
        proof: dpopProof,
        htm: "POST",
        htu: "https://mcp.example.com/tools",
        jtiStore: {
          consume: () => {
            throw new Error("redis_down");
          },
        },
      },
    });
    expect(throwingStoreRes.decision).toBe("unavailable");
    expect(throwingStoreRes.reason).toBe("state_unavailable");

    // 3. InMemoryDpopJtiStore fails closed when full of unexpired entries (never evicts active jti).
    const fullStore = new InMemoryDpopJtiStore(2);
    expect(fullStore.consume("jti-1", now + 60, now)).toBe(true);
    expect(fullStore.consume("jti-2", now + 60, now)).toBe(true);
    expect(fullStore.consume("jti-3", now + 60, now)).toBe(false);
    // Original jti-1 is still tracked and rejected on replay.
    expect(fullStore.consume("jti-1", now + 60, now)).toBe(false);

    // 4. Post-precheck clock re-check catches voice verdict expiring mid-flight without burning nonce.
    const validVoiceJws = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-voice-liveness+jwt", kid },
      {
        iss: "https://api.entros.io",
        jti: "4".repeat(64),
        iat: now - 25,
        exp: now + 10,
        session_id: "sess-clock",
        verdict: "likely_human",
        calibrated_llr: 4.5,
        operating_profile: "webrtc_16k",
        model_version: "0".repeat(64),
        signal_quality: { snr_db: 22, speech_ms: 2000, clipping: 0, codec_bandwidth_hz: 8000 },
        partial_spoof_spans: [],
        consistency_drift: {
          status: "evaluated",
          windows_evaluated: 3,
          floor_spread_db: 1,
          tail_decay_spread_db: 1,
          spectral_tilt_drift: 0.1,
          reason: null,
        },
        abstain_reason: null,
        retention: "memory_only",
      },
      sk,
    );
    const voicePermit = signEd25519Jws(
      { alg: "EdDSA", typ: "entros-agent-permit+jwt", kid },
      {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent" },
        aud: "https://mcp.example.com/tools",
        jti: "5".repeat(64),
        iat: now - 5,
        exp: now + 295,
        request_digest: digest,
        assurance_tier: "voice_liveness_webrtc",
        modality: ["voice_liveness"],
        freshness_verified_at: now - 25,
        continuity: { session_id: "sess-clock", mode: "call_session", call_continuity_verified: true },
        uniqueness_status: "session_bound",
        voice_verdict_jws: validVoiceJws,
        webauthn_assertion_digest: null,
        policy_id: "pol_voice_clock",
        scitt_receipt: null,
      },
      sk,
    );
    let clockCalls = 0;
    const nonceStore = new InMemoryPermitNonceStoreV2();
    const expiredPostRes = await verifyAgentPermitV2({
      permitJws: voicePermit,
      policy: {
        policy_id: "pol_voice_clock",
        version: 2,
        allowed_assurance_tiers: ["voice_liveness_webrtc"],
        required_modalities: ["voice_liveness"],
        max_evidence_age_seconds: 120,
        max_permit_lifetime_seconds: 300,
        require_continuity: true,
        require_dpop: false,
        require_scitt_receipt: false,
      },
      expectedAudience: "https://mcp.example.com/tools",
      action,
      jwks,
      nowSeconds: () => {
        clockCalls += 1;
        return clockCalls === 1 ? now : now + 20;
      },
      nonceStore,
    });
    expect(expiredPostRes.decision).toBe("deny");
    expect(expiredPostRes.reason).toBe("voice_verdict_invalid");
    expect(nonceStore.peek("5".repeat(64))).toBeNull();

    // 5. Invalid numeric bounds fail closed in verifyDpopProofV2 and evaluatePolicyV2.
    const badDpopBounds = await verifyDpopProofV2({
      proof: dpopProof,
      permitJws: dpopPermit,
      expectedHtm: "POST",
      expectedHtu: "https://mcp.example.com/tools",
      expectedJkt: jkt,
      nowSeconds: Number.NaN,
      maxAgeSeconds: 0,
    });
    expect(badDpopBounds.ok).toBe(false);

    const badPolicyBounds = evaluatePolicyV2({
      permit: {
        iss: "https://api.entros.io",
        sub: "usr_01",
        actor: { id: "spiffe://acme/agent" },
        aud: "https://mcp.example.com/tools",
        jti: "6".repeat(64),
        iat: now - 5,
        exp: now + 200,
        request_digest: digest,
        assurance_tier: "passkey_webauthn_uv",
        modality: ["webauthn_uv"],
        freshness_verified_at: now - 5,
        continuity: { session_id: "s1", mode: "stateless" },
        uniqueness_status: "unmeasured",
        voice_verdict_jws: null,
        webauthn_assertion_digest: "f".repeat(64),
        policy_id: "pol_bad_bounds",
        scitt_receipt: null,
      },
      policy: {
        policy_id: "pol_bad_bounds",
        version: 2,
        allowed_assurance_tiers: ["passkey_webauthn_uv"],
        required_modalities: ["webauthn_uv"],
        max_evidence_age_seconds: Number.NaN,
        max_permit_lifetime_seconds: 300,
        require_continuity: false,
        require_dpop: false,
        require_scitt_receipt: false,
      },
      expectedAudience: "https://mcp.example.com/tools",
      expectedRequestDigest: digest,
      nowSeconds: now,
    });
    expect(badPolicyBounds.decision).toBe("deny");
    expect(badPolicyBounds.reason).toBe("policy_mismatch");
  });

  it("hardens SCITT unprotected crit, PermitApiClient verify fail-closed, EntrosClient default receipt verify, voice guard rules, and WS serialization", async () => {
    const sk = new Uint8Array(32).fill(51);
    const pk = ed25519.getPublicKey(sk);
    const kid = "scitt-unprot-crit";
    const jwks: JwksDocument = {
      keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid, x: base64UrlEncode(pk) }],
    };

    // 1. SCITT rejects crit (label 2) in COSE unprotected header map.
    const protectedBytes = concatAll([
      cborUint(5, 3),
      cborUint(0, 1),
      cborNegInt(-8),
      cborUint(0, 4),
      cborBytes(encoder.encode(kid)),
      cborUint(0, 395),
      cborUint(0, 1),
    ]);
    const payloadBytes = encoder.encode(
      canonicalizeJcs({
        schema: "entros-scitt-permit-v2",
        jti: "a".repeat(64),
        request_digest: "b".repeat(64),
        policy_id: "pol_1",
        decision: "allow",
        reason: "accepted",
        assurance_tier: "passkey_webauthn_uv",
        modality: ["webauthn_uv"],
        aud: "https://mcp.example.com/tools",
        freshness_verified_at: 1795450000,
        evaluated_at: 1795450001,
        model_version: null,
        retention: "memory_only",
      }),
    );
    const leafHash = sha256(concatAll([Uint8Array.of(0x00), payloadBytes]));
    const inclusionTuple = concatAll([cborUint(4, 3), cborUint(0, 1), cborUint(0, 0), cborUint(4, 0)]);
    const vdpMap = concatAll([cborUint(5, 1), cborNegInt(-1), inclusionTuple]);
    // Unprotected header includes label 2 (crit) alongside 396 (vdp).
    const unprotectedWithCrit = concatAll([
      cborUint(5, 2),
      cborUint(0, 2),
      cborUint(4, 1),
      cborUint(0, 99),
      cborUint(0, 396),
      vdpMap,
    ]);
    const sigStruct = concatAll([
      cborUint(4, 4),
      cborText("Signature1"),
      cborBytes(protectedBytes),
      cborBytes(new Uint8Array(0)),
      cborBytes(leafHash),
    ]);
    const sig = ed25519.sign(sigStruct, sk);
    const badReceipt = base64UrlEncode(
      concatAll([
        Uint8Array.of(0xd2),
        cborUint(4, 4),
        cborBytes(protectedBytes),
        unprotectedWithCrit,
        cborBytes(payloadBytes),
        cborBytes(sig),
      ]),
    );
    const critUnprotRes = await verifyScittReceipt({ receipt: badReceipt, jwks });
    expect(critUnprotRes.ok).toBe(false);

    // 2. PermitApiClient fails closed on contradictory verify responses & matches content-type case-insensitively.
    const policy: PolicyV2 = {
      policy_id: "pol_client",
      version: 2,
      allowed_assurance_tiers: ["passkey_webauthn_uv"],
      required_modalities: ["webauthn_uv"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      require_continuity: false,
      require_dpop: false,
      require_scitt_receipt: false,
    };
    const action: CanonicalActionV2Input = {
      kind: "mcp.tool_call",
      server: "payments",
      tool: "wire_transfer",
      arguments: { amount: 10 },
    };

    const bogus403Api = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () =>
        new Response(JSON.stringify({ verified: true, decision: "allow" }), {
          status: 403,
          headers: { "Content-Type": "APPLICATION/JSON; charset=utf-8" },
        })) as typeof fetch,
    });
    await expect(
      bogus403Api.verifyPermitOnline({
        permit_jws: "a.b.c",
        expected_aud: "https://mcp.example.com/tools",
        action,
        policy,
      }),
    ).rejects.toThrow(/non-2xx|allow/i);

    const mismatch200Api = createPermitApiClient({
      baseUrl: "https://api.entros.io",
      fetch: (async () =>
        new Response(JSON.stringify({ verified: true, decision: "deny" }), {
          status: 200,
          headers: { "Content-Type": "APPLICATION/JSON" },
        })) as typeof fetch,
    });
    await expect(
      mismatch200Api.verifyPermitOnline({
        permit_jws: "a.b.c",
        expected_aud: "https://mcp.example.com/tools",
        action,
        policy,
      }),
    ).rejects.toThrow(/disagree|mismatch/i);

    // 3. EntrosClient.fetchScittReceipt verifies by default with client.jwks and supports explicit opt-out.
    const validReceipt = buildScittReceipt({
      secretKey: sk,
      kid,
      statement: {
        schema: "entros-scitt-permit-v2",
        jti: "a".repeat(64),
        request_digest: "b".repeat(64),
        policy_id: "pol_1",
        decision: "allow",
        reason: "accepted",
        assurance_tier: "passkey_webauthn_uv",
        modality: ["webauthn_uv"],
        aud: "https://mcp.example.com/tools",
        freshness_verified_at: 1795450000,
        evaluated_at: 1795450001,
        model_version: null,
        retention: "memory_only",
      },
    });
    const unifiedClient = createEntrosClient({
      baseUrl: "https://api.entros.io",
      jwks,
      fetch: (async () =>
        new Response(JSON.stringify({ scitt_receipt: validReceipt }), {
          status: 200,
          headers: { "Content-Type": "APPLICATION/JSON" },
        })) as typeof fetch,
    });
    const defaultVerified = await unifiedClient.fetchScittReceipt("a".repeat(64));
    expect(defaultVerified.verifiedReceipt).not.toBeNull();
    expect(defaultVerified.verifiedReceipt?.kid).toBe(kid);

    const optOut = await unifiedClient.fetchScittReceipt("a".repeat(64), {
      verifyWithJwks: false,
    });
    expect(optOut.verifiedReceipt).toBeNull();

    // 4. Voice webhook guard enforces full voice_rules (min_calibrated_llr, allowed_profiles, etc.).
    const strictVoicePolicy: PolicyV2 = {
      policy_id: "pol_voice_rules",
      version: 2,
      allowed_assurance_tiers: ["voice_liveness_webrtc"],
      required_modalities: ["voice_liveness"],
      max_evidence_age_seconds: 120,
      max_permit_lifetime_seconds: 300,
      require_continuity: false,
      require_dpop: false,
      require_scitt_receipt: false,
      voice_rules: {
        allowed_profiles: ["webrtc_16k"],
        allowed_verdicts: ["likely_human"],
        min_calibrated_llr: 10.0,
        min_speech_ms: 1500,
        min_snr_db: 12,
        max_partial_spoof_spans: 0,
        reject_on_abstain: true,
        reject_on_consistency_drift: true,
      },
    };
    const lkStrictGuard = createLiveKitToolGuard({
      server: "voice-banking",
      audience: "https://mcp.example.com/tools",
      policy: strictVoicePolicy,
      jwks: jwsVectors.jwks,
      nowSeconds: jwsVectors.now_seconds,
    });
    const lowLlrStepUp = await lkStrictGuard.guardToolCall({
      roomName: "bank_room",
      participantIdentity: "caller_1",
      sessionId: "lk_room_bank_8831_caller_01",
      toolName: "transfer_funds",
      args: { amount: 100 },
      voiceVerdictJws: jwsVectors.valid_voice_verdict.jws,
    });
    expect(lowLlrStepUp.status).toBe("deny");
    if (lowLlrStepUp.status === "deny") {
      expect(lowLlrStepUp.reason).toBe("voice_verdict_not_allowed");
    }

    // 5. VoiceLivenessClient.connectStream serializes verdict verification, guards post-close, catches start errors, and wraps WHATWG SyntaxError.
    class StrictWhatwgWs implements WebSocketLike {
      readyState = 1;
      constructor(_url: string, opts?: string | string[] | { headers?: Record<string, string> }) {
        if (opts && typeof opts === "object" && !Array.isArray(opts)) {
          throw new SyntaxError("Invalid subprotocol '[object Object]'");
        }
      }
      send() {}
      close() {}
      addEventListener() {}
    }
    const whatwgClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      apiKey: "secret-key",
      webSocketCtor: StrictWhatwgWs,
    });
    expect(() =>
      whatwgClient.connectStream({
        sessionId: "s-whatwg",
        codec: "pcm16_16k",
        onVerdict: () => {},
      }),
    ).toThrow(VoiceClientError);

    const orderTarget = new EventTarget();
    class OrderWs implements WebSocketLike {
      readyState = 1;
      send() {}
      close() {
        this.readyState = 3;
      }
      addEventListener(type: string, listener: (ev: unknown) => void) {
        orderTarget.addEventListener(type, listener as EventListener);
      }
    }
    let resolveCount = 0;
    const delivered: string[] = [];
    const orderClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      webSocketCtor: OrderWs,
    });
    const orderStream = orderClient.connectStream({
      sessionId: "lk_room_bank_8831_caller_01",
      codec: "pcm16_16k",
      nowSeconds: jwsVectors.now_seconds,
      verifyWithJwks: {
        resolveEd25519Key: async (lookupKid) => {
          const callNum = ++resolveCount;
          // First verdict takes longer than second; serialization must still deliver first before second.
          await new Promise((r) => setTimeout(r, callNum === 1 ? 30 : 2));
          const key = jwsVectors.jwks.keys.find((k) => k.kid === lookupKid)!;
          return {
            status: "found",
            kid: lookupKid,
            publicKey: base64UrlDecodeStrict(key.x)!,
          };
        },
      },
      onVerdict: ({ verdictJws }) => {
        delivered.push(verdictJws === jwsVectors.valid_voice_verdict.jws ? "human" : "abstain");
      },
    });
    orderTarget.dispatchEvent(
      new MessageEvent("message", {
        data: JSON.stringify({ verdict_jws: jwsVectors.valid_voice_verdict.jws }),
      }),
    );
    orderTarget.dispatchEvent(
      new MessageEvent("message", {
        data: JSON.stringify({ verdict_jws: jwsVectors.valid_voice_abstain.jws }),
      }),
    );
    await new Promise((r) => setTimeout(r, 70));
    expect(delivered).toEqual(["human", "abstain"]);

    // Post-close callbacks must be suppressed.
    orderStream.close();
    orderTarget.dispatchEvent(
      new MessageEvent("message", {
        data: JSON.stringify({ verdict_jws: jwsVectors.valid_voice_verdict.jws }),
      }),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(delivered).toEqual(["human", "abstain"]);

    // sendStartFrame error routes cleanly to onError.
    class FailingStartWs implements WebSocketLike {
      readyState = 1;
      send() {
        throw new Error("socket write failed");
      }
      close() {}
      addEventListener() {}
    }
    const startErrors: string[] = [];
    const failStartClient = createVoiceLivenessClient({
      baseUrl: "https://api.entros.io",
      webSocketCtor: FailingStartWs,
    });
    failStartClient.connectStream({
      sessionId: "s-fail-start",
      codec: "pcm16_16k",
      onVerdict: () => {},
      onError: (err) => startErrors.push(err.code),
    });
    expect(startErrors).toEqual(["stream_error"]);
  });
});
