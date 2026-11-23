// @vitest-environment node
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
  base64UrlEncode,
  createJwksCache,
  createPermitApiClient,
  hashActionV2,
  verifyAgentPermitV2,
  type CanonicalActionV2Input,
  type JwksDocument,
  type PolicyV2,
} from "../src/permit";
import {
  createVoiceLivenessClient,
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
    const secretAudioB64 = base64UrlEncode(secretAudio);
    const debugEvents: VoiceClientDebugEvent[] = [];

    const mockFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      const parsed = JSON.parse(String(init?.body)) as { audio_b64url: string };
      expect(parsed.audio_b64url).toBe(secretAudioB64);
      return new Response(
        JSON.stringify({
          verdict_jws: jwsVectors.valid_voice_verdict.jws,
          request_id: "req_voice_01",
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
        public readonly protocols?: string | string[],
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
    expect(sent[0]).toBeInstanceOf(Uint8Array);
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
          request_digest: hashActionV2({
            kind: "voice.tool_call",
            server: "voice-banking",
            tool: "transfer_funds",
            arguments: { amount: 250 },
          }).requestDigest,
          mode: "oidc_ciba",
          approval_url: `https://approve.entros.io/step-up/${scenario.jti}`,
          challenge_b64url:
            webauthnVectors.challenge_derivation.expected_challenge_b64url,
          expires_at: scenario.now_seconds + 180,
          auth_req_id: "ciba_req_01",
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
      expect(abstainRes.stepUp?.auth_req_id).toBe("ciba_req_01");
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
