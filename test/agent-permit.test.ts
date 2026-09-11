// @vitest-environment node
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import {
  AGENT_PERMIT_LIMITS,
  AGENT_PERMIT_NETWORK,
  AgentPermitValidationError,
  agentPermitId,
  createAgentPermitRequest,
  encodeAgentPermitApproval,
  encodeAgentPermitFragment,
  encodeAgentPermitSettlement,
  evaluateAgentPermit,
  isAgentPermitAudience,
  isAgentStateEvidence,
  normalizeAgentPermitRequest,
  parseAgentPermitApproval,
  parseAgentPermitFragment,
  parseAgentPermitMessage,
  parseAgentPermitSettlement,
  precheckAgentPermit,
  renderAgentPermitMessage,
  renderAgentPermitPresentation,
  verifyAgentPermitSignatures,
  type AgentPermitRequest,
  type AgentStateEvidence,
  type AgentStateReadResult,
} from "../src/agent-permit";
import { base58Encode } from "../src/base58";
import { normalizePolicyRequest, POLICY_NETWORK, type PolicyEvidence } from "../src/policy";
import { makePolicyEvidence } from "./policy-fixtures";

interface VectorKey {
  seedHex: string;
  publicKey: string;
  publicKeyHex: string;
}

interface ValidVector {
  name: string;
  request: AgentPermitRequest;
  message: string;
  permitId: string;
  presentation: string;
  operatorSignature: string;
  presentationSignature: string;
  copiedPresentationSignature: string;
  approval: string;
  settlementBundle: string;
}

interface Vectors {
  network: Record<string, string>;
  constants: Record<string, string | number>;
  keys: Record<"operator" | "agentWallet" | "other", VectorKey> &
    Record<"smallOrder" | "nonCanonical", { publicKey: string; publicKeyHex: string }>;
  valid: ValidVector[];
  invalidMessages: { name: string; message: string }[];
  signatures: {
    name: string;
    message: string;
    publicKey: string;
    signature: string;
    strict: boolean;
    permissive: boolean;
  }[];
}

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/agent-permit-vectors.json", import.meta.url), "utf8"),
) as Vectors;
const encoder = new TextEncoder();
const hex = (value: string) =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const toHex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const sign = (seedHex: string, text: string) =>
  toHex(ed25519.sign(encoder.encode(text), hex(seedHex)));
const standard = vectors.valid[0] as ValidVector;
const { operator, agentWallet, other } = vectors.keys;

function signed(request: AgentPermitRequest, walletSeed = agentWallet.seedHex) {
  const message = renderAgentPermitMessage(request);
  return {
    operatorSignature: sign(operator.seedHex, message),
    presentationSignature: sign(
      walletSeed,
      renderAgentPermitPresentation(agentPermitId(request)),
    ),
  };
}

function agentState(
  request: AgentPermitRequest,
  overrides: Partial<AgentStateEvidence> = {},
): AgentStateReadResult {
  return {
    status: "available",
    evidence: {
      cluster: "devnet",
      genesisHash: AGENT_PERMIT_NETWORK.genesisHash,
      coreProgram: AGENT_PERMIT_NETWORK.coreProgram,
      agentRegistryProgram: AGENT_PERMIT_NETWORK.agentRegistryProgram,
      agentCollection: AGENT_PERMIT_NETWORK.agentCollection,
      agent: request.agent,
      agentAccount: POLICY_NETWORK.programIds.registry,
      owner: request.operator,
      cachedOwner: request.operator,
      agentWallet: request.agentWallet,
      agentWalletStatus: "bound",
      readContextSlot: 500,
      ...overrides,
    },
  };
}

function operatorEvidence(
  now: number,
  wallet: string,
  change: (evidence: PolicyEvidence) => void = () => {},
) {
  const evidence = makePolicyEvidence(now);
  evidence.identity.walletPubkey = wallet;
  change(evidence);
  return { status: "available" as const, evidence };
}

function settle(
  request: AgentPermitRequest,
  now: number,
  options: {
    state?: AgentStateReadResult;
    evidence?: ReturnType<typeof operatorEvidence> | { status: "unavailable"; reason: string };
    signatures?: { operatorSignature: string; presentationSignature: string };
  } = {},
) {
  return evaluateAgentPermit({
    request,
    ...(options.signatures ?? signed(request)),
    agentState: options.state ?? agentState(request),
    operatorEvidence: options.evidence ?? operatorEvidence(now, request.operator),
    nowSeconds: now,
  });
}

describe("frozen vectors", () => {
  it.each(vectors.valid.map((vector) => [vector.name, vector] as const))(
    "reproduces %s byte for byte",
    (_name, vector) => {
      expect(normalizeAgentPermitRequest(vector.request)).toEqual(vector.request);
      expect(renderAgentPermitMessage(vector.request)).toBe(vector.message);
      expect(parseAgentPermitMessage(vector.message)).toEqual(vector.request);
      expect(agentPermitId(vector.request)).toBe(vector.permitId);
      expect(renderAgentPermitPresentation(vector.permitId)).toBe(vector.presentation);
      expect(
        verifyAgentPermitSignatures(vector.request, {
          operatorSignature: vector.operatorSignature,
          presentationSignature: vector.presentationSignature,
        }),
      ).toEqual({ operator: true, presentation: true });
      expect(
        verifyAgentPermitSignatures(vector.request, {
          operatorSignature: vector.operatorSignature,
          presentationSignature: vector.copiedPresentationSignature,
        }),
      ).toEqual({ operator: true, presentation: false });
      const approval = parseAgentPermitApproval(vector.approval);
      expect(approval).not.toBeNull();
      expect(
        encodeAgentPermitApproval({
          permitId: approval!.permitId,
          operatorSignature: approval!.operatorSignature,
          verifiedTransaction: approval!.verifiedTransaction,
        }),
      ).toBe(vector.approval);
      const bundle = parseAgentPermitSettlement(vector.settlementBundle);
      expect(bundle).not.toBeNull();
      expect(
        encodeAgentPermitSettlement({
          nonce: bundle!.nonce,
          operatorSignature: bundle!.operatorSignature,
          presentationSignature: bundle!.presentationSignature,
          verifiedTransaction: bundle!.verifiedTransaction,
        }),
      ).toBe(vector.settlementBundle);
    },
  );

  it("pins the same deployment and limits as the independent generator", () => {
    expect(vectors.network).toEqual(AGENT_PERMIT_NETWORK);
    expect(vectors.constants.minLifetimeSeconds).toBe(AGENT_PERMIT_LIMITS.minLifetimeSeconds);
    expect(vectors.constants.maxLifetimeSeconds).toBe(AGENT_PERMIT_LIMITS.maxLifetimeSeconds);
    expect(vectors.constants.maxAudienceLength).toBe(AGENT_PERMIT_LIMITS.maxAudienceLength);
    expect(vectors.constants.maxLabelLength).toBe(AGENT_PERMIT_LIMITS.maxLabelLength);
    expect(vectors.constants.minTimeSeconds).toBe(AGENT_PERMIT_LIMITS.minTimeSeconds);
    expect(vectors.constants.maxTimeSeconds).toBe(AGENT_PERMIT_LIMITS.maxTimeSeconds);
    expect(vectors.constants.clockSkewSeconds).toBe(AGENT_PERMIT_LIMITS.clockSkewSeconds);
  });

  it.each(vectors.invalidMessages.map((vector) => [vector.name, vector.message] as const))(
    "rejects %s",
    (_name, message) => {
      expect(() => parseAgentPermitMessage(message)).toThrow(AgentPermitValidationError);
    },
  );

  it("starts both texts with bytes that no Solana transaction message can carry", () => {
    for (const vector of vectors.valid) {
      for (const text of [vector.message, vector.presentation]) {
        const [first = 0, second = 0] = encoder.encode(text);
        expect(first & 0x80).toBe(0);
        expect(second).toBeGreaterThanOrEqual(first);
      }
    }
  });
});

describe("signature rules", () => {
  it("matches the generator's strict results", () => {
    for (const vector of vectors.signatures) {
      if (vector.publicKey !== operator.publicKey) continue;
      const result = verifyAgentPermitSignatures(standard.request, {
        operatorSignature: vector.signature,
        presentationSignature: standard.presentationSignature,
      });
      expect(result.operator, vector.name).toBe(vector.strict);
    }
  });

  it("refuses the small-order forgery that the library default accepts", () => {
    const forgery = vectors.signatures.find(
      (vector) => vector.name === "identity key with a zero signature",
    )!;
    const message = encoder.encode(forgery.message);
    expect(ed25519.verify(hex(forgery.signature), message, hex(vectors.keys.smallOrder.publicKeyHex))).toBe(true);
    expect(
      ed25519.verify(hex(forgery.signature), message, hex(vectors.keys.smallOrder.publicKeyHex), {
        zip215: false,
      }),
    ).toBe(false);
    for (const field of ["operator", "agentWallet"] as const) {
      expect(() =>
        normalizeAgentPermitRequest({ ...standard.request, [field]: vectors.keys.smallOrder.publicKey }),
      ).toThrow(AgentPermitValidationError);
      expect(() =>
        normalizeAgentPermitRequest({ ...standard.request, [field]: vectors.keys.nonCanonical.publicKey }),
      ).toThrow(AgentPermitValidationError);
    }
  });

  it("rejects signature text outside lowercase hex", () => {
    const upper = standard.operatorSignature.toUpperCase();
    expect(
      verifyAgentPermitSignatures(standard.request, {
        operatorSignature: upper,
        presentationSignature: standard.presentationSignature,
      }).operator,
    ).toBe(false);
    expect(
      verifyAgentPermitSignatures(standard.request, {
        operatorSignature: 7,
        presentationSignature: null,
      }),
    ).toEqual({ operator: false, presentation: false });
  });
});

describe("audience grammar", () => {
  it("accepts only strings equal to their WHATWG href", () => {
    const hosts = ["consumer.example", "a.bc", "x-y.z9", "api.v2.consumer.example"];
    const ports = ["", ":1", ":8443", ":65535"];
    const paths = ["/", "/a", "/a/b", "/a/b/", "/.well-known/agent", "/a~b_c.d-e"];
    const candidates = new Set<string>();
    for (const host of hosts)
      for (const port of ports)
        for (const path of paths) {
          candidates.add(`https://${host}${port}${path}`);
          candidates.add(`http://127.0.0.1${port}${path}`);
        }
    let accepted = 0;
    for (const value of candidates) {
      if (!isAgentPermitAudience(value)) continue;
      accepted += 1;
      expect(new URL(value).href).toBe(value);
    }
    expect(accepted).toBe(candidates.size);
  });

  it("rejects forms that WHATWG rewrites or that hide the host", () => {
    for (const value of [
      "https://consumer.example:443/",
      "http://127.0.0.1:80/",
      "https://consumer.example/a/./b",
      "https://consumer.example/a/%2e%2e/b",
      "https://consumer.example//a",
      "https://CONSUMER.example/",
      "https://consumer.example:0/",
      "https://consumer.example:65536/",
      "https://localhost/",
      "http://localhost/",
      "https://127.0.0.1/",
      "https://ab--cd.example/",
      "https://consumer.example/a b",
    ]) {
      expect(isAgentPermitAudience(value), value).toBe(false);
    }
  });
});

describe("request creation", () => {
  const input = {
    agent: standard.request.agent,
    agentWallet: standard.request.agentWallet,
    operator: standard.request.operator,
    audience: standard.request.audience,
    action: standard.request.action,
    policy: normalizePolicyRequest({
      id: "agent-demo",
      version: 1,
      minTrustScore: 100,
      maxVerificationAgeSeconds: 86400,
      requiredAssurance: "browser_unattested",
      uniquenessRequirement: "allow_unmeasured",
      cluster: "devnet",
    }),
    issuedAt: standard.request.issuedAt,
    lifetimeSeconds: 600,
  };

  it("reproduces the standard vector from its parts", () => {
    expect(createAgentPermitRequest({ ...input, nonce: standard.request.nonce })).toEqual(
      standard.request,
    );
  });

  it("draws a fresh 32-byte nonce when none is supplied", () => {
    const first = createAgentPermitRequest(input);
    const second = createAgentPermitRequest(input);
    expect(first.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(first.nonce).not.toBe(second.nonce);
  });

  it("enforces the lifetime bounds", () => {
    for (const lifetimeSeconds of [0, 29, 901, 1.5]) {
      expect(() => createAgentPermitRequest({ ...input, lifetimeSeconds })).toThrow(
        AgentPermitValidationError,
      );
    }
    for (const lifetimeSeconds of [30, 900]) {
      expect(createAgentPermitRequest({ ...input, lifetimeSeconds }).expiresAt).toBe(
        input.issuedAt + lifetimeSeconds,
      );
    }
  });

  it("rejects extra fields and a changed deployment constant", () => {
    expect(() => normalizeAgentPermitRequest({ ...standard.request, extra: 1 })).toThrow(
      AgentPermitValidationError,
    );
    for (const [field, value] of [
      ["agentCollection", "C6W2bq4BoVT8FDvqhdp3sbcHFBjNBXE8TsNak2wTXQs9"],
      ["agentRegistryProgram", "8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ"],
      ["entrosAnchorProgram", POLICY_NETWORK.programIds.verifier],
      ["genesisHash", "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"],
      ["cluster", "mainnet-beta"],
    ] as const) {
      expect(() => normalizeAgentPermitRequest({ ...standard.request, [field]: value })).toThrow(
        AgentPermitValidationError,
      );
    }
  });
});

describe("precheck", () => {
  const request = standard.request;
  const signatures = {
    operatorSignature: standard.operatorSignature,
    presentationSignature: standard.presentationSignature,
  };

  it("accepts until the second before expiry", () => {
    expect(precheckAgentPermit({ request, ...signatures, nowSeconds: request.expiresAt - 1 })).toEqual({
      ok: true,
      request,
      permitId: standard.permitId,
    });
    expect(precheckAgentPermit({ request, ...signatures, nowSeconds: request.expiresAt })).toMatchObject({
      ok: false,
      reason: "permit_expired",
    });
  });

  it("tolerates 30 seconds of clock skew between consumer instances and no more", () => {
    expect(
      precheckAgentPermit({ request, ...signatures, nowSeconds: request.issuedAt - 30 }).ok,
    ).toBe(true);
    expect(
      precheckAgentPermit({ request, ...signatures, nowSeconds: request.issuedAt - 31 }),
    ).toMatchObject({ ok: false, reason: "invalid_permit" });
  });

  it("checks expiry before either signature", () => {
    expect(
      precheckAgentPermit({
        request,
        operatorSignature: "00".repeat(64),
        presentationSignature: "00".repeat(64),
        nowSeconds: request.expiresAt + 5,
      }),
    ).toMatchObject({ ok: false, reason: "permit_expired" });
  });

  it("names which signature failed", () => {
    const now = request.issuedAt + 1;
    expect(
      precheckAgentPermit({
        request,
        operatorSignature: sign(other.seedHex, standard.message),
        presentationSignature: standard.presentationSignature,
        nowSeconds: now,
      }),
    ).toMatchObject({ ok: false, reason: "invalid_signature" });
    expect(
      precheckAgentPermit({
        request,
        operatorSignature: standard.operatorSignature,
        presentationSignature: standard.copiedPresentationSignature,
        nowSeconds: now,
      }),
    ).toMatchObject({ ok: false, reason: "invalid_presentation" });
  });

  it("refuses an invalid settlement clock", () => {
    for (const nowSeconds of [0, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER]) {
      expect(() => precheckAgentPermit({ request, ...signatures, nowSeconds })).toThrow(
        AgentPermitValidationError,
      );
    }
  });
});

describe("settlement evaluation", () => {
  const request = standard.request;
  const now = request.issuedAt + 60;

  it("allows a bound agent under a passing operator policy", () => {
    const result = settle(request, now);
    expect(result).toMatchObject({
      decision: "allow",
      reason: "accepted",
      permitId: standard.permitId,
      evaluatedAt: now,
      expiresAt: now + 90,
    });
    expect(result.policy?.decision).toBe("allow");
    expect(result.agentState?.owner).toBe(request.operator);
  });

  it("caps the result at the permit expiry", () => {
    const late = request.expiresAt - 5;
    expect(settle(request, late)).toMatchObject({ decision: "allow", expiresAt: request.expiresAt });
  });

  it("reports expiry before reading anything else", () => {
    expect(
      settle(request, request.expiresAt, {
        state: { status: "unavailable", reason: "rpc_unavailable" },
        evidence: { status: "unavailable", reason: "rpc_unavailable" },
      }),
    ).toMatchObject({ decision: "deny", reason: "permit_expired" });
  });

  it("maps every agent state failure", () => {
    expect(settle(request, now, { state: { status: "unavailable", reason: "rpc_unavailable" } })).toMatchObject({
      decision: "unavailable",
      reason: "agent_unavailable",
    });
    for (const [reason, expected] of [
      ["wrong_cluster", "wrong_cluster"],
      ["agent_missing", "agent_missing"],
      ["agent_unregistered", "agent_unregistered"],
      ["agent_invalid", "agent_invalid"],
      ["invalid_request", "agent_invalid"],
      ["rpc_unavailable", "agent_invalid"],
    ] as const) {
      expect(settle(request, now, { state: { status: "invalid", reason } })).toMatchObject({
        decision: "deny",
        reason: expected,
      });
    }
  });

  it("rejects agent state for another agent, deployment or shape", () => {
    const mismatched: AgentStateReadResult[] = [
      agentState(request, { agent: base58Encode(new Uint8Array(32).fill(9)) }),
      agentState(request, { agentCollection: "C6W2bq4BoVT8FDvqhdp3sbcHFBjNBXE8TsNak2wTXQs9" }),
      agentState(request, { agentWalletStatus: "unbound" }),
      agentState(request, { cachedOwner: other.publicKey }),
      { status: "available", evidence: { ...(agentState(request) as { evidence: AgentStateEvidence }).evidence, snapshot: true } as unknown as AgentStateEvidence },
    ];
    for (const state of mismatched) {
      expect(settle(request, now, { state })).toMatchObject({ decision: "deny", reason: "agent_invalid" });
    }
  });

  it("denies a permit after the agent moves to another owner", () => {
    expect(
      settle(request, now, {
        state: agentState(request, {
          owner: other.publicKey,
          cachedOwner: other.publicKey,
          agentWallet: null,
          agentWalletStatus: "unbound",
        }),
      }),
    ).toMatchObject({ decision: "deny", reason: "owner_changed" });
    expect(
      settle(request, now, {
        state: agentState(request, {
          owner: other.publicKey,
          agentWalletStatus: "stale",
        }),
      }),
    ).toMatchObject({ decision: "deny", reason: "owner_changed" });
  });

  it("names each agent wallet failure", () => {
    expect(
      settle(request, now, {
        state: agentState(request, { cachedOwner: other.publicKey, agentWalletStatus: "stale" }),
      }),
    ).toMatchObject({ reason: "agent_wallet_stale" });
    expect(
      settle(request, now, {
        state: agentState(request, { agentWallet: null, agentWalletStatus: "unbound" }),
      }),
    ).toMatchObject({ reason: "agent_wallet_unbound" });
    expect(
      settle(request, now, { state: agentState(request, { agentWallet: other.publicKey }) }),
    ).toMatchObject({ reason: "agent_wallet_changed" });
  });

  it("reads the operator policy at settlement", () => {
    expect(
      settle(request, now, {
        evidence: operatorEvidence(now, request.operator, (evidence) => {
          evidence.identity.trustScore = 99;
        }),
      }),
    ).toMatchObject({ decision: "deny", reason: "score_below_minimum" });
    expect(
      settle(request, now, {
        evidence: operatorEvidence(now, request.operator, (evidence) => {
          evidence.identity.lastVerificationTimestamp = now - 86400;
          evidence.transaction.blockTime = now - 86400;
          evidence.identity.creationTimestamp = now - 90000;
        }),
      }),
    ).toMatchObject({ decision: "deny", reason: "verification_stale" });
    expect(settle(request, now, { evidence: { status: "unavailable", reason: "rpc_unavailable" } })).toMatchObject({
      decision: "unavailable",
      reason: "state_unavailable",
    });
  });

  it("requires an attestation when the signed policy asks for one", () => {
    const strict = vectors.valid[1] as ValidVector;
    const strictNow = strict.request.issuedAt + 10;
    const result = evaluateAgentPermit({
      request: strict.request,
      operatorSignature: strict.operatorSignature,
      presentationSignature: strict.presentationSignature,
      agentState: agentState(strict.request),
      operatorEvidence: operatorEvidence(strictNow, strict.request.operator, (evidence) => {
        evidence.identity.trustScore = 600;
      }),
      nowSeconds: strictNow,
    });
    expect(result).toMatchObject({ decision: "deny", reason: "attestation_required" });
  });

  it("rejects operator evidence for another wallet", () => {
    expect(settle(request, now, { evidence: operatorEvidence(now, other.publicKey) })).toMatchObject({
      decision: "deny",
      reason: "invalid_evidence",
    });
  });

  it("handles operator and agent wallet rotation", () => {
    const migrated = operatorEvidence(now, other.publicKey);
    expect(
      settle(request, now, {
        state: agentState(request, {
          owner: other.publicKey,
          cachedOwner: other.publicKey,
          agentWallet: request.agentWallet,
        }),
        evidence: migrated,
      }),
    ).toMatchObject({ reason: "owner_changed" });

    const rotatedKey = vectors.keys.agentWallet.publicKey === request.agentWallet ? other : agentWallet;
    expect(
      settle(request, now, { state: agentState(request, { agentWallet: rotatedKey.publicKey }) }),
    ).toMatchObject({ reason: "agent_wallet_changed" });
    const rebound = { ...request, agentWallet: rotatedKey.publicKey };
    expect(settle(rebound, now, { signatures: signed(rebound, rotatedKey.seedHex) })).toMatchObject({
      decision: "allow",
    });
  });

  it("validates the agent state shape independently", () => {
    const evidence = (agentState(request) as { evidence: AgentStateEvidence }).evidence;
    expect(isAgentStateEvidence(evidence)).toBe(true);
    expect(isAgentStateEvidence({ ...evidence, readContextSlot: -1 })).toBe(false);
    expect(isAgentStateEvidence({ ...evidence, owner: "not base58" })).toBe(false);
  });
});

describe("transport encodings", () => {
  it("round-trips the signing page fragment", () => {
    const fragment = encodeAgentPermitFragment(standard.request);
    expect(fragment.startsWith("request=")).toBe(true);
    expect(parseAgentPermitFragment(`#${fragment}`)).toEqual({
      request: standard.request,
      message: standard.message,
    });
  });

  it("rejects other fragments", () => {
    for (const fragment of [
      "",
      "bind=abc",
      "request=***",
      "request=" + "A".repeat(9000),
      "request=" + Buffer.from(standard.message + "\n").toString("base64url"),
    ]) {
      expect(parseAgentPermitFragment(fragment)).toBeNull();
    }
  });

  it("rejects malformed approvals and settlement bundles", () => {
    const approval = JSON.parse(standard.approval) as Record<string, unknown>;
    const bundle = JSON.parse(standard.settlementBundle) as Record<string, unknown>;
    for (const value of [
      { ...approval, extra: 1 },
      { ...approval, version: 2 },
      { ...approval, operatorSignature: String(approval.operatorSignature).toUpperCase() },
      { ...approval, verifiedTransaction: "1" + String(approval.verifiedTransaction) },
      "not json",
    ]) {
      expect(parseAgentPermitApproval(value)).toBeNull();
    }
    for (const value of [
      { ...bundle, extra: 1 },
      { ...bundle, nonce: "0".repeat(64) },
      { ...bundle, presentationSignature: "00" },
    ]) {
      expect(parseAgentPermitSettlement(value)).toBeNull();
    }
  });
});
