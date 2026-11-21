// @vitest-environment node
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import {
  encodeAgentPermitSettlement,
  renderAgentPermitPresentation,
  type AgentStateReadResult,
} from "../src/agent-permit";
import {
  canonicalizeJson,
  canonicalizeMcpAction,
  createChallengeFromOpenAiMcpRequest,
  createHumanLayerApprovalCall,
  createInMemoryNonceStore,
  createMcpApprovalChallenge,
  createMcpApprovalGate,
  hashMcpAction,
  McpActionValidationError,
  McpApprovalError,
  McpNonceStoreError,
  settleOpenAiMcpApproval,
  toOpenAiMcpApprovalRequest,
  verifyHumanLayerApprovalCallback,
  verifyMcpApprovalSettlement,
  type McpApprovalChallenge,
  type OpenAiMcpApprovalRequest,
} from "../src/mcp";
import {
  AGENT_REGISTRY_DEVNET_CONFIG,
  base58Encode,
  deriveAgentAccountPda,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveSasAttestationPda,
  readAgentState,
  readIntegratorEvidence,
  SAS_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_PROGRAM_IDS,
  SolanaAddress,
  type SolanaTransport,
} from "../src/solana";
import {
  buildAgentAccountBuffer,
  buildCoreAssetBuffer,
  createEvidenceFixture,
  toBase64,
} from "./solana-fixtures";

const encoder = new TextEncoder();

function keypairFromSeed(fill: number) {
  const secret = new Uint8Array(32).fill(fill);
  const pubkeyBytes = ed25519.getPublicKey(secret);
  return {
    secret,
    publicKey: base58Encode(pubkeyBytes),
  };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function signText(secret: Uint8Array, text: string): string {
  return toHex(ed25519.sign(encoder.encode(text), secret));
}

const OWNER_KEY = keypairFromSeed(0x21);
const AGENT_WALLET_KEY = keypairFromSeed(0x32);
const ATTACKER_KEY = keypairFromSeed(0x43);
const NEW_OWNER_KEY = keypairFromSeed(0x54);
const AGENT_ASSET = base58Encode(new Uint8Array(32).fill(0x65));
const AUDIENCE = "https://mcp.example.test/tools/execute";
const NOW = 1_800_000_000;

function signChallenge(
  challenge: McpApprovalChallenge,
  verifiedTransaction: string,
  opts: {
    operatorSecret?: Uint8Array;
    agentSecret?: Uint8Array;
  } = {},
) {
  const operatorSignature = signText(
    opts.operatorSecret ?? OWNER_KEY.secret,
    challenge.message,
  );
  const presentationSignature = signText(
    opts.agentSecret ?? AGENT_WALLET_KEY.secret,
    renderAgentPermitPresentation(challenge.permitId),
  );
  return encodeAgentPermitSettlement({
    nonce: challenge.nonce,
    operatorSignature,
    presentationSignature,
    verifiedTransaction,
  });
}

function createMockChain(opts: {
  owner?: string;
  cachedOwner?: string;
  agentWallet?: string | null;
  blockTime?: number;
  lastVerificationTimestamp?: number;
  trustScore?: number;
  expiry?: number;
  migratedAt?: number;
  delayMs?: number;
  failRpc?: boolean;
} = {}) {
  const owner = opts.owner ?? OWNER_KEY.publicKey;
  const cachedOwner = opts.cachedOwner ?? owner;
  const agentWallet =
    opts.agentWallet === undefined ? AGENT_WALLET_KEY.publicKey : opts.agentWallet;

  const evidenceFixture = createEvidenceFixture({
    walletPubkey: OWNER_KEY.publicKey,
    nowSeconds: NOW,
    blockTime: opts.blockTime ?? NOW - 60,
    lastVerificationTimestamp:
      opts.lastVerificationTimestamp ?? opts.blockTime ?? NOW - 60,
    trustScore: opts.trustScore ?? 500,
    expiry: opts.expiry ?? NOW + 3600,
    migratedAt: opts.migratedAt,
  });

  const [identityAddr] = deriveIdentityPda(OWNER_KEY.publicKey);
  const [attAddr] = deriveSasAttestationPda(OWNER_KEY.publicKey);
  const [migAddr] = deriveMigrationRecordPda(OWNER_KEY.publicKey);
  const [agentAccountAddr] = deriveAgentAccountPda(AGENT_ASSET);

  const assetBuf = buildCoreAssetBuffer({ owner });
  const agentAccountBuf = buildAgentAccountBuffer({
    asset: AGENT_ASSET,
    cachedOwner,
    agentWallet,
  });

  let rpcCalls = 0;

  const mockFetch: typeof globalThis.fetch = async (_url, init) => {
    rpcCalls += 1;
    if (opts.delayMs) {
      await new Promise((resolve) => setTimeout(resolve, opts.delayMs));
    }
    if (opts.failRpc) {
      throw new Error("Synthetic RPC outage");
    }
    const body = JSON.parse(String(init?.body)) as {
      id: number;
      method: string;
      params: unknown[];
    };
    let result: unknown;
    if (body.method === "getGenesisHash") {
      result = SOLANA_DEVNET_GENESIS_HASH;
    } else if (body.method === "getSignatureStatuses") {
      result = { context: { slot: 101 }, value: [evidenceFixture.status] };
    } else if (body.method === "getTransaction") {
      result = {
        ...evidenceFixture.transaction,
        transaction: {
          signatures: evidenceFixture.transaction.transaction.signatures,
          message: {
            accountKeys:
              evidenceFixture.transaction.transaction.message.accountKeys.map(
                (k) => ({
                  pubkey: new SolanaAddress(k.pubkey).toBase58(),
                  signer: k.signer,
                  writable: k.writable,
                }),
              ),
            instructions:
              evidenceFixture.transaction.transaction.message.instructions.map(
                (ix) =>
                  "accounts" in ix
                    ? {
                        programId: new SolanaAddress(ix.programId).toBase58(),
                        accounts: ix.accounts.map((a) =>
                          new SolanaAddress(a).toBase58(),
                        ),
                        data: ix.data,
                      }
                    : ix,
              ),
          },
        },
      };
    } else if (body.method === "getMultipleAccounts") {
      const addresses = body.params[0] as string[];
      result = {
        context: { slot: 105 },
        value: addresses.map((addr) => {
          if (addr === AGENT_ASSET) {
            return {
              data: [toBase64(assetBuf), "base64"],
              executable: false,
              lamports: 1,
              owner: AGENT_REGISTRY_DEVNET_CONFIG.coreProgramId,
            };
          }
          if (addr === agentAccountAddr) {
            return {
              data: [toBase64(agentAccountBuf), "base64"],
              executable: false,
              lamports: 1,
              owner: AGENT_REGISTRY_DEVNET_CONFIG.programId,
            };
          }
          return null;
        }),
      };
    } else if (body.method === "getAccountInfo") {
      const addr = String(body.params[0]);
      if (addr === identityAddr) {
        result = {
          context: { slot: 102 },
          value: {
            data: [toBase64(evidenceFixture.identityAccount.data), "base64"],
            executable: false,
            lamports: 1,
            owner: SOLANA_PROGRAM_IDS.anchor,
          },
        };
      } else if (addr === attAddr) {
        result = {
          context: { slot: 102 },
          value: {
            data: [toBase64(evidenceFixture.sasAccount.data), "base64"],
            executable: false,
            lamports: 1,
            owner: SAS_DEVNET_CONFIG.programId,
          },
        };
      } else if (addr === migAddr) {
        result = {
          context: { slot: 102 },
          value: evidenceFixture.migrationAccount
            ? {
                data: [toBase64(evidenceFixture.migrationAccount.data), "base64"],
                executable: false,
                lamports: 1,
                owner: SOLANA_PROGRAM_IDS.anchor,
              }
            : null,
        };
      }
    }
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
      { status: 200 },
    );
  };

  const connection: SolanaTransport = {
    endpoint: "https://rpc.example.test",
    fetch: mockFetch,
  };

  return {
    connection,
    verifiedTransaction: evidenceFixture.input.transactionSignature,
    evidenceFixture,
    get rpcCalls() {
      return rpcCalls;
    },
    resetRpcCalls() {
      rpcCalls = 0;
    },
  };
}

describe("canonical MCP action hashing", () => {
  it("produces identical SHA-256 regardless of object key order and normalizes -0", () => {
    const a = canonicalizeMcpAction({
      server: "treasury",
      tool: "transfer",
      arguments: { z: -0, nested: { b: "two", a: 1 }, list: [1, 2] },
    });
    const b = canonicalizeMcpAction({
      server: "treasury",
      tool: "transfer",
      arguments: { list: [1, 2], nested: { a: 1, b: "two" }, z: 0 },
    });
    expect(a.sha256).toBe(b.sha256);
    expect(a.canonicalJson).toBe(b.canonicalJson);
    expect(a.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes SHA-256 on any argument, tool, or server mutation", () => {
    const base = hashMcpAction({
      server: "treasury",
      tool: "transfer",
      arguments: { amount: 100, recipient: "alice" },
    });
    expect(
      hashMcpAction({
        server: "treasury",
        tool: "transfer",
        arguments: { amount: 101, recipient: "alice" },
      }),
    ).not.toBe(base);
    expect(
      hashMcpAction({
        server: "treasury",
        tool: "transfer",
        arguments: { amount: "100", recipient: "alice" },
      }),
    ).not.toBe(base);
    expect(
      hashMcpAction({
        server: "other",
        tool: "transfer",
        arguments: { amount: 100, recipient: "alice" },
      }),
    ).not.toBe(base);
  });

  it("fails closed on undefined, NaN, Infinity, cycles, and deep nesting", () => {
    expect(() =>
      canonicalizeMcpAction({
        server: "s",
        tool: "t",
        arguments: { bad: undefined },
      }),
    ).toThrow(McpActionValidationError);
    expect(() => canonicalizeJson({ x: Number.NaN })).toThrow(
      McpActionValidationError,
    );
    expect(() => canonicalizeJson({ x: Number.POSITIVE_INFINITY })).toThrow(
      McpActionValidationError,
    );

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJson(cyclic)).toThrow(McpActionValidationError);

    let deep: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 40; i += 1) deep = { child: deep };
    expect(() => canonicalizeJson(deep)).toThrow(McpActionValidationError);
  });
});

describe("@entros/verify/mcp challenge creation and adversarial settlement", () => {
  const defaultAction = {
    server: "vault",
    tool: "release_funds",
    arguments: { recipient: "vendor-1", amountMinor: 5000 },
  };

  it("enforces <= 900s lifetime and rejects duplicate nonces or stale live agents", async () => {
    const nonceStore = createInMemoryNonceStore();
    for (const lifetimeSeconds of [29, 901, 0, -5, 1.5, Number.NaN]) {
      await expect(
        createMcpApprovalChallenge({
          subject: OWNER_KEY.publicKey,
          actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
          audience: AUDIENCE,
          action: defaultAction,
          lifetimeSeconds,
          nowSeconds: NOW,
        }),
      ).rejects.toThrow(McpApprovalError);
    }

    const staleChain = createMockChain({
      owner: NEW_OWNER_KEY.publicKey,
      cachedOwner: OWNER_KEY.publicKey,
    });
    await expect(
      createMcpApprovalChallenge({
        actor: { agent: AGENT_ASSET },
        audience: AUDIENCE,
        action: defaultAction,
        nowSeconds: NOW,
        connection: staleChain.connection,
      }),
    ).rejects.toMatchObject({ reason: "agent_wallet_stale" });

    const fixedNonce = "ab".repeat(32);
    await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      nowSeconds: NOW,
      nonce: fixedNonce,
      nonceStore,
    });
    await expect(
      createMcpApprovalChallenge({
        subject: OWNER_KEY.publicKey,
        actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
        audience: AUDIENCE,
        action: defaultAction,
        nowSeconds: NOW,
        nonce: fixedNonce,
        nonceStore,
      }),
    ).rejects.toThrow(McpNonceStoreError);
  });

  it("settles valid approval, preserves original verifiedAt and honest assurance, and refuses replay", async () => {
    const chain = createMockChain({
      blockTime: NOW - 120,
      lastVerificationTimestamp: NOW - 120,
      trustScore: 620,
    });
    const nonceStore = createInMemoryNonceStore();

    const challenge = await createMcpApprovalChallenge({
      actor: { agent: AGENT_ASSET },
      audience: AUDIENCE,
      action: defaultAction,
      policy: {
        id: "mcp-high-risk",
        version: 1,
        minTrustScore: 400,
        maxVerificationAgeSeconds: 3600,
        maxEvaluationAgeSeconds: 90,
        requiredAssurance: "browser_unattested",
        uniquenessRequirement: "allow_unmeasured",
        requireAttestation: true,
        cluster: "devnet",
      },
      lifetimeSeconds: 600,
      nowSeconds: NOW,
      connection: chain.connection,
      nonceStore,
    });

    expect(challenge.subject).toBe(OWNER_KEY.publicKey);
    expect(challenge.actor.agentWallet).toBe(AGENT_WALLET_KEY.publicKey);
    expect(challenge.assurance.tier).toBe("browser_unattested");
    expect(challenge.assurance.uniqueness).toBe("unmeasured");
    expect(challenge.assurance.executionPresenceProven).toBe(false);
    expect(challenge.assurance.notice.toLowerCase()).toContain(
      "does not prove human presence",
    );

    const settlement = signChallenge(challenge, chain.verifiedTransaction);
    const result = await verifyMcpApprovalSettlement({
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      expectedAction: defaultAction,
      expectedSubject: OWNER_KEY.publicKey,
      expectedActor: {
        agent: AGENT_ASSET,
        agentWallet: AGENT_WALLET_KEY.publicKey,
      },
      connection: chain.connection,
      nowSeconds: NOW + 30,
    });

    expect(result.decision).toBe("allow");
    if (result.decision !== "allow") return;
    // Original verifiedAt is preserved verbatim, never refreshed to settlement time.
    expect(result.verifiedAt).toBe(NOW - 120);
    expect(result.evaluatedAt).toBe(NOW + 30);
    expect(result.assuranceTier).toBe("browser_unattested");
    expect(result.uniquenessStatus).toBe("unmeasured");
    expect(result.executionPresenceProven).toBe(false);
    expect(result.trustScore).toBe(620);

    // Sequential replay is denied.
    const replay = await verifyMcpApprovalSettlement({
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      expectedAction: defaultAction,
      connection: chain.connection,
      nowSeconds: NOW + 31,
    });
    expect(replay).toMatchObject({
      decision: "deny",
      reason: "nonce_replayed",
    });
  });

  it("allows at most one winner under concurrent double-spend settlement races", async () => {
    const chain = createMockChain({ delayMs: 15 });
    const nonceStore = createInMemoryNonceStore();
    const challenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      nowSeconds: NOW,
      nonceStore,
    });
    const settlement = signChallenge(challenge, chain.verifiedTransaction);

    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        verifyMcpApprovalSettlement({
          settlement,
          nonceStore,
          expectedAudience: AUDIENCE,
          expectedAction: defaultAction,
          connection: chain.connection,
          nowSeconds: NOW + 5,
        }),
      ),
    );

    const allowed = results.filter((r) => r.decision === "allow");
    const replayed = results.filter(
      (r) => r.decision === "deny" && r.reason === "nonce_replayed",
    );
    expect(allowed).toHaveLength(1);
    expect(replayed).toHaveLength(9);
  });

  it("never burns a valid pending nonce on failed prechecks, tampered args, wrong audience, bad signatures, or RPC failure", async () => {
    const chain = createMockChain();
    const nonceStore = createInMemoryNonceStore();
    const challenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      nowSeconds: NOW,
      nonceStore,
    });
    const validSettlement = signChallenge(challenge, chain.verifiedTransaction);
    const wrongOpSig = signChallenge(challenge, chain.verifiedTransaction, {
      operatorSecret: ATTACKER_KEY.secret,
    });
    const wrongActorSig = signChallenge(challenge, chain.verifiedTransaction, {
      agentSecret: ATTACKER_KEY.secret,
    });

    chain.resetRpcCalls();

    // 1. Wrong audience (zero RPC, nonce unconsumed)
    expect(
      await verifyMcpApprovalSettlement({
        settlement: validSettlement,
        nonceStore,
        expectedAudience: "https://evil.example.test/tools/execute",
        expectedAction: defaultAction,
        connection: chain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "audience_mismatch" });

    // 2. Modified tool arguments (zero RPC, nonce unconsumed)
    expect(
      await verifyMcpApprovalSettlement({
        settlement: validSettlement,
        nonceStore,
        expectedAudience: AUDIENCE,
        expectedAction: {
          ...defaultAction,
          arguments: { recipient: "attacker", amountMinor: 5000 },
        },
        connection: chain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "action_mismatch" });

    // 3. Forged operator signature (zero RPC, nonce unconsumed)
    expect(
      await verifyMcpApprovalSettlement({
        settlement: wrongOpSig,
        nonceStore,
        expectedAudience: AUDIENCE,
        expectedAction: defaultAction,
        connection: chain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "invalid_signature" });

    // 4. Wrong actor wallet presentation signature (zero RPC, nonce unconsumed)
    expect(
      await verifyMcpApprovalSettlement({
        settlement: wrongActorSig,
        nonceStore,
        expectedAudience: AUDIENCE,
        expectedAction: defaultAction,
        connection: chain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "invalid_presentation" });

    // 5. Wrong expected actor (zero RPC, nonce unconsumed)
    expect(
      await verifyMcpApprovalSettlement({
        settlement: validSettlement,
        nonceStore,
        expectedActor: {
          agent: AGENT_ASSET,
          agentWallet: ATTACKER_KEY.publicKey,
        },
        connection: chain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "actor_mismatch" });

    // None of the precheck rejections touched RPC.
    expect(chain.rpcCalls).toBe(0);

    // 6. Transient RPC outage does not burn the nonce.
    const brokenChain = createMockChain({ failRpc: true });
    expect(
      await verifyMcpApprovalSettlement({
        settlement: validSettlement,
        nonceStore,
        expectedAudience: AUDIENCE,
        expectedAction: defaultAction,
        connection: brokenChain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "unavailable", reason: "agent_unavailable" });

    // Nonce is STILL unconsumed, so the legitimate settlement succeeds now.
    expect(nonceStore.peek(challenge.nonce)?.consumedAt).toBeNull();
    const ok = await verifyMcpApprovalSettlement({
      settlement: validSettlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      expectedAction: defaultAction,
      connection: chain.connection,
      nowSeconds: NOW + 10,
    });
    expect(ok.decision).toBe("allow");
  });

  it("refuses expired permits (precheck and mid-flight), stale verifiedAt, migrated wallets, and post-sale agent transfers", async () => {
    const nonceStore = createInMemoryNonceStore();

    // A. Expired permit at precheck (zero RPC)
    const expChain = createMockChain();
    const expChallenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      lifetimeSeconds: 60,
      nowSeconds: NOW,
      nonceStore,
    });
    const expSettlement = signChallenge(
      expChallenge,
      expChain.verifiedTransaction,
    );
    expect(
      await verifyMcpApprovalSettlement({
        settlement: expSettlement,
        nonceStore,
        connection: expChain.connection,
        nowSeconds: NOW + 60,
      }),
    ).toMatchObject({ decision: "deny", reason: "permit_expired" });
    expect(expChain.rpcCalls).toBe(0);

    // B. Mid-flight permit expiration after RPC reads complete
    const midChain = createMockChain();
    const midChallenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      lifetimeSeconds: 60,
      nowSeconds: NOW,
      nonceStore,
    });
    const midSettlement = signChallenge(
      midChallenge,
      midChain.verifiedTransaction,
    );
    let ticks = 0;
    const advancingClock = () => {
      ticks += 1;
      return ticks === 1 ? NOW + 55 : NOW + 65;
    };
    expect(
      await verifyMcpApprovalSettlement({
        settlement: midSettlement,
        nonceStore,
        readAgentState: ({ agent }) =>
          readAgentState({ agent, connection: midChain.connection }),
        readIntegratorEvidence: ({ walletPubkey, transactionSignature }) =>
          readIntegratorEvidence({
            walletPubkey,
            transactionSignature,
            connection: midChain.connection,
            nowSeconds: NOW + 55,
          }),
        nowSeconds: advancingClock,
      }),
    ).toMatchObject({ decision: "deny", reason: "permit_expired" });
    expect(nonceStore.peek(midChallenge.nonce)?.consumedAt).toBeNull();

    // C. Stale verifiedAt evidence
    const staleChain = createMockChain({
      blockTime: NOW - 500,
      lastVerificationTimestamp: NOW - 500,
    });
    const staleChallenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      policy: {
        id: "fresh-only",
        version: 1,
        minTrustScore: 100,
        maxVerificationAgeSeconds: 300,
        requiredAssurance: "browser_unattested",
        uniquenessRequirement: "allow_unmeasured",
        cluster: "devnet",
      },
      nowSeconds: NOW,
      nonceStore,
    });
    expect(
      await verifyMcpApprovalSettlement({
        settlement: signChallenge(
          staleChallenge,
          staleChain.verifiedTransaction,
        ),
        nonceStore,
        connection: staleChain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "verification_stale" });

    // D. Migrated source wallet (57-byte MigrationRecord invalidates prior attestation)
    const migChain = createMockChain({
      blockTime: NOW - 60,
      migratedAt: NOW - 60,
    });
    const migChallenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      policy: {
        id: "attestation-required",
        version: 1,
        minTrustScore: 100,
        maxVerificationAgeSeconds: 3600,
        requiredAssurance: "browser_unattested",
        uniquenessRequirement: "allow_unmeasured",
        requireAttestation: true,
        cluster: "devnet",
      },
      nowSeconds: NOW,
      nonceStore,
    });
    expect(
      await verifyMcpApprovalSettlement({
        settlement: signChallenge(migChallenge, migChain.verifiedTransaction),
        nonceStore,
        connection: migChain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "attestation_required" });

    // E. Post-sale / transferred agent Core asset
    const transferredChain = createMockChain({
      owner: NEW_OWNER_KEY.publicKey,
      cachedOwner: OWNER_KEY.publicKey,
    });
    const transferChallenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: defaultAction,
      nowSeconds: NOW,
      nonceStore,
    });
    expect(
      await verifyMcpApprovalSettlement({
        settlement: signChallenge(
          transferChallenge,
          transferredChain.verifiedTransaction,
        ),
        nonceStore,
        connection: transferredChain.connection,
        nowSeconds: NOW + 5,
      }),
    ).toMatchObject({ decision: "deny", reason: "owner_changed" });
  });
});

describe("OpenAI mcp_approval_request, HumanLayer callbacks, and createMcpApprovalGate", () => {
  it("completes and enforces OpenAI mcp_approval_request / mcp_approval_response roundtrip", async () => {
    const chain = createMockChain();
    const nonceStore = createInMemoryNonceStore();

    const incoming: OpenAiMcpApprovalRequest = {
      type: "mcp_approval_request",
      id: "mcpr_01abc",
      server_label: "payments",
      name: "send_payout",
      arguments: JSON.stringify({ currency: "USDC", amount: 250 }),
    };

    const { challenge, approvalRequest } =
      await createChallengeFromOpenAiMcpRequest(incoming, {
        actor: { agent: AGENT_ASSET },
        audience: AUDIENCE,
        nowSeconds: NOW,
        connection: chain.connection,
        nonceStore,
      });

    expect(toOpenAiMcpApprovalRequest(challenge, { id: incoming.id })).toEqual(
      approvalRequest,
    );

    const settlement = signChallenge(challenge, chain.verifiedTransaction);

    // Tampered arguments on resume are rejected without burning the nonce.
    const tampered = await settleOpenAiMcpApproval({
      approvalRequest: {
        ...incoming,
        arguments: JSON.stringify({ currency: "USDC", amount: 9999 }),
      },
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 10,
    });
    expect(tampered.response).toEqual({
      type: "mcp_approval_response",
      approval_request_id: "mcpr_01abc",
      approve: false,
      reason: "action_mismatch",
    });

    // Authentic request settles and approves once.
    const accepted = await settleOpenAiMcpApproval({
      approvalRequest: incoming,
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 11,
    });
    expect(accepted.response).toEqual({
      type: "mcp_approval_response",
      approval_request_id: "mcpr_01abc",
      approve: true,
    });

    // Replay returns approve: false with nonce_replayed.
    const replayed = await settleOpenAiMcpApproval({
      approvalRequest: incoming,
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 12,
    });
    expect(replayed.response).toEqual({
      type: "mcp_approval_response",
      approval_request_id: "mcpr_01abc",
      approve: false,
      reason: "nonce_replayed",
    });
  });

  it("completes and enforces HumanLayer pause/resume callbacks", async () => {
    const chain = createMockChain();
    const nonceStore = createInMemoryNonceStore();

    const challenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: {
        server: "ops",
        tool: "rotate_key",
        arguments: { environment: "devnet", keyId: "k-1" },
      },
      nowSeconds: NOW,
      nonceStore,
    });

    const call = createHumanLayerApprovalCall(challenge, {
      runId: "run_42",
      callId: "call_7",
      state: { ticket: "internal-free" },
    });
    expect(call.spec.fn).toBe("ops.rotate_key");
    expect(call.spec.state.entros.executionPresenceProven).toBe(false);
    expect(call.spec.state.entros.assuranceTier).toBe("browser_unattested");

    const settlement = signChallenge(challenge, chain.verifiedTransaction);

    // Denied by human reviewer -> resume: false, nonce intact.
    const rejected = await verifyHumanLayerApprovalCallback({
      callback: {
        ...call,
        status: { approved: false, comment: "Not now" },
      },
      settlement,
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 10,
    });
    expect(rejected).toMatchObject({
      runId: "run_42",
      callId: "call_7",
      resume: false,
      settlement: { decision: "deny", reason: "approval_rejected" },
    });

    // Tampered kwargs -> action_mismatch, nonce intact.
    const tampered = await verifyHumanLayerApprovalCallback({
      callback: {
        ...call,
        spec: {
          ...call.spec,
          kwargs: { environment: "devnet", keyId: "k-999" },
        },
        status: {
          approved: true,
          metadata: { entrosSettlement: settlement },
        },
      },
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 11,
    });
    expect(tampered).toMatchObject({
      resume: false,
      settlement: { decision: "deny", reason: "action_mismatch" },
    });

    // Genuine approved callback resumes once.
    const resumed = await verifyHumanLayerApprovalCallback({
      callback: {
        ...call,
        status: {
          approved: true,
          metadata: { entrosSettlement: settlement },
        },
      },
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 12,
    });
    expect(resumed.resume).toBe(true);
    expect(resumed.settlement.decision).toBe("allow");

    // Replayed webhook refused.
    const replayed = await verifyHumanLayerApprovalCallback({
      callback: {
        ...call,
        status: {
          approved: true,
          metadata: { entrosSettlement: settlement },
        },
      },
      nonceStore,
      expectedAudience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: NOW + 13,
    });
    expect(replayed).toMatchObject({
      resume: false,
      settlement: { decision: "deny", reason: "nonce_replayed" },
    });
  });

  it("wires audience, policy, nonceStore, and Solana connection via createMcpApprovalGate", async () => {
    const chain = createMockChain();
    const gate = createMcpApprovalGate({
      audience: AUDIENCE,
      connection: chain.connection,
      nowSeconds: () => NOW + 10,
    });

    const challenge = await gate.createChallenge({
      actor: { agent: AGENT_ASSET },
      action: {
        server: "governance",
        tool: "cast_vote",
        arguments: { proposal: "prop-1", choice: "yes" },
      },
    });
    const settlement = signChallenge(challenge, chain.verifiedTransaction);
    const result = await gate.verifySettlement({
      settlement,
      expectedAction: {
        server: "governance",
        tool: "cast_vote",
        arguments: { choice: "yes", proposal: "prop-1" },
      },
    });
    expect(result.decision).toBe("allow");
  });

  it("refuses agent_wallet_changed when the agent wallet rotated after permit issuance", async () => {
    const rotatedWallet = keypairFromSeed(0x77).publicKey;
    const chain = createMockChain({ agentWallet: rotatedWallet });
    const nonceStore = createInMemoryNonceStore();
    const challenge = await createMcpApprovalChallenge({
      subject: OWNER_KEY.publicKey,
      actor: { agent: AGENT_ASSET, agentWallet: AGENT_WALLET_KEY.publicKey },
      audience: AUDIENCE,
      action: {
        server: "vault",
        tool: "withdraw",
        arguments: { amount: 1 },
      },
      nowSeconds: NOW,
      nonceStore,
    });
    const settlement = signChallenge(challenge, chain.verifiedTransaction);
    const res = await verifyMcpApprovalSettlement({
      settlement,
      nonceStore,
      connection: chain.connection,
      nowSeconds: NOW + 5,
    });
    expect(res).toMatchObject({
      decision: "deny",
      reason: "agent_wallet_changed",
    });

    // Also ensure an unavailable custom agentState maps to unavailable.
    const unavailableAgent = await verifyMcpApprovalSettlement({
      settlement,
      nonceStore,
      readAgentState: async (): Promise<AgentStateReadResult> => ({
        status: "unavailable",
        reason: "rpc_unavailable",
      }),
      readIntegratorEvidence: async () => ({
        status: "unavailable",
        reason: "rpc_unavailable",
      }),
      nowSeconds: NOW + 5,
    });
    expect(unavailableAgent).toMatchObject({
      decision: "unavailable",
      reason: "agent_unavailable",
    });
  });
});
