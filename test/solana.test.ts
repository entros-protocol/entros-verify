// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AGENT_REGISTRY_DEVNET_CONFIG,
  base58Decode,
  base58Encode,
  BLOCK_TIME_TOLERANCE_SECONDS,
  CLOCK_CATCH_UP_SECONDS,
  createProgramAddressSync,
  createSolanaRpcClient,
  decodeBase64,
  decodeIdentityState,
  deriveAgentAccountPda,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveMintPda,
  deriveSasAttestationPda,
  findLatestVerificationTransaction,
  findProgramAddressSync,
  INTEGRATOR_DEVNET_GENESIS_HASH,
  isOnEd25519Curve,
  readAgentState,
  readIntegratorEvidence,
  readMigrationRecord,
  SAS_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_PROGRAM_IDS,
  SolanaAddress,
  SYSTEM_PROGRAM_ID,
  verifyEntrosAttestation,
  type ParsedTransactionLike,
  type SignatureInfoLike,
  type SolanaConnectionLike,
} from "../src/solana";
import {
  buildAgentAccountBuffer,
  buildCoreAssetBuffer,
  buildIdentityStateBuffer,
  buildMigrationRecordBuffer,
  buildSasAttestationBuffer,
  createEvidenceFixture,
  encodeResetInstruction,
  toBase64,
} from "./solana-fixtures";

const WALLET = base58Encode(new Uint8Array(32).fill(7));
const AGENT = base58Encode(new Uint8Array(32).fill(11));
const OWNER = base58Encode(new Uint8Array(32).fill(12));
const OTHER = base58Encode(new Uint8Array(32).fill(13));
const AGENT_WALLET = base58Encode(new Uint8Array(32).fill(14));

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("@entros/verify/solana address, base64, and PDA primitives", () => {
  it("derives deterministic off-curve PDAs and rejects invalid seeds", () => {
    const [identityPda, bump] = deriveIdentityPda(WALLET);
    expect(bump).toBeGreaterThanOrEqual(0);
    expect(bump).toBeLessThanOrEqual(255);
    expect(isOnEd25519Curve(new SolanaAddress(identityPda).toBytes())).toBe(false);

    const recreated = createProgramAddressSync(
      [new TextEncoder().encode("identity"), new SolanaAddress(WALLET).toBytes(), Uint8Array.of(bump)],
      SOLANA_PROGRAM_IDS.anchor,
    );
    expect(recreated).toBe(identityPda);

    expect(() =>
      findProgramAddressSync([new Uint8Array(33)], SOLANA_PROGRAM_IDS.anchor),
    ).toThrow(TypeError);
    expect(() =>
      findProgramAddressSync(
        Array.from({ length: 16 }, () => new Uint8Array(1)),
        SOLANA_PROGRAM_IDS.anchor,
      ),
    ).toThrow(TypeError);
  });

  it("decodes valid base64 and rejects malformed base64", () => {
    const sample = Uint8Array.from([0, 1, 2, 253, 254, 255]);
    expect(decodeBase64(toBase64(sample))).toEqual(sample);
    expect(decodeBase64("")).toEqual(new Uint8Array(0));
    expect(decodeBase64("abc")).toBeNull();
    expect(decodeBase64("!!!!")).toBeNull();
  });
});

describe("decodeIdentityState and readMigrationRecord", () => {
  it.each([543, 551, 583, 593])(
    "decodes supported %i-byte IdentityState layout",
    (length) => {
      const raw = buildIdentityStateBuffer({
        owner: WALLET,
        trustScore: 481,
        verificationCount: 7,
        lastVerificationTimestamp: 1_700_009_999,
        lastResetTimestamp: 1_699_000_000,
        projectionVersion: 2,
        lastRebaselineTimestamp: 1_699_500_000,
        length,
      });
      const decoded = decodeIdentityState(raw);
      expect(decoded).not.toBeNull();
      expect(decoded!.owner).toBe(WALLET);
      expect(decoded!.trustScore).toBe(481);
      expect(decoded!.verificationCount).toBe(7);
      expect(decoded!.lastResetTimestamp).toBe(length >= 551 ? 1_699_000_000 : 0);
      expect(decoded!.projectionVersion).toBe(length >= 593 ? 2 : 0);
      expect(decoded!.lastRebaselineTimestamp).toBe(
        length >= 593 ? 1_699_500_000 : 0,
      );
    },
  );

  it("rejects legacy pre-543 layouts, bad discriminators, and unsafe timestamps", () => {
    expect(
      decodeIdentityState(buildIdentityStateBuffer({ owner: WALLET, length: 207 })),
    ).toBeNull();
    const badDisc = buildIdentityStateBuffer({ owner: WALLET });
    badDisc[0] = 0;
    expect(decodeIdentityState(badDisc)).toBeNull();

    const unsafe = buildIdentityStateBuffer({ owner: WALLET });
    new DataView(unsafe.buffer).setBigInt64(40, 9_007_199_254_740_992n, true);
    expect(decodeIdentityState(unsafe)).toBeNull();
  });

  it("parses 57-byte and extended MigrationRecord buffers and fails closed on corruption", () => {
    const valid = buildMigrationRecordBuffer(1_799_999_000);
    expect(
      readMigrationRecord({
        data: valid,
        executable: false,
        owner: SOLANA_PROGRAM_IDS.anchor,
      }),
    ).toEqual({ status: "migrated", migratedAt: 1_799_999_000 });

    const extended = new Uint8Array(65);
    extended.set(valid, 0);
    expect(
      readMigrationRecord({
        data: extended,
        executable: false,
        owner: SOLANA_PROGRAM_IDS.anchor,
      }),
    ).toEqual({ status: "migrated", migratedAt: 1_799_999_000 });

    // Absent or foreign-owned address reads as none.
    expect(readMigrationRecord(null)).toEqual({ status: "none" });
    expect(
      readMigrationRecord({
        data: valid,
        executable: false,
        owner: SYSTEM_PROGRAM_ID,
      }),
    ).toEqual({ status: "none" });

    // Truncated, bad discriminator, zero timestamp, or executable fails closed.
    expect(
      readMigrationRecord({
        data: valid.subarray(0, 56),
        executable: false,
        owner: SOLANA_PROGRAM_IDS.anchor,
      }),
    ).toEqual({ status: "invalid" });
    expect(
      readMigrationRecord({
        data: valid,
        executable: true,
        owner: SOLANA_PROGRAM_IDS.anchor,
      }),
    ).toEqual({ status: "invalid" });
  });
});

describe("verifyEntrosAttestation", () => {
  const SAS_OWNER = new SolanaAddress(SAS_DEVNET_CONFIG.programId);
  const ANCHOR_OWNER = new SolanaAddress(SOLANA_PROGRAM_IDS.anchor);

  it("verifies active attestation, clamps trustScore, and flags post-reset expiry", async () => {
    const sasBuf = buildSasAttestationBuffer({
      wallet: WALLET,
      trustScore: 720,
      verifiedAt: 1_780_000_000n,
      expiry: 4_000_000_000n,
    });
    const resetIdBuf = buildIdentityStateBuffer({
      owner: WALLET,
      creationTimestamp: 1_700_000_000,
      trustScore: 0,
      lastResetTimestamp: 1_780_000_100,
    });
    const connection: SolanaConnectionLike = {
      getMultipleAccountsInfo: async () => [
        { data: sasBuf, owner: SAS_OWNER },
        { data: resetIdBuf, owner: ANCHOR_OWNER },
        null,
      ],
    };
    expect(
      await verifyEntrosAttestation(WALLET, connection, {
        nowSeconds: 1_790_000_000,
      }),
    ).toEqual({
      isHuman: true,
      trustScore: 0,
      verifiedAt: 1_780_000_000,
      mode: "wallet-connected",
      expired: true,
    });
  });

  it("handles 64-bit post-2038 expiry and migration invalidation over JSON-RPC fetch", async () => {
    const sasBuf = buildSasAttestationBuffer({
      wallet: WALLET,
      trustScore: 650,
      verifiedAt: 1_780_000_000n,
      expiry: 4_294_967_296n,
    });
    const idBuf = buildIdentityStateBuffer({
      owner: WALLET,
      creationTimestamp: 1_700_000_000,
      trustScore: 650,
    });
    const migBuf = buildMigrationRecordBuffer(1_780_000_000);

    let includeMigration = false;
    const mockFetch: typeof globalThis.fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as {
        id: number;
        method: string;
        params: unknown[];
      };
      expect(body.method).toBe("getMultipleAccounts");
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            context: { slot: 500 },
            value: [
              {
                data: [toBase64(sasBuf), "base64"],
                executable: false,
                lamports: 1,
                owner: SAS_DEVNET_CONFIG.programId,
              },
              {
                data: [toBase64(idBuf), "base64"],
                executable: false,
                lamports: 1,
                owner: SOLANA_PROGRAM_IDS.anchor,
              },
              includeMigration
                ? {
                    data: [toBase64(migBuf), "base64"],
                    executable: false,
                    lamports: 1,
                    owner: SOLANA_PROGRAM_IDS.anchor,
                  }
                : null,
            ],
          },
        }),
        { status: 200 },
      );
    };

    const transport = { endpoint: "https://rpc.example.test", fetch: mockFetch };
    expect(
      await verifyEntrosAttestation(WALLET, transport, {
        nowSeconds: 4_294_967_295,
      }),
    ).toEqual({
      isHuman: true,
      trustScore: 650,
      verifiedAt: 1_780_000_000,
      mode: "wallet-connected",
      expired: false,
    });
    expect(
      await verifyEntrosAttestation(WALLET, transport, {
        nowSeconds: 4_294_967_296,
      }),
    ).toMatchObject({ expired: true });

    includeMigration = true;
    expect(
      await verifyEntrosAttestation(WALLET, transport, {
        nowSeconds: 1_790_000_000,
      }),
    ).toBeNull();
  });

  it("falls back to getAccountInfo and rejects pre-creation or wrong-owner accounts", async () => {
    const [attPda] = deriveSasAttestationPda(WALLET);
    const [idPda] = deriveIdentityPda(WALLET);
    const sasBuf = buildSasAttestationBuffer({
      wallet: WALLET,
      verifiedAt: 1_780_000_000n,
      expiry: 0n,
    });
    const newerId = buildIdentityStateBuffer({
      owner: WALLET,
      creationTimestamp: 1_780_000_001,
    });
    const connection: SolanaConnectionLike = {
      getAccountInfo: async (address) => {
        if (address.toBase58() === attPda) {
          return { data: sasBuf, owner: SAS_DEVNET_CONFIG.programId };
        }
        if (address.toBase58() === idPda) {
          return { data: newerId, owner: SOLANA_PROGRAM_IDS.anchor };
        }
        return null;
      },
    };
    expect(await verifyEntrosAttestation(WALLET, connection)).toBeNull();
  });
});

describe("readIntegratorEvidence and findLatestVerificationTransaction", () => {
  it.each([
    "mint",
    "update",
    "compact",
    "legacy-compact",
    "bound",
    "rebaseline",
  ] as const)("accepts confirmed %s transactions", async (kind) => {
    const fixture = createEvidenceFixture({
      kind,
      includeSessionDigest: kind === "update",
      includeTrailingProofRequestState: kind === "mint" || kind === "rebaseline",
    });
    const result = await readIntegratorEvidence(fixture.input);
    expect(result.status).toBe("available");
    if (result.status !== "available") return;
    expect(result.evidence.cluster).toBe("devnet");
    expect(result.evidence.genesisHash).toBe(INTEGRATOR_DEVNET_GENESIS_HASH);
    expect(result.evidence.transaction.kind).toBe(
      kind === "compact" || kind === "legacy-compact" || kind === "bound"
        ? "update"
        : kind,
    );
    expect(result.evidence.attestation.status).toBe("present");
  });

  it.each([-2, -1, 0, 1, 2])(
    "enforces 2-second slot-time tolerance at offset %i s",
    async (offset) => {
      const blockTime = 1_799_999_990;
      const fixture = createEvidenceFixture({
        blockTime,
        lastVerificationTimestamp: blockTime + offset,
      });
      expect((await readIntegratorEvidence(fixture.input)).status).toBe(
        "available",
      );
    },
  );

  it("rejects timestamps outside 2-second tolerance and resets at blockTime - 2", async () => {
    const blockTime = 1_799_999_990;
    const tooEarly = createEvidenceFixture({
      blockTime,
      lastVerificationTimestamp: blockTime - BLOCK_TIME_TOLERANCE_SECONDS - 1,
    });
    expect(await readIntegratorEvidence(tooEarly.input)).toEqual({
      status: "invalid",
      reason: "transaction_invalid",
    });

    const resetConflict = createEvidenceFixture({
      blockTime,
      lastResetTimestamp: blockTime - BLOCK_TIME_TOLERANCE_SECONDS,
    });
    expect(await readIntegratorEvidence(resetConflict.input)).toEqual({
      status: "invalid",
      reason: "transaction_invalid",
    });
  });

  it("reconciles device clocks behind chain time within 15 seconds and rejects +16 seconds", async () => {
    const now = 1_800_000_000;
    const withinBudget = createEvidenceFixture({
      nowSeconds: now,
      blockTime: now + CLOCK_CATCH_UP_SECONDS,
    });
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "Date", "performance"],
    });
    vi.setSystemTime(now * 1000);

    const pending = readIntegratorEvidence({
      ...withinBudget.input,
      nowSeconds: () => Math.floor(Date.now() / 1000),
    });
    await vi.runAllTimersAsync();
    const res = await pending;
    expect(res.status).toBe("available");
    expect(performance.now()).toBe(CLOCK_CATCH_UP_SECONDS * 1000);

    vi.useRealTimers();
    const beyondBudget = createEvidenceFixture({
      nowSeconds: now,
      blockTime: now + CLOCK_CATCH_UP_SECONDS + 1,
    });
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "Date", "performance"],
    });
    vi.setSystemTime(now * 1000);
    const rejected = await readIntegratorEvidence({
      ...beyondBudget.input,
      nowSeconds: () => Math.floor(Date.now() / 1000),
    });
    expect(rejected).toEqual({
      status: "invalid",
      reason: "transaction_invalid",
    });
    expect(performance.now()).toBe(0);
  });

  it("maps expired, pre-reset, pre-creation, migrated, and lamport-dusted SAS to missing", async () => {
    const blockTime = 1_799_999_990;

    // Expired SAS
    const expired = createEvidenceFixture({ expiry: 1_800_000_000 });
    const expiredRes = await readIntegratorEvidence(expired.input);
    expect(expiredRes).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });

    // Migrated at or after verification
    const migrated = createEvidenceFixture({ migratedAt: blockTime });
    const migratedRes = await readIntegratorEvidence(migrated.input);
    expect(migratedRes).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });

    // Migrated before verification stays present
    const afterMigration = createEvidenceFixture({ migratedAt: blockTime - 1 });
    expect(await readIntegratorEvidence(afterMigration.input)).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "present" } },
    });

    // Lamport-dusted System Program empty account -> missing
    const dusted = createEvidenceFixture();
    dusted.sasAccount.owner = new SolanaAddress(SYSTEM_PROGRAM_ID);
    dusted.sasAccount.data = new Uint8Array(0);
    expect(await readIntegratorEvidence(dusted.input)).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });

    // Malformed 56-byte migration record -> invalid attestation
    const badMig = createEvidenceFixture({ migratedAt: blockTime - 1 });
    badMig.migrationAccount!.data = badMig.migrationAccount!.data.subarray(0, 56);
    expect(await readIntegratorEvidence(badMig.input)).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "invalid" } },
    });
  });

  it("rejects reset transactions, wrong cluster, isolated deployments, and trailing instruction bytes", async () => {
    const resetTx = createEvidenceFixture();
    const ix0 = resetTx.transaction.transaction.message.instructions[0]!;
    if ("data" in ix0) ix0.data = encodeResetInstruction();
    expect(await readIntegratorEvidence(resetTx.input)).toEqual({
      status: "invalid",
      reason: "transaction_invalid",
    });

    const trailingBytes = createEvidenceFixture();
    const ix1 = trailingBytes.transaction.transaction.message.instructions[0]!;
    if ("data" in ix1) {
      const raw = base58Decode(ix1.data)!;
      const grown = new Uint8Array(raw.length + 1);
      grown.set(raw, 0);
      ix1.data = base58Encode(grown);
    }
    expect(await readIntegratorEvidence(trailingBytes.input)).toEqual({
      status: "invalid",
      reason: "transaction_invalid",
    });

    const wrongCluster = createEvidenceFixture();
    wrongCluster.connection.getGenesisHash = async () =>
      "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    expect(await readIntegratorEvidence(wrongCluster.input)).toEqual({
      status: "invalid",
      reason: "wrong_cluster",
    });

    const isolated = createEvidenceFixture();
    expect(
      await readIntegratorEvidence({
        ...isolated.input,
        deployment: {
          generation: "request-bound-v1",
          consumerProgram: OWNER,
          verifierProgram: OTHER,
          deploymentDomain: "11".repeat(32),
          genesisHash: SOLANA_DEVNET_GENESIS_HASH,
        },
      }),
    ).toEqual({ status: "invalid", reason: "unsupported_deployment" });
  });

  it("reads full evidence over standard JSON-RPC fetch transport", async () => {
    const fixture = createEvidenceFixture({ kind: "update" });
    const [identityAddr] = deriveIdentityPda(fixture.wallet);
    const [attAddr] = deriveSasAttestationPda(fixture.wallet);
    const [migAddr] = deriveMigrationRecordPda(fixture.wallet);
    const methods: string[] = [];

    const mockFetch: typeof globalThis.fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as {
        id: number;
        method: string;
        params: unknown[];
      };
      methods.push(body.method);
      let result: unknown;
      if (body.method === "getGenesisHash") {
        result = SOLANA_DEVNET_GENESIS_HASH;
      } else if (body.method === "getSignatureStatuses") {
        result = { context: { slot: 101 }, value: [fixture.status] };
      } else if (body.method === "getTransaction") {
        result = {
          ...fixture.transaction,
          transaction: {
            signatures: fixture.transaction.transaction.signatures,
            message: {
              accountKeys:
                fixture.transaction.transaction.message.accountKeys.map((k) => ({
                  pubkey: new SolanaAddress(k.pubkey).toBase58(),
                  signer: k.signer,
                  writable: k.writable,
                })),
              instructions:
                fixture.transaction.transaction.message.instructions.map((ix) =>
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
      } else if (body.method === "getAccountInfo") {
        const addr = String(body.params[0]);
        if (addr === identityAddr) {
          result = {
            context: { slot: 102 },
            value: {
              data: [toBase64(fixture.identityAccount.data), "base64"],
              executable: false,
              lamports: 1,
              owner: SOLANA_PROGRAM_IDS.anchor,
            },
          };
        } else if (addr === attAddr) {
          result = {
            context: { slot: 102 },
            value: {
              data: [toBase64(fixture.sasAccount.data), "base64"],
              executable: false,
              lamports: 1,
              owner: SAS_DEVNET_CONFIG.programId,
            },
          };
        } else if (addr === migAddr) {
          result = { context: { slot: 102 }, value: null };
        }
      }
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
        { status: 200 },
      );
    };

    const client = createSolanaRpcClient({
      endpoint: "https://rpc.example.test",
      fetch: mockFetch,
    });
    const res = await readIntegratorEvidence({
      walletPubkey: fixture.input.walletPubkey,
      transactionSignature: fixture.input.transactionSignature,
      connection: client,
      nowSeconds: fixture.input.nowSeconds,
    });
    expect(res.status).toBe("available");
    expect(methods).toContain("getGenesisHash");
    expect(methods).toContain("getSignatureStatuses");
    expect(methods).toContain("getTransaction");
    expect(methods).toContain("getAccountInfo");
  });

  it("discovers verification transactions with candidateSignatures and verifiedAt paging", async () => {
    const fixture = createEvidenceFixture();
    const qualifying = fixture.input.transactionSignature;
    const verifiedAt = 1_799_999_990;
    const later: SignatureInfoLike[] = Array.from({ length: 1_050 }, (_, i) => ({
      signature: `later-${i}`,
      slot: 200 + i,
      err: null,
      blockTime: verifiedAt + 10 + i,
    }));
    const entries: SignatureInfoLike[] = [
      ...later,
      { signature: qualifying, slot: 100, err: null, blockTime: verifiedAt },
    ];
    const txs: Record<string, ParsedTransactionLike> = {
      [qualifying]: fixture.transaction,
    };
    const pages: number[] = [];
    const connection: SolanaConnectionLike = {
      getSignaturesForAddress: async (_addr, options) => {
        pages.push(options?.limit ?? 0);
        const start = options?.before
          ? entries.findIndex((e) => e.signature === options.before) + 1
          : 0;
        return entries.slice(start, start + (options?.limit ?? 1_000));
      },
      getParsedTransaction: async (sig) => txs[sig] ?? null,
    };

    // Fast path via candidateSignatures avoids paging history.
    expect(
      await findLatestVerificationTransaction({
        walletPubkey: fixture.input.walletPubkey,
        connection,
        verifiedAt,
        candidateSignatures: [qualifying],
      }),
    ).toEqual({ status: "found", signature: qualifying });
    expect(pages).toEqual([]);

    // Paged search finds transaction past 1,000 later entries.
    expect(
      await findLatestVerificationTransaction({
        walletPubkey: fixture.input.walletPubkey,
        connection,
        verifiedAt,
      }),
    ).toEqual({ status: "found", signature: qualifying });
    expect(pages).toEqual([1_000, 1_000]);
  });
});

describe("readAgentState", () => {
  function setupAgent(opts: {
    owner?: string;
    cachedOwner?: string;
    agentWallet?: string | null;
    assetBytes?: Uint8Array | null;
    agentAccountBytes?: Uint8Array | null;
    genesis?: string;
    slot?: number;
  } = {}) {
    const assetData =
      opts.assetBytes === undefined
        ? buildCoreAssetBuffer({ owner: opts.owner ?? OWNER })
        : opts.assetBytes;
    const agentAccountData =
      opts.agentAccountBytes === undefined
        ? buildAgentAccountBuffer({
            asset: AGENT,
            cachedOwner: opts.cachedOwner ?? opts.owner ?? OWNER,
            agentWallet:
              opts.agentWallet === undefined ? AGENT_WALLET : opts.agentWallet,
          })
        : opts.agentAccountBytes;

    const mockFetch: typeof globalThis.fetch = async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as {
        id: number;
        method: string;
      };
      const result =
        body.method === "getGenesisHash"
          ? (opts.genesis ?? SOLANA_DEVNET_GENESIS_HASH)
          : {
              context: { slot: opts.slot ?? 400 },
              value: [
                assetData
                  ? {
                      data: [toBase64(assetData), "base64"],
                      executable: false,
                      lamports: 1,
                      owner: AGENT_REGISTRY_DEVNET_CONFIG.coreProgramId,
                    }
                  : null,
                agentAccountData
                  ? {
                      data: [toBase64(agentAccountData), "base64"],
                      executable: false,
                      lamports: 1,
                      owner: AGENT_REGISTRY_DEVNET_CONFIG.programId,
                    }
                  : null,
              ],
            };
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
        { status: 200 },
      );
    };

    return { endpoint: "https://rpc.example.test", fetch: mockFetch };
  }

  it("reports bound, unbound, and stale (post-Core-transfer) agent states via JSON-RPC", async () => {
    const [agentAccount] = deriveAgentAccountPda(AGENT);
    const bound = await readAgentState({ agent: AGENT, connection: setupAgent() });
    expect(bound).toEqual({
      status: "available",
      evidence: {
        cluster: "devnet",
        genesisHash: SOLANA_DEVNET_GENESIS_HASH,
        coreProgram: AGENT_REGISTRY_DEVNET_CONFIG.coreProgramId,
        agentRegistryProgram: AGENT_REGISTRY_DEVNET_CONFIG.programId,
        agentCollection: AGENT_REGISTRY_DEVNET_CONFIG.collection,
        agent: AGENT,
        agentAccount,
        owner: OWNER,
        cachedOwner: OWNER,
        agentWallet: AGENT_WALLET,
        agentWalletStatus: "bound",
        readContextSlot: 400,
      },
    });

    const stale = await readAgentState({
      agent: AGENT,
      connection: setupAgent({ owner: OTHER, cachedOwner: OWNER }),
    });
    expect(stale).toMatchObject({
      status: "available",
      evidence: {
        owner: OTHER,
        cachedOwner: OWNER,
        agentWallet: AGENT_WALLET,
        agentWalletStatus: "stale",
      },
    });

    const unbound = await readAgentState({
      agent: AGENT,
      connection: setupAgent({ agentWallet: null }),
    });
    expect(unbound).toMatchObject({
      status: "available",
      evidence: { agentWallet: null, agentWalletStatus: "unbound" },
    });
  });

  it("rejects burned assets, wrong collections, wrong clusters, lag, and malformed accounts", async () => {
    expect(
      await readAgentState({
        agent: AGENT,
        connection: setupAgent({ assetBytes: Uint8Array.of(0) }),
      }),
    ).toEqual({ status: "invalid", reason: "agent_missing" });

    expect(
      await readAgentState({
        agent: AGENT,
        connection: setupAgent({
          assetBytes: buildCoreAssetBuffer({ owner: OWNER, collection: OTHER }),
        }),
      }),
    ).toEqual({ status: "invalid", reason: "agent_unregistered" });

    expect(
      await readAgentState({
        agent: AGENT,
        connection: setupAgent({
          genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        }),
      }),
    ).toEqual({ status: "invalid", reason: "wrong_cluster" });

    expect(
      await readAgentState({
        agent: AGENT,
        connection: setupAgent({ slot: 99 }),
        minContextSlot: 100,
      }),
    ).toEqual({ status: "invalid", reason: "agent_invalid" });

    expect(
      await readAgentState({
        agent: "not-valid-base58",
        connection: setupAgent(),
      }),
    ).toEqual({ status: "invalid", reason: "invalid_request" });

    for (const badAgent of [null, undefined, 123, {}]) {
      expect(
        await readAgentState({
          agent: badAgent as unknown as string,
          connection: setupAgent(),
        }),
      ).toEqual({ status: "invalid", reason: "invalid_request" });
    }

    const fixture = createEvidenceFixture();
    for (const badWallet of [null, undefined, 123, {}]) {
      expect(
        await readIntegratorEvidence({
          ...fixture.input,
          walletPubkey: badWallet as unknown as string,
        }),
      ).toEqual({ status: "invalid", reason: "invalid_request" });
    }
    expect(fixture.calls).toEqual([]);
  });
});
