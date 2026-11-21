// @vitest-environment node
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CLOCK_CATCH_UP_SECONDS,
  decodeIdentityState,
  deriveAgentAccountPda,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveMintPda,
  deriveProofRequestStatePda,
  deriveSasAttestationPda,
  deriveVerificationResultPda,
  readAgentState,
  readIntegratorEvidence,
  readMigrationRecord,
  SOLANA_PROGRAM_IDS,
  SolanaAddress,
  SYSTEM_PROGRAM_ID,
  verifyEntrosAttestation,
  type ParsedTransactionLike,
  type RawAccountInfoLike,
  type SolanaConnectionLike,
} from "../src/solana";

const vectors = JSON.parse(
  readFileSync(
    new URL("./fixtures/solana-parity-vectors.json", import.meta.url),
    "utf8",
  ),
);

const fromB64 = (value: string): Uint8Array =>
  new Uint8Array(Buffer.from(value, "base64"));

const nonceBytes = Uint8Array.from(
  vectors.nonceHex.match(/../g) as string[],
  (b) => Number.parseInt(b, 16),
);

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function buildTx(
  kind: "update" | "mint" | "rebaseline" | "compact" | "bound" | "reset",
  blockTime = vectors.blockTime,
): ParsedTransactionLike {
  const wallet = new SolanaAddress(vectors.wallet);
  const identityPda = new SolanaAddress(vectors.pdas.identity[0]);
  const proofReqPda = new SolanaAddress(vectors.pdas.proofRequestState[0]);
  const anchorProgram = new SolanaAddress(vectors.programs.anchor);
  const verifierProgram = new SolanaAddress(vectors.programs.verifier);
  const sys = new SolanaAddress(SYSTEM_PROGRAM_ID);

  const instructions: ParsedTransactionLike["transaction"]["message"]["instructions"][number][] =
    [];

  if (kind === "mint") {
    instructions.push({
      programId: anchorProgram,
      accounts: Array.from({ length: 11 }, (_, i) =>
        i === 0 ? wallet : i === 1 ? identityPda : sys,
      ),
      data: vectors.instructions.mint,
    });
  } else if (kind === "rebaseline") {
    instructions.push({
      programId: anchorProgram,
      accounts: Array.from({ length: 6 }, (_, i) =>
        i === 0 ? wallet : i === 1 ? identityPda : sys,
      ),
      data: vectors.instructions.rebaseline,
    });
  } else if (kind === "compact") {
    const verPda = new SolanaAddress(vectors.pdas.verificationCompact[0]);
    instructions.push(
      {
        programId: verifierProgram,
        accounts: [wallet, verPda, sys],
        data: vectors.instructions.compact.verifier,
      },
      {
        programId: anchorProgram,
        accounts: Array.from({ length: 8 }, (_, i) =>
          i === 0 ? wallet : i === 1 ? identityPda : i === 2 ? verPda : sys,
        ),
        data: vectors.instructions.compact.anchor,
      },
    );
  } else if (kind === "bound") {
    const verPda = new SolanaAddress(vectors.pdas.verificationBound[0]);
    instructions.push(
      {
        programId: verifierProgram,
        accounts: [wallet, verPda, identityPda, proofReqPda, sys],
        data: vectors.instructions.bound.verifier,
      },
      {
        programId: anchorProgram,
        accounts: Array.from({ length: 9 }, (_, i) =>
          i === 0
            ? wallet
            : i === 1
              ? identityPda
              : i === 2
                ? proofReqPda
                : i === 3
                  ? verPda
                  : sys,
        ),
        data: vectors.instructions.bound.anchor,
      },
    );
  } else if (kind === "reset") {
    instructions.push({
      programId: anchorProgram,
      accounts: Array.from({ length: 5 }, (_, i) =>
        i === 0 ? wallet : i === 1 ? identityPda : sys,
      ),
      data: vectors.instructions.reset,
    });
  } else {
    instructions.push({
      programId: anchorProgram,
      accounts: Array.from({ length: 8 }, (_, i) =>
        i === 0 ? wallet : i === 1 ? identityPda : sys,
      ),
      data: vectors.instructions.update,
    });
  }

  return {
    slot: 100,
    blockTime,
    version: "legacy",
    meta: { err: null },
    transaction: {
      signatures: [vectors.signature],
      message: {
        accountKeys: [{ pubkey: wallet, signer: true, writable: true }],
        instructions,
      },
    },
  };
}

function makeEvidenceConnection(opts: {
  identityData?: Uint8Array | null;
  sasData?: Uint8Array | null;
  sasOwner?: string;
  migrationData?: Uint8Array | null;
  migrationOwner?: string;
  tx?: ParsedTransactionLike;
  genesisHash?: string;
}): SolanaConnectionLike {
  const idPda = vectors.pdas.identity[0];
  const attPda = vectors.pdas.sasAttestation[0];
  const migPda = vectors.pdas.migration[0];
  const tx = opts.tx ?? buildTx("update");

  return {
    getGenesisHash: async () => opts.genesisHash ?? vectors.genesisHash,
    getSignatureStatuses: async () => ({
      context: { slot: 101 },
      value: [{ slot: 100, confirmations: 1, err: null, confirmationStatus: "confirmed" }],
    }),
    getParsedTransaction: async () => tx,
    getAccountInfoAndContext: async (address) => {
      const key = address.toBase58();
      let value: RawAccountInfoLike | null = null;
      if (key === idPda) {
        const data =
          opts.identityData === undefined
            ? fromB64(vectors.identityBuffers.activeBase64)
            : opts.identityData;
        value = data
          ? { data, executable: false, lamports: 1, owner: vectors.programs.anchor }
          : null;
      } else if (key === attPda) {
        const data =
          opts.sasData === undefined
            ? fromB64(vectors.sasBuffers.activeBase64)
            : opts.sasData;
        value = data
          ? {
              data,
              executable: false,
              lamports: 1,
              owner: opts.sasOwner ?? vectors.programs.sas,
            }
          : null;
      } else if (key === migPda && opts.migrationData) {
        value = {
          data: opts.migrationData,
          executable: false,
          lamports: 1,
          owner: opts.migrationOwner ?? vectors.programs.anchor,
        };
      }
      return { context: { slot: 102 }, value };
    },
  };
}

describe("canonical shared-vector parity (@entros/verify/solana)", () => {
  it("matches every PDA and bump byte-for-byte", () => {
    expect(deriveIdentityPda(vectors.wallet)).toEqual(vectors.pdas.identity);
    expect(deriveMintPda(vectors.wallet)).toEqual(vectors.pdas.mint);
    expect(deriveMigrationRecordPda(vectors.wallet)).toEqual(vectors.pdas.migration);
    expect(deriveProofRequestStatePda(vectors.wallet)).toEqual(
      vectors.pdas.proofRequestState,
    );
    expect(deriveSasAttestationPda(vectors.wallet)).toEqual(
      vectors.pdas.sasAttestation,
    );
    expect(deriveVerificationResultPda(vectors.wallet, nonceBytes, false)).toEqual(
      vectors.pdas.verificationCompact,
    );
    expect(deriveVerificationResultPda(vectors.wallet, nonceBytes, true)).toEqual(
      vectors.pdas.verificationBound,
    );
    expect(deriveAgentAccountPda(vectors.agentFixtures.devnet.assetAddress)).toEqual(
      vectors.pdas.agentAccount,
    );
  });

  it("matches IdentityState prefix layouts and MigrationRecord boundaries", () => {
    const d593 = decodeIdentityState(fromB64(vectors.identityBuffers.full593Base64));
    const d583 = decodeIdentityState(fromB64(vectors.identityBuffers.prefix583Base64));
    const d551 = decodeIdentityState(fromB64(vectors.identityBuffers.prefix551Base64));
    const d543 = decodeIdentityState(fromB64(vectors.identityBuffers.prefix543Base64));
    expect(d593?.projectionVersion).toBe(2);
    expect(d593?.lastRebaselineTimestamp).toBe(vectors.nowSeconds - 200);
    expect(d583?.projectionVersion).toBe(0);
    expect(d551?.lastResetTimestamp).toBe(vectors.nowSeconds - 500);
    expect(d543?.lastResetTimestamp).toBe(0);
    expect(
      decodeIdentityState(fromB64(vectors.identityBuffers.legacy207Base64)),
    ).toBeNull();

    expect(
      readMigrationRecord(
        {
          data: fromB64(vectors.migrationBuffers.atBlockTimeBase64),
          executable: false,
          owner: SOLANA_PROGRAM_IDS.anchor,
        },
        SOLANA_PROGRAM_IDS.anchor,
      ),
    ).toEqual({ status: "migrated", migratedAt: vectors.blockTime });
    expect(
      readMigrationRecord(
        {
          data: fromB64(vectors.migrationBuffers.extended65Base64),
          executable: false,
          owner: SOLANA_PROGRAM_IDS.anchor,
        },
        SOLANA_PROGRAM_IDS.anchor,
      ),
    ).toEqual({ status: "migrated", migratedAt: vectors.blockTime - 1 });
    expect(
      readMigrationRecord(
        {
          data: fromB64(vectors.migrationBuffers.truncated56Base64),
          executable: false,
          owner: SOLANA_PROGRAM_IDS.anchor,
        },
        SOLANA_PROGRAM_IDS.anchor,
      ),
    ).toEqual({ status: "invalid" });
  });

  it("matches active, expired, reset, migrated, and SAS mismatch evidence cases", async () => {
    for (const [kind, idKey, expectedKind] of [
      ["update", "activeBase64", "update"],
      ["mint", "mintBase64", "mint"],
      ["compact", "activeBase64", "update"],
      ["bound", "activeBase64", "update"],
      ["rebaseline", "rebaselineBase64", "rebaseline"],
    ] as const) {
      const res = await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          identityData: fromB64(vectors.identityBuffers[idKey]),
          tx: buildTx(kind),
        }),
        nowSeconds: vectors.nowSeconds,
      });
      expect(res.status, kind).toBe("available");
      if (res.status === "available") {
        expect(res.evidence.transaction.kind).toBe(expectedKind);
        expect(res.evidence.attestation.status).toBe("present");
      }
    }

    // Expired SAS -> missing
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          sasData: fromB64(vectors.sasBuffers.expiredBase64),
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });

    // Reset -> pre-reset SAS -> missing
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          identityData: fromB64(vectors.identityBuffers.resetBase64),
          sasData: fromB64(vectors.sasBuffers.preResetBase64),
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });

    // Migrated at verification time -> missing; truncated -> invalid; foreign -> present
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          migrationData: fromB64(vectors.migrationBuffers.atBlockTimeBase64),
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          migrationData: fromB64(vectors.migrationBuffers.truncated56Base64),
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "invalid" } },
    });
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          migrationData: fromB64(vectors.migrationBuffers.atBlockTimeBase64),
          migrationOwner: SYSTEM_PROGRAM_ID,
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "present" } },
    });

    // SAS mismatches -> invalid; lamport dust -> missing
    for (const key of [
      "wrongWalletBase64",
      "wrongSchemaBase64",
      "falseHumanBase64",
      "zeroSignerBase64",
      "nonZeroTokenBase64",
    ] as const) {
      expect(
        await readIntegratorEvidence({
          walletPubkey: vectors.wallet,
          transactionSignature: vectors.signature,
          connection: makeEvidenceConnection({
            sasData: fromB64(vectors.sasBuffers[key]),
          }),
          nowSeconds: vectors.nowSeconds,
        }),
        key,
      ).toMatchObject({
        status: "available",
        evidence: { attestation: { status: "invalid" } },
      });
    }

    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({
          sasData: new Uint8Array(0),
          sasOwner: SYSTEM_PROGRAM_ID,
        }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toMatchObject({
      status: "available",
      evidence: { attestation: { status: "missing" } },
    });
  });

  it("matches 2s slot tolerance, 15s clock catch-up, SAS batch read, and captured Core agent states", async () => {
    // 2s tolerance
    const idPlus2 = fromB64(vectors.identityBuffers.activeBase64);
    new DataView(idPlus2.buffer).setBigInt64(48, BigInt(vectors.blockTime + 2), true);
    expect(
      (
        await readIntegratorEvidence({
          walletPubkey: vectors.wallet,
          transactionSignature: vectors.signature,
          connection: makeEvidenceConnection({ identityData: idPlus2 }),
          nowSeconds: vectors.nowSeconds,
        })
      ).status,
    ).toBe("available");

    const idMinus3 = fromB64(vectors.identityBuffers.activeBase64);
    new DataView(idMinus3.buffer).setBigInt64(48, BigInt(vectors.blockTime - 3), true);
    expect(
      await readIntegratorEvidence({
        walletPubkey: vectors.wallet,
        transactionSignature: vectors.signature,
        connection: makeEvidenceConnection({ identityData: idMinus3 }),
        nowSeconds: vectors.nowSeconds,
      }),
    ).toEqual({ status: "invalid", reason: "transaction_invalid" });

    // 15s clock catch-up
    const futureBlock = vectors.nowSeconds + 4;
    const futureId = fromB64(vectors.identityBuffers.activeBase64);
    new DataView(futureId.buffer).setBigInt64(48, BigInt(futureBlock), true);
    const futureSas = fromB64(vectors.sasBuffers.activeBase64);
    new DataView(futureSas.buffer).setBigInt64(104, BigInt(futureBlock), true);
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "Date", "performance"],
    });
    vi.setSystemTime(vectors.nowSeconds * 1000);
    const catchupPending = readIntegratorEvidence({
      walletPubkey: vectors.wallet,
      transactionSignature: vectors.signature,
      connection: makeEvidenceConnection({
        identityData: futureId,
        sasData: futureSas,
        tx: buildTx("update", futureBlock),
      }),
      nowSeconds: () => Math.floor(Date.now() / 1000),
    });
    await vi.runAllTimersAsync();
    expect((await catchupPending).status).toBe("available");
    expect(performance.now()).toBe(4000);
    expect(CLOCK_CATCH_UP_SECONDS).toBe(15);
    vi.useRealTimers();

    // verifyEntrosAttestation parity
    const sasConn: SolanaConnectionLike = {
      getMultipleAccountsInfo: async () => [
        {
          data: fromB64(vectors.sasBuffers.activeBase64),
          owner: vectors.programs.sas,
        },
        {
          data: fromB64(vectors.identityBuffers.activeBase64),
          owner: vectors.programs.anchor,
        },
        null,
      ],
    };
    vi.useFakeTimers();
    vi.setSystemTime(vectors.nowSeconds * 1000);
    expect(await verifyEntrosAttestation(vectors.wallet, sasConn)).toEqual({
      isHuman: true,
      trustScore: 300,
      verifiedAt: vectors.blockTime,
      mode: "wallet-connected",
      expired: false,
    });
    vi.useRealTimers();

    // Captured devnet & localnet Core + 8004 agent states
    const devnetAgent = vectors.agentFixtures.devnet;
    expect(
      await readAgentState({
        agent: devnetAgent.assetAddress,
        connection: {
          getGenesisHash: async () => vectors.genesisHash,
          getMultipleAccountsInfoAndContext: async () => ({
            context: { slot: devnetAgent.contextSlot },
            value: [
              {
                data: fromB64(devnetAgent.assetBase64),
                executable: false,
                lamports: 1,
                owner: vectors.programs.core,
              },
              {
                data: fromB64(devnetAgent.agentAccountBase64),
                executable: false,
                lamports: 1,
                owner: vectors.programs.agentRegistry,
              },
            ],
          }),
        },
      }),
    ).toEqual({
      status: "available",
      evidence: {
        cluster: "devnet",
        genesisHash: vectors.genesisHash,
        coreProgram: vectors.programs.core,
        agentRegistryProgram: vectors.programs.agentRegistry,
        agentCollection: vectors.programs.agentCollection,
        agent: devnetAgent.assetAddress,
        agentAccount: devnetAgent.agentAccountAddress,
        owner: devnetAgent.owner,
        cachedOwner: devnetAgent.owner,
        agentWallet: null,
        agentWalletStatus: "unbound",
        readContextSlot: devnetAgent.contextSlot,
      },
    });

    const localnet = vectors.agentFixtures.localnet;
    for (const [stage, expected] of [
      ["registered", [localnet.ownerA, localnet.ownerA, null, "unbound"]],
      ["bound", [localnet.ownerA, localnet.ownerA, localnet.agentWallets.first, "bound"]],
      ["coreTransfer", [localnet.ownerB, localnet.ownerA, localnet.agentWallets.first, "stale"]],
      ["reboundByB", [localnet.ownerB, localnet.ownerB, localnet.agentWallets.successor, "bound"]],
      ["registryTransfer", [localnet.ownerA, localnet.ownerA, null, "unbound"]],
    ] as const) {
      const stageBytes = localnet.stages[stage];
      const res = await readAgentState({
        agent: localnet.agent,
        connection: {
          getGenesisHash: async () => vectors.genesisHash,
          getMultipleAccountsInfoAndContext: async () => ({
            context: { slot: 1 },
            value: [
              {
                data: fromB64(stageBytes.asset),
                executable: false,
                lamports: 1,
                owner: vectors.programs.core,
              },
              {
                data: fromB64(stageBytes.agentAccount),
                executable: false,
                lamports: 1,
                owner: vectors.programs.agentRegistry,
              },
            ],
          }),
        },
      });
      expect(res, stage).toMatchObject({
        status: "available",
        evidence: {
          agentAccount: localnet.agentAccount,
          owner: expected[0],
          cachedOwner: expected[1],
          agentWallet: expected[2],
          agentWalletStatus: expected[3],
        },
      });
    }
  });
});
