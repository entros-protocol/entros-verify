import {
  AGENT_REGISTRY_DEVNET_CONFIG,
  base58Encode,
  deriveAgentAccountPda,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveMintPda,
  deriveProofRequestStatePda,
  deriveSasAttestationPda,
  deriveVerificationResultPda,
  IDENTITY_STATE_DISCRIMINATOR,
  MIGRATION_RECORD_DISCRIMINATOR,
  SAS_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_PROGRAM_IDS,
  SolanaAddress,
  SYSTEM_PROGRAM_ID,
  type ParsedTransactionLike,
  type RawAccountInfoLike,
  type SignatureStatusLike,
  type SolanaConnectionLike,
} from "../src/solana";

const ANCHOR_DISCS = {
  mint_anchor: [68, 56, 113, 102, 236, 152, 146, 60],
  update_anchor: [120, 192, 72, 245, 112, 246, 119, 135],
  update_anchor_compact: [213, 176, 229, 104, 213, 148, 253, 186],
  update_anchor_bound: [246, 210, 191, 60, 123, 82, 229, 214],
  rebaseline_anchor: [129, 211, 18, 16, 17, 54, 143, 18],
  reset_identity_state: [26, 78, 86, 143, 247, 132, 85, 203],
} as const;

const VERIFIER_DISCS = {
  verify_proof: [217, 211, 191, 110, 144, 13, 186, 98],
  verify_proof_compact: [78, 42, 251, 67, 237, 19, 187, 192],
  verify_proof_bound: [56, 250, 245, 67, 70, 133, 5, 140],
} as const;

const AGENT_ACCOUNT_DISCRIMINATOR = Uint8Array.from([
  0xf1, 0x77, 0x45, 0x8c, 0xe9, 0x09, 0x70, 0x32,
]);

const encoder = new TextEncoder();

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function buildIdentityStateBuffer(opts: {
  owner: string;
  mint?: string;
  bump?: number;
  creationTimestamp?: number;
  lastVerificationTimestamp?: number;
  verificationCount?: number;
  trustScore?: number;
  commitmentFill?: number;
  lastResetTimestamp?: number;
  projectionVersion?: number;
  lastRebaselineTimestamp?: number;
  length?: number;
}): Uint8Array {
  const full = new Uint8Array(593);
  const view = new DataView(full.buffer);
  const owner = new SolanaAddress(opts.owner);
  const [mintAddr] = deriveMintPda(owner);
  const [, derivedBump] = deriveIdentityPda(owner);
  const mint = new SolanaAddress(opts.mint ?? mintAddr);

  full.set(IDENTITY_STATE_DISCRIMINATOR, 0);
  full.set(owner.toBytes(), 8);
  view.setBigInt64(40, BigInt(opts.creationTimestamp ?? 1_799_999_000), true);
  view.setBigInt64(
    48,
    BigInt(opts.lastVerificationTimestamp ?? 1_799_999_990),
    true,
  );
  view.setUint32(56, opts.verificationCount ?? 7, true);
  view.setUint16(60, opts.trustScore ?? 300, true);
  full.fill(opts.commitmentFill ?? 3, 62, 94);
  full.set(mint.toBytes(), 94);
  full[126] = opts.bump ?? derivedBump;
  view.setBigInt64(543, BigInt(opts.lastResetTimestamp ?? 0), true);
  view.setUint16(583, opts.projectionVersion ?? 1, true);
  view.setBigInt64(585, BigInt(opts.lastRebaselineTimestamp ?? 0), true);

  return opts.length !== undefined ? full.slice(0, opts.length) : full;
}

export function buildSasAttestationBuffer(opts: {
  wallet: string;
  trustScore?: number;
  verifiedAt?: bigint;
  expiry?: bigint;
  isHuman?: number;
  mode?: string;
  signerFill?: number;
  credential?: string;
  schema?: string;
}): Uint8Array {
  const modeBytes = encoder.encode(opts.mode ?? "wallet-connected");
  const dataLen = 1 + 2 + 8 + 4 + modeBytes.length;
  const buf = new Uint8Array(1 + 96 + 4 + dataLen + 32 + 8 + 32);
  const view = new DataView(buf.buffer);

  buf[0] = 2;
  buf.set(new SolanaAddress(opts.wallet).toBytes(), 1);
  buf.set(
    new SolanaAddress(
      opts.credential ?? SAS_DEVNET_CONFIG.entrosCredentialPda,
    ).toBytes(),
    33,
  );
  buf.set(
    new SolanaAddress(
      opts.schema ?? SAS_DEVNET_CONFIG.entrosSchemaPda,
    ).toBytes(),
    65,
  );
  view.setUint32(97, dataLen, true);
  buf[101] = opts.isHuman ?? 1;
  view.setUint16(102, opts.trustScore ?? 300, true);
  view.setBigInt64(104, opts.verifiedAt ?? 1_799_999_990n, true);
  view.setUint32(112, modeBytes.length, true);
  buf.set(modeBytes, 116);
  buf.fill(opts.signerFill ?? 9, 101 + dataLen, 133 + dataLen);
  view.setBigInt64(133 + dataLen, opts.expiry ?? 1_800_001_000n, true);
  return buf;
}

export function buildMigrationRecordBuffer(
  migratedAt: number,
  previousWalletFill = 9,
): Uint8Array {
  const buf = new Uint8Array(57);
  const view = new DataView(buf.buffer);
  buf.set(MIGRATION_RECORD_DISCRIMINATOR, 0);
  view.setBigInt64(8, BigInt(migratedAt), true);
  view.setBigUint64(16, 90n, true);
  buf[24] = 254;
  buf.fill(previousWalletFill, 25, 57);
  return buf;
}

export function buildCoreAssetBuffer(opts: {
  owner: string;
  collection?: string;
  updateAuthorityTag?: number;
  name?: string;
  uri?: string;
  pluginTail?: Uint8Array;
}): Uint8Array {
  const nameBytes = encoder.encode(opts.name ?? "entros-agent");
  const uriBytes = encoder.encode(opts.uri ?? "https://entros.io/agent.json");
  const tail = opts.pluginTail ?? new Uint8Array(0);
  const total =
    1 + 32 + 1 + 32 + 4 + nameBytes.length + 4 + uriBytes.length + 1 + tail.length;
  const buf = new Uint8Array(total);
  const view = new DataView(buf.buffer);
  let offset = 0;
  buf[offset] = 1;
  offset += 1;
  buf.set(new SolanaAddress(opts.owner).toBytes(), offset);
  offset += 32;
  buf[offset] = opts.updateAuthorityTag ?? 2;
  offset += 1;
  buf.set(
    new SolanaAddress(
      opts.collection ?? AGENT_REGISTRY_DEVNET_CONFIG.collection,
    ).toBytes(),
    offset,
  );
  offset += 32;
  view.setUint32(offset, nameBytes.length, true);
  offset += 4;
  buf.set(nameBytes, offset);
  offset += nameBytes.length;
  view.setUint32(offset, uriBytes.length, true);
  offset += 4;
  buf.set(uriBytes, offset);
  offset += uriBytes.length;
  buf[offset] = 0; // seq = None
  offset += 1;
  buf.set(tail, offset);
  return buf;
}

export function buildAgentAccountBuffer(opts: {
  asset: string;
  cachedOwner: string;
  agentWallet: string | null;
  collection?: string;
  bump?: number;
}): Uint8Array {
  const buf = new Uint8Array(748);
  const [, derivedBump] = deriveAgentAccountPda(opts.asset);
  buf.set(AGENT_ACCOUNT_DISCRIMINATOR, 0);
  buf.set(
    new SolanaAddress(
      opts.collection ?? AGENT_REGISTRY_DEVNET_CONFIG.collection,
    ).toBytes(),
    8,
  );
  buf.set(new SolanaAddress(opts.cachedOwner).toBytes(), 72);
  buf.set(new SolanaAddress(opts.asset).toBytes(), 104);
  buf[136] = opts.bump ?? derivedBump;
  buf[137] = 1;
  if (opts.agentWallet !== null) {
    buf[138] = 1;
    buf.set(new SolanaAddress(opts.agentWallet).toBytes(), 139);
  } else {
    buf[138] = 0;
  }
  return buf;
}

function encodeReceiptArgs(
  validatedAt: number,
  sessionFinalDigest: Uint8Array | null = null,
): Uint8Array {
  const length = sessionFinalDigest ? 8 + 1 + 1 + 32 : 8 + 1 + 1;
  const buf = new Uint8Array(length);
  const view = new DataView(buf.buffer);
  view.setBigInt64(0, BigInt(validatedAt), true);
  buf[8] = 1;
  if (sessionFinalDigest) {
    buf[9] = 1;
    buf.set(sessionFinalDigest, 10);
  } else {
    buf[9] = 0;
  }
  return buf;
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function encodeResetInstruction(): string {
  return base58Encode(
    concatBytes(
      Uint8Array.from(ANCHOR_DISCS.reset_identity_state),
      new Uint8Array(34),
    ),
  );
}

export interface EvidenceFixtureOptions {
  walletPubkey?: string;
  nowSeconds?: number;
  blockTime?: number;
  kind?: "mint" | "update" | "compact" | "bound" | "rebaseline" | "legacy-compact";
  trustScore?: number;
  verificationCount?: number;
  creationTimestamp?: number;
  lastVerificationTimestamp?: number;
  lastResetTimestamp?: number;
  lastRebaselineTimestamp?: number;
  projectionVersion?: number;
  attestation?: "present" | "missing" | "unavailable";
  identity?: "present" | "missing" | "unavailable";
  expiry?: number;
  migratedAt?: number;
  migration?: "unavailable";
  includeSessionDigest?: boolean;
  includeTrailingProofRequestState?: boolean;
}

export function createEvidenceFixture(options: EvidenceFixtureOptions = {}) {
  const nowSeconds = options.nowSeconds ?? 1_800_000_000;
  const blockTime = options.blockTime ?? nowSeconds - 10;
  const wallet = new SolanaAddress(
    options.walletPubkey ?? new Uint8Array(32).fill(7),
  );
  const anchorProgram = new SolanaAddress(SOLANA_PROGRAM_IDS.anchor);
  const verifierProgram = new SolanaAddress(SOLANA_PROGRAM_IDS.verifier);
  const sasProgram = new SolanaAddress(SAS_DEVNET_CONFIG.programId);
  const defaultAddr = new SolanaAddress(SYSTEM_PROGRAM_ID);

  const [identityAddr, bump] = deriveIdentityPda(wallet);
  const identityPda = new SolanaAddress(identityAddr);
  const [attestationAddr] = deriveSasAttestationPda(wallet);
  const attestationPda = new SolanaAddress(attestationAddr);
  const [migrationAddr] = deriveMigrationRecordPda(wallet);
  const migrationPda = new SolanaAddress(migrationAddr);
  const [proofRequestStateAddr] = deriveProofRequestStatePda(wallet);
  const proofRequestStatePda = new SolanaAddress(proofRequestStateAddr);

  const signature = base58Encode(new Uint8Array(64).fill(8));
  const commitment = new Uint8Array(32).fill(3);
  const nonce = new Uint8Array(32).fill(4);
  const kind = options.kind ?? "update";
  const projectionVersion = options.projectionVersion ?? 1;

  const identityData = buildIdentityStateBuffer({
    owner: wallet.toBase58(),
    bump,
    creationTimestamp:
      options.creationTimestamp ??
      (kind === "mint" ? blockTime : nowSeconds - 1000),
    lastVerificationTimestamp: options.lastVerificationTimestamp ?? blockTime,
    verificationCount: options.verificationCount ?? (kind === "mint" ? 0 : 7),
    trustScore: options.trustScore ?? (kind === "mint" ? 0 : 300),
    commitmentFill: 3,
    lastResetTimestamp: options.lastResetTimestamp ?? 0,
    projectionVersion,
    lastRebaselineTimestamp:
      options.lastRebaselineTimestamp ??
      (kind === "rebaseline" ? blockTime : 0),
  });

  const identityAccount: RawAccountInfoLike & {
    data: Uint8Array;
    owner: SolanaAddress;
    executable: boolean;
  } = {
    data: identityData,
    executable: false,
    lamports: 1,
    owner: anchorProgram,
  };

  const sasAccount: RawAccountInfoLike & {
    data: Uint8Array;
    owner: SolanaAddress;
    executable: boolean;
  } = {
    data: buildSasAttestationBuffer({
      wallet: wallet.toBase58(),
      trustScore: options.trustScore ?? (kind === "mint" ? 0 : 300),
      verifiedAt: BigInt(blockTime),
      expiry: BigInt(options.expiry ?? nowSeconds + 1000),
    }),
    executable: false,
    lamports: 1,
    owner: sasProgram,
  };

  let migrationAccount:
    | (RawAccountInfoLike & {
        data: Uint8Array;
        owner: SolanaAddress;
        executable: boolean;
      })
    | null =
    options.migratedAt === undefined
      ? null
      : {
          data: buildMigrationRecordBuffer(options.migratedAt),
          executable: false,
          lamports: 1,
          owner: anchorProgram,
        };

  const sessionDigest = options.includeSessionDigest
    ? new Uint8Array(32).fill(0xab)
    : null;
  const receiptBytes = encodeReceiptArgs(blockTime, sessionDigest);

  const instructions: ParsedTransactionLike["transaction"]["message"]["instructions"][number][] =
    [];

  if (kind === "mint") {
    const accounts = Array.from({ length: 11 }, (_, i) =>
      i === 0 ? wallet : i === 1 ? identityPda : defaultAddr,
    );
    if (options.includeTrailingProofRequestState) {
      accounts.push(proofRequestStatePda);
    }
    instructions.push({
      programId: anchorProgram,
      accounts,
      data: base58Encode(
        concatBytes(Uint8Array.from(ANCHOR_DISCS.mint_anchor), commitment),
      ),
    });
  } else if (kind === "rebaseline") {
    const accounts = Array.from({ length: 6 }, (_, i) =>
      i === 0 ? wallet : i === 1 ? identityPda : defaultAddr,
    );
    if (options.includeTrailingProofRequestState) {
      accounts.push(proofRequestStatePda);
    }
    const pv = new Uint8Array(2);
    new DataView(pv.buffer).setUint16(0, projectionVersion, true);
    instructions.push({
      programId: anchorProgram,
      accounts,
      data: base58Encode(
        concatBytes(
          Uint8Array.from(ANCHOR_DISCS.rebaseline_anchor),
          commitment,
          pv,
        ),
      ),
    });
  } else if (kind === "compact" || kind === "legacy-compact") {
    const [verAddr] = deriveVerificationResultPda(wallet, nonce, false);
    const verificationPda = new SolanaAddress(verAddr);
    if (kind === "compact") {
      const thresholds = new Uint8Array(4);
      const tv = new DataView(thresholds.buffer);
      tv.setUint16(0, 96, true);
      tv.setUint16(2, 3, true);
      instructions.push({
        programId: verifierProgram,
        accounts: [wallet, verificationPda, defaultAddr],
        data: base58Encode(
          concatBytes(
            Uint8Array.from(VERIFIER_DISCS.verify_proof_compact),
            nonce,
            new Uint8Array(256).fill(1),
            commitment,
            new Uint8Array(32).fill(2),
            thresholds,
          ),
        ),
      });
    } else {
      const proofBytes = new Uint8Array(256).fill(1);
      const proofLen = new Uint8Array(4);
      new DataView(proofLen.buffer).setUint32(0, proofBytes.length, true);
      const inputsCount = new Uint8Array(4);
      new DataView(inputsCount.buffer).setUint32(0, 1, true);
      instructions.push({
        programId: verifierProgram,
        accounts: [wallet, verificationPda, defaultAddr],
        data: base58Encode(
          concatBytes(
            Uint8Array.from(VERIFIER_DISCS.verify_proof),
            proofLen,
            proofBytes,
            inputsCount,
            commitment,
            nonce,
          ),
        ),
      });
    }
    const accounts = Array.from({ length: 8 }, (_, i) =>
      i === 0
        ? wallet
        : i === 1
          ? identityPda
          : i === 2
            ? verificationPda
            : defaultAddr,
    );
    instructions.push({
      programId: anchorProgram,
      accounts,
      data: base58Encode(
        concatBytes(
          Uint8Array.from(ANCHOR_DISCS.update_anchor_compact),
          receiptBytes,
        ),
      ),
    });
  } else if (kind === "bound") {
    const [verAddr] = deriveVerificationResultPda(wallet, nonce, true);
    const verificationPda = new SolanaAddress(verAddr);
    const tail = new Uint8Array(12);
    const tv = new DataView(tail.buffer);
    tv.setUint16(0, 96, true);
    tv.setUint16(2, 3, true);
    tv.setBigUint64(4, BigInt(blockTime + 300), true);
    instructions.push({
      programId: verifierProgram,
      accounts: [
        wallet,
        verificationPda,
        identityPda,
        proofRequestStatePda,
        defaultAddr,
      ],
      data: base58Encode(
        concatBytes(
          Uint8Array.from(VERIFIER_DISCS.verify_proof_bound),
          nonce,
          new Uint8Array(256).fill(1),
          commitment,
          new Uint8Array(32).fill(2),
          tail,
        ),
      ),
    });
    const accounts = Array.from({ length: 9 }, (_, i) =>
      i === 0
        ? wallet
        : i === 1
          ? identityPda
          : i === 2
            ? proofRequestStatePda
            : i === 3
              ? verificationPda
              : defaultAddr,
    );
    instructions.push({
      programId: anchorProgram,
      accounts,
      data: base58Encode(
        concatBytes(
          Uint8Array.from(ANCHOR_DISCS.update_anchor_bound),
          receiptBytes,
        ),
      ),
    });
  } else {
    const accounts = Array.from({ length: 8 }, (_, i) =>
      i === 0 ? wallet : i === 1 ? identityPda : defaultAddr,
    );
    instructions.push({
      programId: anchorProgram,
      accounts,
      data: base58Encode(
        concatBytes(
          Uint8Array.from(ANCHOR_DISCS.update_anchor),
          commitment,
          receiptBytes,
        ),
      ),
    });
  }

  const transaction: ParsedTransactionLike = {
    slot: 100,
    blockTime,
    version: "legacy",
    meta: { err: null },
    transaction: {
      signatures: [signature],
      message: {
        accountKeys: [{ pubkey: wallet, signer: true, writable: true }],
        instructions,
      },
    },
  };

  const status: SignatureStatusLike = {
    slot: 100,
    confirmations: 1,
    err: null,
    confirmationStatus: "confirmed",
  };

  const calls: string[] = [];
  const state = {
    identityAccount,
    sasAccount,
    migrationAccount,
    transaction,
    status,
  };

  const connection: SolanaConnectionLike = {
    async getGenesisHash() {
      calls.push("genesis");
      return SOLANA_DEVNET_GENESIS_HASH;
    },
    async getSignatureStatuses() {
      calls.push("status");
      return { context: { slot: 101 }, value: [state.status] };
    },
    async getParsedTransaction() {
      calls.push("transaction");
      return state.transaction;
    },
    async getAccountInfoAndContext(address) {
      if (address.equals(migrationPda)) {
        calls.push("migration");
        if (options.migration === "unavailable") {
          throw new Error("Synthetic RPC failure");
        }
        return { context: { slot: 102 }, value: state.migrationAccount };
      }
      const isIdentity = address.equals(identityPda);
      calls.push(isIdentity ? "identity" : "attestation");
      const mode = isIdentity ? options.identity : options.attestation;
      if (mode === "unavailable") throw new Error("Synthetic RPC failure");
      return {
        context: { slot: 102 },
        value:
          mode === "missing"
            ? null
            : isIdentity
              ? state.identityAccount
              : state.sasAccount,
      };
    },
  };

  return {
    input: {
      walletPubkey: wallet.toBase58(),
      transactionSignature: signature,
      connection,
      nowSeconds,
    },
    connection,
    wallet,
    identityPda,
    attestationPda,
    migrationPda,
    proofRequestStatePda,
    calls,
    get identityAccount() {
      return state.identityAccount;
    },
    set identityAccount(v) {
      state.identityAccount = v;
    },
    get sasAccount() {
      return state.sasAccount;
    },
    set sasAccount(v) {
      state.sasAccount = v;
    },
    get migrationAccount() {
      return state.migrationAccount;
    },
    set migrationAccount(v) {
      state.migrationAccount = v;
    },
    get transaction() {
      return state.transaction;
    },
    set transaction(v) {
      state.transaction = v;
    },
    get status() {
      return state.status;
    },
    set status(v) {
      state.status = v;
    },
  };
}
