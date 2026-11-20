import anchorPackage from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { INTEGRATOR_PROGRAM_IDS } from "@entros/pulse-sdk";
import { AGENT_PERMIT_NETWORK } from "@entros/verify/agent-permit";
import anchorIdl from "./anchor-fixture-idl.json" with { type: "json" };
import {
  ENTROS_VOTER_WEIGHT_PROGRAM_ID,
  MIGRATION_RECORD_DISCRIMINATOR,
  REGISTRAR_DISCRIMINATOR,
  SPL_GOVERNANCE_PROGRAM_ID,
  VOTER_WEIGHT_RECORD_DISCRIMINATOR,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveRegistrarPda,
  deriveVoterWeightRecordPda,
} from "./realms-check.mjs";

const { BN, BorshAccountsCoder, BorshInstructionCoder, utils } = anchorPackage;

const AGENT_ACCOUNT_DISCRIMINATOR = Buffer.from("f177458ce9097032", "hex");
const ANCHOR_PROGRAM = new PublicKey(INTEGRATOR_PROGRAM_IDS.anchor);
const SAS_PROGRAM = new PublicKey(INTEGRATOR_PROGRAM_IDS.sas);
const SAS_CREDENTIAL = new PublicKey(INTEGRATOR_PROGRAM_IDS.credential);
const SAS_SCHEMA = new PublicKey(INTEGRATOR_PROGRAM_IDS.schema);
const REGISTRY_PROGRAM = new PublicKey(AGENT_PERMIT_NETWORK.agentRegistryProgram);
const CORE_PROGRAM = new PublicKey(AGENT_PERMIT_NETWORK.coreProgram);
const AGENT_COLLECTION = new PublicKey(AGENT_PERMIT_NETWORK.agentCollection);

export function deriveAttestationPda(walletPubkey) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("attestation"),
      SAS_CREDENTIAL.toBuffer(),
      SAS_SCHEMA.toBuffer(),
      new PublicKey(walletPubkey).toBuffer(),
    ],
    SAS_PROGRAM,
  )[0];
}

/** Encodes a 204-byte SAS attestation matching the pinned devnet layout. */
export function encodeSasAttestation({
  walletPubkey,
  trustScore,
  verifiedAt,
  expiry = 0,
  invalid = false,
}) {
  const wallet = new PublicKey(walletPubkey);
  const mode = Buffer.from("wallet-connected", "utf8");
  const dataLen = 15 + mode.length;
  const raw = Buffer.alloc(173 + dataLen);
  raw[0] = invalid ? 9 : 2;
  wallet.toBuffer().copy(raw, 1);
  SAS_CREDENTIAL.toBuffer().copy(raw, 33);
  SAS_SCHEMA.toBuffer().copy(raw, 65);
  raw.writeUInt32LE(dataLen, 97);
  raw[101] = 1;
  raw.writeUInt16LE(trustScore, 102);
  raw.writeBigInt64LE(BigInt(verifiedAt), 104);
  raw.writeUInt32LE(mode.length, 112);
  mode.copy(raw, 116);
  // Non-zero issuer signer pubkey; trailing 32-byte token_account stays all zero.
  raw.fill(9, 101 + dataLen, 133 + dataLen);
  raw.writeBigInt64LE(BigInt(expiry), 133 + dataLen);
  return raw;
}

/** Encodes a 57-byte Entros MigrationRecord account. */
export function encodeMigrationRecord({
  migratedAt,
  migratedSlot,
  bump = 254,
  previousWallet,
}) {
  const raw = Buffer.alloc(57);
  MIGRATION_RECORD_DISCRIMINATOR.copy(raw, 0);
  raw.writeBigInt64LE(BigInt(migratedAt), 8);
  raw.writeBigUInt64LE(BigInt(migratedSlot), 16);
  raw[24] = bump;
  new PublicKey(previousWallet).toBuffer().copy(raw, 25);
  return raw;
}

/** Encodes a 178-byte entros-voter-weight Registrar account. */
export function encodeRegistrar({
  governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
  realm,
  governingTokenMint,
  minTrustScore,
  maxVerificationAge,
}) {
  const raw = Buffer.alloc(178);
  REGISTRAR_DISCRIMINATOR.copy(raw, 0);
  new PublicKey(governanceProgramId).toBuffer().copy(raw, 8);
  new PublicKey(realm).toBuffer().copy(raw, 40);
  new PublicKey(governingTokenMint).toBuffer().copy(raw, 72);
  raw.writeUInt16LE(minTrustScore, 104);
  raw.writeBigInt64LE(BigInt(maxVerificationAge), 106);
  return raw;
}

/** Encodes a Borsh VoterWeightRecord matching spl-governance-addin-api. */
export function encodeVoterWeightRecord({
  realm,
  governingTokenMint,
  governingTokenOwner,
  voterWeight,
  voterWeightExpiry = null,
  weightAction = null,
  weightActionTarget = null,
}) {
  const parts = [
    VOTER_WEIGHT_RECORD_DISCRIMINATOR,
    new PublicKey(realm).toBuffer(),
    new PublicKey(governingTokenMint).toBuffer(),
    new PublicKey(governingTokenOwner).toBuffer(),
  ];
  const weightBuf = Buffer.alloc(8);
  weightBuf.writeBigUInt64LE(BigInt(voterWeight), 0);
  parts.push(weightBuf);

  if (voterWeightExpiry === null) {
    parts.push(Buffer.from([0]));
  } else {
    const expiryBuf = Buffer.alloc(9);
    expiryBuf[0] = 1;
    expiryBuf.writeBigUInt64LE(BigInt(voterWeightExpiry), 1);
    parts.push(expiryBuf);
  }

  if (weightAction === null) {
    parts.push(Buffer.from([0]));
  } else {
    parts.push(Buffer.from([1, weightAction]));
  }

  if (weightActionTarget === null) {
    parts.push(Buffer.from([0]));
  } else {
    parts.push(Buffer.from([1]), new PublicKey(weightActionTarget).toBuffer());
  }

  parts.push(Buffer.alloc(8));
  return Buffer.concat(parts);
}

function borshString(value) {
  const bytes = Buffer.from(value, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function borshOptionI64(value) {
  if (value === null || value === undefined) return Buffer.from([0]);
  const buf = Buffer.alloc(9);
  buf[0] = 1;
  buf.writeBigInt64LE(BigInt(value), 1);
  return buf;
}

function borshOptionU64(value) {
  if (value === null || value === undefined) return Buffer.from([0]);
  const buf = Buffer.alloc(9);
  buf[0] = 1;
  buf.writeBigUInt64LE(BigInt(value), 1);
  return buf;
}

/** Encodes a Borsh ProposalV2 account matching spl-governance. */
export function encodeProposalV2({
  governance,
  governingTokenMint,
  tokenOwnerRecord,
  state = 2,
  draftAt = 1799999000,
  votingAt = 1799999500,
  votingAtSlot = 950,
  name = "Synthetic Proposal",
}) {
  const optionLabel = borshString("Approve");
  const optionTail = Buffer.alloc(15); // vote_weight(8) + result(1) + 3*u16(6)
  const optionCount = Buffer.alloc(4);
  optionCount.writeUInt32LE(1, 0);
  const draftBuf = Buffer.alloc(8);
  draftBuf.writeBigInt64LE(BigInt(draftAt), 0);

  return Buffer.concat([
    Buffer.from([14]), // GovernanceAccountType::ProposalV2
    new PublicKey(governance).toBuffer(),
    new PublicKey(governingTokenMint).toBuffer(),
    Buffer.from([state]), // ProposalState (0=Draft, 2=Voting)
    new PublicKey(tokenOwnerRecord).toBuffer(),
    Buffer.from([0, 0]), // signatories_count, signatories_signed_off_count
    Buffer.from([0]), // VoteType::SingleChoice
    optionCount,
    optionLabel,
    optionTail,
    borshOptionU64(0), // deny_vote_weight: Some(0)
    Buffer.from([0]), // reserved1
    Buffer.from([0]), // abstain_vote_weight: None
    Buffer.from([0]), // start_voting_at: None
    draftBuf,
    Buffer.from([0]), // signing_off_at: None
    borshOptionI64(votingAt),
    borshOptionU64(votingAtSlot),
    Buffer.from([0]), // voting_completed_at: None
    Buffer.from([0]), // executing_at: None
    Buffer.from([0]), // closed_at: None
    Buffer.from([0]), // execution_flags: None
    Buffer.from([0]), // max_vote_weight: None
    Buffer.from([0]), // max_voting_time: None
    Buffer.from([0]), // vote_threshold: None
    Buffer.alloc(64), // reserved
    borshString(name),
    borshString(""),
    Buffer.alloc(8), // veto_vote_weight
  ]);
}

function encodeCoreAsset(owner, collection = AGENT_COLLECTION) {
  const name = Buffer.from("Reference Agent");
  const uri = Buffer.from("ipfs://synthetic-reference-agent");
  const data = Buffer.alloc(
    1 + 32 + 1 + 32 + 4 + name.length + 4 + uri.length + 1,
  );
  let offset = 0;
  data[offset++] = 1;
  new PublicKey(owner).toBuffer().copy(data, offset);
  offset += 32;
  data[offset++] = 2;
  new PublicKey(collection).toBuffer().copy(data, offset);
  offset += 32;
  data.writeUInt32LE(name.length, offset);
  name.copy(data, offset + 4);
  offset += 4 + name.length;
  data.writeUInt32LE(uri.length, offset);
  uri.copy(data, offset + 4);
  offset += 4 + uri.length;
  data[offset] = 0;
  return data;
}

function encodeAgentAccount(asset, bump, cachedOwner, agentWallet) {
  const data = Buffer.alloc(748);
  AGENT_ACCOUNT_DISCRIMINATOR.copy(data, 0);
  AGENT_COLLECTION.toBuffer().copy(data, 8);
  new PublicKey(cachedOwner).toBuffer().copy(data, 40);
  new PublicKey(cachedOwner).toBuffer().copy(data, 72);
  new PublicKey(asset).toBuffer().copy(data, 104);
  data[136] = bump;
  data[137] = 0;
  data[138] = agentWallet ? 1 : 0;
  if (agentWallet) new PublicKey(agentWallet).toBuffer().copy(data, 139);
  return data;
}

/**
 * Synthetic devnet fixture backing published `@entros/pulse-sdk@4.17.0` readers
 * (`findLatestVerificationTransaction`, `readIntegratorEvidence`,
 * `verifyEntrosAttestation`, `readAgentState`) and Realms pre-flight checks.
 */
export function createReferenceFixture({
  nowSeconds = 1800000000,
  currentSlot = 1000,
} = {}) {
  const accountCoder = new BorshAccountsCoder(anchorIdl);
  const instructionCoder = new BorshInstructionCoder(anchorIdl);

  const state = {
    now: nowSeconds,
    slot: currentSlot,
    rpcUnavailable: false,
    wrongGenesis: false,
  };
  const reads = [];
  const wallets = new Map();
  const transactions = new Map();
  const agents = new Map();
  const customAccounts = new Map();
  let txCounter = 1;

  function nextSignature() {
    const bytes = new Uint8Array(64).fill(7);
    bytes[0] = (txCounter >> 8) & 0xff;
    bytes[1] = txCounter & 0xff;
    bytes[63] = (txCounter * 17) & 0xff;
    txCounter += 1;
    return utils.bytes.bs58.encode(bytes);
  }

  function nextCommitment() {
    // Prefix 0x01 stays strictly below the BN254 scalar field modulus.
    const bytes = new Array(32).fill(0);
    bytes[0] = 1;
    bytes[1] = (txCounter >> 8) & 0xff;
    bytes[2] = txCounter & 0xff;
    bytes[31] = ((txCounter * 31) % 250) + 1;
    return bytes;
  }

  function buildAnchorTx({
    wallet,
    identity,
    mint,
    instructionName,
    args,
    slot,
    blockTime,
    failed = false,
  }) {
    const ixDef = anchorIdl.instructions.find(
      (entry) => entry.name === instructionName,
    );
    if (!ixDef) throw new Error(`Missing IDL instruction: ${instructionName}`);
    const accounts = ixDef.accounts.map((account, index) => {
      if (account.name === "user" || account.name === "authority") return wallet;
      if (account.name === "identity_state") return identity;
      if (account.name === "mint") return mint;
      return account.address
        ? new PublicKey(account.address)
        : new PublicKey(new Uint8Array(32).fill(index + 40));
    });
    const encodedData = utils.bytes.bs58.encode(
      instructionCoder.encode(instructionName, args),
    );
    const signature = nextSignature();
    const parsed = {
      slot,
      blockTime,
      meta: {
        err: failed ? { InstructionError: [0, "SyntheticFailure"] } : null,
        fee: 5000,
        preBalances: [],
        postBalances: [],
        innerInstructions: [],
        logMessages: [],
        preTokenBalances: [],
        postTokenBalances: [],
      },
      transaction: {
        signatures: [signature],
        message: {
          accountKeys: accounts.map((pubkey, index) => ({
            pubkey,
            signer: index === 0,
            writable: index < 3,
          })),
          instructions: [
            {
              programId: ANCHOR_PROGRAM,
              accounts,
              data: encodedData,
            },
          ],
          recentBlockhash: PublicKey.default.toBase58(),
        },
      },
      version: "legacy",
    };
    transactions.set(signature, { signature, slot, blockTime, failed, parsed });
    return signature;
  }

  function ensureWallet(walletPubkey) {
    const existing = wallets.get(walletPubkey);
    if (existing) return existing;
    const wallet = new PublicKey(walletPubkey);
    const [identity, identityBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("identity"), wallet.toBuffer()],
      ANCHOR_PROGRAM,
    );
    const [mint] = PublicKey.findProgramAddressSync(
      [Buffer.from("mint"), wallet.toBuffer()],
      ANCHOR_PROGRAM,
    );
    const attestationPda = deriveAttestationPda(wallet);
    const migrationPda = deriveMigrationRecordPda(wallet);
    const record = {
      wallet,
      walletPubkey: wallet.toBase58(),
      identity,
      identityBump,
      mint,
      attestationPda,
      migrationPda,
      identityState: null,
      attestation: null,
      migration: null,
      history: [],
    };
    wallets.set(record.walletPubkey, record);
    return record;
  }

  function recordHistory(record, signature, slot, blockTime, failed = false) {
    record.history.unshift({
      signature,
      slot,
      blockTime,
      err: failed ? { InstructionError: [0, "SyntheticFailure"] } : null,
      confirmationStatus: "confirmed",
    });
  }

  function setAttestation(walletPubkey, spec) {
    const record = ensureWallet(walletPubkey);
    if (!spec || spec.status === "missing") {
      record.attestation = null;
      return;
    }
    const trustScore = spec.trustScore ?? record.identityState?.trustScore ?? 0;
    const verifiedAt =
      spec.verifiedAt ?? record.identityState?.lastVerificationTimestamp ?? state.now - 10;
    const expiry = spec.expiresAt ?? 0;
    record.attestation = {
      data: encodeSasAttestation({
        walletPubkey,
        trustScore,
        verifiedAt,
        expiry,
        invalid: spec.status === "invalid",
      }),
      owner: SAS_PROGRAM,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    };
  }

  function mintWallet(
    walletPubkey,
    {
      verifiedAt = state.now - 10,
      slot = state.slot - 5,
      attestation = { status: "present" },
    } = {},
  ) {
    const record = ensureWallet(walletPubkey);
    const commitment = nextCommitment();
    const signature = buildAnchorTx({
      wallet: record.wallet,
      identity: record.identity,
      mint: record.mint,
      instructionName: "mint_anchor",
      args: { initial_commitment: commitment },
      slot,
      blockTime: verifiedAt,
    });
    record.identityState = {
      creationTimestamp: verifiedAt,
      lastVerificationTimestamp: verifiedAt,
      verificationCount: 0,
      trustScore: 0,
      currentCommitment: commitment,
      lastResetTimestamp: 0,
      projectionVersion: 1,
      lastRebaselineTimestamp: 0,
    };
    recordHistory(record, signature, slot, verifiedAt);
    setAttestation(walletPubkey, attestation);
    return { signature, identityPda: record.identity.toBase58() };
  }

  function updateWallet(
    walletPubkey,
    {
      trustScore = 250,
      verifiedAt = state.now - 10,
      slot = state.slot - 2,
      verificationCount,
      projectionVersion = 1,
      attestation = { status: "present" },
    } = {},
  ) {
    const record = ensureWallet(walletPubkey);
    const commitment = nextCommitment();
    const creationTimestamp =
      record.identityState?.creationTimestamp ?? verifiedAt - 86400;
    const nextCount =
      verificationCount ??
      Math.max(1, (record.identityState?.verificationCount ?? 0) + 1);
    const signature = buildAnchorTx({
      wallet: record.wallet,
      identity: record.identity,
      mint: record.mint,
      instructionName: "update_anchor",
      args: {
        new_commitment: commitment,
        receipt: {
          validated_at: new BN(verifiedAt),
          assurance_tier: 0,
          session_final_digest: null,
        },
      },
      slot,
      blockTime: verifiedAt,
    });
    record.identityState = {
      creationTimestamp,
      lastVerificationTimestamp: verifiedAt,
      verificationCount: nextCount,
      trustScore,
      currentCommitment: commitment,
      lastResetTimestamp: record.identityState?.lastResetTimestamp ?? 0,
      projectionVersion,
      lastRebaselineTimestamp:
        record.identityState?.lastRebaselineTimestamp ?? 0,
    };
    recordHistory(record, signature, slot, verifiedAt);
    setAttestation(walletPubkey, attestation);
    return { signature, identityPda: record.identity.toBase58() };
  }

  function resetWallet(
    walletPubkey,
    { resetAt = state.now - 5, slot = state.slot - 1, projectionVersion = 1 } = {},
  ) {
    const record = ensureWallet(walletPubkey);
    if (!record.identityState) {
      throw new Error("Wallet has no IdentityState to reset");
    }
    const commitment = nextCommitment();
    const signature = buildAnchorTx({
      wallet: record.wallet,
      identity: record.identity,
      mint: record.mint,
      instructionName: "reset_identity_state",
      args: {
        new_commitment: commitment,
        projection_version: projectionVersion,
      },
      slot,
      blockTime: resetAt,
    });
    record.identityState = {
      ...record.identityState,
      lastVerificationTimestamp: Math.max(
        record.identityState.lastVerificationTimestamp,
        resetAt,
      ),
      trustScore: 0,
      currentCommitment: commitment,
      lastResetTimestamp: resetAt,
      projectionVersion,
    };
    recordHistory(record, signature, slot, resetAt);
    return { signature };
  }

  function rebaselineWallet(
    walletPubkey,
    {
      trustScore = 250,
      verifiedAt = state.now - 5,
      slot = state.slot - 1,
      projectionVersion = 1,
      attestation = { status: "present" },
    } = {},
  ) {
    const record = ensureWallet(walletPubkey);
    const commitment = nextCommitment();
    const creationTimestamp =
      record.identityState?.creationTimestamp ?? verifiedAt - 86400;
    const verificationCount = Math.max(
      1,
      (record.identityState?.verificationCount ?? 0) + 1,
    );
    const signature = buildAnchorTx({
      wallet: record.wallet,
      identity: record.identity,
      mint: record.mint,
      instructionName: "rebaseline_anchor",
      args: {
        new_commitment: commitment,
        projection_version: projectionVersion,
      },
      slot,
      blockTime: verifiedAt,
    });
    record.identityState = {
      creationTimestamp,
      lastVerificationTimestamp: verifiedAt,
      verificationCount,
      trustScore,
      currentCommitment: commitment,
      lastResetTimestamp: record.identityState?.lastResetTimestamp ?? 0,
      projectionVersion,
      lastRebaselineTimestamp: verifiedAt,
    };
    recordHistory(record, signature, slot, verifiedAt);
    setAttestation(walletPubkey, attestation);
    return { signature, identityPda: record.identity.toBase58() };
  }

  function migrateWallet(
    walletPubkey,
    { previousWallet, migratedAt, migratedSlot, corrupted = false },
  ) {
    const record = ensureWallet(walletPubkey);
    const data = encodeMigrationRecord({
      migratedAt,
      migratedSlot,
      previousWallet,
    });
    if (corrupted) data[0] ^= 0xff;
    record.migration = {
      data,
      owner: ANCHOR_PROGRAM,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    };
    return record.migrationPda.toBase58();
  }

  function registerAgent({ agent, owner, agentWallet = null }) {
    const asset = new PublicKey(agent);
    const [agentAccountPda, bump] = PublicKey.findProgramAddressSync(
      [Buffer.from("agent"), asset.toBuffer()],
      REGISTRY_PROGRAM,
    );
    const entry = {
      asset,
      agentAccountPda,
      bump,
      coreOwner: new PublicKey(owner),
      cachedOwner: new PublicKey(owner),
      agentWallet: agentWallet ? new PublicKey(agentWallet) : null,
      collection: AGENT_COLLECTION,
      burned: false,
    };
    agents.set(asset.toBase58(), entry);
    return { agent: asset.toBase58(), agentAccount: agentAccountPda.toBase58() };
  }

  function bindAgentWallet(agent, agentWallet) {
    const entry = agents.get(agent);
    if (!entry) throw new Error(`Unknown agent: ${agent}`);
    entry.agentWallet = new PublicKey(agentWallet);
    entry.cachedOwner = entry.coreOwner;
    state.slot += 1;
  }

  function transferAgentDirect(agent, newOwner) {
    const entry = agents.get(agent);
    if (!entry) throw new Error(`Unknown agent: ${agent}`);
    entry.coreOwner = new PublicKey(newOwner);
    state.slot += 1;
  }

  function transferAgentThroughRegistry(agent, newOwner) {
    const entry = agents.get(agent);
    if (!entry) throw new Error(`Unknown agent: ${agent}`);
    entry.coreOwner = new PublicKey(newOwner);
    entry.cachedOwner = entry.coreOwner;
    entry.agentWallet = null;
    state.slot += 1;
  }

  function setAgentCachedOwner(agent, cachedOwner) {
    const entry = agents.get(agent);
    if (!entry) throw new Error(`Unknown agent: ${agent}`);
    entry.cachedOwner = new PublicKey(cachedOwner);
    state.slot += 1;
  }

  function setRegistrar({
    realm,
    governingTokenMint,
    minTrustScore,
    maxVerificationAge,
    governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
  }) {
    const registrarPda = deriveRegistrarPda(realm, governingTokenMint);
    customAccounts.set(registrarPda.toBase58(), {
      data: encodeRegistrar({
        governanceProgramId,
        realm,
        governingTokenMint,
        minTrustScore,
        maxVerificationAge,
      }),
      owner: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    });
    return registrarPda.toBase58();
  }

  function setProposal({
    proposal,
    governance,
    governingTokenMint,
    tokenOwnerRecord,
    state: proposalState = 2,
    draftAt = state.now - 1000,
    votingAt = state.now - 500,
    votingAtSlot = 950,
    name = "Synthetic Proposal",
    governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
  }) {
    const proposalKey = new PublicKey(proposal);
    customAccounts.set(proposalKey.toBase58(), {
      data: encodeProposalV2({
        governance,
        governingTokenMint,
        tokenOwnerRecord,
        state: proposalState,
        draftAt,
        votingAt,
        votingAtSlot,
        name,
      }),
      owner: new PublicKey(governanceProgramId),
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    });
    return proposalKey.toBase58();
  }

  function setVoterWeightRecord({
    realm,
    governingTokenMint,
    voter,
    voterWeight = 0,
    voterWeightExpiry = 0,
    weightAction = null,
    weightActionTarget = null,
  }) {
    const vwrPda = deriveVoterWeightRecordPda(realm, governingTokenMint, voter);
    customAccounts.set(vwrPda.toBase58(), {
      data: encodeVoterWeightRecord({
        realm,
        governingTokenMint,
        governingTokenOwner: voter,
        voterWeight,
        voterWeightExpiry,
        weightAction,
        weightActionTarget,
      }),
      owner: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    });
    return vwrPda.toBase58();
  }

  function removeVoterWeightRecord({ realm, governingTokenMint, voter }) {
    const vwrPda = deriveVoterWeightRecordPda(realm, governingTokenMint, voter);
    customAccounts.delete(vwrPda.toBase58());
  }

  async function encodeIdentityAccount(record) {
    const s = record.identityState;
    if (!s) return null;
    const data = await accountCoder.encode("IdentityState", {
      owner: record.wallet,
      creation_timestamp: new BN(s.creationTimestamp),
      last_verification_timestamp: new BN(s.lastVerificationTimestamp),
      verification_count: s.verificationCount,
      trust_score: s.trustScore,
      current_commitment: s.currentCommitment,
      mint: record.mint,
      bump: record.identityBump,
      recent_timestamps: [
        new BN(s.lastVerificationTimestamp),
        ...Array.from({ length: 51 }, () => new BN(0)),
      ],
      last_reset_timestamp: new BN(s.lastResetTimestamp),
      new_wallet: PublicKey.default,
      projection_version: s.projectionVersion,
      last_rebaseline_timestamp: new BN(s.lastRebaselineTimestamp),
    });
    return {
      data,
      owner: ANCHOR_PROGRAM,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    };
  }

  async function lookupAccount(pubkey) {
    const address = pubkey.toBase58();
    if (customAccounts.has(address)) {
      return customAccounts.get(address);
    }
    for (const record of wallets.values()) {
      if (record.identity.equals(pubkey)) return encodeIdentityAccount(record);
      if (record.attestationPda.equals(pubkey)) return record.attestation;
      if (record.migrationPda.equals(pubkey)) return record.migration;
    }
    for (const entry of agents.values()) {
      if (entry.asset.equals(pubkey)) {
        return {
          data: entry.burned
            ? Buffer.from([0])
            : encodeCoreAsset(entry.coreOwner, entry.collection),
          owner: CORE_PROGRAM,
          executable: false,
          lamports: 1,
          rentEpoch: 0,
        };
      }
      if (entry.agentAccountPda.equals(pubkey)) {
        return {
          data: encodeAgentAccount(
            entry.asset,
            entry.bump,
            entry.cachedOwner,
            entry.agentWallet,
          ),
          owner: REGISTRY_PROGRAM,
          executable: false,
          lamports: 1,
          rentEpoch: 0,
        };
      }
    }
    return null;
  }

  const connection = {
    async getGenesisHash() {
      reads.push("genesis");
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return state.wrongGenesis
        ? "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
        : AGENT_PERMIT_NETWORK.genesisHash;
    },
    async getSlot() {
      reads.push("slot");
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return state.slot;
    },
    async getSignaturesForAddress(address, options = {}) {
      reads.push(`signatures:${address.toBase58()}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      for (const record of wallets.values()) {
        if (record.identity.equals(address)) {
          const limit = options.limit ?? 1000;
          let list = record.history;
          if (options.before) {
            const idx = list.findIndex((item) => item.signature === options.before);
            list = idx >= 0 ? list.slice(idx + 1) : [];
          }
          return list.slice(0, limit);
        }
      }
      return [];
    },
    async getSignatureStatuses([signature]) {
      reads.push(`status:${signature}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      const entry = transactions.get(signature);
      return {
        context: { slot: state.slot },
        value: [
          entry
            ? {
                slot: entry.slot,
                confirmations: 1,
                err: entry.failed ? { InstructionError: [0, "SyntheticFailure"] } : null,
                confirmationStatus: "confirmed",
              }
            : null,
        ],
      };
    },
    async getParsedTransaction(signature) {
      reads.push(`transaction:${signature}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return transactions.get(signature)?.parsed ?? null;
    },
    async getAccountInfo(address) {
      reads.push(`account:${address.toBase58()}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return lookupAccount(address);
    },
    async getAccountInfoAndContext(address) {
      reads.push(`accountCtx:${address.toBase58()}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return {
        context: { slot: state.slot },
        value: await lookupAccount(address),
      };
    },
    async getMultipleAccountsInfo(keys) {
      reads.push(`accounts:${keys.map((key) => key.toBase58()).join(",")}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return Promise.all(keys.map((key) => lookupAccount(key)));
    },
    async getMultipleAccountsInfoAndContext(keys) {
      reads.push(`accountsCtx:${keys.map((key) => key.toBase58()).join(",")}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return {
        context: { slot: state.slot },
        value: await Promise.all(keys.map((key) => lookupAccount(key))),
      };
    },
  };

  return {
    connection,
    state,
    reads,
    walletRecord: ensureWallet,
    mintWallet,
    updateWallet,
    resetWallet,
    rebaselineWallet,
    migrateWallet,
    setAttestation,
    registerAgent,
    bindAgentWallet,
    transferAgentDirect,
    transferAgentThroughRegistry,
    setAgentCachedOwner,
    setRegistrar,
    setProposal,
    setVoterWeightRecord,
    removeVoterWeightRecord,
    deriveIdentityPda,
    deriveMigrationRecordPda,
    deriveAttestationPda,
    deriveRegistrarPda,
    deriveVoterWeightRecordPda,
  };
}
