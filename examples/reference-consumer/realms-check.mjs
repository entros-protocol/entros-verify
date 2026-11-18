/**
 * Realms voter-weight pre-flight and atomic transaction builder/verifier.
 *
 * Models the devnet `entros-voter-weight` plugin contract ("one eligible wallet,
 * one vote"): checks IdentityState score and age plus the 57-byte
 * MigrationRecord slot against a Proposal's `voting_at_slot`, then builds and
 * verifies the atomic `[create_voter_weight_record?,
 * update_voter_weight_record_for_action, spl_governance_ix]` transaction.
 */

import { createHash } from "node:crypto";
import {
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { INTEGRATOR_PROGRAM_IDS } from "@entros/pulse-sdk";

export const ENTROS_VOTER_WEIGHT_PROGRAM_ID = new PublicKey(
  "99nwXzcugse3x8kxE9v6mxZiq8T9gHDoznaaG6qcw534",
);
export const SPL_GOVERNANCE_PROGRAM_ID = new PublicKey(
  "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw",
);
export const ENTROS_ANCHOR_PROGRAM_ID = new PublicKey(
  INTEGRATOR_PROGRAM_IDS.anchor,
);

export const IDENTITY_DISCRIMINATOR = Buffer.from([
  156, 32, 87, 93, 52, 155, 248, 207,
]);
export const MIGRATION_RECORD_DISCRIMINATOR = Buffer.from([
  16, 36, 116, 243, 192, 61, 40, 1,
]);
export const VOTER_WEIGHT_RECORD_DISCRIMINATOR = Buffer.from([
  46, 249, 155, 75, 153, 248, 116, 9,
]);

export const IDENTITY_LAST_VERIFICATION_OFFSET = 48;
export const IDENTITY_TRUST_SCORE_OFFSET = 60;
export const IDENTITY_MIN_DATA_LEN = 62;
export const MIGRATION_RECORD_MIN_LEN = 57;
export const MIGRATION_RECORD_SLOT_OFFSET = 16;
export const REGISTRAR_MIN_LEN = 178;

export const VoterWeightActionTag = Object.freeze({
  CastVote: 0,
  CommentProposal: 1,
  CreateGovernance: 2,
  CreateProposal: 3,
  SignOffProposal: 4,
});

function sha256Prefix(label) {
  return createHash("sha256").update(label).digest().subarray(0, 8);
}

export const REGISTRAR_DISCRIMINATOR = sha256Prefix("account:Registrar");
export const CREATE_VWR_DISCRIMINATOR = sha256Prefix(
  "global:create_voter_weight_record",
);
export const UPDATE_VWR_FOR_ACTION_DISCRIMINATOR = sha256Prefix(
  "global:update_voter_weight_record_for_action",
);

export function deriveRegistrarPda(realm, governingTokenMint) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("registrar"),
      new PublicKey(realm).toBuffer(),
      new PublicKey(governingTokenMint).toBuffer(),
    ],
    ENTROS_VOTER_WEIGHT_PROGRAM_ID,
  )[0];
}

export function deriveVoterWeightRecordPda(realm, governingTokenMint, voter) {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("voter-weight-record"),
      new PublicKey(realm).toBuffer(),
      new PublicKey(governingTokenMint).toBuffer(),
      new PublicKey(voter).toBuffer(),
    ],
    ENTROS_VOTER_WEIGHT_PROGRAM_ID,
  )[0];
}

export function deriveIdentityPda(voter) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("identity"), new PublicKey(voter).toBuffer()],
    ENTROS_ANCHOR_PROGRAM_ID,
  )[0];
}

export function deriveMigrationRecordPda(voter) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("migration"), new PublicKey(voter).toBuffer()],
    ENTROS_ANCHOR_PROGRAM_ID,
  )[0];
}

export function deriveRealmConfigPda(
  realm,
  governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("realm-config"), new PublicKey(realm).toBuffer()],
    new PublicKey(governanceProgramId),
  )[0];
}

export function parseRegistrarAccount(accountInfo, expectedRealm, expectedMint) {
  if (
    !accountInfo ||
    accountInfo.executable ||
    !new PublicKey(accountInfo.owner).equals(ENTROS_VOTER_WEIGHT_PROGRAM_ID)
  ) {
    return null;
  }
  const data = Buffer.from(accountInfo.data);
  if (
    data.length < REGISTRAR_MIN_LEN ||
    !data.subarray(0, 8).equals(REGISTRAR_DISCRIMINATOR)
  ) {
    return null;
  }
  const governanceProgramId = new PublicKey(data.subarray(8, 40));
  const realm = new PublicKey(data.subarray(40, 72));
  const governingTokenMint = new PublicKey(data.subarray(72, 104));
  if (
    expectedRealm &&
    !realm.equals(new PublicKey(expectedRealm))
  ) {
    return null;
  }
  if (
    expectedMint &&
    !governingTokenMint.equals(new PublicKey(expectedMint))
  ) {
    return null;
  }
  const minTrustScore = data.readUInt16LE(104);
  const maxVerificationAge = Number(data.readBigInt64LE(106));
  if (!Number.isSafeInteger(maxVerificationAge) || maxVerificationAge < 1) {
    return null;
  }
  return {
    governanceProgramId: governanceProgramId.toBase58(),
    realm: realm.toBase58(),
    governingTokenMint: governingTokenMint.toBase58(),
    minTrustScore,
    maxVerificationAge,
  };
}

export function parseIdentityForRealms(accountInfo) {
  if (
    !accountInfo ||
    accountInfo.executable ||
    !new PublicKey(accountInfo.owner).equals(ENTROS_ANCHOR_PROGRAM_ID)
  ) {
    return null;
  }
  const data = Buffer.from(accountInfo.data);
  if (
    data.length < IDENTITY_MIN_DATA_LEN ||
    !data.subarray(0, 8).equals(IDENTITY_DISCRIMINATOR)
  ) {
    return null;
  }
  const owner = new PublicKey(data.subarray(8, 40)).toBase58();
  const lastVerificationTimestamp = Number(
    data.readBigInt64LE(IDENTITY_LAST_VERIFICATION_OFFSET),
  );
  const trustScore = data.readUInt16LE(IDENTITY_TRUST_SCORE_OFFSET);
  if (
    !Number.isSafeInteger(lastVerificationTimestamp) ||
    lastVerificationTimestamp < 1
  ) {
    return null;
  }
  return { owner, lastVerificationTimestamp, trustScore };
}

export function parseMigrationRecordSlot(accountInfo) {
  if (
    !accountInfo ||
    !new PublicKey(accountInfo.owner).equals(ENTROS_ANCHOR_PROGRAM_ID)
  ) {
    return { status: "none", migratedSlot: null };
  }
  const data = Buffer.from(accountInfo.data);
  if (
    accountInfo.executable ||
    data.length < MIGRATION_RECORD_MIN_LEN ||
    !data.subarray(0, 8).equals(MIGRATION_RECORD_DISCRIMINATOR)
  ) {
    return { status: "invalid", migratedSlot: null };
  }
  const migratedAt = Number(data.readBigInt64LE(8));
  const migratedSlot = Number(data.readBigUInt64LE(MIGRATION_RECORD_SLOT_OFFSET));
  const bump = data[24];
  const previousWallet = new PublicKey(data.subarray(25, 57)).toBase58();
  if (!Number.isSafeInteger(migratedAt) || !Number.isSafeInteger(migratedSlot)) {
    return { status: "invalid", migratedSlot: null };
  }
  return {
    status: "migrated",
    migratedAt,
    migratedSlot,
    bump,
    previousWallet,
  };
}

/**
 * Parses `ProposalV2` bytes from `spl-governance` to extract `voting_at_slot`.
 */
export function parseProposalVotingAtSlot(accountInfo, governanceProgramId) {
  if (
    !accountInfo ||
    accountInfo.executable ||
    !new PublicKey(accountInfo.owner).equals(new PublicKey(governanceProgramId))
  ) {
    return { status: "invalid", votingAtSlot: null };
  }
  const data = Buffer.from(accountInfo.data);
  let offset = 0;
  const need = (bytes) => {
    if (offset + bytes > data.length) {
      throw new Error("Truncated ProposalV2 account");
    }
  };
  try {
    need(1);
    const accountType = data[offset++];
    if (accountType !== 14) {
      return { status: "invalid", votingAtSlot: null };
    }
    // governance (32) + governing_token_mint (32) + state (1) + token_owner_record (32)
    // + signatories_count (1) + signatories_signed_off_count (1)
    need(32 + 32 + 1 + 32 + 1 + 1);
    const state = data[offset + 64];
    offset += 99;

    // vote_type
    need(1);
    const voteType = data[offset++];
    if (voteType === 1) {
      need(4);
      offset += 4;
    } else if (voteType !== 0) {
      return { status: "invalid", votingAtSlot: null };
    }

    // options: Vec<ProposalOption>
    need(4);
    const optionCount = data.readUInt32LE(offset);
    offset += 4;
    if (optionCount > 64) {
      return { status: "invalid", votingAtSlot: null };
    }
    for (let index = 0; index < optionCount; index += 1) {
      need(4);
      const labelLen = data.readUInt32LE(offset);
      offset += 4;
      need(labelLen + 8 + 1 + 6);
      offset += labelLen + 15;
    }

    const skipOption = (size) => {
      need(1);
      const present = data[offset++];
      if (present === 1) {
        need(size);
        offset += size;
      } else if (present !== 0) {
        throw new Error("Invalid Borsh Option tag");
      }
    };

    skipOption(8); // deny_vote_weight
    need(1);
    offset += 1; // reserved1
    skipOption(8); // abstain_vote_weight
    skipOption(8); // start_voting_at
    need(8);
    offset += 8; // draft_at
    skipOption(8); // signing_off_at
    skipOption(8); // voting_at

    need(1);
    const hasVotingAtSlot = data[offset++];
    if (hasVotingAtSlot === 0) {
      return { status: "not_in_voting", state, votingAtSlot: null };
    }
    if (hasVotingAtSlot !== 1) {
      return { status: "invalid", votingAtSlot: null };
    }
    need(8);
    const votingAtSlot = Number(data.readBigUInt64LE(offset));
    if (!Number.isSafeInteger(votingAtSlot)) {
      return { status: "invalid", votingAtSlot: null };
    }
    return { status: "voting", state, votingAtSlot };
  } catch {
    return { status: "invalid", votingAtSlot: null };
  }
}

export function parseVoterWeightRecordAccount(accountInfo) {
  if (
    !accountInfo ||
    accountInfo.executable ||
    !new PublicKey(accountInfo.owner).equals(ENTROS_VOTER_WEIGHT_PROGRAM_ID)
  ) {
    return null;
  }
  const data = Buffer.from(accountInfo.data);
  if (
    data.length < 115 ||
    !data.subarray(0, 8).equals(VOTER_WEIGHT_RECORD_DISCRIMINATOR)
  ) {
    return null;
  }
  const realm = new PublicKey(data.subarray(8, 40)).toBase58();
  const governingTokenMint = new PublicKey(data.subarray(40, 72)).toBase58();
  const governingTokenOwner = new PublicKey(data.subarray(72, 104)).toBase58();
  const voterWeight = Number(data.readBigUInt64LE(104));

  let offset = 112;
  let voterWeightExpiry = null;
  const hasExpiry = data[offset++];
  if (hasExpiry === 1) {
    if (offset + 8 > data.length) return null;
    voterWeightExpiry = Number(data.readBigUInt64LE(offset));
    offset += 8;
  } else if (hasExpiry !== 0) {
    return null;
  }

  let weightAction = null;
  const hasAction = data[offset++];
  if (hasAction === 1) {
    if (offset + 1 > data.length) return null;
    weightAction = data[offset++];
  } else if (hasAction !== 0) {
    return null;
  }

  let weightActionTarget = null;
  const hasTarget = data[offset++];
  if (hasTarget === 1) {
    if (offset + 32 > data.length) return null;
    weightActionTarget = new PublicKey(
      data.subarray(offset, offset + 32),
    ).toBase58();
  } else if (hasTarget !== 0) {
    return null;
  }

  return {
    realm,
    governingTokenMint,
    governingTokenOwner,
    voterWeight,
    voterWeightExpiry,
    weightAction,
    weightActionTarget,
  };
}

/**
 * Evaluates voter eligibility before prompting a wallet signature for a Realms action.
 */
export async function preflightRealmsVoterWeight({
  connection,
  realm,
  governingTokenMint,
  voter,
  action,
  actionTarget,
  nowSeconds,
}) {
  if (
    !Number.isSafeInteger(action) ||
    !Object.values(VoterWeightActionTag).includes(action)
  ) {
    return { eligible: false, reason: "invalid_weight_action" };
  }
  if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 1) {
    return { eligible: false, reason: "invalid_clock" };
  }
  let realmKey;
  let mintKey;
  let voterKey;
  let targetKey;
  try {
    realmKey = new PublicKey(realm);
    mintKey = new PublicKey(governingTokenMint);
    voterKey = new PublicKey(voter);
    targetKey = new PublicKey(actionTarget);
  } catch {
    return { eligible: false, reason: "invalid_request" };
  }
  if (targetKey.equals(PublicKey.default)) {
    return { eligible: false, reason: "invalid_weight_action_target" };
  }

  const registrarPda = deriveRegistrarPda(realmKey, mintKey);
  const voterWeightRecordPda = deriveVoterWeightRecordPda(
    realmKey,
    mintKey,
    voterKey,
  );
  const identityPda = deriveIdentityPda(voterKey);
  const migrationRecordPda = deriveMigrationRecordPda(voterKey);
  const keys = [
    registrarPda,
    voterWeightRecordPda,
    identityPda,
    migrationRecordPda,
  ];
  if (action === VoterWeightActionTag.CastVote) {
    keys.push(targetKey);
  }

  let accounts;
  try {
    accounts = await connection.getMultipleAccountsInfo(keys);
  } catch {
    return { eligible: false, reason: "state_unavailable" };
  }

  const [registrarInfo, vwrInfo, identityInfo, migrationInfo, proposalInfo] =
    accounts;
  const registrar = parseRegistrarAccount(registrarInfo, realmKey, mintKey);
  if (!registrar) {
    return { eligible: false, reason: "registrar_invalid" };
  }

  const identity = parseIdentityForRealms(identityInfo);
  if (!identity) {
    return { eligible: false, reason: "identity_missing_or_invalid" };
  }
  if (identity.owner !== voterKey.toBase58()) {
    return { eligible: false, reason: "identity_owner_mismatch" };
  }
  if (identity.trustScore < registrar.minTrustScore) {
    return {
      eligible: false,
      reason: "insufficient_trust_score",
      trustScore: identity.trustScore,
      minTrustScore: registrar.minTrustScore,
    };
  }
  const ageSeconds = nowSeconds - identity.lastVerificationTimestamp;
  if (ageSeconds < 0 || ageSeconds >= registrar.maxVerificationAge) {
    return {
      eligible: false,
      reason: "verification_expired",
      ageSeconds,
      maxVerificationAge: registrar.maxVerificationAge,
    };
  }

  let migrationSlot = null;
  let votingAtSlot = null;
  if (action === VoterWeightActionTag.CastVote) {
    const migration = parseMigrationRecordSlot(migrationInfo);
    if (migration.status === "invalid") {
      return { eligible: false, reason: "invalid_migration_record" };
    }
    migrationSlot = migration.migratedSlot;

    const proposal = parseProposalVotingAtSlot(
      proposalInfo,
      registrar.governanceProgramId,
    );
    if (proposal.status === "invalid") {
      return { eligible: false, reason: "invalid_proposal_account" };
    }
    if (proposal.status === "not_in_voting" || proposal.votingAtSlot === null) {
      return { eligible: false, reason: "proposal_not_in_voting" };
    }
    votingAtSlot = proposal.votingAtSlot;

    // Strict inequality: an identity that arrived in or after the voting start slot is refused.
    if (migrationSlot !== null && !(migrationSlot < votingAtSlot)) {
      return {
        eligible: false,
        reason: "identity_migrated_after_voting_start",
        migrationSlot,
        votingAtSlot,
      };
    }
  }

  const existingVwr = parseVoterWeightRecordAccount(vwrInfo);
  const needsCreateVoterWeightRecord = existingVwr === null;
  if (
    existingVwr !== null &&
    (existingVwr.realm !== realmKey.toBase58() ||
      existingVwr.governingTokenMint !== mintKey.toBase58() ||
      existingVwr.governingTokenOwner !== voterKey.toBase58())
  ) {
    return { eligible: false, reason: "voter_weight_record_mismatch" };
  }

  return {
    eligible: true,
    policyModel: "one eligible wallet, one vote",
    voterWeight: 1,
    needsCreateVoterWeightRecord,
    registrar,
    identity,
    migrationSlot,
    votingAtSlot,
    registrarPda: registrarPda.toBase58(),
    voterWeightRecordPda: voterWeightRecordPda.toBase58(),
    identityPda: identityPda.toBase58(),
    migrationRecordPda: migrationRecordPda.toBase58(),
  };
}

export function buildCreateVoterWeightRecordInstruction({
  realm,
  governingTokenMint,
  voter,
  payer = voter,
}) {
  const realmKey = new PublicKey(realm);
  const mintKey = new PublicKey(governingTokenMint);
  const voterKey = new PublicKey(voter);
  const payerKey = new PublicKey(payer);
  const registrarPda = deriveRegistrarPda(realmKey, mintKey);
  const voterWeightRecordPda = deriveVoterWeightRecordPda(
    realmKey,
    mintKey,
    voterKey,
  );
  const data = Buffer.alloc(40);
  CREATE_VWR_DISCRIMINATOR.copy(data, 0);
  voterKey.toBuffer().copy(data, 8);

  return new TransactionInstruction({
    programId: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
    keys: [
      { pubkey: registrarPda, isSigner: false, isWritable: false },
      { pubkey: voterWeightRecordPda, isSigner: false, isWritable: true },
      { pubkey: voterKey, isSigner: true, isWritable: false },
      { pubkey: payerKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export function buildUpdateVoterWeightRecordForActionInstruction({
  realm,
  governingTokenMint,
  voter,
  action,
  actionTarget,
}) {
  const realmKey = new PublicKey(realm);
  const mintKey = new PublicKey(governingTokenMint);
  const voterKey = new PublicKey(voter);
  const targetKey = new PublicKey(actionTarget);
  if (targetKey.equals(PublicKey.default)) {
    throw new Error("actionTarget cannot be the default pubkey");
  }
  const registrarPda = deriveRegistrarPda(realmKey, mintKey);
  const voterWeightRecordPda = deriveVoterWeightRecordPda(
    realmKey,
    mintKey,
    voterKey,
  );
  const identityPda = deriveIdentityPda(voterKey);
  const data = Buffer.alloc(41);
  UPDATE_VWR_FOR_ACTION_DISCRIMINATOR.copy(data, 0);
  data.writeUInt8(action, 8);
  targetKey.toBuffer().copy(data, 9);

  const keys = [
    { pubkey: registrarPda, isSigner: false, isWritable: false },
    { pubkey: voterWeightRecordPda, isSigner: false, isWritable: true },
    { pubkey: voterKey, isSigner: true, isWritable: false },
    { pubkey: identityPda, isSigner: false, isWritable: false },
  ];
  if (action === VoterWeightActionTag.CastVote) {
    keys.push({
      pubkey: deriveMigrationRecordPda(voterKey),
      isSigner: false,
      isWritable: false,
    });
    keys.push({
      pubkey: targetKey,
      isSigner: false,
      isWritable: false,
    });
  }

  return new TransactionInstruction({
    programId: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
    keys,
    data,
  });
}

/** Builds a synthetic spl-governance CastVote instruction referencing the VoterWeightRecord. */
export function buildSplGovernanceCastVoteInstruction({
  realm,
  governance,
  proposal,
  proposalOwnerRecord,
  voterTokenOwnerRecord,
  voter,
  governingTokenMint,
  payer = voter,
  governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
}) {
  const govProgram = new PublicKey(governanceProgramId);
  const realmKey = new PublicKey(realm);
  const proposalKey = new PublicKey(proposal);
  const voterTorKey = new PublicKey(voterTokenOwnerRecord);
  const mintKey = new PublicKey(governingTokenMint);
  const voterKey = new PublicKey(voter);
  const payerKey = new PublicKey(payer);
  const [voteRecordPda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("governance"),
      proposalKey.toBuffer(),
      voterTorKey.toBuffer(),
    ],
    govProgram,
  );
  const voterWeightRecordPda = deriveVoterWeightRecordPda(
    realmKey,
    mintKey,
    voterKey,
  );
  const choiceCount = Buffer.alloc(4);
  choiceCount.writeUInt32LE(1);
  const data = Buffer.concat([
    Buffer.from([13, 0]),
    choiceCount,
    Buffer.from([0, 100]),
  ]);

  return new TransactionInstruction({
    programId: govProgram,
    keys: [
      { pubkey: realmKey, isSigner: false, isWritable: false },
      { pubkey: new PublicKey(governance), isSigner: false, isWritable: true },
      { pubkey: proposalKey, isSigner: false, isWritable: true },
      {
        pubkey: new PublicKey(proposalOwnerRecord),
        isSigner: false,
        isWritable: true,
      },
      { pubkey: voterTorKey, isSigner: false, isWritable: true },
      { pubkey: voterKey, isSigner: true, isWritable: false },
      { pubkey: voteRecordPda, isSigner: false, isWritable: true },
      { pubkey: mintKey, isSigner: false, isWritable: false },
      { pubkey: payerKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      {
        pubkey: deriveRealmConfigPda(realmKey, govProgram),
        isSigner: false,
        isWritable: false,
      },
      { pubkey: voterWeightRecordPda, isSigner: false, isWritable: false },
    ],
    data,
  });
}

/**
 * Builds one atomic transaction:
 * `[create_voter_weight_record?, update_voter_weight_record_for_action, spl_governance_ix]`.
 */
export function buildAtomicRealmsGovernanceTransaction({
  realm,
  governingTokenMint,
  voter,
  payer = voter,
  action,
  actionTarget,
  needsCreateVoterWeightRecord,
  governanceInstruction,
  recentBlockhash = PublicKey.default.toBase58(),
}) {
  if (!governanceInstruction || !governanceInstruction.programId) {
    throw new Error("governanceInstruction is required");
  }
  const instructions = [];
  if (needsCreateVoterWeightRecord) {
    instructions.push(
      buildCreateVoterWeightRecordInstruction({
        realm,
        governingTokenMint,
        voter,
        payer,
      }),
    );
  }
  instructions.push(
    buildUpdateVoterWeightRecordForActionInstruction({
      realm,
      governingTokenMint,
      voter,
      action,
      actionTarget,
    }),
  );
  instructions.push(governanceInstruction);

  const transaction = new Transaction({
    feePayer: new PublicKey(payer),
    recentBlockhash,
  });
  transaction.add(...instructions);
  return transaction;
}

/**
 * Verifies the atomic governance transaction structure and resulting VoterWeightRecord
 * current-slot expiry (`Some(clock.slot)`) and action/target binding.
 */
export function verifyAtomicRealmsGovernanceTransaction({
  transaction,
  realm,
  governingTokenMint,
  voter,
  expectedAction,
  expectedTarget,
  executionSlot,
  governanceProgramId = SPL_GOVERNANCE_PROGRAM_ID,
  resultingVoterWeightRecord,
}) {
  const realmKey = new PublicKey(realm);
  const mintKey = new PublicKey(governingTokenMint);
  const voterKey = new PublicKey(voter);
  const targetKey = new PublicKey(expectedTarget);
  const govProgramKey = new PublicKey(governanceProgramId);
  const registrarPda = deriveRegistrarPda(realmKey, mintKey);
  const voterWeightRecordPda = deriveVoterWeightRecordPda(
    realmKey,
    mintKey,
    voterKey,
  );
  const identityPda = deriveIdentityPda(voterKey);
  const migrationRecordPda = deriveMigrationRecordPda(voterKey);

  const instructions = transaction?.instructions;
  if (!Array.isArray(instructions) || instructions.length < 2 || instructions.length > 3) {
    return { ok: false, reason: "invalid_instruction_count" };
  }

  let offset = 0;
  let includesCreateVwr = false;
  if (instructions.length === 3) {
    const createIx = instructions[0];
    if (
      !createIx.programId.equals(ENTROS_VOTER_WEIGHT_PROGRAM_ID) ||
      createIx.data.length !== 40 ||
      !createIx.data.subarray(0, 8).equals(CREATE_VWR_DISCRIMINATOR) ||
      !new PublicKey(createIx.data.subarray(8, 40)).equals(voterKey) ||
      createIx.keys.length < 5 ||
      !createIx.keys[0].pubkey.equals(registrarPda) ||
      !createIx.keys[1].pubkey.equals(voterWeightRecordPda) ||
      !createIx.keys[2].pubkey.equals(voterKey) ||
      !createIx.keys[2].isSigner
    ) {
      return { ok: false, reason: "invalid_create_voter_weight_instruction" };
    }
    includesCreateVwr = true;
    offset = 1;
  }

  const updateIx = instructions[offset];
  const governanceIx = instructions[offset + 1];

  if (
    !updateIx.programId.equals(ENTROS_VOTER_WEIGHT_PROGRAM_ID) ||
    updateIx.data.length !== 41 ||
    !updateIx.data.subarray(0, 8).equals(UPDATE_VWR_FOR_ACTION_DISCRIMINATOR)
  ) {
    return { ok: false, reason: "invalid_update_voter_weight_instruction" };
  }

  const encodedAction = updateIx.data.readUInt8(8);
  const encodedTarget = new PublicKey(updateIx.data.subarray(9, 41));
  if (encodedAction !== expectedAction) {
    return { ok: false, reason: "action_mismatch" };
  }
  if (!encodedTarget.equals(targetKey) || encodedTarget.equals(PublicKey.default)) {
    return { ok: false, reason: "target_mismatch" };
  }

  if (
    updateIx.keys.length < 4 ||
    !updateIx.keys[0].pubkey.equals(registrarPda) ||
    !updateIx.keys[1].pubkey.equals(voterWeightRecordPda) ||
    !updateIx.keys[1].isWritable ||
    !updateIx.keys[2].pubkey.equals(voterKey) ||
    !updateIx.keys[2].isSigner ||
    !updateIx.keys[3].pubkey.equals(identityPda)
  ) {
    return { ok: false, reason: "invalid_update_accounts" };
  }

  if (expectedAction === VoterWeightActionTag.CastVote) {
    if (
      updateIx.keys.length < 6 ||
      !updateIx.keys[4].pubkey.equals(migrationRecordPda) ||
      !updateIx.keys[5].pubkey.equals(targetKey)
    ) {
      return { ok: false, reason: "missing_cast_vote_evidence_accounts" };
    }
  }

  if (
    !governanceIx.programId.equals(govProgramKey) ||
    !governanceIx.keys.some((meta) => meta.pubkey.equals(voterWeightRecordPda))
  ) {
    return { ok: false, reason: "invalid_governance_instruction" };
  }

  if (resultingVoterWeightRecord !== undefined) {
    const parsed =
      resultingVoterWeightRecord?.data !== undefined
        ? parseVoterWeightRecordAccount(resultingVoterWeightRecord)
        : resultingVoterWeightRecord;
    if (!parsed) {
      return { ok: false, reason: "invalid_voter_weight_record" };
    }
    if (
      parsed.realm !== realmKey.toBase58() ||
      parsed.governingTokenMint !== mintKey.toBase58() ||
      parsed.governingTokenOwner !== voterKey.toBase58()
    ) {
      return { ok: false, reason: "voter_weight_record_mismatch" };
    }
    if (parsed.voterWeight !== 1) {
      return { ok: false, reason: "unexpected_voter_weight" };
    }
    if (
      parsed.voterWeightExpiry === null ||
      parsed.voterWeightExpiry !== executionSlot
    ) {
      return { ok: false, reason: "voter_weight_slot_expired" };
    }
    if (parsed.weightAction !== expectedAction) {
      return { ok: false, reason: "record_action_mismatch" };
    }
    if (parsed.weightActionTarget !== targetKey.toBase58()) {
      return { ok: false, reason: "record_target_mismatch" };
    }
  }

  return {
    ok: true,
    includesCreateVwr,
    voterWeightRecordPda: voterWeightRecordPda.toBase58(),
    action: encodedAction,
    target: encodedTarget.toBase58(),
    executionSlot,
  };
}
