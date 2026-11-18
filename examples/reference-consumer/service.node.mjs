import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { normalizePolicyRequest } from "@entros/verify/policy";
import { renderAgentPermitPresentation } from "@entros/verify/agent-permit";
import {
  createReferenceFixture,
  encodeVoterWeightRecord,
} from "./fixture.mjs";
import {
  ENTROS_VOTER_WEIGHT_PROGRAM_ID,
  VoterWeightActionTag,
  buildSplGovernanceCastVoteInstruction,
  preflightRealmsVoterWeight,
  verifyAtomicRealmsGovernanceTransaction,
} from "./realms-check.mjs";
import {
  ReferenceConsumerService,
  actionChallengeSigningBytes,
  checkWarmPolicyReuse,
} from "./service.mjs";
import {
  FAILURE_CLASSES,
  ReferenceTelemetryCollector,
  TELEMETRY_STAGES,
  classifyFailure,
  computePercentile,
} from "./telemetry.mjs";

const ORIGIN = "http://127.0.0.1:43211";
const ACTION = {
  kind: "grant_access",
  resource: "reference-vault",
  durationSeconds: 180,
};

function makeWallet() {
  const pair = generateKeyPairSync("ed25519");
  const pubkey = new PublicKey(
    pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
  ).toBase58();
  return {
    pubkey,
    signHex(bytes) {
      return sign(null, bytes, pair.privateKey).toString("hex");
    },
  };
}

function makeHarness({ minTrustScore = 200, requireAttestation = false } = {}) {
  const fixture = createReferenceFixture({
    nowSeconds: 1800000000,
    currentSlot: 1000,
  });
  const policy = normalizePolicyRequest({
    id: "reference-policy",
    version: 1,
    minTrustScore,
    maxVerificationAgeSeconds: 1800,
    maxEvaluationAgeSeconds: 90,
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    requireAttestation,
    cluster: "devnet",
  });
  const service = new ReferenceConsumerService({
    policy,
    agentPolicy: policy,
    actionAudience: `${ORIGIN}/action-settlements`,
    agentAudience: `${ORIGIN}/agent-permit-settlements`,
    allowedOrigins: [ORIGIN],
    connection: fixture.connection,
    nowSeconds: () => fixture.state.now,
  });
  return { fixture, policy, service };
}

test("warm policy reuse accepts valid evidence at 0 SOL and preserves original verifiedAt", async () => {
  const { fixture, service } = makeHarness({
    minTrustScore: 200,
    requireAttestation: true,
  });
  const wallet = makeWallet();
  const originalVerifiedAt = fixture.state.now - 900;
  fixture.updateWallet(wallet.pubkey, {
    trustScore: 250,
    verifiedAt: originalVerifiedAt,
    slot: 990,
    attestation: { status: "present", expiresAt: fixture.state.now + 7200 },
  });

  const reused = await service.checkWarmPolicy({
    walletPubkey: wallet.pubkey,
    origin: ORIGIN,
  });

  assert.equal(reused.ok, true);
  assert.equal(reused.status, "reused");
  assert.equal(reused.feeLamports, 0);
  assert.equal(reused.captureRounds, 0);
  assert.equal(reused.verifiedAt, originalVerifiedAt);
  assert.equal(reused.policy.evidence_timestamp, originalVerifiedAt);
  assert.equal(reused.policy.evaluated_age_seconds, 900);
  assert.notEqual(reused.attestationPda, null);
});

test("warm policy reuse routes stale, below-floor, reset, missing-attestation, and absent wallets to capture", async () => {
  const { fixture, service } = makeHarness({
    minTrustScore: 200,
    requireAttestation: true,
  });

  const absent = makeWallet();
  assert.equal(
    (await service.checkWarmPolicy({ walletPubkey: absent.pubkey, origin: ORIGIN }))
      .reason,
    "evidence_not_found",
  );

  const stale = makeWallet();
  fixture.updateWallet(stale.pubkey, {
    trustScore: 250,
    verifiedAt: fixture.state.now - 1800,
    slot: 980,
    attestation: { status: "present", expiresAt: fixture.state.now + 3600 },
  });
  assert.equal(
    (await service.checkWarmPolicy({ walletPubkey: stale.pubkey, origin: ORIGIN }))
      .reason,
    "verification_stale",
  );

  const lowScore = makeWallet();
  fixture.updateWallet(lowScore.pubkey, {
    trustScore: 150,
    verifiedAt: fixture.state.now - 60,
    slot: 985,
    attestation: { status: "present", expiresAt: fixture.state.now + 3600 },
  });
  assert.equal(
    (
      await service.checkWarmPolicy({
        walletPubkey: lowScore.pubkey,
        origin: ORIGIN,
      })
    ).reason,
    "score_below_minimum",
  );

  const noAttestation = makeWallet();
  fixture.updateWallet(noAttestation.pubkey, {
    trustScore: 250,
    verifiedAt: fixture.state.now - 60,
    slot: 986,
    attestation: { status: "missing" },
  });
  assert.equal(
    (
      await service.checkWarmPolicy({
        walletPubkey: noAttestation.pubkey,
        origin: ORIGIN,
      })
    ).reason,
    "attestation_required",
  );

  const resetWallet = makeWallet();
  fixture.updateWallet(resetWallet.pubkey, {
    trustScore: 250,
    verifiedAt: fixture.state.now - 60,
    slot: 987,
    attestation: { status: "present", expiresAt: fixture.state.now + 3600 },
  });
  fixture.resetWallet(resetWallet.pubkey, {
    resetAt: fixture.state.now - 10,
    slot: 995,
  });
  const afterReset = await service.checkWarmPolicy({
    walletPubkey: resetWallet.pubkey,
    origin: ORIGIN,
  });
  assert.equal(afterReset.status, "needs_capture");
  assert.ok(
    afterReset.reason === "evidence_not_found" ||
      afterReset.reason === "invalid_evidence",
  );

  const legacyMissing = await checkWarmPolicyReuse({
    walletPubkey: noAttestation.pubkey,
    connection: fixture.connection,
    nowSeconds: fixture.state.now,
    requireLegacyAttestation: true,
  });
  assert.equal(legacyMissing.status, "needs_capture");
  assert.equal(legacyMissing.reason, "attestation_required");

  fixture.state.rpcUnavailable = true;
  const rpcDown = await service.checkWarmPolicy({
    walletPubkey: noAttestation.pubkey,
    origin: ORIGIN,
  });
  assert.equal(rpcDown.status, "needs_capture");
  assert.equal(rpcDown.reason, "state_unavailable");
  fixture.state.rpcUnavailable = false;
});

test("protected action supports cold mint, returning update, post-reset refusal, rebaseline acceptance, origin refusal, and concurrent replay defense", async () => {
  const { fixture, service } = makeHarness({
    minTrustScore: 0,
    requireAttestation: false,
  });
  const wallet = makeWallet();

  // Origin allowlist refusal
  const wrongOrigin = service.issueActionChallenge({
    wallet: wallet.pubkey,
    action: ACTION,
    origin: "https://attacker.example",
  });
  assert.equal(wrongOrigin.ok, false);
  assert.equal(wrongOrigin.reason, "origin_invalid");

  // Cold mint accepted under minTrustScore=0
  const mintTx = fixture.mintWallet(wallet.pubkey, {
    verifiedAt: fixture.state.now - 20,
    slot: 980,
    attestation: { status: "missing" },
  });
  const mintChallenge = service.issueActionChallenge({
    wallet: wallet.pubkey,
    action: ACTION,
    origin: ORIGIN,
  });
  const mintRes = await service.settleAction({
    challenge: mintChallenge.challenge,
    signature: wallet.signHex(
      actionChallengeSigningBytes(mintChallenge.challenge),
    ),
    verifiedTransaction: mintTx.signature,
    origin: ORIGIN,
  });
  assert.equal(mintRes.ok, true);
  assert.equal(mintRes.action.transactionKind, "mint");

  // Returning update + concurrent duplicate settlement race
  const updateTx = fixture.updateWallet(wallet.pubkey, {
    trustScore: 300,
    verifiedAt: fixture.state.now - 10,
    slot: 985,
  });
  const raceChallenge = service.issueActionChallenge({
    wallet: wallet.pubkey,
    action: ACTION,
    origin: ORIGIN,
  });
  const racePayload = {
    challenge: raceChallenge.challenge,
    signature: wallet.signHex(
      actionChallengeSigningBytes(raceChallenge.challenge),
    ),
    verifiedTransaction: updateTx.signature,
    origin: ORIGIN,
  };
  const [raceA, raceB] = await Promise.all([
    service.settleAction(racePayload),
    service.settleAction(racePayload),
  ]);
  const wins = [raceA, raceB].filter((item) => item.ok);
  const losses = [raceA, raceB].filter((item) => !item.ok);
  assert.equal(wins.length, 1);
  assert.equal(losses.length, 1);
  assert.equal(losses[0].reason, "nonce_unavailable");

  // Post-reset refuses both reset tx and prior update tx
  const resetTx = fixture.resetWallet(wallet.pubkey, {
    resetAt: fixture.state.now - 5,
    slot: 990,
  });
  const resetChallenge = service.issueActionChallenge({
    wallet: wallet.pubkey,
    action: ACTION,
    origin: ORIGIN,
  });
  const resetReject = await service.settleAction({
    challenge: resetChallenge.challenge,
    signature: wallet.signHex(
      actionChallengeSigningBytes(resetChallenge.challenge),
    ),
    verifiedTransaction: resetTx.signature,
    origin: ORIGIN,
  });
  assert.equal(resetReject.ok, false);
  assert.equal(resetReject.reason, "invalid_evidence");

  const stalePreResetReject = await service.settleAction({
    challenge: resetChallenge.challenge,
    signature: wallet.signHex(
      actionChallengeSigningBytes(resetChallenge.challenge),
    ),
    verifiedTransaction: updateTx.signature,
    origin: ORIGIN,
  });
  assert.equal(stalePreResetReject.ok, false);
  assert.equal(stalePreResetReject.reason, "invalid_evidence");

  // Client-supplied evidence and policy overrides are ignored during settlement.
  const lowWallet = makeWallet();
  const lowFixture = makeHarness({ minTrustScore: 200 });
  const lowTx = lowFixture.fixture.updateWallet(lowWallet.pubkey, {
    trustScore: 50,
    verifiedAt: lowFixture.fixture.state.now - 10,
    slot: 990,
  });
  const lowChallenge = lowFixture.service.issueActionChallenge({
    wallet: lowWallet.pubkey,
    action: ACTION,
    origin: ORIGIN,
  });
  const forgedClientEvidence = await lowFixture.service.settleAction({
    challenge: lowChallenge.challenge,
    signature: lowWallet.signHex(
      actionChallengeSigningBytes(lowChallenge.challenge),
    ),
    verifiedTransaction: lowTx.signature,
    origin: ORIGIN,
    clientEvidence: { decision: "allow", trustScore: 10000 },
    policy: { minTrustScore: 0 },
  });
  assert.equal(forgedClientEvidence.ok, false);
  assert.equal(forgedClientEvidence.reason, "score_below_minimum");

  // Rebaseline accepted after reset
  const rebaselineTx = fixture.rebaselineWallet(wallet.pubkey, {
    trustScore: 220,
    verifiedAt: fixture.state.now - 2,
    slot: 995,
  });
  const rebaselineRes = await service.settleAction({
    challenge: resetChallenge.challenge,
    signature: wallet.signHex(
      actionChallengeSigningBytes(resetChallenge.challenge),
    ),
    verifiedTransaction: rebaselineTx.signature,
    origin: ORIGIN,
  });
  assert.equal(rebaselineRes.ok, true);
  assert.equal(rebaselineRes.action.transactionKind, "rebaseline");
});

test("Agent Operator Permit enforces 0-RPC precheck, replay, copied permit, owner_changed, and agent_wallet_stale", async () => {
  const { fixture, service } = makeHarness({ minTrustScore: 200 });
  const owner = makeWallet();
  const agentAsset = makeWallet().pubkey;
  const agentWallet = makeWallet();
  const otherAgent = makeWallet();
  const buyer = makeWallet();

  const updateTx = fixture.updateWallet(owner.pubkey, {
    trustScore: 260,
    verifiedAt: fixture.state.now - 30,
    slot: 985,
  });
  fixture.registerAgent({
    agent: agentAsset,
    owner: owner.pubkey,
    agentWallet: agentWallet.pubkey,
  });

  const signPermit = (permit, signerOwner = owner, signerAgent = agentWallet) => ({
    version: 1,
    nonce: permit.nonce,
    operatorSignature: signerOwner.signHex(Buffer.from(permit.message, "utf8")),
    presentationSignature: signerAgent.signHex(
      Buffer.from(renderAgentPermitPresentation(permit.permitId), "utf8"),
    ),
    verifiedTransaction: updateTx.signature,
  });

  // 1. Valid settlement + concurrent duplicate replay refusal
  const p1 = await service.requestAgentPermit({
    agent: agentAsset,
    action: ACTION,
    origin: ORIGIN,
  });
  assert.equal(p1.ok, true);
  assert.equal(p1.subject, owner.pubkey);
  assert.equal(p1.actor, agentWallet.pubkey);

  const b1 = signPermit(p1);
  const [s1, s2] = await Promise.all([
    service.settleAgentPermit(b1, { origin: ORIGIN }),
    service.settleAgentPermit(b1, { origin: ORIGIN }),
  ]);
  assert.equal([s1, s2].filter((r) => r.ok).length, 1);
  assert.equal(
    [s1, s2].find((r) => !r.ok).reason,
    "nonce_unavailable",
  );

  // 2. 0-RPC precheck refusal on forged operator signature and copied presentation
  const p2 = await service.requestAgentPermit({
    agent: agentAsset,
    action: ACTION,
    origin: ORIGIN,
  });
  const readsBeforeSig = fixture.reads.length;
  const badOp = await service.settleAgentPermit(
    signPermit(p2, buyer, agentWallet),
    { origin: ORIGIN },
  );
  assert.equal(badOp.reason, "invalid_signature");
  assert.equal(fixture.reads.length, readsBeforeSig);

  const copied = await service.settleAgentPermit(
    signPermit(p2, owner, otherAgent),
    { origin: ORIGIN },
  );
  assert.equal(copied.reason, "invalid_presentation");
  assert.equal(fixture.reads.length, readsBeforeSig);

  // 3. 0-RPC precheck refusal on expired permit
  const pExp = await service.requestAgentPermit({
    agent: agentAsset,
    action: ACTION,
    origin: ORIGIN,
  });
  const expBundle = signPermit(pExp);
  fixture.state.now += 601;
  const readsBeforeExp = fixture.reads.length;
  const expired = await service.settleAgentPermit(expBundle, { origin: ORIGIN });
  assert.equal(expired.reason, "permit_expired");
  assert.equal(fixture.reads.length, readsBeforeExp);
  fixture.state.now -= 601;

  // 4. Stale agent wallet cache refusal (owner matches operator, cachedOwner drifted)
  const pStale = await service.requestAgentPermit({
    agent: agentAsset,
    action: ACTION,
    origin: ORIGIN,
  });
  const staleBundle = signPermit(pStale);
  fixture.setAgentCachedOwner(agentAsset, buyer.pubkey);
  const staleRes = await service.settleAgentPermit(staleBundle, {
    origin: ORIGIN,
  });
  assert.equal(staleRes.reason, "agent_wallet_stale");

  // Restore cache, then test direct transfer -> owner_changed
  fixture.bindAgentWallet(agentAsset, agentWallet.pubkey);
  const pTransfer = await service.requestAgentPermit({
    agent: agentAsset,
    action: ACTION,
    origin: ORIGIN,
  });
  const transferBundle = signPermit(pTransfer);
  fixture.transferAgentDirect(agentAsset, buyer.pubkey);
  const moved = await service.settleAgentPermit(transferBundle, {
    origin: ORIGIN,
  });
  assert.equal(moved.reason, "owner_changed");
});

test("Realms pre-flight and atomic transaction verification enforce score, age, 57-byte MigrationRecord slot, and Some(clock.slot) expiry", async () => {
  const { fixture, service } = makeHarness();
  const realm = makeWallet().pubkey;
  const governingTokenMint = makeWallet().pubkey;
  const governance = makeWallet().pubkey;
  const proposal = makeWallet().pubkey;
  const draftProposal = makeWallet().pubkey;
  const proposalOwnerRecord = makeWallet().pubkey;
  const voterTor = makeWallet().pubkey;

  fixture.setRegistrar({
    realm,
    governingTokenMint,
    minTrustScore: 200,
    maxVerificationAge: 3600,
  });
  fixture.setProposal({
    proposal,
    governance,
    governingTokenMint,
    tokenOwnerRecord: proposalOwnerRecord,
    state: 2,
    votingAtSlot: 950,
  });
  fixture.setProposal({
    proposal: draftProposal,
    governance,
    governingTokenMint,
    tokenOwnerRecord: proposalOwnerRecord,
    state: 0,
    votingAt: null,
    votingAtSlot: null,
  });

  // Cold voter (no VWR yet) -> needsCreateVoterWeightRecord = true, 3-ix atomic tx
  const coldVoter = makeWallet();
  fixture.updateWallet(coldVoter.pubkey, {
    trustScore: 250,
    verifiedAt: fixture.state.now - 100,
    slot: 990,
  });
  const coldPre = await service.preflightRealms({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    origin: ORIGIN,
  });
  assert.equal(coldPre.eligible, true);
  assert.equal(coldPre.needsCreateVoterWeightRecord, true);

  const castVoteIx = buildSplGovernanceCastVoteInstruction({
    realm,
    governance,
    proposal,
    proposalOwnerRecord,
    voterTokenOwnerRecord: voterTor,
    voter: coldVoter.pubkey,
    governingTokenMint,
  });
  const coldTx = service.buildAtomicRealmsTransaction({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    needsCreateVoterWeightRecord: true,
    governanceInstruction: castVoteIx,
  });
  assert.equal(coldTx.instructions.length, 3);

  const executionSlot = 1000;
  const validVwr = {
    data: encodeVoterWeightRecord({
      realm,
      governingTokenMint,
      governingTokenOwner: coldVoter.pubkey,
      voterWeight: 1,
      voterWeightExpiry: executionSlot,
      weightAction: VoterWeightActionTag.CastVote,
      weightActionTarget: proposal,
    }),
    owner: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
    executable: false,
  };
  assert.equal(
    verifyAtomicRealmsGovernanceTransaction({
      transaction: coldTx,
      realm,
      governingTokenMint,
      voter: coldVoter.pubkey,
      expectedAction: VoterWeightActionTag.CastVote,
      expectedTarget: proposal,
      executionSlot,
      resultingVoterWeightRecord: validVwr,
    }).ok,
    true,
  );

  // Cross-slot expiry mismatch is rejected
  const staleSlotCheck = verifyAtomicRealmsGovernanceTransaction({
    transaction: coldTx,
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    expectedAction: VoterWeightActionTag.CastVote,
    expectedTarget: proposal,
    executionSlot: executionSlot + 1,
    resultingVoterWeightRecord: validVwr,
  });
  assert.equal(staleSlotCheck.ok, false);
  assert.equal(staleSlotCheck.reason, "voter_weight_slot_expired");

  // Wrong target is rejected
  const wrongTarget = verifyAtomicRealmsGovernanceTransaction({
    transaction: coldTx,
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    expectedAction: VoterWeightActionTag.CastVote,
    expectedTarget: draftProposal,
    executionSlot,
    resultingVoterWeightRecord: validVwr,
  });
  assert.equal(wrongTarget.ok, false);
  assert.equal(wrongTarget.reason, "target_mismatch");

  // Warm voter (existing VWR) -> needsCreateVoterWeightRecord = false, 2-ix atomic tx
  fixture.setVoterWeightRecord({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
  });
  const warmPre = await service.preflightRealms({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    origin: ORIGIN,
  });
  assert.equal(warmPre.eligible, true);
  assert.equal(warmPre.needsCreateVoterWeightRecord, false);

  const warmTx = service.buildAtomicRealmsTransaction({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    needsCreateVoterWeightRecord: false,
    governanceInstruction: castVoteIx,
  });
  assert.equal(warmTx.instructions.length, 2);
  assert.equal(
    verifyAtomicRealmsGovernanceTransaction({
      transaction: warmTx,
      realm,
      governingTokenMint,
      voter: coldVoter.pubkey,
      expectedAction: VoterWeightActionTag.CastVote,
      expectedTarget: proposal,
      executionSlot,
      resultingVoterWeightRecord: validVwr,
    }).ok,
    true,
  );

  // Pre-voting migration (migratedSlot 949 < votingAtSlot 950) allowed
  const earlyMigrated = makeWallet();
  fixture.updateWallet(earlyMigrated.pubkey, {
    trustScore: 240,
    verifiedAt: fixture.state.now - 50,
    slot: 980,
  });
  fixture.migrateWallet(earlyMigrated.pubkey, {
    previousWallet: makeWallet().pubkey,
    migratedAt: fixture.state.now - 500,
    migratedSlot: 949,
  });
  const earlyPre = await preflightRealmsVoterWeight({
    connection: fixture.connection,
    realm,
    governingTokenMint,
    voter: earlyMigrated.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    nowSeconds: fixture.state.now,
  });
  assert.equal(earlyPre.eligible, true);
  assert.equal(earlyPre.migrationSlot, 949);

  // Same-slot migration (migratedSlot 950 === votingAtSlot 950) refused
  const sameSlotMigrated = makeWallet();
  fixture.updateWallet(sameSlotMigrated.pubkey, {
    trustScore: 240,
    verifiedAt: fixture.state.now - 50,
    slot: 980,
  });
  fixture.migrateWallet(sameSlotMigrated.pubkey, {
    previousWallet: makeWallet().pubkey,
    migratedAt: fixture.state.now - 200,
    migratedSlot: 950,
  });
  const sameSlotPre = await preflightRealmsVoterWeight({
    connection: fixture.connection,
    realm,
    governingTokenMint,
    voter: sameSlotMigrated.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    nowSeconds: fixture.state.now,
  });
  assert.equal(sameSlotPre.eligible, false);
  assert.equal(sameSlotPre.reason, "identity_migrated_after_voting_start");

  // Corrupted MigrationRecord discriminator refused
  const badMigration = makeWallet();
  fixture.updateWallet(badMigration.pubkey, {
    trustScore: 240,
    verifiedAt: fixture.state.now - 50,
    slot: 980,
  });
  fixture.migrateWallet(badMigration.pubkey, {
    previousWallet: makeWallet().pubkey,
    migratedAt: fixture.state.now - 500,
    migratedSlot: 900,
    corrupted: true,
  });
  const corruptPre = await preflightRealmsVoterWeight({
    connection: fixture.connection,
    realm,
    governingTokenMint,
    voter: badMigration.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    nowSeconds: fixture.state.now,
  });
  assert.equal(corruptPre.eligible, false);
  assert.equal(corruptPre.reason, "invalid_migration_record");

  // Insufficient trust score, expired verification, and draft proposal refused
  const lowVoter = makeWallet();
  fixture.updateWallet(lowVoter.pubkey, {
    trustScore: 100,
    verifiedAt: fixture.state.now - 50,
    slot: 980,
  });
  assert.equal(
    (
      await preflightRealmsVoterWeight({
        connection: fixture.connection,
        realm,
        governingTokenMint,
        voter: lowVoter.pubkey,
        action: VoterWeightActionTag.CastVote,
        actionTarget: proposal,
        nowSeconds: fixture.state.now,
      })
    ).reason,
    "insufficient_trust_score",
  );

  const staleVoter = makeWallet();
  fixture.updateWallet(staleVoter.pubkey, {
    trustScore: 250,
    verifiedAt: fixture.state.now - 3600,
    slot: 980,
  });
  assert.equal(
    (
      await preflightRealmsVoterWeight({
        connection: fixture.connection,
        realm,
        governingTokenMint,
        voter: staleVoter.pubkey,
        action: VoterWeightActionTag.CastVote,
        actionTarget: proposal,
        nowSeconds: fixture.state.now,
      })
    ).reason,
    "verification_expired",
  );

  assert.equal(
    (
      await preflightRealmsVoterWeight({
        connection: fixture.connection,
        realm,
        governingTokenMint,
        voter: coldVoter.pubkey,
        action: VoterWeightActionTag.CastVote,
        actionTarget: draftProposal,
        nowSeconds: fixture.state.now,
      })
    ).reason,
    "proposal_not_in_voting",
  );

  // Wrong governance program in final instruction rejected
  const fakeGovIx = new TransactionInstruction({
    programId: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
    keys: [],
    data: Buffer.alloc(0),
  });
  const badGovTx = service.buildAtomicRealmsTransaction({
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CastVote,
    actionTarget: proposal,
    needsCreateVoterWeightRecord: false,
    governanceInstruction: fakeGovIx,
  });
  assert.equal(
    verifyAtomicRealmsGovernanceTransaction({
      transaction: badGovTx,
      realm,
      governingTokenMint,
      voter: coldVoter.pubkey,
      expectedAction: VoterWeightActionTag.CastVote,
      expectedTarget: proposal,
      executionSlot,
    }).reason,
    "invalid_governance_instruction",
  );

  // Non-CastVote action (CreateProposal) uses 1 remaining account (IdentityState only)
  const createProposalPre = await preflightRealmsVoterWeight({
    connection: fixture.connection,
    realm,
    governingTokenMint,
    voter: coldVoter.pubkey,
    action: VoterWeightActionTag.CreateProposal,
    actionTarget: governance,
    nowSeconds: fixture.state.now,
  });
  assert.equal(createProposalPre.eligible, true);
  assert.equal(createProposalPre.votingAtSlot, null);

  // VoterWeightRecord belonging to a different voter is rejected
  const otherVoterVwr = {
    data: encodeVoterWeightRecord({
      realm,
      governingTokenMint,
      governingTokenOwner: makeWallet().pubkey,
      voterWeight: 1,
      voterWeightExpiry: executionSlot,
      weightAction: VoterWeightActionTag.CastVote,
      weightActionTarget: proposal,
    }),
    owner: ENTROS_VOTER_WEIGHT_PROGRAM_ID,
    executable: false,
  };
  assert.equal(
    verifyAtomicRealmsGovernanceTransaction({
      transaction: warmTx,
      realm,
      governingTokenMint,
      voter: coldVoter.pubkey,
      expectedAction: VoterWeightActionTag.CastVote,
      expectedTarget: proposal,
      executionSlot,
      resultingVoterWeightRecord: otherVoterVwr,
    }).reason,
    "voter_weight_record_mismatch",
  );
});

test("telemetry summarizes cold vs warm p50/p95 stage latencies and all 10 failure/abandonment classes", () => {
  assert.deepEqual(TELEMETRY_STAGES, [
    "permissions",
    "capture",
    "validation",
    "proof",
    "walletPrompts",
    "confirmation",
    "return",
  ]);
  assert.deepEqual(FAILURE_CLASSES, [
    "permissions",
    "unsupported_device",
    "capture",
    "validation",
    "stale_baseline",
    "unavailable_service",
    "funding",
    "wallet_rejection",
    "confirmation",
    "return",
  ]);

  assert.equal(computePercentile([], 50), null);
  assert.equal(computePercentile([10, 20, 30, 40, 50], 50), 30);
  assert.equal(computePercentile([10, 20, 30, 40, 50], 95), 50);

  assert.equal(classifyFailure({ reason: "microphone_denied" }), "permissions");
  assert.equal(classifyFailure({ reason: "no_microphone" }), "unsupported_device");
  assert.equal(classifyFailure({ reason: "capture_aborted" }), "capture");
  assert.equal(classifyFailure({ reason: "score_below_minimum" }), "validation");
  assert.equal(classifyFailure({ reason: "drift_too_high" }), "stale_baseline");
  assert.equal(classifyFailure({ reason: "rpc_unavailable" }), "unavailable_service");
  assert.equal(classifyFailure({ reason: "insufficient_sol" }), "funding");
  assert.equal(classifyFailure({ reason: "wallet_rejected" }), "wallet_rejection");
  assert.equal(classifyFailure({ reason: "tx_expired" }), "confirmation");
  assert.equal(classifyFailure({ reason: "popup_blocked" }), "return");

  const collector = new ReferenceTelemetryCollector();
  for (const captureMs of [12000, 14000, 16000, 18000, 25000]) {
    collector.recordRun({
      mode: "cold",
      outcome: "completed",
      stages: {
        permissions: 600,
        capture: captureMs,
        validation: 1800,
        proof: 1100,
        walletPrompts: 3000,
        confirmation: 1900,
        return: 200,
      },
    });
  }
  collector.recordRun({
    mode: "warm",
    outcome: "completed",
    stages: {
      permissions: 0,
      capture: 0,
      validation: 150,
      proof: 0,
      walletPrompts: 0,
      confirmation: 0,
      return: 80,
    },
  });
  collector.recordRun({
    mode: "cold",
    outcome: "failed",
    reason: "drift_too_high",
    stages: { permissions: 500, capture: 15000, validation: 1500 },
  });
  collector.recordRun({
    mode: "cold",
    outcome: "abandoned",
    reason: "user_canceled",
    stages: { permissions: 400, capture: 3500 },
  });

  const summary = collector.summarize();
  assert.equal(summary.totalRuns, 8);
  assert.equal(summary.cold.completed, 5);
  assert.equal(summary.cold.failed, 1);
  assert.equal(summary.cold.abandoned, 1);
  assert.equal(summary.cold.stages.capture.count, 7);
  assert.equal(summary.cold.stages.capture.p50Ms, 15000);
  assert.equal(summary.cold.stages.capture.p95Ms, 25000);
  assert.equal(summary.warm.stages.capture.p50Ms, 0);
  assert.equal(summary.warm.stages.validation.p50Ms, 150);
  assert.equal(summary.failuresByClass.stale_baseline, 1);
  assert.equal(summary.abandonmentsByClass.wallet_rejection, 1);

  assert.throws(
    () =>
      collector.recordRun({
        mode: "cold",
        outcome: "completed",
        audio: [0.1, 0.2],
        stages: {},
      }),
    /raw field/,
  );
});
