import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { normalizePolicyRequest } from "@entros/verify/policy";
import { renderAgentPermitPresentation } from "@entros/verify/agent-permit";
import {
  createReferenceFixture,
  encodeVoterWeightRecord,
} from "./fixture.mjs";
import {
  VoterWeightActionTag,
  buildSplGovernanceCastVoteInstruction,
} from "./realms-check.mjs";
import {
  ReferenceConsumerService,
  actionChallengeSigningBytes,
} from "./service.mjs";

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

const ORIGIN = "http://127.0.0.1:43211";
const ACTION = {
  kind: "grant_access",
  resource: "reference-vault",
  durationSeconds: 120,
};

const fixture = createReferenceFixture({ nowSeconds: 1800000000, currentSlot: 1000 });
const policy = normalizePolicyRequest({
  id: "reference-consumer",
  version: 1,
  minTrustScore: 200,
  maxVerificationAgeSeconds: 1800,
  maxEvaluationAgeSeconds: 90,
  requiredAssurance: "browser_unattested",
  uniquenessRequirement: "allow_unmeasured",
  requireAttestation: true,
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

// 1. Warm policy reuse before capture (0 SOL, zero rounds, preserved original verifiedAt)
const human = makeWallet();
const originalVerifiedAt = fixture.state.now - 600;
const updateTx = fixture.updateWallet(human.pubkey, {
  trustScore: 260,
  verifiedAt: originalVerifiedAt,
  slot: 990,
  attestation: { status: "present", expiresAt: fixture.state.now + 7200 },
});
const warmReused = await service.checkWarmPolicy({
  walletPubkey: human.pubkey,
  origin: ORIGIN,
});
assert.equal(warmReused.ok, true);
assert.equal(warmReused.status, "reused");
assert.equal(warmReused.feeLamports, 0);
assert.equal(warmReused.captureRounds, 0);
assert.equal(warmReused.verifiedAt, originalVerifiedAt);

// Stale / below-floor / missing-attestation route to capture
const lowScoreWallet = makeWallet();
fixture.updateWallet(lowScoreWallet.pubkey, {
  trustScore: 50,
  verifiedAt: fixture.state.now - 30,
  slot: 992,
});
const warmLowScore = await service.checkWarmPolicy({
  walletPubkey: lowScoreWallet.pubkey,
  origin: ORIGIN,
});
assert.equal(warmLowScore.status, "needs_capture");
assert.equal(warmLowScore.reason, "score_below_minimum");

// 2. Protected action lifecycle: returning update, replay refusal, origin refusal, reset refusal, rebaseline acceptance
const badOrigin = service.issueActionChallenge({
  wallet: human.pubkey,
  action: ACTION,
  origin: "https://untrusted.example",
});
assert.equal(badOrigin.reason, "origin_invalid");

const challengeRes = service.issueActionChallenge({
  wallet: human.pubkey,
  action: ACTION,
  origin: ORIGIN,
});
assert.equal(challengeRes.ok, true);
const actionPayload = {
  challenge: challengeRes.challenge,
  signature: human.signHex(actionChallengeSigningBytes(challengeRes.challenge)),
  verifiedTransaction: updateTx.signature,
  origin: ORIGIN,
};
const settled = await service.settleAction(actionPayload);
assert.equal(settled.ok, true);
assert.equal(settled.action.verifiedAt, originalVerifiedAt);

const replayedAction = await service.settleAction(actionPayload);
assert.equal(replayedAction.reason, "nonce_unavailable");

const resetTx = fixture.resetWallet(human.pubkey, {
  resetAt: fixture.state.now - 5,
  slot: 995,
});
const postResetChallenge = service.issueActionChallenge({
  wallet: human.pubkey,
  action: ACTION,
  origin: ORIGIN,
});
const postResetSettled = await service.settleAction({
  challenge: postResetChallenge.challenge,
  signature: human.signHex(actionChallengeSigningBytes(postResetChallenge.challenge)),
  verifiedTransaction: resetTx.signature,
  origin: ORIGIN,
});
assert.equal(postResetSettled.ok, false);
assert.equal(postResetSettled.reason, "invalid_evidence");

const rebaselineTx = fixture.rebaselineWallet(human.pubkey, {
  trustScore: 260,
  verifiedAt: fixture.state.now - 2,
  slot: 998,
  attestation: { status: "present", expiresAt: fixture.state.now + 7200 },
});
const rebaselineChallenge = service.issueActionChallenge({
  wallet: human.pubkey,
  action: ACTION,
  origin: ORIGIN,
});
const rebaselineSettled = await service.settleAction({
  challenge: rebaselineChallenge.challenge,
  signature: human.signHex(
    actionChallengeSigningBytes(rebaselineChallenge.challenge),
  ),
  verifiedTransaction: rebaselineTx.signature,
  origin: ORIGIN,
});
assert.equal(rebaselineSettled.ok, true);
assert.equal(rebaselineSettled.action.transactionKind, "rebaseline");

// 3. Agent Operator Permit pause-and-approve (subject owner + actor agent)
const agentAsset = makeWallet().pubkey;
const agentWallet = makeWallet();
const thiefWallet = makeWallet();
const buyerWallet = makeWallet();
fixture.registerAgent({
  agent: agentAsset,
  owner: human.pubkey,
  agentWallet: agentWallet.pubkey,
});

const permit1 = await service.requestAgentPermit({
  agent: agentAsset,
  action: ACTION,
  origin: ORIGIN,
});
assert.equal(permit1.ok, true);
assert.equal(permit1.status, "paused_for_owner_approval");
assert.equal(permit1.subject, human.pubkey);
assert.equal(permit1.actor, agentWallet.pubkey);

const makeBundle = (permit, presenter = agentWallet) => ({
  version: 1,
  nonce: permit.nonce,
  operatorSignature: human.signHex(Buffer.from(permit.message, "utf8")),
  presentationSignature: presenter.signHex(
    Buffer.from(renderAgentPermitPresentation(permit.permitId), "utf8"),
  ),
  verifiedTransaction: rebaselineTx.signature,
});

const permitAllowed = await service.settleAgentPermit(makeBundle(permit1), {
  origin: ORIGIN,
});
assert.equal(permitAllowed.ok, true);

const permitReplayed = await service.settleAgentPermit(makeBundle(permit1), {
  origin: ORIGIN,
});
assert.equal(permitReplayed.reason, "nonce_unavailable");

const permit2 = await service.requestAgentPermit({
  agent: agentAsset,
  action: ACTION,
  origin: ORIGIN,
});
const copiedPermit = await service.settleAgentPermit(
  makeBundle(permit2, thiefWallet),
  { origin: ORIGIN },
);
assert.equal(copiedPermit.reason, "invalid_presentation");

const permit3 = await service.requestAgentPermit({
  agent: agentAsset,
  action: ACTION,
  origin: ORIGIN,
});
const heldBundle = makeBundle(permit3);
fixture.setAgentCachedOwner(agentAsset, buyerWallet.pubkey);
const staleWallet = await service.settleAgentPermit(heldBundle, {
  origin: ORIGIN,
});
assert.equal(staleWallet.reason, "agent_wallet_stale");

fixture.transferAgentDirect(agentAsset, buyerWallet.pubkey);
const afterTransfer = await service.settleAgentPermit(heldBundle, {
  origin: ORIGIN,
});
assert.equal(afterTransfer.reason, "owner_changed");

fixture.bindAgentWallet(agentAsset, agentWallet.pubkey);
fixture.transferAgentDirect(agentAsset, human.pubkey);
fixture.bindAgentWallet(agentAsset, agentWallet.pubkey);
const permitExpiredReq = await service.requestAgentPermit({
  agent: agentAsset,
  action: ACTION,
  origin: ORIGIN,
});
const expiredBundle = makeBundle(permitExpiredReq);
fixture.state.now += 601;
const readsBeforeExpired = fixture.reads.length;
const expiredPermit = await service.settleAgentPermit(expiredBundle, {
  origin: ORIGIN,
});
const expiredPrecheckRpcReads = fixture.reads.length - readsBeforeExpired;
assert.equal(expiredPermit.reason, "permit_expired");
assert.equal(expiredPrecheckRpcReads, 0);
fixture.state.now -= 601;

// 4. Realms voter-weight pre-flight and atomic governance transaction verification
const realm = makeWallet().pubkey;
const governingTokenMint = makeWallet().pubkey;
const governance = makeWallet().pubkey;
const proposal = makeWallet().pubkey;
const proposalOwnerRecord = makeWallet().pubkey;
const voterTokenOwnerRecord = makeWallet().pubkey;

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

const preflightEligible = await service.preflightRealms({
  realm,
  governingTokenMint,
  voter: human.pubkey,
  action: VoterWeightActionTag.CastVote,
  actionTarget: proposal,
  origin: ORIGIN,
});
assert.equal(preflightEligible.eligible, true);
assert.equal(preflightEligible.policyModel, "one eligible wallet, one vote");
assert.equal(preflightEligible.needsCreateVoterWeightRecord, true);

const castVoteIx = buildSplGovernanceCastVoteInstruction({
  realm,
  governance,
  proposal,
  proposalOwnerRecord,
  voterTokenOwnerRecord,
  voter: human.pubkey,
  governingTokenMint,
});
const atomicTx = service.buildAtomicRealmsTransaction({
  realm,
  governingTokenMint,
  voter: human.pubkey,
  action: VoterWeightActionTag.CastVote,
  actionTarget: proposal,
  needsCreateVoterWeightRecord: preflightEligible.needsCreateVoterWeightRecord,
  governanceInstruction: castVoteIx,
});
const currentSlot = await fixture.connection.getSlot();
const resultingVwr = {
  data: encodeVoterWeightRecord({
    realm,
    governingTokenMint,
    governingTokenOwner: human.pubkey,
    voterWeight: 1,
    voterWeightExpiry: currentSlot,
    weightAction: VoterWeightActionTag.CastVote,
    weightActionTarget: proposal,
  }),
  owner: atomicTx.instructions[0].programId,
  executable: false,
};
const txVerified = service.verifyAtomicRealmsTransaction({
  transaction: atomicTx,
  realm,
  governingTokenMint,
  voter: human.pubkey,
  expectedAction: VoterWeightActionTag.CastVote,
  expectedTarget: proposal,
  executionSlot: currentSlot,
  resultingVoterWeightRecord: resultingVwr,
});
assert.equal(txVerified.ok, true);

// Migrated voter after proposal voting_at_slot is rejected by pre-flight
const migratedLate = makeWallet();
fixture.updateWallet(migratedLate.pubkey, {
  trustScore: 260,
  verifiedAt: fixture.state.now - 10,
  slot: 999,
});
fixture.migrateWallet(migratedLate.pubkey, {
  previousWallet: makeWallet().pubkey,
  migratedAt: fixture.state.now - 10,
  migratedSlot: 960,
});
const latePreflight = await service.preflightRealms({
  realm,
  governingTokenMint,
  voter: migratedLate.pubkey,
  action: VoterWeightActionTag.CastVote,
  actionTarget: proposal,
  origin: ORIGIN,
});
assert.equal(latePreflight.eligible, false);
assert.equal(latePreflight.reason, "identity_migrated_after_voting_start");

// 5. Cold vs warm telemetry summary
service.recordTelemetry({
  mode: "cold",
  outcome: "completed",
  stages: {
    permissions: 800,
    capture: 14500,
    validation: 1900,
    proof: 1100,
    walletPrompts: 3200,
    confirmation: 1800,
    return: 250,
  },
});
service.recordTelemetry({
  mode: "warm",
  outcome: "completed",
  stages: {
    permissions: 0,
    capture: 0,
    validation: 180,
    proof: 0,
    walletPrompts: 0,
    confirmation: 0,
    return: 90,
  },
});
service.recordTelemetry({
  mode: "cold",
  outcome: "failed",
  failureClass: "wallet_rejection",
  stages: { permissions: 700, capture: 13200, validation: 1700, proof: 1050 },
});
const telemetry = service.telemetrySummary();
assert.equal(telemetry.cold.total, 2);
assert.equal(telemetry.warm.total, 1);
assert.equal(telemetry.failuresByClass.wallet_rejection, 1);

console.log(
  JSON.stringify(
    {
      warmPolicyReuse: {
        status: warmReused.status,
        feeLamports: warmReused.feeLamports,
        captureRounds: warmReused.captureRounds,
        preservedVerifiedAt: warmReused.verifiedAt === originalVerifiedAt,
        belowFloorRoutedToCapture: warmLowScore.reason,
      },
      protectedAction: {
        originRefused: badOrigin.reason,
        updateSettled: settled.ok,
        replayRefused: replayedAction.reason,
        postResetRefused: postResetSettled.reason,
        rebaselineSettled: rebaselineSettled.ok,
      },
      agentPermit: {
        pausedForApproval: permit1.status,
        settled: permitAllowed.ok,
        replayRefused: permitReplayed.reason,
        copiedRefused: copiedPermit.reason,
        staleAgentWalletRefused: staleWallet.reason,
        postTransferRefused: afterTransfer.reason,
        expiredPrecheckRefused: expiredPermit.reason,
        expiredPrecheckRpcReads,
      },
      realms: {
        policyModel: preflightEligible.policyModel,
        atomicTxVerified: txVerified.ok,
        includesCreateVwr: txVerified.includesCreateVwr,
        postVotingMigrationRefused: latePreflight.reason,
      },
      telemetry: {
        coldRuns: telemetry.cold.total,
        warmRuns: telemetry.warm.total,
        warmCaptureP50Ms: telemetry.warm.stages.capture.p50Ms,
        coldCaptureP50Ms: telemetry.cold.stages.capture.p50Ms,
      },
      actionsExecuted: service.actions().length,
      syntheticOnly: true,
    },
    null,
    2,
  ),
);
