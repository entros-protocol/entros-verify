import {
  evaluatePolicy,
  normalizePolicyRequest,
  policyResultToWire,
  POLICY_NETWORK,
  type PolicyEvidence,
  type PolicyRequest,
} from "../src/policy";

export function makePolicyEvidence(
  now = Math.floor(Date.now() / 1000),
): PolicyEvidence {
  return {
    cluster: "devnet",
    genesisHash: POLICY_NETWORK.genesisHash,
    programIds: { ...POLICY_NETWORK.programIds },
    assuranceTier: "browser_unattested",
    uniquenessStatus: "unmeasured",
    readContextSlot: 100,
    identity: {
      walletPubkey: "11111111111111111111111111111111",
      identityPda: POLICY_NETWORK.programIds.anchor,
      creationTimestamp: now - 86400,
      lastVerificationTimestamp: now - 10,
      verificationCount: 5,
      trustScore: 250,
      currentCommitment: "01".repeat(32),
      projectionVersion: 1,
      lastResetTimestamp: 0,
      lastRebaselineTimestamp: 0,
      mint: POLICY_NETWORK.programIds.registry,
    },
    transaction: {
      signature: "1".repeat(64),
      slot: 100,
      blockTime: now - 10,
      commitment: "01".repeat(32),
      kind: "update",
    },
    attestation: { status: "missing" },
  };
}

export function makePolicyPayload(
  policy: PolicyRequest = normalizePolicyRequest(),
  now = Math.floor(Date.now() / 1000),
) {
  const evidence = makePolicyEvidence(now);
  const result = evaluatePolicy(policy, { status: "available", evidence }, now);
  return {
    wallet_pubkey: evidence.identity.walletPubkey,
    attestation_pda: null,
    tx_sig: evidence.transaction.signature,
    trust_score: evidence.identity.trustScore,
    cluster: "devnet" as const,
    policy: policyResultToWire(result),
  };
}
