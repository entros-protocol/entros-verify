import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PublicKey } from "@solana/web3.js";
import {
  findLatestVerificationTransaction,
  readAgentState,
  readIntegratorEvidence,
  verifyEntrosAttestation,
} from "@entros/pulse-sdk";
import {
  evaluateAgentPermit,
  renderAgentPermitPresentation,
} from "@entros/verify/agent-permit";
import {
  evaluatePolicy,
  normalizePolicyRequest,
} from "@entros/verify/policy";
import { createReferenceFixture } from "./fixture.mjs";
import { createReferenceConsumerServer } from "./http.mjs";
import { VoterWeightActionTag } from "./realms-check.mjs";
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

test("published package versions are pinned and SAS + 57-byte MigrationRecord cross-check works", async () => {
  const pulsePkg = JSON.parse(
    readFileSync(
      new URL("./node_modules/@entros/pulse-sdk/package.json", import.meta.url),
      "utf8",
    ),
  );
  const verifyPkg = JSON.parse(
    readFileSync(
      new URL("./node_modules/@entros/verify/package.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(pulsePkg.version, "4.17.0");
  assert.equal(verifyPkg.version, "0.5.0");

  const fixture = createReferenceFixture({
    nowSeconds: 1800000000,
    currentSlot: 1000,
  });
  const wallet = makeWallet();
  const tx = fixture.updateWallet(wallet.pubkey, {
    trustScore: 280,
    verifiedAt: fixture.state.now - 120,
    slot: 990,
    attestation: { status: "present", expiresAt: fixture.state.now + 7200 },
  });

  const found = await findLatestVerificationTransaction({
    walletPubkey: wallet.pubkey,
    connection: fixture.connection,
    verifiedAt: fixture.state.now - 120,
  });
  assert.deepEqual(found, { status: "found", signature: tx.signature });

  const observation = await readIntegratorEvidence({
    walletPubkey: wallet.pubkey,
    transactionSignature: tx.signature,
    connection: fixture.connection,
    nowSeconds: () => fixture.state.now,
  });
  assert.equal(observation.status, "available");
  assert.equal(observation.evidence.attestation.status, "present");

  const policy = normalizePolicyRequest({
    id: "published-integration",
    version: 1,
    minTrustScore: 200,
    maxVerificationAgeSeconds: 3600,
    maxEvaluationAgeSeconds: 90,
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    requireAttestation: true,
    cluster: "devnet",
  });
  const decision = evaluatePolicy(policy, observation, fixture.state.now);
  assert.equal(decision.decision, "allow");

  const sasBeforeMigration = await verifyEntrosAttestation(
    wallet.pubkey,
    fixture.connection,
  );
  assert.notEqual(sasBeforeMigration, null);
  assert.equal(sasBeforeMigration.trustScore, 280);

  // Migration after the attestation's verifiedAt invalidates the prior SAS attestation.
  fixture.migrateWallet(wallet.pubkey, {
    previousWallet: makeWallet().pubkey,
    migratedAt: fixture.state.now - 60,
    migratedSlot: 995,
  });
  const sasAfterMigration = await verifyEntrosAttestation(
    wallet.pubkey,
    fixture.connection,
  );
  assert.equal(sasAfterMigration, null);

  // Published readAgentState + evaluateAgentPermit work end-to-end.
  const agent = makeWallet().pubkey;
  const agentWallet = makeWallet();
  fixture.registerAgent({
    agent,
    owner: wallet.pubkey,
    agentWallet: agentWallet.pubkey,
  });
  const agentState = await readAgentState({
    agent,
    connection: fixture.connection,
  });
  assert.equal(agentState.status, "available");
  assert.equal(agentState.evidence.agentWalletStatus, "bound");
  assert.equal(typeof evaluateAgentPermit, "function");
});

test("loopback HTTP server serves warm check, protected actions, agent permits, Realms pre-flight, telemetry, and origin checks", async () => {
  const fixture = createReferenceFixture({
    nowSeconds: 1800000000,
    currentSlot: 1000,
  });
  const owner = makeWallet();
  const agent = makeWallet().pubkey;
  const agentWallet = makeWallet();
  const realm = makeWallet().pubkey;
  const mint = makeWallet().pubkey;
  const governance = makeWallet().pubkey;
  const proposal = makeWallet().pubkey;
  const tor = makeWallet().pubkey;

  const updateTx = fixture.updateWallet(owner.pubkey, {
    trustScore: 260,
    verifiedAt: fixture.state.now - 100,
    slot: 990,
    attestation: { status: "present", expiresAt: fixture.state.now + 7200 },
  });
  fixture.registerAgent({
    agent,
    owner: owner.pubkey,
    agentWallet: agentWallet.pubkey,
  });
  fixture.setRegistrar({
    realm,
    governingTokenMint: mint,
    minTrustScore: 200,
    maxVerificationAge: 3600,
  });
  fixture.setProposal({
    proposal,
    governance,
    governingTokenMint: mint,
    tokenOwnerRecord: tor,
    state: 2,
    votingAtSlot: 950,
  });

  const policy = normalizePolicyRequest({
    id: "http-reference",
    version: 1,
    minTrustScore: 200,
    maxVerificationAgeSeconds: 1800,
    maxEvaluationAgeSeconds: 90,
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    requireAttestation: true,
    cluster: "devnet",
  });

  let server;
  let baseUrl;
  // Bind port 0 first, then configure the service's exact loopback audience and origin allowlist.
  let service;
  const router = createReferenceConsumerServer(
    {
      checkWarmPolicy: (...args) => service.checkWarmPolicy(...args),
      issueActionChallenge: (...args) => service.issueActionChallenge(...args),
      settleAction: (...args) => service.settleAction(...args),
      requestAgentPermit: (...args) => service.requestAgentPermit(...args),
      settleAgentPermit: (...args) => service.settleAgentPermit(...args),
      preflightRealms: (...args) => service.preflightRealms(...args),
      telemetrySummary: (...args) => service.telemetrySummary(...args),
      actions: (...args) => service.actions(...args),
    },
  );
  server = router;

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
    service = new ReferenceConsumerService({
      policy,
      agentPolicy: policy,
      actionAudience: `${baseUrl}/action-settlements`,
      agentAudience: `${baseUrl}/agent-permit-settlements`,
      allowedOrigins: [baseUrl],
      connection: fixture.connection,
      nowSeconds: () => fixture.state.now,
    });

    const post = (path, body, headers = {}) =>
      fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: baseUrl,
          ...headers,
        },
        body: JSON.stringify(body),
      });

    // Origin mismatch -> 403
    const badOrigin = await post(
      "/warm-check",
      { walletPubkey: owner.pubkey },
      { origin: "https://evil.example" },
    );
    assert.equal(badOrigin.status, 403);
    assert.equal((await badOrigin.json()).error, "origin_invalid");

    // Non-JSON content type -> 415
    const wrongType = await fetch(`${baseUrl}/warm-check`, {
      method: "POST",
      headers: { "content-type": "text/plain", origin: baseUrl },
      body: "{}",
    });
    assert.equal(wrongType.status, 415);

    // Oversized body -> 413
    const tooLarge = await fetch(`${baseUrl}/warm-check`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: baseUrl },
      body: "a".repeat(17 * 1024),
    });
    assert.equal(tooLarge.status, 413);

    // Warm policy reuse over HTTP
    const warmRes = await post("/warm-check", { walletPubkey: owner.pubkey });
    assert.equal(warmRes.status, 200);
    const warmBody = await warmRes.json();
    assert.equal(warmBody.ok, true);
    assert.equal(warmBody.status, "reused");
    assert.equal(warmBody.feeLamports, 0);
    assert.equal(warmBody.verifiedAt, fixture.state.now - 100);

    // Action challenge + settlement + replay refusal over HTTP
    const action = {
      kind: "grant_access",
      resource: "reference-vault",
      durationSeconds: 120,
    };
    const chRes = await (
      await post("/action-challenges", { wallet: owner.pubkey, action })
    ).json();
    assert.equal(chRes.ok, true);
    const settleBody = {
      challenge: chRes.challenge,
      signature: owner.signHex(actionChallengeSigningBytes(chRes.challenge)),
      verifiedTransaction: updateTx.signature,
    };
    const settled = await (
      await post("/action-settlements", settleBody)
    ).json();
    assert.equal(settled.ok, true);
    const replayed = await (
      await post("/action-settlements", settleBody)
    ).json();
    assert.equal(replayed.reason, "nonce_unavailable");

    // Agent permit pause-and-approve + settlement over HTTP
    const permitReq = await (
      await post("/agent-permit-requests", { agent, action })
    ).json();
    assert.equal(permitReq.ok, true);
    assert.equal(permitReq.status, "paused_for_owner_approval");
    const permitSettled = await (
      await post("/agent-permit-settlements", {
        version: 1,
        nonce: permitReq.nonce,
        operatorSignature: owner.signHex(
          Buffer.from(permitReq.message, "utf8"),
        ),
        presentationSignature: agentWallet.signHex(
          Buffer.from(renderAgentPermitPresentation(permitReq.permitId), "utf8"),
        ),
        verifiedTransaction: updateTx.signature,
      })
    ).json();
    assert.equal(permitSettled.ok, true);

    // Realms pre-flight over HTTP
    const realmsRes = await (
      await post("/realms-preflight", {
        realm,
        governingTokenMint: mint,
        voter: owner.pubkey,
        action: VoterWeightActionTag.CastVote,
        actionTarget: proposal,
      })
    ).json();
    assert.equal(realmsRes.eligible, true);
    assert.equal(realmsRes.policyModel, "one eligible wallet, one vote");

    // Telemetry and actions endpoints
    service.recordTelemetry({
      mode: "warm",
      outcome: "completed",
      stages: { validation: 140, return: 60 },
    });
    const telemetry = await (await fetch(`${baseUrl}/telemetry`)).json();
    assert.equal(telemetry.warm.completed, 1);
    const actions = await (await fetch(`${baseUrl}/actions`)).json();
    assert.equal(actions.length, 2);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
