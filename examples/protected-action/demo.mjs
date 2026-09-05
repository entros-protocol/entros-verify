import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { readIntegratorEvidence } from "@entros/pulse-sdk";
import { evaluatePolicy, normalizePolicyRequest } from "@entros/verify/policy";
import { LocalPolicySettlement, signingBytes } from "./service.mjs";
import { createEvidenceFixture } from "./fixture.mjs";

const now = 1800000000;
const action = {
  kind: "grant_access",
  resource: "synthetic-vault",
  durationSeconds: 60,
};
const policy = normalizePolicyRequest({
  ...normalizePolicyRequest(undefined, 100),
  id: "local-vault",
  maxVerificationAgeSeconds: 120,
});
function setup(audience = "http://127.0.0.1:43210/local-action") {
  const key = generateKeyPairSync("ed25519");
  const wallet = new PublicKey(
    key.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
  ).toBase58();
  const fixture = createEvidenceFixture({
    walletPubkey: wallet,
    nowSeconds: now,
  });
  const service = new LocalPolicySettlement({
    policy,
    audience,
    nowSeconds: () => now,
    evaluatePolicy,
    decodeWallet(value) {
      const pubkey = new PublicKey(value);
      if (pubkey.toBase58() !== value) throw new Error("Invalid wallet");
      return pubkey.toBytes();
    },
    readEvidence({ wallet: walletPubkey, signature: transactionSignature }) {
      return readIntegratorEvidence({
        walletPubkey,
        transactionSignature,
        connection: fixture.connection,
        nowSeconds: now,
      });
    },
  });
  function request() {
    const challenge = service.issue(wallet, action);
    return {
      challenge,
      signature: sign(null, signingBytes(challenge), key.privateKey).toString(
        "hex",
      ),
      verifiedTransaction: fixture.signature,
    };
  }
  return { key, wallet, fixture, service, request };
}

const demo = setup();
const request = demo.request();
const allowed = await demo.service.settle(request);
assert.equal(allowed.ok, true);
const replay = await demo.service.settle(request);
assert.equal(replay.reason, "nonce_unavailable");
const changed = demo.request();
demo.fixture.state.trustScore = 0;
changed.clientEvidence = { decision: "allow", trustScore: 10000 };
const rejected = await demo.service.settle(changed);
assert.equal(rejected.reason, "score_below_minimum");
assert.equal(demo.service.actions().length, 1);
console.log(
  JSON.stringify(
    {
      validRequest: "access_granted",
      replayedRequest: replay.reason,
      changedEvidence: rejected.reason,
      actionsExecuted: demo.service.actions().length,
      syntheticOnly: true,
    },
    null,
    2,
  ),
);
