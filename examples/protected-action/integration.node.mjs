import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { once } from "node:events";
import { PublicKey } from "@solana/web3.js";
import { readIntegratorEvidence } from "@entros/pulse-sdk";
import { evaluatePolicy, normalizePolicyRequest } from "@entros/verify/policy";
import { LocalPolicySettlement, signingBytes } from "./service.mjs";
import { createLocalSettlementServer } from "./http.mjs";
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

test("actual strict reader and evaluator allow a fresh signed action with optional missing SAS", async () => {
  const f = setup();
  const observation = await readIntegratorEvidence({
    walletPubkey: f.wallet,
    transactionSignature: f.fixture.signature,
    connection: f.fixture.connection,
    nowSeconds: now,
  });
  assert.equal(observation.status, "available", JSON.stringify(observation));
  assert.equal(observation.evidence.attestation.status, "missing");
  const result = await f.service.settle(f.request());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(f.service.actions().length, 1);
  assert.ok(f.fixture.reads.includes(f.fixture.identity.toBase58()));
  assert.ok(f.fixture.reads.includes(f.fixture.attestation.toBase58()));
});

for (const [name, change, reason] of [
  [
    "score drop",
    (state) => {
      state.trustScore = 7;
    },
    "score_below_minimum",
  ],
  [
    "missing identity",
    (state) => {
      state.identityMissing = true;
    },
    "invalid_evidence",
  ],
  [
    "RPC failure",
    (state) => {
      state.rpcUnavailable = true;
    },
    "state_unavailable",
  ],
  [
    "changed commitment",
    (state) => {
      state.changedCommitment = true;
    },
    "invalid_evidence",
  ],
  [
    "failed transaction",
    (state) => {
      state.transactionFailed = true;
    },
    "invalid_evidence",
  ],
  [
    "unavailable transaction",
    (state) => {
      state.transactionUnavailable = true;
    },
    "state_unavailable",
  ],
])
  test(`actual reader rejects ${name} after challenge issuance`, async () => {
    const f = setup();
    const request = f.request();
    change(f.fixture.state);
    request.clientEvidence = { decision: "allow", trustScore: 10000 };
    const result = await f.service.settle(request);
    assert.equal(result.ok, false);
    assert.equal(result.reason, reason, JSON.stringify(result));
    assert.equal(f.service.actions().length, 0);
  });

test("actual evaluator cannot borrow recent identity time for an old transaction", async () => {
  const f = setup();
  const request = f.request();
  f.fixture.transaction.blockTime = now - 121;
  const result = await f.service.settle(request);
  assert.equal(result.reason, "verification_stale", JSON.stringify(result));
  assert.equal(f.service.actions().length, 0);
});

test("32 concurrent signed requests execute one action through actual reader and evaluator", async () => {
  const f = setup();
  const request = f.request();
  const results = await Promise.all(
    Array.from({ length: 32 }, () =>
      f.service.settle(structuredClone(request)),
    ),
  );
  assert.equal(
    results.filter((result) => result.ok).length,
    1,
    JSON.stringify(results),
  );
  assert.equal(
    results.filter((result) => result.reason === "nonce_unavailable").length,
    31,
  );
  assert.equal(f.service.actions().length, 1);
});

test("HTTP action verifies signatures and rechecks server state independently of browser evidence", async () => {
  let service;
  const server = createLocalSettlementServer({
    issue(...args) {
      return service.issue(...args);
    },
    settle(...args) {
      return service.settle(...args);
    },
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  const f = setup(origin + "/local-action");
  service = f.service;
  async function post(path, body) {
    const response = await fetch(origin + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    assert.equal(response.status, 200);
    return response.json();
  }
  async function signedRequest() {
    const challenge = await post("/challenge", { wallet: f.wallet, action });
    return {
      challenge,
      signature: sign(null, signingBytes(challenge), f.key.privateKey).toString(
        "hex",
      ),
      verifiedTransaction: f.fixture.signature,
    };
  }
  try {
    const request = await signedRequest();
    assert.equal((await post("/local-action", request)).ok, true);
    assert.equal(
      (await post("/local-action", request)).reason,
      "nonce_unavailable",
    );
    const stale = await signedRequest();
    f.fixture.state.trustScore = 7;
    stale.clientEvidence = { decision: "allow", trustScore: 10000 };
    stale.policy = { minTrustScore: 0 };
    assert.equal(
      (await post("/local-action", stale)).reason,
      "score_below_minimum",
    );
    assert.equal(service.actions().length, 1);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
