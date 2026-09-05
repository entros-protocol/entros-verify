import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { LocalPolicySettlement, signingBytes } from "./service.mjs";

const action = {
  kind: "grant_access",
  resource: "synthetic-vault",
  durationSeconds: 60,
};
const audience = "http://127.0.0.1:43210/local-action";
function keypair() {
  const pair = generateKeyPairSync("ed25519");
  return {
    ...pair,
    wallet: pair.publicKey
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("hex"),
  };
}
function fixture(options = {}) {
  const owner = keypair();
  let now = 1800000000;
  let authoritative = {
    decision: "allow",
    reason: "accepted",
    trustScore: 100,
  };
  let reads = 0;
  const requestedReads = [];
  const policy = { minTrustScore: 100 };
  const service = new LocalPolicySettlement({
    policy,
    audience,
    nowSeconds: () => now,
    decodeWallet(wallet) {
      if (!/^[a-f0-9]{64}$/.test(wallet)) throw new Error("Invalid wallet");
      return Buffer.from(wallet, "hex");
    },
    async readEvidence(input) {
      reads++;
      requestedReads.push(input);
      if (options.read) await options.read();
      return { ...authoritative };
    },
    evaluatePolicy(request, evidence) {
      assert.equal(request.minTrustScore, 100);
      return evidence.trustScore >= request.minTrustScore
        ? {
            ...evidence,
            expiresAt: now + 90,
            evidence: {
              identity: { walletPubkey: owner.wallet },
              transaction: { signature: "synthetic-verified-tx" },
            },
          }
        : { decision: "deny", reason: "score_below_minimum" };
    },
  });
  function request(
    challenge = service.issue(owner.wallet, action),
    signer = owner,
  ) {
    return {
      challenge,
      signature: sign(
        null,
        signingBytes(challenge),
        signer.privateKey,
      ).toString("hex"),
      verifiedTransaction: "synthetic-verified-tx",
    };
  }
  return {
    service,
    owner,
    request,
    policy,
    reads: () => reads,
    requestedReads,
    advance(seconds) {
      now += seconds;
    },
    state(value) {
      authoritative = value;
    },
  };
}

test("valid signed action consumes its nonce and creates one local grant", async () => {
  const f = fixture();
  const request = f.request();
  const result = await f.service.settle(request);
  assert.equal(result.ok, true);
  assert.equal(result.action.wallet, f.owner.wallet);
  assert.equal(result.action.resource, "synthetic-vault");
  assert.deepEqual(f.requestedReads, [
    { wallet: f.owner.wallet, signature: request.verifiedTransaction },
  ]);
  assert.equal((await f.service.settle(request)).reason, "nonce_unavailable");
  assert.equal(f.service.actions().length, 1);
});

test("action signature rejects another wallet signer", async () => {
  const f = fixture();
  const request = f.request(undefined, keypair());
  assert.equal((await f.service.settle(request)).reason, "invalid_signature");
  assert.equal(f.reads(), 0);
});

for (const [name, mutate] of [
  [
    "wallet",
    (challenge) => {
      challenge.wallet = keypair().wallet;
    },
  ],
  [
    "action identifier",
    (challenge) => {
      challenge.action.kind = "delete_access";
    },
  ],
  [
    "action parameters",
    (challenge) => {
      challenge.action.durationSeconds = 3600;
    },
  ],
  [
    "audience",
    (challenge) => {
      challenge.audience = "http://127.0.0.1:43211/local-action";
    },
  ],
  [
    "expiry",
    (challenge) => {
      challenge.expiresAt += 1;
    },
  ],
  [
    "version",
    (challenge) => {
      challenge.version = 2;
    },
  ],
])
  test(`rejects substituted ${name}`, async () => {
    const f = fixture();
    const request = f.request();
    mutate(request.challenge);
    const result = await f.service.settle(request);
    assert.equal(result.ok, false);
    assert.equal(f.reads(), 0);
    assert.equal(f.service.actions().length, 0);
  });

test("client evidence and client policy cannot replace current server state", async () => {
  const f = fixture();
  const request = f.request();
  request.clientEvidence = { decision: "allow", trustScore: 10000 };
  request.policy = { minTrustScore: 0 };
  request.now = 0;
  request.programIds = { entrosAnchor: "attacker-program" };
  f.state({ decision: "allow", trustScore: 7 });
  assert.equal((await f.service.settle(request)).reason, "score_below_minimum");
  assert.equal(f.service.actions().length, 0);
  assert.equal(f.reads(), 1);
});

test("server policy copy does not inherit later caller mutations", async () => {
  const f = fixture();
  f.policy.minTrustScore = 0;
  f.state({ decision: "allow", trustScore: 7 });
  assert.equal(
    (await f.service.settle(f.request())).reason,
    "score_below_minimum",
  );
});

test("state changing after the browser callback prevents the local action", async () => {
  const f = fixture();
  const request = f.request();
  f.state({ decision: "deny", reason: "verification_stale", trustScore: 100 });
  assert.equal((await f.service.settle(request)).reason, "verification_stale");
  assert.equal(f.service.actions().length, 0);
});

test("RPC failure never creates a grant", async () => {
  const f = fixture({
    read: async () => {
      throw new Error("synthetic RPC failure");
    },
  });
  assert.equal(
    (await f.service.settle(f.request())).reason,
    "state_unavailable",
  );
  assert.equal(f.service.actions().length, 0);
});

test("expired challenge fails before evidence retrieval", async () => {
  const f = fixture();
  const request = f.request();
  f.advance(120);
  assert.equal((await f.service.settle(request)).reason, "challenge_expired");
  assert.equal(f.reads(), 0);
});

test("expiry while reading evidence fails before consuming the nonce", async () => {
  let release;
  const hold = new Promise((resolve) => {
    release = resolve;
  });
  const f = fixture({ read: () => hold });
  const running = f.service.settle(f.request());
  f.advance(120);
  release();
  assert.equal((await running).reason, "challenge_expired");
  assert.equal(f.service.actions().length, 0);
});

test("64 concurrent submissions consume one nonce once", async () => {
  let release;
  const hold = new Promise((resolve) => {
    release = resolve;
  });
  const f = fixture({ read: () => hold });
  const request = f.request();
  const pending = Array.from({ length: 64 }, () =>
    f.service.settle(structuredClone(request)),
  );
  release();
  const results = await Promise.all(pending);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(
    results.filter((result) => result.reason === "nonce_unavailable").length,
    63,
  );
  assert.equal(f.service.actions().length, 1);
});

test("canonical action serialization ignores property insertion order", () => {
  const f = fixture();
  const request = f.request();
  const reordered = {
    ...request.challenge,
    action: {
      durationSeconds: 60,
      resource: "synthetic-vault",
      kind: "grant_access",
    },
  };
  assert.deepEqual(signingBytes(reordered), signingBytes(request.challenge));
});

test("unknown action keys fail before challenge issuance", () => {
  const f = fixture();
  assert.throws(
    () =>
      f.service.issue(f.owner.wallet, { ...action, recipient: "substituted" }),
    /Invalid protected action/,
  );
});
