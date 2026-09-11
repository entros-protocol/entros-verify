import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { PublicKey } from "@solana/web3.js";
import { parseAgentPermitMessage } from "@entros/verify/agent-permit";
import { actionRecord, permitAction } from "./action.mjs";
import { generateAgentKey } from "./agent.mjs";
import { createScenario, DEFAULT_ACTION } from "./scenario.mjs";

const REGISTRY = new PublicKey("8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C");

describe("issuing permit requests", () => {
  it("binds the request to the current owner and bound agent wallet", async () => {
    const scenario = createScenario();
    const issued = await scenario.requestPermit();
    const request = parseAgentPermitMessage(issued.message);
    assert.equal(request.agent, scenario.agent);
    assert.equal(request.operator, scenario.operatorKey.publicKey);
    assert.equal(request.agentWallet, scenario.agentKey.publicKey);
    assert.equal(request.audience, "http://127.0.0.1:43210/agent-action");
    assert.equal(request.expiresAt - request.issuedAt, 600);
    assert.deepEqual(request.action, permitAction(scenario.agent, DEFAULT_ACTION));
    assert.equal(issued.fragment.startsWith("request="), true);
  });

  it("names the agent inside the action digest", () => {
    const other = generateAgentKey().publicKey;
    const agent = generateAgentKey().publicKey;
    assert.notEqual(permitAction(agent, DEFAULT_ACTION).sha256, permitAction(other, DEFAULT_ACTION).sha256);
    assert.equal(
      permitAction(agent, DEFAULT_ACTION).sha256,
      createHash("sha256").update(actionRecord(agent, DEFAULT_ACTION)).digest("hex"),
    );
  });

  it("refuses agents without a trusted agent wallet", async () => {
    const unbound = createScenario();
    unbound.chain.transferThroughRegistry(unbound.otherKey.publicKey);
    assert.deepEqual(await unbound.service.issue({ agent: unbound.agent, action: DEFAULT_ACTION }), {
      ok: false,
      reason: "agent_wallet_unbound",
    });
    const stale = createScenario();
    stale.chain.transferDirect(stale.otherKey.publicKey);
    assert.deepEqual(await stale.service.issue({ agent: stale.agent, action: DEFAULT_ACTION }), {
      ok: false,
      reason: "agent_wallet_stale",
    });
  });

  it("refuses burned, foreign and unreachable agents and malformed actions", async () => {
    const burned = createScenario();
    burned.chain.state.burned = true;
    assert.equal((await burned.service.issue({ agent: burned.agent, action: DEFAULT_ACTION })).reason, "agent_missing");
    const foreign = createScenario();
    foreign.chain.state.collection = new PublicKey(new Uint8Array(32).fill(8));
    assert.equal(
      (await foreign.service.issue({ agent: foreign.agent, action: DEFAULT_ACTION })).reason,
      "agent_unregistered",
    );
    const down = createScenario();
    down.chain.state.rpcUnavailable = true;
    assert.equal((await down.service.issue({ agent: down.agent, action: DEFAULT_ACTION })).reason, "agent_unavailable");
    const scenario = createScenario();
    for (const action of [
      { ...DEFAULT_ACTION, resource: "another-vault" },
      { ...DEFAULT_ACTION, durationSeconds: 0 },
      { ...DEFAULT_ACTION, extra: true },
    ]) {
      assert.equal((await scenario.service.issue({ agent: scenario.agent, action })).reason, "invalid_request");
    }
  });

  it("caps pending requests per agent until they expire", async () => {
    const scenario = createScenario({ serviceOptions: { maxPendingPerAgent: 2 } });
    await scenario.requestPermit();
    await scenario.requestPermit();
    assert.equal(
      (await scenario.service.issue({ agent: scenario.agent, action: DEFAULT_ACTION })).reason,
      "capacity_reached",
    );
    scenario.clock.now += 600;
    assert.equal((await scenario.service.issue({ agent: scenario.agent, action: DEFAULT_ACTION })).ok, true);
  });
});

describe("settling permits", () => {
  it("executes the stored action once for the bound agent wallet", async () => {
    const scenario = createScenario();
    const issued = await scenario.requestPermit();
    const result = await scenario.service.settle(scenario.bundle(issued));
    assert.equal(result.ok, true);
    assert.equal(result.action.permitId, issued.permitId);
    assert.equal(result.action.agentWallet, scenario.agentKey.publicKey);
    assert.equal(result.action.accessExpiresAt, scenario.clock.now + 60);
    assert.equal(result.action.policy.decision, "allow");
    assert.equal((await scenario.service.settle(scenario.bundle(issued))).reason, "nonce_unavailable");
    assert.equal(scenario.service.actions().length, 1);
  });

  it("rejects a copied permit and a forged approval without chain reads", async () => {
    const scenario = createScenario();
    const issued = await scenario.requestPermit();
    const reads = scenario.chain.reads.length;
    assert.equal((await scenario.service.settle(scenario.copiedBundle(issued))).reason, "invalid_presentation");
    assert.equal(
      (await scenario.service.settle(scenario.bundle(issued, scenario.agentKey, scenario.otherKey))).reason,
      "invalid_signature",
    );
    assert.equal(scenario.chain.reads.length, reads);
    assert.equal((await scenario.service.settle(scenario.bundle(issued))).ok, true);
  });

  it("rejects an expired permit before any chain read and forgets it", async () => {
    const scenario = createScenario();
    const issued = await scenario.requestPermit();
    const bundle = scenario.bundle(issued);
    scenario.clock.now += 600;
    const reads = scenario.chain.reads.length;
    assert.equal((await scenario.service.settle(bundle)).reason, "permit_expired");
    assert.equal(scenario.chain.reads.length, reads);
    assert.equal((await scenario.service.settle(bundle)).reason, "nonce_unavailable");
  });

  it("rejects a permit after either kind of transfer", async () => {
    for (const transfer of ["transferDirect", "transferThroughRegistry"]) {
      const scenario = createScenario();
      const held = scenario.bundle(await scenario.requestPermit());
      scenario.chain[transfer](scenario.otherKey.publicKey);
      assert.equal((await scenario.service.settle(held)).reason, "owner_changed", transfer);
    }
  });

  it("rejects requests bound to an agent wallet the owner has replaced", async () => {
    const scenario = createScenario();
    const held = scenario.bundle(await scenario.requestPermit());
    const replacement = generateAgentKey();
    scenario.chain.bind(replacement.publicKey);
    assert.equal((await scenario.service.settle(held)).reason, "agent_wallet_changed");
    const fresh = await scenario.requestPermit();
    assert.equal((await scenario.service.settle(scenario.bundle(fresh, replacement))).ok, true);
  });

  it("reads the owner's Entros standing at settlement", async () => {
    const scenario = createScenario();
    const operator = scenario.chain.operator(scenario.operatorKey.publicKey);
    const low = scenario.bundle(await scenario.requestPermit());
    operator.trustScore = 99;
    assert.equal((await scenario.service.settle(low)).reason, "score_below_minimum");
    operator.trustScore = 250;
    const old = scenario.bundle(await scenario.requestPermit());
    operator.verificationAgeSeconds = 7200;
    assert.equal((await scenario.service.settle(old)).reason, "verification_stale");
    operator.verificationAgeSeconds = 10;
    const missing = scenario.bundle(await scenario.requestPermit());
    operator.identityMissing = true;
    assert.equal((await scenario.service.settle(missing)).reason, "invalid_evidence");
  });

  it("follows the operator to a new wallet after migration and transfer", async () => {
    const scenario = createScenario();
    const held = scenario.bundle(await scenario.requestPermit());
    const successor = generateAgentKey();
    scenario.chain.operator(scenario.operatorKey.publicKey).identityMissing = true;
    scenario.chain.operator(successor.publicKey);
    scenario.chain.transferThroughRegistry(successor.publicKey);
    scenario.chain.bind(scenario.agentKey.publicKey);
    assert.equal((await scenario.service.settle(held)).reason, "owner_changed");
    const issued = await scenario.requestPermit();
    assert.equal(parseAgentPermitMessage(issued.message).operator, successor.publicKey);
    assert.equal((await scenario.service.settle(scenario.bundle(issued, scenario.agentKey, successor))).ok, true);
  });

  it("settles one of two concurrent presentations", async () => {
    const scenario = createScenario();
    const bundle = scenario.bundle(await scenario.requestPermit());
    const results = await Promise.all([scenario.service.settle(bundle), scenario.service.settle(bundle)]);
    assert.deepEqual(results.map((result) => result.ok).sort(), [false, true]);
    assert.equal(results.find((result) => !result.ok).reason, "nonce_unavailable");
    assert.equal(scenario.service.actions().length, 1);
  });

  it("keeps a permit to the consumer that issued it", async () => {
    const issuer = createScenario();
    const bundle = issuer.bundle(await issuer.requestPermit());
    const elsewhere = createScenario({ audience: "http://127.0.0.1:43211/agent-action" });
    assert.equal((await elsewhere.service.settle(bundle)).reason, "nonce_unavailable");
  });

  it("tolerates a clock 30 seconds behind the issuing instance and no more", async () => {
    const scenario = createScenario();
    // The settling clock must still sit after the verification, or the evidence reads as future.
    scenario.chain.operator(scenario.operatorKey.publicKey).verificationAgeSeconds = 60;
    const behind = scenario.bundle(await scenario.requestPermit());
    const tooFar = scenario.bundle(await scenario.requestPermit());
    scenario.clock.now -= 30;
    assert.equal((await scenario.service.settle(behind)).ok, true);
    scenario.clock.now -= 1;
    assert.equal((await scenario.service.settle(tooFar)).reason, "invalid_permit");
  });

  it("rejects malformed bundles and never reads registry metadata", async () => {
    const scenario = createScenario();
    for (const body of [null, {}, "not json", { version: 1 }]) {
      assert.equal((await scenario.service.settle(body)).reason, "invalid_request");
    }
    const keyHash = createHash("sha256").update("entros:human-operator").digest().subarray(0, 16);
    const [metadata] = PublicKey.findProgramAddressSync(
      [Buffer.from("agent_meta"), new PublicKey(scenario.agent).toBuffer(), keyHash],
      REGISTRY,
    );
    await scenario.service.settle(scenario.bundle(await scenario.requestPermit()));
    assert.equal(scenario.chain.reads.some((read) => read.includes(metadata.toBase58())), false);
    assert.equal(
      scenario.chain.reads.filter((read) => read.startsWith("accounts:")).every(
        (read) => read === `accounts:${scenario.agent},${scenario.chain.agentAccount}`,
      ),
      true,
    );
  });
});
