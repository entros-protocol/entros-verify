import assert from "node:assert/strict";
import { createScenario } from "./scenario.mjs";

const scenario = createScenario();

const first = await scenario.requestPermit();
const allowed = await scenario.service.settle(scenario.bundle(first));
assert.equal(allowed.ok, true);
const replayed = await scenario.service.settle(scenario.bundle(first));
assert.equal(replayed.reason, "nonce_unavailable");

const second = await scenario.requestPermit();
const copied = await scenario.service.settle(scenario.copiedBundle(second));
assert.equal(copied.reason, "invalid_presentation");

const third = await scenario.requestPermit();
const held = scenario.bundle(third);
scenario.chain.transferDirect(scenario.otherKey.publicKey);
const transferred = await scenario.service.settle(held);
assert.equal(transferred.reason, "owner_changed");

const later = createScenario();
const fourth = await later.requestPermit();
const late = later.bundle(fourth);
later.clock.now += 601;
const readsBefore = later.chain.reads.length;
const expired = await later.service.settle(late);
assert.equal(expired.reason, "permit_expired");
assert.equal(later.chain.reads.length, readsBefore);

assert.equal(scenario.service.actions().length, 1);
console.log(
  JSON.stringify(
    {
      presentedByAgentWallet: allowed.ok ? "access_granted" : allowed.reason,
      replayedPermit: replayed.reason,
      copiedPermit: copied.reason,
      afterTransfer: transferred.reason,
      expiredPermit: expired.reason,
      chainReadsForExpiredPermit: later.chain.reads.length - readsBefore,
      actionsExecuted: scenario.service.actions().length,
      syntheticOnly: true,
    },
    null,
    2,
  ),
);
