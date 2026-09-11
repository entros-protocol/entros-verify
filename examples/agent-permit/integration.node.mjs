import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import {
  buildSetAgentWalletInstructions,
  encodeAgentWalletBindingFragment,
  parseAgentWalletBindingFragment,
  verifyAgentWalletBindingRequest,
} from "@entros/pulse-sdk";
import { parseAgentPermitFragment } from "@entros/verify/agent-permit";
import { createBindingRequest, generateAgentKey, loadAgentKey, saveAgentKey } from "./agent.mjs";
import { createAgentPermitServer } from "./http.mjs";
import { createScenario, DEFAULT_ACTION } from "./scenario.mjs";

describe("agent key files and binding requests", () => {
  const directory = mkdtempSync(join(tmpdir(), "entros-agent-permit-"));
  after(() => rmSync(directory, { recursive: true, force: true }));

  it("writes a Solana keypair file once and reads it back", () => {
    const key = generateAgentKey();
    const path = join(directory, "agent-key.json");
    saveAgentKey(path, key);
    assert.equal(loadAgentKey(path).publicKey, key.publicKey);
    assert.throws(() => saveAgentKey(path, generateAgentKey()), { code: "EEXIST" });
    assert.equal(loadAgentKey(path).publicKey, key.publicKey);
  });

  it("produces a binding request that the registry transaction builder accepts", async () => {
    const key = generateAgentKey();
    const agent = generateAgentKey().publicKey;
    const owner = generateAgentKey().publicKey;
    const request = createBindingRequest({ key, agent, owner, nowSeconds: 1_800_000_000 });
    assert.equal(request.deadline, 1_800_000_240);
    assert.equal(verifyAgentWalletBindingRequest(request), true);
    assert.deepEqual(parseAgentWalletBindingFragment(encodeAgentWalletBindingFragment(request)), request);
    const instructions = await buildSetAgentWalletInstructions(request);
    assert.equal(instructions.length, 2);
  });
});

describe("HTTP settlement", () => {
  let server;
  let base;
  let scenario;

  before(async () => {
    let service;
    server = createAgentPermitServer({
      issue: (input) => service.issue(input),
      settle: (input) => service.settle(input),
      actions: () => service.actions(),
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    base = `http://127.0.0.1:${port}`;
    scenario = createScenario({ audience: `${base}/agent-action` });
    service = scenario.service;
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  async function post(path, body, headers = { "content-type": "application/json" }) {
    const response = await fetch(`${base}${path}`, {
      method: "POST",
      headers,
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }

  it("issues, signs, presents and executes one action over loopback", async () => {
    const issued = await post("/permit-requests", { agent: scenario.agent, action: DEFAULT_ACTION });
    assert.equal(issued.status, 200);
    assert.equal(issued.body.ok, true);
    const parsed = parseAgentPermitFragment(issued.body.fragment);
    assert.equal(parsed.message, issued.body.message);
    const settled = await post("/settlements", scenario.bundle(issued.body));
    assert.equal(settled.body.ok, true);
    const replayed = await post("/settlements", scenario.bundle(issued.body));
    assert.equal(replayed.body.reason, "nonce_unavailable");
    const actions = await (await fetch(`${base}/actions`)).json();
    assert.equal(actions.length, 1);
  });

  it("bounds the HTTP surface", async () => {
    assert.equal((await post("/settlements", "x".repeat(17 * 1024))).status, 413);
    assert.equal((await post("/settlements", "{}", { "content-type": "text/plain" })).status, 415);
    assert.equal(
      (await post("/settlements", "{}", { "content-type": "application/json", origin: "https://evil.example" })).status,
      403,
    );
    assert.equal((await post("/elsewhere", {})).status, 404);
    assert.equal((await post("/settlements", "{not json")).status, 400);
  });
});
