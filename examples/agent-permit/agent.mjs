import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { Connection, PublicKey } from "@solana/web3.js";
import {
  AGENT_WALLET_BINDING_MAX_DEADLINE_SECONDS,
  agentWalletBindingMessage,
  encodeAgentWalletBindingFragment,
  readAgentState,
} from "@entros/pulse-sdk";
import {
  agentPermitId,
  encodeAgentPermitSettlement,
  parseAgentPermitApproval,
  parseAgentPermitMessage,
  renderAgentPermitPresentation,
} from "@entros/verify/agent-permit";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// The registry limit is 300 seconds past its own clock. The margin covers clock skew.
const BINDING_LIFETIME_SECONDS = AGENT_WALLET_BINDING_MAX_DEADLINE_SECONDS - 60;

/** An agent key held as its 32-byte seed. */
export function agentKeyFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error("Invalid agent key seed");
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  const publicBytes = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return {
    publicKey: new PublicKey(publicBytes).toBase58(),
    seed: Uint8Array.from(seed),
    sign: (message) => sign(null, Buffer.from(message), privateKey).toString("hex"),
  };
}

export function generateAgentKey() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  return agentKeyFromSeed(seed);
}

/** Writes a Solana CLI keypair file. Refuses to replace an existing file. */
export function saveAgentKey(path, key) {
  const secret = [...key.seed, ...new PublicKey(key.publicKey).toBytes()];
  writeFileSync(path, JSON.stringify(secret), { flag: "wx", mode: 0o600 });
}

export function loadAgentKey(path) {
  const secret = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(secret) || secret.length !== 64) throw new Error("Invalid keypair file");
  const key = agentKeyFromSeed(Uint8Array.from(secret.slice(0, 32)));
  if (new PublicKey(Uint8Array.from(secret.slice(32))).toBase58() !== key.publicKey) {
    throw new Error("Keypair file halves disagree");
  }
  return key;
}

/** The registry binding request that the owner sends from the Entros signing page. */
export function createBindingRequest({ key, agent, owner, nowSeconds }) {
  const deadline = nowSeconds + BINDING_LIFETIME_SECONDS;
  const fields = { agent, agentWallet: key.publicKey, owner, deadline };
  return { version: 1, ...fields, signature: key.sign(agentWalletBindingMessage(fields)) };
}

/** Checks the approval against the stored request and signs the presentation. */
export function createSettlementBundle({ key, message, approval }) {
  const request = parseAgentPermitMessage(message);
  const parsed = parseAgentPermitApproval(approval);
  if (!parsed) throw new Error("Invalid approval");
  const permitId = agentPermitId(request);
  if (parsed.permitId !== permitId) throw new Error("The approval names another permit");
  if (request.agentWallet !== key.publicKey) throw new Error("The request names another agent wallet");
  return encodeAgentPermitSettlement({
    nonce: request.nonce,
    operatorSignature: parsed.operatorSignature,
    presentationSignature: key.sign(new TextEncoder().encode(renderAgentPermitPresentation(permitId))),
    verifiedTransaction: parsed.verifiedTransaction,
  });
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  return response.json();
}

async function main(argv) {
  const [command, ...rest] = argv;
  const { values } = parseArgs({
    args: rest,
    options: {
      key: { type: "string" },
      agent: { type: "string" },
      rpc: { type: "string", default: "https://api.devnet.solana.com" },
      site: { type: "string", default: "https://entros.io" },
      consumer: { type: "string", default: "http://127.0.0.1:5199" },
      state: { type: "string", default: "agent-request.json" },
      approval: { type: "string" },
      resource: { type: "string", default: "synthetic-vault" },
      duration: { type: "string", default: "60" },
    },
  });
  const now = () => Math.floor(Date.now() / 1000);
  if (command === "keygen") {
    const key = generateAgentKey();
    saveAgentKey(values.key ?? "agent-key.json", key);
    console.log(`Agent wallet: ${key.publicKey}`);
    return;
  }
  if (command === "bind") {
    const key = loadAgentKey(values.key ?? "agent-key.json");
    const state = await readAgentState({
      agent: values.agent,
      connection: new Connection(values.rpc, "confirmed"),
    });
    if (state.status !== "available") throw new Error(`Agent state ${state.status}: ${state.reason}`);
    const request = createBindingRequest({
      key,
      agent: values.agent,
      owner: state.evidence.owner,
      nowSeconds: now(),
    });
    console.log(`Owner ${state.evidence.owner} opens this address within four minutes:`);
    console.log(`${values.site}/agents#${encodeAgentWalletBindingFragment(request)}`);
    return;
  }
  if (command === "request") {
    const result = await postJson(`${values.consumer}/permit-requests`, {
      agent: values.agent,
      action: {
        kind: "grant_access",
        resource: values.resource,
        durationSeconds: Number(values.duration),
      },
    });
    if (!result.ok) throw new Error(`Request refused: ${result.reason}`);
    writeFileSync(values.state, JSON.stringify({ message: result.message }, null, 2), { flag: "wx" });
    console.log(`Permit ${result.permitId}. The owner opens this address to sign:`);
    console.log(`${values.site}/agents#${result.fragment}`);
    return;
  }
  if (command === "present") {
    const key = loadAgentKey(values.key ?? "agent-key.json");
    const { message } = JSON.parse(readFileSync(values.state, "utf8"));
    const bundle = createSettlementBundle({ key, message, approval: values.approval });
    console.log(JSON.stringify(await postJson(`${values.consumer}/settlements`, bundle), null, 2));
    return;
  }
  throw new Error("Usage: node agent.mjs <keygen|bind|request|present> [options]");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
