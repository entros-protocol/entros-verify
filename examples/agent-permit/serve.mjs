import { parseArgs } from "node:util";
import { Connection } from "@solana/web3.js";
import { readAgentState, readIntegratorEvidence } from "@entros/pulse-sdk";
import { normalizePolicyRequest } from "@entros/verify/policy";
import { createAgentPermitServer } from "./http.mjs";
import { AgentPermitSettlement } from "./service.mjs";

// Runs the reference consumer on loopback against devnet. It executes a synthetic action only.
const { values } = parseArgs({
  options: {
    rpc: { type: "string", default: "https://api.devnet.solana.com" },
    port: { type: "string", default: "5199" },
    "min-trust-score": { type: "string", default: "100" },
    "max-verification-age": { type: "string", default: "86400" },
  },
});
const port = Number(values.port);
const connection = new Connection(values.rpc, "confirmed");
const nowSeconds = () => Math.floor(Date.now() / 1000);
const service = new AgentPermitSettlement({
  audience: `http://127.0.0.1:${port}/agent-action`,
  policy: normalizePolicyRequest({
    id: "agent-permit-demo",
    version: 1,
    minTrustScore: Number(values["min-trust-score"]),
    maxVerificationAgeSeconds: Number(values["max-verification-age"]),
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    cluster: "devnet",
  }),
  nowSeconds,
  readAgentState: ({ agent }) => readAgentState({ agent, connection }),
  readOperatorEvidence: ({ wallet, signature }) =>
    readIntegratorEvidence({
      walletPubkey: wallet,
      transactionSignature: signature,
      connection,
      nowSeconds,
    }),
  log: (entry) => console.log(JSON.stringify({ at: new Date().toISOString(), ...entry })),
});

createAgentPermitServer(service).listen(port, "127.0.0.1", () => {
  console.log(`Reference consumer on http://127.0.0.1:${port}, reading ${values.rpc}`);
});
