import { readAgentState, readIntegratorEvidence } from "@entros/pulse-sdk";
import {
  encodeAgentPermitApproval,
  encodeAgentPermitSettlement,
  parseAgentPermitMessage,
  renderAgentPermitPresentation,
} from "@entros/verify/agent-permit";
import { normalizePolicyRequest } from "@entros/verify/policy";
import { createSettlementBundle, generateAgentKey } from "./agent.mjs";
import { createChainFixture } from "./fixture.mjs";
import { AgentPermitSettlement } from "./service.mjs";

export const DEFAULT_ACTION = Object.freeze({
  kind: "grant_access",
  resource: "synthetic-vault",
  durationSeconds: 60,
});

export const DEFAULT_POLICY = normalizePolicyRequest({
  id: "agent-demo",
  version: 1,
  minTrustScore: 100,
  maxVerificationAgeSeconds: 3600,
  requiredAssurance: "browser_unattested",
  uniquenessRequirement: "allow_unmeasured",
  cluster: "devnet",
});

const encoder = new TextEncoder();

/** One agent, its bound agent wallet, its owner, and a consumer, all on synthetic devnet state. */
export function createScenario({
  now = 1_800_000_000,
  audience = "http://127.0.0.1:43210/agent-action",
  serviceOptions = {},
} = {}) {
  const clock = { now };
  const operatorKey = generateAgentKey();
  const agentKey = generateAgentKey();
  const otherKey = generateAgentKey();
  const agent = generateAgentKey().publicKey;
  const chain = createChainFixture({ agent, owner: operatorKey.publicKey, nowSeconds: now });
  chain.bind(agentKey.publicKey);
  const service = new AgentPermitSettlement({
    audience,
    policy: DEFAULT_POLICY,
    nowSeconds: () => clock.now,
    readAgentState: ({ agent: address }) =>
      readAgentState({ agent: address, connection: chain.connection }),
    readOperatorEvidence: ({ wallet, signature }) =>
      readIntegratorEvidence({
        walletPubkey: wallet,
        transactionSignature: signature,
        connection: chain.connection,
        nowSeconds: () => clock.now,
      }),
    ...serviceOptions,
  });

  /** The owner's approval, as the Entros signing page returns it. */
  function approve(issued, signer = operatorKey) {
    return encodeAgentPermitApproval({
      permitId: issued.permitId,
      operatorSignature: signer.sign(encoder.encode(issued.message)),
      verifiedTransaction: chain.operator(parseAgentPermitMessage(issued.message).operator).signature,
    });
  }

  async function requestPermit(action = DEFAULT_ACTION) {
    const issued = await service.issue({ agent, action });
    if (!issued.ok) throw new Error(`Issue refused: ${issued.reason}`);
    return issued;
  }

  function bundle(issued, key = agentKey, signer = operatorKey) {
    return createSettlementBundle({ key, message: issued.message, approval: approve(issued, signer) });
  }

  /** A bundle whose presentation someone signed with a key other than the bound agent wallet. */
  function copiedBundle(issued, key = otherKey) {
    const request = parseAgentPermitMessage(issued.message);
    return encodeAgentPermitSettlement({
      nonce: request.nonce,
      operatorSignature: operatorKey.sign(encoder.encode(issued.message)),
      presentationSignature: key.sign(encoder.encode(renderAgentPermitPresentation(issued.permitId))),
      verifiedTransaction: chain.operator(request.operator).signature,
    });
  }

  return {
    clock,
    operatorKey,
    agentKey,
    otherKey,
    agent,
    chain,
    service,
    approve,
    requestPermit,
    bundle,
    copiedBundle,
  };
}
