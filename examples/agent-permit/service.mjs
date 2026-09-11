import {
  agentPermitId,
  createAgentPermitRequest,
  encodeAgentPermitFragment,
  evaluateAgentPermit,
  parseAgentPermitSettlement,
  precheckAgentPermit,
  renderAgentPermitMessage,
} from "@entros/verify/agent-permit";
import { normalizePolicyRequest, policyResultToWire } from "@entros/verify/policy";
import { canonicalAction, permitAction } from "./action.mjs";

const LOOPBACK_AUDIENCE = /^http:\/\/127\.0\.0\.1(?::[1-9][0-9]{0,4})?\/agent-action$/;

/**
 * Issues Agent Operator Permit requests and settles permits for one synthetic action.
 * Pending requests and executed actions live in this process only.
 */
export class AgentPermitSettlement {
  #pending = new Map();
  #actions = [];
  #audience;
  #policy;
  #readAgentState;
  #readOperatorEvidence;
  #clock;
  #lifetimeSeconds;
  #maxPending;
  #maxPendingPerAgent;
  #log;

  constructor({
    audience,
    policy,
    readAgentState,
    readOperatorEvidence,
    nowSeconds,
    lifetimeSeconds = 600,
    maxPending = 1000,
    maxPendingPerAgent = 4,
    log = () => {},
  }) {
    if (typeof audience !== "string" || !LOOPBACK_AUDIENCE.test(audience)) {
      throw new Error("Only a loopback agent-action audience is supported");
    }
    this.#audience = audience;
    this.#policy = normalizePolicyRequest(policy);
    this.#readAgentState = readAgentState;
    this.#readOperatorEvidence = readOperatorEvidence;
    this.#clock = nowSeconds;
    this.#lifetimeSeconds = lifetimeSeconds;
    this.#maxPending = maxPending;
    this.#maxPendingPerAgent = maxPendingPerAgent;
    this.#log = log;
  }

  #now() {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < 1) throw new Error("Invalid server clock");
    return now;
  }

  #prune(now) {
    for (const [nonce, entry] of this.#pending) {
      if (entry.request.expiresAt <= now) this.#pending.delete(nonce);
    }
  }

  /** Reads the agent now and issues a request bound to its current owner and agent wallet. */
  async issue({ agent, action }) {
    let checked;
    try {
      checked = canonicalAction(action);
      permitAction(agent, checked);
    } catch {
      return { ok: false, reason: "invalid_request" };
    }
    this.#prune(this.#now());
    const forAgent = [...this.#pending.values()].filter((entry) => entry.request.agent === agent);
    if (this.#pending.size >= this.#maxPending || forAgent.length >= this.#maxPendingPerAgent) {
      return { ok: false, reason: "capacity_reached" };
    }
    let state;
    try {
      state = await this.#readAgentState({ agent });
    } catch {
      return { ok: false, reason: "agent_unavailable" };
    }
    if (state?.status === "unavailable") return { ok: false, reason: "agent_unavailable" };
    if (state?.status !== "available") {
      const reason = ["wrong_cluster", "agent_missing", "agent_unregistered"].includes(state?.reason)
        ? state.reason
        : "agent_invalid";
      return { ok: false, reason };
    }
    const { evidence } = state;
    if (evidence.agent !== agent) return { ok: false, reason: "agent_invalid" };
    if (evidence.agentWalletStatus === "stale") return { ok: false, reason: "agent_wallet_stale" };
    if (evidence.agentWalletStatus === "unbound") return { ok: false, reason: "agent_wallet_unbound" };
    const now = this.#now();
    let request;
    try {
      request = createAgentPermitRequest({
        agent,
        agentWallet: evidence.agentWallet,
        operator: evidence.owner,
        audience: this.#audience,
        action: permitAction(agent, checked),
        policy: this.#policy,
        issuedAt: now,
        lifetimeSeconds: this.#lifetimeSeconds,
      });
    } catch {
      return { ok: false, reason: "agent_invalid" };
    }
    const message = renderAgentPermitMessage(request);
    const entry = Object.freeze({ request, message, action: checked });
    this.#pending.set(request.nonce, entry);
    this.#log({ event: "issued", agent, operator: request.operator, slot: evidence.readContextSlot });
    return {
      ok: true,
      permitId: agentPermitId(request),
      message,
      fragment: encodeAgentPermitFragment(request),
    };
  }

  /** Verifies a settlement bundle and executes the stored action once. */
  async settle(input) {
    const bundle = parseAgentPermitSettlement(input);
    if (!bundle) return { ok: false, reason: "invalid_request" };
    const entry = this.#pending.get(bundle.nonce);
    if (!entry) return { ok: false, reason: "nonce_unavailable" };
    const signatures = {
      operatorSignature: bundle.operatorSignature,
      presentationSignature: bundle.presentationSignature,
    };
    // Expiry and both signatures cost no chain read.
    const precheck = precheckAgentPermit({
      request: entry.request,
      ...signatures,
      nowSeconds: this.#now(),
    });
    if (!precheck.ok) {
      if (precheck.reason === "permit_expired") this.#pending.delete(bundle.nonce);
      this.#log({ event: "settled", permitId: precheck.permitId, reason: precheck.reason, chainReads: 0 });
      return { ok: false, reason: precheck.reason };
    }
    let agentState;
    let operatorEvidence;
    try {
      [agentState, operatorEvidence] = await Promise.all([
        this.#readAgentState({ agent: entry.request.agent }),
        this.#readOperatorEvidence({
          wallet: entry.request.operator,
          signature: bundle.verifiedTransaction,
        }),
      ]);
    } catch {
      return { ok: false, reason: "state_unavailable" };
    }
    // The reads take time, so the evaluation uses a clock sampled after they return.
    const now = this.#now();
    const result = evaluateAgentPermit({
      request: entry.request,
      ...signatures,
      agentState,
      operatorEvidence,
      nowSeconds: now,
    });
    this.#log({
      event: "settled",
      permitId: result.permitId,
      reason: result.reason,
      owner: result.agentState?.owner ?? null,
      slot: result.agentState?.readContextSlot ?? null,
      chainReads: 2,
    });
    if (result.decision !== "allow") {
      if (result.reason === "permit_expired") this.#pending.delete(bundle.nonce);
      return { ok: false, reason: result.reason };
    }
    if (this.#pending.get(bundle.nonce) !== entry) return { ok: false, reason: "nonce_unavailable" };
    this.#pending.delete(bundle.nonce);
    const record = Object.freeze({
      id: this.#actions.length + 1,
      permitId: result.permitId,
      agent: entry.request.agent,
      operator: entry.request.operator,
      agentWallet: entry.request.agentWallet,
      ...entry.action,
      settledAt: now,
      accessExpiresAt: now + entry.action.durationSeconds,
      ownerReadSlot: result.agentState.readContextSlot,
      policy: policyResultToWire(result.policy),
    });
    this.#actions.push(record);
    return { ok: true, action: structuredClone(record) };
  }

  actions() {
    return structuredClone(this.#actions);
  }
}
