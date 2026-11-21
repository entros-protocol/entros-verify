# `@entros/verify`

[![npm version](https://img.shields.io/npm/v/@entros/verify.svg)](https://www.npmjs.com/package/@entros/verify)

React component for wallet-connected Entros verification on Solana devnet.
It opens the Entros popup and checks the returned application policy result before calling `onVerified`.

Source: [github.com/entros-protocol/entros-verify](https://github.com/entros-protocol/entros-verify) · Hosted by [entros.io](https://entros.io).

Pin an exact version when you integrate the policy contract.
The package is published, and the hosted Entros popup supports this policy contract.
A self-hosted popup must implement the same contract before it can serve an upgraded consumer.

Install with React 19:

```bash
npm install @entros/verify
```

## Usage

```tsx
import { EntrosVerify } from "@entros/verify";

<EntrosVerify
  integratorKey="your-integrator-key"
  onVerified={(result) => showVerificationResult(result)}
  onError={(error) => showVerificationError(error.reason, error.policyReason)}
/>;
```

Without `policy`, the component uses a one-day verification age, a 90-second evaluation age, and optional SAS issuance.
The score floor defaults to zero or the supplied `minTrustScore`.
The consumer rejects older popups that omit the policy result.

## Application policy

```tsx
<EntrosVerify
  integratorKey="your-integrator-key"
  policy={{
    id: "claim-access",
    version: 1,
    minTrustScore: 200,
    maxVerificationAgeSeconds: 300,
    maxEvaluationAgeSeconds: 90,
    requiredAssurance: "browser_unattested",
    uniquenessRequirement: "allow_unmeasured",
    requireAttestation: false,
    cluster: "devnet",
  }}
  onVerified={(result) => showVerificationResult(result)}
  onError={(error) => showVerificationError(error.reason, error.policyReason)}
/>
```

The consumer checks the requested policy, account observations, score, freshness, and matching result fields.
Supplying conflicting `minTrustScore` and `policy.minTrustScore` values fails before the popup opens.

The result states `browser_unattested` assurance and `unmeasured` uniqueness.
These fields do not establish sensor provenance or population uniqueness.

## Warm policy reuse

Before starting browser capture, a host can check whether the wallet already satisfies the policy on devnet.
When existing evidence passes, verification completes at `0 SOL` and zero capture rounds.
Warm reuse preserves the original `verifiedAt` timestamp (`lastVerificationTimestamp`). It never refreshes evidence age.

`@entros/verify` exports `evaluateWarmPolicyReuse` without adding a dependency on `@entros/pulse-sdk`.
Supply either a pre-read observation or injected async readers backed by your configured RPC connection:

```ts
import { evaluateWarmPolicyReuse } from "@entros/verify";

const warm = await evaluateWarmPolicyReuse({
  walletPubkey,
  policy,
  findVerification: ({ walletPubkey: wallet }) =>
    findLatestVerificationTransaction({ walletPubkey: wallet, connection, verifiedAt }),
  readEvidence: ({ walletPubkey: wallet, transactionSignature }) =>
    readIntegratorEvidence({
      walletPubkey: wallet,
      transactionSignature: transactionSignature!,
      connection,
      nowSeconds: now,
    }),
  nowSeconds: now,
});
```

`evaluateWarmPolicyReuse` normalizes the policy, rejects wallet mismatches, and returns `reused` only when `evaluatePolicy` returns `allow`.
Set `requireLegacyAttestation: true` when calling without a negotiated policy so reuse requires a present attestation.
Stale evidence, below-floor scores, reset identities, or missing evidence return `needs_capture` so the flow proceeds to capture.
Reused results retain `devnet`, `browser_unattested` assurance, and `unmeasured` population uniqueness.

## Result

```ts
import type { PolicyResult } from "@entros/verify/policy";

interface EntrosVerifyResult {
  walletPubkey: string;
  attestationPda: string | null;
  txSig: string;
  trustScore: number;
  cluster: "devnet";
  policy: PolicyResult & { decision: "allow" };
}
```

The `policy` result contains the evaluated requirements, expiry, and typed evidence.
A non-null `attestationPda` identifies an account that passed validation during evaluation.
Optional attestations with `missing` or `unavailable` status carry no issued address. Invalid accounts fail the policy.
Required attestations must exist and remain valid through consumption.

## Component options

```tsx
<EntrosVerify
  integratorKey="your-integrator-key"
  cluster="devnet"
  minTrustScore={200}
  popupWidth={480}
  popupHeight={800}
  timeoutMs={9 * 60 * 1000}
  popupBlockedFallback={true}
  className="verification-button"
  onVerified={(result) => showVerificationResult(result)}
  onError={(error) => showVerificationError(error.reason, error.policyReason)}
  onProgress={(progress) => showProgress(progress.status)}
>
  Verify with Entros
</EntrosVerify>
```

`integratorKey` and `onVerified` are required. The dimensions, timeout, and popup fallback above show their defaults.
Use `style` for inline styles and children for custom button content.
`onProgress` reports popup heartbeats during the flow.

## Errors

`onError` receives `reason` and an optional `policyReason`.
Policy reasons describe application requirements or evidence availability. They do not expose private behavioral rejection signals.

| Reason              | Meaning                                             |
| ------------------- | --------------------------------------------------- |
| `wallet_rejected`   | User denied wallet connection or signing            |
| `validation_failed` | Verification or the application policy did not pass |
| `network_error`     | The flow encountered a network failure              |
| `user_canceled`     | User closed the popup before completion             |
| `origin_invalid`    | The integrator origin failed the allowlist check    |
| `popup_blocked`     | The browser blocked `window.open()`                 |
| `timeout`           | The popup exceeded `timeoutMs`                      |
| `unknown`           | The flow encountered an unclassified failure        |

## Settlement checks

The React-free `@entros/verify/policy` subpath exports `normalizePolicyRequest`, `evaluatePolicy`, and strict wire guards.
Pair the evaluator with `readIntegratorEvidence` from Pulse `4.10.2` or later against your service's configured RPC connection.
The evaluator accepts typed observations. It cannot authenticate observations supplied by a browser.

For protected actions, your service owns the policy and authenticates the wallet's signature over a one-use action challenge.
Bind the challenge to the wallet, action parameters, audience, and expiry.
Read current chain evidence before executing the action. Consume the challenge and execute the action in one atomic operation.
An on-chain action must enforce its requirements within the action transaction.

Run the [protected-action example](examples/protected-action) to exercise signature checks, fresh policy evaluation, and one-use settlement with synthetic data.

## Agent Operator Permit

The React-free `@entros/verify/agent-permit` subpath implements permit version 1 for agents in the 8004 agent registry on devnet.
A permit authorizes one action by one registered agent. The wallet that owns the agent signs it, and the agent's registered agent wallet presents it.

1. Your service reads the agent with `readAgentState` from Pulse `4.12.0` or later.
2. Your service calls `createAgentPermitRequest` and stores the rendered text under its nonce.
3. The owner opens the request on the Entros signing page and signs it with the owning wallet.
4. The agent signs `renderAgentPermitPresentation(permitId)` with its agent wallet and sends the settlement bundle.
5. Your service runs `precheckAgentPermit`, reads agent state and operator evidence, and runs `evaluateAgentPermit`.
6. On `allow`, your service consumes the nonce and executes the stored action in one atomic operation.

```ts
import {
  evaluateAgentPermit,
  parseAgentPermitSettlement,
  precheckAgentPermit,
} from "@entros/verify/agent-permit";

const bundle = parseAgentPermitSettlement(body);
const stored = bundle && pending.get(bundle.nonce);
if (!bundle || !stored) return reject("nonce_unavailable");

const signatures = {
  operatorSignature: bundle.operatorSignature,
  presentationSignature: bundle.presentationSignature,
};
const precheck = precheckAgentPermit({ request: stored, ...signatures, nowSeconds: now() });
if (!precheck.ok) return reject(precheck.reason);

const [agentState, operatorEvidence] = await Promise.all([
  readAgentState({ agent: stored.agent, connection }),
  readIntegratorEvidence({
    walletPubkey: stored.operator,
    transactionSignature: bundle.verifiedTransaction,
    connection,
    nowSeconds: now,
  }),
]);
const result = evaluateAgentPermit({
  request: stored,
  ...signatures,
  agentState,
  operatorEvidence,
  nowSeconds: now(),
});
```

The precheck covers expiry and both signatures, so an expired or forged permit costs your service no chain read.
Sample the clock again after the reads, because a permit can expire while they run.

- Compare the request with what your service issued: at least the nonce and the terms. Passing the stored request as `request`, as above, does both.
  A service that keeps only the nonce and some terms passes them as `expected: { nonce, audience, action, policy }`, with `agent` and `operator` when it stores them.
  `evaluateAgentPermit` then denies a signed request with another nonce or other terms with `request_mismatch`.
  Never take policy or RPC settings from the agent.
- Execute the stored action at settlement. Do not return a reusable credential to the presenter.
- The owner is the wallet in the Metaplex Core asset. The registry's cached owner and the `entros:human-operator` metadata grant nothing.
- A transfer after the settlement read can still land before your action. An on-chain action must check ownership inside its transaction.

Run the [agent-permit example](examples/agent-permit) to exercise issuance, both signatures, transfer rejection, and one-use settlement with synthetic data.

A permit states current wallet control of a registered agent and the owner's Entros policy result. It does not establish legal ownership, population uniqueness, or hardware assurance.

## Zero-GPL Solana readers (`@entros/verify/solana`)

The React-free `@entros/verify/solana` subpath reads Solana devnet state using only permissive MIT dependencies (`@noble/curves` and `@noble/hashes`). It requires no `@solana/web3.js` or `@coral-xyz/anchor` runtime dependency and accepts a Solana RPC endpoint URL, a custom `fetch` config, or a duck-typed `Connection` instance.

- `readIntegratorEvidence` and `findLatestVerificationTransaction` read confirmed Entros verification evidence, enforcing the 2-second slot-time tolerance, 15-second device clock catch-up, and 57-byte `MigrationRecord` checks.
- `readAgentState` reads a Metaplex Core asset and its 8004 registry `AgentAccount` at one confirmed slot.
- `verifyEntrosAttestation` fetches the SAS attestation, `IdentityState`, and `MigrationRecord` accounts in one batch.
- `decodeIdentityState` and `readMigrationRecord` parse raw account buffers directly.

```ts
import { evaluatePolicy, normalizePolicyRequest } from "@entros/verify/policy";
import { readIntegratorEvidence } from "@entros/verify/solana";

const observation = await readIntegratorEvidence({
  walletPubkey,
  transactionSignature,
  connection: "https://api.devnet.solana.com",
  nowSeconds: () => Math.floor(Date.now() / 1000),
});
const result = evaluatePolicy(
  normalizePolicyRequest(),
  observation,
  Math.floor(Date.now() / 1000),
);
```

## MCP single-use approval adapter (`@entros/verify/mcp`)

The React-free `@entros/verify/mcp` subpath wraps `@entros/verify/agent-permit`, `@entros/verify/policy`, and `@entros/verify/solana` into a pause-and-approve workflow for Model Context Protocol servers, OpenAI `mcp_approval_request` flows, and HumanLayer pause/resume callbacks.

- `createMcpApprovalChallenge` binds `subject` (Core asset owner wallet), `actor` (8004 Metaplex Core asset and bound agent wallet), `audience`, canonical tool `action.sha256`, `policy`, `devnet`, and a lifetime up to 900 seconds.
- `verifyMcpApprovalSettlement` validates permit structure, expiry, strict Ed25519 signatures, expected bindings, live Metaplex Core ownership, current Entros evidence, and policy rules before consuming the single-use nonce atomically through `McpNonceStore`. Failed attempts never burn a valid pending nonce.
- `createChallengeFromOpenAiMcpRequest` and `settleOpenAiMcpApproval` adapt OpenAI `mcp_approval_request` and `mcp_approval_response` items.
- `createHumanLayerApprovalCall` and `verifyHumanLayerApprovalCallback` adapt HumanLayer pause and resume webhooks.

An owner-signed MCP approval preserves the original `verifiedAt` timestamp and `browser_unattested` assurance tier. It authorizes one later agent action and does not prove human presence when the agent executes that action.

## Reference consumer

Run the [reference-consumer example](examples/reference-consumer) to test a standalone application built against published npm packages.
It exercises warm policy reuse, Integrator Policy v1 settlement, Agent Operator Permit pause-and-approve, Realms voter-weight checks, and stage latency telemetry.
For Realms governance, the plugin enforces `one eligible wallet, one vote` with current-slot expiry and migration-slot checks against each proposal.
All demonstrations and tests run locally against synthetic devnet fixtures.

## Migration from `0.1.1`

Version `0.2.0` changes the callback contract:

- Handle `attestationPda: null` when optional SAS issuance is missing or unavailable.
- Read the required `policy` result for evaluated requirements, expiry, and evidence status.
- Handle `onError` when the hosted popup lacks the policy contract or the returned evidence does not satisfy it.

The popup retains transport envelope version `1` and negotiates the policy contract through separate request fields.
The compatible popup supplies legacy consumers with their original payload types after a valid attestation exists and the requested score floor passes.
A popup rollback makes upgraded consumers reject results until compatible service returns.

## Limitations

- Devnet only. Mainnet support remains planned.
- The browser callback reports the completed flow. Protected actions require the settlement checks above.
- Integrator origins require the hosted allowlist. Self-serve onboarding remains planned.
- Mobile browsers can open the popup in a new tab. This component does not implement native Mobile Wallet Adapter support.

## Integration safeguards

- Checks the message origin against the configured popup origin.
- Checks the popup window and per-popup `request_id`.
- Rejects invalid, expired, or mismatched policy results.
- Applies the parent timeout and handles popup blocking and cancellation.

## License

MIT.
