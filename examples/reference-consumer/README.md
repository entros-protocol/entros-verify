# Published-package reference consumer

This runnable Node.js example installs published `@entros/pulse-sdk@4.17.0` and `@entros/verify@0.5.0` from npm.
It exercises warm policy reuse, Integrator Policy v1 settlement, Agent Operator Permit approval, Realms voter-weight checks, and stage latency telemetry.
All tests and demonstrations run locally against synthetic devnet fixtures with no live network submission.

## Run locally

Use Node.js 24.19.0 or later. Run these commands from this directory:

```sh
npm ci --legacy-peer-deps=false
npm test
npm run demo
```

The test suite generates disposable Ed25519 keys in memory and starts a loopback HTTP server on an ephemeral port.
The server closes after every test run.

## Covered workflows

### 1. Warm policy reuse before capture

The consumer reads `IdentityState`, finds the newest qualifying transaction, calls `readIntegratorEvidence`, and evaluates the server policy before requesting capture.
When existing devnet evidence satisfies the policy, access completes at 0 SOL and zero capture rounds.
Warm reuse preserves the original `verifiedAt` timestamp and never refreshes evidence age.
Stale evidence, below-floor scores, reset identities, or missing required attestations route the user to browser capture.

### 2. Integrator Policy v1 action settlement

The service enforces an explicit origin allowlist and issues one-use action challenges bound to wallet, action, audience, nonce, and expiry.
Settlement checks the wallet signature, ignores browser-supplied evidence or policy overrides, reads current chain state, and consumes the nonce atomically.
The suite covers cold mint, returning update, post-reset refusal, rebaseline acceptance, origin refusal, and concurrent duplicate settlement.

### 3. Agent Operator Permit pause-and-approve

A permit separates the `subject` (the owner wallet holding the Metaplex Core asset) from the `actor` (the bound 8004 agent wallet).
At settlement, `precheckAgentPermit` rejects expired permits, invalid operator signatures, and copied presentations with zero RPC reads.
Valid permits proceed to live `readAgentState` and `readIntegratorEvidence` reads and `evaluateAgentPermit`.
The suite rejects replayed nonces, copied permits, stale agent wallet caches (`agent_wallet_stale`), and transferred agents (`owner_changed`).

### 4. Realms voter-weight pre-flight and atomic transaction

The `realms-check.mjs` module models the devnet `entros-voter-weight` plugin for `one eligible wallet, one vote` governance.
Pre-flight checks `IdentityState` Trust Score and verification age plus the 57-byte `MigrationRecord` slot against the proposal's `voting_at_slot`.
An identity that migrated in or after the voting start slot fails pre-flight before prompting a wallet signature.
The transaction builder assembles `[create_voter_weight_record?, update_voter_weight_record_for_action, spl_governance_ix]` in one atomic transaction and checks `Some(clock.slot)` expiry and action binding.

### 5. Cold vs warm stage latency telemetry

`telemetry.mjs` computes cold and warm `p50`, `p95`, and sample counts across `permissions`, `capture`, `validation`, `proof`, `walletPrompts`, `confirmation`, and `return`.
It classifies failures and abandonments into `permissions`, `unsupported_device`, `capture`, `validation`, `stale_baseline`, `unavailable_service`, `funding`, `wallet_rejection`, `confirmation`, and `return`.
The collector rejects raw audio, motion, touch, or fingerprint fields.

## Files

| File | Purpose |
| --- | --- |
| `service.mjs` | Warm reuse check, protected action consumer, and Agent Operator Permit service |
| `http.mjs` | Bounded JSON loopback HTTP server with origin allowlist enforcement |
| `realms-check.mjs` | Realms voter-weight pre-flight and atomic transaction builder and verifier |
| `telemetry.mjs` | Cold and warm stage latency summaries and failure classification |
| `fixture.mjs` | Synthetic devnet accounts, transactions, SAS attestations, 8004 agents, and Realms state |
| `anchor-fixture-idl.json` | Subset of the published Pulse `4.17.0` Anchor IDL for encoding synthetic accounts and instructions |
| `demo.mjs` | End-to-end demonstration across all five workflows |
| `service.node.mjs` | Unit tests for warm reuse, actions, permits, Realms, and telemetry |
| `integration.node.mjs` | Published-package contract checks, SAS migration cross-check, and loopback HTTP tests |

`anchor-fixture-idl.json` extracts `mint_anchor`, `update_anchor`, `rebaseline_anchor`, `reset_identity_state`, `IdentityState`, `MigrationRecord`, and `UpdateReceiptArgs` from published Pulse `4.17.0`.
Source: https://github.com/entros-protocol/pulse-sdk/blob/1e4820ed6ed46729120287f8c5323e602c47903a/src/protocol/idl/entros_anchor.json

## Scope and limits

- Devnet only. Mainnet support remains planned.
- Policy results carry `browser_unattested` assurance and `unmeasured` population uniqueness.
- Warm policy reuse preserves original `verifiedAt` and never certifies present human presence.
- Realms voter weight enforces `one eligible wallet, one vote` per configured registrar rules.
- This example stores pending nonces and executed actions in process memory only. Production services must consume nonces and execute actions inside one durable transaction.
- Synthetic fixtures verify consumer logic only. They do not establish sensor provenance, population uniqueness, or an external production deployment.
