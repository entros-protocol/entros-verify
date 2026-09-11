# Agent Operator Permit reference consumer

This runnable Node.js example issues Agent Operator Permit requests and settles permits for one synthetic action.
It uses the Pulse and Verify releases pinned in `package.json`. The tests and the demonstration run against synthetic devnet state.

## Run locally

Use Node.js 24.19.0 or later. Run these commands from this directory:

```sh
npm ci
npm test
npm run demo
```

The demonstration reports these outcomes:

| Step | Outcome |
| --- | --- |
| The bound agent wallet presents a signed permit | `access_granted` |
| The same permit arrives again | `nonce_unavailable` |
| Another key presents a copy of a signed permit | `invalid_presentation` |
| The agent moves to another owner before settlement | `owner_changed` |
| A permit arrives after expiry | `permit_expired`, with no chain read |

## Roles

| Role | Holds | Does |
| --- | --- | --- |
| Owner | The wallet in the agent's Metaplex Core asset | Binds the agent wallet once, then signs each permit request on the Entros signing page |
| Agent | The agent wallet key bound in the 8004 registry | Asks for a permit request, then presents the signed permit |
| Consumer | This service | Issues requests, verifies permits against chain state, and executes the stored action once |

## Flow

1. The agent runs `node agent.mjs bind`. The owner opens the printed address and sends the binding transaction.
2. The agent runs `node agent.mjs request`. The consumer reads the agent and stores the request text under its nonce.
3. The owner opens the printed address on the Entros signing page, reviews the request, and signs it.
4. The agent runs `node agent.mjs present` with the approval that the signing page shows.
5. The consumer checks expiry and both signatures before any chain read.
6. The consumer reads agent state and the owner's verification evidence, then evaluates its policy.
7. On `allow`, the consumer deletes the nonce and executes the stored action in one synchronous step.

The consumer ignores policy, RPC settings and request text from the agent. It settles only the request text it stored.

## Run against devnet

`serve.mjs` runs the consumer on loopback against a devnet RPC endpoint. It still executes a synthetic action only.

```sh
npm run serve
node agent.mjs keygen --key agent-key.json
node agent.mjs bind --key agent-key.json --agent <agent asset>
node agent.mjs request --agent <agent asset> --state agent-request-1.json
node agent.mjs present --key agent-key.json --state agent-request-1.json --approval '<approval JSON>'
```

The agent must be registered in the 8004 agent registry on devnet. The owner's wallet needs an Entros Anchor verified within the policy age.
`keygen` refuses to replace an existing key file. Keep the key file private.

## Files

| File | Purpose |
| --- | --- |
| `service.mjs` | Request issuance, pending storage, precheck, chain reads, evaluation and one-use execution |
| `action.mjs` | Binary action record and the label the owner reads |
| `agent.mjs` | Agent key handling, binding request, presentation signature and command line |
| `http.mjs` | Bounded JSON endpoints on loopback |
| `serve.mjs` | Devnet consumer with Pulse readers |
| `fixture.mjs` | Synthetic Core asset, registry account and owner evidence |
| `scenario.mjs` | Shared setup for the demonstration and tests |
| `demo.mjs` | The five outcomes in the table above |
| `service.node.mjs` | Issuance, settlement, transfer, rebinding, migration, clock and concurrency tests |
| `integration.node.mjs` | Key files, binding requests and the HTTP flow |

`anchor-fixture-idl.json` contains the IdentityState and update_anchor definitions from the published Pulse SDK source.
The fixture uses this subset only to encode synthetic accounts and instructions.
Source: https://github.com/entros-protocol/pulse-sdk/blob/16fed63d0d740b96f4a7f0c00034e37517c75f94/src/protocol/idl/entros_anchor.json

## Storage and settlement boundary

This example keeps pending requests and executed actions in one process. It provides no durable storage or production deployment.
For a durable service, delete the nonce and execute the action inside one database transaction.
Execute the stored action at settlement. Do not return a reusable credential to the presenter.

A transfer can land between the settlement read and the action. An on-chain action must check ownership inside its own transaction.

The tests establish behavior for synthetic fixtures. They do not establish real sensor capture, uniqueness, legal ownership, hardware assurance, or an external application deployment.
