# Protected action with Entros policy

This runnable Node.js example grants access to a synthetic resource after authenticating a signed action and evaluating current verification evidence.
It uses Pulse 4.10.2 and Verify 0.2.0. The test suite exercises the same settlement service as the demonstration.

## Run locally

Use Node.js 24.19.0 or later. Run these commands from this directory:

```sh
npm ci
npm test
npm run demo
```

The demonstration reports access granted, replay rejected, changed evidence rejected, and one executed action.
It generates disposable signing keys in memory. It uses synthetic RPC responses and makes no blockchain submission.
The HTTP integration test binds an available loopback port and closes its server after testing.

## Action flow

1. The server issues a one-use challenge for a wallet and action.
2. The wallet signs canonical bytes containing the action parameters, audience, nonce, and expiry.
3. The server checks the signature against its stored challenge.
4. The server reads identity and transaction evidence with its own RPC connection.
5. The server evaluates its own policy against that evidence and its clock.
6. The server consumes the nonce and grants access in one synchronous operation.

The service ignores browser-supplied evidence and policy configuration.
`onVerified` tells the browser that the popup completed. Your server still authenticates and authorizes each protected action.

## Files

| File                   | Purpose                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `service.mjs`          | Canonical signing bytes, challenge storage, signature checks, policy evaluation, and local grant |
| `http.mjs`             | Bounded JSON endpoints for the loopback integration test                                         |
| `demo.mjs`             | Accepted request, replay rejection, and changed-evidence rejection                               |
| `fixture.mjs`          | Synthetic identity, transaction, and RPC state                                                   |
| `service.node.mjs`     | Signature, substitution, expiry, replay, and concurrency tests                                   |
| `integration.node.mjs` | Released reader/evaluator and local HTTP tests                                                   |

`anchor-fixture-idl.json` contains the IdentityState and update_anchor definitions from the published Pulse SDK source.
The fixture uses this subset only to encode synthetic accounts and instructions.
Source: https://github.com/entros-protocol/pulse-sdk/blob/16fed63d0d740b96f4a7f0c00034e37517c75f94/src/protocol/idl/entros_anchor.json

## Application integration

The demonstration's policy permits devnet browser evidence with unmeasured uniqueness and optional SAS attestation.
Choose requirements that match your application. These requirements do not change protocol policy.
Use your configured RPC connection and the authenticated wallet when supplying the service's readEvidence adapter:

```js
import { readIntegratorEvidence } from "@entros/pulse-sdk";

const readEvidence = ({ wallet, signature }) =>
  readIntegratorEvidence({
    walletPubkey: wallet,
    transactionSignature: signature,
    connection: serverConnection,
    nowSeconds: () => Math.floor(Date.now() / 1000),
  });
```

`serverConnection` belongs to your service configuration. Never accept an RPC URL or a policy object from the action request.
Replace the fixture adapter when integrating. Wallet software must sign the exact bytes returned by `signingBytes`.
The example fixes its audience to a loopback endpoint. A deployed service must bind the challenge to its configured HTTPS action audience.

## Storage and settlement boundary

This example keeps nonces and grants in one process. It provides no durable sessions or production deployment.
For a durable service, consume the nonce and execute the action within one database transaction.
Handle expiry and concurrent requests inside that transaction. Retain the signature, action-binding, and evidence checks.
An RPC read gives an off-chain snapshot. For on-chain actions, enforce the relevant account state and policy inside the action transaction.

The tests establish behavior for synthetic fixtures. They do not establish real sensor capture, uniqueness, hardware assurance, or an external application deployment.
