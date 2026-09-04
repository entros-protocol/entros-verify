# `@entros/verify`

[![npm version](https://img.shields.io/npm/v/@entros/verify.svg)](https://www.npmjs.com/package/@entros/verify)

React component for Entros verification on Solana devnet. It opens the Entros popup and reports a completed wallet-connected verification.

Source: [github.com/entros-protocol/entros-verify](https://github.com/entros-protocol/entros-verify) · Hosted by [entros.io](https://entros.io).

The published package remains `0.1.1`. The policy API below describes candidate source that requires package publication and a compatible hosted popup.
Do not deploy a consumer that requires this API before the popup release completes.

```bash
npm install @entros/verify
```

## Five-line usage

```tsx
import { EntrosVerify } from "@entros/verify";

<EntrosVerify
  integratorKey="your-integrator-key"
  onVerified={(result) => showVerificationResult(result)}
/>
```

## Published 0.1.1 result shape

```ts
interface EntrosVerifyResult {
  walletPubkey: string;        // base58 Solana pubkey
  attestationPda: string;      // derived SAS account address
  txSig: string;               // base58 verification tx signature
  trustScore: number;          // current Trust Score (0–10000)
  cluster: "devnet";
}
```

The callback reports a completed Entros verification and its derived attestation address. It does not independently prove physical presence.

SAS issuance is best-effort after wallet-connected verification. Check that the returned address contains an attestation account before relying on it.

## Full API

This example describes published version `0.1.1`. The candidate policy API follows below.

```tsx
<EntrosVerify
  integratorKey="your-integrator-key" // required
  cluster="devnet"                    // only supported cluster
  minTrustScore={200}               // reserved for the policy contract
  popupWidth={480}                  // CSS px, default 480
  popupHeight={720}                 // CSS px, default 720
  timeoutMs={9 * 60 * 1000}         // 9 min default
  popupBlockedFallback={true}       // inline retry UI when popup blocked
  className="..."                   // applied to trigger button
  style={{ ... }}
  onVerified={(r) => {}}            // required
  onError={(e) => {}}               // optional — covers cancel, reject, timeout, etc.
  onProgress={(p) => {}}            // optional — heartbeats from popup
>
  Verify with Entros                {/* custom button content */}
</EntrosVerify>
```

Version `0.1.1` forwards `minTrustScore` to the hosted flow. Do not use the
browser callback as an authorization boundary. Recheck current on-chain state
when the protected action settles.

## Error reasons

`onError` receives one of:

- `wallet_rejected` — user denied wallet connection or signing
- `validation_failed` — verification did not pass server-side checks
- `network_error` — popup encountered a network failure mid-flow
- `user_canceled` — user closed the popup before completing
- `origin_invalid` — integrator origin was not on the Entros allowlist
- `popup_blocked` — browser blocked `window.open()`
- `timeout` — popup remained open longer than `timeoutMs` without completing
- `unknown` — fallback for unexpected failure modes

Specific server-side rejection signals are deliberately not surfaced to the client.

## Candidate policy API

The candidate consumer requires a versioned policy result before calling `onVerified`.
It checks the original requirements, account observations, score, freshness, and matching result fields.
It rejects older popups that omit the policy result.

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

Without `policy`, the candidate uses a one-day verification age, a 90-second evaluation age, and optional SAS issuance.
The score floor defaults to zero or the supplied `minTrustScore`.
Supplying conflicting legacy and policy floors fails before the popup opens.

The candidate result adds `policy`, which includes the evaluated requirements, expiry, and typed evidence.
Its `attestationPda` is nullable. A non-null address identifies an account validated during evaluation.
`missing` and `unavailable` optional attestations carry no issued address. Invalid accounts fail the policy.
Required attestations must exist and remain valid through consumption.

The result states `browser_unattested` assurance and `unmeasured` uniqueness.
It makes no sensor-provenance or population-uniqueness claim.

The React-free `@entros/verify/policy` subpath exports `normalizePolicyRequest`, `evaluatePolicy`, and strict wire guards.
Pair the evaluator with Pulse's strict evidence reader against your service's configured RPC connection.
The evaluator accepts typed observations. It cannot authenticate observations supplied by a browser.

For protected actions, your service owns the policy and authenticates the wallet's signature over a one-use action challenge.
Bind the challenge to the wallet, action parameters, audience, and expiry.
Read current chain evidence before executing the action. Consume the challenge atomically with the action.
An on-chain action must enforce its requirements within the action transaction.

The popup retains transport envelope version `1` and negotiates the policy contract through separate request fields.
Older consumers receive their original payload types only after a valid attestation exists.
A popup rollback makes upgraded consumers reject results until compatible service returns.

## v1 limitations

- Devnet only. Mainnet support is planned after the protocol clears its release gates.
- The callback reports a completed flow. Integrator Policy v1 will define the
  fail-closed score, freshness, assurance, uniqueness, and attestation contract.
- Hardcoded integrator allowlist on the entros.io side. Self-serve integrator onboarding is planned.
- Mobile browsers may open the popup as a new tab rather than a windowed popup. Native mobile support via Mobile Wallet Adapter is not yet implemented in this component; see [`entros-mobile`](https://github.com/entros-protocol/entros-mobile) for the native Solana Mobile dApp.

## Integration safeguards

- Origin gate on every postMessage (`event.origin === "https://entros.io"`)
- Replay protection via per-popup `request_id`
- Parent timeout through [`timeoutMs`](#full-api)
- Popup-blocked fallback with user-gesture retry
- Idempotent cancel
- React 19 typed strict-mode

## License

MIT.
