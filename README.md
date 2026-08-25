# `@entros/verify`

[![npm version](https://img.shields.io/npm/v/@entros/verify.svg)](https://www.npmjs.com/package/@entros/verify)

React component for Entros verification on Solana devnet. It opens the Entros popup and reports a completed wallet-connected verification.

Source: [github.com/entros-protocol/entros-verify](https://github.com/entros-protocol/entros-verify) · Hosted by [entros.io](https://entros.io).

```bash
npm install @entros/verify
```

## Five-line usage

```tsx
import { EntrosVerify } from "@entros/verify";

<EntrosVerify
  integratorKey="your-integrator-key"
  onVerified={(result) => unlockClaim(result.walletPubkey)}
/>
```

## Result shape

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

```tsx
<EntrosVerify
  integratorKey="your-integrator-key" // required
  cluster="devnet"                    // only supported cluster
  minTrustScore={200}               // optional floor on verification history
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

## v1 limitations

- Devnet only. Mainnet support is planned after the protocol clears its release gates.
- Hardcoded integrator allowlist on the entros.io side. Self-serve integrator onboarding is planned.
- Mobile browsers may open the popup as a new tab rather than a windowed popup. Native mobile support via Mobile Wallet Adapter is not yet implemented in this component; see [`entros-mobile`](https://github.com/entros-protocol/entros-mobile) for the native Solana Mobile dApp.

## Integration safeguards

- Origin gate on every postMessage (`event.origin === "https://entros.io"`)
- Replay protection via per-popup `request_id`
- 9-minute default timeout
- Popup-blocked fallback with user-gesture retry
- Idempotent cancel
- React 19 typed strict-mode

## License

MIT.
