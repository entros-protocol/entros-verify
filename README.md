# `@entros/verify` and `entros-verify`

[![npm version](https://img.shields.io/npm/v/@entros/verify.svg)](https://www.npmjs.com/package/@entros/verify)

Pure-MIT TypeScript (`@entros/verify@1.0.0`) and Python (`entros-verify@1.0.0`) SDKs for the Entros Live Human-Presence and Consent Firewall across Voice-AI and autonomous MCP agents.

Source: [github.com/entros-protocol/entros-verify](https://github.com/entros-protocol/entros-verify) | Docs and product: [entros.io](https://entros.io)

## What this package does

`@entros/verify` binds real-time zero-retention voice liveness and hardware Passkey (`WebAuthn UV`) step-up approvals to single-use, `RFC 8785` canonical action permits (`Entros-Agent-Permit-v2`), with `IETF SCITT` (`RFC 9943`) transparency receipts and native MCP / Voice-AI adapters.

- **Headless 3-dependency pure-MIT core:** `@noble/curves`, `@noble/hashes`, and `jose`. Zero GPL, AGPL, LGPL, or MPL runtime dependencies (`npm run check-licenses -- --clean-room`).
- **React is optional:** `react` and `react-dom` are optional peers isolated strictly under `@entros/verify/react`. Node.js, Bun, Deno, Cloudflare Workers, and Vercel Edge runtimes import `.`, `./voice`, `./permit`, `./mcp`, `./browser-signals`, `./solana`, `./policy`, and `./agent-permit` without React.
- **No wallets or tokens required for v2:** Enterprise Voice-AI and MCP deployments use standard HTTPS APIs, Ed25519 JWKS, OIDC/OAuth 2.1, and WebAuthn Passkeys. Preserved v1 Solana devnet readers and v1 wallet permits remain available under `@entros/verify/solana`, `@entros/verify/policy`, and `@entros/verify/agent-permit`.

## Scope and assurance boundary

- **Voice liveness vs caller identity:** A signed `VoiceLivenessVerdict` (`entros-voice-liveness+jwt`) evidences acoustic liveness for a scored audio window under a pinned `model_version` and `operating_profile` (`webrtc_16k`, `telephony_8k`, or `wideband_clean`) with mandatory `retention: "memory_only"`. It does not identify a caller's legal identity or store a voiceprint database. Caller identity comes from your authenticated session (`sub`) or a hardware Passkey assertion (`WebAuthn UV`).
- **Empirical detection scope:** Detection performance depends on the pinned server `model_version` and codec operating profile. Entros makes no general deepfake immunity or unspoofable guarantee. Uncertain audio (`suspicious` or `insufficient_signal`) routes to hardware Passkey step-up rather than silent fallback.
- **WebAuthn boundary:** Standard `navigator.credentials.get()` verifies hardware-backed user verification (`UP=1`, `UV=1`) over the `permit_challenge` at `expectedOrigin`. It does not guarantee hardware-screen display of tool JSON without W3C Secure Payment Confirmation or a native trusted signing UI.
- **Passive browser telemetry:** `@entros/verify/browser-signals` produces additive telemetry tagged `assurance_tier: "passive_browser_risk"` and `standalone_consent: false`. It never satisfies voice or cryptographic Passkey policies.

## Install

### TypeScript / JavaScript

```bash
npm install @entros/verify
```

### Python (`>= 3.11`)

```bash
pip install entros-verify
# Optional first-party Voice-AI and agent framework adapters:
pip install "entros-verify[mcp,langgraph]"
pip install livekit-plugins-entros pipecat-entros
```

## Subpath exports (`@entros/verify`)

| Subpath | Purpose | React required |
| --- | --- | --- |
| `@entros/verify` | Headless v2 root (`EntrosClient`, `verifyAgentPermitV2`, `verifyVoiceLivenessVerdict`, `evaluatePolicyV2`, JCS, WebAuthn, SCITT, types) | No |
| `@entros/verify/voice` | Voice Liveness REST (`POST /v1/voice/analyze`) and WebSocket (`GET /v1/voice/stream`) clients plus offline `VoiceLivenessVerdict` verifier | No |
| `@entros/verify/permit` | Zero-dep `RFC 8785` JCS, strict `zip215: false` EdDSA JWS verifier, `Policy v2`, zero-CBOR P-256 WebAuthn verifier (`lowS: false`), `RFC 9449` DPoP, zero-dep CBOR-subset `IETF SCITT` verifier, bounded Ed25519 JWKS cache, and `/v1/permits/*` client | No |
| `@entros/verify/mcp` | `MCP 2026-07-28` stateless `InputRequiredResult` (MRTR), `MCP 2025-11-25` `SEP-1036` URL-Mode Elicitation, HTTP `403 insufficient_scope`, OpenAI Responses v2, Vercel AI SDK `toolApproval`, LiveKit/Vapi/Retell webhook guards, atomic `PermitNonceStoreV2`, and preserved v1 helpers | No |
| `@entros/verify/browser-signals` | Optional additive `passive_browser_risk` telemetry helper (never standalone consent) | No |
| `@entros/verify/solana` | Preserved pure-MIT Solana devnet chain readers | No |
| `@entros/verify/policy` | Preserved v1 Integrator Policy evaluator | No |
| `@entros/verify/agent-permit` | Preserved v1 Agent Operator Permit evaluator | No |
| `@entros/verify/react` | Optional React components (`EntrosPasskeyApprove` and legacy `EntrosVerify`) with `"use client"` | Yes |

## Quickstart: Verify an `Entros-Agent-Permit-v2` offline

```ts
import {
  createJwksCache,
  InMemoryPermitNonceStoreV2,
  verifyAgentPermitV2,
  type PolicyV2,
} from "@entros/verify";

const jwks = createJwksCache({
  jwksUrl: "https://api.entros.io/.well-known/jwks.json",
  ttlSeconds: 300,
  negativeCacheSeconds: 10,
});
const nonceStore = new InMemoryPermitNonceStoreV2();

const policy: PolicyV2 = {
  policy_id: "wire-transfer-high-v2",
  version: 2,
  allowed_assurance_tiers: ["voice_plus_passkey", "passkey_webauthn_uv"],
  required_modalities: ["webauthn_uv"],
  max_evidence_age_seconds: 120,
  max_permit_lifetime_seconds: 300,
  require_continuity: true,
  require_dpop: true,
  require_scitt_receipt: true,
};

const result = await verifyAgentPermitV2({
  permitJws,
  policy,
  expectedAudience: "https://mcp.acme-bank.example/v1/mcp",
  action: {
    kind: "mcp.tool_call",
    server: "treasury-mcp",
    tool: "transfer_funds",
    arguments: { amount: 250, currency: "USD", recipient: "acct_9942" },
  },
  jwks,
  dpop: { proof: dpopHeader, htm: "POST", htu: "https://mcp.acme-bank.example/v1/mcp" },
  nonceStore,
});

if (result.decision !== "allow") {
  throw new Error(`Denied: ${result.reason}`);
}
```

All non-mutating cryptographic, expiry, digest, policy, voice, WebAuthn, DPoP, and SCITT checks run before `nonceStore.consume()` is invoked. Failed probes never burn valid pending nonces.

## Quickstart: MCP `2026-07-28` Stateless MRTR Gate

```ts
import { createStatelessMcpApprovalGate } from "@entros/verify/mcp";

const gate = createStatelessMcpApprovalGate({
  audience: "https://mcp.acme-bank.example/v1/mcp",
  policy,
  jwks,
  stateSecret: process.env.ENTROS_MRTR_SECRET!,
});

// Round 1: return InputRequiredResult without exposing credentials to the LLM.
const challenge = await gate.createInputRequiredResult({
  action: {
    kind: "mcp.tool_call",
    server: "treasury-mcp",
    tool: "transfer_funds",
    arguments: { amount: 250, currency: "USD", recipient: "acct_9942" },
  },
});

// Round 2: any stateless replica verifies requestState HMAC + permit + atomic jti.
const verification = await gate.verifyInputResponse({
  action: retriedAction,
  requestState: retriedRequestState,
  inputResponses: retriedInputResponses,
});
```

For `MCP 2025-11-25` clients, use `createUrlElicitationChallenge` (`SEP-1036`, `mode: "url"`) and `formatInsufficientScopeHeader` (`HTTP 403` scope-union). For Vercel AI SDK tools, use `createVercelToolApprovalGate` targeting `toolApproval: "user-approval"`.

## Quickstart: Voice-AI Webhook Guards (LiveKit, Vapi, Retell)

```ts
import { createLiveKitToolGuard } from "@entros/verify/mcp";

const guard = createLiveKitToolGuard({
  server: "voice-banking",
  audience: "https://mcp.acme-bank.example/v1/mcp",
  policy,
  jwks,
});

const verdict = await guard.guardToolCall({
  roomName: "bank_room_8831",
  participantIdentity: "caller_01",
  sessionId: "lk_room_bank_8831_caller_01",
  toolName: "transfer_funds",
  args: { amount: 250, currency: "USD" },
  voiceVerdictJws: latestSessionVerdictJws,
});
```

Raw un-denoised audio should always be streamed to `/v1/voice/stream` before any neural denoiser or STT stage. When a session verdict returns `suspicious` or `insufficient_signal`, the guard returns `status: "step_up_required"` for hardware Passkey fallback.

## Hardware Passkey Verification (`@entros/verify/permit` and `@entros/verify/react`)

Hardware FIDO2 authenticators emit ASN.1 DER ECDSA P-256 signatures with arbitrary `s` in `[1, n - 1]`, including high-S signatures (`s > n / 2`). `verifyWebAuthnAssertionV2` verifies DER signatures with `{ format: "der", lowS: false, prehash: true }` without any CBOR dependency and requires `UP=1` and `UV=1`.

In React apps, render `<EntrosPasskeyApprove>` from `@entros/verify/react`:

```tsx
import { EntrosPasskeyApprove } from "@entros/verify/react";

<EntrosPasskeyApprove
  jti={challenge.metadata.jti}
  requestDigest={challenge.metadata.request_digest}
  rpId="approve.entros.io"
  onApproved={(assertion) => submitAssertion(assertion)}
/>;
```

## Preserved v1 Solana Devnet and Browser Popup Surfaces

- `@entros/verify/solana` provides zero-GPL Solana devnet chain readers (`readIntegratorEvidence`, `readAgentState`, `verifyEntrosAttestation`, `findLatestVerificationTransaction`).
- `@entros/verify/policy` and `@entros/verify/agent-permit` remain byte-compatible with v1 devnet integrators.
- `@entros/verify/react` retains `<EntrosVerify>` for the legacy devnet popup flow; `evaluateWarmPolicyReuse` stays exported from the headless root.
- Legacy HumanLayer v1 exports in `@entros/verify/mcp` remain exported for backwards compatibility and are marked `@deprecated` following upstream discontinuation.

## Shared Cross-Language Parity Suite

Deterministic fixtures under `spec/vectors/agent-permit-v2/` (excluded from npm tarballs) validate identical digests, signatures, and refusal codes across TypeScript (`vitest`), Python (`pytest`), and Rust (`cargo test`):

- `jcs-vectors.json`: `RFC 8785` UTF-16 sorting (`U+1D11E` before `U+E000`), ES6 floats, lone-surrogate and depth-33 rejections.
- `jws-eddsa-vectors.json`: Strict `zip215: false` EdDSA JWS checks, small-order key rejection, `S >= L` scalar rejection, forbidden headers, unknown/revoked `kid`, and `retention: "memory_only"`.
- `webauthn-p256-vectors.json`: Low-S and high-S DER P-256 assertions, `UP`/`UV` flags, `rpIdHash`, origin, challenge, and `signCount` rollback checks.
- `scitt-receipt-vectors.json`: Definite-length CBOR Tag `18` `COSE_Sign1` receipts (`headers 1, 4, 395, 396`) and `RFC 9162` Merkle inclusion proofs.
- `policy-v2-vectors.json`: All 7 `assurance_tier` values, anti-downgrade refusals, freshness monotonicity, partial-spoof spans, consistency drift, DPoP `cnf.jkt`, non-mutating prechecks, and 32-way concurrent `jti` replay races.

## Development and Verification

```bash
npm run typecheck
npm test
npm run check-licenses -- --clean-room
npm run build
npm run verify-publish-contents
npm audit --omit=dev --audit-level=high
```

## License

MIT.
