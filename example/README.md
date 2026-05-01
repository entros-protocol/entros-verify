# `@entros/verify` example integrator

A minimal Vite + React 19 app that wires `<EntrosVerify>` against a localhost
popup host. Use this for end-to-end development and as a reference when
embedding the package in a real integrator.

## Prerequisites

- Node 20+
- Phantom (or any Solana wallet) on devnet with some devnet SOL
- The Entros popup host running locally on port 3000 (the `entros.io` repo, route `/embed/verify-popup`)

## Run

From this directory:

```bash
npm install
npm run dev
```

The app starts on `http://localhost:3001`. Open it, click **Verify with Entros**,
and walk through the flow in the popup window.

## What it does

- Renders `<EntrosVerify baseOrigin="http://localhost:3000" integratorKey="jupiter" cluster="devnet" />`
- Logs every `onVerified` / `onError` / `onProgress` callback into a streaming event log
- On success, polls the returned `attestation_pda` on devnet for up to 60 seconds and reports when the SAS attestation account appears
- Links the returned `tx_sig` to Solana Explorer

## Notes

- `baseOrigin` is the package's documented internal override for localhost development. Production consumers omit it; the package defaults to `https://entros.io`.
- The `integrator=jupiter` value is just a registered key; the popup host accepts any localhost origin in dev mode regardless of which key you pass.
- This folder is gitignored at the dist + node_modules level; the source is committed as integrator reference.
