/**
 * Public type surface for `@entros/verify`.
 *
 * Wire format (popup → parent via postMessage) uses snake_case
 * (`wallet_pubkey`); the JS API surfaced to integrators uses camelCase
 * (`walletPubkey`). The popup-manager layer translates between them.
 */

import type { PolicyReason, PolicyResult, PolicyWireResult } from "./policy";

export type Cluster = "devnet";

/** Result delivered to the integrator's onVerified callback. */
export interface EntrosVerifyResult {
  walletPubkey: string;
  attestationPda: string | null;
  txSig: string;
  trustScore: number;
  cluster: Cluster;
  policy: PolicyResult & { decision: "allow" };
}

/**
 * Opaque error categories. Specific server-side reason codes never reach
 * the client (per the public-copy specificity rule in the org).
 */
export type EntrosVerifyErrorReason =
  | "wallet_rejected"
  | "validation_failed"
  | "network_error"
  | "user_canceled"
  | "origin_invalid"
  | "popup_blocked"
  | "timeout"
  | "unknown";

export interface EntrosVerifyError {
  reason: EntrosVerifyErrorReason;
  policyReason?: PolicyReason;
}

export type EntrosVerifyProgressStatus =
  | "wallet_connecting"
  | "capturing"
  | "proving"
  | "submitting"
  | "attesting";

export interface EntrosVerifyProgress {
  status: EntrosVerifyProgressStatus;
}

// ---------------------------------------------------------------------------
// postMessage envelope (wire format — snake_case)
// ---------------------------------------------------------------------------

export type EntrosMessageType =
  | "entros/verified"
  | "entros/error"
  | "entros/heartbeat";

export interface EntrosMessage<TPayload = unknown> {
  version: 1;
  source: "entros";
  type: EntrosMessageType;
  request_id: string;
  timestamp: number;
  payload: TPayload;
}

export interface VerifiedPayload {
  wallet_pubkey: string;
  attestation_pda: string | null;
  tx_sig: string;
  trust_score: number;
  cluster: Cluster;
  policy?: PolicyWireResult;
}

export interface ErrorPayload {
  reason: EntrosVerifyErrorReason;
  policy_reason?: PolicyReason;
}

export interface HeartbeatPayload {
  status: EntrosVerifyProgressStatus;
}
