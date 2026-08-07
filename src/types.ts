/**
 * Public type surface for `@entros/verify`.
 *
 * Wire format (popup → parent via postMessage) uses snake_case
 * (`wallet_pubkey`); the JS API surfaced to integrators uses camelCase
 * (`walletPubkey`). The popup-manager layer translates between them.
 */

export type Cluster = "devnet";

/** Result delivered to the integrator's onVerified callback. */
export interface EntrosVerifyResult {
  walletPubkey: string;
  attestationPda: string;
  txSig: string;
  trustScore: number;
  cluster: Cluster;
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
  attestation_pda: string;
  tx_sig: string;
  trust_score: number;
  cluster: Cluster;
}

export interface ErrorPayload {
  reason: EntrosVerifyErrorReason;
}

export interface HeartbeatPayload {
  status: EntrosVerifyProgressStatus;
}
