/**
 * Type guards and validation for postMessage envelopes received from the
 * Entros verify popup. The component is the trust boundary — every message
 * arriving on `window` is hostile until proven otherwise.
 *
 * Validation order in popup-manager.ts:
 *   1. event.origin matches expected popup origin (caller's responsibility)
 *   2. isEntrosMessage(event.data)
 *   3. event.data.request_id matches the parent's expected ID
 *   4. isFreshMessage(event.data)
 *   5. payload-specific guard for the message type
 *
 * Skipping any step is a security regression.
 */

import type {
  EntrosMessage,
  ErrorPayload,
  HeartbeatPayload,
  VerifiedPayload,
} from "./types";

/**
 * Maximum allowed clock drift between popup and parent. 90 seconds.
 *
 * The popup completes verification in seconds. A tighter window narrows
 * replay surface without affecting legitimate flows. The 9-minute
 * popup-open timeout is enforced separately by popup-manager.
 */
const MAX_TIMESTAMP_DRIFT_MS = 90 * 1000;

/** Allowed error reason values on the wire. */
const ERROR_REASONS = new Set<string>([
  "wallet_rejected",
  "validation_failed",
  "network_error",
  "user_canceled",
  "origin_invalid",
  "popup_blocked",
  "timeout",
  "unknown",
]);

const HEARTBEAT_STATUSES = new Set<string>([
  "wallet_connecting",
  "capturing",
  "proving",
  "submitting",
  "attesting",
]);

const ENTROS_MESSAGE_TYPES = new Set<string>([
  "entros/verified",
  "entros/error",
  "entros/heartbeat",
]);

const CLUSTERS = new Set<string>(["devnet"]);

export function isEntrosMessage(data: unknown): data is EntrosMessage {
  if (typeof data !== "object" || data === null) return false;
  const msg = data as Record<string, unknown>;
  return (
    msg.source === "entros" &&
    msg.version === 1 &&
    typeof msg.type === "string" &&
    ENTROS_MESSAGE_TYPES.has(msg.type) &&
    typeof msg.request_id === "string" &&
    msg.request_id.length > 0 &&
    typeof msg.timestamp === "number" &&
    Number.isFinite(msg.timestamp) &&
    "payload" in msg
  );
}

export function isFreshMessage(msg: EntrosMessage, now: number = Date.now()): boolean {
  return Math.abs(now - msg.timestamp) < MAX_TIMESTAMP_DRIFT_MS;
}

export function isVerifiedPayload(payload: unknown): payload is VerifiedPayload {
  if (typeof payload !== "object" || payload === null) return false;
  const p = payload as Record<string, unknown>;
  return (
    typeof p.wallet_pubkey === "string" &&
    p.wallet_pubkey.length > 0 &&
    typeof p.attestation_pda === "string" &&
    p.attestation_pda.length > 0 &&
    typeof p.tx_sig === "string" &&
    p.tx_sig.length > 0 &&
    typeof p.trust_score === "number" &&
    Number.isFinite(p.trust_score) &&
    p.trust_score >= 0 &&
    typeof p.cluster === "string" &&
    CLUSTERS.has(p.cluster)
  );
}

export function isErrorPayload(payload: unknown): payload is ErrorPayload {
  if (typeof payload !== "object" || payload === null) return false;
  const p = payload as Record<string, unknown>;
  return typeof p.reason === "string" && ERROR_REASONS.has(p.reason);
}

export function isHeartbeatPayload(payload: unknown): payload is HeartbeatPayload {
  if (typeof payload !== "object" || payload === null) return false;
  const p = payload as Record<string, unknown>;
  return typeof p.status === "string" && HEARTBEAT_STATUSES.has(p.status);
}
