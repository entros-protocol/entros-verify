/**
 * Popup-window state machine for `<EntrosVerify>`.
 *
 * Owns: window.open, postMessage listener, popup.closed polling, timeout.
 * Boundary with the React layer: open → returns a handle (or null if blocked).
 * Component is responsible for rendering the trigger button and the
 * popup-blocked fallback UI.
 *
 * Security model — every postMessage from the popup is treated as hostile
 * until proven otherwise. Validation order (skipping any step is a
 * regression):
 *   1. event.origin === expectedPopupOrigin
 *   2. event.source === popup (the window we opened, not a sibling tab)
 *   3. envelope shape matches `EntrosMessage` (version, source, type)
 *   4. event.data.request_id === this popup's request_id (replay defense)
 *   5. timestamp within drift window (90s)
 *   6. payload-specific guard for the message type
 */

import {
  isEntrosMessage,
  isErrorPayload,
  isFreshMessage,
  isHeartbeatPayload,
  isVerifiedPayload,
} from "./messaging";
import type {
  Cluster,
  EntrosVerifyError,
  EntrosVerifyErrorReason,
  EntrosVerifyProgress,
  EntrosVerifyResult,
} from "./types";
import { buildPopupUrl, generateRequestId } from "./url";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const POPUP_CLOSED_POLL_MS = 500;

/**
 * Grace period after detecting popup.closed before firing user_canceled.
 * Lets the final `entros/verified` message arrive when the popup posts
 * and self-closes within the same event-loop turn.
 */
const POPUP_CLOSED_GRACE_MS = 1500;

/**
 * After a popup-emitted outcome (`entros/verified` or `entros/error`),
 * the popup owns its own close — its success / failure surface renders
 * and either self-closes or waits for explicit user action (e.g., the
 * baseline-stale recovery surface). The parent only force-closes after
 * this defensive fallback in case the popup fails to close itself.
 * Generous enough to allow interactive failure surfaces to be read and
 * acted on; short enough that an abandoned popup eventually dies.
 */
const POPUP_OWNED_FALLBACK_CLOSE_MS = 30_000;

export interface OpenPopupOptions {
  baseOrigin: string;
  integratorKey: string;
  cluster: Cluster;
  minTrustScore?: number;
  popupWidth: number;
  popupHeight: number;
  timeoutMs?: number;
  onVerified: (result: EntrosVerifyResult) => void;
  onError: (error: EntrosVerifyError) => void;
  onProgress?: (progress: EntrosVerifyProgress) => void;
}

export interface PopupHandle {
  /**
   * Force-cancel the popup. Closes the window if still open, fires
   * onError({reason: "user_canceled"}), and tears down listeners.
   * Idempotent.
   */
  cancel: () => void;
}

export function openVerifyPopup(opts: OpenPopupOptions): PopupHandle | null {
  if (typeof window === "undefined") {
    throw new Error("openVerifyPopup must be called in a browser context");
  }

  const requestId = generateRequestId();
  const parentOrigin = window.location.origin;
  const url = buildPopupUrl({
    baseOrigin: opts.baseOrigin,
    integratorKey: opts.integratorKey,
    parentOrigin,
    cluster: opts.cluster,
    requestId,
    minTrustScore: opts.minTrustScore,
  });

  const left = Math.max(
    0,
    Math.floor((window.screen.availWidth - opts.popupWidth) / 2),
  );
  const top = Math.max(
    0,
    Math.floor((window.screen.availHeight - opts.popupHeight) / 2),
  );
  const features = [
    `width=${opts.popupWidth}`,
    `height=${opts.popupHeight}`,
    `left=${left}`,
    `top=${top}`,
    "menubar=no",
    "toolbar=no",
    // location=yes lets the user verify entros.io in the URL bar.
    "location=yes",
    "status=no",
    "resizable=yes",
    "scrollbars=yes",
  ].join(",");

  // Unique window name per popup. A fixed name causes collision when an
  // integrator renders multiple <EntrosVerify> on one page — the second
  // window.open would reuse the existing popup.
  const popupName = `entros_verify_${requestId}`;
  const rawPopup = window.open(url, popupName, features);
  if (!rawPopup || rawPopup.closed) {
    return null;
  }
  // Narrow once so closures below see the non-null type.
  const popup: Window = rawPopup;

  const expectedPopupOrigin = new URL(opts.baseOrigin).origin;

  let settled = false;
  let pollTimerId: ReturnType<typeof setInterval> | null = null;
  let timeoutTimerId: ReturnType<typeof setTimeout> | null = null;
  let popupClosedAtMs: number | null = null;

  function clearListenersAndTimers(): void {
    window.removeEventListener("message", onMessage);
    if (pollTimerId !== null) {
      clearInterval(pollTimerId);
      pollTimerId = null;
    }
    if (timeoutTimerId !== null) {
      clearTimeout(timeoutTimerId);
      timeoutTimerId = null;
    }
  }

  function forceClosePopup(): void {
    if (popup && !popup.closed) {
      try {
        popup.close();
      } catch {
        // Defensive only. We opened this window so we own the close permission;
        // this branch is for esoteric extension or browser-quirk edge cases.
      }
    }
  }

  function settleVerified(result: EntrosVerifyResult): void {
    if (settled) return;
    settled = true;
    // The popup owns its own close on the verified path so its
    // recognition surface (`Verified.` checkmark) is visible to the user
    // before the window dies. Parent only force-closes as a defensive
    // fallback in case the popup fails to close itself.
    clearListenersAndTimers();
    setTimeout(forceClosePopup, POPUP_OWNED_FALLBACK_CLOSE_MS);
    opts.onVerified(result);
  }

  /**
   * @param forceImmediateClose
   *   - false (default) — error came from a popup-emitted `entros/error`
   *     message; the popup is still alive and rendering its own
   *     `PopupFailure` (auto-close) or interactive recovery surface
   *     (e.g., baseline-stale). Parent waits the fallback window before
   *     force-closing so the user sees the failure category.
   *   - true — error came from the parent (timeout, user cancel, or
   *     polling detected the popup already closed). No popup-side
   *     surface to preserve; force-close immediately.
   */
  function settleError(
    reason: EntrosVerifyErrorReason,
    forceImmediateClose = false,
  ): void {
    if (settled) return;
    settled = true;
    clearListenersAndTimers();
    if (forceImmediateClose) {
      forceClosePopup();
    } else {
      setTimeout(forceClosePopup, POPUP_OWNED_FALLBACK_CLOSE_MS);
    }
    opts.onError({ reason });
  }

  function onMessage(event: MessageEvent): void {
    if (settled) return;

    // Origin gate — first and most important check.
    if (event.origin !== expectedPopupOrigin) return;

    // Source gate — defense-in-depth against another same-origin tab on
    // entros.io (e.g., the standalone /verify route open in a sibling tab)
    // posting a forged message. Only the popup we opened is authoritative.
    if (event.source !== popup) return;

    if (!isEntrosMessage(event.data)) return;

    // Replay protection — request_id must match this popup's ID.
    if (event.data.request_id !== requestId) return;

    if (!isFreshMessage(event.data)) return;

    switch (event.data.type) {
      case "entros/verified": {
        if (isVerifiedPayload(event.data.payload)) {
          settleVerified({
            walletPubkey: event.data.payload.wallet_pubkey,
            attestationPda: event.data.payload.attestation_pda,
            txSig: event.data.payload.tx_sig,
            trustScore: event.data.payload.trust_score,
            cluster: event.data.payload.cluster,
          });
        }
        break;
      }
      case "entros/error": {
        if (isErrorPayload(event.data.payload)) {
          settleError(event.data.payload.reason);
        }
        break;
      }
      case "entros/heartbeat": {
        if (isHeartbeatPayload(event.data.payload) && opts.onProgress) {
          opts.onProgress({ status: event.data.payload.status });
        }
        break;
      }
    }
  }

  function onPoll(): void {
    if (settled) return;
    if (popup.closed) {
      // Start the grace period the first time we observe the close.
      if (popupClosedAtMs === null) {
        popupClosedAtMs = Date.now();
        return;
      }
      if (Date.now() - popupClosedAtMs >= POPUP_CLOSED_GRACE_MS) {
        settleError("user_canceled", true);
      }
    } else {
      popupClosedAtMs = null;
    }
  }

  function onTimeout(): void {
    settleError("timeout", true);
  }

  window.addEventListener("message", onMessage);
  pollTimerId = setInterval(onPoll, POPUP_CLOSED_POLL_MS);
  timeoutTimerId = setTimeout(onTimeout, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  return {
    cancel: () => settleError("user_canceled", true),
  };
}
