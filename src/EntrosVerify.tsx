/**
 * <EntrosVerify> — drop-in trigger for the Entros verification popup.
 *
 * Renders a button. On click, opens a popup window to entros.io. User
 * completes wallet-connected verification inside the popup; the popup
 * posts the result back via postMessage; this component fires the
 * integrator's onVerified callback.
 *
 * See README and `EntrosVerifyProps` for usage.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { CSSProperties, ReactElement, ReactNode } from "react";

import { openVerifyPopup, type PopupHandle } from "./popup-manager";
import type {
  Cluster,
  EntrosVerifyError,
  EntrosVerifyErrorReason,
  EntrosVerifyProgress,
  EntrosVerifyResult,
} from "./types";

const DEFAULT_BASE_ORIGIN = "https://entros.io";
const DEFAULT_POPUP_WIDTH = 480;
const DEFAULT_POPUP_HEIGHT = 720;
/**
 * After a verification settles (done or error), state returns to idle so
 * the component is ready for re-use without consumer intervention. Long
 * enough to render the brief "done" / "error" UX without blocking re-clicks.
 */
const SETTLE_RESET_MS = 1500;

export interface EntrosVerifyProps {
  /** Integrator key registered with Entros. Required. */
  integratorKey: string;
  /** Solana cluster. Defaults to "devnet". v1 supports devnet only. */
  cluster?: Cluster;
  /**
   * Optional Trust Score floor. The popup runs the verification regardless
   * and reports the result; if `minTrustScore` is set and the resulting
   * score is below it, the popup posts `entros/error` with reason
   * `validation_failed` instead of `entros/verified`.
   */
  minTrustScore?: number;
  /** Called on successful verification. Required. */
  onVerified: (result: EntrosVerifyResult) => void;
  /** Called on any failure or cancellation. Optional. */
  onError?: (error: EntrosVerifyError) => void;
  /** Called on progress heartbeats from the popup. Optional. */
  onProgress?: (progress: EntrosVerifyProgress) => void;
  /** Popup width in CSS pixels. Defaults to 480. */
  popupWidth?: number;
  /** Popup height in CSS pixels. Defaults to 720. */
  popupHeight?: number;
  /**
   * Maximum time the popup is allowed to be open before this component
   * fires onError({reason: "timeout"}). Defaults to 9 minutes.
   */
  timeoutMs?: number;
  /** Custom button content. Defaults to "Verify with Entros". */
  children?: ReactNode;
  /** className applied to the trigger button. */
  className?: string;
  /** Inline style applied to the trigger button. */
  style?: CSSProperties;
  /**
   * If true, when the popup is blocked the component renders an inline
   * retry button. Clicking it triggers a fresh window.open from a confirmed
   * user gesture, which most browsers allow. Defaults to true.
   */
  popupBlockedFallback?: boolean;
  /**
   * INTERNAL: Override the entros.io base origin. Intended for end-to-end
   * testing against a localhost popup host. Production consumers should
   * not set this.
   */
  baseOrigin?: string;
}

type State =
  | { kind: "idle" }
  | { kind: "opening" }
  | { kind: "blocked" }
  | { kind: "waiting" }
  | { kind: "done" }
  | { kind: "error"; reason: EntrosVerifyErrorReason };

export function EntrosVerify(props: EntrosVerifyProps): ReactElement {
  const [state, setState] = useState<State>({ kind: "idle" });
  const handleRef = useRef<PopupHandle | null>(null);
  const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Refs hold the latest callbacks so trigger stays stable across re-renders
  // even when consumers pass inline arrow functions. Avoids unnecessary
  // re-creation of the click handler on every parent render.
  const onVerifiedRef = useRef(props.onVerified);
  const onErrorRef = useRef(props.onError);
  const onProgressRef = useRef(props.onProgress);
  useEffect(() => {
    onVerifiedRef.current = props.onVerified;
    onErrorRef.current = props.onError;
    onProgressRef.current = props.onProgress;
  });

  // Tear down any in-flight popup + reset timer on unmount.
  useEffect(() => {
    return () => {
      if (handleRef.current) {
        handleRef.current.cancel();
        handleRef.current = null;
      }
      if (resetTimerRef.current !== null) {
        clearTimeout(resetTimerRef.current);
        resetTimerRef.current = null;
      }
    };
  }, []);

  const scheduleReset = useCallback(() => {
    if (resetTimerRef.current !== null) {
      clearTimeout(resetTimerRef.current);
    }
    resetTimerRef.current = setTimeout(() => {
      resetTimerRef.current = null;
      setState({ kind: "idle" });
    }, SETTLE_RESET_MS);
  }, []);

  const trigger = useCallback(() => {
    if (resetTimerRef.current !== null) {
      clearTimeout(resetTimerRef.current);
      resetTimerRef.current = null;
    }
    setState({ kind: "opening" });

    const handle = openVerifyPopup({
      baseOrigin: props.baseOrigin ?? DEFAULT_BASE_ORIGIN,
      integratorKey: props.integratorKey,
      cluster: props.cluster ?? "devnet",
      minTrustScore: props.minTrustScore,
      popupWidth: props.popupWidth ?? DEFAULT_POPUP_WIDTH,
      popupHeight: props.popupHeight ?? DEFAULT_POPUP_HEIGHT,
      timeoutMs: props.timeoutMs,
      onVerified: (result) => {
        handleRef.current = null;
        setState({ kind: "done" });
        onVerifiedRef.current(result);
        scheduleReset();
      },
      onError: (error) => {
        handleRef.current = null;
        setState({ kind: "error", reason: error.reason });
        onErrorRef.current?.(error);
        scheduleReset();
      },
      onProgress: (progress) => {
        onProgressRef.current?.(progress);
      },
    });

    if (handle === null) {
      setState({ kind: "blocked" });
      onErrorRef.current?.({ reason: "popup_blocked" });
      return;
    }

    handleRef.current = handle;
    setState({ kind: "waiting" });
  }, [
    props.baseOrigin,
    props.cluster,
    props.integratorKey,
    props.minTrustScore,
    props.popupHeight,
    props.popupWidth,
    props.timeoutMs,
    scheduleReset,
  ]);

  const isWaiting = state.kind === "opening" || state.kind === "waiting";
  const showFallback =
    state.kind === "blocked" && (props.popupBlockedFallback ?? true);

  return (
    <div className="entros-verify-container" data-state={state.kind}>
      <button
        type="button"
        onClick={trigger}
        disabled={isWaiting}
        className={props.className}
        style={props.style}
      >
        {isWaiting
          ? "Verifying…"
          : (props.children ?? "Verify with Entros")}
      </button>
      {showFallback && (
        <div role="alert" className="entros-verify-blocked">
          <span>Popup blocked. </span>
          <button type="button" onClick={trigger} className={props.className}>
            Click here to open verification
          </button>
        </div>
      )}
    </div>
  );
}
