import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openVerifyPopup } from "../src/popup-manager";
import type { EntrosMessage } from "../src/types";

interface FakePopup {
  closed: boolean;
  close: ReturnType<typeof vi.fn>;
}

function makePopup(): FakePopup {
  return {
    closed: false,
    close: vi.fn(function (this: FakePopup) {
      this.closed = true;
    }),
  };
}

const baseOpts = {
  baseOrigin: "https://entros.io",
  integratorKey: "jupiter",
  cluster: "devnet" as const,
  popupWidth: 480,
  popupHeight: 720,
};

const POPUP_ORIGIN = "https://entros.io";

/**
 * Find the most recent request_id by inspecting the URL the test passed to
 * window.open. The component generates the ID internally; tests need to
 * mirror it back when posting messages.
 */
function getRequestIdFromOpenSpy(spy: ReturnType<typeof vi.fn>): string {
  const lastCall = spy.mock.calls[spy.mock.calls.length - 1];
  if (!lastCall) throw new Error("window.open was not called");
  const url = new URL(String(lastCall[0]));
  const id = url.searchParams.get("request_id");
  if (!id) throw new Error("request_id missing from popup URL");
  return id;
}

function postMessage(
  data: EntrosMessage,
  source: FakePopup,
  opts: { origin?: string } = {},
): void {
  const event = new MessageEvent("message", {
    data,
    origin: opts.origin ?? POPUP_ORIGIN,
    source: source as unknown as Window,
  });
  window.dispatchEvent(event);
}

describe("openVerifyPopup", () => {
  let openSpy: ReturnType<typeof vi.fn>;
  let popup: FakePopup;

  beforeEach(() => {
    popup = makePopup();
    openSpy = vi.fn(() => popup);
    window.open = openSpy as unknown as typeof window.open;
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it("calls window.open with the correct URL", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    expect(openSpy).toHaveBeenCalledOnce();
    const url = new URL(String(openSpy.mock.calls[0]?.[0]));
    expect(url.origin).toBe("https://entros.io");
    expect(url.pathname).toBe("/embed/verify-popup");
    expect(url.searchParams.get("integrator")).toBe("jupiter");
  });

  it("fires onVerified when popup posts entros/verified", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    const requestId = getRequestIdFromOpenSpy(openSpy);
    postMessage({
      version: 1,
      source: "entros",
      type: "entros/verified",
      request_id: requestId,
      timestamp: Date.now(),
      payload: {
        wallet_pubkey: "11111111111111111111111111111111",
        attestation_pda: "22222222222222222222222222222222",
        tx_sig: "abcd",
        trust_score: 250,
        cluster: "devnet",
      },
    }, popup);

    expect(onVerified).toHaveBeenCalledOnce();
    expect(onVerified).toHaveBeenCalledWith({
      walletPubkey: "11111111111111111111111111111111",
      attestationPda: "22222222222222222222222222222222",
      txSig: "abcd",
      trustScore: 250,
      cluster: "devnet",
    });
    expect(onError).not.toHaveBeenCalled();
    // Popup owns its own close on the verified path so its recognition
    // surface renders before the window dies. Parent does not force-close
    // synchronously; the defensive fallback fires after 5s.
    expect(popup.close).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30000);
    expect(popup.close).toHaveBeenCalled();
  });

  it("fires onError when popup posts entros/error", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    postMessage({
      version: 1,
      source: "entros",
      type: "entros/error",
      request_id: getRequestIdFromOpenSpy(openSpy),
      timestamp: Date.now(),
      payload: { reason: "wallet_rejected" },
    }, popup);

    expect(onError).toHaveBeenCalledWith({ reason: "wallet_rejected" });
    expect(onVerified).not.toHaveBeenCalled();
    // Popup-emitted errors are treated like verified: popup owns the close
    // so its `PopupFailure` surface can render. Parent fallback fires at 5s.
    expect(popup.close).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30000);
    expect(popup.close).toHaveBeenCalled();
  });

  it("fires onProgress on heartbeat", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    const onProgress = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError, onProgress });

    postMessage({
      version: 1,
      source: "entros",
      type: "entros/heartbeat",
      request_id: getRequestIdFromOpenSpy(openSpy),
      timestamp: Date.now(),
      payload: { status: "capturing" },
    }, popup);

    expect(onProgress).toHaveBeenCalledWith({ status: "capturing" });
    expect(onVerified).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Security: origin gate
  // -------------------------------------------------------------------------

  it("ignores messages from a wrong origin", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    const requestId = getRequestIdFromOpenSpy(openSpy);
    postMessage(
      {
        version: 1,
        source: "entros",
        type: "entros/verified",
        request_id: requestId,
        timestamp: Date.now(),
        payload: {
          wallet_pubkey: "x",
          attestation_pda: "x",
          tx_sig: "x",
          trust_score: 100,
          cluster: "devnet",
        },
      },
      popup,
      { origin: "https://evil.example.com" },
    );

    expect(onVerified).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Security: replay protection
  // -------------------------------------------------------------------------

  it("ignores messages with a mismatched request_id", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    postMessage({
      version: 1,
      source: "entros",
      type: "entros/verified",
      request_id: "WRONG_ID",
      timestamp: Date.now(),
      payload: {
        wallet_pubkey: "x",
        attestation_pda: "x",
        tx_sig: "x",
        trust_score: 100,
        cluster: "devnet",
      },
    }, popup);

    expect(onVerified).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Security: protocol version + source
  // -------------------------------------------------------------------------

  it("ignores messages with a non-entros source", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    const requestId = getRequestIdFromOpenSpy(openSpy);
    postMessage({
      // intentionally bad envelope to exercise the type guard
      version: 1,
      source: "phishing" as unknown as "entros",
      type: "entros/verified",
      request_id: requestId,
      timestamp: Date.now(),
      payload: {
        wallet_pubkey: "x",
        attestation_pda: "x",
        tx_sig: "x",
        trust_score: 100,
        cluster: "devnet",
      },
    } as EntrosMessage, popup);

    expect(onVerified).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Popup-blocked detection
  // -------------------------------------------------------------------------

  it("returns null when window.open returns null", () => {
    openSpy.mockReturnValue(null);
    const handle = openVerifyPopup({
      ...baseOpts,
      onVerified: vi.fn(),
      onError: vi.fn(),
    });
    expect(handle).toBeNull();
  });

  it("returns null when window.open returns an immediately-closed window", () => {
    const blockedPopup = makePopup();
    blockedPopup.closed = true;
    openSpy.mockReturnValue(blockedPopup);
    const handle = openVerifyPopup({
      ...baseOpts,
      onVerified: vi.fn(),
      onError: vi.fn(),
    });
    expect(handle).toBeNull();
  });

  // -------------------------------------------------------------------------
  // popup.closed polling + grace period
  // -------------------------------------------------------------------------

  it("fires user_canceled after grace period when popup is closed without a message", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    popup.closed = true;
    // First poll detects close and starts grace; second poll after 1500ms fires.
    vi.advanceTimersByTime(500); // first poll observes close
    expect(onError).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1500); // grace period elapses on next poll
    expect(onError).toHaveBeenCalledWith({ reason: "user_canceled" });
    expect(onVerified).not.toHaveBeenCalled();
  });

  it("does not fire user_canceled when verified message arrives just before close", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    const requestId = getRequestIdFromOpenSpy(openSpy);
    postMessage({
      version: 1,
      source: "entros",
      type: "entros/verified",
      request_id: requestId,
      timestamp: Date.now(),
      payload: {
        wallet_pubkey: "x",
        attestation_pda: "x",
        tx_sig: "x",
        trust_score: 100,
        cluster: "devnet",
      },
    }, popup);
    popup.closed = true;
    vi.advanceTimersByTime(3000);

    expect(onVerified).toHaveBeenCalledOnce();
    expect(onError).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Timeout
  // -------------------------------------------------------------------------

  it("fires timeout after the configured duration with no message", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({
      ...baseOpts,
      onVerified,
      onError,
      timeoutMs: 1000,
    });

    vi.advanceTimersByTime(1000);
    expect(onError).toHaveBeenCalledWith({ reason: "timeout" });
  });

  // -------------------------------------------------------------------------
  // Cancel handle
  // -------------------------------------------------------------------------

  it("cancel() fires user_canceled and closes the popup", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    const handle = openVerifyPopup({ ...baseOpts, onVerified, onError });

    expect(handle).not.toBeNull();
    handle?.cancel();

    expect(onError).toHaveBeenCalledWith({ reason: "user_canceled" });
    expect(popup.close).toHaveBeenCalled();
  });

  it("cancel() is idempotent", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    const handle = openVerifyPopup({ ...baseOpts, onVerified, onError });

    handle?.cancel();
    handle?.cancel();
    handle?.cancel();

    expect(onError).toHaveBeenCalledOnce();
  });

  // -------------------------------------------------------------------------
  // Source gate: same-origin tab spoofing defense
  // -------------------------------------------------------------------------

  it("ignores messages whose source is not the popup we opened", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    const requestId = getRequestIdFromOpenSpy(openSpy);
    // Synthesize a message that passes origin + envelope checks but comes
    // from a different Window source (e.g., a sibling entros.io tab).
    const otherWindow = {} as Window;
    const event = new MessageEvent("message", {
      data: {
        version: 1,
        source: "entros",
        type: "entros/verified",
        request_id: requestId,
        timestamp: Date.now(),
        payload: {
          wallet_pubkey: "x",
          attestation_pda: "x",
          tx_sig: "x",
          trust_score: 100,
          cluster: "devnet",
        },
      },
      origin: POPUP_ORIGIN,
      source: otherWindow,
    });
    window.dispatchEvent(event);

    expect(onVerified).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Stale messages
  // -------------------------------------------------------------------------

  it("ignores messages with a timestamp older than the drift window", () => {
    const onVerified = vi.fn();
    const onError = vi.fn();
    openVerifyPopup({ ...baseOpts, onVerified, onError });

    postMessage({
      version: 1,
      source: "entros",
      type: "entros/verified",
      request_id: getRequestIdFromOpenSpy(openSpy),
      timestamp: Date.now() - 10 * 60 * 1000, // 10 min ago — past 90s window
      payload: {
        wallet_pubkey: "x",
        attestation_pda: "x",
        tx_sig: "x",
        trust_score: 100,
        cluster: "devnet",
      },
    }, popup);

    expect(onVerified).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Multiple popups don't cross-talk
  // -------------------------------------------------------------------------

  it("two popups with different request IDs do not cross-respond", () => {
    const onVerifiedA = vi.fn();
    const onVerifiedB = vi.fn();
    const popupA = makePopup();
    const popupB = makePopup();
    openSpy.mockReturnValueOnce(popupA);
    openSpy.mockReturnValueOnce(popupB);

    openVerifyPopup({
      ...baseOpts,
      onVerified: onVerifiedA,
      onError: vi.fn(),
    });
    const idA = getRequestIdFromOpenSpy(openSpy);

    openVerifyPopup({
      ...baseOpts,
      onVerified: onVerifiedB,
      onError: vi.fn(),
    });
    const idB = getRequestIdFromOpenSpy(openSpy);

    expect(idA).not.toBe(idB);

    postMessage({
      version: 1,
      source: "entros",
      type: "entros/verified",
      request_id: idA,
      timestamp: Date.now(),
      payload: {
        wallet_pubkey: "x",
        attestation_pda: "x",
        tx_sig: "x",
        trust_score: 100,
        cluster: "devnet",
      },
    }, popupA);

    expect(onVerifiedA).toHaveBeenCalledOnce();
    expect(onVerifiedB).not.toHaveBeenCalled();
  });
});
