import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, act } from "@testing-library/react";
import { EntrosVerify } from "../src/EntrosVerify";

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

describe("<EntrosVerify>", () => {
  let openSpy: ReturnType<typeof vi.fn>;
  let popup: FakePopup;

  beforeEach(() => {
    popup = makePopup();
    openSpy = vi.fn(() => popup);
    window.open = openSpy as unknown as typeof window.open;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("renders default button text", () => {
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
      />,
    );
    expect(screen.getByRole("button")).toHaveTextContent("Verify with Entros");
  });

  it("renders custom children", () => {
    render(
      <EntrosVerify integratorKey="demo-integrator" onVerified={vi.fn()}>
        Claim airdrop
      </EntrosVerify>,
    );
    expect(screen.getByRole("button")).toHaveTextContent("Claim airdrop");
  });

  it("triggers window.open on click", () => {
    render(
      <EntrosVerify integratorKey="demo-integrator" onVerified={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(openSpy).toHaveBeenCalledOnce();
    const url = new URL(String(openSpy.mock.calls[0]?.[0]));
    expect(url.origin).toBe("https://entros.io");
    expect(url.searchParams.get("integrator")).toBe("demo-integrator");
    expect(url.searchParams.get("cluster")).toBe("devnet");
  });

  it("disables the button while waiting", () => {
    render(
      <EntrosVerify integratorKey="demo-integrator" onVerified={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByRole("button")).toBeDisabled();
    expect(screen.getByRole("button")).toHaveTextContent("Verifying…");
  });

  it("keeps the default verification open past the website backstop", () => {
    vi.useFakeTimers();
    const onError = vi.fn();
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        onError={onError}
      />,
    );
    fireEvent.click(screen.getByRole("button"));

    act(() => vi.advanceTimersByTime(8 * 60 * 1000 + 30_000));
    expect(onError).not.toHaveBeenCalled();
    expect(popup.close).not.toHaveBeenCalled();
    expect(screen.getByRole("button")).toHaveTextContent("Verifying…");

    act(() => vi.advanceTimersByTime(30_000));
    expect(onError).toHaveBeenCalledWith({ reason: "timeout" });
    expect(popup.close).toHaveBeenCalledOnce();
    expect(screen.getByRole("button")).toBeEnabled();
    expect(
      screen.getByRole("button").closest(".entros-verify-container"),
    ).toHaveAttribute("data-state", "error");
  });

  it("shows popup-blocked fallback when window.open returns null", () => {
    openSpy.mockReturnValue(null);
    const onError = vi.fn();
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        onError={onError}
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /click here to open verification/i }),
    ).toBeInTheDocument();
    expect(onError).toHaveBeenCalledWith({ reason: "popup_blocked" });
  });

  it("hides popup-blocked fallback when popupBlockedFallback={false}", () => {
    openSpy.mockReturnValue(null);
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        popupBlockedFallback={false}
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("fallback retry triggers a fresh window.open", () => {
    openSpy.mockReturnValueOnce(null).mockReturnValue(popup);
    render(
      <EntrosVerify integratorKey="demo-integrator" onVerified={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(openSpy).toHaveBeenCalledTimes(1);

    fireEvent.click(
      screen.getByRole("button", { name: /click here to open verification/i }),
    );
    expect(openSpy).toHaveBeenCalledTimes(2);
  });

  it("fires onVerified when popup posts entros/verified", () => {
    const onVerified = vi.fn();
    render(<EntrosVerify integratorKey="demo-integrator" onVerified={onVerified} />);
    fireEvent.click(screen.getByRole("button"));

    const url = new URL(String(openSpy.mock.calls[0]?.[0]));
    const requestId = url.searchParams.get("request_id");

    act(() => {
      window.dispatchEvent(
        new MessageEvent("message", {
          data: {
            version: 1,
            source: "entros",
            type: "entros/verified",
            request_id: requestId,
            timestamp: Date.now(),
            payload: {
              wallet_pubkey: "wallet",
              attestation_pda: "att",
              tx_sig: "sig",
              trust_score: 250,
              cluster: "devnet",
            },
          },
          origin: "https://entros.io",
          source: popup as unknown as Window,
        }),
      );
    });

    expect(onVerified).toHaveBeenCalledWith({
      walletPubkey: "wallet",
      attestationPda: "att",
      txSig: "sig",
      trustScore: 250,
      cluster: "devnet",
    });
  });

  it("forwards baseOrigin override (E2E testing)", () => {
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        baseOrigin="http://localhost:3000"
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    const url = new URL(String(openSpy.mock.calls[0]?.[0]));
    expect(url.origin).toBe("http://localhost:3000");
  });

  it("applies className and style to the trigger button", () => {
    render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        className="custom-class"
        style={{ background: "red" }}
      />,
    );
    const button = screen.getByRole("button");
    expect(button).toHaveClass("custom-class");
    expect(button).toHaveStyle({ background: "red" });
  });

  it("rapid double-click does not open two popups (button disabled while waiting)", () => {
    render(
      <EntrosVerify integratorKey="demo-integrator" onVerified={vi.fn()} />,
    );
    const button = screen.getByRole("button");
    fireEvent.click(button);
    fireEvent.click(button);
    fireEvent.click(button);
    expect(openSpy).toHaveBeenCalledOnce();
  });

  it("cancels in-flight popup on unmount", () => {
    const onError = vi.fn();
    const { unmount } = render(
      <EntrosVerify
        integratorKey="demo-integrator"
        onVerified={vi.fn()}
        onError={onError}
      />,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(popup.close).not.toHaveBeenCalled();

    unmount();
    expect(popup.close).toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith({ reason: "user_canceled" });
  });
});
