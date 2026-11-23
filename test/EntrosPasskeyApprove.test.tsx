import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { base64UrlEncode } from "../src/permit/encoding";
import { EntrosPasskeyApprove } from "../src/react";

const VECTORS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../spec/vectors/agent-permit-v2",
);

const webauthnVectors = JSON.parse(
  readFileSync(resolve(VECTORS_DIR, "webauthn-p256-vectors.json"), "utf-8"),
) as {
  challenge_derivation: {
    jti: string;
    request_digest: string;
    expected_challenge_b64url: string;
  };
  expected_rp_id: string;
};

describe("React EntrosPasskeyApprove", () => {
  it("requests hardware UV bound to derived permit_challenge and returns Base64URL assertion", async () => {
    const fakeCred = {
      type: "public-key",
      rawId: Uint8Array.from([1, 2, 3, 4]).buffer,
      response: {
        authenticatorData: Uint8Array.from({ length: 37 }, (_, i) => i).buffer,
        clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}')
          .buffer,
        signature: Uint8Array.from([
          0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ]).buffer,
      },
    };
    const mockGet = vi.fn(async (opts: CredentialRequestOptions) => {
      expect(opts.publicKey?.userVerification).toBe("required");
      expect(opts.publicKey?.rpId).toBe(webauthnVectors.expected_rp_id);
      const ch = new Uint8Array(opts.publicKey!.challenge as ArrayBuffer);
      expect(base64UrlEncode(ch)).toBe(
        webauthnVectors.challenge_derivation.expected_challenge_b64url,
      );
      return fakeCred as unknown as Credential;
    });
    Object.defineProperty(navigator, "credentials", {
      value: { get: mockGet },
      configurable: true,
    });

    const onApproved = vi.fn();
    render(
      <EntrosPasskeyApprove
        jti={webauthnVectors.challenge_derivation.jti}
        requestDigest={webauthnVectors.challenge_derivation.request_digest}
        rpId={webauthnVectors.expected_rp_id}
        onApproved={onApproved}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Approve with Passkey" }),
    );
    await waitFor(() => expect(onApproved).toHaveBeenCalledTimes(1));
    expect(onApproved.mock.calls[0]?.[0]).toMatchObject({
      credential_id: expect.any(String),
      authenticator_data: expect.any(String),
      client_data_json: expect.any(String),
      signature: expect.any(String),
    });
  });

  it("reports user_canceled when Passkey prompt is aborted", async () => {
    const abortErr = new Error("User aborted");
    abortErr.name = "NotAllowedError";
    Object.defineProperty(navigator, "credentials", {
      value: { get: vi.fn(async () => Promise.reject(abortErr)) },
      configurable: true,
    });

    const onError = vi.fn();
    render(
      <EntrosPasskeyApprove
        jti={webauthnVectors.challenge_derivation.jti}
        requestDigest={webauthnVectors.challenge_derivation.request_digest}
        rpId={webauthnVectors.expected_rp_id}
        onApproved={vi.fn()}
        onError={onError}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Approve with Passkey" }),
    );
    await waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
    expect(onError.mock.calls[0]?.[0]?.code).toBe("user_canceled");
  });
});
