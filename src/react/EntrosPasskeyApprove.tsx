/**
 * Optional React Passkey (`WebAuthn UV`) step-up approval button.
 *
 * Derives the exact `permit_challenge` from `(jti, requestDigest)`, invokes
 * `navigator.credentials.get()` with `userVerification: "required"`, and emits
 * unpadded Base64URL assertion fields ready for `/v1/permits/step-up` or
 * offline `verifyWebAuthnAssertionV2`.
 */

import { useCallback, useState } from "react";
import type { CSSProperties, ReactElement, ReactNode } from "react";

import { base64UrlDecodeStrict, base64UrlEncode } from "../permit/encoding";
import type { WebAuthnAssertionInput } from "../permit/types";
import { deriveWebAuthnChallengeV2 } from "../permit/webauthn";

export interface EntrosPasskeyApproveError {
  code:
    | "webauthn_unavailable"
    | "invalid_challenge"
    | "user_canceled"
    | "assertion_failed";
  message: string;
}

export interface EntrosPasskeyApproveProps {
  /** Single-use permit jti (64 lowercase hex). */
  jti: string;
  /** Canonical RFC 8785 action request_digest (64 lowercase hex). */
  requestDigest: string;
  /** Relying Party ID matching the approval origin host. */
  rpId: string;
  /** Optional list of Base64URL credential IDs permitted to sign. */
  allowCredentialIds?: readonly string[];
  /** Timeout in milliseconds for the browser Passkey prompt. Default 60,000. */
  timeoutMs?: number;
  /** Called with the encoded WebAuthn assertion when hardware UV succeeds. */
  onApproved: (assertion: WebAuthnAssertionInput) => void;
  /** Optional error callback when Passkey approval fails or is canceled. */
  onError?: (error: EntrosPasskeyApproveError) => void;
  /** Button label content. Defaults to "Approve with Passkey". */
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  disabled?: boolean;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function EntrosPasskeyApprove(
  props: EntrosPasskeyApproveProps,
): ReactElement {
  const [status, setStatus] = useState<"idle" | "prompting" | "done" | "error">(
    "idle",
  );

  const handleClick = useCallback(async () => {
    if (
      typeof navigator === "undefined" ||
      !navigator.credentials ||
      typeof navigator.credentials.get !== "function"
    ) {
      setStatus("error");
      props.onError?.({
        code: "webauthn_unavailable",
        message: "WebAuthn navigator.credentials.get is unavailable in this browser",
      });
      return;
    }

    let challengeBytes: Uint8Array;
    try {
      challengeBytes = deriveWebAuthnChallengeV2(
        props.jti,
        props.requestDigest,
      ).challengeBytes;
    } catch (error) {
      setStatus("error");
      props.onError?.({
        code: "invalid_challenge",
        message:
          error instanceof Error
            ? error.message
            : "Invalid permit jti or requestDigest",
      });
      return;
    }

    let allowCredentials: PublicKeyCredentialDescriptor[] | undefined;
    if (props.allowCredentialIds && props.allowCredentialIds.length > 0) {
      const descriptors: PublicKeyCredentialDescriptor[] = [];
      for (const id of props.allowCredentialIds) {
        const decoded = base64UrlDecodeStrict(id);
        if (!decoded || decoded.length === 0) {
          setStatus("error");
          props.onError?.({
            code: "invalid_challenge",
            message: "Invalid Base64URL entry in allowCredentialIds",
          });
          return;
        }
        descriptors.push({ type: "public-key", id: toArrayBuffer(decoded) });
      }
      allowCredentials = descriptors;
    }

    setStatus("prompting");
    try {
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: toArrayBuffer(challengeBytes),
          rpId: props.rpId,
          userVerification: "required",
          timeout: props.timeoutMs ?? 60_000,
          ...(allowCredentials ? { allowCredentials } : {}),
        },
      });

      if (!credential || credential.type !== "public-key") {
        setStatus("error");
        props.onError?.({
          code: "user_canceled",
          message: "Passkey approval returned no public-key credential",
        });
        return;
      }

      const pkCred = credential as PublicKeyCredential;
      const response = pkCred.response as AuthenticatorAssertionResponse;
      const assertion: WebAuthnAssertionInput = {
        credential_id: base64UrlEncode(new Uint8Array(pkCred.rawId)),
        authenticator_data: base64UrlEncode(
          new Uint8Array(response.authenticatorData),
        ),
        client_data_json: base64UrlEncode(
          new Uint8Array(response.clientDataJSON),
        ),
        signature: base64UrlEncode(new Uint8Array(response.signature)),
      };
      setStatus("done");
      props.onApproved(assertion);
    } catch (error) {
      setStatus("error");
      const name = error instanceof Error ? error.name : "";
      props.onError?.({
        code:
          name === "NotAllowedError" || name === "AbortError"
            ? "user_canceled"
            : "assertion_failed",
        message:
          error instanceof Error ? error.message : "Passkey assertion failed",
      });
    }
  }, [
    props.allowCredentialIds,
    props.jti,
    props.onApproved,
    props.onError,
    props.requestDigest,
    props.rpId,
    props.timeoutMs,
  ]);

  const busy = status === "prompting";

  return (
    <button
      type="button"
      data-entros-passkey-state={status}
      disabled={props.disabled === true || busy}
      onClick={() => {
        void handleClick();
      }}
      className={props.className}
      style={props.style}
    >
      {busy ? "Waiting for Passkey..." : (props.children ?? "Approve with Passkey")}
    </button>
  );
}
