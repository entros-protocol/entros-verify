/**
 * `@entros/verify/react` optional React UI surface.
 *
 * Isolates React components (`EntrosPasskeyApprove` for v2 hardware Passkey
 * step-up and `EntrosVerify` for legacy browser popup compatibility) so headless
 * server, MCP, edge, and Voice-AI runtimes never import React.
 */

export { EntrosVerify } from "../EntrosVerify";
export type { EntrosVerifyProps } from "../EntrosVerify";

export { EntrosPasskeyApprove } from "./EntrosPasskeyApprove";
export type {
  EntrosPasskeyApproveError,
  EntrosPasskeyApproveProps,
} from "./EntrosPasskeyApprove";

export type {
  Cluster,
  EntrosVerifyError,
  EntrosVerifyErrorReason,
  EntrosVerifyProgress,
  EntrosVerifyProgressStatus,
  EntrosVerifyResult,
} from "../types";
export type {
  PolicyReason,
  PolicyRequest,
  PolicyRequestInput,
  PolicyResult,
} from "../policy";
export type { WebAuthnAssertionInput } from "../permit/types";
