/**
 * `@entros/verify` — public surface.
 *
 * Drop-in React component for Entros verification. See
 * https://entros.io and https://docs.entros.io/integrate/verify.
 */

export { EntrosVerify } from "./EntrosVerify";
export type { EntrosVerifyProps } from "./EntrosVerify";
export type {
  PolicyRequestInput,
  PolicyRequest,
  PolicyResult,
  PolicyReason,
} from "./policy";
export type {
  Cluster,
  EntrosVerifyError,
  EntrosVerifyErrorReason,
  EntrosVerifyProgress,
  EntrosVerifyProgressStatus,
  EntrosVerifyResult,
} from "./types";
