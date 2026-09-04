/**
 * URL builders for the Entros verify popup.
 *
 * The component constructs the popup URL deterministically from the
 * integrator's props. The popup host validates every field server-side;
 * these helpers exist to fail loudly on the integrator's side when a
 * misconfiguration would have wasted a popup roundtrip.
 */

import type { Cluster } from "./types";
import {
  encodePolicyRequest,
  normalizePolicyRequest,
  type PolicyRequestInput,
} from "./policy";

const VALID_INTEGRATOR_KEY = /^[a-z0-9_-]{1,64}$/;
const ORIGIN_PATTERN = /^https?:\/\/[^/]+$/;

export interface BuildPopupUrlOptions {
  /** entros.io base origin. Override for E2E testing only. */
  baseOrigin: string;
  integratorKey: string;
  /** Caller's window origin — popup posts back to this. */
  parentOrigin: string;
  cluster: Cluster;
  requestId: string;
  minTrustScore?: number;
  policy?: PolicyRequestInput;
}

export function buildPopupUrl(opts: BuildPopupUrlOptions): string {
  if (opts.cluster !== "devnet") {
    throw new Error(
      "Unsupported cluster: @entros/verify currently supports devnet only",
    );
  }
  if (!VALID_INTEGRATOR_KEY.test(opts.integratorKey)) {
    throw new Error(
      `Invalid integratorKey: must match /^[a-z0-9_-]{1,64}$/ (got "${opts.integratorKey}")`,
    );
  }
  if (!ORIGIN_PATTERN.test(opts.parentOrigin)) {
    throw new Error(
      `Invalid parentOrigin: must be a fully-qualified origin (got "${opts.parentOrigin}")`,
    );
  }
  if (opts.minTrustScore !== undefined) {
    if (
      !Number.isInteger(opts.minTrustScore) ||
      opts.minTrustScore < 0 ||
      opts.minTrustScore > 10000
    ) {
      throw new Error(
        `Invalid minTrustScore: must be an integer in [0, 10000] (got ${String(opts.minTrustScore)})`,
      );
    }
  }
  const policy = normalizePolicyRequest(opts.policy, opts.minTrustScore);

  const url = new URL("/embed/verify-popup", opts.baseOrigin);
  url.searchParams.set("integrator", opts.integratorKey);
  url.searchParams.set("parent_origin", opts.parentOrigin);
  url.searchParams.set("cluster", opts.cluster);
  url.searchParams.set("request_id", opts.requestId);
  url.searchParams.set("policy_version", "1");
  url.searchParams.set("policy", encodePolicyRequest(policy));
  if (opts.minTrustScore !== undefined) {
    url.searchParams.set("min_trust_score", String(opts.minTrustScore));
  }
  return url.toString();
}

/**
 * Generates a cryptographically random request ID for replay protection.
 * Uses crypto.randomUUID when available (modern browsers + Node 19+).
 * Falls back to crypto.getRandomValues (broadly supported back to IE11)
 * formatted as a UUIDv4. Math.random is never used.
 */
export function generateRequestId(): string {
  if (typeof crypto === "undefined") {
    throw new Error(
      "crypto is unavailable in this environment; @entros/verify requires a secure context",
    );
  }
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  if (typeof crypto.getRandomValues !== "function") {
    throw new Error(
      "crypto.getRandomValues is unavailable; @entros/verify requires a secure context",
    );
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // RFC 4122 v4 framing: bits 6-7 of byte 8 are 0b10, bits 12-15 of byte 6
  // are 0b0100. The remaining bits are random.
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0"));
  return (
    hex.slice(0, 4).join("") +
    "-" +
    hex.slice(4, 6).join("") +
    "-" +
    hex.slice(6, 8).join("") +
    "-" +
    hex.slice(8, 10).join("") +
    "-" +
    hex.slice(10, 16).join("")
  );
}
