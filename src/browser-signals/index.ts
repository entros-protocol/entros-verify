/**
 * `@entros/verify/browser-signals` public surface.
 *
 * Optional additive passive client telemetry tagged with
 * `assurance_tier: "passive_browser_risk"`. Passive browser signals are never
 * accepted as standalone consent and never satisfy voice or cryptographic
 * Passkey assurance policies.
 */

import { isPlainRecord, isValidUnixSeconds } from "../permit/encoding";

export const PASSIVE_BROWSER_RISK_TIER = "passive_browser_risk" as const;
export const PASSIVE_BROWSER_RISK_NOTICE =
  "Additive passive browser risk telemetry only. Never standalone human consent and never satisfies voice or hardware Passkey assurance tiers.";

export interface PassiveBrowserSignals {
  /** Whether `navigator.webdriver` reports automated browser control. */
  webdriver: boolean;
  /** Number of logical CPU cores when reported by `navigator.hardwareConcurrency`. */
  hardwareConcurrency: number | null;
  /** Touch pointer capability when reported by `navigator.maxTouchPoints`. */
  maxTouchPoints: number | null;
  /** Coarse viewport dimensions (rounded to nearest 16 px). */
  viewportBucket: { width: number; height: number } | null;
  /** Whether `window.isSecureContext` is true. */
  secureContext: boolean;
  /** Whether WebAuthn `navigator.credentials.get` is available. */
  webauthnAvailable: boolean;
}

export interface PassiveBrowserSignalEnvelope {
  schema: "entros-passive-browser-risk-v2";
  assurance_tier: "passive_browser_risk";
  standalone_consent: false;
  collected_at: number;
  signals: PassiveBrowserSignals;
  notice: string;
}

export interface BrowserSignalEnvironment {
  navigator?: {
    webdriver?: unknown;
    hardwareConcurrency?: unknown;
    maxTouchPoints?: unknown;
    credentials?: { get?: unknown };
  };
  window?: {
    innerWidth?: unknown;
    innerHeight?: unknown;
    isSecureContext?: unknown;
  };
}

function roundBucket(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return null;
  }
  return Math.round(value / 16) * 16;
}

/**
 * Collects minimal, non-fingerprinting passive browser risk signals without
 * setting cookies, reading canvas/WebGL hashes, or creating cross-site IDs.
 * Safe to call in SSR or headless runtimes (returns conservative defaults).
 */
export function collectPassiveBrowserSignals(
  env?: BrowserSignalEnvironment,
): PassiveBrowserSignals {
  const nav =
    env?.navigator ??
    (typeof globalThis.navigator !== "undefined"
      ? (globalThis.navigator as BrowserSignalEnvironment["navigator"])
      : undefined);
  const win =
    env?.window ??
    (typeof globalThis.window !== "undefined"
      ? (globalThis.window as BrowserSignalEnvironment["window"])
      : undefined);

  const width = roundBucket(win?.innerWidth);
  const height = roundBucket(win?.innerHeight);

  return {
    webdriver: nav?.webdriver === true,
    hardwareConcurrency:
      typeof nav?.hardwareConcurrency === "number" &&
      Number.isSafeInteger(nav.hardwareConcurrency) &&
      nav.hardwareConcurrency >= 0
        ? nav.hardwareConcurrency
        : null,
    maxTouchPoints:
      typeof nav?.maxTouchPoints === "number" &&
      Number.isSafeInteger(nav.maxTouchPoints) &&
      nav.maxTouchPoints >= 0
        ? nav.maxTouchPoints
        : null,
    viewportBucket:
      width !== null && height !== null ? { width, height } : null,
    secureContext: win?.isSecureContext === true,
    webauthnAvailable: typeof nav?.credentials?.get === "function",
  };
}

/**
 * Wraps passive browser telemetry in a typed envelope explicitly labeled
 * `assurance_tier: "passive_browser_risk"` and `standalone_consent: false`.
 */
export function createPassiveBrowserSignalEnvelope(
  signals: PassiveBrowserSignals = collectPassiveBrowserSignals(),
  options?: { nowSeconds?: number },
): PassiveBrowserSignalEnvelope {
  const collectedAt = options?.nowSeconds ?? Math.floor(Date.now() / 1000);
  return {
    schema: "entros-passive-browser-risk-v2",
    assurance_tier: PASSIVE_BROWSER_RISK_TIER,
    standalone_consent: false,
    collected_at: collectedAt,
    signals: {
      webdriver: signals.webdriver === true,
      hardwareConcurrency: signals.hardwareConcurrency,
      maxTouchPoints: signals.maxTouchPoints,
      viewportBucket: signals.viewportBucket
        ? {
            width: signals.viewportBucket.width,
            height: signals.viewportBucket.height,
          }
        : null,
      secureContext: signals.secureContext === true,
      webauthnAvailable: signals.webauthnAvailable === true,
    },
    notice: PASSIVE_BROWSER_RISK_NOTICE,
  };
}

/**
 * Runtime type guard for `PassiveBrowserSignalEnvelope`.
 */
export function isPassiveBrowserSignalEnvelope(
  value: unknown,
): value is PassiveBrowserSignalEnvelope {
  if (!isPlainRecord(value)) return false;
  if (value.schema !== "entros-passive-browser-risk-v2") return false;
  if (value.assurance_tier !== PASSIVE_BROWSER_RISK_TIER) return false;
  if (value.standalone_consent !== false) return false;
  if (!isValidUnixSeconds(value.collected_at)) return false;
  if (!isPlainRecord(value.signals)) return false;
  if (
    typeof value.signals.webdriver !== "boolean" ||
    typeof value.signals.secureContext !== "boolean" ||
    typeof value.signals.webauthnAvailable !== "boolean"
  ) {
    return false;
  }
  return typeof value.notice === "string" && value.notice.length > 0;
}
