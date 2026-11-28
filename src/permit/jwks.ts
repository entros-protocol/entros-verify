/**
 * Ed25519 JWKS cache and static resolver enforcing bounded TTL (<= 300 s),
 * negative-cache refresh floor (>= 10 s), single refresh on unknown `kid`,
 * and revoked key rejection.
 */

import {
  base64UrlDecodeStrict,
  isPlainRecord,
  isStrictHttpsOrLoopbackUri,
} from "./encoding";
import {
  PERMIT_V2_LIMITS,
  type Ed25519Jwk,
  type JwkLookupResult,
  type JwksDocument,
  type JwksResolver,
  type JwksSource,
} from "./types";

const MAX_NEGATIVE_CACHE_ENTRIES = 4_096;

interface ParsedJwksEntry {
  kid: string;
  publicKey: Uint8Array;
  revoked: boolean;
}

export interface JwksCacheOptions {
  /** HTTPS (or http://127.0.0.1) JWKS URL, e.g. `https://api.entros.io/.well-known/jwks.json`. */
  jwksUrl: string;
  /** Maximum cache lifetime in seconds (1..300). Default 300. */
  ttlSeconds?: number;
  /** Minimum cooldown in seconds before refreshing on unknown `kid` (>= 10). Default 10. */
  negativeCacheSeconds?: number;
  /** Optional local revocation list overriding JWKS status. */
  revokedKids?: ReadonlySet<string> | readonly string[];
  /** Custom fetch implementation for testing or edge runtimes. */
  fetch?: typeof globalThis.fetch;
  /** Optional clock returning Unix seconds. */
  nowSeconds?: () => number;
  /** Optional per-request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
}

function toRevokedSet(
  revoked?: ReadonlySet<string> | readonly string[],
): ReadonlySet<string> {
  if (!revoked) return new Set();
  return revoked instanceof Set ? revoked : new Set(revoked);
}

function parseJwksDocument(doc: unknown): Map<string, ParsedJwksEntry> {
  if (!isPlainRecord(doc) || !Array.isArray(doc.keys)) {
    throw new Error("Invalid JWKS document: missing keys array");
  }
  const entries = new Map<string, ParsedJwksEntry>();
  for (const item of doc.keys) {
    if (!isPlainRecord(item)) continue;
    if (item.kty !== "OKP" || item.crv !== "Ed25519") continue;
    if (item.use !== undefined && item.use !== "sig") continue;
    if (item.alg !== undefined && item.alg !== "EdDSA") continue;
    if (typeof item.kid !== "string" || item.kid.trim().length === 0) continue;
    if (typeof item.x !== "string") continue;
    const rawKey = base64UrlDecodeStrict(item.x);
    if (!rawKey || rawKey.length !== 32) continue;
    const existing = entries.get(item.kid);
    const revoked = item.status === "revoked" || existing?.revoked === true;
    entries.set(item.kid, {
      kid: item.kid,
      publicKey: rawKey,
      revoked,
    });
  }
  return entries;
}

/**
 * Static in-memory JWKS resolver for offline verification and tests.
 */
export function createStaticJwksResolver(
  jwks: JwksDocument,
  revokedKids?: ReadonlySet<string> | readonly string[],
): JwksResolver {
  const entries = parseJwksDocument(jwks);
  const localRevoked = toRevokedSet(revokedKids);

  return {
    resolveEd25519Key(kid: string): JwkLookupResult {
      if (typeof kid !== "string" || kid.trim().length === 0) {
        return { status: "unknown", kid: "" };
      }
      if (localRevoked.has(kid)) {
        return { status: "revoked", kid };
      }
      const entry = entries.get(kid);
      if (!entry) {
        return { status: "unknown", kid };
      }
      if (entry.revoked) {
        return { status: "revoked", kid };
      }
      return {
        status: "found",
        kid,
        publicKey: new Uint8Array(entry.publicKey),
      };
    },
  };
}

/**
 * Caching JWKS resolver for `GET /.well-known/jwks.json`.
 *
 * Bounds cache TTL to at most 300 seconds, refreshes at most once on an
 * unknown `kid` subject to a >= 10-second negative-cache floor, deduplicates
 * concurrent fetches, and fails closed on revoked keys or transport errors.
 */
export class JwksCache implements JwksResolver {
  readonly #jwksUrl: string;
  readonly #ttlSeconds: number;
  readonly #negativeCacheSeconds: number;
  readonly #localRevoked: ReadonlySet<string>;
  readonly #fetchImpl: typeof globalThis.fetch;
  readonly #nowSeconds: () => number;
  readonly #timeoutMs: number;

  #entries: Map<string, ParsedJwksEntry> | null = null;
  #fetchedAt = 0;
  #lastRefreshAttemptAt = 0;
  #unknownNegativeCache = new Map<string, number>();
  #inflight: Promise<void> | null = null;

  constructor(options: JwksCacheOptions) {
    if (!isStrictHttpsOrLoopbackUri(options.jwksUrl)) {
      throw new Error(
        "JWKS URL must be a strict HTTPS URI (or http://127.0.0.1 for local tests)",
      );
    }
    const ttl = options.ttlSeconds ?? PERMIT_V2_LIMITS.maxJwksTtlSeconds;
    if (
      !Number.isSafeInteger(ttl) ||
      ttl < 1 ||
      ttl > PERMIT_V2_LIMITS.maxJwksTtlSeconds
    ) {
      throw new Error(
        `JWKS cache TTL must be between 1 and ${PERMIT_V2_LIMITS.maxJwksTtlSeconds} seconds`,
      );
    }
    const neg =
      options.negativeCacheSeconds ?? PERMIT_V2_LIMITS.minNegativeCacheSeconds;
    if (
      !Number.isSafeInteger(neg) ||
      neg < PERMIT_V2_LIMITS.minNegativeCacheSeconds
    ) {
      throw new Error(
        `JWKS negative cache floor must be at least ${PERMIT_V2_LIMITS.minNegativeCacheSeconds} seconds`,
      );
    }
    const fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new Error("A fetch implementation is required for JwksCache");
    }
    this.#jwksUrl = options.jwksUrl;
    this.#ttlSeconds = ttl;
    this.#negativeCacheSeconds = neg;
    this.#localRevoked = toRevokedSet(options.revokedKids);
    this.#fetchImpl = fetchImpl;
    this.#nowSeconds =
      options.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.#timeoutMs = options.timeoutMs ?? 5_000;
  }

  async #refresh(now: number): Promise<void> {
    if (this.#inflight) {
      await this.#inflight;
      return;
    }
    this.#lastRefreshAttemptAt = now;
    const task = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
      try {
        const response = await this.#fetchImpl(this.#jwksUrl, {
          method: "GET",
          headers: { accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(`JWKS HTTP ${response.status}`);
        }
        const json: unknown = await response.json();
        const parsed = parseJwksDocument(json);
        this.#entries = parsed;
        this.#fetchedAt = this.#nowSeconds();
        for (const loadedKid of parsed.keys()) {
          this.#unknownNegativeCache.delete(loadedKid);
        }
      } finally {
        clearTimeout(timer);
      }
    })();

    this.#inflight = task;
    try {
      await task;
    } finally {
      this.#inflight = null;
    }
  }

  #recordNegativeCache(kid: string, now: number): void {
    // Insertion order matches recording time, so stop at the first live entry.
    for (const [cachedKid, recordedAt] of this.#unknownNegativeCache) {
      if (now - recordedAt >= this.#negativeCacheSeconds) {
        this.#unknownNegativeCache.delete(cachedKid);
      } else {
        break;
      }
    }
    if (this.#unknownNegativeCache.has(kid)) {
      this.#unknownNegativeCache.delete(kid);
    } else if (this.#unknownNegativeCache.size >= MAX_NEGATIVE_CACHE_ENTRIES) {
      const oldest = this.#unknownNegativeCache.keys().next().value;
      if (oldest !== undefined) {
        this.#unknownNegativeCache.delete(oldest);
      }
    }
    this.#unknownNegativeCache.set(kid, now);
  }

  async resolveEd25519Key(kid: string): Promise<JwkLookupResult> {
    if (typeof kid !== "string" || kid.trim().length === 0) {
      return { status: "unknown", kid: "" };
    }
    if (this.#localRevoked.has(kid)) {
      return { status: "revoked", kid };
    }

    const now = this.#nowSeconds();
    const cacheExpired =
      this.#entries === null || now - this.#fetchedAt >= this.#ttlSeconds;
    let didRefresh = false;

    if (cacheExpired) {
      try {
        await this.#refresh(now);
        didRefresh = true;
      } catch (error) {
        return {
          status: "unavailable",
          detail: error instanceof Error ? error.message : "JWKS fetch failed",
        };
      }
    }

    let entry = this.#entries?.get(kid);
    if (!entry) {
      const lastNeg = this.#unknownNegativeCache.get(kid);
      const negExpired =
        lastNeg === undefined || now - lastNeg >= this.#negativeCacheSeconds;
      if (lastNeg !== undefined && negExpired) {
        this.#unknownNegativeCache.delete(kid);
      }
      const canRefresh =
        !didRefresh &&
        negExpired &&
        now - this.#lastRefreshAttemptAt >= this.#negativeCacheSeconds;

      if (canRefresh) {
        try {
          await this.#refresh(now);
          didRefresh = true;
        } catch (error) {
          return {
            status: "unavailable",
            detail:
              error instanceof Error ? error.message : "JWKS refresh failed",
          };
        }
        entry = this.#entries?.get(kid);
      }
      if (!entry) {
        if (didRefresh) {
          this.#recordNegativeCache(kid, this.#nowSeconds());
        }
        return { status: "unknown", kid };
      }
    }

    if (entry.revoked) {
      return { status: "revoked", kid };
    }
    return {
      status: "found",
      kid,
      publicKey: new Uint8Array(entry.publicKey),
    };
  }
}

export function createJwksCache(options: JwksCacheOptions): JwksCache {
  return new JwksCache(options);
}

export function normalizeJwksSource(
  source: JwksSource,
  revokedKids?: ReadonlySet<string> | readonly string[],
): JwksResolver {
  if (
    typeof source === "object" &&
    source !== null &&
    "resolveEd25519Key" in source &&
    typeof source.resolveEd25519Key === "function"
  ) {
    const localRevoked = toRevokedSet(revokedKids);
    if (localRevoked.size === 0) return source;
    return {
      async resolveEd25519Key(kid: string): Promise<JwkLookupResult> {
        if (localRevoked.has(kid)) return { status: "revoked", kid };
        return source.resolveEd25519Key(kid);
      },
    };
  }
  return createStaticJwksResolver(source as JwksDocument, revokedKids);
}

export function isEd25519Jwk(value: unknown): value is Ed25519Jwk {
  if (!isPlainRecord(value)) return false;
  if (value.kty !== "OKP" || value.crv !== "Ed25519") return false;
  if (typeof value.kid !== "string" || value.kid.trim().length === 0) {
    return false;
  }
  if (typeof value.x !== "string") return false;
  const decoded = base64UrlDecodeStrict(value.x);
  return decoded !== null && decoded.length === 32;
}
