/**
 * Atomic single-use `PermitNonceStoreV2` implementation for `Entros-Agent-Permit-v2`.
 *
 * Designed for strictly post-precheck invocation: consumers run all non-mutating
 * cryptographic, policy, voice, WebAuthn, DPoP, and SCITT checks before calling
 * `consume`, so invalid probes never burn valid pending nonces.
 */

import { isLowerHex64NonZero } from "../permit/encoding";
import type {
  PermitNonceStoreV2,
  PermitNonceV2ConsumeInput,
  PermitNonceV2ConsumeResult,
  PermitNonceV2Record,
} from "../permit/types";

export interface InMemoryPermitNonceStoreV2Options {
  /** Maximum tracked jti entries before rejecting new inserts. Default 50,000. */
  maxEntries?: number;
  /** Seconds past `expiresAt` to retain consumed jtis for replay diagnostics. Default 3,600. */
  retainConsumedSeconds?: number;
}

export class PermitNonceStoreV2Error extends Error {
  constructor(
    public readonly code:
      | "duplicate_jti"
      | "capacity_reached"
      | "invalid_record",
    message: string,
  ) {
    super(message);
    this.name = "PermitNonceStoreV2Error";
  }
}

function cloneRecord(record: PermitNonceV2Record): PermitNonceV2Record {
  return { ...record };
}

/**
 * Single-process atomic in-memory `PermitNonceStoreV2`.
 *
 * `consume()` checks and transitions `consumedAt` synchronously without yielding,
 * guaranteeing at-most-once settlement under concurrent replay storms (e.g., 1/32).
 * Multi-instance production deployments should implement `PermitNonceStoreV2`
 * using an atomic Redis `SET NX EX` or SQL `UPDATE ... WHERE consumed_at IS NULL`.
 */
export class InMemoryPermitNonceStoreV2 implements PermitNonceStoreV2 {
  readonly #records = new Map<string, PermitNonceV2Record>();
  readonly #maxEntries: number;
  readonly #retainConsumedSeconds: number;

  constructor(options: InMemoryPermitNonceStoreV2Options = {}) {
    const maxEntries = options.maxEntries ?? 50_000;
    const retainConsumedSeconds = options.retainConsumedSeconds ?? 3_600;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new PermitNonceStoreV2Error(
        "invalid_record",
        "maxEntries must be a positive integer",
      );
    }
    if (
      !Number.isSafeInteger(retainConsumedSeconds) ||
      retainConsumedSeconds < 0
    ) {
      throw new PermitNonceStoreV2Error(
        "invalid_record",
        "retainConsumedSeconds must be a non-negative integer",
      );
    }
    this.#maxEntries = maxEntries;
    this.#retainConsumedSeconds = retainConsumedSeconds;
  }

  prune(nowSeconds: number): number {
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 1) return 0;
    let removed = 0;
    for (const [jti, record] of this.#records) {
      const stalePending =
        record.consumedAt === null && nowSeconds >= record.expiresAt;
      const staleConsumed =
        record.consumedAt !== null &&
        nowSeconds >= record.expiresAt + this.#retainConsumedSeconds;
      if (stalePending || staleConsumed) {
        this.#records.delete(jti);
        removed += 1;
      }
    }
    return removed;
  }

  register(record: {
    jti: string;
    requestDigest: string;
    aud: string;
    policyId?: string;
    issuedAt: number;
    expiresAt: number;
  }): void {
    if (!isLowerHex64NonZero(record.jti)) {
      throw new PermitNonceStoreV2Error(
        "invalid_record",
        "jti must be a non-zero 64-char lowercase hex string",
      );
    }
    if (!isLowerHex64NonZero(record.requestDigest)) {
      throw new PermitNonceStoreV2Error(
        "invalid_record",
        "requestDigest must be a non-zero 64-char lowercase hex string",
      );
    }
    this.prune(record.issuedAt);
    if (this.#records.has(record.jti)) {
      throw new PermitNonceStoreV2Error(
        "duplicate_jti",
        "Permit jti is already registered",
      );
    }
    if (this.#records.size >= this.#maxEntries) {
      throw new PermitNonceStoreV2Error(
        "capacity_reached",
        "PermitNonceStoreV2 capacity reached",
      );
    }
    this.#records.set(record.jti, {
      jti: record.jti,
      requestDigest: record.requestDigest,
      aud: record.aud,
      ...(record.policyId !== undefined ? { policyId: record.policyId } : {}),
      createdAt: record.issuedAt,
      expiresAt: record.expiresAt,
      consumedAt: null,
    });
  }

  peek(jti: string): PermitNonceV2Record | null {
    const entry = this.#records.get(jti);
    return entry ? cloneRecord(entry) : null;
  }

  consume(input: PermitNonceV2ConsumeInput): PermitNonceV2ConsumeResult {
    if (!isLowerHex64NonZero(input.jti)) {
      return { status: "not_found" };
    }
    const existing = this.#records.get(input.jti);
    if (!existing) {
      if (input.requireRegistered === true) {
        return { status: "not_found" };
      }
      if (
        !Number.isSafeInteger(input.nowSeconds) ||
        input.nowSeconds >= input.expiresAt
      ) {
        return { status: "expired" };
      }
      this.prune(input.nowSeconds);
      if (this.#records.size >= this.#maxEntries) {
        throw new PermitNonceStoreV2Error(
          "capacity_reached",
          "PermitNonceStoreV2 capacity reached",
        );
      }
      const created: PermitNonceV2Record = {
        jti: input.jti,
        requestDigest: input.requestDigest,
        aud: input.aud,
        ...(input.policyId !== undefined ? { policyId: input.policyId } : {}),
        createdAt: input.nowSeconds,
        expiresAt: input.expiresAt,
        consumedAt: input.nowSeconds,
      };
      this.#records.set(input.jti, created);
      return { status: "consumed", record: cloneRecord(created) };
    }

    if (
      existing.requestDigest !== input.requestDigest ||
      existing.aud !== input.aud
    ) {
      return { status: "not_found" };
    }
    if (existing.consumedAt !== null) {
      return { status: "already_consumed", consumedAt: existing.consumedAt };
    }
    if (
      !Number.isSafeInteger(input.nowSeconds) ||
      input.nowSeconds >= existing.expiresAt
    ) {
      return { status: "expired" };
    }
    existing.consumedAt = input.nowSeconds;
    return { status: "consumed", record: cloneRecord(existing) };
  }

  get size(): number {
    return this.#records.size;
  }
}

export function createInMemoryPermitNonceStoreV2(
  options?: InMemoryPermitNonceStoreV2Options,
): InMemoryPermitNonceStoreV2 {
  return new InMemoryPermitNonceStoreV2(options);
}
