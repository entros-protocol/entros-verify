import type { McpApprovalChallenge } from "./approval";

export interface McpNonceRecord {
  nonce: string;
  permitId: string;
  challenge: McpApprovalChallenge;
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
}

export type McpNonceConsumeResult =
  | { status: "consumed"; record: McpNonceRecord }
  | { status: "not_found" }
  | { status: "already_consumed"; consumedAt: number }
  | { status: "expired" };

/**
 * Atomic single-use nonce store for MCP approval settlement.
 *
 * Production multi-instance services should back `consume` with an atomic
 * compare-and-swap or database transaction (`UPDATE ... WHERE consumed_at IS NULL`)
 * so concurrent settlement attempts with the same nonce succeed at most once.
 */
export interface McpNonceStore {
  /** Registers a newly issued challenge under its unique nonce. Rejects duplicates. */
  register(challenge: McpApprovalChallenge): Promise<void> | void;
  /** Non-mutating lookup used before running RPC reads and policy evaluation. */
  peek(nonce: string): Promise<McpNonceRecord | null> | McpNonceRecord | null;
  /**
   * Atomically marks a pending nonce consumed. Must succeed at most once even
   * when multiple settlement calls race on the same nonce.
   */
  consume(input: {
    nonce: string;
    permitId: string;
    nowSeconds: number;
  }): Promise<McpNonceConsumeResult> | McpNonceConsumeResult;
}

export interface InMemoryNonceStoreOptions {
  /** Maximum tracked records before rejecting new registrations. Default 10,000. */
  maxEntries?: number;
  /** Seconds after `expiresAt` to keep consumed nonces for replay diagnostics. Default 3,600. */
  retainConsumedSeconds?: number;
}

export class McpNonceStoreError extends Error {
  constructor(
    public readonly code: "duplicate_nonce" | "capacity_reached" | "invalid_record",
    message: string,
  ) {
    super(message);
    this.name = "McpNonceStoreError";
  }
}

function cloneRecord(record: McpNonceRecord): McpNonceRecord {
  return structuredClone(record);
}

/**
 * Single-process atomic in-memory `McpNonceStore`.
 *
 * `consume` checks state and records `consumedAt` synchronously without yielding,
 * guaranteeing at-most-once settlement across concurrent async calls within one process.
 */
export class InMemoryNonceStore implements McpNonceStore {
  readonly #records = new Map<string, McpNonceRecord>();
  readonly #maxEntries: number;
  readonly #retainConsumedSeconds: number;

  constructor(options: InMemoryNonceStoreOptions = {}) {
    const maxEntries = options.maxEntries ?? 10_000;
    const retainConsumedSeconds = options.retainConsumedSeconds ?? 3_600;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new McpNonceStoreError(
        "invalid_record",
        "maxEntries must be a positive integer",
      );
    }
    if (
      !Number.isSafeInteger(retainConsumedSeconds) ||
      retainConsumedSeconds < 0
    ) {
      throw new McpNonceStoreError(
        "invalid_record",
        "retainConsumedSeconds must be a non-negative integer",
      );
    }
    this.#maxEntries = maxEntries;
    this.#retainConsumedSeconds = retainConsumedSeconds;
  }

  /** Removes expired unconsumed entries and consumed entries past retention. */
  prune(nowSeconds: number): number {
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 1) return 0;
    let removed = 0;
    for (const [nonce, record] of this.#records) {
      const stalePending =
        record.consumedAt === null && nowSeconds >= record.expiresAt;
      const staleConsumed =
        record.consumedAt !== null &&
        nowSeconds >= record.expiresAt + this.#retainConsumedSeconds;
      if (stalePending || staleConsumed) {
        this.#records.delete(nonce);
        removed += 1;
      }
    }
    return removed;
  }

  register(challenge: McpApprovalChallenge): void {
    if (!challenge || typeof challenge.nonce !== "string") {
      throw new McpNonceStoreError(
        "invalid_record",
        "Challenge must carry a valid nonce",
      );
    }
    this.prune(challenge.issuedAt);
    if (this.#records.has(challenge.nonce)) {
      throw new McpNonceStoreError(
        "duplicate_nonce",
        "Nonce is already registered",
      );
    }
    if (this.#records.size >= this.#maxEntries) {
      throw new McpNonceStoreError(
        "capacity_reached",
        "Nonce store capacity reached",
      );
    }
    this.#records.set(challenge.nonce, {
      nonce: challenge.nonce,
      permitId: challenge.permitId,
      challenge: structuredClone(challenge),
      createdAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
      consumedAt: null,
    });
  }

  peek(nonce: string): McpNonceRecord | null {
    const entry = this.#records.get(nonce);
    return entry ? cloneRecord(entry) : null;
  }

  consume(input: {
    nonce: string;
    permitId: string;
    nowSeconds: number;
  }): McpNonceConsumeResult {
    const entry = this.#records.get(input.nonce);
    if (!entry || entry.permitId !== input.permitId) {
      return { status: "not_found" };
    }
    if (entry.consumedAt !== null) {
      return { status: "already_consumed", consumedAt: entry.consumedAt };
    }
    if (
      !Number.isSafeInteger(input.nowSeconds) ||
      input.nowSeconds >= entry.expiresAt
    ) {
      return { status: "expired" };
    }
    entry.consumedAt = input.nowSeconds;
    return { status: "consumed", record: cloneRecord(entry) };
  }

  get size(): number {
    return this.#records.size;
  }
}

/** Creates an `InMemoryNonceStore` instance. */
export function createInMemoryNonceStore(
  options?: InMemoryNonceStoreOptions,
): InMemoryNonceStore {
  return new InMemoryNonceStore(options);
}
