/**
 * Cold and warm verification stage latency summary and failure classification.
 * Records timing counts and bounded categories only, never raw capture or audio.
 */

export const TELEMETRY_STAGES = Object.freeze([
  "permissions",
  "capture",
  "validation",
  "proof",
  "walletPrompts",
  "confirmation",
  "return",
]);

export const FAILURE_CLASSES = Object.freeze([
  "permissions",
  "unsupported_device",
  "capture",
  "validation",
  "stale_baseline",
  "unavailable_service",
  "funding",
  "wallet_rejection",
  "confirmation",
  "return",
]);

const FORBIDDEN_TELEMETRY_KEYS = new Set([
  "audio",
  "pcm",
  "phraseAudio",
  "motion",
  "touch",
  "rawMotion",
  "rawTouch",
  "fingerprint",
  "features",
]);

const REASON_TO_FAILURE_CLASS = new Map([
  ["permissions", "permissions"],
  ["permission_denied", "permissions"],
  ["microphone_denied", "permissions"],
  ["motion_denied", "permissions"],
  ["unsupported_device", "unsupported_device"],
  ["no_microphone", "unsupported_device"],
  ["missing_audio_api", "unsupported_device"],
  ["unsupported_browser", "unsupported_device"],
  ["capture", "capture"],
  ["capture_failed", "capture"],
  ["capture_aborted", "capture"],
  ["capture_timeout", "capture"],
  ["validation", "validation"],
  ["validation_failed", "validation"],
  ["score_below_minimum", "validation"],
  ["verification_stale", "validation"],
  ["attestation_required", "validation"],
  ["invalid_evidence", "validation"],
  ["stale_baseline", "stale_baseline"],
  ["baseline_stale", "stale_baseline"],
  ["drift_too_high", "stale_baseline"],
  ["rebaseline_required", "stale_baseline"],
  ["unavailable_service", "unavailable_service"],
  ["state_unavailable", "unavailable_service"],
  ["agent_unavailable", "unavailable_service"],
  ["network_error", "unavailable_service"],
  ["rpc_unavailable", "unavailable_service"],
  ["service_unavailable", "unavailable_service"],
  ["timeout", "unavailable_service"],
  ["funding", "funding"],
  ["insufficient_funds", "funding"],
  ["insufficient_sol", "funding"],
  ["fee_unfunded", "funding"],
  ["wallet_rejection", "wallet_rejection"],
  ["wallet_rejected", "wallet_rejection"],
  ["user_rejected", "wallet_rejection"],
  ["user_canceled", "wallet_rejection"],
  ["confirmation", "confirmation"],
  ["confirmation_failed", "confirmation"],
  ["transaction_failed", "confirmation"],
  ["tx_expired", "confirmation"],
  ["slot_expired", "confirmation"],
  ["return", "return"],
  ["origin_invalid", "return"],
  ["popup_blocked", "return"],
  ["return_failed", "return"],
  ["handoff_failed", "return"],
]);

/** Nearest-rank percentile over a pre-sorted array of non-negative numbers. */
export function computePercentile(sortedValues, percentile) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) return null;
  if (
    typeof percentile !== "number" ||
    !Number.isFinite(percentile) ||
    percentile <= 0 ||
    percentile > 100
  ) {
    throw new Error("Percentile must be in (0, 100]");
  }
  const rank = Math.ceil((percentile / 100) * sortedValues.length);
  const index = Math.max(0, Math.min(sortedValues.length - 1, rank - 1));
  return sortedValues[index];
}

/** Maps a failure or abandonment code, reason, or stage into the 10 standard classes. */
export function classifyFailure(input) {
  if (typeof input === "string") {
    const mapped = REASON_TO_FAILURE_CLASS.get(input);
    if (mapped) return mapped;
    throw new Error(`Unsupported failure class: ${input}`);
  }
  if (input && typeof input === "object") {
    for (const candidate of [input.failureClass, input.reason, input.code, input.stage]) {
      if (typeof candidate === "string") {
        const mapped = REASON_TO_FAILURE_CLASS.get(candidate);
        if (mapped) return mapped;
      }
    }
  }
  throw new Error("Unable to classify failure event");
}

function emptyStageSamples() {
  return Object.fromEntries(TELEMETRY_STAGES.map((stage) => [stage, []]));
}

function emptyClassCounts() {
  return Object.fromEntries(FAILURE_CLASSES.map((name) => [name, 0]));
}

function summarizeBucket(bucket) {
  const stages = {};
  for (const stage of TELEMETRY_STAGES) {
    const sorted = [...bucket.stages[stage]].sort((a, b) => a - b);
    stages[stage] = {
      count: sorted.length,
      p50Ms: computePercentile(sorted, 50),
      p95Ms: computePercentile(sorted, 95),
    };
  }
  return {
    total: bucket.total,
    completed: bucket.completed,
    failed: bucket.failed,
    abandoned: bucket.abandoned,
    stages,
  };
}

export class ReferenceTelemetryCollector {
  #cold = {
    total: 0,
    completed: 0,
    failed: 0,
    abandoned: 0,
    stages: emptyStageSamples(),
  };
  #warm = {
    total: 0,
    completed: 0,
    failed: 0,
    abandoned: 0,
    stages: emptyStageSamples(),
  };
  #failuresByClass = emptyClassCounts();
  #abandonmentsByClass = emptyClassCounts();

  recordRun(event) {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new Error("Telemetry event must be an object");
    }
    for (const key of Object.keys(event)) {
      if (FORBIDDEN_TELEMETRY_KEYS.has(key)) {
        throw new Error(`Telemetry must not include raw field: ${key}`);
      }
    }
    if (event.mode !== "cold" && event.mode !== "warm") {
      throw new Error("Telemetry mode must be cold or warm");
    }
    if (!["completed", "failed", "abandoned"].includes(event.outcome)) {
      throw new Error("Telemetry outcome must be completed, failed, or abandoned");
    }

    const stages = event.stages ?? {};
    if (typeof stages !== "object" || stages === null || Array.isArray(stages)) {
      throw new Error("Telemetry stages must be an object");
    }
    const validatedStages = [];
    for (const [stage, latencyMs] of Object.entries(stages)) {
      if (!TELEMETRY_STAGES.includes(stage)) {
        throw new Error(`Unknown telemetry stage: ${stage}`);
      }
      if (
        typeof latencyMs !== "number" ||
        !Number.isFinite(latencyMs) ||
        latencyMs < 0
      ) {
        throw new Error(`Invalid latency for stage ${stage}`);
      }
      validatedStages.push([stage, latencyMs]);
    }

    let classified = null;
    if (event.outcome === "failed") {
      classified = classifyFailure(
        event.failureClass ?? { reason: event.reason, code: event.code, stage: event.stage },
      );
    } else if (event.outcome === "abandoned") {
      classified = classifyFailure(
        event.abandonmentClass ??
          event.failureClass ?? { reason: event.reason, code: event.code, stage: event.stage },
      );
    }

    const bucket = event.mode === "cold" ? this.#cold : this.#warm;
    bucket.total += 1;
    bucket[event.outcome] += 1;
    for (const [stage, latencyMs] of validatedStages) {
      bucket.stages[stage].push(latencyMs);
    }
    if (event.outcome === "failed" && classified) {
      this.#failuresByClass[classified] += 1;
    } else if (event.outcome === "abandoned" && classified) {
      this.#abandonmentsByClass[classified] += 1;
    }
  }

  summarize() {
    return {
      cold: summarizeBucket(this.#cold),
      warm: summarizeBucket(this.#warm),
      failuresByClass: { ...this.#failuresByClass },
      abandonmentsByClass: { ...this.#abandonmentsByClass },
      totalRuns: this.#cold.total + this.#warm.total,
    };
  }
}
