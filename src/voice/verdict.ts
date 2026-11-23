/**
 * Offline verifier for signed `VoiceLivenessVerdict` JWS tokens
 * (`typ: "entros-voice-liveness+jwt"`).
 *
 * Enforces `alg: "EdDSA"`, strict RFC 8032 (`zip215: false`), `retention: "memory_only"`,
 * lifetime bounds (`30..300 s`), 160 ms partial-spoof span alignment, and all
 * 8 canonical `abstain_reason` enum values.
 */

import {
  isLowerHex64,
  isPlainRecord,
  isPrintableAscii,
  isStrictHttpsOrLoopbackUri,
  isValidUnixSeconds,
  isVoiceJti,
} from "../permit/encoding";
import { verifyEdDsaJws } from "../permit/jws";
import {
  ALL_VOICE_ABSTAIN_REASONS,
  PERMIT_V2_LIMITS,
  VOICE_VERDICT_TYP,
  type ConsistencyDrift,
  type JwksSource,
  type PartialSpoofSpan,
  type VoiceAbstainReason,
  type VoiceLivenessVerdictClaims,
  type VoiceOperatingProfile,
  type VoiceSignalQuality,
  type VoiceVerdictDecision,
} from "../permit/types";

const ALLOWED_VERDICTS: ReadonlySet<string> = new Set<VoiceVerdictDecision>([
  "likely_human",
  "suspicious",
  "likely_synthetic",
  "insufficient_signal",
]);

const ALLOWED_PROFILES: ReadonlySet<string> = new Set<VoiceOperatingProfile>([
  "webrtc_16k",
  "telephony_8k",
  "wideband_clean",
]);

const ALLOWED_ABSTAIN_REASONS: ReadonlySet<string> = new Set<string>(
  ALL_VOICE_ABSTAIN_REASONS,
);

const ALLOWED_DRIFT_STATUSES: ReadonlySet<string> = new Set([
  "evaluated",
  "elevated",
  "not_applicable",
]);

export interface VerifyVoiceLivenessVerdictInput {
  jws: unknown;
  jwks: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  nowSeconds?: number | (() => number);
  expectedIssuer?: string;
}

export type VerifyVoiceLivenessVerdictReason =
  | "invalid_jws"
  | "unsupported_alg"
  | "invalid_typ"
  | "unknown_kid"
  | "revoked_kid"
  | "invalid_signature"
  | "voice_retention_violation"
  | "voice_verdict_invalid"
  | "state_unavailable";

export type VerifyVoiceLivenessVerdictResult =
  | {
      ok: true;
      claims: VoiceLivenessVerdictClaims;
      kid: string;
      evaluatedAt: number;
    }
  | {
      ok: false;
      reason: VerifyVoiceLivenessVerdictReason;
      detail: string;
    };

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function parseSignalQuality(value: unknown): VoiceSignalQuality | null {
  if (!isPlainRecord(value)) return null;
  if (!isFiniteNumber(value.snr_db)) return null;
  if (
    typeof value.speech_ms !== "number" ||
    !Number.isSafeInteger(value.speech_ms) ||
    value.speech_ms < 0
  ) {
    return null;
  }
  if (
    !isFiniteNumber(value.clipping) ||
    value.clipping < 0 ||
    value.clipping > 1
  ) {
    return null;
  }
  if (
    typeof value.codec_bandwidth_hz !== "number" ||
    !Number.isSafeInteger(value.codec_bandwidth_hz) ||
    value.codec_bandwidth_hz <= 0
  ) {
    return null;
  }
  return {
    snr_db: value.snr_db,
    speech_ms: value.speech_ms,
    clipping: value.clipping,
    codec_bandwidth_hz: value.codec_bandwidth_hz,
  };
}

function parsePartialSpoofSpans(value: unknown): PartialSpoofSpan[] | null {
  if (!Array.isArray(value)) return null;
  const spans: PartialSpoofSpan[] = [];
  for (const item of value) {
    if (!isPlainRecord(item)) return null;
    if (
      typeof item.start_ms !== "number" ||
      !Number.isSafeInteger(item.start_ms) ||
      item.start_ms < 0 ||
      item.start_ms % 160 !== 0
    ) {
      return null;
    }
    if (
      typeof item.end_ms !== "number" ||
      !Number.isSafeInteger(item.end_ms) ||
      item.end_ms <= item.start_ms ||
      (item.end_ms - item.start_ms) % 160 !== 0
    ) {
      return null;
    }
    if (
      !isFiniteNumber(item.spoof_probability) ||
      item.spoof_probability < 0 ||
      item.spoof_probability > 1
    ) {
      return null;
    }
    spans.push({
      start_ms: item.start_ms,
      end_ms: item.end_ms,
      spoof_probability: item.spoof_probability,
    });
  }
  return spans;
}

function parseConsistencyDrift(value: unknown): ConsistencyDrift | null {
  if (!isPlainRecord(value)) return null;
  if (
    typeof value.status !== "string" ||
    !ALLOWED_DRIFT_STATUSES.has(value.status)
  ) {
    return null;
  }
  if (
    typeof value.windows_evaluated !== "number" ||
    !Number.isSafeInteger(value.windows_evaluated) ||
    value.windows_evaluated < 0
  ) {
    return null;
  }
  const optionalFloat = (v: unknown): number | null | undefined => {
    if (v === null) return null;
    if (isFiniteNumber(v)) return v;
    return undefined;
  };
  const floor = optionalFloat(value.floor_spread_db);
  const tail = optionalFloat(value.tail_decay_spread_db);
  const tilt = optionalFloat(value.spectral_tilt_drift);
  if (floor === undefined || tail === undefined || tilt === undefined) {
    return null;
  }
  if (
    value.reason !== null &&
    (typeof value.reason !== "string" || value.reason.length === 0)
  ) {
    return null;
  }
  return {
    status: value.status as ConsistencyDrift["status"],
    windows_evaluated: value.windows_evaluated,
    floor_spread_db: floor,
    tail_decay_spread_db: tail,
    spectral_tilt_drift: tilt,
    reason: value.reason,
  };
}

/**
 * Verifies a signed `VoiceLivenessVerdict` JWS offline against an Ed25519 JWKS.
 */
export async function verifyVoiceLivenessVerdict(
  input: VerifyVoiceLivenessVerdictInput,
): Promise<VerifyVoiceLivenessVerdictResult> {
  const now =
    input.nowSeconds === undefined
      ? Math.floor(Date.now() / 1000)
      : typeof input.nowSeconds === "function"
        ? input.nowSeconds()
        : input.nowSeconds;
  if (!isValidUnixSeconds(now)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid verifier clock timestamp",
    };
  }

  const jwsCheck = await verifyEdDsaJws({
    jws: input.jws,
    expectedTyp: VOICE_VERDICT_TYP,
    jwks: input.jwks,
    revokedKids: input.revokedKids,
  });
  if (!jwsCheck.ok) {
    return {
      ok: false,
      reason: jwsCheck.reason,
      detail: jwsCheck.detail,
    };
  }

  const p = jwsCheck.payload;

  // Enforce RAM-only zero-persistence retention invariant explicitly.
  if (p.retention !== "memory_only") {
    return {
      ok: false,
      reason: "voice_retention_violation",
      detail: "VoiceLivenessVerdict retention must equal 'memory_only'",
    };
  }

  if (!isStrictHttpsOrLoopbackUri(p.iss)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid voice verdict issuer URI",
    };
  }
  if (input.expectedIssuer !== undefined && p.iss !== input.expectedIssuer) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict issuer mismatch",
    };
  }
  if (!isVoiceJti(p.jti)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict jti must be 64 lowercase hex or UUIDv7",
    };
  }
  if (!isValidUnixSeconds(p.iat) || !isValidUnixSeconds(p.exp)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict iat/exp must be valid Unix seconds",
    };
  }
  const lifetime = p.exp - p.iat;
  if (
    lifetime < PERMIT_V2_LIMITS.voiceMinLifetimeSeconds ||
    lifetime > PERMIT_V2_LIMITS.voiceMaxLifetimeSeconds
  ) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict lifetime must be between 30 and 300 seconds",
    };
  }
  if (p.iat > now + PERMIT_V2_LIMITS.clockSkewSeconds) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict iat exceeds allowed clock skew",
    };
  }
  if (now >= p.exp) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Voice verdict is expired",
    };
  }
  if (
    typeof p.session_id !== "string" ||
    p.session_id.length < 1 ||
    p.session_id.length > PERMIT_V2_LIMITS.maxIdentifierLength ||
    !isPrintableAscii(p.session_id)
  ) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid voice verdict session_id",
    };
  }
  if (typeof p.verdict !== "string" || !ALLOWED_VERDICTS.has(p.verdict)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid voice verdict enum value",
    };
  }
  const verdict = p.verdict as VoiceVerdictDecision;

  if (p.calibrated_llr === null) {
    if (verdict !== "insufficient_signal") {
      return {
        ok: false,
        reason: "voice_verdict_invalid",
        detail: "calibrated_llr may be null only when verdict is 'insufficient_signal'",
      };
    }
  } else if (!isFiniteNumber(p.calibrated_llr)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "calibrated_llr must be a finite number or null on insufficient_signal",
    };
  }

  if (
    typeof p.operating_profile !== "string" ||
    !ALLOWED_PROFILES.has(p.operating_profile)
  ) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid operating_profile",
    };
  }
  if (!isLowerHex64(p.model_version)) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "model_version must be a 64-char lowercase hex SHA-256",
    };
  }

  const signalQuality = parseSignalQuality(p.signal_quality);
  if (!signalQuality) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid signal_quality telemetry",
    };
  }

  const partialSpoofSpans = parsePartialSpoofSpans(p.partial_spoof_spans);
  if (!partialSpoofSpans) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid partial_spoof_spans",
    };
  }

  const consistencyDrift = parseConsistencyDrift(p.consistency_drift);
  if (!consistencyDrift) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "Invalid consistency_drift",
    };
  }

  let abstainReason: VoiceAbstainReason | null = null;
  if (verdict === "insufficient_signal") {
    if (
      typeof p.abstain_reason !== "string" ||
      !ALLOWED_ABSTAIN_REASONS.has(p.abstain_reason)
    ) {
      return {
        ok: false,
        reason: "voice_verdict_invalid",
        detail: "insufficient_signal verdict requires a canonical abstain_reason",
      };
    }
    abstainReason = p.abstain_reason as VoiceAbstainReason;
  } else if (p.abstain_reason !== null) {
    return {
      ok: false,
      reason: "voice_verdict_invalid",
      detail: "abstain_reason must be null unless verdict is 'insufficient_signal'",
    };
  }

  return {
    ok: true,
    kid: jwsCheck.kid,
    evaluatedAt: now,
    claims: {
      iss: p.iss,
      jti: p.jti,
      iat: p.iat,
      exp: p.exp,
      session_id: p.session_id,
      verdict,
      calibrated_llr: p.calibrated_llr,
      operating_profile: p.operating_profile as VoiceOperatingProfile,
      model_version: p.model_version,
      signal_quality: signalQuality,
      partial_spoof_spans: partialSpoofSpans,
      consistency_drift: consistencyDrift,
      abstain_reason: abstainReason,
      retention: "memory_only",
    },
  };
}
