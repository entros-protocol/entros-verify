/**
 * Pure Policy v2 evaluator and full Entros-Agent-Permit-v2 verifier enforcing
 * all 31 refusal codes in strict precheck order with atomic post-precheck
 * single-use `jti` consumption.
 */

import { verifyVoiceLivenessVerdict } from "../voice/verdict";
import { hashActionV2 } from "./canonical";
import { verifyDpopProofV2 } from "./dpop";
import {
  constantTimeEqualString,
  isCanonicalAudUri,
  isLowerHex64NonZero,
  isPlainRecord,
  isPrintableAscii,
  isStrictHttpsOrLoopbackUri,
  isValidUnixSeconds,
} from "./encoding";
import { verifyEdDsaJws } from "./jws";
import { verifyScittReceipt } from "./scitt";
import {
  AGENT_PERMIT_V2_TYP,
  ALL_ASSURANCE_TIERS_V2,
  PERMIT_V2_LIMITS,
  type AgentPermitV2Claims,
  type AssuranceTierV2,
  type ContinuityModeV2,
  type DpopVerifyResult,
  type PermitActorV2,
  type PermitCnfV2,
  type PermitContinuityV2,
  type PermitV2DenyCode,
  type PolicyV2,
  type UniquenessStatusV2,
  type VerifyAgentPermitV2Input,
  type VerifyAgentPermitV2Result,
  type VerifiedScittReceipt,
  type VoiceLivenessVerdictClaims,
  type WebAuthnVerifyResult,
} from "./types";
import { deriveWebAuthnChallengeV2, verifyWebAuthnAssertionV2 } from "./webauthn";

const ASSURANCE_TIER_SET: ReadonlySet<string> = new Set(ALL_ASSURANCE_TIERS_V2);
const CONTINUITY_MODES: ReadonlySet<string> = new Set<ContinuityModeV2>([
  "call_session",
  "step_up_only",
  "stateless",
]);
const UNIQUENESS_STATUSES: ReadonlySet<string> = new Set<UniquenessStatusV2>([
  "unmeasured",
  "session_bound",
  "enterprise_idp_subject",
]);

function readNowSeconds(clock?: number | (() => number)): number | null {
  try {
    const val =
      clock === undefined
        ? Math.floor(Date.now() / 1000)
        : typeof clock === "function"
          ? clock()
          : clock;
    return isValidUnixSeconds(val) ? val : null;
  } catch {
    return null;
  }
}

function parseActor(value: unknown): PermitActorV2 | null {
  if (!isPlainRecord(value)) return null;
  if (
    typeof value.id !== "string" ||
    value.id.length < 1 ||
    value.id.length > 256 ||
    !isPrintableAscii(value.id)
  ) {
    return null;
  }
  if (
    value.client_id !== undefined &&
    (typeof value.client_id !== "string" || value.client_id.length === 0)
  ) {
    return null;
  }
  if (
    value.key_jkt !== undefined &&
    (typeof value.key_jkt !== "string" || value.key_jkt.length === 0)
  ) {
    return null;
  }
  if (value.act !== undefined && !isPlainRecord(value.act)) {
    return null;
  }
  return {
    id: value.id,
    ...(value.client_id !== undefined ? { client_id: value.client_id } : {}),
    ...(value.key_jkt !== undefined ? { key_jkt: value.key_jkt } : {}),
    ...(value.act !== undefined ? { act: value.act } : {}),
  };
}

function parseContinuity(value: unknown): PermitContinuityV2 | null {
  if (!isPlainRecord(value)) return null;
  if (
    typeof value.session_id !== "string" ||
    value.session_id.length < 1 ||
    value.session_id.length > PERMIT_V2_LIMITS.maxIdentifierLength ||
    !isPrintableAscii(value.session_id)
  ) {
    return null;
  }
  if (typeof value.mode !== "string" || !CONTINUITY_MODES.has(value.mode)) {
    return null;
  }
  if (
    value.call_continuity_verified !== undefined &&
    typeof value.call_continuity_verified !== "boolean"
  ) {
    return null;
  }
  if (
    value.step_up_triggered !== undefined &&
    typeof value.step_up_triggered !== "boolean"
  ) {
    return null;
  }
  if (
    value.prior_permit_jti !== undefined &&
    value.prior_permit_jti !== null &&
    !isLowerHex64NonZero(value.prior_permit_jti)
  ) {
    return null;
  }
  return {
    session_id: value.session_id,
    mode: value.mode as ContinuityModeV2,
    ...(value.call_continuity_verified !== undefined
      ? { call_continuity_verified: value.call_continuity_verified }
      : {}),
    ...(value.step_up_triggered !== undefined
      ? { step_up_triggered: value.step_up_triggered }
      : {}),
    ...(value.prior_permit_jti !== undefined
      ? { prior_permit_jti: value.prior_permit_jti }
      : {}),
  };
}

function parseCnf(value: unknown): PermitCnfV2 | undefined | null {
  if (value === undefined) return undefined;
  if (!isPlainRecord(value)) return null;
  if (typeof value.jkt !== "string" || value.jkt.length === 0) return null;
  return { jkt: value.jkt };
}

/**
 * Validates step 7 schema invariants for an `Entros-Agent-Permit-v2` payload.
 * Leaves lifetime, clock skew, expiry, and canonical `aud` grammar for steps 8..11
 * so exact refusal codes fire in normative order.
 */
export function parseAgentPermitV2Claims(
  payload: unknown,
): AgentPermitV2Claims | null {
  if (!isPlainRecord(payload)) return null;
  if (!isStrictHttpsOrLoopbackUri(payload.iss)) return null;
  if (
    typeof payload.sub !== "string" ||
    payload.sub.length < 1 ||
    payload.sub.length > PERMIT_V2_LIMITS.maxSubjectLength ||
    !isPrintableAscii(payload.sub)
  ) {
    return null;
  }
  const actor = parseActor(payload.actor);
  if (!actor) return null;
  if (typeof payload.aud !== "string" || payload.aud.length === 0) return null;
  if (!isLowerHex64NonZero(payload.jti)) return null;
  if (!isValidUnixSeconds(payload.iat) || !isValidUnixSeconds(payload.exp)) {
    return null;
  }
  if (!isLowerHex64NonZero(payload.request_digest)) return null;
  if (
    typeof payload.assurance_tier !== "string" ||
    !ASSURANCE_TIER_SET.has(payload.assurance_tier)
  ) {
    return null;
  }
  if (
    !Array.isArray(payload.modality) ||
    payload.modality.length === 0 ||
    !payload.modality.every(
      (item) => typeof item === "string" && item.length > 0,
    )
  ) {
    return null;
  }
  const modality = payload.modality as string[];
  for (let i = 1; i < modality.length; i += 1) {
    if (modality[i - 1]! >= modality[i]!) return null; // must be strictly sorted & unique
  }
  if (!isValidUnixSeconds(payload.freshness_verified_at)) return null;
  const continuity = parseContinuity(payload.continuity);
  if (!continuity) return null;
  if (
    typeof payload.uniqueness_status !== "string" ||
    !UNIQUENESS_STATUSES.has(payload.uniqueness_status)
  ) {
    return null;
  }
  if (
    payload.voice_verdict_jws !== null &&
    (typeof payload.voice_verdict_jws !== "string" ||
      payload.voice_verdict_jws.length === 0)
  ) {
    return null;
  }
  if (
    payload.webauthn_assertion_digest !== null &&
    !isLowerHex64NonZero(payload.webauthn_assertion_digest)
  ) {
    return null;
  }
  if (
    typeof payload.policy_id !== "string" ||
    payload.policy_id.length < 1 ||
    payload.policy_id.length > PERMIT_V2_LIMITS.maxIdentifierLength ||
    !isPrintableAscii(payload.policy_id)
  ) {
    return null;
  }
  if (
    payload.scitt_receipt !== null &&
    (typeof payload.scitt_receipt !== "string" ||
      payload.scitt_receipt.length === 0)
  ) {
    return null;
  }

  const cnf = parseCnf(payload.cnf);
  if (cnf === null) return null;
  if (
    cnf !== undefined &&
    actor.key_jkt !== undefined &&
    cnf.jkt !== actor.key_jkt
  ) {
    return null;
  }
  if (
    payload.authorization_details !== undefined &&
    !Array.isArray(payload.authorization_details)
  ) {
    return null;
  }
  if (
    payload.txn !== undefined &&
    (typeof payload.txn !== "string" || payload.txn.length === 0)
  ) {
    return null;
  }

  return {
    iss: payload.iss,
    sub: payload.sub,
    actor,
    aud: payload.aud,
    jti: payload.jti,
    iat: payload.iat,
    exp: payload.exp,
    request_digest: payload.request_digest,
    assurance_tier: payload.assurance_tier as AssuranceTierV2,
    modality: [...modality],
    freshness_verified_at: payload.freshness_verified_at,
    continuity,
    uniqueness_status: payload.uniqueness_status as UniquenessStatusV2,
    voice_verdict_jws: payload.voice_verdict_jws,
    webauthn_assertion_digest: payload.webauthn_assertion_digest,
    policy_id: payload.policy_id,
    scitt_receipt: payload.scitt_receipt,
    ...(cnf !== undefined ? { cnf } : {}),
    ...(payload.authorization_details !== undefined
      ? { authorization_details: payload.authorization_details }
      : {}),
    ...(payload.txn !== undefined ? { txn: payload.txn } : {}),
  };
}

function isVoiceTier(tier: AssuranceTierV2): boolean {
  return (
    tier === "voice_liveness_webrtc" ||
    tier === "voice_liveness_telephony" ||
    tier === "voice_plus_passkey"
  );
}

function isWebAuthnTier(tier: AssuranceTierV2): boolean {
  return tier === "passkey_webauthn_uv" || tier === "voice_plus_passkey";
}

function evaluateVoicePolicyBinding(
  permit: AgentPermitV2Claims,
  voice: VoiceLivenessVerdictClaims,
  policy: PolicyV2,
  now: number,
): { ok: true } | { ok: false; reason: PermitV2DenyCode; detail: string } {
  // Retention invariant (Step 20).
  if (voice.retention !== "memory_only") {
    return {
      ok: false,
      reason: "voice_retention_violation",
      detail: "Voice verdict retention must equal 'memory_only'",
    };
  }

  // Freshness monotonicity against voice verdict timestamp.
  if (permit.freshness_verified_at > voice.iat) {
    return {
      ok: false,
      reason: "freshness_regression",
      detail: "permit.freshness_verified_at exceeds underlying voice verdict iat",
    };
  }

  // Session continuity binding.
  if (
    voice.session_id.length === 0 ||
    voice.session_id !== permit.continuity.session_id
  ) {
    return {
      ok: false,
      reason: "continuity_broken",
      detail: "Voice verdict session_id does not match permit continuity session_id",
    };
  }

  const rules = policy.voice_rules;
  if (rules?.max_voice_age_seconds !== undefined) {
    if (
      !Number.isFinite(rules.max_voice_age_seconds) ||
      rules.max_voice_age_seconds < 1 ||
      now - voice.iat > rules.max_voice_age_seconds
    ) {
      return {
        ok: false,
        reason: "evidence_stale",
        detail: "Voice verdict age exceeds policy.voice_rules.max_voice_age_seconds",
      };
    }
  }

  // Step 21: Operating profile alignment with both assurance_tier and policy.
  if (
    permit.assurance_tier === "voice_liveness_webrtc" &&
    voice.operating_profile !== "webrtc_16k" &&
    voice.operating_profile !== "wideband_clean"
  ) {
    return {
      ok: false,
      reason: "voice_profile_disallowed",
      detail:
        "voice_liveness_webrtc requires 'webrtc_16k' or 'wideband_clean' operating_profile",
    };
  }
  if (
    permit.assurance_tier === "voice_liveness_telephony" &&
    voice.operating_profile !== "telephony_8k"
  ) {
    return {
      ok: false,
      reason: "voice_profile_disallowed",
      detail: "voice_liveness_telephony requires 'telephony_8k' operating_profile",
    };
  }
  if (rules && !rules.allowed_profiles.includes(voice.operating_profile)) {
    return {
      ok: false,
      reason: "voice_profile_disallowed",
      detail: `Voice operating_profile '${voice.operating_profile}' is not allowed by policy`,
    };
  }
  if (
    rules?.allowed_model_versions &&
    rules.allowed_model_versions.length > 0 &&
    !rules.allowed_model_versions.includes(voice.model_version)
  ) {
    return {
      ok: false,
      reason: "voice_profile_disallowed",
      detail: `Voice model_version '${voice.model_version}' is not in policy allowlist`,
    };
  }

  // Step 22: Verdict, abstain, LLR floor, speech_ms, and SNR gates.
  const allowedVerdicts = rules?.allowed_verdicts ?? ["likely_human"];
  if (!allowedVerdicts.includes(voice.verdict)) {
    return {
      ok: false,
      reason: "voice_verdict_not_allowed",
      detail: `Voice verdict '${voice.verdict}' is not allowed by policy`,
    };
  }
  if (
    rules?.reject_on_abstain !== false &&
    voice.verdict === "insufficient_signal"
  ) {
    return {
      ok: false,
      reason: "voice_verdict_not_allowed",
      detail: "Voice verdict abstained with insufficient_signal",
    };
  }
  if (
    rules?.min_calibrated_llr !== undefined &&
    (!Number.isFinite(rules.min_calibrated_llr) ||
      voice.calibrated_llr === null ||
      voice.calibrated_llr < rules.min_calibrated_llr)
  ) {
    return {
      ok: false,
      reason: "voice_verdict_not_allowed",
      detail: "Voice calibrated_llr is below policy.voice_rules.min_calibrated_llr",
    };
  }
  if (
    rules?.min_speech_ms !== undefined &&
    (!Number.isFinite(rules.min_speech_ms) ||
      rules.min_speech_ms < 0 ||
      voice.signal_quality.speech_ms < rules.min_speech_ms)
  ) {
    return {
      ok: false,
      reason: "voice_verdict_not_allowed",
      detail: "Voice speech_ms is below policy.voice_rules.min_speech_ms",
    };
  }
  if (
    rules?.min_snr_db !== undefined &&
    (!Number.isFinite(rules.min_snr_db) ||
      voice.signal_quality.snr_db < rules.min_snr_db)
  ) {
    return {
      ok: false,
      reason: "voice_verdict_not_allowed",
      detail: "Voice snr_db is below policy.voice_rules.min_snr_db",
    };
  }

  // Step 23: Partial-spoof span gate.
  const maxSpans = rules?.max_partial_spoof_spans ?? 0;
  if (
    !Number.isFinite(maxSpans) ||
    maxSpans < 0 ||
    voice.partial_spoof_spans.length > maxSpans
  ) {
    return {
      ok: false,
      reason: "partial_spoof_detected",
      detail: "Voice partial_spoof_spans count exceeds policy maximum",
    };
  }
  if (rules?.max_partial_spoof_probability !== undefined) {
    const probCap = rules.max_partial_spoof_probability;
    if (
      !Number.isFinite(probCap) ||
      probCap < 0 ||
      probCap > 1 ||
      voice.partial_spoof_spans.some((span) => span.spoof_probability > probCap)
    ) {
      return {
        ok: false,
        reason: "partial_spoof_detected",
        detail: "Voice partial_spoof_spans probability exceeds policy ceiling",
      };
    }
  }

  // Step 24: Rolling consistency drift monitor gate.
  if (
    rules?.reject_on_consistency_drift !== false &&
    voice.consistency_drift.status === "elevated"
  ) {
    return {
      ok: false,
      reason: "consistency_drift_exceeded",
      detail: "Voice consistency_drift status is elevated",
    };
  }

  return { ok: true };
}

export interface EvaluatePolicyV2Input {
  permit: AgentPermitV2Claims;
  policy: PolicyV2;
  expectedAudience: string;
  expectedRequestDigest: string;
  expectedSessionId?: string;
  nowSeconds: number;
  voiceVerdict?: VoiceLivenessVerdictClaims | null;
}

export type EvaluatePolicyV2Result =
  | { decision: "allow"; reason: "accepted" }
  | { decision: "deny"; reason: PermitV2DenyCode; detail: string };

/**
 * Evaluates non-mutating Steps 8 through 18 (pre-voice policy checks) in
 * normative order without evaluating voice or WebAuthn bindings.
 */
function evaluatePreVoicePolicyV2(
  input: Omit<EvaluatePolicyV2Input, "voiceVerdict">,
): EvaluatePolicyV2Result {
  const { permit, policy, expectedAudience, expectedRequestDigest, nowSeconds } =
    input;
  const deny = (
    reason: PermitV2DenyCode,
    detail: string,
  ): EvaluatePolicyV2Result => ({ decision: "deny", reason, detail });

  if (!isPlainRecord(policy) || policy.version !== 2) {
    return deny("policy_mismatch", "Policy version must equal 2");
  }
  if (
    typeof policy.max_permit_lifetime_seconds !== "number" ||
    !Number.isFinite(policy.max_permit_lifetime_seconds) ||
    policy.max_permit_lifetime_seconds < 1
  ) {
    return deny(
      "policy_mismatch",
      "Policy max_permit_lifetime_seconds must be a finite positive number",
    );
  }
  if (
    typeof policy.max_evidence_age_seconds !== "number" ||
    !Number.isFinite(policy.max_evidence_age_seconds) ||
    policy.max_evidence_age_seconds < 1
  ) {
    return deny(
      "policy_mismatch",
      "Policy max_evidence_age_seconds must be a finite positive number",
    );
  }
  if (!isValidUnixSeconds(nowSeconds)) {
    return deny("invalid_permit", "Invalid evaluation clock timestamp");
  }

  // Step 8: Permit lifetime bounds (30..900 s and <= policy cap).
  const lifetime = permit.exp - permit.iat;
  if (
    lifetime < PERMIT_V2_LIMITS.minLifetimeSeconds ||
    lifetime > PERMIT_V2_LIMITS.maxLifetimeSeconds ||
    lifetime > policy.max_permit_lifetime_seconds
  ) {
    return deny(
      "lifetime_exceeded",
      `Permit lifetime ${lifetime}s is outside allowed bounds`,
    );
  }

  // Step 9: Forward clock skew cap (<= 30 s).
  if (permit.iat > nowSeconds + PERMIT_V2_LIMITS.clockSkewSeconds) {
    return deny(
      "clock_skew_exceeded",
      "Permit iat exceeds 30-second forward clock skew limit",
    );
  }

  // Step 10: Expiry check.
  if (nowSeconds >= permit.exp) {
    return deny("permit_expired", "Permit has expired");
  }

  // Step 11: Canonical RFC 8707 audience URI grammar and exact equality.
  if (
    !isCanonicalAudUri(permit.aud) ||
    !isCanonicalAudUri(expectedAudience) ||
    permit.aud !== expectedAudience
  ) {
    return deny(
      "audience_mismatch",
      "Permit aud failed canonical URI grammar or does not match expected resource URI",
    );
  }

  // Step 12: Exact RFC 8785 request_digest equality.
  if (
    !isLowerHex64NonZero(expectedRequestDigest) ||
    !constantTimeEqualString(permit.request_digest, expectedRequestDigest)
  ) {
    return deny(
      "request_digest_mismatch",
      "Recomputed RFC 8785 request_digest does not match permit",
    );
  }

  // Step 13: Policy contract identifier match.
  if (permit.policy_id !== policy.policy_id) {
    return deny(
      "policy_mismatch",
      `Permit policy_id '${permit.policy_id}' does not match '${policy.policy_id}'`,
    );
  }

  // Step 14: Explicit assurance_tier set membership (never linear rank).
  if (!policy.allowed_assurance_tiers.includes(permit.assurance_tier)) {
    return deny(
      "assurance_downgrade",
      `Assurance tier '${permit.assurance_tier}' is not in allowed_assurance_tiers`,
    );
  }

  // Step 15: Required modalities subset check.
  for (const requiredModality of policy.required_modalities) {
    if (!permit.modality.includes(requiredModality)) {
      return deny(
        "modality_missing",
        `Required modality '${requiredModality}' is absent from permit`,
      );
    }
  }

  // Uniqueness boundary enforcement when policy requests stronger uniqueness.
  if (
    policy.uniqueness_requirement === "require_session_bound" &&
    permit.uniqueness_status === "unmeasured"
  ) {
    return deny(
      "assurance_downgrade",
      "Policy requires session_bound or enterprise_idp_subject uniqueness",
    );
  }
  if (
    policy.uniqueness_requirement === "require_enterprise_idp_subject" &&
    permit.uniqueness_status !== "enterprise_idp_subject"
  ) {
    return deny(
      "assurance_downgrade",
      "Policy requires enterprise_idp_subject uniqueness",
    );
  }

  // Step 16: Freshness monotonicity against permit iat.
  if (permit.freshness_verified_at > permit.iat) {
    return deny(
      "freshness_regression",
      "permit.freshness_verified_at cannot exceed permit.iat",
    );
  }

  // Step 17: Evidence age bound.
  if (nowSeconds - permit.freshness_verified_at > policy.max_evidence_age_seconds) {
    return deny(
      "evidence_stale",
      "Underlying human presence evidence exceeds policy.max_evidence_age_seconds",
    );
  }

  // Step 18: Session continuity requirement.
  if (
    input.expectedSessionId !== undefined &&
    permit.continuity.session_id !== input.expectedSessionId
  ) {
    return deny(
      "continuity_broken",
      "Permit continuity.session_id does not match active session",
    );
  }
  if (policy.require_continuity) {
    if (permit.continuity.call_continuity_verified !== true) {
      return deny(
        "continuity_broken",
        "Policy requires call_continuity_verified === true",
      );
    }
    if (
      (isVoiceTier(permit.assurance_tier) ||
        policy.required_modalities.includes("voice_liveness")) &&
      permit.continuity.mode !== "call_session"
    ) {
      return deny(
        "continuity_broken",
        "Continuous voice policy requires continuity.mode === 'call_session'",
      );
    }
  }

  return { decision: "allow", reason: "accepted" };
}

/**
 * Pure, side-effect-free Policy v2 evaluator over already-verified permit and
 * optional voice claims. Evaluates Steps 8 through 25 in normative order.
 */
export function evaluatePolicyV2(
  input: EvaluatePolicyV2Input,
): EvaluatePolicyV2Result {
  const preVoice = evaluatePreVoicePolicyV2(input);
  if (preVoice.decision === "deny") {
    return preVoice;
  }

  const { permit, policy, nowSeconds } = input;
  const deny = (
    reason: PermitV2DenyCode,
    detail: string,
  ): EvaluatePolicyV2Result => ({ decision: "deny", reason, detail });

  // Steps 19..24: Voice binding checks when voice is required or supplied.
  const voiceRequired =
    isVoiceTier(permit.assurance_tier) ||
    policy.required_modalities.includes("voice_liveness");
  if (voiceRequired && !input.voiceVerdict) {
    return deny(
      "voice_verdict_invalid",
      "Voice liveness verdict is required by assurance tier or policy",
    );
  }
  if (input.voiceVerdict) {
    const voiceCheck = evaluateVoicePolicyBinding(
      permit,
      input.voiceVerdict,
      policy,
      nowSeconds,
    );
    if (!voiceCheck.ok) {
      return deny(voiceCheck.reason, voiceCheck.detail);
    }
  }

  // WebAuthn digest presence when WebAuthn is required.
  const webauthnRequired =
    isWebAuthnTier(permit.assurance_tier) ||
    policy.required_modalities.includes("webauthn_uv");
  if (webauthnRequired && permit.webauthn_assertion_digest === null) {
    return deny(
      "webauthn_assertion_invalid",
      "Permit missing webauthn_assertion_digest for WebAuthn policy",
    );
  }

  return { decision: "allow", reason: "accepted" };
}

/**
 * Verifies an `Entros-Agent-Permit-v2` JWS end-to-end across all 31 refusal
 * checks. Runs every non-mutating cryptographic, policy, voice, WebAuthn, DPoP,
 * and SCITT precheck before consuming `jti` atomically in `nonceStore`.
 */
export async function verifyAgentPermitV2(
  input: VerifyAgentPermitV2Input,
): Promise<VerifyAgentPermitV2Result> {
  const precheckNow = readNowSeconds(input.nowSeconds);
  if (precheckNow === null) {
    return {
      decision: "deny",
      reason: "invalid_permit",
      detail: "Invalid verifier clock timestamp",
      permit: null,
      evaluatedAt: 0,
    };
  }

  const deny = (
    reason: PermitV2DenyCode,
    detail: string,
    permit: AgentPermitV2Claims | null = null,
    evaluatedAt = precheckNow,
  ): VerifyAgentPermitV2Result => ({
    decision: "deny",
    reason,
    detail,
    permit,
    evaluatedAt,
  });

  const unavailable = (
    detail: string,
    permit: AgentPermitV2Claims | null = null,
    evaluatedAt = precheckNow,
  ): VerifyAgentPermitV2Result => ({
    decision: "unavailable",
    reason: "state_unavailable",
    detail,
    permit,
    evaluatedAt,
  });

  // Steps 1..6: Compact JWS structure, alg/headers, typ, kid, revocation, Ed25519 (zip215: false).
  const jwsResult = await verifyEdDsaJws({
    jws: input.permitJws,
    expectedTyp: AGENT_PERMIT_V2_TYP,
    jwks: input.jwks,
    revokedKids: input.revokedKids,
  });
  if (!jwsResult.ok) {
    if (jwsResult.reason === "state_unavailable") {
      return unavailable(jwsResult.detail);
    }
    return deny(jwsResult.reason, jwsResult.detail);
  }

  // Step 7: Strict permit claim schema.
  const permit = parseAgentPermitV2Claims(jwsResult.payload);
  if (!permit) {
    return deny(
      "invalid_permit",
      "Permit payload is missing required claims or has invalid claim types",
    );
  }

  // Compute expected RFC 8785 request_digest from live action or explicit digest.
  let expectedRequestDigest: string;
  if (input.action !== undefined) {
    try {
      expectedRequestDigest = hashActionV2(input.action).requestDigest;
    } catch {
      return deny(
        "request_digest_mismatch",
        "Unable to canonicalize live action for request_digest check",
        permit,
      );
    }
    if (
      input.expectedRequestDigest !== undefined &&
      !constantTimeEqualString(
        expectedRequestDigest,
        input.expectedRequestDigest,
      )
    ) {
      return deny(
        "request_digest_mismatch",
        "Supplied action digest does not match expectedRequestDigest",
        permit,
      );
    }
  } else if (input.expectedRequestDigest !== undefined) {
    expectedRequestDigest = input.expectedRequestDigest;
  } else {
    return deny(
      "request_digest_mismatch",
      "Either action or expectedRequestDigest must be supplied",
      permit,
    );
  }

  // Steps 8..18: Pre-voice policy checks (non-mutating; Step 25 runs after Steps 19..24).
  const baseCheck = evaluatePreVoicePolicyV2({
    permit,
    policy: input.policy,
    expectedAudience: input.expectedAudience,
    expectedRequestDigest,
    expectedSessionId: input.expectedSessionId,
    nowSeconds: precheckNow,
  });

  if (baseCheck.decision === "deny") {
    return deny(baseCheck.reason, baseCheck.detail, permit);
  }

  const voiceRequired =
    isVoiceTier(permit.assurance_tier) ||
    input.policy.required_modalities.includes("voice_liveness");

  // Steps 19..24: Verify embedded VoiceLivenessVerdict JWS when required or present.
  let verifiedVoice: VoiceLivenessVerdictClaims | null = null;
  if (voiceRequired || permit.voice_verdict_jws !== null) {
    if (permit.voice_verdict_jws === null) {
      return deny(
        "voice_verdict_invalid",
        "Permit missing required voice_verdict_jws",
        permit,
      );
    }
    const voiceRes = await verifyVoiceLivenessVerdict({
      jws: permit.voice_verdict_jws,
      jwks: input.voiceJwks ?? input.jwks,
      revokedKids: input.revokedKids,
      nowSeconds: precheckNow,
    });
    if (!voiceRes.ok) {
      if (voiceRes.reason === "state_unavailable") {
        return unavailable(voiceRes.detail, permit);
      }
      if (voiceRes.reason === "voice_retention_violation") {
        return deny("voice_retention_violation", voiceRes.detail, permit);
      }
      return deny("voice_verdict_invalid", voiceRes.detail, permit);
    }
    verifiedVoice = voiceRes.claims;

    const voiceBinding = evaluateVoicePolicyBinding(
      permit,
      verifiedVoice,
      input.policy,
      precheckNow,
    );
    if (!voiceBinding.ok) {
      return deny(voiceBinding.reason, voiceBinding.detail, permit);
    }
  }

  // Steps 25..26: WebAuthn UV digest & optional raw P-256 DER assertion check.
  const webauthnRequired =
    isWebAuthnTier(permit.assurance_tier) ||
    input.policy.required_modalities.includes("webauthn_uv");
  if (webauthnRequired && permit.webauthn_assertion_digest === null) {
    return deny(
      "webauthn_assertion_invalid",
      "Permit missing required webauthn_assertion_digest",
      permit,
    );
  }

  let verifiedWebAuthn: Extract<WebAuthnVerifyResult, { ok: true }> | null =
    null;
  if (input.webauthn !== undefined) {
    const derived = deriveWebAuthnChallengeV2(
      permit.jti,
      permit.request_digest,
    );
    const waRes = verifyWebAuthnAssertionV2({
      ...input.webauthn,
      expectedChallenge: derived.challengeBase64Url,
    });
    if (!waRes.ok) {
      return deny(waRes.reason, waRes.detail, permit);
    }
    if (
      permit.webauthn_assertion_digest === null ||
      !constantTimeEqualString(
        waRes.assertionDigest,
        permit.webauthn_assertion_digest,
      )
    ) {
      return deny(
        "webauthn_assertion_invalid",
        "WebAuthn assertion digest does not match permit.webauthn_assertion_digest",
        permit,
      );
    }
    verifiedWebAuthn = waRes;
  }

  // Step 27: RFC 9449 DPoP sender-constrain verification.
  let verifiedDpop: Extract<DpopVerifyResult, { ok: true }> | null = null;
  if (input.policy.require_dpop || input.dpop !== undefined) {
    const expectedJkt = permit.cnf?.jkt;
    if (!expectedJkt) {
      return deny(
        "dpop_proof_invalid",
        "Permit missing cnf.jkt required for DPoP verification",
        permit,
      );
    }
    if (!input.dpop) {
      return deny(
        "dpop_proof_invalid",
        "Policy requires RFC 9449 DPoP proof",
        permit,
      );
    }
    // Defer jtiStore consumption until after Step 28 and post-precheck clock validation.
    const dpopRes = await verifyDpopProofV2({
      proof: input.dpop.proof,
      expectedJkt,
      expectedHtm: input.dpop.htm,
      expectedHtu: input.dpop.htu,
      permitJws: input.permitJws,
      nowSeconds: precheckNow,
      maxAgeSeconds: input.dpop.maxAgeSeconds,
    });
    if (!dpopRes.ok) {
      return deny("dpop_proof_invalid", dpopRes.detail, permit);
    }
    verifiedDpop = dpopRes;
  }

  // Step 28: IETF SCITT COSE_Sign1 receipt verification.
  let verifiedScitt: VerifiedScittReceipt | null = null;
  if (input.policy.require_scitt_receipt) {
    if (permit.scitt_receipt === null) {
      return deny(
        "scitt_receipt_invalid",
        "Policy requires an embedded IETF SCITT receipt",
        permit,
      );
    }
    const scittRes = await verifyScittReceipt({
      receipt: permit.scitt_receipt,
      jwks: input.scittJwks ?? input.jwks,
      revokedKids: input.revokedKids,
      expectedJti: permit.jti,
      expectedRequestDigest: permit.request_digest,
      expectedPolicyId: permit.policy_id,
      expectedAud: permit.aud,
      expectedDecision: "allow",
    });
    if (!scittRes.ok) {
      if (scittRes.reason === "state_unavailable") {
        return unavailable(scittRes.detail, permit);
      }
      return deny("scitt_receipt_invalid", scittRes.detail, permit);
    }
    verifiedScitt = scittRes.receipt;
  }

  // Resample clock after async JWKS/crypto work before atomic nonce consumption.
  const postPrecheckNow = readNowSeconds(input.nowSeconds);
  if (postPrecheckNow === null) {
    return deny("invalid_permit", "Invalid post-precheck clock timestamp", permit);
  }
  if (postPrecheckNow >= permit.exp) {
    return deny(
      "permit_expired",
      "Permit expired before nonce consumption",
      permit,
      postPrecheckNow,
    );
  }
  if (
    postPrecheckNow - permit.freshness_verified_at >
    input.policy.max_evidence_age_seconds
  ) {
    return deny(
      "evidence_stale",
      "Evidence became stale before nonce consumption",
      permit,
      postPrecheckNow,
    );
  }
  if (verifiedVoice !== null) {
    if (postPrecheckNow >= verifiedVoice.exp) {
      return deny(
        "voice_verdict_invalid",
        "Voice verdict expired before nonce consumption",
        permit,
        postPrecheckNow,
      );
    }
    if (
      input.policy.voice_rules?.max_voice_age_seconds !== undefined &&
      postPrecheckNow - verifiedVoice.iat >
        input.policy.voice_rules.max_voice_age_seconds
    ) {
      return deny(
        "evidence_stale",
        "Voice verdict became stale before nonce consumption",
        permit,
        postPrecheckNow,
      );
    }
  }
  if (verifiedDpop !== null) {
    const dpopMaxAge = input.dpop?.maxAgeSeconds ?? 60;
    if (postPrecheckNow - verifiedDpop.iat > dpopMaxAge) {
      return deny(
        "dpop_proof_invalid",
        "DPoP proof became stale before nonce consumption",
        permit,
        postPrecheckNow,
      );
    }
    if (input.dpop?.jtiStore !== undefined) {
      let dpopFresh: boolean;
      try {
        dpopFresh = await input.dpop.jtiStore.consume(
          verifiedDpop.jti,
          verifiedDpop.iat + dpopMaxAge + PERMIT_V2_LIMITS.clockSkewSeconds,
          postPrecheckNow,
        );
      } catch (error) {
        return unavailable(
          error instanceof Error ? error.message : "DPoP replay store backend error",
          permit,
          postPrecheckNow,
        );
      }
      if (!dpopFresh) {
        return deny(
          "dpop_proof_invalid",
          "DPoP proof jti has already been used",
          permit,
          postPrecheckNow,
        );
      }
    }
  }

  // Steps 29..30: Atomic post-precheck single-use jti consumption.
  if (input.nonceStore !== undefined) {
    let consumeRes;
    try {
      consumeRes = await input.nonceStore.consume({
        jti: permit.jti,
        requestDigest: permit.request_digest,
        aud: permit.aud,
        policyId: permit.policy_id,
        expiresAt: permit.exp,
        nowSeconds: postPrecheckNow,
        requireRegistered: input.requireRegisteredNonce,
      });
    } catch (error) {
      return unavailable(
        error instanceof Error ? error.message : "Nonce store backend error",
        permit,
        postPrecheckNow,
      );
    }

    if (consumeRes.status === "not_found") {
      return deny(
        "nonce_not_found",
        "Permit jti was not registered in nonce store",
        permit,
        postPrecheckNow,
      );
    }
    if (consumeRes.status === "already_consumed") {
      return deny(
        "nonce_replayed",
        "Permit jti has already been consumed",
        permit,
        postPrecheckNow,
      );
    }
    if (consumeRes.status === "expired") {
      return deny(
        "permit_expired",
        "Permit jti expired in nonce store",
        permit,
        postPrecheckNow,
      );
    }
  }

  return {
    decision: "allow",
    reason: "accepted",
    permit,
    voiceVerdict: verifiedVoice,
    webauthn: verifiedWebAuthn,
    dpop: verifiedDpop,
    scittReceipt: verifiedScitt,
    evaluatedAt: postPrecheckNow,
  };
}
