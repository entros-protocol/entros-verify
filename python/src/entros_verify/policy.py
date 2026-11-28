"""Pure Policy v2 evaluator and full 31-step AgentPermit v2 verifier.

Evaluates checks in strict precheck order (refusal codes 1 to 28) before
executing atomic single-use jti consumption (codes 29 to 31), ensuring invalid
probes never burn valid nonces.
"""

from __future__ import annotations

import hmac
import inspect
import re
import time
from collections.abc import Callable, Mapping

from pydantic import ValidationError

from entros_verify.canonical import hash_action_v2
from entros_verify.dpop import DpopJtiStore, DpopVerificationResult, verify_dpop_proof
from entros_verify.errors import (
    CanonicalizationError,
    JwksUnavailableError,
    JwsVerificationError,
    NonceStoreError,
)
from entros_verify.jwks import JwksKeySource, as_jwks_source
from entros_verify.jws import parse_and_validate_jws_header, verify_ed25519_strict
from entros_verify.models import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_PERMIT_LIFETIME_SECONDS,
    MAX_TIMESTAMP_SECONDS,
    MIN_PERMIT_LIFETIME_SECONDS,
    MIN_TIMESTAMP_SECONDS,
    AgentPermitV2,
    CanonicalAction,
    DpopVerificationInput,
    PolicyV2,
    RefusalCode,
    ScittReceiptResult,
    VerificationResult,
    VoiceLivenessVerdict,
    WebAuthnAssertionInput,
    WebAuthnVerificationResult,
)
from entros_verify.nonce_store import NonceConsumeResult, PermitNonceStoreV2
from entros_verify.scitt import (
    ScittVerificationError,
    verify_scitt_receipt,
    verify_scitt_receipt_async,
)
from entros_verify.uri import is_canonical_audience_uri, is_canonical_issuer_uri
from entros_verify.voice import (
    verify_voice_liveness_verdict,
    verify_voice_liveness_verdict_async,
)
from entros_verify.webauthn import verify_webauthn_assertion

AGENT_PERMIT_TYP = "entros-agent-permit+jwt"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO_HEX64 = "0" * 64

_VOICE_TIERS = frozenset(
    {"voice_liveness_webrtc", "voice_liveness_telephony", "voice_plus_passkey"}
)
_WEBAUTHN_TIERS = frozenset({"passkey_webauthn_uv", "voice_plus_passkey"})


def _is_non_zero_hex64(value: str) -> bool:
    return bool(_HEX64_RE.match(value)) and value != _ZERO_HEX64


def _is_printable_ascii(text: str, min_len: int, max_len: int) -> bool:
    if len(text) < min_len or len(text) > max_len:
        return False
    return all(0x20 <= ord(ch) <= 0x7E for ch in text)


def _safe_ct_eq_str(left: str, right: str) -> bool:
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeEncodeError:
        return False


def _read_now_seconds(now_seconds: int | Callable[[], int] | None) -> int | None:
    try:
        val = (
            int(time.time())
            if now_seconds is None
            else (now_seconds() if callable(now_seconds) else now_seconds)
        )
    except Exception:
        return None
    if not isinstance(val, int) or isinstance(val, bool):
        return None
    if not (MIN_TIMESTAMP_SECONDS <= val <= MAX_TIMESTAMP_SECONDS):
        return None
    return val


def _deny(
    reason: RefusalCode,
    *,
    evaluated_at: int,
    detail: str | None = None,
    permit: AgentPermitV2 | None = None,
    voice_verdict: VoiceLivenessVerdict | None = None,
) -> VerificationResult:
    return VerificationResult(
        ok=False,
        decision="deny",
        reason=reason,
        detail=detail,
        permit=permit,
        voice_verdict=voice_verdict,
        evaluated_at=evaluated_at,
    )


def _unavailable(
    *,
    evaluated_at: int,
    detail: str,
    permit: AgentPermitV2 | None = None,
) -> VerificationResult:
    return VerificationResult(
        ok=False,
        decision="unavailable",
        reason=RefusalCode.STATE_UNAVAILABLE,
        detail=detail,
        permit=permit,
        evaluated_at=evaluated_at,
    )


def _validate_permit_structure(
    payload: Mapping[str, object],
    *,
    evaluated_at: int,
) -> tuple[AgentPermitV2 | None, VerificationResult | None]:
    """Step 7: Validate AgentPermitV2 schema and claim formats."""
    try:
        permit = AgentPermitV2.model_validate(payload)
    except ValidationError as exc:
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail=f"Invalid AgentPermitV2 claims: {exc.error_count()} validation error(s)",
        )

    if not is_canonical_issuer_uri(permit.iss):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="Invalid permit issuer URI",
        )

    if not _is_printable_ascii(permit.sub, 1, 256):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="Invalid sub claim format",
        )

    if not _is_non_zero_hex64(permit.jti):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="jti must be non-zero 64 lowercase hex",
        )

    if not _is_non_zero_hex64(permit.request_digest):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="request_digest must be non-zero 64 lowercase hex",
        )

    if not (MIN_TIMESTAMP_SECONDS <= permit.iat <= MAX_TIMESTAMP_SECONDS):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="iat timestamp out of valid bounds",
        )

    if not (MIN_TIMESTAMP_SECONDS <= permit.exp <= MAX_TIMESTAMP_SECONDS):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="exp timestamp out of valid bounds",
        )

    if not (MIN_TIMESTAMP_SECONDS <= permit.freshness_verified_at <= MAX_TIMESTAMP_SECONDS):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="freshness_verified_at timestamp out of valid bounds",
        )

    if not permit.modality or any(not _is_printable_ascii(m, 1, 64) for m in permit.modality):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="modality must be a non-empty list of printable ASCII tokens",
        )
    if any(
        permit.modality[i - 1] >= permit.modality[i]
        for i in range(1, len(permit.modality))
    ):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="modality must be strictly sorted and unique",
        )

    if not _is_printable_ascii(permit.policy_id, 1, 128):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="Invalid policy_id claim",
        )

    if not _is_printable_ascii(permit.continuity.session_id, 1, 128):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="Invalid continuity.session_id",
        )

    if permit.continuity.prior_permit_jti is not None and not _is_non_zero_hex64(
        permit.continuity.prior_permit_jti
    ):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="Invalid continuity.prior_permit_jti",
        )

    if permit.webauthn_assertion_digest is not None and not _is_non_zero_hex64(
        permit.webauthn_assertion_digest
    ):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="webauthn_assertion_digest must be non-zero 64 lowercase hex when present",
        )

    if (
        permit.cnf is not None
        and permit.actor.key_jkt is not None
        and not _safe_ct_eq_str(permit.cnf.jkt, permit.actor.key_jkt)
    ):
        return None, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=evaluated_at,
            detail="permit cnf.jkt does not match actor.key_jkt",
        )

    return permit, None


def _requires_voice(permit: AgentPermitV2, policy: PolicyV2) -> bool:
    return (
        permit.assurance_tier in _VOICE_TIERS
        or "voice_liveness" in policy.required_modalities
    )


def _requires_webauthn(permit: AgentPermitV2, policy: PolicyV2) -> bool:
    return (
        permit.assurance_tier in _WEBAUTHN_TIERS
        or "webauthn_uv" in policy.required_modalities
    )


def _check_uniqueness(permit: AgentPermitV2, policy: PolicyV2) -> bool:
    req = policy.uniqueness_requirement
    if req == "allow_unmeasured":
        return True
    if req == "require_session_bound":
        return permit.uniqueness_status in ("session_bound", "enterprise_idp_subject")
    if req == "require_enterprise_idp_subject":
        return permit.uniqueness_status == "enterprise_idp_subject"
    return False


def _evaluate_pre_voice_steps(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    expected_audience: str,
    expected_request_digest: str | None,
    now_seconds: int,
    expected_session_id: str | None = None,
    digest_err: str | None = None,
) -> VerificationResult | None:
    """Evaluate pure non-I/O steps 8 through 18 in normative order; return None if allowed."""
    if (
        not isinstance(now_seconds, int)
        or isinstance(now_seconds, bool)
        or not (MIN_TIMESTAMP_SECONDS <= now_seconds <= MAX_TIMESTAMP_SECONDS)
    ):
        return _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=0,
            detail="Invalid evaluation clock timestamp",
            permit=permit,
        )

    if (
        permit.cnf is not None
        and permit.actor.key_jkt is not None
        and not _safe_ct_eq_str(permit.cnf.jkt, permit.actor.key_jkt)
    ):
        return _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=now_seconds,
            detail="permit cnf.jkt does not match actor.key_jkt",
            permit=permit,
        )

    # Step 8: Permit lifetime bounds (30..900s and policy cap).
    lifetime = permit.exp - permit.iat
    max_lifetime = min(MAX_PERMIT_LIFETIME_SECONDS, policy.max_permit_lifetime_seconds)
    if lifetime < MIN_PERMIT_LIFETIME_SECONDS or lifetime > max_lifetime:
        return _deny(
            RefusalCode.LIFETIME_EXCEEDED,
            evaluated_at=now_seconds,
            detail=f"Permit lifetime {lifetime}s outside allowed 30..{max_lifetime}s",
            permit=permit,
        )

    # Step 9: Forward clock skew <= 30s.
    if permit.iat > now_seconds + MAX_CLOCK_SKEW_SECONDS:
        return _deny(
            RefusalCode.CLOCK_SKEW_EXCEEDED,
            evaluated_at=now_seconds,
            detail="Permit iat exceeds 30s forward clock skew",
            permit=permit,
        )

    # Step 10: Permit expiry.
    if now_seconds >= permit.exp:
        return _deny(
            RefusalCode.PERMIT_EXPIRED,
            evaluated_at=now_seconds,
            detail="Permit has expired",
            permit=permit,
        )

    # Step 11: Canonical RFC 8707 audience URI match.
    if not is_canonical_audience_uri(permit.aud) or not is_canonical_audience_uri(
        expected_audience
    ):
        return _deny(
            RefusalCode.AUDIENCE_MISMATCH,
            evaluated_at=now_seconds,
            detail="Audience URI failed canonical RFC 8707 grammar",
            permit=permit,
        )
    if not hmac.compare_digest(
        permit.aud.encode("utf-8"), expected_audience.encode("utf-8")
    ):
        return _deny(
            RefusalCode.AUDIENCE_MISMATCH,
            evaluated_at=now_seconds,
            detail="Permit aud does not match expected resource URI",
            permit=permit,
        )

    # Step 12: Canonical RFC 8785 request_digest match.
    if (
        expected_request_digest is None
        or not _is_non_zero_hex64(expected_request_digest)
        or not hmac.compare_digest(
            permit.request_digest.encode("ascii"), expected_request_digest.encode("ascii")
        )
    ):
        return _deny(
            RefusalCode.REQUEST_DIGEST_MISMATCH,
            evaluated_at=now_seconds,
            detail=digest_err or "Recomputed request_digest does not match permit",
            permit=permit,
        )

    # Step 13: Policy contract identifier match.
    if permit.policy_id != policy.policy_id:
        return _deny(
            RefusalCode.POLICY_MISMATCH,
            evaluated_at=now_seconds,
            detail="Permit policy_id does not satisfy Policy v2",
            permit=permit,
        )

    # Step 14: Explicit assurance_tier set membership (anti-downgrade).
    if permit.assurance_tier not in policy.allowed_assurance_tiers:
        return _deny(
            RefusalCode.ASSURANCE_DOWNGRADE,
            evaluated_at=now_seconds,
            detail=f"assurance_tier {permit.assurance_tier!r} not in allowed_assurance_tiers",
            permit=permit,
        )

    # Step 15: Required modalities subset check against policy.required_modalities.
    permit_modalities = set(permit.modality)
    required_modalities = set(policy.required_modalities)
    if not required_modalities.issubset(permit_modalities):
        missing = sorted(required_modalities - permit_modalities)
        return _deny(
            RefusalCode.MODALITY_MISSING,
            evaluated_at=now_seconds,
            detail=f"Missing required modalities: {missing}",
            permit=permit,
        )

    # Uniqueness boundary enforcement when policy requests stronger uniqueness.
    if not _check_uniqueness(permit, policy):
        return _deny(
            RefusalCode.ASSURANCE_DOWNGRADE,
            evaluated_at=now_seconds,
            detail=(
                f"uniqueness_status {permit.uniqueness_status!r} does not satisfy "
                f"{policy.uniqueness_requirement!r}"
            ),
            permit=permit,
        )

    # Step 16 (part 1): Freshness monotonicity against permit iat.
    if permit.freshness_verified_at > permit.iat:
        return _deny(
            RefusalCode.FRESHNESS_REGRESSION,
            evaluated_at=now_seconds,
            detail="freshness_verified_at exceeds permit iat",
            permit=permit,
        )

    # Step 17: Evidence staleness bound.
    if now_seconds - permit.freshness_verified_at > policy.max_evidence_age_seconds:
        return _deny(
            RefusalCode.EVIDENCE_STALE,
            evaluated_at=now_seconds,
            detail="Underlying human-presence evidence exceeds max_evidence_age_seconds",
            permit=permit,
        )

    # Step 18: Continuity requirement.
    if (
        expected_session_id is not None
        and permit.continuity.session_id != expected_session_id
    ):
        return _deny(
            RefusalCode.CONTINUITY_BROKEN,
            evaluated_at=now_seconds,
            detail="Permit continuity.session_id does not match active session",
            permit=permit,
        )
    voice_required = _requires_voice(permit, policy)
    if policy.require_continuity:
        if permit.continuity.call_continuity_verified is not True:
            return _deny(
                RefusalCode.CONTINUITY_BROKEN,
                evaluated_at=now_seconds,
                detail="Policy requires verified call continuity",
                permit=permit,
            )
        if voice_required and permit.continuity.mode != "call_session":
            return _deny(
                RefusalCode.CONTINUITY_BROKEN,
                evaluated_at=now_seconds,
                detail="Continuous voice screening requires continuity.mode == 'call_session'",
                permit=permit,
            )

    return None


def _evaluate_voice_binding_steps(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    voice_verdict: VoiceLivenessVerdict | None,
    now_seconds: int,
) -> VerificationResult | None:
    """Evaluate pure steps 19 through 24 for VoiceLivenessVerdict binding."""
    voice_required = _requires_voice(permit, policy)
    if voice_required and voice_verdict is None:
        return _deny(
            RefusalCode.VOICE_VERDICT_INVALID,
            evaluated_at=now_seconds,
            detail="Verified VoiceLivenessVerdict is required",
            permit=permit,
        )

    if voice_verdict is None:
        return None

    # Step 20: Mandatory memory_only retention invariant.
    if voice_verdict.retention != "memory_only":
        return _deny(
            RefusalCode.VOICE_RETENTION_VIOLATION,
            evaluated_at=now_seconds,
            detail="VoiceLivenessVerdict retention must be 'memory_only'",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Freshness monotonicity against underlying voice verdict iat.
    if permit.freshness_verified_at > voice_verdict.iat:
        return _deny(
            RefusalCode.FRESHNESS_REGRESSION,
            evaluated_at=now_seconds,
            detail="freshness_verified_at exceeds underlying voice verdict iat",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Session ID continuity binding.
    if not voice_verdict.session_id or voice_verdict.session_id != permit.continuity.session_id:
        return _deny(
            RefusalCode.CONTINUITY_BROKEN,
            evaluated_at=now_seconds,
            detail="Voice verdict session_id does not match permit continuity.session_id",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    rules = policy.voice_rules

    # Optional voice age bound when explicitly configured.
    if (
        rules is not None
        and rules.max_voice_age_seconds is not None
        and now_seconds - voice_verdict.iat > rules.max_voice_age_seconds
    ):
        return _deny(
            RefusalCode.EVIDENCE_STALE,
            evaluated_at=now_seconds,
            detail="Voice verdict age exceeds policy.voice_rules.max_voice_age_seconds",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 21: Operating profile alignment with assurance_tier and optional voice_rules.
    if (
        permit.assurance_tier == "voice_liveness_webrtc"
        and voice_verdict.operating_profile not in ("webrtc_16k", "wideband_clean")
    ):
        return _deny(
            RefusalCode.VOICE_PROFILE_DISALLOWED,
            evaluated_at=now_seconds,
            detail="voice_liveness_webrtc requires webrtc_16k or wideband_clean profile",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if (
        permit.assurance_tier == "voice_liveness_telephony"
        and voice_verdict.operating_profile != "telephony_8k"
    ):
        return _deny(
            RefusalCode.VOICE_PROFILE_DISALLOWED,
            evaluated_at=now_seconds,
            detail="voice_liveness_telephony requires telephony_8k profile",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if rules is not None and voice_verdict.operating_profile not in rules.allowed_profiles:
        return _deny(
            RefusalCode.VOICE_PROFILE_DISALLOWED,
            evaluated_at=now_seconds,
            detail=f"operating_profile {voice_verdict.operating_profile!r} is disallowed",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if (
        rules is not None
        and rules.allowed_model_versions
        and voice_verdict.model_version not in rules.allowed_model_versions
    ):
        return _deny(
            RefusalCode.VOICE_PROFILE_DISALLOWED,
            evaluated_at=now_seconds,
            detail="Voice model_version is not in allowed_model_versions",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 22: Verdict, abstain, and optional calibrated LLR / signal quality floors.
    allowed_verdicts = rules.allowed_verdicts if rules is not None else ["likely_human"]
    reject_on_abstain = rules.reject_on_abstain if rules is not None else True
    if (
        voice_verdict.verdict == "insufficient_signal" and reject_on_abstain
    ) or voice_verdict.verdict not in allowed_verdicts:
        return _deny(
            RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
            evaluated_at=now_seconds,
            detail=f"Voice verdict {voice_verdict.verdict!r} is not permitted by policy",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if rules is not None and rules.min_calibrated_llr is not None and (
        voice_verdict.calibrated_llr is None
        or voice_verdict.calibrated_llr < rules.min_calibrated_llr
    ):
        return _deny(
            RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
            evaluated_at=now_seconds,
            detail="Voice calibrated_llr is below policy minimum",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if (
        rules is not None
        and rules.min_speech_ms is not None
        and voice_verdict.signal_quality.speech_ms < rules.min_speech_ms
    ):
        return _deny(
            RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
            evaluated_at=now_seconds,
            detail="Voice speech_ms is below policy minimum",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if (
        rules is not None
        and rules.min_snr_db is not None
        and voice_verdict.signal_quality.snr_db < rules.min_snr_db
    ):
        return _deny(
            RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
            evaluated_at=now_seconds,
            detail="Voice snr_db is below policy minimum",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 23: Partial-spoof span gate.
    max_spans = rules.max_partial_spoof_spans if rules is not None else 0
    if len(voice_verdict.partial_spoof_spans) > max_spans:
        return _deny(
            RefusalCode.PARTIAL_SPOOF_DETECTED,
            evaluated_at=now_seconds,
            detail="Partial spoof spans exceed policy.voice_rules.max_partial_spoof_spans",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if (
        rules is not None
        and rules.max_partial_spoof_probability is not None
        and any(
            span.spoof_probability > rules.max_partial_spoof_probability
            for span in voice_verdict.partial_spoof_spans
        )
    ):
        return _deny(
            RefusalCode.PARTIAL_SPOOF_DETECTED,
            evaluated_at=now_seconds,
            detail="Partial spoof span probability exceeds policy ceiling",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 24: Rolling consistency drift monitor gate.
    reject_drift = rules.reject_on_consistency_drift if rules is not None else True
    if reject_drift and voice_verdict.consistency_drift.status == "elevated":
        return _deny(
            RefusalCode.CONSISTENCY_DRIFT_EXCEEDED,
            evaluated_at=now_seconds,
            detail="Voice consistency_drift status is elevated",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    return None


def _evaluate_webauthn_steps(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    webauthn_result: WebAuthnVerificationResult | None,
    now_seconds: int,
    voice_verdict: VoiceLivenessVerdict | None,
) -> tuple[str | None, VerificationResult | None]:
    """Evaluate pure steps 25 and 26 for hardware Passkey (WebAuthn UV) checks."""
    webauthn_digest: str | None = permit.webauthn_assertion_digest
    if _requires_webauthn(permit, policy) and permit.webauthn_assertion_digest is None:
        return None, _deny(
            RefusalCode.WEBAUTHN_ASSERTION_INVALID,
            evaluated_at=now_seconds,
            detail="Permit missing required webauthn_assertion_digest",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if webauthn_result is not None:
        if not webauthn_result.ok:
            return None, _deny(
                webauthn_result.reason or RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                evaluated_at=now_seconds,
                detail="WebAuthn assertion verification failed",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if (
            permit.webauthn_assertion_digest is None
            or webauthn_result.assertion_digest is None
            or not _safe_ct_eq_str(
                webauthn_result.assertion_digest,
                permit.webauthn_assertion_digest,
            )
        ):
            return None, _deny(
                RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                evaluated_at=now_seconds,
                detail="WebAuthn assertion digest does not match permit.webauthn_assertion_digest",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        webauthn_digest = webauthn_result.assertion_digest
    return webauthn_digest, None


def _evaluate_dpop_step(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    dpop_verified: bool | None,
    now_seconds: int,
    voice_verdict: VoiceLivenessVerdict | None,
) -> VerificationResult | None:
    """Evaluate pure step 27 for RFC 9449 DPoP sender-constraint enforcement."""
    if policy.require_dpop:
        if permit.cnf is None or dpop_verified is not True:
            return _deny(
                RefusalCode.DPOP_PROOF_INVALID,
                evaluated_at=now_seconds,
                detail="Policy requires valid RFC 9449 DPoP proof bound to cnf.jkt",
                permit=permit,
                voice_verdict=voice_verdict,
            )
    elif dpop_verified is False:
        return _deny(
            RefusalCode.DPOP_PROOF_INVALID,
            evaluated_at=now_seconds,
            detail="Presented DPoP proof failed verification",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    return None


def _evaluate_scitt_step(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    scitt_receipt: ScittReceiptResult | None,
    require_scitt_verified: bool,
    now_seconds: int,
    voice_verdict: VoiceLivenessVerdict | None,
) -> tuple[ScittReceiptResult | None, VerificationResult | None]:
    """Evaluate pure step 28 for IETF SCITT receipt presence and allow bindings."""
    if not policy.require_scitt_receipt:
        return None, None
    if permit.scitt_receipt is None or (require_scitt_verified and scitt_receipt is None):
        return None, _deny(
            RefusalCode.SCITT_RECEIPT_INVALID,
            evaluated_at=now_seconds,
            detail="Policy requires a verified SCITT COSE_Sign1 receipt",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if scitt_receipt is not None:
        sp = scitt_receipt.payload
        if (
            sp.decision != "allow"
            or sp.jti != permit.jti
            or sp.request_digest != permit.request_digest
            or sp.policy_id != permit.policy_id
            or sp.aud != permit.aud
            or sp.retention != "memory_only"
        ):
            return None, _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now_seconds,
                detail="SCITT receipt payload does not match allow permit bindings",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        return scitt_receipt, None
    return None, None


def evaluate_policy_v2(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    expected_audience: str,
    expected_request_digest: str,
    now_seconds: int,
    expected_session_id: str | None = None,
    voice_verdict: VoiceLivenessVerdict | None = None,
    webauthn_result: WebAuthnVerificationResult | None = None,
    dpop_verified: bool | None = None,
    scitt_receipt: ScittReceiptResult | None = None,
    require_scitt_verified: bool = True,
) -> VerificationResult:
    """Pure Policy v2 evaluator with zero I/O or nonce mutation (steps 8 to 28)."""
    pre_voice_err = _evaluate_pre_voice_steps(
        permit=permit,
        policy=policy,
        expected_audience=expected_audience,
        expected_request_digest=expected_request_digest,
        now_seconds=now_seconds,
        expected_session_id=expected_session_id,
    )
    if pre_voice_err is not None:
        return pre_voice_err

    voice_err = _evaluate_voice_binding_steps(
        permit=permit,
        policy=policy,
        voice_verdict=voice_verdict,
        now_seconds=now_seconds,
    )
    if voice_err is not None:
        return voice_err

    webauthn_digest, webauthn_err = _evaluate_webauthn_steps(
        permit=permit,
        policy=policy,
        webauthn_result=webauthn_result,
        now_seconds=now_seconds,
        voice_verdict=voice_verdict,
    )
    if webauthn_err is not None:
        return webauthn_err

    dpop_err = _evaluate_dpop_step(
        permit=permit,
        policy=policy,
        dpop_verified=dpop_verified,
        now_seconds=now_seconds,
        voice_verdict=voice_verdict,
    )
    if dpop_err is not None:
        return dpop_err

    verified_scitt, scitt_err = _evaluate_scitt_step(
        permit=permit,
        policy=policy,
        scitt_receipt=scitt_receipt,
        require_scitt_verified=require_scitt_verified,
        now_seconds=now_seconds,
        voice_verdict=voice_verdict,
    )
    if scitt_err is not None:
        return scitt_err

    return VerificationResult(
        ok=True,
        decision="allow",
        reason=None,
        permit=permit,
        voice_verdict=voice_verdict,
        scitt_receipt=verified_scitt,
        webauthn_assertion_digest=webauthn_digest,
        evaluated_at=now_seconds,
    )


def _resolve_expected_digest(
    *,
    action: CanonicalAction | Mapping[str, object] | None,
    expected_request_digest: str | None,
) -> tuple[str | None, str | None]:
    if action is not None:
        try:
            computed = hash_action_v2(action)
        except CanonicalizationError as exc:
            return None, f"Action canonicalization failed: {exc}"
        if expected_request_digest is not None and not _safe_ct_eq_str(
            computed, expected_request_digest
        ):
            return None, "Provided action digest disagrees with expected_request_digest"
        return computed, None
    return expected_request_digest, None


def _apply_nonce_outcome(
    outcome: NonceConsumeResult,
    *,
    precheck: VerificationResult,
    evaluated_at: int,
) -> VerificationResult:
    if outcome.status == "consumed":
        if precheck.evaluated_at != evaluated_at:
            return precheck.model_copy(update={"evaluated_at": evaluated_at})
        return precheck
    if outcome.status == "not_found":
        return _deny(
            RefusalCode.NONCE_NOT_FOUND,
            evaluated_at=evaluated_at,
            detail="Permit jti was not registered in the nonce store",
            permit=precheck.permit,
            voice_verdict=precheck.voice_verdict,
        )
    if outcome.status == "already_consumed":
        return _deny(
            RefusalCode.NONCE_REPLAYED,
            evaluated_at=evaluated_at,
            detail="Permit jti has already been consumed",
            permit=precheck.permit,
            voice_verdict=precheck.voice_verdict,
        )
    return _deny(
        RefusalCode.PERMIT_EXPIRED,
        evaluated_at=evaluated_at,
        detail="Nonce record expired before consumption",
        permit=precheck.permit,
        voice_verdict=precheck.voice_verdict,
    )


def _run_dpop_precheck(
    *,
    permit: AgentPermitV2,
    permit_jws: str,
    policy: PolicyV2,
    dpop: DpopVerificationInput | None,
    now_seconds: int,
) -> tuple[bool | None, DpopVerificationResult | None]:
    if not policy.require_dpop and dpop is None:
        return None, None
    if permit.cnf is None or dpop is None:
        return False, None
    res = verify_dpop_proof(
        proof_jwt=dpop.proof_jwt,
        expected_jkt=permit.cnf.jkt,
        expected_htm=dpop.htm,
        expected_htu=dpop.htu,
        permit_jws=permit_jws,
        now_seconds=now_seconds,
        max_age_seconds=dpop.max_age_seconds,
    )
    return res.ok, res


def _finalize_post_precheck_checks(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    voice_verdict: VoiceLivenessVerdict | None,
    dpop: DpopVerificationInput | None,
    dpop_res: DpopVerificationResult | None,
    dpop_jti_store: DpopJtiStore | None,
    now_seconds: int | Callable[[], int] | None,
) -> tuple[int, VerificationResult | None]:
    """Resample clock after async/sync JWKS work, recheck expiry/age, and consume DPoP jti."""
    post_now = _read_now_seconds(now_seconds)
    if post_now is None:
        return 0, _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=0,
            detail="Invalid post-precheck clock timestamp",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if post_now >= permit.exp:
        return post_now, _deny(
            RefusalCode.PERMIT_EXPIRED,
            evaluated_at=post_now,
            detail="Permit expired before nonce consumption",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if post_now - permit.freshness_verified_at > policy.max_evidence_age_seconds:
        return post_now, _deny(
            RefusalCode.EVIDENCE_STALE,
            evaluated_at=post_now,
            detail="Evidence became stale before nonce consumption",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if voice_verdict is not None:
        if post_now >= voice_verdict.exp:
            return post_now, _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=post_now,
                detail="Voice verdict expired before nonce consumption",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if (
            policy.voice_rules is not None
            and policy.voice_rules.max_voice_age_seconds is not None
            and post_now - voice_verdict.iat > policy.voice_rules.max_voice_age_seconds
        ):
            return post_now, _deny(
                RefusalCode.EVIDENCE_STALE,
                evaluated_at=post_now,
                detail="Voice verdict became stale before nonce consumption",
                permit=permit,
                voice_verdict=voice_verdict,
            )
    if dpop is not None and dpop_res is not None and dpop_res.ok:
        if dpop_res.iat is not None and post_now - dpop_res.iat > dpop.max_age_seconds:
            return post_now, _deny(
                RefusalCode.DPOP_PROOF_INVALID,
                evaluated_at=post_now,
                detail="DPoP proof became stale before nonce consumption",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if dpop_jti_store is not None and dpop_res.jti is not None and dpop_res.iat is not None:
            try:
                dpop_fresh = dpop_jti_store.consume(
                    dpop_res.jti,
                    dpop_res.iat + dpop.max_age_seconds + MAX_CLOCK_SKEW_SECONDS,
                    post_now,
                )
            except Exception as exc:
                return post_now, _unavailable(
                    evaluated_at=post_now,
                    detail=f"DPoP replay store backend error: {type(exc).__name__}",
                    permit=permit,
                )
            if not dpop_fresh:
                return post_now, _deny(
                    RefusalCode.DPOP_PROOF_INVALID,
                    evaluated_at=post_now,
                    detail="DPoP jti replay detected",
                    permit=permit,
                    voice_verdict=voice_verdict,
                )
    return post_now, None


def _run_webauthn_and_dpop_prechecks(
    *,
    permit: AgentPermitV2,
    permit_jws: str,
    policy: PolicyV2,
    voice_verdict: VoiceLivenessVerdict | None,
    webauthn_assertion: WebAuthnAssertionInput | None,
    dpop: DpopVerificationInput | None,
    now: int,
) -> tuple[str | None, DpopVerificationResult | None, VerificationResult | None]:
    """Run Steps 25..27 strictly before Step 28 SCITT."""
    webauthn_res: WebAuthnVerificationResult | None = None
    if webauthn_assertion is not None:
        webauthn_res = verify_webauthn_assertion(
            webauthn_assertion,
            jti=permit.jti,
            request_digest=permit.request_digest,
            expected_assertion_digest=permit.webauthn_assertion_digest,
        )
    webauthn_digest, webauthn_err = _evaluate_webauthn_steps(
        permit=permit,
        policy=policy,
        webauthn_result=webauthn_res,
        now_seconds=now,
        voice_verdict=voice_verdict,
    )
    if webauthn_err is not None:
        return None, None, webauthn_err

    dpop_ok, dpop_res = _run_dpop_precheck(
        permit=permit,
        permit_jws=permit_jws,
        policy=policy,
        dpop=dpop,
        now_seconds=now,
    )
    dpop_err = _evaluate_dpop_step(
        permit=permit,
        policy=policy,
        dpop_verified=dpop_ok,
        now_seconds=now,
        voice_verdict=voice_verdict,
    )
    if dpop_err is not None:
        return None, None, dpop_err

    return webauthn_digest, dpop_res, None


def verify_agent_permit_v2(
    permit_jws: str,
    *,
    policy: PolicyV2,
    expected_audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    action: CanonicalAction | Mapping[str, object] | None = None,
    expected_request_digest: str | None = None,
    expected_session_id: str | None = None,
    now_seconds: int | Callable[[], int] | None = None,
    voice_jwks: JwksKeySource | Mapping[str, object] | None = None,
    scitt_jwks: JwksKeySource | Mapping[str, object] | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
    webauthn_assertion: WebAuthnAssertionInput | None = None,
    dpop: DpopVerificationInput | None = None,
    dpop_jti_store: DpopJtiStore | None = None,
    nonce_store: PermitNonceStoreV2 | None = None,
    require_registered_nonce: bool = False,
) -> VerificationResult:
    """Synchronously verify an AgentPermit v2 compact JWS in strict 31-step order."""
    now = _read_now_seconds(now_seconds)
    if now is None:
        return _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=0,
            detail="Invalid verifier clock timestamp",
        )

    # Steps 1 to 4 (header parsing).
    try:
        parsed = parse_and_validate_jws_header(permit_jws, expected_typ=AGENT_PERMIT_TYP)
    except JwsVerificationError as exc:
        return _deny(RefusalCode(exc.code), evaluated_at=now, detail=str(exc))

    # Steps 4 to 5: JWKS key lookup & revocation check.
    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    try:
        lookup = source.get_key(parsed.kid)
    except JwksUnavailableError as exc:
        return _unavailable(evaluated_at=now, detail=str(exc))

    if lookup.status != "found" or lookup.key is None:
        return _deny(
            lookup.refusal_code or RefusalCode.UNKNOWN_KID,
            evaluated_at=now,
            detail=f"JWKS lookup failed for kid={parsed.kid}: {lookup.status}",
        )

    # Step 6: Strict RFC 8032 / zip215=False Ed25519 signature verification.
    if not verify_ed25519_strict(
        lookup.key.public_key_bytes, parsed.signature, parsed.signing_input
    ):
        return _deny(
            RefusalCode.INVALID_SIGNATURE,
            evaluated_at=now,
            detail="Permit Ed25519 signature verification failed",
        )

    # Step 7: Strict permit schema validation.
    permit, err = _validate_permit_structure(parsed.payload, evaluated_at=now)
    if err is not None or permit is None:
        return err or _deny(RefusalCode.INVALID_PERMIT, evaluated_at=now)

    # Steps 8 to 18 before any remote voice/SCITT JWKS fetches or WebAuthn/DPoP crypto.
    digest_str, digest_err = _resolve_expected_digest(
        action=action,
        expected_request_digest=expected_request_digest,
    )
    pre_voice_err = _evaluate_pre_voice_steps(
        permit=permit,
        policy=policy,
        expected_audience=expected_audience,
        expected_request_digest=digest_str,
        now_seconds=now,
        expected_session_id=expected_session_id,
        digest_err=digest_err,
    )
    if pre_voice_err is not None:
        return pre_voice_err

    # Steps 19 to 24: Verify embedded VoiceLivenessVerdict JWS & rules before WebAuthn/DPoP/SCITT.
    voice_required = _requires_voice(permit, policy)
    voice_verdict: VoiceLivenessVerdict | None = None
    if voice_required or permit.voice_verdict_jws is not None:
        if permit.voice_verdict_jws is None:
            return _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=now,
                detail="Permit missing required voice_verdict_jws",
                permit=permit,
            )
        v_source = as_jwks_source(voice_jwks or jwks, revoked_kids=revoked_kids)
        v_res = verify_voice_liveness_verdict(
            permit.voice_verdict_jws,
            jwks=v_source,
            now_seconds=now,
        )
        if v_res.reason == RefusalCode.STATE_UNAVAILABLE:
            return _unavailable(
                evaluated_at=now,
                detail=v_res.detail or "Voice JWKS unavailable",
                permit=permit,
            )
        if not v_res.ok:
            if v_res.reason == RefusalCode.VOICE_RETENTION_VIOLATION:
                return _deny(
                    RefusalCode.VOICE_RETENTION_VIOLATION,
                    evaluated_at=now,
                    detail=v_res.detail or "Voice verdict retention violation",
                    permit=permit,
                )
            return _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=now,
                detail=v_res.detail or "Embedded voice verdict verification failed",
                permit=permit,
            )
        voice_verdict = v_res.verdict

    voice_err = _evaluate_voice_binding_steps(
        permit=permit,
        policy=policy,
        voice_verdict=voice_verdict,
        now_seconds=now,
    )
    if voice_err is not None:
        return voice_err

    # Steps 25 to 27: WebAuthn and DPoP prechecks strictly before Step 28 SCITT.
    webauthn_digest, dpop_res, wd_err = _run_webauthn_and_dpop_prechecks(
        permit=permit,
        permit_jws=permit_jws,
        policy=policy,
        voice_verdict=voice_verdict,
        webauthn_assertion=webauthn_assertion,
        dpop=dpop,
        now=now,
    )
    if wd_err is not None:
        return wd_err

    # Step 28: Verify IETF SCITT receipt strictly when policy.require_scitt_receipt is True.
    scitt_res: ScittReceiptResult | None = None
    if policy.require_scitt_receipt:
        if permit.scitt_receipt is None:
            return _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now,
                detail="Policy requires an embedded IETF SCITT receipt",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        s_source = as_jwks_source(scitt_jwks or jwks, revoked_kids=revoked_kids)
        try:
            scitt_res = verify_scitt_receipt(
                permit.scitt_receipt,
                jwks=s_source,
                expected_decision="allow",
            )
        except JwksUnavailableError as exc:
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except ScittVerificationError as exc:
            return _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now,
                detail=str(exc),
                permit=permit,
                voice_verdict=voice_verdict,
            )

    verified_scitt, scitt_err = _evaluate_scitt_step(
        permit=permit,
        policy=policy,
        scitt_receipt=scitt_res,
        require_scitt_verified=True,
        now_seconds=now,
        voice_verdict=voice_verdict,
    )
    if scitt_err is not None:
        return scitt_err

    precheck = VerificationResult(
        ok=True,
        decision="allow",
        reason=None,
        permit=permit,
        voice_verdict=voice_verdict,
        scitt_receipt=verified_scitt,
        webauthn_assertion_digest=webauthn_digest,
        evaluated_at=now,
    )

    post_now, post_err = _finalize_post_precheck_checks(
        permit=permit,
        policy=policy,
        voice_verdict=voice_verdict,
        dpop=dpop,
        dpop_res=dpop_res,
        dpop_jti_store=dpop_jti_store,
        now_seconds=now_seconds,
    )
    if post_err is not None:
        return post_err

    # Steps 29 to 30: Strictly post-precheck atomic jti consumption.
    if nonce_store is not None:
        try:
            outcome = nonce_store.consume_once(
                jti=permit.jti,
                now_seconds=post_now,
                expires_at=permit.exp,
                require_registered=require_registered_nonce,
                request_digest=permit.request_digest,
                aud=permit.aud,
                policy_id=permit.policy_id,
            )
            if inspect.isawaitable(outcome):
                raise NonceStoreError(
                    "async_store",
                    "Async PermitNonceStoreV2 requires verify_agent_permit_v2_async",
                )
        except NonceStoreError as exc:
            return _unavailable(evaluated_at=post_now, detail=str(exc), permit=permit)
        except Exception as exc:
            return _unavailable(
                evaluated_at=post_now,
                detail=f"Nonce store backend error: {type(exc).__name__}",
                permit=permit,
            )
        return _apply_nonce_outcome(outcome, precheck=precheck, evaluated_at=post_now)

    return precheck.model_copy(update={"evaluated_at": post_now}) if post_now != now else precheck


async def verify_agent_permit_v2_async(
    permit_jws: str,
    *,
    policy: PolicyV2,
    expected_audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    action: CanonicalAction | Mapping[str, object] | None = None,
    expected_request_digest: str | None = None,
    expected_session_id: str | None = None,
    now_seconds: int | Callable[[], int] | None = None,
    voice_jwks: JwksKeySource | Mapping[str, object] | None = None,
    scitt_jwks: JwksKeySource | Mapping[str, object] | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
    webauthn_assertion: WebAuthnAssertionInput | None = None,
    dpop: DpopVerificationInput | None = None,
    dpop_jti_store: DpopJtiStore | None = None,
    nonce_store: PermitNonceStoreV2 | None = None,
    require_registered_nonce: bool = False,
) -> VerificationResult:
    """Asynchronously verify an AgentPermit v2 compact JWS in strict 31-step order."""
    now = _read_now_seconds(now_seconds)
    if now is None:
        return _deny(
            RefusalCode.INVALID_PERMIT,
            evaluated_at=0,
            detail="Invalid verifier clock timestamp",
        )

    try:
        parsed = parse_and_validate_jws_header(permit_jws, expected_typ=AGENT_PERMIT_TYP)
    except JwsVerificationError as exc:
        return _deny(RefusalCode(exc.code), evaluated_at=now, detail=str(exc))

    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    try:
        lookup = await source.get_key_async(parsed.kid)
    except JwksUnavailableError as exc:
        return _unavailable(evaluated_at=now, detail=str(exc))

    if lookup.status != "found" or lookup.key is None:
        return _deny(
            lookup.refusal_code or RefusalCode.UNKNOWN_KID,
            evaluated_at=now,
            detail=f"JWKS lookup failed for kid={parsed.kid}: {lookup.status}",
        )

    if not verify_ed25519_strict(
        lookup.key.public_key_bytes, parsed.signature, parsed.signing_input
    ):
        return _deny(
            RefusalCode.INVALID_SIGNATURE,
            evaluated_at=now,
            detail="Permit Ed25519 signature verification failed",
        )

    permit, err = _validate_permit_structure(parsed.payload, evaluated_at=now)
    if err is not None or permit is None:
        return err or _deny(RefusalCode.INVALID_PERMIT, evaluated_at=now)

    # Steps 8 to 18 before any remote voice/SCITT JWKS fetches or WebAuthn/DPoP crypto.
    digest_str, digest_err = _resolve_expected_digest(
        action=action,
        expected_request_digest=expected_request_digest,
    )
    pre_voice_err = _evaluate_pre_voice_steps(
        permit=permit,
        policy=policy,
        expected_audience=expected_audience,
        expected_request_digest=digest_str,
        now_seconds=now,
        expected_session_id=expected_session_id,
        digest_err=digest_err,
    )
    if pre_voice_err is not None:
        return pre_voice_err

    # Steps 19 to 24: Verify embedded VoiceLivenessVerdict JWS & rules before WebAuthn/DPoP/SCITT.
    voice_required = _requires_voice(permit, policy)
    voice_verdict: VoiceLivenessVerdict | None = None
    if voice_required or permit.voice_verdict_jws is not None:
        if permit.voice_verdict_jws is None:
            return _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=now,
                detail="Permit missing required voice_verdict_jws",
                permit=permit,
            )
        v_source = as_jwks_source(voice_jwks or jwks, revoked_kids=revoked_kids)
        v_res = await verify_voice_liveness_verdict_async(
            permit.voice_verdict_jws,
            jwks=v_source,
            now_seconds=now,
        )
        if v_res.reason == RefusalCode.STATE_UNAVAILABLE:
            return _unavailable(
                evaluated_at=now,
                detail=v_res.detail or "Voice JWKS unavailable",
                permit=permit,
            )
        if not v_res.ok:
            if v_res.reason == RefusalCode.VOICE_RETENTION_VIOLATION:
                return _deny(
                    RefusalCode.VOICE_RETENTION_VIOLATION,
                    evaluated_at=now,
                    detail=v_res.detail or "Voice verdict retention violation",
                    permit=permit,
                )
            return _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=now,
                detail=v_res.detail or "Embedded voice verdict verification failed",
                permit=permit,
            )
        voice_verdict = v_res.verdict

    voice_err = _evaluate_voice_binding_steps(
        permit=permit,
        policy=policy,
        voice_verdict=voice_verdict,
        now_seconds=now,
    )
    if voice_err is not None:
        return voice_err

    # Steps 25 to 27: WebAuthn and DPoP prechecks strictly before Step 28 SCITT.
    webauthn_digest, dpop_res, wd_err = _run_webauthn_and_dpop_prechecks(
        permit=permit,
        permit_jws=permit_jws,
        policy=policy,
        voice_verdict=voice_verdict,
        webauthn_assertion=webauthn_assertion,
        dpop=dpop,
        now=now,
    )
    if wd_err is not None:
        return wd_err

    # Step 28: Verify IETF SCITT receipt strictly when policy.require_scitt_receipt is True.
    scitt_res: ScittReceiptResult | None = None
    if policy.require_scitt_receipt:
        if permit.scitt_receipt is None:
            return _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now,
                detail="Policy requires an embedded IETF SCITT receipt",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        s_source = as_jwks_source(scitt_jwks or jwks, revoked_kids=revoked_kids)
        try:
            scitt_res = await verify_scitt_receipt_async(
                permit.scitt_receipt,
                jwks=s_source,
                expected_decision="allow",
            )
        except JwksUnavailableError as exc:
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except ScittVerificationError as exc:
            return _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now,
                detail=str(exc),
                permit=permit,
                voice_verdict=voice_verdict,
            )

    verified_scitt, scitt_err = _evaluate_scitt_step(
        permit=permit,
        policy=policy,
        scitt_receipt=scitt_res,
        require_scitt_verified=True,
        now_seconds=now,
        voice_verdict=voice_verdict,
    )
    if scitt_err is not None:
        return scitt_err

    precheck = VerificationResult(
        ok=True,
        decision="allow",
        reason=None,
        permit=permit,
        voice_verdict=voice_verdict,
        scitt_receipt=verified_scitt,
        webauthn_assertion_digest=webauthn_digest,
        evaluated_at=now,
    )

    # Resample clock after async JWKS fetches before DPoP/nonce consumption.
    post_now, post_err = _finalize_post_precheck_checks(
        permit=permit,
        policy=policy,
        voice_verdict=voice_verdict,
        dpop=dpop,
        dpop_res=dpop_res,
        dpop_jti_store=dpop_jti_store,
        now_seconds=now_seconds,
    )
    if post_err is not None:
        return post_err

    if nonce_store is not None:
        try:
            maybe_outcome = nonce_store.consume_once(
                jti=permit.jti,
                now_seconds=post_now,
                expires_at=permit.exp,
                require_registered=require_registered_nonce,
                request_digest=permit.request_digest,
                aud=permit.aud,
                policy_id=permit.policy_id,
            )
            outcome: NonceConsumeResult
            if inspect.isawaitable(maybe_outcome):
                outcome = await maybe_outcome
            else:
                outcome = maybe_outcome
        except NonceStoreError as exc:
            return _unavailable(evaluated_at=post_now, detail=str(exc), permit=permit)
        except Exception as exc:
            return _unavailable(
                evaluated_at=post_now,
                detail=f"Nonce store backend error: {type(exc).__name__}",
                permit=permit,
            )
        return _apply_nonce_outcome(outcome, precheck=precheck, evaluated_at=post_now)

    return precheck.model_copy(update={"evaluated_at": post_now}) if post_now != now else precheck
