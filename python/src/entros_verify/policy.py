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
from collections.abc import Mapping

from pydantic import ValidationError

from entros_verify.canonical import hash_action_v2
from entros_verify.dpop import verify_dpop_proof
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
    VoiceRules,
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

    return permit, None


def _requires_voice(permit: AgentPermitV2, policy: PolicyV2) -> bool:
    return (
        permit.assurance_tier in _VOICE_TIERS
        or "voice_liveness" in policy.required_modalities
        or "voice_liveness" in permit.modality
        or permit.voice_verdict_jws is not None
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


def evaluate_policy_v2(
    *,
    permit: AgentPermitV2,
    policy: PolicyV2,
    expected_audience: str,
    expected_request_digest: str,
    now_seconds: int,
    voice_verdict: VoiceLivenessVerdict | None = None,
    webauthn_result: WebAuthnVerificationResult | None = None,
    dpop_verified: bool | None = None,
    scitt_receipt: ScittReceiptResult | None = None,
    require_scitt_verified: bool = True,
) -> VerificationResult:
    """Pure Policy v2 evaluator with zero I/O or nonce mutation (steps 8 to 28)."""
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
    if not _is_non_zero_hex64(expected_request_digest) or not hmac.compare_digest(
        permit.request_digest.encode("ascii"), expected_request_digest.encode("ascii")
    ):
        return _deny(
            RefusalCode.REQUEST_DIGEST_MISMATCH,
            evaluated_at=now_seconds,
            detail="Recomputed request_digest does not match permit",
            permit=permit,
        )

    # Step 13: Policy ID and uniqueness contract match.
    if permit.policy_id != policy.policy_id or not _check_uniqueness(permit, policy):
        return _deny(
            RefusalCode.POLICY_MISMATCH,
            evaluated_at=now_seconds,
            detail="Permit policy_id or uniqueness_status does not satisfy Policy v2",
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

    # Step 15: Required modalities subset check (policy + tier invariants).
    permit_modalities = set(permit.modality)
    required_modalities = set(policy.required_modalities)
    if permit.assurance_tier in _VOICE_TIERS:
        required_modalities.add("voice_liveness")
    if permit.assurance_tier in _WEBAUTHN_TIERS:
        required_modalities.add("webauthn_uv")
    if not required_modalities.issubset(permit_modalities):
        missing = sorted(required_modalities - permit_modalities)
        return _deny(
            RefusalCode.MODALITY_MISSING,
            evaluated_at=now_seconds,
            detail=f"Missing required modalities: {missing}",
            permit=permit,
        )

    # Step 16: Freshness monotonicity against permit iat and underlying voice verdict.
    if permit.freshness_verified_at > permit.iat:
        return _deny(
            RefusalCode.FRESHNESS_REGRESSION,
            evaluated_at=now_seconds,
            detail="freshness_verified_at exceeds permit iat",
            permit=permit,
        )
    if voice_verdict is not None and permit.freshness_verified_at > voice_verdict.iat:
        return _deny(
            RefusalCode.FRESHNESS_REGRESSION,
            evaluated_at=now_seconds,
            detail="freshness_verified_at exceeds underlying voice verdict iat",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 17: Evidence staleness bound.
    if now_seconds - permit.freshness_verified_at > policy.max_evidence_age_seconds:
        return _deny(
            RefusalCode.EVIDENCE_STALE,
            evaluated_at=now_seconds,
            detail="Underlying human-presence evidence exceeds max_evidence_age_seconds",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 18: Continuity requirement.
    voice_required = _requires_voice(permit, policy)
    if policy.require_continuity:
        if permit.continuity.call_continuity_verified is not True:
            return _deny(
                RefusalCode.CONTINUITY_BROKEN,
                evaluated_at=now_seconds,
                detail="Policy requires verified call continuity",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if voice_required and permit.continuity.mode != "call_session":
            return _deny(
                RefusalCode.CONTINUITY_BROKEN,
                evaluated_at=now_seconds,
                detail="Continuous voice screening requires continuity.mode == 'call_session'",
                permit=permit,
                voice_verdict=voice_verdict,
            )

    # Steps 19 to 24: VoiceLivenessVerdict binding checks.
    if voice_required:
        if voice_verdict is None:
            return _deny(
                RefusalCode.VOICE_VERDICT_INVALID,
                evaluated_at=now_seconds,
                detail="Verified VoiceLivenessVerdict is required",
                permit=permit,
            )

        # Step 20: Mandatory memory_only retention invariant.
        if voice_verdict.retention != "memory_only":
            return _deny(
                RefusalCode.VOICE_RETENTION_VIOLATION,
                evaluated_at=now_seconds,
                detail="VoiceLivenessVerdict retention must be 'memory_only'",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        # Session ID continuity binding.
        if voice_verdict.session_id != permit.continuity.session_id:
            return _deny(
                RefusalCode.CONTINUITY_BROKEN,
                evaluated_at=now_seconds,
                detail="Voice verdict session_id does not match permit continuity.session_id",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        rules = policy.voice_rules or VoiceRules()

        # Voice age check.
        if now_seconds - voice_verdict.iat > rules.max_voice_age_seconds:
            return _deny(
                RefusalCode.EVIDENCE_STALE,
                evaluated_at=now_seconds,
                detail="Voice verdict age exceeds policy.voice_rules.max_voice_age_seconds",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        # Step 21: Operating profile alignment with policy and assurance_tier.
        if voice_verdict.operating_profile not in rules.allowed_profiles:
            return _deny(
                RefusalCode.VOICE_PROFILE_DISALLOWED,
                evaluated_at=now_seconds,
                detail=f"operating_profile {voice_verdict.operating_profile!r} is disallowed",
                permit=permit,
                voice_verdict=voice_verdict,
            )
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
        if (
            rules.allowed_model_versions
            and voice_verdict.model_version not in rules.allowed_model_versions
        ):
            return _deny(
                RefusalCode.VOICE_PROFILE_DISALLOWED,
                evaluated_at=now_seconds,
                detail="Voice model_version is not in allowed_model_versions",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        # Step 22: Verdict, calibrated LLR, and acoustic signal quality floors.
        if (
            voice_verdict.verdict == "insufficient_signal" and rules.reject_on_abstain
        ) or voice_verdict.verdict not in rules.allowed_verdicts:
            return _deny(
                RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
                evaluated_at=now_seconds,
                detail=f"Voice verdict {voice_verdict.verdict!r} is not permitted by policy",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if (
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
            voice_verdict.signal_quality.speech_ms < rules.min_speech_ms
            or voice_verdict.signal_quality.snr_db < rules.min_snr_db
        ):
            return _deny(
                RefusalCode.VOICE_VERDICT_NOT_ALLOWED,
                evaluated_at=now_seconds,
                detail="Voice signal quality is below policy floor",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        # Step 23: Partial-spoof span gate.
        if len(voice_verdict.partial_spoof_spans) > rules.max_partial_spoof_spans:
            return _deny(
                RefusalCode.PARTIAL_SPOOF_DETECTED,
                evaluated_at=now_seconds,
                detail="Partial spoof spans exceed policy.voice_rules.max_partial_spoof_spans",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if rules.max_partial_spoof_probability is not None and any(
            span.spoof_probability > rules.max_partial_spoof_probability
            for span in voice_verdict.partial_spoof_spans
        ):
            return _deny(
                RefusalCode.PARTIAL_SPOOF_DETECTED,
                evaluated_at=now_seconds,
                detail="Partial spoof span probability exceeds policy ceiling",
                permit=permit,
                voice_verdict=voice_verdict,
            )

        # Step 24: Rolling consistency drift monitor gate.
        if (
            rules.reject_on_consistency_drift
            and voice_verdict.consistency_drift.status == "elevated"
        ):
            return _deny(
                RefusalCode.CONSISTENCY_DRIFT_EXCEEDED,
                evaluated_at=now_seconds,
                detail="Voice consistency_drift status is elevated",
                permit=permit,
                voice_verdict=voice_verdict,
            )

    # Steps 25 and 26: Hardware Passkey (WebAuthn UV) checks.
    webauthn_digest: str | None = permit.webauthn_assertion_digest
    if _requires_webauthn(permit, policy):
        if permit.webauthn_assertion_digest is None:
            return _deny(
                RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                evaluated_at=now_seconds,
                detail="Permit missing required webauthn_assertion_digest",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if webauthn_result is not None and not webauthn_result.ok:
            return _deny(
                webauthn_result.reason or RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                evaluated_at=now_seconds,
                detail="WebAuthn assertion verification failed",
                permit=permit,
                voice_verdict=voice_verdict,
            )
        if webauthn_result is not None and webauthn_result.assertion_digest is not None:
            webauthn_digest = webauthn_result.assertion_digest
    elif webauthn_result is not None and not webauthn_result.ok:
        return _deny(
            webauthn_result.reason or RefusalCode.WEBAUTHN_ASSERTION_INVALID,
            evaluated_at=now_seconds,
            detail="Provided WebAuthn assertion failed verification",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Step 27: RFC 9449 DPoP sender-constrain check.
    if (
        permit.cnf is not None
        and permit.actor.key_jkt is not None
        and not hmac.compare_digest(
            permit.cnf.jkt.encode("ascii"), permit.actor.key_jkt.encode("ascii")
        )
    ):
        return _deny(
            RefusalCode.DPOP_PROOF_INVALID,
            evaluated_at=now_seconds,
            detail="permit cnf.jkt does not match actor.key_jkt",
            permit=permit,
            voice_verdict=voice_verdict,
        )
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

    # Step 28: IETF SCITT receipt verification and binding.
    if policy.require_scitt_receipt and (
        permit.scitt_receipt is None or (require_scitt_verified and scitt_receipt is None)
    ):
        return _deny(
            RefusalCode.SCITT_RECEIPT_INVALID,
            evaluated_at=now_seconds,
            detail="Policy requires a verified SCITT COSE_Sign1 receipt",
            permit=permit,
            voice_verdict=voice_verdict,
        )
    if scitt_receipt is not None:
        sp = scitt_receipt.payload
        if (
            sp.jti != permit.jti
            or sp.request_digest != permit.request_digest
            or sp.policy_id != permit.policy_id
            or sp.aud != permit.aud
            or sp.retention != "memory_only"
        ):
            return _deny(
                RefusalCode.SCITT_RECEIPT_INVALID,
                evaluated_at=now_seconds,
                detail="SCITT receipt payload does not match permit bindings",
                permit=permit,
                voice_verdict=voice_verdict,
            )

    return VerificationResult(
        ok=True,
        decision="allow",
        reason=None,
        permit=permit,
        voice_verdict=voice_verdict,
        scitt_receipt=scitt_receipt,
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
        if expected_request_digest is not None and not hmac.compare_digest(
            computed.encode("ascii"), expected_request_digest.encode("ascii")
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


def _run_dpop_check(
    *,
    permit: AgentPermitV2,
    permit_jws: str,
    policy: PolicyV2,
    dpop: DpopVerificationInput | None,
    now_seconds: int,
) -> bool | None:
    if not policy.require_dpop and dpop is None:
        return None
    if permit.cnf is None:
        return False
    if (
        permit.actor.key_jkt is not None
        and not hmac.compare_digest(
            permit.cnf.jkt.encode("ascii"), permit.actor.key_jkt.encode("ascii")
        )
    ):
        return False
    if dpop is None:
        return False
    res = verify_dpop_proof(
        proof_jwt=dpop.proof_jwt,
        expected_jkt=permit.cnf.jkt,
        expected_htm=dpop.htm,
        expected_htu=dpop.htu,
        permit_jws=permit_jws,
        now_seconds=now_seconds,
        max_age_seconds=dpop.max_age_seconds,
    )
    return res.ok


def verify_agent_permit_v2(
    permit_jws: str,
    *,
    policy: PolicyV2,
    expected_audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    action: CanonicalAction | Mapping[str, object] | None = None,
    expected_request_digest: str | None = None,
    now_seconds: int | None = None,
    voice_jwks: JwksKeySource | Mapping[str, object] | None = None,
    scitt_jwks: JwksKeySource | Mapping[str, object] | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
    webauthn_assertion: WebAuthnAssertionInput | None = None,
    dpop: DpopVerificationInput | None = None,
    nonce_store: PermitNonceStoreV2 | None = None,
    require_registered_nonce: bool = False,
) -> VerificationResult:
    """Synchronously verify an AgentPermit v2 compact JWS in strict 31-step order."""
    now = int(time.time()) if now_seconds is None else now_seconds

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

    # Resolve expected request_digest from live action (for step 12).
    digest_str, digest_err = _resolve_expected_digest(
        action=action,
        expected_request_digest=expected_request_digest,
    )
    if digest_str is None:
        # Still check steps 8..11 before reporting digest mismatch so order stays exact.
        pre_digest_check = evaluate_policy_v2(
            permit=permit,
            policy=policy,
            expected_audience=expected_audience,
            expected_request_digest=permit.request_digest,
            now_seconds=now,
            voice_verdict=None,
        )
        if pre_digest_check.reason in (
            RefusalCode.LIFETIME_EXCEEDED,
            RefusalCode.CLOCK_SKEW_EXCEEDED,
            RefusalCode.PERMIT_EXPIRED,
            RefusalCode.AUDIENCE_MISMATCH,
        ):
            return pre_digest_check
        return _deny(
            RefusalCode.REQUEST_DIGEST_MISMATCH,
            evaluated_at=now,
            detail=digest_err or "Missing expected action or request_digest",
            permit=permit,
        )

    # Verify embedded VoiceLivenessVerdict JWS when voice applies (for steps 16, 19..24).
    voice_verdict: VoiceLivenessVerdict | None = None
    if _requires_voice(permit, policy) and permit.voice_verdict_jws is not None:
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
        if v_res.verdict is not None and (
            v_res.ok or v_res.reason == RefusalCode.VOICE_RETENTION_VIOLATION
        ):
            voice_verdict = v_res.verdict

    # Verify raw WebAuthn assertion if supplied (for steps 25..26).
    webauthn_res: WebAuthnVerificationResult | None = None
    if webauthn_assertion is not None:
        webauthn_res = verify_webauthn_assertion(
            webauthn_assertion,
            jti=permit.jti,
            request_digest=permit.request_digest,
            expected_assertion_digest=permit.webauthn_assertion_digest,
        )

    # Verify RFC 9449 DPoP proof if required or supplied (for step 27).
    dpop_ok = _run_dpop_check(
        permit=permit,
        permit_jws=permit_jws,
        policy=policy,
        dpop=dpop,
        now_seconds=now,
    )

    # Verify IETF SCITT receipt if required or present (for step 28).
    scitt_res: ScittReceiptResult | None = None
    scitt_failed = False
    if permit.scitt_receipt is not None:
        s_source = as_jwks_source(scitt_jwks or jwks, revoked_kids=revoked_kids)
        try:
            scitt_res = verify_scitt_receipt(permit.scitt_receipt, jwks=s_source)
        except JwksUnavailableError as exc:
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except ScittVerificationError:
            scitt_failed = True

    precheck = evaluate_policy_v2(
        permit=permit,
        policy=policy,
        expected_audience=expected_audience,
        expected_request_digest=digest_str,
        now_seconds=now,
        voice_verdict=voice_verdict,
        webauthn_result=webauthn_res,
        dpop_verified=dpop_ok,
        scitt_receipt=scitt_res,
    )
    if not precheck.ok:
        return precheck
    if scitt_failed:
        return _deny(
            RefusalCode.SCITT_RECEIPT_INVALID,
            evaluated_at=now,
            detail="Embedded SCITT receipt failed COSE_Sign1 or Merkle proof verification",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    # Steps 29 to 30: Strictly post-precheck atomic jti consumption.
    if nonce_store is not None:
        try:
            outcome = nonce_store.consume_once(
                jti=permit.jti,
                now_seconds=now,
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
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except Exception as exc:
            return _unavailable(
                evaluated_at=now,
                detail=f"Nonce store backend error: {type(exc).__name__}",
                permit=permit,
            )
        return _apply_nonce_outcome(outcome, precheck=precheck, evaluated_at=now)

    return precheck


async def verify_agent_permit_v2_async(
    permit_jws: str,
    *,
    policy: PolicyV2,
    expected_audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    action: CanonicalAction | Mapping[str, object] | None = None,
    expected_request_digest: str | None = None,
    now_seconds: int | None = None,
    voice_jwks: JwksKeySource | Mapping[str, object] | None = None,
    scitt_jwks: JwksKeySource | Mapping[str, object] | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
    webauthn_assertion: WebAuthnAssertionInput | None = None,
    dpop: DpopVerificationInput | None = None,
    nonce_store: PermitNonceStoreV2 | None = None,
    require_registered_nonce: bool = False,
) -> VerificationResult:
    """Asynchronously verify an AgentPermit v2 compact JWS in strict 31-step order."""
    now = int(time.time()) if now_seconds is None else now_seconds

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

    digest_str, digest_err = _resolve_expected_digest(
        action=action,
        expected_request_digest=expected_request_digest,
    )
    if digest_str is None:
        pre_digest_check = evaluate_policy_v2(
            permit=permit,
            policy=policy,
            expected_audience=expected_audience,
            expected_request_digest=permit.request_digest,
            now_seconds=now,
            voice_verdict=None,
        )
        if pre_digest_check.reason in (
            RefusalCode.LIFETIME_EXCEEDED,
            RefusalCode.CLOCK_SKEW_EXCEEDED,
            RefusalCode.PERMIT_EXPIRED,
            RefusalCode.AUDIENCE_MISMATCH,
        ):
            return pre_digest_check
        return _deny(
            RefusalCode.REQUEST_DIGEST_MISMATCH,
            evaluated_at=now,
            detail=digest_err or "Missing expected action or request_digest",
            permit=permit,
        )

    voice_verdict: VoiceLivenessVerdict | None = None
    if _requires_voice(permit, policy) and permit.voice_verdict_jws is not None:
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
        if v_res.verdict is not None and (
            v_res.ok or v_res.reason == RefusalCode.VOICE_RETENTION_VIOLATION
        ):
            voice_verdict = v_res.verdict

    webauthn_res: WebAuthnVerificationResult | None = None
    if webauthn_assertion is not None:
        webauthn_res = verify_webauthn_assertion(
            webauthn_assertion,
            jti=permit.jti,
            request_digest=permit.request_digest,
            expected_assertion_digest=permit.webauthn_assertion_digest,
        )

    dpop_ok = _run_dpop_check(
        permit=permit,
        permit_jws=permit_jws,
        policy=policy,
        dpop=dpop,
        now_seconds=now,
    )

    scitt_res: ScittReceiptResult | None = None
    scitt_failed = False
    if permit.scitt_receipt is not None:
        s_source = as_jwks_source(scitt_jwks or jwks, revoked_kids=revoked_kids)
        try:
            scitt_res = await verify_scitt_receipt_async(permit.scitt_receipt, jwks=s_source)
        except JwksUnavailableError as exc:
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except ScittVerificationError:
            scitt_failed = True

    precheck = evaluate_policy_v2(
        permit=permit,
        policy=policy,
        expected_audience=expected_audience,
        expected_request_digest=digest_str,
        now_seconds=now,
        voice_verdict=voice_verdict,
        webauthn_result=webauthn_res,
        dpop_verified=dpop_ok,
        scitt_receipt=scitt_res,
    )
    if not precheck.ok:
        return precheck
    if scitt_failed:
        return _deny(
            RefusalCode.SCITT_RECEIPT_INVALID,
            evaluated_at=now,
            detail="Embedded SCITT receipt failed COSE_Sign1 or Merkle proof verification",
            permit=permit,
            voice_verdict=voice_verdict,
        )

    if nonce_store is not None:
        try:
            maybe_outcome = nonce_store.consume_once(
                jti=permit.jti,
                now_seconds=now,
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
            return _unavailable(evaluated_at=now, detail=str(exc), permit=permit)
        except Exception as exc:
            return _unavailable(
                evaluated_at=now,
                detail=f"Nonce store backend error: {type(exc).__name__}",
                permit=permit,
            )
        return _apply_nonce_outcome(outcome, precheck=precheck, evaluated_at=now)

    return precheck
