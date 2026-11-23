"""Strict Pydantic v2 data models for Entros AgentPermit v2, VoiceLivenessVerdict, Policy v2, and SCITT."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic import JsonValue as JsonValue

JsonObject: TypeAlias = dict[str, JsonValue]

MIN_TIMESTAMP_SECONDS = 946_684_800
MAX_TIMESTAMP_SECONDS = 253_402_300_799
MIN_PERMIT_LIFETIME_SECONDS = 30
MAX_PERMIT_LIFETIME_SECONDS = 900
MIN_VOICE_VERDICT_LIFETIME_SECONDS = 30
MAX_VOICE_VERDICT_LIFETIME_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30

VoiceVerdictValue: TypeAlias = Literal[
    "likely_human",
    "suspicious",
    "likely_synthetic",
    "insufficient_signal",
]

OperatingProfile: TypeAlias = Literal[
    "webrtc_16k",
    "telephony_8k",
    "wideband_clean",
]

AbstainReason: TypeAlias = Literal[
    "silence",
    "short_speech",
    "low_snr",
    "clipping",
    "unsupported_codec",
    "packet_loss",
    "ensemble_disagreement",
    "inference_unavailable",
]

AssuranceTier: TypeAlias = Literal[
    "voice_liveness_webrtc",
    "voice_liveness_telephony",
    "passkey_webauthn_uv",
    "voice_plus_passkey",
    "passive_browser_risk",
    "hardware_attested_mobile",
    "browser_unattested",
]

ContinuityMode: TypeAlias = Literal[
    "call_session",
    "step_up_only",
    "stateless",
]

UniquenessStatus: TypeAlias = Literal[
    "unmeasured",
    "session_bound",
    "enterprise_idp_subject",
]

UniquenessRequirement: TypeAlias = Literal[
    "allow_unmeasured",
    "require_session_bound",
    "require_enterprise_idp_subject",
]

ConsistencyDriftStatus: TypeAlias = Literal[
    "evaluated",
    "elevated",
    "not_applicable",
]

ActionKind: TypeAlias = Literal[
    "mcp.tool_call",
    "voice.tool_call",
    "http.action",
]

Decision: TypeAlias = Literal["allow", "deny", "unavailable"]


class RefusalCode(StrEnum):
    """Canonical refusal codes in exact precheck order."""

    INVALID_JWS = "invalid_jws"
    UNSUPPORTED_ALG = "unsupported_alg"
    INVALID_TYP = "invalid_typ"
    UNKNOWN_KID = "unknown_kid"
    REVOKED_KID = "revoked_kid"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_PERMIT = "invalid_permit"
    LIFETIME_EXCEEDED = "lifetime_exceeded"
    CLOCK_SKEW_EXCEEDED = "clock_skew_exceeded"
    PERMIT_EXPIRED = "permit_expired"
    AUDIENCE_MISMATCH = "audience_mismatch"
    REQUEST_DIGEST_MISMATCH = "request_digest_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    ASSURANCE_DOWNGRADE = "assurance_downgrade"
    MODALITY_MISSING = "modality_missing"
    FRESHNESS_REGRESSION = "freshness_regression"
    EVIDENCE_STALE = "evidence_stale"
    CONTINUITY_BROKEN = "continuity_broken"
    VOICE_VERDICT_INVALID = "voice_verdict_invalid"
    VOICE_RETENTION_VIOLATION = "voice_retention_violation"
    VOICE_PROFILE_DISALLOWED = "voice_profile_disallowed"
    VOICE_VERDICT_NOT_ALLOWED = "voice_verdict_not_allowed"
    PARTIAL_SPOOF_DETECTED = "partial_spoof_detected"
    CONSISTENCY_DRIFT_EXCEEDED = "consistency_drift_exceeded"
    WEBAUTHN_ASSERTION_INVALID = "webauthn_assertion_invalid"
    WEBAUTHN_UV_REQUIRED = "webauthn_uv_required"
    DPOP_PROOF_INVALID = "dpop_proof_invalid"
    SCITT_RECEIPT_INVALID = "scitt_receipt_invalid"
    NONCE_NOT_FOUND = "nonce_not_found"
    NONCE_REPLAYED = "nonce_replayed"
    STATE_UNAVAILABLE = "state_unavailable"


class StrictModel(BaseModel):
    """Base strict model disallowing type coercion, extra keys, and non-finite floats."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        allow_inf_nan=False,
    )


class SignalQuality(StrictModel):
    """Acoustic quality telemetry for a scored audio window."""

    snr_db: float
    speech_ms: int = Field(ge=0)
    clipping: float = Field(ge=0.0, le=1.0)
    codec_bandwidth_hz: int = Field(gt=0)


class PartialSpoofSpan(StrictModel):
    """160 ms-aligned partial-splice span flagged by the voice liveness engine."""

    start_ms: int = Field(ge=0)
    end_ms: int = Field(gt=0)
    spoof_probability: float = Field(ge=0.0, le=1.0)

    @field_validator("start_ms")
    @classmethod
    def _validate_start_alignment(cls, value: int) -> int:
        if value % 160 != 0:
            raise ValueError("start_ms must be aligned to 160 ms")
        return value

    def model_post_init(self, __context: object) -> None:
        if self.end_ms <= self.start_ms:
            raise ValueError("end_ms must be greater than start_ms")
        if (self.end_ms - self.start_ms) % 160 != 0:
            raise ValueError("span duration must be a multiple of 160 ms")


class ConsistencyDrift(StrictModel):
    """Rolling spectral-consistency monitor output."""

    status: ConsistencyDriftStatus
    windows_evaluated: int = Field(ge=0)
    floor_spread_db: float | None = None
    tail_decay_spread_db: float | None = None
    spectral_tilt_drift: float | None = None
    reason: str | None = None


class VoiceLivenessVerdict(StrictModel):
    """Signed voice liveness verdict claims (entros-voice-liveness+jwt)."""

    iss: str
    jti: str
    iat: int
    exp: int
    session_id: str
    verdict: VoiceVerdictValue
    calibrated_llr: float | None
    operating_profile: OperatingProfile
    model_version: str
    signal_quality: SignalQuality
    partial_spoof_spans: list[PartialSpoofSpan]
    consistency_drift: ConsistencyDrift
    abstain_reason: AbstainReason | None
    retention: str


class Actor(StrictModel):
    """AI agent workload identity carried inside an AgentPermit v2."""

    id: str = Field(min_length=1, max_length=256)
    client_id: str | None = None
    key_jkt: str | None = None
    act: Actor | None = None


class Continuity(StrictModel):
    """Session continuity metadata for an AgentPermit v2."""

    session_id: str = Field(min_length=1, max_length=128)
    mode: ContinuityMode
    call_continuity_verified: bool | None = None
    step_up_triggered: bool | None = None
    prior_permit_jti: str | None = None


class ConfirmationClaim(StrictModel):
    """RFC 9449 DPoP sender-constrain confirmation claim."""

    jkt: str = Field(min_length=1, max_length=128)


class AgentPermitV2(StrictModel):
    """Signed AgentPermit v2 claims (entros-agent-permit+jwt)."""

    iss: str
    sub: str
    actor: Actor
    aud: str
    jti: str
    iat: int
    exp: int
    request_digest: str
    assurance_tier: AssuranceTier
    modality: list[str]
    freshness_verified_at: int
    continuity: Continuity
    uniqueness_status: UniquenessStatus
    voice_verdict_jws: str | None
    webauthn_assertion_digest: str | None
    policy_id: str
    scitt_receipt: str | None
    cnf: ConfirmationClaim | None = None
    authorization_details: list[JsonObject] | None = None
    txn: str | None = None


class CanonicalAction(StrictModel):
    """Action object committed by request_digest."""

    kind: ActionKind
    server: str
    tool: str
    arguments: JsonObject
    rar_details: list[JsonObject] | None = None


def _default_allowed_profiles() -> list[OperatingProfile]:
    return ["webrtc_16k", "telephony_8k"]


def _default_allowed_verdicts() -> list[VoiceVerdictValue]:
    return ["likely_human"]


class VoiceRules(StrictModel):
    """Voice liveness verification constraints under Policy v2."""

    allowed_profiles: list[OperatingProfile] = Field(default_factory=_default_allowed_profiles)
    allowed_verdicts: list[VoiceVerdictValue] = Field(default_factory=_default_allowed_verdicts)
    min_calibrated_llr: float = 2.0
    min_speech_ms: int = Field(default=1500, ge=0)
    min_snr_db: float = 8.0
    max_voice_age_seconds: int = Field(default=60, ge=1)
    max_partial_spoof_spans: int = Field(default=0, ge=0)
    max_partial_spoof_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    reject_on_abstain: bool = True
    reject_on_consistency_drift: bool = True
    allowed_model_versions: list[str] = Field(default_factory=list)


class PolicyV2(StrictModel):
    """Decomposed Policy v2 verification contract."""

    policy_id: str = Field(min_length=1, max_length=128)
    version: Literal[2] = 2
    allowed_assurance_tiers: list[AssuranceTier]
    required_modalities: list[str] = Field(default_factory=list)
    max_evidence_age_seconds: int = Field(ge=1)
    max_permit_lifetime_seconds: int = Field(default=900, ge=30, le=900)
    require_continuity: bool = False
    require_dpop: bool = False
    require_scitt_receipt: bool = False
    uniqueness_requirement: UniquenessRequirement = "allow_unmeasured"
    voice_rules: VoiceRules | None = None


class ScittDecisionPayload(StrictModel):
    """Metadata-only canonical decision payload inside a SCITT COSE_Sign1 receipt."""

    schema_name: Literal["entros-scitt-permit-v2"] = Field(alias="schema")
    jti: str
    request_digest: str
    policy_id: str
    aud: str
    decision: Literal["allow", "deny"]
    reason: str
    assurance_tier: AssuranceTier
    modality: list[str]
    freshness_verified_at: int
    evaluated_at: int
    model_version: str | None
    retention: Literal["memory_only"]

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        allow_inf_nan=False,
        populate_by_name=True,
    )


class ScittReceiptResult(StrictModel):
    """Verified IETF SCITT COSE_Sign1 receipt details."""

    kid: str
    vds: int
    tree_size: int
    leaf_index: int
    merkle_root_hex: str
    payload: ScittDecisionPayload


class WebAuthnAssertionInput(StrictModel):
    """Raw WebAuthn navigator.credentials.get() assertion fields for zero-CBOR verification."""

    authenticator_data: bytes | str
    client_data_json: bytes | str
    signature: bytes | str
    credential_id: bytes | str
    public_key: bytes | str | JsonObject
    expected_rp_id: str
    expected_origin: str
    stored_sign_count: int | None = Field(default=None, ge=0)
    allow_cross_origin: bool = False


class WebAuthnVerificationResult(StrictModel):
    """Output of zero-CBOR WebAuthn P-256 verification."""

    ok: bool
    reason: RefusalCode | None = None
    sign_count: int | None = None
    assertion_digest: str | None = None
    rp_id_hash_hex: str | None = None


class DpopVerificationInput(StrictModel):
    """Inputs for RFC 9449 DPoP proof verification."""

    proof_jwt: str
    htm: str
    htu: str
    max_age_seconds: int = Field(default=60, ge=1)


class VerificationResult(StrictModel):
    """Decision record returned by offline or online AgentPermit v2 verification."""

    ok: bool
    decision: Decision
    reason: RefusalCode | None = None
    detail: str | None = None
    permit: AgentPermitV2 | None = None
    voice_verdict: VoiceLivenessVerdict | None = None
    scitt_receipt: ScittReceiptResult | None = None
    webauthn_assertion_digest: str | None = None
    evaluated_at: int
