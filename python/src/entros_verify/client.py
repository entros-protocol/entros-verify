"""Synchronous and asynchronous Entros Firewall API clients.

Targets the B2B API contract:
- POST /v1/voice/analyze
- GET  /v1/voice/stream
- POST /v1/permits/issue
- POST /v1/permits/step-up (`operation: "create" | "poll" | "complete"`)
- POST /v1/permits/verify
- GET  /v1/permits/receipt/{jti}
- GET  /.well-known/jwks.json
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

import httpx

from entros_verify.canonical import hash_action_v2
from entros_verify.dpop import DpopJtiStore
from entros_verify.errors import EntrosApiError
from entros_verify.jwks import JwksCache, JwksKeySource, as_jwks_source
from entros_verify.jws import b64url_decode_nopad
from entros_verify.models import (
    AssuranceTier,
    CanonicalAction,
    DpopVerificationInput,
    JsonObject,
    OperatingProfile,
    PolicyV2,
    ScittReceiptResult,
    UniquenessStatus,
    VerificationResult,
    WebAuthnAssertionInput,
)
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2, verify_agent_permit_v2_async
from entros_verify.scitt import (
    ScittVerificationError,
    verify_scitt_receipt,
    verify_scitt_receipt_async,
)
from entros_verify.uri import is_canonical_issuer_uri
from entros_verify.voice import (
    AsyncVoiceClient,
    VoiceAnalyzeResponse,
    VoiceClient,
    VoiceCodec,
    VoiceStreamCodec,
    VoiceStreamSession,
)

StepUpMode = Literal["mcp_mrtr", "sep_1036", "oidc_ciba"]
StepUpProtocol = StepUpMode

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO_HEX64 = "0" * 64


def _validate_hex64_jti(jti: str, operation: str) -> str:
    if not isinstance(jti, str) or not _HEX64_RE.match(jti) or jti == _ZERO_HEX64:
        raise ValueError(f"{operation} requires a non-zero 64-char lowercase hex jti")
    return jti


def _serialize_action(action: CanonicalAction | Mapping[str, object]) -> dict[str, object]:
    if isinstance(action, CanonicalAction):
        return action.model_dump(exclude_none=True)
    return dict(action)


def _serialize_policy(policy: PolicyV2 | Mapping[str, object]) -> dict[str, object]:
    if isinstance(policy, PolicyV2):
        return policy.model_dump(exclude_none=True)
    return dict(policy)


@dataclass(frozen=True)
class IssuedPermitResponse:
    """200 OK response from POST /v1/permits/issue when a permit is minted."""

    status: Literal["issued"]
    permit_jws: str
    jti: str
    request_digest: str
    assurance_tier: AssuranceTier
    expires_at: int
    scitt_receipt: str


@dataclass(frozen=True)
class StepUpRequiredResponse:
    """202 Accepted response from POST /v1/permits/issue when Passkey step-up is required."""

    status: Literal["step_up_required"]
    reason: str
    required_assurance_tier: AssuranceTier
    request_digest: str
    recommended_step_up_endpoint: str


IssuePermitResult = IssuedPermitResponse | StepUpRequiredResponse


@dataclass(frozen=True)
class StepUpChallengeResponse:
    """Response from POST /v1/permits/step-up (`operation: "create"`)."""

    jti: str
    protocol: StepUpProtocol
    approval_url: str
    challenge_b64url: str
    expires_at: int
    mcp_input_required: dict[str, object] | None = None
    sep_1036: dict[str, object] | None = None
    ciba: dict[str, object] | None = None

    @property
    def mode(self) -> StepUpProtocol:
        return self.protocol

    @property
    def auth_req_id(self) -> str | None:
        if self.ciba is not None:
            val = self.ciba.get("auth_req_id")
            if isinstance(val, str):
                return val
        return None

    @property
    def request_state(self) -> str | None:
        if self.mcp_input_required is not None:
            val = self.mcp_input_required.get("requestState")
            if isinstance(val, str):
                return val
        return None


@dataclass(frozen=True)
class CompleteStepUpResponse:
    """Response from POST /v1/permits/step-up (`operation: "complete"`)."""

    jti: str
    request_digest: str
    assurance_tier: AssuranceTier
    freshness_verified_at: int
    expires_at: int
    webauthn_assertion_digest: str
    permit_jws: str
    scitt_receipt: str


@dataclass(frozen=True)
class PollStepUpResponse:
    """Response from POST /v1/permits/step-up (`operation: "poll"`)."""

    status: Literal["pending", "completed", "expired"]
    jti: str
    expires_at: int
    completed: CompleteStepUpResponse | None = None


@dataclass(frozen=True)
class OnlineVerifyResponse:
    """Response from POST /v1/permits/verify across 200 allow and 403/409 deny payloads."""

    verified: bool
    ok: bool
    decision: Literal["allow", "deny"]
    reason: str | None = None
    refusal_code: str | None = None
    message: str | None = None
    jti: str | None = None
    assurance_tier: AssuranceTier | None = None
    freshness_verified_at: int | None = None
    consumed_at: int | None = None
    scitt_receipt: str | None = None


def _auth_headers(api_key: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _parse_json_response(
    response: httpx.Response,
    operation: str,
    *,
    allowed_error_statuses: frozenset[int] = frozenset(),
) -> Mapping[str, object]:
    if response.status_code >= 400 and response.status_code not in allowed_error_statuses:
        err_code: str | None = None
        try:
            body: object = response.json()
            if isinstance(body, Mapping):
                raw_code = body.get("refusal_code") or body.get("error")
                if isinstance(raw_code, str):
                    err_code = raw_code
        except Exception:
            pass
        raise EntrosApiError(
            f"{operation} failed with HTTP {response.status_code}",
            status_code=response.status_code,
            error_code=err_code,
        )
    try:
        parsed: object = response.json()
    except Exception:
        raise EntrosApiError(
            f"{operation} response was not valid JSON",
            status_code=response.status_code,
        ) from None
    if not isinstance(parsed, Mapping):
        raise EntrosApiError(
            f"{operation} response was not a JSON object",
            status_code=response.status_code,
        )
    return parsed


def _parse_assurance_tier_strict(value: object) -> AssuranceTier | None:
    if value == "voice_liveness_webrtc":
        return "voice_liveness_webrtc"
    if value == "voice_liveness_telephony":
        return "voice_liveness_telephony"
    if value == "passkey_webauthn_uv":
        return "passkey_webauthn_uv"
    if value == "voice_plus_passkey":
        return "voice_plus_passkey"
    if value == "passive_browser_risk":
        return "passive_browser_risk"
    if value == "hardware_attested_mobile":
        return "hardware_attested_mobile"
    if value == "browser_unattested":
        return "browser_unattested"
    return None


def _parse_issue_response(data: Mapping[str, object]) -> IssuePermitResult:
    status = data.get("status")
    if status == "step_up_required":
        reason = data.get("reason")
        req_tier = _parse_assurance_tier_strict(data.get("required_assurance_tier"))
        request_digest = data.get("request_digest")
        endpoint = data.get("recommended_step_up_endpoint")
        if (
            not isinstance(reason, str)
            or req_tier is None
            or not isinstance(request_digest, str)
            or not isinstance(endpoint, str)
        ):
            raise EntrosApiError("Permit step_up_required response missing required fields")
        return StepUpRequiredResponse(
            status="step_up_required",
            reason=reason,
            required_assurance_tier=req_tier,
            request_digest=request_digest,
            recommended_step_up_endpoint=endpoint,
        )

    permit_jws = data.get("permit_jws")
    jti = data.get("jti")
    request_digest = data.get("request_digest")
    tier = _parse_assurance_tier_strict(data.get("assurance_tier"))
    expires_at = data.get("expires_at")
    scitt_receipt = data.get("scitt_receipt")
    if (
        status != "issued"
        or not isinstance(permit_jws, str)
        or not isinstance(jti, str)
        or not isinstance(request_digest, str)
        or tier is None
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(scitt_receipt, str)
    ):
        raise EntrosApiError("Permit issuance response missing required fields")
    return IssuedPermitResponse(
        status="issued",
        permit_jws=permit_jws,
        jti=jti,
        request_digest=request_digest,
        assurance_tier=tier,
        expires_at=expires_at,
        scitt_receipt=scitt_receipt,
    )


def _parse_step_up_challenge(data: Mapping[str, object]) -> StepUpChallengeResponse:
    jti = data.get("jti")
    protocol_raw = data.get("protocol")
    approval_url = data.get("approval_url")
    challenge_b64url = data.get("challenge_b64url")
    expires_at = data.get("expires_at")
    if (
        not isinstance(jti, str)
        or protocol_raw not in ("mcp_mrtr", "sep_1036", "oidc_ciba")
        or not isinstance(approval_url, str)
        or not isinstance(challenge_b64url, str)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
    ):
        raise EntrosApiError("Create step-up response missing required fields")
    protocol: StepUpProtocol = protocol_raw
    mcp_raw = data.get("mcp_input_required")
    sep_raw = data.get("sep_1036")
    ciba_raw = data.get("ciba")
    return StepUpChallengeResponse(
        jti=jti,
        protocol=protocol,
        approval_url=approval_url,
        challenge_b64url=challenge_b64url,
        expires_at=expires_at,
        mcp_input_required=dict(mcp_raw) if isinstance(mcp_raw, Mapping) else None,
        sep_1036=dict(sep_raw) if isinstance(sep_raw, Mapping) else None,
        ciba=dict(ciba_raw) if isinstance(ciba_raw, Mapping) else None,
    )


def _parse_complete_step_up(data: Mapping[str, object]) -> CompleteStepUpResponse:
    jti = data.get("jti")
    request_digest = data.get("request_digest")
    tier = _parse_assurance_tier_strict(data.get("assurance_tier"))
    freshness = data.get("freshness_verified_at")
    expires_at = data.get("expires_at")
    wa_digest = data.get("webauthn_assertion_digest")
    permit_jws = data.get("permit_jws")
    scitt_receipt = data.get("scitt_receipt")
    if (
        not isinstance(jti, str)
        or not isinstance(request_digest, str)
        or tier is None
        or not isinstance(freshness, int)
        or isinstance(freshness, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(wa_digest, str)
        or not isinstance(permit_jws, str)
        or not isinstance(scitt_receipt, str)
    ):
        raise EntrosApiError("Complete step-up response missing required fields")
    return CompleteStepUpResponse(
        jti=jti,
        request_digest=request_digest,
        assurance_tier=tier,
        freshness_verified_at=freshness,
        expires_at=expires_at,
        webauthn_assertion_digest=wa_digest,
        permit_jws=permit_jws,
        scitt_receipt=scitt_receipt,
    )


def _parse_poll_step_up(data: Mapping[str, object]) -> PollStepUpResponse:
    status = data.get("status")
    if status == "completed":
        completed = _parse_complete_step_up(data)
        return PollStepUpResponse(
            status="completed",
            jti=completed.jti,
            expires_at=completed.expires_at,
            completed=completed,
        )
    if status in ("pending", "expired"):
        jti = data.get("jti")
        expires_at = data.get("expires_at")
        if not isinstance(jti, str) or not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise EntrosApiError(f"Poll step-up '{status}' response missing jti or expires_at")
        return PollStepUpResponse(
            status="pending" if status == "pending" else "expired",
            jti=jti,
            expires_at=expires_at,
        )
    raise EntrosApiError(f"Unknown poll step-up status: {status!r}")


def _parse_online_verify(
    data: Mapping[str, object],
    *,
    status_code: int,
) -> OnlineVerifyResponse:
    verified_raw = data.get("verified")
    ok_raw = data.get("ok")
    if isinstance(verified_raw, bool) and isinstance(ok_raw, bool) and verified_raw != ok_raw:
        raise EntrosApiError(
            "Online verify response has contradictory verified and ok fields",
            status_code=status_code,
            error_code="invalid_response",
        )
    if isinstance(verified_raw, bool):
        verified = verified_raw
    elif isinstance(ok_raw, bool):
        verified = ok_raw
    else:
        raise EntrosApiError(
            "Online verify response missing boolean verified field",
            status_code=status_code,
            error_code="invalid_response",
        )

    decision_raw = data.get("decision")
    if decision_raw is not None and decision_raw not in ("allow", "deny"):
        raise EntrosApiError(
            "Online verify response has invalid decision field",
            status_code=status_code,
            error_code="invalid_response",
        )
    decision: Literal["allow", "deny"] = (
        decision_raw
        if decision_raw in ("allow", "deny")
        else ("allow" if verified else "deny")
    )
    if verified != (decision == "allow"):
        raise EntrosApiError(
            "Online verify response verified and decision fields disagree",
            status_code=status_code,
            error_code="invalid_response",
        )
    if status_code >= 400 and (verified or decision == "allow"):
        raise EntrosApiError(
            f"Online verify HTTP {status_code} response cannot report allow",
            status_code=status_code,
            error_code="invalid_response",
        )

    refusal_raw = data.get("refusal_code")
    reason_raw = data.get("reason")
    refusal_code = (
        refusal_raw
        if isinstance(refusal_raw, str)
        else (reason_raw if isinstance(reason_raw, str) else None)
    )
    msg_raw = data.get("message")
    jti_raw = data.get("jti")
    freshness_raw = data.get("freshness_verified_at")
    consumed_raw = data.get("consumed_at")
    receipt_raw = data.get("scitt_receipt")
    return OnlineVerifyResponse(
        verified=verified,
        ok=verified,
        decision=decision,
        reason=refusal_code,
        refusal_code=refusal_code,
        message=msg_raw if isinstance(msg_raw, str) else None,
        jti=jti_raw if isinstance(jti_raw, str) else None,
        assurance_tier=_parse_assurance_tier_strict(data.get("assurance_tier")),
        freshness_verified_at=freshness_raw if isinstance(freshness_raw, int) and not isinstance(freshness_raw, bool) else None,
        consumed_at=consumed_raw if isinstance(consumed_raw, int) and not isinstance(consumed_raw, bool) else None,
        scitt_receipt=receipt_raw if isinstance(receipt_raw, str) else None,
    )


def _build_issue_body(
    *,
    sub: str,
    actor: Mapping[str, object],
    aud: str,
    action: CanonicalAction | Mapping[str, object],
    policy: PolicyV2 | Mapping[str, object],
    ttl_seconds: int,
    voice_verdict_jws: str | None,
    webauthn_assertion: JsonObject | None,
    uniqueness_status: UniquenessStatus | None,
    session_id: str | None,
    authorization_details: list[JsonObject] | None,
    txn: str | None,
) -> dict[str, object]:
    # Validate action canonicalizability before sending over the wire.
    hash_action_v2(action)
    evidence: dict[str, object] = {}
    if voice_verdict_jws is not None:
        evidence["voice_verdict_jws"] = voice_verdict_jws
    if webauthn_assertion is not None:
        evidence["webauthn_assertion"] = dict(webauthn_assertion)

    body: dict[str, object] = {
        "sub": sub,
        "actor": dict(actor),
        "aud": aud,
        "ttl_seconds": ttl_seconds,
        "action": _serialize_action(action),
        "policy": _serialize_policy(policy),
        "evidence": evidence,
    }
    if uniqueness_status is not None:
        body["uniqueness_status"] = uniqueness_status
    if session_id is not None:
        body["session_id"] = session_id
    if authorization_details is not None:
        body["authorization_details"] = authorization_details
    if txn is not None:
        body["txn"] = txn
    return body


def _build_create_step_up_body(
    *,
    protocol: StepUpProtocol,
    sub: str,
    actor: Mapping[str, object],
    aud: str,
    policy_id: str,
    action: CanonicalAction | Mapping[str, object] | None,
    request_digest: str | None,
    ttl_seconds: int,
    uniqueness_status: UniquenessStatus | None,
    session_id: str | None,
    voice_verdict_jws: str | None,
    summary: str | None,
    authorization_details: list[JsonObject] | None,
    txn: str | None,
) -> dict[str, object]:
    digest = request_digest if request_digest is not None else (
        hash_action_v2(action) if action is not None else None
    )
    if digest is None:
        raise ValueError("request_step_up requires either action or request_digest")
    body: dict[str, object] = {
        "operation": "create",
        "protocol": protocol,
        "sub": sub,
        "actor": dict(actor),
        "aud": aud,
        "request_digest": digest,
        "policy_id": policy_id,
        "ttl_seconds": ttl_seconds,
    }
    if uniqueness_status is not None:
        body["uniqueness_status"] = uniqueness_status
    if session_id is not None:
        body["session_id"] = session_id
    if voice_verdict_jws is not None:
        body["voice_verdict_jws"] = voice_verdict_jws
    if summary is not None:
        body["summary"] = summary
    if authorization_details is not None:
        body["authorization_details"] = authorization_details
    if txn is not None:
        body["txn"] = txn
    return body


def _build_complete_step_up_body(
    *,
    jti: str,
    webauthn_assertion: Mapping[str, object],
    public_key: Mapping[str, object] | str,
    expected_rp_id: str,
    expected_origin: str,
    stored_sign_count: int | None,
    allow_cross_origin: bool,
) -> dict[str, object]:
    _validate_hex64_jti(jti, "complete_step_up")
    body: dict[str, object] = {
        "operation": "complete",
        "jti": jti,
        "webauthn_assertion": dict(webauthn_assertion),
        "public_key": dict(public_key) if isinstance(public_key, Mapping) else public_key,
        "expected_rp_id": expected_rp_id,
        "expected_origin": expected_origin,
        "allow_cross_origin": allow_cross_origin,
    }
    if stored_sign_count is not None:
        body["stored_sign_count"] = stored_sign_count
    return body


def _build_verify_online_body(
    *,
    permit_jws: str,
    expected_aud: str,
    action: CanonicalAction | Mapping[str, object],
    policy: PolicyV2 | Mapping[str, object],
    dpop_proof_jws: str | None,
    dpop_htm: str | None,
    dpop_htu: str | None,
    webauthn: Mapping[str, object] | None,
) -> dict[str, object]:
    hash_action_v2(action)
    body: dict[str, object] = {
        "permit_jws": permit_jws,
        "expected_aud": expected_aud,
        "action": _serialize_action(action),
        "policy": _serialize_policy(policy),
    }
    if dpop_proof_jws is not None:
        body["dpop_proof_jws"] = dpop_proof_jws
    if dpop_htm is not None:
        body["dpop_htm"] = dpop_htm
    if dpop_htu is not None:
        body["dpop_htu"] = dpop_htu
    if webauthn is not None:
        body["webauthn"] = dict(webauthn)
    return body


def _extract_receipt_payload(response: httpx.Response, jti: str) -> bytes | str:
    if response.status_code >= 400:
        raise EntrosApiError(
            f"GET /v1/permits/receipt/{jti} failed with HTTP {response.status_code}",
            status_code=response.status_code,
        )
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type.lower():
        parsed = _parse_json_response(response, "GET /v1/permits/receipt")
        env_jti = parsed.get("jti")
        if isinstance(env_jti, str) and env_jti != jti:
            raise EntrosApiError("Receipt JSON envelope jti mismatch")
        receipt_str = parsed.get("scitt_receipt") or parsed.get("receipt")
        if not isinstance(receipt_str, str) or not receipt_str:
            raise EntrosApiError("Receipt JSON envelope missing scitt_receipt field")
        return receipt_str
    return response.content


def _decode_raw_receipt_bytes(raw_or_b64: bytes | str) -> bytes:
    if isinstance(raw_or_b64, bytes):
        return raw_or_b64
    try:
        return b64url_decode_nopad(raw_or_b64)
    except ValueError as exc:
        raise EntrosApiError(
            f"Invalid Base64URL SCITT receipt in JSON envelope: {exc}",
            error_code="invalid_response",
        ) from None


class EntrosClient:
    """Synchronous client for Entros Voice Liveness and AgentPermit v2 endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        jwks_ttl_seconds: float = 300.0,
        revoked_kids: set[str] | frozenset[str] | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        normalized = base_url.rstrip("/")
        if not is_canonical_issuer_uri(normalized):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = normalized
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._http_client = httpx.Client(timeout=timeout_seconds, transport=transport)
        self._owns_jwks_cache = jwks is None
        self._jwks_cache: JwksCache | None = None

        if jwks is not None:
            self._jwks: JwksKeySource = as_jwks_source(jwks, revoked_kids=revoked_kids)
        else:
            cache = JwksCache(
                f"{normalized}/.well-known/jwks.json",
                ttl_seconds=jwks_ttl_seconds,
                revoked_kids=revoked_kids,
                timeout_seconds=timeout_seconds,
                sync_transport=transport,
            )
            self._jwks_cache = cache
            self._jwks = cache

        self.voice = VoiceClient(
            normalized,
            api_key=api_key,
            jwks=self._jwks,
            timeout_seconds=timeout_seconds,
            transport=transport,
            http_client=self._http_client,
        )

    def close(self) -> None:
        """Close pooled HTTP connections."""
        try:
            self._http_client.close()
        finally:
            if self._owns_jwks_cache and self._jwks_cache is not None:
                self._jwks_cache.close()

    def __enter__(self) -> EntrosClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @property
    def jwks(self) -> JwksKeySource:
        return self._jwks

    def analyze_voice(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        return self.voice.analyze(
            audio,
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            now_seconds=now_seconds,
        )

    def issue_permit(
        self,
        *,
        sub: str,
        actor: Mapping[str, object],
        aud: str,
        action: CanonicalAction | Mapping[str, object],
        policy: PolicyV2 | Mapping[str, object],
        ttl_seconds: int = 300,
        voice_verdict_jws: str | None = None,
        webauthn_assertion: JsonObject | None = None,
        uniqueness_status: UniquenessStatus | None = None,
        session_id: str | None = None,
        authorization_details: list[JsonObject] | None = None,
        txn: str | None = None,
    ) -> IssuePermitResult:
        """Request a single-use AgentPermit v2 from POST /v1/permits/issue (200 or 202)."""
        body = _build_issue_body(
            sub=sub,
            actor=actor,
            aud=aud,
            action=action,
            policy=policy,
            ttl_seconds=ttl_seconds,
            voice_verdict_jws=voice_verdict_jws,
            webauthn_assertion=webauthn_assertion,
            uniqueness_status=uniqueness_status,
            session_id=session_id,
            authorization_details=authorization_details,
            txn=txn,
        )
        try:
            response = self._http_client.post(
                f"{self._base_url}/v1/permits/issue",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Permit issue request failed: {type(exc).__name__}") from None
        return _parse_issue_response(_parse_json_response(response, "POST /v1/permits/issue"))

    def request_step_up(
        self,
        *,
        protocol: StepUpProtocol,
        sub: str,
        actor: Mapping[str, object],
        aud: str,
        policy_id: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        request_digest: str | None = None,
        ttl_seconds: int = 300,
        uniqueness_status: UniquenessStatus | None = None,
        session_id: str | None = None,
        voice_verdict_jws: str | None = None,
        summary: str | None = None,
        authorization_details: list[JsonObject] | None = None,
        txn: str | None = None,
    ) -> StepUpChallengeResponse:
        """Create an out-of-band Passkey step-up challenge via POST /v1/permits/step-up."""
        body = _build_create_step_up_body(
            protocol=protocol,
            sub=sub,
            actor=actor,
            aud=aud,
            policy_id=policy_id,
            action=action,
            request_digest=request_digest,
            ttl_seconds=ttl_seconds,
            uniqueness_status=uniqueness_status,
            session_id=session_id,
            voice_verdict_jws=voice_verdict_jws,
            summary=summary,
            authorization_details=authorization_details,
            txn=txn,
        )
        try:
            response = self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up create request failed: {type(exc).__name__}") from None
        return _parse_step_up_challenge(
            _parse_json_response(response, "POST /v1/permits/step-up (create)")
        )

    def poll_step_up(self, jti: str) -> PollStepUpResponse:
        """Poll step-up challenge settlement status via POST /v1/permits/step-up."""
        _validate_hex64_jti(jti, "poll_step_up")
        try:
            response = self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json={"operation": "poll", "jti": jti},
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up poll request failed: {type(exc).__name__}") from None
        return _parse_poll_step_up(
            _parse_json_response(response, "POST /v1/permits/step-up (poll)")
        )

    def complete_step_up(
        self,
        *,
        jti: str,
        webauthn_assertion: Mapping[str, object],
        public_key: Mapping[str, object] | str,
        expected_rp_id: str,
        expected_origin: str,
        stored_sign_count: int | None = None,
        allow_cross_origin: bool = False,
    ) -> CompleteStepUpResponse:
        """Settle a pending step-up challenge with a WebAuthn assertion."""
        body = _build_complete_step_up_body(
            jti=jti,
            webauthn_assertion=webauthn_assertion,
            public_key=public_key,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            stored_sign_count=stored_sign_count,
            allow_cross_origin=allow_cross_origin,
        )
        try:
            response = self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up complete request failed: {type(exc).__name__}") from None
        return _parse_complete_step_up(
            _parse_json_response(response, "POST /v1/permits/step-up (complete)")
        )

    def verify_permit_online(
        self,
        *,
        permit_jws: str,
        expected_aud: str,
        action: CanonicalAction | Mapping[str, object],
        policy: PolicyV2 | Mapping[str, object],
        dpop_proof_jws: str | None = None,
        dpop_htm: str | None = None,
        dpop_htu: str | None = None,
        webauthn: Mapping[str, object] | None = None,
    ) -> OnlineVerifyResponse:
        """Verify and atomically consume a permit via POST /v1/permits/verify."""
        body = _build_verify_online_body(
            permit_jws=permit_jws,
            expected_aud=expected_aud,
            action=action,
            policy=policy,
            dpop_proof_jws=dpop_proof_jws,
            dpop_htm=dpop_htm,
            dpop_htu=dpop_htu,
            webauthn=webauthn,
        )
        try:
            response = self._http_client.post(
                f"{self._base_url}/v1/permits/verify",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Online verify request failed: {type(exc).__name__}") from None

        data = _parse_json_response(
            response,
            "POST /v1/permits/verify",
            allowed_error_statuses=frozenset({403, 409}),
        )
        return _parse_online_verify(data, status_code=response.status_code)

    def verify_permit_offline(
        self,
        permit_jws: str,
        *,
        policy: PolicyV2,
        expected_audience: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        expected_request_digest: str | None = None,
        now_seconds: int | Callable[[], int] | None = None,
        webauthn_assertion: WebAuthnAssertionInput | None = None,
        dpop: DpopVerificationInput | None = None,
        dpop_jti_store: DpopJtiStore | None = None,
        nonce_store: PermitNonceStoreV2 | None = None,
        require_registered_nonce: bool = False,
    ) -> VerificationResult:
        """Verify an AgentPermit v2 offline against the configured JWKS."""
        return verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience=expected_audience,
            jwks=self._jwks,
            action=action,
            expected_request_digest=expected_request_digest,
            now_seconds=now_seconds,
            webauthn_assertion=webauthn_assertion,
            dpop=dpop,
            dpop_jti_store=dpop_jti_store,
            nonce_store=nonce_store,
            require_registered_nonce=require_registered_nonce,
        )

    def get_receipt(
        self,
        jti: str,
        *,
        verify: bool = True,
    ) -> bytes | ScittReceiptResult:
        """Retrieve a SCITT COSE_Sign1 compliance receipt from GET /v1/permits/receipt/{jti}."""
        _validate_hex64_jti(jti, "get_receipt")
        headers = _auth_headers(self._api_key)
        headers["Accept"] = "application/scitt-receipt+cose, application/json"
        try:
            response = self._http_client.get(
                f"{self._base_url}/v1/permits/receipt/{jti}",
                headers=headers,
            )
        except Exception as exc:
            raise EntrosApiError(f"Receipt fetch failed: {type(exc).__name__}") from None

        raw_or_b64 = _extract_receipt_payload(response, jti)
        if not verify:
            return _decode_raw_receipt_bytes(raw_or_b64)

        try:
            return verify_scitt_receipt(raw_or_b64, jwks=self._jwks, expected_jti=jti)
        except ScittVerificationError as exc:
            raise EntrosApiError(f"SCITT receipt verification failed: {exc}") from exc


class AsyncEntrosClient:
    """Asynchronous client for Entros Voice Liveness and AgentPermit v2 endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        jwks_ttl_seconds: float = 300.0,
        revoked_kids: set[str] | frozenset[str] | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        normalized = base_url.rstrip("/")
        if not is_canonical_issuer_uri(normalized):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = normalized
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._http_client = httpx.AsyncClient(timeout=timeout_seconds, transport=transport)
        self._owns_jwks_cache = jwks is None
        self._jwks_cache: JwksCache | None = None

        if jwks is not None:
            self._jwks: JwksKeySource = as_jwks_source(jwks, revoked_kids=revoked_kids)
        else:
            cache = JwksCache(
                f"{normalized}/.well-known/jwks.json",
                ttl_seconds=jwks_ttl_seconds,
                revoked_kids=revoked_kids,
                timeout_seconds=timeout_seconds,
                async_transport=transport,
            )
            self._jwks_cache = cache
            self._jwks = cache

        self.voice = AsyncVoiceClient(
            normalized,
            api_key=api_key,
            jwks=self._jwks,
            timeout_seconds=timeout_seconds,
            transport=transport,
            http_client=self._http_client,
        )

    async def aclose(self) -> None:
        """Close pooled asynchronous HTTP connections."""
        try:
            await self._http_client.aclose()
        finally:
            if self._owns_jwks_cache and self._jwks_cache is not None:
                await self._jwks_cache.aclose()

    async def __aenter__(self) -> AsyncEntrosClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    @property
    def jwks(self) -> JwksKeySource:
        return self._jwks

    async def analyze_voice(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        return await self.voice.analyze(
            audio,
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            now_seconds=now_seconds,
        )

    def stream_voice(
        self,
        *,
        session_id: str,
        codec: VoiceStreamCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        adapter: Literal["webrtc", "twilio", "genesys"] = "webrtc",
        connect_timeout: float = 10.0,
        now_seconds: int | None = None,
    ) -> VoiceStreamSession:
        return self.voice.stream(
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            adapter=adapter,
            connect_timeout=connect_timeout,
            now_seconds=now_seconds,
        )

    async def issue_permit(
        self,
        *,
        sub: str,
        actor: Mapping[str, object],
        aud: str,
        action: CanonicalAction | Mapping[str, object],
        policy: PolicyV2 | Mapping[str, object],
        ttl_seconds: int = 300,
        voice_verdict_jws: str | None = None,
        webauthn_assertion: JsonObject | None = None,
        uniqueness_status: UniquenessStatus | None = None,
        session_id: str | None = None,
        authorization_details: list[JsonObject] | None = None,
        txn: str | None = None,
    ) -> IssuePermitResult:
        body = _build_issue_body(
            sub=sub,
            actor=actor,
            aud=aud,
            action=action,
            policy=policy,
            ttl_seconds=ttl_seconds,
            voice_verdict_jws=voice_verdict_jws,
            webauthn_assertion=webauthn_assertion,
            uniqueness_status=uniqueness_status,
            session_id=session_id,
            authorization_details=authorization_details,
            txn=txn,
        )
        try:
            response = await self._http_client.post(
                f"{self._base_url}/v1/permits/issue",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Permit issue request failed: {type(exc).__name__}") from None
        return _parse_issue_response(_parse_json_response(response, "POST /v1/permits/issue"))

    async def request_step_up(
        self,
        *,
        protocol: StepUpProtocol,
        sub: str,
        actor: Mapping[str, object],
        aud: str,
        policy_id: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        request_digest: str | None = None,
        ttl_seconds: int = 300,
        uniqueness_status: UniquenessStatus | None = None,
        session_id: str | None = None,
        voice_verdict_jws: str | None = None,
        summary: str | None = None,
        authorization_details: list[JsonObject] | None = None,
        txn: str | None = None,
    ) -> StepUpChallengeResponse:
        body = _build_create_step_up_body(
            protocol=protocol,
            sub=sub,
            actor=actor,
            aud=aud,
            policy_id=policy_id,
            action=action,
            request_digest=request_digest,
            ttl_seconds=ttl_seconds,
            uniqueness_status=uniqueness_status,
            session_id=session_id,
            voice_verdict_jws=voice_verdict_jws,
            summary=summary,
            authorization_details=authorization_details,
            txn=txn,
        )
        try:
            response = await self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up create request failed: {type(exc).__name__}") from None
        return _parse_step_up_challenge(
            _parse_json_response(response, "POST /v1/permits/step-up (create)")
        )

    async def poll_step_up(self, jti: str) -> PollStepUpResponse:
        _validate_hex64_jti(jti, "poll_step_up")
        try:
            response = await self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json={"operation": "poll", "jti": jti},
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up poll request failed: {type(exc).__name__}") from None
        return _parse_poll_step_up(
            _parse_json_response(response, "POST /v1/permits/step-up (poll)")
        )

    async def complete_step_up(
        self,
        *,
        jti: str,
        webauthn_assertion: Mapping[str, object],
        public_key: Mapping[str, object] | str,
        expected_rp_id: str,
        expected_origin: str,
        stored_sign_count: int | None = None,
        allow_cross_origin: bool = False,
    ) -> CompleteStepUpResponse:
        body = _build_complete_step_up_body(
            jti=jti,
            webauthn_assertion=webauthn_assertion,
            public_key=public_key,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            stored_sign_count=stored_sign_count,
            allow_cross_origin=allow_cross_origin,
        )
        try:
            response = await self._http_client.post(
                f"{self._base_url}/v1/permits/step-up",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Step-up complete request failed: {type(exc).__name__}") from None
        return _parse_complete_step_up(
            _parse_json_response(response, "POST /v1/permits/step-up (complete)")
        )

    async def verify_permit_online(
        self,
        *,
        permit_jws: str,
        expected_aud: str,
        action: CanonicalAction | Mapping[str, object],
        policy: PolicyV2 | Mapping[str, object],
        dpop_proof_jws: str | None = None,
        dpop_htm: str | None = None,
        dpop_htu: str | None = None,
        webauthn: Mapping[str, object] | None = None,
    ) -> OnlineVerifyResponse:
        body = _build_verify_online_body(
            permit_jws=permit_jws,
            expected_aud=expected_aud,
            action=action,
            policy=policy,
            dpop_proof_jws=dpop_proof_jws,
            dpop_htm=dpop_htm,
            dpop_htu=dpop_htu,
            webauthn=webauthn,
        )
        try:
            response = await self._http_client.post(
                f"{self._base_url}/v1/permits/verify",
                json=body,
                headers=_auth_headers(self._api_key),
            )
        except Exception as exc:
            raise EntrosApiError(f"Online verify request failed: {type(exc).__name__}") from None

        data = _parse_json_response(
            response,
            "POST /v1/permits/verify",
            allowed_error_statuses=frozenset({403, 409}),
        )
        return _parse_online_verify(data, status_code=response.status_code)

    async def verify_permit_offline(
        self,
        permit_jws: str,
        *,
        policy: PolicyV2,
        expected_audience: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        expected_request_digest: str | None = None,
        now_seconds: int | Callable[[], int] | None = None,
        webauthn_assertion: WebAuthnAssertionInput | None = None,
        dpop: DpopVerificationInput | None = None,
        dpop_jti_store: DpopJtiStore | None = None,
        nonce_store: PermitNonceStoreV2 | None = None,
        require_registered_nonce: bool = False,
    ) -> VerificationResult:
        return await verify_agent_permit_v2_async(
            permit_jws,
            policy=policy,
            expected_audience=expected_audience,
            jwks=self._jwks,
            action=action,
            expected_request_digest=expected_request_digest,
            now_seconds=now_seconds,
            webauthn_assertion=webauthn_assertion,
            dpop=dpop,
            dpop_jti_store=dpop_jti_store,
            nonce_store=nonce_store,
            require_registered_nonce=require_registered_nonce,
        )

    async def get_receipt(
        self,
        jti: str,
        *,
        verify: bool = True,
    ) -> bytes | ScittReceiptResult:
        _validate_hex64_jti(jti, "get_receipt")
        headers = _auth_headers(self._api_key)
        headers["Accept"] = "application/scitt-receipt+cose, application/json"
        try:
            response = await self._http_client.get(
                f"{self._base_url}/v1/permits/receipt/{jti}",
                headers=headers,
            )
        except Exception as exc:
            raise EntrosApiError(f"Receipt fetch failed: {type(exc).__name__}") from None

        raw_or_b64 = _extract_receipt_payload(response, jti)
        if not verify:
            return _decode_raw_receipt_bytes(raw_or_b64)

        try:
            return await verify_scitt_receipt_async(
                raw_or_b64,
                jwks=self._jwks,
                expected_jti=jti,
            )
        except ScittVerificationError as exc:
            raise EntrosApiError(f"SCITT receipt verification failed: {exc}") from exc
