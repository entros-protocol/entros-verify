"""Synchronous and asynchronous Entros Firewall API clients.

Targets the B2B API contract:
- POST /v1/voice/analyze
- GET  /v1/voice/stream
- POST /v1/permits/issue
- POST /v1/permits/step-up
- POST /v1/permits/verify
- GET  /v1/permits/receipt/{jti}
- GET  /.well-known/jwks.json
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import httpx

from entros_verify.canonical import hash_action_v2
from entros_verify.errors import EntrosApiError
from entros_verify.jwks import JwksCache, JwksKeySource
from entros_verify.models import (
    CanonicalAction,
    DpopVerificationInput,
    JsonObject,
    OperatingProfile,
    PolicyV2,
    ScittReceiptResult,
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
    VoiceStreamSession,
)

StepUpMode = Literal["mcp_mrtr", "sep_1036", "oidc_ciba"]


@dataclass(frozen=True)
class IssuedPermitResponse:
    """Response from POST /v1/permits/issue or settled POST /v1/permits/step-up."""

    permit_jws: str
    jti: str
    request_digest: str
    expires_at: int
    scitt_receipt: str | None = None


@dataclass(frozen=True)
class StepUpChallengeResponse:
    """Response from POST /v1/permits/step-up challenge creation."""

    jti: str
    request_digest: str
    mode: StepUpMode
    approval_url: str
    expires_at: int
    auth_req_id: str | None = None
    request_state: str | None = None


@dataclass(frozen=True)
class OnlineVerifyResponse:
    """Response from POST /v1/permits/verify."""

    ok: bool
    decision: str
    reason: str | None = None
    jti: str | None = None
    scitt_receipt: str | None = None


def _auth_headers(api_key: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _parse_json_response(response: httpx.Response, operation: str) -> Mapping[str, object]:
    if response.status_code >= 400:
        err_code: str | None = None
        try:
            body: object = response.json()
            if isinstance(body, Mapping) and isinstance(body.get("error"), str):
                err_code = str(body["error"])
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


def _parse_issued_permit(data: Mapping[str, object]) -> IssuedPermitResponse:
    permit_jws = data.get("permit_jws") or data.get("token")
    jti = data.get("jti")
    request_digest = data.get("request_digest")
    expires_at = data.get("expires_at") or data.get("exp")
    if (
        not isinstance(permit_jws, str)
        or not isinstance(jti, str)
        or not isinstance(request_digest, str)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
    ):
        raise EntrosApiError("Permit issuance response missing required fields")
    receipt = data.get("scitt_receipt")
    return IssuedPermitResponse(
        permit_jws=permit_jws,
        jti=jti,
        request_digest=request_digest,
        expires_at=expires_at,
        scitt_receipt=receipt if isinstance(receipt, str) else None,
    )


def _parse_step_up_challenge(data: Mapping[str, object], default_mode: StepUpMode) -> StepUpChallengeResponse:
    jti = data.get("jti")
    request_digest = data.get("request_digest")
    approval_url = data.get("approval_url")
    expires_at = data.get("expires_at") or data.get("exp")
    mode_raw = data.get("mode", default_mode)
    if (
        not isinstance(jti, str)
        or not isinstance(request_digest, str)
        or not isinstance(approval_url, str)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or mode_raw not in ("mcp_mrtr", "sep_1036", "oidc_ciba")
    ):
        raise EntrosApiError("Step-up response missing required fields")
    mode: StepUpMode = mode_raw
    auth_req_id = data.get("auth_req_id")
    request_state = data.get("request_state")
    return StepUpChallengeResponse(
        jti=jti,
        request_digest=request_digest,
        mode=mode,
        approval_url=approval_url,
        expires_at=expires_at,
        auth_req_id=auth_req_id if isinstance(auth_req_id, str) else None,
        request_state=request_state if isinstance(request_state, str) else None,
    )


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
        self._jwks: JwksKeySource | Mapping[str, object] = (
            jwks
            if jwks is not None
            else JwksCache(
                f"{normalized}/.well-known/jwks.json",
                ttl_seconds=jwks_ttl_seconds,
                revoked_kids=revoked_kids,
                timeout_seconds=timeout_seconds,
                sync_transport=transport,
            )
        )
        self.voice = VoiceClient(
            normalized,
            api_key=api_key,
            jwks=self._jwks,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )

    @property
    def jwks(self) -> JwksKeySource | Mapping[str, object]:
        return self._jwks

    def analyze_voice(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
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
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        subject: str,
        actor: Mapping[str, object],
        session_id: str,
        voice_verdict_jws: str | None = None,
        webauthn_assertion: JsonObject | None = None,
    ) -> IssuedPermitResponse:
        """Request a single-use AgentPermit v2 from POST /v1/permits/issue."""
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "request_digest": request_digest,
            "policy_id": policy_id,
            "aud": audience,
            "sub": subject,
            "actor": dict(actor),
            "session_id": session_id,
        }
        if voice_verdict_jws is not None:
            body["voice_verdict_jws"] = voice_verdict_jws
        if webauthn_assertion is not None:
            body["webauthn_assertion"] = webauthn_assertion

        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.post(
                    f"{self._base_url}/v1/permits/issue",
                    json=body,
                    headers=_auth_headers(self._api_key),
                )
        except Exception as exc:
            raise EntrosApiError(f"Permit issue request failed: {type(exc).__name__}") from None
        return _parse_issued_permit(_parse_json_response(response, "POST /v1/permits/issue"))

    def request_step_up(
        self,
        *,
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        mode: StepUpMode,
        session_id: str | None = None,
        subject: str | None = None,
        reason: str | None = None,
    ) -> StepUpChallengeResponse:
        """Register an out-of-band Passkey step-up challenge via POST /v1/permits/step-up."""
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "mode": mode,
            "policy_id": policy_id,
            "aud": audience,
            "request_digest": request_digest,
        }
        if session_id is not None:
            body["session_id"] = session_id
        if subject is not None:
            body["sub"] = subject
        if reason is not None:
            body["reason"] = reason

        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.post(
                    f"{self._base_url}/v1/permits/step-up",
                    json=body,
                    headers=_auth_headers(self._api_key),
                )
        except Exception as exc:
            raise EntrosApiError(f"Step-up request failed: {type(exc).__name__}") from None
        return _parse_step_up_challenge(
            _parse_json_response(response, "POST /v1/permits/step-up"),
            mode,
        )

    def verify_permit_online(
        self,
        *,
        permit_jws: str,
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        dpop_proof: str | None = None,
    ) -> OnlineVerifyResponse:
        """Verify and atomically consume a permit via POST /v1/permits/verify."""
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "permit_jws": permit_jws,
            "request_digest": request_digest,
            "policy_id": policy_id,
            "aud": audience,
        }
        headers = _auth_headers(self._api_key)
        if dpop_proof is not None:
            headers["DPoP"] = dpop_proof

        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.post(
                    f"{self._base_url}/v1/permits/verify",
                    json=body,
                    headers=headers,
                )
        except Exception as exc:
            raise EntrosApiError(f"Online verify request failed: {type(exc).__name__}") from None

        data = _parse_json_response(response, "POST /v1/permits/verify")
        decision = data.get("decision")
        ok = data.get("ok")
        if not isinstance(decision, str) or not isinstance(ok, bool):
            raise EntrosApiError("Online verify response missing decision/ok fields")
        reason = data.get("reason")
        jti = data.get("jti")
        receipt = data.get("scitt_receipt")
        return OnlineVerifyResponse(
            ok=ok,
            decision=decision,
            reason=reason if isinstance(reason, str) else None,
            jti=jti if isinstance(jti, str) else None,
            scitt_receipt=receipt if isinstance(receipt, str) else None,
        )

    def verify_permit_offline(
        self,
        permit_jws: str,
        *,
        policy: PolicyV2,
        expected_audience: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        expected_request_digest: str | None = None,
        now_seconds: int | None = None,
        webauthn_assertion: WebAuthnAssertionInput | None = None,
        dpop: DpopVerificationInput | None = None,
        nonce_store: PermitNonceStoreV2 | None = None,
        require_registered_nonce: bool = False,
    ) -> VerificationResult:
        """Verify an AgentPermit v2 offline against the cached JWKS."""
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
        headers = _auth_headers(self._api_key)
        headers["Accept"] = "application/scitt-receipt+cose, application/json"
        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.get(
                    f"{self._base_url}/v1/permits/receipt/{jti}",
                    headers=headers,
                )
        except Exception as exc:
            raise EntrosApiError(f"Receipt fetch failed: {type(exc).__name__}") from None

        if response.status_code >= 400:
            raise EntrosApiError(
                f"GET /v1/permits/receipt/{jti} failed with HTTP {response.status_code}",
                status_code=response.status_code,
            )

        content_type = response.headers.get("content-type", "")
        raw_or_b64: bytes | str
        if "application/json" in content_type:
            parsed = _parse_json_response(response, "GET /v1/permits/receipt")
            receipt_str = parsed.get("scitt_receipt") or parsed.get("receipt")
            if not isinstance(receipt_str, str) or not receipt_str:
                raise EntrosApiError("Receipt JSON envelope missing receipt field")
            raw_or_b64 = receipt_str
        else:
            raw_or_b64 = response.content

        if not verify:
            return raw_or_b64.encode("ascii") if isinstance(raw_or_b64, str) else raw_or_b64

        try:
            return verify_scitt_receipt(raw_or_b64, jwks=self._jwks)
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
        self._jwks: JwksKeySource | Mapping[str, object] = (
            jwks
            if jwks is not None
            else JwksCache(
                f"{normalized}/.well-known/jwks.json",
                ttl_seconds=jwks_ttl_seconds,
                revoked_kids=revoked_kids,
                timeout_seconds=timeout_seconds,
                async_transport=transport,
            )
        )
        self.voice = AsyncVoiceClient(
            normalized,
            api_key=api_key,
            jwks=self._jwks,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )

    @property
    def jwks(self) -> JwksKeySource | Mapping[str, object]:
        return self._jwks

    async def analyze_voice(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
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
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
        connect_timeout: float = 10.0,
    ) -> VoiceStreamSession:
        return self.voice.stream(
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            connect_timeout=connect_timeout,
        )

    async def issue_permit(
        self,
        *,
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        subject: str,
        actor: Mapping[str, object],
        session_id: str,
        voice_verdict_jws: str | None = None,
        webauthn_assertion: JsonObject | None = None,
    ) -> IssuedPermitResponse:
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "request_digest": request_digest,
            "policy_id": policy_id,
            "aud": audience,
            "sub": subject,
            "actor": dict(actor),
            "session_id": session_id,
        }
        if voice_verdict_jws is not None:
            body["voice_verdict_jws"] = voice_verdict_jws
        if webauthn_assertion is not None:
            body["webauthn_assertion"] = webauthn_assertion

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds, transport=self._transport
            ) as client:
                response = await client.post(
                    f"{self._base_url}/v1/permits/issue",
                    json=body,
                    headers=_auth_headers(self._api_key),
                )
        except Exception as exc:
            raise EntrosApiError(f"Permit issue request failed: {type(exc).__name__}") from None
        return _parse_issued_permit(_parse_json_response(response, "POST /v1/permits/issue"))

    async def request_step_up(
        self,
        *,
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        mode: StepUpMode,
        session_id: str | None = None,
        subject: str | None = None,
        reason: str | None = None,
    ) -> StepUpChallengeResponse:
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "mode": mode,
            "policy_id": policy_id,
            "aud": audience,
            "request_digest": request_digest,
        }
        if session_id is not None:
            body["session_id"] = session_id
        if subject is not None:
            body["sub"] = subject
        if reason is not None:
            body["reason"] = reason

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds, transport=self._transport
            ) as client:
                response = await client.post(
                    f"{self._base_url}/v1/permits/step-up",
                    json=body,
                    headers=_auth_headers(self._api_key),
                )
        except Exception as exc:
            raise EntrosApiError(f"Step-up request failed: {type(exc).__name__}") from None
        return _parse_step_up_challenge(
            _parse_json_response(response, "POST /v1/permits/step-up"),
            mode,
        )

    async def verify_permit_online(
        self,
        *,
        permit_jws: str,
        action: CanonicalAction | Mapping[str, object],
        policy_id: str,
        audience: str,
        dpop_proof: str | None = None,
    ) -> OnlineVerifyResponse:
        request_digest = hash_action_v2(action)
        body: dict[str, object] = {
            "permit_jws": permit_jws,
            "request_digest": request_digest,
            "policy_id": policy_id,
            "aud": audience,
        }
        headers = _auth_headers(self._api_key)
        if dpop_proof is not None:
            headers["DPoP"] = dpop_proof

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds, transport=self._transport
            ) as client:
                response = await client.post(
                    f"{self._base_url}/v1/permits/verify",
                    json=body,
                    headers=headers,
                )
        except Exception as exc:
            raise EntrosApiError(f"Online verify request failed: {type(exc).__name__}") from None

        data = _parse_json_response(response, "POST /v1/permits/verify")
        decision = data.get("decision")
        ok = data.get("ok")
        if not isinstance(decision, str) or not isinstance(ok, bool):
            raise EntrosApiError("Online verify response missing decision/ok fields")
        reason = data.get("reason")
        jti = data.get("jti")
        receipt = data.get("scitt_receipt")
        return OnlineVerifyResponse(
            ok=ok,
            decision=decision,
            reason=reason if isinstance(reason, str) else None,
            jti=jti if isinstance(jti, str) else None,
            scitt_receipt=receipt if isinstance(receipt, str) else None,
        )

    async def verify_permit_offline(
        self,
        permit_jws: str,
        *,
        policy: PolicyV2,
        expected_audience: str,
        action: CanonicalAction | Mapping[str, object] | None = None,
        expected_request_digest: str | None = None,
        now_seconds: int | None = None,
        webauthn_assertion: WebAuthnAssertionInput | None = None,
        dpop: DpopVerificationInput | None = None,
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
            nonce_store=nonce_store,
            require_registered_nonce=require_registered_nonce,
        )

    async def get_receipt(
        self,
        jti: str,
        *,
        verify: bool = True,
    ) -> bytes | ScittReceiptResult:
        headers = _auth_headers(self._api_key)
        headers["Accept"] = "application/scitt-receipt+cose, application/json"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds, transport=self._transport
            ) as client:
                response = await client.get(
                    f"{self._base_url}/v1/permits/receipt/{jti}",
                    headers=headers,
                )
        except Exception as exc:
            raise EntrosApiError(f"Receipt fetch failed: {type(exc).__name__}") from None

        if response.status_code >= 400:
            raise EntrosApiError(
                f"GET /v1/permits/receipt/{jti} failed with HTTP {response.status_code}",
                status_code=response.status_code,
            )

        content_type = response.headers.get("content-type", "")
        raw_or_b64: bytes | str
        if "application/json" in content_type:
            parsed = _parse_json_response(response, "GET /v1/permits/receipt")
            receipt_str = parsed.get("scitt_receipt") or parsed.get("receipt")
            if not isinstance(receipt_str, str) or not receipt_str:
                raise EntrosApiError("Receipt JSON envelope missing receipt field")
            raw_or_b64 = receipt_str
        else:
            raw_or_b64 = response.content

        if not verify:
            return raw_or_b64.encode("ascii") if isinstance(raw_or_b64, str) else raw_or_b64

        try:
            return await verify_scitt_receipt_async(raw_or_b64, jwks=self._jwks)
        except ScittVerificationError as exc:
            raise EntrosApiError(f"SCITT receipt verification failed: {exc}") from exc
