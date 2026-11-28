"""VoiceLivenessVerdict offline JWS verifier and zero-retention REST/WebSocket voice clients.

Raw audio bytes and Base64-encoded audio payloads are never emitted in errors or logs.
"""

from __future__ import annotations

import base64
import contextlib
import json
import math
import re
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode

import httpx
import websockets
from pydantic import ValidationError

from entros_verify.errors import EntrosApiError, JwksUnavailableError, JwsVerificationError
from entros_verify.jwks import JwksKeySource, as_jwks_source
from entros_verify.jws import parse_and_validate_jws_header, verify_ed25519_strict
from entros_verify.models import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_TIMESTAMP_SECONDS,
    MAX_VOICE_VERDICT_LIFETIME_SECONDS,
    MIN_TIMESTAMP_SECONDS,
    MIN_VOICE_VERDICT_LIFETIME_SECONDS,
    OperatingProfile,
    RefusalCode,
    VoiceLivenessVerdict,
)
from entros_verify.uri import is_canonical_issuer_uri

VOICE_VERDICT_TYP = "entros-voice-liveness+jwt"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_UUIDV7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

VoiceCodec = Literal["pcm16_16k", "pcm16_8k", "opus_16k", "opus_48k", "mulaw_8k", "alaw_8k", "wav"]
VoiceStreamCodec = Literal["pcm16_16k", "pcm16_8k", "opus_16k", "opus_48k", "mulaw_8k", "alaw_8k"]
VoiceWireEncoding = Literal["pcm16", "opus", "mulaw", "alaw", "wav"]

_CODEC_WIRE_MAP: dict[VoiceCodec, tuple[VoiceWireEncoding, int | None, OperatingProfile]] = {
    "pcm16_16k": ("pcm16", 16_000, "webrtc_16k"),
    "pcm16_8k": ("pcm16", 8_000, "telephony_8k"),
    "opus_16k": ("opus", 16_000, "webrtc_16k"),
    "opus_48k": ("opus", 48_000, "wideband_clean"),
    "mulaw_8k": ("mulaw", 8_000, "telephony_8k"),
    "alaw_8k": ("alaw", 8_000, "telephony_8k"),
    "wav": ("wav", None, "webrtc_16k"),
}


def map_voice_codec_to_wire(codec: VoiceCodec) -> tuple[VoiceWireEncoding, int | None, OperatingProfile]:
    """Map an ergonomic SDK codec string to wire `(encoding, sample_rate_hz, default_profile)`."""
    if codec not in _CODEC_WIRE_MAP:
        raise ValueError(f"Unsupported voice codec: {codec!r}")
    return _CODEC_WIRE_MAP[codec]


def _is_printable_ascii(text: str, min_len: int, max_len: int) -> bool:
    if len(text) < min_len or len(text) > max_len:
        return False
    return all(0x20 <= ord(ch) <= 0x7E for ch in text)


@dataclass(frozen=True)
class VoiceVerdictVerificationResult:
    """Outcome of offline VoiceLivenessVerdict JWS verification."""

    ok: bool
    reason: RefusalCode | None = None
    detail: str | None = None
    verdict: VoiceLivenessVerdict | None = None
    kid: str | None = None


def _validate_voice_verdict_claims(
    payload: Mapping[str, object],
    *,
    now_seconds: int,
    kid: str,
) -> VoiceVerdictVerificationResult:
    # Enforce mandatory memory_only retention invariant before expiry or schema errors.
    if payload.get("retention") != "memory_only":
        parsed_verdict: VoiceLivenessVerdict | None = None
        with contextlib.suppress(ValidationError):
            parsed_verdict = VoiceLivenessVerdict.model_validate(payload)
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_RETENTION_VIOLATION,
            detail="Voice verdict retention must equal 'memory_only'",
            verdict=parsed_verdict,
            kid=kid,
        )

    try:
        verdict = VoiceLivenessVerdict.model_validate(payload)
    except ValidationError as exc:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail=f"Invalid VoiceLivenessVerdict schema: {exc.error_count()} validation error(s)",
            kid=kid,
        )

    if not is_canonical_issuer_uri(verdict.iss):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Invalid voice verdict issuer URI",
            kid=kid,
        )

    if not (_HEX64_RE.match(verdict.jti) or _UUIDV7_RE.match(verdict.jti)):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Voice verdict jti must be 64 lowercase hex or UUIDv7",
            kid=kid,
        )

    if not _HEX64_RE.match(verdict.model_version):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Voice verdict model_version must be 64 lowercase hex SHA-256",
            kid=kid,
        )

    if not _is_printable_ascii(verdict.session_id, 1, 128):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Voice verdict session_id must be printable ASCII (1..128 chars)",
            kid=kid,
        )

    if not (MIN_TIMESTAMP_SECONDS <= verdict.iat <= MAX_TIMESTAMP_SECONDS):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Voice verdict iat out of bounds",
            kid=kid,
        )

    if not (MIN_TIMESTAMP_SECONDS <= verdict.exp <= MAX_TIMESTAMP_SECONDS):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_VERDICT_INVALID,
            detail="Voice verdict exp out of bounds",
            kid=kid,
        )

    if verdict.verdict == "insufficient_signal":
        if verdict.abstain_reason is None:
            return VoiceVerdictVerificationResult(
                ok=False,
                reason=RefusalCode.VOICE_VERDICT_INVALID,
                detail="insufficient_signal verdict must provide abstain_reason",
                kid=kid,
            )
    else:
        if verdict.calibrated_llr is None:
            return VoiceVerdictVerificationResult(
                ok=False,
                reason=RefusalCode.VOICE_VERDICT_INVALID,
                detail="calibrated_llr may only be null when verdict is insufficient_signal",
                kid=kid,
            )
        if verdict.abstain_reason is not None:
            return VoiceVerdictVerificationResult(
                ok=False,
                reason=RefusalCode.VOICE_VERDICT_INVALID,
                detail="abstain_reason must be null unless verdict is insufficient_signal",
                kid=kid,
            )

    lifetime = verdict.exp - verdict.iat
    if (
        lifetime < MIN_VOICE_VERDICT_LIFETIME_SECONDS
        or lifetime > MAX_VOICE_VERDICT_LIFETIME_SECONDS
    ):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.LIFETIME_EXCEEDED,
            detail="Voice verdict lifetime must be within 30..300 seconds",
            kid=kid,
        )

    if verdict.iat > now_seconds + MAX_CLOCK_SKEW_SECONDS:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.CLOCK_SKEW_EXCEEDED,
            detail="Voice verdict iat exceeds 30s forward clock skew",
            kid=kid,
        )

    if now_seconds >= verdict.exp:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.PERMIT_EXPIRED,
            detail="Voice verdict has expired",
            kid=kid,
        )

    return VoiceVerdictVerificationResult(ok=True, verdict=verdict, kid=kid)


def verify_voice_liveness_verdict(
    compact_jws: str,
    *,
    jwks: JwksKeySource | Mapping[str, object],
    now_seconds: int | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
) -> VoiceVerdictVerificationResult:
    """Synchronously verify a signed VoiceLivenessVerdict JWS (entros-voice-liveness+jwt)."""
    now = int(time.time()) if now_seconds is None else now_seconds
    try:
        parsed = parse_and_validate_jws_header(compact_jws, expected_typ=VOICE_VERDICT_TYP)
    except JwsVerificationError as exc:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode(exc.code),
            detail=str(exc),
        )

    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    try:
        lookup = source.get_key(parsed.kid)
    except JwksUnavailableError as exc:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.STATE_UNAVAILABLE,
            detail=str(exc),
            kid=parsed.kid,
        )

    if lookup.status != "found" or lookup.key is None:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=lookup.refusal_code or RefusalCode.UNKNOWN_KID,
            detail=f"Voice issuer kid lookup failed: {lookup.status}",
            kid=parsed.kid,
        )

    if not verify_ed25519_strict(
        lookup.key.public_key_bytes, parsed.signature, parsed.signing_input
    ):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.INVALID_SIGNATURE,
            detail="VoiceLivenessVerdict Ed25519 signature verification failed",
            kid=parsed.kid,
        )

    return _validate_voice_verdict_claims(parsed.payload, now_seconds=now, kid=parsed.kid)


async def verify_voice_liveness_verdict_async(
    compact_jws: str,
    *,
    jwks: JwksKeySource | Mapping[str, object],
    now_seconds: int | None = None,
    revoked_kids: set[str] | frozenset[str] | None = None,
) -> VoiceVerdictVerificationResult:
    """Asynchronously verify a signed VoiceLivenessVerdict JWS (entros-voice-liveness+jwt)."""
    now = int(time.time()) if now_seconds is None else now_seconds
    try:
        parsed = parse_and_validate_jws_header(compact_jws, expected_typ=VOICE_VERDICT_TYP)
    except JwsVerificationError as exc:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode(exc.code),
            detail=str(exc),
        )

    source = as_jwks_source(jwks, revoked_kids=revoked_kids)
    try:
        lookup = await source.get_key_async(parsed.kid)
    except JwksUnavailableError as exc:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.STATE_UNAVAILABLE,
            detail=str(exc),
            kid=parsed.kid,
        )

    if lookup.status != "found" or lookup.key is None:
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=lookup.refusal_code or RefusalCode.UNKNOWN_KID,
            detail=f"Voice issuer kid lookup failed: {lookup.status}",
            kid=parsed.kid,
        )

    if not verify_ed25519_strict(
        lookup.key.public_key_bytes, parsed.signature, parsed.signing_input
    ):
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.INVALID_SIGNATURE,
            detail="VoiceLivenessVerdict Ed25519 signature verification failed",
            kid=parsed.kid,
        )

    return _validate_voice_verdict_claims(parsed.payload, now_seconds=now, kid=parsed.kid)


@dataclass(frozen=True)
class VoiceAnalyzeResponse:
    """Response from POST /v1/voice/analyze or a /v1/voice/stream verdict frame."""

    verdict_jws: str
    verdict: VoiceLivenessVerdict | None = None
    request_id: str | None = None
    inference_ms: float | None = None


_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{64,}={0,2}")


def _sanitize_voice_error_detail(message: str) -> str:
    """Redact long Base64-like blobs and bound length so audio payloads never leak."""
    return _LONG_B64_RE.sub("[redacted]", message)[:240]


def _parse_verdict_envelope(
    data: object,
) -> tuple[str, str | None, float | None]:
    if not isinstance(data, Mapping):
        raise EntrosApiError("Voice API response was not a JSON object")
    verdict_jws = data.get("verdict_jws")
    if not isinstance(verdict_jws, str) or not verdict_jws:
        raise EntrosApiError("Voice API response missing verdict_jws")

    request_id_raw = data.get("request_id")
    request_id = request_id_raw if isinstance(request_id_raw, str) else None

    inf_raw = data.get("inference_ms")
    inference_ms: float | None = None
    if (
        isinstance(inf_raw, (int, float))
        and not isinstance(inf_raw, bool)
        and math.isfinite(float(inf_raw))
    ):
        inference_ms = float(inf_raw)

    return verdict_jws, request_id, inference_ms


def _extract_verdict_response(
    data: object,
    *,
    jwks: JwksKeySource | Mapping[str, object] | None = None,
    expected_session_id: str | None = None,
    now_seconds: int | None = None,
) -> VoiceAnalyzeResponse:
    verdict_jws, request_id, inference_ms = _parse_verdict_envelope(data)

    if jwks is not None:
        verified = verify_voice_liveness_verdict(
            verdict_jws,
            jwks=jwks,
            now_seconds=now_seconds,
        )
        if not verified.ok or verified.verdict is None:
            raise EntrosApiError(
                f"Voice verdict verification failed: {verified.reason}",
                error_code=verified.reason.value if verified.reason else None,
            )
        if expected_session_id is not None and verified.verdict.session_id != expected_session_id:
            raise EntrosApiError(
                "Voice verdict session_id does not match request session_id",
                error_code=RefusalCode.CONTINUITY_BROKEN.value,
            )
        return VoiceAnalyzeResponse(
            verdict_jws=verdict_jws,
            verdict=verified.verdict,
            request_id=request_id,
            inference_ms=inference_ms,
        )

    # Never expose unverified inline claims when no JWKS is configured.
    return VoiceAnalyzeResponse(
        verdict_jws=verdict_jws,
        verdict=None,
        request_id=request_id,
        inference_ms=inference_ms,
    )


async def _extract_verdict_response_async(
    data: object,
    *,
    jwks: JwksKeySource | Mapping[str, object] | None = None,
    expected_session_id: str | None = None,
    now_seconds: int | None = None,
) -> VoiceAnalyzeResponse:
    verdict_jws, request_id, inference_ms = _parse_verdict_envelope(data)

    if jwks is not None:
        verified = await verify_voice_liveness_verdict_async(
            verdict_jws,
            jwks=jwks,
            now_seconds=now_seconds,
        )
        if not verified.ok or verified.verdict is None:
            raise EntrosApiError(
                f"Voice verdict verification failed: {verified.reason}",
                error_code=verified.reason.value if verified.reason else None,
            )
        if expected_session_id is not None and verified.verdict.session_id != expected_session_id:
            raise EntrosApiError(
                "Voice verdict session_id does not match request session_id",
                error_code=RefusalCode.CONTINUITY_BROKEN.value,
            )
        return VoiceAnalyzeResponse(
            verdict_jws=verdict_jws,
            verdict=verified.verdict,
            request_id=request_id,
            inference_ms=inference_ms,
        )

    # Never expose unverified inline claims when no JWKS is configured.
    return VoiceAnalyzeResponse(
        verdict_jws=verdict_jws,
        verdict=None,
        request_id=request_id,
        inference_ms=inference_ms,
    )


def _build_analyze_request_payload(
    audio: bytes,
    *,
    session_id: str,
    codec: VoiceCodec,
    operating_profile: OperatingProfile | None,
) -> dict[str, object]:
    if not isinstance(audio, (bytes, bytearray)) or len(audio) == 0:
        raise ValueError("audio must be non-empty raw bytes")
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")
    encoding, sample_rate_hz, default_profile = map_voice_codec_to_wire(codec)
    payload: dict[str, object] = {
        "session_id": session_id,
        "audio_b64": base64.b64encode(bytes(audio)).decode("ascii"),
        "encoding": encoding,
        "operating_profile": operating_profile or default_profile,
    }
    if sample_rate_hz is not None:
        payload["sample_rate_hz"] = sample_rate_hz
    return payload


def _build_analyze_headers(api_key: str | None) -> dict[str, str]:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _parse_analyze_http_response(response: httpx.Response, audio_bytes_len: int) -> object:
    if response.status_code >= 400:
        error_code: str | None = None
        try:
            err_body: object = response.json()
            if isinstance(err_body, Mapping) and isinstance(err_body.get("error"), str):
                error_code = str(err_body["error"])
        except Exception:
            pass
        raise EntrosApiError(
            f"Voice analyze failed with HTTP {response.status_code} (audio_bytes={audio_bytes_len})",
            status_code=response.status_code,
            error_code=error_code,
        )

    try:
        return response.json()
    except Exception:
        raise EntrosApiError(
            "Voice analyze response was not valid JSON",
            status_code=response.status_code,
        ) from None


def _build_ws_stream_url(base_url: str, adapter: str = "webrtc") -> str:
    trimmed = base_url.rstrip("/")
    query = urlencode({"adapter": adapter})
    if trimmed.startswith("https://"):
        return "wss://" + trimmed[len("https://") :] + f"/v1/voice/stream?{query}"
    if trimmed.startswith("http://127.0.0.1"):
        return "ws://" + trimmed[len("http://") :] + f"/v1/voice/stream?{query}"
    raise ValueError("base_url must be https:// or http://127.0.0.1")


class VoiceStreamSession:
    """Async streaming session for GET /v1/voice/stream.

    Streams raw audio frames directly without upstream denoising and emits zero
    raw audio bytes or Base64 audio strings in errors or diagnostics.
    """

    def __init__(
        self,
        *,
        ws_url: str,
        session_id: str,
        codec: VoiceStreamCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        connect_timeout: float = 10.0,
        now_seconds: int | None = None,
    ) -> None:
        encoding, sample_rate_hz, default_profile = map_voice_codec_to_wire(codec)
        if encoding == "wav" or sample_rate_hz is None:
            raise ValueError("WebSocket voice streaming requires pcm16, opus, mulaw, or alaw codec")
        self._ws_url = ws_url
        self._session_id = session_id
        self._codec = codec
        self._wire_codec = encoding
        self._sample_rate_hz = sample_rate_hz
        self._operating_profile: OperatingProfile = operating_profile or default_profile
        self._api_key = api_key
        self._jwks = jwks
        self._connect_timeout = connect_timeout
        self._now_seconds = now_seconds
        self._ws: websockets.ClientConnection | None = None

    async def __aenter__(self) -> VoiceStreamSession:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def connect(self) -> None:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        ws: websockets.ClientConnection | None = None
        try:
            ws = await websockets.connect(
                self._ws_url,
                additional_headers=headers if headers else None,
                open_timeout=self._connect_timeout,
            )
            start_frame = json.dumps(
                {
                    "type": "start",
                    "session_id": self._session_id,
                    "codec": self._wire_codec,
                    "sample_rate_hz": self._sample_rate_hz,
                    "operating_profile": self._operating_profile,
                },
                separators=(",", ":"),
            )
            await ws.send(start_frame)
            self._ws = ws
        except Exception as exc:
            self._ws = None
            if ws is not None:
                with contextlib.suppress(Exception):
                    await ws.close()
            raise EntrosApiError(
                f"Failed to open voice stream for session {self._session_id}: {type(exc).__name__}"
            ) from None

    async def send_audio(self, raw_audio_chunk: bytes) -> None:
        """Send raw un-denoised audio bytes over the WebSocket stream."""
        if self._ws is None:
            raise EntrosApiError("Voice stream is not connected")
        if not isinstance(raw_audio_chunk, (bytes, bytearray)):
            raise TypeError("raw_audio_chunk must be bytes or bytearray")
        try:
            await self._ws.send(bytes(raw_audio_chunk))
        except Exception as exc:
            raise EntrosApiError(
                f"Voice stream audio send failed (chunk_bytes={len(raw_audio_chunk)}): {type(exc).__name__}"
            ) from None

    async def _send_control(self, control_type: Literal["flush", "pause", "resume", "stop"]) -> None:
        if self._ws is None:
            raise EntrosApiError("Voice stream is not connected")
        try:
            await self._ws.send(json.dumps({"type": control_type}, separators=(",", ":")))
        except Exception as exc:
            raise EntrosApiError(
                f"Voice stream {control_type} failed: {type(exc).__name__}"
            ) from None

    async def flush(self) -> None:
        """Signal an immediate inference flush on the voice stream."""
        await self._send_control("flush")

    async def finish_utterance(self) -> None:
        """Signal end-of-utterance flush on the voice stream."""
        await self.flush()

    async def pause(self) -> None:
        """Pause streaming audio scoring on the voice stream."""
        await self._send_control("pause")

    async def resume(self) -> None:
        """Resume streaming audio scoring on the voice stream."""
        await self._send_control("resume")

    async def stop(self) -> None:
        """Gracefully stop the voice stream and request final summary."""
        await self._send_control("stop")

    async def receive_verdicts(
        self,
        *,
        now_seconds: int | None = None,
    ) -> AsyncIterator[VoiceAnalyzeResponse]:
        """Yield rolling signed VoiceLivenessVerdict frames verified asynchronously."""
        if self._ws is None:
            raise EntrosApiError("Voice stream is not connected")
        eval_now = now_seconds if now_seconds is not None else self._now_seconds
        try:
            async for raw_message in self._ws:
                raw_text = raw_message.decode("utf-8") if isinstance(raw_message, bytes) else raw_message
                parsed: object = json.loads(raw_text)
                if not isinstance(parsed, Mapping):
                    continue
                frame_type = parsed.get("type")
                if frame_type == "error":
                    code = parsed.get("code") or parsed.get("error_code")
                    msg = parsed.get("message")
                    safe_msg = (
                        _sanitize_voice_error_detail(msg)
                        if isinstance(msg, str) and msg
                        else "Voice stream server returned an error frame"
                    )
                    safe_code = _sanitize_voice_error_detail(code) if isinstance(code, str) else None
                    raise EntrosApiError(
                        safe_msg,
                        error_code=safe_code,
                    )
                if frame_type in (None, "verdict") and isinstance(parsed.get("verdict_jws"), str):
                    yield await _extract_verdict_response_async(
                        parsed,
                        jwks=self._jwks,
                        expected_session_id=self._session_id,
                        now_seconds=eval_now,
                    )
        except EntrosApiError:
            raise
        except Exception as exc:
            raise EntrosApiError(f"Voice stream receive failed: {type(exc).__name__}") from None

    async def close(self) -> None:
        if self._ws is not None:
            ws = self._ws
            self._ws = None
            with contextlib.suppress(Exception):
                await ws.close()


class VoiceClient:
    """Synchronous REST client for POST /v1/voice/analyze with pooled HTTP connections."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not is_canonical_issuer_uri(base_url.rstrip("/")):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._jwks = jwks
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._client: httpx.Client | None = http_client
        self._owns_client = http_client is None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
            )
            self._owns_client = True
        return self._client

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> VoiceClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def analyze(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        """Analyze a single raw audio clip via POST /v1/voice/analyze."""
        body = _build_analyze_request_payload(
            audio,
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
        )
        headers = _build_analyze_headers(self._api_key)
        try:
            response = self._get_client().post(
                f"{self._base_url}/v1/voice/analyze",
                json=body,
                headers=headers,
            )
        except Exception as exc:
            raise EntrosApiError(
                f"Voice analyze request failed (audio_bytes={len(audio)}): {type(exc).__name__}"
            ) from None

        data = _parse_analyze_http_response(response, len(audio))
        return _extract_verdict_response(
            data,
            jwks=self._jwks,
            expected_session_id=session_id,
            now_seconds=now_seconds,
        )


class AsyncVoiceClient:
    """Asynchronous REST and WebSocket client for /v1/voice/analyze and /v1/voice/stream."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not is_canonical_issuer_uri(base_url.rstrip("/")):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._jwks = jwks
        self._timeout_seconds = timeout_seconds
        self._transport = transport
        self._client: httpx.AsyncClient | None = http_client
        self._owns_client = http_client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
            )
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> AsyncVoiceClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    async def analyze(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        """Asynchronously analyze a single raw audio clip via POST /v1/voice/analyze."""
        body = _build_analyze_request_payload(
            audio,
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
        )
        headers = _build_analyze_headers(self._api_key)
        try:
            response = await self._get_client().post(
                f"{self._base_url}/v1/voice/analyze",
                json=body,
                headers=headers,
            )
        except Exception as exc:
            raise EntrosApiError(
                f"Voice analyze request failed (audio_bytes={len(audio)}): {type(exc).__name__}"
            ) from None

        data = _parse_analyze_http_response(response, len(audio))
        return await _extract_verdict_response_async(
            data,
            jwks=self._jwks,
            expected_session_id=session_id,
            now_seconds=now_seconds,
        )

    def stream(
        self,
        *,
        session_id: str,
        codec: VoiceStreamCodec = "pcm16_16k",
        operating_profile: OperatingProfile | None = None,
        adapter: Literal["webrtc", "twilio", "genesys"] = "webrtc",
        connect_timeout: float = 10.0,
        now_seconds: int | None = None,
    ) -> VoiceStreamSession:
        """Create an async WebSocket streaming session for GET /v1/voice/stream."""
        return VoiceStreamSession(
            ws_url=_build_ws_stream_url(self._base_url, adapter=adapter),
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            api_key=self._api_key,
            jwks=self._jwks,
            connect_timeout=connect_timeout,
            now_seconds=now_seconds,
        )
