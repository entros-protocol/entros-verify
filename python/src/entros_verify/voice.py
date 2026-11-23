"""VoiceLivenessVerdict offline JWS verifier and zero-retention REST/WebSocket voice clients.

Raw audio bytes and Base64-encoded audio payloads are never emitted in errors or logs.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Literal

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

VoiceCodec = Literal["pcm16_16k", "pcm16_8k", "opus_16k", "opus_48k", "mulaw_8k", "alaw_8k"]

_CODEC_CONTENT_TYPES: dict[VoiceCodec, str] = {
    "pcm16_16k": "audio/l16;rate=16000;channels=1",
    "pcm16_8k": "audio/l16;rate=8000;channels=1",
    "opus_16k": "audio/opus;rate=16000",
    "opus_48k": "audio/opus;rate=48000",
    "mulaw_8k": "audio/pcmu;rate=8000",
    "alaw_8k": "audio/pcma;rate=8000",
}


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

    # Check calibrated_llr and abstain_reason consistency.
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

    if verdict.retention != "memory_only":
        return VoiceVerdictVerificationResult(
            ok=False,
            reason=RefusalCode.VOICE_RETENTION_VIOLATION,
            detail="Voice verdict retention must equal 'memory_only'",
            verdict=verdict,
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


def _extract_verdict_response(
    data: object,
    *,
    jwks: JwksKeySource | Mapping[str, object] | None = None,
    now_seconds: int | None = None,
) -> VoiceAnalyzeResponse:
    if not isinstance(data, Mapping):
        raise EntrosApiError("Voice API response was not a JSON object")
    verdict_jws = data.get("verdict_jws") or data.get("token")
    if not isinstance(verdict_jws, str) or not verdict_jws:
        raise EntrosApiError("Voice API response missing verdict_jws")

    request_id_raw = data.get("request_id")
    request_id = request_id_raw if isinstance(request_id_raw, str) else None

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
        return VoiceAnalyzeResponse(
            verdict_jws=verdict_jws,
            verdict=verified.verdict,
            request_id=request_id,
        )

    # Parse claims if returned inline without cryptographic verification (caller opted out of JWKS).
    inline_verdict: VoiceLivenessVerdict | None = None
    raw_verdict = data.get("verdict")
    if isinstance(raw_verdict, Mapping):
        try:
            inline_verdict = VoiceLivenessVerdict.model_validate(raw_verdict)
        except ValidationError:
            inline_verdict = None

    return VoiceAnalyzeResponse(
        verdict_jws=verdict_jws,
        verdict=inline_verdict,
        request_id=request_id,
    )


def _build_ws_stream_url(base_url: str) -> str:
    trimmed = base_url.rstrip("/")
    if trimmed.startswith("https://"):
        return "wss://" + trimmed[len("https://") :] + "/v1/voice/stream"
    if trimmed.startswith("http://127.0.0.1"):
        return "ws://" + trimmed[len("http://") :] + "/v1/voice/stream"
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
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self._ws_url = ws_url
        self._session_id = session_id
        self._codec = codec
        self._operating_profile = operating_profile
        self._api_key = api_key
        self._jwks = jwks
        self._connect_timeout = connect_timeout
        self._ws: websockets.ClientConnection | None = None

    async def __aenter__(self) -> VoiceStreamSession:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def connect(self) -> None:
        headers: dict[str, str] = {"X-Entros-Session-Id": self._session_id}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        try:
            self._ws = await websockets.connect(
                self._ws_url,
                additional_headers=headers,
                open_timeout=self._connect_timeout,
            )
            config_frame = json.dumps(
                {
                    "type": "config",
                    "session_id": self._session_id,
                    "codec": self._codec,
                    "operating_profile": self._operating_profile,
                },
                separators=(",", ":"),
            )
            await self._ws.send(config_frame)
        except Exception as exc:
            self._ws = None
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
            # Never include raw audio payload bytes in exception messages.
            raise EntrosApiError(
                f"Voice stream audio send failed (chunk_bytes={len(raw_audio_chunk)}): {type(exc).__name__}"
            ) from None

    async def finish_utterance(self) -> None:
        """Signal end-of-utterance flush on the voice stream."""
        if self._ws is None:
            raise EntrosApiError("Voice stream is not connected")
        try:
            await self._ws.send(json.dumps({"type": "flush", "session_id": self._session_id}))
        except Exception as exc:
            raise EntrosApiError(f"Voice stream flush failed: {type(exc).__name__}") from None

    async def receive_verdicts(self) -> AsyncIterator[VoiceAnalyzeResponse]:
        """Yield rolling signed VoiceLivenessVerdict frames from the stream."""
        if self._ws is None:
            raise EntrosApiError("Voice stream is not connected")
        try:
            async for raw_message in self._ws:
                if isinstance(raw_message, bytes):
                    raw_text = raw_message.decode("utf-8")
                else:
                    raw_text = raw_message
                parsed: object = json.loads(raw_text)
                if isinstance(parsed, Mapping) and parsed.get("type") == "error":
                    code = parsed.get("error_code")
                    raise EntrosApiError(
                        "Voice stream server returned an error frame",
                        error_code=code if isinstance(code, str) else None,
                    )
                if isinstance(parsed, Mapping) and (
                    "verdict_jws" in parsed or "token" in parsed
                ):
                    yield _extract_verdict_response(parsed, jwks=self._jwks)
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
    """Synchronous REST client for POST /v1/voice/analyze."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not is_canonical_issuer_uri(base_url.rstrip("/")):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._jwks = jwks
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def analyze(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        """Analyze a single raw audio clip via POST /v1/voice/analyze."""
        if not isinstance(audio, (bytes, bytearray)) or len(audio) == 0:
            raise ValueError("audio must be non-empty raw bytes")
        headers = {
            "Content-Type": _CODEC_CONTENT_TYPES[codec],
            "X-Entros-Session-Id": session_id,
            "X-Entros-Operating-Profile": operating_profile,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            with httpx.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.post(
                    f"{self._base_url}/v1/voice/analyze",
                    content=bytes(audio),
                    headers=headers,
                )
        except Exception as exc:
            # Never emit raw audio bytes or base64 audio in errors.
            raise EntrosApiError(
                f"Voice analyze request failed (audio_bytes={len(audio)}): {type(exc).__name__}"
            ) from None

        if response.status_code >= 400:
            error_code: str | None = None
            try:
                err_body: object = response.json()
                if isinstance(err_body, Mapping) and isinstance(err_body.get("error"), str):
                    error_code = str(err_body["error"])
            except Exception:
                pass
            raise EntrosApiError(
                f"Voice analyze failed with HTTP {response.status_code} (audio_bytes={len(audio)})",
                status_code=response.status_code,
                error_code=error_code,
            )

        try:
            data: object = response.json()
        except Exception:
            raise EntrosApiError(
                "Voice analyze response was not valid JSON",
                status_code=response.status_code,
            ) from None

        return _extract_verdict_response(data, jwks=self._jwks, now_seconds=now_seconds)


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
    ) -> None:
        if not is_canonical_issuer_uri(base_url.rstrip("/")):
            raise ValueError("base_url must be a canonical HTTPS or 127.0.0.1 URI")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._jwks = jwks
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def analyze(
        self,
        audio: bytes,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
        now_seconds: int | None = None,
    ) -> VoiceAnalyzeResponse:
        """Asynchronously analyze a single raw audio clip via POST /v1/voice/analyze."""
        if not isinstance(audio, (bytes, bytearray)) or len(audio) == 0:
            raise ValueError("audio must be non-empty raw bytes")
        headers = {
            "Content-Type": _CODEC_CONTENT_TYPES[codec],
            "X-Entros-Session-Id": session_id,
            "X-Entros-Operating-Profile": operating_profile,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"{self._base_url}/v1/voice/analyze",
                    content=bytes(audio),
                    headers=headers,
                )
        except Exception as exc:
            raise EntrosApiError(
                f"Voice analyze request failed (audio_bytes={len(audio)}): {type(exc).__name__}"
            ) from None

        if response.status_code >= 400:
            error_code: str | None = None
            try:
                err_body: object = response.json()
                if isinstance(err_body, Mapping) and isinstance(err_body.get("error"), str):
                    error_code = str(err_body["error"])
            except Exception:
                pass
            raise EntrosApiError(
                f"Voice analyze failed with HTTP {response.status_code} (audio_bytes={len(audio)})",
                status_code=response.status_code,
                error_code=error_code,
            )

        try:
            data: object = response.json()
        except Exception:
            raise EntrosApiError(
                "Voice analyze response was not valid JSON",
                status_code=response.status_code,
            ) from None

        return _extract_verdict_response(data, jwks=self._jwks, now_seconds=now_seconds)

    def stream(
        self,
        *,
        session_id: str,
        codec: VoiceCodec = "pcm16_16k",
        operating_profile: OperatingProfile = "webrtc_16k",
        connect_timeout: float = 10.0,
    ) -> VoiceStreamSession:
        """Create an async WebSocket streaming session for GET /v1/voice/stream."""
        return VoiceStreamSession(
            ws_url=_build_ws_stream_url(self._base_url),
            session_id=session_id,
            codec=codec,
            operating_profile=operating_profile,
            api_key=self._api_key,
            jwks=self._jwks,
            connect_timeout=connect_timeout,
        )
