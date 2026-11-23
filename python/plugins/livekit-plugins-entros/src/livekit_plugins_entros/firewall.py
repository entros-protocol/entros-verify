"""LiveKit Agents raw WebRTC track subscriber and @entros_voice_gate tool guard.

Subscribes to inbound caller 16 kHz WebRTC audio tracks BEFORE any noise
cancellation or STT processing, streams raw PCM16 frames to GET /v1/voice/stream,
stores the latest signed VoiceLivenessVerdict keyed by session_id (metadata only,
zero audio persistence), and gates privileged agent tools behind AgentPermit v2
with SEP-1036 or OpenID Connect CIBA Passkey step-up on suspicious or
insufficient_signal verdicts.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from entros_verify.client import AsyncEntrosClient, StepUpChallengeResponse
from entros_verify.jwks import JwksKeySource
from entros_verify.models import (
    OperatingProfile,
    PolicyV2,
    RefusalCode,
    VerificationResult,
    VoiceLivenessVerdict,
)
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2_async
from entros_verify.voice import (
    VoiceAnalyzeResponse,
    VoiceCodec,
    verify_voice_liveness_verdict_async,
)

LiveKitStepUpMode = Literal["sep_1036", "oidc_ciba"]


@runtime_checkable
class AudioFrameProtocol(Protocol):
    """Protocol matching livekit.rtc.AudioFrame."""

    @property
    def data(self) -> memoryview | bytes | bytearray: ...

    @property
    def sample_rate(self) -> int: ...

    @property
    def num_channels(self) -> int: ...


@runtime_checkable
class AudioFrameEventProtocol(Protocol):
    """Protocol matching livekit.rtc.AudioFrameEvent yielded by AudioStream."""

    @property
    def frame(self) -> AudioFrameProtocol: ...


@runtime_checkable
class AudioStreamProtocol(Protocol):
    """Async iterable yielding raw inbound WebRTC audio frames or frame events."""

    def __aiter__(self) -> AsyncIterator[AudioFrameEventProtocol | AudioFrameProtocol]: ...


@runtime_checkable
class VoiceStreamSinkProtocol(Protocol):
    """Protocol matching entros_verify.voice.VoiceStreamSession for streaming or testing."""

    async def __aenter__(self) -> VoiceStreamSinkProtocol: ...

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None: ...

    async def send_audio(self, raw_audio_chunk: bytes) -> None: ...

    async def finish_utterance(self) -> None: ...

    def receive_verdicts(self) -> AsyncIterator[VoiceAnalyzeResponse]: ...


@dataclass(frozen=True)
class SessionVerdictRecord:
    """Latest verified signed VoiceLivenessVerdict stored in memory for a call session."""

    session_id: str
    verdict_jws: str
    verdict: VoiceLivenessVerdict
    received_at: int


class EntrosVoiceGateBlocked(Exception):
    """Raised when a gated LiveKit tool cannot execute without step-up or valid permit."""

    def __init__(
        self,
        *,
        reason: str,
        step_up: StepUpChallengeResponse | None = None,
        verification: VerificationResult | None = None,
    ) -> None:
        self.reason = reason
        self.step_up = step_up
        self.verification = verification
        super().__init__(f"Entros voice gate blocked tool execution: {reason}")


def _extract_raw_pcm(item: AudioFrameEventProtocol | AudioFrameProtocol) -> tuple[bytes, int]:
    frame: AudioFrameProtocol = item.frame if isinstance(item, AudioFrameEventProtocol) else item
    return bytes(frame.data), frame.sample_rate


class EntrosVoiceFirewall:
    """Subscribes to raw LiveKit WebRTC tracks and tracks latest signed verdicts by session_id.

    Audio bytes are forwarded directly to /v1/voice/stream without upstream denoising
    and are never persisted to disk or retained in session state.
    """

    def __init__(
        self,
        *,
        client: AsyncEntrosClient | None = None,
        jwks: JwksKeySource | Mapping[str, object] | None = None,
        operating_profile: OperatingProfile = "webrtc_16k",
        stream_factory: Callable[[str], VoiceStreamSinkProtocol] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._client = client
        self._jwks = jwks if jwks is not None else (client.jwks if client is not None else None)
        self._operating_profile = operating_profile
        self._stream_factory = stream_factory
        self._clock = clock or (lambda: int(time.time()))
        self._verdicts: dict[str, SessionVerdictRecord] = {}

    @property
    def client(self) -> AsyncEntrosClient | None:
        return self._client

    def get_latest_verdict(self, session_id: str) -> SessionVerdictRecord | None:
        """Return the latest verified VoiceLivenessVerdict record for session_id."""
        return self._verdicts.get(session_id)

    def clear_session(self, session_id: str) -> None:
        """Remove verdict metadata when a LiveKit room session closes."""
        self._verdicts.pop(session_id, None)

    async def record_verdict_jws(
        self,
        session_id: str,
        verdict_jws: str,
        *,
        now_seconds: int | None = None,
    ) -> SessionVerdictRecord | None:
        """Verify an incoming signed VoiceLivenessVerdict JWS offline and store it by session_id."""
        if self._jwks is None:
            raise ValueError("jwks or client with jwks must be configured to verify verdicts")
        now = self._clock() if now_seconds is None else now_seconds
        res = await verify_voice_liveness_verdict_async(
            verdict_jws,
            jwks=self._jwks,
            now_seconds=now,
        )
        if not res.ok or res.verdict is None:
            return None
        if res.verdict.session_id != session_id:
            return None
        record = SessionVerdictRecord(
            session_id=session_id,
            verdict_jws=verdict_jws,
            verdict=res.verdict,
            received_at=now,
        )
        self._verdicts[session_id] = record
        return record

    def _open_stream(self, session_id: str) -> VoiceStreamSinkProtocol:
        if self._stream_factory is not None:
            return self._stream_factory(session_id)
        if self._client is None:
            raise ValueError("AsyncEntrosClient or stream_factory is required for live track streaming")
        codec: VoiceCodec = "pcm16_8k" if self._operating_profile == "telephony_8k" else "pcm16_16k"
        return self._client.stream_voice(
            session_id=session_id,
            codec=codec,
            operating_profile=self._operating_profile,
        )

    async def attach_raw_audio_track(
        self,
        *,
        session_id: str,
        audio_stream: AudioStreamProtocol,
        denoiser_applied: bool = False,
    ) -> SessionVerdictRecord | None:
        """Consume raw 16 kHz WebRTC audio before any denoiser/STT and stream to /v1/voice/stream.

        Fails closed if denoiser_applied is True so neural denoisers never sit upstream
        of voice anti-spoofing.
        """
        if denoiser_applied:
            raise ValueError(
                "Upstream denoising is forbidden before Entros voice liveness scoring; "
                "subscribe to the raw inbound WebRTC track before noise cancellation or STT."
            )

        sink = self._open_stream(session_id)
        async with sink:
            async def _recv_loop() -> None:
                async for item in sink.receive_verdicts():
                    await self.record_verdict_jws(session_id, item.verdict_jws)

            recv_task = asyncio.create_task(_recv_loop())
            try:
                async for frame_item in audio_stream:
                    raw_pcm, sample_rate = _extract_raw_pcm(frame_item)
                    if sample_rate <= 0:
                        raise ValueError("Audio frame sample_rate must be positive")
                    if raw_pcm:
                        await sink.send_audio(raw_pcm)
                await sink.finish_utterance()
                await recv_task
            finally:
                if not recv_task.done():
                    recv_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await recv_task

        return self.get_latest_verdict(session_id)


def entros_voice_gate(
    *,
    policy: PolicyV2,
    audience: str,
    nonce_store: PermitNonceStoreV2,
    jwks: JwksKeySource | Mapping[str, object],
    firewall: EntrosVoiceFirewall | None = None,
    client: AsyncEntrosClient | None = None,
    server: str = "livekit-voice-agent",
    tool_name: str | None = None,
    step_up_mode: LiveKitStepUpMode = "sep_1036",
    require_registered_nonce: bool = False,
    raise_on_block: bool = False,
    clock: Callable[[], int] | None = None,
) -> Callable[[Callable[..., object]], Callable[..., Awaitable[object]]]:
    """Decorate a LiveKit Agent tool to require a verified AgentPermit v2.

    When no valid permit is attached and the active session verdict is suspicious,
    insufficient_signal, or missing, triggers SEP-1036 or OIDC CIBA Passkey step-up
    instead of executing the privileged tool.
    """
    now_fn = clock or (lambda: int(time.time()))

    def _decorator(fn: Callable[..., object]) -> Callable[..., Awaitable[object]]:
        resolved_tool = tool_name or getattr(fn, "__name__", "voice_tool")
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def _wrapper(*args: object, **kwargs: object) -> object:
            call_kwargs = dict(kwargs)
            session_id_raw = call_kwargs.pop("entros_session_id", None)
            if session_id_raw is None:
                session_id_raw = call_kwargs.get("session_id")
            session_id = session_id_raw if isinstance(session_id_raw, str) else ""
            permit_raw = call_kwargs.pop("entros_permit", None)
            if permit_raw is None:
                permit_raw = call_kwargs.pop("permit_jws", None)
            permit_jws = permit_raw if isinstance(permit_raw, str) and permit_raw else None

            bound = sig.bind_partial(*args, **call_kwargs)
            bound.apply_defaults()
            action: dict[str, object] = {
                "kind": "voice.tool_call",
                "server": server,
                "tool": resolved_tool,
                "arguments": dict(bound.arguments),
            }
            now = now_fn()

            # Check active voice verdict if firewall is attached and no permit was supplied yet.
            latest = firewall.get_latest_verdict(session_id) if (firewall and session_id) else None
            if permit_jws is None:
                verdict_val = latest.verdict.verdict if latest is not None else "insufficient_signal"
                if verdict_val == "likely_synthetic":
                    if raise_on_block:
                        raise EntrosVoiceGateBlocked(reason=RefusalCode.VOICE_VERDICT_NOT_ALLOWED.value)
                    return {
                        "decision": "deny",
                        "reason": RefusalCode.VOICE_VERDICT_NOT_ALLOWED.value,
                        "step_up_required": False,
                    }

                # Trigger SEP-1036 or OIDC CIBA Passkey step-up on suspicious/insufficient_signal
                # or whenever policy requires an AgentPermit v2 not yet presented.
                active_client = client or (firewall.client if firewall else None)
                step_up_resp: StepUpChallengeResponse | None = None
                if active_client is not None:
                    step_up_resp = await active_client.request_step_up(
                        action=action,
                        policy_id=policy.policy_id,
                        audience=audience,
                        mode=step_up_mode,
                        session_id=session_id or None,
                        reason=f"voice_verdict:{verdict_val}",
                    )
                if raise_on_block:
                    raise EntrosVoiceGateBlocked(
                        reason=f"step_up_required:{verdict_val}",
                        step_up=step_up_resp,
                    )
                return {
                    "decision": "step_up_required",
                    "mode": step_up_mode,
                    "voice_verdict": verdict_val,
                    "policy_id": policy.policy_id,
                    "step_up": (
                        {
                            "jti": step_up_resp.jti,
                            "request_digest": step_up_resp.request_digest,
                            "approval_url": step_up_resp.approval_url,
                            "expires_at": step_up_resp.expires_at,
                            "auth_req_id": step_up_resp.auth_req_id,
                        }
                        if step_up_resp is not None
                        else None
                    ),
                }

            result = await verify_agent_permit_v2_async(
                permit_jws,
                policy=policy,
                expected_audience=audience,
                jwks=jwks,
                action=action,
                now_seconds=now,
                nonce_store=nonce_store,
                require_registered_nonce=require_registered_nonce,
            )
            if not result.ok:
                reason = result.reason.value if result.reason else "denied"
                if raise_on_block:
                    raise EntrosVoiceGateBlocked(reason=reason, verification=result)
                return {
                    "decision": result.decision,
                    "reason": reason,
                    "detail": result.detail,
                }

            output = fn(*args, **call_kwargs)
            if inspect.isawaitable(output):
                return await output
            return output

        return _wrapper

    return _decorator
