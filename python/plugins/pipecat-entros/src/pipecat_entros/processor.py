"""Pipecat FrameProcessor tapping raw InputAudioRawFrame and gating FunctionCallInProgressFrame.

Architecture invariants:
- Taps raw InputAudioRawFrame in parallel without modifying or denoising audio and
  without blocking downstream STT forwarding.
- Emits EntrosVoiceVerdictFrame metadata downstream whenever a verified signed
  VoiceLivenessVerdict arrives.
- Intercepts privileged FunctionCallInProgressFrame calls and forwards them only
  after an AgentPermit v2 passes all prechecks and atomic jti consumption.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum

from entros_verify.jwks import JwksKeySource
from entros_verify.models import PolicyV2, RefusalCode, VoiceLivenessVerdict
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2_async
from entros_verify.voice import verify_voice_liveness_verdict_async


class FrameDirection(Enum):
    """Direction of frame traversal in a Pipecat pipeline."""

    DOWNSTREAM = 1
    UPSTREAM = 2


@dataclass
class Frame:
    """Base pipeline frame compatible with Pipecat frame semantics."""

    id: int = 0


@dataclass
class InputAudioRawFrame(Frame):
    """Raw inbound PCM audio frame tapped before denoising or STT."""

    audio: bytes = b""
    sample_rate: int = 16000
    num_channels: int = 1


@dataclass
class FunctionCallInProgressFrame(Frame):
    """LLM function/tool call frame intercepted until AgentPermit v2 resolves."""

    function_name: str = ""
    tool_call_id: str = ""
    arguments: dict[str, object] = field(default_factory=dict)
    permit_jws: str | None = None


@dataclass
class EntrosVoiceVerdictFrame(Frame):
    """Metadata-only frame emitted downstream when a signed VoiceLivenessVerdict verifies."""

    session_id: str = ""
    verdict_jws: str = ""
    verdict: VoiceLivenessVerdict | None = None


@dataclass
class EntrosStepUpRequiredFrame(Frame):
    """Frame emitted when a gated tool call is halted pending Passkey step-up or valid permit."""

    session_id: str = ""
    function_name: str = ""
    tool_call_id: str = ""
    reason: str = ""
    policy_id: str = ""


class FrameProcessor:
    """Lightweight standalone base matching pipecat.processors.frame_processor.FrameProcessor."""

    def __init__(self, *, name: str | None = None) -> None:
        self.name = name or type(self).__name__
        self._downstream: list[tuple[Frame, FrameDirection]] = []
        self._push_hook: Callable[[Frame, FrameDirection], Awaitable[None]] | None = None

    def set_push_hook(
        self,
        hook: Callable[[Frame, FrameDirection], Awaitable[None]],
    ) -> None:
        self._push_hook = hook

    @property
    def pushed_frames(self) -> list[tuple[Frame, FrameDirection]]:
        return list(self._downstream)

    async def push_frame(
        self,
        frame: Frame,
        direction: FrameDirection = FrameDirection.DOWNSTREAM,
    ) -> None:
        self._downstream.append((frame, direction))
        if self._push_hook is not None:
            await self._push_hook(frame, direction)

    async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
        await self.push_frame(frame, direction)


class EntrosVoiceFirewallProcessor(FrameProcessor):
    """Pipecat FrameProcessor tapping raw audio in parallel and gating privileged tool calls.

    Raw InputAudioRawFrame audio is forwarded to STT immediately without blocking or
    applying any denoising, while a parallel non-blocking background copy streams to
    Entros for signed VoiceLivenessVerdict scoring.
    """

    def __init__(
        self,
        *,
        session_id: str,
        policy: PolicyV2,
        audience: str,
        jwks: JwksKeySource | Mapping[str, object],
        nonce_store: PermitNonceStoreV2,
        audio_tap_callback: Callable[[bytes, int], Awaitable[None]] | None = None,
        permit_resolver: Callable[[str, str, Mapping[str, object]], Awaitable[str | None]] | None = None,
        gated_functions: set[str] | frozenset[str] | None = None,
        server: str = "pipecat-voice-agent",
        require_registered_nonce: bool = False,
        clock: Callable[[], int] | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name or "EntrosVoiceFirewallProcessor")
        self._session_id = session_id
        self._policy = policy
        self._audience = audience
        self._jwks = jwks
        self._nonce_store = nonce_store
        self._audio_tap_callback = audio_tap_callback
        self._permit_resolver = permit_resolver
        self._gated_functions = frozenset(gated_functions) if gated_functions is not None else None
        self._server = server
        self._require_registered_nonce = require_registered_nonce
        self._clock = clock or (lambda: int(time.time()))
        self._latest_verdict_jws: str | None = None
        self._latest_verdict: VoiceLivenessVerdict | None = None
        self._tap_tasks: set[asyncio.Task[None]] = set()

    @property
    def latest_verdict(self) -> VoiceLivenessVerdict | None:
        return self._latest_verdict

    @property
    def latest_verdict_jws(self) -> str | None:
        return self._latest_verdict_jws

    def _is_gated(self, function_name: str) -> bool:
        if self._gated_functions is None:
            return True
        return function_name in self._gated_functions

    async def ingest_verdict_jws(
        self,
        verdict_jws: str,
        *,
        now_seconds: int | None = None,
    ) -> EntrosVoiceVerdictFrame | None:
        """Verify an incoming VoiceLivenessVerdict JWS and emit EntrosVoiceVerdictFrame downstream."""
        now = self._clock() if now_seconds is None else now_seconds
        res = await verify_voice_liveness_verdict_async(
            verdict_jws,
            jwks=self._jwks,
            now_seconds=now,
        )
        if not res.ok or res.verdict is None:
            return None
        if res.verdict.session_id != self._session_id:
            return None

        self._latest_verdict_jws = verdict_jws
        self._latest_verdict = res.verdict
        verdict_frame = EntrosVoiceVerdictFrame(
            session_id=self._session_id,
            verdict_jws=verdict_jws,
            verdict=res.verdict,
        )
        await self.push_frame(verdict_frame, FrameDirection.DOWNSTREAM)
        return verdict_frame

    async def drain_audio_taps(self) -> None:
        """Await any pending parallel raw-audio tap tasks (useful for graceful shutdown)."""
        if self._tap_tasks:
            await asyncio.gather(*list(self._tap_tasks), return_exceptions=True)

    def _spawn_audio_tap(self, raw_audio: bytes, sample_rate: int) -> None:
        if self._audio_tap_callback is None or not raw_audio:
            return
        callback = self._audio_tap_callback

        async def _run_tap() -> None:
            await callback(raw_audio, sample_rate)

        task = asyncio.create_task(_run_tap())
        self._tap_tasks.add(task)
        task.add_done_callback(self._tap_tasks.discard)

    async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
        """Tap raw audio frames without blocking STT and gate privileged function calls."""
        if isinstance(frame, InputAudioRawFrame):
            # Tap raw un-denoised audio in parallel; immediately forward original frame to STT.
            self._spawn_audio_tap(bytes(frame.audio), frame.sample_rate)
            await self.push_frame(frame, direction)
            return

        if isinstance(frame, FunctionCallInProgressFrame) and self._is_gated(frame.function_name):
            permit_jws = frame.permit_jws
            if permit_jws is None and self._permit_resolver is not None:
                permit_jws = await self._permit_resolver(
                    frame.function_name,
                    frame.tool_call_id,
                    frame.arguments,
                )

            if not permit_jws:
                verdict_label = (
                    self._latest_verdict.verdict
                    if self._latest_verdict is not None
                    else "insufficient_signal"
                )
                await self.push_frame(
                    EntrosStepUpRequiredFrame(
                        session_id=self._session_id,
                        function_name=frame.function_name,
                        tool_call_id=frame.tool_call_id,
                        reason=f"permit_required:{verdict_label}",
                        policy_id=self._policy.policy_id,
                    ),
                    direction,
                )
                return

            action: dict[str, object] = {
                "kind": "voice.tool_call",
                "server": self._server,
                "tool": frame.function_name,
                "arguments": dict(frame.arguments),
            }
            result = await verify_agent_permit_v2_async(
                permit_jws,
                policy=self._policy,
                expected_audience=self._audience,
                jwks=self._jwks,
                action=action,
                now_seconds=self._clock(),
                nonce_store=self._nonce_store,
                require_registered_nonce=self._require_registered_nonce,
            )
            if not result.ok:
                reason = result.reason.value if result.reason else RefusalCode.INVALID_PERMIT.value
                await self.push_frame(
                    EntrosStepUpRequiredFrame(
                        session_id=self._session_id,
                        function_name=frame.function_name,
                        tool_call_id=frame.tool_call_id,
                        reason=reason,
                        policy_id=self._policy.policy_id,
                    ),
                    direction,
                )
                return

            await self.push_frame(frame, direction)
            return

        await self.push_frame(frame, direction)
