"""Pipecat FrameProcessor tapping raw InputAudioRawFrame and gating FunctionCallInProgressFrame.

Architecture invariants:
- Uses real pipecat classes when pipecat is installed, falling back to compatible
  standalone types only when pipecat is unavailable, and recognizes duck-typed
  Pipecat-compatible audio/tool frames fail-closed.
- Taps raw InputAudioRawFrame into a bounded sequential worker queue without
  blocking downstream STT forwarding and without retaining raw audio bytes in memory.
- Emits EntrosVoiceVerdictFrame metadata downstream whenever a verified signed
  VoiceLivenessVerdict arrives.
- Intercepts privileged FunctionCallInProgressFrame calls and forwards them only
  after an AgentPermit v2 passes all prechecks, session continuity binding, and
  atomic jti consumption.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from entros_verify.jwks import JwksKeySource
from entros_verify.models import PolicyV2, RefusalCode, VoiceLivenessVerdict
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2_async
from entros_verify.voice import verify_voice_liveness_verdict_async

if TYPE_CHECKING:
    _HAS_REAL_PIPECAT: bool

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

    class FrameProcessor:
        """Typed fallback interface matching pipecat.processors.frame_processor.FrameProcessor."""

        name: str

        def __init__(self, *, name: str | None = None) -> None: ...

        def set_push_hook(
            self,
            hook: Callable[[Frame, FrameDirection], Awaitable[None]],
        ) -> None: ...

        async def push_frame(
            self,
            frame: Frame,
            direction: FrameDirection = FrameDirection.DOWNSTREAM,
        ) -> None: ...

        async def process_frame(self, frame: Frame, direction: FrameDirection) -> None: ...

else:
    try:
        from pipecat.frames.frames import (
            Frame,
            FunctionCallInProgressFrame,
            InputAudioRawFrame,
        )
        from pipecat.processors.frame_processor import FrameDirection, FrameProcessor

        _HAS_REAL_PIPECAT = True
    except ImportError:
        _HAS_REAL_PIPECAT = False

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

        class FrameProcessor:
            """Lightweight standalone base matching pipecat FrameProcessor with zero frame retention."""

            def __init__(self, *, name: str | None = None) -> None:
                self.name = name or type(self).__name__
                self._push_hook: Callable[[Frame, FrameDirection], Awaitable[None]] | None = None

            def set_push_hook(
                self,
                hook: Callable[[Frame, FrameDirection], Awaitable[None]],
            ) -> None:
                self._push_hook = hook

            async def push_frame(
                self,
                frame: Frame,
                direction: FrameDirection = FrameDirection.DOWNSTREAM,
            ) -> None:
                # Never retain raw audio frames in memory; forward solely through the hook.
                if self._push_hook is not None:
                    await self._push_hook(frame, direction)

            async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
                await self.push_frame(frame, direction)


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


_VERDICT_SEVERITY: dict[str, int] = {
    "likely_human": 0,
    "insufficient_signal": 1,
    "suspicious": 2,
    "likely_synthetic": 3,
}


@dataclass(frozen=True)
class _FunctionCallExtraction:
    valid: bool
    function_name: str
    tool_call_id: str
    arguments: Mapping[str, object]
    permit_jws: str | None


def _extract_function_call_fields(frame: object) -> _FunctionCallExtraction | None:
    """Recognize FunctionCallInProgressFrame or duck-typed tool-call frames fail-closed."""
    if isinstance(frame, (EntrosStepUpRequiredFrame, EntrosVoiceVerdictFrame)):
        return None
    is_known = isinstance(frame, FunctionCallInProgressFrame)
    if not is_known and not hasattr(frame, "function_name"):
        return None

    fn_name = getattr(frame, "function_name", None)
    tool_call_id = getattr(frame, "tool_call_id", None)
    arguments = getattr(frame, "arguments", None)
    valid_fn = isinstance(fn_name, str) and bool(fn_name.strip())
    valid_call_id = isinstance(tool_call_id, str) and bool(tool_call_id.strip())
    valid_args = isinstance(arguments, Mapping)
    if not (valid_fn and valid_call_id and valid_args):
        return _FunctionCallExtraction(
            valid=False,
            function_name=fn_name if isinstance(fn_name, str) else "",
            tool_call_id=tool_call_id if isinstance(tool_call_id, str) else "",
            arguments={},
            permit_jws=None,
        )

    assert isinstance(fn_name, str)
    assert isinstance(tool_call_id, str)
    assert isinstance(arguments, Mapping)
    permit_raw = getattr(frame, "permit_jws", None)
    permit_jws = permit_raw if isinstance(permit_raw, str) and permit_raw else None
    return _FunctionCallExtraction(
        valid=True,
        function_name=fn_name,
        tool_call_id=tool_call_id,
        arguments=arguments,
        permit_jws=permit_jws,
    )


def _is_output_or_tts_audio_frame(frame: object) -> bool:
    for cls in type(frame).__mro__:
        lower_name = cls.__name__.lower()
        if "output" in lower_name or "tts" in lower_name:
            return True
    return False


def _extract_audio_frame_fields(frame: object) -> tuple[bytes, int] | None:
    """Recognize inbound InputAudioRawFrame while rejecting outbound/TTS audio frames."""
    is_known = isinstance(frame, InputAudioRawFrame)
    if _HAS_REAL_PIPECAT:
        if not is_known:
            return None
    elif not is_known and _is_output_or_tts_audio_frame(frame):
        return None

    audio = getattr(frame, "audio", None)
    sample_rate = getattr(frame, "sample_rate", None)
    if (
        not isinstance(audio, (bytes, bytearray, memoryview))
        or not isinstance(sample_rate, int)
        or isinstance(sample_rate, bool)
        or sample_rate <= 0
    ):
        return None
    return bytes(audio), sample_rate


class EntrosVoiceFirewallProcessor(FrameProcessor):
    """Pipecat FrameProcessor tapping raw audio in parallel and gating privileged tool calls.

    Raw InputAudioRawFrame audio is forwarded to STT immediately without blocking or
    applying any denoising, while a bounded sequential background queue streams raw
    copies to Entros for signed VoiceLivenessVerdict scoring without retaining frames.
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
        on_audio_tap_error: Callable[[Exception], None] | None = None,
        max_pending_audio_taps: int = 64,
        permit_resolver: Callable[[str, str, Mapping[str, object]], Awaitable[str | None]] | None = None,
        gated_functions: set[str] | frozenset[str] | None = None,
        server: str = "pipecat-voice-agent",
        require_registered_nonce: bool = False,
        clock: Callable[[], int] | None = None,
        name: str | None = None,
    ) -> None:
        if max_pending_audio_taps < 1:
            raise ValueError("max_pending_audio_taps must be >= 1")
        super().__init__(name=name or "EntrosVoiceFirewallProcessor")
        self._session_id = session_id
        self._policy = policy
        self._audience = audience
        self._jwks = jwks
        self._nonce_store = nonce_store
        self._audio_tap_callback = audio_tap_callback
        self._on_audio_tap_error = on_audio_tap_error
        self._max_pending_audio_taps = max_pending_audio_taps
        self._permit_resolver = permit_resolver
        self._gated_functions = frozenset(gated_functions) if gated_functions is not None else None
        self._server = server
        self._require_registered_nonce = require_registered_nonce
        self._clock = clock or (lambda: int(time.time()))
        self._latest_verdict_jws: str | None = None
        self._latest_verdict: VoiceLivenessVerdict | None = None
        self._tap_queue: asyncio.Queue[tuple[bytes, int] | None] | None = None
        self._tap_worker: asyncio.Task[None] | None = None
        self._draining = False
        self._dropped_audio_taps = 0

    def _active_verdict(self, now: int | None = None) -> VoiceLivenessVerdict | None:
        ts = self._clock() if now is None else now
        if self._latest_verdict is not None and ts >= self._latest_verdict.exp:
            self._latest_verdict = None
            self._latest_verdict_jws = None
        return self._latest_verdict

    @property
    def latest_verdict(self) -> VoiceLivenessVerdict | None:
        return self._active_verdict()

    @property
    def latest_verdict_jws(self) -> str | None:
        self._active_verdict()
        return self._latest_verdict_jws

    @property
    def dropped_audio_taps(self) -> int:
        return self._dropped_audio_taps

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
        existing = self._active_verdict(now)
        if existing is not None:
            if res.verdict.iat < existing.iat:
                return None
            if (
                res.verdict.iat == existing.iat
                and _VERDICT_SEVERITY.get(res.verdict.verdict, 1)
                < _VERDICT_SEVERITY.get(existing.verdict, 1)
            ):
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

    async def _run_tap_worker(self, queue: asyncio.Queue[tuple[bytes, int] | None]) -> None:
        callback = self._audio_tap_callback
        if callback is None:
            return
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                raw_audio, sample_rate = item
                try:
                    await callback(raw_audio, sample_rate)
                except Exception as exc:
                    if self._on_audio_tap_error is not None:
                        with contextlib.suppress(Exception):
                            self._on_audio_tap_error(exc)
            finally:
                queue.task_done()

    def _ensure_tap_worker(self) -> asyncio.Queue[tuple[bytes, int] | None]:
        if self._tap_queue is None:
            self._tap_queue = asyncio.Queue(maxsize=self._max_pending_audio_taps)
        if self._tap_worker is None or self._tap_worker.done():
            self._tap_worker = asyncio.create_task(self._run_tap_worker(self._tap_queue))
        return self._tap_queue

    def _enqueue_audio_tap(self, raw_audio: bytes, sample_rate: int) -> None:
        if self._draining or self._audio_tap_callback is None or not raw_audio:
            return
        queue = self._ensure_tap_worker()
        try:
            queue.put_nowait((raw_audio, sample_rate))
        except asyncio.QueueFull:
            # Drop the oldest queued audio chunk so memory stays strictly bounded.
            with contextlib.suppress(asyncio.QueueEmpty):
                _ = queue.get_nowait()
                queue.task_done()
            self._dropped_audio_taps += 1
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait((raw_audio, sample_rate))

    async def drain_audio_taps(self) -> None:
        """Await all queued audio tap callbacks and stop the worker cleanly."""
        self._draining = True
        try:
            queue = self._tap_queue
            worker = self._tap_worker
            if queue is not None and worker is not None and not worker.done():
                put_task: asyncio.Task[None] = asyncio.create_task(queue.put(None))
                done, pending = await asyncio.wait(
                    {put_task, worker},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if put_task in pending:
                    put_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await put_task
                else:
                    with contextlib.suppress(asyncio.CancelledError):
                        await put_task
                if worker not in done:
                    await worker
            elif worker is not None:
                with contextlib.suppress(asyncio.CancelledError):
                    await worker
        finally:
            self._tap_worker = None
            self._tap_queue = None
            self._draining = False

    async def process_frame(self, frame: Frame, direction: FrameDirection) -> None:
        """Tap raw audio frames without blocking STT and gate privileged function calls."""
        if _HAS_REAL_PIPECAT:
            await super().process_frame(frame, direction)
        frame_type_name = type(frame).__name__
        if frame_type_name in ("EndFrame", "CancelFrame"):
            await self.drain_audio_taps()
            await self.push_frame(frame, direction)
            return

        call_fields = _extract_function_call_fields(frame)
        if call_fields is not None:
            if not call_fields.valid:
                await self.push_frame(
                    EntrosStepUpRequiredFrame(
                        session_id=self._session_id,
                        function_name=call_fields.function_name,
                        tool_call_id=call_fields.tool_call_id,
                        reason=RefusalCode.INVALID_PERMIT.value,
                        policy_id=self._policy.policy_id,
                    ),
                    direction,
                )
                return

            fn_name = call_fields.function_name
            tool_call_id = call_fields.tool_call_id
            arguments = call_fields.arguments
            permit_jws = call_fields.permit_jws
            if not self._is_gated(fn_name):
                await self.push_frame(frame, direction)
                return

            if permit_jws is None and self._permit_resolver is not None:
                permit_jws = await self._permit_resolver(fn_name, tool_call_id, arguments)

            if not permit_jws:
                active_verdict = self._active_verdict()
                verdict_label = (
                    active_verdict.verdict
                    if active_verdict is not None
                    else "insufficient_signal"
                )
                await self.push_frame(
                    EntrosStepUpRequiredFrame(
                        session_id=self._session_id,
                        function_name=fn_name,
                        tool_call_id=tool_call_id,
                        reason=f"permit_required:{verdict_label}",
                        policy_id=self._policy.policy_id,
                    ),
                    direction,
                )
                return

            action: dict[str, object] = {
                "kind": "voice.tool_call",
                "server": self._server,
                "tool": fn_name,
                "arguments": dict(arguments),
            }
            result = await verify_agent_permit_v2_async(
                permit_jws,
                policy=self._policy,
                expected_audience=self._audience,
                jwks=self._jwks,
                action=action,
                expected_session_id=self._session_id,
                now_seconds=self._clock,
                nonce_store=self._nonce_store,
                require_registered_nonce=self._require_registered_nonce,
            )
            if not result.ok or result.permit is None:
                reason = result.reason.value if result.reason else RefusalCode.INVALID_PERMIT.value
                await self.push_frame(
                    EntrosStepUpRequiredFrame(
                        session_id=self._session_id,
                        function_name=fn_name,
                        tool_call_id=tool_call_id,
                        reason=reason,
                        policy_id=self._policy.policy_id,
                    ),
                    direction,
                )
                return

            await self.push_frame(frame, direction)
            return

        audio_fields = _extract_audio_frame_fields(frame)
        if audio_fields is not None:
            raw_audio, sample_rate = audio_fields
            self._enqueue_audio_tap(raw_audio, sample_rate)
            await self.push_frame(frame, direction)
            return

        await self.push_frame(frame, direction)
