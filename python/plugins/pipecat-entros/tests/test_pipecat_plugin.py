"""Unit tests for pipecat-entros EntrosVoiceFirewallProcessor."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    VOICE_VERDICT_TYP,
    InMemoryPermitNonceStoreV2,
    PolicyV2,
    StaticJwksProvider,
    hash_action_v2,
)
from entros_verify._testing import b64url_encode_nopad, sign_eddsa_compact_jws
from pipecat_entros import (
    EntrosStepUpRequiredFrame,
    EntrosVoiceFirewallProcessor,
    EntrosVoiceVerdictFrame,
    Frame,
    FrameDirection,
    FunctionCallInProgressFrame,
    InputAudioRawFrame,
)


@dataclass
class _ExternalPipecatAudioFrame:
    """Simulates a real upstream pipecat InputAudioRawFrame class not inheriting our fallback."""

    audio: bytes
    sample_rate: int
    num_channels: int = 1


@dataclass
class _ExternalPipecatToolFrame:
    """Simulates a real upstream pipecat FunctionCallInProgressFrame class not inheriting our fallback."""

    function_name: str
    tool_call_id: str
    arguments: dict[str, object]


async def test_pipecat_parallel_audio_tap_verdict_frame_and_function_gating() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "pc-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    now = 1795450150
    session_id = "pc_call_77"
    policy = PolicyV2(
        policy_id="pc-transfer-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()
    tapped_audio: list[tuple[bytes, int]] = []
    pushed: list[tuple[Frame, FrameDirection]] = []

    async def _tap(raw_audio: bytes, sample_rate: int) -> None:
        tapped_audio.append((raw_audio, sample_rate))

    async def _capture_push(frame: Frame, direction: FrameDirection) -> None:
        pushed.append((frame, direction))

    processor = EntrosVoiceFirewallProcessor(
        session_id=session_id,
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        nonce_store=store,
        audio_tap_callback=_tap,
        gated_functions={"transfer_funds"},
        clock=lambda: now,
    )
    # Zero raw-audio retention: fallback FrameProcessor must NEVER retain pushed frames in memory.
    assert not hasattr(processor, "_downstream")
    assert not hasattr(processor, "pushed_frames")
    processor.set_push_hook(_capture_push)

    # 1. Raw InputAudioRawFrame passes downstream untouched without blocking STT.
    raw_pcm = b"\x10\x20\x30\x40" * 80
    audio_frame = InputAudioRawFrame(audio=raw_pcm, sample_rate=16000, num_channels=1)
    await processor.process_frame(audio_frame, FrameDirection.DOWNSTREAM)
    await processor.drain_audio_taps()

    assert len(tapped_audio) == 1 and tapped_audio[0] == (raw_pcm, 16000)
    assert pushed[0][0] is audio_frame
    assert audio_frame.audio == raw_pcm

    # 2. Signed VoiceLivenessVerdict emits EntrosVoiceVerdictFrame downstream.
    verdict_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="pc-k1",
        typ=VOICE_VERDICT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "jti": "e" * 64,
            "iat": now - 5,
            "exp": now + 115,
            "session_id": session_id,
            "verdict": "likely_human",
            "calibrated_llr": 4.4,
            "operating_profile": "webrtc_16k",
            "model_version": "0" * 64,
            "signal_quality": {
                "snr_db": 24.0,
                "speech_ms": 2000,
                "clipping": 0.0,
                "codec_bandwidth_hz": 8000,
            },
            "partial_spoof_spans": [],
            "consistency_drift": {
                "status": "evaluated",
                "windows_evaluated": 3,
                "floor_spread_db": 1.0,
                "tail_decay_spread_db": 1.0,
                "spectral_tilt_drift": 0.2,
                "reason": None,
            },
            "abstain_reason": None,
            "retention": "memory_only",
        },
    )
    verdict_frame = await processor.ingest_verdict_jws(verdict_jws)
    assert verdict_frame is not None
    assert isinstance(pushed[-1][0], EntrosVoiceVerdictFrame)

    # 3. Ungated tool passes straight through.
    ungated = FunctionCallInProgressFrame(function_name="check_balance", tool_call_id="tc-0", arguments={})
    await processor.process_frame(ungated, FrameDirection.DOWNSTREAM)
    ungated_out: Frame = pushed[-1][0]
    assert ungated_out is ungated

    # 4. Gated tool without permit is halted and emits EntrosStepUpRequiredFrame.
    blocked_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-1",
        arguments={"amount": 250},
    )
    await processor.process_frame(blocked_call, FrameDirection.DOWNSTREAM)
    last_frame = pushed[-1][0]
    assert isinstance(last_frame, EntrosStepUpRequiredFrame)
    assert last_frame.tool_call_id == "tc-1"

    # 5. Duck-typed third-party Pipecat-compatible audio & tool frames MUST fail closed (never bypassed!).
    ext_audio = _ExternalPipecatAudioFrame(audio=b"\xaa\xbb" * 40, sample_rate=16000)
    await processor.process_frame(cast(Frame, ext_audio), FrameDirection.DOWNSTREAM)
    await processor.drain_audio_taps()
    assert len(tapped_audio) == 2 and tapped_audio[1] == (b"\xaa\xbb" * 40, 16000)

    ext_tool = _ExternalPipecatToolFrame(
        function_name="transfer_funds",
        tool_call_id="tc-ext",
        arguments={"amount": 500},
    )
    await processor.process_frame(cast(Frame, ext_tool), FrameDirection.DOWNSTREAM)
    assert isinstance(pushed[-1][0], EntrosStepUpRequiredFrame)
    assert pushed[-1][0].tool_call_id == "tc-ext"

    # 6. Permit minted for a DIFFERENT session_id must fail continuity_broken WITHOUT burning nonce.
    digest = hash_action_v2(
        {
            "kind": "voice.tool_call",
            "server": "pipecat-voice-agent",
            "tool": "transfer_funds",
            "arguments": {"amount": 250},
        }
    )
    other_session_permit = sign_eddsa_compact_jws(
        private_key=priv,
        kid="pc-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-pc",
            "actor": {"id": "spiffe://acme.example/pc-agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "d" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": "different_session_99", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "1" * 64,
            "policy_id": "pc-transfer-v2",
            "scitt_receipt": None,
        },
    )
    wrong_sess_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-wrong-sess",
        arguments={"amount": 250},
        permit_jws=other_session_permit,
    )
    await processor.process_frame(wrong_sess_call, FrameDirection.DOWNSTREAM)
    assert isinstance(pushed[-1][0], EntrosStepUpRequiredFrame)
    assert pushed[-1][0].reason == "continuity_broken"
    assert store.peek("d" * 64) is None

    # 7. Gated tool with valid AgentPermit v2 passes once, then replay is blocked.
    permit_jws = sign_eddsa_compact_jws(
        private_key=priv,
        kid="pc-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-pc",
            "actor": {"id": "spiffe://acme.example/pc-agent"},
            "aud": "https://mcp.acme.example/v1/mcp",
            "jti": "f" * 64,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": session_id, "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "1" * 64,
            "policy_id": "pc-transfer-v2",
            "scitt_receipt": None,
        },
    )
    approved_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-2",
        arguments={"amount": 250},
        permit_jws=permit_jws,
    )
    await processor.process_frame(approved_call, FrameDirection.DOWNSTREAM)
    approved_out: Frame = pushed[-1][0]
    assert approved_out is approved_call

    replay_call = FunctionCallInProgressFrame(
        function_name="transfer_funds",
        tool_call_id="tc-3",
        arguments={"amount": 250},
        permit_jws=permit_jws,
    )
    await processor.process_frame(replay_call, FrameDirection.DOWNSTREAM)
    replay_frame = pushed[-1][0]
    assert isinstance(replay_frame, EntrosStepUpRequiredFrame)
    assert replay_frame.reason == "nonce_replayed"


async def test_pipecat_bounded_audio_tap_queue_and_error_callback() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "pc-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    policy = PolicyV2(
        policy_id="pc-q",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    errors: list[Exception] = []
    gate = asyncio.Event()

    async def _slow_failing_tap(raw_audio: bytes, sample_rate: int) -> None:
        await gate.wait()
        raise RuntimeError("upstream_voice_tap_error")

    processor = EntrosVoiceFirewallProcessor(
        session_id="pc_q_sess",
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        nonce_store=InMemoryPermitNonceStoreV2(),
        audio_tap_callback=_slow_failing_tap,
        on_audio_tap_error=errors.append,
        max_pending_audio_taps=2,
    )

    # Burst 6 frames before worker drains: queue stays bounded and counts dropped frames.
    for i in range(6):
        frame = InputAudioRawFrame(audio=bytes([i]) * 32, sample_rate=16000)
        await processor.process_frame(frame, FrameDirection.DOWNSTREAM)

    assert processor.dropped_audio_taps >= 3
    gate.set()
    await processor.drain_audio_taps()
    assert len(errors) >= 1 and isinstance(errors[0], RuntimeError)


@dataclass
class _OutputAudioRawFrame:
    audio: bytes
    sample_rate: int = 16000


@dataclass
class _TTSAudioRawFrame:
    audio: bytes
    sample_rate: int = 16000


@dataclass
class _MalformedToolFrame:
    function_name: str
    tool_call_id: object
    arguments: object


@dataclass
class EndFrame(Frame):
    pass


async def test_pipecat_fail_closed_tool_frames_tts_filter_severity_expiry_and_drain_safety() -> None:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "pc-k2",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    now_box = [1795450200]
    policy = PolicyV2(
        policy_id="pc-hardened-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    tapped: list[bytes] = []
    pushed: list[Frame] = []

    async def _tap(raw_audio: bytes, sample_rate: int) -> None:
        tapped.append(raw_audio)
        raise RuntimeError("tap failure")

    def _exploding_error_hook(exc: Exception) -> None:
        raise RuntimeError("error callback also threw")

    async def _push(frame: Frame, direction: FrameDirection) -> None:
        pushed.append(frame)

    processor = EntrosVoiceFirewallProcessor(
        session_id="pc_hard_1",
        policy=policy,
        audience="https://mcp.acme.example/v1/mcp",
        jwks=jwks,
        nonce_store=InMemoryPermitNonceStoreV2(),
        audio_tap_callback=_tap,
        on_audio_tap_error=_exploding_error_hook,
        gated_functions={"transfer_funds"},
        clock=lambda: now_box[0],
    )
    processor.set_push_hook(_push)

    # 1. Malformed FunctionCallInProgressFrame & duck-typed tool frames fail closed with invalid_permit (never fall through or substitute {}).
    malformed_frames: list[object] = [
        FunctionCallInProgressFrame(function_name="", tool_call_id="tc-1", arguments={}),
        FunctionCallInProgressFrame(function_name="check_balance", tool_call_id="", arguments={}),
        _MalformedToolFrame(function_name="transfer_funds", tool_call_id="tc-bad-args", arguments="not-a-dict"),
        _MalformedToolFrame(function_name="transfer_funds", tool_call_id=None, arguments={"amount": 10}),
    ]
    for bad in malformed_frames:
        await processor.process_frame(cast(Frame, bad), FrameDirection.DOWNSTREAM)
        out = pushed[-1]
        assert isinstance(out, EntrosStepUpRequiredFrame)
        assert out.reason == "invalid_permit"

    # 2. Bot OutputAudioRawFrame and TTSAudioRawFrame must NOT be tapped into caller voice liveness.
    await processor.process_frame(cast(Frame, _OutputAudioRawFrame(audio=b"\x01" * 64)), FrameDirection.DOWNSTREAM)
    await processor.process_frame(cast(Frame, _TTSAudioRawFrame(audio=b"\x02" * 64)), FrameDirection.DOWNSTREAM)
    await processor.drain_audio_taps()
    assert tapped == []

    # 3. Same-second severity downgrade must be rejected; verdict expires at now >= exp.
    def _verdict(label: str, *, iat_val: int, exp_val: int) -> str:
        return sign_eddsa_compact_jws(
            private_key=priv,
            kid="pc-k2",
            typ=VOICE_VERDICT_TYP,
            payload={
                "iss": "https://api.entros.io",
                "jti": "e" * 64,
                "iat": iat_val,
                "exp": exp_val,
                "session_id": "pc_hard_1",
                "verdict": label,
                "calibrated_llr": 4.0 if label == "likely_human" else -3.0,
                "operating_profile": "webrtc_16k",
                "model_version": "0" * 64,
                "signal_quality": {
                    "snr_db": 22.0,
                    "speech_ms": 2000,
                    "clipping": 0.0,
                    "codec_bandwidth_hz": 8000,
                },
                "partial_spoof_spans": [],
                "consistency_drift": {
                    "status": "evaluated",
                    "windows_evaluated": 3,
                    "floor_spread_db": 1.0,
                    "tail_decay_spread_db": 1.0,
                    "spectral_tilt_drift": 0.1,
                    "reason": None,
                },
                "abstain_reason": None,
                "retention": "memory_only",
            },
        )

    assert await processor.ingest_verdict_jws(
        _verdict("likely_synthetic", iat_val=now_box[0] - 20, exp_val=now_box[0] + 20)
    ) is not None
    # Same-second downgrade to suspicious or likely_human must be rejected.
    assert await processor.ingest_verdict_jws(
        _verdict("suspicious", iat_val=now_box[0] - 20, exp_val=now_box[0] + 20)
    ) is None
    assert await processor.ingest_verdict_jws(
        _verdict("likely_human", iat_val=now_box[0] - 20, exp_val=now_box[0] + 20)
    ) is None
    assert processor.latest_verdict is not None
    assert processor.latest_verdict.verdict == "likely_synthetic"

    # Once now >= exp, latest_verdict expires and tool gating reports insufficient_signal.
    now_box[0] += 25
    assert processor.latest_verdict is None
    assert processor.latest_verdict_jws is None
    await processor.process_frame(
        FunctionCallInProgressFrame(function_name="transfer_funds", tool_call_id="tc-exp", arguments={"a": 1}),
        FrameDirection.DOWNSTREAM,
    )
    exp_out = pushed[-1]
    assert isinstance(exp_out, EntrosStepUpRequiredFrame)
    assert exp_out.reason == "permit_required:insufficient_signal"

    # 4. Exploding on_audio_tap_error + EndFrame drain completes cleanly without deadlock.
    await processor.process_frame(InputAudioRawFrame(audio=b"\x99" * 64, sample_rate=16000), FrameDirection.DOWNSTREAM)
    await asyncio.wait_for(
        processor.process_frame(EndFrame(), FrameDirection.DOWNSTREAM),
        timeout=2.0,
    )
    assert len(tapped) == 1
    assert isinstance(pushed[-1], EndFrame)
