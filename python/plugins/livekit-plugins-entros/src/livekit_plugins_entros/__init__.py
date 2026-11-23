"""LiveKit Agents plugin for Entros real-time voice liveness and AgentPermit v2 gating."""

from livekit_plugins_entros.firewall import (
    AudioFrameProtocol,
    AudioStreamProtocol,
    EntrosVoiceFirewall,
    EntrosVoiceGateBlocked,
    SessionVerdictRecord,
    VoiceStreamSinkProtocol,
    entros_voice_gate,
)

__version__ = "1.0.0"

__all__ = [
    "AudioFrameProtocol",
    "AudioStreamProtocol",
    "EntrosVoiceFirewall",
    "EntrosVoiceGateBlocked",
    "SessionVerdictRecord",
    "VoiceStreamSinkProtocol",
    "__version__",
    "entros_voice_gate",
]
