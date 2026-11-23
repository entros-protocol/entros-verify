"""Pipecat FrameProcessor for Entros parallel voice liveness and AgentPermit v2 gating."""

from pipecat_entros.processor import (
    EntrosStepUpRequiredFrame,
    EntrosVoiceFirewallProcessor,
    EntrosVoiceVerdictFrame,
    Frame,
    FrameDirection,
    FrameProcessor,
    FunctionCallInProgressFrame,
    InputAudioRawFrame,
)

__version__ = "1.0.0"

__all__ = [
    "EntrosStepUpRequiredFrame",
    "EntrosVoiceFirewallProcessor",
    "EntrosVoiceVerdictFrame",
    "Frame",
    "FrameDirection",
    "FrameProcessor",
    "FunctionCallInProgressFrame",
    "InputAudioRawFrame",
    "__version__",
]
