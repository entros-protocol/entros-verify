# pipecat-entros

First-party Pipecat `FrameProcessor` plugin for the Entros Live Human-Presence and Consent Firewall.

## What it provides

- `EntrosVoiceFirewallProcessor`: taps raw `InputAudioRawFrame` frames into a bounded non-blocking background worker without modifying or retaining audio bytes, emits metadata-only `EntrosVoiceVerdictFrame` frames when signed verdicts verify, and gates privileged `FunctionCallInProgressFrame` calls behind single-use `AgentPermit` v2 tokens bound to the active `session_id`.

## Installation

```bash
pip install pipecat-entros
```
