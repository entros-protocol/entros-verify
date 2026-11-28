# livekit-plugins-entros

First-party LiveKit Agents plugin for the Entros Live Human-Presence and Consent Firewall.

## What it provides

- `EntrosVoiceFirewall`: subscribes to raw inbound 16 kHz WebRTC tracks before noise cancellation or STT, streams PCM16 chunks to `GET /v1/voice/stream`, and tracks verified `VoiceLivenessVerdict` metadata per `session_id` with zero audio persistence.
- `@entros_voice_gate`: gates privileged LiveKit Agent tools behind single-use `AgentPermit` v2 tokens bound to the active `session_id` and routes `suspicious` or `insufficient_signal` sessions to `SEP-1036` or OpenID Connect CIBA Passkey step-up.

## Installation

```bash
pip install livekit-plugins-entros
```
