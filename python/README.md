# entros-verify (Python SDK)

Pure-MIT Python SDK for verifying Entros `VoiceLivenessVerdict` JWS tokens, `Entros-Agent-Permit-v2` single-use action permits, `Policy v2` contracts, zero-CBOR WebAuthn P-256 assertions, RFC 9449 DPoP proofs, and IETF SCITT (`RFC 9943`) `COSE_Sign1` receipts.

## Scope notice

- A `VoiceLivenessVerdict` evidences acoustic liveness for a scored audio window under a pinned `model_version` and `operating_profile` (`webrtc_16k`, `telephony_8k`, or `wideband_clean`) with `retention: "memory_only"`. It does not perform speaker identification or establish caller legal identity without a separate authenticated session (`sub`) or hardware Passkey assertion.
- Standard WebAuthn `navigator.credentials.get()` verification proves hardware-backed User Presence (`UP=1`) and User Verification (`UV=1`) over a domain-separated `permit_challenge` bound to `jti` and `request_digest`.
- Voice audio must be sent raw before any neural denoising (`DeepFilterNet`, `RNNoise`, `Krisp`) or STT processing.

## Installation

```bash
pip install entros-verify
```

Optional extras for agent frameworks:

```bash
pip install "entros-verify[mcp]"
pip install "entros-verify[langgraph]"
```

First-party voice framework plugins ship as dedicated packages under `python/plugins/`:

```bash
pip install livekit-plugins-entros
pip install pipecat-entros
```

- `livekit-plugins-entros`: raw 16 kHz WebRTC track subscriber and `@entros_voice_gate` tool decorator.
- `pipecat-entros`: `EntrosVoiceFirewallProcessor` parallel raw-audio tap and `FunctionCallInProgressFrame` gate.

## Quick verification example

```python
from entros_verify import (
    InMemoryPermitNonceStoreV2,
    PolicyV2,
    verify_agent_permit_v2,
)

policy = PolicyV2(
    policy_id="wire-transfer-high-v2",
    allowed_assurance_tiers=["voice_plus_passkey", "passkey_webauthn_uv"],
    required_modalities=["webauthn_uv"],
    max_evidence_age_seconds=120,
    max_permit_lifetime_seconds=300,
)

nonce_store = InMemoryPermitNonceStoreV2()
result = verify_agent_permit_v2(
    permit_jws,
    policy=policy,
    expected_audience="https://mcp.acme-bank.example/v1/mcp",
    jwks=jwks_cache,
    action={
        "kind": "mcp.tool_call",
        "server": "treasury-mcp",
        "tool": "transfer_funds",
        "arguments": {"amount": 250, "currency": "USD", "recipient": "acct_9942"},
    },
    nonce_store=nonce_store,
)
assert result.ok and result.decision == "allow"
```

## Development checks

```bash
pytest -v
mypy --strict src
ruff check src plugins scripts tests
python scripts/check_python_licenses.py
```
