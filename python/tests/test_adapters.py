"""Unit tests for LangGraph interrupt() node and FastMCP @require_human_consent decorator."""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from entros_verify import (
    AGENT_PERMIT_TYP,
    InMemoryPermitNonceStoreV2,
    PolicyV2,
    ScittDecisionPayload,
    ScittReceiptResult,
    StaticJwksProvider,
    b64url_decode_nopad,
    b64url_encode_nopad,
    canonicalize_jcs_bytes,
    create_scitt_receipt,
    hash_action_v2,
    sign_eddsa_compact_jws,
)
from entros_verify.adapters import (
    ConsentDeniedError,
    entros_consent_node,
    entros_consent_node_async,
    format_insufficient_scope_header,
    require_human_consent,
)
from entros_verify.adapters.fastmcp import RequestStateClaims, sign_request_state


@dataclass
class _MockCommand:
    resume: object


def _make_key_and_jwks() -> tuple[Ed25519PrivateKey, StaticJwksProvider]:
    priv = Ed25519PrivateKey.generate()
    jwks = StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "adapter-k1",
                    "x": b64url_encode_nopad(priv.public_key().public_bytes_raw()),
                }
            ]
        }
    )
    return priv, jwks


def _mint_passkey_permit(
    priv: Ed25519PrivateKey,
    *,
    jti: str,
    request_digest: str,
    audience: str,
    policy_id: str,
    now: int,
    with_scitt: bool = False,
) -> str:
    scitt_b64: str | None = None
    if with_scitt:
        scitt_b64 = create_scitt_receipt(
            private_key=priv,
            kid="adapter-k1",
            payload=ScittDecisionPayload(
                schema="entros-scitt-permit-v2",
                jti=jti,
                request_digest=request_digest,
                policy_id=policy_id,
                aud=audience,
                decision="allow",
                reason="accepted",
                assurance_tier="passkey_webauthn_uv",
                modality=["webauthn_uv"],
                freshness_verified_at=now - 5,
                evaluated_at=now,
                model_version=None,
                retention="memory_only",
            ),
        )
    return sign_eddsa_compact_jws(
        private_key=priv,
        kid="adapter-k1",
        typ=AGENT_PERMIT_TYP,
        payload={
            "iss": "https://api.entros.io",
            "sub": "usr-lg-1",
            "actor": {"id": "spiffe://acme.example/agent"},
            "aud": audience,
            "jti": jti,
            "iat": now - 5,
            "exp": now + 295,
            "request_digest": request_digest,
            "assurance_tier": "passkey_webauthn_uv",
            "modality": ["webauthn_uv"],
            "freshness_verified_at": now - 5,
            "continuity": {"session_id": "lg-sess", "mode": "step_up_only"},
            "uniqueness_status": "enterprise_idp_subject",
            "voice_verdict_jws": None,
            "webauthn_assertion_digest": "f" * 64,
            "policy_id": policy_id,
            "scitt_receipt": scitt_b64,
        },
    )


def test_langgraph_consent_node_interrupt_and_atomic_resume() -> None:
    priv, jwks = _make_key_and_jwks()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="lg-transfer-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()
    captured_challenges: list[dict[str, object]] = []

    def _interrupt_accept(challenge: dict[str, object]) -> object:
        # Must be strictly JSON-serializable for LangGraph checkpointers.
        encoded = json.dumps(challenge)
        assert encoded
        captured_challenges.append(challenge)
        jti = str(challenge["jti"])
        digest = str(challenge["request_digest"])
        permit = _mint_passkey_permit(
            priv,
            jti=jti,
            request_digest=digest,
            audience=audience,
            policy_id=policy.policy_id,
            now=now,
        )
        return _MockCommand(resume={"permit_jws": permit})

    node = entros_consent_node(
        policy,
        store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_interrupt_accept,
        clock=lambda: now,
    )
    state: dict[str, object] = {
        "action": {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "transfer_funds",
            "arguments": {"amount": 250, "currency": "USD"},
        }
    }
    out = node(state)
    consent = out["entros_consent"]
    assert isinstance(consent, dict)
    assert consent["approved"] is True
    assert consent["assurance_tier"] == "passkey_webauthn_uv"
    assert len(captured_challenges) == 1

    # Tampered settlement digest must raise ConsentDeniedError.
    def _interrupt_tampered(challenge: dict[str, object]) -> object:
        permit = _mint_passkey_permit(
            priv,
            jti=str(challenge["jti"]),
            request_digest="a" * 64,
            audience=audience,
            policy_id=policy.policy_id,
            now=now,
        )
        return {"permit_jws": permit}

    bad_node = entros_consent_node(
        policy,
        store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_interrupt_tampered,
        clock=lambda: now,
    )
    with pytest.raises(ConsentDeniedError, match="request_digest_mismatch"):
        bad_node(state)


async def test_langgraph_consent_node_async_resume() -> None:
    priv, jwks = _make_key_and_jwks()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="lg-async-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()

    def _interrupt(challenge: dict[str, object]) -> object:
        permit = _mint_passkey_permit(
            priv,
            jti=str(challenge["jti"]),
            request_digest=str(challenge["request_digest"]),
            audience=audience,
            policy_id=policy.policy_id,
            now=now,
        )
        return _MockCommand(resume={"permit_jws": permit})

    node = entros_consent_node_async(
        policy,
        store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_interrupt,
        clock=lambda: now,
    )
    out = await node(
        {
            "action": {
                "kind": "mcp.tool_call",
                "server": "treasury-mcp",
                "tool": "transfer_funds",
                "arguments": {"amount": 50},
            }
        }
    )
    consent = out["entros_consent"]
    assert isinstance(consent, dict) and consent["approved"] is True


async def test_fastmcp_mrtr_and_sep1036_consent_flows() -> None:
    priv, jwks = _make_key_and_jwks()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="fastmcp-wire-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        require_scitt_receipt=True,
    )
    store = InMemoryPermitNonceStoreV2()
    logged_receipts: list[ScittReceiptResult] = []
    executions = [0]

    @require_human_consent(
        policy=policy,
        audience=audience,
        nonce_store=store,
        jwks=jwks,
        server="treasury-mcp",
        protocol_mode="mcp_mrtr",
        request_state_secret=b"stateless-replica-shared-secret-32b!",
        on_scitt_receipt=logged_receipts.append,
        clock=lambda: now,
    )
    async def transfer_funds(amount: int, recipient: str) -> dict[str, object]:
        executions[0] += 1
        return {"status": "transferred", "amount": amount, "recipient": recipient}

    # Round 1: returns MCP 2026-07-28 InputRequiredResult without executing tool.
    round1 = await transfer_funds(amount=250, recipient="acct_9942")
    assert isinstance(round1, dict)
    assert round1["resultType"] == "input_required"
    assert isinstance(round1["requestState"], str)
    input_reqs = round1["inputRequests"]
    assert isinstance(input_reqs, list) and len(input_reqs) == 1
    req_entry = input_reqs[0]
    assert isinstance(req_entry, dict) and req_entry["mode"] == "url"
    jti = str(req_entry["elicitationId"])
    assert executions[0] == 0

    expected_digest = hash_action_v2(
        {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "transfer_funds",
            "arguments": {"amount": 250, "recipient": "acct_9942"},
        }
    )
    permit_jws = _mint_passkey_permit(
        priv,
        jti=jti,
        request_digest=expected_digest,
        audience=audience,
        policy_id=policy.policy_id,
        now=now,
        with_scitt=True,
    )

    # Tampered argument on Round 2 fails request_digest_mismatch without burning nonce.
    tampered = await transfer_funds(
        amount=99999,
        recipient="acct_9942",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": permit_jws}],
    )
    assert isinstance(tampered, dict) and tampered["reason"] == "request_digest_mismatch"
    assert executions[0] == 0

    # Tampered requestState HMAC fails invalid_signature without burning nonce.
    bad_state = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        requestState=str(round1["requestState"])[:-2] + "AA",
        inputResponses=[{"permit_jws": permit_jws}],
    )
    assert isinstance(bad_state, dict) and bad_state["reason"] == "invalid_signature"
    assert executions[0] == 0

    # Valid Round 2 succeeds once and logs SCITT receipt.
    round2 = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": permit_jws}],
    )
    assert round2 == {"status": "transferred", "amount": 250, "recipient": "acct_9942"}
    assert executions[0] == 1
    assert len(logged_receipts) == 1
    assert logged_receipts[0].payload.jti == jti

    # Replayed Round 2 fails nonce_replayed.
    replay = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": permit_jws}],
    )
    assert isinstance(replay, dict) and replay["reason"] == "nonce_replayed"
    assert executions[0] == 1

    # SEP-1036 URL-Mode Elicitation emits mode="url" (never form mode).
    sep_challenge = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        mcp_consent_mode="sep_1036",
    )
    assert isinstance(sep_challenge, dict)
    assert sep_challenge["method"] == "elicitation/create"
    params = sep_challenge["params"]
    assert isinstance(params, dict) and params["mode"] == "url"

    # HTTP 403 insufficient_scope helper preserves existing scopes.
    header = format_insufficient_scope_header("mcp:tools:read mcp:tools:write")
    assert header == 'Bearer error="insufficient_scope", scope="mcp:tools:read mcp:tools:write entros:permit:step_up"'


async def test_fastmcp_mrtr_enforces_request_state_jti_binding_and_jcs() -> None:
    priv, jwks = _make_key_and_jwks()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="fastmcp-jti-bind-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()
    executions = [0]

    secret = b"mrtr-binding-shared-secret-32bytes!"
    claims = RequestStateClaims(
        jti="a" * 64,
        request_digest="b" * 64,
        aud=audience,
        policy_id=policy.policy_id,
        iat=now,
        exp=now + 300,
    )
    token = sign_request_state(claims, secret)
    raw_payload = b64url_decode_nopad(token.split(".", 1)[0])
    assert raw_payload == canonicalize_jcs_bytes(
        {
            "jti": claims.jti,
            "request_digest": claims.request_digest,
            "aud": claims.aud,
            "policy_id": claims.policy_id,
            "iat": claims.iat,
            "exp": claims.exp,
        }
    )

    @require_human_consent(
        policy=policy,
        audience=audience,
        nonce_store=store,
        jwks=jwks,
        server="treasury-mcp",
        protocol_mode="mcp_mrtr",
        request_state_secret=secret,
        clock=lambda: now,
    )
    async def wire_funds(amount: int, destination: str) -> dict[str, object]:
        executions[0] += 1
        return {"ok": True, "amount": amount, "destination": destination}

    round1 = await wire_funds(amount=100, destination="acct_1")
    assert isinstance(round1, dict) and round1["resultType"] == "input_required"
    reqs = round1["inputRequests"]
    assert isinstance(reqs, list) and isinstance(reqs[0], dict)
    jti_1 = str(reqs[0]["elicitationId"])

    expected_digest = hash_action_v2(
        {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "wire_funds",
            "arguments": {"amount": 100, "destination": "acct_1"},
        }
    )

    # Register a second distinct jti for the exact same action, audience, and policy.
    jti_2 = "9" * 64
    store.register(
        jti=jti_2,
        created_at=now,
        expires_at=now + 300,
        request_digest=expected_digest,
        aud=audience,
        policy_id=policy.policy_id,
    )
    mismatched_permit = _mint_passkey_permit(
        priv,
        jti=jti_2,
        request_digest=expected_digest,
        audience=audience,
        policy_id=policy.policy_id,
        now=now,
    )

    # Round 2 with requestState(jti_1) + permit(jti_2) must deny without burning either nonce.
    denied = await wire_funds(
        amount=100,
        destination="acct_1",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": mismatched_permit}],
    )
    assert isinstance(denied, dict)
    assert denied["isError"] is True
    assert denied["reason"] == "nonce_not_found"
    assert executions[0] == 0
    rec_1 = store.peek(jti_1)
    rec_2 = store.peek(jti_2)
    assert rec_1 is not None and rec_1.consumed_at is None
    assert rec_2 is not None and rec_2.consumed_at is None

    # Legitimate retry with matching jti_1 still succeeds once.
    matching_permit = _mint_passkey_permit(
        priv,
        jti=jti_1,
        request_digest=expected_digest,
        audience=audience,
        policy_id=policy.policy_id,
        now=now,
    )
    accepted = await wire_funds(
        amount=100,
        destination="acct_1",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": matching_permit}],
    )
    assert accepted == {"ok": True, "amount": 100, "destination": "acct_1"}
    assert executions[0] == 1
