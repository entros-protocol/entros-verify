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
    canonicalize_jcs_bytes,
    hash_action_v2,
)
from entros_verify._testing import (
    b64url_decode_nopad,
    b64url_encode_nopad,
    create_scitt_receipt,
    sign_eddsa_compact_jws,
)
from entros_verify.adapters import (
    ConsentDeniedError,
    entros_consent_node,
    entros_consent_node_async,
    format_insufficient_scope_header,
    require_human_consent,
)
from entros_verify.adapters.fastmcp import (
    RequestStateClaims,
    sign_request_state,
    verify_request_state,
)


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
    ttl_seconds: int = 300,
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
            "exp": now - 5 + ttl_seconds,
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

    # Missing requestState on MRTR Round 2 retry must fail closed (cannot bypass MRTR binding).
    missing_state = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        inputResponses=[{"permit_jws": permit_jws}],
    )
    assert isinstance(missing_state, dict)
    assert missing_state["isError"] is True
    assert missing_state["reason"] == "invalid_permit"
    assert executions[0] == 0

    # Malformed webauthn_assertion / dpop inputs must return denial dicts, not raise ValidationError.
    bad_webauthn = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": permit_jws}],
        webauthn_assertion={"bad": True},
    )
    assert isinstance(bad_webauthn, dict)
    assert bad_webauthn["isError"] is True
    assert bad_webauthn["reason"] == "webauthn_assertion_invalid"

    bad_dpop = await transfer_funds(
        amount=250,
        recipient="acct_9942",
        requestState=round1["requestState"],
        inputResponses=[{"permit_jws": permit_jws}],
        dpop={"bad": True},
    )
    assert isinstance(bad_dpop, dict)
    assert bad_dpop["isError"] is True
    assert bad_dpop["reason"] == "dpop_proof_invalid"
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

    # Untrusted caller kwargs MUST NOT override server-configured protocol_mode="mcp_mrtr".
    # Passing unexpected kwarg must fail (never downgrade to sep_1036).
    with pytest.raises(TypeError):
        await transfer_funds(
            amount=250,
            recipient="acct_9942",
            mcp_consent_mode="sep_1036",
        )

    # Server-configured SEP-1036 URL-Mode Elicitation emits mode="url" (never form mode).
    @require_human_consent(
        policy=policy,
        audience=audience,
        nonce_store=store,
        jwks=jwks,
        server="treasury-mcp",
        protocol_mode="sep_1036",
        clock=lambda: now,
    )
    async def sep_transfer_funds(amount: int, recipient: str) -> dict[str, object]:
        return {"status": "transferred", "amount": amount, "recipient": recipient}

    sep_challenge = await sep_transfer_funds(amount=250, recipient="acct_9942")
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
            "v": 2,
            "jti": claims.jti,
            "request_digest": claims.request_digest,
            "aud": claims.aud,
            "policy_id": claims.policy_id,
            "iat": claims.iat,
            "exp": claims.exp,
        }
    )
    verified_claims = verify_request_state(token, secret, now_seconds=now)
    assert verified_claims == claims
    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_request_state(claims, b"too-short-secret")

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


def test_langgraph_true_interrupt_reexecution_has_zero_orphan_nonces_and_jti_binding() -> None:
    """Simulate real LangGraph interrupt() raising on Run 1 and re-entering from line 1 on Run 2."""
    priv, jwks = _make_key_and_jwks()
    now = 1795450150
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="lg-reexec-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()

    class _GraphInterrupt(Exception):
        def __init__(self, challenge: dict[str, object]) -> None:
            super().__init__("graph_interrupt")
            self.challenge = challenge

    resume_payload: list[object] = []
    seen_challenges: list[dict[str, object]] = []

    def _real_interrupt(challenge: dict[str, object]) -> object:
        seen_challenges.append(challenge)
        if not resume_payload:
            raise _GraphInterrupt(challenge)
        return resume_payload.pop(0)

    node = entros_consent_node(
        policy,
        store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_real_interrupt,
        clock=lambda: now,
    )
    state: dict[str, object] = {
        "action": {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "transfer_funds",
            "arguments": {"amount": 400, "currency": "USD"},
        }
    }

    # Run 1: raises GraphInterrupt with challenge jti_1 and registers exactly 1 nonce.
    with pytest.raises(_GraphInterrupt) as exc_info:
        node(state)
    challenge_1 = exc_info.value.challenge
    jti_1 = str(challenge_1["jti"])
    digest = str(challenge_1["request_digest"])
    assert store.size == 1

    # Register another distinct jti_2 and try to resume with jti_2 -> MUST be rejected.
    jti_2 = "8" * 64
    store.register(
        jti=jti_2,
        created_at=now,
        expires_at=now + 300,
        request_digest=digest,
        aud=audience,
        policy_id=policy.policy_id,
    )
    wrong_permit = _mint_passkey_permit(
        priv,
        jti=jti_2,
        request_digest=digest,
        audience=audience,
        policy_id=policy.policy_id,
        now=now,
    )
    resume_payload.append(_MockCommand(resume={"permit_jws": wrong_permit}))
    with pytest.raises(ConsentDeniedError, match="nonce_not_found"):
        node(state)
    # Re-execution MUST have reused jti_1 instead of registering an orphan third nonce.
    assert store.size == 2
    assert seen_challenges[-1]["jti"] == jti_1

    # Run 2 (legitimate resume from line 1): reuses jti_1, verifies & consumes atomically.
    good_permit = _mint_passkey_permit(
        priv,
        jti=jti_1,
        request_digest=digest,
        audience=audience,
        policy_id=policy.policy_id,
        now=now,
    )
    resume_payload.append(_MockCommand(resume={"permit_jws": good_permit}))
    out = node(state)
    consent = out["entros_consent"]
    assert isinstance(consent, dict) and consent["approved"] is True
    assert consent["jti"] == jti_1
    assert store.size == 2
    rec_1 = store.peek(jti_1)
    assert rec_1 is not None and rec_1.consumed_at == now


async def test_langgraph_per_thread_isolation_and_async_lock() -> None:
    import asyncio

    priv, jwks = _make_key_and_jwks()
    now = 1795450200
    audience = "https://mcp.acme.example/v1/mcp"
    policy = PolicyV2(
        policy_id="lg-iso-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
    )
    store = InMemoryPermitNonceStoreV2()

    class _Pause(Exception):
        def __init__(self, challenge: dict[str, object]) -> None:
            super().__init__("pause")
            self.challenge = challenge

    def _raise_interrupt(challenge: dict[str, object]) -> object:
        raise _Pause(challenge)

    node = entros_consent_node(
        policy,
        store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_raise_interrupt,
        clock=lambda: now,
    )
    same_action_state: dict[str, object] = {
        "action": {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "transfer_funds",
            "arguments": {"amount": 100},
        }
    }

    with pytest.raises(_Pause) as exc_a:
        node(same_action_state, {"configurable": {"thread_id": "thread-A"}})
    with pytest.raises(_Pause) as exc_b:
        node(same_action_state, {"configurable": {"thread_id": "thread-B"}})
    # Distinct threads for the exact same action MUST get isolated jtis.
    assert exc_a.value.challenge["jti"] != exc_b.value.challenge["jti"]

    # Re-entering thread-A reuses thread-A's jti without registering a third nonce.
    with pytest.raises(_Pause) as exc_a2:
        node(same_action_state, {"configurable": {"thread_id": "thread-A"}})
    assert exc_a2.value.challenge["jti"] == exc_a.value.challenge["jti"]
    assert store.size == 2

    # Async lock coalesces concurrent check-and-register on the same thread without orphan nonces.
    async_store = InMemoryPermitNonceStoreV2()

    async def _slow_interrupt(challenge: dict[str, object]) -> object:
        await asyncio.sleep(0.01)
        permit = _mint_passkey_permit(
            priv,
            jti=str(challenge["jti"]),
            request_digest=str(challenge["request_digest"]),
            audience=audience,
            policy_id=policy.policy_id,
            now=now,
        )
        return _MockCommand(resume={"permit_jws": permit})

    async_node = entros_consent_node_async(
        policy,
        async_store,
        audience=audience,
        jwks=jwks,
        interrupt_fn=_slow_interrupt,
        clock=lambda: now,
    )
    r1, r2 = await asyncio.gather(
        async_node({**same_action_state, "thread_id": "async-t1"}),
        async_node({**same_action_state, "thread_id": "async-t2"}),
    )
    c1 = r1["entros_consent"]
    c2 = r2["entros_consent"]
    assert isinstance(c1, dict) and isinstance(c2, dict)
    assert c1["approved"] is True and c2["approved"] is True
    assert c1["jti"] != c2["jti"]


async def test_fastmcp_scope_injection_elicitation_id_ttl_clamp_and_optional_register() -> None:
    priv, jwks = _make_key_and_jwks()
    now = 1795450200
    audience = "https://mcp.acme.example/v1/mcp"

    # 1. RFC 6750 scope validation rejects header injection & deduplicates.
    assert (
        format_insufficient_scope_header(["mcp:read mcp:write", "mcp:read"])
        == 'Bearer error="insufficient_scope", scope="mcp:read mcp:write entros:permit:step_up"'
    )
    for malicious in (
        'read" evil="1',
        "read\\escape",
        "read\r\nX-Injected: 1",
        "read\twrite",
        "café",
    ):
        with pytest.raises(ValueError, match="Invalid RFC 6750 scope token"):
            format_insufficient_scope_header(malicious)

    # 2. Validates audience & approval_base_url at decoration time.
    short_policy = PolicyV2(
        policy_id="fastmcp-hardened-v2",
        allowed_assurance_tiers=["passkey_webauthn_uv"],
        required_modalities=["webauthn_uv"],
        max_evidence_age_seconds=120,
        max_permit_lifetime_seconds=60,
    )
    store = InMemoryPermitNonceStoreV2()
    with pytest.raises(ValueError, match="audience"):
        require_human_consent(
            policy=short_policy,
            audience="http://insecure.example/mcp",
            nonce_store=store,
            jwks=jwks,
        )
    with pytest.raises(ValueError, match="approval_base_url"):
        require_human_consent(
            policy=short_policy,
            audience=audience,
            approval_base_url="http://evil.example/approve",
            nonce_store=store,
            jwks=jwks,
        )

    # 3. Gates Round-1 nonce_store.register on require_registered_nonce=False and clamps TTL <= policy.max_permit_lifetime_seconds.
    secret = b"fastmcp-hardened-secret-32-bytes!!"

    @require_human_consent(
        policy=short_policy,
        audience=audience,
        nonce_store=store,
        jwks=jwks,
        server="treasury-mcp",
        protocol_mode="mcp_mrtr",
        request_state_secret=secret,
        challenge_ttl_seconds=300,
        require_registered_nonce=False,
        clock=lambda: now,
    )
    async def send_wire(amount: int) -> dict[str, object]:
        return {"sent": amount}

    r1 = await send_wire(amount=75)
    assert isinstance(r1, dict) and r1["resultType"] == "input_required"
    assert store.size == 0  # require_registered_nonce=False skipped Round-1 register
    claims = verify_request_state(str(r1["requestState"]), secret, now_seconds=now)
    assert claims is not None
    assert claims.exp == now + 60  # Clamped from 300 to policy.max_permit_lifetime_seconds=60

    digest = hash_action_v2(
        {
            "kind": "mcp.tool_call",
            "server": "treasury-mcp",
            "tool": "send_wire",
            "arguments": {"amount": 75},
        }
    )
    good_permit = _mint_passkey_permit(
        priv,
        jti=claims.jti,
        request_digest=digest,
        audience=audience,
        policy_id=short_policy.policy_id,
        now=now,
        ttl_seconds=60,
    )
    other_permit = _mint_passkey_permit(
        priv,
        jti="7" * 64,
        request_digest=digest,
        audience=audience,
        policy_id=short_policy.policy_id,
        now=now,
        ttl_seconds=60,
    )

    # 4. Honors elicitationId in inputResponses: rejects list with only wrong elicitationId, selects matching entry otherwise.
    wrong_elicit = await send_wire(
        amount=75,
        requestState=r1["requestState"],
        inputResponses=[{"elicitationId": "7" * 64, "permit_jws": other_permit}],
    )
    assert isinstance(wrong_elicit, dict) and wrong_elicit["isError"] is True
    assert wrong_elicit["reason"] == "invalid_permit"

    matched_elicit = await send_wire(
        amount=75,
        requestState=r1["requestState"],
        inputResponses=[
            {"elicitationId": "7" * 64, "permit_jws": other_permit},
            {"elicitationId": claims.jti, "permit_jws": good_permit},
        ],
    )
    assert matched_elicit == {"sent": 75}
