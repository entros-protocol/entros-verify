"""LangGraph interrupt() HITL consent node for AgentPermit v2.

Emits a strictly JSON-serializable interrupt(challenge) payload and verifies
Command(resume=settlement) atomically against Policy v2 and PermitNonceStoreV2
before permitting graph transition to the privileged tool node.
"""

from __future__ import annotations

import importlib
import inspect
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from urllib.parse import urlencode

from entros_verify.canonical import hash_action_v2
from entros_verify.errors import EntrosVerifyError
from entros_verify.jwks import JwksKeySource
from entros_verify.models import (
    CanonicalAction,
    DpopVerificationInput,
    PolicyV2,
    VerificationResult,
    WebAuthnAssertionInput,
)
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2, verify_agent_permit_v2_async


class ConsentDeniedError(EntrosVerifyError):
    """Raised when an AgentPermit v2 settlement fails verification in a LangGraph node."""

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        reason = result.reason.value if result.reason else "denied"
        super().__init__(f"Human consent denied ({reason}): {result.detail or ''}".strip())


def _default_langgraph_interrupt(payload: dict[str, object]) -> object:
    try:
        lg_types = importlib.import_module("langgraph.types")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "langgraph is not installed; install entros-verify[langgraph] or pass interrupt_fn"
        ) from exc
    interrupt_callable = getattr(lg_types, "interrupt", None)
    if not callable(interrupt_callable):
        raise RuntimeError("langgraph.types.interrupt is unavailable")
    return interrupt_callable(payload)


def _extract_action_default(state: Mapping[str, object]) -> Mapping[str, object]:
    raw_action = state.get("action") or state.get("pending_action")
    if isinstance(raw_action, CanonicalAction):
        return {
            "kind": raw_action.kind,
            "server": raw_action.server,
            "tool": raw_action.tool,
            "arguments": raw_action.arguments,
            **({"rar_details": raw_action.rar_details} if raw_action.rar_details is not None else {}),
        }
    if isinstance(raw_action, Mapping):
        return raw_action
    raise ValueError("Graph state must include an 'action' mapping or custom action_extractor")


def _unwrap_settlement(
    resumed: object,
) -> tuple[str | None, WebAuthnAssertionInput | None, DpopVerificationInput | None]:
    # Support LangGraph Command(resume=...) wrappers or plain settlement dicts/strings.
    payload: object = getattr(resumed, "resume", resumed)
    if isinstance(payload, str):
        return payload, None, None
    if isinstance(payload, Mapping):
        permit_raw = payload.get("permit_jws") or payload.get("permit")
        permit_jws = permit_raw if isinstance(permit_raw, str) else None

        webauthn_raw = payload.get("webauthn_assertion")
        webauthn_input: WebAuthnAssertionInput | None = None
        if isinstance(webauthn_raw, WebAuthnAssertionInput):
            webauthn_input = webauthn_raw
        elif isinstance(webauthn_raw, Mapping):
            webauthn_input = WebAuthnAssertionInput.model_validate(webauthn_raw)

        dpop_raw = payload.get("dpop")
        dpop_input: DpopVerificationInput | None = None
        if isinstance(dpop_raw, DpopVerificationInput):
            dpop_input = dpop_raw
        elif isinstance(dpop_raw, Mapping):
            dpop_input = DpopVerificationInput.model_validate(dpop_raw)

        return permit_jws, webauthn_input, dpop_input
    return None, None, None


def _build_approval_url(base_url: str, jti: str) -> str:
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{urlencode({'jti': jti})}"


def entros_consent_node(
    policy: PolicyV2,
    nonce_store: PermitNonceStoreV2,
    *,
    audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    approval_base_url: str = "https://approve.entros.io/consent",
    challenge_ttl_seconds: int = 300,
    action_extractor: Callable[[Mapping[str, object]], CanonicalAction | Mapping[str, object]] | None = None,
    interrupt_fn: Callable[[dict[str, object]], object] | None = None,
    jti_generator: Callable[[], str] | None = None,
    clock: Callable[[], int] | None = None,
    require_registered_nonce: bool = True,
    raise_on_deny: bool = True,
) -> Callable[[Mapping[str, object]], dict[str, object]]:
    """Build a synchronous LangGraph node enforcing AgentPermit v2 via interrupt()."""
    if challenge_ttl_seconds < 30 or challenge_ttl_seconds > 900:
        raise ValueError("challenge_ttl_seconds must be within 30..900")

    extract_action = action_extractor or _extract_action_default
    do_interrupt = interrupt_fn or _default_langgraph_interrupt
    gen_jti = jti_generator or (lambda: secrets.token_hex(32))
    now_fn = clock or (lambda: int(time.time()))

    def _node(state: Mapping[str, object]) -> dict[str, object]:
        action = extract_action(state)
        request_digest = hash_action_v2(action)
        now = now_fn()
        expires_at = now + challenge_ttl_seconds
        jti = gen_jti()

        reg_res = nonce_store.register(
            jti=jti,
            expires_at=expires_at,
            created_at=now,
            request_digest=request_digest,
            aud=audience,
            policy_id=policy.policy_id,
        )
        if inspect.isawaitable(reg_res):
            raise RuntimeError("Async PermitNonceStoreV2 requires entros_consent_node_async")

        challenge: dict[str, object] = {
            "type": "entros_consent_required",
            "jti": jti,
            "request_digest": request_digest,
            "aud": audience,
            "policy_id": policy.policy_id,
            "approval_url": _build_approval_url(approval_base_url, jti),
            "expires_at": expires_at,
        }

        resumed = do_interrupt(challenge)
        permit_jws, webauthn_input, dpop_input = _unwrap_settlement(resumed)
        if not permit_jws:
            denied = VerificationResult(
                ok=False,
                decision="deny",
                reason=None,
                detail="Resume settlement missing permit_jws",
                evaluated_at=now_fn(),
            )
            if raise_on_deny:
                raise ConsentDeniedError(denied)
            return {
                "entros_consent": {
                    "approved": False,
                    "decision": "deny",
                    "reason": "invalid_jws",
                    "jti": jti,
                    "request_digest": request_digest,
                }
            }

        result = verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            jwks=jwks,
            action=action,
            now_seconds=now_fn(),
            webauthn_assertion=webauthn_input,
            dpop=dpop_input,
            nonce_store=nonce_store,
            require_registered_nonce=require_registered_nonce,
        )
        if not result.ok or result.permit is None:
            if raise_on_deny:
                raise ConsentDeniedError(result)
            return {
                "entros_consent": {
                    "approved": False,
                    "decision": result.decision,
                    "reason": result.reason.value if result.reason else None,
                    "jti": jti,
                    "request_digest": request_digest,
                }
            }

        return {
            "entros_consent": {
                "approved": True,
                "decision": "allow",
                "jti": result.permit.jti,
                "request_digest": result.permit.request_digest,
                "assurance_tier": result.permit.assurance_tier,
                "modality": list(result.permit.modality),
                "policy_id": result.permit.policy_id,
                "scitt_receipt": result.permit.scitt_receipt,
            }
        }

    return _node


def entros_consent_node_async(
    policy: PolicyV2,
    nonce_store: PermitNonceStoreV2,
    *,
    audience: str,
    jwks: JwksKeySource | Mapping[str, object],
    approval_base_url: str = "https://approve.entros.io/consent",
    challenge_ttl_seconds: int = 300,
    action_extractor: Callable[[Mapping[str, object]], CanonicalAction | Mapping[str, object]] | None = None,
    interrupt_fn: Callable[[dict[str, object]], object] | None = None,
    jti_generator: Callable[[], str] | None = None,
    clock: Callable[[], int] | None = None,
    require_registered_nonce: bool = True,
    raise_on_deny: bool = True,
) -> Callable[[Mapping[str, object]], Awaitable[dict[str, object]]]:
    """Build an async LangGraph node enforcing AgentPermit v2 via interrupt()."""
    if challenge_ttl_seconds < 30 or challenge_ttl_seconds > 900:
        raise ValueError("challenge_ttl_seconds must be within 30..900")

    extract_action = action_extractor or _extract_action_default
    do_interrupt = interrupt_fn or _default_langgraph_interrupt
    gen_jti = jti_generator or (lambda: secrets.token_hex(32))
    now_fn = clock or (lambda: int(time.time()))

    async def _node(state: Mapping[str, object]) -> dict[str, object]:
        action = extract_action(state)
        request_digest = hash_action_v2(action)
        now = now_fn()
        expires_at = now + challenge_ttl_seconds
        jti = gen_jti()

        reg_res = nonce_store.register(
            jti=jti,
            expires_at=expires_at,
            created_at=now,
            request_digest=request_digest,
            aud=audience,
            policy_id=policy.policy_id,
        )
        if inspect.isawaitable(reg_res):
            await reg_res

        challenge: dict[str, object] = {
            "type": "entros_consent_required",
            "jti": jti,
            "request_digest": request_digest,
            "aud": audience,
            "policy_id": policy.policy_id,
            "approval_url": _build_approval_url(approval_base_url, jti),
            "expires_at": expires_at,
        }

        resumed = do_interrupt(challenge)
        if inspect.isawaitable(resumed):
            resumed = await resumed
        permit_jws, webauthn_input, dpop_input = _unwrap_settlement(resumed)
        if not permit_jws:
            denied = VerificationResult(
                ok=False,
                decision="deny",
                reason=None,
                detail="Resume settlement missing permit_jws",
                evaluated_at=now_fn(),
            )
            if raise_on_deny:
                raise ConsentDeniedError(denied)
            return {
                "entros_consent": {
                    "approved": False,
                    "decision": "deny",
                    "reason": "invalid_jws",
                    "jti": jti,
                    "request_digest": request_digest,
                }
            }

        result = await verify_agent_permit_v2_async(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            jwks=jwks,
            action=action,
            now_seconds=now_fn(),
            webauthn_assertion=webauthn_input,
            dpop=dpop_input,
            nonce_store=nonce_store,
            require_registered_nonce=require_registered_nonce,
        )
        if not result.ok or result.permit is None:
            if raise_on_deny:
                raise ConsentDeniedError(result)
            return {
                "entros_consent": {
                    "approved": False,
                    "decision": result.decision,
                    "reason": result.reason.value if result.reason else None,
                    "jti": jti,
                    "request_digest": request_digest,
                }
            }

        return {
            "entros_consent": {
                "approved": True,
                "decision": "allow",
                "jti": result.permit.jti,
                "request_digest": result.permit.request_digest,
                "assurance_tier": result.permit.assurance_tier,
                "modality": list(result.permit.modality),
                "policy_id": result.permit.policy_id,
                "scitt_receipt": result.permit.scitt_receipt,
            }
        }

    return _node
