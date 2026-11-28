"""LangGraph interrupt() HITL consent node for AgentPermit v2.

Emits a strictly JSON-serializable interrupt(challenge) payload, avoids duplicate
orphan nonce registration when LangGraph re-executes the node from line 1 on
resume, isolates pending challenges per thread/run, binds verification strictly
to the interrupted challenge's jti, and consumes the nonce atomically before
permitting transition to the tool node.
"""

from __future__ import annotations

import asyncio
import hmac
import importlib
import inspect
import secrets
import threading
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping
from typing import Protocol
from urllib.parse import urlencode

from pydantic import ValidationError

from entros_verify.adapters.fastmcp import _JtiBoundNonceStore
from entros_verify.canonical import hash_action_v2
from entros_verify.errors import EntrosVerifyError
from entros_verify.jwks import JwksKeySource
from entros_verify.models import (
    CanonicalAction,
    DpopVerificationInput,
    PolicyV2,
    RefusalCode,
    VerificationResult,
    WebAuthnAssertionInput,
)
from entros_verify.nonce_store import PermitNonceRecord, PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2, verify_agent_permit_v2_async
from entros_verify.uri import is_canonical_audience_uri, is_canonical_issuer_uri

MAX_PENDING_CHALLENGES = 4_096
PendingChallengeKey = tuple[str, str, str, str]


class SyncConsentNode(Protocol):
    """Callable signature for synchronous LangGraph consent nodes."""

    def __call__(
        self,
        state: Mapping[str, object],
        config: Mapping[str, object] | None = None,
    ) -> dict[str, object]: ...


class AsyncConsentNode(Protocol):
    """Callable signature for asynchronous LangGraph consent nodes."""

    def __call__(
        self,
        state: Mapping[str, object],
        config: Mapping[str, object] | None = None,
    ) -> Awaitable[dict[str, object]]: ...


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
) -> tuple[
    str | None,
    WebAuthnAssertionInput | None,
    DpopVerificationInput | None,
    RefusalCode | None,
    str | None,
]:
    # Support LangGraph Command(resume=...) wrappers or plain settlement dicts/strings.
    payload: object = getattr(resumed, "resume", resumed)
    if isinstance(payload, str):
        return payload, None, None, None, None
    if isinstance(payload, Mapping):
        permit_raw = payload.get("permit_jws") or payload.get("permit")
        permit_jws = permit_raw if isinstance(permit_raw, str) else None

        webauthn_raw = payload.get("webauthn_assertion")
        webauthn_input: WebAuthnAssertionInput | None = None
        if isinstance(webauthn_raw, WebAuthnAssertionInput):
            webauthn_input = webauthn_raw
        elif isinstance(webauthn_raw, Mapping):
            try:
                webauthn_input = WebAuthnAssertionInput.model_validate(webauthn_raw)
            except ValidationError:
                return (
                    None,
                    None,
                    None,
                    RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                    "Malformed webauthn_assertion in resume settlement",
                )
        elif webauthn_raw is not None:
            return (
                None,
                None,
                None,
                RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                "Malformed webauthn_assertion in resume settlement",
            )

        dpop_raw = payload.get("dpop")
        dpop_input: DpopVerificationInput | None = None
        if isinstance(dpop_raw, DpopVerificationInput):
            dpop_input = dpop_raw
        elif isinstance(dpop_raw, Mapping):
            try:
                dpop_input = DpopVerificationInput.model_validate(dpop_raw)
            except ValidationError:
                return (
                    None,
                    None,
                    None,
                    RefusalCode.DPOP_PROOF_INVALID,
                    "Malformed dpop payload in resume settlement",
                )
        elif dpop_raw is not None:
            return (
                None,
                None,
                None,
                RefusalCode.DPOP_PROOF_INVALID,
                "Malformed dpop payload in resume settlement",
            )

        return permit_jws, webauthn_input, dpop_input, None, None
    return None, None, None, None, None


def _build_approval_url(base_url: str, jti: str) -> str:
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{urlencode({'jti': jti})}"


def _matches_pending_record(
    record: PermitNonceRecord | None,
    *,
    request_digest: str,
    audience: str,
    policy_id: str,
    now: int,
) -> bool:
    if record is None or record.consumed_at is not None or now >= record.expires_at:
        return False
    if record.request_digest is not None and record.request_digest != request_digest:
        return False
    if record.aud is not None and record.aud != audience:
        return False
    return not (record.policy_id is not None and record.policy_id != policy_id)


def _extract_state_challenge_jti(state: Mapping[str, object]) -> str | None:
    raw = state.get("entros_challenge_jti")
    if isinstance(raw, str) and raw:
        return raw
    pending = state.get("entros_pending_challenge")
    if isinstance(pending, Mapping):
        nested = pending.get("jti")
        if isinstance(nested, str) and nested:
            return nested
    return None


def _coerce_id_token(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _extract_correlation_key(
    state: Mapping[str, object],
    config: Mapping[str, object] | None,
) -> str:
    """Derive a per-thread/run correlation key so concurrent threads never share pending challenges."""
    if isinstance(config, Mapping):
        configurable = config.get("configurable")
        if isinstance(configurable, Mapping):
            for field in ("thread_id", "checkpoint_id", "run_id"):
                token = _coerce_id_token(configurable.get(field))
                if token is not None:
                    return f"cfg:{field}:{token}"
        run_token = _coerce_id_token(config.get("run_id"))
        if run_token is not None:
            return f"cfg:run_id:{run_token}"

    explicit_jti = _extract_state_challenge_jti(state)
    if explicit_jti is not None:
        return f"jti:{explicit_jti}"

    for field in ("thread_id", "session_id", "entros_session_id", "run_id"):
        token = _coerce_id_token(state.get(field))
        if token is not None:
            return f"state:{field}:{token}"

    return "default"


def _prune_expired_pending(
    pending: dict[PendingChallengeKey, tuple[str, int]],
    now: int,
) -> None:
    expired_keys: list[PendingChallengeKey] = []
    for k, (_, exp) in pending.items():
        if now >= exp:
            expired_keys.append(k)
        else:
            # All challenges in a node share a fixed TTL, so insertion order is expiry order.
            break
    for k in expired_keys:
        pending.pop(k, None)


def _store_pending_challenge(
    pending: dict[PendingChallengeKey, tuple[str, int]],
    key: PendingChallengeKey,
    jti: str,
    expires_at: int,
    now: int,
) -> None:
    _prune_expired_pending(pending, now)
    pending.pop(key, None)
    if len(pending) >= MAX_PENDING_CHALLENGES:
        # Full sweep before FIFO eviction in case clock jumped backwards/forwards.
        for k in [k for k, (_, exp) in pending.items() if now >= exp]:
            pending.pop(k, None)
        while len(pending) >= MAX_PENDING_CHALLENGES:
            oldest_key = next(iter(pending))
            pending.pop(oldest_key, None)
    pending[key] = (jti, expires_at)


def _validate_node_config(
    *,
    policy: PolicyV2,
    audience: str,
    approval_base_url: str,
    challenge_ttl_seconds: int,
) -> int:
    if challenge_ttl_seconds < 30 or challenge_ttl_seconds > 900:
        raise ValueError("challenge_ttl_seconds must be within 30..900")
    if not is_canonical_audience_uri(audience):
        raise ValueError("audience must be a canonical RFC 8707 audience URI")
    if not is_canonical_issuer_uri(approval_base_url):
        raise ValueError("approval_base_url must be a canonical HTTPS or 127.0.0.1 URI")
    return min(challenge_ttl_seconds, policy.max_permit_lifetime_seconds)


def _build_challenge_payload(
    *,
    jti: str,
    request_digest: str,
    audience: str,
    policy_id: str,
    approval_base_url: str,
    expires_at: int,
) -> dict[str, object]:
    return {
        "type": "entros_consent_required",
        "jti": jti,
        "request_digest": request_digest,
        "aud": audience,
        "policy_id": policy_id,
        "approval_url": _build_approval_url(approval_base_url, jti),
        "expires_at": expires_at,
    }


def _build_missing_settlement_outcome(
    *,
    jti: str,
    request_digest: str,
    parse_reason: RefusalCode | None,
    parse_detail: str | None,
    evaluated_at: int,
    raise_on_deny: bool,
) -> dict[str, object]:
    denied = VerificationResult(
        ok=False,
        decision="deny",
        reason=parse_reason or RefusalCode.INVALID_JWS,
        detail=parse_detail or "Resume settlement missing permit_jws",
        evaluated_at=evaluated_at,
    )
    if raise_on_deny:
        raise ConsentDeniedError(denied)
    return {
        "entros_consent": {
            "approved": False,
            "decision": "deny",
            "reason": denied.reason.value if denied.reason else "invalid_jws",
            "jti": jti,
            "request_digest": request_digest,
        }
    }


def _finalize_consent_result(
    *,
    result: VerificationResult,
    jti: str,
    request_digest: str,
    key: PendingChallengeKey,
    pending_lock: threading.Lock,
    pending_challenges: dict[PendingChallengeKey, tuple[str, int]],
    raise_on_deny: bool,
) -> dict[str, object]:
    jti_matches = (
        result.permit is not None
        and result.permit.jti.isascii()
        and jti.isascii()
        and hmac.compare_digest(result.permit.jti.encode("ascii"), jti.encode("ascii"))
    )
    if not result.ok or result.permit is None or not jti_matches:
        effective = (
            result
            if not result.ok or result.permit is None
            else VerificationResult(
                ok=False,
                decision="deny",
                reason=RefusalCode.NONCE_NOT_FOUND,
                detail="Verified permit jti does not match interrupted challenge jti",
                permit=result.permit,
                evaluated_at=result.evaluated_at,
            )
        )
        if effective.reason in (RefusalCode.PERMIT_EXPIRED, RefusalCode.NONCE_REPLAYED):
            with pending_lock:
                if pending_challenges.get(key, ("", 0))[0] == jti:
                    pending_challenges.pop(key, None)
        if raise_on_deny:
            raise ConsentDeniedError(effective)
        return {
            "entros_consent": {
                "approved": False,
                "decision": effective.decision,
                "reason": effective.reason.value if effective.reason else None,
                "jti": jti,
                "request_digest": request_digest,
            }
        }

    with pending_lock:
        if pending_challenges.get(key, ("", 0))[0] == jti:
            pending_challenges.pop(key, None)

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
) -> SyncConsentNode:
    """Build a synchronous LangGraph node enforcing AgentPermit v2 via interrupt()."""
    effective_ttl = _validate_node_config(
        policy=policy,
        audience=audience,
        approval_base_url=approval_base_url,
        challenge_ttl_seconds=challenge_ttl_seconds,
    )

    extract_action = action_extractor or _extract_action_default
    do_interrupt = interrupt_fn or _default_langgraph_interrupt
    gen_jti = jti_generator or (lambda: secrets.token_hex(32))
    now_fn = clock or (lambda: int(time.time()))
    pending_lock = threading.Lock()
    pending_challenges: dict[PendingChallengeKey, tuple[str, int]] = {}

    def _get_or_register_challenge(
        state: Mapping[str, object],
        config: Mapping[str, object] | None,
        request_digest: str,
        now: int,
    ) -> tuple[str, int, PendingChallengeKey]:
        correlation_key = _extract_correlation_key(state, config)
        key: PendingChallengeKey = (correlation_key, request_digest, audience, policy.policy_id)

        with pending_lock:
            explicit_jti = _extract_state_challenge_jti(state)
            if explicit_jti is not None:
                peeked = nonce_store.peek(explicit_jti)
                if inspect.isawaitable(peeked):
                    raise RuntimeError("Async PermitNonceStoreV2 requires entros_consent_node_async")
                if _matches_pending_record(
                    peeked,
                    request_digest=request_digest,
                    audience=audience,
                    policy_id=policy.policy_id,
                    now=now,
                ):
                    assert peeked is not None
                    return peeked.jti, peeked.expires_at, key

            _prune_expired_pending(pending_challenges, now)
            cached = pending_challenges.get(key)
            if cached is not None:
                cached_jti, cached_exp = cached
                peeked = nonce_store.peek(cached_jti)
                if inspect.isawaitable(peeked):
                    raise RuntimeError("Async PermitNonceStoreV2 requires entros_consent_node_async")
                if _matches_pending_record(
                    peeked,
                    request_digest=request_digest,
                    audience=audience,
                    policy_id=policy.policy_id,
                    now=now,
                ):
                    return cached_jti, cached_exp, key

            jti = gen_jti()
            expires_at = now + effective_ttl
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
            _store_pending_challenge(pending_challenges, key, jti, expires_at, now)
            return jti, expires_at, key

    def _node(
        state: Mapping[str, object],
        config: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        action = extract_action(state)
        request_digest = hash_action_v2(action)
        now = now_fn()
        jti, expires_at, key = _get_or_register_challenge(state, config, request_digest, now)

        challenge = _build_challenge_payload(
            jti=jti,
            request_digest=request_digest,
            audience=audience,
            policy_id=policy.policy_id,
            approval_base_url=approval_base_url,
            expires_at=expires_at,
        )

        resumed = do_interrupt(challenge)
        permit_jws, webauthn_input, dpop_input, parse_reason, parse_detail = _unwrap_settlement(
            resumed
        )
        if parse_reason is not None or not permit_jws:
            return _build_missing_settlement_outcome(
                jti=jti,
                request_digest=request_digest,
                parse_reason=parse_reason,
                parse_detail=parse_detail,
                evaluated_at=now_fn(),
                raise_on_deny=raise_on_deny,
            )

        bound_store = _JtiBoundNonceStore(nonce_store, jti)
        result = verify_agent_permit_v2(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            jwks=jwks,
            action=action,
            now_seconds=now_fn,
            webauthn_assertion=webauthn_input,
            dpop=dpop_input,
            nonce_store=bound_store,
            require_registered_nonce=require_registered_nonce,
        )
        return _finalize_consent_result(
            result=result,
            jti=jti,
            request_digest=request_digest,
            key=key,
            pending_lock=pending_lock,
            pending_challenges=pending_challenges,
            raise_on_deny=raise_on_deny,
        )

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
) -> AsyncConsentNode:
    """Build an async LangGraph node enforcing AgentPermit v2 via interrupt()."""
    effective_ttl = _validate_node_config(
        policy=policy,
        audience=audience,
        approval_base_url=approval_base_url,
        challenge_ttl_seconds=challenge_ttl_seconds,
    )

    extract_action = action_extractor or _extract_action_default
    do_interrupt = interrupt_fn or _default_langgraph_interrupt
    gen_jti = jti_generator or (lambda: secrets.token_hex(32))
    now_fn = clock or (lambda: int(time.time()))
    pending_lock = threading.Lock()
    pending_challenges: dict[PendingChallengeKey, tuple[str, int]] = {}
    async_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
        weakref.WeakKeyDictionary()
    )

    def _get_async_lock() -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        with pending_lock:
            lock = async_locks.get(loop)
            if lock is None:
                lock = asyncio.Lock()
                async_locks[loop] = lock
            return lock

    async def _peek_async(jti: str) -> PermitNonceRecord | None:
        maybe_record = nonce_store.peek(jti)
        if inspect.isawaitable(maybe_record):
            return await maybe_record
        return maybe_record

    async def _get_or_register_challenge(
        state: Mapping[str, object],
        config: Mapping[str, object] | None,
        request_digest: str,
        now: int,
    ) -> tuple[str, int, PendingChallengeKey]:
        correlation_key = _extract_correlation_key(state, config)
        key: PendingChallengeKey = (correlation_key, request_digest, audience, policy.policy_id)

        async with _get_async_lock():
            explicit_jti = _extract_state_challenge_jti(state)
            if explicit_jti is not None:
                peeked = await _peek_async(explicit_jti)
                if _matches_pending_record(
                    peeked,
                    request_digest=request_digest,
                    audience=audience,
                    policy_id=policy.policy_id,
                    now=now,
                ):
                    assert peeked is not None
                    return peeked.jti, peeked.expires_at, key

            with pending_lock:
                _prune_expired_pending(pending_challenges, now)
                cached = pending_challenges.get(key)

            if cached is not None:
                cached_jti, cached_exp = cached
                peeked = await _peek_async(cached_jti)
                if _matches_pending_record(
                    peeked,
                    request_digest=request_digest,
                    audience=audience,
                    policy_id=policy.policy_id,
                    now=now,
                ):
                    return cached_jti, cached_exp, key

            jti = gen_jti()
            expires_at = now + effective_ttl
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
            with pending_lock:
                _store_pending_challenge(pending_challenges, key, jti, expires_at, now)
            return jti, expires_at, key

    async def _node(
        state: Mapping[str, object],
        config: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        action = extract_action(state)
        request_digest = hash_action_v2(action)
        now = now_fn()
        jti, expires_at, key = await _get_or_register_challenge(state, config, request_digest, now)

        challenge = _build_challenge_payload(
            jti=jti,
            request_digest=request_digest,
            audience=audience,
            policy_id=policy.policy_id,
            approval_base_url=approval_base_url,
            expires_at=expires_at,
        )

        resumed = do_interrupt(challenge)
        if inspect.isawaitable(resumed):
            resumed = await resumed
        permit_jws, webauthn_input, dpop_input, parse_reason, parse_detail = _unwrap_settlement(
            resumed
        )
        if parse_reason is not None or not permit_jws:
            return _build_missing_settlement_outcome(
                jti=jti,
                request_digest=request_digest,
                parse_reason=parse_reason,
                parse_detail=parse_detail,
                evaluated_at=now_fn(),
                raise_on_deny=raise_on_deny,
            )

        bound_store = _JtiBoundNonceStore(nonce_store, jti)
        result = await verify_agent_permit_v2_async(
            permit_jws,
            policy=policy,
            expected_audience=audience,
            jwks=jwks,
            action=action,
            now_seconds=now_fn,
            webauthn_assertion=webauthn_input,
            dpop=dpop_input,
            nonce_store=bound_store,
            require_registered_nonce=require_registered_nonce,
        )
        return _finalize_consent_result(
            result=result,
            jti=jti,
            request_digest=request_digest,
            key=key,
            pending_lock=pending_lock,
            pending_challenges=pending_challenges,
            raise_on_deny=raise_on_deny,
        )

    return _node
