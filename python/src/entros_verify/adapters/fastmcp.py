"""FastMCP / MCP tool decorator enforcing AgentPermit v2 human consent.

Supports:
- MCP 2026-07-28 stateless InputRequiredResult (MRTR) with HMAC-SHA256 requestState.
- MCP 2025-11-25 URL-Mode Elicitation (SEP-1036) with opaque approval URLs.
- HTTP 403 WWW-Authenticate insufficient_scope header helper preserving scope union.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import inspect
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode

from pydantic import ValidationError

from entros_verify.canonical import canonicalize_jcs_bytes, hash_action_v2
from entros_verify.errors import CanonicalizationError
from entros_verify.jwks import JwksKeySource
from entros_verify.jws import (
    _parse_json_object_strict,
    b64url_decode_nopad,
    b64url_encode_nopad,
)
from entros_verify.models import (
    MAX_CLOCK_SKEW_SECONDS,
    MAX_TIMESTAMP_SECONDS,
    MIN_TIMESTAMP_SECONDS,
    DpopVerificationInput,
    PolicyV2,
    RefusalCode,
    ScittReceiptResult,
    VerificationResult,
    WebAuthnAssertionInput,
)
from entros_verify.nonce_store import (
    NonceConsumeResult,
    PermitNonceRecord,
    PermitNonceStoreV2,
)
from entros_verify.policy import verify_agent_permit_v2_async
from entros_verify.uri import is_canonical_audience_uri, is_canonical_issuer_uri

McpConsentMode = Literal["mcp_mrtr", "sep_1036"]
STEP_UP_SCOPE = "entros:permit:step_up"
MRTR_STATE_DOMAIN = b"Entros-MCP-MRTR-State-v2\n"
MIN_MRTR_SECRET_LEN = 32

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ZERO_HEX64 = "0" * 64
# RFC 6750 §3.3 scope-token: 1*( %x21 / %x23-5B / %x5D-7E )
_RFC6750_SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")


def _is_non_zero_hex64(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64_RE.match(value)) and value != _ZERO_HEX64


class _JtiBoundNonceStore:
    """Wrap a PermitNonceStoreV2 so consume_once accepts only the expected jti."""

    def __init__(self, inner: PermitNonceStoreV2, expected_jti: str) -> None:
        self._inner = inner
        self._expected_jti = expected_jti

    def register(
        self,
        *,
        jti: str,
        expires_at: int,
        created_at: int,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> Awaitable[None] | None:
        return self._inner.register(
            jti=jti,
            expires_at=expires_at,
            created_at=created_at,
            request_digest=request_digest,
            aud=aud,
            policy_id=policy_id,
        )

    def peek(self, jti: str) -> Awaitable[PermitNonceRecord | None] | PermitNonceRecord | None:
        return self._inner.peek(jti)

    def consume_once(
        self,
        *,
        jti: str,
        now_seconds: int,
        expires_at: int,
        require_registered: bool = False,
        request_digest: str | None = None,
        aud: str | None = None,
        policy_id: str | None = None,
    ) -> Awaitable[NonceConsumeResult] | NonceConsumeResult:
        if not hmac.compare_digest(jti.encode("utf-8"), self._expected_jti.encode("utf-8")):
            return NonceConsumeResult(status="not_found")
        return self._inner.consume_once(
            jti=jti,
            now_seconds=now_seconds,
            expires_at=expires_at,
            require_registered=require_registered,
            request_digest=request_digest,
            aud=aud,
            policy_id=policy_id,
        )


@dataclass(frozen=True)
class RequestStateClaims:
    """Authenticated stateless MCP 2026-07-28 requestState token payload."""

    jti: str
    request_digest: str
    aud: str
    policy_id: str
    iat: int
    exp: int
    v: int = 2


def sign_request_state(claims: RequestStateClaims, secret: bytes) -> str:
    """Sign a stateless HMAC-SHA256 requestState token matching TS and Rust byte-for-byte."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_MRTR_SECRET_LEN:
        raise ValueError(f"request_state_secret must be at least {MIN_MRTR_SECRET_LEN} bytes")
    if claims.v != 2:
        raise ValueError("requestState claims version v must equal 2")
    body: dict[str, object] = {
        "v": 2,
        "jti": claims.jti,
        "request_digest": claims.request_digest,
        "aud": claims.aud,
        "policy_id": claims.policy_id,
        "iat": claims.iat,
        "exp": claims.exp,
    }
    payload_b64 = b64url_encode_nopad(canonicalize_jcs_bytes(body, field="request_state"))
    mac = hmac.new(
        bytes(secret),
        MRTR_STATE_DOMAIN + payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{payload_b64}.{b64url_encode_nopad(mac)}"


def verify_request_state(
    token: str,
    secret: bytes,
    *,
    now_seconds: int,
) -> RequestStateClaims | None:
    """Verify HMAC-SHA256 requestState authenticity, claim grammar, skew, and expiry."""
    if (
        not isinstance(token, str)
        or token.count(".") != 1
        or not isinstance(secret, (bytes, bytearray))
        or len(secret) < MIN_MRTR_SECRET_LEN
    ):
        return None
    payload_b64, mac_b64 = token.split(".", 1)
    if not payload_b64 or not mac_b64:
        return None
    try:
        provided_mac = b64url_decode_nopad(mac_b64)
        if len(provided_mac) != 32:
            return None
        expected_mac = hmac.new(
            bytes(secret),
            MRTR_STATE_DOMAIN + payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(provided_mac, expected_mac):
            return None
        parsed = _parse_json_object_strict(b64url_decode_nopad(payload_b64))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None

    version = parsed.get("v")
    jti = parsed.get("jti")
    request_digest = parsed.get("request_digest")
    aud = parsed.get("aud")
    policy_id = parsed.get("policy_id")
    iat = parsed.get("iat")
    exp = parsed.get("exp")
    if (
        version != 2
        or isinstance(version, bool)
        or not _is_non_zero_hex64(jti)
        or not _is_non_zero_hex64(request_digest)
        or not isinstance(aud, str)
        or not is_canonical_audience_uri(aud)
        or not isinstance(policy_id, str)
        or not policy_id
        or not isinstance(iat, int)
        or isinstance(iat, bool)
        or not isinstance(exp, int)
        or isinstance(exp, bool)
        or not (MIN_TIMESTAMP_SECONDS <= iat <= MAX_TIMESTAMP_SECONDS)
        or not (MIN_TIMESTAMP_SECONDS <= exp <= MAX_TIMESTAMP_SECONDS)
    ):
        return None
    if iat > now_seconds + MAX_CLOCK_SKEW_SECONDS:
        return None
    if now_seconds >= exp:
        return None
    assert isinstance(jti, str) and isinstance(request_digest, str)
    return RequestStateClaims(
        v=2,
        jti=jti,
        request_digest=request_digest,
        aud=aud,
        policy_id=policy_id,
        iat=iat,
        exp=exp,
    )


def _parse_and_validate_scopes(raw: str) -> list[str]:
    if not isinstance(raw, str):
        raise ValueError("Scope entries must be strings")
    tokens: list[str] = []
    for token in raw.split(" "):
        if not token:
            continue
        if not _RFC6750_SCOPE_TOKEN_RE.match(token):
            raise ValueError(f"Invalid RFC 6750 scope token: {token!r}")
        tokens.append(token)
    return tokens


def format_insufficient_scope_header(existing_scopes: str | list[str] | tuple[str, ...] = ()) -> str:
    """Build an RFC 6750 / MCP OAuth 403 WWW-Authenticate header preserving scope union."""
    scopes: list[str] = []
    seen: set[str] = set()
    raw_items: tuple[str, ...] | list[str] = (
        [existing_scopes] if isinstance(existing_scopes, str) else existing_scopes
    )
    for item in raw_items:
        for token in _parse_and_validate_scopes(item):
            if token not in seen:
                seen.add(token)
                scopes.append(token)
    if STEP_UP_SCOPE not in seen:
        scopes.append(STEP_UP_SCOPE)
    scope_str = " ".join(scopes)
    return f'Bearer error="insufficient_scope", scope="{scope_str}"'


def _extract_permit_from_entry(entry: Mapping[str, object]) -> str | None:
    for key in ("permit_jws", "permit", "content", "value"):
        val = entry.get(key)
        if isinstance(val, str) and val.count(".") == 2:
            return val
        if isinstance(val, Mapping):
            nested = val.get("permit_jws") or val.get("permit")
            if isinstance(nested, str) and nested.count(".") == 2:
                return nested
    return None


def _extract_permit_from_retry(
    *,
    input_responses: object,
    explicit_permit: object,
    expected_elicitation_id: str | None = None,
) -> str | None:
    if isinstance(explicit_permit, str) and explicit_permit:
        return explicit_permit
    if isinstance(input_responses, Mapping):
        entry_elicitation = input_responses.get("elicitationId") or input_responses.get(
            "elicitation_id"
        )
        if (
            expected_elicitation_id is not None
            and isinstance(entry_elicitation, str)
            and entry_elicitation
            and entry_elicitation != expected_elicitation_id
        ):
            return None
        for key in ("permit_jws", "permit", "entros_permit"):
            val = input_responses.get(key)
            if isinstance(val, str) and val:
                return val
    if isinstance(input_responses, list):
        untagged_fallback: str | None = None
        for entry in input_responses:
            if not isinstance(entry, Mapping):
                continue
            entry_elicitation = entry.get("elicitationId") or entry.get("elicitation_id")
            if expected_elicitation_id is not None and isinstance(entry_elicitation, str) and entry_elicitation:
                if entry_elicitation == expected_elicitation_id:
                    matched = _extract_permit_from_entry(entry)
                    if matched is not None:
                        return matched
                continue
            if untagged_fallback is None:
                untagged_fallback = _extract_permit_from_entry(entry)
        return untagged_fallback
    return None


def require_human_consent(
    *,
    policy: PolicyV2,
    audience: str,
    nonce_store: PermitNonceStoreV2,
    jwks: JwksKeySource | Mapping[str, object],
    server: str = "fastmcp-server",
    tool_name: str | None = None,
    protocol_mode: McpConsentMode = "mcp_mrtr",
    approval_base_url: str = "https://approve.entros.io/consent",
    request_state_secret: bytes | None = None,
    challenge_ttl_seconds: int = 300,
    require_registered_nonce: bool = True,
    on_scitt_receipt: Callable[[ScittReceiptResult], None] | None = None,
    jti_generator: Callable[[], str] | None = None,
    clock: Callable[[], int] | None = None,
) -> Callable[[Callable[..., object]], Callable[..., Awaitable[object]]]:
    """Decorate a FastMCP / MCP tool handler with AgentPermit v2 verification.

    Round 1 (missing permit): emits MCP 2026-07-28 InputRequiredResult (MRTR) or
    MCP 2025-11-25 SEP-1036 URL-Mode Elicitation challenge and does not run the tool.
    Round 2 (with permit): in MRTR mode, requires and verifies HMAC requestState,
    recomputes RFC 8785 request_digest from live arguments, runs all prechecks,
    consumes jti atomically, invokes on_scitt_receipt if verified, and runs the tool once.
    """
    if challenge_ttl_seconds < 30 or challenge_ttl_seconds > 900:
        raise ValueError("challenge_ttl_seconds must be within 30..900")
    if not is_canonical_audience_uri(audience):
        raise ValueError("audience must be a canonical RFC 8707 audience URI")
    if not is_canonical_issuer_uri(approval_base_url):
        raise ValueError("approval_base_url must be a canonical HTTPS or 127.0.0.1 URI")
    if request_state_secret is not None and len(request_state_secret) < MIN_MRTR_SECRET_LEN:
        raise ValueError(f"request_state_secret must be at least {MIN_MRTR_SECRET_LEN} bytes")

    effective_ttl = min(challenge_ttl_seconds, policy.max_permit_lifetime_seconds)
    hmac_secret = (
        bytes(request_state_secret)
        if request_state_secret is not None
        else secrets.token_bytes(32)
    )
    gen_jti = jti_generator or (lambda: secrets.token_hex(32))
    now_fn = clock or (lambda: int(time.time()))

    def _decorator(fn: Callable[..., object]) -> Callable[..., Awaitable[object]]:
        resolved_tool = tool_name or getattr(fn, "__name__", "mcp_tool")
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def _wrapper(*args: object, **kwargs: object) -> object:
            call_kwargs = dict(kwargs)
            request_state_raw = call_kwargs.pop("requestState", None)
            if request_state_raw is None:
                request_state_raw = call_kwargs.pop("request_state", None)
            input_responses = call_kwargs.pop("inputResponses", None)
            if input_responses is None:
                input_responses = call_kwargs.pop("input_responses", None)
            explicit_permit = call_kwargs.pop("entros_permit", None)
            if explicit_permit is None:
                explicit_permit = call_kwargs.pop("permit_jws", None)
            webauthn_raw = call_kwargs.pop("webauthn_assertion", None)
            dpop_raw = call_kwargs.pop("dpop", None)

            bound = sig.bind_partial(*args, **call_kwargs)
            bound.apply_defaults()
            tool_arguments: dict[str, object] = dict(bound.arguments)
            canonical_action: dict[str, object] = {
                "kind": "mcp.tool_call",
                "server": server,
                "tool": resolved_tool,
                "arguments": tool_arguments,
            }
            try:
                request_digest = hash_action_v2(canonical_action)
            except CanonicalizationError as exc:
                return _denial_response(
                    RefusalCode.REQUEST_DIGEST_MISMATCH,
                    f"Tool action failed canonicalization: {exc}",
                )
            now = now_fn()

            effective_nonce_store: PermitNonceStoreV2 = nonce_store
            expected_elicitation_id: str | None = None
            has_mrtr_state = protocol_mode == "mcp_mrtr" and request_state_raw is not None

            if has_mrtr_state:
                if not isinstance(request_state_raw, str):
                    return _denial_response(RefusalCode.INVALID_PERMIT, "Malformed requestState")
                claims = verify_request_state(request_state_raw, hmac_secret, now_seconds=now)
                if claims is None:
                    return _denial_response(
                        RefusalCode.INVALID_SIGNATURE,
                        "requestState HMAC verification failed or expired",
                    )
                if not hmac.compare_digest(
                    claims.request_digest.encode("ascii"),
                    request_digest.encode("ascii"),
                ):
                    return _denial_response(
                        RefusalCode.REQUEST_DIGEST_MISMATCH,
                        "Retried tool arguments do not match requestState digest",
                    )
                if claims.aud != audience:
                    return _denial_response(
                        RefusalCode.AUDIENCE_MISMATCH,
                        "requestState audience mismatch",
                    )
                if claims.policy_id != policy.policy_id:
                    return _denial_response(
                        RefusalCode.POLICY_MISMATCH,
                        "requestState policy_id mismatch",
                    )
                expected_elicitation_id = claims.jti
                effective_nonce_store = _JtiBoundNonceStore(nonce_store, claims.jti)

            permit_jws = _extract_permit_from_retry(
                input_responses=input_responses,
                explicit_permit=explicit_permit,
                expected_elicitation_id=expected_elicitation_id,
            )

            if permit_jws is None:
                if has_mrtr_state:
                    return _denial_response(
                        RefusalCode.INVALID_PERMIT,
                        "Missing permit_jws for requested elicitationId",
                    )

                jti = gen_jti()
                expires_at = now + effective_ttl
                if require_registered_nonce:
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

                sep = "&" if "?" in approval_base_url else "?"
                approval_url = f"{approval_base_url}{sep}{urlencode({'jti': jti})}"
                summary = f"Human consent required for {server}:{resolved_tool}"

                if protocol_mode == "sep_1036":
                    return {
                        "method": "elicitation/create",
                        "params": {
                            "mode": "url",
                            "elicitationId": jti,
                            "url": approval_url,
                            "message": summary,
                            "requestDigest": request_digest,
                            "policyId": policy.policy_id,
                            "expiresAt": expires_at,
                        },
                    }

                state_token = sign_request_state(
                    RequestStateClaims(
                        v=2,
                        jti=jti,
                        request_digest=request_digest,
                        aud=audience,
                        policy_id=policy.policy_id,
                        iat=now,
                        exp=expires_at,
                    ),
                    hmac_secret,
                )
                return {
                    "resultType": "input_required",
                    "inputRequests": [
                        {
                            "mode": "url",
                            "elicitationId": jti,
                            "url": approval_url,
                            "message": summary,
                            "cacheable": False,
                        }
                    ],
                    "requestState": state_token,
                }

            # Round 2: In MRTR mode, requestState is mandatory so callers cannot bypass jti binding.
            if protocol_mode == "mcp_mrtr" and not has_mrtr_state:
                return _denial_response(
                    RefusalCode.INVALID_PERMIT,
                    "Missing required requestState for MCP MRTR retry",
                )

            webauthn_input: WebAuthnAssertionInput | None = None
            if isinstance(webauthn_raw, WebAuthnAssertionInput):
                webauthn_input = webauthn_raw
            elif isinstance(webauthn_raw, Mapping):
                try:
                    webauthn_input = WebAuthnAssertionInput.model_validate(webauthn_raw)
                except ValidationError:
                    return _denial_response(
                        RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                        "Malformed webauthn_assertion payload",
                    )
            elif webauthn_raw is not None:
                return _denial_response(
                    RefusalCode.WEBAUTHN_ASSERTION_INVALID,
                    "Malformed webauthn_assertion payload",
                )

            dpop_input: DpopVerificationInput | None = None
            if isinstance(dpop_raw, DpopVerificationInput):
                dpop_input = dpop_raw
            elif isinstance(dpop_raw, Mapping):
                try:
                    dpop_input = DpopVerificationInput.model_validate(dpop_raw)
                except ValidationError:
                    return _denial_response(
                        RefusalCode.DPOP_PROOF_INVALID,
                        "Malformed dpop verification payload",
                    )
            elif dpop_raw is not None:
                return _denial_response(
                    RefusalCode.DPOP_PROOF_INVALID,
                    "Malformed dpop verification payload",
                )

            result: VerificationResult = await verify_agent_permit_v2_async(
                permit_jws,
                policy=policy,
                expected_audience=audience,
                jwks=jwks,
                action=canonical_action,
                now_seconds=now_fn,
                webauthn_assertion=webauthn_input,
                dpop=dpop_input,
                nonce_store=effective_nonce_store,
                require_registered_nonce=require_registered_nonce,
            )
            if not result.ok:
                return _denial_response(
                    result.reason or RefusalCode.INVALID_PERMIT,
                    result.detail or "AgentPermit v2 verification failed",
                    decision=result.decision,
                )

            if result.scitt_receipt is not None and on_scitt_receipt is not None:
                on_scitt_receipt(result.scitt_receipt)

            output = fn(*args, **call_kwargs)
            if inspect.isawaitable(output):
                return await output
            return output

        return _wrapper

    return _decorator


def _denial_response(
    reason: RefusalCode,
    detail: str,
    *,
    decision: str = "deny",
) -> dict[str, object]:
    return {
        "isError": True,
        "decision": decision,
        "reason": reason.value,
        "detail": detail,
    }
