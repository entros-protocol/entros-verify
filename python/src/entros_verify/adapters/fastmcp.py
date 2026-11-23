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
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlencode

from entros_verify.canonical import hash_action_v2
from entros_verify.jwks import JwksKeySource
from entros_verify.jws import b64url_decode_nopad, b64url_encode_nopad
from entros_verify.models import (
    DpopVerificationInput,
    PolicyV2,
    RefusalCode,
    ScittReceiptResult,
    VerificationResult,
    WebAuthnAssertionInput,
)
from entros_verify.nonce_store import PermitNonceStoreV2
from entros_verify.policy import verify_agent_permit_v2_async

McpConsentMode = Literal["mcp_mrtr", "sep_1036"]
STEP_UP_SCOPE = "entros:permit:step_up"


@dataclass(frozen=True)
class RequestStateClaims:
    """Authenticated stateless MCP 2026-07-28 requestState token payload."""

    jti: str
    request_digest: str
    aud: str
    policy_id: str
    iat: int
    exp: int


def sign_request_state(claims: RequestStateClaims, secret: bytes) -> str:
    """Sign a stateless HMAC-SHA256 requestState token."""
    if not secret:
        raise ValueError("request_state_secret must be non-empty")
    body = {
        "jti": claims.jti,
        "request_digest": claims.request_digest,
        "aud": claims.aud,
        "policy_id": claims.policy_id,
        "iat": claims.iat,
        "exp": claims.exp,
    }
    payload_b64 = b64url_encode_nopad(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    mac = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{b64url_encode_nopad(mac)}"


def verify_request_state(
    token: str,
    secret: bytes,
    *,
    now_seconds: int,
) -> RequestStateClaims | None:
    """Verify HMAC-SHA256 requestState authenticity and expiry."""
    if not isinstance(token, str) or token.count(".") != 1 or not secret:
        return None
    payload_b64, mac_b64 = token.split(".", 1)
    try:
        provided_mac = b64url_decode_nopad(mac_b64)
        expected_mac = hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(provided_mac, expected_mac):
            return None
        parsed: object = json.loads(b64url_decode_nopad(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(parsed, dict):
        return None
    jti = parsed.get("jti")
    request_digest = parsed.get("request_digest")
    aud = parsed.get("aud")
    policy_id = parsed.get("policy_id")
    iat = parsed.get("iat")
    exp = parsed.get("exp")
    if (
        not isinstance(jti, str)
        or not isinstance(request_digest, str)
        or not isinstance(aud, str)
        or not isinstance(policy_id, str)
        or not isinstance(iat, int)
        or isinstance(iat, bool)
        or not isinstance(exp, int)
        or isinstance(exp, bool)
    ):
        return None
    if now_seconds >= exp:
        return None
    return RequestStateClaims(
        jti=jti,
        request_digest=request_digest,
        aud=aud,
        policy_id=policy_id,
        iat=iat,
        exp=exp,
    )


def format_insufficient_scope_header(existing_scopes: str | list[str] | tuple[str, ...] = ()) -> str:
    """Build an RFC 6750 / MCP OAuth 403 WWW-Authenticate header preserving scope union."""
    scopes: list[str] = []
    if isinstance(existing_scopes, str):
        scopes.extend(s for s in existing_scopes.split() if s)
    else:
        for item in existing_scopes:
            scopes.extend(s for s in item.split() if s)
    if STEP_UP_SCOPE not in scopes:
        scopes.append(STEP_UP_SCOPE)
    scope_str = " ".join(scopes)
    return f'Bearer error="insufficient_scope", scope="{scope_str}"'


def _extract_permit_from_retry(
    *,
    input_responses: object,
    explicit_permit: object,
) -> str | None:
    if isinstance(explicit_permit, str) and explicit_permit:
        return explicit_permit
    if isinstance(input_responses, Mapping):
        for key in ("permit_jws", "permit", "entros_permit"):
            val = input_responses.get(key)
            if isinstance(val, str) and val:
                return val
    if isinstance(input_responses, list):
        for entry in input_responses:
            if isinstance(entry, Mapping):
                for key in ("permit_jws", "permit", "content", "value"):
                    val = entry.get(key)
                    if isinstance(val, str) and val.count(".") == 2:
                        return val
                    if isinstance(val, Mapping):
                        nested = val.get("permit_jws") or val.get("permit")
                        if isinstance(nested, str) and nested.count(".") == 2:
                            return nested
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
    Round 2 (with permit and requestState): verifies requestState HMAC, recomputes
    RFC 8785 request_digest from live arguments, runs all prechecks, consumes jti
    atomically, invokes on_scitt_receipt if verified, and runs the wrapped tool once.
    """
    if challenge_ttl_seconds < 30 or challenge_ttl_seconds > 900:
        raise ValueError("challenge_ttl_seconds must be within 30..900")

    hmac_secret = request_state_secret if request_state_secret is not None else secrets.token_bytes(32)
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
            mode_override = call_kwargs.pop("mcp_consent_mode", None)
            active_mode: McpConsentMode = (
                mode_override if mode_override in ("mcp_mrtr", "sep_1036") else protocol_mode
            )

            bound = sig.bind_partial(*args, **call_kwargs)
            bound.apply_defaults()
            tool_arguments: dict[str, object] = dict(bound.arguments)
            canonical_action: dict[str, object] = {
                "kind": "mcp.tool_call",
                "server": server,
                "tool": resolved_tool,
                "arguments": tool_arguments,
            }
            request_digest = hash_action_v2(canonical_action)
            now = now_fn()

            permit_jws = _extract_permit_from_retry(
                input_responses=input_responses,
                explicit_permit=explicit_permit,
            )

            if permit_jws is None:
                jti = gen_jti()
                expires_at = now + challenge_ttl_seconds
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

                if active_mode == "sep_1036":
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

            # Round 2: If requestState was supplied (MRTR), verify its HMAC and action binding.
            if active_mode == "mcp_mrtr" and request_state_raw is not None:
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

            webauthn_input = (
                webauthn_raw
                if isinstance(webauthn_raw, WebAuthnAssertionInput)
                else (
                    WebAuthnAssertionInput.model_validate(webauthn_raw)
                    if isinstance(webauthn_raw, Mapping)
                    else None
                )
            )
            dpop_input = (
                dpop_raw
                if isinstance(dpop_raw, DpopVerificationInput)
                else (
                    DpopVerificationInput.model_validate(dpop_raw)
                    if isinstance(dpop_raw, Mapping)
                    else None
                )
            )

            result: VerificationResult = await verify_agent_permit_v2_async(
                permit_jws,
                policy=policy,
                expected_audience=audience,
                jwks=jwks,
                action=canonical_action,
                now_seconds=now,
                webauthn_assertion=webauthn_input,
                dpop=dpop_input,
                nonce_store=nonce_store,
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
