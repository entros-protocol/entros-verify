"""Deterministic RFC 8785 JCS canonicalization and request_digest hashing.

Always delegates JSON Canonicalization Scheme serialization to `jcs==0.3.0`
so object keys sort by UTF-16 code units and IEEE-754 floats follow ECMA-262
Number::toString. Never uses stdlib `json.dumps(..., sort_keys=True)`.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping

import jcs

from entros_verify.errors import CanonicalizationError
from entros_verify.models import CanonicalAction, JsonObject

PERMIT_V2_DOMAIN_PREFIX = b"Entros-Agent-Permit-v2\n"
MAX_CANONICAL_DEPTH = 32
MAX_IDENTIFIER_LENGTH = 128
ALLOWED_ACTION_KINDS = frozenset({"mcp.tool_call", "voice.tool_call", "http.action"})


def _contains_lone_surrogate(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            return True
    return False


def _is_printable_ascii(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code > 0x7E:
            return False
    return True


def _validate_identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError(field, f"{field} must be a string")
    if len(value) < 1 or len(value) > MAX_IDENTIFIER_LENGTH:
        raise CanonicalizationError(field, f"{field} length must be between 1 and {MAX_IDENTIFIER_LENGTH}")
    if value != value.strip():
        raise CanonicalizationError(field, f"{field} must not have leading or trailing whitespace")
    if not _is_printable_ascii(value):
        raise CanonicalizationError(field, f"{field} must contain only printable ASCII characters")
    return value


def _validate_json_value(value: object, depth: int, ancestors: set[int], field: str) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError(field, f"JSON nesting exceeds maximum depth of {MAX_CANONICAL_DEPTH}")

    if value is None or isinstance(value, bool):
        return

    if isinstance(value, int):
        return

    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(field, "JSON numbers must be finite (NaN and Infinity are forbidden)")
        return

    if isinstance(value, str):
        if _contains_lone_surrogate(value):
            raise CanonicalizationError(field, "JSON strings must not contain lone UTF-16 surrogates")
        return

    if isinstance(value, list):
        obj_id = id(value)
        if obj_id in ancestors:
            raise CanonicalizationError(field, "Circular reference detected in JSON array")
        ancestors.add(obj_id)
        try:
            for item in value:
                _validate_json_value(item, depth + 1, ancestors, field)
        finally:
            ancestors.remove(obj_id)
        return

    if isinstance(value, dict):
        obj_id = id(value)
        if obj_id in ancestors:
            raise CanonicalizationError(field, "Circular reference detected in JSON object")
        ancestors.add(obj_id)
        try:
            for key, entry in value.items():
                if not isinstance(key, str):
                    raise CanonicalizationError(field, "JSON object keys must be strings")
                if _contains_lone_surrogate(key):
                    raise CanonicalizationError(field, "JSON object keys must not contain lone UTF-16 surrogates")
                _validate_json_value(entry, depth + 1, ancestors, field)
        finally:
            ancestors.remove(obj_id)
        return

    raise CanonicalizationError(field, f"Unsupported JSON value type: {type(value).__name__}")


def canonicalize_jcs_bytes(value: object, *, field: str = "value") -> bytes:
    """Validate and serialize an arbitrary JSON value to UTF-8 RFC 8785 JCS bytes."""
    _validate_json_value(value, 0, set(), field)
    try:
        return jcs.canonicalize(value, utf8=True)
    except Exception as exc:
        raise CanonicalizationError(field, f"RFC 8785 canonicalization failed: {exc}") from exc


def canonicalize_jcs(value: object, *, field: str = "value") -> str:
    """Validate and serialize an arbitrary JSON value to an RFC 8785 JCS string."""
    return canonicalize_jcs_bytes(value, field=field).decode("utf-8")


def _build_action_dict(action: CanonicalAction | Mapping[str, object]) -> dict[str, object]:
    if isinstance(action, CanonicalAction):
        raw: Mapping[str, object] = {
            "kind": action.kind,
            "server": action.server,
            "tool": action.tool,
            "arguments": action.arguments,
            **({"rar_details": action.rar_details} if action.rar_details is not None else {}),
        }
    elif isinstance(action, Mapping):
        raw = action
    else:
        raise CanonicalizationError("action", "Action must be a mapping or CanonicalAction")

    allowed_keys = {"kind", "server", "tool", "arguments", "rar_details"}
    extra_keys = set(raw.keys()) - allowed_keys
    if extra_keys:
        raise CanonicalizationError("action", f"Unexpected action fields: {sorted(extra_keys)}")

    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in ALLOWED_ACTION_KINDS:
        raise CanonicalizationError("kind", "kind must be 'mcp.tool_call', 'voice.tool_call', or 'http.action'")

    server = _validate_identifier(raw.get("server"), "server")
    tool = _validate_identifier(raw.get("tool"), "tool")

    arguments = raw.get("arguments")
    if not isinstance(arguments, dict):
        raise CanonicalizationError("arguments", "arguments must be a plain JSON object")

    payload: dict[str, object] = {
        "kind": kind,
        "server": server,
        "tool": tool,
        "arguments": arguments,
    }

    if "rar_details" in raw:
        rar_details = raw["rar_details"]
        if rar_details is None:
            raise CanonicalizationError(
                "rar_details",
                "Omit rar_details when unused rather than passing null",
            )
        if not isinstance(rar_details, list) or not all(isinstance(item, dict) for item in rar_details):
            raise CanonicalizationError("rar_details", "rar_details must be a list of JSON objects")
        payload["rar_details"] = rar_details

    return payload


def canonicalize_action_v2(action: CanonicalAction | Mapping[str, object]) -> str:
    """Validate and canonicalize an AgentPermit v2 action object using RFC 8785 JCS."""
    payload = _build_action_dict(action)
    return canonicalize_jcs(payload, field="action")


def hash_action_v2(action: CanonicalAction | Mapping[str, object]) -> str:
    """Compute lowercase 64-hex SHA-256('Entros-Agent-Permit-v2\\n' || UTF8(JCS(action)))."""
    payload = _build_action_dict(action)
    jcs_bytes = canonicalize_jcs_bytes(payload, field="action")
    return hashlib.sha256(PERMIT_V2_DOMAIN_PREFIX + jcs_bytes).hexdigest()


def build_canonical_action(
    *,
    kind: str,
    server: str,
    tool: str,
    arguments: JsonObject,
    rar_details: list[JsonObject] | None = None,
) -> dict[str, object]:
    """Construct and validate a canonical action dictionary ready for hashing."""
    raw: dict[str, object] = {
        "kind": kind,
        "server": server,
        "tool": tool,
        "arguments": arguments,
    }
    if rar_details is not None:
        raw["rar_details"] = rar_details
    validated = _build_action_dict(raw)
    _validate_json_value(validated, 0, set(), "action")
    return validated
