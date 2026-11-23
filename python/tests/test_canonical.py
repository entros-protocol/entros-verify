"""Unit tests for RFC 8785 JCS canonicalization and action digest validation."""

from __future__ import annotations

import math

import pytest

from entros_verify import (
    CanonicalAction,
    CanonicalizationError,
    build_canonical_action,
    canonicalize_action_v2,
    canonicalize_jcs,
    hash_action_v2,
)


def test_jcs_depth_boundary_32_accepted_33_rejected() -> None:
    # Root starts at depth 0, so 32 nested dicts reach depth 32 at leaf value.
    ok_obj: dict[str, object] = {"leaf": 1}
    for _ in range(31):
        ok_obj = {"k": ok_obj}
    serialized = canonicalize_jcs(ok_obj)
    assert serialized.endswith('{"leaf":1}' + "}" * 31)

    bad_obj: dict[str, object] = {"k": ok_obj}
    with pytest.raises(CanonicalizationError, match="depth"):
        canonicalize_jcs(bad_obj)


def test_jcs_rejects_cycles_and_non_json_types() -> None:
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    with pytest.raises(CanonicalizationError, match="Circular"):
        canonicalize_jcs(cyclic_list)

    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict
    with pytest.raises(CanonicalizationError, match="Circular"):
        canonicalize_jcs(cyclic_dict)

    with pytest.raises(CanonicalizationError, match="Unsupported"):
        canonicalize_jcs({"b": b"bytes"})

    with pytest.raises(CanonicalizationError, match="strings"):
        canonicalize_jcs({1: "int-key"})


def test_jcs_rejects_surrogates_in_keys_and_values() -> None:
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonicalize_jcs({"\ud800": 1})
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonicalize_jcs({"k": "\udfff"})


def test_jcs_rejects_non_finite_floats() -> None:
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(CanonicalizationError, match="finite"):
            canonicalize_jcs({"x": bad})


def test_action_model_and_builder_parity() -> None:
    model = CanonicalAction(
        kind="voice.tool_call",
        server="treasury-mcp",
        tool="transfer_funds",
        arguments={"amount": 250, "currency": "USD"},
    )
    built = build_canonical_action(
        kind="voice.tool_call",
        server="treasury-mcp",
        tool="transfer_funds",
        arguments={"currency": "USD", "amount": 250},
    )
    assert canonicalize_action_v2(model) == canonicalize_action_v2(built)
    assert hash_action_v2(model) == hash_action_v2(built)

    with pytest.raises(CanonicalizationError, match="Unexpected"):
        hash_action_v2(
            {
                "kind": "mcp.tool_call",
                "server": "s",
                "tool": "t",
                "arguments": {},
                "extra": 1,
            }
        )
