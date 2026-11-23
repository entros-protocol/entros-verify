"""Unit tests for python/scripts/check_python_licenses.py fail-closed license gate."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_python_licenses.py"


def _load_gate_module() -> object:
    spec = importlib.util.spec_from_file_location("check_python_licenses", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_python_licenses"] = module
    spec.loader.exec_module(module)
    return module


def test_license_gate_passes_clean_permissive_records_and_emits_cyclonedx(tmp_path: Path) -> None:
    mod = _load_gate_module()
    records = [
        {"Name": "entros-verify", "Version": "1.0.0", "License": "MIT"},
        {"Name": "cryptography", "Version": "50.0.2", "License": "Apache-2.0 OR BSD-3-Clause"},
        {"Name": "jcs", "Version": "0.3.0", "License": "Apache-2.0"},
        {"Name": "httpx", "Version": "0.28.1", "License": "BSD License"},
        {"Name": "certifi", "Version": "2026.11.20", "License": "Mozilla Public License 2.0 (MPL 2.0)"},
        {"Name": "typing_extensions", "Version": "4.16.0", "License": "PSF-2.0"},
    ]
    in_file = tmp_path / "licenses.json"
    sbom_file = tmp_path / "sbom.cdx.json"
    in_file.write_text(json.dumps(records), encoding="utf-8")

    rc = mod.main(["--from-json", str(in_file), "--sbom-out", str(sbom_file)])  # type: ignore[attr-defined]
    assert rc == 0
    assert sbom_file.exists()
    sbom = json.loads(sbom_file.read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == len(records)


@pytest.mark.parametrize(
    "bad_license",
    [
        "GPL-3.0-only",
        "GNU General Public License v3 (GPLv3)",
        "AGPL-3.0-or-later",
        "LGPL-2.1-only",
        "CC-BY-NC-4.0",
        "CC-BY-SA-4.0",
        "CPML",
        "UNKNOWN",
        "",
        "Proprietary-Custom-1.0",
    ],
)
def test_license_gate_fails_closed_on_forbidden_or_unknown_licenses(
    tmp_path: Path,
    bad_license: str,
) -> None:
    mod = _load_gate_module()
    records = [
        {"Name": "entros-verify", "Version": "1.0.0", "License": "MIT"},
        {"Name": "bad-wheel", "Version": "0.1.0", "License": bad_license},
    ]
    in_file = tmp_path / "bad-licenses.json"
    in_file.write_text(json.dumps(records), encoding="utf-8")

    rc = mod.main(["--from-json", str(in_file)])  # type: ignore[attr-defined]
    assert rc == 1

    report = mod.audit_license_records(records)  # type: ignore[attr-defined]
    assert not report.ok
    assert len(report.findings) == 1
    assert report.findings[0].package == "bad-wheel"
