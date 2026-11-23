#!/usr/bin/env python3
"""Fail-closed Python dependency license audit and CycloneDX SBOM generator.

Runs `pip-licenses` on the installed environment, emits a CycloneDX 1.5 JSON SBOM,
and fails closed on any GPL, AGPL, LGPL, CC-BY-NC, CC-BY-SA, CPML, UNKNOWN, or
non-allowlisted license across all resolved runtime and transitive dependencies.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

FORBIDDEN_LICENSE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("copyleft_gpl", re.compile(r"(^|[^A-Za-z0-9])(A|L)?GPL([^A-Za-z0-9]|$)", re.IGNORECASE)),
    (
        "gnu_copyleft_text",
        re.compile(
            r"GNU\s+(AFFERO\s+|LESSER\s+|LIBRARY\s+)?GENERAL\s+PUBLIC\s+LICENSE",
            re.IGNORECASE,
        ),
    ),
    ("cc_by_nc", re.compile(r"CC[-_\s]?BY[-_\s]?NC|NonCommercial", re.IGNORECASE)),
    ("cc_by_sa", re.compile(r"CC[-_\s]?BY[-_\s]?SA|ShareAlike", re.IGNORECASE)),
    ("cpml", re.compile(r"(^|[^A-Za-z0-9])CPML([^A-Za-z0-9]|$)", re.IGNORECASE)),
    ("anti_compete", re.compile(r"(^|[^A-Za-z0-9])(SSPL|BUSL|BSL-1\.1|ELv2)([^A-Za-z0-9]|$)", re.IGNORECASE)),
    ("unknown", re.compile(r"^(UNKNOWN|UNLICENSED|NONE|PROPRIETARY)$", re.IGNORECASE)),
)

# Permissive commercial licenses plus PSF-2.0 (Python standard typing backports)
# and MPL-2.0 (Mozilla CA root bundle certifi and pathspec).
ALLOWED_LICENSE_TOKENS: frozenset[str] = frozenset(
    {
        "MIT",
        "MIT-0",
        "MIT LICENSE",
        "THE MIT LICENSE (MIT)",
        "APACHE-2.0",
        "APACHE 2.0",
        "APACHE SOFTWARE LICENSE",
        "APACHE LICENSE 2.0",
        "APACHE LICENSE, VERSION 2.0",
        "BSD",
        "BSD LICENSE",
        "BSD-2-CLAUSE",
        "BSD-3-CLAUSE",
        "NEW BSD LICENSE",
        "MODIFIED BSD LICENSE",
        "3-CLAUSE BSD LICENSE",
        "2-CLAUSE BSD LICENSE",
        "ISC",
        "ISC LICENSE",
        "ISC LICENSE (ISCL)",
        "ZLIB",
        "PSF-2.0",
        "PYTHON SOFTWARE FOUNDATION LICENSE",
        "MPL-2.0",
        "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)",
        "MOZILLA PUBLIC LICENSE 2.0",
        "0BSD",
        "UNLICENSE",
    }
)


@dataclass(frozen=True)
class LicenseAuditFinding:
    """Single license policy violation found during audit."""

    package: str
    version: str
    license_expr: str
    reason: str


@dataclass(frozen=True)
class LicenseAuditReport:
    """Complete result of auditing installed Python package licenses."""

    ok: bool
    checked_count: int
    findings: tuple[LicenseAuditFinding, ...]
    sbom: dict[str, object]


def _normalize_token(token: str) -> str:
    cleaned = token.strip()
    while cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1].strip()
    return re.sub(r"\s+", " ", cleaned).upper()


def evaluate_license_expression(license_expr: object) -> tuple[bool, str | None]:
    """Evaluate a package license string strictly; fail closed on forbidden or unknown licenses."""
    if not isinstance(license_expr, str):
        return False, "missing_or_non_string_license"
    trimmed = license_expr.strip()
    if not trimmed:
        return False, "empty_license"

    # First check explicit denylist across the entire raw expression.
    for code, pattern in FORBIDDEN_LICENSE_PATTERNS:
        if pattern.search(trimmed):
            return False, f"forbidden_license:{code}:{trimmed}"

    # Split dual-license OR clauses: package is allowed if at least one OR branch is wholly allowed.
    or_branches = re.split(r"\s+OR\s+", trimmed, flags=re.IGNORECASE)
    for branch in or_branches:
        # pip-licenses joins multi-license declarations with ";" or "AND".
        and_parts = re.split(r"\s+AND\s+|;", branch, flags=re.IGNORECASE)
        normalized_parts = [_normalize_token(part) for part in and_parts if part.strip()]
        if not normalized_parts:
            continue
        if all(part in ALLOWED_LICENSE_TOKENS for part in normalized_parts):
            return True, None

    return False, f"license_not_in_allowlist:{trimmed}"


def build_cyclonedx_sbom(records: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Build a CycloneDX 1.5 JSON SBOM document from pip-licenses records."""
    components: list[dict[str, object]] = []
    for rec in sorted(records, key=lambda r: str(r.get("Name", "")).lower()):
        name = str(rec.get("Name", "")).strip()
        version = str(rec.get("Version", "")).strip()
        lic = str(rec.get("License", "UNKNOWN")).strip() or "UNKNOWN"
        purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": [{"license": {"name": lic}}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "library",
                "name": "entros-verify",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            },
        },
        "components": components,
    }


def audit_license_records(records: Iterable[Mapping[str, object]]) -> LicenseAuditReport:
    """Audit pip-licenses JSON records and construct a CycloneDX SBOM."""
    record_list = list(records)
    findings: list[LicenseAuditFinding] = []

    for rec in record_list:
        name = str(rec.get("Name", "<unnamed>"))
        version = str(rec.get("Version", "unknown"))
        lic = rec.get("License")
        allowed, reason = evaluate_license_expression(lic)
        if not allowed:
            findings.append(
                LicenseAuditFinding(
                    package=name,
                    version=version,
                    license_expr=str(lic),
                    reason=reason or "disallowed_license",
                )
            )

    sbom = build_cyclonedx_sbom(record_list)
    return LicenseAuditReport(
        ok=len(findings) == 0,
        checked_count=len(record_list),
        findings=tuple(findings),
        sbom=sbom,
    )


def collect_pip_licenses(
    *,
    python_executable: str | None = None,
    ignore_packages: list[str] | None = None,
) -> list[dict[str, object]]:
    """Invoke pip-licenses in the active Python environment and return parsed JSON records."""
    exe = python_executable or sys.executable
    cmd = [
        exe,
        "-m",
        "piplicenses",
        "--format=json",
        "--from=mixed",
        "--with-system",
    ]
    if ignore_packages:
        cmd.append("--ignore-packages")
        cmd.extend(ignore_packages)
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"pip-licenses failed with exit code {proc.returncode}: {proc.stderr.strip()}"
        )
    parsed: object = json.loads(proc.stdout)
    if not isinstance(parsed, list):
        raise RuntimeError("pip-licenses output was not a JSON array")
    return [dict(item) for item in parsed if isinstance(item, Mapping)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit installed Python dependency licenses and emit a CycloneDX SBOM."
    )
    parser.add_argument(
        "--sbom-out",
        type=Path,
        default=None,
        help="Optional path to write the CycloneDX 1.5 JSON SBOM.",
    )
    parser.add_argument(
        "--print-sbom",
        action="store_true",
        help="Print the generated CycloneDX JSON SBOM to stdout.",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        default=None,
        help="Audit pre-exported pip-licenses JSON instead of invoking pip-licenses.",
    )
    parser.add_argument(
        "--ignore-packages",
        nargs="*",
        default=[],
        help="Optional package names to exclude from pip-licenses inspection.",
    )
    args = parser.parse_args(argv)

    if args.from_json is not None:
        raw: object = json.loads(args.from_json.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            print("License gate FAILED: input JSON must be an array", file=sys.stderr)
            return 1
        records = [dict(item) for item in raw if isinstance(item, Mapping)]
    else:
        records = collect_pip_licenses(ignore_packages=list(args.ignore_packages))

    report = audit_license_records(records)

    if args.sbom_out is not None:
        args.sbom_out.parent.mkdir(parents=True, exist_ok=True)
        args.sbom_out.write_text(json.dumps(report.sbom, indent=2) + "\n", encoding="utf-8")

    if not report.ok:
        print("Python license gate FAILED:", file=sys.stderr)
        for finding in report.findings:
            print(
                f"  - {finding.package}=={finding.version} ({finding.license_expr}): {finding.reason}",
                file=sys.stderr,
            )
        return 1

    if args.print_sbom:
        print(json.dumps(report.sbom, indent=2))
    else:
        print(
            f"Python license gate OK: {report.checked_count} packages verified "
            f"(zero GPL/AGPL/LGPL/CC-BY-NC/CC-BY-SA/CPML/UNKNOWN)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
