"""Canonical RFC 8707 resource and issuer URI validation.

Grammar enforced:
  aud     = "https://" host [port] path
          | "http://127.0.0.1" [port] path
  host    = label *("." label) "." final
  label   = [a-z0-9] / ([a-z0-9] *61[a-z0-9-] [a-z0-9])
  final   = [a-z] / ([a-z] *61[a-z0-9-] [a-z0-9])
  port    = ":" 1-65535 (no leading zero, excluding scheme default)
  path    = "/" / 1*("/" segment) ["/"]
  segment = 1*[A-Za-z0-9._~-], excluding "." and ".."

Host labels must not contain "-" in both positions 3 and 4 (excluding "xn--").
"""

from __future__ import annotations

import re

MAX_URI_LENGTH = 200
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FINAL_LABEL_RE = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")


def _is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for idx, label in enumerate(labels):
        if len(label) < 1 or len(label) > 63:
            return False
        if idx == len(labels) - 1:
            if not _FINAL_LABEL_RE.match(label):
                return False
        elif not _LABEL_RE.match(label):
            return False
        # Reject R-LDH labels with "--" at positions 3..4 unless punycode ("xn--").
        if len(label) >= 4 and label[2] == "-" and label[3] == "-" and not label.startswith("xn--"):
            return False
    return True


def _is_valid_path(path: str) -> bool:
    if path == "/":
        return True
    if not path.startswith("/"):
        return False
    trimmed = path[1:]
    if trimmed.endswith("/"):
        trimmed = trimmed[:-1]
    if not trimmed:
        return False
    segments = trimmed.split("/")
    for seg in segments:
        if not seg or seg in (".", ".."):
            return False
        if not _SEGMENT_RE.match(seg):
            return False
    return True


def is_canonical_uri(uri: str, *, allow_empty_path: bool = False) -> bool:
    """Return True iff uri strictly matches the canonical URI grammar."""
    if not isinstance(uri, str) or not uri or len(uri) > MAX_URI_LENGTH:
        return False
    if any(ch in uri for ch in ("?", "#", "@", "\\", " ", "\t", "\r", "\n")):
        return False

    if uri.startswith("https://"):
        default_port = 443
        rest = uri[len("https://") :]
        is_loopback = False
    elif uri.startswith("http://127.0.0.1"):
        default_port = 80
        rest = uri[len("http://") :]
        is_loopback = True
    else:
        return False

    slash_idx = rest.find("/")
    if slash_idx == -1:
        if not allow_empty_path:
            return False
        authority = rest
        path = "/"
    else:
        authority = rest[:slash_idx]
        path = rest[slash_idx:]

    if ":" in authority:
        host, port_str = authority.split(":", 1)
        if ":" in port_str or not _PORT_RE.match(port_str):
            return False
        port = int(port_str)
        if port < 1 or port > 65535 or port == default_port:
            return False
    else:
        host = authority

    if is_loopback:
        if host != "127.0.0.1":
            return False
    elif not _is_valid_host(host):
        return False

    return _is_valid_path(path)


def is_canonical_audience_uri(aud: str) -> bool:
    """Validate canonical RFC 8707 audience URI (requires explicit path)."""
    return is_canonical_uri(aud, allow_empty_path=False)


def is_canonical_issuer_uri(iss: str) -> bool:
    """Validate canonical issuer URI (origin-only or with canonical path)."""
    return is_canonical_uri(iss, allow_empty_path=True)
