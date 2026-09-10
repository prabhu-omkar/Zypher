"""
YARA-backed signature matching for compiled artefacts.

The binary scanner previously carried its signatures as Python data structures
and matched them with a loop of `bytes.find` calls plus a set of regexes. That
worked, but it meant every new signature was a code change, the matching cost
grew linearly with the number of signatures, and the knowledge was locked inside
this project.

YARA is the standard format for exactly this job. The rules live in
`rules/crypto.yar` as data, they compile to a single automaton that finds every
pattern in one pass over the file, and the same file can be handed to any other
YARA-capable tool.

This uses **yara-x**, VirusTotal's Rust implementation and the successor to the
original libyara. It ships stable-ABI wheels, so unlike `yara-python` it
installs on current Python without a C toolchain.

Availability is never assumed: if the engine or the rules cannot be loaded, the
caller falls back to the original byte matching rather than losing binary
detection entirely.
"""
from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

RULES_FILENAME = "crypto.yar"

_lock = threading.Lock()
_rules: Any = None
_state: Optional[str] = None  # None = not tried, "ready", or a failure reason


def rules_path() -> str:
    """
    Locate the rule file in both a source checkout and a frozen build.

    PyInstaller extracts bundled data under sys._MEIPASS, so the packaged app
    cannot use a path relative to this module's source location.
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidate = os.path.join(base, "backend", "scanners", "rules", RULES_FILENAME)
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(os.path.dirname(__file__), "rules", RULES_FILENAME)


def _load() -> None:
    """Compile the rules once. Records why it failed rather than raising."""
    global _rules, _state
    if _state is not None:
        return

    try:
        import yara_x
    except ImportError:
        _state = "yara-x is not installed"
        return

    path = rules_path()
    if not os.path.isfile(path):
        _state = f"rule file not found at {path}"
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        _rules = yara_x.compile(source)
        _state = "ready"
    except Exception as exc:
        _state = f"rules failed to compile: {exc}"


def is_available() -> bool:
    with _lock:
        _load()
    return _state == "ready"


def unavailable_reason() -> Optional[str]:
    """Why matching is unavailable, or None when it is working."""
    with _lock:
        _load()
    return None if _state == "ready" else _state


def rule_count() -> int:
    """How many rules are loaded — surfaced so a build can assert they shipped."""
    if not is_available():
        return 0
    try:
        return sum(1 for _ in _rules)
    except TypeError:
        # Older bindings do not make Rules iterable; fall back to counting the
        # rule declarations in the source.
        try:
            with open(rules_path(), "r", encoding="utf-8") as f:
                return sum(1 for line in f if line.lstrip().startswith("rule "))
        except OSError:
            return 0


@dataclass
class SignatureMatch:
    """One rule firing at one offset."""
    rule: str
    algorithm: str
    asset_type: str
    offset: int
    length: int
    pattern: str
    note: str = ""
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None


def _meta(rule) -> Dict[str, Any]:
    try:
        return dict(rule.metadata)
    except Exception:
        return {}


def scan_bytes(data: bytes, timeout: float = 30.0) -> Optional[List[SignatureMatch]]:
    """
    Match the rule set against a buffer.

    Returns None when matching is unavailable, which the caller distinguishes
    from an empty list — "could not check" is not "found nothing".
    """
    if not is_available():
        return None

    try:
        import yara_x

        scanner = yara_x.Scanner(_rules)
        try:
            scanner.set_timeout(int(timeout))
        except Exception:
            # Not every binding version exposes a timeout; a missing one is not
            # worth losing the scan over.
            pass
        results = scanner.scan(data)
    except Exception:
        return None

    matches: List[SignatureMatch] = []
    for rule in results.matching_rules:
        meta = _meta(rule)
        algorithm = str(meta.get("algorithm") or rule.identifier)
        asset_type = str(meta.get("asset_type") or "algorithm")
        note = str(meta.get("note") or "")

        key_size = meta.get("key_size")
        key_size = int(key_size) if isinstance(key_size, int) else None
        mode = meta.get("mode")
        curve = meta.get("curve")

        for pattern in rule.patterns:
            for instance in pattern.matches:
                matches.append(SignatureMatch(
                    rule=rule.identifier,
                    algorithm=algorithm,
                    asset_type=asset_type,
                    offset=instance.offset,
                    length=instance.length,
                    pattern=pattern.identifier,
                    note=note,
                    key_size=key_size,
                    mode=str(mode) if mode is not None else None,
                    curve=str(curve) if curve is not None else None,
                ))

    return matches
