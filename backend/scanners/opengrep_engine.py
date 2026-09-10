"""
Dataflow analysis for compiled-free source trees, via a bundled OpenGrep binary.

Tiers 1-3 each read one construct at a time. The AST scanner knows that
``rsa.generate_private_key(key_size=bits)`` generates an RSA key, but ``bits`` is
a variable, so the key size — the X in Mosca's inequality — comes back
undetermined. The same is true of ``Cipher.getInstance(transform)``: the
algorithm is whatever was passed in, and a syntax tree cannot say what that was.

Closing that gap needs a whole-program model: a call graph, function summaries,
and the ability to replay a summary at each call site. OpenGrep implements
exactly that (``--taint-intrafile``), and does it without the things that would
break this project:

* **No runtime dependency.** One self-contained executable. CodeQL needs its own
  ~1 GB CLI; SonarQube, IBM's ``cbomkit-lib`` and Joern all need a JVM, and Joern
  wants a 4-100 GB heap.
* **No network.** The binary carries no endpoints and no telemetry. ECDAT is an
  air-gapped tool.
* **A licence that permits redistribution** (LGPL-2.1). The CodeQL CLI terms
  restrict automated analysis to open-source codebases, which excludes the
  closed-source estate this tool exists to inventory.

See ``vendor/opengrep/NOTICE.md`` for the compliance record.

Availability is never assumed. If the binary is missing, too old, or fails, the
caller keeps the Tier 1-3 findings and records why Tier 4 did not contribute —
a scan that silently loses dataflow resolution would report key sizes as
undetermined with no indication that anything went wrong.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

RULES_FILENAME = "crypto-taint.yaml"
BINARY_NAME = "opengrep.exe" if os.name == "nt" else "opengrep"

# The upstream release this integration was written and tested against. A
# different build is allowed to run — the flags used here are stable — but the
# version is recorded on every finding so a regression can be traced to it.
EXPECTED_VERSION = "1.30.0"

# Per-rule, per-file ceiling. OpenGrep's own default is 5 s; a pathological
# generated file should not be able to stall a scan. The dispatching CLI
# takes whole seconds here and rejects a float.
RULE_TIMEOUT_SECONDS = 5

# Whole-invocation ceiling. Generous, because this runs once per scan rather than
# once per file, and a large tree legitimately takes longer than a single file.
PROCESS_TIMEOUT_SECONDS = 300.0

# Matches the shared walker's 8 MB cap so Tier 4 sees the same files as the rest
# of the pipeline. OpenGrep defaults to 1 MB, which would silently skip files the
# AST scanner did read.
MAX_TARGET_BYTES = 8 * 1024 * 1024

_lock = threading.Lock()
_state: Optional[str] = None  # None = not tried, "ready", or a failure reason
_version: Optional[str] = None


def _candidate_roots() -> List[str]:
    """
    Places the vendored binary may live, most specific first.

    PyInstaller extracts bundled data under ``sys._MEIPASS``, so a frozen build
    cannot resolve a path relative to this module's source location. The
    directory beside the executable is also checked, which is what lets a build
    ship the binary as an external file rather than inside the archive.
    """
    roots: List[str] = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
        roots.append(os.path.dirname(sys.executable))
    roots.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    return roots


def binary_path() -> Optional[str]:
    """Locate the vendored binary, or None when it was not shipped."""
    for root in _candidate_roots():
        candidate = os.path.join(root, "vendor", "opengrep", BINARY_NAME)
        if os.path.isfile(candidate):
            return candidate
    return None


def rules_path() -> Optional[str]:
    """Locate the Tier 4 rule file, or None when it was not shipped."""
    for root in _candidate_roots():
        candidate = os.path.join(root, "backend", "scanners", "rules", RULES_FILENAME)
        if os.path.isfile(candidate):
            return candidate
    local = os.path.join(os.path.dirname(__file__), "rules", RULES_FILENAME)
    return local if os.path.isfile(local) else None


def _no_window() -> Dict[str, Any]:
    """Keep the subprocess from flashing a console window in the desktop app."""
    if os.name != "nt":
        return {}
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _load() -> None:
    """Probe the binary once. Records why it failed rather than raising."""
    global _state, _version
    if _state is not None:
        return

    exe = binary_path()
    if exe is None:
        _state = "opengrep binary was not bundled with this build"
        return
    if rules_path() is None:
        _state = f"rule file {RULES_FILENAME} was not bundled with this build"
        return

    try:
        proc = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            **_no_window(),
        )
    except OSError as exc:
        _state = f"opengrep binary could not be executed: {exc}"
        return
    except subprocess.TimeoutExpired:
        _state = "opengrep binary did not respond to --version"
        return

    if proc.returncode != 0:
        _state = f"opengrep --version exited {proc.returncode}"
        return

    _version = (proc.stdout or "").strip().splitlines()[0].strip() if proc.stdout else ""
    _state = "ready"


def is_available() -> bool:
    with _lock:
        _load()
    return _state == "ready"


def unavailable_reason() -> Optional[str]:
    """Why dataflow analysis is unavailable, or None when it is working."""
    with _lock:
        _load()
    return None if _state == "ready" else _state


def version() -> Optional[str]:
    with _lock:
        _load()
    return _version


def rule_count() -> int:
    """How many rules are loaded — surfaced so a build can assert they shipped."""
    path = rules_path()
    if path is None:
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.lstrip().startswith("- id:"))
    except OSError:
        return 0


@dataclass
class TaintFinding:
    """
    One cryptographic parameter whose value was resolved by following dataflow.

    ``value`` is the literal that actually reached the argument, and ``param``
    says what it means — a key size, a curve name, an algorithm string. The
    source location is where that literal was written, which is usually a
    different line, and often a different function, from ``file_path``.
    """
    rule: str
    param: str
    value: str
    file_path: str
    line_number: int
    column_number: Optional[int]
    snippet: str
    family: Optional[str] = None
    asset_type: str = "algorithm"
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    hops: List[str] = field(default_factory=list)

    @property
    def value_as_int(self) -> Optional[int]:
        try:
            return int(self.value)
        except (TypeError, ValueError):
            return None

    @property
    def unquoted_value(self) -> str:
        v = self.value.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            return v[1:-1]
        return v


def _unwrap_location(node: Any) -> Optional[Dict[str, Any]]:
    """
    Pull the location dict out of OpenGrep's tagged-union trace nodes.

    A taint source is encoded as ``["CliLoc", [{location...}, "literal"]]`` and a
    call step as ``["CliCall", [[{location...}, "name"], ...]]``. Both shapes are
    walked defensively: the encoding is an implementation detail of the tool, and
    a change to it must degrade to "no trace" rather than crash a scan.
    """
    if isinstance(node, dict):
        return node if "path" in node and "start" in node else None
    if isinstance(node, (list, tuple)):
        for item in node:
            found = _unwrap_location(item)
            if found is not None:
                return found
    return None


def _trace_literal(trace: Dict[str, Any]) -> tuple:
    """Return ``(literal, source_path, source_line)`` from a dataflow trace."""
    source = trace.get("taint_source")
    if not isinstance(source, (list, tuple)) or len(source) < 2:
        return None, None, None

    payload = source[1]
    literal = None
    if isinstance(payload, (list, tuple)):
        for item in payload:
            if isinstance(item, str):
                literal = item
                break

    location = _unwrap_location(payload)
    path = location.get("path") if location else None
    line = (location.get("start") or {}).get("line") if location else None
    return literal, path, line


def _trace_hops(trace: Dict[str, Any]) -> List[str]:
    """Names of the intermediate variables the value passed through."""
    hops: List[str] = []
    for var in trace.get("intermediate_vars") or []:
        if isinstance(var, dict):
            content = var.get("content")
            if isinstance(content, str) and content not in hops:
                hops.append(content)
    return hops


def _parse_results(payload: Dict[str, Any]) -> List[TaintFinding]:
    findings: List[TaintFinding] = []

    for result in payload.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        param = metadata.get("param")
        if not param:
            # A rule without `param` cannot be interpreted; skipping it is
            # correct, and loudly wrong rules are caught by the rule tests.
            continue

        trace = extra.get("dataflow_trace") or {}
        literal, source_path, source_line = _trace_literal(trace)
        if literal is None:
            # The finding is real but the value could not be read out of the
            # trace, which makes it useless here — Tiers 1-3 already reported
            # the call site itself.
            continue

        start = result.get("start") or {}
        findings.append(TaintFinding(
            rule=str(result.get("check_id") or "unknown"),
            param=str(param),
            value=str(literal),
            file_path=str(result.get("path") or "").replace("\\", "/"),
            line_number=int(start.get("line") or 0),
            column_number=start.get("col"),
            snippet=(extra.get("lines") or "").strip()[:200],
            family=metadata.get("family"),
            asset_type=str(metadata.get("asset_type") or "algorithm"),
            source_file=(source_path or "").replace("\\", "/") or None,
            source_line=source_line,
            hops=_trace_hops(trace),
        ))

    return findings


def default_exclusions() -> List[str]:
    """
    The traversal exclusions the rest of the pipeline already applies.

    Tier 4 must see the same files as Tiers 1-3 or the inventory disagrees with
    itself, so the walker's exclusion set is reused rather than restated.
    """
    from backend.scanners.walker import EXCLUDED_DIRS

    return sorted(EXCLUDED_DIRS)


def scan_paths(
    targets: Sequence[str],
    excluded_dirs: Optional[Sequence[str]] = None,
    timeout: float = PROCESS_TIMEOUT_SECONDS,
) -> Optional[List[TaintFinding]]:
    """
    Run the rule set over one or more files or directories.

    Returns None when analysis could not run, which the caller distinguishes from
    an empty list — "could not check" is not "found nothing". This is the same
    contract ``yara_engine.scan_bytes`` uses.
    """
    if not targets:
        return []
    if not is_available():
        return None

    exe = binary_path()
    rules = rules_path()
    if exe is None or rules is None:  # pragma: no cover - guarded by is_available
        return None

    # Every flag below exists on the CLI that actually dispatches. The binary
    # carries two front-ends — `opengrep scan --help` prints the OCaml one, while
    # invocations land on the Python one, whose option set is a subset. Flags are
    # therefore taken from `scan --legacy --help`, not from `scan --help`:
    # `--exclude-minified-files` and `--skip-invalid-configs` appear in the
    # former and are rejected by the latter. Minified files are skipped by
    # default regardless.
    command = [
        exe, "scan",
        "--config", rules,
        # Cross-function taint. Without this flag the scan degrades to exactly
        # what Tier 1 already does and contributes nothing.
        "--taint-intrafile",
        # The resolved literal lives in the trace, so the trace is the payload.
        "--dataflow-traces",
        "--json",
        # ECDAT scans arbitrary folders and extracted archives, which are not
        # repositories; without this, a stray .gitignore silently drops files.
        "--no-git-ignore",
        # And without this, OpenGrep's own built-in ignore list applies. It
        # excludes test and fixture directories among others, which would make
        # Tier 4 see a different file set from Tiers 1-3 — silently, with the
        # files reported only as "skipped". Exclusions are ECDAT's to decide, and
        # `walker.EXCLUDED_DIRS` is where that decision lives.
        "--x-ignore-semgrepignore-files",
        "--disable-version-check",
        # Keep the progress banner off stdout so the payload is JSON and nothing
        # else.
        "--quiet",
        "--timeout", str(int(RULE_TIMEOUT_SECONDS)),
        "--max-target-bytes", str(MAX_TARGET_BYTES),
    ]
    patterns = default_exclusions() if excluded_dirs is None else list(excluded_dirs)
    for pattern in patterns:
        command += ["--exclude", pattern]
    command += list(targets)

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            **_no_window(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    # Findings are reported on stdout as JSON. A non-zero exit accompanies
    # partial failures (an unparseable file, a rule timeout) and still carries
    # usable results, so the payload is preferred over the exit code.
    if not proc.stdout:
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    return _parse_results(payload)
