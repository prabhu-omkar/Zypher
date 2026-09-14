"""
Tests for the shared filesystem walker.

These exist because the absence of traversal exclusions was the single worst
defect in the tool: a scan of the project directory read its own previous scan
output, every vendored dependency and all build artefacts, producing 6019
artefacts in 278 seconds.
"""
import os

from backend.scanners.walker import (
    WalkLimits, WalkStats, walk_files, is_excluded_dir, is_excluded_file,
)
from backend.scanners.source_scanner import SourceCodeScanner


def _write(path, content="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def test_dependency_and_build_directories_are_pruned(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "app.py"), "import hashlib")
    _write(os.path.join(root, "node_modules", "left-pad", "index.js"), "crypto")
    _write(os.path.join(root, ".git", "config"), "[core]")
    _write(os.path.join(root, "venv", "lib", "mod.py"), "import rsa")
    _write(os.path.join(root, "build", "out.js"), "aes")
    _write(os.path.join(root, "dist", "bundle.js"), "aes")
    _write(os.path.join(root, "__pycache__", "app.py"), "x")

    found = [os.path.basename(p) for p in walk_files(root, accept=SourceCodeScanner().accepts)]
    assert found == ["app.py"], f"only first-party source should be walked, got {found}"


def test_ecdat_own_scan_output_is_never_ingested(tmp_path):
    """
    The feedback loop that inflated every scan.

    Scan results are JSON, the source scanner reads .json, and results were
    written into the project tree — so each scan re-ingested all previous ones.
    """
    root = str(tmp_path)
    _write(os.path.join(root, "config.json"), '{"tls": "TLSv1.2"}')
    _write(os.path.join(root, "data_store", "scan_SCAN-ABC123.json"), '{"artefacts": []}')
    # Also guard against the file being copied somewhere else entirely.
    _write(os.path.join(root, "backup", "scan_SCAN-DEF456.json"), '{"artefacts": []}')

    found = [os.path.basename(p) for p in walk_files(root, accept=SourceCodeScanner().accepts)]
    assert "config.json" in found
    assert not any(n.startswith("scan_SCAN-") for n in found)


def test_lockfiles_are_excluded(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "package.json"), '{"dependencies":{}}')
    _write(os.path.join(root, "package-lock.json"), '{"lockfileVersion":3}')
    _write(os.path.join(root, "yarn.lock"), "# yarn")

    found = [os.path.basename(p) for p in walk_files(root, accept=SourceCodeScanner().accepts)]
    assert "package.json" in found
    assert "package-lock.json" not in found
    assert "yarn.lock" not in found


def test_oversized_files_are_skipped_and_counted(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "small.py"), "import hashlib")
    _write(os.path.join(root, "huge.py"), "x" * 5000)

    stats = WalkStats()
    limits = WalkLimits(max_file_bytes=1000)
    found = [os.path.basename(p) for p in walk_files(root, limits=limits, stats=stats)]

    assert "small.py" in found
    assert "huge.py" not in found
    assert stats.files_skipped_size == 1


def test_file_limit_stops_the_walk_and_is_reported(tmp_path):
    root = str(tmp_path)
    for i in range(30):
        _write(os.path.join(root, f"mod{i}.py"), "import hashlib")

    stats = WalkStats()
    found = list(walk_files(root, limits=WalkLimits(max_files=10), stats=stats))

    assert len(found) == 10
    assert stats.hit_file_limit is True


def test_depth_limit_is_reported(tmp_path):
    root = str(tmp_path)
    deep = root
    for i in range(10):
        deep = os.path.join(deep, f"lvl{i}")
    _write(os.path.join(deep, "deep.py"), "import hashlib")

    stats = WalkStats()
    list(walk_files(root, limits=WalkLimits(max_depth=3), stats=stats))
    assert stats.hit_depth_limit is True


def test_a_single_file_target_bypasses_traversal(tmp_path):
    target = os.path.join(str(tmp_path), "one.py")
    _write(target, "import hashlib")
    assert list(walk_files(target)) == [target]


def test_allowed_extensions_override_the_shared_exclusion(tmp_path):
    """The container scanner needs .tar image bundles that others must ignore."""
    root = str(tmp_path)
    _write(os.path.join(root, "image.tar"), "x")

    assert list(walk_files(root)) == []
    allowed = list(walk_files(root, limits=WalkLimits(allowed_extensions={".tar"})))
    assert len(allowed) == 1


def test_exclusion_predicates_are_case_insensitive():
    assert is_excluded_dir("NODE_MODULES")
    assert is_excluded_dir(".Git")
    assert is_excluded_file("PACKAGE-LOCK.JSON")
    assert not is_excluded_dir("backend")
    assert not is_excluded_file("auth_service.py")
