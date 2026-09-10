"""
Shared filesystem traversal for all ECDAT scanners.

Every scanner used to call os.walk() directly with no exclusions, which meant a
scan of any real project descended into node_modules/, .git/, virtualenvs, build
output — and, worst of all, into ECDAT's own data_store/ directory, so each scan
re-ingested the JSON of every previous scan. A scan of this repository produced
6019 artefacts in 278 seconds, nearly all of them noise.

This module centralises the traversal rules so that behaviour cannot drift
between the four scanners again.
"""
import os
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Set

# Directories that never contain first-party cryptographic decisions worth
# reporting. Matched case-insensitively against the directory name itself.
EXCLUDED_DIRS: Set[str] = {
    # Dependency trees — vendored third-party code
    "node_modules", "bower_components", "jspm_packages", "vendor",
    "site-packages", "dist-packages", "packages",
    # Version control & tooling metadata
    ".git", ".hg", ".svn", ".bzr", ".idea", ".vscode", ".vs",
    # Python environments & caches
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", "venv", ".venv", "env", ".env.d", "virtualenv",
    "*.egg-info",
    # Build output
    "build", "dist", "out", "target", "bin", "obj", ".next", ".nuxt",
    ".svelte-kit", ".parcel-cache", ".turbo", ".gradle", "cmake-build-debug",
    # ECDAT's own state — scanning this makes every scan quadratic
    "data_store", "design-system",
    # Misc
    ".cache", ".terraform", "coverage", "htmlcov", ".DS_Store",
}

# Individual files that are pure machine output: enormous, and any crypto
# "finding" inside them is a restatement of the manifest we already parse.
EXCLUDED_FILENAMES: Set[str] = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "pipfile.lock", "cargo.lock", "composer.lock",
    "gemfile.lock", "go.sum", "flake.lock",
}

# Extensions that are never worth opening as text or probing as binaries.
EXCLUDED_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".avif",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".webm", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".pyd", ".map", ".min.js", ".min.css",
}

# Hard ceilings. A scan that would exceed these stops cleanly and reports how
# much it covered, instead of appearing to hang forever.
DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024      # 8 MB — larger is generated/vendored
DEFAULT_MAX_FILES = 25_000                    # files actually opened
DEFAULT_MAX_DEPTH = 25                        # directory nesting


@dataclass
class WalkLimits:
    """Caps applied to a single traversal."""
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_depth: int = DEFAULT_MAX_DEPTH
    follow_symlinks: bool = False
    extra_excluded_dirs: Set[str] = field(default_factory=set)
    # Extensions this particular scanner legitimately wants even though the
    # shared list excludes them — e.g. the container scanner needs ".tar"
    # image bundles, which are noise for every other scanner.
    allowed_extensions: Set[str] = field(default_factory=set)


@dataclass
class WalkStats:
    """What a traversal actually covered — surfaced to the user after a scan."""
    files_seen: int = 0
    files_scanned: int = 0
    files_skipped_size: int = 0
    files_skipped_type: int = 0
    dirs_pruned: int = 0
    hit_file_limit: bool = False
    hit_depth_limit: bool = False

    def as_dict(self) -> dict:
        return {
            "files_seen": self.files_seen,
            "files_scanned": self.files_scanned,
            "files_skipped_size": self.files_skipped_size,
            "files_skipped_type": self.files_skipped_type,
            "dirs_pruned": self.dirs_pruned,
            "hit_file_limit": self.hit_file_limit,
            "hit_depth_limit": self.hit_depth_limit,
        }


def is_excluded_dir(name: str) -> bool:
    lowered = name.lower()
    if lowered in EXCLUDED_DIRS:
        return True
    # Hidden directories, except the few that legitimately hold config we scan.
    if lowered.startswith(".") and lowered not in {".github", ".gitlab", ".circleci"}:
        return True
    if lowered.endswith(".egg-info"):
        return True
    return False


def is_excluded_file(name: str, allowed_extensions: Optional[Set[str]] = None) -> bool:
    lowered = name.lower()
    if lowered in EXCLUDED_FILENAMES:
        return True
    # Our own persisted scan output, wherever it has been copied to.
    if lowered.startswith("scan_") and lowered.endswith(".json"):
        return True
    if allowed_extensions and any(lowered.endswith(ext) for ext in allowed_extensions):
        return False
    for ext in EXCLUDED_EXTENSIONS:
        if lowered.endswith(ext):
            return True
    return False


def walk_files(
    root: str,
    limits: Optional[WalkLimits] = None,
    accept: Optional[Callable[[str], bool]] = None,
    stats: Optional[WalkStats] = None,
) -> Iterator[str]:
    """
    Yield absolute paths of candidate files beneath ``root``.

    ``accept`` is the per-scanner predicate (extension match, filename match)
    applied after the shared exclusions; files it rejects are counted as
    skipped-by-type rather than silently dropped, so a scan can explain itself.
    """
    limits = limits or WalkLimits()
    stats = stats if stats is not None else WalkStats()

    if not os.path.exists(root):
        return

    # A single file target bypasses traversal entirely.
    if os.path.isfile(root):
        stats.files_seen += 1
        if _accept_file(root, os.path.basename(root), limits, accept, stats):
            stats.files_scanned += 1
            yield root
        return

    root_depth = os.path.abspath(root).rstrip(os.sep).count(os.sep)
    excluded_dirs = limits.extra_excluded_dirs

    for current_dir, subdirs, files in os.walk(root, topdown=True, followlinks=limits.follow_symlinks):
        depth = os.path.abspath(current_dir).rstrip(os.sep).count(os.sep) - root_depth
        if depth >= limits.max_depth:
            stats.hit_depth_limit = True
            stats.dirs_pruned += len(subdirs)
            subdirs[:] = []
            continue

        # Prune in place so os.walk never descends into them at all. This is
        # what makes the traversal fast, not merely quiet.
        kept = []
        for d in subdirs:
            if is_excluded_dir(d) or d.lower() in excluded_dirs:
                stats.dirs_pruned += 1
            else:
                kept.append(d)
        subdirs[:] = kept

        for name in files:
            if stats.files_scanned >= limits.max_files:
                stats.hit_file_limit = True
                return

            stats.files_seen += 1
            path = os.path.join(current_dir, name)
            if _accept_file(path, name, limits, accept, stats):
                stats.files_scanned += 1
                yield path


def _accept_file(
    path: str,
    name: str,
    limits: WalkLimits,
    accept: Optional[Callable[[str], bool]],
    stats: WalkStats,
) -> bool:
    if is_excluded_file(name, limits.allowed_extensions):
        stats.files_skipped_type += 1
        return False

    if accept is not None and not accept(path):
        stats.files_skipped_type += 1
        return False

    try:
        if os.path.getsize(path) > limits.max_file_bytes:
            stats.files_skipped_size += 1
            return False
    except OSError:
        stats.files_skipped_type += 1
        return False

    return True


def count_candidate_files(
    root: str,
    accept: Optional[Callable[[str], bool]] = None,
    limits: Optional[WalkLimits] = None,
) -> int:
    """
    Pre-count candidates so scan progress can be reported as a real fraction
    rather than an animated guess.
    """
    total = 0
    for _ in walk_files(root, limits=limits, accept=accept):
        total += 1
    return total
