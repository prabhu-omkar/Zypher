"""
Package URL (purl) identifiers for dependency artefacts.

A CBOM that says "this project uses crypto-js" is not machine-actionable — the
name alone does not identify the package registry, and every vulnerability
service keys off a canonical identifier. purl is that identifier and is a first
class field in CycloneDX 1.6, so emitting it turns the dependency half of the
inventory from a list of names into something an SCA tool, an OSV query or a
GRC platform can consume directly.

    pkg:npm/crypto-js@4.2.0
    pkg:pypi/cryptography@41.0.4
    pkg:maven/org.bouncycastle/bcprov-jdk18on@1.70

Version specifiers are the awkward part. Manifests pin ranges (`^4.2.0`,
`>=1.5`), and a range is not a version. The base version is used, and the fact
that it came from a range is recorded so nothing downstream reports a
range-derived finding as if the exact version were known.
"""
import re
from typing import Optional, Tuple

# Scanner ecosystem label -> purl type, per the Package URL specification.
PURL_TYPE_BY_ECOSYSTEM = {
    "npm": "npm",
    "pip": "pypi",
    "pypi": "pypi",
    "maven": "maven",
    "gradle": "maven",
    "go": "golang",
    "golang": "golang",
    "cargo": "cargo",
    "crates": "cargo",
    "composer": "composer",
    "packagist": "composer",
    "gem": "gem",
    "rubygems": "gem",
    "nuget": "nuget",
}

# OSV's ecosystem names differ from purl types.
OSV_ECOSYSTEM_BY_PURL_TYPE = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "composer": "Packagist",
    "gem": "RubyGems",
    "nuget": "NuGet",
}

# Leading comparison operators and range markers found in manifests.
_SPECIFIER = re.compile(r"^\s*(?:[\^~=<>!]+|v)\s*")
# Everything from the first range separator onwards.
_RANGE_TAIL = re.compile(r"\s*(?:,|\|\||\s-\s|\s+).*$")

_RANGE_MARKERS = ("^", "~", ">", "<", "*", "x", "||", ",", " - ")


def normalise_version(raw: Optional[str]) -> Tuple[Optional[str], bool]:
    """
    Reduce a manifest version specifier to a concrete version.

    Returns ``(version, was_a_range)``. ``^4.2.0`` becomes ``("4.2.0", True)``
    because 4.2.0 is only the lower bound of what may actually be installed;
    ``==4.2.0`` becomes ``("4.2.0", False)``.
    """
    if not raw:
        return None, False

    text = raw.strip()
    if not text or text in ("*", "latest"):
        return None, True

    is_range = any(marker in text for marker in _RANGE_MARKERS)
    # `==1.2.3` pins exactly; `>=1.2.3` does not.
    if text.startswith("==") and not any(m in text[2:] for m in _RANGE_MARKERS):
        is_range = False

    cleaned = _SPECIFIER.sub("", text)
    cleaned = _RANGE_TAIL.sub("", cleaned).strip()
    cleaned = cleaned.strip("=<>!~^ ")

    if not re.match(r"^\d[\w.\-+]*$", cleaned):
        return None, True
    return cleaned, is_range


def build_purl(
    ecosystem: Optional[str],
    package_name: Optional[str],
    version: Optional[str] = None,
) -> Optional[str]:
    """
    Build a purl, or None when the ecosystem or name is unknown.

    Maven coordinates arrive as ``group:artifact`` and become a namespaced
    purl, which is what the specification requires for that type.
    """
    if not ecosystem or not package_name:
        return None

    purl_type = PURL_TYPE_BY_ECOSYSTEM.get(ecosystem.strip().lower())
    if not purl_type:
        return None

    name = package_name.strip()
    namespace = None

    if purl_type == "maven" and ":" in name:
        namespace, _, name = name.partition(":")
    elif purl_type == "npm" and name.startswith("@") and "/" in name:
        namespace, _, name = name.partition("/")
    elif purl_type == "composer" and "/" in name:
        namespace, _, name = name.partition("/")

    if purl_type in ("pypi", "npm"):
        # Both registries treat names case-insensitively; PyPI also normalises
        # underscores and dots to hyphens.
        name = name.lower()
        if purl_type == "pypi":
            name = re.sub(r"[._]+", "-", name)

    purl = f"pkg:{purl_type}/"
    if namespace:
        purl += f"{namespace}/"
    purl += name
    if version:
        purl += f"@{version}"
    return purl


def osv_ecosystem_for(purl: str) -> Optional[str]:
    """Map a purl back to the ecosystem name OSV expects."""
    if not purl or not purl.startswith("pkg:"):
        return None
    purl_type = purl[4:].split("/", 1)[0]
    return OSV_ECOSYSTEM_BY_PURL_TYPE.get(purl_type)
