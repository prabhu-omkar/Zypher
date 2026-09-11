"""
Crypto-agility scoring.

NIST CSWP 39 frames agility as the ability to replace an algorithm without
disrupting the systems that use it. That is a property of how the cryptography
is *wired in*, not of the primitive: the same RSA call is a one-line change
behind a provider interface and a rewrite when the key size is a literal in
forty call sites.

Four factors, each scored 0-100 and reported separately so the number can be
argued with rather than merely trusted:

  indirection      is the choice made at the call site, or passed in?
  configurability  can it be changed by editing configuration, or only code?
  concentration    how many distinct places have to change?
  substitutability is there a standardised drop-in to change *to*?

Only one of these feeds the migration estimate. Y already models how far an
asset reaches (occurrence spread), who owns it (target type), and whether both
ends must negotiate the change (asymmetric primitives) — so folding the whole
score into Y would count those three twice. Indirection is the one thing Y does
not otherwise see, and it is the only factor that moves the estimate.
"""
from typing import Dict, Optional, Tuple

from backend.models import (
    AlgorithmClass, ArtefactType, CryptographicArtefact, TargetType,
)

# Where a value can be changed without touching code.
CONFIGURATION_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg", ".properties",
    ".env", ".xml", ".plist",
}
CONFIGURATION_FILENAMES = {
    "dockerfile", "docker-compose.yml", "nginx.conf", "httpd.conf",
    "ssl.conf", "sshd_config", "openssl.cnf",
}

AGILE_THRESHOLD = 70.0
RIGID_THRESHOLD = 40.0

BAND_AGILE = "Agile"
BAND_MODERATE = "Moderate"
BAND_RIGID = "Rigid"

# How much each factor contributes to the reported score.
WEIGHTS = {
    "indirection": 0.30,
    "configurability": 0.30,
    "concentration": 0.15,
    "substitutability": 0.25,
}


def _indirection(art: CryptographicArtefact) -> Tuple[float, str]:
    """
    Whether the algorithm choice is made where it is used.

    parameter_source records how the value was established. A parameter the
    dataflow tier had to trace across function boundaries is, by definition,
    not written at the call site — there is a layer of indirection, which is
    what makes a swap cheap. A literal read straight off the call site is the
    opposite.
    """
    source = art.parameter_source
    if source == "dataflow":
        return 80.0, (
            "The parameter reaches this call from elsewhere, so there is a "
            "layer to change it at."
        )
    if source == "literal":
        return 30.0, (
            "The parameter is a literal at the call site, so every site has to "
            "be edited to change it."
        )
    if source == "assumed":
        return 50.0, (
            "No parameter was readable, so how the algorithm is selected here "
            "could not be determined."
        )
    return 50.0, (
        "This was matched as text rather than parsed, so how the algorithm is "
        "selected could not be determined."
    )


def _configurability(art: CryptographicArtefact) -> Tuple[float, str]:
    """Whether changing this means editing configuration, code, or nothing you own."""
    location = (art.location or "").lower().replace("\\", "/")
    name = location.rsplit("/", 1)[-1]
    extension = "." + name.rsplit(".", 1)[-1] if "." in name else ""

    if art.type == ArtefactType.HARDWARE_MODULE:
        return 10.0, "Held in hardware: changing it is procurement, not a code edit."
    if art.target_type == TargetType.BINARY:
        return 5.0, "Compiled into a binary with no source, so only the vendor can change it."
    if art.type == ArtefactType.CERTIFICATE:
        return 75.0, "A certificate is reissued rather than rewritten."
    if art.target_type == TargetType.DEPENDENCY:
        return 70.0, "Changing this means moving to another release of the package."
    if name in CONFIGURATION_FILENAMES or extension in CONFIGURATION_EXTENSIONS:
        return 90.0, "Declared in configuration, so it changes without touching code."
    if art.type == ArtefactType.PROTOCOL:
        return 85.0, "A protocol version is an endpoint setting."
    if art.target_type == TargetType.CONTAINER:
        return 65.0, "Changing this means rebuilding the image."
    return 55.0, "Written in source code you own."


def _concentration(art: CryptographicArtefact) -> Tuple[float, str]:
    """How many distinct places have to change."""
    sites = max(1, art.occurrence_count or 1)
    if sites == 1:
        return 90.0, "One occurrence, so one place to change."
    # Falls away steadily rather than off a cliff: ten sites is harder than one,
    # a thousand is harder than ten, but not a hundred times harder.
    import math
    score = max(20.0, 90.0 - 25.0 * math.log10(sites))
    return round(score, 1), f"{sites} occurrences, so {sites} places to change."


def _substitutability(art: CryptographicArtefact) -> Tuple[float, str]:
    """Whether there is a standardised thing to change to."""
    if art.algorithm_class in (AlgorithmClass.POST_QUANTUM, AlgorithmClass.HYBRID):
        return 100.0, "Already on a post-quantum standard; nothing to substitute."
    if art.algorithm_class in (AlgorithmClass.SYMMETRIC, AlgorithmClass.HASH):
        return 95.0, "A longer key or digest is a parameter change, not a new algorithm."
    if art.algorithm_class in (
        AlgorithmClass.ASYMMETRIC_FACTORING,
        AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
    ):
        return 55.0, (
            "A standardised replacement exists, but both ends have to negotiate "
            "it, so a dual-stack period is unavoidable."
        )
    if art.algorithm_class == AlgorithmClass.LEGACY_BROKEN:
        return 70.0, "A modern replacement is well established and needs no negotiation."
    return 40.0, "The primitive is unidentified, so no replacement can be named yet."


def score_artefact(art: CryptographicArtefact) -> Dict:
    """The agility score for one asset, with every factor and its reasoning."""
    factors = {
        "indirection": _indirection(art),
        "configurability": _configurability(art),
        "concentration": _concentration(art),
        "substitutability": _substitutability(art),
    }

    total = sum(WEIGHTS[name] * value for name, (value, _) in factors.items())
    total = round(total, 1)

    if total >= AGILE_THRESHOLD:
        band = BAND_AGILE
    elif total >= RIGID_THRESHOLD:
        band = BAND_MODERATE
    else:
        band = BAND_RIGID

    indirection_value = factors["indirection"][0]

    return {
        "score": total,
        "band": band,
        "factors": {
            name: {"score": value, "weight": WEIGHTS[name], "reason": reason}
            for name, (value, reason) in factors.items()
        },
        # Only indirection feeds the migration estimate. Y already accounts for
        # occurrence spread, ownership and two-party negotiation, so using the
        # whole score would count all three a second time.
        "migration_multiplier": migration_multiplier(indirection_value),
        "summary": _summarise(band, factors),
    }


def migration_multiplier(indirection_score: float) -> float:
    """
    What indirection does to the migration estimate.

    Deliberately narrow: this is the one agility factor Y does not already
    model, and a hardcoded parameter is genuinely more work to replace than one
    that arrives from somewhere else.
    """
    if indirection_score >= 70:
        return 0.9
    if indirection_score <= 35:
        return 1.2
    return 1.0


def _summarise(band: str, factors: Dict) -> str:
    weakest = min(factors.items(), key=lambda kv: kv[1][0])
    name, (value, reason) = weakest
    return (
        f"{band}. The binding constraint is {name.replace('_', ' ')} "
        f"({value:g}/100): {reason}"
    )


def score_all(artefacts) -> Dict[str, Dict]:
    return {art.id: score_artefact(art) for art in artefacts}


def estate_summary(scores: Dict[str, Dict]) -> Dict:
    """Roll the per-asset scores up into something a programme owner can read."""
    if not scores:
        return {"average_score": None, "band_distribution": {}, "rigid_count": 0}

    values = [entry["score"] for entry in scores.values()]
    distribution: Dict[str, int] = {}
    for entry in scores.values():
        distribution[entry["band"]] = distribution.get(entry["band"], 0) + 1

    return {
        "average_score": round(sum(values) / len(values), 1),
        "band_distribution": distribution,
        # The assets that will dominate any future migration, whatever the
        # algorithm turns out to be.
        "rigid_count": distribution.get(BAND_RIGID, 0),
    }
