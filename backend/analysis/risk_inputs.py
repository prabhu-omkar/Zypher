"""
Where X, Y and Z come from, and on what authority.

The risk engine used to read all three straight off the artefact, and the
artefact got them from a constant table in the extractor keyed on the algorithm
name. That is wrong in three separate ways:

  X  is a property of the *data*, not of the algorithm. RSA-2048 protecting a
     session cookie and RSA-2048 protecting a medical record have the same
     primitive and nothing else in common. X now comes from a data-sensitivity
     profile chosen for the scan, refined by what the asset actually does.

  Y  is a property of *who has to make the change and how far it reaches*, not
     of the primitive. Three call sites in your own source is not the same job
     as an HSM firmware upgrade. Y is now computed bottom-up from the evidence
     and reports its own breakdown.

  Z  is not a number. It is an expert-elicited distribution with a publication
     date attached, and it belongs on a calendar rather than floating as "8
     years from whenever this happened to run".

Every constant below carries the source it came from. Where a value is
interpolated rather than published, it says so.
"""
from __future__ import annotations

import math
from datetime import date, timedelta
from typing import Dict, List, Optional, Tuple

from backend.models import (
    AlgorithmClass, ArtefactType, BusinessCriticality, CryptographicArtefact,
    CryptoUsage, DataSensitivityProfile, RegulatoryDeadline, TargetType,
)

DAYS_PER_YEAR = 365.2425


def years_from(anchor: date, years: float) -> date:
    # date + timedelta reads only the whole-day part, so a fractional day is
    # discarded rather than carried. Truncating made "15 years from 2026-01-01"
    # land on 2040-12-31; rounding puts it where a reader expects it.
    return anchor + timedelta(days=round(years * DAYS_PER_YEAR))


def years_between(start: date, end: date) -> float:
    return round((end - start).days / DAYS_PER_YEAR, 2)


# =============================================================== X: shelf life

# How long data of each class must stay confidential, in years.
#
# These are retention periods drawn from the regimes that actually mandate them,
# not estimates. They are the default for a profile; a scan can override the
# number directly when an organisation knows its own retention policy.
PROFILE_RETENTION_YEARS: Dict[DataSensitivityProfile, float] = {
    # Session tokens, CSRF values, short-lived cache entries. Worthless to an
    # adversary by the time any quantum computer exists.
    DataSensitivityProfile.SESSION: 0.5,
    # Ordinary operational data with no statutory retention.
    DataSensitivityProfile.GENERAL_BUSINESS: 3.0,
    # Financial records: 7 years is the common statutory floor (SOX §802 in the
    # US, Companies Act in India and the UK).
    DataSensitivityProfile.FINANCIAL: 7.0,
    # Personal data held under a retention policy; 10 years is a common ceiling
    # for employment and contract records.
    DataSensitivityProfile.PERSONAL_DATA: 10.0,
    # Health records. Retention is measured in decades in nearly every
    # jurisdiction, and longer for paediatric records.
    DataSensitivityProfile.HEALTH: 25.0,
    # Government records under a standard classification review cycle.
    DataSensitivityProfile.GOVERNMENT: 25.0,
    # National-security material. CNSA 2.0 exists precisely because this class
    # of data outlives any plausible CRQC estimate.
    DataSensitivityProfile.NATIONAL_SECURITY: 50.0,
}

PROFILE_LABELS: Dict[DataSensitivityProfile, str] = {
    DataSensitivityProfile.SESSION: "Session / ephemeral",
    DataSensitivityProfile.GENERAL_BUSINESS: "General business",
    DataSensitivityProfile.FINANCIAL: "Financial records",
    DataSensitivityProfile.PERSONAL_DATA: "Personal data",
    DataSensitivityProfile.HEALTH: "Health records",
    DataSensitivityProfile.GOVERNMENT: "Government / classified",
    DataSensitivityProfile.NATIONAL_SECURITY: "National security",
}

# For assets that prove *who* rather than hide *what*, X is not a retention
# period. A forged signature only matters while the credential that made it is
# still trusted, and a credential expires on a schedule you control. These are
# the validity windows in ordinary use.
AUTHENTICITY_VALIDITY_YEARS: Dict[ArtefactType, float] = {
    ArtefactType.CERTIFICATE: 1.5,       # CA/B Forum caps TLS certs near 398 days
    ArtefactType.KEY: 3.0,               # typical signing-key rotation
    ArtefactType.HARDWARE_MODULE: 10.0,  # an HSM-held root outlives everything
    ArtefactType.CLOUD_SERVICE: 2.0,
    ArtefactType.PROTOCOL: 3.0,
    ArtefactType.LIBRARY: 3.0,
    ArtefactType.ALGORITHM: 3.0,
}

_SIGNATURE_MARKERS = (
    "DSA", "ECDSA", "EDDSA", "ED25519", "ED448", "SIGN", "SIGNATURE",
    "ML-DSA", "SLH-DSA", "DILITHIUM", "SPHINCS", "FALCON", "RSA-PSS", "PSS",
)
_KEY_EXCHANGE_MARKERS = (
    "DH", "ECDH", "X25519", "X448", "KEM", "ML-KEM", "KYBER", "KEY EXCHANGE",
    "KEYEXCHANGE", "ECIES",
)


def classify_usage(art: CryptographicArtefact) -> CryptoUsage:
    """
    What this asset is *for*. Drives which definition of X applies.

    Where the evidence is ambiguous the answer is the confidentiality-bearing
    one, because that is the reading that produces the longer X. An asset whose
    purpose we cannot determine must not be given the shorter, gentler horizon.
    """
    name = f"{art.algorithm_family} {art.name}".upper()

    if art.algorithm_class == AlgorithmClass.HASH:
        return CryptoUsage.INTEGRITY

    if art.type == ArtefactType.CERTIFICATE:
        return CryptoUsage.AUTHENTICITY

    if any(m in name for m in _SIGNATURE_MARKERS):
        # "ECDH" contains "DH" but is key agreement, so key-exchange markers win
        # when both appear.
        if not any(m in name for m in _KEY_EXCHANGE_MARKERS):
            return CryptoUsage.AUTHENTICITY

    if art.algorithm_class == AlgorithmClass.SYMMETRIC:
        return CryptoUsage.CONFIDENTIALITY

    if art.algorithm_class in (
        AlgorithmClass.ASYMMETRIC_FACTORING,
        AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
    ):
        return CryptoUsage.KEY_TRANSPORT

    if art.type == ArtefactType.PROTOCOL:
        return CryptoUsage.KEY_TRANSPORT

    return CryptoUsage.UNKNOWN


def derive_shelf_life_x(
    art: CryptographicArtefact,
    profile: DataSensitivityProfile,
    retention_override: Optional[float] = None,
) -> Tuple[float, CryptoUsage, str]:
    """
    Returns (X in years, the usage it was derived from, a one-line rationale).
    """
    usage = classify_usage(art)
    retention = (
        retention_override
        if retention_override is not None
        else PROFILE_RETENTION_YEARS[profile]
    )

    if usage == CryptoUsage.AUTHENTICITY:
        # A certificate states its own validity window. Measured beats assumed,
        # for the same reason a read key size beats a conventional default.
        if art.measured_validity_years:
            x = art.measured_validity_years
            source = "read from the certificate"
        else:
            x = AUTHENTICITY_VALIDITY_YEARS.get(art.type, 3.0)
            source = "the conventional window for this asset type"
        why = (
            f"Authenticity asset: X is the {x:g}-year window this credential "
            f"stays trusted ({source}), not the {retention:g}-year data "
            f"retention. A forged signature is only useful while the credential "
            f"is valid, so harvest-now-decrypt-later does not apply."
        )
        return x, usage, why

    if usage == CryptoUsage.INTEGRITY:
        x = art.measured_validity_years or AUTHENTICITY_VALIDITY_YEARS.get(art.type, 3.0)
        why = (
            f"Integrity asset: X is the {x:g}-year window in which a forged "
            f"digest would still be accepted."
        )
        return x, usage, why

    label = PROFILE_LABELS[profile]
    why = (
        f"Confidentiality asset under the '{label}' profile: anything it "
        f"protects must stay secret for {retention:g} years. Traffic captured "
        f"today is decrypted the day a CRQC exists, so X is the retention "
        f"period of the data, not the lifetime of the session."
    )
    return retention, usage, why


# ============================================================ Y: migration time

# Base effort in years, by who actually has to make the change. The question is
# not how hard the code edit is, it is how long before the fix is in your hands.
BASE_CONTROL_YEARS: Dict[TargetType, float] = {
    TargetType.SOURCE_CODE: 0.25,   # you own it; the limit is review and release
    TargetType.DEPENDENCY: 0.75,    # upstream must ship first, then you upgrade
    TargetType.BINARY: 1.50,        # no source; a vendor release or a rebuild
    TargetType.CONTAINER: 0.50,     # base image rebuild and redeploy
    TargetType.MULTI_TARGET: 0.50,
}

# Where the asset type dominates the schedule regardless of who owns the code.
BASE_ARTEFACT_YEARS: Dict[ArtefactType, float] = {
    ArtefactType.PROTOCOL: 0.15,          # an endpoint configuration change
    ArtefactType.CERTIFICATE: 0.30,       # reissue and redeploy
    ArtefactType.KEY: 0.75,               # re-key and redistribute
    ArtefactType.CLOUD_SERVICE: 0.50,     # provider-managed rotation
    ArtefactType.HARDWARE_MODULE: 2.50,   # procurement, firmware, key ceremony
}

# An asymmetric primitive cannot be swapped unilaterally: both ends must
# negotiate it, which means a dual-stack period and interoperability testing.
# Raising a symmetric key size or a hash is a parameter change.
NEGOTIATION_MULTIPLIER = 1.20

COORDINATION_MULTIPLIER: Dict[BusinessCriticality, float] = {
    BusinessCriticality.CRITICAL: 1.30,   # change control, staged rollout
    BusinessCriticality.HIGH: 1.15,
    BusinessCriticality.MEDIUM: 1.00,
    BusinessCriticality.LOW: 1.00,
}

Y_FLOOR, Y_CEILING = 0.1, 6.0


def derive_migration_time_y(art: CryptographicArtefact) -> Tuple[float, Dict]:
    """
    Compute Y bottom-up from the evidence, and return the working alongside it.

    The breakdown is part of the contract: a number a reviewer cannot take apart
    is a number they cannot argue with, and an unarguable migration estimate is
    not worth putting in front of a budget holder.
    """
    control_base = BASE_CONTROL_YEARS.get(art.target_type, 0.5)
    artefact_base = BASE_ARTEFACT_YEARS.get(art.type)

    # An HSM discovered by reading source code still costs HSM time, so the
    # slower of the two bases wins rather than the more specific one.
    if artefact_base is not None and artefact_base > control_base:
        base, base_reason = artefact_base, f"{art.type.value} lifecycle"
    else:
        base, base_reason = control_base, f"{art.target_type.value} ownership"

    sites = max(1, art.occurrence_count or 1)
    spread = round(1.0 + 0.30 * math.log10(sites), 3)

    negotiation = (
        NEGOTIATION_MULTIPLIER
        if art.algorithm_class in (
            AlgorithmClass.ASYMMETRIC_FACTORING,
            AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
        )
        else 1.0
    )
    coordination = COORDINATION_MULTIPLIER.get(art.business_criticality, 1.0)

    # How the algorithm is wired in. Only the indirection part of the agility
    # score is used: the rest of it measures reach, ownership and negotiation,
    # all of which the three multipliers above already account for.
    from backend.analysis.agility import migration_multiplier, _indirection
    indirection_score, _ = _indirection(art)
    agility = migration_multiplier(indirection_score)

    y = base * spread * negotiation * coordination * agility
    y = round(min(Y_CEILING, max(Y_FLOOR, y)), 2)

    breakdown = {
        "base_years": base,
        "base_reason": base_reason,
        "occurrence_sites": sites,
        "spread_multiplier": spread,
        "negotiation_multiplier": negotiation,
        "coordination_multiplier": coordination,
        "agility_multiplier": agility,
        "result_years": y,
        "explanation": (
            f"{base:g}y base ({base_reason}) x {spread:g} for {sites} "
            f"occurrence{'s' if sites != 1 else ''}"
            + (f" x {negotiation:g} for two-party negotiation" if negotiation > 1 else "")
            + (f" x {coordination:g} for {art.business_criticality.value.lower()} "
               f"change control" if coordination > 1 else "")
            + (f" x {agility:g} for a hardcoded parameter" if agility > 1 else "")
            + (f" x {agility:g} for an already-indirected parameter"
               if agility < 1 else "")
            + f" = {y:g} years."
        ),
    }
    return y, breakdown


# ================================================================ Z: the horizon

# Cumulative probability that a cryptographically relevant quantum computer
# exists within N years, from the Global Risk Institute Quantum Threat Timeline
# Report 2025, which surveys 26 named experts.
#
# The 10-year and 15-year bands are the report's published figures. The 5, 20
# and 30-year rows are interpolated and extrapolated from them and are marked
# as such — they are not published values and must not be cited as if they were.
CRQC_PROBABILITY_CURVE: List[Tuple[float, float, float, str]] = [
    # (years from now, low, high, provenance)
    (0.0, 0.00, 0.00, "definition"),
    (5.0, 0.08, 0.15, "interpolated"),
    (10.0, 0.28, 0.49, "GRI 2025, published"),
    (15.0, 0.51, 0.70, "GRI 2025, published"),
    (20.0, 0.70, 0.85, "extrapolated"),
    (30.0, 0.90, 0.97, "extrapolated"),
]

CRQC_CURVE_SOURCE = (
    "Global Risk Institute, Quantum Threat Timeline Report 2025 "
    "(expert elicitation, n=26). 10-year and 15-year bands are published; "
    "other points are interpolated."
)

# The default point estimate for Z, in years. Eight years sits just inside the
# published 10-year band, which is the conservative end of it.
DEFAULT_Z_YEARS = 8.0


def crqc_probability_within(years: float) -> Tuple[float, float, str]:
    """
    (low, high, provenance) probability that a CRQC exists within `years`.

    Linear interpolation between the curve points. Reported as a band rather
    than a midpoint, because collapsing an expert range to a single number
    invents a precision the survey does not have.
    """
    if years <= 0:
        return 0.0, 0.0, "definition"
    if years >= CRQC_PROBABILITY_CURVE[-1][0]:
        _, lo, hi, prov = CRQC_PROBABILITY_CURVE[-1]
        return lo, hi, prov

    # A query that lands exactly on a curve point returns that point's own
    # provenance. Without this it falls into the span below it and inherits the
    # weaker of the two labels, so the published 10-year figure would report
    # itself as interpolated.
    for t, lo, hi, prov in CRQC_PROBABILITY_CURVE:
        if years == t:
            return lo, hi, prov

    for i in range(len(CRQC_PROBABILITY_CURVE) - 1):
        t0, lo0, hi0, prov0 = CRQC_PROBABILITY_CURVE[i]
        t1, lo1, hi1, prov1 = CRQC_PROBABILITY_CURVE[i + 1]
        if t0 <= years <= t1:
            f = (years - t0) / (t1 - t0) if t1 > t0 else 0.0
            lo = lo0 + f * (lo1 - lo0)
            hi = hi0 + f * (hi1 - hi0)
            # A span is only "published" if both ends of it are.
            prov = prov1 if prov0 == prov1 else "interpolated"
            return round(lo, 3), round(hi, 3), prov
    return 0.0, 0.0, "definition"


# ==================================================== regulatory deadline model

# Fixed dates by which a primitive stops being permitted, independent of any
# guess about when a quantum computer arrives. This is the model an auditor
# enforces, and the only one of the four with no estimation in it at all.
IR_8547 = "NIST IR 8547"
SP_800_131A = "NIST SP 800-131A Rev. 2"
CNSA_2 = "NSA CNSA 2.0"

_CLASSICAL_ASYMMETRIC = (
    AlgorithmClass.ASYMMETRIC_FACTORING,
    AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
)


# NIST SP 800-131A Rev. 2 disallows anything below 112 bits of classical
# security. That floor is what RSA-2048, DH-2048 and P-224 sit at; everything
# weaker is already prohibited, not awaiting a quantum computer.
CLASSICAL_SECURITY_FLOOR_BITS = 112

# Minimum modulus / curve size, in bits, that reaches the floor above.
_MIN_MODULUS_BITS = 2048   # RSA, DH, DSA — integer factoring and finite-field DL
_MIN_CURVE_BITS = 224      # elliptic-curve DL


def is_classically_broken(art: CryptographicArtefact) -> bool:
    """
    True when the primitive is already below NIST's classical security floor.

    This used to be tested only for RSA, so DSA-1024 and the short curves
    (secp160r1 at 80-bit, secp192r1 at 96-bit) were assessed as ordinary
    quantum-migration candidates with years of slack, when in fact they are
    disallowed today. Shor's algorithm is not the reason to replace them.
    """
    if art.algorithm_class == AlgorithmClass.LEGACY_BROKEN:
        return True
    if not art.key_size_bits:
        return False

    if art.algorithm_class == AlgorithmClass.ASYMMETRIC_FACTORING:
        return art.key_size_bits < _MIN_MODULUS_BITS

    if art.algorithm_class == AlgorithmClass.ASYMMETRIC_DISCRETE_LOG:
        # For elliptic curves key_size_bits holds the field size, not the
        # security strength — P-256 is 256 bits of field for 128 of security —
        # so the two cases need different floors. P-224 is the smallest curve
        # reaching the 112-bit floor.
        floor = _MIN_CURVE_BITS if art.curve else _MIN_MODULUS_BITS
        return art.key_size_bits < floor

    return False


def regulatory_deadline_for(art: CryptographicArtefact) -> Optional[RegulatoryDeadline]:
    """The date this asset stops being allowed, or None if nothing bars it."""
    if art.algorithm_class in (AlgorithmClass.POST_QUANTUM, AlgorithmClass.HYBRID):
        return None

    if is_classically_broken(art):
        return RegulatoryDeadline(
            authority=SP_800_131A,
            deprecated_on=date(2013, 12, 31),
            disallowed_on=date(2023, 12, 31),
            requirement="Already disallowed for federal use. This is overdue, not upcoming.",
        )

    if art.algorithm_class in _CLASSICAL_ASYMMETRIC:
        return RegulatoryDeadline(
            authority=IR_8547,
            deprecated_on=date(2030, 12, 31),
            disallowed_on=date(2035, 12, 31),
            requirement=(
                "RSA, DH, ECDH and ECDSA at 112-bit classical strength are "
                "deprecated after 2030 and disallowed after 2035."
            ),
        )

    if art.algorithm_class == AlgorithmClass.SYMMETRIC:
        if art.key_size_bits and art.key_size_bits < 256:
            return RegulatoryDeadline(
                authority=CNSA_2,
                deprecated_on=None,
                disallowed_on=date(2030, 12, 31),
                requirement=(
                    "AES-256 is required for national security systems. Below "
                    "256 bits there is no federal PQC deadline, but CNSA 2.0 "
                    "applies wherever NSS rules do."
                ),
                applies_only_to_nss=True,
            )
        return None

    if art.algorithm_class == AlgorithmClass.HASH:
        if art.key_size_bits and art.key_size_bits < 256:
            return RegulatoryDeadline(
                authority=CNSA_2,
                deprecated_on=None,
                disallowed_on=date(2030, 12, 31),
                requirement="CNSA 2.0 requires SHA-384 or SHA-512 for NSS.",
                applies_only_to_nss=True,
            )
        return None

    return None
