"""
What changed between two scans.

A single scan says what the cryptography is. Two scans say whether it is getting
better or worse, which is the question a team actually has to answer every
sprint — and the one that turns this from an audit you run once into the
monitoring stage the migration plan depends on.

Assets are matched on the same identity the aggregator uses to deduplicate
within a scan, so "the same asset" means the same thing here as it does there.
Anything else would let a rename read as a removal plus an addition.
"""
from typing import Any, Dict, List, Optional, Tuple

from backend.models import CryptographicArtefact, MoscaRiskAssessment, ScanResult

# Worse to better, so a numeric comparison reads the way the words do.
_RISK_ORDER = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


def identity(art: CryptographicArtefact) -> Tuple:
    """
    What makes two findings the same asset across scans.

    The file path is included but not the line number: code moves down a file
    without becoming a different asset, and a scan that reported every shifted
    line as a removal plus an addition would be useless as a change report.
    """
    return (
        art.algorithm_family,
        art.type.value,
        (art.location or "").replace("\\", "/"),
    )


# The parameters that can change on an asset without it becoming a different
# asset. Deliberately excluded from the identity above: weakening RSA-2048 to
# RSA-1024 in the same file is one call site getting worse, and reporting it as
# a removal plus an unrelated addition hides exactly the event worth seeing.
_PARAMETERS = ("key_size_bits", "curve", "mode_or_padding")


def _parameter_changes(before: CryptographicArtefact,
                       after: CryptographicArtefact) -> Dict[str, Any]:
    changes = {}
    for field in _PARAMETERS:
        was, now = getattr(before, field), getattr(after, field)
        if was != now:
            changes[field] = {"before": was, "after": now}
    return changes


def _describe(art: CryptographicArtefact,
              risk: Optional[MoscaRiskAssessment]) -> Dict[str, Any]:
    return {
        "artefact_id": art.id,
        "name": art.name,
        "type": art.type.value,
        "algorithm_family": art.algorithm_family,
        "key_size_bits": art.key_size_bits,
        "location": art.location,
        "occurrence_count": art.occurrence_count,
        "risk_category": risk.risk_category.value if risk else None,
        "must_start_by": risk.must_start_by.isoformat()
        if risk and risk.must_start_by else None,
        "quantum_vulnerability": art.quantum_vulnerability.value,
    }


def compare_scans(before: ScanResult, after: ScanResult) -> Dict[str, Any]:
    """
    The difference between two scans of the same target.

    Reported as four disjoint sets plus the movement within the assets present
    in both, so every asset in either scan is accounted for exactly once and the
    totals can be checked against the scan counts.
    """
    before_index = {identity(a): a for a in before.artefacts}
    after_index = {identity(a): a for a in after.artefacts}

    added, removed, worsened, improved, changed, unchanged = [], [], [], [], [], []

    for key, art in after_index.items():
        risk = after.risk_assessments.get(art.id)
        if key not in before_index:
            added.append(_describe(art, risk))
            continue

        previous = before_index[key]
        previous_risk = before.risk_assessments.get(previous.id)
        entry = _describe(art, risk)
        entry["previous_risk_category"] = (
            previous_risk.risk_category.value if previous_risk else None
        )
        entry["previous_occurrence_count"] = previous.occurrence_count
        entry["previous_name"] = previous.name

        parameter_changes = _parameter_changes(previous, art)
        if parameter_changes:
            entry["parameter_changes"] = parameter_changes
        if art.occurrence_count != previous.occurrence_count:
            entry["occurrence_delta"] = (
                art.occurrence_count - previous.occurrence_count
            )

        now = _RISK_ORDER.get(entry["risk_category"], -1)
        was = _RISK_ORDER.get(entry["previous_risk_category"], -1)

        # One bucket per asset, by what matters most about the change: a band
        # movement first, then a parameter change that did not move the band.
        if now > was:
            worsened.append(entry)
        elif now < was:
            improved.append(entry)
        elif parameter_changes:
            changed.append(entry)
        else:
            unchanged.append(entry)

    for key, art in before_index.items():
        if key not in after_index:
            removed.append(_describe(art, before.risk_assessments.get(art.id)))

    def band_counts(result: ScanResult) -> Dict[str, int]:
        return dict(result.summary.risk_distribution)

    before_bands = band_counts(before)
    after_bands = band_counts(after)
    band_movement = {
        band: after_bands.get(band, 0) - before_bands.get(band, 0)
        for band in set(before_bands) | set(after_bands)
    }

    readiness_delta = round(
        after.summary.quantum_readiness_score
        - before.summary.quantum_readiness_score, 1
    )

    # New critical findings are called out separately because they are the only
    # part of a change report anybody reads first.
    new_critical = [
        e for e in added + worsened if e.get("risk_category") == "Critical"
    ]

    return {
        "before": {
            "scan_id": before.summary.scan_id,
            "target_name": before.summary.target_name,
            "created_at": before.summary.created_at.isoformat(),
            "total_artefacts": before.summary.total_artefacts,
            "quantum_readiness_score": before.summary.quantum_readiness_score,
        },
        "after": {
            "scan_id": after.summary.scan_id,
            "target_name": after.summary.target_name,
            "created_at": after.summary.created_at.isoformat(),
            "total_artefacts": after.summary.total_artefacts,
            "quantum_readiness_score": after.summary.quantum_readiness_score,
        },
        "added": added,
        "removed": removed,
        "risk_worsened": worsened,
        "risk_improved": improved,
        "parameters_changed": changed,
        "unchanged": unchanged,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "risk_worsened": len(worsened),
            "risk_improved": len(improved),
            "parameters_changed": len(changed),
            "unchanged": len(unchanged),
            "new_critical": len(new_critical),
        },
        "new_critical": new_critical,
        "band_movement": band_movement,
        "readiness_delta": readiness_delta,
        "verdict": _verdict(added, removed, worsened, improved, changed,
                            readiness_delta),
        "notes": _notes(before, after),
    }


def _verdict(added, removed, worsened, improved, changed,
             readiness_delta: float) -> str:
    if not (added or removed or worsened or improved or changed):
        return "No cryptographic change between these two scans."

    parts: List[str] = []
    if added:
        parts.append(f"{len(added)} new asset{'s' if len(added) != 1 else ''}")
    if removed:
        parts.append(f"{len(removed)} removed")
    if worsened:
        parts.append(f"{len(worsened)} moved to a worse band")
    if improved:
        parts.append(f"{len(improved)} improved")
    if changed:
        parts.append(
            f"{len(changed)} changed parameters without moving band"
        )

    direction = (
        "Readiness improved" if readiness_delta > 0
        else "Readiness fell" if readiness_delta < 0
        else "Readiness unchanged"
    )
    return f"{', '.join(parts)}. {direction} by {abs(readiness_delta):g} points."


def _notes(before: ScanResult, after: ScanResult) -> List[str]:
    """Anything that makes the comparison less than like-for-like."""
    notes: List[str] = []

    if before.summary.mosca_global_z != after.summary.mosca_global_z:
        notes.append(
            f"The two scans were assessed at different horizons "
            f"(Z = {before.summary.mosca_global_z:g} and "
            f"{after.summary.mosca_global_z:g} years), so a band change may "
            f"reflect the horizon rather than the code."
        )

    if before.summary.sensitivity_profile != after.summary.sensitivity_profile:
        notes.append(
            f"The data-sensitivity profile changed "
            f"('{before.summary.sensitivity_profile.value}' to "
            f"'{after.summary.sensitivity_profile.value}'), which changes X for "
            f"every asset. Band movement here is not a change in the code."
        )

    if before.summary.target_name != after.summary.target_name:
        notes.append(
            f"These are scans of differently named targets "
            f"('{before.summary.target_name}' and '{after.summary.target_name}'). "
            f"Comparing them is only meaningful if they are the same system."
        )

    before_files = before.summary.files_scanned or 0
    after_files = after.summary.files_scanned or 0
    if before_files and after_files:
        change = abs(after_files - before_files) / before_files
        if change > 0.25:
            notes.append(
                f"Coverage differs markedly between the scans "
                f"({before_files} files then, {after_files} now). Assets may "
                f"appear or disappear because of what was read, not what exists."
            )

    return notes
