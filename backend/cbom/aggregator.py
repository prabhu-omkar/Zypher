"""
Artefact aggregation.

A CBOM describes the distinct cryptographic assets a system uses. The raw
extractor emits one artefact per textual match, so a file that calls
``hashlib.md5()`` on forty lines used to yield forty "assets" — inflating every
count, burying the genuinely distinct findings, and rendering forty identical
table rows and forty identical migration cards.

Aggregation collapses matches that describe the same cryptographic decision
into a single artefact carrying every occurrence, which is both what CycloneDX
1.6 models with ``evidence.occurrences`` and what a reviewer actually needs.
"""
from typing import Dict, List, Optional, Tuple

from backend.models import CryptographicArtefact, ArtefactOccurrence


# How much a parameter's provenance is worth, strongest last. Used when merging
# so a measured value is never displaced by an assumed one that happened to match.
PROVENANCE_RANK: Dict[Optional[str], int] = {
    None: 0,
    "assumed": 1,
    "literal": 2,
    "dataflow": 3,
}


def _identity(art: CryptographicArtefact) -> Tuple:
    """
    The properties that make two matches the same cryptographic asset.

    Location is deliberately included at file granularity: "RSA-2048 in
    auth_service.py" and "RSA-2048 in token_signer.py" are two things to fix,
    while the same call repeated on five lines of one file is one thing to fix.
    """
    return (
        art.algorithm_family,
        art.key_size_bits,
        art.curve,
        art.mode_or_padding,
        art.type,
        art.target_type,
        art.location,
    )


def aggregate_artefacts(artefacts: List[CryptographicArtefact]) -> List[CryptographicArtefact]:
    """
    Collapse duplicate artefacts, preserving every occurrence.

    The surviving artefact keeps the *highest* assessed severity inputs across
    its duplicates, so aggregation can never hide a worse finding behind a
    milder one: the longest shelf life, the longest migration time, and the
    strongest business criticality win.
    """
    grouped: Dict[Tuple, CryptographicArtefact] = {}

    criticality_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

    for art in artefacts:
        key = _identity(art)
        existing = grouped.get(key)

        occurrence = ArtefactOccurrence(
            location=art.location,
            line_number=art.line_number,
            snippet=art.code_snippet,
        )

        if existing is None:
            art.occurrences = [occurrence]
            art.occurrence_count = 1
            grouped[key] = art
            continue

        # Merge into the artefact already representing this asset.
        if not any(
            o.line_number == occurrence.line_number and o.location == occurrence.location
            for o in existing.occurrences
        ):
            existing.occurrences.append(occurrence)
        existing.occurrence_count = len(existing.occurrences)

        # Never let a merge soften the assessment.
        existing.data_shelf_life_years = max(
            existing.data_shelf_life_years, art.data_shelf_life_years
        )
        existing.migration_time_years = max(
            existing.migration_time_years, art.migration_time_years
        )
        if criticality_rank.get(art.business_criticality.value, 0) > criticality_rank.get(
            existing.business_criticality.value, 0
        ):
            existing.business_criticality = art.business_criticality

        # Keep the earliest line as the canonical pointer, so the UI links to
        # the first occurrence rather than an arbitrary one.
        if art.line_number is not None and (
            existing.line_number is None or art.line_number < existing.line_number
        ):
            existing.line_number = art.line_number
            existing.code_snippet = art.code_snippet

        # Provenance follows the same rule as the risk inputs above: a merge must
        # not weaken what is claimed. Two occurrences can agree on a key size with
        # one having measured it and the other having assumed it, and the merged
        # record should say the value was measured.
        if PROVENANCE_RANK.get(art.parameter_source, 0) > PROVENANCE_RANK.get(
            existing.parameter_source, 0
        ):
            existing.parameter_source = art.parameter_source
        existing.confidence_score = max(existing.confidence_score, art.confidence_score)

    aggregated = list(grouped.values())

    # Order by how much attention each asset deserves, so the first page of any
    # table is the part worth reading.
    aggregated.sort(
        key=lambda a: (
            -criticality_rank.get(a.business_criticality.value, 0),
            -a.occurrence_count,
            a.algorithm_family,
        )
    )
    return aggregated


def merge_artefact_sets(
    scans: List[Tuple[str, List[CryptographicArtefact]]]
) -> List[CryptographicArtefact]:
    """
    Union already-aggregated artefacts from several scans into one inventory.

    This is deliberately *not* ``aggregate_artefacts``. That function assumes it
    is receiving one raw match per artefact and rebuilds the occurrence list
    from scratch, which would discard the occurrences each stored scan has
    already accumulated. Here every input artefact already carries its own
    occurrences, so the lists are concatenated instead.

    Identity is the same as within a single scan, so the same asset found at the
    same location by two scans collapses to one entry — a rescan of the same
    target does not double the inventory — while the same algorithm in two
    different codebases stays two distinct things to fix.

    ``scans`` is a list of ``(scan_label, artefacts)``.
    """
    criticality_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    grouped: Dict[Tuple, CryptographicArtefact] = {}

    for label, artefacts in scans:
        for art in artefacts:
            key = _identity(art)
            existing = grouped.get(key)

            # Work on a copy: these objects come from stored scans and must not
            # be mutated by building the merged view.
            incoming = art.model_copy(deep=True)
            if not incoming.occurrences:
                incoming.occurrences = [
                    ArtefactOccurrence(
                        location=incoming.location,
                        line_number=incoming.line_number,
                        snippet=incoming.code_snippet,
                    )
                ]

            if existing is None:
                incoming.source_scans = [label]
                incoming.occurrence_count = len(incoming.occurrences)
                grouped[key] = incoming
                continue

            seen = {(o.location, o.line_number) for o in existing.occurrences}
            for occurrence in incoming.occurrences:
                if (occurrence.location, occurrence.line_number) not in seen:
                    existing.occurrences.append(occurrence)
                    seen.add((occurrence.location, occurrence.line_number))
            existing.occurrence_count = len(existing.occurrences)

            if label not in existing.source_scans:
                existing.source_scans.append(label)

            # As within a scan, a merge never softens the assessment.
            existing.data_shelf_life_years = max(
                existing.data_shelf_life_years, incoming.data_shelf_life_years
            )
            existing.migration_time_years = max(
                existing.migration_time_years, incoming.migration_time_years
            )
            if criticality_rank.get(incoming.business_criticality.value, 0) > criticality_rank.get(
                existing.business_criticality.value, 0
            ):
                existing.business_criticality = incoming.business_criticality

            if incoming.line_number is not None and (
                existing.line_number is None or incoming.line_number < existing.line_number
            ):
                existing.line_number = incoming.line_number
                existing.code_snippet = incoming.code_snippet

            # One scan may have had dataflow analysis available and another not.
            # The union should claim the better provenance it actually has.
            if PROVENANCE_RANK.get(incoming.parameter_source, 0) > PROVENANCE_RANK.get(
                existing.parameter_source, 0
            ):
                existing.parameter_source = incoming.parameter_source
            existing.confidence_score = max(
                existing.confidence_score, incoming.confidence_score
            )

    merged = list(grouped.values())
    merged.sort(
        key=lambda a: (
            -criticality_rank.get(a.business_criticality.value, 0),
            -a.occurrence_count,
            a.algorithm_family,
        )
    )
    return merged
