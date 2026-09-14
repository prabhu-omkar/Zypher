"""
Tests for artefact aggregation.

Without aggregation, a file calling hashlib.md5() on forty lines reported forty
distinct cryptographic assets, inflating every count on the dashboard and
rendering forty identical rows and migration cards.
"""
from backend.cbom.aggregator import aggregate_artefacts
from backend.models import (
    CryptographicArtefact, ArtefactType, AlgorithmClass,
    QuantumVulnerabilityStatus, BusinessCriticality, TargetType,
)


def _art(**kw):
    defaults = dict(
        id=kw.pop("id", "ART-1"),
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        key_size_bits=2048,
        location="auth.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.MEDIUM,
        data_shelf_life_years=10.0,
        migration_time_years=2.0,
    )
    defaults.update(kw)
    return CryptographicArtefact(**defaults)


def test_repeated_matches_in_one_file_collapse_to_one_asset():
    arts = [_art(id=f"ART-{i}", line_number=i) for i in range(1, 41)]
    result = aggregate_artefacts(arts)

    assert len(result) == 1
    assert result[0].occurrence_count == 40
    assert len(result[0].occurrences) == 40


def test_the_same_algorithm_in_different_files_stays_separate():
    """Two files using RSA-2048 are two things to fix, not one."""
    arts = [_art(id="A", location="auth.py"), _art(id="B", location="tokens.py")]
    assert len(aggregate_artefacts(arts)) == 2


def test_different_key_sizes_stay_separate():
    arts = [
        _art(id="A", key_size_bits=1024, name="RSA-1024"),
        _art(id="B", key_size_bits=4096, name="RSA-4096"),
    ]
    assert len(aggregate_artefacts(arts)) == 2


def test_aggregation_never_softens_the_assessment():
    """
    Merging must keep the worst inputs, so a milder duplicate cannot mask a
    severe finding.
    """
    arts = [
        _art(id="A", line_number=1, business_criticality=BusinessCriticality.LOW,
             data_shelf_life_years=3.0, migration_time_years=1.0),
        _art(id="B", line_number=2, business_criticality=BusinessCriticality.CRITICAL,
             data_shelf_life_years=15.0, migration_time_years=5.0),
    ]
    merged = aggregate_artefacts(arts)[0]

    assert merged.business_criticality == BusinessCriticality.CRITICAL
    assert merged.data_shelf_life_years == 15.0
    assert merged.migration_time_years == 5.0


def test_canonical_pointer_is_the_first_occurrence():
    arts = [_art(id="A", line_number=90), _art(id="B", line_number=12)]
    assert aggregate_artefacts(arts)[0].line_number == 12


def test_most_severe_assets_sort_first():
    arts = [
        _art(id="A", location="a.py", business_criticality=BusinessCriticality.LOW),
        _art(id="B", location="b.py", business_criticality=BusinessCriticality.CRITICAL),
        _art(id="C", location="c.py", business_criticality=BusinessCriticality.MEDIUM),
    ]
    order = [a.business_criticality for a in aggregate_artefacts(arts)]
    assert order[0] == BusinessCriticality.CRITICAL
    assert order[-1] == BusinessCriticality.LOW


def test_duplicate_occurrence_on_the_same_line_is_not_double_counted():
    arts = [_art(id="A", line_number=7), _art(id="B", line_number=7)]
    assert aggregate_artefacts(arts)[0].occurrence_count == 1


def test_empty_input_is_handled():
    assert aggregate_artefacts([]) == []
