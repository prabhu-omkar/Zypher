"""
Tests for crypto-agility scoring and scan-to-scan comparison.

Agility is scored in the sense NIST CSWP 39 uses it: can the algorithm be
replaced without disrupting what depends on it? The thing these tests guard most
carefully is that the score does not leak back into the migration estimate
twice — Y already models reach, ownership and negotiation, so only the factor Y
cannot see is allowed to move it.
"""
from datetime import date, datetime, timezone

import pytest

from backend.analysis import agility
from backend.analysis.delta import compare_scans, identity
from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.analysis.risk_inputs import derive_migration_time_y
from backend.models import (
    AlgorithmClass, ArtefactType, BusinessCriticality, CryptographicArtefact,
    DataSensitivityProfile, MoscaRiskAssessment, QuantumVulnerabilityStatus,
    RiskCategory, ScanResult, ScanSummary, TargetType,
)


def _art(**kw):
    defaults = dict(
        id=kw.pop("id", "ART-1"),
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        key_size_bits=2048,
        location="services/report_builder.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.MEDIUM,
    )
    defaults.update(kw)
    return CryptographicArtefact(**defaults)


# ============================================================ agility scoring

def test_a_hardcoded_parameter_scores_worse_than_an_indirected_one():
    hardcoded = agility.score_artefact(_art(parameter_source="literal"))
    indirected = agility.score_artefact(_art(parameter_source="dataflow"))
    assert indirected["score"] > hardcoded["score"]
    assert indirected["factors"]["indirection"]["score"] > \
        hardcoded["factors"]["indirection"]["score"]


def test_configuration_is_more_agile_than_source_which_beats_a_binary():
    config = agility.score_artefact(_art(location="deploy/tls.yaml"))
    source = agility.score_artefact(_art(location="app/service.py"))
    binary = agility.score_artefact(_art(target_type=TargetType.BINARY,
                                         location="vendor/libcrypto.so"))
    scores = [
        config["factors"]["configurability"]["score"],
        source["factors"]["configurability"]["score"],
        binary["factors"]["configurability"]["score"],
    ]
    assert scores == sorted(scores, reverse=True)


def test_hardware_is_the_least_agile_thing_in_an_estate():
    hsm = agility.score_artefact(_art(type=ArtefactType.HARDWARE_MODULE))
    assert hsm["factors"]["configurability"]["score"] <= 10
    assert "procurement" in hsm["factors"]["configurability"]["reason"]


def test_spread_reduces_agility_sub_linearly():
    one = agility.score_artefact(_art(occurrence_count=1))
    ten = agility.score_artefact(_art(occurrence_count=10))
    thousand = agility.score_artefact(_art(occurrence_count=1000))

    concentration = [e["factors"]["concentration"]["score"]
                     for e in (one, ten, thousand)]
    assert concentration == sorted(concentration, reverse=True)
    # A thousand sites is harder than one, not a thousand times harder.
    assert concentration[-1] > 0


def test_a_symmetric_cipher_is_more_substitutable_than_an_asymmetric_one():
    symmetric = agility.score_artefact(
        _art(algorithm_class=AlgorithmClass.SYMMETRIC, algorithm_family="AES")
    )
    asymmetric = agility.score_artefact(_art())
    assert symmetric["factors"]["substitutability"]["score"] > \
        asymmetric["factors"]["substitutability"]["score"]
    assert "negotiate" in asymmetric["factors"]["substitutability"]["reason"]


def test_an_unidentified_primitive_cannot_be_called_substitutable():
    unknown = agility.score_artefact(
        _art(algorithm_class=AlgorithmClass.UNKNOWN, algorithm_family="Unknown")
    )
    assert unknown["factors"]["substitutability"]["score"] <= 40


def test_the_bands_are_all_reachable():
    rigid = agility.score_artefact(
        _art(target_type=TargetType.BINARY, parameter_source="literal",
             occurrence_count=500, algorithm_class=AlgorithmClass.UNKNOWN,
             type=ArtefactType.HARDWARE_MODULE)
    )
    agile = agility.score_artefact(
        _art(location="deploy/tls.yaml", parameter_source="dataflow",
             occurrence_count=1, algorithm_class=AlgorithmClass.SYMMETRIC)
    )
    assert rigid["band"] == agility.BAND_RIGID
    assert agile["band"] == agility.BAND_AGILE


def test_the_summary_names_the_binding_constraint():
    entry = agility.score_artefact(_art(type=ArtefactType.HARDWARE_MODULE))
    assert "configurability" in entry["summary"]


def test_only_indirection_moves_the_migration_estimate():
    """
    Y already models occurrence spread, ownership and two-party negotiation.
    Folding the whole agility score into it would count all three twice.
    """
    spread_only = _art(occurrence_count=400, parameter_source="literal")
    concentrated = _art(occurrence_count=1, parameter_source="literal")

    # Same indirection, so the same agility multiplier despite very different
    # overall agility scores.
    _, wide = derive_migration_time_y(spread_only)
    _, narrow = derive_migration_time_y(concentrated)
    assert wide["agility_multiplier"] == narrow["agility_multiplier"]
    assert agility.score_artefact(spread_only)["score"] != \
        agility.score_artefact(concentrated)["score"]


def test_a_hardcoded_parameter_lengthens_y_and_says_so():
    _, hardcoded = derive_migration_time_y(_art(parameter_source="literal"))
    _, indirected = derive_migration_time_y(_art(parameter_source="dataflow"))

    assert hardcoded["agility_multiplier"] > 1.0
    assert indirected["agility_multiplier"] < 1.0
    assert hardcoded["result_years"] > indirected["result_years"]
    assert "hardcoded parameter" in hardcoded["explanation"]


def test_the_estate_summary_counts_the_rigid_assets():
    scores = agility.score_all([
        _art(id="A", type=ArtefactType.HARDWARE_MODULE, parameter_source="literal",
             algorithm_class=AlgorithmClass.UNKNOWN, target_type=TargetType.BINARY,
             occurrence_count=500),
        _art(id="B", location="deploy/tls.yaml", parameter_source="dataflow",
             algorithm_class=AlgorithmClass.SYMMETRIC),
    ])
    summary = agility.estate_summary(scores)
    assert summary["rigid_count"] == 1
    assert summary["average_score"] is not None
    assert sum(summary["band_distribution"].values()) == 2


def test_an_empty_estate_has_no_agility_figure():
    assert agility.estate_summary({})["average_score"] is None


# ============================================================ scan comparison

def _summary(scan_id, artefacts, risks, z=8.0, readiness=50.0,
             profile=DataSensitivityProfile.FINANCIAL, files=10):
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for risk in risks.values():
        distribution[risk.risk_category.value] += 1
    return ScanSummary(
        scan_id=scan_id, target_name="Service",
        target_types=[TargetType.SOURCE_CODE],
        created_at=datetime.now(timezone.utc),
        total_artefacts=len(artefacts), risk_distribution=distribution,
        vulnerability_distribution={}, quantum_readiness_score=readiness,
        mosca_global_z=z, sensitivity_profile=profile, files_scanned=files,
    )


def _risk(artefact_id, band):
    return MoscaRiskAssessment(
        artefact_id=artefact_id, shelf_life_x=7.0, migration_time_y=1.0,
        threat_timeline_z=8.0, x_plus_y=8.0, is_at_risk=False,
        safety_margin_years=0.0, risk_category=band, explanation="",
        affected_data_type="", system_exposure="",
        must_start_by=date(2028, 1, 1), must_complete_by=date(2029, 1, 1),
    )


def _scan(scan_id, artefacts, bands, **kw):
    risks = {a.id: _risk(a.id, band) for a, band in zip(artefacts, bands)}
    return ScanResult(
        summary=_summary(scan_id, artefacts, risks, **kw),
        artefacts=artefacts, risk_assessments=risks, recommendations={},
    )


def test_identity_ignores_parameters_so_a_weakened_key_is_not_a_new_asset():
    strong = _art(key_size_bits=2048, location="app/auth.py")
    weak = _art(key_size_bits=1024, location="app/auth.py")
    assert identity(strong) == identity(weak)


def test_identity_separates_the_same_algorithm_in_different_files():
    assert identity(_art(location="a.py")) != identity(_art(location="b.py"))


def test_a_new_asset_is_reported_as_added():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.LOW])
    after = _scan("S2", [
        _art(id="A", location="a.py"),
        _art(id="B", algorithm_family="MD5/SHA-1", location="b.py"),
    ], [RiskCategory.LOW, RiskCategory.CRITICAL])

    delta = compare_scans(before, after)
    assert delta["counts"]["added"] == 1
    assert delta["counts"]["removed"] == 0
    assert delta["added"][0]["algorithm_family"] == "MD5/SHA-1"
    assert delta["counts"]["new_critical"] == 1


def test_a_removed_asset_is_reported_as_removed():
    before = _scan("S1", [_art(id="A", location="a.py"),
                          _art(id="B", location="b.py")],
                   [RiskCategory.LOW, RiskCategory.HIGH])
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.LOW])

    delta = compare_scans(before, after)
    assert delta["counts"]["removed"] == 1
    assert delta["counts"]["added"] == 0


def test_a_band_movement_is_reported_with_both_bands():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.MEDIUM])
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.CRITICAL])

    delta = compare_scans(before, after)
    assert delta["counts"]["risk_worsened"] == 1
    entry = delta["risk_worsened"][0]
    assert entry["previous_risk_category"] == "Medium"
    assert entry["risk_category"] == "Critical"
    assert delta["counts"]["new_critical"] == 1


def test_an_improvement_is_reported_too():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.CRITICAL])
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.LOW])
    delta = compare_scans(before, after)
    assert delta["counts"]["risk_improved"] == 1
    assert delta["counts"]["new_critical"] == 0


def test_a_parameter_change_that_does_not_move_the_band_is_still_reported():
    """Weakening a key inside the same band is exactly the change to catch."""
    before = _scan("S1", [_art(id="A", key_size_bits=4096, location="a.py")],
                   [RiskCategory.HIGH])
    after = _scan("S2", [_art(id="A", key_size_bits=2048, location="a.py")],
                  [RiskCategory.HIGH])

    delta = compare_scans(before, after)
    assert delta["counts"]["parameters_changed"] == 1
    changes = delta["parameters_changed"][0]["parameter_changes"]
    assert changes["key_size_bits"] == {"before": 4096, "after": 2048}


def test_every_asset_lands_in_exactly_one_bucket():
    before = _scan("S1", [_art(id=f"A{i}", location=f"{i}.py") for i in range(4)],
                   [RiskCategory.LOW] * 4)
    after = _scan("S2", [_art(id=f"A{i}", location=f"{i}.py") for i in range(1, 6)],
                  [RiskCategory.LOW] * 5)

    delta = compare_scans(before, after)
    counted = (delta["counts"]["added"] + delta["counts"]["removed"]
               + delta["counts"]["risk_worsened"] + delta["counts"]["risk_improved"]
               + delta["counts"]["parameters_changed"] + delta["counts"]["unchanged"])
    # Four before, five after, three in common: 1 removed + 2 added + 3 unchanged.
    assert counted == 6
    assert delta["counts"]["removed"] == 1
    assert delta["counts"]["added"] == 2


def test_an_unchanged_scan_says_nothing_changed():
    artefacts = [_art(id="A", location="a.py")]
    before = _scan("S1", artefacts, [RiskCategory.LOW])
    after = _scan("S2", artefacts, [RiskCategory.LOW])
    delta = compare_scans(before, after)
    assert "No cryptographic change" in delta["verdict"]


def test_a_horizon_change_is_flagged_as_not_a_code_change():
    """A band that moved because Z moved is not a finding about the code."""
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.LOW], z=15.0)
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.CRITICAL], z=4.0)

    delta = compare_scans(before, after)
    assert any("different horizons" in n for n in delta["notes"])


def test_a_profile_change_is_flagged_as_not_a_code_change():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.LOW],
                   profile=DataSensitivityProfile.SESSION)
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.CRITICAL],
                  profile=DataSensitivityProfile.NATIONAL_SECURITY)

    delta = compare_scans(before, after)
    assert any("data-sensitivity profile changed" in n for n in delta["notes"])


def test_a_large_coverage_difference_is_flagged():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.LOW], files=100)
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.LOW], files=20)

    delta = compare_scans(before, after)
    assert any("Coverage differs" in n for n in delta["notes"])


def test_the_readiness_movement_is_reported():
    before = _scan("S1", [_art(id="A", location="a.py")], [RiskCategory.LOW],
                   readiness=80.0)
    after = _scan("S2", [_art(id="A", location="a.py")], [RiskCategory.CRITICAL],
                  readiness=20.0)
    delta = compare_scans(before, after)
    assert delta["readiness_delta"] == -60.0
    assert "Readiness fell" in delta["verdict"]
