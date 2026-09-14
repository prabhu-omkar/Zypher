"""
Tests for risk banding and the readiness score.

The HIGH band was unreachable in practice: the extractor pre-assigned HIGH or
CRITICAL business criticality to nearly every artefact, and the classifier
escalated anything whose path contained "crypto" or "auth" — which in a
cryptography codebase is almost everything. Every at-risk asset therefore landed
in CRITICAL and real scans reported `"High": 0` at every horizon.
"""
from backend.analysis.classifier import Classifier
from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.main import compute_readiness_score
from backend.models import (
    CryptographicArtefact, ArtefactType, AlgorithmClass,
    QuantumVulnerabilityStatus, BusinessCriticality, TargetType, RiskCategory,
)


def _art(location="services/report_builder.py", **kw):
    defaults = dict(
        id=kw.pop("id", "ART-1"),
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        key_size_bits=2048,
        location=location,
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.MEDIUM,
        data_shelf_life_years=10.0,
        migration_time_years=2.0,
    )
    defaults.update(kw)
    return CryptographicArtefact(**defaults)


def test_at_risk_standard_criticality_lands_in_high_not_critical():
    """X+Y > Z with ordinary criticality is HIGH; this band must be reachable."""
    art = Classifier.classify_artefact(_art(location="services/report_builder.py"))
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)

    assert risk.is_at_risk is True
    assert risk.risk_category == RiskCategory.HIGH


def test_at_risk_in_a_sensitive_context_escalates_to_critical():
    art = Classifier.classify_artefact(_art(location="services/payments/gateway.py"))
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)

    assert art.business_criticality == BusinessCriticality.HIGH
    assert risk.risk_category == RiskCategory.CRITICAL


def test_the_word_crypto_in_a_path_no_longer_escalates_everything():
    """
    The old substring match fired on "crypto" and "private", which appear in
    almost every path of a cryptography project — including this tool's own.
    """
    art = Classifier.classify_artefact(_art(location="backend/crypto/utils.py"))
    assert art.business_criticality == BusinessCriticality.MEDIUM


def test_a_narrow_safety_margin_is_medium():
    art = _art(data_shelf_life_years=5.0, migration_time_years=2.0)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)  # margin 1.0
    assert risk.is_at_risk is False
    assert risk.risk_category == RiskCategory.MEDIUM


def test_a_comfortable_margin_is_low():
    art = _art(data_shelf_life_years=2.0, migration_time_years=1.0)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)  # margin 5.0
    assert risk.risk_category == RiskCategory.LOW


def test_shortening_the_horizon_moves_assets_into_risk():
    art = _art(data_shelf_life_years=5.0, migration_time_years=2.0)
    assert QuantumRiskEngine.evaluate_artefact(art, global_z=20.0).risk_category == RiskCategory.LOW
    assert QuantumRiskEngine.evaluate_artefact(art, global_z=3.0).is_at_risk is True


def test_post_quantum_algorithms_are_always_low():
    art = _art(
        algorithm_family="ML-KEM",
        algorithm_class=AlgorithmClass.POST_QUANTUM,
        quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE,
        data_shelf_life_years=30.0,
        migration_time_years=10.0,
    )
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=1.0)
    assert risk.risk_category == RiskCategory.LOW
    assert risk.is_at_risk is False


def test_classically_broken_primitives_are_always_critical():
    art = _art(
        algorithm_family="Legacy Symmetric Cipher (DES/3DES/RC4)",
        algorithm_class=AlgorithmClass.LEGACY_BROKEN,
        quantum_vulnerability=QuantumVulnerabilityStatus.CLASSICALLY_BROKEN,
        data_shelf_life_years=1.0,
        migration_time_years=0.5,
    )
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=20.0)
    assert risk.risk_category == RiskCategory.CRITICAL


def test_readiness_score_spans_the_full_range():
    """An all-safe inventory scores 100; an all-critical one scores 0."""
    safe = [_art(id=f"S{i}", location=f"m{i}.py", data_shelf_life_years=1.0,
                 migration_time_years=0.5) for i in range(4)]
    safe_risks = QuantumRiskEngine.evaluate_all(safe, global_z=20.0)
    assert compute_readiness_score(safe, safe_risks) == 100.0

    broken = [
        _art(id=f"B{i}", location=f"x{i}.py",
             algorithm_class=AlgorithmClass.LEGACY_BROKEN,
             quantum_vulnerability=QuantumVulnerabilityStatus.CLASSICALLY_BROKEN)
        for i in range(4)
    ]
    broken_risks = QuantumRiskEngine.evaluate_all(broken, global_z=8.0)
    assert compute_readiness_score(broken, broken_risks) == 0.0


def test_readiness_score_is_independent_of_inventory_size():
    """The same proportion of weak crypto scores the same in a big estate."""
    def estate(n):
        arts = []
        for i in range(n):
            if i % 2 == 0:
                arts.append(_art(id=f"C{i}", location=f"a{i}.py",
                                 algorithm_class=AlgorithmClass.LEGACY_BROKEN,
                                 quantum_vulnerability=QuantumVulnerabilityStatus.CLASSICALLY_BROKEN))
            else:
                arts.append(_art(id=f"L{i}", location=f"b{i}.py",
                                 data_shelf_life_years=1.0, migration_time_years=0.5))
        risks = QuantumRiskEngine.evaluate_all(arts, global_z=20.0)
        return compute_readiness_score(arts, risks)

    assert estate(4) == estate(40)


def test_an_empty_inventory_scores_full_marks():
    assert compute_readiness_score([], {}) == 100.0
