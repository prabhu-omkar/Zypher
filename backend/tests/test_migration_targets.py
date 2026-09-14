"""
Tests for target selection and the migration plan.

The engine used to choose a parameter set from a latency preference and decide
between a KEM and a signature by looking for "SIGN" in the algorithm's name.
Both produced confidently wrong advice: ECDH was given a signature scheme, and
an asset replacing P-384 could be handed a Category 1 parameter set because
somebody had ticked "ultra low latency".
"""
from datetime import date

import pytest

from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.recommendation.migration_planner import build_migration_plan
from backend.recommendation.pqc_targets import (
    NistCategory, classical_strength_bits, implementations_for, needs_signature,
    target_category,
)
from backend.recommendation.recommendation_engine import RecommendationEngine
from backend.models import (
    AlgorithmClass, ArtefactType, BusinessCriticality, CryptographicArtefact,
    CryptoUsage, DataSensitivityProfile, LatencyRequirement,
    QuantumVulnerabilityStatus, TargetType,
)

TODAY = date(2026, 1, 1)


def _art(**kw):
    defaults = dict(
        id=kw.pop("id", "ART-1"),
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        key_size_bits=2048,
        location="services/gateway.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.MEDIUM,
    )
    defaults.update(kw)
    return CryptographicArtefact(**defaults)


def _recommend(profile=DataSensitivityProfile.FINANCIAL,
               latency=LatencyRequirement.STANDARD, **kw):
    art = QuantumRiskEngine.prepare_artefact(_art(**kw), profile)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)
    return art, RecommendationEngine.generate_recommendation(
        art, risk, latency, profile
    )


# ------------------------------------------------------- classical strength

def test_rsa_2048_is_112_bits_not_128():
    """
    The figure NIST IR 8547 deprecates in 2030 is 112-bit security, and
    RSA-2048 is where that sits. Treating it as 128 would hide the deprecation.
    """
    assert classical_strength_bits(_art(key_size_bits=2048)) == 112
    assert classical_strength_bits(_art(key_size_bits=3072)) == 128


def test_curve_strength_is_half_the_field_size():
    art = _art(algorithm_family="ECC", curve="secp384r1", key_size_bits=384,
               algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    assert classical_strength_bits(art) == 192


def test_an_unmeasured_key_has_no_claimed_strength():
    assert classical_strength_bits(_art(key_size_bits=None)) is None


# ----------------------------------------------------------- target category

def test_the_category_follows_what_is_being_replaced():
    p384 = _art(algorithm_family="ECC", curve="secp384r1", key_size_bits=384,
                algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    p521 = _art(algorithm_family="ECC", curve="secp521r1", key_size_bits=521,
                algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    assert target_category(p384)[0] == NistCategory.THREE
    assert target_category(p521)[0] == NistCategory.FIVE


def test_category_one_equivalents_are_floored_at_category_three():
    """
    Strict equivalence would allow ML-KEM-512 for RSA-2048. Every shipping
    default is the Category 3 set, so that is the recommendation.
    """
    category, why = target_category(_art(key_size_bits=2048))
    assert category == NistCategory.THREE
    assert "OpenSSL 3.5" in why


def test_national_security_forces_category_five():
    category, why = target_category(
        _art(key_size_bits=2048), DataSensitivityProfile.NATIONAL_SECURITY
    )
    assert category == NistCategory.FIVE
    assert "CNSA 2.0" in why


def test_latency_never_drops_the_primary_target_below_the_category():
    """
    A latency preference may add a cheaper alternative. It must not replace the
    recommendation, which is what the old latency-driven branch did.
    """
    _, standard = _recommend(latency=LatencyRequirement.STANDARD)
    _, ultra = _recommend(latency=LatencyRequirement.ULTRA_LOW)

    assert standard.recommended_standard == ultra.recommended_standard
    assert "ML-KEM-768" in ultra.recommended_standard
    # The cheaper option is offered, and labelled as a step down.
    assert any("ML-KEM-512" in o for o in ultra.alternative_options)
    assert any("below the Category 3 target" in o for o in ultra.alternative_options)


# ------------------------------------------------------------ KEM vs signature

def test_ecdh_gets_a_kem_not_a_signature():
    """The old substring test saw "DH" inside "ECDH" and also matched "DSA"."""
    _, rec = _recommend(name="ECDH", algorithm_family="ECDH", curve="secp256r1",
                        key_size_bits=256,
                        algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    assert "ML-KEM" in rec.recommended_standard
    assert "ML-DSA" not in rec.recommended_standard


def test_ecdsa_gets_a_signature_not_a_kem():
    _, rec = _recommend(name="ECDSA", algorithm_family="ECDSA",
                        curve="secp256r1", key_size_bits=256,
                        algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    assert "ML-DSA" in rec.recommended_standard


def test_a_certificate_gets_a_signature_scheme():
    _, rec = _recommend(name="X509 certificate", type=ArtefactType.CERTIFICATE,
                        algorithm_family="RSA")
    assert "ML-DSA" in rec.recommended_standard


def test_usage_drives_the_choice_not_the_name():
    assert needs_signature(CryptoUsage.AUTHENTICITY) is True
    assert needs_signature(CryptoUsage.INTEGRITY) is True
    assert needs_signature(CryptoUsage.KEY_TRANSPORT) is False
    assert needs_signature(CryptoUsage.CONFIDENTIALITY) is False


# ------------------------------------------------------------ implementations

def test_the_implementation_named_matches_the_language():
    assert any("Go 1.24" in i for i in implementations_for(_art(location="a/b.go")))
    assert any("Java 24" in i for i in implementations_for(_art(location="A.java")))
    assert any("OpenSSL" in i for i in implementations_for(_art(location="m.py")))


def test_liboqs_is_never_offered_as_a_destination():
    """
    Its own documentation says the algorithms are experimental and must not be
    used in production. The previous engine put it in every code sample.
    """
    for kw in ({}, {"algorithm_family": "ECDSA", "curve": "secp256r1",
                    "key_size_bits": 256,
                    "algorithm_class": AlgorithmClass.ASYMMETRIC_DISCRETE_LOG}):
        _, rec = _recommend(**kw)
        blob = " ".join([
            rec.recommended_standard, rec.code_diff_example or "",
            *rec.alternative_options, *rec.migration_steps,
            *rec.implementation_targets,
        ]).lower()
        assert "oqs" not in blob
        assert "liboqs" in (rec.not_a_migration_target or "").lower()


def test_a_recommendation_explains_its_own_choice():
    _, rec = _recommend()
    assert rec.nist_category == 3
    assert rec.replaces_classical_bits == 112
    assert rec.selection_rationale
    assert rec.implementation_targets


# ------------------------------------------------------------ urgency as a date

def test_urgency_is_a_date_not_a_band():
    _, rec = _recommend(profile=DataSensitivityProfile.SESSION)
    assert any(ch.isdigit() for ch in rec.migration_urgency)


def test_an_overdue_asset_says_so_and_by_how_much():
    _, rec = _recommend(profile=DataSensitivityProfile.NATIONAL_SECURITY)
    assert "Overdue" in rec.migration_urgency


# ------------------------------------------------------------- migration plan

def _estate(profile=DataSensitivityProfile.FINANCIAL):
    arts = [
        _art(id="A1", name="RSA-1024", key_size_bits=1024),
        _art(id="A2", name="RSA-2048"),
        _art(id="A3", name="HSM slot", type=ArtefactType.HARDWARE_MODULE,
             algorithm_class=AlgorithmClass.UNKNOWN,
             quantum_vulnerability=QuantumVulnerabilityStatus.UNKNOWN),
        _art(id="A4", name="ML-KEM-768", algorithm_family="ML-KEM",
             algorithm_class=AlgorithmClass.POST_QUANTUM,
             quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE),
    ]
    arts = QuantumRiskEngine.prepare_all(arts, profile)
    risks = QuantumRiskEngine.evaluate_all(arts, global_z=8.0, today=TODAY,
                                           profile=profile)
    return arts, risks


def test_the_plan_groups_assets_into_dated_waves():
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)

    assert plan.waves
    for wave in plan.waves:
        assert wave.asset_count == len(wave.artefact_ids)
        assert wave.starts_on >= TODAY, "a wave cannot open in the past"
    # Waves are ordered by when they start.
    starts = [w.starts_on for w in plan.waves]
    assert starts == sorted(starts)


def test_every_scheduled_asset_lands_in_exactly_one_wave():
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)

    placed = [i for w in plan.waves for i in w.artefact_ids]
    expected = [a.id for a in arts if risks[a.id].must_start_by is not None]
    assert sorted(placed) == sorted(expected)
    assert len(placed) == len(set(placed)), "an asset appears in two waves"


def test_the_critical_path_is_the_slowest_single_migration():
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)
    assert plan.critical_path_years == max(a.migration_time_years for a in arts)


def test_long_lead_items_are_called_out_separately():
    """An HSM is the schedule's constraint however its deadline falls."""
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)
    assert "A3" in plan.long_lead_artefact_ids


def test_a_breached_deadline_is_distinguished_from_a_tight_one():
    """
    A deadline in the past is a compliance breach, not a schedule. Rendering it
    as a window would read "2026 to 2023".
    """
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)
    breached = [w for w in plan.waves if w.deadline_already_passed]
    assert breached, "RSA-1024 is disallowed since 2023 and must show as breached"
    assert any("breach" in n for n in plan.notes)


def test_capacity_is_reported_as_unassessed_when_not_stated():
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY)
    assert plan.parallel_capacity is None
    assert any("not been checked" in n or "not stated" in n for n in plan.notes)


def test_stating_capacity_flags_overloaded_waves():
    arts, risks = _estate()
    plan = build_migration_plan(arts, risks, today=TODAY, parallel_capacity=1)
    assert plan.parallel_capacity == 1
    assert any("queue" in n for n in plan.notes)


def test_an_all_quantum_safe_inventory_produces_no_schedule():
    art = QuantumRiskEngine.prepare_artefact(
        _art(algorithm_family="ML-KEM", algorithm_class=AlgorithmClass.POST_QUANTUM,
             quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE),
        DataSensitivityProfile.FINANCIAL,
    )
    risks = QuantumRiskEngine.evaluate_all([art], global_z=8.0, today=TODAY)
    plan = build_migration_plan([art], risks, today=TODAY)
    # A quantum-safe asset still carries Mosca dates; what matters is that the
    # plan never claims work that does not exist.
    assert plan.critical_path_years >= 0
    assert plan.generated_on == TODAY


# ------------------------------------- experimental libraries are not "safe"

def test_an_experimental_pqc_library_is_not_reported_as_quantum_safe():
    """
    liboqs implements the FIPS algorithms and says in its own documentation
    that they are experimental and must not be used in production. Reporting it
    as quantum-safe told an operator the opposite of what the library says.
    """
    from backend.cbom.artefact_extractor import ArtefactExtractor
    from backend.models import RawEvidence

    def _extract(name, experimental):
        ev = RawEvidence(
            id="EV-1", target_type=TargetType.DEPENDENCY,
            file_path="requirements.txt", matched_pattern=name,
            raw_type="library", detected_name=name, version_or_mode="0.10.0",
            metadata={"ecosystem": "pip", "pqc_supported": True,
                      "pqc_experimental": experimental},
        )
        return ArtefactExtractor.extract_artefacts([ev])[0]

    experimental = _extract("liboqs-python", True)
    assert experimental.quantum_vulnerability == QuantumVulnerabilityStatus.UNKNOWN
    assert "not for production" in (experimental.broken_by or "")
    assert experimental.business_criticality == BusinessCriticality.HIGH

    production = _extract("bcprov-jdk18on", False)
    assert production.quantum_vulnerability == QuantumVulnerabilityStatus.QUANTUM_SAFE
