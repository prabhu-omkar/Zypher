"""
Tests for the derivation of X, Y and Z, and for the four risk models.

The engine used to read all three straight off a constant table keyed on the
algorithm name, which made X a property of the primitive rather than of the data
it protects, and Y a property of the primitive rather than of who has to change
it. These tests pin the properties that fix depends on.

Dates are pinned rather than taken from the clock: a schedule test that passes
in September and fails in October is not a test.
"""
from datetime import date

import pytest

from backend.analysis.risk_inputs import (
    classify_usage, crqc_probability_within, derive_migration_time_y,
    derive_shelf_life_x, regulatory_deadline_for,
)
from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.models import (
    AlgorithmClass, ArtefactType, BusinessCriticality, CryptographicArtefact,
    CryptoUsage, DataSensitivityProfile, QuantumVulnerabilityStatus,
    RiskCategory, RiskModel, TargetType,
)

TODAY = date(2026, 1, 1)


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


# ------------------------------------------------------------------ X: shelf life

def test_x_comes_from_the_data_profile_not_the_algorithm():
    """
    The same primitive protecting different classes of data must not get the
    same X. This is the defect the whole derivation exists to fix.
    """
    session = QuantumRiskEngine.prepare_artefact(
        _art(), DataSensitivityProfile.SESSION
    )
    health = QuantumRiskEngine.prepare_artefact(
        _art(), DataSensitivityProfile.HEALTH
    )
    assert session.data_shelf_life_years == 0.5
    assert health.data_shelf_life_years == 25.0


def test_an_authenticity_asset_does_not_inherit_the_retention_period():
    """
    A signature only has to resist forgery while the credential is trusted.
    Harvest-now-decrypt-later does not apply to it, so a 25-year retention
    policy must not push a certificate's X to 25 years.
    """
    cert = QuantumRiskEngine.prepare_artefact(
        _art(type=ArtefactType.CERTIFICATE, name="ECDSA P-256 certificate",
             algorithm_family="ECDSA"),
        DataSensitivityProfile.HEALTH,
    )
    assert cert.crypto_usage == CryptoUsage.AUTHENTICITY
    assert cert.data_shelf_life_years == 1.5
    assert "not the 25-year data retention" in cert.shelf_life_rationale


def test_a_confidentiality_asset_does_inherit_the_retention_period():
    aes = QuantumRiskEngine.prepare_artefact(
        _art(name="AES-128", algorithm_family="AES", key_size_bits=128,
             algorithm_class=AlgorithmClass.SYMMETRIC),
        DataSensitivityProfile.HEALTH,
    )
    assert aes.crypto_usage == CryptoUsage.CONFIDENTIALITY
    assert aes.data_shelf_life_years == 25.0


def test_key_agreement_is_not_mistaken_for_a_signature():
    """"ECDH" contains "DH" and "DSA"-like substrings; it is still key transport."""
    assert classify_usage(_art(name="ECDH", algorithm_family="ECDH",
                               algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)) \
        == CryptoUsage.KEY_TRANSPORT
    assert classify_usage(_art(name="ECDSA", algorithm_family="ECDSA",
                               algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)) \
        == CryptoUsage.AUTHENTICITY


def test_an_unidentifiable_asset_takes_the_longer_x():
    """Ambiguity resolves toward the conservative reading, never the gentler one."""
    unknown = QuantumRiskEngine.prepare_artefact(
        _art(name="private_key.pem", type=ArtefactType.KEY,
             algorithm_family="Unknown", algorithm_class=AlgorithmClass.UNKNOWN),
        DataSensitivityProfile.FINANCIAL,
    )
    assert unknown.data_shelf_life_years == 7.0  # retention, not a validity window


def test_an_explicit_retention_policy_overrides_the_profile():
    art = QuantumRiskEngine.prepare_artefact(
        _art(), DataSensitivityProfile.FINANCIAL, retention_override=12.0
    )
    assert art.data_shelf_life_years == 12.0


def test_a_per_asset_override_beats_the_scan_wide_one():
    art = QuantumRiskEngine.prepare_artefact(
        _art(shelf_life_override_years=40.0),
        DataSensitivityProfile.SESSION, retention_override=2.0,
    )
    assert art.data_shelf_life_years == 40.0


# --------------------------------------------------------------- Y: migration time

def test_y_reflects_who_has_to_make_the_change():
    """Your own source is faster to fix than a vendor binary you cannot rebuild."""
    owned, _ = derive_migration_time_y(_art(target_type=TargetType.SOURCE_CODE))
    dependency, _ = derive_migration_time_y(_art(target_type=TargetType.DEPENDENCY))
    binary, _ = derive_migration_time_y(_art(target_type=TargetType.BINARY))
    assert owned < dependency < binary


def test_y_grows_with_how_far_the_asset_reaches():
    one, _ = derive_migration_time_y(_art(occurrence_count=1))
    many, _ = derive_migration_time_y(_art(occurrence_count=500))
    assert many > one
    # Sub-linear: 500 sites is not 500 times the work.
    assert many < one * 3


def test_an_hsm_costs_hsm_time_even_when_found_in_source():
    """
    The slower of the two bases wins. An HSM reference discovered by reading
    source code still means procurement and a key ceremony.
    """
    y, breakdown = derive_migration_time_y(
        _art(type=ArtefactType.HARDWARE_MODULE, target_type=TargetType.SOURCE_CODE)
    )
    assert y >= 2.5
    assert "hardware_module" in breakdown["base_reason"]


def test_a_protocol_config_change_is_the_cheapest_fix():
    protocol, _ = derive_migration_time_y(
        _art(type=ArtefactType.PROTOCOL, algorithm_class=AlgorithmClass.LEGACY_BROKEN)
    )
    assert protocol <= 0.3


def test_y_shows_its_working():
    _, breakdown = derive_migration_time_y(_art(occurrence_count=10))
    assert breakdown["occurrence_sites"] == 10
    assert breakdown["result_years"] == pytest.approx(
        breakdown["base_years"] * breakdown["spread_multiplier"]
        * breakdown["negotiation_multiplier"] * breakdown["coordination_multiplier"],
        abs=0.01,
    )
    assert "occurrence" in breakdown["explanation"]


# ------------------------------------------------------------------- Z and models

def test_the_crqc_curve_is_a_band_and_is_monotonic():
    lo5, hi5, _ = crqc_probability_within(5)
    lo10, hi10, prov10 = crqc_probability_within(10)
    lo15, hi15, _ = crqc_probability_within(15)

    assert lo5 < lo10 < lo15
    assert hi5 < hi10 < hi15
    # The 10-year figures are the published ones and must not drift.
    assert (lo10, hi10) == (0.28, 0.49)
    assert prov10 == "GRI 2025, published"


def test_interpolated_points_are_labelled_as_such():
    _, _, provenance = crqc_probability_within(7)
    assert provenance != "GRI 2025, published"


def test_all_four_models_report_on_an_ordinary_asset():
    art = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.FINANCIAL)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)

    models = {v.model for v in risk.model_verdicts}
    assert models == {
        RiskModel.MOSCA, RiskModel.PROBABILISTIC, RiskModel.REGULATORY,
        RiskModel.HNDL,
    }
    # Every verdict names where it came from.
    assert all(v.source for v in risk.model_verdicts)


def test_the_regulatory_deadline_binds_when_it_lands_first():
    """
    A short-lived secret is comfortable under Mosca but still hits a fixed
    standards deadline, and the earlier of the two is the one that governs.
    """
    art = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.SESSION)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=25.0, today=TODAY)

    assert risk.binding_model == RiskModel.REGULATORY
    assert risk.must_complete_by == date(2035, 12, 31)


def test_the_regulatory_model_is_silent_for_post_quantum_assets():
    assert regulatory_deadline_for(
        _art(algorithm_class=AlgorithmClass.POST_QUANTUM)
    ) is None


def test_an_nss_only_deadline_is_reported_but_does_not_create_risk():
    """CNSA 2.0 binds national security systems. It must not be applied to
    everyone else as though it did."""
    art = _art(name="AES-128", algorithm_family="AES", key_size_bits=128,
               algorithm_class=AlgorithmClass.SYMMETRIC)
    deadline = regulatory_deadline_for(art)
    assert deadline is not None and deadline.applies_only_to_nss

    art = QuantumRiskEngine.prepare_artefact(art, DataSensitivityProfile.SESSION)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=25.0, today=TODAY)
    regulatory = next(
        v for v in risk.model_verdicts if v.model == RiskModel.REGULATORY
    )
    assert regulatory.at_risk is False


# ------------------------------------------------------------------- the schedule

def test_the_engine_produces_dates_not_just_a_band():
    art = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.FINANCIAL)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=15.0, today=TODAY)

    assert risk.must_start_by is not None
    assert risk.must_complete_by is not None
    assert risk.must_start_by < risk.must_complete_by
    assert risk.assessed_on == TODAY
    assert risk.crqc_estimated_on.year == 2041  # 2026 + 15


def test_an_asset_whose_start_date_has_passed_is_flagged_overdue():
    art = QuantumRiskEngine.prepare_artefact(
        _art(), DataSensitivityProfile.NATIONAL_SECURITY
    )
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)

    assert risk.is_overdue is True
    assert risk.must_start_by < TODAY
    assert risk.slack_years < 0


def test_a_longer_horizon_pushes_the_start_date_out():
    art = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.FINANCIAL)
    near = QuantumRiskEngine.evaluate_artefact(art, global_z=6.0, today=TODAY)
    far = QuantumRiskEngine.evaluate_artefact(art, global_z=12.0, today=TODAY)
    assert far.must_start_by > near.must_start_by


# ------------------------------------------------------------------------- HNDL

def test_hndl_exposure_is_a_magnitude_not_a_boolean():
    art = QuantumRiskEngine.prepare_artefact(
        _art(), DataSensitivityProfile.NATIONAL_SECURITY
    )
    exposed = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)
    assert exposed.hndl_exposure_years > 0

    safe = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.SESSION)
    unexposed = QuantumRiskEngine.evaluate_artefact(safe, global_z=25.0, today=TODAY)
    assert unexposed.hndl_exposure_years == 0.0


def test_a_quantum_safe_asset_carries_no_deadline_at_any_horizon():
    art = QuantumRiskEngine.prepare_artefact(
        _art(algorithm_family="ML-KEM", name="ML-KEM-768",
             algorithm_class=AlgorithmClass.POST_QUANTUM,
             quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE),
        DataSensitivityProfile.NATIONAL_SECURITY,
    )
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=1.0, today=TODAY)
    assert risk.risk_category == RiskCategory.LOW
    assert risk.is_at_risk is False


def test_the_assessment_carries_the_reasoning_through():
    art = QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.FINANCIAL)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)

    assert risk.crypto_usage == CryptoUsage.KEY_TRANSPORT
    assert risk.shelf_life_rationale
    assert risk.migration_time_explanation
    assert risk.probability_source and "Global Risk Institute" in risk.probability_source


# --------------------------------------------------------------------- banding

def _with(x, y, **kw):
    art = _art(**kw)
    art.data_shelf_life_years = x
    art.migration_time_years = y
    art.crypto_usage = CryptoUsage.KEY_TRANSPORT
    art.shelf_life_rationale = "pinned by the test"
    return art


def test_under_a_year_of_slack_is_high_even_for_an_ordinary_asset():
    """
    A band that lumps "start next week" together with "start in three years"
    tells a planner nothing. Below a year the work is effectively due now.
    """
    risk = QuantumRiskEngine.evaluate_artefact(
        _with(7.5, 0.2), global_z=8.0, today=TODAY,
    )
    assert 0 <= risk.slack_years < 1
    assert risk.risk_category == RiskCategory.HIGH


def test_comfortable_slack_stays_low_however_critical_the_asset():
    """
    Consequence sharpens an urgent band; it does not invent urgency. Escalating
    here would park a sensitive estate permanently in MEDIUM.
    """
    risk = QuantumRiskEngine.evaluate_artefact(
        _with(2.0, 0.5, business_criticality=BusinessCriticality.CRITICAL),
        global_z=20.0, today=TODAY,
    )
    assert risk.risk_category == RiskCategory.LOW


def test_business_criticality_sharpens_an_urgent_band():
    ordinary = QuantumRiskEngine.evaluate_artefact(
        _with(9.0, 2.0, business_criticality=BusinessCriticality.MEDIUM),
        global_z=8.0, today=TODAY,
    )
    sensitive = QuantumRiskEngine.evaluate_artefact(
        _with(9.0, 2.0, business_criticality=BusinessCriticality.CRITICAL),
        global_z=8.0, today=TODAY,
    )
    assert ordinary.risk_category == RiskCategory.HIGH
    assert sensitive.risk_category == RiskCategory.CRITICAL


def test_stored_inputs_are_not_silently_re_derived():
    """
    An artefact reloaded from a stored scan must keep the X and Y it was audited
    with. Re-deriving them on read would rewrite the audited record whenever the
    profile defaults changed.
    """
    art = _with(13.0, 4.0)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)
    assert risk.shelf_life_x == 13.0
    assert risk.migration_time_y == 4.0


# --------------------------------------------------- the classical security floor

def test_short_curves_are_recognised_as_already_disallowed():
    """
    secp160r1 gives 80-bit and secp192r1 96-bit classical security, both below
    the 112-bit floor in SP 800-131A. The check used to apply to RSA only, so
    these were assessed as ordinary migration candidates with years of slack.
    """
    for curve, bits in [("secp160r1", 80), ("secp192r1", 96)]:
        art = _art(name=f"ECC ({curve})", algorithm_family="ECC", curve=curve,
                   key_size_bits=bits,
                   algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
        risk = QuantumRiskEngine.evaluate_artefact(
            QuantumRiskEngine.prepare_artefact(art, DataSensitivityProfile.SESSION),
            global_z=25.0, today=TODAY,
        )
        assert risk.risk_category == RiskCategory.CRITICAL, curve


def test_dsa_1024_is_recognised_as_already_disallowed():
    art = _art(name="DSA-1024", algorithm_family="Diffie-Hellman / DSA",
               key_size_bits=1024,
               algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    risk = QuantumRiskEngine.evaluate_artefact(
        QuantumRiskEngine.prepare_artefact(art, DataSensitivityProfile.SESSION),
        global_z=25.0, today=TODAY,
    )
    assert risk.risk_category == RiskCategory.CRITICAL


def test_curves_at_or_above_the_floor_are_not_swept_up():
    # key_size_bits carries the curve's field size, not its security strength:
    # P-256 is 256 bits of field for 128 bits of security.
    art = _art(name="ECC (secp256r1)", algorithm_family="ECC", curve="secp256r1",
               key_size_bits=256,
               algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG)
    risk = QuantumRiskEngine.evaluate_artefact(
        QuantumRiskEngine.prepare_artefact(art, DataSensitivityProfile.SESSION),
        global_z=25.0, today=TODAY,
    )
    assert risk.risk_category != RiskCategory.CRITICAL


def test_rsa_2048_is_above_the_floor():
    risk = QuantumRiskEngine.evaluate_artefact(
        QuantumRiskEngine.prepare_artefact(_art(), DataSensitivityProfile.SESSION),
        global_z=25.0, today=TODAY,
    )
    assert risk.risk_category != RiskCategory.CRITICAL


# ------------------------------------------- quantum safety short-circuits

def _safe(**kw):
    defaults = dict(
        algorithm_family="AES", key_size_bits=256,
        algorithm_class=AlgorithmClass.SYMMETRIC,
        quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE,
        business_criticality=BusinessCriticality.HIGH,
    )
    defaults.update(kw)
    art = QuantumRiskEngine.prepare_artefact(
        _art(**defaults), DataSensitivityProfile.FINANCIAL
    )
    return QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)


def test_an_asset_safe_by_key_length_is_not_banded_by_mosca():
    """
    AES-256 is quantum-safe by having enough key length, which is recorded as a
    vulnerability status and not as an algorithm class. The short-circuit tested
    the class alone, so these fell through to slack banding and were reported as
    high risk directly beside a "Quantum-safe" badge.
    """
    risk = _safe()
    assert risk.risk_category == RiskCategory.LOW
    assert risk.is_at_risk is False
    assert risk.is_overdue is False


def test_a_quantum_safe_asset_carries_no_deadline_and_no_exposure():
    risk = _safe()
    assert risk.must_start_by is None
    assert risk.must_complete_by is None
    assert risk.slack_years is None
    assert risk.binding_model is None
    # The probabilistic verdict would otherwise claim this asset's protection
    # "lapses" at X+Y, and HNDL would claim harvestable years. Neither is true.
    assert risk.hndl_exposure_years == 0.0
    assert risk.breach_probability_high is None
    assert all(v.at_risk is False for v in risk.model_verdicts)
    assert all("Not applicable" in v.detail for v in risk.model_verdicts)


def test_a_long_lived_secret_does_not_make_a_safe_asset_risky():
    """X + Y > Z is arithmetically true here; it still says nothing."""
    art = QuantumRiskEngine.prepare_artefact(
        _art(algorithm_family="AES", key_size_bits=256,
             algorithm_class=AlgorithmClass.SYMMETRIC,
             quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE),
        DataSensitivityProfile.NATIONAL_SECURITY,   # X = 50 years
    )
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0, today=TODAY)
    assert risk.x_plus_y > risk.threat_timeline_z
    assert risk.risk_category == RiskCategory.LOW


def test_a_hash_safe_at_its_digest_length_is_also_cleared():
    risk = _safe(algorithm_family="SHA-2 / SHA-3", key_size_bits=384,
                 algorithm_class=AlgorithmClass.HASH)
    assert risk.risk_category == RiskCategory.LOW


def test_a_degraded_asset_is_still_assessed():
    """AES-128 is weakened by Grover and genuinely does need a key upgrade."""
    risk = _safe(key_size_bits=128,
                 quantum_vulnerability=QuantumVulnerabilityStatus.DEGRADED)
    assert risk.risk_category != RiskCategory.LOW
    assert risk.must_start_by is not None


def test_an_unidentified_asset_is_never_cleared_as_safe():
    risk = _safe(algorithm_family="Unknown", key_size_bits=None,
                 algorithm_class=AlgorithmClass.UNKNOWN,
                 quantum_vulnerability=QuantumVulnerabilityStatus.UNKNOWN)
    assert risk.risk_category != RiskCategory.LOW
