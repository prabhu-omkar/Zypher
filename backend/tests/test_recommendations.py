"""
Tests that a recommendation actually fits the asset it is attached to.

Every asset whose primitive was not recognised used to be classified as
SYMMETRIC by default, so the engine advised "migrate to AES-256-GCM" for
private key files, HSM references, cryptographic libraries and deprecated TLS
versions alike — advice that is meaningless for all four.
"""
import pytest

from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.recommendation.recommendation_engine import RecommendationEngine
from backend.models import (
    CryptographicArtefact, ArtefactType, AlgorithmClass,
    QuantumVulnerabilityStatus, BusinessCriticality, TargetType,
)


def _recommend(**kw):
    defaults = dict(
        id="ART-1",
        name="Asset",
        type=ArtefactType.ALGORITHM,
        algorithm_family="Unknown",
        location="app.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.UNKNOWN,
        quantum_vulnerability=QuantumVulnerabilityStatus.UNKNOWN,
        business_criticality=BusinessCriticality.MEDIUM,
        data_shelf_life_years=7.0,
        migration_time_years=2.0,
    )
    defaults.update(kw)
    art = CryptographicArtefact(**defaults)
    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)
    return RecommendationEngine.generate_recommendation(art, risk)


def test_rsa_gets_a_kem_target():
    rec = _recommend(
        algorithm_family="RSA", key_size_bits=2048,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
    )
    assert "ML-KEM" in rec.recommended_standard


def test_ecdsa_gets_a_signature_target():
    rec = _recommend(
        algorithm_family="ECDSA",
        algorithm_class=AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
    )
    assert "ML-DSA" in rec.recommended_standard


def test_aes_128_is_told_to_grow_its_key():
    rec = _recommend(
        algorithm_family="AES", key_size_bits=128,
        algorithm_class=AlgorithmClass.SYMMETRIC,
        quantum_vulnerability=QuantumVulnerabilityStatus.DEGRADED,
    )
    assert "AES-256" in rec.recommended_standard


def test_a_deprecated_protocol_is_told_to_upgrade_the_protocol():
    """Not "migrate to AES-256-GCM", which does not describe the fix."""
    rec = _recommend(
        type=ArtefactType.PROTOCOL,
        algorithm_family="Deprecated Protocol (SSL/TLS < 1.2)",
        algorithm_class=AlgorithmClass.LEGACY_BROKEN,
        quantum_vulnerability=QuantumVulnerabilityStatus.CLASSICALLY_BROKEN,
    )
    assert "TLS 1.3" in rec.recommended_standard
    assert "AES-256-GCM" not in rec.recommended_standard
    assert any("TLSv1.1" in s or "SSLv3" in s for s in rec.migration_steps)


def test_a_library_is_told_to_review_its_primitives():
    rec = _recommend(
        type=ArtefactType.LIBRARY,
        algorithm_family="Crypto-JS Suite",
    )
    assert "AES-256-GCM" not in rec.recommended_standard
    assert "librar" in rec.recommended_standard.lower()


def test_an_unidentified_key_is_told_to_identify_the_algorithm():
    rec = _recommend(
        type=ArtefactType.KEY,
        algorithm_family="Hardcoded-Private-Key",
    )
    assert "AES-256-GCM" not in rec.recommended_standard
    assert "identify" in rec.recommended_standard.lower()
    assert rec.is_hybrid_available is False, "no hybrid path can be claimed for an unknown primitive"


def test_an_hsm_reference_is_not_told_to_swap_ciphers():
    rec = _recommend(
        type=ArtefactType.HARDWARE_MODULE,
        algorithm_family="HSM/PKCS#11 Module",
        business_criticality=BusinessCriticality.CRITICAL,
    )
    assert "AES-256-GCM" not in rec.recommended_standard
    assert any("vendor" in s.lower() or "module" in s.lower() for s in rec.migration_steps)


def test_post_quantum_assets_are_told_to_stay_put():
    rec = _recommend(
        algorithm_family="ML-KEM",
        algorithm_class=AlgorithmClass.POST_QUANTUM,
        quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE,
    )
    assert "quantum-safe" in rec.recommended_standard.lower()


def test_hybrid_availability_is_only_claimed_when_a_path_is_named():
    named = _recommend(
        algorithm_family="RSA", key_size_bits=2048,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
    )
    assert named.is_hybrid_available is True
    assert named.hybrid_recommendation

    unnamed = _recommend(type=ArtefactType.KEY, algorithm_family="Hardcoded-Private-Key")
    assert unnamed.is_hybrid_available is False
    assert unnamed.hybrid_recommendation is None


@pytest.mark.parametrize(
    "artefact_type,family",
    [
        (ArtefactType.KEY, "Hardcoded-Private-Key"),
        (ArtefactType.CERTIFICATE, "X509-Certificate"),
        (ArtefactType.HARDWARE_MODULE, "HSM/PKCS#11 Module"),
        (ArtefactType.LIBRARY, "Crypto-JS Suite"),
        (ArtefactType.CLOUD_SERVICE, "Cloud KMS Service"),
    ],
)
def test_every_recommendation_has_actionable_steps(artefact_type, family):
    rec = _recommend(type=artefact_type, algorithm_family=family)
    assert rec.migration_steps, f"{artefact_type} produced no migration steps"
    assert rec.recommended_standard
    assert rec.migration_urgency
