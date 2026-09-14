import pytest
from backend.models import TargetType, RiskCategory, BusinessCriticality
from backend.scanners.source_scanner import SourceCodeScanner
from backend.scanners.binary_scanner import BinaryScanner
from backend.scanners.dependency_scanner import DependencyScanner
from backend.scanners.container_scanner import ContainerScanner
from backend.cbom.artefact_extractor import ArtefactExtractor
from backend.cbom.cbom_builder import CBOMBuilder
from backend.analysis.classifier import Classifier
from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.recommendation.recommendation_engine import RecommendationEngine
from backend.main import execute_pipeline


def test_source_code_scanner(sample_tree):
    scanner = SourceCodeScanner()
    evidences = scanner.scan_file(str(sample_tree / "source_repo" / "auth_service.py"))
    assert len(evidences) > 0
    # Should detect RSA, ECDSA, MD5, and AWS KMS
    detected_algs = [e.detected_name for e in evidences]
    assert "RSA" in detected_algs
    assert "ECC" in detected_algs
    assert "MD5/SHA-1" in detected_algs


def test_binary_scanner(sample_tree):
    scanner = BinaryScanner()
    evidences = scanner.scan_file(str(sample_tree / "binaries" / "crypto_firmware.bin"))
    assert len(evidences) > 0
    detected = [e.detected_name for e in evidences]
    assert "AES" in detected or "SHA-256" in detected or "MD5" in detected


def test_dependency_scanner(sample_tree):
    scanner = DependencyScanner()
    evidences = scanner.scan_file(str(sample_tree / "dependencies" / "package.json"))
    assert len(evidences) >= 3
    names = [e.matched_pattern for e in evidences]
    assert "crypto-js" in names
    assert "elliptic" in names


def test_container_scanner(sample_tree):
    scanner = ContainerScanner()
    evidences = scanner.scan_dockerfile(str(sample_tree / "containers" / "Dockerfile"))
    assert len(evidences) >= 2


def test_mosca_algorithm():
    # Test Mosca Calculation X + Y > Z
    # Case 1: X=10, Y=2, Z=8 -> X+Y=12 > 8 (At Risk -> Critical with High Criticality)
    from backend.models import CryptographicArtefact, ArtefactType, AlgorithmClass, QuantumVulnerabilityStatus
    
    art = CryptographicArtefact(
        id="TEST-1",
        name="RSA-2048",
        type=ArtefactType.ALGORITHM,
        algorithm_family="RSA",
        location="auth.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.ASYMMETRIC_FACTORING,
        quantum_vulnerability=QuantumVulnerabilityStatus.FULLY_BROKEN,
        business_criticality=BusinessCriticality.HIGH,
        data_shelf_life_years=10.0,
        migration_time_years=2.0
    )

    risk = QuantumRiskEngine.evaluate_artefact(art, global_z=8.0)
    assert risk.is_at_risk is True
    assert risk.x_plus_y == 12.0
    assert risk.risk_category == RiskCategory.CRITICAL

    # Case 2: Post Quantum FIPS 203 ML-KEM
    art_pqc = CryptographicArtefact(
        id="TEST-2",
        name="ML-KEM-768",
        type=ArtefactType.ALGORITHM,
        algorithm_family="ML-KEM",
        location="kem.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.POST_QUANTUM,
        quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE,
        business_criticality=BusinessCriticality.LOW,
        data_shelf_life_years=10.0,
        migration_time_years=0.0
    )
    risk_pqc = QuantumRiskEngine.evaluate_artefact(art_pqc, global_z=8.0)
    assert risk_pqc.is_at_risk is False
    assert risk_pqc.risk_category == RiskCategory.LOW


def test_cyclonedx_cbom_generation():
    from backend.models import CryptographicArtefact, ArtefactType, AlgorithmClass, QuantumVulnerabilityStatus
    art = CryptographicArtefact(
        id="ART-001",
        name="AES-256-GCM",
        type=ArtefactType.ALGORITHM,
        algorithm_family="AES",
        key_size_bits=256,
        mode_or_padding="GCM",
        location="cipher.py",
        target_type=TargetType.SOURCE_CODE,
        algorithm_class=AlgorithmClass.SYMMETRIC,
        quantum_vulnerability=QuantumVulnerabilityStatus.QUANTUM_SAFE,
        business_criticality=BusinessCriticality.MEDIUM
    )
    cbom = CBOMBuilder.build_cyclonedx_cbom([art], target_name="TestApp")
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 1
    assert cbom["components"][0]["cryptoProperties"]["assetType"] == "algorithm"


def test_full_pipeline_execution(sample_tree):
    from backend.scanners.source_scanner import SourceCodeScanner
    scanner = SourceCodeScanner()
    evidences = scanner.scan_file(str(sample_tree / "source_repo" / "auth_service.py"))
    result = execute_pipeline("TestAuthService", TargetType.SOURCE_CODE, evidences, mosca_z=8.0)
    assert result.summary.total_artefacts > 0
    assert len(result.risk_assessments) == result.summary.total_artefacts
    assert len(result.recommendations) == result.summary.total_artefacts
