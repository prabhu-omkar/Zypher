"""
Tests for X.509 certificate discovery.

A certificate was previously found by the source scanner noticing the text
"-----BEGIN CERTIFICATE-----" and recording an asset whose algorithm was
"unknown" — the least useful possible result for the one artefact type that
states its own cryptography in machine-readable form.
"""
import datetime

import pytest

from backend.analysis.quantum_risk_engine import QuantumRiskEngine
from backend.cbom.artefact_extractor import ArtefactExtractor
from backend.models import (
    AlgorithmClass, ArtefactType, BusinessCriticality, CryptoUsage,
    DataSensitivityProfile,
)
from backend.scanners.certificate_scanner import CertificateScanner

cryptography = pytest.importorskip("cryptography")
from cryptography import x509                                   # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa     # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402


def _write_certificate(path, common_name, key, starts_in_days, expires_in_days,
                       ca=False, encoding=serialization.Encoding.PEM):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=starts_in_days))
        .not_valid_after(now + datetime.timedelta(days=expires_in_days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    certificate = builder.sign(key, hashes.SHA256())
    path.write_bytes(certificate.public_bytes(encoding))
    return certificate


def _rsa(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


@pytest.fixture
def scanner():
    s = CertificateScanner()
    if not s.is_available():
        pytest.skip("cryptography is not installed")
    return s


# ----------------------------------------------------------------- parsing

def test_an_rsa_certificate_reports_its_real_key_size(scanner, tmp_path):
    path = tmp_path / "api.pem"
    _write_certificate(path, "api.example.com", _rsa(2048), -1, 365)

    evidence = scanner.scan_file(str(path))
    assert len(evidence) == 1
    found = evidence[0]

    assert found.key_length == 2048
    assert found.raw_type == "certificate"
    assert "RSA" in found.detected_name
    assert found.metadata["subject"] == "api.example.com"
    assert found.metadata["is_expired"] is False


def test_an_ec_certificate_reports_its_curve(scanner, tmp_path):
    path = tmp_path / "edge.crt"
    _write_certificate(path, "edge.example.com", ec.generate_private_key(ec.SECP384R1()), -1, 365)

    found = scanner.scan_file(str(path))[0]
    assert found.curve_name == "secp384r1"
    # The field size, which is what the rest of the pipeline expects for a curve.
    assert found.key_length == 384
    assert "ECDSA" in found.detected_name


def test_der_encoding_is_read_as_well_as_pem(scanner, tmp_path):
    path = tmp_path / "binary.der"
    _write_certificate(path, "der.example.com", _rsa(), -1, 365,
                       encoding=serialization.Encoding.DER)

    found = scanner.scan_file(str(path))[0]
    assert found.key_length == 2048
    assert found.metadata["subject"] == "der.example.com"


def test_a_bundle_yields_every_certificate_in_it(scanner, tmp_path):
    first = tmp_path / "a.pem"
    second = tmp_path / "b.pem"
    _write_certificate(first, "first.example.com", _rsa(), -1, 365)
    _write_certificate(second, "second.example.com", _rsa(), -1, 365)

    bundle = tmp_path / "chain.ca-bundle"
    bundle.write_bytes(first.read_bytes() + second.read_bytes())

    evidence = scanner.scan_file(str(bundle))
    assert len(evidence) == 2
    assert {e.metadata["subject"] for e in evidence} == {
        "first.example.com", "second.example.com"
    }
    assert all(e.metadata["certificates_in_file"] == 2 for e in evidence)


def test_a_file_that_does_not_parse_is_reported_not_skipped(scanner, tmp_path):
    """A certificate the tool could not open is not a certificate that is safe."""
    path = tmp_path / "broken.pem"
    path.write_text("this is not a certificate")

    found = scanner.scan_file(str(path))[0]
    assert found.metadata["unreadable"] is True
    assert "could not be parsed" in found.detected_name


def test_only_certificate_extensions_are_accepted(scanner, tmp_path):
    assert scanner.accepts("a/b/server.pem") is True
    assert scanner.accepts("a/b/server.crt") is True
    assert scanner.accepts("a/b/chain.ca-bundle") is True
    assert scanner.accepts("a/b/main.py") is False
    assert scanner.accepts("a/b/private.key") is False


def test_an_oversized_file_is_not_read(scanner, tmp_path):
    path = tmp_path / "huge.pem"
    path.write_bytes(b"x" * (2 * 1024 * 1024))
    assert scanner.scan_file(str(path)) == []


# ------------------------------------------------------------- expiry facts

def test_an_expired_certificate_is_flagged(scanner, tmp_path):
    path = tmp_path / "old.pem"
    _write_certificate(path, "old.example.com", _rsa(), -400, -10)

    found = scanner.scan_file(str(path))[0]
    assert found.metadata["is_expired"] is True
    assert found.metadata["days_until_expiry"] < 0


def test_the_validity_window_is_measured_not_assumed(scanner, tmp_path):
    path = tmp_path / "three-year.pem"
    _write_certificate(path, "long.example.com", _rsa(), 0, 1095)

    found = scanner.scan_file(str(path))[0]
    assert found.metadata["validity_years"] == pytest.approx(3.0, abs=0.02)


# --------------------------------------------------- through the extractor

def _artefact(evidence):
    return ArtefactExtractor.extract_artefacts([evidence])[0]


def test_a_certificate_is_classified_by_its_real_algorithm(scanner, tmp_path):
    """
    Certificates used to land in the "primitive not identified" branch, which
    told the operator to go and find out what algorithm it was — from an
    artefact that states it.
    """
    path = tmp_path / "api.pem"
    _write_certificate(path, "api.example.com", _rsa(2048), -1, 365)
    artefact = _artefact(scanner.scan_file(str(path))[0])

    assert artefact.type == ArtefactType.CERTIFICATE
    assert artefact.algorithm_class == AlgorithmClass.ASYMMETRIC_FACTORING
    assert artefact.key_size_bits == 2048
    assert artefact.measured_validity_years == pytest.approx(1.0, abs=0.02)


def test_the_measured_validity_becomes_x(scanner, tmp_path):
    """
    For an authenticity asset X is the window the credential is trusted. A real
    notAfter beats the conventional default, and must not be replaced by the
    data-retention period even under a long-retention profile.
    """
    path = tmp_path / "api.pem"
    _write_certificate(path, "api.example.com", _rsa(), 0, 1095)   # three years
    artefact = QuantumRiskEngine.prepare_artefact(
        _artefact(scanner.scan_file(str(path))[0]), DataSensitivityProfile.HEALTH
    )

    assert artefact.crypto_usage == CryptoUsage.AUTHENTICITY
    assert artefact.data_shelf_life_years == pytest.approx(3.0, abs=0.02)
    assert artefact.data_shelf_life_years != 25.0, "must not take the retention period"
    assert "read from the certificate" in artefact.shelf_life_rationale


def test_an_expired_certificate_says_so_in_the_finding(scanner, tmp_path):
    path = tmp_path / "old.pem"
    _write_certificate(path, "old.example.com", _rsa(), -400, -10)
    artefact = _artefact(scanner.scan_file(str(path))[0])

    assert "expired" in (artefact.broken_by or "").lower()
    assert artefact.business_criticality == BusinessCriticality.CRITICAL


def test_an_imminent_expiry_is_called_out(scanner, tmp_path):
    path = tmp_path / "soon.pem"
    _write_certificate(path, "soon.example.com", _rsa(), -1, 9)
    artefact = _artefact(scanner.scan_file(str(path))[0])
    assert "expires in" in (artefact.broken_by or "").lower()


def test_a_certificate_authority_is_treated_as_critical(scanner, tmp_path):
    """Replacing a CA is a chain-wide change, not a single reissue."""
    path = tmp_path / "root.pem"
    _write_certificate(path, "Root CA", _rsa(), -1, 3650, ca=True)
    artefact = _artefact(scanner.scan_file(str(path))[0])
    assert artefact.business_criticality == BusinessCriticality.CRITICAL


def test_the_asset_is_named_for_its_subject_not_its_signature_algorithm(
    scanner, tmp_path
):
    """
    Appending the signature OID produced "RSA-2048-sha256WithRSAEncryption",
    which reads as a primitive nobody has heard of.
    """
    path = tmp_path / "api.pem"
    _write_certificate(path, "api.example.com", _rsa(), -1, 365)
    artefact = _artefact(scanner.scan_file(str(path))[0])

    assert "api.example.com" in artefact.name
    assert "sha256WithRSAEncryption" not in artefact.name
