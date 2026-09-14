"""
Tests for YARA-backed binary signature matching.

The binary scanner used to carry its signatures as Python data and match them
with a loop of `bytes.find` calls. Moving them to a YARA rule file makes each
signature data rather than code, matches every pattern in one pass, and lets the
same rules be used by any other YARA-capable tool.

Two properties are load-bearing:

* **Coverage cannot silently shrink.** A refactor that quietly stopped detecting
  AES or MD5 would be invisible without a test that names each algorithm.
* **Unavailability is not a clean result.** If the engine or the rules fail to
  load, the scanner must fall back to its built-in tables, not report a binary
  as containing no cryptography.
"""
import pytest

from backend.scanners import yara_engine
from backend.scanners.binary_scanner import BinaryScanner

scanner = BinaryScanner()

yara_available = pytest.mark.skipif(
    not yara_engine.is_available(),
    reason=f"YARA unavailable: {yara_engine.unavailable_reason()}",
)


def build(*chunks: bytes) -> bytes:
    """A buffer with the given fragments spaced apart by padding."""
    out = bytearray(16)
    for chunk in chunks:
        out += chunk + bytes(16)
    return bytes(out)


# --------------------------------------------------------------- the engine

@yara_available
def test_rules_load_and_are_not_empty():
    assert yara_engine.is_available()
    assert yara_engine.unavailable_reason() is None
    assert yara_engine.rule_count() >= 20, "the rule set looks truncated"


@yara_available
def test_a_match_reports_its_offset_and_metadata():
    data = build(bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]))
    matches = yara_engine.scan_bytes(data)

    assert matches, "AES S-box not matched"
    aes = next(m for m in matches if m.algorithm == "AES")
    assert aes.offset == 16
    assert aes.length == 16
    assert aes.key_size == 256
    assert aes.note, "rules must explain what the match proves"


def test_unavailable_engine_returns_none_not_an_empty_list(monkeypatch):
    """
    "Could not check" and "found nothing" must be distinguishable, or a binary
    would be reported as clean when nothing ever looked at it.
    """
    monkeypatch.setattr(yara_engine, "_state", "simulated failure")
    monkeypatch.setattr(yara_engine, "_rules", None)
    assert yara_engine.scan_bytes(b"anything") is None
    assert yara_engine.is_available() is False
    assert "simulated failure" in yara_engine.unavailable_reason()


# ------------------------------------------------------- signature coverage

@yara_available
@pytest.mark.parametrize(
    "expected,payload",
    [
        ("AES", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])),
        ("AES", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                       0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB])),
        ("SHA-256", bytes([0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71,
                           0xCF, 0xFB, 0xC0, 0xB5])),
        ("SHA-512", bytes([0x08, 0xC9, 0xBC, 0xF3, 0x67, 0xE6, 0x09, 0x6A])),
        ("MD5", bytes([0x78, 0xA4, 0x6A, 0xD7, 0x56, 0xB7, 0xC7, 0xE8,
                       0xDB, 0x70, 0x20, 0x24, 0xEE, 0xCE, 0xBD, 0xC1])),
        ("ChaCha20", b"expand 32-byte k"),
        ("ChaCha20", b"expand 16-byte k"),
        ("Blowfish", bytes([0x88, 0x6A, 0x3F, 0x24, 0xD3, 0x08, 0xA3, 0x85,
                            0x2E, 0x8A, 0x19, 0x13, 0x44, 0x73, 0x70, 0x03])),
        ("RSA", bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])),
        ("RSA", b"RSA_generate_key"),
        ("ECC", bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])),
        ("ECC", b"EC_KEY_new_by_curve_name"),
        ("ML-KEM", b"2.16.840.1.101.3.4.4"),
        ("ML-DSA", b"2.16.840.1.101.3.4.3"),
        ("PQC-FIPS", b"OQS_KEM_alg_kyber_768"),
        ("Windows-CNG", b"BCryptGenRandom"),
        ("Libsodium", b"crypto_sign_ed25519"),
        ("Legacy-Cipher", b"EVP_des_ede3_cbc"),
        ("MD5/SHA-1", b"EVP_md5"),
        ("X509-Certificate", b"-----BEGIN CERTIFICATE-----"),
        ("Hardcoded-Private-Key", b"-----BEGIN RSA PRIVATE KEY-----"),
        ("TLS/SSL Protocol", b"SSLv3_method"),
    ],
)
def test_signature_is_detected(expected, payload):
    matches = yara_engine.scan_bytes(build(payload)) or []
    algorithms = {m.algorithm for m in matches}
    assert expected in algorithms, f"{expected} not found; matched {algorithms}"


@yara_available
def test_hsm_needs_two_symbols_to_avoid_a_lone_common_name():
    """`C_Initialize` alone is too generic; the rule requires corroboration."""
    one = yara_engine.scan_bytes(build(b"C_Initialize")) or []
    assert not any(m.asset_type == "hardware_module" for m in one)

    two = yara_engine.scan_bytes(build(b"C_Initialize", b"C_OpenSession")) or []
    assert any(m.asset_type == "hardware_module" for m in two)


@yara_available
def test_empty_and_random_data_produce_no_matches():
    import os as _os

    assert yara_engine.scan_bytes(b"") == []
    # Random bytes should not trip a signature; run a few to catch a rule that
    # is short enough to fire by chance.
    for _ in range(5):
        assert yara_engine.scan_bytes(_os.urandom(64 * 1024)) == []


# ------------------------------------------------------------ the scanner

@yara_available
def test_scanner_reports_byte_offsets_and_rule_provenance(tmp_path):
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(build(
        bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
               0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
        b"expand 32-byte k",
    ))

    evidences = scanner.scan_file(str(binary))
    assert evidences

    for evidence in evidences:
        assert evidence.metadata["detector"] == "yara"
        assert evidence.metadata["rule"], "each finding names the rule that produced it"
        assert evidence.column_number is not None, "binaries are located by offset"
        assert evidence.metadata["binary_offset"].startswith("0x")


@yara_available
def test_a_repeated_signature_is_capped_but_counted(tmp_path):
    """
    An embedded certificate bundle repeats one OID per certificate. Emitting
    thousands of identical findings buries the inventory, so offsets are capped
    while the true total is retained.
    """
    oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    binary = tmp_path / "certs.bin"
    binary.write_bytes(build(*[oid] * 400))

    evidences = scanner.scan_file(str(binary))
    rsa = [e for e in evidences if e.detected_name == "RSA"]

    assert 0 < len(rsa) <= scanner.MAX_OFFSETS_PER_RULE
    assert rsa[0].metadata["total_matches_for_rule"] >= 400


@yara_available
def test_the_bundled_demo_firmware_is_fully_recognised():
    """Every algorithm planted in the demo binary must still be reported."""
    evidences = scanner.scan_file("test/binaries/crypto_firmware.bin")
    found = {e.detected_name for e in evidences}

    for expected in ["AES", "SHA-256", "MD5", "ChaCha20", "RSA", "ECC"]:
        assert expected in found, f"{expected} missing; found {found}"


def test_builtin_tables_still_work_as_a_fallback():
    """
    The original matcher is retained so binary detection degrades rather than
    disappearing where the engine cannot load.
    """
    data = build(bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]))
    evidences = scanner._scan_with_builtin_tables("fallback.bin", data)
    assert any(e.detected_name == "AES" for e in evidences)


def test_scanner_falls_back_when_the_engine_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_engine, "scan_bytes", lambda data, timeout=30.0: None)

    binary = tmp_path / "f.bin"
    binary.write_bytes(build(bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                                    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])))

    evidences = scanner.scan_file(str(binary))
    assert evidences, "fallback produced nothing"
    assert all(e.metadata.get("detector") != "yara" for e in evidences)
