r"""
Detection regression tests for real-world crypto idioms.

Every scanner pattern was anchored with two-sided ``\b``. That asserts a
transition between a word and a non-word character, so it depends on BOTH
sides — and when an alternation ends in a quote, as most language-specific
idioms do:

    MessageDigest.getInstance("SHA-1");
    boto3.client('kms', region_name='us-east-1')
    crypto.createHash('md5')

the character after the closing quote is also non-word, there is no transition,
and the trailing ``\b`` fails. The whole pattern then silently did not match, so
genuine findings were dropped with no indication. SHA-1 in the bundled demo
target's own PaymentVault.java was going unreported.

The anchors are now one-sided lookarounds — ``(?<!\w)`` / ``(?!\w)`` — which
express what was intended ("not glued to a word character") without depending on
what the matched text itself begins or ends with.
"""
import pytest

from backend.scanners.source_scanner import SourceCodeScanner

scanner = SourceCodeScanner()


def detect(line: str):
    """Names of every pattern that fires on a line."""
    return {p["detected_name"] for p in scanner.PATTERNS if p["regex"].search(line + "\n")}


# Idioms that the two-sided anchors dropped, plus the ones that always worked —
# so a future change to the anchors cannot silently break either group.
@pytest.mark.parametrize(
    "expected,line",
    [
        # --- previously MISSED: alternation ends in a quote ---
        ("MD5/SHA-1", 'MessageDigest md = MessageDigest.getInstance("SHA-1");'),
        ("MD5/SHA-1", 'MessageDigest md = MessageDigest.getInstance("MD5");'),
        ("MD5/SHA-1", "const h = crypto.createHash('md5').update(x).digest('hex');"),
        ("MD5/SHA-1", 'const h = crypto.createHash("sha1");'),
        ("SHA-2/SHA-3", 'MessageDigest.getInstance("SHA-256");'),
        ("SHA-2/SHA-3", "crypto.createHash('sha512')"),
        ("Cloud KMS Service", "kms = boto3.client('kms', region_name='us-east-1')"),
        ("Cloud KMS Service", 'kms = boto3.client("kms")'),
        ("Diffie-Hellman", 'KeyPairGenerator.getInstance("DSA");'),
        ("Diffie-Hellman", 'KeyPairGenerator.getInstance("DH");'),
        # --- always worked: alternation ends in a word character ---
        ("RSA", 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SunPKCS11");'),
        ("RSA", "private_key = rsa.generate_private_key(key_size=2048)"),
        ("RSA", "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });"),
        ("AES", 'Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");'),
        ("AES", "crypto.createCipheriv('aes-128-cbc', key, iv);"),
        ("Legacy-Cipher", 'Cipher.getInstance("DESede/CBC/PKCS5Padding");'),
        ("ECC", "ec.generate_private_key(ec.SECP256R1())"),
        ("Cloud KMS Service", "client = SecretClient(vault_url=u, credential=c)"),
        ("HSM/PKCS#11 Module", 'KeyPairGenerator.getInstance("RSA", "SunPKCS11");'),
        ("TLS/SSL Protocol", "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)"),
        ("PQC-FIPS", "kem = oqs.KeyEncapsulation('ML-KEM-768')"),
    ],
)
def test_idiom_is_detected(expected, line):
    assert expected in detect(line), f"{expected} not detected in: {line}"


@pytest.mark.parametrize(
    "line",
    [
        "const AESTHETIC = true;",          # AES inside a longer word
        "let MYRSAKEY = 1;",                # RSA inside a longer word
        "MODES_LIST = []",                  # DES inside a longer word
        "x = address_book",                 # DSA-ish substring
        "descriptor = None",                # DES prefix
    ],
)
def test_substrings_of_longer_words_do_not_match(line):
    """
    The one-sided lookarounds must still reject a match glued to a word
    character — otherwise the fix would trade dropped findings for noise.
    """
    assert detect(line) == set(), f"false positive on: {line}"


def test_the_demo_target_reports_its_planted_sha1():
    """
    PaymentVault.java plants SHA-1 and it was going unreported — the exact
    finding a reviewer would check first.
    """
    evidences = scanner.scan_file("test/source_repo/PaymentVault.java")
    assert any(
        e.detected_name == "MD5/SHA-1" for e in evidences
    ), "SHA-1 planted in the demo target is not detected"


def test_the_demo_target_reports_its_kms_calls():
    evidences = scanner.scan_file("test/source_repo/cert_store.py")
    kinds = {e.raw_type for e in evidences}
    assert "cloud_service" in kinds, "AWS KMS / Key Vault usage not detected"
    assert "certificate" in kinds, "embedded X.509 certificate not detected"


def test_every_problem_statement_category_is_reachable():
    """
    SIH 26164 clause (i) names seven artefact categories. The bundled demo
    target must exercise all seven, or a reviewer checking them off finds gaps.
    """
    from backend.cbom.artefact_extractor import ArtefactExtractor
    from backend.scanners.binary_scanner import BinaryScanner
    from backend.scanners.container_scanner import ContainerScanner
    from backend.scanners.dependency_scanner import DependencyScanner

    evidences = []
    evidences += scanner.scan_directory("test")
    evidences += BinaryScanner().scan_directory("test")
    evidences += DependencyScanner().scan_directory("test")
    evidences += ContainerScanner().scan_directory("test")

    types = {a.type.value for a in ArtefactExtractor.extract_artefacts(evidences)}

    for required in [
        "algorithm", "key", "certificate", "protocol",
        "library", "hardware_module", "cloud_service",
    ]:
        assert required in types, f"demo target produces no {required} artefact"
