"""
Tests for syntax-aware detection.

These cover what the regex path structurally could not do: read a call's real
arguments, follow an aliased import, tell a call from a comment, and say "there
is cryptography here but I cannot tell what" instead of guessing.

The parameter-accuracy cases matter most. Key length feeds X in the Mosca
calculation, and the regex path substituted a default whenever it could not
parse one — so an inventory could report a 1024-bit key as 2048, or an unknown
AES key as quantum-safe.
"""
import textwrap

import pytest

from backend.scanners import ast_scanner
from backend.scanners.source_scanner import SourceCodeScanner

pytestmark = pytest.mark.skipif(
    not ast_scanner.can_parse("x.py"),
    reason="tree-sitter grammars unavailable",
)

scanner = SourceCodeScanner()


def scan(tmp_path, filename, code):
    path = tmp_path / filename
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return scanner.scan_file(str(path))


def names(evidences):
    return {e.detected_name for e in evidences}


def one(evidences, detected_name):
    matches = [e for e in evidences if e.detected_name == detected_name]
    assert matches, f"{detected_name} not detected in {names(evidences)}"
    return matches[0]


# ----------------------------------------------------------- real arguments

def test_key_size_is_read_not_defaulted(tmp_path):
    """A 1024-bit key must not be reported as the 2048 default."""
    ev = scan(tmp_path, "a.py", """
        from cryptography.hazmat.primitives.asymmetric import rsa
        k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    """)
    rsa = one(ev, "RSA")
    assert rsa.key_length == 1024
    assert rsa.metadata["parameters_resolved"] is True


def test_key_size_from_a_javascript_options_object(tmp_path):
    ev = scan(tmp_path, "a.js", """
        const crypto = require('crypto');
        crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
    """)
    assert one(ev, "RSA").key_length == 4096


def test_java_transformation_string_yields_algorithm_and_mode(tmp_path):
    ev = scan(tmp_path, "T.java", """
        public class T {
          void f() throws Exception {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
          }
        }
    """)
    aes = one(ev, "AES")
    assert aes.version_or_mode == "CBC"


def test_key_length_set_on_a_generator_is_bound_to_its_algorithm(tmp_path):
    """
    Java sets key length on the generator, not in the transformation string.
    A file-wide hint would hand AES's 128 to the DESede cipher, so the length is
    paired with the algorithm its generator named.
    """
    ev = scan(tmp_path, "T.java", """
        public class T {
          void f() throws Exception {
            Cipher des = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
          }
        }
    """)
    assert one(ev, "AES").key_length == 128
    assert one(ev, "Legacy-Cipher").key_length != 128, "3DES must not inherit AES's length"


def test_rsa_key_length_from_initialize(tmp_path):
    ev = scan(tmp_path, "T.java", """
        public class T {
          void f() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096);
          }
        }
    """)
    assert one(ev, "RSA").key_length == 4096


def test_unknown_key_length_is_not_invented(tmp_path):
    """
    Substituting 256 for an unstated AES length reported an unknown key as
    quantum-safe — the one direction an inventory must not guess in.
    """
    from backend.cbom.artefact_extractor import ArtefactExtractor

    ev = scan(tmp_path, "a.js", """
        const crypto = require('crypto');
        const c = crypto.createCipheriv(algoFromConfig, key, iv);
    """)
    for e in ev:
        assert e.key_length is None or e.key_length in (128, 192, 256)

    artefacts = ArtefactExtractor.extract_artefacts(
        [e for e in ev if e.detected_name == "AES"]
    )
    for art in artefacts:
        if art.key_size_bits is None:
            assert art.quantum_vulnerability.value == "unknown"


# --------------------------------------------------------- import resolution

def test_aliased_import_is_resolved(tmp_path):
    ev = scan(tmp_path, "a.py", """
        import hashlib as H
        d = H.md5(b"x").hexdigest()
    """)
    assert "MD5/SHA-1" in names(ev)


def test_require_alias_is_resolved(tmp_path):
    ev = scan(tmp_path, "a.js", """
        const c = require('crypto');
        c.createHash('sha1');
    """)
    assert "MD5/SHA-1" in names(ev)


# ------------------------------------------------------------ no false hits

def test_crypto_words_in_comments_are_not_findings(tmp_path):
    ev = scan(tmp_path, "a.py", """
        # This module used to call rsa.generate_private_key with MD5 and DES.
        # Replaced by the new provider; see ticket AES-128.
        value = 1
    """)
    assert ev == [], f"comment produced findings: {names(ev)}"


def test_crypto_words_in_unrelated_strings_are_not_findings(tmp_path):
    ev = scan(tmp_path, "a.py", """
        LABEL = "AES encryption settings"
        HELP = "choose between md5 and sha1"
        print(LABEL, HELP)
    """)
    assert ev == [], f"plain strings produced findings: {names(ev)}"


def test_substrings_of_longer_identifiers_do_not_match(tmp_path):
    ev = scan(tmp_path, "a.js", """
        const AESTHETIC = true;
        const MYRSAKEY = 2;
        function describe() { return AESTHETIC + MYRSAKEY; }
    """)
    assert ev == []


# ------------------------------------------------------ unresolved algorithms

def test_a_dynamic_algorithm_is_reported_as_undetermined(tmp_path):
    """
    `Cipher.getInstance(config.algorithm)` is real cryptography whose algorithm
    is unknowable statically. Reporting nothing hides it; guessing is worse.
    """
    ev = scan(tmp_path, "T.java", """
        public class T {
          void f(Config c) throws Exception {
            Cipher x = Cipher.getInstance(c.algorithm);
          }
        }
    """)
    unresolved = one(ev, "Unresolved-Algorithm")
    assert unresolved.metadata["parameters_resolved"] is False


# ------------------------------------------------------------- housekeeping

def test_pem_blocks_are_found_in_string_literals(tmp_path):
    ev = scan(tmp_path, "a.py", '''
        CERT = """-----BEGIN CERTIFICATE-----
        MIIBkTCB+wIJAKZ
        -----END CERTIFICATE-----"""
    ''')
    assert "X509-Certificate" in names(ev)


def test_evidence_records_which_detector_produced_it(tmp_path):
    ev = scan(tmp_path, "a.py", """
        import hashlib
        hashlib.md5(b"x")
    """)
    assert all(e.metadata["detector"] == "ast" for e in ev)


def test_unsupported_languages_fall_back_to_regex(tmp_path):
    """Go has no bundled grammar here; detection must still happen."""
    ev = scan(tmp_path, "a.go", """
        package main
        import "crypto/rsa"
        func main() { _ = rsa.GenerateKey }
    """)
    assert ev, "regex fallback produced nothing for an unparsed language"
    assert all(e.metadata.get("detector", "regex") == "regex" for e in ev)


def test_files_with_no_cryptographic_token_are_skipped(tmp_path):
    ev = scan(tmp_path, "a.py", """
        def add(a, b):
            return a + b
    """)
    assert ev == []
