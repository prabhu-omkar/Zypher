"""
Tests for Tier 4 — cryptographic parameter resolution by dataflow.

Three properties carry the weight here.

**Resolution must actually cross a function boundary.** The whole reason this tier
exists is that Tiers 1-3 cannot follow a value out of a helper. A test that only
checks a literal at its own call site would pass against the AST scanner alone and
prove nothing.

**A resolved value must beat an assumed one.** Where the earlier tiers cannot read
a key size they substitute a plausible default — RSA gets 2048. For code that
generates 1024-bit keys that is not a cosmetic error: RSA-2048 is broken by Shor
in the future, RSA-1024 is broken *today*, and they land in different risk bands.

**Unavailability must be loud.** If the binary is missing the scan still has to
produce its Tier 1-3 findings, and it has to say that parameters were left
undetermined rather than presenting them as though nothing needed resolving.

The fixtures under ``fixtures/taint`` are deliberately shaped so the value is
written in one function and consumed in another, and they also record, in their
own comments, the languages where a module-level constant is *not* resolved.
"""
import os

import pytest

from backend.models import RawEvidence, TargetType
from backend.scanners import opengrep_engine
from backend.scanners.source_scanner import SourceCodeScanner
from backend.scanners.taint_scanner import (
    BINDING_WINDOW_LINES,
    TaintReport,
    TaintScanner,
    _parse_algorithm_string,
)
from backend.scanners.walker import walk_files

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "taint")

dataflow_available = pytest.mark.skipif(
    not opengrep_engine.is_available(),
    reason=f"dataflow analysis unavailable: {opengrep_engine.unavailable_reason()}",
)


def tier123(root=FIXTURES):
    """Evidence as the earlier tiers produce it, before any refinement."""
    scanner = SourceCodeScanner()
    evidences = []
    for path in walk_files(root, accept=scanner.accepts):
        evidences.extend(scanner.scan_file(path))
    return evidences


@pytest.fixture(scope="module")
def enriched():
    """The fixture corpus after Tier 4, with the report it produced."""
    return TaintScanner().enrich(tier123(), [FIXTURES])


def at(evidences, filename, line):
    for evidence in evidences:
        if evidence.file_path.endswith(filename) and evidence.line_number == line:
            return evidence
    return None


def find(evidences, filename, name=None, key=None, curve=None):
    out = []
    for e in evidences:
        if not e.file_path.endswith(filename):
            continue
        if name is not None and e.detected_name != name:
            continue
        if key is not None and e.key_length != key:
            continue
        if curve is not None and (e.curve_name or "").lower() != curve.lower():
            continue
        out.append(e)
    return out


# ------------------------------------------------------------------ the engine

@dataflow_available
def test_engine_reports_its_version_and_rule_count():
    assert opengrep_engine.is_available()
    assert opengrep_engine.unavailable_reason() is None
    assert opengrep_engine.version()
    assert opengrep_engine.rule_count() >= 15, "the rule set looks truncated"


@dataflow_available
def test_every_rule_in_the_file_fires_on_the_fixtures():
    """
    A rule that matches nothing is indistinguishable from a rule that is broken.
    An early version of the PHP key-size rule focused a metavariable its own
    pattern never bound, so it silently matched nothing; only counting firing
    rules caught it.
    """
    import re

    with open(opengrep_engine.rules_path(), encoding="utf-8") as f:
        declared = set(re.findall(r"- id: (\S+)", f.read()))

    findings = opengrep_engine.scan_paths([FIXTURES])
    fired = {f.rule.rsplit(".", 1)[-1] for f in findings or []}

    assert declared, "no rules declared"
    assert not (declared - fired), f"rules that never fire: {sorted(declared - fired)}"


@dataflow_available
def test_a_finding_carries_the_literal_and_where_it_was_written():
    findings = opengrep_engine.scan_paths([os.path.join(FIXTURES, "keys.py")])
    rsa = next(f for f in findings if f.param == "key_size" and f.rule.endswith("rsa-key-size"))

    assert rsa.value_as_int == 1024
    # The sink is in the helper; the literal is written in the caller.
    assert rsa.line_number != rsa.source_line
    assert rsa.snippet, "a finding must quote the line it applies to"


def test_unavailable_engine_returns_none_not_an_empty_list(monkeypatch):
    """
    "Could not check" and "found nothing" must stay distinguishable, or a scan
    would report every indirect parameter as absent rather than unresolved.
    """
    monkeypatch.setattr(opengrep_engine, "_state", "simulated failure")
    assert opengrep_engine.scan_paths([FIXTURES]) is None
    assert opengrep_engine.is_available() is False
    assert "simulated failure" in opengrep_engine.unavailable_reason()


def test_no_targets_is_not_an_error():
    assert opengrep_engine.scan_paths([]) == []


def test_exclusions_come_from_the_shared_walker():
    """
    Tier 4 must see the same files as Tiers 1-3. OpenGrep's own ignore list
    excludes test and fixture directories, which would have made the two tiers
    disagree about what was scanned — silently.
    """
    from backend.scanners.walker import EXCLUDED_DIRS

    assert set(opengrep_engine.default_exclusions()) == set(EXCLUDED_DIRS)
    assert "node_modules" in opengrep_engine.default_exclusions()


# ------------------------------------------------------- crossing a boundary

@dataflow_available
@pytest.mark.parametrize("filename,line", [
    ("keys.py", 8),      # rsa.generate_private_key(key_size=bits)
    ("keys.js", 9),      # { modulusLength: bits }
    ("keys.go", 14),     # rsa.GenerateKey(rand.Reader, bits)
    ("keys.rb", 9),      # OpenSSL::PKey::RSA.new(bits)
    ("keys.php", 3),     # openssl_pkey_new(["private_key_bits" => $bits])
    ("Vault.cs", 7),     # new RSACryptoServiceProvider(bits)
])
def test_key_size_is_resolved_through_a_wrapper_function(enriched, filename, line):
    evidences, _ = enriched
    evidence = at(evidences, filename, line)
    assert evidence is not None, f"no evidence at {filename}:{line}"
    assert evidence.key_length == 1024, (
        f"{filename}:{line} key size is {evidence.key_length}; the literal 1024 "
        f"is written in the calling function, not here"
    )
    assert "taint" in evidence.metadata.get("detector", "")


@dataflow_available
def test_the_ast_scanner_alone_cannot_do_this():
    """
    Guards the premise. If the earlier tiers ever resolve these on their own,
    the tests above stop proving anything about dataflow.
    """
    baseline = tier123()
    unresolved = at(baseline, "keys.py", 8)
    assert unresolved is not None
    assert unresolved.key_length is None, (
        "keys.py:8 is supposed to be unresolvable without dataflow"
    )
    assert unresolved.metadata.get("parameters_resolved") is False


@dataflow_available
def test_algorithm_name_is_resolved_through_a_wrapper(enriched):
    """`Cipher.getInstance(transform)` — the algorithm is whatever was passed in."""
    evidences, _ = enriched

    # Vault.java:25 is `Cipher.getInstance(transform)`; the caller passes
    # "DES/ECB/PKCS5Padding".
    cipher = at(evidences, "Vault.java", 25)
    assert cipher is not None
    assert cipher.detected_name == "Legacy-Cipher"
    assert cipher.version_or_mode == "ECB", "the mode is carried in the same string"


@dataflow_available
def test_unresolved_algorithm_records_are_given_their_real_name(enriched):
    evidences, _ = enriched
    assert not find(evidences, "Vault.java", name="Unresolved-Algorithm"), (
        "every factory call in the Java fixture is resolvable by dataflow"
    )
    assert find(evidences, "Vault.java", name="RSA")
    assert find(evidences, "Vault.java", name="Legacy-Cipher")
    assert find(evidences, "Vault.java", name="TLS/SSL Protocol")


@dataflow_available
def test_curve_is_resolved_through_a_wrapper(enriched):
    evidences, _ = enriched
    for filename, line, curve in [("keys.py", 24, "secp192r1"),
                                  ("keys.js", 29, "secp160r1")]:
        evidence = at(evidences, filename, line)
        assert evidence is not None
        assert (evidence.curve_name or "").lower() == curve


# -------------------------------------------------- correcting assumed values

@dataflow_available
def test_a_resolved_key_size_replaces_an_assumed_default(enriched):
    """
    The Go and Ruby fixtures have no bundled grammar, so the regex tier reports
    them with its RSA default of 2048 bits for code that generates 1024-bit keys.
    RSA-1024 is already classically broken and RSA-2048 is not, so leaving the
    default in place would put the asset in the wrong risk band.
    """
    evidences, report = enriched

    for filename, line in [("keys.go", 14), ("keys.rb", 9)]:
        evidence = at(evidences, filename, line)
        assert evidence is not None
        assert evidence.key_length == 1024
        assert evidence.metadata.get("taint_replaced_key_length") == 2048, (
            "the displaced default must be recorded so the override is auditable"
        )

    assert report.defaults_corrected >= 2


@dataflow_available
def test_a_resolved_curve_replaces_an_assumed_default(enriched):
    evidences, _ = enriched
    evidence = at(evidences, "keys.py", 24)
    replaced = evidence.metadata.get("taint_replaced_curve")
    assert replaced is not None, "the displaced default must be recorded"
    assert replaced.lower() == "secp256r1"


@dataflow_available
def test_a_baseline_scan_really_does_carry_the_wrong_default():
    """Guards the premise of the two tests above."""
    baseline = tier123()
    assert any(e.key_length == 2048 for e in find(baseline, "keys.go", name="RSA")), (
        "keys.go is supposed to come back with an assumed 2048 before Tier 4"
    )


# ------------------------------------------------------------- binding a size

@dataflow_available
def test_a_generator_key_size_binds_to_the_generator_above_it(enriched):
    """
    `KeyGenerator.getInstance(algo)` and `kg.init(bits)` are separate statements.
    Dataflow supplies the value; which artefact it belongs to is decided by
    proximity to the generator being initialised, and that has to be labelled
    rather than presented as a directly resolved parameter.
    """
    evidences, _ = enriched

    triple_des = at(evidences, "Vault.java", 13)
    assert triple_des.detected_name == "Legacy-Cipher"
    assert triple_des.key_length == 56
    assert triple_des.metadata.get("taint_key_length_binding") == "nearest-generator"

    rsa = at(evidences, "Vault.java", 19)
    assert rsa.detected_name == "RSA"
    assert rsa.key_length == 1024
    assert rsa.metadata.get("taint_key_length_binding") == "nearest-generator"


@dataflow_available
def test_a_directly_resolved_parameter_is_labelled_as_such(enriched):
    evidences, _ = enriched
    assert at(evidences, "keys.py", 8).metadata["taint_key_length_binding"] == "direct"


def test_binding_never_reaches_across_an_unrelated_span():
    """
    The window exists so a key size cannot be attached to a generator that is
    nowhere near it. A value with nothing above it inside the window must not
    bind at all.
    """
    scanner = TaintScanner()
    records = [
        RawEvidence(
            id="a", target_type=TargetType.SOURCE_CODE, file_path="x.java",
            line_number=1, matched_pattern="m", raw_type="algorithm",
            detected_name="AES", metadata={},
        ),
    ]
    assert scanner._nearest_preceding(records, 2) is records[0]
    assert scanner._nearest_preceding(records, 1 + BINDING_WINDOW_LINES) is records[0]
    assert scanner._nearest_preceding(records, 2 + BINDING_WINDOW_LINES) is None
    # Never binds to something below the value.
    assert scanner._nearest_preceding(records, 0) is None


# --------------------------------------------------------- new coverage only

@dataflow_available
def test_languages_with_no_grammar_and_no_regex_are_found_only_here(enriched):
    """
    C# and PHP key generation matches neither a bundled grammar nor any regex
    pattern, so before this tier they produced no evidence at all.
    """
    baseline = tier123()
    assert not find(baseline, "Vault.cs"), "premise: Vault.cs yields nothing in Tiers 1-3"
    assert not find(baseline, "keys.php"), "premise: keys.php yields nothing in Tiers 1-3"

    evidences, report = enriched
    assert find(evidences, "Vault.cs", name="RSA", key=1024)
    assert find(evidences, "keys.php", name="RSA", key=1024)
    assert find(evidences, "Vault.cs", name="MD5/SHA-1")
    assert report.evidence_added >= 4


@dataflow_available
def test_enrichment_never_loses_evidence(enriched):
    """
    Refinement may rename an asset or fill in a parameter, but every location the
    earlier tiers reported must still be reported. A failure here means Tier 4
    cost the scan a finding, which is strictly worse than leaving it unresolved.
    """
    evidences, _ = enriched
    before = tier123()
    assert len(evidences) >= len(before)

    kept = {(e.file_path, e.line_number) for e in evidences}
    missing = {(e.file_path, e.line_number) for e in before} - kept
    assert not missing, f"locations dropped by enrichment: {sorted(missing)}"


# --------------------------------------------------------- known boundaries

@dataflow_available
@pytest.mark.parametrize("filename,line", [
    ("keys.go", 24),   # buildKey(legacyBits) — package-level const
    ("keys.js", 17),   # buildPair(LEGACY_BITS) — module-level const
])
def test_module_level_constants_are_a_known_boundary(enriched, filename, line):
    """
    Documents a real limit rather than asserting a capability. A module- or
    package-level constant passed through a wrapper is resolved in Python, Java
    and C#, but not in Go, JavaScript or Ruby. The fixtures carry both shapes so
    that if upstream closes this gap, this test fails and says so — the correct
    response then is to tighten the assertion, not to delete it.
    """
    evidences, _ = enriched
    evidence = at(evidences, filename, line)
    if evidence is None:
        return  # nothing reported there at all, which is the same boundary
    assert evidence.metadata.get("taint_key_length_binding") != "direct", (
        f"{filename}:{line} now resolves a module-level constant — upstream has "
        f"improved; update this test and the fixture comments"
    )


# ------------------------------------------------------------- the report

def test_an_unavailable_tier_says_so_in_the_coverage_notes():
    report = TaintReport(available=False, reason="binary was not bundled")
    notes = " ".join(report.notes())
    assert "did not run" in notes
    assert "binary was not bundled" in notes
    assert "undetermined" in notes, (
        "the consequence matters more than the cause: a reader has to know that "
        "key sizes in this scan may be unresolved"
    )


def test_confirming_a_value_is_not_reported_as_finding_nothing():
    """
    A scan whose parameters are all directly readable still runs the analysis.
    Reporting that as "found nothing" reads as though the tier never looked.
    """
    confirmed = TaintReport(available=True, findings=8).notes()
    assert "confirmed" in " ".join(confirmed)

    nothing = TaintReport(available=True, findings=0).notes()
    assert "no cryptographic parameters" in " ".join(nothing)


def test_report_counts_add_up():
    report = TaintReport(
        available=True, key_sizes_resolved=3, algorithms_resolved=2, curves_resolved=1,
    )
    assert report.resolutions == 6
    notes = " ".join(report.notes())
    assert "6 parameter(s)" in notes
    assert "3 key size(s)" in notes


def test_disabled_in_settings_is_reported_as_a_reason(monkeypatch):
    from backend.config import config

    monkeypatch.setattr(config, "dataflow_analysis_enabled", False)
    evidences = tier123()
    out, report = TaintScanner().enrich(evidences, [FIXTURES])

    assert out is evidences, "disabling must not alter the evidence"
    assert report.available is False
    assert "disabled" in (report.reason or "")


# --------------------------------------------------- algorithm string parsing

@pytest.mark.parametrize("value,family,mode,key_size", [
    ("AES/GCM/NoPadding", "AES", "GCM", None),
    ("AES-256-CBC", "AES", "CBC", 256),
    ("DES/ECB/PKCS5Padding", "Legacy-Cipher", "ECB", None),
    ("DESede", "Legacy-Cipher", None, None),
    ("DES-EDE3-CBC", "Legacy-Cipher", "CBC", None),
    ("md5", "MD5/SHA-1", None, None),
    ("SHA-256", "SHA-2/SHA-3", None, 256),
    ("RSA", "RSA", None, None),
    ("SSLv3", "TLS/SSL Protocol", None, None),
    ("TLSv1.2", "TLS/SSL Protocol", None, None),
    ("Kyber768", "PQC-FIPS", None, None),
])
def test_algorithm_strings_resolve_to_pipeline_names(value, family, mode, key_size):
    got_family, got_mode, got_key, _ = _parse_algorithm_string(value)
    assert got_family == family, f"{value!r} -> {got_family!r}"
    assert got_mode == mode
    assert got_key == key_size


@pytest.mark.parametrize("value", ["", "SunPKCS11", "BouncyCastle", "someProvider"])
def test_an_unrecognised_string_resolves_to_nothing(value):
    """
    Inventing a family for a provider name would put a fabricated algorithm in
    the CBOM. Returning nothing leaves the record as the earlier tiers had it.
    """
    family, _, _, _ = _parse_algorithm_string(value)
    assert family is None


def test_a_resolved_string_never_overwrites_a_key_or_certificate():
    """
    A PEM block's identity is the artefact. A nearby algorithm string must not
    rename it — that was the class of bug that had private keys recommended for
    migration to AES-256-GCM.
    """
    scanner = TaintScanner()
    pem = RawEvidence(
        id="k", target_type=TargetType.SOURCE_CODE, file_path="x.py", line_number=5,
        matched_pattern="-----BEGIN RSA PRIVATE KEY-----", raw_type="key",
        detected_name="Hardcoded-Private-Key", metadata={},
    )
    out, _ = scanner.enrich([pem], [])
    assert out[0].detected_name == "Hardcoded-Private-Key"


# ------------------------------------------------- provenance in the inventory

def _evidence(line, key=None, detector=None, resolved=None, name="RSA", path="a.py"):
    meta = {}
    if detector is not None:
        meta["detector"] = detector
    if resolved is not None:
        meta["parameters_resolved"] = resolved
    return RawEvidence(
        id=f"e{line}", target_type=TargetType.SOURCE_CODE, file_path=path,
        line_number=line, matched_pattern=name, raw_type="algorithm",
        detected_name=name, key_length=key, metadata=meta,
    )


@pytest.mark.parametrize("detector,resolved,expected", [
    ("ast+taint", True, "dataflow"),
    ("regex+taint", True, "dataflow"),
    ("taint", True, "dataflow"),
    ("ast", True, "literal"),
    ("ast", False, "assumed"),
    (None, None, None),
])
def test_parameter_provenance_is_recorded_on_the_artefact(detector, resolved, expected):
    """
    The inventory has to distinguish a measured key size from an assumed one.
    Without this the two render identically, and an assumed RSA-2048 standing in
    for a real RSA-1024 silently lands the asset in the wrong Mosca band.
    """
    from backend.cbom.artefact_extractor import ArtefactExtractor

    artefacts = ArtefactExtractor.extract_artefacts(
        [_evidence(1, key=2048, detector=detector, resolved=resolved)]
    )
    assert artefacts
    assert artefacts[0].parameter_source == expected


def test_dataflow_resolved_evidence_ranks_above_a_parsed_call_site():
    from backend.cbom.artefact_extractor import _confidence_for

    assert _confidence_for(_evidence(1, detector="ast+taint")) > _confidence_for(
        _evidence(1, detector="ast")
    )
    assert _confidence_for(_evidence(1, detector="ast")) > _confidence_for(
        _evidence(1, detector=None)
    )


def test_aggregation_keeps_the_strongest_provenance():
    """
    Two occurrences can agree on a key size with one having measured it and the
    other having assumed it. The merged record must claim the measurement — the
    same rule the aggregator already applies to shelf life and criticality.
    """
    from backend.cbom.aggregator import aggregate_artefacts
    from backend.cbom.artefact_extractor import ArtefactExtractor

    artefacts = ArtefactExtractor.extract_artefacts([
        _evidence(1, key=1024, detector="ast", resolved=False),
        _evidence(9, key=1024, detector="ast+taint", resolved=True),
    ])
    merged = aggregate_artefacts(artefacts)

    assert len(merged) == 1, "same algorithm, key size and file is one asset"
    assert merged[0].parameter_source == "dataflow"
    assert merged[0].occurrence_count == 2
    assert merged[0].confidence_score == pytest.approx(0.99)


def test_aggregation_does_not_downgrade_when_order_is_reversed():
    """Guards against the rule only holding for one input order."""
    from backend.cbom.aggregator import aggregate_artefacts
    from backend.cbom.artefact_extractor import ArtefactExtractor

    artefacts = ArtefactExtractor.extract_artefacts([
        _evidence(1, key=1024, detector="ast+taint", resolved=True),
        _evidence(9, key=1024, detector="ast", resolved=False),
    ])
    assert aggregate_artefacts(artefacts)[0].parameter_source == "dataflow"


def test_the_merged_view_keeps_the_strongest_provenance_across_scans():
    """One scan may have had the engine available and another not."""
    from backend.cbom.aggregator import merge_artefact_sets
    from backend.cbom.artefact_extractor import ArtefactExtractor

    measured = ArtefactExtractor.extract_artefacts(
        [_evidence(1, key=1024, detector="ast+taint", resolved=True)]
    )
    assumed = ArtefactExtractor.extract_artefacts(
        [_evidence(1, key=1024, detector="ast", resolved=False)]
    )

    merged = merge_artefact_sets([("no-dataflow", assumed), ("with-dataflow", measured)])
    assert len(merged) == 1
    assert merged[0].parameter_source == "dataflow"


# ------------------------------------------------------------ the status API

def test_the_dataflow_status_endpoint_reports_enough_to_audit_a_scan():
    from backend.main import _dataflow_status

    status = _dataflow_status()
    for field in ["enabled", "available", "engine", "rules", "binary_present", "offline"]:
        assert field in status, f"missing {field}"
    assert status["offline"] is True, (
        "the engine reaches no network; the API must say so, because that is why "
        "it was chosen over CodeQL or a SonarQube plugin"
    )
    if status["available"]:
        assert status["version"]
        assert status["rules"] >= 15
    else:
        assert status["reason"], "an unavailable engine must say why"


# ------------------------------------------------------------ curve strength

@pytest.mark.parametrize("curve,bits", [
    ("secp256r1 (P-256)", 256),
    ("secp160r1", 160),
    ("secp192r1", 192),
    ("secp224r1", 224),
    ("secp384r1", 384),
    ("secp521r1", 521),
    ("prime256v1", 256),
    ("P-384", 384),
    ("nistp521", 521),
    ("ed25519", 255),
    ("X25519", 255),
    ("ed448", 448),
    ("brainpoolP256r1", 256),
    ("brainpoolP512r1", 512),
    ("sect571k1", 571),
    ("secp239k1", 239),
])
def test_curve_field_size_is_read_from_the_curve(curve, bits):
    """
    For ECC the curve *is* the strength, and it feeds X in Mosca's inequality.
    This was previously a three-way substring test that mapped every curve
    without "256", "384" or "25519" in its name to 521 bits, so a 160-bit curve
    was reported as 521-bit — understating the risk on the exact asset class where
    the number matters most. Tier 4 resolves arbitrary curve names from real code,
    which is how the defect surfaced.
    """
    from backend.cbom.artefact_extractor import curve_strength_bits

    assert curve_strength_bits(curve) == bits


@pytest.mark.parametrize("curve", [None, "", "weirdcurve", "custom"])
def test_an_unrecognised_curve_is_undetermined_not_guessed(curve):
    """A plausible-looking number is worse than none: it becomes a risk input."""
    from backend.cbom.artefact_extractor import curve_strength_bits

    assert curve_strength_bits(curve) is None


@dataflow_available
def test_a_weak_curve_resolved_by_dataflow_gets_its_real_field_size(enriched):
    """End to end: the curve is traced, then sized correctly."""
    from backend.cbom.aggregator import aggregate_artefacts
    from backend.cbom.artefact_extractor import ArtefactExtractor

    evidences, _ = enriched
    artefacts = aggregate_artefacts(ArtefactExtractor.extract_artefacts(evidences))

    by_curve = {(a.curve or "").lower(): a for a in artefacts if a.algorithm_family == "ECC"}
    assert "secp160r1" in by_curve, f"curves found: {sorted(by_curve)}"
    assert by_curve["secp160r1"].key_size_bits == 160
    assert by_curve["secp192r1"].key_size_bits == 192
