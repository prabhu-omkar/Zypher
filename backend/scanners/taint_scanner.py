"""
Tier 4 — refine the evidence from Tiers 1-3 with values resolved by dataflow.

This pass does not produce a parallel inventory. Tiers 1-3 already found the call
sites; what they could not do is say what was passed to them. A syntax tree sees
``rsa.generate_private_key(key_size=bits)`` and reports an RSA key of unknown
size, and ``Cipher.getInstance(transform)`` as ``Unresolved-Algorithm``. Running
a second detector over the same code would double every entry without answering
either question.

So findings are *merged into* existing evidence, and the merge does two jobs:

**Filling gaps.** An unresolved parameter becomes a known one, and
``Unresolved-Algorithm`` becomes the algorithm.

**Correcting defaults.** This matters more. Where Tiers 1-3 cannot read a value
they substitute a plausible one — RSA defaults to 2048 bits, ECC to P-256. On the
bundled Go fixture that produces five RSA artefacts at 2048 bits for code that
generates 1024-bit keys, which is not a cosmetic error: RSA-2048 is merely
fully broken by Shor, while RSA-1024 is **already classically broken** today. The
two land in different risk bands and carry different remediation urgency. A value
read out of a dataflow trace therefore supersedes a default, and the value it
replaced is recorded so the override can be audited.

Where an evidence record does not exist at all — C# and PHP have neither a
bundled grammar nor a regex that matches their key-generation APIs — a finding
that names an algorithm family emits new evidence rather than being discarded.
"""
from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from backend.models import RawEvidence, TargetType
from backend.scanners import opengrep_engine
from backend.scanners.ast_scanner import (
    _CURVE_IN_STRING,
    _KEYSIZE_IN_STRING,
    _MODE_IN_STRING,
)

# A key size is set on a generator, not in the transformation string, so the two
# statements are adjacent but not identical: `KeyGenerator.getInstance(algo)` on
# one line and `kg.init(bits)` on the next. Dataflow gives the *value*; pairing it
# with the right artefact is still a question of which generator is being
# initialised. Both statements act on the same local variable, so they sit within
# a few lines of each other in any real code. Bindings made this way are labelled
# in metadata, so a reviewer can tell a directly resolved parameter from a bound
# one.
BINDING_WINDOW_LINES = 6

# Algorithm tokens, as they appear in a resolved string, mapped to the names the
# rest of the pipeline uses. Keep in step with
# `ast_scanner._GENERATOR_ALGORITHM_FAMILY`, which covers the same ground for
# statically readable generators.
FAMILY_BY_TOKEN: Dict[str, str] = {
    "aes": "AES", "aes-128": "AES", "aes-192": "AES", "aes-256": "AES",
    "aesgcm": "AES", "rijndael": "AES",
    "chacha20": "ChaCha20-Poly1305", "chacha20-poly1305": "ChaCha20-Poly1305",
    "des": "Legacy-Cipher", "desede": "Legacy-Cipher", "des-ede3": "Legacy-Cipher",
    "des3": "Legacy-Cipher", "tripledes": "Legacy-Cipher", "3des": "Legacy-Cipher",
    "rc2": "Legacy-Cipher", "rc4": "Legacy-Cipher", "arc4": "Legacy-Cipher",
    "blowfish": "Legacy-Cipher", "idea": "Legacy-Cipher", "cast5": "Legacy-Cipher",
    "rsa": "RSA",
    "dsa": "Diffie-Hellman", "dh": "Diffie-Hellman", "diffiehellman": "Diffie-Hellman",
    "ec": "ECC", "ecdsa": "ECC", "ecdh": "ECC", "ed25519": "ECC", "x25519": "ECC",
    "md5": "MD5/SHA-1", "sha1": "MD5/SHA-1", "sha-1": "MD5/SHA-1", "md4": "MD5/SHA-1",
    "sha256": "SHA-2/SHA-3", "sha-256": "SHA-2/SHA-3", "sha384": "SHA-2/SHA-3",
    "sha-384": "SHA-2/SHA-3", "sha512": "SHA-2/SHA-3", "sha-512": "SHA-2/SHA-3",
    "sha3-256": "SHA-2/SHA-3", "sha3-512": "SHA-2/SHA-3", "blake2b": "SHA-2/SHA-3",
    "sslv2": "TLS/SSL Protocol", "sslv3": "TLS/SSL Protocol", "ssl": "TLS/SSL Protocol",
    "tls": "TLS/SSL Protocol", "tlsv1": "TLS/SSL Protocol", "tlsv1.1": "TLS/SSL Protocol",
    "tlsv1.2": "TLS/SSL Protocol", "tlsv1.3": "TLS/SSL Protocol",
    "kyber": "PQC-FIPS", "ml-kem": "PQC-FIPS", "ml-dsa": "PQC-FIPS",
    "dilithium": "PQC-FIPS", "sphincs+": "PQC-FIPS", "slh-dsa": "PQC-FIPS",
    # Parameter-set suffixes are written without a separator, so they survive
    # neither the whole-string nor the token lookup.
    "kyber512": "PQC-FIPS", "kyber768": "PQC-FIPS", "kyber1024": "PQC-FIPS",
    "dilithium2": "PQC-FIPS", "dilithium3": "PQC-FIPS", "dilithium5": "PQC-FIPS",
    "falcon512": "PQC-FIPS", "falcon1024": "PQC-FIPS",
}

# Names whose parameters the pipeline treats as artefact identity rather than as
# an algorithm to be looked up. A resolved value never overwrites one of these.
_NON_ALGORITHM_NAMES = {
    "Hardcoded-Private-Key", "Hardcoded-Public-Key", "X509-Certificate",
    "Cloud KMS Service", "HSM/PKCS#11 Module",
}


@dataclass
class TaintReport:
    """What Tier 4 contributed, for the coverage notes on a scan."""
    available: bool = False
    reason: Optional[str] = None
    version: Optional[str] = None
    rules: int = 0
    findings: int = 0
    key_sizes_resolved: int = 0
    algorithms_resolved: int = 0
    curves_resolved: int = 0
    defaults_corrected: int = 0
    evidence_added: int = 0

    @property
    def resolutions(self) -> int:
        return self.key_sizes_resolved + self.algorithms_resolved + self.curves_resolved

    def notes(self) -> List[str]:
        """Statements for the scan's coverage notes — plain, and never silent."""
        if not self.available:
            return [
                "Dataflow analysis (Tier 4) did not run: "
                f"{self.reason or 'unavailable'}. Parameters passed through "
                "variables or helper functions are reported as undetermined."
            ]
        if self.resolutions == 0:
            # "Found nothing" and "found the same thing" are different outcomes.
            # Reporting the second as the first reads as though Tier 4 never
            # looked, when in fact it corroborated what the earlier tiers read.
            if self.findings:
                return [
                    f"Dataflow analysis traced {self.findings} cryptographic "
                    f"parameter(s) and confirmed the values already read at their "
                    f"call sites; none required resolving indirectly."
                ]
            return ["Dataflow analysis found no cryptographic parameters passed indirectly."]

        note = (
            f"Dataflow analysis resolved {self.resolutions} parameter(s) that are "
            f"not visible at their call site"
        )
        parts = []
        if self.key_sizes_resolved:
            parts.append(f"{self.key_sizes_resolved} key size(s)")
        if self.algorithms_resolved:
            parts.append(f"{self.algorithms_resolved} algorithm name(s)")
        if self.curves_resolved:
            parts.append(f"{self.curves_resolved} curve(s)")
        if parts:
            note += " — " + ", ".join(parts)
        notes = [note + "."]
        if self.defaults_corrected:
            notes.append(
                f"{self.defaults_corrected} assumed default value(s) were replaced "
                f"with the value actually reaching the call."
            )
        if self.evidence_added:
            notes.append(
                f"{self.evidence_added} asset(s) were found only by dataflow analysis."
            )
        return notes


def _parse_algorithm_string(value: str) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]:
    """
    Read a resolved algorithm string into ``(family, mode, key_size, curve)``.

    A Java transformation carries three facts in one token —
    ``"AES/GCM/NoPadding"`` names the cipher, the mode and the padding, and
    ``"AES-128"`` also carries the key length.
    """
    text = (value or "").strip()
    if not text:
        return None, None, None, None

    mode_match = _MODE_IN_STRING.search(text)
    mode = mode_match.group(1).upper() if mode_match else None

    curve_match = _CURVE_IN_STRING.search(text)
    curve = curve_match.group(1) if curve_match else None

    key_size = None
    size_match = _KEYSIZE_IN_STRING.search(text)
    if size_match:
        key_size = int(size_match.group(1))

    # Widening passes, most specific first. The whole string is tried before any
    # splitting so that a compound name resolves as itself — "SHA-256" and
    # "DES-EDE3-CBC" both mean something that their first fragment does not
    # ("sha" and "des" respectively, one of which is a different algorithm
    # family). Only then is the string broken up, and the parts are read left to
    # right so the cipher in "AES-256-CBC" wins over the mode.
    lowered = text.lower()
    family = FAMILY_BY_TOKEN.get(lowered)

    if family is None:
        head = re.split(r"[/\\\s]", lowered, maxsplit=1)[0]
        family = FAMILY_BY_TOKEN.get(head)

    if family is None:
        for token in re.split(r"[^a-z0-9.+]+", lowered):
            if token and token in FAMILY_BY_TOKEN:
                family = FAMILY_BY_TOKEN[token]
                break

    return family, mode, key_size, curve


def _is_algorithmic(evidence: RawEvidence) -> bool:
    """Whether a parameter resolution can meaningfully apply to this record."""
    return (
        evidence.target_type == TargetType.SOURCE_CODE
        and evidence.detected_name not in _NON_ALGORITHM_NAMES
    )


def _annotate(evidence: RawEvidence, finding, binding: str) -> None:
    """Record where a resolved value came from, so the override is auditable."""
    meta = evidence.metadata
    previous = meta.get("detector", "regex")
    if "taint" not in str(previous):
        meta["detector"] = f"{previous}+taint"
    meta["parameters_resolved"] = True
    meta["taint_rule"] = finding.rule.rsplit(".", 1)[-1]
    meta["taint_binding"] = binding
    if finding.source_line:
        meta["taint_source"] = f"{os.path.basename(finding.source_file or '')}:{finding.source_line}"
    if finding.hops:
        meta["taint_hops"] = list(finding.hops)


def _new_evidence(finding, family: str, mode, key_size, curve) -> RawEvidence:
    """Evidence for an asset that only dataflow analysis could see."""
    return RawEvidence(
        id=str(uuid.uuid4()),
        target_type=TargetType.SOURCE_CODE,
        file_path=finding.file_path,
        line_number=finding.line_number,
        column_number=finding.column_number,
        snippet=finding.snippet,
        matched_pattern=finding.unquoted_value,
        raw_type=finding.asset_type,
        detected_name=family,
        version_or_mode=mode,
        key_length=key_size,
        curve_name=curve,
        metadata={
            "rule_name": "Cryptographic parameter resolved by dataflow",
            "detector": "taint",
            "parameters_resolved": True,
            "taint_rule": finding.rule.rsplit(".", 1)[-1],
            "taint_binding": "direct",
            "taint_source": (
                f"{os.path.basename(finding.source_file or '')}:{finding.source_line}"
                if finding.source_line else None
            ),
            "taint_hops": list(finding.hops),
            "file_ext": os.path.splitext(finding.file_path)[1],
        },
    )


class TaintScanner:
    """
    Runs the dataflow pass and merges its results into existing evidence.

    Unlike the other scanners this is not per-file: a whole-program analysis has
    to see the tree at once to build a call graph, and the binary carries a fixed
    start-up cost of roughly two seconds that would be paid per file otherwise.
    It therefore runs once, after the per-file scanners, through ``enrich``.
    """

    def available(self) -> bool:
        return opengrep_engine.is_available()

    def enrich(
        self,
        evidences: List[RawEvidence],
        targets: Sequence[str],
    ) -> Tuple[List[RawEvidence], TaintReport]:
        """
        Resolve parameters across ``targets`` and fold them into ``evidences``.

        Returns the evidence list (enriched in place, plus any additions) and a
        report. Evidence is never dropped: a failure here costs refinement, not
        findings.
        """
        from backend.config import config

        if not config.dataflow_analysis_enabled:
            return evidences, TaintReport(
                available=False,
                reason="disabled in settings",
            )

        report = TaintReport(
            available=opengrep_engine.is_available(),
            reason=opengrep_engine.unavailable_reason(),
            version=opengrep_engine.version(),
            rules=opengrep_engine.rule_count(),
        )
        if not report.available:
            return evidences, report

        findings = opengrep_engine.scan_paths(targets)
        if findings is None:
            report.available = False
            report.reason = "dataflow analysis failed or timed out"
            return evidences, report

        report.findings = len(findings)
        if not findings:
            return evidences, report

        # Evidence indexed by file, in line order, so a binding search is a scan
        # over one file rather than the whole inventory.
        by_file: Dict[str, List[RawEvidence]] = {}
        for evidence in evidences:
            if _is_algorithmic(evidence):
                by_file.setdefault(evidence.file_path, []).append(evidence)
        for records in by_file.values():
            records.sort(key=lambda e: e.line_number or 0)

        added: List[RawEvidence] = []

        # Algorithms and curves are applied before key sizes, because a key size
        # with no record on its own line is bound to the nearest preceding
        # generator, and that generator may be a record this pass is about to
        # create. `KeyGenerator.getInstance(algo)` followed by `kg.init(bits)` is
        # exactly this shape.
        order = {"algorithm": 0, "curve": 1, "key_size": 2}
        for finding in sorted(findings, key=lambda f: (order.get(f.param, 3),
                                                       f.file_path, f.line_number)):
            records = by_file.get(finding.file_path, [])
            exact = [e for e in records if e.line_number == finding.line_number]

            if finding.param == "key_size":
                self._apply_key_size(finding, exact, records, report, added)
            elif finding.param == "curve":
                self._apply_curve(finding, exact, report, added)
            elif finding.param == "algorithm":
                self._apply_algorithm(finding, exact, report, added)

        if added:
            report.evidence_added = len(added)
            evidences = evidences + added
        return evidences, report

    # -------------------------------------------------------------- appliers

    def _apply_key_size(self, finding, exact, records, report, added) -> None:
        size = finding.value_as_int
        if size is None:
            return

        target = exact[0] if exact else None
        binding = "direct"
        if target is None:
            # The generator and its `init()` are different statements. Bind to
            # the nearest preceding algorithm in the same file, which is the
            # generator being initialised.
            target = self._nearest_preceding(records, finding.line_number)
            binding = "nearest-generator"

        if target is None:
            family = finding.family
            if family:
                added.append(_new_evidence(finding, family, None, size, None))
                report.key_sizes_resolved += 1
            return

        if target.key_length is not None and target.key_length != size:
            report.defaults_corrected += 1
            target.metadata["taint_replaced_key_length"] = target.key_length
        if target.key_length != size:
            report.key_sizes_resolved += 1
        target.key_length = size
        # Recorded separately from the record's overall binding: the algorithm may
        # have been resolved directly while the key size was bound by proximity.
        target.metadata["taint_key_length_binding"] = binding
        _annotate(target, finding, binding)

    def _apply_curve(self, finding, exact, report, added) -> None:
        curve = finding.unquoted_value
        if not curve:
            return
        if not exact:
            added.append(_new_evidence(finding, finding.family or "ECC", None, None, curve))
            report.curves_resolved += 1
            return

        target = exact[0]
        if target.curve_name is not None and target.curve_name.lower() != curve.lower():
            report.defaults_corrected += 1
            target.metadata["taint_replaced_curve"] = target.curve_name
        if (target.curve_name or "").lower() != curve.lower():
            report.curves_resolved += 1
        target.curve_name = curve
        if target.detected_name == "Unresolved-Algorithm":
            target.detected_name = "ECC"
        _annotate(target, finding, "direct")

    def _apply_algorithm(self, finding, exact, report, added) -> None:
        family, mode, key_size, curve = _parse_algorithm_string(finding.unquoted_value)
        if family is None:
            # The string resolved but names nothing recognisable — a provider
            # name, or an algorithm this build does not know. Leaving the record
            # as it stands is more honest than inventing a family for it.
            return

        if not exact:
            added.append(_new_evidence(finding, family, mode, key_size, curve))
            report.algorithms_resolved += 1
            return

        target = exact[0]
        if target.detected_name == "Unresolved-Algorithm":
            target.detected_name = family
            report.algorithms_resolved += 1
        elif target.detected_name != family:
            # Tiers 1-3 named it something else. The traced literal is the value
            # that actually reaches the call, so it wins, and the displaced name
            # is kept for audit.
            target.metadata["taint_replaced_name"] = target.detected_name
            target.detected_name = family
            report.algorithms_resolved += 1
            report.defaults_corrected += 1

        if mode and target.version_or_mode != mode:
            target.version_or_mode = mode
        if key_size and target.key_length != key_size:
            if target.key_length is not None:
                report.defaults_corrected += 1
                target.metadata["taint_replaced_key_length"] = target.key_length
            target.key_length = key_size
            report.key_sizes_resolved += 1
        if curve and target.curve_name != curve:
            target.curve_name = curve

        _annotate(target, finding, "direct")

    @staticmethod
    def _nearest_preceding(records: List[RawEvidence], line: int) -> Optional[RawEvidence]:
        """
        The closest algorithm at or above ``line``, within the binding window.

        Records are in line order, so the last one that qualifies is the nearest.
        A record whose *key length* was already resolved at its own call site is
        skipped — that value was read where it was written, and this one belongs
        to something else.
        """
        best: Optional[RawEvidence] = None
        for evidence in records:
            position = evidence.line_number or 0
            if position > line:
                break
            if line - position > BINDING_WINDOW_LINES:
                continue
            if evidence.metadata.get("taint_key_length_binding") == "direct":
                continue
            best = evidence
        return best
