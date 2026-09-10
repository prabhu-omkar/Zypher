import uuid
import re
from typing import List, Dict, Any, Optional
from backend.models import (
    RawEvidence, CryptographicArtefact, ArtefactType,
    AlgorithmClass, QuantumVulnerabilityStatus, BusinessCriticality, TargetType
)
from backend.cbom.purl import build_purl, normalise_version


# Field size in bits for the named curves, which is the ECC analogue of a key
# length and the value that feeds X in Mosca's inequality.
#
# This used to be a three-way substring test — 256 if the name contained "256",
# else 384 if it contained "384", else 521. Every other curve therefore became
# 521 bits. That went unnoticed while the scanners only ever emitted curves from
# their own short list, but Tier 4 resolves whatever name appears in the code, and
# a 160-bit curve reported as 521-bit understates the risk on the one asset class
# where the curve *is* the strength.
_CURVE_BITS: Dict[str, int] = {
    # NIST / SECG prime curves
    "secp160r1": 160, "secp160k1": 160, "secp160r2": 160,
    "secp192r1": 192, "secp192k1": 192, "prime192v1": 192, "p-192": 192,
    "secp224r1": 224, "secp224k1": 224, "p-224": 224,
    "secp256r1": 256, "secp256k1": 256, "prime256v1": 256, "p-256": 256,
    "nist256p": 256, "nistp256": 256,
    "secp384r1": 384, "p-384": 384, "nist384p": 384, "nistp384": 384,
    "secp521r1": 521, "p-521": 521, "nist521p": 521, "nistp521": 521,
    # Edwards / Montgomery
    "ed25519": 255, "x25519": 255, "curve25519": 255,
    "ed448": 448, "x448": 448, "curve448": 448,
    # Brainpool
    "brainpoolp160r1": 160, "brainpoolp192r1": 192, "brainpoolp224r1": 224,
    "brainpoolp256r1": 256, "brainpoolp320r1": 320, "brainpoolp384r1": 384,
    "brainpoolp512r1": 512,
    # Binary-field curves, still present in older embedded code
    "sect163k1": 163, "sect233k1": 233, "sect283k1": 283,
    "sect409k1": 409, "sect571k1": 571,
}

_CURVE_DIGITS = re.compile(r"(\d{3})")


def curve_strength_bits(curve: Optional[str]) -> Optional[int]:
    """
    Field size for a curve name, or None when the curve is not recognised.

    Returning None matters: an unrecognised curve reported at a plausible-looking
    bit count is worse than one reported as undetermined, because the number
    silently becomes a risk input.
    """
    if not curve:
        return None
    text = curve.strip().lower()

    if text in _CURVE_BITS:
        return _CURVE_BITS[text]

    # Names often arrive decorated — "secp256r1 (P-256)", "NID_X9_62_prime256v1".
    for name, bits in _CURVE_BITS.items():
        if name in text:
            return bits

    # A three-digit group in an unknown name is the curve size by convention
    # (secp239k1, brainpoolP320t1). Two-digit groups are deliberately not read
    # this way: "25519" must not become 255 by accident, and it is handled above.
    match = _CURVE_DIGITS.search(text)
    if match:
        return int(match.group(1))

    return None


def _parameter_source_for(ev: RawEvidence) -> Optional[str]:
    """
    How this record's parameters were arrived at.

    The distinction that matters is measured versus assumed. A key size traced
    across a function boundary is a fact; the 2048 the regex tier substitutes when
    it cannot read one is a convention, and the two must not look alike in the
    inventory — they drive different Mosca risk bands.
    """
    detector = str(ev.metadata.get("detector") or "")
    if "taint" in detector:
        return "dataflow"
    resolved = ev.metadata.get("parameters_resolved")
    if resolved is True:
        return "literal"
    if resolved is False:
        return "assumed"
    # Regex evidence records nothing either way. A value it reports was either
    # matched in the line or taken from a default, and it cannot say which.
    return None


def _confidence_for(ev: RawEvidence) -> float:
    """
    Confidence in one piece of evidence.

    Dataflow-resolved parameters rank highest: the value was read where it was
    written and followed to where it is used, rather than inferred from the shape
    of a single line.
    """
    detector = str(ev.metadata.get("detector") or "")
    if "taint" in detector:
        return 0.99
    if detector == "ast":
        # A resolved parse of the call site, materially better than a text match.
        return 0.98
    return 0.90


class ArtefactExtractor:
    """
    Normalizes raw cryptographic evidence from all scanners into unified,
    strongly-typed CryptographicArtefact records for CBOM construction.
    """

    @staticmethod
    def extract_artefacts(raw_evidences: List[RawEvidence]) -> List[CryptographicArtefact]:
        artefacts: List[CryptographicArtefact] = []

        for ev in raw_evidences:
            artefact = ArtefactExtractor._normalize_evidence(ev)
            if artefact:
                artefacts.append(artefact)

        return artefacts

    @staticmethod
    def _normalize_evidence(ev: RawEvidence) -> CryptographicArtefact:
        raw_name = ev.detected_name.upper()
        raw_type = ev.raw_type.lower()
        matched = ev.matched_pattern.upper()
        snippet = ev.snippet or ""

        # Default values
        art_type = ArtefactType.ALGORITHM
        alg_family = ev.detected_name
        # Both default to UNKNOWN, never to a concrete guess.
        alg_class = AlgorithmClass.UNKNOWN
        # Never default to QUANTUM_SAFE. An asset whose primitive we
        # could not identify (a bare key file, a certificate, an HSM reference)
        # must not be reported as safe just because no branch below matched it.
        q_vuln = QuantumVulnerabilityStatus.UNKNOWN
        broken_by: Optional[str] = None
        key_size = ev.key_length
        curve = ev.curve_name
        mode = ev.version_or_mode
        criticality = BusinessCriticality.MEDIUM
        # The artefact-type branch below establishes a floor, and the algorithm
        # branch after it sets criticality from the primitive. Without the floor
        # the second silently overwrote the first, so an expired certificate or
        # a root CA came out at whatever its key size implied — the RSA branch
        # reset a CRITICAL certificate to MEDIUM purely because it was 2048-bit.
        criticality_floor = BusinessCriticality.LOW
        lifetime_desc = "Standard Production Lifetime (3-5 years)"
        hw_ref = None
        cloud_ref = None
        measured_validity = None

        # Determine Artefact Type
        if raw_type == "key":
            art_type = ArtefactType.KEY
            criticality = BusinessCriticality.HIGH
            lifetime_desc = "Private Key Certificate Lifecycle (1-2 years)"
        elif raw_type == "certificate":
            art_type = ArtefactType.CERTIFICATE
            criticality = BusinessCriticality.HIGH
            lifetime_desc = "X.509 Certificate Validity (1-3 years)"
            # A parsed certificate states its own validity window and whether it
            # has already lapsed. Both are facts about this specific asset, so
            # they replace the conventional assumptions rather than sitting
            # alongside them.
            measured_validity = ev.metadata.get("validity_years")
            if measured_validity:
                lifetime_desc = (
                    f"X.509 certificate, {measured_validity:g}-year validity "
                    f"(read from the certificate)"
                )
            if ev.metadata.get("is_expired"):
                criticality_floor = BusinessCriticality.CRITICAL
            elif ev.metadata.get("is_certificate_authority"):
                # A CA signs other certificates, so replacing it is a chain-wide
                # change rather than a single reissue.
                criticality_floor = BusinessCriticality.CRITICAL
        elif raw_type == "protocol":
            art_type = ArtefactType.PROTOCOL
            criticality = BusinessCriticality.MEDIUM
            lifetime_desc = "Network Transport Protocol Lifecycle"
        elif raw_type == "library":
            art_type = ArtefactType.LIBRARY
            criticality = BusinessCriticality.MEDIUM
            lifetime_desc = "Third-Party Library Support Cycle (2-3 years)"
        elif raw_type == "hardware_module":
            art_type = ArtefactType.HARDWARE_MODULE
            criticality = BusinessCriticality.CRITICAL
            lifetime_desc = "Hardware Security Module Firmware Lifecycle (5-10 years)"
            hw_ref = "PKCS#11 HSM / Cryptographic Token"
        elif raw_type == "cloud_service":
            art_type = ArtefactType.CLOUD_SERVICE
            criticality = BusinessCriticality.HIGH
            lifetime_desc = "Cloud Managed KMS Key Rotation (1 year)"
            cloud_ref = "Enterprise Cloud KMS / Vault Service"

        # Classification & Quantum Vulnerability Mapping
        # 1. RSA
        if "RSA" in raw_name or "RSA" in matched:
            alg_family = "RSA"
            alg_class = AlgorithmClass.ASYMMETRIC_FACTORING
            if key_size and key_size <= 1024:
                q_vuln = QuantumVulnerabilityStatus.CLASSICALLY_BROKEN
                broken_by = "Classical Factorization (NFS) & Shor's Algorithm"
                criticality = BusinessCriticality.CRITICAL
            else:
                q_vuln = QuantumVulnerabilityStatus.FULLY_BROKEN
                broken_by = "Shor's Algorithm (Order Finding via Quantum Periodicity)"
                if not key_size:
                    key_size = 2048
                # Baseline: Shor breaks RSA at any size, but how *critical* that is
                # depends on what the key protects. Context (path, artefact type)
                # escalates this in Classifier; an under-strength key is already
                # a defect and stays HIGH.
                criticality = BusinessCriticality.MEDIUM if key_size >= 2048 else BusinessCriticality.HIGH

        # 2. ECC / ECDSA / ECDH / Ed25519
        elif any(k in raw_name or k in matched for k in ["ECC", "ECDSA", "ECDH", "SECP256K1", "ED25519", "X25519", "PRIME256V1"]):
            alg_family = "ECC"
            alg_class = AlgorithmClass.ASYMMETRIC_DISCRETE_LOG
            q_vuln = QuantumVulnerabilityStatus.FULLY_BROKEN
            broken_by = "Shor's Algorithm (Discrete Logarithm on Elliptic Curves)"
            if not curve:
                curve = "secp256r1 (P-256)"
            key_size = curve_strength_bits(curve)
            criticality = BusinessCriticality.MEDIUM

        # 3. Diffie-Hellman / DSA
        elif any(k in raw_name or k in matched for k in ["DIFFIE-HELLMAN", "DH", "DSA"]):
            alg_family = "Diffie-Hellman / DSA"
            alg_class = AlgorithmClass.ASYMMETRIC_DISCRETE_LOG
            q_vuln = QuantumVulnerabilityStatus.FULLY_BROKEN
            broken_by = "Shor's Algorithm (Discrete Logarithm Problem)"
            key_size = key_size or 2048
            criticality = BusinessCriticality.MEDIUM

        # 4. AES
        elif "AES" in raw_name or "AES" in matched:
            alg_family = "AES"
            alg_class = AlgorithmClass.SYMMETRIC
            if key_size is None:
                # The source did not state a length. Assuming 256 would report
                # an unknown key as quantum-safe, which is the one direction an
                # inventory must never guess in.
                q_vuln = QuantumVulnerabilityStatus.UNKNOWN
                broken_by = (
                    "Key length is not stated at this call site. AES-128 is "
                    "degraded by Grover's; AES-256 is not. Confirm the "
                    "configured length before relying on this."
                )
                criticality = BusinessCriticality.MEDIUM
            elif key_size <= 128:
                q_vuln = QuantumVulnerabilityStatus.DEGRADED
                broken_by = "Grover's Algorithm (Reduces 128-bit security to 64-bit quantum effective)"
                criticality = BusinessCriticality.MEDIUM
            else:
                q_vuln = QuantumVulnerabilityStatus.QUANTUM_SAFE
                broken_by = "Resistant (Grover's leaves 128-bit quantum security margin for AES-256)"
                criticality = BusinessCriticality.MEDIUM

        # 5. Legacy Broken Symmetric (DES, 3DES, RC4, Blowfish)
        elif any(k in raw_name or k in matched for k in ["DES", "3DES", "TRIPLEDES", "RC4", "BLOWFISH", "LEGACY-CIPHER"]):
            alg_family = "Legacy Symmetric Cipher (DES/3DES/RC4)"
            alg_class = AlgorithmClass.LEGACY_BROKEN
            q_vuln = QuantumVulnerabilityStatus.CLASSICALLY_BROKEN
            broken_by = "Classical Cryptanalysis & Sweet32 / Meet-in-the-middle"
            criticality = BusinessCriticality.CRITICAL

        # 6. ChaCha20
        elif "CHACHA20" in raw_name or "CHACHA20" in matched:
            alg_family = "ChaCha20-Poly1305"
            alg_class = AlgorithmClass.SYMMETRIC
            key_size = 256
            q_vuln = QuantumVulnerabilityStatus.QUANTUM_SAFE
            broken_by = "Resistant (Grover's preserves 128-bit quantum security)"
            criticality = BusinessCriticality.MEDIUM

        # 7. Broken Hashes (MD5, SHA-1)
        elif any(k in raw_name or k in matched for k in ["MD5", "SHA-1", "SHA1"]):
            alg_family = "MD5/SHA-1"
            alg_class = AlgorithmClass.LEGACY_BROKEN
            q_vuln = QuantumVulnerabilityStatus.CLASSICALLY_BROKEN
            broken_by = "Classical Collision Attacks (SHAttered / Flame)"
            criticality = BusinessCriticality.MEDIUM

        # 8. SHA-2 / SHA-3
        elif any(k in raw_name or k in matched for k in ["SHA-256", "SHA-384", "SHA-512", "SHA-3", "SHA256"]):
            alg_family = "SHA-2 / SHA-3"
            alg_class = AlgorithmClass.HASH
            if "256" in raw_name or "256" in matched:
                q_vuln = QuantumVulnerabilityStatus.DEGRADED
                broken_by = "Grover's (Preimage) & BHT (Collision speedup)"
            else:
                q_vuln = QuantumVulnerabilityStatus.QUANTUM_SAFE
                broken_by = "Quantum-Resistant (Adequate hash bit length)"
            criticality = BusinessCriticality.LOW

        # 9. Post Quantum (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium)
        elif any(k in raw_name or k in matched for k in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS+", "FALCON", "PQC-FIPS", "FIPS 203", "FIPS 204", "FIPS 205"]):
            alg_family = "NIST Post-Quantum Standard (FIPS 203/204/205)"
            alg_class = AlgorithmClass.POST_QUANTUM
            q_vuln = QuantumVulnerabilityStatus.QUANTUM_SAFE
            broken_by = "Lattice-based / Stateless Hash-based (No known quantum shortcut)"
            criticality = BusinessCriticality.LOW

        # 10. Hybrid PQC
        elif any(k in raw_name or k in matched for k in ["HYBRID", "X25519KYBER768", "X25519MLKEM"]):
            alg_family = "Hybrid PQC + Classical Scheme"
            alg_class = AlgorithmClass.HYBRID
            q_vuln = QuantumVulnerabilityStatus.HYBRID_PROTECTED
            broken_by = "Protected by Dual-Layer Classical + Lattice Security"
            criticality = BusinessCriticality.LOW

        # 11. Insecure Protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
        elif any(k in matched for k in ["SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"]):
            alg_family = "Deprecated Protocol (SSL/TLS < 1.2)"
            alg_class = AlgorithmClass.LEGACY_BROKEN
            q_vuln = QuantumVulnerabilityStatus.CLASSICALLY_BROKEN
            broken_by = "POODLE / BEAST / DROWN Classical Attacks"
            criticality = BusinessCriticality.CRITICAL

        # A cryptographic library is not an unidentified primitive — it is a
        # dependency that provides many. The dependency scanner already records
        # whether it offers post-quantum algorithms, so use that rather than
        # lumping libraries in with unreadable key files.
        if art_type == ArtefactType.LIBRARY and alg_class == AlgorithmClass.UNKNOWN:
            if ev.metadata.get("pqc_supported"):
                # Providing a post-quantum algorithm and being safe to depend on
                # are different claims. liboqs and the pqcrypto crates state in
                # their own documentation that their implementations are
                # experimental and must not be used in production, so reporting
                # them as quantum-safe told an operator the opposite of what the
                # library itself says.
                if ev.metadata.get("pqc_experimental"):
                    q_vuln = QuantumVulnerabilityStatus.UNKNOWN
                    broken_by = (
                        "This library implements post-quantum algorithms, but its "
                        "own documentation states they are experimental and not "
                        "for production use. Finding it in a shipped dependency "
                        "manifest is itself the finding."
                    )
                    criticality = BusinessCriticality.HIGH
                else:
                    q_vuln = QuantumVulnerabilityStatus.QUANTUM_SAFE
                    broken_by = (
                        "This library provides post-quantum algorithms. Confirm "
                        "the application actually selects them."
                    )
                    criticality = BusinessCriticality.LOW
            else:
                broken_by = (
                    "A general-purpose cryptographic library. Its risk depends on "
                    "which primitives the application selects from it."
                )

        # An expired or imminently expiring certificate is a present-day defect,
        # reported alongside the quantum verdict rather than instead of it.
        if art_type == ArtefactType.CERTIFICATE:
            days = ev.metadata.get("days_until_expiry")
            note = None
            if ev.metadata.get("is_expired"):
                note = f"This certificate expired {abs(days)} days ago."
            elif days is not None and days <= 30:
                note = f"This certificate expires in {days} days."
            if note:
                broken_by = f"{note} {broken_by}" if broken_by else note

        if q_vuln == QuantumVulnerabilityStatus.UNKNOWN and broken_by is None:
            broken_by = (
                "Undetermined — the underlying algorithm is not visible in the "
                "evidence. Inspect this asset manually."
            )

        # A dependency needs a canonical identifier, not just a display name:
        # every vulnerability service keys off purl, and CycloneDX carries it as
        # a first-class field.
        purl = None
        version_is_range = False
        if ev.target_type == TargetType.DEPENDENCY:
            concrete_version, version_is_range = normalise_version(ev.version_or_mode)
            purl = build_purl(
                ev.metadata.get("ecosystem"),
                ev.matched_pattern,
                concrete_version,
            )

        # Apply the floor the artefact type established, so a fact about this
        # specific asset is never undone by a generalisation about its primitive.
        _RANK = {
            BusinessCriticality.LOW: 0, BusinessCriticality.MEDIUM: 1,
            BusinessCriticality.HIGH: 2, BusinessCriticality.CRITICAL: 3,
        }
        if _RANK[criticality_floor] > _RANK[criticality]:
            criticality = criticality_floor

        # Generate readable unique name
        readable_name = f"{alg_family}"
        if key_size:
            readable_name += f"-{key_size}"
        if curve:
            readable_name += f" ({curve})"
        if art_type == ArtefactType.CERTIFICATE:
            # A certificate is identified by who it is for, not by the algorithm
            # it was signed with. Appending the signature OID produced names like
            # "RSA-2048-sha256WithRSAEncryption", which reads as a primitive
            # nobody has ever heard of.
            subject = ev.metadata.get("subject")
            # Some evidence already carries the word — the source scanner's
            # match on a PEM header is named "X509-Certificate" — so appending
            # it unconditionally produced "X509-Certificate certificate".
            if "certificate" not in readable_name.lower():
                readable_name += " certificate"
            if subject:
                readable_name += f" ({subject})"
        elif mode and mode != "GCM":
            readable_name += f"-{mode}"

        return CryptographicArtefact(
            id=f"ART-{str(uuid.uuid4())[:8].upper()}",
            name=readable_name,
            type=art_type,
            algorithm_family=alg_family,
            mode_or_padding=mode,
            key_size_bits=key_size,
            curve=curve,
            version=ev.version_or_mode,
            location=ev.file_path,
            line_number=ev.line_number,
            target_type=ev.target_type,
            algorithm_class=alg_class,
            quantum_vulnerability=q_vuln,
            broken_by=broken_by,
            business_criticality=criticality,
            # X and Y are deliberately not set here. They used to be constants
            # in a table keyed on the algorithm name, which made X a property of
            # the primitive rather than of the data it protects, and Y a
            # property of the primitive rather than of who has to change it and
            # how far it reaches. Both are now derived in
            # analysis/risk_inputs.py from the scan's sensitivity profile and
            # from this artefact's own evidence, and written back by
            # QuantumRiskEngine.prepare_artefact before assessment.
            artefact_lifetime=lifetime_desc,
            hardware_module_ref=hw_ref,
            cloud_service_ref=cloud_ref,
            code_snippet=snippet,
            measured_validity_years=measured_validity,
            confidence_score=_confidence_for(ev),
            parameter_source=_parameter_source_for(ev),
            purl=purl,
            version_is_range=version_is_range,
        )
