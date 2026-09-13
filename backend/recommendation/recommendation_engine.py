"""
What to migrate each asset to, and when.

Two things decide the target: what the asset is *for* (which the risk layer
already established as a CryptoUsage, rather than being sniffed out of the
algorithm's name) and what security level it is *replacing* (which sets the NIST
category, rather than being chosen by a latency preference). Latency still
matters, but as a reason to prefer one option within a category — never as a
reason to drop below it.

The urgency is a date, taken from the risk engine's schedule. "High / 6-12
months" was a fixed string keyed on a risk band and said nothing about this
particular asset.
"""
from datetime import date
from typing import Dict, List, Optional

from backend.analysis.risk_inputs import classify_usage
from backend.models import (
    AlgorithmClass, ArtefactType, CostConsideration, CryptographicArtefact,
    CryptoUsage, DataSensitivityProfile, LatencyRequirement,
    MoscaRiskAssessment, PQCRecommendation, RiskCategory,
)
from backend.recommendation.pqc_targets import (
    HASH_SIGNATURE_BY_CATEGORY, HYBRID_PARTNER, KEM_BY_CATEGORY, NOT_A_TARGET,
    SIGNATURE_BY_CATEGORY, TLS_HYBRID_GROUP, classical_strength_bits,
    implementations_for, needs_signature, size_note, target_category,
)


class RecommendationEngine:
    """Selects a FIPS 203/204/205 target for an asset and schedules the work."""

    @classmethod
    def _urgency(cls, risk: MoscaRiskAssessment) -> str:
        """
        When work has to begin, as a date rather than a band.

        Falls back to the risk category only for assessments produced before the
        schedule existed, so a stored scan still renders.
        """
        if risk.must_start_by is None:
            return {
                RiskCategory.CRITICAL: "Immediate",
                RiskCategory.HIGH: "High",
                RiskCategory.MEDIUM: "Planned",
            }.get(risk.risk_category, "Scheduled")

        if risk.is_overdue:
            return (
                f"Overdue — the start date was {risk.must_start_by.isoformat()}, "
                f"{abs(risk.slack_years):g} years ago"
            )
        if risk.slack_years is not None and risk.slack_years < 1:
            months = max(1, round(risk.slack_years * 12))
            return f"Start within {months} month{'s' if months != 1 else ''}"
        return (
            f"Start by {risk.must_start_by.isoformat()}, complete by "
            f"{risk.must_complete_by.isoformat()}"
        )

    @classmethod
    def generate_recommendation(
        cls,
        art: CryptographicArtefact,
        risk: MoscaRiskAssessment,
        latency_req: LatencyRequirement = LatencyRequirement.STANDARD,
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
    ) -> PQCRecommendation:
        alg_class = art.algorithm_class
        urgency = cls._urgency(risk)

        # Usage is read off the artefact when the risk layer has established it,
        # and derived read-only when it has not. Unlike X and Y this cannot
        # rewrite an audited number, so deriving it here is safe.
        usage = art.crypto_usage
        if usage == CryptoUsage.UNKNOWN:
            usage = classify_usage(art)

        category, category_why = target_category(art, profile)
        replaces_bits = classical_strength_bits(art)
        implementations = implementations_for(art)

        kem = KEM_BY_CATEGORY[category]
        sig = SIGNATURE_BY_CATEGORY[category]
        slh = HASH_SIGNATURE_BY_CATEGORY[category]
        partner = HYBRID_PARTNER[category]
        tls_group = TLS_HYBRID_GROUP[category]

        rationale = category_why
        size_impact = ""
        standard_reference = None

        # ---------------------------------------------- 1. asymmetric primitives
        if alg_class in (
            AlgorithmClass.ASYMMETRIC_FACTORING,
            AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
        ) or (alg_class == AlgorithmClass.UNKNOWN and needs_signature(usage)):

            if needs_signature(usage):
                rec_standard = sig
                standard_reference = "NIST FIPS 204"
                alt_options = [
                    f"NIST FIPS 205 ({slh}) where the signature must outlive "
                    f"confidence in lattice assumptions — firmware, boot chains "
                    f"and long-lived roots",
                    f"NIST FIPS 204 ({SIGNATURE_BY_CATEGORY[category]}) with a "
                    f"composite X.509 certificate during the dual-stack period",
                ]
                if latency_req == LatencyRequirement.ULTRA_LOW:
                    alt_options.insert(
                        0,
                        "NIST FIPS 204 (ML-DSA-44) only if verification latency "
                        "is measured and proven to be the constraint — this "
                        "drops below the Category 3 target above",
                    )
                hybrid_rec = f"Composite X.509: {partner or 'ECDSA P-256'} + {sig}"
                size_impact = size_note(sig)
                cost = CostConsideration.MEDIUM
                steps = [
                    "1. Confirm the signing stack supports ML-DSA — see the "
                    "implementations listed below.",
                    "2. Issue composite certificates carrying both the classical "
                    "and the ML-DSA key, so verifiers that understand neither "
                    "one alone still succeed.",
                    "3. Check that trust stores, chain-building buffers and any "
                    "certificate-size limits accommodate the larger key and "
                    "signature.",
                    "4. Retire the classical-only signing keys once every "
                    "verifier in the estate accepts the composite.",
                ]
                diff_snippet = f"""# Migration: classical signature -> {sig} (FIPS 204)
# Java 24+, which ships ML-DSA under JEP 497:
- KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
- g.initialize(new ECGenParameterSpec("secp256r1"));
+ KeyPairGenerator g = KeyPairGenerator.getInstance("{sig}");
  KeyPair kp = g.generateKeyPair();
- Signature s = Signature.getInstance("SHA256withECDSA");
+ Signature s = Signature.getInstance("{sig}");"""

            else:
                rec_standard = kem
                standard_reference = "NIST FIPS 203"
                alt_options = [
                    f"Hybrid TLS group {tls_group} — negotiated by default in "
                    f"OpenSSL 3.5 and current browsers",
                    "For SSH: the sntrup761x25519-sha512 key exchange",
                ]
                if latency_req == LatencyRequirement.ULTRA_LOW:
                    alt_options.insert(
                        0,
                        "NIST FIPS 203 (ML-KEM-512) only where the extra "
                        "handshake bytes are measured to matter — this drops "
                        "below the Category 3 target above",
                    )
                hybrid_rec = f"Hybrid KEM: {partner} + {kem}"
                size_impact = size_note(kem)
                cost = CostConsideration.LOW
                steps = [
                    f"1. Enable the {tls_group} hybrid group at every TLS "
                    f"terminating endpoint. A hybrid stays secure if either half "
                    f"holds, so this is safe to deploy before ML-KEM alone is.",
                    "2. Replace RSA key transport with KEM encapsulation in any "
                    "application-level protocol that does its own key exchange.",
                    "3. Confirm no middlebox or MTU limit truncates the larger "
                    "ClientHello — this is the usual cause of a failed rollout.",
                    "4. Measure handshake latency at the edge before and after, "
                    "so the change is defensible if it is ever questioned.",
                ]
                diff_snippet = f"""# Migration: classical key exchange -> {kem} (FIPS 203)
# nginx or any OpenSSL 3.5+ terminator:
- ssl_conf_command Groups X25519:P-256;
+ ssl_conf_command Groups {tls_group}:X25519:P-256;

# Go 1.24+, whose standard library ships ML-KEM:
+ import "crypto/mlkem"
+ dk, err := mlkem.GenerateKey768()
+ sharedSecret, ciphertext := dk.EncapsulationKey().Encapsulate()"""

        # ------------------------------------------- 2. transport protocol config
        elif art.type == ArtefactType.PROTOCOL:
            rec_standard = "TLS 1.3 + hybrid key exchange"
            alt_options = [
                f"{tls_group} hybrid group — shipping in OpenSSL 3.5+ and major "
                f"browsers",
                "TLS 1.2 restricted to AEAD suites, only where 1.3 is not yet "
                "possible",
                "For SSH: enable sntrup761x25519-sha512",
            ]
            hybrid_rec = f"Hybrid key exchange: {partner} + {kem}"
            size_impact = size_note(kem)
            cost = CostConsideration.LOW
            rationale = (
                "A deprecated protocol version is a configuration defect, not an "
                "algorithm choice. Fixing the version comes first; the hybrid "
                "group is what stops the fixed endpoint being harvested."
            )
            steps = [
                "1. Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1 at every "
                "terminating endpoint.",
                "2. Require TLS 1.3, and restrict TLS 1.2 to AEAD cipher suites "
                "where it must remain.",
                f"3. Enable {tls_group} so handshakes resist harvest-now-"
                f"decrypt-later capture.",
                "4. Verify with an external scan that no legacy version remains "
                "negotiable — a disabled protocol that is still reachable is "
                "still a finding.",
            ]
            diff_snippet = f"""# Migration: deprecated TLS -> TLS 1.3 + hybrid PQC key exchange
- ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
+ ssl_protocols TLSv1.2 TLSv1.3;
+ ssl_conf_command Groups {tls_group}:X25519:P-256;
+ ssl_prefer_server_ciphers off;"""

        # ------------------------------------------------- 3. symmetric and legacy
        elif alg_class in (AlgorithmClass.SYMMETRIC, AlgorithmClass.LEGACY_BROKEN):
            is_aes = "AES" in art.algorithm_family.upper()
            rec_standard = "AES-256-GCM"
            alt_options = ["ChaCha20-Poly1305 (256-bit)", "AES-256-GCM-SIV"]
            hybrid_rec = None  # a symmetric cipher has no hybrid form
            size_impact = "No wire-size change; the key doubles in length."
            cost = CostConsideration.LOW
            rationale = (
                "Grover's algorithm halves the effective key length, so a "
                "256-bit key retains a 128-bit margin. There is no post-quantum "
                "replacement to adopt here — the fix is key length, not a new "
                "algorithm."
            )
            if is_aes:
                steps = [
                    "1. Raise the key derivation output from 16 to 32 bytes.",
                    "2. Rotate active keys to full 256-bit entropy — widening the "
                    "parameter without re-keying leaves the old key in place.",
                    "3. Standardise on AEAD modes, which removes padding-oracle "
                    "exposure at the same time.",
                ]
                diff_snippet = """# Migration: AES-128 -> AES-256-GCM
- cipher = AES.new(key_16_bytes, AES.MODE_CBC, iv)
+ from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+ aesgcm = AESGCM(key_32_bytes)   # 128-bit margin after Grover
+ ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)"""
            else:
                rec_standard = "AES-256-GCM"
                rationale = (
                    "This cipher is broken by classical cryptanalysis. It is "
                    "overdue remediation rather than quantum migration, and no "
                    "threat horizon makes it acceptable."
                )
                steps = [
                    "1. Stop using DES, 3DES, RC4 and Blowfish at every "
                    "interface — these are already disallowed by NIST SP "
                    "800-131A.",
                    "2. Re-encrypt stored ciphertext under AES-256-GCM. Data "
                    "encrypted under the old cipher stays broken until it is "
                    "re-encrypted.",
                    "3. Remove the deprecated suites from server configuration "
                    "so they cannot be renegotiated.",
                ]
                diff_snippet = """# Migration: legacy cipher -> AES-256-GCM
- from Crypto.Cipher import DES3
- cipher = DES3.new(key, DES3.MODE_ECB)
+ from cryptography.hazmat.primitives.ciphers.aead import AESGCM
+ cipher = AESGCM(key_32_bytes)"""

        # ----------------------------------------------------------- 4. hashes
        elif alg_class == AlgorithmClass.HASH:
            rec_standard = "SHA-384 / SHA-512"
            standard_reference = "FIPS 180-4 / FIPS 202"
            alt_options = ["SHA3-384", "SHA3-512"]
            hybrid_rec = None
            size_impact = "Digests grow from 32 to 48 or 64 bytes."
            cost = CostConsideration.LOW
            rationale = (
                "Grover gives a quadratic speed-up on preimage search, so a "
                "384-bit digest retains a 192-bit margin. CNSA 2.0 requires "
                "SHA-384 or SHA-512 for national security systems."
            )
            steps = [
                "1. Replace MD5, SHA-1 and SHA-256 with SHA-384 or SHA-512.",
                "2. Widen any column, index or field storing the digest before "
                "switching, or the new value is silently truncated.",
                "3. Re-hash stored integrity checksums; an old digest is not "
                "strengthened by changing the function that produces new ones.",
            ]
            diff_snippet = """# Migration: weak or degraded hash -> SHA-384
- digest = hashlib.md5(data).hexdigest()
+ digest = hashlib.sha384(data).hexdigest()"""

        # -------------------------------------------------- 5. already migrated
        elif alg_class in (AlgorithmClass.POST_QUANTUM, AlgorithmClass.HYBRID):
            rec_standard = "Already quantum-safe"
            alt_options = [
                "Track NIST parameter-set guidance for changes",
                f"Confirm the deployed parameter set reaches Category "
                f"{int(category)} for what this protects",
            ]
            hybrid_rec = None
            size_impact = "Already accounted for."
            cost = CostConsideration.LOW
            rationale = (
                "Nothing to migrate. The remaining work is confirming the "
                "parameter set is strong enough for what this asset protects."
            )
            steps = [
                "Keep this asset in the agility review so a future parameter "
                "change is a configuration edit rather than a rewrite.",
            ]
            diff_snippet = None

        # -------------------------------------------------------- 6. libraries
        elif art.type == ArtefactType.LIBRARY:
            rec_standard = "Review the library's primitives"
            alt_options = [
                "Upgrade to a release with NIST PQC support (FIPS 203/204/205)",
                "Where it is used only for hashing: move to SHA-384 or SHA-512",
                f"Where it provides key exchange or signatures: plan a {kem} / "
                f"{sig} path",
            ]
            hybrid_rec = None
            size_impact = "Depends on the primitives selected."
            cost = CostConsideration.LOW
            rationale = (
                "A library supplies many primitives, so there is no like-for-like "
                "swap. The actionable question is which of them this application "
                "actually calls."
            )
            steps = [
                "1. Confirm the pinned version and whether a PQC-capable release "
                "exists.",
                "2. Identify which algorithms the application actually calls from "
                "this library.",
                "3. Pin an explicit version rather than a floating range, so the "
                "next scan measures something definite.",
                "4. Add it to the agility review so a future swap is a "
                "configuration change rather than a rewrite.",
            ]
            diff_snippet = None

        # ----------------------------------------------- 7. hardware and cloud
        elif art.type in (ArtefactType.HARDWARE_MODULE, ArtefactType.CLOUD_SERVICE):
            rec_standard = "Vendor post-quantum path required"
            alt_options = [
                f"Where the module supports it: {kem} for key transport, {sig} "
                f"for signing",
                "Where it does not: a hardware refresh, which is procurement "
                "lead time rather than engineering time",
            ]
            hybrid_rec = None
            size_impact = "Determined by the mechanisms the module exposes."
            cost = CostConsideration.HIGH
            rationale = (
                "This asset cannot be migrated unilaterally — the schedule is "
                "set by the vendor's firmware, not by your release cycle, which "
                "is why its Y is the longest in the inventory."
            )
            steps = [
                "1. Ask the vendor for a written post-quantum roadmap with dates. "
                "This is the longest-lead item in most estates.",
                "2. List the mechanisms the module currently exposes (PKCS#11 "
                "mechanism list, or the KMS key-spec catalogue).",
                "3. If no PQC firmware path exists, start procurement now — the "
                "lead time, not the migration, is the constraint.",
                "4. Plan the key ceremony and custodian scheduling alongside, "
                "not after.",
            ]
            diff_snippet = None

        # ------------------------------------------- 8. primitive not identified
        else:
            rec_standard = "Identify the algorithm first"
            alt_options = [
                f"If it is RSA or ECC key material: {kem} or {sig}",
                "If symmetric: AES-256-GCM",
                "If a hardware module: confirm PQC support with the vendor",
            ]
            hybrid_rec = None
            size_impact = "Not assessable until the primitive is known."
            cost = CostConsideration.MEDIUM
            rationale = (
                "The algorithm behind this asset is not visible in the evidence. "
                "Naming a target now would be a guess presented as advice."
            )
            steps = [
                "1. Inspect the file or module to determine algorithm, key size "
                "and mode.",
                "2. For certificates and keys, read it from the artefact itself: "
                "`openssl x509 -in cert.pem -noout -text`.",
                "3. Record the finding so the asset is classified on the next "
                "scan rather than staying unknown.",
            ]
            diff_snippet = None

        return PQCRecommendation(
            artefact_id=art.id,
            current_algorithm=art.name,
            recommended_standard=rec_standard,
            alternative_options=alt_options,
            is_hybrid_available=bool(hybrid_rec),
            hybrid_recommendation=hybrid_rec,
            migration_urgency=urgency,
            latency_impact=size_impact,
            estimated_migration_cost=cost,
            migration_steps=steps,
            code_diff_example=diff_snippet,
            standard_reference=standard_reference,
            nist_category=int(category),
            replaces_classical_bits=replaces_bits,
            selection_rationale=rationale,
            implementation_targets=implementations,
            not_a_migration_target=NOT_A_TARGET,
        )

    @classmethod
    def generate_all(
        cls,
        artefacts: List[CryptographicArtefact],
        risk_assessments: Dict[str, MoscaRiskAssessment],
        latency_req: LatencyRequirement = LatencyRequirement.STANDARD,
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
    ) -> Dict[str, PQCRecommendation]:
        recommendations: Dict[str, PQCRecommendation] = {}
        for art in artefacts:
            risk = risk_assessments.get(art.id)
            if risk:
                recommendations[art.id] = cls.generate_recommendation(
                    art, risk, latency_req, profile
                )
        return recommendations
