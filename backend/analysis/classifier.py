from typing import List
from backend.models import CryptographicArtefact, ArtefactType, BusinessCriticality, AlgorithmClass


class Classifier:
    """
    Classifies cryptographic artefacts by Type, Artefact Lifetime,
    Data Shelf Life (Mosca X), and Business Criticality.
    """

    @staticmethod
    def classify_artefact(art: CryptographicArtefact) -> CryptographicArtefact:
        # Determine lifetime details
        if art.type == ArtefactType.KEY:
            art.artefact_lifetime = "Key Rotation Cycle (Annual / 1-2 yrs)"
        elif art.type == ArtefactType.CERTIFICATE:
            art.artefact_lifetime = "X.509 Certificate Validity (398 days / ~1 yr)"
        elif art.type == ArtefactType.PROTOCOL:
            art.artefact_lifetime = "Infrastructure Protocol Deployment (3-5 yrs)"
        elif art.type == ArtefactType.LIBRARY:
            art.artefact_lifetime = "Third-Party Dependency Maintenance Cycle"
        elif art.type == ArtefactType.HARDWARE_MODULE:
            art.artefact_lifetime = "HSM / Secure Element Hardware Lifetime (5-10 yrs)"
        elif art.type == ArtefactType.CLOUD_SERVICE:
            art.artefact_lifetime = "Cloud Provider SLA & KMS Rotation Policy"

        # Refine Business Criticality from the path context.
        #
        # This used to match the bare substrings "crypto" and "private", which
        # fire on almost every path in a cryptography codebase (including this
        # tool's own source tree) and pushed nearly every artefact to HIGH. The
        # result was a risk distribution where the HIGH band was permanently
        # empty because the engine below reserves HIGH for standard-criticality
        # assets. Matching is now on path segments that genuinely indicate a
        # sensitive subsystem.
        segments = {
            seg for seg in art.location.lower().replace("\\", "/").split("/") if seg
        }
        # Strip the file extension from the final segment so "payment.py"
        # matches "payment".
        stems = {seg.rsplit(".", 1)[0] for seg in segments}
        sensitive_contexts = {
            "auth", "authentication", "authorization", "payment", "payments",
            "billing", "banking", "ledger", "identity", "iam", "session",
            "secrets", "keystore", "keyvault", "kms", "hsm", "vault",
            "credentials", "signing", "tls", "pki",
        }
        if stems & sensitive_contexts:
            art.business_criticality = BusinessCriticality.HIGH

        # Key material and hardware modules in a sensitive context are the
        # highest-consequence assets in any inventory.
        if art.type in [ArtefactType.HARDWARE_MODULE, ArtefactType.KEY] and art.business_criticality == BusinessCriticality.HIGH:
            art.business_criticality = BusinessCriticality.CRITICAL

        # A classically broken primitive is a defect regardless of where it sits,
        # but it does not by itself make the surrounding system business-critical.
        # Its severity is expressed by the risk engine, not by inflating this field.
        if art.algorithm_class == AlgorithmClass.LEGACY_BROKEN:
            if art.business_criticality in (BusinessCriticality.LOW, BusinessCriticality.MEDIUM):
                art.business_criticality = BusinessCriticality.MEDIUM

        return art

    @staticmethod
    def classify_all(artefacts: List[CryptographicArtefact]) -> List[CryptographicArtefact]:
        return [Classifier.classify_artefact(art) for art in artefacts]
