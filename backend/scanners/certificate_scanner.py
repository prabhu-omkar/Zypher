"""
X.509 certificate discovery.

Until now a certificate was found by the source scanner noticing the text
"-----BEGIN CERTIFICATE-----" and recording an asset whose algorithm was
"unknown". That is the least useful possible result for the one artefact type
that states its own cryptography in machine-readable form: a certificate names
its public key algorithm, its key size or curve, the algorithm it was signed
with, and exactly how long it is trusted for.

This parses them properly. The parsed key size and curve feed the same risk
engine as everything else, and the validity window feeds X directly — for an
authenticity asset, X *is* the period the credential stays trusted, so a real
notAfter is better than the conventional default the engine would otherwise use.

Certificates that cannot be parsed are reported as unreadable rather than
skipped: a certificate the tool could not open is not a certificate that is
safe.
"""
import os
from datetime import datetime, timezone
from typing import Callable, List, Optional

from backend.models import RawEvidence, TargetType
from backend.scanners.walker import WalkLimits, WalkStats, walk_files

# Certificates are small. Anything larger than this is not one, and reading it
# would only waste the traversal budget.
MAX_CERTIFICATE_BYTES = 1 * 1024 * 1024

PEM_CERTIFICATE_HEADER = b"-----BEGIN CERTIFICATE-----"


class CertificateScanner:
    """Reads X.509 certificates and reports what they actually contain."""

    FILE_EXTENSIONS = {
        ".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle", ".p7b", ".p7c",
    }

    def __init__(self):
        self._x509 = None
        self._load_error: Optional[str] = None

    # ------------------------------------------------------------- loading

    @property
    def x509(self):
        """
        The parser, imported on first use.

        Deferred so that an installation without `cryptography` degrades to
        reporting the reason rather than failing to start.
        """
        if self._x509 is None and self._load_error is None:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
                from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
                self._x509 = x509
                self._ec, self._rsa, self._dsa = ec, rsa, dsa
                self._ed25519, self._ed448 = ed25519, ed448
            except Exception as e:  # pragma: no cover - exercised by absence
                self._load_error = str(e)
        return self._x509

    def is_available(self) -> bool:
        return self.x509 is not None

    def unavailable_reason(self) -> Optional[str]:
        if self.is_available():
            return None
        return (
            f"Certificate parsing is unavailable ({self._load_error}). "
            f"Certificates will be reported only as unread files."
        )

    # ------------------------------------------------------------ accepting

    def accepts(self, file_path: str) -> bool:
        ext = os.path.splitext(os.path.basename(file_path))[1].lower()
        return ext in self.FILE_EXTENSIONS

    def scan_directory(
        self,
        root_dir: str,
        limits: Optional[WalkLimits] = None,
        stats: Optional[WalkStats] = None,
        on_file: Optional[Callable[[str], None]] = None,
    ) -> List[RawEvidence]:
        evidences: List[RawEvidence] = []
        for file_path in walk_files(root_dir, limits=limits, accept=self.accepts, stats=stats):
            if on_file is not None:
                on_file(file_path)
            evidences.extend(self.scan_file(file_path))
        return evidences

    # ------------------------------------------------------------- parsing

    def _public_key_details(self, certificate) -> tuple:
        """(algorithm family, key size in bits, curve name)."""
        key = certificate.public_key()

        if isinstance(key, self._rsa.RSAPublicKey):
            return "RSA", key.key_size, None
        if isinstance(key, self._dsa.DSAPublicKey):
            return "DSA", key.key_size, None
        if isinstance(key, self._ec.EllipticCurvePublicKey):
            # key_size is the curve's field size, which is what the rest of the
            # pipeline expects in key_size_bits for an elliptic curve.
            return "ECDSA", key.curve.key_size, key.curve.name
        if isinstance(key, self._ed25519.Ed25519PublicKey):
            return "Ed25519", 255, "ed25519"
        if isinstance(key, self._ed448.Ed448PublicKey):
            return "Ed448", 448, "ed448"
        return "Unknown", None, None

    @staticmethod
    def _not_valid_after(certificate) -> Optional[datetime]:
        """
        The expiry, timezone-aware.

        `not_valid_after` is deprecated in favour of `not_valid_after_utc` in
        current releases and absent in older ones, so both are tried.
        """
        for attribute in ("not_valid_after_utc", "not_valid_after"):
            value = getattr(certificate, attribute, None)
            if value is not None:
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value
        return None

    @staticmethod
    def _not_valid_before(certificate) -> Optional[datetime]:
        for attribute in ("not_valid_before_utc", "not_valid_before"):
            value = getattr(certificate, attribute, None)
            if value is not None:
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value
        return None

    @staticmethod
    def _common_name(name) -> Optional[str]:
        try:
            from cryptography.x509.oid import NameOID
            values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return values[0].value if values else None
        except Exception:
            return None

    def _is_certificate_authority(self, certificate) -> bool:
        try:
            basic = certificate.extensions.get_extension_for_class(
                self._x509.BasicConstraints
            )
            return bool(basic.value.ca)
        except Exception:
            # No BasicConstraints extension means it is not asserting CA status.
            return False

    def _parse_certificates(self, raw: bytes) -> list:
        """Every certificate in the file. A PEM bundle may hold many."""
        certificates = []
        if PEM_CERTIFICATE_HEADER in raw:
            try:
                certificates = list(self._x509.load_pem_x509_certificates(raw))
            except Exception:
                # Older releases have no bundle loader, and a bundle with one
                # unreadable member should not lose the readable ones.
                for chunk in raw.split(PEM_CERTIFICATE_HEADER)[1:]:
                    block = PEM_CERTIFICATE_HEADER + chunk
                    try:
                        certificates.append(self._x509.load_pem_x509_certificate(block))
                    except Exception:
                        continue
        else:
            try:
                certificates.append(self._x509.load_der_x509_certificate(raw))
            except Exception:
                pass
        return certificates

    # -------------------------------------------------------------- scanning

    def scan_file(self, file_path: str) -> List[RawEvidence]:
        if not self.accepts(file_path):
            return []

        try:
            if os.path.getsize(file_path) > MAX_CERTIFICATE_BYTES:
                return []
            with open(file_path, "rb") as handle:
                raw = handle.read()
        except OSError:
            return []

        if not self.is_available():
            return [self._unreadable(file_path, self._load_error or "parser unavailable")]

        certificates = self._parse_certificates(raw)
        if not certificates:
            # A file named like a certificate that does not parse as one is
            # worth reporting: it is either not a certificate, or a certificate
            # nothing can read.
            return [self._unreadable(file_path, "could not be parsed as X.509")]

        now = datetime.now(timezone.utc)
        evidences: List[RawEvidence] = []

        for index, certificate in enumerate(certificates):
            family, key_size, curve = self._public_key_details(certificate)
            expires = self._not_valid_after(certificate)
            starts = self._not_valid_before(certificate)

            days_remaining = None
            if expires is not None:
                days_remaining = (expires - now).days

            subject = self._common_name(certificate.subject)
            issuer = self._common_name(certificate.issuer)
            self_signed = certificate.subject == certificate.issuer
            is_ca = self._is_certificate_authority(certificate)

            try:
                signature_algorithm = certificate.signature_algorithm_oid._name
            except Exception:
                signature_algorithm = None

            label = subject or os.path.basename(file_path)
            # The detected name carries the algorithm family so the artefact
            # extractor classifies this as RSA or ECDSA rather than falling into
            # the "primitive not identified" branch, which is where every
            # certificate used to land.
            detected = f"{family} X.509 certificate ({label})"

            evidences.append(RawEvidence(
                id=f"CERT-{os.path.basename(file_path)}-{index}",
                target_type=TargetType.SOURCE_CODE,
                file_path=file_path,
                line_number=None,
                snippet=None,
                matched_pattern=f"{family} certificate",
                raw_type="certificate",
                detected_name=detected,
                version_or_mode=signature_algorithm,
                key_length=key_size,
                curve_name=curve,
                metadata={
                    "subject": subject,
                    "issuer": issuer,
                    "self_signed": self_signed,
                    "is_certificate_authority": is_ca,
                    "signature_algorithm": signature_algorithm,
                    "not_valid_before": starts.isoformat() if starts else None,
                    "not_valid_after": expires.isoformat() if expires else None,
                    "days_until_expiry": days_remaining,
                    "is_expired": bool(days_remaining is not None and days_remaining < 0),
                    # The measured validity window, in years. For an
                    # authenticity asset this is X — the period the credential
                    # is trusted — so a real figure beats the conventional
                    # default the risk engine would otherwise apply.
                    "validity_years": (
                        round((expires - starts).days / 365.2425, 2)
                        if expires and starts else None
                    ),
                    "certificates_in_file": len(certificates),
                },
            ))

        return evidences

    @staticmethod
    def _unreadable(file_path: str, reason: str) -> RawEvidence:
        return RawEvidence(
            id=f"CERT-UNREAD-{os.path.basename(file_path)}",
            target_type=TargetType.SOURCE_CODE,
            file_path=file_path,
            matched_pattern="unreadable certificate",
            raw_type="certificate",
            detected_name=f"Unreadable certificate ({reason})",
            metadata={"unreadable": True, "reason": reason},
        )
