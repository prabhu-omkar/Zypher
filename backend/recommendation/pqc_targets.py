"""
Which post-quantum algorithm replaces which classical one, and on what basis.

The engine used to pick a parameter set from a latency enum and decide between a
KEM and a signature by looking for the substring "SIGN" in the algorithm name.
Both are wrong:

  * Parameter sets are chosen by *security level*. What an asset is replacing
    determines the NIST category it has to reach; how fast it needs to be is a
    reason to prefer one alternative over another within that category, not a
    reason to drop below it.

  * Whether an asset needs a KEM or a signature is a property of what it is
    used for, which the risk layer already determines (CryptoUsage). Sniffing
    the name mislabels ECDH as a signature and any class named "...Signer" as a
    key exchange.

Everything named below is shipping in a release that exists today. liboqs is
deliberately absent: its own documentation states the algorithms are
experimental and must not be used in production, so it is not a migration
target.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from backend.models import (
    AlgorithmClass, CryptographicArtefact, CryptoUsage, DataSensitivityProfile,
)


class NistCategory(IntEnum):
    """NIST PQC security categories (FIPS 203/204/205, §attack-cost model)."""
    ONE = 1     # at least as hard as an AES-128 key search
    TWO = 2     # at least as hard as a SHA-256 collision search
    THREE = 3   # at least as hard as an AES-192 key search
    FIVE = 5    # at least as hard as an AES-256 key search


# Classical security strength in bits, from NIST SP 800-57 Part 1 Rev. 5,
# Table 2. Note that RSA-2048 provides 112 bits, not 128 — which is exactly the
# figure NIST IR 8547 deprecates in 2030.
_MODULUS_STRENGTH: List[Tuple[int, int]] = [
    (15360, 256),
    (7680, 192),
    (3072, 128),
    (2048, 112),
    (1024, 80),
]


def classical_strength_bits(art: CryptographicArtefact) -> Optional[int]:
    """
    How many bits of classical security this asset actually provides.

    Returns None when the primitive or its size is not known, so that an
    unmeasured asset is never given a target derived from a guessed strength.
    """
    if art.algorithm_class == AlgorithmClass.SYMMETRIC:
        return art.key_size_bits

    if not art.key_size_bits:
        return None

    if art.algorithm_class == AlgorithmClass.ASYMMETRIC_DISCRETE_LOG and art.curve:
        # key_size_bits holds the curve's field size; elliptic-curve discrete log
        # costs roughly half of it.
        return art.key_size_bits // 2

    if art.algorithm_class in (
        AlgorithmClass.ASYMMETRIC_FACTORING,
        AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
    ):
        for modulus, strength in _MODULUS_STRENGTH:
            if art.key_size_bits >= modulus:
                return strength
        return 80

    return None


# The category a replacement has to reach, given what it is replacing.
#
# A floor of Category 3 applies even when strict equivalence would allow
# Category 1. Two reasons, both load-bearing rather than cautious padding:
# every major deployment has settled on the Category 3 parameter set as its
# default (OpenSSL 3.5 ships X25519MLKEM768 as a default keyshare; Go's
# crypto/mlkem documentation states most applications should use ML-KEM-768),
# and lattice cryptanalysis has had far less time in the open than factoring
# has, so the margin buys room that costs almost nothing here.
TARGET_CATEGORY_FLOOR = NistCategory.THREE


def target_category(
    art: CryptographicArtefact,
    profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
) -> Tuple[NistCategory, str]:
    """(category to migrate to, why that category)."""
    if profile == DataSensitivityProfile.NATIONAL_SECURITY:
        return NistCategory.FIVE, (
            "CNSA 2.0 requires the Category 5 parameter sets for national "
            "security systems, whatever the algorithm being replaced."
        )

    bits = classical_strength_bits(art)
    if bits is None:
        return TARGET_CATEGORY_FLOOR, (
            "The current key size is not readable from the evidence, so the "
            "target defaults to Category 3 — the level every major "
            "implementation ships as its default."
        )

    if bits >= 256:
        return NistCategory.FIVE, (
            f"Replacing {bits}-bit classical security, which is Category 5."
        )
    if bits >= 192:
        return NistCategory.THREE, (
            f"Replacing {bits}-bit classical security, which is Category 3."
        )
    return TARGET_CATEGORY_FLOOR, (
        f"Replacing {bits}-bit classical security. Strict equivalence would "
        f"allow Category 1, but the Category 3 set is what OpenSSL 3.5, Go 1.24 "
        f"and the IETF hybrid all use by default, and the size cost is small."
    )


# FIPS 203 — key encapsulation.
KEM_BY_CATEGORY: Dict[NistCategory, str] = {
    NistCategory.ONE: "ML-KEM-512",
    NistCategory.THREE: "ML-KEM-768",
    NistCategory.FIVE: "ML-KEM-1024",
}

# FIPS 204 — lattice signatures. ML-DSA-44 is Category 2, not 1.
SIGNATURE_BY_CATEGORY: Dict[NistCategory, str] = {
    NistCategory.ONE: "ML-DSA-44",
    NistCategory.TWO: "ML-DSA-44",
    NistCategory.THREE: "ML-DSA-65",
    NistCategory.FIVE: "ML-DSA-87",
}

# FIPS 205 — stateless hash-based signatures. Far larger and slower than
# ML-DSA, and the right answer only where the signature outlives confidence in
# lattice assumptions: firmware and boot-chain signing, long-lived roots.
HASH_SIGNATURE_BY_CATEGORY: Dict[NistCategory, str] = {
    NistCategory.ONE: "SLH-DSA-SHA2-128s",
    NistCategory.TWO: "SLH-DSA-SHA2-128s",
    NistCategory.THREE: "SLH-DSA-SHA2-192s",
    NistCategory.FIVE: "SLH-DSA-SHA2-256s",
}

# The classical half of a hybrid, matched to the category.
HYBRID_PARTNER: Dict[NistCategory, str] = {
    NistCategory.ONE: "X25519",
    NistCategory.TWO: "X25519",
    NistCategory.THREE: "X25519",
    NistCategory.FIVE: "P-384",
}

# The named TLS hybrid groups that are actually negotiable today.
TLS_HYBRID_GROUP: Dict[NistCategory, str] = {
    NistCategory.ONE: "X25519MLKEM768",
    NistCategory.TWO: "X25519MLKEM768",
    NistCategory.THREE: "X25519MLKEM768",
    NistCategory.FIVE: "SecP384r1MLKEM1024",
}

# Wire-size cost of the post-quantum half, for the latency/bandwidth note.
# Public key and ciphertext sizes are from FIPS 203; signature sizes from
# FIPS 204.
KEM_SIZES: Dict[str, Tuple[int, int]] = {
    "ML-KEM-512": (800, 768),
    "ML-KEM-768": (1184, 1088),
    "ML-KEM-1024": (1568, 1568),
}
SIGNATURE_SIZES: Dict[str, Tuple[int, int]] = {
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
}


# --------------------------------------------------------- implementations

class Implementation:
    """A shipping implementation an engineer can actually adopt."""

    def __init__(self, name: str, provides: str, note: str):
        self.name, self.provides, self.note = name, provides, note

    def describe(self) -> str:
        return f"{self.name} — {self.provides}. {self.note}"


# Only releases that exist and ship the algorithm are listed. Each entry states
# what it provides and any limit on it, because "the language supports ML-KEM"
# and "TLS in that language negotiates ML-KEM" are different claims.
IMPLEMENTATIONS: Dict[str, Implementation] = {
    "openssl": Implementation(
        "OpenSSL 3.5+",
        "ML-KEM, ML-DSA and SLH-DSA natively",
        "Released April 2025 and supported until April 2030; ships "
        "X25519MLKEM768 as a default TLS keyshare, so hybrid key exchange is "
        "on without application changes.",
    ),
    "go": Implementation(
        "Go 1.24+",
        "crypto/mlkem (ML-KEM-768 and ML-KEM-1024)",
        "The standard library recommends ML-KEM-768 for most applications. "
        "Signatures are not yet in the standard library.",
    ),
    "java": Implementation(
        "Java 24+",
        "ML-KEM via JEP 496 and ML-DSA via JEP 497",
        "The JDK exposes the algorithms through KeyPairGenerator, KEM and "
        "Signature, but they are not yet wired into javax.net.ssl, so TLS "
        "still needs a provider or a proxy in front.",
    ),
    "bouncycastle": Implementation(
        "Bouncy Castle",
        "ML-KEM, ML-DSA and SLH-DSA on the JVM and .NET",
        "The route where the platform runtime is older than Java 24 or the "
        "application cannot move to OpenSSL 3.5.",
    ),
    "awslc": Implementation(
        "AWS-LC / BoringSSL",
        "ML-KEM and hybrid TLS key exchange",
        "Where an OpenSSL-compatible library is already vendored.",
    ),
}

# Mapped from the file extension of where the asset was found, so the advice
# names a library the reader can actually install.
_EXTENSION_IMPLEMENTATIONS: Dict[str, List[str]] = {
    ".go": ["go", "openssl"],
    ".java": ["java", "bouncycastle"],
    ".kt": ["java", "bouncycastle"],
    ".scala": ["java", "bouncycastle"],
    ".cs": ["bouncycastle", "openssl"],
    ".c": ["openssl", "awslc"],
    ".h": ["openssl", "awslc"],
    ".cpp": ["openssl", "awslc"],
    ".cc": ["openssl", "awslc"],
    ".rs": ["awslc", "openssl"],
    ".py": ["openssl"],
    ".rb": ["openssl"],
    ".js": ["openssl"],
    ".ts": ["openssl"],
    ".php": ["openssl"],
}

NOT_A_TARGET = (
    "liboqs and its language bindings are for experimentation only — the "
    "project's own documentation states the algorithms are experimental and "
    "must not be used in production."
)


def implementations_for(art: CryptographicArtefact) -> List[str]:
    """Named, shipping implementations appropriate to where this asset lives."""
    location = (art.location or "").lower()
    for ext, keys in _EXTENSION_IMPLEMENTATIONS.items():
        if location.endswith(ext):
            return [IMPLEMENTATIONS[k].describe() for k in keys]
    # Anything else — a config file, a binary, a manifest — is served by
    # whatever the platform links against.
    return [IMPLEMENTATIONS["openssl"].describe()]


def needs_signature(usage: CryptoUsage) -> bool:
    """
    Whether this asset needs a signature scheme rather than a KEM.

    Read from what the asset is used for, which the risk layer already
    established, rather than from substrings in its name.
    """
    return usage in (CryptoUsage.AUTHENTICITY, CryptoUsage.INTEGRITY)


def size_note(algorithm: str) -> str:
    """One line on what adopting this costs on the wire."""
    if algorithm in KEM_SIZES:
        pk, ct = KEM_SIZES[algorithm]
        return (
            f"{algorithm} public key {pk} bytes, ciphertext {ct} bytes — "
            f"a hybrid handshake carries about {(pk + ct) / 1024:.1f} KB more "
            f"than a classical one."
        )
    if algorithm in SIGNATURE_SIZES:
        pk, sig = SIGNATURE_SIZES[algorithm]
        return (
            f"{algorithm} public key {pk} bytes, signature {sig} bytes — "
            f"certificates and signed payloads grow accordingly."
        )
    return "Size impact depends on the parameter set selected."
