import os
import re
import uuid
from typing import List, Dict, Any, Optional, Callable
from backend.models import RawEvidence, TargetType
from backend.scanners.walker import walk_files, WalkLimits, WalkStats
from backend.scanners import yara_engine


class BinaryScanner:
    """
    Scanner for compiled binaries (ELF, PE/EXE, Mach-O, shared libraries, firmware/raw binaries).
    Detects embedded cryptographic constants, ASN.1 OIDs, strings, and library symbol tables.
    """

    BINARY_EXTENSIONS = {
        ".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".o", ".a", ".sys", ".drv"
    }

    # Cryptographic Byte Signatures / Constants
    BYTE_SIGNATURES: List[Dict[str, Any]] = [
        {
            "name": "AES S-Box Matrix Constant",
            "bytes": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
            "algorithm": "AES",
            "type": "algorithm",
            "mode": "S-Box Table",
            "key_length": 256
        },
        {
            "name": "ChaCha20 'expand 32-byte k' Sigma Constant",
            "bytes": b"expand 32-byte k",
            "algorithm": "ChaCha20",
            "type": "algorithm",
            "mode": "Stream",
            "key_length": 256
        },
        {
            "name": "ChaCha20 'expand 16-byte k' Tau Constant",
            "bytes": b"expand 16-byte k",
            "algorithm": "ChaCha20",
            "type": "algorithm",
            "mode": "Stream",
            "key_length": 128
        },
        {
            "name": "SHA-256 Fractional Cube Root Constants (K-table prefix)",
            "bytes": bytes([0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5]),
            "algorithm": "SHA-256",
            "type": "algorithm",
            "mode": "Hash"
        },
        {
            "name": "MD5 Initial State Vector",
            "bytes": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
            "algorithm": "MD5",
            "type": "algorithm",
            "mode": "Legacy Hash"
        },
    ]

    # ASN.1 OID Patterns (String and Raw Hex representations)
    ASN1_OIDS: List[Dict[str, Any]] = [
        {"oid": "1.2.840.113549.1.1.1", "hex": bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), "name": "rsaEncryption", "alg": "RSA", "type": "algorithm", "key_size": 2048},
        {"oid": "1.2.840.113549.1.1.11", "hex": bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), "name": "sha256WithRSAEncryption", "alg": "RSA", "type": "algorithm", "key_size": 2048},
        {"oid": "1.2.840.10045.2.1", "hex": bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), "name": "id-ecPublicKey", "alg": "ECC", "type": "algorithm", "curve": "P-256"},
        {"oid": "1.2.840.10045.3.1.7", "hex": bytes([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]), "name": "secp256r1 / prime256v1", "alg": "ECC", "type": "algorithm", "curve": "secp256r1"},
        {"oid": "1.3.101.112", "hex": bytes([0x2b, 0x65, 0x70]), "name": "Ed25519", "alg": "ECC", "type": "algorithm", "curve": "Ed25519"},
        {"oid": "2.16.840.1.101.3.4.1.42", "name": "aes256-GCM", "alg": "AES", "type": "algorithm", "mode": "GCM", "key_size": 256},
        {"oid": "2.16.840.1.101.3.4.1.2", "name": "aes128-CBC", "alg": "AES", "type": "algorithm", "mode": "CBC", "key_size": 128},
        {"oid": "2.16.840.1.101.3.4.4.2", "name": "ML-KEM-768 (FIPS 203)", "alg": "ML-KEM", "type": "algorithm", "mode": "KEM-768"},
        {"oid": "2.16.840.1.101.3.4.3.17", "name": "ML-DSA-65 (FIPS 204)", "alg": "ML-DSA", "type": "algorithm", "mode": "DSA-65"},
    ]

    # Cryptographic API Strings & Symbols (OpenSSL, Windows CNG, Libsodium)
    CRYPTO_SYMBOLS: List[Dict[str, Any]] = [
        {"pattern": r"EVP_aes_256_gcm", "alg": "AES", "type": "algorithm", "mode": "GCM", "key_size": 256},
        {"pattern": r"EVP_aes_128_cbc", "alg": "AES", "type": "algorithm", "mode": "CBC", "key_size": 128},
        {"pattern": r"RSA_new|RSA_generate_key|EVP_PKEY_CTX_set_rsa_keygen_bits", "alg": "RSA", "type": "algorithm", "key_size": 2048},
        {"pattern": r"EC_KEY_new_by_curve_name|EVP_PKEY_CTX_set_ec_paramgen_curve_nid", "alg": "ECC", "type": "algorithm", "curve": "P-256"},
        {"pattern": r"EVP_des_ede3_cbc|DES_set_key", "alg": "3DES", "type": "algorithm", "mode": "CBC", "key_size": 168},
        {"pattern": r"EVP_md5|MD5_Update", "alg": "MD5", "type": "algorithm", "mode": "Legacy Hash"},
        {"pattern": r"EVP_sha1|SHA1_Update", "alg": "SHA-1", "type": "algorithm", "mode": "Legacy Hash"},
        {"pattern": r"EVP_sha256|SHA256_Update", "alg": "SHA-256", "type": "algorithm", "mode": "Hash"},
        {"pattern": r"EVP_sha512|SHA512_Update", "alg": "SHA-512", "type": "algorithm", "mode": "Hash"},
        {"pattern": r"BCryptEncrypt|BCryptGenRandom|NCryptOpenStorageProvider", "alg": "Windows-CNG", "type": "library", "mode": "CNG API"},
        {"pattern": r"crypto_sign_ed25519|crypto_box_curve25519xsalsa20poly1305", "alg": "Libsodium", "type": "library", "mode": "NaCl/Sodium"},
        {"pattern": r"OQS_KEM_alg_kyber_768|OQS_KEM_ml_kem_768_new", "alg": "ML-KEM", "type": "algorithm", "mode": "PQC-KEM"},
    ]

    def scan_file(self, file_path: str) -> List[RawEvidence]:
        """
        Scan a binary for embedded cryptographic signatures.

        Matching is done by the YARA rule set in rules/crypto.yar, which finds
        every pattern in a single pass. The original hand-rolled byte and symbol
        tables below remain as a fallback for environments where the engine or
        the rules are unavailable, so binary detection degrades rather than
        disappearing.
        """
        if not os.path.exists(file_path):
            return []

        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception:
            return []

        matches = yara_engine.scan_bytes(content)
        if matches is not None:
            return self._evidence_from_matches(file_path, matches)

        return self._scan_with_builtin_tables(file_path, content)

    # A single signature can fire thousands of times in one file — an embedded
    # certificate bundle repeats the RSA OID once per certificate. Past a
    # handful, further offsets add nothing an inventory can act on, so the count
    # is recorded and the offsets are capped.
    MAX_OFFSETS_PER_RULE = 12

    def _evidence_from_matches(
        self, file_path: str, matches: List["yara_engine.SignatureMatch"]
    ) -> List[RawEvidence]:
        """Turn rule matches into evidence, one per distinct signature and offset."""
        evidences: List[RawEvidence] = []
        seen = set()

        total_by_rule: Dict[str, int] = {}
        for match in matches:
            total_by_rule[match.rule] = total_by_rule.get(match.rule, 0) + 1

        emitted_by_rule: Dict[str, int] = {}

        for match in matches:
            emitted = emitted_by_rule.get(match.rule, 0)
            if emitted >= self.MAX_OFFSETS_PER_RULE:
                continue

            key = (match.algorithm, match.offset)
            if key in seen:
                continue
            seen.add(key)
            emitted_by_rule[match.rule] = emitted + 1

            evidences.append(RawEvidence(
                id=str(uuid.uuid4()),
                target_type=TargetType.BINARY,
                file_path=file_path.replace("\\", "/"),
                line_number=None,
                # Binaries have offsets rather than lines; the column carries
                # the byte offset so the UI can point at the exact location.
                column_number=match.offset,
                snippet=(
                    f"0x{match.offset:08X}  {match.note or match.rule}"
                    + (
                        f"  (+{total_by_rule[match.rule] - self.MAX_OFFSETS_PER_RULE}"
                        f" further occurrences)"
                        if total_by_rule[match.rule] > self.MAX_OFFSETS_PER_RULE
                        and emitted_by_rule[match.rule] == self.MAX_OFFSETS_PER_RULE
                        else ""
                    )
                ),
                matched_pattern=match.rule,
                raw_type=match.asset_type,
                detected_name=match.algorithm,
                version_or_mode=match.mode,
                key_length=match.key_size,
                curve_name=match.curve,
                metadata={
                    "detector": "yara",
                    "rule": match.rule,
                    "pattern": match.pattern,
                    "binary_offset": f"0x{match.offset:08X}",
                    "match_length": match.length,
                    "total_matches_for_rule": total_by_rule[match.rule],
                    # A signature proves the implementation is present, not that
                    # it is reached at runtime.
                    "parameters_resolved": match.key_size is not None,
                },
            ))

        return evidences

    def _scan_with_builtin_tables(self, file_path: str, content: bytes) -> List[RawEvidence]:
        """Fallback matcher used when the YARA rule set cannot be loaded."""
        evidences: List[RawEvidence] = []

        # 1. Byte Signatures Matching
        for sig in self.BYTE_SIGNATURES:
            idx = 0
            while True:
                idx = content.find(sig["bytes"], idx)
                if idx == -1:
                    break
                evidence = RawEvidence(
                    id=str(uuid.uuid4()),
                    target_type=TargetType.BINARY,
                    file_path=file_path.replace("\\", "/"),
                    line_number=None,
                    column_number=idx,
                    snippet=f"Binary Offset: 0x{idx:08X} [{sig['name']}]",
                    matched_pattern=sig["name"],
                    raw_type=sig["type"],
                    detected_name=sig["algorithm"],
                    version_or_mode=sig.get("mode"),
                    key_length=sig.get("key_length"),
                    metadata={
                        "binary_offset": f"0x{idx:08X}",
                        "signature_name": sig["name"],
                        "match_category": "raw_byte_constant"
                    }
                )
                evidences.append(evidence)
                idx += len(sig["bytes"])

        # 2. ASN.1 OIDs (Byte & ASCII)
        for o in self.ASN1_OIDS:
            # Check byte representation
            if "hex" in o:
                idx = 0
                while True:
                    idx = content.find(o["hex"], idx)
                    if idx == -1:
                        break
                    evidence = RawEvidence(
                        id=str(uuid.uuid4()),
                        target_type=TargetType.BINARY,
                        file_path=file_path.replace("\\", "/"),
                        column_number=idx,
                        snippet=f"ASN.1 OID Byte Match: {o['oid']} ({o['name']}) at 0x{idx:08X}",
                        matched_pattern=f"OID:{o['oid']}",
                        raw_type=o["type"],
                        detected_name=o["alg"],
                        version_or_mode=o.get("mode"),
                        key_length=o.get("key_size"),
                        curve_name=o.get("curve"),
                        metadata={
                            "oid": o["oid"],
                            "oid_name": o["name"],
                            "binary_offset": f"0x{idx:08X}"
                        }
                    )
                    evidences.append(evidence)
                    idx += len(o["hex"])

            # Check ASCII string representation
            oid_bytes = o["oid"].encode("ascii")
            idx = 0
            while True:
                idx = content.find(oid_bytes, idx)
                if idx == -1:
                    break
                evidence = RawEvidence(
                    id=str(uuid.uuid4()),
                    target_type=TargetType.BINARY,
                    file_path=file_path.replace("\\", "/"),
                    column_number=idx,
                    snippet=f"ASCII OID String: {o['oid']} ({o['name']}) at 0x{idx:08X}",
                    matched_pattern=f"ASCII_OID:{o['oid']}",
                    raw_type=o["type"],
                    detected_name=o["alg"],
                    version_or_mode=o.get("mode"),
                    key_length=o.get("key_size"),
                    curve_name=o.get("curve"),
                    metadata={"oid": o["oid"], "binary_offset": f"0x{idx:08X}"}
                )
                evidences.append(evidence)
                idx += len(oid_bytes)

        # 3. String & Symbol Scan
        try:
            # Extract printable ASCII / UTF-8 strings
            text_strings = re.findall(rb"[\x20-\x7E]{4,}", content)
            combined_strings = "\n".join([s.decode("ascii", errors="ignore") for s in text_strings])

            for sym in self.CRYPTO_SYMBOLS:
                matches = re.finditer(sym["pattern"], combined_strings)
                for m in matches:
                    evidence = RawEvidence(
                        id=str(uuid.uuid4()),
                        target_type=TargetType.BINARY,
                        file_path=file_path.replace("\\", "/"),
                        snippet=f"Binary Symbol/String: {m.group(0)}",
                        matched_pattern=m.group(0),
                        raw_type=sym["type"],
                        detected_name=sym["alg"],
                        version_or_mode=sym.get("mode"),
                        key_length=sym.get("key_size"),
                        curve_name=sym.get("curve"),
                        metadata={"symbol_match": m.group(0)}
                    )
                    evidences.append(evidence)
        except Exception:
            pass

        return evidences

    def accepts(self, file_path: str) -> bool:
        """Whether this scanner handles the given path (used by the shared walker)."""
        return os.path.splitext(file_path)[1].lower() in self.BINARY_EXTENSIONS

    def scan_directory(
        self,
        root_dir: str,
        limits: Optional[WalkLimits] = None,
        stats: Optional[WalkStats] = None,
        on_file: Optional[Callable[[str], None]] = None,
    ) -> List[RawEvidence]:
        """Scan all binary files within a directory."""
        evidences: List[RawEvidence] = []
        for file_path in walk_files(root_dir, limits=limits, accept=self.accepts, stats=stats):
            if on_file is not None:
                on_file(file_path)
            evidences.extend(self.scan_file(file_path))
        return evidences
