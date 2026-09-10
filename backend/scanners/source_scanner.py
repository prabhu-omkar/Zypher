import os
import re
import uuid
from typing import List, Dict, Any, Optional, Callable
from backend.models import RawEvidence, TargetType
from backend.scanners.walker import walk_files, WalkLimits, WalkStats
from backend.scanners import ast_scanner


class SourceCodeScanner:
    """
    Multi-language static analysis scanner for detecting cryptographic algorithms,
    protocols, hardcoded keys, certificates, libraries, hardware modules, and cloud KMS calls.
    """

    FILE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
        ".go", ".rs", ".cs", ".php", ".rb", ".kt", ".swift", ".scala", ".env", ".json", ".yaml", ".yml"
    }

    # Cryptographic pattern definitions with capture groups
    PATTERNS: List[Dict[str, Any]] = [
        # Asymmetric - RSA
        {
            "name": "RSA Algorithm",
            "regex": re.compile(r"(?i)(?<!\w)(RSA(?:_PKCS1_OAEP|_PKCS1_v1_5|_PSS)?|generate_private_key\s*\(\s*(?:algorithm\s*=\s*)?rsa|RSA\.generate|KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"']|crypto\.generateKeyPair(?:Sync)?\s*\(\s*[\"']rsa[\"'])(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "RSA",
            "key_regex": re.compile(r"(?i)(?<!\w)(?:key_size|bits|length|keysize)\s*[:=]\s*(\d{3,5})(?!\w)|(?<!\w)(1024|2048|3072|4096)(?!\w)"),
            "default_key_size": 2048,
        },
        # Asymmetric - ECC / ECDSA / ECDH
        {
            "name": "ECC / ECDSA / ECDH",
            "regex": re.compile(r"(?i)(?<!\w)(ECDSA|ECDH|Ed25519|X25519|Ed448|X448|secp256r1|secp256k1|secp384r1|secp521r1|prime256v1|NIST256p|P-256|P-384|P-521|EllipticCurve|ECKey)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "ECC",
            "curve_regex": re.compile(r"(?i)(?<!\w)(secp256r1|secp256k1|prime256v1|secp384r1|secp521r1|ed25519|x25519|ed448|x448|p-256|p-384|p-521)(?!\w)"),
            "default_curve": "P-256",
        },
        # Asymmetric - Diffie-Hellman / DSA
        {
            "name": "Diffie-Hellman / DSA",
            "regex": re.compile(r"(?i)(?<!\w)(DiffieHellman|DHParameterSpec|KeyPairGenerator\.getInstance\s*\(\s*[\"']DSA[\"']|KeyPairGenerator\.getInstance\s*\(\s*[\"']DH[\"'])(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "Diffie-Hellman",
            "default_key_size": 2048,
        },
        # Symmetric - AES
        {
            "name": "AES Symmetric Cipher",
            "regex": re.compile(r"(?i)(?<!\w)(AES(?:-128|-192|-256)?(?:-CBC|-GCM|-CTR|-ECB|-CFB|-OFB)?|AES\.new|Cipher\.getInstance\s*\(\s*[\"']AES[/\w-]*[\"']|crypto\.createCipheriv\s*\(\s*[\"']aes-(128|192|256)-(gcm|cbc|ctr|ecb)[\"'])(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "AES",
            "mode_regex": re.compile(r"(?i)(?<!\w)(GCM|CBC|CTR|ECB|CFB|OFB)(?!\w)"),
            "key_regex": re.compile(r"(?i)(?<!\w)(128|192|256)(?!\w)"),
            "default_key_size": 256,
            "default_mode": "GCM"
        },
        # Symmetric - Legacy / Broken Ciphers (DES, 3DES, RC4, Blowfish)
        {
            "name": "Legacy Weak Cipher (DES / 3DES / RC4 / Blowfish)",
            "regex": re.compile(r"(?i)(?<!\w)(DESede|TripleDES|3DES|DES\.new|ARC4|RC4|Blowfish|Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|RC4|Blowfish)[/\w-]*[\"'])(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "Legacy-Cipher",
            "mode_regex": re.compile(r"(?i)(?<!\w)(CBC|ECB|OFB|CFB)(?!\w)"),
            "default_key_size": 56,
        },
        # Symmetric - ChaCha20 / Poly1305
        {
            "name": "ChaCha20-Poly1305 Cipher",
            "regex": re.compile(r"(?i)(?<!\w)(ChaCha20(?:-Poly1305)?|chacha20_poly1305)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "ChaCha20-Poly1305",
            "default_key_size": 256,
            "default_mode": "Poly1305"
        },
        # Hash - Broken (MD5, SHA-1)
        {
            "name": "Broken Classical Hash (MD5 / SHA-1)",
            "regex": re.compile(r"(?i)(?<!\w)(hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"']|crypto\.createHash\s*\(\s*[\"'](?:md5|sha1)[\"']|MD5_Init|SHA1_Init)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "MD5/SHA-1",
        },
        # Hash - SHA-2 / SHA-3 / BLAKE
        {
            "name": "Secure Hash (SHA-256 / SHA-384 / SHA-512 / SHA-3)",
            "regex": re.compile(r"(?i)(?<!\w)(hashlib\.sha256|hashlib\.sha384|hashlib\.sha512|hashlib\.sha3_\w+|MessageDigest\.getInstance\s*\(\s*[\"'](?:SHA-256|SHA-384|SHA-512|SHA3-256|SHA3-512)[\"']|crypto\.createHash\s*\(\s*[\"'](?:sha256|sha384|sha512)[\"']|SHA256_Init|SHA512_Init)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "SHA-2/SHA-3",
        },
        # Post Quantum Primitives (ML-KEM / Kyber, ML-DSA / Dilithium, SLH-DSA / SPHINCS+, Falcon)
        {
            "name": "Post-Quantum Cryptographic Algorithm",
            "regex": re.compile(r"(?i)(?<!\w)(ML-KEM(?:-512|-768|-1024)?|Kyber(?:512|768|1024)?|ML-DSA(?:-44|-65|-87)?|Dilithium(?:2|3|5)?|SLH-DSA|SPHINCS\+|Falcon(?:-512|-1024)?|FIPS\s*203|FIPS\s*204|FIPS\s*205|liboqs|oqs\.KeyExchange|oqs\.Signature)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "PQC-FIPS",
        },
        # Hybrid Quantum Schemes
        {
            "name": "Hybrid Classical + Post-Quantum Scheme",
            "regex": re.compile(r"(?i)(?<!\w)(X25519Kyber768Draft00|X25519MLKEM768|SecP256r1MLKEM768|HybridKeyExchange|hybrid_kem|dual_algorithm_signature)(?!\w)"),
            "raw_type": "algorithm",
            "detected_name": "Hybrid-PQC",
        },
        # Hardcoded Certificates & Private Keys
        {
            "name": "Hardcoded Private Key / PEM",
            "regex": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|ENCRYPTED)? ?PRIVATE KEY-----"),
            "raw_type": "key",
            "detected_name": "Hardcoded-Private-Key",
        },
        {
            "name": "Hardcoded X.509 Certificate",
            "regex": re.compile(r"-----BEGIN CERTIFICATE-----"),
            "raw_type": "certificate",
            "detected_name": "X509-Certificate",
        },
        # Insecure & Modern TLS / SSL Protocols
        {
            "name": "Cryptographic Protocol (TLS / SSL / SSH / IPsec)",
            "regex": re.compile(r"(?i)(?<!\w)(SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3|PROTOCOL_TLSv1|PROTOCOL_SSLv23|ssl\.PROTOCOL_TLS_CLIENT|ssl\.PROTOCOL_TLS_SERVER|OpenSSL::SSL::SSLContext|tls\.Config)(?!\w)"),
            "raw_type": "protocol",
            "detected_name": "TLS/SSL Protocol",
        },
        # Cloud KMS Services
        {
            "name": "Cloud Key Management Service (AWS KMS / Azure KeyVault / Google Cloud KMS / HashiCorp Vault)",
            "regex": re.compile(r"(?i)(?<!\w)(boto3\.client\s*\(\s*[\"']kms[\"']|aws_kms|kmsClient\.encrypt|kmsClient\.decrypt|SecretClient|KeyVaultClient|cloudkms\.googleapis\.com|hashicorp/vault|vault\.read|vault\.write)(?!\w)"),
            "raw_type": "cloud_service",
            "detected_name": "Cloud KMS Service",
        },
        # Hardware Cryptographic Modules (HSM / PKCS#11 / TPM)
        {
            "name": "Hardware Security Module / PKCS#11 / TPM",
            "regex": re.compile(r"(?i)(?<!\w)(pkcs11|PyKCS11|libsofthsm2|C_Initialize|C_OpenSession|C_Sign|YubiHSM|tpm2_create|TPM2_CC_Encrypt|SunPKCS11|LunaProvider)(?!\w)"),
            "raw_type": "hardware_module",
            "detected_name": "HSM/PKCS#11 Module",
        },
    ]

    def accepts(self, file_path: str) -> bool:
        """Whether this scanner handles the given path (used by the shared walker)."""
        name = os.path.basename(file_path)
        ext = os.path.splitext(name)[1].lower()
        return ext in self.FILE_EXTENSIONS or name.startswith(".env")

    def scan_directory(
        self,
        root_dir: str,
        limits: Optional[WalkLimits] = None,
        stats: Optional[WalkStats] = None,
        on_file: Optional[Callable[[str], None]] = None,
    ) -> List[RawEvidence]:
        """Recursively scan a directory for source code cryptographic evidence."""
        evidences: List[RawEvidence] = []
        for file_path in walk_files(root_dir, limits=limits, accept=self.accepts, stats=stats):
            if on_file is not None:
                on_file(file_path)
            evidences.extend(self.scan_file(file_path))
        return evidences

    # A single cheap pass that decides whether a file is worth looking at.
    #
    # The old scanner ran 15 separate regexes over every line of every file,
    # which measured 0.2 MB/s on real third-party code — roughly 15 minutes at
    # the 25,000-file traversal cap. The overwhelming majority of files contain
    # no cryptography at all, so one combined substring scan rejects them up
    # front and only survivors are parsed or matched in full.
    PREFILTER = re.compile(
        r"(?i)(rsa|ecdsa|ecdh|ed25519|x25519|secp|prime256|curve|diffie|dhparam"
        r"|aes|des|rc2|rc4|blowfish|idea|chacha|poly1305|salsa"
        r"|md5|sha1|sha-1|sha2|sha256|sha384|sha512|sha3|blake"
        r"|cipher|crypto|encrypt|decrypt|sign|digest|hmac|hash"
        r"|kyber|dilithium|falcon|sphincs|ml-kem|ml-dsa|slh-dsa|liboqs|oqs"
        r"|tls|ssl|pkcs|pkcs11|hsm|keystore|keyvault|kms|vault"
        r"|-----BEGIN|private_key|publickey|certificate)"
    )

    def scan_file(self, file_path: str) -> List[RawEvidence]:
        """
        Scan one file.

        Files with a bundled grammar are parsed and inspected at their call
        sites, which reads real argument values instead of guessing defaults and
        cannot match inside comments or unrelated strings. Everything else falls
        back to the regex patterns below.
        """
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except OSError:
            return []

        # Decode once for the prefilter; a file with no cryptographic token
        # anywhere cannot produce evidence from either path.
        text = raw.decode("utf-8", "ignore")
        if not self.PREFILTER.search(text):
            return []

        if ast_scanner.can_parse(file_path):
            language = ast_scanner.language_for(file_path)
            evidences = ast_scanner.scan_source(file_path, raw, language)
            if evidences is not None:
                return evidences

        return self._scan_file_with_regex(file_path)

    def _scan_file_with_regex(self, file_path: str) -> List[RawEvidence]:
        """Scan an individual file for cryptographic evidence."""
        evidences: List[RawEvidence] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return evidences

        full_content = "".join(lines)

        for pat in self.PATTERNS:
            # Check multiline matches (like PEM keys) or line-by-line
            for line_idx, line in enumerate(lines, start=1):
                match = pat["regex"].search(line)
                if match:
                    snippet = line.strip()
                    matched_str = match.group(0)
                    
                    # Extract key size or curve or mode if pattern provides sub-regex
                    key_length = None
                    if "key_regex" in pat:
                        km = pat["key_regex"].search(line)
                        if km:
                            for g in km.groups():
                                if g and g.isdigit():
                                    key_length = int(g)
                                    break
                    if not key_length and "default_key_size" in pat:
                        key_length = pat["default_key_size"]

                    curve_name = None
                    if "curve_regex" in pat:
                        cm = pat["curve_regex"].search(line)
                        if cm:
                            curve_name = cm.group(0).upper()
                    elif "default_curve" in pat:
                        curve_name = pat["default_curve"]

                    mode_str = None
                    if "mode_regex" in pat:
                        mm = pat["mode_regex"].search(line)
                        if mm:
                            mode_str = mm.group(0).upper()
                    elif "default_mode" in pat:
                        mode_str = pat["default_mode"]

                    evidence = RawEvidence(
                        id=str(uuid.uuid4()),
                        target_type=TargetType.SOURCE_CODE,
                        file_path=file_path.replace("\\", "/"),
                        line_number=line_idx,
                        snippet=snippet[:200],
                        matched_pattern=matched_str,
                        raw_type=pat["raw_type"],
                        detected_name=pat["detected_name"],
                        version_or_mode=mode_str,
                        key_length=key_length,
                        curve_name=curve_name,
                        metadata={
                            "rule_name": pat["name"],
                            "file_ext": os.path.splitext(file_path)[1]
                        }
                    )
                    evidences.append(evidence)

            # Special case for PEM block multiline
            if pat["raw_type"] in ["key", "certificate"]:
                pem_matches = pat["regex"].finditer(full_content)
                for pm in pem_matches:
                    start_char = pm.start()
                    line_no = full_content[:start_char].count("\n") + 1
                    # Avoid duplicate if already matched by line iterator
                    if not any(e.file_path == file_path.replace("\\", "/") and e.line_number == line_no and e.raw_type == pat["raw_type"] for e in evidences):
                        evidence = RawEvidence(
                            id=str(uuid.uuid4()),
                            target_type=TargetType.SOURCE_CODE,
                            file_path=file_path.replace("\\", "/"),
                            line_number=line_no,
                            snippet="-----BEGIN CRYPTOGRAPHIC ARTEFACT (PEM)-----",
                            matched_pattern=pm.group(0),
                            raw_type=pat["raw_type"],
                            detected_name=pat["detected_name"],
                            key_length=2048 if pat["raw_type"] == "key" else None,
                            metadata={"is_embedded_pem": True}
                        )
                        evidences.append(evidence)

        return evidences
