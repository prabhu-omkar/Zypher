import os
import re
import json
import uuid
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Callable
from backend.models import RawEvidence, TargetType
from backend.scanners.walker import walk_files, WalkLimits, WalkStats


class DependencyScanner:
    """
    Scanner for third-party and vendor library dependencies across package ecosystems.
    Extracts cryptographic library names, declared versions, and algorithm associations.
    """

    KNOWN_CRYPTO_LIBRARIES: Dict[str, Dict[str, Any]] = {
        # Python
        "cryptography": {"alg": "Cryptography-Suite", "type": "library", "ecosystem": "pip", "pqc": False},
        "pycryptodome": {"alg": "PyCryptodome-Suite", "type": "library", "ecosystem": "pip", "pqc": False},
        "pycrypto": {"alg": "PyCrypto (Deprecated)", "type": "library", "ecosystem": "pip", "pqc": False, "legacy": True},
        "pynacl": {"alg": "PyNaCl / Ed25519", "type": "library", "ecosystem": "pip", "pqc": False},
        "ecdsa": {"alg": "ECDSA-Python", "type": "library", "ecosystem": "pip", "pqc": False},
        "rsa": {"alg": "RSA-Python", "type": "library", "ecosystem": "pip", "pqc": False},
        "liboqs-python": {"alg": "Open Quantum Safe (liboqs)", "type": "library", "ecosystem": "pip", "pqc": True, "experimental": True},
        
        # JavaScript / Node.js
        "crypto-js": {"alg": "Crypto-JS Suite", "type": "library", "ecosystem": "npm", "pqc": False},
        "node-forge": {"alg": "Forge RSA/TLS", "type": "library", "ecosystem": "npm", "pqc": False},
        "elliptic": {"alg": "Elliptic Curves (secp256k1/ed25519)", "type": "library", "ecosystem": "npm", "pqc": False},
        "tweetnacl": {"alg": "TweetNaCl", "type": "library", "ecosystem": "npm", "pqc": False},
        "bcrypt": {"alg": "bcrypt KDF", "type": "library", "ecosystem": "npm", "pqc": False},
        "jose": {"alg": "JOSE / JWT Crypto", "type": "library", "ecosystem": "npm", "pqc": False},
        "openpgp": {"alg": "OpenPGP.js", "type": "library", "ecosystem": "npm", "pqc": False},
        "oqs": {"alg": "LibOQS Quantum Safe JS", "type": "library", "ecosystem": "npm", "pqc": True, "experimental": True},
        
        # Java (Maven / Gradle)
        "bcprov-jdk18on": {"alg": "Bouncy Castle Provider", "type": "library", "ecosystem": "maven", "pqc": True},
        "bcpkix-jdk18on": {"alg": "Bouncy Castle PKIX/CMS", "type": "library", "ecosystem": "maven", "pqc": True},
        "bcprov-jdk15on": {"alg": "Bouncy Castle (Legacy JDK15)", "type": "library", "ecosystem": "maven", "pqc": False},
        "bouncycastle": {"alg": "Bouncy Castle", "type": "library", "ecosystem": "maven", "pqc": False},
        "xmlsec": {"alg": "Apache XML Security", "type": "library", "ecosystem": "maven", "pqc": False},

        # Go
        "golang.org/x/crypto": {"alg": "Go X/Crypto Standard", "type": "library", "ecosystem": "go", "pqc": False},
        "github.com/cloudflare/circl": {"alg": "Cloudflare CIRCL (PQC/KEM)", "type": "library", "ecosystem": "go", "pqc": True},
        "github.com/open-quantum-safe/liboqs-go": {"alg": "LibOQS Go Wrapper", "type": "library", "ecosystem": "go", "pqc": True, "experimental": True},

        # Rust
        "ring": {"alg": "Ring Crypto", "type": "library", "ecosystem": "cargo", "pqc": False},
        "ed25519-dalek": {"alg": "Ed25519 Dalek", "type": "library", "ecosystem": "cargo", "pqc": False},
        "pqcrypto": {"alg": "PQCRYPTO Rust Framework", "type": "library", "ecosystem": "cargo", "pqc": True, "experimental": True},
        "pqcrypto-kyber": {"alg": "ML-KEM / Kyber Rust", "type": "library", "ecosystem": "cargo", "pqc": True, "experimental": True},
        "pqcrypto-dilithium": {"alg": "ML-DSA / Dilithium Rust", "type": "library", "ecosystem": "cargo", "pqc": True, "experimental": True},
        "rustls": {"alg": "Rustls TLS Framework", "type": "library", "ecosystem": "cargo", "pqc": False},

        # C# / .NET
        "BouncyCastle.Cryptography": {"alg": "Bouncy Castle .NET", "type": "library", "ecosystem": "nuget", "pqc": True},
        "System.Security.Cryptography.Algorithms": {"alg": ".NET Cryptography Algorithms", "type": "library", "ecosystem": "nuget", "pqc": False},
    }

    def scan_file(self, file_path: str) -> List[RawEvidence]:
        """Scan a dependency manifest file."""
        evidences: List[RawEvidence] = []
        if not os.path.exists(file_path):
            return evidences

        file_name = os.path.basename(file_path).lower()

        # 1. package.json
        if file_name == "package.json":
            evidences.extend(self._scan_package_json(file_path))
        # 2. requirements.txt / Pipfile
        elif "requirements" in file_name or file_name == "pipfile":
            evidences.extend(self._scan_requirements_txt(file_path))
        # 3. pom.xml
        elif file_name == "pom.xml":
            evidences.extend(self._scan_pom_xml(file_path))
        # 4. go.mod
        elif file_name == "go.mod":
            evidences.extend(self._scan_go_mod(file_path))
        # 5. Cargo.toml
        elif file_name == "cargo.toml":
            evidences.extend(self._scan_cargo_toml(file_path))

        return evidences

    def _scan_package_json(self, file_path: str) -> List[RawEvidence]:
        evidences = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for dep_name, ver in deps.items():
                dep_lower = dep_name.lower()
                for known, meta in self.KNOWN_CRYPTO_LIBRARIES.items():
                    if known.lower() == dep_lower:
                        evidences.append(RawEvidence(
                            id=str(uuid.uuid4()),
                            target_type=TargetType.DEPENDENCY,
                            file_path=file_path.replace("\\", "/"),
                            snippet=f'"{dep_name}": "{ver}"',
                            matched_pattern=dep_name,
                            raw_type="library",
                            detected_name=meta["alg"],
                            version_or_mode=str(ver),
                            metadata={"ecosystem": "npm", "pqc_supported": meta.get("pqc", False),
                                      "pqc_experimental": meta.get("experimental", False)}
                        ))
        except Exception:
            pass
        return evidences

    def _scan_requirements_txt(self, file_path: str) -> List[RawEvidence]:
        evidences = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("#"):
                        continue
                    parts = re.split(r"[=<>~!]", line_clean)
                    pkg_name = parts[0].strip().lower()
                    ver = line_clean[len(pkg_name):].strip() if len(parts) > 1 else "latest"
                    for known, meta in self.KNOWN_CRYPTO_LIBRARIES.items():
                        if known.lower() == pkg_name:
                            evidences.append(RawEvidence(
                                id=str(uuid.uuid4()),
                                target_type=TargetType.DEPENDENCY,
                                file_path=file_path.replace("\\", "/"),
                                line_number=idx,
                                snippet=line_clean,
                                matched_pattern=pkg_name,
                                raw_type="library",
                                detected_name=meta["alg"],
                                version_or_mode=ver,
                                metadata={"ecosystem": "pip", "pqc_supported": meta.get("pqc", False),
                                      "pqc_experimental": meta.get("experimental", False)}
                            ))
        except Exception:
            pass
        return evidences

    def _scan_pom_xml(self, file_path: str) -> List[RawEvidence]:
        evidences = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            # Handle XML namespaces
            ns = {"mvn": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            prefix = "mvn:" if ns else ""
            
            for dep in root.findall(f".//{prefix}dependency", ns):
                art_elem = dep.find(f"{prefix}artifactId", ns)
                ver_elem = dep.find(f"{prefix}version", ns)
                if art_elem is not None and art_elem.text:
                    art_name = art_elem.text.strip().lower()
                    ver = ver_elem.text.strip() if ver_elem is not None and ver_elem.text else "unknown"
                    for known, meta in self.KNOWN_CRYPTO_LIBRARIES.items():
                        if known.lower() in art_name:
                            evidences.append(RawEvidence(
                                id=str(uuid.uuid4()),
                                target_type=TargetType.DEPENDENCY,
                                file_path=file_path.replace("\\", "/"),
                                snippet=f"<artifactId>{art_name}</artifactId> <version>{ver}</version>",
                                matched_pattern=art_name,
                                raw_type="library",
                                detected_name=meta["alg"],
                                version_or_mode=ver,
                                metadata={"ecosystem": "maven", "pqc_supported": meta.get("pqc", False),
                                      "pqc_experimental": meta.get("experimental", False)}
                            ))
        except Exception:
            pass
        return evidences

    def _scan_go_mod(self, file_path: str) -> List[RawEvidence]:
        evidences = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    for known, meta in self.KNOWN_CRYPTO_LIBRARIES.items():
                        if known.lower() in line_clean.lower():
                            parts = line_clean.split()
                            ver = parts[1] if len(parts) > 1 else "v1.0"
                            evidences.append(RawEvidence(
                                id=str(uuid.uuid4()),
                                target_type=TargetType.DEPENDENCY,
                                file_path=file_path.replace("\\", "/"),
                                line_number=idx,
                                snippet=line_clean,
                                matched_pattern=known,
                                raw_type="library",
                                detected_name=meta["alg"],
                                version_or_mode=ver,
                                metadata={"ecosystem": "go", "pqc_supported": meta.get("pqc", False),
                                      "pqc_experimental": meta.get("experimental", False)}
                            ))
        except Exception:
            pass
        return evidences

    def _scan_cargo_toml(self, file_path: str) -> List[RawEvidence]:
        evidences = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    for known, meta in self.KNOWN_CRYPTO_LIBRARIES.items():
                        if line_clean.startswith(known) or f'"{known}"' in line_clean:
                            evidences.append(RawEvidence(
                                id=str(uuid.uuid4()),
                                target_type=TargetType.DEPENDENCY,
                                file_path=file_path.replace("\\", "/"),
                                line_number=idx,
                                snippet=line_clean,
                                matched_pattern=known,
                                raw_type="library",
                                detected_name=meta["alg"],
                                version_or_mode=line_clean.split("=")[-1].strip(" \"'") if "=" in line_clean else "latest",
                                metadata={"ecosystem": "cargo", "pqc_supported": meta.get("pqc", False),
                                      "pqc_experimental": meta.get("experimental", False)}
                            ))
        except Exception:
            pass
        return evidences

    # Manifest filenames this scanner understands. Lockfiles are deliberately
    # absent: the shared walker excludes them, and their contents merely repeat
    # the manifest with thousands of transitive entries.
    MANIFEST_FILENAMES = {
        "package.json", "requirements.txt", "pipfile", "pyproject.toml",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "cargo.toml", "composer.json", "gemfile",
    }

    def accepts(self, file_path: str) -> bool:
        """Whether this scanner handles the given path (used by the shared walker)."""
        name = os.path.basename(file_path).lower()
        return name in self.MANIFEST_FILENAMES or name.startswith("requirements")

    def scan_directory(
        self,
        root_dir: str,
        limits: Optional[WalkLimits] = None,
        stats: Optional[WalkStats] = None,
        on_file: Optional[Callable[[str], None]] = None,
    ) -> List[RawEvidence]:
        """Scan all dependency manifests in a directory."""
        evidences: List[RawEvidence] = []
        for file_path in walk_files(root_dir, limits=limits, accept=self.accepts, stats=stats):
            if on_file is not None:
                on_file(file_path)
            evidences.extend(self.scan_file(file_path))
        return evidences
