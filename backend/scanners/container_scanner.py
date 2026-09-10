import os
import re
import tarfile
import uuid
from typing import List, Dict, Any, Optional, Callable
from backend.models import RawEvidence, TargetType
from backend.scanners.walker import walk_files, WalkLimits, WalkStats


class ContainerScanner:
    """
    Scanner for container definitions (Dockerfiles, Containerfiles, OCI layers, tarballs).
    Detects base images with outdated crypto stacks, embedded keys/certs, and weak TLS configurations.
    """

    BASE_IMAGE_CRYPTO_MAP = {
        "ubuntu:14.04": {"openssl": "1.0.1f (Vulnerable to Heartbleed/Old TLS)", "pqc": False},
        "ubuntu:16.04": {"openssl": "1.0.2g (Deprecated)", "pqc": False},
        "ubuntu:18.04": {"openssl": "1.1.1 (End of Life)", "pqc": False},
        "debian:8": {"openssl": "1.0.1k", "pqc": False},
        "debian:9": {"openssl": "1.1.0j", "pqc": False},
        "alpine:3.10": {"libcrypto": "LibreSSL 2.9.2", "pqc": False},
        "alpine:3.12": {"libcrypto": "LibreSSL 3.1.2", "pqc": False},
        "centos:7": {"openssl": "1.0.2k", "pqc": False},
        "python:3.7": {"openssl": "1.1.1", "pqc": False},
        "node:12": {"openssl": "1.1.1d", "pqc": False},
    }

    DOCKERFILE_PATTERNS = [
        # Base image
        {
            "regex": re.compile(r"(?i)^FROM\s+([a-zA-Z0-9_\-\./:]+)"),
            "raw_type": "library",
            "name": "Base Image Crypto Stack",
            "is_base_image": True
        },
        # Copying private keys or certificates
        {
            "regex": re.compile(r"(?i)(?:COPY|ADD)\s+.*(?<!\w)([a-zA-Z0-9_\-\.]+\.(?:key|pem|crt|cer|p12|pfx|pkcs8))(?!\w)"),
            "raw_type": "key",
            "name": "Embedded Key/Certificate in Container Image Layer"
        },
        # Installing crypto libraries
        {
            "regex": re.compile(r"(?i)(?:RUN\s+.*(?:apt-get|apk|yum|dnf)\s+install\s+.*)(openssl|libssl-dev|libsodium-dev|liboqs-dev|ca-certificates|strongswan)"),
            "raw_type": "library",
            "name": "Container OS Cryptographic Library Installation"
        },
        # Insecure TLS in server configs
        {
            "regex": re.compile(r"(?i)(?<!\w)(ssl_protocols\s+.*(?:TLSv1|TLSv1\.1)|SSLProtocol\s+.*(?:SSLv2|SSLv3|TLSv1))(?!\w)"),
            "raw_type": "protocol",
            "name": "Insecure TLS Protocol in Container Config"
        },
        # Exposed Secrets / Hardcoded Keys in ENV
        {
            "regex": re.compile(r"(?i)ENV\s+(?:.*(?:PRIVATE_KEY|SECRET_KEY|API_KEY|ENCRYPTION_KEY|CERTIFICATE)\s*=\s*[\"']?([a-zA-Z0-9+/=_\-]{16,})[\"']?)"),
            "raw_type": "key",
            "name": "Hardcoded Key in Container Environment Variable"
        }
    ]

    def scan_dockerfile(self, file_path: str) -> List[RawEvidence]:
        """Scan a Dockerfile for crypto assets, layers, and configuration."""
        evidences: List[RawEvidence] = []
        if not os.path.exists(file_path):
            return evidences

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return evidences

        for idx, line in enumerate(lines, start=1):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            for pat in self.DOCKERFILE_PATTERNS:
                match = pat["regex"].search(line_clean)
                if match:
                    detected_name = match.group(1) if match.groups() else pat["name"]
                    version = None
                    raw_type = pat["raw_type"]

                    if pat.get("is_base_image"):
                        base_img = match.group(1).lower()
                        for known_img, info in self.BASE_IMAGE_CRYPTO_MAP.items():
                            if known_img in base_img:
                                detected_name = f"Base OS Crypto ({known_img})"
                                version = info.get("openssl") or info.get("libcrypto")
                                break

                    evidence = RawEvidence(
                        id=str(uuid.uuid4()),
                        target_type=TargetType.CONTAINER,
                        file_path=file_path.replace("\\", "/"),
                        line_number=idx,
                        snippet=line_clean[:200],
                        matched_pattern=match.group(0),
                        raw_type=raw_type,
                        detected_name=detected_name,
                        version_or_mode=version,
                        metadata={"container_scan_rule": pat["name"]}
                    )
                    evidences.append(evidence)

        return evidences

    def scan_container_tar(self, tar_path: str) -> List[RawEvidence]:
        """Inspect a saved container image archive (.tar) for embedded certificates and crypto files."""
        evidences: List[RawEvidence] = []
        if not os.path.exists(tar_path):
            return evidences

        try:
            with tarfile.open(tar_path, "r") as tar:
                for member in tar.getmembers():
                    name_lower = member.name.lower()
                    if name_lower.endswith((".key", ".pem", ".crt", ".pfx", ".p12")):
                        evidences.append(RawEvidence(
                            id=str(uuid.uuid4()),
                            target_type=TargetType.CONTAINER,
                            file_path=f"{tar_path.replace('\\', '/')}!/{member.name}",
                            snippet=f"Embedded certificate/key file in container layer: {member.name}",
                            matched_pattern=member.name,
                            raw_type="key" if ".key" in name_lower else "certificate",
                            detected_name=os.path.basename(member.name),
                            metadata={"is_layer_member": True, "size": member.size}
                        ))
        except Exception:
            pass

        return evidences

    def accepts(self, file_path: str) -> bool:
        """Whether this scanner handles the given path (used by the shared walker)."""
        name = os.path.basename(file_path).lower()
        if "dockerfile" in name or "containerfile" in name:
            return True
        return name.endswith((".tar", ".tar.gz")) and "image" in name

    def scan_directory(
        self,
        root_dir: str,
        limits: Optional[WalkLimits] = None,
        stats: Optional[WalkStats] = None,
        on_file: Optional[Callable[[str], None]] = None,
    ) -> List[RawEvidence]:
        """Scan all container definition files in a directory."""
        evidences: List[RawEvidence] = []
        # Container image tarballs are legitimate targets here, so the generic
        # archive-extension exclusion must not apply to this scanner's walk.
        walk_limits = limits or WalkLimits()
        walk_limits.allowed_extensions = walk_limits.allowed_extensions | {".tar", ".tar.gz"}
        for file_path in walk_files(root_dir, limits=walk_limits, accept=self.accepts, stats=stats):
            if on_file is not None:
                on_file(file_path)
            name = os.path.basename(file_path).lower()
            if "dockerfile" in name or "containerfile" in name:
                evidences.extend(self.scan_dockerfile(file_path))
            else:
                evidences.extend(self.scan_container_tar(file_path))
        return evidences
