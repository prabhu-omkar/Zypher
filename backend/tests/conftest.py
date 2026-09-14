"""
Shared test fixtures.

The suite used to call execute_pipeline() against the live storage manager, so
every `pytest` run left a real scan_SCAN-*.json file behind in the project's
data_store/. Those files then accumulated in the UI's scan history and — before
the walker gained an exclusion list — were re-ingested by the next directory
scan, which is how a scan of this repository reached 6019 artefacts.

Tests now run against a temporary data directory that is discarded afterwards.
"""
import pytest

from backend.cbom.storage import EnterpriseStorageManager


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """Point the application's storage manager at a throwaway directory."""
    import backend.main as main

    temp_store = tmp_path / "data_store"
    temp_store.mkdir()

    isolated = EnterpriseStorageManager(data_dir=str(temp_store))
    monkeypatch.setattr(main, "storage_manager", isolated)

    # Modules that captured the manager at import time must see the same object.
    monkeypatch.setattr("backend.main.storage_manager", isolated)

    yield isolated


@pytest.fixture
def client(isolated_storage):
    from fastapi.testclient import TestClient
    from backend.main import app

    return TestClient(app)


# Cryptographic material the scanners are expected to find. Written into a
# temporary directory per test rather than read from a checked-in folder: the
# demo target under test/ is meant to be moved or copied away, so the suite must
# not depend on its location — or on its continued existence.
_AUTH_SERVICE_PY = '''\
import boto3
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
import hashlib

HARDCODED_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0YkX2o...TRUNCATED_TEST_PLACEHOLDER...==
-----END RSA PRIVATE KEY-----"""

def init_auth_keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def sign_session_token(data: bytes):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    return ec_key.sign(data, ec.ECDSA(hashes.SHA256()))

def hash_legacy_password(pwd: str):
    return hashlib.md5(pwd.encode()).hexdigest()

def connect_kms():
    return boto3.client('kms', region_name='us-east-1')
'''

_PAYMENT_VAULT_JAVA = '''\
package com.enterprise.banking;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;

public class PaymentVault {
    public static void encryptCreditCard(byte[] data) throws Exception {
        Cipher desCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
    public static void generateHSMSignature() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SunPKCS11");
        kpg.initialize(2048);
    }
    public static byte[] hashTransaction(byte[] payload) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(payload);
    }
}
'''

_PACKAGE_JSON = """\
{
  "name": "enterprise-fintech-gateway",
  "version": "2.4.0",
  "dependencies": {
    "crypto-js": "^4.2.0",
    "node-forge": "^1.3.1",
    "elliptic": "^6.5.4",
    "bcrypt": "^5.1.0",
    "jose": "^4.14.4",
    "express": "^4.18.2"
  }
}
"""

_REQUIREMENTS_TXT = """\
cryptography==41.0.4
pycryptodome==3.19.0
liboqs-python==0.8.0
pynacl==1.5.0
rsa==4.9
fastapi==0.104.1
"""

_DOCKERFILE = """\
FROM ubuntu:16.04
RUN apt-get update && apt-get install -y openssl libssl-dev
RUN echo "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;" > /etc/nginx/ssl.conf
COPY server.key /etc/ssl/private/server.key
COPY cert.pem /etc/ssl/certs/cert.pem
ENV ENCRYPTION_KEY=4b89f81a798f0293cb84a91e4f201092
EXPOSE 443
"""


def _build_firmware_blob() -> bytes:
    """
    A small binary carrying the constants and symbols the binary scanner looks
    for, at known offsets.
    """
    blob = bytearray(b"\x00" * 32)
    blob += bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76])   # AES S-box
    blob += b"\x00" * 16
    blob += bytes([0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71,
                   0xCF, 0xFB, 0xC0, 0xB5])                            # SHA-256 K-table
    blob += b"\x00" * 16
    blob += bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                   0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])   # MD5 init vector
    blob += b"\x00" * 34
    blob += b"expand 32-byte k"                                        # ChaCha20 sigma
    blob += b"\x00EVP_aes_256_gcm\x00RSA_generate_key\x00"
    blob += b"1.2.840.113549.1.1.11\x002.16.840.1.101.3.4.4.2\x00"
    blob += b"OQS_KEM_alg_kyber_768\x00"
    return bytes(blob)


@pytest.fixture
def sample_tree(tmp_path):
    """A four-modality target tree: source, dependencies, container, binary."""
    root = tmp_path / "target"
    (root / "source_repo").mkdir(parents=True)
    (root / "dependencies").mkdir()
    (root / "containers").mkdir()
    (root / "binaries").mkdir()

    (root / "source_repo" / "auth_service.py").write_text(_AUTH_SERVICE_PY, encoding="utf-8")
    (root / "source_repo" / "PaymentVault.java").write_text(_PAYMENT_VAULT_JAVA, encoding="utf-8")
    (root / "dependencies" / "package.json").write_text(_PACKAGE_JSON, encoding="utf-8")
    (root / "dependencies" / "requirements.txt").write_text(_REQUIREMENTS_TXT, encoding="utf-8")
    (root / "containers" / "Dockerfile").write_text(_DOCKERFILE, encoding="utf-8")
    (root / "binaries" / "crypto_firmware.bin").write_bytes(_build_firmware_blob())

    return root
