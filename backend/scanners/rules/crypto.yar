/*
 * Cryptographic signatures for compiled artefacts.
 *
 * These replace a hand-rolled table of byte comparisons in binary_scanner.py.
 * YARA is the standard format for binary pattern matching: rules are data
 * rather than code, so a new signature is a text edit instead of a Python
 * change, the matcher is a compiled automaton rather than a Python loop over
 * `bytes.find`, and the same rules can be handed to any other YARA-capable
 * tool.
 *
 * Every rule carries metadata the scanner turns directly into evidence:
 *
 *   algorithm   the cryptographic family reported
 *   asset_type  algorithm | library | key | certificate | protocol
 *   key_size    bits, where the signature implies one
 *   mode        cipher mode or role, where implied
 *   curve       elliptic curve, where implied
 *   note        what the match actually proves, shown as the evidence snippet
 *
 * Signatures are constants and symbol names, not behaviour. A match proves the
 * implementation is *present*, not that it is reached at runtime.
 */

/* ---------------------------------------------------------------- AES ---- */

rule aes_sbox
{
    meta:
        algorithm = "AES"
        asset_type = "algorithm"
        key_size = 256
        mode = "S-Box Table"
        note = "AES forward S-box lookup table"
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}

rule aes_inverse_sbox
{
    meta:
        algorithm = "AES"
        asset_type = "algorithm"
        key_size = 256
        mode = "Inverse S-Box Table"
        note = "AES inverse S-box, present in implementations that decrypt"
    strings:
        $rsbox = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
    condition:
        $rsbox
}

rule aes_te0_table
{
    meta:
        algorithm = "AES"
        asset_type = "algorithm"
        key_size = 256
        mode = "T-Table"
        note = "AES T-table, used by speed-optimised software implementations"
    strings:
        $te0 = { c6 63 63 a5 f8 7c 7c 84 ee 77 77 99 f6 7b 7b 8d }
    condition:
        $te0
}

/* ------------------------------------------------------------- Hashes ---- */

rule sha256_constants
{
    meta:
        algorithm = "SHA-256"
        asset_type = "algorithm"
        mode = "Hash"
        note = "SHA-256 round constants (fractional cube roots of the first primes)"
    strings:
        /* K[0..2] little-endian, as emitted by most C compilers. Three
           consecutive 32-bit constants are distinctive enough on their own,
           and stopping at three tolerates the padding and alignment that vary
           between toolchains. */
        $k_le = { 98 2f 8a 42 91 44 37 71 cf fb c0 b5 }
        /* Same constants big-endian */
        $k_be = { 42 8a 2f 98 71 37 44 91 b5 c0 fb cf }
        /* H[0..1] initial state */
        $h_le = { 67 e6 09 6a 85 ae 67 bb }
    condition:
        any of them
}

rule sha512_constants
{
    meta:
        algorithm = "SHA-512"
        asset_type = "algorithm"
        mode = "Hash"
        note = "SHA-512 initial hash values"
    strings:
        $h0 = { 08 c9 bc f3 67 e6 09 6a }
        $k0 = { d8 28 c7 a2 d1 a1 5a 42 }
    condition:
        any of them
}

rule sha1_constants
{
    meta:
        algorithm = "SHA-1"
        asset_type = "algorithm"
        mode = "Legacy Hash"
        note = "SHA-1 initial state — broken by collision attack (SHAttered)"
    strings:
        $h_le = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 f0 e1 d2 c3 }
        $k = { 99 79 82 5a a1 eb d9 6e dc bc 1b 8f d6 c1 62 ca }
    condition:
        any of them
}

rule md5_constants
{
    meta:
        algorithm = "MD5"
        asset_type = "algorithm"
        mode = "Legacy Hash"
        note = "MD5 initial state — broken by collision attack"
    strings:
        $iv = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 }
        $t0 = { 78 a4 6a d7 56 b7 c7 e8 db 70 20 24 ee ce bd c1 }
    condition:
        /* The IV alone is shared with SHA-1's first 16 bytes, so require the
           sine table when only the IV is present. */
        $t0 or ($iv and not sha1_constants)
}

/* ---------------------------------------------------- Stream ciphers ---- */

rule chacha20_sigma
{
    meta:
        algorithm = "ChaCha20"
        asset_type = "algorithm"
        key_size = 256
        mode = "Stream"
        note = "ChaCha20 sigma constant for 256-bit keys"
    strings:
        $sigma = "expand 32-byte k" ascii
    condition:
        $sigma
}

rule chacha20_tau
{
    meta:
        algorithm = "ChaCha20"
        asset_type = "algorithm"
        key_size = 128
        mode = "Stream"
        note = "ChaCha20 tau constant for 128-bit keys"
    strings:
        $tau = "expand 16-byte k" ascii
    condition:
        $tau
}

/* --------------------------------------------- Legacy block ciphers ---- */

rule des_tables
{
    meta:
        algorithm = "DES"
        asset_type = "algorithm"
        key_size = 56
        mode = "Legacy Block Cipher"
        note = "DES permutation tables — 56-bit key, brute-forceable"
    strings:
        /* PC-1 key schedule permutation */
        $pc1 = { 39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02 }
        /* Initial permutation */
        $ip = { 3a 32 2a 22 1a 12 0a 02 3c 34 2c 24 1c 14 0c 04 }
    condition:
        any of them
}

rule blowfish_pbox
{
    meta:
        algorithm = "Blowfish"
        asset_type = "algorithm"
        key_size = 448
        mode = "Legacy Block Cipher"
        note = "Blowfish P-array, initialised from the digits of pi"
    strings:
        $p = { 88 6a 3f 24 d3 08 a3 85 2e 8a 19 13 44 73 70 03 }
    condition:
        $p
}

/* ------------------------------------------------------ ASN.1 OIDs ---- */

rule oid_rsa_encryption
{
    meta:
        algorithm = "RSA"
        asset_type = "algorithm"
        key_size = 2048
        note = "ASN.1 OID 1.2.840.113549.1.1.1 rsaEncryption"
    strings:
        $oid = { 2a 86 48 86 f7 0d 01 01 01 }
        $txt = "1.2.840.113549.1.1.1" ascii
    condition:
        any of them
}

rule oid_sha256_with_rsa
{
    meta:
        algorithm = "RSA"
        asset_type = "algorithm"
        key_size = 2048
        mode = "PKCS#1 signature"
        note = "ASN.1 OID 1.2.840.113549.1.1.11 sha256WithRSAEncryption"
    strings:
        $oid = { 2a 86 48 86 f7 0d 01 01 0b }
        $txt = "1.2.840.113549.1.1.11" ascii
    condition:
        any of them
}

rule oid_ec_public_key
{
    meta:
        algorithm = "ECC"
        asset_type = "algorithm"
        curve = "secp256r1"
        note = "ASN.1 OID 1.2.840.10045.2.1 id-ecPublicKey"
    strings:
        $oid = { 2a 86 48 ce 3d 02 01 }
        $txt = "1.2.840.10045.2.1" ascii
    condition:
        any of them
}

rule oid_secp256r1
{
    meta:
        algorithm = "ECC"
        asset_type = "algorithm"
        curve = "secp256r1"
        note = "ASN.1 OID 1.2.840.10045.3.1.7 prime256v1 / P-256"
    strings:
        $oid = { 2a 86 48 ce 3d 03 01 07 }
    condition:
        $oid
}

rule oid_ed25519
{
    meta:
        algorithm = "ECC"
        asset_type = "algorithm"
        curve = "ed25519"
        note = "ASN.1 OID 1.3.101.112 Ed25519"
    strings:
        $oid = { 2b 65 70 }
        $txt = "1.3.101.112" ascii
    condition:
        /* Three bytes is short enough to appear by chance, so require the
           textual form or a longer DER context. */
        $txt or ($oid and for any i in (0..#oid) : (uint8(@oid[i] - 1) == 0x03))
}

rule oid_ml_kem
{
    meta:
        algorithm = "ML-KEM"
        asset_type = "algorithm"
        mode = "FIPS 203"
        note = "ASN.1 OID 2.16.840.1.101.3.4.4.2 ML-KEM-768"
    strings:
        $txt = "2.16.840.1.101.3.4.4" ascii
    condition:
        $txt
}

rule oid_ml_dsa
{
    meta:
        algorithm = "ML-DSA"
        asset_type = "algorithm"
        mode = "FIPS 204"
        note = "ASN.1 OID 2.16.840.1.101.3.4.3.17 ML-DSA-65"
    strings:
        $txt = "2.16.840.1.101.3.4.3" ascii
    condition:
        $txt
}

/* ---------------------------------------------- Library symbol names ---- */

rule openssl_aes_symbols
{
    meta:
        algorithm = "AES"
        asset_type = "algorithm"
        note = "OpenSSL AES interface symbols"
    strings:
        $gcm256 = "EVP_aes_256_gcm" ascii
        $gcm128 = "EVP_aes_128_gcm" ascii
        $cbc128 = "EVP_aes_128_cbc" ascii
        $cbc256 = "EVP_aes_256_cbc" ascii
    condition:
        any of them
}

rule openssl_legacy_symbols
{
    meta:
        algorithm = "Legacy-Cipher"
        asset_type = "algorithm"
        key_size = 168
        mode = "CBC"
        note = "OpenSSL 3DES/RC4 interface symbols — deprecated ciphers"
    strings:
        $des3 = "EVP_des_ede3_cbc" ascii
        $desk = "DES_set_key" ascii
        $rc4 = "EVP_rc4" ascii
    condition:
        any of them
}

rule openssl_hash_symbols
{
    meta:
        algorithm = "MD5/SHA-1"
        asset_type = "algorithm"
        mode = "Legacy Hash"
        note = "OpenSSL MD5/SHA-1 interface symbols"
    strings:
        $md5 = "EVP_md5" ascii
        $md5u = "MD5_Update" ascii
        $sha1 = "EVP_sha1" ascii
        $sha1u = "SHA1_Update" ascii
    condition:
        any of them
}

rule openssl_rsa_symbols
{
    meta:
        algorithm = "RSA"
        asset_type = "algorithm"
        key_size = 2048
        note = "OpenSSL RSA key generation symbols"
    strings:
        $a = "RSA_generate_key" ascii
        $b = "RSA_generate_key_ex" ascii
        $c = "EVP_PKEY_CTX_set_rsa_keygen_bits" ascii
    condition:
        any of them
}

rule openssl_ec_symbols
{
    meta:
        algorithm = "ECC"
        asset_type = "algorithm"
        curve = "secp256r1"
        note = "OpenSSL elliptic curve symbols"
    strings:
        $a = "EC_KEY_new_by_curve_name" ascii
        $b = "EVP_PKEY_CTX_set_ec_paramgen_curve_nid" ascii
        $c = "ECDH_compute_key" ascii
    condition:
        any of them
}

rule windows_cng_symbols
{
    meta:
        algorithm = "Windows-CNG"
        asset_type = "library"
        note = "Windows Cryptography API: Next Generation"
    strings:
        $a = "BCryptEncrypt" ascii
        $b = "BCryptGenRandom" ascii
        $c = "NCryptOpenStorageProvider" ascii
    condition:
        any of them
}

rule libsodium_symbols
{
    meta:
        algorithm = "Libsodium"
        asset_type = "library"
        note = "Libsodium / NaCl interface symbols"
    strings:
        $a = "crypto_sign_ed25519" ascii
        $b = "crypto_box_curve25519xsalsa20poly1305" ascii
        $c = "crypto_secretbox_easy" ascii
    condition:
        any of them
}

rule liboqs_symbols
{
    meta:
        algorithm = "PQC-FIPS"
        asset_type = "algorithm"
        mode = "Post-Quantum"
        note = "Open Quantum Safe symbols — a post-quantum implementation is present"
    strings:
        $a = "OQS_KEM_alg_kyber_768" ascii
        $b = "OQS_KEM_ml_kem_768_new" ascii
        $c = "OQS_SIG_alg_dilithium" ascii
        $d = "OQS_KEM_new" ascii
    condition:
        any of them
}

rule pkcs11_symbols
{
    meta:
        algorithm = "HSM/PKCS#11 Module"
        asset_type = "hardware_module"
        note = "PKCS#11 entry points — a hardware token interface is present"
    strings:
        $a = "C_Initialize" ascii
        $b = "C_OpenSession" ascii
        $c = "C_GetFunctionList" ascii
    condition:
        2 of them
}

/* ------------------------------------------ Embedded key material ---- */

rule embedded_private_key
{
    meta:
        algorithm = "Hardcoded-Private-Key"
        asset_type = "key"
        key_size = 2048
        note = "PEM private key block embedded in a compiled artefact"
    strings:
        $pem = "-----BEGIN" ascii
        $rsa = "PRIVATE KEY-----" ascii
    condition:
        $pem and $rsa
}

rule embedded_certificate
{
    meta:
        algorithm = "X509-Certificate"
        asset_type = "certificate"
        note = "PEM certificate embedded in a compiled artefact"
    strings:
        $cert = "-----BEGIN CERTIFICATE-----" ascii
    condition:
        $cert
}

/* ------------------------------------------------ Deprecated TLS ---- */

rule deprecated_tls_versions
{
    meta:
        algorithm = "TLS/SSL Protocol"
        asset_type = "protocol"
        note = "Deprecated TLS/SSL version strings"
    strings:
        $a = "SSLv2_method" ascii
        $b = "SSLv3_method" ascii
        $c = "TLSv1_method" ascii
        $d = "TLSv1_1_method" ascii
    condition:
        any of them
}
