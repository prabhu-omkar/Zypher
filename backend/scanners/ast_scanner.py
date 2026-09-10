"""
Syntax-aware cryptographic detection.

The regex scanner matches raw text, which means it cannot tell a call from a
comment, cannot follow an aliased import, and cannot read a call's arguments.
That last one matters most: key size drives X in the Mosca calculation, and the
regex path substituted a *default* whenever it could not parse one — so an
artefact labelled "RSA-2048" was frequently a guess, and an actual
``key_size=1024`` (already classically broken) could be reported as 2048.

This module parses the file instead and inspects the call sites:

* ``import hashlib as H`` … ``H.md5()`` resolves to ``hashlib.md5``.
* ``rsa.generate_private_key(key_size=1024)`` yields a real 1024, not a default.
* ``Cipher.getInstance("AES/CBC/PKCS5Padding")`` yields algorithm *and* mode.
* ``Cipher.getInstance(config.algorithm)`` is recorded as an unresolved
  algorithm rather than missed entirely or guessed at.
* Crypto words inside comments and unrelated strings are not calls, so they
  never match.

Regex remains the fallback for languages without a bundled grammar, and as the
cheap pre-filter that decides whether a file is worth parsing at all.
"""
from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from backend.models import RawEvidence, TargetType

# ---------------------------------------------------------------------------
# Grammar availability
# ---------------------------------------------------------------------------

# Extension -> tree-sitter language name.
LANGUAGE_BY_EXTENSION: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
}

_parsers: Dict[str, Any] = {}
_queries: Dict[str, Any] = {}
_unavailable: set = set()


def _parser_for(language: str):
    """Return a cached parser, or None if the grammar is not available."""
    if language in _unavailable:
        return None
    if language not in _parsers:
        try:
            from tree_sitter_language_pack import get_parser

            _parsers[language] = get_parser(language)
        except Exception:
            # A missing grammar must degrade to the regex path, never crash a scan.
            _unavailable.add(language)
            return None
    return _parsers[language]


def _query_for(language: str):
    """
    A compiled query selecting only the node kinds the rules examine.

    Built from the language spec so the two cannot drift apart. Cached: query
    compilation is not free and a scan parses thousands of files.
    """
    if language in _queries:
        return _queries[language]

    spec = SPECS.get(language)
    if spec is None:
        _queries[language] = None
        return None

    try:
        from tree_sitter import Query, QueryCursor  # noqa: F401
        from tree_sitter_language_pack import get_language

        parts = [f"({kind}) @call" for kind in spec.call_nodes]
        parts += [f"({kind}) @string" for kind in spec.string_nodes]
        parts += [f"({kind}) @import" for kind in spec.import_nodes]
        parts += [f"({kind}) @reference" for kind in spec.reference_nodes]
        _queries[language] = Query(get_language(language), "\n".join(parts))
    except Exception:
        _queries[language] = None
    return _queries[language]


def language_for(file_path: str) -> Optional[str]:
    return LANGUAGE_BY_EXTENSION.get(os.path.splitext(file_path)[1].lower())


def can_parse(file_path: str) -> bool:
    language = language_for(file_path)
    return bool(language) and _parser_for(language) is not None


# ---------------------------------------------------------------------------
# Per-language node vocabulary
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LanguageSpec:
    call_nodes: Tuple[str, ...]
    args_field: str
    string_nodes: Tuple[str, ...]
    number_nodes: Tuple[str, ...]
    import_nodes: Tuple[str, ...]
    # Nodes whose bare text is worth checking against constant rules
    # (ssl.PROTOCOL_TLSv1, ec.SECP256R1 used as a value, and so on).
    reference_nodes: Tuple[str, ...] = ()


SPECS: Dict[str, LanguageSpec] = {
    "python": LanguageSpec(
        call_nodes=("call",),
        args_field="arguments",
        string_nodes=("string",),
        number_nodes=("integer",),
        import_nodes=("import_statement", "import_from_statement"),
        reference_nodes=("attribute",),
    ),
    "javascript": LanguageSpec(
        call_nodes=("call_expression", "new_expression"),
        args_field="arguments",
        string_nodes=("string", "template_string"),
        number_nodes=("number",),
        import_nodes=("import_statement", "lexical_declaration", "variable_declaration"),
        reference_nodes=("member_expression",),
    ),
    "java": LanguageSpec(
        call_nodes=("method_invocation", "object_creation_expression"),
        args_field="arguments",
        string_nodes=("string_literal",),
        number_nodes=("decimal_integer_literal",),
        import_nodes=("import_declaration",),
        reference_nodes=("field_access",),
    ),
}
SPECS["typescript"] = SPECS["javascript"]
SPECS["tsx"] = SPECS["javascript"]


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """
    One cryptographic construct.

    ``callee`` matches the resolved callee text (everything before the argument
    list, with import aliases expanded). ``arg_pattern``, when present, must
    match one of the call's *literal* string arguments — which is how
    ``Cipher.getInstance("AES/...")`` is told apart from
    ``Cipher.getInstance("DESede/...")``.
    """
    name: str
    detected_name: str
    raw_type: str
    callee: re.Pattern
    arg_pattern: Optional[re.Pattern] = None
    # Reads a key length out of the literal arguments.
    key_from_arg: Optional[re.Pattern] = None
    key_kwarg: Tuple[str, ...] = ()
    default_key_size: Optional[int] = None
    mode_from_arg: Optional[re.Pattern] = None
    default_mode: Optional[str] = None
    curve_from_arg: Optional[re.Pattern] = None
    default_curve: Optional[str] = None
    # True when a rule describes a value reference rather than a call.
    is_reference: bool = False
    # Disambiguation for callees shared by several algorithms. A bare
    # ``generate_private_key`` is RSA when it carries a key size and ECC when it
    # carries a curve; without one of these the rule must not claim the call.
    require_kwarg: Tuple[str, ...] = ()
    require_curve_arg: bool = False
    # Callees this rule must not claim, so `rsa.generate_private_key` is never
    # also reported as ECC.
    exclude_callee: Optional[re.Pattern] = None


_KEYSIZE_IN_STRING = re.compile(r"(?i)(?<!\d)(512|1024|2048|3072|4096|128|192|256)(?!\d)")
_MODE_IN_STRING = re.compile(r"(?i)(?<![A-Z0-9])(GCM|CBC|CTR|ECB|CFB|OFB|XTS|CCM)(?![A-Z0-9])")
# `.init(128)` / `.initialize(2048)` / `.setKeySize(256)` on a key generator.
_GENERATOR_KEY_LENGTH = re.compile(
    r"(?i)\.(?:init|initialize|setKeySize|setKeyLength)\s*\(\s*(\d{2,5})\s*\)"
)

# `KeyGenerator.getInstance("AES")` / `KeyPairGenerator.getInstance("RSA")`
_GENERATOR_ALGORITHM = re.compile(
    r"(?i)(?:KeyGenerator|KeyPairGenerator|SecretKeyFactory)\.getInstance\s*"
    r"\(\s*[\"\']([A-Za-z0-9_-]+)"
)

# Generator algorithm name -> the detected_name a rule would report.
_GENERATOR_ALGORITHM_FAMILY = {
    "aes": "AES", "chacha20": "ChaCha20-Poly1305",
    "des": "Legacy-Cipher", "desede": "Legacy-Cipher", "tripledes": "Legacy-Cipher",
    "rc2": "Legacy-Cipher", "rc4": "Legacy-Cipher", "blowfish": "Legacy-Cipher",
    "rsa": "RSA", "dsa": "Diffie-Hellman", "dh": "Diffie-Hellman",
    "ec": "ECC", "ecdsa": "ECC",
}

_CURVE_IN_STRING = re.compile(
    r"(?i)(?<![A-Z0-9])(secp256r1|secp256k1|secp384r1|secp521r1|prime256v1|"
    r"P-256|P-384|P-521|ed25519|x25519|ed448|x448)(?![A-Z0-9])"
)

RULES: List[Rule] = [
    # ------------------------------------------------------------------ RSA
    Rule(
        name="RSA key generation",
        detected_name="RSA", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:rsa\.generate_private_key|RSA\.generate|"
                          r"generateKeyPairSync|generateKeyPair)$"),
        exclude_callee=re.compile(r"(?i)(?:^|\.)ec\."),
        key_kwarg=("key_size", "modulusLength", "bits", "keysize", "key_length"),
        default_key_size=2048,
    ),
    Rule(
        # Bare generate_private_key, disambiguated by a key size argument.
        name="RSA key generation (unqualified)",
        detected_name="RSA", raw_type="algorithm",
        callee=re.compile(r"(?i)^generate_private_key$"),
        require_kwarg=("key_size", "modulusLength", "bits", "keysize", "key_length"),
        key_kwarg=("key_size", "modulusLength", "bits", "keysize", "key_length"),
        default_key_size=2048,
    ),
    Rule(
        name="RSA via provider string",
        detected_name="RSA", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:KeyPairGenerator\.getInstance|"
                          r"Cipher\.getInstance|Signature\.getInstance|KeyFactory\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^RSA(?:/|$|_)"),
        key_from_arg=_KEYSIZE_IN_STRING,
        default_key_size=2048,
    ),
    # ------------------------------------------------------------------ ECC
    Rule(
        name="Elliptic curve key generation",
        detected_name="ECC", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:ec\.generate_private_key|"
                          r"createECDH|ECDH|ECDSA|EllipticCurve|SigningKey\.generate)$"),
        exclude_callee=re.compile(r"(?i)(?:^|\.)rsa\."),
        curve_from_arg=_CURVE_IN_STRING,
        default_curve="secp256r1",
    ),
    Rule(
        # Bare generate_private_key, disambiguated by a named curve argument.
        name="Elliptic curve key generation (unqualified)",
        detected_name="ECC", raw_type="algorithm",
        callee=re.compile(r"(?i)^generate_private_key$"),
        require_curve_arg=True,
        curve_from_arg=_CURVE_IN_STRING,
        default_curve="secp256r1",
    ),
    Rule(
        name="Elliptic curve via provider string",
        detected_name="ECC", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:KeyPairGenerator\.getInstance|"
                          r"Signature\.getInstance|KeyAgreement\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^(?:EC|ECDSA|ECDH)(?:/|$|withSHA)"),
        curve_from_arg=_CURVE_IN_STRING,
        default_curve="secp256r1",
    ),
    Rule(
        name="Named elliptic curve",
        detected_name="ECC", raw_type="algorithm", is_reference=True,
        callee=re.compile(r"(?i)(?:^|\.)(?:SECP256R1|SECP256K1|SECP384R1|SECP521R1|"
                          r"Ed25519|X25519|Ed448|X448|NIST256p|prime256v1)$"),
        curve_from_arg=_CURVE_IN_STRING,
        default_curve="secp256r1",
    ),
    # --------------------------------------------------------- DH / DSA
    Rule(
        name="Diffie-Hellman / DSA via provider string",
        detected_name="Diffie-Hellman", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:KeyPairGenerator\.getInstance|"
                          r"Signature\.getInstance|KeyAgreement\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^(?:DSA|DH|DiffieHellman)$"),
        default_key_size=2048,
    ),
    Rule(
        name="Diffie-Hellman parameters",
        detected_name="Diffie-Hellman", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:DiffieHellman|DHParameterSpec|"
                          r"generate_parameters|createDiffieHellman)$"),
        key_kwarg=("key_size", "generator", "primeLength"),
        default_key_size=2048,
    ),
    # ------------------------------------------------------------------ AES
    Rule(
        name="AES cipher",
        detected_name="AES", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:AES\.new|AESGCM|AESCCM|AESOCB3|AESSIV)$"),
        key_from_arg=_KEYSIZE_IN_STRING,
        mode_from_arg=_MODE_IN_STRING,
        default_key_size=256, default_mode="GCM",
    ),
    Rule(
        name="AES via provider string",
        detected_name="AES", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:Cipher\.getInstance|createCipheriv|"
                          r"createDecipheriv|KeyGenerator\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^aes(?:-|/|$)"),
        key_from_arg=_KEYSIZE_IN_STRING,
        mode_from_arg=_MODE_IN_STRING,
        default_key_size=256, default_mode="GCM",
    ),
    # ------------------------------------------------- Legacy symmetric
    Rule(
        name="Legacy cipher via provider string",
        detected_name="Legacy-Cipher", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:Cipher\.getInstance|createCipheriv|"
                          r"createDecipheriv|KeyGenerator\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^(?:des|desede|3des|tripledes|rc2|rc4|arc4|"
                               r"blowfish|idea)(?:-|/|$)"),
        mode_from_arg=_MODE_IN_STRING,
        default_key_size=56,
    ),
    Rule(
        name="Legacy cipher constructor",
        detected_name="Legacy-Cipher", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:DES\.new|DES3\.new|ARC4\.new|ARC2\.new|"
                          r"Blowfish\.new|TripleDES|DESede)$"),
        default_key_size=56,
    ),
    # ------------------------------------------------------------ ChaCha20
    Rule(
        name="ChaCha20-Poly1305",
        detected_name="ChaCha20-Poly1305", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:ChaCha20Poly1305|ChaCha20|chacha20_poly1305)$"),
        default_key_size=256, default_mode="Poly1305",
    ),
    # -------------------------------------------------------------- Hashes
    Rule(
        name="Broken hash",
        detected_name="MD5/SHA-1", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:hashlib\.md5|hashlib\.sha1|md5|sha1|"
                          r"MD5\.new|SHA1\.new|MD5_Init|SHA1_Init)$"),
    ),
    Rule(
        name="Broken hash via provider string",
        detected_name="MD5/SHA-1", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:MessageDigest\.getInstance|createHash|"
                          r"Mac\.getInstance|Signature\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^(?:md5|md2|md4|sha-?1|hmacmd5|hmacsha1|"
                               r"sha1with\w+|md5with\w+)$"),
    ),
    Rule(
        name="Secure hash",
        detected_name="SHA-2/SHA-3", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:hashlib\.sha224|hashlib\.sha256|hashlib\.sha384|"
                          r"hashlib\.sha512|hashlib\.sha3_\w+|hashlib\.blake2[bs]|"
                          r"SHA256_Init|SHA512_Init)$"),
    ),
    Rule(
        name="Secure hash via provider string",
        detected_name="SHA-2/SHA-3", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:MessageDigest\.getInstance|createHash|"
                          r"Mac\.getInstance)$"),
        arg_pattern=re.compile(r"(?i)^(?:sha-?(?:224|256|384|512)|sha3-?\w+|"
                               r"hmacsha(?:224|256|384|512)|blake2\w*)$"),
    ),
    # ---------------------------------------------------------------- PQC
    Rule(
        name="NIST post-quantum algorithm",
        detected_name="PQC-FIPS", raw_type="algorithm",
        callee=re.compile(r"(?i)(?:^|\.)(?:oqs\.KeyEncapsulation|oqs\.Signature|"
                          r"KeyEncapsulation|Signature|MLKEM|ML_KEM|MLDSA|ML_DSA|"
                          r"SLHDSA|Kyber|Dilithium|Falcon|SPHINCS)$"),
        arg_pattern=re.compile(r"(?i)(?:ML-?KEM|ML-?DSA|SLH-?DSA|Kyber|Dilithium|"
                               r"Falcon|SPHINCS)"),
    ),
    # ---------------------------------------------------------- Cloud KMS
    Rule(
        name="Cloud key management service",
        detected_name="Cloud KMS Service", raw_type="cloud_service",
        callee=re.compile(r"(?i)(?:^|\.)(?:boto3\.client|boto3\.resource|client)$"),
        arg_pattern=re.compile(r"(?i)^(?:kms|secretsmanager|acm)$"),
    ),
    Rule(
        name="Cloud key vault client",
        detected_name="Cloud KMS Service", raw_type="cloud_service",
        callee=re.compile(r"(?i)(?:^|\.)(?:SecretClient|KeyClient|CertificateClient|"
                          r"KeyVaultClient|KeyManagementServiceClient|"
                          r"hvac\.Client|kmsClient\.encrypt|kmsClient\.decrypt)$"),
    ),
    # ------------------------------------------------ Hardware modules
    Rule(
        name="Hardware security module",
        detected_name="HSM/PKCS#11 Module", raw_type="hardware_module",
        callee=re.compile(r"(?i)(?:^|\.)(?:PyKCS11\.\w+|pkcs11\.\w+|C_Initialize|"
                          r"C_OpenSession|C_Sign|lib\.load)$"),
    ),
    Rule(
        name="Hardware provider string",
        detected_name="HSM/PKCS#11 Module", raw_type="hardware_module",
        callee=re.compile(r"(?i)(?:^|\.)(?:KeyPairGenerator\.getInstance|"
                          r"KeyStore\.getInstance|Signature\.getInstance|"
                          r"Security\.addProvider)$"),
        arg_pattern=re.compile(r"(?i)^(?:SunPKCS11|PKCS11|LunaProvider|nCipherKM|"
                               r"YubiHSM|BC-FIPS)"),
    ),
    # ------------------------------------------------------------ Protocols
    Rule(
        name="TLS protocol selection",
        detected_name="TLS/SSL Protocol", raw_type="protocol",
        callee=re.compile(r"(?i)(?:^|\.)(?:SSLContext|create_default_context|"
                          r"SSLContext\.getInstance|wrap_socket)$"),
        arg_pattern=re.compile(r"(?i)(?:SSLv2|SSLv3|TLSv1|TLS_?v?1\.[0-3]|PROTOCOL_\w+|TLS)"),
    ),
    Rule(
        name="TLS protocol constant",
        detected_name="TLS/SSL Protocol", raw_type="protocol", is_reference=True,
        callee=re.compile(r"(?i)(?:^|\.)(?:PROTOCOL_TLSv1|PROTOCOL_TLSv1_1|"
                          r"PROTOCOL_TLSv1_2|PROTOCOL_SSLv3|PROTOCOL_SSLv23|"
                          r"PROTOCOL_TLS_CLIENT|PROTOCOL_TLS_SERVER)$"),
    ),
]

# Provider-style factories whose algorithm argument is not a literal. Without
# this the call is invisible — the same blind spot the regex scanner has — even
# though "there is cryptography here and we cannot tell what" is exactly the
# finding an inventory should carry.
UNRESOLVED_FACTORY = Rule(
    name="Cryptographic factory with a non-literal algorithm",
    detected_name="Unresolved-Algorithm", raw_type="algorithm",
    callee=re.compile(r"(?i)(?:^|\.)(?:Cipher\.getInstance|MessageDigest\.getInstance|"
                      r"KeyPairGenerator\.getInstance|KeyGenerator\.getInstance|"
                      r"Signature\.getInstance|Mac\.getInstance|SecretKeyFactory\.getInstance|"
                      r"createHash|createCipheriv|createDecipheriv|createHmac)$"),
)


# PEM blocks, read out of string literals rather than raw file text so that a
# certificate mentioned in a comment is not reported as a deployed one.
PEM_RULES = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
     "Hardcoded-Private-Key", "key"),
    (re.compile(r"-----BEGIN CERTIFICATE-----"), "X509-Certificate", "certificate"),
    (re.compile(r"-----BEGIN PUBLIC KEY-----"), "Hardcoded-Public-Key", "key"),
]


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

@dataclass
class _Call:
    callee: str
    literal_args: List[str] = field(default_factory=list)
    kwargs: Dict[str, str] = field(default_factory=dict)
    has_dynamic_args: bool = False
    line: int = 0
    snippet: str = ""


def _text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _unquote(raw: str) -> str:
    raw = raw.strip()
    for quote in ('"""', "'''", '"', "'", "`"):
        if len(raw) >= 2 * len(quote) and raw.startswith(quote) and raw.endswith(quote):
            return raw[len(quote):-len(quote)]
    return raw


def _collect_aliases(source: bytes, import_nodes) -> Dict[str, str]:
    """
    Map local names back to their imported origin.

    ``import hashlib as H`` makes ``H.md5()`` indistinguishable from any other
    ``.md5()`` to a text matcher; here it resolves to ``hashlib.md5``.
    """
    aliases: Dict[str, str] = {}
    for node in import_nodes:
        text = _text(source, node)
        # `import x as y` / `from a import b as c` / `import {a as b} from 'm'`
        for local, origin in re.findall(r"(?:^|[\s,{(])([\w.]+)\s+as\s+([\w.]+)", text):
            aliases[origin] = local
        for origin, local in re.findall(r"([\w.]+)\s+as\s+([\w.]+)", text):
            aliases[local] = origin
        # `const crypto = require('crypto')`
        m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['\"]([\w/@.-]+)['\"]", text)
        if m:
            aliases[m.group(1)] = m.group(2)
    return aliases


def _resolve(callee: str, aliases: Dict[str, str]) -> str:
    """Expand a leading alias segment, so H.md5 becomes hashlib.md5."""
    if not aliases:
        return callee
    head, _, rest = callee.partition(".")
    origin = aliases.get(head)
    if origin:
        return f"{origin}.{rest}" if rest else origin
    return callee


def _read_call(source: bytes, node, spec: LanguageSpec, aliases: Dict[str, str]) -> _Call:
    args = node.child_by_field_name(spec.args_field)
    end = args.start_byte if args is not None else node.end_byte
    callee = source[node.start_byte:end].decode("utf-8", "replace").strip()
    # `new Foo(...)` — drop the keyword so rules match the constructor name.
    callee = re.sub(r"^new\s+", "", callee).strip()

    call = _Call(
        callee=_resolve(callee, aliases),
        line=node.start_point[0] + 1,
        snippet=_text(source, node).splitlines()[0][:200] if node.end_byte > node.start_byte else "",
    )

    if args is None:
        return call

    for child in args.children:
        if child.type in (",", "(", ")"):
            continue
        if child.type in spec.string_nodes:
            call.literal_args.append(_unquote(_text(source, child)))
        elif child.type in spec.number_nodes:
            call.literal_args.append(_text(source, child))
        elif child.type in ("keyword_argument", "pair", "assignment_expression"):
            parts = _text(source, child).split("=", 1)
            if len(parts) == 2:
                call.kwargs[parts[0].strip()] = _unquote(parts[1].strip())
            else:
                call.has_dynamic_args = True
        elif child.type == "object":
            # JS options object: { modulusLength: 2048 }
            for key, value in re.findall(r"(\w+)\s*:\s*([\w'\"-]+)", _text(source, child)):
                call.kwargs[key] = _unquote(value)
        elif child.type in ("identifier", "attribute", "member_expression",
                            "field_access", "subscript", "call", "call_expression",
                            "method_invocation", "binary_operator", "binary_expression"):
            call.has_dynamic_args = True
            # A named curve or algorithm passed as a value still identifies itself.
            call.literal_args.append(_text(source, child))
        else:
            call.has_dynamic_args = True

    return call


def _first_int(values: List[str]) -> Optional[int]:
    for value in values:
        if value.isdigit():
            return int(value)
    return None


def _match_rules(call: _Call) -> List[Tuple[Rule, Optional[str]]]:
    """Rules satisfied by a call, with the literal argument that decided it."""
    matched = []
    for rule in RULES:
        if rule.is_reference:
            continue
        if not rule.callee.search(call.callee):
            continue
        if rule.exclude_callee and rule.exclude_callee.search(call.callee):
            continue
        if rule.require_kwarg and not any(
            k.lower() in {r.lower() for r in rule.require_kwarg} for k in call.kwargs
        ):
            continue
        if rule.require_curve_arg and not any(
            _CURVE_IN_STRING.search(a) for a in call.literal_args
        ):
            continue
        if rule.arg_pattern is None:
            matched.append((rule, None))
            continue
        hit = next((a for a in call.literal_args if rule.arg_pattern.search(a)), None)
        if hit is not None:
            matched.append((rule, hit))

    # Nothing claimed a known factory call: record it as undetermined rather
    # than letting it disappear.
    if not matched and UNRESOLVED_FACTORY.callee.search(call.callee):
        matched.append((UNRESOLVED_FACTORY, None))
    return matched


def scan_source(file_path: str, source: bytes, language: str) -> Optional[List[RawEvidence]]:
    """
    Parse and inspect a file. Returns None when the language has no grammar, so
    the caller can fall back to the regex scanner.
    """
    spec = SPECS.get(language)
    parser = _parser_for(language)
    if spec is None or parser is None:
        return None

    try:
        tree = parser.parse(source)
    except Exception:
        return None

    root = tree.root_node
    query = _query_for(language)
    if query is None:
        return None

    from tree_sitter import QueryCursor

    captures = QueryCursor(query).captures(root)
    call_nodes = captures.get("call", ())
    string_nodes = captures.get("string", ())
    reference_nodes = captures.get("reference", ())

    aliases = _collect_aliases(source, captures.get("import", ()))
    normalised_path = file_path.replace("\\", "/")

    # Key length is often set on a generator rather than in the transformation
    # string. Associating the two statements properly needs dataflow, so this
    # pairs each length with the algorithm named by the nearest preceding
    # generator and applies it only to artefacts of that algorithm — a
    # file-wide hint would hand one algorithm's length to another.
    key_hints: Dict[str, int] = {}
    current_algorithm: Optional[str] = None
    for node in sorted(call_nodes, key=lambda n: n.start_byte):
        text = _text(source, node)
        named = _GENERATOR_ALGORITHM.search(text)
        if named:
            current_algorithm = _GENERATOR_ALGORITHM_FAMILY.get(named.group(1).lower())
        length = _GENERATOR_KEY_LENGTH.search(text)
        if length and current_algorithm:
            key_hints.setdefault(current_algorithm, int(length.group(1)))
    evidences: List[RawEvidence] = []
    seen: set = set()

    def emit(rule: Rule, line: int, snippet: str, matched_text: str,
             key_size, mode, curve, resolved: bool):
        key = (rule.detected_name, line, mode, key_size, curve)
        if key in seen:
            return
        seen.add(key)
        evidences.append(RawEvidence(
            id=str(uuid.uuid4()),
            target_type=TargetType.SOURCE_CODE,
            file_path=normalised_path,
            line_number=line,
            # Marks AST-derived evidence; the extractor raises confidence for it.
            column_number=1,
            snippet=snippet[:200],
            matched_pattern=matched_text,
            raw_type=rule.raw_type,
            detected_name=rule.detected_name,
            version_or_mode=mode,
            key_length=key_size,
            curve_name=curve,
            metadata={
                "rule_name": rule.name,
                "detector": "ast",
                "language": language,
                "file_ext": os.path.splitext(file_path)[1],
                # False when the algorithm came from a variable rather than a
                # literal, so the inventory can say so instead of guessing.
                "parameters_resolved": resolved,
            },
        ))

    for node in call_nodes:
        if True:
            call = _read_call(source, node, spec, aliases)
            for rule, hit in _match_rules(call):
                pool = ([hit] if hit else []) + call.literal_args + list(call.kwargs.values())

                key_size = None
                for name in rule.key_kwarg:
                    for kwarg, value in call.kwargs.items():
                        if kwarg.lower() == name.lower() and value.isdigit():
                            key_size = int(value)
                            break
                    if key_size:
                        break
                if key_size is None and rule.key_from_arg:
                    for value in pool:
                        m = rule.key_from_arg.search(value)
                        if m:
                            key_size = int(m.group(1))
                            break
                needed_key = bool(rule.key_kwarg or rule.key_from_arg)
                # True only when the length came out of the source. A default is
                # a guess, and an invented length makes an unknown key look
                # quantum-safe — so nothing is substituted here.
                read_key = key_size is not None
                if key_size is None and not rule.key_kwarg:
                    key_size = _first_int(call.literal_args)
                    read_key = key_size is not None
                if key_size is None and rule.detected_name in key_hints:
                    key_size = key_hints[rule.detected_name]
                    read_key = True

                mode = None
                if rule.mode_from_arg:
                    for value in pool:
                        m = rule.mode_from_arg.search(value)
                        if m:
                            mode = m.group(1).upper()
                            break
                # A mode is only reported when the source states one.
                if mode is None and rule.default_mode and hit:
                    mode = None

                curve = None
                if rule.curve_from_arg:
                    for value in pool:
                        m = rule.curve_from_arg.search(value)
                        if m:
                            curve = m.group(1)
                            break
                curve = curve or rule.default_curve

                # Resolved when the parameters this rule cares about were
                # actually read from the source, rather than substituted.
                resolved = (
                    rule is not UNRESOLVED_FACTORY
                    and (read_key or not needed_key)
                    and (curve is not None or rule.curve_from_arg is None)
                    and (hit is not None or rule.arg_pattern is None)
                )
                emit(rule, call.line, call.snippet, hit or call.callee,
                     key_size, mode, curve, resolved)

    # --- bare references (named curves, protocol constants) --------------
    for node in reference_nodes:
        if True:
            text = _text(source, node)
            resolved_text = _resolve(text, aliases)
            for rule in RULES:
                if rule.is_reference and rule.callee.search(resolved_text):
                    curve = None
                    if rule.curve_from_arg:
                        m = rule.curve_from_arg.search(text)
                        curve = m.group(1) if m else rule.default_curve
                    emit(rule, node.start_point[0] + 1, text, text,
                         None, None, curve, True)

    # --- PEM material inside string literals ------------------------------
    for node in string_nodes:
        if True:
            text = _text(source, node)
            for pattern, name, raw_type in PEM_RULES:
                if pattern.search(text):
                    line = node.start_point[0] + 1
                    key = (name, line, None, None, None)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidences.append(RawEvidence(
                        id=str(uuid.uuid4()),
                        target_type=TargetType.SOURCE_CODE,
                        file_path=normalised_path,
                        line_number=line,
                        column_number=1,
                        snippet=pattern.pattern.replace("\\", "")[:200],
                        matched_pattern=name,
                        raw_type=raw_type,
                        detected_name=name,
                        key_length=2048 if raw_type == "key" else None,
                        metadata={
                            "rule_name": "Embedded PEM block",
                            "detector": "ast",
                            "language": language,
                            "is_embedded_pem": True,
                            "parameters_resolved": True,
                        },
                    ))
                    break

    return evidences
