from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
import hashlib

LEGACY_BITS = 1024


def _build_rsa(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def legacy_rsa():
    return _build_rsa(LEGACY_BITS)


def _build_dsa(bits):
    return dsa.generate_private_key(key_size=bits)


def weak_dsa():
    return _build_dsa(1024)


def _build_ec(curve):
    return ec.generate_private_key(curve)


def weak_curve():
    return _build_ec("secp192r1")


def _digest(name, data):
    return hashlib.new(name, data)


def legacy_digest(data):
    return _digest("md5", data)
