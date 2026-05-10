"""RSAES-OAEP encryption/decryption with block chunking.

Reference: RFC 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2"
https://www.rfc-editor.org/rfc/rfc8017
"""

from __future__ import annotations

from .oaep import HASH_LEN, eme_oaep_decode, eme_oaep_encode
from .rsa import PrivateKey, PublicKey, i2osp, os2ip, rsadp, rsaep

__all__ = ["encrypt", "decrypt"]


def _key_size_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8


def _encrypt_block(pub: PublicKey, message: bytes) -> bytes:
    k = _key_size_bytes(pub.n)
    em = eme_oaep_encode(message, k)
    c = rsaep(pub, os2ip(em))
    return i2osp(c, k)


def _decrypt_block(priv: PrivateKey, block: bytes) -> bytes:
    k = _key_size_bytes(priv.n)
    if len(block) != k:
        raise ValueError("decryption error")
    m = rsadp(priv, os2ip(block))
    em = i2osp(m, k)
    return eme_oaep_decode(em, k)


def encrypt(plaintext: bytes, pub: PublicKey) -> bytes:
    """RSAES-OAEP encrypt arbitrary-length plaintext (RFC 8017 Section 7.1.1)."""
    k = _key_size_bytes(pub.n)
    max_block = k - 2 * HASH_LEN - 2
    if max_block <= 0:
        raise ValueError("RSA modulus too small for OAEP-SHA256")

    if not plaintext:
        return _encrypt_block(pub, b"")

    out = bytearray()
    for i in range(0, len(plaintext), max_block):
        out.extend(_encrypt_block(pub, plaintext[i:i + max_block]))
    return bytes(out)


def decrypt(ciphertext: bytes, priv: PrivateKey) -> bytes:
    """RSAES-OAEP decrypt blockwise (RFC 8017 Section 7.1.2)."""
    k = _key_size_bytes(priv.n)
    if len(ciphertext) == 0 or len(ciphertext) % k != 0:
        raise ValueError("decryption error")

    out = bytearray()
    for i in range(0, len(ciphertext), k):
        out.extend(_decrypt_block(priv, ciphertext[i:i + k]))
    return bytes(out)
