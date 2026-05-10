"""EME-OAEP encoding with MGF1-SHA256.

Reference: RFC 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2"
https://www.rfc-editor.org/rfc/rfc8017
"""

from __future__ import annotations

import hashlib
import secrets

from .rsa import i2osp

__all__ = ["HASH_LEN", "mgf1", "eme_oaep_encode", "eme_oaep_decode"]


HASH_LEN = 32  # SHA-256 digest size


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """Mask Generation Function 1 with SHA-256 (RFC 8017 Section B.2.1)."""
    if mask_len < 0:
        raise ValueError("mask_len must be non-negative")
    if mask_len > (1 << 32) * HASH_LEN:
        raise ValueError("mask too long")

    output = bytearray()
    counter = 0
    while len(output) < mask_len:
        output.extend(hashlib.sha256(seed + i2osp(counter, 4)).digest())
        counter += 1
    return bytes(output[:mask_len])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def eme_oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP encode (RFC 8017 Section 7.1.1, step 2)."""
    m_len = len(message)
    if m_len > k - 2 * HASH_LEN - 2:
        raise ValueError("message too long")

    l_hash = hashlib.sha256(label).digest()
    ps = b"\x00" * (k - m_len - 2 * HASH_LEN - 2)
    db = l_hash + ps + b"\x01" + message

    seed = secrets.token_bytes(HASH_LEN)
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    masked_db = _xor(db, db_mask)
    seed_mask = mgf1(masked_db, HASH_LEN)
    masked_seed = _xor(seed, seed_mask)

    return b"\x00" + masked_seed + masked_db


def eme_oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP decode (RFC 8017 Section 7.1.2, step 3)."""
    if len(em) != k or k < 2 * HASH_LEN + 2:
        raise ValueError("decryption error")

    y = em[0]
    masked_seed = em[1:1 + HASH_LEN]
    masked_db = em[1 + HASH_LEN:]

    seed_mask = mgf1(masked_db, HASH_LEN)
    seed = _xor(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    db = _xor(masked_db, db_mask)

    l_hash = hashlib.sha256(label).digest()
    l_hash_prime = db[:HASH_LEN]
    rest = db[HASH_LEN:]

    # rest must be PS (all 0x00) || 0x01 || message
    delimiter_index = -1
    for i, byte in enumerate(rest):
        if byte == 0x01:
            delimiter_index = i
            break
        if byte != 0x00:
            break

    if y != 0 or l_hash != l_hash_prime or delimiter_index == -1:
        raise ValueError("decryption error")

    return rest[delimiter_index + 1:]
