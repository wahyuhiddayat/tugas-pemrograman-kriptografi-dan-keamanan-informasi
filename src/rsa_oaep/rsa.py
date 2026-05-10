"""RSA primitives: keypair generation and RSAEP/RSADP.

Reference: RFC 8017 "PKCS #1: RSA Cryptography Specifications Version 2.2"
https://www.rfc-editor.org/rfc/rfc8017
"""

from __future__ import annotations

from dataclasses import dataclass

from .number_theory import generate_prime, modinv

__all__ = [
    "PublicKey",
    "PrivateKey",
    "generate_keypair",
    "i2osp",
    "os2ip",
    "rsaep",
    "rsadp",
]


@dataclass(frozen=True)
class PublicKey:
    """RSA public key holding the modulus n and public exponent e."""

    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    """RSA private key holding the modulus n and private exponent d."""

    n: int
    d: int


def generate_keypair(bits: int = 2048, e: int = 65537) -> tuple[PublicKey, PrivateKey]:
    """Generate an RSA keypair whose modulus is exactly bits bits long.

    Raises ValueError if bits is not an even integer of at least 16. Retries
    prime generation internally until gcd(e, phi(n)) == 1 is satisfied.
    """
    if bits < 16 or bits % 2 != 0:
        raise ValueError("bits must be an even integer >= 16")

    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = modinv(e, phi)
        except ValueError:
            continue
        return PublicKey(n=n, e=e), PrivateKey(n=n, d=d)


def i2osp(x: int, x_len: int) -> bytes:
    """Integer to octet string primitive (RFC 8017 Section 4.1)."""
    if x < 0 or x >= 1 << (8 * x_len):
        raise ValueError("integer too large to fit in x_len bytes")
    return x.to_bytes(x_len, byteorder="big")


def os2ip(octets: bytes) -> int:
    """Octet string to integer primitive (RFC 8017 Section 4.2)."""
    return int.from_bytes(octets, byteorder="big")


def rsaep(pub: PublicKey, m: int) -> int:
    """RSA encryption primitive: c = m^e mod n (RFC 8017 Section 5.1.1)."""
    if not 0 <= m < pub.n:
        raise ValueError("message representative out of range")
    return pow(m, pub.e, pub.n)


def rsadp(priv: PrivateKey, c: int) -> int:
    """RSA decryption primitive: m = c^d mod n (RFC 8017 Section 5.1.2)."""
    if not 0 <= c < priv.n:
        raise ValueError("ciphertext representative out of range")
    return pow(c, priv.d, priv.n)
