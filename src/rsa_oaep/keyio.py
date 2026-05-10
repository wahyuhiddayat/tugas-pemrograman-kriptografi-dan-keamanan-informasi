"""Hex-encoded RSA key file I/O.

File format (one key per file, two non-empty text lines):
- Line 1: modulus `n` as hex (lowercase, zero-padded to key size in bytes * 2)
- Line 2: exponent `e` (public) or `d` (private) as hex (natural width)

This format follows the assignment spec ("Key ditulis sebagai teks dalam
notasi hexadecimal") rather than PEM/DER from RFC 8017.
"""

from __future__ import annotations

from pathlib import Path

from .rsa import PrivateKey, PublicKey

__all__ = [
    "save_public_key",
    "load_public_key",
    "save_private_key",
    "load_private_key",
]


def _hex_width(n: int) -> int:
    return ((n.bit_length() + 7) // 8) * 2


def _read_two_hex_values(path: str | Path) -> tuple[int, int]:
    text = Path(path).read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 2:
        raise ValueError("malformed key file: expected exactly two non-empty lines")
    try:
        return int(lines[0], 16), int(lines[1], 16)
    except ValueError as exc:
        raise ValueError(f"invalid hex in key file: {exc}") from exc


def save_public_key(pub: PublicKey, path: str | Path) -> None:
    width = _hex_width(pub.n)
    Path(path).write_text(f"{pub.n:0{width}x}\n{pub.e:x}\n", encoding="utf-8")


def load_public_key(path: str | Path) -> PublicKey:
    n, e = _read_two_hex_values(path)
    return PublicKey(n=n, e=e)


def save_private_key(priv: PrivateKey, path: str | Path) -> None:
    width = _hex_width(priv.n)
    Path(path).write_text(f"{priv.n:0{width}x}\n{priv.d:x}\n", encoding="utf-8")


def load_private_key(path: str | Path) -> PrivateKey:
    n, d = _read_two_hex_values(path)
    return PrivateKey(n=n, d=d)
