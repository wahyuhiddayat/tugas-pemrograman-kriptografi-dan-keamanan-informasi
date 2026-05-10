"""Hex-encoded RSA key file I/O.

Each key file holds exactly two non-empty text lines. The first line is the
modulus n as lowercase hex, zero-padded to the full byte width of the key.
The second line is the public exponent e or private exponent d with no padding.

This format follows the assignment spec (keys written in hexadecimal notation)
rather than PEM/DER from RFC 8017.
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
    """Return the number of hex characters needed to represent n at its byte boundary."""
    # Round bit length up to the nearest byte, then convert to hex digit count.
    return ((n.bit_length() + 7) // 8) * 2


def _read_two_hex_values(path: str | Path) -> tuple[int, int]:
    """Parse a key file and return its two hex-encoded integers as a pair.

    Raises ValueError if the file does not contain exactly two non-empty lines
    or if either line is not valid hexadecimal.
    """
    text = Path(path).read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 2:
        raise ValueError("malformed key file: expected exactly two non-empty lines")
    try:
        return int(lines[0], 16), int(lines[1], 16)
    except ValueError as exc:
        raise ValueError(f"invalid hex in key file: {exc}") from exc


def save_public_key(pub: PublicKey, path: str | Path) -> None:
    """Write a public key to a file in the two-line hex format.

    The modulus n is zero-padded to the full byte width of the key. The public
    exponent e is written without padding.
    """
    width = _hex_width(pub.n)
    Path(path).write_text(f"{pub.n:0{width}x}\n{pub.e:x}\n", encoding="utf-8")


def load_public_key(path: str | Path) -> PublicKey:
    """Read and return a public key from a file written by save_public_key."""
    n, e = _read_two_hex_values(path)
    return PublicKey(n=n, e=e)


def save_private_key(priv: PrivateKey, path: str | Path) -> None:
    """Write a private key to a file in the two-line hex format.

    The modulus n is zero-padded to the full byte width of the key. The private
    exponent d is written without padding.
    """
    width = _hex_width(priv.n)
    Path(path).write_text(f"{priv.n:0{width}x}\n{priv.d:x}\n", encoding="utf-8")


def load_private_key(path: str | Path) -> PrivateKey:
    """Read and return a private key from a file written by save_private_key."""
    n, d = _read_two_hex_values(path)
    return PrivateKey(n=n, d=d)
