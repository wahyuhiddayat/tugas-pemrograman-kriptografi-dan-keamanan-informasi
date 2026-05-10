"""Tests for RSA primitives: I2OSP, OS2IP, keypair generation, and RSAEP/RSADP."""

import secrets

import pytest

from rsa_oaep.rsa import (
    PrivateKey,
    PublicKey,
    generate_keypair,
    i2osp,
    os2ip,
    rsadp,
    rsaep,
)


# I2OSP / OS2IP

@pytest.mark.parametrize(
    "x, x_len",
    [
        (0, 1),
        (1, 1),
        (255, 1),
        (256, 2),
        (65535, 2),
        (1, 4),
        (0xDEADBEEF, 4),
        (0, 256),
        ((1 << 2047), 256),
    ],
)
def test_i2osp_os2ip_roundtrip(x, x_len):
    """Verify that converting an integer to bytes and back recovers the original value."""
    encoded = i2osp(x, x_len)
    assert len(encoded) == x_len
    assert os2ip(encoded) == x


def test_i2osp_overflow():
    """Verify that i2osp raises ValueError when the integer does not fit in the requested byte length."""
    with pytest.raises(ValueError):
        i2osp(256, 1)
    with pytest.raises(ValueError):
        i2osp(1 << 16, 2)


def test_i2osp_negative():
    """Verify that i2osp raises ValueError for negative integers."""
    with pytest.raises(ValueError):
        i2osp(-1, 1)


def test_os2ip_empty():
    """Verify that an empty byte string converts to zero."""
    assert os2ip(b"") == 0


# Keypair

@pytest.fixture(scope="module")
def keypair_2048():
    """Generate a 2048-bit keypair shared across all tests in this module."""
    return generate_keypair(bits=2048, e=65537)


def test_generate_keypair_modulus_size(keypair_2048):
    """Verify that the generated modulus is 2048 bits and the public exponent is 65537."""
    pub, priv = keypair_2048
    assert pub.n.bit_length() == 2048
    assert priv.n == pub.n
    assert pub.e == 65537


def test_generate_keypair_rejects_odd_bits():
    """Verify that an odd bit count raises ValueError."""
    with pytest.raises(ValueError):
        generate_keypair(bits=2047)


def test_generate_keypair_rejects_tiny_bits():
    """Verify that a bit count below the minimum raises ValueError."""
    with pytest.raises(ValueError):
        generate_keypair(bits=8)


def test_generate_keypair_small_modulus_works():
    """Verify that key generation succeeds for a smaller 512-bit modulus."""
    pub, _ = generate_keypair(bits=512)
    assert pub.n.bit_length() == 512


# RSAEP / RSADP roundtrip

def test_rsa_primitive_roundtrip_random_messages(keypair_2048):
    """Verify that encrypting and decrypting random messages recovers the originals."""
    pub, priv = keypair_2048
    for _ in range(5):
        m = 1 + secrets.randbelow(pub.n - 1)
        c = rsaep(pub, m)
        assert rsadp(priv, c) == m


def test_rsa_primitive_roundtrip_boundary_messages(keypair_2048):
    """Verify that boundary message values (0, 1, and n-1) survive a roundtrip."""
    pub, priv = keypair_2048
    for m in (0, 1, 2, pub.n - 1):
        c = rsaep(pub, m)
        assert rsadp(priv, c) == m


def test_rsaep_rejects_out_of_range(keypair_2048):
    """Verify that rsaep raises ValueError for message representatives outside [0, n)."""
    pub, _ = keypair_2048
    with pytest.raises(ValueError):
        rsaep(pub, pub.n)
    with pytest.raises(ValueError):
        rsaep(pub, -1)


def test_rsadp_rejects_out_of_range(keypair_2048):
    """Verify that rsadp raises ValueError for ciphertext representatives outside [0, n)."""
    _, priv = keypair_2048
    with pytest.raises(ValueError):
        rsadp(priv, priv.n)
    with pytest.raises(ValueError):
        rsadp(priv, -1)
