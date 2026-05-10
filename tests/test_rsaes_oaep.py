"""Tests for RSAES-OAEP encrypt and decrypt with block chunking."""

import secrets

import pytest

from rsa_oaep.rsa import generate_keypair
from rsa_oaep.rsaes_oaep import decrypt, encrypt


K = 256  # 2048-bit modulus = 256 bytes
MAX_BLOCK = 190


@pytest.fixture(scope="module")
def keypair():
    """Generate a 2048-bit keypair shared across all tests in this module."""
    return generate_keypair(bits=2048)


# Roundtrip

@pytest.mark.parametrize("size", [0, 1, MAX_BLOCK - 1, MAX_BLOCK, MAX_BLOCK + 1, 1024])
def test_roundtrip_random_sizes(keypair, size):
    """Verify that random plaintext of various sizes survives an encrypt/decrypt roundtrip."""
    pub, priv = keypair
    pt = secrets.token_bytes(size)
    ct = encrypt(pt, pub)
    assert len(ct) % K == 0
    assert decrypt(ct, priv) == pt


def test_roundtrip_known_pattern(keypair):
    """Verify that a short plaintext containing null bytes survives a roundtrip."""
    pub, priv = keypair
    pt = b"hello world\x00\x01\x02"
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_all_zero_bytes(keypair):
    """Verify that a buffer of all zero bytes survives a roundtrip."""
    pub, priv = keypair
    pt = b"\x00" * 500
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_all_ff_bytes(keypair):
    """Verify that a buffer of all 0xFF bytes survives a roundtrip."""
    pub, priv = keypair
    pt = b"\xff" * 500
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_large(keypair):
    """Verify that a 50 KB plaintext (roughly 270 blocks) survives a roundtrip."""
    pub, priv = keypair
    pt = secrets.token_bytes(50 * 1024)
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_block_boundaries(keypair):
    """Verify that plaintexts that are exact multiples of the block size produce the correct ciphertext length."""
    pub, priv = keypair
    for size in (MAX_BLOCK, 2 * MAX_BLOCK, 3 * MAX_BLOCK):
        pt = secrets.token_bytes(size)
        ct = encrypt(pt, pub)
        assert len(ct) == (size // MAX_BLOCK) * K
        assert decrypt(ct, priv) == pt


def test_block_count(keypair):
    """Verify that the ciphertext length reflects the number of OAEP blocks used."""
    pub, priv = keypair
    # 191 bytes needs two blocks (190 in the first, 1 in the second).
    assert len(encrypt(secrets.token_bytes(191), pub)) == 2 * K
    # exactly 190 bytes fits in one block.
    assert len(encrypt(secrets.token_bytes(190), pub)) == K


def test_two_encrypts_differ(keypair):
    """Verify that encrypting the same message twice produces different ciphertexts due to the random seed."""
    pub, _ = keypair
    pt = b"same message"
    assert encrypt(pt, pub) != encrypt(pt, pub)


# Error cases

def test_decrypt_rejects_empty(keypair):
    """Verify that an empty ciphertext raises ValueError."""
    _, priv = keypair
    with pytest.raises(ValueError):
        decrypt(b"", priv)


def test_decrypt_rejects_non_multiple_length(keypair):
    """Verify that a ciphertext whose length is not a multiple of the block size raises ValueError."""
    _, priv = keypair
    with pytest.raises(ValueError):
        decrypt(b"\x00" * (K - 1), priv)
    with pytest.raises(ValueError):
        decrypt(b"\x00" * (K + 1), priv)


def test_decrypt_tampered_block_fails(keypair):
    """Verify that a single flipped bit in the ciphertext causes decryption to fail."""
    pub, priv = keypair
    ct = bytearray(encrypt(b"secret message that fits in one block", pub))
    ct[100] ^= 0x01
    with pytest.raises(ValueError):
        decrypt(bytes(ct), priv)
