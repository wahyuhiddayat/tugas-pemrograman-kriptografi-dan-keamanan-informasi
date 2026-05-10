import secrets

import pytest

from rsa_oaep.rsa import generate_keypair
from rsa_oaep.rsaes_oaep import decrypt, encrypt


K = 256  # 2048-bit modulus = 256 bytes
MAX_BLOCK = 190


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(bits=2048)


# Roundtrip

@pytest.mark.parametrize("size", [0, 1, MAX_BLOCK - 1, MAX_BLOCK, MAX_BLOCK + 1, 1024])
def test_roundtrip_random_sizes(keypair, size):
    pub, priv = keypair
    pt = secrets.token_bytes(size)
    ct = encrypt(pt, pub)
    assert len(ct) % K == 0
    assert decrypt(ct, priv) == pt


def test_roundtrip_known_pattern(keypair):
    pub, priv = keypair
    pt = b"hello world\x00\x01\x02"
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_all_zero_bytes(keypair):
    pub, priv = keypair
    pt = b"\x00" * 500
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_all_ff_bytes(keypair):
    pub, priv = keypair
    pt = b"\xff" * 500
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_large(keypair):
    # 50 KB = ~270 blocks; mostly stresses decrypt modexp with big d.
    pub, priv = keypair
    pt = secrets.token_bytes(50 * 1024)
    assert decrypt(encrypt(pt, pub), priv) == pt


def test_roundtrip_block_boundaries(keypair):
    pub, priv = keypair
    for size in (MAX_BLOCK, 2 * MAX_BLOCK, 3 * MAX_BLOCK):
        pt = secrets.token_bytes(size)
        ct = encrypt(pt, pub)
        assert len(ct) == (size // MAX_BLOCK) * K
        assert decrypt(ct, priv) == pt


def test_block_count(keypair):
    pub, priv = keypair
    # 191 bytes -> 2 blocks (190 + 1)
    assert len(encrypt(secrets.token_bytes(191), pub)) == 2 * K
    # exactly 190 -> 1 block
    assert len(encrypt(secrets.token_bytes(190), pub)) == K


def test_two_encrypts_differ(keypair):
    pub, _ = keypair
    pt = b"same message"
    assert encrypt(pt, pub) != encrypt(pt, pub)


# Error cases

def test_decrypt_rejects_empty(keypair):
    _, priv = keypair
    with pytest.raises(ValueError):
        decrypt(b"", priv)


def test_decrypt_rejects_non_multiple_length(keypair):
    _, priv = keypair
    with pytest.raises(ValueError):
        decrypt(b"\x00" * (K - 1), priv)
    with pytest.raises(ValueError):
        decrypt(b"\x00" * (K + 1), priv)


def test_decrypt_tampered_block_fails(keypair):
    pub, priv = keypair
    ct = bytearray(encrypt(b"secret message that fits in one block", pub))
    ct[100] ^= 0x01
    with pytest.raises(ValueError):
        decrypt(bytes(ct), priv)
