"""Tests for MGF1 and EME-OAEP encode/decode."""

import secrets

import pytest

from rsa_oaep.oaep import HASH_LEN, eme_oaep_decode, eme_oaep_encode, mgf1


K = 256  # 2048-bit modulus = 256 bytes
MAX_MSG = K - 2 * HASH_LEN - 2  # 190


# MGF1

@pytest.mark.parametrize("length", [1, 16, 32, 100, 256, 1000])
def test_mgf1_output_length(length):
    """Verify that mgf1 produces output of exactly the requested length."""
    assert len(mgf1(b"seed", length)) == length


def test_mgf1_deterministic():
    """Verify that mgf1 returns the same output for the same seed and length."""
    assert mgf1(b"hello", 64) == mgf1(b"hello", 64)


def test_mgf1_different_seeds_differ():
    """Verify that distinct seeds produce distinct mgf1 outputs."""
    assert mgf1(b"seed1", 64) != mgf1(b"seed2", 64)


def test_mgf1_zero_length():
    """Verify that requesting zero bytes returns an empty byte string."""
    assert mgf1(b"seed", 0) == b""


def test_mgf1_negative_length():
    """Verify that a negative mask length raises ValueError."""
    with pytest.raises(ValueError):
        mgf1(b"seed", -1)


# EME-OAEP roundtrip

@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"a",
        b"hello world",
        b"x" * MAX_MSG,
        secrets.token_bytes(100),
    ],
)
def test_eme_oaep_roundtrip(message):
    """Verify that encoding then decoding a message recovers the original."""
    em = eme_oaep_encode(message, K)
    assert len(em) == K
    assert em[0] == 0x00
    assert eme_oaep_decode(em, K) == message


def test_eme_oaep_roundtrip_with_label():
    """Verify that encoding with a label decodes correctly when the same label is provided."""
    label = b"my-label"
    msg = b"secret"
    em = eme_oaep_encode(msg, K, label=label)
    assert eme_oaep_decode(em, K, label=label) == msg


def test_eme_oaep_two_encodes_differ():
    """Verify that encoding the same message twice produces different output due to the random seed."""
    assert eme_oaep_encode(b"same", K) != eme_oaep_encode(b"same", K)


# Encode error cases

def test_encode_rejects_message_too_long():
    """Verify that encoding a message exceeding the maximum length raises ValueError."""
    with pytest.raises(ValueError):
        eme_oaep_encode(b"x" * (MAX_MSG + 1), K)


# Decode error cases

def test_decode_wrong_label_fails():
    """Verify that decoding with a mismatched label raises ValueError."""
    em = eme_oaep_encode(b"secret", K, label=b"correct")
    with pytest.raises(ValueError):
        eme_oaep_decode(em, K, label=b"wrong")


def test_decode_tampered_masked_db_fails():
    """Verify that a single flipped bit in the masked DB region causes decoding to fail."""
    em = bytearray(eme_oaep_encode(b"secret", K))
    em[100] ^= 0xFF
    with pytest.raises(ValueError):
        eme_oaep_decode(bytes(em), K)


def test_decode_tampered_y_byte_fails():
    """Verify that a non-zero leading byte causes decoding to fail."""
    em = bytearray(eme_oaep_encode(b"secret", K))
    em[0] = 0x42
    with pytest.raises(ValueError):
        eme_oaep_decode(bytes(em), K)


def test_decode_wrong_length_fails():
    """Verify that an encoded message buffer with the wrong length raises ValueError."""
    em = eme_oaep_encode(b"secret", K)
    with pytest.raises(ValueError):
        eme_oaep_decode(em + b"\x00", K)
    with pytest.raises(ValueError):
        eme_oaep_decode(em[:-1], K)
