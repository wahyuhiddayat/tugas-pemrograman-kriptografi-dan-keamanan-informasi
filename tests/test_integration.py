"""End-to-end tests covering key generation, disk I/O, and encrypt/decrypt cycles."""

import secrets

import pytest

from rsa_oaep.key_io import (
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from rsa_oaep.rsa import generate_keypair
from rsa_oaep.rsaes_oaep import decrypt, encrypt


@pytest.fixture(scope="module")
def keypair():
    """Generate a 2048-bit keypair shared across all tests in this module."""
    return generate_keypair(bits=2048)


@pytest.mark.parametrize("size", [5, 1024, 10 * 1024])
def test_full_pipeline_with_disk_io(tmp_path, keypair, size):
    """Verify that saving keys to disk and reloading them preserves encrypt/decrypt correctness."""
    pub, priv = keypair
    pub_path = tmp_path / "rsa.pub"
    priv_path = tmp_path / "rsa.priv"
    save_public_key(pub, pub_path)
    save_private_key(priv, priv_path)

    plaintext = secrets.token_bytes(size)
    pt_path = tmp_path / "plain.bin"
    pt_path.write_bytes(plaintext)

    pub_loaded = load_public_key(pub_path)
    ciphertext = encrypt(pt_path.read_bytes(), pub_loaded)
    ct_path = tmp_path / "cipher.bin"
    ct_path.write_bytes(ciphertext)

    priv_loaded = load_private_key(priv_path)
    decrypted = decrypt(ct_path.read_bytes(), priv_loaded)

    assert decrypted == plaintext


@pytest.mark.parametrize(
    "pattern",
    [
        b"\x00" * 200,
        b"\xff" * 200,
        b"hello world\n" * 50,
        bytes(range(256)) * 4,
    ],
)
def test_byte_patterns_roundtrip(keypair, pattern):
    """Verify that structured and edge-case byte patterns survive an encrypt/decrypt roundtrip."""
    pub, priv = keypair
    assert decrypt(encrypt(pattern, pub), priv) == pattern


def test_keyfile_persistence_across_runs(tmp_path, keypair):
    """Verify that a key pair saved then reloaded in separate steps still encrypts and decrypts correctly."""
    pub, priv = keypair
    pub_path = tmp_path / "rsa.pub"
    priv_path = tmp_path / "rsa.priv"
    save_public_key(pub, pub_path)
    save_private_key(priv, priv_path)

    msg = b"persistence check"
    ciphertext = encrypt(msg, load_public_key(pub_path))
    assert decrypt(ciphertext, load_private_key(priv_path)) == msg
