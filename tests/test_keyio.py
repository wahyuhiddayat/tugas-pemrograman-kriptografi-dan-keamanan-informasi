import pytest

from rsa_oaep.keyio import (
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from rsa_oaep.rsa import PrivateKey, PublicKey, generate_keypair


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(bits=2048)


# Roundtrip

def test_public_key_roundtrip(tmp_path, keypair):
    pub, _ = keypair
    path = tmp_path / "key.pub"
    save_public_key(pub, path)
    assert load_public_key(path) == pub


def test_private_key_roundtrip(tmp_path, keypair):
    _, priv = keypair
    path = tmp_path / "key.priv"
    save_private_key(priv, path)
    assert load_private_key(path) == priv


# File format

def test_public_key_file_format(tmp_path, keypair):
    pub, _ = keypair
    path = tmp_path / "key.pub"
    save_public_key(pub, path)
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert len(lines[0]) == 512  # n padded to 2048-bit / 4 hex chars
    assert all(c in "0123456789abcdef" for c in lines[0])
    assert lines[1] == "10001"  # e = 65537


def test_private_key_file_format(tmp_path, keypair):
    _, priv = keypair
    path = tmp_path / "key.priv"
    save_private_key(priv, path)
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert len(lines[0]) == 512
    assert all(c in "0123456789abcdef" for c in lines[0])
    assert all(c in "0123456789abcdef" for c in lines[1])


# Error cases

def test_load_rejects_one_line(tmp_path):
    path = tmp_path / "bad.pub"
    path.write_text("abcdef\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_public_key(path)


def test_load_rejects_invalid_hex(tmp_path):
    path = tmp_path / "bad.pub"
    path.write_text("notahex\n10001\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_public_key(path)


def test_load_tolerates_trailing_blank_lines(tmp_path):
    path = tmp_path / "ok.pub"
    path.write_text("ff\n10001\n\n  \n", encoding="utf-8")
    pub = load_public_key(path)
    assert pub.n == 0xFF
    assert pub.e == 0x10001


def test_load_rejects_empty_file(tmp_path):
    path = tmp_path / "empty.pub"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        load_public_key(path)
