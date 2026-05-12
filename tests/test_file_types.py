"""
tests/test_file_types.py
========================
Automated roundtrip test: encrypt → decrypt → byte-by-byte comparison
for multiple file types: .txt, .png, .jpg, .mp3, .mp4, .pdf, binary.

Run from the project root:
    python -m pytest tests/test_file_types.py -v
or standalone:
    python tests/test_file_types.py
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.rsa_oaep.key_io import load_private_key, load_public_key, save_private_key, save_public_key
from src.rsa_oaep.rsa import generate_keypair
from src.rsa_oaep.rsaes_oaep import decrypt, encrypt


# Sample file generators
def _make_txt(path: Path, size: int = 4096):
    """Plain-text file (ASCII + unicode)."""
    chunk = (
        "Ini adalah file teks untuk testing RSA-OAEP-256.\n"
        "This line contains some Unicode: ñ, é, ü, 中文, العربية.\n"
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
    )
    content = (chunk * ((size // len(chunk)) + 1))[:size]
    path.write_text(content, encoding="utf-8")


def _make_png(path: Path):
    """Minimal valid 8×8 red PNG (no external library needed)."""
    def _chunk(name: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + name + data
        return c + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)          # 8×8 RGB
    raw_rows = b"".join(b"\x00" + b"\xff\x00\x00" * 8 for _ in range(8))  # red pixels
    idat = zlib.compress(raw_rows)

    data = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )
    path.write_bytes(data)


def _make_jpg(path: Path):
    """Minimal valid JPEG (SOI + APP0 + SOF0 stub + EOI).
    Not a viewable image but valid enough for binary roundtrip testing."""
    # Minimal JPEG header bytes (SOI marker only + EOI), good enough for binary test
    data = bytes([
        0xFF, 0xD8,                     # SOI
        0xFF, 0xE0, 0x00, 0x10,         # APP0 marker + length (16)
        0x4A, 0x46, 0x49, 0x46, 0x00,  # "JFIF\0"
        0x01, 0x01,                     # version 1.1
        0x00,                           # aspect ratio units = 0
        0x00, 0x01, 0x00, 0x01,         # Xdensity, Ydensity
        0x00, 0x00,                     # thumbnail size 0×0
        0xFF, 0xD9,                     # EOI
    ])
    path.write_bytes(data)


def _make_binary(path: Path, size: int = 8192):
    """Generic binary file with all 256 byte values."""
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    path.write_bytes(data)


def _make_mp3(path: Path):
    """Minimal MP3 stub (ID3v2 header + silence frame)."""
    # ID3v2.3 header (10 bytes) + some zero-filled content
    id3 = b"ID3" + bytes([3, 0, 0]) + struct.pack(">I", 0)   # 10 bytes, size=0
    # Fake MPEG frame header: sync + MPEG1 + Layer3 + 128kbps + 44.1kHz + stereo
    mp3_frame = bytes([0xFF, 0xFB, 0x90, 0x00]) + b"\x00" * 413  # minimal frame
    path.write_bytes(id3 + mp3_frame * 4)


def _make_pdf(path: Path):
    """Minimal valid PDF stub."""
    content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj

2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj

3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj

xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n

trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
"""
    path.write_bytes(content)


def _make_mp4(path: Path):
    """Minimal MP4 stub (ftyp + mdat box) — valid enough for binary roundtrip testing."""
    # ftyp box: size(4) + 'ftyp'(4) + major_brand 'mp42'(4) + minor_version(4) + compatible 'mp42'(4)
    ftyp = struct.pack(">I", 20) + b"ftyp" + b"mp42" + struct.pack(">I", 0) + b"mp42"
    # mdat box: size(4) + 'mdat'(4) + some zero bytes as fake media data
    mdat_data = b"\x00" * 256
    mdat = struct.pack(">I", 8 + len(mdat_data)) + b"mdat" + mdat_data
    path.write_bytes(ftyp + mdat)


def _make_large_txt(path: Path, size_mb: float = 0.5):
    """Larger text file to exercise multi-block chunking."""
    size = int(size_mb * 1024 * 1024)
    chunk = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 RSA-OAEP-256 multi-block test.\n"
    content = (chunk * (size // len(chunk) + 1))[:size]
    path.write_bytes(content)


# Test harness
SAMPLE_FACTORIES = {
    "txt":        (_make_txt,    ".txt"),
    "png":        (_make_png,    ".png"),
    "jpg":        (_make_jpg,    ".jpg"),
    "binary":     (_make_binary, ".bin"),
    "mp3":        (_make_mp3,    ".mp3"),
    "mp4":        (_make_mp4,    ".mp4"),
    "pdf":        (_make_pdf,    ".pdf"),
    "large_txt":  (_make_large_txt, ".txt"),
}

PASS  = "✅ PASS"
FAIL  = "❌ FAIL"
SEP   = "─" * 64


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_tests():
    print(SEP)
    print("  RSA-OAEP-256  ·  Multi-file roundtrip test")
    print(SEP)

    results = []

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Generate a single keypair for all tests
        print("\n  Generating 2048-bit RSA keypair…", end=" ", flush=True)
        t0 = time.perf_counter()
        pub, priv = generate_keypair(bits=2048)
        elapsed = time.perf_counter() - t0
        pub_path  = tmp_path / "test_public.key"
        priv_path = tmp_path / "test_private.key"
        save_public_key(pub, pub_path)
        save_private_key(priv, priv_path)
        pub  = load_public_key(pub_path)
        priv = load_private_key(priv_path)
        print(f"done ({elapsed:.2f}s)\n")

        for name, (factory, ext) in SAMPLE_FACTORIES.items():
            plain_path = tmp_path / f"sample_{name}{ext}"
            enc_path   = tmp_path / f"sample_{name}.enc"
            dec_path   = tmp_path / f"sample_{name}_dec{ext}"

            # Create sample
            factory(plain_path)
            original = plain_path.read_bytes()

            print(f"  [{name:12s}]  {len(original):>9,} bytes  ", end="", flush=True)

            try:
                # Encrypt
                t0 = time.perf_counter()
                ciphertext = encrypt(original, pub)
                enc_path.write_bytes(ciphertext)

                # Decrypt
                ciphertext2 = enc_path.read_bytes()
                recovered   = decrypt(ciphertext2, priv)
                dec_path.write_bytes(recovered)

                elapsed = time.perf_counter() - t0

                # Compare
                if recovered == original:
                    sha = _sha256(original)[:16]
                    print(f"{PASS}  ({elapsed:.2f}s)  SHA256[:16]={sha}")
                    results.append((name, True, None))
                else:
                    print(f"{FAIL}  SHA256 mismatch!")
                    print(f"             original : {_sha256(original)}")
                    print(f"             recovered: {_sha256(recovered)}")
                    results.append((name, False, "hash mismatch"))

            except Exception as exc:
                print(f"{FAIL}  Exception: {exc}")
                results.append((name, False, str(exc)))

    # Summary
    print(f"\n{SEP}")
    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    print(f"  Results: {passed}/{total} passed")
    print(SEP)

    if passed < total:
        print("\n  Failed tests:")
        for name, ok, reason in results:
            if not ok:
                print(f"    • {name}: {reason}")
        sys.exit(1)
    else:
        print("\n  All tests passed! 🎉")


# pytest integration
import pytest

@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("keys")
    pub, priv = generate_keypair(bits=2048)
    save_public_key(pub,  tmp / "pub.key")
    save_private_key(priv, tmp / "priv.key")
    pub  = load_public_key(tmp / "pub.key")
    priv = load_private_key(tmp / "priv.key")
    return pub, priv


@pytest.mark.parametrize("name,factory_ext", list(SAMPLE_FACTORIES.items()))
def test_roundtrip(tmp_path, keypair, name, factory_ext):
    factory, ext = factory_ext
    pub, priv = keypair

    plain_path = tmp_path / f"sample{ext}"
    factory(plain_path)
    original = plain_path.read_bytes()

    ciphertext = encrypt(original, pub)
    recovered  = decrypt(ciphertext, priv)

    assert recovered == original, (
        f"Roundtrip failed for {name}: "
        f"SHA256 original={_sha256(original)[:16]} recovered={_sha256(recovered)[:16]}"
    )


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_tests()