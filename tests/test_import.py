"""Smoke test verifying the rsa_oaep package can be imported."""

import rsa_oaep


def test_package_imports():
    """Verify that the package exposes an __all__ attribute after import."""
    assert hasattr(rsa_oaep, "__all__")
