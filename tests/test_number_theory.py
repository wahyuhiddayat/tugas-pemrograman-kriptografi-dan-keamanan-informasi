import pytest

from rsa_oaep.number_theory import egcd, generate_prime, is_probable_prime, modinv


KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97, 101, 7919, 104729]
KNOWN_COMPOSITES = [4, 6, 8, 9, 15, 21, 25, 100, 1024, 9999]
# Carmichael numbers — fool naive Fermat tests but Miller-Rabin must reject them.
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601]


def test_is_prime_known_primes():
    for p in KNOWN_PRIMES:
        assert is_probable_prime(p), p


def test_is_prime_known_composites():
    for c in KNOWN_COMPOSITES:
        assert not is_probable_prime(c), c


def test_is_prime_rejects_carmichael_numbers():
    for c in CARMICHAEL:
        assert not is_probable_prime(c), c


def test_is_prime_rejects_small_invalid_inputs():
    assert not is_probable_prime(0)
    assert not is_probable_prime(1)
    assert not is_probable_prime(-7)


def test_is_prime_large_mersenne():
    # 2**521 - 1 is a known Mersenne prime (M13).
    assert is_probable_prime(2**521 - 1)


@pytest.mark.parametrize("bits", [256, 512, 1024])
def test_generate_prime_bit_length(bits):
    p = generate_prime(bits)
    assert p.bit_length() == bits
    assert is_probable_prime(p)


def test_generate_prime_two_runs_differ():
    assert generate_prime(512) != generate_prime(512)


def test_generate_prime_rejects_tiny_bits():
    with pytest.raises(ValueError):
        generate_prime(1)


def test_egcd_basic():
    g, x, y = egcd(30, 18)
    assert g == 6
    assert 30 * x + 18 * y == g


def test_egcd_coprime():
    g, x, y = egcd(17, 31)
    assert g == 1
    assert 17 * x + 31 * y == 1


def test_egcd_with_zero():
    assert egcd(0, 5) == (5, 0, 1)
    assert egcd(7, 0)[0] == 7


@pytest.mark.parametrize("a, m", [(3, 7), (17, 31), (65537, 1000003), (2, 9)])
def test_modinv_roundtrip(a, m):
    inv = modinv(a, m)
    assert (a * inv) % m == 1


def test_modinv_no_inverse_when_not_coprime():
    with pytest.raises(ValueError):
        modinv(6, 9)
