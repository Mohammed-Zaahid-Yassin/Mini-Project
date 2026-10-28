"""
Automated unit tests for EC Lifted ElGamal key generation, encryption, and point unmasking.
"""

import pytest
from fastecdsa.curve import P256
from fastecdsa.point import Point
from src.config import G, CURVE_ORDER, POINT_SEC1_BYTES, POINT_INFINITY_BYTES
from src.encoding import encode_temperature
from src.elgamal import (
    generate_keypair,
    validate_keypair,
    encrypt,
    decrypt_point,
    point_to_bytes,
    bytes_to_point,
    is_infinity,
    is_point_on_curve,
    Ciphertext,
)


class TestKeyGeneration:
    """Tests P-256 keypair generation."""

    def test_keypair_validity(self):
        priv, pub = generate_keypair()
        assert 1 <= priv < CURVE_ORDER
        assert isinstance(pub, Point)
        assert is_point_on_curve(pub)
        assert not is_infinity(pub)
        assert validate_keypair(priv, pub)

    def test_keypair_algebraic_relationship(self):
        priv, pub = generate_keypair()
        assert (priv * G) == pub

    def test_keypair_randomness(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2


class TestPointSerialization:
    """Tests canonical 65-byte SEC1 serialization and deserialization."""

    def test_generator_roundtrip(self):
        raw = point_to_bytes(G)
        assert len(raw) == POINT_SEC1_BYTES
        assert raw[0] == 0x04
        rec = bytes_to_point(raw)
        assert rec == G

    def test_arbitrary_point_roundtrip(self):
        _, pub = generate_keypair()
        raw = point_to_bytes(pub)
        assert len(raw) == POINT_SEC1_BYTES
        assert raw[0] == 0x04
        rec = bytes_to_point(raw)
        assert rec == pub

    def test_point_at_infinity_serialization(self):
        inf = 0 * G
        raw = point_to_bytes(inf)
        assert len(raw) == POINT_SEC1_BYTES
        assert raw == POINT_INFINITY_BYTES
        rec = bytes_to_point(raw)
        assert is_infinity(rec)

    def test_invalid_point_deserialization(self):
        # Truncated byte sequence
        with pytest.raises(ValueError):
            bytes_to_point(b"\x04" + b"\x00" * 30)

        # Invalid prefix (not 0x04 or 0x00)
        with pytest.raises(ValueError):
            bytes_to_point(b"\x02" + b"\x01" * 64)

        # Coordinates not on P-256 curve
        invalid_coords = b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
        with pytest.raises(ValueError):
            bytes_to_point(invalid_coords)


class TestLiftedElGamalEncryption:
    """Tests encryption and point unmasking correctness."""

    def test_worked_example_23_5_degrees(self):
        priv, pub = generate_keypair()
        temp = 23.5
        m = encode_temperature(temp)  # 735
        ct = encrypt(m, pub)

        assert isinstance(ct, Ciphertext)
        assert is_point_on_curve(ct.c1)
        assert is_point_on_curve(ct.c2)

        # Verify decrypted point P = C2 - x*C1 == M * G
        p_dec = decrypt_point(ct, priv)
        expected_point = m * G
        assert p_dec == expected_point

    def test_ephemeral_scalar_randomness(self):
        # Encrypting the identical plaintext twice must produce distinct ciphertexts
        _, pub = generate_keypair()
        m = 735
        ct1 = encrypt(m, pub)
        ct2 = encrypt(m, pub)

        assert ct1.c1 != ct2.c1
        assert ct1.c2 != ct2.c2

    def test_ciphertext_serialization(self):
        _, pub = generate_keypair()
        ct = encrypt(500, pub)
        ct_bytes = ct.to_bytes()
        assert len(ct_bytes) == 130
        rec_ct = Ciphertext.from_bytes(ct_bytes)
        assert rec_ct.c1 == ct.c1
        assert rec_ct.c2 == ct.c2

    def test_invalid_encryption_inputs(self):
        _, pub = generate_keypair()
        with pytest.raises(TypeError):
            encrypt("735", pub)  # type: ignore
        with pytest.raises(TypeError):
            encrypt(True, pub)   # bool not allowed

        # Infinity cannot be used as public key
        inf = 0 * G
        with pytest.raises(ValueError):
            encrypt(735, inf)
