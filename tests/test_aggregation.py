"""
Automated unit tests for homomorphic ciphertext aggregation and interval shifting.
"""

import pytest
from src.config import G
from src.encoding import encode_temperature
from src.elgamal import generate_keypair, encrypt, decrypt_point, Ciphertext
from src.aggregation import (
    aggregate_ciphertexts,
    decrypt_aggregate_point,
    apply_interval_shift,
    verify_candidate_sum,
)


class TestHomomorphicAggregation:
    """Tests additive homomorphic aggregation of EC ciphertexts."""

    @pytest.fixture
    def keypair(self):
        return generate_keypair()

    def test_single_ciphertext_aggregation(self, keypair):
        priv, pub = keypair
        m = 735
        ct = encrypt(m, pub)
        agg = aggregate_ciphertexts([ct])
        assert agg.c1 == ct.c1
        assert agg.c2 == ct.c2

        p_dec = decrypt_aggregate_point(agg, priv)
        assert p_dec == (m * G)

    def test_multi_sensor_aggregation(self, keypair):
        priv, pub = keypair
        temperatures = [15.0, 20.0, 25.0, 30.0]
        encoded = [encode_temperature(t) for t in temperatures]
        ciphertexts = [encrypt(m, pub) for m in encoded]

        agg = aggregate_ciphertexts(ciphertexts)
        p_dec = decrypt_aggregate_point(agg, priv)

        expected_sum = sum(encoded)
        assert p_dec == (expected_sum * G)

    def test_empty_sequence_raises(self):
        with pytest.raises(ValueError):
            aggregate_ciphertexts([])

    def test_invalid_type_raises(self, keypair):
        _, pub = keypair
        ct = encrypt(500, pub)
        with pytest.raises(TypeError):
            aggregate_ciphertexts([ct, "invalid_ct"])  # type: ignore


class TestIntervalShifting:
    """Tests interval shifting and candidate verification."""

    @pytest.fixture
    def keypair(self):
        return generate_keypair()

    def test_interval_shift_correctness(self, keypair):
        priv, pub = keypair
        # 3 sensors reporting 0.0°C (M=500 each, sum=1500)
        ciphertexts = [encrypt(500, pub) for _ in range(3)]
        agg = aggregate_ciphertexts(ciphertexts)
        p_dec = decrypt_aggregate_point(agg, priv)

        n_sensors = 3
        p_shifted = apply_interval_shift(p_dec, n_sensors)

        # Expected shifted point: (1500 - 100 * 3) * G = 1200 * G
        expected_k = 1500 - (100 * n_sensors)
        assert p_shifted == (expected_k * G)

    def test_verify_candidate_sum(self, keypair):
        priv, pub = keypair
        temps = [21.0, 23.0, 26.0]
        encoded = [encode_temperature(t) for t in temps]
        ciphertexts = [encrypt(m, pub) for m in encoded]
        agg = aggregate_ciphertexts(ciphertexts)

        p_dec = decrypt_aggregate_point(agg, priv)
        p_shifted = apply_interval_shift(p_dec, len(temps))

        actual_m_sum = sum(encoded)
        assert verify_candidate_sum(p_shifted, actual_m_sum, len(temps)) is True

        # Incorrect candidate should be rejected
        assert verify_candidate_sum(p_shifted, actual_m_sum + 1, len(temps)) is False
        assert verify_candidate_sum(p_shifted, actual_m_sum - 1, len(temps)) is False
