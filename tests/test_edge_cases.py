"""
Automated unit tests for Week 3 edge cases, Point at Infinity, and boundary values.
"""

import pytest
from src.config import G
from src.encoding import encode_temperature
from src.elgamal import generate_keypair, encrypt, decrypt_point, is_infinity
from src.aggregation import (
    aggregate_ciphertexts,
    decrypt_aggregate_point,
    apply_interval_shift,
    handle_infinity_edge_case,
    verify_candidate_sum,
)


class TestPointAtInfinityEdgeCases:
    """Tests the Point at Infinity O edge cases and minimum-bound telemetry."""

    @pytest.fixture
    def keypair(self):
        return generate_keypair()

    def test_single_sensor_minimum_boundary(self, keypair):
        priv, pub = keypair
        # 1 sensor reporting -40.0°C (M=100)
        ct = encrypt(encode_temperature(-40.0), pub)
        p_dec = decrypt_point(ct, priv)
        p_shifted = apply_interval_shift(p_dec, n_sensors=1)

        # 100*G - 100*G = O
        assert is_infinity(p_shifted)
        hit, rec_sum, rec_avg = handle_infinity_edge_case(p_shifted, n_sensors=1)
        assert hit is True
        assert rec_sum == 100
        assert rec_avg == -40.0
        assert verify_candidate_sum(p_shifted, candidate_m_sum=100, n_sensors=1) is True

    @pytest.mark.parametrize("n_sensors", [2, 5, 10])
    def test_multi_sensor_all_minimum_boundary(self, keypair, n_sensors):
        priv, pub = keypair
        ciphertexts = [encrypt(encode_temperature(-40.0), pub) for _ in range(n_sensors)]
        agg = aggregate_ciphertexts(ciphertexts)
        p_dec = decrypt_aggregate_point(agg, priv)
        p_shifted = apply_interval_shift(p_dec, n_sensors=n_sensors)

        # (100 * N) * G - (100 * N) * G = O
        assert is_infinity(p_shifted)
        hit, rec_sum, rec_avg = handle_infinity_edge_case(p_shifted, n_sensors)
        assert hit is True
        assert rec_sum == 100 * n_sensors
        assert rec_avg == -40.0
        assert verify_candidate_sum(p_shifted, candidate_m_sum=100 * n_sensors, n_sensors=n_sensors) is True

    def test_all_maximum_boundary_80_degrees(self, keypair):
        priv, pub = keypair
        n_sensors = 5
        ciphertexts = [encrypt(encode_temperature(80.0), pub) for _ in range(n_sensors)]
        agg = aggregate_ciphertexts(ciphertexts)
        p_dec = decrypt_aggregate_point(agg, priv)
        p_shifted = apply_interval_shift(p_dec, n_sensors=n_sensors)

        # Max sum = 1300 * 5 = 6500. Shifted scalar = 6500 - 500 = 6000 = 1200 * 5
        expected_k = 1200 * n_sensors
        expected_point = expected_k * G
        assert not is_infinity(p_shifted)
        assert p_shifted == expected_point
        assert verify_candidate_sum(p_shifted, candidate_m_sum=1300 * n_sensors, n_sensors=n_sensors) is True

    def test_mixed_boundary_conditions(self, keypair):
        priv, pub = keypair
        # 2 sensors at -40°C (M=100 each) and 2 sensors at 80°C (M=1300 each)
        # Total M_sum = 200 + 2600 = 2800. N = 4.
        temps = [-40.0, -40.0, 80.0, 80.0]
        ciphertexts = [encrypt(encode_temperature(t), pub) for t in temps]
        agg = aggregate_ciphertexts(ciphertexts)
        p_dec = decrypt_aggregate_point(agg, priv)
        p_shifted = apply_interval_shift(p_dec, n_sensors=4)

        # Shifted scalar = 2800 - (100 * 4) = 2400
        expected_point = 2400 * G
        assert not is_infinity(p_shifted)
        assert p_shifted == expected_point
        assert verify_candidate_sum(p_shifted, candidate_m_sum=2800, n_sensors=4) is True

    def test_invalid_interval_shift_parameters(self, keypair):
        priv, pub = keypair
        ct = encrypt(500, pub)
        p_dec = decrypt_point(ct, priv)

        with pytest.raises(ValueError):
            apply_interval_shift(p_dec, n_sensors=0)
        with pytest.raises(ValueError):
            apply_interval_shift(p_dec, n_sensors=-1)
