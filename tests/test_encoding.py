"""
Automated unit tests for fixed-point temperature encoding and decoding.
"""

import math
import pytest
from src.config import TEMP_MIN, TEMP_MAX, M_MIN, M_MAX
from src.encoding import (
    round_away_from_zero,
    encode_temperature,
    decode_temperature,
    decode_temperature_sum,
)


class TestRoundAwayFromZero:
    """Tests C99 lroundf() equivalent rounding."""

    def test_positive_halfway_cases(self):
        # Ties must round away from zero
        assert round_away_from_zero(0.5) == 1
        assert round_away_from_zero(1.5) == 2
        assert round_away_from_zero(2.5) == 3
        assert round_away_from_zero(3.5) == 4
        assert round_away_from_zero(735.5) == 736

    def test_negative_halfway_cases(self):
        # Negative ties must round away from zero (towards -inf)
        assert round_away_from_zero(-0.5) == -1
        assert round_away_from_zero(-1.5) == -2
        assert round_away_from_zero(-2.5) == -3
        assert round_away_from_zero(-3.5) == -4

    def test_divergence_from_python_round(self):
        # Explicit proof that round_away_from_zero != built-in round() for even ties
        assert round_away_from_zero(2.5) == 3
        assert round(2.5) == 2  # Banker's rounding rounds to nearest even

        assert round_away_from_zero(-2.5) == -3
        assert round(-2.5) == -2  # Banker's rounding rounds to nearest even

    def test_non_halfway_cases(self):
        assert round_away_from_zero(2.1) == 2
        assert round_away_from_zero(2.9) == 3
        assert round_away_from_zero(-2.1) == -2
        assert round_away_from_zero(-2.9) == -3
        assert round_away_from_zero(0.0) == 0

    def test_invalid_types_and_values(self):
        with pytest.raises(TypeError):
            round_away_from_zero("2.5")  # type: ignore
        with pytest.raises(TypeError):
            round_away_from_zero(None)  # type: ignore
        with pytest.raises(ValueError):
            round_away_from_zero(float("nan"))
        with pytest.raises(ValueError):
            round_away_from_zero(float("inf"))


class TestTemperatureEncoding:
    """Tests temperature conversion to fixed-point integer scalars."""

    def test_boundary_values(self):
        # Minimum temperature: -40.0°C -> M = 100
        assert encode_temperature(-40.0) == 100
        # Maximum temperature: 80.0°C -> M = 1300
        assert encode_temperature(80.0) == 1300
        # Zero point: 0.0°C -> M = 500
        assert encode_temperature(0.0) == 500

    def test_worked_example_23_5(self):
        # Worked example from prompt: 23.5°C -> (23.5 + 50.0) * 10 = 735
        m = encode_temperature(23.5)
        assert m == 735
        t_rec = decode_temperature(m)
        assert t_rec == 23.5

    def test_sub_degree_rounding(self):
        # 23.55 -> (23.55 + 50.0) * 10 = 735.5 -> round away from zero -> 736
        assert encode_temperature(23.55) == 736
        assert decode_temperature(736) == 23.6

        # 23.54 -> (23.54 + 50.0) * 10 = 735.4 -> 735
        assert encode_temperature(23.54) == 735

    def test_out_of_range_temperatures(self):
        with pytest.raises(ValueError):
            encode_temperature(-40.01)
        with pytest.raises(ValueError):
            encode_temperature(-100.0)
        with pytest.raises(ValueError):
            encode_temperature(80.01)
        with pytest.raises(ValueError):
            encode_temperature(150.0)

    def test_invalid_input_types(self):
        with pytest.raises(TypeError):
            encode_temperature("23.5")  # type: ignore
        with pytest.raises(TypeError):
            encode_temperature(None)  # type: ignore
        with pytest.raises(ValueError):
            encode_temperature(float("nan"))
        with pytest.raises(ValueError):
            encode_temperature(float("inf"))

    def test_full_range_roundtrip_precision(self):
        # Test every 0.1°C step between -40.0°C and 80.0°C (1201 points)
        for step in range(-400, 801):
            temp = step / 10.0
            m = encode_temperature(temp)
            assert M_MIN <= m <= M_MAX
            temp_decoded = decode_temperature(m)
            assert temp_decoded == pytest.approx(temp, abs=1e-5)


class TestTemperatureDecoding:
    """Tests decoding integers back to physical temperatures."""

    def test_invalid_m_type(self):
        with pytest.raises(TypeError):
            decode_temperature(735.0)  # float not allowed
        with pytest.raises(TypeError):
            decode_temperature(True)   # bool is int subclass in Python

    def test_out_of_range_m(self):
        with pytest.raises(ValueError):
            decode_temperature(99)
        with pytest.raises(ValueError):
            decode_temperature(1301)

    def test_decode_temperature_sum(self):
        # 3 sensors reporting 20.0°C (M=700), sum = 2100
        # Expected temp sum = 60.0°C
        temp_sum = decode_temperature_sum(2100, n_sensors=3)
        assert temp_sum == 60.0

        # Boundary checks
        with pytest.raises(ValueError):
            decode_temperature_sum(2100, n_sensors=0)
        with pytest.raises(ValueError):
            decode_temperature_sum(200, n_sensors=3)  # Min for 3 sensors is 300
