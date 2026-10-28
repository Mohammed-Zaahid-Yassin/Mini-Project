"""
Fixed-point temperature encoding and decoding module.
Implements C99 lroundf() equivalent rounding for IoT sensor telemetry.
"""

import math
from typing import Union
from src.config import TEMP_MIN, TEMP_MAX, OFFSET, SCALE, M_MIN, M_MAX


def round_away_from_zero(val: float) -> int:
    """
    Rounds a floating-point value to the nearest integer, breaking ties away from zero.

    This function strictly replicates the IEEE 754 / C99 `lroundf()` behavior required
    for cross-platform parity between Python simulations and ESP32 microcontroller firmware.

    Why Python's built-in round() is NOT used:
        Python's `round()` implements 'round half to even' (Banker's rounding). For example:
        - Python `round(2.5)` yields `2` (rounds down to nearest even integer)
        - Python `round(3.5)` yields `4` (rounds up to nearest even integer)
        Conversely, C99 `lroundf(2.5f)` yields `3` (rounds away from zero).
        If Python and C use disparate rounding strategies, the homomorphic scalar ciphertext
        will disagree on boundary values, breaking discrete logarithm recovery.

    Mathematical Definition:
        For val >= 0: floor(val + 0.5)
        For val < 0:  ceil(val - 0.5)

    Args:
        val: The floating-point number to round.

    Returns:
        The nearest integer with halfway cases rounded away from zero.

    Raises:
        TypeError: If val is not a numeric type.
        ValueError: If val is NaN or infinite.
    """
    if not isinstance(val, (int, float)):
        raise TypeError(f"Expected numeric float or int, got {type(val).__name__}")
    if math.isnan(val) or math.isinf(val):
        raise ValueError(f"Cannot round non-finite float: {val}")

    if val >= 0.0:
        return math.floor(val + 0.5)
    else:
        return math.ceil(val - 0.5)


def encode_temperature(temperature: Union[float, int]) -> int:
    """
    Converts a floating-point temperature in Celsius to a positive fixed-point integer.

    Formula:
        M = round_away_from_zero((temperature + OFFSET) * SCALE)
        where OFFSET = 50.0 and SCALE = 10.0

    Why Fixed-Point Encoding is Mandatory Before Elliptic Curve Encryption:
        1. Elliptic curve cryptography operates strictly over finite fields (e.g., GF(p))
           and cyclic subgroups of prime order q. There is no concept of a floating-point
           point on an elliptic curve.
        2. EC Lifted ElGamal maps a plaintext scalar M to a curve point M * G. M must be an integer.
        3. Raw temperatures may be negative (e.g., -40.0°C). Shifting by +50.0 ensures all
           encoded messages M are strictly positive integers in the range [100, 1300].
        4. Multiplying by 10.0 preserves 0.1°C telemetry precision (standard DHT22/SHT3x resolution)
           while eliminating fractional values.

    Input Validation:
        Valid temperature range: [-40.0°C, 80.0°C]
        Resulting integer M range: [100, 1300]

    Args:
        temperature: Temperature in degrees Celsius.

    Returns:
        Encoded integer scalar M.

    Raises:
        TypeError: If temperature is not a float or int.
        ValueError: If temperature is outside the valid range [-40.0, 80.0] or non-finite.

    Worked Example:
        Temperature = 23.5°C
        Shifted = 23.5 + 50.0 = 73.5
        Scaled = 73.5 * 10.0 = 735.0
        M = round_away_from_zero(735.0) = 735
    """
    if not isinstance(temperature, (int, float)):
        raise TypeError(f"Temperature must be float or int, got {type(temperature).__name__}")
    if math.isnan(temperature) or math.isinf(temperature):
        raise ValueError(f"Temperature must be finite, got {temperature}")

    # Explicit boundary check
    if temperature < TEMP_MIN or temperature > TEMP_MAX:
        raise ValueError(
            f"Temperature {temperature}°C out of valid range [{TEMP_MIN}°C, {TEMP_MAX}°C]"
        )

    # Shift and scale
    scaled = (float(temperature) + OFFSET) * SCALE
    encoded_m = round_away_from_zero(scaled)

    # Sanity check against theoretical bounds
    if not (M_MIN <= encoded_m <= M_MAX):
        raise ValueError(
            f"Encoded integer {encoded_m} unexpectedly out of bounds [{M_MIN}, {M_MAX}]"
        )

    return encoded_m


def decode_temperature(encoded_m: int) -> float:
    """
    Converts an encoded fixed-point integer back to a floating-point temperature in Celsius.

    Inverse Formula:
        T = (encoded_m / SCALE) - OFFSET = (encoded_m - 500) / 10.0

    Args:
        encoded_m: Encoded integer scalar.

    Returns:
        Reconstructed temperature in degrees Celsius (to 1 decimal place).

    Raises:
        TypeError: If encoded_m is not an integer.
        ValueError: If encoded_m is outside the valid range [100, 1300].

    Worked Example:
        Encoded M = 735
        Unscaled = 735 / 10.0 = 73.5
        Unshifted = 73.5 - 50.0 = 23.5°C
    """
    if not isinstance(encoded_m, int) or isinstance(encoded_m, bool):
        raise TypeError(f"Encoded value must be an integer, got {type(encoded_m).__name__}")

    if not (M_MIN <= encoded_m <= M_MAX):
        raise ValueError(
            f"Encoded integer {encoded_m} is outside the valid single-sensor range [{M_MIN}, {M_MAX}]"
        )

    temp = (float(encoded_m) / SCALE) - OFFSET
    # Round to 1 decimal place to eliminate floating-point representation artifacts (e.g., 23.500000000000004)
    return round(temp, 1)


def decode_temperature_sum(encoded_m_sum: int, n_sensors: int) -> float:
    """
    Converts an aggregated sum of encoded integers back to the sum of physical temperatures.

    Formula:
        T_sum = (encoded_m_sum - (OFFSET * SCALE * n_sensors)) / SCALE
              = (encoded_m_sum - (500 * n_sensors)) / 10.0

    Args:
        encoded_m_sum: Sum of encoded integers for n_sensors.
        n_sensors: Number of participating sensors (N >= 1).

    Returns:
        Aggregated temperature sum in degrees Celsius.

    Raises:
        ValueError: If n_sensors < 1 or sum is mathematically impossible.
    """
    if n_sensors < 1:
        raise ValueError(f"Sensor count must be at least 1, got {n_sensors}")

    min_sum = M_MIN * n_sensors
    max_sum = M_MAX * n_sensors
    if not (min_sum <= encoded_m_sum <= max_sum):
        raise ValueError(
            f"Encoded sum {encoded_m_sum} outside allowable range [{min_sum}, {max_sum}] for N={n_sensors}"
        )

    temp_sum = (float(encoded_m_sum) - (OFFSET * SCALE * n_sensors)) / SCALE
    return round(temp_sum, 1)
