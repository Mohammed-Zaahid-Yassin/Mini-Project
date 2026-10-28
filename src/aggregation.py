"""
Homomorphic aggregation, interval shifting, and edge-case handling module.
Implements EC Lifted ElGamal ciphertext addition and baseline correction.
"""

from typing import Sequence, Tuple, Optional
from fastecdsa.point import Point
from src.config import G, BASELINE_PER_SENSOR, SHIFTED_MAX_PER_SENSOR
from src.elgamal import (
    Ciphertext,
    decrypt_point,
    is_infinity,
    get_infinity_point,
    is_point_on_curve,
)


def aggregate_ciphertexts(ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
    """
    Homomorphically aggregates a collection of Lifted ElGamal ciphertexts.

    Mathematical Operation:
        Given N ciphertexts CT_i = (C1_i, C2_i) for i = 1, ..., N:
        C1_agg = C1_1 + C1_2 + ... + C1_N = (sum_{i=1}^N r_i) * G
        C2_agg = C2_1 + C2_2 + ... + C2_N = (sum_{i=1}^N M_i) * G + (sum_{i=1}^N r_i) * Y

    Why This Preserves IoT Privacy:
        The untrusted aggregator combines ciphertexts purely by executing elliptic curve
        point addition on the coordinates. At no point does the aggregator learn individual
        sensor readings M_i or ephemeral blinding factors r_i. The individual ciphertexts
        fuse irrevocably into a single aggregate pair (C1_agg, C2_agg).

    Args:
        ciphertexts: Non-empty sequence of Ciphertext instances.

    Returns:
        Aggregate Ciphertext instance (C1_agg, C2_agg).

    Raises:
        ValueError: If the input sequence is empty or elements are invalid.
    """
    if not ciphertexts:
        raise ValueError("Cannot aggregate an empty sequence of ciphertexts")

    # Start with first ciphertext
    first = ciphertexts[0]
    if not isinstance(first, Ciphertext):
        raise TypeError(f"Expected Ciphertext instance, got {type(first).__name__}")

    agg_c1 = first.c1
    agg_c2 = first.c2

    # Add each subsequent ciphertext using elliptic curve point addition
    for i, ct in enumerate(ciphertexts[1:], start=2):
        if not isinstance(ct, Ciphertext):
            raise TypeError(f"Item {i} is not a Ciphertext instance: {type(ct).__name__}")
        agg_c1 = agg_c1 + ct.c1
        agg_c2 = agg_c2 + ct.c2

    return Ciphertext(c1=agg_c1, c2=agg_c2)


def decrypt_aggregate_point(aggregate_ciphertext: Ciphertext, private_key: int) -> Point:
    """
    Unmasks the aggregate ciphertext to produce the unshifted sum point P.

    Formula:
        P = C2_agg - (x * C1_agg)
          = (M_sum * G + r_sum * Y) - x * (r_sum * G)
          = M_sum * G

    Args:
        aggregate_ciphertext: Aggregated (C1_agg, C2_agg).
        private_key: Decryptor's private key scalar x.

    Returns:
        Point P = M_sum * G.
    """
    return decrypt_point(aggregate_ciphertext, private_key)


def apply_interval_shift(decrypted_point: Point, n_sensors: int) -> Point:
    """
    Applies the baseline correction for N sensors to narrow the ECDLP search window.

    Formula:
        P_shifted = P - (100 * N) * G

    Mathematical Motivation:
        Because each sensor reading T_i in [-40°C, 80°C] encodes to M_i in [100, 1300],
        the aggregate sum M_sum lies in [100*N, 1300*N].
        Without interval shifting, a discrete logarithm search would have to search across
        the entire offset range.
        By subtracting the known minimum baseline (100 * N) * G, the shifted target point:
            P_shifted = (M_sum - 100*N) * G = k * G
        represents an integer k in the bounded interval:
            k in [0, 1200 * N]
        This aligns the lower bound of the discrete logarithm problem precisely at zero!

    Edge Case Handling:
        When every sensor reports the minimum temperature (-40.0°C), M_sum = 100 * N.
        Thus: P_shifted = (100*N - 100*N) * G = 0 * G = O (Point at Infinity).

    Args:
        decrypted_point: Unshifted decrypted point P = M_sum * G.
        n_sensors: Number of participating sensors N (N >= 1).

    Returns:
        Shifted elliptic curve point P_shifted.

    Raises:
        ValueError: If n_sensors < 1 or decrypted_point is invalid.
    """
    if n_sensors < 1:
        raise ValueError(f"Sensor count must be at least 1, got {n_sensors}")
    if not is_point_on_curve(decrypted_point):
        raise ValueError("Invalid decrypted point: does not lie on curve P-256")

    # Baseline scalar: 100 * N
    baseline_scalar = BASELINE_PER_SENSOR * n_sensors
    baseline_point = baseline_scalar * G

    # Shift: P_shifted = P - baseline_point
    p_shifted = decrypted_point - baseline_point
    return p_shifted


def handle_infinity_edge_case(p_shifted: Point, n_sensors: int) -> Tuple[bool, Optional[int], Optional[float]]:
    """
    Explicitly detects and handles the Point at Infinity (O) edge case for downstream recovery.

    Why the Point at Infinity is a Valid Mathematical Result:
        In elliptic curve group theory, O is the neutral identity element (analogous to 0 in integer addition).
        When all N sensors report -40.0°C, the shifted scalar is exactly:
            k = M_sum - 100*N = 0
        In geometric terms, 0 * G produces no affine (X, Y) coordinate pair on the curve;
        it evaluates strictly to the identity element O.

    Why Downstream Search Algorithms Must Explicitly Bypass O:
        Algorithms such as Baby-Step Giant-Step (BSGS) and Pollard's Kangaroo rely on extracting
        affine X-coordinates (e.g., hash(X)) or performing affine point operations. Attempting to
        affine-normalize O or compute X-coordinates triggers a division-by-zero or undefined projective
        state. Handling O immediately short-circuits the search with zero latency.

    Args:
        p_shifted: The shifted point P_shifted to evaluate.
        n_sensors: Number of sensors N.

    Returns:
        Tuple of (is_infinity_hit, recovered_m_sum, recovered_avg_temp):
        - If p_shifted is O: (True, 100 * N, -40.0)
        - Otherwise: (False, None, None)
    """
    if is_infinity(p_shifted):
        # Known lower-bound sum: M_sum = 100 * N
        m_sum = BASELINE_PER_SENSOR * n_sensors
        avg_temp = -40.0
        return True, m_sum, avg_temp
    return False, None, None


def verify_candidate_sum(p_shifted: Point, candidate_m_sum: int, n_sensors: int) -> bool:
    """
    Verifies a known candidate encoded sum against the shifted decrypted point P_shifted.

    This function serves as the Week 2/3 verification interface prior to the implementation
    of bounded discrete logarithm search algorithms (BSGS/Kangaroo in Weeks 5+).

    Verification Check:
        Let candidate shifted scalar k = candidate_m_sum - 100 * N.
        1. If k == 0: Verify that is_infinity(p_shifted) is True.
        2. If k > 0: Verify that p_shifted == (k * G).

    Args:
        p_shifted: The actual shifted point computed from ciphertexts and private key.
        candidate_m_sum: The reference encoded sum M_sum = sum(M_i).
        n_sensors: Number of sensors N.

    Returns:
        True if the decrypted point matches the candidate sum exactly, False otherwise.
    """
    if n_sensors < 1:
        raise ValueError(f"Sensor count N must be >= 1, got {n_sensors}")

    min_allowed = BASELINE_PER_SENSOR * n_sensors
    max_allowed = (BASELINE_PER_SENSOR + SHIFTED_MAX_PER_SENSOR) * n_sensors

    if not (min_allowed <= candidate_m_sum <= max_allowed):
        return False

    k = candidate_m_sum - (BASELINE_PER_SENSOR * n_sensors)

    if k == 0:
        return is_infinity(p_shifted)
    else:
        expected_point = k * G
        return p_shifted == expected_point
