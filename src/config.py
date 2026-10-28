"""
System configuration and cryptographic parameters.
Benchmarking Bounded ECDLP Recovery for Privacy-Preserving IoT Aggregation.
"""

from fastecdsa.curve import P256

# ---------------------------------------------------------------------------
# Elliptic Curve Parameters (NIST P-256 / secp256r1)
# ---------------------------------------------------------------------------
P256_CURVE = P256
G = P256.G  # Base generator point
CURVE_ORDER = P256.q  # Prime order of the subgroup (q)
FIELD_PRIME = P256.p  # Prime defining the finite field GF(p)

# ---------------------------------------------------------------------------
# Sensor Temperature & Fixed-Point Encoding Constraints
# ---------------------------------------------------------------------------
# Temperature measurement bounds for IoT environmental sensors (e.g., DHT22/SHT3x)
TEMP_MIN: float = -40.0
TEMP_MAX: float = 80.0

# Fixed-point transformation parameters:
# Formula: M = round_away_from_zero((T + OFFSET) * SCALE)
OFFSET: float = 50.0
SCALE: float = 10.0

# Encoded message integer range for a single sensor:
# T = -40.0°C -> M_min = (-40.0 + 50.0) * 10 = 100
# T =  80.0°C -> M_max = ( 80.0 + 50.0) * 10 = 1300
M_MIN: int = 100
M_MAX: int = 1300

# ---------------------------------------------------------------------------
# Interval Shifting Parameters (Week 2 & Week 3)
# ---------------------------------------------------------------------------
# For N sensors, the minimum possible sum is N * M_MIN = 100 * N.
# Interval shifting subtracts (100 * N) * G so the search interval starts at 0.
BASELINE_PER_SENSOR: int = 100

# After subtracting baseline, each sensor contributes between 0 and 1200.
# The shifted sum for N sensors lies in [0, 1200 * N].
SHIFTED_MAX_PER_SENSOR: int = 1200

# ---------------------------------------------------------------------------
# Authentication & Serialization Constants (Week 4)
# ---------------------------------------------------------------------------
HMAC_ALGORITHM: str = "sha256"
HMAC_KEY_BYTES: int = 32
POINT_SEC1_BYTES: int = 65  # 0x04 || X (32 bytes) || Y (32 bytes)
POINT_INFINITY_BYTES: bytes = b"\x00" * POINT_SEC1_BYTES  # Canonical 65-byte zero
SENSOR_ID_MAX_LEN: int = 32
