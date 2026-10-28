"""
Benchmarking Bounded ECDLP Recovery for Privacy-Preserving IoT Aggregation
Implementation of Weeks 1–4: Mathematical Foundations & Protocol Correctness.
"""

from src.config import (
    P256_CURVE,
    TEMP_MIN,
    TEMP_MAX,
    OFFSET,
    SCALE,
    BASELINE_PER_SENSOR,
    SHIFTED_MAX_PER_SENSOR,
)
from src.encoding import (
    round_away_from_zero,
    encode_temperature,
    decode_temperature,
)
from src.elgamal import (
    Ciphertext,
    generate_keypair,
    encrypt,
    decrypt_point,
    point_to_bytes,
    bytes_to_point,
    is_infinity,
    is_point_on_curve,
)
from src.aggregation import (
    aggregate_ciphertexts,
    decrypt_aggregate_point,
    apply_interval_shift,
    verify_candidate_sum,
)
from src.authentication import (
    SensorPacket,
    AggregatePacket,
    compute_hop1_mac,
    verify_hop1_mac,
    compute_hop2_mac,
    verify_hop2_mac,
    build_bitmask,
    count_bitmask_sensors,
)
from src.protocol import (
    SensorNode,
    Aggregator,
    Decryptor,
)

__all__ = [
    "P256_CURVE",
    "TEMP_MIN",
    "TEMP_MAX",
    "OFFSET",
    "SCALE",
    "BASELINE_PER_SENSOR",
    "SHIFTED_MAX_PER_SENSOR",
    "round_away_from_zero",
    "encode_temperature",
    "decode_temperature",
    "Ciphertext",
    "generate_keypair",
    "encrypt",
    "decrypt_point",
    "point_to_bytes",
    "bytes_to_point",
    "is_infinity",
    "is_point_on_curve",
    "aggregate_ciphertexts",
    "decrypt_aggregate_point",
    "apply_interval_shift",
    "verify_candidate_sum",
    "SensorPacket",
    "AggregatePacket",
    "compute_hop1_mac",
    "verify_hop1_mac",
    "compute_hop2_mac",
    "verify_hop2_mac",
    "build_bitmask",
    "count_bitmask_sensors",
    "SensorNode",
    "Aggregator",
    "Decryptor",
]
