"""
Three-tier privacy-preserving protocol simulation module.
Coordinates SensorNode, Untrusted Aggregator, and Decryptor roles.
"""

import math
from typing import Dict, List, Tuple, Optional, Any, Sequence
from fastecdsa.point import Point
from src.config import G
from src.encoding import (
    encode_temperature,
    decode_temperature_sum,
)
from src.elgamal import (
    Ciphertext,
    encrypt,
    is_infinity,
    is_point_on_curve,
)
from src.aggregation import (
    aggregate_ciphertexts,
    decrypt_aggregate_point,
    apply_interval_shift,
    handle_infinity_edge_case,
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
    decode_bitmask_sensors,
)


class SensorNode:
    """
    Simulates an IoT sensor node (e.g., ESP32 with DHT22 temperature sensor).

    Responsibilities:
        1. Measures physical temperature and applies fixed-point encoding M = round((T+50)*10).
        2. Encrypts M under Decryptor public key Y using Lifted ElGamal with fresh ephemeral r.
        3. Maintains a strictly monotonic sequence counter Seq.
        4. Computes Hop-1 HMAC-SHA256 authentication tag binding SensorID, C1, C2, Seq, Epoch.
        5. Transmits authenticated SensorPacket to Aggregator.
    """

    def __init__(self, sensor_id: str, auth_key: bytes, public_key: Point):
        self.sensor_id = sensor_id
        self.auth_key = auth_key
        self.public_key = public_key
        self.seq: int = 0

    def generate_reading(self, temperature: float, epoch: int) -> SensorPacket:
        """
        Creates an authenticated sensor telemetry packet.

        Args:
            temperature: Reading in degrees Celsius [-40.0, 80.0].
            epoch: Current network time epoch.

        Returns:
            SensorPacket containing encrypted reading, sequence number, and Hop-1 MAC.
        """
        encoded_m = encode_temperature(temperature)
        ct = encrypt(encoded_m, self.public_key)

        # Monotonically increment sequence number
        self.seq += 1

        mac = compute_hop1_mac(
            sensor_key=self.auth_key,
            sensor_id=self.sensor_id,
            c1=ct.c1,
            c2=ct.c2,
            seq=self.seq,
            epoch=epoch,
        )

        return SensorPacket(
            sensor_id=self.sensor_id,
            c1=ct.c1,
            c2=ct.c2,
            seq=self.seq,
            epoch=epoch,
            mac=mac,
        )


class Aggregator:
    """
    Simulates the Untrusted Aggregator (e.g., intermediate gateway, edge server, or MQTT broker).

    Security Posture:
        - UNTRUSTED with respect to confidentiality: The aggregator NEVER holds the decryption
          private key and cannot decrypt individual ciphertexts.
        - Semihonest or untrusted execution: The aggregator might drop packets, fail to aggregate,
          or attempt to forge metadata. Hop-2 MAC ensures the Decryptor knows who routed the packet,
          though HMAC alone cannot guarantee mathematical correctness of the EC point addition.

    Responsibilities:
        1. Validates Hop-1 MAC for incoming sensor packets using per-sensor secret keys.
        2. Enforces monotonic sequence numbers per sensor to reject replay attacks.
        3. Enforces matching epoch identifiers to prevent stale cross-epoch packet injection.
        4. Homomorphically aggregates valid ciphertexts: C1_agg = sum(C1), C2_agg = sum(C2).
        5. Constructs participation bitmask over the known sensor universe.
        6. Computes Hop-2 HMAC-SHA256 authentication tag using decryptor_auth_key.
        7. Transmits AggregatePacket to Decryptor.
    """

    def __init__(
        self,
        decryptor_auth_key: bytes,
        sensor_keys: Dict[str, bytes],
        sensor_universe: List[str],
    ):
        self.decryptor_auth_key = decryptor_auth_key
        self.sensor_keys = sensor_keys
        self.sensor_universe = list(sensor_universe)
        # Track highest accepted sequence number per sensor to reject replays
        self.last_seq: Dict[str, int] = {sid: 0 for sid in sensor_universe}

    def verify_sensor_packet(self, packet: SensorPacket, current_epoch: int) -> Tuple[bool, str]:
        """
        Validates an incoming sensor packet against authenticity, freshness, and replay policies.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        # 1. Check known sensor enrollment
        if packet.sensor_id not in self.sensor_keys:
            return False, f"REJECT_UNKNOWN_SENSOR: Sensor '{packet.sensor_id}' not enrolled"

        # 2. Check epoch freshness
        if packet.epoch != current_epoch:
            return False, f"REJECT_STALE_EPOCH: Packet epoch {packet.epoch} does not match active epoch {current_epoch}"

        # 3. Check sequence number policy: strictly monotonic (seq > last_seq)
        last = self.last_seq.get(packet.sensor_id, 0)
        if packet.seq <= last:
            return False, f"REJECT_REPLAY_OR_OUT_OF_ORDER: Received seq {packet.seq} <= last seen {last}"

        # 4. Check Hop-1 MAC authenticity
        key = self.sensor_keys[packet.sensor_id]
        if not verify_hop1_mac(
            sensor_key=key,
            sensor_id=packet.sensor_id,
            c1=packet.c1,
            c2=packet.c2,
            seq=packet.seq,
            epoch=packet.epoch,
            mac=packet.mac,
        ):
            return False, f"REJECT_INVALID_HOP1_MAC: Cryptographic checksum verification failed"

        # Packet is authenticated and fresh
        return True, "ACCEPTED"

    def aggregate_epoch(
        self,
        packets: Sequence[SensorPacket],
        current_epoch: int,
    ) -> Tuple[Optional[AggregatePacket], List[str], List[Tuple[SensorPacket, str]]]:
        """
        Processes an epoch collection of sensor packets, filtering invalid packets
        and producing an authenticated AggregatePacket.

        Returns:
            Tuple of (aggregate_packet, accepted_sensor_ids, rejected_log).
        """
        accepted_packets: List[SensorPacket] = []
        accepted_ids: List[str] = []
        seen_in_this_epoch: set = set()
        rejections: List[Tuple[SensorPacket, str]] = []

        for pkt in packets:
            # Prevent duplicate submissions by the same sensor within one epoch
            if pkt.sensor_id in seen_in_this_epoch:
                rejections.append((pkt, "REJECT_DUPLICATE_IN_EPOCH"))
                continue

            valid, reason = self.verify_sensor_packet(pkt, current_epoch)
            if valid:
                self.last_seq[pkt.sensor_id] = pkt.seq
                seen_in_this_epoch.add(pkt.sensor_id)
                accepted_packets.append(pkt)
                accepted_ids.append(pkt.sensor_id)
            else:
                rejections.append((pkt, reason))

        if not accepted_packets:
            return None, [], rejections

        # Homomorphically add ciphertexts
        ciphertexts = [pkt.ciphertext() for pkt in accepted_packets]
        agg_ct = aggregate_ciphertexts(ciphertexts)

        # Construct participation bitmask
        bitmask = build_bitmask(accepted_ids, self.sensor_universe)
        n_count = len(accepted_packets)

        # Sign with Hop-2 MAC
        hop2_mac = compute_hop2_mac(
            decryptor_key=self.decryptor_auth_key,
            c1_agg=agg_ct.c1,
            c2_agg=agg_ct.c2,
            n_count=n_count,
            epoch=current_epoch,
            bitmask=bitmask,
        )

        agg_packet = AggregatePacket(
            c1_agg=agg_ct.c1,
            c2_agg=agg_ct.c2,
            count=n_count,
            epoch=current_epoch,
            bitmask=bitmask,
            mac=hop2_mac,
        )

        return agg_packet, accepted_ids, rejections


class Decryptor:
    """
    Simulates the Trusted Decryptor node (e.g., institutional sink or authorized controller).

    Security Posture:
        - Holds the master private key x.
        - Holds the shared Hop-2 symmetric authentication key.
        - Validates aggregate provenance, metadata integrity, and quorum constraints before decryption.

    Responsibilities:
        1. Validates Hop-2 MAC tag over (C1_agg, C2_agg, N, Epoch, Bitmask).
        2. Validates epoch monotonicity (epoch >= last_seen_epoch).
        3. Validates bitmask structure and verifies HammingWeight(bitmask) == N.
        4. Computes decrypted point P = C2_agg - (x * C1_agg).
        5. Computes shifted point P_shifted = P - (100 * N) * G.
        6. Explicitly detects and handles Point at Infinity edge case (all -40°C readings).
        7. Supports known-candidate verification for research testing (Weeks 1–4).
    """

    def __init__(
        self,
        private_key: int,
        public_key: Point,
        decryptor_auth_key: bytes,
        sensor_universe: List[str],
        min_quorum: int = 1,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.decryptor_auth_key = decryptor_auth_key
        self.sensor_universe = list(sensor_universe)
        self.min_quorum = min_quorum
        self.last_seen_epoch: int = 0

    def process_aggregate(
        self,
        packet: AggregatePacket,
        candidate_m_sum: Optional[int] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates aggregate metadata, decrypts the curve point, applies interval shifting,
        and optionally verifies against a known candidate sum.

        Returns:
            Tuple of (success: bool, status_message: str, details_dict: Dict).
        """
        result: Dict[str, Any] = {
            "epoch": packet.epoch,
            "count": packet.count,
            "is_infinity": False,
            "m_sum": None,
            "avg_temp": None,
            "candidate_match": None,
        }

        # 1. Verify Hop-2 MAC authenticity
        if not verify_hop2_mac(
            decryptor_key=self.decryptor_auth_key,
            c1_agg=packet.c1_agg,
            c2_agg=packet.c2_agg,
            n_count=packet.count,
            epoch=packet.epoch,
            bitmask=packet.bitmask,
            mac=packet.mac,
        ):
            return False, "REJECT_INVALID_HOP2_MAC: Decryptor MAC tag mismatch", result

        # 2. Verify epoch freshness / monotonicity
        if packet.epoch < self.last_seen_epoch:
            return False, (
                f"REJECT_NON_MONOTONIC_EPOCH: Received epoch {packet.epoch} "
                f"< last observed epoch {self.last_seen_epoch}"
            ), result

        # 3. Verify bitmask length
        expected_bytes = math.ceil(len(self.sensor_universe) / 8)
        if len(packet.bitmask) != expected_bytes:
            return False, (
                f"REJECT_INVALID_BITMASK_LENGTH: Expected {expected_bytes} bytes, "
                f"got {len(packet.bitmask)}"
            ), result

        # 4. Verify count consistency with bitmask Hamming weight
        actual_count = count_bitmask_sensors(packet.bitmask)
        if actual_count != packet.count:
            return False, (
                f"REJECT_COUNT_BITMASK_MISMATCH: Packet declared count {packet.count} "
                f"but bitmask contains {actual_count} active sensors"
            ), result

        # 5. Verify quorum bounds
        if packet.count < self.min_quorum or packet.count > len(self.sensor_universe):
            return False, (
                f"REJECT_QUORUM_VIOLATION: Count {packet.count} out of allowable range "
                f"[{self.min_quorum}, {len(self.sensor_universe)}]"
            ), result

        # Update last seen epoch
        self.last_seen_epoch = packet.epoch

        # 6. Decrypt unshifted elliptic curve point: P = C2_agg - (x * C1_agg)
        p_decrypted = decrypt_aggregate_point(packet.ciphertext(), self.private_key)

        # 7. Apply interval shift: P_shifted = P - (100 * N) * G
        p_shifted = apply_interval_shift(p_decrypted, packet.count)

        # 8. Check for Point at Infinity edge case (all sensors reported -40°C)
        is_inf, recovered_m_sum, recovered_avg = handle_infinity_edge_case(p_shifted, packet.count)
        if is_inf:
            result["is_infinity"] = True
            result["m_sum"] = recovered_m_sum
            result["avg_temp"] = recovered_avg
            if candidate_m_sum is not None:
                result["candidate_match"] = (candidate_m_sum == recovered_m_sum)
            return True, "ACCEPTED_POINT_AT_INFINITY_LOWER_BOUND", result

        # 9. Verify candidate sum if provided (Weeks 1–4 verification interface)
        if candidate_m_sum is not None:
            match = verify_candidate_sum(p_shifted, candidate_m_sum, packet.count)
            result["candidate_match"] = match
            if match:
                result["m_sum"] = candidate_m_sum
                total_temp = decode_temperature_sum(candidate_m_sum, packet.count)
                result["avg_temp"] = round(total_temp / packet.count, 2)

        return True, "ACCEPTED_POINT_VALID", result
