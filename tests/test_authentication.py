"""
Automated unit tests for two-hop HMAC-SHA256 authentication and serialization.
"""

import secrets
import pytest
from src.config import G
from src.elgamal import generate_keypair, encrypt
from src.authentication import (
    build_bitmask,
    count_bitmask_sensors,
    decode_bitmask_sensors,
    compute_hop1_mac,
    verify_hop1_mac,
    compute_hop2_mac,
    verify_hop2_mac,
    serialize_hop1_payload,
    serialize_hop2_payload,
)


class TestBitmaskOperations:
    """Tests participation bitmask construction and parsing."""

    def test_bitmask_hamming_weight_and_roundtrip(self):
        universe = [f"sensor-{i:02d}" for i in range(16)]
        reporting = ["sensor-01", "sensor-04", "sensor-15"]

        bitmask = build_bitmask(reporting, universe)
        assert len(bitmask) == 2  # ceil(16 / 8) = 2 bytes
        assert count_bitmask_sensors(bitmask) == 3

        decoded = decode_bitmask_sensors(bitmask, universe)
        assert sorted(decoded) == sorted(reporting)

    def test_bitmask_all_sensors(self):
        universe = [f"s-{i}" for i in range(10)]
        bitmask = build_bitmask(universe, universe)
        assert count_bitmask_sensors(bitmask) == 10

    def test_unknown_sensor_in_bitmask_raises(self):
        universe = ["s-1", "s-2"]
        with pytest.raises(ValueError):
            build_bitmask(["s-3"], universe)


class TestHop1Authentication:
    """Tests Hop-1 (Sensor -> Aggregator) authentication integrity."""

    @pytest.fixture
    def test_data(self):
        _, pub = generate_keypair()
        ct = encrypt(735, pub)
        key = secrets.token_bytes(32)
        sensor_id = "sensor-42"
        seq = 1
        epoch = 100
        mac = compute_hop1_mac(key, sensor_id, ct.c1, ct.c2, seq, epoch)
        return {
            "key": key,
            "sensor_id": sensor_id,
            "c1": ct.c1,
            "c2": ct.c2,
            "seq": seq,
            "epoch": epoch,
            "mac": mac,
        }

    def test_valid_hop1_mac_verification(self, test_data):
        assert verify_hop1_mac(
            sensor_key=test_data["key"],
            sensor_id=test_data["sensor_id"],
            c1=test_data["c1"],
            c2=test_data["c2"],
            seq=test_data["seq"],
            epoch=test_data["epoch"],
            mac=test_data["mac"],
        ) is True

    def test_hop1_ciphertext_tampering_detected(self, test_data):
        # Alter C1
        tampered_c1 = test_data["c1"] + G
        assert verify_hop1_mac(
            sensor_key=test_data["key"],
            sensor_id=test_data["sensor_id"],
            c1=tampered_c1,
            c2=test_data["c2"],
            seq=test_data["seq"],
            epoch=test_data["epoch"],
            mac=test_data["mac"],
        ) is False

    def test_hop1_metadata_tampering_detected(self, test_data):
        # Tampered sequence number
        assert verify_hop1_mac(
            sensor_key=test_data["key"],
            sensor_id=test_data["sensor_id"],
            c1=test_data["c1"],
            c2=test_data["c2"],
            seq=test_data["seq"] + 1,
            epoch=test_data["epoch"],
            mac=test_data["mac"],
        ) is False

        # Tampered epoch
        assert verify_hop1_mac(
            sensor_key=test_data["key"],
            sensor_id=test_data["sensor_id"],
            c1=test_data["c1"],
            c2=test_data["c2"],
            seq=test_data["seq"],
            epoch=test_data["epoch"] + 1,
            mac=test_data["mac"],
        ) is False

        # Tampered sensor identity
        assert verify_hop1_mac(
            sensor_key=test_data["key"],
            sensor_id="sensor-99",
            c1=test_data["c1"],
            c2=test_data["c2"],
            seq=test_data["seq"],
            epoch=test_data["epoch"],
            mac=test_data["mac"],
        ) is False

    def test_sensor_key_isolation(self, test_data):
        other_key = secrets.token_bytes(32)
        assert verify_hop1_mac(
            sensor_key=other_key,
            sensor_id=test_data["sensor_id"],
            c1=test_data["c1"],
            c2=test_data["c2"],
            seq=test_data["seq"],
            epoch=test_data["epoch"],
            mac=test_data["mac"],
        ) is False


class TestHop2Authentication:
    """Tests Hop-2 (Aggregator -> Decryptor) authentication integrity."""

    @pytest.fixture
    def test_data(self):
        _, pub = generate_keypair()
        ct = encrypt(1500, pub)
        key = secrets.token_bytes(32)
        count = 3
        epoch = 100
        bitmask = b"\x07"  # 3 sensors (bits 0, 1, 2)
        mac = compute_hop2_mac(key, ct.c1, ct.c2, count, epoch, bitmask)
        return {
            "key": key,
            "c1_agg": ct.c1,
            "c2_agg": ct.c2,
            "count": count,
            "epoch": epoch,
            "bitmask": bitmask,
            "mac": mac,
        }

    def test_valid_hop2_mac_verification(self, test_data):
        assert verify_hop2_mac(
            decryptor_key=test_data["key"],
            c1_agg=test_data["c1_agg"],
            c2_agg=test_data["c2_agg"],
            n_count=test_data["count"],
            epoch=test_data["epoch"],
            bitmask=test_data["bitmask"],
            mac=test_data["mac"],
        ) is True

    def test_hop2_tampering_count_detected(self, test_data):
        # Attacker modifies N to disrupt interval shifting
        assert verify_hop2_mac(
            decryptor_key=test_data["key"],
            c1_agg=test_data["c1_agg"],
            c2_agg=test_data["c2_agg"],
            n_count=test_data["count"] + 1,
            epoch=test_data["epoch"],
            bitmask=test_data["bitmask"],
            mac=test_data["mac"],
        ) is False

    def test_hop2_tampering_bitmask_detected(self, test_data):
        assert verify_hop2_mac(
            decryptor_key=test_data["key"],
            c1_agg=test_data["c1_agg"],
            c2_agg=test_data["c2_agg"],
            n_count=test_data["count"],
            epoch=test_data["epoch"],
            bitmask=b"\x0f",
            mac=test_data["mac"],
        ) is False
