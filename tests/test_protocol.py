"""
Automated end-to-end protocol simulation tests for Sensor, Aggregator, and Decryptor.
"""

import secrets
import pytest
from src.config import G
from src.encoding import encode_temperature
from src.elgamal import generate_keypair
from src.authentication import compute_hop1_mac, compute_hop2_mac, SensorPacket, AggregatePacket
from src.protocol import SensorNode, Aggregator, Decryptor


class TestProtocolPipeline:
    """Tests the full multi-tier execution lifecycle."""

    @pytest.fixture
    def environment(self):
        sensor_ids = ["sensor-01", "sensor-02", "sensor-03", "sensor-04"]
        sensor_keys = {sid: secrets.token_bytes(32) for sid in sensor_ids}
        decryptor_key = secrets.token_bytes(32)

        priv, pub = generate_keypair()
        sensors = {sid: SensorNode(sid, sensor_keys[sid], pub) for sid in sensor_ids}
        aggregator = Aggregator(decryptor_key, sensor_keys, sensor_ids)
        decryptor = Decryptor(priv, pub, decryptor_key, sensor_ids)

        return {
            "sensor_ids": sensor_ids,
            "sensor_keys": sensor_keys,
            "decryptor_key": decryptor_key,
            "sensors": sensors,
            "aggregator": aggregator,
            "decryptor": decryptor,
            "pub": pub,
            "priv": priv,
        }

    def test_end_to_end_successful_epoch(self, environment):
        sensors = environment["sensors"]
        aggregator = environment["aggregator"]
        decryptor = environment["decryptor"]

        epoch = 1
        temps = {"sensor-01": 20.0, "sensor-02": 22.5, "sensor-03": 25.0, "sensor-04": 27.5}
        packets = [sensors[sid].generate_reading(temps[sid], epoch) for sid in temps]

        agg_pkt, accepted, rejections = aggregator.aggregate_epoch(packets, current_epoch=epoch)
        assert len(accepted) == 4
        assert len(rejections) == 0
        assert agg_pkt is not None

        expected_m_sum = sum(encode_temperature(t) for t in temps.values())
        success, reason, result = decryptor.process_aggregate(agg_pkt, candidate_m_sum=expected_m_sum)

        assert success is True
        assert reason == "ACCEPTED_POINT_VALID"
        assert result["candidate_match"] is True
        assert result["count"] == 4
        # Expected average temp = (20.0 + 22.5 + 25.0 + 27.5) / 4 = 23.75°C
        assert result["avg_temp"] == pytest.approx(23.75, abs=0.01)

    def test_replayed_packet_rejected_by_aggregator(self, environment):
        sensors = environment["sensors"]
        aggregator = environment["aggregator"]

        epoch = 1
        pkt = sensors["sensor-01"].generate_reading(20.0, epoch)

        # First reception accepted
        valid, _ = aggregator.verify_sensor_packet(pkt, current_epoch=epoch)
        assert valid is True
        aggregator.last_seq["sensor-01"] = pkt.seq

        # Replay attempt in same epoch rejected by sequence tracking
        valid_replay, reason = aggregator.verify_sensor_packet(pkt, current_epoch=epoch)
        assert valid_replay is False
        assert "REJECT_REPLAY_OR_OUT_OF_ORDER" in reason

    def test_stale_epoch_rejected_by_aggregator(self, environment):
        sensors = environment["sensors"]
        aggregator = environment["aggregator"]

        # Packet generated for epoch 1
        pkt = sensors["sensor-01"].generate_reading(20.0, epoch=1)

        # Aggregator running at epoch 2
        valid, reason = aggregator.verify_sensor_packet(pkt, current_epoch=2)
        assert valid is False
        assert "REJECT_STALE_EPOCH" in reason

    def test_unregistered_sensor_rejected_by_aggregator(self, environment):
        aggregator = environment["aggregator"]
        pub = environment["pub"]

        rogue_key = secrets.token_bytes(32)
        rogue_sensor = SensorNode("unregistered-device", rogue_key, pub)
        pkt = rogue_sensor.generate_reading(22.0, epoch=1)

        valid, reason = aggregator.verify_sensor_packet(pkt, current_epoch=1)
        assert valid is False
        assert "REJECT_UNKNOWN_SENSOR" in reason

    def test_decryptor_rejects_non_monotonic_epoch(self, environment):
        sensors = environment["sensors"]
        aggregator = environment["aggregator"]
        decryptor = environment["decryptor"]

        # Process epoch 5
        pkts5 = [sensors[sid].generate_reading(20.0, epoch=5) for sid in ["sensor-01", "sensor-02"]]
        agg_pkt5, _, _ = aggregator.aggregate_epoch(pkts5, current_epoch=5)
        success, _, _ = decryptor.process_aggregate(agg_pkt5)
        assert success is True

        # Decryptor now rejects an incoming packet from epoch 4
        pkts4 = [sensors[sid].generate_reading(20.0, epoch=4) for sid in ["sensor-01", "sensor-02"]]
        agg_pkt4, _, _ = aggregator.aggregate_epoch(pkts4, current_epoch=4)
        success4, reason4, _ = decryptor.process_aggregate(agg_pkt4)
        assert success4 is False
        assert "REJECT_NON_MONOTONIC_EPOCH" in reason4

    def test_decryptor_rejects_count_bitmask_inconsistency(self, environment):
        sensors = environment["sensors"]
        aggregator = environment["aggregator"]
        decryptor = environment["decryptor"]
        key = environment["decryptor_key"]

        pkts = [sensors[sid].generate_reading(20.0, epoch=1) for sid in ["sensor-01", "sensor-02"]]
        agg_pkt, _, _ = aggregator.aggregate_epoch(pkts, current_epoch=1)

        # Tamper count from 2 to 3 and recompute MAC with decryptor key
        tampered_pkt = AggregatePacket(
            c1_agg=agg_pkt.c1_agg,
            c2_agg=agg_pkt.c2_agg,
            count=3,  # Bitmask actually only has 2 bits set
            epoch=1,
            bitmask=agg_pkt.bitmask,
            mac=compute_hop2_mac(key, agg_pkt.c1_agg, agg_pkt.c2_agg, 3, 1, agg_pkt.bitmask),
        )

        success, reason, _ = decryptor.process_aggregate(tampered_pkt)
        assert success is False
        assert "REJECT_COUNT_BITMASK_MISMATCH" in reason
