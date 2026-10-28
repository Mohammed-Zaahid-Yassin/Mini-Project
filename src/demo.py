"""
End-to-end demonstration script for Weeks 1–4.
Benchmarking Bounded ECDLP Recovery for Privacy-Preserving IoT Aggregation.

Executes:
- Week 1: Fixed-point encoding, key generation, and Lifted ElGamal encryption.
- Week 2: Homomorphic aggregation, point unmasking, and interval shifting.
- Week 3: Point at Infinity edge-case detection and boundary validation.
- Week 4: Two-hop HMAC-SHA256 authentication and attack scenario matrix.
"""

import secrets
from typing import List
from src.config import G
from src.encoding import (
    encode_temperature,
    decode_temperature,
    round_away_from_zero,
    decode_temperature_sum,
)
from src.elgamal import (
    generate_keypair,
    encrypt,
    decrypt_point,
    point_to_bytes,
    is_infinity,
)
from src.aggregation import (
    aggregate_ciphertexts,
    apply_interval_shift,
    handle_infinity_edge_case,
    verify_candidate_sum,
)
from src.authentication import (
    build_bitmask,
    count_bitmask_sensors,
    compute_hop1_mac,
    verify_hop1_mac,
    compute_hop2_mac,
    verify_hop2_mac,
)
from src.protocol import SensorNode, Aggregator, Decryptor


def print_banner(title: str) -> None:
    print("\n" + "=" * 80)
    print(f"  {title.upper()}")
    print("=" * 80)


def demo_week1() -> None:
    print_banner("Week 1: EC Lifted ElGamal & Fixed-Point Encoding")

    print("\n[Step 1.1] Floating-Point vs Fixed-Point Conversion")
    sample_temps = [-40.0, -12.5, 0.0, 23.5, 23.55, 36.6, 80.0]
    print(f"{'Input (°C)':<12} | {'Formula ((T+50)*10)':<25} | {'Encoded (M)':<12} | {'Decoded (°C)':<12}")
    print("-" * 68)
    for t in sample_temps:
        m = encode_temperature(t)
        t_rec = decode_temperature(m)
        formula_str = f"({t:+.2f} + 50.0) * 10"
        print(f"{t:<12.2f} | {formula_str:<25} | {m:<12} | {t_rec:<12.1f}")

    print("\n[Step 1.2] Rounding Demonstration: Ties-Away-From-Zero (lroundf) vs Python round()")
    tie_values = [2.5, 3.5, -2.5, -3.5, 735.5]
    print(f"{'Value':<10} | {'round_away_from_zero()':<24} | {'Python round()':<18} | {'Note':<20}")
    print("-" * 75)
    for val in tie_values:
        custom_r = round_away_from_zero(val)
        py_r = round(val)
        diff = "Differs! (Matches C99)" if custom_r != py_r else "Identical"
        print(f"{val:<10.1f} | {custom_r:<24} | {py_r:<18} | {diff:<20}")

    print("\n[Step 1.3] Cryptographic Key Generation (NIST P-256)")
    private_key, public_key = generate_keypair()
    print("  Private key: [PROTECTED - 256-bit secret scalar in GF(q)]")
    pub_bytes = point_to_bytes(public_key)
    print(f"  Public key (Y = x*G): SEC1 65 bytes, prefix {pub_bytes[0]:#04x}")
    print(f"  Public key X: {hex(public_key.x)[:20]}...")
    print(f"  Public key Y: {hex(public_key.y)[:20]}...")

    print("\n[Step 1.4] Worked Example: Encrypting 23.5°C")
    target_temp = 23.5
    encoded_m = encode_temperature(target_temp)
    print(f"  1. Plaintext temperature: {target_temp}°C")
    print(f"  2. Encoded integer M: {encoded_m}")
    ct = encrypt(encoded_m, public_key)
    c1_bytes = point_to_bytes(ct.c1)
    c2_bytes = point_to_bytes(ct.c2)
    print(f"  3. Ephemeral public point C1 (r*G): {c1_bytes[:10].hex()}... (65 bytes)")
    print(f"  4. Masked message point C2 (M*G + r*Y): {c2_bytes[:10].hex()}... (65 bytes)")

    print("\n[Step 1.5] Decryption Point Computation (Unmasking)")
    p_decrypted = decrypt_point(ct, private_key)
    expected_point = encoded_m * G
    matches = (p_decrypted == expected_point)
    print(f"  Decrypted Point P = C2 - (x * C1)")
    print(f"  Expected Point: M * G = {encoded_m} * G")
    print(f"  Verification Result (P == M*G): {matches} [Exact mathematical match]")


def demo_week2() -> None:
    print_banner("Week 2: Homomorphic Aggregation & Interval Shifting")

    private_key, public_key = generate_keypair()
    readings = [18.2, 22.0, 25.4, 30.1, -12.5]
    n_sensors = len(readings)

    print(f"Simulating {n_sensors} IoT Sensor Nodes reporting in current epoch:")
    ciphertexts = []
    encoded_values = []
    for i, t in enumerate(readings, 1):
        m = encode_temperature(t)
        encoded_values.append(m)
        ct = encrypt(m, public_key)
        ciphertexts.append(ct)
        print(f"  Sensor {i}: Temp = {t:+5.1f}°C -> Encoded M = {m} -> Ciphertext (130 bytes)")

    ref_m_sum = sum(encoded_values)
    ref_temp_sum = sum(readings)
    ref_temp_avg = ref_temp_sum / n_sensors
    print(f"\nGround Truth (Hidden from Aggregator):")
    print(f"  Sum of Encoded Integers (M_sum) = {ref_m_sum}")
    print(f"  Sum of Temperatures = {ref_temp_sum:.1f}°C")
    print(f"  Average Temperature = {ref_temp_avg:.2f}°C")

    print("\n[Step 2.1] Aggregator executes Homomorphic Point Addition:")
    print("  C1_agg = C1_1 + C1_2 + ... + C1_N")
    print("  C2_agg = C2_1 + C2_2 + ... + C2_N")
    agg_ct = aggregate_ciphertexts(ciphertexts)
    print(f"  Aggregate C1: {point_to_bytes(agg_ct.c1)[:10].hex()}... (65 bytes)")
    print(f"  Aggregate C2: {point_to_bytes(agg_ct.c2)[:10].hex()}... (65 bytes)")
    print("  -> Aggregator has zero knowledge of individual readings or the plaintext sum!")

    print("\n[Step 2.2] Decryptor Unmasks the Aggregate Point:")
    print("  P = C2_agg - (x * C1_agg) = M_sum * G")
    p_decrypted = decrypt_point(agg_ct, private_key)
    print(f"  Unmasked Point P matches (M_sum * G): {p_decrypted == (ref_m_sum * G)}")

    print("\n[Step 2.3] Interval Shifting (Baseline Correction):")
    print(f"  P_shifted = P - (100 * N) * G = P - ({100 * n_sensors}) * G")
    p_shifted = apply_interval_shift(p_decrypted, n_sensors)
    expected_k = ref_m_sum - (100 * n_sensors)
    print(f"  Shifted scalar k = M_sum - 100*N = {ref_m_sum} - {100 * n_sensors} = {expected_k}")
    print(f"  Search interval narrowed to: [0, {1200 * n_sensors}]")

    print("\n[Step 2.4] Known-Candidate Verification:")
    verified = verify_candidate_sum(p_shifted, ref_m_sum, n_sensors)
    print(f"  Testing candidate M_sum={ref_m_sum}: Result = {verified}")
    bad_candidate = ref_m_sum + 1
    bad_verified = verify_candidate_sum(p_shifted, bad_candidate, n_sensors)
    print(f"  Testing invalid candidate M_sum={bad_candidate}: Result = {bad_verified} [Correctly rejected]")


def demo_week3() -> None:
    print_banner("Week 3: Interval Shifting & Point at Infinity Edge Cases")

    private_key, public_key = generate_keypair()
    n_sensors = 5

    print("\n[Scenario A] All N=5 Sensors report the Minimum Temperature (-40.0°C)")
    min_readings = [-40.0] * n_sensors
    ciphertexts_min = [encrypt(encode_temperature(t), public_key) for t in min_readings]
    agg_min = aggregate_ciphertexts(ciphertexts_min)
    p_decrypted_min = decrypt_point(agg_min, private_key)
    p_shifted_min = apply_interval_shift(p_decrypted_min, n_sensors)

    print(f"  Raw Encoded M per sensor: 100")
    print(f"  M_sum = {100 * n_sensors}")
    print(f"  P = (100 * {n_sensors}) * G = {100 * n_sensors} * G")
    print(f"  P_shifted = P - (100 * {n_sensors}) * G = 0 * G")
    is_inf_detected = is_infinity(p_shifted_min)
    print(f"  is_infinity(P_shifted): {is_inf_detected}")
    hit, rec_sum, rec_avg = handle_infinity_edge_case(p_shifted_min, n_sensors)
    print(f"  Edge-case handler output: Hit={hit}, Recovered M_sum={rec_sum}, Recovered Avg={rec_avg}°C")
    print("  -> Point at Infinity successfully detected; bypassed downstream DLP search!")

    print("\n[Scenario B] All N=5 Sensors report the Maximum Temperature (+80.0°C)")
    max_readings = [80.0] * n_sensors
    ciphertexts_max = [encrypt(encode_temperature(t), public_key) for t in max_readings]
    agg_max = aggregate_ciphertexts(ciphertexts_max)
    p_decrypted_max = decrypt_point(agg_max, private_key)
    p_shifted_max = apply_interval_shift(p_decrypted_max, n_sensors)

    expected_k_max = 1200 * n_sensors
    expected_point_max = expected_k_max * G
    print(f"  Raw Encoded M per sensor: 1300")
    print(f"  M_sum = {1300 * n_sensors}")
    print(f"  Expected P_shifted = (1200 * N) * G = {expected_k_max} * G")
    print(f"  Actual P_shifted matches expected upper-bound: {p_shifted_max == expected_point_max}")


def demo_week4() -> None:
    print_banner("Week 4: Two-Hop Authentication Architecture & Attack Matrix")

    # Setup 3 simulated sensors, 1 aggregator, 1 decryptor
    sensor_ids = ["sensor-01", "sensor-02", "sensor-03"]
    sensor_keys = {sid: secrets.token_bytes(32) for sid in sensor_ids}
    decryptor_key = secrets.token_bytes(32)

    private_key, public_key = generate_keypair()
    sensors = [SensorNode(sid, sensor_keys[sid], public_key) for sid in sensor_ids]
    aggregator = Aggregator(decryptor_key, sensor_keys, sensor_ids)
    decryptor = Decryptor(private_key, public_key, decryptor_key, sensor_ids)

    print("\nEnrolled Infrastructure:")
    print(f"  Universe: {sensor_ids}")
    print("  Cryptographic domain separation: Sensor keys != Decryptor key")

    current_epoch = 100
    test_temps = [21.5, 22.0, 24.5]

    print("\n--- Attack Simulation 1: Normal Valid Flow ---")
    packets = [s.generate_reading(t, current_epoch) for s, t in zip(sensors, test_temps)]
    agg_packet, accepted, rejections = aggregator.aggregate_epoch(packets, current_epoch)
    print(f"  Aggregator accepted {len(accepted)} packets: {accepted}")
    print(f"  Rejections: {rejections}")
    assert agg_packet is not None
    ref_m_sum = sum(encode_temperature(t) for t in test_temps)
    success, reason, result = decryptor.process_aggregate(agg_packet, candidate_m_sum=ref_m_sum)
    print(f"  Decryptor Outcome: Success={success}, Reason='{reason}'")
    print(f"  Recovered Average: {result['avg_temp']}°C (Candidate match: {result['candidate_match']})")

    print("\n--- Attack Simulation 2: Ciphertext Tampering (Man-in-the-Middle) ---")
    pkt_tampered = sensors[0].generate_reading(25.0, current_epoch + 1)
    # Malicious actor tampers with C2 point
    tampered_c2 = pkt_tampered.c2 + G
    from src.authentication import SensorPacket
    bad_pkt = SensorPacket(
        sensor_id=pkt_tampered.sensor_id,
        c1=pkt_tampered.c1,
        c2=tampered_c2,
        seq=pkt_tampered.seq,
        epoch=pkt_tampered.epoch,
        mac=pkt_tampered.mac,
    )
    valid, reason = aggregator.verify_sensor_packet(bad_pkt, current_epoch + 1)
    print(f"  Tampered C2 packet verification: Valid={valid}, Reason='{reason}'")

    print("\n--- Attack Simulation 3: Forged / Invalid Hop-1 MAC ---")
    bad_mac_pkt = SensorPacket(
        sensor_id=pkt_tampered.sensor_id,
        c1=pkt_tampered.c1,
        c2=pkt_tampered.c2,
        seq=pkt_tampered.seq + 1,
        epoch=pkt_tampered.epoch,
        mac=secrets.token_bytes(32),
    )
    valid, reason = aggregator.verify_sensor_packet(bad_mac_pkt, current_epoch + 1)
    print(f"  Forged MAC packet verification: Valid={valid}, Reason='{reason}'")

    print("\n--- Attack Simulation 4: Packet Replay Attack ---")
    # Replay previous valid packet
    valid, reason = aggregator.verify_sensor_packet(packets[0], current_epoch + 1)
    print(f"  Replayed packet (old Seq/Epoch): Valid={valid}, Reason='{reason}'")

    print("\n--- Attack Simulation 5: Out-of-Order / Stale Sequence Number ---")
    out_of_order_pkt = SensorPacket(
        sensor_id=sensors[0].sensor_id,
        c1=pkt_tampered.c1,
        c2=pkt_tampered.c2,
        seq=1,  # Lower than current sequence
        epoch=current_epoch + 1,
        mac=compute_hop1_mac(sensor_keys[sensors[0].sensor_id], sensors[0].sensor_id, pkt_tampered.c1, pkt_tampered.c2, 1, current_epoch + 1),
    )
    valid, reason = aggregator.verify_sensor_packet(out_of_order_pkt, current_epoch + 1)
    print(f"  Stale sequence number packet: Valid={valid}, Reason='{reason}'")

    print("\n--- Attack Simulation 6: Aggregate Forgery / Bad Hop-2 MAC ---")
    from src.authentication import AggregatePacket
    forged_agg_pkt = AggregatePacket(
        c1_agg=agg_packet.c1_agg,
        c2_agg=agg_packet.c2_agg,
        count=agg_packet.count,
        epoch=current_epoch + 1,
        bitmask=agg_packet.bitmask,
        mac=secrets.token_bytes(32),
    )
    success, reason, _ = decryptor.process_aggregate(forged_agg_pkt)
    print(f"  Forged Hop-2 MAC aggregate: Success={success}, Reason='{reason}'")

    print("\n--- Attack Simulation 7: Metadata Tampering (Count/Bitmask Mismatch) ---")
    # Attacker tampers with N count to manipulate baseline shift
    tampered_meta_pkt = AggregatePacket(
        c1_agg=agg_packet.c1_agg,
        c2_agg=agg_packet.c2_agg,
        count=agg_packet.count + 5,  # Claim 8 sensors instead of 3
        epoch=current_epoch + 1,
        bitmask=agg_packet.bitmask,
        mac=compute_hop2_mac(decryptor_key, agg_packet.c1_agg, agg_packet.c2_agg, agg_packet.count + 5, current_epoch + 1, agg_packet.bitmask),
    )
    success, reason, _ = decryptor.process_aggregate(tampered_meta_pkt)
    print(f"  Count-Bitmask tampering: Success={success}, Reason='{reason}'")

    print("\n--- Attack Simulation 8: Key Confusion Between Sensors ---")
    # Verify sensor-01 packet with sensor-02's key
    s1_pkt = sensors[0].generate_reading(20.0, current_epoch + 2)
    s2_key = sensor_keys["sensor-02"]
    verified_with_wrong_key = verify_hop1_mac(
        sensor_key=s2_key,
        sensor_id=s1_pkt.sensor_id,
        c1=s1_pkt.c1,
        c2=s1_pkt.c2,
        seq=s1_pkt.seq,
        epoch=s1_pkt.epoch,
        mac=s1_pkt.mac,
    )
    print(f"  Sensor 1 packet verified with Sensor 2 key: {verified_with_wrong_key} [Isolated key domains]")


def main() -> None:
    print_banner("Benchmarking Bounded ECDLP Recovery (Weeks 1–4 Demonstration)")
    demo_week1()
    demo_week2()
    demo_week3()
    demo_week4()
    print_banner("All Demonstration Scenarios Executed Successfully")


if __name__ == "__main__":
    main()
