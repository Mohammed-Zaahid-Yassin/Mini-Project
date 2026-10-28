# Week 4 Implementation Report: Two-Hop Authentication Architecture

## 1. Objectives

1. Implement HMAC-SHA256 authentication using Python's standard `hmac` and `hashlib` modules.
2. Create two distinct logical authentication domains:
   - **Hop 1:** Sensor to Aggregator ($K_{\text{sensor}, i}$ binding SensorID, $C_1$, $C_2$, Seq, Epoch).
   - **Hop 2:** Aggregator to Decryptor ($K_{\text{decryptor}}$ binding $C_{1, \text{agg}}$, $C_{2, \text{agg}}$, $N$, Epoch, Bitmask).
3. Implement deterministic, length-delimited canonical serialization to prevent malleability.
4. Enforce replay mitigation via per-sensor monotonic sequence numbers ($\text{Seq} > \text{last\_seq}$) and epoch freshness.
5. Use `hmac.compare_digest()` for constant-time MAC verification.
6. Build a complete multi-tier simulation (`SensorNode`, `Aggregator`, `Decryptor`) demonstrating mitigation of 8 distinct attack scenarios.
7. Document the fundamental security limitation: HMAC authenticates provenance and transport integrity, not arithmetic correctness of the aggregation.

---

## 2. Plain-English Explanation

Encryption locks the data so eavesdroppers cannot read it, but encryption alone does not prove who sent the message or prevent an attacker from tampering with it or resending an old message a thousand times (a replay attack).

To solve this, we place a unique, tamper-proof digital wax seal (an HMAC) on every packet:
1. **Hop 1:** Each sensor seals its encrypted reading with its own secret key, stamping it with an increasing sequence number and a time epoch. If a rogue device alters the ciphertext or tries to replay last week's reading, the aggregator immediately catches and drops it.
2. **Hop 2:** After combining the valid vaults, the aggregator creates a checklist (a bitmask) showing which sensors checked in, stamps the total count $N$, and seals the package with a separate key shared only with the decryptor.

---

## 3. Mathematical & Cryptographic Formulation

### 3.1 Hop-1 Authentication
$$\text{MAC}_1 = \text{HMAC-SHA256}(K_{\text{sensor}, i}, \mathcal{D}_1 \parallel \text{len}(\text{ID}) \parallel \text{ID} \parallel C_1 \parallel C_2 \parallel \text{Seq} \parallel \text{Epoch})$$

Where $\mathcal{D}_1 = \text{"PPA-IOT-HOP1-SENSOR-V1"}$ is the domain separation tag.

### 3.2 Hop-2 Authentication
$$\text{MAC}_2 = \text{HMAC-SHA256}(K_{\text{decryptor}}, \mathcal{D}_2 \parallel C_{1, \text{agg}} \parallel C_{2, \text{agg}} \parallel N \parallel \text{Epoch} \parallel \text{len}(\text{Mask}) \parallel \text{Bitmask})$$

Where $\mathcal{D}_2 = \text{"PPA-IOT-HOP2-AGGREGATOR-V1"}$.

### 3.3 Decryptor Metadata Audit
Before executing scalar multiplications, the Decryptor verifies:
1. $\text{HMAC-Verify}(K_{\text{decryptor}}, \text{Payload}_2, \text{MAC}_2) == \text{True}$
2. $\text{Epoch} \ge \text{last\_seen\_epoch}$
3. $\text{HammingWeight}(\text{Bitmask}) == N$
4. $N_{\min} \le N \le |U|$

---

## 4. Functions Implemented

- `build_bitmask(reporting_sensor_ids, sensor_universe) -> bytes` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `count_bitmask_sensors(bitmask: bytes) -> int` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `decode_bitmask_sensors(bitmask: bytes, sensor_universe) -> List[str]` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `compute_hop1_mac(...) -> bytes` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `verify_hop1_mac(...) -> bool` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `compute_hop2_mac(...) -> bytes` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `verify_hop2_mac(...) -> bool` ([authentication.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/authentication.py))
- `SensorNode`, `Aggregator`, `Decryptor` classes ([protocol.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/protocol.py))

---

## 5. Security Attack Mitigation Matrix

| Scenario | Attack Type | Tampered Field | Result | Mechanism |
|---|---|---|---|---|
| 1 | Baseline Normal | None | Accepted | Valid Hop-1 & Hop-2 MACs |
| 2 | Man-in-the-Middle | Ciphertext $C_2 \to C_2 + G$ | Rejected | Hop-1 MAC validation failure |
| 3 | Forgery Attempt | Random 32-byte MAC | Rejected | Hop-1 MAC validation failure |
| 4 | Replay Attack | Old packet retransmitted | Rejected | Stale sequence number policy |
| 5 | Sequence Rollback | $\text{Seq} \le \text{last\_seq}$ | Rejected | Strict monotonic sequence policy |
| 6 | Gateway Forgery | Altered aggregate MAC | Rejected | Hop-2 MAC validation failure |
| 7 | Metadata Tampering | Injected $N+5$ count | Rejected | Bitmask Hamming weight audit |
| 8 | Key Confusion | Sensor 1 verified with Sensor 2 key | Rejected | Independent per-sensor keys |

---

## 6. Diagram & Graph References

- **Diagram C:** [Two-Hop Authentication Sequence](figures/diagram_c_authentication.png) illustrates the message exchange, replay checks, and metadata verification.
- **Graph 5:** [Protocol Security Validation Audit](figures/graph5_protocol_validation.png) summarizes the 100% enforcement rate across all 8 security attack test suites.

---

## 7. Fundamental Security Limitation

> [!WARNING]
> **HMAC Authenticates Provenance, Not Mathematical Truth:**
> The Hop-2 HMAC guarantees that the aggregate packet was packaged by the authorized Aggregator possessing $K_{\text{decryptor}}$, and that the ciphertext points and metadata were not altered in transit.
>
> However, HMAC **cannot prove** that the Aggregator performed the correct elliptic curve addition ($C_{1, \text{agg}} = \sum C_{1, i}$). An adversarial Aggregator possessing the Hop-2 key could inject a false ciphertext into the sum while still generating a valid Hop-2 MAC. Preventing this requires Zero-Knowledge Proofs (e.g., ZK-SNARKs or verifiable computation), which are outside the scope of lightweight IoT protocols.

---

## 8. Verification & Completed Boundaries

- **Verified:** Complete two-hop HMAC pipeline, replay filter, sequence tracking, bitmask audit, and attack mitigations.
- **Incomplete / Deferred:** Physical hardware networking (ESP-IDF MQTT stack scheduled for Month 4).
