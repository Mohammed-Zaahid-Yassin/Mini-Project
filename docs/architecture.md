# System Architecture: Privacy-Preserving IoT Telemetry Aggregation

## 1. Architectural Overview

This research project benchmarks bounded discrete logarithm recovery for privacy-preserving IoT sensor aggregation. In large-scale IoT deployments (e.g., smart agriculture, smart cities, environmental monitoring), battery-constrained microcontrollers like the ESP32 periodically transmit telemetry to an edge aggregator.

The system is organized into a three-tier logical hierarchy:

```
[ Tier 1: Sensor Nodes ]  ===( Hop-1: Authenticated Ciphertext )===>  [ Tier 2: Untrusted Aggregator ]
                                                                                   ||
                                                                          ( Hop-2: Authenticated
                                                                            Aggregate Packet )
                                                                                   ||
                                                                                   v
                                                                      [ Tier 3: Trusted Decryptor ]
```

![Diagram A: Overall Architecture](figures/diagram_a_architecture.png)

---

## 2. Component Specifications

### 2.1 Tier 1: Simulated Sensor Nodes (ESP32)

Each sensor node represents an embedded microcontroller connected to an environmental sensor (such as a DHT22 or SHT3x).

- **Data Capture:** Measures temperature $T \in [-40.0^\circ\text{C}, 80.0^\circ\text{C}]$.
- **Fixed-Point Encoding:** Converts decimal temperature into a positive integer scalar:
  $$M = \text{round\_away\_from\_zero}((T + 50.0) \times 10.0)$$
- **Lifted ElGamal Encryption:** Samples fresh ephemeral scalar $r \in [1, q-1]$ using OS CSPRNG and computes:
  $$C_1 = r \cdot G, \quad C_2 = M \cdot G + r \cdot Y$$
- **Hop-1 Message Authentication:** Signs the payload with secret symmetric key $K_{\text{sensor}, i}$ using HMAC-SHA256:
  $$\text{MAC}_1 = \text{HMAC-SHA256}(K_{\text{sensor}, i}, \text{Domain}_1 \parallel \text{SensorID} \parallel C_1 \parallel C_2 \parallel \text{Seq} \parallel \text{Epoch})$$
- **State Maintained:** Strictly monotonic sequence counter $\text{Seq}_i$.

### 2.2 Tier 2: Untrusted Aggregator (Edge Gateway / Broker)

The aggregator acts as an intermediate middleman (e.g., local server or MQTT broker) that collects telemetry across a network epoch.

- **Trust Posture:** Untrusted with respect to data confidentiality. The aggregator possesses neither the decryption private key $x$ nor individual sensor readings $M_i$.
- **Hop-1 Verification:** Validates incoming sensor packets:
  1. Sensor identity enrollment verification.
  2. Epoch freshness check ($\text{Epoch} == \text{CurrentEpoch}$).
  3. Replay protection ($\text{Seq} > \text{last\_seq}[\text{sensor\_id}]$).
  4. Constant-time HMAC comparison using `hmac.compare_digest()`.
- **Homomorphic Ciphertext Aggregation:** Performs elliptic curve point addition blindly:
  $$C_{1, \text{agg}} = \sum_{i=1}^N C_{1, i}, \quad C_{2, \text{agg}} = \sum_{i=1}^N C_{2, i}$$
- **Metadata Generation:**
  - Active count $N$ of participating sensors.
  - Participation Bitmask: Bytearray of length $\lceil U / 8 \rceil$ indicating active sensors in universe $U$.
- **Hop-2 Message Authentication:** Authenticates aggregate payload for the Decryptor:
  $$\text{MAC}_2 = \text{HMAC-SHA256}(K_{\text{decryptor}}, \text{Domain}_2 \parallel C_{1, \text{agg}} \parallel C_{2, \text{agg}} \parallel N \parallel \text{Epoch} \parallel \text{Bitmask})$$

### 2.3 Tier 3: Trusted Decryptor (Central Sink / Institution)

The decryptor represents the authorized recipient possessing the master private key $x$.

- **Hop-2 Verification & Metadata Audit:**
  1. Constant-time HMAC check with $K_{\text{decryptor}}$.
  2. Epoch monotonicity ($\text{Epoch} \ge \text{last\_seen\_epoch}$).
  3. Bitmask consistency: $\text{HammingWeight}(\text{Bitmask}) == N$.
  4. Quorum validation: $N_{\min} \le N \le N_{\max}$.
- **Decryption Unmasking:** Computes the decrypted elliptic curve point:
  $$P = C_{2, \text{agg}} - x \cdot C_{1, \text{agg}} = \left(\sum_{i=1}^N M_i\right) \cdot G$$
- **Interval Shifting (Baseline Correction):** Narrowing the discrete log search interval by subtracting the minimum baseline $(100 \cdot N) \cdot G$:
  $$P_{\text{shifted}} = P - (100 \cdot N) \cdot G = \left(M_{\text{sum}} - 100 \cdot N\right) \cdot G = k \cdot G$$
- **Edge-Case Detection:** If $P_{\text{shifted}} == \mathcal{O}$ (Point at Infinity), immediately short-circuits recovery to $M_{\text{sum}} = 100 \cdot N$, yielding $T_{\text{avg}} = -40.0^\circ\text{C}$ with zero latency.
- **Candidate Verification (Weeks 1–4 Interface):** Verifies reference candidates against $P_{\text{shifted}}$ prior to bounded-DLP search implementation in Weeks 5+.

---

## 3. Protocol Message Formats

### 3.1 Hop-1 Packet Structure

| Field | Size | Encoding / Type | Description |
|---|---|---|---|
| Domain Tag | 23 bytes | ASCII string | `PPA-IOT-HOP1-SENSOR-V1` |
| Sensor ID Length | 2 bytes | uint16 big-endian | Length $L$ of Sensor ID string |
| Sensor ID | $L$ bytes | UTF-8 string | Identity of transmitting sensor node |
| $C_1$ | 65 bytes | SEC1 uncompressed | Ephemeral blinding point $r \cdot G$ |
| $C_2$ | 65 bytes | SEC1 uncompressed | Masked message point $M \cdot G + r \cdot Y$ |
| Sequence Number | 8 bytes | uint64 big-endian | Monotonically increasing per-sensor counter |
| Epoch Identifier | 8 bytes | uint64 big-endian | Time window index |
| Hop-1 MAC | 32 bytes | Binary | HMAC-SHA256 authentication tag |

### 3.2 Hop-2 Aggregate Packet Structure

| Field | Size | Encoding / Type | Description |
|---|---|---|---|
| Domain Tag | 27 bytes | ASCII string | `PPA-IOT-HOP2-AGGREGATOR-V1` |
| $C_{1, \text{agg}}$ | 65 bytes | SEC1 uncompressed | Homomorphically aggregated $C_1$ points |
| $C_{2, \text{agg}}$ | 65 bytes | SEC1 uncompressed | Homomorphically aggregated $C_2$ points |
| Sensor Count $N$ | 4 bytes | uint32 big-endian | Count of valid contributing sensors |
| Epoch Identifier | 8 bytes | uint64 big-endian | Time window index |
| Bitmask Length | 2 bytes | uint16 big-endian | Byte length $B = \lceil U / 8 \rceil$ of bitmask |
| Participation Bitmask | $B$ bytes | Binary bitfield | Active sensor flags ($i$-th bit = 1 if sensor $i$ reported) |
| Hop-2 MAC | 32 bytes | Binary | HMAC-SHA256 authentication tag |

---

## 4. Security Domain Separation

```
[ Sensor 1 (Key K_1) ] ---> \
[ Sensor 2 (Key K_2) ] --->  |--> [ Aggregator ] ===( Key K_decryptor )===> [ Decryptor (Private Key x) ]
[ Sensor 3 (Key K_3) ] ---> /
```

1. **Independent Sensor Keys:** Each sensor possesses a distinct symmetric key $K_i$. Compromising Sensor 1 does not compromise Sensor 2 or allow forging telemetry under Sensor 2's identity.
2. **Aggregator Domain Separation:** The aggregator signs Hop-2 with $K_{\text{decryptor}}$. Sensor keys cannot authenticate Hop-2 aggregates, and the decryptor key cannot verify Hop-1 packets.
3. **Master Key Isolation:** Only the Decryptor holds the elliptic curve scalar private key $x$. Neither the Aggregator nor the Sensor nodes have access to $x$.
