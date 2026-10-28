# Week 2 Implementation Report: Homomorphic Aggregation & Interval Shifting

## 1. Objectives

1. Implement `aggregate_ciphertexts()` to combine multiple Lifted ElGamal ciphertexts using elliptic curve point addition.
2. Implement `decrypt_aggregate_point()` to compute $P = C_{2, \text{agg}} - x \cdot C_{1, \text{agg}}$.
3. Implement `apply_interval_shift()` to perform baseline correction for $N$ sensors: $P_{\text{shifted}} = P - (100 \cdot N) \cdot G$.
4. Implement a candidate-sum verification interface to validate decrypted points without claiming automated discrete logarithm recovery.
5. Provide a multi-sensor demonstration showing that aggregation conceals individual readings from the aggregator.

---

## 2. Plain-English Explanation

Imagine $N$ sensors each place their temperature reading inside a locked digital vault. When the untrusted edge server (the aggregator) receives all $N$ vaults, it does not have the key to open any of them. Instead, thanks to the magic of elliptic curve homomorphic encryption, the aggregator can "fuse" all the vaults together.

When the final decryptor uses its master key on this single fused vault, it opens to reveal the **sum** of all the numbers inside, while neither the aggregator nor the network ever learned what any individual sensor reported.

To make it much easier to find the final answer later on, the decryptor subtracts the lowest possible starting number ($100 \times N$). This shifts the math so the answer starts at zero.

---

## 3. Mathematical Explanation

### 3.1 Ciphertext Addition
Given $N$ ciphertexts $\text{CT}_i = (C_{1, i}, C_{2, i})$:

$$C_{1, \text{agg}} = \sum_{i=1}^N C_{1, i} = \left(\sum_{i=1}^N r_i\right) \cdot G$$

$$C_{2, \text{agg}} = \sum_{i=1}^N C_{2, i} = \left(\sum_{i=1}^N M_i\right) \cdot G + \left(\sum_{i=1}^N r_i\right) \cdot Y$$

### 3.2 Decryption Unmasking
Using private key $x$ (where $Y = x \cdot G$):

$$P = C_{2, \text{agg}} - x \cdot C_{1, \text{agg}} = M_{\text{sum}} \cdot G$$

### 3.3 Interval Shifting (Baseline Correction)
Because $M_i \in [100, 1300]$, the minimum possible sum for $N$ sensors is $100 \cdot N$.
Subtracting the baseline point:

$$P_{\text{shifted}} = P - (100 \cdot N) \cdot G = (M_{\text{sum}} - 100 \cdot N) \cdot G = k \cdot G$$

Where $k \in [0, 1200 \cdot N]$.

---

## 4. Functions Implemented

- `aggregate_ciphertexts(ciphertexts: Sequence[Ciphertext]) -> Ciphertext` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))
- `decrypt_aggregate_point(aggregate_ciphertext: Ciphertext, private_key: int) -> Point` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))
- `apply_interval_shift(decrypted_point: Point, n_sensors: int) -> Point` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))
- `verify_candidate_sum(p_shifted: Point, candidate_m_sum: int, n_sensors: int) -> bool` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))
- `decode_temperature_sum(encoded_m_sum: int, n_sensors: int) -> float` ([encoding.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/encoding.py))

---

## 5. Important Code Walkthrough

```python
# Multi-sensor simulation
readings = [18.2, 22.0, 25.4, 30.1, -12.5]
ciphertexts = [encrypt(encode_temperature(t), public_key) for t in readings]

# Aggregator (Blind addition)
agg_ct = aggregate_ciphertexts(ciphertexts)

# Decryptor (Unmasking)
p_dec = decrypt_aggregate_point(agg_ct, private_key)

# Interval shift for N=5
p_shifted = apply_interval_shift(p_dec, n_sensors=5)

# Verification against ground truth sum
ref_sum = sum(encode_temperature(t) for t in readings)  # 3332
assert verify_candidate_sum(p_shifted, candidate_m_sum=ref_sum, n_sensors=5) is True
```

---

## 6. Diagram & Graph References

- **Diagram B:** [Mathematical Derivation](figures/diagram_b_mathematics.png) shows Steps 4, 5, and 6 connecting ciphertext accumulation to unmasking and interval shifting.
- **Graph 3:** [Aggregation Correctness Across Scales](figures/graph3_aggregation_correctness.png) confirms exact 100% mathematical match between decrypted point $P$ and reference sum across $N \in [1, 100]$.

---

## 7. Test Cases & Real Outcomes

Executed via `pytest tests/test_aggregation.py`:
- `test_single_ciphertext_aggregation`: Validates aggregation on $N=1$: **PASSED**.
- `test_multi_sensor_aggregation`: Accumulates 4 sensors, unmasks $P$, verifies $(M_{\text{sum}} \cdot G)$: **PASSED**.
- `test_interval_shift_correctness`: Verifies $(1500 - 300) \cdot G = 1200 \cdot G$: **PASSED**.
- `test_verify_candidate_sum`: Confirms candidate verification returns True for valid sum and False for $M_{\text{sum}} \pm 1$: **PASSED**.
- `test_empty_sequence_raises`: Rejects empty ciphertext collections: **PASSED**.

---

## 8. Common Mistakes to Avoid

1. **Confusing point addition with integer scalar addition:** In elliptic curve cryptography, adding points requires group addition formulas involving modular slope arithmetic ($\lambda = (y_2 - y_1)/(x_2 - x_1)$), not ordinary integer addition.
2. **Claiming automated discrete-log recovery:** Weeks 1–4 deliberately do not implement BSGS or Kangaroo. Candidate verification proves group-theoretic correctness without faking algorithmic inversion.

---

## 9. Verification & Completed Boundaries

- **Verified:** Homomorphic ciphertext addition, unmasking, interval shifting, and candidate verification across arbitrary sensor counts.
- **Incomplete / Deferred:** Solving the bounded discrete logarithm without prior knowledge of the candidate sum.
