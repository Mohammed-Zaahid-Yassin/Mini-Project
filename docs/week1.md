# Week 1 Implementation Report: EC Lifted ElGamal & Fixed-Point Encoding

## 1. Objectives

1. Initialize the NIST P-256 (secp256r1) elliptic curve using `fastecdsa`.
2. Implement a fixed-point temperature encoder matching C99 `lroundf()` behavior for $T \in [-40.0^\circ\text{C}, 80.0^\circ\text{C}]$.
3. Implement a corresponding decoding function converting encoded integers back to temperatures.
4. Implement secure keypair generation $(x, Y = xG)$ using a CSPRNG.
5. Implement EC Lifted ElGamal encryption: $C_1 = rG$, $C_2 = MG + rY$.
6. Establish canonical 65-byte SEC1 point serialization.
7. Provide a single-ciphertext decryption point computation $P = C_2 - xC_1 = MG$.

---

## 2. Plain-English Explanation

You cannot directly encrypt a fractional measurement like $23.5^\circ\text{C}$ on an elliptic curve because curves only understand whole numbers. We first shift the temperature by adding $+50.0$ (turning negative temperatures into positive ones) and multiply by $10.0$ to turn tenths of a degree into whole numbers. For example, $23.5^\circ\text{C}$ becomes $735$.

Next, we place this number inside a cryptographic digital lockbox using two points on a graph ($C_1$ and $C_2$). $C_1$ acts as a randomized blinding point, while $C_2$ masks our temperature point using the receiver's public key. The receiver uses their secret private key to peel away the blinding layer, leaving the pure encrypted temperature point.

---

## 3. Mathematical Explanation

### 3.1 Encoding
$$M = \text{round\_away\_from\_zero}((T + 50.0) \times 10.0)$$
Input domain: $T \in [-40.0, 80.0] \subset \mathbb{R}$
Output range: $M \in [100, 1300] \subset \mathbb{Z}$

### 3.2 Inversion
$$T = \frac{M - 500}{10.0}$$

### 3.3 Lifted ElGamal Encryption
- Private key: $x \in_R [1, q - 1]$
- Public key: $Y = x \cdot G$
- Fresh ephemeral scalar: $r \in_R [1, q - 1]$
- Blinding point: $C_1 = r \cdot G$
- Masked message: $C_2 = M \cdot G + r \cdot Y$

### 3.4 Decryption Point
$$P = C_2 - x \cdot C_1 = M \cdot G + r(x \cdot G) - x(r \cdot G) = M \cdot G$$

---

## 4. Functions Implemented

- `round_away_from_zero(val: float) -> int` ([encoding.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/encoding.py))
- `encode_temperature(temperature: float) -> int` ([encoding.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/encoding.py))
- `decode_temperature(encoded_m: int) -> float` ([encoding.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/encoding.py))
- `generate_keypair() -> Tuple[int, Point]` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `validate_keypair(private_key: int, public_key: Point) -> bool` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `encrypt(encoded_m: int, public_key: Point) -> Ciphertext` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `decrypt_point(ciphertext: Ciphertext, private_key: int) -> Point` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `point_to_bytes(pt: Point) -> bytes` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `bytes_to_point(data: bytes) -> Point` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))

---

## 5. Important Code Walkthrough

### Worked Example: 23.5°C
```python
# 1. Physical temperature
temp = 23.5

# 2. Fixed-point encoding
m = encode_temperature(temp)  # Returns 735

# 3. Key generation
private_key, public_key = generate_keypair()

# 4. Encryption with fresh ephemeral scalar r
ciphertext = encrypt(m, public_key)
# ciphertext.c1 is r * G (65 bytes SEC1)
# ciphertext.c2 is 735 * G + r * Y (65 bytes SEC1)

# 5. Point unmasking
p_decrypted = decrypt_point(ciphertext, private_key)
assert p_decrypted == (735 * G)
```

---

## 6. Diagram & Graph References

- **Graph 1:** [Fixed-Point Encoding Linearity](figures/graph1_fixed_point_encoding.png) demonstrates exact linearity from $-40.0^\circ\text{C}$ ($M=100$) to $80.0^\circ\text{C}$ ($M=1300$).
- **Graph 2:** [Quantization Error](figures/graph2_quantization_error.png) confirms error is bounded within $\pm 0.05^\circ\text{C}$.
- **Diagram B:** [Mathematical Derivation](figures/diagram_b_mathematics.png) illustrates the transformation pipeline.

---

## 7. Test Cases & Real Outcomes

Executed via `pytest tests/test_encoding.py tests/test_encryption.py`:
- `TestRoundAwayFromZero`: Halfway positive ($2.5 \to 3$), halfway negative ($-2.5 \to -3$), and divergence from Python's Banker's rounding: **PASSED**.
- `TestTemperatureEncoding`: Boundaries ($-40^\circ\text{C} \to 100$, $80^\circ\text{C} \to 1300$), 23.5°C worked example ($M=735$), out-of-range rejection: **PASSED**.
- `TestKeyGeneration`: Validates $Y = xG$, private key range, and non-identity public key: **PASSED**.
- `TestLiftedElGamalEncryption`: Nonce freshness (two encryptions of same plaintext produce distinct points), unmasking $P == MG$: **PASSED**.
- `TestPointSerialization`: Canonical 65-byte roundtrip for generator $G$, random points, and Point at Infinity: **PASSED**.

---

## 8. Common Mistakes to Avoid

1. **Using Python's built-in `round()`:** Rounding $2.5$ gives $2$ in Python, but $3$ in C99 `lroundf()`. This discrepancy breaks discrete-log recovery on boundary inputs.
2. **Reusing the ephemeral scalar $r$:** If two ciphertexts use the same $r$, $C_{2, a} - C_{2, b} = (M_a - M_b)G$, completely compromising plaintext privacy.
3. **Printing private keys in logs:** Never expose secret scalar $x$.

---

## 9. Verification & Completed Boundaries

- **Verified:** Complete parity of encoding, key generation, encryption, serialization, and point unmasking.
- **Incomplete / Deferred:** Discrete logarithm solving (BSGS in Week 5, Pollard's Kangaroo in Week 6).
