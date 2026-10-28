# Week 3 Implementation Report: Interval Shifting & Point at Infinity Edge Cases

## 1. Objectives

1. Implement an explicit, library-compatible `is_infinity()` check for `fastecdsa`.
2. Implement and test the edge case where all $N$ sensors report the minimum temperature ($-40.0^\circ\text{C}$).
3. Mathematically prove and verify that all minimum-bound readings yield $P_{\text{shifted}} = \mathcal{O}$ (the Point at Infinity).
4. Provide a short-circuit return path recovering $M_{\text{sum}} = 100 \cdot N$ and $T_{\text{avg}} = -40.0^\circ\text{C}$ with zero search latency.
5. Verify upper-bound telemetry (all $80.0^\circ\text{C}$ readings produce $P_{\text{shifted}} = (1200 \cdot N) \cdot G$).
6. Provide extensive test coverage for single-sensor, multi-sensor, mixed boundaries, and defensive parameter validation.

---

## 2. Plain-English Explanation

In ordinary math, if you start at $500$ and subtract $500$, you get zero. But in elliptic curve math, "zero" is not an ordinary coordinate $(x, y)$. It is an abstract concept called the **Point at Infinity** ($\mathcal{O}$). It acts like the black hole of elliptic curve equations.

If all $10$ sensors report the coldest possible temperature ($-40^\circ\text{C}$), our baseline correction formula zeroes out. If our code didn't know about this "black hole," future search algorithms would try to compute divisions by zero and crash. By checking for the Point at Infinity first, we can immediately declare the answer without running any slow search algorithm at all.

---

## 3. Mathematical Explanation

### 3.1 Lower-Bound Derivation
When every sensor reports $T_i = -40.0^\circ\text{C}$:
$$M_i = \text{round}((-40.0 + 50.0) \times 10.0) = 100$$
For $N$ sensors:
$$M_{\text{sum}} = \sum_{i=1}^N 100 = 100 \cdot N$$

The decrypted unmasked point is:
$$P = (100 \cdot N) \cdot G$$

The interval shift subtracts the baseline $(100 \cdot N) \cdot G$:
$$P_{\text{shifted}} = P - (100 \cdot N) \cdot G = (100 \cdot N - 100 \cdot N) \cdot G = 0 \cdot G = \mathcal{O}$$

### 3.2 Upper-Bound Derivation
When every sensor reports $T_i = 80.0^\circ\text{C}$:
$$M_i = \text{round}((80.0 + 50.0) \times 10.0) = 1300$$
$$M_{\text{sum}} = 1300 \cdot N$$

The interval shift yields:
$$P_{\text{shifted}} = (1300 \cdot N - 100 \cdot N) \cdot G = (1200 \cdot N) \cdot G$$

### 3.3 Search Interval
The shifted scalar $k$ satisfies:
$$k \in [0, \, 1200 \cdot N]$$
When $k = 0$, $P_{\text{shifted}} = \mathcal{O}$.
When $k > 0$, $P_{\text{shifted}}$ is a valid affine point on the P-256 curve.

---

## 4. Functions Implemented

- `is_infinity(pt: Point) -> bool` ([elgamal.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/elgamal.py))
- `handle_infinity_edge_case(p_shifted: Point, n_sensors: int) -> Tuple[bool, Optional[int], Optional[float]]` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))
- `apply_interval_shift(decrypted_point: Point, n_sensors: int) -> Point` ([aggregation.py](file:///d:/College%20stuff/Mini%20Project/Codebase/src/aggregation.py))

---

## 5. Important Code Walkthrough

```python
# Handling the Point at Infinity in Decryptor
p_shifted = apply_interval_shift(p_decrypted, n_sensors)

is_inf, recovered_m_sum, recovered_avg = handle_infinity_edge_case(p_shifted, n_sensors)
if is_inf:
    # Lower bound hit: All sensors reported -40.0°C!
    # No Pollard's Kangaroo or BSGS search needed
    return True, recovered_m_sum, recovered_avg
```

---

## 6. Diagram & Graph References

- **Diagram D:** [Point at Infinity Edge Case](figures/diagram_d_infinity_edge_case.png) shows the branch between the immediate return path ($k=0$) and downstream discrete logarithm search ($k > 0$).
- **Graph 4:** [Edge-Case Boundaries](figures/graph4_edge_case_boundaries.png) compares $k = 0$ ($\mathcal{O}$), intermediate values, and upper-bound $k = 12,000$ for $N=10$.

---

## 7. Test Cases & Real Outcomes

Executed via `pytest tests/test_edge_cases.py`:
- `test_single_sensor_minimum_boundary`: $N=1$, $T=-40^\circ\text{C} \implies P_{\text{shifted}} = \mathcal{O}$: **PASSED**.
- `test_multi_sensor_all_minimum_boundary`: Parameterized for $N \in [2, 5, 10]$: **PASSED**.
- `test_all_maximum_boundary_80_degrees`: $N=5$, $T=80^\circ\text{C} \implies P_{\text{shifted}} = 6000 \cdot G$: **PASSED**.
- `test_mixed_boundary_conditions`: 2 sensors at $-40^\circ\text{C}$ and 2 at $80^\circ\text{C}$: **PASSED**.
- `test_invalid_interval_shift_parameters`: $N \le 0$ raises ValueError: **PASSED**.

---

## 8. Common Mistakes to Avoid

1. **Treating $\mathcal{O}$ as a program crash or division by zero:** In group theory, $\mathcal{O}$ is the valid additive identity ($P + \mathcal{O} = P$). It must be handled as a legitimate mathematical state.
2. **Missing the short-circuit opportunity:** Attempting to feed $\mathcal{O}$ into BSGS or Kangaroo would cause affine conversion failures; checking for $\mathcal{O}$ eliminates search overhead entirely.

---

## 9. Verification & Completed Boundaries

- **Verified:** Complete handling of lower bound $\mathcal{O}$, upper bound $(1200 \cdot N) \cdot G$, and mixed boundary conditions.
- **Incomplete / Deferred:** Bounded discrete logarithm search for arbitrary non-identity points $k \in [1, 1200 \cdot N]$.
