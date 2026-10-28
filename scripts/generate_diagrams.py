"""
Generates Mermaid source files and renders high-resolution architecture diagrams.
Outputs:
- docs/figures/diagram_a_architecture.mmd & .png
- docs/figures/diagram_b_mathematics.mmd & .png
- docs/figures/diagram_c_authentication.mmd & .png
- docs/figures/diagram_d_infinity_edge_case.mmd & .png
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches


MERMAID_DIAGRAM_A = """graph LR
    %% Three-Tier Architecture for Privacy-Preserving IoT Telemetry (Weeks 1-4 Simulation)
    
    subgraph Tier1["TIER 1: Simulated Sensor Node (ESP32)"]
        direction TB
        T1_Sense["Temperature Sensor<br/>T in [-40.0°C, 80.0°C]"]
        T1_Encode["Fixed-Point Encoder<br/>M = round_away_from_zero((T+50)*10)<br/>M in [100, 1300]"]
        T1_Encrypt["Lifted ElGamal Encryptor<br/>Fresh CSPRNG scalar r<br/>C1 = r*G, C2 = M*G + r*Y"]
        T1_Auth["Hop-1 Authenticator (HMAC-SHA256)<br/>Key: K_sensor_i<br/>MAC(K_sensor_i, C1||C2||Seq||Epoch)"]
        
        T1_Sense --> T1_Encode --> T1_Encrypt --> T1_Auth
    end

    subgraph Tier2["TIER 2: Untrusted Aggregator (PC/Gateway)"]
        direction TB
        T2_Verify["Hop-1 Verifier & Filter<br/>Constant-time HMAC check<br/>Replay filter (Seq > last_seq)<br/>Epoch freshness check"]
        T2_Agg["Homomorphic EC Accumulator<br/>C1_agg = sum(C1_i)<br/>C2_agg = sum(C2_i)<br/>(Individual ciphertexts hidden)"]
        T2_Meta["Metadata Generator<br/>N = active sensor count<br/>Participation Bitmask"]
        T2_Auth["Hop-2 Authenticator (HMAC-SHA256)<br/>Key: K_decryptor<br/>MAC(K_dec, C1_agg||C2_agg||N||Epoch||Mask)"]
        
        T2_Verify --> T2_Agg --> T2_Meta --> T2_Auth
    end

    subgraph Tier3["TIER 3: Trusted Decryptor (Server/Sink)"]
        direction TB
        T3_Verify["Hop-2 Verifier & Metadata Audit<br/>Constant-time HMAC check<br/>Epoch monotonicity check<br/>Bitmask Hamming weight == N"]
        T3_Decrypt["Point Unmasking (Holds Private Key x)<br/>P = C2_agg - x * C1_agg<br/>P = M_sum * G"]
        T3_Shift["Interval Shifting (Baseline Correction)<br/>P_shifted = P - (100*N)*G<br/>Maps sum to [0, 1200*N]*G"]
        T3_Edge["Edge-Case & Candidate Verifier<br/>If P_shifted == O: M_sum = 100*N<br/>Else: Verify candidate k*G == P_shifted"]
        
        T3_Verify --> T3_Decrypt --> T3_Shift --> T3_Edge
    end

    T1_Auth ==>|"Authenticated Hop-1 Packet<br/>(SensorID, C1, C2, Seq, Epoch, MAC1)"| T2_Verify
    T2_Auth ==>|"Authenticated Hop-2 Packet<br/>(C1_agg, C2_agg, N, Epoch, Bitmask, MAC2)"| T3_Verify

    %% Styling & Roles
    classDef sensor fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    classDef agg fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef dec fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
    class T1_Sense,T1_Encode,T1_Encrypt,T1_Auth sensor;
    class T2_Verify,T2_Agg,T2_Meta,T2_Auth agg;
    class T3_Verify,T3_Decrypt,T3_Shift,T3_Edge dec;
"""

MERMAID_DIAGRAM_B = """graph TD
    %% Mathematical Flowchart: Plaintext to Shifted Decrypted Point
    
    subgraph S_Inputs["1. Physical Sensor Readings"]
        T_vals["Temperatures: T_1, T_2, ..., T_N in [-40°C, 80°C]"]
    end

    subgraph S_Encoding["2. Fixed-Point Encoding (C99 lroundf)"]
        M_vals["Scalars: M_i = round_away_from_zero((T_i + 50.0) * 10.0)<br/>M_i in [100, 1300]"]
        T_vals --> M_vals
    end

    subgraph S_Encryption["3. EC Lifted ElGamal Encryption"]
        CT_vals["Ciphertexts: CT_i = (C1_i, C2_i)<br/>C1_i = r_i * G<br/>C2_i = M_i * G + r_i * Y"]
        M_vals --> CT_vals
    end

    subgraph S_Aggregation["4. Homomorphic Aggregation (Untrusted Middleman)"]
        AGG_vals["Aggregate Ciphertext:<br/>C1_agg = sum(C1_i) = (sum r_i) * G<br/>C2_agg = sum(C2_i) = (sum M_i) * G + (sum r_i) * Y"]
        CT_vals --> AGG_vals
    end

    subgraph S_Decryption["5. Unmasking via Decryptor Private Key x"]
        P_val["Decrypted Curve Point:<br/>P = C2_agg - x * C1_agg<br/>P = (sum M_i) * G = M_sum * G"]
        AGG_vals --> P_val
    end

    subgraph S_Shift["6. Interval Shifting (Baseline Correction)"]
        P_shift["Shifted Point:<br/>P_shifted = P - (100 * N) * G<br/>P_shifted = (M_sum - 100 * N) * G = k * G<br/>k in [0, 1200 * N]"]
        P_val --> P_shift
    end

    subgraph S_Verification["7. Recovery / Verification Phase"]
        Inf_Branch{"Is P_shifted == O?"}
        Inf_Yes["Point at Infinity Lower Bound<br/>k = 0 -> M_sum = 100 * N<br/>Avg Temp = -40.0°C (Immediate recovery)"]
        Inf_No["Bounded ECDLP Target (Weeks 1-4 Candidate Verification)<br/>Check P_shifted == (candidate_M_sum - 100*N) * G"]
        
        P_shift --> Inf_Branch
        Inf_Branch -->|Yes| Inf_Yes
        Inf_Branch -->|No| Inf_No
    end
"""

MERMAID_DIAGRAM_C = """sequenceDiagram
    autonumber
    actor Sensor as Sensor Node i (ESP32 Sim)
    actor Aggregator as Untrusted Aggregator (PC Sim)
    actor Decryptor as Trusted Decryptor (Sink Sim)

    Note over Sensor: Encode: M_i = round((T_i+50)*10)<br/>Encrypt: C1_i=r*G, C2_i=M_i*G+r*Y<br/>Seq_i = Seq_i + 1
    Note over Sensor: Hop-1 MAC = HMAC(K_sensor_i, C1||C2||Seq||Epoch)
    Sensor->>Aggregator: SensorPacket (ID_i, C1_i, C2_i, Seq_i, Epoch, MAC1)

    Note over Aggregator: 1. Verify ID_i enrolled<br/>2. Verify Epoch freshness<br/>3. Verify Seq_i > last_seq[i] (Replay Check)<br/>4. Verify HMAC constant-time
    alt Invalid Hop-1 Check
        Aggregator-->>Sensor: Drop packet (log rejection reason)
    else Valid Packet
        Note over Aggregator: Accept packet & update last_seq[i]<br/>Accumulate: C1_agg += C1_i, C2_agg += C2_i<br/>Update Bitmask: set bit i = 1
    end

    Note over Aggregator: Epoch Closes (N valid sensors)<br/>Hop-2 MAC = HMAC(K_dec, C1_agg||C2_agg||N||Epoch||Bitmask)
    Aggregator->>Decryptor: AggregatePacket (C1_agg, C2_agg, N, Epoch, Bitmask, MAC2)

    Note over Decryptor: 1. Verify Hop-2 HMAC constant-time<br/>2. Verify Epoch >= last_seen_epoch<br/>3. Verify Bitmask length & HammingWeight(Bitmask) == N<br/>4. Verify Quorum bounds
    alt Invalid Hop-2 Check
        Note over Decryptor: Reject Aggregate & Halt
    else Valid Aggregate
        Note over Decryptor: Unmask: P = C2_agg - x * C1_agg<br/>Shift: P_shifted = P - (100*N)*G<br/>Check Edge Case: P_shifted == O?<br/>Verify Candidate Plaintext Sum
    end
"""

MERMAID_DIAGRAM_D = """graph TD
    %% Point at Infinity Edge Case Flow
    
    StartNode["N Sensors Report Telemetry"] --> Readings{"What did sensors read?"}
    
    Readings -->|"All N sensors read -40.0°C (Absolute Min)"| MinPath["All M_i = 100<br/>M_sum = 100 * N"]
    Readings -->|"Mixed or warmer readings"| NormalPath["Some M_i > 100<br/>M_sum > 100 * N"]
    Readings -->|"All N sensors read +80.0°C (Absolute Max)"| MaxPath["All M_i = 1300<br/>M_sum = 1300 * N"]

    MinPath --> DecMin["Decrypted Point: P = (100 * N) * G"]
    NormalPath --> DecNorm["Decrypted Point: P = (M_sum) * G"]
    MaxPath --> DecMax["Decrypted Point: P = (1300 * N) * G"]

    DecMin --> ShiftMin["Interval Shift: P_shifted = P - (100 * N) * G<br/>P_shifted = (100*N - 100*N) * G = 0 * G"]
    DecNorm --> ShiftNorm["Interval Shift: P_shifted = P - (100 * N) * G<br/>P_shifted = (M_sum - 100*N) * G = k * G (k > 0)"]
    DecMax --> ShiftMax["Interval Shift: P_shifted = P - (100 * N) * G<br/>P_shifted = (1200 * N) * G"]

    ShiftMin --> InfCheck{"Is P_shifted == O?<br/>(Z == 0 in Jacobian coords)"}
    ShiftNorm --> InfCheck
    ShiftMax --> InfCheck

    InfCheck -->|"YES (k = 0)"| DirectResolve["SHORT-CIRCUIT / IMMEDIATE RETURN<br/>Lower-bound triggered!<br/>Recovered M_sum = 100 * N<br/>Average Temperature = -40.0°C<br/>Bypasses DLP Search (Zero Latency)"]
    InfCheck -->|"NO (k in [1, 1200*N])"| NormalDLP["Pass to Bounded ECDLP Search Engine<br/>(Weeks 1-4: Candidate Verifier<br/>Weeks 5+: BSGS / Kangaroo)"]

    %% Styling
    classDef infNode fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef normNode fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    class DirectResolve infNode;
    class NormalDLP normNode;
"""


def render_diagram_a_image(output_path: str):
    """Renders Diagram A using matplotlib."""
    fig, ax = plt.subplots(figsize=(14, 7), dpi=300)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis("off")

    fig.suptitle(
        "Diagram A: Overall Three-Tier Architecture (Simulated IoT Telemetry)",
        fontsize=15,
        fontweight="bold",
        y=0.96,
    )
    ax.text(
        7.0,
        7.4,
        "Privacy-Preserving Homomorphic Temperature Aggregation (Weeks 1–4 Software Foundation)",
        ha="center",
        fontsize=11,
        color="#455a64",
    )

    # Box 1: Sensor ESP32
    tier1 = patches.FancyBboxPatch(
        (0.5, 0.8), 3.8, 6.2, boxstyle="round,pad=0.3", edgecolor="#0288d1", facecolor="#e1f5fe", linewidth=2
    )
    ax.add_patch(tier1)
    ax.text(2.4, 6.7, "TIER 1: SENSOR NODE (SIM)", ha="center", fontsize=11, fontweight="bold", color="#01579b")
    ax.text(
        2.4,
        4.8,
        "• DHT22 Reading: T ∈ [-40°C, 80°C]\n"
        "• Fixed-Point Encoding:\n"
        "  M = round((T + 50.0) * 10.0)\n"
        "• Lifted ElGamal Encryption:\n"
        "  Fresh CSPRNG scalar r\n"
        "  C1 = r·G\n"
        "  C2 = M·G + r·Y\n"
        "• Hop-1 HMAC-SHA256:\n"
        "  Key: Secret K_sensor_i\n"
        "  Binds SensorID, C1, C2, Seq, Epoch",
        ha="center",
        va="center",
        fontsize=9,
        family="monospace",
        color="#0d47a1",
    )

    # Box 2: Untrusted Aggregator
    tier2 = patches.FancyBboxPatch(
        (5.1, 0.8), 3.8, 6.2, boxstyle="round,pad=0.3", edgecolor="#f57c00", facecolor="#fff3e0", linewidth=2
    )
    ax.add_patch(tier2)
    ax.text(7.0, 6.7, "TIER 2: UNTRUSTED AGGREGATOR", ha="center", fontsize=11, fontweight="bold", color="#e65100")
    ax.text(
        7.0,
        4.8,
        "• Hop-1 Verification:\n"
        "  hmac.compare_digest()\n"
        "  Enforce Seq > last_seq (No Replay)\n"
        "  Enforce active Epoch\n"
        "• Homomorphic Aggregation:\n"
        "  C1_agg = Σ C1_i\n"
        "  C2_agg = Σ C2_i\n"
        "  (Never decrypts or learns M_i)\n"
        "• Metadata Generation:\n"
        "  Active Count N, Participation Bitmask\n"
        "• Hop-2 HMAC-SHA256:\n"
        "  Key: Secret K_decryptor",
        ha="center",
        va="center",
        fontsize=9,
        family="monospace",
        color="#bf360c",
    )

    # Box 3: Decryptor
    tier3 = patches.FancyBboxPatch(
        (9.7, 0.8), 3.8, 6.2, boxstyle="round,pad=0.3", edgecolor="#388e3c", facecolor="#e8f5e9", linewidth=2
    )
    ax.add_patch(tier3)
    ax.text(11.6, 6.7, "TIER 3: TRUSTED DECRYPTOR", ha="center", fontsize=11, fontweight="bold", color="#1b5e20")
    ax.text(
        11.6,
        4.8,
        "• Hop-2 Verification:\n"
        "  hmac.compare_digest()\n"
        "  Monotonic Epoch: Epoch >= last_seen\n"
        "  Bitmask Audit: Weight(Bitmask) == N\n"
        "• Point Unmasking (Master Key x):\n"
        "  P = C2_agg - x·C1_agg = M_sum·G\n"
        "• Interval Shifting:\n"
        "  P_shifted = P - (100·N)·G = k·G\n"
        "• Infinity Detection:\n"
        "  If P_shifted == O -> M_sum = 100·N\n"
        "• Known-Candidate Sum Verification",
        ha="center",
        va="center",
        fontsize=9,
        family="monospace",
        color="#1b5e20",
    )

    # Flow arrows
    ax.annotate(
        "", xy=(5.0, 3.8), xytext=(4.4, 3.8),
        arrowprops=dict(facecolor="#0288d1", edgecolor="#01579b", width=3, headwidth=9),
    )
    ax.text(4.7, 4.2, "Hop 1 Packet\n(C1, C2, Seq, Epoch, MAC)", ha="center", fontsize=8, fontweight="bold", color="#01579b")

    ax.annotate(
        "", xy=(9.6, 3.8), xytext=(9.0, 3.8),
        arrowprops=dict(facecolor="#f57c00", edgecolor="#bf360c", width=3, headwidth=9),
    )
    ax.text(9.3, 4.2, "Hop 2 Packet\n(C1_agg, C2_agg, N, Bitmask, MAC)", ha="center", fontsize=8, fontweight="bold", color="#bf360c")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def render_diagram_b_image(output_path: str):
    """Renders Diagram B (Mathematical Transformation Pipeline)."""
    fig, ax = plt.subplots(figsize=(13, 8), dpi=300)
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 8.5)
    ax.axis("off")

    fig.suptitle(
        "Diagram B: Encryption and Aggregation Mathematical Transformation Pipeline",
        fontsize=14,
        fontweight="bold",
        y=0.96,
    )
    ax.text(
        6.5, 8.0,
        "Mathematical derivation from physical telemetry to shifted decrypted elliptic curve point",
        ha="center", fontsize=10.5, color="#546e7a"
    )

    steps = [
        ("Step 1: Physical Reading", "T_i ∈ [-40.0°C, 80.0°C]", "#e3f2fd", "#1565c0", 0.5, 5.0, 3.5, 2.2),
        ("Step 2: Fixed-Point Scalar", "M_i = round((T_i + 50.0) * 10.0)\nM_i ∈ [100, 1300]", "#e8f5e9", "#2e7d32", 4.7, 5.0, 3.6, 2.2),
        ("Step 3: Lifted ElGamal", "C1_i = r_i·G\nC2_i = M_i·G + r_i·Y", "#fff3e0", "#e65100", 8.9, 5.0, 3.6, 2.2),
        ("Step 4: Homomorphic Aggregation", "C1_agg = Σ C1_i = (Σ r_i)·G\nC2_agg = Σ C2_i = (Σ M_i)·G + (Σ r_i)·Y", "#f3e5f5", "#7b1fa2", 0.5, 1.2, 3.8, 2.4),
        ("Step 5: Decryption Unmasking", "P = C2_agg - x·C1_agg\nP = (Σ M_i)·G = M_sum·G", "#e0f2f1", "#00695c", 4.7, 1.2, 3.6, 2.4),
        ("Step 6: Interval Shifting", "P_shifted = P - (100·N)·G\nP_shifted = (M_sum - 100·N)·G = k·G\nk ∈ [0, 1200·N]", "#fbe9e7", "#d84315", 8.9, 1.2, 3.6, 2.4),
    ]

    for title, formula, bg, border, x, y, w, h in steps:
        box = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25", edgecolor=border, facecolor=bg, linewidth=2)
        ax.add_patch(box)
        ax.text(x + w / 2, y + h - 0.4, title, ha="center", fontsize=10, fontweight="bold", color=border)
        ax.text(x + w / 2, y + h / 2 - 0.2, formula, ha="center", va="center", fontsize=9, family="monospace", color="#263238")

    # Connect arrows Step 1 -> 2 -> 3
    ax.annotate("", xy=(4.6, 6.1), xytext=(4.1, 6.1), arrowprops=dict(facecolor="#1565c0", width=2, headwidth=7))
    ax.annotate("", xy=(8.8, 6.1), xytext=(8.4, 6.1), arrowprops=dict(facecolor="#2e7d32", width=2, headwidth=7))
    
    # Connect Step 3 down to Step 4
    ax.annotate("", xy=(2.4, 3.7), xytext=(10.7, 4.9), arrowprops=dict(facecolor="#e65100", width=2, headwidth=7, connectionstyle="arc3,rad=-0.3"))
    
    # Connect Step 4 -> 5 -> 6
    ax.annotate("", xy=(4.6, 2.4), xytext=(4.4, 2.4), arrowprops=dict(facecolor="#7b1fa2", width=2, headwidth=7))
    ax.annotate("", xy=(8.8, 2.4), xytext=(8.4, 2.4), arrowprops=dict(facecolor="#00695c", width=2, headwidth=7))

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def render_diagram_c_image(output_path: str):
    """Renders Diagram C (Two-Hop Sequence & Security Verification)."""
    fig, ax = plt.subplots(figsize=(13, 8), dpi=300)
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 9)
    ax.axis("off")

    fig.suptitle(
        "Diagram C: Two-Hop Authentication Message Sequence & Replay Mitigation",
        fontsize=14,
        fontweight="bold",
        y=0.96,
    )
    ax.text(6.5, 8.5, "Hop 1 (Sensor -> Aggregator) & Hop 2 (Aggregator -> Decryptor) Security Lifecycle", ha="center", fontsize=10.5, color="#546e7a")

    # Three actor vertical bars
    actors = [("Sensor Node i\n(ESP32 Sim)", 2.0, "#0288d1"), ("Untrusted Aggregator\n(Gateway Sim)", 6.5, "#f57c00"), ("Trusted Decryptor\n(Sink Sim)", 11.0, "#388e3c")]
    for name, x, color in actors:
        box = patches.FancyBboxPatch((x - 1.2, 7.3), 2.4, 0.9, boxstyle="round,pad=0.15", edgecolor=color, facecolor="#ffffff", linewidth=2)
        ax.add_patch(box)
        ax.text(x, 7.75, name, ha="center", va="center", fontsize=9.5, fontweight="bold", color=color)
        ax.plot([x, x], [0.8, 7.2], color=color, linestyle="--", linewidth=1.5, alpha=0.7)

    # Sequence items
    # 1. Hop 1 transmit
    ax.annotate("", xy=(6.4, 6.2), xytext=(2.1, 6.2), arrowprops=dict(facecolor="#0288d1", edgecolor="#01579b", width=2, headwidth=7))
    ax.text(4.25, 6.4, "1. Hop-1 Packet: (SensorID, C1, C2, Seq, Epoch, MAC1)", ha="center", fontsize=8.5, fontweight="bold", color="#01579b")

    # Aggregator check box
    chk1 = patches.FancyBboxPatch((5.2, 4.7), 2.6, 1.2, boxstyle="round,pad=0.1", edgecolor="#f57c00", facecolor="#fff3e0", linewidth=1.5)
    ax.add_patch(chk1)
    ax.text(6.5, 5.3, "Hop-1 Verification:\n✓ Sensor enrolled\n✓ Epoch matches active\n✓ Seq > last_seq (No Replay)\n✓ hmac.compare_digest()", ha="center", va="center", fontsize=7.5, color="#bf360c")

    # 2. Hop 2 transmit
    ax.annotate("", xy=(10.9, 3.8), xytext=(6.6, 3.8), arrowprops=dict(facecolor="#f57c00", edgecolor="#bf360c", width=2, headwidth=7))
    ax.text(8.75, 4.0, "2. Hop-2 Packet: (C1_agg, C2_agg, N, Epoch, Bitmask, MAC2)", ha="center", fontsize=8.5, fontweight="bold", color="#bf360c")

    # Decryptor check box
    chk2 = patches.FancyBboxPatch((9.7, 1.8), 2.6, 1.6, boxstyle="round,pad=0.1", edgecolor="#388e3c", facecolor="#e8f5e9", linewidth=1.5)
    ax.add_patch(chk2)
    ax.text(11.0, 2.6, "Hop-2 Verification:\n✓ hmac.compare_digest()\n✓ Epoch >= last_seen\n✓ Weight(Bitmask) == N\n✓ Quorum [min, max]\n✓ Unmask & Interval Shift", ha="center", va="center", fontsize=7.5, color="#1b5e20")

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def render_diagram_d_image(output_path: str):
    """Renders Diagram D (Point at Infinity Edge-Case Resolution)."""
    fig, ax = plt.subplots(figsize=(12, 7.5), dpi=300)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8.5)
    ax.axis("off")

    fig.suptitle(
        "Diagram D: Point at Infinity (O) Edge Case and Short-Circuit Decision Flow",
        fontsize=14,
        fontweight="bold",
        y=0.96,
    )
    ax.text(6.0, 8.0, "Why all minimum-bound readings produce P_shifted = O and how downstream recovery bypasses it", ha="center", fontsize=10.5, color="#546e7a")

    # Top condition
    box_top = patches.FancyBboxPatch((3.5, 6.6), 5.0, 1.0, boxstyle="round,pad=0.2", edgecolor="#0288d1", facecolor="#e1f5fe", linewidth=2)
    ax.add_patch(box_top)
    ax.text(6.0, 7.1, "N Sensors Report Temperature Telemetry", ha="center", va="center", fontsize=10.5, fontweight="bold", color="#01579b")

    # Left: Minimum readings
    box_min = patches.FancyBboxPatch((0.8, 4.4), 4.8, 1.6, boxstyle="round,pad=0.2", edgecolor="#c62828", facecolor="#ffebee", linewidth=2)
    ax.add_patch(box_min)
    ax.text(3.2, 5.2, "CASE A: All Sensors Read -40.0°C\n• Each M_i = 100\n• M_sum = 100·N\n• Decrypted P = (100·N)·G\n• Shift: P_shifted = P - (100·N)·G = 0·G", ha="center", va="center", fontsize=8.5, family="monospace", color="#b71c1c")

    # Right: Normal / Warmer readings
    box_norm = patches.FancyBboxPatch((6.4, 4.4), 4.8, 1.6, boxstyle="round,pad=0.2", edgecolor="#2e7d32", facecolor="#e8f5e9", linewidth=2)
    ax.add_patch(box_norm)
    ax.text(8.8, 5.2, "CASE B: Mixed / Warmer Readings\n• Some M_i > 100\n• M_sum > 100·N\n• Decrypted P = (M_sum)·G\n• Shift: P_shifted = k·G (where k > 0)", ha="center", va="center", fontsize=8.5, family="monospace", color="#1b5e20")

    # Arrows down
    ax.annotate("", xy=(3.2, 4.3), xytext=(4.8, 6.5), arrowprops=dict(facecolor="#c62828", width=2, headwidth=7))
    ax.annotate("", xy=(8.8, 4.3), xytext=(7.2, 6.5), arrowprops=dict(facecolor="#2e7d32", width=2, headwidth=7))

    # Decision Diamond / Check
    chk_box = patches.FancyBboxPatch((4.0, 2.6), 4.0, 1.2, boxstyle="round,pad=0.2", edgecolor="#455a64", facecolor="#eceff1", linewidth=2)
    ax.add_patch(chk_box)
    ax.text(6.0, 3.2, "Infinity Check: is_infinity(P_shifted)?\n(Tests Jacobian Z == 0 or 0·G)", ha="center", va="center", fontsize=9, fontweight="bold", color="#263238")

    ax.annotate("", xy=(4.5, 3.9), xytext=(3.2, 4.3), arrowprops=dict(facecolor="#c62828", width=2, headwidth=7))
    ax.annotate("", xy=(7.5, 3.9), xytext=(8.8, 4.3), arrowprops=dict(facecolor="#2e7d32", width=2, headwidth=7))

    # Outcome 1: Immediate short circuit
    out1 = patches.FancyBboxPatch((0.5, 0.6), 5.2, 1.5, boxstyle="round,pad=0.2", edgecolor="#c62828", facecolor="#ffcdd2", linewidth=2)
    ax.add_patch(out1)
    ax.text(3.1, 1.35, "YES -> SHORT-CIRCUIT LOWER BOUND\n• Recovered M_sum = 100·N\n• Average Temp = -40.0°C\n• Bypasses DLP search with ZERO latency!", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#b71c1c")

    # Outcome 2: Downstream search
    out2 = patches.FancyBboxPatch((6.3, 0.6), 5.2, 1.5, boxstyle="round,pad=0.2", edgecolor="#2e7d32", facecolor="#c8e6c9", linewidth=2)
    ax.add_patch(out2)
    ax.text(8.9, 1.35, "NO -> PASS TO BOUNDED ECDLP SEARCH\n• Target scalar k ∈ [1, 1200·N]\n• Weeks 1-4: Candidate verifier\n• Weeks 5+: BSGS / Pollard's Kangaroo", ha="center", va="center", fontsize=8.5, fontweight="bold", color="#1b5e20")

    ax.annotate("", xy=(3.1, 2.2), xytext=(5.0, 2.5), arrowprops=dict(facecolor="#c62828", width=2, headwidth=7))
    ax.annotate("", xy=(8.9, 2.2), xytext=(7.0, 2.5), arrowprops=dict(facecolor="#2e7d32", width=2, headwidth=7))

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def main():
    figures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "figures"))
    os.makedirs(figures_dir, exist_ok=True)

    # Write Mermaid source files
    diagrams = {
        "diagram_a_architecture.mmd": MERMAID_DIAGRAM_A,
        "diagram_b_mathematics.mmd": MERMAID_DIAGRAM_B,
        "diagram_c_authentication.mmd": MERMAID_DIAGRAM_C,
        "diagram_d_infinity_edge_case.mmd": MERMAID_DIAGRAM_D,
    }

    for filename, content in diagrams.items():
        filepath = os.path.join(figures_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Generated Mermaid source: {filepath}")

    # Render PNG images for all diagrams
    print("Rendering Diagram A image...")
    render_diagram_a_image(os.path.join(figures_dir, "diagram_a_architecture.png"))

    print("Rendering Diagram B image...")
    render_diagram_b_image(os.path.join(figures_dir, "diagram_b_mathematics.png"))

    print("Rendering Diagram C image...")
    render_diagram_c_image(os.path.join(figures_dir, "diagram_c_authentication.png"))

    print("Rendering Diagram D image...")
    render_diagram_d_image(os.path.join(figures_dir, "diagram_d_infinity_edge_case.png"))

    print("All diagrams rendered successfully.")


if __name__ == "__main__":
    main()
